#include "session.h"
#include <arpa/inet.h>
#include <dirent.h>
#include <fstream>
#include <map>
#include <set>

/*
 * network_connect / network_accept / network_flow_close from a once-a-second poll of /proc/net: a socket
 * owned (through /proc/<pid>/fd) by a tracked process is reported when first seen and
 * closed when it leaves the table.  Sockets that live less than a poll are missed, the
 * first poll reports sockets that were already open, and timestamps are poll times.
 * Value0 is the socket inode (the flow id); Value1 packs protocol, local and remote port
 * as the driver does.
 */

namespace {
struct Owner {
    DWORD pid = 0;
    uint64_t start = 0;
};

struct Flow {
    Owner owner;
    uint64_t packed = 0;
    std::wstring endpoints;
    std::wstring detail;
    ULONG type = MsMonNetworkConnect;
};

std::map<uint64_t, Flow> gFlows;
}

void NetReset()
{
    gFlows.clear();
}

static std::wstring Address(const std::string& hex, unsigned port, bool v6)
{
    unsigned char bytes[16]{};
    /* The kernel prints each 32-bit word of the address in host order. */
    for (size_t word = 0; word < (v6 ? 4u : 1u) && hex.size() >= (word + 1) * 8; word++) {
        uint32_t value = static_cast<uint32_t>(std::stoul(hex.substr(word * 8, 8), nullptr, 16));
        std::memcpy(bytes + word * 4, &value, sizeof(value));
    }
    char text[INET6_ADDRSTRLEN]{};
    inet_ntop(v6 ? AF_INET6 : AF_INET, bytes, text, sizeof(text));
    std::string formatted = v6 ? "[" + std::string(text) + "]" : std::string(text);
    return LinuxWide(formatted) + L":" + std::to_wstring(port);
}

void NetPoll(LinuxSession& session)
{
    session.Enter(MSMON_SENSOR_LINUX_NET_POLL);
    std::map<uint64_t, Owner> owners;
    for (const auto& process : session.TrackedProcesses()) {
        const std::string directory = "/proc/" + std::to_string(process.first) + "/fd";
        DIR* fds = opendir(directory.c_str());
        if (fds == nullptr) continue;
        while (dirent* entry = readdir(fds)) {
            char target[64];
            ssize_t length = readlink((directory + "/" + entry->d_name).c_str(), target, sizeof(target) - 1);
            if (length <= 0) continue;
            target[length] = '\0';
            unsigned long long inode = 0;
            if (sscanf(target, "socket:[%llu]", &inode) == 1) owners.emplace(inode, Owner{process.first, process.second});
        }
        closedir(fds);
    }

    static const struct {
        const char* path;
        const wchar_t* protocol;
        unsigned number;
        bool v6;
    } tables[] = {
        {"/proc/net/tcp", L"tcp", 6, false}, {"/proc/net/tcp6", L"tcp", 6, true},
        {"/proc/net/udp", L"udp", 17, false}, {"/proc/net/udp6", L"udp", 17, true},
    };
    std::map<uint64_t, Flow> current;
    std::set<uint64_t> listening;
    for (const auto& table : tables) {
        std::ifstream file(table.path);
        std::string line;
        std::getline(file, line);
        while (std::getline(file, line)) {
            char local[33]{}, remote[33]{};
            unsigned localPort = 0, remotePort = 0, state = 0;
            unsigned long long inode = 0;
            if (sscanf(line.c_str(), " %*u: %32[0-9A-Fa-f]:%x %32[0-9A-Fa-f]:%x %x %*s %*s %*s %*u %*u %llu",
                       local, &localPort, remote, &remotePort, &state, &inode) != 6 || inode == 0) continue;
            auto owner = owners.find(inode);
            if (owner == owners.end()) continue;
            Flow flow;
            flow.owner = owner->second;
            flow.packed = (static_cast<uint64_t>(table.number) << 32) | (static_cast<uint64_t>(localPort & 0xffff) << 16) |
                          (remotePort & 0xffff);
            flow.endpoints = Address(local, localPort, table.v6) + L" -> " + Address(remote, remotePort, table.v6);
            /* 0x0A is TCP_LISTEN; an unconnected UDP socket has remote port 0. */
            const bool listen = table.number == 6 && state == 0x0A;
            if (listen) listening.insert(flow.packed >> 16);
            wchar_t stateText[8];
            swprintf_s(stateText, L"%02X", state);
            flow.detail = std::wstring(listen ? L"listen" : table.number == 17 && remotePort == 0 ? L"bind" : L"connect") +
                          L";proto=" + table.protocol + L";state=" + stateText;
            current.emplace(inode, std::move(flow));
        }
    }
    for (auto& item : current) {
        Flow& flow = item.second;
        /* A TCP connection on a tracked listener's port was accepted, not initiated. */
        if (flow.detail.compare(0, 7, L"connect") == 0 && (flow.packed >> 32) == 6 && listening.count(flow.packed >> 16) != 0) {
            flow.type = MsMonNetworkAccept;
            flow.detail.replace(0, 7, L"accept");
        }
        if (gFlows.count(item.first) != 0) continue;
        session.Log(MSMON_SENSOR_LINUX_NET_POLL, flow.type, flow.owner.pid, flow.owner.start, 0, item.first, flow.packed,
                    flow.endpoints, flow.detail);
    }
    for (const auto& flow : gFlows) {
        if (current.count(flow.first) != 0) continue;
        session.Log(MSMON_SENSOR_LINUX_NET_POLL, MsMonNetworkFlowClose, flow.second.owner.pid, flow.second.owner.start,
                    0, flow.first, flow.second.packed, flow.second.endpoints, L"close");
    }
    gFlows.swap(current);
}
