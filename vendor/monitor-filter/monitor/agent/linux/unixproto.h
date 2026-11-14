#pragma once
/*
 * Desktop services over AF_UNIX, the agent's side (bpf/unix.bpf.h walks the streams; bpf.cpp writes the records): a
 * display's X11 extension table, asked once per display as any client would, and the record of a kernel summary.
 * Header-only, so tests/linux_unix_test.cpp checks it offline (against a fake X server).
 */
#include "../rpc_names.h"
#include "sysagg.h"
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <functional>
#include <string>
#include <vector>

/* The service an MM_UNIX_* number names, as UnixService names its endpoint. */
inline std::wstring UnixServiceName(uint32_t svc)
{
    return svc == MM_UNIX_X11 ? L"x11" : svc == MM_UNIX_DBUS ? L"dbus" : svc == MM_UNIX_PULSE ? L"pulse" : L"unix";
}

/* Size bytes to or from Fd (non-blocking) before Deadline (a peer that trickles bytes cannot stretch it); false at
 * the deadline, on an error or at the end. */
inline bool UnixTransfer(int fd, void* data, size_t size, bool send, std::chrono::steady_clock::time_point deadline)
{
    auto* bytes = static_cast<uint8_t*>(data);
    for (size_t done = 0; done < size;) {
        const ssize_t moved = send ? ::send(fd, bytes + done, size - done, MSG_NOSIGNAL) : ::recv(fd, bytes + done, size - done, 0);
        if (moved > 0) {
            done += static_cast<size_t>(moved);
            continue;
        }
        if (moved == 0 || (errno != EAGAIN && errno != EINTR)) return false;
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
        pollfd wait{fd, static_cast<short>(send ? POLLOUT : POLLIN), 0};
        if (left <= 0 || poll(&wait, 1, static_cast<int>(left)) <= 0) return false;
    }
    return true;
}

/* The bytes of the Xauthority file at Path when it is a regular file Uid owns, of at most 64 KiB; else "". A client's
 * environment names the path and the agent reads it as root: never a FIFO or device (they block or never end), a
 * symlink, or a file of another user (a cookie the client could not read itself). */
inline std::string X11AuthorityFile(const std::string& path, uid_t uid)
{
    const int fd = open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return {};
    struct stat file{};
    std::string bytes;
    if (fstat(fd, &file) == 0 && S_ISREG(file.st_mode) && file.st_uid == uid && file.st_size <= 65536) {
        bytes.resize(static_cast<size_t>(file.st_size));
        const ssize_t got = bytes.empty() ? 0 : read(fd, &bytes[0], bytes.size());
        bytes.resize(got > 0 ? static_cast<size_t>(got) : 0);
    }
    close(fd);
    return bytes;
}

/* The MIT-MAGIC-COOKIE-1 an Xauthority file (its bytes) holds for display Number (a local or wildcard entry: family,
 * address, number, name, data, each but the family a big-endian length and its bytes), or "". */
inline std::string X11Cookie(const std::string& file, const std::string& number)
{
    size_t at = 0;
    auto field = [&](std::string& out) {
        if (at + 2 > file.size()) return false;
        const size_t length = static_cast<uint8_t>(file[at]) << 8 | static_cast<uint8_t>(file[at + 1]);
        if (at + 2 + length > file.size()) return false;
        out.assign(file, at + 2, length);
        at += 2 + length;
        return true;
    };
    while (at + 2 <= file.size()) {
        const unsigned family = static_cast<uint8_t>(file[at]) << 8 | static_cast<uint8_t>(file[at + 1]);
        at += 2;
        std::string address, display, name, data;
        if (!field(address) || !field(display) || !field(name) || !field(data)) break;
        if ((family == 256 || family == 65535) && (display == number || display.empty()) && name == "MIT-MAGIC-COOKIE-1")
            return data;
    }
    return {};
}

/* The extension table of the X server at Endpoint ("unix:/tmp/.X11-unix/X5", "unix:@/tmp/.X11-unix/X5" abstract):
 * a connection with no authorization (the game's display runs -ac), or with Cookie (MIT-MAGIC-COOKIE-1) when one is
 * given, its setup, one QueryExtension per X11ExtensionNames() name, their replies, closed. All of it within TimeoutMs.
 * SkipServer: true for the pid of a server (SO_PEERCRED) that is not to be asked (a tracked process's own listener
 * would see the agent, and a cookie sent to it). false: no table, Why says why (refused:<reason> when the server wants
 * a cookie it was not given, skipped:tracked_server). */
inline bool X11QueryExtensions(const std::string& endpoint, X11Extensions& out, std::string& why, int timeoutMs = 500,
                               const std::string& cookie = {}, const std::function<bool(pid_t)>& skipServer = {})
{
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    out.clear();
    const std::string path = endpoint.rfind("unix:", 0) == 0 ? endpoint.substr(5) : std::string();
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    if (path.empty() || path.size() >= sizeof(address.sun_path)) {
        why = "no_path";
        return false;
    }
    const bool abstract = path[0] == '@';   /* an abstract name starts with a NUL byte */
    std::memcpy(address.sun_path, path.data(), path.size());
    if (abstract) address.sun_path[0] = 0;
    const socklen_t length = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + path.size() + (abstract ? 0 : 1));
    const int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0 || connect(fd, reinterpret_cast<const sockaddr*>(&address), length) != 0) {
        why = "connect_failed:" + std::to_string(errno);
        if (fd >= 0) close(fd);
        return false;
    }
    ucred server{};
    socklen_t size = sizeof(server);
    if (skipServer && getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &server, &size) == 0 && skipServer(server.pid)) {
        why = "skipped:tracked_server";
        close(fd);
        return false;
    }
    bool ok = false;
    const std::vector<std::string>& names = X11ExtensionNames();
    do {
        /* protocol 11.0, the authorization's name and data lengths, then each padded to 4 */
        static const std::string kCookie = "MIT-MAGIC-COOKIE-1";
        const size_t name = cookie.empty() ? 0 : kCookie.size(), data = cookie.size();
        std::vector<uint8_t> setup = {'l', 0, 11, 0, 0, 0, static_cast<uint8_t>(name), 0, static_cast<uint8_t>(data),
                                      static_cast<uint8_t>(data >> 8), 0, 0};
        setup.insert(setup.end(), kCookie.begin(), kCookie.begin() + name);
        setup.resize((setup.size() + 3) & ~size_t(3));
        setup.insert(setup.end(), cookie.begin(), cookie.end());
        setup.resize((setup.size() + 3) & ~size_t(3));
        uint8_t reply[32];
        if (!UnixTransfer(fd, setup.data(), setup.size(), true, deadline) || !UnixTransfer(fd, reply, 8, false, deadline)) {
            why = "no_setup_reply";
            break;
        }
        std::vector<uint8_t> rest((reply[6] | reply[7] << 8) * 4u);
        if (!rest.empty() && !UnixTransfer(fd, rest.data(), rest.size(), false, deadline)) {
            why = "setup_cut";
            break;
        }
        if (reply[0] != 1) {   /* 0 failed (no authorization), 2 authenticate */
            why = "refused:" + std::string(rest.begin(), rest.begin() + std::min<size_t>(rest.size(), reply[1]));
            break;
        }
        std::vector<uint8_t> requests;
        for (const std::string& name : names) {   /* QueryExtension: 98, length, name length, the name padded to 4 */
            const size_t padded = (name.size() + 3) & ~size_t(3);
            const size_t units = 2 + padded / 4;
            const uint8_t head[8] = {98, 0, static_cast<uint8_t>(units), static_cast<uint8_t>(units >> 8),
                                     static_cast<uint8_t>(name.size()), static_cast<uint8_t>(name.size() >> 8), 0, 0};
            requests.insert(requests.end(), head, head + 8);
            requests.insert(requests.end(), name.begin(), name.end());
            requests.resize(requests.size() + padded - name.size());
        }
        if (!UnixTransfer(fd, requests.data(), requests.size(), true, deadline)) {
            why = "send_failed";
            break;
        }
        ok = true;
        for (size_t index = 0; index < names.size(); index++) {
            if (!UnixTransfer(fd, reply, sizeof(reply), false, deadline) || reply[0] != 1) {   /* replies come in order */
                why = "no_reply";
                ok = false;
                break;
            }
            if (reply[8]) out.push_back({names[index], reply[9], reply[10], reply[11]});
        }
    } while (false);
    close(fd);
    if (ok) why = "ok";
    return ok;
}

/* A kernel summary of a desktop service connection's op (agg nr MM_COUNT_UNIX | service | MM_UNIX_RX, key the
 * socket's inode << 32 | the op): an etw_rpc record of the connection, text its endpoint, value0 the bytes, value1 the
 * messages, detail repeats_tail;syscall=unix_service;aggregate=kernel;interface=;operation=;direction=sent|received;
 * socket=<inode>;repeats_before=<messages>;... (unparsed: bytes past the walk; D-Bus: the messages past its heads by
 * type, method_call... signal, sasl the handshake's calls). */
inline LinuxRecord UnixAggSummary(uint32_t nr, uint64_t key, const std::wstring& service, const std::wstring& endpoint,
                                  const X11Extensions& extensions, const mm_agg& total)
{
    const uint32_t svc = nr & 0xf, op = static_cast<uint32_t>(key);
    const bool rx = (nr & MM_UNIX_RX) != 0;
    const std::wstring name = op == MM_UNIX_OP_UNPARSED  ? L"unparsed"
                              : svc == MM_UNIX_X11       ? (rx ? X11ReceivedName(op, extensions) : X11RequestName(op, extensions))
                              : svc == MM_UNIX_PULSE     ? PulseCommandName(op)
                              : svc == MM_UNIX_DBUS      ? DbusTypeName(op)
                                                         : L"op" + std::to_wstring(op);
    LinuxRecord record = AggSummary("unix_service", nullptr, 0, total);
    record.sensor = MSMON_SENSOR_LINUX_EBPF_IPC;
    record.type = MsMonEtwRpc;
    record.text = endpoint;
    record.detail.insert(record.detail.find(L";repeats_before="), L";interface=" + service + L";operation=" + name +
                                                                     L";direction=" + (rx ? L"received" : L"sent") +
                                                                     L";socket=" + std::to_wstring(key >> 32));
    return record;
}
