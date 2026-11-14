/*
 * Packet capture output (docs/LINUX.md, "Packet capture"). The kernel's packet records (bpf_pkt.inc
 * OnPacket) become Enhanced Packet Blocks in pcapng parts beside the events (<output stem>.pcapng,
 * then .1, .2, ... at the events' part size), one LINKTYPE_RAW interface stamped in FILETIME units.
 * A socket only wineserver has used so far may be the Nexon launcher's (wineserver creates and
 * connects every Wine socket): its packets are held until a tracked non-wineserver process uses it
 * (owner in the kernel tag), and dropped, counted, when its maker (wineserver) closes it or the session
 * ends unattributed. Another process's close ends nothing (socket_join.h: Wine clients close per-call fds).
 * Each closed part becomes a packet_capture_part note that agent.cpp chains into the log; the part is
 * hashed on its own thread so the BPF thread never stalls on it.
 * PacketsAdd and PacketsPolled run on the BPF thread, PacketsTakeNotes on the main thread: one mutex
 * guards it all.
 */
#include "packets.h"
#include <algorithm>
#include <cerrno>
#include <condition_variable>
#include <deque>
#include <fstream>
#include <future>
#include <mutex>
#include <set>
#include <unordered_map>

static_assert(sizeof(mm_pkt) == 48, "struct mm_pkt is shared with pkt.bpf.h");

namespace {

/* shortcut: held packets of unattributed sockets are capped at 16 MiB in all; beyond it the socket
 * held longest is dropped (counted unattributed and in held_overflow) so a new socket's handshake is
 * always kept; raise it if held_overflow shows up next to game sockets that start mid-stream. */
constexpr uint64_t HELD_TOTAL_BYTES = 16ull << 20;

struct Held {
    mm_pkt header;
    uint64_t time;
    std::string data;
};

/* A closed part waiting for its hash. */
struct Part {
    std::future<std::string> hash;
    std::wstring detail;
};

struct State {
    std::mutex mutex;
    std::condition_variable detachedWake;
    std::wstring base;
    uint64_t maxPart = 0;
    bool started = false;
    bool closed = false;     /* no more writes: a write failed, or the session ended */
    bool finished = false;   /* the totals note was made */
    bool polled = false;     /* a BPF thread polls the pkts ring (PacketsStopping) */
    bool stopping = false;   /* the final drain waits for the BPF thread to detach and read the ring */
    bool detached = false;   /* it did */
    int error = 0;
    std::wstring reason = L"the kernel (eBPF) sensors are not running";
    std::ofstream out;
    unsigned part = 0;
    uint64_t fileBytes = 0, partPackets = 0, partWire = 0, partCaptured = 0, partFirst = 0, partLast = 0, partDrops = 0;
    uint64_t packets = 0, wire = 0, captured = 0, truncated = 0, gso = 0, drops = 0;
    uint64_t attributed = 0, unattributed = 0, unattributedPackets = 0, unattributedBytes = 0, overflow = 0, skipped = 0;
    std::unordered_map<uint64_t, std::vector<Held>> held;   /* by socket cookie */
    uint64_t heldBytes = 0;
    struct Owner {
        DWORD pid, server;
        uint64_t ino;
    };
    std::unordered_map<uint64_t, Owner> owners;   /* cookie -> owner once attributed */
    std::set<std::pair<uint64_t, DWORD>> closing;   /* (inode, closer) since the pkts ring was last read to its end */
    std::unordered_map<DWORD, std::string> names;           /* pid -> /proc/<pid>/comm (Wine sets the .exe name) */
    std::deque<Part> parts;
};
State gPackets;

void Put16(std::string& out, uint16_t value) { out.append(reinterpret_cast<const char*>(&value), 2); }
void Put32(std::string& out, uint32_t value) { out.append(reinterpret_cast<const char*>(&value), 4); }
void Pad(std::string& out) { out.append((4 - out.size() % 4) % 4, '\0'); }
void Option(std::string& out, uint16_t code, const std::string& value)
{
    Put16(out, code);
    Put16(out, static_cast<uint16_t>(value.size()));
    out += value;
    Pad(out);
}
/* type, total length, body (padded), total length. */
std::string Block(uint32_t type, const std::string& body)
{
    std::string out;
    Put32(out, type);
    Put32(out, static_cast<uint32_t>(body.size() + 12));
    out += body;
    Put32(out, static_cast<uint32_t>(body.size() + 12));
    return out;
}

std::wstring PartPath(unsigned part)
{
    return part == 0 ? gPackets.base : gPackets.base + L"." + std::to_wstring(part);
}

void OpenPart()
{
    State& s = gPackets;
    s.out.open(LinuxNarrow(PartPath(s.part)), std::ios::binary | std::ios::trunc);
    std::string shb, idb;
    Put32(shb, 0x1A2B3C4D);   /* byte-order magic, host order */
    Put16(shb, 1);
    Put16(shb, 0);
    shb.append(8, '\xff');    /* section length: not known */
    Put16(idb, 101);          /* LINKTYPE_RAW: IPv4 or IPv6, told by the first nibble */
    Put16(idb, 0);
    Put32(idb, MM_PKT_MAX);
    Option(idb, 9, std::string(1, '\x07'));   /* if_tsresol: 10^-7 s, the log's FILETIME unit */
    Put32(idb, 0);
    const std::string header = Block(0x0A0D0D0A, shb) + Block(1, idb);
    s.out.write(header.data(), static_cast<std::streamsize>(header.size()));
    s.fileBytes = header.size();
    s.partPackets = s.partWire = s.partCaptured = s.partFirst = s.partLast = 0;
    s.partDrops = s.drops;
}

/* The part is read back and hashed on its own thread (std::async): the BPF thread, which also drains
 * the events ring, never waits for it; PacketsTakeNotes collects the hashes in part order. */
void ClosePart()
{
    State& s = gPackets;
    s.out.flush();
    const bool failed = !s.out;
    s.out.close();
    const std::wstring path = PartPath(s.part);
    s.parts.push_back({std::async(std::launch::async, Sha256File, path),
                       L"path=" + path.substr(path.find_last_of(L'/') + 1) + L";part=" + std::to_wstring(s.part) +
                           L";packets=" + std::to_wstring(s.partPackets) + L";wire_bytes=" + std::to_wstring(s.partWire) +
                           L";captured_bytes=" + std::to_wstring(s.partCaptured) + L";file_bytes=" +
                           std::to_wstring(s.fileBytes) + L";first_utc=" +
                           LinuxWide(s.partFirst ? Timestamp(s.partFirst) : "") + L";last_utc=" +
                           LinuxWide(s.partLast ? Timestamp(s.partLast) : "") + L";ring_drops=" +
                           std::to_wstring(s.drops - s.partDrops) + (failed ? L";write_failed=1" : L"")});
}

const std::string& Name(DWORD pid)
{
    State& s = gPackets;
    if (s.names.size() > 4096) s.names.clear();   /* processes come and go; names are read again on demand */
    std::string& name = s.names[pid];
    if (name.empty()) {
        std::ifstream file("/proc/" + std::to_string(pid) + "/comm");
        if (!std::getline(file, name) || name.empty()) name = "?";
    }
    return name;
}

/* One EPB, attributed to Owner; Held marks one written when its socket got attributed. */
void Write(const mm_pkt& h, uint64_t time, const unsigned char* data, DWORD owner, bool held, uint32_t skipped)
{
    State& s = gPackets;
    if (s.closed) return;
    if (s.maxPart != 0 && s.fileBytes >= s.maxPart) {
        ClosePart();
        s.part++;
        OpenPart();
    }
    std::string comment = "pid=" + std::to_string(owner) + ";process=" + Name(owner) + ";socket=socket:[" +
                          std::to_string(h.ino) + "];cookie=" + std::to_string(h.cookie);
    if (h.server) comment += ";wineserver=" + std::to_string(h.server);
    if (held) comment += ";held=1";
    if (h.gso_segs > 1) comment += ";gso_segs=" + std::to_string(h.gso_segs);
    if (skipped) comment += ";pending_skipped=" + std::to_string(skipped);
    const uint64_t stamp = time - MSMON_UNIX_EPOCH_AS_FILETIME;
    std::string epb;
    Put32(epb, 0);
    Put32(epb, static_cast<uint32_t>(stamp >> 32));
    Put32(epb, static_cast<uint32_t>(stamp));
    Put32(epb, h.cap_len);
    Put32(epb, h.len);
    epb.append(reinterpret_cast<const char*>(data), h.cap_len);
    Pad(epb);
    const uint32_t flags = h.dir == MM_PKT_OUT ? 2 : 1;   /* epb_flags direction: 1 inbound, 2 outbound */
    Option(epb, 2, std::string(reinterpret_cast<const char*>(&flags), 4));
    Option(epb, 1, comment);
    Put32(epb, 0);
    const std::string block = Block(6, epb);
    s.out.write(block.data(), static_cast<std::streamsize>(block.size()));
    s.fileBytes += block.size();
    s.partPackets++;
    s.partWire += h.len;
    s.partCaptured += h.cap_len;
    /* Held packets are written late: min/max keep first_utc/last_utc bounding every packet of the part. */
    s.partFirst = s.partFirst ? std::min(s.partFirst, time) : time;
    s.partLast = std::max(s.partLast, time);
    s.packets++;
    s.wire += h.len;
    s.captured += h.cap_len;
    if (h.len > h.cap_len) s.truncated++;
    if (h.gso_segs > 1) s.gso++;
    if (!s.out) {   /* disk full or gone: close what was written, capture ends */
        ClosePart();
        s.closed = true;
    }
}

void Flush(std::unordered_map<uint64_t, std::vector<Held>>::iterator entry, DWORD owner)
{
    State& s = gPackets;
    for (const Held& packet : entry->second) {
        s.heldBytes -= packet.data.size();
        Write(packet.header, packet.time, reinterpret_cast<const unsigned char*>(packet.data.data()), owner, true, 0);
    }
    s.attributed++;
    s.held.erase(entry);
}

void Drop(std::unordered_map<uint64_t, std::vector<Held>>::iterator entry)
{
    State& s = gPackets;
    for (const Held& packet : entry->second) {
        s.heldBytes -= packet.data.size();
        s.unattributedPackets++;
        s.unattributedBytes += packet.header.len;
    }
    s.unattributed++;
    s.held.erase(entry);
}

/* Holds a packet of a socket no tracked non-wineserver process used yet; when the budget is full the
 * socket held longest goes first (a game socket gets its owner within one round trip, the launcher's
 * may never), so a new socket's handshake is never refused. */
void Hold(const mm_pkt& h, const unsigned char* data, uint64_t fileTime)
{
    State& s = gPackets;
    while (s.heldBytes + h.cap_len > HELD_TOTAL_BYTES && !s.held.empty()) {
        Drop(std::min_element(s.held.begin(), s.held.end(), [](const auto& a, const auto& b) {
            return a.second.front().time < b.second.front().time;
        }));
        s.overflow++;
    }
    s.held[h.cookie].push_back({h, fileTime, std::string(reinterpret_cast<const char*>(data), h.cap_len)});
    s.heldBytes += h.cap_len;
}

}  // namespace

void PacketsConfigure(const std::wstring& path, uint64_t maxPartBytes)
{
    std::lock_guard<std::mutex> lock(gPackets.mutex);
    gPackets.base = path;
    gPackets.maxPart = maxPartBytes;
}

const std::wstring& PacketsPath()
{
    return gPackets.base;
}

bool PacketsStart(int error, const std::wstring& detail)
{
    std::lock_guard<std::mutex> lock(gPackets.mutex);
    State& s = gPackets;
    if (s.base.empty() || s.started) return s.started;
    if (error == 0) {
        errno = 0;
        OpenPart();
        if (!s.out) {
            error = errno != 0 ? errno : EIO;
            s.out.close();
            s.reason = L"open_failed=" + s.base;
        }
    } else {
        s.reason = detail;
    }
    s.error = error;
    s.started = error == 0;
    return s.started;
}

std::pair<std::wstring, std::wstring> PacketsNote()
{
    std::lock_guard<std::mutex> lock(gPackets.mutex);
    const State& s = gPackets;
    if (s.base.empty()) return {};
    if (!s.started) {
        return {L"packet_capture_unavailable", L"errno=" + std::to_wstring(s.error) + L";" + s.reason +
                                                   L";no packets are captured"};
    }
    return {L"packet_capture_active",
            L"path=" + s.base.substr(s.base.find_last_of(L'/') + 1) + L";linktype=101;snaplen=" +
                std::to_wstring(MM_PKT_MAX) + L";tsresol=7;cgroup=/sys/fs/cgroup;programs=mm_skb_ingress,mm_skb_egress,"
                L"mm_sock_create,mm_sock_connect,mm_sock_send,mm_sock_recv;pending_socket_bytes=" +
                std::to_wstring(MM_PENDING_MAX) + L";held_total_bytes=" + std::to_wstring(HELD_TOTAL_BYTES) +
                L";part_bytes=" + std::to_wstring(s.maxPart)};
}

void PacketsAdd(const mm_pkt& h, const unsigned char* data, uint64_t fileTime)
{
    std::lock_guard<std::mutex> lock(gPackets.mutex);
    State& s = gPackets;
    if (!s.started || s.closed) return;
    DWORD owner = h.owner;
    if (owner == 0) {
        /* A packet that read the tag (pkt.bpf.h) just before the game's first send/recv set its owner
         * on another CPU can arrive after that owner's first packet: it belongs to the known owner. */
        const auto known = s.owners.find(h.cookie);
        if (known == s.owners.end()) {
            Hold(h, data, fileTime);
            return;
        }
        owner = known->second.pid;
    } else {
        /* shortcut: forgotten all at once past 65536 live attributed sockets (a late racing packet is
         * then held and dropped), key by close order if a session ever has that many. */
        if (s.owners.size() >= 65536) s.owners.clear();
        s.owners[h.cookie] = {owner, h.server, h.ino};
    }
    uint32_t skipped = 0;
    auto pending = s.held.find(h.cookie);
    if (pending != s.held.end()) {
        Flush(pending, owner);
        skipped = h.skipped;
        s.skipped += skipped;
    }
    Write(h, fileTime, data, owner, false, skipped);
}

void PacketsKernelDrops(uint64_t total)
{
    std::lock_guard<std::mutex> lock(gPackets.mutex);
    gPackets.drops = total;
}

void PacketsSocketClosed(uint64_t ino, DWORD closer)
{
    std::lock_guard<std::mutex> lock(gPackets.mutex);
    const State& s = gPackets;
    if (ino != 0 && s.started && !s.closed) gPackets.closing.insert({ino, closer});   /* capture off: nothing to end */
}

bool PacketsStopping()
{
    std::lock_guard<std::mutex> lock(gPackets.mutex);
    gPackets.polled = true;
    return gPackets.stopping;
}

void PacketsPolled(bool detached)
{
    std::lock_guard<std::mutex> lock(gPackets.mutex);
    State& s = gPackets;
    if (!s.closing.empty()) {
        /* Any packet's inode: the tag gets its inode only at the first hook that sees sock->file. Only the
         * maker's close ends a socket: a held one's maker is its wineserver (owner 0: only wineserver used
         * it), an attributed one's is its wineserver or, without one, its owner. */
        for (auto it = s.held.begin(); it != s.held.end();) {
            auto next = std::next(it);
            if (std::any_of(it->second.begin(), it->second.end(), [&](const Held& packet) {
                    return s.closing.count({packet.header.ino, packet.header.server}) != 0;
                })) {
                Drop(it);
            }
            it = next;
        }
        for (auto it = s.owners.begin(); it != s.owners.end();) {
            const State::Owner& o = it->second;
            it = s.closing.count({o.ino, o.server ? o.server : o.pid}) != 0 ? s.owners.erase(it) : std::next(it);
        }
        s.closing.clear();
    }
    if (detached && !s.detached) {
        s.detached = true;
        s.detachedWake.notify_all();
    }
}

std::vector<std::pair<std::wstring, std::wstring>> PacketsTakeNotes(bool final)
{
    State& s = gPackets;
    std::wstring totals;
    std::deque<Part> done;
    {
        std::unique_lock<std::mutex> lock(s.mutex);
        if (final && s.started && !s.finished) {
            bool complete = true;
            if (s.polled) {
                /* The BPF thread detaches mm_skb_* and reads the pkts ring to its end (PktPoll) so the
                 * last packets and drops are in the totals; it polls every 200 ms. */
                s.stopping = true;
                complete = s.detachedWake.wait_for(lock, std::chrono::seconds(5), [&] { return s.detached; });
            }
            while (!s.held.empty()) Drop(s.held.begin());
            if (!s.closed) ClosePart();
            s.closed = s.finished = true;
            totals = L"parts=" + std::to_wstring(s.part + 1) + L";packets=" + std::to_wstring(s.packets) +
                               L";wire_bytes=" + std::to_wstring(s.wire) + L";captured_bytes=" +
                               std::to_wstring(s.captured) + L";truncated=" + std::to_wstring(s.truncated) +
                               L";gso_packets=" + std::to_wstring(s.gso) + L";attributed_sockets=" +
                               std::to_wstring(s.attributed) + L";unattributed_sockets=" +
                               std::to_wstring(s.unattributed) + L";unattributed_packets=" +
                               std::to_wstring(s.unattributedPackets) + L";unattributed_bytes=" +
                               std::to_wstring(s.unattributedBytes) + L";held_overflow=" + std::to_wstring(s.overflow) +
                               L";pending_skipped=" + std::to_wstring(s.skipped) + L";ring_drops=" +
                               std::to_wstring(s.drops) + (complete ? L"" : L";final_read=timed_out");
        }
        while (!s.parts.empty() &&
               (final || s.parts.front().hash.wait_for(std::chrono::seconds(0)) == std::future_status::ready)) {
            done.push_back(std::move(s.parts.front()));
            s.parts.pop_front();
        }
    }
    std::vector<std::pair<std::wstring, std::wstring>> notes;
    for (Part& part : done) notes.push_back({L"packet_capture_part", part.detail + L";sha256=" + LinuxWide(part.hash.get())});
    if (!totals.empty()) notes.push_back({L"packet_capture", totals});
    return notes;
}
