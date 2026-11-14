/* The netattr upgrade (docs/LINUX.md "Socket join"): sockets wineserver (or any tracked helper)
 * made, attributed to the tracked process that reads and writes them.  User space only: it is fed
 * by the syscall records the core programs already send, so it adds no BPF code. */
#include "socket_join.h"
#include <cerrno>
#include <mutex>
#include <sys/socket.h>

namespace {

/* JoinFlush runs on the thread that stops tracking, the others on the ring thread. */
SocketJoin join;
std::mutex joinLock;
/* Set by JoinFlush: StopTracking clears tracking only after it, so a use opened in between would
 * never get its close; nothing is joined until JoinClose. */
bool joinFlushed = false;

/* One record the join asked for, for the process that used a socket another one made: its
 * network_flow_established at its first I/O (Tid, the call First and its Result), or its
 * network_flow_close with the bytes it moved.  No stack: the socket's calls were the maker's. */
void WriteJoin(const SocketJoin::Change& change, DWORD tid, const char* first, int64_t result)
{
    if (gBpf.session == nullptr) return;
    static const wchar_t* const kVia[] = {L"socket", L"connect", L"bind", L"listen", L"accept"};
    const SocketJoin::Socket& socket = change.socket;
    const bool inet = socket.family == AF_INET || socket.family == AF_INET6;
    const uint64_t protocol = !inet ? 0 : socket.type == SOCK_STREAM ? 6 : socket.type == SOCK_DGRAM ? 17 : 0;
    const bool local = socket.via == SocketJoin::kBind || socket.via == SocketJoin::kListen;
    LinuxRecord record;
    record.sensor = socket.family == AF_UNIX ? MSMON_SENSOR_LINUX_EBPF_IPC : MSMON_SENSOR_LINUX_EBPF_NET;
    record.pid = change.use.who.pid;
    record.start = change.use.who.start;
    record.timestamp = change.time;
    record.flags = MsMonFlagServiceCorrelated;
    record.value0 = change.inode;
    /* Packed as the driver does: protocol, local port, remote port. */
    record.value1 = (protocol << 32) | (static_cast<uint64_t>(socket.port) << (local ? 16 : 0));
    record.text = socket.endpoint;
    const std::wstring creator =
        L";creator_pid=" + std::to_wstring(socket.creator.pid) + L";creator_start=" + std::to_wstring(socket.creator.start);
    if (change.opened) {
        record.type = MsMonNetworkFlowEstablished;
        record.tid = tid;
        record.status = 0;   /* established, as on Windows; the maker's errno is creator_status */
        record.detail = std::wstring(kVia[socket.via]) + L";family=" + std::to_wstring(socket.family) + L";type=" +
                        std::to_wstring(socket.type) + L";service_correlated" + creator + L";creator_status=" +
                        std::to_wstring(socket.status) + L";creator_time=" + LinuxWide(Timestamp(socket.time)) +
                        L";first_use=" + LinuxWide(first) + L";first_use_ret=" + std::to_wstring(result);
    } else {
        record.type = MsMonNetworkFlowClose;
        record.detail = L"close;service_correlated;reason=" + std::wstring(change.reason) + L";bytes_sent=" +
                        std::to_wstring(change.use.sent) + L";bytes_received=" + std::to_wstring(change.use.received) +
                        creator;
    }
    gBpf.session->Write(record);
}

/* Feeds the join with a call on a socket fd (socket()/accept(): the new one); OnSyscall calls it
 * before the call's own record and before Repeated(), so every byte is counted. */
void JoinSocket(const mm_event& e, const Syscall& call, uint64_t start, const std::wstring& endpoint, unsigned family,
                uint16_t port)
{
    if (!S_ISSOCK(e.mode) || e.ino == 0) return;
    const SocketJoin::Who who{e.tgid, start};
    const uint64_t time = BootToFileTime(e.ts_ns);
    const bool ok = e.ret >= 0;
    /* recvmmsg/sendmmsg return message counts, and a MSG_PEEK read takes nothing: no bytes. */
    const bool peek = (e.nr == SYS_recvfrom && (e.args[3] & MSG_PEEK) != 0) ||
                      (e.nr == SYS_recvmsg && (e.args[2] & MSG_PEEK) != 0);
    const uint64_t bytes =
        e.ret > 0 && !peek && e.nr != SYS_recvmmsg && e.nr != SYS_sendmmsg ? static_cast<uint64_t>(e.ret) : 0;
    const long status = ok ? 0 : static_cast<long>(e.ret);
    SocketJoin::Changes changes;
    {
        std::lock_guard<std::mutex> lock(joinLock);
        if (joinFlushed) return;
        switch (call.op) {
        case Op::Socket:
            if (ok) changes = join.Made(e.ino, who, SocketJoin::kSocket, e.args[0], e.args[1] & 0xf, 0, {}, 0, time);
            break;
        case Op::Accept:
            if (ok) changes = join.Made(e.ino, who, SocketJoin::kAccept, family, SOCK_STREAM, port, endpoint, 0, time);
            break;
        case Op::Connect:   /* Wine's nonblocking connect (EINPROGRESS) is kept as creator_status; other failures never connected */
            if (ok || e.ret == -EINPROGRESS)
                changes = join.Made(e.ino, who, SocketJoin::kConnect, family, 0, port, endpoint, status, time);
            break;
        case Op::Bind:
        case Op::Listen:
            if (ok)
                changes = join.Made(e.ino, who, call.op == Op::Bind ? SocketJoin::kBind : SocketJoin::kListen, family, 0,
                                    port, endpoint, 0, time);
            break;
        case Op::Close:
            changes = join.Closed(e.ino, who, time);
            break;
        case Op::Read:
        case Op::RecvFrom:
            /* sendfile/splice/copy_file_range resolve their input fd: a socket there was read from
             * (shortcut in socket_join.h: their output socket is not counted). */
            changes = join.Io(e.ino, who, 0, bytes, time);
            break;
        case Op::Write:
        case Op::SendTo:
            changes = join.Io(e.ino, who, bytes, 0, time);
            break;
        default:
            break;
        }
    }
    for (const auto& change : changes) WriteJoin(change, change.opened ? e.tid : 0, call.name, e.ret);
}

/* A process exited (reason empty) or left scope: its uses end, and the sockets it made end with it. */
void JoinForget(const mm_event& e, uint64_t start, const std::wstring& reason)
{
    SocketJoin::Changes changes;
    {
        std::lock_guard<std::mutex> lock(joinLock);
        changes = join.Gone({e.tgid, start}, reason.empty() ? L"process_exit" : L"untracked", BootToFileTime(e.ts_ns));
    }
    for (const auto& change : changes) WriteJoin(change, 0, "", 0);
}

/* Tracking stops: every joined flow still open gets its network_flow_close (session_end). */
void JoinFlush()
{
    SocketJoin::Changes changes;
    {
        std::lock_guard<std::mutex> lock(joinLock);
        changes = join.Flush(0);   /* 0: written at the current time */
        joinFlushed = true;
    }
    for (const auto& change : changes) WriteJoin(change, 0, "", 0);
}

void JoinClose()
{
    std::lock_guard<std::mutex> lock(joinLock);
    join = SocketJoin{};
    joinFlushed = false;
}

void JoinNotes(Notes& notes)
{
    notes.push_back({L"socket_join",
                     L"a socket one tracked process made (connect, bind, listen, accept: wineserver for Wine programs) is"
                     L" attributed to each other tracked process that reads or writes it: network_flow_established"
                     L" (service_correlated, value0 the inode) at its first I/O, network_flow_close with"
                     L" bytes_sent/bytes_received when the maker closes it or exits, the user exits or leaves scope, the"
                     L" inode is reused or tracking stops; sockets made before the session, never bound or connected by"
                     L" their maker, or whose connect failed or was dropped, are not joined; dropped I/O records and"
                     L" sendfile/splice into a socket are missing from the totals"});
}

}  // namespace
