/* TCP lifecycle (tcp upgrade, docs/LINUX.md "TCP lifecycle"): MM_TCP records (tcp.bpf.h) become
 * etw_tcp records named as Windows' Microsoft-Windows-TCPIP events (agent/etw.cpp TcpEventName). */
#include <netinet/tcp.h>
#include <bpf/btf.h>
#include <unordered_set>

namespace {

/* enum sk_rst_reason names from the running kernel's BTF (its numbering is kernel-specific). */
std::vector<std::wstring> gRstReasons;
bool gTcpOn = false;
/* Cookies with a retransmit Repeated() key: only their CLOSE scans gBpf.repeats. */
std::unordered_set<uint64_t> gTcpHeld;

/* The Microsoft-Windows-TCPIP event a record stands for, so etw_tcp reads the same on both systems;
 * id 0 where Windows has none. */
struct TcpName {
    uint32_t id;
    const wchar_t* name;
};

/* err: sk_err; orphan: no fd is left; shutdown: sk_shutdown; retransmits: icsk_retransmits (> 0 when
 * unacknowledged data was being retransmitted; packets_out is already purged at the timeout's CLOSE). */
constexpr TcpName TcpEventName(uint32_t what, unsigned from, unsigned to, uint32_t err, bool orphan, unsigned shutdown,
                               uint32_t retransmits)
{
    switch (what) {
    case MM_TCP_ACCEPT: return {1017, L"accept_completed"};
    case MM_TCP_RST_IN: return {1184, L"reset_received"};
    case MM_TCP_RST_OUT: return {1479, L"reset_sent"};
    case MM_TCP_RETRANS: return to == TCP_SYN_SENT ? TcpName{1186, L"connect_retransmit"} : TcpName{0, L"retransmit"};
    default: break;
    }
    if (from == TCP_SYN_SENT && to == TCP_ESTABLISHED) return {1033, L"connect_completed"};
    if ((from == TCP_ESTABLISHED && to == TCP_FIN_WAIT1) || (from == TCP_CLOSE_WAIT && to == TCP_LAST_ACK))
        return {1038, L"close_issued"};
    /* tcp_fin sets RCV_SHUTDOWN (1) first; FIN_WAIT2 -> CLOSE of a socket its process still holds is the
     * remote FIN after shutdown(SHUT_WR). */
    if ((from == TCP_ESTABLISHED && to == TCP_CLOSE_WAIT) || (from == TCP_FIN_WAIT1 && to == TCP_CLOSING) ||
        (from == TCP_FIN_WAIT2 && to == TCP_CLOSE && err == 0 && !orphan && (shutdown & 1)))
        return {1176, L"fin_received"};
    /* After a RST, reset_received already said it. */
    if (to != TCP_CLOSE || err == ECONNRESET || err == EPIPE) return {0, L"state_change"};
    if (from == TCP_SYN_SENT && err != 0)
        return err == ETIMEDOUT ? TcpName{1045, L"connect_timeout"} : TcpName{1034, L"connect_failed"};
    /* tcp_write_err: ETIMEDOUT, or the ICMP error that preceded the timeout. A FIN never acknowledged
     * is Windows' disconnect timeout; otherwise RTO give-up with data unacknowledged, or keepalive/
     * zero-window probes (tcp_ack cleared icsk_retransmits when everything was acknowledged). */
    if (err != 0 && err != ECONNABORTED) {
        if (from == TCP_FIN_WAIT1 || from == TCP_CLOSING || from == TCP_LAST_ACK) return {1048, L"disconnect_timeout"};
        return retransmits == 0 ? TcpName{1047, L"keepalive_timeout"} : TcpName{1046, L"retransmit_timeout"};
    }
    if (err == 0 && (from == TCP_LAST_ACK || from == TCP_CLOSING || (from == TCP_FIN_WAIT2 && orphan)))
        return {1043, L"disconnect_completed"};
    return from == TCP_LISTEN ? TcpName{0, L"state_change"} : TcpName{1039, L"abort_issued"};
}

constexpr uint32_t TcpId(uint32_t what, unsigned from, unsigned to, uint32_t err = 0, bool orphan = false,
                         unsigned shutdown = 0, uint32_t retransmits = 0)
{
    return TcpEventName(what, from, to, err, orphan, shutdown, retransmits).id;
}
static_assert(TcpId(MM_TCP_STATE, TCP_SYN_SENT, TCP_ESTABLISHED) == 1033, "connect completed");
static_assert(TcpId(MM_TCP_STATE, TCP_SYN_SENT, TCP_CLOSE, ECONNREFUSED) == 1034, "refused");
static_assert(TcpId(MM_TCP_STATE, TCP_SYN_SENT, TCP_CLOSE) == 1039, "closed while connecting");
static_assert(TcpId(MM_TCP_STATE, TCP_FIN_WAIT2, TCP_CLOSE, 0, false, 3) == 1176, "FIN after shutdown(SHUT_WR)");
static_assert(TcpId(MM_TCP_STATE, TCP_FIN_WAIT2, TCP_CLOSE, 0, false, 2) == 1039, "connect(AF_UNSPEC) when half-closed");
static_assert(TcpId(MM_TCP_STATE, TCP_FIN_WAIT2, TCP_CLOSE, 0, true, 3) == 1043, "closed: to the TIME_WAIT minisock");
static_assert(TcpId(MM_TCP_STATE, TCP_LAST_ACK, TCP_CLOSE) == 1043, "passive close done");
static_assert(TcpId(MM_TCP_STATE, TCP_ESTABLISHED, TCP_CLOSE, 0, false, 3) == 1039, "unread data on close");
static_assert(TcpId(MM_TCP_STATE, TCP_ESTABLISHED, TCP_CLOSE, ETIMEDOUT, false, 0, 3) == 1046, "retransmission timeout");
static_assert(TcpId(MM_TCP_STATE, TCP_ESTABLISHED, TCP_CLOSE, ETIMEDOUT) == 1047, "keepalive timeout");
static_assert(TcpId(MM_TCP_STATE, TCP_ESTABLISHED, TCP_CLOSE, EHOSTUNREACH, false, 0, 15) == 1046, "RTO after ICMP");
static_assert(TcpId(MM_TCP_STATE, TCP_FIN_WAIT1, TCP_CLOSE, ETIMEDOUT, true, 3, 8) == 1048, "orphan FIN unacknowledged");
static_assert(TcpId(MM_TCP_STATE, TCP_LAST_ACK, TCP_CLOSE, ETIMEDOUT, false, 3, 8) == 1048, "LAST_ACK timeout");
static_assert(TcpId(MM_TCP_STATE, TCP_ESTABLISHED, TCP_CLOSE, ECONNRESET) == 0, "after reset_received");
static_assert(TcpId(MM_TCP_STATE, TCP_ESTABLISHED, TCP_CLOSE_WAIT) == 1176, "remote FIN");
static_assert(TcpId(MM_TCP_RETRANS, 0, TCP_SYN_SENT) == 1186, "SYN retransmit");

std::wstring TcpState(unsigned state)
{
    static const wchar_t* const names[] = {L"0", L"ESTABLISHED", L"SYN_SENT", L"SYN_RECV", L"FIN_WAIT1", L"FIN_WAIT2",
                                           L"TIME_WAIT", L"CLOSE", L"CLOSE_WAIT", L"LAST_ACK", L"LISTEN", L"CLOSING",
                                           L"NEW_SYN_RECV", L"BOUND_INACTIVE"};
    return state < std::size(names) ? names[state] : std::to_wstring(state);
}

/* "addr:port", IPv6 as "[addr]:port" (as Endpoint writes them). */
std::wstring TcpAddress(unsigned family, const uint8_t* address, uint16_t port)
{
    char text[INET6_ADDRSTRLEN]{};
    if (family != AF_INET && family != AF_INET6) return L"family=" + std::to_wstring(family);
    inet_ntop(static_cast<int>(family), address, text, sizeof(text));
    return family == AF_INET6 ? L"[" + LinuxWide(text) + L"]:" + std::to_wstring(port)
                              : LinuxWide(text) + L":" + std::to_wstring(port);
}

/* One etw_tcp record, attributed to the socket tag's maker (wineserver under Wine; user_pid names the
 * game once it used the socket), never to the CPU's current task. Retransmissions are collapsed per
 * connection like syscall repeats; the counts still held go out before the connection's CLOSE record. */
void OnTcp(const mm_tcp_event& t)
{
    gBpf.session->Enter(MSMON_SENSOR_LINUX_EBPF_NET);
    mm_event e{};   /* the maker's identity for Record and Repeated; no stack, no PE context */
    e.kind = MM_TCP;
    e.nr = MM_SYSCALLS + MM_TCP;   /* 521, the Repeated key: never a syscall number */
    e.tgid = t.tgid;
    e.start_ns = t.start_ns;
    e.ts_ns = t.ts_ns;
    e.ret = t.sk_err != 0 ? -static_cast<int64_t>(t.sk_err) : 0;
    const std::wstring connection = std::to_wstring(t.tgid) + L"|" + std::to_wstring(e.nr) + L"|" +
                                    std::to_wstring(t.cookie) + L"|";
    if (t.what == MM_TCP_STATE && t.newstate == TCP_CLOSE && gTcpHeld.erase(t.cookie) != 0) FlushRepeats(e, connection);
    const TcpName name = TcpEventName(t.what, t.oldstate, t.newstate, t.sk_err, t.orphan != 0, t.shutdown, t.retransmits);
    const std::wstring text = TcpAddress(t.family, t.saddr, t.sport) + L" -> " + TcpAddress(t.family, t.daddr, ntohs(t.dport));
    std::wstring detail = L"event=" + std::wstring(name.name) +
                          (t.what == MM_TCP_STATE ? L";from=" + TcpState(t.oldstate) + L";to=" + TcpState(t.newstate)
                                                  : L";state=" + TcpState(t.newstate)) +
                          L";sock_ino=" + std::to_wstring(t.ino);
    if (t.owner != 0 && t.owner != t.tgid) detail += L";user_pid=" + std::to_wstring(t.owner);
    if (t.sk_err != 0) {
        const char* errno_name = strerrorname_np(static_cast<int>(t.sk_err));
        detail += L";err=" + (errno_name != nullptr ? LinuxWide(errno_name) : std::to_wstring(t.sk_err));
    }
    if (t.shutdown != 0) detail += L";shutdown=" + std::to_wstring(t.shutdown);
    if (t.orphan != 0) detail += L";orphan=1";
    if (t.what == MM_TCP_RST_OUT) {
        const size_t reason = static_cast<size_t>(static_cast<uint32_t>(t.reason));
        detail += L";reason=" + (reason < gRstReasons.size() && !gRstReasons[reason].empty() ? gRstReasons[reason]
                                                                                             : std::to_wstring(t.reason));
    }
    if (t.what == MM_TCP_RETRANS && t.reason != 0) detail += L";retransmit_err=" + std::to_wstring(t.reason);
    detail += L";rexmit=" + std::to_wstring(t.total_retrans) + L";srtt_us=" + std::to_wstring(t.srtt_us >> 3) +
              L";bytes_acked=" + std::to_wstring(t.bytes_acked) + L";bytes_received=" + std::to_wstring(t.bytes_received);
    if (t.what == MM_TCP_RETRANS) {
        gTcpHeld.insert(t.cookie);
        if (Repeated(e, "tcp_retransmit", MSMON_SENSOR_LINUX_EBPF_NET, MsMonEtwTcp, text, t.cookie, false, detail)) return;
    }
    Record(e, MSMON_SENSOR_LINUX_EBPF_NET, MsMonEtwTcp, name.id, t.cookie, text, detail, MsMonFlagObserverRecord);
}

void TcpRing(const void* data, size_t size)
{
    if (size < sizeof(mm_tcp_event)) return;
    mm_tcp_event t;
    std::memcpy(&t, data, sizeof(t));
    OnTcp(t);
}

int TcpOpened(std::wstring& detail, unsigned&)
{
    if (btf* vmlinux = btf__load_vmlinux_btf()) {
        const int id = btf__find_by_name_kind(vmlinux, "sk_rst_reason", BTF_KIND_ENUM);
        const btf_type* type = id > 0 ? btf__type_by_id(vmlinux, id) : nullptr;
        for (unsigned index = 0; type != nullptr && index < btf_vlen(type); index++) {
            /* "struct": in C++ the btf_enum() accessor hides the type name. */
            const struct btf_enum& value = btf_enum(type)[index];
            std::string name = btf__name_by_offset(vmlinux, value.name_off);
            if (name.rfind("SK_RST_REASON_", 0) == 0) name.erase(0, 14);
            if (value.val < 0 || value.val >= 256) continue;
            if (gRstReasons.size() <= static_cast<size_t>(value.val)) gRstReasons.resize(value.val + 1);
            gRstReasons[value.val] = LinuxWide(name);
        }
        btf__free(vmlinux);
    }
    gTcpOn = GroupOn("tcp") && Attached("mm_tcp_state");
    detail += gTcpOn ? L";tcp_lifecycle=on" : L";tcp_lifecycle=off";
    return 0;
}

void TcpClose()
{
    gRstReasons.clear();
    gTcpHeld.clear();
    gTcpOn = false;
}

void TcpNotes(Notes& notes)
{
    if (!gTcpOn) return;
    notes.push_back({L"tcp_lifecycle",
                     L"etw_tcp for TCP sockets known from their first tracked use since tracking began (created,"
                     L" connected, sent or received on, or accepted by a tracked process; a listener's connections"
                     L" from the handshake on); the record's process is the socket's first tracked user (under Wine"
                     L" wineserver, which connects and accepts for the prefix) and user_pid the game once it used it;"
                     L" value1 is the socket cookie (the pcapng comments' cookie), sock_ino joins socket:[ino];"
                     L" not seen: connections no tracked process touched, the TIME_WAIT/FIN_WAIT2 minisocket after"
                     L" close() (the remote FIN, FIN-WAIT-2 timeout) and resets sent for segments no socket owns"});
}

}  // namespace
