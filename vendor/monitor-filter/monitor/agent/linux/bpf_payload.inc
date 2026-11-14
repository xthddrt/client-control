/* Socket bytes and DNS (payload upgrade; docs/LINUX.md "Socket bytes and DNS"). Included by bpf.cpp at
 * global scope after Record/Repeated/FlushRepeats (MSMON_BPF builds only). payload.bpf.h sends the bytes
 * of each send/receive call on a network socket to payload_ring as mm_chunk records, before the call's
 * MM_SYSCALL record; OnSyscall takes them (TakePayload) and writes them as a network_data payload series
 * on the call's own I/O record (RecordPayload), then parses DNS from them (DnsRecords). bpf_up.inc's TLS records use
 * the same path (tls_plaintext series). */
#include <chrono>
#include <map>
#include <string>
#include <tuple>

/* DNS wire format (dns.cpp): one message as the etw_dns text and detail; false when Data is not one. */
bool DnsDescribe(const uint8_t* data, size_t size, std::wstring& name, std::wstring& detail, bool& response);
/* DNS over TCP: appends Bytes to Stream and returns the complete length-prefixed messages it holds. */
std::vector<std::string> DnsTcpTake(std::string& stream, const uint8_t* bytes, size_t size);

namespace {

/* One message of a call (one mmsghdr entry of sendmmsg/recvmmsg, else the call's bytes). */
struct PayloadMessage {
    uint64_t total = 0;       /* bytes the call moved for this message */
    uint64_t operation = 0;   /* operation_id once written */
    std::vector<BYTE> bytes;  /* captured, contiguous from 0 */
};
using PayloadMessages = std::map<uint32_t, PayloadMessage>;
struct PayloadPending {
    DWORD tgid = 0;
    uint64_t seen = 0;   /* bytes of the chunks that arrived, kept or not (compared with cap_bytes) */
    uint64_t held = 0;   /* bytes kept in messages */
    bool cut = false;    /* a chunk was dropped (cap): later ones are too, so gaps are only at the end */
    PayloadMessages messages;
};

ring_buffer* payloadRing = nullptr;   /* payload_ring; only with payload capture on */
/* Chunks of calls whose MM_SYSCALL record has not been handled yet, by (tid, ts_ns). */
std::map<std::pair<uint32_t, uint64_t>, PayloadPending> payloadChunks;
/* Bytes held in payloadChunks. Draining payload_ring moves its bytes into the heap, so the ring's own
 * bound is kept here: past it chunks are dropped and their calls logged partial or chunks_lost.
 * shortcut: one global cap, not per call; raise it if sessions show chunks_lost under load. */
uint64_t payloadHeld = 0;
constexpr uint64_t kPayloadHeldMax = 64ull << 20;
/* DNS over TCP: unfinished length-prefixed bytes per (tgid, socket inode, received). */
std::map<std::tuple<DWORD, uint64_t, bool>, std::string> dnsStreams;

/* payload_ring: one chunk of a call's bytes, kept until the call's record arrives. */
int OnChunk(void*, void* data, size_t size)
{
    const auto* chunk = static_cast<const mm_chunk*>(data);
    if (size < offsetof(mm_chunk, data) || chunk->len > MM_CHUNK || size < offsetof(mm_chunk, data) + chunk->len) return 0;
    PayloadPending& pending = payloadChunks[{chunk->tid, chunk->ts_ns}];
    pending.tgid = chunk->tgid;
    pending.seen += chunk->len;
    /* The kernel sends a call's chunks in order and stops at the first that does not fit; past the
     * held-bytes cap the rest of the call is dropped here the same way. */
    auto found = pending.messages.find(chunk->msg);
    if (pending.cut || payloadHeld + chunk->len > kPayloadHeldMax) {
        pending.cut = true;
        return 0;
    }
    if ((found == pending.messages.end() ? 0 : found->second.bytes.size()) != chunk->off) return 0;
    PayloadMessage& message = pending.messages[chunk->msg];
    message.total = chunk->msg_len;
    message.bytes.insert(message.bytes.end(), chunk->data, chunk->data + chunk->len);
    pending.held += chunk->len;
    payloadHeld += chunk->len;
    return 0;
}

/* Erases [First, Last) of payloadChunks, keeping payloadHeld. */
void ErasePending(std::map<std::pair<uint32_t, uint64_t>, PayloadPending>::iterator first,
                  std::map<std::pair<uint32_t, uint64_t>, PayloadPending>::iterator last)
{
    while (first != last) {
        payloadHeld -= first->second.held;
        first = payloadChunks.erase(first);
    }
}

/* The bytes the kernel sent for this call (MM_F_PAYLOAD), by message. Its chunks were committed
 * before its record and the copy thread publishes them before it, but ring_buffer__consume stops at the
 * first slot another CPU has reserved and not yet committed (busy bit), so later copy passes are waited
 * for until cap_bytes (what the kernel committed) have arrived, for at most 25 ms. Chunks of earlier calls of the same thread are orphans of a record
 * the full events ring lost and are dropped.
 * shortcut: orphans of a thread that makes no further payload call stay until its process exits
 * (bounded by kPayloadHeldMax). */
/* BPF thread: the chunks the copy thread has published so far, into payloadChunks. */
void DrainChunks()
{
    for (Raw& chunk : TakeQueued(gCopy.chunks)) OnChunk(nullptr, chunk.data(), chunk.size());
}

PayloadMessages TakePayload(const mm_event& e)
{
    if (payloadRing == nullptr) return {};
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(25);
    auto found = payloadChunks.end();
    for (;;) {
        DrainChunks();
        found = payloadChunks.find({e.tid, e.ts_ns});
        if ((found == payloadChunks.end() ? 0 : found->second.seen) >= e.cap_bytes ||
            std::chrono::steady_clock::now() >= deadline) {
            break;
        }
        WaitFullPass(deadline);
    }
    ErasePending(payloadChunks.lower_bound({e.tid, 0}), payloadChunks.lower_bound({e.tid, e.ts_ns}));
    if (found == payloadChunks.end()) return {};
    PayloadMessages messages = std::move(found->second.messages);
    ErasePending(found, std::next(found));
    return messages;
}

/* One end of the call's AF_INET/AF_INET6 socket (MM_F_SOCKID) as "address:port". */
std::wstring SocketAddress(const mm_event& e, bool remote)
{
    if ((e.flags & MM_F_SOCKID) == 0 || (e.sk_family != AF_INET && e.sk_family != AF_INET6)) return {};
    char text[INET6_ADDRSTRLEN]{};
    inet_ntop(e.sk_family, remote ? e.sk_raddr : e.sk_laddr, text, sizeof(text));
    const std::wstring port = std::to_wstring(remote ? e.sk_rport : e.sk_lport);
    return e.sk_family == AF_INET6 ? L"[" + LinuxWide(text) + L"]:" + port : LinuxWide(text) + L":" + port;
}

/* Why a call's capture ended short (MM_CAP_*); "truncated": its buffers held fewer bytes than it
 * reported (MSG_TRUNC). */
std::wstring CapStop(uint32_t stop)
{
    std::wstring text;
    for (const auto& [bit, name] : {std::pair{MM_CAP_LIMIT, L"limit"}, std::pair{MM_CAP_DROP, L"ring_full"},
                                    std::pair{MM_CAP_FAULT, L"fault"}, std::pair{MM_CAP_STEPS, L"steps"}}) {
        if ((stop & bit) != 0) text += (text.empty() ? L"" : L",") + std::wstring(name);
    }
    return text.empty() ? L"truncated" : text;
}

/* The I/O record of a call whose bytes were captured (MM_F_PAYLOAD): one payload series per
 * message, every chunk repeating the I/O metadata as MsMonLogPayloadSeries does on Windows, the
 * detail naming the socket's endpoints. Never collapsed by Repeated(). A call none of whose
 * bytes arrived is one record flagged payload_unavailable, its reason first in the detail. Keep: the bytes of a message
 * logged (--log-content's AF_UNIX and pipe bytes: one chunk), the rest partial with payload_stop=content_cap. */
void RecordPayload(const mm_event& e, PayloadMessages& messages, unsigned sensor, ULONG type, uint64_t value0,
                   uint64_t value1, const std::wstring& text, std::wstring detail, ULONG flags, bool sent,
                   ULONG kind = MsMonPayloadNetworkData, size_t keep = SIZE_MAX)
{
    if (!SocketAddress(e, false).empty()) detail += L";endpoints=" + SocketAddress(e, false) + L" -> " + SocketAddress(e, true);
    if (e.sk_family == AF_NETLINK) detail += L";netlink=" + std::to_wstring(e.sk_protocol);
    uint64_t stored = 0;
    for (const auto& [index, message] : messages) stored += message.bytes.size();
    /* Fewer bytes than the kernel committed: the agent lost chunks (held-bytes cap or busy ring). */
    const std::wstring stop = stored < e.cap_bytes ? L"chunks_lost" : CapStop(e.cap_stop);
    /* The reason leads the detail of a payload_unavailable record, as on Windows; sent bytes keep
     * payload_input as the driver's unavailable records do. */
    const std::wstring reason = L"payload_" + stop;
    const ULONG unavailable = flags | MsMonFlagPayloadUnavailable | (sent ? MsMonFlagPayloadInput : 0);
    if (messages.empty()) {
        Record(e, sensor, type, value0, value1, text, reason + L";" + detail, unavailable);
        return;
    }
    const bool many = e.nr == SYS_sendmmsg || e.nr == SYS_recvmmsg;
    for (auto& [index, message] : messages) {
        std::wstring part = detail + (many ? L";msg=" + std::to_wstring(index) : L"");
        const bool capped = message.bytes.size() > keep;
        if (capped) message.bytes.resize(keep);
        if (message.bytes.size() < message.total) {
            /* A partial series carries whole 8 KiB chunks only (verify_log.py): the captured tail
             * after the last whole chunk is counted as missing too. */
            message.bytes.resize(message.bytes.size() - message.bytes.size() % MSMON_PAYLOAD_CHUNK_BYTES);
            part += L";payload_missing=" + std::to_wstring(message.total - message.bytes.size()) + L";payload_stop=" +
                    (capped ? std::wstring(L"content_cap") : stop);
        }
        if (message.bytes.empty()) {
            Record(e, sensor, type, many ? message.total : value0, value1, text, reason + L";" + part, unavailable);
            continue;
        }
        LinuxRecord record = MakeRecord(e, sensor, type, many ? message.total : value0, value1, text, part,
                                        flags | (sent ? MsMonFlagPayloadInput : 0));
        record.operation = message.operation = gBpf.session->NextOperation();
        gBpf.session->WritePayloadSeries(record, kind, message.total, message.bytes);
    }
    /* The capture walks the messages in order and ended early: the messages after the last one with
     * bytes have no chunk (and no known size), so one record names them. Without a stop or loss,
     * missing indices are zero-length messages. */
    const uint64_t moved = std::min<uint64_t>(e.ret, MM_IOV_MAX);
    const uint64_t first = messages.rbegin()->first + 1;
    if (many && (e.cap_stop != 0 || stored < e.cap_bytes) && first < moved) {
        Record(e, sensor, type, 0, value1, text,
               reason + L";" + detail + L";msg_missing=" + std::to_wstring(first) + L"-" + std::to_wstring(moved - 1),
               unavailable);
    }
}

/* etw_dns records from a call's DNS messages (remote port 53: UDP one message per datagram, TCP
 * 2-byte length framing across calls), text and detail as the Windows DNS-Client records; value0
 * 3006 for a query, 3008 for a response; operation_id names the payload the message came from. */
void DnsRecords(const mm_event& e, PayloadMessages& messages, uint16_t port, const std::wstring& server, bool received)
{
    if (port != 53 || (e.sk_family != AF_INET && e.sk_family != AF_INET6)) return;
    const bool tcp = e.sk_type == SOCK_STREAM;
    const auto key = std::make_tuple(static_cast<DWORD>(e.tgid), static_cast<uint64_t>(e.ino), received);
    for (auto& [index, message] : messages) {
        (void)index;
        const bool complete = message.bytes.size() == message.total;
        std::vector<std::string> wires;
        if (!tcp && complete) wires.emplace_back(message.bytes.begin(), message.bytes.end());
        if (tcp && !complete) dnsStreams.erase(key);   /* a gap: the framing cannot be followed */
        if (tcp && complete) wires = DnsTcpTake(dnsStreams[key], message.bytes.data(), message.bytes.size());
        for (const std::string& wire : wires) {
            std::wstring name, detail;
            bool response = false;
            if (!DnsDescribe(reinterpret_cast<const uint8_t*>(wire.data()), wire.size(), name, detail, response)) continue;
            LinuxRecord record = MakeRecord(e, MSMON_SENSOR_LINUX_EBPF_NET, MsMonEtwDns, response ? 3008 : 3006, 0, name,
                                            detail + L";transport=" + (tcp ? L"tcp" : L"udp") + L";server=" + server,
                                            MsMonFlagObserverRecord);
            record.operation = message.operation;
            gBpf.session->Write(record);
        }
    }
}

/* Before every load attempt: with --no-payloads (and no --log-content) the ring is one page, so no 64 MiB is locked. */
void PayloadPrepare(bpf_object* object, bool payloads)
{
    if (!payloads && !gBpf.content) bpf_map__set_max_entries(bpf_object__find_map_by_name(object, "payload_ring"), 4096);
}

int PayloadOpened(std::wstring& detail, unsigned&)
{
    if (gBpf.payloads || gBpf.content) {
        payloadRing = ring_buffer__new(bpf_map__fd(bpf_object__find_map_by_name(gBpf.object, "payload_ring")), CopyChunk,
                                       nullptr, nullptr);
        if (payloadRing == nullptr) return errno != 0 ? errno : ENOMEM;
    }
    detail += L";payload=" + std::wstring(gBpf.payloads ? L"on" : L"off") + L";content=" + (gBpf.content ? L"on" : L"off") +
              L";payload_chunk=" + std::to_wstring(MM_CHUNK) + L";payload_call_max=" + std::to_wstring(MM_PAYLOAD_MAX);
    return 0;
}

/* Chunks whose record the full events ring lost would otherwise sit in payload_ring. */
void PayloadPoll()
{
    if (payloadRing != nullptr) DrainChunks();
}

void PayloadForget(const mm_event& e)
{
    for (auto it = payloadChunks.begin(); it != payloadChunks.end();) {
        auto next = std::next(it);
        if (it->second.tgid == e.tgid) ErasePending(it, next);
        it = next;
    }
    for (auto it = dnsStreams.begin(); it != dnsStreams.end();) {
        it = std::get<0>(it->first) == e.tgid ? dnsStreams.erase(it) : std::next(it);
    }
}

void PayloadClose()
{
    if (payloadRing != nullptr) ring_buffer__free(payloadRing);
    payloadRing = nullptr;
    payloadChunks.clear();
    payloadHeld = 0;
    dnsStreams.clear();
}

}  // namespace
