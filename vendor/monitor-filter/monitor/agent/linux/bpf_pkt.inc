/* Packet capture hooks (packets upgrade, docs/LINUX.md "Packet capture"); included by bpf.cpp. The pkts
 * ring is copied with the events ring (gBpf.ring, CopyRun) and taken on the BPF thread; packets.cpp writes
 * the pcapng parts. */
#include "packets.h"

namespace {

int gPktDrops = -1;   /* pkt_drops map fd while capture runs */
bool gPktDetached = false;

/* No capture or no more capture: destroy whichever mm_skb_* link is attached (never one direction). */
void PktDetach()
{
    for (auto link = gBpf.links.begin(); link != gBpf.links.end();) {
        if (link->first.rfind("mm_skb_", 0) == 0) {
            bpf_link__destroy(link->second);
            link = gBpf.links.erase(link);
        } else {
            ++link;
        }
    }
}

int OnPacket(void*, void* data, size_t size)
{
    const auto* packet = static_cast<const mm_pkt*>(data);
    if (size < sizeof(mm_pkt) || packet->cap_len > size - sizeof(mm_pkt)) return 0;
    PacketsAdd(*packet, reinterpret_cast<const unsigned char*>(packet + 1), BootToFileTime(packet->ts_ns));
    return 0;
}

bool PktWanted()
{
    return !PacketsPath().empty();
}

void PktPrepare(bpf_object* object, bool on)
{
    if (!on) bpf_map__set_autocreate(bpf_object__find_map_by_name(object, "pkts"), false);
}

int PktOpened(std::wstring& detail, unsigned&)
{
    bpf_map* ring = gBpf.object != nullptr ? bpf_object__find_map_by_name(gBpf.object, "pkts") : nullptr;
    int error = 0;
    bool openFailed = false;   /* PacketsStart could not open the pcapng and already named why */
    if (GroupOn("packets") && Attached("mm_skb_egress") && Attached("mm_skb_ingress") && ring != nullptr) {
        if (ring_buffer__add(gBpf.ring, bpf_map__fd(ring), CopyPacket, nullptr) == 0) {
            if (PacketsStart(0, {})) {
                gPktDrops = bpf_map__fd(bpf_object__find_map_by_name(gBpf.object, "pkt_drops"));
                detail += L";packets=on";
                return 0;
            }
            openFailed = true;   /* the ring stays added; nothing will fill it */
        } else {
            error = errno != 0 ? errno : EIO;
        }
    }
    PktDetach();
    if (!PacketsPath().empty() && !openFailed) {
        const std::wstring reason = error != 0              ? L"ring_buffer__add failed"
                                    : !GroupOn("packets")    ? L"the packets program group did not load (see ebpf_active optional=)"
                                                             : L"mm_skb_egress or mm_skb_ingress did not attach to /sys/fs/cgroup";
        PacketsStart(error != 0 ? error : EOPNOTSUPP, reason);
    }
    detail += L";packets=off";
    return 0;
}

/* A close counts as the socket's end only when its maker closes it (PacketsPolled): the game closes
 * per-call fds of wineserver's sockets (socket_join.h), which must not drop their held handshake.
 * shortcut: the maker's close of one fd ends the socket (wineserver holds one fd per socket for the
 * object's life; ia32 closes are not seen and wait for the final drain), track the socket's
 * destruction (an fentry on sk_destruct) if held packets of live sockets show up dropped. */
void PktSyscall(const mm_event& e, const Syscall& call)
{
    if (call.op == Op::Close && S_ISSOCK(e.mode)) PacketsSocketClosed(e.ino, e.tgid);
}

void PktPoll()
{
    if (gPktDrops < 0) return;
    if (!gPktDetached && PacketsStopping()) {   /* the final drain: no new packets from here on */
        PktDetach();
        gPktDetached = true;
        /* Packets the kernel queued before the detach are published by the next full copy pass. */
        WaitFullPass(std::chrono::steady_clock::now() + std::chrono::seconds(2));
    }
    /* Take every packet published so far before this round's closes take effect: the copy thread
     * publishes a pass's packets before its events, so a socket's last packets precede its close. */
    for (Raw& packet : TakeQueued(gCopy.packets)) OnPacket(nullptr, packet.data(), packet.size());
    const int cpus = libbpf_num_possible_cpus();
    if (cpus <= 0) return;
    std::vector<uint64_t> values(static_cast<size_t>(cpus));
    const uint32_t zero = 0;
    if (bpf_map_lookup_elem(gPktDrops, &zero, values.data()) != 0) return;
    uint64_t total = 0;
    for (uint64_t value : values) total += value;
    PacketsKernelDrops(total);
    PacketsPolled(gPktDetached);
}

void PktClose()
{
    gPktDrops = -1;
    gPktDetached = false;
}

}  // namespace
