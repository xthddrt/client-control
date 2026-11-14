/*
 * Packet capture (packets upgrade, docs/LINUX.md "Packet capture"). cgroup_skb programs attached to the
 * cgroup v2 root (a BPF_F_ALLOW_MULTI link, bpf.cpp) see every IP packet of the machine; packets of
 * sockets tagged in mm_socks (socks.bpf.h, included just before this file) are copied to pkts. Both
 * programs always return 1: a monitor never drops or alters traffic.
 * Runs in softirq: uses no scratch, walkbuf, capwalk or ws_scratch (per-CPU state a syscall program
 * on the same CPU could be using).
 * Helpers, all allowed for BPF_PROG_TYPE_CGROUP_SKB (cg_skb_func_proto, 7.0): bpf_sk_fullsock,
 * bpf_sk_storage_get, bpf_get_socket_cookie, bpf_skb_load_bytes, bpf_ringbuf_reserve/submit/discard,
 * bpf_ktime_get_boot_ns, bpf_map_lookup_elem.
 */
_Static_assert(sizeof(struct mm_pkt) == 48, "struct mm_pkt is shared with packets.cpp");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 32 << 20);
} pkts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} pkt_drops SEC(".maps");

/* Verifier-safe: one constant-key lookup, a null check, one atomic add. */
static __always_inline void count_pkt_drop(void)
{
    __u32 zero = 0;
    __u64* value = bpf_map_lookup_elem(&pkt_drops, &zero);
    if (value) __sync_fetch_and_add(value, 1);
}

/* One ring record per packet. Verifier-safe: Size is a constant at each inlined call, so the
 * reservation is constant; cap is re-checked against [1, Size] on the register the helper gets, so
 * bpf_skb_load_bytes' length is bounded by the reserved memory; the record is submitted or discarded
 * on every path; no loops. */
static __always_inline void emit_packet(struct __sk_buff* skb, const struct mm_pkt* h, __u32 cap, const __u32 size)
{
    struct mm_pkt* e = bpf_ringbuf_reserve(&pkts, sizeof(*e) + size, 0);
    if (!e) {
        count_pkt_drop();
        return;
    }
    *e = *h;
    e->cap_len = cap;
    if (cap == 0 || cap > size || bpf_skb_load_bytes(skb, 0, (void*)(e + 1), cap) < 0) {
        bpf_ringbuf_discard(e, 0);
        count_pkt_drop();
        return;
    }
    bpf_ringbuf_submit(e, 0);
}

/* Packets of tagged sockets, both directions. The packet starts at the IP header in cgroup_skb
 * programs; an egress SYN-ACK of a request socket arrives with its listener as skb->sk (the kernel
 * passes sk_to_full_sk). Verifier-safe: no loops; a fixed chain of null checks; stores into the
 * 48-byte tag at constant offsets; four constant-size emit_packet reservations (128 B, 2 KiB, 16 KiB,
 * 64 KiB) so a small packet does not reserve 64 KiB of ring.
 * shortcut: a socket only wineserver used is captured up to MM_PENDING_MAX bytes until the game uses
 * it (the rest counted in skipped), raise it if pending_skipped shows up for game sockets. */
static __always_inline int capture(struct __sk_buff* skb, __u16 dir)
{
    struct bpf_sock* sk = skb->sk;
    if (!sk) return 1;
    sk = bpf_sk_fullsock(sk);
    if (!sk) return 1;
    struct mm_sock* s = bpf_sk_storage_get(&mm_socks, sk, 0, 0);
    if (!s) return 1;
    const __u64 cookie = bpf_get_socket_cookie(skb);
    own_tag(s, cookie);
    const __u32 len = skb->len;
    if (len == 0) return 1;
    if (!s->owner) {
        if (s->pending >= MM_PENDING_MAX) {
            __sync_fetch_and_add(&s->skipped, 1);
            return 1;
        }
        __sync_fetch_and_add(&s->pending, len);
    }
    struct mm_pkt h = {};
    h.ts_ns = bpf_ktime_get_boot_ns();
    h.cookie = cookie;
    h.ino = s->ino;
    h.owner = s->owner;
    h.server = s->server;
    h.len = len;
    h.skipped = s->skipped;
    h.dir = dir;
    h.gso_segs = skb->gso_segs;
    if (len <= 128) emit_packet(skb, &h, len, 128);
    else if (len <= 2048) emit_packet(skb, &h, len, 2048);
    else if (len <= 16384) emit_packet(skb, &h, len, 16384);
    else emit_packet(skb, &h, len < MM_PKT_MAX ? len : MM_PKT_MAX, MM_PKT_MAX);
    return 1;
}

SEC("cgroup_skb/egress")
int mm_skb_egress(struct __sk_buff* skb)
{
    return capture(skb, MM_PKT_OUT);
}

SEC("cgroup_skb/ingress")
int mm_skb_ingress(struct __sk_buff* skb)
{
    return capture(skb, MM_PKT_IN);
}
