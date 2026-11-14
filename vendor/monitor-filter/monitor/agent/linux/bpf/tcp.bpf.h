/*
 * TCP lifecycle (tcp upgrade, docs/LINUX.md "TCP lifecycle"): state changes, accepts, resets and
 * retransmissions of the TCP sockets socks.bpf.h tagged, as MM_TCP records (struct mm_tcp_event).
 * Optional group "tcp" (needs "socks"). Most of these run in softirq context: the process comes from
 * the socket's tag, never from current, and no per-CPU scratch map is used.
 *
 * shortcut: a connection no tracked process created, connected, sent, received on or accepted since
 * tracking began has no tag and is not followed; seed mm_socks from sock_diag if those matter.
 * shortcut: after close() the TIME_WAIT/FIN_WAIT2 minisocket replaces the socket (no tag: the remote
 * FIN after close, FIN-WAIT-2 timeouts and resets it sends are not seen); follow
 * inet_twsk_* if a session needs them.
 * shortcut: records belong to the tag's maker (wineserver under Wine, which connects and accepts for
 * the prefix) with user_pid=<owner> once the game used the socket; attribute to the requesting
 * client when the wineserver upgrade's request view is joined in.
 */

/* The socket's tag, or 0 when no tracked process used it. Verifier-safe: one bpf_sk_storage_get
 * without F_CREATE (allowed in tp_btf, BPF_TRACE_RAW_TP, and in LSM programs; it returns NULL in
 * hardirq/NMI and for non-full sockets, so the timewait/request socks tcp_send_reset may pass are
 * never dereferenced as tcp_sock), one bpf_get_socket_cookie, stores at constant offsets of the
 * 48-byte value; sk is the program's trusted BTF argument, NULL-checked by every caller. */
static __always_inline struct mm_sock* tcp_tag(const struct sock* sk)
{
    struct mm_sock* s = bpf_sk_storage_get(&mm_socks, (struct sock*)sk, 0, 0);
    if (!s || !s->maker) return 0;
    own_tag(s, bpf_get_socket_cookie((void*)sk));
    return s;
}

/* One MM_TCP record. Verifier-safe: no loop, one constant 128-byte ringbuf reserve submitted on the
 * only path, writes at constant offsets, kernel fields read through bpf_probe_read_kernel
 * (BPF_CORE_READ); a timewait or request sock has only sock_common, so nothing past it is read for
 * those (the skc_state gate; tcp_tag already refuses them). */
static __always_inline void emit_tcp(const struct sock* sk, const struct mm_sock* s, __u32 what, int oldstate,
                                     int newstate, int reason)
{
    struct mm_tcp_event* e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        count_drop();
        return;
    }
    __builtin_memset(e, 0, sizeof(*e));
    e->kind = MM_TCP;
    e->what = what;
    e->tgid = s->maker;
    e->owner = s->owner;
    e->start_ns = s->maker_start;
    e->ino = s->ino;
    e->cookie = s->cookie;
    e->ts_ns = bpf_ktime_get_boot_ns();
    e->oldstate = oldstate;
    e->newstate = newstate;
    e->reason = reason;
    e->family = BPF_CORE_READ(sk, __sk_common.skc_family);
    e->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    e->dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    if (e->family == AF_INET6) {
        BPF_CORE_READ_INTO(&e->saddr, sk, __sk_common.skc_v6_rcv_saddr);
        BPF_CORE_READ_INTO(&e->daddr, sk, __sk_common.skc_v6_daddr);
    } else {
        __be32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        __be32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        __builtin_memcpy(e->saddr, &saddr, 4);
        __builtin_memcpy(e->daddr, &daddr, 4);
    }
    int state = BPF_CORE_READ(sk, __sk_common.skc_state);
    if (state != TCP_TIME_WAIT && state != TCP_NEW_SYN_RECV) {
        const struct tcp_sock* tp = (const struct tcp_sock*)sk;
        e->sk_err = BPF_CORE_READ(sk, sk_err);
        e->shutdown = BPF_CORE_READ(sk, sk_shutdown);
        e->orphan = BPF_CORE_READ(sk, sk_socket) == 0;
        e->retransmits = BPF_CORE_READ((const struct inet_connection_sock*)sk, icsk_retransmits);
        e->total_retrans = BPF_CORE_READ(tp, total_retrans);
        e->srtt_us = BPF_CORE_READ(tp, srtt_us);
        e->bytes_acked = BPF_CORE_READ(tp, bytes_acked);
        e->bytes_received = BPF_CORE_READ(tp, bytes_received);
    }
    bpf_ringbuf_submit(e, 0);
}

/* Every state change of a tagged TCP socket (connect's CLOSE -> SYN_SENT included: lsm/socket_connect
 * tagged it in the caller first; a listener's children carry its cloned tag from SYN_RECV on). The
 * tracepoint is generic (MPTCP and SCTP fire it too; tag_sk tags any INET socket), so other protocols
 * are skipped before their sock is read as tcp_sock. Verifier-safe: NULL check, one direct BTF load
 * of the trusted sk, tcp_tag, emit_tcp; straight-line. */
SEC("tp_btf/inet_sock_set_state")
int BPF_PROG(mm_tcp_state, const struct sock* sk, const int oldstate, const int newstate)
{
    if (!sk || sk->sk_protocol != IPPROTO_TCP) return 0;
    struct mm_sock* s = tcp_tag(sk);
    if (s) emit_tcp(sk, s, MM_TCP_STATE, oldstate, newstate, 0);
    return 0;
}

/* accept() grafts the new socket onto its struct socket in the accepting process (a void hook:
 * returns 0); tag_sk tags it when that process is tracked. Verifier-safe: NULL checks, one direct
 * BTF load of the trusted sk, tag_sk (socks.bpf.h, no loop), emit_tcp. */
SEC("lsm/sock_graft")
int BPF_PROG(mm_tcp_accept, struct sock* sk, struct socket* parent)
{
    if (!sk || !parent || sk->sk_protocol != IPPROTO_TCP) return 0;
    struct mm_sock* s = tag_sk(sk, parent);
    if (s) {
        int state = BPF_CORE_READ(sk, __sk_common.skc_state);
        emit_tcp(sk, s, MM_TCP_ACCEPT, state, state, 0);
    }
    return 0;
}

/* A RST arrived; the state is still the one it arrived in. Verifier-safe: NULL check, tcp_tag, emit_tcp. */
SEC("tp_btf/tcp_receive_reset")
int BPF_PROG(mm_tcp_rst_in, struct sock* sk)
{
    if (!sk) return 0;
    struct mm_sock* s = tcp_tag(sk);
    if (s) {
        int state = BPF_CORE_READ(sk, __sk_common.skc_state);
        emit_tcp(sk, s, MM_TCP_RST_IN, state, state, 0);
    }
    return 0;
}

/* sk is NULL for a RST to a segment no socket owns, and may be a timewait or request sock (tcp_tag
 * returns 0 for those). Verifier-safe: NULL check, tcp_tag, emit_tcp. */
SEC("tp_btf/tcp_send_reset")
int BPF_PROG(mm_tcp_rst_out, const struct sock* sk, const struct sk_buff* skb, const enum sk_rst_reason reason)
{
    if (!sk) return 0;
    struct mm_sock* s = tcp_tag(sk);
    if (s) {
        int state = BPF_CORE_READ(sk, __sk_common.skc_state);
        emit_tcp(sk, s, MM_TCP_RST_OUT, state, state, reason);
    }
    return 0;
}

/* One retransmitted segment (the agent collapses storms). Verifier-safe: NULL check, tcp_tag, emit_tcp. */
SEC("tp_btf/tcp_retransmit_skb")
int BPF_PROG(mm_tcp_retrans, const struct sock* sk, const struct sk_buff* skb, int err)
{
    if (!sk) return 0;
    struct mm_sock* s = tcp_tag(sk);
    if (s) {
        int state = BPF_CORE_READ(sk, __sk_common.skc_state);
        emit_tcp(sk, s, MM_TCP_RETRANS, state, state, err);
    }
    return 0;
}
