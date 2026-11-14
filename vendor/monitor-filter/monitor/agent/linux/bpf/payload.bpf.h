/* Socket byte capture (payload upgrade), included from monitor.bpf.c after fd_file().
 * sock_identity: resolve_fd calls it for a socket fd (fills sk_*, sets MM_F_SOCKID).
 * capture_payload: mm_sys_exit calls it for every recorded call before the record is reserved; it copies
 * the bytes a send/receive call on an AF_INET/AF_INET6/AF_NETLINK socket moved to payload_ring as
 * mm_chunk records (payload_bpf.h), which bpf_payload.inc joins to the call's record by (tid, ts_ns); with
 * MM_CFG_CONTENT (--log-content) those of an AF_UNIX socket or a pipe too (Wine's protocol pipes never reach it). */
#include <bpf/bpf_endian.h>

#define MM_MSG_PEEK 0x2   /* MSG_PEEK: the bytes stay queued and are read (and captured) again later */
#define MM_MSG_TRUNC 0x20 /* MSG_TRUNC on a stream socket: the kernel discards ret bytes, the buffer is untouched */

static __always_inline __u64 arg_at(struct mm_event* e, __u8 index);   /* monitor.bpf.c */

/* The bytes of send/receive calls on network sockets, as mm_chunk records. A ring of its own, so a
 * traffic burst cannot crowd the syscall records out of `events`; a full ring stops that call's
 * capture (MM_CAP_DROP) and costs no record. --no-payloads shrinks it to one page (bpf_payload.inc). */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 << 20);
} payload_ring SEC(".maps");

/* Walk state of the call being captured, and the chunk being sent. */
struct mm_capwalk {
    __u64 msgs;          /* user mmsghdr array (MM_DATA_MMSG), else 0 */
    __u64 iov;           /* user iovec array of the current message; 0 for MM_DATA_BUF */
    __u64 base;          /* user address of the next byte */
    __u64 left;          /* bytes at base still to send, bounded by msg_left */
    __u64 msg_left;      /* bytes of the current message not walked yet */
    __u32 nmsg;          /* mmsghdr entries to walk */
    __u32 next;          /* next mmsghdr entry */
    __u32 iovcnt;
    __u32 iovidx;        /* next iovec */
    __u32 budget;        /* bytes this call may still send (MM_PAYLOAD_MAX) */
    __u32 captured;
    __u32 stop;          /* MM_CAP_* */
    __u32 compat;        /* ia32 call: compat_mmsghdr (32 bytes), compat_msghdr and compat_iovec (8 bytes) layouts */
    struct mm_chunk k;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct mm_capwalk);
} capwalk SEC(".maps");

/* A socket fd's family, type, protocol and endpoints (MM_F_SOCKID). Called from mm_sys_enter (the call's
 * fd) and mm_sys_exit (an accepted fd). Verifier-safe: straight-line CO-RE reads of kernel memory and two
 * constant 16-byte probe reads, no loop; a static __noinline subprogram, so its few branches are
 * verified on their own and do not multiply the callers' states. */
static __noinline void sock_identity(struct mm_event* e, struct file* file)
{
    struct socket* sock = (struct socket*)BPF_CORE_READ(file, private_data);
    if (!sock) return;
    struct sock* sk = BPF_CORE_READ(sock, sk);
    if (!sk) return;
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    e->sk_family = family;
    e->sk_type = BPF_CORE_READ(sock, type);
    e->sk_protocol = BPF_CORE_READ(sk, sk_protocol);
    e->sk_lport = BPF_CORE_READ(sk, __sk_common.skc_num);
    e->sk_rport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    if (family == AF_INET) {
        __u32 local = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        __u32 remote = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        __builtin_memcpy(e->sk_laddr, &local, 4);
        __builtin_memcpy(e->sk_raddr, &remote, 4);
    } else if (family == AF_INET6) {
        bpf_probe_read_kernel(e->sk_laddr, 16, __builtin_preserve_access_index(&sk->__sk_common.skc_v6_rcv_saddr));
        bpf_probe_read_kernel(e->sk_raddr, 16, __builtin_preserve_access_index(&sk->__sk_common.skc_v6_daddr));
    }
    e->flags |= MM_F_SOCKID;
}

/* One step of a call's payload walk: load the next mmsghdr entry, load the next iovec, or send up
 * to MM_CHUNK bytes to payload_ring. Returns 1 to end the walk. Verifier-safe: no loop inside; the
 * walk state lives in the per-CPU capwalk map value, so every field is an unknown scalar on each
 * step (nothing loop-carried for the verifier to track; the callback is verified once); every
 * length is clamped to [0, MM_CHUNK] right before use; user memory is only read with
 * bpf_probe_read_user into that map value. */
static long cap_step(__u32 index, void* unused)
{
    __u32 zero = 0;
    struct mm_capwalk* w = bpf_map_lookup_elem(&capwalk, &zero);
    if (!w) return 1;
    if (w->msg_left == 0) {
        struct mmsghdr m = {};
        if (!w->msgs || w->next >= w->nmsg) return 1;
        long fault;
        if (w->compat) {
            __u32 c[8];   /* compat_mmsghdr: name, namelen, iov, iovlen, control, controllen, flags, msg_len */
            fault = bpf_probe_read_user(c, sizeof(c), (const void*)(w->msgs + (__u64)w->next * sizeof(c)));
            m.msg_hdr.msg_iov = (struct iovec*)(__u64)c[2];
            m.msg_hdr.msg_iovlen = c[3];
            m.msg_len = c[7];
        } else {
            fault = bpf_probe_read_user(&m, sizeof(m), (const void*)(w->msgs + (__u64)w->next * sizeof(m)));
        }
        if (fault != 0) {
            w->stop |= MM_CAP_FAULT;
            return 1;
        }
        w->k.msg = w->next++;
        w->k.off = 0;
        w->k.msg_len = m.msg_len;
        w->msg_left = m.msg_len;
        w->iov = (__u64)m.msg_hdr.msg_iov;
        w->iovcnt = m.msg_hdr.msg_iovlen > MM_IOV_MAX ? MM_IOV_MAX : (__u32)m.msg_hdr.msg_iovlen;
        w->iovidx = 0;
        w->left = 0;
        return 0;
    }
    if (w->left == 0) {
        struct iovec v = {};
        if (w->iovidx >= w->iovcnt) {
            w->msg_left = 0;     /* the buffers hold less than the call reported (MSG_TRUNC) */
            return 0;
        }
        long fault;
        if (w->compat) {
            __u32 c[2];   /* compat_iovec */
            fault = bpf_probe_read_user(c, sizeof(c), (const void*)(w->iov + (__u64)w->iovidx * sizeof(c)));
            v.iov_base = (void*)(__u64)c[0];
            v.iov_len = c[1];
        } else {
            fault = bpf_probe_read_user(&v, sizeof(v), (const void*)(w->iov + (__u64)w->iovidx * sizeof(v)));
        }
        if (fault != 0) {
            w->stop |= MM_CAP_FAULT;
            return 1;
        }
        w->iovidx++;
        w->base = (__u64)v.iov_base;
        w->left = v.iov_len < w->msg_left ? v.iov_len : w->msg_left;
        return 0;
    }
    if (w->budget == 0) {
        w->stop |= MM_CAP_LIMIT;
        return 1;
    }
    __u64 n = w->left < w->budget ? w->left : w->budget;
    barrier_var(n);
    if (n > MM_CHUNK) n = MM_CHUNK;
    if (bpf_probe_read_user(w->k.data, n, (const void*)w->base) != 0) {
        w->stop |= MM_CAP_FAULT;
        return 1;
    }
    w->k.len = (__u32)n;
    if (bpf_ringbuf_output(&payload_ring, &w->k, offsetof(struct mm_chunk, data) + n, BPF_RB_NO_WAKEUP) != 0) {
        w->stop |= MM_CAP_DROP;
        return 1;
    }
    w->base += n;
    w->left -= n;
    w->msg_left -= n;
    w->k.off += (__u32)n;
    w->budget -= (__u32)n;
    w->captured += (__u32)n;
    return 0;
}

/* The bytes a send/receive call moved (ret > 0) on a network socket to payload_ring, at most
 * MM_PAYLOAD_MAX; sets MM_F_PAYLOAD and cap_*. MSG_PEEK calls are left out (wineserver peeks 1 byte on
 * every POLLIN; the bytes are read again), and so are MSG_TRUNC receives on a stream socket (TCP drops
 * the bytes without copying them, so the buffer holds stale data). Verifier-safe: straight-line set-up, one constant-size user
 * read (the msghdr) and one bpf_loop with the constant bound MM_CAP_WALK; no loop of its own. */
static __always_inline void capture_payload(struct mm_event* p, const struct mm_sysinfo* info, long ret)
{
    __u8 data = info->data;
    if (!data || ret <= 0) return;
    const int socket = (p->flags & MM_F_SOCKID) != 0;
    const int network = socket && (p->sk_family == AF_INET || p->sk_family == AF_INET6 || p->sk_family == AF_NETLINK);
    if (!network && !(socket && p->sk_family == AF_UNIX) && (p->mode & S_IFMT) != S_IFIFO) return;
    struct mm_config* c = cfg();
    if (!c || !(c->flags & (network ? MM_CFG_PAYLOAD : MM_CFG_CONTENT))) return;
    if (info->flags_arg) {
        __u64 msgflags = arg_at(p, info->flags_arg);
        if ((msgflags & MM_MSG_PEEK) || ((msgflags & MM_MSG_TRUNC) && p->sk_type == SOCK_STREAM)) return;
    }
    __u32 zero = 0;
    struct mm_capwalk* w = bpf_map_lookup_elem(&capwalk, &zero);
    if (!w) return;
    w->msgs = 0;
    w->iov = 0;
    w->base = 0;
    w->left = 0;
    w->msg_left = (__u64)ret;
    w->nmsg = 0;
    w->next = 0;
    w->iovcnt = 0;
    w->iovidx = 0;
    w->budget = MM_PAYLOAD_MAX;
    w->captured = 0;
    w->stop = 0;
    w->compat = (p->flags & MM_F_COMPAT) != 0;
    w->k.tid = p->tid;
    w->k.tgid = p->tgid;
    w->k.ts_ns = p->ts_ns;
    w->k.msg = 0;
    w->k.off = 0;
    w->k.msg_len = (__u32)ret;
    if (data == MM_DATA_BUF) {
        w->base = p->args[1];
        w->left = (__u64)ret < p->args[2] ? (__u64)ret : p->args[2];
    } else if (data == MM_DATA_IOV) {
        w->iov = p->args[1];
        w->iovcnt = p->args[2] > MM_IOV_MAX ? MM_IOV_MAX : (__u32)p->args[2];
    } else if (data == MM_DATA_MSG) {
        struct user_msghdr h = {};
        long fault;
        if (w->compat) {
            __u32 c[4];   /* compat_msghdr: name, namelen, iov, iovlen */
            fault = bpf_probe_read_user(c, sizeof(c), (const void*)p->args[1]);
            h.msg_iov = (struct iovec*)(__u64)c[2];
            h.msg_iovlen = c[3];
        } else {
            fault = bpf_probe_read_user(&h, sizeof(h), (const void*)p->args[1]);
        }
        if (fault != 0) {
            w->stop = MM_CAP_FAULT;
            w->msg_left = 0;
        } else {
            w->iov = (__u64)h.msg_iov;
            w->iovcnt = h.msg_iovlen > MM_IOV_MAX ? MM_IOV_MAX : (__u32)h.msg_iovlen;
        }
    } else if (data == MM_DATA_MMSG) {
        w->msgs = p->args[1];
        w->nmsg = ret > MM_IOV_MAX ? MM_IOV_MAX : (__u32)ret;
        w->msg_left = 0;
        w->k.msg_len = 0;
    } else {
        return;
    }
    if (w->msg_left != 0 || w->nmsg != 0) bpf_loop(MM_CAP_WALK, cap_step, 0, 0);
    if (w->stop == 0 && (w->msg_left != 0 || w->next < w->nmsg)) w->stop = MM_CAP_STEPS;
    p->cap_bytes = w->captured;
    p->cap_stop = w->stop;
    p->flags |= MM_F_PAYLOAD;
}

/* Ret bytes of one user buffer at Base to payload_ring, as capture_payload does for a send/receive call (up.bpf.h:
 * the plaintext of a TLS record call). Same walk, so the same verifier argument; no msghdr or iovec. */
static __always_inline void capture_buffer(struct mm_event* p, __u64 base, long ret)
{
    struct mm_config* c = cfg();
    if (!c || !(c->flags & MM_CFG_PAYLOAD) || ret <= 0) return;
    __u32 zero = 0;
    struct mm_capwalk* w = bpf_map_lookup_elem(&capwalk, &zero);
    if (!w) return;
    w->msgs = 0;
    w->iov = 0;
    w->base = base;
    w->left = (__u64)ret;
    w->msg_left = (__u64)ret;
    w->nmsg = 0;
    w->next = 0;
    w->iovcnt = 0;
    w->iovidx = 0;
    w->budget = MM_PAYLOAD_MAX;
    w->captured = 0;
    w->stop = 0;
    w->compat = 0;
    w->k.tid = p->tid;
    w->k.tgid = p->tgid;
    w->k.ts_ns = p->ts_ns;
    w->k.msg = 0;
    w->k.off = 0;
    w->k.msg_len = (__u32)ret;
    bpf_loop(MM_CAP_WALK, cap_step, 0, 0);
    if (w->stop == 0 && w->msg_left != 0) w->stop = MM_CAP_STEPS;
    p->cap_bytes = w->captured;
    p->cap_stop = w->stop;
    p->flags |= MM_F_PAYLOAD;
}
