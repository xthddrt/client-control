/*
 * Desktop services over AF_UNIX (unix_bpf.h): mm_sys_exit's unix_head. A tracked process's AF_UNIX connect puts its
 * socket in unix_svc, pending; the first send says whether it opens an X11, D-Bus or PulseAudio connection (else the
 * socket leaves). On such a connection every send and receive (write, writev, sendto, sendmsg, sendmmsg; read, readv,
 * recvfrom, recvmsg, recvmmsg) has its bytes gathered over all its iovecs and messages, at most MM_UNIX_HEAD of them,
 * after the header part the previous call ended inside (unix_gather), and every message in them is framed
 * (mm_unix_frame) and counted per (socket, op) in agg, a run of one op as one count (unix_walk); a message the call
 * only began is passed over in the next calls, a header it cut is carried to the next.
 * - X11 and PulseAudio: a send's op that is the first since the agent last drained agg is sampled, and a call with
 *   sampled ops sends its bytes to the agent as an MM_UNIX head (bpf.cpp names the ops and decodes their fields): per
 *   socket and op a second, one record and one summary, at any rate. Receives are summaries only.
 * - D-Bus (an op is its strings; here its type): a call's messages are listed in a head, both ways, at most
 *   MM_UNIX_DBUS_HEADS heads a second per socket (the messages past them are counted); the SASL handshake's lines
 *   before (MM_UNIX_S_TEXT_*) are counted as MM_UNIX_DBUS_SASL, their calls sent raw.
 * Bytes the walk does not reach (past MM_UNIX_HEAD or MM_UNIX_STEPS) are counted as MM_UNIX_OP_UNPARSED. The gather and
 * the walk are global functions keeping their state in the per-CPU unix_scratch (their bpf_loop callbacks read it
 * there), so their verification does not multiply with unix_head's paths. Reuses events, count_drop, count_loss,
 * agg_add, arg_at.
 */
#define MM_MSG_PEEK_UNIX 0x2

/* Not LRU: a full map refuses a connect (MM_LOSS_UNIX_FULL) instead of dropping a live connection's state unseen; a
 * connection's state leaves with its socket (mm_unix_release) or at its first send when it opens no service. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct mm_unix_sock);
} unix_svc SEC(".maps");

/* The gather's walk of the call's buffers, as payload.bpf.h's capwalk: mmsghdr entries, their iovecs, the bytes. */
struct unix_gather {
    __u64 msgs;       /* mmsghdr array (sendmmsg, recvmmsg), else 0 */
    __u64 iov;        /* iovec array of the current message; 0: one buffer (base, left) */
    __u64 base;
    __u64 left;       /* bytes at base, bounded by msg_left */
    __u64 msg_left;   /* bytes of the current message not walked yet */
    __u64 skip;       /* bytes still to pass over: the rest of a message the previous call began */
    __u64 bytes;      /* bytes of the call's messages (mmsg: summed from msg_len) */
    __u32 nmsg, next, iovcnt, iovidx;
    __u32 len;        /* bytes in head.data */
    __u32 cap;        /* len's limit: the carried part + MM_UNIX_HEAD */
    __u32 compat;
    __u32 pad;
};

/* The framing walk over head.data and the run of one op it has not counted yet. */
struct unix_walk {
    __u64 at;          /* the next message's start in head.data */
    __u64 ino;
    __u64 run_bytes;
    __u64 run_first;   /* bytes of the run's first message (a sampled one is left out of the count) */
    __u32 nr;          /* agg nr: MM_COUNT_UNIX | svc | MM_UNIX_RX */
    __u32 svc, rx, big;
    __u32 list;        /* D-Bus within its heads: every message listed in head.op (up to MM_UNIX_SAMPLED), not counted */
    __u32 incomplete;  /* stopped at a header the head does not hold */
    __u32 lost;        /* stopped at bytes that are no message */
    __u32 run_op, run_n, run_at;
    __u32 sampled;     /* entries in head.op */
    __u32 pad;
};

/* One per CPU (about 8 KB: too big for the stack): the head, and the gather's and the walk's state. */
struct unix_work {
    struct mm_unix_head head;
    struct unix_gather g;
    struct unix_walk w;
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct unix_work);
} unix_scratch SEC(".maps");

static __always_inline struct unix_work* unix_work(void)
{
    __u32 zero = 0;
    return bpf_map_lookup_elem(&unix_scratch, &zero);
}

/* bpf_loop callback: one step of the gather (load an mmsghdr entry, load an iovec, pass over skipped bytes, or copy
 * into head.data). Verifier-safe: no loop inside; the offset is compared below MM_UNIX_HEAD + MM_UNIX_PART and the
 * length clamped to MM_UNIX_HEAD after a barrier, so every copy ends inside data[]. */
static long unix_gather_step(__u32 index, void* unused)
{
    struct unix_work* k = unix_work();
    if (!k) return 1;
    struct unix_gather* g = &k->g;
    if (g->msg_left == 0) {
        if (!g->msgs || g->next >= g->nmsg) return 1;
        __u64 iov = 0, count = 0, length = 0;
        if (g->compat) {
            __u32 c[8];   /* compat_mmsghdr: name, namelen, iov, iovlen, control, controllen, flags, msg_len */
            if (bpf_probe_read_user(c, sizeof(c), (const void*)(g->msgs + (__u64)g->next * sizeof(c)))) return 1;
            iov = c[2], count = c[3], length = c[7];
        } else {
            struct mmsghdr m = {};
            if (bpf_probe_read_user(&m, sizeof(m), (const void*)(g->msgs + (__u64)g->next * sizeof(m)))) return 1;
            iov = (__u64)m.msg_hdr.msg_iov, count = m.msg_hdr.msg_iovlen, length = m.msg_len;
        }
        g->next++;
        g->bytes += length;
        g->msg_left = length;
        g->iov = iov;
        g->iovcnt = count > MM_IOV_MAX ? MM_IOV_MAX : (__u32)count;
        g->iovidx = 0;
        g->left = 0;
        return 0;
    }
    if (g->len >= g->cap && !g->skip) {
        if (!g->msgs) return 1;
        g->msg_left = 0;   /* the head is full: only the other messages' lengths are summed */
        return 0;
    }
    if (g->left == 0) {
        if (!g->iov || g->iovidx >= g->iovcnt) {
            g->msg_left = 0;   /* the buffers hold less than the call reported */
            return 0;
        }
        __u64 base = 0, length = 0;
        if (g->compat) {
            __u32 c[2];   /* compat_iovec */
            if (bpf_probe_read_user(c, sizeof(c), (const void*)(g->iov + (__u64)g->iovidx * sizeof(c)))) return 1;
            base = c[0], length = c[1];
        } else {
            struct iovec v = {};
            if (bpf_probe_read_user(&v, sizeof(v), (const void*)(g->iov + (__u64)g->iovidx * sizeof(v)))) return 1;
            base = (__u64)v.iov_base, length = v.iov_len;
        }
        g->iovidx++;
        g->base = base;
        g->left = length < g->msg_left ? length : g->msg_left;
        return 0;
    }
    __u64 n = g->left;
    if (g->skip) {
        if (n > g->skip) n = g->skip;
        g->skip -= n;
    } else {
        /* 64-bit: a 32-bit copy's zero extension would part the bounded register from the one the pointer uses */
        __u64 off = g->len, cap = g->cap;
        if (off > MM_UNIX_HEAD + MM_UNIX_PART || cap > MM_UNIX_HEAD + MM_UNIX_PART || off >= cap) return 1;
        if (n > cap - off) n = cap - off;
        if (n > MM_UNIX_HEAD) n = MM_UNIX_HEAD;
        barrier_var(n);
        if (bpf_probe_read_user(&k->head.data[off], n, (const void*)g->base)) return 1;   /* not resident: short */
        g->len = off + n;
    }
    g->base += n;
    g->left -= n;
    g->msg_left -= n;
    return 0;
}

/* The call's bytes (Data: MM_DATA_*) into head.data after the Part carried bytes already there, past Skip bytes:
 * head.len, g.bytes (the call's), g.skip (what is left to pass over). Global, so unix_head's verification does not
 * multiply with its loop. */
__noinline int unix_gather(struct mm_event* p, __u32 data, __u32 part, __u32 skip)
{
    struct unix_work* k = unix_work();
    if (!p || !k) return -1;
    struct unix_gather* g = &k->g;
    __builtin_memset(g, 0, sizeof(*g));
    g->compat = (p->flags & MM_F_COMPAT) != 0;
    g->len = part;
    g->cap = part + MM_UNIX_HEAD;
    g->skip = skip;
    g->bytes = (__u64)p->ret;
    g->msg_left = (__u64)p->ret;
    if (data == MM_DATA_BUF) {
        g->base = p->args[1];
        g->left = (__u64)p->ret < p->args[2] ? (__u64)p->ret : p->args[2];
    } else if (data == MM_DATA_IOV) {
        g->iov = p->args[1];
        g->iovcnt = p->args[2] > MM_IOV_MAX ? MM_IOV_MAX : (__u32)p->args[2];
    } else if (data == MM_DATA_MSG) {
        if (g->compat) {
            __u32 c[4] = {};   /* compat_msghdr: name, namelen, iov, iovlen */
            if (bpf_probe_read_user(c, sizeof(c), (const void*)p->args[1])) return -1;
            g->iov = c[2];
            g->iovcnt = c[3] > MM_IOV_MAX ? MM_IOV_MAX : c[3];
        } else {
            struct user_msghdr m = {};
            if (bpf_probe_read_user(&m, sizeof(m), (const void*)p->args[1])) return -1;
            g->iov = (__u64)m.msg_iov;
            g->iovcnt = m.msg_iovlen > MM_IOV_MAX ? MM_IOV_MAX : (__u32)m.msg_iovlen;
        }
    } else if (data == MM_DATA_MMSG) {
        g->msgs = p->args[1];
        g->nmsg = p->ret > MM_IOV_MAX ? MM_IOV_MAX : (__u32)p->ret;
        g->bytes = 0;
        g->msg_left = 0;
    } else {
        return -1;
    }
    bpf_loop(MM_CAP_WALK, unix_gather_step, 0, 0);
    k->head.len = g->len;
    return 0;
}

/* Counts the walk's run (run_n messages of one op) in agg; an X11 or PulseAudio send's run whose op is new since the
 * agent's last drain lists its first message in head.op (sampled, its call and bytes left out of the count; past
 * MM_UNIX_SAMPLED it is counted instead). */
static __always_inline void unix_count(struct unix_work* k)
{
    struct unix_walk* w = &k->w;
    const __u64 key = w->ino << 32 | w->run_op;
    const __u64 bytes = w->run_bytes > 0xffffffffull ? 0xffffffffull : w->run_bytes;
    const __u64 first = w->run_first < bytes ? w->run_first : bytes;
    const __u64 sample = w->rx || w->svc == MM_UNIX_DBUS ? 0 : MM_AGG_SAMPLE;
    int counted = agg_add(w->nr, key, first, (__u64)w->run_n | bytes << 32, MM_AGG_COUNT | sample);
    if (counted == 2) {
        __u32 index = w->sampled;
        if (index < MM_UNIX_SAMPLED) {
            k->head.op[index & (MM_UNIX_SAMPLED - 1)] = w->run_at << 16 | (w->run_op & 0xffff);
            w->sampled = index + 1;
        } else {
            agg_add(w->nr, key, 0, 1 | first << 32, MM_AGG_COUNT);
        }
    }
    w->run_n = 0;
    w->run_bytes = 0;
}

/* bpf_loop callback: frames the message at w.at. Verifier-safe: at is compared below MM_UNIX_HEAD + MM_UNIX_PART, so
 * mm_unix_frame's constant offsets (< MM_UNIX_PART) stay inside data[]. */
static long unix_walk_step(__u32 index, void* unused)
{
    struct unix_work* k = unix_work();
    if (!k) return 1;
    struct unix_walk* w = &k->w;
    __u64 at = w->at, len = k->head.len;
    if (at >= len || at > MM_UNIX_HEAD + MM_UNIX_PART) return 1;
    __u32 op = 0;
    __u64 size = mm_unix_frame(w->svc, w->rx, w->big, &k->head.data[at], (__u32)(len - at), &op);
    if (size == 0) {
        w->incomplete = 1;
        return 1;
    }
    if (size == ~0ull) {
        w->lost = 1;
        return 1;
    }
    __u32 listed = w->sampled;
    if (w->list && listed < MM_UNIX_SAMPLED) {
        k->head.op[listed & (MM_UNIX_SAMPLED - 1)] = (__u32)at << 16 | (op & 0xffff);
        w->sampled = listed + 1;
    } else {
        if (w->run_n && op != w->run_op) unix_count(k);
        if (!w->run_n) {
            w->run_op = op;
            w->run_at = (__u32)at;
            w->run_first = size;
        }
        w->run_n++;
        w->run_bytes += size;
    }
    w->at = at + size;
    return 0;
}

/* Frames and counts the messages in head.data from At (Nr: the agg nr; Ino: the socket; Mode: the service | rx << 8 |
 * big << 16 | list << 24): w.at, w.incomplete, w.lost, w.sampled. Global, so unix_head's verification does not
 * multiply with its loop. */
__noinline int unix_walk(__u64 ino, __u32 nr, __u32 mode, __u32 at)
{
    struct unix_work* k = unix_work();
    if (!k) return -1;
    struct unix_walk* w = &k->w;
    __builtin_memset(w, 0, sizeof(*w));
    w->at = at;
    w->ino = ino;
    w->nr = nr;
    w->svc = mode & 0xff;
    w->rx = (mode >> 8) & 1;
    w->big = (mode >> 16) & 1;
    w->list = (mode >> 24) & 1;
    bpf_loop(MM_UNIX_STEPS, unix_walk_step, 0, 0);
    if (w->run_n) unix_count(k);
    return 0;
}

/* bpf_loop callback of unix_asked: adds one iovec's length. */
struct unix_sum {
    __u64 iov;
    __u64 total;
    __u32 count;
    __u32 compat;
};
static long unix_sum_step(__u32 index, struct unix_sum* s)
{
    if (index >= s->count) return 1;
    if (s->compat) {
        __u32 c[2] = {};
        if (bpf_probe_read_user(c, sizeof(c), (const void*)(s->iov + (__u64)index * sizeof(c)))) return 1;
        s->total += c[1];
    } else {
        struct iovec v = {};
        if (bpf_probe_read_user(&v, sizeof(v), (const void*)(s->iov + (__u64)index * sizeof(v)))) return 1;
        s->total += v.iov_len;
    }
    return 0;
}

/* A send's requested bytes (a partial write sent fewer): its count, or its iovecs' lengths. Global, as unix_gather. */
__noinline __u64 unix_asked(struct mm_event* p, __u32 data)
{
    if (!p) return 0;
    if (data == MM_DATA_BUF) return p->args[2];
    struct unix_sum s = {.compat = (p->flags & MM_F_COMPAT) != 0};
    if (data == MM_DATA_IOV) {
        s.iov = p->args[1];
        s.count = (__u32)p->args[2];
    } else if (s.compat) {
        __u32 c[4] = {};   /* compat_msghdr: name, namelen, iov, iovlen */
        if (bpf_probe_read_user(c, sizeof(c), (const void*)p->args[1])) return 0;
        s.iov = c[2], s.count = c[3];
    } else {
        struct user_msghdr m = {};
        if (bpf_probe_read_user(&m, sizeof(m), (const void*)p->args[1])) return 0;
        s.iov = (__u64)m.msg_iov, s.count = (__u32)m.msg_iovlen;
    }
    bpf_loop(MM_IOV_MAX, unix_sum_step, &s, 0);
    return s.total;
}

/* The head to the events ring before its call's record (MM_F_UNIX_HEAD on the record). */
static __always_inline void unix_emit(struct mm_event* p, struct mm_unix_head* h, __u32 svc)
{
    h->kind = MM_UNIX;
    h->tgid = p->tgid;
    h->tid = p->tid;
    h->svc = svc;
    h->ts_ns = p->ts_ns;
    h->ino = p->ino;
    __u32 len = h->len;
    barrier_var(len);
    if (len > MM_UNIX_HEAD + MM_UNIX_PART) len = MM_UNIX_HEAD + MM_UNIX_PART;
    if (bpf_ringbuf_output(&events, h, __builtin_offsetof(struct mm_unix_head, data) + len, 0)) {
        count_drop();
        return;
    }
    p->flags |= MM_F_UNIX_HEAD;
}

/* 1 while the per-CPU work is still this call's (Tid): the program is preemptible, and a task that ran unix_head on this
 * CPU meanwhile rewrote it. Else the call's Bytes are counted unparsed and the socket's state is left as it was. */
static __always_inline int unix_mine(struct unix_work* k, __u32 tid, __u32 nr, __u64 ino, __u64 bytes)
{
    if (k->head.tid == tid) return 1;
    count_loss(MM_LOSS_SCRATCH);
    agg_add(nr, ino << 32 | MM_UNIX_OP_UNPARSED, 0, 1 | (bytes > 0xffffffffull ? 0xffffffffull : bytes) << 32, MM_AGG_COUNT);
    return 0;
}

/* D-Bus's part of a call on S (Rx; its bytes in the head from At): | 2 when they are the SASL handshake's lines (a send
 * ending in BEGIN ends the sent handshake, a call starting a message its direction's), | 1 while the second's heads
 * leave room for its head; 0 on X11 and PulseAudio. Global, so its tests do not multiply with unix_head's paths. */
__noinline int unix_dbus(struct mm_unix_sock* s, __u32 rx, __u32 at)
{
    struct unix_work* k = unix_work();
    if (!s || !k || s->svc != MM_UNIX_DBUS) return 0;
    __u64 now = bpf_ktime_get_boot_ns();
    if (now - s->window_ns >= 1000000000ull) {
        s->window_ns = now;
        s->heads = 0;
    }
    const int list = s->heads < MM_UNIX_DBUS_HEADS;
    const __u32 text = rx ? MM_UNIX_S_TEXT_RX : MM_UNIX_S_TEXT_TX, len = k->head.len;
    if (!(s->flags & text)) return list;
    if (at < len && mm_unix_dbus_start(&k->head.data[at & (MM_UNIX_HEAD - 1)], len - at)) {
        s->flags &= ~text;
        return list;
    }
    if (!rx && len >= 7 && mm_unix_dbus_begin(&k->head.data[(len - 7) & (2 * MM_UNIX_HEAD - 1)])) s->flags &= ~text;
    return 2 | list;
}

/* A connected socket's first state (in .rodata: with its header parts it is too big for the stack). */
const struct mm_unix_sock unix_pending = {.svc = MM_UNIX_PENDING};

/* At an AF_UNIX call's exit (p: its record, Data: MM_DATA_*, Flags: argument index + 1 of its MSG_* flags): a connect
 * makes the socket pending; a send or receive on a service connection is walked. Global, so mm_sys_exit's verification
 * does not grow with it. */
__noinline int unix_head(struct mm_event* p, __u32 data, __u32 flags)
{
    if (!p || !(p->flags & MM_F_SOCKID) || p->sk_family != AF_UNIX) return 0;
    __u64 ino = p->ino;
    if (p->nr == 42) {   /* connect (ia32 socketcall's too); -EINPROGRESS: a non-blocking one */
        if ((p->ret == 0 || p->ret == -115) && bpf_map_update_elem(&unix_svc, &ino, &unix_pending, BPF_ANY))
            count_loss(MM_LOSS_UNIX_FULL);
        return 0;
    }
    __u32 nr = p->nr, rx;
    if (nr == 1 || nr == 20 || nr == 44 || nr == 46 || nr == 307) rx = 0;
    else if (nr == 0 || nr == 19 || nr == 45 || nr == 47 || nr == 299) rx = 1;
    else return 0;
    if (p->ret <= 0 || (flags && (arg_at(p, flags) & MM_MSG_PEEK_UNIX))) return 0;   /* peeked bytes are read again */
    struct mm_unix_sock* s = bpf_map_lookup_elem(&unix_svc, &ino);
    if (!s || (rx && s->svc == MM_UNIX_PENDING)) return 0;
    const __u32 d = rx & 1;
    const __u64 ret = (__u64)p->ret, mmsg = data == MM_DATA_MMSG;   /* mmsg: ret is the messages */
    __u32 svc = s->svc, nr_agg = MM_COUNT_UNIX | svc | (rx ? MM_UNIX_RX : 0);
    if (rx && (s->flags & MM_UNIX_S_RX_LOST)) {
        agg_add(nr_agg, ino << 32 | MM_UNIX_OP_UNPARSED, 0, 1 | (mmsg ? 0 : ret << 32), MM_AGG_COUNT);
        return 0;
    }
    __u32 skip = s->skip[d], part = s->part_len[d];
    if (!mmsg && skip >= ret) {   /* the whole call continues the last message */
        s->skip[d] = skip - (__u32)ret;
        return 0;
    }
    struct unix_work* k = unix_work();
    if (!k) return 0;
    struct mm_unix_head* h = &k->head;
    const __u32 tid = p->tid;
    h->tid = tid;   /* unix_mine's mark */
    h->sampled = 0;
    if (part > MM_UNIX_PART) part = 0;
    if (part) __builtin_memcpy(h->data, s->part[d], MM_UNIX_PART);
    if (unix_gather(p, data, part, skip) || !unix_mine(k, tid, nr_agg, ino, mmsg ? 0 : ret)) return 0;
    if (k->g.skip) {   /* mmsg: its messages all continue the last one */
        s->skip[d] = (__u32)k->g.skip;
        return 0;
    }
    const __u64 bytes = k->g.bytes > skip ? k->g.bytes - skip : 0;
    __u32 at = 0, big = (s->flags & MM_UNIX_S_BIG) != 0;
    if (svc == MM_UNIX_PENDING) {
        svc = mm_unix_classify(h->data, h->len, &at, &big);
        if (!svc) {
            bpf_map_delete_elem(&unix_svc, &ino);
            return 0;
        }
        nr_agg = MM_COUNT_UNIX | svc;
        s->svc = svc;
        s->flags = (big ? MM_UNIX_S_BIG : 0) | (svc == MM_UNIX_X11 ? MM_UNIX_S_RX_SETUP : 0) |
                   (svc == MM_UNIX_DBUS ? MM_UNIX_S_TEXT_TX | MM_UNIX_S_TEXT_RX : 0);
    }
    const int dbus = unix_dbus(s, rx, at);
    const __u32 list = dbus & 1;
    if (dbus & 2) {   /* each call holds whole lines: counted, sent raw for a message after BEGIN */
        agg_add(nr_agg, ino << 32 | MM_UNIX_DBUS_SASL, 0, 1 | (bytes > 0xffffffffull ? 0xffffffffull : bytes) << 32, MM_AGG_COUNT);
        if (list) {
            s->heads++;
            unix_emit(p, h, svc | rx << 4);   /* MM_UNIX_RX */
        }
        return 0;
    }
    __u32 incomplete = 0;
    if (rx && (s->flags & MM_UNIX_S_RX_SETUP)) {   /* the server's setup reply: 8 bytes, then 4 * length more */
        if (h->len < 8) {
            incomplete = 1;
        } else {
            s->flags &= ~MM_UNIX_S_RX_SETUP;
            at = 8 + mm_unix_u16(&h->data[6], big) * 4;
        }
    }
    struct unix_walk* w = &k->w;
    if (incomplete) {
        w->at = at;
        w->incomplete = 1;
        w->lost = w->sampled = 0;
    } else if (unix_walk(ino, nr_agg, svc | rx << 8 | big << 16 | list << 24, at) || !unix_mine(k, tid, nr_agg, ino, bytes)) {
        return 0;
    }
    const __u64 end = part + bytes, stop = w->at;
    __u32 next = 0, carry = 0;
    __u64 unparsed = mm_unix_after(rx, stop, h->len, part, bytes, bytes, w->incomplete, &next, &carry);
    if (unparsed == ~0ull) {   /* a receive past the walk, or a message past 4 GiB: lost */
        if (rx) s->flags |= MM_UNIX_S_RX_LOST;
        unparsed = end > stop ? end - stop : 0;
        next = carry = 0;
    } else if (unparsed && !rx && !mmsg) {   /* a partial write past the walk: its unsent rest comes next */
        const __u64 asked = unix_asked(p, data);
        if (asked > ret && asked - ret <= 0xffffffffull) next = (__u32)(asked - ret);
    }
    s->skip[d] = next;
    s->part_len[d] = carry ? (__u32)(end - stop) : 0;
    if (carry) {
        const __u32 from = (__u32)stop & (2 * MM_UNIX_HEAD - 1);   /* below the head: the mask only bounds it */
        __builtin_memcpy(s->part[d], &h->data[from], MM_UNIX_PART);
    }
    if (unparsed)
        agg_add(nr_agg, ino << 32 | MM_UNIX_OP_UNPARSED, 0, 1 | (unparsed > 0xffffffffull ? 0xffffffffull : unparsed) << 32,
                MM_AGG_COUNT);
    if (w->sampled && (!rx || list)) {   /* X11 and PulseAudio sends' sampled ops; D-Bus's listed messages */
        s->heads += list;
        h->sampled = w->sampled;
        unix_emit(p, h, svc | rx << 4 | big << 5);   /* MM_UNIX_RX, MM_UNIX_BIG */
    }
    return 0;
}

/* A connection's state goes with its socket: at the release of its last reference, not at a close of one of its fds
 * (a fork's inherited copy, a dup). Every AF_UNIX socket's release on the machine passes here: one hash delete, mostly
 * of a key that is not there. Optional group "unix": without it closed connections' states stay until unix_svc is
 * full, and new connects are then counted (MM_LOSS_UNIX_FULL), not walked. */
SEC("fentry/unix_release")
int BPF_PROG(mm_unix_release, struct socket* sock)
{
    __u64 ino = BPF_CORE_READ(sock, file, f_inode, i_ino);
    if (ino) bpf_map_delete_elem(&unix_svc, &ino);
    return 0;
}
