/*
 * Wineserver requests (wineserver upgrade; agent/linux/wineserver.cpp decodes them, docs/LINUX.md
 * "Wineserver requests"). A Wine thread sends each request to wineserver over its own request pipe:
 * write(request_fd, req, 64) without variable data, else writev(request_fd, {req[64], data...}); it
 * reads the reply from its reply pipe: read(reply_fd, reply, 64), then read(reply_fd, data, n). Both
 * fds sit in the thread's TEB (ntdll_thread_data). mm_ws_enter copies every request (ws_cfg) to the
 * events ring as MM_WS_REQUEST, but the hot ones ws_cfg names, which it counts per key in agg (ws_agg:
 * only the first of a key between two drains is copied); mm_ws_exit copies their replies as MM_WS_REPLY.
 * A write, splice, tee, vmsplice, pwritev2 or sendfile into a request pipe that is not one whole request of the
 * writer's own thread is one MM_WS_F_REJECTED record (ws_reject).
 *
 * Optional group "wineserver" (programs mm_ws_*): if the verifier refuses it, only these records are
 * lost. It also fills ws_pipes (each Wine thread's request, reply and wait pipe inodes: mm_sys_exit counts
 * their reads and writes only) and ws_serving (the client whose request wineserver read last: mm_sys_exit
 * gives wineserver's syscalls MM_F_SERVING). Reuses events, count_drop, count_key, agg_add, current_tracked,
 * fd_file, compat_syscall, teb32 and read_pe_any (pe.bpf.h). A create_window's and a destroy_window's successful reply
 * keep ws_windows, the window owners the uprobes read (ws_window).
 */

#define WS_S_IFIFO 0010000
#define WS_PIPEFS_MAGIC 0x50495045
/* TEB layout of Wine 11 (unix_private.h ntdll_thread_data in TEB.GdiTebBatch; winternl.h TEB). The
 * fd offsets are computed, not asserted by Wine, so the request fd is also checked to be a pipe. */
#define WS_TEB64_SELF 0x30        /* NT_TIB.Self */
#define WS_TEB64_CLIENT_ID 0x40   /* ClientId: u64 UniqueProcess, UniqueThread */
#define WS_TEB64_FDS 0x384        /* request_fd, reply_fd */
#define WS_TEB32_CLIENT_ID 0x20
#define WS_TEB32_FDS 0x220
#define WS_DATA_MASK (MM_WS_DATA - 1)
#define WS_REQ_INIT_FIRST_THREAD 5   /* unix_pid +12, unix_tid +16, debug_level +20, reply_fd +24, wait_fd +28 */
#define WS_REQ_INIT_THREAD 6         /* unix_tid +12, reply_fd +16, wait_fd +20 */

/* A thread's request, reply and wait fds from its first request (init_first_thread or init_thread), for the
 * requests it sends before its TEB is in use: Wine's start-up opens its first registry keys (DllOverrides,
 * Image File Execution Options) then, before ws_teb can find the TEB. Key: the thread id. */
struct mm_ws_early {
    __s32 fds[4];
    __u64 reply_ino;   /* the reply pipe: the thread reads its replies on the other end of it */
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct mm_ws_early);
} ws_early SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct mm_ws_config);
} ws_cfg SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct mm_ws_inflight);
} ws_inflight SEC(".maps");

/* Window owners by user-handle index (mm_ws_window_index), from create_window and destroy_window replies. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MM_WS_WINDOWS);
    __type(key, __u32);
    __type(value, struct mm_ws_window);
} ws_windows SEC(".maps");

/* A create_window reply (Create 1) gives its creator a window, a destroy_window reply takes one away, when Status is
 * success (the agent takes away the windows a thread's or process's end frees, bpf_ws.inc WsWindowsGone). shortcut: one handle space; the windows of two Wine prefixes tracked at once share it (a later create
 * overwrites, a stale entry names a dead owner) -- key by wineserver if two prefixes ever run under one agent. Global,
 * so mm_ws_exit's verification does not grow with it. */
__noinline int ws_window(__u32 create, __u32 status, __u32 handle)
{
    __u32 index = mm_ws_window_index(handle);
    struct mm_ws_window* w = index ? bpf_map_lookup_elem(&ws_windows, &index) : 0;
    if (!w || status) return 0;
    if (create) {
        __u64 id = bpf_get_current_pid_tgid();
        w->tgid = id >> 32;
        w->tid = (__u32)id;
        w->gen = handle >> 16;
    } else if (mm_ws_window_match(w, handle)) {
        w->tgid = 0;
    }
    return 0;
}

/* One event per CPU (about 17 KB: too big for the stack). */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct mm_ws_event);
} ws_scratch SEC(".maps");

/* The thread's Wine TEB or 0. 64-bit: the GS base, whose Tib.Self (+0x30) points at itself (Wine sets
 * it once per thread with arch_prctl(ARCH_SET_GS)). ia32: the GDT TLS descriptor Wine loads FS with
 * (set_thread_area), found as the one whose base has Tib.Self (+0x18) == base (pe.bpf.h teb32).
 * Verifier-safe: no loop beyond three unrolled steps; constant offsets and constant-size probe reads. */
static __always_inline __u64 ws_teb(struct task_struct* task, int compat)
{
    if (!compat) {
        __u64 teb = BPF_CORE_READ(task, thread.gsbase), self = 0;
        if (!teb || bpf_probe_read_user(&self, sizeof(self), (void*)(teb + WS_TEB64_SELF))) return 0;
        return self == teb ? teb : 0;
    }
    return teb32(task);
}

struct ws_copy {
    __u64 iov;      /* the writev iovec array */
    __u32 count;    /* iovcnt */
    __u32 compat;   /* compat_iovec (8 bytes) instead of iovec (16) */
    __u32 pos;      /* bytes copied into data[] */
    __u32 stop;     /* 1: copy nothing (more), only sum the lengths (a chunk could not be read, or a sum only) */
    __u64 total;    /* bytes the data iovecs hold (64-bit: lengths that wrap 32 bits do not add up to request_size) */
};

/* bpf_loop callback: appends iovec index + 1 (iovec 0 is the fixed part) to data[].
 * Verifier-safe: checked once as a callback; the offset is masked below MM_WS_DATA and the length is
 * re-checked <= MM_WS_DATA after a barrier, so every write ends inside data[2 * MM_WS_DATA]. */
static long ws_chunk(__u32 index, struct ws_copy* c)
{
    __u32 zero = 0;
    struct mm_ws_event* e = bpf_map_lookup_elem(&ws_scratch, &zero);
    if (!e || index + 1 >= c->count) return 1;
    __u64 base = 0, len = 0;
    if (c->compat) {
        __u32 v[2] = {};
        if (bpf_probe_read_user(v, sizeof(v), (void*)(c->iov + (__u64)(index + 1) * 8))) return 1;
        base = v[0];
        len = v[1];
    } else {
        __u64 v[2] = {};
        if (bpf_probe_read_user(v, sizeof(v), (void*)(c->iov + (__u64)(index + 1) * 16))) return 1;
        base = v[0];
        len = v[1];
    }
    c->total += len;
    if (len == 0 || c->pos >= MM_WS_DATA || c->stop) return 0;   /* past the cap: keep summing lengths */
    __u32 off = c->pos;
    barrier_var(off);
    off &= WS_DATA_MASK;
    __u32 take = len < MM_WS_DATA ? (__u32)len : MM_WS_DATA;
    if (take > MM_WS_DATA - off) take = MM_WS_DATA - off;
    barrier_var(take);
    if (take > MM_WS_DATA) return 1;
    /* A page not faulted in yet (non-sleepable program): keep the request with the bytes so far; the
     * agent sees data_len < total and reports payload_truncated / truncated_path. */
    if (bpf_probe_read_user(&e->data[off], take, (void*)base)) {
        c->stop = 1;
        return 0;
    }
    c->pos = off + take;
    return 0;
}

/* The bytes the data iovecs (all but the first) of a writev hold. Global, so mm_ws_enter's verification does not
 * grow with it. */
__noinline __u64 ws_total(__u64 iov, __u32 count, __u32 compat)
{
    struct ws_copy sum = {.iov = iov, .count = count, .compat = compat, .stop = 1};
    bpf_loop(5, ws_chunk, &sum, 0);
    return sum.total;
}

/* Verifier-safe: straight-line helper calls and constant-offset stores into a map value. */
static __always_inline void ws_ids(struct mm_ws_event* e, struct task_struct* task)
{
    __u64 id = bpf_get_current_pid_tgid();
    e->tgid = id >> 32;
    e->tid = (__u32)id;
    e->start_ns = BPF_CORE_READ(task, group_leader, start_boottime);
    e->ts_ns = bpf_ktime_get_boot_ns();
}

/* Registers a Wine thread's request, reply and wait pipes (TEB fds) in ws_pipes, once per thread.
 * Verifier-safe: straight-line; two fd_file lookups. */
static __always_inline void ws_pipes_add(struct task_struct* task, __s32* fds, __u64 request)
{
    struct mm_ws_pipe pipe = {.tgid = bpf_get_current_pid_tgid() >> 32, .request = 1};
    bpf_map_update_elem(&ws_pipes, &request, &pipe, BPF_ANY);
    pipe.request = 0;
    struct file* reply = fd_file(task, fds[1]);
    struct file* wait = fd_file(task, fds[2]);
    __u64 ino = reply ? BPF_CORE_READ(reply, f_inode, i_ino) : 0;
    if (ino) bpf_map_update_elem(&ws_pipes, &ino, &pipe, BPF_ANY);
    ino = wait ? BPF_CORE_READ(wait, f_inode, i_ino) : 0;
    if (ino) bpf_map_update_elem(&ws_pipes, &ino, &pipe, BPF_ANY);
}

/* A write on a request pipe that is not one whole request of the writer's own thread (ws_bpf.h MM_WS_REJECT_* says
 * which of them kfilter refuses in block mode): one MM_WS_F_REJECTED record each, its first 64 bytes read from Header
 * (0: e->fixed holds them), and counted (ebpf_losses ws_rejected). Verifier-safe: straight-line; constant-size
 * copies; one ring output of offsetof(data) + sizeof(struct mm_ws_reject). */
static __always_inline int ws_reject(void* ctx, struct mm_ws_event* e, struct task_struct* task,
                                     struct mm_ws_reject* reject, __u32 compat, __u64 header)
{
    count_loss(MM_LOSS_WS_REJECTED);
    if (header) bpf_probe_read_user(e->fixed, MM_WS_FIXED, (void*)header);   /* zero-filled when unreadable */
    e->kind = MM_WS_REQUEST;
    e->req = *(__u32*)&e->fixed[0];
    e->total = *(__u32*)&e->fixed[4];
    e->flags = MM_WS_F_REJECTED | (compat ? MM_WS_F_COMPAT : 0);
    e->win_pid = e->win_tid = 0;
    ws_ids(e, task);
    long bytes = bpf_get_stack(ctx, e->stack, sizeof(e->stack), BPF_F_USER_STACK);
    e->frames = bytes > 0 ? (__u32)(bytes / sizeof(__u64)) : 0;
    e->pe.rip = 0;
    e->pe.bytes = 0;
    e->pe.flags = 0;
    __builtin_memcpy(e->data, reject, sizeof(*reject));
    e->data_len = sizeof(*reject);
    if (bpf_ringbuf_output(&events, e, __builtin_offsetof(struct mm_ws_event, data) + sizeof(*reject), 0)) count_drop();
    return 0;
}

/* Request Req (its header in e->fixed) of the current process, when ws_cfg aggregates it and it is not exempt
 * (filter, ioctl_codes): counted in agg per key. 1: counted there (agg full: in counts), nothing else to do; 2: the
 * first call of its key since the agent last drained agg (captured, MM_WS_F_SAMPLED); 0: not aggregated. Global, so
 * mm_ws_enter's verification does not grow with it. Verifier-safe: offsets masked into fixed[]; early-exit compares
 * (every match reaches the same state, so at most 11 paths). */
__noinline int ws_agg(struct mm_ws_event* e, __u32 req)
{
    __u32 zero = 0;
    struct mm_ws_config* c = bpf_map_lookup_elem(&ws_cfg, &zero);
    if (!e || !c || req >= MM_WS_REQUESTS) return 0;
    __u32 slot = req;
    barrier_var(slot);   /* keeps the mask: clang would drop it, and the verifier lose the bound */
    slot &= MM_WS_REQUESTS - 1;
    if (!(c->agg[slot >> 6] & (1ull << (slot & 63)))) return 0;
#pragma unroll
    for (int i = 0; i < 2; i++) {
        if (c->filter[i].mask && req == c->filter[i].req &&
            (*(__u32*)&e->fixed[c->filter[i].off & (MM_WS_FIXED - 4)] & c->filter[i].mask))
            return 0;
    }
    if (req == c->ioctl_req) {
        __u32 code = *(__u32*)&e->fixed[12];
#pragma unroll
        for (int i = 0; i < 8; i++) {
            if (c->ioctl_codes[i] == code) return 0;
        }
    }
    __u32 hi = c->key[slot][0] & (MM_WS_FIXED - 4), lo = c->key[slot][1] & (MM_WS_FIXED - 4);
    __u64 key = (hi ? (__u64)*(__u32*)&e->fixed[hi] << 32 : 0) | (lo ? *(__u32*)&e->fixed[lo] : 0);
    int counted = agg_add(MM_COUNT_WS | req, key, 0, 0, MM_AGG_CALL | MM_AGG_SAMPLE);
    if (!counted) count_key((bpf_get_current_pid_tgid() & ~0xffffffffull) | MM_COUNT_WS | req);
    return counted == 2 ? 2 : 1;
}

/* wineserver ("wineserver", or a distribution's "wineserver64"). */
static __always_inline int ws_server(void)
{
    char comm[16] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    return comm[0] == 'w' && comm[1] == 'i' && comm[2] == 'n' && comm[3] == 'e' && comm[4] == 's' && comm[5] == 'e' &&
           comm[6] == 'r' && comm[7] == 'v' && comm[8] == 'e' && comm[9] == 'r';
}

/* A tracked Wine thread writes a request to its request pipe (and wineserver's poll ends whom it serves); a write,
 * splice, tee, vmsplice, pwritev2 or sendfile into a request pipe that is not one whole request of the writer's own
 * thread is a rejected-write record (ws_reject). Verifier-safe: straight-line apart from ws_teb's 3 unrolled steps
 * and one bpf_loop of at most 5 (ws_chunk); ws_total and ws_agg are global functions; the want/data bitmap index is
 * masked to 0..7; every copy has a constant size or one clamped to MM_WS_DATA; read_pe is pe.bpf.h's bounded copy; one
 * ring output whose size is clamped to offsetof(data) + MM_WS_DATA, or ws_reject's constant one. */
SEC("tp_btf/sys_enter")
int BPF_PROG(mm_ws_enter, struct pt_regs* regs, long id)
{
    if (id == 7 || id == 232 || id == 281 || id == 441) {   /* poll, epoll_wait, epoll_pwait, epoll_pwait2 */
        __u32 waiter = bpf_get_current_pid_tgid() >> 32;
        bpf_map_delete_elem(&ws_serving, &waiter);   /* wineserver waits again: it serves no one */
        return 0;
    }
    /* write, writev, splice, tee, vmsplice, pwritev2, sendfile: x86_64 1, 20, 275, 276, 278, 328, 40; ia32 4, 146, 313,
     * 315, 316, 379, 187 and sendfile64 239 */
    if (id != 1 && id != 20 && id != 4 && id != 146 && id != 275 && id != 276 && id != 278 && id != 313 && id != 315 &&
        id != 316 && id != 328 && id != 40 && id != 379 && id != 187 && id != 239)
        return 0;
    struct task_struct* task = bpf_get_current_task_btf();
    int compat = compat_syscall(task);
    __u32 vec = id == (compat ? 146 : 20), tee = id == (compat ? 315 : 276);
    /* pwritev2 (offset -1 writes a pipe as writev does) and sendfile (into a pipe it splices): never Wine's requests */
    __u32 sendfile = id == (compat ? 187 : 40) || (compat && id == 239);
    __u32 other = sendfile || id == (compat ? 379 : 328);
    __u32 splice = tee || other || id == (compat ? 313 : 275) || id == (compat ? 316 : 278);   /* not write or writev */
    if (!vec && !splice && id != (compat ? 4 : 1)) return 0;
    if (!current_tracked()) return 0;
    __u64 fd = compat ? BPF_CORE_READ(regs, bx) : BPF_CORE_READ(regs, di);
    __u64 buf = compat ? BPF_CORE_READ(regs, cx) : BPF_CORE_READ(regs, si);
    __u64 count = BPF_CORE_READ(regs, dx);
    if (tee) {   /* tee(in, out, len); vmsplice(fd, iov, nr_segs) and pwritev2(fd, iov, vlen, ...) are read as write */
        fd = buf;
    } else if (id == (compat ? 313 : 275)) {   /* splice(in, off_in, out, off_out, len) */
        fd = count;
        count = compat ? BPF_CORE_READ(regs, di) : BPF_CORE_READ(regs, r8);
    } else if (sendfile) {   /* sendfile(out, in, offset, count) */
        count = compat ? BPF_CORE_READ(regs, si) : BPF_CORE_READ(regs, r10);
    }
    __u64 teb = 0, replyIno = 0;
    __s32 fds[4] = {-1, -1, -1, -1};   /* request_fd, reply_fd, wait_fd[2] */
    if (!splice) {
        teb = ws_teb(task, compat);
        if (teb) {
            if (bpf_probe_read_user(fds, sizeof(fds), (void*)(teb + (compat ? WS_TEB32_FDS : WS_TEB64_FDS)))) return 0;
        } else {
            /* No TEB yet: the fds its first request named, or that first request itself (a plain 64-byte write
             * naming this very thread, as only Wine's start-up sends it). */
            __u64 pidTgid = bpf_get_current_pid_tgid();
            __u32 self = (__u32)pidTgid;
            struct mm_ws_early* early = bpf_map_lookup_elem(&ws_early, &self);
            __u32 first[8] = {};
            if (early) {
                __builtin_memcpy(fds, early->fds, sizeof(fds));
                replyIno = early->reply_ino;
            } else if (!vec && count == MM_WS_FIXED && !bpf_probe_read_user(first, sizeof(first), (void*)buf) && !first[1]) {
                if (first[0] == WS_REQ_INIT_FIRST_THREAD && first[3] == (__u32)(pidTgid >> 32) && first[4] == self) {
                    fds[1] = (__s32)first[6];
                    fds[2] = (__s32)first[7];
                } else if (first[0] == WS_REQ_INIT_THREAD && first[3] == self) {
                    fds[1] = (__s32)first[4];
                    fds[2] = (__s32)first[5];
                }
                struct file* reply = fd_file(task, fds[1]);
                if (reply) {
                    fds[0] = (__s32)fd;
                    struct mm_ws_early found = {.reply_ino = BPF_CORE_READ(reply, f_inode, i_ino)};
                    __builtin_memcpy(found.fds, fds, sizeof(fds));
                    replyIno = found.reply_ino;
                    bpf_map_update_elem(&ws_early, &self, &found, BPF_ANY);
                }
            }
        }
    }
    __u32 own = fds[0] >= 0 && (__s32)fd == fds[0];
    /* wineserver writes replies, never requests: while it serves another process's request (ws_serving) its 60k writes
     * a second skip the lookups below; a process named wineserver that read no other's request is checked as any */
    if (!own && !teb && !splice) {
        __u32 writer = bpf_get_current_pid_tgid() >> 32;
        struct mm_ws_serving* serving = bpf_map_lookup_elem(&ws_serving, &writer);
        if (serving && serving->tgid != writer) return 0;
    }
    /* Request pipes only (the TEB's request_fd is a computed offset: insist that it is a pipe). */
    struct file* file = fd_file(task, (int)fd);
    if (!file || (BPF_CORE_READ(file, f_inode, i_mode) & S_IFMT) != WS_S_IFIFO) return 0;
    __u64 ino = BPF_CORE_READ(file, f_inode, i_ino);
    struct mm_ws_reject reject = {.ino = ino, .count = count, .fd = (__s32)fd, .nr = (__u32)id};
    if (!own) {
        /* Another thread's or process's request pipe (wineserver would act for its owner), or no request pipe (ws_pipes
         * keys are pipefs inode numbers, which a named FIFO elsewhere may share). */
        struct mm_ws_pipe* pipe = bpf_map_lookup_elem(&ws_pipes, &ino);
        if (!pipe || !pipe->request || BPF_CORE_READ(file, f_inode, i_sb, s_magic) != WS_PIPEFS_MAGIC) return 0;
        reject.reason = other ? MM_WS_REJECT_OTHER : splice ? MM_WS_REJECT_SPLICE : MM_WS_REJECT_FOREIGN;
        reject.owner = pipe->tgid;
    }
    __u32 zero = 0;
    struct mm_ws_event* e = bpf_map_lookup_elem(&ws_scratch, &zero);
    struct mm_ws_config* c = bpf_map_lookup_elem(&ws_cfg, &zero);
    if (!e || !c) return 0;
    __builtin_memset(e->fixed, 0, MM_WS_FIXED);
    /* The header: the write's buffer, or writev's first iovec (zero-filled when unreadable). */
    __u64 header = splice ? 0 : buf, len0 = count;
    int unreadable = 0;
    if (vec) {
        __u64 first[2] = {};
        unreadable = bpf_probe_read_user(first, compat ? 8 : 16, (void*)buf) != 0;
        header = compat ? (__u32)first[0] : first[0];
        len0 = compat ? first[0] >> 32 : first[1];
    }
    if (!own) goto reject;
    if (!bpf_map_lookup_elem(&ws_pipes, &ino)) ws_pipes_add(task, fds, ino);
    if (vec ? count < 2 || count > 6 : count != MM_WS_FIXED) {   /* the fixed part and 1..5 data chunks */
        reject.reason = vec ? MM_WS_REJECT_CHUNKS : MM_WS_REJECT_SIZE;
        goto reject;
    }
    if (unreadable || len0 != MM_WS_FIXED) {   /* a resumed partial writev starts inside a request */
        reject.reason = unreadable ? MM_WS_REJECT_UNREADABLE : MM_WS_REJECT_RESUMED;
        goto reject;
    }
    if (bpf_probe_read_user(e->fixed, MM_WS_FIXED, (void*)header)) {
        reject.reason = MM_WS_REJECT_UNREADABLE;
        header = 0;
        goto reject;
    }
    header = 0;   /* e->fixed holds it from here */
    __u32 req = *(__u32*)&e->fixed[0];
    __u32 size = *(__u32*)&e->fixed[4];
    if (vec != (size != 0)) {
        reject.reason = MM_WS_REJECT_FORM;
        goto reject;
    }
    /* wineserver reads request_size bytes as the data: what the chunks hold beyond that it reads as another request */
    if (vec && ws_total(buf, (__u32)count, (__u32)compat) != size) {
        reject.reason = MM_WS_REJECT_TOTAL;
        goto reject;
    }
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&ws_inflight, &tid);    /* a new request ends any unanswered one */
    int sampled = ws_agg(e, req);
    if (sampled == 1) return 0;
    /* wanted or not; a number past the table as the last one ("unknown") */
    count_key((bpf_get_current_pid_tgid() & ~0xffffffffull) | MM_COUNT_WS |
              (req < MM_WS_REQUESTS ? req : MM_WS_REQUESTS - 1));
    if (req < MM_WS_REQUESTS && !(c->want[(req >> 6) & 7] & (1ull << (req & 63)))) return 0;
    __u32 data = req < MM_WS_REQUESTS ? (c->data[(req >> 6) & 7] >> (req & 63)) & 1 : 0;
    e->kind = MM_WS_REQUEST;
    e->req = req;
    e->total = size;
    e->flags = (compat ? MM_WS_F_COMPAT : 0) | (sampled ? MM_WS_F_SAMPLED : 0);
    e->data_len = 0;
    ws_ids(e, task);
    e->win_pid = 0;   /* no TEB yet (Wine's start-up): its Windows ids are not known */
    e->win_tid = 0;
    if (teb && compat) {
        __u32 ids[2] = {};
        bpf_probe_read_user(ids, sizeof(ids), (void*)(teb + WS_TEB32_CLIENT_ID));
        e->win_pid = ids[0];
        e->win_tid = ids[1];
    } else if (teb) {
        __u64 ids[2] = {};
        bpf_probe_read_user(ids, sizeof(ids), (void*)(teb + WS_TEB64_CLIENT_ID));
        e->win_pid = (__u32)ids[0];
        e->win_tid = (__u32)ids[1];
    }
    if (vec) {
        struct ws_copy copy = {.iov = buf, .count = (__u32)count, .compat = (__u32)compat};
        bpf_loop(5, ws_chunk, &copy, 0);
        e->data_len = copy.pos;
    }
    long bytes = bpf_get_stack(ctx, e->stack, sizeof(e->stack), BPF_F_USER_STACK);
    e->frames = bytes > 0 ? (__u32)(bytes / sizeof(__u64)) : 0;
    e->pe.rip = 0;
    e->pe.bytes = 0;
    e->pe.flags = 0;
    /* The request runs inside an Nt* call, so TEB->syscall_frame is valid (64-bit or ia32 TEB). */
    read_pe_any(&e->pe, task, regs, compat);
    __u32 len = e->data_len;
    barrier_var(len);
    if (len > MM_WS_DATA) len = MM_WS_DATA;
    if (bpf_ringbuf_output(&events, e, __builtin_offsetof(struct mm_ws_event, data) + len, 0)) {
        count_drop();
        return 0;
    }
    struct mm_ws_inflight f = {.req = req, .reply_fd = fds[1], .compat = (__u32)compat, .data = data,
                               .early = replyIno != 0, .reply_ino = replyIno,
                               .window = req == c->window_req[1] ? *(__u32*)&e->fixed[12] : 0};
    bpf_map_update_elem(&ws_inflight, &tid, &f, BPF_ANY);
    return 0;
reject:
    return ws_reject(ctx, e, task, &reject, compat, header);
}

/* The reply to an in-flight wanted request: read(reply_fd, reply, 64), then read(reply_fd, data, n).
 * Verifier-safe: straight-line; constant 64-byte copies and one copy whose size is clamped to
 * MM_WS_DATA after a barrier, at offset 0 of data[]; one ring output of at most offsetof(data) +
 * MM_WS_DATA. Cheap for every other syscall exit: one compare of ret and nr, one hash lookup. */
SEC("tp_btf/sys_exit")
int BPF_PROG(mm_ws_exit, struct pt_regs* regs, long ret)
{
    if (ret <= 0) return 0;
    long nr = BPF_CORE_READ(regs, orig_ax);
    if (nr != 0 && nr != 3) return 0;          /* read; ia32 read */
    /* wineserver read a request header: until it waits again, its syscalls serve that pipe's client (or no
     * tracked one). Its vararg data (request_size bytes, read next and maybe in parts) is no header, even when
     * 64 bytes long. shortcut: a 64-bit wineserver only; an ia32 one (i386-only Wine) serves unattributed. */
    if (nr == 0 && ws_server()) {
        __u32 server = bpf_get_current_pid_tgid() >> 32;
        struct file* file = fd_file(bpf_get_current_task_btf(), (int)BPF_CORE_READ(regs, di));
        __u64 ino = file ? BPF_CORE_READ(file, f_inode, i_ino) : 0;
        struct mm_ws_pipe* pipe = bpf_map_lookup_elem(&ws_pipes, &ino);
        if (pipe && pipe->request && pipe->toread) {
            pipe->toread = ret < pipe->toread ? pipe->toread - (__u32)ret : 0;
            return 0;
        }
        if (ret != MM_WS_FIXED) return 0;
        struct mm_ws_serving serving = {};
        if (pipe && pipe->request) {
            __u32 header[2] = {};   /* req, request_size */
            bpf_probe_read_user(header, sizeof(header), (void*)BPF_CORE_READ(regs, si));
            serving.tgid = pipe->tgid;
            serving.req = header[0];
            pipe->toread = header[1];
            bpf_map_update_elem(&ws_serving, &server, &serving, BPF_ANY);
        } else if (file && (BPF_CORE_READ(file, f_inode, i_mode) & S_IFMT) == WS_S_IFIFO) {
            bpf_map_delete_elem(&ws_serving, &server);   /* an untracked client's request */
        }
        return 0;
    }
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct mm_ws_inflight* f = bpf_map_lookup_elem(&ws_inflight, &tid);
    if (!f || nr != (f->compat ? 3 : 0)) return 0;
    __u64 fd = f->compat ? BPF_CORE_READ(regs, bx) : BPF_CORE_READ(regs, di);
    __u64 buf = f->compat ? BPF_CORE_READ(regs, cx) : BPF_CORE_READ(regs, si);
    if (f->early) {
        struct file* reply = fd_file(bpf_get_current_task_btf(), (int)fd);
        if (!reply || BPF_CORE_READ(reply, f_inode, i_ino) != f->reply_ino) return 0;
    } else if ((__s32)fd != f->reply_fd) {
        return 0;
    }
    __u32 zero = 0;
    if (!f->phase) {
        if (ret != MM_WS_FIXED || bpf_probe_read_user(f->header, MM_WS_FIXED, (void*)buf)) {
            bpf_map_delete_elem(&ws_inflight, &tid);
            return 0;
        }
        struct mm_ws_config* c = bpf_map_lookup_elem(&ws_cfg, &zero);
        if (c && c->window_req[0] && (f->req == c->window_req[0] || f->req == c->window_req[1]))
            ws_window(f->req == c->window_req[0], *(__u32*)&f->header[0],
                      f->req == c->window_req[0] ? *(__u32*)&f->header[8] : f->window);
        if (*(__u32*)&f->header[4] && f->data) {   /* reply_size: its data is read next */
            f->phase = 1;
            return 0;
        }
    }
    struct mm_ws_event* e = bpf_map_lookup_elem(&ws_scratch, &zero);
    if (!e) {
        bpf_map_delete_elem(&ws_inflight, &tid);
        return 0;
    }
    __builtin_memcpy(e->fixed, f->header, MM_WS_FIXED);
    __u32 take = 0;
    if (f->phase) {
        take = ret > MM_WS_DATA ? MM_WS_DATA : (__u32)ret;
        barrier_var(take);
        if (take > MM_WS_DATA) take = MM_WS_DATA;
        if (bpf_probe_read_user(e->data, take, (void*)buf)) take = 0;
    }
    e->kind = MM_WS_REPLY;
    e->req = f->req;
    e->total = *(__u32*)&f->header[4];
    e->data_len = take;
    e->flags = f->compat ? MM_WS_F_COMPAT : 0;
    e->win_pid = e->win_tid = e->frames = 0;
    e->pe.rip = 0;
    e->pe.bytes = 0;
    e->pe.flags = 0;
    ws_ids(e, bpf_get_current_task_btf());
    bpf_map_delete_elem(&ws_inflight, &tid);
    if (bpf_ringbuf_output(&events, e, __builtin_offsetof(struct mm_ws_event, data) + take, 0)) count_drop();
    return 0;
}
