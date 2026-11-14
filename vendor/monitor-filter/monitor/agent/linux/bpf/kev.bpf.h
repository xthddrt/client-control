/*
 * Kernel events that are not syscalls of their own (docs/LINUX.md "Kernel events"): MM_KEV records (struct
 * mm_event, nr = MM_KEV_*), decoded by bpf_kev.inc. Observation only: tracepoints and fentry/fexit, so msmon takes no
 * part in any decision. Three optional groups (bpf.cpp gGroups):
 * - uring (mm_uring_*): io_uring operations, which run in the kernel without the read, write, openat or connect
 *   syscalls msmon records (submission: opcode, file or path, endpoint; completion: the result), and Linux AIO
 *   reads and writes with their file.
 * - kevents (mm_kev_*): signals another process or the kernel sends a tracked one; instructions the kernel trapped
 *   (SIGSEGV SI_KERNEL: CPUID/RDTSC faulting, RDPMC, RDMSR, IN/OUT, other #GP; UMIP emulation of SGDT, SIDT, SLDT,
 *   STR, SMSW); audited capability checks; module autoload requests; credential changes.
 * - faults (mm_fault_*, only with --page-faults): the first touch of each page of a shared file or shmem mapping
 *   (memfd, SysV shm, MAP_SHARED files): reads and writes through a mapping make no syscall.
 * Every program returns at once for an untracked task. Reuses events, scratch (fresh_scratch, fill_identity),
 * tracked, walk_path, resolve_fd, dir_for, read_sockaddr and count_drop.
 */

#define KEV_SIGILL 4
#define KEV_SIGTRAP 5
#define KEV_SIGBUS 7
#define KEV_SIGFPE 8
#define KEV_SIGSEGV 11
#define KEV_SIGSYS 31
#define KEV_SI_KERNEL 0x80
#define KEV_CAP_OPT_NOAUDIT 0x2
#define KEV_VM_MAYSHARE 0x80
#define KEV_PTRACE_MODE_READ 0x01
#define KEV_PTRACE_MODE_NOAUDIT 0x04

/* An MM_KEV record without a PE context to the events ring (its user stack first). */
static __always_inline void kev_emit(void* ctx, struct mm_event* e)
{
    long bytes = bpf_get_stack(ctx, e->stack, sizeof(e->stack), BPF_F_USER_STACK);
    e->frames = bytes > 0 ? (__u32)(bytes / sizeof(__u64)) : 0;
    if (bpf_ringbuf_output(&events, e, MM_EVENT_SHORT, 0)) count_drop();
}

/* A tracked task's record of kind MM_KEV / nr, identity of current. */
static __always_inline struct mm_event* kev_start(__u32 nr)
{
    if (!current_tracked()) return 0;
    struct mm_event* e = fresh_scratch();
    if (!e) return 0;
    e->kind = MM_KEV;
    e->nr = nr;
    fill_identity(e, bpf_get_current_task_btf());
    e->args[0] = e->args[1] = e->args[2] = e->args[3] = e->args[4] = e->args[5] = 0;
    return e;
}

/* ---- uring ---- */

/* Submitted io_uring requests of tracked tasks until their completion, keyed by the io_kiocb. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct mm_event);
} uring_inflight SEC(".maps");

/* A request is prepared (its sqe read) when this fires: the fd, the open's path and the connect's address are known.
 * An SQPOLL or io-wq thread is a thread of the submitting process, so tgid tracking covers it.
 * shortcut: statx, unlinkat, renameat, mkdirat, linkat and symlinkat name no path (their own structs; add them as
 * io_open is read below if they are seen); fixed files and fixed open slots name no file. Verifier-safe: straight
 * line apart from walk_path's bpf_loop; constant-size reads. */
SEC("tp_btf/io_uring_submit_req")
int BPF_PROG(mm_uring_submit, struct io_kiocb* req)
{
    struct mm_event* e = kev_start(MM_KEV_URING);
    if (!e) return 0;
    struct task_struct* task = bpf_get_current_task_btf();
    __u8 op = BPF_CORE_READ(req, opcode);
    __u64 flags = BPF_CORE_READ(req, flags);
    e->args[0] = op;
    e->args[2] = BPF_CORE_READ(req, cqe.user_data);
    e->args[3] = flags;
    if (op == IORING_OP_OPENAT || op == IORING_OP_OPENAT2) {
        struct io_open* open = (struct io_open*)req;   /* io_kiocb_to_cmd: the command is the request's first bytes */
        /* struct filename starts with its name pointer (in an embedded struct vmlinux.h cannot name). */
        const char* name = 0;
        bpf_probe_read_kernel(&name, sizeof(name), BPF_CORE_READ(open, filename.__incomplete_filename));
        e->args[1] = (__u64)(__s64)BPF_CORE_READ(open, dfd);
        e->args[3] = BPF_CORE_READ(open, how.flags);
        if (name && bpf_probe_read_kernel_str(e->path_a, MM_PATH, name) > 0)
            dir_for(e, task, 2, e->path_a, e->kdir_a, MM_F_KDIR_A);
    } else {
        /* cqe.fd holds the sqe's fd only for an op that takes a file; close keeps its own in the command. */
        int fd = op == IORING_OP_CLOSE ? BPF_CORE_READ((struct io_close*)req, fd) : BPF_CORE_READ(req, cqe.fd);
        e->args[1] = (__u64)(__s64)fd;
        if (op == IORING_OP_CONNECT) {
            struct io_connect* connect = (struct io_connect*)req;
            read_sockaddr(e, BPF_CORE_READ(connect, addr), (__u32)BPF_CORE_READ(connect, addr_len));
        }
        /* op is dead from here, so the verifier walks the fd's file once for every opcode */
        if (fd >= 0 && !(flags & (1ull << REQ_F_FIXED_FILE_BIT))) resolve_fd(e, task, fd);
    }
    long bytes = bpf_get_stack(ctx, e->stack, sizeof(e->stack), BPF_F_USER_STACK);
    e->frames = bytes > 0 ? (__u32)(bytes / sizeof(__u64)) : 0;
    __u64 key = (__u64)req;
    if (bpf_map_update_elem(&uring_inflight, &key, e, BPF_ANY) == 0) count_loss(MM_LOSS_URING_STORED);
    return 0;
}

/* Its CQE: the result, and an opened fd's file. shortcut: a multishot request's later CQEs and a CQE_SKIP_SUCCESS
 * request (no CQE; its entry ages out of the LRU) are not recorded; the agent counts every stored request that never
 * got here as ebpf_losses uring_unfinished (MM_LOSS_URING_STORED - MM_LOSS_URING_DONE). */
SEC("tp_btf/io_uring_complete")
int BPF_PROG(mm_uring_complete, struct io_ring_ctx* ring, void* req, struct io_uring_cqe* cqe)
{
    __u64 key = (__u64)req;
    struct mm_event* p = bpf_map_lookup_elem(&uring_inflight, &key);
    if (!p) return 0;
    __s32 res = BPF_CORE_READ(cqe, res);
    __u64 now = bpf_ktime_get_boot_ns();
    p->ret = res;
    p->dur_ns = now - p->ts_ns;
    p->ts_ns = now;
    __u64 op = p->args[0];
    if ((op == IORING_OP_OPENAT || op == IORING_OP_OPENAT2) && res >= 0 && (bpf_get_current_pid_tgid() >> 32) == p->tgid)
        resolve_fd(p, bpf_get_current_task_btf(), res);
    if (bpf_ringbuf_output(&events, p, MM_EVENT_SHORT, 0)) count_drop();
    if (bpf_map_delete_elem(&uring_inflight, &key) == 0) count_loss(MM_LOSS_URING_DONE);
    return 0;
}

/* Linux AIO (io_submit): one read or write with its file, as it is prepared; no result (AIO completes later). */
SEC("fentry/aio_prep_rw")
int BPF_PROG(mm_uring_aio, struct kiocb* req, const struct iocb* iocb, int rw_type)
{
    struct mm_event* e = kev_start(MM_KEV_AIO);
    if (!e) return 0;
    e->args[0] = BPF_CORE_READ(iocb, aio_lio_opcode);
    e->args[1] = BPF_CORE_READ(iocb, aio_fildes);
    e->args[2] = BPF_CORE_READ(iocb, aio_nbytes);
    e->args[3] = BPF_CORE_READ(iocb, aio_offset);
    e->args[4] = rw_type;
    struct file* file = BPF_CORE_READ(req, ki_filp);
    if (file) {
        e->mode = BPF_CORE_READ(file, f_inode, i_mode);
        e->ino = BPF_CORE_READ(file, f_inode, i_ino);
        int result = walk_path(__builtin_preserve_access_index(&file->f_path), e->kpath);
        if (result >= 0) e->flags |= MM_F_KPATH | (result ? MM_F_TRUNC_K : 0);
    }
    kev_emit(ctx, e);
    return 0;
}

/* ---- kevents ---- */

/* The instruction at ip of the trapped task (current): its first 8 bytes, ax and cx (CPUID's leaf). */
static __always_inline void kev_insn(void* ctx, __u64 ip, struct pt_regs* regs, __u32 source)
{
    struct mm_event* e = kev_start(MM_KEV_INSN);
    if (!e) return;
    __u64 bytes = 0;
    bpf_probe_read_user(&bytes, sizeof(bytes), (void*)ip);
    e->args[0] = ip;
    e->args[1] = bytes;
    e->args[2] = BPF_CORE_READ(regs, ax);
    e->args[3] = BPF_CORE_READ(regs, cx);
    e->args[4] = source;
    kev_emit(ctx, e);
}

/* A process's own fault signal (int3, single step, a hardware breakpoint hit, an access violation, a guard page or
 * write-watch hit, SIGILL, SIGBUS, SIGFPE, SIGSYS from seccomp or syscall user dispatch): counted in agg per (signal,
 * code, ip page) with the fault addresses' range, so a Wine guard-page or write-watch storm costs one update a fault;
 * the first fault of a key since the agent's last drain is an MM_KEV_SELFSIG record with its addresses, registers and
 * stack, the rest its summary. Fires in the faulting thread (current). */
static __always_inline void kev_selfsig(void* ctx, int sig, struct kernel_siginfo* info, int code, struct task_struct* task)
{
    struct pt_regs* regs = (struct pt_regs*)bpf_task_pt_regs(task);
    __u64 ip = BPF_CORE_READ(regs, ip);
    __u64 addr = (__u64)info > 1 && code > 0 ? (__u64)BPF_CORE_READ(info, _sifields._sigfault._addr) : 0;
    __u64 key = (__u64)(code & 0xffff) << 48 | ((ip >> 12) & 0xffffffffffffull);
    if (agg_add(MM_COUNT_SIGNAL | (sig & 0xff), key, addr, 0, MM_AGG_CALL | MM_AGG_SAMPLE) != 2) return;
    struct mm_event* e = kev_start(MM_KEV_SELFSIG);
    if (!e) return;
    e->args[0] = sig;
    e->args[1] = (__u64)(__s64)code;
    e->args[2] = ip;
    e->args[3] = addr;
    e->args[4] = (__u64)BPF_CORE_READ(task, thread.trap_nr) << 32 | (__u32)BPF_CORE_READ(task, thread.error_code);
    if (sig == KEV_SIGSYS && (__u64)info > 1)
        e->args[5] = (__u64)BPF_CORE_READ(info, _sifields._sigsys._arch) << 32 | (__u32)BPF_CORE_READ(info, _sifields._sigsys._syscall);
    else if (sig == KEV_SIGTRAP)
        e->args[5] = BPF_CORE_READ(task, thread.virtual_dr6);
    kev_emit(ctx, e);
}

/* A signal to a tracked process from another process or the kernel (a debugger, a user's kill, wineserver's suspend,
 * SIGCHLD of a child), the process's own SIGSEGV SI_KERNEL (a trapped instruction) and its other fault signals
 * (kev_selfsig). Other signals a process sends itself are its kill/tgkill records. Fires in the sender's context; info
 * is SEND_SIG_NOINFO (0) or SEND_SIG_PRIV (1) for the kernel's own. */
SEC("tp_btf/signal_generate")
int BPF_PROG(mm_kev_signal, int sig, struct kernel_siginfo* info, struct task_struct* task, int group, int result)
{
    __u32 tgid = BPF_CORE_READ(task, tgid);
    if (!bpf_map_lookup_elem(&tracked, &tgid)) return 0;
    __u32 sender = bpf_get_current_pid_tgid() >> 32;
    int code = (__u64)info == 1 ? KEV_SI_KERNEL : (__u64)info == 0 ? 0 : BPF_CORE_READ(info, si_code);
    if (sender == tgid) {
        if (sig == KEV_SIGSEGV && code == KEV_SI_KERNEL) {
            struct pt_regs* regs = (struct pt_regs*)bpf_task_pt_regs(task);
            kev_insn(ctx, BPF_CORE_READ(regs, ip), regs, MM_INSN_SIGSEGV);
        } else if (sig == KEV_SIGTRAP || sig == KEV_SIGSEGV || sig == KEV_SIGILL || sig == KEV_SIGBUS || sig == KEV_SIGFPE ||
                   sig == KEV_SIGSYS) {
            kev_selfsig(ctx, sig, info, code, task);
        }
        return 0;
    }
    struct mm_event* e = fresh_scratch();
    if (!e) return 0;
    e->kind = MM_KEV;
    e->nr = MM_KEV_SIGNAL;
    e->tgid = tgid;
    e->tid = BPF_CORE_READ(task, pid);
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->start_ns = BPF_CORE_READ(task, group_leader, start_boottime);
    e->ts_ns = bpf_ktime_get_boot_ns();
    e->args[0] = sig;
    e->args[1] = (__u64)(__s64)code;
    e->args[2] = result;
    e->args[3] = group;
    e->args[4] = (__u64)info > 1 && code <= 0 ? (__u32)BPF_CORE_READ(info, _sifields._kill._pid) : 0;
    e->args[5] = 0;
    /* User-sent (kill, tgkill, sigqueue: code <= 0) runs in the sender; a kernel signal may come from any context. */
    e->target_tgid = code <= 0 ? sender : 0;
    bpf_get_current_comm(e->path_a, 16);
    e->frames = 0;
    if (bpf_ringbuf_output(&events, e, MM_EVENT_SHORT, 0)) count_drop();
    return 0;
}

/* UMIP: the kernel emulates SGDT, SIDT, SLDT, STR and SMSW for user mode with dummy values (no signal). Every user
 * #GP of a tracked thread passes here first (its ip kept until the exit: emulation moves ip past the instruction);
 * the others (CPUID faulting, RDMSR...) return false and become the SIGSEGV above. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} umip_ip SEC(".maps");

SEC("fentry/fixup_umip_exception")
int BPF_PROG(mm_kev_umip_entry, struct pt_regs* regs)
{
    if (!current_tracked()) return 0;
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u64 ip = BPF_CORE_READ(regs, ip);
    bpf_map_update_elem(&umip_ip, &tid, &ip, BPF_ANY);
    return 0;
}

SEC("fexit/fixup_umip_exception")
int BPF_PROG(mm_kev_umip, struct pt_regs* regs, bool emulated)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u64* ip = bpf_map_lookup_elem(&umip_ip, &tid);
    if (!ip) return 0;
    if (emulated) kev_insn(ctx, *ip, regs, MM_INSN_UMIP);
    bpf_map_delete_elem(&umip_ip, &tid);
    return 0;
}

/* An untracked process's ptrace access check on a tracked one: a debugger's attach, process_vm_readv/writev, an open of
 * /proc/<pid>/mem (attach mode) or of maps, environ, fd... (audited read mode; /proc/<pid>/stat's NOAUDIT read checks
 * are skipped, every ps and top makes them). Counted in agg per (actor, mode, the actor's syscall) under the target's
 * tgid; the first of a key since the last drain is an MM_KEV_OUTSIDE record with the actor's comm and executable.
 * The monitors' own reads are left out: the agent's, and kfilterd's (its module poll reads every protected program's
 * maps a few times a second, and its open decisions read /proc/<tid>/mem). Cost: a trampoline on every ptrace access
 * check on the machine (each /proc/<pid>/ open of another process, ps and top included), its mode test and one tracked
 * lookup, about 0.1 us; an untracked actor's check on a tracked process one agg update more, a record once a second
 * per (actor, mode, call). shortcut: a check the DAC test refuses first (another user without CAP_SYS_PTRACE) never
 * reaches this hook; hook __ptrace_may_access if such attempts must be seen. */
SEC("fexit/security_ptrace_access_check")
int BPF_PROG(mm_kev_outside, struct task_struct* child, unsigned int mode, int ret)
{
    if ((mode & (KEV_PTRACE_MODE_READ | KEV_PTRACE_MODE_NOAUDIT)) == (KEV_PTRACE_MODE_READ | KEV_PTRACE_MODE_NOAUDIT))
        return 0;
    __u32 target = BPF_CORE_READ(child, tgid);
    if (!bpf_map_lookup_elem(&tracked, &target)) return 0;
    struct mm_config* c = cfg();
    __u64 actor = bpf_get_current_pid_tgid();
    if (!c || monitor_tgid(c, actor >> 32) || current_tracked()) return 0;
    struct task_struct* task = bpf_get_current_task_btf();
    struct pt_regs* regs = (struct pt_regs*)bpf_task_pt_regs(task);
    __u64 call = (__u16)regs->orig_ax | (compat_syscall(task) ? MM_OUTSIDE_COMPAT : 0);
    __u64 key = (actor >> 32) << 32 | (mode & 0xff) << 24 | call;
    if (agg_add(MM_COUNT_OUTSIDE, key, 0, 0, MM_AGG_CALL | MM_AGG_SAMPLE | (__u64)target << 32) != 2) return 0;
    struct mm_event* e = fresh_scratch();
    if (!e) return 0;
    e->kind = MM_KEV;
    e->nr = MM_KEV_OUTSIDE;
    e->tgid = target;
    e->tid = BPF_CORE_READ(child, pid);
    e->ppid = BPF_CORE_READ(child, real_parent, tgid);
    e->start_ns = BPF_CORE_READ(child, group_leader, start_boottime);
    e->ts_ns = bpf_ktime_get_boot_ns();
    e->target_tgid = actor >> 32;
    e->ret = ret;
    e->args[0] = mode;
    e->args[1] = (__u64)(__s64)ret;
    e->args[2] = call;
    e->args[3] = (__u32)actor;
    e->args[4] = e->args[5] = 0;
    bpf_get_current_comm(e->path_a, 16);
    struct file* exe = BPF_CORE_READ(task, mm, exe_file);
    if (exe && walk_path(__builtin_preserve_access_index(&exe->f_path), e->kpath) >= 0) e->flags |= MM_F_KPATH;
    e->frames = 0;   /* the actor's stack would be resolved against the target's modules */
    if (bpf_ringbuf_output(&events, e, MM_EVENT_SHORT, 0)) count_drop();
    return 0;
}

/* An audited capable() check (CAP_OPT_NOAUDIT probes are not attempts), with its result. */
SEC("fexit/security_capable")
int BPF_PROG(mm_kev_capable, const struct cred* cred, struct user_namespace* ns, int cap, unsigned int opts, int ret)
{
    if (opts & KEV_CAP_OPT_NOAUDIT) return 0;
    struct mm_event* e = kev_start(MM_KEV_CAP);
    if (!e) return 0;
    e->args[0] = cap;
    e->args[1] = opts;
    e->ret = ret;
    kev_emit(ctx, e);
    return 0;
}

/* request_module: a socket family, filesystem or device without its module (net-pf-N, fs-..., char-major-...). */
SEC("fexit/security_kernel_module_request")
int BPF_PROG(mm_kev_module, char* name, int ret)
{
    struct mm_event* e = kev_start(MM_KEV_MODULE);
    if (!e) return 0;
    bpf_probe_read_kernel_str(e->path_a, MM_PATH, name);
    e->ret = ret;
    kev_emit(ctx, e);
    return 0;
}

/* New credentials that change an id or the effective capabilities (setuid calls, a setuid exec, capset); an exec
 * that keeps them (every one) is not recorded. */
SEC("fentry/commit_creds")
int BPF_PROG(mm_kev_cred, struct cred* new)
{
    if (!current_tracked()) return 0;
    const struct cred* old = BPF_CORE_READ(bpf_get_current_task_btf(), real_cred);
    __u64 uid = (__u64)BPF_CORE_READ(old, uid.val) << 32 | BPF_CORE_READ(new, uid.val);
    __u64 euid = (__u64)BPF_CORE_READ(old, euid.val) << 32 | BPF_CORE_READ(new, euid.val);
    __u64 gid = (__u64)BPF_CORE_READ(old, gid.val) << 32 | BPF_CORE_READ(new, gid.val);
    __u64 egid = (__u64)BPF_CORE_READ(old, egid.val) << 32 | BPF_CORE_READ(new, egid.val);
    __u64 capOld = BPF_CORE_READ(old, cap_effective.val), capNew = BPF_CORE_READ(new, cap_effective.val);
    if ((__u32)uid == uid >> 32 && (__u32)euid == euid >> 32 && (__u32)gid == gid >> 32 && (__u32)egid == egid >> 32 &&
        capOld == capNew)
        return 0;
    struct mm_event* e = kev_start(MM_KEV_CRED);
    if (!e) return 0;
    e->args[0] = uid;
    e->args[1] = euid;
    e->args[2] = gid;
    e->args[3] = egid;
    e->args[4] = capOld;
    e->args[5] = capNew;
    kev_emit(ctx, e);
    return 0;
}

/* ---- seccomp ---- */

/* A call of a tracked process stopped before sys_enter, which neither counts nor records it: seccomp (RET_ERRNO, TRAP,
 * TRACE without a tracer, USER_NOTIF refused; a KILL never returns, its exit code says SIGSYS) or syscall user dispatch
 * (its SIGSYS is also a self-signal record). Counted in agg per number (MM_COUNT_SECCOMP / MM_COUNT_DISPATCH), the
 * agent's summaries name it seccomp:<call> / dispatch:<call>. __secure_computing takes no arguments here: the number
 * is the task's orig_ax. Optional group "seccomp" (a kernel without these functions loses only them). */
static __always_inline void stopped(__u32 kind)
{
    if (!current_tracked()) return;
    struct task_struct* task = bpf_get_current_task_btf();
    struct pt_regs* regs = (struct pt_regs*)bpf_task_pt_regs(task);
    long nr = regs->orig_ax;
    __u32 low = nr >= 0 && nr < MM_SYSCALLS ? (__u32)nr : MM_COUNT_OTHER;
    agg_add(kind | low | (compat_syscall(task) ? MM_COUNT_COMPAT : 0), 0, 0, 0, MM_AGG_CALL);
}

SEC("fexit/__secure_computing")
int BPF_PROG(mm_seccomp_filter, int ret)
{
    if (ret != 0) stopped(MM_COUNT_SECCOMP);
    return 0;
}

SEC("fexit/syscall_user_dispatch")
int BPF_PROG(mm_seccomp_dispatch, struct pt_regs* regs, bool ret)
{
    if (ret) stopped(MM_COUNT_DISPATCH);
    return 0;
}

/* ---- faults ---- */

/* Pages already reported: (tgid, inode, page, write). */
struct kev_page {
    __u32 tgid;
    __u32 write;
    __u64 ino;
    __u64 page;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct kev_page);
    __type(value, __u8);
} fault_seen SEC(".maps");

struct kev_vma {
    __u64 address;
    __u64 offset;
    struct file* file;
};

static long kev_fault_vma(struct task_struct* task, struct vm_area_struct* vma, struct kev_vma* v)
{
    if (!(vma->vm_flags & KEV_VM_MAYSHARE) || !vma->vm_file) return 0;
    v->file = vma->vm_file;
    v->offset = v->address - vma->vm_start + (vma->vm_pgoff << 12);
    return 0;
}

/* A user page fault of a tracked task in a shared mapping with a file (MAP_SHARED files, memfd, SysV shm, shared
 * anonymous memory), once per page and access kind. Only a page that is not mapped yet faults (fault-around maps up
 * to 16 neighbours of a read fault), so this is first touch, not every access. Opt-in: every fault of a tracked task
 * looks up its vma. */
SEC("tp_btf/page_fault_user")
int BPF_PROG(mm_fault_user, unsigned long address, struct pt_regs* regs, unsigned long error_code)
{
    if (!current_tracked()) return 0;
    struct task_struct* task = bpf_get_current_task_btf();
    struct kev_vma v = {.address = address};
    if (bpf_find_vma(task, address, kev_fault_vma, &v, 0) || !v.file) return 0;
    struct file* file = v.file;   /* a local, so CO-RE relocates struct file and not kev_vma */
    struct kev_page key = {.tgid = bpf_get_current_pid_tgid() >> 32, .write = (error_code & 2) != 0,
                           .ino = BPF_CORE_READ(file, f_inode, i_ino), .page = v.offset >> 12};
    __u8 one = 1;
    if (bpf_map_update_elem(&fault_seen, &key, &one, BPF_NOEXIST)) return 0;
    struct mm_event* e = kev_start(MM_KEV_FAULT);
    if (!e) return 0;
    e->args[0] = address;
    e->args[1] = BPF_CORE_READ(regs, ip);
    e->args[2] = error_code;
    e->args[3] = v.offset;
    e->mode = BPF_CORE_READ(file, f_inode, i_mode);
    e->ino = key.ino;
    int result = walk_path(__builtin_preserve_access_index(&file->f_path), e->kpath);
    if (result >= 0) e->flags |= MM_F_KPATH | (result ? MM_F_TRUNC_K : 0);
    kev_emit(ctx, e);
    return 0;
}
