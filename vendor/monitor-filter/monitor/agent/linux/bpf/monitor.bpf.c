// SPDX-License-Identifier: GPL-2.0
/*
 * msmon kernel sensors (see docs/LINUX.md): every recorded syscall of a tracked
 * process with its arguments, result, duration, kernel-resolved paths and an 8-frame
 * user stack; process/thread lifetime from the scheduler tracepoints; in-kernel
 * inheritance so a child is tracked before it runs; executable file mappings with the final LSM verdict
 * (fexit on security_mmap_file/security_file_mprotect: observed, never decided); and LSM self-protection
 * that refuses the tracked tree ptrace and signals against the agent (bpf() and perf_event_open only with
 * MM_CFG_PROTECT_TREE: msmon observes, kfilter's policy decides what the client may do).
 * ia32 syscalls (32-bit Wine: the i386 unix side of old WoW64) are recorded under the x86_64 number
 * ia32_nr maps them to (MM_F_COMPAT), the socketcall and ipc multiplexers' subcalls included. Every syscall of
 * a tracked process, recorded or not, is also counted per process (counts; bpf.cpp WriteCounts).
 *
 * Paths are rebuilt from dentries (no bpf_d_path: it is refused in tracepoints and in
 * non-sleepable LSM hooks), so a path is the name in the task's mount namespace.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "monitor_bpf.h"

char LICENSE[] SEC("license") = "GPL";

#define AT_FDCWD -100
#define PROT_EXEC 0x4
#define EPERM 1
#define WALK_LEN 4096
#define WALK_MASK (WALK_LEN - 1)
#define WALK_DEPTH 64
/* vmlinux.h has no macros; the upgrade headers use these too (do not redefine them there). */
#define AF_UNIX 1
#define AF_INET 2
#define AF_INET6 10
#define AF_NETLINK 16
#define S_IFMT 0170000
#define S_IFSOCK 0140000
#define S_IFIFO 0010000
#define TS_COMPAT 0x0002   /* arch/x86 thread_info.h: the task is in an ia32 (32-bit) syscall */

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct mm_config);
} mm_cfg SEC(".maps");

static __always_inline struct mm_config* cfg(void)
{
    __u32 zero = 0;
    return bpf_map_lookup_elem(&mm_cfg, &zero);
}

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, struct mm_tracked);
} tracked SEC(".maps");

/* ia32 syscall number (or MM_IA32_SOCKETCALL/MM_IA32_IPC + subcall) -> x86_64 number + 1 (0: not recorded);
 * filled by the agent (bpf_ia32.inc). */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MM_IA32_KEYS);
    __type(key, __u32);
    __type(value, __u32);
} ia32_nr SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MM_SYSCALLS);
    __type(key, __u32);
    __type(value, struct mm_sysinfo);
} sysinfo SEC(".maps");

/* One in-flight syscall per thread; deleted at its exit, at its thread's exit or exec. Not LRU: a full map refuses the
 * next call (counted, MM_LOSS_PENDING_FULL) instead of evicting another thread's call unseen. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MM_PENDING);
    __type(key, __u32);
    __type(value, struct mm_event);
} pending SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 << 20);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct mm_event);
} scratch SEC(".maps");

struct walk_buf {
    char data[WALK_LEN + 256];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct walk_buf);
} walkbuf SEC(".maps");

/* Wine's protocol pipes and whom wineserver serves (ws.bpf.h fills both; mm_sys_exit reads them). */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct mm_ws_pipe);
} ws_pipes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, struct mm_ws_serving);
} ws_serving SEC(".maps");

/* Records lost because the ring was full; the agent turns increases into sequence gaps. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} drops SEC(".maps");

static __always_inline void count_drop(void)
{
    __u32 zero = 0;
    __u64* value = bpf_map_lookup_elem(&drops, &zero);
    if (value) __sync_fetch_and_add(value, 1);
}

/* Calls and records lost without a ring drop (MM_LOSS_*; the agent's ebpf_losses note). */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MM_LOSS_KEYS);
    __type(key, __u32);
    __type(value, __u64);
} losses SEC(".maps");

static __always_inline void count_loss(__u32 index)
{
    __u64* value = bpf_map_lookup_elem(&losses, &index);
    if (value) __sync_fetch_and_add(value, 1);
}

/* Catch-all: calls per tracked process of every syscall number and wineserver request (MM_COUNT_* keys) not counted
 * in agg, so nothing the client does is wholly unseen; the agent reads and deletes a process's keys when it ends
 * (bpf.cpp WriteCounts). Per-CPU, so the hot path takes no atomic; not LRU, so a full map is a counted loss. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, MM_COUNT_KEYS);
    __type(key, __u64);
    __type(value, __u64);
} counts SEC(".maps");

static __always_inline void count_key(__u64 key)
{
    __u64* value = bpf_map_lookup_elem(&counts, &key);
    if (value) {
        *value += 1;
        return;
    }
    __u64 one = 1;
    /* another CPU's insert in between left this CPU's slot 0 */
    if (bpf_map_update_elem(&counts, &key, &one, BPF_ANY)) count_loss(MM_LOSS_COUNTS_FULL);
}

/* agg (MM_AGG_*, bpf.cpp AggFlush) and what is aggregated: aggcfg[nr], aggcfg[MM_SYSCALLS + ia32 nr]. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2 * MM_SYSCALLS);
    __type(key, __u32);
    __type(value, struct mm_aggcfg);
} aggcfg SEC(".maps");

/* Two agg maps; agg_live names the one calls are counted in. Each second the agent points agg_live at the other (the
 * update returns after an RCU grace period, when no program holds an element of the first any more) and drains the
 * first, so no call lands in an element after its key was read and deleted (or reused for another key). Not
 * preallocated: kernel memory follows the keys in use, about 1 KiB each with 16 possible CPUs. */
struct mm_agg_map {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, MM_AGG_KEYS);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct mm_agg_key);
    __type(value, struct mm_agg);
} agg0 SEC(".maps"), agg1 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 1);
    __type(key, __u32);
    __array(values, struct mm_agg_map);
} agg_live SEC(".maps") = {.values = {&agg0}};

#define MM_AGG_CALL 1    /* agg_add: count a call */
#define MM_AGG_ERROR 2   /* ... and/or a failure */
#define MM_AGG_SAMPLE 4  /* ... but not the key's first call since the agent's last drain: 2 is returned, the caller records it */
#define MM_AGG_COUNT 8   /* len's low half is the calls (their run: the first sampled, the rest counted), its high half
                          * their bytes; no range, addr the first call's bytes (a sampled one leaves with its call) */

/* Adds a call of the current process (or of the tgid in what's high half: an outside actor's check on it) to the live
 * agg map (nr: a counts key's low half); what 0 adds only the range to a key already there. 0 when that map is full:
 * the caller counts the call in counts instead. Global, so the verifier checks it once and the programs that call it
 * (sys_agg, the wineserver requests, the kernel events) do not grow. Per-CPU and without an atomic like count_key. */
__noinline int agg_add(__u32 nr, __u64 key, __u64 addr, __u64 len, __u64 what)
{
    __u32 zero = 0;
    void* live = bpf_map_lookup_elem(&agg_live, &zero);
    if (!live) return 0;
    struct mm_agg_key k = {.tgid = what >> 32 ? what >> 32 : bpf_get_current_pid_tgid() >> 32, .nr = nr, .key = key};
    struct mm_agg* v = bpf_map_lookup_elem(live, &k);
    int sampled = 0;
    if (!v) {
        if (!what) return 0;
        struct mm_agg fresh = {};
        /* another CPU's insert in between is as good; a sampled call leaves every slot zero (no summary of it alone) */
        if (bpf_map_update_elem(live, &k, &fresh, BPF_NOEXIST) == 0 && (what & MM_AGG_SAMPLE)) {
            if (!(what & MM_AGG_COUNT) || (__u32)len <= 1) return 2;
            sampled = 1;   /* a run: its first call is sampled, the others (and their bytes) are counted below */
            len -= 1 | (addr < (len >> 32) ? addr : len >> 32) << 32;
        }
        v = bpf_map_lookup_elem(live, &k);
        if (!v) {
            count_loss(MM_LOSS_AGG_FULL);
            return 0;
        }
    }
    __u64 now = bpf_ktime_get_boot_ns();
    if (!v->first_ns) {   /* this CPU's first call (an insert zeroes the other CPUs' slots) */
        v->first_ns = now;
        v->lo = ~0ull;
    }
    v->last_ns = now;
    if (what & MM_AGG_COUNT) {
        v->calls += (__u32)len;
        v->bytes += len >> 32;
        return sampled ? 2 : 1;
    }
    if (what & MM_AGG_CALL) v->calls++;
    if (what & MM_AGG_ERROR) v->errors++;
    if (addr) {
        if (addr < v->lo) v->lo = addr;
        if (addr + len > v->hi) v->hi = addr + len;
        v->bytes += len;
    }
    return 1;
}

struct walk_ctx {
    struct dentry* d;
    struct vfsmount* vfs;
    struct mount* mnt;
    __u32 off;
};

static long walk_step(__u32 index, struct walk_ctx* c)
{
    __u32 zero = 0;
    struct walk_buf* buf = bpf_map_lookup_elem(&walkbuf, &zero);
    if (!buf) return 1;
    /* Locals, so CO-RE relocates the kernel structs and not walk_ctx. */
    struct dentry* d = c->d;
    struct vfsmount* vfs = c->vfs;
    struct mount* mnt = c->mnt;
    struct dentry* root = BPF_CORE_READ(vfs, mnt_root);
    if (d == root) {
        struct mount* parent = BPF_CORE_READ(mnt, mnt_parent);
        if (!parent || parent == mnt) return 1;
        c->d = BPF_CORE_READ(mnt, mnt_mountpoint);
        c->mnt = parent;
        c->vfs = (struct vfsmount*)((void*)parent + bpf_core_field_offset(struct mount, mnt));
        return 0;
    }
    struct dentry* up = BPF_CORE_READ(d, d_parent);
    if (!up || up == d) return 1;
    __u32 len = BPF_CORE_READ(d, d_name.len) & 255;
    const unsigned char* name = BPF_CORE_READ(d, d_name.name);
    __u32 off = c->off;
    if (len == 0 || off <= len + 1) return 1;
    off -= len;
    bpf_probe_read_kernel(&buf->data[off & WALK_MASK], len, name);
    off -= 1;
    buf->data[off & WALK_MASK] = '/';
    c->off = off;
    c->d = up;
    return 0;
}

/* Absolute path of Path into Out (MM_PATH bytes). Returns 1 when Out was truncated,
 * -1 when nothing could be resolved. */
static __noinline int walk_path(const struct path* path, char* out)
{
    __u32 zero = 0;
    struct walk_buf* buf = bpf_map_lookup_elem(&walkbuf, &zero);
    if (!buf || !path || !out) return -1;
    struct walk_ctx c = {};
    c.d = BPF_CORE_READ(path, dentry);
    c.vfs = BPF_CORE_READ(path, mnt);
    if (!c.d || !c.vfs) return -1;
    c.mnt = (struct mount*)((void*)c.vfs - bpf_core_field_offset(struct mount, mnt));
    c.off = WALK_LEN - 1;
    buf->data[WALK_LEN - 1] = 0;
    bpf_loop(WALK_DEPTH, walk_step, &c, 0);
    if (c.off == WALK_LEN - 1) {
        c.off -= 1;
        buf->data[c.off & WALK_MASK] = '/';
    }
    bpf_probe_read_kernel_str(out, MM_PATH, &buf->data[c.off & WALK_MASK]);
    return (WALK_LEN - 1 - c.off) >= MM_PATH ? 1 : 0;
}

static __always_inline struct file* fd_file(struct task_struct* task, int fd)
{
    struct file* file = 0;
    if (fd < 0) return 0;
    struct fdtable* table = BPF_CORE_READ(task, files, fdt);
    if (!table) return 0;
    unsigned int max = BPF_CORE_READ(table, max_fds);
    if ((unsigned int)fd >= max) return 0;
    struct file** array = BPF_CORE_READ(table, fd);
    bpf_probe_read_kernel(&file, sizeof(file), &array[fd]);
    return file;
}

#include "payload.bpf.h"   /* sock_identity, capture_payload (payload upgrade) */

/* The fd's file into kpath/mode/ino/pos. */
static __always_inline void resolve_fd(struct mm_event* e, struct task_struct* task, int fd)
{
    struct file* file = fd_file(task, fd);
    if (!file) return;
    e->mode = BPF_CORE_READ(file, f_inode, i_mode);
    e->ino = BPF_CORE_READ(file, f_inode, i_ino);
    e->pos = BPF_CORE_READ(file, f_pos);
    if ((e->mode & S_IFMT) == S_IFSOCK) sock_identity(e, file);
    int result = walk_path(__builtin_preserve_access_index(&file->f_path), e->kpath);
    if (result >= 0) e->flags |= MM_F_KPATH | (result ? MM_F_TRUNC_K : 0);
}

/* The directory a relative path is resolved against: a dirfd's file, or the cwd. */
static __always_inline int resolve_dir(struct task_struct* task, int dirfd, char* out)
{
    if (dirfd == AT_FDCWD) {
        struct fs_struct* fs = BPF_CORE_READ(task, fs);
        if (!fs) return -1;
        return walk_path(__builtin_preserve_access_index(&fs->pwd), out);
    }
    struct file* file = fd_file(task, dirfd);
    if (!file) return -1;
    return walk_path(__builtin_preserve_access_index(&file->f_path), out);
}

static __always_inline __u64 arg_at(struct mm_event* e, __u8 index)
{
    /* index is argument index + 1 */
    switch (index) {
    case 1: return e->args[0];
    case 2: return e->args[1];
    case 3: return e->args[2];
    case 4: return e->args[3];
    case 5: return e->args[4];
    case 6: return e->args[5];
    default: return 0;
    }
}

static __always_inline int read_user_path(struct mm_event* e, __u8 index, char* out, __u32 trunc)
{
    const char* pointer = (const char*)arg_at(e, index);
    out[0] = 0;
    if (!pointer) return -1;
    long length = bpf_probe_read_user_str(out, MM_PATH, pointer);
    if (length <= 0) {
        out[0] = 0;
        return -1;
    }
    if (length == MM_PATH) e->flags |= trunc;
    return 0;
}

static __always_inline void dir_for(struct mm_event* e, struct task_struct* task, __u8 dir, const char* path,
                                    char* out, __u32 flag)
{
    out[0] = 0;
    if (dir == MM_DIR_NONE || path[0] == '/' || path[0] == 0) return;
    int dirfd = dir == MM_DIR_CWD ? AT_FDCWD : (int)arg_at(e, dir);
    if (resolve_dir(task, dirfd, out) >= 0) e->flags |= flag;
}

static __always_inline void fill_identity(struct mm_event* e, struct task_struct* task)
{
    __u64 id = bpf_get_current_pid_tgid();
    e->tgid = id >> 32;
    e->tid = (__u32)id;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->start_ns = BPF_CORE_READ(task, group_leader, start_boottime);
    e->ts_ns = bpf_ktime_get_boot_ns();
}

static __always_inline struct mm_event* fresh_scratch(void)
{
    __u32 zero = 0;
    struct mm_event* e = bpf_map_lookup_elem(&scratch, &zero);
    if (!e) return 0;
    e->kind = 0;
    e->flags = 0;
    e->mode = 0;
    e->ino = 0;
    e->pos = 0;
    e->frames = 0;
    e->ret = 0;
    e->dur_ns = 0;
    e->target_tgid = 0;
    e->sock_len = 0;
    e->path_a[0] = 0;
    e->path_b[0] = 0;
    e->kpath[0] = 0;
    e->kdir_a[0] = 0;
    e->kdir_b[0] = 0;
    e->pe.rip = 0;
    e->pe.bytes = 0;
    e->pe.flags = 0;
    return e;
}

static __always_inline int current_tracked(void)
{
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    return bpf_map_lookup_elem(&tracked, &tgid) != 0;
}

static __always_inline void read_sockaddr(struct mm_event* e, const void* pointer, __u32 length)
{
    if (!pointer || length == 0) return;
    if (length > MM_PATH) length = MM_PATH;
    length &= 0x1ff;
    if (length > MM_PATH) return;
    if (bpf_probe_read_user(e->path_b, length, pointer) == 0) {
        e->sock_len = length;
        e->flags |= MM_F_SOCK;
    }
}

/* The peer of a sendmsg/recvmsg: msg_name and msg_namelen of the user msghdr (compat_msghdr: two u32). */
static __always_inline void read_msg_name(struct mm_event* e, const void* msg)
{
    struct {
        const void* name;
        int length;
    } header = {};
    if (!msg) return;
    if (e->flags & MM_F_COMPAT) {
        __u32 compat[2] = {};
        if (bpf_probe_read_user(compat, sizeof(compat), msg) != 0) return;
        header.name = (const void*)(__u64)compat[0];
        header.length = (int)compat[1];
    } else if (bpf_probe_read_user(&header, sizeof(header), msg) != 0) {
        return;
    }
    if (header.length <= 0) return;
    read_sockaddr(e, header.name, (__u32)header.length);
}

/* 1 when a kernel path is below scope root Slot. */
static __always_inline int under_one_root(const struct mm_config* c, __u32 slot, const char* kpath)
{
    __u32 rootLength = c->root_len[slot & (MM_ROOTS - 1)];
    if (rootLength == 0 || rootLength >= MM_PATH) return 0;
    const char* root = c->root[slot & (MM_ROOTS - 1)];
    for (__u32 index = 0; index < MM_PATH; index++) {
        if (index >= rootLength) break;
        if (kpath[index] != root[index]) return 0;
    }
    return kpath[rootLength & (MM_PATH - 1)] == '/';
}

/* 1 when a kernel path is below any configured scope root (the Nexon family spans several directories). */
static __always_inline int under_root(const struct mm_config* c, const char* kpath)
{
#pragma unroll
    for (__u32 slot = 0; slot < MM_ROOTS; slot++) {
        if (under_one_root(c, slot, kpath)) return 1;
    }
    return 0;
}

static __always_inline int any_root(const struct mm_config* c)
{
    return c->root_len[0] || c->root_len[1] || c->root_len[2] || c->root_len[3];
}

/* 1 when the exec'd program's basename starts with "wine" (wine, wine64, wine-preloader,
 * wineserver). exec has already set comm to that basename; scanning the path for its last '/'
 * instead blows the verifier's 1M-instruction budget. */
static __always_inline int wine_image(void)
{
    char comm[16];
    if (bpf_get_current_comm(comm, sizeof(comm))) return 0;
    return comm[0] == 'w' && comm[1] == 'i' && comm[2] == 'n' && comm[3] == 'e';
}

static __always_inline void read_argv(struct mm_event* e, const char* const* argv)
{
    e->flags |= MM_F_ARGV;
    const int compat = (e->flags & MM_F_COMPAT) != 0;   /* an array of u32 pointers */
#pragma unroll
    for (int slot = 0; slot < MM_ARGV_SLOTS; slot++) {
        __u64 arg = 0;
        e->path_b[slot * MM_ARGV_SLOT] = 0;
        if (!argv) break;
        if (compat) {
            __u32 arg32 = 0;
            if (bpf_probe_read_user(&arg32, sizeof(arg32), (const char*)argv + slot * 4) != 0) break;
            arg = arg32;
        } else if (bpf_probe_read_user(&arg, sizeof(arg), &argv[slot]) != 0) {
            break;
        }
        if (!arg) break;
        bpf_probe_read_user_str(&e->path_b[slot * MM_ARGV_SLOT], MM_ARGV_SLOT, (const char*)arg);
    }
}

/* A 32-bit (ia32) syscall: its numbers and argument registers are not the x86_64 ones kSyscalls describes. */
static __always_inline int compat_syscall(struct task_struct* task)
{
    return (task->thread_info.status & TS_COMPAT) != 0;
}

#define IA32_OLD_MMAP 90
#define IA32_SOCKETCALL 102
#define IA32_IPC 117
#define IA32_FANOTIFY_MARK 339
#define NR_SHMAT 30   /* x86_64 numbers (vmlinux.h has no __NR_*) */
#define NR_FORK 57
#define NR_VFORK 58
#define NR_CLONE3 435
#define MAP_ANONYMOUS 0x20
#define EEXIST 17
/* CLONE_NEWNS, NEWCGROUP, NEWUTS, NEWIPC, NEWUSER, NEWPID, NEWNET, NEWTIME */
#define CLONE_NEW_ANY 0x7e020080ull

/* socketcall(call, args): the u32 arguments of each call at args (net/socket.c nargs). */
static const __u8 socketcall_nargs[21] = {0, 3, 3, 3, 2, 3, 3, 3, 4, 4, 4, 6, 6, 2, 5, 5, 3, 3, 4, 5, 4};

/* The ia32 registers bx..bp as the arguments of the x86_64 call: as they are, unpacked from socketcall's array or
 * old_mmap's struct (Wine's i386 preloader maps with it; its offset is in bytes, mmap2's in pages), with
 * fanotify_mark's 64-bit mask joined from two, or reordered from ipc(call, first, second, third, ptr, fifth) as
 * ipc/syscall.c passes them on (msgrcv version 0, 32-bit glibc's, through its ipc_kludge {msgp, msgtyp} at ptr).
 * Verifier-safe: one read of at most 24 bytes into a 24-byte stack array (size clamped by the table), one 8-byte
 * read and constant stores. */
static __always_inline void ia32_args(struct mm_event* e, struct pt_regs* regs, long id, __u32 sub)
{
    __u64 r[6] = {(__u32)BPF_CORE_READ(regs, bx), (__u32)BPF_CORE_READ(regs, cx), (__u32)BPF_CORE_READ(regs, dx),
                  (__u32)BPF_CORE_READ(regs, si), (__u32)BPF_CORE_READ(regs, di), (__u32)BPF_CORE_READ(regs, bp)};
    if (id == IA32_SOCKETCALL || id == IA32_OLD_MMAP) {
        const int mmap = id == IA32_OLD_MMAP;
        __u32 v[6] = {};
        __u32 size = mmap ? sizeof(v) : sub < 21 ? socketcall_nargs[sub] * 4 : 0;
        if (size > sizeof(v)) size = sizeof(v);
        bpf_probe_read_user(v, size, (void*)r[mmap ? 0 : 1]);
        for (int i = 0; i < 6; i++) e->args[i] = v[i];
        if (mmap) e->args[5] >>= 12;
        return;
    }
    if (id == IA32_FANOTIFY_MARK) {   /* fd, flags, mask_lo, mask_hi, dfd, pathname */
        e->args[0] = r[0], e->args[1] = r[1], e->args[2] = r[2] | r[3] << 32, e->args[3] = r[4], e->args[4] = r[5];
        e->args[5] = 0;
        return;
    }
    if (id != IA32_IPC) {
        for (int i = 0; i < 6; i++) e->args[i] = r[i];
        return;
    }
    __u64 first = r[1], second = r[2], third = r[3], ptr = r[4], fifth = r[5];
    e->flags |= MM_F_IPC;
    e->args[3] = e->args[4] = e->args[5] = 0;
    switch (sub) {
    case 1:   /* semop */
        e->args[0] = first, e->args[1] = ptr, e->args[2] = second;
        break;
    case 3:   /* semctl */
        e->args[3] = ptr;
        /* fall through */
    case 2:   /* semget */
    case 23:  /* shmget */
        e->args[0] = first, e->args[1] = second, e->args[2] = third;
        break;
    case 4:   /* semtimedop */
        e->args[0] = first, e->args[1] = ptr, e->args[2] = second, e->args[3] = fifth;
        break;
    case 11:  /* msgsnd */
    case 21:  /* shmat: the address goes to *third */
        e->args[0] = first, e->args[1] = ptr, e->args[2] = second, e->args[3] = third;
        break;
    case 12:  /* msgrcv; version 0 (the call's high half) passes msgp and msgtyp in an ipc_kludge at ptr */
        if ((r[0] >> 16) == 0) {
            __s32 kludge[2] = {};
            bpf_probe_read_user(kludge, sizeof(kludge), (void*)ptr);
            ptr = (__u32)kludge[0], fifth = (__u32)kludge[1];
        }
        e->args[0] = first, e->args[1] = ptr, e->args[2] = second, e->args[3] = (__s64)(__s32)fifth, e->args[4] = third;
        break;
    case 13:  /* msgget */
        e->args[0] = first, e->args[1] = second, e->args[2] = 0;
        break;
    case 14:  /* msgctl */
    case 24:  /* shmctl */
        e->args[0] = first, e->args[1] = second, e->args[2] = ptr;
        break;
    default:  /* 22 shmdt */
        e->args[0] = ptr, e->args[1] = e->args[2] = 0;
        break;
    }
}

#include "pe.bpf.h"   /* read_pe (pecaller upgrade) */

/* The vma of a thread's last syscall site and whether Windows code is there (sys_direct). */
struct direct_seen {
    __u64 lo;
    __u64 hi;
    __u32 direct;
    __u32 pad;
};
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct direct_seen);
} direct_seen SEC(".maps");

struct direct_ctx {
    __u64 vdso;
    struct direct_seen seen;
};

/* e_lfanew of the PE header at Base (within its first page); 0 when there is none or it is not resident. */
static __always_inline __u32 pe_at(__u64 base)
{
    __u16 mz = 0;
    __u32 lfanew = 0, pe = 0;
    if (bpf_probe_read_user(&mz, 2, (void*)base) != 0 || mz != 0x5a4d) return 0;   /* "MZ" */
    if (bpf_probe_read_user(&lfanew, 4, (void*)(base + 0x3c)) != 0 || lfanew < 0x40 || lfanew > 4096 - 84) return 0;
    if (bpf_probe_read_user(&pe, 4, (void*)(base + lfanew)) != 0 || pe != 0x4550) return 0;   /* "PE\0\0" */
    return lfanew;
}

static long direct_vma(struct task_struct* task, struct vm_area_struct* vma, struct direct_ctx* c)
{
    c->seen.lo = vma->vm_start;
    c->seen.hi = vma->vm_end;
    if (!vma->vm_file) c->seen.direct = vma->vm_start != c->vdso;
    else c->seen.direct = pe_at(vma->vm_start - (vma->vm_pgoff << 12)) != 0;
    return 0;
}

/* 1 when Windows code made the current syscall with its own syscall or int 0x80 instruction, past Wine: its return
 * address is in anonymous memory other than the vDSO, or in a file mapping with a PE header at offset 0 (kfilter's
 * kb_direct test; Wine's own calls come from ELF code). Cached per thread by the vma of its last syscall site, so a
 * hot call costs a task-storage lookup. shortcut: a site's vma unmapped and replaced by other code keeps its answer
 * until the thread calls from elsewhere; key the cache by mm sequence if that is ever seen. Global, so the callers'
 * verification does not grow with it. */
__noinline __u32 sys_direct(void)
{
    struct task_struct* task = bpf_get_current_task_btf();
    struct pt_regs* regs = (struct pt_regs*)bpf_task_pt_regs(task);
    __u64 ip = regs->ip;
    struct direct_seen* seen = bpf_task_storage_get(&direct_seen, task, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (seen && ip >= seen->lo && ip < seen->hi) return seen->direct;
    struct direct_ctx c = {.vdso = (__u64)BPF_CORE_READ(task, mm, context.vdso)};
    if (bpf_find_vma(task, ip, direct_vma, &c, 0) != 0) return 0;
    if (seen) *seen = c.seen;
    return c.seen.direct;
}

/* bpf_find_vma callback: the mapping's protection (VM_READ, VM_WRITE and VM_EXEC have PROT_*'s bits). */
static long agg_prot(struct task_struct* task, struct vm_area_struct* vma, __u64* prot)
{
    *prot = vma->vm_flags & 7;
    return 0;
}

#define IA32_RECVMMSG 337
#define IA32_SENDMMSG 345
#define IA32_RECVMMSG_TIME64 417
#define NR_RECVMMSG 299
#define NR_SENDMMSG 307

/* The threads that made a native helper's I/O call (MM_AGG_NATIVE_IO), marked at its entry: only their exits look for
 * tracking, so another process's read, write, send or receive costs a task-storage lookup at its exit, no hash lookup. */
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, __u32);
} native_io_threads SEC(".maps");

/* A native helper's (xdg-open, a browser) read, write, send or receive (MM_AGG_NATIVE_IO), at its exit: one call in agg
 * per (process, call, the fd's inode and its type) with its bytes (none for sendmmsg/recvmmsg, whose result is messages) or its
 * failure, so a browser's busy sockets, pipes and eventfds put no ring record on each call. The first of a key since the
 * agent's last drain is a record of its own (MM_F_NATIVE_IO: the fd's inode, mode and socket, a sendto/sendmsg/recvfrom/
 * recvmsg endpoint, never its bytes) and is counted in counts, as a call agg refused is. No path walk: one costs about
 * 200,000 verified instructions, past mm_sys_enter's limit; the agent names the inode from the helper's open record.
 * Global, so sys_agg's callers' verification does not grow with it. */
__noinline int native_io(long id, long ret)
{
    struct task_struct* task = bpf_get_current_task_btf();
    struct pt_regs* regs = (struct pt_regs*)bpf_task_pt_regs(task);
    const __u32 compat = (task->thread_info.status & TS_COMPAT) != 0;
    struct file* file = fd_file(task, compat ? (int)(__u32)regs->bx : (int)regs->di);
    const __u64 ino = file ? BPF_CORE_READ(file, f_inode, i_ino) : 0;
    const __u32 mode = file ? BPF_CORE_READ(file, f_inode, i_mode) : 0;
    /* the type in the key's top 4 bits (MM_NATIVE_IO_KEY): a socket's or pipe's inode number can equal a file's */
    const __u64 key = MM_NATIVE_IO_KEY(mode, ino);
    const __u32 nr = (__u32)id | (compat ? MM_COUNT_COMPAT : 0);
    const int mmsg = compat ? id == IA32_RECVMMSG || id == IA32_SENDMMSG || id == IA32_RECVMMSG_TIME64
                            : id == NR_RECVMMSG || id == NR_SENDMMSG;
    const __u64 bytes = ret > 0 && !mmsg ? (__u64)ret : 0;
    int counted = ret < 0 ? agg_add(nr, key, 0, 0, MM_AGG_CALL | MM_AGG_ERROR | MM_AGG_SAMPLE)
                          : agg_add(nr, key, 0, 1 | bytes << 32, MM_AGG_COUNT | MM_AGG_SAMPLE);
    if (counted != 1) count_key((bpf_get_current_pid_tgid() & ~0xffffffffull) | nr);
    if (counted != 2) return 1;
    __u32 nr64 = (__u32)id;
    if (compat) {
        __u32 key = nr64;
        __u32* mapped = bpf_map_lookup_elem(&ia32_nr, &key);
        if (!mapped || *mapped == 0 || *mapped > MM_SYSCALLS) return 1;
        nr64 = *mapped - 1;
    }
    struct mm_sysinfo* info = bpf_map_lookup_elem(&sysinfo, &nr64);
    struct mm_event* e = fresh_scratch();
    if (!info || !e) return 1;
    e->kind = MM_SYSCALL;
    e->nr = nr64;
    fill_identity(e, task);
    e->flags = MM_F_NATIVE_IO | (compat ? MM_F_COMPAT : 0);
    if (compat) {
        e->args[0] = (__u32)regs->bx, e->args[1] = (__u32)regs->cx, e->args[2] = (__u32)regs->dx;
        e->args[3] = (__u32)regs->si, e->args[4] = (__u32)regs->di, e->args[5] = (__u32)regs->bp;
    } else {
        e->args[0] = regs->di, e->args[1] = regs->si, e->args[2] = regs->dx;
        e->args[3] = regs->r10, e->args[4] = regs->r8, e->args[5] = regs->r9;
    }
    e->ret = ret;
    if (file) {   /* resolve_fd but the path walk */
        e->mode = mode;
        e->ino = ino;
        e->pos = BPF_CORE_READ(file, f_pos);
        if ((e->mode & S_IFMT) == S_IFSOCK) sock_identity(e, file);
    }
    if (info->sock == MM_SOCK_IN_4) {
        read_sockaddr(e, (const void*)e->args[4], (__u32)e->args[5]);
    } else if (info->sock == MM_SOCK_MSG_IN_1 || (ret >= 0 && info->sock == MM_SOCK_MSG_OUT_1)) {
        read_msg_name(e, (const void*)e->args[1]);
    } else if (ret >= 0 && info->sock == MM_SOCK_OUT_4 && e->args[5]) {
        int length = 0;
        if (bpf_probe_read_user(&length, sizeof(length), (const void*)e->args[5]) == 0 && length > 0)
            read_sockaddr(e, (const void*)e->args[4], (__u32)length);
    }
    if (e->tid != (__u32)bpf_get_current_pid_tgid()) {   /* preempted: another task rewrote the scratch record */
        count_loss(MM_LOSS_SCRATCH);
        return 1;
    }
    if (bpf_ringbuf_output(&events, e, MM_EVENT_SHORT, 0)) count_drop();
    return 1;
}

/* A call aggcfg names (once counted only: futex, rt_sigprocmask, poll, munmap...; anonymous memory that is not
 * executable; a native helper's I/O) goes to agg instead of a record: at its entry (How 0, or MM_TRACK_NATIVE for a
 * native helper; the caller checked tracking), or at its exit (How 1, untracked processes skipped here: the failure of
 * a call counted at entry, or an MMAP/MREMAP/NATIVE_IO call, whose address or bytes are known only then; a NATIVE_IO
 * call of another process is a record). Returns 1 when the entry is counted here and records
 * nothing (not even in counts); with agg full, 0: the entry takes the record path (counts, and a record if sysinfo
 * wants one). The arguments come from the task's pt_regs, which hold them from entry to exit. A Wine process's call
 * Windows code made itself is counted apart (MM_COUNT_DIRECT). Global, so mm_sys_enter's and mm_sys_exit's
 * verification does not grow with it. */
__noinline int sys_agg(long id, long ret, __u32 how)
{
    if (id < 0 || id >= MM_SYSCALLS) return 0;
    struct task_struct* task = bpf_get_current_task_btf();
    __u32 compat = (task->thread_info.status & TS_COMPAT) != 0;
    __u32 index = (__u32)id + (compat ? MM_SYSCALLS : 0);
    struct mm_aggcfg* c = bpf_map_lookup_elem(&aggcfg, &index);
    if (!c || !c->mode) return 0;
    __u32 mode = c->mode, late = mode == MM_AGG_MMAP || mode == MM_AGG_MREMAP, exit = how & 1;
    __u32 native = how & MM_TRACK_NATIVE;
    if (exit) {
        if (!late && mode != MM_AGG_NATIVE_IO && ret >= 0) return 0;
        __u32 tgid = bpf_get_current_pid_tgid() >> 32;
        struct mm_tracked* t = bpf_map_lookup_elem(&tracked, &tgid);
        if (!t) return 0;
        native = t->flags & MM_TRACK_NATIVE;
    }
    if (mode == MM_AGG_NATIVE_IO) {
        if (!native) return 0;
        if (exit) return native_io(id, ret);
        bpf_task_storage_get(&native_io_threads, task, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);   /* its exit is looked at */
        return 1;
    }
    struct pt_regs* regs = (struct pt_regs*)bpf_task_pt_regs(task);
    __u64 a[8] = {};   /* a[7] stays 0: argument index 0 (none) - 1 & 7 */
    if (compat) {
        a[0] = (__u32)regs->bx, a[1] = (__u32)regs->cx, a[2] = (__u32)regs->dx;
        a[3] = (__u32)regs->si, a[4] = (__u32)regs->di, a[5] = (__u32)regs->bp;
    } else {
        a[0] = regs->di, a[1] = regs->si, a[2] = regs->dx, a[3] = regs->r10, a[4] = regs->r8, a[5] = regs->r9;
    }
    if ((mode == MM_AGG_MPROTECT && (a[2] & PROT_EXEC)) || (mode == MM_AGG_FCNTL && MM_FCNTL_RECORDED((__u32)a[1])) ||
        (mode == MM_AGG_MMAP && ((a[2] & PROT_EXEC) || !(a[3] & MAP_ANONYMOUS))))
        return 0;
    if (late && !exit) return 1;   /* counted at its exit */
    __u64 key = a[(c->key - 1) & 7], addr = a[(c->addr - 1) & 7], len = a[(c->len - 1) & 7];
    __u32 what = exit ? MM_AGG_ERROR : MM_AGG_CALL;
    __u64 moved = 0;
    if (late) {
        what = MM_AGG_CALL | (ret < 0 ? MM_AGG_ERROR : 0);
        if (mode == MM_AGG_MMAP) {
            addr = ret < 0 ? 0 : ret;
        } else if (ret >= 0) {   /* mremap(old, old_len, new_len, ...): the moved mapping, both ranges */
            key = MM_AGG_PROT_UNKNOWN;
            bpf_find_vma(task, ret, agg_prot, &key, 0);
            moved = ret;
        } else {
            key = MM_AGG_PROT_UNKNOWN;
            bpf_find_vma(task, addr, agg_prot, &key, 0);
        }
    } else if (exit) {
        addr = 0;   /* its range was counted at entry */
    }
    __u32 nr = (__u32)id | (compat ? MM_COUNT_COMPAT : 0) | (!native && sys_direct() ? MM_COUNT_DIRECT : 0);
    int counted = agg_add(nr, key, addr, len, what);
    if (moved) agg_add(nr, key, moved, a[2], 0);   /* the new range: bytes are the two lengths, not the span between */
    if (!counted && late) count_key((bpf_get_current_pid_tgid() & ~0xffffffffull) | (nr & ~MM_COUNT_DIRECT));
    return counted;
}

/* The first MM_RIOV_MAX elements of a call's remote array (Array: its argument index + 1, Count: its length's, Elem:
 * an element's bytes for x86_64) into path_b (MM_F_RIOV, sock_len bytes), its first 8 bytes into pos: every remote
 * iovec of process_vm_readv/writev with its length, move_pages' page addresses. Global, so mm_sys_enter's
 * verification does not grow with it. */
__noinline int read_remote(struct mm_event* e, __u32 array, __u32 count, __u32 elem)
{
    if (!e) return 0;
    __u64 base = arg_at(e, array), n = arg_at(e, count);
    if (e->flags & MM_F_COMPAT) elem /= 2;
    if (n > MM_RIOV_MAX) n = MM_RIOV_MAX;
    __u32 bytes = (__u32)n * (elem & 31);
    barrier_var(bytes);
    if (!base || bytes == 0 || bytes > MM_PATH) return 0;
    if (bpf_probe_read_user(e->path_b, bytes, (const void*)base) != 0) return 0;
    e->sock_len = bytes;
    e->flags |= MM_F_RIOV;
    __builtin_memcpy(&e->pos, e->path_b, sizeof(e->pos));
    return 0;
}

SEC("tp_btf/sys_enter")
int BPF_PROG(mm_sys_enter, struct pt_regs* regs, long id)
{
    __u32 self = bpf_get_current_pid_tgid() >> 32;
    struct mm_tracked* tracking = bpf_map_lookup_elem(&tracked, &self);
    if (!tracking) return 0;
    const __u32 native = tracking->flags & MM_TRACK_NATIVE;
    struct task_struct* task = bpf_get_current_task_btf();
    const int compat = compat_syscall(task);
    const int known = id >= 0 && id < MM_SYSCALLS;
    if (known && sys_agg(id, 0, native)) return 0;
    count_key((bpf_get_current_pid_tgid() & ~0xffffffffull) | (compat ? MM_COUNT_COMPAT : 0) |
              (known ? (__u64)id : MM_COUNT_OTHER));
    if (!known) return 0;
    /* An ia32 syscall (32-bit Wine: the launcher, nexon_client, NGService): its number, or socketcall's and ipc's
     * subcall, maps to the x86_64 call of the same meaning (ia32_nr), its arguments are in bx, cx, dx, si, di, bp
     * (ia32_args). */
    __u32 nr = (__u32)id, sub = 0;
    if (compat) {
        __u32 key = nr;
        if (id == IA32_SOCKETCALL || id == IA32_IPC) {
            sub = (__u32)BPF_CORE_READ(regs, bx) & 0xffff;   /* ipc: the version is in the high half */
            if (sub >= 32) return 0;
            key = (id == IA32_SOCKETCALL ? MM_IA32_SOCKETCALL : MM_IA32_IPC) + sub;
        }
        __u32* mapped = bpf_map_lookup_elem(&ia32_nr, &key);
        if (!mapped || *mapped == 0 || *mapped > MM_SYSCALLS) return 0;
        nr = *mapped - 1;
    }
    struct mm_sysinfo* info = bpf_map_lookup_elem(&sysinfo, &nr);
    if (!info || !info->want || (native && !info->more.native)) return 0;
    struct mm_event* e = fresh_scratch();
    if (!e) return 0;
    e->kind = MM_SYSCALL;
    e->nr = nr;
    fill_identity(e, task);
    if (compat) {
        e->flags = MM_F_COMPAT;
        ia32_args(e, regs, id, sub);
    } else {
        e->args[0] = BPF_CORE_READ(regs, di);
        e->args[1] = BPF_CORE_READ(regs, si);
        e->args[2] = BPF_CORE_READ(regs, dx);
        e->args[3] = BPF_CORE_READ(regs, r10);
        e->args[4] = BPF_CORE_READ(regs, r8);
        e->args[5] = BPF_CORE_READ(regs, r9);
    }
    if (info->path_a && read_user_path(e, info->path_a, e->path_a, MM_F_TRUNC_A) == 0)
        dir_for(e, task, info->dir_a, e->path_a, e->kdir_a, MM_F_KDIR_A);
    if (info->path_b && read_user_path(e, info->path_b, e->path_b, MM_F_TRUNC_B) == 0)
        dir_for(e, task, info->dir_b, e->path_b, e->kdir_b, MM_F_KDIR_B);
    if (info->fd) resolve_fd(e, task, (int)arg_at(e, info->fd));
    if (info->sock == MM_SOCK_IN_1) read_sockaddr(e, (const void*)e->args[1], (__u32)e->args[2]);
    else if (info->sock == MM_SOCK_IN_4) read_sockaddr(e, (const void*)e->args[4], (__u32)e->args[5]);
    else if (info->sock == MM_SOCK_MSG_IN_1) read_msg_name(e, (const void*)e->args[1]);
    if (info->argv) read_argv(e, (const char* const*)arg_at(e, info->argv));
    if (info->riov) read_remote(e, info->riov, info->more.rcount, info->more.relem);
    __u32 tid = e->tid;
    /* The program runs preemptible (migrate_disable only): a task that ran sys_enter on this CPU meanwhile rewrote
     * the scratch record. shortcut: the other scratch users (fork, exec, image, kev records) are short and unchecked;
     * move them to task storage if ebpf_losses ever shows scratch_reuse. */
    if (tid != (__u32)bpf_get_current_pid_tgid()) {
        count_loss(MM_LOSS_SCRATCH);
        return 0;
    }
    /* shortcut: one pending call per thread; nothing has been seen to overwrite one (a signal handler runs after
     * the interrupted call's sys_exit), so a second slot is not kept: add one if pending_overwrite is ever nonzero. */
    long error = bpf_map_update_elem(&pending, &tid, e, BPF_NOEXIST);
    if (error == -EEXIST) {
        count_loss(MM_LOSS_PENDING_OVERWRITE);
        bpf_map_update_elem(&pending, &tid, e, BPF_ANY);
    } else if (error) {
        count_loss(MM_LOSS_PENDING_FULL);
    }
    return 0;
}

#include "unix.bpf.h"   /* unix_head: X11, D-Bus and PulseAudio over AF_UNIX */

#define NR_IOCTL 16
#define DRM_MAJOR 226

/* --log-content: the first 64 bytes (32 when 64 are not readable) of a DRM device's or a socket's ioctl argument as the
 * call left it (MAC, ESSID, GPU parameters), into kdir_b (MM_F_IOCTL_ARG, cap_bytes); a DRM ioctl's size field
 * bounds it. */
static __always_inline void ioctl_arg(struct mm_event* p)
{
    if (p->nr != NR_IOCTL || !p->args[2]) return;
    struct mm_config* c = cfg();
    if (!c || !(c->flags & MM_CFG_CONTENT)) return;
    struct file* file = fd_file(bpf_get_current_task_btf(), (int)p->args[0]);
    if (!file) return;
    __u32 mode = BPF_CORE_READ(file, f_inode, i_mode) & S_IFMT;
    __u32 size = 64;
    if (mode == 0020000) {   /* S_IFCHR */
        if ((BPF_CORE_READ(file, f_inode, i_rdev) >> 20) != DRM_MAJOR) return;
        __u32 field = ((__u32)p->args[1] >> 16) & 0x3fff;   /* _IOC_SIZE */
        if (field == 0) return;
        if (field < 64) size = field;
    } else if (mode != S_IFSOCK) {
        return;
    }
    barrier_var(size);
    if (size > 64) size = 64;
    if (bpf_probe_read_user(p->kdir_b, size, (const void*)p->args[2])) {
        if (size <= 32 || bpf_probe_read_user(p->kdir_b, 32, (const void*)p->args[2])) return;
        size = 32;
    }
    p->cap_bytes = size;
    p->flags |= MM_F_IOCTL_ARG;
}

/* At a recorded call's exit: MM_F_DIRECT (sys_direct), an ioctl's argument (ioctl_arg), and the output fd's file
 * (Outfd: its argument index + 1; MM_F_OUTFD) of a call that moves bytes fd to fd without a user buffer (sendfile,
 * splice, tee, copy_file_range), so the record names both ends. Global, so mm_sys_exit's verification does not grow
 * with it. */
__noinline int record_extra(struct mm_event* p, __u32 outfd)
{
    if (!p) return 0;
    if (sys_direct()) p->flags |= MM_F_DIRECT;
    ioctl_arg(p);
    if (!outfd) return 0;
    struct file* file = fd_file(bpf_get_current_task_btf(), (int)arg_at(p, outfd));
    if (!file) return 0;
    p->out_ino = BPF_CORE_READ(file, f_inode, i_ino);
    p->out_mode = BPF_CORE_READ(file, f_inode, i_mode);
    p->flags |= MM_F_OUTFD;
    return 0;
}

SEC("tp_btf/sys_exit")
int BPF_PROG(mm_sys_exit, struct pt_regs* regs, long ret)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct mm_event* p = bpf_map_lookup_elem(&pending, &tid);
    if (!p) {
        /* No record: an aggregated call's failure, an anonymous mapping or mremap, or a native helper's I/O (only on
         * a thread native_io_threads marked) may go to agg (sys_agg); any other call, of any process, costs this array
         * lookup only (a read, write, send or receive also the task-storage lookup). */
        long id = regs->orig_ax;
        struct task_struct* task = bpf_get_current_task_btf();
        __u32 index = (__u32)id + (compat_syscall(task) ? MM_SYSCALLS : 0);
        struct mm_aggcfg* c = id >= 0 && id < MM_SYSCALLS ? bpf_map_lookup_elem(&aggcfg, &index) : 0;
        if (c && c->mode && (ret < 0 || c->mode >= MM_AGG_MMAP) &&   /* MMAP, MREMAP, NATIVE_IO */
            (c->mode != MM_AGG_NATIVE_IO || bpf_task_storage_get(&native_io_threads, task, 0, 0)))
            sys_agg(id, ret, 1);
        return 0;
    }
    __u32 nr = p->nr;
    struct mm_sysinfo* info = bpf_map_lookup_elem(&sysinfo, &nr);
    if (!info) {
        bpf_map_delete_elem(&pending, &tid);
        return 0;
    }
    /* Wine's request/reply/wait pipes: their bytes are the requests mm_ws_* decode, so they are only counted. */
    if ((p->mode & S_IFMT) == S_IFIFO && bpf_map_lookup_elem(&ws_pipes, &p->ino)) {
        bpf_map_delete_elem(&pending, &tid);
        return 0;
    }
    /* wineserver doing the work of the client whose request it read last. */
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct mm_ws_serving* serving = bpf_map_lookup_elem(&ws_serving, &tgid);
    if (serving && !p->target_tgid) {
        p->target_tgid = serving->tgid;
        p->served_req = serving->req;
        p->flags |= MM_F_SERVING;
    }
    /* execve/execveat are logged by sched_process_exec when they succeed. */
    if (info->want == 2 && ret == 0) {
        bpf_map_delete_elem(&pending, &tid);
        return 0;
    }
    /* clone/fork: a success is its MM_FORK or MM_THREAD_START; only failures and new namespaces are kept. */
    if (info->want == 3 && ret >= 0) {
        __u64 flags = nr == NR_FORK || nr == NR_VFORK ? 0 : p->args[0];
        if (nr == NR_CLONE3 && bpf_probe_read_user(&flags, sizeof(flags), (void*)p->args[0])) flags = 0;
        if (!(flags & CLONE_NEW_ANY)) {
            bpf_map_delete_elem(&pending, &tid);
            return 0;
        }
    }
    /* ipc(SHMAT) returns 0 and puts the address at args[3]; the x86_64 shmat returns it. */
    if ((p->flags & MM_F_IPC) && nr == NR_SHMAT && ret == 0) {
        __u32 address = 0;
        if (bpf_probe_read_user(&address, sizeof(address), (void*)p->args[3]) == 0) ret = address;
    }
    struct task_struct* task = bpf_get_current_task_btf();
    __u64 now = bpf_ktime_get_boot_ns();
    p->ret = ret;
    p->dur_ns = now - p->ts_ns;
    p->ts_ns = now;
    if (info->retfd && ret >= 0) resolve_fd(p, task, (int)ret);
    if (ret >= 0 && (info->sock == MM_SOCK_OUT_1 || info->sock == MM_SOCK_OUT_4)) {
        const void* address = (const void*)(info->sock == MM_SOCK_OUT_1 ? p->args[1] : p->args[4]);
        const int* lengthPointer = (const int*)(info->sock == MM_SOCK_OUT_1 ? p->args[2] : p->args[5]);
        int length = 0;
        if (lengthPointer && bpf_probe_read_user(&length, sizeof(length), lengthPointer) == 0 && length > 0)
            read_sockaddr(p, address, (__u32)length);
    }
    if (ret >= 0 && info->sock == MM_SOCK_MSG_OUT_1) read_msg_name(p, (const void*)p->args[1]);
    record_extra(p, info->more.outfd);
    /* A desktop service connection's call, for the agent's service decoders; no branch here (states). */
    unix_head(p, info->data, info->flags_arg);
    /* Its chunks go to payload_ring before the record goes to events (the agent relies on it). */
    capture_payload(p, info, ret);
    long bytes = bpf_get_stack(ctx, p->stack, sizeof(p->stack), BPF_F_USER_STACK);
    p->frames = bytes > 0 ? (__u32)(bytes / sizeof(__u64)) : 0;
    read_pe_any(&p->pe, task, regs, (p->flags & MM_F_COMPAT) != 0);
    /* A record without a PE context leaves out mm_event.pe (bpf.cpp OnRing). Verifier-safe: two
     * reservations of constant size, each copied with that same constant. */
    if (p->pe.rip) {
        struct mm_event* e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (!e) {
            count_drop();
        } else {
            bpf_probe_read_kernel(e, sizeof(*e), p);
            bpf_ringbuf_submit(e, 0);
        }
    } else {
        void* e = bpf_ringbuf_reserve(&events, MM_EVENT_SHORT, 0);
        if (!e) {
            count_drop();
        } else {
            bpf_probe_read_kernel(e, MM_EVENT_SHORT, p);
            bpf_ringbuf_submit(e, 0);
        }
    }
    bpf_map_delete_elem(&pending, &tid);
    return 0;
}

/* MM_TRACK_HANDOFF for a process winebrowser.exe forks (Wine names a process's main thread after its Windows image,
 * 15 bytes and a NUL): the sign-in hand-off's native chain (xdg-open, the browser, its helpers) goes to handoff_depth. */
static __always_inline __u32 handoff_fork(void)
{
    struct task_struct* leader = BPF_CORE_READ(bpf_get_current_task_btf(), group_leader);
    __u64 comm[2] = {};
    if (!leader || bpf_core_read(comm, sizeof(comm), &leader->comm)) return 0;
    return comm[0] == 0x776f7262656e6977ull && comm[1] == 0x6578652e726573ull ? MM_TRACK_HANDOFF : 0;   /* winebrowser.exe */
}

/* Tracking is copied inside copy_process, before the child can run. */
SEC("tp_btf/task_newtask")
int BPF_PROG(mm_newtask, struct task_struct* task, __u64 clone_flags)
{
    __u32 parent = bpf_get_current_pid_tgid() >> 32;
    struct mm_tracked* from = bpf_map_lookup_elem(&tracked, &parent);
    if (!from) return 0;
    __u32 pid = BPF_CORE_READ(task, pid);
    __u32 tgid = BPF_CORE_READ(task, tgid);
    if (pid != tgid) return 0;   /* a thread shares its process's entry */
    struct mm_tracked entry = {};
    entry.start_ns = BPF_CORE_READ(task, start_boottime);
    /* MsMonFlagInheritedTrack; a native helper's, the hand-off's and the launch's child is one */
    entry.flags = 2 | (from->flags & (MM_TRACK_NATIVE | MM_TRACK_HANDOFF | MM_TRACK_LAUNCH)) | handoff_fork();
    entry.depth = from->depth;
    bpf_map_update_elem(&tracked, &tgid, &entry, BPF_ANY);
    return 0;
}

/* The current Wine thread's ClientId (Windows process and thread id) into args[0], args[1]; 0 when it has no
 * TEB (a unix thread) or its memory is gone. 64-bit: GS base TEB +0x40; ia32: the TLS-descriptor TEB +0x20.
 * Verifier-safe: teb32's three unrolled steps and constant-size probe reads. */
static __always_inline void win_ids(struct mm_event* s)
{
    struct task_struct* task = bpf_get_current_task_btf();
    s->args[0] = s->args[1] = 0;
    __u64 teb = task->thread.gsbase, self = 0;
    if (teb && bpf_probe_read_user(&self, sizeof(self), (const void*)(teb + MM_TEB_SELF)) == 0 && self == teb) {
        __u64 ids[2] = {};
        if (bpf_probe_read_user(ids, sizeof(ids), (const void*)(teb + 0x40)) == 0) {
            s->args[0] = (__u32)ids[0];
            s->args[1] = (__u32)ids[1];
        }
        return;
    }
    teb = teb32(task);
    __u32 ids32[2] = {};
    if (teb && bpf_probe_read_user(ids32, sizeof(ids32), (const void*)(teb + 0x20)) == 0) {
        s->args[0] = ids32[0];
        s->args[1] = ids32[1];
    }
}

static __always_inline void emit_task(__u32 kind, struct task_struct* task, __u32 target)
{
    struct mm_event* s = fresh_scratch();
    if (!s) return;
    s->kind = kind;
    s->args[0] = s->args[1] = 0;
    /* A thread's Windows ids, as the Windows thread notify gives them: at exit the exiting task is current and
     * its TEB is still mapped (sched_process_exit runs before exit_mm). At start (sched_process_fork, in the
     * parent) the new thread has no TEB yet; its ids come with its first wineserver request. */
    if (kind == MM_THREAD_EXIT && BPF_CORE_READ(task, pid) == (__u32)bpf_get_current_pid_tgid()) win_ids(s);
    s->tgid = BPF_CORE_READ(task, tgid);
    s->tid = BPF_CORE_READ(task, pid);
    s->ppid = BPF_CORE_READ(task, real_parent, tgid);
    s->start_ns = BPF_CORE_READ(task, group_leader, start_boottime);
    s->ts_ns = bpf_ktime_get_boot_ns();
    s->target_tgid = target;
    s->args[2] = BPF_CORE_READ(task, exit_code);   /* at exit: do_exit's code (wait status: status << 8 or the signal) */
    struct mm_event* e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        count_drop();
        return;
    }
    bpf_probe_read_kernel(e, sizeof(*e), s);
    bpf_ringbuf_submit(e, 0);
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(mm_fork, struct task_struct* parent, struct task_struct* child)
{
    __u32 tgid = BPF_CORE_READ(parent, tgid);
    if (!bpf_map_lookup_elem(&tracked, &tgid)) return 0;
    __u32 childPid = BPF_CORE_READ(child, pid);
    __u32 childTgid = BPF_CORE_READ(child, tgid);
    if (childPid == childTgid) {
        struct mm_event* s = fresh_scratch();
        if (!s) return 0;
        s->kind = MM_FORK;
        s->tgid = childTgid;
        s->tid = childPid;
        s->ppid = tgid;
        s->start_ns = BPF_CORE_READ(child, start_boottime);
        s->ts_ns = bpf_ktime_get_boot_ns();
        s->target_tgid = childTgid;
        struct mm_event* e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (!e) {
            count_drop();
            return 0;
        }
        bpf_probe_read_kernel(e, sizeof(*e), s);
        bpf_ringbuf_submit(e, 0);
    } else {
        emit_task(MM_THREAD_START, child, 0);
    }
    return 0;
}

/* One MM_ARGV record (8 KiB: too big for the stack). */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct mm_argv);
} argvbuf SEC(".maps");

/* MM_ARGV: the new image's whole argv, read from its mm (exec copied it there just before this tracepoint, so it is
 * resident and no later exec can race it), and the end of its environment, where a launcher's WINE* and LD_*
 * variables are appended. shortcut: variables before the last MM_ARGV_BYTES are not kept; also read from
 * env_start when one is needed. Verifier-safe: two reads whose sizes are clamped to MM_ARGV_BYTES after a barrier,
 * at offsets 0 and <= MM_ARGV_BYTES of data[2 * MM_ARGV_BYTES], and one ring output of at most the record. */
static __always_inline void emit_argv(struct task_struct* task, struct mm_event* s)
{
    __u32 zero = 0;
    struct mm_argv* a = bpf_map_lookup_elem(&argvbuf, &zero);
    if (!a) return;
    __u64 arg_start = BPF_CORE_READ(task, mm, arg_start), arg_end = BPF_CORE_READ(task, mm, arg_end);
    __u64 env_start = BPF_CORE_READ(task, mm, env_start), env_end = BPF_CORE_READ(task, mm, env_end);
    a->kind = MM_ARGV;
    a->tgid = s->tgid;
    a->start_ns = s->start_ns;
    a->argv_total = arg_end > arg_start ? (__u32)(arg_end - arg_start) : 0;
    __u32 n = a->argv_total < MM_ARGV_BYTES ? a->argv_total : MM_ARGV_BYTES;
    barrier_var(n);
    if (n > MM_ARGV_BYTES) return;
    if (bpf_probe_read_user(a->data, n, (void*)arg_start)) n = 0;
    __u32 m = env_end > env_start ? (__u32)(env_end - env_start) : 0;
    if (m > MM_ARGV_BYTES) m = MM_ARGV_BYTES;
    barrier_var(m);
    if (m > MM_ARGV_BYTES) return;
    if (bpf_probe_read_user(&a->data[n & (2 * MM_ARGV_BYTES - 1)], m, (void*)(env_end - m))) m = 0;
    a->argv_len = n;
    a->env_len = m;
    __u32 size = n + m;
    barrier_var(size);
    if (size > 2 * MM_ARGV_BYTES) return;
    if (bpf_ringbuf_output(&events, a, __builtin_offsetof(struct mm_argv, data) + size, 0)) count_drop();
}

/* MM_ENV records (4 KiB each: too big for the stack). */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct mm_env);
} envbuf SEC(".maps");

struct env_ctx {
    __u64 start;
    __u64 end;
    __u64 start_ns;
    __u32 tgid;
};

/* bpf_loop callback: the environment's chunk Index as one MM_ENV record. Verifier-safe: one read whose size is clamped
 * to MM_ARGV_BYTES after a barrier into data[MM_ARGV_BYTES], one ring output of at most the record. */
static long env_chunk(__u32 index, struct env_ctx* c)
{
    __u32 zero = 0;
    struct mm_env* v = bpf_map_lookup_elem(&envbuf, &zero);
    __u64 at = c->start + (__u64)index * MM_ARGV_BYTES;
    if (!v || at >= c->end) return 1;
    __u32 n = c->end - at < MM_ARGV_BYTES ? (__u32)(c->end - at) : MM_ARGV_BYTES;
    barrier_var(n);
    if (n == 0 || n > MM_ARGV_BYTES || bpf_probe_read_user(v->data, n, (void*)at) != 0) return 1;
    v->kind = MM_ENV;
    v->tgid = c->tgid;
    v->start_ns = c->start_ns;
    v->offset = index * MM_ARGV_BYTES;
    v->len = n;
    v->total = (__u32)(c->end - c->start);
    if (bpf_ringbuf_output(&events, v, __builtin_offsetof(struct mm_env, data) + n, 0)) {
        count_drop();
        return 1;
    }
    return 0;
}

/* Scope: an untracked process that execs a Wine loader (wine, a preloader, wineserver) in a directory under a root is
 * the client from its first instruction, not from its first executable mapping there: Wine starts a Windows program
 * with its current directory as the unix one (ntdll's fork_and_exec), so Wine's start-up is recorded too. MM_SCOPE
 * with nr MM_SCOPE_WINE_EXEC and that directory. */
static __always_inline void scope_wine_exec(struct task_struct* task, __u32 tgid)
{
    struct mm_config* c = cfg();
    if (!c || !any_root(c) || tgid == c->agent_tgid || !wine_image()) return;
    struct fs_struct* fs = BPF_CORE_READ(task, fs);
    struct mm_event* s = fresh_scratch();
    if (!fs || !s || walk_path(__builtin_preserve_access_index(&fs->pwd), s->kpath) < 0 || !under_root(c, s->kpath)) return;
    struct mm_tracked entry = {};
    entry.start_ns = BPF_CORE_READ(task, group_leader, start_boottime);
    entry.flags = 1;   /* MsMonFlagExplicitTrack */
    if (bpf_map_update_elem(&tracked, &tgid, &entry, BPF_NOEXIST) != 0) return;
    s->kind = MM_SCOPE;
    s->nr = MM_SCOPE_WINE_EXEC;
    s->flags = MM_F_KPATH;
    fill_identity(s, task);
    if (bpf_ringbuf_output(&events, s, sizeof(*s), 0)) count_drop();
}

/* Scope: the first exec of kfilterctl launch's child (the launch wrapper: nexon-launcher and its xdpyinfo, grep and
 * /usr/bin/wine), which joined its session cgroup kfilter/launch-<launcher pid> before the exec (filter/tool/
 * linux_client.cpp), so the launch is recorded from its first instruction, not from Wine's exec under a root or a
 * decision kfilter names it in. Only the launcher's own child matches (its parent's pid is in the cgroup's name): a
 * descendant that left tracking and execs again in that cgroup does not join. MM_SCOPE with nr MM_SCOPE_LAUNCH and
 * kpath the cgroup's name; tracked MM_TRACK_LAUNCH. Global, so mm_exec's verification does not grow with it. */
__noinline int scope_launch(void)
{
    struct mm_config* c = cfg();
    struct task_struct* task = bpf_get_current_task_btf();
    const __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    if (!c || tgid == c->agent_tgid) return 0;
    struct cgroup* cgrp = BPF_CORE_READ(task, cgroups, dfl_cgrp);
    if (!cgrp || BPF_CORE_READ(cgrp, level) != 2) return 0;
    char name[MM_CGROUP_NAME] = {};
    __u64 parent = 0;
    if (bpf_probe_read_kernel_str(name, sizeof(name), BPF_CORE_READ(cgrp, kn, name)) <= 0 ||
        bpf_probe_read_kernel(&parent, sizeof(parent), BPF_CORE_READ(cgrp, self.parent, cgroup, kn, name)) ||
        parent != 0x7265746c69666bull)   /* "kfilter" */
        return 0;
    const __u32 launcher = mm_launch_cgroup_pid(name);
    if (!launcher || launcher != BPF_CORE_READ(task, real_parent, tgid)) return 0;
    struct mm_event* s = fresh_scratch();
    if (!s) return 0;
    struct mm_tracked entry = {};
    entry.start_ns = BPF_CORE_READ(task, group_leader, start_boottime);
    entry.flags = 1 | MM_TRACK_LAUNCH;   /* MsMonFlagExplicitTrack */
    if (bpf_map_update_elem(&tracked, &tgid, &entry, BPF_NOEXIST) != 0) return 0;
    s->kind = MM_SCOPE;
    s->nr = MM_SCOPE_LAUNCH;
    s->flags = MM_F_KPATH;
    __builtin_memcpy(s->kpath, name, sizeof(name));
    fill_identity(s, task);
    if (bpf_ringbuf_output(&events, s, sizeof(*s), 0)) count_drop();
    return 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(mm_exec, struct task_struct* task, pid_t old_pid, struct linux_binprm* bprm)
{
    __u32 tgid = BPF_CORE_READ(task, tgid);
    struct mm_tracked* tracking = bpf_map_lookup_elem(&tracked, &tgid);
    if (!tracking) {
        scope_wine_exec(task, tgid);
        if (!bpf_map_lookup_elem(&tracked, &tgid)) scope_launch();
        tracking = bpf_map_lookup_elem(&tracked, &tgid);
        if (!tracking) return 0;
    }
    struct mm_event* s = fresh_scratch();
    if (!s) return 0;
    s->kind = MM_EXEC;
    fill_identity(s, task);
    /* The whole environment (MM_ENV, the agent writes it as process_environment), then the argv record (MM_ARGV), both
     * before MM_EXEC: the agent joins them to that record. */
    struct env_ctx env = {.start = BPF_CORE_READ(task, mm, env_start), .end = BPF_CORE_READ(task, mm, env_end),
                          .start_ns = s->start_ns, .tgid = s->tgid};
    if (env.end > env.start) bpf_loop(MM_ENV_CHUNKS, env_chunk, &env, 0);
    emit_argv(task, s);
    bpf_probe_read_kernel_str(s->path_a, MM_PATH, BPF_CORE_READ(bprm, filename));
    struct file* file = BPF_CORE_READ(bprm, file);
    if (file && walk_path(__builtin_preserve_access_index(&file->f_path), s->kpath) >= 0) s->flags |= MM_F_KPATH;
    /* The argv the execve entry captured, keyed by the thread that called it. */
    __u32 tid = (__u32)old_pid;
    struct mm_event* p = bpf_map_lookup_elem(&pending, &tid);
    if (p && (p->flags & MM_F_ARGV)) {
        bpf_probe_read_kernel(s->path_b, sizeof(s->path_b), p->path_b);
        s->flags |= MM_F_ARGV;
    }
    if (p && tid != s->tid) bpf_map_delete_elem(&pending, &tid);   /* a thread's exec: its sys_exit comes as the leader */
    /* A native program (xdg-open, a browser) is not the client, but kfilter keeps deciding for it: it stays tracked as
     * a native helper (MM_TRACK_NATIVE: the calls mm_sysinfo.more.native marks, its I/O aggregated, sockets not
     * captured) for native_depth native execs in a row (handoff_depth in the sign-in hand-off); deeper, it and its
     * children leave tracking (the agent forgets it on this record). The launch wrapper's programs are in scope until a
     * Wine loader's exec, which ends the wrapper. args[0]: its native depth (0: a Wine or in-scope image), args[1]: 1
     * when it leaves tracking here. */
    struct mm_config* c = cfg();
    __u32 depth = 0, drop = 0;
    const __u32 wine = wine_image(), flags = tracking->flags;
    if (!wine && !(flags & MM_TRACK_LAUNCH) && !(c && (s->flags & MM_F_KPATH) && under_root(c, s->kpath))) {
        depth = (flags & MM_TRACK_NATIVE) ? tracking->depth + 1 : 1;
        drop = !c || depth > ((flags & MM_TRACK_HANDOFF) ? c->handoff_depth : c->native_depth);
    }
    s->args[0] = depth;
    s->args[1] = drop;
    struct mm_event* e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        count_drop();
    } else {
        bpf_probe_read_kernel(e, sizeof(*e), s);
        bpf_ringbuf_submit(e, 0);
    }
    if (drop) {
        bpf_map_delete_elem(&tracked, &tgid);
    } else {
        tracking->flags = depth ? (flags | MM_TRACK_NATIVE)
                                : (flags & ~(MM_TRACK_NATIVE | MM_TRACK_HANDOFF | (wine ? MM_TRACK_LAUNCH : 0)));
        tracking->depth = depth;
    }
    return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(mm_exit, struct task_struct* task, bool group_dead)
{
    __u32 tgid = BPF_CORE_READ(task, tgid);
    if (!bpf_map_lookup_elem(&tracked, &tgid)) return 0;
    __u32 tid = BPF_CORE_READ(task, pid);
    if (bpf_map_lookup_elem(&pending, &tid)) {   /* its call's sys_exit never came: that record is lost */
        count_loss(MM_LOSS_PENDING_STALE);
        bpf_map_delete_elem(&pending, &tid);
    }
    emit_task(group_dead ? MM_EXIT : MM_THREAD_EXIT, task, 0);
    if (group_dead) bpf_map_delete_elem(&tracked, &tgid);
    return 0;
}

/* Scope: an untracked process that maps an executable file under a root is the client.
 * Also used from file_mprotect, the path Wine takes: it maps PE sections without
 * PROT_EXEC and mprotects the code sections executable afterwards. */
static __always_inline int scope_file(struct file* file)
{
    struct mm_config* c = cfg();
    if (!file || !c || !any_root(c)) return 0;
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    if (tgid == c->agent_tgid || bpf_map_lookup_elem(&tracked, &tgid)) return 0;
    struct mm_event* s = fresh_scratch();
    if (!s) return 0;
    if (walk_path(__builtin_preserve_access_index(&file->f_path), s->kpath) < 0) return 0;
    if (!under_root(c, s->kpath)) return 0;
    struct task_struct* task = bpf_get_current_task_btf();
    struct mm_tracked entry = {};
    entry.start_ns = BPF_CORE_READ(task, group_leader, start_boottime);
    entry.flags = 1;             /* MsMonFlagExplicitTrack */
    bpf_map_update_elem(&tracked, &tgid, &entry, BPF_NOEXIST);
    s->kind = MM_SCOPE;
    s->nr = 0;
    s->flags = MM_F_KPATH;
    fill_identity(s, task);
    struct mm_event* e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        count_drop();
        return 0;
    }
    bpf_probe_read_kernel(e, sizeof(*e), s);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* MM_IMAGE: a tracked process's executable mapping of File with the verdict every LSM (kfilter's BPF LSM
 * included) returned, so a refused load is recorded too (Windows PsSetLoadImageNotifyRoutine parity; the agent
 * turns it into image_load at once instead of waiting for the maps poll). */
static __always_inline void emit_image(void* ctx, struct file* file, __u32 hook, __u64 base, __u64 size, __u64 prot, __u64 flags,
                                       __u64 offset, int ret)
{
    if (!current_tracked()) return;
    struct mm_event* s = fresh_scratch();
    if (!s) return;
    struct task_struct* task = bpf_get_current_task_btf();
    s->kind = MM_IMAGE;
    s->nr = hook;
    fill_identity(s, task);
    s->args[0] = base;
    s->args[1] = size;
    s->args[2] = prot;
    s->args[3] = flags;
    s->args[4] = offset;
    s->args[5] = 0;
    s->ret = ret;
    s->mode = BPF_CORE_READ(file, f_inode, i_mode);
    s->ino = BPF_CORE_READ(file, f_inode, i_ino);
    int result = walk_path(__builtin_preserve_access_index(&file->f_path), s->kpath);
    if (result >= 0) s->flags |= MM_F_KPATH | (result ? MM_F_TRUNC_K : 0);
    long bytes = bpf_get_stack(ctx, s->stack, sizeof(s->stack), BPF_F_USER_STACK);
    s->frames = bytes > 0 ? (__u32)(bytes / sizeof(__u64)) : 0;
    struct mm_event* e = bpf_ringbuf_reserve(&events, MM_EVENT_SHORT, 0);
    if (!e) {
        count_drop();
        return;
    }
    bpf_probe_read_kernel(e, MM_EVENT_SHORT, s);
    bpf_ringbuf_submit(e, 0);
}

/* fexit, not lsm/: msmon takes no part in the decision (an LSM program would change attach-order behaviour and
 * would not see kfilter's verdict: the first nonzero BPF LSM return skips the programs after it). Ret is
 * the final verdict. Scope runs on any verdict: a refused client mapping still names the client. */
SEC("fexit/security_mmap_file")
int BPF_PROG(mm_mmap_file, struct file* file, unsigned long prot, unsigned long flags, int ret)
{
    if (!file || (prot & PROT_EXEC) == 0) return 0;
    scope_file(file);
    emit_image(ctx, file, MM_IMAGE_MMAP, 0, 0, prot, flags, 0, ret);
    return 0;
}

SEC("fexit/security_file_mprotect")
int BPF_PROG(mm_file_mprotect, struct vm_area_struct* vma, unsigned long reqprot, unsigned long prot, int ret)
{
    if ((prot & PROT_EXEC) == 0) return 0;
    struct file* file = BPF_CORE_READ(vma, vm_file);
    if (!file) return 0;
    scope_file(file);
    /* The vma may extend past the mprotect range (it is split afterwards); start - offset is the mapping base. */
    __u64 start = BPF_CORE_READ(vma, vm_start), end = BPF_CORE_READ(vma, vm_end);
    emit_image(ctx, file, MM_IMAGE_MPROTECT, start, end - start, prot, 0, (__u64)BPF_CORE_READ(vma, vm_pgoff) << 12, ret);
    return 0;
}

static __always_inline int deny(__u32 what, __u32 target)
{
    struct task_struct* task = bpf_get_current_task_btf();
    struct mm_event* s = fresh_scratch();
    if (s) {
        s->kind = MM_DENIED;
        s->nr = what;
        s->target_tgid = target;
        fill_identity(s, task);
        struct mm_event* e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            bpf_probe_read_kernel(e, sizeof(*e), s);
            bpf_ringbuf_submit(e, 0);
        } else {
            count_drop();
        }
    }
    return -EPERM;
}

/* The agent or kfilterd (the monitors), whose tgids the agent configured (0: none). */
static __always_inline int monitor_tgid(const struct mm_config* c, __u32 tgid)
{
    return c && tgid != 0 && (tgid == c->agent_tgid || tgid == c->kfilterd_tgid);
}

/* Self-protection: the monitors (the agent and kfilterd) stay out of the tracked tree's reach (ptrace and signals),
 * which changes nothing the client does to anything else. A BPF LSM program runs only while every program before it
 * returned 0, so ret is 0 here; it is passed on unchanged. */
SEC("lsm/ptrace_access_check")
int BPF_PROG(mm_ptrace, struct task_struct* child, unsigned int mode, int ret)
{
    struct mm_config* c = cfg();
    if (ret != 0) return ret;
    __u32 target = BPF_CORE_READ(child, tgid);
    if (!monitor_tgid(c, target) || !current_tracked()) return 0;
    return deny(MM_DENY_PTRACE, target);
}

SEC("lsm/task_kill")
int BPF_PROG(mm_kill, struct task_struct* p, struct kernel_siginfo* info, int sig, const struct cred* cred, int ret)
{
    struct mm_config* c = cfg();
    if (ret != 0) return ret;
    __u32 target = BPF_CORE_READ(p, tgid);
    if (!monitor_tgid(c, target) || !current_tracked()) return 0;
    return deny(MM_DENY_KILL, target);
}

/* bpf() and perf_event_open are refused to the tracked tree only with MM_CFG_PROTECT_TREE (agent
 * --protect-tree): by default msmon observes only and the syscalls are recorded with their result (system:bpf,
 * system:perf_event_open). */
static __always_inline int protect_tree(void)
{
    struct mm_config* c = cfg();
    return c && (c->flags & MM_CFG_PROTECT_TREE) && current_tracked();
}

SEC("lsm/bpf")
int BPF_PROG(mm_bpf, int cmd, union bpf_attr* attr, unsigned int size, bool kernel, int ret)
{
    if (ret != 0) return ret;
    if (kernel || !protect_tree()) return 0;
    return deny(MM_DENY_BPF, 0);
}

SEC("lsm/perf_event_open")
int BPF_PROG(mm_perf, int type, int ret)
{
    if (ret != 0) return ret;
    if (!protect_tree()) return 0;
    return deny(MM_DENY_PERF, 0);
}

/* Upgrade programs, each in its own file (docs/LINUX.md "Kernel sensor upgrades"). Each group of
 * programs is optional: bpf.cpp loads the object without a group the verifier refuses. */
#include "socks.bpf.h"   /* mm_socks socket tags, mm_sock_* (shared by tcp and packets) */
#include "tcp.bpf.h"     /* mm_tcp_* */
#include "pkt.bpf.h"     /* mm_skb_* */
#include "ws.bpf.h"      /* mm_ws_* */
#include "kev.bpf.h"     /* mm_uring_*, mm_kev_*, mm_fault_* */
#include "up.bpf.h"      /* mm_up_* */
