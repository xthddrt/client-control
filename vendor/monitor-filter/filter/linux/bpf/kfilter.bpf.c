// SPDX-License-Identifier: GPL-2.0
/*
 * kfilterd's kernel layer (see docs/LINUX.md): LSM hooks that decide every open, read,
 * write, exec, delete, rename, link, truncate, chmod/chown/xattr, file mapping, device
 * ioctl, process-memory access, signal, socket connect/bind/listen/accept, incoming packet,
 * netlink query and registry request of a protected program, in the kernel, from the
 * policy kfilterd compiled into maps. The decision follows driver/policy.c
 * KfDecideWithRights: first matching rule in policy order, allow must cover every requested
 * right, counted rules take a use in an open phase, audit/would-deny in audit mode, deny in
 * block mode.
 *
 * Under Wine the program is a Windows one and much of its work is done by others:
 * wineserver opens its files, connects its sockets, reads other processes' memory and keeps
 * its registry; winedevice.exe answers its device requests. Those operations are decided as
 * the program's own (KFILTER_EVENT_FLAG_BROKERED): wineserver is charged to the client whose
 * request it is serving, from the moment it reads the client's request pipe until it writes
 * the reply. Registry requests never reach a syscall, so they are decoded from the client's
 * own write to wineserver and refused there (the write fails with EFAULT, which Wine turns
 * into STATUS_ACCESS_VIOLATION for that call). Each Wine process is named by its Windows
 * image (argv[0], which Wine rewrites to C:\...\Program.exe), and rules can be scoped to it.
 *
 * Paths are rebuilt from dentries (bpf_d_path is refused in non-sleepable hooks) in the
 * task's mount namespace. Protection is task storage: a task created by a protected task
 * is protected from allocation, before it can run. Working memory is per task (task
 * storage), so a decision preempted on this CPU cannot see another task's state; hooks that
 * run in softirq use a per-CPU area of their own.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "kfilter_bpf.h"
#include "../../driver/kfilter.h"

char LICENSE[] SEC("license") = "GPL";

extern struct task_struct* bpf_task_from_pid(s32 pid) __ksym;
extern void bpf_task_release(struct task_struct* p) __ksym;

#define EPERM 1
#define ENOENT 2
#define EFAULT 14
#define ENOMEM 12
#define SIGKILL 9
#define SIGSTOP 19
#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define PROT_EXEC 0x4
#define MAP_SHARED 0x01
#define MAP_FIXED 0x10
#define MAP_FIXED_NOREPLACE 0x100000
#define MAY_WRITE 0x2
#define MAY_READ 0x4
#define MAY_ACCESS 0x10
#define MAY_CHDIR 0x40
#define AT_FDCWD -100
#define AT_EMPTY_PATH 0x1000
#define FMODE_READ 0x1
#define FMODE_WRITE 0x2
#define FMODE_EXEC 0x20
/* open flag of an exec open (do_open_execat). Since 6.8 LSMs must test it: f_mode only
 * gains FMODE_EXEC after security_file_open has run. */
#define __FMODE_EXEC 0x20
#define O_TRUNC 01000
#define O_CREAT 0100
#define O_EXCL 0200
#define S_IFMT 0170000
#define S_IFDIR 0040000
#define S_IFCHR 0020000
#define S_IFBLK 0060000
#define S_IFREG 0100000
#define S_IFIFO 0010000
#define VM_WRITE 0x2
#define VM_EXEC 0x4
#define PTRACE_MODE_ATTACH 0x02
#define PTRACE_MODE_NOAUDIT 0x04
#define CLONE_THREAD 0x00010000
#define AF_UNIX 1
#define AF_INET 2
#define AF_INET6 10
#define AF_NETLINK 16
#define AF_PACKET 17
#define MFD_EXEC 0x10
#define MSG_FASTOPEN 0x20000000
#define NETLINK_ROUTE 0
#define NETLINK_SOCK_DIAG 4
#define RTM_GETLINK 18
#define RTM_GETADDR 22
#define RTM_GETROUTE 26
#define RTM_GETNEIGH 30
#define PR_SET_MM 35
#define TS_COMPAT 0x0002
#define ATTR_ATIME_SET (1 << 7)
#define ATTR_MTIME_SET (1 << 8)
#define ATTR_TOUCH (1 << 17)
/* Filesystem identity ioctls on any file: the Linux volume serial (block-volume-serial). */
#define FS_IOC_GETFSUUID 0x80111500u
#define FS_IOC_GETFSSYSFSPATH 0x80811501u
#define FS_IOC_GETFSLABEL 0x81009431u
/* Interface ioctls on a socket (SIOCGIFNAME..SIOCGIFMAP, ethtool, wireless): adapter identity. */
#define SIOC_IF_FIRST 0x8910u
#define SIOC_IF_LAST 0x8970u
#define SIOC_WIRELESS_FIRST 0x8B00u
#define SIOC_WIRELESS_LAST 0x8BFFu
/* Windows process access: PROCESS_TERMINATE, for a signal to an outside process. */
#define KB_PROCESS_TERMINATE 0x1
#define STATUS_OBJECT_NAME_INVALID ((__s32)0xC0000033)
#define STATUS_ACCESS_DENIED ((__s32)0xC0000022)
/* Pseudo filesystems whose objects have no path the policy names. */
#define SOCKFS_MAGIC 0x534F434B
#define PIPEFS_MAGIC 0x50495045
#define ANON_INODE_FS_MAGIC 0x09041934
#define NSFS_MAGIC 0x6e736673
#define PIDFS_MAGIC 0x50494446
#define BPF_FS_MAGIC 0xcafe4a11
#define DMA_BUF_MAGIC 0x444d4142
#define SECRETMEM_MAGIC 0x5345434d
#define PROC_SUPER_MAGIC 0x9fa0
#define MQUEUE_MAGIC 0x19800202
/* Process access bits a HANDLE/OPEN rule must grant for memory access (VM_OPERATION|READ|WRITE). */
#define KB_PROCESS_MEMORY_RIGHTS 0x38
/* task_struct.flags: an io_uring worker, a kernel thread. */
#define PF_IO_WORKER 0x00000010
#define PF_KTHREAD 0x00200000
#define KB_FILE_TARGETS (KFILTER_TARGET_FILE | KFILTER_TARGET_DIR | KFILTER_TARGET_PIPE)
#define WALK_LEN 4096
#define WALK_MASK (WALK_LEN - 1)
#define GLOB_STEPS 8192
#define NONE 0xFFFFFFFFu
/* Which text a glob runs over. */
#define TEXT_PATH 0
#define TEXT_VALUE 1
#define TEXT_IMAGE 2

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct kb_cfg);
} kb_config SEC(".maps");

/*
 * A policy's rules are a rule set: kb_rules, kb_literal, kb_globs (KB_GLOB_END after the last), kb_netrules (zeroed
 * from the last on), kb_used and kb_phase, or the second set of _b maps. kfilterd compiles each policy into the set
 * not in force and then flips kb_live, so a lookup, which reads kb_live once (scratch set), never sees two
 * policies' rules mixed; set 0's maps are the ones a kfilterd before the second set pinned.
 * shortcut: each lookup (kb_decide_global, kb_outside_rights, kb_net_decide_global, kb_msg_decide_global) reads
 * kb_live itself, so a request a hook decides by several (a Wine registry write: request, key, rename; a send:
 * address, DNS name, message) can have its parts decided by the two policies when a reload switches between them,
 * and pass where each policy alone refuses one part; read kb_live once per hook invocation if that moment matters.
 */
struct kb_rule_map {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, KB_RULES);
    __type(key, __u32);
    __type(value, struct kb_rule);
};

struct kb_literal_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, KB_RULES);
    __type(key, struct kb_key);
    __type(value, struct kb_slots);
};

struct kb_glob_map {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, KB_GLOBS);
    __type(key, __u32);
    __type(value, __u32);
};

struct kb_net_map {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, KB_NET);
    __type(key, __u32);
    __type(value, struct kb_net);
};

/* Uses taken per counted rule: rules first, then network rules (as policy.c's Used). */
struct kb_used_map {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, KB_RULES + KB_NET);
    __type(key, __u32);
    __type(value, __u32);
};

struct kb_phase_map {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct kb_state);
};

struct kb_rule_map kb_rules SEC(".maps");
struct kb_literal_map kb_literal SEC(".maps");
struct kb_glob_map kb_globs SEC(".maps");
struct kb_net_map kb_netrules SEC(".maps");
struct kb_used_map kb_used SEC(".maps");
struct kb_phase_map kb_phase SEC(".maps");
struct kb_rule_map kb_rules_b SEC(".maps");
struct kb_literal_map kb_literal_b SEC(".maps");
struct kb_glob_map kb_globs_b SEC(".maps");
struct kb_net_map kb_netrules_b SEC(".maps");
struct kb_used_map kb_used_b SEC(".maps");
struct kb_phase_map kb_phase_b SEC(".maps");

/* The rule set in force: 0 or 1. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} kb_live SEC(".maps");

/* The Wine requests some system rule names past /system/wine/ (KB_WINE_ROOT), one bit each by number: any other
 * request without a row of its own (kb_wreqs) is left at once, as most of a program's requests are (select). */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, KB_WNAMED_WORDS);
    __type(key, __u32);
    __type(value, __u64);
} kb_wnamed SEC(".maps");

/* Each part of a rule set by set number. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 2);
    __type(key, __u32);
    __array(values, struct kb_rule_map);
} kb_rule_sets SEC(".maps") = {.values = {&kb_rules, &kb_rules_b}};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 2);
    __type(key, __u32);
    __array(values, struct kb_literal_map);
} kb_literal_sets SEC(".maps") = {.values = {&kb_literal, &kb_literal_b}};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 2);
    __type(key, __u32);
    __array(values, struct kb_glob_map);
} kb_glob_sets SEC(".maps") = {.values = {&kb_globs, &kb_globs_b}};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 2);
    __type(key, __u32);
    __array(values, struct kb_net_map);
} kb_net_sets SEC(".maps") = {.values = {&kb_netrules, &kb_netrules_b}};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 2);
    __type(key, __u32);
    __array(values, struct kb_used_map);
} kb_used_sets SEC(".maps") = {.values = {&kb_used, &kb_used_b}};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 2);
    __type(key, __u32);
    __array(values, struct kb_phase_map);
} kb_phase_sets SEC(".maps") = {.values = {&kb_phase, &kb_phase_b}};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct kb_launch);
} kb_launch_pass SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct kb_task);
} kb_tasks SEC(".maps");

/* Wine processes by tgid: their Windows image and whether they are protected. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, struct kb_proc);
} kb_procs SEC(".maps");

/* Windows pid of a process being created -> the creator's tgid, until the child's first request names it. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
} kb_creators SEC(".maps");

/* A zeroed kb_proc to create entries from (too large for the stack). */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct kb_proc);
} kb_proc_zero SEC(".maps");

/* softirq nesting per CPU: the two receive hooks also run from a socket's backlog in
 * process context, where a softirq can interrupt them. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} kb_irq_depth SEC(".maps");

/* Wine request and reply pipes by inode address. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct kb_pipe);
} kb_pipes SEC(".maps");

/* Registry key handles of protected processes and their NT names. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct kb_hkey_id);
    __type(value, struct kb_hkey);
} kb_hkeys SEC(".maps");

/* Process and thread handles of Wine processes and what they reach (thread-handle rules). */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct kb_hkey_id);
    __type(value, struct kb_ohandle);
} kb_ohandles SEC(".maps");

/* The process a handle kfilter could not name reaches, as wineserver's reply to a get_process_info or get_thread_info
 * through it named it (learn_handle): used for addr= decisions only; every other request through such a handle is
 * decided on the placeholder \@unknown, which only rules naming it meet. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct kb_hkey_id);
    __type(value, __u32);
} kb_learnt SEC(".maps");

/* Window owners (struct kb_window), by the low 16 bits of a window handle, from the create_window and
 * get_desktop_window replies of every decoded Wine process. wineserver finds a window by those bits alone when the
 * handle's high word is 0 or 0xFFFF, else only at that generation; a window dies with its thread without a
 * destroy_window, so an entry of another generation is stale. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct kb_window);
} kb_windows SEC(".maps");

/* NT names of the files a protected program opened with create_file (a volume, a file), by handle, while a keyed rule
 * can name them (ioctl, read, write): apart from kb_hkeys, whose registry names these opens would push out. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct kb_hkey_id);
    __type(value, struct kb_hkey);
} kb_fnames SEC(".maps");

/* The RPC interface bound on a named pipe handle (struct kb_rpc), by handle. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct kb_hkey_id);
    __type(value, struct kb_rpc);
} kb_rpcs SEC(".maps");

/* Handles of Wine processes known not to be processes or threads (an unnamed section, and its copies):
 * a copy of one with explicit access is not decided as a process handle kfilter did not see made. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct kb_hkey_id);
    __type(value, __u32);
} kb_xhandles SEC(".maps");

/* A non-process handle copied into a process kfilter could not identify: Wine runs a DuplicateHandle from another
 * process as an APC in the source (APC_DUP_HANDLE), into a destination handle wineserver made for it. The copy's
 * value, until the initiator's get_apc_result reply names it (then kb_xhandles of the initiator). shortcut: by
 * value alone; two such copies with one value at the same time may mark the wrong one; upgrade: key by APC. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
} kb_xmoved SEC(".maps");

#define KB_REQ_GET_APC_RESULT 20
#define KB_APC_DUP_HANDLE 15

/* kb_pending.object.thread of a request whose reply handle is no process or thread (kb_xhandles). */
#define KB_OBJECT_OTHER 2

/* Wineserver just gave out handle Id: whatever kfilter recorded for that number before is stale (the
 * old handle was closed in a way kfilter did not see), so it is forgotten before the new one is recorded:
 * a stale thread or process record would decide a token's copy as a process handle (nexon_client.exe). */
static __always_inline void fresh_handle(struct kb_hkey_id* id)
{
    bpf_map_delete_elem(&kb_hkeys, id);
    bpf_map_delete_elem(&kb_ohandles, id);
    bpf_map_delete_elem(&kb_xhandles, id);
    bpf_map_delete_elem(&kb_learnt, id);
    bpf_map_delete_elem(&kb_fnames, id);
    bpf_map_delete_elem(&kb_rpcs, id);
}

/* A handle a process inherited at its start, as no process or thread: wineserver copies a creator's
 * inheritable handles into the child at the same values (Chromium hands its children events and sections
 * so), and kfilter did not see them made there. Looked up in the creator's table (kb_proc.creator), and
 * recorded for the child. shortcut: one creator up, and a value the creator closed or reused since the
 * child started reads as the creator's current handle; upgrade: copy records at new_process if it matters. */
static __always_inline int inherited_other(struct kb_hkey_id* id)
{
    struct kb_proc* proc = bpf_map_lookup_elem(&kb_procs, &id->tgid);
    if (!proc || proc->creator == 0 || proc->creator == id->tgid) return 0;
    struct kb_hkey_id parent = {proc->creator, id->handle};
    if (!bpf_map_lookup_elem(&kb_xhandles, &parent)) return 0;
    __u32 one = 1;
    bpf_map_update_elem(&kb_xhandles, id, &one, BPF_ANY);
    return 1;
}

/* Requests (protocol 930) whose reply's first field is a new handle to an object that is no process or
 * thread: APCs, reserve objects, events (also a process's idle event and a service's shutdown event), keyed events,
 * mutexes, semaphores, create_file, alloc_file_handle, a lock's wait, debug objects and exception events, timers,
 * message queues, async waits, window stations (the process's own too), desktops, tokens (open, duplicate, filter),
 * mailslots, symlinks, device managers, completions, jobs, alert fds, shared GPU objects. (Named files, pipes, sections
 * and directories go through kb_nt_object and kb_hkeys; an unnamed create_mapping through unnamed_section; a driver's
 * handle to a process or thread through kb_kobjects.) An exact list: a reply whose first field is not a handle must
 * not be recorded as one (create_device's reply has no fields). */
static __always_inline int object_maker(__u32 req)
{
    switch (req) {
    case 19: case 24: case 30: case 33: case 34: case 35: case 36: case 38: case 40: case 43: case 44: case 46:
    case 53: case 77: case 79: case 100: case 101: case 113: case 118: case 133: case 135: case 170: case 171:
    case 174: case 177: case 178: case 179: case 219: case 220: case 225: case 226: case 237: case 242: case 243:
    case 250: case 259: case 262: case 263: case 264: case 283: case 284: case 297: case 302: case 303:
        return 1;
    default:
        return 0;
    }
}

/* The process or thread behind a kernel object pointer winedevice gave wineserver for one of its handles
 * (set_kernel_object_ptr), by {tgid, pointer}: the handle get_kernel_object_handle later makes from that pointer (a
 * driver opening the process with any access) reaches it. */
struct kb_kobject_id {
    __u32 tgid;
    __u32 pad;
    __u64 ptr;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct kb_kobject_id);
    __type(value, struct kb_ohandle);
} kb_kobjects SEC(".maps");

/* Requests waiting for wineserver's reply, by client thread id. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct kb_pending);
} kb_pending SEC(".maps");

/* Wine thread id (TEB ClientId) -> tgid, to name the client of a device request. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, __u32);
} kb_wintids SEC(".maps");

/* winedevice.exe thread id -> tgid of the client whose device request it is handling. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
} kb_serving SEC(".maps");

/* Opens already decided for a program, by struct file address (see struct kb_grant). */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, struct kb_grant);
} kb_files SEC(".maps");

/* Connections blocked with kfilterctl block-connection: socket inode -> directions. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u32);
} kb_blocked SEC(".maps");

/* Message rules' unix= patterns (struct kb_unix_name) by set * KB_NET + slot, written with their set: a slot whose kb_net
 * is not a unix rule is never read. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2 * KB_NET);
    __type(key, __u32);
    __type(value, struct kb_unix_name);
} kb_unix_names SEC(".maps");

/* The code ranges of protected Wine programs' own modules (kb_mods), by tgid. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct kb_mods);
} kb_mods SEC(".maps");

/* addr= rules' ranges (struct kb_ranges), by rule set and the rule's slot in it: set << 16 | slot. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2 * KB_ADDRESS_RULES);
    __type(key, __u32);
    __type(value, struct kb_ranges);
} kb_ranges SEC(".maps");

/* Module bases for addr= (struct kb_base) of the programs kb_mods has, by tgid. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct kb_base);
} kb_bases SEC(".maps");

/* Images a program with a module table has mapped or made executable so far, by tgid (kfilterd makes the entry,
 * the kernel counts): its kb_bases entry is current while it was read at this count. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
} kb_modseq SEC(".maps");

/* What the decision being made reaches in memory (struct kb_access). */
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct kb_access);
} kb_accesses SEC(".maps");

/* A Wine request's data as wineserver reads it: the chunks of its writev after the header joined, its first
 * KB_REQ_DATA bytes (struct kb_reqdata), which the decoders read so that a name split across chunks is still whole;
 * a name past them (behind a security descriptor of 4 KiB) is joined again from its own offset (kb_request_at).
 * Copied a block at a time (the block past KB_REQ_DATA bounds a copy for the verifier; a value over 8 KiB is not
 * allocated without sleeping). */
#define KB_REQ_DATA 4096
#define KB_REQ_BLOCK 256
#define KB_REQ_CHUNKS 5          /* __SERVER_MAX_DATA */
struct kb_reqdata {
    __u64 iov;                   /* join_step's state, in map memory so the verifier's states converge */
    __u64 base, length, done;    /* the chunk being copied */
    __u32 count, compat, chunk, at, stop;
    __u32 skip;                  /* bytes of the data still to pass over before joining */
    __u8 data[KB_REQ_DATA + KB_REQ_BLOCK];
};

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct kb_reqdata);
} kb_reqdata SEC(".maps");

#ifdef KB_TEST_BENCH
/* The write kb_bench_pipe hands kb_wine_request in place of the task's syscall registers. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct kb_bench_io);
} kb_bench_ios SEC(".maps");
#endif

/* PE image views of protected Wine programs, by {tgid, base}: Wine maps an image's header page
 * from its file at offset 0 (MAP_FIXED) at the view's base, and copies the sections whose file
 * alignment is under a page into anonymous memory above it. A stale entry is harmless: the header
 * is read again from the program's memory before anything counts as inside an image. */
struct kb_view {
    __u32 tgid;
    __u32 pad;
    __u64 base;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct kb_view);
    __type(value, __u32);
} kb_views SEC(".maps");

/* Sockets created by protected programs: the owner, for hooks that run in softirq, and the
 * UDP peers this socket has already been authorised to talk to. */
struct kb_peer {
    __u8 address[16];
    __u32 port;
    __u32 family;
};

struct kb_sock {
    __u32 tgid;
    __u32 generation;
    __u32 next;
    __u32 sent;       /* messages sent so far (send attempts by the program) */
    __u32 received;   /* receive attempts */
    struct kb_peer peer[8];
};

struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct kb_sock);
} kb_socks SEC(".maps");

/* The task that made a pipe, recorded when the task is one kfilter follows (see kb_pipe_alloc). */
struct kb_pipe_creator {
    __u32 tgid;
    __u32 inside;        /* made by the family or by wineserver (Wine's own plumbing): never decided */
};

struct {
    __uint(type, BPF_MAP_TYPE_INODE_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct kb_pipe_creator);
} kb_pipe_creators SEC(".maps");

/* Decisions to kfilterd (about 650 bytes each): 64 MiB holds about 100,000, a Chromium launcher's start-up
 * burst (23,000 a second) with room to spare; 16 MiB dropped 2,206 of them. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 << 20);
} kb_events SEC(".maps");

/* Programs wmi_provider stopped (tgid: the thread), until kfilterd resumes them: a kfilterd that
 * takes a pinned layer over resumes those its predecessor left stopped. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
} kb_wmi_stopped SEC(".maps");

/* Decisions the ring could not hold; kfilterd adds them to DroppedEvents. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} kb_drops SEC(".maps");

struct kb_scratch {
    char path[KB_PATH];
    char pattern[KB_PATH];   /* a rule path plus a slash-star suffix; masked indexes keep loops cheap to verify */
    char value[KB_VALUE];
    char image[KB_PROG];     /* the program the decision is for (its Windows image under Wine) */
    __u32 len;
    __u32 vlen;
    __u32 ilen;
    __u32 ibase;             /* start of the file name in image */
    __u32 failed;            /* the path could not be resolved or was too long */
    __u32 doubled;           /* the name just converted has repeated backslashes (kb_collapse) */
    __u32 cursor;            /* kb_collapse's write position */
    __u32 set;               /* the rule set (kb_live) the decision under way reads */
    __u32 ncand;
    __u32 cand[KB_CANDIDATES];
    __u8 address[16];
    __u32 tgid;              /* the program the decision is for */
    __u32 brokered;          /* made by wineserver or winedevice on its behalf */
    __u32 any_value;         /* registry value enumeration: every value-scoped deny applies */
    __u32 rename_chars;      /* registry rename: characters of the new name in name */
    __u32 msize;             /* message: its byte count */
    __u32 mlen;              /* message: bytes of it in walk */
    __u32 mindex;            /* message: its number on its connection */
    __u64 minode;            /* message: its socket's inode */
    __u64 caller;            /* message: return address into the calling module (0: unknown) */
    __u32 mbits;             /* message: the module= bits of that module */
    __u32 pe_words;          /* message: 8-byte words of the Windows stack in walk */
    __u32 dlabel;            /* DNS query: bytes left in the name's current label */
    __u32 owner_tid;         /* registry open/create: the thread whose reply carries the handle */
    __u32 htarget;           /* thread handle: the rule kind (THREAD_OPEN/THREAD_HANDLE, PROCESS: none) */
    __u32 hremoved;          /* thread handle: the rights a rule must grant */
    __u32 haccess;           /* thread handle: the access asked for */
    __u32 outside_rule;      /* kb_outside_rights: the rule that decided, 0 when none */
    /* Loop state kept here, not on the stack: a value loaded from a map is unknown to the
     * verifier, so the loops below converge instead of being followed step by step. */
    __u32 woff;
    __u32 slow, shigh;       /* pe_caller's binary search */
    __u32 gp, gt, gstar, gmark, gplen, gtlen;
    __u64 hfnv;              /* path hashes while probing literal rules */
    __u32 hdjb;
    __u32 request[16];       /* a Wine request header: req, request_size, reply_size, fields */
    __u8 name[KB_PATH];      /* a UTF-16 name from a Wine request */
    struct kb_pending pending;
    char walk[WALK_LEN + 256];
};

/* Working memory: per task in task context (a preempted decision keeps its own), per CPU
 * in softirq (which nothing on that CPU can preempt). */
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct kb_scratch);
} kb_scratch_tasks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, struct kb_scratch);
} kb_scratch_irq SEC(".maps");

static __always_inline struct kb_scratch* scratch(void)
{
    return bpf_task_storage_get(&kb_scratch_tasks, bpf_get_current_task_btf(), 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
}

/* Irq is the nesting slot of a receive hook (1 or 2), 0 in task context. */
static __always_inline struct kb_scratch* scratch_irq(__u32 irq)
{
    __u32 slot = (irq - 1) & 1;
    return bpf_map_lookup_elem(&kb_scratch_irq, &slot);
}

static __always_inline struct kb_scratch* scratch_for(__u32 irq)
{
    return irq ? scratch_irq(irq) : scratch();
}

/* Enters a receive hook: its slot (1 or 2), 0 when nested deeper (not decided). */
static __always_inline __u32 irq_enter(void)
{
    __u32 zero = 0;
    __u32* depth = bpf_map_lookup_elem(&kb_irq_depth, &zero);
    if (!depth) return 0;
    __u32 slot = __sync_fetch_and_add(depth, 1) + 1;
    if (slot > 2) {
        __sync_fetch_and_sub(depth, 1);
        return 0;
    }
    return slot;
}

static __always_inline void irq_leave(void)
{
    __u32 zero = 0;
    __u32* depth = bpf_map_lookup_elem(&kb_irq_depth, &zero);
    if (depth) __sync_fetch_and_sub(depth, 1);
}

static __always_inline struct kb_cfg* kb_cfg_get(void)
{
    __u32 zero = 0;
    return bpf_map_lookup_elem(&kb_config, &zero);
}

static __always_inline __u32 live_set(void)
{
    __u32 zero = 0;
    __u32* live = bpf_map_lookup_elem(&kb_live, &zero);
    return live && *live == 1 ? 1 : 0;
}

/* Rule Slot of rule set *Set, the decision's latched scratch set (a key in map memory takes no stack). */
static __always_inline struct kb_rule* rule_at(__u32* set, __u32 slot)
{
    void* rules = bpf_map_lookup_elem(&kb_rule_sets, set);
    return rules ? bpf_map_lookup_elem(rules, &slot) : 0;
}

static __always_inline struct kb_task* task_state(struct task_struct* task)
{
    if (!task) return 0;
    return bpf_task_storage_get(&kb_tasks, task, 0, 0);
}

static __always_inline __u32 current_tgid(void)
{
    return bpf_get_current_pid_tgid() >> 32;
}

static __always_inline __u32 current_tid(void)
{
    return (__u32)bpf_get_current_pid_tgid();
}

/* Program Tgid mapped or made executable some code: if kfilterd keeps its module table,
 * ask it (once until it rereads) to reread the program's maps. */
static __always_inline void modules_changed(__u32 tgid)
{
    struct kb_mods* mods = bpf_map_lookup_elem(&kb_mods, &tgid);
    if (!mods || mods->dirty) return;
    mods->dirty = 1;
    struct kb_event* e = bpf_ringbuf_reserve(&kb_events, sizeof(*e), 0);
    if (!e) return;   /* dirty stays set: the next refresh (kfilterd's own timer) covers it */
    __builtin_memset(e, 0, sizeof(*e));
    e->kind = KB_EV_MODULES;
    e->tgid = tgid;
    bpf_ringbuf_submit(e, 0);
}

/* Wine registers an image view program Tgid mapped (Req map_image_view or map_builtin_view: a DLL or EXE load), the
 * only mapping that moves an addr= module base: its kb_bases entry is not current until kfilterd has reread its maps.
 * Data views, anonymous code (JIT, unpacking) and protection changes leave it current. */
static __always_inline void image_mapped(__u32 req, __u32 tgid)
{
    if (req != KB_REQ_MAP_IMAGE_VIEW && req != KB_REQ_MAP_BUILTIN_VIEW) return;
    __u32* seq = bpf_map_lookup_elem(&kb_modseq, &tgid);
    if (!seq) return;
    __sync_fetch_and_add(seq, 1);
    modules_changed(tgid);
}

static __always_inline int proc_guarded(__u32 tgid)
{
    struct kb_proc* proc = bpf_map_lookup_elem(&kb_procs, &tgid);
    return proc && proc->guarded;
}

/* For handle crossings: protected, or a Wine process a protected one created (kb_proc.creator) that is
 * not named yet - Chromium opens its new child (PROCESS_QUERY_INFORMATION) before Wine names it, and
 * its exec was decided at admission. */
static __always_inline int family_member(__u32 tgid)
{
    struct kb_proc* proc = bpf_map_lookup_elem(&kb_procs, &tgid);
    if (!proc) return 0;
    if (proc->guarded) return 1;
    __u32 creator = proc->creator;
    return creator != 0 && creator != tgid && proc_guarded(creator);
}

/* A task of the protected family: its own mark, or (a Wine thread) its process's. */
static __always_inline int task_protected(struct task_struct* task, struct kb_task* state)
{
    if (!state) return 0;
    if (state->guarded) return 1;
    return state->role == KB_ROLE_WINE && proc_guarded(BPF_CORE_READ(task, tgid));
}

static __always_inline int protected_current(void)
{
    struct task_struct* task = bpf_get_current_task_btf();
    return task_protected(task, task_state(task));
}

/* The program's image into s->image (nothing for a process Wine has not named). */
static __always_inline void load_image(struct kb_scratch* s, __u32 tgid)
{
    struct kb_proc* proc = bpf_map_lookup_elem(&kb_procs, &tgid);
    s->ilen = 0;
    s->ibase = 0;
    s->image[0] = 0;
    if (!proc || proc->ilen == 0 || proc->ilen >= KB_PROG) return;
    bpf_probe_read_kernel(s->image, KB_PROG, proc->image);
    s->ilen = proc->ilen;
    s->ibase = proc->ibase < KB_PROG ? proc->ibase : 0;
}

/* Scratch for a decision about Tgid, made by the current task itself. */
static __always_inline struct kb_scratch* reset_for(__u32 tgid, __u32 brokered)
{
    struct kb_scratch* s = scratch();
    if (!s) return 0;
    s->failed = 0;
    s->vlen = 0;
    s->len = 0;
    s->any_value = 0;
    s->tgid = tgid;
    s->brokered = brokered;
    load_image(s, tgid);
    return s;
}

/*
 * Starts a decision when the current task works for a protected program: the program
 * itself, wineserver serving its request, or winedevice handling its device request.
 * Returns 0 with the scratch set up (s->tgid, s->brokered, s->image), 1 when the task works
 * for no protected program, -ENOMEM when it does but no working memory could be had.
 */
static __always_inline int begin(void)
{
    struct task_struct* task = bpf_get_current_task_btf();
    struct kb_task* state = task_state(task);
    if (!state) return 1;   /* not kfilter's: never refused here (only a protected program's decision is) */
    __u32 tgid = current_tgid();
    __u32 subject = 0, brokered = 0;
    if (state->guarded) {
        subject = tgid;
    } else if (state->role == KB_ROLE_WINE) {
        struct kb_proc* proc = bpf_map_lookup_elem(&kb_procs, &tgid);
        if (proc && proc->guarded) {
            state->guarded = 1;   /* admitted by its Windows image; cached on the thread */
            subject = tgid;
        } else if (proc && proc->device_host) {
            __u32 tid = current_tid();
            __u32* client = bpf_map_lookup_elem(&kb_serving, &tid);
            if (client && *client != 0 && proc_guarded(*client)) {
                subject = *client;
                brokered = 1;
            }
        }
    } else if (state->role == KB_ROLE_WINESERVER && state->client != 0 && proc_guarded(state->client)) {
        subject = state->client;
        brokered = 1;
    }
    if (subject == 0) return 1;
    if (reset_for(subject, brokered)) return 0;
    /* No working memory for a protected program's decision: refuse in block mode. */
    struct kb_cfg* c = kb_cfg_get();
    return c && c->enabled && c->mode == KFILTER_MODE_BLOCK ? -ENOMEM : 1;
}

/* Starts a decision in an LSM hook, or returns: 0 when there is nothing to decide. */
#define BEGIN()                                      \
    do {                                             \
        int started_ = begin();                      \
        if (started_ != 0) return started_ < 0 ? -ENOMEM : 0; \
    } while (0)

static __always_inline int gated(__u32 bit);
static __always_inline int system_begin(void);
__noinline int kb_unix_listen(__u64 skAddress, __u32 tgid);
__noinline int kb_reach_decide(__u32 actor, __u64 targetAddress, __u32 access, __u32 value, __u32 flags);
static __always_inline int owner_decide(__s32 who);
#define KB_REACH_SIGIO 1       /* kb_reach_decide's Flags: a signal a file raises (SIGIO) */
#define KB_REACH_INTO 2        /* ... the target task is protected (its hook's BTF pointer can say) */
#define KB_REACH_QUERY 4       /* ... a PTRACE_MODE_READ check (block-process-queries), not a signal (block-process-signals) */

/* Global functions (verified once each); LSM programs must return a bounded errno. */
__noinline int kb_decide_global(__u32 target, __u32 rights, __u32 value, __u32 listed);
__noinline int kb_net_decide_global(__u32 irq, __u32 tgid, __u32 kind, __u32 port, __u32 right);
__noinline int kb_wine_query(__u32 tgid, __u32 ownerTid, __u64 data, __u32 size);
__noinline int kb_thread_decide(__u32 fork);
__noinline int kb_memory_decide(__u64 start, __u64 end, __u32 prot, __u32 shared);
__noinline int kb_system_decide(__u32 rights, __u32 listed);
__noinline int kb_unknown_peer(__u64 childAddress, __u32 client, __u32 clientTid);
__noinline int kb_count_take(__u32 set, __u32 count, __u32 slot, __u32 peek);
__noinline int kb_address_match(__u32 slot, __u32 action);
__noinline int kb_access_text(void);
__noinline __u32 kb_request_access(__u32 target, __u64 data, __u32 size);
__noinline int kb_proc_mem(__u64 fileAddress, __u32 mask);
__noinline int kb_wine_note(__u32 tgid, __u32 ownerTid, __u64 data, __u32 size);
__noinline int kb_wine_variant(__u32 index, __u64 data, __u32 size);
__noinline int kb_wine_decide(void);
__noinline __u64 kb_request_at(__u32 at, __u32 bytes);


/* 0, -EPERM, or -ENOENT for a refusal by a hide rule. */
static __always_inline int kb_decided(int result)
{
    return result == 0 ? 0 : result == -ENOENT ? -ENOENT : -EPERM;
}

static __always_inline int kb_decide(__u32 target, __u32 rights, __u32 value)
{
    return kb_decided(kb_decide_global(target, rights, value, 0));
}

/* kb_decide, except that a request no rule matches is allowed without an event whatever the
 * default: /anon files, and every KFILTER_TARGETS_RULE_ONLY target (kb_decide too). */
static __always_inline int kb_decide_listed(__u32 target, __u32 rights, __u32 value)
{
    return kb_decided(kb_decide_global(target, rights, value, 1));
}

static __always_inline int kb_net_decide(__u32 irq, __u32 tgid, __u32 family, __u32 protocol, __u32 port, __u32 right)
{
    /* Five arguments at most: family and protocol travel as (family << 8) | protocol. */
    return kb_net_decide_global(irq, tgid, (family << 8) | (protocol & 0xFF), port, right) != 0 ? -EPERM : 0;
}

/* ---- paths ---- */

/* A kernel pointer as a plain integer (global functions take only scalars). */
static __always_inline __u64 address_of(const void* pointer)
{
    __u64 value = 0;
    bpf_probe_read_kernel(&value, sizeof(value), &pointer);
    return value;
}

struct walk_ctx {
    struct dentry* d;
    struct vfsmount* vfs;
    struct mount* mnt;
    __u32 done;   /* the walk reached the root or a pseudo file's name */
};

static long walk_step(__u32 index, struct walk_ctx* c)
{
    struct kb_scratch* s = scratch();
    if (!s) return 1;
    struct dentry* d = c->d;
    struct vfsmount* vfs = c->vfs;
    struct mount* mnt = c->mnt;
    struct dentry* root = BPF_CORE_READ(vfs, mnt_root);
    if (d == root) {
        struct mount* parent = BPF_CORE_READ(mnt, mnt_parent);
        if (!parent || parent == mnt) {
            c->done = 1;
            return 1;
        }
        c->d = BPF_CORE_READ(mnt, mnt_mountpoint);
        c->mnt = parent;
        c->vfs = (struct vfsmount*)((void*)parent + bpf_core_field_offset(struct mount, mnt));
        return 0;
    }
    struct dentry* up = BPF_CORE_READ(d, d_parent);
    if (!up) return 1;
    /* Self-parented but not its filesystem's root: a pseudo file with no path (memfd:<name>,
     * SYSV<key>, the dev/zero of shared-anonymous memory). It is named /anon/<its name>, which
     * no real path can be (never "/"). */
    int pseudo = up == d;
    if (pseudo && d == BPF_CORE_READ(d, d_sb, s_root)) {
        c->done = 1;
        return 1;
    }
    __u32 len = BPF_CORE_READ(d, d_name.len) & 255;
    const unsigned char* name = BPF_CORE_READ(d, d_name.name);
    __u32 off = s->woff;
    if (len == 0 || off <= len + 1 + (pseudo ? 5 : 0)) {
        s->woff = 0;   /* too deep for the buffer */
        return 1;
    }
    off -= len;
    bpf_probe_read_kernel(&s->walk[off & WALK_MASK], len, name);
    off -= 1;
    s->walk[off & WALK_MASK] = '/';
    if (pseudo) {
        off -= 5;
        __builtin_memcpy(&s->walk[off & WALK_MASK], "/anon", 5);
    }
    s->woff = off;
    c->d = up;
    c->done = pseudo;
    return pseudo;
}

/* The absolute path of Dentry on Vfs into s->path / s->len; sets s->failed otherwise.
 * Global (verified once): the pointers travel as integers and are only probe-read. */
__noinline int kb_walk(__u64 dentryAddress, __u64 vfsAddress)
{
    struct dentry* dentry = (struct dentry*)dentryAddress;
    struct vfsmount* vfs = (struct vfsmount*)vfsAddress;
    struct kb_scratch* s = scratch();
    if (!s) return -1;
    s->len = 0;
    s->path[0] = 0;
    if (!dentry || !vfs) {
        s->failed = 1;
        return -1;
    }
    struct walk_ctx c = {};
    c.d = dentry;
    c.vfs = vfs;
    c.mnt = (struct mount*)((void*)vfs - bpf_core_field_offset(struct mount, mnt));
    s->woff = WALK_LEN - 1;
    s->walk[WALK_LEN - 1] = 0;
    bpf_loop(64, walk_step, &c, 0);
    __u32 off = s->woff;
    /* Cut off (deeper than 64 steps): its tail could read as any path, /anon/... too. */
    if (!c.done || off == 0 || off > WALK_LEN - 1) {
        s->failed = 1;
        return -1;
    }
    if (off == WALK_LEN - 1) {
        off -= 1;
        s->walk[off & WALK_MASK] = '/';
    }
    __u32 length = WALK_LEN - 1 - off;
    if (length >= KB_PATH) {
        s->failed = 1;
        return -1;
    }
    bpf_probe_read_kernel_str(s->path, KB_PATH, &s->walk[off & WALK_MASK]);
    s->len = length;
    return 0;
}

static __always_inline int walk_path(const struct path* path)
{
    return kb_walk((__u64)BPF_CORE_READ(path, dentry), (__u64)BPF_CORE_READ(path, mnt));
}

static __always_inline int walk_file(struct file* file)
{
    return walk_path(__builtin_preserve_access_index(&file->f_path));
}

/* A dentry without its mount (inode hooks): the filesystem's first mount. */
static __always_inline int walk_inode_dentry(struct dentry* dentry)
{
    struct super_block* sb = BPF_CORE_READ(dentry, d_sb);
    struct mount* mnt = BPF_CORE_READ(sb, s_mounts);
    if (!mnt) {
        struct kb_scratch* s = scratch();
        if (s) s->failed = 1;
        return -1;
    }
    return kb_walk(address_of(dentry), (__u64)((void*)mnt + bpf_core_field_offset(struct mount, mnt)));
}

/* s->path += "/" + Name, for the path hooks that name an entry in a directory. */
static __always_inline int append_name(struct dentry* dentry)
{
    struct kb_scratch* s = scratch();
    if (!s || s->failed) return -1;
    __u32 len = BPF_CORE_READ(dentry, d_name.len);
    const unsigned char* name = BPF_CORE_READ(dentry, d_name.name);
    __u32 at = s->len;
    if (at == 1) at = 0;   /* the parent is "/" */
    if (len == 0 || len > 255 || at + 1 + len >= KB_PATH) {
        s->failed = 1;
        return -1;
    }
    s->path[at & (KB_PATH - 1)] = '/';
    bpf_probe_read_kernel(&s->path[(at + 1) & (KB_PATH - 1)], len & 255, name);
    at = at + 1 + len;
    s->path[at & (KB_PATH - 1)] = 0;
    s->len = at;
    return 0;
}

static __always_inline int walk_entry(const struct path* dir, struct dentry* dentry)
{
    if (walk_path(dir) != 0) return -1;
    return append_name(dentry);
}

static __always_inline __u32 inode_mode(struct inode* inode)
{
    return inode ? BPF_CORE_READ(inode, i_mode) : 0;
}

static __always_inline unsigned long fs_magic(struct inode* inode)
{
    return BPF_CORE_READ(inode, i_sb, s_magic);
}

static __always_inline int pseudo_fs(struct inode* inode)
{
    unsigned long magic = fs_magic(inode);
    return magic == SOCKFS_MAGIC || magic == PIPEFS_MAGIC || magic == ANON_INODE_FS_MAGIC || magic == NSFS_MAGIC ||
           magic == PIDFS_MAGIC || magic == BPF_FS_MAGIC || magic == DMA_BUF_MAGIC || magic == SECRETMEM_MAGIC;
}

/* Identity character devices, as fanotify.cpp IdentityDevice. */
static __always_inline int starts_with(struct kb_scratch* s, const char* prefix, __u32 n)
{
    if (s->len < n) return 0;
    for (__u32 i = 0; i < 16; i++) {
        if (i >= n) break;
        if (s->path[i] != prefix[i]) return 0;
    }
    return 1;
}

/* s->path ends in Suffix (n bytes, n <= 32). */
static __always_inline int ends_with(struct kb_scratch* s, const char* suffix, __u32 n)
{
    if (s->len < n || s->len >= KB_PATH) return 0;
    __u32 start = s->len - n;
    for (__u32 i = 0; i < 32; i++) {
        if (i >= n) break;
        if (s->path[(start + i) & (KB_PATH - 1)] != suffix[i]) return 0;
    }
    return 1;
}

static __always_inline int identity_device(struct kb_scratch* s)
{
    return starts_with(s, "/dev/hidraw", 11) || starts_with(s, "/dev/sg", 7) || starts_with(s, "/dev/bsg/", 9) ||
           starts_with(s, "/dev/bus/usb/", 13) || starts_with(s, "/dev/nvme", 9);
}

static __always_inline __u32 lower(__u8 c)
{
    return (c >= 'A' && c <= 'Z') ? c + 32 : c;
}

/* A fixed name (under 32 bytes) as s->path, for decisions on things that have no file. */
static __always_inline void set_path(struct kb_scratch* s, const char* text, __u32 n)
{
    for (__u32 i = 0; i < 32; i++) {
        if (i >= n) break;
        s->path[i] = text[i];
    }
    s->path[n & 31] = 0;
    s->len = n;
    s->failed = 0;
}

/* s->path += Text (n < 32 bytes); a path too long for KB_PATH is a name failure. */
static __always_inline void append_text(struct kb_scratch* s, const char* text, __u32 n)
{
    __u32 at = s->len;
    if (at + n >= KB_PATH) {
        s->failed = 1;
        return;
    }
    for (__u32 i = 0; i < 32; i++) {
        if (i >= n) break;
        s->path[(at + i) & (KB_PATH - 1)] = text[i];
    }
    s->len = at + n;
    s->path[s->len & (KB_PATH - 1)] = 0;
}

/* s->path += Number in decimal. */
static __always_inline void append_number(struct kb_scratch* s, __u32 number)
{
    char digits[16];
    __u32 n = 0;
    for (__u32 i = 0; i < 10; i++) {
        digits[i] = '0' + number % 10;
        number /= 10;
        n = i + 1;
        if (number == 0) break;
    }
    __u32 at = s->len;
    if (at + n >= KB_PATH) {
        s->failed = 1;
        return;
    }
    for (__u32 i = 0; i < 10; i++) {
        if (i >= n) break;
        s->path[(at + i) & (KB_PATH - 1)] = digits[(n - 1 - i) & 15];
    }
    s->len = at + n;
    s->path[s->len & (KB_PATH - 1)] = 0;
}

/* s->path += the low N (<= 8) hex digits of Value, lowercase. */
static __always_inline void append_hex(struct kb_scratch* s, __u32 value, __u32 n)
{
    static const char hex[] = "0123456789abcdef";
    __u32 at = s->len;
    if (at + n >= KB_PATH) {
        s->failed = 1;
        return;
    }
    for (__u32 i = 0; i < 8; i++) {
        if (i >= n) break;
        s->path[(at + i) & (KB_PATH - 1)] = hex[(value >> ((4 * (n - 1 - i)) & 31)) & 0xF];
    }
    s->len = at + n;
    s->path[s->len & (KB_PATH - 1)] = 0;
}

/* s->path += the string at Address (user memory when User), cut to fit. */
static __always_inline void append_string(struct kb_scratch* s, const void* address, int user)
{
    __u32 at = s->len & (KB_PATH - 1);
    __u32 room = KB_PATH - 1 - at;
    long n = user ? bpf_probe_read_user_str(&s->path[at], room & (KB_PATH - 1), address)
                  : bpf_probe_read_kernel_str(&s->path[at], room & (KB_PATH - 1), address);
    if (n > 0) s->len = at + (__u32)n - 1;
    s->path[s->len & (KB_PATH - 1)] = 0;
}

/* KfExtensionMask of s->path. */
struct ext_ctx {
    __u32 dot;
    __u32 stop;
};

static long ext_step(__u32 index, struct ext_ctx* c)
{
    struct kb_scratch* s = scratch();
    if (!s || index >= s->len || index >= KB_PATH) return 1;
    __u32 at = s->len - 1 - index;
    char ch = s->path[at & (KB_PATH - 1)];
    if (ch == '/' || ch == '\\') return 1;
    if (ch == '.') {
        c->dot = at;
        return 1;
    }
    return 0;
}

static __always_inline __u32 extension_mask(struct kb_scratch* s)
{
    struct ext_ctx c = {NONE, 0};
    bpf_loop(KB_PATH, ext_step, &c, 0);
    if (c.dot == NONE || c.dot + 4 != s->len) return KFILTER_EXT_OTHER;
    __u32 a = lower(s->path[(c.dot + 1) & (KB_PATH - 1)]);
    __u32 b = lower(s->path[(c.dot + 2) & (KB_PATH - 1)]);
    __u32 d = lower(s->path[(c.dot + 3) & (KB_PATH - 1)]);
    if (a == 'e' && b == 'x' && d == 'e') return KFILTER_EXT_EXE;
    if (a == 'd' && b == 'l' && d == 'l') return KFILTER_EXT_DLL;
    if (a == 's' && b == 'y' && d == 's') return KFILTER_EXT_SYS;
    if (a == 'o' && b == 'c' && d == 'x') return KFILTER_EXT_OCX;
    return KFILTER_EXT_OTHER;
}

/* ---- KfMatchGlob over s->pattern (Plen) and s->path, s->value or s->image ---- */

struct glob_ctx {
    __u32 icase, text, result, irq;   /* result: 0 running, 1 match, 2 no match */
};

static long glob_step(__u32 index, struct glob_ctx* g)
{
    struct kb_scratch* s = scratch_for(g->irq);
    if (!s) {
        g->result = 2;
        return 1;
    }
    __u32 p = s->gp, t = s->gt, plen = s->gplen;
    char pc = p < plen ? s->pattern[p & (KB_PATH - 1)] : 0;
    if (t < s->gtlen) {
        if (p < plen && pc == '*') {
            s->gp = p + 1;
            s->gstar = p + 1;
            s->gmark = t;
            return 0;
        }
        char tc = g->text == TEXT_VALUE   ? s->value[t & (KB_VALUE - 1)]
                  : g->text == TEXT_IMAGE ? s->image[t & (KB_PROG - 1)]
                                          : s->path[t & (KB_PATH - 1)];
        if (p < plen && (g->icase ? lower(pc) == lower(tc) : pc == tc)) {
            s->gp = p + 1;
            s->gt = t + 1;
            return 0;
        }
        if (s->gstar != NONE) {
            s->gp = s->gstar;
            s->gmark = s->gmark + 1;
            s->gt = s->gmark;
            return 0;
        }
        g->result = 2;
        return 1;
    }
    if (p < plen && pc == '*') {
        s->gp = p + 1;
        return 0;
    }
    g->result = p == plen ? 1 : 2;
    return 1;
}

/* 1 match, 0 no match, -1 undecided within the step budget. Text runs from Start.
 * Global: verified once. */
__noinline int kb_glob(__u32 plen, __u32 text, __u32 start, __u32 irq)
{
    struct kb_scratch* s = scratch_for(irq);
    if (!s) return 0;
    struct glob_ctx g = {};
    s->gp = 0;
    s->gt = start;
    s->gplen = plen;
    s->gtlen = text == TEXT_VALUE ? s->vlen : text == TEXT_IMAGE ? s->ilen : s->len;
    s->gstar = NONE;
    s->gmark = start;
    /* Linux paths are case-sensitive; NT names, values and program names are not. */
    g.icase = text == TEXT_IMAGE || s->pattern[0] != '/';
    g.text = text;
    g.irq = irq;
    bpf_loop(GLOB_STEPS, glob_step, &g, 0);
    return g.result == 1 ? 1 : g.result == 2 ? 0 : -1;
}

/* Copy rule text into s->pattern. */
static __always_inline int load_pattern(struct kb_rule* rule, int text)
{
    struct kb_scratch* s = scratch();
    if (!s) return -1;
    if (text == TEXT_VALUE) {
        bpf_probe_read_kernel(s->pattern, KB_VALUE, rule->value);
        return rule->vlen;
    }
    if (text == TEXT_IMAGE) {
        bpf_probe_read_kernel(s->pattern, KB_IMAGE, rule->image);
        return rule->ilen;
    }
    bpf_probe_read_kernel(s->pattern, KB_PATTERN, rule->path);
    return rule->plen;
}

/* KfPathMatches / exact match of rule Slot's wildcard path on s->path. Undecided counts
 * as a match for deny and audit rules (fail closed) and as no match for allow rules. */
static __always_inline int glob_path(struct kb_rule* rule)
{
    struct kb_scratch* s = scratch();
    if (!s) return 0;
    __u32 plen = load_pattern(rule, TEXT_PATH);
    if (plen == 0 || plen >= KB_PATTERN) return 0;
    int undecided = rule->action == KFilterActionAllow ? 0 : 1;
    int result = kb_glob(plen, TEXT_PATH, 0, 0);
    if (result != 0) return result > 0 ? 1 : undecided;
    if ((rule->flags & KFILTER_RULE_EXACT) != 0 || s->pattern[(plen - 1) & (KB_PATTERN - 1)] == '*') return 0;
    s->pattern[plen & (KB_PATH - 1)] = s->pattern[0] == '/' ? '/' : '\\';
    s->pattern[(plen + 1) & (KB_PATH - 1)] = '*';
    result = kb_glob(plen + 2, TEXT_PATH, 0, 0);
    return result > 0 ? 1 : result == 0 ? 0 : undecided;
}

/* Slot: the rule's place in its rule set. Addressed: the match flags (KB_MATCH_FLAGS): KB_ADDRESSED and KB_ADDRESS_ONLY
 * for addr= rules (KB_ROOT is probe_step's and kb_glob_rule's). */
static __always_inline int glob_value(struct kb_rule* rule, __u32 slot, __u32 addressed)
{
    struct kb_scratch* s = scratch();
    /* addr=: only a decision on memory, by its ranges; one only addr= rules decide passes every other rule by. */
    if ((rule->flags & KFILTER_RULE_ADDRESS) != 0)
        return (addressed & KB_ADDRESSED) != 0 && kb_address_match(slot, rule->action) != 0;
    if ((addressed & KB_ADDRESS_ONLY) != 0) return 0;
    /* module=: the caller's module (pe_caller), not a value. */
    if (rule->mbit) return s && (s->mbits & rule->mbit) != 0;
    if (!rule->vlen) return 1;
    if (!s) return 0;
    /* Value enumeration names no value: a value-scoped deny or audit covers it (RegEnumValue
     * returns the data too), a value-scoped allow does not. */
    if (s->any_value) return rule->action != KFilterActionAllow;
    if (s->vlen == 0) return 0;
    __u32 vlen = load_pattern(rule, TEXT_VALUE);
    if (vlen == 0 || vlen >= KB_VALUE) return 0;
    int result = kb_glob(vlen, TEXT_VALUE, 0, 0);
    return result > 0 ? 1 : result == 0 ? 0 : (rule->action == KFilterActionAllow ? 0 : 1);
}

/* The rule's image= against the program the decision is for (KfImageMatches). */
static __always_inline int glob_image(struct kb_rule* rule)
{
    struct kb_scratch* s = scratch();
    if (!rule->ilen) return 1;
    if (!s || s->ilen == 0) return 0;
    __u32 ilen = load_pattern(rule, TEXT_IMAGE);
    if (ilen == 0 || ilen >= KB_IMAGE) return 0;
    int result = kb_glob(ilen, TEXT_IMAGE, rule->iwhole ? 0 : s->ibase, 0);
    return result > 0 ? 1 : result == 0 ? 0 : (rule->action == KFilterActionAllow ? 0 : 1);
}

/* One range of the addr= rule a->slot keys against what the decision reaches. Its state is in map memory (kb_access),
 * so the step is verified once whatever the range count. */
static long address_step(__u32 index, void* unused)
{
    struct kb_access* a = bpf_task_storage_get(&kb_accesses, bpf_get_current_task_btf(), 0, 0);
    struct kb_ranges* r = a ? bpf_map_lookup_elem(&kb_ranges, &a->slot) : 0;   /* keys in map memory: no stack */
    if (!a || !r || index >= r->count) return 1;
    __u32 i = index & (KB_RANGES - 1);
    __u64 lo = r->lo[i], hi = r->hi[i];
    __u32 module = r->module[i];
    if (module != 0) {
        __u32 bit = (module - 1) & (KB_MOD_BITS - 1);
        struct kb_base* b = a->current ? bpf_map_lookup_elem(&kb_bases, &a->target) : 0;
        if (!b) {
            a->matched |= 2;   /* no current module table: where the range lies is unknown */
            return 0;
        }
        if ((b->present & (1u << bit)) == 0) return 0;   /* the module is not mapped in the target */
        __u64 size = b->size[bit];
        if (size != 0 && hi >= size) hi = size - 1;     /* a module-relative range ends with the image */
        if (lo > hi) return 0;
        lo += b->base[bit];
        hi += b->base[bit];
    }
    for (__u32 j = 0; j < KB_ACCESS; j++) {
        if (j >= a->count) break;
        if (a->lo[j] <= hi && a->hi[j] >= lo) a->matched |= 1;
        if (a->lo[j] >= lo && a->hi[j] <= hi) a->covered |= 1u << j;
    }
    return 0;
}

/*
 * The addr= rule in Slot of the decision's rule set against what the decision reaches (kb_accesses). A deny or audit
 * matches when one of its ranges overlaps, or either side is unknown (part of the access, or the target's module
 * table for a module-relative range); an allow only when each range reached lies within one of its ranges, so it
 * never lets through bytes a later deny protects. A module the current table shows absent is not there.
 */
__noinline int kb_address_match(__u32 slot, __u32 action)
{
    struct kb_scratch* s = scratch();
    struct kb_access* a = bpf_task_storage_get(&kb_accesses, bpf_get_current_task_btf(), 0, 0);
    int deny = action != KFilterActionAllow;
    if (!s || !a) return deny;
    a->slot = s->set << 16 | (slot & 0xFFFF);
    struct kb_ranges* r = bpf_map_lookup_elem(&kb_ranges, &a->slot);
    if (!r || a->unknown) return deny;
    struct kb_base* b = a->target ? bpf_map_lookup_elem(&kb_bases, &a->target) : 0;
    __u32* seq = a->target ? bpf_map_lookup_elem(&kb_modseq, &a->target) : 0;
    a->current = b && seq && b->seq == *seq && b->gen == r->gen;
    a->matched = 0;
    a->covered = 0;
    bpf_loop(KB_RANGES, address_step, 0, 0);
    if (deny) return a->matched != 0;
    return a->count != 0 && a->count <= KB_ACCESS && a->covered == (1u << a->count) - 1;
}

/* ---- rule selection ---- */

/* KfRuleMatches without the path (Outside: KfPolicyOutsideRights' test). */
static __always_inline int rule_applies(struct kb_rule* rule, __u32 target, __u32 rights, __u32 ext, int outside)
{
    if ((rule->targets & target) == 0) return 0;
    if (outside) return (rule->rights & rights) != 0;
    if (rule->action == KFilterActionAllow && rule->rights == 0) return 0;
    if ((target & (KFILTER_TARGET_FILE | KFILTER_TARGET_DIR | KFILTER_TARGET_PIPE)) != 0 && rule->ext != 0 &&
        (rule->ext & ext) == 0) return 0;
    if (rule->action == KFilterActionAllow) {
        if (rights == 0 || (rights & ~rule->rights) != 0) return 0;
    } else if (rule->rights != 0 && rights != 0 && (rights & rule->rights) == 0) {
        return 0;
    }
    return 1;
}

/* kb_first_match's loops (one context: each one's on the stack was too much for the deepest call chain). */
struct match_ctx {
    __u32 target, rights, ext, outside, lower_bound;
    __u32 overflow;          /* probe_step: more candidates than KB_CANDIDATES */
    __u32 best;              /* glob_list_step: the lowest matching slot so far */
    __u32 addressed;         /* KB_ADDRESSED, KB_ADDRESS_ONLY, KB_NAMED_ONLY */
};

/* Literal rules: the whole path, and (not EXACT) every parent of it. */
static long probe_step(__u32 index, struct match_ctx* c)
{
    struct kb_scratch* s = scratch();
    if (!s || index > s->len) return 1;
    char ch = index < s->len ? s->path[index & (KB_PATH - 1)] : 0;
    int whole = index == s->len;
    /* A parent shorter than the decision's space root (KB_ROOT) does not name it. */
    if ((whole || ((ch == '/' || ch == '\\') && index > 0)) && index >= KB_ROOT_OF(c->addressed)) {
        struct kb_key key = {s->hfnv, s->hdjb, index};
        void* literal = bpf_map_lookup_elem(&kb_literal_sets, &s->set);
        struct kb_slots* slots = literal ? bpf_map_lookup_elem(literal, &key) : 0;
        if (slots) {
            for (__u32 i = 0; i < KB_PER_PATH; i++) {
                if (i >= slots->count) break;
                __u32 slot = slots->slot[i];
                if (slot < c->lower_bound) continue;
                struct kb_rule* rule = rule_at(&s->set, slot);
                if (!rule || rule->plen != index) continue;
                if (!whole && (rule->flags & KFILTER_RULE_EXACT) != 0) continue;
                if (!rule_applies(rule, c->target, c->rights, c->ext, c->outside)) continue;
                __u32 n = s->ncand;
                if (n >= KB_CANDIDATES) {
                    c->overflow = 1;
                    return 1;
                }
                s->cand[n & (KB_CANDIDATES - 1)] = slot;
                s->ncand = n + 1;
            }
        }
    }
    if (whole) return 1;
    /* NT names (registry keys, Windows images) match without case: kfilterd hashes their
     * literal rules lowercased. */
    unsigned char hashed = s->path[0] == '/' ? (unsigned char)ch : (unsigned char)lower(ch);
    /* The hashes live in map memory, not in the callback context: the verifier treats them
     * as unknown, so iterations converge instead of each hash value being its own state. */
    s->hfnv = kb_fnv_step(s->hfnv, hashed);
    s->hdjb = kb_djb_step(s->hdjb, hashed);
    return 0;
}

/* Wildcard rule Slot of the decision's rule set applies to the request and matches it. Global: verified once,
 * outside glob_list_step's loop (7.0's loop precision pass fails on a global call inlined in a bpf_loop step).
 * Outside carries kb_decide_global's match flags (KB_MATCH_FLAGS) above its bit 0 (five arguments at most). The list
 * also holds literal rules past KB_PER_PATH on one path: on \@unknown only those decide. */
__noinline int kb_glob_rule(__u32 slot, __u32 target, __u32 rights, __u32 ext, __u32 outside)
{
    struct kb_scratch* s = scratch();
    if (!s) return 0;
    struct kb_rule* rule = rule_at(&s->set, slot);
    if (!rule || ((outside & KB_NAMED_ONLY) != 0 && rule->wild) || rule->head < KB_ROOT_OF(outside) ||
        !rule_applies(rule, target, rights, ext, outside & 1))
        return 0;
    if (!glob_path(rule) || ((outside & 1) == 0 && !glob_value(rule, slot, outside)) || !glob_image(rule)) return 0;
    return 1;
}

static long glob_list_step(__u32 index, struct match_ctx* c)
{
    struct kb_scratch* s = scratch();
    if (!s) return 1;
    void* globs = bpf_map_lookup_elem(&kb_glob_sets, &s->set);
    __u32* slotPointer = globs ? bpf_map_lookup_elem(globs, &index) : 0;
    if (!slotPointer) return 1;
    __u32 slot = *slotPointer;
    if (slot >= c->best) return 1;   /* globs are in policy order, KB_GLOB_END after the last */
    if (slot < c->lower_bound || kb_glob_rule(slot, c->target, c->rights, c->ext, c->outside | c->addressed) == 0)
        return 0;
    c->best = slot;
    return 1;
}

/* A literal candidate's own path is s->path's first Plen bytes: its slot came from a hash of them, so no
 * other path's rule decides. */
static __always_inline int literal_path(struct kb_scratch* s, struct kb_rule* rule)
{
    __u32 plen = load_pattern(rule, TEXT_PATH);
    __u32 len = s->len;
    if (plen == 0 || plen > len || plen >= KB_PATTERN) return 0;
    s->len = plen;
    int same = kb_glob(plen, TEXT_PATH, 0, 0) > 0;
    s->len = len;
    return same;
}

/* The lowest-numbered rule of rule set s->set at or after Lower that matches s->path; NONE
 * when there is none, NONE - 1 when the candidates overflowed (fail closed). Outside: as kb_glob_rule's, and with
 * KB_NAMED_ONLY literal rules alone (no wildcard rule), with KB_ROOT rules naming past its space's root alone. */
__noinline __u32 kb_first_match(__u32 target, __u32 rights, __u32 ext, __u32 outside, __u32 lower)
{
    struct kb_scratch* s = scratch();
    if (!s) return NONE - 1;
    s->ncand = 0;
    s->hfnv = KB_FNV_INIT;
    s->hdjb = KB_DJB_INIT;
    struct match_ctx match = {target, rights, ext, outside & 1, lower, 0, NONE, outside & ~1u};
    bpf_loop(KB_PATH + 1, probe_step, &match, 0);
    if (match.overflow) return NONE - 1;
    __u32 best = NONE;
    for (__u32 i = 0; i < KB_CANDIDATES; i++) {
        if (i >= s->ncand) break;
        __u32 slot = s->cand[i];
        if (slot >= best) continue;
        struct kb_rule* rule = rule_at(&s->set, slot);
        if (!rule || !literal_path(s, rule)) continue;
        if (!match.outside && !glob_value(rule, slot, match.addressed)) continue;
        if (!glob_image(rule)) continue;
        best = slot;
    }
    match.best = best;
    bpf_loop(KB_GLOBS, glob_list_step, &match, 0);
    return match.best;
}

/* KfCountTake for counted rule Slot of rule set *Set (network rules use KB_RULES + index). A peek (a
 * metadata query) takes no use: the stat before each open must not spend the open's. */
static __always_inline int take_use(__u32* set, __u32 count, __u32 slot, int peek)
{
    if (count == 0) return 1;
    __u32 uses = (count & KFILTER_COUNT_USES) >> KFILTER_COUNT_USES_SHIFT;
    __u32 phase = count & KFILTER_COUNT_PHASE;
    __u32 zero = 0;
    void* phases = bpf_map_lookup_elem(&kb_phase_sets, set);
    void* counts = bpf_map_lookup_elem(&kb_used_sets, set);
    struct kb_state* state = phases ? bpf_map_lookup_elem(phases, &zero) : 0;
    __u32* used = counts ? bpf_map_lookup_elem(counts, &slot) : 0;
    if (!state || !used || state->phase < phase) return 0;
    if (peek) return *used < uses;
    int taken = 0;
    for (int attempt = 0; attempt < 8; attempt++) {
        __u32 current = *used;
        if (current >= uses) return 0;
        if (__sync_val_compare_and_swap(used, current, current + 1) == current) {
            taken = 1;
            break;
        }
    }
    if (!taken) return 0;
    if ((count & KFILTER_COUNT_OPENS) != 0) {
        for (int attempt = 0; attempt < 8; attempt++) {
            __u32 open = state->phase;
            if (open > phase) break;
            if (__sync_val_compare_and_swap(&state->phase, open, phase + 1) == open) break;
        }
    }
    return 1;
}

/* take_use for kb_decide_global and kb_outside_rights, verified once; the network rule loops' steps inline it
 * (a global call in their step made the network programs several times longer to verify). */
__noinline int kb_count_take(__u32 set, __u32 count, __u32 slot, __u32 peek)
{
    return take_use(&set, count, slot, peek);
}

static __always_inline int count_take(__u32 set, __u32 count, __u32 slot, int peek)
{
    return count == 0 || kb_count_take(set, count, slot, peek) != 0;
}

/* ---- events ---- */

static __always_inline void count_drop(void)
{
    __u32 zero = 0;
    __u64* drops = bpf_map_lookup_elem(&kb_drops, &zero);
    if (drops) __sync_fetch_and_add(drops, 1);
}

struct direct_ctx {
    __u64 vdso;
    __u32 direct;
};

/* e_lfanew of the PE header at Base in the current program's memory (within its first page); 0 when
 * there is none or it is not resident. */
static __always_inline __u32 pe_at(__u64 base)
{
    __u16 mz = 0;
    __u32 lfanew = 0, pe = 0;
    if (bpf_probe_read_user(&mz, 2, (void*)base) != 0 || mz != 0x5a4d) return 0;   /* "MZ" */
    if (bpf_probe_read_user(&lfanew, 4, (void*)(base + 0x3c)) != 0 || lfanew < 0x40 || lfanew > 4096 - 84) return 0;
    if (bpf_probe_read_user(&pe, 4, (void*)(base + lfanew)) != 0 || pe != 0x4550) return 0;   /* "PE\0\0" */
    return lfanew;
}

/* The code the syscall came from: anonymous memory other than the vDSO (copied stubs, JIT, a PE
 * section Wine copied), or a file mapping with a PE header at its file offset 0. */
static long direct_vma(struct task_struct* task, struct vm_area_struct* vma, struct direct_ctx* c)
{
    if (!vma->vm_file) c->direct = vma->vm_start != c->vdso;
    else c->direct = pe_at(vma->vm_start - (vma->vm_pgoff << 12)) != 0;
    return 0;
}

/*
 * KFILTER_EVENT_FLAG_DIRECT when the current task is a Wine thread in a syscall that Windows code made
 * with its own syscall instruction, past Wine: Wine's own (its unix side, libc, the vDSO) come from
 * ELF code. Unknown, so not direct, while the task holds its mmap lock (mprotect's decision).
 */
__noinline __u32 kb_direct(void)
{
    struct task_struct* task = bpf_get_current_task_btf();
    struct kb_task* state = task_state(task);
    if (!state || state->role != KB_ROLE_WINE) return 0;
    struct pt_regs* regs = (struct pt_regs*)bpf_task_pt_regs(task);
    if (!regs || (long)BPF_CORE_READ(regs, orig_ax) < 0) return 0;   /* not in a syscall: a uprobe's decision */
    struct direct_ctx c = {(__u64)BPF_CORE_READ(task, mm, context.vdso), 0};
    if (bpf_find_vma(task, BPF_CORE_READ(regs, ip), direct_vma, &c, 0) != 0) return 0;
    return c.direct ? KFILTER_EVENT_FLAG_DIRECT : 0;
}

static __always_inline void event_image(struct kb_event* e, struct kb_scratch* s)
{
    e->image[0] = 0;
    if (s->ilen != 0) bpf_probe_read_kernel_str(e->image, KB_IMAGE, &s->image[s->ibase & (KB_PROG - 1)]);
}

static __always_inline void emit(__u32 kind, __u32 target, __u32 action, __u32 flags, __s32 status, __u32 value,
                                 __u32 ruleId, __u32 rights, int withPath)
{
    struct kb_scratch* s = scratch();
    if (!s) return;
    flags |= kb_direct();
    struct kb_event* e = bpf_ringbuf_reserve(&kb_events, sizeof(*e), 0);
    if (!e) {
        count_drop();
        return;
    }
    e->kind = kind;
    e->tgid = s->tgid;
    e->target = target;
    e->action = action;
    e->flags = flags | (s->brokered ? KFILTER_EVENT_FLAG_BROKERED : 0);
    e->status = status;
    e->value = value;
    e->rule_id = ruleId;
    e->rights = rights;
    e->ppid = 0;
    e->path[0] = 0;
    if (withPath && !s->failed) bpf_probe_read_kernel_str(e->path, KB_PATH, s->path);
    event_image(e, s);
    bpf_ringbuf_submit(e, 0);
}

/* The outcome of Action in the configured mode, logged as policy.c logs it. */
static __always_inline int verdict(__u32 target, __u32 action, __u32 flags, __u32 value, __u32 ruleId,
                                   __u32 rights, __u32 mode)
{
    if (action == KFilterActionAllow) {
        emit(KB_EV_DECISION, target, KFilterActionAllow, flags, 0, value, ruleId, rights, 1);
        return 0;
    }
    if (action == KFilterActionAudit) {
        emit(KB_EV_DECISION, target, KFilterActionAudit, flags, 0, value, ruleId, rights, 1);
        return 0;
    }
    if (mode == KFILTER_MODE_BLOCK) {
        emit(KB_EV_DECISION, target, KFilterActionDeny, flags, STATUS_ACCESS_DENIED, value, ruleId, rights, 1);
        return -EPERM;
    }
    emit(KB_EV_DECISION, target, KFilterActionAudit, flags | KFILTER_EVENT_FLAG_WOULD_DENY, STATUS_ACCESS_DENIED,
         value, ruleId, rights, 1);
    return 0;
}

static __always_inline int root_matches(struct kb_cfg* c, struct kb_scratch* s)
{
    __u32 n = c->root_len;
    if (n == 0 || n >= KB_PATTERN || s->len < n) return 0;
    for (__u32 i = 0; i < KB_PATTERN; i++) {
        if (i >= n) break;
        if (s->path[i & (KB_PATH - 1)] != c->root[i]) return 0;
    }
    return s->len == n || s->path[n & (KB_PATH - 1)] == '/';
}

/* [At, At + Bytes) reached by a decision on memory; past KB_ACCESS ranges the rest is unknown. */
static __always_inline void access_add(struct kb_access* a, __u64 at, __u64 bytes)
{
    __u32 n = a->count;
    if (bytes == 0) return;
    if (n >= KB_ACCESS) {
        a->unknown = 1;
        return;
    }
    a->lo[n & (KB_ACCESS - 1)] = at;
    a->hi[n & (KB_ACCESS - 1)] = at + bytes - 1 < at ? ~0ull : at + bytes - 1;
    a->count = n + 1;
}

/* " addr=0x<start>+<bytes>" for the first range a decision on memory reaches (",..." when it reaches more), "?" for
 * an unknown part, written after s->path's end but not counted in s->len: the event of a decision an addr= rule made,
 * which copies the string, says what it reached (other rules' events keep the bare path the loop's tools match). */
__noinline int kb_access_text(void)
{
    static const char hex[] = "0123456789abcdef";
    struct kb_scratch* s = scratch();
    struct kb_access* a = bpf_task_storage_get(&kb_accesses, bpf_get_current_task_btf(), 0, 0);
    if (!s || !a || s->failed || s->len > KB_PATH - 48) return 0;
    __u32 at = s->len;
    const char head[] = " addr=";
    for (int i = 0; i < 6; i++) s->path[(at + i) & (KB_PATH - 1)] = head[i];
    at += 6;
    if (a->count != 0) {
        __u64 lo = a->lo[0], bytes = a->hi[0] - lo + 1;
        __u32 n = bytes == 0 || bytes > 0xFFFFFFFFull ? 0xFFFFFFFFu : (__u32)bytes, digits = 1;
        s->path[at & (KB_PATH - 1)] = '0';
        s->path[(at + 1) & (KB_PATH - 1)] = 'x';
        for (int i = 0; i < 16; i++) s->path[(at + 2 + i) & (KB_PATH - 1)] = hex[(lo >> (60 - 4 * i)) & 0xF];
        s->path[(at + 18) & (KB_PATH - 1)] = '+';
        at += 19;
        for (__u32 rest = n / 10; rest != 0 && digits < 10; rest /= 10) digits++;
        for (int i = 9; i >= 0; i--) {
            if ((__u32)i < digits) s->path[(at + i) & (KB_PATH - 1)] = '0' + n % 10;
            if ((__u32)i < digits) n /= 10;
        }
        at += digits & 15;
        if (a->count > 1) {
            for (int i = 0; i < 4; i++) s->path[(at + i) & (KB_PATH - 1)] = ",..."[i];
            at += 4;
        }
    }
    if (a->unknown) {
        if (a->count != 0) s->path[(at++) & (KB_PATH - 1)] = ',';
        s->path[(at++) & (KB_PATH - 1)] = '?';
    }
    s->path[at & (KB_PATH - 1)] = 0;
    return 0;
}

/*
 * KfDecideWithRights for the program in s->tgid on s->path (and s->value for devices, registry
 * values and DNS types). Listed: 1 rule-only, 2 rule-only with a name failure decided (DNS, WMI),
 * with KB_ADDRESSED and KB_ADDRESS_ONLY for a decision on memory (addr= rules), KB_NAMED_ONLY on \@unknown, and
 * KB_ROOT for a decision only rules naming its space meet (KB_WINE_ROOT: a Wine request kfilter did not decide before
 * K2), and the kernel's own targets (KB_TARGET_KEYED ... KB_TARGET_SIGNAL) only rules naming them meet.
 * Returns 0 to allow, -EPERM to deny (-ENOENT by a hide rule).
 */
__noinline int kb_decide_global(__u32 target, __u32 rights, __u32 value, __u32 listed)
{
    struct kb_cfg* c = kb_cfg_get();
    struct kb_scratch* s = scratch();
    if (!c || !s || !c->enabled || c->mode == KFILTER_MODE_OFF) return 0;
    __u32 flags = c->flags;
    __u32 mode = c->mode;
    if (rights == 0) rights = KFILTER_RIGHT_OPEN;
    /* Devices and volumes: the ioctl; DNS: the query type. */
    __u32 eventValue = (target & (KFILTER_TARGET_DEVICE | KB_TARGET_ARGUMENT | KFILTER_TARGET_VOLUME | KFILTER_TARGET_DNS)) != 0
                           ? value : rights;
    /* A request Windows code made with its own syscall instruction, past Wine. */
    if ((flags & KFILTER_CFG_BLOCK_DIRECT_SYSCALL) != 0 && kb_direct() != 0)
        return verdict(target, KFilterActionDeny, 0, eventValue, 0, rights, mode);
    if ((target & (KFILTER_TARGET_FILE | KFILTER_TARGET_DIR | KFILTER_TARGET_PIPE)) != 0 &&
        (flags & KFILTER_CFG_BLOCK_FILES) == 0) return 0;
    if (target == KFILTER_TARGET_PROCESS && (flags & KFILTER_CFG_BLOCK_PROCESS_CREATE) == 0) return 0;
    if (target == KFILTER_TARGET_REGISTRY && (flags & KFILTER_CFG_BLOCK_REGISTRY) == 0) return 0;
    if (target == KFILTER_TARGET_VOLUME && (flags & KFILTER_CFG_BLOCK_VOLUME_SERIAL) == 0) return 0;
    if ((target & KFILTER_TARGETS_RULE_ONLY) != 0 && (listed & 3) == 0) listed |= 1;
    /* module= rules match the caller pe_caller named just before: system, thread and dns decisions only. */
    if ((target & (KFILTER_TARGET_SYSTEM | KFILTER_TARGET_THREAD | KFILTER_TARGET_DNS | KB_TARGET_KEYED)) == 0) s->mbits = 0;
    /* shortcut: a rule-only name that could not be built is allowed unlogged (a DNS or WMI query's,
     * listed 2, is decided: a name failure); refuse the others too once such names can fail. */
    if (s->failed && (listed & 3) == 1) return 0;
    if (s->failed) {
        emit(KB_EV_DECISION, target, mode == KFILTER_MODE_BLOCK ? KFilterActionDeny : KFilterActionAudit,
             KFILTER_EVENT_FLAG_NAME_FAILURE | (mode == KFILTER_MODE_BLOCK ? 0 : KFILTER_EVENT_FLAG_WOULD_DENY),
             STATUS_ACCESS_DENIED, eventValue, 0, rights, 0);
        return mode == KFILTER_MODE_BLOCK ? -EPERM : 0;
    }
    __u32 ext = extension_mask(s);
    __u32 action = 0, ruleId = 0, exhausted = 0, eventFlags = 0, risk = 0, spentAllow = 0, hide = 0, address = 0;
    __u32 lower = 0;
    s->set = live_set();
    for (int attempt = 0; attempt < 4; attempt++) {
        __u32 slot = kb_first_match(target, rights, ext, listed & KB_MATCH_FLAGS, lower);
        if (slot == NONE) break;
        if (slot == NONE - 1) {
            action = KFilterActionDeny;   /* more candidates than the kernel tracks */
            break;
        }
        struct kb_rule* rule = rule_at(&s->set, slot);
        if (!rule) break;
        if (!count_take(s->set, rule->count, slot, rights == KFILTER_RIGHT_QUERY && (target & KB_FILE_TARGETS) != 0)) {
            /* A spent counted rule steps aside: an allow, so the request is refused unless a
             * later rule allows it; a deny or audit, so later rules decide (block once). */
            if (exhausted == 0) exhausted = rule->rule_id;
            if (rule->action == KFilterActionAllow) spentAllow = 1;
            lower = slot + 1;
            continue;
        }
        action = rule->action;
        ruleId = rule->rule_id;
        risk = rule->risk;
        hide = (rule->flags & KFILTER_RULE_HIDE) != 0;
        address = (rule->flags & KFILTER_RULE_ADDRESS) != 0;
        if (rule->count != 0) eventFlags |= KFILTER_EVENT_FLAG_COUNTED;
        break;
    }
    /* Rule-only: no rule, no decision and no event, unless its counted allow is spent. */
    if (action == 0 && (listed & 3) != 0) {
        if (!spentAllow) return 0;
        action = KFilterActionDeny;
    }
    int strict = (flags & KFILTER_CFG_DEFAULT_DENY) != 0;
    if (action == 0 && !strict && target == KFILTER_TARGET_PROCESS && root_matches(c, s)) action = KFilterActionAllow;
    if (action == 0 && (target == KFILTER_TARGET_DEVICE || target == KFILTER_TARGET_VOLUME)) action = KFilterActionDeny;
    if (action == 0) action = strict ? KFilterActionDeny : KFilterActionAllow;
    if (action == KFilterActionDeny && ruleId == 0 && exhausted != 0) {
        ruleId = exhausted;
        eventFlags |= KFILTER_EVENT_FLAG_EXHAUSTED;
    }
    /* An allowed metadata query is not logged (msmon records each; a Wine start makes tens of
     * thousands): its refusals and audits are. */
    if (action == KFilterActionAllow && !risk && rights == KFILTER_RIGHT_QUERY && (target & KB_FILE_TARGETS) != 0) return 0;
    if (address) kb_access_text();
    /* An allow by a risk= rule is also a RISK record, before the allow (as policy.c). */
    if (action == KFilterActionAllow && risk) emit(KB_EV_DECISION, target, KFilterActionRisk, 0, 0, eventValue, ruleId, rights, 1);
    int result = verdict(target, action, eventFlags, eventValue, ruleId, rights, mode);
    return result != 0 && hide ? -ENOENT : result;
}

/* KfPolicyOutsideRights on s->path: the rights the first matching HANDLE/OPEN/LAUNCH
 * allow grants (0 when none). */
__noinline __u32 kb_outside_rights(__u32 target, __u32 requested, __u32 isRoot)
{
    struct kb_cfg* c = kb_cfg_get();
    struct kb_scratch* s = scratch();
    if (!c || !s) return 0;
    s->outside_rule = 0;
    if (s->failed) return 0;
    __u32 lower = 0;
    s->set = live_set();
    for (int attempt = 0; attempt < 4; attempt++) {
        __u32 slot = kb_first_match(target, requested, 0, 1, lower);
        if (slot >= NONE - 1) return 0;
        struct kb_rule* rule = rule_at(&s->set, slot);
        if (!rule) return 0;
        if ((rule->account == KFILTER_ACCOUNT_SYSTEM && !isRoot) || !count_take(s->set, rule->count, slot, 0)) {
            lower = slot + 1;
            continue;
        }
        s->outside_rule = rule->rule_id;
        if (rule->action != KFilterActionAllow) return 0;
        if (rule->risk) emit(KB_EV_DECISION, target, KFilterActionRisk, 0, 0, requested, rule->rule_id, requested, 1);
        return rule->rights;
    }
    return 0;
}

/* ---- files ---- */

static __always_inline int exec_open(struct file* file)
{
    return (BPF_CORE_READ(file, f_mode) & FMODE_EXEC) != 0 || (BPF_CORE_READ(file, f_flags) & __FMODE_EXEC) != 0;
}

static __always_inline __u32 open_rights(struct file* file, __u32* target)
{
    __u32 mode = BPF_CORE_READ(file, f_mode);
    __u32 openFlags = BPF_CORE_READ(file, f_flags);
    __u32 rights = 0;
    if (mode & FMODE_READ) rights |= KFILTER_RIGHT_READ;
    if (mode & FMODE_WRITE) rights |= KFILTER_RIGHT_WRITE;
    if ((openFlags & O_TRUNC) != 0 || ((openFlags & O_CREAT) != 0 && (openFlags & O_EXCL) != 0)) rights |= KFILTER_RIGHT_WRITE;
    if (rights == 0) rights = KFILTER_RIGHT_READ | KFILTER_RIGHT_WRITE;
    __u32 type = inode_mode(BPF_CORE_READ(file, f_inode)) & S_IFMT;
    *target = KFILTER_TARGET_FILE;
    if (type == S_IFDIR) {
        *target = KFILTER_TARGET_DIR;
        rights |= KFILTER_RIGHT_ENUMERATE;
    } else if (type == S_IFIFO) {
        *target = KFILTER_TARGET_PIPE;
    }
    return rights;
}

/* A block device (with block-raw-disk) or an identity character device is a device decision. */
static __always_inline int device_target(struct kb_cfg* c, struct kb_scratch* s, __u32 type)
{
    if (type == S_IFBLK) return (c->flags & KFILTER_CFG_BLOCK_RAW_DISK) != 0;
    return type == S_IFCHR && identity_device(s);
}

static __always_inline void device_value(struct kb_scratch* s, __u32 code)
{
    /* KfDeviceValueText: "0x%08X" */
    static const char hex[] = "0123456789ABCDEF";
    s->value[0] = '0';
    s->value[1] = 'x';
    for (int i = 0; i < 8; i++) s->value[2 + i] = hex[(code >> (28 - 4 * i)) & 0xF];
    s->value[10] = 0;
    s->vlen = 10;
}

/* Rights an open already holds for the program in s->tgid (see struct kb_grant). */
static __always_inline int granted(struct file* file, __u32 rights)
{
    struct kb_cfg* c = kb_cfg_get();
    struct kb_scratch* s = scratch();
    __u64 key = address_of(file);
    struct kb_grant* grant = bpf_map_lookup_elem(&kb_files, &key);
    return c && s && grant && grant->tgid == s->tgid && grant->generation == c->generation &&
           (rights & ~grant->rights) == 0;
}

/* Generation: kb_config's, read before the decision read kb_live (kfilterd writes kb_live, then kb_config), so an
 * allow made by the old policy's rules during a reload is never cached under the new policy. */
static __always_inline void grant(struct file* file, __u32 rights, __u32 generation)
{
    struct kb_scratch* s = scratch();
    if (!s) return;
    __u64 key = address_of(file);
    struct kb_grant* old = bpf_map_lookup_elem(&kb_files, &key);
    struct kb_grant value = {s->tgid, rights, generation, 0};
    if (old && old->tgid == s->tgid && old->generation == generation) value.rights |= old->rights;
    bpf_map_update_elem(&kb_files, &key, &value, BPF_ANY);
}

/*
 * s->path /proc/<pid>[/...] (a procfs path) as whose process it is to the program in s->tgid:
 * /proc/@self (its own), /proc/@family (another protected one), /proc/@wine (a Wine process
 * or wineserver outside the family) or /proc/@outside, so rules can tell them apart.
 * shortcut: pids are looked up in the initial pid namespace, as kfilterctl launch runs the
 * client; a client in its own pid namespace needs the namespace of the procfs mount.
 */
__noinline int kb_proc_name(void)
{
    static const char names[4][8] = {"@self", "@family", "@wine", "@outside"};
    static const __u32 lengths[4] = {5, 7, 5, 8};
    struct kb_scratch* s = scratch();
    if (!s || s->failed || s->len < 7 || s->len >= KB_PATH - 16 || !starts_with(s, "/proc/", 6)) return 0;
    __u32 pid = 0, end = 6;
    for (__u32 i = 6; i < 16; i++) {
        char ch = s->path[i];
        if (ch < '0' || ch > '9') break;
        pid = pid * 10 + (ch - '0');
        end = i + 1;
    }
    if (end == 6 || (s->path[end & 31] != '/' && s->path[end & 31] != 0)) return 0;
    __u32 kind = 3;
    struct task_struct* task = bpf_task_from_pid((s32)pid);
    if (task) {
        struct kb_task* state = task_state(task);
        if (BPF_CORE_READ(task, tgid) == s->tgid) kind = 0;
        else if (task_protected(task, state)) kind = 1;
        else if (state && state->role != KB_ROLE_NONE) kind = 2;
        bpf_task_release(task);
    }
    __u32 n = lengths[kind & 3];
    __u32 len = s->len - end + 6 + n;
    bpf_probe_read_kernel_str(s->walk, KB_PATH, &s->path[end & 31]);
    bpf_probe_read_kernel(&s->path[6], 8, names[kind & 3]);
    bpf_probe_read_kernel_str(&s->path[(6 + n) & 15], KB_PATH - 16, s->walk);
    s->len = len;
    return 0;
}

/* Decides Rights on File for the program in s->tgid. Cached: an open (or a received file)
 * whose rights were decided is not decided again for reads, writes or mappings within them. */
static __always_inline int decide_file(struct file* file, __u32 target, __u32 rights, int cached)
{
    struct kb_cfg* c = kb_cfg_get();
    struct kb_scratch* s = scratch();
    if (!c || !s) return 0;
    struct inode* inode = BPF_CORE_READ(file, f_inode);
    if (!inode || pseudo_fs(inode)) return 0;
    if (cached && granted(file, rights)) return 0;
    __u32 generation = c->generation;   /* before kb_decide reads kb_live (grant) */
    walk_file(file);
    unsigned long magic = fs_magic(inode);
    /* /proc/<pid>/... as whose it is (kb_proc_name returns at once for any other path): also when the file is not
     * on procfs, as an open through /proc/self/fd/<n> of a pipe, which was decided as /proc/<own pid>/fd/<n>
     * (gio, trial 262). */
    kb_proc_name();
    /* "/": no rule can name it, as in the path hooks (MapleStory.exe lists it through wineserver). */
    if (!s->failed && s->len == 1) return 0;
    /* A POSIX message queue (mq_open opens it on the kernel's own mount, which walks to "/<name>"). */
    if (magic == MQUEUE_MAGIC) {
        set_path(s, "/anon/mqueue/", 13);
        append_string(s, BPF_CORE_READ(file, f_path.dentry, d_name.name), 0);
    }
    __u32 type = inode_mode(inode) & S_IFMT;
    if (!s->failed && device_target(c, s, type)) {
        device_value(s, 0);
        return kb_decide(KFILTER_TARGET_DEVICE, KFILTER_RIGHT_RAW_DEVICE, 0);
    }
    /* memfd, SysV shm, shared-anonymous memory and message queues (/anon/...): decided only by a rule naming them. */
    int result = !s->failed && starts_with(s, "/anon/", 6) ? kb_decide_listed(target, rights, 0)
                                                            : kb_decide(target, rights, 0);
    if (result == 0) grant(file, rights, generation);
    return result;
}

/* ---- Wine ---- */

/* The thread's TEB, validated by its self pointer (64-bit: GS base; 32-bit: the FS
 * descriptor Wine installs in one of the GDT TLS slots). 0 when the thread has none yet. */
static __always_inline __u64 wine_teb(struct task_struct* task, __u32 compat)
{
    if (!compat) {
        __u64 teb = BPF_CORE_READ(task, thread.gsbase);
        __u64 self = 0;
        if (teb == 0 || bpf_probe_read_user(&self, sizeof(self), (void*)(teb + 0x30)) != 0 || self != teb) return 0;
        return teb;
    }
    for (int i = 0; i < 3; i++) {
        __u64 raw = 0;
        bpf_probe_read_kernel(&raw, sizeof(raw), __builtin_preserve_access_index(&task->thread.tls_array[i]));
        __u32 base = (__u32)(((raw >> 16) & 0xFFFFFF) | ((raw >> 56) << 24));
        __u32 self = 0;
        if (base == 0 || bpf_probe_read_user(&self, sizeof(self), (void*)(__u64)(base + 0x18)) != 0) continue;
        if (self == base) return base;
    }
    return 0;
}

/* A pipe's key in kb_pipes: its inode's address mixed with its inode number, so a freed
 * pipe's address reused by a new pipe is a different key (no stale owner). */
static __always_inline __u64 pipe_key(struct inode* inode)
{
    if (!inode) return 0;
    return address_of(inode) ^ ((__u64)BPF_CORE_READ(inode, i_ino) << 32);
}

static __always_inline struct file* fd_file(struct task_struct* task, __s32 fd)
{
    if (fd < 0) return 0;
    struct fdtable* fdt = BPF_CORE_READ(task, files, fdt);
    if (!fdt || (__u32)fd >= BPF_CORE_READ(fdt, max_fds)) return 0;
    struct file** table = BPF_CORE_READ(fdt, fd);
    struct file* file = 0;
    bpf_probe_read_kernel(&file, sizeof(file), &table[fd]);
    return file;
}

static __always_inline struct kb_proc* proc_entry(__u32 tgid)
{
    struct kb_proc* proc = bpf_map_lookup_elem(&kb_procs, &tgid);
    if (proc) return proc;
    __u32 zero = 0;
    struct kb_proc* fresh = bpf_map_lookup_elem(&kb_proc_zero, &zero);   /* not on the 512-byte stack */
    if (!fresh) return 0;
    bpf_map_update_elem(&kb_procs, &tgid, fresh, BPF_NOEXIST);
    return bpf_map_lookup_elem(&kb_procs, &tgid);
}

struct base_ctx {
    __u32 tgid, len;
};

/* The running result is kept in the map value, not the context (see probe_step). */
static long base_step(__u32 index, struct base_ctx* c)
{
    struct kb_proc* proc = bpf_map_lookup_elem(&kb_procs, &c->tgid);
    if (!proc || index >= c->len) return 1;
    char ch = proc->image[index & (KB_PROG - 1)];
    if (ch == '\\' || ch == '/') proc->ibase = index + 1;   /* a Windows name, or a Linux program's path */
    return 0;
}

/* Image is exactly Name (with its terminating NUL); n < 32. */
static __always_inline int image_equals(struct kb_proc* proc, const char* name, __u32 n)
{
    for (__u32 i = 0; i < 32; i++) {
        if (i > n) break;
        if (proc->image[i] != name[i]) return 0;
    }
    return 1;
}

static __always_inline int loader_name(struct kb_proc* proc)
{
    return image_equals(proc, "wine", 4) || image_equals(proc, "wine64", 6) ||
           image_equals(proc, "wine-preloader", 14) || image_equals(proc, "wine64-preloader", 16);
}

/* The file name of the program in s->image equals Name (lowercase, n < 32 bytes), any case. */
static __always_inline int image_is(struct kb_scratch* s, const char* name, __u32 n)
{
    if (s->ilen < s->ibase || s->ilen - s->ibase != n) return 0;
    for (__u32 i = 0; i < 32; i++) {
        if (i >= n) break;
        if (lower(s->image[(s->ibase + i) & (KB_PROG - 1)]) != (__u8)name[i]) return 0;
    }
    return 1;
}

/* A protect name starting with '\' ends s->image (any case): a Windows program to protect. */
__noinline int kb_windows_protected(void)
{
    struct kb_cfg* c = kb_cfg_get();
    struct kb_scratch* s = scratch();
    if (!c || !s || s->ilen == 0 || s->ilen >= KB_PROG) return 0;
    for (__u32 n = 0; n < KB_NAMES; n++) {
        if (n >= c->name_count) break;
        __u32 len = c->name_len[n];
        if (len < 2 || len >= KB_NAME || len > s->ilen || c->names[n][0] != '\\') continue;
        __u32 start = s->ilen - len;
        int same = 1;
        for (__u32 i = 0; i < KB_NAME; i++) {
            if (i >= len) break;
            if (lower(s->image[(start + i) & (KB_PROG - 1)]) != lower(c->names[n][i])) {
                same = 0;
                break;
            }
        }
        if (same) return 1;
    }
    return 0;
}

/* The launch pass for a Windows program: its parent (the program that created it) is the
 * armed creator, compared on its Windows file name, or on its executable's name. */
static __always_inline int base_is(struct kb_scratch* s, struct kb_launch* pass)
{
    __u32 n = pass->creator_len;
    if (n == 0 || n >= KB_CREATOR || n >= s->len) return 0;
    __u32 start = s->len - n;
    if (s->path[(start - 1) & (KB_PATH - 1)] != '/') return 0;
    for (__u32 i = 0; i < KB_CREATOR; i++) {
        if (i >= n) break;
        if (s->path[(start + i) & (KB_PATH - 1)] != pass->creator[i]) return 0;
    }
    return 1;
}

static __always_inline int windows_creator_is(__u32 tgid, struct kb_launch* pass)
{
    struct kb_proc* proc = bpf_map_lookup_elem(&kb_procs, &tgid);
    __u32 n = pass->creator_len;
    if (!proc || proc->ilen == 0 || proc->ilen >= KB_PROG || n == 0 || n >= KB_CREATOR) return 0;
    if (proc->ilen < proc->ibase || proc->ilen - proc->ibase != n) return 0;
    for (__u32 i = 0; i < KB_CREATOR; i++) {
        if (i >= n) break;
        if (lower(proc->image[(proc->ibase + i) & (KB_PROG - 1)]) != lower(pass->creator[i])) return 0;
    }
    return 1;
}

static __always_inline int spend_launch_pass(struct kb_launch* pass)
{
    for (int attempt = 0; attempt < 8; attempt++) {
        __u32 left = pass->left;
        if (left == 0) return 0;
        if (__sync_val_compare_and_swap(&pass->left, left, left - 1) == left) {
            if (left == 1) pass->until_ns = 0;
            return 1;
        }
    }
    return 0;
}

static __always_inline int walk_exe(struct task_struct* task)
{
    struct file* exe = BPF_CORE_READ(task, mm, exe_file);
    if (!exe) {
        struct kb_scratch* s = scratch();
        if (s) s->failed = 1;
        return -1;
    }
    return walk_file(exe);
}

static __always_inline int take_windows_launch_pass(struct task_struct* task)
{
    __u32 zero = 0;
    struct kb_launch* pass = bpf_map_lookup_elem(&kb_launch_pass, &zero);
    if (!pass || pass->until_ns == 0 || bpf_ktime_get_ns() >= pass->until_ns || pass->left == 0) return 0;
    struct task_struct* parent = BPF_CORE_READ(task, real_parent);
    struct kb_task* own = task_state(task);
    __u32 creatorTgid = own && own->creator != 0 ? own->creator : BPF_CORE_READ(parent, tgid);
    int creator = windows_creator_is(creatorTgid, pass);
    if (!creator) {
        struct kb_scratch* s = scratch();
        if (!s) return 0;
        s->failed = 0;
        walk_exe(parent);
        creator = !s->failed && base_is(s, pass);
    }
    return creator && spend_launch_pass(pass);
}

/* s->path = the program's image, for decisions that name the program itself. */
static __always_inline void path_is_image(struct kb_scratch* s)
{
    bpf_probe_read_kernel(s->path, KB_PROG, s->image);
    s->path[KB_PROG - 1] = 0;
    s->len = s->ilen < KB_PROG ? s->ilen : KB_PROG - 1;
    s->failed = s->ilen == 0;
}

/*
 * Names the current Wine process by its Windows image the first time it can (argv[0] once
 * Wine's loader has rewritten it to C:\...\Program.exe; read once, so the program cannot
 * rename itself later), and admits it when a '\' protect name matches. A protected program
 * started outside the family is refused in block mode with block-process-create unless the
 * launch pass admits it: it is killed before its own code runs. Returns -EFAULT to refuse.
 */
__noinline int kb_wine_name(__u32 tgid)
{
    struct kb_cfg* c = kb_cfg_get();
    struct task_struct* task = bpf_get_current_task_btf();
    struct kb_task* state = task_state(task);
    struct kb_proc* proc = proc_entry(tgid);
    if (!c || !state || !proc) return 0;
    if (state->guarded) proc->guarded = 1;
    /* Until Wine has rewritten argv[0] (hundreds of start-up requests); once named, never again (a Linux program's
     * name from its exec is not a Windows name: Wine's replaces it). */
    if (proc->ilen != 0 && !proc->unix_image) return 0;
    proc->ilen = 0;
    proc->unix_image = 0;
    proc->tries++;
    __u64 arguments = BPF_CORE_READ(task, mm, arg_start);
    long n = bpf_probe_read_user_str(proc->image, KB_PROG, (void*)arguments);
    if (n < 4 || n > KB_PROG) {
        proc->image[0] = 0;
        return 0;
    }
    /* Before Wine rewrites it, argv[0] is the loader: a Unix path, or a bare loader name from
     * $PATH. After, the Windows program: C:\...\x.exe, or the bare name it was started as
     * (`wine start.exe` leaves "start.exe"). */
    if (proc->image[0] == '/' || loader_name(proc)) {
        proc->image[0] = 0;
        return 0;
    }
    struct base_ctx base = {tgid, (__u32)(n - 1)};
    proc->ibase = 0;
    bpf_loop(KB_PROG, base_step, &base, 0);
    if (proc->ibase >= KB_PROG) proc->ibase = 0;
    proc->ilen = (__u32)(n - 1);
    struct kb_scratch* s = reset_for(tgid, 0);
    if (!s) return 0;
    proc->device_host = image_is(s, "winedevice.exe", 14);
    if (proc->guarded || !c->enabled || c->mode == KFILTER_MODE_OFF || !kb_windows_protected()) return 0;
    int enforce = c->mode == KFILTER_MODE_BLOCK && (c->flags & KFILTER_CFG_BLOCK_PROCESS_CREATE) != 0;
    if (enforce) {
        int admitted = take_windows_launch_pass(task);
        path_is_image(s);
        if (!admitted) {
            emit(KB_EV_DECISION, KFILTER_TARGET_PROCESS, KFilterActionDeny, KFILTER_EVENT_FLAG_PROCESS_CREATE,
                 STATUS_ACCESS_DENIED, 0, 0, KFILTER_RIGHT_CREATE, 1);
            bpf_send_signal(SIGKILL);
            return -EFAULT;
        }
        emit(KB_EV_DECISION, KFILTER_TARGET_PROCESS, KFilterActionAllow, KFILTER_EVENT_FLAG_PROCESS_CREATE, 0, 0, 0,
             KFILTER_RIGHT_CREATE, 1);
    }
    path_is_image(s);
    proc->guarded = 1;
    state->guarded = 1;
    emit(KB_EV_PROTECT, 0, 0, 0, 0, 0, 0, 0, 1);
    return 0;
}

/* KfRightsFromRegistryAccess */
static __always_inline __u32 registry_rights(__u32 access)
{
    __u32 rights = 0;
    if ((access & (0x10000000u | 0x02000000u)) != 0) {
        return KFILTER_RIGHT_READ | KFILTER_RIGHT_WRITE | KFILTER_RIGHT_DELETE | KFILTER_RIGHT_RENAME |
               KFILTER_RIGHT_SET_SECURITY | KFILTER_RIGHT_ENUMERATE;
    }
    if ((access & (0x0001u | 0x0010u | 0x00020000u | 0x80000000u | 0x20000000u)) != 0) rights |= KFILTER_RIGHT_READ;
    if ((access & (0x0008u | 0x80000000u | 0x20000000u)) != 0) rights |= KFILTER_RIGHT_ENUMERATE;
    if ((access & (0x0002u | 0x0004u | 0x0020u | 0x40000000u)) != 0) rights |= KFILTER_RIGHT_WRITE;
    if ((access & 0x00010000u) != 0) rights |= KFILTER_RIGHT_DELETE;
    if ((access & (0x00040000u | 0x00080000u)) != 0) rights |= KFILTER_RIGHT_SET_SECURITY;
    return rights;
}

/* UTF-16 s->name -> s->path at s->len or s->value (ASCII; anything else as '?'). */
struct u16_ctx {
    __u32 count, at, to_value;
};

static long u16_step(__u32 index, struct u16_ctx* c)
{
    struct kb_scratch* s = scratch();
    if (!s || index >= c->count) return 1;
    __u32 from = (index * 2) & (KB_PATH - 1);
    __u8 low = s->name[from];
    __u8 high = s->name[(from + 1) & (KB_PATH - 1)];
    char ch = (high == 0 && low != 0 && low < 0x80) ? (char)low : '?';
    __u32 at = c->at + index;
    if (c->to_value) {
        s->value[at & (KB_VALUE - 1)] = ch;
        return 0;
    }
    if (ch == '\\' && at > 0 && s->path[(at - 1) & (KB_PATH - 1)] == '\\') s->doubled = 1;
    s->path[at & (KB_PATH - 1)] = ch;
    return 0;
}

static long collapse_step(__u32 index, void* unused)
{
    struct kb_scratch* s = scratch();
    if (!s || index >= s->len || index >= KB_PATH) return 1;
    char ch = s->path[index & (KB_PATH - 1)];
    __u32 out = s->cursor;
    if (ch == '\\' && out > 0 && s->path[(out - 1) & (KB_PATH - 1)] == '\\') return 0;
    s->path[out & (KB_PATH - 1)] = ch;
    s->cursor = out + 1;
    return 0;
}

/* wineserver's lookups skip repeated backslashes (Wine's own display set-up sends ...\Current\\System\...):
 * so does the name decided, or \A\\B would pass a rule on \A\B. A pass of its own, only when needed: its
 * cursor lives in the scratch, so the verifier does not follow it value by value. */
__noinline int kb_collapse(void)
{
    struct kb_scratch* s = scratch();
    if (!s || !s->doubled) return 0;
    s->doubled = 0;
    s->cursor = 0;
    bpf_loop(KB_PATH, collapse_step, 0, 0);
    s->len = s->cursor & (KB_PATH - 1);
    s->path[s->len & (KB_PATH - 1)] = 0;
    return 0;
}

/* The UTF-16 name at Pointer (Bytes long, in the request's joined data) into s->name; Bytes/2 characters, -1 if too
 * long. */
static __always_inline int read_name(__u64 pointer, __u32 bytes)
{
    struct kb_scratch* s = scratch();
    if (!s) return -1;
    bytes &= ~1u;
    if (bytes > KB_PATH) {
        s->failed = 1;
        return -1;
    }
    if (bytes != 0 && bpf_probe_read_kernel(s->name, bytes, (void*)pointer) != 0) {
        s->failed = 1;
        return -1;
    }
    return (int)(bytes / 2);
}

/* The address of Bytes of a request's data from byte At (its objattr's name): in the joined data at Data (*Size bytes)
 * when they lie in it, else joined again from At when they lie in the request (a security descriptor of 4 KiB puts a
 * name past the joined bytes; wineserver reads it there), and *Size is 0 then (the joined bytes are gone); 0 when they
 * lie past the request or cannot be read. */
static __always_inline __u64 request_bytes(__u64 data, __u32* size, __u32 at, __u32 bytes)
{
    struct kb_scratch* s = scratch();
    if (data == 0 || !s) return 0;
    if (at <= *size && bytes <= *size - at) return data + at;
    __u32 total = s->request[1];
    if (at > total || bytes > total - at) return 0;
    *size = 0;
    return kb_request_at(at, bytes);
}

/* s->path = the key Parent (a handle of Tgid; 0: none) joined with Chars characters of
 * s->name. An unknown parent or a name that does not fit is a name failure. */
static __always_inline int key_path(__u32 tgid, __u32 parent, __u32 chars)
{
    struct kb_scratch* s = scratch();
    if (!s) return -1;
    s->len = 0;
    s->path[0] = 0;
    if (parent != 0) {
        struct kb_hkey_id id = {tgid, parent};
        struct kb_hkey* key = bpf_map_lookup_elem(&kb_hkeys, &id);
        /* A handle it inherited (the console, std handles): Wine gives the child its creator's values,
         * which may be inherited themselves (cmd.exe's console from conhost.exe). */
#pragma unroll
        for (int up = 0; up < 3 && !key; up++) {
            struct kb_proc* holder = bpf_map_lookup_elem(&kb_procs, &id.tgid);
            if (!holder || holder->creator == 0 || holder->creator == id.tgid) break;
            id.tgid = holder->creator;
            key = bpf_map_lookup_elem(&kb_hkeys, &id);
        }
        if (!key || key->len == 0 || key->len >= KB_PATH) {
            s->failed = 1;
            return -1;
        }
        bpf_probe_read_kernel(s->path, KB_PATH, key->path);
        s->len = key->len;
        if (chars == 0) return 0;
        if (s->len + 1 >= KB_PATH) {
            s->failed = 1;
            return -1;
        }
        s->path[s->len & (KB_PATH - 1)] = '\\';
        s->len += 1;
    } else if (chars == 0) {
        s->failed = 1;
        return -1;
    }
    if (s->len + chars >= KB_PATH) {
        s->failed = 1;
        return -1;
    }
    struct u16_ctx convert = {chars, s->len, 0};
    bpf_loop(KB_PATH / 2, u16_step, &convert, 0);
    s->len += chars;
    s->path[s->len & (KB_PATH - 1)] = 0;
    kb_collapse();
    return 0;
}

/* s->value = Chars characters of s->name. */
static __always_inline void value_name(__u32 chars)
{
    struct kb_scratch* s = scratch();
    if (!s) return;
    /* A longer name (AppCompatFlags\Layers names its values by a program's full path) is kept as its first
     * KB_VALUE - 2 characters and '~': no exact rule of a real (short) value name matches it, and a pattern
     * (value=*Domain*) still matches its start. shortcut: two such names alike in their first 126
     * characters decide alike; upgrade: a longer KB_VALUE (it is KFILTER_MAX_VALUE in the rule format). */
    if (chars >= KB_VALUE) {   /* constant indexes: the verifier keeps no bound on a clamped count */
        struct u16_ctx convert = {KB_VALUE - 2, 0, 1};
        bpf_loop(KB_VALUE, u16_step, &convert, 0);
        s->value[KB_VALUE - 2] = '~';
        s->value[KB_VALUE - 1] = 0;
        s->vlen = KB_VALUE - 1;
        return;
    }
    struct u16_ctx convert = {chars, 0, 1};
    bpf_loop(KB_VALUE, u16_step, &convert, 0);
    s->value[chars & (KB_VALUE - 1)] = 0;
    s->vlen = chars;
}

/* kb_wine_request's answer to kb_file_permission: refuse the write, or decide the
 * registry request prepared in the scratch (s->path, s->value) with these rights. The
 * decision itself is made by the hook, so the deep matching chain is not stacked on top of
 * the request decoding (512 bytes of stack for the whole call chain). */
#define KB_REQ_REFUSE 1            /* an unadmitted program (kb_wine_name logged and killed it) */
/* A protected program's write to a request pipe that Wine never makes (someone else's pipe, a split header, a request
 * number past the protocol's, data chunks that do not add up to its request_size), or by a task that is not a decoded
 * Wine process: refused and logged as KB_RAW_REQUEST. */
#define KB_REQ_RAW 2
#define KB_RAW_REQUEST 0x4000u     /* refuse()'s value for it, plus the splice-family syscall number */
#define KB_REG_DECIDE (1 << 16)
#define KB_REG_RENAME (1 << 17)    /* then decide the new name too (kb_rename_target) */
#define KB_REG_PENDING (1 << 18)   /* allowed: record the key for the handle in the reply */
#define KB_REG_RIGHTS 0xFFFF
#define KB_SYSTEM_DECIDE (1 << 20)  /* decide the system request in s->path with these rights (kb_wine_query) */
#define KB_NT_OBJECT (1 << 21)   /* with KB_REG_DECIDE: an NT object, not a registry request */
#define KB_NT_PIPE (1 << 22)     /* ... a named pipe */
#define KB_NT_VOLUME (1 << 23)   /* ... a volume identity query (get_volume_info): the class in s->request[14] */
/* With KB_SYSTEM_DECIDE: a request without a row of its own, decided with KB_WINE_ROOT (kb_system_listed). */
#define KB_SYSTEM_NAMED (1 << 24)
static __always_inline __u32 kb_system_listed(int code)
{
    return 1 | ((code & KB_SYSTEM_NAMED) != 0 ? KB_WINE_ROOT : 0);
}

/*
 * Prepares a registry request of a protected program (header in s->request, its data joined
 * at Data, Size bytes; Tgid/Tid own the request pipe) for the decision
 * driver/registry.c makes for the matching RegNtPre* class. Returns 0 when there is nothing
 * to decide, else KB_REG_* | rights.
 */
__noinline int kb_registry(__u32 tgid, __u32 tid, __u64 data, __u32 size)
{
    struct kb_scratch* s = scratch();
    if (!s) return 0;
    __u32 req = s->request[0];
    __u32 a = s->request[3];   /* first field, offset 12 */
    __u32 b = s->request[4];
    __u32 d = s->request[5];
    int chars;
    switch (req) {
    case KB_REQ_OPEN_KEY:   /* parent, access, attributes; name */
    case KB_REQ_UNLOAD_REGISTRY: { /* parent, attributes; name */
        chars = read_name(data, size);
        if (chars >= 0) key_path(tgid, a, (__u32)chars);
        if (req == KB_REQ_UNLOAD_REGISTRY) return KB_REG_DECIDE | KFILTER_RIGHT_DELETE;
        s->pending.req = req;
        s->pending.key.kind = KB_HKEY_KEY;
        s->owner_tid = tid;
        return KB_REG_DECIDE | KB_REG_PENDING | registry_rights(b);
    }
    case KB_REQ_CREATE_KEY:    /* access, options; objattr {rootdir, attributes, sd_len, name_len} sd name */
    case KB_REQ_LOAD_REGISTRY: { /* file; objattr */
        __u32 attributes[4] = {};
        if (size < 16 || bpf_probe_read_kernel(attributes, sizeof(attributes), (void*)data) != 0) {
            s->failed = 1;
        } else {
            __u64 name = request_bytes(data, &size, 16 + (attributes[2] & ~1u), attributes[3]);
            if (name == 0) {
                s->failed = 1;
            } else {
                chars = read_name(name, attributes[3]);
                if (chars >= 0) key_path(tgid, attributes[0], (__u32)chars);
            }
        }
        if (req == KB_REQ_LOAD_REGISTRY) return KB_REG_DECIDE | KFILTER_RIGHT_WRITE;
        s->pending.req = req;
        s->pending.key.kind = KB_HKEY_KEY;
        s->owner_tid = tid;
        return KB_REG_DECIDE | KB_REG_PENDING | registry_rights(a);
    }
    case KB_REQ_GET_KEY_VALUE:      /* hkey; name: RegNtPreQueryValueKey */
    case KB_REQ_DELETE_KEY_VALUE:   /* hkey; name: RegNtPreDeleteValueKey */
        key_path(tgid, a, 0);
        chars = read_name(data, size);
        if (chars >= 0) value_name((__u32)chars);
        return KB_REG_DECIDE | (req == KB_REQ_GET_KEY_VALUE ? KFILTER_RIGHT_READ : KFILTER_RIGHT_DELETE);
    case KB_REQ_SET_KEY_VALUE:      /* hkey, type, namelen; name, data */
        key_path(tgid, a, 0);
        chars = read_name(data, d <= size ? d : size);
        if (chars >= 0) value_name((__u32)chars);
        return KB_REG_DECIDE | KFILTER_RIGHT_WRITE;
    case KB_REQ_ENUM_KEY:           /* hkey, index (-1: query the key itself), info_class */
        key_path(tgid, a, 0);
        return KB_REG_DECIDE | (b == 0xFFFFFFFFu ? KFILTER_RIGHT_READ : KFILTER_RIGHT_ENUMERATE);
    case KB_REQ_ENUM_KEY_VALUE:     /* hkey, index, info_class: covered by any value-scoped deny */
        key_path(tgid, a, 0);
        s->any_value = 1;
        return KB_REG_DECIDE | KFILTER_RIGHT_ENUMERATE;
    case KB_REQ_DELETE_KEY:
        key_path(tgid, a, 0);
        return KB_REG_DECIDE | KFILTER_RIGHT_DELETE;
    case KB_REQ_SAVE_REGISTRY:
        key_path(tgid, a, 0);
        return KB_REG_DECIDE | KFILTER_RIGHT_READ;
    /* Windows decides neither a flush nor a change notification; both are read here, which
     * the open of the key already needed (KEY_NOTIFY is part of KEY_READ). */
    case KB_REQ_FLUSH_KEY:                  /* hkey */
    case KB_REQ_SET_REGISTRY_NOTIFICATION:  /* hkey, event, subtree, filter */
        key_path(tgid, a, 0);
        return KB_REG_DECIDE | KFILTER_RIGHT_READ;
    /* Every handle kb_hkeys names (a key, a file, pipe or section opened by its NT name, an object directory) as
     * registry on its name, as before kfilter kept their kinds: deciding a file's or pipe's by the file and pipe rules
     * would make those rules refuse what they never met. */
    case KB_REQ_GET_SECURITY_OBJECT:   /* handle, security_info: RegNtPreQueryKeySecurity (READ_CONTROL) */
    case KB_REQ_SET_SECURITY_OBJECT: { /* handle, security_info; sd: RegNtPreSetKeySecurity (WRITE_DAC) */
        struct kb_hkey_id id = {tgid, a};
        if (!bpf_map_lookup_elem(&kb_hkeys, &id)) return 0;   /* not a handle kfilter named */
        key_path(tgid, a, 0);
        return KB_REG_DECIDE | (req == KB_REQ_GET_SECURITY_OBJECT ? KFILTER_RIGHT_READ : KFILTER_RIGHT_SET_SECURITY);
    }
    case KB_REQ_RENAME_KEY:         /* hkey; new name: the old and the new name are renamed */
        key_path(tgid, a, 0);
        chars = read_name(data, size);
        s->rename_chars = chars > 0 ? (__u32)chars : 0;
        return KB_REG_DECIDE | KB_REG_RENAME | KFILTER_RIGHT_RENAME;
    default:
        return 0;
    }
}

/* The last '\' of s->path, scanning from the end (a bpf_loop, so the verifier does not
 * follow every (index, position) pair). */
struct cut_ctx {
    __u32 cut;
};

static long cut_step(__u32 index, struct cut_ctx* c)
{
    struct kb_scratch* s = scratch();
    if (!s || index >= s->len || index >= KB_PATH) return 1;
    __u32 at = s->len - 1 - index;
    if (s->path[at & (KB_PATH - 1)] == '\\') {
        c->cut = at;
        return 1;
    }
    return 0;
}

/* s->path = the renamed key's new name: the old name's parent plus the new last component
 * (s->name, s->rename_chars characters). */
__noinline int kb_rename_target(void)
{
    struct kb_scratch* s = scratch();
    if (!s) return 0;
    struct cut_ctx c = {0};
    bpf_loop(KB_PATH, cut_step, &c, 0);
    __u32 chars = s->rename_chars;
    if (s->failed || chars == 0 || c.cut == 0 || c.cut >= KB_PATH || c.cut + 1 + chars >= KB_PATH) {
        s->failed = 1;
        return 0;
    }
    s->len = c.cut + 1;
    struct u16_ctx convert = {chars, s->len, 0};
    bpf_loop(KB_PATH / 2, u16_step, &convert, 0);
    s->len += chars;
    s->path[s->len & (KB_PATH - 1)] = 0;
    kb_collapse();
    return 0;
}

/* After an allowed open or create: the handle in wineserver's reply gets this key's name. */
__noinline int kb_registry_pending(void)
{
    struct kb_scratch* s = scratch();
    if (!s || s->failed) return 0;
    __u32 tid = s->owner_tid;
    s->pending.key.len = s->len;
    bpf_probe_read_kernel(s->pending.key.path, KB_PATH, s->path);
    bpf_map_update_elem(&kb_pending, &tid, &s->pending, BPF_ANY);
    return 0;
}

/* ---- Wine's NT namespace: devices and named pipes (open_file_object, create_named_pipe) ----
 * Objects with no unix file behind them: \??\PhysicalDrive0, \??\Nsi, \Device\MountPointManager,
 * \??\HID#..., \Device\Afd, and named pipes. Decided as on Windows' minifilter: a pipe as a pipe,
 * anything else as a file open of its NT name (so rules read deny|file|\??\PhysicalDrive*). */

/* NT file access -> kfilter rights; attribute-only and SYNCHRONIZE opens are a bare open. */
static __always_inline __u32 nt_file_rights(__u32 access)
{
    __u32 rights = 0;
    if ((access & (0x0001u | 0x0008u | 0x80000000u | 0x10000000u)) != 0) rights |= KFILTER_RIGHT_READ;
    if ((access & (0x0002u | 0x0004u | 0x0010u | 0x40000000u | 0x10000000u)) != 0) rights |= KFILTER_RIGHT_WRITE;
    if ((access & (0x0020u | 0x20000000u | 0x10000000u)) != 0) rights |= KFILTER_RIGHT_EXECUTE;
    if ((access & 0x00010000u) != 0) rights |= KFILTER_RIGHT_DELETE;
    if ((access & (0x00040000u | 0x00080000u)) != 0) rights |= KFILTER_RIGHT_SET_SECURITY;
    return rights;
}

/* Section access -> kfilter rights: QUERY and MAP_READ read, MAP_WRITE and EXTEND_SIZE write, MAP_EXECUTE execute. */
static __always_inline __u32 section_rights(__u32 access)
{
    __u32 rights = 0;
    if ((access & (0x0001u | 0x0004u | 0x80000000u | 0x10000000u)) != 0) rights |= KFILTER_RIGHT_READ;
    if ((access & (0x0002u | 0x0010u | 0x40000000u | 0x10000000u)) != 0) rights |= KFILTER_RIGHT_WRITE;
    if ((access & (0x0008u | 0x20000000u | 0x10000000u)) != 0) rights |= KFILTER_RIGHT_EXECUTE;
    if ((access & 0x00010000u) != 0) rights |= KFILTER_RIGHT_DELETE;
    if ((access & (0x00040000u | 0x00080000u)) != 0) rights |= KFILTER_RIGHT_SET_SECURITY;
    return rights;
}

/* s->path starts with Prefix (lowercase, Length characters), without case. */
static __always_inline int nt_prefix(struct kb_scratch* s, const char* prefix, __u32 length)
{
    if (s->len < length) return 0;
#pragma unroll
    for (__u32 i = 0; i < 18; i++) {
        if (i >= length) break;
        if (lower(s->path[i]) != (__u32)prefix[i]) return 0;
    }
    return 1;
}

/* Prepares an NT object request for the decision: open_file_object, open_mapping and
 * open_directory (access, attributes, rootdir; name) or create_named_pipe, create_mapping and
 * create_directory (access, ...; objattr). A named section (shared memory other programs can
 * open by name, or probe for) is decided as a file of its NT name; an unnamed create_mapping has
 * nothing to decide. Directories are only named (their handles root the names opened in them).
 * A name relative to a handle kfilter did not name is a name failure. Returns
 * KB_REG_DECIDE | KB_NT_* | KB_REG_PENDING | rights, KB_REG_PENDING alone for a directory, or 0. */
/* An unnamed create_mapping: nothing to decide, but its reply's handle is recorded as no process
 * (kb_xhandles), so copying it with explicit access is not decided as an unknown process handle. */
static __always_inline int unnamed_section(__u32 tgid, __u32 tid)
{
    struct kb_scratch* s = scratch();
    if (!s) return 0;
    s->pending.req = KB_REQ_CREATE_MAPPING;
    s->pending.owner = tgid;
    s->pending.object.thread = KB_OBJECT_OTHER;
    s->len = 0;
    s->owner_tid = tid;
    return KB_REG_PENDING;
}

__noinline int kb_nt_object(__u32 tgid, __u32 tid, __u64 data, __u32 size)
{
    struct kb_scratch* s = scratch();
    if (!s) return 0;
    __u32 req = s->request[0];
    __u32 access = s->request[3];   /* offset 12 in every one of them */
    int section = req == KB_REQ_OPEN_MAPPING || req == KB_REQ_CREATE_MAPPING;
    int directory = req == KB_REQ_OPEN_DIRECTORY || req == KB_REQ_CREATE_DIRECTORY;
    __u32 rights = section ? section_rights(access) : nt_file_rights(access);
    int chars = -1;
    s->pending.object.thread = 0;
    if (req == KB_REQ_OPEN_FILE_OBJECT || req == KB_REQ_OPEN_MAPPING || req == KB_REQ_OPEN_DIRECTORY) {
        chars = read_name(data, size);
        if (chars >= 0) key_path(tgid, s->request[5], (__u32)chars);   /* rootdir, offset 20 */
    } else {
        __u32 attributes[4] = {};   /* rootdir, attributes, sd_len, name_len */
        if (size < 16 || bpf_probe_read_kernel(attributes, sizeof(attributes), (void*)data) != 0) {
            if (req == KB_REQ_CREATE_MAPPING) return unnamed_section(tgid, tid);   /* no object attributes */
            s->failed = 1;
        } else {
            if (req == KB_REQ_CREATE_MAPPING && attributes[3] == 0) return unnamed_section(tgid, tid);
            __u64 name = request_bytes(data, &size, 16 + (attributes[2] & ~1u), attributes[3]);
            if (name == 0) {
                s->failed = 1;
            } else {
                chars = read_name(name, attributes[3]);
                if (chars >= 0) key_path(tgid, attributes[0], (__u32)chars);
            }
        }
        rights |= KFILTER_RIGHT_CREATE;
    }
    s->pending.req = req;
    s->owner_tid = tid;
    s->pending.key.kind = directory ? KB_HKEY_DIRECTORY : KB_HKEY_FILE;
    if (directory) return KB_REG_PENDING;
    if (section) return KB_REG_DECIDE | KB_REG_PENDING | KB_NT_OBJECT | rights;
    int pipe = !s->failed && (nt_prefix(s, "\\??\\pipe\\", 9) || nt_prefix(s, "\\device\\namedpipe\\", 18));
    if (pipe) s->pending.key.kind = KB_HKEY_PIPE;
    return KB_REG_DECIDE | KB_REG_PENDING | KB_NT_OBJECT | (pipe ? KB_NT_PIPE : 0) | rights;
}

/* get_volume_info (handle, async, info_class at +56): the classes Windows' minifilter decides as
 * volume identity, FileFsVolumeInformation (1: serial, label) and FileFsObjectIdInformation (8).
 * Wine answers them from its mount manager. The path is the handle's NT name when kfilter named
 * it, else \Device\Volume; the value is the class as 0x%08X. */
__noinline int kb_volume_query(__u32 tgid, __u32 handle, __u32 info)
{
    struct kb_scratch* s = scratch();
    if (!s || (info != 1 && info != 8)) return 0;
    key_path(tgid, handle, 0);
    if (s->failed) {
        s->failed = 0;
        set_path(s, "\\Device\\Volume", 14);
        s->len = 14;
    }
    device_value(s, info);
    return KB_REG_DECIDE | KB_NT_OBJECT | KB_NT_VOLUME | KFILTER_RIGHT_QUERY;
}

/* A Windows process or thread id -> tgid, as wineserver's own replies name them
 * (init_first_thread, new_thread): never from the program's memory (its TEB). An id kfilter
 * did not learn is unknown, and an unknown process or thread counts as outside the family. */
static __always_inline void learn_id(__u32 id, __u32 tgid)
{
    if (id != 0 && tgid != 0) bpf_map_update_elem(&kb_wintids, &id, &tgid, BPF_ANY);
}

/* ---- process and thread handles (driver/object.c) ---- */

/* s->path = a process's program: its Windows image under Wine, else its executable. */
static __always_inline void program_path(struct kb_scratch* s, struct task_struct* task, __u32 tgid)
{
    struct kb_proc* proc = bpf_map_lookup_elem(&kb_procs, &tgid);
    s->failed = 0;
    if (proc && proc->ilen != 0 && proc->ilen < KB_PROG) {
        bpf_probe_read_kernel(s->path, KB_PROG, proc->image);
        s->path[KB_PROG - 1] = 0;
        s->len = proc->ilen;
        return;
    }
    if (task) walk_exe(task);
    else s->failed = 1;
}

/* A process, thread or handle kfilter cannot place, named for the log as "(unknown handle 0x00001234)"
 * or "(unknown pid 0x...)": no rule can match a name in parentheses, so it is decided as before. */
static __always_inline void unknown_name(struct kb_scratch* s, __u32 pid, __u32 value)
{
    const char head[] = "(unknown handle 0x";
    const char phead[] = "(unknown pid 0x";
    int at = 0;
    if (pid) {
#pragma unroll
        for (int i = 0; i < (int)sizeof(phead) - 1; i++) s->path[at++] = phead[i];
    } else {
#pragma unroll
        for (int i = 0; i < (int)sizeof(head) - 1; i++) s->path[at++] = head[i];
    }
#pragma unroll
    for (int i = 7; i >= 0; i--) {
        __u32 digit = (value >> (i * 4)) & 0xF;
        s->path[at++ & (KB_PATH - 1)] = digit < 10 ? '0' + digit : 'a' + digit - 10;
    }
    s->path[at++ & (KB_PATH - 1)] = ')';
    s->path[at & (KB_PATH - 1)] = 0;
    s->len = at;
    s->failed = 0;
}

#define KB_HANDLE_DECIDE (1 << 19)        /* decide the process or thread handle prepared in the scratch */
#define KB_CURRENT_PROCESS 0xFFFFFFFFu   /* GetCurrentProcess() */
#define KB_CURRENT_THREAD 0xFFFFFFFEu    /* GetCurrentThread() */
#define KB_ALL_ACCESS 0x1FFFFFu          /* PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS */
#define KB_THREAD_DANGEROUS 0xFFBu       /* KfThreadDangerous */
#define KB_PROCESS_DANGEROUS 0xEFBu      /* KfProcessDangerous */
#define KB_DUPLICATE_CLOSE_SOURCE 1
#define KB_DUPLICATE_SAME_ACCESS 2

/* An access mask with its generic rights mapped as wineserver maps them for threads or
 * processes; MAXIMUM_ALLOWED asks for everything. */
static __always_inline __u32 handle_access(__u32 access, __u32 thread)
{
    __u32 mapped = access & ~0xF2000000u;
    if ((access & 0x12000000u) != 0) mapped |= KB_ALL_ACCESS;                      /* GENERIC_ALL, MAXIMUM_ALLOWED */
    if ((access & 0x80000000u) != 0) mapped |= thread ? 0x20048u : 0x20410u;      /* GENERIC_READ */
    if ((access & 0x40000000u) != 0) mapped |= thread ? 0x20437u : 0x20BEBu;      /* GENERIC_WRITE */
    if ((access & 0x20000000u) != 0) mapped |= thread ? 0x121800u : 0x121001u;    /* GENERIC_EXECUTE */
    return mapped;
}

/* A process or thread handle one protected program takes on another (Object, not itself):
 * a peer or thread-peer decision, made only where such a rule exists (rule-only), on the
 * access it asks for. s->path is the other program; image= is the requester. */
static __always_inline int peer_handle(struct kb_cfg* c, struct kb_scratch* s, __u32 object, __u32 thread, __u32 access)
{
    __u32 target = thread ? KFILTER_TARGET_THREAD_PEER : KFILTER_TARGET_PEER;
    if ((c->targets & target) == 0 || access == 0) return 0;
    s->htarget = target;
    s->hremoved = access;
    s->haccess = access;
    program_path(s, 0, object);
    return KB_HANDLE_DECIDE;
}

/* The process a handle record reaches (0: unknown). new_process's names the child by its
 * Windows pid until the child's init_first_thread reply names its tgid. */
static __always_inline __u32 ohandle_tgid(struct kb_ohandle* record)
{
    if (record->tgid != 0 || record->pid == 0) return record->tgid;
    __u32 pid = record->pid;
    __u32* found = bpf_map_lookup_elem(&kb_wintids, &pid);
    return found ? *found : 0;
}

/* The process a process handle of Tgid reaches, 0 when kfilter did not see it made. */
static __always_inline __u32 process_target(__u32 tgid, __u32 handle)
{
    if (handle == KB_CURRENT_PROCESS) return tgid;
    struct kb_hkey_id id = {tgid, handle};
    struct kb_ohandle* known = bpf_map_lookup_elem(&kb_ohandles, &id);
    return known && !known->thread ? ohandle_tgid(known) : 0;
}

/* ---- what a Wine request reaches past its own decision (kb_wine_decide) ---- */

#define KB_WINE_DECIDE (KB_HANDLE_DECIDE | 1)   /* decide what the request in the scratch reaches: kb_wine_decide */
#define KB_T_HANDLE 1   /* a process or thread handle at any offset: peer or thread-peer, only rules naming the request */
#define KB_T_TID 2      /* Windows thread ids: a peer decision on each one's program, by a pseudo-right */
#define KB_T_WINDOW 3   /* windows: a peer decision on each one's owner, by a pseudo-right */
#define KB_T_KEY 4      /* keyed decisions: /system/wine/<request>/<key>, /system/rpc/... */
#define KB_T_VALUE 5    /* a system request's decisions by value= alone */
#define KB_VARIANTS 8   /* decisions past a request's own, at most (adjust_token_privileges: its first 8 privileges) */

struct kb_wtarget {
    __u8 kind;
    __u8 field;          /* header word of the handle, thread id or window */
    __u8 field2;         /* a second thread id or window (0: none) */
    __u8 vfield;         /* header word whose 0x%08X the decision's value is (a message, an offset, a key; 0: none) */
    __u32 access;        /* KB_T_HANDLE: what wineserver asks of the handle; KB_T_TID and KB_T_WINDOW: the pseudo-right */
};

/* Offsets are the request's (3-wineserver-protocol.md Appendix A; wineserver's handlers checked for the access). */
#define KB_WT(req, kind, field, field2, vfield, access) [req] = {kind, field, field2, vfield, access}
#define KB_WQUERY KFILTER_ACCESS_WINDOW_QUERY
#define KB_WSET KFILTER_ACCESS_WINDOW_SET
static const struct kb_wtarget kb_wtargets[KB_REQ_COUNT] = {
    KB_WT(KB_REQ_NEW_THREAD, KB_T_HANDLE, 3, 0, 0, 0x2),                 /* PROCESS_CREATE_THREAD (wineserver asks 0) */
    KB_WT(KB_REQ_GET_THREAD_INFO, KB_T_HANDLE, 3, 0, 0, 0),              /* the query rights it asks for (+16) */
    KB_WT(KB_REQ_GET_THREAD_TIMES, KB_T_HANDLE, 3, 0, 0, 0x800),         /* THREAD_QUERY_LIMITED_INFORMATION */
    KB_WT(KB_REQ_GET_PROCESS_IDLE_EVENT, KB_T_HANDLE, 3, 0, 0, 0x400),   /* PROCESS_QUERY_INFORMATION */
    KB_WT(KB_REQ_CANCEL_SYNC, KB_T_HANDLE, 3, 0, 0, 0x1),                /* THREAD_TERMINATE */
    KB_WT(KB_REQ_MAKE_PROCESS_SYSTEM, KB_T_HANDLE, 3, 0, 0, 0x200),      /* PROCESS_SET_INFORMATION */
    KB_WT(KB_REQ_GRANT_PROCESS_ADMIN_TOKEN, KB_T_HANDLE, 3, 0, 0, 0x200),
    KB_WT(KB_REQ_ASSIGN_JOB, KB_T_HANDLE, 4, 0, 0, 0x101),               /* PROCESS_SET_QUOTA | PROCESS_TERMINATE */
    KB_WT(KB_REQ_PROCESS_IN_JOB, KB_T_HANDLE, 4, 0, 0, 0x400),
    KB_WT(KB_REQ_SEND_MESSAGE, KB_T_TID, 3, 0, 7, KFILTER_ACCESS_WINDOW_MESSAGE),   /* to id's queue; msg@0x1c */
    KB_WT(182 /* get_thread_desktop */, KB_T_TID, 3, 0, 0, KB_WQUERY),
    KB_WT(187 /* attach_thread_input */, KB_T_TID, 3, 4, 0, KFILTER_ACCESS_INPUT),   /* tid_from, tid_to */
    KB_WT(188 /* get_thread_input */, KB_T_TID, 3, 0, 0, KFILTER_ACCESS_INPUT),
    KB_WT(128 /* is_window_hung */, KB_T_WINDOW, 3, 0, 0, KB_WQUERY),
    KB_WT(143 /* destroy_window */, KB_T_WINDOW, 3, 0, 0, KB_WSET),
    KB_WT(145 /* set_window_owner */, KB_T_WINDOW, 3, 4, 0, KB_WSET),   /* handle, owner */
    KB_WT(146 /* get_window_info */, KB_T_WINDOW, 3, 0, 4, KB_WQUERY),   /* GetWindowLong's offset */
    KB_WT(148 /* set_window_info */, KB_T_WINDOW, 3, 0, 4, KB_WSET),
    KB_WT(149 /* set_parent */, KB_T_WINDOW, 3, 4, 0, KB_WSET),          /* handle, parent */
    KB_WT(150 /* get_window_parents */, KB_T_WINDOW, 3, 0, 0, KB_WQUERY),
    KB_WT(KB_REQ_GET_WINDOW_LIST, KB_T_WINDOW, 4, 0, 0, KB_WQUERY),      /* the parent it lists */
    KB_WT(152 /* get_class_windows */, KB_T_WINDOW, 3, 0, 0, KB_WQUERY),
    KB_WT(153 /* get_window_children_from_point */, KB_T_WINDOW, 3, 0, 0, KB_WQUERY),
    KB_WT(KB_REQ_GET_WINDOW_TREE, KB_T_WINDOW, 3, 0, 0, KB_WQUERY),
    KB_WT(155 /* set_window_pos */, KB_T_WINDOW, 5, 0, 0, KB_WSET),      /* handle@0x14 */
    KB_WT(156 /* get_window_rectangles */, KB_T_WINDOW, 3, 0, 0, KB_WQUERY),
    KB_WT(KB_REQ_GET_WINDOW_TEXT, KB_T_WINDOW, 3, 0, 0, KB_WQUERY),
    KB_WT(158 /* set_window_text */, KB_T_WINDOW, 3, 0, 0, KB_WSET),
    KB_WT(159 /* get_windows_offset */, KB_T_WINDOW, 3, 4, 0, KB_WQUERY),   /* from, to */
    KB_WT(160 /* get_visible_region */, KB_T_WINDOW, 3, 0, 0, KB_WQUERY),
    KB_WT(161 /* get_window_region */, KB_T_WINDOW, 3, 0, 0, KB_WQUERY),
    KB_WT(162 /* set_window_region */, KB_T_WINDOW, 3, 0, 0, KB_WSET),
    KB_WT(163 /* get_update_region */, KB_T_WINDOW, 3, 0, 0, KB_WQUERY),
    KB_WT(164 /* update_window_zorder */, KB_T_WINDOW, 3, 0, 0, KB_WSET),
    KB_WT(165 /* redraw_window */, KB_T_WINDOW, 3, 0, 0, KB_WSET),
    KB_WT(166 /* set_window_property */, KB_T_WINDOW, 3, 0, 0, KB_WSET),
    KB_WT(167 /* remove_window_property */, KB_T_WINDOW, 3, 0, 0, KB_WSET),
    KB_WT(168 /* get_window_property */, KB_T_WINDOW, 3, 0, 0, KB_WQUERY),
    KB_WT(169 /* get_window_properties */, KB_T_WINDOW, 3, 0, 0, KB_WQUERY),
    KB_WT(KB_REQ_REGISTER_HOTKEY, KB_T_WINDOW, 3, 0, 6, KFILTER_ACCESS_INPUT),      /* vkey@0x18 */
    KB_WT(186 /* unregister_hotkey */, KB_T_WINDOW, 3, 0, 0, KFILTER_ACCESS_INPUT),
    KB_WT(192 /* set_foreground_window */, KB_T_WINDOW, 3, 0, 0, KB_WSET),
    KB_WT(193 /* set_focus_window */, KB_T_WINDOW, 3, 0, 0, KB_WSET),
    KB_WT(194 /* set_active_window */, KB_T_WINDOW, 3, 0, 0, KB_WSET),
    KB_WT(195 /* set_capture_window */, KB_T_WINDOW, 3, 0, 0, KFILTER_ACCESS_INPUT),
    KB_WT(196 /* set_caret_window */, KB_T_WINDOW, 3, 0, 0, KB_WSET),
    KB_WT(197 /* set_caret_info */, KB_T_WINDOW, 4, 0, 0, KB_WSET),     /* handle@0x10 */
    KB_WT(205 /* set_class_info */, KB_T_WINDOW, 3, 0, 4, KB_WSET),     /* SetClassLong's offset */
    KB_WT(206 /* get_class_info */, KB_T_WINDOW, 3, 0, 4, KB_WQUERY),
    KB_WT(275 /* get_window_layered_info */, KB_T_WINDOW, 3, 0, 0, KB_WQUERY),
    KB_WT(276 /* set_window_layered_info */, KB_T_WINDOW, 3, 0, 0, KB_WSET),
    KB_WT(KB_REQ_NEW_PROCESS, KB_T_KEY, 0, 0, 0, 0),
    KB_WT(KB_REQ_READ, KB_T_KEY, 0, 0, 0, 0),
    KB_WT(KB_REQ_WRITE, KB_T_KEY, 0, 0, 0, 0),
    KB_WT(KB_REQ_IOCTL, KB_T_KEY, 0, 0, 0, 0),
    KB_WT(KB_REQ_SEND_HARDWARE_MESSAGE, KB_T_KEY, 0, 0, 0, 0),
    KB_WT(KB_REQ_GET_KEY_STATE, KB_T_KEY, 0, 0, 0, 0),
    KB_WT(KB_REQ_SET_HOOK, KB_T_KEY, 0, 0, 0, 0),
    KB_WT(KB_REQ_GET_CLIPBOARD_DATA, KB_T_KEY, 0, 0, 0, 0),
    KB_WT(KB_REQ_ADJUST_TOKEN_PRIVILEGES, KB_T_VALUE, 0, 0, 0, 0),
    KB_WT(KB_REQ_SET_THREAD_INFO, KB_T_VALUE, 0, 0, 0, 0),
    KB_WT(KB_REQ_SET_CURSOR, KB_T_KEY, 0, 0, 0, 0),
    KB_WT(KB_REQ_UPDATE_RAWINPUT_DEVICES, KB_T_KEY, 0, 0, 0, 0),
};

/* Req of a protected program reaches past its own decision what some rule can meet (kb_wtargets): the request in
 * s->request, with Joined bytes of its data (0: none), is left to kb_wine_decide. */
static __always_inline int wine_targets(struct kb_cfg* c, struct kb_scratch* s, __u32 req, __u32 joined)
{
    if (req >= KB_REQ_COUNT || !c->enabled || c->mode == KFILTER_MODE_OFF) return 0;
    __u32 kind = kb_wtargets[req].kind;
    int made = kind == KB_T_HANDLE                       ? (c->targets & (KB_TARGET_PEER_VALUE | KB_TARGET_THREAD_VALUE)) != 0
               : kind == KB_T_TID || kind == KB_T_WINDOW ? (c->targets & KB_TARGET_WINDOW) != 0
               : kind == KB_T_KEY                        ? (c->targets & KB_TARGET_KEYED) != 0
               : kind == KB_T_VALUE                      ? (c->targets & KB_TARGET_SYSTEM_VALUE) != 0
                                                         : 0;
    if (!made) return 0;
    s->haccess = joined;   /* kb_wine_decide's data */
    return KB_WINE_DECIDE;
}

/* wine_targets for the request in s->request of protected program Tgid (Joined: its data's bytes): a global function,
 * so kb_wine_request's paths do not each verify it. */
__noinline int kb_wine_reaches(__u32 tgid, __u32 joined)
{
    struct kb_cfg* c = kb_cfg_get();
    struct kb_scratch* s = reset_for(tgid, 0);
    if (!c || !s) return 0;
    return wine_targets(c, s, s->request[0], joined) == KB_WINE_DECIDE ? KB_WINE_DECIDE : 0;
}

/*
 * A process or thread handle request of a decoded Wine program (header in s->request):
 * records what the reply's handle reaches, and prepares the decision object.c makes for a
 * handle crossing the family boundary: s->htarget, s->hremoved (the rights a rule must
 * grant), s->haccess, and s->path the outside program; or, for one protected program
 * reaching another, a peer decision (peer_handle). Guarded: the requester is protected; Joined: the bytes of its
 * data kb_request_data joined (0: none). Returns KB_HANDLE_DECIDE, KB_WINE_DECIDE (new_thread, new_process: what they
 * reach, once the reply is kept for) or 0. Wine carries out what a process handle allows (remote
 * threads, VirtualAllocEx, mapped views, termination) in wineserver or through an APC the
 * target runs itself, so the rights are decided here, when the handle is made, as on Windows.
 * A process or thread kfilter cannot name (an id or handle it did not see made, the next
 * process of get_next_process) counts as outside. So does the handle a protected program
 * duplicates when kfilter did not see it made (inherited, evicted from kb_ohandles): Wine
 * grants the copy whatever access is asked, so process rights asked for it are decided as
 * for an unknown outside process. DUPLICATE_SAME_ACCESS from a handle of the family copies
 * rights decided when that handle was made, and is not decided again.
 * shortcut: an unknown handle that is not a process (an event, a file) duplicated with
 * explicit access overlapping process rights is decided too (refused in block mode); Wine
 * itself duplicates with DUPLICATE_SAME_ACCESS. Upgrade: learn handle types if a game does.
 */
__noinline int kb_handle_request(__u32 tgid, __u32 ownerTid, __u32 guarded, __u32 joined)
{
    struct kb_cfg* c = kb_cfg_get();
    struct kb_scratch* s = scratch();
    if (!c || !s) return 0;
    __u32 req = s->request[0];
    __u32 object = 0, thread = 1, access = 0, dest = tgid, holder = tgid, known = KB_ALL_ACCESS;
    __u32 unknownPid = 0, unknownValue = 0;   /* what to name an object kfilter cannot place by */
    __u32 childPid = 0;   /* a copy of a handle to a child the holder made, not started yet */
    if (req == KB_REQ_OPEN_PROCESS || req == KB_REQ_OPEN_THREAD) {   /* pid or tid, access, attributes */
        __u32 id = s->request[3];
        __u32* found = bpf_map_lookup_elem(&kb_wintids, &id);
        object = found ? *found : 0;
        thread = req == KB_REQ_OPEN_THREAD;
        unknownPid = 1;
        unknownValue = id;
        access = s->request[4];
    } else if (req == KB_REQ_GET_NEXT_PROCESS) {   /* last, access, attributes, flags */
        thread = 0;
        access = s->request[4];
    } else if (req == KB_REQ_NEW_PROCESS) {   /* token, debug, parent_process, flags, socket_fd, access */
        thread = 0;
        access = s->request[8];
    } else if (req == KB_REQ_GET_NEXT_THREAD || req == KB_REQ_NEW_THREAD) {
        /* get_next_thread: process, last, access; new_thread: process, access, flags, request_fd */
        object = process_target(tgid, s->request[3]);
        access = s->request[req == KB_REQ_NEW_THREAD ? 4 : 5];
    } else if (req == KB_REQ_DUP_HANDLE) {   /* src_process, src_handle, dst_process, access, attributes, options */
        __u32 source = s->request[3], handle = s->request[4], target = s->request[5], options = s->request[8];
        unknownValue = handle;
        holder = process_target(tgid, source);
        if (holder == 0 && !guarded) return 0;
        if (handle == KB_CURRENT_THREAD || handle == KB_CURRENT_PROCESS) {
            object = tgid;   /* wineserver: a pseudo handle is the requester's, whatever the source */
            thread = handle == KB_CURRENT_THREAD;
        } else {
            struct kb_hkey_id id = {holder, handle};
            struct kb_ohandle* record = holder != 0 ? bpf_map_lookup_elem(&kb_ohandles, &id) : 0;
            if (record) {
                object = ohandle_tgid(record);
                thread = record->thread;
                known = record->access;
                if (object == 0 && !record->thread) childPid = record->pid;
            } else if (holder != 0 && bpf_map_lookup_elem(&kb_hkeys, &id)) {
                /* A registry key: the copy keeps the key's name (crypt32 duplicates its certificate
                 * store keys), or every request through it would be a name failure. */
                struct kb_hkey* key = bpf_map_lookup_elem(&kb_hkeys, &id);
                dest = target != 0 ? process_target(tgid, target) : 0;
                if (!key || dest == 0) return 0;
                bpf_probe_read_kernel(&s->pending.key, sizeof(s->pending.key), key);
                if ((options & KB_DUPLICATE_CLOSE_SOURCE) != 0) bpf_map_delete_elem(&kb_hkeys, &id);
                s->pending.req = req;
                s->pending.owner = dest;
                s->pending.object.tgid = 0;
                s->pending.object.thread = 0;
                bpf_map_update_elem(&kb_pending, &ownerTid, &s->pending, BPF_ANY);
                return 0;
            } else if (holder != 0 && (bpf_map_lookup_elem(&kb_xhandles, &id) || inherited_other(&id))) {
                /* No process or thread (an unnamed section): not decided; the copy is known too. */
                if ((options & KB_DUPLICATE_CLOSE_SOURCE) != 0) bpf_map_delete_elem(&kb_xhandles, &id);
                if (target == 0) return 0;   /* a close */
                dest = process_target(tgid, target);   /* 0: an APC's destination (kb_xmoved) */
                s->pending.req = req;
                s->pending.owner = dest;
                s->pending.object.tgid = 0;
                s->pending.object.thread = KB_OBJECT_OTHER;
                s->pending.key.len = 0;
                bpf_map_update_elem(&kb_pending, &ownerTid, &s->pending, BPF_ANY);
                return 0;
            } else if (!guarded) {
                return 0;   /* not a handle kfilter saw made */
            } else {
                thread = 0;   /* unknown: an outside process (see above) */
                if (holder == tgid || proc_guarded(holder)) known = 0;
            }
            if (holder != 0 && (options & KB_DUPLICATE_CLOSE_SOURCE) != 0) bpf_map_delete_elem(&kb_ohandles, &id);
        }
        if ((object == 0 && !guarded) || target == 0) return 0;   /* nothing to decide; or a close */
        dest = process_target(tgid, target);
        if (dest == 0) return 0;
        access = (options & KB_DUPLICATE_SAME_ACCESS) != 0 ? known : s->request[6];
    } else {
        return 0;
    }
    if (object != 0 || req == KB_REQ_GET_NEXT_PROCESS || req == KB_REQ_NEW_PROCESS) {
        /* The reply's handle, in Dest's table, reaches Object (0: one kfilter cannot name). */
        s->pending.req = req;
        s->pending.owner = dest;
        s->pending.object.tgid = object;
        s->pending.object.thread = thread;
        s->pending.object.access = access;
        s->pending.object.pid = childPid;   /* the copy still reaches that child once it starts */
        s->pending.key.len = 0;
        bpf_map_update_elem(&kb_pending, &ownerTid, &s->pending, BPF_ANY);
    }
    /* A new thread's rights come from the process handle it is made with (CREATE_THREAD);
     * a new process is decided when it execs. What either reaches past that (kb_wine_variant: the process of
     * new_thread's handle, new_process's child image) is decided once the reply's handle is kept for. */
    if (req == KB_REQ_NEW_THREAD || req == KB_REQ_NEW_PROCESS) return guarded ? wine_targets(c, s, req, joined) : 0;
    if (!c->enabled || c->mode == KFILTER_MODE_OFF) return 0;
    /* The family's own new child before it starts: new_process gave its creator full access already, so a
     * copy within the family adds nothing (Chromium copies the handle before resuming the child). */
    if (childPid != 0 && guarded && family_member(dest)) return 0;
    /* A process that has exited (kfilter learns these ids from Wine's replies only, and forgets a process
     * when it exits): a handle to it reaches nothing to read, write or inject into. Chromium copies its
     * handles to exited children (PROCESS_QUERY_INFORMATION) to read their exit codes. */
    if (object != 0 && object != tgid && !bpf_map_lookup_elem(&kb_procs, &object)) return 0;
    int strict = (c->flags & KFILTER_CFG_DEFAULT_DENY) != 0;
    /* An unknown process or thread counts as outside: decided, not waved through. */
    int objectIn = object != 0 && (object == tgid ? guarded : family_member(object));
    int destIn = dest == tgid ? guarded : family_member(dest);
    __u32 target, outside;
    if (req == KB_REQ_DUP_HANDLE) {
        int sourceIn = guarded || family_member(holder);
        /* All inside the family: a peer decision when the copy reaches another program. */
        if (guarded && objectIn && sourceIn && destIn)
            return object == dest ? 0 : peer_handle(c, s, object, thread, handle_access(access, thread));
        if (objectIn == sourceIn && sourceIn == destIn) return 0;   /* all outside */
        if (objectIn && !destIn) {
            target = thread ? KFILTER_TARGET_THREAD_HANDLE : KFILTER_TARGET_HANDLE;   /* an outside process receives the client */
            outside = dest;
        } else if (!objectIn && destIn) {
            target = thread ? KFILTER_TARGET_THREAD_OPEN : KFILTER_TARGET_OPEN;       /* the client receives an outside one */
            outside = object;
        } else {
            target = KFILTER_TARGET_PROCESS;         /* object.c: no rule grants this crossing */
            outside = object;
        }
    } else if (!guarded) {
        /* An outside program opening the client or its thread: decided in strict mode only, as on Windows. */
        if (!objectIn || !strict) return 0;
        target = thread ? KFILTER_TARGET_THREAD_HANDLE : KFILTER_TARGET_HANDLE;
        outside = tgid;
    } else {
        if (objectIn) return object == tgid ? 0 : peer_handle(c, s, object, thread, handle_access(access, thread));
        target = thread ? KFILTER_TARGET_THREAD_OPEN : KFILTER_TARGET_OPEN;
        outside = object;
    }
    if ((c->flags & KFILTER_CFG_BLOCK_PROCESS_MEMORY) == 0) return 0;
    __u32 removed = handle_access(access, thread) &
                    (strict ? 0xFFFFFFFFu : thread ? KB_THREAD_DANGEROUS : KB_PROCESS_DANGEROUS);
    if (removed == 0) return 0;
    s->htarget = target;
    s->hremoved = removed;
    s->haccess = access;
    program_path(s, 0, outside);
    if (outside == 0 && (req == KB_REQ_DUP_HANDLE || unknownPid)) unknown_name(s, unknownPid, unknownValue);
    else if (s->failed && outside != 0) unknown_name(s, 1, outside);   /* a process with no image kfilter knows */
    return KB_HANDLE_DECIDE;
}

/*
 * The handle decision kb_handle_request prepared (KfObjectPre): every right it would strip
 * needs an open, handle, thread-open or thread-handle rule's grant. Wine cannot be handed a handle with
 * fewer rights than it asked for, so a refusal fails the whole request (as a refused registry
 * request does). Returns 0 or -EPERM. A peer, thread-peer or system decision a Wine request made is
 * decided as its rules say; on memory, htarget's top byte carries KB_ADDRESSED, KB_ADDRESS_ONLY and KB_LEARNED, and
 * on \@unknown KB_NAMED_ONLY.
 */
__noinline int kb_handle_decide(void)
{
    struct kb_cfg* c = kb_cfg_get();
    struct kb_scratch* s = scratch();
    if (!c || !s) return 0;
    __u32 target = s->htarget & 0xFFFFFF;
    if (target == KFILTER_TARGET_PEER || target == KFILTER_TARGET_THREAD_PEER || target == KFILTER_TARGET_SYSTEM) {
        __u32 listed = 1 | (s->htarget >> 24 & (KB_ADDRESSED | KB_ADDRESS_ONLY | KB_NAMED_ONLY));
        if (kb_decide_global(target, s->hremoved, 0, listed) != 0) return -EPERM;
        struct kb_access* a = (s->htarget >> 24 & KB_LEARNED) != 0
                                  ? bpf_task_storage_get(&kb_accesses, bpf_get_current_task_btf(), 0, 0) : 0;
        if (!a || a->target == 0) return 0;
        /* A handle a get_process_info reply named: addr= rules alone decide again, on that program. */
        program_path(s, 0, a->target);
        return kb_decide_global(s->htarget & 0xFFFFFF, s->hremoved, 0, 1 | KB_ADDRESSED | KB_ADDRESS_ONLY);
    }
    __u32 removed = s->hremoved, granted = 0;
    s->outside_rule = 0;
    if (s->htarget != KFILTER_TARGET_PROCESS) {
        __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        granted = kb_outside_rights(s->htarget, removed, uid == 0) & removed;
    }
    __u32 action = granted == removed ? KFilterActionAllow : KFilterActionDeny;
    __u32 process = s->htarget == KFILTER_TARGET_OPEN || s->htarget == KFILTER_TARGET_HANDLE;
    __u32 flags = process && (removed & KB_PROCESS_MEMORY_RIGHTS) != 0 ? KFILTER_EVENT_FLAG_MEMORY_READ : 0;
    return verdict(s->htarget, action, flags, s->haccess, s->outside_rule, removed, c->mode);
}

/* The current Wine process's loader is under one of the decoded Wine installs. */
__noinline int kb_wine_decodable(void)
{
    struct kb_cfg* c = kb_cfg_get();
    struct kb_scratch* s = scratch();
    if (!c || !s) return 0;
    s->failed = 0;
    walk_exe(bpf_get_current_task_btf());
    if (s->failed) return 0;
    for (__u32 n = 0; n < KB_WINE_DIRS; n++) {
        if (n >= c->wine_dir_count) break;
        __u32 len = c->wine_dir_len[n];
        if (len == 0 || len >= KB_WINE_DIR || len > s->len) continue;
        int same = 1;
        for (__u32 i = 0; i < KB_WINE_DIR; i++) {
            if (i >= len) break;
            if (s->path[i] != c->wine_dirs[n][i]) {
                same = 0;
                break;
            }
        }
        if (same) return 1;
    }
    return 0;
}

#define KB_W_NAMED 0    /* no row of its own: /system/wine/<request>, decided only where a rule names it (KB_WINE_ROOT) */
#define KB_W_HANDLE 1   /* +12 is a process or thread handle: another protected program's (peer), or its own (system) */
#define KB_W_PLAIN 2    /* system */
#define KB_W_CREATE 3   /* system, when its objattr names the object */
#define KB_W_OPEN 4     /* system; the data is the name */
#define KB_W_EITHER 5   /* as KB_W_HANDLE, but its own process by pseudo handle or by a handle kfilter did not see made is system too */

/* The requests kfilter decided before every request was, by number (a direct index, rodata): what each decides. */
struct kb_wreq {
    __u32 kind;
    __u32 right;         /* of the system decision */
    __u32 access;        /* the process or thread access a peer decision asks for */
};

#define KB_W(req, kind, right, access) [req] = {kind, right, access}
static const struct kb_wreq kb_wreqs[KB_REQ_COUNT] = {
    KB_W(KB_REQ_TERMINATE_PROCESS, KB_W_HANDLE, KFILTER_RIGHT_WRITE, 0x1),
    KB_W(KB_REQ_TERMINATE_THREAD, KB_W_HANDLE, KFILTER_RIGHT_WRITE, 0x1),
    KB_W(KB_REQ_GET_PROCESS_INFO, KB_W_HANDLE, KFILTER_RIGHT_QUERY, 0x1000),
    KB_W(KB_REQ_GET_PROCESS_DEBUG_INFO, KB_W_HANDLE, KFILTER_RIGHT_QUERY, 0x1000),
    KB_W(KB_REQ_GET_PROCESS_IMAGE_NAME, KB_W_HANDLE, KFILTER_RIGHT_QUERY, 0x1000),
    KB_W(KB_REQ_GET_PROCESS_VM_COUNTERS, KB_W_HANDLE, KFILTER_RIGHT_QUERY, 0x1000),
    KB_W(KB_REQ_SET_PROCESS_INFO, KB_W_HANDLE, KFILTER_RIGHT_WRITE, 0x200),
    KB_W(KB_REQ_GET_MAPPING_FILENAME, KB_W_HANDLE, KFILTER_RIGHT_QUERY, 0x400),
    KB_W(KB_REQ_GET_IMAGE_VIEW_INFO, KB_W_HANDLE, KFILTER_RIGHT_QUERY, 0x400),
    KB_W(KB_REQ_SET_THREAD_INFO, KB_W_PLAIN, KFILTER_RIGHT_WRITE, 0),
    KB_W(KB_REQ_SUSPEND_THREAD, KB_W_HANDLE, KFILTER_RIGHT_WRITE, 0x2),
    KB_W(KB_REQ_RESUME_THREAD, KB_W_HANDLE, KFILTER_RIGHT_WRITE, 0x2),
    KB_W(KB_REQ_QUEUE_APC, KB_W_HANDLE, KFILTER_RIGHT_WRITE, 0),
    KB_W(KB_REQ_CREATE_EVENT, KB_W_CREATE, KFILTER_RIGHT_CREATE, 0),
    KB_W(KB_REQ_OPEN_EVENT, KB_W_OPEN, KFILTER_RIGHT_QUERY, 0),
    KB_W(KB_REQ_CREATE_MUTEX, KB_W_CREATE, KFILTER_RIGHT_CREATE, 0),
    KB_W(KB_REQ_OPEN_MUTEX, KB_W_OPEN, KFILTER_RIGHT_QUERY, 0),
    KB_W(KB_REQ_CREATE_SEMAPHORE, KB_W_CREATE, KFILTER_RIGHT_CREATE, 0),
    KB_W(KB_REQ_OPEN_SEMAPHORE, KB_W_OPEN, KFILTER_RIGHT_QUERY, 0),
    KB_W(KB_REQ_CREATE_MAPPING, KB_W_CREATE, KFILTER_RIGHT_CREATE, 0),
    KB_W(KB_REQ_OPEN_MAPPING, KB_W_OPEN, KFILTER_RIGHT_QUERY, 0),
    KB_W(KB_REQ_LIST_PROCESSES, KB_W_PLAIN, KFILTER_RIGHT_QUERY, 0),
    KB_W(KB_REQ_DEBUG_PROCESS, KB_W_HANDLE, KFILTER_RIGHT_WRITE, 0x800),
    KB_W(KB_REQ_READ_PROCESS_MEMORY, KB_W_HANDLE, KFILTER_RIGHT_QUERY, 0x10),
    KB_W(KB_REQ_WRITE_PROCESS_MEMORY, KB_W_HANDLE, KFILTER_RIGHT_WRITE, 0x28),
    KB_W(KB_REQ_GET_THREAD_CONTEXT, KB_W_HANDLE, KFILTER_RIGHT_QUERY, 0x8),
    KB_W(KB_REQ_SET_THREAD_CONTEXT, KB_W_HANDLE, KFILTER_RIGHT_WRITE, 0x10),
    KB_W(KB_REQ_GET_WINDOW_LIST, KB_W_PLAIN, KFILTER_RIGHT_QUERY, 0),
    KB_W(KB_REQ_GET_WINDOW_TREE, KB_W_PLAIN, KFILTER_RIGHT_QUERY, 0),
    KB_W(KB_REQ_GET_WINDOW_TEXT, KB_W_PLAIN, KFILTER_RIGHT_QUERY, 0),
    KB_W(KB_REQ_OPEN_WINSTATION, KB_W_OPEN, KFILTER_RIGHT_QUERY, 0),
    KB_W(KB_REQ_OPEN_DESKTOP, KB_W_OPEN, KFILTER_RIGHT_QUERY, 0),
    KB_W(KB_REQ_OPEN_TOKEN, KB_W_EITHER, KFILTER_RIGHT_QUERY, 0x400),
    KB_W(KB_REQ_ADJUST_TOKEN_PRIVILEGES, KB_W_PLAIN, KFILTER_RIGHT_WRITE, 0),
    KB_W(KB_REQ_GET_SYSTEM_HANDLES, KB_W_PLAIN, KFILTER_RIGHT_QUERY, 0),
    KB_W(KB_REQ_GET_TCP_CONNECTIONS, KB_W_PLAIN, KFILTER_RIGHT_QUERY, 0),
    KB_W(KB_REQ_GET_UDP_ENDPOINTS, KB_W_PLAIN, KFILTER_RIGHT_QUERY, 0),
    KB_W(KB_REQ_CREATE_DIRECTORY, KB_W_CREATE, KFILTER_RIGHT_CREATE, 0),
    KB_W(KB_REQ_OPEN_DIRECTORY, KB_W_OPEN, KFILTER_RIGHT_QUERY, 0),
    KB_W(KB_REQ_GET_DIRECTORY_ENTRIES, KB_W_PLAIN, KFILTER_RIGHT_QUERY, 0),
    KB_W(KB_REQ_CREATE_SYMLINK, KB_W_CREATE, KFILTER_RIGHT_CREATE, 0),
    KB_W(KB_REQ_OPEN_SYMLINK, KB_W_OPEN, KFILTER_RIGHT_QUERY, 0),
    KB_W(KB_REQ_QUERY_SYMLINK, KB_W_PLAIN, KFILTER_RIGHT_QUERY, 0),
    KB_W(KB_REQ_SUSPEND_PROCESS, KB_W_HANDLE, KFILTER_RIGHT_WRITE, 0x800),
    KB_W(KB_REQ_RESUME_PROCESS, KB_W_HANDLE, KFILTER_RIGHT_WRITE, 0x800),
};

/* Every request's name and the right of its decision as /system/wine/<name> (kfilter_bpf.h KB_WINE_REQUESTS). */
struct kb_wname {
    __u32 len;
    __u32 right;
    char name[32];       /* get_window_children_from_point, the longest, has 30 */
};

#define KB_WQ KFILTER_RIGHT_QUERY
#define KB_WC KFILTER_RIGHT_CREATE
#define KB_WW KFILTER_RIGHT_WRITE
#define KB_WNAME(name, right) {sizeof(#name) - 1, KB_W##right, #name},
static const struct kb_wname kb_wnames[] = {KB_WINE_REQUESTS(KB_WNAME)};
_Static_assert(sizeof(kb_wnames) / sizeof(kb_wnames[0]) == KB_REQ_COUNT, "a name for every request");

/* Some system rule names Req past /system/wine/ (kb_wnamed). */
static __always_inline int named_request(__u32 req)
{
    __u32 word = req / 64;
    __u64* bits = bpf_map_lookup_elem(&kb_wnamed, &word);
    return bits && ((*bits >> (req % 64)) & 1) != 0;
}

/* Req (< KB_REQ_COUNT) has a row of its own, or a rule names it: kb_wine_query may decide it. */
static __always_inline int wine_decided(__u32 req)
{
    return kb_wreqs[req].kind != KB_W_NAMED || req == KB_REQ_GET_THREAD_INFO || named_request(req);
}

/* winedevice's kernel objects (kb_kobjects): set_kernel_object_ptr (manager, handle, user_ptr) ties a pointer to the
 * object of one of its handles, and get_kernel_object_handle (manager, user_ptr, access) makes a new handle from it,
 * which reaches that process or thread when the first handle did (its reply is recorded in kb_learnt, for addr= rules). */
__noinline int kb_kernel_object(__u32 tgid, __u32 ownerTid)
{
    struct kb_scratch* s = scratch();
    if (!s) return 0;
    struct kb_kobject_id id = {tgid, 0, 0};
    if (s->request[0] == KB_REQ_SET_KERNEL_OBJECT_PTR) {
        id.ptr = (__u64)s->request[7] << 32 | s->request[6];   /* user_ptr@0x18 */
        struct kb_hkey_id handle = {tgid, s->request[4]};      /* handle@0x10 */
        struct kb_ohandle* record = bpf_map_lookup_elem(&kb_ohandles, &handle);
        if (record) bpf_map_update_elem(&kb_kobjects, &id, record, BPF_ANY);
        else bpf_map_delete_elem(&kb_kobjects, &id);
        return 0;
    }
    id.ptr = (__u64)s->request[5] << 32 | s->request[4];       /* user_ptr@0x10 */
    struct kb_ohandle* record = bpf_map_lookup_elem(&kb_kobjects, &id);
    if (!record) return 0;
    s->pending.req = KB_REQ_GET_KERNEL_OBJECT_HANDLE;
    s->pending.owner = tgid;
    s->pending.object = *record;
    s->pending.object.access = s->request[6];                  /* access@0x18 */
    s->pending.key.len = 0;
    bpf_map_update_elem(&kb_pending, &ownerTid, &s->pending, BPF_ANY);
    return 0;
}

/* Req's reply names a new handle to no process or thread (object_maker): kept pending for wineserver_reply, which
 * records it in kb_xhandles; what follows may still decide the request. */
static __always_inline void expect_object(__u32 req, __u32 tgid, __u32 ownerTid)
{
    struct kb_scratch* s = scratch();
    if (!s || !object_maker(req)) return;
    s->pending.req = req;
    s->pending.owner = tgid;
    s->pending.object.tgid = 0;
    s->pending.object.thread = KB_OBJECT_OTHER;
    s->pending.key.len = 0;
    bpf_map_update_elem(&kb_pending, &ownerTid, &s->pending, BPF_ANY);
}

/* Requests whose data a decoder reads (a name, an objattr, an apc_call, contexts, a child's startup info, privileges,
 * raw input devices): kb_request_data joins it. */
static __always_inline int reads_data(__u32 req)
{
    switch (req) {
    case KB_REQ_NEW_PROCESS: case KB_REQ_ADJUST_TOKEN_PRIVILEGES: case KB_REQ_UPDATE_RAWINPUT_DEVICES:
    case KB_REQ_QUEUE_APC: case KB_REQ_CREATE_EVENT: case KB_REQ_OPEN_EVENT: case KB_REQ_CREATE_MUTEX:
    case KB_REQ_OPEN_MUTEX: case KB_REQ_CREATE_SEMAPHORE: case KB_REQ_OPEN_SEMAPHORE: case KB_REQ_OPEN_FILE_OBJECT:
    case KB_REQ_CREATE_MAPPING: case KB_REQ_OPEN_MAPPING: case KB_REQ_CREATE_KEY: case KB_REQ_OPEN_KEY:
    case KB_REQ_SET_KEY_VALUE: case KB_REQ_GET_KEY_VALUE: case KB_REQ_DELETE_KEY_VALUE: case KB_REQ_LOAD_REGISTRY:
    case KB_REQ_UNLOAD_REGISTRY: case KB_REQ_RENAME_KEY: case KB_REQ_SET_THREAD_CONTEXT: case KB_REQ_CREATE_NAMED_PIPE:
    case KB_REQ_OPEN_WINSTATION: case KB_REQ_OPEN_DESKTOP: case KB_REQ_CREATE_DIRECTORY: case KB_REQ_OPEN_DIRECTORY:
    case KB_REQ_CREATE_SYMLINK: case KB_REQ_OPEN_SYMLINK:
        return 1;
    default:
        return 0;
    }
}

/* One block of the chunk kb_request_data is joining, or the next chunk: the task's kb_reqdata holds the state. */
static long join_step(__u32 index, void* unused)
{
    struct kb_reqdata* d = bpf_task_storage_get(&kb_reqdata, bpf_get_current_task_btf(), 0, 0);
    if (!d) return 1;
    __u32 at = d->at;
    if (d->done >= d->length || d->stop || at >= KB_REQ_DATA) {
        __u32 chunk = d->chunk + 1;
        if (d->stop || at >= KB_REQ_DATA || chunk >= d->count || chunk > KB_REQ_CHUNKS) return 1;
        __u64 vector[2] = {};   /* base, length */
        if (d->compat) {
            __u32 small[2] = {};
            if (bpf_probe_read_user(small, sizeof(small), (void*)(d->iov + chunk * 8)) != 0) return 1;
            vector[0] = small[0];
            vector[1] = small[1];
        } else if (bpf_probe_read_user(vector, sizeof(vector), (void*)(d->iov + chunk * 16)) != 0) {
            return 1;
        }
        d->chunk = chunk;
        d->base = vector[0];
        d->length = vector[1];
        d->done = 0;
        return 0;
    }
    __u64 rest = d->length - d->done;
    if (d->skip != 0) {   /* before the bytes kb_request_at joins */
        __u32 pass = rest < d->skip ? (__u32)rest : d->skip;
        d->skip -= pass;
        d->done += pass;
        return 0;
    }
    __u32 take = rest < KB_REQ_BLOCK ? (__u32)rest : KB_REQ_BLOCK;
    if (take > KB_REQ_DATA - at) take = KB_REQ_DATA - at;
    if (take == 0 || take > KB_REQ_BLOCK) return 1;
    if (bpf_probe_read_user(&d->data[at & (KB_REQ_DATA - 1)], take, (void*)(d->base + d->done)) != 0) {
        d->stop = 1;   /* a page it could not read: what came before stays joined */
        return 0;
    }
    d->at = at + take;
    d->done += take;
    return 0;
}

/* Joins the chunks of D's request from byte Skip of its data: the bytes joined. */
static __always_inline int join_from(struct kb_reqdata* d, __u32 skip)
{
    d->chunk = 0;
    d->base = 0;
    d->length = 0;
    d->done = 0;
    d->at = 0;
    d->stop = 0;
    d->skip = skip;
    bpf_loop(3 * KB_REQ_CHUNKS + KB_REQ_DATA / KB_REQ_BLOCK + 1, join_step, 0, 0);   /* each chunk, its skip, each block */
    return d->at <= KB_REQ_DATA ? (int)d->at : 0;
}

/*
 * The data of a request writev (iovecs 1 to Count - 1 at Iov, ia32's 8-byte ones when Compat) as wineserver reads it:
 * the chunks in order, so a name split across them is decoded whole. With Join their first KB_REQ_DATA bytes are
 * joined into the task's kb_reqdata (a chunk that cannot be read ends what is joined). Returns the bytes joined, or -1
 * when the chunks do not add up to Size, the header's request_size (Wine never writes that; wineserver would read
 * other bytes than were decided).
 */
__noinline int kb_request_data(__u64 iov, __u32 count, __u32 compat, __u32 size, __u32 join)
{
    __u64 total = 0;
    for (__u32 i = 1; i <= KB_REQ_CHUNKS; i++) {
        if (i >= count) break;
        __u64 vector[2] = {};   /* base, length */
        if (compat) {
            __u32 small[2] = {};
            if (bpf_probe_read_user(small, sizeof(small), (void*)(iov + i * 8)) != 0) return -1;
            vector[1] = small[1];
        } else if (bpf_probe_read_user(vector, sizeof(vector), (void*)(iov + i * 16)) != 0) {
            return -1;
        }
        total += vector[1];
    }
    if (total != size) return -1;
    struct kb_reqdata* d = join ? bpf_task_storage_get(&kb_reqdata, bpf_get_current_task_btf(), 0,
                                                       BPF_LOCAL_STORAGE_GET_F_CREATE) : 0;
    if (!d) return 0;
    d->iov = iov;
    d->count = count;
    d->compat = compat;
    return join_from(d, 0);
}

/* The request kb_request_data joined, joined again from byte At of its data (its first KB_REQ_DATA bytes are gone
 * then): the address of what was joined when that is at least Bytes, else 0. */
__noinline __u64 kb_request_at(__u32 at, __u32 bytes)
{
    struct kb_reqdata* d = bpf_task_storage_get(&kb_reqdata, bpf_get_current_task_btf(), 0, 0);
    if (!d || bytes > KB_REQ_DATA) return 0;
    return join_from(d, at) >= (int)bytes ? address_of(d->data) : 0;
}

/*
 * A Wine thread writes to a pipe. A request to wineserver on a thread's request pipe
 * (registered the first time from the TEB's request_fd) names the process, keeps registry
 * handles' names and prepares a protected program's registry requests for the decision.
 * A protected program may write a registered request pipe only as Wine does: its own, one
 * whole request header per write, data chunks that add up to its request_size; anything else
 * could reach wineserver undecided and is refused. Returns 0, KB_REQ_REFUSE, KB_REQ_RAW, or
 * KB_REG_*, KB_HANDLE_DECIDE or KB_SYSTEM_DECIDE for kb_file_permission.
 */
__noinline int kb_wine_request(__u64 inodeAddress, __u32 second)
{
    /* Runs with or without a policy: pipes, names and key handles are learnt all along;
     * only the decisions (kb_decide_global, admission) look at the mode. */
    struct kb_cfg* c = kb_cfg_get();
    if (!c) return 0;
    struct task_struct* task = bpf_get_current_task_btf();
    struct kb_task* state = task_state(task);
    struct pt_regs* regs = (struct pt_regs*)bpf_task_pt_regs(task);
    if (!state || !regs) return 0;
    __u32 tgid = current_tgid(), tid = current_tid();
    struct kb_proc* proc = proc_entry(tgid);
    if (!proc) return 0;
    if (!proc->checked) {
        proc->decode = kb_wine_decodable();
        /* Until kfilterd's first policy names the Wine install, ask again: a program already
         * running when kfilterd starts would otherwise never be decoded. */
        proc->checked = c->wine_dir_count != 0;
    }
    if (kb_wine_name(tgid) != 0) return KB_REQ_REFUSE;
    int guarded = task_protected(task, state);
    struct kb_pipe* pipe = bpf_map_lookup_elem(&kb_pipes, &inodeAddress);
    /* A protected task that exec'd a program other than Wine's, writing a request pipe it inherited. */
    if (!proc->decode) return guarded && pipe && pipe->kind == KB_PIPE_REQUEST ? KB_REQ_RAW : 0;
    __u32 ownerTid = tid;
    if (pipe) {
        if (pipe->kind != KB_PIPE_REQUEST) return 0;
        /* Someone else's request pipe: wineserver would act as that process. */
        if (pipe->tgid != tgid) return guarded ? KB_REQ_RAW : 0;
        ownerTid = pipe->tid;
        /* Any write here is a new request (decoded or not): what was pending got no reply,
         * and a reply to an undecoded request must not be read as the pending one's. Not when the hook comes back
         * (Second): the first pass ended the last request, and kept what this one's reply names (learn_handle). */
        if (!second && bpf_map_lookup_elem(&kb_pending, &ownerTid)) bpf_map_delete_elem(&kb_pending, &ownerTid);
    }
    __u32 compat = (BPF_CORE_READ(task, thread_info.status) & TS_COMPAT) != 0;
    long nr = BPF_CORE_READ(regs, orig_ax);
    __u64 fd, buffer, count;
    int vector, plain;
    if (compat) {
        fd = BPF_CORE_READ(regs, bx);
        buffer = BPF_CORE_READ(regs, cx) & 0xFFFFFFFFull;
        count = BPF_CORE_READ(regs, dx);
        vector = nr == 146;
        plain = nr == 4;
    } else {
        fd = BPF_CORE_READ(regs, di);
        buffer = BPF_CORE_READ(regs, si);
        count = BPF_CORE_READ(regs, dx);
        vector = nr == 20;
        plain = nr == 1;
    }
#ifdef KB_TEST_BENCH
    struct kb_bench_io* io = bpf_map_lookup_elem(&kb_bench_ios, &(__u32){0});
    if (io && io->active) {   /* the bench's write (kb_bench_pipe), not this task's syscall */
        compat = io->compat;
        buffer = io->buffer;
        count = io->count;
        vector = io->vector;
        plain = !io->vector;
    }
#endif
    int refuse = pipe && guarded;   /* a malformed write to a registered request pipe */
    if (!vector && !plain) return refuse ? KB_REQ_RAW : 0;
    if (!pipe && plain && count == 64) {
        /* A thread's first request names it and its reply fd, before its TEB is in use:
         * init_first_thread (unix_pid, unix_tid, debug_level, reply_fd) and init_thread
         * (unix_tid, reply_fd). Wine's start-up opens its first keys right after. */
        __u32 first[8] = {};
        if (bpf_probe_read_user(first, sizeof(first), (void*)buffer) == 0 && first[1] == 0 &&
            ((first[0] == KB_REQ_INIT_FIRST_THREAD && first[3] == tgid && first[4] == tid) ||
             (first[0] == KB_REQ_INIT_THREAD && first[3] == tid))) {
            __s32 replyFd = (__s32)(first[0] == KB_REQ_INIT_FIRST_THREAD ? first[6] : first[4]);
            bpf_map_delete_elem(&kb_pending, &tid);
            /* The process's ids come from wineserver's init_first_thread reply. Only the first
             * one is believed: Wine sends it before any program code runs, so a later one is
             * written by the program (a thread's ids come from its creator's new_thread reply). */
            if (first[0] == KB_REQ_INIT_FIRST_THREAD && !proc->ids) {
                struct kb_scratch* s = scratch();
                if (s) {
                    proc->ids = 1;
                    s->pending.req = KB_REQ_INIT_FIRST_THREAD;
                    s->pending.owner = tgid;
                    s->pending.key.len = 0;
                    bpf_map_update_elem(&kb_pending, &tid, &s->pending, BPF_ANY);
                }
            }
            struct kb_pipe registered = {tgid, tid, KB_PIPE_REQUEST, 0};
            bpf_map_update_elem(&kb_pipes, &inodeAddress, &registered, BPF_ANY);
            struct file* reply = fd_file(task, replyFd);
            if (reply) {
                __u64 replyInode = pipe_key(BPF_CORE_READ(reply, f_inode));
                registered.kind = KB_PIPE_REPLY;
                if (replyInode) bpf_map_update_elem(&kb_pipes, &replyInode, &registered, BPF_ANY);
            }
            /* A new thread of a protected program where a rule names init_thread (init_first_thread is not decided:
             * its reply names the process for kfilter, and an allowed decision would read it again as a new request). */
            if (first[0] == KB_REQ_INIT_THREAD && guarded && !second && named_request(KB_REQ_INIT_THREAD)) {
                struct kb_scratch* s = reset_for(tgid, 0);
                if (!s) return 0;
                for (int i = 0; i < 16; i++) s->request[i] = i < 8 ? first[i] : 0;
                return kb_wine_query(tgid, tid, 0, 0);
            }
            return 0;
        }
    }
    __u64 teb = 0;
    __s32 fds[2] = {-1, -1};   /* ntdll_thread_data request_fd, reply_fd */
    if (!pipe) {
        teb = wine_teb(task, compat);
        if (teb == 0) return 0;
        if (bpf_probe_read_user(fds, sizeof(fds), (void*)(teb + (compat ? 0x220 : 0x384))) != 0) return 0;
        if (fds[0] < 0 || (__s32)fd != fds[0]) return 0;
    }
    __u64 header = buffer, data = 0;
    __u32 size = 0;
    if (vector) {
        if (count < 2 || count > 1 + KB_REQ_CHUNKS) return refuse ? KB_REQ_RAW : 0;
        __u64 first[2] = {};   /* the header's iovec */
        if (compat) {
            __u32 small[2] = {};
            if (bpf_probe_read_user(small, sizeof(small), (void*)buffer) != 0) return refuse ? KB_REQ_RAW : 0;
            first[0] = small[0];
            first[1] = small[1];
        } else if (bpf_probe_read_user(first, sizeof(first), (void*)buffer) != 0) {
            return refuse ? KB_REQ_RAW : 0;
        }
        if (first[1] != 64) return refuse ? KB_REQ_RAW : 0;   /* a resumed partial write */
        header = first[0];
    } else if (count != 64) {
        return refuse ? KB_REQ_RAW : 0;
    }
    __u32 request[16] = {};
    if (bpf_probe_read_user(request, sizeof(request), (void*)header) != 0) return refuse ? KB_REQ_RAW : 0;
    __u32 req = request[0];
    if (req >= KB_REQ_COUNT || vector != (request[1] != 0)) return refuse ? KB_REQ_RAW : 0;
    if (vector) {
        /* What wineserver reads: every chunk, joined (a name split across them is decided whole). One it could not
         * read (or no memory to join into) leaves the decoders unreadable data, as an unreadable chunk did before. */
        /* A protected program's file name, write and ioctl data too while a keyed rule can name them. */
        __u32 join = reads_data(req) || (guarded && (c->targets & KB_TARGET_KEYED) != 0 &&
                                         (req == KB_REQ_CREATE_FILE || req == KB_REQ_WRITE || req == KB_REQ_IOCTL));
        /* An unprotected program's chunks are checked only when joined (nothing to refuse). */
        int joined = guarded || join ? kb_request_data(buffer, (__u32)count, compat, request[1], join) : 0;
        if (joined < 0) return refuse ? KB_REQ_RAW : 0;
        size = request[1] < KB_REQ_DATA ? request[1] : KB_REQ_DATA;
        struct kb_reqdata* d = join && (__u32)joined == size ? bpf_task_storage_get(&kb_reqdata, task, 0, 0) : 0;
        data = d ? address_of(d->data) : 0;
    }
    if (!pipe) {
        struct kb_pipe registered = {tgid, tid, KB_PIPE_REQUEST, 0};
        bpf_map_update_elem(&kb_pipes, &inodeAddress, &registered, BPF_ANY);
        struct file* reply = fd_file(task, fds[1]);
        if (reply) {
            __u64 replyInode = pipe_key(BPF_CORE_READ(reply, f_inode));
            registered.kind = KB_PIPE_REPLY;
            if (replyInode) bpf_map_update_elem(&kb_pipes, &replyInode, &registered, BPF_ANY);
        }
        state->pipes = 1;
    }
    /* A new request: whatever was pending for this thread got no reply (not again in the second pass, above). */
    if (!second && bpf_map_lookup_elem(&kb_pending, &ownerTid)) bpf_map_delete_elem(&kb_pending, &ownerTid);
    expect_object(req, tgid, ownerTid);
    /* The request's own decision first, so a refused one leaves nothing recorded; not again when the hook comes back
     * after an allowed system decision (Second). Most requests pass on one lookup (wine_decided). */
    if (!second && guarded && wine_decided(req) &&
        (c->targets & (KFILTER_TARGET_PEER | KFILTER_TARGET_THREAD_PEER | KFILTER_TARGET_SYSTEM)) != 0) {
        struct kb_scratch* s = reset_for(tgid, 0);
        if (!s) return 0;
        for (int i = 0; i < 16; i++) s->request[i] = request[i];
        int code = kb_wine_query(tgid, ownerTid, data, size);
        if (code != 0) return code;
    }
    image_mapped(req, tgid);
    if (req == KB_REQ_CLOSE_HANDLE) {
        struct kb_hkey_id id = {tgid, request[3]};
        bpf_map_delete_elem(&kb_hkeys, &id);
        bpf_map_delete_elem(&kb_ohandles, &id);
        bpf_map_delete_elem(&kb_xhandles, &id);
        bpf_map_delete_elem(&kb_learnt, &id);
        bpf_map_delete_elem(&kb_fnames, &id);
        bpf_map_delete_elem(&kb_rpcs, &id);
        return 0;
    }
    if (req == KB_REQ_GET_APC_RESULT) {   /* its reply may name the copy an APC_DUP_HANDLE made here */
        struct kb_scratch* s = scratch();
        if (!s) return 0;
        s->pending.req = req;
        s->pending.owner = tgid;
        s->pending.object.thread = 0;
        s->pending.key.len = 0;
        bpf_map_update_elem(&kb_pending, &ownerTid, &s->pending, BPF_ANY);
        return 0;
    }
    if (req == KB_REQ_GET_NEXT_DEVICE_REQUEST) {
        /* winedevice finished its last device request: it serves no one until the reply. */
        __u32 none = 0;
        bpf_map_update_elem(&kb_serving, &ownerTid, &none, BPF_ANY);
        struct kb_scratch* s = scratch();
        if (!s) return 0;
        s->pending.req = req;
        s->pending.key.len = 0;
        bpf_map_update_elem(&kb_pending, &ownerTid, &s->pending, BPF_ANY);
        return 0;
    }
    if (req == KB_REQ_SET_KERNEL_OBJECT_PTR || req == KB_REQ_GET_KERNEL_OBJECT_HANDLE) {
        struct kb_scratch* s = reset_for(tgid, 0);
        if (!s) return 0;
        for (int i = 0; i < 16; i++) s->request[i] = request[i];
        kb_kernel_object(tgid, ownerTid);
        return 0;
    }
    /* Windows' owners for every decoded Wine process (a window rule meets windows made before it); a protected
     * program's create_file names while a keyed rule can name them. */
    if (req == KB_REQ_CREATE_WINDOW || req == KB_REQ_GET_DESKTOP_WINDOW ||
        (req == KB_REQ_CREATE_FILE && guarded && (c->targets & KB_TARGET_KEYED) != 0)) {
        struct kb_scratch* s = reset_for(tgid, 0);
        if (!s) return 0;
        for (int i = 0; i < 16; i++) s->request[i] = request[i];
        kb_wine_note(tgid, ownerTid, data, size);
        return 0;
    }
    if (req == KB_REQ_OPEN_PROCESS || req == KB_REQ_OPEN_THREAD || req == KB_REQ_DUP_HANDLE ||
        req == KB_REQ_GET_NEXT_THREAD || req == KB_REQ_GET_NEXT_PROCESS || req == KB_REQ_NEW_THREAD ||
        req == KB_REQ_NEW_PROCESS) {
        /* Followed for every decoded Wine process: an outside one may open the client's threads. */
        struct kb_scratch* s = reset_for(tgid, 0);
        if (!s) return 0;
        for (int i = 0; i < 16; i++) s->request[i] = request[i];
        return kb_handle_request(tgid, ownerTid, guarded, data != 0 ? size : 0);
    }
    /* Another program's window, thread or process (by a handle at any offset), and keyed decisions (kb_wine_decide).
     * None of these requests is one of the volume, NT object and registry requests below. */
    if (guarded && kb_wtargets[req].kind != 0) {
        struct kb_scratch* s = scratch();
        if (!s) return 0;
        bpf_probe_read_kernel(s->request, sizeof(request), request);
        return kb_wine_reaches(tgid, data != 0 ? size : 0);
    }
    if (req == KB_REQ_GET_VOLUME_INFO) {
        if (!guarded) return 0;
        struct kb_scratch* s = reset_for(tgid, 0);
        if (!s) return 0;
        for (int i = 0; i < 16; i++) s->request[i] = request[i];
        return kb_volume_query(tgid, request[3], request[14]);
    }
    if (req == KB_REQ_OPEN_FILE_OBJECT || req == KB_REQ_CREATE_NAMED_PIPE || req == KB_REQ_OPEN_MAPPING ||
        req == KB_REQ_CREATE_MAPPING || req == KB_REQ_OPEN_DIRECTORY || req == KB_REQ_CREATE_DIRECTORY) {
        /* Names are kept for every decoded Wine process (a later open may be relative to the handle). */
        struct kb_scratch* s = reset_for(tgid, 0);
        if (!s) return 0;
        for (int i = 0; i < 16; i++) s->request[i] = request[i];
        int code = kb_nt_object(tgid, ownerTid, data, size);
        /* A directory is only named; a decision goes to the hook (it records the name if allowed). */
        if (guarded && (code & KB_REG_DECIDE) != 0) return code;
        if ((code & KB_REG_PENDING) != 0) kb_registry_pending();
        return 0;
    }
    if ((req < KB_REQ_CREATE_KEY || req > KB_REQ_RENAME_KEY) && req != KB_REQ_GET_SECURITY_OBJECT &&
        req != KB_REQ_SET_SECURITY_OBJECT) return 0;
    /* Key names are kept for every decoded Wine process, protected or not yet: a program
     * becomes protected when Wine names it, after its start-up opened its first keys. */
    if (!guarded && req != KB_REQ_OPEN_KEY && req != KB_REQ_CREATE_KEY) return 0;
    struct kb_scratch* s = reset_for(tgid, 0);
    if (!s) return 0;
    for (int i = 0; i < 16; i++) s->request[i] = request[i];
    int code = kb_registry(tgid, ownerTid, data, size);
    if (guarded) return code;
    if ((code & KB_REG_PENDING) != 0) kb_registry_pending();
    return 0;
}

/* The reply wineserver writes for client thread Tid of Tgid, at Buffer, to its request Pending: what it names (a
 * handle's process or key, ids, a device request's client) is recorded, and the request ends. */
static __always_inline int wineserver_reply(struct kb_pending* pending, __u32 tid, __u32 tgid, __u64 buffer)
{
    __u32 reply[16] = {};   /* generic reply: error, reply_size, then the request's fields */
    if (bpf_probe_read_user(reply, sizeof(reply), (void*)buffer) != 0) return 0;
    /* NT_SUCCESS: STATUS_OBJECT_NAME_EXISTS (0x40000000) from create_key opens an existing key. */
    if ((reply[0] & 0x80000000u) == 0) {
        if ((pending->req == KB_REQ_CREATE_MAPPING || pending->req == KB_REQ_DUP_HANDLE || object_maker(pending->req)) &&
            pending->object.thread == KB_OBJECT_OTHER) {
            struct kb_hkey_id id = {pending->owner, reply[2]};   /* no process or thread, or a copy of one */
            __u32 one = 1;
            if (id.handle != 0 && pending->owner == 0) bpf_map_update_elem(&kb_xmoved, &id.handle, &one, BPF_ANY);
            else if (id.handle != 0) { fresh_handle(&id); bpf_map_update_elem(&kb_xhandles, &id, &one, BPF_ANY); }
            if (id.handle != 0 && pending->req == KB_REQ_CREATE_FILE && pending->key.len != 0)
                bpf_map_update_elem(&kb_fnames, &id, &pending->key, BPF_ANY);   /* its NT name (kb_wine_note) */
        } else if (pending->req == KB_REQ_GET_APC_RESULT) {   /* reply: apc_result {type, status, handle} */
            __u32 moved = reply[4];
            if (reply[2] == KB_APC_DUP_HANDLE && reply[3] == 0 && moved != 0 &&
                bpf_map_lookup_elem(&kb_xmoved, &moved)) {
                struct kb_hkey_id id = {pending->owner, moved};
                __u32 one = 1;
                fresh_handle(&id);
                bpf_map_update_elem(&kb_xhandles, &id, &one, BPF_ANY);
                bpf_map_delete_elem(&kb_xmoved, &moved);
            }
        } else if (pending->req == KB_REQ_OPEN_KEY || pending->req == KB_REQ_CREATE_KEY ||
            pending->req == KB_REQ_OPEN_FILE_OBJECT || pending->req == KB_REQ_CREATE_NAMED_PIPE ||
            pending->req == KB_REQ_OPEN_MAPPING || pending->req == KB_REQ_CREATE_MAPPING ||
            pending->req == KB_REQ_OPEN_DIRECTORY || pending->req == KB_REQ_CREATE_DIRECTORY) {
            struct kb_hkey_id id = {tgid, reply[2]};
            if (id.handle != 0) { fresh_handle(&id); bpf_map_update_elem(&kb_hkeys, &id, &pending->key, BPF_ANY); }
        } else if (pending->req == KB_REQ_GET_NEXT_DEVICE_REQUEST) {
            __u32 wintid = reply[11];   /* get_next_device_request_reply.client_tid */
            __u32* client = bpf_map_lookup_elem(&kb_wintids, &wintid);
            __u32 value = client ? *client : 0;
            bpf_map_update_elem(&kb_serving, &tid, &value, BPF_ANY);
        } else if (pending->req == KB_REQ_INIT_FIRST_THREAD) {   /* reply: pid, tid */
            learn_id(reply[2], tgid);
            learn_id(reply[3], tgid);
            __u32 winpid = reply[2];
            __u32* creator = bpf_map_lookup_elem(&kb_creators, &winpid);
            struct kb_proc* created = creator ? bpf_map_lookup_elem(&kb_procs, &tgid) : 0;
            if (created) created->creator = *creator;
        } else if (pending->req == KB_REQ_NEW_THREAD) {   /* reply: tid, handle */
            learn_id(reply[2], pending->object.tgid);
            struct kb_hkey_id id = {pending->owner, reply[3]};
            if (id.handle != 0) { fresh_handle(&id); bpf_map_update_elem(&kb_ohandles, &id, &pending->object, BPF_ANY); }
        } else if (pending->req == KB_REQ_NEW_PROCESS) {   /* reply: info, pid, handle */
            __u32 winpid = reply[3], creator = pending->owner;
            if (winpid != 0) bpf_map_update_elem(&kb_creators, &winpid, &creator, BPF_ANY);
            struct kb_hkey_id id = {pending->owner, reply[4]};
            struct kb_ohandle child = pending->object;
            child.pid = reply[3];
            if (id.handle != 0) { fresh_handle(&id); bpf_map_update_elem(&kb_ohandles, &id, &child, BPF_ANY); }
        } else if (pending->req == KB_REQ_DUP_HANDLE && pending->key.len != 0) {
            struct kb_hkey_id id = {pending->owner, reply[2]};   /* the copy of a registry key */
            if (id.handle != 0) { fresh_handle(&id); bpf_map_update_elem(&kb_hkeys, &id, &pending->key, BPF_ANY); }
        } else if (pending->req == KB_REQ_OPEN_THREAD || pending->req == KB_REQ_OPEN_PROCESS ||
                   pending->req == KB_REQ_DUP_HANDLE || pending->req == KB_REQ_GET_NEXT_THREAD ||
                   pending->req == KB_REQ_GET_NEXT_PROCESS) {
            struct kb_hkey_id id = {pending->owner, reply[2]};   /* the reply's handle */
            if (id.handle != 0) { fresh_handle(&id); bpf_map_update_elem(&kb_ohandles, &id, &pending->object, BPF_ANY); }
        } else if (pending->req == KB_REQ_GET_KERNEL_OBJECT_HANDLE) {
            /* A driver's handle from a kernel object pointer: the process it reaches serves addr= rules alone, as one a
             * get_process_info reply names (every other rule meets requests through it on \@unknown, as before). */
            struct kb_hkey_id id = {pending->owner, reply[2]};
            __u32 object = ohandle_tgid(&pending->object);
            if (id.handle != 0) fresh_handle(&id);
            if (id.handle != 0 && object != 0) bpf_map_update_elem(&kb_learnt, &id, &object, BPF_ANY);
        } else if (pending->req == KB_REQ_CREATE_WINDOW && reply[2] != 0) {   /* reply: handle@0x8 */
            __u32 index = reply[2] & 0xFFFF;
            struct kb_window window = {reply[2] >> 16, tgid};
            bpf_map_update_elem(&kb_windows, &index, &window, BPF_ANY);
        } else if (pending->req == KB_REQ_GET_DESKTOP_WINDOW) {   /* reply: top_window@0x8, msg_window@0xc */
            for (int i = 2; i < 4; i++) {
                __u32 index = reply[i] & 0xFFFF;
                struct kb_window shared = {reply[i] >> 16, KB_WINDOW_SHARED};
                if (reply[i] != 0) bpf_map_update_elem(&kb_windows, &index, &shared, BPF_ANY);
            }
        } else if (pending->req == KB_REQ_GET_PROCESS_INFO || pending->req == KB_REQ_GET_THREAD_INFO) {
            /* A handle kfilter could not name (learn_handle): the reply names its process (pid@0x8). */
            __u32 pid = reply[2];
            __u32* named = bpf_map_lookup_elem(&kb_wintids, &pid);
            struct kb_hkey_id id = {pending->owner, pending->object.pid};
            if (named && *named != 0) bpf_map_update_elem(&kb_learnt, &id, named, BPF_ANY);
        }
    }
    bpf_map_delete_elem(&kb_pending, &tid);
    return 0;
}

/*
 * wineserver reads a pipe: a request pipe makes it serve that client until it writes the
 * reply. It writes a pipe: the client's reply pipe ends that, and the reply's handle (for a
 * pending key open) or client thread (for a device request) is recorded.
 */
__noinline int kb_wineserver_pipe(__u64 inodeAddress, __u32 write)
{
    struct task_struct* task = bpf_get_current_task_btf();
    struct kb_task* state = task_state(task);
    if (!state) return 0;
    struct kb_pipe* pipe = bpf_map_lookup_elem(&kb_pipes, &inodeAddress);
    if (!write) {
        if (pipe && pipe->kind == KB_PIPE_REQUEST) {
            state->client = pipe->tgid;
            state->client_tid = pipe->tid;
        } else {
            state->client = 0;
            state->client_tid = 0;
        }
        return 0;
    }
    if (!pipe || pipe->kind != KB_PIPE_REPLY) return 0;
    __u32 serving = state->client_tid;
    state->client = 0;
    state->client_tid = 0;
    __u32 tid = pipe->tid, tgid = pipe->tgid;
    /* Only the reply to the request wineserver just read: a reply pipe the program registered
     * as another thread's (a forged first request) is not read as that thread's. */
    if (serving != tid) return 0;
    struct kb_pending* pending = bpf_map_lookup_elem(&kb_pending, &tid);
    if (!pending) return 0;
    struct pt_regs* regs = (struct pt_regs*)bpf_task_pt_regs(task);
    if (!regs) return 0;
    long nr = BPF_CORE_READ(regs, orig_ax);
    __u64 buffer = BPF_CORE_READ(regs, si);
    if (nr == 20) {
        __u64 first = 0;
        if (bpf_probe_read_user(&first, sizeof(first), (void*)buffer) != 0) return 0;
        buffer = first;
    } else if (nr != 1) {
        return 0;
    }
    return wineserver_reply(pending, tid, tgid, buffer);
}

/* wineserver waiting for events (epoll_wait, epoll_pwait, epoll_pwait2, poll, ppoll)
 * serves no one: a request that got no reply (data not there yet, the client gone) does
 * not leave its client charged for the event loop's own work. */
SEC("tp_btf/sys_enter")
int BPF_PROG(kb_sys_enter, struct pt_regs* regs, long id)
{
    if (id != 232 && id != 281 && id != 441 && id != 7 && id != 271) return 0;
    struct kb_task* state = task_state(bpf_get_current_task_btf());
    if (state && state->role == KB_ROLE_WINESERVER && state->client != 0) {
        state->client = 0;
        state->client_tid = 0;
    }
    return 0;
}

/* ---- file hooks ---- */

/* Refusals that need no rule: changing its own exe link, kernel image loads, bpf() and
 * perf_event_open from the client, and requests to wineserver kfilter cannot decode. (PR_SET_PTRACER is not refused: Wine sets it so that
 * wineserver can reach the client, and kfilter decides that access itself.) */
static __always_inline int refuse(__u32 value)
{
    struct kb_cfg* c = kb_cfg_get();
    if (!c || !c->enabled || c->mode == KFILTER_MODE_OFF) return 0;
    struct kb_scratch* s = reset_for(current_tgid(), 0);
    if (!s) return 0;
    s->failed = 1;   /* no path */
    return verdict(KFILTER_TARGET_PROCESS, KFilterActionDeny, 0, value, 0, 0, c->mode);
}

/* Inode is a pipe registered as a Wine thread's request pipe. */
static __always_inline int request_pipe(struct inode* inode)
{
    if (!inode || fs_magic(inode) != PIPEFS_MAGIC) return 0;
    __u64 key = pipe_key(inode);
    struct kb_pipe* pipe = bpf_map_lookup_elem(&kb_pipes, &key);
    return pipe && pipe->kind == KB_PIPE_REQUEST;
}

/* splice, tee and vmsplice fill a pipe without file_permission, so kb_wine_request never sees
 * the request: a protected task doing that to a request pipe is refused (Wine never does). */
static __always_inline int splice_refused(__s64 fd, __u32 nr)
{
    struct task_struct* task = bpf_get_current_task_btf();
    if (!task_protected(task, task_state(task))) return 0;
    struct file* file = fd_file(task, (__s32)fd);
    if (!file || !request_pipe(BPF_CORE_READ(file, f_inode))) return 0;
    return refuse(KB_RAW_REQUEST + nr);
}

/* The pipe each takes: vmsplice(fd), splice(in, off_in, out), tee(in, out); int 0x80 too. An
 * fmod_ret's return is the syscall's: the x64 ones are long, or -EPERM reads as 0xFFFFFFFF
 * (4 GiB spliced). The ia32 ones return 32-bit eax. */
SEC("fmod_ret/__x64_sys_vmsplice")
long BPF_PROG(kb_vmsplice, struct pt_regs* regs, long ret)
{
    return ret != 0 ? ret : splice_refused(BPF_CORE_READ(regs, di), 278);
}

SEC("fmod_ret/__x64_sys_splice")
long BPF_PROG(kb_splice, struct pt_regs* regs, long ret)
{
    return ret != 0 ? ret : splice_refused(BPF_CORE_READ(regs, dx), 275);
}

SEC("fmod_ret/__x64_sys_tee")
long BPF_PROG(kb_tee, struct pt_regs* regs, long ret)
{
    return ret != 0 ? ret : splice_refused(BPF_CORE_READ(regs, si), 276);
}

SEC("fmod_ret/__ia32_sys_vmsplice")
int BPF_PROG(kb_vmsplice32, struct pt_regs* regs, int ret)
{
    return ret != 0 ? ret : splice_refused((__s32)BPF_CORE_READ(regs, bx), 278);
}

SEC("fmod_ret/__ia32_sys_splice")
int BPF_PROG(kb_splice32, struct pt_regs* regs, int ret)
{
    return ret != 0 ? ret : splice_refused((__s32)BPF_CORE_READ(regs, dx), 275);
}

SEC("fmod_ret/__ia32_sys_tee")
int BPF_PROG(kb_tee32, struct pt_regs* regs, int ret)
{
    return ret != 0 ? ret : splice_refused((__s32)BPF_CORE_READ(regs, cx), 276);
}

/* Wine sends a request's data (a key or object name, often a constant in ntdll.so) with writev. A page
 * the process has not touched yet cannot be read by the non-sleepable decoder in kb_file_permission,
 * which would make the name a failure (refused in block mode: Wine's start-up open of
 * \KernelObjects\__wine_user_shared_data failed about 1 time in 12). This sleepable hook faults in, before writev
 * reaches file_permission, the first and last byte of every chunk kb_request_data joins (as far as it joins them) of a
 * Wine thread's request whose data a decoder reads (create_file's, write's and ioctl's too while a keyed rule can name
 * them: an RPC call or a file name not read would go undecided). */
static __always_inline int prefault_request(__u64 iov, __u64 count, int compat)
{
    struct kb_task* state = task_state(bpf_get_current_task_btf());
    if (!state || state->role != KB_ROLE_WINE || count < 2 || count > 1 + KB_REQ_CHUNKS) return 0;
    struct kb_cfg* c = kb_cfg_get();
    __u32 keyed = c && (c->targets & KB_TARGET_KEYED) != 0;
    __u64 at = 0;
    for (__u32 i = 0; i <= KB_REQ_CHUNKS; i++) {
        if (i >= count || at >= KB_REQ_DATA) break;
        __u64 vector[2] = {};   /* base, length */
        if (compat) {
            __u32 small[2] = {};
            if (bpf_copy_from_user(small, sizeof(small), (void*)(iov + i * 8)) != 0) return 0;
            vector[0] = small[0];
            vector[1] = small[1];
        } else if (bpf_copy_from_user(vector, sizeof(vector), (void*)(iov + i * 16)) != 0) {
            return 0;
        }
        if (i == 0) {   /* the header: only a request whose data is decoded */
            __u32 req = 0;
            if (vector[1] != 64 || bpf_copy_from_user(&req, sizeof(req), (void*)vector[0]) != 0) return 0;
            if (!reads_data(req) && !(keyed && (req == KB_REQ_CREATE_FILE || req == KB_REQ_WRITE || req == KB_REQ_IOCTL)))
                return 0;
            continue;
        }
        if (vector[1] == 0) continue;
        __u64 length = vector[1] < KB_REQ_DATA - at ? vector[1] : KB_REQ_DATA - at;
        char byte = 0;
        bpf_copy_from_user(&byte, 1, (void*)vector[0]);
        bpf_copy_from_user(&byte, 1, (void*)(vector[0] + length - 1));
        at += length;
    }
    return 0;
}

SEC("fentry.s/__x64_sys_writev")
int BPF_PROG(kb_prefault_writev, struct pt_regs* regs)
{
    return prefault_request(BPF_CORE_READ(regs, si), BPF_CORE_READ(regs, dx), 0);
}

SEC("fentry.s/__ia32_sys_writev")
int BPF_PROG(kb_prefault_writev32, struct pt_regs* regs)
{
    return prefault_request(BPF_CORE_READ(regs, cx) & 0xFFFFFFFFull, BPF_CORE_READ(regs, dx) & 0xFFFFFFFFull, 1);
}

SEC("lsm/file_open")
int BPF_PROG(kb_file_open, struct file* file, int ret)
{
    if (ret != 0) return ret;
    BEGIN();
    if (exec_open(file)) {
        /* Every exec-open (image, ELF interpreter): the process-create decision. */
        walk_file(file);
        return kb_decide(KFILTER_TARGET_PROCESS, KFILTER_RIGHT_CREATE, 0);
    }
    __u32 target = 0;
    __u32 rights = open_rights(file, &target);
    return decide_file(file, target, rights, 0);
}

/* A pipe made by a task kfilter follows records its creator. Pipes from anyone else carry none:
 * they came from outside the family (inherited stdio, SCM_RIGHTS). */
SEC("lsm/inode_alloc_security")
int BPF_PROG(kb_pipe_alloc, struct inode* inode, int ret)
{
    if (ret != 0) return ret;
    struct task_struct* task = bpf_get_current_task_btf();
    struct kb_task* state = task_state(task);
    if (!state || BPF_CORE_READ(inode, i_sb, s_magic) != PIPEFS_MAGIC) return 0;
    struct kb_pipe_creator* creator = bpf_inode_storage_get(&kb_pipe_creators, inode, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (creator) {
        creator->tgid = current_tgid();
        creator->inside = task_protected(task, state) || state->role == KB_ROLE_WINESERVER;
    }
    return 0;
}

/* A pipe neither Wine's (a registered request or reply pipe, or one wineserver made) nor made by
 * the family; *Creator is its maker, 0 when kfilter did not follow it. */
static __always_inline int outside_pipe(struct file* file, __u32* creator)
{
    struct inode* inode = file->f_inode;
    __u64 key = pipe_key(inode);
    if (bpf_map_lookup_elem(&kb_pipes, &key)) return 0;
    struct kb_pipe_creator* made = bpf_inode_storage_get(&kb_pipe_creators, inode, 0, 0);
    *creator = made ? made->tgid : 0;
    return !made || !made->inside;
}

/*
 * Rights on a pipe from outside the family, for the program in s->tgid: /anon/pipe/<the program
 * that made it> (its Windows image under Wine), /anon/pipe/@outside when kfilter did not follow
 * the maker or it is gone. Decided only by a rule naming it, once per open file.
 * shortcut: a pipe from a program kfilter does not follow is @outside, not named by its maker;
 * record every pipe's maker in kb_pipe_alloc if rules must tell those apart.
 */
__noinline int kb_pipe_decide(__u64 fileAddress, __u32 creator, __u32 rights)
{
    struct kb_cfg* c = kb_cfg_get();
    struct kb_scratch* s = scratch();
    struct file* file = (struct file*)fileAddress;
    if (!c || !s || (c->targets & KFILTER_TARGET_PIPE) == 0) return 0;
    /* Its own, made before it was protected (a program admitted by its Windows image). */
    if (creator != 0 && (creator == s->tgid || proc_guarded(creator))) return 0;
    if (granted(file, rights)) return 0;
    __u32 generation = c->generation;   /* before kb_decide_global reads kb_live (grant) */
    s->failed = 0;
    s->len = 0;
    struct kb_proc* proc = creator != 0 ? bpf_map_lookup_elem(&kb_procs, &creator) : 0;
    if (proc && proc->ilen != 0 && proc->ilen < KB_PROG) {
        set_path(s, "/anon/pipe/", 11);
        append_string(s, proc->image, 0);
    } else if (creator != 0) {
        struct task_struct* task = bpf_task_from_pid((s32)creator);
        if (task) {
            walk_exe(task);
            bpf_task_release(task);
            if (!s->failed) {
                bpf_probe_read_kernel_str(s->walk, KB_PATH, s->path);
                set_path(s, "/anon/pipe", 10);
                append_string(s, s->walk, 0);
            }
        }
    }
    if (s->len == 0 || s->failed) set_path(s, "/anon/pipe/@outside", 19);
    int result = kb_decide_global(KFILTER_TARGET_PIPE, rights, 0, 1);
    if (result == 0) grant(file, rights, generation);
    return result;
}

/*
 * A Wine task's write to a pipe (Inode), as kb_file_permission decides it: kb_wine_request's request, its own decision
 * and the second pass after an allowed system decision, then its registry, NT object, volume, handle or raw request
 * decision. Returns 0 or -EFAULT (a refusal fails the write; Wine returns STATUS_ACCESS_VIOLATION, and any other errno
 * would kill the process), KB_WINE_DECIDE when what it reaches past its own decision is to be decided
 * (kb_wine_decide), or 1 when it was no request kfilter decides.
 */
static __always_inline int wine_write(__u64 inodeAddress)
{
    int code = kb_wine_request(inodeAddress, 0);
    if (code > 0 && (code & KB_SYSTEM_DECIDE) != 0) {
        if (kb_decide_global(KFILTER_TARGET_SYSTEM, code & KB_REG_RIGHTS, 0, kb_system_listed(code)) != 0)
            return -EFAULT;
        /* Allowed as /system/wine/<request>: its other decisions follow (a named section or object directory by
         * its NT name, a registry, volume or handle request) and what it records (kb_wine_request again). */
        code = kb_wine_request(inodeAddress, 1);
    }
    if (code > 0) {   /* not "!= 0": clang would return code itself, unbounded to the verifier */
        /* A refused thread handle: the write fails, as a refused registry request does. */
        if (code == KB_HANDLE_DECIDE) return kb_handle_decide() != 0 ? -EFAULT : 0;
        /* What it reaches past its own decision: another program's window or thread, keyed decisions. */
        if (code == KB_WINE_DECIDE) return KB_WINE_DECIDE;
        if (code == KB_REQ_RAW) return refuse(KB_RAW_REQUEST) != 0 ? -EFAULT : 0;
        if (code < KB_REG_DECIDE) {
            /* A malformed write to wineserver, or an unadmitted program: refused in block mode only. */
            struct kb_cfg* c = kb_cfg_get();
            return c && c->enabled && c->mode == KFILTER_MODE_BLOCK ? -EFAULT : 0;
        }
        /* A refused registry request or NT object open: the write fails, Wine returns
         * STATUS_ACCESS_VIOLATION. */
        __u32 decided = (code & KB_NT_OBJECT) == 0 ? KFILTER_TARGET_REGISTRY :
                        (code & KB_NT_VOLUME) != 0 ? KFILTER_TARGET_VOLUME :
                        (code & KB_NT_PIPE) != 0 ? KFILTER_TARGET_PIPE : KFILTER_TARGET_FILE;
        __u32 value = 0;
        if ((code & KB_NT_VOLUME) != 0) {
            struct kb_scratch* scratchState = scratch();
            value = scratchState ? scratchState->request[14] : 0;
        }
        if (kb_decide_global(decided, code & KB_REG_RIGHTS, value, 0) != 0) return -EFAULT;
        if ((code & KB_REG_RENAME) != 0) {
            kb_rename_target();
            if (kb_decide_global(KFILTER_TARGET_REGISTRY, KFILTER_RIGHT_RENAME, 0, 0) != 0) return -EFAULT;
        }
        if ((code & KB_REG_PENDING) != 0) kb_registry_pending();
        return 0;
    }
    return 1;
}

/* kb_wine_reach, the tail call kb_file_permission makes to decide what a Wine request reaches past its own decision:
 * a program of its own, so that chain's verification does not count in kb_file_permission's (near the kernel's
 * limit). kfilterd fills it at load. */
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} kb_reach SEC(".maps");

SEC("lsm/file_permission")
int BPF_PROG(kb_file_permission, struct file* file, int mask, int ret)
{
    if (ret != 0 || (mask & (MAY_READ | MAY_WRITE)) == 0) return ret;
    struct task_struct* task = bpf_get_current_task_btf();
    struct kb_task* state = task_state(task);
    if (!state) return 0;
    struct inode* inode = BPF_CORE_READ(file, f_inode);
    __u32 type = inode_mode(inode) & S_IFMT;
    /* A protected task outside Wine writing a request pipe it was handed: never decoded. */
    if (type == S_IFIFO && state->role == KB_ROLE_NONE && state->guarded && (mask & MAY_WRITE) != 0 &&
        request_pipe(inode)) return refuse(KB_RAW_REQUEST);
    if (type == S_IFIFO && state->role != KB_ROLE_NONE && fs_magic(inode) == PIPEFS_MAGIC) {
        __u64 inodeAddress = pipe_key(inode);
        /* Global functions return unknown scalars to the verifier: map them to a bounded errno. */
        if (state->role == KB_ROLE_WINESERVER) {
            kb_wineserver_pipe(inodeAddress, (mask & MAY_WRITE) != 0);
            return 0;
        }
        int code = (mask & MAY_WRITE) != 0 ? wine_write(inodeAddress) : 1;
        if (code == KB_WINE_DECIDE) {
            bpf_tail_call(ctx, &kb_reach, 0);
            return 0;   /* no kb_wine_reach: kfilterd fills kb_reach before it attaches anything */
        }
        if (code <= 0) return code == 0 ? 0 : -EFAULT;
    }
    /* Pipes: only one from outside the family is decided (two lookups for every other). */
    int pipe = type == S_IFIFO && fs_magic(inode) == PIPEFS_MAGIC;
    __u32 creator = 0;
    if (pipe && !outside_pipe(file, &creator)) return 0;
    BEGIN();
    /* /proc/<pid>/mem: each access, by its address (addr= rules). */
    if (type == S_IFREG && kb_proc_mem(address_of(file), mask) != 0) return -EPERM;
    __u32 target = type == S_IFDIR ? KFILTER_TARGET_DIR : type == S_IFIFO ? KFILTER_TARGET_PIPE : KFILTER_TARGET_FILE;
    __u32 rights = 0;
    if (mask & MAY_READ) rights |= type == S_IFDIR ? KFILTER_RIGHT_ENUMERATE : KFILTER_RIGHT_READ;
    if (mask & MAY_WRITE) rights |= KFILTER_RIGHT_WRITE;
    if (pipe) return kb_decided(kb_pipe_decide(address_of(file), creator, rights));
    return decide_file(file, target, rights, 1);
}

/* kb_file_permission's tail call (kb_reach), never attached: what the request kb_wine_request left in the scratch
 * reaches past its own decision (kb_wine_decide). */
SEC("lsm/file_permission")
int BPF_PROG(kb_wine_reach, struct file* file, int mask, int ret)
{
    return kb_wine_decide() != 0 ? -EFAULT : 0;
}

/* A file passed to the program over SCM_RIGHTS (under Wine: every file wineserver opened
 * for it) is decided like an open, unless this open was already decided for it. */
SEC("lsm/file_receive")
int BPF_PROG(kb_file_receive, struct file* file, int ret)
{
    if (ret != 0) return ret;
    BEGIN();
    if (exec_open(file)) return 0;
    __u32 target = 0;
    __u32 rights = open_rights(file, &target);
    __u32 creator = 0;
    if (fs_magic(BPF_CORE_READ(file, f_inode)) == PIPEFS_MAGIC)
        return outside_pipe(file, &creator) ? kb_decided(kb_pipe_decide(address_of(file), creator, rights)) : 0;
    return decide_file(file, target, rights, 1);
}

SEC("lsm/file_free_security")
int BPF_PROG(kb_file_free, struct file* file)
{
    __u64 key = address_of(file);
    /* Every file freed on the system passes here: a lock-free lookup first. */
    if (bpf_map_lookup_elem(&kb_files, &key)) bpf_map_delete_elem(&kb_files, &key);
    /* A socket's last file: its block-connection entry goes with it (inode numbers are reused). */
    struct inode* inode = BPF_CORE_READ(file, f_inode);
    if (inode && fs_magic(inode) == SOCKFS_MAGIC) {
        __u64 number = BPF_CORE_READ(inode, i_ino);
        if (bpf_map_lookup_elem(&kb_blocked, &number)) bpf_map_delete_elem(&kb_blocked, &number);
    }
    return 0;
}

/* A device ioctl that was allowed on s->path, decided again by its argument (ABI 11, KB_GATE_ARGUMENT): value
 * 0x<cmd>:0x<the first 32 bits Arg points to> ("?" when it cannot be read), met only by device rules whose value names an
 * argument (KB_TARGET_ARGUMENT: DRM GETPARAM's id, value=0xC0106446:0x00000002), never by a glob over the command alone.
 * Its event names the argument after the path (" arg=0x00000002"), past s->len, which rules match. */
__noinline int kb_ioctl_argument(__u32 cmd, __u64 arg)
{
    static const char hex[] = "0123456789ABCDEF";
    struct kb_scratch* s = scratch();
    if (!s || !gated(KB_GATE_ARGUMENT) || s->failed || s->len > KB_PATH - 24) return 0;
    __u32 param = 0;
    int known = arg != 0 && bpf_probe_read_user(&param, sizeof(param), (const void*)arg) == 0;
    device_value(s, cmd);
    s->value[10] = ':';
    if (known) {
        s->value[11] = '0';
        s->value[12] = 'x';
        for (int i = 0; i < 8; i++) s->value[13 + i] = hex[(param >> (28 - 4 * i)) & 0xF];
    } else {
        s->value[11] = '?';
    }
    s->vlen = known ? 21 : 12;
    s->value[s->vlen & (KB_VALUE - 1)] = 0;
    __u32 at = s->len;
    const char text[] = " arg=";
    for (int i = 0; i < 5; i++) s->path[(at + i) & (KB_PATH - 1)] = text[i];
    for (int i = 0; i < 11; i++) s->path[(at + 5 + i) & (KB_PATH - 1)] = 11 + i < s->vlen ? s->value[11 + i] : 0;
    return kb_decide_global(KB_TARGET_ARGUMENT, KFILTER_RIGHT_RAW_DEVICE, cmd, 1);
}

/* Device ioctls; filesystem identity ioctls (block-volume-serial); interface ioctls on a
 * socket (block-network-adapter), any other socket ioctl as /net/ioctl/0x<code> where a rule names it (ABI 11, root
 * /net/ioctl/); any other ioctl only where a device rule names it. */
static __always_inline int decide_ioctl(struct file* file, unsigned int cmd, unsigned long arg)
{
    BEGIN();
    struct kb_cfg* c = kb_cfg_get();
    struct kb_scratch* s = scratch();
    struct inode* inode = BPF_CORE_READ(file, f_inode);
    if (!c || !s || !inode) return 0;
    __u32 type = inode_mode(inode) & S_IFMT;
    if (fs_magic(inode) == SOCKFS_MAGIC) {
        int adapter = (cmd >= SIOC_IF_FIRST && cmd <= SIOC_IF_LAST) || (cmd >= SIOC_WIRELESS_FIRST && cmd <= SIOC_WIRELESS_LAST);
        if (adapter && (c->flags & KFILTER_CFG_BLOCK_NETWORK_ADAPTER) != 0) {
            set_path(s, "/net/ioctl", 10);
            device_value(s, cmd);
            return kb_decide(KFILTER_TARGET_DEVICE, KFILTER_RIGHT_RAW_DEVICE, cmd);
        }
        if (!gated(KB_GATE_SOCKET_IOCTL)) return 0;
        set_path(s, "/net/ioctl/0x", 13);
        append_hex(s, cmd, 8);
        device_value(s, cmd);
        return kb_decided(kb_decide_global(KFILTER_TARGET_DEVICE, KFILTER_RIGHT_RAW_DEVICE, cmd, 1 | KB_ROOT(11)));
    }
    int device = !pseudo_fs(inode) && (type == S_IFBLK || type == S_IFCHR);
    if (!pseudo_fs(inode) && (type == S_IFREG || type == S_IFDIR) &&
        (cmd == FS_IOC_GETFSUUID || cmd == FS_IOC_GETFSSYSFSPATH || cmd == FS_IOC_GETFSLABEL)) {
        walk_file(file);
        device_value(s, cmd);
        return kb_decide(KFILTER_TARGET_VOLUME, KFILTER_RIGHT_QUERY, cmd);
    }
    if (device) {
        walk_file(file);
        if (!s->failed && device_target(c, s, type)) {
            device_value(s, cmd);
            int result = kb_decide(KFILTER_TARGET_DEVICE, KFILTER_RIGHT_RAW_DEVICE, cmd);
            return result != 0 ? result : kb_decided(kb_ioctl_argument(cmd, arg));
        }
    }
    /* Any other device (a GPU, a terminal), a file, or an anonymous inode (/anon/[userfaultfd],
     * /anon/dmabuf): decided only where a deny or audit device rule names it (value = the ioctl).
     * shortcut: not cached, so under such a rule every ioctl (a GPU's per frame) walks its path;
     * keep an LRU of (file, cmd) verdicts if that shows. */
    if (!c->ioctl_rules) return 0;
    if (!device) walk_file(file);
    device_value(s, cmd);
    int result = kb_decide_listed(KFILTER_TARGET_DEVICE, KFILTER_RIGHT_RAW_DEVICE, cmd);
    return result != 0 ? result : kb_decided(kb_ioctl_argument(cmd, arg));
}

/* FIOSETOWN and SIOCSPGRP set a socket's SIGIO owner (Arg points to it) as F_SETOWN does: kb_owner_decide, by whoever
 * sets it. */
static __always_inline int ioctl_owner(struct file* file, unsigned int cmd, unsigned long arg)
{
    __s32 who = 0;
    if ((cmd != 0x8901 && cmd != 0x8902) || fs_magic(BPF_CORE_READ(file, f_inode)) != SOCKFS_MAGIC ||
        bpf_probe_read_user(&who, sizeof(who), (const void*)arg) != 0)
        return 0;
    return kb_decided(owner_decide(who));   /* inline: the ioctl hook's frames leave no room for another */
}

SEC("lsm/file_ioctl")
int BPF_PROG(kb_file_ioctl, struct file* file, unsigned int cmd, unsigned long arg, int ret)
{
    if (ret != 0) return ret;
    int owner = ioctl_owner(file, cmd, arg);
    return owner != 0 ? owner : decide_ioctl(file, cmd, arg);
}

/* 32-bit programs (the Nexon launcher, grap-updater under Wine) issue compat ioctls. */
SEC("lsm/file_ioctl_compat")
int BPF_PROG(kb_file_ioctl_compat, struct file* file, unsigned int cmd, unsigned long arg, int ret)
{
    if (ret != 0) return ret;
    int owner = ioctl_owner(file, cmd, arg & 0xFFFFFFFFul);
    return owner != 0 ? owner : decide_ioctl(file, cmd, arg & 0xFFFFFFFFul);
}

static __always_inline __u32 dentry_target(struct dentry* dentry)
{
    __u32 type = inode_mode(BPF_CORE_READ(dentry, d_inode)) & S_IFMT;
    return type == S_IFDIR ? KFILTER_TARGET_DIR : type == S_IFIFO ? KFILTER_TARGET_PIPE : KFILTER_TARGET_FILE;
}

static __always_inline int decide_entry(const struct path* dir, struct dentry* dentry, __u32 target, __u32 rights)
{
    walk_entry(dir, dentry);
    return kb_decide(target, rights, 0);
}

/* Starting a second decision in the same hook: keep who it is for, clear the path. */
static __always_inline int again(void)
{
    struct kb_scratch* s = scratch();
    if (!s) return -1;
    s->failed = 0;
    s->vlen = 0;
    s->len = 0;
    return 0;
}

SEC("lsm/path_unlink")
int BPF_PROG(kb_path_unlink, const struct path* dir, struct dentry* dentry, int ret)
{
    if (ret != 0) return ret;
    BEGIN();
    return decide_entry(dir, dentry, dentry_target(dentry), KFILTER_RIGHT_DELETE);
}

SEC("lsm/path_rmdir")
int BPF_PROG(kb_path_rmdir, const struct path* dir, struct dentry* dentry, int ret)
{
    if (ret != 0) return ret;
    BEGIN();
    return decide_entry(dir, dentry, KFILTER_TARGET_DIR, KFILTER_RIGHT_DELETE);
}

SEC("lsm/path_mkdir")
int BPF_PROG(kb_path_mkdir, const struct path* dir, struct dentry* dentry, umode_t mode, int ret)
{
    if (ret != 0) return ret;
    BEGIN();
    return decide_entry(dir, dentry, KFILTER_TARGET_DIR, KFILTER_RIGHT_WRITE);
}

SEC("lsm/path_mknod")
int BPF_PROG(kb_path_mknod, const struct path* dir, struct dentry* dentry, umode_t mode, unsigned int dev, int ret)
{
    if (ret != 0) return ret;
    BEGIN();
    return decide_entry(dir, dentry, (mode & S_IFMT) == S_IFIFO ? KFILTER_TARGET_PIPE : KFILTER_TARGET_FILE,
                        KFILTER_RIGHT_WRITE);
}

SEC("lsm/path_symlink")
int BPF_PROG(kb_path_symlink, const struct path* dir, struct dentry* dentry, const char* old_name, int ret)
{
    if (ret != 0) return ret;
    BEGIN();
    return decide_entry(dir, dentry, KFILTER_TARGET_FILE, KFILTER_RIGHT_WRITE);
}

SEC("lsm/path_link")
int BPF_PROG(kb_path_link, struct dentry* old_dentry, const struct path* new_dir, struct dentry* new_dentry, int ret)
{
    if (ret != 0) return ret;
    BEGIN();
    /* A link stays on one mount: the old name is under the new directory's mount. A new
     * name for a file reaches its contents, so the old name needs read as well as rename. */
    kb_walk(address_of(old_dentry), (__u64)BPF_CORE_READ(new_dir, mnt));
    int result = kb_decide(dentry_target(old_dentry), KFILTER_RIGHT_RENAME | KFILTER_RIGHT_READ, 0);
    if (result != 0 || again() != 0) return result;
    return decide_entry(new_dir, new_dentry, KFILTER_TARGET_FILE, KFILTER_RIGHT_WRITE);
}

SEC("lsm/path_rename")
int BPF_PROG(kb_path_rename, const struct path* old_dir, struct dentry* old_dentry, const struct path* new_dir,
             struct dentry* new_dentry, unsigned int flags, int ret)
{
    if (ret != 0) return ret;
    BEGIN();
    int result = decide_entry(old_dir, old_dentry, dentry_target(old_dentry), KFILTER_RIGHT_RENAME);
    if (result != 0 || again() != 0) return result;
    return decide_entry(new_dir, new_dentry, dentry_target(old_dentry), KFILTER_RIGHT_WRITE);
}

SEC("lsm/path_truncate")
int BPF_PROG(kb_path_truncate, const struct path* path, int ret)
{
    if (ret != 0) return ret;
    BEGIN();
    walk_path(path);
    return kb_decide(KFILTER_TARGET_FILE, KFILTER_RIGHT_WRITE, 0);
}

SEC("lsm/file_truncate")
int BPF_PROG(kb_file_truncate, struct file* file, int ret)
{
    if (ret != 0) return ret;
    BEGIN();
    return decide_file(file, KFILTER_TARGET_FILE, KFILTER_RIGHT_WRITE, 1);
}

SEC("lsm/path_chmod")
int BPF_PROG(kb_path_chmod, const struct path* path, umode_t mode, int ret)
{
    if (ret != 0) return ret;
    BEGIN();
    walk_path(path);
    return kb_decide(dentry_target(BPF_CORE_READ(path, dentry)), KFILTER_RIGHT_SET_SECURITY, 0);
}

SEC("lsm/path_chown")
int BPF_PROG(kb_path_chown, const struct path* path, __u64 uid, __u64 gid, int ret)
{
    if (ret != 0) return ret;
    BEGIN();
    walk_path(path);
    return kb_decide(dentry_target(BPF_CORE_READ(path, dentry)), KFILTER_RIGHT_SET_SECURITY, 0);
}

SEC("lsm/inode_setxattr")
int BPF_PROG(kb_inode_setxattr, struct mnt_idmap* idmap, struct dentry* dentry, const char* name, const void* value,
             size_t size, int flags, int ret)
{
    if (ret != 0) return ret;
    BEGIN();
    walk_inode_dentry(dentry);
    return kb_decide(dentry_target(dentry), KFILTER_RIGHT_SET_SECURITY, 0);
}

SEC("lsm/inode_removexattr")
int BPF_PROG(kb_inode_removexattr, struct mnt_idmap* idmap, struct dentry* dentry, const char* name, int ret)
{
    if (ret != 0) return ret;
    BEGIN();
    walk_inode_dentry(dentry);
    return kb_decide(dentry_target(dentry), KFILTER_RIGHT_SET_SECURITY, 0);
}

/* Explicit time changes (utimensat); mode, owner and size come through the path hooks. */
SEC("lsm/inode_setattr")
int BPF_PROG(kb_inode_setattr, struct mnt_idmap* idmap, struct dentry* dentry, struct iattr* attr, int ret)
{
    if (ret != 0) return ret;
    __u32 valid = BPF_CORE_READ(attr, ia_valid);
    if ((valid & (ATTR_ATIME_SET | ATTR_MTIME_SET)) == 0) {
        /* Times set to now (utimensat with no times, touch): right touch (ABI 11), rule-only. */
        if ((valid & ATTR_TOUCH) == 0 || !gated(KB_GATE_TOUCH)) return 0;
        BEGIN();
        walk_inode_dentry(dentry);
        return kb_decided(kb_decide_global(dentry_target(dentry), KFILTER_RIGHT_TOUCH, 0, 1));
    }
    BEGIN();
    walk_inode_dentry(dentry);
    return kb_decide(dentry_target(dentry), KFILTER_RIGHT_SET_SECURITY, 0);
}

/* ---- metadata queries (block-file-queries) ---- */

/* The query is on an fd whose open was already decided for this program, as Windows decides
 * the open and not a query on its handle: fstat, fstatat or statx with AT_EMPTY_PATH and an
 * empty or NULL name, fgetxattr, flistxattr. Not the cwd (AT_FDCWD), a name that cannot be
 * read, an O_PATH or inherited fd (never granted), or a file the fd no longer holds. */
static __always_inline int fd_granted(struct dentry* dentry)
{
    struct task_struct* task = bpf_get_current_task_btf();
    struct pt_regs* regs = (struct pt_regs*)bpf_task_pt_regs(task);
    if (!regs) return 0;
    long nr = BPF_CORE_READ(regs, orig_ax);
    int compat = (BPF_CORE_READ(task, thread_info.status) & TS_COMPAT) != 0;
    __s32 fd = compat ? (__s32)BPF_CORE_READ(regs, bx) : (__s32)BPF_CORE_READ(regs, di);
    __u64 name = 0, flags = 0;
    int at = 1;
    if (!compat && (nr == 262 || nr == 332)) {   /* newfstatat(fd, name, buf, flags), statx(fd, name, flags, ...) */
        name = BPF_CORE_READ(regs, si);
        flags = nr == 262 ? BPF_CORE_READ(regs, r10) : BPF_CORE_READ(regs, dx);
    } else if (compat && (nr == 300 || nr == 383)) {   /* fstatat64, statx */
        name = BPF_CORE_READ(regs, cx) & 0xFFFFFFFFull;
        flags = nr == 300 ? BPF_CORE_READ(regs, si) : BPF_CORE_READ(regs, dx);
    } else if (compat ? (nr == 108 || nr == 197 || nr == 231 || nr == 234)   /* fstat, fstat64, fgetxattr, flistxattr */
                      : (nr == 5 || nr == 193 || nr == 196)) {
        at = 0;
    } else {
        return 0;
    }
    if (at) {
        char first = 0;
        if ((flags & AT_EMPTY_PATH) == 0 || fd == AT_FDCWD) return 0;
        if (name != 0 && (bpf_probe_read_user(&first, 1, (void*)name) != 0 || first != 0)) return 0;
    }
    struct file* file = fd_file(task, fd);
    return file && BPF_CORE_READ(file, f_path.dentry) == dentry && granted(file, 0);
}

/*
 * Rights (QUERY; a watch enumerate or read) on Dentry, named as its open would be: by Path when
 * the hook has one, else on its filesystem's first mount; /proc/@self...; /anon/... only by a
 * rule naming it. A device node is a file here (device rules' uses are for opens and ioctls).
 * Fds: a query on a decided open is not decided again.
 * shortcut: no per-dentry cache, so each stat walks its path; add an LRU {tgid, dentry,
 * generation} if the cost shows.
 */
__noinline int kb_query(__u64 pathAddress, __u64 dentryAddress, __u32 rights, __u32 fds)
{
    const __u32 files = KFILTER_CFG_BLOCK_FILES | KFILTER_CFG_BLOCK_FILE_QUERIES;
    const struct path* path = (const struct path*)pathAddress;
    struct dentry* dentry = (struct dentry*)dentryAddress;
    struct kb_cfg* c = kb_cfg_get();
    struct kb_scratch* s = scratch();
    struct inode* inode = BPF_CORE_READ(dentry, d_inode);
    if (!c || !s || !inode || !c->enabled || c->mode == KFILTER_MODE_OFF || (c->flags & files) != files ||
        pseudo_fs(inode)) return 0;
    if (fds && fd_granted(dentry)) return 0;
    if (path) walk_path(path);
    else walk_inode_dentry(dentry);
    kb_proc_name();   /* /proc/<pid>/...: as whose it is, on procfs or not (an fd link's target is not) */
    if (!s->failed && s->len == 1) return 0;   /* "/": no rule can name it */
    return kb_decide_global(dentry_target(dentry), rights, 0, !s->failed && starts_with(s, "/anon/", 6));
}

/* kb_query from a hook (global: verified once for the seven programs). */
static __always_inline int decide_query(const struct path* path, struct dentry* dentry, __u32 rights, int fds)
{
    return kb_decided(kb_query(address_of(path), address_of(dentry), rights, fds));
}

/* stat, lstat, fstatat, statx, fstat. */
SEC("lsm/inode_getattr")
int BPF_PROG(kb_inode_getattr, const struct path* path, int ret)
{
    if (ret != 0) return ret;
    BEGIN();
    return decide_query(path, BPF_CORE_READ(path, dentry), KFILTER_RIGHT_QUERY, 1);
}

/* access, faccessat, faccessat2 (MAY_ACCESS); every other permission check returns at once.
 * shortcut: an inode hook, so named by the inode's first alias; a hard link is decided under
 * that name. Read the path from the syscall if that matters. */
SEC("lsm/inode_permission")
int BPF_PROG(kb_inode_access, struct inode* inode, int mask, int ret)
{
    if (ret != 0 || (mask & (MAY_ACCESS | MAY_CHDIR)) == 0) return ret;
    if ((mask & MAY_CHDIR) != 0 && !gated(KB_GATE_CHDIR)) return 0;
    BEGIN();
    struct hlist_node* first = BPF_CORE_READ(inode, i_dentry.first);
    if (!first) return 0;
    struct dentry* dentry = (struct dentry*)((void*)first - bpf_core_field_offset(struct dentry, d_u.d_alias));
    if ((mask & MAY_CHDIR) != 0) {
        /* chdir, fchdir, chroot (ABI 11): dir right chdir, rule-only, named by the inode's first alias as access is. */
        walk_inode_dentry(dentry);
        return kb_decided(kb_decide_global(KFILTER_TARGET_DIR, KFILTER_RIGHT_CHDIR, 0, 1));
    }
    return decide_query(0, dentry, KFILTER_RIGHT_QUERY, 0);
}

/* readlink, readlinkat (realpath's walk; /proc/self/fd/N). */
SEC("lsm/inode_readlink")
int BPF_PROG(kb_inode_readlink, struct dentry* dentry, int ret)
{
    if (ret != 0) return ret;
    BEGIN();
    return decide_query(0, dentry, KFILTER_RIGHT_QUERY, 0);
}

/* getxattr, lgetxattr, fgetxattr (Wine's user.DOSATTRIB). */
SEC("lsm/inode_getxattr")
int BPF_PROG(kb_inode_getxattr, struct dentry* dentry, const char* name, int ret)
{
    if (ret != 0) return ret;
    BEGIN();
    return decide_query(0, dentry, KFILTER_RIGHT_QUERY, 1);
}

SEC("lsm/inode_listxattr")
int BPF_PROG(kb_inode_listxattr, struct dentry* dentry, int ret)
{
    if (ret != 0) return ret;
    BEGIN();
    return decide_query(0, dentry, KFILTER_RIGHT_QUERY, 1);
}

/* A change watch (inotify, fanotify, dnotify) shows what a listing or a read would: enumerate
 * on a directory, read on a file. The path is resolved (a watch through /proc/self/fd/N names
 * the directory); wineserver's watch for ReadDirectoryChangesW is the client's (brokered). */
SEC("lsm/path_notify")
int BPF_PROG(kb_path_notify, const struct path* path, __u64 mask, unsigned int obj_type, int ret)
{
    if (ret != 0) return ret;
    BEGIN();
    struct dentry* dentry = BPF_CORE_READ(path, dentry);
    return decide_query(path, dentry, dentry_target(dentry) == KFILTER_TARGET_DIR ? KFILTER_RIGHT_ENUMERATE
                                                                                   : KFILTER_RIGHT_READ, 0);
}

/* statfs, fstatfs: f_fsid folds the ext4 UUID. Logged (an audit volume event, value 0) with
 * block-volume-serial, never refused: Wine checks filesystem types with it.
 * shortcut: f_fsid itself is not hidden; an fexit zeroing it is the upgrade if Windows code is
 * seen reading it. */
/* statfs and fstatfs as /system/statfs<path> (ABI 11), query, rule-only (kfilterctl check warns: Wine checks filesystem
 * types with it); a path too long to prefix passes. */
__noinline int kb_statfs_decide(__u64 dentryAddress)
{
    struct kb_scratch* s = scratch();
    if (!s) return 0;
    walk_inode_dentry((struct dentry*)dentryAddress);
    __u32 len = s->len;
    if (s->failed || len == 0 || len >= KB_PATH - 16) {
        s->failed = 0;
        return 0;
    }
    bpf_probe_read_kernel_str(s->walk, KB_PATH, s->path);
    set_path(s, "/system/statfs", 14);
    bpf_probe_read_kernel_str(&s->path[14], KB_PATH - 16, s->walk);
    s->len = len + 14;
    return kb_system_decide(KFILTER_RIGHT_QUERY, KB_ROOT(14));
}

SEC("lsm/sb_statfs")
int BPF_PROG(kb_sb_statfs, struct dentry* dentry, int ret)
{
    if (ret != 0) return ret;
    BEGIN();
    if (gated(KB_GATE_STATFS) && kb_statfs_decide(address_of(dentry)) != 0) return -EPERM;
    struct kb_cfg* c = kb_cfg_get();
    struct inode* inode = BPF_CORE_READ(dentry, d_inode);
    if (!c || !inode || !c->enabled || c->mode == KFILTER_MODE_OFF || (c->flags & KFILTER_CFG_BLOCK_VOLUME_SERIAL) == 0 ||
        pseudo_fs(inode)) return 0;
    walk_inode_dentry(dentry);
    emit(KB_EV_DECISION, KFILTER_TARGET_VOLUME, KFilterActionAudit, 0, 0, 0, 0, KFILTER_RIGHT_QUERY, 1);
    return 0;
}

/*
 * A driver (.sys) winedevice.exe maps as code. winedevice serves no protected program while it
 * loads one (services.exe starts it, outside the family), so this is winedevice's own file
 * execute (image=winedevice.exe), decided only where a rule names it.
 */
__noinline int kb_driver_load(__u64 fileAddress)
{
    __u32 tgid = current_tgid();
    struct kb_proc* proc = bpf_map_lookup_elem(&kb_procs, &tgid);
    if (!proc || !proc->device_host) return 0;
    struct kb_scratch* s = reset_for(tgid, 0);
    if (!s) return 0;
    walk_file((struct file*)fileAddress);
    if (s->failed || extension_mask(s) != KFILTER_EXT_SYS) return 0;
    return kb_decide_global(KFILTER_TARGET_FILE, KFILTER_RIGHT_EXECUTE, 0, 1);
}

/* BEGIN for a code mapping: a task that works for no protected program may still be
 * winedevice loading a driver. */
#define BEGIN_CODE(file)                                                         \
    do {                                                                         \
        int started_ = begin();                                                  \
        if (started_ < 0) return -ENOMEM;                                        \
        if (started_ > 0) {                                                      \
            struct kb_task* role_ = task_state(bpf_get_current_task_btf());      \
            if (!role_ || role_->role != KB_ROLE_WINE) return 0;                 \
            return kb_decided(kb_driver_load(address_of(file)));                 \
        }                                                                        \
    } while (0)

/* [Start, End) that the mmap or mprotect being made asks for (x86_64, and int 0x80); Start 0 when
 * unknown (the old i386 mmap passes a struct). */
static __always_inline __u64 request_range(__u64* end)
{
    struct task_struct* task = bpf_get_current_task_btf();
    struct pt_regs* regs = (struct pt_regs*)bpf_task_pt_regs(task);
    if (!regs) return 0;
    long nr = BPF_CORE_READ(regs, orig_ax);
    __u64 start, length;
    if ((BPF_CORE_READ(task, thread_info.status) & TS_COMPAT) != 0) {
        if (nr != 192 && nr != 125 && nr != 380) return 0;   /* mmap2, mprotect, pkey_mprotect */
        start = BPF_CORE_READ(regs, bx) & 0xFFFFFFFFull;
        length = BPF_CORE_READ(regs, cx) & 0xFFFFFFFFull;
    } else {
        if (nr != 9 && nr != 10 && nr != 329) return 0;
        start = BPF_CORE_READ(regs, di);
        length = BPF_CORE_READ(regs, si);
    }
    *end = start + length;
    return start;
}

/* A Wine process maps a file at offset 0 in place (MAP_FIXED): an image view's header (kb_views). */
static __always_inline void note_view(unsigned long flags)
{
    if ((flags & (MAP_FIXED | MAP_FIXED_NOREPLACE)) == 0) return;
    struct task_struct* task = bpf_get_current_task_btf();
    struct kb_task* state = task_state(task);
    struct pt_regs* regs = (struct pt_regs*)bpf_task_pt_regs(task);
    if (!state || state->role != KB_ROLE_WINE || !regs) return;
    int compat = (BPF_CORE_READ(task, thread_info.status) & TS_COMPAT) != 0;
    __u64 offset = compat ? BPF_CORE_READ(regs, bp) : BPF_CORE_READ(regs, r9);
    __u64 end = 0;
    __u64 base = request_range(&end);
    if (base == 0 || offset != 0 || BPF_CORE_READ(regs, orig_ax) != (compat ? 192 : 9)) return;
    struct kb_view view = {current_tgid(), 0, base};
    __u32 one = 1;
    bpf_map_update_elem(&kb_views, &view, &one, BPF_ANY);
}

/* The shmem file of shared anonymous memory (MAP_SHARED|MAP_ANONYMOUS, a shared /dev/zero mapping). */
static __always_inline int shared_anonymous(struct file* file)
{
    struct dentry* d = BPF_CORE_READ(file, f_path.dentry);
    __u64 name = 0;
    if (!d || BPF_CORE_READ(d, d_parent) != d || BPF_CORE_READ(d, d_name.len) != 8) return 0;
    bpf_probe_read_kernel(&name, 8, BPF_CORE_READ(d, d_name.name));
    return name == 0x6f72657a2f766564ull;   /* "dev/zero" */
}

/* The /dev/zero device (1:5): mapping it makes anonymous memory (private, or shmem's "dev/zero" when shared). */
static __always_inline int dev_zero(struct file* file)
{
    struct inode* inode = BPF_CORE_READ(file, f_inode);
    return (inode_mode(inode) & S_IFMT) == S_IFCHR && BPF_CORE_READ(inode, i_rdev) == ((1u << 20) | 5);
}

/* A non-executable anonymous mmap waiting for its address (lsm/mmap_file has none unless MAP_FIXED, lsm/mmap_addr gets the
 * one the kernel picked; nothing else runs between them): its length and protection, for the syscall it was made in. */
struct kb_map_stash {
    __u64 length;
    __u32 prot;
    __u32 shared;
    long nr;
};

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct kb_map_stash);
} kb_map_stashes SEC(".maps");

/* lsm/mmap_file's half: a protected program's non-executable anonymous mmap (Data) is stashed for lsm/mmap_addr; any other
 * mmap clears the stash, so one a failed mmap left (it never reached mmap_addr: a zero length, no room) never decides a
 * later mapping. */
__noinline int kb_map_stash(__u32 prot, __u32 flags, __u32 data)
{
    struct kb_cfg* c = kb_cfg_get();
    if (!c || (c->memory_rules & KB_MEMORY_DATA) == 0) return 0;
    struct task_struct* task = bpf_get_current_task_btf();
    if (!data || !protected_current()) {
        struct kb_map_stash* stale = bpf_task_storage_get(&kb_map_stashes, task, 0, 0);
        if (stale) stale->nr = 0;
        return 0;
    }
    struct pt_regs* regs = (struct pt_regs*)bpf_task_pt_regs(task);
    struct kb_map_stash* stash = bpf_task_storage_get(&kb_map_stashes, task, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!stash || !regs) return 0;
    __u64 end = 0;
    __u64 start = request_range(&end);
    stash->length = end > start ? end - start : 0;   /* 0: unknown (the old i386 mmap passes a struct) */
    stash->prot = prot;
    stash->shared = (flags & MAP_SHARED) != 0;
    stash->nr = BPF_CORE_READ(regs, orig_ax);
    return 0;
}

/* lsm/mmap_addr's half: the mmap kb_map_stash stashed in this syscall, decided at Addr, where the kernel placed it. */
__noinline int kb_map_stashed(__u64 addr)
{
    struct kb_cfg* c = kb_cfg_get();
    struct task_struct* task = bpf_get_current_task_btf();
    struct kb_map_stash* stash = c && (c->memory_rules & KB_MEMORY_DATA) != 0
                                     ? bpf_task_storage_get(&kb_map_stashes, task, 0, 0) : 0;
    if (!stash || stash->nr == 0) return 0;
    struct pt_regs* regs = (struct pt_regs*)bpf_task_pt_regs(task);
    long nr = stash->nr;
    stash->nr = 0;
    if (!regs || BPF_CORE_READ(regs, orig_ax) != nr) return 0;
    return kb_memory_decide(addr, stash->length != 0 ? addr + stash->length : 0, stash->prot, stash->shared);
}

/*
 * A file a protected program maps into memory (mmap; under Wine MapViewOfFile, NtMapViewOfSection and image
 * views): a system decision on /system/map<its path>, execute for code, read for data, plus write for a
 * shared writable view, with the calling module for module= rules. Every mapping, not only an open's first:
 * only while a system rule can name /system/map/ (map_rules). Rule-only; a path too long to prefix passes.
 */
__noinline int kb_map_decide(__u64 fileAddress, __u32 rights)
{
    struct kb_scratch* s = scratch();
    if (!s) return 0;
    walk_file((struct file*)fileAddress);
    __u32 len = s->len;
    if (s->failed || len == 0 || len >= KB_PATH - 16) {
        s->failed = 0;   /* the file decision that follows walks it again */
        return 0;
    }
    bpf_probe_read_kernel_str(s->walk, KB_PATH, s->path);
    set_path(s, "/system/map", 11);
    bpf_probe_read_kernel_str(&s->path[11], KB_PATH - 16, s->walk);
    s->len = len + 11;
    return kb_system_decide(rights, 1);
}

/* A mapping of a file: execute for code, read for data, write for a shared writable view;
 * within an open's decided rights it is not decided again. Executable anonymous memory (a
 * /dev/zero mapping too) is kb_memory_decide's. */
SEC("lsm/mmap_file")
int BPF_PROG(kb_mmap_file, struct file* file, unsigned long reqprot, unsigned long prot, unsigned long flags, int ret)
{
    if (ret != 0) return ret;
    if ((prot & PROT_EXEC) != 0) modules_changed(current_tgid());
    /* 7.0.0-43 marks the hook's file trusted_ptr_or_null and wants it null-checked as a pointer (a check by
     * value was refused: "pointer arithmetic on trusted_ptr_or_null_"); older kernels take it for non-NULL. */
    if (!file || ((prot & PROT_EXEC) != 0 && dev_zero(file))) {
        kb_map_stash(prot, flags, (prot & PROT_EXEC) == 0);
        if ((prot & PROT_EXEC) == 0) return 0;
        __u64 end = 0;
        __u64 start = (flags & (MAP_FIXED | MAP_FIXED_NOREPLACE)) != 0 ? request_range(&end) : 0;
        return kb_decided(kb_memory_decide(start, end, prot, (flags & MAP_SHARED) != 0));
    }
    kb_map_stash(prot, flags, 0);
    note_view(flags);
    if ((prot & PROT_EXEC) != 0) BEGIN_CODE(file);
    else BEGIN();
    __u32 rights = (prot & PROT_EXEC) != 0 ? KFILTER_RIGHT_EXECUTE : KFILTER_RIGHT_READ;
    __u32 write = (flags & MAP_SHARED) != 0 && (prot & PROT_WRITE) != 0 ? KFILTER_RIGHT_WRITE : 0;
    struct kb_cfg* c = kb_cfg_get();
    if (c && c->map_rules) {
        int mapped = kb_decided(kb_map_decide(address_of(file), rights | write));
        if (mapped != 0) return mapped;
    }
    if ((prot & PROT_EXEC) != 0) return decide_file(file, KFILTER_TARGET_FILE, KFILTER_RIGHT_EXECUTE, 1);
    return decide_file(file, KFILTER_TARGET_FILE, rights | write, 1);
}

/*
 * wbemprox.dll's code turning executable in a protected program while a rule can name /system/wmi/:
 * the program stops (SIGSTOP, taken when the mprotect returns) until kfilterd has put kb_wmi on its
 * IWbemServices methods and resumed it, so no query runs before the probe (a uprobe is installed only in code
 * that was not writable when it registered, and Wine maps sections writable first). Only while
 * kfilterd runs: no one else would resume it (kb_wmi_stopped keeps it for the next kfilterd).
 */
static __always_inline void wmi_provider(struct file* file)
{
    struct kb_cfg* c = kb_cfg_get();
    if (!c || !c->wmi_rules || !c->enabled || c->mode == KFILTER_MODE_OFF || !protected_current()) return;
    struct {
        __u64 head;
        __u32 tail;
    } name = {};
    struct dentry* d = BPF_CORE_READ(file, f_path.dentry);
    if (BPF_CORE_READ(d, d_name.len) != 12 || bpf_probe_read_kernel(&name, 12, BPF_CORE_READ(d, d_name.name)) != 0 ||
        name.head != 0x786f72706d656277ull || name.tail != 0x6c6c642eu)   /* "wbemprox", ".dll" */
        return;
    struct task_struct* daemon = c->daemon_tgid ? bpf_task_from_pid(c->daemon_tgid) : 0;
    if (!daemon) return;
    bpf_task_release(daemon);
    __u32 tgid = current_tgid(), tid = current_tid();
    /* Left unprobed rather than stopped with no one told, or with no record to resume it by. */
    if (bpf_map_update_elem(&kb_wmi_stopped, &tgid, &tid, BPF_ANY) != 0) return;
    struct kb_event* e = bpf_ringbuf_reserve(&kb_events, sizeof(*e), 0);
    if (!e) {
        bpf_map_delete_elem(&kb_wmi_stopped, &tgid);
        return;
    }
    __builtin_memset(e, 0, sizeof(*e));
    e->kind = KB_EV_WMI;
    e->tgid = tgid;
    e->value = tid;
    bpf_ringbuf_submit(e, 0);
    bpf_send_signal(SIGSTOP);
}

/* mprotect of anonymous memory to read, read-write or none (ABI 11, KB_MEMORY_DATA): kb_memory_decide on its range. */
static __always_inline int memory_protect(struct vm_area_struct* vma, unsigned long prot)
{
    struct kb_cfg* c = kb_cfg_get();
    if (!c || (c->memory_rules & KB_MEMORY_DATA) == 0) return 0;
    struct file* file = BPF_CORE_READ(vma, vm_file);
    int zero = file && dev_zero(file);
    if (file && !zero && !shared_anonymous(file)) return 0;   /* a file's pages */
    __u64 end = 0;
    __u64 start = request_range(&end);
    return kb_decided(kb_memory_decide(start, end, prot, file && !zero));
}

SEC("lsm/file_mprotect")
int BPF_PROG(kb_file_mprotect, struct vm_area_struct* vma, unsigned long reqprot, unsigned long prot, int ret)
{
    if (ret != 0) return ret;
    if ((prot & PROT_EXEC) == 0) return memory_protect(vma, prot);
    modules_changed(current_tgid());   /* Wine maps a module's sections writable, then makes its code executable */
    struct file* file = BPF_CORE_READ(vma, vm_file);
    __u64 had = BPF_CORE_READ(vma, vm_flags);
    int zero = file && dev_zero(file);   /* a private /dev/zero mapping keeps the device as its file */
    if (!file || zero || shared_anonymous(file)) {
        /* Decided when it becomes executable, or writable as well. */
        if ((had & VM_EXEC) != 0 && ((prot & PROT_WRITE) == 0 || (had & VM_WRITE) != 0)) return 0;
        __u64 end = 0;
        __u64 start = request_range(&end);
        return kb_decided(kb_memory_decide(start, end, prot, file && !zero));
    }
    if ((had & VM_EXEC) != 0) return 0;
    wmi_provider(file);
    BEGIN_CODE(file);
    return decide_file(file, KFILTER_TARGET_FILE, KFILTER_RIGHT_EXECUTE, 1);
}

/* ---- processes ---- */

/* KfPolicyMatchesProtectedName on s->path: under the root, or ending in a '/' protect name. */
static __always_inline int protected_name(struct kb_cfg* c, struct kb_scratch* s)
{
    if (s->failed) return 0;
    if (root_matches(c, s)) return 1;
    for (__u32 n = 0; n < KB_NAMES; n++) {
        if (n >= c->name_count) break;
        __u32 len = c->name_len[n];
        if (len == 0 || len >= KB_NAME || len > s->len || c->names[n][0] == '\\') continue;
        __u32 start = s->len - len;
        int same = 1;
        for (__u32 i = 0; i < KB_NAME; i++) {
            if (i >= len) break;
            if (s->path[(start + i) & (KB_PATH - 1)] != c->names[n][i]) {
                same = 0;
                break;
            }
        }
        if (same && (c->names[n][0] == '/' || start == 0 || s->path[(start - 1) & (KB_PATH - 1)] == '/')) return 1;
    }
    return 0;
}

/* TakeLaunchPass: the armed creator starts the image itself, or a LAUNCH broker whose
 * parent is the creator does. */
static __always_inline int take_launch_pass(struct task_struct* task)
{
    __u32 zero = 0;
    struct kb_launch* pass = bpf_map_lookup_elem(&kb_launch_pass, &zero);
    if (!pass || pass->until_ns == 0 || bpf_ktime_get_ns() >= pass->until_ns || pass->left == 0) return 0;
    struct kb_scratch* s = scratch();
    if (!s) return 0;
    s->failed = 0;
    walk_exe(task);   /* still the pre-exec image */
    int creator = base_is(s, pass) || windows_creator_is(BPF_CORE_READ(task, tgid), pass);
    if (!creator) {
        struct task_struct* parent = BPF_CORE_READ(task, real_parent);
        s->failed = 0;
        walk_exe(parent);
        if (!base_is(s, pass) && !windows_creator_is(BPF_CORE_READ(parent, tgid), pass)) return 0;
        s->failed = 0;
        walk_exe(task);
        __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        if ((kb_outside_rights(KFILTER_TARGET_LAUNCH, KFILTER_RIGHT_CREATE, uid == 0) & KFILTER_RIGHT_CREATE) == 0) return 0;
    }
    return spend_launch_pass(pass);
}

static __always_inline int same_as_expect(struct kb_scratch* s, struct kb_task* state)
{
    __u32 n = state->expect_len;
    if (n != s->len || n >= KB_PATH) return 0;
    for (__u32 i = 0; i < KB_PATH; i++) {
        if (i >= n) break;
        if (s->path[i] != state->expect[i]) return 0;
    }
    return 1;
}

/* The Wine role of an exec'd image: its loaders run Windows programs; wineserver brokers. */
static __always_inline __u32 wine_role(struct kb_scratch* s)
{
    if (s->failed) return KB_ROLE_NONE;
    if (ends_with(s, "/wineserver", 11)) return KB_ROLE_WINESERVER;
    if (ends_with(s, "/wine", 5) || ends_with(s, "/wine64", 7) || ends_with(s, "/wine-preloader", 15) ||
        ends_with(s, "/wine64-preloader", 17)) return KB_ROLE_WINE;
    return KB_ROLE_NONE;
}

/* KfProcessExec: the launch handshake image check, and admission of a protected image
 * started outside the launcher (refused in block mode without the launch pass). Also marks
 * Wine's loaders and wineserver: wineserver is never itself protected, its work is charged
 * to the client it serves. */
/* bpf_for_each_map_elem callback: forgets one Windows id (kb_wintids). shortcut: every id, so a second
 * Wine prefix's server running at the same time loses its ids too; upgrade: key ids by wineserver. */
static long forget_id(struct bpf_map* map, __u32* key, __u32* value, void* ctx)
{
    bpf_map_delete_elem(map, key);
    return 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(kb_bprm_check, struct linux_binprm* bprm, int ret)
{
    if (ret != 0) return ret;
    struct kb_cfg* c = kb_cfg_get();
    if (!c) return 0;
    struct task_struct* task = bpf_get_current_task_btf();
    struct kb_task* state = task_state(task);
    __u32 tgid = current_tgid();
    struct kb_scratch* s = reset_for(tgid, 0);
    if (!s) {
        /* Without working memory the image cannot be named. Only an exec inside the family
         * is refused; any other program's exec must never fail because of kfilter. */
        int enforce = c->mode == KFILTER_MODE_BLOCK && (c->flags & KFILTER_CFG_BLOCK_PROCESS_CREATE) != 0;
        return enforce && state && state->guarded ? -ENOMEM : 0;
    }
    walk_file(BPF_CORE_READ(bprm, file));
    __u32 role = wine_role(s);
    /* A new wineserver numbers Windows processes and threads afresh: the ids the last one gave out now
     * name other threads (a stale id named a dead process, its threads' opens decided as outside). */
    if (role == KB_ROLE_WINESERVER) bpf_for_each_map_elem(&kb_wintids, forget_id, 0, 0);
    int result = 0;
    if (state) state->forked = 0;   /* its own program now: its children name it as creator */
    if (!c->enabled || c->mode == KFILTER_MODE_OFF) {
        /* No policy: nothing is decided, but Wine's roles are, so a policy loaded later
         * finds wineserver and its clients' pipes already known. */
        if (role != KB_ROLE_NONE) {
            if (!state) state = bpf_task_storage_get(&kb_tasks, task, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
            if (state) {
                state->role = role;
                if (role == KB_ROLE_WINESERVER) state->guarded = 0;
                state->client = 0;
            }
        } else if (state) {
            state->role = KB_ROLE_NONE;
        }
        if (!state) bpf_task_storage_delete(&kb_scratch_tasks, task);
        return 0;
    }
    if (state && state->guarded) {
        if (state->expect_len != 0) {
            int mismatch = !same_as_expect(s, state);
            state->expect_len = 0;
            if (mismatch) {
                int block = c->mode == KFILTER_MODE_BLOCK;
                emit(KB_EV_DECISION, KFILTER_TARGET_PROCESS, block ? KFilterActionDeny : KFilterActionAudit,
                     KFILTER_EVENT_FLAG_PROCESS_CREATE, STATUS_OBJECT_NAME_INVALID, 0, 0, KFILTER_RIGHT_CREATE, 1);
                if (block) return -EPERM;
            }
        }
        if (role == KB_ROLE_WINESERVER) {
            /* A wineserver the family starts serves whoever connects; it leaves the family. */
            state->guarded = 0;
            state->role = KB_ROLE_WINESERVER;
            struct kb_event* e = bpf_ringbuf_reserve(&kb_events, sizeof(*e), 0);
            if (e) {
                __builtin_memset(e, 0, sizeof(*e));
                e->kind = KB_EV_EXIT;
                e->tgid = tgid;
                bpf_ringbuf_submit(e, 0);
            }
            return 0;
        }
        if (role != KB_ROLE_NONE) state->role = role;
        return 0;
    }
    if (protected_name(c, s)) {
        int enforce = c->mode == KFILTER_MODE_BLOCK && (c->flags & KFILTER_CFG_BLOCK_PROCESS_CREATE) != 0;
        if (enforce) {
            if (!take_launch_pass(task)) {
                walk_file(BPF_CORE_READ(bprm, file));
                emit(KB_EV_DECISION, KFILTER_TARGET_PROCESS, KFilterActionDeny, KFILTER_EVENT_FLAG_PROCESS_CREATE,
                     STATUS_ACCESS_DENIED, 0, 0, KFILTER_RIGHT_CREATE, 1);
                return -EPERM;
            }
            walk_file(BPF_CORE_READ(bprm, file));
            emit(KB_EV_DECISION, KFILTER_TARGET_PROCESS, KFilterActionAllow, KFILTER_EVENT_FLAG_PROCESS_CREATE, 0, 0, 0,
                 KFILTER_RIGHT_CREATE, 1);
        }
        /* Admitted as a family root: children it forked before this exec stay outside. */
        state = bpf_task_storage_get(&kb_tasks, task, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
        if (!state) return enforce ? -EPERM : 0;
        state->guarded = 1;
        state->expect_len = 0;
        if (role == KB_ROLE_WINE) state->role = role;
        /* Marked here, before kfilterd hears of it: its KfBpfProtect then leaves the entry alone (it would otherwise
         * write back a copy read before kb_exec_name names the program). */
        struct kb_proc* admitted = proc_entry(tgid);
        if (admitted) admitted->guarded = 1;
        emit(KB_EV_PROTECT, 0, 0, 0, 0, 0, 0, 0, 1);
        return 0;
    }
    if (role != KB_ROLE_NONE) {
        state = bpf_task_storage_get(&kb_tasks, task, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
        if (state) {
            state->role = role;
            state->guarded = 0;
            state->client = 0;
        }
        return 0;
    }
    if (state) state->role = KB_ROLE_NONE;
    /* Nothing kfilter needs from this program: give its working memory back. */
    if (!state) bpf_task_storage_delete(&kb_scratch_tasks, task);
    return result;
}

/* A task created by a protected task is protected before it exists for anyone else; a
 * Wine thread or wineserver's child keeps its role. A protected program's thread is a
 * thread decision where a thread rule exists. */
SEC("lsm/task_alloc")
int BPF_PROG(kb_task_alloc, struct task_struct* task, u64 clone_flags, int ret)
{
    if (ret != 0) return ret;
    struct task_struct* current = bpf_get_current_task_btf();
    struct kb_task* parent = task_state(current);
    if (!parent) return 0;
    int guarded = task_protected(current, parent);
    if (!guarded && parent->role == KB_ROLE_NONE) return 0;
    if (guarded && (clone_flags & CLONE_THREAD) != 0) {
        struct kb_cfg* c = kb_cfg_get();
        if (c && (c->targets & KFILTER_TARGET_THREAD) != 0 && kb_thread_decide(0) != 0) return -EPERM;
    } else if (guarded && gated(KB_GATE_FORK) && kb_thread_decide(1) != 0) {
        return -EPERM;   /* a fork, vfork or clone of a process: /system/fork */
    }
    struct kb_task* state = bpf_task_storage_get(&kb_tasks, task, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    /* Refuse the fork rather than create an unprotected member of the family. */
    if (!state) return guarded ? -EPERM : 0;
    state->guarded = guarded;
    state->expect_len = 0;
    state->role = parent->role;
    state->pipes = 0;
    state->client = 0;
    state->client_tid = 0;
    if ((clone_flags & CLONE_THREAD) != 0) {
        state->creator = parent->creator;
        state->forked = parent->forked;
    } else {
        state->creator = parent->forked && parent->creator != 0 ? parent->creator : current_tgid();
        state->forked = 1;
    }
    return 0;
}

/* A protected Linux program is named by its executable once its exec has succeeded, so image= rules can be scoped
 * to it (the Chrome sign-in hand-off: gio, chrome; before, only Wine's Windows names were known, so image=gio never
 * matched). Every exec is a new program: a Wine program's child exec'ing xdg-open is xdg-open's interpreter now. A
 * Wine loader's exec clears the name for Wine's own (kb_wine_name, from argv[0], once). */
/* bpf_for_each_map_elem callback: forgets one window's owner (kb_windows). */
static long forget_window(struct bpf_map* map, __u32* key, struct kb_window* value, void* ctx)
{
    value->gen = 0;
    value->tgid = 0;
    return 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(kb_exec_name, struct task_struct* task, pid_t old_pid, struct linux_binprm* bprm)
{
    struct kb_task* state = task_state(task);
    /* A new wineserver numbers windows afresh, as it does thread ids (kb_bprm_check forgets those): every owner the
     * last one's windows had is stale. Here, not in kb_bprm_check, which is near the verifier's limit. */
    if (state && state->role == KB_ROLE_WINESERVER) bpf_for_each_map_elem(&kb_windows, forget_window, 0, 0);
    if (!state || !state->guarded) return 0;
    __u32 tgid = BPF_CORE_READ(task, tgid);
    struct kb_proc* proc = proc_entry(tgid);
    if (!proc) return 0;
    proc->guarded = 1;   /* as KfBpfProtect would: it then leaves this entry alone */
    struct kb_scratch* s = reset_for(tgid, 0);
    if (!s) return 0;
    walk_file(BPF_CORE_READ(bprm, file));
    /* A new program: its own name. A Wine loader (or a path too long to keep) is named by Wine's argv[0] later. */
    proc->device_host = 0;
    if (wine_role(s) != KB_ROLE_NONE || s->failed || s->len < 2 || s->len >= KB_PROG) {
        proc->ilen = 0;
        proc->unix_image = 0;
        proc->image[0] = 0;
        return 0;
    }
    bpf_probe_read_kernel(proc->image, KB_PROG, s->path);
    proc->image[s->len & (KB_PROG - 1)] = 0;
    proc->ibase = 0;
    struct base_ctx base = {tgid, s->len};
    bpf_loop(KB_PROG, base_step, &base, 0);
    if (proc->ibase >= KB_PROG) proc->ibase = 0;
    proc->ilen = s->len;
    proc->unix_image = 1;
    return 0;
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(kb_fork, struct task_struct* parent, struct task_struct* child)
{
    if (BPF_CORE_READ(child, pid) != BPF_CORE_READ(child, tgid) || !task_protected(child, task_state(child))) return 0;
    /* The child runs its parent's program until it execs: it has the parent's name (gio's fork read Chrome's
     * SingletonLock before exec'ing gio-launch-desktop, unnamed, so image=gio did not apply). Marked protected
     * here, before kfilterd hears of it (KfBpfProtect then leaves the entry alone). */
    __u32 ptgid = BPF_CORE_READ(parent, tgid), ctgid = BPF_CORE_READ(child, tgid);
    struct kb_proc* from = bpf_map_lookup_elem(&kb_procs, &ptgid);
    struct kb_proc* to = proc_entry(ctgid);
    if (to) {
        to->guarded = 1;
        if (from && from->ilen != 0 && from->ilen < KB_PROG && to->ilen == 0) {
            bpf_probe_read_kernel(to->image, KB_PROG, from->image);
            to->ilen = from->ilen;
            to->ibase = from->ibase;
            to->unix_image = from->unix_image;
            to->device_host = from->device_host;
        }
    }
    struct kb_event* e = bpf_ringbuf_reserve(&kb_events, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    e->kind = KB_EV_PROTECT;
    e->tgid = BPF_CORE_READ(child, tgid);
    e->ppid = BPF_CORE_READ(parent, tgid);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(kb_exit, struct task_struct* task, bool group_dead)
{
    if (!group_dead) return 0;
    __u32 tgid = BPF_CORE_READ(task, tgid);
    /* A killed or crashed kfilterd leaves no ptrace exemption for whoever gets its pid next
     * (its atexit never ran). Its pid is not reused before the group is dead. */
    struct kb_cfg* c = kb_cfg_get();
    if (c && c->daemon_tgid == tgid) c->daemon_tgid = 0;
    struct kb_task* state = task_state(task);
    if (!state) return 0;
    int wasProtected = task_protected(task, state);
    bpf_map_delete_elem(&kb_procs, &tgid);
    if (!wasProtected) return 0;
    struct kb_event* e = bpf_ringbuf_reserve(&kb_events, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    e->kind = KB_EV_EXIT;
    e->tgid = tgid;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/*
 * A family member reaching another member's (Child, protected) memory itself (not wineserver for a client):
 * process_vm_readv/writev is a peer decision on that program with the remote iovecs (the first KB_ACCESS; more, or
 * a list it cannot read, is an unknown address); a ptrace attach (or seize), after which it can read and write any
 * address and debug register, a peer and a thread-peer decision with every right on an unknown address. Never
 * decided before addr= existed, so only while an addr= rule is loaded, and only such rules meet them, with or without
 * block-process-memory. Yama's ptrace scope 1 (checked first) leaves this to a parent and its descendants. Other
 * attach checks in the family (/proc/<pid>/mem opens, pidfd_getfd) carry no address and stay undecided.
 * shortcut: the iovecs are read again from the caller's memory after process_vm_rw copied them, so another thread
 * can change them in between (as a Wine request's data; LINUX.md, "Addresses read twice"); decide on the kernel's
 * copy (an fexit on iovec_from_user) if that matters.
 */
__noinline int kb_native_peer(__u64 childAddress)
{
    struct kb_cfg* c = kb_cfg_get();
    struct task_struct* task = bpf_get_current_task_btf();
    struct task_struct* child = (struct task_struct*)childAddress;
    struct kb_task* state = task_state(task);
    struct pt_regs* regs = (struct pt_regs*)bpf_task_pt_regs(task);
    if (!c || !state || !regs || !c->enabled || c->mode == KFILTER_MODE_OFF || (c->flags & KB_CFG_ADDRESS) == 0 ||
        (c->targets & (KFILTER_TARGET_PEER | KFILTER_TARGET_THREAD_PEER)) == 0 || state->role == KB_ROLE_WINESERVER)
        return 0;
    __u32 tgid = current_tgid(), object = BPF_CORE_READ(child, tgid);
    if (object == tgid || !task_protected(task, state)) return 0;
    /* An io_uring worker's pt_regs are its creator's at a past syscall: it makes no process_vm or ptrace call. */
    if ((BPF_CORE_READ(task, flags) & (PF_IO_WORKER | PF_KTHREAD)) != 0) return 0;
    long nr = BPF_CORE_READ(regs, orig_ax);
    int compat = (BPF_CORE_READ(task, thread_info.status) & TS_COMPAT) != 0;
    int attach = compat ? nr == 26 : nr == 101;   /* ptrace */
    if (!attach && (compat ? nr != 347 && nr != 348 : nr != 310 && nr != 311)) return 0;   /* process_vm_readv, ..._writev */
    __u32 write = compat ? nr == 348 : nr == 311;
    __u64 iov = compat ? BPF_CORE_READ(regs, si) & 0xFFFFFFFFull : BPF_CORE_READ(regs, r10);
    __u64 count = compat ? BPF_CORE_READ(regs, di) & 0xFFFFFFFFull : BPF_CORE_READ(regs, r8);
    struct kb_scratch* s = reset_for(tgid, 0);
    if (!s) return 0;
    /* Without room for the address the decision still carries one: an unknown one (kb_address_match). */
    struct kb_access* a = bpf_task_storage_get(&kb_accesses, task, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (a) {
        a->target = object;
        a->count = 0;
        a->unknown = attach || count > KB_ACCESS;
        for (__u32 i = 0; i < KB_ACCESS; i++) {
            if (attach || i >= count) break;
            __u64 vector[2] = {};
            __u32 narrow[2] = {};
            long read = compat ? bpf_probe_read_user(narrow, sizeof(narrow), (void*)(iov + 8 * i))
                               : bpf_probe_read_user(vector, sizeof(vector), (void*)(iov + 16 * i));
            if (read != 0) {
                a->unknown = 1;   /* not resident: a hook that cannot fault does not see it */
                continue;
            }
            if (compat) access_add(a, narrow[0], narrow[1]);
            else access_add(a, vector[0], vector[1]);
        }
    }
    program_path(s, child, object);
    if (!attach) {
        return kb_decide_global(KFILTER_TARGET_PEER, write ? 0x28 : 0x10 /* vm-write,vm-operation; vm-read */, 0,
                                1 | KB_ADDRESSED | KB_ADDRESS_ONLY);
    }
    if ((c->targets & KFILTER_TARGET_PEER) != 0 &&
        kb_decide_global(KFILTER_TARGET_PEER, KB_ALL_ACCESS, 0, 1 | KB_ADDRESSED | KB_ADDRESS_ONLY) != 0) return -EPERM;
    if ((c->targets & KFILTER_TARGET_THREAD_PEER) == 0) return 0;
    return kb_decide_global(KFILTER_TARGET_THREAD_PEER, KB_ALL_ACCESS, 0, 1 | KB_ADDRESSED | KB_ADDRESS_ONLY);
}

/*
 * A family member's read or write (Mask) of /proc/<pid>/mem (File; not wineserver's for a client): another
 * member's is a peer decision on that program, its own /proc/self/mem /system/wine/self/read_process_memory or
 * write_process_memory, at the file position (read, write) or offset (pread64, pwrite64) for the call's byte
 * count; any other call (readv, an io_uring worker's...) reaches an unknown address. Decided on each access, not only
 * at the open; as kb_native_peer, only while an addr= rule is loaded, and only such rules meet it.
 */
__noinline int kb_proc_mem(__u64 fileAddress, __u32 mask)
{
    struct kb_cfg* c = kb_cfg_get();
    struct kb_scratch* s = scratch();
    struct file* file = (struct file*)fileAddress;
    struct task_struct* current = bpf_get_current_task_btf();
    struct pt_regs* regs = (struct pt_regs*)bpf_task_pt_regs(current);
    __u32 write = (mask & MAY_WRITE) != 0;
    if (!c || !s || !regs || !c->enabled || c->mode == KFILTER_MODE_OFF || (c->flags & KB_CFG_ADDRESS) == 0 ||
        s->brokered || fs_magic(BPF_CORE_READ(file, f_inode)) != PROC_SUPER_MAGIC) return 0;
    char name[4] = {};
    bpf_probe_read_kernel(name, sizeof(name), BPF_CORE_READ(file, f_path.dentry, d_name.name));
    if (name[0] != 'm' || name[1] != 'e' || name[2] != 'm' || name[3] != 0) return 0;
    struct inode* inode = BPF_CORE_READ(file, f_inode);
    struct proc_inode* proc = (void*)inode - bpf_core_field_offset(struct proc_inode, vfs_inode);
    struct pid* pid = BPF_CORE_READ(proc, pid);
    if (!pid) return 0;   /* no process's file */
    struct task_struct* task = bpf_task_from_pid(BPF_CORE_READ(pid, numbers[0].nr));
    if (!task) return 0;
    __u32 object = BPF_CORE_READ(task, tgid);
    int self = object == s->tgid;
    if ((!self && !task_protected(task, task_state(task))) ||
        (c->targets & (self ? KFILTER_TARGET_SYSTEM : KFILTER_TARGET_PEER)) == 0) {
        bpf_task_release(task);
        return 0;
    }
    if (self) {
        set_path(s, "/system/wine/self/", 18);
        if (write) append_text(s, "write_process_memory", 20);
        else append_text(s, "read_process_memory", 19);
    } else {
        program_path(s, task, object);
    }
    bpf_task_release(task);
    /* Without room for the address the decision still carries one: an unknown one (kb_address_match). */
    struct kb_access* a = bpf_task_storage_get(&kb_accesses, current, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (a) {
        a->target = object;
        a->count = 0;
        a->unknown = 0;
        long nr = BPF_CORE_READ(regs, orig_ax);
        /* An io_uring worker's pt_regs are its creator's at a past syscall, not this access's. */
        if ((BPF_CORE_READ(current, flags) & (PF_IO_WORKER | PF_KTHREAD)) != 0) {
            a->unknown = 1;
        } else if ((BPF_CORE_READ(current, thread_info.status) & TS_COMPAT) != 0) {
            __u64 bytes = BPF_CORE_READ(regs, dx) & 0xFFFFFFFFull;
            if (nr == 3 || nr == 4) access_add(a, BPF_CORE_READ(file, f_pos), bytes);   /* read, write */
            else if (nr == 180 || nr == 181)                                            /* pread64, pwrite64 */
                access_add(a, (BPF_CORE_READ(regs, si) & 0xFFFFFFFFull) | BPF_CORE_READ(regs, di) << 32, bytes);
            else a->unknown = 1;
        } else {
            __u64 bytes = BPF_CORE_READ(regs, dx);
            if (nr == 0 || nr == 1) access_add(a, BPF_CORE_READ(file, f_pos), bytes);
            else if (nr == 17 || nr == 18) access_add(a, BPF_CORE_READ(regs, r10), bytes);
            else a->unknown = 1;
        }
    }
    int result = self ? kb_decide_global(KFILTER_TARGET_SYSTEM, write ? KFILTER_RIGHT_WRITE : KFILTER_RIGHT_QUERY, 0,
                                         1 | KB_ADDRESSED | KB_ADDRESS_ONLY)
                      : kb_decide_global(KFILTER_TARGET_PEER, write ? 0x28 : 0x10, 0, 1 | KB_ADDRESSED | KB_ADDRESS_ONLY);
    s->failed = 0;   /* the file decision that follows names its own path (a target with no name must not fail it) */
    return result;
}

/*
 * block-process-memory: memory access (ptrace attach, /proc/<pid>/mem, process_vm_*)
 * across the family boundary. An outside process reaching the client needs a HANDLE
 * allow for its program, the client reaching outside an OPEN allow for the target's
 * program, each granting VM_OPERATION|VM_READ|VM_WRITE. wineserver acts for the client
 * whose request it is serving (ReadProcessMemory and friends). Metadata reads stay open.
 */
/* A reach kb_reach_decide can decide: its switch (Flag) is on, or a peer rule names a signal or mode. Every kill and READ
 * check on the system passes here first. */
static __always_inline int reach_gated(__u32 flag)
{
    struct kb_cfg* c = kb_cfg_get();
    return c && ((c->flags & flag) != 0 || gated(KB_GATE_PEER));
}

/* A PTRACE_MODE_READ check on Child (kcmp, process_madvise, move_pages, migrate_pages, get_robust_list,
 * /proc/<pid>/environ, maps, smaps, pagemap, stack, fd, exe...): kb_reach_decide with right query-information and value
 * the mode (Into: Child is protected), charged as begin() charges: wineserver serving a client, and winedevice serving
 * one, reach for it; wineserver's own checks outside a request are Wine's (as its signals), never decided. */
__noinline int kb_read_reach(__u64 childAddress, __u32 mode, __u32 into)
{
    struct kb_task* state = task_state(bpf_get_current_task_btf());
    __u32 tid = current_tid();
    __u32* client = bpf_map_lookup_elem(&kb_serving, &tid);
    __u32 actor = current_tgid();
    if (state && state->role == KB_ROLE_WINESERVER) actor = state->client;
    else if (client && *client != 0) actor = *client;
    if (actor == 0) return 0;
    return kb_reach_decide(actor, childAddress, 0x400 /* PROCESS_QUERY_INFORMATION */, mode,
                           KB_REACH_QUERY | (into ? KB_REACH_INTO : 0));
}

/* Not a NOAUDIT check: /proc/<pid>/stat makes those on every read. */
static __always_inline int ptrace_read(struct task_struct* child, unsigned int mode)
{
    if ((mode & PTRACE_MODE_NOAUDIT) != 0 || !reach_gated(KFILTER_CFG_BLOCK_PROCESS_QUERIES)) return 0;
    return kb_decided(kb_read_reach(address_of(child), mode, task_protected(child, task_state(child))));
}

SEC("lsm/ptrace_access_check")
int BPF_PROG(kb_ptrace, struct task_struct* child, unsigned int mode, int ret)
{
    if (ret != 0) return ret;
    if ((mode & PTRACE_MODE_ATTACH) == 0) return ptrace_read(child, mode);
    struct task_struct* task = bpf_get_current_task_btf();
    struct kb_task* state = task_state(task);
    /* wineserver carrying out a memory or context request through a handle kfilter could not name. */
    if (state && state->role == KB_ROLE_WINESERVER && state->client != 0 &&
        kb_unknown_peer(address_of(child), state->client, state->client_tid) != 0) return -EPERM;
    /* A family member's own process_vm_readv/writev into another, or its ptrace attach: addr= rules, before
     * block-process-memory's gate. */
    if (state && task_protected(child, task_state(child)) && kb_native_peer(address_of(child)) != 0) return -EPERM;
    struct kb_cfg* c = kb_cfg_get();
    if (!c || !c->enabled || c->mode == KFILTER_MODE_OFF || (c->flags & KFILTER_CFG_BLOCK_PROCESS_MEMORY) == 0) return 0;
    __u32 actor = current_tgid();
    __u32 brokered = 0;
    if (state && state->role == KB_ROLE_WINESERVER && state->client != 0) {
        actor = state->client;
        brokered = 1;
    }
    int self = brokered ? proc_guarded(actor) : task_protected(task, state);
    int other = task_protected(child, task_state(child));
    if (self == other || actor == c->daemon_tgid) return 0;
    struct kb_scratch* s = reset_for(actor, brokered);
    if (!s) return 0;
    __u32 target = self ? KFILTER_TARGET_OPEN : KFILTER_TARGET_HANDLE;
    if (self) program_path(s, child, BPF_CORE_READ(child, tgid));
    else program_path(s, brokered ? 0 : task, actor);
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    __u32 rights = kb_outside_rights(target, KB_PROCESS_MEMORY_RIGHTS, uid == 0);
    __u32 action = (rights & KB_PROCESS_MEMORY_RIGHTS) == KB_PROCESS_MEMORY_RIGHTS ? KFilterActionAllow : KFilterActionDeny;
    return verdict(target, action, KFILTER_EVENT_FLAG_MEMORY_READ, mode, s->outside_rule, KB_PROCESS_MEMORY_RIGHTS, c->mode);
}

/* A signal kfilter did not decide before (kb_reach_decide) that the current task sends Target: a kill(pid, 0) probe, one
 * inside the family, one into it from outside (Flags KB_REACH_INTO), or a file's SIGIO whose owner it sets (KB_REACH_SIGIO).
 * Only a signal the sender makes itself: wineserver's (Wine's suspensions, context reads, APCs and exits while serving a
 * request, already decided as that request) and winedevice's for a client are never decided. */
static __always_inline int signal_reach(__u64 targetAddress, __u32 sig, __u32 flags)
{
    struct task_struct* task = bpf_get_current_task_btf();
    struct kb_task* state = task_state(task);
    __u32 tid = current_tid();
    if ((state && state->role == KB_ROLE_WINESERVER) || bpf_map_lookup_elem(&kb_serving, &tid)) return 0;
    if ((flags & KB_REACH_INTO) == 0 && !task_protected(task, state)) return 0;
    __u32 access = sig == 0 ? 0x1000 : KB_PROCESS_TERMINATE;   /* QUERY_LIMITED_INFORMATION for a probe */
    return kb_reach_decide(current_tgid(), targetAddress, access, sig, flags);
}

__noinline int kb_signal_reach(__u64 targetAddress, __u32 sig, __u32 flags)
{
    return signal_reach(targetAddress, sig, flags);
}

/* The client signalling a process outside its family: allowed when an OPEN rule for that
 * program grants PROCESS_TERMINATE, as on Windows. */
SEC("lsm/task_kill")
int BPF_PROG(kb_task_kill, struct task_struct* p, struct kernel_siginfo* info, int sig, const struct cred* cred, int ret)
{
    if (ret != 0) return ret;
    int into = task_protected(p, task_state(p));
    if (sig == 0 || into) {
        if (!reach_gated(KFILTER_CFG_BLOCK_PROCESS_SIGNALS)) return 0;
        return kb_decided(kb_signal_reach(address_of(p), (__u32)sig, into ? KB_REACH_INTO : 0));
    }
    BEGIN();
    struct kb_cfg* c = kb_cfg_get();
    struct kb_scratch* s = scratch();
    if (!c || !s || !c->enabled || c->mode == KFILTER_MODE_OFF || (c->flags & KFILTER_CFG_BLOCK_PROCESS_MEMORY) == 0) return 0;
    program_path(s, p, BPF_CORE_READ(p, tgid));
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    __u32 rights = kb_outside_rights(KFILTER_TARGET_OPEN, KB_PROCESS_TERMINATE, uid == 0);
    __u32 action = (rights & KB_PROCESS_TERMINATE) != 0 ? KFilterActionAllow : KFilterActionDeny;
    return verdict(KFILTER_TARGET_OPEN, action, 0, (__u32)sig, s->outside_rule, KB_PROCESS_TERMINATE, c->mode);
}

/* prctl options other than PR_SET_MM: /system/prctl/0x<option> (PR_SET_TSC, 0x001a: switching the RDTSC trap off;
 * PR_SET_SECCOMP, PR_SET_NAME...), query for the gets, write otherwise, rule-only. */
__noinline int kb_prctl_decide(__u32 option)
{
    /* PR_GET_PDEATHSIG, DUMPABLE, UNALIGN, KEEPCAPS, FPEMU, FPEXC, TIMING, NAME, ENDIAN, SECCOMP, CAPBSET_READ, TSC,
     * SECUREBITS, TIMERSLACK, CHILD_SUBREAPER, NO_NEW_PRIVS, TID_ADDRESS, THP_DISABLE, FP_MODE, SPECULATION_CTRL,
     * TAGGED_ADDR_CTRL, IO_FLUSHER */
    const __u64 gets = 1ull << 2 | 1ull << 3 | 1ull << 5 | 1ull << 7 | 1ull << 9 | 1ull << 11 | 1ull << 13 | 1ull << 16 |
                       1ull << 19 | 1ull << 21 | 1ull << 23 | 1ull << 25 | 1ull << 27 | 1ull << 30 | 1ull << 37 |
                       1ull << 39 | 1ull << 40 | 1ull << 42 | 1ull << 46 | 1ull << 52 | 1ull << 56 | 1ull << 58;
    int started = system_begin();
    if (started <= 0) return started;
    struct kb_scratch* s = scratch();
    if (!s) return 0;
    set_path(s, "/system/prctl/0x", 16);
    append_hex(s, option, option > 0xFFFF ? 8 : 4);
    int get = option < 64 && (gets >> option & 1) != 0;
    return kb_system_decide(get ? KFILTER_RIGHT_QUERY : KFILTER_RIGHT_WRITE, KB_ROOT(13));
}

SEC("lsm/task_prctl")
int BPF_PROG(kb_task_prctl, int option, unsigned long arg2, unsigned long arg3, unsigned long arg4,
             unsigned long arg5, int ret)
{
    if (ret != 0) return ret;
    if (option == PR_SET_MM) return protected_current() ? refuse((__u32)option) : 0;
    return gated(KB_GATE_PRCTL) ? kb_decided(kb_prctl_decide((__u32)option)) : 0;
}

SEC("lsm/kernel_read_file")
int BPF_PROG(kb_kernel_read_file, struct file* file, enum kernel_read_file_id id, bool contents, int ret)
{
    if (ret != 0 || !protected_current()) return ret;
    return refuse(0x1000 + (__u32)id);
}

SEC("lsm/bpf")
int BPF_PROG(kb_bpf, int cmd, union bpf_attr* attr, unsigned int size, bool kernel, int ret)
{
    if (ret != 0 || kernel || !protected_current()) return ret;
    return refuse(0x2000 + (__u32)cmd);
}

SEC("lsm/perf_event_open")
int BPF_PROG(kb_perf_event_open, int type, int ret)
{
    if (ret != 0 || !protected_current()) return ret;
    return refuse(0x3000 + (__u32)type);
}

/* ---- network (KfPolicyNetworkDecide) ---- */

struct net_ctx {
    __u32 family, protocol, port, right, base;
    __u32 action, rule_id, flags, irq;
    void* rules;   /* the rule set's network rules, looked up once (in the step: 60,000 more verified per program) */
};

static long net_step(__u32 index, struct net_ctx* n)
{
    struct kb_scratch* s = scratch_for(n->irq);
    if (!s) return 1;
    struct kb_net* rule = bpf_map_lookup_elem(n->rules, &index);
    if (!rule || rule->action == 0) return 1;   /* a zeroed rule after the last */
    if (rule->family != n->family || rule->prefix > (n->family == 4 ? 32u : 128u)) return 0;
    if (rule->protocol != 0 && rule->protocol != n->protocol) return 0;
    if (rule->port != 0 && rule->port != n->port) return 0;
    if (rule->action == KFilterActionAllow) {
        if (rule->rights == 0 || (n->right & ~rule->rights) != 0) return 0;
    } else if (rule->rights != 0 && (rule->rights & n->right) == 0) {
        return 0;
    }
    __u32 full = rule->prefix / 8;
    __u32 rest = rule->prefix % 8;
    for (__u32 i = 0; i < 16; i++) {
        if (i >= full) break;
        if (s->address[i] != rule->address[i]) return 0;
    }
    if (rest != 0 && full < 16) {
        __u8 mask = (__u8)(0xFFu << (8 - rest));
        if ((s->address[full & 15] & mask) != (rule->address[full & 15] & mask)) return 0;
    }
    if (rule->ilen != 0) {
        if (s->ilen == 0 || rule->ilen >= KB_IMAGE) return 0;
        bpf_probe_read_kernel(s->pattern, KB_IMAGE, rule->image);
        if (kb_glob(rule->ilen, TEXT_IMAGE, rule->iwhole ? 0 : s->ibase, n->irq) <= 0) return 0;
    }
    if (!take_use(&s->set, rule->count, n->base + index, 0)) {
        if (n->flags == 0) {
            n->flags = KFILTER_EVENT_FLAG_EXHAUSTED;
            n->rule_id = rule->rule_id;
        }
        return 0;
    }
    n->action = rule->action;
    n->rule_id = rule->rule_id;
    n->flags = (rule->count != 0 ? KFILTER_EVENT_FLAG_COUNTED : 0) |
               (rule->action == KFilterActionAllow && rule->risk ? KFILTER_EVENT_FLAG_RISK : 0);
    return 1;
}

/* s->address is a loopback address of Family (4 or 6). */
static __always_inline int loopback(struct kb_scratch* s, __u32 family)
{
    if (family == 4) return s->address[0] == 127;
    if (family != 6 || s->address[15] != 1) return 0;
    for (int i = 0; i < 15; i++) {
        if (s->address[i] != 0) return 0;
    }
    return 1;
}

/* The RISK record of a network or message allow by a risk= rule (E, not yet submitted): a
 * copy that names the right, submitted first, as network.c logs it. */
static __always_inline void emit_net_risk(struct kb_event* e)
{
    struct kb_event* r = bpf_ringbuf_reserve(&kb_events, sizeof(*r), 0);
    if (!r) {
        count_drop();
        return;
    }
    bpf_probe_read_kernel(r, sizeof(*r), e);
    r->action = KFilterActionRisk;
    r->flags &= KFILTER_EVENT_FLAG_NETWORK | KFILTER_EVENT_FLAG_MESSAGE | KFILTER_EVENT_FLAG_BROKERED;
    r->status = 0;
    r->value = r->rights;
    bpf_ringbuf_submit(r, 0);
}

/* s->address holds the remote (or bound) address; Tgid is the program the socket is for. */
__noinline int kb_net_decide_global(__u32 irq, __u32 tgid, __u32 kind, __u32 port, __u32 right)
{
    __u32 family = kind >> 8;
    __u32 protocol = kind & 0xFF;
    struct kb_cfg* c = kb_cfg_get();
    struct kb_scratch* s = scratch_for(irq);
    if (!c || !s || !c->enabled || c->mode == KFILTER_MODE_OFF || (c->flags & KFILTER_CFG_BLOCK_NETWORK) == 0) return 0;
    if (family != 4 && family != 6) return 0;
    if ((c->flags & KFILTER_CFG_NET_ALLOW_LOOPBACK) != 0 && loopback(s, family)) return 0;
    if (irq || s->tgid != tgid) load_image(s, tgid);
    s->set = live_set();
    struct net_ctx n = {family, protocol, port, right, KB_RULES, 0, 0, 0, irq, 0};
    n.action = (c->flags & KFILTER_CFG_NET_DEFAULT_ALLOW) != 0 ? KFilterActionAllow : KFilterActionDeny;
    __u32 fallback = n.action;
    n.rules = bpf_map_lookup_elem(&kb_net_sets, &s->set);
    if (n.rules) bpf_loop(KB_NET, net_step, &n, 0);
    if (n.action == 0) n.action = fallback;
    __u32 direct = irq ? 0 : kb_direct();
    if (direct && (c->flags & KFILTER_CFG_BLOCK_DIRECT_SYSCALL) != 0) {
        n.action = KFilterActionDeny;
        n.rule_id = 0;
        n.flags = 0;
    }
    struct kb_event* e = bpf_ringbuf_reserve(&kb_events, sizeof(*e), 0);
    __u32 mode = c->mode;
    int deny = n.action == KFilterActionDeny && mode == KFILTER_MODE_BLOCK;
    if (e) {
        e->kind = KB_EV_DECISION;
        e->tgid = tgid;
        e->target = KFILTER_TARGET_NETWORK;
        e->action = n.action == KFilterActionDeny && !deny ? KFilterActionAudit : n.action;
        e->flags = KFILTER_EVENT_FLAG_NETWORK | n.flags | direct |
                   (n.action == KFilterActionDeny && mode == KFILTER_MODE_AUDIT ? KFILTER_EVENT_FLAG_WOULD_DENY : 0) |
                   (!irq && s->brokered ? KFILTER_EVENT_FLAG_BROKERED : 0);
        e->status = n.action == KFilterActionDeny ? STATUS_ACCESS_DENIED : 0;
        e->value = port;
        e->rule_id = n.rule_id;
        e->rights = right;
        e->ppid = (family << 8) | protocol;
        e->port = port;
        /* The address bytes in the path field; kfilterd formats them. */
        bpf_probe_read_kernel(e->path, 16, s->address);
        e->path[16] = 0;
        event_image(e, s);
        if ((n.flags & KFILTER_EVENT_FLAG_RISK) != 0) emit_net_risk(e);
        bpf_ringbuf_submit(e, 0);
    } else {
        count_drop();
    }
    return deny ? -EPERM : 0;
}

/* An IPv4-mapped IPv6 address (::ffff:a.b.c.d) is decided as the IPv4 address. */
static __always_inline void unmap_ipv4(struct kb_scratch* s, __u32* family)
{
    if (*family != 6) return;
    for (int i = 0; i < 10; i++) {
        if (s->address[i] != 0) return;
    }
    if (s->address[10] != 0xFF || s->address[11] != 0xFF) return;
    __u8 v4[4] = {s->address[12], s->address[13], s->address[14], s->address[15]};
    __builtin_memset(s->address, 0, 16);
    __builtin_memcpy(s->address, v4, 4);
    *family = 4;
}

/* sockaddr in kernel memory -> s->address, family 4/6, port */
static __always_inline int read_sockaddr(struct kb_scratch* s, const struct sockaddr* address, __u32* family, __u32* port)
{
    if (!s || !address) return -1;
    __u16 sa = 0;
    bpf_probe_read_kernel(&sa, sizeof(sa), &address->sa_family);
    __builtin_memset(s->address, 0, 16);
    if (sa == AF_INET) {
        struct sockaddr_in in = {};
        bpf_probe_read_kernel(&in, sizeof(in), address);
        __builtin_memcpy(s->address, &in.sin_addr, 4);
        *family = 4;
        *port = bpf_ntohs(in.sin_port);
        return 0;
    }
    if (sa == AF_INET6) {
        struct sockaddr_in6 in6 = {};
        bpf_probe_read_kernel(&in6, sizeof(in6), address);
        __builtin_memcpy(s->address, &in6.sin6_addr, 16);
        *family = 6;
        *port = bpf_ntohs(in6.sin6_port);
        unmap_ipv4(s, family);
        return 0;
    }
    return -1;
}

/* A Unix socket address as a pipe path: its file path, or "/@name" for an abstract one. A relative
 * path (Wine connects to "socket" in its server dir) is resolved from the cwd, as the kernel does;
 * a cwd that cannot be named is a name failure (refused in block mode), never a pass. */
static __always_inline int unix_path(struct kb_scratch* s, const struct sockaddr* address, int length)
{
    __u16 sa = 0;
    bpf_probe_read_kernel(&sa, sizeof(sa), &address->sa_family);
    if (sa != AF_UNIX || length <= 2) return -1;
    __u32 n = (__u32)length - 2;
    if (n > 108) n = 108;
    char first = 0;
    bpf_probe_read_kernel(&first, 1, (const char*)address + 2);
    if (first != 0) {
        __u32 at = 0;
        if (first != '/') {
            struct fs_struct* fs = BPF_CORE_READ((struct task_struct*)bpf_get_current_task_btf(), fs);
            if (!fs || walk_path(__builtin_preserve_access_index(&fs->pwd)) != 0) {
                s->failed = 1;
                return 0;
            }
            at = s->len == 1 ? 0 : s->len;   /* the cwd is "/" */
            if (at + 2 >= KB_PATH) {
                s->failed = 1;
                return 0;
            }
            s->path[at & (KB_PATH - 1)] = '/';
            at += 1;
        }
        /* Up to the address's end (the kernel puts the NUL there after this hook), not past it into its stack. */
        long copied = bpf_probe_read_kernel_str(&s->path[at & (KB_PATH - 1)], n < 108 ? n + 1 : 109, (const char*)address + 2);
        if (copied <= 1) return -1;
        s->len = at + (__u32)(copied - 1);
        if (s->len >= KB_PATH) {
            s->failed = 1;
            return 0;
        }
    } else {
        /* Abstract: the bytes after the leading NUL, which may contain more NULs. */
        s->path[0] = '/';
        s->path[1] = '@';
        if (n > 1) bpf_probe_read_kernel(&s->path[2], (n - 1) & 127, (const char*)address + 3);
        s->len = n + 1;
        s->path[(n + 1) & (KB_PATH - 1)] = 0;
    }
    s->failed = 0;
    return 0;
}

/* The name AF_UNIX socket U was bound to, as unix_path names a connect to it: its path (walked from where it was bound;
 * s->failed when that cannot be named), or /@name for an abstract one. -1 for a socket bound to nothing. */
static __always_inline int unix_name(struct kb_scratch* s, struct unix_sock* u)
{
    struct unix_address* address = BPF_CORE_READ(u, addr);
    if (!address) return -1;
    __u32 length = BPF_CORE_READ(address, len);
    const char* name = (const char*)address + bpf_core_field_offset(struct unix_address, name) + 2;   /* sun_path */
    char first = 0;
    bpf_probe_read_kernel(&first, 1, name);
    if (first != 0) {
        walk_path(__builtin_preserve_access_index(&u->path));
    } else {
        __u32 n = length > 2 ? length - 2 : 0;   /* the bytes after the leading NUL, as unix_path names a connect's */
        if (n > 108) n = 108;
        s->path[0] = '/';
        s->path[1] = '@';
        if (n > 1) bpf_probe_read_kernel(&s->path[2], (n - 1) & 127, name + 1);
        s->len = n + 1;
        s->path[(n + 1) & (KB_PATH - 1)] = 0;
    }
    return 0;
}

/* Does the socket already hold an allow for this peer under the current policy? */
static __always_inline int peer_known(struct kb_scratch* s, struct kb_sock* owner, __u32 family, __u32 port)
{
    struct kb_cfg* c = kb_cfg_get();
    if (!owner || !s || !c || owner->generation != c->generation) return 0;
    for (int slot = 0; slot < 8; slot++) {
        if (owner->peer[slot].family != family || owner->peer[slot].port != port) continue;
        int same = 1;
        for (int index = 0; index < 16; index++) {
            if (owner->peer[slot].address[index] != s->address[index]) {
                same = 0;
                break;
            }
        }
        if (same) return 1;
    }
    return 0;
}

/* Remember a peer after an allow, under Generation as grant's; a policy reload invalidates the whole cache. */
static __always_inline void peer_add(struct kb_scratch* s, struct kb_sock* owner, __u32 family, __u32 port,
                                     __u32 generation)
{
    if (!owner || !s) return;
    if (owner->generation != generation) {
        owner->generation = generation;
        owner->next = 0;
        __builtin_memset(owner->peer, 0, sizeof(owner->peer));
    }
    __u32 slot = owner->next & 7;
    __builtin_memset(&owner->peer[slot], 0, sizeof(owner->peer[slot]));
    owner->peer[slot].family = family;
    owner->peer[slot].port = port;
    __builtin_memcpy(owner->peer[slot].address, s->address, 16);
    owner->next = slot + 1;
}

static __always_inline __u32 protocol_of(struct socket* sock)
{
    return BPF_CORE_READ(sock, sk, sk_protocol);
}

/* A socket made for a protected program (by it, or by wineserver serving it) records it. */
SEC("lsm/socket_post_create")
int BPF_PROG(kb_socket_post_create, struct socket* sock, int family, int type, int protocol, int kern, int ret)
{
    if (ret != 0 || kern || (family != AF_INET && family != AF_INET6 && family != AF_UNIX)) return ret;   /* unix: its owner */
    BEGIN();
    struct kb_scratch* s = scratch();
    struct sock* sk = sock->sk;   /* a BTF pointer, as socket storage needs */
    if (!sk || !s) return 0;
    struct kb_sock* owner = bpf_sk_storage_get(&kb_socks, sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
    if (owner) {
        __builtin_memset(owner, 0, sizeof(*owner));
        owner->tgid = s->tgid;
    }
    return 0;
}

static __always_inline int udp_decide(struct socket* sock, __u32 family, __u32 port)
{
    struct kb_scratch* s = scratch();
    struct kb_cfg* c = kb_cfg_get();
    struct sock* sk = sock->sk;   /* a BTF pointer, as socket storage needs */
    struct kb_sock* owner = sk ? bpf_sk_storage_get(&kb_socks, sk, 0, 0) : 0;
    if (!s || !c) return 0;
    if (owner && peer_known(s, owner, family, port)) return 0;
    __u32 generation = c->generation;   /* before kb_net_decide reads kb_live (grant) */
    int result = kb_net_decide(0, s->tgid, family, 17, port, KFILTER_RIGHT_CONNECT);
    if (result == 0 && owner) peer_add(s, owner, family, port, generation);
    return result;
}

SEC("lsm/socket_connect")
int BPF_PROG(kb_socket_connect, struct socket* sock, struct sockaddr* address, int addrlen, int ret)
{
    if (ret != 0) return ret;
    BEGIN();
    struct kb_scratch* s = scratch();
    if (!s) return 0;
    __u32 family = 0, port = 0;
    if (unix_path(s, address, addrlen) == 0) return kb_decide(KFILTER_TARGET_PIPE, KFILTER_RIGHT_CONNECT, 0);
    if (read_sockaddr(s, address, &family, &port) != 0) return 0;
    if (protocol_of(sock) == 17) return udp_decide(sock, family, port);
    return kb_net_decide(0, s->tgid, family, protocol_of(sock), port, KFILTER_RIGHT_CONNECT);
}

/* ---- messages: each send and receive on a connection (message rules) ---- */

/* The peer of a connected socket into s->address. */
static __always_inline int peer_address(struct kb_scratch* s, struct sock* sk, __u32* family, __u32* port)
{
    if (!s || !sk) return -1;
    __builtin_memset(s->address, 0, 16);
    __u16 sa = BPF_CORE_READ(sk, __sk_common.skc_family);
    *port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    if (sa == AF_INET) {
        __u32 address = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        __builtin_memcpy(s->address, &address, 4);
        *family = 4;
        return 0;
    }
    if (sa == AF_INET6) {
        BPF_CORE_READ_INTO(&s->address, sk, __sk_common.skc_v6_daddr);
        *family = 6;
        unmap_ipv4(s, family);
        return 0;
    }
    return -1;
}

static __always_inline __u64 socket_inode(struct socket* sock)
{
    struct inode* inode = BPF_CORE_READ(sock, file, f_inode);
    return inode ? BPF_CORE_READ(inode, i_ino) : 0;
}

/* The first bytes of a send (its first segment, up to KB_MSG_BYTES) into s->walk, in
 * 256-byte steps: each copy is bounded on its own, so the verifier needs no relation
 * between the offset and the length. */
struct copy_ctx {
    __u64 base;
    __u32 len;
};

static long copy_step(__u32 index, struct copy_ctx* c)
{
    struct kb_scratch* s = scratch();
    __u32 off = index * 256;
    if (!s || off >= c->len) return 1;
    __u32 take = c->len - off;
    if (take > 256) take = 256;
    bpf_probe_read_user(&s->walk[off & (KB_MSG_BYTES - 1)], take, (void*)(c->base + off));
    return 0;
}

static __always_inline void capture(struct kb_scratch* s, struct msghdr* msg)
{
    __u8 type = BPF_CORE_READ(msg, msg_iter.iter_type);
    __u64 count = BPF_CORE_READ(msg, msg_iter.count);
    __u64 base = 0, length = 0;
    s->msize = count > 0xFFFFFFFFull ? 0xFFFFFFFFu : (__u32)count;
    s->mlen = 0;
    if (type == 0) {   /* ITER_UBUF: one user buffer */
        base = (__u64)BPF_CORE_READ(msg, msg_iter.ubuf);
        length = count;
    } else if (type == 1) {   /* ITER_IOVEC: the first segment, from the current offset */
        const struct iovec* vector = BPF_CORE_READ(msg, msg_iter.__iov);
        struct iovec first = {};
        __u64 offset = BPF_CORE_READ(msg, msg_iter.iov_offset);
        if (!vector || bpf_probe_read_kernel(&first, sizeof(first), vector) != 0 || offset >= first.iov_len) return;
        base = (__u64)first.iov_base + offset;
        length = first.iov_len - offset;
        if (length > count) length = count;
    } else {
        return;   /* kernel buffers (splice, sendfile): counted, not read */
    }
    if (base == 0) return;
    struct copy_ctx c = {base, (__u32)(length > KB_MSG_BYTES ? KB_MSG_BYTES : length)};
    bpf_loop(KB_MSG_BYTES / 256, copy_step, &c, 0);
    s->mlen = c.len;
}

/* s->path, a unix send's peer, against the unix= pattern of a rule set's message rule (kb_unix_names Key); undecided
 * within the step budget meets a deny or audit (fail closed), not an Allow. Global: verified once. */
__noinline int kb_unix_match(__u32 key, __u32 allow)
{
    struct kb_scratch* s = scratch();
    struct kb_unix_name* name = bpf_map_lookup_elem(&kb_unix_names, &key);
    if (!s || !name || name->len == 0 || name->len >= KB_VALUE) return 0;
    bpf_probe_read_kernel(s->pattern, KB_VALUE, name->path);
    int glob = kb_glob(name->len, TEXT_PATH, 0, 0);
    return glob > 0 || (glob < 0 && !allow);
}

struct msg_ctx {
    __u32 right, family, protocol, port;
    __u32 action, rule_id, flags;
    void* rules;   /* as net_ctx's */
};

static long msg_step(__u32 index, struct msg_ctx* m)
{
    struct kb_scratch* s = scratch();
    if (!s) return 1;
    struct kb_net* rule = bpf_map_lookup_elem(m->rules, &index);
    if (!rule || rule->action == 0) return 1;   /* a zeroed rule after the last */
    if ((rule->rights & m->right) == 0 || (rule->rights & ~KFILTER_RIGHTS_MESSAGE) != 0) return 0;
    if (m->family == KFILTER_NET_FAMILY_UNIX) {
        /* A unix send: only unix= rules, by the peer's name in s->path. */
        /* prefix 129: the loader's "matches nothing" (a module= past KB_MOD_BITS). */
        if (rule->family != m->family || rule->prefix > 128 ||
            !kb_unix_match((s->set & 1) * KB_NET + index, rule->action == KFilterActionAllow))
            return 0;
    } else if (rule->family != 0) {
        if (rule->family != m->family || rule->prefix > (m->family == 4 ? 32u : 128u)) return 0;
        __u32 full = rule->prefix / 8;
        __u32 rest = rule->prefix % 8;
        for (__u32 i = 0; i < 16; i++) {
            if (i >= full) break;
            if (s->address[i] != rule->address[i]) return 0;
        }
        if (rest != 0 && full < 16) {
            __u8 mask = (__u8)(0xFFu << (8 - rest));
            if ((s->address[full & 15] & mask) != (rule->address[full & 15] & mask)) return 0;
        }
    }
    if (rule->protocol != 0 && rule->protocol != m->protocol) return 0;
    if (rule->port != 0 && rule->port != m->port) return 0;
    if (rule->index_max != 0 && (s->mindex < rule->index_min || s->mindex > rule->index_max)) return 0;
    if (rule->size_max != 0 && (s->msize < rule->size_min || s->msize > rule->size_max)) return 0;
    if (rule->match_len != 0) {
        __u32 off = rule->match_off, len = rule->match_len;
        if (len > 16 || off + len > s->mlen) return 0;
        for (__u32 i = 0; i < 16; i++) {
            if (i >= len) break;
            if ((__u8)s->walk[(off + i) & (KB_MSG_BYTES - 1)] != rule->match[i]) return 0;
        }
    }
    if (rule->mbit != 0 && (s->mbits & rule->mbit) == 0) return 0;
    if (rule->ilen != 0) {
        if (s->ilen == 0 || rule->ilen >= KB_IMAGE) return 0;
        bpf_probe_read_kernel(s->pattern, KB_IMAGE, rule->image);
        if (kb_glob(rule->ilen, TEXT_IMAGE, rule->iwhole ? 0 : s->ibase, 0) <= 0) return 0;
    }
    if (!take_use(&s->set, rule->count, KB_RULES + index, 0)) {
        if (m->flags == 0) {
            m->flags = KFILTER_EVENT_FLAG_EXHAUSTED;
            m->rule_id = rule->rule_id;
        }
        return 0;
    }
    m->action = rule->action;
    m->rule_id = rule->rule_id;
    m->flags = (rule->count != 0 ? KFILTER_EVENT_FLAG_COUNTED : 0) |
               (rule->action == KFilterActionAllow && rule->risk ? KFILTER_EVENT_FLAG_RISK : 0);
    return 1;
}

/* A message decision for the program in s->tgid: s->address/port the peer, s->msize,
 * s->mindex, s->minode, and for a send s->walk/s->mlen its first bytes. Blocked: the
 * connection was blocked with kfilterctl block-connection. Returns 0 or -EPERM. */
__noinline int kb_msg_decide_global(__u32 kind, __u32 port, __u32 right, __u32 blocked)
{
    struct kb_cfg* c = kb_cfg_get();
    struct kb_scratch* s = scratch();
    if (!c || !s || !c->enabled || c->mode == KFILTER_MODE_OFF || (c->flags & KFILTER_CFG_BLOCK_NETWORK) == 0) return 0;
    __u32 family = kind >> 8;
    s->set = live_set();
    struct msg_ctx m = {right, family, kind & 0xFF, port, 0, 0, 0, 0};
    /* A unix send (s->path its peer): unix= rules alone decide it, no default (Wine's and the desktop's own sockets). */
    __u32 unix = family == KFILTER_NET_FAMILY_UNIX;
    if (blocked) {
        m.action = KFilterActionDeny;   /* block-connection: loopback too, it names one connection */
    } else {
        if (!unix && c->msg_count == 0 && (c->flags & KFILTER_CFG_MESSAGE_DEFAULT_DENY) == 0) return 0;
        /* network-loopback exempts messages as it exempts connections (kb_net_decide_global). */
        if ((c->flags & KFILTER_CFG_NET_ALLOW_LOOPBACK) != 0 && loopback(s, family)) return 0;
        m.rules = bpf_map_lookup_elem(&kb_net_sets, &s->set);
        if (m.rules) bpf_loop(KB_NET, msg_step, &m, 0);
        if (m.action == 0) {
            /* No rule decided: the default, logged only when it refuses. */
            if (unix || (c->flags & KFILTER_CFG_MESSAGE_DEFAULT_DENY) == 0) return 0;
            m.action = KFilterActionDeny;
        }
    }
    __u32 mode = c->mode;
    int deny = m.action == KFilterActionDeny && mode == KFILTER_MODE_BLOCK;
    __u32 direct = kb_direct();
    struct kb_event* e = bpf_ringbuf_reserve(&kb_events, sizeof(*e), 0);
    if (e) {
        e->kind = KB_EV_DECISION;
        e->tgid = s->tgid;
        e->target = KFILTER_TARGET_NETWORK;
        e->action = m.action == KFilterActionDeny && !deny ? KFilterActionAudit : m.action;
        e->flags = KFILTER_EVENT_FLAG_NETWORK | KFILTER_EVENT_FLAG_MESSAGE | m.flags | direct |
                   (m.action == KFilterActionDeny && mode == KFILTER_MODE_AUDIT ? KFILTER_EVENT_FLAG_WOULD_DENY : 0);
        e->status = m.action == KFilterActionDeny ? STATUS_ACCESS_DENIED : 0;
        e->value = s->msize;
        e->rule_id = m.rule_id;
        e->rights = right;
        e->ppid = kind;
        e->size = s->msize;
        e->index = s->mindex;
        e->inode = s->minode;
        e->port = port;
        /* A unix send's bytes are not shown (X11, D-Bus and Pulse auth cookies; msmon logs them with --log-content):
         * match= still decides on them. */
        e->shown = right == KFILTER_RIGHT_SEND && !unix ? (s->mlen < KB_MSG_SHOWN ? s->mlen : KB_MSG_SHOWN) : 0;
        e->caller = s->caller;
        bpf_probe_read_kernel(e->path, 16, s->address);
        if (!unix) bpf_probe_read_kernel(&e->path[16], KB_MSG_SHOWN, s->walk);
        else __builtin_memset(&e->path[16], 0, KB_MSG_SHOWN);
        e->path[16 + KB_MSG_SHOWN] = 0;
        if (unix) bpf_probe_read_kernel_str(&e->path[KB_MSG_NAME], KB_PATH - KB_MSG_NAME, s->path);
        event_image(e, s);
        if ((m.flags & KFILTER_EVENT_FLAG_RISK) != 0) emit_net_risk(e);
        bpf_ringbuf_submit(e, 0);
    } else {
        count_drop();
    }
    return deny ? -EPERM : 0;
}

/* ---- the Windows module that made a send or receive (module= rules) ---- */

/* Wine 11.0 x64 (dlls/ntdll/unix/signal_x86_64.c): GS base is the thread's TEB; a thread
 * inside a Wine syscall runs on its kernel stack (TEB+0x3a8) below its syscall_frame
 * (TEB+0x378), which saved the Windows side's rip and rsp. */
#define KB_TEB_SELF 0x30
#define KB_TEB_STACK_BASE 0x08
#define KB_TEB_SYSCALL_FRAME 0x378
#define KB_TEB_KERNEL_STACK 0x3a8
#define KB_FRAME_RSP 0x88
#define KB_PE_BYTES 2048     /* of the Windows stack scanned for the caller */

static __always_inline __u64 user_word(__u64 address)
{
    __u64 value = 0;
    if (bpf_probe_read_user(&value, sizeof(value), (const void*)address) != 0) return 0;
    return value;
}

/* The first word from the top of the copied stack that lies in one of the program's own
 * module code ranges (binary search over kb_mods, sorted by start).
 * shortcut: a stale word left in a Wine frame's locals can name the wrong module (no
 * unwinding, as msmon's stack scan); unwind with .pdata in the kernel if that misleads. */
static long caller_step(__u32 index, void* unused)
{
    struct kb_scratch* s = scratch();
    if (!s || index >= s->pe_words) return 1;
    struct kb_mods* mods = bpf_map_lookup_elem(&kb_mods, &s->tgid);
    if (!mods) return 1;
    __u64 word = *(__u64*)&s->walk[(index * 8) & (WALK_LEN - 8)];
    /* The bounds live in the scratch (unknown to the verifier), so the steps converge: with
     * them on the stack every program using pe_caller took ~0.1 s more to load. */
    s->slow = 0;
    s->shigh = mods->count < KB_MODS ? mods->count : KB_MODS;
    for (int step = 0; step < 8; step++) {
        __u32 low = s->slow, high = s->shigh;
        if (low >= high) break;
        __u32 middle = (low + high) / 2;
        if (mods->m[middle & (KB_MODS - 1)].low <= word) s->slow = middle + 1;
        else s->shigh = middle;
    }
    __u32 low = s->slow;
    if (low == 0) return 0;
    struct kb_mod* found = &mods->m[(low - 1) & (KB_MODS - 1)];
    if (word >= found->high) return 0;
    s->caller = word;
    s->mbits = found->bits;
    return 1;
}

/* s->caller/mbits for the current thread: its Windows stack at the syscall it is in, or (Entry)
 * at the Windows function a uprobe stopped at, its return address on top; read into s->walk
 * (before a send's bytes are). Nothing when the program has no module table or the thread is
 * not inside a Wine syscall (without Entry). */
static __always_inline void pe_caller(struct kb_scratch* s, int entry)
{
    s->caller = 0;
    s->mbits = 0;
    struct kb_mods* mods = bpf_map_lookup_elem(&kb_mods, &s->tgid);
    if (!mods || mods->count == 0) return;
    struct task_struct* task = bpf_get_current_task_btf();
    struct pt_regs* regs = (struct pt_regs*)bpf_task_pt_regs(task);
    __u64 teb = task->thread.gsbase;
    if (!teb || !regs || user_word(teb + KB_TEB_SELF) != teb) return;
    __u64 rsp = regs->sp;
    if (!entry) {
        __u64 frame = user_word(teb + KB_TEB_SYSCALL_FRAME);
        /* Wine's is_inside_syscall(): on its kernel stack, below the frame. */
        if (!frame || rsp < user_word(teb + KB_TEB_KERNEL_STACK) || rsp > frame) return;
        rsp = user_word(frame + KB_FRAME_RSP);
    }
    __u64 base = user_word(teb + KB_TEB_STACK_BASE);
    if (!rsp) return;
    __u64 n = base > rsp ? base - rsp : KB_PE_BYTES;   /* a fiber's stack lies outside the TEB's */
    if (n > KB_PE_BYTES) n = KB_PE_BYTES;
    n &= ~7ull;
    if (n == 0 || bpf_probe_read_user(s->walk, n & (KB_PE_BYTES * 2 - 1) & ~7ull, (const void*)rsp) != 0) return;
    s->pe_words = (__u32)(n / 8);
    bpf_loop(KB_PE_BYTES / 8, caller_step, 0, 0);
}

/* ---- Wine requests about other programs and the system (peer, thread-peer, system) ---- */

/* The process access a queue_apc on a process handle needs, by its APC (apc_call type). */
static __always_inline __u32 apc_access(__u64 data, __u32 size)
{
    __u32 type = 0;
    if (size < 4 || bpf_probe_read_kernel(&type, sizeof(type), (void*)data) != 0) return 0;
    if (type == 14) return 0x2;     /* APC_CREATE_THREAD (CreateRemoteThread): PROCESS_CREATE_THREAD */
    if (type == 15) return 0x40;    /* APC_DUP_HANDLE: PROCESS_DUP_HANDLE */
    if (type == 6) return 0x400;    /* APC_VIRTUAL_QUERY: PROCESS_QUERY_INFORMATION */
    return type >= 3 && type <= 13 ? 0x8 : 0;   /* VirtualAllocEx/ProtectEx/FreeEx, views: PROCESS_VM_OPERATION */
}

/* x86 debug registers in set_thread_context's contexts (context_t, 1720 bytes each): machine@0, flags@4, and from
 * +824 dr0-dr3, dr6, dr7, 64-bit for x86_64 (0x8664), 32-bit for i386. */
#define KB_CONTEXT_BYTES 1720
#define KB_CONTEXT_DEBUG 824
#define KB_SERVER_CTX_DEBUG_REGISTERS 0x10

/* The first context in Data that sets the debug registers: each breakpoint DR7 enables, its address and length.
 * Read into the access's spare words, not the stack: this runs at the end of the request hook's deepest call chain
 * (KB_ACCESS 8 leaves hi[5..7] free while at most 4 breakpoints are added). A context the request has (Whole bytes
 * of data) but its joined data (Size) does not (a chunk kb_request_data could not read) is unknown. */
static __always_inline __u32 debug_registers(struct kb_access* a, __u64 data, __u32 size, __u32 whole)
{
    for (__u32 n = 0; n < 2; n++) {
        __u64 at = data + n * KB_CONTEXT_BYTES;
        if (size < (n + 1) * KB_CONTEXT_BYTES) {
            if (whole < (n + 1) * KB_CONTEXT_BYTES) break;
            a->unknown = 1;
            return KB_ADDRESSED;
        }
        a->hi[7] = 0;   /* machine, flags */
        a->hi[6] = 0;   /* DR7 */
        if (bpf_probe_read_kernel(&a->hi[7], 8, (void*)at) != 0) {
            a->unknown = 1;
            return KB_ADDRESSED;
        }
        if (((a->hi[7] >> 32) & KB_SERVER_CTX_DEBUG_REGISTERS) == 0) continue;
        __u32 wide = (__u32)a->hi[7] == 0x8664 ? 8 : 4;   /* x86_64 registers, else i386's */
        if (bpf_probe_read_kernel(&a->hi[6], wide, (void*)(at + KB_CONTEXT_DEBUG + 5 * wide)) != 0) {
            a->unknown = 1;
            return KB_ADDRESSED;
        }
        for (__u32 i = 0; i < 4; i++) {
            __u64 dr7 = a->hi[6];
            if ((dr7 & (3ull << (2 * i))) == 0) continue;   /* DR7's L and G enables */
            __u32 len = (dr7 >> (18 + 4 * i)) & 3;          /* DR7's LEN: 1, 2, 8 or 4 bytes */
            a->hi[5] = 0;
            if (bpf_probe_read_kernel(&a->hi[5], wide, (void*)(at + KB_CONTEXT_DEBUG + i * wide)) != 0) a->unknown = 1;
            else access_add(a, a->hi[5], len == 0 ? 1 : len == 1 ? 2 : len == 2 ? 8 : 4);
        }
        return a->count != 0 || a->unknown ? KB_ADDRESSED : 0;   /* every breakpoint cleared: no address */
    }
    return 0;
}

/*
 * What the Wine request in s->request reaches in Target's memory (0: a process kfilter cannot name), into the
 * task's kb_access: read_ and write_process_memory (address, size); queue_apc's system APCs on memory
 * (VirtualQueryEx and unmapping: one byte; allocating and mapping where the caller chose; freeing, protecting,
 * flushing, locking); get_mapping_filename and get_image_view_info (one byte); set_thread_context's breakpoints.
 * Returns KB_ADDRESSED when it reaches memory, with KB_ADDRESS_ONLY for get_image_view_info (decided for addr=
 * rules alone), else 0.
 */
__noinline __u32 kb_request_access(__u32 target, __u64 data, __u32 size)
{
    struct kb_scratch* s = scratch();
    if (!s) return 0;
    __u32 req = s->request[0];
    __u32 only = req == KB_REQ_GET_IMAGE_VIEW_INFO ? KB_ADDRESS_ONLY : 0;
    if (req != KB_REQ_READ_PROCESS_MEMORY && req != KB_REQ_WRITE_PROCESS_MEMORY && req != KB_REQ_QUEUE_APC &&
        req != KB_REQ_GET_MAPPING_FILENAME && req != KB_REQ_GET_IMAGE_VIEW_INFO && req != KB_REQ_SET_THREAD_CONTEXT)
        return 0;
    struct kb_access* a = bpf_task_storage_get(&kb_accesses, bpf_get_current_task_btf(), 0,
                                               BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!a) return KB_ADDRESSED | only;   /* no room for the address: an unknown one (kb_address_match) */
    a->target = target;
    a->count = 0;
    a->unknown = 0;
    __u64 address = (__u64)s->request[5] << 32 | s->request[4];   /* addr@0x10 */
    if (req == KB_REQ_READ_PROCESS_MEMORY || req == KB_REQ_WRITE_PROCESS_MEMORY) {
        /* read: reply_size bytes; write: request_size */
        access_add(a, address, req == KB_REQ_READ_PROCESS_MEMORY ? s->request[2] : s->request[1]);
        return KB_ADDRESSED;
    }
    if (req == KB_REQ_GET_MAPPING_FILENAME || req == KB_REQ_GET_IMAGE_VIEW_INFO) {
        access_add(a, address, 1);
        return KB_ADDRESSED | only;
    }
    if (req == KB_REQ_SET_THREAD_CONTEXT) return debug_registers(a, data, size, s->request[1]);
    /* apc_call: type (and a field), addr@+8, size@+16, read into the access's last words (not the stack). */
    a->lo[KB_ACCESS - 3] = 0;
    if (size < 4 || bpf_probe_read_kernel(&a->lo[KB_ACCESS - 3], 4, (void*)data) != 0) return 0;
    __u32 type = (__u32)a->lo[KB_ACCESS - 3];
    if (type < 3 || type > 13) return 0;   /* user, async I/O, create_thread, dup_handle: no memory */
    /* Its address past the joined data (a chunk kb_request_data could not read). */
    if (size < 24 || bpf_probe_read_kernel(&a->lo[KB_ACCESS - 2], 16, (void*)(data + 8)) != 0) {
        a->unknown = 1;
        return KB_ADDRESSED;
    }
    __u64 at = a->lo[KB_ACCESS - 2], length = a->lo[KB_ACCESS - 1];
    if ((type == 3 || type == 4 || type == 11 || type == 12) && at == 0) return 0;   /* the system picks the place */
    if (type == 6 || type == 13) access_add(a, at, 1);   /* virtual_query, unmap_view */
    else if (length == 0) a->unknown = 1;                /* the whole region or section: its extent is not given */
    else access_add(a, at, length);
    return KB_ADDRESSED;
}

/* A get_process_info or get_thread_info through a handle kfilter cannot name: wineserver's reply names its process
 * (kb_wineserver_pipe), which kb_learnt keeps for the addr= decisions of the requests after it. */
static __always_inline void learn_handle(struct kb_scratch* s, __u32 ownerTid, __u32 tgid)
{
    s->pending.req = s->request[0];
    s->pending.owner = tgid;
    s->pending.object.tgid = 0;
    s->pending.object.thread = 0;
    s->pending.object.access = 0;
    s->pending.object.pid = s->request[3];   /* the handle, until the reply */
    s->pending.key.len = 0;
    bpf_map_update_elem(&kb_pending, &ownerTid, &s->pending, BPF_ANY);
}

/*
 * A request through a handle kfilter cannot name (get_next_process's, inherited, or one it did not see made).
 * Memory and context requests: wineserver carries them out on the target's task (process_vm_readv, ptrace), where
 * kb_ptrace names the target and kb_unknown_peer decides them as peer or thread-peer; each is kept, with what it
 * reaches, as the client thread's pending request, which a new request or wineserver's reply ends. Every other
 * request is decided now on the placeholder program \@unknown, which only a rule naming it meets (no wildcard rule:
 * these requests were not decided before it, so rules written before it keep what they meet). A process a
 * get_process_info reply named for the handle (kb_learnt) serves addr= alone: the module table of its ranges, and
 * after an allowed placeholder decision one that only addr= rules meet, on that program.
 */
static __always_inline int unknown_handle(struct kb_cfg* c, struct kb_scratch* s, __u32 ownerTid, __u32 tgid,
                                          __u32 thread, __u32 access, __u64 data, __u32 size)
{
    __u32 req = s->request[0];
    __u32 target = thread ? KFILTER_TARGET_THREAD_PEER : KFILTER_TARGET_PEER;
    struct kb_hkey_id id = {tgid, s->request[3]};
    __u32* learnt = bpf_map_lookup_elem(&kb_learnt, &id);
    __u32 object = learnt && *learnt != tgid ? *learnt : 0;   /* a handle to itself names no peer */
    if (req == KB_REQ_GET_PROCESS_INFO && object == 0) learn_handle(s, ownerTid, tgid);
    if ((c->targets & target) == 0) return 0;
    __u32 addressed = kb_request_access(object, data, size);
    if (req == KB_REQ_READ_PROCESS_MEMORY || req == KB_REQ_WRITE_PROCESS_MEMORY || req == KB_REQ_GET_THREAD_CONTEXT ||
        req == KB_REQ_SET_THREAD_CONTEXT) {
        struct kb_access* a = addressed ? bpf_task_storage_get(&kb_accesses, bpf_get_current_task_btf(), 0, 0) : 0;
        s->pending.req = req;
        s->pending.owner = tgid;
        s->pending.object.tgid = 0;
        s->pending.object.thread = thread;
        s->pending.object.access = access;
        s->pending.object.pid = 0;
        s->pending.key.len = 0;
        s->pending.key.kind = addressed;   /* kb_unknown_peer's flags; what the request reaches follows */
        struct kb_access* kept = (struct kb_access*)s->pending.key.path;
        if (a) {
            bpf_probe_read_kernel(kept, sizeof(*a), a);
        } else if (addressed) {
            kept->count = 0;
            kept->unknown = 1;   /* no room for the address: an unknown one */
        }
        bpf_map_update_elem(&kb_pending, &ownerTid, &s->pending, BPF_ANY);
        return 0;
    }
    if (access == 0) return 0;
    set_path(s, "\\@unknown", 9);
    if (object != 0 && (addressed & KB_ADDRESSED) != 0) addressed |= KB_LEARNED;
    s->htarget = target | (addressed | KB_NAMED_ONLY) << 24;
    s->hremoved = access;
    s->haccess = access;
    return KB_HANDLE_DECIDE;
}

/* peer_handle for a request through a handle to Object, with what the request reaches in Object's memory. */
static __always_inline int peer_request(struct kb_cfg* c, struct kb_scratch* s, __u32 object, __u32 thread,
                                        __u32 access, __u64 data, __u32 size)
{
    int code = peer_handle(c, s, object, thread, access);
    if (code != 0) s->htarget |= kb_request_access(object, data, size) << 24;
    return code;
}

/* wineserver, serving Client's thread ClientTid, reaches Child for a request unknown_handle kept: a peer or
 * thread-peer decision of Client on Child's program (not its own) at the first reach, with what the request
 * reaches in Child's memory; its later reaches of Child (Wine 11 falls back from a refused process_vm_readv to ptrace
 * and /proc/<pid>/mem) meet that verdict without another event, until the reply ends the entry. Rule-only. */
__noinline int kb_unknown_peer(__u64 childAddress, __u32 client, __u32 clientTid)
{
    struct kb_cfg* c = kb_cfg_get();
    if (!c || !c->enabled || c->mode == KFILTER_MODE_OFF) return 0;
    struct kb_pending* pending = bpf_map_lookup_elem(&kb_pending, &clientTid);
    if (!pending || pending->owner != client) return 0;
    __u32 req = pending->req;
    if (req != KB_REQ_READ_PROCESS_MEMORY && req != KB_REQ_WRITE_PROCESS_MEMORY && req != KB_REQ_GET_THREAD_CONTEXT &&
        req != KB_REQ_SET_THREAD_CONTEXT) return 0;
    __u32 object = BPF_CORE_READ((struct task_struct*)childAddress, tgid);
    /* object.tgid: the program decided (unknown_handle leaves it 0), object.pid: 1 once it was refused. */
    if (pending->object.tgid != 0) return pending->object.tgid == object && pending->object.pid != 0 ? -EPERM : 0;
    if (object == client) return 0;
    pending->object.tgid = object;
    __u32 thread = pending->object.thread, access = pending->object.access, addressed = pending->key.kind;
    struct kb_access* a = addressed ? bpf_task_storage_get(&kb_accesses, bpf_get_current_task_btf(), 0,
                                                           BPF_LOCAL_STORAGE_GET_F_CREATE) : 0;
    if (a) bpf_probe_read_kernel(a, sizeof(*a), pending->key.path);   /* none: an unknown address */
    if (a) a->target = object;
    struct kb_scratch* s = reset_for(client, 1);
    if (!s || peer_handle(c, s, object, thread, access) == 0) return 0;
    s->htarget |= addressed << 24;
    int refused = kb_handle_decide();
    pending = bpf_map_lookup_elem(&kb_pending, &clientTid);
    if (refused != 0 && pending && pending->owner == client && pending->object.tgid == object) pending->object.pid = 1;
    return refused;
}

/*
 * A protected program's Wine request (header in s->request, data at Data, Size bytes) that
 * reaches another protected program, or asks about the system: process and thread requests on
 * another Wine program's handle (remote threads, memory, context, suspension, process queries,
 * mapped file names, its token) are prepared as peer or thread-peer decisions (KB_HANDLE_DECIDE),
 * whether that program is protected or not; on its own (not by pseudo handle), enumerations,
 * named objects, tokens and hiding from a debugger as system decisions on
 * /system/wine/<request>[/<object name>] (KB_SYSTEM_DECIDE | right), by pseudo handle on
 * /system/wine/self/<request>, with the calling module for module= rules. Rule-only: the hook
 * decides only where a rule names them. A handle to an outside program was also decided when it
 * was made (object.c); a peer rule decides each request. Through a handle kfilter cannot name
 * (inherited, evicted from kb_ohandles, get_next_process's), see unknown_handle. A request on memory
 * carries what it reaches (kb_request_access) for addr= rules. Every other request (no row of its own) is
 * /system/wine/<request> where a system rule names it past /system/wine/ (kb_wnamed; KB_WINE_ROOT: no broader rule
 * meets it, as none did before), its right by its name: query to read or open, create, else write.
 * shortcut: object names are as the program gave them, relative to their root directory
 * (\BaseNamedObjects for kernelbase's), and match case-sensitively as every /... path does;
 * name directory handles (as registry keys are) if rules must name the full NT path.
 */
__noinline int kb_wine_query(__u32 tgid, __u32 ownerTid, __u64 data, __u32 size)
{
    struct kb_cfg* c = kb_cfg_get();
    struct kb_scratch* s = scratch();
    if (!c || !s || !c->enabled || c->mode == KFILTER_MODE_OFF) return 0;
    __u32 req = s->request[0];
    if (req >= KB_REQ_COUNT) return 0;
    if (req == KB_REQ_GET_THREAD_INFO) {   /* its reply can name a thread handle */
        struct kb_hkey_id id = {tgid, s->request[3]};
        struct kb_ohandle* record = id.handle < 0xFFFFFFFAu ? bpf_map_lookup_elem(&kb_ohandles, &id) : 0;
        if (id.handle < 0xFFFFFFFAu && (!record || ohandle_tgid(record) == 0)) learn_handle(s, ownerTid, tgid);
    }
    /* get_image_view_info was never decided: only while an addr= rule can. */
    if (req == KB_REQ_GET_IMAGE_VIEW_INFO && (c->flags & KB_CFG_ADDRESS) == 0) return 0;
    const struct kb_wreq* w = &kb_wreqs[req];
    __u32 kind = w->kind, right = w->right, listed = 0;
    if (kind == KB_W_NAMED) {
        if (!named_request(req)) return 0;
        right = kb_wnames[req].right;
        listed = KB_SYSTEM_NAMED;
    }
    /* What its rules' value= names (0x%08X): a context read's flags, a thread change's mask, a volume query's class,
     * a hotkey's key; a rule without value= decides it as before. */
    __u32 word = req == KB_REQ_GET_THREAD_CONTEXT ? 5 : req == KB_REQ_SET_THREAD_INFO ? 12
                 : req == KB_REQ_GET_VOLUME_INFO ? 14 : req == KB_REQ_REGISTER_HOTKEY ? 6 : 0;
    if (word != 0) device_value(s, s->request[word & 15]);
    __u32 self = 0;
    if (kind == KB_W_HANDLE || kind == KB_W_EITHER) {
        __u32 handle = s->request[3];
        __u32 pseudo = handle == KB_CURRENT_PROCESS || handle == KB_CURRENT_THREAD;
        struct kb_hkey_id id = {tgid, handle};
        struct kb_ohandle* record = pseudo ? 0 : bpf_map_lookup_elem(&kb_ohandles, &id);
        if (record) {
            __u32 object = ohandle_tgid(record), thread = record->thread;
            __u32 access = req == KB_REQ_OPEN_TOKEN && thread ? 0x40 /* THREAD_QUERY_INFORMATION */
                           : req != KB_REQ_QUEUE_APC ? w->access
                           : thread ? 0x10 /* THREAD_SET_CONTEXT: a user APC */ : apc_access(data, size);
            /* Any other Wine program kfilter tracks, protected or not (explorer.exe, services.exe):
             * rule-only, so a peer rule can refuse each request per target. One it cannot name
             * (get_next_process's) is decided when wineserver reaches its task (kb_unknown_peer). */
            if (object != tgid) return object != 0 ? peer_request(c, s, object, thread, access, data, size)
                                                   : unknown_handle(c, s, ownerTid, tgid, thread, access, data, size);
        } else if (kind == KB_W_HANDLE && !pseudo) {
            /* No record: the request says which kind of handle it is; a queue_apc's APC does. */
            __u32 apc = req == KB_REQ_QUEUE_APC ? apc_access(data, size) : 0;
            __u32 thread = req == KB_REQ_TERMINATE_THREAD || req == KB_REQ_SUSPEND_THREAD ||
                           req == KB_REQ_RESUME_THREAD || req == KB_REQ_GET_THREAD_CONTEXT ||
                           req == KB_REQ_SET_THREAD_CONTEXT || (req == KB_REQ_QUEUE_APC && apc == 0);
            __u32 access = req != KB_REQ_QUEUE_APC ? w->access : apc != 0 ? apc : 0x10 /* a user APC */;
            return unknown_handle(c, s, ownerTid, tgid, thread, access, data, size);
        } else if (kind == KB_W_HANDLE) {
            /* Its own process or thread by pseudo handle (GetCurrentProcess(), GetCurrentThread()) is
             * /system/wine/self/<request>, apart from /system/wine/<request> (by a real handle to itself),
             * whose rules Wine's own context reads must not meet; only while a rule can name it. */
            if (!c->self_rules) return 0;
            self = 1;
        }
    } else if (req == KB_REQ_SET_THREAD_INFO && (s->request[12] & 0x40) == 0) {
        return 0;   /* only SET_THREAD_INFO_DBG_HIDDEN (mask at +48): ThreadHideFromDebugger; the rest: value_variant */
    }
    if ((c->targets & KFILTER_TARGET_SYSTEM) == 0) return 0;
    if (self) set_path(s, "/system/wine/self/", 18);
    else set_path(s, "/system/wine/", 13);
    __u32 head = self ? 18 : 13;
    bpf_probe_read_kernel(&s->path[head & 31], sizeof(kb_wnames[0].name), kb_wnames[req].name);
    s->len = head + (kb_wnames[req].len & 31);
    if (kind == KB_W_CREATE || kind == KB_W_OPEN) {
        __u64 name = data;
        __u32 bytes = size;
        if (kind == KB_W_CREATE) {
            __u32 attributes[4] = {};   /* objattr: rootdir, attributes, sd_len, name_len; sd; name */
            __u32 total = s->request[1];
            if (size < 16 || bpf_probe_read_kernel(attributes, sizeof(attributes), (void*)data) != 0) return 0;
            /* An unnamed object (most events and mappings) is the program's own business. */
            if (attributes[3] == 0 || attributes[2] > total - 16 || attributes[3] > total - 16 - attributes[2]) return 0;
            bytes = attributes[3] < KB_PATH ? attributes[3] : KB_PATH;   /* a longer name keeps its head */
            name = request_bytes(data, &size, 16 + attributes[2], bytes);   /* 0: read_name fails (a name failure) */
        }
        int chars = read_name(name, bytes < KB_PATH ? bytes : KB_PATH);
        if (chars > 0) {
            s->path[s->len & (KB_PATH - 1)] = '/';
            s->len += 1;
            struct u16_ctx convert = {(__u32)chars, s->len, 0};
            bpf_loop(KB_PATH / 2, u16_step, &convert, 0);
            s->len += chars;
            s->path[s->len & (KB_PATH - 1)] = 0;
            kb_collapse();
        }
    }
    pe_caller(s, 0);
    __u32 addressed = kb_request_access(tgid, data, size);
    if (addressed == 0) return KB_SYSTEM_DECIDE | right | listed;
    /* On its own memory: decided as a handle request (kb_handle_decide), which carries the address. */
    s->htarget = KFILTER_TARGET_SYSTEM | addressed << 24;
    s->hremoved = right;
    return KB_HANDLE_DECIDE;
}

/* ---- what a Wine request reaches past its own decision: windows, threads, handles at any offset, keys ---- */

/*
 * Bookkeeping, kept pending for wineserver's reply, of the request in s->request (Data, Size: its joined data): the
 * owner of the window create_window makes, the desktop's windows (get_desktop_window: no program's), and the NT name of
 * the file a protected program opens with create_file (its objattr), which kb_wine_variant names a handle by.
 */
__noinline int kb_wine_note(__u32 tgid, __u32 ownerTid, __u64 data, __u32 size)
{
    struct kb_scratch* s = scratch();
    if (!s) return 0;
    __u32 req = s->request[0];
    s->pending.req = req;
    s->pending.owner = tgid;
    s->pending.object.tgid = 0;
    s->pending.object.thread = KB_OBJECT_OTHER;   /* create_file's reply handle is no process or thread either */
    s->pending.key.len = 0;
    if (req == KB_REQ_CREATE_FILE) {
        __u32 attributes[4] = {};   /* objattr: rootdir, attributes, sd_len, name_len; sd; name */
        if (size < 16 || bpf_probe_read_kernel(attributes, sizeof(attributes), (void*)data) != 0) return 0;
        __u64 name = attributes[3] != 0 ? request_bytes(data, &size, 16 + (attributes[2] & ~1u), attributes[3]) : 0;
        if (name == 0) return 0;
        int chars = read_name(name, attributes[3]);
        if (chars <= 0 || key_path(tgid, attributes[0], (__u32)chars) != 0 || s->failed) return 0;
        s->pending.key.len = s->len;
        s->pending.key.kind = KB_HKEY_FILE;
        bpf_probe_read_kernel(s->pending.key.path, KB_PATH, s->path);
    }
    bpf_map_update_elem(&kb_pending, &ownerTid, &s->pending, BPF_ANY);
    return 0;
}

/* The program behind a window handle (kb_windows), 0 when kfilter cannot place it: a high word of 0 or 0xFFFF finds
 * the window at any generation, as wineserver does. */
static __always_inline __u32 window_owner(__u32 handle)
{
    __u32 index = handle & 0xFFFF, gen = handle >> 16;
    struct kb_window* window = bpf_map_lookup_elem(&kb_windows, &index);
    if (!window || (gen != 0 && gen != 0xFFFF && gen != window->gen)) return 0;
    return window->tgid;
}

/* The program owning a window or thread id: 0 when kfilter cannot place it (an owner that exited is a stale entry). */
static __always_inline __u32 owner_of(__u32 thread, __u32 id)
{
    __u32* found = thread ? bpf_map_lookup_elem(&kb_wintids, &id) : 0;
    __u32 owner = thread ? (found ? *found : 0) : window_owner(id);
    return owner == 0 || owner == KB_WINDOW_SHARED || bpf_map_lookup_elem(&kb_procs, &owner) ? owner : 0;
}

/* Index 0 and 1: the program of each thread id or window the request names (KB_T_TID, KB_T_WINDOW), by its
 * pseudo-right, with the message, offset or key as its value; a request naming two decides each other program's once.
 * One kfilter cannot place is \@unknown-thread or \@unknown-window: only deny and audit rules naming it decide it. */
static __always_inline int owner_variant(struct kb_scratch* s, const struct kb_wtarget* t, __u32 index)
{
    __u32 thread = t->kind == KB_T_TID;
    if (index > 1 || (index == 1 && t->field2 == 0)) return 0;
    __u32 id = s->request[(index != 0 ? t->field2 : t->field) & 15];
    __u32 owner = owner_of(thread, id);
    if (id == 0 || owner == s->tgid || owner == KB_WINDOW_SHARED) return -1;
    if (index == 1) {
        __u32 first = s->request[t->field & 15];
        if (first != 0 && owner_of(thread, first) == owner) return -1;   /* decided as the first one's */
    }
    int listed = 1;
    if (owner == 0) {
        if (thread) set_path(s, "\\@unknown-thread", 16);
        else set_path(s, "\\@unknown-window", 16);
        listed |= KB_NAMED_ONLY;   /* allows naming it are not loaded (kfilterd): one cannot vouch for it */
    } else {
        program_path(s, 0, owner);
    }
    if (t->vfield != 0) device_value(s, s->request[t->vfield & 15]);
    s->htarget = KB_TARGET_WINDOW;
    s->hremoved = t->access;
    return listed;
}

/* Index 0: the process or thread a handle at the request's offset reaches (KB_T_HANDLE), with the access wineserver
 * asks of it; its value is the request's name, and only peer and thread-peer rules with value= meet it (PEER_VALUE,
 * THREAD_VALUE: these requests were not decided on that program before). Its own process or thread is no decision
 * (/system/wine/<request> is); a handle kfilter cannot name is \@unknown, as K1's requests through one. */
static __always_inline int handle_variant(struct kb_cfg* c, struct kb_scratch* s, const struct kb_wtarget* t, __u32 index)
{
    __u32 req = s->request[0] & 511;
    __u32 handle = s->request[t->field & 15];
    __u32 thread = req == KB_REQ_GET_THREAD_INFO || req == KB_REQ_GET_THREAD_TIMES || req == KB_REQ_CANCEL_SYNC;
    /* get_thread_info: wineserver asks the query rights the client asks (+16), else THREAD_QUERY_LIMITED_INFORMATION
     * (Wine's own NtQueryInformationThread asks none). */
    __u32 asked = s->request[4] & 0x840;
    __u32 access = req != KB_REQ_GET_THREAD_INFO ? t->access : asked != 0 ? asked : 0x800;
    if (index != 0 || (c->targets & (KB_TARGET_PEER_VALUE | KB_TARGET_THREAD_VALUE)) == 0 || access == 0 ||
        req >= KB_REQ_COUNT) return 0;
    if (handle == KB_CURRENT_PROCESS || handle == KB_CURRENT_THREAD) return -1;
    struct kb_hkey_id id = {s->tgid, handle};
    struct kb_ohandle* record = bpf_map_lookup_elem(&kb_ohandles, &id);
    __u32 object = record ? ohandle_tgid(record) : 0;
    int listed = 1;
    if (record) thread = record->thread;
    if (object == s->tgid) return -1;
    /* The family's own new child before it starts (new_process's handle; new_process gave its creator full access):
     * CreateProcess's first thread in it, the job Chromium puts it in, WaitForInputIdle on it. */
    if (record && object == 0 && record->pid != 0) return -1;
    if (object != 0) {
        if (!bpf_map_lookup_elem(&kb_procs, &object)) return -1;   /* exited */
        program_path(s, 0, object);
    } else {
        if (!record && (bpf_map_lookup_elem(&kb_xhandles, &id) || inherited_other(&id))) return -1;   /* no process */
        set_path(s, "\\@unknown", 9);
        listed |= KB_NAMED_ONLY;
    }
    bpf_probe_read_kernel(s->value, sizeof(kb_wnames[0].name), kb_wnames[req].name);
    s->vlen = kb_wnames[req].len & 31;
    s->htarget = thread ? KB_TARGET_THREAD_VALUE : KB_TARGET_PEER_VALUE;
    s->hremoved = access;
    return listed;
}

/* s->path += "0x" and 8 lowercase hex digits. */
static __always_inline void append_code(struct kb_scratch* s, __u32 value)
{
    append_text(s, "0x", 2);
    append_hex(s, value, 8);
}

/* s->path += the NT name of a handle of the program (kb_hkeys: a device, pipe or section; kb_fnames: a create_file),
 * "@unknown" for one kfilter did not name. */
static __always_inline void handle_name(struct kb_scratch* s, __u32 handle)
{
    struct kb_hkey_id id = {s->tgid, handle};
    struct kb_hkey* name = bpf_map_lookup_elem(&kb_hkeys, &id);
    if (!name) name = bpf_map_lookup_elem(&kb_fnames, &id);
    if (!name || name->len == 0 || name->len >= KB_PATH || s->len + name->len >= KB_PATH) append_text(s, "@unknown", 8);
    else append_string(s, name->path, 0);
}

#define KB_FSCTL_PIPE_TRANSCEIVE 0x0011C017u

/*
 * A DCE/RPC PDU written to (write) or transceived on (ioctl) a named pipe handle, in Data: a bind or alter_context
 * keeps its first context's interface for the handle (kb_rpcs, no decision); a request on that context is
 * /system/rpc/<interface uuid>/<opnum> (svcctl's RStartServiceW: /system/rpc/367abb81-9844-35f1-ad32-98f038001003/19).
 * shortcut: one context per handle, little-endian PDUs (every Windows client's); upgrade: a context table if a client
 * binds several interfaces on one pipe.
 */
static __always_inline int rpc_variant(struct kb_scratch* s, __u32 handle, __u64 data, __u32 size)
{
    struct kb_hkey_id id = {s->tgid, handle};
    struct kb_hkey* pipe = bpf_map_lookup_elem(&kb_hkeys, &id);
    __u8* pdu = s->name;   /* the header (and a bind's first context), read past the scratch's name buffer */
    if (!pipe || pipe->kind != KB_HKEY_PIPE || data == 0 || size < 24 ||
        bpf_probe_read_kernel(pdu, 48, (void*)data) != 0 || pdu[0] != 5) return -1;   /* rpc_vers 5 */
    if (pdu[2] == 11 || pdu[2] == 14) {   /* bind, alter_context: p_cont_id@28, abstract syntax uuid@32 */
        struct kb_rpc bound = {};
        if (size < 48 || bpf_probe_read_kernel(bound.uuid, 16, (void*)(data + 32)) != 0) return -1;
        bound.context = pdu[28] | pdu[29] << 8;
        bpf_map_update_elem(&kb_rpcs, &id, &bound, BPF_ANY);
        return -1;
    }
    struct kb_rpc* bound = bpf_map_lookup_elem(&kb_rpcs, &id);
    if (pdu[2] != 0 || !bound || bound->context != (__u32)(pdu[20] | pdu[21] << 8)) return -1;   /* a request */
    set_path(s, "/system/rpc/", 12);
    __u8* u = bound->uuid;
    append_hex(s, u[0] | u[1] << 8 | u[2] << 16 | (__u32)u[3] << 24, 8);
    append_text(s, "-", 1);
    append_hex(s, u[4] | u[5] << 8, 4);
    append_text(s, "-", 1);
    append_hex(s, u[6] | u[7] << 8, 4);
    append_text(s, "-", 1);
    append_hex(s, u[8] << 8 | u[9], 4);
    append_text(s, "-", 1);
    append_hex(s, u[10] << 8 | u[11], 4);
    append_hex(s, u[12] << 24 | u[13] << 16 | u[14] << 8 | u[15], 8);
    append_text(s, "/", 1);
    append_number(s, pdu[22] | pdu[23] << 8);   /* opnum */
    s->htarget = KB_TARGET_KEYED;
    s->hremoved = KFILTER_RIGHT_WRITE;
    return 1;
}

/* new_process's child image, from its startup info (96 bytes after objattr, handles and jobs, then the curdir, dllpath
 * and imagepath strings, read where they lie in the request's data, past its first 4 KiB too); "@unknown" when it
 * cannot be read. */
static __always_inline void child_image(struct kb_scratch* s, __u64 data, __u32 size)
{
    __u32 head[4] = {};   /* objattr: rootdir, attributes, sd_len, name_len */
    __u32 lengths[3] = {};   /* curdir, dllpath, imagepath at +64 of the startup info */
    __u64 at = 0, image = 0, bytes = 0, info = 0, name = 0;
    if (size >= 16 && bpf_probe_read_kernel(head, sizeof(head), (void*)data) == 0) {
        at = ((16ull + (head[2] & ~1u) + (head[3] & ~1u) + 3) & ~3ull) + s->request[11] + s->request[12];
        if (at + 96 <= s->request[1]) info = request_bytes(data, &size, (__u32)at + 64, sizeof(lengths));
        if (info != 0 && bpf_probe_read_kernel(lengths, sizeof(lengths), (void*)info) == 0) {
            image = at + 96 + lengths[0] + lengths[1];
            bytes = lengths[2];
        }
    }
    if (bytes != 0 && bytes <= KB_PATH && image + bytes <= s->request[1])
        name = request_bytes(data, &size, (__u32)image, (__u32)bytes);
    int chars = name != 0 ? read_name(name, (__u32)bytes) : -1;
    if (chars <= 0 || s->len + chars >= KB_PATH - 32) {
        s->failed = 0;
        append_text(s, "@unknown", 8);
        return;
    }
    struct u16_ctx convert = {(__u32)chars, s->len, 0};
    bpf_loop(KB_PATH / 2, u16_step, &convert, 0);
    s->len += chars;
    s->path[s->len & (KB_PATH - 1)] = 0;
    kb_collapse();
}

/*
 * Index of a request's keyed decisions (KB_T_KEY), /system/wine/<request>/<key> (rules naming the key alone meet them,
 * after the request's own decision on /system/wine/<request>): set_hook/<WH id>/<global|process|thread>,
 * get_key_state/<0xvkey|all>, send_hardware_message/<injected|hardware>/<keyboard|mouse|hid> (value: the key),
 * set_cursor/<pos|clip|show> (one for each it does), update_rawinput_devices/<inputsink|normal>,
 * get_clipboard_data/<format>, ioctl/<NT name>/0x<code>, read/<NT name>, write/<NT name>, new_process/<image>
 * [/spoofed-parent][/debug]; write's and FSCTL_PIPE_TRANSCEIVE's RPC call (rpc_variant).
 */
static __always_inline int key_variant(struct kb_cfg* c, struct kb_scratch* s, __u32 index, __u64 data, __u32 size)
{
    __u32 req = s->request[0] & 511;
    if (req >= KB_REQ_COUNT) return 0;
    if ((c->targets & KB_TARGET_KEYED) == 0) return 0;
    __u32 handle = s->request[4];   /* read, write, ioctl: async_data_t's handle at +16 */
    if (index == 1 && req == KB_REQ_WRITE) return rpc_variant(s, handle, data, size);
    if (index == 1 && req == KB_REQ_IOCTL && s->request[3] == KB_FSCTL_PIPE_TRANSCEIVE) return rpc_variant(s, handle, data, size);
    if (index > 2 || (index != 0 && req != KB_REQ_SET_CURSOR)) return 0;
    set_path(s, "/system/wine/", 13);
    bpf_probe_read_kernel(&s->path[13], sizeof(kb_wnames[0].name), kb_wnames[req].name);
    s->len = 13 + (kb_wnames[req].len & 31);
    append_text(s, "/", 1);
    __u32 key = s->request[3];
    if (req == KB_REQ_SET_HOOK) {   /* id@0xc (WH_*, signed), pid@0x10, tid@0x14 */
        if ((int)key < 0) append_text(s, "-", 1);
        append_number(s, (int)key < 0 ? -key : key);
        if (s->request[5] != 0) append_text(s, "/thread", 7);
        else if (s->request[4] != 0) append_text(s, "/process", 8);
        else append_text(s, "/global", 7);
    } else if (req == KB_REQ_GET_KEY_STATE) {   /* key@0x10: -1 asks for the whole table */
        if ((int)s->request[4] < 0) append_text(s, "all", 3);
        else append_code(s, s->request[4]);
    } else if (req == KB_REQ_SEND_HARDWARE_MESSAGE) {   /* input.type@0x10, kbd.vkey@0x14, flags@0x38 */
        __u32 type = s->request[4];
        if ((s->request[14] & 1) != 0) append_text(s, "injected/", 9);   /* SEND_HWMSG_INJECTED: SendInput */
        else append_text(s, "hardware/", 9);
        if (type == 0) append_text(s, "mouse", 5);
        else if (type == 1) append_text(s, "keyboard", 8);
        else if (type == 2) append_text(s, "hid", 3);
        else append_number(s, type);
        if (type == 1) device_value(s, s->request[5] & 0xFFFF);
    } else if (req == KB_REQ_SET_CURSOR) {   /* flags@0xc: HANDLE 1, COUNT 2, POS 4, CLIP 8, NOCLIP 0x10, FSCLIP 0x20 */
        if ((key & (index == 0 ? 0x04 : index == 1 ? 0x38 : 0x03)) == 0) return -1;
        if (index == 0) append_text(s, "pos", 3);
        else if (index == 1) append_text(s, "clip", 4);
        else append_text(s, "show", 4);
    } else if (req == KB_REQ_UPDATE_RAWINPUT_DEVICES) {   /* devices: usage page, usage, flags, target; 12 bytes */
        __u32 sink = 0, flags = 0;
        for (__u32 i = 0; i < 16; i++) {   /* shortcut: the first 16 devices; a program registers a handful */
            if ((i + 1) * 12 > size) break;
            if (bpf_probe_read_kernel(&flags, 4, (void*)(data + i * 12 + 4)) == 0 && (flags & 0x1100) != 0) sink = 1;
        }
        if (s->request[1] != 0 && data == 0) append_text(s, "@unknown", 8);
        else if (sink) append_text(s, "inputsink", 9);   /* RIDEV_INPUTSINK, RIDEV_EXINPUTSINK: input in the background */
        else append_text(s, "normal", 6);
    } else if (req == KB_REQ_GET_CLIPBOARD_DATA) {
        append_number(s, key);
    } else if (req == KB_REQ_IOCTL) {   /* code@0xc */
        handle_name(s, handle);
        append_text(s, "/", 1);
        append_code(s, key);
    } else if (req == KB_REQ_READ || req == KB_REQ_WRITE) {
        handle_name(s, handle);
    } else if (req == KB_REQ_NEW_PROCESS) {   /* debug@0x10, parent_process@0x14 */
        child_image(s, data, size);
        if (s->request[5] != 0) append_text(s, "/spoofed-parent", 15);
        if (s->request[4] != 0) append_text(s, "/debug", 6);
    } else {
        return 0;
    }
    s->htarget = KB_TARGET_KEYED;
    s->hremoved = kb_wnames[req].right;
    return 1;
}

/* Index of a system request's decisions by value= alone (KB_T_VALUE: SYSTEM_VALUE, which only system rules with value=
 * meet): set_thread_info's mask without ThreadHideFromDebugger (with it its own decision carries the mask), and each of
 * adjust_token_privileges' privileges (the first KB_VARIANTS), 0x%08X of its LUID, so a rule naming one meets the
 * request wherever the privilege lies in it. */
static __always_inline int value_variant(struct kb_cfg* c, struct kb_scratch* s, __u32 index, __u64 data, __u32 size)
{
    __u32 req = s->request[0] & 511, value = 0;
    if (req >= KB_REQ_COUNT || (c->targets & KB_TARGET_SYSTEM_VALUE) == 0) return 0;
    if (req == KB_REQ_SET_THREAD_INFO) {
        if (index != 0 || (s->request[12] & 0x40) != 0) return 0;
        value = s->request[12];
    } else if (index >= KB_VARIANTS || (index + 1) * 12 > size ||
               bpf_probe_read_kernel(&value, 4, (void*)(data + index * 12)) != 0) {
        return 0;   /* privileges: luid (low, high), attributes; 12 bytes each */
    }
    set_path(s, "/system/wine/", 13);
    bpf_probe_read_kernel(&s->path[13], sizeof(kb_wnames[0].name), kb_wnames[req].name);
    s->len = 13 + (kb_wnames[req].len & 31);
    device_value(s, value);
    s->htarget = KB_TARGET_SYSTEM_VALUE;
    s->hremoved = KFILTER_RIGHT_WRITE;
    return 1;
}

/* Decision Index past the request's own (the request in s->request; Data, Size: its joined data), prepared in the
 * scratch (path, value, s->htarget its target, s->hremoved its rights): kb_decide_global's Listed, 0 when there is no
 * such decision, -1 when this one is not made. */
__noinline int kb_wine_variant(__u32 index, __u64 data, __u32 size)
{
    struct kb_cfg* c = kb_cfg_get();
    struct kb_scratch* s = scratch();
    __u32 req = s ? s->request[0] : KB_REQ_COUNT;
    if (!c || !s || req >= KB_REQ_COUNT) return 0;
    const struct kb_wtarget* t = &kb_wtargets[req];
    s->failed = 0;
    s->vlen = 0;
    s->len = 0;
    if (t->kind == KB_T_HANDLE) return handle_variant(c, s, t, index);
    if (t->kind == KB_T_TID || t->kind == KB_T_WINDOW) return (c->targets & KB_TARGET_WINDOW) != 0 ? owner_variant(s, t, index) : 0;
    if (t->kind == KB_T_KEY) return key_variant(c, s, index, data, size);
    if (t->kind == KB_T_VALUE) return value_variant(c, s, index, data, size);
    return 0;
}

/*
 * What a protected program's Wine request reaches past its own decision (kb_wtargets), decided after it: another
 * program's process or thread through a handle at any offset, the program owning a window or a thread the request
 * names, its keyed decisions; each in turn, a refusal ending them. s->haccess: the bytes of its data kb_request_data
 * joined (0: none). Rule-only. Returns 0 or -EPERM.
 */
__noinline int kb_wine_decide(void)
{
    struct kb_cfg* c = kb_cfg_get();
    struct kb_scratch* s = scratch();
    if (!c || !s || !c->enabled || c->mode == KFILTER_MODE_OFF) return 0;
    __u32 size = s->haccess;
    struct kb_reqdata* d = size != 0 ? bpf_task_storage_get(&kb_reqdata, bpf_get_current_task_btf(), 0, 0) : 0;
    __u64 data = d ? address_of(d->data) : 0;
    if (!d) size = 0;
    pe_caller(s, 0);   /* module= on keyed rules */
    for (__u32 index = 0; index < KB_VARIANTS; index++) {
        int listed = kb_wine_variant(index, data, size);
        if (listed == 0) break;
        if (listed < 0) continue;
        if (kb_decide_global(s->htarget, s->hremoved, 0, (__u32)listed & (1 | KB_NAMED_ONLY)) != 0) return -EPERM;
    }
    return 0;
}

/* A thread a protected program creates (task_alloc with CLONE_THREAD): a thread decision on the
 * program it runs in, with the creating module for module= rules. Rule-only. Fork: a process it creates without a
 * thread (fork, vfork, clone; its exec is decided apart): /system/fork, create, a system decision of ABI 11. */
__noinline int kb_thread_decide(__u32 fork)
{
    struct kb_scratch* s = reset_for(current_tgid(), 0);
    if (!s) return 0;
    if (fork) set_path(s, "/system/fork", 12);
    else program_path(s, bpf_get_current_task_btf(), s->tgid);
    pe_caller(s, 0);
    return fork ? kb_decide_global(KFILTER_TARGET_SYSTEM, KFILTER_RIGHT_CREATE, 0, 1 | KB_ROOT(12))
                : kb_decide_global(KFILTER_TARGET_THREAD, KFILTER_RIGHT_CREATE, 0, 1);
}

/* ---- system: rule-only decisions on /system/<what> ---- */

/* Starts a system decision: 1 with the scratch set up when some rule names the system target and
 * the current task works for a protected program, 0 to pass undecided, -ENOMEM to refuse. */
static __always_inline int system_begin(void)
{
    struct kb_cfg* c = kb_cfg_get();
    if (!c || (c->targets & KFILTER_TARGET_SYSTEM) == 0) return 0;
    int started = begin();
    return started == 0 ? 1 : started < 0 ? -ENOMEM : 0;
}

/* The system decision on s->path, with the calling Windows module for module= rules; Listed as kb_decide_global's
 * (rule-only: 1, with the match flags of a decision only rules naming it meet). */
__noinline int kb_system_decide(__u32 rights, __u32 listed)
{
    struct kb_scratch* s = scratch();
    if (!s) return 0;
    pe_caller(s, 0);
    return kb_decide_global(KFILTER_TARGET_SYSTEM, rights, 0, listed | 1);
}

struct view_ctx {
    __u64 top;
    __u64 base;
    __u32 tgid;
};

static long view_step(__u32 index, struct view_ctx* v)
{
    __u64 down = (__u64)index << 16;
    if (down > v->top) return 1;
    struct kb_view key = {v->tgid, 0, v->top - down};
    if (!bpf_map_lookup_elem(&kb_views, &key)) return 0;
    v->base = key.base;
    return 1;
}

/* Anonymous memory a protected program maps or protects without execute (ABI 11, while a rule names it: KB_MEMORY_DATA):
 * /system/memory/<private|shared>/<rw|r|none>, write, reaching [Start, End) of its memory for addr= rules (Start 0: an
 * unknown place). Met only by rules naming the protection past the kind (a wildcard right after private/ does not). */
static __always_inline int memory_data(struct kb_scratch* s, __u64 start, __u64 end, __u32 prot, __u32 shared)
{
    if (shared) set_path(s, "/system/memory/shared/", 22);
    else set_path(s, "/system/memory/private/", 23);
    if ((prot & PROT_WRITE) != 0) append_text(s, "rw", 2);
    else if ((prot & PROT_READ) != 0) append_text(s, "r", 1);
    else append_text(s, "none", 4);
    struct kb_access* a = bpf_task_storage_get(&kb_accesses, bpf_get_current_task_btf(), 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (a) {
        a->target = s->tgid;
        a->count = 0;
        a->unknown = start == 0 || end <= start;
        if (!a->unknown) access_add(a, start, end - start);
    }
    return kb_system_decide(KFILTER_RIGHT_WRITE, KB_ADDRESSED | KB_ROOT(shared ? 23 : 24));
}

/*
 * Executable anonymous memory a protected program maps or makes executable (or writable while
 * executable): a system decision on /system/memory/<private|shared|image>/<rx|rwx>, execute, with the
 * calling module for module= rules. Image: inside a PE image view (kb_views, the nearest within
 * 256 MiB below, and its SizeOfImage), where Wine copies sections whose file alignment is under a
 * page. [Start, End) is the request; Start 0 when the kernel picks the place, never inside a view.
 * shortcut: a program can map any PE file at offset 0 in place and call the memory above it image;
 * decide image/rx as execute of the view's file (keep its path in kb_views) if a rule must see that.
 */
__noinline int kb_memory_decide(__u64 start, __u64 end, __u32 prot, __u32 shared)
{
    struct kb_cfg* c = kb_cfg_get();
    __u32 code = (prot & PROT_EXEC) != 0;
    if (!c || (c->memory_rules & (code ? 1 : KB_MEMORY_DATA)) == 0) return 0;
    int started = begin();
    if (started != 0) return started < 0 ? -EPERM : 0;
    struct kb_scratch* s = scratch();
    struct kb_task* state = task_state(bpf_get_current_task_btf());
    if (!s || s->brokered) return 0;   /* wineserver's or winedevice's own memory */
    if (!code) return memory_data(s, start, end, prot, shared);
    int image = 0;
    if (!shared && start != 0 && state && state->role == KB_ROLE_WINE) {
        struct view_ctx v = {start & ~0xFFFFull, 0, s->tgid};
        bpf_loop(4096, view_step, &v, 0);
        __u32 lfanew = v.base ? pe_at(v.base) : 0;
        __u32 size = 0;
        if (lfanew) bpf_probe_read_user(&size, 4, (void*)(v.base + lfanew + 80));   /* OptionalHeader.SizeOfImage */
        image = end <= v.base + size;
    }
    if (shared) set_path(s, "/system/memory/shared/", 22);
    else if (image) set_path(s, "/system/memory/image/", 21);
    else set_path(s, "/system/memory/private/", 23);
    if ((prot & PROT_WRITE) != 0) append_text(s, "rwx", 3);
    else append_text(s, "rx", 2);
    return kb_system_decide(KFILTER_RIGHT_EXECUTE, 1);
}

static __always_inline long system_named(const char* name, __u32 n, __u32 rights)
{
    int started = system_begin();
    if (started <= 0) return started;
    struct kb_scratch* s = scratch();
    if (!s) return 0;
    set_path(s, name, n);
    return kb_decided(kb_system_decide(rights, 1));
}

/* uname (host name, kernel release) and sysinfo (uptime, memory, load), query: every entry,
 * int 0x80 too (i386 enters the compat sysinfo, and has two older unames). Wine starts with
 * either refused. An x64 fmod_ret returns long (an int -EPERM would read as 0xFFFFFFFF). */
SEC("fmod_ret/__x64_sys_newuname")
long BPF_PROG(kb_uname, struct pt_regs* regs, long ret)
{
    return ret != 0 ? ret : system_named("/system/uname", 13, KFILTER_RIGHT_QUERY);
}

SEC("fmod_ret/__ia32_sys_newuname")
long BPF_PROG(kb_uname32, struct pt_regs* regs, long ret)
{
    return ret != 0 ? ret : system_named("/system/uname", 13, KFILTER_RIGHT_QUERY);
}

SEC("fmod_ret/__ia32_sys_uname")
long BPF_PROG(kb_olduname32, struct pt_regs* regs, long ret)
{
    return ret != 0 ? ret : system_named("/system/uname", 13, KFILTER_RIGHT_QUERY);
}

SEC("fmod_ret/__ia32_sys_olduname")
long BPF_PROG(kb_oldolduname32, struct pt_regs* regs, long ret)
{
    return ret != 0 ? ret : system_named("/system/uname", 13, KFILTER_RIGHT_QUERY);
}

SEC("fmod_ret/__x64_sys_sysinfo")
long BPF_PROG(kb_sysinfo, struct pt_regs* regs, long ret)
{
    return ret != 0 ? ret : system_named("/system/sysinfo", 15, KFILTER_RIGHT_QUERY);
}

SEC("fmod_ret/__ia32_compat_sys_sysinfo")
long BPF_PROG(kb_sysinfo32, struct pt_regs* regs, long ret)
{
    return ret != 0 ? ret : system_named("/system/sysinfo", 15, KFILTER_RIGHT_QUERY);
}

/* Scheduling a task (its own, another's; wineserver's for the client it serves), write:
 * sched_setaffinity and sched_setscheduler/setparam/setattr as /system/sched, setpriority as
 * /system/sched/nice, ioprio_set as /system/sched/ioprio (a rule on /system/sched covers all three). */
SEC("lsm/task_setscheduler")
int BPF_PROG(kb_task_setscheduler, struct task_struct* p, int ret)
{
    return ret != 0 ? ret : (int)system_named("/system/sched", 13, KFILTER_RIGHT_WRITE);
}

SEC("lsm/task_setnice")
int BPF_PROG(kb_task_setnice, struct task_struct* p, int nice, int ret)
{
    return ret != 0 ? ret : (int)system_named("/system/sched/nice", 18, KFILTER_RIGHT_WRITE);
}

SEC("lsm/task_setioprio")
int BPF_PROG(kb_task_setioprio, struct task_struct* p, int ioprio, int ret)
{
    return ret != 0 ? ret : (int)system_named("/system/sched/ioprio", 20, KFILTER_RIGHT_WRITE);
}

/* Socket options: /system/sockopt/<level>/<optname> (level socket, ip, ipv6, tcp, udp or its number), query for
 * getsockopt, write for setsockopt; wineserver's on its client's sockets are the client's. */
__noinline int kb_sockopt_decide(int level, int optname, __u32 rights)
{
    int started = system_begin();
    if (started <= 0) return started;
    struct kb_scratch* s = scratch();
    if (!s) return 0;
    set_path(s, "/system/sockopt/", 16);
    if (level == 1) append_text(s, "socket", 6);   /* SOL_SOCKET */
    else if (level == 0) append_text(s, "ip", 2);
    else if (level == 41) append_text(s, "ipv6", 4);
    else if (level == 6) append_text(s, "tcp", 3);
    else if (level == 17) append_text(s, "udp", 3);
    else append_number(s, (__u32)level);
    append_text(s, "/", 1);
    append_number(s, (__u32)optname);
    return kb_system_decide(rights, 1);
}

SEC("lsm/socket_getsockopt")
int BPF_PROG(kb_socket_getsockopt, struct socket* sock, int level, int optname, int ret)
{
    return ret != 0 ? ret : kb_decided(kb_sockopt_decide(level, optname, KFILTER_RIGHT_QUERY));
}

SEC("lsm/socket_setsockopt")
int BPF_PROG(kb_socket_setsockopt, struct socket* sock, int level, int optname, int ret)
{
    return ret != 0 ? ret : kb_decided(kb_sockopt_decide(level, optname, KFILTER_RIGHT_WRITE));
}

/* A socket's own and its peer's address (getsockname, getpeername): /system/sockname, /system/peername, query. */
SEC("lsm/socket_getsockname")
int BPF_PROG(kb_socket_getsockname, struct socket* sock, int ret)
{
    return ret != 0 ? ret : (int)system_named("/system/sockname", 16, KFILTER_RIGHT_QUERY);
}

SEC("lsm/socket_getpeername")
int BPF_PROG(kb_socket_getpeername, struct socket* sock, int ret)
{
    return ret != 0 ? ret : (int)system_named("/system/peername", 16, KFILTER_RIGHT_QUERY);
}

/* Mounts (mount, umount, pivot_root, move_mount): /system/mount, write. The kernel log (syslog, /dev/kmsg):
 * /system/syslog, query to read it or its size, write to clear it or set the console. Setting the clock
 * (clock_settime, settimeofday, adjtimex that changes it): /system/time, write. */
SEC("lsm/sb_mount")
int BPF_PROG(kb_sb_mount, const char* dev, const struct path* path, const char* type, unsigned long flags, void* data,
             int ret)
{
    return ret != 0 ? ret : (int)system_named("/system/mount", 13, KFILTER_RIGHT_WRITE);
}

SEC("lsm/sb_umount")
int BPF_PROG(kb_sb_umount, struct vfsmount* mnt, int flags, int ret)
{
    return ret != 0 ? ret : (int)system_named("/system/mount", 13, KFILTER_RIGHT_WRITE);
}

SEC("lsm/sb_pivotroot")
int BPF_PROG(kb_sb_pivotroot, const struct path* old_path, const struct path* new_path, int ret)
{
    return ret != 0 ? ret : (int)system_named("/system/mount", 13, KFILTER_RIGHT_WRITE);
}

SEC("lsm/move_mount")
int BPF_PROG(kb_move_mount, const struct path* from_path, const struct path* to_path, int ret)
{
    return ret != 0 ? ret : (int)system_named("/system/mount", 13, KFILTER_RIGHT_WRITE);
}

SEC("lsm/syslog")
int BPF_PROG(kb_syslog, int type, int ret)
{
    /* SYSLOG_ACTION_CLOSE, OPEN, READ, READ_ALL, SIZE_UNREAD, SIZE_BUFFER read; READ_CLEAR, CLEAR, CONSOLE_* change */
    __u32 rights = type <= 3 || type >= 9 ? KFILTER_RIGHT_QUERY : KFILTER_RIGHT_WRITE;
    return ret != 0 ? ret : (int)system_named("/system/syslog", 14, rights);
}

SEC("lsm/settime")
int BPF_PROG(kb_settime, const struct timespec64* ts, const struct timezone* tz, int ret)
{
    return ret != 0 ? ret : (int)system_named("/system/time", 12, KFILTER_RIGHT_WRITE);
}

/* arch_prctl: /system/arch_prctl/0x<option> (0x1011 ARCH_GET_CPUID, 0x1002 ARCH_SET_FS, which Wine
 * uses), query for the gets, write otherwise. ARCH_SET_CPUID names its argument: 0x1012/0 turns CPUID
 * faulting on (the launch's trap shim), 0x1012/1 off, so a rule can keep the trap armed. */
static __always_inline long arch_prctl_decide(__u32 option, unsigned long arg)
{
    int started = system_begin();
    if (started <= 0) return started;
    struct kb_scratch* s = scratch();
    if (!s) return 0;
    set_path(s, "/system/arch_prctl/0x", 21);
    append_hex(s, option, option > 0xFFFF ? 8 : 4);
    if (option == 0x1012) append_text(s, arg != 0 ? "/1" : "/0", 2);
    int get = option == 0x1003 || option == 0x1004 || option == 0x1011 || option == 0x4001 || option == 0x4002 ||
              option == 0x4004;
    return kb_decided(kb_system_decide(get ? KFILTER_RIGHT_QUERY : KFILTER_RIGHT_WRITE, 1));
}

SEC("fmod_ret/__x64_sys_arch_prctl")
long BPF_PROG(kb_arch_prctl, struct pt_regs* regs, long ret)
{
    return ret != 0 ? ret : arch_prctl_decide((__u32)BPF_CORE_READ(regs, di), BPF_CORE_READ(regs, si));
}

SEC("fmod_ret/__ia32_sys_arch_prctl")
long BPF_PROG(kb_arch_prctl32, struct pt_regs* regs, long ret)
{
    return ret != 0 ? ret : arch_prctl_decide((__u32)BPF_CORE_READ(regs, bx), (__u32)BPF_CORE_READ(regs, cx));
}

/* ---- every syscall: /system/syscall/<name>[/<key>] (kfilter_syscalls.h, filter/tools/gen_syscalls.py) ---- */

#include "kfilter_syscalls.h"     /* KB_SYSCALL_NAME, KB_SYSCALL_DECIDER0 and 1; its tables below */
#define KB_X64 0
#define KB_IA32 1
#define KB_SYSCALLS 512           /* numbers per table */
#define KB_KEY_DEC 1              /* the argument (masked) in signed decimal */
#define KB_KEY_HEX 2              /* ... as 0x<hex> (flags) */
#define KB_KEY_WAIT 3             /* wait4's pid: any, child or group */
#define KB_KEY_WAITID 4           /* waitid's idtype: any, child or group */
#define KB_KEY_LOCK64 5           /* ia32 fcntl's command in decimal, its LFS locks (F_GETLK64 12-F_SETLKW64 14) as x86_64's (5-7) */
#define KB_KEY_AT 0x80            /* beside the kind: the argument points to the key, a 32-bit word (ia32's old select) */
#define KB_NO_ARGUMENT 7

/* A call of one table: its name (an ia32 one's x86_64 name where it has one), which argument is its key and how it is
 * written, the range of its own memory it reaches (addr= rules), whether it only reads (query; else write), and
 * whether every process makes it all the time (hot: only rules naming its argument meet it). */
struct kb_syscall {
    char name[KB_SYSCALL_NAME];
    __u8 key, argument, address, length, query, hot;
    __u32 mask;
};

#define KB_SYSCALL(abi, nr, name, key, argument, mask, address, length, query, hot) \
    [abi][nr] = {name, key, argument, address, length, query, hot, mask},
static const struct kb_syscall kb_syscalls[2][KB_SYSCALLS] = {
#include "kfilter_syscalls.h"
};
#undef KB_SYSCALL

/* Argument Index (0-5) of the syscall Regs entered, by its ABI's registers; an ia32 one is 32 bits. */
static __always_inline __u64 syscall_argument(struct pt_regs* regs, __u32 compat, __u32 index)
{
    if (compat) {
        __u64 value = index == 0 ? BPF_CORE_READ(regs, bx) : index == 1 ? BPF_CORE_READ(regs, cx)
                    : index == 2 ? BPF_CORE_READ(regs, dx) : index == 3 ? BPF_CORE_READ(regs, si)
                    : index == 4 ? BPF_CORE_READ(regs, di) : BPF_CORE_READ(regs, bp);
        return value & 0xFFFFFFFFull;
    }
    return index == 0 ? BPF_CORE_READ(regs, di) : index == 1 ? BPF_CORE_READ(regs, si)
         : index == 2 ? BPF_CORE_READ(regs, dx) : index == 3 ? BPF_CORE_READ(regs, r10)
         : index == 4 ? BPF_CORE_READ(regs, r8) : BPF_CORE_READ(regs, r9);
}

/* What a rule names of key Value of a call of Kind (kb_syscall_keys): a wait's class (0 any, 1 child, 2 group), else the
 * value. wait4: -1 any child, > 0 that child, 0 or < -1 a group; waitid: P_ALL, P_PID or P_PIDFD, P_PGID. */
static __always_inline __u32 key_class(__u32 kind, __u32 value)
{
    if (kind == KB_KEY_WAIT) return (__s32)value == -1 ? 0 : (__s32)value > 0 ? 1 : 2;
    if (kind == KB_KEY_WAITID) return value == 0 ? 0 : value == 1 || value == 3 ? 1 : 2;
    return value;
}

/* s->path += "/" + the key of a call: Value in signed decimal, as 0x<hex>, or a wait's class. */
static __always_inline void append_key(struct kb_scratch* s, __u32 kind, __u32 value)
{
    append_text(s, "/", 1);
    if (kind == KB_KEY_HEX) {
        __u32 digits = 1;
        for (__u32 rest = value >> 4; rest != 0 && digits < 8; rest >>= 4) digits++;
        append_text(s, "0x", 2);
        append_hex(s, value, digits);
    } else if (kind == KB_KEY_WAIT || kind == KB_KEY_WAITID) {
        __u32 which = key_class(kind, value);
        if (which == 0) append_text(s, "any", 3);
        else if (which == 1) append_text(s, "child", 5);
        else append_text(s, "group", 5);
    } else if ((__s32)value < 0) {
        append_text(s, "-", 1);
        append_number(s, (__u32)(-(__s32)value));
    } else {
        append_number(s, value);
    }
}

/* ia32's multiplexed calls as the x86_64 call each names: socketcall's SYS_SOCKET (1) to SYS_SENDMMSG (20), ipc's SEMOP
 * (1) to SHMCTL (24); 0 for none. */
static const __u16 kb_multiplexed[2][32] = {
    {0, 41, 49, 42, 50, 43, 51, 52, 53, 44, 45, 44, 45, 48, 54, 55, 46, 47, 288, 299, 307},
    {0, 65, 64, 66, 220, 0, 0, 0, 0, 0, 0, 69, 70, 68, 71, 0, 0, 0, 0, 0, 0, 30, 67, 29, 31},
};

/* What the rules of each rule set name of a call (KfBpfApply, written with the rule set): its keys, or any. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4 * KB_SYSCALLS);
    __type(key, __u32);
    __type(value, struct kb_syscall_named);
} kb_syscall_keys SEC(".maps");

/*
 * The syscall whose entry Regs are (Compat: an ia32 one, int 0x80 from a 64-bit program too) as a system decision on
 * /system/syscall/<name>[/<key>], with the calling module for module= rules: the program's own call (not wineserver's
 * or winedevice's while serving it), rule-only, and met only by rules naming the space (KB_ROOT /system/syscall), a hot
 * call's only by rules naming its argument. ia32's socketcall and ipc are the x86_64 call they carry (connect, shmdt...).
 * A call on the caller's own memory reaches [address, address + length) for addr= rules. A call or key no rule of the
 * rule set in force names returns before any decision work (kb_syscall_keys). Called through a tail call from the
 * fmod_ret on the call's entry point, attached only while a rule names the call (KfBpfApply).
 */
__noinline int kb_syscall_decide(__u64 regsAddress, __u32 compat)
{
    struct pt_regs* regs = (struct pt_regs*)regsAddress;
    long nr = BPF_CORE_READ(regs, orig_ax);
    if (nr < 0 || nr >= KB_SYSCALLS) return 0;
    __u32 abi = compat ? KB_IA32 : KB_X64, number = (__u32)nr, ipc = 0;
    __u64 vector = 0;   /* socketcall: its call's arguments, 32-bit words */
    if (compat && (nr == 102 || nr == 117)) {
        __u32 sub = (__u32)syscall_argument(regs, 1, 0) & 0xFFFF;   /* ipc's version above */
        __u32 x64 = sub < 32 ? kb_multiplexed[nr == 117][sub & 31] : 0;
        if (x64 != 0) {
            abi = KB_X64;
            number = x64;
            ipc = nr == 117;   /* its arguments are not the call's own: no key or range */
            if (!ipc) vector = syscall_argument(regs, 1, 1);
        }
    }
    const struct kb_syscall* call = &kb_syscalls[abi & 1][number & (KB_SYSCALLS - 1)];
    if (call->name[0] == 0) return 0;
    __u32 kind = ipc ? 0 : call->key & ~KB_KEY_AT, key = 0;
    if (kind != 0) {
        __u64 argument = syscall_argument(regs, compat, call->argument);
        __u32 word = 0;
        if (vector) bpf_probe_read_user(&word, sizeof(word), (const void*)(vector + 4 * call->argument));
        else if ((call->key & KB_KEY_AT) != 0) bpf_probe_read_user(&word, sizeof(word), (const void*)argument);
        if (vector || (call->key & KB_KEY_AT) != 0) argument = word;
        key = (__u32)argument & call->mask;
        if (kind == KB_KEY_LOCK64 && key >= 12 && key <= 14) key -= 7;
    }
    __u32 index = live_set() << 10 | (abi & 1) << 9 | (number & (KB_SYSCALLS - 1));
    struct kb_syscall_named* named = bpf_map_lookup_elem(&kb_syscall_keys, &index);
    if (!named) return 0;
    if (!named->any) {
        __u32 wanted = key_class(kind, key), found = 0;
        for (__u32 i = 0; i < KB_SYSCALL_KEYS; i++) {
            if (i >= named->count) break;
            if (named->key[i] == wanted) found = 1;
        }
        if (!found) return 0;
    }
    int started = system_begin();
    if (started <= 0) return started;
    struct kb_scratch* s = scratch();
    if (!s || s->brokered) return 0;
    set_path(s, "/system/syscall/", 16);
    long copied = bpf_probe_read_kernel_str(&s->path[16], KB_SYSCALL_NAME, call->name);
    s->len = 16 + (copied > 1 ? (__u32)copied - 1 : 0);
    __u32 root = call->hot ? s->len + 2 : 15;   /* "/system/syscall", or past "/<name>/" */
    if (kind != 0) append_key(s, kind, key);
    __u32 listed = 1 | KB_ROOT(root);
    if (call->address < KB_NO_ARGUMENT && !vector && !ipc) {
        struct kb_access* a = bpf_task_storage_get(&kb_accesses, bpf_get_current_task_btf(), 0,
                                                   BPF_LOCAL_STORAGE_GET_F_CREATE);
        if (a) {
            a->target = s->tgid;
            a->count = 0;
            a->unknown = 0;
            access_add(a, syscall_argument(regs, compat, call->address), syscall_argument(regs, compat, call->length));
        }
        listed |= KB_ADDRESSED;   /* without room for the range: an unknown one (kb_address_match) */
    }
    return kb_system_decide(call->query ? KFILTER_RIGHT_QUERY : KFILTER_RIGHT_WRITE, listed);
}

/* The entry points' programs tail-call these, one per prototype group (a tail call needs the caller's). */
struct kb_tail_map {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
};

struct kb_tail_map kb_syscall_tail0 SEC(".maps");
struct kb_tail_map kb_syscall_tail1 SEC(".maps");

static __always_inline long syscall_decided(struct pt_regs* regs)
{
    __u32 compat = (BPF_CORE_READ((struct task_struct*)bpf_get_current_task_btf(), thread_info.status) & TS_COMPAT) != 0;
    return kb_decided(kb_syscall_decide(address_of(regs), compat));
}

/* Loaded for an entry point of their group, never attached: kfilterd puts them in kb_syscall_tail0 and _tail1. An x64
 * fmod_ret returns long (an int -EPERM would read as 0xFFFFFFFF); an ia32 entry's return is its eax. */
SEC("fmod_ret/" KB_SYSCALL_DECIDER0)
long BPF_PROG(kb_syscall, struct pt_regs* regs, long ret)
{
    return ret != 0 ? ret : syscall_decided(regs);
}

SEC("fmod_ret/" KB_SYSCALL_DECIDER1)
long BPF_PROG(kb_syscall1, struct pt_regs* regs, long ret)
{
    return ret != 0 ? ret : syscall_decided(regs);
}

/* An entry point (a zero-argument call's __do_sys_<name> serves both tables): a tail call into its group's decision. */
#define KB_STUB(program, function, group, names)                                                   \
    SEC("fmod_ret/" #function)                                                                     \
    long BPF_PROG(program, struct pt_regs* regs, long ret)                                         \
    {                                                                                              \
        if (ret == 0) bpf_tail_call(ctx, group ? (void*)&kb_syscall_tail1 : (void*)&kb_syscall_tail0, 0); \
        return ret;                                                                                \
    }
#include "kfilter_syscalls.h"
#undef KB_STUB

/* ---- Windows calls Wine answers in the program's own process (uprobes kfilterd attaches) ---- */

#define WBEM_E_ACCESS_DENIED 0x80041003u

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, KB_W32_NAMES);
    __type(key, __u32);
    __type(value, struct kb_w32name);
} kb_w32names SEC(".maps");

/* Returns a refused function from its entry: Value in the return register, at the caller's return
 * address, its stack as after the callee's ret (Pop: the bytes of a stdcall callee's arguments). */
static __always_inline int skip_call(struct pt_regs* ctx, __u64 ret, __u32 value, __u32 i386, __u32 pop)
{
    ctx->ax = value;
    ctx->ip = ret;
    ctx->sp += (i386 ? 4 : 8) + pop;
    return 0;
}

/* Wine's syscall dispatcher in each decoded install's ntdll.so (struct kb_dispatch, by KB_UP_LIBRARY), as kfilterd
 * found it in the file. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2 * KB_WINE_DIRS);
    __type(key, __u32);
    __type(value, struct kb_dispatch);
} kb_dispatch SEC(".maps");

#define KB_UP_ELSEWHERE (~0ull)   /* kb_up_decide's Where: the call does not return into ntdll.so */

struct ntdll_ctx {
    __u64 address;   /* the return address */
    __u64 offset;    /* out: its offset in ntdll.so's file, KB_UP_ELSEWHERE outside it */
};

static long ntdll_vma(struct task_struct* task, struct vm_area_struct* vma, struct ntdll_ctx* c)
{
    __u64 name = 0;
    struct dentry* d = vma->vm_file ? BPF_CORE_READ(vma, vm_file, f_path.dentry) : 0;
    if (d && BPF_CORE_READ(d, d_name.len) == 8) bpf_probe_read_kernel(&name, 8, BPF_CORE_READ(d, d_name.name));
    if (name == 0x6f732e6c6c64746eull) c->offset = c->address - vma->vm_start + ((__u64)vma->vm_pgoff << 12);   /* "ntdll.so" */
    return 0;
}

#define KB_UP_DESKTOP_KEY 0
#define KB_UP_SELF_KEY 1
#define KB_UP_OTHER_KEY 2
#define KB_UP_UNKNOWN_KEY 3

/* Whose window Hwnd is to the program (kb_windows): KB_UP_SELF_KEY, _OTHER_KEY (another program's, or every top-level
 * window: HWND_BROADCAST), _DESKTOP_KEY (the desktop's own, or none: the screen) or _UNKNOWN_KEY (one kfilter cannot
 * place). */
static __always_inline __u32 window_key(struct kb_scratch* s, __u32 hwnd)
{
    __u32 owner = hwnd == 0 || hwnd == 0xFFFF ? 0 : owner_of(0, hwnd);
    if (hwnd == 0 || owner == KB_WINDOW_SHARED) return KB_UP_DESKTOP_KEY;
    if (owner == s->tgid) return KB_UP_SELF_KEY;
    return owner != 0 || hwnd == 0xFFFF ? KB_UP_OTHER_KEY : KB_UP_UNKNOWN_KEY;
}

/*
 * kb_win32k's decision on a call Wine answers in the program's own process, after system_begin. Cookie: kfilterd's for
 * its function (KB_UP_*); Key: the argument its key or class is; Address and Handle: NtQueryVirtualMemory's address and
 * process (Address: NtGet/SetContextThread's CONTEXT); Where: the offset in ntdll.so the call returns to. Only a call
 * Windows code made, through Wine's syscall dispatcher, is decided: Wine's own calls of ntdll.so's functions also return
 * into ntdll.so. In an install whose dispatcher kfilterd did not find, a win32u.so call is still decided by its return
 * into ntdll.so (which calls no win32u.so function), an ntdll.so one is not. A win32u.so call is decided on
 * /system/win32k/<function> as before keys existed (unless no rule can meet that: KB_UP_SKIP_FUNCTION), then, not refused
 * and while a rule names its keys (KB_UP_KEYED), on /system/win32k/<function>/<key>, which only rules naming its keys meet
 * (@unknown only rules naming it; @self and @desktop skipped where none can: KB_UP_SKIP_SELF, _DESKTOP); an ntdll.so one
 * once, on
 * /system/ntdll/<function>[/<class>], which only rules naming /system/ntdll meet. Returns nonzero to refuse the call.
 */
__noinline int kb_up_decide(__u64 cookie, __u64 key, __u64 address, __u64 handle, __u64 where)
{
    struct kb_scratch* s = scratch();
    __u32 slot = KB_UP_LIBRARY(cookie), index = cookie & KB_UP_INDEX, kind = KB_UP_KIND(cookie);
    __u32 ntdll = (cookie & KB_UP_NTDLL) != 0, i386 = (cookie & KB_UP_I386) != 0;
    struct kb_dispatch* d = bpf_map_lookup_elem(&kb_dispatch, &slot);
    if (!s || where == KB_UP_ELSEWHERE) return 0;
    if (d && d->end > d->start ? where < d->start || where >= d->end : ntdll) return 0;
    struct kb_w32name* function = bpf_map_lookup_elem(&kb_w32names, &index);
    if (!function) return 0;
    if (!ntdll) {
        set_path(s, "/system/win32k/", 15);
        append_string(s, function->name, 0);
        if ((cookie & KB_UP_SKIP_FUNCTION) == 0 && kb_system_decide(KFILTER_RIGHT_QUERY, 1) != 0) return 1;
        if ((cookie & KB_UP_KEYED) == 0 || kind == 0 || kind > KB_UP_WINDOW) return 0;
        __u32 root = s->len + 1;   /* past "/<function>/" */
        __u32 listed = 1 | KB_ROOT(root);
        append_text(s, "/", 1);
        if (kind == KB_UP_VKEY) {
            append_code(s, (__u32)key);
        } else if (kind == KB_UP_HOOK && (__s32)key < 0) {
            append_text(s, "-", 1);
            append_number(s, -(__u32)key);
        } else if (kind == KB_UP_WINDOW) {
            /* The program's own windows and the desktop are most calls (each frame's): no rule naming them, no decision. */
            __u32 whose = window_key(s, (__u32)key);
            if (whose == KB_UP_SELF_KEY && (cookie & KB_UP_SKIP_SELF) != 0) return 0;
            if (whose == KB_UP_DESKTOP_KEY && (cookie & KB_UP_SKIP_DESKTOP) != 0) return 0;
            if (whose == KB_UP_DESKTOP_KEY) append_text(s, "@desktop", 8);
            else if (whose == KB_UP_SELF_KEY) append_text(s, "@self", 5);
            else if (whose == KB_UP_OTHER_KEY) append_text(s, "@other", 6);
            else append_text(s, "@unknown", 8);
            /* As K3's \@unknown-window: only rules naming it, no wildcard (and kfilterd loads no allow naming it). */
            if (whose == KB_UP_UNKNOWN_KEY) listed |= KB_NAMED_ONLY;
        } else {
            append_number(s, (__u32)key);
        }
        return kb_system_decide(KFILTER_RIGHT_QUERY, listed);
    }
    __u32 listed = 1 | KB_ROOT(13);   /* "/system/ntdll" */
    __u32 rights = KB_UP_RIGHT(cookie) == 1 ? KFILTER_RIGHT_WRITE : KB_UP_RIGHT(cookie) == 2 ? KFILTER_RIGHT_CREATE
                                                                                             : KFILTER_RIGHT_QUERY;
    set_path(s, "/system/ntdll/", 14);
    append_string(s, function->name, 0);
    if (kind == KB_UP_MEMORY) {
        /* Another process's memory is wineserver's APC_VIRTUAL_QUERY (queue_apc: a peer decision with addr=). */
        if ((__u32)handle != 0xFFFFFFFFu) return 0;   /* NtCurrentProcess() */
        struct kb_access* a = bpf_task_storage_get(&kb_accesses, bpf_get_current_task_btf(), 0,
                                                   BPF_LOCAL_STORAGE_GET_F_CREATE);
        if (a) {
            a->target = s->tgid;
            a->count = 0;
            a->unknown = 0;
            access_add(a, i386 ? (__u32)address : address, 1);
        }
        listed |= KB_ADDRESSED;
    }
    if (kind == KB_UP_CLASS || kind == KB_UP_CLASS2 || kind == KB_UP_MEMORY) {
        append_text(s, "/", 1);
        append_number(s, (__u32)key);
    }
    if (kind == KB_UP_CONTEXT) {
        __u32 flags = 0;   /* ContextFlags: at 0x30 in an x86_64 CONTEXT, first in an i386 one */
        if (bpf_probe_read_user(&flags, 4, (void*)(address + (i386 ? 0 : 0x30))) == 0) device_value(s, flags);
    }
    return kb_system_decide(rights, listed);
}

/*
 * A win32u.so or ntdll.so function Wine answers in the program's own process, from desktop shared memory, the X server
 * or its own state, with no request to decide (key state, the cursor, window lists and texts, screen reads, hooks,
 * input; process, thread, system and memory queries, the debugger's checks): kb_up_decide, with the calling module for
 * module= rules. A refused call returns at once with the cookie's failure value (0, or STATUS_ACCESS_DENIED for the
 * NTSTATUS ones). Wine's unix side takes SysV register arguments on x86_64, stack ones on i386; its dispatcher resets
 * its stack after the call, so an i386 (stdcall) function is skipped like a cdecl one. kfilterd attaches this to every
 * process's win32u.so and ntdll.so (x86_64-unix and i386-unix), for the functions system rules name; each call of a
 * probed function takes a trap in every process mapping the library, the decision only in a protected one's.
 * shortcut: a call made while another thread holds the program's mmap lock for writing is not decided
 * (bpf_find_vma only trylocks); keep each process's ntdll.so base in a map kfilterd fills from its maps, and compare
 * without the lock, if a program can make that happen at will.
 */
SEC("uprobe.multi")
int kb_win32k(struct pt_regs* ctx)
{
    if (system_begin() <= 0) return 0;
    __u64 cookie = bpf_get_attach_cookie(ctx);
    __u32 i386 = (cookie & KB_UP_I386) != 0, kind = KB_UP_KIND(cookie);
    __u64 ret = 0;
    if (bpf_probe_read_user(&ret, i386 ? 4 : 8, (void*)ctx->sp) != 0) return 0;
    struct ntdll_ctx from = {ret, KB_UP_ELSEWHERE};
    if (bpf_find_vma(bpf_get_current_task_btf(), ret, ntdll_vma, &from, 0) != 0) return 0;
    __u64 a[4] = {ctx->di, ctx->si, ctx->dx, ctx->cx};
    if (i386) {
        __u32 words[5] = {};   /* the return address, then four arguments */
        bpf_probe_read_user(words, sizeof(words), (void*)ctx->sp);
        for (int i = 0; i < 4; i++) a[i] = words[i + 1];
    }
    __u32 at = kind == KB_UP_HOOK ? 3 : kind == KB_UP_CLASS2 ? 1 : kind == KB_UP_MEMORY ? 2 : 0;
    if (kb_up_decide(cookie, a[at & 3], a[1], a[0], from.offset) == 0) return 0;
    return skip_call(ctx, ret, (__u32)(cookie >> 32), i386, 0);
}

struct wql_ctx {
    __u32 chars;
    __u32 phase;   /* 0: looking for FROM, 1: the blanks after it, 2: the class, 3: done; an object
                    * path's 5: its start, 4: its server and namespace */
    __u32 matched;   /* characters of "from" matched */
    __u32 edge;      /* the previous character ends an identifier (or there was none) */
};

static long wql_step(__u32 index, struct wql_ctx* c)
{
    struct kb_scratch* s = scratch();
    if (!s || index >= c->chars || c->phase == 3) return 1;
    __u32 at = (index * 2) & (KB_PATH - 1);
    __u8 ch = s->name[at];
    if (s->name[(at + 1) & (KB_PATH - 1)] != 0) ch = 0x80;   /* not ASCII */
    if (ch == 0) {   /* its end, where Wine's parser stops */
        c->phase = 3;
        return 1;
    }
    if (ch >= 0x80) return 1;   /* Wine's identifier character (or, after a blank, its space): a name failure */
    /* An object path (phase 5): \\server\ROOT\CIMV2:<class> (Wine checks the server and namespace) or the
     * class, up to '.' or '=', which Wine queries as "SELECT * FROM <class>": the class as after FROM. */
    if (c->phase == 5) c->phase = ch == '\\' ? 4 : 1;
    if (c->phase == 4) {
        if (ch == ':') c->phase = 1;
        return 0;
    }
    __u32 low = lower(ch);
    int letter = (low >= 'a' && low <= 'z') || (ch >= '0' && ch <= '9') || ch == '_';
    if (c->phase == 0) {
        /* FROM is a word of its own: Wine's lexer splits "SELECT*FROM" too, but its identifiers
         * also take '-' and 0x05 (wbemprox's id_char). */
        int word = letter || ch == '-' || ch == 5;
        if (c->matched == 4 && !word) c->phase = 1;
        else if (c->matched < 4 && low == (__u32)"from"[c->matched & 3] && (c->matched > 0 || c->edge)) c->matched++;
        else c->matched = low == 'f' && c->edge ? 1 : 0;
        c->edge = !word;
        return 0;
    }
    if (c->phase == 1 && !letter) return 0;   /* blanks (Wine's space runs over any iswspace), or what Wine's parse rejects */
    if (letter) {
        c->phase = 2;
        if (s->len + 1 >= KB_PATH) return 1;
        s->path[s->len & (KB_PATH - 1)] = (char)low;   /* WQL class names have no case (kfilterctl lowers rules) */
        s->len += 1;
        return 0;
    }
    c->phase = 3;
    return 1;
}

/* One character of a method's name (UTF-16 in s->name) onto s->path, lowercased (Wine finds methods without case); its
 * end at a NUL (c->phase 3). Any other character than an identifier's is in no method's name: a name failure. */
static long method_step(__u32 index, struct wql_ctx* c)
{
    struct kb_scratch* s = scratch();
    if (!s || index >= c->chars) return 1;
    __u32 at = (index * 2) & (KB_PATH - 1);
    __u8 ch = s->name[at];
    if (s->name[(at + 1) & (KB_PATH - 1)] != 0) return 1;
    if (ch == 0) {
        c->phase = 3;
        return 1;
    }
    __u32 low = lower(ch);
    if (!((low >= 'a' && low <= 'z') || (ch >= '0' && ch <= '9') || ch == '_') || s->len + 1 >= KB_PATH) return 1;
    s->path[s->len & (KB_PATH - 1)] = (char)low;
    s->len += 1;
    return 0;
}

/* The UTF-16 string at Address into s->name, up to Bytes (even) or the end of its page; the bytes read (0: none). */
static __always_inline __u32 read_text(__u64 address, __u32 bytes)
{
    struct kb_scratch* s = scratch();
    if (!s || bytes > KB_PATH) return 0;
    if (bpf_probe_read_user(s->name, bytes, (void*)address) == 0) return bytes;
    __u32 part = (4096 - (address & 4095)) & ~1u;   /* a short string just before an unmapped page */
    return part <= bytes && bpf_probe_read_user(s->name, part, (void*)address) == 0 ? part : 0;
}

#define KB_WMI_METHOD 64   /* characters of a method's name: a longer one is a name failure */

/* The decision on a WQL query (the string at Query up to its NUL, as Wine parses it, not a BSTR's
 * byte count the program sets), or on an object path (Path: GetObject, CreateInstanceEnum, ExecMethod):
 * /system/wmi/<class> (lowercase), "@other" for one with no FROM (ASSOCIATORS OF, REFERENCES OF) or
 * no class, query, with the module that called the method for module= rules. One whose class does
 * not end within its first 256 characters, or cannot be read, is a name failure. With Method (ExecMethod's name, a
 * NUL-terminated string): /system/wmi/<class>/<method> (lowercase), execute, which only rules naming a class's methods
 * meet (a rule on the class decided its queries alone before methods were decided), and only while one is loaded
 * (KB_WMI_METHOD_RULES). */
__noinline int kb_wmi_decide(__u64 query, __u32 path, __u64 method)
{
    struct kb_scratch* s = scratch();
    struct kb_cfg* cfg = kb_cfg_get();
    if (!s || !cfg || !cfg->wmi_rules) return 0;   /* a probe left over from a policy that named WMI */
    /* No rule names a class's methods: nothing can meet a method, its name failures included. */
    if (method != 0 && (cfg->wmi_rules & KB_WMI_METHOD_RULES) == 0) return 0;
    set_path(s, "/system/wmi/", 12);
    __u32 bytes = read_text(query, KB_PATH);
    struct wql_ctx c = {bytes / 2, path ? 5 : 0, 0, 1};
    bpf_loop(KB_PATH / 2, wql_step, &c, 0);
    if (c.phase != 3) s->failed = 1;
    if (s->len == 12) append_text(s, "@other", 6);
    __u32 listed = 2, rights = KFILTER_RIGHT_QUERY;
    if (method != 0) {
        if (s->len >= 0xFF) s->failed = 1;   /* past what KB_ROOT holds */
        listed |= KB_ROOT(s->len + 1);       /* past "/<class>/" */
        rights = KFILTER_RIGHT_EXECUTE;
        append_text(s, "/", 1);
        __u32 named = s->len;
        struct wql_ctx m = {read_text(method, 2 * KB_WMI_METHOD) / 2, 0, 0, 0};
        bpf_loop(KB_WMI_METHOD, method_step, &m, 0);
        if (m.phase != 3 || s->len == named) s->failed = 1;
    }
    s->path[s->len & (KB_PATH - 1)] = 0;
    pe_caller(s, 1);
    return kb_decide_global(KFILTER_TARGET_SYSTEM, rights, 0, listed);
}

/*
 * IWbemServices::ExecQuery, ExecQueryAsync, GetObject, CreateInstanceEnum and ExecMethod in wbemprox.dll (Wine's
 * in-process WMI; the cookie's KB_WMI_*): a refused call returns WBEM_E_ACCESS_DENIED at once (an
 * async query's sink is never called). kfilterd attaches this in each protected program that loads
 * wbemprox, at the methods' file offsets; the program is stopped meanwhile (wmi_provider). Windows x64
 * calling convention (the query or a method's name in r8, a path in rdx), or i386 stdcall (on the stack after this,
 * and the language for a query; the callee pops this and five arguments, four for CreateInstanceEnum, seven for
 * ExecMethod). GetObject with no path makes an empty class object: nothing to decide.
 */
SEC("uprobe.multi")
int kb_wmi(struct pt_regs* ctx)
{
    if (system_begin() <= 0) return 0;
    __u64 cookie = bpf_get_attach_cookie(ctx);
    __u32 i386 = (cookie & KB_UP_I386) != 0, method = cookie & KB_UP_INDEX;
    __u32 call = method == KB_WMI_EXEC_METHOD;
    __u32 path = method == KB_WMI_GET_OBJECT || method == KB_WMI_CREATE_INSTANCE_ENUM || call;
    __u64 ret = 0, query = ctx->r8, second = ctx->dx, name = 0;
    barrier_var(second);   /* two loads: a load from a chosen ctx offset is refused by the verifier */
    if (call) name = query;
    if (path) query = second;
    if (bpf_probe_read_user(&ret, i386 ? 4 : 8, (void*)ctx->sp) != 0) return 0;
    if (i386) {
        __u32 words[2] = {};   /* the second and third arguments */
        if (bpf_probe_read_user(words, sizeof(words), (void*)(ctx->sp + 8)) != 0) return 0;
        query = path ? words[0] : words[1];
        name = call ? words[1] : 0;
    }
    if (method == KB_WMI_GET_OBJECT && query == 0) return 0;
    if (kb_wmi_decide(query, path, call ? (name ? name : 1) : 0) == 0) return 0;
    return skip_call(ctx, ret, WBEM_E_ACCESS_DENIED, i386,
                     !i386 ? 0 : method == KB_WMI_CREATE_INSTANCE_ENUM ? 20 : call ? 32 : 24);
}

/* s->path += <family>/<type>/<protocol> of a socket, as /system/socket names them. */
static __always_inline void append_socket(struct kb_scratch* s, int family, int type, int protocol)
{
    if (family == AF_UNIX) append_text(s, "unix", 4);
    else if (family == AF_INET) append_text(s, "inet", 4);
    else if (family == AF_INET6) append_text(s, "inet6", 5);
    else if (family == AF_NETLINK) append_text(s, "netlink", 7);
    else if (family == AF_PACKET) append_text(s, "packet", 6);
    else append_number(s, (__u32)family);
    append_text(s, "/", 1);
    type &= 0xF;   /* without SOCK_NONBLOCK and SOCK_CLOEXEC */
    if (type == 1) append_text(s, "stream", 6);
    else if (type == 2) append_text(s, "dgram", 5);
    else if (type == 3) append_text(s, "raw", 3);
    else if (type == 5) append_text(s, "seqpacket", 9);
    else append_number(s, (__u32)type);
    append_text(s, "/", 1);
    append_number(s, (__u32)protocol);
}

/* A socket the program (or wineserver for it) creates: /system/socket/<family>/<type>/<protocol>,
 * create; unix, inet, inet6, netlink and packet, stream, dgram, raw and seqpacket by name, the
 * rest and protocols by number (netlink 15 is the udev monitor, inet raw 1 ICMP). */
SEC("lsm/socket_create")
int BPF_PROG(kb_socket_create, int family, int type, int protocol, int kern, int ret)
{
    if (ret != 0 || kern) return ret;
    int started = system_begin();
    if (started <= 0) return started;
    struct kb_scratch* s = scratch();
    if (!s) return 0;
    set_path(s, "/system/socket/", 15);
    append_socket(s, family, type, protocol);
    return kb_decided(kb_system_decide(KFILTER_RIGHT_CREATE, 1));
}

/* An anonymous inode's class as /system/<class>: [userfaultfd], [io_uring] (io_uring_setup),
 * [secretmem] (memfd_secret) and others, create; [memfd] is /system/memfd/<its name>, plus
 * execute with MFD_EXEC. Returns the rights. */
__noinline __u32 kb_anon_name(__u64 nameAddress)
{
    const struct qstr* name = (const struct qstr*)nameAddress;
    struct kb_scratch* s = scratch();
    if (!s || !name) return 0;
    const unsigned char* text = BPF_CORE_READ(name, name);
    __u32 len = BPF_CORE_READ(name, len);
    char first = 0;
    bpf_probe_read_kernel(&first, 1, text);
    set_path(s, "/system/", 8);
    if (first == '[' && len >= 2 && len < 32) {
        bpf_probe_read_kernel(&s->path[8], (len - 2) & 31, text + 1);
        s->len = 8 + ((len - 2) & 31);
        s->path[s->len & (KB_PATH - 1)] = 0;
    } else {
        append_string(s, text, 0);
    }
    __u32 rights = KFILTER_RIGHT_CREATE;
    if (s->len != 13 || !ends_with(s, "memfd", 5)) return rights;
    struct task_struct* task = bpf_get_current_task_btf();
    struct pt_regs* regs = (struct pt_regs*)bpf_task_pt_regs(task);
    if (!regs) return rights;
    int compat = (BPF_CORE_READ(task, thread_info.status) & TS_COMPAT) != 0;
    if (BPF_CORE_READ(regs, orig_ax) != (compat ? 356 : 319)) return rights;   /* memfd_create */
    __u64 user = compat ? BPF_CORE_READ(regs, bx) & 0xFFFFFFFFull : BPF_CORE_READ(regs, di);
    __u64 flags = compat ? BPF_CORE_READ(regs, cx) : BPF_CORE_READ(regs, si);
    append_text(s, "/", 1);
    append_string(s, (const void*)user, 1);
    return (flags & MFD_EXEC) != 0 ? rights | KFILTER_RIGHT_EXECUTE : rights;
}

/* Anonymous inodes the program creates (userfaultfd, io_uring, memfd, memfd_secret): a refusal
 * fails the syscall with EPERM; Wine falls back without userfaultfd. */
SEC("lsm/inode_init_security_anon")
int BPF_PROG(kb_anon_create, struct inode* inode, const struct qstr* name, const struct inode* context, int ret)
{
    if (ret != 0) return ret;
    int started = system_begin();
    if (started <= 0) return started;
    __u32 rights = kb_anon_name(address_of(name));
    return rights != 0 ? kb_decided(kb_system_decide(rights, 1)) : 0;
}

/* The kernel keyrings: keyctl, add_key and request_key reach every key and keyring through this
 * check. /system/keyring/<type>/<description> (e.g. keyring/_ses, user/<name>), write for write,
 * link, setattr and unlink, read otherwise.
 * shortcut: a keyring the program makes for itself (KEYCTL_JOIN_SESSION_KEYRING) is not decided;
 * add lsm/key_alloc if a rule must refuse that. */
SEC("lsm/key_permission")
int kb_key_permission(unsigned long long* ctx)
{
    /* Not BPF_PROG: key_ref_t points to an incomplete struct, which the verifier will not read
     * from the context; bpf_get_func_arg gives it as a number. */
    enum key_need_perm need = (enum key_need_perm)ctx[2];
    int ret = (int)ctx[3];
    if (ret != 0) return ret;
    int started = system_begin();
    if (started <= 0) return started;
    struct kb_scratch* s = scratch();
    __u64 reference = 0;
    if (!s || bpf_get_func_arg(ctx, 0, &reference) != 0) return 0;
    struct key* key = (struct key*)(reference & ~1ull);   /* the low bit marks possession */
    set_path(s, "/system/keyring/", 16);
    append_string(s, BPF_CORE_READ(key, type, name), 0);
    append_text(s, "/", 1);
    append_string(s, BPF_CORE_READ(key, description), 0);
    int write = need == KEY_NEED_WRITE || need == KEY_NEED_LINK || need == KEY_NEED_SETATTR || need == KEY_NEED_UNLINK;
    return kb_decided(kb_system_decide(write ? KFILTER_RIGHT_WRITE : KFILTER_RIGHT_READ, 1));
}

/* SysV IPC: each use of a shared memory segment, message queue or semaphore set, the program's
 * own or another's (a get by key, attach, send, receive, op, stat): /system/ipc/<shm|msg|sem>/<key
 * as 8 hex digits, 00000000 for IPC_PRIVATE>, read and/or write as asked, query for a get that
 * asks for neither. The kind comes from the syscall (x64; i386, its ipc() multiplexer too).
 * shortcut: creating an object is not decided, only its uses; add the *_alloc_security hooks if
 * a rule must refuse the create itself. */
SEC("lsm/ipc_permission")
int BPF_PROG(kb_ipc_permission, struct kern_ipc_perm* perm, short flag, int ret)
{
    if (ret != 0) return ret;
    int started = system_begin();
    if (started <= 0) return started;
    struct kb_scratch* s = scratch();
    struct task_struct* task = bpf_get_current_task_btf();
    struct pt_regs* regs = (struct pt_regs*)bpf_task_pt_regs(task);
    if (!s || !regs) return 0;
    long nr = BPF_CORE_READ(regs, orig_ax);
    int shm, msg;
    if ((BPF_CORE_READ(task, thread_info.status) & TS_COMPAT) != 0) {
        __u32 call = nr == 117 ? BPF_CORE_READ(regs, bx) & 0xFFFF : 0;   /* ipc(): SEMOP 1.., MSGSND 11.., SHMAT 21.. */
        shm = (nr >= 395 && nr <= 398) || call >= 21;
        msg = (nr >= 399 && nr <= 402) || (call >= 11 && call < 21);
    } else {
        shm = nr >= 29 && nr <= 31;
        msg = nr >= 68 && nr <= 71;
    }
    set_path(s, "/system/ipc/", 12);
    if (shm) append_text(s, "shm/", 4);
    else if (msg) append_text(s, "msg/", 4);
    else append_text(s, "sem/", 4);
    append_hex(s, (__u32)BPF_CORE_READ(perm, key), 8);
    __u32 rights = ((flag & 0444) != 0 ? KFILTER_RIGHT_READ : 0) | ((flag & 0222) != 0 ? KFILTER_RIGHT_WRITE : 0);
    return kb_decided(kb_system_decide(rights != 0 ? rights : KFILTER_RIGHT_QUERY, 1));
}

/* An io_uring passthrough command (NVMe and others) is the ioctl it stands for. */
SEC("lsm/uring_cmd")
int BPF_PROG(kb_uring_cmd, struct io_uring_cmd* command, int ret)
{
    if (ret != 0) return ret;
    return decide_ioctl(BPF_CORE_READ(command, file), BPF_CORE_READ(command, cmd_op), 0);
}

/* ---- DNS: the names a program looks up (dns rules) ---- */

struct dns_ctx {
    __u32 start, end, done;   /* done: 1 the name ended, 2 it is malformed */
};

/* One byte of a query's name (s->walk at start + index) into s->path, lowercase and dotted. */
static long dns_step(__u32 index, struct dns_ctx* d)
{
    struct kb_scratch* s = scratch();
    __u32 at = d->start + index;
    if (!s || at >= d->end || s->len >= 254) {
        d->done = 2;
        return 1;
    }
    __u8 c = s->walk[at & (KB_MSG_BYTES - 1)];
    if (s->dlabel != 0) {
        s->dlabel -= 1;
        s->path[s->len & 255] = (char)lower(c);
        s->len += 1;
        return 0;
    }
    if (c == 0 || c > 63) {   /* the root label ends it; above 63 a compression pointer, not a plain name */
        d->done = c == 0 ? 1 : 2;
        return 1;
    }
    s->dlabel = c;
    if (s->len != 0) {
        s->path[s->len & 255] = '.';
        s->len += 1;
    }
    return 0;
}

/*
 * A DNS query the program sends to port 53 (UDP; TCP with its length prefix in the same send): a dns
 * decision, query, on its question's name (lowercase, dotted, as a dns rule names it), value its
 * type, with the calling module for module= rules. Rule-only. A response, or a message without a
 * question, is none; a malformed name or more than one question is a name failure.
 * shortcut: only port 53, and a TCP query whose first segment is just its length (glibc's writev) is
 * not decided (glibc sends one only after the same name's UDP query was); read the second segment in
 * capture() if a resolver sends its first query that way.
 */
__noinline int kb_dns_decide(__u32 tcp)
{
    struct kb_cfg* c = kb_cfg_get();
    struct kb_scratch* s = scratch();
    if (!c || !s || (c->targets & KFILTER_TARGET_DNS) == 0) return 0;
    __u32 start = 0;
    if (tcp) {
        if (s->mlen < 2 || (((__u32)(__u8)s->walk[0] << 8) | (__u8)s->walk[1]) + 2 != s->msize) return 0;
        start = 2;
    }
    if (s->mlen < start + 12) return 0;
    __u32 flags = (__u8)s->walk[(start + 2) & 15];
    __u32 questions = ((__u32)(__u8)s->walk[(start + 4) & 15] << 8) | (__u8)s->walk[(start + 5) & 15];
    if ((flags & 0x80) != 0 || questions == 0) return 0;   /* QR: a response */
    s->len = 0;
    s->vlen = 0;
    s->dlabel = 0;
    s->failed = 0;
    struct dns_ctx d = {start + 12, s->mlen, 0};
    long used = bpf_loop(256, dns_step, &d, 0);
    __u32 at = start + 12 + (used > 0 ? (__u32)used : 0);
    __u32 type = 0;
    if (questions != 1 || d.done != 1 || at + 4 > s->mlen) s->failed = 1;
    else type = ((__u32)(__u8)s->walk[at & (KB_MSG_BYTES - 1)] << 8) | (__u8)s->walk[(at + 1) & (KB_MSG_BYTES - 1)];
    s->path[s->len & 255] = 0;
    /* value= matches the type in decimal ("28": AAAA). */
    char digits[8];
    __u32 n = 0;
    for (__u32 left = type; n < 5; left /= 10) {
        digits[n++] = '0' + left % 10;
        if (left < 10) break;
    }
    for (__u32 i = 0; i < 5; i++) {
        if (i >= n) break;
        s->value[i] = digits[(n - 1 - i) & 7];
    }
    s->value[n & 7] = 0;
    s->vlen = n;
    return kb_decide_global(KFILTER_TARGET_DNS, KFILTER_RIGHT_QUERY, type, 2);
}

/*
 * One message of the program on an INET socket (Right: send or receive), or a send to an AF_UNIX peer (Family
 * KFILTER_NET_FAMILY_UNIX, its name in s->path): the connection block and the message rules, with the message's number
 * on its connection. Sends carry their first bytes for match= and the event; receives are decided before data arrives.
 * A query to a DNS server is first a dns decision on its name.
 */
static __always_inline int decide_message(struct socket* sock, struct msghdr* msg, __u32 family, __u32 port, __u32 right)
{
    struct kb_scratch* s = scratch();
    struct sock* sk = sock->sk;   /* a BTF pointer, as socket storage needs */
    if (!s || !sk) return 0;
    __u32 unix = family == KFILTER_NET_FAMILY_UNIX;
    struct kb_sock* owner = bpf_sk_storage_get(&kb_socks, sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
    /* A unix socket's owner is the program that made it (unix_owner: a squatted name), never one that sent on it. */
    if (owner && owner->tgid == 0 && !unix) owner->tgid = s->tgid;
    __u32 number = 0;
    if (owner) number = right == KFILTER_RIGHT_SEND ? ++owner->sent : ++owner->received;
    s->mindex = number;
    s->minode = socket_inode(sock);
    s->msize = 0;
    s->mlen = 0;
    pe_caller(s, 0);
    if (right == KFILTER_RIGHT_SEND && msg) capture(s, msg);
    __u32 protocol = protocol_of(sock);
    if (right == KFILTER_RIGHT_SEND && port == 53 && (protocol == 17 || protocol == 6) &&
        kb_dns_decide(protocol == 6) != 0) return -EPERM;
    __u32* blocked = s->minode && !unix ? bpf_map_lookup_elem(&kb_blocked, &s->minode) : 0;   /* INET connections only */
    int block = blocked && (*blocked & right) != 0;
    __u32 kind = (family << 8) | (protocol & 0xFF);
    return kb_msg_decide_global(kind, port, right, block) != 0 ? -EPERM : 0;
}

/*
 * s->path := the peer a send on connected AF_UNIX socket Sk goes to, by the name it was bound to (unix_name); -1 for
 * another family, no peer, or one bound to nothing or not nameable (a socketpair's, the server's end of an accepted
 * connection to an unbound client), which no unix= rule can name.
 */
__noinline int kb_unix_peer(__u64 skAddress)
{
    struct kb_scratch* s = scratch();
    struct unix_sock* u = (struct unix_sock*)skAddress;
    if (!s || !u || BPF_CORE_READ(u, sk.__sk_common.skc_family) != AF_UNIX) return -1;
    struct unix_sock* peer = (struct unix_sock*)BPF_CORE_READ(u, peer);
    s->failed = 0;
    return peer && unix_name(s, peer) == 0 && !s->failed ? 0 : -1;
}

/*
 * A send to an AF_UNIX peer before its message decision (kb_socket_sendmsg's, which kb_bench_net shares): Sendto, one with
 * an address unix_path named in s->path, is first its pipe connect decision; then, only while a unix= rule is loaded
 * (KB_GATE_UNIX_MESSAGE), its peer is that address, or connected socket Sk's (kb_unix_peer). Returns 1 to decide the
 * message, 0 to let the send through, or the connect decision's refusal.
 */
__noinline int kb_unix_send(__u32 sendto, __u64 sk)
{
    if (sendto) {
        struct kb_scratch* s = scratch();
        int result = kb_decide(KFILTER_TARGET_PIPE, KFILTER_RIGHT_CONNECT, 0);
        if (result != 0 || !s || s->failed) return result;
    }
    if (!gated(KB_GATE_UNIX_MESSAGE)) return 0;
    return sendto || kb_unix_peer(sk) == 0;
}

/* An unconnected datagram send names its destination (decided per peer); then, on any
 * INET socket, the message itself. A send to an AF_UNIX peer is a message decision only while a message rule names
 * unix= (ABI 12, KB_GATE_UNIX_MESSAGE): an X11, D-Bus or Pulse client library treats a refused write as fatal, so such
 * a rule is the kill switch of a connection. */
SEC("lsm/socket_sendmsg")
int BPF_PROG(kb_socket_sendmsg, struct socket* sock, struct msghdr* msg, int size, int ret)
{
    if (ret != 0) return ret;
    const struct sockaddr* name = BPF_CORE_READ(msg, msg_name);
    int length = BPF_CORE_READ(msg, msg_namelen);
    BEGIN();
    struct kb_scratch* s = scratch();
    if (!s) return 0;
    __u32 family = 0, port = 0;
    if (name && length != 0 && unix_path(s, name, length) == 0) {
        int result = kb_unix_send(1, 0);
        if (result <= 0) return kb_decided(result);   /* bounded for the verifier: a global function's result is not */
        family = KFILTER_NET_FAMILY_UNIX;   /* s->path: the peer */
    } else if (name && length != 0) {
        if (read_sockaddr(s, name, &family, &port) != 0) return 0;
        __u32 protocol = protocol_of(sock);
        int result = 0;
        /* A TCP send with a name connects only with MSG_FASTOPEN (TCP Fast Open), past lsm/socket_connect: a connect. */
        int fastopen = protocol == 6 && (BPF_CORE_READ(msg, msg_flags) & MSG_FASTOPEN) != 0;
        if (protocol == 17) result = udp_decide(sock, family, port);
        else if (protocol != 6 || fastopen) result = kb_net_decide(0, s->tgid, family, protocol, port, KFILTER_RIGHT_CONNECT);
        if (result != 0) return result;
        if (read_sockaddr(s, name, &family, &port) != 0) return 0;   /* the peer again, for the message */
    } else if (peer_address(s, BPF_CORE_READ(sock, sk), &family, &port) != 0) {
        if (kb_unix_send(0, address_of(BPF_CORE_READ(sock, sk))) <= 0) return 0;
        family = KFILTER_NET_FAMILY_UNIX;
    }
    return decide_message(sock, msg, family, port, KFILTER_RIGHT_SEND);
}

/* Each receive of the program on an INET socket, before its data is copied. */
SEC("lsm/socket_recvmsg")
int BPF_PROG(kb_socket_recvmsg, struct socket* sock, struct msghdr* msg, int size, int flags, int ret)
{
    if (ret != 0) return ret;
    BEGIN();
    struct kb_scratch* s = scratch();
    if (!s) return 0;
    __u32 family = 0, port = 0;
    if (peer_address(s, BPF_CORE_READ(sock, sk), &family, &port) != 0) {
        /* An unconnected socket: no peer yet, the rules see any address. */
        __u16 sa = BPF_CORE_READ(sock, sk, __sk_common.skc_family);
        if (sa != AF_INET && sa != AF_INET6) return 0;
        __builtin_memset(s->address, 0, 16);
        family = sa == AF_INET ? 4 : 6;
        port = 0;
    }
    return decide_message(sock, msg, family, port, KFILTER_RIGHT_RECEIVE);
}

/* An AF_UNIX bind to an abstract name (squatting @/tmp/.X11-unix/X6): the program's pipe listen on /@name (ABI 11,
 * met only by pipe rules naming listen). A pathname bind is path_mknod's file write on its path; an autobind's name is
 * decided at its listen. */
__noinline int kb_unix_bind(__u64 addressAddress, int length)
{
    struct kb_scratch* s = scratch();
    const struct sockaddr* address = (const struct sockaddr*)addressAddress;
    char first = 1;
    bpf_probe_read_kernel(&first, 1, (const char*)address + 2);
    if (!s || length <= 2 || first != 0 || unix_path(s, address, length) != 0) return 0;
    return kb_decide_global(KFILTER_TARGET_PIPE, KFILTER_RIGHT_LISTEN, 0, 1);
}

SEC("lsm/socket_bind")
int BPF_PROG(kb_socket_bind, struct socket* sock, struct sockaddr* address, int addrlen, int ret)
{
    if (ret != 0) return ret;
    BEGIN();
    struct kb_scratch* s = scratch();
    if (!s) return 0;
    __u16 sa = 0;
    bpf_probe_read_kernel(&sa, sizeof(sa), &address->sa_family);
    if (sa == AF_UNIX) return gated(KB_GATE_LISTEN) ? kb_decided(kb_unix_bind(address_of(address), addrlen)) : 0;
    __u32 family = 0, port = 0;
    if (read_sockaddr(s, address, &family, &port) != 0 || port == 0) return 0;
    return kb_net_decide(0, s->tgid, family, protocol_of(sock), port, KFILTER_RIGHT_LISTEN);
}

/* The socket's own address and port (listen, accept). */
static __always_inline int local_address(struct kb_scratch* s, struct sock* sk, __u32* family, __u32* port)
{
    if (!s || !sk) return -1;
    __builtin_memset(s->address, 0, 16);
    __u16 sa = BPF_CORE_READ(sk, __sk_common.skc_family);
    *port = BPF_CORE_READ(sk, __sk_common.skc_num);
    if (sa == AF_INET) {
        __u32 address = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        __builtin_memcpy(s->address, &address, 4);
        *family = 4;
        return 0;
    }
    if (sa == AF_INET6) {
        BPF_CORE_READ_INTO(&s->address, sk, __sk_common.skc_v6_rcv_saddr);
        *family = 6;
        unmap_ipv4(s, family);
        return 0;
    }
    return -1;
}

SEC("lsm/socket_listen")
int BPF_PROG(kb_socket_listen, struct socket* sock, int backlog, int ret)
{
    if (ret != 0) return ret;
    BEGIN();
    struct kb_scratch* s = scratch();
    if (!s) return 0;
    __u32 family = 0, port = 0;
    struct sock* sk = BPF_CORE_READ(sock, sk);
    if (sk && BPF_CORE_READ(sk, __sk_common.skc_family) == AF_UNIX)   /* an AF_UNIX server (ABI 11) */
        return gated(KB_GATE_LISTEN) ? kb_decided(kb_unix_listen(address_of(sk), s->tgid)) : 0;
    if (local_address(s, sk, &family, &port) != 0) return 0;
    return kb_net_decide(0, s->tgid, family, protocol_of(sock), port, KFILTER_RIGHT_LISTEN);
}

SEC("lsm/socket_accept")
int BPF_PROG(kb_socket_accept, struct socket* sock, struct socket* newsock, int ret)
{
    if (ret != 0) return ret;
    BEGIN();
    struct kb_scratch* s = scratch();
    if (!s) return 0;
    __u32 family = 0, port = 0;
    struct sock* sk = BPF_CORE_READ(sock, sk);
    if (sk && BPF_CORE_READ(sk, __sk_common.skc_family) == AF_UNIX)   /* an AF_UNIX server (ABI 11) */
        return gated(KB_GATE_LISTEN) ? kb_decided(kb_unix_listen(address_of(sk), s->tgid)) : 0;
    if (local_address(s, sk, &family, &port) != 0) return 0;
    return kb_net_decide(0, s->tgid, family, protocol_of(sock), port, KFILTER_RIGHT_LISTEN);
}

/* An incoming TCP connection on a protected listener, decided on its source (softirq). */
static __always_inline int conn_request(__u32 irq, const struct sock* sk, struct request_sock* req)
{
    struct kb_sock* owner = bpf_sk_storage_get(&kb_socks, (void*)sk, 0, 0);
    struct kb_scratch* s = scratch_irq(irq);
    if (!owner || !s) return 0;
    __builtin_memset(s->address, 0, 16);
    __u16 family = BPF_CORE_READ(req, __req_common.skc_family);
    __u32 port = bpf_ntohs(BPF_CORE_READ(req, __req_common.skc_dport));
    if (family == AF_INET) {
        __u32 address = BPF_CORE_READ(req, __req_common.skc_daddr);
        __builtin_memcpy(s->address, &address, 4);
        return kb_net_decide(irq, owner->tgid, 4, 6, port, KFILTER_RIGHT_LISTEN);
    }
    if (family == AF_INET6) {
        BPF_CORE_READ_INTO(&s->address, req, __req_common.skc_v6_daddr);
        __u32 decided = 6;
        unmap_ipv4(s, &decided);
        return kb_net_decide(irq, owner->tgid, decided, 6, port, KFILTER_RIGHT_LISTEN);
    }
    return 0;
}

SEC("lsm/inet_conn_request")
int BPF_PROG(kb_inet_conn_request, const struct sock* sk, struct sk_buff* skb, struct request_sock* req, int ret)
{
    if (ret != 0) return ret;
    __u32 irq = irq_enter();
    if (irq == 0) return 0;
    int result = conn_request(irq, sk, req);
    irq_leave();
    return result;
}

/* An incoming datagram for a protected UDP socket, decided on its source (softirq). */
static __always_inline int receive_datagram(__u32 irq, struct sock* sk, struct sk_buff* skb)
{
    struct kb_sock* owner = bpf_sk_storage_get(&kb_socks, sk, 0, 0);
    struct kb_scratch* s = scratch_irq(irq);
    if (!owner || !s) return 0;
    unsigned char* head = BPF_CORE_READ(skb, head);
    __u16 network = BPF_CORE_READ(skb, network_header);
    __u16 transport = BPF_CORE_READ(skb, transport_header);
    __u16 protocol = bpf_ntohs(BPF_CORE_READ(skb, protocol));
    __u16 sourcePort = 0;
    bpf_probe_read_kernel(&sourcePort, sizeof(sourcePort), head + transport);
    __u32 port = bpf_ntohs(sourcePort);
    __builtin_memset(s->address, 0, 16);
    if (protocol == 0x0800) {
        bpf_probe_read_kernel(s->address, 4, head + network + 12);   /* iphdr.saddr */
        if (peer_known(s, owner, 4, port)) return 0;
        return kb_net_decide(irq, owner->tgid, 4, 17, port, KFILTER_RIGHT_LISTEN);
    }
    if (protocol == 0x86DD) {
        bpf_probe_read_kernel(s->address, 16, head + network + 8);   /* ipv6hdr.saddr */
        __u32 family = 6;
        unmap_ipv4(s, &family);
        if (peer_known(s, owner, family, port)) return 0;
        return kb_net_decide(irq, owner->tgid, family, 17, port, KFILTER_RIGHT_LISTEN);
    }
    return 0;
}

SEC("lsm/socket_sock_rcv_skb")
int BPF_PROG(kb_sock_rcv_skb, struct sock* sk, struct sk_buff* skb, int ret)
{
    if (ret != 0 || BPF_CORE_READ(sk, sk_protocol) != 17) return ret;
    __u32 irq = irq_enter();
    if (irq == 0) return 0;
    int result = receive_datagram(irq, sk, skb);
    irq_leave();
    return result;
}

/* Interface, address, route and neighbour (ARP) queries and socket tables over netlink:
 * the Linux \Device\Nsi (block-network-adapter). Device decisions on /net/netlink/route
 * (value: the message type) and /net/netlink/sock_diag. */
/* Generic netlink family names by id (NETLINK_GENERIC's nlmsg_type), which kfilterd reads from the controller while a
 * device rule names /net/netlink/... (KB_GATE_NETLINK). */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, struct kb_genl_name);
} kb_genl SEC(".maps");

/*
 * Every other netlink message (ABI 11): /net/netlink/<family>/<type> (route, audit, kobject_uevent... or the protocol's
 * number; type in decimal), value the type, a device decision, rule-only, met only by rules naming the family past its
 * slash (the literal /net/netlink/route, written for the four queries below, does not meet /net/netlink/route/24).
 * NETLINK_GENERIC by family name: a lookup (CTRL_CMD_GETFAMILY) is /net/netlink/generic/<name> (nl80211: refusing it
 * hides the family), a message to a family /net/netlink/generic/<name>/<command> (its id where kfilterd has no name),
 * the controller's other commands /net/netlink/generic/nlctrl/<command>.
 */
__noinline int kb_netlink_decide(__u32 protocol, __u32 type, __u64 data)
{
    static const char families[23][16] = {"route", "unused", "usersock", "firewall", "sock_diag", "nflog", "xfrm",
                                          "selinux", "iscsi", "audit", "fib_lookup", "connector", "netfilter", "ip6_fw",
                                          "dnrtmsg", "kobject_uevent", "generic", "17", "scsitransport", "ecryptfs",
                                          "rdma", "crypto", "smc"};
    struct kb_scratch* s = scratch();
    if (!s) return 0;
    set_path(s, "/net/netlink/", 13);
    if (protocol < 23) append_string(s, families[protocol], 0);
    else append_number(s, protocol);
    append_text(s, "/", 1);
    __u32 root = s->len;
    if (protocol != 16) {
        append_number(s, type);
    } else {
        __u8 command = 0;
        bpf_probe_read_kernel(&command, 1, (const void*)(data + 16));   /* genlmsghdr.cmd */
        struct kb_genl_name* family = bpf_map_lookup_elem(&kb_genl, &type);
        if (type == 0x10 && command == 3) {   /* GENL_ID_CTRL, CTRL_CMD_GETFAMILY: the name it looks up */
            __u32 at = 20;                     /* past nlmsghdr and genlmsghdr */
            for (int i = 0; i < 4; i++) {
                __u16 attribute[2] = {};
                if (bpf_probe_read_kernel(attribute, sizeof(attribute), (const void*)(data + at)) != 0 || attribute[0] < 4) break;
                if ((attribute[1] & 0x3FFF) == 2) {   /* CTRL_ATTR_FAMILY_NAME */
                    append_string(s, (const void*)(data + at + 4), 0);
                    break;
                }
                at += (attribute[0] + 3) & ~3u;
            }
        } else if (type == 0x10) {
            append_text(s, "nlctrl/", 7);
            append_number(s, command);
        } else {
            if (family) append_string(s, family->name, 0);
            else append_number(s, type);
            append_text(s, "/", 1);
            append_number(s, command);
        }
    }
    device_value(s, type);
    return kb_decide_global(KFILTER_TARGET_DEVICE, KFILTER_RIGHT_RAW_DEVICE, type, 1 | KB_ROOT(root));
}

SEC("lsm/netlink_send")
int BPF_PROG(kb_netlink_send, struct sock* sk, struct sk_buff* skb, int ret)
{
    if (ret != 0) return ret;
    BEGIN();
    struct kb_cfg* c = kb_cfg_get();
    struct kb_scratch* s = scratch();
    if (!c || !s) return 0;
    __u32 protocol = BPF_CORE_READ(sk, sk_protocol);
    struct nlmsghdr header = {};
    unsigned char* data = BPF_CORE_READ(skb, data);
    bpf_probe_read_kernel(&header, sizeof(header), data);
    __u32 type = header.nlmsg_type;
    if ((c->flags & KFILTER_CFG_BLOCK_NETWORK_ADAPTER) != 0) {
        int query = protocol == NETLINK_ROUTE &&
                    (type == RTM_GETLINK || type == RTM_GETADDR || type == RTM_GETROUTE || type == RTM_GETNEIGH);
        if (query || protocol == NETLINK_SOCK_DIAG) {
            if (query) set_path(s, "/net/netlink/route", 18);
            else set_path(s, "/net/netlink/sock_diag", 22);
            device_value(s, type);
            return kb_decide(KFILTER_TARGET_DEVICE, KFILTER_RIGHT_RAW_DEVICE, type);
        }
    }
    return gated(KB_GATE_NETLINK) ? kb_decided(kb_netlink_decide(protocol, type, (__u64)data)) : 0;
}

/* ---- ABI 11: hooks and decisions kfilter did not make before, made only where a rule names them ---- */

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} kb_gates SEC(".maps");

/* Some rule of the policy in force can name the decisions behind Bit (KB_GATE_*). */
static __always_inline int gated(__u32 bit)
{
    __u32 zero = 0;
    __u32* gates = bpf_map_lookup_elem(&kb_gates, &zero);
    return gates && (*gates & bit) != 0;
}

extern const int __preempt_count __ksym __weak;
extern const void mmap_min_addr __ksym __weak;

/* The hook runs in an interrupt (a socket's softirq), where no task's working memory may be used: a decision of the
 * interrupted task may be under way in it. Without __preempt_count to tell, it counts as one. */
static __always_inline int in_interrupt(void)
{
    if (!bpf_ksym_exists(&__preempt_count)) return 1;
    int count = *(int*)bpf_this_cpu_ptr(&__preempt_count);
    return (count & (0x00F00000 | 0x000F0000 | 0x00000100)) != 0;   /* NMI, hardirq, serving a softirq */
}

/* A system decision of ABI 11 on Name (n < 32 bytes), in a space Root bytes long, where Gate's rules name it. */
static __always_inline long system_space(__u32 gate, const char* name, __u32 n, __u32 root, __u32 rights)
{
    if (!gated(gate)) return 0;
    int started = system_begin();
    if (started <= 0) return started;
    struct kb_scratch* s = scratch();
    if (!s) return 0;
    set_path(s, name, n);
    return kb_decided(kb_system_decide(rights, KB_ROOT(root)));
}

/* A process other than the one the decision is for (a task of another thread group). */
static __always_inline int other_process(struct task_struct* p)
{
    struct kb_scratch* s = scratch();
    return p && s && BPF_CORE_READ(p, tgid) != s->tgid;
}

/* s->value = signal:0x%08X of Value (Query: ptrace:, a mode), which only peer rules naming one meet (KB_TARGET_SIGNAL),
 * and the event's text after the path, past s->len: " signal=0x00000013" (" ptrace=0x00000009"). */
static __always_inline void reach_value(struct kb_scratch* s, __u32 query, __u32 value)
{
    static const char hex[] = "0123456789ABCDEF";
    const char signal[] = "signal", ptrace[] = "ptrace";
    for (int i = 0; i < 6; i++) s->value[i] = query ? ptrace[i] : signal[i];
    s->value[6] = ':';
    s->value[7] = '0';
    s->value[8] = 'x';
    for (int i = 0; i < 8; i++) s->value[9 + i] = hex[(value >> (28 - 4 * i)) & 0xF];
    s->value[17] = 0;
    s->vlen = 17;
    __u32 at = s->len;
    if (s->failed || at > KB_PATH - 24) return;
    s->path[at & (KB_PATH - 1)] = ' ';
    for (int i = 0; i < 6; i++) s->path[(at + 1 + i) & (KB_PATH - 1)] = s->value[i];
    s->path[(at + 7) & (KB_PATH - 1)] = '=';
    for (int i = 0; i < 10; i++) s->path[(at + 8 + i) & (KB_PATH - 1)] = s->value[7 + i];
    s->path[(at + 18) & (KB_PATH - 1)] = 0;
}

/*
 * The program Actor reaching task Target in ways kfilter did not decide before: a signal (Access PROCESS_TERMINATE, or
 * QUERY_LIMITED_INFORMATION for a kill(pid, 0) probe) or a PTRACE_MODE_READ check (QUERY: QUERY_INFORMATION), Value the
 * signal or the ptrace mode. Inside the family a peer decision of Actor on Target's program, value signal:0x%08X
 * (ptrace:0x%08X), met only by peer rules naming one (KB_TARGET_SIGNAL, KB_GATE_PEER); across the family's boundary,
 * with block-process-signals (QUERY: block-process-queries), a HANDLE grant (into the family) or OPEN grant (out of it)
 * of Access. A signal the family sends outside is block-process-memory's (kb_task_kill), unless a file raises it
 * (SIGIO). Returns 0 or -EPERM.
 */
__noinline int kb_reach_decide(__u32 actor, __u64 targetAddress, __u32 access, __u32 value, __u32 flags)
{
    struct kb_cfg* c = kb_cfg_get();
    struct task_struct* target = (struct task_struct*)targetAddress;
    if (!c || !target || !c->enabled || c->mode == KFILTER_MODE_OFF || actor == c->daemon_tgid) return 0;
    __u32 object = BPF_CORE_READ(target, tgid), query = flags & KB_REACH_QUERY;
    if (object == actor) return 0;
    int inside = proc_guarded(actor), into = (flags & KB_REACH_INTO) != 0;
    if (!inside) {
        struct task_struct* task = bpf_task_from_pid((s32)actor);
        if (task) {
            inside = task_protected(task, task_state(task));
            bpf_task_release(task);
        }
    }
    if (inside && into) {
        if (!gated(KB_GATE_PEER)) return 0;
        struct kb_scratch* s = reset_for(actor, 0);
        if (!s) return 0;
        program_path(s, target, object);
        reach_value(s, query, value);
        return kb_decide_global(KB_TARGET_SIGNAL, access, 0, 1);
    }
    __u32 gate = query ? KFILTER_CFG_BLOCK_PROCESS_QUERIES : KFILTER_CFG_BLOCK_PROCESS_SIGNALS;
    if ((c->flags & gate) == 0 || (!inside && !into) ||
        (inside && !query && access == KB_PROCESS_TERMINATE && (flags & KB_REACH_SIGIO) == 0))
        return 0;
    struct kb_scratch* s = reset_for(actor, 0);
    if (!s) return 0;
    __u32 kind = inside ? KFILTER_TARGET_OPEN : KFILTER_TARGET_HANDLE;
    if (inside) {
        program_path(s, target, object);
    } else {
        struct task_struct* task = bpf_task_from_pid((s32)actor);
        program_path(s, task, actor);
        if (task) bpf_task_release(task);
    }
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    __u32 granted = kb_outside_rights(kind, access, uid == 0);
    __u32 action = (granted & access) == access ? KFilterActionAllow : KFilterActionDeny;
    return verdict(kind, action, 0, value, s->outside_rule, access, c->mode);
}

/* ---- files: locks, fcntl, SIGIO ---- */

/* A lock on a file or directory (fcntl F_SETLK, F_SETLKW, F_OFD_SETLK*, flock; wineserver's lock_file for its client is
 * the client's): right lock on its path, value F_RDLCK or F_WRLCK; unlocks are not decided. */
SEC("lsm/file_lock")
int BPF_PROG(kb_file_lock, struct file* file, unsigned int cmd, int ret)
{
    if (ret != 0 || cmd > 1 || !gated(KB_GATE_LOCK)) return ret;   /* F_RDLCK 0, F_WRLCK 1 */
    BEGIN();
    struct kb_scratch* s = scratch();
    struct inode* inode = BPF_CORE_READ(file, f_inode);
    if (!s || !inode || pseudo_fs(inode)) return 0;
    walk_file(file);
    kb_proc_name();
    if (cmd == 0) __builtin_memcpy(s->value, "F_RDLCK", 8);
    else __builtin_memcpy(s->value, "F_WRLCK", 8);
    s->vlen = 7;
    __u32 target = (inode_mode(inode) & S_IFMT) == S_IFDIR ? KFILTER_TARGET_DIR : KFILTER_TARGET_FILE;
    return kb_decided(kb_decide_global(target, KFILTER_RIGHT_LOCK, 0, 1));
}

/* A file's SIGIO owner set to Who (a pid, or minus a process group) by the current task (F_SETOWN, F_SETOWN_EX, FIOSETOWN,
 * SIOCSPGRP): decided as the SIGIO the setter sends that owner (signal_reach), as one a socket raises in softirq
 * cannot be decided when it is sent. shortcut: a group is decided by its leader, and one whose leader exited not at all;
 * walk the group's tasks if that matters. */
static __always_inline int owner_decide(__s32 who)
{
    struct kb_cfg* c = kb_cfg_get();
    if (who == 0 || !c || ((c->flags & KFILTER_CFG_BLOCK_PROCESS_SIGNALS) == 0 && !gated(KB_GATE_PEER))) return 0;
    struct task_struct* owner = bpf_task_from_pid(who < 0 ? (s32)(0u - (__u32)who) : who);
    if (!owner) return 0;
    __u32 into = task_protected(owner, task_state(owner)) ? KB_REACH_INTO : 0;
    int result = signal_reach(address_of(owner), 29 /* SIGIO */, KB_REACH_SIGIO | into);
    bpf_task_release(owner);
    return result;
}

__noinline int kb_owner_decide(__s32 who)
{
    return owner_decide(who);
}

/* F_SETOWN_EX's owner (struct f_owner_ex at Arg) as F_SETOWN takes one: a pid, or minus a process group. */
static __always_inline __s32 owner_ex(unsigned long arg)
{
    __s32 owner[2] = {};   /* type (F_OWNER_TID, F_OWNER_PID, F_OWNER_PGRP), pid */
    if (bpf_probe_read_user(owner, sizeof(owner), (const void*)arg) != 0) return 0;
    return owner[0] == 2 ? -owner[1] : owner[1];
}

/* fcntl commands that send signals or change a file's reach: /system/fcntl/<setown|setown_ex|setsig|setlease|notify|
 * add_seals>, write; F_SETOWN and F_SETOWN_EX also as the SIGIO they set up (kb_owner_decide). Locks are file_lock's. */
SEC("lsm/file_fcntl")
int BPF_PROG(kb_file_fcntl, struct file* file, unsigned int cmd, unsigned long arg, int ret)
{
    if (ret != 0) return ret;
    if (cmd == 8 || cmd == 15) {
        int owner = kb_decided(kb_owner_decide(cmd == 8 ? (__s32)arg : owner_ex(arg)));
        if (owner != 0) return owner;
    }
    if ((cmd != 8 && cmd != 15 && cmd != 10 && cmd != 1024 && cmd != 1026 && cmd != 1033) || !gated(KB_GATE_FCNTL))
        return 0;
    int started = system_begin();
    if (started <= 0) return started;
    struct kb_scratch* s = scratch();
    if (!s) return 0;
    set_path(s, "/system/fcntl/", 14);
    if (cmd == 8) append_text(s, "setown", 6);              /* F_SETOWN */
    else if (cmd == 15) append_text(s, "setown_ex", 9);     /* F_SETOWN_EX */
    else if (cmd == 10) append_text(s, "setsig", 6);        /* F_SETSIG */
    else if (cmd == 1024) append_text(s, "setlease", 8);    /* F_SETLEASE */
    else if (cmd == 1026) append_text(s, "notify", 6);      /* F_NOTIFY (dnotify) */
    else append_text(s, "add_seals", 9);                    /* F_ADD_SEALS */
    return kb_decided(kb_system_decide(KFILTER_RIGHT_WRITE, KB_ROOT(13)));
}

/* The process that last set a file's owner (F_SETOWN, F_SETOWN_EX, FIOSETOWN, SIOCSPGRP), by struct file: who a SIGIO
 * that file raises comes from. Every owner change passes file_set_fowner, so a reused address is rewritten before its
 * file can raise one. shortcut: an evicted entry leaves its file's SIGIO undecided; keep a file storage if it shows. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, __u32);
} kb_fowners SEC(".maps");

/* Returns void in the kernel: it can only note the setter. */
SEC("lsm/file_set_fowner")
int BPF_PROG(kb_file_set_fowner, struct file* file)
{
    __u64 key = address_of(file);
    __u32 tgid = current_tgid();
    bpf_map_update_elem(&kb_fowners, &key, &tgid, BPF_ANY);
    return 0;
}

/* The signal (SIGIO, F_SETSIG's) a file raises for the processes its owner names (Tsk), decided as one the owner's
 * setter sends (kb_reach_decide: block-process-signals across the family's boundary, peer rules naming a signal inside
 * it). Decided when raised in a task (a pipe or tty write); one raised in an interrupt (a socket's softirq), where no
 * task's working memory may be used, was decided when its owner was set (kb_owner_decide). */
SEC("lsm/file_send_sigiotask")
int BPF_PROG(kb_file_send_sigiotask, struct task_struct* tsk, struct fown_struct* fown, int sig, int ret)
{
    if (ret != 0 || in_interrupt() || !reach_gated(KFILTER_CFG_BLOCK_PROCESS_SIGNALS)) return ret;
    __u64 key = address_of(BPF_CORE_READ(fown, file));
    __u32* setter = bpf_map_lookup_elem(&kb_fowners, &key);
    if (!setter || *setter == 0) return 0;
    __u32 flags = KB_REACH_SIGIO | (task_protected(tsk, task_state(tsk)) ? KB_REACH_INTO : 0);
    return kb_decided(kb_reach_decide(*setter, address_of(tsk), KB_PROCESS_TERMINATE, sig != 0 ? (__u32)sig : 29 /* SIGIO */,
                                      flags));
}

/* ---- sockets ---- */

SEC("lsm/socket_shutdown")
int BPF_PROG(kb_socket_shutdown, struct socket* sock, int how, int ret)
{
    if (ret != 0) return ret;
    /* /system/socket/shutdown/<rd|wr|rdwr>, write */
    if (how == 0) return (int)system_space(KB_GATE_SHUTDOWN, "/system/socket/shutdown/rd", 26, 23, KFILTER_RIGHT_WRITE);
    if (how == 1) return (int)system_space(KB_GATE_SHUTDOWN, "/system/socket/shutdown/wr", 26, 23, KFILTER_RIGHT_WRITE);
    return (int)system_space(KB_GATE_SHUTDOWN, "/system/socket/shutdown/rdwr", 28, 23, KFILTER_RIGHT_WRITE);
}

/* A connected pair (socketpair): /system/socketpair/<family>/<type>/<protocol>, create (each socket's own creation is
 * /system/socket's). */
SEC("lsm/socket_socketpair")
int BPF_PROG(kb_socket_socketpair, struct socket* socka, struct socket* sockb, int ret)
{
    if (ret != 0 || !gated(KB_GATE_SOCKETPAIR)) return ret;
    int started = system_begin();
    if (started <= 0) return started;
    struct kb_scratch* s = scratch();
    struct sock* sk = BPF_CORE_READ(socka, sk);
    if (!s || !sk) return 0;
    set_path(s, "/system/socketpair/", 19);
    append_socket(s, BPF_CORE_READ(sk, __sk_common.skc_family), BPF_CORE_READ(socka, type), BPF_CORE_READ(sk, sk_protocol));
    return kb_decided(kb_system_decide(KFILTER_RIGHT_CREATE, KB_ROOT(18)));
}

/*
 * An AF_UNIX server of program Tgid reached at socket Sk (a unix_sock): its listen, an accept, an incoming connection or
 * datagram. A pipe decision of that program on the socket's address (its path, or /@name for an abstract one), right
 * listen, rule-only; a pipe rule without rights= does not name listen (it is loaded without it), so only rules naming it
 * meet these. An unbound socket is not decided.
 */
__noinline int kb_unix_listen(__u64 skAddress, __u32 tgid)
{
    struct kb_scratch* s = reset_for(tgid, 0);
    if (!s || unix_name(s, (struct unix_sock*)skAddress) != 0) return 0;
    return kb_decide_global(KFILTER_TARGET_PIPE, KFILTER_RIGHT_LISTEN, 0, 1);
}

/* The protected program a socket belongs to (socket_post_create records it), 0 for any other. */
static __always_inline __u32 unix_owner(struct sock* sk)
{
    struct kb_sock* owner = sk ? bpf_sk_storage_get(&kb_socks, sk, 0, 0) : 0;
    return owner && proc_guarded(owner->tgid) ? owner->tgid : 0;
}

/* A connection or datagram reaching a protected program's AF_UNIX socket (squatting a name others connect to), from
 * anyone: decided as that program's listen on it (kb_unix_listen). */
SEC("lsm/unix_stream_connect")
int BPF_PROG(kb_unix_stream_connect, struct sock* sock, struct sock* other, struct sock* newsk, int ret)
{
    if (ret != 0 || !gated(KB_GATE_LISTEN) || in_interrupt()) return ret;
    __u32 owner = unix_owner(other);
    return owner != 0 ? kb_decided(kb_unix_listen(address_of(other), owner)) : 0;
}

SEC("lsm/unix_may_send")
int BPF_PROG(kb_unix_may_send, struct socket* sock, struct socket* other, int ret)
{
    if (ret != 0 || !gated(KB_GATE_LISTEN) || in_interrupt()) return ret;
    struct sock* sk = other->sk;   /* a BTF pointer, as socket storage needs */
    __u32 owner = unix_owner(sk);
    return owner != 0 ? kb_decided(kb_unix_listen(address_of(sk), owner)) : 0;
}

/* ---- tasks: limits, scheduling and session queries on other processes, credentials, capabilities ---- */

/* s->path += a resource's name (RLIMIT_*), or its number. */
static __always_inline void append_resource(struct kb_scratch* s, __u32 resource)
{
    static const char names[16][12] = {"cpu", "fsize", "data", "stack", "core", "rss", "nproc", "nofile", "memlock",
                                       "as", "locks", "sigpending", "msgqueue", "nice", "rtprio", "rttime"};
    if (resource >= 16) {
        append_number(s, resource);
        return;
    }
    append_string(s, names[resource & 15], 0);
}

/* /system/rlimit/<resource>[/other], write for a change, query for a read: setrlimit and prlimit64 on the program
 * (task_setrlimit), prlimit64 on another process (task_prlimit, which names no resource: it is the call's). */
__noinline int kb_rlimit_decide(__u32 resource, __u32 other, __u32 rights)
{
    if (!gated(KB_GATE_RLIMIT)) return 0;
    int started = system_begin();
    if (started <= 0) return started;
    struct kb_scratch* s = scratch();
    if (!s) return 0;
    set_path(s, "/system/rlimit/", 15);
    append_resource(s, resource);
    if (other) append_text(s, "/other", 6);
    return kb_system_decide(rights, KB_ROOT(14));
}

SEC("lsm/task_setrlimit")
int BPF_PROG(kb_task_setrlimit, struct task_struct* p, unsigned int resource, struct rlimit* new_rlim, int ret)
{
    if (ret != 0 || BPF_CORE_READ(p, tgid) != current_tgid()) return ret;   /* another process's: task_prlimit's */
    return kb_decided(kb_rlimit_decide(resource, 0, KFILTER_RIGHT_WRITE));
}

SEC("lsm/task_prlimit")
int BPF_PROG(kb_task_prlimit, const struct cred* cred, const struct cred* tcred, unsigned int flags, int ret)
{
    if (ret != 0 || !gated(KB_GATE_RLIMIT)) return ret;
    struct task_struct* task = bpf_get_current_task_btf();
    struct pt_regs* regs = (struct pt_regs*)bpf_task_pt_regs(task);
    if (!regs) return 0;
    int compat = (BPF_CORE_READ(task, thread_info.status) & TS_COMPAT) != 0;
    if (BPF_CORE_READ(regs, orig_ax) != (compat ? 340 : 302)) return 0;   /* prlimit64(pid, resource, new, old) */
    __s32 pid = compat ? (__s32)BPF_CORE_READ(regs, bx) : (__s32)BPF_CORE_READ(regs, di);
    __u32 resource = compat ? (__u32)BPF_CORE_READ(regs, cx) : (__u32)BPF_CORE_READ(regs, si);
    struct task_struct* other = bpf_task_from_pid(pid);
    if (!other) return 0;
    int same = BPF_CORE_READ(other, tgid) == current_tgid();   /* a thread of its own */
    bpf_task_release(other);
    if (same) return 0;
    __u32 rights = ((flags & 1) != 0 ? KFILTER_RIGHT_QUERY : 0) | ((flags & 2) != 0 ? KFILTER_RIGHT_WRITE : 0);
    return kb_decided(kb_rlimit_decide(resource, 1, rights));
}

/* /system/task/<getscheduler|getioprio|getpgid|getsid|setpgid> on a task of another process (its own are not decided),
 * query (setpgid: write). */
static __always_inline int task_query(struct task_struct* p, const char* name, __u32 n, __u32 rights)
{
    if (!gated(KB_GATE_TASK)) return 0;
    int started = system_begin();
    if (started <= 0) return started;
    struct kb_scratch* s = scratch();
    if (!s || !other_process(p)) return 0;
    set_path(s, name, n);
    return kb_decided(kb_system_decide(rights, KB_ROOT(12)));
}

SEC("lsm/task_getscheduler")
int BPF_PROG(kb_task_getscheduler, struct task_struct* p, int ret)
{
    return ret != 0 ? ret : task_query(p, "/system/task/getscheduler", 25, KFILTER_RIGHT_QUERY);
}

SEC("lsm/task_getioprio")
int BPF_PROG(kb_task_getioprio, struct task_struct* p, int ret)
{
    return ret != 0 ? ret : task_query(p, "/system/task/getioprio", 22, KFILTER_RIGHT_QUERY);
}

SEC("lsm/task_getpgid")
int BPF_PROG(kb_task_getpgid, struct task_struct* p, int ret)
{
    return ret != 0 ? ret : task_query(p, "/system/task/getpgid", 20, KFILTER_RIGHT_QUERY);
}

SEC("lsm/task_getsid")
int BPF_PROG(kb_task_getsid, struct task_struct* p, int ret)
{
    return ret != 0 ? ret : task_query(p, "/system/task/getsid", 19, KFILTER_RIGHT_QUERY);
}

SEC("lsm/task_setpgid")
int BPF_PROG(kb_task_setpgid, struct task_struct* p, pid_t pgid, int ret)
{
    return ret != 0 ? ret : task_query(p, "/system/task/setpgid", 20, KFILTER_RIGHT_WRITE);
}

/* /system/cred/<setuid|setgid|setgroups|capset|capget>: changing its credentials (set*uid, set*gid, setgroups, capset),
 * write; reading a task's capabilities (capget), query. */
SEC("lsm/task_fix_setuid")
int BPF_PROG(kb_task_fix_setuid, struct cred* new, const struct cred* old, int flags, int ret)
{
    return ret != 0 ? ret : (int)system_space(KB_GATE_CRED, "/system/cred/setuid", 19, 12, KFILTER_RIGHT_WRITE);
}

SEC("lsm/task_fix_setgid")
int BPF_PROG(kb_task_fix_setgid, struct cred* new, const struct cred* old, int flags, int ret)
{
    return ret != 0 ? ret : (int)system_space(KB_GATE_CRED, "/system/cred/setgid", 19, 12, KFILTER_RIGHT_WRITE);
}

SEC("lsm/task_fix_setgroups")
int BPF_PROG(kb_task_fix_setgroups, struct cred* new, const struct cred* old, int ret)
{
    return ret != 0 ? ret : (int)system_space(KB_GATE_CRED, "/system/cred/setgroups", 22, 12, KFILTER_RIGHT_WRITE);
}

SEC("lsm/capset")
int BPF_PROG(kb_capset, struct cred* new, const struct cred* old, const kernel_cap_t* effective,
             const kernel_cap_t* inheritable, const kernel_cap_t* permitted, int ret)
{
    return ret != 0 ? ret : (int)system_space(KB_GATE_CRED, "/system/cred/capset", 19, 12, KFILTER_RIGHT_WRITE);
}

SEC("lsm/capget")
int BPF_PROG(kb_capget, const struct task_struct* target, kernel_cap_t* effective, kernel_cap_t* inheritable,
             kernel_cap_t* permitted, int ret)
{
    return ret != 0 ? ret : (int)system_space(KB_GATE_CRED, "/system/cred/capget", 19, 12, KFILTER_RIGHT_QUERY);
}

/* A capability check of the program's own (its credentials, not a file's or another task's):
 * /system/capability/<name> (sys_admin, net_raw...; past the known ones, its number), query. A refusal fails the call
 * that asked as if the capability were missing (EPERM). Checked very often: decided only while a rule names the space. */
SEC("lsm/capable")
int BPF_PROG(kb_capable, const struct cred* cred, struct user_namespace* ns, int cap, unsigned int opts, int ret)
{
    static const char names[41][20] = {
        "chown", "dac_override", "dac_read_search", "fowner", "fsetid", "kill", "setgid", "setuid", "setpcap",
        "linux_immutable", "net_bind_service", "net_broadcast", "net_admin", "net_raw", "ipc_lock", "ipc_owner",
        "sys_module", "sys_rawio", "sys_chroot", "sys_ptrace", "sys_pacct", "sys_admin", "sys_boot", "sys_nice",
        "sys_resource", "sys_time", "sys_tty_config", "mknod", "lease", "audit_write", "audit_control", "setfcap",
        "mac_override", "mac_admin", "syslog", "wake_alarm", "block_suspend", "audit_read", "perfmon", "bpf",
        "checkpoint_restore"};
    if (ret != 0 || !gated(KB_GATE_CAPABILITY) || in_interrupt()) return ret;
    struct task_struct* task = bpf_get_current_task_btf();
    if (BPF_CORE_READ(task, cred) != cred) return 0;
    int started = system_begin();
    if (started <= 0) return started;
    struct kb_scratch* s = scratch();
    if (!s) return 0;
    set_path(s, "/system/capability/", 19);
    if (cap >= 0 && cap < 41) append_string(s, names[cap], 0);
    else append_number(s, (__u32)cap);
    return kb_decided(kb_system_decide(KFILTER_RIGHT_QUERY, KB_ROOT(18)));
}

SEC("lsm/userns_create")
int BPF_PROG(kb_userns_create, const struct cred* cred, int ret)
{
    return ret != 0 ? ret : (int)system_space(KB_GATE_NAMESPACE, "/system/namespace/user", 22, 17, KFILTER_RIGHT_CREATE);
}

/* ---- SysV objects, forks, ptrace, kernel modules ---- */

/* Creating a SysV object: /system/ipc/create/<shm|msg|sem>/<key, 8 hex digits> (its uses are /system/ipc/<kind>/<key>). */
static __always_inline int ipc_create(struct kern_ipc_perm* perm, const char* kind)
{
    if (!gated(KB_GATE_IPC)) return 0;
    int started = system_begin();
    if (started <= 0) return started;
    struct kb_scratch* s = scratch();
    if (!s) return 0;
    set_path(s, "/system/ipc/create/", 19);
    append_text(s, kind, 4);
    append_hex(s, (__u32)BPF_CORE_READ(perm, key), 8);
    return kb_decided(kb_system_decide(KFILTER_RIGHT_CREATE, KB_ROOT(18)));
}

SEC("lsm/shm_alloc_security")
int BPF_PROG(kb_shm_alloc, struct kern_ipc_perm* perm, int ret)
{
    return ret != 0 ? ret : ipc_create(perm, "shm/");
}

SEC("lsm/msg_queue_alloc_security")
int BPF_PROG(kb_msg_queue_alloc, struct kern_ipc_perm* perm, int ret)
{
    return ret != 0 ? ret : ipc_create(perm, "msg/");
}

SEC("lsm/sem_alloc_security")
int BPF_PROG(kb_sem_alloc, struct kern_ipc_perm* perm, int ret)
{
    return ret != 0 ? ret : ipc_create(perm, "sem/");
}

/* ptrace(PTRACE_TRACEME): asking its parent to trace it. */
SEC("lsm/ptrace_traceme")
int BPF_PROG(kb_ptrace_traceme, struct task_struct* parent, int ret)
{
    return ret != 0 ? ret : (int)system_space(KB_GATE_PTRACE, "/system/ptrace/traceme", 22, 14, KFILTER_RIGHT_WRITE);
}

/* A module the kernel loads for the program (socket() of an absent family: request_module): /system/kernel/module/
 * <name>, create; a refusal fails that call (EAFNOSUPPORT for a socket). */
SEC("lsm/kernel_module_request")
int BPF_PROG(kb_kernel_module_request, char* kmod_name, int ret)
{
    if (ret != 0 || !gated(KB_GATE_KERNEL)) return ret;
    int started = system_begin();
    if (started <= 0) return started;
    struct kb_scratch* s = scratch();
    if (!s) return 0;
    set_path(s, "/system/kernel/module/", 22);
    append_string(s, kmod_name, 0);
    return kb_decided(kb_system_decide(KFILTER_RIGHT_CREATE, KB_ROOT(14)));
}

/* Data the program hands the kernel to load from a buffer (init_module, a kexec image, firmware): /system/kernel/load/
 * <module|firmware|kexec-image|kexec-initramfs|policy|x509|unknown>, create. (Loads from a file are always refused,
 * kb_kernel_read_file.) */
SEC("lsm/kernel_load_data")
int BPF_PROG(kb_kernel_load_data, enum kernel_load_data_id id, bool contents, int ret)
{
    if (ret != 0) return ret;
    if (id == LOADING_MODULE) return (int)system_space(KB_GATE_KERNEL, "/system/kernel/load/module", 26, 14, KFILTER_RIGHT_CREATE);
    if (id == LOADING_FIRMWARE) return (int)system_space(KB_GATE_KERNEL, "/system/kernel/load/firmware", 28, 14, KFILTER_RIGHT_CREATE);
    if (id == LOADING_KEXEC_IMAGE) return (int)system_space(KB_GATE_KERNEL, "/system/kernel/load/kexec-image", 31, 14, KFILTER_RIGHT_CREATE);
    if (id == LOADING_KEXEC_INITRAMFS)
        return (int)system_space(KB_GATE_KERNEL, "/system/kernel/load/kexec-initramfs", 35, 14, KFILTER_RIGHT_CREATE);
    if (id == LOADING_POLICY) return (int)system_space(KB_GATE_KERNEL, "/system/kernel/load/policy", 26, 14, KFILTER_RIGHT_CREATE);
    if (id == LOADING_X509_CERTIFICATE) return (int)system_space(KB_GATE_KERNEL, "/system/kernel/load/x509", 24, 14, KFILTER_RIGHT_CREATE);
    return (int)system_space(KB_GATE_KERNEL, "/system/kernel/load/unknown", 27, 14, KFILTER_RIGHT_CREATE);
}

/* ---- memory below mmap_min_addr ---- */

/* A mapping placed below mmap_min_addr (the kernel already refuses one without CAP_SYS_RAWIO):
 * /system/memory/low, create. */
SEC("lsm/mmap_addr")
int BPF_PROG(kb_mmap_addr, unsigned long addr, int ret)
{
    if (ret != 0) return ret;
    if (kb_map_stashed(addr) != 0) return -EPERM;
    if (!gated(KB_GATE_LOW)) return 0;   /* before mmap_min_addr's read: every mmap on the system passes here */
    unsigned long low = 65536;
    if (bpf_ksym_exists(&mmap_min_addr)) bpf_probe_read_kernel(&low, sizeof(low), &mmap_min_addr);
    if (addr >= low) return 0;
    return (int)system_space(KB_GATE_LOW, "/system/memory/low", 18, 18, KFILTER_RIGHT_CREATE);
}

#ifdef KB_TEST_BENCH
/*
 * Test bench (filter/tests/linux_bpf_bench.cpp, tests/bpf_bench.sh): built only into kfilter_bench.bpf.o and run
 * with BPF_PROG_TEST_RUN on the bench's own unpinned maps, never attached. The calling task becomes a protected
 * program named by the request's image as kb_wine_name names a Wine process, and the request is decided by what a
 * hook runs: system_begin and kb_system_decide for system decisions, begin and kb_decide_global for the rest, and
 * kb_wine_query with kb_handle_decide for a Wine request (wine); wineserver's replies and module table changes as
 * their hooks run them.
 */
/* kb_bench_syscall's registers (kb_bench.wine 6). */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct pt_regs);
} kb_bench_regs SEC(".maps");

/* The calling task becomes a protected program named by B's image; 0 on success. */
static __always_inline int bench_program(struct kb_bench* b)
{
    struct kb_task* state = bpf_task_storage_get(&kb_tasks, bpf_get_current_task_btf(), 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    __u32 tgid = current_tgid();
    struct kb_proc* proc = proc_entry(tgid);
    __u32 n = b->ilen;
    if (!state || !proc || n >= KB_PROG || b->len >= KB_PATH || b->vlen >= KB_VALUE) return 1;
    state->guarded = 1;
    proc->guarded = 1;
    bpf_probe_read_kernel(proc->image, KB_PROG, b->image);
    struct base_ctx base = {tgid, n};
    proc->ibase = 0;
    bpf_loop(KB_PROG, base_step, &base, 0);
    if (proc->ibase >= KB_PROG) proc->ibase = 0;
    proc->ilen = n;
    return 0;
}

SEC("syscall")
int kb_bench_decide(struct kb_bench* b)
{
    if (bench_program(b) != 0) return 1;
    __u32 tgid = current_tgid(), len = b->len, vlen = b->vlen, target = b->target;
    if (len >= KB_PATH || vlen >= KB_VALUE) return 1;
    if (b->wine == 2) {
        struct kb_pending* pending = bpf_map_lookup_elem(&kb_pending, &(__u32){current_tid()});
        b->decided = pending != 0;
        if (pending) wineserver_reply(pending, current_tid(), tgid, b->data);
        return 0;
    }
    if (b->wine == 3) {
        if (b->request[0] != 0) image_mapped(b->request[0], tgid);
        else modules_changed(tgid);
        return 0;
    }
    int started = target == KFILTER_TARGET_SYSTEM ? system_begin() : begin() == 0;
    b->decided = started > 0;
    b->verdict = 0;
    if (started <= 0) return 0;
    struct kb_scratch* s = scratch();
    struct kb_access* a = bpf_task_storage_get(&kb_accesses, bpf_get_current_task_btf(), 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!s || !a) return 1;
    b->ibase = s->ibase;
    if (b->wine == 1 || b->wine == 4 || b->wine == 5) {
        /* As kb_file_permission decides a request kb_wine_request decoded: its data chunks joined (a write whose
         * chunks do not add up to its request_size is refused), then its decoders and the decisions they prepare. */
        int joined = b->count > 1 ? kb_request_data(b->iov, b->count, 0, b->request[1], 1) : 0;
        if (joined < 0) {
            b->decided = 1;
            b->verdict = kb_decided(refuse(KB_RAW_REQUEST));
            return 0;
        }
        __u32 size = b->request[1] < KB_REQ_DATA ? b->request[1] : KB_REQ_DATA;
        struct kb_reqdata* d = (__u32)joined == size ? bpf_task_storage_get(&kb_reqdata, bpf_get_current_task_btf(), 0, 0) : 0;
        __u64 data = d ? address_of(d->data) : 0;
        for (int i = 0; i < 16; i++) s->request[i] = b->request[i];
        __u32 req = b->request[0];
        if (b->wine == 4) {
            expect_object(req, tgid, current_tid());
            if (req == KB_REQ_SET_KERNEL_OBJECT_PTR || req == KB_REQ_GET_KERNEL_OBJECT_HANDLE) {
                b->decided = 0;
                kb_kernel_object(tgid, current_tid());
                return 0;
            }
            int nt = req == KB_REQ_OPEN_FILE_OBJECT || req == KB_REQ_CREATE_NAMED_PIPE || req == KB_REQ_OPEN_MAPPING ||
                     req == KB_REQ_CREATE_MAPPING || req == KB_REQ_OPEN_DIRECTORY || req == KB_REQ_CREATE_DIRECTORY;
            int code = nt ? kb_nt_object(tgid, current_tid(), data, size) : kb_registry(tgid, current_tid(), data, size);
            b->decided = code > 0 && (code & KB_REG_DECIDE) != 0;
            if (b->decided) {
                __u32 decided = (code & KB_NT_OBJECT) == 0 ? KFILTER_TARGET_REGISTRY :
                                (code & KB_NT_PIPE) != 0 ? KFILTER_TARGET_PIPE : KFILTER_TARGET_FILE;
                b->verdict = kb_decided(kb_decide_global(decided, code & KB_REG_RIGHTS, 0, 0));
            }
            if (code > 0 && (code & KB_REG_PENDING) != 0 && b->verdict == 0) kb_registry_pending();
            return 0;
        }
        if (b->wine == 5) expect_object(req, tgid, current_tid());
        int code = kb_wine_query(tgid, current_tid(), data, size);
        b->decided = code == KB_HANDLE_DECIDE || (code > 0 && (code & KB_SYSTEM_DECIDE) != 0);
        if (code == KB_HANDLE_DECIDE) b->verdict = kb_decided(kb_handle_decide());
        else if (b->decided)
            b->verdict = kb_decided(kb_decide_global(KFILTER_TARGET_SYSTEM, code & KB_REG_RIGHTS, 0, kb_system_listed(code)));
        if (b->wine != 5 || b->verdict != 0 || code == KB_HANDLE_DECIDE) return 0;
        /* 5: then, as kb_wine_request's second pass runs it, the bookkeeping and what the request reaches past its own
         * decision (kb_wine_note, kb_handle_request, wine_targets: kb_wine_decide). */
        s = reset_for(tgid, 0);
        struct kb_cfg* c = kb_cfg_get();
        if (!s || !c || req >= KB_REQ_COUNT) return 1;
        for (int i = 0; i < 16; i++) s->request[i] = b->request[i];
        __u32 kept = data != 0 ? size : 0;
        if (req == KB_REQ_CREATE_WINDOW || req == KB_REQ_GET_DESKTOP_WINDOW ||
            (req == KB_REQ_CREATE_FILE && (c->targets & KB_TARGET_KEYED) != 0)) {
            kb_wine_note(tgid, current_tid(), data, size);
            return 0;
        }
        if (req == KB_REQ_OPEN_PROCESS || req == KB_REQ_OPEN_THREAD || req == KB_REQ_DUP_HANDLE ||
            req == KB_REQ_GET_NEXT_THREAD || req == KB_REQ_GET_NEXT_PROCESS || req == KB_REQ_NEW_THREAD ||
            req == KB_REQ_NEW_PROCESS)
            code = kb_handle_request(tgid, current_tid(), 1, kept);
        else
            code = kb_wtargets[req].kind != 0 ? wine_targets(c, s, req, kept) : 0;
        if (code == KB_WINE_DECIDE) b->verdict = kb_decided(kb_wine_decide());
        else if (code == KB_HANDLE_DECIDE) b->verdict = kb_decided(kb_handle_decide());
        b->decided |= code == KB_WINE_DECIDE || code == KB_HANDLE_DECIDE;
        return 0;
    }
    bpf_probe_read_kernel(s->path, KB_PATH, b->path);
    s->len = len;
    /* A decision on memory: what it reaches, as the hook would have written it. */
    if ((b->listed & KB_ADDRESSED) != 0) bpf_probe_read_kernel(a, sizeof(*a), &b->access);
    if (target == KFILTER_TARGET_SYSTEM && (b->listed & (KB_ADDRESSED | KB_ADDRESS_ONLY)) == 0) {
        b->verdict = kb_decided(kb_system_decide(b->rights, b->listed));
        return 0;
    }
    if (target == KFILTER_TARGET_DEVICE && vlen == 0) {
        device_value(s, b->value);
    } else {
        bpf_probe_read_kernel(s->value, KB_VALUE, b->value_text);
        s->vlen = vlen;
    }
    b->verdict = kb_decided(kb_decide_global(target, b->rights, b->value, b->listed));
    return 0;
}

#define KB_BENCH_PIPE 0xFFFF888000001000ull   /* the request pipe kb_bench_pipe registers for this thread (an inode key) */

/* kb_bench.wine 9: a Wine request write, decided by the request pipe hook's own code (kfilter_bpf.h). */
SEC("syscall")
int kb_bench_pipe(struct kb_bench* b)
{
    __u32 tgid = current_tgid();
    struct kb_task* state = bpf_task_storage_get(&kb_tasks, bpf_get_current_task_btf(), 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    struct kb_proc* proc = proc_entry(tgid);
    struct kb_bench_io* io = bpf_map_lookup_elem(&kb_bench_ios, &(__u32){0});
    if (bench_program(b) != 0 || !state || !proc || !io) return 1;
    __u64 inode = KB_BENCH_PIPE;
    struct kb_pipe registered = {tgid, current_tid(), KB_PIPE_REQUEST, 0};
    bpf_map_update_elem(&kb_pipes, &inode, &registered, BPF_ANY);
    proc->checked = 1;
    proc->decode = 1;
    state->role = KB_ROLE_WINE;
    __u32 count = b->count;
    io->vector = count > 1;
    io->buffer = b->iov;
    io->count = count > 1 ? count : 64;
    io->compat = b->compat;
    io->active = 1;
    int code = wine_write(inode);
    if (code == KB_WINE_DECIDE) code = kb_wine_decide() != 0 ? -EFAULT : 0;   /* kb_wine_reach's */
    io->active = 0;
    state->role = KB_ROLE_NONE;
    b->decided = 1;
    b->verdict = code < 0 ? -EFAULT : 0;
    return 0;
}

/* A syscall as its entry point's program decides it (kb_bench.wine 6), in registers the bench's map holds (kernel
 * memory, as an entry's are). A program of its own: kb_bench_decide's frame on top of the decision's passed 512 bytes. */
SEC("syscall")
int kb_bench_syscall(struct kb_bench* b)
{
    __u32 zero = 0;
    struct pt_regs* regs = bpf_map_lookup_elem(&kb_bench_regs, &zero);
    if (!regs || bench_program(b) != 0) return 1;
#define KB_ARGUMENT(i) ((__u64)b->request[3 + 2 * (i)] << 32 | b->request[2 + 2 * (i)])
    __u32 compat = b->request[1] != 0;
    regs->orig_ax = b->request[0];
    regs->bx = KB_ARGUMENT(0);   /* ia32's registers, then x86_64's from them (a ctx offset picked at run time is refused) */
    regs->cx = KB_ARGUMENT(1);
    regs->dx = KB_ARGUMENT(2);
    regs->si = KB_ARGUMENT(3);
    regs->di = KB_ARGUMENT(4);
    regs->bp = KB_ARGUMENT(5);
    regs->r10 = KB_ARGUMENT(3);
    regs->r8 = KB_ARGUMENT(4);
    regs->r9 = KB_ARGUMENT(5);
#undef KB_ARGUMENT
    if (!compat) {
        regs->di = regs->bx;
        regs->si = regs->cx;
    }
    b->verdict = kb_decided(kb_syscall_decide(address_of(regs), compat));
    b->decided = 1;
    return 0;
}

/* A unix_sock and, in its second half, its unix_address, in map memory: kb_unix_listen reads them at this kernel's offsets. */
struct kb_bench_sock {
    char bytes[4096];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct kb_bench_sock);
} kb_bench_unix SEC(".maps");

/* ABI 11's decision functions as their hooks call them (kb_bench.wine 7): request[0] which, the rest their arguments:
 * 1 kb_thread_decide(1), a fork; 2 kb_rlimit_decide(resource, other, rights); 3 kb_reach_decide(actor, the calling task,
 * access, value, flags); 4 kb_prctl_decide(option); 5 kb_memory_decide(start, end, prot, shared), 64-bit words low first;
 * 6 kb_netlink_decide(protocol, type, a message in value_text); 7 kb_unix_bind(a sockaddr in value_text, length);
 * 8 kb_map_stash(prot, flags, data), its length request[4] (what request_range reads from an mmap's registers);
 * 9 kb_map_stashed(addr); 10 kb_ioctl_argument(cmd, a pointer to the argument in the bench's memory) on path;
 * 11 kb_owner_decide(who); the calling task as the sender in KB_ROLE request[4] (task 0: none) of: 12
 * kb_signal_reach(task request[1], signal, flags), 13 kb_read_reach(task request[1], mode, into); 14 kb_unix_listen on a
 * unix socket of the calling program bound to the sun_path in value_text; after system_begin, 15 kb_up_decide(cookie,
 * key, address, handle, where), 64-bit words low first from request[1], and 16 kb_wmi_decide(query, path, method),
 * query and method pointers into the bench's memory at request[1] and [4] (0: no method); 17 kb_unknown_peer(task
 * request[1], the calling program, the calling thread): wineserver reaching that task for the thread's pending request. */
SEC("syscall")
int kb_bench_helper(struct kb_bench* b)
{
    if (bench_program(b) != 0) return 1;
    __u32 which = b->request[0];
    int verdict = 0;
    struct kb_task* state = task_state(bpf_get_current_task_btf());
    if (which == 12 || which == 13) {
        struct task_struct* task = bpf_task_from_pid((s32)b->request[1]);
        if (!task || !state) {
            if (task) bpf_task_release(task);
            return 1;
        }
        __u32 role = state->role;
        state->role = b->request[4];
        verdict = which == 12 ? kb_signal_reach(address_of(task), b->request[2], b->request[3])
                              : kb_read_reach(address_of(task), b->request[2], b->request[3]);
        state->role = role;
        bpf_task_release(task);
    }
    if (which == 17) {
        struct task_struct* task = bpf_task_from_pid((s32)b->request[1]);
        if (!task) return 1;
        verdict = kb_unknown_peer(address_of(task), current_tgid(), current_tid());
        bpf_task_release(task);
    }
    if (which == 8) {
        kb_map_stash(b->request[1], b->request[2], b->request[3]);
        struct kb_map_stash* stash = bpf_task_storage_get(&kb_map_stashes, bpf_get_current_task_btf(), 0, 0);
        if (stash && b->request[3]) stash->length = b->request[4];
    }
    if (which == 9) verdict = kb_map_stashed((__u64)b->request[2] << 32 | b->request[1]);
    if (which == 10 && begin() == 0) {
        struct kb_scratch* s = scratch();
        if (!s) return 1;
        bpf_probe_read_kernel(s->path, KB_PATH, b->path);
        s->len = b->len;
        verdict = kb_ioctl_argument(b->request[1], (__u64)b->request[3] << 32 | b->request[2]);
    }
    if (which == 11) verdict = kb_owner_decide((__s32)b->request[1]);
#define KB_WORD(i) ((__u64)b->request[(i) + 1] << 32 | b->request[i])
    if (which == 15 && system_begin() > 0) verdict = kb_up_decide(KB_WORD(1), KB_WORD(3), KB_WORD(5), KB_WORD(7), KB_WORD(9));
    if (which == 16 && system_begin() > 0) verdict = kb_wmi_decide(KB_WORD(1), b->request[3], KB_WORD(4));
#undef KB_WORD
    if (which == 14) {
        __u32 zero = 0, vlen = b->vlen;
        struct kb_bench_sock* sock = bpf_map_lookup_elem(&kb_bench_unix, &zero);
        __u32 at = bpf_core_field_offset(struct unix_sock, addr), len = bpf_core_field_offset(struct unix_address, len);
        __u32 name = bpf_core_field_offset(struct unix_address, name);
        if (!sock || at > 2048 - 8 || len > 2048 - 4 || name > 2048 - 2 - KB_VALUE || vlen > 108) return 1;
        *(__u64*)&sock->bytes[at] = address_of(sock) + 2048;
        *(__u32*)&sock->bytes[2048 + len] = 2 + vlen;   /* sun_family and the name */
        bpf_probe_read_kernel(&sock->bytes[2048 + name + 2], KB_VALUE, b->value_text);
        verdict = kb_unix_listen(address_of(sock), current_tgid());
    }
    if (which == 1) verdict = kb_thread_decide(1);
    else if (which == 2) verdict = kb_rlimit_decide(b->request[1], b->request[2], b->request[3]);
    else if (which == 3)
        verdict = kb_reach_decide(b->request[1], address_of(bpf_get_current_task_btf()), b->request[2], b->request[3], b->request[4]);
    else if (which == 4) verdict = kb_prctl_decide(b->request[1]);
    else if (which == 5)
        verdict = kb_memory_decide((__u64)b->request[2] << 32 | b->request[1], (__u64)b->request[4] << 32 | b->request[3],
                                   b->request[5], b->request[6]);
    else if (which == 6 && begin() == 0) verdict = kb_netlink_decide(b->request[1], b->request[2], address_of(b->value_text));
    else if (which == 7 && begin() == 0) verdict = kb_unix_bind(address_of(b->value_text), b->request[1]);   /* after BEGIN */
    b->verdict = kb_decided(verdict);
    b->decided = 1;
    return 0;
}

/* The socket kb_bench_net's UDP sends and receives share (kb_sock: its peer cache). */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct kb_sock);
} kb_bench_socks SEC(".maps");

/*
 * A network decision as its hook makes it (kb_bench.wine 8): request[0] what, [1] family (4, 6), [2] protocol, [3] port,
 * [4..7] the peer's address, [8] a message's size, [9] its number; a send's first bytes in value_text. 1: a TCP connect
 * (socket_connect); 2: a send, a DNS query first when it goes to port 53 (decide_message); 3: a receive; 4: a UDP send
 * through the socket's peer cache (udp_decide); 5: a UDP datagram received, in softirq, through that cache
 * (receive_datagram); 6: a send to an AF_UNIX peer whose sun_path is path (len bytes), request[1] 0 a connected one
 * (kb_unix_peer: a socket in kb_bench_unix bound to it, connected to itself), 1 a sendto's address (unix_path; [2] an
 * addrlen naming fewer of its bytes, no NUL after them), through the hook's kb_unix_send (a sendto's pipe connect
 * decision, the unix gate).
 * request[15] out: the ns it took.
 */
SEC("syscall")
int kb_bench_net(struct kb_bench* b)
{
    __u64 start = bpf_ktime_get_ns();   /* a syscall program's test run reports no duration */
    __u32 zero = 0;
    struct kb_sock* owner = bpf_map_lookup_elem(&kb_bench_socks, &zero);
    struct kb_cfg* c = kb_cfg_get();
    if (!owner || !c || bench_program(b) != 0 || begin() != 0) return 1;
    struct kb_scratch* s = scratch();
    if (!s) return 1;
    __u32 what = b->request[0], family = b->request[1], protocol = b->request[2], port = b->request[3];
    bpf_probe_read_kernel(s->address, 16, &b->request[4]);
    int verdict = 0;
    if (what == 1) {
        verdict = kb_net_decide(0, s->tgid, family, protocol, port, KFILTER_RIGHT_CONNECT);
    } else if (what == 4) {
        __u32 generation = c->generation;
        if (!peer_known(s, owner, family, port)) {
            verdict = kb_net_decide(0, s->tgid, family, 17, port, KFILTER_RIGHT_CONNECT);
            if (verdict == 0) peer_add(s, owner, family, port, generation);
        }
    } else if (what == 5) {
        __u32 irq = irq_enter();
        struct kb_scratch* q = irq ? scratch_irq(irq) : 0;
        if (q) {
            bpf_probe_read_kernel(q->address, 16, &b->request[4]);
            if (!peer_known(q, owner, family, port)) verdict = kb_net_decide(irq, s->tgid, family, 17, port, KFILTER_RIGHT_LISTEN);
        }
        if (irq) irq_leave();
    } else {
        int sent = 1;
        if (what == 6) {
            __u32 at = bpf_core_field_offset(struct unix_sock, addr), len = bpf_core_field_offset(struct unix_address, len);
            __u32 name = bpf_core_field_offset(struct unix_address, name), peer = bpf_core_field_offset(struct unix_sock, peer);
            __u32 sunLength = b->len & 127;
            struct kb_bench_sock* sock = bpf_map_lookup_elem(&kb_bench_unix, &zero);
            if (!sock || at > 2048 - 8 || peer > 2048 - 8 || len > 1024 - 4 || name > 1024 - 2 - 128 || sunLength > 108) return 1;
            *(__u16*)&sock->bytes[bpf_core_field_offset(struct sock, __sk_common.skc_family) & 2047] = AF_UNIX;
            *(__u64*)&sock->bytes[peer] = address_of(sock);
            *(__u64*)&sock->bytes[at] = address_of(sock) + 2048;
            *(__u32*)&sock->bytes[2048 + len] = 2 + sunLength;   /* sun_family and the name */
            *(__u16*)&sock->bytes[3072] = AF_UNIX;   /* a sendto's sockaddr_un */
            bpf_probe_read_kernel(&sock->bytes[2048 + name + 2], 128, b->path);
            bpf_probe_read_kernel(&sock->bytes[3074], 128, b->path);
            __u32 given = b->request[2] != 0 && b->request[2] < sunLength ? b->request[2] : sunLength;   /* a short addrlen */
            if (b->request[1] && unix_path(s, (const struct sockaddr*)&sock->bytes[3072], 2 + given) != 0) return 1;
            sent = kb_unix_send(b->request[1], address_of(sock));   /* the hook's: a sendto's connect, the gate, the peer */
            family = KFILTER_NET_FAMILY_UNIX;
            protocol = 0;
            port = 0;
        }
        __u32 right = what == 2 || what == 6 ? KFILTER_RIGHT_SEND : KFILTER_RIGHT_RECEIVE;
        s->mindex = b->request[9];
        s->minode = 0;
        s->msize = b->request[8];
        s->caller = 0;
        s->mbits = 0;
        s->mlen = right == KFILTER_RIGHT_SEND ? b->vlen & (KB_VALUE - 1) : 0;
        bpf_probe_read_kernel(s->walk, KB_VALUE, b->value_text);
        if (sent <= 0) verdict = sent;
        else if (what == 2 && port == 53 && (protocol == 17 || protocol == 6) && kb_dns_decide(protocol == 6) != 0) verdict = -EPERM;
        else if (kb_msg_decide_global((family << 8) | (protocol & 0xFF), port, right, 0) != 0) verdict = -EPERM;
    }
    b->verdict = kb_decided(verdict);
    b->decided = 1;
    b->request[15] = (__u32)(bpf_ktime_get_ns() - start);
    return 0;
}

/* kb_bench_hold's state: [0] 1 while it holds, 2 once it ended; [1] set by the bench to end it. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u32);
} kb_bench_holds SEC(".maps");

static long hold_step(__u32 index, __u64* until)
{
    __u32 one = 1;
    __u32* release = bpf_map_lookup_elem(&kb_bench_holds, &one);
    return !release || *release != 0 || bpf_ktime_get_ns() > *until;
}

/* A decision under way as an LSM hook's runs, non-sleepable under the RCU read lock (BPF_PROG_TEST_RUN runs a raw_tp
 * program so; kb_bench_decide is sleepable, which no RCU grace period waits for), until the bench ends it or a
 * second passes: the reader of the bench's grace case. */
SEC("raw_tp")
int kb_bench_hold(void* ctx)
{
    __u32 zero = 0;
    __u32* held = bpf_map_lookup_elem(&kb_bench_holds, &zero);
    if (!held) return 1;
    __u64 until = bpf_ktime_get_ns() + 1000000000ull;
    *held = 1;
    for (int i = 0; i < 8; i++) bpf_loop(1 << 23, hold_step, &until, 0);
    *held = 2;
    return 0;
}
#endif
