#pragma once

/*
 * Maps shared by linux/bpf/kfilter.bpf.c (kernel) and linux/bpf_loader.cpp (kfilterd).
 * kfilterd compiles each KFILTER_CONFIG into these; the LSM programs decide from them
 * with the same first-match, rights, counted-rule and mode rules as driver/policy.c.
 */
#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#define KB_PATH 512          /* bytes of a resolved path; a longer one is a name failure */
#define KB_PATTERN 256       /* bytes of a rule path; a longer rule refuses block mode */
#define KB_VALUE 128         /* bytes of a value name (registry value, device ioctl); KFILTER_MAX_VALUE */
#define KB_IMAGE 64          /* bytes of an image= pattern; KFILTER_MAX_IMAGE */
#define KB_PROG 256          /* bytes of a program's image path; a longer one keeps its tail */
#define KB_RULES 16384       /* KFILTER_MAX_RULES */
#define KB_GLOBS 256         /* rules with '*': each is tried on every decision */
#define KB_GLOB_END 0xFFFFFFFFu /* in kb_globs after the last wildcard rule */
#define KB_PER_PATH 8        /* rules sharing one literal path */
#define KB_NET 256           /* KFILTER_MAX_NET_RULES */
#define KB_NAMES 16          /* KFILTER_MAX_PROTECTED */
#define KB_NAME 128
#define KB_CANDIDATES 16
#define KB_CREATOR 64
#define KB_WINE_DIRS 4
#define KB_WINE_DIR 64
#define KB_MODS 128          /* code ranges of one program's own Windows modules (module= rules) */
#define KB_MOD_BITS 32       /* distinct module= patterns */
#define KB_W32_NAMES 1024    /* win32u.so functions system rules can name (/system/win32k/<function>) */
#define KB_W32_NAME 64

/* kb_cfg.flags carries KFILTER_CFG_*; kb_rule fields are KFILTER_RULE's. */
struct kb_rule {
    __u32 action;
    __u32 targets;
    __u32 rights;
    __u32 ext;
    __u32 rule_id;
    __u32 account;
    __u32 count;
    __u32 flags;
    __u32 plen;
    __u32 vlen;
    __u32 wild;          /* the path has a '*' */
    __u32 ilen;          /* image= pattern length, 0: every program */
    __u32 iwhole;        /* the image pattern has a separator: match the whole image path */
    __u32 risk;          /* risk=: an allow by this rule also logs a RISK event */
    __u32 mbit;          /* module= (KFILTER_RULE_MODULE): the pattern's bit in kb_mod.bits, matched instead of value */
    __u32 head;          /* bytes of path before its first '*' (all of it without one): how far it names a space (KB_ROOT) */
    char path[KB_PATTERN];
    char value[KB_VALUE];
    char image[KB_IMAGE];
};

/* kb_literal key: two independent hashes of a literal rule path and its length. */
struct kb_key {
    __u64 fnv;
    __u32 djb;
    __u32 len;
};

struct kb_slots {
    __u32 count;
    __u32 slot[KB_PER_PATH];
};

struct kb_net {
    __u32 action;
    __u32 family;
    __u32 protocol;
    __u32 prefix;
    __u32 port;
    __u32 rule_id;
    __u32 rights;
    __u32 count;
    __u32 risk;
    __u32 ilen;
    __u32 iwhole;
    __u8 address[16];
    __u8 pad[4];
    char image[KB_IMAGE];
    /* Message rules (rights KFILTER_RIGHT_SEND/RECEIVE): 0 when unused. */
    __u32 size_min, size_max, index_min, index_max, match_off, match_len;
    __u8 match[16];
    __u32 mbit;          /* module=: the pattern's bit in kb_mod.bits; 0 for any caller */
    __u32 pad2;
};

struct kb_cfg {
    __u32 enabled;       /* 0 while kfilterd rewrites the maps: decisions allow */
    __u32 mode;
    __u32 flags;
    __u32 generation;
    __u32 rule_count;
    __u32 glob_count;
    __u32 net_count;
    __u32 name_count;
    __u32 root_len;
    __u32 daemon_tgid;
    /* Wine installs whose wineserver protocol this layer decodes (Wine 11.0, protocol 930),
     * as loader path prefixes such as /opt/wine-stable/. Programs run by any other Wine are
     * named but not attributed: its request layout and TEB offsets differ. */
    __u32 msg_count;     /* message rules among the network rules */
    __u32 targets;       /* every target some rule names: rule-only decisions are skipped without one */
    __u32 ioctl_rules;   /* a deny or audit device rule: ioctls on any file are decided where one names it */
    __u32 memory_rules;  /* a system rule that can name /system/memory/...: executable anonymous memory is decided */
    __u32 wmi_rules;     /* a system rule that can name /system/wmi/...: wbemprox.dll's queries are probed; KB_WMI_METHOD_RULES */
    __u32 map_rules;     /* a system rule names /system/map... (its head, not a broad /system/ star): each file mapping is decided */
    __u32 self_rules;    /* a system rule names /system/wine/self...: requests on its own pseudo handles are decided */
    __u32 wine_dir_count;
    __u32 wine_dir_len[KB_WINE_DIRS];
    char wine_dirs[KB_WINE_DIRS][KB_WINE_DIR];
    __u32 name_len[KB_NAMES];
    char root[KB_PATTERN];
    /* Protect names: '/...' is a Linux executable suffix, '\...' a Windows image name. */
    char names[KB_NAMES][KB_NAME];
};

/* kb_state: counted-rule phase (1 = only the first phase open). */
struct kb_state {
    __u32 phase;
    __u32 pad;
};

/* The code of a protected Wine program's own Windows modules (not Wine's, not the prefix's
 * windows directory), by tgid: executable ranges sorted by start, each with the bits of the
 * module= patterns its file name matches. kfilterd writes it from /proc/<pid>/maps; the
 * kernel sets dirty (and sends KB_EV_MODULES) when the program maps or makes code
 * executable, and kfilterd rereads the maps. */
struct kb_mod {
    __u64 low;
    __u64 high;
    __u32 bits;
    __u32 pad;
};

struct kb_mods {
    __u32 count;
    __u32 dirty;
    struct kb_mod m[KB_MODS];
};

/* addr= rules (KFILTER_RULE_ADDRESS). An address rule's ranges (kb_ranges, by rule set and slot): module[i] is 0
 * for an absolute range, else 1 + the module pattern slot (kb_bases) its offsets start from; gen is the pattern
 * list (kb_base.gen) those slots belong to. */
#define KB_RANGES 16             /* KFILTER_MAX_ADDRESS */
#define KB_ADDRESS_RULES 1024    /* addr= rules in one policy */
struct kb_ranges {
    __u32 gen;
    __u32 count;
    __u8 module[KB_RANGES];
    __u64 lo[KB_RANGES];
    __u64 hi[KB_RANGES];         /* inclusive */
};

/* A program with a module table (kb_mods), by tgid: the image base and SizeOfImage of the lowest mapped PE file
 * (Wine's own DLLs too) each module pattern names, as kfilterd read /proc/<pid>/maps when the program's kb_modseq
 * count was Seq, for pattern list Gen. */
struct kb_base {
    __u32 seq;
    __u32 gen;
    __u32 present;               /* bit i: pattern i names a mapped module */
    __u32 pad;
    __u64 base[KB_MOD_BITS];
    __u32 size[KB_MOD_BITS];
};

/* What a decision on memory reaches (kb_accesses, task storage), written just before that decision: the process
 * (0: one kfilter cannot name) and up to KB_ACCESS ranges of its memory. kb_address_match keeps its loop state here. */
#define KB_ACCESS 8
struct kb_access {
    __u32 target;
    __u32 count;
    __u32 unknown;               /* part of it has no known address */
    __u32 slot;                  /* kb_address_match: the rule's kb_ranges key */
    __u32 current;               /* ... the target's module table is current for the rule's ranges */
    __u32 matched;               /* ... 1: a range overlaps, 2: a range is unknown */
    __u32 covered;               /* ... bit j: range j of the access lies within one of the rule's ranges */
    __u32 pad;
    __u64 lo[KB_ACCESS];
    __u64 hi[KB_ACCESS];         /* inclusive */
};

/* kb_cfg.flags beside the KFILTER_CFG_* bits: an addr= rule is loaded, so the decisions only such rules meet are made. */
#define KB_CFG_ADDRESS 0x80000000u
/* kb_decide_global's Listed above its low bits: the decision reaches memory (kb_accesses, written just before it),
 * and with ADDRESS_ONLY only addr= rules decide it (kfilter did not make such decisions before addr= existed).
 * KB_LEARNED (kb_handle_decide only): after the placeholder decision, an addr= one on the program kb_learnt names.
 * KB_NAMED_ONLY: the placeholder \@unknown, which only rules naming it decide, no wildcard rule (kfilter did not decide
 * these requests before, so rules written before it must not meet them). */
#define KB_ADDRESSED 0x10
#define KB_ADDRESS_ONLY 0x20
#define KB_LEARNED 0x40
#define KB_NAMED_ONLY 0x80
/* Decisions kfilter did not make before ABI 11 (syscalls, the hooks and rights it added), which only rules naming them
 * meet: KB_ROOT(n), rules whose path names the space past its first n bytes (a literal parent, or a wildcard whose fixed
 * head is shorter as /system/ is for /system/syscall/..., does not). New rights (lock, chdir, touch) lie outside a
 * rule's every-right default, and a pipe rule without rights= is loaded without listen. */
#define KB_ROOT(n) ((__u32)(n) << 16)
#define KB_ROOT_OF(listed) (((listed) >> 16) & 0xFF)
#define KB_MATCH_FLAGS (KB_ADDRESSED | KB_ADDRESS_ONLY | KB_NAMED_ONLY | KB_ROOT(0xFF))
/* A Wine request kfilter did not decide before every request was (/system/wine/<request>), which only rules whose fixed
 * text (kb_rule.head) reaches past /system/wine/ into its name decide: /system/wine/get_message or /system/wine/get_
 * with a star, never a star right after /system/wine/ or sooner, nor a rule on /system/wine or /system itself. */
#define KB_WINE_HEAD 13      /* strlen("/system/wine/") */
#define KB_WINE_ROOT KB_ROOT(KB_WINE_HEAD + 1)
/* ABI 11 decisions on a target of the kernel's own (logged as the public one: KfBpfPublicTarget), which kfilterd gives
 * only the rules naming them, so no other rule meets them, a value= glob included: ARGUMENT (device), an ioctl's
 * argument, for device rules whose value names one (0x<cmd>:0x<param>); SIGNAL (peer), a signal or PTRACE_MODE_READ check
 * inside the family, for peer rules whose value names one (signal:0x<signal>, ptrace:0x<mode>). */
#define KB_TARGET_ARGUMENT 0x01000000u
#define KB_TARGET_SIGNAL 0x02000000u

/* What some rule of the policy in force can name among the decisions ABI 11 added (kb_gates, a bit each): a hook makes
 * such a decision only while its bit is set, so a policy naming none of them decides as before and costs nothing more
 * (block-direct-syscall included). KfBpfApply sets a space's bit when a rule's fixed head reaches its root. */
#define KB_GATE_LOCK (1u << 0)          /* a file or dir rule names lock */
#define KB_GATE_FCNTL (1u << 1)         /* /system/fcntl */
#define KB_GATE_PEER (1u << 2)          /* a peer rule naming a signal or mode: signals, READ checks and SIGIO in the family */
#define KB_GATE_SHUTDOWN (1u << 3)      /* /system/socket/shutdown */
#define KB_GATE_SOCKETPAIR (1u << 4)    /* /system/socketpair */
#define KB_GATE_LISTEN (1u << 5)        /* a pipe rule names listen (AF_UNIX servers) */
#define KB_GATE_RLIMIT (1u << 6)        /* /system/rlimit */
#define KB_GATE_TASK (1u << 7)          /* /system/task */
#define KB_GATE_CRED (1u << 8)          /* /system/cred */
#define KB_GATE_CAPABILITY (1u << 9)    /* /system/capability */
#define KB_GATE_NAMESPACE (1u << 10)    /* /system/namespace */
#define KB_GATE_LOW (1u << 11)          /* /system/memory/low */
#define KB_GATE_IPC (1u << 12)          /* /system/ipc/create */
#define KB_GATE_FORK (1u << 13)         /* /system/fork */
#define KB_GATE_PTRACE (1u << 14)       /* /system/ptrace */
#define KB_GATE_KERNEL (1u << 15)       /* /system/kernel */
#define KB_GATE_PRCTL (1u << 16)        /* /system/prctl */
#define KB_GATE_CHDIR (1u << 17)        /* a dir rule names chdir */
#define KB_GATE_TOUCH (1u << 18)        /* a file or dir rule names touch */
#define KB_GATE_STATFS (1u << 19)       /* /system/statfs */
#define KB_GATE_NETLINK (1u << 20)      /* a device rule names /net/netlink/<family>/... beyond route and sock_diag's */
#define KB_GATE_SOCKET_IOCTL (1u << 21) /* a device rule names /net/ioctl/<code> */
#define KB_GATE_ARGUMENT (1u << 22)     /* a device rule's value names an ioctl's argument (0x<cmd>:0x<param>) */
#define KB_GATE_UNIX_MESSAGE (1u << 23) /* a message rule names unix= (ABI 12): sends on AF_UNIX sockets */
/* cfg.memory_rules beside its first bit (executable anonymous memory): a rule names /system/memory/<private|shared>/<r|rw|none>. */
#define KB_MEMORY_DATA 2u

/* What the rules of a rule set name of a syscall (kb_syscall_keys, by set << 10 | ia32 << 9 | number): any key, or up to
 * KB_SYSCALL_KEYS literal ones (the masked argument; a wait's class: 0 any, 1 child, 2 group). A call or key no rule names
 * is not decided, so a rule naming one key of a hot call costs the call's other keys nothing. */
#define KB_SYSCALL_KEYS 8
struct kb_syscall_named {
    __u32 any;
    __u32 count;
    __u32 key[KB_SYSCALL_KEYS];
};

/* A generic netlink family's name (kb_genl, by its id): kfilterd reads them from the controller. */
struct kb_genl_name {
    char name[16];   /* GENL_NAMSIZ */
};

/* Decisions kfilter did not make before K3's rules could name them, each on a target of the kernel's own (logged as the
 * public one: kfilterd's OnEvent), which kfilterd gives only the rules that name it, so no other rule meets them:
 * KEYED (system): a Wine request's keyed decision, /system/wine/<request>/<key> or /system/rpc/<interface>/<opnum>, for
 * the system rules whose fixed text (before any star) reaches into a keyed space (not a rule on the bare request);
 * PEER_VALUE, THREAD_VALUE (peer, thread-peer): what a request reaches through a handle at any offset, valued by the
 * request's name, for the peer and thread-peer rules with value=; SYSTEM_VALUE (system): a system request's masks and
 * values decided by value= alone (set_thread_info's other masks, adjust_token_privileges' privileges), for the system
 * rules with value=; WINDOW (peer): another program's window, thread or input by a pseudo-right (KFILTER_ACCESS_*), for
 * the peer rules naming one (KFILTER_RULE_PSEUDO), so a rule without rights= meets exactly the accesses it met. */
#define KB_TARGET_KEYED 0x00800000u
#define KB_TARGET_PEER_VALUE 0x00400000u
#define KB_TARGET_THREAD_VALUE 0x00200000u
#define KB_TARGET_SYSTEM_VALUE 0x00100000u
#define KB_TARGET_WINDOW 0x00080000u
/* The requests whose keyed decisions name /system/wine/<request>/<key> (kb_wine_variant). */
#define KB_KEYED_REQUESTS {KB_REQ_NEW_PROCESS, KB_REQ_READ, KB_REQ_WRITE, KB_REQ_IOCTL, KB_REQ_SEND_HARDWARE_MESSAGE, \
                           KB_REQ_GET_KEY_STATE, KB_REQ_SET_HOOK, KB_REQ_GET_CLIPBOARD_DATA, KB_REQ_SET_CURSOR, \
                           KB_REQ_UPDATE_RAWINPUT_DEVICES}

/* A window's owner (kb_windows, by the low 16 bits of its handle: wineserver's user handle index): the generation its
 * handle's high word carries, and the process that created it (KB_WINDOW_SHARED: the desktop's, no program's). */
struct kb_window {
    __u32 gen;
    __u32 tgid;
};
#define KB_WINDOW_SHARED 0xFFFFFFFFu

/* The RPC interface a named pipe handle was bound to (kb_rpcs): the first context of the last bind or alter_context
 * sent on it, its id and interface UUID. */
struct kb_rpc {
    __u8 uuid[16];
    __u32 context;
    __u32 pad;
};

/* What a task is to Wine. */
#define KB_ROLE_NONE 0
#define KB_ROLE_WINE 1        /* runs a Windows program through a Wine loader */
#define KB_ROLE_WINESERVER 2  /* the broker that serves Wine clients' requests */

/* Task storage: protection follows the task_struct, so a child is protected the moment
 * it is allocated (before it has a pid), and a thread like its process. */
struct kb_task {
    __u32 guarded;      /* 1: the task is in the protected family */
    __u32 expect_len;   /* launch handshake: the image the next exec must be */
    __u32 role;         /* KB_ROLE_* */
    __u32 pipes;        /* Wine thread: its request and reply pipes are registered */
    __u32 client;       /* wineserver: tgid of the client whose request it is serving (0: none) */
    __u32 client_tid;
    /* The process that created this one: under Wine, CreateProcess double-forks, so the new
     * program's parent is a reaper, not its creator. Inherited through the intermediate
     * fork child (forked: not exec'd since its fork). */
    __u32 creator;
    __u32 forked;
    char expect[KB_PATH];
};

/* Per-process Wine state, by tgid. */
struct kb_proc {
    __u32 guarded;       /* the process is protected (mirrors its threads' kb_task.guarded) */
    __u32 ilen;          /* image path length; 0 until Wine has named the process */
    __u32 ibase;         /* start of the file name in image */
    __u32 device_host;   /* the image is winedevice.exe: its threads serve device requests */
    __u32 tries;         /* attempts to read the image */
    __u32 checked;       /* decode has been set from the loader's install */
    __u32 decode;        /* run by a Wine whose requests this layer decodes */
    __u32 ids;           /* its init_first_thread was seen: only that reply names its ids */
    __u32 creator;       /* the Wine process that created it (new_process), 0 unknown: whose handles it inherits */
    __u32 unix_image;    /* image is a Linux program's executable (set at its exec); Wine's Windows name replaces it */
    char image[KB_PROG];
};

/* A wineserver pipe, by its inode: which client thread it belongs to. */
#define KB_PIPE_REQUEST 1
#define KB_PIPE_REPLY 2
struct kb_pipe {
    __u32 tgid;
    __u32 tid;
    __u32 kind;
    __u32 pad;
};

/* A registry key handle of a protected process, and its full NT name. */
struct kb_hkey_id {
    __u32 tgid;
    __u32 handle;
};

struct kb_hkey {
    __u32 len;
    __u32 kind;          /* in kb_hkeys: the object (KB_HKEY_*); a pending memory request's: kb_unknown_peer's flags */
    char path[KB_PATH];
};

/* What a named handle reaches: a key (0, and any other value, as a layer before kinds wrote), an NT object opened by
 * its name (a device or file, a named section), a named pipe, an object directory. */
#define KB_HKEY_KEY 0
#define KB_HKEY_FILE 1
#define KB_HKEY_PIPE 2
#define KB_HKEY_DIRECTORY 3

/* A process or thread handle of a Wine process (from open_process, open_thread,
 * get_next_process, get_next_thread, new_process, new_thread or dup_handle), by kb_hkey_id:
 * the process it reaches. */
struct kb_ohandle {
    __u32 tgid;          /* the process of the object (0: unknown) */
    __u32 thread;        /* 1: a thread handle, 0: a process handle */
    __u32 access;        /* the access it was asked with */
    __u32 pid;           /* new_process: the child's Windows pid, until its tgid is learnt */
};

/* A request waiting for wineserver's reply, by client thread id: the key an open or create
 * names, or the process or thread a handle request reaches, kept for the handle the reply
 * carries. */
struct kb_pending {
    __u32 req;
    __u32 owner;         /* handle requests: the process whose handle table gets the handle */
    struct kb_ohandle object;
    struct kb_hkey key;
};

/* A file whose open was decided for a program: reads, writes and mappings of the same open
 * within the granted rights are not decided again (rights count once per open, as on
 * Windows). Removed when the file is freed. */
struct kb_grant {
    __u32 tgid;
    __u32 rights;
    __u32 generation;
    __u32 pad;
};

/* The one-time allow-launch pass (ALLOW_LAUNCH). */
struct kb_launch {
    __u64 until_ns;      /* bpf_ktime_get_ns deadline; 0 = closed */
    __u32 left;
    __u32 creator_len;
    char creator[KB_CREATOR];
};

enum kb_kind {
    KB_EV_DECISION = 1,  /* one decision, for KfLogBpfDecision */
    KB_EV_PROTECT = 2,   /* tgid became protected (fork of a protected process, or admission) */
    KB_EV_EXIT = 3,      /* a protected process exited */
    KB_EV_MODULES = 4,   /* a program with a kb_mods entry mapped code: reread its modules */
    KB_EV_WMI = 5,       /* a protected program made wbemprox.dll's code executable and stopped (value: the
                          * thread): kfilterd puts kb_wmi on its IWbemServices methods and resumes it */
};

/* The functions kb_win32k is attached to (by uprobe cookie, KB_UP_INDEX): /system/win32k/<name>. */
struct kb_w32name {
    char name[KB_W32_NAME];
};

/* Uprobe cookies: the function's kb_w32names index, its library's machine, and (high 32 bits) what
 * a refused call returns; kb_win32k's also its space, key and right, and its Wine install's dispatcher (kb_dispatch). */
#define KB_UP_INDEX 0xFFFFu
#define KB_UP_I386 0x10000u
#define KB_UP_NTDLL 0x20000u                           /* an ntdll.so call: /system/ntdll/<function>[/<class>] */
#define KB_UP_KEYED 0x40000u                           /* a rule names its keys: /system/win32k/<function>/<key> */
#define KB_UP_KIND(cookie) (((cookie) >> 19) & 0xF)    /* KB_UP_VKEY ... KB_UP_CONTEXT, 0: no key */
#define KB_UP_LIBRARY(cookie) (((cookie) >> 23) & 7)   /* kb_dispatch's slot: 2 * the install's index + i386 */
#define KB_UP_RIGHT(cookie) (((cookie) >> 26) & 3)     /* an ntdll.so call's right: 0 query, 1 write, 2 create */
#define KB_UP_COOKIE(kind, library, right) ((__u64)(kind) << 19 | (__u64)(library) << 23 | (__u64)(right) << 26)
/* What no rule can meet, so kb_up_decide skips it (a keyed function's calls are hot: NtUserCallHwndParam each frame): the
 * function's own decision (attached for its keys alone), or its window key's @self or @desktop. */
#define KB_UP_SKIP_FUNCTION 0x10000000u
#define KB_UP_SKIP_SELF 0x20000000u
#define KB_UP_SKIP_DESKTOP 0x40000000u
/* What keys a call (KB_UP_KIND): win32u.so's past /system/win32k/<function>/ (as get_key_state's, get_clipboard_data's
 * and set_hook's keys), ntdll.so's the /<class> of /system/ntdll/<function>, or (CONTEXT) its value=. */
#define KB_UP_VKEY 1      /* a virtual key, argument 1: 0x%08x */
#define KB_UP_FORMAT 2    /* a clipboard format, argument 1: decimal */
#define KB_UP_HOOK 3      /* a hook id (WH_*), argument 4: signed decimal */
#define KB_UP_WINDOW 4    /* a window, argument 1, by its owner (kb_windows): @self, @other, @desktop or @unknown */
#define KB_UP_CLASS 5     /* an information class, argument 1: decimal */
#define KB_UP_CLASS2 6    /* ... argument 2 */
#define KB_UP_MEMORY 7    /* NtQueryVirtualMemory: its class (argument 3), on the program's own memory (argument 2) */
#define KB_UP_CONTEXT 8   /* NtGet/SetContextThread: value= its CONTEXT's ContextFlags (argument 2) */
/* The calls kb_win32k decides past a win32u.so function's own decision (a key), and the only ntdll.so ones it decides
 * (a probe costs every Wine process mapping the library a trap on each call, Wine's own ones too): X(library, function,
 * kind, right). The keyed win32u.so ones are those msmon keys by the same argument (monitor/agent/linux/bpf_up.inc). */
#define KB_UP_CALLS(X)                                                                                                    \
    X(win32u, NtUserGetAsyncKeyState, KB_UP_VKEY, 0) X(win32u, NtUserGetKeyState, KB_UP_VKEY, 0)                        \
    X(win32u, NtUserGetClipboardData, KB_UP_FORMAT, 0) X(win32u, NtUserSetWindowsHookEx, KB_UP_HOOK, 0)                 \
    X(win32u, NtUserInternalGetWindowText, KB_UP_WINDOW, 0) X(win32u, NtUserGetClassName, KB_UP_WINDOW, 0)              \
    X(win32u, NtUserGetDC, KB_UP_WINDOW, 0) X(win32u, NtUserGetWindowDC, KB_UP_WINDOW, 0)                              \
    X(win32u, NtUserPrintWindow, KB_UP_WINDOW, 0) X(win32u, NtUserCallHwndParam, KB_UP_WINDOW, 0)                      \
    X(win32u, NtUserMessageCall, KB_UP_WINDOW, 0) X(win32u, NtUserPostMessage, KB_UP_WINDOW, 0)                        \
    X(win32u, NtUserSetWindowLong, KB_UP_WINDOW, 0) X(win32u, NtUserSetWindowLongPtr, KB_UP_WINDOW, 0)                 \
    X(win32u, NtUserSetWindowPos, KB_UP_WINDOW, 0)                                                                      \
    X(ntdll, NtQuerySystemInformation, KB_UP_CLASS, 0) X(ntdll, NtQuerySystemInformationEx, KB_UP_CLASS, 0)            \
    X(ntdll, NtQueryInformationProcess, KB_UP_CLASS2, 0) X(ntdll, NtSetInformationProcess, KB_UP_CLASS2, 1)            \
    X(ntdll, NtQueryInformationThread, KB_UP_CLASS2, 0) X(ntdll, NtSetInformationThread, KB_UP_CLASS2, 1)              \
    X(ntdll, NtQueryObject, KB_UP_CLASS2, 0) X(ntdll, NtQueryVirtualMemory, KB_UP_MEMORY, 0)                           \
    X(ntdll, NtGetContextThread, KB_UP_CONTEXT, 0) X(ntdll, NtSetContextThread, KB_UP_CONTEXT, 1)                      \
    X(ntdll, NtCreateThreadEx, 0, 2) X(ntdll, NtQuerySystemEnvironmentValue, 0, 0)                                     \
    X(ntdll, NtQuerySystemEnvironmentValueEx, 0, 0) X(ntdll, NtQueryLicenseValue, 0, 0)                                \
    X(ntdll, NtSystemDebugControl, 0, 1)

/* Wine's syscall dispatcher in a decoded install's ntdll.so (kb_dispatch, by KB_UP_LIBRARY), as file offsets
 * [start, end): kb_win32k decides a call returning there, one Windows code made. 0, 0: not found. */
struct kb_dispatch {
    __u64 start;
    __u64 end;
};

/* kb_wmi's methods (uprobe cookie, KB_UP_INDEX), each the IWbemServices vtable entry Wine's
 * wbem_services_vtbl has: ExecQuery and ExecQueryAsync take WQL as their third argument, GetObject
 * and CreateInstanceEnum an object path or class as their second (Wine queries "SELECT * FROM <class>"),
 * ExecMethod an object path second and the method's name third (/system/wmi/<class>/<method>).
 * GetObjectAsync, CreateInstanceEnumAsync and ExecMethodAsync are stubs that fail in Wine 11, so they are not probed. */
#define KB_WMI_EXEC_QUERY 0             /* entry 20 */
#define KB_WMI_EXEC_QUERY_ASYNC 1       /* entry 21 */
#define KB_WMI_GET_OBJECT 2             /* entry 6 */
#define KB_WMI_CREATE_INSTANCE_ENUM 3   /* entry 18 */
#define KB_WMI_EXEC_METHOD 4            /* entry 24 */
#define KB_WMI_METHOD_RULES 2           /* kb_cfg.wmi_rules: a rule reaches past /system/wmi/<class>/: methods are decided */
#define KB_WMI_METHODS 5

struct kb_event {
    __u32 kind;
    __u32 tgid;
    __u32 target;
    __u32 action;
    __u32 flags;
    __s32 status;
    __u32 value;
    __u32 rule_id;
    __u32 rights;
    __u32 ppid;
    char path[KB_PATH];
    char image[KB_IMAGE];   /* file name of the requesting program, "" when unknown */
    /* Message decisions (KFILTER_EVENT_FLAG_MESSAGE): the byte count, the message's number
     * on its connection, the socket inode and the peer port; path holds the peer address
     * (16 bytes) then the first KB_MSG_SHOWN bytes of a send. */
    __u32 size;
    __u32 index;
    __u64 inode;
    __u32 port;
    __u32 shown;
    __u64 caller;        /* message: the return address into the calling module, 0 when unknown */
};

#define KB_MSG_SHOWN 64      /* bytes of a send carried in its decision event */
#define KB_MSG_BYTES 4096    /* bytes of a send that match= can look at */
#define KB_MSG_NAME 128      /* a unix message's event: where in path the peer's name starts */
/* A message rule's unix= pattern (KFILTER_NET_FAMILY_UNIX), beside kb_net in kb_unix_names by set * KB_NET + its slot:
 * kb_net's pinned layout has no room for it. */
struct kb_unix_name {
    __u32 len;
    __u32 pad;
    char path[KB_VALUE];
};

#ifdef KB_TEST_BENCH
/* kb_bench_decide's context (filter/tests/linux_bpf_bench.cpp): one request, decided by the code a hook runs. */
struct kb_bench {
    __u32 target;        /* KFILTER_TARGET_* */
    __u32 rights;
    __u32 value;         /* device and volume: the ioctl or class (a device's value text is made from it) */
    __u32 listed;        /* kb_decide_global's Listed; system decisions go through kb_system_decide */
    __u32 len;           /* bytes of path */
    __u32 ilen;          /* bytes of image; 0: a program Wine has not named */
    __u32 vlen;          /* bytes of value_text */
    __u32 decided;       /* out: 0 when the hook would pass the request undecided */
    __s32 verdict;       /* out: 0, -EPERM or -ENOENT */
    __u32 ibase;         /* out: where the image's file name starts */
    char path[KB_PATH];
    char image[KB_PROG]; /* the program's image as Wine names it (C:\...\x.exe) or a Linux executable's path */
    char value_text[KB_VALUE];
    /* listed with KB_ADDRESSED: what the decision reaches (kb_accesses). */
    struct kb_access access;
    /* wine 1: instead of path, value and listed, a Wine request (header, and its data chunks as the writev's iovecs at
     * iov: count of them with the header's first, the bench's own memory) decided as kb_file_permission decides one:
     * the chunks joined (kb_request_data), kb_wine_query, then kb_handle_decide or the system decision; 2: wineserver's
     * reply (at data) to this thread's pending request, as kb_wineserver_pipe reads it; 3: what kb_wine_request and
     * the code mapping hooks run for this program's module table: request[0] a request it sent, 0 code it made
     * executable; 4: as 1, the bookkeeping and decoders after its own decision instead: a pending handle (object_maker),
     * winedevice's kernel objects (kb_kernel_object), registry and NT object requests (kb_registry, kb_nt_object); 5: as
     * 1 (with object_maker's pending handle), then, its own decision not refused, the second pass's bookkeeping
     * (kb_wine_note) and decisions on what it reaches (kb_handle_request, kb_wine_decide); 9 (kb_bench_pipe): the write
     * itself, as the request pipe's hook decides it, through kb_wine_request on a pipe registered as this thread's and
     * kb_file_permission's dispatch (wine_write, then kb_wine_decide): count 1 is a write of the header at iov,
     * else a writev of count iovecs at iov, ia32's 8-byte ones when compat;
     * 6 (kb_bench_syscall): a syscall, as its entry point's program decides it: request[0] its number,
     * [1] 1 for ia32, [2..13] its six arguments, low then high word; 7 (kb_bench_helper): one of ABI 11's decision
     * functions, request[0] which, the rest its arguments; 8 (kb_bench_net): a network decision as its hook makes it,
     * request[15] out the ns it took. */
    __u32 wine;
    __u32 count;
    __u64 data;
    __u64 iov;
    __u32 request[16];
    __u32 compat;
};

/* kb_bench_pipe's write, which kb_wine_request takes in place of the task's syscall registers. */
struct kb_bench_io {
    __u64 buffer;        /* the writev's iovecs, or the write's header */
    __u64 count;         /* iovecs, or the write's 64 bytes */
    __u32 vector;        /* a writev */
    __u32 compat;        /* ia32 iovecs */
    __u32 active;
    __u32 pad;
};
#endif

/* Hashes of a literal rule path; the kernel computes them incrementally over the path. */
static inline __u64 kb_fnv_step(__u64 hash, unsigned char c) { return (hash ^ c) * 1099511628211ull; }
static inline __u32 kb_djb_step(__u32 hash, unsigned char c) { return hash * 33u + c; }
#define KB_FNV_INIT 14695981039346656037ull
#define KB_DJB_INIT 5381u

/* Wine 11.0 (server protocol 930): request numbers and layouts (server_protocol.h). */
#define KB_WINE_PROTOCOL 930
#define KB_REQ_NEW_PROCESS 0
#define KB_REQ_NEW_THREAD 2
#define KB_REQ_INIT_FIRST_THREAD 5
#define KB_REQ_INIT_THREAD 6
#define KB_REQ_TERMINATE_PROCESS 7
#define KB_REQ_TERMINATE_THREAD 8
#define KB_REQ_GET_PROCESS_INFO 9
#define KB_REQ_GET_PROCESS_DEBUG_INFO 10
#define KB_REQ_GET_PROCESS_IMAGE_NAME 11
#define KB_REQ_GET_PROCESS_VM_COUNTERS 12
#define KB_REQ_SET_PROCESS_INFO 13
#define KB_REQ_GET_THREAD_INFO 14
#define KB_REQ_GET_THREAD_TIMES 15
#define KB_REQ_SET_THREAD_INFO 16
#define KB_REQ_SUSPEND_THREAD 17
#define KB_REQ_RESUME_THREAD 18
#define KB_REQ_QUEUE_APC 19
#define KB_REQ_CLOSE_HANDLE 21
#define KB_REQ_DUP_HANDLE 23
#define KB_REQ_OPEN_PROCESS 27
#define KB_REQ_OPEN_THREAD 28
#define KB_REQ_CREATE_EVENT 30
#define KB_REQ_OPEN_EVENT 33
#define KB_REQ_CREATE_MUTEX 36
#define KB_REQ_OPEN_MUTEX 38
#define KB_REQ_CREATE_SEMAPHORE 40
#define KB_REQ_OPEN_SEMAPHORE 43
#define KB_REQ_CREATE_FILE 44
#define KB_REQ_OPEN_FILE_OBJECT 45
#define KB_REQ_GET_VOLUME_INFO 52
#define KB_REQ_CREATE_MAPPING 63
#define KB_REQ_OPEN_MAPPING 64
#define KB_REQ_MAP_IMAGE_VIEW 68
#define KB_REQ_MAP_BUILTIN_VIEW 69
#define KB_REQ_GET_IMAGE_VIEW_INFO 70
#define KB_REQ_GET_MAPPING_FILENAME 75
#define KB_REQ_LIST_PROCESSES 76
#define KB_REQ_DEBUG_PROCESS 82
#define KB_REQ_READ_PROCESS_MEMORY 84
#define KB_REQ_WRITE_PROCESS_MEMORY 85
#define KB_REQ_CREATE_KEY 86
#define KB_REQ_OPEN_KEY 87
#define KB_REQ_DELETE_KEY 88
#define KB_REQ_FLUSH_KEY 89
#define KB_REQ_ENUM_KEY 90
#define KB_REQ_SET_KEY_VALUE 91
#define KB_REQ_GET_KEY_VALUE 92
#define KB_REQ_ENUM_KEY_VALUE 93
#define KB_REQ_DELETE_KEY_VALUE 94
#define KB_REQ_LOAD_REGISTRY 95
#define KB_REQ_UNLOAD_REGISTRY 96
#define KB_REQ_SAVE_REGISTRY 97
#define KB_REQ_SET_REGISTRY_NOTIFICATION 98
#define KB_REQ_RENAME_KEY 99
#define KB_REQ_GET_THREAD_CONTEXT 105
#define KB_REQ_SET_THREAD_CONTEXT 106
#define KB_REQ_GET_PROCESS_IDLE_EVENT 118
#define KB_REQ_SEND_MESSAGE 119
#define KB_REQ_SEND_HARDWARE_MESSAGE 121
#define KB_REQ_CANCEL_SYNC 131
#define KB_REQ_READ 136
#define KB_REQ_WRITE 137
#define KB_REQ_IOCTL 138
#define KB_REQ_CREATE_NAMED_PIPE 140
#define KB_REQ_CREATE_WINDOW 142
#define KB_REQ_GET_DESKTOP_WINDOW 144
#define KB_REQ_GET_WINDOW_LIST 151
#define KB_REQ_GET_WINDOW_TREE 154
#define KB_REQ_GET_WINDOW_TEXT 157
#define KB_REQ_OPEN_WINSTATION 171
#define KB_REQ_OPEN_DESKTOP 178
#define KB_REQ_REGISTER_HOTKEY 185
#define KB_REQ_GET_KEY_STATE 190
#define KB_REQ_SET_HOOK 198
#define KB_REQ_GET_CLIPBOARD_DATA 211
#define KB_REQ_OPEN_TOKEN 220
#define KB_REQ_ADJUST_TOKEN_PRIVILEGES 222
#define KB_REQ_SET_SECURITY_OBJECT 232
#define KB_REQ_GET_SECURITY_OBJECT 233
#define KB_REQ_GET_SYSTEM_HANDLES 234
#define KB_REQ_GET_TCP_CONNECTIONS 235
#define KB_REQ_GET_UDP_ENDPOINTS 236
#define KB_REQ_CREATE_DIRECTORY 239
#define KB_REQ_OPEN_DIRECTORY 240
#define KB_REQ_GET_DIRECTORY_ENTRIES 241
#define KB_REQ_CREATE_SYMLINK 242
#define KB_REQ_OPEN_SYMLINK 243
#define KB_REQ_QUERY_SYMLINK 244
#define KB_REQ_GET_NEXT_DEVICE_REQUEST 253
#define KB_REQ_SET_KERNEL_OBJECT_PTR 255
#define KB_REQ_GET_KERNEL_OBJECT_HANDLE 258
#define KB_REQ_MAKE_PROCESS_SYSTEM 259
#define KB_REQ_GRANT_PROCESS_ADMIN_TOKEN 260
#define KB_REQ_SET_CURSOR 279
#define KB_REQ_UPDATE_RAWINPUT_DEVICES 282
#define KB_REQ_ASSIGN_JOB 285
#define KB_REQ_PROCESS_IN_JOB 286
#define KB_REQ_SUSPEND_PROCESS 291
#define KB_REQ_RESUME_PROCESS 292
#define KB_REQ_GET_NEXT_PROCESS 293
#define KB_REQ_GET_NEXT_THREAD 294
#define KB_REQ_COUNT 306
#define KB_WNAMED_WORDS ((KB_REQ_COUNT + 63) / 64)   /* kb_wnamed: one bit per request */

/* Every request of protocol 930 by number (wineserver's req_names): X(name, right), the right of its decision as
 * /system/wine/<name> where no row of its own says otherwise: Q (query) to read or open, C (create), W (write). */
#define KB_WINE_REQUESTS(X) \
    X(new_process, W) X(get_new_process_info, Q) X(new_thread, W) X(get_startup_info, Q) X(init_process_done, W) \
    X(init_first_thread, W) X(init_thread, W) X(terminate_process, W) X(terminate_thread, W) X(get_process_info, Q) \
    X(get_process_debug_info, Q) X(get_process_image_name, Q) X(get_process_vm_counters, Q) X(set_process_info, W) \
    X(get_thread_info, Q) X(get_thread_times, Q) X(set_thread_info, W) X(suspend_thread, W) X(resume_thread, W) \
    X(queue_apc, W) X(get_apc_result, Q) X(close_handle, W) X(set_handle_info, W) X(dup_handle, W) \
    X(allocate_reserve_object, W) X(compare_objects, Q) X(set_object_permanence, W) X(open_process, Q) \
    X(open_thread, Q) X(select, W) X(create_event, C) X(event_op, W) X(query_event, Q) X(open_event, Q) \
    X(create_keyed_event, C) X(open_keyed_event, Q) X(create_mutex, C) X(release_mutex, W) X(open_mutex, Q) \
    X(query_mutex, Q) X(create_semaphore, C) X(release_semaphore, W) X(query_semaphore, Q) X(open_semaphore, Q) \
    X(create_file, C) X(open_file_object, Q) X(alloc_file_handle, W) X(get_handle_unix_name, Q) X(get_handle_fd, Q) \
    X(get_directory_cache_entry, Q) X(flush, W) X(get_file_info, Q) X(get_volume_info, Q) X(lock_file, W) \
    X(unlock_file, W) X(recv_socket, W) X(send_socket, W) X(socket_get_events, W) X(socket_send_icmp_id, W) \
    X(socket_get_icmp_id, W) X(get_next_console_request, Q) X(read_directory_changes, W) X(read_change, W) \
    X(create_mapping, C) X(open_mapping, Q) X(get_mapping_info, Q) X(get_image_map_address, Q) X(map_view, W) \
    X(map_image_view, W) X(map_builtin_view, W) X(get_image_view_info, Q) X(unmap_view, W) \
    X(get_mapping_committed_range, Q) X(add_mapping_committed_range, W) X(is_same_mapping, Q) \
    X(get_mapping_filename, Q) X(list_processes, Q) X(create_debug_obj, C) X(wait_debug_event, W) \
    X(queue_exception_event, W) X(get_exception_status, Q) X(continue_debug_event, W) X(debug_process, W) \
    X(set_debug_obj_info, W) X(read_process_memory, W) X(write_process_memory, W) X(create_key, C) X(open_key, Q) \
    X(delete_key, W) X(flush_key, W) X(enum_key, Q) X(set_key_value, W) X(get_key_value, Q) X(enum_key_value, Q) \
    X(delete_key_value, W) X(load_registry, W) X(unload_registry, W) X(save_registry, W) \
    X(set_registry_notification, W) X(rename_key, W) X(create_timer, C) X(open_timer, Q) X(set_timer, W) \
    X(cancel_timer, W) X(get_timer_info, Q) X(get_thread_context, Q) X(set_thread_context, W) X(add_atom, W) \
    X(delete_atom, W) X(find_atom, Q) X(get_atom_information, Q) X(add_user_atom, W) X(get_user_atom_name, Q) \
    X(get_msg_queue_handle, Q) X(get_msg_queue, Q) X(set_queue_fd, W) X(set_queue_mask, W) X(get_queue_status, Q) \
    X(get_process_idle_event, Q) X(send_message, W) X(post_quit_message, W) X(send_hardware_message, W) \
    X(get_message, Q) X(reply_message, W) X(accept_hardware_message, W) X(get_message_reply, Q) X(set_win_timer, W) \
    X(kill_win_timer, W) X(is_window_hung, Q) X(get_serial_info, Q) X(set_serial_info, W) X(cancel_sync, W) \
    X(register_async, W) X(cancel_async, W) X(get_async_result, Q) X(set_async_direct_result, W) X(read, W) \
    X(write, W) X(ioctl, W) X(set_irp_result, W) X(create_named_pipe, C) X(set_named_pipe_info, W) \
    X(create_window, C) X(destroy_window, W) X(get_desktop_window, Q) X(set_window_owner, W) X(get_window_info, Q) \
    X(init_window_info, W) X(set_window_info, W) X(set_parent, W) X(get_window_parents, Q) X(get_window_list, Q) \
    X(get_class_windows, Q) X(get_window_children_from_point, Q) X(get_window_tree, Q) X(set_window_pos, W) \
    X(get_window_rectangles, Q) X(get_window_text, Q) X(set_window_text, W) X(get_windows_offset, Q) \
    X(get_visible_region, Q) X(get_window_region, Q) X(set_window_region, W) X(get_update_region, Q) \
    X(update_window_zorder, W) X(redraw_window, W) X(set_window_property, W) X(remove_window_property, W) \
    X(get_window_property, Q) X(get_window_properties, Q) X(create_winstation, C) X(open_winstation, Q) \
    X(close_winstation, W) X(set_winstation_monitors, W) X(get_process_winstation, Q) X(set_process_winstation, W) \
    X(enum_winstation, Q) X(create_desktop, C) X(open_desktop, Q) X(open_input_desktop, Q) X(set_input_desktop, W) \
    X(close_desktop, W) X(get_thread_desktop, Q) X(set_thread_desktop, W) X(set_user_object_info, W) \
    X(register_hotkey, W) X(unregister_hotkey, W) X(attach_thread_input, W) X(get_thread_input, Q) \
    X(get_last_input_time, Q) X(get_key_state, Q) X(set_key_state, W) X(set_foreground_window, W) \
    X(set_focus_window, W) X(set_active_window, W) X(set_capture_window, W) X(set_caret_window, W) \
    X(set_caret_info, W) X(set_hook, W) X(remove_hook, W) X(start_hook_chain, W) X(finish_hook_chain, W) \
    X(get_hook_info, Q) X(create_class, C) X(destroy_class, W) X(set_class_info, W) X(get_class_info, Q) \
    X(open_clipboard, Q) X(close_clipboard, W) X(empty_clipboard, W) X(set_clipboard_data, W) \
    X(get_clipboard_data, Q) X(get_clipboard_formats, Q) X(enum_clipboard_formats, Q) X(release_clipboard, W) \
    X(get_clipboard_info, Q) X(set_clipboard_viewer, W) X(add_clipboard_listener, W) \
    X(remove_clipboard_listener, W) X(create_token, C) X(open_token, Q) X(set_desktop_shell_windows, W) \
    X(adjust_token_privileges, W) X(get_token_privileges, Q) X(check_token_privileges, Q) X(duplicate_token, W) \
    X(filter_token, W) X(access_check, W) X(get_token_sid, Q) X(get_token_groups, Q) X(get_token_default_dacl, Q) \
    X(set_token_default_dacl, W) X(set_security_object, W) X(get_security_object, Q) X(get_system_handles, Q) \
    X(get_tcp_connections, Q) X(get_udp_endpoints, Q) X(create_mailslot, C) X(set_mailslot_info, W) \
    X(create_directory, C) X(open_directory, Q) X(get_directory_entries, Q) X(create_symlink, C) X(open_symlink, Q) \
    X(query_symlink, Q) X(get_object_info, Q) X(get_object_name, Q) X(get_object_type, Q) X(get_object_types, Q) \
    X(allocate_locally_unique_id, W) X(create_device_manager, C) X(create_device, C) X(delete_device, W) \
    X(get_next_device_request, Q) X(get_kernel_object_ptr, Q) X(set_kernel_object_ptr, W) X(grab_kernel_object, W) \
    X(release_kernel_object, W) X(get_kernel_object_handle, Q) X(make_process_system, W) \
    X(grant_process_admin_token, W) X(get_token_info, Q) X(create_linked_token, C) X(create_completion, C) \
    X(open_completion, Q) X(add_completion, W) X(remove_completion, W) X(get_thread_completion, Q) \
    X(query_completion, Q) X(set_completion_info, W) X(add_fd_completion, W) X(set_fd_completion_mode, W) \
    X(set_fd_disp_info, W) X(set_fd_name_info, W) X(set_fd_eof_info, W) X(get_window_layered_info, Q) \
    X(set_window_layered_info, W) X(alloc_user_handle, W) X(free_user_handle, W) X(set_cursor, W) \
    X(get_cursor_history, Q) X(get_rawinput_buffer, Q) X(update_rawinput_devices, W) X(create_job, C) \
    X(open_job, Q) X(assign_job, W) X(process_in_job, W) X(set_job_limits, W) X(set_job_completion_port, W) \
    X(get_job_info, Q) X(terminate_job, W) X(suspend_process, W) X(resume_process, W) X(get_next_process, Q) \
    X(get_next_thread, Q) X(set_keyboard_repeat, W) X(get_inproc_sync_fd, Q) X(get_inproc_alert_fd, Q) \
    X(d3dkmt_object_create, W) X(d3dkmt_object_update, W) X(d3dkmt_object_query, W) X(d3dkmt_object_open, W) \
    X(d3dkmt_share_objects, W) X(d3dkmt_object_open_name, W) X(d3dkmt_mutex_acquire, W) X(d3dkmt_mutex_release, W)
