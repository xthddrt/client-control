#pragma once

/*
 * Shared ABI between kfilter.sys and kfilterctl.exe. Keep this file free of OS
 * headers and compiler-specific types; both user and kernel builds include it.
 *
 * ABI 6:
 *   - independent operation rights, including process/network/raw-device rights
 *   - typed targets and registry value matching
 *   - immutable policy generations + stable rule IDs
 *   - bounded network rules and an optional AppContainer package identity
 *   - risk reasons on rules and adapter filtering
 *   - Image: rules and network rules can name the program they apply to, and every event
 *     names the program that made the request (under Wine: the Windows image, not the loader)
 *   - counted deny and audit rules (uses=N: block the first N requests, then step aside)
 * ABI 7:
 *   - message rules: network rules with send/receive rights decide each message a program
 *     sends or receives on an allowed connection (size, position, bytes); Linux BPF layer
 * ABI 9 (Linux BPF layer):
 *   - rule-only targets PEER, THREAD_PEER, SYSTEM, DNS and THREAD (KFILTER_TARGETS_RULE_ONLY)
 *   - QUERY is a file, dir and pipe right (metadata without an open; block-file-queries decides
 *     it on Linux, Windows decides attributes-only creates as QUERY); HIDE and MODULE rule flags
 *   - DIRECT events (and block-direct-syscall); QUERY, SYSTEM and THREAD degraded classes
 * ABI 10 (Linux BPF layer):
 *   - addr= on peer, thread-peer and system rules (ADDRESS flag): up to 16 memory ranges per rule in
 *     KFILTER_RULE.Address, absolute or relative to a module of the target program named in Value
 * ABI 11 (Linux BPF layer):
 *   - peer pseudo-rights (KFILTER_ACCESS_*: another program's windows and input), met only by rules naming them
 *     (KFILTER_RULE_PSEUDO)
 *   - value= on peer and thread-peer rules (a message, offset or key as 0x%08X; a Wine request's name)
 *   - file and dir rights LOCK (file_lock), CHDIR (chdir, fchdir) and TOUCH (utimensat with no time), outside a
 *     rule's every-right default; switches BLOCK_PROCESS_SIGNALS and BLOCK_PROCESS_QUERIES (signals and PTRACE_MODE_READ
 *     checks across the family's boundary)
 * ABI 12 (Linux BPF layer):
 *   - message rules on AF_UNIX peers: KFILTER_NET_RULE.Unix (unix=, Family KFILTER_NET_FAMILY_UNIX), sends only
 */

/* Fixed-width field types: ULONG is 32 bits on Windows (LLP64) but `unsigned long` is
 * 64 bits on Linux (LP64), and the Linux daemon and tools must agree on one layout. */
#if defined(_MSC_VER)
typedef unsigned long KF_ULONG;
typedef long KF_LONG;
typedef unsigned __int64 KF_UINT64;
#elif defined(__bpf__)
/* linux/bpf/kfilter.bpf.c uses only the constants; vmlinux.h supplies the types. */
typedef __u32 KF_ULONG;
typedef __s32 KF_LONG;
typedef __u64 KF_UINT64;
#else
#include <stddef.h> /* wchar_t in C */
#include <stdint.h>
typedef uint32_t KF_ULONG;
typedef int32_t KF_LONG;
typedef uint64_t KF_UINT64;
#endif

#define KFILTER_DEVICE_NAME L"\\Device\\KFilter"
#define KFILTER_DOS_NAME L"\\DosDevices\\KFilter"
#define KFILTER_USER_PATH "\\\\.\\KFilter"

#define KFILTER_ABI_VERSION 12u
#define KFILTER_MAX_NAME 512u
#define KFILTER_MAX_VALUE 128u
#define KFILTER_MAX_RISK 64u
#define KFILTER_MAX_IMAGE 64u   /* image= pattern on a rule; the program's name on an event */
#define KFILTER_MAX_RULES 16384u  /* a strict policy has one counted rule per object */
#define KFILTER_MAX_NET_RULES 256u
#define KFILTER_MAX_PROTECTED 16u
#define KFILTER_MAX_SID 68u
#if defined(_MSC_VER)
#define KFILTER_RING_CAPACITY 8192u   /* nonpaged pool in the Windows driver */
#else
/* kfilterd's ring (heap, ~2.3 KB an event): 8,192 dropped 3,509 decisions of a full run while msmon wrote its own
 * burst (trial 339); 65,536 (~150 MB) holds most of what the BPF ring (64 MiB, ~100,000) can hand over at once. */
#define KFILTER_RING_CAPACITY 65536u
#endif

/* Rule actions. Audit means "allow, but record"; RISK is an additional use record. */
typedef enum _KFILTER_ACTION {
    KFilterActionAudit = 1,
    KFilterActionAllow = 2,
    KFilterActionDeny = 3,
    KFilterActionRisk = 4
} KFILTER_ACTION;

/* Enforcement modes. */
#define KFILTER_MODE_OFF 0u
#define KFILTER_MODE_AUDIT 1u
#define KFILTER_MODE_BLOCK 2u

/* What a rule applies to. */
#define KFILTER_TARGET_FILE 0x00000001u
#define KFILTER_TARGET_DIR 0x00000002u
#define KFILTER_TARGET_REGISTRY 0x00000004u
#define KFILTER_TARGET_PROCESS 0x00000008u
#define KFILTER_TARGET_VOLUME 0x00000010u
#define KFILTER_TARGET_DEVICE 0x00000020u
#define KFILTER_TARGET_PIPE 0x00000040u
#define KFILTER_TARGET_NETWORK 0x00000080u
/* Exceptions to the built-in process blocks, matched on the image path of the
 * outside process. HANDLE: a process that receives a handle to a protected
 * process keeps the listed process access rights (PROCESS_VM_READ etc.); every
 * other right is stripped. LAUNCH: a process that starts a protected image on
 * behalf of its parent, the armed launcher, may use the launch pass. */
#define KFILTER_TARGET_HANDLE 0x00000100u
#define KFILTER_TARGET_LAUNCH 0x00000200u
/* OPEN: the reverse of HANDLE. The protected client, opening (or receiving) a
 * handle to the outside process, keeps the listed process access rights; every
 * other right is stripped. */
#define KFILTER_TARGET_OPEN 0x00000400u
/* The same two exceptions for thread handles; the rights are THREAD_* access bits. */
#define KFILTER_TARGET_THREAD_HANDLE 0x00000800u
#define KFILTER_TARGET_THREAD_OPEN 0x00001000u
#define KFILTER_TARGETS_OUTSIDE (KFILTER_TARGET_HANDLE | KFILTER_TARGET_LAUNCH | KFILTER_TARGET_OPEN |                                  KFILTER_TARGET_THREAD_HANDLE | KFILTER_TARGET_THREAD_OPEN)
/* Linux only (kfilterd's BPF layer). PEER/THREAD_PEER: a process or thread handle (rights are
 * access masks) one protected program takes on another of its family; Path names the target
 * program as HANDLE rules do. SYSTEM: a query of the system itself, named /system/<what>
 * (e.g. /system/uname). DNS: a name the program looks up (Path is the name, no '/'). THREAD:
 * a thread the program creates (Path names the program it runs in; rights create). */
#define KFILTER_TARGET_PEER 0x00002000u
#define KFILTER_TARGET_THREAD_PEER 0x00004000u
#define KFILTER_TARGET_SYSTEM 0x00008000u
#define KFILTER_TARGET_DNS 0x00010000u
#define KFILTER_TARGET_THREAD 0x00020000u
/* Decided only where a rule names them: with no matching rule the request is allowed and
 * logged nowhere, even under DEFAULT_DENY (a policy that never names them is unaffected);
 * only a spent counted allow (uses=N) refuses it.
 * Files named /anon/... (memfd, SysV shm, shared-anonymous memory) are decided the same way. */
#define KFILTER_TARGETS_RULE_ONLY (KFILTER_TARGET_PEER | KFILTER_TARGET_THREAD_PEER | KFILTER_TARGET_SYSTEM | \
                                   KFILTER_TARGET_DNS | KFILTER_TARGET_THREAD)
/* PEER pseudo-rights (ABI 11): reading, changing or sending messages to another program's windows (its window, or the
 * thread a message goes to), and its input (hotkeys, attached input, the input state of its threads). The generic
 * rights' bits, which no process or thread access decision carries (they are mapped before it is made). A rule meets
 * these decisions only when kfilterctl read their names (KFILTER_RULE_PSEUDO): never one without rights= or a mask. */
#define KFILTER_ACCESS_INPUT 0x10000000u
#define KFILTER_ACCESS_WINDOW_QUERY 0x20000000u
#define KFILTER_ACCESS_WINDOW_SET 0x40000000u
#define KFILTER_ACCESS_WINDOW_MESSAGE 0x80000000u
#define KFILTER_ACCESS_PSEUDO (KFILTER_ACCESS_INPUT | KFILTER_ACCESS_WINDOW_QUERY | KFILTER_ACCESS_WINDOW_SET | \
                               KFILTER_ACCESS_WINDOW_MESSAGE)

/*
 * KFILTER_RULE.Count / KFILTER_NET_RULE.Count: 0 for a standing rule; otherwise a counted
 * relaxation that allows USES requests per Play (in any order), only once its PHASE is
 * open. Phase 1 is open from the start; a rule marked OPENS opens the phase after its own
 * on its first use. Arming the launch pass (or loading a policy) restores every count and
 * closes every phase but the first. On a deny or audit rule the count limits how often the
 * rule applies: `deny ... uses=1` refuses the first matching request, after which the rule
 * steps aside and the rules below it decide.
 */
#define KFILTER_COUNT_PHASE 0x0000FFFFu
#define KFILTER_COUNT_USES 0x7FFF0000u
#define KFILTER_COUNT_USES_SHIFT 16
#define KFILTER_COUNT_OPENS 0x80000000u

/* Rule account: which account the outside process must run as (HANDLE/LAUNCH). */
#define KFILTER_ACCOUNT_ANY 0u
#define KFILTER_ACCOUNT_SYSTEM 1u

/* Independent operation rights. A create is allowed only when every requested
 * right is authorized. `execute` does not imply `read`. */
#define KFILTER_RIGHT_READ 0x00000001u
#define KFILTER_RIGHT_WRITE 0x00000002u
#define KFILTER_RIGHT_EXECUTE 0x00000004u
#define KFILTER_RIGHT_DELETE 0x00000008u
#define KFILTER_RIGHT_RENAME 0x00000010u
#define KFILTER_RIGHT_SET_SECURITY 0x00000020u
#define KFILTER_RIGHT_ENUMERATE 0x00000040u
/* Volume identity queries; on Linux also file, dir and pipe metadata without an open (stat,
 * access, readlink, xattr reads), SYSTEM queries and DNS lookups. */
#define KFILTER_RIGHT_QUERY 0x00000080u
#define KFILTER_RIGHT_CREATE 0x00000100u
#define KFILTER_RIGHT_CONNECT 0x00000200u
#define KFILTER_RIGHT_LISTEN 0x00000400u
#define KFILTER_RIGHT_RAW_DEVICE 0x00000800u
/* A request that asks for none of the rights above (an attributes-only or
 * synchronize-only open); an allow rule must name it explicitly. */
#define KFILTER_RIGHT_OPEN 0x00001000u
#define KFILTER_RIGHTS_ALL 0x00001FFFu
/* Network rules only: each message sent or received on a connection (message rules). */
#define KFILTER_RIGHT_SEND 0x00002000u
#define KFILTER_RIGHT_RECEIVE 0x00004000u
#define KFILTER_RIGHTS_MESSAGE (KFILTER_RIGHT_SEND | KFILTER_RIGHT_RECEIVE)
/* Linux file and dir rules only, decided where a rule names them (a rule without rights= covers KFILTER_RIGHTS_ALL,
 * not these): a byte-range or whole-file lock, making a directory the current one, setting a file's times to now. */
#define KFILTER_RIGHT_LOCK 0x00008000u
#define KFILTER_RIGHT_CHDIR 0x00010000u
#define KFILTER_RIGHT_TOUCH 0x00020000u
#define KFILTER_RIGHTS_FILE_NAMED (KFILTER_RIGHT_LOCK | KFILTER_RIGHT_CHDIR | KFILTER_RIGHT_TOUCH)
#define KFILTER_MAX_MATCH 16u

/* Rule flags (reserved for future use; parser accepts the legacy names and
 * converts them to rights). */
#define KFILTER_RULE_DATA_ONLY 0x00000001u
#define KFILTER_RULE_EXECUTE_ONLY 0x00000002u
/* KFILTER_RULE.Flags: the rule matches its path only, not the objects below it. */
#define KFILTER_RULE_EXACT 0x00000004u
/* Linux: a refusal by this deny rule fails with ENOENT (the object seems not to exist), not EPERM. */
#define KFILTER_RULE_HIDE 0x00000008u
/* Value is a module= glob (the Windows module whose code made the request), not a value name;
 * never on registry or device rules. */
#define KFILTER_RULE_MODULE 0x00000010u
/* Linux: addr= (peer, thread-peer and system rules): the rule meets only a decision on memory that overlaps one of
 * Address[0..AddressCount) (an allow: that lies within them); Value lists the module patterns those ranges name. */
#define KFILTER_RULE_ADDRESS 0x00000020u
/* Linux (ABI 11): a peer rule whose rights= names pseudo-rights (KFILTER_ACCESS_*): it meets window, thread and input
 * decisions, by those rights alone. */
#define KFILTER_RULE_PSEUDO 0x00000040u
#define KFILTER_MAX_ADDRESS 16u

typedef struct _KFILTER_ADDRESS_RANGE {
    KF_UINT64 Low;    /* inclusive; from the module's image base when the range names a module */
    KF_UINT64 High;   /* inclusive */
} KFILTER_ADDRESS_RANGE;

/* Config flags. DEFAULT_DENY is the strict mode: nothing without a rule, no built-in
 * allowance (child processes from the root, non-identity volume queries), and outside
 * processes opening the client lose every access right a HANDLE rule does not grant. */
#define KFILTER_CFG_BLOCK_FILES 0x00000001u
#define KFILTER_CFG_BLOCK_REGISTRY 0x00000002u
#define KFILTER_CFG_BLOCK_VOLUME_SERIAL 0x00000004u
#define KFILTER_CFG_BLOCK_PROCESS_MEMORY 0x00000008u
#define KFILTER_CFG_BLOCK_PROCESS_CREATE 0x00000010u
#define KFILTER_CFG_BLOCK_RAW_DISK 0x00000020u
#define KFILTER_CFG_BLOCK_NETWORK 0x00000040u
#define KFILTER_CFG_DEFAULT_DENY 0x00000080u
#define KFILTER_CFG_NET_DEFAULT_ALLOW 0x00000100u
#define KFILTER_CFG_NET_ALLOW_LOOPBACK 0x00000200u
#define KFILTER_CFG_BLOCK_NETWORK_ADAPTER 0x00000400u
/* A message no message rule decides is denied (default: allowed). */
#define KFILTER_CFG_MESSAGE_DEFAULT_DENY 0x00000800u
/* Linux: metadata without an open (stat, access, readlink, xattr reads) is decided as QUERY on
 * files, dirs and pipes, and change watches as enumerate (dirs) or read (files). */
#define KFILTER_CFG_BLOCK_FILE_QUERIES 0x00001000u
/* Linux under Wine: every decision on a request a Windows program made with its own syscall
 * instruction (KFILTER_EVENT_FLAG_DIRECT) is a deny. */
#define KFILTER_CFG_BLOCK_DIRECT_SYSCALL 0x00002000u
/* Linux: signals across the family's boundary that block-process-memory leaves alone need a HANDLE (into the family)
 * or OPEN (a kill(pid, 0) probe out of it) rule's grant of PROCESS_TERMINATE (QUERY_LIMITED_INFORMATION for a probe),
 * SIGIO too: decided where its owner is set across it (F_SETOWN, F_SETOWN_EX, FIOSETOWN, SIOCSPGRP; a process group by
 * its leader) and where a task raises it (a socket's softirq is not decided); PTRACE_MODE_READ checks across it (kcmp,
 * /proc/<pid>/maps, environ...) a grant of PROCESS_QUERY_INFORMATION. */
#define KFILTER_CFG_BLOCK_PROCESS_SIGNALS 0x00004000u
#define KFILTER_CFG_BLOCK_PROCESS_QUERIES 0x00008000u

/* Status registration bits. */
#define KFILTER_REG_MINIFILTER 0x00000001u
#define KFILTER_REG_REGISTRY 0x00000002u
#define KFILTER_REG_OBJECT 0x00000004u
#define KFILTER_REG_PROCESS 0x00000008u
#define KFILTER_REG_DISK 0x00000010u
#define KFILTER_REG_NETWORK 0x00000020u
#define KFILTER_REG_NSI 0x00000040u
#define KFILTER_REG_DEVICE 0x00000080u
/* Linux: kfilterd's BPF LSM layer (linux/bpf/kfilter.bpf.c) is attached. */
#define KFILTER_REG_BPF 0x00000100u

/* Extension classes for file/dir rules; 0 means any extension. */
#define KFILTER_EXT_EXE 0x00000001u
#define KFILTER_EXT_DLL 0x00000002u
#define KFILTER_EXT_SYS 0x00000004u
#define KFILTER_EXT_OCX 0x00000008u
#define KFILTER_EXT_OTHER 0x00000010u

typedef struct _KFILTER_RULE {
    KF_ULONG Action;
    KF_ULONG Targets;
    KF_ULONG Rights;
    KF_ULONG Extensions;
    KF_ULONG RuleId;
    KF_ULONG Account;
    KF_ULONG Count;   /* KFILTER_COUNT_*; 0 for a standing rule */
    KF_ULONG Flags;   /* KFILTER_RULE_EXACT, _HIDE, _MODULE, _ADDRESS */
    wchar_t Path[KFILTER_MAX_NAME];
    wchar_t Value[KFILTER_MAX_VALUE];
    wchar_t Risk[KFILTER_MAX_RISK];
    /* Empty: every protected program. Otherwise a glob on the requesting program: with a
     * separator it matches the whole image path, without one the file name (any case). */
    wchar_t Image[KFILTER_MAX_IMAGE];
    /* addr= (KFILTER_RULE_ADDRESS), 0 otherwise. AddressModule[i]: 0 for an absolute range, else the 1-based place
     * in Value's list of the module (in the target program) Address[i] is relative to. */
    KF_ULONG AddressCount;
    unsigned char AddressModule[KFILTER_MAX_ADDRESS];
    KFILTER_ADDRESS_RANGE Address[KFILTER_MAX_ADDRESS];
} KFILTER_RULE;

#define KFILTER_NET_FAMILY_UNIX 1u

typedef struct _KFILTER_NET_RULE {
    KF_ULONG Action;
    KF_ULONG Family;      /* 4 or 6; 0 (message rules only): any address; KFILTER_NET_FAMILY_UNIX: Unix names the peer */
    KF_ULONG Protocol;    /* 0 any, 6 TCP, 17 UDP */
    KF_ULONG PrefixLength;
    KF_ULONG Port;        /* 0 any */
    KF_ULONG RuleId;
    KF_ULONG Rights;      /* connect and/or listen; 0 means both. Message rules: send and/or receive */
    KF_ULONG Count;       /* KFILTER_COUNT_*; 0 for a standing rule */
    unsigned char Address[16];
    wchar_t Risk[KFILTER_MAX_RISK];
    wchar_t Image[KFILTER_MAX_IMAGE];   /* as KFILTER_RULE.Image */
    /* Message rules (Rights within KFILTER_RIGHTS_MESSAGE): each limit 0 when unused. A send
     * matches when its byte count is within [SizeMin, SizeMax], it is message IndexMin..IndexMax
     * on its connection (1 = the first in that direction), and MatchLength bytes at
     * MatchOffset equal Match. Receives are decided before the data arrives: only endpoint,
     * index and program apply to them. */
    KF_ULONG SizeMin;
    KF_ULONG SizeMax;
    KF_ULONG IndexMin;
    KF_ULONG IndexMax;
    KF_ULONG MatchOffset;
    KF_ULONG MatchLength;
    unsigned char Match[KFILTER_MAX_MATCH];
    /* Message rules, Linux under Wine: the Windows module (DLL or EXE file name pattern, as
     * Image) whose code made the send or receive, i.e. the first module on the calling
     * thread's Windows stack that is not Wine's own or in the prefix's windows directory.
     * Empty: any caller. */
    wchar_t Module[KFILTER_MAX_IMAGE];
    /* Message rules, Linux (ABI 12), Family KFILTER_NET_FAMILY_UNIX: a glob on the whole name of the AF_UNIX peer a send
     * goes to (/tmp/.X11-unix/X5, /@name for an abstract one): a connected socket's by its bound path, symlinks resolved,
     * a sendto's by its address as written; empty on every other rule. */
    wchar_t Unix[KFILTER_MAX_VALUE];
} KFILTER_NET_RULE;

typedef struct _KFILTER_CONFIG {
    KF_ULONG AbiVersion;
    KF_ULONG Flags;
    KF_ULONG Mode;
    KF_ULONG RuleCount;
    KF_ULONG ProtectedCount;
    KF_ULONG NetworkRuleCount;
    KF_ULONG Generation;
    KF_ULONG PackageSidLength;
    wchar_t Root[KFILTER_MAX_NAME];
    wchar_t Protected[KFILTER_MAX_PROTECTED][KFILTER_MAX_NAME];
    unsigned char PackageSid[KFILTER_MAX_SID];
    KFILTER_NET_RULE Network[KFILTER_MAX_NET_RULES];
    /* Last, so SET_CONFIG/GET_CONFIG carry only the RuleCount rules in use:
     * KFILTER_CONFIG_SIZE(RuleCount) bytes. */
    KFILTER_RULE Rules[KFILTER_MAX_RULES];
} KFILTER_CONFIG;

#define KFILTER_CONFIG_SIZE(count)     (sizeof(KFILTER_CONFIG) - sizeof(KFILTER_RULE) * (KFILTER_MAX_RULES - (KF_ULONG)(count)))

/* Value carries requested rights, except for a device decision where it is the IOCTL
 * (zero for CREATE and non-control operations). */
typedef struct _KFILTER_EVENT {
    KF_UINT64 Timestamp;
    KF_ULONG ProcessId;
    KF_ULONG Target;
    KF_ULONG Action;
    KF_ULONG Flags;
    KF_LONG Status;
    KF_ULONG Value;
    KF_ULONG RuleId;
    KF_ULONG Generation;
    wchar_t Path[KFILTER_MAX_NAME];
    /* File name of the program that made the request (under Wine its Windows image, e.g.
     * MapleStory.exe); empty when unknown. */
    wchar_t Image[KFILTER_MAX_IMAGE];
} KFILTER_EVENT;

#define KFILTER_EVENT_FLAG_WOULD_DENY 0x00000001u
#define KFILTER_EVENT_FLAG_NAME_FAILURE 0x00000002u
#define KFILTER_EVENT_FLAG_MISSING_CONTEXT 0x00000004u
#define KFILTER_EVENT_FLAG_NETWORK 0x00000008u
#define KFILTER_EVENT_FLAG_PROCESS_CREATE 0x00000010u
#define KFILTER_EVENT_FLAG_MEMORY_READ 0x00000020u
#define KFILTER_EVENT_FLAG_MEMORY_DUP 0x00000040u
/* Allowed by a counted rule (RuleId); Value is the requested rights. */
#define KFILTER_EVENT_FLAG_COUNTED 0x00000080u
/* A summary of identical events collapsed within a second (same process, target,
 * action, flags, value, rule and path); Generation holds how many were collapsed. */
#define KFILTER_EVENT_FLAG_REPEAT 0x00000100u
/* Denied although a counted rule matched: its uses were spent or its phase was not open.
 * RuleId names that rule. */
#define KFILTER_EVENT_FLAG_EXHAUSTED 0x00000200u
/* A network allow with Risk was used; network.c emits the separate RISK event. */
#define KFILTER_EVENT_FLAG_RISK 0x00000400u
/* Linux: the operation was made by a broker on the client's behalf (wineserver opening a
 * file or connecting a socket for it, winedevice answering its device request) and was
 * decided as the client's. ProcessId and Image name the client. */
#define KFILTER_EVENT_FLAG_BROKERED 0x00000800u
/* A message decision (KFILTER_TARGET_NETWORK): Value = the message's byte count; Path names
 * the direction, endpoint, connection (socket:[inode]), position and first bytes. */
#define KFILTER_EVENT_FLAG_MESSAGE 0x00001000u
/* Linux under Wine: made by a direct syscall from Windows code, not through Wine. */
#define KFILTER_EVENT_FLAG_DIRECT 0x00002000u

#define KFILTER_STATUS_DEGRADED_RAW_DISK 0x00000001u
#define KFILTER_STATUS_DEGRADED_ADAPTER 0x00000002u
#define KFILTER_STATUS_DEGRADED_DEVICE 0x00000004u
/* A class of decisions no active layer makes: its layer is missing or partly attached
 * (Linux: a BPF program did not attach), or the policy holds rules of that class the
 * layers cannot enforce (block mode refuses such a policy; audit mode loads it). */
#define KFILTER_STATUS_DEGRADED_FILES 0x00000008u
#define KFILTER_STATUS_DEGRADED_REGISTRY 0x00000010u
#define KFILTER_STATUS_DEGRADED_PROCESS 0x00000020u
#define KFILTER_STATUS_DEGRADED_MEMORY 0x00000040u    /* process and thread handles, memory */
#define KFILTER_STATUS_DEGRADED_NETWORK 0x00000080u
#define KFILTER_STATUS_DEGRADED_MESSAGE 0x00000100u   /* message rules, message-default deny */
#define KFILTER_STATUS_DEGRADED_VOLUME 0x00000200u
/* Linux: block mode whose enforcement ends when kfilterd exits (no pinned BPF links). */
#define KFILTER_STATUS_FAIL_OPEN 0x00000400u
/* Linux: metadata queries (QUERY on files), SYSTEM rules and THREAD rules go undecided. */
#define KFILTER_STATUS_DEGRADED_QUERY 0x00000800u
#define KFILTER_STATUS_DEGRADED_SYSTEM 0x00001000u
#define KFILTER_STATUS_DEGRADED_THREAD 0x00002000u
/* Linux: a Wine install whose wineserver protocol the BPF layer does not decode (its programs' registry, handle, peer,
 * /system/wine and NT object requests are not decided; block mode protecting a Windows program is refused). */
#define KFILTER_STATUS_DEGRADED_WINE 0x00004000u

typedef struct _KFILTER_STATUS {
    KF_ULONG AbiVersion;
    KF_ULONG Mode;
    KF_ULONG Flags;
    KF_ULONG RuleCount;
    KF_ULONG ProtectedCount;
    KF_ULONG NetworkRuleCount;
    KF_ULONG TrackedProcesses;
    KF_ULONG Allowed;
    KF_ULONG Denied;
    KF_ULONG Audited;
    KF_ULONG WouldDeny;
    KF_ULONG NameFailures;
    KF_ULONG MissingContexts;
    KF_ULONG DroppedEvents;
    KF_ULONG Registered;
    KF_ULONG PolicyGeneration;
    KF_ULONG SidFailures;
    KF_ULONG Degraded;
    KF_UINT64 SessionTag;
} KFILTER_STATUS;

typedef struct _KFILTER_READ_REQUEST {
    KF_ULONG MaximumEvents;
    KF_ULONG Reserved;
} KFILTER_READ_REQUEST;

typedef struct _KFILTER_TRACK_REQUEST {
    KF_ULONG ProcessId;
    KF_ULONG Reserved;
    KF_ULONG Generation;
    KF_ULONG Flags;
} KFILTER_TRACK_REQUEST;

/* KFILTER_ADMIT_REQUEST.Flags (Linux): the image is a Wine loader or a script that runs one;
 * after its NUL, ImagePath holds the Windows program it is asked to run (C:\...\x.exe or a
 * bare name), optionally followed by NUL and that program's Linux path. The program, not the
 * loader, must be protected or under the root. */
#define KFILTER_ADMIT_FLAG_PROGRAM 0x00000001u

typedef struct _KFILTER_ADMIT_REQUEST {
    KF_ULONG ProcessId;
    KF_ULONG Generation;
    KF_ULONG Flags;
    KF_ULONG SidLength;
    wchar_t ImagePath[KFILTER_MAX_NAME];
    unsigned char Sid[KFILTER_MAX_SID];
} KFILTER_ADMIT_REQUEST;

/*
 * One-time pass for a launcher button in block mode: the next Starts protected images
 * started by a creator whose image file name is CreatorName (e.g. nexon_client.exe), or
 * by a LAUNCH-rule broker on its behalf, are admitted, provided they come within
 * ArmSeconds; every later start is refused. Arming also restores the counted rules
 * (KFILTER_RULE.Count) and closes every phase but the first.
 */
typedef struct _KFILTER_ALLOW_LAUNCH_REQUEST {
    KF_ULONG ArmSeconds;
    KF_ULONG Starts;
    wchar_t CreatorName[KFILTER_MAX_NAME];
} KFILTER_ALLOW_LAUNCH_REQUEST;

/* Linux: refuse every send and/or receive on one live connection, named by its socket inode
 * (socket:[N] in kfilterctl watch and msmon). Directions 0 lifts the block. */
typedef struct _KFILTER_CONNECTION_REQUEST {
    KF_UINT64 SocketInode;
    KF_ULONG Directions;   /* KFILTER_RIGHT_SEND | KFILTER_RIGHT_RECEIVE */
    KF_ULONG Reserved;
} KFILTER_CONNECTION_REQUEST;

/* Linux: the run kfilterd's decisions belong to. SessionTag (non-zero) replaces
 * KFILTER_STATUS.SessionTag. OWN_EVENTS makes the caller (msmon-agent) the only reader of the
 * decision ring while it runs: READ_EVENTS and CLEAR_EVENTS from anyone else fail with EBUSY.
 * Without it, a caller that owns the ring gives it up. */
#define KFILTER_SESSION_OWN_EVENTS 0x00000001u
typedef struct _KFILTER_SESSION_REQUEST {
    KF_UINT64 SessionTag;
    KF_ULONG Flags;
    KF_ULONG Reserved;
} KFILTER_SESSION_REQUEST;

typedef KFILTER_RULE* PKFILTER_RULE;
typedef KFILTER_CONFIG* PKFILTER_CONFIG;
typedef KFILTER_EVENT* PKFILTER_EVENT;
typedef KFILTER_STATUS* PKFILTER_STATUS;
typedef KFILTER_READ_REQUEST* PKFILTER_READ_REQUEST;
typedef KFILTER_TRACK_REQUEST* PKFILTER_TRACK_REQUEST;
typedef KFILTER_ADMIT_REQUEST* PKFILTER_ADMIT_REQUEST;

#ifdef CTL_CODE
#define KFILTER_IOCTL_GET_STATUS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS)
#define KFILTER_IOCTL_SET_CONFIG CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define KFILTER_IOCTL_READ_EVENTS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS)
#define KFILTER_IOCTL_CLEAR_EVENTS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define KFILTER_IOCTL_TRACK_PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define KFILTER_IOCTL_CLEAR_TRACKING CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define KFILTER_IOCTL_GET_CONFIG CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_READ_ACCESS)
#define KFILTER_IOCTL_ADMIT_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define KFILTER_IOCTL_REGISTER_LAUNCHER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define KFILTER_IOCTL_ALLOW_LAUNCH CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define KFILTER_IOCTL_BLOCK_CONNECTION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80A, METHOD_BUFFERED, FILE_WRITE_ACCESS)
/* Linux only (kfilterd): KFILTER_SESSION_REQUEST; and stop: off, unpin, exit. */
#define KFILTER_IOCTL_SET_SESSION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80B, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define KFILTER_IOCTL_SHUTDOWN CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80C, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#endif
