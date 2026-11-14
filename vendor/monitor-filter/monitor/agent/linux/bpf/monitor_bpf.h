#pragma once

/*
 * Records shared by agent/linux/bpf/monitor.bpf.c (kernel) and agent/linux/bpf.cpp
 * (agent). Plain fixed-width fields only: the same layout on both sides.
 */
#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#define MM_PATH 256        /* bytes kept per path; longer ones are flagged truncated */
#define MM_FRAMES 8        /* user return addresses per syscall record */
#define MM_SYSCALLS 512    /* x86_64 syscall numbers covered by mm_sysinfo (and ia32 numbers by ia32_nr) */
/* ia32_nr keys of the ia32 multiplexers' subcalls: socketcall(102) and ipc(117) (bpf_ia32.inc). */
#define MM_IA32_SOCKETCALL MM_SYSCALLS          /* + SYS_SOCKET..SYS_SENDMMSG (1..20) */
#define MM_IA32_IPC (MM_SYSCALLS + 32)          /* + SEMOP..SHMCTL (1..24) */
#define MM_IA32_KEYS (MM_SYSCALLS + 64)
/* counts map key: tgid << 32 | the raw syscall number (MM_COUNT_OTHER: out of range), | MM_COUNT_COMPAT for an ia32
 * call; or tgid << 32 | MM_COUNT_WS | a wineserver request number. The other namespaces are agg keys only (bpf.cpp
 * AggWrite): a syscall Windows code made itself (DIRECT, beside the number), calls seccomp or syscall user dispatch
 * stopped before sys_enter (SECCOMP, DISPATCH, beside the number), a process's own fault signal (SIGNAL | the signal),
 * an untracked process's ptrace access check on a tracked one (OUTSIDE, agg tgid the target) and a desktop service's
 * requests and messages on an AF_UNIX socket (UNIX | MM_UNIX_* service | MM_UNIX_RX; unix_bpf.h). */
#define MM_COUNT_COMPAT 0x10000
#define MM_COUNT_WS 0x20000
#define MM_COUNT_DIRECT 0x40000
#define MM_COUNT_SECCOMP 0x80000
#define MM_COUNT_DISPATCH 0x100000
#define MM_COUNT_SIGNAL 0x200000
#define MM_COUNT_OUTSIDE 0x400000
#define MM_COUNT_UNIX 0x800000
#define MM_COUNT_UCALL 0x1000000   /* agg: a MM_UP_PAGE function past its records of the second (low half its index) */
#define MM_COUNT_OTHER 0xffff
#define MM_ARGV_BYTES 4096 /* MM_ARGV: argv bytes kept, and as many of the end of the environment */
#define MM_ROOTS 4         /* scope roots matched in the kernel: the client root and 3 extra roots */
#define MM_ARGV_SLOTS 8    /* execve: first 8 arguments, 32 bytes each, in path_b (used when MM_ARGV read nothing) */
#define MM_ARGV_SLOT 32

enum mm_kind {
    MM_SYSCALL = 1,      /* one completed syscall of a tracked thread */
    MM_FORK = 2,         /* a tracked process forked a new process */
    MM_EXEC = 3,         /* a tracked process exec'd (path_a = new image, path_b = argv) */
    MM_EXIT = 4,         /* a tracked process exited */
    MM_THREAD_START = 5,
    MM_THREAD_EXIT = 6,
    MM_SCOPE = 7,        /* an untracked process mapped an executable file under the root (nr 0), or exec'd a Wine
                          * loader in a directory under it (nr MM_SCOPE_WINE_EXEC; kpath that directory) */
    MM_DENIED = 8,       /* self-protection refused ptrace/kill of the agent (or bpf/perf_event_open; nr = which) */
    /* Records that are not struct mm_event; each starts with __u32 kind (bpf.cpp OnRing). */
    MM_TCP = 9,          /* struct mm_tcp_event (tcp_bpf.h): one TCP lifecycle fact */
    MM_WS_REQUEST = 10,  /* struct mm_ws_event (ws_bpf.h): a Wine client's request to wineserver */
    MM_WS_REPLY = 11,    /* struct mm_ws_event: wineserver's reply to it */
    MM_IMAGE = 12,       /* struct mm_event: an executable file mapping of a tracked process with the final LSM verdict
                          * (nr = MM_IMAGE_MMAP/MPROTECT; args: base, size, prot, mmap flags, file offset; ret) */
    MM_ARGV = 13,        /* struct mm_argv: the new image's whole argv (and environment end), just before its MM_EXEC */
    MM_KEV = 14,         /* struct mm_event from a kernel-event hook (kev.bpf.h), nr = MM_KEV_* */
    MM_ENV = 15,         /* struct mm_env: part of the new image's environment, before its MM_ARGV */
    MM_UNIX = 16,        /* struct mm_unix_head (unix_bpf.h): a desktop service connection's bytes of one call, before
                          * its MM_SYSCALL record */
};

/* MM_KEV.nr (above every syscall number, so repeat keys never meet a syscall's) */
#define MM_KEV_URING 1025    /* an io_uring operation: args opcode, fd, user_data, flags/open flags; ret = its CQE res */
#define MM_KEV_AIO 1026      /* a Linux AIO read or write (aio_prep_rw): args opcode, fd, nbytes, offset, rw */
#define MM_KEV_SIGNAL 1027   /* a signal another process or the kernel sent a tracked one: args sig, code, result,
                              * group, siginfo sender pid; target_tgid the sending process (user-sent only) */
#define MM_KEV_INSN 1028     /* an instruction the kernel trapped: args ip, its first 8 bytes, ax, cx, MM_INSN_* */
#define MM_KEV_CAP 1029      /* an audited capability check: args cap, opts; ret */
#define MM_KEV_MODULE 1030   /* a module autoload request (path_a its name); ret */
#define MM_KEV_CRED 1031     /* credentials changed: args (old << 32 | new) uid, euid, gid, egid; old, new cap_effective */
#define MM_KEV_FAULT 1032    /* first touch of a page of a shared file/shmem mapping: args address, ip, error_code,
                              * file offset */
#define MM_KEV_UCALL 1033    /* a Windows-level call Wine answers in-process (up.bpf.h: win32u.so NtUserXxx and NtGdiXxx,
                              * ntdll.so NtXxx): pos the attach cookie (MM_UP_*), args its first six arguments, ret the
                              * calls of the same (function, key argument) left out since the last record; path_a
                              * sock_len bytes of its UNICODE_STRING argument (UTF-16) */
#define MM_KEV_TLS 1034      /* a GnuTLS record send or receive (up.bpf.h): args session, buffer, size, cookie (MM_UP_TLS_*);
                              * ret its result; the plaintext goes to payload_ring as for socket I/O (MM_F_PAYLOAD) */
#define MM_KEV_WMI 1035      /* wbemprox's IWbemServices::ExecQuery, ExecQueryAsync, GetObject or CreateInstanceEnum
                              * entry (up.bpf.h): path_a (spilling into path_b) sock_len bytes of the WQL text or object
                              * path (UTF-16); args this, the BSTR, the method (MM_UP_WMI_*, the attach cookie) */
#define MM_KEV_SELFSIG 1036  /* a tracked process's own fault signal (SIGTRAP, SIGSEGV, SIGILL, SIGBUS, SIGFPE, SIGSYS), the
                              * first of its (signal, code, ip page) since the agent last drained agg (the rest are its
                              * summary): args sig, si_code, ip, si_addr, trap_nr << 32 | error_code, SIGSYS's syscall
                              * (arch << 32) or SIGTRAP's debug status (thread.virtual_dr6) */
#define MM_KEV_OUTSIDE 1037  /* an untracked process's ptrace access check on a tracked one (attach, or an audited read:
                              * ptrace, process_vm_*, /proc/<pid>/mem and maps...), the first of its (actor, mode, call)
                              * since the last drain; identity the target, target_tgid the actor; args mode, ret, the
                              * actor's syscall (MM_OUTSIDE_COMPAT: ia32), its tid; path_a its comm, kpath its exe */
#define MM_OUTSIDE_COMPAT 0x10000
#define MM_UP_WMI_EXEC_QUERY 0             /* vtable entry 20: WQL in the 3rd argument */
#define MM_UP_WMI_EXEC_QUERY_ASYNC 1       /* entry 21: WQL in the 3rd */
#define MM_UP_WMI_GET_OBJECT 2             /* entry 6: an object path in the 2nd */
#define MM_UP_WMI_CREATE_INSTANCE_ENUM 3   /* entry 18: a class in the 2nd */
#define MM_UP_WMI_METHODS 4
#define MM_INSN_SIGSEGV 1    /* SIGSEGV SI_KERNEL: CPUID/RDTSC faulting, RDPMC, RDMSR, IN/OUT, other #GP */
#define MM_INSN_UMIP 2       /* emulated by the kernel's UMIP fixup: SGDT, SIDT, SLDT, STR, SMSW */

/* losses map (per-CPU array of MM_LOSS_KEYS counters): calls or records lost without a ring drop; the agent writes
 * them as the ebpf_losses coverage note. */
#define MM_LOSS_PENDING_OVERWRITE 0   /* sys_enter found the thread's previous call still pending: its record is lost */
#define MM_LOSS_PENDING_STALE 1       /* a thread ended with a call pending (exec by a non-leader thread) */
#define MM_LOSS_WS_REJECTED 2         /* a write on a Wine request pipe not captured as one request (partial, resumed,
                                       * more than 5 chunks, sizes that disagree, another's pipe, splice, pwritev2,
                                       * sendfile): a request_pipe_rejected record each */
#define MM_LOSS_SCRATCH 3             /* sys_enter's per-CPU record (or unix_head's work) changed hands while it was
                                       * preempted: dropped (unix_head: the call's bytes counted unparsed) */
#define MM_LOSS_PENDING_FULL 4        /* pending held MM_PENDING calls: this call's record is lost */
#define MM_LOSS_COUNTS_FULL 5         /* counts held its MM_COUNT_KEYS keys: this call is in no syscall_counts */
#define MM_LOSS_AGG_FULL 6            /* agg held MM_AGG_KEYS keys: this call is only counted (counts), not summarized */
/* Two pairs whose difference the agent writes: io_uring operations stored at submission and written at completion
 * (the rest were evicted from uring_inflight, sent no CQE, or were in flight at the stop), and calls the uprobes' rate
 * limit left out and those a record or the stop's drain reported (the rest: an up_rate key evicted). */
#define MM_LOSS_URING_STORED 7
#define MM_LOSS_URING_DONE 8
#define MM_LOSS_UCALL_SKIPPED 9
#define MM_LOSS_UCALL_REPORTED 10
#define MM_LOSS_UNIX_FULL 11          /* unix_svc held its keys: a tracked process's AF_UNIX connect is not walked */
#define MM_LOSS_KEYS 12

/* Map sizes; full maps refuse a new key (never evict one), and each refusal is a loss above. */
#define MM_PENDING 4096
#define MM_COUNT_KEYS 32768
#define MM_AGG_KEYS 16384

/* Kernel aggregates (monitor.bpf.c sys_agg): calls of one process counted per (call, key argument) in the agg map
 * agg_live names, read and deleted by the agent every second and written as one repeats_tail summary each (bpf.cpp
 * AggFlush). aggcfg (index nr, + MM_SYSCALLS for an ia32 number) says which calls and how; the others take the record
 * path. */
#define MM_AGG_ENTER 1      /* counted at entry, a failure added at exit */
#define MM_AGG_MPROTECT 2   /* as ENTER unless the protection is executable (a record: image_load, anon_pe) */
#define MM_AGG_FCNTL 3      /* as ENTER unless MM_FCNTL_RECORDED */
#define MM_AGG_MMAP 4       /* an anonymous, not executable mapping: counted at exit with the range it returned */
#define MM_AGG_MREMAP 5     /* counted at exit; key the moved mapping's protection (+ MM_AGG_PROT_UNKNOWN), range the
                             * old and the new one */
#define MM_AGG_NATIVE_IO 6  /* a native helper's call (MM_TRACK_NATIVE; a record for any other process): counted at exit
                             * per the fd's inode with its bytes, the first of a key each drain a record (native_io) */
/* A native helper's I/O aggregate key: the inode number, its type (S_IFMT) in the top 4 bits. shortcut: an inode number
 * past 2^60 would share them; none of the filesystems here (ext4, tmpfs, btrfs, sockfs, pipefs) makes one. */
#define MM_NATIVE_IO_KEY(mode, ino) ((__u64)(ino) | (__u64)((mode) & 0170000) << 48)
#define MM_AGG_PROT_UNKNOWN 0x100
struct mm_aggcfg {
    __u8 mode;           /* MM_AGG_*; 0: not aggregated */
    __u8 key;            /* argument index + 1 whose value keys the aggregate (0: none) */
    __u8 addr;           /* argument index + 1 of an address, len of a length: the range [addr, addr + len) */
    __u8 len;
};
/* agg key: nr is a counts key's low half (the raw syscall number | MM_COUNT_COMPAT, or MM_COUNT_WS | request), so a
 * call the full map refused is counted there instead. */
struct mm_agg_key {
    __u32 tgid;
    __u32 nr;
    __u64 key;
};
/* agg value, per CPU (bpf.cpp merges them); a slot no call reached has first_ns 0. Times are CLOCK_BOOTTIME. */
struct mm_agg {
    __u64 calls;
    __u64 errors;        /* calls that returned a negative errno (counted at their exit) */
    __u64 bytes;         /* sum of the ranges' lengths */
    __u64 first_ns;
    __u64 last_ns;
    __u64 lo;            /* lowest address of a range (~0: none), hi the highest end */
    __u64 hi;
};
/* fcntl commands always recorded (MM_AGG_FCNTL): leases, directory notification, seals, signal routing (F_SETOWN,
 * F_SETOWN_EX, F_SETSIG) and record locks (F_SETLK, F_SETLKW, the ia32 F_SETLK64/F_SETLKW64, F_OFD_SETLK/SETLKW). */
#define MM_FCNTL_RECORDED(cmd)                                                                                         \
    ((cmd) == 6 || (cmd) == 7 || (cmd) == 8 || (cmd) == 10 || (cmd) == 13 || (cmd) == 14 || (cmd) == 15 ||            \
     (cmd) == 37 || (cmd) == 38 || (cmd) == 1024 || (cmd) == 1026 || (cmd) == 1033)

#define MM_SCOPE_WINE_EXEC 1
#define MM_SCOPE_LAUNCH 2    /* the first exec of kfilterctl launch's child (kpath its cgroup's name, launch-<launcher pid>) */
#define MM_CGROUP_NAME 24     /* bytes of a session cgroup's name read (launch-<pid>: at most 14 and a NUL) */

/* The launcher's pid in a kfilterctl launch session cgroup's name, "launch-<pid>" and a NUL; 0 when it is none. The NUL
 * is found in the loop, at a constant index per step: the verifier takes no variable stack offset here. */
static inline __u32 mm_launch_cgroup_pid(const char name[MM_CGROUP_NAME])
{
    if (name[0] != 'l' || name[1] != 'a' || name[2] != 'u' || name[3] != 'n' || name[4] != 'c' || name[5] != 'h' ||
        name[6] != '-')
        return 0;
    __u32 pid = 0;
    for (int at = 7; at < 15; at++) {   /* pid_max is at most 4194304: 7 digits */
        const char digit = name[at];
        if (digit == 0) return pid;
        if (digit < '0' || digit > '9') return 0;
        pid = pid * 10 + (__u32)(digit - '0');
    }
    return 0;
}

/* MM_IMAGE.nr */
#define MM_IMAGE_MMAP 1      /* security_mmap_file: no address yet (base 0) */
#define MM_IMAGE_MPROTECT 2  /* security_file_mprotect: base/size are the vma's */

/* MM_DENIED.nr */
#define MM_DENY_PTRACE 1
#define MM_DENY_BPF 2
#define MM_DENY_PERF 3
#define MM_DENY_KILL 4

/* mm_event.flags */
#define MM_F_TRUNC_A 0x01
#define MM_F_TRUNC_B 0x02
#define MM_F_TRUNC_K 0x04
#define MM_F_KPATH 0x08      /* kpath holds the fd's (or returned fd's) kernel path */
#define MM_F_KDIR_A 0x10     /* kdir_a holds the directory a relative path_a is under */
#define MM_F_KDIR_B 0x20
#define MM_F_SOCK 0x40       /* path_b holds sock_len bytes of a sockaddr */
#define MM_F_ARGV 0x80       /* path_b holds MM_ARGV_SLOTS argv slots */
#define MM_F_SOCKID 0x100    /* sk_* hold the identity of the resolved fd's socket (payload.bpf.h) */
#define MM_F_PAYLOAD 0x200   /* the call's bytes went to payload_ring; cap_* are valid (payload.bpf.h) */
#define MM_F_COMPAT 0x400    /* an ia32 syscall (32-bit Wine): nr is the x86_64 number it maps to (ia32_nr), args are
                              * the ia32 registers; mmap2's offset is in pages */
#define MM_F_IPC 0x800       /* unpacked from the ia32 ipc multiplexer (x86_64 argument order; shmat: args[3] receives
                              * the address, which sys_exit moves to ret) */
#define MM_F_SERVING 0x1000  /* wineserver made the call while serving a client's request (ws.bpf.h ws_serving):
                              * target_tgid is the client, served_req the request number */
#define MM_F_UNIX_HEAD 0x2000 /* an MM_UNIX head of this call came first (unix.bpf.h: X11 requests, D-Bus messages and
                               * PulseAudio commands the agent names from it) */
#define MM_F_RIOV 0x4000     /* path_b holds sock_len bytes of the remote array (mm_sysinfo.riov) */
#define MM_F_OUTFD 0x8000    /* out_ino/out_mode are the output fd's file (mm_sysinfo.more.outfd) */
#define MM_F_DIRECT 0x10000  /* Windows code made the syscall with its own instruction (sys_direct) */
#define MM_F_IOCTL_ARG 0x20000 /* MM_CFG_CONTENT: kdir_b holds cap_bytes bytes of a DRM or socket ioctl's argument at exit */
#define MM_F_NATIVE_IO 0x40000 /* a native helper's I/O call recorded at its exit as the first of its agg key (native_io):
                                * no duration, stack or bytes; the rest of the second's calls are that key's summary */

/* mm_sysinfo.dir_* */
#define MM_DIR_NONE 0
#define MM_DIR_CWD 0xFE      /* a relative path is under the cwd */
/* 1..6: argument index + 1 that holds a dirfd (AT_FDCWD means the cwd) */

/* mm_sysinfo.sock */
#define MM_SOCK_NONE 0
#define MM_SOCK_IN_1 1       /* sockaddr in arg1, length arg2 (connect, bind) */
#define MM_SOCK_IN_4 2       /* sockaddr in arg4, length arg5 (sendto) */
#define MM_SOCK_OUT_1 3      /* sockaddr out in arg1, length pointer arg2 (accept, accept4) */
#define MM_SOCK_OUT_4 4      /* sockaddr out in arg4, length pointer arg5 (recvfrom) */
#define MM_SOCK_MSG_IN_1 5   /* msghdr in arg1, msg_name read at entry (sendmsg) */
#define MM_SOCK_MSG_OUT_1 6  /* msghdr in arg1, msg_name read at exit (recvmsg) */

/* What sys_enter captures for one syscall number; filled by the agent. */
struct mm_sysinfo {
    __u8 want;           /* 0: not recorded */
    __u8 path_a;         /* argument index + 1 of a user path, 0 = none */
    __u8 dir_a;          /* MM_DIR_* or argument index + 1 of its dirfd */
    __u8 path_b;
    __u8 dir_b;
    __u8 fd;             /* argument index + 1 of an fd whose file is resolved at entry */
    __u8 retfd;          /* 1: the return value is a new fd, resolved at exit */
    __u8 sock;           /* MM_SOCK_* */
    __u8 argv;           /* argument index + 1 of an argv array */
    __u8 data;           /* MM_DATA_* (payload_bpf.h): where the call's bytes are, captured on network sockets */
    __u8 flags_arg;      /* argument index + 1 of a MSG_* flags argument (MSG_PEEK calls are not captured) */
    __u8 riov;           /* argument index + 1 of a remote array (process_vm_*'s iovecs, move_pages' pages): its first
                          * MM_RIOV_MAX elements go to path_b (MM_F_RIOV), the first 8 bytes also to pos */
    struct {             /* one braced group, so a row that names none of them leaves them all 0 */
        __u8 native;     /* 1: also recorded for a native helper (MM_TRACK_NATIVE) */
        __u8 rcount;     /* argument index + 1 of riov's element count */
        __u8 relem;      /* riov's element bytes (16 an iovec, 8 a pointer; halved for an ia32 call) */
        __u8 outfd;      /* argument index + 1 of an output fd (sendfile, splice, tee, copy_file_range): MM_F_OUTFD */
    } more;
};
#define MM_RIOV_MAX 16

#define MM_PE_BYTES 512     /* PE stack copied from TEB->syscall_frame->rsp (pe.bpf.h) */

/* The PE (Windows) side of the Wine syscall a thread is in (pe.bpf.h read_pe); rip 0 = none. 544 bytes. */
struct mm_pe {
    __u64 rip;           /* syscall_frame->rip */
    __u64 rsp;           /* syscall_frame->rsp: stack[0] is the qword at rsp */
    __u64 rbp;           /* syscall_frame->rbp */
    __u32 bytes;         /* bytes copied into stack (0..MM_PE_BYTES) */
    __u32 flags;         /* MM_PE_I386: an ia32 thread; rip/rsp/rbp are eip/esp/ebp, the stack holds 4-byte words */
    __u8 stack[MM_PE_BYTES];
};

struct mm_event {
    __u32 kind;
    __u32 tgid;
    __u32 tid;
    __u32 ppid;
    __u64 start_ns;      /* group leader start_boottime: /proc/<pid>/stat starttime in ns */
    __u64 ts_ns;         /* CLOCK_BOOTTIME at the record */
    __u64 dur_ns;
    __s64 ret;
    __u64 args[6];
    __u32 nr;
    __u32 frames;
    __u32 mode;          /* i_mode of the resolved file */
    __u32 flags;         /* MM_F_* */
    __u64 pos;           /* f_pos of the fd at entry */
    __u64 ino;           /* inode number of the resolved file */
    __u64 stack[MM_FRAMES];
    __u32 target_tgid;   /* MM_FORK: the child; MM_DENIED: the target; MM_F_SERVING: the client served */
    __u32 sock_len;
    char path_a[MM_PATH];
    char path_b[MM_PATH];
    char kpath[MM_PATH];
    char kdir_a[MM_PATH];
    char kdir_b[MM_PATH];
    /* The resolved fd's socket (MM_F_SOCKID) and the call's byte capture (MM_F_PAYLOAD): payload.bpf.h. */
    __u16 sk_family;
    __u16 sk_type;
    __u16 sk_protocol;
    __u16 sk_lport;      /* host order */
    __u16 sk_rport;      /* host order */
    __u16 sk_pad;
    __u32 cap_bytes;     /* bytes sent to payload_ring */
    __u8 sk_laddr[16];   /* network order; IPv4 in the first 4 bytes */
    __u8 sk_raddr[16];
    __u32 cap_stop;      /* MM_CAP_* (payload_bpf.h) */
    __u32 served_req;    /* MM_F_SERVING: the wineserver request being served */
    __u64 out_ino;       /* MM_F_OUTFD */
    __u32 out_mode;
    __u32 out_pad;
    struct mm_pe pe;     /* must stay last: a record without a PE context ends before it (MM_EVENT_SHORT) */
};

#define MM_PE_I386 0x1

/* MM_ARGV record: argv_len bytes of the NUL-separated argv, then env_len bytes of the environment's end (the
 * variables a launcher appends). The ring record ends after them. The whole environment follows as MM_ENV records. */
struct mm_argv {
    __u32 kind;
    __u32 tgid;
    __u64 start_ns;
    __u32 argv_len;
    __u32 env_len;
    __u32 argv_total;    /* arg_end - arg_start: more than argv_len when cut */
    __u32 pad;
    char data[2 * MM_ARGV_BYTES];
};

/* MM_ENV record: len bytes of the new image's environment from offset (NUL-separated variables), one per
 * MM_ARGV_BYTES, up to MM_ENV_CHUNKS of them, just before its MM_ARGV; total is env_end - env_start. */
#define MM_ENV_CHUNKS 16
struct mm_env {
    __u32 kind;
    __u32 tgid;
    __u64 start_ns;
    __u32 offset;
    __u32 len;
    __u32 total;
    __u32 pad;
    char data[MM_ARGV_BYTES];
};

/* Ring bytes of an mm_event whose pe.rip is 0 (mm_sys_exit reserves only these). */
#define MM_EVENT_SHORT __builtin_offsetof(struct mm_event, pe)

/* config map, key 0: written by the agent after load, before attach. */
struct mm_config {
    __u32 agent_tgid;
    __u32 kfilterd_tgid;           /* protected as the agent is (0: none running) */
    __u32 flags;                   /* MM_CFG_* */
    __u32 root_len[MM_ROOTS];      /* 0: slot unused (all 0: no in-kernel scope check) */
    char root[MM_ROOTS][MM_PATH];  /* the scope roots, no trailing '/' */
    __u32 native_depth;            /* execs of native programs kept tracked in a row (--native-depth; 0: none) */
    __u32 handoff_depth;           /* the same for the sign-in hand-off (MM_TRACK_HANDOFF) */
};
#define MM_CFG_PAYLOAD 0x1   /* capture socket bytes (payload.bpf.h); off with --no-payloads */
#define MM_CFG_PROTECT_TREE 0x2   /* also refuse the tracked tree bpf() and perf_event_open (off by default: msmon
                                   * observes only; kfilter's policy owns what the client may do) */
#define MM_CFG_CONTENT 0x4   /* --log-content: also capture AF_UNIX and pipe bytes (payload.bpf.h) and DRM and socket
                              * ioctls' argument structs (record_extra) */

/* tracked map value */
struct mm_tracked {
    __u64 start_ns;
    __u32 flags;         /* MsMonFlagExplicitTrack / MsMonFlagInheritedTrack, MM_TRACK_* */
    __u32 depth;         /* MM_TRACK_NATIVE: native execs since the last Wine or in-scope image */
};
#define MM_TRACK_NATIVE 0x100   /* a native helper (xdg-open, a browser): only mm_sysinfo.more.native calls are recorded,
                                 * its I/O is kernel aggregates (MM_AGG_NATIVE_IO), its sockets are not tagged (no packets) */
#define MM_TRACK_HANDOFF 0x200  /* forked by winebrowser.exe: the sign-in hand-off, native to handoff_depth (inherited) */
#define MM_TRACK_LAUNCH 0x400   /* kfilterctl launch's child and its descendants until a Wine loader's exec: in scope at
                                 * every exec (inherited) */

/* Records and constants each upgrade shares between its BPF code and its agent code. */
#include "payload_bpf.h"
#include "tcp_bpf.h"
#include "pkt_bpf.h"
#include "ws_bpf.h"
#include "up_bpf.h"
#include "unix_bpf.h"
