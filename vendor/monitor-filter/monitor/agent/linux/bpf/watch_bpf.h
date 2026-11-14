#pragma once
/* Watchpoints (--watch: agent/linux/watch.cpp, docs/LINUX.md "Watchpoints"), shared by bpf/watch.bpf.c and the agent:
 * the hits of the hardware data breakpoints the agent opens per thread, and the debug-register writes those breakpoints
 * made fail, counted in watch_hits per (thread, second, ip, watch) and read by the agent once the second is over. */
#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#define MM_WATCH_KEYS 4096
#define MM_WATCH_CONFLICT 0x100   /* key.watch: a tracer's PTRACE_POKEUSR of a debug register failed ENOSPC */
#define MM_WATCH_DR0 848          /* x86_64 offsetof(struct user, u_debugreg): PTRACE_POKEUSR's DR0 (asserted in watch.cpp) */
#define MM_WATCH_CAP 10000        /* a breakpoint hit this often in one second is closed (about 1% of a core in traps) */

struct mm_watch_key {
    __u32 tid;
    __u32 tgid;
    __u32 second;   /* CLOCK_BOOTTIME seconds */
    __u32 watch;    /* the --watch's index (the perf link's cookie), or MM_WATCH_CONFLICT */
    __u64 ip;       /* the user instruction after the access (a data breakpoint traps after it); conflict: the value written */
    __u64 addr;     /* the watched address; conflict: the debug register's number */
};

struct mm_watch_hit {
    __u64 count;
    __u64 first_ns;   /* CLOCK_BOOTTIME */
    __u64 last_ns;
    __u64 actor;      /* conflict: the tracer's tgid (wineserver for a Windows program's SetThreadContext) */
    __u64 mark;       /* hit: the breakpoint's hits at every ip (its perf count) when the key began or last reported the cap */
};
