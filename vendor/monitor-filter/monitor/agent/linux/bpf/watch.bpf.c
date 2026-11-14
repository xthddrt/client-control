// SPDX-License-Identifier: GPL-2.0
/*
 * msmon watchpoints (--watch: agent/linux/watch.cpp, docs/LINUX.md "Watchpoints"), a BPF object of their own that the
 * agent loads only with --watch. mm_watch_hit runs on every hit of a hardware data breakpoint the agent opened on a
 * thread (perf_event_open PERF_TYPE_BREAKPOINT, the watch's index as the link's cookie) and counts it in watch_hits per
 * (thread, second, ip, watch) instead of writing a sample: a hot address costs its #DB trap and this count, no ring
 * traffic and no agent work per hit; a breakpoint hit MM_WATCH_CAP times in one second is one watch_over record, on
 * which the agent closes it. mm_watch_ptrace counts a tracer's PTRACE_POKEUSR of a debug register that failed
 * ENOSPC: wineserver setting a Windows program's thread context while the watches hold some of that thread's 4 debug
 * registers. The agent reads and deletes a key 2 seconds after its second, when no program still holds it.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "watch_bpf.h"

char LICENSE[] SEC("license") = "GPL";

#define PTRACE_POKEUSR 6
#define ENOSPC 28

/* Preallocated (the default): perf_event programs run in the #DB handler, where allocating is not safe. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MM_WATCH_KEYS);
    __type(key, struct mm_watch_key);
    __type(value, struct mm_watch_hit);
} watch_hits SEC(".maps");

/* Hits and conflicts left uncounted because watch_hits was full (the agent's watch_losses record). */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} watch_lost SEC(".maps");

/* The key of a breakpoint past MM_WATCH_CAP hits in a second, for the agent to close it: room for every thread of the
 * family (258 in the census) times 4 watches. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);
} watch_over SEC(".maps");

/* Counts one hit of Key, a new key starting from Fresh: the key's value when it existed, else NULL. A key belongs to one
 * thread, which runs on one CPU at a time: no atomics. */
static __always_inline struct mm_watch_hit* count_key(struct mm_watch_key* key, struct mm_watch_hit* fresh)
{
    __u64 now = bpf_ktime_get_boot_ns();
    key->second = now / 1000000000;
    struct mm_watch_hit* hit = bpf_map_lookup_elem(&watch_hits, key);
    if (hit) {
        hit->count++;
        hit->last_ns = now;
        return hit;
    }
    fresh->count = 1;
    fresh->first_ns = now;
    fresh->last_ns = now;
    if (bpf_map_update_elem(&watch_hits, key, fresh, BPF_NOEXIST) == 0) return NULL;
    __u32 zero = 0;
    __u64* lost = bpf_map_lookup_elem(&watch_lost, &zero);
    if (lost) *lost += 1;
    return NULL;
}

SEC("perf_event")
int mm_watch_hit(struct bpf_perf_event_data* ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct mm_watch_key key = {
        .tid = (__u32)id,
        .tgid = id >> 32,
        .watch = (__u32)bpf_get_attach_cookie(ctx),
        .ip = ctx->regs.ip,   /* user mode: the breakpoints exclude the kernel */
        .addr = ctx->addr,
    };
    struct bpf_perf_event_value value = {};
    bpf_perf_prog_read_value(ctx, &value, sizeof(value));   /* the breakpoint's hits so far, at every ip */
    struct mm_watch_hit fresh = {.mark = value.counter};
    struct mm_watch_hit* hit = count_key(&key, &fresh);
    /* The breakpoint's hits since the mark all fall in this key's second: at the cap the agent closes it (one record
     * per MM_WATCH_CAP hits until it has). */
    if (hit && value.counter - hit->mark >= MM_WATCH_CAP) {
        hit->mark = value.counter;
        bpf_ringbuf_output(&watch_over, &key, sizeof(key), 0);
    }
    return 0;   /* counted: no sample */
}

SEC("fexit/arch_ptrace")
int BPF_PROG(mm_watch_ptrace, struct task_struct* child, long request, unsigned long addr, unsigned long data, long ret)
{
    if (ret != -ENOSPC || request != PTRACE_POKEUSR || addr < MM_WATCH_DR0 || addr >= MM_WATCH_DR0 + 8 * 8) return 0;
    struct mm_watch_key key = {
        .tid = child->pid,
        .tgid = child->tgid,
        .watch = MM_WATCH_CONFLICT,
        .ip = data,
        .addr = (addr - MM_WATCH_DR0) / 8,
    };
    struct mm_watch_hit fresh = {.actor = bpf_get_current_pid_tgid() >> 32};
    count_key(&key, &fresh);
    return 0;
}
