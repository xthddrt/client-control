/*
 * User-space function probes (docs/LINUX.md "Function probes"): the optional group uprobes (mm_up_*). bpf_up.inc
 * attaches the library probes once per file (every process that maps it) and wbemprox's per process; each program
 * returns at once for an untracked process. Observation only: no register or memory is changed.
 * - mm_up_call, mm_up_call32: Windows-level calls Wine answers inside the process with no syscall or wineserver
 *   request (win32u.so NtUserXxx/NtGdiXxx: key state, cursor, windows, screen; ntdll.so NtXxx: system, process and
 *   thread queries), as MM_KEV_UCALL with the call's PE context. Wine's unix side takes SysV register arguments on
 *   x86_64 and stack arguments on i386. One record per (process, function, key argument) per MM_UP_WINDOW_NS; the
 *   calls in between are counted on the next one. A window function's (MM_UP_HWND, --window-probes) calls on a
 *   window ws_windows says the caller made, or on none, are left out before that: only other programs' windows (and
 *   windows made before tracking) are recorded, target_tgid their owner.
 * - mm_up_tls, mm_up_tls32 (entry) and mm_up_tls_ret (return): gnutls_record_send/recv (Wine's schannel in
 *   secur32.so), as MM_KEV_TLS; the plaintext the call moved goes to payload_ring as a socket call's bytes do.
 * - mm_up_wmi, mm_up_wmi32: wbemprox.dll's IWbemServices::ExecQuery, ExecQueryAsync, GetObject and CreateInstanceEnum
 *   (PE code: Windows x64 or stdcall arguments; the cookie's MM_UP_WMI_*), attached per process once its code is
 *   executable, as MM_KEV_WMI with the WQL text or object path.
 * Reuses events, scratch (kev_start), up_emit's read_pe_any and payload.bpf.h's capwalk/cap_step.
 */

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct up_rate_key);
    __type(value, struct up_rate);
} up_rate SEC(".maps");

/* A gnutls call between its entry and its return, by thread. */
struct up_tls_call {
    __u64 session;
    __u64 buf;
    __u64 size;
    __u64 cookie;
};
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct up_tls_call);
} up_tls SEC(".maps");

/* The record to the events ring with its user stack; whole (with e->pe) when it has a PE context. */
static __always_inline void up_emit(void* ctx, struct mm_event* e)
{
    long bytes = bpf_get_stack(ctx, e->stack, sizeof(e->stack), BPF_F_USER_STACK);
    e->frames = bytes > 0 ? (__u32)(bytes / sizeof(__u64)) : 0;
    long full = e->pe.rip ? bpf_ringbuf_output(&events, e, sizeof(*e), 0) : bpf_ringbuf_output(&events, e, MM_EVENT_SHORT, 0);
    if (full) count_drop();
}

/* The process that made window Hwnd (ws_windows), 0 when not known. */
static __always_inline __u32 up_window_owner(__u64 hwnd)
{
    __u32 index = mm_ws_window_index(hwnd);
    struct mm_ws_window* w = index ? bpf_map_lookup_elem(&ws_windows, &index) : 0;
    return w && mm_ws_window_match(w, hwnd) ? w->tgid : 0;
}

/* 1 while process K's records of a MM_UP_PAGE function this second are fewer than MM_UP_PAGES (counted here, in an
 * up_rate entry of its own); unlocked, so two CPUs at once may let one more through. */
static __always_inline int up_page_room(const struct up_rate_key* k, __u64 now)
{
    struct up_rate_key b = {.tgid = k->tgid, .cookie = k->cookie | MM_UP_BUDGET};
    struct up_rate* budget = bpf_map_lookup_elem(&up_rate, &b);
    if (!budget) {
        struct up_rate first = {now, 1};
        bpf_map_update_elem(&up_rate, &b, &first, BPF_ANY);
        return 1;
    }
    if (now - budget->last_ns >= MM_UP_WINDOW_NS) {
        budget->last_ns = now;
        budget->skipped = 0;
    }
    if (budget->skipped >= MM_UP_PAGES) return 0;
    budget->skipped++;
    return 1;
}

static __always_inline void up_call(struct pt_regs* ctx, const __u64* a, int compat)
{
    __u64 cookie = bpf_get_attach_cookie(ctx);
    __u32 keyarg = MM_UP_KEY(cookie), strarg = MM_UP_STR(cookie), key2arg = MM_UP_KEY2(cookie);
    struct up_rate_key k = {};
    k.tgid = bpf_get_current_pid_tgid() >> 32;
    __u32 owner = 0;
    if (cookie & MM_UP_HWND) {
        owner = up_window_owner(a[0]);
        if (owner == k.tgid || !mm_ws_window_index(a[0])) return;   /* its own window, or none (its own queue) */
    }
    k.cookie = (__u32)cookie;
    __u64 text = 0;
#pragma unroll
    for (int i = 0; i < 6; i++) {
        if (keyarg == i + 1) k.key = a[i];
        if (key2arg == i + 1) k.key2 = cookie & MM_UP_PAGE ? a[i] >> 12 : a[i];
        if (strarg == i + 1) text = a[i];
    }
    __u64 now = bpf_ktime_get_boot_ns(), skipped = 0;
    struct up_rate* rate = bpf_map_lookup_elem(&up_rate, &k);
    if (rate && now - rate->last_ns < MM_UP_WINDOW_NS) {
        __sync_fetch_and_add(&rate->skipped, 1);
        count_loss(MM_LOSS_UCALL_SKIPPED);
        return;
    }
    if ((cookie & MM_UP_PAGE) && !up_page_room(&k, now)) {   /* a walk past the second's records: its pages summed */
        agg_add(MM_COUNT_UCALL | (__u32)(cookie & 0xffff), k.key, k.key2 << 12, 4096, MM_AGG_CALL);
        return;
    }
    if (rate) {
        skipped = rate->skipped;
        rate->skipped = 0;
        rate->last_ns = now;
        __u32 reported = MM_LOSS_UCALL_REPORTED;
        __u64* value = bpf_map_lookup_elem(&losses, &reported);
        if (value) __sync_fetch_and_add(value, skipped);
    } else {
        struct up_rate fresh = {now, 0};
        bpf_map_update_elem(&up_rate, &k, &fresh, BPF_ANY);
    }
    struct mm_event* e = kev_start(MM_KEV_UCALL);
    if (!e) return;
    e->pos = cookie;
    e->ret = (__s64)skipped;
    e->target_tgid = owner;
#pragma unroll
    for (int i = 0; i < 6; i++) e->args[i] = a[i];
    /* UNICODE_STRING: Length (bytes), MaximumLength, then Buffer at 8 (x64) or 4 (i386). */
    __u64 head[2] = {};
    if (text && bpf_probe_read_user(head, compat ? 8 : 16, (const void*)text) == 0) {
        __u64 buffer = compat ? head[0] >> 32 : head[1];
        __u64 n = head[0] & 0xffff;
        if (n > MM_PATH) n = MM_PATH;
        n &= 2 * MM_PATH - 1;
        if (n > MM_PATH) n = MM_PATH;
        if (buffer && n && bpf_probe_read_user(e->path_a, n, (const void*)buffer) == 0) e->sock_len = n;
    }
    read_pe_any(&e->pe, bpf_get_current_task_btf(), ctx, compat);
    up_emit(ctx, e);
}

SEC("uprobe.multi")
int mm_up_call(struct pt_regs* ctx)
{
    if (!current_tracked()) return 0;
    __u64 a[6] = {ctx->di, ctx->si, ctx->dx, ctx->cx, ctx->r8, ctx->r9};
    up_call(ctx, a, 0);
    return 0;
}

SEC("uprobe.multi")
int mm_up_call32(struct pt_regs* ctx)
{
    if (!current_tracked()) return 0;
    __u32 s[7] = {};   /* the return address, then six arguments */
    bpf_probe_read_user(s, sizeof(s), (const void*)ctx->sp);
    __u64 a[6] = {s[1], s[2], s[3], s[4], s[5], s[6]};
    up_call(ctx, a, 1);
    return 0;
}

/* A tracked process that is not a native helper (whose bytes are never captured, as for its sockets). */
static __always_inline int up_tls_wanted(void)
{
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct mm_tracked* t = bpf_map_lookup_elem(&tracked, &tgid);
    return t && !(t->flags & MM_TRACK_NATIVE);
}

static __always_inline void up_tls_enter(struct pt_regs* ctx, __u64 session, __u64 buf, __u64 size, __u64 flags)
{
    struct up_tls_call call = {session, buf, size, bpf_get_attach_cookie(ctx) | flags};
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    bpf_map_update_elem(&up_tls, &tid, &call, BPF_ANY);
}

SEC("uprobe.multi")
int mm_up_tls(struct pt_regs* ctx)
{
    if (!up_tls_wanted()) return 0;
    up_tls_enter(ctx, ctx->di, ctx->si, ctx->dx, 0);
    return 0;
}

SEC("uprobe.multi")
int mm_up_tls32(struct pt_regs* ctx)
{
    if (!up_tls_wanted()) return 0;
    __u32 s[4] = {};
    bpf_probe_read_user(s, sizeof(s), (const void*)ctx->sp);
    up_tls_enter(ctx, s[1], s[2], s[3], MM_UP_TLS_32);
    return 0;
}

/* Both arches' return: the bytes a send took or a receive filled are known only here. */
SEC("uretprobe.multi")
int mm_up_tls_ret(struct pt_regs* ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct up_tls_call* found = bpf_map_lookup_elem(&up_tls, &tid);
    if (!found) return 0;
    struct up_tls_call call = *found;
    bpf_map_delete_elem(&up_tls, &tid);
    int compat = (call.cookie & MM_UP_TLS_32) != 0;
    struct mm_event* e = kev_start(MM_KEV_TLS);
    if (!e) return 0;
    e->ret = compat ? (__s64)(__s32)ctx->ax : (__s64)ctx->ax;
    e->args[0] = call.session;
    e->args[1] = call.buf;
    e->args[2] = call.size;
    e->args[3] = call.cookie;
    if (e->ret > 0) capture_buffer(e, call.buf, e->ret);
    read_pe_any(&e->pe, bpf_get_current_task_btf(), ctx, compat);
    up_emit(ctx, e);
    return 0;
}

/* ExecQuery(this, strQueryLanguage, strQuery, ...) and the others (Method): the probe is in PE code, so its own registers
 * are the PE context. */
static __always_inline void up_wmi(struct pt_regs* ctx, __u64 self, __u64 query, __u64 method, int compat)
{
    struct mm_event* e = kev_start(MM_KEV_WMI);
    if (!e) return;
    e->args[0] = self;
    e->args[1] = query;
    e->args[2] = method;
    __u32 length = 0;   /* a BSTR's byte length is the dword before it */
    if (query && bpf_probe_read_user(&length, sizeof(length), (const void*)(query - 4)) == 0) {
        __u64 n = length > 2 * MM_PATH ? 2 * MM_PATH : length;
        n &= 4 * MM_PATH - 1;
        if (n > 2 * MM_PATH) n = 2 * MM_PATH;
        if (n && bpf_probe_read_user(e->path_a, n, (const void*)query) == 0) e->sock_len = n;
    }
    e->pe.rip = ctx->ip;
    e->pe.rsp = ctx->sp;
    e->pe.rbp = ctx->bp;
    e->pe.flags = compat ? MM_PE_I386 : 0;
    if (bpf_probe_read_user(e->pe.stack, MM_PE_BYTES, (const void*)ctx->sp) == 0) e->pe.bytes = MM_PE_BYTES;
    up_emit(ctx, e);
}

/* GetObject and CreateInstanceEnum take their path or class second, the queries their WQL third. */
static __always_inline int up_wmi_path(__u64 method)
{
    return method == MM_UP_WMI_GET_OBJECT || method == MM_UP_WMI_CREATE_INSTANCE_ENUM;
}

SEC("uprobe.multi")
int mm_up_wmi(struct pt_regs* ctx)
{
    if (!current_tracked()) return 0;
    const __u64 method = bpf_get_attach_cookie(ctx);
    __u64 query = ctx->r8, second = ctx->dx;
    barrier_var(second);   /* two loads: a load from a chosen ctx offset is refused by the verifier */
    if (up_wmi_path(method)) query = second;
    up_wmi(ctx, ctx->cx, query, method, 0);
    return 0;
}

SEC("uprobe.multi")
int mm_up_wmi32(struct pt_regs* ctx)
{
    if (!current_tracked()) return 0;
    const __u64 method = bpf_get_attach_cookie(ctx);
    __u32 s[4] = {};   /* return address, this, strQueryLanguage or the path, strQuery */
    bpf_probe_read_user(s, sizeof(s), (const void*)ctx->sp);
    up_wmi(ctx, s[1], up_wmi_path(method) ? s[2] : s[3], method, 1);
    return 0;
}
