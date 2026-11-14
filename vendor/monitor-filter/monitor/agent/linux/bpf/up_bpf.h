#pragma once
/* User-space function probes (up.bpf.h; the agent's bpf_up.inc attaches them and decodes MM_KEV_UCALL, MM_KEV_TLS and
 * MM_KEV_WMI). The attach cookie says what was hit. */

/* MM_KEV_UCALL cookie: bits 0-15 the agent's function index, 16-19 the argument (1-6) whose value keys the rate limit
 * (0: the function alone), 20-23 the argument (1-6) that points at a UNICODE_STRING to copy (0: none), 24 the agent's
 * i386 flag, 25 MM_UP_HWND, 26 MM_UP_PAGE, 28-31 MM_UP_KEY2. */
#define MM_UP_HWND (1u << 25)   /* the first argument is a window: calls on the caller's own windows are left out */
#define MM_UP_PAGE (1u << 26)   /* the second key is an address, keyed by its page; past MM_UP_PAGES records a second
                                 * the calls are a kernel aggregate (MM_COUNT_UCALL) holding their pages' range */
#define MM_UP_BUDGET (1u << 27) /* up_rate: a MM_UP_PAGE function's records this second (skipped counts them) */
#define MM_UP_KEY(cookie) (((cookie) >> 16) & 0xf)
#define MM_UP_STR(cookie) (((cookie) >> 20) & 0xf)
#define MM_UP_KEY2(cookie) (((cookie) >> 28) & 0xf)   /* a second key argument (1-6): up_rate_key.key2 */
#define MM_UP_WINDOW_NS 1000000000ull   /* one record per (process, function, key) per window; the rest are counted */
#define MM_UP_PAGES 64                  /* a MM_UP_PAGE function's records a second per process (a VirtualQuery walk) */

/* MM_KEV_TLS cookie */
#define MM_UP_TLS_RECV 0x1     /* gnutls_record_recv (else gnutls_record_send) */
#define MM_UP_TLS_32 0x2       /* set by the ia32 entry program: the result is a 32-bit ssize_t */

/* up_rate (key, value): the last record of a (process, attach cookie, key) and the calls left out since; the agent
 * writes those still held at the stop (bpf_up.inc UpDrain). */
struct up_rate_key {
    __u32 tgid;
    __u32 cookie;
    __u64 key;
    __u64 key2;   /* its own field: folded into key, two (handle, address) pairs could meet */
};
struct up_rate {
    __u64 last_ns;
    __u64 skipped;
};
