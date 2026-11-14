#pragma once
/*
 * Wineserver requests (ws.bpf.h captures, agent/linux/wineserver.cpp decodes). Included by
 * monitor_bpf.h after struct mm_pe; MM_WS_REQUEST / MM_WS_REPLY are its kinds. No protocol numbers
 * here: the agent writes the wanted requests into ws_cfg (WsCaptureConfig).
 */

#define MM_WS_FIXED 64       /* every request and reply starts with a 64-byte fixed part */
#define MM_WS_DATA 8192      /* bytes kept of the request vararg / of the reply data (one payload chunk) */
#define MM_WS_REQUESTS 512   /* request numbers ws_cfg covers (protocol 930 has 306) */
#define MM_WS_F_COMPAT 0x1   /* the client is a 32-bit (ia32) Wine process */
#define MM_WS_F_SAMPLED 0x2  /* an aggregated request's first call of its key since the agent last drained agg */
#define MM_WS_F_REJECTED 0x4 /* no request: a write on a request pipe that is not one (data: struct mm_ws_reject) */

/* mm_ws_reject.reason: writes on a request pipe that are not one whole request of the writer's own thread. kfilter
 * refuses them in block mode for a protected program, but TOTAL, FOREIGN on another thread's pipe of the same process,
 * and sendfile (it reaches a pipe without file_permission). */
#define MM_WS_REJECT_CHUNKS 1      /* writev of fewer than 2 or more than 6 iovecs */
#define MM_WS_REJECT_RESUMED 2     /* writev whose first iovec is not the 64-byte header (a resumed partial write) */
#define MM_WS_REJECT_SIZE 3        /* a write of other than 64 bytes */
#define MM_WS_REJECT_UNREADABLE 4  /* the header could not be read */
#define MM_WS_REJECT_FORM 5        /* request_size says data and the write has none, or the other way round */
#define MM_WS_REJECT_TOTAL 6       /* the data chunks do not add up to request_size */
#define MM_WS_REJECT_FOREIGN 7     /* another thread's or process's request pipe */
#define MM_WS_REJECT_SPLICE 8      /* splice, tee or vmsplice into a request pipe */
#define MM_WS_REJECT_OTHER 9       /* pwritev2 or sendfile into a request pipe */

/* A rejected write's data[]; its fixed[] holds the first 64 bytes it carried (zero when unreadable). */
struct mm_ws_reject {
    __u64 ino;       /* the request pipe */
    __u64 count;     /* the syscall's count argument: bytes (write, splice, tee, sendfile), iovecs (writev, vmsplice,
                      * pwritev2) */
    __s32 fd;
    __u32 nr;        /* the syscall number in its own ABI (MM_WS_F_COMPAT: ia32) */
    __u32 reason;    /* MM_WS_REJECT_* */
    __u32 owner;     /* tgid whose request pipe it is (0: unknown) */
};

struct mm_ws_event {
    __u32 kind;          /* MM_WS_REQUEST or MM_WS_REPLY */
    __u32 tgid;
    __u32 tid;
    __u32 req;           /* request number; a reply carries the number of the request it answers */
    __u32 total;         /* request: request_header.request_size; reply: reply_header.reply_size */
    __u32 data_len;      /* bytes of data[] filled, <= MM_WS_DATA */
    __u32 win_pid;       /* request: TEB ClientId (Windows process and thread id) */
    __u32 win_tid;
    __u32 frames;        /* request: user return addresses in stack[] */
    __u32 flags;         /* MM_WS_F_* */
    __u64 start_ns;      /* group leader start_boottime */
    __u64 ts_ns;         /* CLOCK_BOOTTIME */
    __u64 stack[MM_FRAMES];
    __u8 fixed[MM_WS_FIXED];
    struct mm_pe pe;     /* request: the PE side of the Nt* call (pe.bpf.h); rip 0 = none, replies too */
    /* Only MM_WS_DATA bytes are used; the upper half keeps every copy's end in bounds for the verifier.
     * The ring record ends after data_len bytes of it. */
    __u8 data[2 * MM_WS_DATA];
};

/* ws_inflight value, key tid: a wanted request whose reply has not been read yet. */
struct mm_ws_inflight {
    __u32 req;
    __s32 reply_fd;
    __u32 compat;
    __u32 phase;         /* 0: the 64-byte reply is next; 1: its data is next */
    __u32 data;          /* 1: capture the reply data (else the reply is sent after its 64 bytes) */
    __u32 early;         /* 1: sent before the TEB was in use: the reply comes on reply_ino, read through
                          * the other end of the pipe than the reply_fd its first request named */
    __u32 window;        /* destroy_window: the window it names (ws_window takes it out of ws_windows on success) */
    __u32 pad;
    __u64 reply_ino;
    __u8 header[MM_WS_FIXED];
};

/* ws_cfg value, key 0: written by the agent from its protocol table before attach. */
struct mm_ws_config {
    __u64 want[8];           /* bit n: capture request number n */
    __u64 data[8];           /* bit n: also capture the reply data of request n */
    __u32 ioctl_req;         /* the 'ioctl' request; its ioctl_codes are never aggregated */
    __u32 ioctl_codes[8];    /* 0 = unused */
    /* Request req is never aggregated when the u32 at fixed[off] has a bit of mask (mask 0: slot unused). */
    struct {
        __u32 req, off, mask;
    } filter[2];
    __u16 window_req[2];     /* create_window, destroy_window: their successes keep ws_windows */
    /* bit n: request n is counted in agg per key instead of captured, except its first call of a key since the agent
     * last drained agg (MM_WS_F_SAMPLED); the key is the u32 at fixed[key[n][0]] << 32 | the u32 at fixed[key[n][1]]
     * (offset 0: none). */
    __u64 agg[8];
    __u8 key[MM_WS_REQUESTS][2];
};

/* ws_pipes value, key the inode number of a tracked Wine thread's request, reply or wait pipe. */
struct mm_ws_pipe {
    __u32 tgid;      /* the Wine client */
    __u32 request;   /* 1: its request pipe (wineserver reads the requests from it) */
    __u32 toread;    /* request pipe: vararg bytes of the last request header wineserver has still to read */
};

/* ws_windows value, index a window handle's user-handle index (mm_ws_window_index): the process and thread whose
 * create_window made it, and its generation; tgid 0 when none (destroyed, or made before tracking). The uprobes keep
 * only window calls on other programs' windows by it (up.bpf.h). */
struct mm_ws_window {
    __u32 tgid;
    __u32 tid;
    __u32 gen;
    __u32 pad;
};
#define MM_WS_WINDOWS 32768

/* Wine's index of a window handle (server/user.c handle_to_entry: (low word - FIRST_USER_HANDLE 0x20) >> 1, here
 * without the constant), so a handle's low word alone names the same window; 0 below that first handle (no window:
 * NULL, the caller's own queue). */
static inline __u32 mm_ws_window_index(__u64 hwnd)
{
    __u32 low = (__u32)hwnd & 0xffff;
    return low < 0x20 ? 0 : low >> 1;
}

/* 1 when Hwnd, as passed, names the window W holds: its generation (high word) matches, or the high word is 0 or 0xffff,
 * which wineserver takes for any generation. */
static inline int mm_ws_window_match(const struct mm_ws_window* w, __u64 hwnd)
{
    __u32 high = (__u32)hwnd >> 16;
    return w->tgid != 0 && (high == 0 || high == 0xffff || high == w->gen);
}

/* ws_serving value, key wineserver's tgid: the client whose request it read last, until it waits again. */
struct mm_ws_serving {
    __u32 tgid;
    __u32 req;
};

#ifdef __cplusplus
static_assert(__builtin_offsetof(struct mm_ws_event, fixed) == 120, "mm_ws_event.fixed");
static_assert(__builtin_offsetof(struct mm_ws_event, pe) == 184, "mm_ws_event.pe");
static_assert(__builtin_offsetof(struct mm_ws_event, data) == 728, "mm_ws_event.data");
static_assert(sizeof(struct mm_ws_event) == 728 + 2 * MM_WS_DATA, "mm_ws_event size");
static_assert(sizeof(struct mm_ws_config) == 256 + 2 * MM_WS_REQUESTS, "mm_ws_config size");
static_assert(sizeof(struct mm_ws_reject) == 32, "mm_ws_reject size");
#else
_Static_assert(__builtin_offsetof(struct mm_ws_event, data) == 728, "mm_ws_event.data");
_Static_assert(sizeof(struct mm_ws_event) == 728 + 2 * MM_WS_DATA, "mm_ws_event size");
_Static_assert(sizeof(struct mm_ws_config) == 256 + 2 * MM_WS_REQUESTS, "mm_ws_config size");
#endif
