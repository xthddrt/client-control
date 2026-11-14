/*
 * A fake Wine client for tests/ebpf_checks/wineserver.sh (root): it looks to ws.bpf.h like a Wine 11
 * thread talking to wineserver. It sets up a TEB (64-bit: GS base, Tib.Self at +0x30, ClientId at +0x40,
 * request/reply fds at +0x384; ia32: a set_thread_area TLS entry, Self at +0x18, ClientId at +0x20,
 * fds at +0x220), maps ./ntdll.so (holding the "wine-11.0" build string) and plays both sides of a few
 * protocol-930 exchanges (the decoded ones, generic ones, a window message, a burst of select the kernel
 * aggregates, an unknown request): it writes each request to its request pipe as Wine does (write of 64
 * bytes, or writev of the 64-byte part and its data), drains it, puts the reply into its reply pipe and
 * reads it back as Wine does (64 bytes, then the reply data). Then the writes ws.bpf.h rejects (32 bytes; a
 * splice and a pwritev2, 64-bit). Last (64-bit), renamed wineserver, it reads a request whose 64-byte vararg follows its
 * header apart (ws.bpf.h must not take that read for a header): its failing open after that is served for
 * the header's request.
 *
 * Freestanding (no libc), so the same source builds with -m32 where no 32-bit libc is installed.
 * Run it from the directory holding ntdll.so. Exit 0 = every syscall worked.
 */
typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

#if defined(__x86_64__)
enum { NR_READ = 0, NR_WRITE = 1, NR_OPEN = 2, NR_MMAP = 9, NR_WRITEV = 20, NR_NANOSLEEP = 35, NR_PRCTL = 157,
       NR_ARCH_PRCTL = 158, NR_EXIT_GROUP = 231, NR_SPLICE = 275, NR_PIPE2 = 293, NR_PWRITEV2 = 328 };
#define TEB_SELF 0x30
#define TEB_CLIENT_ID 0x40
#define TEB_FDS 0x384
static long sys6(long n, long a, long b, long c, long d, long e, long f)
{
    long r;
    register long r10 __asm__("r10") = d, r8 __asm__("r8") = e, r9 __asm__("r9") = f;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
    return r;
}
#else
enum { NR_READ = 3, NR_WRITE = 4, NR_OPEN = 5, NR_OLD_MMAP = 90, NR_WRITEV = 146, NR_NANOSLEEP = 162,
       NR_SET_THREAD_AREA = 243, NR_EXIT_GROUP = 252, NR_PIPE2 = 331 };
#define TEB_SELF 0x18
#define TEB_CLIENT_ID 0x20
#define TEB_FDS 0x220
static long sys6(long n, long a, long b, long c, long d, long e, long f)
{
    long r;
    (void)d, (void)e, (void)f;   /* every ia32 call used here takes at most 3 arguments */
    __asm__ volatile("int $0x80" : "=a"(r) : "a"(n), "b"(a), "c"(b), "d"(c) : "memory");
    return r;
}
#endif
#define sys3(n, a, b, c) sys6(n, (long)(a), (long)(b), (long)(c), 0, 0, 0)

/* gcc may emit calls to these even when freestanding. */
void* memset(void* d, int c, unsigned long n)
{
    u8* p = d;
    while (n--) *p++ = (u8)c;
    return d;
}
void* memcpy(void* d, const void* s, unsigned long n)
{
    u8* p = d;
    const u8* q = s;
    while (n--) *p++ = *q++;
    return d;
}

static u8 teb[0x2000] __attribute__((aligned(4096)));
static u8 scratch[16384];
static int failed;
static int fds[2];      /* request pipe: read end (the "server"), write end (request_fd) */
static int replies[2];  /* reply pipe: read end (reply_fd), write end (the "server") */

static long check(long ret)
{
    if (ret < 0 && ret > -4096) failed = 1;   /* -errno; an ia32 mmap address can look negative */
    return ret;
}

static void put32(u8* p, u32 v)
{
    for (int i = 0; i < 4; i++) p[i] = (u8)(v >> (8 * i));
}
static void put64(u8* p, u64 v)
{
    for (int i = 0; i < 8; i++) p[i] = (u8)(v >> (8 * i));
}
static u32 utf16(u8* out, const char* s)
{
    u32 n = 0;
    for (; *s; s++, n += 2) {
        out[n] = (u8)*s;
        out[n + 1] = 0;
    }
    return n;
}

static void nap(long seconds)
{
    long ts[2] = {seconds, 0};
    sys3(NR_NANOSLEEP, ts, 0, 0);
}

struct iov {
    void* base;
    unsigned long len;
};

/* One exchange: the request (fixed part + up to two data chunks) and its reply (64 bytes + data). */
static void exchange(u8* req, u32 reqNo, u8* d1, u32 l1, u8* d2, u32 l2, u8* reply, u32 replyData)
{
    put32(req, reqNo);
    put32(req + 4, l1 + l2);
    if (l1 + l2 == 0) {
        check(sys3(NR_WRITE, fds[1], req, 64));
    } else {
        struct iov vec[3] = {{req, 64}, {d1, l1}, {d2, l2}};
        check(sys3(NR_WRITEV, fds[1], vec, l2 ? 3 : 2));
    }
    check(sys3(NR_READ, fds[0], scratch, 64 + l1 + l2));   /* the "server" takes the request */
    put32(reply + 4, replyData);
    check(sys3(NR_WRITE, replies[1], reply, 64 + replyData));
    check(sys3(NR_READ, replies[0], scratch, 64));
    if (replyData) check(sys3(NR_READ, replies[0], scratch, replyData));
}

__attribute__((force_align_arg_pointer, noreturn)) void _start(void)
{
    static u8 req[64], reply[64 + 64], name[512], data[512];
    u32 n, m;

    check(sys3(NR_PIPE2, fds, 0, 0));
    check(sys3(NR_PIPE2, replies, 0, 0));
#if defined(__x86_64__)
    put64(teb + TEB_SELF, (u64)(unsigned long)teb);
    put64(teb + TEB_CLIENT_ID, 0x20);
    put64(teb + TEB_CLIENT_ID + 8, 0x24);
    check(sys3(NR_ARCH_PRCTL, 0x1001 /* ARCH_SET_GS */, teb, 0));
#else
    put32(teb + TEB_SELF, (u32)(unsigned long)teb);
    put32(teb + TEB_CLIENT_ID, 0x20);
    put32(teb + TEB_CLIENT_ID + 4, 0x24);
    /* struct user_desc: entry -1 (any free TLS slot), base, limit 0xfff pages; seg_32bit, limit_in_pages, useable. */
    u32 desc[4] = {0xffffffffu, (u32)(unsigned long)teb, 0xfff, 0x1 | 0x10 | 0x40};
    check(sys3(NR_SET_THREAD_AREA, desc, 0, 0));
#endif
    put32(teb + TEB_FDS, (u32)fds[1]);
    put32(teb + TEB_FDS + 4, (u32)replies[0]);

    /* The agent's decoder gate reads the build string of the ntdll.so this process maps. */
    long so = check(sys3(NR_OPEN, "ntdll.so", 0, 0));
#if defined(__x86_64__)
    check(sys6(NR_MMAP, 0, 4096, 1 /* PROT_READ */, 2 /* MAP_PRIVATE */, so, 0));
#else
    u32 args[6] = {0, 4096, 1, 2, (u32)so, 0};
    check(sys3(NR_OLD_MMAP, args, 0, 0));
#endif
    nap(1);   /* the agent admits this process (MM_SCOPE) before the first request */

    /* open_key(87): parent 0 (absolute), access KEY_READ -> hkey 0x10. */
    memset(req, 0, 64);
    memset(reply, 0, sizeof(reply));
    put32(req + 16, 0x20019);
    n = utf16(name, "\\Registry\\Machine\\Software\\MsmonProbe");
    put32(reply + 8, 0x10);
    exchange(req, 87, name, n, 0, 0, reply, 0);

    /* set_key_value(91): hkey 0x10, REG_SZ, name "Probe", data "hello" (as Wine: three iovecs). */
    memset(req, 0, 64);
    memset(reply, 0, sizeof(reply));
    put32(req + 12, 0x10);
    put32(req + 16, 1);
    n = utf16(name, "Probe");
    put32(req + 20, n);
    m = utf16(data, "hello");
    exchange(req, 91, name, n, data, m, reply, 0);

    /* get_key_value(92): the reply carries type 1, total 10 and the data. */
    memset(req, 0, 64);
    memset(reply, 0, sizeof(reply));
    put32(req + 8, 256);
    put32(req + 12, 0x10);
    n = utf16(name, "Probe");
    put32(reply + 8, 1);
    put32(reply + 12, 10);
    utf16(reply + 64, "hello");
    exchange(req, 92, name, n, 0, 0, reply, 10);

    /* open_process(27): Windows pid 2457, PROCESS_VM_READ -> handle 0x20. */
    memset(req, 0, 64);
    memset(reply, 0, sizeof(reply));
    put32(req + 12, 2457);
    put32(req + 16, 0x10);
    put32(reply + 8, 0x20);
    exchange(req, 27, 0, 0, 0, 0, reply, 0);

    /* read_process_memory(84): handle 0x20, 16 bytes at 0x10000 (the length is the header's reply_size). */
    memset(req, 0, 64);
    memset(reply, 0, sizeof(reply));
    put32(req + 8, 16);
    put32(req + 12, 0x20);
    put64(req + 16, 0x10000);
    exchange(req, 84, 0, 0, 0, 0, reply, 16);

    /* create_file(44): objattr with the NT name, then the unix path -> handle 0x24. */
    memset(req, 0, 64);
    memset(reply, 0, sizeof(reply));
    memset(name, 0, sizeof(name));
    put32(req + 12, 0x80100080);
    put32(req + 16, 3);
    put32(req + 20, 3);   /* FILE_OPEN_IF */
    put32(req + 24, 0x60);
    put32(req + 28, 0x80);
    n = utf16(name + 16, "\\??\\unix\\tmp\\msmon-probe.txt");
    put32(name + 4, 0x40);
    put32(name + 12, n);
    n = (16 + n + 3) & ~3u;
    m = 0;
    for (const char* p = "/tmp/msmon-probe.txt"; *p; p++) data[m++] = (u8)*p;
    put32(reply + 8, 0x24);
    exchange(req, 44, name, n, data, m, reply, 0);

    /* ioctl(138) IOCTL_AFD_WINE_CONNECT to 127.0.0.1:9 on socket 0x28: STATUS_PENDING (Wine completes it
     * by APC; the record carries the pending status). */
    memset(req, 0, 64);
    memset(reply, 0, sizeof(reply));
    memset(data, 0, sizeof(data));
    put32(req + 12, 0x12032c);
    put32(req + 16, 0x28);
    put64(req + 32, 0x5000);
    put32(data, 16);   /* addr_len */
    put32(data + 4, 1);   /* synchronous */
    data[8] = 2;   /* WS_AF_INET */
    data[11] = 9;  /* port 9, big-endian */
    data[12] = 127;
    data[15] = 1;
    put32(reply, 0x103);
    exchange(req, 138, data, 8 + 16, 0, 0, reply, 0);

    /* query_event(32) twice: the generic decoder's system:query_event (collapsed). */
    for (int i = 0; i < 2; i++) {
        memset(req, 0, 64);
        memset(reply, 0, sizeof(reply));
        exchange(req, 32, 0, 0, 0, 0, reply, 0);
    }

    /* create_window(142) -> 0x10066; send_message(119) WM_COPYDATA "hello" to thread 0x999 (never seen: recorded). */
    memset(req, 0, 64);
    memset(reply, 0, sizeof(reply));
    put32(reply + 8, 0x10066);
    exchange(req, 142, 0, 0, 0, 0, reply, 0);
    memset(req, 0, 64);
    memset(reply, 0, sizeof(reply));
    put32(req + 12, 0x999);
    put32(req + 16, 5);   /* MSG_OTHER_PROCESS */
    put32(req + 24, 0x10077);
    put32(req + 28, 0x4a);
    m = utf16(data, "hello");
    exchange(req, 119, data, m, 0, 0, reply, 0);

    /* get_message(122) receives WM_KEYDOWN 'A' (its key withheld without --log-real-input). */
    memset(req, 0, 64);
    memset(reply, 0, sizeof(reply));
    put32(reply + 8, 0x10066);
    put32(reply + 12, 0x100);
    put32(reply + 16, 0x41);
    put32(reply + 32, 7);   /* MSG_HARDWARE */
    exchange(req, 122, 0, 0, 0, 0, reply, 0);

    /* ioctl(138) IOCTL_STORAGE_QUERY_PROPERTY on handle 0x2c: 12 bytes in, 8 back (its key's first call: recorded). */
    memset(req, 0, 64);
    memset(reply, 0, sizeof(reply));
    memset(data, 0, 12);
    put32(req + 8, 8);
    put32(req + 12, 0x2d1400);
    put32(req + 16, 0x2c);
    for (int i = 0; i < 8; i++) reply[64 + i] = (u8)(i + 1);
    exchange(req, 138, data, 12, 0, 0, reply, 8);

    /* select(29) x200 with flags 2: a kernel aggregate (the first call recorded, aggregate=sampled). */
    for (int i = 0; i < 200; i++) {
        memset(req, 0, 64);
        memset(reply, 0, sizeof(reply));
        put32(req + 12, 2);
        exchange(req, 29, 0, 0, 0, 0, reply, 0);
    }

    /* Request 400 (past the table): system:unknown. */
    memset(req, 0, 64);
    memset(reply, 0, sizeof(reply));
    put32(req + 12, 7);
    put32(reply, 0xC0000002);   /* STATUS_NOT_IMPLEMENTED */
    exchange(req, 400, 0, 0, 0, 0, reply, 0);

    /* send_hardware_message(121): a real (not injected) key 'A', recorded without its key. */
    memset(req, 0, 64);
    memset(reply, 0, sizeof(reply));
    put32(req + 16, 1);
    put32(req + 20, 0x41);
    exchange(req, 121, 0, 0, 0, 0, reply, 0);

    /* get_async_result(134): 10 bytes back; set_irp_result(139): 5 bytes of an IRP's output. */
    memset(req, 0, 64);
    memset(reply, 0, sizeof(reply));
    put64(req + 16, 0x7f00);
    utf16(reply + 64, "hello");
    exchange(req, 134, 0, 0, 0, 0, reply, 10);
    memset(req, 0, 64);
    memset(reply, 0, sizeof(reply));
    put32(req + 12, 0x304);
    put32(req + 20, 5);
    for (int i = 0; i < 5; i++) data[i] = (u8)('1' + i);
    exchange(req, 139, data, 5, 0, 0, reply, 0);

    /* Rejected writes, a record each: 32 bytes (no request header); a splice and a pwritev2 (offset -1: a writev) into
     * the request pipe (x86_64). */
    memset(req, 0, 64);
    check(sys3(NR_WRITE, fds[1], req, 32));
    check(sys3(NR_READ, fds[0], scratch, 32));
#if defined(__x86_64__)
    int source[2];
    check(sys3(NR_PIPE2, source, 0, 0));
    check(sys3(NR_WRITE, source[1], req, 8));
    check(sys6(NR_SPLICE, source[0], 0, fds[1], 0, 8, 0));
    check(sys3(NR_READ, fds[0], scratch, 8));
    struct iov eight[1] = {{req, 8}};
    check(sys6(NR_PWRITEV2, fds[1], (long)eight, 1, -1, -1, 0));
    check(sys3(NR_READ, fds[0], scratch, 8));
#endif

#if defined(__x86_64__)
    /* As wineserver: query_mutex(39) with 64 bytes of vararg whose first u32 is 0 (new_process), read as Wine's
     * read_request does (the header, then the data); the open after it is served for query_mutex. */
    check(sys3(NR_PRCTL, 15 /* PR_SET_NAME */, "wineserver", 0));
    memset(req, 0, 64);
    memset(data, 0, 64);
    put32(req, 39);
    put32(req + 4, 64);
    struct iov served[2] = {{req, 64}, {data, 64}};
    check(sys3(NR_WRITEV, fds[1], served, 2));
    check(sys3(NR_READ, fds[0], scratch, 64));
    check(sys3(NR_READ, fds[0], scratch, 64));
    sys3(NR_OPEN, "/msmon-served-probe", 0, 0);   /* ENOENT */
#endif

    nap(3);   /* stay alive (ntdll.so mapped) while the agent handles the first event */
    sys3(NR_EXIT_GROUP, failed, 0, 0);
    for (;;) {
    }
}
