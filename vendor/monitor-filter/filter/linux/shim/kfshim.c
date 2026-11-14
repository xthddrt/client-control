/*
 * kfshim: CPUID and RDTSC/RDTSCP trapping inside the program, without a tracer
 * (`kfilterctl launch --trap-cpuid / --trap-rdtsc`). wineserver ptrace-attaches to its clients for
 * debug registers and memory, so a second tracer would break Wine; this runs in-process instead.
 *
 * Preloaded (LD_PRELOAD, which the ld.so that wine-preloader loads honours) into every dynamically
 * linked process of the launch, as <dir>/$LIB/libkfshim.so: <dir>/config says what to do,
 * "cpuid rdtsc log=<file> mask=<leaf>,..." (hex leaves). The configuration travels inside the
 * LD_PRELOAD path, so it reaches every process that loads the shim (whatever closes descriptors or
 * rebuilds the environment) and never sits in an environment the program reads. A process the shim
 * loads into without its configuration, or where a trap it was asked for cannot be armed, exits 126
 * instead of running untrapped. The constructor snapshots the CPUID leaves (those that differ between
 * cores on each CPU it may run on), installs a SIGSEGV handler and makes the instructions fault
 * (arch_prctl ARCH_SET_CPUID 0, prctl PR_SET_TSC PR_TSC_SIGSEGV). A
 * SIGSEGV with SI_KERNEL at one of them is answered here (a masked leaf reads all zeros) and the first
 * use of each leaf or instruction per process is appended to the log, with per-process totals at exit.
 * Every other SIGSEGV goes to the handler the program installed: sigaction and signal are
 * interposed. msmon records each trap on its own (tp_btf/signal_generate), outside the program.
 *
 * shortcut: the program can see the shim (LD_PRELOAD in its environment, the .so in its maps) and undo
 * it with raw syscalls. `deny|system|/system/arch_prctl/0x1012/1` keeps CPUID faulting on (the shim
 * never turns it off).
 *
 * Built twice, x86_64 and i386, without libc headers (a host may have only the 32-bit libc
 * runtime): the few libc functions used are declared here, and the handler uses raw syscalls.
 */
#include <stdint.h>
#include <cpuid.h>

extern int open(const char* path, int flags, ...);
extern long read(int fd, void* buffer, unsigned long size);
extern int close(int fd);
extern void* dlsym(void* handle, const char* name);
typedef struct { const char* dli_fname; void* dli_fbase; const char* dli_sname; void* dli_saddr; } Dl_info;
extern int dladdr(const void* address, Dl_info* info);
extern unsigned long getauxval(unsigned long type);
extern void* mmap(void* address, unsigned long size, int protection, int flags, int fd, long offset);
#define RTLD_NEXT ((void*)-1l)

/* glibc's struct sigaction (x86_64 and i386 layouts follow from the field types). */
struct ksigaction {
    void* handler;
    unsigned long mask[1024 / (8 * sizeof(unsigned long))];
    int flags;
    void (*restorer)(void);
};
#define SIGSEGV 11
#define SA_SIGINFO 4
#define SA_RESTART 0x10000000
#define SI_KERNEL 0x80
#define SIG_DFL ((void*)0)
#define SIG_IGN ((void*)1)
#define SIG_ERR ((void*)-1l)
#define ARCH_SET_CPUID 0x1012
#define PR_SET_TSC 26
#define PR_TSC_ENABLE 1
#define PR_TSC_SIGSEGV 2
#define PR_GET_NAME 16
#define AT_SYSINFO_EHDR 33

#ifdef __x86_64__
typedef long long greg;   /* ucontext_t: uc_mcontext.gregs at 40 */
enum { GREGS = 40, R_AX = 13, R_BX = 11, R_CX = 14, R_DX = 12, R_IP = 16 };
enum { NR_write = 1, NR_getpid = 39, NR_prctl = 157, NR_arch_prctl = 158, NR_sched_setaffinity = 203,
       NR_sched_getaffinity = 204, NR_exit_group = 231 };
#else
typedef int greg;         /* ucontext_t: uc_mcontext.gregs at 20 */
enum { GREGS = 20, R_AX = 11, R_BX = 8, R_CX = 10, R_DX = 9, R_IP = 14 };
enum { NR_write = 4, NR_getpid = 20, NR_prctl = 172, NR_arch_prctl = 384, NR_sched_setaffinity = 241,
       NR_sched_getaffinity = 242, NR_exit_group = 252 };
#endif

/* No TLS, no errno: a trap can come from Windows code, whose segment state is Wine's business. */
static long sys3(long n, long a, long b, long c)
{
    long r;
#ifdef __x86_64__
    __asm__ volatile("syscall" : "=a"(r) : "0"(n), "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
#else
    __asm__ volatile("int $0x80" : "=a"(r) : "0"(n), "b"(a), "c"(b), "d"(c) : "memory");
#endif
    return r;
}

struct leaf { uint32_t leaf, sub, r[4]; };
static struct leaf leaves[1536];
static unsigned leafCount;
static uint32_t maxBasic, maxExtended, maxHypervisor;   /* the snapshot's ranges (no hypervisor: 0) */
static int intel;
static uint32_t masked[16];
static unsigned maskCount;
static int cpuidOn, tscOn, logFd = -1, ownerPid;
static unsigned long vdso;

/* A use per process: kind (1 cpuid, 2 rdtsc, 3 rdtscp) | vdso << 2 | subleaf << 3 | leaf << 32. */
struct seen { unsigned long long key; unsigned long count; };
static struct seen seen[512];

static struct ksigaction app;   /* what the program asked for SIGSEGV */
static int haveApp;
static int (*realSigaction)(int, const struct ksigaction*, struct ksigaction*);

static int subleaves(uint32_t l)
{
    return l == 4 || l == 7 || l == 0xb || l == 0xd || l == 0xf || l == 0x10 || l == 0x12 || l == 0x14 ||
           l == 0x17 || l == 0x18 || l == 0x1a || l == 0x1b || l == 0x1d || l == 0x1e || l == 0x1f || l == 0x20 ||
           l == 0x23 || l == 0x24 || l == 0x8000001d || l == 0x80000020;
}

/* Leaves whose values differ between cores (APIC ids; on a hybrid CPU also the core type, a P or E
 * core's caches, TLBs, power and frequency: all of these on an i5-14400; AMD's ids in 0x8000001e). */
static const uint32_t coreLeaves[] = {1, 4, 6, 0xb, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1f, 0x80000006, 0x8000001e};
enum { CORE_LEAVES = sizeof(coreLeaves) / sizeof(coreLeaves[0]), CORE_SUBLEAVES = 64 };
struct core { uint32_t read, r[CORE_LEAVES][CORE_SUBLEAVES][4]; };
static struct core* cores;   /* by CPU number, read before faulting is armed */
static unsigned coreCount;

static int coreLeaf(uint32_t l)
{
    for (int i = 0; i < CORE_LEAVES; i++) {
        if (coreLeaves[i] == l) return i;
    }
    return -1;
}

/* The CPU this thread runs on, as the vDSO's getcpu reads it: the limit of the per-CPU GDT segment
 * (selector 15 * 8 + 3) is node << 12 | cpu. LSL is no syscall and never faults; ~0u if it fails. */
static unsigned currentCpu(void)
{
    unsigned limit = 0;
    int ok;
    __asm__ volatile("lsl %[selector], %[limit]" : [limit] "=r"(limit), "=@ccz"(ok) : [selector] "r"(15u * 8 + 3));
    return ok ? limit & 0xfff : ~0u;
}

/* The per-core leaves on each CPU of the affinity mask, moving there to read them: a trap then answers
 * for the core it runs on with no syscall (Chrome's seccomp sandbox kills on arch_prctl, and kfilter's
 * arch_prctl deny would charge an untrap to the program). A CPU missing here reads as the snapshot's. */
static void readCores(void)
{
    enum { WORDS = 1024 / (8 * sizeof(unsigned long)), BITS = 8 * sizeof(unsigned long) };
    unsigned long all[WORDS] = {0};
    unsigned last = 0;
    if (sys3(NR_sched_getaffinity, 0, sizeof(all), (long)all) <= 0) return;
    for (unsigned cpu = 0; cpu < WORDS * BITS; cpu++) {
        if (all[cpu / BITS] >> cpu % BITS & 1) last = cpu;
    }
    void* table = mmap(0, (last + 1) * sizeof(struct core), 3, 0x22, -1, 0);   /* RW, PRIVATE|ANONYMOUS */
    if (table == (void*)-1l) return;
    cores = table;
    coreCount = last + 1;
    for (unsigned cpu = 0; cpu <= last; cpu++) {
        unsigned long one[WORDS] = {0};
        one[cpu / BITS] = all[cpu / BITS] & 1ul << cpu % BITS;
        if (one[cpu / BITS] == 0 || sys3(NR_sched_setaffinity, 0, sizeof(one), (long)one) != 0 || currentCpu() != cpu) {
            continue;
        }
        for (int i = 0; i < CORE_LEAVES; i++) {
            for (uint32_t s = 0; s < (subleaves(coreLeaves[i]) ? CORE_SUBLEAVES : 1u); s++) {
                uint32_t* r = cores[cpu].r[i][s];
                __cpuid_count(coreLeaves[i], s, r[0], r[1], r[2], r[3]);
            }
        }
        cores[cpu].read = 1;
    }
    sys3(NR_sched_setaffinity, 0, sizeof(all), (long)all);
}

static void snapshot(uint32_t l, uint32_t s)
{
    if (leafCount >= sizeof(leaves) / sizeof(leaves[0])) return;
    struct leaf* e = &leaves[leafCount++];
    e->leaf = l;
    e->sub = s;
    __cpuid_count(l, s, e->r[0], e->r[1], e->r[2], e->r[3]);
}

static void snapshotAll(void)
{
    uint32_t a, b, c, d;
    __cpuid(0, maxBasic, b, c, d);
    intel = b == 0x756e6547 && d == 0x49656e69 && c == 0x6c65746e;   /* GenuineIntel */
    for (uint32_t l = 0; l <= maxBasic && l < 0x40; l++) {
        for (uint32_t s = 0; s < (subleaves(l) ? 64u : 1u); s++) snapshot(l, s);
    }
    __cpuid(1, a, b, c, d);
    int hypervisor = (c >> 31) != 0;
    __cpuid(0x40000000, a, b, c, d);
    if (hypervisor && a >= 0x40000000 && a < 0x40000100) maxHypervisor = a;
    for (uint32_t l = 0x40000000; maxHypervisor != 0 && l <= maxHypervisor && l < 0x40000040; l++) snapshot(l, 0);
    __cpuid(0x80000000, maxExtended, b, c, d);
    for (uint32_t l = 0x80000000; l <= maxExtended && l < 0x80000040; l++) {
        for (uint32_t s = 0; s < (subleaves(l) ? 16u : 1u); s++) snapshot(l, s);
    }
}

/* ---- the log: one line per write, O_APPEND, so processes interleave whole lines ---- */

struct line { char text[200]; unsigned n; };

static void put(struct line* b, const char* text)
{
    while (*text && b->n < sizeof(b->text) - 1) b->text[b->n++] = *text++;
}

static void putHex(struct line* b, unsigned long long value)
{
    char digits[16];
    int n = 0;
    do digits[n++] = "0123456789abcdef"[value & 0xF]; while ((value >>= 4) != 0);
    put(b, "0x");
    while (n > 0 && b->n < sizeof(b->text) - 1) b->text[b->n++] = digits[--n];
}

static void putDec(struct line* b, unsigned long value)
{
    char digits[24];
    int n = 0;
    do digits[n++] = (char)('0' + value % 10); while ((value /= 10) != 0);
    while (n > 0 && b->n < sizeof(b->text) - 1) b->text[b->n++] = digits[--n];
}

static void logUse(unsigned long long key, unsigned long count, unsigned long ip)
{
    if (logFd < 0) return;
    static const char* const kinds[] = {"?", "cpuid", "rdtsc", "rdtscp"};
    char name[17] = {0};
    sys3(NR_prctl, PR_GET_NAME, (long)name, 0);   /* Wine names each process after its .exe */
    struct line b = {{0}, 0};
    put(&b, "kfshim pid=");
    putDec(&b, (unsigned long)sys3(NR_getpid, 0, 0, 0));
    put(&b, " exe=");
    put(&b, name);
    put(&b, sizeof(void*) == 8 ? " bits=64 insn=" : " bits=32 insn=");
    put(&b, kinds[key & 3]);
    if ((key & 3) == 1) {
        put(&b, " leaf=");
        putHex(&b, key >> 32);
        put(&b, " subleaf=");
        putHex(&b, (key >> 3) & 0x1FFFFFFF);
        for (unsigned i = 0; i < maskCount; i++) {
            if (masked[i] == (uint32_t)(key >> 32)) put(&b, " masked=1");
        }
    }
    if (key & 4) put(&b, " vdso=1");
    if (ip != 0) {
        put(&b, " first ip=");
        putHex(&b, ip);
    } else {
        put(&b, " count=");
        putDec(&b, count);
    }
    put(&b, "\n");
    sys3(NR_write, logFd, (long)b.text, b.n);
}

/* Counts a use; the thread that sees it first in this process logs it. Lock-free: a handler can
 * interrupt another on the same thread. */
static void note(unsigned long long key, unsigned long ip)
{
    unsigned h = ((unsigned)(key >> 32) ^ (unsigned)key) * 2654435761u >> 23;
    for (unsigned i = 0; i < 512; i++) {
        struct seen* e = &seen[(h + i) & 511];
        unsigned long long old = __sync_val_compare_and_swap(&e->key, 0ull, key);
        if (old != 0 && old != key) continue;
        if (__atomic_fetch_add(&e->count, 1, __ATOMIC_RELAXED) == 0) logUse(key, 1, ip);
        return;
    }
}

/* ---- the trap ---- */

/* Refuses to go on: a message on stderr and exit 126, the launch's own "cannot run it". */
static void die(const char* text, const char* detail)
{
    struct line b = {{0}, 0};
    put(&b, "kfshim: ");
    put(&b, text);
    put(&b, detail);
    put(&b, "\n");
    sys3(NR_write, 2, (long)b.text, b.n);
    sys3(NR_exit_group, 126, 0, 0);
}

static uint64_t realTsc(int withAux, uint32_t* aux)
{
    uint32_t lo, hi, c = 0;
    sys3(NR_prctl, PR_SET_TSC, PR_TSC_ENABLE, 0);   /* per thread, and only for these two instructions */
    if (withAux) __asm__ volatile("rdtscp" : "=a"(lo), "=d"(hi), "=c"(c));
    else __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    sys3(NR_prctl, PR_SET_TSC, PR_TSC_SIGSEGV, 0);
    *aux = c;
    return ((uint64_t)hi << 32) | lo;
}

/* What the hardware answers, but masked leaves read zeros: a per-core leaf as this thread's core does.
 * Past the highest leaf of its range Intel answers the highest basic leaf (Intel SDM, CPUID), AMD and
 * the others zeros. */
static void answer(uint32_t l, uint32_t s, uint32_t* r)
{
    r[0] = r[1] = r[2] = r[3] = 0;
    for (unsigned i = 0; i < maskCount; i++) {
        if (masked[i] == l) return;
    }
    int core = coreLeaf(l);
    unsigned cpu = core >= 0 ? currentCpu() : ~0u;
    if (cpu < coreCount && cores[cpu].read && (s < CORE_SUBLEAVES || !subleaves(l))) {
        for (int k = 0; k < 4; k++) r[k] = cores[cpu].r[core][subleaves(l) ? s : 0][k];
        return;
    }
    int inRange = l <= maxBasic || (l >= 0x80000000 && l <= maxExtended) || (l >= 0x40000000 && l <= maxHypervisor);
    if (!inRange && !intel) return;
    if (!inRange) l = maxBasic;
    for (unsigned i = 0; i < leafCount; i++) {
        if (leaves[i].leaf == l && (leaves[i].sub == s || !subleaves(l))) {
            for (int k = 0; k < 4; k++) r[k] = leaves[i].r[k];
            return;
        }
    }
}

static int emulate(greg* g)
{
    const unsigned char* ip = (const unsigned char*)(unsigned long)g[R_IP];
    unsigned long long inVdso = vdso != 0 && (unsigned long)ip - vdso < 0x2000 ? 4 : 0;
    if (cpuidOn && ip[0] == 0x0F && ip[1] == 0xA2) {
        uint32_t l = (uint32_t)g[R_AX], s = (uint32_t)g[R_CX], r[4];
        answer(l, s, r);
        g[R_AX] = r[0];
        g[R_BX] = r[1];
        g[R_CX] = r[2];
        g[R_DX] = r[3];
        g[R_IP] += 2;
        note((unsigned long long)l << 32 | (unsigned long long)(s & 0x1FFFFFFF) << 3 | inVdso | 1, (unsigned long)ip);
        return 1;
    }
    int rdtscp = ip[0] == 0x0F && ip[1] == 0x01 && ip[2] == 0xF9;
    if (tscOn && ((ip[0] == 0x0F && ip[1] == 0x31) || rdtscp)) {
        uint32_t aux;
        uint64_t tsc = realTsc(rdtscp, &aux);
        g[R_AX] = (uint32_t)tsc;
        g[R_DX] = (uint32_t)(tsc >> 32);
        if (rdtscp) g[R_CX] = aux;
        g[R_IP] += rdtscp ? 3 : 2;
        note(inVdso | (rdtscp ? 3 : 2), (unsigned long)ip);
        return 1;
    }
    return 0;
}

static void handler(int sig, void* info, void* context)
{
    /* SI_KERNEL is a #GP: the instruction at ip was fetched, so it can be read. */
    if (((int*)info)[2] == SI_KERNEL && emulate((greg*)((char*)context + GREGS))) return;
    if (haveApp && app.handler != SIG_DFL && app.handler != SIG_IGN) {
        if (app.flags & SA_SIGINFO) ((void (*)(int, void*, void*))app.handler)(sig, info, context);
        else ((void (*)(int))app.handler)(sig);
        return;
    }
    /* The program's default: returning re-runs the faulting instruction, which now kills it. */
    struct ksigaction fallback = {SIG_DFL, {0}, 0, 0};
    realSigaction(SIGSEGV, &fallback, 0);
}

/* ---- interposed libc: SIGSEGV actions and the calls that exec ---- */

static void* next(void** slot, const char* name)
{
    if (*slot == 0) *slot = dlsym(RTLD_NEXT, name);
    return *slot;
}

int sigaction(int sig, const struct ksigaction* act, struct ksigaction* old)
{
    if (next((void**)&realSigaction, "sigaction") == 0) return -1;
    if (sig != SIGSEGV || (!cpuidOn && !tscOn)) return realSigaction(sig, act, old);
    if (old != 0) {
        struct ksigaction none = {SIG_DFL, {0}, 0, 0};
        *old = haveApp ? app : none;
    }
    if (act == 0) return 0;
    struct ksigaction mine = *act;   /* the program's mask and flags (SA_ONSTACK: Wine's signal stack) */
    mine.handler = (void*)handler;
    mine.flags |= SA_SIGINFO;
    int result = realSigaction(SIGSEGV, &mine, 0);
    if (result == 0) {
        app = *act;
        haveApp = 1;
    }
    return result;
}

void* signal(int sig, void* handler)
{
    static void* real;
    if (sig != SIGSEGV || (!cpuidOn && !tscOn)) return ((void* (*)(int, void*))next(&real, "signal"))(sig, handler);
    struct ksigaction act = {handler, {0}, SA_RESTART, 0}, old;
    act.mask[0] = 1ul << (SIGSEGV - 1);   /* as glibc's signal(): BSD semantics */
    return sigaction(sig, &act, &old) == 0 ? old.handler : SIG_ERR;
}

/* RDTSC faulting outlives execve, and ld.so reads the TSC before any constructor: each exec runs with
 * it off. shortcut: execl/execle/execlp, system and popen reach exec inside glibc and are not
 * covered (no Wine library uses them for programs); a missed exec dies at start under --trap-rdtsc. */
#define EXEC_OFF(call) do { if (tscOn) sys3(NR_prctl, PR_SET_TSC, PR_TSC_ENABLE, 0); } while (0); \
    int result = call; \
    if (tscOn) sys3(NR_prctl, PR_SET_TSC, PR_TSC_SIGSEGV, 0); \
    return result

typedef char* const* argv_t;
int execve(const char* path, argv_t argv, argv_t envp)
{
    static void* real;
    EXEC_OFF(((int (*)(const char*, argv_t, argv_t))next(&real, "execve"))(path, argv, envp));
}
int execv(const char* path, argv_t argv)
{
    static void* real;
    EXEC_OFF(((int (*)(const char*, argv_t))next(&real, "execv"))(path, argv));
}
int execvp(const char* file, argv_t argv)
{
    static void* real;
    EXEC_OFF(((int (*)(const char*, argv_t))next(&real, "execvp"))(file, argv));
}
int execvpe(const char* file, argv_t argv, argv_t envp)
{
    static void* real;
    EXEC_OFF(((int (*)(const char*, argv_t, argv_t))next(&real, "execvpe"))(file, argv, envp));
}
int posix_spawn(int* pid, const char* path, const void* actions, const void* attributes, argv_t argv, argv_t envp)
{
    static void* real;
    EXEC_OFF(((int (*)(int*, const char*, const void*, const void*, argv_t, argv_t))next(&real, "posix_spawn"))(
        pid, path, actions, attributes, argv, envp));
}
int posix_spawnp(int* pid, const char* file, const void* actions, const void* attributes, argv_t argv, argv_t envp)
{
    static void* real;
    EXEC_OFF(((int (*)(int*, const char*, const void*, const void*, argv_t, argv_t))next(&real, "posix_spawnp"))(
        pid, file, actions, attributes, argv, envp));
}

/* ---- setup ---- */

static int starts(const char* text, const char* prefix)
{
    while (*prefix) {
        if (*text++ != *prefix++) return 0;
    }
    return 1;
}

static uint32_t hex(const char** cursor)
{
    uint32_t value = 0;
    const char* p = *cursor;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
    for (;; p++) {
        int d = *p >= '0' && *p <= '9' ? *p - '0' : *p >= 'a' && *p <= 'f' ? *p - 'a' + 10
              : *p >= 'A' && *p <= 'F' ? *p - 'A' + 10 : -1;
        if (d < 0) break;
        value = value << 4 | (uint32_t)d;
    }
    *cursor = p;
    return value;
}

/* <dir>/config for the shim loaded as <dir>/lib/<multiarch>/libkfshim.so (ld.so's $LIB expanded). */
static int configPath(const char* library, char* path, unsigned size)
{
    unsigned n = 0, slashes = 0;
    while (library[n] != 0) n++;
    while (n > 0 && slashes < 3) slashes += library[--n] == '/';
    if (slashes < 3 || n == 0 || n + sizeof("/config") > size) return 0;
    for (unsigned i = 0; i < n; i++) path[i] = library[i];
    for (unsigned i = 0; i < sizeof("/config"); i++) path[n + i] = "/config"[i];
    return 1;
}

#ifndef KFSHIM_TEST
__attribute__((constructor))
#endif
static void start(void)
{
    char name[17] = {0};
    sys3(NR_prctl, PR_GET_NAME, (long)name, 0);
    /* wineserver serves every program of the prefix, and only its clients are the program. */
    if (starts(name, "wineserver")) return;
    if (next((void**)&realSigaction, "sigaction") == 0) die("no sigaction to interpose", "");
    Dl_info self = {0, 0, 0, 0};
    char where[512] = "?", config[1024];
    long length = -1;
    if (dladdr((void*)start, &self) != 0 && self.dli_fname != 0 && configPath(self.dli_fname, where, sizeof(where))) {
        int fd = open(where, 02000000);   /* RDONLY|CLOEXEC */
        length = fd >= 0 ? read(fd, config, sizeof(config) - 1) : -1;
        if (fd >= 0) close(fd);
    }
    if (length <= 0) die("no trap configuration, so not running untrapped: ", where);
    config[length] = 0;
    int wantCpuid = 0, wantTsc = 0;
    char path[512];
    path[0] = 0;
    for (const char* p = config; *p;) {
        if (*p == ' ') {
            p++;
        } else if (starts(p, "log=")) {
            unsigned n = 0;
            for (p += 4; *p && *p != ' ' && n < sizeof(path) - 1; p++) path[n++] = *p;
            path[n] = 0;
        } else if (starts(p, "mask=")) {
            p += 5;
            while (maskCount < 16) {
                masked[maskCount++] = hex(&p);
                if (*p != ',') break;
                p++;
            }
        } else {
            wantCpuid |= starts(p, "cpuid");
            wantTsc |= starts(p, "rdtsc");
            while (*p && *p != ' ') p++;
        }
    }
    if (path[0] != 0) logFd = open(path, 01 | 02000 | 0100 | 02000000, 0600);   /* WRONLY|APPEND|CREAT|CLOEXEC */
    ownerPid = (int)sys3(NR_getpid, 0, 0, 0);
    vdso = getauxval(AT_SYSINFO_EHDR);
    snapshotAll();
    if (wantCpuid) readCores();

    struct ksigaction mine = {(void*)handler, {0}, SA_SIGINFO, 0};
    if (realSigaction(SIGSEGV, &mine, &app) != 0) die("cannot install its SIGSEGV handler", "");
    haveApp = app.handler != SIG_DFL;
    /* No cpuid_fault on this CPU, or a policy refusing it: the program would run untrapped. */
    cpuidOn = wantCpuid && sys3(NR_arch_prctl, ARCH_SET_CPUID, 0, 0) == 0;
    if (wantCpuid && !cpuidOn) die("cannot turn CPUID faulting on", "");
    tscOn = wantTsc && sys3(NR_prctl, PR_SET_TSC, PR_TSC_SIGSEGV, 0) == 0;
    if (wantTsc && !tscOn) die("cannot turn RDTSC faulting on", "");
}

__attribute__((destructor)) static void finish(void)
{
    if (logFd < 0 || sys3(NR_getpid, 0, 0, 0) != ownerPid) return;   /* a fork child that never exec'd */
    for (unsigned i = 0; i < 512; i++) {
        if (seen[i].key != 0) logUse(seen[i].key, seen[i].count, 0);
    }
}
