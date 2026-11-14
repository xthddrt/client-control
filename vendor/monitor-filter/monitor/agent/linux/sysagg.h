#pragma once
/*
 * Kernel aggregates (bpf/monitor.bpf.c sys_agg into agg): the calls counted per (process, call, key argument) instead
 * of recorded one by one, and the summary record each aggregate becomes when bpf.cpp AggFlush drains agg (every
 * second, before a process's end and at the stop). Header-only, so tests/linux_sysagg_test.cpp checks it offline.
 */
#include "session.h"
#include "bpf/monitor_bpf.h"
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <initializer_list>
#include <iterator>
#include <string>
#include <sys/stat.h>
#include <unordered_map>
#include <utility>
#include <vector>

/* A call aggcfg sets beyond the default (MM_AGG_ENTER without key or range for every number that has no record of
 * its own): mode, key and range as argument index + 1 (0: none), the key's name in the summary; nr64/nr32 the x86_64
 * and ia32 numbers (-1: none), whose arguments sit in the same places. memory: the summary is a file_section
 * (linux.ebpf_memory), else a file_query_information. */
struct AggCall {
    int16_t nr64, nr32;
    uint8_t mode, key, addr, len;
    bool memory;
    const char* keyName;
};

constexpr AggCall kAggCalls[] = {
    /* Memory: anonymous mappings and protections that are not executable (executable ones are records with image_load
     * and anon_pe), and every unmap, remap, advice, sync and lock, with its range. */
    {9, 192, MM_AGG_MMAP, 3, 0, 2, true, "prot"},            /* mmap, mmap2: the range at the address returned */
    {10, 125, MM_AGG_MPROTECT, 3, 1, 2, true, "prot"},
    {329, 380, MM_AGG_MPROTECT, 3, 1, 2, true, "prot"},      /* pkey_mprotect */
    {11, 91, MM_AGG_ENTER, 0, 1, 2, true, nullptr},          /* munmap */
    {12, 45, MM_AGG_ENTER, 0, 1, 0, true, nullptr},          /* brk: the break asked for (0: a query) */
    {25, 163, MM_AGG_MREMAP, 0, 1, 2, true, "prot"},         /* mremap: the old and the new range */
    {26, 144, MM_AGG_ENTER, 3, 1, 2, true, "flags"},         /* msync */
    {28, 219, MM_AGG_ENTER, 3, 1, 2, true, "advice"},        /* madvise */
    {149, 150, MM_AGG_ENTER, 0, 1, 2, true, nullptr},        /* mlock */
    {150, 151, MM_AGG_ENTER, 0, 1, 2, true, nullptr},        /* munlock */
    {151, 152, MM_AGG_ENTER, 1, 0, 0, true, "flags"},        /* mlockall */
    {152, 153, MM_AGG_ENTER, 0, 0, 0, true, nullptr},        /* munlockall */
    {325, 376, MM_AGG_ENTER, 3, 1, 2, true, "flags"},        /* mlock2 */
    {216, 257, MM_AGG_ENTER, 0, 1, 2, true, nullptr},        /* remap_file_pages */
    {237, 274, MM_AGG_ENTER, 3, 1, 2, true, "mode"},         /* mbind */
    {238, 276, MM_AGG_ENTER, 1, 0, 0, true, "mode"},         /* set_mempolicy */
    {239, 275, MM_AGG_ENTER, 5, 4, 0, true, "flags"},        /* get_mempolicy */
    {450, 450, MM_AGG_ENTER, 0, 1, 2, true, nullptr},        /* set_mempolicy_home_node */
    {453, 453, MM_AGG_ENTER, 3, 1, 2, true, "flags"},        /* map_shadow_stack */
    {324, 375, MM_AGG_ENTER, 1, 0, 0, true, "cmd"},          /* membarrier */
    {330, 381, MM_AGG_ENTER, 2, 0, 0, true, "access"},       /* pkey_alloc */
    {331, 382, MM_AGG_ENTER, 1, 0, 0, true, "pkey"},         /* pkey_free */
    /* fcntl: the commands MM_FCNTL_RECORDED names are records; ia32 fcntl (55) runs compat_sys_fcntl64 too. */
    {72, 221, MM_AGG_FCNTL, 2, 0, 0, false, "cmd"},
    {-1, 55, MM_AGG_FCNTL, 2, 0, 0, false, "cmd"},
    /* Keyed by the argument that says what the call does (F4's keys). */
    {8, 19, MM_AGG_ENTER, 3, 0, 0, false, "whence"},         /* lseek */
    {-1, 140, MM_AGG_ENTER, 5, 0, 0, false, "whence"},       /* _llseek(fd, high, low, result, whence) */
    {14, 175, MM_AGG_ENTER, 1, 0, 0, false, "how"},          /* rt_sigprocmask */
    {-1, 126, MM_AGG_ENTER, 1, 0, 0, false, "how"},          /* sigprocmask */
    {202, 240, MM_AGG_ENTER, 2, 1, 0, false, "op"},          /* futex: the range of futex words */
    {-1, 422, MM_AGG_ENTER, 2, 1, 0, false, "op"},           /* futex_time64 */
    {449, 449, MM_AGG_ENTER, 3, 0, 0, false, "flags"},       /* futex_waitv */
    {454, 454, MM_AGG_ENTER, 4, 1, 0, false, "flags"},       /* futex_wake */
    {455, 455, MM_AGG_ENTER, 4, 1, 0, false, "flags"},       /* futex_wait */
    {456, 456, MM_AGG_ENTER, 2, 0, 0, false, "flags"},       /* futex_requeue */
    {233, 255, MM_AGG_ENTER, 2, 0, 0, false, "op"},          /* epoll_ctl */
    {98, 77, MM_AGG_ENTER, 1, 0, 0, false, "who"},           /* getrusage */
    {97, 191, MM_AGG_ENTER, 1, 0, 0, false, "resource"},     /* getrlimit, ia32 ugetrlimit */
    {-1, 76, MM_AGG_ENTER, 1, 0, 0, false, "resource"},      /* ia32 getrlimit (old) */
    {228, 265, MM_AGG_ENTER, 1, 0, 0, false, "clock"},       /* clock_gettime */
    {-1, 403, MM_AGG_ENTER, 1, 0, 0, false, "clock"},        /* clock_gettime64 */
    {229, 266, MM_AGG_ENTER, 1, 0, 0, false, "clock"},       /* clock_getres */
    {-1, 406, MM_AGG_ENTER, 1, 0, 0, false, "clock"},        /* clock_getres_time64 */
    {230, 267, MM_AGG_ENTER, 1, 0, 0, false, "clock"},       /* clock_nanosleep */
    {-1, 407, MM_AGG_ENTER, 1, 0, 0, false, "clock"},        /* clock_nanosleep_time64 */
    {222, 259, MM_AGG_ENTER, 1, 0, 0, false, "clock"},       /* timer_create */
    {36, 105, MM_AGG_ENTER, 1, 0, 0, false, "which"},        /* getitimer */
    {38, 104, MM_AGG_ENTER, 1, 0, 0, false, "which"},        /* setitimer */
    {318, 355, MM_AGG_ENTER, 3, 0, 0, false, "flags"},       /* getrandom */
    {60, 1, MM_AGG_ENTER, 1, 0, 0, false, "code"},           /* exit: a thread's exit code */
    {231, 252, MM_AGG_ENTER, 1, 0, 0, false, "code"},        /* exit_group: the process's */
    {292, 330, MM_AGG_ENTER, 3, 0, 0, false, "flags"},       /* dup3 */
    {293, 331, MM_AGG_ENTER, 2, 0, 0, false, "flags"},       /* pipe2 */
    {290, 328, MM_AGG_ENTER, 2, 0, 0, false, "flags"},       /* eventfd2 */
    {289, 327, MM_AGG_ENTER, 4, 0, 0, false, "flags"},       /* signalfd4 */
    {283, 322, MM_AGG_ENTER, 2, 0, 0, false, "flags"},       /* timerfd_create */
    {291, 329, MM_AGG_ENTER, 1, 0, 0, false, "flags"},       /* epoll_create1 */
    {294, 332, MM_AGG_ENTER, 1, 0, 0, false, "flags"},       /* inotify_init1 */
    {436, 436, MM_AGG_ENTER, 3, 0, 0, false, "flags"},       /* close_range */
    {334, 386, MM_AGG_ENTER, 3, 0, 0, false, "flags"},       /* rseq */
    {146, 159, MM_AGG_ENTER, 1, 0, 0, false, "policy"},      /* sched_get_priority_max */
    {147, 160, MM_AGG_ENTER, 1, 0, 0, false, "policy"},      /* sched_get_priority_min */
    /* A native helper's (xdg-open, a browser) reads, writes, sends and receives, per the fd's inode (records for every
     * other process): its bytes, the first of a key each second a record (monitor.bpf.c native_io). */
    {0, 3, MM_AGG_NATIVE_IO, 1, 0, 0, false, "ino"},         /* read */
    {1, 4, MM_AGG_NATIVE_IO, 1, 0, 0, false, "ino"},         /* write */
    {17, 180, MM_AGG_NATIVE_IO, 1, 0, 0, false, "ino"},      /* pread64 */
    {18, 181, MM_AGG_NATIVE_IO, 1, 0, 0, false, "ino"},      /* pwrite64 */
    {19, 145, MM_AGG_NATIVE_IO, 1, 0, 0, false, "ino"},      /* readv */
    {20, 146, MM_AGG_NATIVE_IO, 1, 0, 0, false, "ino"},      /* writev */
    {295, 333, MM_AGG_NATIVE_IO, 1, 0, 0, false, "ino"},     /* preadv */
    {296, 334, MM_AGG_NATIVE_IO, 1, 0, 0, false, "ino"},     /* pwritev */
    {327, 378, MM_AGG_NATIVE_IO, 1, 0, 0, false, "ino"},     /* preadv2 */
    {328, 379, MM_AGG_NATIVE_IO, 1, 0, 0, false, "ino"},     /* pwritev2 */
    {44, 369, MM_AGG_NATIVE_IO, 1, 0, 0, false, "ino"},      /* sendto */
    {45, 371, MM_AGG_NATIVE_IO, 1, 0, 0, false, "ino"},      /* recvfrom */
    {46, 370, MM_AGG_NATIVE_IO, 1, 0, 0, false, "ino"},      /* sendmsg */
    {47, 372, MM_AGG_NATIVE_IO, 1, 0, 0, false, "ino"},      /* recvmsg */
    {307, 345, MM_AGG_NATIVE_IO, 1, 0, 0, false, "ino"},     /* sendmmsg: no bytes (its result is messages) */
    {299, 337, MM_AGG_NATIVE_IO, 1, 0, 0, false, "ino"},     /* recvmmsg: no bytes */
    {-1, 417, MM_AGG_NATIVE_IO, 1, 0, 0, false, "ino"},      /* recvmmsg_time64: no bytes */
};

/* --native-depth for the sign-in hand-off (a native chain winebrowser.exe starts: xdg-open, the browser's zygote,
 * renderers, crashpad and shell helpers are 4 to 7 execs deep): at least 8, at most the kernel's 64. */
inline uint32_t HandoffDepth(uint64_t nativeDepth)
{
    return static_cast<uint32_t>(std::min<uint64_t>(std::max<uint64_t>(nativeDepth, 8), 64));
}

/* How a process the kernel found joined (MM_SCOPE nr): its first executable mapping under a root (Path the file), the
 * exec of a Wine loader in a directory under one (Path that directory), or the first exec of kfilterctl launch's child
 * (Path its session cgroup, launch-<launcher pid>). */
inline std::wstring ScopeNote(uint32_t nr, const std::wstring& path)
{
    return (nr == MM_SCOPE_WINE_EXEC ? L";scope=wine_exec_cwd:" : nr == MM_SCOPE_LAUNCH ? L";scope=kfilter_launch:"
                                                                                        : L";scope=exec_mapping:") + path;
}

/* prctl's strings (sysinfo reads arg2 into path_a and arg5 into path_b for every option): ";name=" the thread's new
 * name for PR_SET_NAME (15), ";vma_name=" an anonymous range's for PR_SET_VMA (0x53564d41) PR_SET_VMA_ANON_NAME (0). */
inline std::wstring PrctlNames(uint64_t option, uint64_t arg2, const std::wstring& name2, const std::wstring& name5)
{
    if (option == 15) return L";name=" + name2;
    if (option == 0x53564d41 && arg2 == 0) return L";vma_name=" + name5;
    return {};
}

/* The kAggCalls row of a syscall number, or nullptr. */
inline const AggCall* AggFind(bool ia32, uint32_t nr)
{
    for (const AggCall& call : kAggCalls) {
        if ((ia32 ? call.nr32 : call.nr64) == static_cast<int>(nr)) return &call;
    }
    return nullptr;
}

/* One aggregate's per-CPU slots as one; a slot no call reached (first_ns 0) is left out. */
inline mm_agg AggMerge(const mm_agg* slots, size_t count)
{
    mm_agg total{};
    total.lo = ~0ull;
    for (size_t index = 0; index < count; index++) {
        const mm_agg& slot = slots[index];
        if (slot.first_ns == 0) continue;
        total.calls += slot.calls;
        total.errors += slot.errors;
        total.bytes += slot.bytes;
        total.first_ns = total.first_ns == 0 ? slot.first_ns : std::min(total.first_ns, slot.first_ns);
        total.last_ns = std::max(total.last_ns, slot.last_ns);
        total.lo = std::min(total.lo, slot.lo);
        total.hi = std::max(total.hi, slot.hi);
    }
    return total;
}

/* Aggregates of a process the session has not admitted yet (the kernel tracks a child from its fork; its fork or scope
 * record may still be queued), held by bpf.cpp AggFlush until it is. Lost counts the calls of those that never will be:
 * held when every record queued before them has been processed (the copy pass Pass is published and the queue is
 * empty) and still not admitted, or dropped at the process's end (Drop) or at the stop. */
struct AggHeld {
    struct Entry {
        mm_agg_key key;
        mm_agg total;
        uint64_t pass;
    };
    std::vector<Entry> entries;
    uint64_t lost = 0;

    /* Write(key, total) is true once written. Only nonzero: that process's alone (its exit or exec, in the middle of a
     * slice of records, so nothing is dropped). */
    template <class Write> void Retry(Write write, uint32_t only, uint64_t passes, bool queueEmpty)
    {
        std::vector<Entry> waiting;
        for (const Entry& entry : entries) {
            if (only != 0 && entry.key.tgid != only) waiting.push_back(entry);
            else if (write(entry.key, entry.total)) continue;
            else if (only == 0 && queueEmpty && passes >= entry.pass) lost += entry.total.calls;
            else waiting.push_back(entry);
        }
        entries.swap(waiting);
    }

    /* Tgid 0: every process's. */
    void Drop(uint32_t tgid)
    {
        std::vector<Entry> waiting;
        for (const Entry& entry : entries) {
            if (tgid == 0 || entry.key.tgid == tgid) lost += entry.total.calls;
            else waiting.push_back(entry);
        }
        entries.swap(waiting);
    }
};

inline std::wstring AggHex(uint64_t value)
{
    wchar_t text[24];
    swprintf(text, 24, L"0x%llx", static_cast<unsigned long long>(value));
    return text;
}

/* An inode's type as /proc/<pid>/fd names sockets and pipes: socket, pipe, file, dir, char, anon_inode (an eventfd,
 * an epoll). */
inline const wchar_t* InodeKind(uint32_t mode)
{
    return S_ISSOCK(mode) ? L"socket" : S_ISFIFO(mode) ? L"pipe" : S_ISREG(mode) ? L"file" : S_ISDIR(mode) ? L"dir"
           : S_ISCHR(mode) ? L"char" : L"anon_inode";
}

/* A file no path names (a native helper's fd it did not open in scope), by its inode's type: socket:[N], pipe:[N],
 * file:[N], dir:[N], char:[N], anon_inode:[N]. */
inline std::wstring InodeName(uint32_t mode, uint64_t ino)
{
    return std::wstring(InodeKind(mode)) + L":[" + std::to_wstring(ino) + L"]";
}

/* ";ino=<N>;inode_type=<kind>" of a native helper's I/O aggregate key (MM_NATIVE_IO_KEY: the type in the top 4 bits). */
inline std::wstring NativeIoKey(uint64_t key)
{
    return L";ino=" + AggHex(key & 0x0fffffffffffffffull) + L";inode_type=" + InodeKind(static_cast<uint32_t>(key >> 48) & S_IFMT);
}

/* A native helper's I/O call recorded as the first of its kernel aggregate (MM_F_NATIVE_IO): ino= and inode_type= join
 * it to that aggregate's summaries (system:<call>, ino=, inode_type=). */
inline std::wstring NativeIoNote(uint32_t mode, uint64_t ino)
{
    return L";native_io=sampled" + NativeIoKey(MM_NATIVE_IO_KEY(mode, ino));
}

/* The paths native helpers opened inodes by (tgid -> inode -> its type and the path), naming their MM_F_NATIVE_IO
 * records, which carry no kernel path: the process's own open, else its parent's (an inherited fd), of an inode of the
 * same type (a socket's or pipe's number can equal a file's); else the inode by its type. shortcut: keyed without the
 * device, so a same-type inode of another filesystem with an opened file's number takes its name; carry s_dev in
 * mm_event if that is ever seen. */
struct NativeFiles {
    std::unordered_map<uint32_t, std::unordered_map<uint64_t, std::pair<uint32_t, std::wstring>>> files;

    void Opened(uint32_t tgid, uint64_t ino, uint32_t mode, const std::wstring& path)
    {
        auto& own = files[tgid];
        /* shortcut: closes are not recorded for a native helper, so a browser's cache files would pile up; past 4096
         * its names start over (older inodes named by type); forget an inode at its close if names go missing */
        if (own.size() >= 4096) own.clear();
        own[ino] = {mode & S_IFMT, path};
    }

    std::wstring Name(uint32_t tgid, uint32_t ppid, uint64_t ino, uint32_t mode) const
    {
        for (const uint32_t owner : {tgid, ppid}) {
            const auto table = files.find(owner);
            if (table == files.end()) continue;
            const auto file = table->second.find(ino);
            if (file != table->second.end() && file->second.first == (mode & S_IFMT)) return file->second.second;
        }
        return InodeName(mode, ino);
    }
};

/* A Wine loader's executable (wine, wine64, wine-preloader...: its basename starts with "wine", as mm_exec's wine_image
 * takes it): a process running one is no native helper. */
inline bool WineLoader(const std::wstring& exe)
{
    return exe.compare(exe.rfind(L'/') + 1, 4, L"wine") == 0;
}

/* An aggregate's summary in the repeats_tail form (as the agent's own collapse writes the calls it counted):
 * text system:<name>, value0 the ranges' bytes, value1 the calls, detail
 * repeats_tail;syscall=<name>;aggregate=kernel[;<key name>=<key>];repeats_before=<calls>;repeat_bytes=;repeat_span_us=;
 * errors=<failed calls>[;repeat_offsets=<lowest>-<highest end>]. Name: the call, "ia32:<name>" for an ia32 one;
 * Call its kAggCalls row (nullptr: no key, not memory). The caller sets pid, start and timestamp. */
inline LinuxRecord AggSummary(const std::string& name, const AggCall* call, uint64_t key, const mm_agg& total)
{
    const bool memory = call != nullptr && call->memory;
    const std::wstring wide(name.begin(), name.end());
    LinuxRecord record;
    record.sensor = memory ? MSMON_SENSOR_LINUX_EBPF_MEMORY : MSMON_SENSOR_LINUX_EBPF_FILE;
    record.type = memory ? MsMonFileSection : MsMonFileQueryInformation;
    record.value0 = total.bytes;
    record.value1 = total.calls;
    record.text = L"system:" + wide;
    record.detail = L"repeats_tail;syscall=" + wide + L";aggregate=kernel";
    if (call != nullptr && call->mode == MM_AGG_NATIVE_IO)
        record.detail += NativeIoKey(key);
    else if (call != nullptr && call->keyName != nullptr)
        record.detail += L";" + std::wstring(call->keyName, call->keyName + strlen(call->keyName)) + L"=" + AggHex(key);
    record.detail += L";repeats_before=" + std::to_wstring(total.calls) + L";repeat_bytes=" + std::to_wstring(total.bytes) +
                     L";repeat_span_us=" + std::to_wstring((total.last_ns - total.first_ns) / 1000) + L";errors=" +
                     std::to_wstring(total.errors);
    if (total.lo <= total.hi) record.detail += L";repeat_offsets=" + AggHex(total.lo) + L"-" + AggHex(total.hi);
    return record;
}

/* ---- Kernel events summarized in agg (kev.bpf.h): a process's own fault signals and outside processes' access checks;
 * calls stopped before sys_enter are syscall summaries (bpf.cpp CountName: seccomp:, dispatch:). The first two are
 * observer coverage records of the tracked process, not process_handle: no kfilter decision is theirs, and an outside
 * actor's check is not the tracked process's action (process_handle's process_id is always the actor). ---- */

/* "sig<name>" of a signal number, or "sig<number>" for a realtime one. */
inline std::wstring SignalName(uint64_t sig)
{
    static const wchar_t* const names[] = {L"0",    L"hup",  L"int",  L"quit", L"ill",    L"trap", L"abrt", L"bus",  L"fpe",
                                           L"kill", L"usr1", L"segv", L"usr2", L"pipe",   L"alrm", L"term", L"stkflt",
                                           L"chld", L"cont", L"stop", L"tstp", L"ttin",   L"ttou", L"urg",  L"xcpu", L"xfsz",
                                           L"vtalrm", L"prof", L"winch", L"io", L"pwr", L"sys"};
    return L"sig" + (sig < std::size(names) ? std::wstring(names[sig]) : std::to_wstring(sig));
}

/* A fault signal's si_code by name (asm-generic/siginfo.h); the kernel's and a sender's codes for any signal. */
inline std::wstring SignalCodeName(uint64_t sig, int64_t code)
{
    if (code == 0x80) return L"si_kernel";   /* x86's int3 and #GP: the trap is not told apart */
    if (code <= 0) return code == 0 ? L"si_user" : code == -6 ? L"si_tkill" : code == -1 ? L"si_queue" : L"si_" + std::to_wstring(code);
    struct Names {
        uint64_t sig;
        const wchar_t* prefix;
        std::initializer_list<const wchar_t*> names;
    };
    static const Names table[] = {
        {4, L"ill_", {L"illopc", L"illopn", L"illadr", L"illtrp", L"prvopc", L"prvreg", L"coproc", L"badstk"}},
        {5, L"trap_", {L"brkpt", L"trace", L"branch", L"hwbkpt", L"unk", L"perf"}},
        {7, L"bus_", {L"adraln", L"adrerr", L"objerr", L"mceerr_ar", L"mceerr_ao"}},
        {8, L"fpe_", {L"intdiv", L"intovf", L"fltdiv", L"fltovf", L"fltund", L"fltres", L"fltinv", L"fltsub"}},
        {11, L"segv_", {L"maperr", L"accerr", L"bnderr", L"pkuerr", L"accadi", L"adiderr", L"adiperr", L"mteaerr", L"mteserr", L"cperr"}},
        {31, L"sys_", {L"seccomp", L"user_dispatch"}},
    };
    for (const Names& row : table) {
        if (row.sig == sig && static_cast<size_t>(code) <= row.names.size()) return row.prefix + std::wstring(row.names.begin()[code - 1]);
    }
    return L"code_" + std::to_wstring(code);
}

/* The detail of a fault signal's first record of its (signal, code, ip page) (MM_KEV_SELFSIG): ip and si_addr (the
 * faulting address; the instruction for SIGILL/SIGFPE/SIGTRAP), the trap and page-fault error code (bit 1 a write,
 * bit 4 an instruction fetch), SIGTRAP's debug status (dr6: bits 0-3 the hardware breakpoint hit, 14 a single step),
 * SIGSYS's syscall. */
inline std::wstring SelfSignalDetail(uint64_t sig, int64_t code, uint64_t ip, uint64_t addr, uint64_t trapError, uint64_t extra)
{
    std::wstring detail = L"self_signal;signal=" + std::to_wstring(sig) + L";name=" + SignalName(sig) + L";code=" +
                          std::to_wstring(code) + L";code_name=" + SignalCodeName(sig, code) + L";ip=" + AggHex(ip) +
                          L";addr=" + AggHex(addr) + L";trap=" + std::to_wstring(trapError >> 32) + L";error_code=" +
                          AggHex(trapError & 0xffffffffu);
    if (sig == 5) detail += L";dr6=" + AggHex(extra);
    if (sig == 31) detail += L";syscall=" + std::to_wstring(static_cast<int32_t>(extra)) + L";arch=" + AggHex(extra >> 32);
    return detail;
}

/* The summary of a fault signal's aggregate (key: si_code << 48 | ip page): coverage self_signal, value1 the faults,
 * repeat_offsets the fault addresses' range. */
inline LinuxRecord SelfSignalSummary(uint32_t sig, uint64_t key, const mm_agg& total)
{
    LinuxRecord record = AggSummary("self_signal", nullptr, 0, total);
    const int64_t code = static_cast<int16_t>(key >> 48);
    const std::wstring fields = L";signal=" + std::to_wstring(sig) + L";name=" + SignalName(sig) + L";code=" + std::to_wstring(code) +
                                L";code_name=" + SignalCodeName(sig, code) + L";ip_page=" + AggHex((key & 0xffffffffffffull) << 12);
    record.detail.insert(record.detail.find(L";repeats_before="), fields);
    record.sensor = MSMON_SENSOR_LINUX_EBPF_MEMORY;
    record.type = MsMonCoverage;
    record.flags = MsMonFlagObserverRecord;
    record.text = L"self_signal";
    record.value0 = 0;
    return record;
}

/* PTRACE_MODE_* bits by name. */
inline std::wstring PtraceModeNames(uint64_t mode)
{
    static const std::pair<uint64_t, const wchar_t*> bits[] = {{0x01, L"read"}, {0x02, L"attach"}, {0x04, L"noaudit"},
                                                               {0x08, L"fscreds"}, {0x10, L"realcreds"}};
    std::wstring names;
    for (const auto& [bit, name] : bits)
        if (mode & bit) names += (names.empty() ? L"" : L"|") + std::wstring(name);
    return names;
}

/* The detail of an outside actor's access check on a tracked process (MM_KEV_OUTSIDE, or its summary's fields): the
 * actor, the PTRACE_MODE_* bits, the actor's syscall (Call: its name, "ia32:<name>" for an ia32 one) and the result. */
inline std::wstring OutsideFields(uint64_t actor, uint64_t mode, const std::string& call)
{
    return L";actor_pid=" + std::to_wstring(actor) + L";mode=" + AggHex(mode) + L";mode_names=" + PtraceModeNames(mode) +
           L";call=" + std::wstring(call.begin(), call.end());
}

/* The summary of an outside actor's aggregate (key: actor << 32 | mode << 24 | its syscall): coverage outside_access of
 * the target, target_process_id the actor, actor_exe= its executable as its first record named it (Exe, else
 * pid:<actor>). */
inline LinuxRecord OutsideSummary(uint64_t key, const std::string& call, const std::wstring& exe, const mm_agg& total)
{
    LinuxRecord record = AggSummary("outside_access", nullptr, 0, total);
    record.detail.insert(record.detail.find(L";repeats_before="),
                         OutsideFields(key >> 32, (key >> 24) & 0xff, call) + L";actor_exe=" +
                             (!exe.empty() ? exe : L"pid:" + std::to_wstring(key >> 32)));
    record.sensor = MSMON_SENSOR_LINUX_EBPF_MEMORY;
    record.type = MsMonCoverage;
    record.flags = MsMonFlagObserverRecord;
    record.text = L"outside_access";
    record.target = static_cast<DWORD>(key >> 32);
    record.value0 = 0;
    return record;
}

/* A process's or thread's exit (do_exit's code, as a wait status): ";exit_code=<hex>" and ";exit_status=<n>" for an
 * exit, or ";signal=<n>[;core_dumped=1]" for a death by signal. */
inline std::wstring ExitDetail(uint64_t code)
{
    std::wstring detail = L";exit_code=" + AggHex(code);
    if ((code & 0x7f) == 0) return detail + L";exit_status=" + std::to_wstring((code >> 8) & 0xff);
    return detail + L";signal=" + std::to_wstring(code & 0x7f) + ((code & 0x80) ? L";core_dumped=1" : L"");
}

/* The environment an exec started with (NUL-separated NAME=value variables) as process_environment details (UTF-8)
 * of at most Limit bytes each: "<NAME>=<value>" for a launcher or Wine/graphics configuration variable (WINE*, LD_*,
 * DXVK_*, VKD3D_*, MESA_*, __GL_*, PROTON_*, DISPLAY, WAYLAND_DISPLAY) and, with Values (--log-environment), for every
 * one; otherwise "<NAME>=withheld:<bytes>", since a value may hold a secret the user exported. ';' becomes ','. */
inline std::vector<std::string> EnvironmentParts(const std::string& env, bool values, size_t limit = 1000)
{
    static const char* const shown[] = {"WINE", "LD_", "DXVK_", "VKD3D_", "MESA_", "__GL_", "PROTON_", "DISPLAY=", "WAYLAND_DISPLAY="};
    std::vector<std::string> parts;
    for (size_t at = 0, end; at < env.size(); at = end + 1) {
        end = std::min(env.find('\0', at), env.size());
        const std::string variable = env.substr(at, end - at);
        const size_t equals = variable.find('=');
        if (equals == std::string::npos) continue;
        bool show = values;
        for (const char* prefix : shown) show = show || variable.rfind(prefix, 0) == 0;
        std::string item = show ? variable : variable.substr(0, equals + 1) + "withheld:" + std::to_string(variable.size() - equals - 1);
        std::replace(item.begin(), item.end(), ';', ',');
        /* a variable longer than Limit is a part of its own, which the record limit cuts (flagged truncated_detail) */
        if (parts.empty() || parts.back().size() + 1 + item.size() > limit) parts.emplace_back();
        parts.back() += (parts.back().empty() ? "" : ";") + item;
    }
    return parts;
}

/* ---- Per-address detail of syscall records (bpf.cpp OnSyscall). ---- */

/* The process another process's /proc/<pid>/ path names (its maps, smaps, pagemap, mem, environ...), or 0. */
inline DWORD ProcTarget(const std::wstring& path, uint32_t self)
{
    if (path.compare(0, 6, L"/proc/") != 0 || path.size() < 7 || path[6] < L'0' || path[6] > L'9') return 0;
    const unsigned long pid = std::wcstoul(path.c_str() + 6, nullptr, 10);
    return pid != self && pid <= 0xffffffffu ? static_cast<DWORD>(pid) : 0;
}

/* /proc/<pid>/mem or pagemap (also under task/<tid>/): a read's offset there is an address (pagemap's: its page
 * number * 8), so it keys the collapse and every address read keeps its record. */
inline bool ProcAddressFile(const std::wstring& path)
{
    const size_t slash = path.rfind(L'/');
    if (path.compare(0, 6, L"/proc/") != 0 || slash == std::wstring::npos || slash <= 6) return false;
    const std::wstring name = path.substr(slash + 1);
    return (name == L"mem" || name == L"pagemap") && path[slash - 1] >= L'0' && path[slash - 1] <= L'9';
}

/* The remote array mm_sys_enter copied (MM_F_RIOV: sock_len bytes of path_b) as "base:len,..." (Pairs: iovecs) or
 * "address,...", ia32 elements half as wide; ",+" when Count says the call passed more than MM_RIOV_MAX. */
inline std::wstring RemoteList(const mm_event& e, bool pairs, uint64_t count)
{
    if ((e.flags & MM_F_RIOV) == 0) return {};
    const size_t word = (e.flags & MM_F_COMPAT) != 0 ? 4 : 8, element = pairs ? 2 * word : word;
    std::wstring list;
    for (size_t at = 0; at + element <= std::min<size_t>(e.sock_len, sizeof(e.path_b)); at += element) {
        uint64_t base = 0, length = 0;
        std::memcpy(&base, e.path_b + at, word);
        if (pairs) std::memcpy(&length, e.path_b + at + word, word);
        list += (list.empty() ? L"" : L",") + AggHex(base) + (pairs ? L":" + AggHex(length) : L"");
    }
    if (count > MM_RIOV_MAX) list += L",+";
    return list;
}
