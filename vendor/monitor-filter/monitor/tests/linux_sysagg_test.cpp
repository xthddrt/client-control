/* Offline checks of the kernel aggregates' agent side (agent/linux/sysagg.h): the per-CPU merge, the summary record
 * (repeats_tail form), native helpers' I/O and its sampled record, the hand-off's depth, the scope notes, the fcntl
 * commands that stay records, prctl's names, the aggcfg table against the ia32 map
 * (bpf_ia32.inc), the aggregates held for processes not admitted yet, and the records of the kernel events summarized
 * there (fault signals, outside actors), exit codes, the environment at exec and the per-address detail. The kernel
 * side is checked by tests/ebpf_checks/sysall.sh, gaps.sh and scope.sh (root). */
#include "../agent/linux/sysagg.h"
#include <cstring>
#include <iostream>
#include <set>
#include <utility>

static bool Check(bool condition, const char* message)
{
    if (!condition) std::cerr << "FAIL: " << message << "\n";
    return condition;
}

/* The ia32 numbers a record names (bpf_ia32.inc rows below MM_SYSCALLS: the multiplexers' subcalls are above). */
static const unsigned kIa32Mapped[] = {
#define MM_IA32(name32, nr32, name64) nr32,
#include "../agent/linux/bpf_ia32.inc"
#undef MM_IA32
};

int main()
{
    bool ok = true;

    /* Merge: slots no call reached are left out; sums, earliest first, latest last, widest range. */
    mm_agg slots[4] = {};
    slots[0] = {3, 1, 0x2000, 1000, 5000, 0x7000, 0x8000};
    slots[2] = {2, 0, 0x1000, 800, 9000, 0x5000, 0x6000};
    slots[3].lo = ~0ull;   /* touched by a failure only: counted, no range */
    slots[3].first_ns = 2000, slots[3].last_ns = 2000, slots[3].errors = 4;
    const mm_agg total = AggMerge(slots, 4);
    ok &= Check(total.calls == 5 && total.errors == 5 && total.bytes == 0x3000, "merge sums calls, errors and bytes");
    ok &= Check(total.first_ns == 800 && total.last_ns == 9000, "merge keeps the earliest first and latest last call");
    ok &= Check(total.lo == 0x5000 && total.hi == 0x8000, "merge keeps the lowest address and the highest end");
    mm_agg none[2] = {};
    ok &= Check(AggMerge(none, 2).first_ns == 0 && AggMerge(none, 2).lo > AggMerge(none, 2).hi,
                "a key whose slots are all empty merges to no call and no range");

    /* Summaries: a memory call with its range, a keyed call, an ia32 call, a call without row (no key). */
    const AggCall* munmap = AggFind(false, 11);
    ok &= Check(munmap != nullptr && munmap->memory && munmap->addr == 1 && munmap->len == 2, "munmap: memory, arg1+arg2");
    LinuxRecord record = AggSummary("munmap", munmap, 0, total);
    ok &= Check(record.sensor == MSMON_SENSOR_LINUX_EBPF_MEMORY && record.type == MsMonFileSection, "memory summary type");
    ok &= Check(record.text == L"system:munmap" && record.value0 == 0x3000 && record.value1 == 5, "summary text and values");
    ok &= Check(record.detail == L"repeats_tail;syscall=munmap;aggregate=kernel;repeats_before=5;repeat_bytes=12288;"
                                 L"repeat_span_us=8;errors=5;repeat_offsets=0x5000-0x8000",
                "memory summary detail");
    mm_agg futexTotal = {7, 2, 0, 1000000, 3000000, 0x10, 0x10};
    record = AggSummary("futex", AggFind(false, 202), 0x81, futexTotal);
    ok &= Check(record.sensor == MSMON_SENSOR_LINUX_EBPF_FILE && record.type == MsMonFileQueryInformation, "other summary type");
    ok &= Check(record.detail == L"repeats_tail;syscall=futex;aggregate=kernel;op=0x81;repeats_before=7;repeat_bytes=0;"
                                 L"repeat_span_us=2000;errors=2;repeat_offsets=0x10-0x10",
                "keyed summary detail (futex op, the futex word's address)");
    mm_agg seek = {1, 0, 0, 5, 5, ~0ull, 0};
    record = AggSummary("ia32:_llseek", AggFind(true, 140), 2, seek);
    ok &= Check(record.text == L"system:ia32:_llseek" &&
                    record.detail == L"repeats_tail;syscall=ia32:_llseek;aggregate=kernel;whence=0x2;repeats_before=1;"
                                     L"repeat_bytes=0;repeat_span_us=0;errors=0",
                "ia32 summary: its own name and key, no range");
    record = AggSummary("getpid", AggFind(false, 39), 0, seek);
    ok &= Check(record.detail.find(L"aggregate=kernel;repeats_before=1;") != std::wstring::npos, "a call without row has no key");

    /* A native helper's I/O: per the fd's inode with its bytes, no range; its first call of the second a record of its
     * own naming the inode (and the file the helper opened it by, else the inode's type). */
    for (const auto& [nr64, nr32] : {std::pair{0, 3}, std::pair{1, 4}, std::pair{44, 369}, std::pair{45, 371}, std::pair{46, 370},
                                     std::pair{47, 372}, std::pair{307, 345}, std::pair{299, 337}, std::pair{20, 146}}) {
        const AggCall* io = AggFind(false, nr64);
        ok &= Check(io != nullptr && io->mode == MM_AGG_NATIVE_IO && io->key == 1 && !io->addr && !io->memory &&
                        AggFind(true, nr32) == io && std::strcmp(io->keyName, "ino") == 0,
                    "native I/O rows: both ABIs, keyed by the fd's inode, no range");
    }
    mm_agg sent = {41, 3, 9000, 1000000, 2000000, ~0ull, 0};
    record = AggSummary("sendmsg", AggFind(false, 46), MM_NATIVE_IO_KEY(S_IFSOCK | 0777, 0x1f2e), sent);
    ok &= Check(record.text == L"system:sendmsg" && record.value0 == 9000 && record.value1 == 41 &&
                    record.detail == L"repeats_tail;syscall=sendmsg;aggregate=kernel;ino=0x1f2e;inode_type=socket;"
                                     L"repeats_before=41;repeat_bytes=9000;repeat_span_us=1000;errors=3",
                "native I/O summary: its calls, failures and bytes per inode and its type");
    ok &= Check(MM_NATIVE_IO_KEY(S_IFSOCK | 0777, 41) != MM_NATIVE_IO_KEY(S_IFREG | 0644, 41) &&
                    MM_NATIVE_IO_KEY(S_IFREG | 0644, 41) == MM_NATIVE_IO_KEY(S_IFREG | 0600, 41) &&
                    NativeIoKey(MM_NATIVE_IO_KEY(S_IFREG, 0xfffffffffull)) == L";ino=0xfffffffff;inode_type=file",
                "native I/O keys: a socket and a file of one inode number apart");
    ok &= Check(NativeIoNote(S_IFIFO | 0600, 0x1f2e) == L";native_io=sampled;ino=0x1f2e;inode_type=pipe" &&
                    NativeIoNote(0, 0) == L";native_io=sampled;ino=0x0;inode_type=anon_inode",
                "native I/O sample note: the summary's ino= and inode_type=");
    /* Naming a sampled record: the helper's own open, its parent's (an inherited fd), the type must match. */
    NativeFiles files;
    files.Opened(10, 41, S_IFREG | 0644, L"/home/u/.config/a");
    files.Opened(9, 42, S_IFREG | 0644, L"/tmp/parent");
    files.Opened(10, 42, S_IFDIR | 0755, L"/tmp/own-dir");
    ok &= Check(files.Name(10, 9, 41, S_IFREG | 0600) == L"/home/u/.config/a" &&
                    files.Name(10, 9, 42, S_IFREG | 0644) == L"/tmp/parent" && files.Name(10, 9, 42, S_IFDIR) == L"/tmp/own-dir" &&
                    files.Name(10, 9, 41, S_IFSOCK | 0777) == L"socket:[41]" && files.Name(11, 12, 41, S_IFREG) == L"file:[41]",
                "native files: own, the parent's, by type, else the inode's type");
    for (uint64_t ino = 100; ino < 100 + 4094; ino++) files.Opened(10, ino, S_IFREG, L"/f");   /* and 41, 42 */
    ok &= Check(files.Name(10, 0, 41, S_IFREG) == L"/home/u/.config/a" && files.files[10].size() == 4096, "native files: 4096 kept");
    files.Opened(10, 99, S_IFREG, L"/g");
    ok &= Check(files.files[10].size() == 1 && files.Name(10, 0, 41, S_IFREG) == L"file:[41]" && files.Name(10, 0, 99, S_IFREG) == L"/g",
                "native files: past 4096 a process's names start over");
    ok &= Check(WineLoader(L"/usr/bin/wine") && WineLoader(L"/usr/lib/wine/wine64-preloader") && WineLoader(L"wineserver") &&
                    !WineLoader(L"/opt/google/chrome/chrome") && !WineLoader(L"/usr/bin/xdg-open") && !WineLoader(L"/winex/sh") &&
                    !WineLoader(L"/usr/bin/win"),
                "a Wine loader by its executable's name");
    ok &= Check(InodeName(S_IFSOCK | 0777, 41) == L"socket:[41]" && InodeName(S_IFIFO | 0600, 7) == L"pipe:[7]" &&
                    InodeName(S_IFREG | 0644, 9) == L"file:[9]" && InodeName(0600, 3) == L"anon_inode:[3]",
                "an unnamed inode by its type");
    ok &= Check(HandoffDepth(3) == 8 && HandoffDepth(0) == 8 && HandoffDepth(12) == 12 && HandoffDepth(500) == 64,
                "the sign-in hand-off's depth: at least 8, at most 64");
    ok &= Check(ScopeNote(0, L"/c/MapleStory.exe") == L";scope=exec_mapping:/c/MapleStory.exe" &&
                    ScopeNote(MM_SCOPE_WINE_EXEC, L"/c") == L";scope=wine_exec_cwd:/c" &&
                    ScopeNote(MM_SCOPE_LAUNCH, L"launch-226212") == L";scope=kfilter_launch:launch-226212",
                "scope notes");
    const auto launchPid = [](const char* text) {
        char name[MM_CGROUP_NAME] = {};
        std::strncpy(name, text, sizeof(name) - 1);   /* as bpf_probe_read_kernel_str leaves it */
        return mm_launch_cgroup_pid(name);
    };
    ok &= Check(launchPid("launch-5") == 5 && launchPid("launch-42") == 42 && launchPid("launch-226212") == 226212 &&
                    launchPid("launch-4194303") == 4194303,
                "a launch cgroup's name gives its launcher's pid");
    ok &= Check(launchPid("launch-") == 0 && launchPid("launch-12a") == 0 && launchPid("launch-0") == 0 &&
                    launchPid("lunch-5") == 0 && launchPid("launch-123456789012345678") == 0 && launchPid("init.scope") == 0,
                "no launcher in any other cgroup's name");

    /* fcntl: signal routing, leases, notification, seals and record locks stay records; the rest are aggregated. */
    for (unsigned cmd : {6u, 7u, 8u, 10u, 13u, 14u, 15u, 37u, 38u, 1024u, 1026u, 1033u})
        ok &= Check(MM_FCNTL_RECORDED(cmd), "an always-recorded fcntl command");
    for (unsigned cmd : {0u, 1u, 2u, 3u, 4u, 5u, 9u, 11u, 12u, 16u, 36u, 1025u, 1030u, 1031u})
        ok &= Check(!MM_FCNTL_RECORDED(cmd), "an aggregated fcntl command");

    ok &= Check(PrctlNames(15, 0x1000, L"MapleSt:disk$0", L"") == L";name=MapleSt:disk$0", "PR_SET_NAME names the thread");
    ok &= Check(PrctlNames(0x53564d41, 0, L"", L"dxvk-heap") == L";vma_name=dxvk-heap", "PR_SET_VMA names the range");
    ok &= Check(PrctlNames(0x53564d41, 1, L"", L"x").empty() && PrctlNames(26, 1, L"x", L"y").empty(),
                "other prctl options name nothing");

    /* The table: arguments in range, one row per number, and against the ia32 map: a call aggregated only in part
     * (MMAP, MPROTECT, FCNTL, NATIVE_IO) is recorded otherwise, so it must be mapped; a wholly aggregated one must not be. */
    const std::set<unsigned> mapped(std::begin(kIa32Mapped), std::end(kIa32Mapped));
    std::set<std::pair<bool, int>> seen;
    for (const AggCall& call : kAggCalls) {
        ok &= Check(call.key <= 6 && call.addr <= 6 && call.len <= 6 && call.mode >= MM_AGG_ENTER && call.mode <= MM_AGG_NATIVE_IO,
                    "a row's arguments and mode are in range");
        ok &= Check(call.nr64 < MM_SYSCALLS && call.nr32 < MM_SYSCALLS && (call.nr64 >= 0 || call.nr32 >= 0), "a row's numbers");
        for (const auto& number : {std::make_pair(false, static_cast<int>(call.nr64)), std::make_pair(true, static_cast<int>(call.nr32))}) {
            if (number.second < 0) continue;
            ok &= Check(seen.insert(number).second, "one row per number");
        }
        if (call.nr32 < 0) continue;
        const bool partial = call.mode == MM_AGG_MMAP || call.mode == MM_AGG_MPROTECT || call.mode == MM_AGG_FCNTL ||
                             call.mode == MM_AGG_NATIVE_IO;
        if (partial != (mapped.count(static_cast<unsigned>(call.nr32)) != 0))
            ok &= Check(false, ("ia32 " + std::to_string(call.nr32) + ": partly aggregated iff recorded").c_str());
    }
    ok &= Check(AggFind(true, 90) == nullptr && mapped.count(90), "ia32 old_mmap is a record (its struct unpacked)");
    ok &= Check(mapped.count(55) && mapped.count(221) && AggFind(true, 55)->mode == MM_AGG_FCNTL,
                "ia32 fcntl and fcntl64 (both compat_sys_fcntl64): records for the recorded commands, aggregates otherwise");
    ok &= Check(AggFind(true, 140)->key == 5 && AggFind(false, 8)->key == 3, "lseek's whence: arg3, _llseek's arg5");

    /* Held aggregates of processes not admitted yet: written once admitted; lost once the queue caught up past them
     * without it, or at the process's end; a process's own retry (its exit, mid-slice) drops nothing. */
    {
        AggHeld held;
        std::set<uint32_t> admitted;
        std::vector<uint32_t> written;
        auto write = [&](const mm_agg_key& key, const mm_agg&) {
            if (!admitted.count(key.tgid)) return false;
            written.push_back(key.tgid);
            return true;
        };
        auto entry = [](uint32_t tgid, uint64_t calls, uint64_t pass) {
            AggHeld::Entry one{};
            one.key.tgid = tgid;
            one.total.calls = calls;
            one.pass = pass;
            return one;
        };
        held.entries = {entry(10, 3, 5), entry(11, 4, 5), entry(12, 5, 9)};
        held.Retry(write, 0, 4, true);
        ok &= Check(held.entries.size() == 3 && held.lost == 0, "held while its pass is not processed");
        held.Retry(write, 0, 5, false);
        ok &= Check(held.entries.size() == 3 && held.lost == 0, "held while records are still queued");
        admitted = {10};
        held.Retry(write, 11, 9, true);
        ok &= Check(held.entries.size() == 3 && written.empty() && held.lost == 0, "a process's own retry touches no other");
        held.Retry(write, 0, 6, true);
        ok &= Check(written == std::vector<uint32_t>{10} && held.lost == 4 && held.entries.size() == 1 &&
                        held.entries[0].key.tgid == 12,
                    "written once admitted; lost once the queue caught up past it unadmitted");
        held.entries.push_back(entry(13, 6, 100));
        held.Drop(12);
        ok &= Check(held.lost == 9 && held.entries.size() == 1, "its end drops a process's held calls");
        held.Drop(0);
        ok &= Check(held.lost == 15 && held.entries.empty(), "the stop drops all");
    }

    /* The agg namespaces (MM_COUNT_*): one bit each, clear of a syscall number, the ia32 bit and a request number. */
    {
        const uint32_t spaces[] = {MM_COUNT_COMPAT, MM_COUNT_WS, MM_COUNT_DIRECT, MM_COUNT_SECCOMP, MM_COUNT_DISPATCH,
                                   MM_COUNT_SIGNAL, MM_COUNT_OUTSIDE};
        uint32_t all = 0;
        for (uint32_t space : spaces) {
            ok &= Check((space & (space - 1)) == 0 && (space & (all | MM_COUNT_OTHER)) == 0, "an agg namespace is a bit of its own");
            all |= space;
        }
    }

    /* A process's own fault signals (MM_KEV_SELFSIG): names, codes, the first record's detail and the summary of a
     * guard-page storm (999 more faults at one ip page, their addresses' range). */
    ok &= Check(SignalName(5) == L"sigtrap" && SignalName(11) == L"sigsegv" && SignalName(31) == L"sigsys" &&
                    SignalName(40) == L"sig40",
                "signal names");
    ok &= Check(SignalCodeName(5, 0x80) == L"si_kernel" && SignalCodeName(5, 4) == L"trap_hwbkpt" &&
                    SignalCodeName(5, 2) == L"trap_trace" && SignalCodeName(11, 2) == L"segv_accerr" &&
                    SignalCodeName(31, 2) == L"sys_user_dispatch" && SignalCodeName(8, 1) == L"fpe_intdiv" &&
                    SignalCodeName(11, 99) == L"code_99" && SignalCodeName(11, 0) == L"si_user" && SignalCodeName(6, -6) == L"si_tkill",
                "si_code names (int3 is SI_KERNEL on x86)");
    ok &= Check(SelfSignalDetail(5, 4, 0x140001234, 0x140001234, 1ull << 32, 0x1) ==
                    L"self_signal;signal=5;name=sigtrap;code=4;code_name=trap_hwbkpt;ip=0x140001234;addr=0x140001234;trap=1;"
                    L"error_code=0x0;dr6=0x1",
                "a hardware breakpoint (DR0) hit: its debug status");
    ok &= Check(SelfSignalDetail(31, 1, 0x7f0000001000, 0x7f0000000ffe, 0, 0xc000003eull << 32 | 39) ==
                    L"self_signal;signal=31;name=sigsys;code=1;code_name=sys_seccomp;ip=0x7f0000001000;addr=0x7f0000000ffe;trap=0;"
                    L"error_code=0x0;syscall=39;arch=0xc000003e",
                "a seccomp trap: its syscall and arch");
    {
        const mm_agg storm = {999, 0, 0, 1000000, 9000000, 0x10000, 0x10000 + 998 * 4096};
        const LinuxRecord summary = SelfSignalSummary(11, 2ull << 48 | 0x140001, storm);
        ok &= Check(summary.type == MsMonCoverage && summary.flags == MsMonFlagObserverRecord &&
                        summary.sensor == MSMON_SENSOR_LINUX_EBPF_MEMORY && summary.text == L"self_signal" &&
                        summary.value1 == 999 && summary.value0 == 0,
                    "a fault storm's summary: one observer coverage record (no process_handle: no decision is its)");
        ok &= Check(summary.detail == L"repeats_tail;syscall=self_signal;aggregate=kernel;signal=11;name=sigsegv;code=2;"
                                      L"code_name=segv_accerr;ip_page=0x140001000;repeats_before=999;repeat_bytes=0;"
                                      L"repeat_span_us=8000;errors=0;repeat_offsets=0x10000-0x3f6000",
                    "a fault storm's summary detail: its ip page and the fault addresses' range");
    }

    /* An outside actor's access checks on a tracked process (MM_KEV_OUTSIDE): mode names and the summary. */
    ok &= Check(PtraceModeNames(0x11) == L"read|realcreds" && PtraceModeNames(0x0a) == L"attach|fscreds", "PTRACE_MODE_* names");
    {
        const mm_agg reads = {40, 0, 0, 2000, 3000, ~0ull, 0};
        const LinuxRecord summary = OutsideSummary(4242ull << 32 | 0x12ull << 24 | 310, "process_vm_readv", L"/usr/bin/scanmem", reads);
        ok &= Check(summary.type == MsMonCoverage && summary.flags == MsMonFlagObserverRecord && summary.target == 4242 &&
                        summary.text == L"outside_access" && summary.value1 == 40,
                    "an outside actor's summary: an observer record of the target naming the actor (not its process_handle)");
        ok &= Check(summary.detail == L"repeats_tail;syscall=outside_access;aggregate=kernel;actor_pid=4242;mode=0x12;"
                                      L"mode_names=attach|realcreds;call=process_vm_readv;actor_exe=/usr/bin/scanmem;"
                                      L"repeats_before=40;repeat_bytes=0;repeat_span_us=1;errors=0",
                    "an outside actor's summary detail");
        ok &= Check(OutsideSummary(7ull << 32 | 0x09ull << 24 | 257, "openat", L"", reads).detail.find(L";actor_exe=pid:7;") !=
                        std::wstring::npos,
                    "an unnamed actor");
    }

    /* Exit codes (do_exit's code as a wait status). */
    ok &= Check(ExitDetail(0x700) == L";exit_code=0x700;exit_status=7" && ExitDetail(0) == L";exit_code=0x0;exit_status=0" &&
                    ExitDetail(9) == L";exit_code=0x9;signal=9" && ExitDetail(0x8b) == L";exit_code=0x8b;signal=11;core_dumped=1",
                "exit codes: a status, a signal, a core dump");

    /* The environment at exec: names, Wine's and the loader's values, the rest withheld unless asked; ';' -> ','. */
    {
        const char raw[] = "WINEPREFIX=/p\0SECRET=abc\0LD_PRELOAD=x.so\0PATH=/bin;/sbin\0NOVALUE\0EMPTY=";
        const std::string env(raw, sizeof(raw));
        auto parts = EnvironmentParts(env, false);
        ok &= Check(parts.size() == 1 && parts[0] == "WINEPREFIX=/p;SECRET=withheld:3;LD_PRELOAD=x.so;PATH=withheld:10;EMPTY=withheld:0",
                    "values withheld but the launcher's and Wine's");
        parts = EnvironmentParts(env, true);
        ok &= Check(parts.size() == 1 && parts[0] == "WINEPREFIX=/p;SECRET=abc;LD_PRELOAD=x.so;PATH=/bin,/sbin;EMPTY=",
                    "--log-environment: every value");
        parts = EnvironmentParts(env, true, 31);
        ok &= Check(parts.size() == 3 && parts[0] == "WINEPREFIX=/p;SECRET=abc" && parts[1] == "LD_PRELOAD=x.so;PATH=/bin,/sbin" &&
                        parts[2] == "EMPTY=",
                    "parts of at most the limit");
        parts = EnvironmentParts(std::string(40, 'A') + "=1", true, 30);
        ok &= Check(parts.size() == 1 && parts[0].size() == 42, "a variable over the limit is a part of its own (the record cuts it)");
    }

    /* Per-address detail: /proc targets, the files whose offset is an address, remote arrays. */
    ok &= Check(ProcTarget(L"/proc/1234/maps", 99) == 1234 && ProcTarget(L"/proc/99/maps", 99) == 0 &&
                    ProcTarget(L"/proc/self/maps", 99) == 0 && ProcTarget(L"/home/proc/1/maps", 99) == 0,
                "/proc/<pid>/ names another process");
    ok &= Check(ProcAddressFile(L"/proc/1234/mem") && ProcAddressFile(L"/proc/1234/task/1240/pagemap") &&
                    !ProcAddressFile(L"/proc/1234/maps") && !ProcAddressFile(L"/tmp/mem") && !ProcAddressFile(L"/proc/mem"),
                "/proc/<pid>/mem and pagemap offsets are addresses");
    {
        mm_event e{};
        e.flags = MM_F_RIOV;
        const uint64_t iov[4] = {0x140001000, 0x10, 0x7ffe0000, 0x2000};
        std::memcpy(e.path_b, iov, sizeof(iov));
        e.sock_len = sizeof(iov);
        ok &= Check(RemoteList(e, true, 2) == L"0x140001000:0x10,0x7ffe0000:0x2000", "every remote iovec with its length");
        ok &= Check(RemoteList(e, true, 17) == L"0x140001000:0x10,0x7ffe0000:0x2000,+", "more than MM_RIOV_MAX: marked");
        ok &= Check(RemoteList(e, false, 4) == L"0x140001000,0x10,0x7ffe0000,0x2000", "move_pages' page addresses");
        const uint32_t compat[4] = {0x401000, 0x20, 0x402000, 0x8};
        std::memcpy(e.path_b, compat, sizeof(compat));
        e.sock_len = sizeof(compat);
        e.flags |= MM_F_COMPAT;
        ok &= Check(RemoteList(e, true, 2) == L"0x401000:0x20,0x402000:0x8", "ia32 iovecs");
        e.flags = 0;
        ok &= Check(RemoteList(e, true, 2).empty(), "nothing copied: nothing listed");
    }

    std::cout << (ok ? "linux sysagg test: PASS" : "linux sysagg test: FAIL") << "\n";
    return ok ? 0 : 1;
}
