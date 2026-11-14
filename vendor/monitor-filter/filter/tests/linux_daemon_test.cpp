// Checks kfilterd's decision logic and its socket protocol without root. Uses the
// daemon objects minus main and fanotify marks, with the test's own child processes
// standing in for the client.
//
//   build.sh builds and runs it as build/linux/kfilterd-test.

#include "../linux/kf_linux.h"
#include "../linux/kfilter_socket.h"
#include "../linux/bpf/kfilter_bpf.h"

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <dirent.h>
#include <elf.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <string>
#include <thread>
#include <vector>

/* kfilterctl's socket client (tool/linux_client.cpp), declared with its underlying
 * types: tool/linux_compat.h's HANDLE differs from the driver shim's. */
bool Ioctl(intptr_t device, uint32_t code, void* input, uint32_t inputLength,
           void* output, uint32_t outputLength, uint32_t* returned);

static int gFailures = 0;
static void Expect(const char* name, bool value)
{
    if (!value) {
        std::printf("FAIL %s\n", name);
        gFailures++;
    }
}

static pid_t Spawn(const std::vector<const char*>& arguments)
{
    pid_t child = fork();
    if (child == 0) {
        execv(arguments[0], (char* const*)arguments.data());
        _exit(127);
    }
    return child;
}

/* Wait until Pid runs an image ending in Suffix (its exec is done). */
static bool WaitForImage(pid_t pid, const std::wstring& suffix)
{
    for (int attempt = 0; attempt < 200; attempt++) {
        std::wstring image = KfExePath(pid);
        if (image.size() >= suffix.size() && image.compare(image.size() - suffix.size(), suffix.size(), suffix) == 0) return true;
        usleep(10000);
    }
    return false;
}

/* Wait until Tid is blocked in syscall Number. */
static bool WaitForSyscall(pid_t tid, long number)
{
    for (int attempt = 0; attempt < 200; attempt++) {
        char text[256] = {};
        int fd = open(("/proc/" + std::to_string(tid) + "/syscall").c_str(), O_RDONLY);
        if (fd >= 0) {
            (void)!read(fd, text, sizeof(text) - 1);
            close(fd);
            if (strtol(text, nullptr, 10) == number) return true;
        }
        usleep(10000);
    }
    return false;
}

static pid_t ChildOf(pid_t parent)
{
    for (int attempt = 0; attempt < 200; attempt++) {
        DIR* proc = opendir("/proc");
        struct dirent* entry;
        while (proc != nullptr && (entry = readdir(proc)) != nullptr) {
            pid_t pid = (pid_t)atoi(entry->d_name);
            KfTask task;
            if (pid > 0 && KfReadTask(pid, task) && task.ppid == parent && WaitForImage(pid, L"/sleep")) {
                closedir(proc);
                return pid;
            }
        }
        if (proc != nullptr) closedir(proc);
        usleep(10000);
    }
    return 0;
}

static void Fill(wchar_t* destination, const wchar_t* source)
{
    wcsncpy(destination, source, KFILTER_MAX_NAME - 1);
}

/* kb_wnamed (KfBpfWineNamed): the Wine requests system rules name past /system/wine/, one bit each. */
static void WineRequestBits()
{
    std::unique_ptr<KFILTER_CONFIG> config(new KFILTER_CONFIG());
    const struct { ULONG targets; const wchar_t* path; } rules[] = {
        {KFILTER_TARGET_SYSTEM, L"/system/wine/get_message"},      /* 122 */
        {KFILTER_TARGET_SYSTEM, L"/system/wine/set_hook*"},        /* 198 */
        {KFILTER_TARGET_SYSTEM, L"/system/wine/d3dkmt_mutex*"},    /* 304, 305 */
        {KFILTER_TARGET_SYSTEM, L"/system/wine/*"},                /* none: a star right after /system/wine/ */
        {KFILTER_TARGET_SYSTEM, L"/system/*"},
        {KFILTER_TARGET_SYSTEM, L"/system/wine"},
        {KFILTER_TARGET_SYSTEM, L"/system/wine/get_message/x"},    /* a deeper path names no request */
        {KFILTER_TARGET_SYSTEM, L"/system/wine/self/get_thread_context"},
        {KFILTER_TARGET_FILE, L"/system/wine/select"},             /* not a system rule */
    };
    for (const auto& rule : rules) {
        KFILTER_RULE& slot = config->Rules[config->RuleCount++];
        slot.Targets = rule.targets;
        Fill(slot.Path, rule.path);
    }
    uint64_t named[KB_WNAMED_WORDS] = {1, 1, 1, 1, 1};
    KfBpfWineNamed(config.get(), named);
    const uint64_t expected[KB_WNAMED_WORDS] = {0, 1ull << (122 - 64), 0, 1ull << (198 - 192), 3ull << (304 - 256)};
    Expect("kb_wnamed: literal and pattern names set their requests' bits, broad and deeper rules none",
           memcmp(named, expected, sizeof(named)) == 0);
}

/* KfBpfKeyedRule: the system rules whose fixed text reaches past /system/wine/<request>/ of a request with keyed
 * decisions, or into /system/rpc, meet the keyed decisions (a target of their own), and no other rule does: not one on
 * the bare request, not a pattern stopping before its key; KfBpfPublicTarget logs the kernel's own targets as public. */
static void KeyedRules()
{
    const struct { const char* path; bool keyed; } rules[] = {
        {"/system/wine/set_hook/13/global", true}, {"/system/wine/set_hook/*", true}, {"/system/wine/ioctl/\\??\\C:/*", true},
        {"/system/wine/new_process/*/debug", true}, {"/system/rpc/367abb81-9844-35f1-ad32-98f038001003/19", true},
        {"/system/rpc*", true}, {"/system/rpc", true}, {"/system/wine/set_hook", false}, {"/system/wine/set_hook*", false},
        {"/system/wine/set_*l", false}, {"/system/wine/*", false}, {"/system/*", false}, {"/system", false},
        {"/system/wine/get_message/x", false}, {"/system/wine/open_mutex/a/b", false},
    };
    KFILTER_RULE rule{};
    rule.Targets = KFILTER_TARGET_SYSTEM;
    int wrong = 0;
    for (const auto& entry : rules) {
        if (KfBpfKeyedRule(rule, entry.path) == entry.keyed) continue;
        std::printf("  keyed %s: %d\n", entry.path, !entry.keyed);
        wrong++;
    }
    rule.Targets = KFILTER_TARGET_FILE;
    Expect("keyed: rules reaching a key alone, never a rule on the bare request or a broader one",
           wrong == 0 && !KfBpfKeyedRule(rule, "/system/wine/set_hook/13/global"));
    Expect("keyed: the kernel's own targets are logged as system, peer and thread-peer",
           KfBpfPublicTarget(KB_TARGET_KEYED) == KFILTER_TARGET_SYSTEM && KfBpfPublicTarget(KB_TARGET_SYSTEM_VALUE) == KFILTER_TARGET_SYSTEM &&
               KfBpfPublicTarget(KB_TARGET_PEER_VALUE) == KFILTER_TARGET_PEER &&
               KfBpfPublicTarget(KB_TARGET_WINDOW) == KFILTER_TARGET_PEER &&
               KfBpfPublicTarget(KB_TARGET_THREAD_VALUE) == KFILTER_TARGET_THREAD_PEER &&
               KfBpfPublicTarget(KFILTER_TARGET_FILE) == KFILTER_TARGET_FILE);
}

/* KfWineProtocol: the number an x86_64 ntdll.so's version check compares the server's with. */
static void WineProtocols()
{
    // A small ELF: .text at file 0x100 (address 0x1100) with `cmp $951,%esi`, `mov $951,%edx` and
    // `lea "version mismatch"(%rip),%rdi`; .rodata at file 0x200 (address 0x3200) with the text.
    std::string file(0x300, '\0');
    Elf64_Ehdr header{};
    memcpy(header.e_ident, ELFMAG, SELFMAG);
    header.e_ident[EI_CLASS] = ELFCLASS64;
    header.e_shoff = 0x240;
    header.e_shentsize = sizeof(Elf64_Shdr);
    header.e_shnum = 3;
    memcpy(&file[0], &header, sizeof(header));
    Elf64_Shdr sections[3] = {};
    sections[1] = {0, SHT_PROGBITS, 0, 0x1100, 0x100, 0x40, 0, 0, 16, 0};
    sections[2] = {0, SHT_PROGBITS, 0, 0x3200, 0x200, 0x40, 0, 0, 16, 0};
    memcpy(&file[0x240], sections, sizeof(sections));
    const unsigned char code[] = {0x81, 0xfe, 0xb7, 0x03, 0x00, 0x00,          /* cmp $0x3b7,%esi */
                                  0xba, 0xb7, 0x03, 0x00, 0x00,                /* mov $0x3b7,%edx */
                                  0x48, 0x8d, 0x3d, 0x00, 0x00, 0x00, 0x00};   /* lea disp(%rip),%rdi */
    memcpy(&file[0x100], code, sizeof(code));
    const int32_t displacement = 0x3200 - (0x1100 + (int32_t)sizeof(code));
    memcpy(&file[0x100 + sizeof(code) - 4], &displacement, 4);
    memcpy(&file[0x200], "version mismatch %d/%d.\n", 24);
    Expect("protocol: the version check's number", KfWineProtocol(file) == 951);
    std::string unchecked = file;
    unchecked[0x101] = 0x90;   /* no compare against it: not the check */
    Expect("protocol: a number nothing compares is none", KfWineProtocol(unchecked) == 0);
    Expect("protocol: Wine 11.0's build string without the check is 930",
           KfWineProtocol(unchecked + std::string("wine-11.0\0", 10)) == 930);
    Expect("protocol: not an ELF file", KfWineProtocol("version mismatch %d/%d") == 0);
    std::FILE* installed = std::fopen("/opt/wine-stable/lib/wine/x86_64-unix/ntdll.so", "rb");
    if (installed != nullptr) {
        std::string data;
        char buffer[1 << 16];
        for (size_t read; (read = std::fread(buffer, 1, sizeof(buffer), installed)) > 0;) data.append(buffer, read);
        std::fclose(installed);
        const unsigned protocol = KfWineProtocol(data);
        const size_t build = data.find(std::string("wine-11.0\0", 10));
        if (build != std::string::npos) {
            Expect("protocol: the installed Wine 11.0 speaks 930", protocol == 930);
            for (size_t at = build; at != std::string::npos; at = data.find(std::string("wine-11.0\0", 10), at))
                data.replace(at, 10, std::string("wine-99.0\0", 10));   /* a point release's string: its check decides */
            Expect("protocol: ... found by its version check, not by its build string", KfWineProtocol(data) == 930);
        } else {
            std::printf("kfilterd-test: /opt/wine-stable speaks wineserver protocol %u\n", protocol);
        }
    }
}

/* KfBpfUprobeFunctions: the functions kb_win32k is attached to in a win32u.so or ntdll.so (this lists them; the loader
 * attaches nothing in the bench, gBenchLayer) and their cookie bits. win32u.so: every export a rule matches as before keys
 * existed, keyed (KB_UP_KEYED) only where a rule's fixed text reaches /system/win32k/<function>/; ntdll.so: only
 * KB_UP_CALLS' functions, named by /system/ntdll, the function, a class or a pattern beginning one, never by a star
 * right after /system/ or by /system. */
static void UprobeAttachCase()
{
    std::unique_ptr<KFILTER_CONFIG> config(new KFILTER_CONFIG());
    const std::map<std::string, uint64_t> win32u = {{"NtUserGetAsyncKeyState", 1}, {"NtUserGetClassName", 2},
                                                    {"NtUserInternalGetWindowText", 3}, {"NtUserGetCursorPos", 4},
                                                    {"NtUserCallHwndParam", 5}, {"NtUserBuildHwndList", 6}};
    const std::map<std::string, uint64_t> ntdll = {{"NtQueryInformationProcess", 1}, {"NtQuerySystemInformation", 2},
                                                   {"NtCreateFile", 3}, {"NtQueryVirtualMemory", 4}, {"NtSetContextThread", 5}};
    using Named = std::map<std::string, uint64_t>;
    auto named = [&](std::vector<const wchar_t*> paths, bool inNtdll, ULONG targets = KFILTER_TARGET_SYSTEM) {
        config->RuleCount = (ULONG)paths.size();
        for (size_t index = 0; index < paths.size(); index++) {
            config->Rules[index] = KFILTER_RULE{};
            config->Rules[index].Action = KFilterActionDeny;
            config->Rules[index].Targets = targets;
            config->Rules[index].RuleId = (ULONG)index + 1;
            Fill(config->Rules[index].Path, paths[index]);
        }
        return KfBpfUprobeFunctions(config.get(), inNtdll, inNtdll ? ntdll : win32u);
    };
    const uint64_t denied = 0xC0000022ull << 32;
    Expect("uprobes: the live loop's function rules attach their functions, keyless, nothing in ntdll.so",
           named({L"/system/win32k/NtUserGetClassName", L"/system/win32k/NtUserBuildHwndList"}, false) ==
                   Named{{"NtUserBuildHwndList", denied}, {"NtUserGetClassName", 0}} &&
               named({L"/system/win32k/NtUserGetClassName"}, true).empty());
    Expect("uprobes: a rule naming a key attaches its function keyed, without its own decision (no rule names it)",
           named({L"/system/win32k/NtUserGetAsyncKeyState/0x00000070"}, false) ==
               Named{{"NtUserGetAsyncKeyState", KB_UP_KEYED | KB_UP_SKIP_FUNCTION | KB_UP_COOKIE(KB_UP_VKEY, 0, 0)}});
    Expect("uprobes: ... and a window key its function, as a window",
           named({L"/system/win32k/NtUserInternalGetWindowText/@*"}, false) ==
               Named{{"NtUserInternalGetWindowText", KB_UP_KEYED | KB_UP_SKIP_FUNCTION | KB_UP_COOKIE(KB_UP_WINDOW, 0, 0)}});
    Expect("uprobes: @other alone skips the function, its own windows and the desktop; a rule on the function keeps it",
           named({L"/system/win32k/NtUserCallHwndParam/@other"}, false) ==
                   Named{{"NtUserCallHwndParam", KB_UP_KEYED | KB_UP_SKIP_FUNCTION | KB_UP_SKIP_SELF | KB_UP_SKIP_DESKTOP |
                                                     KB_UP_COOKIE(KB_UP_WINDOW, 0, 0)}} &&
               named({L"/system/win32k/NtUserCallHwndParam/@other", L"/system/win32k/NtUserCallHwndParam/@desktop",
                      L"/system/win32k/NtUserCallHwndParam"}, false) ==
                   Named{{"NtUserCallHwndParam", KB_UP_KEYED | KB_UP_SKIP_SELF | KB_UP_COOKIE(KB_UP_WINDOW, 0, 0)}});
    const Named every = named({L"/system/win32k/*"}, false);
    bool keyless = every.size() == win32u.size();
    for (const auto& entry : every) keyless = keyless && (entry.second & KB_UP_KEYED) == 0;
    Expect("uprobes: /system/win32k/* attaches every export, keyless", keyless);
    Expect("uprobes: a pattern stopping before the function's keys reaches none, nor its functions",
           named({L"/system/win32k/NtUser*/@other"}, false).empty());
    const uint64_t processInfo = KB_UP_NTDLL | KB_UP_COOKIE(KB_UP_CLASS2, 0, 0) | denied;
    Expect("uprobes: an ntdll.so class attaches its function", named({L"/system/ntdll/NtQueryInformationProcess/7"}, true) ==
                                                                  Named{{"NtQueryInformationProcess", processInfo}});
    Expect("uprobes: ... and the function", named({L"/system/ntdll/NtQueryInformationProcess"}, true) ==
                                               Named{{"NtQueryInformationProcess", processInfo}});
    Expect("uprobes: an ntdll.so function kfilter does not decide attaches nothing",
           named({L"/system/ntdll/NtCreateFile"}, true).empty());
    Expect("uprobes: /system/*, /system, /system/ntd* and a file rule attach nothing in ntdll.so",
           named({L"/system/*", L"/system", L"/system/ntd*"}, true).empty() &&
               named({L"/system/ntdll"}, true, KFILTER_TARGET_FILE).empty());
    const Named space = named({L"/system/ntdll*"}, true), parent = named({L"/system/ntdll"}, true);
    Expect("uprobes: /system/ntdll* and /system/ntdll attach the four it decides, not NtCreateFile",
           space.size() == 4 && space.count("NtCreateFile") == 0 && parent == space);
    Expect("uprobes: a pattern over NtQuery attaches those three", named({L"/system/ntdll/NtQuery*"}, true).size() == 3);
    Expect("uprobes: NtSetContextThread asks write, by its ContextFlags",
           named({L"/system/ntdll/NtSetContextThread"}, true) ==
               Named{{"NtSetContextThread", KB_UP_NTDLL | KB_UP_COOKIE(KB_UP_CONTEXT, 0, 1) | denied}});
}

/* KfWineDispatcher: the function holding ntdll.so's one service table selection, bounded by .eh_frame_hdr's function
 * starts; in the installed Wine 11 too (in Wine 9's, which names it, it is __wine_syscall_dispatcher: checked with
 * readelf, x86_64 and i386). */
static void DispatcherCase()
{
    // A small ELF: one PT_LOAD at address 0x10000 for the whole file, .eh_frame_hdr at file 0x200 (PT_GNU_EH_FRAME)
    // with functions at 0x10100, 0x10140 and 0x10180, the selection at file 0x150.
    std::string file(0x300, '\0');
    Elf64_Ehdr header{};
    memcpy(header.e_ident, ELFMAG, SELFMAG);
    header.e_ident[EI_CLASS] = ELFCLASS64;
    header.e_phoff = 0x40;
    header.e_phentsize = sizeof(Elf64_Phdr);
    header.e_phnum = 2;
    memcpy(&file[0], &header, sizeof(header));
    Elf64_Phdr segments[2] = {};
    segments[0].p_type = PT_LOAD;
    segments[0].p_vaddr = 0x10000;
    segments[0].p_filesz = segments[0].p_memsz = 0x300;
    segments[1].p_type = PT_GNU_EH_FRAME;
    segments[1].p_offset = 0x200;
    segments[1].p_vaddr = 0x10200;
    segments[1].p_filesz = 12 + 3 * 8;
    memcpy(&file[0x40], segments, sizeof(segments));
    const unsigned char head[4] = {1, 0x1b, 0x03, 0x3b};
    const int32_t table[2 + 6] = {0, 3, -0x100, 0, -0xC0, 0, -0x80, 0};
    memcpy(&file[0x200], head, 4);
    memcpy(&file[0x204], table, sizeof(table));
    memcpy(&file[0x150], "\xc1\xeb\x08\x83\xe3\x30", 6);
    uint64_t start = 0, end = 0;
    Expect("dispatcher: the function holding the selection", KfWineDispatcher(file, start, end) && start == 0x140 && end == 0x180);
    std::string twice = file;
    memcpy(&twice[0x170], "\xc1\xeb\x08\x83\xe3\x30", 6);
    Expect("dispatcher: two selections are none", !KfWineDispatcher(twice, start, end));
    std::string none = file;
    none[0x150] = 0;
    Expect("dispatcher: no selection is none", !KfWineDispatcher(none, start, end));
    for (const char* path : {"/opt/wine-stable/lib/wine/x86_64-unix/ntdll.so", "/opt/wine-stable/lib/wine/i386-unix/ntdll.so"}) {
        std::FILE* installed = std::fopen(path, "rb");
        if (installed == nullptr) continue;
        std::string data;
        char buffer[1 << 16];
        for (size_t read; (read = std::fread(buffer, 1, sizeof(buffer), installed)) > 0;) data.append(buffer, read);
        std::fclose(installed);
        const size_t select = data.find("\xc1\xeb\x08\x83\xe3\x30");
        Expect((std::string("dispatcher: found in ") + path).c_str(),
               KfWineDispatcher(data, start, end) && start <= select && select < end && end - start < 0x2000);
        /* Its calls through the service table (call *%r12; i386: call *%edi) return inside it: what a call is decided by. */
        const std::string call = strstr(path, "i386") ? "\xff\xd7" : "\x41\xff\xd4";
        int inside = 0;
        for (size_t at = data.find(call, start); at != std::string::npos && at < end; at = data.find(call, at + 1))
            inside += at + call.size() < end;
        Expect((std::string("dispatcher: its two service table calls return inside it in ") + path).c_str(), inside == 2);
    }
}

/* bpf_loader.cpp: the /system/syscall entry points (kfilter.bpf.c's kb_s_* programs) a policy's rules attach, and what
 * they name of each call (kb_syscall_keys, by ia32 << 9 | number). */
std::vector<std::string> KfBpfSyscallPrograms(const KFILTER_CONFIG* config);
std::map<uint32_t, kb_syscall_named> KfBpfSyscallKeys(const KFILTER_CONFIG* config);

/* What each system rule path attaches: a rule naming nothing attaches nothing, a rule naming one call exactly its entry
 * points (both tables'; a zero-argument call's one), a hot call only with its argument. */
static void SyscallAttachCase()
{
    std::unique_ptr<KFILTER_CONFIG> config(new KFILTER_CONFIG());
    auto attached = [&](std::vector<const wchar_t*> paths) {
        config->RuleCount = (ULONG)paths.size();
        for (size_t index = 0; index < paths.size(); index++) {
            config->Rules[index] = KFILTER_RULE{};
            config->Rules[index].Action = KFilterActionDeny;
            config->Rules[index].Targets = KFILTER_TARGET_SYSTEM;
            config->Rules[index].RuleId = (ULONG)index + 1;
            Fill(config->Rules[index].Path, paths[index]);
        }
        std::vector<std::string> programs = KfBpfSyscallPrograms(config.get());
        std::sort(programs.begin(), programs.end());
        return programs;
    };
    using List = std::vector<std::string>;
    Expect("a policy without syscall rules attaches nothing", attached({}).empty() &&
                                                                  attached({L"/system/uname", L"/system/sysinfo"}).empty());
    Expect("wildcards right after /system/ or /system/syscall/, and the parents, attach nothing",
           attached({L"/system/*", L"/system/syscall/*", L"/system/syscall", L"/system", L"/system/sys*"}).empty());
    Expect("a rule naming getrandom attaches exactly its two entry points",
           attached({L"/system/syscall/getrandom"}) == List{"kb_s_ia32_sys_getrandom", "kb_s_x64_sys_getrandom"});
    Expect("... with its key too", attached({L"/system/syscall/getrandom/0x1"}) ==
                                       List{"kb_s_ia32_sys_getrandom", "kb_s_x64_sys_getrandom"});
    Expect("a zero-argument call has one entry point for both tables",
           attached({L"/system/syscall/getpid"}) == List{"kb_s_do_sys_getpid"});
    Expect("ia32 fcntl and fcntl64 share their entry point",
           attached({L"/system/syscall/fcntl/6"}) == List{"kb_s_ia32_compat_sys_fcntl64", "kb_s_x64_sys_fcntl"});
    Expect("a hot call named without its argument attaches nothing",
           attached({L"/system/syscall/futex", L"/system/syscall/futex/*"}).empty());
    const List futexes = attached({L"/system/syscall/fu*"});
    Expect("a wildcard over futex* attaches the futex2 calls, not futex",
           std::count(futexes.begin(), futexes.end(), "kb_s_x64_sys_futex_wake") == 1 &&
               std::count(futexes.begin(), futexes.end(), "kb_s_x64_sys_futex") == 0);
    Expect("a hot call named with its argument attaches its entry points (ia32 futex and futex_time64 too)",
           attached({L"/system/syscall/futex/9"}) ==
               List{"kb_s_ia32_sys_futex", "kb_s_ia32_sys_futex_time32", "kb_s_x64_sys_futex"});
    const List signals = attached({L"/system/syscall/rt_sig*"});
    Expect("a wildcard over names attaches the calls it reaches, not a hot one among them",
           std::count(signals.begin(), signals.end(), "kb_s_x64_sys_rt_sigaction") == 1 &&
               std::count(signals.begin(), signals.end(), "kb_s_x64_sys_rt_sigprocmask") == 0 &&
               std::count(signals.begin(), signals.end(), "kb_s_ia32_compat_sys_rt_sigaction") == 1);
    Expect("ia32's compat rt_sigreturn has its zero-argument entry point",
           attached({L"/system/syscall/rt_sigreturn"}) == List{"kb_s_do_compat_sys_rt_sigreturn", "kb_s_do_sys_rt_sigreturn"});
    Expect("a socket call attaches ia32's socketcall, which carries it",
           attached({L"/system/syscall/connect"}) ==
               List{"kb_s_ia32_compat_sys_socketcall", "kb_s_ia32_sys_connect", "kb_s_x64_sys_connect"});
    Expect("... and a SysV call ia32's ipc", attached({L"/system/syscall/shmdt"}) ==
                                                List{"kb_s_ia32_compat_sys_ipc", "kb_s_ia32_sys_shmdt", "kb_s_x64_sys_shmdt"});
    /* The keys: literal ones, a wait's class, any for the call itself or a wildcard; text the kernel never writes names
     * none. */
    attached({L"/system/syscall/futex/9", L"/system/syscall/futex/137", L"/system/syscall/wait4/child",
              L"/system/syscall/getrandom", L"/system/syscall/fcntl/0x6", L"/system/syscall/getrandom/0x1",
              L"/system/syscall/fadvise64/4*"});
    const std::map<uint32_t, kb_syscall_named> keys = KfBpfSyscallKeys(config.get());
    auto keyed = [&](uint32_t index, std::vector<uint32_t> wanted) {
        auto found = keys.find(index);
        return found != keys.end() && !found->second.any &&
               std::vector<uint32_t>(found->second.key, found->second.key + found->second.count) == wanted;
    };
    auto any = [&](uint32_t index) { return keys.count(index) != 0 && keys.at(index).any != 0; };
    Expect("syscall keys: futex 9 and 137 in both tables", keyed(202, {9, 137}) && keyed(1 << 9 | 240, {9, 137}) &&
                                                               keyed(1 << 9 | 422, {9, 137}));
    Expect("syscall keys: wait4's child class", keyed(61, {1}));
    Expect("syscall keys: getrandom any (a rule on the call)", any(318) && any(1 << 9 | 355));
    Expect("syscall keys: fcntl's 0x6 is no decimal key: no key at all", keyed(72, {}));
    Expect("syscall keys: a wildcard over fadvise64's keys is any", any(221));
    Expect("syscall keys: a call none names has no entry", keys.count(0) == 0 && keys.count(1 << 9 | 3) == 0);
    config->Rules[0].Targets = KFILTER_TARGET_FILE;
    config->RuleCount = 1;
    Expect("only system rules attach", KfBpfSyscallPrograms(config.get()).empty());
    Expect("the kernel's own targets are logged as public ones",
           KfBpfPublicTarget(KB_TARGET_ARGUMENT) == KFILTER_TARGET_DEVICE && KfBpfPublicTarget(KB_TARGET_SIGNAL) == KFILTER_TARGET_PEER &&
               KfBpfPublicTarget(KFILTER_TARGET_FILE) == KFILTER_TARGET_FILE);
}

int main()
{
    SyscallAttachCase();
    UprobeAttachCase();
    DispatcherCase();
    std::string sleepPath = "/usr/bin/sleep";
    std::string shellPath = "/usr/bin/dash";
    if (access(sleepPath.c_str(), X_OK) != 0 || access(shellPath.c_str(), X_OK) != 0) {
        std::printf("FAIL needs /usr/bin/sleep and /usr/bin/dash\n");
        return 1;
    }
    std::string directory = "/tmp/kfilterd-test-" + std::to_string(getpid());
    mkdir(directory.c_str(), 0700);
    std::string fifo = directory + "/fifo";
    std::string fifoOut = directory + "/fifo-out";
    std::string gate = directory + "/gate";
    std::string early = directory + "/early";
    mkfifo(fifo.c_str(), 0600);
    mkfifo(fifoOut.c_str(), 0600);
    mkfifo(gate.c_str(), 0600);
    mkfifo(early.c_str(), 0600);

    Expect("policy initializes", NT_SUCCESS(KfPolicyInitialize()) && NT_SUCCESS(KfEventsInitialize()));
    gKfRegisteredMask = KFILTER_REG_MINIFILTER | KFILTER_REG_PROCESS | KFILTER_REG_DISK | KFILTER_REG_DEVICE;

    // The socket protocol: kfilterctl's Ioctl against the daemon's KfServe.
    int pair[2];
    Expect("socketpair", socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    std::thread server([&] { while (KfServe(pair[1], getpid())) {} });

    std::unique_ptr<KFILTER_CONFIG> config(new KFILTER_CONFIG());
    config->AbiVersion = KFILTER_ABI_VERSION;
    config->Mode = KFILTER_MODE_BLOCK;
    config->Flags = KFILTER_CFG_BLOCK_FILES | KFILTER_CFG_BLOCK_PROCESS_CREATE;
    config->ProtectedCount = 3;
    Fill(config->Protected[0], L"/sleep");
    Fill(config->Protected[1], L"/dash");
    Fill(config->Protected[2], L"\\MapleStory.exe");
    config->RuleCount = 1;
    config->Rules[0].Action = KFilterActionDeny;
    config->Rules[0].Targets = KFILTER_TARGET_FILE;
    config->Rules[0].Rights = KFILTER_RIGHTS_ALL;
    config->Rules[0].RuleId = 1;
    Fill(config->Rules[0].Path, L"/etc/hostname");
    Expect("SET_CONFIG over the socket",
           Ioctl(pair[0], KFILTER_OP_SET_CONFIG << 2, config.get(), (uint32_t)KFILTER_CONFIG_SIZE(1), nullptr, 0, nullptr));
    KFILTER_STATUS status {};
    uint32_t returned = 0;
    Expect("GET_STATUS over the socket",
           Ioctl(pair[0], KFILTER_OP_GET_STATUS << 2, nullptr, 0, &status, sizeof(status), &returned) &&
               returned == sizeof(status));
    Expect("status carries the config", status.AbiVersion == KFILTER_ABI_VERSION && status.Mode == KFILTER_MODE_BLOCK &&
                                           status.RuleCount == 1 && status.ProtectedCount == 3 &&
                                           status.Registered == gKfRegisteredMask);
    config->Rules[0].Path[0] = L'e';   // not absolute
    Expect("invalid config refused with EINVAL",
           !Ioctl(pair[0], KFILTER_OP_SET_CONFIG << 2, config.get(), (uint32_t)KFILTER_CONFIG_SIZE(1), nullptr, 0, nullptr) &&
               errno == EINVAL);

    // Tracking and a file decision for a protected process.
    pid_t sleeper = Spawn({ sleepPath.c_str(), "30", nullptr });
    Expect("sleep started", WaitForImage(sleeper, L"/sleep"));
    KFILTER_TRACK_REQUEST track {};
    track.ProcessId = (ULONG)sleeper;
    Expect("TRACK_PID admits a protected image",
           Ioctl(pair[0], KFILTER_OP_TRACK_PID << 2, &track, sizeof(track), nullptr, 0, nullptr));
    track.ProcessId = (ULONG)getpid();
    Expect("TRACK_PID reports a non-match as ENOENT",
           !Ioctl(pair[0], KFILTER_OP_TRACK_PID << 2, &track, sizeof(track), nullptr, 0, nullptr) && errno == ENOENT);
    KfTask task;
    Expect("protected task", KfReadTask(sleeper, task) && KfTaskProtected(task));
    KfSetCurrentProcess(sleeper, true);
    std::wstring denied = L"/etc/hostname";
    std::wstring allowed = L"/etc/passwd";
    UNICODE_STRING name { (USHORT)(denied.size() * sizeof(WCHAR)), 0, (PWSTR)denied.c_str() };
    Expect("deny rule denies in block mode",
           KfDecideWithRights(KFILTER_TARGET_FILE, &name, KFILTER_RIGHT_READ, NULL, 0, NULL, NULL, NULL, 0) != FALSE);
    name = { (USHORT)(allowed.size() * sizeof(WCHAR)), 0, (PWSTR)allowed.c_str() };
    Expect("other files allowed",
           KfDecideWithRights(KFILTER_TARGET_FILE, &name, KFILTER_RIGHT_READ, NULL, 0, NULL, NULL, NULL, 0) == FALSE);
    Expect("unresolved name denied in block mode",
           KfDecideWithRights(KFILTER_TARGET_FILE, NULL, KFILTER_RIGHT_READ, NULL, 0, NULL, NULL, NULL, 0) != FALSE);
    std::vector<KFILTER_EVENT> events(64);
    KFILTER_READ_REQUEST read {};
    read.MaximumEvents = 64;
    returned = 0;
    Expect("READ_EVENTS over the socket",
           Ioctl(pair[0], KFILTER_OP_READ_EVENTS << 2, &read, sizeof(read), events.data(),
                 (uint32_t)(events.size() * sizeof(KFILTER_EVENT)), &returned));
    bool sawDeny = false;
    for (size_t index = 0; index < returned / sizeof(KFILTER_EVENT); index++) {
        sawDeny = sawDeny || (events[index].ProcessId == (ULONG)sleeper && events[index].Action == KFilterActionDeny &&
                              events[index].RuleId == 1 && wcscmp(events[index].Path, L"/etc/hostname") == 0);
    }
    Expect("the denial is in the ring with pid, rule and path", sawDeny);

    // How a blocked open is made, from /proc/<tid>/syscall.
    pid_t reader = fork();
    if (reader == 0) { open(fifo.c_str(), O_RDONLY); _exit(0); }
    pid_t writer = fork();
    if (writer == 0) { open(fifoOut.c_str(), O_WRONLY | O_TRUNC); _exit(0); }
    bool exec = false;
    Expect("reader blocked in openat", WaitForSyscall(reader, 257));
    Expect("O_RDONLY is read", KfOpenRights(reader, exec) == KFILTER_RIGHT_READ && !exec);
    Expect("writer blocked in openat", WaitForSyscall(writer, 257));
    Expect("O_WRONLY|O_TRUNC is write", KfOpenRights(writer, exec) == KFILTER_RIGHT_WRITE);
    kill(reader, SIGKILL);
    kill(writer, SIGKILL);
    waitpid(reader, nullptr, 0);
    waitpid(writer, nullptr, 0);

    // Descendants inherit only when forked after their parent was admitted.
    std::string lateScript = "read x < " + gate + "; " + sleepPath + " 30 & wait";
    pid_t lateShell = Spawn({ shellPath.c_str(), "-c", lateScript.c_str(), nullptr });
    std::string earlyScript = sleepPath + " 30 & read x < " + early + "; wait";
    pid_t earlyShell = Spawn({ shellPath.c_str(), "-c", earlyScript.c_str(), nullptr });
    Expect("shells started", WaitForImage(lateShell, L"/dash") && WaitForImage(earlyShell, L"/dash"));
    pid_t earlyChild = ChildOf(earlyShell);
    Expect("early child exists", earlyChild != 0);
    sleep(1);   // /proc start times have clock-tick resolution
    Expect("track shells", NT_SUCCESS(KfProcessTrack(UlongToHandle((ULONG)lateShell))) &&
                               NT_SUCCESS(KfProcessTrack(UlongToHandle((ULONG)earlyShell))));
    int gateFd = open(gate.c_str(), O_WRONLY);
    (void)!write(gateFd, "\n", 1);
    close(gateFd);
    pid_t lateChild = ChildOf(lateShell);
    Expect("late child protected", lateChild != 0 && KfReadTask(lateChild, task) && KfTaskProtected(task));
    Expect("child forked before admission not adopted", KfReadTask(earlyChild, task) && !KfTaskProtected(task));

    // A protected image started outside the launcher is refused in block mode,
    // unless the one-time launch pass names its creator.
    pid_t outsider = fork();
    if (outsider == 0) { pause(); _exit(0); }
    KfTask outside;
    Expect("outsider identity", KfReadTask(outsider, outside) && !KfTaskProtected(outside));
    std::wstring sleepImage = L"/usr/bin/sleep";
    Expect("protected exec refused outside the launcher", KfProcessExec(outside, false, sleepImage));
    std::wstring self = KfExePath(getpid());
    std::unique_ptr<KFILTER_ALLOW_LAUNCH_REQUEST> pass(new KFILTER_ALLOW_LAUNCH_REQUEST());
    pass->ArmSeconds = 60;
    pass->Starts = 1;
    Fill(pass->CreatorName, self.substr(self.find_last_of(L'/') + 1).c_str());
    Expect("ALLOW_LAUNCH", NT_SUCCESS(KfProcessAllowLaunch(pass.get())));
    Expect("launch pass admits the exec", !KfProcessExec(outside, false, sleepImage) && KfTaskProtected(outside));
    pid_t second = fork();
    if (second == 0) { pause(); _exit(0); }
    KfTask secondTask;
    Expect("pass is used up", KfReadTask(second, secondTask) && KfProcessExec(secondTask, false, sleepImage));

    // Launch handshake: only the registered launcher admits its own child, and the
    // child's first exec must be the admitted image.
    KfSetCurrentProcess(getpid(), false);
    Expect("register launcher", NT_SUCCESS(KfProcessRegisterLauncher()));
    pid_t launched = fork();
    if (launched == 0) { pause(); _exit(0); }
    std::unique_ptr<KFILTER_ADMIT_REQUEST> admit(new KFILTER_ADMIT_REQUEST());
    admit->ProcessId = (ULONG)launched;
    Fill(admit->ImagePath, sleepImage.c_str());
    Expect("admit own child", NT_SUCCESS(KfProcessAdmit(admit.get())));
    admit->ProcessId = 1;
    Expect("admit refused for a process that is not the launcher's child",
           KfProcessAdmit(admit.get()) == STATUS_ACCESS_DENIED);
    KfTask launchedTask;
    Expect("admitted child protected", KfReadTask(launched, launchedTask) && KfTaskProtected(launchedTask));
    Expect("first exec of another image refused", KfProcessExec(launchedTask, true, L"/usr/bin/cat"));

    // A Wine loader, or a script that runs one, is admitted for the protected Windows program
    // it is asked to run; the program must be protected, and only loaders and scripts qualify.
    std::string script = directory + "/nexon-launcher";
    FILE* scriptFile = fopen(script.c_str(), "w");
    if (scriptFile != nullptr) { fputs("#!/bin/sh\nexec wine start MapleStory.exe\n", scriptFile); fclose(scriptFile); }
    auto admitFor = [&](const std::wstring& image, const std::wstring& program, ULONG flags) {
        pid_t child = fork();
        if (child == 0) { pause(); _exit(0); }
        std::unique_ptr<KFILTER_ADMIT_REQUEST> request(new KFILTER_ADMIT_REQUEST());
        request->ProcessId = (ULONG)child;
        request->Flags = flags;
        std::wstring field = image + L'\0' + program;
        wmemcpy(request->ImagePath, field.data(), field.size());
        NTSTATUS result = KfProcessAdmit(request.get());
        kill(child, SIGKILL);
        waitpid(child, nullptr, 0);
        return result;
    };
    const std::wstring maple = L"C:\\Nexon\\Library\\maplestorycw\\appdata\\MapleStory.exe";
    Expect("wine admitted for a protected program",
           NT_SUCCESS(admitFor(L"/opt/wine-stable/bin/wine", maple, KFILTER_ADMIT_FLAG_PROGRAM)));
    Expect("wine without --program refused",
           admitFor(L"/opt/wine-stable/bin/wine", maple, 0) == STATUS_ACCESS_DENIED);
    Expect("wine for an unprotected program refused",
           admitFor(L"/opt/wine-stable/bin/wine", L"C:\\windows\\notepad.exe", KFILTER_ADMIT_FLAG_PROGRAM) == STATUS_ACCESS_DENIED);
    Expect("script admitted for a protected program",
           NT_SUCCESS(admitFor(KfWide(script), L"\\MapleStory.exe", KFILTER_ADMIT_FLAG_PROGRAM)));
    Expect("a plain binary is not a loader",
           admitFor(L"/usr/bin/true", maple, KFILTER_ADMIT_FLAG_PROGRAM) == STATUS_ACCESS_DENIED);
    unlink(script.c_str());

    // The decision ring: a monitor session owns it, so other readers get EBUSY; its tag is
    // what GET_STATUS reports. A second connection stands in for kfilterctl watch.
    int other[2];
    Expect("second socketpair", socketpair(AF_UNIX, SOCK_STREAM, 0, other) == 0);
    std::thread otherServer([&] { while (KfServe(other[1], sleeper)) {} });
    KFILTER_SESSION_REQUEST session {};
    session.SessionTag = 0x5E55105;
    session.Flags = KFILTER_SESSION_OWN_EVENTS;
    Expect("SET_SESSION claims the ring",
           Ioctl(pair[0], KFILTER_OP_SET_SESSION << 2, &session, sizeof(session), nullptr, 0, nullptr));
    Expect("status carries the session tag",
           Ioctl(pair[0], KFILTER_OP_GET_STATUS << 2, nullptr, 0, &status, sizeof(status), nullptr) &&
               status.SessionTag == 0x5E55105);
    Expect("another reader refused with EBUSY",
           !Ioctl(other[0], KFILTER_OP_READ_EVENTS << 2, &read, sizeof(read), events.data(),
                  (uint32_t)(events.size() * sizeof(KFILTER_EVENT)), nullptr) && errno == EBUSY);
    Expect("another clear refused with EBUSY",
           !Ioctl(other[0], KFILTER_OP_CLEAR_EVENTS << 2, nullptr, 0, nullptr, 0, nullptr) && errno == EBUSY);
    Expect("the owner still reads",
           Ioctl(pair[0], KFILTER_OP_READ_EVENTS << 2, &read, sizeof(read), events.data(),
                 (uint32_t)(events.size() * sizeof(KFILTER_EVENT)), nullptr));
    Expect("a second claim refused", !Ioctl(other[0], KFILTER_OP_SET_SESSION << 2, &session, sizeof(session),
                                            nullptr, 0, nullptr) && errno == EBUSY);
    session.Flags = 0;
    session.SessionTag = 0;
    Expect("owner releases the ring",
           Ioctl(pair[0], KFILTER_OP_SET_SESSION << 2, &session, sizeof(session), nullptr, 0, nullptr));
    Expect("released ring readable by others",
           Ioctl(other[0], KFILTER_OP_READ_EVENTS << 2, &read, sizeof(read), events.data(),
                 (uint32_t)(events.size() * sizeof(KFILTER_EVENT)), nullptr));
    shutdown(other[0], SHUT_RDWR);
    close(other[0]);
    otherServer.join();

    // Rules no active layer enforces (no BPF here): block mode refuses them, audit mode loads
    // them and GET_STATUS reports the class as degraded, as it does a missing layer.
    config->Rules[0].Path[0] = L'/';
    config->NetworkRuleCount = 1;
    config->Network[0].Action = KFilterActionDeny;
    config->Network[0].Rights = KFILTER_RIGHT_SEND;
    config->Network[0].RuleId = 2;
    Expect("block mode refuses a message rule without BPF (EOPNOTSUPP)",
           !Ioctl(pair[0], KFILTER_OP_SET_CONFIG << 2, config.get(), (uint32_t)KFILTER_CONFIG_SIZE(1), nullptr, 0, nullptr) &&
               errno == EOPNOTSUPP);
    config->Mode = KFILTER_MODE_AUDIT;
    config->Flags |= KFILTER_CFG_BLOCK_REGISTRY;
    Expect("audit mode loads it",
           Ioctl(pair[0], KFILTER_OP_SET_CONFIG << 2, config.get(), (uint32_t)KFILTER_CONFIG_SIZE(1), nullptr, 0, nullptr));
    Expect("status reports message and registry degraded",
           Ioctl(pair[0], KFILTER_OP_GET_STATUS << 2, nullptr, 0, &status, sizeof(status), nullptr) &&
               (status.Degraded & KFILTER_STATUS_DEGRADED_MESSAGE) != 0 &&
               (status.Degraded & KFILTER_STATUS_DEGRADED_REGISTRY) != 0 &&
               (status.Degraded & KFILTER_STATUS_FAIL_OPEN) == 0);
    config->Mode = KFILTER_MODE_BLOCK;
    // With the BPF layer but without kb_socket_recvmsg, the message rule is still unenforced.
    Expect("a degraded message hook leaves message rules unenforced in block mode",
           KfMessagesUnenforced(config.get(), KFILTER_STATUS_DEGRADED_MESSAGE) &&
               !KfMessagesUnenforced(config.get(), 0));
    config->Flags &= ~KFILTER_CFG_BLOCK_REGISTRY;
    config->NetworkRuleCount = 0;
    // ABI 10: an addr= peer deny is the BPF layer's alone; a malformed one loads in no mode.
    KFILTER_RULE& memory = config->Rules[1];
    memory = KFILTER_RULE{};
    memory.Action = KFilterActionDeny;
    memory.Targets = KFILTER_TARGET_PEER;
    memory.Rights = 0x10;
    memory.RuleId = 2;
    memory.Flags = KFILTER_RULE_ADDRESS;
    Fill(memory.Path, L"C:\\*\\MapleStory.exe");
    wcscpy(memory.Value, L"MapleStory.exe");
    memory.AddressCount = 2;
    memory.AddressModule[0] = 1;
    memory.Address[0] = {0x1000, 0x1FFF};
    memory.Address[1] = {0x140000000ull, 0x14FFFFFFFull};
    config->RuleCount = 2;
    auto setConfig = [&] {
        return Ioctl(pair[0], KFILTER_OP_SET_CONFIG << 2, config.get(), (uint32_t)KFILTER_CONFIG_SIZE(2), nullptr, 0, nullptr);
    };
    Expect("block mode refuses an addr= rule without BPF (EOPNOTSUPP)", !setConfig() && errno == EOPNOTSUPP);
    config->Mode = KFILTER_MODE_AUDIT;
    Expect("audit mode loads an addr= rule", setConfig());
    memory.AddressModule[1] = 2;
    Expect("an addr= range naming a module Value does not list is refused", !setConfig() && errno == EINVAL);
    memory.AddressModule[1] = 0;
    memory.Address[1] = {0x14FFFFFFFull, 0x140000000ull};
    Expect("an addr= range from high to low is refused", !setConfig() && errno == EINVAL);
    memory.Address[1] = {0x140000000ull, 0x14FFFFFFFull};
    memory.Targets = KFILTER_TARGET_FILE;
    Expect("addr= on a file rule is refused", !setConfig() && errno == EINVAL);
    memory.Targets = KFILTER_TARGET_PEER;
    memory.Flags = KFILTER_RULE_ADDRESS | KFILTER_RULE_MODULE;
    Expect("addr= with module= is refused", !setConfig() && errno == EINVAL);
    memory.Flags = 0;
    Expect("ranges without addr= are refused", !setConfig() && errno == EINVAL);
    config->RuleCount = 1;
    config->Mode = KFILTER_MODE_BLOCK;
    Expect("block mode without BPF loads",
           Ioctl(pair[0], KFILTER_OP_SET_CONFIG << 2, config.get(), (uint32_t)KFILTER_CONFIG_SIZE(1), nullptr, 0, nullptr));
    Expect("and says it fails open",
           Ioctl(pair[0], KFILTER_OP_GET_STATUS << 2, nullptr, 0, &status, sizeof(status), nullptr) &&
               (status.Degraded & KFILTER_STATUS_FAIL_OPEN) != 0);
    // A Wine install whose protocol the BPF layer does not decode: block mode protecting a Windows program says so
    // (refused), one protecting Linux programs alone, or audit mode, does not.
    Expect("an undecoded Wine refuses block mode for a protected Windows program",
           KfMessagesUnenforced(config.get(), KFILTER_STATUS_DEGRADED_WINE) && !KfMessagesUnenforced(config.get(), 0));
    config->ProtectedCount = 2;
    Expect("... not for Linux programs alone", !KfMessagesUnenforced(config.get(), KFILTER_STATUS_DEGRADED_WINE));
    config->ProtectedCount = 3;
    config->Mode = KFILTER_MODE_AUDIT;
    Expect("... nor in audit mode", !KfMessagesUnenforced(config.get(), KFILTER_STATUS_DEGRADED_WINE));
    config->Mode = KFILTER_MODE_BLOCK;
    Expect("SHUTDOWN turns the policy off",
           Ioctl(pair[0], KFILTER_OP_SHUTDOWN << 2, nullptr, 0, nullptr, 0, nullptr) &&
               Ioctl(pair[0], KFILTER_OP_GET_STATUS << 2, nullptr, 0, &status, sizeof(status), nullptr) &&
               status.Mode == KFILTER_MODE_OFF && status.Degraded == 0);

    for (pid_t pid : { sleeper, lateShell, earlyShell, lateChild, earlyChild, outsider, second, launched }) {
        if (pid > 0) kill(pid, SIGKILL);
    }
    int earlyFd = open(early.c_str(), O_RDWR | O_NONBLOCK);
    if (earlyFd >= 0) close(earlyFd);
    while (waitpid(-1, nullptr, WNOHANG) > 0) {}
    shutdown(pair[0], SHUT_RDWR);
    close(pair[0]);
    server.join();
    unlink(fifo.c_str());
    unlink(fifoOut.c_str());
    unlink(gate.c_str());
    unlink(early.c_str());
    rmdir(directory.c_str());

    WineRequestBits();
    KeyedRules();
    WineProtocols();
    if (gFailures == 0) std::printf("kfilterd-test: PASS\n");
    return gFailures == 0 ? 0 : 1;
}
