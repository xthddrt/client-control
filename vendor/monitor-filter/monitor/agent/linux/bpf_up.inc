/* Function probes (up.bpf.h: the uprobes group; docs/LINUX.md "Function probes"). Included by bpf.cpp at global scope
 * after Record/Repeated and bpf_payload.inc. A probed library is attached once per file, for every process that maps
 * it (uprobe_multi, pid -1), as kfilter's kb_win32k is; the programs return at once for an untracked process. The
 * libraries of the Wine installs kfilter decodes are probed at start; any other the first time a tracked process maps
 * it: the copy thread spots the mmap record as it leaves the ring (UpCopied) and a worker thread attaches (about 8 ms a
 * link), and a joined process brings the ones it already has (UpJoined). wbemprox.dll's ExecQuery is PE code, which
 * Wine maps writable before making it executable, and a uprobe goes only into a mapping that is not writable when it
 * registers: it is attached per process once that code is executable (UpCopied spots it, the worker attaches it first
 * in line) and dropped at exit (UpForget). shortcut: the first process to map a library outside those installs
 * (libgnutls too) misses its calls until the attach; probe it at start as well if a client's first calls are lost. */
#include <sys/resource.h>
#include <climits>
#include <condition_variable>
#include <cwctype>
#include <elf.h>
#include <iterator>
#include "../etw.h"   /* SanitizeQuery */

namespace {

bool gWindowProbes = false;   /* --window-probes: the window functions (UpCall.hwnd) are probed too */

/* Windows-level calls Wine answers in-process. Key: the argument (1-6) whose value keys the one-record-a-second limit
 * (a virtual key, a class, a handle, a window, a source DC); text: the argument (1-6) pointing at a UNICODE_STRING;
 * key2: a second argument (1-6) in the key (NtQueryVirtualMemory's address, a message, an offset), and the one
 * kUpClasses names for a multiplexer unless cls says another (NtUserCallHwndParam's code; kUpClasses has no
 * NtQueryVirtualMemory row); hwnd: the first argument is a window, probed only with --window-probes, and the kernel
 * leaves out the calls on the caller's own windows (MM_UP_HWND); page: key2 is an address, keyed by its page, and
 * past MM_UP_PAGES records a second (a VirtualQuery walk) the calls are a kernel aggregate (MM_UP_PAGE). */
struct UpCall {
    const char* library;
    const char* name;
    uint8_t key, text, key2 = 0, cls = 0;
    bool hwnd = false, page = false;
};
const UpCall kUpCalls[] = {
    /* win32u.so: Wine 11 answers key state, the cursor and the foreground window from desktop shared memory, so these
     * send no wineserver request. */
    {"win32u.so", "NtUserGetAsyncKeyState", 1, 0},
    {"win32u.so", "NtUserGetKeyState", 1, 0},
    {"win32u.so", "NtUserGetKeyboardState", 0, 0},
    {"win32u.so", "NtUserGetCursorPos", 0, 0},
    {"win32u.so", "NtUserGetCursorInfo", 0, 0},
    {"win32u.so", "NtUserGetForegroundWindow", 0, 0},
    {"win32u.so", "NtUserGetGUIThreadInfo", 0, 0},
    {"win32u.so", "NtUserBuildHwndList", 0, 0},
    {"win32u.so", "NtUserInternalGetWindowText", 1, 0},
    {"win32u.so", "NtUserGetClassName", 1, 0},
    {"win32u.so", "NtUserFindWindowEx", 3, 3},
    {"win32u.so", "NtUserGetClipboardData", 1, 0},
    {"win32u.so", "NtUserGetRawInputData", 0, 0},
    {"win32u.so", "NtUserGetRawInputBuffer", 0, 0},
    {"win32u.so", "NtUserRegisterRawInputDevices", 0, 0},
    {"win32u.so", "NtUserSetWindowsHookEx", 4, 2},
    {"win32u.so", "NtUserSetWinEventHook", 0, 0},
    {"win32u.so", "NtUserSendInput", 0, 0},
    {"win32u.so", "NtUserGetDC", 1, 0},
    {"win32u.so", "NtUserGetWindowDC", 1, 0},
    {"win32u.so", "NtGdiBitBlt", 6, 0},
    {"win32u.so", "NtGdiStretchBlt", 6, 0},
    {"win32u.so", "NtGdiGetPixel", 1, 0},
    {"win32u.so", "NtGdiGetDIBitsInternal", 2, 0},
    {"win32u.so", "NtUserEnumDisplayDevices", 0, 0},
    {"win32u.so", "NtUserEnumDisplaySettings", 0, 0},
    {"win32u.so", "NtGdiDdDDIEnumAdapters2", 0, 0},
    {"win32u.so", "NtUserPrintWindow", 1, 0},
    /* Window functions, only with --window-probes (off by default): MapleStory calls NtUserCallHwndParam every frame
     * (ClientToScreen, GetWindowLong on its own window), and each call of a probed function takes a trap (about 1-2 us)
     * however the kernel then filters it; probed by default once, it put msmon at 98% CPU, blacked the game's window at
     * launch and dropped about 1 channel change in 4 (2026-11-12 11:50-12:00). The kernel now leaves out every call on
     * the caller's own windows (ws_windows), so only other programs' windows are recorded, but the trap remains:
     * linux_wine_test.sh measures it. NtUserCallHwndParam: GetWindowThreadProcessId, GetWindowLong, GetClassLong,
     * GetWindowRect of any window from the shared user handle table, keyed by window and code; NtUserMessageCall
     * (SendMessage and the rest, DefWindowProc...) and NtUserPostMessage by window and message, class the call type;
     * NtUserSetWindowLong(Ptr) by window and offset; NtUserSetWindowPos by window. */
    {"win32u.so", "NtUserCallHwndParam", 1, 0, 3, 0, true},
    {"win32u.so", "NtUserMessageCall", 1, 0, 2, 6, true},
    {"win32u.so", "NtUserPostMessage", 1, 0, 2, 0, true},
    {"win32u.so", "NtUserSetWindowLong", 1, 0, 2, 0, true},
    {"win32u.so", "NtUserSetWindowLongPtr", 1, 0, 2, 0, true},
    {"win32u.so", "NtUserSetWindowPos", 1, 0, 0, 0, true},
    /* ntdll.so: anti-debug and environment queries answered without a request. */
    {"ntdll.so", "NtQuerySystemInformation", 1, 0},
    {"ntdll.so", "NtQuerySystemInformationEx", 1, 0},
    {"ntdll.so", "NtQueryInformationProcess", 2, 0},
    {"ntdll.so", "NtSetInformationProcess", 2, 0},
    {"ntdll.so", "NtQueryInformationThread", 2, 0},
    {"ntdll.so", "NtSetInformationThread", 2, 0},
    {"ntdll.so", "NtQueryVirtualMemory", 1, 0, 2, 0, false, true},   /* handle and the page of the address */
    {"ntdll.so", "NtGetContextThread", 1, 0},
    {"ntdll.so", "NtSetContextThread", 1, 0},
    {"ntdll.so", "NtQueryObject", 2, 0},
    {"ntdll.so", "NtCreateThreadEx", 5, 0},
    {"ntdll.so", "NtQueryLicenseValue", 1, 1},
    {"ntdll.so", "NtQuerySystemEnvironmentValue", 1, 1},
    {"ntdll.so", "NtQuerySystemEnvironmentValueEx", 1, 1},
    {"ntdll.so", "NtSystemDebugControl", 1, 0},
};
constexpr uint64_t kUpI386 = 1ull << 24;   /* cookie: attached to an i386 library */

/* Information classes worth a name (the anti-debug and environment ones); the argument holding the class. */
struct UpClass {
    const char* call;
    uint32_t value;
    const wchar_t* name;
};
const UpClass kUpClasses[] = {
    {"NtQuerySystemInformation", 0, L"SystemBasicInformation"},
    {"NtQuerySystemInformation", 1, L"SystemProcessorInformation"},
    {"NtQuerySystemInformation", 2, L"SystemPerformanceInformation"},
    {"NtQuerySystemInformation", 3, L"SystemTimeOfDayInformation"},
    {"NtQuerySystemInformation", 5, L"SystemProcessInformation"},
    {"NtQuerySystemInformation", 8, L"SystemProcessorPerformanceInformation"},
    {"NtQuerySystemInformation", 11, L"SystemModuleInformation"},
    {"NtQuerySystemInformation", 16, L"SystemHandleInformation"},
    {"NtQuerySystemInformation", 35, L"SystemKernelDebuggerInformation"},
    {"NtQuerySystemInformation", 57, L"SystemExtendedProcessInformation"},
    {"NtQuerySystemInformation", 64, L"SystemExtendedHandleInformation"},
    {"NtQuerySystemInformation", 73, L"SystemLogicalProcessorInformation"},
    {"NtQuerySystemInformation", 76, L"SystemFirmwareTableInformation"},
    {"NtQuerySystemInformation", 88, L"SystemProcessIdInformation"},
    {"NtQuerySystemInformation", 90, L"SystemBootEnvironmentInformation"},
    {"NtQuerySystemInformation", 103, L"SystemCodeIntegrityInformation"},
    {"NtQuerySystemInformation", 107, L"SystemLogicalProcessorInformationEx"},
    {"NtQuerySystemInformation", 145, L"SystemSecureBootInformation"},
    {"NtQuerySystemInformation", 149, L"SystemKernelDebuggerInformationEx"},
    {"NtQuerySystemInformation", 1000, L"SystemWineVersionInformation"},
    {"NtQueryInformationProcess", 0, L"ProcessBasicInformation"},
    {"NtQueryInformationProcess", 7, L"ProcessDebugPort"},
    {"NtQueryInformationProcess", 26, L"ProcessWow64Information"},
    {"NtQueryInformationProcess", 27, L"ProcessImageFileName"},
    {"NtQueryInformationProcess", 30, L"ProcessDebugObjectHandle"},
    {"NtQueryInformationProcess", 31, L"ProcessDebugFlags"},
    {"NtQueryInformationProcess", 43, L"ProcessImageFileNameWin32"},
    {"NtQueryInformationProcess", 60, L"ProcessCommandLineInformation"},
    {"NtQueryInformationThread", 0, L"ThreadBasicInformation"},
    {"NtQueryInformationThread", 9, L"ThreadQuerySetWin32StartAddress"},
    {"NtQueryInformationThread", 17, L"ThreadHideFromDebugger"},
    {"NtSetInformationThread", 17, L"ThreadHideFromDebugger"},
    {"NtSetInformationProcess", 40, L"ProcessInstrumentationCallback"},
    /* Wine 11 include/ntuser.h enum NtUserCallHwndParam_* (the third argument) */
    {"NtUserCallHwndParam", 0, L"ClientToScreen"},
    {"NtUserCallHwndParam", 1, L"GetChildRect"},
    {"NtUserCallHwndParam", 2, L"GetClassLongA"},
    {"NtUserCallHwndParam", 3, L"GetClassLongW"},
    {"NtUserCallHwndParam", 4, L"GetClassLongPtrA"},
    {"NtUserCallHwndParam", 5, L"GetClassLongPtrW"},
    {"NtUserCallHwndParam", 6, L"GetClassWord"},
    {"NtUserCallHwndParam", 7, L"GetScrollInfo"},
    {"NtUserCallHwndParam", 8, L"GetWindowInfo"},
    {"NtUserCallHwndParam", 9, L"GetWindowLongA"},
    {"NtUserCallHwndParam", 10, L"GetWindowLongW"},
    {"NtUserCallHwndParam", 11, L"GetWindowLongPtrA"},
    {"NtUserCallHwndParam", 12, L"GetWindowLongPtrW"},
    {"NtUserCallHwndParam", 13, L"GetWindowRect"},
    {"NtUserCallHwndParam", 14, L"GetClientRect"},
    {"NtUserCallHwndParam", 15, L"GetPresentRect"},
    {"NtUserCallHwndParam", 16, L"GetWindowRelative"},
    {"NtUserCallHwndParam", 17, L"GetWindowThread"},
    {"NtUserCallHwndParam", 18, L"GetWindowWord"},
    {"NtUserCallHwndParam", 19, L"IsChild"},
    {"NtUserCallHwndParam", 20, L"MapWindowPoints"},
    {"NtUserCallHwndParam", 21, L"MirrorRgn"},
    {"NtUserCallHwndParam", 22, L"MonitorFromWindow"},
    {"NtUserCallHwndParam", 23, L"ScreenToClient"},
    {"NtUserCallHwndParam", 24, L"SetDialogInfo"},
    {"NtUserCallHwndParam", 25, L"SetMDIClientInfo"},
    {"NtUserCallHwndParam", 26, L"SendHardwareInput"},
    {"NtUserCallHwndParam", 27, L"ExposeWindowSurface"},
    {"NtUserCallHwndParam", 28, L"GetWinMonitorDpi"},
    {"NtUserCallHwndParam", 29, L"SetRawWindowPos"},
    /* Wine 11 include/ntuser.h NtUserMessageCall types (the sixth argument) */
    {"NtUserMessageCall", 0x29a, L"ScrollBarWndProc"},
    {"NtUserMessageCall", 0x29c, L"PopupMenuWndProc"},
    {"NtUserMessageCall", 0x29d, L"DesktopWindowProc"},
    {"NtUserMessageCall", 0x29e, L"DefWindowProc"},
    {"NtUserMessageCall", 0x2ab, L"CallWindowProc"},
    {"NtUserMessageCall", 0x2b1, L"SendMessage"},
    {"NtUserMessageCall", 0x2b3, L"SendMessageTimeout"},
    {"NtUserMessageCall", 0x2b7, L"SendNotifyMessage"},
    {"NtUserMessageCall", 0x2b8, L"SendMessageCallback"},
    {"NtUserMessageCall", 0x300, L"ClipboardWindowProc"},
    {"NtUserMessageCall", 0x3001, L"GetDispatchParams"},
    {"NtUserMessageCall", 0x3002, L"SpyGetMsgName"},
    {"NtUserMessageCall", 0x303, L"SpyEnter"},
    {"NtUserMessageCall", 0x304, L"SpyExit"},
    {"NtUserMessageCall", 0x305, L"WinProcResult"},
    {"NtUserMessageCall", 0x306, L"ImeDriverCall"},
    {"NtUserMessageCall", 0x307, L"SystemTrayCall"},
    {"NtUserMessageCall", 0x308, L"DragDropCall"},
    {"NtUserMessageCall", 0x309, L"PostDdeCall"},
    /* GWL_ / GWLP_ offsets (the second argument): a window procedure replaced is another program's window subclassed */
    {"NtUserSetWindowLong", 0xfffffffc, L"GWLP_WNDPROC"},
    {"NtUserSetWindowLong", 0xfffffffa, L"GWLP_HINSTANCE"},
    {"NtUserSetWindowLong", 0xfffffff8, L"GWLP_HWNDPARENT"},
    {"NtUserSetWindowLong", 0xfffffff4, L"GWLP_ID"},
    {"NtUserSetWindowLong", 0xfffffff0, L"GWL_STYLE"},
    {"NtUserSetWindowLong", 0xffffffec, L"GWL_EXSTYLE"},
    {"NtUserSetWindowLong", 0xffffffeb, L"GWLP_USERDATA"},
    {"NtUserSetWindowLongPtr", 0xfffffffc, L"GWLP_WNDPROC"},
    {"NtUserSetWindowLongPtr", 0xfffffffa, L"GWLP_HINSTANCE"},
    {"NtUserSetWindowLongPtr", 0xfffffff8, L"GWLP_HWNDPARENT"},
    {"NtUserSetWindowLongPtr", 0xfffffff4, L"GWLP_ID"},
    {"NtUserSetWindowLongPtr", 0xfffffff0, L"GWL_STYLE"},
    {"NtUserSetWindowLongPtr", 0xffffffec, L"GWL_EXSTYLE"},
    {"NtUserSetWindowLongPtr", 0xffffffeb, L"GWLP_USERDATA"},
};

/* Window messages worth a name on NtUserMessageCall and NtUserPostMessage records. */
const std::pair<uint32_t, const wchar_t*> kUpMessages[] = {
    {0x0002, L"WM_DESTROY"}, {0x0003, L"WM_MOVE"}, {0x0005, L"WM_SIZE"}, {0x0006, L"WM_ACTIVATE"}, {0x0007, L"WM_SETFOCUS"},
    {0x0008, L"WM_KILLFOCUS"}, {0x000a, L"WM_ENABLE"}, {0x000b, L"WM_SETREDRAW"}, {0x000c, L"WM_SETTEXT"},
    {0x000d, L"WM_GETTEXT"}, {0x000e, L"WM_GETTEXTLENGTH"}, {0x000f, L"WM_PAINT"}, {0x0010, L"WM_CLOSE"}, {0x0012, L"WM_QUIT"},
    {0x0018, L"WM_SHOWWINDOW"}, {0x001c, L"WM_ACTIVATEAPP"}, {0x0020, L"WM_SETCURSOR"}, {0x003d, L"WM_GETOBJECT"},
    {0x0046, L"WM_WINDOWPOSCHANGING"}, {0x0047, L"WM_WINDOWPOSCHANGED"}, {0x004a, L"WM_COPYDATA"}, {0x0084, L"WM_NCHITTEST"},
    {0x0100, L"WM_KEYDOWN"}, {0x0101, L"WM_KEYUP"}, {0x0102, L"WM_CHAR"}, {0x0104, L"WM_SYSKEYDOWN"}, {0x0105, L"WM_SYSKEYUP"},
    {0x0111, L"WM_COMMAND"}, {0x0112, L"WM_SYSCOMMAND"}, {0x0113, L"WM_TIMER"}, {0x0200, L"WM_MOUSEMOVE"},
    {0x0201, L"WM_LBUTTONDOWN"}, {0x0202, L"WM_LBUTTONUP"}, {0x0204, L"WM_RBUTTONDOWN"}, {0x0205, L"WM_RBUTTONUP"},
    {0x020a, L"WM_MOUSEWHEEL"}, {0x0400, L"WM_USER"},
};

struct UpPending {   /* a library to probe in every process, or (tgid) wbemprox code [start, end) that process made executable */
    uint32_t tgid = 0;
    std::string path;
    uint64_t start = 0, end = 0;
};
struct UpTargets {   /* a library's probed functions */
    const char* entry = nullptr;   /* program at their entry */
    const char* exit = nullptr;    /* program at their return, or nullptr */
    std::vector<unsigned long> offsets;
    std::vector<__u64> cookies;
};
struct {
    std::mutex mutex;                                    /* the worker, the copy thread and the BPF thread */
    std::set<std::string> libraries;                     /* probed in every process (or queued) */
    std::vector<bpf_link*> links;                        /* theirs */
    std::unordered_map<uint32_t, std::vector<bpf_link*>> processes;   /* tgid -> its ExecQuery links */
    std::unordered_map<uint32_t, UpPending> pending;     /* copy thread: tid -> wbemprox code its running mprotect makes executable */
    std::condition_variable wake;
    std::deque<UpPending> queue;                         /* to attach */
    std::vector<bpf_link*> dead;                         /* links of exited processes, for the worker to destroy */
    bool stop = false;
    std::thread worker;
} gUp;
/* Wine installs probed from the start (kfilter's DecodedWineDirs roots). */
const char* const kWineRoots[] = {"/opt/wine-stable", "/opt/wine-staging", "/opt/wine-devel", "/usr/local"};

/* File offsets of the named functions in an ELF shared object's .dynsym (0: not exported). Done here because
 * libbpf 1.3's uprobe_multi lookup by name finds none of them (and no versioned name). */
template <typename Ehdr, typename Shdr, typename Sym>
void ElfOffsets(const std::vector<uint8_t>& f, const std::vector<const char*>& names, std::vector<unsigned long>& out)
{
    Ehdr eh;
    if (f.size() < sizeof(eh)) return;
    std::memcpy(&eh, f.data(), sizeof(eh));
    if (eh.e_shentsize != sizeof(Shdr) || eh.e_shoff == 0 || eh.e_shoff + uint64_t(eh.e_shnum) * sizeof(Shdr) > f.size()) return;
    std::vector<Shdr> sh(eh.e_shnum);
    std::memcpy(sh.data(), f.data() + eh.e_shoff, sh.size() * sizeof(Shdr));
    for (const Shdr& table : sh) {
        if (table.sh_type != SHT_DYNSYM || table.sh_link >= sh.size() || table.sh_offset > f.size()) continue;
        const uint64_t strings = sh[table.sh_link].sh_offset;
        const uint64_t end = std::min<uint64_t>(f.size(), table.sh_offset + table.sh_size);
        for (uint64_t at = table.sh_offset; at + sizeof(Sym) <= end; at += sizeof(Sym)) {
            Sym sym;
            std::memcpy(&sym, f.data() + at, sizeof(sym));
            if ((sym.st_info & 0xf) != STT_FUNC || sym.st_shndx == SHN_UNDEF || sym.st_shndx >= sh.size() ||
                strings + sym.st_name >= f.size())
                continue;
            const char* name = reinterpret_cast<const char*>(f.data() + strings + sym.st_name);
            const size_t length = strnlen(name, f.size() - (strings + sym.st_name));
            for (size_t index = 0; index < names.size(); index++) {
                if (out[index] == 0 && std::strlen(names[index]) == length && std::memcmp(name, names[index], length) == 0)
                    out[index] = sym.st_value - sh[sym.st_shndx].sh_addr + sh[sym.st_shndx].sh_offset;
            }
        }
    }
}

/* Path's class (i386 or not) and the file offsets of Names in it. */
std::vector<unsigned long> ElfFunctions(const std::string& path, const std::vector<const char*>& names, bool& i386)
{
    std::vector<unsigned long> offsets(names.size(), 0);
    std::ifstream in(path, std::ios::binary);
    const std::vector<uint8_t> file((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    i386 = file.size() > EI_CLASS && file[EI_CLASS] == ELFCLASS32;
    if (i386) ElfOffsets<Elf32_Ehdr, Elf32_Shdr, Elf32_Sym>(file, names, offsets);
    else ElfOffsets<Elf64_Ehdr, Elf64_Shdr, Elf64_Sym>(file, names, offsets);
    return offsets;
}

/* Program at Path's file Offsets in Pid (-1: every process): one uprobe_multi link, else one link per offset. Returns the
 * links made. */
std::vector<bpf_link*> UpAttach(const char* program, pid_t pid, const std::string& path, std::vector<unsigned long> offsets,
                                std::vector<__u64> cookies, bool retprobe)
{
    std::vector<bpf_link*> made;
    bpf_program* prog = bpf_object__find_program_by_name(gBpf.object, program);
    if (prog == nullptr || offsets.empty()) return made;
    auto attach = [&](size_t first, size_t count) {
        bpf_uprobe_multi_opts opts{};
        opts.sz = sizeof(opts);
        opts.offsets = offsets.data() + first;
        opts.cookies = cookies.data() + first;
        opts.cnt = count;
        opts.retprobe = retprobe;
        bpf_link* link = bpf_program__attach_uprobe_multi(prog, pid, path.c_str(), nullptr, &opts);
        if (link != nullptr) made.push_back(link);
        return link != nullptr;
    };
    if (!attach(0, cookies.size()) && cookies.size() > 1 && errno != ESRCH) {
        for (size_t index = 0; index < cookies.size(); index++) attach(index, 1);
    }
    return made;
}

/* The functions probed in a library: win32u.so, ntdll.so (Wine's unix side) or libgnutls.so.30. */
UpTargets UpResolve(const std::string& path, const std::string& base)
{
    const bool gnutls = base.rfind("libgnutls.so.30", 0) == 0;
    std::vector<const char*> syms;
    std::vector<__u64> cookies;
    if (gnutls) {
        syms = {"gnutls_record_send", "gnutls_record_recv"};
        cookies = {0, MM_UP_TLS_RECV};
    } else {
        for (size_t index = 0; index < std::size(kUpCalls); index++) {
            if (base != kUpCalls[index].library || (kUpCalls[index].hwnd && !gWindowProbes)) continue;
            syms.push_back(kUpCalls[index].name);
            cookies.push_back(index | uint64_t(kUpCalls[index].key) << 16 | uint64_t(kUpCalls[index].text) << 20 |
                              uint64_t(kUpCalls[index].key2) << 28 | (kUpCalls[index].hwnd ? MM_UP_HWND : 0) |
                              (kUpCalls[index].page ? MM_UP_PAGE : 0));
        }
    }
    bool i386 = false;
    const std::vector<unsigned long> found = ElfFunctions(path, syms, i386);
    UpTargets targets;
    targets.entry = gnutls ? (i386 ? "mm_up_tls32" : "mm_up_tls") : (i386 ? "mm_up_call32" : "mm_up_call");
    targets.exit = gnutls ? "mm_up_tls_ret" : nullptr;
    for (size_t index = 0; index < syms.size(); index++) {
        if (found[index] == 0) continue;   /* not in this build */
        targets.offsets.push_back(found[index]);
        targets.cookies.push_back(cookies[index] | (i386 && !gnutls ? kUpI386 : 0));
    }
    return targets;
}

/* Path's probes in every process that maps it, now or later. */
std::vector<bpf_link*> UpProbe(const std::string& path)
{
    const UpTargets targets = UpResolve(path, path.substr(path.find_last_of('/') + 1));
    std::vector<bpf_link*> made;
    for (const char* program : {targets.entry, targets.exit}) {
        if (program == nullptr) continue;
        const std::vector<bpf_link*> links = UpAttach(program, -1, path, targets.offsets, targets.cookies, program == targets.exit);
        made.insert(made.end(), links.begin(), links.end());
    }
    return made;
}

/* Job's process's IWbemServices probes (PeWmiMethods), those Job's code range holds. shortcut: one link per process
 * mapping; a process that maps wbemprox twice gets two probes and two records per query, fine for a module loaded once. */
std::vector<bpf_link*> UpWmiProbe(const UpPending& job)
{
    uint16_t machine = 0;
    const std::vector<uint64_t> found = PeWmiMethods(job.path, machine);
    std::vector<unsigned long> offsets;
    std::vector<__u64> cookies;
    for (unsigned method = 0; method < found.size(); method++) {
        if (found[method] == 0 || found[method] < job.start || found[method] >= job.end) continue;
        offsets.push_back(static_cast<unsigned long>(found[method]));
        cookies.push_back(method);
    }
    return UpAttach(machine == 0x14c ? "mm_up_wmi32" : "mm_up_wmi", static_cast<pid_t>(job.tgid), job.path, offsets,
                    cookies, false);
}

bool UpWanted(const std::string& path)
{
    const std::string base = path.substr(path.find_last_of('/') + 1);
    return base == "win32u.so" || base == "ntdll.so" || base.rfind("libgnutls.so.30", 0) == 0;
}

/* Path probed in every process, once (gUp.mutex held). */
void UpLibrary(const std::string& path)
{
    if (!gUp.libraries.insert(path).second) return;
    gUp.queue.push_back({0, path});
    gUp.wake.notify_one();
}

void UpWork()
{
    std::unique_lock<std::mutex> lock(gUp.mutex);
    for (;;) {
        gUp.wake.wait(lock, [] { return gUp.stop || !gUp.queue.empty() || !gUp.dead.empty(); });
        if (gUp.stop) return;
        /* Each attach and detach waits for the kernel (ms to tens of ms), so it is done unlocked: the copy thread
         * never waits for it. */
        std::vector<bpf_link*> dead;
        dead.swap(gUp.dead);
        UpPending job;
        const bool attach = !gUp.queue.empty();
        if (attach) {
            job = std::move(gUp.queue.front());
            gUp.queue.pop_front();
        }
        lock.unlock();
        for (bpf_link* link : dead) bpf_link__destroy(link);
        std::vector<bpf_link*> made;
        if (attach) made = job.tgid == 0 ? UpProbe(job.path) : UpWmiProbe(job);
        lock.lock();
        /* shortcut: a process forgotten while its ExecQuery link was made keeps it until close; check the process
         * here if short-lived WMI callers pile links up. */
        if (made.empty()) continue;
        std::vector<bpf_link*>& owner = job.tgid == 0 ? gUp.links : gUp.processes[job.tgid];
        owner.insert(owner.end(), made.begin(), made.end());
    }
}

/* Copy thread, as records leave the ring (only tracked processes' reach it): an executable mmap of a probed library
 * queues it; wbemprox code turning executable (MM_IMAGE_MPROTECT from inside an mprotect, then that thread's mprotect
 * returning 0: a uprobe is installed only in a mapping that is not writable when it registers, and Wine maps PE
 * sections writable first) queues its ExecQuery probe first in line, as the query may follow at once. */
void UpCopied(const void* data, size_t size)
{
    uint32_t kind = 0, nr = 0, flags = 0, tgid = 0, tid = 0;
    uint64_t args[6] = {};
    int64_t ret = 0;
    if (!gUp.worker.joinable() || size < offsetof(mm_event, kpath) + MM_PATH) return;
    const char* bytes = static_cast<const char*>(data);
    std::memcpy(&kind, bytes, sizeof(kind));
    std::memcpy(&nr, bytes + offsetof(mm_event, nr), sizeof(nr));
    const bool image = kind == MM_IMAGE && nr == MM_IMAGE_MPROTECT;
    if (!image && (kind != MM_SYSCALL || (nr != SYS_mmap && nr != SYS_mprotect))) return;
    std::memcpy(&flags, bytes + offsetof(mm_event, flags), sizeof(flags));
    std::memcpy(&tgid, bytes + offsetof(mm_event, tgid), sizeof(tgid));
    std::memcpy(&tid, bytes + offsetof(mm_event, tid), sizeof(tid));
    std::memcpy(args, bytes + offsetof(mm_event, args), sizeof(args));
    std::memcpy(&ret, bytes + offsetof(mm_event, ret), sizeof(ret));
    const std::string path = (flags & MM_F_KPATH) == 0 ? std::string()
                             : std::string(bytes + offsetof(mm_event, kpath), strnlen(bytes + offsetof(mm_event, kpath), MM_PATH));
    if (image) {   /* args: vma start, size, prot, flags, file offset */
        if (ret == 0 && WmiModule(path) == "wbemprox.dll") gUp.pending[tid] = {tgid, path, args[4], args[4] + args[1]};
        return;
    }
    if (nr == SYS_mprotect) {
        const auto found = gUp.pending.find(tid);
        if (found == gUp.pending.end()) return;
        const UpPending job = found->second;
        gUp.pending.erase(found);
        if (ret != 0 || !(args[2] & 0x4)) return;   /* PROT_EXEC */
        std::lock_guard<std::mutex> lock(gUp.mutex);
        gUp.queue.push_front(job);
        gUp.wake.notify_one();
        return;
    }
    if (!(args[2] & 0x4) || ret < 0 || !UpWanted(path)) return;   /* PROT_EXEC */
    std::lock_guard<std::mutex> lock(gUp.mutex);
    UpLibrary(path);
}

/* A process joined after it mapped its libraries: the probed ones it has (read from its maps). */
void UpJoined(uint32_t pid)
{
    if (!gUp.worker.joinable()) return;
    std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
    std::lock_guard<std::mutex> lock(gUp.mutex);
    for (std::string line; std::getline(maps, line);) {
        const size_t slash = line.find('/');
        if (slash == std::string::npos || line.find(" r-xp ") == std::string::npos || !UpWanted(line.substr(slash))) continue;
        UpLibrary(line.substr(slash));
    }
}

/* The process exited (or left scope): the worker destroys its ExecQuery links. */
void UpForget(uint32_t tgid)
{
    std::lock_guard<std::mutex> lock(gUp.mutex);
    auto found = gUp.processes.find(tgid);
    if (found == gUp.processes.end()) return;
    gUp.dead.insert(gUp.dead.end(), found->second.begin(), found->second.end());
    gUp.processes.erase(found);
    gUp.wake.notify_one();
}

/* At the stop: the calls the rate limit still holds (up_rate: left out since their key's last record) as repeats_tail
 * records of their function (value0 the key, value1 the calls), so only an evicted key's are lost (ebpf_losses
 * ucall_unreported). */
void UpDrain()
{
    bpf_map* map = gBpf.object ? bpf_object__find_map_by_name(gBpf.object, "up_rate") : nullptr;
    if (map == nullptr) return;
    const int fd = bpf_map__fd(map);
    std::vector<up_rate_key> keys;
    up_rate_key at{}, next{};
    for (bool first = true; bpf_map_get_next_key(fd, first ? nullptr : &at, &next) == 0; first = false) keys.push_back(at = next);
    for (const up_rate_key& key : keys) {
        up_rate rate{};
        uint64_t start = 0;
        ULONG flags = 0;
        const uint32_t index = key.cookie & 0xffff;
        if (bpf_map_lookup_and_delete_elem(fd, &key, &rate) != 0 || rate.skipped == 0 || index >= std::size(kUpCalls) ||
            (key.cookie & MM_UP_BUDGET) != 0 || !gBpf.session->Tracked(key.tgid, start, flags))
            continue;
        gBpf.upDrained += rate.skipped;
        LinuxRecord record;
        record.sensor = MSMON_SENSOR_LINUX_EBPF_FILE;
        record.type = MsMonFileQueryInformation;
        record.pid = key.tgid;
        record.start = start;
        record.value0 = key.key;
        record.value1 = rate.skipped;
        record.text = L"system:" + LinuxWide(kUpCalls[index].name);
        record.detail = L"repeats_tail;syscall=" + LinuxWide(kUpCalls[index].name) + L";key=" + Hex(key.key) +
                        ((key.cookie & MM_UP_PAGE) != 0 ? L";page=" + Hex(key.key2 << 12) : key.key2 ? L";key2=" + Hex(key.key2) : L"") +
                        L";repeats_before=" +
                        std::to_wstring(rate.skipped) + L";library=" + ((key.cookie & kUpI386) != 0 ? L"i386-unix/" : L"x86_64-unix/") +
                        LinuxWide(kUpCalls[index].library) + NativeNote(key.tgid);
        gBpf.session->Write(record);
    }
}

/* The kernel aggregate of a MM_UP_PAGE function's calls past its MM_UP_PAGES records of a second (Index: its kUpCalls
 * row; Key: its key argument, a handle): a repeats_tail record of the function, key=, the pages' range in
 * repeat_offsets, repeat_bytes 4096 a call. */
LinuxRecord UpAggSummary(uint32_t index, uint64_t key, const mm_agg& total)
{
    LinuxRecord record = AggSummary(index < std::size(kUpCalls) ? kUpCalls[index].name : "ucall", nullptr, 0, total);
    record.detail.insert(record.detail.find(L";repeats_before="), L";key=" + Hex(key));
    return record;
}

std::wstring Utf16(const char* bytes, size_t size)
{
    std::wstring text;
    for (size_t at = 0; at + 1 < size; at += 2) {
        const wchar_t c = static_cast<wchar_t>(static_cast<uint8_t>(bytes[at]) | static_cast<uint8_t>(bytes[at + 1]) << 8);
        if (c == 0) break;
        text += c == L';' ? L',' : c;   /* ';' separates detail fields */
    }
    return text;
}

/* MM_KEV_UCALL: system:<function>, value0 the key argument, value1 the calls of that key left out before it. */
void OnUpCall(const mm_event& e, const std::wstring& note)
{
    const uint32_t index = static_cast<uint32_t>(e.pos & 0xffff);
    if (index >= std::size(kUpCalls)) return;
    const UpCall& call = kUpCalls[index];
    const bool i386 = (e.pos & kUpI386) != 0;
    const uint32_t msg = static_cast<uint32_t>(e.args[1]);
    const bool message = std::strcmp(call.name, "NtUserMessageCall") == 0 || std::strcmp(call.name, "NtUserPostMessage") == 0;
    /* a keyboard message's wparam and lparam are the user's typing: withheld but with --log-real-input */
    const bool withheld = message && WsKeyboardMessage(msg, 0) && !gRealInput;
    std::wstring detail = L"call=" + LinuxWide(call.name) + L";args=";
    for (unsigned at = 0; at < 6; at++) detail += (at ? L"," : L"") + (withheld && (at == 2 || at == 3) ? L"withheld" : Hex(e.args[at]));
    const uint64_t key = call.key ? e.args[call.key - 1] : 0;
    for (const UpClass& known : kUpClasses) {
        /* The class is the first argument of the system queries, the second of the handle-taking ones, key2 of a
         * multiplexer, else cls's; an int argument's upper half is not the caller's. */
        const uint64_t value = call.cls                                        ? e.args[call.cls - 1]
                               : call.key2                                     ? e.args[call.key2 - 1]
                               : std::strncmp(call.name, "NtQuerySystem", 13) == 0 ? e.args[0]
                                                                                  : e.args[1];
        if (std::strcmp(known.call, call.name) == 0 && known.value == static_cast<uint32_t>(value))
            detail += L";class_name=" + std::wstring(known.name);
    }
    DWORD target = 0;
    if (call.hwnd) {   /* another program's window (MM_UP_HWND): its owner, or unknown (made before tracking) */
        target = e.target_tgid;
        detail += target != 0 ? L";owner_pid=" + std::to_wstring(target) : std::wstring(L";owner=unknown");
        for (const auto& [value, name] : kUpMessages) {
            if (message && value == msg) detail += L";msg_name=" + std::wstring(name);
        }
        if (withheld) detail += L";input=withheld";
    }
    const uint64_t self = i386 ? 0xffffffffull : ~0ull;   /* NtCurrentProcess(); NtCurrentThread() is one below */
    if (std::strstr(call.name, "Process") || std::strstr(call.name, "Thread") || std::strstr(call.name, "VirtualMemory")) {
        if (e.args[0] == self || e.args[0] == self - 1) detail += L";handle=self";
    }
    if (e.sock_len != 0) detail += L";string=" + Utf16(e.path_a, std::min<size_t>(e.sock_len, sizeof(e.path_a)));
    if (e.ret > 0) detail += L";calls_skipped=" + std::to_wstring(e.ret);
    detail += std::wstring(L";library=") + (i386 ? L"i386-unix/" : L"x86_64-unix/") + LinuxWide(call.library) + note;
    Record(e, MSMON_SENSOR_LINUX_EBPF_FILE, MsMonFileQueryInformation, key, e.ret > 0 ? e.ret : 0,
           L"system:" + LinuxWide(call.name), detail, 0, target);
}

/* MM_KEV_TLS: the plaintext of one TLS record call as a tls_plaintext payload on a file_write/file_read of
 * tls:session=<gnutls session>. Wine's schannel moves the ciphertext itself, so no fd: the same thread's next socket
 * send (or its previous receive) carries it. */
void OnUpTls(const mm_event& e, PayloadMessages& payload, const std::wstring& note)
{
    const bool received = (e.args[3] & MM_UP_TLS_RECV) != 0;
    const ULONG type = received ? MsMonFileRead : MsMonFileWrite;
    const std::wstring text = L"tls:session=" + Hex(e.args[0]);
    std::wstring detail = std::wstring(L"tls_plaintext;via=gnutls;call=") + (received ? L"gnutls_record_recv" : L"gnutls_record_send") +
                          L";requested=" + std::to_wstring(e.args[2]) + L";ret=" + std::to_wstring(e.ret) +
                          ((e.args[3] & MM_UP_TLS_32) != 0 ? L";arch=i386;" : L";arch=x86_64;") + L"source=uprobe" + note;
    const uint64_t bytes = e.ret > 0 ? static_cast<uint64_t>(e.ret) : 0;
    if ((e.flags & MM_F_PAYLOAD) != 0) {
        RecordPayload(e, payload, MSMON_SENSOR_LINUX_EBPF_NET, type, bytes, 0, text, detail, 0, !received, MsMonPayloadTlsPlaintext);
        return;
    }
    if (Repeated(e, "tls", MSMON_SENSOR_LINUX_EBPF_NET, type, text, received, true, detail)) return;
    Record(e, MSMON_SENSOR_LINUX_EBPF_NET, type, bytes, 0, text, detail, 0);
}

/* MM_KEV_WMI: an etw_wmi record with the WQL text or object path (Windows: WMI-Activity's Query), its class as text;
 * operation exec_query, exec_query_async, get_object or create_instance_enum. */
void OnUpWmi(const mm_event& e, const std::wstring& note)
{
    static const wchar_t* const kOperations[MM_UP_WMI_METHODS] = {L"exec_query", L"exec_query_async", L"get_object",
                                                                  L"create_instance_enum"};
    const uint64_t method = e.args[2] < MM_UP_WMI_METHODS ? e.args[2] : MM_UP_WMI_EXEC_QUERY;
    const std::wstring query = Utf16(e.path_a, std::min<size_t>(e.sock_len, sizeof(e.path_a) + sizeof(e.path_b)));
    std::wstring wmiClass;
    if (method == MM_UP_WMI_GET_OBJECT || method == MM_UP_WMI_CREATE_INSTANCE_ENUM) {
        /* \\server\ROOT\CIMV2:<class> or <class>, up to '.' (its key) or '=' (a singleton's @), as Wine's parse_path */
        const size_t colon = query.rfind(L"\\", 0) == 0 ? query.find(L':') : std::wstring::npos;
        const size_t begin = query.find_first_not_of(L' ', colon == std::wstring::npos ? 0 : colon + 1);
        if (begin != std::wstring::npos) wmiClass = query.substr(begin, query.find_first_of(L".= ", begin) - begin);
    } else {
        std::wstring upper = query;
        for (wchar_t& c : upper) c = static_cast<wchar_t>(std::towupper(c));
        const size_t from = upper.find(L" FROM ");
        if (from != std::wstring::npos) {
            const size_t begin = query.find_first_not_of(L' ', from + 6);
            if (begin != std::wstring::npos) wmiClass = query.substr(begin, query.find_first_of(L" ", begin) - begin);
        }
    }
    std::wstring detail = std::wstring(L"operation=") + kOperations[method] + L";query=" +
                          (gBpf.payloads ? query : SanitizeQuery(query)) +
                          (method == MM_UP_WMI_GET_OBJECT || method == MM_UP_WMI_CREATE_INSTANCE_ENUM ? L";language=path"
                                                                                                       : L";language=WQL") +
                          L";source=uprobe" + note;
    const std::wstring text = L"query:" + (wmiClass.empty() ? std::wstring(L"unknown") : wmiClass);
    if (Repeated(e, "wmi", MSMON_SENSOR_LINUX_EBPF_FILE, MsMonEtwWmi, text, std::hash<std::wstring>()(query), false, detail)) return;
    Record(e, MSMON_SENSOR_LINUX_EBPF_FILE, MsMonEtwWmi, 0, 0, text, detail, 0);
}

/* MM_KEV_UCALL, MM_KEV_TLS, MM_KEV_WMI */
void OnUp(const mm_event& e)
{
    /* First, so the chunks of a record the agent drops do not wait in payloadChunks. */
    PayloadMessages payload = (e.flags & MM_F_PAYLOAD) != 0 ? TakePayload(e) : PayloadMessages{};
    uint64_t start = 0;
    ULONG trackFlags = 0;
    if (!gBpf.session->Tracked(e.tgid, start, trackFlags)) return;
    const std::wstring note = NativeNote(e.tgid);
    if (e.nr == MM_KEV_UCALL) OnUpCall(e, note);
    if (e.nr == MM_KEV_TLS) OnUpTls(e, payload, note);
    if (e.nr == MM_KEV_WMI) OnUpWmi(e, note);
}

/* The worker that attaches, first the known Wine installs' libraries; each link is an fd, so the fd limit goes to its
 * hard maximum. */
int UpOpened(std::wstring& detail, unsigned&)
{
    detail += L";uprobes=" + GroupState("uprobes");
    if (!GroupOn("uprobes")) return 0;
    rlimit files{};
    if (getrlimit(RLIMIT_NOFILE, &files) == 0 && files.rlim_cur < files.rlim_max) {
        files.rlim_cur = files.rlim_max;
        setrlimit(RLIMIT_NOFILE, &files);
    }
    gUp.stop = false;
    {
        std::lock_guard<std::mutex> lock(gUp.mutex);
        for (const char* root : kWineRoots) {
            for (const char* library : {"x86_64-unix/ntdll.so", "x86_64-unix/win32u.so", "i386-unix/ntdll.so", "i386-unix/win32u.so"}) {
                char real[PATH_MAX];   /* as /proc maps and the kernel name it */
                if (realpath((std::string(root) + "/lib/wine/" + library).c_str(), real) != nullptr) UpLibrary(real);
            }
        }
    }
    gUp.worker = std::thread(UpWork);
    return 0;
}

void UpNotes(Notes& notes)
{
    notes.emplace_back(L"function_probes",
                       L"uprobes=" + GroupState("uprobes") +
                           L";records=system:<NtUserXxx|NtGdiXxx|NtXxx> (win32u.so and ntdll.so calls Wine answers"
                           L" in-process: key state, cursor, windows, screen reads, hooks, raw input, system and process"
                           L" queries; one record per process, function and key argument a second, calls_skipped counts"
                           L" the rest),tls:session=<gnutls> file_write/file_read (Wine's schannel through"
                           L" libgnutls.so.30; plaintext as tls_plaintext payloads unless --no-payloads),etw_wmi"
                           L" query:<class> (wbemprox ExecQuery with the WQL text);probed=once per library file (every process"
                           L" mapping it traps, only tracked ones are recorded), the Wine installs under /opt/wine-* and"
                           L" /usr/local from the start, others from a few ms after a tracked process first maps them,"
                           L" wbemprox per process once its code is executable;window_probes=" +
                           (gWindowProbes ? std::wstring(L"on") : std::wstring(L"off(--window-probes)")) +
                           L" (NtUserCallHwndParam, NtUserMessageCall, NtUserPostMessage, NtUserSetWindowLong(Ptr),"
                           L" NtUserSetWindowPos on other programs' windows only; a trap per call however filtered)"
                           L";not_seen=TLS inside PE"
                           L" code (OpenSSL/BoringSSL DLLs, CEF, game crypto: decrypt events.pcapng with an SSLKEYLOGFILE"
                           L" the program writes),return values of win32u/ntdll calls");
}

void UpClose()
{
    if (gUp.worker.joinable()) {
        {
            std::lock_guard<std::mutex> lock(gUp.mutex);
            gUp.stop = true;
        }
        gUp.wake.notify_one();
        gUp.worker.join();
    }
    std::lock_guard<std::mutex> lock(gUp.mutex);
    gUp.queue.clear();
    for (bpf_link* link : gUp.dead) bpf_link__destroy(link);
    gUp.dead.clear();
    for (bpf_link* link : gUp.links) bpf_link__destroy(link);
    gUp.links.clear();
    gUp.libraries.clear();
    for (auto& [tgid, links] : gUp.processes) {
        for (bpf_link* link : links) bpf_link__destroy(link);
    }
    gUp.processes.clear();
    gUp.pending.clear();
}

}  // namespace
