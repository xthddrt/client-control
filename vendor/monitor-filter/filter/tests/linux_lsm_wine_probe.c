/* The Windows side of tests/linux_lsm_test.sh's Wine section: process and thread handles and
 * the registry requests kfilter decides from wineserver's protocol, a file query, and requests
 * reaching kfpeer.exe (a copy of this program it starts) or asking about the system, new executable
 * memory and an open made with its own syscall instruction. Each action prints
 * "name=denied" when it failed and "name=ok" otherwise (under Wine a refused request fails with
 * STATUS_ACCESS_VIOLATION). No CRT or Windows headers: built by the test with
 *   clang -target x86_64-w64-windows-gnu -ffreestanding -c, then GNU ld -m i386pep
 * against Wine's own kernel32/advapi32/ntdll/user32 import libraries. Run as "hold" it waits, maps
 * executable memory and waits again (the protected side); as "peer" (kfpeer.exe) it enumerates
 * processes and handles, starts a thread and creates a named mutex, its exit code saying which failed; as "outside" it opens a running kfprobe.exe
 * (an outside opener); as "register" it registers its stdout pipe as a wineserver request pipe of
 * its own (a forged init_thread), for the protected shell that ran it to write raw requests to; as
 * "inproc" it makes calls Wine answers in-process (the cursor and window list in win32u.so, also from
 * a 32-bit rundll32; key states by key, window titles its own and kfpeer.exe's; ntdll.so's process queries by class)
 * and WMI queries (wmic, x64 and 32-bit, and its own ExecQuery and ExecMethod calls through ole32); as "hwndparam" it
 * times GetWindowRect (NtUserCallHwndParam) on its own window; as
 * "addr" it reaches into kfpeer.exe (run as "target") inside and outside addr= ranges (tests/linux_lsm_test.sh); as
 * "requests" it makes one wineserver request of each family /system/wine/<request> rules name (a message to another
 * program's window, the foreground, the clipboard, a global keyboard hook, a job, a token, an object's name, an atom,
 * a desktop switch, a file lock) and wine_server_call writes of its own: a name split across data chunks, then data
 * chunks that do not add up to the request's size (Wine never writes that: refused, or wineserver loses its place); as
 * "reach" what requests reach past their own decision (reach()), its peer kfpeer.exe run as "window". */
typedef void* HANDLE;
typedef void* HKEY;
typedef unsigned long DWORD;
typedef int BOOL;
#define API __declspec(dllimport) __stdcall

API HANDLE CreateToolhelp32Snapshot(DWORD, DWORD);
API BOOL Thread32First(HANDLE, void*);
API BOOL Thread32Next(HANDLE, void*);
API DWORD GetCurrentProcessId(void);
API HANDLE GetCurrentProcess(void);
API HANDLE GetCurrentThread(void);
API HANDLE OpenThread(DWORD, BOOL, DWORD);
API HANDLE OpenProcess(DWORD, BOOL, DWORD);
API BOOL DuplicateHandle(HANDLE, HANDLE, HANDLE, HANDLE*, DWORD, BOOL, DWORD);
API BOOL CloseHandle(HANDLE);
API HANDLE CreateEventA(void*, BOOL, BOOL, const char*);
API HANDLE CreateMutexA(void*, BOOL, const char*);
API HANDLE GetStdHandle(DWORD);
API BOOL WriteFile(HANDLE, const void*, DWORD, DWORD*, void*);
API void ExitProcess(unsigned);
API long RegOpenKeyExA(HKEY, const char*, DWORD, DWORD, HKEY*);
API long RegFlushKey(HKEY);
API BOOL OpenProcessToken(HANDLE, DWORD, HANDLE*);
API long RegNotifyChangeKeyValue(HKEY, BOOL, DWORD, HANDLE, BOOL);
API long RegGetKeySecurity(HKEY, DWORD, void*, DWORD*);
API long RegSetKeySecurity(HKEY, DWORD, void*);
API long RegCloseKey(HKEY);
API long RegQueryValueExA(HKEY, const char*, DWORD*, DWORD*, unsigned char*, DWORD*);
API BOOL InitializeSecurityDescriptor(void*, DWORD);
API BOOL SetSecurityDescriptorDacl(void*, BOOL, void*, BOOL);
API BOOL Process32First(HANDLE, void*);
API BOOL Process32Next(HANDLE, void*);
API void Sleep(DWORD);
API void* VirtualAlloc(void*, unsigned long long, DWORD, DWORD);
API BOOL VirtualProtect(void*, unsigned long long, DWORD, DWORD*);
API HANDLE CreateThread(void*, unsigned long long, DWORD (__stdcall*)(void*), void*, DWORD, DWORD*);
API const char* GetCommandLineA(void);
API long NtGetNextThread(HANDLE, HANDLE, DWORD, DWORD, DWORD, HANDLE*);
API long NtGetNextProcess(HANDLE, DWORD, DWORD, DWORD, HANDLE*);
API DWORD GetModuleFileNameA(HANDLE, char*, DWORD);
API DWORD GetFileAttributesA(const char*);
API DWORD GetLastError(void);
API long NtQuerySystemInformation(DWORD, void*, DWORD, DWORD*);
API BOOL ReadProcessMemory(HANDLE, const void*, void*, unsigned long long, unsigned long long*);
API BOOL WriteProcessMemory(HANDLE, void*, const void*, unsigned long long, unsigned long long*);
API HANDLE CreateRemoteThread(HANDLE, void*, unsigned long long, DWORD (__stdcall*)(void*), void*, DWORD, DWORD*);
API DWORD WaitForSingleObject(HANDLE, DWORD);
API BOOL GetExitCodeProcess(HANDLE, DWORD*);
API BOOL GetCursorPos(long*);
API BOOL EnumWindows(BOOL (__stdcall*)(HANDLE, long long), long long);
API HANDLE CreateWindowExA(DWORD, const char*, const char*, DWORD, int, int, int, int, HANDLE, HANDLE, HANDLE, void*);
API unsigned long long VirtualQueryEx(HANDLE, const void*, void*, unsigned long long);
API long NtQueryInformationProcess(HANDLE, DWORD, void*, DWORD, DWORD*);
API DWORD GetProcessId(HANDLE);
API BOOL SetThreadContext(HANDLE, const void*);
API BOOL GetThreadContext(HANDLE, void*);
API DWORD SuspendThread(HANDLE);
API DWORD ResumeThread(HANDLE);
API BOOL TerminateProcess(HANDLE, unsigned);
API long CoInitializeEx(void*, DWORD);
API long CoCreateInstance(const void*, void*, DWORD, const void*, void**);
API long long SendMessageTimeoutA(HANDLE, unsigned, unsigned long long, long long, unsigned, unsigned, unsigned long long*);
API HANDLE GetDesktopWindow(void);
API BOOL SetForegroundWindow(HANDLE);
API BOOL OpenClipboard(HANDLE);
API BOOL EmptyClipboard(void);
API HANDLE SetClipboardData(unsigned, HANDLE);
API HANDLE GetClipboardData(unsigned);
API BOOL CloseClipboard(void);
API HANDLE GlobalAlloc(unsigned, unsigned long long);
API void* GlobalLock(HANDLE);
API BOOL GlobalUnlock(HANDLE);
API HANDLE SetWindowsHookExA(int, long long (__stdcall*)(int, unsigned long long, long long), HANDLE, DWORD);
API BOOL UnhookWindowsHookEx(HANDLE);
API HANDLE GetModuleHandleA(const char*);
API HANDLE CreateJobObjectA(void*, const char*);
API BOOL AssignProcessToJobObject(HANDLE, HANDLE);
API BOOL DuplicateToken(HANDLE, int, HANDLE*);
API long NtQueryObject(HANDLE, DWORD, void*, DWORD, DWORD*);
API unsigned short GlobalAddAtomA(const char*);
API HANDLE CreateDesktopA(const char*, const char*, void*, DWORD, DWORD, void*);
API BOOL SwitchDesktop(HANDLE);
API BOOL CloseDesktop(HANDLE);
API DWORD GetTempPathA(DWORD, char*);
API BOOL LockFile(HANDLE, DWORD, DWORD, DWORD, DWORD);
API unsigned wine_server_call(void*);
API HANDLE FindWindowA(const char*, const char*);
API DWORD GetWindowThreadProcessId(HANDLE, DWORD*);
API BOOL SendNotifyMessageA(HANDLE, unsigned, unsigned long long, long long);
API BOOL PostMessageA(HANDLE, unsigned, unsigned long long, long long);
API BOOL PostThreadMessageA(DWORD, unsigned, unsigned long long, long long);
API long long SetWindowLongPtrA(HANDLE, int, long long);
API int InternalGetWindowText(HANDLE, unsigned short*, int);
API BOOL PeekMessageA(void*, HANDLE, unsigned, unsigned, unsigned);
API long long DispatchMessageA(const void*);
API unsigned SendInput(unsigned, void*, int);
API BOOL DeviceIoControl(HANDLE, DWORD, void*, DWORD, void*, DWORD, DWORD*, void*);
API HANDLE OpenSCManagerA(const char*, const char*, DWORD);
API HANDLE OpenServiceA(HANDLE, const char*, DWORD);
API BOOL StartServiceA(HANDLE, DWORD, const char**);
API BOOL CloseServiceHandle(HANDLE);
API BOOL GetThreadTimes(HANDLE, void*, void*, void*, void*);
API DWORD GetCurrentThreadId(void);
API void SetLastError(DWORD);
API DWORD GetTickCount(void);
API short GetAsyncKeyState(int);
API BOOL GetWindowRect(HANDLE, long*);
API BOOL QueryPerformanceCounter(long long*);
API BOOL QueryPerformanceFrequency(long long*);

typedef struct {
    DWORD cb;
    char *reserved, *desktop, *title;
    DWORD x, y, width, height, columns, rows, fill, flags;
    unsigned short show, reserved2;
    void* reserved3;
    HANDLE input, output, error;
} STARTUPINFOA;

typedef struct {
    HANDLE process, thread;
    DWORD pid, tid;
} PROCESS_INFORMATION;

API BOOL CreateProcessA(const char*, char*, void*, void*, BOOL, DWORD, void*, const char*, STARTUPINFOA*,
                        PROCESS_INFORMATION*);
API HANDLE CreateNamedPipeA(const char*, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, void*);
API HANDLE CreateFileA(const char*, DWORD, DWORD, void*, DWORD, DWORD, HANDLE);
API long NtQueryVolumeInformationFile(HANDLE, void*, void*, DWORD, DWORD);
API HANDLE CreateFileMappingA(HANDLE, void*, DWORD, DWORD, DWORD, const char*);
API HANDLE OpenFileMappingA(DWORD, BOOL, const char*);

#define HKEY_CURRENT_USER ((HKEY)(unsigned long long)0x80000001)
#define KEY_READ 0x20019
#define KEY_NOTIFY 0x10
#define READ_CONTROL 0x20000
#define WRITE_DAC 0x40000
#define DACL_SECURITY_INFORMATION 4

typedef struct {
    DWORD size, usage, tid, owner;
    long base, delta;
    DWORD flags;
} THREADENTRY32;

typedef struct {
    DWORD size, usage, pid;
    unsigned long long heap;
    DWORD module, threads, parent;
    long priority;
    DWORD flags;
    char exe[260];
} PROCESSENTRY32;

/* A Linux system call, made directly (as a program can, around Wine). */
static long long linux_syscall(long long number, long long a, long long b, long long c)
{
    long long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(number), "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
    return result;
}

static long long linux_syscall6(long long number, long long a, long long b, long long c, long long d, long long e,
                                long long f)
{
    long long result;
    register long long r10 __asm__("r10") = d, r8 __asm__("r8") = e, r9 __asm__("r9") = f;
    __asm__ volatile("syscall" : "=a"(result) : "a"(number), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return result;
}

static int has_word(const char* text, const char* word)
{
    for (; *text; text++) {
        int i = 0;
        while (word[i] && text[i] == word[i]) i++;
        if (!word[i]) return 1;
    }
    return 0;
}

static void say(const char* name, const char* word)
{
    char text[96];
    DWORD n = 0, written;
    while (name[n] && n < 80) { text[n] = name[n]; n++; }
    text[n++] = '=';
    for (int i = 0; word[i] && n < 94; i++) text[n++] = word[i];
    text[n++] = '\n';
    WriteFile(GetStdHandle((DWORD)-11), text, n, &written, 0);
}

static void line(const char* name, int failed)
{
    say(name, failed ? "denied" : "ok");
}

static void say_number(const char* name, unsigned long long value)
{
    char digits[24];
    int n = 23;
    digits[n] = 0;
    do digits[--n] = (char)('0' + value % 10); while ((value /= 10) != 0 && n > 0);
    say(name, digits + n);
}

static HKEY key(const char* name, DWORD access)
{
    HKEY result = 0;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, name, 0, access, &result) != 0) return 0;
    return result;
}

static DWORD __stdcall idle(void* unused)
{
    (void)unused;
    Sleep(5000);
    return 0;
}

static int windows;

static BOOL __stdcall count_window(HANDLE window, long long unused)
{
    (void)window;
    (void)unused;
    windows++;
    return 1;
}

/* Runs a command line (a child, so in the family) to its end: "ok" when it exits 0, "denied" when it
 * fails as a program does (wmic: -1), "crashed" for an exception code. */
static void run(const char* name, const char* command)
{
    static char line[300];
    static STARTUPINFOA startup = {sizeof(startup)};
    PROCESS_INFORMATION child;
    DWORD code = 0, i = 0;
    for (; command[i] && i < sizeof(line) - 1; i++) line[i] = command[i];
    line[i] = 0;
    if (!CreateProcessA(0, line, 0, 0, 0, 0, 0, 0, &startup, &child)) {
        say(name, "not_started");
        return;
    }
    WaitForSingleObject(child.process, 60000);
    GetExitCodeProcess(child.process, &code);
    say(name, code == 0 ? "ok" : code == 0xFFFFFFFF || code < 0x100 ? "denied" : "crashed");
}

/* WQL queries this module makes itself, through IWbemServices::ExecQuery (vtable entry 20), and the
 * same classes through ExecQueryAsync (21), GetObject (6) and CreateInstanceEnum (18): "denied" when
 * it fails (kb_wmi's WBEM_E_ACCESS_DENIED). Each is a BSTR: its byte count, then the text. */
#define BSTR_OF(text) {sizeof(text) - 2, text}
static struct { DWORD bytes; unsigned short text[200]; } wql_language = BSTR_OF(L"WQL"), wql_space = BSTR_OF(L"ROOT\\CIMV2"),
    wql_star = BSTR_OF(L"SELECT*FROM Win32_BIOS"),
    wql_long = BSTR_OF(L"SELECT Caption, Description, IdentificationCode, Manufacturer, Name, ReleaseDate, SerialNumber, "
                       L"SMBIOSBIOSVersion, SMBIOSMajorVersion, SMBIOSMinorVersion, Version FROM Win32_BIOS"),
    wql_unsized = {0, L"SELECT * FROM Win32_BIOS"},   /* a byte count Wine ignores */
    wql_dash = BSTR_OF(L"SELECT SerialNumber, x-from FROM Win32_BIOS"),   /* "x-from" is one identifier to Wine */
    wql_module = BSTR_OF(L"SELECT * FROM Win32_Processor"),
    path_bios = BSTR_OF(L"Win32_BIOS"), path_bios_key = BSTR_OF(L"Win32_BIOS=@"), path_os = BSTR_OF(L"Win32_OperatingSystem"),
    path_process = BSTR_OF(L"Win32_Process"), method_none = BSTR_OF(L"KfNoSuchMethod");

/* An IWbemObjectSink for ExecQueryAsync: QueryInterface, AddRef, Release, Indicate, SetStatus. */
static volatile long sink_done;
static long __stdcall sink_query(void* self, const void* iid, void** out) { *out = self; return 0; }
static unsigned long __stdcall sink_ref(void* self) { return 1; }
static long __stdcall sink_indicate(void* self, long count, void** objects) { return 0; }
static long __stdcall sink_status(void* self, long flags, long result, void* text, void* object) { sink_done = 1; return 0; }
static void* sink_vtbl[5] = {(void*)sink_query, (void*)sink_ref, (void*)sink_ref, (void*)sink_indicate, (void*)sink_status};
static void* sink[1] = {sink_vtbl};

static void wql(void)
{
    static const DWORD locator_class[4] = {0x4590f811, 0x11d01d3a, 0xaa001f89, 0x242e4b00};   /* WbemLocator */
    static const DWORD locator_iid[4] = {0xdc12a687, 0x11cf737f, 0xaa004d88, 0x242e4b00};     /* IWbemLocator */
    typedef long (*connect_server)(void*, void*, void*, void*, void*, long, void*, void*, void**);
    typedef long (*exec_query)(void*, void*, void*, long, void*, void**);
    void *locator = 0, *services = 0, *results;
    CoInitializeEx(0, 0);
    if (CoCreateInstance(locator_class, 0, 1 /* CLSCTX_INPROC_SERVER */, locator_iid, &locator) == 0)
        ((connect_server)(*(void***)locator)[3])(locator, wql_space.text, 0, 0, 0, 0, 0, 0, &services);
    if (!services) {
        say("wql_setup", "failed");
        return;
    }
    exec_query exec = (exec_query)(*(void***)services)[20];
    line("wmi_star", exec(services, wql_language.text, wql_star.text, 0, 0, &results) != 0);
    line("wmi_long", exec(services, wql_language.text, wql_long.text, 0, 0, &results) != 0);
    line("wmi_unsized", exec(services, wql_language.text, wql_unsized.text, 0, 0, &results) != 0);
    line("wmi_dash", exec(services, wql_language.text, wql_dash.text, 0, 0, &results) != 0);
    line("wmi_module", exec(services, wql_language.text, wql_module.text, 0, 0, &results) != 0);
    typedef long (*exec_async)(void*, void*, void*, long, void*, void*);
    typedef long (*get_object)(void*, void*, long, void*, void**, void**);
    typedef long (*instance_enum)(void*, void*, long, void*, void**);
    void** methods = *(void***)services;
    void* object = 0;
    line("wmi_get_object", ((get_object)methods[6])(services, path_bios.text, 0, 0, &object, 0) != 0);
    /* Wine itself fails "Win32_BIOS=@" (it queries WHERE <key>=@, wbemprox parse_path), so only kfilter's own
     * WBEM_E_ACCESS_DENIED counts as refused: the check is that kfilter names the class of a key path. */
    line("wmi_get_object_key", ((get_object)methods[6])(services, path_bios_key.text, 0, 0, &object, 0)
                                   == (long)0x80041003);
    line("wmi_get_object_os", ((get_object)methods[6])(services, path_os.text, 0, 0, &object, 0) != 0);
    line("wmi_instance_enum", ((instance_enum)methods[18])(services, path_bios.text, 0, 0, &results) != 0);
    /* ExecMethod (24) of a method Win32_Process does not have: kfilter decides it by name first (refused:
     * WBEM_E_ACCESS_DENIED); Wine fails it otherwise (WBEM_E_INVALID_METHOD), running nothing. */
    typedef long (*exec_method)(void*, void*, void*, long, void*, void*, void**, void**);
    void* out = 0;
    line("wmi_method", ((exec_method)methods[24])(services, path_process.text, method_none.text, 0, 0, 0, &out, 0) ==
                           (long)0x80041003);
    const long queued = ((exec_async)methods[21])(services, wql_language.text, wql_star.text, 0, 0, sink);
    line("wmi_async", queued != 0);
    for (int wait = 0; queued == 0 && wait < 50 && !sink_done; wait++) Sleep(100);   /* its thread done before exit */
}

/* Outside the family: open a running kfprobe.exe (the protected one) to terminate it. */
static void outside(void)
{
    for (int attempt = 0; attempt < 50; attempt++) {
        static PROCESSENTRY32 entry;   /* static: no memset without a CRT */
        entry.size = sizeof(entry);
        HANDLE snapshot = CreateToolhelp32Snapshot(2 /* TH32CS_SNAPPROCESS */, 0);
        for (BOOL more = Process32First(snapshot, &entry); more; more = Process32Next(snapshot, &entry)) {
            if (!has_word(entry.exe, "kfprobe.exe")) continue;
            HANDLE process = OpenProcess(0x1 /* TERMINATE */, 0, entry.pid);
            line("outside_open", process == 0);
            if (process) CloseHandle(process);
            CloseHandle(snapshot);
            ExitProcess(0);
        }
        CloseHandle(snapshot);
        Sleep(200);
    }
    line("outside_setup", 1);
    ExitProcess(1);
}

/* This thread's wineserver request and reply pipes (Wine's ntdll_thread_data in the TEB). */
static int* server_fds(void)
{
    unsigned long long teb;
    __asm__ volatile("movq %%gs:0x30, %0" : "=r"(teb));
    return (int*)(teb + 0x384);
}

/* A raw close_handle(0) to wineserver on our own request pipe, past Wine's decoding: 1 by
 * vmsplice, 2 by splice from a pipe of ours, 3 by /bin/sh, which we fork and exec with the pipe
 * (a protected program that is no longer Wine). Each is refused in block mode; when it went
 * through, its reply is read here so our next request gets its own. */
#define Z8 "\\0\\0\\0\\0\\0\\0\\0\\0"
static void raw_request(const char* name, int how)
{
    static unsigned int request[16] = {21 /* close_handle */};
    static unsigned char reply[64];
    static unsigned long long iov[2];
    static char* argv[] = {"/bin/sh", "-c", "printf '\\025" Z8 Z8 Z8 Z8 Z8 Z8 Z8 "\\0\\0\\0\\0\\0\\0\\0' >&9", 0};
    int* fds = server_fds();
    int sent = 0;
    long long result = 0;
    if (how == 1) {
        iov[0] = (unsigned long long)request;
        iov[1] = 64;
        result = linux_syscall6(278 /* vmsplice */, fds[0], (long long)iov, 1, 0, 0, 0);
        sent = result == 64;
    } else if (how == 2) {
        int other[2] = {-1, -1};
        if (linux_syscall(293 /* pipe2 */, (long long)other, 0, 0) == 0) {
            linux_syscall(1 /* write */, other[1], (long long)request, 64);
            result = linux_syscall6(275 /* splice */, other[0], 0, fds[0], 0, 64, 0);
            sent = result == 64;
            linux_syscall(3 /* close */, other[0], 0, 0);
            linux_syscall(3 /* close */, other[1], 0, 0);
        }
    } else {
        long long child = linux_syscall(57 /* fork */, 0, 0, 0);
        if (child == 0) {
            linux_syscall(33 /* dup2: not close-on-exec */, fds[0], 9, 0);
            linux_syscall(59 /* execve */, (long long)argv[0], (long long)argv, 0);
            linux_syscall(60 /* exit */, 127, 0, 0);
        }
        int status = -1;
        sent = child > 0 && linux_syscall6(61 /* wait4 */, child, (long long)&status, 0, 0, 0, 0) == child && status == 0;
    }
    if (sent) linux_syscall(0 /* read */, fds[1], (long long)reply, 64);
    /* vmsplice and splice are refused with -EPERM, not 0xFFFFFFFF (an int-typed x64 fmod_ret). */
    line(name, how == 3 ? !sent : result == -1);
}

/* Fixed places of memory for addr= rules (the policy of tests/linux_lsm_test.sh names them): kfpeer.exe's ("target")
 * and its own. */
#define KF_PEER_MEMORY 0x500000000ull
#define KF_SELF_MEMORY 0x510000000ull

/* addr= rules: reads, VirtualQueryEx and a hardware breakpoint in kfpeer.exe inside and outside the denied
 * 0x500001000-0x500001FFF (at both edges, and at kfpeer.exe+0x1000-0x1FFF, a module-relative range), a query with no
 * address after a refused read (it must not meet the rights-less addr= rule), a write of its own memory by pseudo
 * handle, the 9th rule on kfpeer.exe's own path, and a handle from NtGetNextProcess before (\@unknown, whose rule has a
 * range of its own) and after get_process_info names it (then kfpeer.exe's rules decide). */
static void addr(void)
{
    static char peer[280], arguments[300], buffer[16];
    static STARTUPINFOA startup = {sizeof(startup)};
    static unsigned long long info[6], peb[6], context[154] __attribute__((aligned(16)));
    PROCESS_INFORMATION child;
    unsigned long long got = 0, base = 0;
    DWORD n = GetModuleFileNameA(0, peer, 260);
    while (n > 0 && peer[n - 1] != '\\') n--;
    for (int i = 0; i < 11; i++) peer[n + i] = "kfpeer.exe"[i];
    for (DWORD i = 0; i < n; i++) arguments[i] = peer[i];
    for (int i = 0; i < 18; i++) arguments[n + i] = "kfpeer.exe target"[i];
    char* self = VirtualAlloc((void*)KF_SELF_MEMORY, 0x2000, 0x3000 /* COMMIT | RESERVE */, 0x04 /* READWRITE */);
    if (!self || !CreateProcessA(peer, arguments, 0, 0, 0, 0, 0, 0, &startup, &child)) {
        line("addr_setup", 1);
        ExitProcess(0);
    }
    Sleep(3000);   /* it has mapped its memory, and kfilterd has read its module table */
    const char* memory = (const char*)KF_PEER_MEMORY;
    line("addr_read_in", !ReadProcessMemory(child.process, memory + 0x1010, buffer, 2, &got));
    line("addr_read_out", !ReadProcessMemory(child.process, memory + 0x10, buffer, 2, &got));
    line("addr_edge_low", !ReadProcessMemory(child.process, memory + 0xFFF, buffer, 2, &got));    /* last byte = LO */
    line("addr_edge_high", !ReadProcessMemory(child.process, memory + 0x2000, buffer, 2, &got));  /* first byte = HI+1 */
    line("addr_marker_query", GetProcessId(child.process) == 0);
    line("addr_spill_read", !ReadProcessMemory(child.process, memory + 0x3800, buffer, 2, &got));
    if (NtQueryInformationProcess(child.process, 0 /* ProcessBasicInformation */, peb, sizeof(peb), 0) != 0 ||
        !ReadProcessMemory(child.process, (const char*)peb[1] + 0x10 /* ImageBaseAddress */, &base, 8, &got)) {
        line("addr_module_setup", 1);
    } else {
        line("addr_module_in", !ReadProcessMemory(child.process, (const char*)base + 0x1010, buffer, 2, &got));
        line("addr_module_out", !ReadProcessMemory(child.process, (const char*)base + 0x10, buffer, 2, &got));
    }
    line("addr_query_in", VirtualQueryEx(child.process, memory + 0x1010, info, sizeof(info)) == 0);
    line("addr_query_out", VirtualQueryEx(child.process, memory + 0x10, info, sizeof(info)) == 0);
    HANDLE thread = OpenThread(0x10 | 0x8 | 0x2 /* SET_CONTEXT | GET_CONTEXT | SUSPEND_RESUME */, 0, child.tid);
    if (thread) SuspendThread(thread);
    ((DWORD*)context)[12] = 0x100010;              /* ContextFlags @0x30: CONTEXT_AMD64 | DEBUG_REGISTERS */
    context[9] = KF_PEER_MEMORY + 0x1010;          /* Dr0 @0x48 */
    context[14] = 0x10001;                         /* Dr7 @0x70: Dr0 on, a one-byte write watch */
    line("addr_dr_in", !thread || !SetThreadContext(thread, context));
    context[9] = KF_PEER_MEMORY + 0x10;
    line("addr_dr_out", !thread || !SetThreadContext(thread, context));
    line("addr_get_context", !thread || !GetThreadContext(thread, context));
    if (thread) {
        ResumeThread(thread);
        CloseHandle(thread);
    }
    /* Its own memory by pseudo handle: a write, which Wine 11 asks wineserver for (its NtReadVirtualMemory copies the
     * current process's memory itself, no request). */
    line("addr_self_in", !WriteProcessMemory(GetCurrentProcess(), self + 0x1010, buffer, 2, &got));
    line("addr_self_out", !WriteProcessMemory(GetCurrentProcess(), self + 0x10, buffer, 2, &got));
    /* A handle kfilter cannot name: decided on \@unknown until a get_process_info reply names it. */
    HANDLE next = 0, following = 0;
    if (NtGetNextProcess(0, 0x400 | 0x10 /* QUERY_INFORMATION | VM_READ */, 0, 0, &next) != 0) {
        line("addr_unknown_setup", 1);
    } else {
        line("addr_unknown_query_in", VirtualQueryEx(next, memory + 0x2010, info, sizeof(info)) == 0);
        line("addr_unknown_query_out", VirtualQueryEx(next, memory + 0x10, info, sizeof(info)) == 0);
    }
    for (HANDLE h = next; h; h = following) {
        if (GetProcessId(h) == child.pid) {
            line("addr_next_read_in", !ReadProcessMemory(h, memory + 0x1010, buffer, 2, &got));
            line("addr_next_query_in", VirtualQueryEx(h, memory + 0x1010, info, sizeof(info)) == 0);
            line("addr_next_read_out", !ReadProcessMemory(h, memory + 0x10, buffer, 2, &got));
            break;
        }
        following = 0;
        if (NtGetNextProcess(h, 0x400 | 0x10, 0, 0, &following) != 0) following = 0;
    }
    TerminateProcess(child.process, 0);
    ExitProcess(0);
}

static long long __stdcall keyboard(int code, unsigned long long w, long long l)
{
    (void)code;
    (void)w;
    (void)l;
    return 0;
}

/* Wine's struct __server_request_info: the 64-byte request, then the data chunks wine_server_call writes after it. */
struct server_request {
    unsigned int header[16];   /* req, request_size, reply_size, fields */
    unsigned int data_count;
    void* reply_data;
    struct { const void* ptr; unsigned int size; } data[5];
};

/* open_mutex (38: access, attributes, rootdir; the name) by wine_server_call, its name split after its 5th character:
 * Size is what the header claims of it. STATUS_ACCESS_VIOLATION is kfilter's refusal. */
static unsigned split_open_mutex(unsigned size)
{
    static const unsigned short name[] = {'\\', 'B', 'a', 's', 'e', 'N', 'a', 'm', 'e', 'd', 'O', 'b', 'j', 'e', 'c', 't',
                                          's', '\\', 'k', 'f', 'p', 'r', 'o', 'b', 'e', '-', 's', 'p', 'l', 'i', 't'};
    static struct server_request request;
    request.header[0] = 38;
    request.header[1] = size;
    request.header[3] = 0x100000;   /* SYNCHRONIZE */
    request.data_count = 2;
    request.data[0].ptr = name;
    request.data[0].size = 10;
    request.data[1].ptr = (const char*)name + 10;
    request.data[1].size = sizeof(name) - 10;
    return wine_server_call(&request);
}

/* One request of each family as /system/wine/<request> rules name them (tests/linux_lsm_test.sh denies each). */
static void requests(void)
{
    unsigned long long result = 0;
    line("req_send_message", SendMessageTimeoutA(GetDesktopWindow(), 0 /* WM_NULL */, 0, 0, 2 /* ABORTIFHUNG */, 2000,
                                                 &result) == 0);
    HANDLE window = CreateWindowExA(0, "STATIC", "kfprobe", 0, 0, 0, 1, 1, 0, 0, 0, 0);
    line("req_foreground", !window || !SetForegroundWindow(window));
    HANDLE text = GlobalAlloc(2 /* MOVEABLE */, 8);
    char* bytes = text ? GlobalLock(text) : 0;
    if (bytes) {
        for (int i = 0; i < 8; i++) bytes[i] = "kfprobe"[i];
        GlobalUnlock(text);
    }
    if (!window || !OpenClipboard(window) || !EmptyClipboard() || !SetClipboardData(1 /* CF_TEXT */, text)) {
        line("req_clipboard_setup", 1);
    } else {
        CloseClipboard();
        line("req_clipboard", !OpenClipboard(window) || !GetClipboardData(1));
        CloseClipboard();
    }
    HANDLE hook = SetWindowsHookExA(13 /* WH_KEYBOARD_LL */, keyboard, GetModuleHandleA(0), 0);
    line("req_hook", hook == 0);
    if (hook) UnhookWindowsHookEx(hook);
    HANDLE job = CreateJobObjectA(0, 0);
    line("req_job", !job || !AssignProcessToJobObject(job, GetCurrentProcess()));
    HANDLE token = 0, copy = 0;
    line("req_token", !OpenProcessToken(GetCurrentProcess(), 0x2 | 0x8 /* DUPLICATE | QUERY */, &token) ||
                          !DuplicateToken(token, 2 /* SecurityImpersonation */, &copy));
    static char name[512];
    DWORD length = 0;
    HANDLE event = CreateEventA(0, 1, 0, "kfprobe-named");
    line("req_object_name", !event || NtQueryObject(event, 1 /* ObjectNameInformation */, name, sizeof(name), &length) != 0);
    line("req_atom", GlobalAddAtomA("kfprobe-atom") == 0);
    HANDLE desktop = CreateDesktopA("kfprobe-desk", 0, 0, 0, 0x100 | 0x80 /* SWITCHDESKTOP | CREATEMENU */, 0);
    line("req_desktop", !desktop || !SwitchDesktop(desktop));
    if (desktop) CloseDesktop(desktop);
    static char temp[300];
    DWORD n = GetTempPathA(260, temp);
    for (int i = 0; n && i < 13; i++) temp[n + i] = "kfprobe-lock"[i];
    HANDLE file = n ? CreateFileA(temp, 0xC0000000u /* GENERIC_READ|WRITE */, 0, 0, 2 /* CREATE_ALWAYS */, 0, 0) : 0;
    line("req_lock", !file || file == (HANDLE)(long long)-1 || !LockFile(file, 0, 0, 1, 0));
    /* A name split across chunks is decided whole (STATUS_ACCESS_VIOLATION: the deny on its name). */
    line("split_name", split_open_mutex(62) == 0xC0000005u);
    /* Chunks past what the header says: refused; let through (audit mode), wineserver reads the rest as the next
     * request, so this comes last. */
    line("split_short", split_open_mutex(10) == 0xC0000005u);
    ExitProcess(0);
}

/* "window" (kfpeer.exe): a top-level window of its own, its messages pumped for 25 s. */
static void window(void)
{
    static unsigned long long message[6];   /* MSG */
    HANDLE made = CreateWindowExA(0, "STATIC", "kfpeer-window", 0, 0, 0, 1, 1, 0, 0, 0, 0);
    for (DWORD start = GetTickCount(); GetTickCount() - start < 25000;) {
        while (PeekMessageA(message, 0, 0, 0, 1 /* PM_REMOVE */)) DispatchMessageA(message);
        Sleep(10);
    }
    ExitProcess(made ? 0 : 1);
}

/* Starts kfpeer.exe as "window" (Child) and finds its window, 0 when it cannot. */
static HANDLE peer_window(PROCESS_INFORMATION* child)
{
    static char peer[280], arguments[300];
    static STARTUPINFOA startup = {sizeof(startup)};
    DWORD n = GetModuleFileNameA(0, peer, 260);
    while (n > 0 && peer[n - 1] != '\\') n--;
    for (int i = 0; i < 11; i++) peer[n + i] = "kfpeer.exe"[i];
    for (int i = 0; i < 18; i++) arguments[n + i] = "kfpeer.exe window"[i];
    for (DWORD i = 0; i < n; i++) arguments[i] = peer[i];
    if (!CreateProcessA(peer, arguments, 0, 0, 0, 0, 0, 0, &startup, child)) return 0;
    Sleep(2000);   /* it makes its window */
    return FindWindowA("STATIC", "kfpeer-window");
}

/* Messages to kfpeer.exe's window (WM_COPYDATA by its full handle, its low 16 bits and a high word 0xFFFF; WM_USER+1
 * sent, posted, notified and posted to its thread; WM_NULL), its window changed (a raw set_window_pos by
 * wine_server_call, the handle at 0x14; SetWindowLongPtr, which Wine sends its thread as a message) and read
 * (InternalGetWindowText), its process put in a job (the handle CreateProcess gave) and its thread's times, a global and
 * a thread hook, SendInput of 'A' and 'B', DeviceIoControl on MountPointManager by code, and svcctl's RStartServiceW.
 * With Placed 0 (kfilterd started after kfpeer.exe made its window: a window and thread it cannot place) only the
 * window's change and messages. */
static void reach(int placed)
{
    static unsigned long long result, copy[3] = {1, 4, 0};   /* COPYDATASTRUCT: dwData, cbData, lpData */
    static char text[4] = "kf";
    static unsigned short title[64];
    PROCESS_INFORMATION child = {0};
    HANDLE window = placed ? peer_window(&child) : FindWindowA("STATIC", "kfpeer-window");
    if (!window) {
        line("reach_window", 1);
        ExitProcess(0);
    }
    DWORD tid = GetWindowThreadProcessId(window, 0);
    copy[2] = (unsigned long long)text;
    const unsigned long long full = (unsigned long long)window;
    static struct server_request position;   /* set_window_pos: swp_flags, paint_flags, monitor_dpi, handle@0x14 */
    position.header[0] = 155;
    position.header[5] = (unsigned)full;
    line("win_set_pos", wine_server_call(&position) == 0xC0000005u);
    line("win_null", !SendMessageTimeoutA(window, 0 /* WM_NULL */, 0, 0, 2, 2000, &result));
    SetLastError(0);
    line("win_set_long", SetWindowLongPtrA(window, -20 /* GWL_EXSTYLE */, 0) == 0 && GetLastError() != 0);
    if (!placed) {
        line("win_unknown_message", !SendMessageTimeoutA(window, 0x401, 0, 0, 2, 2000, &result));
        ExitProcess(0);
    }
    line("win_copydata", !SendMessageTimeoutA(window, 0x4A, 0, (long long)copy, 2, 2000, &result));
    line("win_copydata_low16", !SendMessageTimeoutA((HANDLE)(full & 0xFFFF), 0x4A, 0, (long long)copy, 2, 2000, &result));
    line("win_copydata_high", !SendMessageTimeoutA((HANDLE)((full & 0xFFFF) | 0xFFFF0000ull), 0x4A, 0, (long long)copy, 2, 2000,
                                                    &result));
    line("win_send", !SendMessageTimeoutA(window, 0x401 /* WM_USER+1 */, 0, 0, 2, 2000, &result));
    line("win_notify", !SendNotifyMessageA(window, 0x401, 0, 0));
    line("win_post", !PostMessageA(window, 0x401, 0, 0));
    line("win_post_thread", !PostThreadMessageA(tid, 0x401, 0, 0));
    line("win_text", InternalGetWindowText(window, title, 64) == 0);
    HANDLE job = CreateJobObjectA(0, 0);
    line("job_assign", !job || !AssignProcessToJobObject(job, child.process));
    unsigned long long times[4];
    HANDLE thread = OpenThread(0x800 /* QUERY_LIMITED_INFORMATION */, 0, tid);   /* named by its open_thread */
    line("thread_times", !thread || !GetThreadTimes(thread, &times[0], &times[1], &times[2], &times[3]));
    if (thread) CloseHandle(thread);
    HANDLE hook = SetWindowsHookExA(13 /* WH_KEYBOARD_LL */, keyboard, GetModuleHandleA(0), 0);
    line("hook_global", hook == 0);
    if (hook) UnhookWindowsHookEx(hook);
    hook = SetWindowsHookExA(2 /* WH_KEYBOARD */, keyboard, 0, GetCurrentThreadId());
    line("hook_thread", hook == 0);
    if (hook) UnhookWindowsHookEx(hook);
    static unsigned long long input[5];   /* INPUT: type, then KEYBDINPUT (vk, scan, flags, time, extra) */
    input[0] = 1;                         /* INPUT_KEYBOARD */
    input[1] = 'A';
    line("input_a", SendInput(1, input, 40) == 0);
    input[1] = 'B';
    line("input_b", SendInput(1, input, 40) == 0);
    HANDLE manager = CreateFileA("\\\\.\\MountPointManager", 0, 3, 0, 3, 0, 0);
    static unsigned char in[64], out[16];
    DWORD got = 0;
    SetLastError(0);
    /* No output buffer: after a refused write Wine 11 reads its unwritten reply's wait handle, which is the request's
     * output size, and waits on it (ERROR_INVALID_HANDLE, or a hang on a real handle); with none it returns the
     * refusal (STATUS_ACCESS_VIOLATION). */
    line("ioctl_mountmgr", manager != (HANDLE)(long long)-1 &&
                           !DeviceIoControl(manager, 0x006D0008 /* IOCTL_MOUNTMGR_QUERY_POINTS */, in, sizeof(in), out, 0,
                                            &got, 0) && GetLastError() == 998 /* ERROR_NOACCESS */);
    HANDLE manager2 = OpenSCManagerA(0, 0, 1 /* SC_MANAGER_CONNECT */);
    HANDLE service = manager2 ? OpenServiceA(manager2, "PlugPlay", 0x10 /* SERVICE_START */) : 0;
    /* Running already (1056): the call reached services.exe; anything else: refused on the way. */
    line("svc_start", service && !StartServiceA(service, 0, 0) && GetLastError() != 1056);
    if (service) CloseServiceHandle(service);
    if (manager2) CloseServiceHandle(manager2);
    TerminateProcess(child.process, 0);
    ExitProcess(0);
}

void start(void)
{
    if (has_word(GetCommandLineA(), " hold")) {
        Sleep(12000);   /* past a restarted kfilterd (attaching takes about 6 s) */
        VirtualAlloc(0, 4096, 0x3000, 0x40);   /* new executable memory: the module table is reread */
        Sleep(10000);
        ExitProcess(0);
    }
    if (has_word(GetCommandLineA(), " outside")) outside();
    if (has_word(GetCommandLineA(), " addr")) addr();
    if (has_word(GetCommandLineA(), " requests")) requests();
    if (has_word(GetCommandLineA(), " window")) window();
    if (has_word(GetCommandLineA(), " reach")) reach(!has_word(GetCommandLineA(), " unplaced"));
    if (has_word(GetCommandLineA(), " target")) {
        /* addr's peer: memory at a fixed place to be read, a thread to put a breakpoint on. */
        char* memory = VirtualAlloc((void*)KF_PEER_MEMORY, 0x4000, 0x3000, 0x04);
        for (int i = 0; memory && i < 0x4000; i++) memory[i] = (char)i;
        Sleep(30000);
        ExitProcess(memory ? 0 : 1);
    }
    if (has_word(GetCommandLineA(), " hwndparam")) {
        /* NtUserCallHwndParam's cost (linux_lsm_test.sh): GetWindowRect of its own window, which Wine answers through it
         * (as GetWindowLong, ClientToScreen), 200,000 times; ns a call. */
        static long rect[4];
        long long start = 0, end = 0, frequency = 1;
        HANDLE own = CreateWindowExA(0, "STATIC", "kfprobe", 0, 0, 0, 1, 1, 0, 0, 0, 0);
        QueryPerformanceFrequency(&frequency);
        QueryPerformanceCounter(&start);
        for (int i = 0; i < 200000; i++) GetWindowRect(own, rect);
        QueryPerformanceCounter(&end);
        say_number("hwndparam_ns", (unsigned long long)((end - start) * 1000000000 / (frequency > 0 ? frequency : 1)) / 200000);
        ExitProcess(0);
    }
    if (has_word(GetCommandLineA(), " inproc")) {
        /* Calls Wine answers in this process (win32u.so): the cursor, and the window list (with a
         * window of our own in it); the same from a 32-bit program. WMI (wbemprox's ExecQuery, in
         * wmic): a class a rule names and one it does not, and the 32-bit wmic. */
        static long point[2];
        line("win32k_cursor", !GetCursorPos(point));
        HANDLE own = CreateWindowExA(0, "STATIC", "kfprobe", 0, 0, 0, 1, 1, 0, 0, 0, 0);
        EnumWindows(count_window, 0);
        line("win32k_enum", windows == 0);
        /* Keyed win32u.so calls: VK_F1's state refused, VK_A's not (both pressed by SendInput, so an allowed call reads
         * them down); another program's window title refused, its own not. */
        static unsigned long long input[5];   /* INPUT: type, then KEYBDINPUT (vk, scan, flags, time, extra) */
        input[0] = 1;                         /* INPUT_KEYBOARD */
        for (int up = 0; up < 2; up++) {
            const unsigned long long flags = up ? 2ull << 32 : 0;   /* dwFlags KEYEVENTF_KEYUP, after wVk and wScan */
            input[1] = 0x70 | flags;
            SendInput(1, input, 40);
            input[1] = 'A' | flags;
            SendInput(1, input, 40);
            if (up) break;
            line("win32k_key_f1", GetAsyncKeyState(0x70) == 0);
            line("win32k_key_a", GetAsyncKeyState('A') == 0);
        }
        static unsigned short title[64];
        PROCESS_INFORMATION peer = {0};
        HANDLE other = peer_window(&peer);
        line("win32k_text_own", InternalGetWindowText(own, title, 64) == 0);
        say("win32k_text_other", !other ? "no-peer" : InternalGetWindowText(other, title, 64) == 0 ? "denied" : "ok");
        if (peer.process) TerminateProcess(peer.process, 0);
        /* ntdll.so: ProcessDebugPort refused, ProcessBasicInformation not. */
        static unsigned long long information[6];
        line("ntdll_debug_port", NtQueryInformationProcess(GetCurrentProcess(), 7, information, 8, 0) != 0);
        line("ntdll_basic", NtQueryInformationProcess(GetCurrentProcess(), 0, information, 48, 0) != 0);
        /* Wine's own call (critic 1.14): while BeingDebugged is set, closing a bad handle makes ntdll.so's NtClose ask
         * NtQueryInformationProcess(ProcessDebugPort) itself, returning into ntdll.so outside the dispatcher. Not decided:
         * linux_lsm_test.sh finds two ProcessDebugPort events, kernel32's start_process (CheckRemoteDebuggerPresent) and the
         * probe's own call above. */
        unsigned long long teb;
        __asm__ volatile("movq %%gs:0x30, %0" : "=r"(teb));
        unsigned char* being_debugged = *(unsigned char**)(teb + 0x60) + 2;   /* PEB.BeingDebugged */
        *being_debugged = 1;
        const BOOL closed = CloseHandle((HANDLE)0x7ff8ull);
        *being_debugged = 0;
        line("ntdll_wine_own", closed);
        run("win32k_i386", "C:\\windows\\syswow64\\rundll32.exe user32.dll,GetAsyncKeyState");
        run("wmi_bios", "C:\\windows\\system32\\wbem\\wmic.exe bios get serialnumber");
        run("wmi_os", "C:\\windows\\system32\\wbem\\wmic.exe os get caption");
        run("wmi_bios32", "C:\\windows\\syswow64\\wbem\\wmic.exe bios get serialnumber");
        wql();
        ExitProcess(0);
    }
    if (has_word(GetCommandLineA(), " peer")) {
        static char table[1 << 20];
        DWORD n = 0, failed = 0;
        Sleep(1500);   /* kfilterd reads this program's module table (module= rules) */
        if (NtQuerySystemInformation(5 /* SystemProcessInformation: list_processes */, table, sizeof(table), &n) != 0) failed |= 1;
        if (NtQuerySystemInformation(16 /* SystemHandleInformation: get_system_handles */, table, sizeof(table), &n) != 0) failed |= 2;
        HANDLE created = CreateThread(0, 0, idle, 0, 0, 0);
        if (!created) failed |= 4;
        if (!CreateMutexA(0, 0, "kf-probe")) failed |= 8;   /* a named object */
        Sleep(3000);   /* its creator reaches into it meanwhile */
        ExitProcess(0x100 | failed);
    }
    if (has_word(GetCommandLineA(), " register")) {
        int reply[2] = {-1, -1};
        static unsigned int forged[16] = {6 /* init_thread */};
        linux_syscall(293 /* pipe2 */, (long long)reply, 0, 0);
        forged[3] = (unsigned)linux_syscall(186 /* gettid */, 0, 0, 0);
        forged[4] = (unsigned)reply[0];
        linux_syscall(1 /* write */, 1, (long long)forged, 64);
        ExitProcess(0);
    }
    /* A thread of another Wine process (explorer.exe, services.exe, ...), outside the family. */
    THREADENTRY32 entry = {sizeof(entry)};
    DWORD tid = 0, owner = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(4 /* TH32CS_SNAPTHREAD */, 0);
    for (BOOL more = Thread32First(snapshot, &entry); more; more = Thread32Next(snapshot, &entry)) {
        if (entry.owner != GetCurrentProcessId() && entry.owner > 8) {
            tid = entry.tid;
            owner = entry.owner;
            break;
        }
    }
    CloseHandle(snapshot);
    if (tid == 0) {
        line("thread_setup", 1);
        ExitProcess(1);
    }
    HANDLE thread = OpenThread(0x8 | 0x2 /* GET_CONTEXT | SUSPEND_RESUME */, 0, tid);
    line("thread_open", thread == 0);
    if (thread) CloseHandle(thread);
    thread = OpenThread(0x800 /* QUERY_LIMITED_INFORMATION */, 0, tid);
    line("thread_open_query", thread == 0);
    if (thread) CloseHandle(thread);
    /* A thread of our own, named by its creator's new_thread reply, is inside the family. */
    DWORD own = 0;
    HANDLE created = CreateThread(0, 0, idle, 0, 0, &own);
    thread = created ? OpenThread(0x8 | 0x2 /* GET_CONTEXT | SUSPEND_RESUME */, 0, own) : 0;
    line("thread_open_own", thread == 0);
    if (thread) CloseHandle(thread);
    /* Our own thread handed to the outside process (a thread-handle rule). */
    HANDLE process = OpenProcess(0x40 /* DUP_HANDLE */, 0, owner), copy = 0;
    line("thread_dup_out", !process || !DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), process, &copy,
                                                        0x1FFFFF, 0, 0));
    if (process) CloseHandle(process);
    /* A process handle to it with the rights a remote thread or VirtualAllocEx needs (an open rule). */
    process = OpenProcess(0x2 | 0x8 /* CREATE_THREAD | VM_OPERATION */, 0, owner);
    line("process_open", process == 0);
    if (process) CloseHandle(process);
    /* A copy of an allowed process handle still reaches it: its threads need a thread-open rule. */
    process = OpenProcess(0x400 /* QUERY_INFORMATION */, 0, owner);
    HANDLE same = 0, next = 0;
    if (process && DuplicateHandle(GetCurrentProcess(), process, GetCurrentProcess(), &same, 0, 0, 2 /* SAME_ACCESS */)) {
        line("thread_next_dup", NtGetNextThread(same, 0, 0x8 | 0x2, 0, 0, &next) != 0);
        if (next) CloseHandle(next);
        CloseHandle(same);
    } else {
        line("thread_next_dup_setup", 1);
    }
    if (process) CloseHandle(process);
    /* A process kfilter cannot name (the next one, opened with no dangerous right), copied with
     * all rights: Wine grants them, so it is decided as an open of an outside process. */
    HANDLE any = 0, raised = 0;
    if (NtGetNextProcess(0, 0x1000 /* QUERY_LIMITED_INFORMATION */, 0, 0, &any) == 0) {
        line("process_next_dup", !DuplicateHandle(GetCurrentProcess(), any, GetCurrentProcess(), &raised, 0x1FFFFF, 0, 0));
        if (raised) CloseHandle(raised);
        CloseHandle(any);
    } else {
        line("process_next_dup_setup", 1);
    }
    /* Copies of an event (not a process): with its own rights, and with SYNCHRONIZE. */
    HANDLE event = CreateEventA(0, 1, 0, 0);
    copy = 0;
    line("event_dup", !event || !DuplicateHandle(GetCurrentProcess(), event, GetCurrentProcess(), &copy, 0, 0, 2));
    if (copy) CloseHandle(copy);
    copy = 0;
    line("event_dup_sync", !event || !DuplicateHandle(GetCurrentProcess(), event, GetCurrentProcess(), &copy,
                                                      0x100000 /* SYNCHRONIZE */, 0, 0));
    if (copy) CloseHandle(copy);
    copy = 0;   /* with explicit EVENT_MODIFY_STATE (0x2: create-thread were it a process), as Chromium does */
    line("event_dup_modify", !event || !DuplicateHandle(GetCurrentProcess(), event, GetCurrentProcess(), &copy,
                                                        0x100002, 0, 0));
    if (copy) CloseHandle(copy);
    if (event) CloseHandle(event);
    /* The process token copied with TOKEN_QUERY (0x8: vm-operation were it a process), as Chromium's sandbox
     * does (open_token, then dup_handle within the process). */
    HANDLE token = 0;
    copy = 0;
    line("token_dup", !OpenProcessToken(GetCurrentProcess(), 0x8, &token) ||
                      !DuplicateHandle(GetCurrentProcess(), token, GetCurrentProcess(), &copy, 0x8, 0, 0));
    if (copy) CloseHandle(copy);
    if (token) CloseHandle(token);
    /* Wine's NT namespace (create_named_pipe, open_file_object): an allowed pipe, its client
     * open, a denied pipe name, and the mount manager device. */
    const HANDLE invalid = (HANDLE)(long long)-1;
    HANDLE server = CreateNamedPipeA("\\\\.\\pipe\\kfprobe-ok", 3 /* DUPLEX */, 0, 1, 512, 512, 0, 0);
    line("nt_pipe_create", server == invalid);
    HANDLE client = CreateFileA("\\\\.\\pipe\\kfprobe-ok", 0xC0000000u /* GENERIC_READ|WRITE */, 0, 0,
                                3 /* OPEN_EXISTING */, 0, 0);
    line("nt_pipe_open", client == invalid);
    if (client != invalid) CloseHandle(client);
    if (server != invalid) CloseHandle(server);
    server = CreateNamedPipeA("\\\\.\\pipe\\kfprobe-denied", 3, 0, 1, 512, 512, 0, 0);
    line("nt_pipe_denied", server == invalid);
    if (server != invalid) CloseHandle(server);
    HANDLE device = CreateFileA("\\\\.\\MountPointManager", 0, 3 /* SHARE_READ|WRITE */, 0, 3, 0, 0);
    line("nt_device", device == invalid);
    if (device != invalid) CloseHandle(device);
    /* Named sections (create_mapping, open_mapping, relative to the BaseNamedObjects directory): an
     * allowed one and its open by name, and a denied name. */
    HANDLE section = CreateFileMappingA(invalid, 0, 4 /* PAGE_READWRITE */, 0, 4096, "Local\\kfprobe-section-ok");
    line("section_create", section == 0);
    HANDLE opened = OpenFileMappingA(4 /* FILE_MAP_READ */, 0, "Local\\kfprobe-section-ok");
    line("section_open", opened == 0);
    if (opened) CloseHandle(opened);
    if (section) CloseHandle(section);
    section = CreateFileMappingA(invalid, 0, 4, 0, 4096, "Local\\kfprobe-section-denied");
    line("section_denied", section == 0);
    if (section) CloseHandle(section);
    /* An unnamed section copied with explicit access, as Chromium's shared memory is (SECTION_QUERY |
     * MAP_WRITE | MAP_READ = 0x7, which as process rights would be terminate and create-thread): not a
     * process handle, so not decided as one; and the copy of the copy. */
    section = CreateFileMappingA(invalid, 0, 4, 0, 4096, 0);
    copy = 0;
    line("section_dup", !section || !DuplicateHandle(GetCurrentProcess(), section, GetCurrentProcess(), &copy, 7, 0, 0));
    HANDLE again = 0;
    line("section_dup_copy", !copy || !DuplicateHandle(GetCurrentProcess(), copy, GetCurrentProcess(), &again, 7, 0, 0));
    if (again) CloseHandle(again);
    if (copy) CloseHandle(copy);
    if (section) CloseHandle(section);
    /* The volume serial through wineserver's get_volume_info (FileFsVolumeInformation on \\.\C:). */
    HANDLE volume = CreateFileA("\\\\.\\C:", 0, 3, 0, 3, 0, 0);
    if (volume != invalid) {
        unsigned long long status[2] = {0, 0};
        static char info[512];
        line("volume_serial", NtQueryVolumeInformationFile(volume, status, info, sizeof(info), 1) != 0);
        CloseHandle(volume);
    } else {
        line("volume_serial_open", 1);
    }
    raw_request("vmsplice_request", 1);
    raw_request("splice_request", 2);
    raw_request("exec_request", 3);
    /* A forged first request (init_thread on a pipe of our own, its TEB naming the outside
     * thread) must not make that thread look like ours. */
    int fds[2] = {-1, -1};
    static unsigned long long teb[16];
    teb[8] = owner;   /* ClientId at 0x40: UniqueProcess, UniqueThread */
    teb[9] = tid;
    if (linux_syscall(293 /* pipe2 */, (long long)fds, 0, 0) == 0) {
        unsigned int forged[16] = {6 /* init_thread */, 0, 0, (unsigned)linux_syscall(186 /* gettid */, 0, 0, 0),
                                   (unsigned)fds[0], (unsigned)fds[0], (unsigned)(unsigned long long)teb,
                                   (unsigned)((unsigned long long)teb >> 32)};
        linux_syscall(1 /* write */, fds[1], (long long)forged, 64);
        linux_syscall(3 /* close */, fds[0], 0, 0);
        linux_syscall(3 /* close */, fds[1], 0, 0);
    }
    thread = OpenThread(0x8 | 0x2 /* GET_CONTEXT | SUSPEND_RESUME */, 0, tid);
    line("thread_open_forged", thread == 0);
    if (thread) CloseHandle(thread);

    /* A denied key spelled with a doubled backslash: wineserver skips it, so kfilter refuses the name. */
    HKEY k = key("Software\\KfProbe\\\\Double", KEY_READ);
    line("reg_double_backslash", k == 0);
    if (k) RegCloseKey(k);

    /* A value name longer than kfilter keeps (AppCompatFlags\\Layers names values by a program's path): asked
     * for on an allowed key, it is not there (2), not refused as a name failure (998, ERROR_NOACCESS). */
    k = key("Software\\KfProbe\\Long", KEY_READ);
    line("reg_long_value", !k || RegQueryValueExA(k, "C:\\Program Files (x86)\\Nexon\\Nexon Launcher\\bin\\"
                                 "nexon_client\\nexon_client.exe-a-value-name-longer-than-one-hundred-and-twenty-"
                                 "eight-characters", 0, 0, 0, 0) != 2);
    if (k) RegCloseKey(k);

    /* Registry requests on keys the open of which is allowed once (uses=1). */
    k = key("Software\\KfProbe\\Flush", KEY_READ);
    if (k) {
        line("reg_flush", RegFlushKey(k) != 0);
        RegCloseKey(k);
    } else {
        line("reg_flush_open", 1);
    }
    k = key("Software\\KfProbe\\Notify", KEY_NOTIFY);
    if (k) {
        HANDLE event = CreateEventA(0, 1, 0, 0);
        line("reg_notify", RegNotifyChangeKeyValue(k, 0, 1 /* NAME */, event, 1) != 0);
        RegCloseKey(k);
    } else {
        line("reg_notify_open", 1);
    }
    k = key("Software\\KfProbe\\GetSecurity", KEY_READ);
    if (k) {
        static char sd[4096];
        DWORD size = sizeof(sd);
        line("reg_get_security", RegGetKeySecurity(k, DACL_SECURITY_INFORMATION, sd, &size) != 0);
        RegCloseKey(k);
    } else {
        line("reg_get_security_open", 1);
    }
    k = key("Software\\KfProbe\\SetSecurity", READ_CONTROL | WRITE_DAC);
    if (k) {
        static unsigned long long sd[8];   /* SECURITY_DESCRIPTOR, a NULL DACL */
        InitializeSecurityDescriptor(sd, 1);
        SetSecurityDescriptorDacl(sd, 1, 0, 0);
        line("reg_set_security", RegSetKeySecurity(k, DACL_SECURITY_INFORMATION, sd) != 0);
        RegCloseKey(k);
    } else {
        line("reg_set_security_open", 1);
    }
    /* Executable memory of its own (private), and a Linux open it makes itself, past Wine. */
    void* jit = VirtualAlloc(0, 4096, 0x3000 /* COMMIT | RESERVE */, 0x04 /* READWRITE */);
    DWORD was = 0;
    line("anon_exec", !jit || !VirtualProtect(jit, 4096, 0x40 /* EXECUTE_READWRITE */, &was));
    long long fd = linux_syscall(2 /* open */, (long long)"/etc/hostname", 0, 0);
    line("direct_open", fd < 0);
    if (fd >= 0) linux_syscall(3 /* close */, fd, 0, 0);
    /* A file next to this program that a hide rule denies seems not to exist (Wine stats it). */
    static char hidden[280];
    DWORD n = GetModuleFileNameA(0, hidden, 260);
    while (n > 0 && hidden[n - 1] != '\\') n--;
    for (int i = 0; i < 7; i++) hidden[n + i] = "hidden"[i];
    DWORD error = GetFileAttributesA(hidden) != 0xFFFFFFFF ? 0 : GetLastError();
    say("attr_hidden", error == 0 ? "ok" : error == 2 || error == 3 ? "hidden" : "denied");

    /* Another protected program (kfpeer.exe, a copy of this one next to it): a thread handle with
     * the rights a debug-register check needs and one without, its memory, a remote thread; then
     * its own system requests and thread creation (its exit code). */
    static char peer[280];
    static STARTUPINFOA startup = {sizeof(startup)};
    PROCESS_INFORMATION child;
    n = GetModuleFileNameA(0, peer, 260);
    while (n > 0 && peer[n - 1] != '\\') n--;
    for (int i = 0; i < 11; i++) peer[n + i] = "kfpeer.exe"[i];
    /* argv[0] (its image to kfilter) is the command line's first word: the full path, as launchers give it. */
    static char arguments[300];
    for (int i = 0; i < 16; i++) arguments[n + i] = "kfpeer.exe peer"[i];
    for (DWORD i = 0; i < n; i++) arguments[i] = peer[i];
    if (!CreateProcessA(peer, arguments, 0, 0, 0, 0, 0, 0, &startup, &child)) {
        line("peer_setup", 1);
        ExitProcess(0);
    }
    Sleep(1500);   /* started: its ids are known from its first request */
    thread = OpenThread(0x848 /* GET_CONTEXT | QUERY_INFORMATION | QUERY_LIMITED_INFORMATION */, 0, child.tid);
    line("peer_thread_context", thread == 0);
    if (thread) CloseHandle(thread);
    thread = OpenThread(0x800 /* QUERY_LIMITED_INFORMATION */, 0, child.tid);
    line("peer_thread_query", thread == 0);
    if (thread) CloseHandle(thread);
    /* Through the handle CreateProcess returned (never decided): each request is. */
    static char code[2];
    unsigned long long got = 0;
    line("peer_read_memory", !ReadProcessMemory(child.process, (const void*)start, code, 2, &got));
    HANDLE remote = CreateRemoteThread(child.process, 0, 0, idle, 0, 0, 0);
    line("peer_remote_thread", remote == 0);
    if (remote) CloseHandle(remote);
    DWORD status = 0;
    WaitForSingleObject(child.process, 20000);
    if (!GetExitCodeProcess(child.process, &status) || (status & ~15u) != 0x100) {
        line("peer_exit", 1);
    } else {
        line("peer_list_processes", status & 1);
        line("peer_system_handles", status & 2);
        line("peer_thread_create", status & 4);
        line("peer_named_mutex", status & 8);
    }
    ExitProcess(0);
}
