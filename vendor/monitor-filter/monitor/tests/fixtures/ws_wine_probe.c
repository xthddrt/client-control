/* The Windows side of tests/linux_wine_test.sh's wineserver rows: VirtualAlloc of 64 KiB read-write and VirtualProtect
 * of its first page to PAGE_NOACCESS (anonymous memory the kernel aggregates), its address printed as "alloc=0x<hex>";
 * VirtualQuery of three addresses of it in a row (each page keeps its NtQueryVirtualMemory record), the first page again
 * at another offset and a walk of 256 reserved pages (past 64 records a second: a kernel aggregate); a copy of itself
 * loaded as a library and freed (map_image_view, then unmap_view: an image unload); then a copy of itself run as
 * "peer", which makes a window, and a message posted to that window (a send_message to another process); the peer
 * exits 0 when it got it. The window probes (--window-probes): a window of its own and 100000 GetWindowLongA of it (no
 * record: its own window), their time per call printed as "hwndparam_ns=<n>" ("bench" does only that, the baseline
 * without the probes), "self=0x<hwnd>" and "peer=0x<hwnd>", and GetWindowLongA of the peer's window by its whole
 * handle, its low word and its low word with 0xffff as high word (three records naming the peer). Exit 0 when every
 * step worked. No CRT or Windows headers: built by the test with clang
 * -target x86_64-w64-windows-gnu -ffreestanding -c, then GNU ld -m i386pep against Wine's own kernel32 and user32
 * import libraries. */
typedef void* HANDLE;
typedef unsigned long DWORD;
typedef int BOOL;
#define API __declspec(dllimport) __stdcall

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

typedef struct {
    HANDLE window;
    unsigned message;
    unsigned long long wparam;
    long long lparam;
    DWORD time;
    long x, y;
    DWORD lprivate;
} MSG;

API void* VirtualAlloc(void*, unsigned long long, DWORD, DWORD);
API BOOL VirtualProtect(void*, unsigned long long, DWORD, DWORD*);
API HANDLE GetStdHandle(DWORD);
API BOOL WriteFile(HANDLE, const void*, DWORD, DWORD*, void*);
API const char* GetCommandLineA(void);
API DWORD GetModuleFileNameA(HANDLE, char*, DWORD);
API BOOL CreateProcessA(const char*, char*, void*, void*, BOOL, DWORD, void*, const char*, STARTUPINFOA*,
                        PROCESS_INFORMATION*);
API DWORD WaitForSingleObject(HANDLE, DWORD);
API BOOL GetExitCodeProcess(HANDLE, DWORD*);
API void Sleep(DWORD);
API unsigned long long VirtualQuery(const void*, void*, unsigned long long);
API BOOL CopyFileA(const char*, const char*, BOOL);
API HANDLE LoadLibraryExA(const char*, HANDLE, DWORD);
API BOOL FreeLibrary(HANDLE);
API BOOL DeleteFileA(const char*);
API void ExitProcess(unsigned);
API HANDLE CreateWindowExA(DWORD, const char*, const char*, DWORD, int, int, int, int, HANDLE, HANDLE, HANDLE, void*);
API HANDLE FindWindowA(const char*, const char*);
API BOOL PostMessageA(HANDLE, unsigned, unsigned long long, long long);
API BOOL PeekMessageA(MSG*, HANDLE, unsigned, unsigned, unsigned);
API long GetWindowLongA(HANDLE, int);
API BOOL QueryPerformanceCounter(long long*);
API BOOL QueryPerformanceFrequency(long long*);

#define PROBE_MESSAGE 0x401   /* WM_USER + 1 */

static void say(const char* text)
{
    DWORD length = 0, written;
    while (text[length]) length++;
    WriteFile(GetStdHandle((DWORD)-11 /* STD_OUTPUT_HANDLE */), text, length, &written, 0);
}

static void hex(const char* name, unsigned long long value)
{
    static char text[40];
    int at = 0;
    while (*name) text[at++] = *name++;
    text[at++] = '=', text[at++] = '0', text[at++] = 'x';
    for (int digit = 0; digit < 16; digit++) text[at++] = "0123456789abcdef"[(value >> (60 - 4 * digit)) & 15];
    text[at++] = '\n', text[at] = 0;
    say(text);
}

/* A window of its own and 100000 GetWindowLongA of it (NtUserCallHwndParam): "hwndparam_ns=" their time per call. */
static HANDLE bench(void)
{
    HANDLE self = CreateWindowExA(0, "STATIC", "msmon-self", 0, 0, 0, 1, 1, 0, 0, 0, 0);
    long long start = 0, end = 0, frequency = 1;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);
    for (int call = 0; call < 100000; call++) GetWindowLongA(self, -16 /* GWL_STYLE */);
    QueryPerformanceCounter(&end);
    static char text[40] = "hwndparam_ns=";
    unsigned long long ns = (unsigned long long)((end - start) * 10000 / frequency), at = 13, digits = 1;   /* per call */
    for (unsigned long long left = ns; left >= 10; left /= 10) digits++;
    for (unsigned long long index = 0; index < digits; index++, ns /= 10) text[at + digits - 1 - index] = (char)('0' + ns % 10);
    text[at + digits] = '\n';
    text[at + digits + 1] = 0;
    say(text);
    return self;
}

static void peer(void)
{
    static MSG message;
    if (!CreateWindowExA(0, "STATIC", "msmon-peer", 0, 0, 0, 1, 1, 0, 0, 0, 0)) ExitProcess(2);
    for (int tries = 0; tries < 400; tries++) {
        while (PeekMessageA(&message, 0, 0, 0, 1 /* PM_REMOVE */))
            if (message.message == PROBE_MESSAGE) ExitProcess(0);
        Sleep(50);
    }
    ExitProcess(3);
}

void start(void)
{
    const char* line = GetCommandLineA();
    for (const char* at = line; *at; at++) {
        if (at[0] == ' ' && at[1] == 'p' && at[2] == 'e' && at[3] == 'e' && at[4] == 'r') peer();
        if (at[0] == ' ' && at[1] == 'b' && at[2] == 'e' && at[3] == 'n' && at[4] == 'c' && at[5] == 'h') ExitProcess(bench() ? 0 : 1);
    }
    unsigned failed = 0;
    char* area = VirtualAlloc(0, 0x10000, 0x3000 /* MEM_COMMIT | MEM_RESERVE */, 0x04 /* PAGE_READWRITE */);
    DWORD was = 0;
    if (!area || !VirtualProtect(area, 0x1000, 0x01 /* PAGE_NOACCESS */, &was)) failed |= 1;
    static char text[32] = "alloc=0x";
    unsigned long long address = (unsigned long long)area;
    for (int digit = 0; digit < 16; digit++) text[8 + digit] = "0123456789abcdef"[(address >> (60 - 4 * digit)) & 15];
    text[24] = '\n';
    say(text);
    static unsigned char information[48];   /* MEMORY_BASIC_INFORMATION */
    for (int page = 0; page < 3; page++) {
        if (area && !VirtualQuery(area + page * 0x1000, information, sizeof(information))) failed |= 16;
    }
    /* The first page again at another offset (counted with its page's record, none of its own), then a walk of 256
     * reserved pages, its address printed as "walk=0x<hex>": past 64 records a second the queries are a kernel
     * aggregate holding their pages' range. */
    if (area && !VirtualQuery(area + 0x10, information, sizeof(information))) failed |= 16;
    char* walk = VirtualAlloc(0, 0x100000, 0x2000 /* MEM_RESERVE */, 0x01 /* PAGE_NOACCESS */);
    for (int page = 0; walk && page < 256; page++) {
        if (!VirtualQuery(walk + page * 0x1000, information, sizeof(information))) failed |= 16;
    }
    static char walked[32] = "walk=0x";
    address = (unsigned long long)walk;
    for (int digit = 0; digit < 16; digit++) walked[7 + digit] = "0123456789abcdef"[(address >> (60 - 4 * digit)) & 15];
    walked[23] = '\n';
    say(walked);

    static char self[300], command[340];
    static STARTUPINFOA startup = {sizeof(startup)};
    PROCESS_INFORMATION child;
    DWORD length = GetModuleFileNameA(0, self, 260), at = 0, code = 1;
    command[at++] = '"';
    for (DWORD i = 0; i < length; i++) command[at++] = self[i];
    for (const char* tail = "\" peer"; *tail; tail++) command[at++] = *tail;
    command[at] = 0;
    if (!length || !CreateProcessA(self, command, 0, 0, 0, 0, 0, 0, &startup, &child)) ExitProcess(failed | 2);
    /* A copy loaded as a library (not run: DONT_RESOLVE_DLL_REFERENCES) and freed. */
    HANDLE library = CopyFileA(self, "C:\\msmon-unload.dll", 0) ? LoadLibraryExA("C:\\msmon-unload.dll", 0, 1) : 0;
    say(library && FreeLibrary(library) ? "unload=ok\n" : "unload=failed\n");
    DeleteFileA("C:\\msmon-unload.dll");
    HANDLE window = 0;
    for (int tries = 0; tries < 200 && !window; tries++) {
        window = FindWindowA(0, "msmon-peer");
        if (!window) Sleep(50);
    }
    if (!window || !PostMessageA(window, PROBE_MESSAGE, 0x31, 0x32)) failed |= 4;
    HANDLE own = bench();
    if (!own) failed |= 32;
    hex("self", (unsigned long long)own);
    hex("peer", (unsigned long long)window);
    const unsigned long long low = (unsigned long long)window & 0xffff;
    GetWindowLongA(window, -16);
    GetWindowLongA((HANDLE)low, -16);
    GetWindowLongA((HANDLE)(0xffff0000ull | low), -16);
    WaitForSingleObject(child.process, 30000);
    if (!GetExitCodeProcess(child.process, &code) || code != 0) failed |= 8;
    say(failed ? "probe=failed\n" : "probe=ok\n");
    ExitProcess(failed);
}
