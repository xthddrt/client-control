/* The Windows side of tests/linux_watch_test.sh's Wine session: after 1.5 s (the agent watches a new process's threads
 * within its first ticks), msmon_watched written 1000 times; then SetThreadContext of its own thread with debug
 * registers (Dr0 = &msmon_watched, Dr7 = 0: nothing enabled), which wineserver carries out with ptrace; then, on a new
 * thread, watch_wine_dll.dll loaded, freed, its old base taken with VirtualAlloc and the DLL loaded again (elsewhere),
 * the old address of its msmon_dll_watched written 50 times and the new one 100 times. Prints "set_context=ok" or
 * "set_context=failed error=<GetLastError>", then "dll=moved old=0x... new=0x..." or "dll=<what failed>". No CRT or
 * Windows headers: built as ws_wine_probe.c is (clang -target x86_64-w64-windows-gnu -ffreestanding -c, ld -m i386pep
 * with Wine's kernel32). */
typedef void* HANDLE;
typedef unsigned long DWORD;
typedef int BOOL;
typedef unsigned long long SIZE_T;
#define API __declspec(dllimport) __stdcall

API HANDLE GetStdHandle(DWORD);
API BOOL WriteFile(HANDLE, const void*, DWORD, DWORD*, void*);
API void Sleep(DWORD);
API void ExitProcess(unsigned);
API HANDLE GetCurrentThread(void);
API BOOL SetThreadContext(HANDLE, const void*);
API DWORD GetLastError(void);
API HANDLE LoadLibraryA(const char*);
API void* GetProcAddress(HANDLE, const char*);
API BOOL FreeLibrary(HANDLE);
API void* VirtualAlloc(void*, SIZE_T, DWORD, DWORD);
API HANDLE CreateThread(void*, SIZE_T, DWORD(__stdcall*)(void*), void*, DWORD, DWORD*);
API DWORD WaitForSingleObject(HANDLE, DWORD);

/* The watched variable: the test reads its RVA from the image's symbol table (nm). */
volatile unsigned long long msmon_watched __attribute__((aligned(8)));

static void say(const char* text)
{
    DWORD length = 0, written;
    while (text[length]) length++;
    WriteFile(GetStdHandle((DWORD)-11 /* STD_OUTPUT_HANDLE */), text, length, &written, 0);
}

/* Appends Add to Text. */
static void append(char* text, const char* add)
{
    while (*text) text++;
    while ((*text++ = *add++)) {
    }
}

/* Appends Value in hex ("0x...") to Text. */
static void hex(char* text, unsigned long long value)
{
    static char digits[19];
    int count = 1;
    for (unsigned long long rest = value; rest >= 16; rest /= 16) count++;
    digits[0] = '0';
    digits[1] = 'x';
    for (int i = count - 1; i >= 0; i--, value /= 16) digits[2 + i] = "0123456789abcdef"[value % 16];
    digits[2 + count] = 0;
    append(text, digits);
}

static DWORD __stdcall dll_part(void* unused)
{
    (void)unused;
    HANDLE first = LoadLibraryA("watch_wine_dll.dll");
    volatile unsigned long long* old = first ? GetProcAddress(first, "msmon_dll_watched") : 0;
    if (!old) {
        say("dll=not_loaded\n");
        return 1;
    }
    Sleep(1500);   /* the agent resolves the DLL's watch from its image list and opens it on this thread */
    FreeLibrary(first);
    /* Its old base taken, the DLL is loaded elsewhere (relocated), and the watch follows it. */
    void* block = VirtualAlloc(first, (SIZE_T)((char*)old - (char*)first) + 8, 0x3000 /* MEM_RESERVE | MEM_COMMIT */,
                               0x04 /* PAGE_READWRITE */);
    HANDLE second = LoadLibraryA("watch_wine_dll.dll");
    volatile unsigned long long* moved = second ? GetProcAddress(second, "msmon_dll_watched") : 0;
    if (!block || !moved || moved == old) {
        say(!block ? "dll=old_base_not_taken\n" : "dll=not_moved\n");
        return 1;
    }
    Sleep(1500);
    for (unsigned i = 0; i < 50; i++) *old = i;   /* plain memory now: its breakpoint was closed */
    for (unsigned i = 0; i < 100; i++) *moved = i;
    static char text[64] = "dll=moved old=";
    hex(text, (unsigned long long)old);
    append(text, " new=");
    hex(text, (unsigned long long)moved);
    append(text, "\n");
    say(text);
    return 0;
}

void start(void)
{
    Sleep(1500);
    for (unsigned i = 0; i < 1000; i++) msmon_watched = i;
    /* CONTEXT (x64, 1232 bytes, 16-aligned): ContextFlags at 0x30, Dr0 at 0x48, Dr7 at 0x70 (0: no breakpoint enabled). */
    static unsigned char context[1232] __attribute__((aligned(16)));
    *(DWORD*)(context + 0x30) = 0x00100010;   /* CONTEXT_AMD64 | CONTEXT_DEBUG_REGISTERS */
    *(unsigned long long*)(context + 0x48) = (unsigned long long)&msmon_watched;
    if (SetThreadContext(GetCurrentThread(), context)) {
        say("set_context=ok\n");
    } else {
        static char text[48] = "set_context=failed error=";
        DWORD error = GetLastError(), at = 25, digits = 1;
        for (DWORD rest = error; rest >= 10; rest /= 10) digits++;
        for (DWORD i = digits; i > 0; i--, error /= 10) text[at + i - 1] = (char)('0' + error % 10);
        text[at + digits] = '\n';
        say(text);
    }
    /* On a new thread: the main thread's debug registers are wineserver's now (the DLL's watch is side=watch there). */
    HANDLE thread = CreateThread(0, 0, dll_part, 0, 0, 0);
    if (thread) WaitForSingleObject(thread, 0xFFFFFFFF);
    else say("dll=no_thread\n");
    ExitProcess(0);
}
