#pragma once

/*
 * The handful of Win32 types and calls the shared agent sources use, mapped onto
 * Linux (implemented in platform.cpp).  Only CP_UTF8 conversions are supported, and
 * wchar_t strings are UTF-32 here.
 */

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <string>
#include <unistd.h>
#include <vector>

typedef uint8_t BYTE;
typedef uint16_t WORD;
typedef uint16_t USHORT;
typedef uint32_t DWORD;
typedef uint32_t ULONG;
typedef uint32_t UINT;
typedef uint64_t ULONGLONG;
typedef int BOOL;
typedef void* HANDLE;
typedef void* LPVOID;
typedef unsigned char* PUCHAR;
#define VOID void
#define WINAPI
#define TRUE 1
#define FALSE 0
#define MAX_PATH 260
#define MAXDWORD 0xffffffffu
#define CP_UTF8 65001u
#define INVALID_HANDLE_VALUE (reinterpret_cast<HANDLE>(static_cast<intptr_t>(-1)))

#define ERROR_SUCCESS 0
#define ERROR_INVALID_DATA EINVAL
#define ERROR_GEN_FAILURE EIO

#define REG_SZ 1u
#define REG_EXPAND_SZ 2u
#define REG_DWORD 4u
#define REG_LINK 6u
#define REG_MULTI_SZ 7u
#define REG_QWORD 11u

#define GENERIC_READ 0x80000000u
#define FILE_SHARE_READ 1u
#define FILE_SHARE_WRITE 2u
#define FILE_SHARE_DELETE 4u
#define OPEN_EXISTING 3u
#define FILE_ATTRIBUTE_NORMAL 0x80u
#define TH32CS_SNAPPROCESS 2u
#define THREAD_PRIORITY_HIGHEST 2
#define CTRL_C_EVENT 0u
#define CTRL_BREAK_EVENT 1u
#define CTRL_CLOSE_EVENT 2u
#define BCRYPT_USE_SYSTEM_PREFERRED_RNG 2u

struct GUID {
    unsigned long Data1;
    unsigned short Data2;
    unsigned short Data3;
    unsigned char Data4[8];
};

struct FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
};

struct SYSTEMTIME {
    WORD wYear, wMonth, wDayOfWeek, wDay, wHour, wMinute, wSecond, wMilliseconds;
};

union LARGE_INTEGER {
    int64_t QuadPart;
};

struct PROCESSENTRY32W {
    DWORD dwSize;
    DWORD th32ProcessID;
    DWORD th32ParentProcessID;
};

typedef BOOL (*PHANDLER_ROUTINE)(DWORD);

/* 100 ns intervals between 1601-01-01 and 1970-01-01. */
#define MSMON_UNIX_EPOCH_AS_FILETIME 116444736000000000ull

void GetSystemTimeAsFileTime(FILETIME* value);
BOOL FileTimeToSystemTime(const FILETIME* value, SYSTEMTIME* time);
void GetLocalTime(SYSTEMTIME* time);
uint64_t GetTickCount64();
int MultiByteToWideChar(UINT codePage, DWORD flags, const char* input, int inputLength,
                        wchar_t* output, int outputLength);
int WideCharToMultiByte(UINT codePage, DWORD flags, const wchar_t* input, int inputLength,
                        char* output, int outputLength, const char* defaultChar, BOOL* usedDefault);
inline DWORD GetLastError() { return static_cast<DWORD>(errno); }
inline DWORD GetCurrentProcessId() { return static_cast<DWORD>(getpid()); }
DWORD GetEnvironmentVariableW(const wchar_t* name, wchar_t* buffer, DWORD size);
BOOL GetComputerNameW(wchar_t* buffer, DWORD* size);
DWORD GetModuleFileNameW(HANDLE module, wchar_t* buffer, DWORD size);
BOOL SetConsoleCtrlHandler(PHANDLER_ROUTINE handler, BOOL add);
inline HANDLE GetCurrentThread() { return nullptr; }
inline BOOL SetThreadPriority(HANDLE, int) { return TRUE; }
long BCryptGenRandom(void* algorithm, BYTE* buffer, ULONG size, ULONG flags);

HANDLE CreateFileW(const wchar_t* path, DWORD access, DWORD share, void* security,
                   DWORD disposition, DWORD attributes, HANDLE templateFile);
BOOL ReadFile(HANDLE file, void* buffer, DWORD size, DWORD* read, void* overlapped);
BOOL GetFileSizeEx(HANDLE file, LARGE_INTEGER* size);
constexpr DWORD FILE_BEGIN = 0, FILE_CURRENT = 1, FILE_END = 2;
BOOL SetFilePointerEx(HANDLE file, LARGE_INTEGER distance, LARGE_INTEGER* position, DWORD method);
BOOL CloseHandle(HANDLE handle);
HANDLE CreateToolhelp32Snapshot(DWORD flags, DWORD pid);
BOOL Process32FirstW(HANDLE snapshot, PROCESSENTRY32W* entry);
BOOL Process32NextW(HANDLE snapshot, PROCESSENTRY32W* entry);

inline int _wcsnicmp(const wchar_t* left, const wchar_t* right, size_t count) { return wcsncasecmp(left, right, count); }
inline int _wcsicmp(const wchar_t* left, const wchar_t* right) { return wcscasecmp(left, right); }

template <size_t N, typename... Args>
int swprintf_s(wchar_t (&buffer)[N], const wchar_t* format, Args... args)
{
    return swprintf(buffer, N, format, args...);
}

inline int wcscpy_s(wchar_t* buffer, size_t size, const wchar_t* source)
{
    size_t length = wcslen(source);
    if (length >= size) {
        if (size != 0) buffer[0] = L'\0';
        return ERANGE;
    }
    wmemcpy(buffer, source, length + 1);
    return 0;
}

template <size_t N>
int wcscpy_s(wchar_t (&buffer)[N], const wchar_t* source)
{
    return wcscpy_s(buffer, N, source);
}

/* Linux helpers shared by the agent and the sensors (platform.cpp). */
std::wstring LinuxWide(const std::string& value);
std::string LinuxNarrow(const std::wstring& value);
/* Start time of a live process as a FILETIME value, from /proc/<pid>/stat; 0 if gone. */
uint64_t LinuxProcessStart(DWORD pid, DWORD* parent = nullptr);
bool LinuxProcessIdentity(DWORD pid, std::wstring& path, uint64_t& startTime);
/* Boot time as FILETIME; LinuxProcessStart is this plus the /proc start ticks. */
uint64_t LinuxBootFileTime();
/* Under Wine /proc/<pid>/exe is the loader, so the client is found by what it maps or
 * by its Wine prefix: true when the process has an executable file mapping under a root,
 * or its WINEPREFIX (default $HOME/.wine) is Prefix. */
bool LinuxInScope(DWORD pid, const std::vector<std::wstring>& roots, const std::wstring& prefix);
/* True when argv[0] is Wine's winedevice.exe. */
bool LinuxWinedevice(const std::wstring& argv0);
/* Path with symlinks resolved as far as it exists (a Wine prefix's dosdevices/c: -> drive_c), else Path. */
std::wstring LinuxResolvedPath(const std::wstring& path);
