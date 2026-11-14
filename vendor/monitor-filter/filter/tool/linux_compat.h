#pragma once

/*
 * The Win32 surface kfilterctl.cpp uses, for the Linux build. Types keep their Windows
 * widths (ULONG/DWORD are 32 bits). The device is kfilterd's Unix socket
 * (linux_client.cpp); everything else is a thin libc mapping. Windows-only features
 * (AppContainer, ACLs, QueryDosDevice) are #ifdef'd out in kfilterctl.cpp instead.
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <cwchar>
#include <cwctype>
#include <string>

/* Real Windows control codes: the self-test checks device rules against them, and the
 * socket carries the function number ((code >> 2) & 0xFFF). */
#define CTL_CODE(type, function, method, access) \
    ((unsigned long)(((type) << 16) | ((access) << 14) | ((function) << 2) | (method)))
#define FILE_DEVICE_UNKNOWN 0x00000022
#define METHOD_BUFFERED 0
#define FILE_ANY_ACCESS 0
#define FILE_READ_ACCESS 1
#define FILE_WRITE_ACCESS 2

#include "../driver/kfilter.h"

#define VOID void
typedef KF_ULONG ULONG;
typedef uint32_t DWORD;
typedef int BOOL;
typedef unsigned long long ULONGLONG;
typedef uint8_t UCHAR;
typedef uint8_t BYTE;
typedef uint16_t WORD;
typedef intptr_t HANDLE;
typedef struct in_addr IN_ADDR;
typedef struct in6_addr IN6_ADDR;
#define TRUE 1
#define FALSE 0
#define MAX_PATH 4096
#define INVALID_HANDLE_VALUE ((HANDLE)-1)

/* kfilterd replies with errno; these are the outcomes kfilterctl distinguishes. */
#define ERROR_NOT_FOUND ENOENT
#define ERROR_INVALID_PARAMETER EINVAL
#define ERROR_INVALID_HANDLE ESRCH
inline DWORD GetLastError() { return (DWORD)errno; }

/* Access masks named in handle rules (winnt.h values). */
#define DELETE 0x00010000u
#define READ_CONTROL 0x00020000u
#define WRITE_DAC 0x00040000u
#define WRITE_OWNER 0x00080000u
#define SYNCHRONIZE 0x00100000u
#define GENERIC_READ 0x80000000u
#define GENERIC_WRITE 0x40000000u
#define GENERIC_EXECUTE 0x20000000u
#define GENERIC_ALL 0x10000000u
#define PROCESS_TERMINATE 0x0001u
#define PROCESS_CREATE_THREAD 0x0002u
#define PROCESS_SET_SESSIONID 0x0004u
#define PROCESS_VM_OPERATION 0x0008u
#define PROCESS_VM_READ 0x0010u
#define PROCESS_VM_WRITE 0x0020u
#define PROCESS_DUP_HANDLE 0x0040u
#define PROCESS_CREATE_PROCESS 0x0080u
#define PROCESS_SET_QUOTA 0x0100u
#define PROCESS_SET_INFORMATION 0x0200u
#define PROCESS_QUERY_INFORMATION 0x0400u
#define PROCESS_SUSPEND_RESUME 0x0800u
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000u
#define PROCESS_SET_LIMITED_INFORMATION 0x2000u
#define THREAD_TERMINATE 0x0001u
#define THREAD_SUSPEND_RESUME 0x0002u
#define THREAD_GET_CONTEXT 0x0008u
#define THREAD_SET_CONTEXT 0x0010u
#define THREAD_SET_INFORMATION 0x0020u
#define THREAD_QUERY_INFORMATION 0x0040u
#define THREAD_SET_THREAD_TOKEN 0x0080u
#define THREAD_IMPERSONATE 0x0100u
#define THREAD_DIRECT_IMPERSONATION 0x0200u
#define THREAD_SET_LIMITED_INFORMATION 0x0400u
#define THREAD_QUERY_LIMITED_INFORMATION 0x0800u

#define MAXIMUM_ALLOWED 0x02000000u
#define FILE_READ_DATA 0x0001u
#define FILE_WRITE_DATA 0x0002u
#define FILE_APPEND_DATA 0x0004u
#define FILE_READ_EA 0x0008u
#define FILE_WRITE_EA 0x0010u
#define FILE_EXECUTE 0x0020u
#define FILE_READ_ATTRIBUTES 0x0080u
#define FILE_WRITE_ATTRIBUTES 0x0100u
#define KEY_QUERY_VALUE 0x0001u
#define KEY_SET_VALUE 0x0002u
#define KEY_CREATE_SUB_KEY 0x0004u
#define KEY_ENUMERATE_SUB_KEYS 0x0008u
#define KEY_NOTIFY 0x0010u
#define KEY_CREATE_LINK 0x0020u
#define KEY_READ 0x00020019u
#define KEY_WRITE 0x00020006u
#define PAGE_READONLY 0x02u
#define PAGE_READWRITE 0x04u
#define PAGE_WRITECOPY 0x08u
#define PAGE_EXECUTE 0x10u
#define PAGE_EXECUTE_READ 0x20u
#define PAGE_EXECUTE_READWRITE 0x40u
#define PAGE_EXECUTE_WRITECOPY 0x80u
/* Two Windows control codes the self-test checks the device snippet against. */
#define IOCTL_SCSI_GET_INQUIRY_DATA CTL_CODE(0x00000004, 0x0403, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NDIS_QUERY_GLOBAL_STATS CTL_CODE(0x00000017, 0, 2, FILE_ANY_ACCESS)
#define RTL_NUMBER_OF(array) (sizeof(array) / sizeof((array)[0]))
/* Track failures that must not be mistaken for "not protected". */
#define ERROR_GEN_FAILURE EIO
#define ERROR_ACCESS_DENIED EACCES
#define ERROR_NOT_ENOUGH_MEMORY ENOMEM
#define ERROR_NO_SYSTEM_RESOURCES ENOSPC
/* No DOS device namespace on Linux. */
inline DWORD QueryDosDeviceW(const wchar_t*, wchar_t*, DWORD) { errno = ENOENT; return 0; }

/* String functions. */
#define _TRUNCATE ((size_t)-1)
#define _wcsnicmp wcsncasecmp
#define _wcsicmp wcscasecmp
#define _wtoi(text) ((int)wcstol((text), nullptr, 10))
#define _wcstoui64 wcstoull
#define _strtoui64 strtoull

inline int wcscpy_s(wchar_t* destination, size_t size, const wchar_t* source)
{
    if (destination == nullptr || size == 0) return EINVAL;
    size_t length = wcslen(source);
    if (length >= size) { destination[0] = L'\0'; return ERANGE; }
    wmemcpy(destination, source, length + 1);
    return 0;
}
template <size_t N> int wcscpy_s(wchar_t (&destination)[N], const wchar_t* source)
{
    return wcscpy_s(destination, N, source);
}
inline int wcsncpy_s(wchar_t* destination, size_t size, const wchar_t* source, size_t count)
{
    if (destination == nullptr || size == 0) return EINVAL;
    size_t length = wcslen(source);
    if (count != _TRUNCATE && count < length) length = count;
    if (length >= size) length = size - 1;   // _TRUNCATE semantics
    wmemcpy(destination, source, length);
    destination[length] = L'\0';
    return 0;
}
inline int swprintf_s(wchar_t* buffer, size_t size, const wchar_t* format, ...)
{
    va_list arguments;
    va_start(arguments, format);
    int result = vswprintf(buffer, size, format, arguments);
    va_end(arguments);
    return result;
}
template <size_t N> int swprintf_s(wchar_t (&buffer)[N], const wchar_t* format, ...)
{
    va_list arguments;
    va_start(arguments, format);
    int result = vswprintf(buffer, N, format, arguments);
    va_end(arguments);
    return result;
}

/* UTF-8 <-> UTF-32, in the two call shapes kfilterctl uses. */
#define CP_UTF8 65001u
int WideCharToMultiByte(unsigned codePage, DWORD flags, const wchar_t* wide, int wideLength,
                        char* output, int outputLength, const char* defaultChar, BOOL* usedDefault);
int MultiByteToWideChar(unsigned codePage, DWORD flags, const char* text, int textLength,
                        wchar_t* output, int outputLength);
inline void SetConsoleOutputCP(unsigned) {}

inline int InetPtonW(int family, const wchar_t* text, void* output)
{
    char narrow[INET6_ADDRSTRLEN + 1];
    size_t index = 0;
    for (; text[index] != L'\0'; index++) {
        if (index >= INET6_ADDRSTRLEN || text[index] > 0x7F) return 0;
        narrow[index] = (char)text[index];
    }
    narrow[index] = '\0';
    return inet_pton(family, narrow, output);
}

inline int _wfopen_s(FILE** file, const wchar_t* path, const wchar_t* mode)
{
    char narrowMode[8] = {};
    for (size_t index = 0; index + 1 < sizeof(narrowMode) && mode[index] != L'\0'; index++) {
        narrowMode[index] = (char)mode[index];
    }
    int length = WideCharToMultiByte(CP_UTF8, 0, path, (int)wcslen(path), nullptr, 0, nullptr, nullptr);
    std::string narrow((size_t)length, '\0');
    WideCharToMultiByte(CP_UTF8, 0, path, (int)wcslen(path), narrow.data(), length, nullptr, nullptr);
    *file = fopen(narrow.c_str(), narrowMode);
    return *file == nullptr ? errno : 0;
}

inline DWORD GetTempPathW(DWORD size, wchar_t* buffer)
{
    const char* directory = getenv("TMPDIR");
    std::wstring path = L"/tmp/";
    if (directory != nullptr && directory[0] == '/') {
        path.clear();
        for (const char* cursor = directory; *cursor != '\0'; cursor++) path.push_back((wchar_t)(unsigned char)*cursor);
        if (path.back() != L'/') path.push_back(L'/');
    }
    if (path.size() + 1 > size) return 0;
    wcscpy_s(buffer, size, path.c_str());
    return (DWORD)path.size();
}
BOOL DeleteFileW(const wchar_t* path);

inline void Sleep(DWORD milliseconds) { usleep((useconds_t)milliseconds * 1000u); }
inline ULONGLONG GetTickCount64()
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (ULONGLONG)now.tv_sec * 1000u + (ULONGLONG)now.tv_nsec / 1000000u;
}

/* KFILTER_EVENT.Timestamp is a FILETIME on Linux too. */
typedef struct { DWORD dwLowDateTime; DWORD dwHighDateTime; } FILETIME;
typedef struct { WORD wYear, wMonth, wDayOfWeek, wDay, wHour, wMinute, wSecond, wMilliseconds; } SYSTEMTIME;
BOOL FileTimeToSystemTime(const FILETIME* fileTime, SYSTEMTIME* systemTime);
BOOL SystemTimeToTzSpecificLocalTime(const void* zone, const SYSTEMTIME* universal, SYSTEMTIME* local);

/* kfilterd's socket in place of \\.\KFilter (linux_client.cpp). */
HANDLE OpenDevice();
bool Ioctl(HANDLE device, DWORD code, void* input, DWORD inputLength,
           void* output, DWORD outputLength, DWORD* returned);
inline BOOL CloseHandle(HANDLE handle) { return close((int)handle) == 0; }
/* `kfilterctl launch` on Linux: cgroup, privilege drop, admission, exec. */
int LaunchLinux(const std::wstring& image, int argc, wchar_t** argv, int first, bool network);
