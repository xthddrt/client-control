#pragma once

/*
 * Just enough of the NT kernel surface for driver/policy.c and driver/events.c to
 * compile unchanged into kfilterd. Spin locks are pthread mutexes, pool memory is
 * calloc, Interlocked* are GCC atomics. Nothing here is a kernel API on Linux.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include "../driver/kfilter.h"

#define VOID void
typedef uint8_t BOOLEAN;
typedef uint8_t UCHAR;
typedef UCHAR* PUCHAR;
typedef uint16_t USHORT;
typedef KF_ULONG ULONG;
typedef ULONG* PULONG;
typedef int32_t LONG;
typedef int64_t LONGLONG;
typedef uint64_t ULONG64;
typedef size_t SIZE_T;
typedef wchar_t WCHAR;
typedef WCHAR* PWSTR;
typedef const WCHAR* PCWSTR;
typedef WCHAR* PWCHAR;
typedef int32_t NTSTATUS;
typedef void* HANDLE;
typedef void* PVOID;
typedef void* PSID;
typedef void* PEPROCESS;
typedef void* PDRIVER_OBJECT;
typedef void* PDEVICE_OBJECT;
typedef void* PIRP;

typedef struct _UNICODE_STRING {
    USHORT Length;          /* bytes, as on NT */
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef union _LARGE_INTEGER {
    LONGLONG QuadPart;
} LARGE_INTEGER;

#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif

#define NT_SUCCESS(status) ((NTSTATUS)(status) >= 0)
#define STATUS_SUCCESS ((NTSTATUS)0x00000000)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001)
#define STATUS_INVALID_CID ((NTSTATUS)0xC000000B)
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000D)
#define STATUS_INVALID_DEVICE_REQUEST ((NTSTATUS)0xC0000010)
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022)
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023)
#define STATUS_OBJECT_NAME_INVALID ((NTSTATUS)0xC0000033)
#define STATUS_REVISION_MISMATCH ((NTSTATUS)0xC0000059)
#define STATUS_INVALID_SID ((NTSTATUS)0xC0000078)
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xC000009A)
#define STATUS_DEVICE_NOT_READY ((NTSTATUS)0xC00000A3)
#define STATUS_NOT_SUPPORTED ((NTSTATUS)0xC00000BB)
#define STATUS_NOT_FOUND ((NTSTATUS)0xC0000225)
#define STATUS_ALREADY_REGISTERED ((NTSTATUS)0xC0000718)

typedef pthread_mutex_t KSPIN_LOCK;
typedef int KIRQL;
#define KeInitializeSpinLock(lock) pthread_mutex_init((lock), NULL)
#define KeAcquireSpinLock(lock, irql) (*(irql) = 0, pthread_mutex_lock(lock))
#define KeReleaseSpinLock(lock, irql) ((void)(irql), pthread_mutex_unlock(lock))

#define InterlockedIncrement(target) __atomic_add_fetch((target), 1, __ATOMIC_SEQ_CST)
#define InterlockedDecrement(target) __atomic_sub_fetch((target), 1, __ATOMIC_SEQ_CST)
#define InterlockedExchange(target, value) __atomic_exchange_n((target), (value), __ATOMIC_SEQ_CST)
/* Returns the initial value, as the NT routine does. */
#define InterlockedCompareExchange(target, exchange, comparand) __extension__({ \
    LONG kfExpected_ = (comparand);                                         \
    __atomic_compare_exchange_n((target), &kfExpected_, (exchange), 0,      \
                                __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);        \
    kfExpected_; })

#define POOL_FLAG_NON_PAGED 0
#define ExAllocatePool2(flags, size, tag) calloc(1, (size))
#define ExFreePoolWithTag(pointer, tag) free((void*)(pointer))
#define RtlZeroMemory(destination, length) memset((destination), 0, (length))
#define RtlCopyMemory(destination, source, length) memcpy((destination), (source), (length))
#define FIELD_OFFSET(type, field) offsetof(type, field)

static inline SIZE_T RtlCompareMemory(const void* left, const void* right, SIZE_T length)
{
    const unsigned char* a = (const unsigned char*)left;
    const unsigned char* b = (const unsigned char*)right;
    SIZE_T index = 0;
    while (index < length && a[index] == b[index]) index++;
    return index;
}

/* Linux has no package SIDs: kfilterctl never sends one, and a config that does is invalid. */
#define RtlValidSid(sid) FALSE
#define RtlLengthSid(sid) 0u

#define HandleToULong(handle) ((ULONG)(uintptr_t)(handle))
#define UlongToHandle(value) ((HANDLE)(uintptr_t)(value))

static inline void KeQuerySystemTime(LARGE_INTEGER* time)
{
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    time->QuadPart = (LONGLONG)(116444736000000000ull + (uint64_t)now.tv_sec * 10000000ull +
                                (uint64_t)now.tv_nsec / 100u);
}

#ifdef __cplusplus
extern "C" {
#endif
/* The process the current decision is for: kfilterd decides on behalf of the
 * process that raised the fanotify event, not for itself. */
HANDLE PsGetCurrentProcessId(void);
#ifdef __cplusplus
}
#endif
