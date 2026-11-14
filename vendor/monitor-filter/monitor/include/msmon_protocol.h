#pragma once

/* Kernel-mode builds may not have the CRT's <stdint.h>; MSVC accepts the identical
 * typedef if it is also included elsewhere. */
#if defined(_KERNEL_MODE)
typedef unsigned __int64 uint64_t;
#else
#include <stdint.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define MSMON_DEVICE_NAME L"\\Device\\MsMon"
#define MSMON_DOS_DEVICE_NAME L"\\DosDevices\\MsMon"
#define MSMON_USER_DEVICE_PATH "\\\\.\\MsMon"
#define MSMON_PROTOCOL_VERSION 4u
#define MSMON_MAX_EVENT_RECORD_BYTES 16384u
#define MSMON_MAX_EVENT_STRING_BYTES 2048u
#define MSMON_PAYLOAD_CHUNK_BYTES 8192u
#define MSMON_MAX_PAYLOAD_TOTAL_BYTES (8u * 1024u * 1024u)
#define MSMON_READ_MAX_BYTES (1024u * 1024u)
#define MSMON_DEFAULT_QUEUE_RECORDS 16384u
/* The byte limit bounds nonpaged memory; the record limit only has to exceed what it admits. */
#define MSMON_MAX_QUEUE_RECORDS 131072u
#define MSMON_DEFAULT_QUEUE_BYTES (64u * 1024u * 1024u)
#define MSMON_MAX_QUEUE_BYTES (128u * 1024u * 1024u)
#define MSMON_CLIENT_PATH_CHARS 260u
#define MSMON_EXTRA_ROOTS 3u
#define MSMON_MAX_STACK_FRAMES 24u

typedef enum _MSMON_EVENT_TYPE {
    MsMonProcessStart = 1,
    MsMonProcessExit = 2,
    MsMonThreadStart = 3,
    MsMonThreadExit = 4,
    MsMonImageLoad = 5,
    MsMonProcessHandle = 6,
    MsMonThreadHandle = 7,
    MsMonFileCreate = 10,
    MsMonFileRead = 11,
    MsMonFileWrite = 12,
    MsMonFileSetInformation = 13,
    MsMonFileDirectoryControl = 14,
    MsMonFileCleanup = 15,
    MsMonFileDeviceControl = 16,
    MsMonFileSystemControl = 17,
    MsMonFileQueryVolumeInformation = 18,
    MsMonFileQueryInformation = 19,
    MsMonRegistryOpen = 20,
    MsMonRegistryCreate = 21,
    MsMonRegistrySetValue = 22,
    MsMonRegistryDelete = 23,
    MsMonRegistryRename = 24,
    MsMonRegistryQuery = 25,
    MsMonRegistryEnumerate = 26,
    MsMonNetworkConnect = 30,
    MsMonNetworkAccept = 31,
    MsMonNetworkFlowEstablished = 32,
    MsMonNetworkFlowClose = 33,
    MsMonFileSection = 34,
    MsMonFileClose = 35,
    MsMonFileFlush = 36,
    MsMonFileQuerySecurity = 37,
    MsMonFileSetSecurity = 38,
    MsMonFileQueryEa = 39,
    MsMonFileSetEa = 40,
    MsMonEtwWmi = 100,
    MsMonEtwDns = 101,
    MsMonEtwRpc = 102,
    MsMonEtwUnattributed = 103,
    MsMonEtwTcp = 104,
    MsMonEtwCodeIntegrity = 105,
    MsMonCoverage = 110,
    MsMonCoverageUsage = 111,
    MsMonKfilterDecision = 120
} MSMON_EVENT_TYPE;

typedef enum _MSMON_EVENT_FLAGS {
    MsMonFlagExplicitTrack = 0x00000001u,
    MsMonFlagInheritedTrack = 0x00000002u,
    MsMonFlagTruncatedPath = 0x00000004u,
    MsMonFlagMissingPath = 0x00000008u,
    MsMonFlagServiceCorrelated = 0x00000010u,
    MsMonFlagObserverRecord = 0x00000020u,
    MsMonFlagPayloadPresent = 0x00000040u,
    MsMonFlagPayloadUnavailable = 0x00000080u,
    MsMonFlagPayloadFinalChunk = 0x00000100u,
    MsMonFlagPayloadInput = 0x00000200u,
    MsMonFlagPayloadPartial = 0x00000400u,
    MsMonFlagTruncatedDetail = 0x00000800u   /* the detail string was cut at the record's string limit (Linux) */
} MSMON_EVENT_FLAGS;

typedef enum _MSMON_PAYLOAD_KIND {
    MsMonPayloadNone = 0,
    MsMonPayloadRegistryValue = 1,
    MsMonPayloadVolumeInformation = 2,
    MsMonPayloadNetworkData = 3,     /* bytes one send/receive call moved on a network socket (Linux) */
    MsMonPayloadIpcData = 4,         /* bytes a Wine named pipe / device read or write or an RPC request stub moved (Linux) */
    MsMonPayloadTlsPlaintext = 5     /* plaintext one TLS record call took or returned (Linux: Wine's schannel via GnuTLS) */
} MSMON_PAYLOAD_KIND;

typedef enum _MSMON_CATEGORY {
    MsMonCategoryUnknown = 0,
    MsMonCategoryClientData = 1,
    MsMonCategoryWindowsRuntime = 2,
    MsMonCategoryExternalProcess = 3,
    MsMonCategoryBrowserInteraction = 4,
    MsMonCategoryHardwareIdentity = 5,
    MsMonCategoryUserData = 6,
    MsMonCategoryRegistry = 7,
    MsMonCategoryNetwork = 8,
    MsMonCategoryIpc = 9
} MSMON_CATEGORY;

typedef enum _MSMON_ATTRIBUTION {
    MsMonAttributionUnknown = 0,
    MsMonAttributionProcessOnly = 1,
    MsMonAttributionStackResolved = 2,
    MsMonAttributionServiceCorrelated = 3,
    MsMonAttributionStaticEvidence = 4
} MSMON_ATTRIBUTION;

#pragma pack(push, 8)
typedef struct _MSMON_EVENT_HEADER {
    unsigned long Size;
    unsigned long Version;
    unsigned long Type;
    unsigned long Flags;
    uint64_t Sequence;
    uint64_t Timestamp;
    uint64_t SessionId;
    unsigned long ProcessId;
    unsigned long ParentProcessId;
    unsigned long ThreadId;
    unsigned long TargetProcessId;
    uint64_t ProcessStartTime;
    uint64_t TargetProcessStartTime;
    long Status;
    unsigned long DesiredAccess;
    unsigned long Category;
    unsigned long Attribution;
    unsigned short TextOffset;
    unsigned short TextBytes;
    unsigned short DetailOffset;
    unsigned short DetailBytes;
    unsigned short ComponentOffset;
    unsigned short ComponentBytes;
    uint64_t Value0;
    uint64_t Value1;
    uint64_t OperationId;
    uint64_t PayloadTotalBytes;
    uint64_t PayloadByteOffset;
    unsigned long PayloadChunkIndex;
    unsigned long PayloadChunkCount;
    unsigned long PayloadKind;
    unsigned long PayloadOffset;
    unsigned long PayloadBytes;
    /*
     * User-mode return addresses of the requesting thread, one uint64_t
     * each, at StackOffset; both zero when no stack was captured.
     * These two fields were a zeroed Reserved ULONG, so the layout is unchanged.
     */
    unsigned short StackOffset;
    unsigned short StackFrames;
} MSMON_EVENT_HEADER;

typedef struct _MSMON_PAYLOAD {
    uint64_t OperationId;
    uint64_t TotalBytes;
    uint64_t ByteOffset;
    unsigned long ChunkIndex;
    unsigned long ChunkCount;
    unsigned long Kind;
    const void* Data;
    unsigned long ByteCount;
} MSMON_PAYLOAD;

typedef struct _MSMON_SESSION_CONFIG {
    uint64_t SessionId;
    unsigned long QueueRecords;
    unsigned long QueueBytes;
    unsigned long PayloadMode;
    unsigned long Reserved;
    wchar_t ClientRoot[MSMON_CLIENT_PATH_CHARS];
    /*
     * Further device-path roots tracked like ClientRoot; empty entries are
     * unused.  Drivers accept the shorter structure that ends at ClientRoot.
     */
    wchar_t ExtraRoots[MSMON_EXTRA_ROOTS][MSMON_CLIENT_PATH_CHARS];
} MSMON_SESSION_CONFIG;

typedef struct _MSMON_TRACK_REQUEST {
    unsigned long ProcessId;
    unsigned long Flags;
    uint64_t ProcessStartTime;
} MSMON_TRACK_REQUEST;

typedef struct _MSMON_READ_REQUEST {
    unsigned long TimeoutMilliseconds;
    unsigned long MaximumBytes;
} MSMON_READ_REQUEST;

typedef struct _MSMON_STATISTICS {
    uint64_t SessionId;
    uint64_t QueuedEvents;
    uint64_t QueuedBytes;
    uint64_t DroppedEvents;
    uint64_t TrackedProcesses;
    uint64_t QueueRecordLimit;
    uint64_t QueueByteLimit;
} MSMON_STATISTICS;
#pragma pack(pop)

typedef MSMON_EVENT_HEADER* PMSMON_EVENT_HEADER;
typedef MSMON_SESSION_CONFIG* PMSMON_SESSION_CONFIG;
typedef MSMON_TRACK_REQUEST* PMSMON_TRACK_REQUEST;
typedef MSMON_READ_REQUEST* PMSMON_READ_REQUEST;
typedef MSMON_STATISTICS* PMSMON_STATISTICS;

/* The Linux agent has no device; its in-process sensors produce the same records. */
#ifdef CTL_CODE
#define MSMON_IOCTL_START_SESSION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define MSMON_IOCTL_STOP_SESSION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define MSMON_IOCTL_TRACK_PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define MSMON_IOCTL_READ_EVENTS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_READ_ACCESS)
#define MSMON_IOCTL_STATISTICS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_READ_ACCESS)
#define MSMON_IOCTL_STOP_TRACKING CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define MSMON_IOCTL_REFRESH_MODULES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define MSMON_IOCTL_COVERAGE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_READ_ACCESS)
#endif

static __inline int MsMonNetworkUnregisterComplete(long Status)
{
    return Status == 0 || (unsigned long)Status == 0xC0220001u;
}

/*
 * FwpsFlowRemoveContext0: STATUS_SUCCESS removed the association (flowDeleteFn already
 * ran synchronously); STATUS_UNSUCCESSFUL means no context is associated. Everything
 * else - notably STATUS_PENDING (0x103), which is success-valued but leaves an
 * asynchronous flowDeleteFn still to come - means the removal is not finished.
 */
static __inline int MsMonFlowRemoveComplete(long Status)
{
    return Status == 0 || (unsigned long)Status == 0xC0000001u;
}

/*
 * An explicit track request names the incarnation the caller resolved.  Zero
 * means "no expectation" (the automatic process/image callers); anything else
 * must equal the creation time the driver just read, or the PID was reused
 * between the caller's identity query and this IOCTL.
 */
static __inline int MsMonTrackAdmitsStart(uint64_t Expected, uint64_t Actual)
{
    return Expected == 0 || Expected == Actual;
}

#ifdef __cplusplus
}
#endif
