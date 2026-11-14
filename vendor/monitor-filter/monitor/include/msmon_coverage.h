#pragma once

/* Kernel-mode builds may not have the CRT's <stdint.h>; MSVC accepts the identical
 * typedef if it is also included elsewhere. */
#if defined(_KERNEL_MODE)
typedef unsigned __int64 uint64_t;
#else
#include <stdint.h>
#endif

/*
 * Runtime sensor accounting.  This is additive: it does not change the event
 * header or MSMON_STATISTICS.  One slot per event type and one per sensor/call
 * keeps the block small enough for a single buffered IOCTL.
 */

#define MSMON_COVERAGE_VERSION 1u
#define MSMON_EVENT_SLOTS 128u
#define MSMON_SENSOR_SLOTS 64u

typedef enum _MSMON_SENSOR_ID {
    /* Hot-path sensors. */
    MSMON_SENSOR_PROCESS_NOTIFY = 0,
    MSMON_SENSOR_THREAD_NOTIFY = 1,
    MSMON_SENSOR_IMAGE_NOTIFY = 2,
    MSMON_SENSOR_OBJECT_PROCESS = 3,
    MSMON_SENSOR_OBJECT_THREAD = 4,
    MSMON_SENSOR_FILE_PRE_CREATE = 5,
    MSMON_SENSOR_FILE_POST_CREATE = 6,
    MSMON_SENSOR_FILE_PRE_OP = 7,
    MSMON_SENSOR_FILE_POST_OP = 8,
    MSMON_SENSOR_REGISTRY_CALLBACK = 9,
    MSMON_SENSOR_WFP_CLASSIFY = 10,
    MSMON_SENSOR_WFP_NOTIFY = 11,
    MSMON_SENSOR_BLACKCAT_CHECK = 12,
    MSMON_SENSOR_IOCTL_DISPATCH = 13,

    /* Registration calls: one slot each so every failure is preserved. */
    MSMON_SENSOR_REG_PROCESS_NOTIFY = 20,
    MSMON_SENSOR_REG_THREAD_NOTIFY = 21,
    MSMON_SENSOR_REG_IMAGE_NOTIFY = 22,
    MSMON_SENSOR_REG_OBJECT_PROCESS = 23,
    MSMON_SENSOR_REG_OBJECT_THREAD = 24,
    MSMON_SENSOR_REG_FILTER_REGISTER = 25,
    MSMON_SENSOR_REG_FILTER_START = 26,
    MSMON_SENSOR_REG_REGISTRY = 27,
    MSMON_SENSOR_REG_WFP_0 = 28,
    MSMON_SENSOR_REG_WFP_1 = 29,
    MSMON_SENSOR_REG_WFP_2 = 30,
    MSMON_SENSOR_REG_WFP_3 = 31,
    MSMON_SENSOR_REG_WFP_4 = 32,
    MSMON_SENSOR_REG_WFP_5 = 33,
    MSMON_SENSOR_REG_WFP_ENGINE = 34,
    MSMON_SENSOR_REG_ETW_WMI = 35,
    MSMON_SENSOR_REG_ETW_DNS = 36,
    MSMON_SENSOR_REG_ETW_RPC = 37,
    MSMON_SENSOR_REG_ATTRIBUTION = 38,

    /* Linux agent sensors (agent/linux): event sources, then their set-up calls. */
    MSMON_SENSOR_LINUX_FANOTIFY = 40,
    MSMON_SENSOR_LINUX_PROC_CONNECTOR = 41,
    MSMON_SENSOR_LINUX_MAPS_POLL = 42,
    MSMON_SENSOR_LINUX_NET_POLL = 43,
    MSMON_SENSOR_REG_LINUX_FANOTIFY = 44,
    MSMON_SENSOR_REG_LINUX_PROC_CONNECTOR = 45,
    MSMON_SENSOR_REG_LINUX_MAPS_POLL = 46,
    MSMON_SENSOR_REG_LINUX_NET_POLL = 47,
    /* Linux kernel (eBPF) sensors (agent/linux/bpf/monitor.bpf.c), then their set-up. */
    MSMON_SENSOR_LINUX_EBPF_PROCESS = 48,
    MSMON_SENSOR_LINUX_EBPF_FILE = 49,
    MSMON_SENSOR_LINUX_EBPF_NET = 50,
    MSMON_SENSOR_LINUX_EBPF_IPC = 51,
    MSMON_SENSOR_LINUX_EBPF_DEVICE = 52,
    MSMON_SENSOR_LINUX_EBPF_MEMORY = 53,
    MSMON_SENSOR_REG_LINUX_EBPF_PROCESS = 54,
    MSMON_SENSOR_REG_LINUX_EBPF_FILE = 55,
    MSMON_SENSOR_REG_LINUX_EBPF_NET = 56,
    MSMON_SENSOR_REG_LINUX_EBPF_IPC = 57,
    MSMON_SENSOR_REG_LINUX_EBPF_DEVICE = 58,
    MSMON_SENSOR_REG_LINUX_EBPF_MEMORY = 59,
    /* Linux wineserver-request decoder (agent/linux/bpf/ws.bpf.h, agent/linux/wineserver.cpp), then its set-up.
     * 62 and 63 are free. */
    MSMON_SENSOR_LINUX_EBPF_WINESERVER = 60,
    MSMON_SENSOR_REG_LINUX_EBPF_WINESERVER = 61,

    MSMON_SENSOR_MAX = 62
} MSMON_SENSOR_ID;

typedef enum _MSMON_SKIP_REASON {
    MSMON_SKIP_UNTRACKED = 0,
    MSMON_SKIP_IRQL = 1,
    MSMON_SKIP_NO_NAME = 2,
    MSMON_SKIP_ALLOC = 3,
    MSMON_SKIP_TRACK = 4,
    MSMON_SKIP_QUEUE = 5
} MSMON_SKIP_REASON;

#pragma pack(push, 8)
typedef struct _MSMON_COVERAGE {
    unsigned long Version;
    unsigned long Size;
    uint64_t SessionId;
    uint64_t EventAttempted[MSMON_EVENT_SLOTS];
    uint64_t EventDropped[MSMON_EVENT_SLOTS];
    uint64_t SensorEntered[MSMON_SENSOR_SLOTS];
    uint64_t SensorLogged[MSMON_SENSOR_SLOTS];
    uint64_t SkipUntracked;
    uint64_t SkipIrql;
    uint64_t SkipNoName;
    uint64_t AllocFailures;
    uint64_t TrackFailures;
    uint64_t QueueDrops;
    uint64_t BlackCatMatches;
    uint64_t PayloadCaptured[4];
    uint64_t RegistrationOk;
    uint64_t RegistrationFailed;
    long RegistrationStatus[MSMON_SENSOR_SLOTS];
} MSMON_COVERAGE;
#pragma pack(pop)

typedef MSMON_COVERAGE* PMSMON_COVERAGE;
