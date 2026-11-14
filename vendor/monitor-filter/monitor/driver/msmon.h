#pragma once

#include <ntifs.h>
#include <ntstrsafe.h>
#include <sddl.h>
#include "../include/msmon_protocol.h"
#include "../include/msmon_coverage.h"

#define MSMON_POOL_TAG 'noSM'

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD MsMonDriverUnload;
VOID MsMonRecordStatus(PCWSTR Name, NTSTATUS Status);

NTSTATUS MsMonAttributionInitialize(VOID);
NTSTATUS MsMonAttributionRefresh(VOID);
VOID MsMonAttributionStop(VOID);
BOOLEAN MsMonCurrentIsBlackCat(VOID);
VOID MsMonAttributionNoteImage(PCUNICODE_STRING FullImageName, PVOID ImageBase, SIZE_T ImageSize);
UNICODE_STRING MsMonBlackCatComponent(BOOLEAN Active, PWCHAR Buffer, USHORT Characters);

NTSTATUS MsMonEventsInitialize(VOID);
VOID MsMonEventsUninitialize(VOID);
NTSTATUS MsMonEventsStart(ULONGLONG SessionId, ULONG QueueRecords, ULONG QueueBytes, ULONG PayloadMode);
VOID MsMonEventsStop(VOID);
VOID MsMonEventsWakeAll(VOID);
BOOLEAN MsMonPayloadEnabled(VOID);
VOID MsMonEventsNoteDropped(VOID);
ULONGLONG MsMonNextOperationId(VOID);
NTSTATUS MsMonLogEvent(
    ULONG Type,
    HANDLE ProcessId,
    LONGLONG ProcessStartTime,
    HANDLE ParentProcessId,
    HANDLE ThreadId,
    HANDLE TargetProcessId,
    LONGLONG TargetProcessStartTime,
    ULONG Flags,
    NTSTATUS Status,
    ULONG DesiredAccess,
    ULONG Category,
    ULONGLONG Value0,
    ULONGLONG Value1,
    PCUNICODE_STRING Text,
    PCUNICODE_STRING Detail
);
NTSTATUS MsMonLogEventWithOperation(
    ULONG Type, HANDLE ProcessId, LONGLONG ProcessStartTime, HANDLE ThreadId, ULONG Flags, NTSTATUS Status,
    ULONG Category, ULONGLONG Value0, ULONGLONG Value1,
    PCUNICODE_STRING Text, PCUNICODE_STRING Detail, ULONGLONG OperationId
);
NTSTATUS MsMonLogPayloadSeries(
    ULONG Type, HANDLE ProcessId, LONGLONG ProcessStartTime, HANDLE ThreadId, ULONG Flags, NTSTATUS Status,
    ULONG Category, ULONGLONG Value0, ULONGLONG Value1,
    PCUNICODE_STRING Text, PCUNICODE_STRING Detail,
    ULONG PayloadKind, ULONGLONG OperationId, ULONGLONG TotalBytes,
    const VOID* Payload, ULONG AvailableBytes
);
NTSTATUS MsMonReadEvents(PVOID Output, ULONG MaximumBytes, ULONG TimeoutMilliseconds, PULONG BytesRead);
VOID MsMonGetStatistics(PMSMON_STATISTICS Statistics);
VOID MsMonCoverageReset(ULONGLONG SessionId);
VOID MsMonCoverageEnter(ULONG SensorId);
VOID MsMonCoverageLogged(ULONG SensorId);
VOID MsMonCoverageSkip(MSMON_SKIP_REASON Reason);
VOID MsMonCoverageRegister(ULONG SensorId, NTSTATUS Status);
VOID MsMonCoverageBlackCatMatch(VOID);
VOID MsMonGetCoverage(PMSMON_COVERAGE Coverage);

NTSTATUS MsMonProcessInitialize(VOID);
NTSTATUS MsMonImageInitialize(VOID);
VOID MsMonProcessUninitialize(VOID);
NTSTATUS MsMonProcessStartSession(PCUNICODE_STRING Roots, ULONG RootCount);
VOID MsMonProcessStopSession(VOID);
NTSTATUS MsMonTrackProcess(HANDLE ProcessId, ULONG Flags, LONGLONG ExpectedStartTime);
BOOLEAN MsMonIsTracked(HANDLE ProcessId, LONGLONG StartTime);
LONGLONG MsMonProcessStartTime(HANDLE ProcessId);
ULONG MsMonTrackedProcessCount(VOID);

NTSTATUS MsMonObjectInitialize(PDRIVER_OBJECT DriverObject);
VOID MsMonObjectUninitialize(VOID);
BOOLEAN MsMonObjectAvailable(VOID);
NTSTATUS MsMonObjectStatus(VOID);

NTSTATUS MsMonFileFilterInitialize(PDRIVER_OBJECT DriverObject);
VOID MsMonFileFilterUninitialize(VOID);

NTSTATUS MsMonRegistryInitialize(PDRIVER_OBJECT DriverObject);
VOID MsMonRegistryUninitialize(VOID);

NTSTATUS MsMonNetworkInitialize(PDEVICE_OBJECT DeviceObject);
VOID MsMonNetworkUninitialize(VOID);
BOOLEAN MsMonNetworkAvailable(VOID);
ULONG MsMonNetworkCoverage(VOID);
