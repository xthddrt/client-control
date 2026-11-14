#pragma once

#ifdef _WIN32
#include <ntifs.h>
#include <ntstrsafe.h>
#include <sddl.h>
#else
/* kfilterd (Linux) compiles policy.c and events.c against a small NT shim. */
#include "../linux/posix_shim.h"
#endif
#include "kfilter.h"
#include "match.h"

#ifdef _WIN32
#define KFILTER_POOL_TAG 'tlFK'
#else
#define KFILTER_POOL_TAG 0u   /* calloc has no tags */
#endif

/* main.c */
ULONG KfDriverRegisteredMask(VOID);

/* policy.c */
NTSTATUS KfPolicyInitialize(VOID);
VOID KfPolicyUninitialize(VOID);
NTSTATUS KfPolicySetConfig(const KFILTER_CONFIG* Config, ULONG Length);
ULONG KfPolicyGetConfig(PKFILTER_CONFIG Config, ULONG Capacity);
VOID KfPolicyGetStatus(PKFILTER_STATUS Status);
ULONG KfPolicyMode(VOID);
ULONG KfPolicyGeneration(VOID);
BOOLEAN KfPolicyFlag(ULONG Flag);
BOOLEAN KfPolicyBlockVolumeSerial(VOID);
BOOLEAN KfPolicyBlockProcessMemory(VOID);
BOOLEAN KfPolicyBlockRawDisk(VOID);
BOOLEAN KfPolicyBlockNetwork(VOID);
BOOLEAN KfPolicyBlockNetworkAdapter(VOID);
BOOLEAN KfPolicyBlockFiles(VOID);
BOOLEAN KfPolicyBlockRegistry(VOID);
BOOLEAN KfPolicyBlockProcessCreate(VOID);
BOOLEAN KfPolicyDefaultDeny(VOID);
BOOLEAN KfPolicyRawDiskDegraded(VOID);
BOOLEAN KfPolicyMatchesProtectedName(PCUNICODE_STRING ImagePath);
BOOLEAN KfPolicyPackageSidMatches(const UCHAR* Sid, ULONG SidLength);
BOOLEAN KfPolicyHasProcessRules(VOID);
BOOLEAN KfPolicyValueEnumerationDenied(PCUNICODE_STRING KeyPath, ULONG* RuleIdOut);
BOOLEAN KfPolicyIsUnderRoot(PCUNICODE_STRING ImagePath);
VOID KfPolicyResetCounts(VOID);
ULONG KfPolicyOutsideRights(ULONG Target, PCUNICODE_STRING ImagePath, BOOLEAN IsSystem,
                            ULONG Requested, ULONG* RuleIdOut, ULONG* FlagsOut);
BOOLEAN KfPolicyLaunchBroker(PCUNICODE_STRING ImagePath, BOOLEAN IsSystem);
BOOLEAN KfDecide(ULONG Target, PCUNICODE_STRING Path, ULONG DesiredAccess,
                 PCUNICODE_STRING Value, ULONG VolumeClass,
                 ULONG* RuleIdOut, BOOLEAN* NameFailureOut);
BOOLEAN KfDecideWithRights(ULONG Target, PCUNICODE_STRING Path, ULONG Rights,
                           PCUNICODE_STRING Value, ULONG VolumeClass,
                           ULONG* RuleIdOut, BOOLEAN* NameFailureOut, ULONG* ActionOut,
                           ULONG EventValue);
ULONG KfPolicyNetworkDecide(HANDLE ProcessId, ULONG Family, ULONG Protocol, ULONG RemotePort,
                            const UCHAR* Address, ULONG Right, ULONG* RuleIdOut, ULONG* FlagsOut);
VOID KfCountNameFailure(VOID);
VOID KfCountMissingContext(VOID);
VOID KfCountSidFailure(VOID);
VOID KfCountDenied(VOID);
/* A decision made elsewhere (kfilterd's BPF layer), counted as KfDecideWithRights counts. */
VOID KfCountDecision(ULONG Action, ULONG Flags);

/* events.c */
NTSTATUS KfEventsInitialize(VOID);
VOID KfEventsUninitialize(VOID);
VOID KfLogEventFor(HANDLE ProcessId, ULONG Target, ULONG Action, ULONG Flags, NTSTATUS Status,
                   ULONG Value, ULONG RuleId, PCUNICODE_STRING Path);
VOID KfLogEvent(ULONG Target, ULONG Action, ULONG Flags, NTSTATUS Status, ULONG Value,
                ULONG RuleId, PCUNICODE_STRING Path);
ULONG KfReadEvents(KFILTER_EVENT* Output, ULONG MaximumEvents);
VOID KfClearEvents(VOID);
ULONG KfDroppedEventCount(VOID);
/* Records a BPF-layer decision: the ring entry and the status counters. */
VOID KfLogBpfDecision(HANDLE ProcessId, ULONG Target, ULONG Action, ULONG Flags, NTSTATUS Status,
                      ULONG Value, ULONG RuleId, PCUNICODE_STRING Path, PCWSTR Image);

/* process.c */
NTSTATUS KfProcessInitialize(VOID);
VOID KfProcessUninitialize(VOID);
BOOLEAN KfProcessIsProtectedPid(HANDLE ProcessId, LONGLONG StartTime);
BOOLEAN KfProcessIsProtectedCurrent(VOID);
ULONG KfProcessCurrentGeneration(VOID);
/* The image path of a protected process (Linux: under Wine its Windows image), copied into
 * Buffer; returns its length, 0 when unknown. */
ULONG KfProcessImageOf(HANDLE ProcessId, PWCHAR Buffer, ULONG Capacity);
ULONG KfProcessTrackedCount(VOID);
NTSTATUS KfProcessTrack(HANDLE ProcessId);
NTSTATUS KfProcessRegisterLauncher(VOID);
NTSTATUS KfProcessAllowLaunch(const KFILTER_ALLOW_LAUNCH_REQUEST* Request);
NTSTATUS KfProcessAdmit(const KFILTER_ADMIT_REQUEST* Request);
VOID KfProcessClearTracking(VOID);
BOOLEAN KfProcessParentAllowed(HANDLE ParentProcessId);
NTSTATUS KfProcessGetSid(PEPROCESS Process, PUCHAR Buffer, PULONG Length);
BOOLEAN KfProcessIsSystem(PEPROCESS Process);

/* callback modules */
NTSTATUS KfFileInitialize(PDRIVER_OBJECT DriverObject);
VOID KfFileUninitialize(VOID);
NTSTATUS KfRegistryInitialize(PDRIVER_OBJECT DriverObject);
VOID KfRegistryUninitialize(VOID);
NTSTATUS KfObjectInitialize(PDRIVER_OBJECT DriverObject);
VOID KfObjectUninitialize(VOID);

NTSTATUS KfDiskInitialize(PDRIVER_OBJECT DriverObject);
VOID KfDiskUninitialize(VOID);
NTSTATUS KfDiskDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp);
BOOLEAN KfDiskIsFilterDevice(PDEVICE_OBJECT DeviceObject);
BOOLEAN KfDiskAvailable(VOID);
BOOLEAN KfDiskDegraded(VOID);
NTSTATUS KfDiskRearm(VOID);

NTSTATUS KfDeviceInitialize(PDRIVER_OBJECT DriverObject);
VOID KfDeviceUninitialize(VOID);
NTSTATUS KfDeviceDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp);
BOOLEAN KfDeviceIsFilterDevice(PDEVICE_OBJECT DeviceObject);
BOOLEAN KfDeviceAvailable(VOID);
BOOLEAN KfDeviceDegraded(VOID);
BOOLEAN KfDeviceNsiAttached(VOID);

NTSTATUS KfNetworkInitialize(PDEVICE_OBJECT DeviceObject);
VOID KfNetworkUninitialize(VOID);
BOOLEAN KfNetworkAvailable(VOID);
