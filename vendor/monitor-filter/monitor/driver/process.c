#include "msmon.h"

typedef struct _MSMON_PROCESS_ENTRY {
    LIST_ENTRY Link;
    HANDLE ProcessId;
    HANDLE ParentProcessId;
    LONGLONG StartTime;
    ULONG Flags;
} MSMON_PROCESS_ENTRY, *PMSMON_PROCESS_ENTRY;

static LIST_ENTRY gProcesses;
static KSPIN_LOCK gProcessLock;
static volatile LONG gProcessCount;
#define MSMON_MAX_SCOPE_ROOTS (1u + MSMON_EXTRA_ROOTS)
static UNICODE_STRING gRoots[MSMON_MAX_SCOPE_ROOTS];
static ULONG gRootCount;
static KMUTEX gRootMutex;
static BOOLEAN gSessionActive;
static BOOLEAN gProcessNotifyEx;
static BOOLEAN gProcessNotifyRegistered;
static BOOLEAN gThreadNotifyRegistered;
static BOOLEAN gImageNotifyRegistered;
static BOOLEAN gCallbackRundownInitialized;
static BOOLEAN gProcessInitialized;
static EX_RUNDOWN_REF gCallbackRundown;

VOID MsMonRecordStatus(PCWSTR Name, NTSTATUS Status)
{
    UNICODE_STRING path;
    UNICODE_STRING valueName;
    OBJECT_ATTRIBUTES attributes;
    HANDLE key = NULL;
    RtlInitUnicodeString(&path, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\msmon");
    InitializeObjectAttributes(&attributes, &path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (!NT_SUCCESS(ZwOpenKey(&key, KEY_SET_VALUE, &attributes))) return;
    RtlInitUnicodeString(&valueName, Name);
    (VOID)ZwSetValueKey(key, &valueName, 0, REG_DWORD, &Status, sizeof(Status));
    (VOID)ZwClose(key);
}

/*
 * Track any executable image beneath a configured root, not a hard-coded list.
 * The installation contains PE payloads with non-.exe extensions (for example
 * the GRAP .aes images) and private-server builds may rename helpers.  The
 * first root is the appdata scope chosen by the agent; further roots cover
 * client components started by something else, such as the NGS service the
 * service control manager launches.  Descendants are inherited separately.
 */
static BOOLEAN MsMonImageUnderRoot(PCUNICODE_STRING ImageFileName)
{
    BOOLEAN result = FALSE;
    ULONG index;
    if (!gSessionActive || gRootCount == 0 || ImageFileName == NULL || ImageFileName->Buffer == NULL) {
        return FALSE;
    }
    (VOID)KeWaitForSingleObject(&gRootMutex, Executive, KernelMode, FALSE, NULL);
    for (index = 0; gSessionActive && index < gRootCount && !result; index++) {
        PCUNICODE_STRING root = &gRoots[index];
        if (ImageFileName->Length > root->Length && RtlPrefixUnicodeString(root, ImageFileName, TRUE)) {
            result = ImageFileName->Buffer[root->Length / sizeof(WCHAR)] == L'\\';
        }
    }
    KeReleaseMutex(&gRootMutex, FALSE);
    return result;
}

/*
 * The agent configures the root as a device path (\Device\HarddiskVolumeN\...),
 * but CreateInfo->ImageFileName is the name the creator passed, normally
 * \??\C:\..., so a prefix match on it never succeeds for a newly started
 * client.  SeLocateProcessImageName returns the device form; the caller's
 * name is kept as a fallback.
 */
static BOOLEAN MsMonProcessImageUnderRoot(PEPROCESS Process, PCUNICODE_STRING FallbackName)
{
    PUNICODE_STRING imageName = NULL;
    BOOLEAN result = FALSE;
    if (!gSessionActive) return FALSE;
    if (NT_SUCCESS(SeLocateProcessImageName(Process, &imageName))) {
        result = MsMonImageUnderRoot(imageName);
        ExFreePool(imageName);
    }
    if (!result && FallbackName != NULL) result = MsMonImageUnderRoot(FallbackName);
    return result;
}

static VOID MsMonClearProcesses(VOID)
{
    PLIST_ENTRY entry;
    KIRQL oldIrql;
    KeAcquireSpinLock(&gProcessLock, &oldIrql);
    while (!IsListEmpty(&gProcesses)) {
        entry = RemoveHeadList(&gProcesses);
        ExFreePoolWithTag(CONTAINING_RECORD(entry, MSMON_PROCESS_ENTRY, Link), MSMON_POOL_TAG);
    }
    gProcessCount = 0;
    KeReleaseSpinLock(&gProcessLock, oldIrql);
}

static VOID MsMonFreeRoots(PUNICODE_STRING Roots, ULONG Count)
{
    ULONG index;
    for (index = 0; index < Count; index++) {
        if (Roots[index].Buffer != NULL) ExFreePoolWithTag(Roots[index].Buffer, MSMON_POOL_TAG);
    }
}

static NTSTATUS MsMonCopyRoot(PCUNICODE_STRING Root, PUNICODE_STRING Normalized)
{
    PWSTR buffer;
    USHORT length;

    if (Root == NULL || Root->Buffer == NULL || Root->Length == 0 ||
        Root->Length >= MSMON_CLIENT_PATH_CHARS * sizeof(WCHAR)) return STATUS_INVALID_PARAMETER;
    length = Root->Length;
    while (length > 3 * sizeof(WCHAR) && Root->Buffer[length / sizeof(WCHAR) - 1] == L'\\') {
        length -= sizeof(WCHAR);
    }
    buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, (SIZE_T)length + sizeof(WCHAR), MSMON_POOL_TAG);
    if (buffer == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    RtlCopyMemory(buffer, Root->Buffer, length);
    buffer[length / sizeof(WCHAR)] = L'\0';
    Normalized->Buffer = buffer;
    Normalized->Length = length;
    Normalized->MaximumLength = length + sizeof(WCHAR);
    return STATUS_SUCCESS;
}

NTSTATUS MsMonProcessStartSession(PCUNICODE_STRING Roots, ULONG RootCount)
{
    UNICODE_STRING normalized[MSMON_MAX_SCOPE_ROOTS];
    UNICODE_STRING old[MSMON_MAX_SCOPE_ROOTS];
    ULONG oldCount;
    ULONG index;
    NTSTATUS status;

    if (Roots == NULL || RootCount == 0 || RootCount > MSMON_MAX_SCOPE_ROOTS) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(normalized, sizeof(normalized));
    for (index = 0; index < RootCount; index++) {
        status = MsMonCopyRoot(&Roots[index], &normalized[index]);
        if (!NT_SUCCESS(status)) {
            MsMonFreeRoots(normalized, index);
            return status;
        }
    }

    MsMonClearProcesses();
    (VOID)KeWaitForSingleObject(&gRootMutex, Executive, KernelMode, FALSE, NULL);
    RtlCopyMemory(old, gRoots, sizeof(old));
    oldCount = gRootCount;
    RtlCopyMemory(gRoots, normalized, sizeof(gRoots));
    gRootCount = RootCount;
    gSessionActive = TRUE;
    KeReleaseMutex(&gRootMutex, FALSE);
    MsMonFreeRoots(old, oldCount);
    return STATUS_SUCCESS;
}

VOID MsMonProcessStopSession(VOID)
{
    UNICODE_STRING old[MSMON_MAX_SCOPE_ROOTS];
    ULONG oldCount;
    (VOID)KeWaitForSingleObject(&gRootMutex, Executive, KernelMode, FALSE, NULL);
    gSessionActive = FALSE;
    RtlCopyMemory(old, gRoots, sizeof(old));
    oldCount = gRootCount;
    RtlZeroMemory(gRoots, sizeof(gRoots));
    gRootCount = 0;
    KeReleaseMutex(&gRootMutex, FALSE);
    MsMonFreeRoots(old, oldCount);
    MsMonClearProcesses();
}

NTSTATUS MsMonTrackProcess(HANDLE ProcessId, ULONG Flags, LONGLONG ExpectedStartTime)
{
    PMSMON_PROCESS_ENTRY entry;
    PMSMON_PROCESS_ENTRY existing;
    PMSMON_PROCESS_ENTRY stale = NULL;
    PLIST_ENTRY link;
    PEPROCESS process = NULL;
    KIRQL oldIrql;
    BOOLEAN duplicate = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    (VOID)KeWaitForSingleObject(&gRootMutex, Executive, KernelMode, FALSE, NULL);
    if (!gSessionActive) {
        KeReleaseMutex(&gRootMutex, FALSE);
        return STATUS_DEVICE_NOT_READY;
    }
    entry = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*entry), MSMON_POOL_TAG);
    if (entry == NULL) {
        KeReleaseMutex(&gRootMutex, FALSE);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(entry, sizeof(*entry));
    entry->ProcessId = ProcessId;
    entry->Flags = Flags;
    if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &process))) {
        entry->StartTime = PsGetProcessCreateTimeQuadPart(process);
        entry->ParentProcessId = NULL;
        ObDereferenceObject(process);
        if (!MsMonTrackAdmitsStart((ULONGLONG)ExpectedStartTime, (ULONGLONG)entry->StartTime)) {
            ExFreePoolWithTag(entry, MSMON_POOL_TAG);
            KeReleaseMutex(&gRootMutex, FALSE);
            return STATUS_REVISION_MISMATCH;
        }
    } else {
        ExFreePoolWithTag(entry, MSMON_POOL_TAG);
        KeReleaseMutex(&gRootMutex, FALSE);
        return STATUS_NOT_FOUND;
    }

    KeAcquireSpinLock(&gProcessLock, &oldIrql);
    for (link = gProcesses.Flink; link != &gProcesses; link = link->Flink) {
        existing = CONTAINING_RECORD(link, MSMON_PROCESS_ENTRY, Link);
        if (existing->ProcessId == ProcessId) {
            if (existing->StartTime == entry->StartTime) {
                duplicate = TRUE;
            } else {
                RemoveEntryList(&existing->Link);
                stale = existing;
                InterlockedDecrement(&gProcessCount);
            }
            break;
        }
    }
    if (!duplicate) {
        InsertTailList(&gProcesses, &entry->Link);
        InterlockedIncrement(&gProcessCount);
    }
    KeReleaseSpinLock(&gProcessLock, oldIrql);
    KeReleaseMutex(&gRootMutex, FALSE);
    if (stale != NULL) ExFreePoolWithTag(stale, MSMON_POOL_TAG);
    if (duplicate) ExFreePoolWithTag(entry, MSMON_POOL_TAG);
    return status;
}

BOOLEAN MsMonIsTracked(HANDLE ProcessId, LONGLONG StartTime)
{
    PLIST_ENTRY link;
    KIRQL oldIrql;
    BOOLEAN found = FALSE;
    KeAcquireSpinLock(&gProcessLock, &oldIrql);
    for (link = gProcesses.Flink; link != &gProcesses; link = link->Flink) {
        PMSMON_PROCESS_ENTRY entry = CONTAINING_RECORD(link, MSMON_PROCESS_ENTRY, Link);
        if (entry->ProcessId == ProcessId &&
            (StartTime == 0 || entry->StartTime == 0 || entry->StartTime == StartTime)) {
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&gProcessLock, oldIrql);
    return found;
}

LONGLONG MsMonProcessStartTime(HANDLE ProcessId)
{
    PLIST_ENTRY link;
    KIRQL oldIrql;
    LONGLONG startTime = 0;
    KeAcquireSpinLock(&gProcessLock, &oldIrql);
    for (link = gProcesses.Flink; link != &gProcesses; link = link->Flink) {
        PMSMON_PROCESS_ENTRY entry = CONTAINING_RECORD(link, MSMON_PROCESS_ENTRY, Link);
        if (entry->ProcessId == ProcessId) {
            startTime = entry->StartTime;
            break;
        }
    }
    KeReleaseSpinLock(&gProcessLock, oldIrql);
    return startTime;
}

ULONG MsMonTrackedProcessCount(VOID)
{
    return (ULONG)gProcessCount;
}

static VOID MsMonForgetProcess(HANDLE ProcessId, LONGLONG StartTime)
{
    PLIST_ENTRY link;
    KIRQL oldIrql;
    PMSMON_PROCESS_ENTRY removed = NULL;
    KeAcquireSpinLock(&gProcessLock, &oldIrql);
    for (link = gProcesses.Flink; link != &gProcesses; link = link->Flink) {
        PMSMON_PROCESS_ENTRY entry = CONTAINING_RECORD(link, MSMON_PROCESS_ENTRY, Link);
        if (entry->ProcessId == ProcessId && entry->StartTime == StartTime) {
            RemoveEntryList(&entry->Link);
            removed = entry;
            InterlockedDecrement(&gProcessCount);
            break;
        }
    }
    KeReleaseSpinLock(&gProcessLock, oldIrql);
    if (removed != NULL) ExFreePoolWithTag(removed, MSMON_POOL_TAG);
}

static VOID MsMonProcessNotifyInner(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    LONGLONG startTime = PsGetProcessCreateTimeQuadPart(Process);
    ULONG flags;
    NTSTATUS status;

    MsMonCoverageEnter(MSMON_SENSOR_PROCESS_NOTIFY);
    if (CreateInfo == NULL) {
        BOOLEAN tracked = MsMonIsTracked(ProcessId, startTime);
        if (tracked || MsMonCurrentIsBlackCat()) {
            (VOID)MsMonLogEvent(MsMonProcessExit, ProcessId, startTime, NULL, NULL, NULL, 0, 0,
                                STATUS_SUCCESS, 0, MsMonCategoryExternalProcess,
                                (ULONGLONG)startTime, 0, NULL, NULL);
            MsMonCoverageLogged(MSMON_SENSOR_PROCESS_NOTIFY);
        }
        if (tracked) MsMonForgetProcess(ProcessId, startTime);
        return;
    }
    if (!NT_SUCCESS(CreateInfo->CreationStatus)) {
        /*
         * A driver called before this one (kfilter) refused the creation: the
         * process never runs. Record the refusal with its status when it is in
         * scope, and drop any tracking the image notify started. A refusal by a
         * driver called after this one is not visible here.
         */
        if (MsMonIsTracked(CreateInfo->ParentProcessId, 0) || MsMonIsTracked(ProcessId, startTime) ||
            MsMonProcessImageUnderRoot(Process, CreateInfo->ImageFileName) || MsMonCurrentIsBlackCat()) {
            MsMonForgetProcess(ProcessId, startTime);
            (VOID)MsMonLogEvent(MsMonProcessStart, ProcessId, startTime, CreateInfo->ParentProcessId, NULL, NULL, 0,
                                0, CreateInfo->CreationStatus, 0, MsMonCategoryExternalProcess,
                                (ULONGLONG)startTime, 0, CreateInfo->ImageFileName, CreateInfo->CommandLine);
            MsMonCoverageLogged(MSMON_SENSOR_PROCESS_NOTIFY);
        }
        return;
    }
    if (MsMonIsTracked(CreateInfo->ParentProcessId, 0)) {
        flags = MsMonFlagInheritedTrack;
    } else if (MsMonIsTracked(ProcessId, startTime) ||
               MsMonProcessImageUnderRoot(Process, CreateInfo->ImageFileName)) {
        /* Already tracked when MsMonImageNotify saw the executable map. */
        flags = MsMonFlagExplicitTrack;
    } else if (MsMonCurrentIsBlackCat()) {
        /*
         * A process created by BlackCat is part of the observed application
         * tree.  Log it and add it to the tracked set so its later file,
         * registry, network, and handle events are not lost.
         */
        flags = MsMonFlagExplicitTrack;
        status = MsMonTrackProcess(ProcessId, flags, 0);
        if (!NT_SUCCESS(status)) {
            MsMonCoverageSkip(MSMON_SKIP_TRACK);
            MsMonEventsNoteDropped();
            return;
        }
        (VOID)MsMonLogEvent(MsMonProcessStart, ProcessId, startTime, CreateInfo->ParentProcessId, NULL, NULL, 0,
                            flags, STATUS_SUCCESS, 0, MsMonCategoryExternalProcess,
                            (ULONGLONG)startTime, 0, CreateInfo->ImageFileName, CreateInfo->CommandLine);
        MsMonCoverageLogged(MSMON_SENSOR_PROCESS_NOTIFY);
        return;
    } else {
        return;
    }
    status = MsMonTrackProcess(ProcessId, flags, 0);
    if (!NT_SUCCESS(status)) {
        MsMonCoverageSkip(MSMON_SKIP_TRACK);
        MsMonEventsNoteDropped();
        return;
    }
    (VOID)MsMonLogEvent(MsMonProcessStart, ProcessId, startTime, CreateInfo->ParentProcessId, NULL, NULL, 0,
                        flags, STATUS_SUCCESS, 0, MsMonCategoryExternalProcess,
                        (ULONGLONG)startTime, 0, CreateInfo->ImageFileName, CreateInfo->CommandLine);
    MsMonCoverageLogged(MSMON_SENSOR_PROCESS_NOTIFY);
}

static VOID MsMonProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    if (!ExAcquireRundownProtection(&gCallbackRundown)) return;
    MsMonProcessNotifyInner(Process, ProcessId, CreateInfo);
    ExReleaseRundownProtection(&gCallbackRundown);
}

static VOID MsMonThreadNotify(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create)
{
    LONGLONG startTime = MsMonProcessStartTime(ProcessId);
    if (!ExAcquireRundownProtection(&gCallbackRundown)) return;
    MsMonCoverageEnter(MSMON_SENSOR_THREAD_NOTIFY);
    if (MsMonIsTracked(ProcessId, 0) || MsMonCurrentIsBlackCat()) {
        (VOID)MsMonLogEvent(Create ? MsMonThreadStart : MsMonThreadExit,
                            ProcessId, startTime, NULL, ThreadId, NULL, 0, 0, STATUS_SUCCESS, 0,
                            MsMonCategoryUnknown, 0, 0, NULL, NULL);
        MsMonCoverageLogged(MSMON_SENSOR_THREAD_NOTIFY);
    }
    ExReleaseRundownProtection(&gCallbackRundown);
}

/*
 * Windows build 26200 delivers the process-create callback before the new
 * process's executable and ntdll.dll image loads, but that order is not
 * documented.  If an image load arrives first, start tracking the client
 * there so those records are not skipped; the create callback then finds it
 * tracked and logs the process start.  Only a
 * process whose own image is under the root qualifies, so an unrelated process
 * that maps a DLL from the client directory is not pulled in.
 */
static VOID MsMonTrackClientAtFirstImage(PCUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
    PEPROCESS process = NULL;
    if (!gSessionActive || ProcessId == NULL || ImageInfo->SystemModeImage) return;
    if (!MsMonImageUnderRoot(FullImageName)) return;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &process))) return;
    if (MsMonProcessImageUnderRoot(process, NULL) &&
        !NT_SUCCESS(MsMonTrackProcess(ProcessId, MsMonFlagExplicitTrack, 0))) {
        MsMonCoverageSkip(MSMON_SKIP_TRACK);
        MsMonEventsNoteDropped();
    }
    ObDereferenceObject(process);
}

static VOID MsMonImageNotify(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
    if (!ExAcquireRundownProtection(&gCallbackRundown)) return;
    MsMonCoverageEnter(MSMON_SENSOR_IMAGE_NOTIFY);
    if (ImageInfo->SystemModeImage) {
        MsMonAttributionNoteImage(FullImageName, ImageInfo->ImageBase, ImageInfo->ImageSize);
    } else if (!MsMonIsTracked(ProcessId, 0)) {
        MsMonTrackClientAtFirstImage(FullImageName, ProcessId, ImageInfo);
    }
    if (MsMonIsTracked(ProcessId, 0) || MsMonCurrentIsBlackCat()) {
        /* Read the start after the admission above: MsMonProcessStartTime only
         * knows tracked processes, so an image that arrives before the
         * process-start record would otherwise be logged with start 0 and then
         * discarded by the agent's early-image merge. */
        (VOID)MsMonLogEvent(MsMonImageLoad, ProcessId, MsMonProcessStartTime(ProcessId),
                            NULL, NULL, NULL, 0, 0,
                            STATUS_SUCCESS, 0, MsMonCategoryUnknown,
                            (ULONGLONG)ImageInfo->ImageBase, ImageInfo->ImageSize, FullImageName, NULL);
        MsMonCoverageLogged(MSMON_SENSOR_IMAGE_NOTIFY);
    }
    ExReleaseRundownProtection(&gCallbackRundown);
}

static VOID MsMonProcessNotifyLegacy(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create)
{
    PEPROCESS process = NULL;
    if (!ExAcquireRundownProtection(&gCallbackRundown)) return;
    if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &process))) {
        if (Create) {
            PUNICODE_STRING imageName = NULL;
            if (NT_SUCCESS(SeLocateProcessImageName(process, &imageName))) {
                PS_CREATE_NOTIFY_INFO info;
                RtlZeroMemory(&info, sizeof(info));
                info.ParentProcessId = ParentId;
                info.ImageFileName = imageName;
                MsMonProcessNotifyInner(process, ProcessId, &info);
                ExFreePool(imageName);
            } else {
                /*
                 * A create whose image name cannot be resolved is still a
                 * create: passing NULL would be read as an exit, emitting a
                 * bogus process_exit and untracking the process. Report the
                 * create without a path instead (the inner routine accepts a
                 * NULL ImageFileName).
                 */
                PS_CREATE_NOTIFY_INFO info;
                RtlZeroMemory(&info, sizeof(info));
                info.ParentProcessId = ParentId;
                MsMonProcessNotifyInner(process, ProcessId, &info);
            }
        } else {
            MsMonProcessNotifyInner(process, ProcessId, NULL);
        }
        ObDereferenceObject(process);
    }
    ExReleaseRundownProtection(&gCallbackRundown);
}

static VOID MsMonRemoveProcessNotify(VOID)
{
    if (!gProcessNotifyRegistered) return;
    if (gProcessNotifyEx) {
        (VOID)PsSetCreateProcessNotifyRoutineEx(MsMonProcessNotify, TRUE);
    } else {
        (VOID)PsSetCreateProcessNotifyRoutine(MsMonProcessNotifyLegacy, TRUE);
    }
    gProcessNotifyRegistered = FALSE;
}

NTSTATUS MsMonProcessInitialize(VOID)
{
    NTSTATUS status;
    InitializeListHead(&gProcesses);
    KeInitializeSpinLock(&gProcessLock);
    KeInitializeMutex(&gRootMutex, 0);
    gProcessCount = 0;
    RtlZeroMemory(gRoots, sizeof(gRoots));
    gRootCount = 0;
    gSessionActive = FALSE;
    gProcessNotifyEx = FALSE;
    gProcessNotifyRegistered = FALSE;
    gThreadNotifyRegistered = FALSE;
    gImageNotifyRegistered = FALSE;
    gCallbackRundownInitialized = TRUE;
    gProcessInitialized = TRUE;
    ExInitializeRundownProtection(&gCallbackRundown);
    status = PsSetCreateProcessNotifyRoutineEx(MsMonProcessNotify, FALSE);
    if (NT_SUCCESS(status)) {
        gProcessNotifyEx = TRUE;
        gProcessNotifyRegistered = TRUE;
    } else {
        status = PsSetCreateProcessNotifyRoutine(MsMonProcessNotifyLegacy, FALSE);
        if (!NT_SUCCESS(status)) {
            MsMonCoverageRegister(MSMON_SENSOR_REG_PROCESS_NOTIFY, status);
            return status;
        }
        gProcessNotifyRegistered = TRUE;
    }
    MsMonCoverageRegister(MSMON_SENSOR_REG_PROCESS_NOTIFY, status);
    status = PsSetCreateThreadNotifyRoutine(MsMonThreadNotify);
    if (!NT_SUCCESS(status)) {
        MsMonCoverageRegister(MSMON_SENSOR_REG_THREAD_NOTIFY, status);
        MsMonRemoveProcessNotify();
        return status;
    }
    MsMonCoverageRegister(MSMON_SENSOR_REG_THREAD_NOTIFY, status);
    gThreadNotifyRegistered = TRUE;
    return STATUS_SUCCESS;
}

NTSTATUS MsMonImageInitialize(VOID)
{
    NTSTATUS status = PsSetLoadImageNotifyRoutine(MsMonImageNotify);
    gImageNotifyRegistered = NT_SUCCESS(status);
    MsMonCoverageRegister(MSMON_SENSOR_REG_IMAGE_NOTIFY, status);
    MsMonRecordStatus(L"ImageRegisterStatus", status);
    return status;
}

VOID MsMonProcessUninitialize(VOID)
{
    /*
     * MsMonProcessInitialize may never have run if an earlier driver
     * initialisation step failed; the list, mutex and spin lock would still be
     * zeroed memory and must not be touched.
     */
    if (!gProcessInitialized) return;
    MsMonRecordStatus(L"ProcessUninitializeStart", STATUS_SUCCESS);
    if (gImageNotifyRegistered) {
        /*
         * Image-notify routines are removed with PsRemoveLoadImageNotifyRoutine.
         * The previous code called PsSetLoadImageNotifyRoutine again, which only
         * fails (the routine is already registered) and leaves a pointer to this
         * driver in the kernel's notify list after the image is unloaded. The
         * next image load anywhere in the system then jumps into unmapped code
         * and bugchecks.
         */
        NTSTATUS removeStatus = PsRemoveLoadImageNotifyRoutine(MsMonImageNotify);
        gImageNotifyRegistered = FALSE;
        MsMonRecordStatus(L"ImageRemoveStatus", removeStatus);
    } else {
        MsMonRecordStatus(L"ImageRemoveStatus", STATUS_PROCEDURE_NOT_FOUND);
    }
    if (gThreadNotifyRegistered) {
        (VOID)PsRemoveCreateThreadNotifyRoutine(MsMonThreadNotify);
        gThreadNotifyRegistered = FALSE;
    }
    MsMonRemoveProcessNotify();
    if (gCallbackRundownInitialized) {
        /*
         * The wait refuses new callback acquisitions and drains the callbacks
         * already running; ExRundownCompleted must follow it and only then is
         * the rundown state final.
         */
        ExWaitForRundownProtectionRelease(&gCallbackRundown);
        ExRundownCompleted(&gCallbackRundown);
        gCallbackRundownInitialized = FALSE;
    }
    MsMonRecordStatus(L"RundownComplete", STATUS_SUCCESS);
    MsMonProcessStopSession();
}
