#include "msmon.h"
#include <wdmsec.h>

static const GUID MSMON_DEVICE_GUID = { 0xdb6a8ad5, 0xc08e, 0x4f95, { 0x8d, 0x15, 0x11, 0x5a, 0x72, 0x13, 0x6d, 0x40 } };

/*
 * Control IRPs can block inside the driver (MSMON_IOCTL_READ_EVENTS waits for
 * events). DriverUnload must not return while one of those is still executing
 * our code, so every dispatch takes a rundown reference and unload refuses new
 * acquisitions, waits for the ones in flight, then marks the rundown complete.
 */
static EX_RUNDOWN_REF gIoRundown;
static KMUTEX gSessionMutex;

static NTSTATUS MsMonCompleteIrp(PIRP Irp, NTSTATUS Status, ULONG_PTR Information)
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

static NTSTATUS MsMonCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    if (!ExAcquireRundownProtection(&gIoRundown)) {
        return MsMonCompleteIrp(Irp, STATUS_DELETE_PENDING, 0);
    }
    ExReleaseRundownProtection(&gIoRundown);
    return MsMonCompleteIrp(Irp, STATUS_SUCCESS, 0);
}

static NTSTATUS MsMonStartSession(PMSMON_SESSION_CONFIG Config, ULONG InputLength)
{
    UNICODE_STRING roots[1 + MSMON_EXTRA_ROOTS];
    ULONG rootCount = 0;
    ULONG index;
    NTSTATUS status;
    SIZE_T length;

    (VOID)KeWaitForSingleObject(&gSessionMutex, Executive, KernelMode, FALSE, NULL);
    length = wcsnlen(Config->ClientRoot, MSMON_CLIENT_PATH_CHARS);
    if (length == 0 || length == MSMON_CLIENT_PATH_CHARS) {
        status = STATUS_INVALID_PARAMETER;
        goto Done;
    }
    roots[rootCount].Buffer = Config->ClientRoot;
    roots[rootCount].Length = (USHORT)(length * sizeof(WCHAR));
    roots[rootCount].MaximumLength = roots[rootCount].Length;
    rootCount++;
    /* Agents built before ExtraRoots existed send the structure without it. */
    if (InputLength >= sizeof(MSMON_SESSION_CONFIG)) {
        for (index = 0; index < MSMON_EXTRA_ROOTS; index++) {
            length = wcsnlen(Config->ExtraRoots[index], MSMON_CLIENT_PATH_CHARS);
            if (length == MSMON_CLIENT_PATH_CHARS) {
                status = STATUS_INVALID_PARAMETER;
                goto Done;
            }
            if (length == 0) continue;
            roots[rootCount].Buffer = Config->ExtraRoots[index];
            roots[rootCount].Length = (USHORT)(length * sizeof(WCHAR));
            roots[rootCount].MaximumLength = roots[rootCount].Length;
            rootCount++;
        }
    }
    MsMonProcessStopSession();
    MsMonEventsStop();
    status = MsMonEventsStart(Config->SessionId, Config->QueueRecords, Config->QueueBytes, Config->PayloadMode);
    if (!NT_SUCCESS(status)) goto Done;
    status = MsMonProcessStartSession(roots, rootCount);
    if (NT_SUCCESS(status)) status = MsMonAttributionRefresh();
    if (NT_SUCCESS(status) && !MsMonObjectAvailable()) {
        UNICODE_STRING text;
        UNICODE_STRING detail;
        RtlInitUnicodeString(&text, L"object_callbacks_unavailable");
        RtlInitUnicodeString(&detail, L"Process and thread handle events are disabled; status is in value0");
        (VOID)MsMonLogEvent(MsMonCoverage, PsGetCurrentProcessId(), MsMonProcessStartTime(PsGetCurrentProcessId()), NULL, PsGetCurrentThreadId(),
                            NULL, 0, MsMonFlagObserverRecord, STATUS_SUCCESS, 0,
                            MsMonCategoryUnknown, (ULONG)MsMonObjectStatus(), 0, &text, &detail);
    }
    if (NT_SUCCESS(status) && MsMonNetworkCoverage() != 0x3f) {
        UNICODE_STRING text;
        UNICODE_STRING detail;
        RtlInitUnicodeString(&text, MsMonNetworkAvailable() ? L"network_callbacks_partial" : L"network_callbacks_unavailable");
        RtlInitUnicodeString(&detail, L"WFP layer availability bitmask is in value0; other monitoring remains active");
        (VOID)MsMonLogEvent(MsMonCoverage, PsGetCurrentProcessId(), MsMonProcessStartTime(PsGetCurrentProcessId()), NULL, PsGetCurrentThreadId(),
                            NULL, 0, MsMonFlagObserverRecord, STATUS_SUCCESS, 0,
                            MsMonCategoryUnknown, MsMonNetworkCoverage(), 0, &text, &detail);
    }
    if (!NT_SUCCESS(status)) {
        MsMonProcessStopSession();
        MsMonEventsStop();
    }
Done:
    KeReleaseMutex(&gSessionMutex, FALSE);
    return status;
}

static NTSTATUS MsMonDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG inputLength = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outputLength = stack->Parameters.DeviceIoControl.OutputBufferLength;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR information = 0;

    UNREFERENCED_PARAMETER(DeviceObject);
    if (!ExAcquireRundownProtection(&gIoRundown)) {
        return MsMonCompleteIrp(Irp, STATUS_DELETE_PENDING, 0);
    }
    MsMonCoverageEnter(MSMON_SENSOR_IOCTL_DISPATCH);
    switch (code) {
    case MSMON_IOCTL_START_SESSION:
        if (inputLength < (ULONG)FIELD_OFFSET(MSMON_SESSION_CONFIG, ExtraRoots)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        status = MsMonStartSession((PMSMON_SESSION_CONFIG)Irp->AssociatedIrp.SystemBuffer, inputLength);
        break;
    case MSMON_IOCTL_STOP_SESSION:
        (VOID)KeWaitForSingleObject(&gSessionMutex, Executive, KernelMode, FALSE, NULL);
        MsMonAttributionStop();
        MsMonProcessStopSession();
        MsMonEventsStop();
        KeReleaseMutex(&gSessionMutex, FALSE);
        status = STATUS_SUCCESS;
        break;
    case MSMON_IOCTL_STOP_TRACKING:
        (VOID)KeWaitForSingleObject(&gSessionMutex, Executive, KernelMode, FALSE, NULL);
        MsMonAttributionStop();
        MsMonProcessStopSession();
        KeReleaseMutex(&gSessionMutex, FALSE);
        status = STATUS_SUCCESS;
        break;
    case MSMON_IOCTL_REFRESH_MODULES:
        status = MsMonAttributionRefresh();
        break;
    case MSMON_IOCTL_TRACK_PID: {
        PMSMON_TRACK_REQUEST request = (PMSMON_TRACK_REQUEST)Irp->AssociatedIrp.SystemBuffer;
        LONGLONG validatedStart;
        if (inputLength < sizeof(*request)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        status = MsMonTrackProcess(UlongToHandle(request->ProcessId),
                                   request->Flags != 0 ? request->Flags : MsMonFlagExplicitTrack,
                                   (LONGLONG)request->ProcessStartTime);
        if (NT_SUCCESS(status)) {
            /* Log what the driver admitted, not the caller's possibly stale value. */
            validatedStart = MsMonProcessStartTime(UlongToHandle(request->ProcessId));
            (VOID)MsMonLogEvent(MsMonProcessStart, UlongToHandle(request->ProcessId), validatedStart, NULL, NULL,
                                NULL, 0, request->Flags, STATUS_SUCCESS, 0,
                                MsMonCategoryExternalProcess, (ULONGLONG)validatedStart, 0, NULL, NULL);
        }
        break;
    }
    case MSMON_IOCTL_READ_EVENTS: {
        PMSMON_READ_REQUEST request = (PMSMON_READ_REQUEST)Irp->AssociatedIrp.SystemBuffer;
        ULONG maximum = min(outputLength, MSMON_READ_MAX_BYTES);
        ULONG timeout = 500;
        ULONG bytes = 0;
        if (inputLength >= sizeof(*request)) timeout = request->TimeoutMilliseconds;
        if (timeout > 1000) timeout = 1000;
        if (maximum < MSMON_MAX_EVENT_RECORD_BYTES) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        status = MsMonReadEvents(Irp->AssociatedIrp.SystemBuffer, maximum, timeout, &bytes);
        information = bytes;
        break;
    }
    case MSMON_IOCTL_STATISTICS:
        if (outputLength < sizeof(MSMON_STATISTICS)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        MsMonGetStatistics((PMSMON_STATISTICS)Irp->AssociatedIrp.SystemBuffer);
        information = sizeof(MSMON_STATISTICS);
        status = STATUS_SUCCESS;
        break;
    case MSMON_IOCTL_COVERAGE:
        if (outputLength < sizeof(MSMON_COVERAGE)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        MsMonGetCoverage((PMSMON_COVERAGE)Irp->AssociatedIrp.SystemBuffer);
        information = sizeof(MSMON_COVERAGE);
        status = STATUS_SUCCESS;
        break;
    default:
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    ExReleaseRundownProtection(&gIoRundown);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

VOID MsMonDriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING dosName;
    MsMonRecordStatus(L"DriverUnloadStart", STATUS_SUCCESS);

    /*
     * Wake a collector that is blocked in MSMON_IOCTL_READ_EVENTS first: it
     * holds a rundown reference and would otherwise make the wait below sit out
     * its read timeout, which can be one second.
     */
    MsMonEventsWakeAll();

    /*
     * Drain the control plane before any sensor is torn down. A control IRP
     * already inside MsMonStartSession would otherwise re-arm the event queue
     * and the process session (allocating roots in MsMonProcessStartSession)
     * after MsMonProcessUninitialize has stopped and freed that state. Once the
     * rundown is complete the acquire in MsMonDeviceControl fails, so a later
     * START_SESSION, TRACK, STOP or READ gets STATUS_DELETE_PENDING instead of
     * running against half-freed state. ExRundownCompleted must follow the wait.
     */
    ExWaitForRundownProtectionRelease(&gIoRundown);
    ExRundownCompleted(&gIoRundown);

    MsMonNetworkUninitialize();
    MsMonRecordStatus(L"NetworkStopped", STATUS_SUCCESS);
    MsMonRegistryUninitialize();
    MsMonRecordStatus(L"RegistryStopped", STATUS_SUCCESS);
    MsMonFileFilterUninitialize();
    MsMonRecordStatus(L"FileFilterStopped", STATUS_SUCCESS);
    MsMonObjectUninitialize();
    MsMonRecordStatus(L"ObjectStopped", STATUS_SUCCESS);
    MsMonProcessUninitialize();
    MsMonRecordStatus(L"ProcessStopped", STATUS_SUCCESS);
    MsMonAttributionStop();

    MsMonEventsUninitialize();
    RtlInitUnicodeString(&dosName, MSMON_DOS_DEVICE_NAME);
    (VOID)IoDeleteSymbolicLink(&dosName);
    if (DriverObject->DeviceObject != NULL) IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNICODE_STRING deviceName;
    UNICODE_STRING dosName;
    PDEVICE_OBJECT deviceObject = NULL;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);
    ExInitializeRundownProtection(&gIoRundown);
    KeInitializeMutex(&gSessionMutex, 0);
    DriverObject->MajorFunction[IRP_MJ_CREATE] = MsMonCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = MsMonCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MsMonDeviceControl;

    RtlInitUnicodeString(&deviceName, MSMON_DEVICE_NAME);
    RtlInitUnicodeString(&dosName, MSMON_DOS_DEVICE_NAME);
    status = IoCreateDeviceSecure(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN,
                                  FILE_DEVICE_SECURE_OPEN, FALSE,
                                  &SDDL_DEVOBJ_SYS_ALL_ADM_ALL,
                                  &MSMON_DEVICE_GUID, &deviceObject);
    if (!NT_SUCCESS(status)) return status;
    status = IoCreateSymbolicLink(&dosName, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(deviceObject);
        return status;
    }

    status = MsMonAttributionInitialize();
    MsMonCoverageRegister(MSMON_SENSOR_REG_ATTRIBUTION, status);
    if (!NT_SUCCESS(status)) {
        (VOID)IoDeleteSymbolicLink(&dosName);
        IoDeleteDevice(deviceObject);
        return status;
    }
    status = MsMonEventsInitialize();
    if (NT_SUCCESS(status)) status = MsMonProcessInitialize();
    if (NT_SUCCESS(status)) {
        status = MsMonObjectInitialize(DriverObject);
        if (!NT_SUCCESS(status)) {
            DbgPrint("MsMon: ObRegisterCallbacks unavailable; continuing without object events\n");
            status = STATUS_SUCCESS;
        }
    }
    if (NT_SUCCESS(status)) status = MsMonFileFilterInitialize(DriverObject);
    if (NT_SUCCESS(status)) status = MsMonRegistryInitialize(DriverObject);
    if (NT_SUCCESS(status)) {
        status = MsMonNetworkInitialize(deviceObject);
        if (!NT_SUCCESS(status)) {
            DbgPrint("MsMon: WFP initialization failed 0x%08X; continuing without network events\n", status);
            status = STATUS_SUCCESS;
        }
    }
    if (NT_SUCCESS(status)) status = MsMonImageInitialize();
    if (!NT_SUCCESS(status)) {
        MsMonNetworkUninitialize();
        MsMonRegistryUninitialize();
        MsMonFileFilterUninitialize();
        MsMonObjectUninitialize();
        MsMonProcessUninitialize();
        MsMonEventsUninitialize();
        (VOID)IoDeleteSymbolicLink(&dosName);
        IoDeleteDevice(deviceObject);
        return status;
    }

    deviceObject->Flags |= DO_BUFFERED_IO;
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    DriverObject->DriverUnload = MsMonDriverUnload;
    return STATUS_SUCCESS;
}
