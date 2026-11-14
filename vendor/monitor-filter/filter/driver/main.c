#include "kf.h"
#include <wdmsec.h>

/*
 * Driver entry, control device and lifetime.
 *
 * The device is administrator-only. The driver never reads a policy from disk;
 * the control tool parses and validates it and sends a complete generation.
 */

static const GUID KFILTER_DEVICE_GUID = { 0x8a1c4f52, 0x2d7b, 0x4f0e, { 0x9c, 0x31, 0x6e, 0x52, 0xb4, 0x0d, 0x77, 0x21 } };

static EX_RUNDOWN_REF gIoRundown;
static ULONG gRegisteredMask;
static ULONG64 gSessionTag;
static PDEVICE_OBJECT gControlDevice;

ULONG KfDriverRegisteredMask(VOID)
{
    ULONG mask = gRegisteredMask;

    /*
     * PASSIVE_LEVEL only: KfDiskAvailable takes the disk mutex. Both callers
     * (configuration validation and the status IRP) run on control requests.
     */
    if (KfDiskAvailable()) mask |= KFILTER_REG_DISK;
    else mask &= ~KFILTER_REG_DISK;
    if (KfDeviceAvailable()) mask |= KFILTER_REG_DEVICE;
    else mask &= ~KFILTER_REG_DEVICE;
    if (KfDeviceNsiAttached()) mask |= KFILTER_REG_NSI;
    else mask &= ~KFILTER_REG_NSI;
    return mask;
}

static NTSTATUS KfCompleteIrp(PIRP Irp, NTSTATUS Status, ULONG_PTR Information)
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

static NTSTATUS KfDispatchPass(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    if (KfDiskIsFilterDevice(DeviceObject)) return KfDiskDispatch(DeviceObject, Irp);
    if (KfDeviceIsFilterDevice(DeviceObject)) return KfDeviceDispatch(DeviceObject, Irp);
    return KfCompleteIrp(Irp, STATUS_INVALID_DEVICE_REQUEST, 0);
}

static NTSTATUS KfCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    if (KfDiskIsFilterDevice(DeviceObject)) return KfDiskDispatch(DeviceObject, Irp);
    if (KfDeviceIsFilterDevice(DeviceObject)) return KfDeviceDispatch(DeviceObject, Irp);
    if (!ExAcquireRundownProtection(&gIoRundown)) {
        return KfCompleteIrp(Irp, STATUS_DELETE_PENDING, 0);
    }
    ExReleaseRundownProtection(&gIoRundown);
    return KfCompleteIrp(Irp, STATUS_SUCCESS, 0);
}

static NTSTATUS KfDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG inputLength = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outputLength = stack->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR information = 0;

    if (KfDiskIsFilterDevice(DeviceObject)) return KfDiskDispatch(DeviceObject, Irp);
    if (KfDeviceIsFilterDevice(DeviceObject)) return KfDeviceDispatch(DeviceObject, Irp);
    if (!ExAcquireRundownProtection(&gIoRundown)) {
        return KfCompleteIrp(Irp, STATUS_DELETE_PENDING, 0);
    }

    switch (code) {
    case KFILTER_IOCTL_GET_STATUS:
        if (buffer == NULL || outputLength < sizeof(KFILTER_STATUS)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        KfPolicyGetStatus((PKFILTER_STATUS)buffer);
        ((PKFILTER_STATUS)buffer)->Registered = KfDriverRegisteredMask();
        ((PKFILTER_STATUS)buffer)->SessionTag = gSessionTag;
        information = sizeof(KFILTER_STATUS);
        status = STATUS_SUCCESS;
        break;

    case KFILTER_IOCTL_SET_CONFIG:
        /* A config carries only its RuleCount rules: KFILTER_CONFIG_SIZE(RuleCount) bytes. */
        if (buffer == NULL || inputLength < KFILTER_CONFIG_SIZE(0)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        status = KfPolicySetConfig((const KFILTER_CONFIG*)buffer, inputLength);
        break;

    case KFILTER_IOCTL_GET_CONFIG: {
        ULONG size;
        if (buffer == NULL) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        size = KfPolicyGetConfig((PKFILTER_CONFIG)buffer, outputLength);
        if (size > outputLength) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        information = size;
        status = STATUS_SUCCESS;
        break;
    }

    case KFILTER_IOCTL_READ_EVENTS: {
        KFILTER_READ_REQUEST request;
        ULONG maximumEvents;
        ULONG count;
        if (buffer == NULL || outputLength < sizeof(KFILTER_EVENT)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        maximumEvents = outputLength / sizeof(KFILTER_EVENT);
        if (maximumEvents > KFILTER_RING_CAPACITY) maximumEvents = KFILTER_RING_CAPACITY;
        if (inputLength >= sizeof(request)) {
            RtlCopyMemory(&request, buffer, sizeof(request));
            if (request.MaximumEvents != 0 && request.MaximumEvents < maximumEvents) {
                maximumEvents = request.MaximumEvents;
            }
        }
        count = KfReadEvents((PKFILTER_EVENT)buffer, maximumEvents);
        information = (ULONG_PTR)count * sizeof(KFILTER_EVENT);
        status = STATUS_SUCCESS;
        break;
    }

    case KFILTER_IOCTL_CLEAR_EVENTS:
        KfClearEvents();
        status = STATUS_SUCCESS;
        break;

    case KFILTER_IOCTL_TRACK_PID: {
        KFILTER_TRACK_REQUEST request;
        if (buffer == NULL || inputLength < sizeof(request)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        RtlCopyMemory(&request, buffer, sizeof(request));
        status = KfProcessTrack(UlongToHandle(request.ProcessId));
        break;
    }

    case KFILTER_IOCTL_ADMIT_PROCESS: {
        KFILTER_ADMIT_REQUEST request;
        if (buffer == NULL || inputLength < sizeof(request)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        RtlCopyMemory(&request, buffer, sizeof(request));
        status = KfProcessAdmit(&request);
        break;
    }

    case KFILTER_IOCTL_REGISTER_LAUNCHER:
        status = KfProcessRegisterLauncher();
        break;

    case KFILTER_IOCTL_ALLOW_LAUNCH: {
        KFILTER_ALLOW_LAUNCH_REQUEST request;
        if (buffer == NULL || inputLength < sizeof(request)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        RtlCopyMemory(&request, buffer, sizeof(request));
        status = KfProcessAllowLaunch(&request);
        break;
    }

    case KFILTER_IOCTL_CLEAR_TRACKING:
        KfProcessClearTracking();
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

VOID KfDriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING dosName;

    UNREFERENCED_PARAMETER(DriverObject);
    gRegisteredMask = 0;

    /*
     * Drain the control plane first. ExWaitForRundownProtectionRelease refuses
     * new acquisitions and waits for control IRPs already inside KfPolicySetConfig
     * (which can call KfDiskRearm) or KfPolicyGetStatus, so no layer is torn down
     * under a live control request. Completing the rundown must follow the wait;
     * policy and event state, which those IRPs also read, are freed last.
     */
    ExWaitForRundownProtectionRelease(&gIoRundown);
    ExRundownCompleted(&gIoRundown);

    KfDeviceUninitialize();
    KfDiskUninitialize();
    KfNetworkUninitialize();
    KfFileUninitialize();
    KfRegistryUninitialize();
    KfObjectUninitialize();
    KfProcessUninitialize();

    KfPolicyUninitialize();
    KfEventsUninitialize();

    RtlInitUnicodeString(&dosName, KFILTER_DOS_NAME);
    (VOID)IoDeleteSymbolicLink(&dosName);
    if (gControlDevice != NULL) {
        IoDeleteDevice(gControlDevice);
        gControlDevice = NULL;
    }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNICODE_STRING deviceName;
    UNICODE_STRING dosName;
    PDEVICE_OBJECT deviceObject = NULL;
    LARGE_INTEGER timestamp;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);
    ExInitializeRundownProtection(&gIoRundown);
    KeQuerySystemTime(&timestamp);
    gSessionTag = (ULONG64)timestamp.QuadPart;
    gRegisteredMask = 0;

    DriverObject->MajorFunction[IRP_MJ_CREATE] = KfCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = KfCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = KfDispatchPass;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = KfDeviceControl;
    DriverObject->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] = KfDispatchPass;
    DriverObject->MajorFunction[IRP_MJ_READ] = KfDispatchPass;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = KfDispatchPass;
    DriverObject->MajorFunction[IRP_MJ_FLUSH_BUFFERS] = KfDispatchPass;
    DriverObject->MajorFunction[IRP_MJ_SHUTDOWN] = KfDispatchPass;
    DriverObject->MajorFunction[IRP_MJ_PNP] = KfDispatchPass;
    DriverObject->MajorFunction[IRP_MJ_POWER] = KfDispatchPass;
    DriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL] = KfDispatchPass;
    DriverObject->MajorFunction[IRP_MJ_FILE_SYSTEM_CONTROL] = KfDispatchPass;

    RtlInitUnicodeString(&deviceName, KFILTER_DEVICE_NAME);
    RtlInitUnicodeString(&dosName, KFILTER_DOS_NAME);
    status = IoCreateDeviceSecure(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN,
                                  FILE_DEVICE_SECURE_OPEN, FALSE, &SDDL_DEVOBJ_SYS_ALL_ADM_ALL,
                                  &KFILTER_DEVICE_GUID, &deviceObject);
    if (!NT_SUCCESS(status)) return status;
    status = IoCreateSymbolicLink(&dosName, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(deviceObject);
        return status;
    }

    status = KfEventsInitialize();
    if (!NT_SUCCESS(status)) goto Failed;
    status = KfPolicyInitialize();
    if (!NT_SUCCESS(status)) goto Failed;
    status = KfProcessInitialize();
    if (!NT_SUCCESS(status)) goto Failed;
    gRegisteredMask |= KFILTER_REG_PROCESS;

    if (NT_SUCCESS(KfObjectInitialize(DriverObject))) {
        gRegisteredMask |= KFILTER_REG_OBJECT;
    } else {
        DbgPrint("kfilter: object callbacks unavailable\n");
    }
    if (NT_SUCCESS(KfRegistryInitialize(DriverObject))) {
        gRegisteredMask |= KFILTER_REG_REGISTRY;
    } else {
        DbgPrint("kfilter: registry callback unavailable\n");
    }
    status = KfFileInitialize(DriverObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("kfilter: minifilter registration failed 0x%08X\n", status);
        goto Failed;
    }
    gRegisteredMask |= KFILTER_REG_MINIFILTER;

    gControlDevice = deviceObject;
    (VOID)KfDiskInitialize(DriverObject);
    if (KfDiskAvailable()) gRegisteredMask |= KFILTER_REG_DISK;
    (VOID)KfDeviceInitialize(DriverObject);
    if (KfDeviceAvailable()) gRegisteredMask |= KFILTER_REG_DEVICE;
    (VOID)KfNetworkInitialize(deviceObject);
    if (KfNetworkAvailable()) gRegisteredMask |= KFILTER_REG_NETWORK;

    deviceObject->Flags |= DO_BUFFERED_IO;
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    DriverObject->DriverUnload = KfDriverUnload;
    return STATUS_SUCCESS;

Failed:
    KfDeviceUninitialize();
    KfDiskUninitialize();
    KfNetworkUninitialize();
    KfFileUninitialize();
    KfRegistryUninitialize();
    KfObjectUninitialize();
    KfProcessUninitialize();
    KfPolicyUninitialize();
    KfEventsUninitialize();
    (VOID)IoDeleteSymbolicLink(&dosName);
    IoDeleteDevice(deviceObject);
    return status;
}
