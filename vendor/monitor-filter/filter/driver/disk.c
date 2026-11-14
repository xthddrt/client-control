#include "kf.h"
#include <ntddstor.h>
#include <ntddvol.h>
#include <wdmguid.h>

/*
 * Raw disk and volume device filter.
 *
 * A minifilter never sees opens of \Device\HarddiskN\DR0 or the storage IOCTLs
 * sent to a volume device. This module attaches a small upper filter to every
 * disk and volume device that exists now or arrives later (PnP device-interface
 * notification), uses a global rundown reference plus a per-device
 * IO_REMOVE_LOCK for in-flight IRPs, and sends every protected-process create,
 * device-control, internal-device-control and filesystem-control request
 * through the device rules with the raw-device right.
 */

#define KFILTER_MAX_DISK_FILTERS 48u
#define KFILTER_DISK_MAGIC 0x4B46444Bu

typedef struct _KF_DISK_EXTENSION {
    ULONG Magic;
    IO_REMOVE_LOCK RemoveLock;
    PDEVICE_OBJECT Device;
    PDEVICE_OBJECT Target;
    PDEVICE_OBJECT Self;
    BOOLEAN Removed;
    WCHAR Name[KFILTER_MAX_NAME];
} KF_DISK_EXTENSION, *PKF_DISK_EXTENSION;

static PKF_DISK_EXTENSION gDiskFilters[KFILTER_MAX_DISK_FILTERS];
static KMUTEX gDiskLock;
static KMUTEX gDiskRearmLock;
static PDRIVER_OBJECT gDiskDriver;
static PVOID gDiskNotification;
static PVOID gVolumeNotification;
static EX_RUNDOWN_REF gDiskRundown;
static BOOLEAN gDiskRundownInitialized;
static volatile LONG gDiskAttachFailures;

static NTSTATUS KfCompleteDiskIrp(PIRP Irp, NTSTATUS Status)
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

BOOLEAN KfDiskIsFilterDevice(PDEVICE_OBJECT DeviceObject)
{
    PKF_DISK_EXTENSION extension;
    if (DeviceObject == NULL || DeviceObject->DeviceExtension == NULL) return FALSE;
    extension = (PKF_DISK_EXTENSION)DeviceObject->DeviceExtension;
    return extension->Magic == KFILTER_DISK_MAGIC;
}

/* Event paths and device rules want \Device\HarddiskVolumeN, not the \??\
 * symbolic link the interface notification reports. */
static VOID KfDeviceName(PDEVICE_OBJECT Target, PWSTR Buffer)
{
    POBJECT_NAME_INFORMATION information = NULL;
    ULONG needed = 0;

    Buffer[0] = L'\0';
    if (Target == NULL) return;
    if (NT_SUCCESS(ObQueryNameString(Target, NULL, 0, &needed)) || needed == 0) return;
    information = ExAllocatePool2(POOL_FLAG_NON_PAGED, needed, KFILTER_POOL_TAG);
    if (information == NULL) return;
    if (NT_SUCCESS(ObQueryNameString(Target, information, needed, &needed)) &&
        information->Name.Buffer != NULL) {
        ULONG characters = information->Name.Length / sizeof(WCHAR);
        if (characters >= KFILTER_MAX_NAME) characters = KFILTER_MAX_NAME - 1;
        RtlCopyMemory(Buffer, information->Name.Buffer, (SIZE_T)characters * sizeof(WCHAR));
        Buffer[characters] = L'\0';
    }
    ExFreePoolWithTag(information, KFILTER_POOL_TAG);
}

static NTSTATUS KfDiskAttachTarget(PDEVICE_OBJECT Target)
{
    PDEVICE_OBJECT filter = NULL;
    PDEVICE_OBJECT attached;
    PKF_DISK_EXTENSION extension;
    NTSTATUS status;
    LONG index;

    if (Target == NULL) return STATUS_INVALID_PARAMETER;
    if (KfDiskIsFilterDevice(Target)) return STATUS_SUCCESS;
    (VOID)KeWaitForSingleObject(&gDiskLock, Executive, KernelMode, FALSE, NULL);
    for (index = 0; index < KFILTER_MAX_DISK_FILTERS; index++) {
        if (gDiskFilters[index] != NULL && gDiskFilters[index]->Device == Target) {
            KeReleaseMutex(&gDiskLock, FALSE);
            return STATUS_SUCCESS;
        }
    }
    for (index = 0; index < KFILTER_MAX_DISK_FILTERS && gDiskFilters[index] != NULL; index++);
    if (index == KFILTER_MAX_DISK_FILTERS) {
        KeReleaseMutex(&gDiskLock, FALSE);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    status = IoCreateDevice(gDiskDriver, sizeof(KF_DISK_EXTENSION), NULL,
                            Target->DeviceType, Target->Characteristics, FALSE, &filter);
    if (!NT_SUCCESS(status)) {
        KeReleaseMutex(&gDiskLock, FALSE);
        return status;
    }
    extension = (PKF_DISK_EXTENSION)filter->DeviceExtension;
    RtlZeroMemory(extension, sizeof(*extension));
    extension->Magic = KFILTER_DISK_MAGIC;
    extension->Device = Target;
    extension->Target = Target;
    extension->Self = filter;
    IoInitializeRemoveLock(&extension->RemoveLock, KFILTER_POOL_TAG, 0, 0);
    KfDeviceName(Target, extension->Name);
    filter->Flags |= Target->Flags & (DO_BUFFERED_IO | DO_DIRECT_IO | DO_POWER_PAGABLE | DO_POWER_INRUSH);
    filter->StackSize = Target->StackSize + 1;
    attached = IoAttachDeviceToDeviceStack(filter, Target);
    if (attached == NULL) {
        IoDeleteDevice(filter);
        KeReleaseMutex(&gDiskLock, FALSE);
        return STATUS_UNSUCCESSFUL;
    }
    extension->Target = attached;
    gDiskFilters[index] = extension;
    filter->Flags &= ~DO_DEVICE_INITIALIZING;
    KeReleaseMutex(&gDiskLock, FALSE);
    return STATUS_SUCCESS;
}

static VOID KfDiskRemoveFromList(PKF_DISK_EXTENSION Extension)
{
    LONG index;
    (VOID)KeWaitForSingleObject(&gDiskLock, Executive, KernelMode, FALSE, NULL);
    for (index = 0; index < KFILTER_MAX_DISK_FILTERS; index++) {
        if (gDiskFilters[index] == Extension) {
            gDiskFilters[index] = NULL;
            break;
        }
    }
    KeReleaseMutex(&gDiskLock, FALSE);
}

static NTSTATUS KfDiskInterfaceNotification(PVOID NotificationStructure, PVOID Context)
{
    PDEVICE_INTERFACE_CHANGE_NOTIFICATION notification =
        (PDEVICE_INTERFACE_CHANGE_NOTIFICATION)NotificationStructure;
    PFILE_OBJECT fileObject = NULL;
    PDEVICE_OBJECT target = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(Context);
    if (!ExAcquireRundownProtection(&gDiskRundown)) return STATUS_DELETE_PENDING;
    if (notification != NULL && IsEqualGUID(&notification->Event, &GUID_DEVICE_INTERFACE_ARRIVAL) &&
        notification->SymbolicLinkName != NULL) {
        status = IoGetDeviceObjectPointer(notification->SymbolicLinkName, FILE_READ_ATTRIBUTES,
                                          &fileObject, &target);
        if (NT_SUCCESS(status)) {
            status = KfDiskAttachTarget(target);
            ObDereferenceObject(fileObject);
        }
        if (!NT_SUCCESS(status)) {
            InterlockedIncrement(&gDiskAttachFailures);
            DbgPrint("kfilter: disk/volume attachment failed 0x%08X\n", status);
        }
    }
    ExReleaseRundownProtection(&gDiskRundown);
    return status;
}

/*
 * This filter sits above the file system, so normal file creates, reads and
 * writes also arrive here. They carry the remaining path in the file object and
 * belong to the minifilter; only a handle opened directly on the disk or volume
 * (empty remaining name) is a raw-device request this layer owns.
 */
static BOOLEAN KfDiskRawRequest(PIO_STACK_LOCATION Stack)
{
    if (Stack == NULL || Stack->FileObject == NULL) return FALSE;
    switch (Stack->MajorFunction) {
    case IRP_MJ_CREATE:
    case IRP_MJ_READ:
    case IRP_MJ_WRITE:
    case IRP_MJ_DEVICE_CONTROL:
    case IRP_MJ_INTERNAL_DEVICE_CONTROL:
    case IRP_MJ_FILE_SYSTEM_CONTROL:
        break;
    default:
        return FALSE;
    }
    return Stack->FileObject->FileName.Length == 0;
}

NTSTATUS KfDiskDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PKF_DISK_EXTENSION extension;
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    PDEVICE_OBJECT target;
    NTSTATUS status;

    if (!ExAcquireRundownProtection(&gDiskRundown)) {
        return KfCompleteDiskIrp(Irp, STATUS_DELETE_PENDING);
    }
    extension = KfDiskIsFilterDevice(DeviceObject)
                    ? (PKF_DISK_EXTENSION)DeviceObject->DeviceExtension : NULL;
    if (extension == NULL) {
        ExReleaseRundownProtection(&gDiskRundown);
        return KfCompleteDiskIrp(Irp, STATUS_DEVICE_DOES_NOT_EXIST);
    }
    status = IoAcquireRemoveLock(&extension->RemoveLock, Irp);
    if (!NT_SUCCESS(status)) {
        ExReleaseRundownProtection(&gDiskRundown);
        return KfCompleteDiskIrp(Irp, STATUS_DELETE_PENDING);
    }
    target = extension->Target;
    if (target == NULL) {
        IoReleaseRemoveLock(&extension->RemoveLock, Irp);
        ExReleaseRundownProtection(&gDiskRundown);
        return KfCompleteDiskIrp(Irp, STATUS_DEVICE_DOES_NOT_EXIST);
    }

    if (stack->MajorFunction == IRP_MJ_PNP && stack->MinorFunction == IRP_MN_REMOVE_DEVICE) {
        extension->Removed = TRUE;
        KfDiskRemoveFromList(extension);
        /* Wait for in-flight IRPs before the lower device is removed. */
        IoReleaseRemoveLockAndWait(&extension->RemoveLock, Irp);
        IoSkipCurrentIrpStackLocation(Irp);
        status = IoCallDriver(target, Irp);
        IoDetachDevice(target);
        IoDeleteDevice(DeviceObject);
        ExReleaseRundownProtection(&gDiskRundown);
        return status;
    }

    /* File-system metadata and paging I/O on nameless stream file objects can also
     * run on a protected thread and must never be denied. */
    if (KfDiskDecisionRequired(stack->MajorFunction, (ULONG)Irp->RequestorMode) &&
        !(Irp->Flags & IRP_PAGING_IO) &&
        KfProcessIsProtectedCurrent() && KfPolicyBlockRawDisk() && KfDiskRawRequest(stack)) {
        UNICODE_STRING path;
        UNICODE_STRING value;
        WCHAR valueText[16];
        PCUNICODE_STRING valuePointer = NULL;
        ULONG code = 0;
        ULONG ruleId = 0;
        BOOLEAN nameFailure = FALSE;
        RtlInitUnicodeString(&path, extension->Name);
        if (stack->MajorFunction == IRP_MJ_DEVICE_CONTROL ||
            stack->MajorFunction == IRP_MJ_INTERNAL_DEVICE_CONTROL) {
            code = stack->Parameters.DeviceIoControl.IoControlCode;
        } else if (stack->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL) {
            code = stack->Parameters.FileSystemControl.FsControlCode;
        }
        /* An open and a plain read/write carry code zero; the value is still
         * written so a value=0x00000000 rule can authorize it. */
        (VOID)KfDeviceValueText(code, valueText, RTL_NUMBER_OF(valueText));
        RtlInitUnicodeString(&value, valueText);
        valuePointer = &value;
        if (KfDecideWithRights(KFILTER_TARGET_DEVICE, &path, KFILTER_RIGHT_RAW_DEVICE,
                               valuePointer, 0, &ruleId, &nameFailure, NULL, code)) {
            IoReleaseRemoveLock(&extension->RemoveLock, Irp);
            ExReleaseRundownProtection(&gDiskRundown);
            return KfCompleteDiskIrp(Irp, STATUS_ACCESS_DENIED);
        }
    }

    IoSkipCurrentIrpStackLocation(Irp);
    if (stack->MajorFunction == IRP_MJ_POWER) {
        status = PoCallDriver(target, Irp);
    } else {
        status = IoCallDriver(target, Irp);
    }
    IoReleaseRemoveLock(&extension->RemoveLock, Irp);
    ExReleaseRundownProtection(&gDiskRundown);
    return status;
}

NTSTATUS KfDiskInitialize(PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status;

    RtlZeroMemory(gDiskFilters, sizeof(gDiskFilters));
    KeInitializeMutex(&gDiskLock, 0);
    KeInitializeMutex(&gDiskRearmLock, 0);
    gDiskDriver = DriverObject;
    gDiskNotification = NULL;
    gVolumeNotification = NULL;
    gDiskAttachFailures = 0;
    ExInitializeRundownProtection(&gDiskRundown);
    gDiskRundownInitialized = TRUE;
    status = IoRegisterPlugPlayNotification(EventCategoryDeviceInterfaceChange,
                                            PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES,
                                            (PVOID)&GUID_DEVINTERFACE_DISK, DriverObject,
                                            (PDRIVER_NOTIFICATION_CALLBACK_ROUTINE)KfDiskInterfaceNotification,
                                            NULL, &gDiskNotification);
    if (!NT_SUCCESS(status)) {
        InterlockedIncrement(&gDiskAttachFailures);
        return status;
    }
    status = IoRegisterPlugPlayNotification(EventCategoryDeviceInterfaceChange,
                                            PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES,
                                            (PVOID)&GUID_DEVINTERFACE_VOLUME, DriverObject,
                                            (PDRIVER_NOTIFICATION_CALLBACK_ROUTINE)KfDiskInterfaceNotification,
                                            NULL, &gVolumeNotification);
    if (!NT_SUCCESS(status)) {
        InterlockedIncrement(&gDiskAttachFailures);
        KfDiskUninitialize();
        return status;
    }
    return STATUS_SUCCESS;
}

BOOLEAN KfDiskAvailable(VOID)
{
    LONG index;
    BOOLEAN available = FALSE;

    /* A layer that failed to attach leaves some disk or volume outside the
     * containment boundary; block mode must not claim to cover it. */
    if (InterlockedCompareExchange(&gDiskAttachFailures, 0, 0) != 0) return FALSE;
    (VOID)KeWaitForSingleObject(&gDiskLock, Executive, KernelMode, FALSE, NULL);
    for (index = 0; index < KFILTER_MAX_DISK_FILTERS; index++) {
        if (gDiskFilters[index] != NULL) {
            available = TRUE;
            break;
        }
    }
    KeReleaseMutex(&gDiskLock, FALSE);
    return available;
}

BOOLEAN KfDiskDegraded(VOID)
{
    return InterlockedCompareExchange(&gDiskAttachFailures, 0, 0) != 0;
}

NTSTATUS KfDiskRearm(VOID)
{
    NTSTATUS status;
    LONG previousFailures;

    (VOID)KeWaitForSingleObject(&gDiskRearmLock, Executive, KernelMode, FALSE, NULL);
    if (gDiskDriver == NULL || !gDiskRundownInitialized) {
        KeReleaseMutex(&gDiskRearmLock, FALSE);
        return STATUS_DEVICE_NOT_READY;
    }
    previousFailures = InterlockedCompareExchange(&gDiskAttachFailures, 0, 0);
    if (gDiskNotification != NULL) {
        (VOID)IoUnregisterPlugPlayNotification(gDiskNotification);
        gDiskNotification = NULL;
    }
    if (gVolumeNotification != NULL) {
        (VOID)IoUnregisterPlugPlayNotification(gVolumeNotification);
        gVolumeNotification = NULL;
    }
    status = IoRegisterPlugPlayNotification(EventCategoryDeviceInterfaceChange,
                                            PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES,
                                            (PVOID)&GUID_DEVINTERFACE_DISK, gDiskDriver,
                                            (PDRIVER_NOTIFICATION_CALLBACK_ROUTINE)KfDiskInterfaceNotification,
                                            NULL, &gDiskNotification);
    if (NT_SUCCESS(status)) {
        status = IoRegisterPlugPlayNotification(EventCategoryDeviceInterfaceChange,
                                                PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES,
                                                (PVOID)&GUID_DEVINTERFACE_VOLUME, gDiskDriver,
                                                (PDRIVER_NOTIFICATION_CALLBACK_ROUTINE)KfDiskInterfaceNotification,
                                                NULL, &gVolumeNotification);
    }
    if (!NT_SUCCESS(status)) {
        InterlockedIncrement(&gDiskAttachFailures);
        goto Done;
    }
    if (InterlockedCompareExchange(&gDiskAttachFailures, 0, previousFailures) != previousFailures) {
        status = STATUS_DEVICE_NOT_READY;
        goto Done;
    }
    status = KfDiskAvailable() ? STATUS_SUCCESS : STATUS_DEVICE_NOT_READY;
Done:
    KeReleaseMutex(&gDiskRearmLock, FALSE);
    return status;
}

VOID KfDiskUninitialize(VOID)
{
    LONG index;

    if (gDiskNotification != NULL) {
        (VOID)IoUnregisterPlugPlayNotification(gDiskNotification);
        gDiskNotification = NULL;
    }
    if (gVolumeNotification != NULL) {
        (VOID)IoUnregisterPlugPlayNotification(gVolumeNotification);
        gVolumeNotification = NULL;
    }
    if (gDiskRundownInitialized) {
        ExWaitForRundownProtectionRelease(&gDiskRundown);
        ExRundownCompleted(&gDiskRundown);
        gDiskRundownInitialized = FALSE;
    }
    if (gDiskDriver != NULL) {
        (VOID)KeWaitForSingleObject(&gDiskLock, Executive, KernelMode, FALSE, NULL);
    }
    for (index = 0; index < KFILTER_MAX_DISK_FILTERS; index++) {
        PKF_DISK_EXTENSION extension = gDiskFilters[index];
        if (extension == NULL) continue;
        gDiskFilters[index] = NULL;
        extension->Removed = TRUE;
        /* IoReleaseRemoveLockAndWait needs a matching acquire. The rundown wait
         * above has drained every dispatch, so this succeeds unless the lock is
         * already being removed. */
        if (NT_SUCCESS(IoAcquireRemoveLock(&extension->RemoveLock, extension))) {
            IoReleaseRemoveLockAndWait(&extension->RemoveLock, extension);
        }
        if (extension->Target != NULL) IoDetachDevice(extension->Target);
        IoDeleteDevice(extension->Self);
    }
    if (gDiskDriver != NULL) KeReleaseMutex(&gDiskLock, FALSE);
    /* No rearm may register notifications against the driver object after this. */
    gDiskDriver = NULL;
}
