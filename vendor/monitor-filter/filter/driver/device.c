#include "kf.h"
#include <ndisguid.h>
#include <hidclass.h>
#include <usbiodef.h>
#include <ntddstor.h>
#include <wdmguid.h>

#define KFILTER_DEVICE_MAGIC 0x4B464456u
#define KFILTER_DEVICE_NOTIFICATIONS 4u

static const GUID KF_GUID_DEVINTERFACE_HID = {
    0x4D1E55B2, 0xF16F, 0x11CF, { 0x88, 0xCB, 0x00, 0x11, 0x11, 0x00, 0x00, 0x30 }
};
static const GUID KF_GUID_DEVINTERFACE_USB_DEVICE = {
    0xA5DCBF10, 0x6530, 0x11D2, { 0x90, 0x1F, 0x00, 0xC0, 0x4F, 0xB9, 0x51, 0xED }
};

typedef struct _KF_DEVICE_EXTENSION {
    ULONG Magic;
    IO_REMOVE_LOCK RemoveLock;
    PDEVICE_OBJECT Device;
    PDEVICE_OBJECT Target;
    PDEVICE_OBJECT Self;
    BOOLEAN Removed;
    WCHAR Name[KFILTER_MAX_NAME];
    struct _KF_DEVICE_EXTENSION* Next;
} KF_DEVICE_EXTENSION, *PKF_DEVICE_EXTENSION;

static PKF_DEVICE_EXTENSION gDeviceFilters;
static KMUTEX gDeviceLock;
static PDRIVER_OBJECT gDeviceDriver;
static PVOID gDeviceNotification[KFILTER_DEVICE_NOTIFICATIONS];
static EX_RUNDOWN_REF gDeviceRundown;
static BOOLEAN gDeviceRundownInitialized;
static volatile LONG gDeviceAttachFailures;
static volatile LONG gDeviceNsiReady;
static volatile LONG gDeviceMountReady;

static NTSTATUS KfCompleteDeviceIrp(PIRP Irp, NTSTATUS Status)
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

BOOLEAN KfDeviceIsFilterDevice(PDEVICE_OBJECT DeviceObject)
{
    PKF_DEVICE_EXTENSION extension;
    if (DeviceObject == NULL || DeviceObject->DeviceExtension == NULL) return FALSE;
    extension = (PKF_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    return extension->Magic == KFILTER_DEVICE_MAGIC;
}

static BOOLEAN KfDeviceName(PDEVICE_OBJECT Target, PWSTR Buffer)
{
    POBJECT_NAME_INFORMATION information = NULL;
    ULONG needed = 0;
    BOOLEAN found = FALSE;

    Buffer[0] = L'\0';
    if (Target == NULL) return FALSE;
    if (NT_SUCCESS(ObQueryNameString(Target, NULL, 0, &needed)) || needed == 0) return FALSE;
    information = ExAllocatePool2(POOL_FLAG_NON_PAGED, needed, KFILTER_POOL_TAG);
    if (information == NULL) return FALSE;
    if (NT_SUCCESS(ObQueryNameString(Target, information, needed, &needed)) &&
        information->Name.Buffer != NULL && information->Name.Length != 0) {
        ULONG characters = information->Name.Length / sizeof(WCHAR);
        if (characters >= KFILTER_MAX_NAME) {
            ExFreePoolWithTag(information, KFILTER_POOL_TAG);
            return FALSE;
        }
        RtlCopyMemory(Buffer, information->Name.Buffer, (SIZE_T)characters * sizeof(WCHAR));
        Buffer[characters] = L'\0';
        found = characters != 0;
    }
    ExFreePoolWithTag(information, KFILTER_POOL_TAG);
    return found;
}

/* The top of a HID/USB stack is often an unnamed function or filter device: name the
 * stack by its first named device going down (at worst the PDO, which always has one). */
static BOOLEAN KfDeviceStackName(PDEVICE_OBJECT Top, PWSTR Buffer)
{
    PDEVICE_OBJECT device = Top;

    ObReferenceObject(device);
    while (device != NULL) {
        PDEVICE_OBJECT lower;
        if (KfDeviceName(device, Buffer)) {
            ObDereferenceObject(device);
            return TRUE;
        }
        lower = IoGetLowerDeviceObject(device);
        ObDereferenceObject(device);
        device = lower;
    }
    return FALSE;
}

static NTSTATUS KfDeviceAttachTarget(PDEVICE_OBJECT Target)
{
    PDEVICE_OBJECT filter = NULL;
    PDEVICE_OBJECT attached;
    PKF_DEVICE_EXTENSION extension;
    NTSTATUS status;

    if (Target == NULL) return STATUS_INVALID_PARAMETER;
    if (KfDeviceIsFilterDevice(Target)) return STATUS_SUCCESS;
    (VOID)KeWaitForSingleObject(&gDeviceLock, Executive, KernelMode, FALSE, NULL);
    for (extension = gDeviceFilters; extension != NULL; extension = extension->Next) {
        if (extension->Device == Target) {
            KeReleaseMutex(&gDeviceLock, FALSE);
            return STATUS_SUCCESS;
        }
    }
    status = IoCreateDevice(gDeviceDriver, sizeof(KF_DEVICE_EXTENSION), NULL,
                            Target->DeviceType, Target->Characteristics, FALSE, &filter);
    if (!NT_SUCCESS(status)) {
        KeReleaseMutex(&gDeviceLock, FALSE);
        return status;
    }
    extension = (PKF_DEVICE_EXTENSION)filter->DeviceExtension;
    RtlZeroMemory(extension, sizeof(*extension));
    extension->Magic = KFILTER_DEVICE_MAGIC;
    extension->Device = Target;
    extension->Target = Target;
    extension->Self = filter;
    IoInitializeRemoveLock(&extension->RemoveLock, KFILTER_POOL_TAG, 0, 0);
    if (!KfDeviceStackName(Target, extension->Name)) {
        IoDeleteDevice(filter);
        KeReleaseMutex(&gDeviceLock, FALSE);
        return STATUS_OBJECT_NAME_INVALID;
    }
    filter->Flags |= Target->Flags & (DO_BUFFERED_IO | DO_DIRECT_IO | DO_POWER_PAGABLE | DO_POWER_INRUSH);
    filter->StackSize = Target->StackSize + 1;
    attached = IoAttachDeviceToDeviceStack(filter, Target);
    if (attached == NULL) {
        IoDeleteDevice(filter);
        KeReleaseMutex(&gDeviceLock, FALSE);
        return STATUS_UNSUCCESSFUL;
    }
    extension->Target = attached;
    extension->Next = gDeviceFilters;
    gDeviceFilters = extension;
    filter->Flags &= ~DO_DEVICE_INITIALIZING;
    KeReleaseMutex(&gDeviceLock, FALSE);
    return STATUS_SUCCESS;
}

static NTSTATUS KfDeviceAttachNamed(PCWSTR Name)
{
    UNICODE_STRING path;
    PFILE_OBJECT fileObject = NULL;
    PDEVICE_OBJECT target = NULL;
    NTSTATUS status;

    RtlInitUnicodeString(&path, Name);
    status = IoGetDeviceObjectPointer(&path, FILE_READ_ATTRIBUTES, &fileObject, &target);
    if (NT_SUCCESS(status)) {
        status = KfDeviceAttachTarget(target);
        ObDereferenceObject(fileObject);
    }
    return status;
}

static VOID KfDeviceFailure(NTSTATUS Status)
{
    InterlockedIncrement(&gDeviceAttachFailures);
    DbgPrint("kfilter: device attachment failed 0x%08X\n", Status);
}

static VOID KfDeviceScanScsi(VOID)
{
    ULONG index;

    for (index = 0; index < 256; index++) {
        WCHAR name[64];
        NTSTATUS status = RtlStringCchPrintfW(name, RTL_NUMBER_OF(name), L"\\GLOBAL??\\Scsi%u:", index);
        if (!NT_SUCCESS(status)) {
            KfDeviceFailure(status);
            continue;
        }
        status = KfDeviceAttachNamed(name);
        if (KfScsiLinkMissing((unsigned long)status)) continue;
        if (!NT_SUCCESS(status)) KfDeviceFailure(status);
    }
}

static VOID KfDeviceRemoveFromList(PKF_DEVICE_EXTENSION Extension)
{
    PKF_DEVICE_EXTENSION* link;

    (VOID)KeWaitForSingleObject(&gDeviceLock, Executive, KernelMode, FALSE, NULL);
    for (link = &gDeviceFilters; *link != NULL; link = &(*link)->Next) {
        if (*link == Extension) {
            *link = Extension->Next;
            break;
        }
    }
    KeReleaseMutex(&gDeviceLock, FALSE);
    if (_wcsicmp(Extension->Name, L"\\Device\\Nsi") == 0) InterlockedExchange(&gDeviceNsiReady, 0);
    if (_wcsicmp(Extension->Name, L"\\Device\\MountPointManager") == 0) {
        InterlockedExchange(&gDeviceMountReady, 0);
    }
}

static NTSTATUS KfDeviceInterfaceNotification(PVOID NotificationStructure, PVOID Context)
{
    PDEVICE_INTERFACE_CHANGE_NOTIFICATION notification =
        (PDEVICE_INTERFACE_CHANGE_NOTIFICATION)NotificationStructure;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(Context);
    if (!ExAcquireRundownProtection(&gDeviceRundown)) return STATUS_DELETE_PENDING;
    if (notification != NULL && IsEqualGUID(&notification->Event, &GUID_DEVICE_INTERFACE_ARRIVAL) &&
        notification->SymbolicLinkName != NULL) {
        if (IsEqualGUID(&notification->InterfaceClassGuid, &GUID_DEVINTERFACE_DISK)) {
            KfDeviceScanScsi();
        } else {
            PFILE_OBJECT fileObject = NULL;
            PDEVICE_OBJECT target = NULL;
            status = IoGetDeviceObjectPointer(notification->SymbolicLinkName, FILE_READ_ATTRIBUTES,
                                              &fileObject, &target);
            if (NT_SUCCESS(status)) {
                status = KfDeviceAttachTarget(target);
                ObDereferenceObject(fileObject);
                if (!NT_SUCCESS(status)) KfDeviceFailure(status);
            } else if (status != STATUS_SHARING_VIOLATION && status != STATUS_ACCESS_DENIED &&
                       status != STATUS_NO_SUCH_DEVICE && status != STATUS_DELETE_PENDING &&
                       status != STATUS_OBJECT_NAME_NOT_FOUND) {
                /* A device that is gone, held exclusively or refuses even a kernel open is
                 * no route the protected process can open now either: not a missing attachment. */
                KfDeviceFailure(status);
            }
        }
    }
    ExReleaseRundownProtection(&gDeviceRundown);
    return status;
}

NTSTATUS KfDeviceDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PKF_DEVICE_EXTENSION extension;
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    PDEVICE_OBJECT target;
    NTSTATUS status;

    if (!ExAcquireRundownProtection(&gDeviceRundown)) {
        return KfCompleteDeviceIrp(Irp, STATUS_DELETE_PENDING);
    }
    extension = KfDeviceIsFilterDevice(DeviceObject)
                    ? (PKF_DEVICE_EXTENSION)DeviceObject->DeviceExtension : NULL;
    if (extension == NULL) {
        ExReleaseRundownProtection(&gDeviceRundown);
        return KfCompleteDeviceIrp(Irp, STATUS_DEVICE_DOES_NOT_EXIST);
    }
    status = IoAcquireRemoveLock(&extension->RemoveLock, Irp);
    if (!NT_SUCCESS(status)) {
        ExReleaseRundownProtection(&gDeviceRundown);
        return KfCompleteDeviceIrp(Irp, STATUS_DELETE_PENDING);
    }
    target = extension->Target;
    if (target == NULL) {
        IoReleaseRemoveLock(&extension->RemoveLock, Irp);
        ExReleaseRundownProtection(&gDeviceRundown);
        return KfCompleteDeviceIrp(Irp, STATUS_DEVICE_DOES_NOT_EXIST);
    }

    if (stack->MajorFunction == IRP_MJ_PNP && stack->MinorFunction == IRP_MN_REMOVE_DEVICE) {
        extension->Removed = TRUE;
        KfDeviceRemoveFromList(extension);
        IoReleaseRemoveLockAndWait(&extension->RemoveLock, Irp);
        IoSkipCurrentIrpStackLocation(Irp);
        status = IoCallDriver(target, Irp);
        IoDetachDevice(target);
        IoDeleteDevice(DeviceObject);
        ExReleaseRundownProtection(&gDeviceRundown);
        return status;
    }

    if (KfDeviceDecisionRequired(stack->MajorFunction, (ULONG)Irp->RequestorMode) &&
        !(Irp->Flags & IRP_PAGING_IO) && KfProcessIsProtectedCurrent()) {
        UNICODE_STRING path;
        UNICODE_STRING value;
        WCHAR valueText[16];
        PCUNICODE_STRING valuePointer = NULL;
        ULONG code = stack->MajorFunction == IRP_MJ_CREATE
                         ? 0 : stack->Parameters.DeviceIoControl.IoControlCode;
        ULONG ruleId = 0;
        BOOLEAN nameFailure = FALSE;

        RtlInitUnicodeString(&path, extension->Name);
        /* The open is decided with code zero; it carries that value too, so a
         * value=0x00000000 rule can authorize the open a control rule needs. */
        (VOID)KfDeviceValueText(code, valueText, RTL_NUMBER_OF(valueText));
        RtlInitUnicodeString(&value, valueText);
        valuePointer = &value;
        if (KfDecideWithRights(KFILTER_TARGET_DEVICE, &path, KFILTER_RIGHT_RAW_DEVICE,
                               valuePointer, 0, &ruleId, &nameFailure, NULL, code)) {
            IoReleaseRemoveLock(&extension->RemoveLock, Irp);
            ExReleaseRundownProtection(&gDeviceRundown);
            return KfCompleteDeviceIrp(Irp, STATUS_ACCESS_DENIED);
        }
    }

    IoSkipCurrentIrpStackLocation(Irp);
    if (stack->MajorFunction == IRP_MJ_POWER) {
        status = PoCallDriver(target, Irp);
    } else {
        status = IoCallDriver(target, Irp);
    }
    IoReleaseRemoveLock(&extension->RemoveLock, Irp);
    ExReleaseRundownProtection(&gDeviceRundown);
    return status;
}

NTSTATUS KfDeviceInitialize(PDRIVER_OBJECT DriverObject)
{
    static const GUID* classes[KFILTER_DEVICE_NOTIFICATIONS] = {
        &GUID_DEVINTERFACE_NET, &KF_GUID_DEVINTERFACE_HID,
        &KF_GUID_DEVINTERFACE_USB_DEVICE, &GUID_DEVINTERFACE_DISK
    };
    NTSTATUS status;
    ULONG index;

    gDeviceFilters = NULL;
    KeInitializeMutex(&gDeviceLock, 0);
    gDeviceDriver = DriverObject;
    RtlZeroMemory(gDeviceNotification, sizeof(gDeviceNotification));
    gDeviceAttachFailures = 0;
    gDeviceNsiReady = 0;
    gDeviceMountReady = 0;
    ExInitializeRundownProtection(&gDeviceRundown);
    gDeviceRundownInitialized = TRUE;

    status = KfDeviceAttachNamed(L"\\Device\\Nsi");
    if (NT_SUCCESS(status)) InterlockedExchange(&gDeviceNsiReady, 1);
    else KfDeviceFailure(status);
    status = KfDeviceAttachNamed(L"\\Device\\MountPointManager");
    if (NT_SUCCESS(status)) InterlockedExchange(&gDeviceMountReady, 1);
    else KfDeviceFailure(status);
    KfDeviceScanScsi();

    for (index = 0; index < KFILTER_DEVICE_NOTIFICATIONS; index++) {
        status = IoRegisterPlugPlayNotification(EventCategoryDeviceInterfaceChange,
                                                PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES,
                                                (PVOID)classes[index], DriverObject,
                                                (PDRIVER_NOTIFICATION_CALLBACK_ROUTINE)KfDeviceInterfaceNotification,
                                                NULL, &gDeviceNotification[index]);
        if (!NT_SUCCESS(status)) KfDeviceFailure(status);
    }
    return STATUS_SUCCESS;
}

BOOLEAN KfDeviceAvailable(VOID)
{
    return InterlockedCompareExchange(&gDeviceAttachFailures, 0, 0) == 0 &&
           InterlockedCompareExchange(&gDeviceNsiReady, 0, 0) != 0 &&
           InterlockedCompareExchange(&gDeviceMountReady, 0, 0) != 0;
}

BOOLEAN KfDeviceDegraded(VOID)
{
    return !KfDeviceAvailable();
}

BOOLEAN KfDeviceNsiAttached(VOID)
{
    return InterlockedCompareExchange(&gDeviceNsiReady, 0, 0) != 0;
}

VOID KfDeviceUninitialize(VOID)
{
    PKF_DEVICE_EXTENSION extension;
    ULONG index;

    if (gDeviceDriver == NULL) return;
    for (index = 0; index < KFILTER_DEVICE_NOTIFICATIONS; index++) {
        if (gDeviceNotification[index] != NULL) {
            (VOID)IoUnregisterPlugPlayNotification(gDeviceNotification[index]);
            gDeviceNotification[index] = NULL;
        }
    }
    if (gDeviceRundownInitialized) {
        ExWaitForRundownProtectionRelease(&gDeviceRundown);
        ExRundownCompleted(&gDeviceRundown);
        gDeviceRundownInitialized = FALSE;
    }
    (VOID)KeWaitForSingleObject(&gDeviceLock, Executive, KernelMode, FALSE, NULL);
    extension = gDeviceFilters;
    gDeviceFilters = NULL;
    KeReleaseMutex(&gDeviceLock, FALSE);
    while (extension != NULL) {
        PKF_DEVICE_EXTENSION next = extension->Next;
        extension->Removed = TRUE;
        if (NT_SUCCESS(IoAcquireRemoveLock(&extension->RemoveLock, extension))) {
            IoReleaseRemoveLockAndWait(&extension->RemoveLock, extension);
        }
        if (extension->Target != NULL) IoDetachDevice(extension->Target);
        IoDeleteDevice(extension->Self);
        extension = next;
    }
    gDeviceNsiReady = 0;
    gDeviceMountReady = 0;
    gDeviceDriver = NULL;
}
