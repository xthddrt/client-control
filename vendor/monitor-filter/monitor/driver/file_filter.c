#include <fltKernel.h>
#include "msmon.h"

#define MSMON_POOL_TAG 'noSM'
/* Volume results are small (FILE_FS_*_INFORMATION); cap what is copied out. */
#define MSMON_VOLUME_MAX_BYTES 1024u

static PFLT_FILTER gFilter;

/*
 * One completion context for every file operation we decide to observe.
 *
 * The requestor must be captured in the pre-operation callback.  A post-
 * operation callback can run in a different thread (and, for asynchronous
 * I/O, a different process), so re-reading PsGetCurrentProcessId() there
 * silently drops or misattributes events.  The tracking decision and the
 * requestor identity travel with the operation instead.
 */
typedef struct _MSMON_FILE_CONTEXT {
    PFLT_FILE_NAME_INFORMATION NameInfo;
    HANDLE ProcessId;
    LONGLONG ProcessStartTime;
    HANDLE ThreadId;
    BOOLEAN Tracked;
    ULONG DesiredAccess;
    ULONG Reserved;
} MSMON_FILE_CONTEXT, *PMSMon_FILE_CONTEXT;

static ULONG MsMonFileCategory(PCUNICODE_STRING Path)
{
    UNICODE_STRING namedPipe;
    UNICODE_STRING mailslot;
    RtlInitUnicodeString(&namedPipe, L"\\Device\\NamedPipe");
    RtlInitUnicodeString(&mailslot, L"\\Device\\Mailslot");
    if (Path != NULL && Path->Length >= namedPipe.Length &&
        RtlPrefixUnicodeString(&namedPipe, Path, TRUE)) return MsMonCategoryIpc;
    if (Path != NULL && Path->Length >= mailslot.Length &&
        RtlPrefixUnicodeString(&mailslot, Path, TRUE)) return MsMonCategoryIpc;
    return MsMonCategoryUnknown;
}

static ULONG MsMonEventType(UCHAR MajorFunction)
{
    switch (MajorFunction) {
    case IRP_MJ_READ: return MsMonFileRead;
    case IRP_MJ_WRITE: return MsMonFileWrite;
    case IRP_MJ_SET_INFORMATION: return MsMonFileSetInformation;
    case IRP_MJ_QUERY_INFORMATION: return MsMonFileQueryInformation;
    case IRP_MJ_DIRECTORY_CONTROL: return MsMonFileDirectoryControl;
    case IRP_MJ_CLEANUP: return MsMonFileCleanup;
    case IRP_MJ_CLOSE: return MsMonFileClose;
    case IRP_MJ_FLUSH_BUFFERS: return MsMonFileFlush;
    case IRP_MJ_QUERY_SECURITY: return MsMonFileQuerySecurity;
    case IRP_MJ_SET_SECURITY: return MsMonFileSetSecurity;
    case IRP_MJ_QUERY_EA: return MsMonFileQueryEa;
    case IRP_MJ_SET_EA: return MsMonFileSetEa;
    case IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION: return MsMonFileSection;
    case IRP_MJ_DEVICE_CONTROL:
    case IRP_MJ_INTERNAL_DEVICE_CONTROL: return MsMonFileDeviceControl;
    case IRP_MJ_FILE_SYSTEM_CONTROL: return MsMonFileSystemControl;
    case IRP_MJ_QUERY_VOLUME_INFORMATION: return MsMonFileQueryVolumeInformation;
    default: return MsMonCoverage;
    }
}

static ULONGLONG MsMonEventValue(PFLT_CALLBACK_DATA Data, BOOLEAN Second)
{
    switch (Data->Iopb->MajorFunction) {
    case IRP_MJ_READ:
        return Second ? (ULONGLONG)Data->Iopb->Parameters.Read.ByteOffset.QuadPart : Data->Iopb->Parameters.Read.Length;
    case IRP_MJ_WRITE:
        return Second ? (ULONGLONG)Data->Iopb->Parameters.Write.ByteOffset.QuadPart : Data->Iopb->Parameters.Write.Length;
    case IRP_MJ_SET_INFORMATION:
        return Second ? 0 : Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    case IRP_MJ_QUERY_INFORMATION:
        return Second ? 0 : Data->Iopb->Parameters.QueryFileInformation.FileInformationClass;
    case IRP_MJ_DIRECTORY_CONTROL:
        if (Second) return 0;
        if (Data->Iopb->MinorFunction == IRP_MN_QUERY_DIRECTORY) {
            return Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass;
        }
        return Data->Iopb->MinorFunction;
    case IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION:
        return Second ? Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection :
                        Data->Iopb->Parameters.AcquireForSectionSynchronization.SyncType;
    case IRP_MJ_QUERY_SECURITY:
        return Second ? 0 : Data->Iopb->Parameters.QuerySecurity.SecurityInformation;
    case IRP_MJ_SET_SECURITY:
        return Second ? 0 : Data->Iopb->Parameters.SetSecurity.SecurityInformation;
    case IRP_MJ_DEVICE_CONTROL:
    case IRP_MJ_INTERNAL_DEVICE_CONTROL:
        return Second ? Data->Iopb->Parameters.DeviceIoControl.Common.InputBufferLength :
                        Data->Iopb->Parameters.DeviceIoControl.Common.IoControlCode;
    case IRP_MJ_FILE_SYSTEM_CONTROL:
        return Second ? Data->Iopb->Parameters.FileSystemControl.Common.InputBufferLength :
                        Data->Iopb->Parameters.FileSystemControl.Common.FsControlCode;
    case IRP_MJ_QUERY_VOLUME_INFORMATION:
        return Second ? 0 : Data->Iopb->Parameters.QueryVolumeInformation.FsInformationClass;
    default:
        return 0;
    }
}

static PFLT_FILE_NAME_INFORMATION MsMonAcquireName(PFLT_CALLBACK_DATA Data, ULONG QueryFlags)
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    /*
     * FltGetFileNameInformation is documented for IRQL <= APC_LEVEL. Paging
     * I/O and some cleanup paths can reach a minifilter above that, so refuse
     * instead of letting the filter manager query the file system at a raised
     * IRQL.
     */
    if (KeGetCurrentIrql() > APC_LEVEL) {
        MsMonCoverageSkip(MSMON_SKIP_IRQL);
        return NULL;
    }
    if (!NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | QueryFlags, &nameInfo))) {
        MsMonCoverageSkip(MSMON_SKIP_NO_NAME);
        return NULL;
    }
    return nameInfo;
}

static PMSMon_FILE_CONTEXT MsMonCreateFileContext(PFLT_CALLBACK_DATA Data, ULONG QueryFlags)
{
    PMSMon_FILE_CONTEXT context;
    ULONG requestorId;
    HANDLE requestor;

    /*
     * Decide before allocating.  This callback is invoked for file I/O from
     * every process on the system; allocating a context for every unrelated
     * create/read/write would be an unnecessary nonpaged-pool cost.
     */
    requestorId = FltGetRequestorProcessId(Data);
    if (requestorId == 0) requestorId = HandleToUlong(PsGetCurrentProcessId());
    requestor = UlongToHandle(requestorId);
    if (!MsMonIsTracked(requestor, 0) && !MsMonCurrentIsBlackCat()) {
        MsMonCoverageSkip(MSMON_SKIP_UNTRACKED);
        return NULL;
    }

    context = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*context), MSMON_POOL_TAG);
    if (context == NULL) {
        MsMonCoverageSkip(MSMON_SKIP_ALLOC);
        MsMonEventsNoteDropped();
        return NULL;
    }
    RtlZeroMemory(context, sizeof(*context));
    context->ProcessId = requestor;
    context->ProcessStartTime = MsMonProcessStartTime(requestor);
    context->ThreadId = PsGetCurrentThreadId();
    context->Tracked = TRUE;
    context->NameInfo = MsMonAcquireName(Data, QueryFlags);
    return context;
}

static VOID MsMonFreeFileContext(PMSMon_FILE_CONTEXT Context)
{
    if (Context == NULL) return;
    if (Context->NameInfo != NULL) {
        FltReleaseFileNameInformation(Context->NameInfo);
        Context->NameInfo = NULL;
    }
    ExFreePoolWithTag(Context, MSMON_POOL_TAG);
}

static FLT_PREOP_CALLBACK_STATUS MsMonPreCreate(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext
)
{
    PMSMon_FILE_CONTEXT context;
    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;
    MsMonCoverageEnter(MSMON_SENSOR_FILE_PRE_CREATE);

    context = MsMonCreateFileContext(Data, FLT_FILE_NAME_QUERY_DEFAULT);
    if (context == NULL) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (!context->Tracked) {
        MsMonFreeFileContext(context);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (Data->Iopb->MajorFunction == IRP_MJ_CREATE &&
        Data->Iopb->Parameters.Create.SecurityContext != NULL) {
        context->DesiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    }
    /*
     * Resolve the name in the pre-create path, which is the documented safe
     * place for a file-system name query. Post-create used to query the name
     * itself, which can recurse into the file system and is not valid when
     * the create failed.
     */
    *CompletionContext = context;
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

static FLT_PREOP_CALLBACK_STATUS MsMonPreOperation(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext
)
{
    PMSMon_FILE_CONTEXT context;
    ULONG queryFlags;
    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;
    MsMonCoverageEnter(MSMON_SENSOR_FILE_PRE_OP);

    /*
     * Section acquisition runs in the memory-manager path.  Even though a name
     * query is usually served from the name cache, never let it issue file
     * system I/O there; a missing path is preferable to re-entering the FS
     * during paging.
     */
    queryFlags = Data->Iopb->MajorFunction == IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION
                     ? FLT_FILE_NAME_QUERY_CACHE_ONLY
                     : FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP;
    context = MsMonCreateFileContext(Data, queryFlags);
    if (context == NULL) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (!context->Tracked) {
        MsMonFreeFileContext(context);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    *CompletionContext = context;
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

static VOID MsMonVolumeUnavailable(
    PFLT_CALLBACK_DATA Data, PMSMon_FILE_CONTEXT Context, PCWSTR Reason
)
{
    UNICODE_STRING detail;
    PCUNICODE_STRING path = Context->NameInfo != NULL ? &Context->NameInfo->Name : NULL;
    ULONG category = MsMonEventValue(Data, FALSE) == 1 ? MsMonCategoryHardwareIdentity : MsMonFileCategory(path);
    RtlInitUnicodeString(&detail, Reason);
    (VOID)MsMonLogEvent(MsMonFileQueryVolumeInformation, Context->ProcessId, Context->ProcessStartTime, NULL,
                        Context->ThreadId, NULL, 0, MsMonFlagPayloadUnavailable,
                        Data->IoStatus.Status, 0, category, MsMonEventValue(Data, FALSE),
                        0, path, &detail);
}

static VOID MsMonCaptureVolume(PFLT_CALLBACK_DATA Data, PMSMon_FILE_CONTEXT Context)
{
    PCUNICODE_STRING path = Context->NameInfo != NULL ? &Context->NameInfo->Name : NULL;
    ULONG category = MsMonEventValue(Data, FALSE) == 1 ? MsMonCategoryHardwareIdentity : MsMonFileCategory(path);
    PVOID buffer = Data->Iopb->Parameters.QueryVolumeInformation.VolumeBuffer;
    ULONG length = Data->Iopb->Parameters.QueryVolumeInformation.Length;
    ULONG information = (ULONG)Data->IoStatus.Information;
    UCHAR local[MSMON_VOLUME_MAX_BYTES];
    BOOLEAN copied = FALSE;

    if (!NT_SUCCESS(Data->IoStatus.Status)) {
        if (Data->IoStatus.Status == STATUS_BUFFER_OVERFLOW ||
            Data->IoStatus.Status == STATUS_BUFFER_TOO_SMALL) {
            /*
             * Two-pass probe: the caller asked with a short buffer and repeats
             * the request with the correct size. No value is available yet, so
             * this is metadata, not an unavailable payload.
             */
            UNICODE_STRING detail;
            RtlInitUnicodeString(&detail, L"two_pass_probe");
            (VOID)MsMonLogEvent(MsMonFileQueryVolumeInformation, Context->ProcessId, Context->ProcessStartTime, NULL,
                                Context->ThreadId, NULL, 0, 0, Data->IoStatus.Status, 0,
                                category, MsMonEventValue(Data, FALSE), 0, path, &detail);
        } else {
            MsMonVolumeUnavailable(Data, Context, L"volume_query_failed");
        }
        return;
    }
    if (buffer == NULL) {
        MsMonVolumeUnavailable(Data, Context, L"missing_volume_buffer");
        return;
    }
    if (information == 0 || information > length) {
        MsMonVolumeUnavailable(Data, Context, L"invalid_volume_result");
        return;
    }
    if (information > MSMON_VOLUME_MAX_BYTES) {
        MsMonVolumeUnavailable(Data, Context, L"volume_result_too_large");
        return;
    }
    if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
        MsMonVolumeUnavailable(Data, Context, L"unsafe_irql");
        return;
    }
    /*
     * The buffer is either a filter-manager system buffer or the caller's user
     * buffer. Only read the user case in the requesting process context, and
     * never without a probe: a post-operation callback can run in an arbitrary
     * thread, where a user address belongs to another address space.
     */
    if (FltGetRequestorProcessId(Data) != HandleToUlong(PsGetCurrentProcessId()) &&
        (ULONG_PTR)buffer < (ULONG_PTR)MmUserProbeAddress) {
        MsMonVolumeUnavailable(Data, Context, L"foreign_process_context");
        return;
    }
    __try {
        if ((ULONG_PTR)buffer < (ULONG_PTR)MmUserProbeAddress) {
            ProbeForRead(buffer, information, sizeof(UCHAR));
        }
        RtlCopyMemory(local, buffer, information);
        copied = TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        copied = FALSE;
    }
    if (!copied) {
        MsMonVolumeUnavailable(Data, Context, L"unsafe_result_buffer");
        return;
    }
    (VOID)MsMonLogPayloadSeries(MsMonFileQueryVolumeInformation, Context->ProcessId, Context->ProcessStartTime,
                                Context->ThreadId, 0, Data->IoStatus.Status, category,
                                MsMonEventValue(Data, FALSE), 0, path, NULL,
                                MsMonPayloadVolumeInformation, MsMonNextOperationId(),
                                information, local, information);
}

static FLT_POSTOP_CALLBACK_STATUS MsMonPostOperation(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID CompletionContext,
    FLT_POST_OPERATION_FLAGS Flags
)
{
    PMSMon_FILE_CONTEXT context = (PMSMon_FILE_CONTEXT)CompletionContext;
    PCUNICODE_STRING path;
    UNREFERENCED_PARAMETER(FltObjects);

    if (context == NULL) return FLT_POSTOP_FINISHED_PROCESSING;
    path = context->NameInfo != NULL ? &context->NameInfo->Name : NULL;

    if ((Flags & FLTFL_POST_OPERATION_DRAINING) == 0 && context->Tracked) {
        if (Data->Iopb->MajorFunction == IRP_MJ_QUERY_VOLUME_INFORMATION && MsMonPayloadEnabled() &&
            Data->Iopb->Parameters.QueryVolumeInformation.FsInformationClass == FileFsVolumeInformation) {
            MsMonCaptureVolume(Data, context);
        } else {
            (VOID)MsMonLogEvent(MsMonEventType(Data->Iopb->MajorFunction),
                                context->ProcessId, context->ProcessStartTime, NULL, context->ThreadId, NULL, 0,
                                path == NULL ? MsMonFlagMissingPath : 0, Data->IoStatus.Status, 0,
                                MsMonFileCategory(path), MsMonEventValue(Data, FALSE),
                                MsMonEventValue(Data, TRUE), path, NULL);
        }
        MsMonCoverageLogged(MSMON_SENSOR_FILE_POST_OP);
    }
    MsMonFreeFileContext(context);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

static FLT_POSTOP_CALLBACK_STATUS MsMonPostCreate(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID CompletionContext,
    FLT_POST_OPERATION_FLAGS Flags
)
{
    PMSMon_FILE_CONTEXT context = (PMSMon_FILE_CONTEXT)CompletionContext;
    PFLT_FILE_NAME_INFORMATION nameInfo;
    PFLT_FILE_NAME_INFORMATION tunneled = NULL;
    PCUNICODE_STRING path;
    UNREFERENCED_PARAMETER(FltObjects);

    if (context == NULL) return FLT_POSTOP_FINISHED_PROCESSING;
    nameInfo = context->NameInfo;
    path = nameInfo != NULL ? &nameInfo->Name : NULL;

    if (Flags & FLTFL_POST_OPERATION_DRAINING) {
        MsMonFreeFileContext(context);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    if (context->Tracked) {
        ULONGLONG options = 0;
        if (Data->Iopb->MajorFunction == IRP_MJ_CREATE) {
            /*
             * A normalized name obtained in pre-create can be invalidated by name
             * tunneling; FltGetTunneledName returns the name that was actually used.
             */
            if (nameInfo != NULL && KeGetCurrentIrql() == PASSIVE_LEVEL &&
                NT_SUCCESS(FltGetTunneledName(Data, nameInfo, &tunneled)) && tunneled != NULL) {
                path = &tunneled->Name;
            }
            options = Data->Iopb->Parameters.Create.Options;
        }
        (VOID)MsMonLogEvent(MsMonFileCreate, context->ProcessId, context->ProcessStartTime, NULL, context->ThreadId,
                            NULL, 0, path == NULL ? MsMonFlagMissingPath : 0, Data->IoStatus.Status,
                            context->DesiredAccess, MsMonFileCategory(path),
                            options, Data->IoStatus.Information, path, NULL);
        MsMonCoverageLogged(MSMON_SENSOR_FILE_POST_CREATE);
    }
    if (tunneled != NULL) FltReleaseFileNameInformation(tunneled);
    MsMonFreeFileContext(context);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

static const FLT_OPERATION_REGISTRATION gOperations[] = {
    { IRP_MJ_CREATE, 0, MsMonPreCreate, MsMonPostCreate, NULL },
    { IRP_MJ_CREATE_NAMED_PIPE, 0, MsMonPreCreate, MsMonPostCreate, NULL },
    { IRP_MJ_CREATE_MAILSLOT, 0, MsMonPreCreate, MsMonPostCreate, NULL },
    { IRP_MJ_READ, FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO, MsMonPreOperation, MsMonPostOperation, NULL },
    { IRP_MJ_WRITE, FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO, MsMonPreOperation, MsMonPostOperation, NULL },
    { IRP_MJ_SET_INFORMATION, 0, MsMonPreOperation, MsMonPostOperation, NULL },
    { IRP_MJ_QUERY_INFORMATION, 0, MsMonPreOperation, MsMonPostOperation, NULL },
    { IRP_MJ_DIRECTORY_CONTROL, 0, MsMonPreOperation, MsMonPostOperation, NULL },
    { IRP_MJ_CLEANUP, 0, MsMonPreOperation, MsMonPostOperation, NULL },
    { IRP_MJ_CLOSE, 0, MsMonPreOperation, MsMonPostOperation, NULL },
    { IRP_MJ_FLUSH_BUFFERS, 0, MsMonPreOperation, MsMonPostOperation, NULL },
    { IRP_MJ_QUERY_SECURITY, 0, MsMonPreOperation, MsMonPostOperation, NULL },
    { IRP_MJ_SET_SECURITY, 0, MsMonPreOperation, MsMonPostOperation, NULL },
    { IRP_MJ_QUERY_EA, 0, MsMonPreOperation, MsMonPostOperation, NULL },
    { IRP_MJ_SET_EA, 0, MsMonPreOperation, MsMonPostOperation, NULL },
    { IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION, 0, MsMonPreOperation, MsMonPostOperation, NULL },
    { IRP_MJ_DEVICE_CONTROL, 0, MsMonPreOperation, MsMonPostOperation, NULL },
    { IRP_MJ_INTERNAL_DEVICE_CONTROL, 0, MsMonPreOperation, MsMonPostOperation, NULL },
    { IRP_MJ_FILE_SYSTEM_CONTROL, 0, MsMonPreOperation, MsMonPostOperation, NULL },
    { IRP_MJ_QUERY_VOLUME_INFORMATION, 0, MsMonPreOperation, MsMonPostOperation, NULL },
    { IRP_MJ_OPERATION_END, 0, NULL, NULL, NULL }
};

static NTSTATUS FLTAPI MsMonFilterUnload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    MsMonRecordStatus(L"FilterUnloadCallback", STATUS_FLT_DO_NOT_DETACH);
    /*
     * This filter shares its driver image with the control device and the other
     * callbacks. It cannot be detached on its own, so refuse and let the driver
     * unload path call FltUnregisterFilter exactly once.
     */
    return STATUS_FLT_DO_NOT_DETACH;
}

static const FLT_REGISTRATION gFilterRegistration = {
    sizeof(FLT_REGISTRATION), FLT_REGISTRATION_VERSION, FLTFL_REGISTRATION_SUPPORT_NPFS_MSFS,
    NULL, gOperations,
    MsMonFilterUnload, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

NTSTATUS MsMonFileFilterInitialize(PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status = FltRegisterFilter(DriverObject, &gFilterRegistration, &gFilter);
    MsMonCoverageRegister(MSMON_SENSOR_REG_FILTER_REGISTER, status);
    if (!NT_SUCCESS(status)) return status;
    status = FltStartFiltering(gFilter);
    MsMonCoverageRegister(MSMON_SENSOR_REG_FILTER_START, status);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gFilter);
        gFilter = NULL;
    }
    return status;
}

VOID MsMonFileFilterUninitialize(VOID)
{
    if (gFilter != NULL) {
        FltUnregisterFilter(gFilter);
        MsMonRecordStatus(L"FltUnregisterComplete", STATUS_SUCCESS);
        gFilter = NULL;
    }
}
