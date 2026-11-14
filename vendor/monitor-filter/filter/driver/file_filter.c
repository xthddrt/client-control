#include <fltKernel.h>
#include "kf.h"

/*
 * File, directory, section, pipe and volume enforcement.
 *
 * Create and rename/link set-information are authorization points. The create
 * decision is attached as a stream-handle context and reused for read/write/
 * set-info/set-security/section/device operations, so a path is never re-resolved
 * in the memory-manager path. Missing context or missing name is a scoped denial
 * in enforce mode, never a system-wide denial.
 */

typedef struct _KF_STREAM_CONTEXT {
    ULONG Rights;
    ULONG Generation;
    ULONG RuleId;
    BOOLEAN NameFailure;
    BOOLEAN IsDirectory;
} KF_STREAM_CONTEXT, *PKF_STREAM_CONTEXT;

typedef struct _KF_PRE_CONTEXT {
    KF_STREAM_CONTEXT Decision;
    BOOLEAN Deny;
    BOOLEAN IsDirectory;
} KF_PRE_CONTEXT, *PKF_PRE_CONTEXT;

static PFLT_FILTER gFilter;

static VOID KfContextCleanup(PFLT_CONTEXT Context, FLT_CONTEXT_TYPE Type)
{
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Type);
}

static const FLT_CONTEXT_REGISTRATION gContexts[] = {
    { FLT_STREAMHANDLE_CONTEXT, 0, KfContextCleanup, sizeof(KF_STREAM_CONTEXT),
      KFILTER_POOL_TAG, NULL, NULL },
    { FLT_CONTEXT_END }
};

static PFLT_FILE_NAME_INFORMATION KfAcquireName(PFLT_CALLBACK_DATA Data, ULONG QueryFlags)
{
    PFLT_FILE_NAME_INFORMATION info = NULL;
    if (KeGetCurrentIrql() > APC_LEVEL) return NULL;
    if (!NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | QueryFlags, &info))) {
        info = NULL;
        if (!NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_OPENED | QueryFlags, &info))) {
            return NULL;
        }
    }
    return info;
}

static ULONG KfOperationRights(ULONG MajorFunction, PFLT_CALLBACK_DATA Data)
{
    switch (MajorFunction) {
    case IRP_MJ_READ:
        return KFILTER_RIGHT_READ;
    case IRP_MJ_WRITE:
        return KFILTER_RIGHT_WRITE;
    case IRP_MJ_DIRECTORY_CONTROL:
        return KFILTER_RIGHT_ENUMERATE;
    case IRP_MJ_SET_INFORMATION: {
        FILE_INFORMATION_CLASS infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
        if (infoClass == FileDispositionInformation || infoClass == FileDispositionInformationEx) {
            return KFILTER_RIGHT_DELETE;
        }
        if (infoClass == FileRenameInformation || infoClass == FileRenameInformationEx ||
            infoClass == FileLinkInformation || infoClass == FileLinkInformationEx) {
            return KFILTER_RIGHT_RENAME;
        }
        return KFILTER_RIGHT_WRITE;
    }
    case IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION:
        return KfRightsFromSection(Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection);
    case IRP_MJ_SET_SECURITY:
        return KFILTER_RIGHT_SET_SECURITY;
    /*
     * Control operations can read or modify file data and metadata
     * (FSCTL_SET_ZERO_DATA, FSCTL_SET_REPARSE_POINT, FSCTL_ENUM_USN_DATA, ...),
     * so they are authorized like data access instead of being skipped. There is
     * no per-control-code mapping yet; read+write is the conservative request,
     * and the caller's missing/stale-context and subset checks apply to it.
     */
    case IRP_MJ_DEVICE_CONTROL:
    case IRP_MJ_INTERNAL_DEVICE_CONTROL:
    case IRP_MJ_FILE_SYSTEM_CONTROL:
        return KfRightsFromControlOperation();
    default:
        return 0;
    }
}

/*
 * Rename and hard-link operations name a destination the stream-handle context
 * does not cover: resolve it (FileName relative to RootDirectory when present)
 * and authorize it as a separate request with the rename right.
 */
static BOOLEAN KfDenySetInfoDestination(PFLT_CALLBACK_DATA Data,
                                        PCFLT_RELATED_OBJECTS FltObjects,
                                        ULONG Target)
{
    FILE_INFORMATION_CLASS infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    PVOID buffer = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
    ULONG length = Data->Iopb->Parameters.SetFileInformation.Length;
    PFLT_FILE_NAME_INFORMATION destination = NULL;
    ULONG nameOffset = FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName);
    ULONG ruleId = 0;
    BOOLEAN nameFailure = FALSE;
    BOOLEAN deny;

    if (infoClass != FileRenameInformation && infoClass != FileRenameInformationEx &&
        infoClass != FileLinkInformation && infoClass != FileLinkInformationEx) {
        return FALSE;
    }
    if (buffer != NULL && length >= nameOffset) {
        PFILE_RENAME_INFORMATION rename = (PFILE_RENAME_INFORMATION)buffer;
        if (rename->FileNameLength != 0 && rename->FileNameLength <= length - nameOffset &&
            !NT_SUCCESS(FltGetDestinationFileNameInformation(
                FltObjects->Instance, FltObjects->FileObject, rename->RootDirectory,
                rename->FileName, rename->FileNameLength,
                FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &destination))) {
            destination = NULL;
        }
    }
    deny = KfDecideWithRights(Target, destination != NULL ? &destination->Name : NULL,
                              KFILTER_RIGHT_RENAME, NULL, 0, &ruleId, &nameFailure, NULL, 0);
    if (destination != NULL) FltReleaseFileNameInformation(destination);
    return deny;
}

static FLT_PREOP_CALLBACK_STATUS KfPreCreate(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext
)
{
    PFLT_FILE_NAME_INFORMATION nameInfo;
    PKF_PRE_CONTEXT pre = NULL;
    ULONG desiredAccess = 0;
    ULONG options = 0;
    ULONG target;
    ULONG rights;
    ULONG generation = 0;
    ULONG ruleId = 0;
    BOOLEAN nameFailure = FALSE;
    BOOLEAN directory;
    BOOLEAN deny;

    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;
    if (!KfProcessIsProtectedCurrent()) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    directory = Data->Iopb->MajorFunction == IRP_MJ_CREATE &&
                (Data->Iopb->Parameters.Create.Options & FILE_DIRECTORY_FILE) != 0;
    target = directory ? KFILTER_TARGET_DIR : KFILTER_TARGET_FILE;
    if (Data->Iopb->MajorFunction == IRP_MJ_CREATE_NAMED_PIPE ||
        Data->Iopb->MajorFunction == IRP_MJ_CREATE_MAILSLOT) {
        target = KFILTER_TARGET_PIPE;
    }
    if (Data->Iopb->MajorFunction == IRP_MJ_CREATE &&
        Data->Iopb->Parameters.Create.SecurityContext != NULL) {
        desiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    } else if (Data->Iopb->MajorFunction == IRP_MJ_CREATE_NAMED_PIPE &&
               Data->Iopb->Parameters.CreatePipe.SecurityContext != NULL) {
        desiredAccess = Data->Iopb->Parameters.CreatePipe.SecurityContext->DesiredAccess;
    } else if (Data->Iopb->MajorFunction == IRP_MJ_CREATE_MAILSLOT &&
               Data->Iopb->Parameters.CreateMailslot.SecurityContext != NULL) {
        desiredAccess = Data->Iopb->Parameters.CreateMailslot.SecurityContext->DesiredAccess;
    } else {
        desiredAccess = FILE_READ_DATA;
    }

    nameInfo = KfAcquireName(Data, FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP);
    if (nameInfo != NULL) {
        if (nameInfo->Name.Length >= 2 * sizeof(WCHAR) &&
            (KfMatchGlob(L"\\Device\\NamedPipe*", 18, nameInfo->Name.Buffer,
                         nameInfo->Name.Length / sizeof(WCHAR)) ||
             KfMatchGlob(L"\\Device\\Mailslot*", 17, nameInfo->Name.Buffer,
                         nameInfo->Name.Length / sizeof(WCHAR)))) {
            target = KFILTER_TARGET_PIPE;
        }
    }

    /*
     * The create options are a union member valid only for a real create; pipe
     * and mailslot creates carry different parameters. The disposition can
     * truncate the file and FILE_DELETE_ON_CLOSE can delete it, so fold both
     * into the rights the decision sees.
     */
    options = Data->Iopb->MajorFunction == IRP_MJ_CREATE
                  ? Data->Iopb->Parameters.Create.Options : 0;
    rights = KfCreateRightsForMajor(desiredAccess, options, Data->Iopb->MajorFunction,
                                    directory ? 1 : 0);
    /*
     * Snapshot the generation before the decision. KfDecide acquires its own
     * config reference, so a policy published between this read and that
     * acquire leaves the context older than the live generation and the later
     * handle operations fail the stale-context check (fail closed). Reading the
     * generation afterwards would tag a handle decided under N with N+1.
     */
    generation = KfPolicyGeneration();
    deny = KfDecideWithRights(target, nameInfo != NULL ? &nameInfo->Name : NULL, rights,
                              NULL, 0, &ruleId, &nameFailure, NULL, 0);
    if (nameInfo != NULL) FltReleaseFileNameInformation(nameInfo);

    if (deny) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    pre = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*pre), KFILTER_POOL_TAG);
    if (pre == NULL) {
        if (KfPolicyMode() == KFILTER_MODE_BLOCK) {
            Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    RtlZeroMemory(pre, sizeof(*pre));
    pre->Decision.Rights = rights;
    pre->Decision.Generation = generation;
    pre->Decision.RuleId = ruleId;
    pre->Decision.NameFailure = nameFailure;
    pre->IsDirectory = directory;
    *CompletionContext = pre;
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

static FLT_POSTOP_CALLBACK_STATUS KfPostCreate(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID CompletionContext,
    FLT_POST_OPERATION_FLAGS Flags
)
{
    PKF_PRE_CONTEXT pre = (PKF_PRE_CONTEXT)CompletionContext;
    PKF_STREAM_CONTEXT stream = NULL;

    if (pre == NULL) return FLT_POSTOP_FINISHED_PROCESSING;
    /* STATUS_REPARSE is a success code, but the file object is torn down rather than opened;
     * a draining instance must not attach new contexts either. */
    if (NT_SUCCESS(Data->IoStatus.Status) && Data->IoStatus.Status != STATUS_REPARSE &&
        !FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) {
        /* The fourth argument is the pool type; the tag comes from the context registration. */
        if (NT_SUCCESS(FltAllocateContext(gFilter, FLT_STREAMHANDLE_CONTEXT,
                                          sizeof(*stream), NonPagedPoolNx, &stream))) {
            RtlZeroMemory(stream, sizeof(*stream));
            stream->Rights = pre->Decision.Rights;
            stream->Generation = pre->Decision.Generation;
            stream->RuleId = pre->Decision.RuleId;
            stream->NameFailure = pre->Decision.NameFailure;
            stream->IsDirectory = pre->IsDirectory;
            (VOID)FltSetStreamHandleContext(FltObjects->Instance, Data->Iopb->TargetFileObject,
                                            FLT_SET_CONTEXT_REPLACE_IF_EXISTS,
                                            stream, NULL);
            FltReleaseContext(stream);
        }
    }
    ExFreePoolWithTag(pre, KFILTER_POOL_TAG);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

static FLT_PREOP_CALLBACK_STATUS KfPreOperation(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext
)
{
    PKF_STREAM_CONTEXT context = NULL;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    ULONG rights;
    ULONG target;
    ULONG ruleId = 0;
    ULONG mode;
    BOOLEAN missing = FALSE;
    BOOLEAN nameFailure = FALSE;

    *CompletionContext = NULL;
    if (!KfProcessIsProtectedCurrent() || !KfPolicyBlockFiles() ||
        KfPolicyMode() == KFILTER_MODE_OFF) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    /* Only the create-section acquire may be failed; the other sync types assume the lock is held. */
    if (Data->Iopb->MajorFunction == IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION &&
        Data->Iopb->Parameters.AcquireForSectionSynchronization.SyncType != SyncTypeCreateSection) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    target = Data->Iopb->MajorFunction == IRP_MJ_DIRECTORY_CONTROL
                 ? KFILTER_TARGET_DIR
                 : (Data->Iopb->MajorFunction == IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION
                        ? KFILTER_TARGET_FILE : KFILTER_TARGET_FILE);
    rights = KfOperationRights(Data->Iopb->MajorFunction, Data);
    if (rights == 0) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (!NT_SUCCESS(FltGetStreamHandleContext(FltObjects->Instance, Data->Iopb->TargetFileObject,
                                              &context)) || context == NULL) {
        KfCountMissingContext();
        missing = TRUE;
        ruleId = 0;
    } else if (context->Generation != KfPolicyGeneration()) {
        KfCountMissingContext();
        missing = TRUE;
        ruleId = context->RuleId;
        FltReleaseContext(context);
        context = NULL;
    } else {
        ruleId = context->RuleId;
    }

    if (missing) {
        nameInfo = KfAcquireName(Data, FLT_FILE_NAME_QUERY_CACHE_ONLY);
        KfLogEvent(target, KfPolicyMode() == KFILTER_MODE_BLOCK ? KFilterActionDeny : KFilterActionAudit,
                   (KfPolicyMode() == KFILTER_MODE_BLOCK ? 0 : KFILTER_EVENT_FLAG_WOULD_DENY) |
                       KFILTER_EVENT_FLAG_MISSING_CONTEXT,
                   KfPolicyMode() == KFILTER_MODE_BLOCK ? STATUS_ACCESS_DENIED : STATUS_SUCCESS,
                   rights, 0, nameInfo != NULL ? &nameInfo->Name : NULL);
        if (nameInfo != NULL) FltReleaseFileNameInformation(nameInfo);
        mode = KfPolicyMode();
        if (mode == KFILTER_MODE_BLOCK) {
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (Data->Iopb->MajorFunction == IRP_MJ_SET_SECURITY) {
        /* A security change on an already-open handle uses the class recorded
         * at create; no name re-resolution in this path. */
        target = context->IsDirectory ? KFILTER_TARGET_DIR : KFILTER_TARGET_FILE;
    }

    if (rights == KFILTER_RIGHT_RENAME) {
        BOOLEAN deny;
        target = context->IsDirectory ? KFILTER_TARGET_DIR : KFILTER_TARGET_FILE;
        nameInfo = KfAcquireName(Data, FLT_FILE_NAME_QUERY_DEFAULT);
        deny = KfDecideWithRights(target, nameInfo != NULL ? &nameInfo->Name : NULL,
                                  KFILTER_RIGHT_RENAME, NULL, 0, &ruleId, &nameFailure, NULL, 0);
        if (nameInfo != NULL) FltReleaseFileNameInformation(nameInfo);
        FltReleaseContext(context);
        if (deny || KfDenySetInfoDestination(Data, FltObjects, target)) {
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if ((context->Rights & rights) != rights) {
        nameInfo = KfAcquireName(Data, FLT_FILE_NAME_QUERY_CACHE_ONLY);
        KfLogEvent(target, KfPolicyMode() == KFILTER_MODE_BLOCK ? KFilterActionDeny : KFilterActionAudit,
                   (KfPolicyMode() == KFILTER_MODE_BLOCK ? 0 : KFILTER_EVENT_FLAG_WOULD_DENY),
                   KfPolicyMode() == KFILTER_MODE_BLOCK ? STATUS_ACCESS_DENIED : STATUS_SUCCESS,
                   rights, context->RuleId, nameInfo != NULL ? &nameInfo->Name : NULL);
        if (nameInfo != NULL) FltReleaseFileNameInformation(nameInfo);
        FltReleaseContext(context);
        if (KfPolicyMode() == KFILTER_MODE_BLOCK) {
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    FltReleaseContext(context);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static FLT_PREOP_CALLBACK_STATUS KfPreQueryVolume(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext
)
{
    FS_INFORMATION_CLASS informationClass;
    PFLT_FILE_NAME_INFORMATION nameInfo;
    ULONG ruleId = 0;
    BOOLEAN nameFailure = FALSE;
    BOOLEAN deny;

    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;
    if (!KfProcessIsProtectedCurrent() || !KfPolicyBlockVolumeSerial()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    informationClass = Data->Iopb->Parameters.QueryVolumeInformation.FsInformationClass;
    if (informationClass != FileFsVolumeInformation && informationClass != FileFsObjectIdInformation) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    nameInfo = KfAcquireName(Data, FLT_FILE_NAME_QUERY_CACHE_ONLY);
    deny = KfDecideWithRights(KFILTER_TARGET_VOLUME,
                              nameInfo != NULL ? &nameInfo->Name : NULL,
                              KFILTER_RIGHT_RAW_DEVICE, NULL, (ULONG)informationClass,
                              &ruleId, &nameFailure, NULL, 0);
    if (nameInfo != NULL) FltReleaseFileNameInformation(nameInfo);
    if (deny) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static const FLT_OPERATION_REGISTRATION gOperations[] = {
    { IRP_MJ_CREATE, 0, KfPreCreate, KfPostCreate, NULL },
    { IRP_MJ_CREATE_NAMED_PIPE, 0, KfPreCreate, KfPostCreate, NULL },
    { IRP_MJ_CREATE_MAILSLOT, 0, KfPreCreate, KfPostCreate, NULL },
    { IRP_MJ_READ, FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO, KfPreOperation, NULL, NULL },
    { IRP_MJ_WRITE, FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO, KfPreOperation, NULL, NULL },
    { IRP_MJ_SET_INFORMATION, 0, KfPreOperation, NULL, NULL },
    { IRP_MJ_SET_SECURITY, 0, KfPreOperation, NULL, NULL },
    { IRP_MJ_DIRECTORY_CONTROL, 0, KfPreOperation, NULL, NULL },
    { IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION, 0, KfPreOperation, NULL, NULL },
    { IRP_MJ_QUERY_VOLUME_INFORMATION, 0, KfPreQueryVolume, NULL, NULL },
    { IRP_MJ_DEVICE_CONTROL, 0, KfPreOperation, NULL, NULL },
    { IRP_MJ_INTERNAL_DEVICE_CONTROL, 0, KfPreOperation, NULL, NULL },
    { IRP_MJ_FILE_SYSTEM_CONTROL, 0, KfPreOperation, NULL, NULL },
    { IRP_MJ_OPERATION_END, 0, NULL, NULL, NULL }
};

static NTSTATUS FLTAPI KfFilterUnload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    return STATUS_SUCCESS;
}

static const FLT_REGISTRATION gFilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    FLTFL_REGISTRATION_SUPPORT_NPFS_MSFS,
    gContexts,
    gOperations,
    KfFilterUnload,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

NTSTATUS KfFileInitialize(PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status = FltRegisterFilter(DriverObject, &gFilterRegistration, &gFilter);
    if (!NT_SUCCESS(status)) return status;
    status = FltStartFiltering(gFilter);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gFilter);
        gFilter = NULL;
    }
    return status;
}

VOID KfFileUninitialize(VOID)
{
    if (gFilter != NULL) {
        FltUnregisterFilter(gFilter);
        gFilter = NULL;
    }
}
