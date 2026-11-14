#include "msmon.h"

static LARGE_INTEGER gRegistryCookie;
static BOOLEAN gRegistryRegistered;

/* Cap on bytes copied out of one registry value; keeps the payload stream bounded. */
#define MSMON_REGISTRY_CAPTURE_MAX_BYTES (64u * 1024u)

typedef struct _MSMON_REGISTRY_CONTEXT {
    HANDLE ProcessId;
    LONGLONG ProcessStartTime;
    HANDLE ThreadId;
    ULONG Type;
    ULONG DesiredAccess;
    ULONGLONG Value0;
    ULONGLONG Value1;
    ULONGLONG OperationId;
    UNICODE_STRING Path;
    UNICODE_STRING Detail;
} MSMON_REGISTRY_CONTEXT, *PMSMON_REGISTRY_CONTEXT;

static PCUNICODE_STRING MsMonRegistryPath(PVOID Object)
{
    PCUNICODE_STRING name = NULL;
    ULONG_PTR objectId = 0;
    if (NT_SUCCESS(CmCallbackGetKeyObjectID(&gRegistryCookie, Object, &objectId, &name))) return name;
    return NULL;
}

static USHORT MsMonContextStringLength(PCUNICODE_STRING Value)
{
    if (Value == NULL || Value->Buffer == NULL) return 0;
    return min(Value->Length, MSMON_MAX_EVENT_STRING_BYTES);
}

static PMSMON_REGISTRY_CONTEXT MsMonCreateContext(
    ULONG Type, PCUNICODE_STRING Path, PCUNICODE_STRING Detail,
    ULONGLONG Value0, ULONGLONG Value1, ULONG DesiredAccess
)
{
    USHORT pathBytes = MsMonContextStringLength(Path);
    USHORT detailBytes = MsMonContextStringLength(Detail);
    SIZE_T size = sizeof(MSMON_REGISTRY_CONTEXT) + pathBytes + detailBytes;
    PMSMON_REGISTRY_CONTEXT context = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, MSMON_POOL_TAG);
    PUCHAR cursor;
    if (context == NULL) return NULL;
    RtlZeroMemory(context, size);
    context->ProcessId = PsGetCurrentProcessId();
    context->ProcessStartTime = MsMonProcessStartTime(context->ProcessId);
    context->ThreadId = PsGetCurrentThreadId();
    context->Type = Type;
    context->DesiredAccess = DesiredAccess;
    context->Value0 = Value0;
    context->Value1 = Value1;
    context->OperationId = MsMonNextOperationId();
    cursor = (PUCHAR)(context + 1);
    if (pathBytes != 0) {
        RtlCopyMemory(cursor, Path->Buffer, pathBytes);
        context->Path.Buffer = (PWSTR)cursor;
        context->Path.Length = pathBytes;
        context->Path.MaximumLength = pathBytes;
        cursor += pathBytes;
    }
    if (detailBytes != 0) {
        RtlCopyMemory(cursor, Detail->Buffer, detailBytes);
        context->Detail.Buffer = (PWSTR)cursor;
        context->Detail.Length = detailBytes;
        context->Detail.MaximumLength = detailBytes;
    }
    return context;
}

/*
 * NtQueryValueKey and NtEnumerateValueKey use a two-pass protocol: the first
 * call returns BUFFER_OVERFLOW/BUFFER_TOO_SMALL with the required size, and
 * enumeration terminates with NO_MORE_ENTRIES. Those results carry no value
 * and the follow-up call carries the real one, so they are logged as metadata
 * instead of as an unavailable payload. The recorded session produced ~2,100 of
 * them that looked like genuine failures.
 */
static BOOLEAN MsMonRetryStatus(NTSTATUS Status)
{
    return Status == STATUS_BUFFER_OVERFLOW || Status == STATUS_BUFFER_TOO_SMALL ||
           Status == STATUS_MORE_ENTRIES || Status == STATUS_NO_MORE_ENTRIES;
}

static VOID MsMonRegistryUnavailable(
    PMSMON_REGISTRY_CONTEXT Context, NTSTATUS Status, PCWSTR Reason, ULONG ExtraFlags
)
{
    WCHAR detail[512];
    UNICODE_STRING detailString;
    UNICODE_STRING empty;
    RtlInitUnicodeString(&empty, L"");
    (VOID)RtlStringCchPrintfW(detail, RTL_NUMBER_OF(detail), L"%ws;value=%wZ", Reason,
                              Context->Detail.Buffer != NULL ? &Context->Detail : &empty);
    RtlInitUnicodeString(&detailString, detail);
    (VOID)MsMonLogEventWithOperation(Context->Type, Context->ProcessId, Context->ProcessStartTime, Context->ThreadId,
                                     MsMonFlagPayloadUnavailable | ExtraFlags, Status,
                                     MsMonCategoryRegistry, Context->Value0, Context->Value1,
                                     Context->Path.Buffer != NULL ? &Context->Path : NULL,
                                     &detailString, Context->OperationId);
}

static VOID MsMonRegistryMetadata(PMSMON_REGISTRY_CONTEXT Context, NTSTATUS Status)
{
    (VOID)MsMonLogEventWithOperation(Context->Type, Context->ProcessId, Context->ProcessStartTime, Context->ThreadId,
                                     Context->Path.Buffer == NULL ? MsMonFlagMissingPath : 0,
                                     Status, MsMonCategoryRegistry, Context->Value0, Context->Value1,
                                     Context->Path.Buffer != NULL ? &Context->Path : NULL,
                                     Context->Detail.Buffer != NULL ? &Context->Detail : NULL,
                                     Context->OperationId);
}

static BOOLEAN MsMonIsPostOperation(REG_NOTIFY_CLASS Operation)
{
    switch (Operation) {
    case RegNtPostDeleteKey:
    case RegNtPostSetValueKey:
    case RegNtPostDeleteValueKey:
    case RegNtPostRenameKey:
    case RegNtPostEnumerateKey:
    case RegNtPostEnumerateValueKey:
    case RegNtPostQueryKey:
    case RegNtPostQueryValueKey:
    case RegNtPostQueryMultipleValueKey:
    case RegNtPostCreateKeyEx:
    case RegNtPostOpenKeyEx:
        return TRUE;
    default:
        return FALSE;
    }
}

static VOID MsMonSetCallContext(REG_NOTIFY_CLASS Operation, PVOID Argument, PVOID Context)
{
    switch (Operation) {
    case RegNtPreOpenKeyEx:
    case RegNtPreCreateKeyEx:
        ((PREG_OPEN_KEY_INFORMATION)Argument)->CallContext = Context;
        break;
    case RegNtPreSetValueKey:
        ((PREG_SET_VALUE_KEY_INFORMATION)Argument)->CallContext = Context;
        break;
    case RegNtPreDeleteKey:
        ((PREG_DELETE_KEY_INFORMATION)Argument)->CallContext = Context;
        break;
    case RegNtPreDeleteValueKey:
        ((PREG_DELETE_VALUE_KEY_INFORMATION)Argument)->CallContext = Context;
        break;
    case RegNtPreRenameKey:
        ((PREG_RENAME_KEY_INFORMATION)Argument)->CallContext = Context;
        break;
    case RegNtPreQueryKey:
        ((PREG_QUERY_KEY_INFORMATION)Argument)->CallContext = Context;
        break;
    case RegNtPreQueryValueKey:
        ((PREG_QUERY_VALUE_KEY_INFORMATION)Argument)->CallContext = Context;
        break;
    case RegNtPreQueryMultipleValueKey:
        ((PREG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION)Argument)->CallContext = Context;
        break;
    case RegNtPreEnumerateKey:
        ((PREG_ENUMERATE_KEY_INFORMATION)Argument)->CallContext = Context;
        break;
    case RegNtPreEnumerateValueKey:
        ((PREG_ENUMERATE_VALUE_KEY_INFORMATION)Argument)->CallContext = Context;
        break;
    default:
        break;
    }
}

static VOID MsMonLogRegistryValue(
    PMSMON_REGISTRY_CONTEXT Context, NTSTATUS Status, ULONG Type,
    const VOID* Data, ULONG DataBytes
)
{
    ULONG captured;
    if (DataBytes > MSMON_MAX_PAYLOAD_TOTAL_BYTES) {
        MsMonRegistryUnavailable(Context, Status, L"payload_too_large", 0);
        return;
    }
    captured = min(DataBytes, MSMON_REGISTRY_CAPTURE_MAX_BYTES);
    (VOID)MsMonLogPayloadSeries(Context->Type, Context->ProcessId, Context->ProcessStartTime, Context->ThreadId,
                                0, Status, MsMonCategoryRegistry,
                                Context->Value0, Type,
                                Context->Path.Buffer != NULL ? &Context->Path : NULL,
                                Context->Detail.Buffer != NULL ? &Context->Detail : NULL,
                                MsMonPayloadRegistryValue, Context->OperationId,
                                DataBytes, Data, captured);
}

static VOID MsMonCaptureSingleValue(
    PMSMON_REGISTRY_CONTEXT Context, NTSTATUS Status, KEY_VALUE_INFORMATION_CLASS InformationClass,
    PVOID Information, ULONG BufferLength, ULONG ReturnedLength
)
{
    if (MsMonRetryStatus(Status)) {
        MsMonRegistryMetadata(Context, Status);
        return;
    }
    if (!NT_SUCCESS(Status)) {
        MsMonRegistryUnavailable(Context, Status, L"query_failed", 0);
        return;
    }
    if (Information == NULL || ReturnedLength > BufferLength) {
        MsMonRegistryUnavailable(Context, Status, L"invalid_result_length", 0);
        return;
    }
    switch (InformationClass) {
    case KeyValuePartialInformation: {
        PKEY_VALUE_PARTIAL_INFORMATION value = (PKEY_VALUE_PARTIAL_INFORMATION)Information;
        ULONG offset = (ULONG)FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data);
        if (ReturnedLength < offset || value->DataLength > ReturnedLength - offset) {
            MsMonRegistryUnavailable(Context, Status, L"partial_value_data", 0);
            return;
        }
        MsMonLogRegistryValue(Context, Status, value->Type, value->Data, value->DataLength);
        return;
    }
    case KeyValuePartialInformationAlign64: {
        PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64 value = (PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64)Information;
        ULONG offset = (ULONG)FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION_ALIGN64, Data);
        if (ReturnedLength < offset || value->DataLength > ReturnedLength - offset) {
            MsMonRegistryUnavailable(Context, Status, L"partial_value_data", 0);
            return;
        }
        MsMonLogRegistryValue(Context, Status, value->Type, value->Data, value->DataLength);
        return;
    }
    case KeyValueFullInformation:
    case KeyValueFullInformationAlign64: {
        PKEY_VALUE_FULL_INFORMATION value = (PKEY_VALUE_FULL_INFORMATION)Information;
        /* An empty value has no data, and its DataOffset need not point inside the buffer. */
        if (value->DataLength == 0) {
            MsMonLogRegistryValue(Context, Status, value->Type, Information, 0);
            return;
        }
        if (value->DataOffset > ReturnedLength || value->DataLength > ReturnedLength - value->DataOffset) {
            MsMonRegistryUnavailable(Context, Status, L"invalid_value_offset", 0);
            return;
        }
        MsMonLogRegistryValue(Context, Status, value->Type,
                              (const UCHAR*)Information + value->DataOffset, value->DataLength);
        return;
    }
    case KeyValueBasicInformation:
    case KeyValueLayerInformation:
        MsMonRegistryMetadata(Context, Status);
        return;
    default:
        MsMonRegistryUnavailable(Context, Status, L"unsupported_information_class", 0);
        return;
    }
}

static VOID MsMonCaptureMultipleValues(
    PMSMON_REGISTRY_CONTEXT Context, NTSTATUS Status, PREG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION Info
)
{
    ULONG returned;
    ULONG capacity;
    ULONG index;
    if (MsMonRetryStatus(Status)) {
        MsMonRegistryMetadata(Context, Status);
        return;
    }
    if (!NT_SUCCESS(Status)) {
        MsMonRegistryUnavailable(Context, Status, L"multi_query_failed", 0);
        return;
    }
    if (Info->ValueBuffer == NULL || Info->ValueEntries == NULL ||
        Info->BufferLength == NULL || Info->RequiredBufferLength == NULL) {
        MsMonRegistryUnavailable(Context, Status, L"missing_multi_result", 0);
        return;
    }
    capacity = *Info->BufferLength;
    returned = *Info->RequiredBufferLength;
    if (returned > capacity) {
        MsMonRegistryUnavailable(Context, Status, L"partial_multi_result", 0);
        return;
    }
    for (index = 0; index < Info->EntryCount; index++) {
        PKEY_VALUE_ENTRY entry = &Info->ValueEntries[index];
        MSMON_REGISTRY_CONTEXT valueContext = *Context;
        if (entry->DataOffset > returned || entry->DataLength > returned - entry->DataOffset) {
            MsMonRegistryUnavailable(Context, Status, L"invalid_multi_value_offset", 0);
            continue;
        }
        valueContext.OperationId = MsMonNextOperationId();
        valueContext.Value0 = index;
        valueContext.Value1 = entry->Type;
        if (entry->ValueName != NULL) valueContext.Detail = *entry->ValueName;
        MsMonLogRegistryValue(&valueContext, Status, entry->Type,
                              (const UCHAR*)Info->ValueBuffer + entry->DataOffset,
                              entry->DataLength);
    }
}

static VOID MsMonSetResultName(
    PMSMON_REGISTRY_CONTEXT Context, PCWSTR Name, ULONG NameBytes, ULONG AvailableBytes
)
{
    if (Name == NULL || NameBytes > AvailableBytes) return;
    Context->Detail.Buffer = (PWSTR)Name;
    Context->Detail.Length = (USHORT)min(NameBytes, MSMON_MAX_EVENT_STRING_BYTES);
    Context->Detail.MaximumLength = Context->Detail.Length;
}

static VOID MsMonCaptureRegistryResult(
    REG_NOTIFY_CLASS Operation, PREG_POST_OPERATION_INFORMATION Post,
    PMSMON_REGISTRY_CONTEXT Context, BOOLEAN CapturePayload
)
{
    __try {
        switch (Operation) {
        case RegNtPostQueryValueKey: {
            PREG_QUERY_VALUE_KEY_INFORMATION info = (PREG_QUERY_VALUE_KEY_INFORMATION)Post->PreInformation;
            ULONG returned = info->ResultLength != NULL ? *info->ResultLength : info->Length;
            MsMonCaptureSingleValue(Context, Post->Status, info->KeyValueInformationClass,
                                    info->KeyValueInformation, info->Length, returned);
            return;
        }
        case RegNtPostEnumerateValueKey: {
            PREG_ENUMERATE_VALUE_KEY_INFORMATION info = (PREG_ENUMERATE_VALUE_KEY_INFORMATION)Post->PreInformation;
            ULONG returned = info->ResultLength != NULL ? *info->ResultLength : info->Length;
            MSMON_REGISTRY_CONTEXT named = *Context;
            if (NT_SUCCESS(Post->Status) && returned <= info->Length) {
                if (info->KeyValueInformationClass == KeyValueBasicInformation && returned >= sizeof(KEY_VALUE_BASIC_INFORMATION)) {
                    PKEY_VALUE_BASIC_INFORMATION value = (PKEY_VALUE_BASIC_INFORMATION)info->KeyValueInformation;
                    ULONG offset = (ULONG)FIELD_OFFSET(KEY_VALUE_BASIC_INFORMATION, Name);
                    if (returned >= offset) MsMonSetResultName(&named, value->Name, value->NameLength, returned - offset);
                } else if ((info->KeyValueInformationClass == KeyValueFullInformation ||
                            info->KeyValueInformationClass == KeyValueFullInformationAlign64) &&
                           returned >= sizeof(KEY_VALUE_FULL_INFORMATION)) {
                    PKEY_VALUE_FULL_INFORMATION value = (PKEY_VALUE_FULL_INFORMATION)info->KeyValueInformation;
                    ULONG offset = (ULONG)FIELD_OFFSET(KEY_VALUE_FULL_INFORMATION, Name);
                    if (returned >= offset) MsMonSetResultName(&named, value->Name, value->NameLength, returned - offset);
                }
            }
            if (CapturePayload) {
                MsMonCaptureSingleValue(&named, Post->Status, info->KeyValueInformationClass,
                                        info->KeyValueInformation, info->Length, returned);
            } else {
                MsMonRegistryMetadata(&named, Post->Status);
            }
            return;
        }
        case RegNtPostEnumerateKey: {
            PREG_ENUMERATE_KEY_INFORMATION info = (PREG_ENUMERATE_KEY_INFORMATION)Post->PreInformation;
            ULONG returned = info->ResultLength != NULL ? *info->ResultLength : info->Length;
            MSMON_REGISTRY_CONTEXT named = *Context;
            if (NT_SUCCESS(Post->Status) && returned <= info->Length) {
                if (info->KeyInformationClass == KeyBasicInformation && returned >= sizeof(KEY_BASIC_INFORMATION)) {
                    PKEY_BASIC_INFORMATION value = (PKEY_BASIC_INFORMATION)info->KeyInformation;
                    ULONG offset = (ULONG)FIELD_OFFSET(KEY_BASIC_INFORMATION, Name);
                    if (returned >= offset) MsMonSetResultName(&named, value->Name, value->NameLength, returned - offset);
                } else if (info->KeyInformationClass == KeyNameInformation && returned >= sizeof(KEY_NAME_INFORMATION)) {
                    PKEY_NAME_INFORMATION value = (PKEY_NAME_INFORMATION)info->KeyInformation;
                    ULONG offset = (ULONG)FIELD_OFFSET(KEY_NAME_INFORMATION, Name);
                    if (returned >= offset) MsMonSetResultName(&named, value->Name, value->NameLength, returned - offset);
                }
            }
            MsMonRegistryMetadata(&named, Post->Status);
            return;
        }
        case RegNtPostQueryMultipleValueKey:
            MsMonCaptureMultipleValues(Context, Post->Status,
                                       (PREG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION)Post->PreInformation);
            return;
        default:
            MsMonRegistryMetadata(Context, Post->Status);
            return;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        MsMonRegistryUnavailable(Context, Post->Status, L"unsafe_result_buffer", 0);
    }
}

static NTSTATUS MsMonRegistryCallback(PVOID CallbackContext, PVOID Argument1, PVOID Argument2)
{
    REG_NOTIFY_CLASS operation = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    PMSMON_REGISTRY_CONTEXT context = NULL;
    PCUNICODE_STRING path = NULL;
    PCUNICODE_STRING detail = NULL;
    ULONG type = MsMonRegistryOpen;
    ULONG desiredAccess = 0;
    ULONGLONG value0 = 0;
    ULONGLONG value1 = 0;

    UNREFERENCED_PARAMETER(CallbackContext);
    MsMonCoverageEnter(MSMON_SENSOR_REGISTRY_CALLBACK);
    if (MsMonIsPostOperation(operation)) {
        PREG_POST_OPERATION_INFORMATION post = (PREG_POST_OPERATION_INFORMATION)Argument2;
        context = (PMSMON_REGISTRY_CONTEXT)post->CallContext;
        if (context == NULL) return STATUS_SUCCESS;
        BOOLEAN capturePayload = MsMonPayloadEnabled();
        if (operation == RegNtPostEnumerateKey || operation == RegNtPostEnumerateValueKey ||
            (capturePayload && (operation == RegNtPostQueryValueKey || operation == RegNtPostQueryMultipleValueKey))) {
            MsMonCaptureRegistryResult(operation, post, context, capturePayload);
        } else {
            MsMonRegistryMetadata(context, post->Status);
        }
        MsMonCoverageLogged(MSMON_SENSOR_REGISTRY_CALLBACK);
        ExFreePoolWithTag(context, MSMON_POOL_TAG);
        return STATUS_SUCCESS;
    }
    if (!MsMonIsTracked(PsGetCurrentProcessId(), 0) && !MsMonCurrentIsBlackCat()) {
        MsMonCoverageSkip(MSMON_SKIP_UNTRACKED);
        return STATUS_SUCCESS;
    }

    switch (operation) {
    case RegNtPreOpenKeyEx:
    case RegNtPreCreateKeyEx: {
        PREG_OPEN_KEY_INFORMATION info = (PREG_OPEN_KEY_INFORMATION)Argument2;
        path = info->CompleteName;
        desiredAccess = info->DesiredAccess;
        type = operation == RegNtPreOpenKeyEx ? MsMonRegistryOpen : MsMonRegistryCreate;
        break;
    }
    case RegNtPreSetValueKey: {
        PREG_SET_VALUE_KEY_INFORMATION info = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
        path = MsMonRegistryPath(info->Object);
        detail = info->ValueName;
        value0 = info->DataSize;
        value1 = info->Type;
        type = MsMonRegistrySetValue;
        break;
    }
    case RegNtPreDeleteKey: {
        PREG_DELETE_KEY_INFORMATION info = (PREG_DELETE_KEY_INFORMATION)Argument2;
        path = MsMonRegistryPath(info->Object);
        type = MsMonRegistryDelete;
        break;
    }
    case RegNtPreDeleteValueKey: {
        PREG_DELETE_VALUE_KEY_INFORMATION info = (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;
        path = MsMonRegistryPath(info->Object);
        detail = info->ValueName;
        type = MsMonRegistryDelete;
        break;
    }
    case RegNtPreRenameKey: {
        PREG_RENAME_KEY_INFORMATION info = (PREG_RENAME_KEY_INFORMATION)Argument2;
        path = MsMonRegistryPath(info->Object);
        detail = info->NewName;
        type = MsMonRegistryRename;
        break;
    }
    case RegNtPreQueryKey: {
        PREG_QUERY_KEY_INFORMATION info = (PREG_QUERY_KEY_INFORMATION)Argument2;
        path = MsMonRegistryPath(info->Object);
        value0 = info->KeyInformationClass;
        type = MsMonRegistryQuery;
        break;
    }
    case RegNtPreQueryValueKey: {
        PREG_QUERY_VALUE_KEY_INFORMATION info = (PREG_QUERY_VALUE_KEY_INFORMATION)Argument2;
        path = MsMonRegistryPath(info->Object);
        detail = info->ValueName;
        value0 = info->KeyValueInformationClass;
        type = MsMonRegistryQuery;
        break;
    }
    case RegNtPreQueryMultipleValueKey: {
        PREG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION info = (PREG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION)Argument2;
        path = MsMonRegistryPath(info->Object);
        value0 = info->EntryCount;
        type = MsMonRegistryQuery;
        break;
    }
    case RegNtPreEnumerateKey: {
        PREG_ENUMERATE_KEY_INFORMATION info = (PREG_ENUMERATE_KEY_INFORMATION)Argument2;
        path = MsMonRegistryPath(info->Object);
        value0 = info->Index;
        value1 = info->KeyInformationClass;
        type = MsMonRegistryEnumerate;
        break;
    }
    case RegNtPreEnumerateValueKey: {
        PREG_ENUMERATE_VALUE_KEY_INFORMATION info = (PREG_ENUMERATE_VALUE_KEY_INFORMATION)Argument2;
        path = MsMonRegistryPath(info->Object);
        value0 = info->Index;
        value1 = info->KeyValueInformationClass;
        type = MsMonRegistryEnumerate;
        break;
    }
    default:
        return STATUS_SUCCESS;
    }

    context = MsMonCreateContext(type, path, detail, value0, value1, desiredAccess);
    if (context == NULL) {
        MsMonCoverageSkip(MSMON_SKIP_ALLOC);
        MsMonEventsNoteDropped();
        return STATUS_SUCCESS;
    }
    MsMonSetCallContext(operation, Argument2, context);
    if (MsMonPayloadEnabled() && operation == RegNtPreSetValueKey) {
        PREG_SET_VALUE_KEY_INFORMATION info = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
        if (info->DataSize > MSMON_MAX_PAYLOAD_TOTAL_BYTES) {
            MsMonRegistryUnavailable(context, STATUS_PENDING, L"payload_too_large", MsMonFlagPayloadInput);
        } else {
            ULONG captured = min(info->DataSize, MSMON_REGISTRY_CAPTURE_MAX_BYTES);
            __try {
                (VOID)MsMonLogPayloadSeries(MsMonRegistrySetValue, context->ProcessId, context->ProcessStartTime, context->ThreadId,
                                            MsMonFlagPayloadInput, STATUS_PENDING, MsMonCategoryRegistry,
                                            context->Value0, context->Value1,
                                            context->Path.Buffer != NULL ? &context->Path : NULL,
                                            context->Detail.Buffer != NULL ? &context->Detail : NULL,
                                            MsMonPayloadRegistryValue, context->OperationId,
                                            info->DataSize, info->Data, captured);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                MsMonRegistryUnavailable(context, STATUS_PENDING, L"unsafe_set_buffer", MsMonFlagPayloadInput);
            }
        }
    }
    return STATUS_SUCCESS;
}

NTSTATUS MsMonRegistryInitialize(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING altitude;
    NTSTATUS status;
    RtlInitUnicodeString(&altitude, L"380010");
    status = CmRegisterCallbackEx(MsMonRegistryCallback, &altitude, DriverObject,
                                  NULL, &gRegistryCookie, NULL);
    gRegistryRegistered = NT_SUCCESS(status);
    MsMonCoverageRegister(MSMON_SENSOR_REG_REGISTRY, status);
    return status;
}

VOID MsMonRegistryUninitialize(VOID)
{
    if (gRegistryRegistered) {
        (VOID)CmUnRegisterCallback(gRegistryCookie);
        gRegistryRegistered = FALSE;
    }
}
