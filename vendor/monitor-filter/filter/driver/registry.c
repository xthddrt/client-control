#include "kf.h"

/*
 * Registry enforcement. Key/value open is the gate; query/enumerate/set/
 * delete/rename/load/save/restore/security classes cover handles opened before
 * the current policy. Relative names are resolved against RootObject because a
 * bare "Certificates" must not become a root-level key.
 */

static LARGE_INTEGER gCookie;
static BOOLEAN gRegistered;

static PCUNICODE_STRING KfKeyPath(PVOID Object)
{
    PCUNICODE_STRING name = NULL;
    if (Object == NULL) return NULL;
    if (!NT_SUCCESS(CmCallbackGetKeyObjectID(&gCookie, Object, NULL, &name))) return NULL;
    return name;
}

static BOOLEAN KfIsAbsoluteName(PCUNICODE_STRING Name)
{
    return Name != NULL && Name->Buffer != NULL &&
           Name->Length >= sizeof(WCHAR) && Name->Buffer[0] == L'\\';
}

static NTSTATUS KfResolveKeyName(PVOID RootObject, PCUNICODE_STRING Name,
                                 PWSTR Buffer, ULONG BufferCharacters, PUNICODE_STRING Result)
{
    PCUNICODE_STRING parent;
    ULONG characters;

    if (Name == NULL || Name->Buffer == NULL || Name->Length == 0) return STATUS_INVALID_PARAMETER;
    if (KfIsAbsoluteName(Name)) {
        *Result = *Name;
        return STATUS_SUCCESS;
    }
    parent = KfKeyPath(RootObject);
    if (parent == NULL || parent->Buffer == NULL || parent->Length == 0) return STATUS_NOT_FOUND;
    characters = parent->Length / sizeof(WCHAR) + 1 + Name->Length / sizeof(WCHAR);
    if (characters + 1 > BufferCharacters) return STATUS_BUFFER_OVERFLOW;
    RtlCopyMemory(Buffer, parent->Buffer, parent->Length);
    Buffer[parent->Length / sizeof(WCHAR)] = L'\\';
    RtlCopyMemory(Buffer + parent->Length / sizeof(WCHAR) + 1, Name->Buffer, Name->Length);
    Buffer[characters] = L'\0';
    Result->Buffer = Buffer;
    Result->Length = (USHORT)(characters * sizeof(WCHAR));
    Result->MaximumLength = Result->Length;
    return STATUS_SUCCESS;
}

/*
 * A key open whose full name cannot be built is refused by the name-failure rule. Record
 * what is known, the root key's name (if any), the relative name and why it failed, as a
 * separate name-failure event, so the log can say which key it was. The decision is
 * unchanged.
 */
static VOID KfLogNameFailure(PVOID RootObject, PCUNICODE_STRING Name, NTSTATUS Reason, ULONG DesiredAccess)
{
    static const UNICODE_STRING unknown = RTL_CONSTANT_STRING(L"?");
    static const UNICODE_STRING empty = RTL_CONSTANT_STRING(L"(empty)");
    PCUNICODE_STRING root = KfIsAbsoluteName(Name) ? NULL : KfKeyPath(RootObject);
    WCHAR text[KFILTER_MAX_NAME];
    UNICODE_STRING diagnostic;

    (VOID)RtlStringCchPrintfW(text, KFILTER_MAX_NAME, L"(unresolved 0x%08X) %wZ\\%wZ", (ULONG)Reason,
                              root != NULL && root->Buffer != NULL ? root : &unknown,
                              Name != NULL && Name->Buffer != NULL && Name->Length != 0 ? Name : &empty);
    RtlInitUnicodeString(&diagnostic, text);
    KfLogEvent(KFILTER_TARGET_REGISTRY, KFilterActionAudit, KFILTER_EVENT_FLAG_NAME_FAILURE, Reason,
               KfRightsFromRegistryAccess(DesiredAccess), 0, &diagnostic);
}

static NTSTATUS KfRenamePath(PCUNICODE_STRING Source, PCUNICODE_STRING NewName,
                             PWSTR Buffer, PUNICODE_STRING Result)
{
    ULONG parent;
    ULONG length;
    if (Source == NULL || Source->Buffer == NULL || NewName == NULL ||
        NewName->Buffer == NULL || NewName->Length == 0) return STATUS_INVALID_PARAMETER;
    if (KfIsAbsoluteName(NewName)) {
        *Result = *NewName;
        return STATUS_SUCCESS;
    }
    parent = Source->Length / sizeof(WCHAR);
    while (parent > 0 && Source->Buffer[parent - 1] != L'\\') parent--;
    length = parent + NewName->Length / sizeof(WCHAR);
    if (parent == 0 || length + 1 > KFILTER_MAX_NAME) return STATUS_BUFFER_OVERFLOW;
    RtlCopyMemory(Buffer, Source->Buffer, parent * sizeof(WCHAR));
    RtlCopyMemory(Buffer + parent, NewName->Buffer, NewName->Length);
    Buffer[length] = L'\0';
    Result->Buffer = Buffer;
    Result->Length = (USHORT)(length * sizeof(WCHAR));
    Result->MaximumLength = Result->Length;
    return STATUS_SUCCESS;
}

static NTSTATUS KfCheckPathRights(PCUNICODE_STRING Path, ULONG Rights,
                                  PCUNICODE_STRING Value, ULONG* RuleId, BOOLEAN* NameFailure)
{
    BOOLEAN deny = KfDecideWithRights(KFILTER_TARGET_REGISTRY, Path, Rights, Value, 0,
                                      RuleId, NameFailure, NULL, 0);
    return deny ? STATUS_ACCESS_DENIED : STATUS_SUCCESS;
}

static NTSTATUS KfCheckPath(PCUNICODE_STRING Path, ULONG DesiredAccess,
                            PCUNICODE_STRING Value, ULONG* RuleId, BOOLEAN* NameFailure)
{
    return KfCheckPathRights(Path, KfRightsFromRegistryAccess(DesiredAccess),
                             Value, RuleId, NameFailure);
}

/*
 * RegNtPreEnumerateValueKey has no value name, so a value= deny cannot be
 * tested here. RegEnumValue returns the value data as well as the name, so a
 * key covered by any value-scoped deny refuses value enumeration in block mode.
 */
static NTSTATUS KfCheckValueEnumeration(PCUNICODE_STRING Path)
{
    ULONG ruleId = 0;
    ULONG mode;

    if (!KfPolicyBlockRegistry()) return STATUS_SUCCESS;
    if (KfPolicyRawDiskDegraded()) {
        KfCountDenied();
        KfLogEvent(KFILTER_TARGET_REGISTRY, KFilterActionDeny, 0, STATUS_ACCESS_DENIED,
                   KFILTER_RIGHT_ENUMERATE, 0, Path);
        return STATUS_ACCESS_DENIED;
    }
    if (!KfPolicyValueEnumerationDenied(Path, &ruleId)) return STATUS_SUCCESS;
    mode = KfPolicyMode();
    if (mode == KFILTER_MODE_BLOCK) {
        KfLogEvent(KFILTER_TARGET_REGISTRY, KFilterActionDeny, 0, STATUS_ACCESS_DENIED,
                   KFILTER_RIGHT_ENUMERATE, ruleId, Path);
        return STATUS_ACCESS_DENIED;
    }
    if (mode == KFILTER_MODE_AUDIT) {
        KfLogEvent(KFILTER_TARGET_REGISTRY, KFilterActionAudit,
                   KFILTER_EVENT_FLAG_WOULD_DENY, STATUS_ACCESS_DENIED,
                   KFILTER_RIGHT_ENUMERATE, ruleId, Path);
    }
    return STATUS_SUCCESS;
}

static NTSTATUS KfRegistryCallback(PVOID CallbackContext, PVOID Argument1, PVOID Argument2)
{
    REG_NOTIFY_CLASS operation = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    PCUNICODE_STRING path = NULL;
    PCUNICODE_STRING value = NULL;
    ULONG desiredAccess = 0;
    ULONG rights = 0;
    ULONG ruleId = 0;
    BOOLEAN nameFailure = FALSE;
    WCHAR buffer[KFILTER_MAX_NAME];
    UNICODE_STRING resolved;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(CallbackContext);
    if (Argument2 == NULL) return STATUS_SUCCESS;
    if (!KfProcessIsProtectedCurrent()) return STATUS_SUCCESS;

    switch (operation) {
    case RegNtPreOpenKeyEx:
    case RegNtPreCreateKeyEx: {
        PREG_CREATE_KEY_INFORMATION information = (PREG_CREATE_KEY_INFORMATION)Argument2;
        status = KfResolveKeyName(information->RootObject, information->CompleteName,
                                  buffer, KFILTER_MAX_NAME, &resolved);
        if (NT_SUCCESS(status)) {
            path = &resolved;
        } else {
            KfCountNameFailure();
            KfLogNameFailure(information->RootObject, information->CompleteName, status,
                             information->DesiredAccess);
        }
        desiredAccess = information->DesiredAccess;
        break;
    }
    case RegNtPreLoadKey: {
        PREG_LOAD_KEY_INFORMATION information = (PREG_LOAD_KEY_INFORMATION)Argument2;
        status = KfResolveKeyName(information->Object, information->KeyName,
                                  buffer, KFILTER_MAX_NAME, &resolved);
        if (NT_SUCCESS(status)) {
            path = &resolved;
        } else {
            KfCountNameFailure();
            KfLogNameFailure(information->Object, information->KeyName, status, information->DesiredAccess);
        }
        desiredAccess = information->DesiredAccess;
        break;
    }
    case RegNtPreQueryKey:
        path = KfKeyPath(((PREG_QUERY_KEY_INFORMATION)Argument2)->Object);
        desiredAccess = 0x0001u; /* query value */
        break;
    case RegNtPreQueryValueKey: {
        PREG_QUERY_VALUE_KEY_INFORMATION information = (PREG_QUERY_VALUE_KEY_INFORMATION)Argument2;
        path = KfKeyPath(information->Object);
        value = information->ValueName;
        desiredAccess = 0x0001u;
        break;
    }
    case RegNtPreQueryMultipleValueKey: {
        PREG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION information =
            (PREG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION)Argument2;
        ULONG index;
        path = KfKeyPath(information->Object);
        desiredAccess = 0x0001u;
        if (information->EntryCount > 64 ||
            (information->EntryCount != 0 && information->ValueEntries == NULL)) {
            return KfCheckPath(NULL, desiredAccess, NULL, &ruleId, &nameFailure);
        }
        for (index = 0; index < information->EntryCount; index++) {
            status = KfCheckPath(path, desiredAccess, information->ValueEntries[index].ValueName,
                                 &ruleId, &nameFailure);
            if (!NT_SUCCESS(status)) return status;
        }
        return STATUS_SUCCESS;
    }
    case RegNtPreEnumerateKey:
        path = KfKeyPath(((PREG_ENUMERATE_KEY_INFORMATION)Argument2)->Object);
        rights = KFILTER_RIGHT_ENUMERATE;
        break;
    case RegNtPreEnumerateValueKey:
        path = KfKeyPath(((PREG_ENUMERATE_VALUE_KEY_INFORMATION)Argument2)->Object);
        status = KfCheckValueEnumeration(path);
        if (!NT_SUCCESS(status)) return status;
        rights = KFILTER_RIGHT_ENUMERATE;
        break;
    case RegNtPreSetValueKey: {
        PREG_SET_VALUE_KEY_INFORMATION information = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
        path = KfKeyPath(information->Object);
        value = information->ValueName;
        desiredAccess = 0x0002u;
        break;
    }
    case RegNtPreDeleteValueKey: {
        PREG_DELETE_VALUE_KEY_INFORMATION information = (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;
        path = KfKeyPath(information->Object);
        value = information->ValueName;
        desiredAccess = 0x00010000u; /* DELETE */
        break;
    }
    case RegNtPreDeleteKey:
        path = KfKeyPath(((PREG_DELETE_KEY_INFORMATION)Argument2)->Object);
        desiredAccess = 0x00010000u;
        break;
    case RegNtPreRenameKey: {
        PREG_RENAME_KEY_INFORMATION information = (PREG_RENAME_KEY_INFORMATION)Argument2;
        PCUNICODE_STRING sourceName = KfKeyPath(information->Object);
        if (sourceName == NULL || sourceName->Buffer == NULL) {
            return KfDecideWithRights(KFILTER_TARGET_REGISTRY, NULL, KFILTER_RIGHT_RENAME,
                                      NULL, 0, &ruleId, &nameFailure, NULL, 0)
                       ? STATUS_ACCESS_DENIED : STATUS_SUCCESS;
        }
        if (KfDecideWithRights(KFILTER_TARGET_REGISTRY, sourceName, KFILTER_RIGHT_RENAME,
                               NULL, 0, &ruleId, &nameFailure, NULL, 0)) return STATUS_ACCESS_DENIED;
        status = KfRenamePath(sourceName, information->NewName, buffer, &resolved);
        if (!NT_SUCCESS(status)) {
            return KfDecideWithRights(KFILTER_TARGET_REGISTRY, NULL, KFILTER_RIGHT_RENAME,
                                      NULL, 0, &ruleId, &nameFailure, NULL, 0)
                       ? STATUS_ACCESS_DENIED : STATUS_SUCCESS;
        }
        return KfDecideWithRights(KFILTER_TARGET_REGISTRY, &resolved, KFILTER_RIGHT_RENAME,
                                  NULL, 0, &ruleId, &nameFailure, NULL, 0)
                   ? STATUS_ACCESS_DENIED : STATUS_SUCCESS;
    }
    case RegNtPreQueryKeySecurity:
        path = KfKeyPath(((PREG_QUERY_KEY_SECURITY_INFORMATION)Argument2)->Object);
        desiredAccess = 0x00020000u;
        break;
    case RegNtPreSetKeySecurity:
        path = KfKeyPath(((PREG_SET_KEY_SECURITY_INFORMATION)Argument2)->Object);
        desiredAccess = 0x00040000u;
        break;
    case RegNtPreSaveKey:
        path = KfKeyPath(((PREG_SAVE_KEY_INFORMATION)Argument2)->Object);
        desiredAccess = 0x0001u;
        break;
    case RegNtPreRestoreKey:
        path = KfKeyPath(((PREG_RESTORE_KEY_INFORMATION)Argument2)->Object);
        desiredAccess = 0x0002u;
        break;
    case RegNtPreReplaceKey:
        path = KfKeyPath(((PREG_REPLACE_KEY_INFORMATION)Argument2)->Object);
        desiredAccess = 0x0002u;
        break;
    case RegNtPreUnLoadKey:
        path = KfKeyPath(((PREG_UNLOAD_KEY_INFORMATION)Argument2)->Object);
        desiredAccess = 0x00010000u;
        break;
    default:
        return STATUS_SUCCESS;
    }

    if (rights != 0) return KfCheckPathRights(path, rights, value, &ruleId, &nameFailure);
    return KfCheckPath(path, desiredAccess, value, &ruleId, &nameFailure);
}

NTSTATUS KfRegistryInitialize(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING altitude;
    NTSTATUS status;

    RtlInitUnicodeString(&altitude, L"389002");
    status = CmRegisterCallbackEx(KfRegistryCallback, &altitude, DriverObject, NULL, &gCookie, NULL);
    gRegistered = NT_SUCCESS(status);
    return status;
}

VOID KfRegistryUninitialize(VOID)
{
    if (gRegistered) {
        (VOID)CmUnRegisterCallback(gCookie);
        gRegistered = FALSE;
    }
}
