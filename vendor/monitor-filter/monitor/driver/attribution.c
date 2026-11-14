#include "msmon.h"
#include <aux_klib.h>

static KSPIN_LOCK gAttributionLock;
static ULONG_PTR gBlackCatBase;
static ULONG gBlackCatSize;
static BOOLEAN gBlackCatLoaded;
static BOOLEAN gRefreshCompleted;
static WCHAR gBlackCatName[64];

NTSTATUS MsMonAttributionInitialize(VOID)
{
    KeInitializeSpinLock(&gAttributionLock);
    gBlackCatBase = 0;
    gBlackCatSize = 0;
    gBlackCatLoaded = FALSE;
    gRefreshCompleted = FALSE;
    gBlackCatName[0] = L'\0';
    return AuxKlibInitialize();
}

VOID MsMonAttributionStop(VOID)
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&gAttributionLock, &oldIrql);
    gBlackCatBase = 0;
    gBlackCatSize = 0;
    gBlackCatLoaded = FALSE;
    gRefreshCompleted = FALSE;
    gBlackCatName[0] = L'\0';
    KeReleaseSpinLock(&gAttributionLock, oldIrql);
}

static CHAR MsMonLowerChar(CHAR Value)
{
    return Value >= 'A' && Value <= 'Z' ? Value + ('a' - 'A') : Value;
}

/* BlackCat images are named BlackCat<digits>.sys, for example BlackCat1.sys or BlackCat64.sys. */
static BOOLEAN MsMonBlackCatBaseName(PCSTR Base)
{
    static const CHAR prefix[] = "blackcat";
    static const CHAR suffix[] = ".sys";
    PCSTR cursor;
    ULONG index;
    for (index = 0; index < ARRAYSIZE(prefix) - 1; index++) {
        if (Base[index] == '\0' || MsMonLowerChar(Base[index]) != prefix[index]) return FALSE;
    }
    cursor = Base + ARRAYSIZE(prefix) - 1;
    if (*cursor < '0' || *cursor > '9') return FALSE;
    while (*cursor >= '0' && *cursor <= '9') cursor++;
    /*
     * Compare the suffix characters, then require the terminator.  Looping over
     * ARRAYSIZE(suffix) also visited the terminator, where the '\0' test
     * returned FALSE, so no name ever matched and BlackCat was never detected.
     */
    for (index = 0; index < ARRAYSIZE(suffix) - 1; index++) {
        if (cursor[index] == '\0' || MsMonLowerChar(cursor[index]) != suffix[index]) return FALSE;
    }
    return cursor[ARRAYSIZE(suffix) - 1] == '\0';
}

static BOOLEAN MsMonBlackCatName(PCSTR Path)
{
    PCSTR base = Path;
    PCSTR cursor;
    if (Path == NULL) return FALSE;
    for (cursor = Path; cursor - Path < AUX_KLIB_MODULE_PATH_LEN && *cursor != '\0'; cursor++) {
        if (*cursor == '\\' || *cursor == '/') base = cursor + 1;
    }
    if (cursor - Path == AUX_KLIB_MODULE_PATH_LEN) return FALSE;
    return MsMonBlackCatBaseName(base);
}

/*
 * Called from the load-image callback for kernel images.  BlackCat's
 * DriverEntry runs right after this notification, before the agent's
 * once-per-second refresh would see the module, so record the image range
 * here to make its first operations attributable.
 */
VOID MsMonAttributionNoteImage(PCUNICODE_STRING FullImageName, PVOID ImageBase, SIZE_T ImageSize)
{
    CHAR baseName[64];
    WCHAR wideName[64];
    WCHAR detail[160];
    UNICODE_STRING text;
    UNICODE_STRING detailString;
    USHORT characters;
    USHORT start = 0;
    USHORT length;
    USHORT index;
    KIRQL oldIrql;

    if (FullImageName == NULL || FullImageName->Buffer == NULL || ImageBase == NULL ||
        ImageSize == 0 || ImageSize > MAXULONG) return;
    characters = (USHORT)(FullImageName->Length / sizeof(WCHAR));
    for (index = 0; index < characters; index++) {
        if (FullImageName->Buffer[index] == L'\\' || FullImageName->Buffer[index] == L'/') start = (USHORT)(index + 1);
    }
    length = (USHORT)(characters - start);
    if (length == 0 || length >= RTL_NUMBER_OF(baseName)) return;
    for (index = 0; index < length; index++) {
        WCHAR value = FullImageName->Buffer[start + index];
        if (value == L'\0' || value > 0x7f) return;
        baseName[index] = (CHAR)value;
        wideName[index] = value;
    }
    baseName[length] = '\0';
    wideName[length] = L'\0';
    if (!MsMonBlackCatBaseName(baseName)) return;

    KeAcquireSpinLock(&gAttributionLock, &oldIrql);
    gBlackCatBase = (ULONG_PTR)ImageBase;
    gBlackCatSize = (ULONG)ImageSize;
    gBlackCatLoaded = TRUE;
    RtlCopyMemory(gBlackCatName, wideName, (length + 1) * sizeof(WCHAR));
    KeReleaseSpinLock(&gAttributionLock, oldIrql);

    RtlInitUnicodeString(&text, L"blackcat_loaded");
    (VOID)RtlStringCchPrintfW(detail, RTL_NUMBER_OF(detail), L"name=%ws;base=0x%p;size=0x%lx;source=image_load",
                              wideName, ImageBase, (ULONG)ImageSize);
    RtlInitUnicodeString(&detailString, detail);
    (VOID)MsMonLogEvent(MsMonCoverage, PsGetCurrentProcessId(), MsMonProcessStartTime(PsGetCurrentProcessId()), NULL, PsGetCurrentThreadId(),
                        NULL, 0, MsMonFlagObserverRecord, STATUS_SUCCESS, 0,
                        MsMonCategoryUnknown, (ULONG_PTR)ImageBase, ImageSize, &text, &detailString);
}

/* The loaded BlackCat image's file name, for the component field of events it caused. */
UNICODE_STRING MsMonBlackCatComponent(BOOLEAN Active, PWCHAR Buffer, USHORT Characters)
{
    static const WCHAR fallback[] = L"BlackCat";
    UNICODE_STRING result;
    KIRQL oldIrql;
    USHORT length = 0;

    result.Buffer = Buffer;
    result.Length = 0;
    result.MaximumLength = (USHORT)(Characters * sizeof(WCHAR));
    if (!Active || Buffer == NULL || Characters == 0) return result;
    KeAcquireSpinLock(&gAttributionLock, &oldIrql);
    while (length + 1 < Characters && length < RTL_NUMBER_OF(gBlackCatName) && gBlackCatName[length] != L'\0') {
        Buffer[length] = gBlackCatName[length];
        length++;
    }
    KeReleaseSpinLock(&gAttributionLock, oldIrql);
    if (length == 0) {
        while (length + 1 < Characters && fallback[length] != L'\0') {
            Buffer[length] = fallback[length];
            length++;
        }
    }
    Buffer[length] = L'\0';
    result.Length = (USHORT)(length * sizeof(WCHAR));
    return result;
}

NTSTATUS MsMonAttributionRefresh(VOID)
{
    ULONG bytes = 0;
    NTSTATUS status = AuxKlibQueryModuleInformation(&bytes, sizeof(AUX_MODULE_EXTENDED_INFO), NULL);
    PAUX_MODULE_EXTENDED_INFO modules;
    ULONG count;
    ULONG index;
    ULONG_PTR base = 0;
    ULONG imageSize = 0;
    BOOLEAN loaded = FALSE;
    BOOLEAN changed;
    WCHAR moduleName[64] = L"";
    KIRQL oldIrql;

    if (!NT_SUCCESS(status) && status != STATUS_BUFFER_TOO_SMALL) return status;
    if (bytes == 0) return STATUS_INVALID_BUFFER_SIZE;
    modules = ExAllocatePool2(POOL_FLAG_PAGED, bytes, MSMON_POOL_TAG);
    if (modules == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    status = AuxKlibQueryModuleInformation(&bytes, sizeof(AUX_MODULE_EXTENDED_INFO), modules);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(modules, MSMON_POOL_TAG);
        return status;
    }
    count = bytes / sizeof(AUX_MODULE_EXTENDED_INFO);
    for (index = 0; index < count; index++) {
        PCSTR path = (PCSTR)modules[index].FullPathName;
        if (MsMonBlackCatName(path)) {
            PCSTR name = path;
            PCSTR cursor;
            for (cursor = path; *cursor != '\0'; cursor++) {
                if (*cursor == '\\' || *cursor == '/') name = cursor + 1;
            }
            (VOID)RtlStringCchPrintfW(moduleName, RTL_NUMBER_OF(moduleName), L"%hs", name);
            base = (ULONG_PTR)modules[index].BasicInfo.ImageBase;
            imageSize = modules[index].ImageSize;
            loaded = TRUE;
            break;
        }
    }
    ExFreePoolWithTag(modules, MSMON_POOL_TAG);

    KeAcquireSpinLock(&gAttributionLock, &oldIrql);
    changed = !gRefreshCompleted || loaded != gBlackCatLoaded ||
              base != gBlackCatBase || imageSize != gBlackCatSize;
    gRefreshCompleted = TRUE;
    gBlackCatLoaded = loaded;
    gBlackCatBase = base;
    gBlackCatSize = imageSize;
    RtlCopyMemory(gBlackCatName, moduleName, sizeof(gBlackCatName));
    KeReleaseSpinLock(&gAttributionLock, oldIrql);

    if (changed) {
        WCHAR detail[160];
        UNICODE_STRING text;
        UNICODE_STRING detailString;
        RtlInitUnicodeString(&text, loaded ? L"blackcat_loaded" : L"blackcat_not_loaded");
        (VOID)RtlStringCchPrintfW(detail, RTL_NUMBER_OF(detail), L"name=%ws;base=0x%p;size=0x%lx",
                                  moduleName, (PVOID)base, imageSize);
        RtlInitUnicodeString(&detailString, detail);
        (VOID)MsMonLogEvent(MsMonCoverage, PsGetCurrentProcessId(), MsMonProcessStartTime(PsGetCurrentProcessId()), NULL, PsGetCurrentThreadId(),
                            NULL, 0, MsMonFlagObserverRecord, STATUS_SUCCESS, 0,
                            MsMonCategoryUnknown, base, imageSize, &text, &detailString);
    }
    return STATUS_SUCCESS;
}

BOOLEAN MsMonCurrentIsBlackCat(VOID)
{
    ULONG_PTR base;
    ULONG size;
    PVOID frames[32];
    USHORT count;
    USHORT index;
    KIRQL oldIrql;

    MsMonCoverageEnter(MSMON_SENSOR_BLACKCAT_CHECK);
    KeAcquireSpinLock(&gAttributionLock, &oldIrql);
    base = gBlackCatBase;
    size = gBlackCatSize;
    KeReleaseSpinLock(&gAttributionLock, oldIrql);
    if (base == 0 || size == 0) return FALSE;
    count = RtlCaptureStackBackTrace(1, RTL_NUMBER_OF(frames), frames, NULL);
    for (index = 0; index < count; index++) {
        ULONG_PTR address = (ULONG_PTR)frames[index];
        if (address >= base && address - base < size) {
            MsMonCoverageBlackCatMatch();
            return TRUE;
        }
    }
    return FALSE;
}
