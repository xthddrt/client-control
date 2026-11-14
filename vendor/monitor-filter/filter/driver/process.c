#include "kf.h"

/*
 * Protected-process identity. Every admitted process holds a referenced
 * PEPROCESS object plus PID, creation time, full image path, AppContainer SID
 * and policy generation. Checks use the stored identity; a PID alone never
 * authorizes an operation.
 */

#define KFILTER_MAX_TRACKED 128u

typedef struct _KF_PROCESS_ENTRY {
    HANDLE ProcessId;
    LONGLONG StartTime;
    ULONG Generation;
    PEPROCESS Process;
    BOOLEAN HasSid;
    ULONG SidLength;
    UCHAR Sid[KFILTER_MAX_SID];
    WCHAR Image[KFILTER_MAX_NAME];
} KF_PROCESS_ENTRY;

static KF_PROCESS_ENTRY gTracked[KFILTER_MAX_TRACKED];
static KSPIN_LOCK gTrackedLock;
static volatile LONG gTrackedCount;
static BOOLEAN gProcessInitialized;
static EX_RUNDOWN_REF gCallbackRundown;
static KSPIN_LOCK gLauncherLock;
static PEPROCESS gLauncher;
/* One-time launch pass (KFILTER_IOCTL_ALLOW_LAUNCH); interrupt-time deadline, 0 = closed. */
static KSPIN_LOCK gAllowLock;
static ULONG64 gAllowUntil;
static ULONG gAllowLeft;
static WCHAR gAllowCreator[KFILTER_MAX_NAME];
#define KF_ALLOW_MAX_STARTS 8

static LONGLONG KfProcessStart(PEPROCESS Process)
{
    return Process != NULL ? PsGetProcessCreateTimeQuadPart(Process) : 0;
}

static ULONG KfStringLength(PCWSTR Value)
{
    ULONG length = 0;
    if (Value == NULL) return 0;
    while (length < KFILTER_MAX_NAME && Value[length] != L'\0') length++;
    return length;
}

static LONG KfFindLocked(HANDLE ProcessId, LONGLONG StartTime)
{
    LONG index;
    for (index = 0; index < (LONG)KFILTER_MAX_TRACKED; index++) {
        if (gTracked[index].ProcessId != ProcessId) continue;
        if (StartTime != 0 && gTracked[index].StartTime != StartTime) continue;
        return index;
    }
    return -1;
}

static VOID KfCopyImage(PEPROCESS Process, PWSTR Destination)
{
    PUNICODE_STRING image = NULL;
    Destination[0] = L'\0';
    if (!NT_SUCCESS(SeLocateProcessImageName(Process, &image)) || image == NULL) return;
    if (image->Buffer != NULL) {
        ULONG characters = image->Length / sizeof(WCHAR);
        if (characters >= KFILTER_MAX_NAME) characters = KFILTER_MAX_NAME - 1;
        RtlCopyMemory(Destination, image->Buffer, (SIZE_T)characters * sizeof(WCHAR));
        Destination[characters] = L'\0';
    }
    ExFreePool(image);
}

NTSTATUS KfProcessGetSid(PEPROCESS Process, PUCHAR Buffer, PULONG Length)
{
    PACCESS_TOKEN token;
    PVOID information = NULL;
    NTSTATUS status;

    if (Process == NULL || Buffer == NULL || Length == NULL) return STATUS_INVALID_PARAMETER;
    *Length = 0;
    token = PsReferencePrimaryToken(Process);
    if (token == NULL) return STATUS_NO_TOKEN;
    status = SeQueryInformationToken(token, TokenAppContainerSid, &information);
    PsDereferencePrimaryToken(token);
    if (!NT_SUCCESS(status) || information == NULL) {
        if (information != NULL) ExFreePool(information);
        return status;
    }
    {
        /* The class returns TOKEN_APPCONTAINER_INFORMATION, which points at the SID (NULL when
         * the process is not in an AppContainer). */
        PSID sid = ((PTOKEN_APPCONTAINER_INFORMATION)information)->TokenAppContainer;
        ULONG sidLength = sid != NULL ? RtlLengthSid(sid) : 0;
        if (sidLength > KFILTER_MAX_SID) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else {
            RtlCopyMemory(Buffer, sid, sidLength);
            *Length = sidLength;
            status = STATUS_SUCCESS;
        }
    }
    ExFreePool(information);
    return status;
}

static BOOLEAN KfProcessPackageMatches(PEPROCESS Process)
{
    UCHAR sid[KFILTER_MAX_SID];
    ULONG sidLength = sizeof(sid);
    NTSTATUS status = KfProcessGetSid(Process, sid, &sidLength);
    if (!NT_SUCCESS(status) || sidLength == 0) return KfPolicyPackageSidMatches(NULL, 0);
    return KfPolicyPackageSidMatches(sid, sidLength);
}

static NTSTATUS KfEntryPrepare(PEPROCESS Process, KF_PROCESS_ENTRY* Entry)
{
    NTSTATUS status;

    RtlZeroMemory(Entry, sizeof(*Entry));
    Entry->ProcessId = PsGetProcessId(Process);
    Entry->StartTime = KfProcessStart(Process);
    Entry->Process = Process;
    KfCopyImage(Process, Entry->Image);
    status = KfProcessGetSid(Process, Entry->Sid, &Entry->SidLength);
    Entry->HasSid = NT_SUCCESS(status) && Entry->SidLength != 0;
    return Entry->Image[0] != L'\0' ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

/* Takes ownership of the referenced PEPROCESS on success. */
static NTSTATUS KfProcessAddOwned(PEPROCESS Process)
{
    KF_PROCESS_ENTRY entry;
    KIRQL oldIrql;
    LONG slot = -1;
    LONG existing;
    NTSTATUS status;

    status = KfEntryPrepare(Process, &entry);
    if (!NT_SUCCESS(status)) return status;
    entry.Generation = KfPolicyGeneration();

    KeAcquireSpinLock(&gTrackedLock, &oldIrql);
    existing = KfFindLocked(entry.ProcessId, entry.StartTime);
    if (existing >= 0) {
        KeReleaseSpinLock(&gTrackedLock, oldIrql);
        return STATUS_ALREADY_REGISTERED;
    }
    for (LONG index = 0; index < (LONG)KFILTER_MAX_TRACKED; index++) {
        if (gTracked[index].ProcessId == NULL) {
            slot = index;
            break;
        }
    }
    if (slot < 0) {
        KeReleaseSpinLock(&gTrackedLock, oldIrql);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    gTracked[slot] = entry;
    InterlockedIncrement(&gTrackedCount);
    KeReleaseSpinLock(&gTrackedLock, oldIrql);
    return STATUS_SUCCESS;
}

static VOID KfProcessRemove(HANDLE ProcessId, LONGLONG StartTime)
{
    PEPROCESS release = NULL;
    KIRQL oldIrql;
    LONG index;

    KeAcquireSpinLock(&gTrackedLock, &oldIrql);
    index = KfFindLocked(ProcessId, StartTime);
    if (index >= 0) {
        release = gTracked[index].Process;
        RtlZeroMemory(&gTracked[index], sizeof(gTracked[index]));
        InterlockedDecrement(&gTrackedCount);
    }
    KeReleaseSpinLock(&gTrackedLock, oldIrql);
    if (release != NULL) ObDereferenceObject(release);
}

BOOLEAN KfProcessIsProtectedPid(HANDLE ProcessId, LONGLONG StartTime)
{
    KIRQL oldIrql;
    BOOLEAN found = FALSE;

    if (ProcessId == NULL || ProcessId == (HANDLE)4) return FALSE;
    KeAcquireSpinLock(&gTrackedLock, &oldIrql);
    found = KfFindLocked(ProcessId, StartTime) >= 0;
    KeReleaseSpinLock(&gTrackedLock, oldIrql);
    return found;
}

BOOLEAN KfProcessIsProtectedCurrent(VOID)
{
    return KfProcessIsProtectedPid(PsGetCurrentProcessId(), KfProcessStart(PsGetCurrentProcess()));
}

ULONG KfProcessImageOf(HANDLE ProcessId, PWCHAR Buffer, ULONG Capacity)
{
    KIRQL oldIrql;
    LONG index;
    ULONG length = 0;

    if (Buffer == NULL || Capacity == 0) return 0;
    Buffer[0] = L'\0';
    KeAcquireSpinLock(&gTrackedLock, &oldIrql);
    index = KfFindLocked(ProcessId, 0);
    if (index >= 0) {
        length = KfStringLength(gTracked[index].Image);
        if (length >= Capacity) length = Capacity - 1;
        RtlCopyMemory(Buffer, gTracked[index].Image, (SIZE_T)length * sizeof(WCHAR));
        Buffer[length] = L'\0';
    }
    KeReleaseSpinLock(&gTrackedLock, oldIrql);
    return length;
}

ULONG KfProcessCurrentGeneration(VOID)
{
    KIRQL oldIrql;
    LONG index;
    ULONG generation = 0;

    KeAcquireSpinLock(&gTrackedLock, &oldIrql);
    index = KfFindLocked(PsGetCurrentProcessId(), KfProcessStart(PsGetCurrentProcess()));
    if (index >= 0) generation = gTracked[index].Generation;
    KeReleaseSpinLock(&gTrackedLock, oldIrql);
    return generation;
}

ULONG KfProcessTrackedCount(VOID)
{
    LONG count = gTrackedCount;
    return count > 0 ? (ULONG)count : 0;
}

static VOID KfProcessReleaseAll(VOID)
{
    PEPROCESS release[KFILTER_MAX_TRACKED];
    ULONG count = 0;
    ULONG index;
    KIRQL oldIrql;

    KeAcquireSpinLock(&gTrackedLock, &oldIrql);
    for (index = 0; index < KFILTER_MAX_TRACKED; index++) {
        if (gTracked[index].Process != NULL) {
            release[count++] = gTracked[index].Process;
            RtlZeroMemory(&gTracked[index], sizeof(gTracked[index]));
        }
    }
    gTrackedCount = 0;
    KeReleaseSpinLock(&gTrackedLock, oldIrql);
    for (index = 0; index < count; index++) ObDereferenceObject(release[index]);
}

VOID KfProcessClearTracking(VOID)
{
    KfProcessReleaseAll();
}

/*
 * The launcher registration is a referenced PEPROCESS, not a PID, so PID reuse
 * cannot inherit the privilege. It is replaced by the next registration and
 * cleared when that process exits or the driver unloads.
 */
NTSTATUS KfProcessRegisterLauncher(VOID)
{
    PEPROCESS self = PsGetCurrentProcess();
    PEPROCESS old;
    KIRQL oldIrql;

    if (self == NULL) return STATUS_INVALID_PARAMETER;
    ObReferenceObject(self);
    KeAcquireSpinLock(&gLauncherLock, &oldIrql);
    old = gLauncher;
    gLauncher = self;
    KeReleaseSpinLock(&gLauncherLock, oldIrql);
    if (old != NULL) ObDereferenceObject(old);
    return STATUS_SUCCESS;
}

static BOOLEAN KfProcessIsLauncher(PEPROCESS Process)
{
    BOOLEAN match;
    KIRQL oldIrql;

    if (Process == NULL) return FALSE;
    KeAcquireSpinLock(&gLauncherLock, &oldIrql);
    match = gLauncher == Process;
    KeReleaseSpinLock(&gLauncherLock, oldIrql);
    return match;
}

NTSTATUS KfProcessAllowLaunch(const KFILTER_ALLOW_LAUNCH_REQUEST* Request)
{
    ULONG seconds = Request->ArmSeconds == 0 ? 120 : Request->ArmSeconds;
    ULONG starts = Request->Starts == 0 ? 1 : Request->Starts;
    ULONG length = 0;
    KIRQL oldIrql;

    while (length < KFILTER_MAX_NAME && Request->CreatorName[length] != L'\0') length++;
    if (length == 0 || length == KFILTER_MAX_NAME) return STATUS_INVALID_PARAMETER;
    if (seconds > 600) seconds = 600;
    if (starts > KF_ALLOW_MAX_STARTS) return STATUS_INVALID_PARAMETER;
    KeAcquireSpinLock(&gAllowLock, &oldIrql);
    RtlCopyMemory(gAllowCreator, Request->CreatorName, (SIZE_T)(length + 1) * sizeof(WCHAR));
    gAllowLeft = starts;
    gAllowUntil = KeQueryInterruptTime() + (ULONG64)seconds * 10000000ULL;
    KeReleaseSpinLock(&gAllowLock, oldIrql);
    KfPolicyResetCounts();
    return STATUS_SUCCESS;
}

BOOLEAN KfProcessIsSystem(PEPROCESS Process)
{
    PACCESS_TOKEN token;
    PTOKEN_USER user = NULL;
    BOOLEAN match;

    if (Process == NULL) return FALSE;
    token = PsReferencePrimaryToken(Process);
    if (token == NULL) return FALSE;
    match = NT_SUCCESS(SeQueryInformationToken(token, TokenUser, (PVOID*)&user)) && user != NULL &&
            RtlEqualSid(user->User.Sid, SeExports->SeLocalSystemSid);
    if (user != NULL) ExFreePool(user);
    PsDereferencePrimaryToken(token);
    return match;
}

/* The image file name must equal Name, not merely end with it. */
static BOOLEAN KfProcessImageNamed(PCUNICODE_STRING Image, PCWSTR Name)
{
    UNICODE_STRING name;

    RtlInitUnicodeString(&name, Name);
    return Image != NULL && Image->Buffer != NULL && Image->Length > name.Length &&
           Image->Buffer[(Image->Length - name.Length) / sizeof(WCHAR) - 1] == L'\\' &&
           RtlSuffixUnicodeString(&name, Image, TRUE);
}

/*
 * The armed launcher itself, or a policy LAUNCH broker (e.g. the elevation service) that
 * starts the image with the armed launcher as its parent.
 */
static BOOLEAN KfProcessLaunchedBy(PCWSTR Launcher, HANDLE ParentProcessId)
{
    PEPROCESS creator = PsGetCurrentProcess();
    PEPROCESS parent;
    PUNICODE_STRING image = NULL;
    PUNICODE_STRING parentImage = NULL;
    BOOLEAN parentIsLauncher = FALSE;
    BOOLEAN match;

    if (!NT_SUCCESS(SeLocateProcessImageName(creator, &image)) || image == NULL) return FALSE;
    match = KfProcessImageNamed(image, Launcher);
    if (!match && PsGetProcessId(creator) != ParentProcessId &&
        NT_SUCCESS(PsLookupProcessByProcessId(ParentProcessId, &parent))) {
        if (NT_SUCCESS(SeLocateProcessImageName(parent, &parentImage)) && parentImage != NULL) {
            parentIsLauncher = KfProcessImageNamed(parentImage, Launcher);
            ExFreePool(parentImage);
        }
        ObDereferenceObject(parent);
        /* Checked last: a one-time broker rule is used up when it matches. */
        match = parentIsLauncher && KfPolicyLaunchBroker(image, KfProcessIsSystem(creator));
    }
    ExFreePool(image);
    return match;
}

/*
 * Called in the creator's context for a protected image in block mode. The pass is open
 * until its deadline; each admitted start uses one of its starts, and it closes when
 * none are left.
 */
static BOOLEAN KfProcessTakeLaunchPass(HANDLE ParentProcessId)
{
    WCHAR creator[KFILTER_MAX_NAME];
    ULONG64 now = KeQueryInterruptTime();
    BOOLEAN match = FALSE;
    KIRQL oldIrql;

    KeAcquireSpinLock(&gAllowLock, &oldIrql);
    if (gAllowUntil != 0 && now >= gAllowUntil) gAllowUntil = 0;
    if (gAllowUntil != 0) RtlCopyMemory(creator, gAllowCreator, sizeof(creator));
    match = gAllowUntil != 0;
    KeReleaseSpinLock(&gAllowLock, oldIrql);
    if (!match) return FALSE;

    if (!KfProcessLaunchedBy(creator, ParentProcessId)) return FALSE;

    KeAcquireSpinLock(&gAllowLock, &oldIrql);
    match = gAllowUntil != 0 && now < gAllowUntil && gAllowLeft != 0;
    if (match && --gAllowLeft == 0) gAllowUntil = 0;
    KeReleaseSpinLock(&gAllowLock, oldIrql);
    return match;
}

static VOID KfProcessClearLauncher(VOID)
{
    PEPROCESS old;
    KIRQL oldIrql;

    KeAcquireSpinLock(&gLauncherLock, &oldIrql);
    old = gLauncher;
    gLauncher = NULL;
    KeReleaseSpinLock(&gLauncherLock, oldIrql);
    if (old != NULL) ObDereferenceObject(old);
}

/* Clear the launcher only when it is still this exiting process: a
 * registration that arrived after the caller's check must not be dropped. */
static VOID KfProcessClearLauncherIf(PEPROCESS Process)
{
    PEPROCESS old = NULL;
    KIRQL oldIrql;

    KeAcquireSpinLock(&gLauncherLock, &oldIrql);
    if (gLauncher == Process) {
        old = gLauncher;
        gLauncher = NULL;
    }
    KeReleaseSpinLock(&gLauncherLock, oldIrql);
    if (old != NULL) ObDereferenceObject(old);
}

NTSTATUS KfProcessTrack(HANDLE ProcessId)
{
    PEPROCESS process = NULL;
    PUNICODE_STRING image = NULL;
    NTSTATUS status;
    BOOLEAN matches;

    if (ProcessId == NULL) return STATUS_INVALID_PARAMETER;
    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) return status;
    status = SeLocateProcessImageName(process, &image);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(process);
        /*
         * An image-name resolution failure is not a confirmed non-match: the
         * caller must fail closed rather than ignore the process. STATUS_NOT_FOUND
         * is reserved for the policy comparison below.
         */
        return STATUS_UNSUCCESSFUL;
    }
    matches = KfPolicyMatchesProtectedName(image);
    ExFreePool(image);
    if (!matches) {
        ObDereferenceObject(process);
        return STATUS_NOT_FOUND; /* confirmed non-match */
    }
    if (!KfProcessPackageMatches(process)) {
        KfCountSidFailure();
        ObDereferenceObject(process);
        return STATUS_ACCESS_DENIED;
    }
    status = KfProcessAddOwned(process);
    if (status == STATUS_ALREADY_REGISTERED) {
        ObDereferenceObject(process);
        return STATUS_SUCCESS; /* idempotent duplicate admission */
    }
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(process);
        /*
         * KfProcessAddOwned reports a missing stored image with STATUS_NOT_FOUND.
         * That is an identification/admission failure, not the policy non-match
         * above, so keep the two distinguishable for the tracking tool.
         */
        if (status == STATUS_NOT_FOUND) return STATUS_UNSUCCESSFUL;
    }
    return status;
}

static BOOLEAN KfImageMatchesRequest(PCWSTR Expected, PCWSTR Actual)
{
    ULONG expectedLength;
    ULONG actualLength;

    if (Expected == NULL || Expected[0] == L'\0') return TRUE;
    if (Actual == NULL) return FALSE;
    expectedLength = KfStringLength(Expected);
    actualLength = KfStringLength(Actual);
    if (expectedLength == 0 || actualLength == 0) return FALSE;
    return KfMatchGlob(Expected, expectedLength, Actual, actualLength) ? TRUE : FALSE;
}

NTSTATUS KfProcessAdmit(const KFILTER_ADMIT_REQUEST* Request)
{
    PEPROCESS process = NULL;
    KF_PROCESS_ENTRY entry;
    UCHAR sid[KFILTER_MAX_SID];
    ULONG sidLength = sizeof(sid);
    NTSTATUS status;

    if (Request == NULL || Request->ProcessId == 0) return STATUS_INVALID_PARAMETER;
    if (Request->ImagePath[0] == L'\0') return STATUS_INVALID_PARAMETER;
    if (Request->Generation != 0 && Request->Generation != KfPolicyGeneration()) {
        return STATUS_REVISION_MISMATCH;
    }
    status = PsLookupProcessByProcessId(UlongToHandle(Request->ProcessId), &process);
    if (!NT_SUCCESS(status)) return status;
    status = KfEntryPrepare(process, &entry);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(process);
        return status;
    }
    if (!KfImageMatchesRequest(Request->ImagePath, entry.Image)) {
        ObDereferenceObject(process);
        return STATUS_OBJECT_NAME_INVALID;
    }
    {
        UNICODE_STRING image;
        RtlInitUnicodeString(&image, entry.Image);
        if (!KfPolicyMatchesProtectedName(&image)) {
            ObDereferenceObject(process);
            return STATUS_ACCESS_DENIED;
        }
    }
    if (Request->SidLength != 0) {
        status = KfProcessGetSid(process, sid, &sidLength);
        if (!NT_SUCCESS(status) || Request->SidLength != sidLength ||
            RtlCompareMemory(Request->Sid, sid, sidLength) != sidLength) {
            KfCountSidFailure();
            ObDereferenceObject(process);
            return STATUS_INVALID_SID;
        }
    }
    if (!KfProcessPackageMatches(process)) {
        KfCountSidFailure();
        ObDereferenceObject(process);
        return STATUS_INVALID_SID;
    }
    status = KfProcessAddOwned(process);
    if (status == STATUS_ALREADY_REGISTERED) {
        ObDereferenceObject(process);
        return STATUS_SUCCESS;
    }
    if (!NT_SUCCESS(status)) ObDereferenceObject(process);
    return status;
}

BOOLEAN KfProcessParentAllowed(HANDLE ParentProcessId)
{
    PEPROCESS parent = NULL;
    LONGLONG start;
    BOOLEAN allowed;

    if (ParentProcessId == NULL) return FALSE;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(ParentProcessId, &parent))) return FALSE;
    start = KfProcessStart(parent);
    allowed = KfProcessIsProtectedPid(ParentProcessId, start);
    ObDereferenceObject(parent);
    return allowed;
}

static BOOLEAN KfParentSidMatches(HANDLE ParentProcessId, PEPROCESS Child)
{
    PEPROCESS parent = NULL;
    UCHAR parentSid[KFILTER_MAX_SID];
    ULONG parentSidLength = sizeof(parentSid);
    UCHAR childSid[KFILTER_MAX_SID];
    ULONG childSidLength = sizeof(childSid);
    BOOLEAN matches = TRUE;
    NTSTATUS status;

    if (ParentProcessId == NULL) return TRUE;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(ParentProcessId, &parent))) return FALSE;
    status = KfProcessGetSid(parent, parentSid, &parentSidLength);
    ObDereferenceObject(parent);
    if (!NT_SUCCESS(status) || parentSidLength == 0) return TRUE; /* non-AppContainer family */
    status = KfProcessGetSid(Child, childSid, &childSidLength);
    if (!NT_SUCCESS(status) || childSidLength != parentSidLength ||
        RtlCompareMemory(parentSid, childSid, childSidLength) != childSidLength) {
        matches = FALSE;
    }
    return matches;
}

static VOID KfProcessDenyCreate(PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    KfCountDenied();
    KfLogEvent(KFILTER_TARGET_PROCESS, KFilterActionDeny, KFILTER_EVENT_FLAG_PROCESS_CREATE,
               STATUS_ACCESS_DENIED, 0, 0, CreateInfo->ImageFileName);
    CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
}

static VOID KfProcessNotifyInner(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    HANDLE creatorId;
    BOOLEAN creatorProtected;
    BOOLEAN parentProtected;

    if (CreateInfo == NULL) {
        KfProcessClearLauncherIf(Process);
        KfProcessRemove(ProcessId, KfProcessStart(Process));
        return;
    }
    creatorId = PsGetCurrentProcessId();
    creatorProtected = KfProcessParentAllowed(creatorId);
    parentProtected = creatorId == CreateInfo->ParentProcessId
                          ? creatorProtected
                          : KfProcessParentAllowed(CreateInfo->ParentProcessId);
    if (creatorProtected || parentProtected) {
        BOOLEAN familyAllowed = creatorProtected && parentProtected;
        BOOLEAN packageMatches = KfProcessPackageMatches(Process);
        BOOLEAN sidMatches = KfParentSidMatches(CreateInfo->ParentProcessId, Process);
        BOOLEAN enforce = KfPolicyMode() == KFILTER_MODE_BLOCK && KfPolicyBlockProcessCreate();
        ULONG action = 0;
        ULONG ruleId = 0;
        BOOLEAN nameFailure = FALSE;
        BOOLEAN deny;
        NTSTATUS status;

        if (!familyAllowed && enforce) {
            KfProcessDenyCreate(CreateInfo);
            return;
        }
        if (!packageMatches || !sidMatches) {
            KfCountSidFailure();
            if (enforce) {
                KfProcessDenyCreate(CreateInfo);
                return;
            }
        }
        deny = KfDecideWithRights(KFILTER_TARGET_PROCESS, CreateInfo->ImageFileName,
                                  KFILTER_RIGHT_CREATE, NULL, 0, &ruleId, &nameFailure, &action, 0);
        if (deny) {
            CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
            return;
        }
        if (!familyAllowed || !packageMatches || !sidMatches || action == KFilterActionDeny) return;
        ObReferenceObject(Process);
        status = KfProcessAddOwned(Process);
        if (!NT_SUCCESS(status)) {
            ObDereferenceObject(Process);
            if (KfAdmissionCreationDenied(KfPolicyMode(), (ULONG)status)) {
                KfProcessDenyCreate(CreateInfo);
            }
        }
        return;
    }
    if (KfPolicyMatchesProtectedName(CreateInfo->ImageFileName)) {
        NTSTATUS status;
        BOOLEAN enforce = KfPolicyMode() == KFILTER_MODE_BLOCK && KfPolicyBlockProcessCreate();
        if (!KfProcessPackageMatches(Process)) {
            KfCountSidFailure();
            if (enforce) KfProcessDenyCreate(CreateInfo);
            return;
        }
        /*
         * In enforce mode a root process created by an unprotected parent is
         * admitted only through the launcher/ADMIT_PROCESS handshake. Tracking
         * it here would let an already-running process bypass admission, and
         * allowing it untracked lets any broker start an uncontained copy.
         */
        if (enforce) {
            if (KfProcessIsLauncher(PsGetCurrentProcess())) return;
            if (!KfProcessTakeLaunchPass(CreateInfo->ParentProcessId)) {
                KfProcessDenyCreate(CreateInfo);
                return;
            }
            /* Admitted by the one-time pass: tracked as a family root, like audit mode. */
            KfLogEvent(KFILTER_TARGET_PROCESS, KFilterActionAllow, KFILTER_EVENT_FLAG_PROCESS_CREATE,
                       STATUS_SUCCESS, 0, 0, CreateInfo->ImageFileName);
        }
        ObReferenceObject(Process);
        status = KfProcessAddOwned(Process);
        if (!NT_SUCCESS(status)) {
            ObDereferenceObject(Process);
            if (KfAdmissionCreationDenied(KfPolicyMode(), (ULONG)status)) {
                KfProcessDenyCreate(CreateInfo);
            }
        }
    }
}

static VOID KfProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    if (!ExAcquireRundownProtection(&gCallbackRundown)) return;
    KfProcessNotifyInner(Process, ProcessId, CreateInfo);
    ExReleaseRundownProtection(&gCallbackRundown);
}

NTSTATUS KfProcessInitialize(VOID)
{
    NTSTATUS status;

    RtlZeroMemory(gTracked, sizeof(gTracked));
    KeInitializeSpinLock(&gTrackedLock);
    gTrackedCount = 0;
    KeInitializeSpinLock(&gLauncherLock);
    gLauncher = NULL;
    KeInitializeSpinLock(&gAllowLock);
    gAllowUntil = 0;
    gAllowLeft = 0;
    ExInitializeRundownProtection(&gCallbackRundown);
    gProcessInitialized = TRUE;

    status = PsSetCreateProcessNotifyRoutineEx(KfProcessNotify, FALSE);
    if (!NT_SUCCESS(status)) {
        gProcessInitialized = FALSE;
        return status;
    }
    return STATUS_SUCCESS;
}

VOID KfProcessUninitialize(VOID)
{
    if (!gProcessInitialized) return;
    (VOID)PsSetCreateProcessNotifyRoutineEx(KfProcessNotify, TRUE);
    ExWaitForRundownProtectionRelease(&gCallbackRundown);
    ExRundownCompleted(&gCallbackRundown);
    KfProcessClearLauncher();
    KfProcessClearTracking();
    gProcessInitialized = FALSE;
}
