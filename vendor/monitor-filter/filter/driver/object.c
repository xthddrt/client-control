#include "kf.h"

/*
 * Process and thread handle enforcement. Ob callbacks cannot deny a handle
 * outright, but they can remove dangerous access before it is granted. Both
 * create and duplicate are evaluated, including a duplicate from an
 * unprotected process into a protected one and vice versa.
 */

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE 0x0001
#endif
#ifndef PROCESS_CREATE_THREAD
#define PROCESS_CREATE_THREAD 0x0002
#endif
#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION 0x0008
#endif
#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ 0x0010
#endif
#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE 0x0020
#endif
#ifndef PROCESS_DUP_HANDLE
#define PROCESS_DUP_HANDLE 0x0040
#endif
#ifndef PROCESS_CREATE_PROCESS
#define PROCESS_CREATE_PROCESS 0x0080
#endif
#ifndef PROCESS_SET_INFORMATION
#define PROCESS_SET_INFORMATION 0x0200
#endif
#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION 0x0400
#endif
#ifndef PROCESS_SUSPEND_RESUME
#define PROCESS_SUSPEND_RESUME 0x0800
#endif

#ifndef THREAD_TERMINATE
#define THREAD_TERMINATE 0x0001
#endif
#ifndef THREAD_SUSPEND_RESUME
#define THREAD_SUSPEND_RESUME 0x0002
#endif
#ifndef THREAD_GET_CONTEXT
#define THREAD_GET_CONTEXT 0x0008
#endif
#ifndef THREAD_SET_CONTEXT
#define THREAD_SET_CONTEXT 0x0010
#endif
#ifndef THREAD_SET_INFORMATION
#define THREAD_SET_INFORMATION 0x0020
#endif
#ifndef THREAD_QUERY_INFORMATION
#define THREAD_QUERY_INFORMATION 0x0040
#endif
#ifndef THREAD_SET_THREAD_TOKEN
#define THREAD_SET_THREAD_TOKEN 0x0080
#endif
#ifndef THREAD_IMPERSONATE
#define THREAD_IMPERSONATE 0x0100
#endif
#ifndef THREAD_DIRECT_IMPERSONATION
#define THREAD_DIRECT_IMPERSONATION 0x0200
#endif
#ifndef THREAD_SET_LIMITED_INFORMATION
#define THREAD_SET_LIMITED_INFORMATION 0x0400
#endif
#ifndef THREAD_QUERY_LIMITED_INFORMATION
#define THREAD_QUERY_LIMITED_INFORMATION 0x0800
#endif

static PVOID gRegistration;

static ACCESS_MASK KfProcessDangerous(VOID)
{
    return PROCESS_TERMINATE | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
           PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_DUP_HANDLE |
           PROCESS_CREATE_PROCESS | PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION |
           PROCESS_SUSPEND_RESUME;
}

static ACCESS_MASK KfThreadDangerous(VOID)
{
    return THREAD_TERMINATE | THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
           THREAD_SET_CONTEXT | THREAD_SET_INFORMATION | THREAD_QUERY_INFORMATION |
           THREAD_SET_LIMITED_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION |
           THREAD_SET_THREAD_TOKEN | THREAD_IMPERSONATE | THREAD_DIRECT_IMPERSONATION;
}

static BOOLEAN KfProcessObjectProtected(PEPROCESS Process)
{
    if (Process == NULL) return FALSE;
    return KfProcessIsProtectedPid(PsGetProcessId(Process), PsGetProcessCreateTimeQuadPart(Process));
}

static BOOLEAN KfThreadObjectProtected(PETHREAD Thread)
{
    PEPROCESS process;
    if (Thread == NULL) return FALSE;
    process = IoThreadToProcess(Thread);
    return KfProcessObjectProtected(process);
}

/* Access rights a policy rule lets a handle crossing to or from this outside process
 * keep, out of Requested. Target is the rule kind: HANDLE/THREAD_HANDLE when the outside
 * process receives a client handle, OPEN/THREAD_OPEN when the client opens or receives a
 * handle to it. *RuleIdOut and *FlagsOut are as KfPolicyOutsideRights gives them. */
static ACCESS_MASK KfOutsideRightsAllowed(PEPROCESS Process, ULONG Target, ACCESS_MASK Requested,
                                          ULONG* RuleIdOut, ULONG* FlagsOut)
{
    PUNICODE_STRING image = NULL;
    ACCESS_MASK allowed;

    *RuleIdOut = 0;
    *FlagsOut = 0;
    if (Process == NULL) return 0;
    if (!NT_SUCCESS(SeLocateProcessImageName(Process, &image)) || image == NULL) return 0;
    allowed = KfPolicyOutsideRights(Target, image, KfProcessIsSystem(Process), Requested,
                                    RuleIdOut, FlagsOut);
    ExFreePool(image);
    return allowed & Requested;
}

/* The event names the outside process, so a run's log shows who the handle crossed to. */
static VOID KfLogHandle(ULONG Target, ULONG Action, ULONG Flags, ACCESS_MASK Access, PEPROCESS Outside,
                        ULONG RuleId)
{
    PUNICODE_STRING image = NULL;

    if (Outside != NULL && !NT_SUCCESS(SeLocateProcessImageName(Outside, &image))) image = NULL;
    KfLogEvent(Target, Action, Flags, STATUS_SUCCESS, (ULONG)Access, RuleId, image);
    if (image != NULL) ExFreePool(image);
}

static OB_PREOP_CALLBACK_STATUS KfObjectPre(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION Information)
{
    ACCESS_MASK* access = NULL;
    ACCESS_MASK removed;
    ACCESS_MASK granted = 0;
    ACCESS_MASK dangerous;
    BOOLEAN processObject;
    BOOLEAN strict;
    BOOLEAN objectProtected = FALSE;
    BOOLEAN sourceProtected;
    BOOLEAN destinationProtected = TRUE;
    BOOLEAN block;
    PEPROCESS outside;
    ULONG targetPid = 0;
    ULONG mode;
    ULONG target = 0;
    ULONG ruleId = 0;
    ULONG flags = 0;

    UNREFERENCED_PARAMETER(RegistrationContext);
    if (Information == NULL || Information->Parameters == NULL || Information->Object == NULL) {
        return OB_PREOP_SUCCESS;
    }
    if (Information->KernelHandle) return OB_PREOP_SUCCESS;
    if (!KfPolicyBlockProcessMemory()) return OB_PREOP_SUCCESS;
    strict = KfPolicyDefaultDeny();

    processObject = Information->ObjectType == *PsProcessType;
    if (!processObject && Information->ObjectType != *PsThreadType) return OB_PREOP_SUCCESS;

    sourceProtected = KfProcessIsProtectedCurrent();
    if (processObject) {
        objectProtected = KfProcessObjectProtected((PEPROCESS)Information->Object);
        targetPid = HandleToULong(PsGetProcessId((PEPROCESS)Information->Object));
    } else {
        objectProtected = KfThreadObjectProtected((PETHREAD)Information->Object);
        targetPid = HandleToULong(PsGetThreadProcessId((PETHREAD)Information->Object));
    }

    if (Information->Operation == OB_OPERATION_HANDLE_CREATE) {
        access = &Information->Parameters->CreateHandleInformation.DesiredAccess;
        /*
         * A protected source is filtered on create. An outside process opening the
         * client is filtered only in strict mode (default-deny), where it needs a
         * HANDLE rule like any other crossing; otherwise an outside service (for
         * example the anti-cheat) may open the client, and the reverse direction is
         * covered by duplicate-handle checks.
         */
        if (!sourceProtected) {
            if (!objectProtected || !strict) return OB_PREOP_SUCCESS;
            destinationProtected = FALSE;   /* the handle goes to the outside opener */
        } else if (objectProtected) {
            return OB_PREOP_SUCCESS;
        }
    } else if (Information->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        POB_PRE_DUPLICATE_HANDLE_INFORMATION duplicate =
            &Information->Parameters->DuplicateHandleInformation;
        sourceProtected = sourceProtected ||
            KfProcessObjectProtected((PEPROCESS)duplicate->SourceProcess);
        destinationProtected =
            KfProcessObjectProtected((PEPROCESS)duplicate->TargetProcess);
        access = &duplicate->DesiredAccess;
        /*
         * The handle object, its holder and the receiving process are separate
         * identity states. Only an all-protected duplicate stays inside the
         * family; any cross-family endpoint strips dangerous rights. Duplicates
         * with no protected endpoint are outside this driver's scope.
         */
        if (!objectProtected && !sourceProtected && !destinationProtected) {
            return OB_PREOP_SUCCESS;
        }
        if (objectProtected && sourceProtected && destinationProtected) {
            return OB_PREOP_SUCCESS;
        }
    } else {
        return OB_PREOP_SUCCESS;
    }

    /* Strict mode strips every right a rule does not grant, not just the dangerous ones. */
    dangerous = strict ? (ACCESS_MASK)~0u : (processObject ? KfProcessDangerous() : KfThreadDangerous());
    removed = *access & dangerous;
    if (Information->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        POB_PRE_DUPLICATE_HANDLE_INFORMATION duplicate =
            &Information->Parameters->DuplicateHandleInformation;
        if (objectProtected) {
            outside = !destinationProtected ? (PEPROCESS)duplicate->TargetProcess
                                            : (PEPROCESS)duplicate->SourceProcess;
        } else {
            outside = processObject ? (PEPROCESS)Information->Object
                                    : IoThreadToProcess((PETHREAD)Information->Object);
        }
    } else if (objectProtected) {
        outside = PsGetCurrentProcess();   /* strict mode: an outside process opens the client */
    } else {
        outside = processObject ? (PEPROCESS)Information->Object
                                : IoThreadToProcess((PETHREAD)Information->Object);
    }
    /* An outside process receiving a client handle keeps only what a HANDLE rule allows. */
    if (removed != 0 && objectProtected && !destinationProtected) {
        target = processObject ? KFILTER_TARGET_HANDLE : KFILTER_TARGET_THREAD_HANDLE;
    }
    /* The client opening (or receiving) a handle to an outside process keeps only what an
     * OPEN rule allows. */
    if (removed != 0 && !objectProtected &&
        (Information->Operation == OB_OPERATION_HANDLE_CREATE || destinationProtected)) {
        target = processObject ? KFILTER_TARGET_OPEN : KFILTER_TARGET_THREAD_OPEN;
    }
    if (target != 0) {
        granted = KfOutsideRightsAllowed(outside, target, removed, &ruleId, &flags) & removed;
        removed &= ~granted;
    } else {
        target = KFILTER_TARGET_PROCESS;
    }
    if (granted != 0) {
        KfLogHandle(target, KFilterActionAllow, flags & KFILTER_EVENT_FLAG_COUNTED, *access, outside, ruleId);
    }
    if (removed == 0) return OB_PREOP_SUCCESS;

    mode = KfPolicyMode();
    block = (mode == KFILTER_MODE_BLOCK);
    KfLogHandle(target,
                block ? KFilterActionDeny : KFilterActionAudit,
                (block ? 0 : KFILTER_EVENT_FLAG_WOULD_DENY) | (flags & KFILTER_EVENT_FLAG_EXHAUSTED) |
                    ((removed & (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION)) != 0
                         ? KFILTER_EVENT_FLAG_MEMORY_READ : 0),
                *access, outside, (flags & KFILTER_EVENT_FLAG_EXHAUSTED) != 0 ? ruleId : 0);
    if (block) *access &= ~removed;
    UNREFERENCED_PARAMETER(targetPid);
    return OB_PREOP_SUCCESS;
}

NTSTATUS KfObjectInitialize(PDRIVER_OBJECT DriverObject)
{
    OB_OPERATION_REGISTRATION operations[2];
    OB_CALLBACK_REGISTRATION registration;
    UNICODE_STRING altitude;

    RtlZeroMemory(operations, sizeof(operations));
    operations[0].ObjectType = PsProcessType;
    operations[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operations[0].PreOperation = KfObjectPre;
    operations[0].PostOperation = NULL;
    operations[1].ObjectType = PsThreadType;
    operations[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operations[1].PreOperation = KfObjectPre;
    operations[1].PostOperation = NULL;

    RtlZeroMemory(&registration, sizeof(registration));
    registration.Version = OB_FLT_REGISTRATION_VERSION;
    registration.OperationRegistrationCount = RTL_NUMBER_OF(operations);
    registration.OperationRegistration = operations;
    RtlInitUnicodeString(&altitude, L"389000");
    registration.Altitude = altitude;
    registration.RegistrationContext = DriverObject;

    return ObRegisterCallbacks(&registration, &gRegistration);
}

VOID KfObjectUninitialize(VOID)
{
    if (gRegistration != NULL) {
        ObUnRegisterCallbacks(gRegistration);
        gRegistration = NULL;
    }
}
