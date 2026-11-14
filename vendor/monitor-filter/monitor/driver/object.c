#include "msmon.h"

static PVOID gObjectRegistration;
static NTSTATUS gObjectStatus = STATUS_SUCCESS;

typedef struct _MSMON_OBJECT_CONTEXT {
    HANDLE TargetProcessId;
    LONGLONG ProcessStartTime;
    LONGLONG TargetProcessStartTime;
    ULONG Operation;
    ULONG DesiredAccess;
    BOOLEAN ThreadObject;
} MSMON_OBJECT_CONTEXT, *PMSMON_OBJECT_CONTEXT;

static OB_PREOP_CALLBACK_STATUS MsMonObjectPre(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION Information)
{
    PMSMON_OBJECT_CONTEXT context;
    HANDLE source = PsGetCurrentProcessId();
    ULONG desiredAccess;
    BOOLEAN blackCat;
    ULONG sensor = Information->ObjectType == *PsThreadType
                       ? MSMON_SENSOR_OBJECT_THREAD : MSMON_SENSOR_OBJECT_PROCESS;

    UNREFERENCED_PARAMETER(RegistrationContext);
    Information->CallContext = NULL;
    MsMonCoverageEnter(sensor);
    /* One stack lookup per handle operation, not one per test below. */
    blackCat = MsMonCurrentIsBlackCat();
    if (Information->Parameters == NULL ||
        (Information->KernelHandle && !blackCat) ||
        (!MsMonIsTracked(source, 0) && !blackCat)) {
        MsMonCoverageSkip(MSMON_SKIP_UNTRACKED);
        return OB_PREOP_SUCCESS;
    }
    context = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*context), MSMON_POOL_TAG);
    if (context == NULL) {
        MsMonCoverageSkip(MSMON_SKIP_ALLOC);
        MsMonEventsNoteDropped();
        return OB_PREOP_SUCCESS;
    }
    RtlZeroMemory(context, sizeof(*context));
    context->Operation = Information->Operation;
    context->ProcessStartTime = MsMonProcessStartTime(source);
    context->ThreadObject = Information->ObjectType == *PsThreadType;

    if (Information->Operation == OB_OPERATION_HANDLE_CREATE) {
        desiredAccess = Information->Parameters->CreateHandleInformation.OriginalDesiredAccess;
    } else if (Information->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        desiredAccess = Information->Parameters->DuplicateHandleInformation.OriginalDesiredAccess;
    } else {
        ExFreePoolWithTag(context, MSMON_POOL_TAG);
        return OB_PREOP_SUCCESS;
    }
    context->DesiredAccess = desiredAccess;

    if (context->ThreadObject) {
        context->TargetProcessId = PsGetThreadProcessId((PETHREAD)Information->Object);
        context->TargetProcessStartTime = MsMonProcessStartTime(context->TargetProcessId);
    } else {
        PEPROCESS target = (PEPROCESS)Information->Object;
        context->TargetProcessId = PsGetProcessId(target);
        context->TargetProcessStartTime = PsGetProcessCreateTimeQuadPart(target);
    }
    if (context->TargetProcessId == source) {
        ExFreePoolWithTag(context, MSMON_POOL_TAG);
        return OB_PREOP_SUCCESS;
    }
    Information->CallContext = context;
    return OB_PREOP_SUCCESS;
}

static VOID MsMonObjectPost(PVOID RegistrationContext, POB_POST_OPERATION_INFORMATION Information)
{
    PMSMON_OBJECT_CONTEXT context;
    PUNICODE_STRING imageName = NULL;
    ULONG grantedAccess = 0;

    UNREFERENCED_PARAMETER(RegistrationContext);
    if (Information == NULL) return;
    context = (PMSMON_OBJECT_CONTEXT)Information->CallContext;
    if (context == NULL) return;
    if (Information->Parameters == NULL) {
        ExFreePoolWithTag(context, MSMON_POOL_TAG);
        return;
    }
    if (Information->Operation == OB_OPERATION_HANDLE_CREATE) {
        grantedAccess = Information->Parameters->CreateHandleInformation.GrantedAccess;
    } else if (Information->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        grantedAccess = Information->Parameters->DuplicateHandleInformation.GrantedAccess;
    }
    /* SeLocateProcessImageName is PASSIVE_LEVEL only; post-operation callbacks can run at APC_LEVEL. */
    if (!context->ThreadObject && Information->Object != NULL && KeGetCurrentIrql() == PASSIVE_LEVEL) {
        (VOID)SeLocateProcessImageName((PEPROCESS)Information->Object, &imageName);
    }
    (VOID)MsMonLogEvent(context->ThreadObject ? MsMonThreadHandle : MsMonProcessHandle,
                        PsGetCurrentProcessId(), context->ProcessStartTime, NULL, PsGetCurrentThreadId(),
                        context->TargetProcessId, context->TargetProcessStartTime, 0,
                        Information->ReturnStatus, context->DesiredAccess,
                        MsMonCategoryExternalProcess, context->Operation, grantedAccess,
                        imageName, NULL);
    MsMonCoverageLogged(context->ThreadObject ? MSMON_SENSOR_OBJECT_THREAD : MSMON_SENSOR_OBJECT_PROCESS);
    if (imageName != NULL) ExFreePool(imageName);
    ExFreePoolWithTag(context, MSMON_POOL_TAG);
}

NTSTATUS MsMonObjectInitialize(PDRIVER_OBJECT DriverObject)
{
    OB_OPERATION_REGISTRATION operations[2];
    OB_CALLBACK_REGISTRATION registration;
    UNICODE_STRING altitude;

    RtlZeroMemory(operations, sizeof(operations));
    operations[0].ObjectType = PsProcessType;
    operations[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operations[0].PreOperation = MsMonObjectPre;
    operations[0].PostOperation = MsMonObjectPost;
    operations[1].ObjectType = PsThreadType;
    operations[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operations[1].PreOperation = MsMonObjectPre;
    operations[1].PostOperation = MsMonObjectPost;

    RtlZeroMemory(&registration, sizeof(registration));
    registration.Version = OB_FLT_REGISTRATION_VERSION;
    registration.OperationRegistrationCount = RTL_NUMBER_OF(operations);
    registration.OperationRegistration = operations;
    RtlInitUnicodeString(&altitude, L"380011");
    registration.Altitude = altitude;
    registration.RegistrationContext = DriverObject;
    gObjectStatus = ObRegisterCallbacks(&registration, &gObjectRegistration);
    MsMonCoverageRegister(MSMON_SENSOR_REG_OBJECT_PROCESS, gObjectStatus);
    MsMonCoverageRegister(MSMON_SENSOR_REG_OBJECT_THREAD, gObjectStatus);
    return gObjectStatus;
}

BOOLEAN MsMonObjectAvailable(VOID)
{
    return gObjectRegistration != NULL;
}

NTSTATUS MsMonObjectStatus(VOID)
{
    return gObjectStatus;
}

VOID MsMonObjectUninitialize(VOID)
{
    if (gObjectRegistration != NULL) {
        ObUnRegisterCallbacks(gObjectRegistration);
        gObjectRegistration = NULL;
    }
}
