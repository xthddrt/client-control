#include "kf.h"
#include <ntddk.h>
#pragma warning(push)
#pragma warning(disable:4201)
#define NDIS630 1
#include <ndis.h>
#pragma warning(pop)
#include <fwpsk.h>
#include <fwpmk.h>

#define KF_NETWORK_CALLOUTS 6
#define KF_NETWORK_NO_FIELD 0xFFFFu

static const GUID gCalloutKeys[KF_NETWORK_CALLOUTS] = {
    { 0x6b1f2c11, 0x7a21, 0x4d6e, { 0x9b, 0x31, 0x2c, 0x41, 0x8e, 0x10, 0x51, 0x01 } },
    { 0x6b1f2c11, 0x7a21, 0x4d6e, { 0x9b, 0x31, 0x2c, 0x41, 0x8e, 0x10, 0x51, 0x02 } },
    { 0x6b1f2c11, 0x7a21, 0x4d6e, { 0x9b, 0x31, 0x2c, 0x41, 0x8e, 0x10, 0x51, 0x03 } },
    { 0x6b1f2c11, 0x7a21, 0x4d6e, { 0x9b, 0x31, 0x2c, 0x41, 0x8e, 0x10, 0x51, 0x04 } },
    { 0x6b1f2c11, 0x7a21, 0x4d6e, { 0x9b, 0x31, 0x2c, 0x41, 0x8e, 0x10, 0x51, 0x05 } },
    { 0x6b1f2c11, 0x7a21, 0x4d6e, { 0x9b, 0x31, 0x2c, 0x41, 0x8e, 0x10, 0x51, 0x06 } }
};

static HANDLE gEngine;
static UINT32 gCalloutIds[KF_NETWORK_CALLOUTS];
static BOOLEAN gCalloutRegistered[KF_NETWORK_CALLOUTS];
static ULONG gLayerMask;
static EX_RUNDOWN_REF gNetworkRundown;
static BOOLEAN gNetworkRundownInitialized;

static ULONG KfNetworkIndex(const FWPS_FILTER3* Filter)
{
    ULONG index;
    if (Filter == NULL) return KF_NETWORK_CALLOUTS;
    for (index = 0; index < KF_NETWORK_CALLOUTS; index++) {
        if (gCalloutRegistered[index] && Filter->action.calloutId == gCalloutIds[index]) return index;
    }
    return KF_NETWORK_CALLOUTS;
}

static VOID KfNetworkFields(ULONG Index, UINT16* Address, UINT16* Port, UINT16* Protocol)
{
    if (Index == 0) {
        *Address = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS;
        *Port = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT;
        *Protocol = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL;
    } else if (Index == 1) {
        *Address = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS;
        *Port = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT;
        *Protocol = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL;
    } else if (Index == 2) {
        *Address = FWPS_FIELD_ALE_AUTH_LISTEN_V4_IP_LOCAL_ADDRESS;
        *Port = FWPS_FIELD_ALE_AUTH_LISTEN_V4_IP_LOCAL_PORT;
        *Protocol = KF_NETWORK_NO_FIELD;
    } else if (Index == 3) {
        *Address = FWPS_FIELD_ALE_AUTH_LISTEN_V6_IP_LOCAL_ADDRESS;
        *Port = FWPS_FIELD_ALE_AUTH_LISTEN_V6_IP_LOCAL_PORT;
        *Protocol = KF_NETWORK_NO_FIELD;
    } else if (Index == 4) {
        *Address = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS;
        *Port = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT;
        *Protocol = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL;
    } else {
        *Address = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_ADDRESS;
        *Port = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_PORT;
        *Protocol = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_PROTOCOL;
    }
}

/* Append Value in decimal (or hex) to Buffer at *Length; integer formatting by hand,
 * since classify runs at DISPATCH_LEVEL. */
static VOID KfNetworkAppendNumber(PWCHAR Buffer, ULONG Capacity, ULONG* Length, ULONG Value, ULONG Base)
{
    WCHAR digits[12];
    ULONG count = 0;

    do {
        ULONG digit = Value % Base;
        digits[count++] = (WCHAR)(digit < 10 ? L'0' + digit : L'a' + digit - 10);
        Value /= Base;
    } while (Value != 0 && count < RTL_NUMBER_OF(digits));
    while (count > 0 && *Length + 1 < Capacity) Buffer[(*Length)++] = digits[--count];
}

static VOID KfNetworkAppendText(PWCHAR Buffer, ULONG Capacity, ULONG* Length, PCWSTR Text)
{
    while (*Text != L'\0' && *Length + 1 < Capacity) Buffer[(*Length)++] = *Text++;
}

/* "connect tcp 1.2.3.4:443" / "accept udp [2001:db8:0:0:0:0:0:1]:53": what a network rule names. */
static VOID KfNetworkDescribe(ULONG Index, ULONG Family, ULONG Protocol, const UCHAR* Address, ULONG Port,
                              PWCHAR Buffer, ULONG Capacity, PUNICODE_STRING Text)
{
    ULONG length = 0;
    ULONG part;

    KfNetworkAppendText(Buffer, Capacity, &length, Index < 2 ? L"connect " : Index < 4 ? L"listen " : L"accept ");
    KfNetworkAppendText(Buffer, Capacity, &length, Protocol == 6 ? L"tcp " : Protocol == 17 ? L"udp " : L"ip ");
    if (Family == 4) {
        for (part = 0; part < 4; part++) {
            if (part != 0) KfNetworkAppendText(Buffer, Capacity, &length, L".");
            KfNetworkAppendNumber(Buffer, Capacity, &length, Address[part], 10);
        }
    } else {
        KfNetworkAppendText(Buffer, Capacity, &length, L"[");
        for (part = 0; part < 8; part++) {
            if (part != 0) KfNetworkAppendText(Buffer, Capacity, &length, L":");
            KfNetworkAppendNumber(Buffer, Capacity, &length,
                                  ((ULONG)Address[2 * part] << 8) | Address[2 * part + 1], 16);
        }
        KfNetworkAppendText(Buffer, Capacity, &length, L"]");
    }
    KfNetworkAppendText(Buffer, Capacity, &length, L":");
    KfNetworkAppendNumber(Buffer, Capacity, &length, Port, 10);
    Buffer[length] = L'\0';
    Text->Buffer = Buffer;
    Text->Length = (USHORT)(length * sizeof(WCHAR));
    Text->MaximumLength = (USHORT)(Capacity * sizeof(WCHAR));
}

static VOID NTAPI KfNetworkClassifyInner(
    const FWPS_INCOMING_VALUES0* InFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    void* LayerData,
    const void* ClassifyContext,
    const FWPS_FILTER3* Filter,
    UINT64 FlowContext,
    FWPS_CLASSIFY_OUT0* ClassifyOut
)
{
    ULONG index;
    UINT16 addressField;
    UINT16 portField;
    UINT16 protocolField;
    UINT16 port;
    UINT8 protocol;
    UCHAR address[16];
    ULONG family;
    ULONG action;
    ULONG right;
    ULONG ruleId = 0;
    ULONG flags = 0;
    ULONG mode;
    WCHAR textBuffer[64];
    UNICODE_STRING text;

    UNREFERENCED_PARAMETER(LayerData);
    UNREFERENCED_PARAMETER(ClassifyContext);
    UNREFERENCED_PARAMETER(FlowContext);
    if (ClassifyOut == NULL || InFixedValues == NULL || InMetaValues == NULL) return;
    if ((ClassifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0) return;
    mode = KfPolicyMode();
    if (mode == KFILTER_MODE_OFF) {
        ClassifyOut->actionType = FWP_ACTION_CONTINUE;
        return;
    }
    index = KfNetworkIndex(Filter);
    if (index >= KF_NETWORK_CALLOUTS) {
        ClassifyOut->actionType = FWP_ACTION_CONTINUE;
        return;
    }
    if ((InMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) == 0) {
        ClassifyOut->actionType = FWP_ACTION_CONTINUE;
        return;
    }
    /* shortcut: pid-only WFP lookup, upgrade when WFP exposes a start time */
    if (!KfProcessIsProtectedPid(UlongToHandle((ULONG)InMetaValues->processId), 0)) {
        ClassifyOut->actionType = FWP_ACTION_CONTINUE;
        return;
    }
    if (!KfPolicyBlockNetwork()) {
        ClassifyOut->actionType = FWP_ACTION_CONTINUE;
        return;
    }

    KfNetworkFields(index, &addressField, &portField, &protocolField);
    if (addressField >= InFixedValues->valueCount || portField >= InFixedValues->valueCount ||
        (protocolField != KF_NETWORK_NO_FIELD && protocolField >= InFixedValues->valueCount)) {
        KfLogEventFor(UlongToHandle((ULONG)InMetaValues->processId), KFILTER_TARGET_NETWORK,
                   mode == KFILTER_MODE_BLOCK ? KFilterActionDeny : KFilterActionAudit,
                   KFILTER_EVENT_FLAG_NETWORK | KFILTER_EVENT_FLAG_NAME_FAILURE |
                       (mode == KFILTER_MODE_BLOCK ? 0 : KFILTER_EVENT_FLAG_WOULD_DENY),
                   mode == KFILTER_MODE_BLOCK ? STATUS_ACCESS_DENIED : STATUS_SUCCESS,
                   0, 0, NULL);
        ClassifyOut->actionType = mode == KFILTER_MODE_BLOCK ? FWP_ACTION_BLOCK : FWP_ACTION_CONTINUE;
        if (mode == KFILTER_MODE_BLOCK) ClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        return;
    }
    family = (index & 1) ? 6 : 4;
    RtlZeroMemory(address, sizeof(address));
    if (family == 4) {
        /* WFP supplies the address as a host-order number; store the wire-order
         * bytes that rules hold (InetPtonW layout). */
        (VOID)KfIpv4Bytes(InFixedValues->incomingValue[addressField].value.uint32, address);
    } else {
        RtlCopyMemory(address, InFixedValues->incomingValue[addressField].value.byteArray16,
                      sizeof(address));
    }
    port = InFixedValues->incomingValue[portField].value.uint16;
    protocol = protocolField == KF_NETWORK_NO_FIELD
                   ? 6 : InFixedValues->incomingValue[protocolField].value.uint8;
    right = index < 2 ? KFILTER_RIGHT_CONNECT : KFILTER_RIGHT_LISTEN;

    action = KfPolicyNetworkDecide(UlongToHandle((ULONG)InMetaValues->processId), family, protocol, port, address,
                                   right, &ruleId, &flags);
    KfNetworkDescribe(index, family, protocol, address, port, textBuffer, RTL_NUMBER_OF(textBuffer), &text);
    if ((flags & KFILTER_EVENT_FLAG_RISK) != 0) {
        KfLogEventFor(UlongToHandle((ULONG)InMetaValues->processId), KFILTER_TARGET_NETWORK, KFilterActionRisk, KFILTER_EVENT_FLAG_NETWORK,
                   STATUS_SUCCESS, KfNetworkEventValue(KFilterActionRisk, right, port), ruleId, &text);
    }
    {
        ULONG decision = action;
        if (action == KFilterActionDeny && mode == KFILTER_MODE_AUDIT) action = KFilterActionAudit;
        if (action == KFilterActionDeny) {
            KfLogEventFor(UlongToHandle((ULONG)InMetaValues->processId), KFILTER_TARGET_NETWORK, KFilterActionDeny, KFILTER_EVENT_FLAG_NETWORK | flags,
                       STATUS_ACCESS_DENIED, KfNetworkEventValue(action, right, port), ruleId, &text);
            ClassifyOut->actionType = FWP_ACTION_BLOCK;
            ClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
            return;
        }
        if (action == KFilterActionAudit) {
            KfLogEventFor(UlongToHandle((ULONG)InMetaValues->processId), KFILTER_TARGET_NETWORK, KFilterActionAudit,
                       KfNetworkEventFlags(decision, mode) | flags, STATUS_SUCCESS,
                       KfNetworkEventValue(decision, right, port), ruleId, &text);
        }
        if (action == KFilterActionAllow) {
            KfLogEventFor(UlongToHandle((ULONG)InMetaValues->processId), KFILTER_TARGET_NETWORK, KFilterActionAllow, KFILTER_EVENT_FLAG_NETWORK | flags,
                       STATUS_SUCCESS, KfNetworkEventValue(action, right, port), ruleId, &text);
        }
    }
    ClassifyOut->actionType = FWP_ACTION_CONTINUE;
}

static VOID NTAPI KfNetworkClassify(
    const FWPS_INCOMING_VALUES0* InFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    void* LayerData,
    const void* ClassifyContext,
    const FWPS_FILTER3* Filter,
    UINT64 FlowContext,
    FWPS_CLASSIFY_OUT0* ClassifyOut
)
{
    if (!gNetworkRundownInitialized || !ExAcquireRundownProtection(&gNetworkRundown)) {
        if (ClassifyOut != NULL && (ClassifyOut->rights & FWPS_RIGHT_ACTION_WRITE) != 0) {
            ClassifyOut->actionType = FWP_ACTION_BLOCK;
            ClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        }
        return;
    }
    KfNetworkClassifyInner(InFixedValues, InMetaValues, LayerData, ClassifyContext,
                           Filter, FlowContext, ClassifyOut);
    ExReleaseRundownProtection(&gNetworkRundown);
}

static NTSTATUS NTAPI KfNetworkNotify(
    FWPS_CALLOUT_NOTIFY_TYPE NotifyType,
    const GUID* FilterKey,
    const FWPS_FILTER3* Filter
)
{
    UNREFERENCED_PARAMETER(NotifyType);
    UNREFERENCED_PARAMETER(FilterKey);
    UNREFERENCED_PARAMETER(Filter);
    return STATUS_SUCCESS;
}

static NTSTATUS KfNetworkAddCallout(PDEVICE_OBJECT DeviceObject, ULONG Index,
                                    const GUID* LayerKey, PCWSTR Name)
{
    FWPS_CALLOUT3 callout;
    FWPM_CALLOUT managerCallout;
    FWPM_FILTER filter;
    NTSTATUS status;

    RtlZeroMemory(&callout, sizeof(callout));
    callout.calloutKey = gCalloutKeys[Index];
    callout.classifyFn = KfNetworkClassify;
    callout.notifyFn = KfNetworkNotify;
    status = FwpsCalloutRegister3(DeviceObject, &callout, &gCalloutIds[Index]);
    if (!NT_SUCCESS(status)) return status;
    gCalloutRegistered[Index] = TRUE;

    RtlZeroMemory(&managerCallout, sizeof(managerCallout));
    managerCallout.calloutKey = gCalloutKeys[Index];
    managerCallout.displayData.name = (PWSTR)Name;
    managerCallout.displayData.description = (PWSTR)L"kfilter protected-process network authorization";
    /* Required: without it FwpmCalloutAdd fails with FWP_E_LAYER_NOT_FOUND and no filter is added. */
    managerCallout.applicableLayer = *LayerKey;
    managerCallout.calloutId = gCalloutIds[Index];
    status = FwpmCalloutAdd(gEngine, &managerCallout, NULL, NULL);
    if (!NT_SUCCESS(status)) return status;

    RtlZeroMemory(&filter, sizeof(filter));
    filter.displayData.name = (PWSTR)Name;
    filter.displayData.description = (PWSTR)L"kfilter ALE authorization";
    filter.layerKey = *LayerKey;
    /* UNKNOWN, not TERMINATING: the callout returns CONTINUE for traffic it does not block,
     * so it never overrides another filter's decision with a permit. */
    filter.action.type = FWP_ACTION_CALLOUT_UNKNOWN;
    filter.action.calloutKey = gCalloutKeys[Index];
    filter.weight.type = FWP_EMPTY;
    return FwpmFilterAdd(gEngine, &filter, NULL, NULL);
}

/* A registration failure is also logged (Value = layer index, or 0xFFFF for the engine;
 * Status = the error), so it can be read from the event ring without a debugger. */
static VOID KfNetworkLogFailure(ULONG Index, NTSTATUS Status)
{
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"kfilter WFP registration");
    KfLogEvent(KFILTER_TARGET_NETWORK, KFilterActionAudit, KFILTER_EVENT_FLAG_NETWORK, Status, Index, 0, &name);
}

NTSTATUS KfNetworkInitialize(PDEVICE_OBJECT DeviceObject)
{
    static const GUID* layers[KF_NETWORK_CALLOUTS] = {
        &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        &FWPM_LAYER_ALE_AUTH_LISTEN_V4,
        &FWPM_LAYER_ALE_AUTH_LISTEN_V6,
        &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6
    };
    static PCWSTR names[KF_NETWORK_CALLOUTS] = {
        L"kfilter connect IPv4", L"kfilter connect IPv6",
        L"kfilter listen IPv4", L"kfilter listen IPv6",
        L"kfilter accept IPv4", L"kfilter accept IPv6"
    };
    FWPM_SESSION session;
    NTSTATUS status;
    ULONG index;

    ExInitializeRundownProtection(&gNetworkRundown);
    gNetworkRundownInitialized = TRUE;
    gEngine = NULL;
    gLayerMask = 0;
    RtlZeroMemory(gCalloutIds, sizeof(gCalloutIds));
    RtlZeroMemory(gCalloutRegistered, sizeof(gCalloutRegistered));

    RtlZeroMemory(&session, sizeof(session));
    session.displayData.name = (PWSTR)L"kfilter WFP session";
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    status = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &gEngine);
    if (!NT_SUCCESS(status)) {
        DbgPrint("kfilter: WFP engine open failed 0x%08X\n", status);
        KfNetworkLogFailure(0xFFFF, status);
        return status;
    }
    for (index = 0; index < KF_NETWORK_CALLOUTS; index++) {
        status = KfNetworkAddCallout(DeviceObject, index, layers[index], names[index]);
        if (NT_SUCCESS(status)) {
            gLayerMask |= 1u << index;
        } else {
            DbgPrint("kfilter: WFP layer %lu failed 0x%08X\n", index, status);
            KfNetworkLogFailure(index, status);
        }
    }
    return STATUS_SUCCESS;
}

BOOLEAN KfNetworkAvailable(VOID)
{
    return (gLayerMask & 0x3Fu) == 0x3Fu;
}

VOID KfNetworkUninitialize(VOID)
{
    ULONG index;
    ULONG failures = 0;
    LARGE_INTEGER delay;

    delay.QuadPart = -10000;
    if (gEngine != NULL) {
        (VOID)FwpmEngineClose(gEngine);
        gEngine = NULL;
    }
    for (index = 0; index < KF_NETWORK_CALLOUTS; index++) {
        while (gCalloutRegistered[index]) {
            NTSTATUS status = FwpsCalloutUnregisterById0(gCalloutIds[index]);
            if (KfNetworkUnregisterComplete(status)) {
                gCalloutRegistered[index] = FALSE;
                break;
            }
            failures++;
            if ((failures & 0x3FFu) == 1u) KfNetworkLogFailure(index, status);
            KeDelayExecutionThread(KernelMode, FALSE, &delay);
        }
    }
    if (gNetworkRundownInitialized) {
        ExWaitForRundownProtectionRelease(&gNetworkRundown);
        ExRundownCompleted(&gNetworkRundown);
        gNetworkRundownInitialized = FALSE;
    }
    gLayerMask = 0;
}
