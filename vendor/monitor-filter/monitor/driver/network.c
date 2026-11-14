#include <ntddk.h>
#pragma warning(push)
#pragma warning(disable:4201)
#define NDIS630 1
#include <ndis.h>
#pragma warning(pop)
#include <fwpsk.h>
#include <fwpmk.h>
#include <ntstrsafe.h>
#include "../include/msmon_protocol.h"
#include "../include/msmon_coverage.h"

VOID MsMonCoverageEnter(ULONG SensorId);
VOID MsMonCoverageLogged(ULONG SensorId);
VOID MsMonCoverageSkip(MSMON_SKIP_REASON Reason);
VOID MsMonCoverageRegister(ULONG SensorId, NTSTATUS Status);

#define MSMON_POOL_TAG 'noSM'
#define MSMON_CALLOUT_COUNT 6

BOOLEAN MsMonIsTracked(HANDLE ProcessId, LONGLONG StartTime);
LONGLONG MsMonProcessStartTime(HANDLE ProcessId);
BOOLEAN MsMonCurrentIsBlackCat(VOID);
NTSTATUS MsMonLogEvent(ULONG Type, HANDLE ProcessId, LONGLONG ProcessStartTime, HANDLE ParentProcessId, HANDLE ThreadId,
                       HANDLE TargetProcessId, LONGLONG TargetProcessStartTime, ULONG Flags,
                       NTSTATUS Status, ULONG DesiredAccess, ULONG Category,
                       ULONGLONG Value0, ULONGLONG Value1,
                       PCUNICODE_STRING Text, PCUNICODE_STRING Detail);
VOID MsMonNetworkUninitialize(VOID);

static const GUID MSMON_CALLOUT_KEYS[MSMON_CALLOUT_COUNT] = {
    { 0x43f00e61, 0x2a6f, 0x4dd3, { 0x91, 0x3b, 0x1b, 0x42, 0x8c, 0x83, 0x20, 0x01 } },
    { 0x43f00e61, 0x2a6f, 0x4dd3, { 0x91, 0x3b, 0x1b, 0x42, 0x8c, 0x83, 0x20, 0x02 } },
    { 0x43f00e61, 0x2a6f, 0x4dd3, { 0x91, 0x3b, 0x1b, 0x42, 0x8c, 0x83, 0x20, 0x03 } },
    { 0x43f00e61, 0x2a6f, 0x4dd3, { 0x91, 0x3b, 0x1b, 0x42, 0x8c, 0x83, 0x20, 0x04 } },
    { 0x43f00e61, 0x2a6f, 0x4dd3, { 0x91, 0x3b, 0x1b, 0x42, 0x8c, 0x83, 0x20, 0x05 } },
    { 0x43f00e61, 0x2a6f, 0x4dd3, { 0x91, 0x3b, 0x1b, 0x42, 0x8c, 0x83, 0x20, 0x06 } }
};

typedef struct _MSMON_FLOW_CONTEXT {
    LIST_ENTRY Link;
    UINT64 FlowId;
    UINT32 CalloutId;
    UINT16 LayerId;
    HANDLE ProcessId;
    LONGLONG ProcessStartTime;
    UINT8 Protocol;
    UINT16 LocalPort;
    UINT16 RemotePort;
    BOOLEAN Associating;
    BOOLEAN Deleted;
    WCHAR Endpoints[128];
} MSMON_FLOW_CONTEXT, *PMSMON_FLOW_CONTEXT;

static HANDLE gEngine;
static UINT32 gCalloutIds[MSMON_CALLOUT_COUNT];
static BOOLEAN gCalloutRegistered[MSMON_CALLOUT_COUNT];
static LIST_ENTRY gFlows;
static KSPIN_LOCK gFlowLock;
static BOOLEAN gFlowListInitialized;
static BOOLEAN gNetworkActive;
static ULONG gNetworkLayerMask;
static NTSTATUS gNetworkLayerStatus[MSMON_CALLOUT_COUNT];
static EX_RUNDOWN_REF gNetworkRundown;
static BOOLEAN gNetworkRundownInitialized;

static VOID NTAPI MsMonWfpFlowDelete(UINT16 LayerId, UINT32 CalloutId, UINT64 FlowContext);

/*
 * Classify and flow-delete run at DISPATCH_LEVEL, where RtlStringCchPrintfW
 * must not be used: the kernel CRT formats numbers as narrow text and widens
 * each character through RtlAnsiCharToUnicodeChar, which reads the current
 * process's PEB.  With that page not resident the read bugchecks
 * (IRQL_NOT_LESS_OR_EQUAL in nt!RtlpIsUtf8Process).  Build the text by hand.
 */
static VOID MsMonAppendText(PWSTR Output, SIZE_T Characters, SIZE_T* Offset, PCWSTR Text)
{
    while (*Text != L'\0' && *Offset + 1 < Characters) Output[(*Offset)++] = *Text++;
    Output[*Offset] = L'\0';
}

static VOID MsMonAppendUnsigned(PWSTR Output, SIZE_T Characters, SIZE_T* Offset, ULONG Value)
{
    WCHAR digits[10];
    ULONG count = 0;
    do {
        digits[count++] = (WCHAR)(L'0' + Value % 10);
        Value /= 10;
    } while (Value != 0);
    while (count > 0 && *Offset + 1 < Characters) Output[(*Offset)++] = digits[--count];
    Output[*Offset] = L'\0';
}

/* WFP supplies IPv4 addresses and ports in host byte order: most significant octet first. */
static VOID MsMonFormatIpv4(UINT32 Address, PWSTR Output, SIZE_T Characters)
{
    SIZE_T offset = 0;
    ULONG index;
    if (Characters == 0) return;
    Output[0] = L'\0';
    for (index = 0; index < 4; index++) {
        if (index != 0) MsMonAppendText(Output, Characters, &offset, L".");
        MsMonAppendUnsigned(Output, Characters, &offset, (Address >> (24 - 8 * index)) & 0xff);
    }
}

static VOID MsMonFormatIpv6(const FWP_BYTE_ARRAY16* Address, PWSTR Output, SIZE_T Characters)
{
    static const WCHAR hex[] = L"0123456789abcdef";
    ULONG index;
    ULONG offset = 0;
    if (Address == NULL || Characters < 40) {
        if (Characters != 0) Output[0] = L'\0';
        return;
    }
    for (index = 0; index < 16; index++) {
        Output[offset++] = hex[Address->byteArray16[index] >> 4];
        Output[offset++] = hex[Address->byteArray16[index] & 0xf];
        if ((index & 1) == 1 && index != 15) Output[offset++] = L':';
    }
    Output[offset] = L'\0';
}

static ULONG MsMonCalloutIndex(const FWPS_FILTER3* Filter)
{
    ULONG index;
    for (index = 0; index < MSMON_CALLOUT_COUNT; index++) {
        if (gCalloutRegistered[index] && Filter->action.calloutId == gCalloutIds[index]) return index;
    }
    return MSMON_CALLOUT_COUNT;
}

static VOID MsMonSelectFields(
    ULONG Index,
    PUINT16 LocalAddress,
    PUINT16 RemoteAddress,
    PUINT16 LocalPort,
    PUINT16 RemotePort,
    PUINT16 Protocol
)
{
    BOOLEAN ipv6 = (Index & 1) != 0;
    if (Index >= 4) {
        if (ipv6) {
            *LocalAddress = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_ADDRESS;
            *RemoteAddress = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_REMOTE_ADDRESS;
            *LocalPort = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_PORT;
            *RemotePort = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_REMOTE_PORT;
            *Protocol = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_PROTOCOL;
        } else {
            *LocalAddress = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_ADDRESS;
            *RemoteAddress = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_ADDRESS;
            *LocalPort = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_PORT;
            *RemotePort = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_PORT;
            *Protocol = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_PROTOCOL;
        }
    } else if (Index >= 2) {
        if (ipv6) {
            *LocalAddress = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_ADDRESS;
            *RemoteAddress = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_ADDRESS;
            *LocalPort = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_PORT;
            *RemotePort = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_PORT;
            *Protocol = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_PROTOCOL;
        } else {
            *LocalAddress = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_ADDRESS;
            *RemoteAddress = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS;
            *LocalPort = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT;
            *RemotePort = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT;
            *Protocol = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL;
        }
    } else {
        if (ipv6) {
            *LocalAddress = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_ADDRESS;
            *RemoteAddress = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS;
            *LocalPort = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_PORT;
            *RemotePort = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT;
            *Protocol = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL;
        } else {
            *LocalAddress = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS;
            *RemoteAddress = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS;
            *LocalPort = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT;
            *RemotePort = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT;
            *Protocol = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL;
        }
    }
}

static VOID MsMonLogNetwork(
    ULONG Type,
    HANDLE ProcessId,
    LONGLONG ProcessStartTime,
    UINT64 FlowId,
    UINT8 Protocol,
    UINT16 LocalPort,
    UINT16 RemotePort,
    PCWSTR Endpoints,
    PCWSTR Direction
)
{
    UNICODE_STRING text;
    UNICODE_STRING detail;
    ULONGLONG packed = ((ULONGLONG)Protocol << 32) | ((ULONGLONG)LocalPort << 16) | RemotePort;
    RtlInitUnicodeString(&text, Endpoints);
    RtlInitUnicodeString(&detail, Direction);
    (VOID)MsMonLogEvent(Type, ProcessId, ProcessStartTime, NULL, NULL, NULL, 0, 0, STATUS_SUCCESS, 0,
                        MsMonCategoryNetwork, FlowId, packed, &text, &detail);
}

/* Take the entry for FlowId out of gFlows and report whether this caller owns it.
 * Keyed on the flow id the branch captured before it linked the context, never on
 * the context address: a context a flowDeleteFn already freed, or a new one that
 * reused its address, must not be unlinked or freed here. */
static BOOLEAN MsMonFlowUnlink(UINT64 FlowId)
{
    PLIST_ENTRY link;
    BOOLEAN removed = FALSE;
    KIRQL oldIrql;

    if (!gFlowListInitialized || FlowId == 0) return FALSE;
    KeAcquireSpinLock(&gFlowLock, &oldIrql);
    for (link = gFlows.Flink; link != &gFlows; link = link->Flink) {
        PMSMON_FLOW_CONTEXT candidate = CONTAINING_RECORD(link, MSMON_FLOW_CONTEXT, Link);
        if (candidate->FlowId == FlowId) {
            RemoveEntryList(&candidate->Link);
            removed = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&gFlowLock, oldIrql);
    return removed;
}

static VOID MsMonAssociateFlow(
    const FWPS_INCOMING_VALUES0* InFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    ULONG Index,
    UINT64 FlowId,
    UINT8 Protocol,
    UINT16 LocalPort,
    UINT16 RemotePort,
    PCWSTR Endpoints
)
{
    PMSMON_FLOW_CONTEXT context;
    KIRQL oldIrql;
    NTSTATUS status;
    UINT64 flowId = FlowId;
    UINT16 layerId = InFixedValues->layerId;
    UINT32 calloutId = gCalloutIds[Index];
    BOOLEAN deleted;
    BOOLEAN active;
    if (!gFlowListInitialized || (InMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_FLOW_HANDLE) == 0 ||
        FlowId == 0) return;
    context = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*context), MSMON_POOL_TAG);
    if (context == NULL) return;
    RtlZeroMemory(context, sizeof(*context));
    context->FlowId = flowId;
    context->CalloutId = calloutId;
    context->LayerId = layerId;
    context->ProcessId = UlongToHandle((ULONG)InMetaValues->processId);
    context->ProcessStartTime = MsMonProcessStartTime(context->ProcessId);
    context->Protocol = Protocol;
    context->LocalPort = LocalPort;
    context->RemotePort = RemotePort;
    (VOID)RtlStringCchCopyW(context->Endpoints, RTL_NUMBER_OF(context->Endpoints), Endpoints);

    /* The delete callback can mark but never frees an associating context. */
    KeAcquireSpinLock(&gFlowLock, &oldIrql);
    context->Associating = TRUE;
    InsertTailList(&gFlows, &context->Link);
    KeReleaseSpinLock(&gFlowLock, oldIrql);
    status = FwpsFlowAssociateContext0(flowId, layerId, calloutId, (UINT64)context);

    KeAcquireSpinLock(&gFlowLock, &oldIrql);
    context->Associating = FALSE;
    deleted = context->Deleted;
    active = gNetworkActive;
    if (!NT_SUCCESS(status) && !deleted) RemoveEntryList(&context->Link);
    KeReleaseSpinLock(&gFlowLock, oldIrql);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(context, MSMON_POOL_TAG);
        return;
    }
    if (deleted) {
        MsMonLogNetwork(MsMonNetworkFlowClose, context->ProcessId, context->ProcessStartTime,
                        flowId, context->Protocol, context->LocalPort, context->RemotePort,
                        context->Endpoints, L"flow_close");
        ExFreePoolWithTag(context, MSMON_POOL_TAG);
        return;
    }
    if (active) return;

    status = FwpsFlowRemoveContext0(flowId, layerId, calloutId);
    if ((ULONG)status == 0xC0000001u) {
        /* No association was present, so no flowDeleteFn will come: take the
         * entry back by flow id and free it here. */
        if (MsMonFlowUnlink(flowId)) ExFreePoolWithTag(context, MSMON_POOL_TAG);
    }
    /* STATUS_SUCCESS: the synchronous flowDeleteFn found the linked entry and
     * freed it. PENDING (or any incomplete result): the delayed flowDeleteFn
     * or the unload drain frees it. */
}

static VOID NTAPI MsMonWfpClassifyInner(
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
    UINT16 localAddressField;
    UINT16 remoteAddressField;
    UINT16 localPortField;
    UINT16 remotePortField;
    UINT16 protocolField;
    UINT16 localPort;
    UINT16 remotePort;
    UINT8 protocol;
    UINT64 flowId = 0;
    WCHAR local[48];
    WCHAR remote[48];
    WCHAR endpoints[128];
    SIZE_T endpointsLength;
    PCWSTR direction;
    ULONG type;

    UNREFERENCED_PARAMETER(LayerData);
    UNREFERENCED_PARAMETER(ClassifyContext);
    UNREFERENCED_PARAMETER(FlowContext);
    MsMonCoverageEnter(MSMON_SENSOR_WFP_CLASSIFY);
    if (ClassifyOut == NULL) return;
    index = Filter != NULL ? MsMonCalloutIndex(Filter) : MSMON_CALLOUT_COUNT;
    do {
        if (index >= MSMON_CALLOUT_COUNT || InFixedValues == NULL || InMetaValues == NULL) break;
        if ((InMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) == 0) break;
        if (!MsMonIsTracked(UlongToHandle((ULONG)InMetaValues->processId), 0) &&
            !MsMonCurrentIsBlackCat()) {
            MsMonCoverageSkip(MSMON_SKIP_UNTRACKED);
            break;
        }
        MsMonSelectFields(index, &localAddressField, &remoteAddressField,
                          &localPortField, &remotePortField, &protocolField);
        /*
         * Never index the layer's value array past the count the filter engine
         * supplied; a layer that reports fewer fields would otherwise make the
         * callout read out of bounds.
         */
        if (protocolField >= InFixedValues->valueCount ||
            localAddressField >= InFixedValues->valueCount ||
            remoteAddressField >= InFixedValues->valueCount ||
            localPortField >= InFixedValues->valueCount ||
            remotePortField >= InFixedValues->valueCount) break;
        localPort = InFixedValues->incomingValue[localPortField].value.uint16;
        remotePort = InFixedValues->incomingValue[remotePortField].value.uint16;
        protocol = InFixedValues->incomingValue[protocolField].value.uint8;
        if ((InMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_FLOW_HANDLE) != 0) {
            flowId = InMetaValues->flowHandle;
        }
        if ((index & 1) != 0) {
            MsMonFormatIpv6(InFixedValues->incomingValue[localAddressField].value.byteArray16,
                            local, RTL_NUMBER_OF(local));
            MsMonFormatIpv6(InFixedValues->incomingValue[remoteAddressField].value.byteArray16,
                            remote, RTL_NUMBER_OF(remote));
        } else {
            MsMonFormatIpv4(InFixedValues->incomingValue[localAddressField].value.uint32,
                            local, RTL_NUMBER_OF(local));
            MsMonFormatIpv4(InFixedValues->incomingValue[remoteAddressField].value.uint32,
                            remote, RTL_NUMBER_OF(remote));
        }
        endpointsLength = 0;
        endpoints[0] = L'\0';
        MsMonAppendText(endpoints, RTL_NUMBER_OF(endpoints), &endpointsLength, local);
        MsMonAppendText(endpoints, RTL_NUMBER_OF(endpoints), &endpointsLength, L":");
        MsMonAppendUnsigned(endpoints, RTL_NUMBER_OF(endpoints), &endpointsLength, localPort);
        MsMonAppendText(endpoints, RTL_NUMBER_OF(endpoints), &endpointsLength, L" -> ");
        MsMonAppendText(endpoints, RTL_NUMBER_OF(endpoints), &endpointsLength, remote);
        MsMonAppendText(endpoints, RTL_NUMBER_OF(endpoints), &endpointsLength, L":");
        MsMonAppendUnsigned(endpoints, RTL_NUMBER_OF(endpoints), &endpointsLength, remotePort);
        if (index >= 4) {
            type = MsMonNetworkFlowEstablished;
            direction = L"flow_established";
        } else if (index >= 2) {
            type = MsMonNetworkAccept;
            direction = L"recv_accept";
        } else {
            type = MsMonNetworkConnect;
            direction = L"connect";
        }
        MsMonLogNetwork(type, UlongToHandle((ULONG)InMetaValues->processId),
                        MsMonProcessStartTime(UlongToHandle((ULONG)InMetaValues->processId)), flowId,
                        protocol, localPort, remotePort, endpoints, direction);
        MsMonCoverageLogged(MSMON_SENSOR_WFP_CLASSIFY);
        if (index >= 4 && FlowContext == 0) {
            MsMonAssociateFlow(InFixedValues, InMetaValues, index, flowId,
                               protocol, localPort, remotePort, endpoints);
        }
    } while (0);
    if ((ClassifyOut->rights & FWPS_RIGHT_ACTION_WRITE) != 0) {
        ClassifyOut->actionType = FWP_ACTION_CONTINUE;
    }
}

static VOID NTAPI MsMonWfpClassify(
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
            ClassifyOut->actionType = FWP_ACTION_CONTINUE;
        }
        return;
    }
    MsMonWfpClassifyInner(InFixedValues, InMetaValues, LayerData, ClassifyContext,
                          Filter, FlowContext, ClassifyOut);
    ExReleaseRundownProtection(&gNetworkRundown);
}

static NTSTATUS NTAPI MsMonWfpNotify(
    FWPS_CALLOUT_NOTIFY_TYPE NotifyType,
    const GUID* FilterKey,
    const FWPS_FILTER3* Filter
)
{
    UNREFERENCED_PARAMETER(NotifyType);
    UNREFERENCED_PARAMETER(FilterKey);
    UNREFERENCED_PARAMETER(Filter);
    MsMonCoverageEnter(MSMON_SENSOR_WFP_NOTIFY);
    return STATUS_SUCCESS;
}

static VOID NTAPI MsMonWfpFlowDeleteInner(UINT16 LayerId, UINT32 CalloutId, UINT64 FlowContext)
{
    PLIST_ENTRY link;
    PMSMON_FLOW_CONTEXT context = NULL;
    KIRQL oldIrql;
    UNREFERENCED_PARAMETER(LayerId);
    UNREFERENCED_PARAMETER(CalloutId);
    if (!gFlowListInitialized || FlowContext == 0) return;
    KeAcquireSpinLock(&gFlowLock, &oldIrql);
    for (link = gFlows.Flink; link != &gFlows; link = link->Flink) {
        PMSMON_FLOW_CONTEXT candidate = CONTAINING_RECORD(link, MSMON_FLOW_CONTEXT, Link);
        if ((UINT64)candidate == FlowContext) {
            RemoveEntryList(&candidate->Link);
            if (candidate->Associating) {
                candidate->Deleted = TRUE;
            } else {
                context = candidate;
            }
            break;
        }
    }
    KeReleaseSpinLock(&gFlowLock, oldIrql);
    if (context != NULL) {
        MsMonLogNetwork(MsMonNetworkFlowClose, context->ProcessId, context->ProcessStartTime, context->FlowId,
                        context->Protocol, context->LocalPort, context->RemotePort,
                        context->Endpoints, L"flow_close");
        ExFreePoolWithTag(context, MSMON_POOL_TAG);
    }
}

static VOID NTAPI MsMonWfpFlowDelete(UINT16 LayerId, UINT32 CalloutId, UINT64 FlowContext)
{
    if (!gNetworkRundownInitialized || !ExAcquireRundownProtection(&gNetworkRundown)) return;
    MsMonWfpFlowDeleteInner(LayerId, CalloutId, FlowContext);
    ExReleaseRundownProtection(&gNetworkRundown);
}

static NTSTATUS MsMonAddCallout(
    PDEVICE_OBJECT DeviceObject,
    ULONG Index,
    const GUID* LayerKey,
    PCWSTR Name
)
{
    FWPS_CALLOUT3 callout;
    FWPM_CALLOUT managerCallout;
    FWPM_FILTER filter;
    NTSTATUS status;

    RtlZeroMemory(&callout, sizeof(callout));
    callout.calloutKey = MSMON_CALLOUT_KEYS[Index];
    callout.classifyFn = MsMonWfpClassify;
    callout.notifyFn = MsMonWfpNotify;
    if (Index >= 4) callout.flowDeleteFn = MsMonWfpFlowDelete;
    status = FwpsCalloutRegister3(DeviceObject, &callout, &gCalloutIds[Index]);
    if (!NT_SUCCESS(status)) return status;
    gCalloutRegistered[Index] = TRUE;

    RtlZeroMemory(&managerCallout, sizeof(managerCallout));
    managerCallout.calloutKey = MSMON_CALLOUT_KEYS[Index];
    managerCallout.displayData.name = (PWSTR)Name;
    managerCallout.displayData.description = (PWSTR)L"MapleStory application network metadata monitor";
    managerCallout.applicableLayer = *LayerKey;
    managerCallout.calloutId = gCalloutIds[Index];
    status = FwpmCalloutAdd(gEngine, &managerCallout, NULL, NULL);
    if (!NT_SUCCESS(status)) return status;

    RtlZeroMemory(&filter, sizeof(filter));
    filter.displayData.name = (PWSTR)Name;
    filter.displayData.description = (PWSTR)L"Observe application network authorization and flow events";
    filter.layerKey = *LayerKey;
    filter.action.type = FWP_ACTION_CALLOUT_UNKNOWN;
    filter.action.calloutKey = MSMON_CALLOUT_KEYS[Index];
    filter.weight.type = FWP_EMPTY;
    return FwpmFilterAdd(gEngine, &filter, NULL, NULL);
}

NTSTATUS MsMonNetworkInitialize(PDEVICE_OBJECT DeviceObject)
{
    const GUID* layers[MSMON_CALLOUT_COUNT] = {
        &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        &FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4,
        &FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6
    };
    PCWSTR names[MSMON_CALLOUT_COUNT] = {
        L"MsMon connect IPv4", L"MsMon connect IPv6",
        L"MsMon accept IPv4", L"MsMon accept IPv6",
        L"MsMon flow IPv4", L"MsMon flow IPv6"
    };
    FWPM_SESSION session;
    NTSTATUS status;
    ULONG index;
    ExInitializeRundownProtection(&gNetworkRundown);
    gNetworkRundownInitialized = TRUE;
    KeInitializeSpinLock(&gFlowLock);
    InitializeListHead(&gFlows);
    gFlowListInitialized = TRUE;
    gNetworkActive = FALSE;
    gNetworkLayerMask = 0;

    RtlZeroMemory(&session, sizeof(session));
    session.displayData.name = (PWSTR)L"MsMon dynamic session";
    session.displayData.description = (PWSTR)L"Passive application network monitoring";
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    status = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &gEngine);
    MsMonCoverageRegister(MSMON_SENSOR_REG_WFP_ENGINE, status);
    if (!NT_SUCCESS(status)) return status;

    for (index = 0; index < MSMON_CALLOUT_COUNT; index++) {
        status = MsMonAddCallout(DeviceObject, index, layers[index], names[index]);
        MsMonCoverageRegister(MSMON_SENSOR_REG_WFP_0 + index, status);
        gNetworkLayerStatus[index] = status;
        if (NT_SUCCESS(status)) {
            gNetworkLayerMask |= 1u << index;
        } else {
            DbgPrint("MsMon: WFP layer %lu initialization failed 0x%08X\n", index, status);
        }
    }
    gNetworkActive = gNetworkLayerMask != 0;
    return STATUS_SUCCESS;
}

BOOLEAN MsMonNetworkAvailable(VOID)
{
    return gNetworkActive;
}

ULONG MsMonNetworkCoverage(VOID)
{
    return gNetworkLayerMask;
}

VOID MsMonNetworkUninitialize(VOID)
{
    ULONG index;
    ULONG failures = 0;
    KIRQL oldIrql;
    LARGE_INTEGER delay;

    delay.QuadPart = -10000;
    gNetworkActive = FALSE;
    /*
     * Stop classify and flowDelete work before touching the list. The inactive
     * association branch links a context before removing it, so a classify
     * callback still in flight could otherwise link one after the drain. The
     * wait refuses new acquisitions; ExRundownCompleted follows the drain.
     * DriverEntry's failure path calls this before MsMonNetworkInitialize, so
     * the guard stays.
     */
    if (gNetworkRundownInitialized) {
        ExWaitForRundownProtectionRelease(&gNetworkRundown);
    }
    /*
     * A pending removal calls flowDeleteFn asynchronously. The context is already
     * out of our list, so retain ownership and do not free it until WFP confirms
     * that its association is gone.
     */
    if (gFlowListInitialized) {
        for (;;) {
            PMSMON_FLOW_CONTEXT context = NULL;
            NTSTATUS status;
            KeAcquireSpinLock(&gFlowLock, &oldIrql);
            if (!IsListEmpty(&gFlows)) {
                PLIST_ENTRY entry = RemoveHeadList(&gFlows);
                context = CONTAINING_RECORD(entry, MSMON_FLOW_CONTEXT, Link);
            }
            KeReleaseSpinLock(&gFlowLock, oldIrql);
            if (context == NULL) break;
            do {
                status = FwpsFlowRemoveContext0(context->FlowId, context->LayerId, context->CalloutId);
                if (!MsMonFlowRemoveComplete((long)status)) {
                    KeDelayExecutionThread(KernelMode, FALSE, &delay);
                }
            } while (!MsMonFlowRemoveComplete((long)status));
            MsMonLogNetwork(MsMonNetworkFlowClose, context->ProcessId, context->ProcessStartTime, context->FlowId,
                            context->Protocol, context->LocalPort, context->RemotePort,
                            context->Endpoints, L"flow_close_monitor_stop");
            ExFreePoolWithTag(context, MSMON_POOL_TAG);
        }
        gFlowListInitialized = FALSE;
    }
    if (gEngine != NULL) {
        (VOID)FwpmEngineClose(gEngine);
        gEngine = NULL;
    }
    for (index = 0; index < MSMON_CALLOUT_COUNT; index++) {
        while (gCalloutRegistered[index]) {
            NTSTATUS status = FwpsCalloutUnregisterById0(gCalloutIds[index]);
            if (MsMonNetworkUnregisterComplete(status)) {
                gCalloutRegistered[index] = FALSE;
                gNetworkLayerStatus[index] = STATUS_SUCCESS;
                break;
            }
            gNetworkLayerStatus[index] = status;
            failures++;
            if ((failures & 0x3FFu) == 1u) {
                DbgPrint("MsMon: WFP callout %lu unregister failed 0x%08X\n", index, status);
            }
            KeDelayExecutionThread(KernelMode, FALSE, &delay);
        }
    }
    if (gNetworkRundownInitialized) {
        ExRundownCompleted(&gNetworkRundown);
        gNetworkRundownInitialized = FALSE;
    }
    gNetworkLayerMask = 0;
}
