#include "msmon.h"

typedef struct _MSMON_EVENT_BLOCK {
    LIST_ENTRY Link;
    MSMON_EVENT_HEADER Event;
} MSMON_EVENT_BLOCK, *PMSMON_EVENT_BLOCK;

typedef struct _MSMON_EVENT_QUEUE {
    KSPIN_LOCK Lock;
    LIST_ENTRY Head;
    KEVENT DataAvailable;
    ULONGLONG Sequence;
    ULONGLONG SessionId;
    ULONGLONG OperationId;
    volatile LONG64 Dropped;
    volatile LONG Queued;
    volatile LONG64 QueuedBytes;
    ULONG QueueRecordLimit;
    ULONG QueueByteLimit;
    volatile BOOLEAN PayloadEnabled;
} MSMON_EVENT_QUEUE;

static MSMON_EVENT_QUEUE gQueue;
static BOOLEAN gQueueInitialized;
static MSMON_COVERAGE gCoverage;

/* Upper bound on chunks emitted for one payload operation (8 MiB). */
#define MSMON_MAX_PAYLOAD_CHUNKS 1024u

static USHORT MsMonStringBytes(PCUNICODE_STRING Value, PBOOLEAN Truncated)
{
    if (Value == NULL || Value->Buffer == NULL || Value->Length == 0) return 0;
    if (Value->Length > MSMON_MAX_EVENT_STRING_BYTES) {
        *Truncated = TRUE;
        return MSMON_MAX_EVENT_STRING_BYTES;
    }
    return Value->Length;
}

static VOID MsMonClearQueueLocked(VOID)
{
    while (!IsListEmpty(&gQueue.Head)) {
        PLIST_ENTRY entry = RemoveHeadList(&gQueue.Head);
        PMSMON_EVENT_BLOCK block = CONTAINING_RECORD(entry, MSMON_EVENT_BLOCK, Link);
        ExFreePoolWithTag(block, MSMON_POOL_TAG);
    }
    gQueue.Queued = 0;
    gQueue.QueuedBytes = 0;
    KeResetEvent(&gQueue.DataAvailable);
}

NTSTATUS MsMonEventsInitialize(VOID)
{
    KeInitializeSpinLock(&gQueue.Lock);
    InitializeListHead(&gQueue.Head);
    KeInitializeEvent(&gQueue.DataAvailable, SynchronizationEvent, FALSE);
    gQueue.Sequence = 0;
    gQueue.SessionId = 0;
    gQueue.OperationId = 0;
    gQueue.Dropped = 0;
    gQueue.Queued = 0;
    gQueue.QueuedBytes = 0;
    gQueue.QueueRecordLimit = MSMON_DEFAULT_QUEUE_RECORDS;
    gQueue.QueueByteLimit = MSMON_DEFAULT_QUEUE_BYTES;
    gQueue.PayloadEnabled = FALSE;
    gQueueInitialized = TRUE;
    return STATUS_SUCCESS;
}

NTSTATUS MsMonEventsStart(ULONGLONG SessionId, ULONG QueueRecords, ULONG QueueBytes, ULONG PayloadMode)
{
    KIRQL oldIrql;
    if (SessionId == 0) return STATUS_INVALID_PARAMETER;
    if (QueueRecords == 0) QueueRecords = MSMON_DEFAULT_QUEUE_RECORDS;
    if (QueueBytes == 0) QueueBytes = MSMON_DEFAULT_QUEUE_BYTES;
    QueueRecords = min(QueueRecords, MSMON_MAX_QUEUE_RECORDS);
    QueueBytes = min(QueueBytes, MSMON_MAX_QUEUE_BYTES);
    QueueBytes = max(QueueBytes, MSMON_MAX_EVENT_RECORD_BYTES * 2u);

    KeAcquireSpinLock(&gQueue.Lock, &oldIrql);
    MsMonClearQueueLocked();
    gQueue.Sequence = 0;
    gQueue.OperationId = 0;
    gQueue.Dropped = 0;
    gQueue.SessionId = SessionId;
    gQueue.QueueRecordLimit = QueueRecords;
    gQueue.QueueByteLimit = QueueBytes;
    gQueue.PayloadEnabled = PayloadMode != 0;
    KeReleaseSpinLock(&gQueue.Lock, oldIrql);
    MsMonCoverageReset(SessionId);
    return STATUS_SUCCESS;
}

VOID MsMonEventsStop(VOID)
{
    KIRQL oldIrql;
    if (!gQueueInitialized) return;
    KeAcquireSpinLock(&gQueue.Lock, &oldIrql);
    gQueue.SessionId = 0;
    gQueue.PayloadEnabled = FALSE;
    MsMonClearQueueLocked();
    KeReleaseSpinLock(&gQueue.Lock, oldIrql);
    /* Release a reader that is waiting for events it will never receive. */
    KeSetEvent(&gQueue.DataAvailable, IO_NO_INCREMENT, FALSE);
}

VOID MsMonEventsWakeAll(VOID)
{
    if (!gQueueInitialized) return;
    KeSetEvent(&gQueue.DataAvailable, IO_NO_INCREMENT, FALSE);
}

VOID MsMonEventsUninitialize(VOID)
{
    MsMonEventsStop();
}

BOOLEAN MsMonPayloadEnabled(VOID)
{
    return gQueue.PayloadEnabled;
}

VOID MsMonEventsNoteDropped(VOID)
{
    KIRQL oldIrql;
    if (!gQueueInitialized) return;
    KeAcquireSpinLock(&gQueue.Lock, &oldIrql);
    if (gQueue.SessionId != 0) gQueue.Sequence++;
    InterlockedIncrement64(&gQueue.Dropped);
    KeReleaseSpinLock(&gQueue.Lock, oldIrql);
}

static VOID MsMonCoverageEventAttempt(ULONG Type)
{
    if (Type < MSMON_EVENT_SLOTS) {
        InterlockedIncrement64((volatile LONG64*)&gCoverage.EventAttempted[Type]);
    }
}

static VOID MsMonCoverageEventDrop(ULONG Type)
{
    if (Type < MSMON_EVENT_SLOTS) {
        InterlockedIncrement64((volatile LONG64*)&gCoverage.EventDropped[Type]);
    }
}

VOID MsMonCoverageReset(ULONGLONG SessionId)
{
    /*
     * Registration happens once at load, so RegistrationOk/Failed/Status are
     * deliberately kept: the coverage report is read after a session, and
     * clearing them here would report every registration as never attempted.
     */
    RtlZeroMemory(gCoverage.EventAttempted, sizeof(gCoverage.EventAttempted));
    RtlZeroMemory(gCoverage.EventDropped, sizeof(gCoverage.EventDropped));
    RtlZeroMemory(gCoverage.SensorEntered, sizeof(gCoverage.SensorEntered));
    RtlZeroMemory(gCoverage.SensorLogged, sizeof(gCoverage.SensorLogged));
    RtlZeroMemory(gCoverage.PayloadCaptured, sizeof(gCoverage.PayloadCaptured));
    gCoverage.SkipUntracked = 0;
    gCoverage.SkipIrql = 0;
    gCoverage.SkipNoName = 0;
    gCoverage.AllocFailures = 0;
    gCoverage.TrackFailures = 0;
    gCoverage.QueueDrops = 0;
    gCoverage.BlackCatMatches = 0;
    gCoverage.Version = MSMON_COVERAGE_VERSION;
    gCoverage.Size = sizeof(gCoverage);
    gCoverage.SessionId = SessionId;
}

VOID MsMonCoverageEnter(ULONG SensorId)
{
    if (SensorId < MSMON_SENSOR_SLOTS) {
        InterlockedIncrement64((volatile LONG64*)&gCoverage.SensorEntered[SensorId]);
    }
}

VOID MsMonCoverageLogged(ULONG SensorId)
{
    if (SensorId < MSMON_SENSOR_SLOTS) {
        InterlockedIncrement64((volatile LONG64*)&gCoverage.SensorLogged[SensorId]);
    }
}

VOID MsMonCoverageSkip(MSMON_SKIP_REASON Reason)
{
    switch (Reason) {
    case MSMON_SKIP_UNTRACKED: InterlockedIncrement64((volatile LONG64*)&gCoverage.SkipUntracked); break;
    case MSMON_SKIP_IRQL: InterlockedIncrement64((volatile LONG64*)&gCoverage.SkipIrql); break;
    case MSMON_SKIP_NO_NAME: InterlockedIncrement64((volatile LONG64*)&gCoverage.SkipNoName); break;
    case MSMON_SKIP_ALLOC: InterlockedIncrement64((volatile LONG64*)&gCoverage.AllocFailures); break;
    case MSMON_SKIP_TRACK: InterlockedIncrement64((volatile LONG64*)&gCoverage.TrackFailures); break;
    case MSMON_SKIP_QUEUE: InterlockedIncrement64((volatile LONG64*)&gCoverage.QueueDrops); break;
    default: break;
    }
}

VOID MsMonCoverageRegister(ULONG SensorId, NTSTATUS Status)
{
    if (SensorId >= MSMON_SENSOR_SLOTS) return;
    if (NT_SUCCESS(Status)) {
        InterlockedOr64((volatile LONG64*)&gCoverage.RegistrationOk, (LONG64)(1ull << SensorId));
        gCoverage.RegistrationStatus[SensorId] = 0;
    } else {
        InterlockedOr64((volatile LONG64*)&gCoverage.RegistrationFailed, (LONG64)(1ull << SensorId));
        gCoverage.RegistrationStatus[SensorId] = Status;
    }
}

VOID MsMonCoverageBlackCatMatch(VOID)
{
    InterlockedIncrement64((volatile LONG64*)&gCoverage.BlackCatMatches);
}

VOID MsMonGetCoverage(PMSMON_COVERAGE Coverage)
{
    if (Coverage == NULL) return;
    RtlCopyMemory(Coverage, &gCoverage, sizeof(gCoverage));
    Coverage->Version = MSMON_COVERAGE_VERSION;
    Coverage->Size = sizeof(gCoverage);
}

ULONGLONG MsMonNextOperationId(VOID)
{
    return (ULONGLONG)InterlockedIncrement64((volatile LONG64*)&gQueue.OperationId);
}

/* Exported by ntoskrnl; the WDK headers do not declare it. */
NTSYSAPI ULONG NTAPI RtlWalkFrameChain(_Out_writes_(Count) PVOID* Callers, _In_ ULONG Count, _In_ ULONG Flags);
#define MSMON_WALK_USER_MODE_STACK 1u

static BOOLEAN MsMonStackWanted(ULONG Type)
{
    switch (Type) {
    case MsMonProcessHandle:
    case MsMonThreadHandle:
    case MsMonFileCreate:
    case MsMonFileWrite:
    case MsMonFileSetInformation:
    case MsMonFileDirectoryControl:
    case MsMonFileDeviceControl:
    case MsMonFileSystemControl:
    case MsMonFileQueryVolumeInformation:
    case MsMonFileSetSecurity:
    case MsMonFileSetEa:
    case MsMonRegistryOpen:
    case MsMonRegistryCreate:
    case MsMonRegistrySetValue:
    case MsMonRegistryDelete:
    case MsMonRegistryRename:
    case MsMonRegistryQuery:
    case MsMonRegistryEnumerate:
        return TRUE;
    default:
        return FALSE;
    }
}

/*
 * Return addresses from the requesting thread's user-mode stack, so the agent
 * can name the module inside the process that made the request (for example
 * a DLL loaded into the client).  Walked only when it is both safe and
 * meaningful: at PASSIVE_LEVEL, since the walk reads user memory that may
 * page in; for a request that came from user mode; on a non-system thread
 * that is the thread and process the event is attributed to.  Per-I/O events
 * (reads, cleanup, close, section and information queries) are skipped to
 * keep the cost out of the client's start-up burst.
 */
static ULONG MsMonCaptureUserStack(ULONG Type, HANDLE ProcessId, HANDLE ThreadId, PVOID* Frames)
{
    if (!MsMonStackWanted(Type) || KeGetCurrentIrql() != PASSIVE_LEVEL || ExGetPreviousMode() != UserMode ||
        PsIsSystemThread(PsGetCurrentThread()) || ProcessId != PsGetCurrentProcessId() ||
        (ThreadId != NULL && ThreadId != PsGetCurrentThreadId())) {
        return 0;
    }
    return RtlWalkFrameChain(Frames, MSMON_MAX_STACK_FRAMES, MSMON_WALK_USER_MODE_STACK);
}

static NTSTATUS MsMonLogEventInternal(
    ULONG Type, HANDLE ProcessId, LONGLONG ProcessStartTime, HANDLE ParentProcessId, HANDLE ThreadId,
    HANDLE TargetProcessId, LONGLONG TargetProcessStartTime, ULONG Flags,
    NTSTATUS Status, ULONG DesiredAccess, ULONG Category,
    ULONGLONG Value0, ULONGLONG Value1, PCUNICODE_STRING Text,
    PCUNICODE_STRING Detail, ULONGLONG OperationId, const MSMON_PAYLOAD* Payload
)
{
    PMSMON_EVENT_BLOCK block;
    LARGE_INTEGER timestamp;
    KIRQL oldIrql;
    BOOLEAN truncated = FALSE;
    BOOLEAN blackCat = MsMonCurrentIsBlackCat();
    WCHAR componentName[64];
    UNICODE_STRING component = MsMonBlackCatComponent(blackCat, componentName, RTL_NUMBER_OF(componentName));
    PVOID frames[MSMON_MAX_STACK_FRAMES];
    ULONG frameCount = MsMonCaptureUserStack(Type, ProcessId, ThreadId, frames);
    USHORT textBytes = MsMonStringBytes(Text, &truncated);
    USHORT detailBytes = MsMonStringBytes(Detail, &truncated);
    USHORT componentBytes = blackCat ? MsMonStringBytes(&component, &truncated) : 0;
    ULONG textOffset = (sizeof(MSMON_EVENT_HEADER) + 7u) & ~7u;
    ULONG detailOffset = (textOffset + textBytes + (textBytes != 0 ? 2u : 0u) + 7u) & ~7u;
    ULONG componentOffset = (detailOffset + detailBytes + (detailBytes != 0 ? 2u : 0u) + 7u) & ~7u;
    ULONG stackOffset = (componentOffset + componentBytes + (componentBytes != 0 ? 2u : 0u) + 7u) & ~7u;
    ULONG payloadOffset = (stackOffset + frameCount * (ULONG)sizeof(ULONGLONG) + 7u) & ~7u;
    ULONG payloadBytes = Payload != NULL ? Payload->ByteCount : 0;
    ULONG recordBytes = payloadOffset + payloadBytes;
    ULONG allocationBytes;
    PWSTR destination;
    ULONG index;

    /* The stack never costs the event itself: drop the frames if they would not fit. */
    if (recordBytes > MSMON_MAX_EVENT_RECORD_BYTES && frameCount != 0) {
        frameCount = 0;
        payloadOffset = stackOffset;
        recordBytes = payloadOffset + payloadBytes;
    }
    allocationBytes = sizeof(LIST_ENTRY) + recordBytes;

    MsMonCoverageEventAttempt(Type);
    if (recordBytes > MSMON_MAX_EVENT_RECORD_BYTES ||
        (Payload != NULL && Payload->ByteCount != 0 && Payload->Data == NULL)) {
        MsMonCoverageEventDrop(Type);
        return STATUS_INVALID_PARAMETER;
    }
    if (!gQueueInitialized) {
        MsMonCoverageEventDrop(Type);
        return STATUS_DEVICE_NOT_READY;
    }
    block = ExAllocatePool2(POOL_FLAG_NON_PAGED, allocationBytes, MSMON_POOL_TAG);
    if (block == NULL) {
        MsMonCoverageEventDrop(Type);
        MsMonCoverageSkip(MSMON_SKIP_ALLOC);
        KeAcquireSpinLock(&gQueue.Lock, &oldIrql);
        if (gQueue.SessionId != 0) gQueue.Sequence++;
        InterlockedIncrement64(&gQueue.Dropped);
        KeReleaseSpinLock(&gQueue.Lock, oldIrql);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(block, allocationBytes);
    block->Event.Size = recordBytes;
    block->Event.Version = MSMON_PROTOCOL_VERSION;
    block->Event.Type = Type;
    block->Event.Flags = Flags | (truncated ? MsMonFlagTruncatedPath : 0);
    block->Event.ProcessId = HandleToULong(ProcessId);
    block->Event.ParentProcessId = HandleToULong(ParentProcessId);
    block->Event.ThreadId = HandleToULong(ThreadId);
    block->Event.TargetProcessId = HandleToULong(TargetProcessId);
    block->Event.ProcessStartTime = (ULONGLONG)ProcessStartTime;
    block->Event.TargetProcessStartTime = (ULONGLONG)TargetProcessStartTime;
    block->Event.Status = Status;
    block->Event.DesiredAccess = DesiredAccess;
    block->Event.Category = Category;
    block->Event.Attribution = blackCat ? MsMonAttributionStackResolved : MsMonAttributionProcessOnly;
    block->Event.Value0 = Value0;
    block->Event.Value1 = Value1;
    block->Event.OperationId = Payload != NULL ? Payload->OperationId : OperationId;
    KeQuerySystemTime(&timestamp);
    block->Event.Timestamp = (ULONGLONG)timestamp.QuadPart;

    if (textBytes != 0) {
        block->Event.TextOffset = (USHORT)textOffset;
        block->Event.TextBytes = textBytes;
        destination = (PWSTR)((PUCHAR)&block->Event + textOffset);
        RtlCopyMemory(destination, Text->Buffer, textBytes);
        destination[textBytes / sizeof(WCHAR)] = L'\0';
    }
    if (detailBytes != 0) {
        block->Event.DetailOffset = (USHORT)detailOffset;
        block->Event.DetailBytes = detailBytes;
        destination = (PWSTR)((PUCHAR)&block->Event + detailOffset);
        RtlCopyMemory(destination, Detail->Buffer, detailBytes);
        destination[detailBytes / sizeof(WCHAR)] = L'\0';
    }
    if (componentBytes != 0) {
        block->Event.ComponentOffset = (USHORT)componentOffset;
        block->Event.ComponentBytes = componentBytes;
        destination = (PWSTR)((PUCHAR)&block->Event + componentOffset);
        RtlCopyMemory(destination, component.Buffer, componentBytes);
        destination[componentBytes / sizeof(WCHAR)] = L'\0';
    }
    if (frameCount != 0) {
        PULONGLONG stack = (PULONGLONG)((PUCHAR)&block->Event + stackOffset);
        block->Event.StackOffset = (USHORT)stackOffset;
        block->Event.StackFrames = (USHORT)frameCount;
        for (index = 0; index < frameCount; index++) stack[index] = (ULONGLONG)(ULONG_PTR)frames[index];
    }
    if (Payload != NULL) {
        block->Event.Flags |= MsMonFlagPayloadPresent;
        if (Payload->ChunkIndex + 1 == Payload->ChunkCount) block->Event.Flags |= MsMonFlagPayloadFinalChunk;
        if (Payload->ByteOffset + Payload->ByteCount < Payload->TotalBytes) block->Event.Flags |= MsMonFlagPayloadPartial;
        block->Event.PayloadTotalBytes = Payload->TotalBytes;
        block->Event.PayloadByteOffset = Payload->ByteOffset;
        block->Event.PayloadChunkIndex = Payload->ChunkIndex;
        block->Event.PayloadChunkCount = Payload->ChunkCount;
        block->Event.PayloadKind = Payload->Kind;
        block->Event.PayloadBytes = payloadBytes;
        if (payloadBytes != 0) {
            block->Event.PayloadOffset = payloadOffset;
            RtlCopyMemory((PUCHAR)&block->Event + payloadOffset, Payload->Data, payloadBytes);
        }
    }

    KeAcquireSpinLock(&gQueue.Lock, &oldIrql);
    if (gQueue.SessionId == 0) {
        KeReleaseSpinLock(&gQueue.Lock, oldIrql);
        ExFreePoolWithTag(block, MSMON_POOL_TAG);
        MsMonCoverageEventDrop(Type);
        return STATUS_DEVICE_NOT_READY;
    }
    block->Event.SessionId = gQueue.SessionId;
    block->Event.Sequence = ++gQueue.Sequence;
    if ((ULONG)gQueue.Queued >= gQueue.QueueRecordLimit ||
        (ULONGLONG)gQueue.QueuedBytes + recordBytes > gQueue.QueueByteLimit) {
        InterlockedIncrement64(&gQueue.Dropped);
        KeReleaseSpinLock(&gQueue.Lock, oldIrql);
        ExFreePoolWithTag(block, MSMON_POOL_TAG);
        MsMonCoverageEventDrop(Type);
        MsMonCoverageSkip(MSMON_SKIP_QUEUE);
        return STATUS_QUOTA_EXCEEDED;
    }
    InsertTailList(&gQueue.Head, &block->Link);
    InterlockedIncrement(&gQueue.Queued);
    InterlockedAdd64(&gQueue.QueuedBytes, recordBytes);
    KeSetEvent(&gQueue.DataAvailable, IO_NO_INCREMENT, FALSE);
    KeReleaseSpinLock(&gQueue.Lock, oldIrql);
    if (Payload != NULL && Payload->Kind < RTL_NUMBER_OF(gCoverage.PayloadCaptured)) {
        InterlockedIncrement64((volatile LONG64*)&gCoverage.PayloadCaptured[Payload->Kind]);
    }
    return STATUS_SUCCESS;
}

NTSTATUS MsMonLogEventWithOperation(
    ULONG Type, HANDLE ProcessId, LONGLONG ProcessStartTime, HANDLE ThreadId, ULONG Flags, NTSTATUS Status,
    ULONG Category, ULONGLONG Value0, ULONGLONG Value1,
    PCUNICODE_STRING Text, PCUNICODE_STRING Detail, ULONGLONG OperationId
)
{
    return MsMonLogEventInternal(Type, ProcessId, ProcessStartTime, NULL, ThreadId, NULL, 0, Flags,
                                 Status, 0, Category, Value0, Value1, Text, Detail,
                                 OperationId, NULL);
}

NTSTATUS MsMonLogEvent(
    ULONG Type, HANDLE ProcessId, LONGLONG ProcessStartTime, HANDLE ParentProcessId, HANDLE ThreadId,
    HANDLE TargetProcessId, LONGLONG TargetProcessStartTime, ULONG Flags,
    NTSTATUS Status, ULONG DesiredAccess, ULONG Category,
    ULONGLONG Value0, ULONGLONG Value1, PCUNICODE_STRING Text, PCUNICODE_STRING Detail
)
{
    return MsMonLogEventInternal(Type, ProcessId, ProcessStartTime, ParentProcessId, ThreadId,
                                 TargetProcessId, TargetProcessStartTime, Flags,
                                 Status, DesiredAccess, Category, Value0, Value1,
                                 Text, Detail, 0, NULL);
}

NTSTATUS MsMonLogPayloadSeries(
    ULONG Type, HANDLE ProcessId, LONGLONG ProcessStartTime, HANDLE ThreadId, ULONG Flags, NTSTATUS Status,
    ULONG Category, ULONGLONG Value0, ULONGLONG Value1,
    PCUNICODE_STRING Text, PCUNICODE_STRING Detail,
    ULONG PayloadKind, ULONGLONG OperationId, ULONGLONG TotalBytes,
    const VOID* Payload, ULONG AvailableBytes
)
{
    ULONGLONG chunkCount;
    ULONGLONG offset = 0;
    if (OperationId == 0) OperationId = MsMonNextOperationId();
    if (AvailableBytes != 0 && Payload == NULL) return STATUS_INVALID_PARAMETER;
    if (AvailableBytes > TotalBytes) return STATUS_INVALID_BUFFER_SIZE;
    chunkCount = TotalBytes == 0 ? 1 : (TotalBytes + MSMON_PAYLOAD_CHUNK_BYTES - 1) / MSMON_PAYLOAD_CHUNK_BYTES;
    if (chunkCount > MSMON_MAX_PAYLOAD_CHUNKS) return STATUS_INVALID_BUFFER_SIZE;

    if (TotalBytes == 0) {
        MSMON_PAYLOAD empty = {OperationId, 0, 0, 0, 1, PayloadKind, NULL, 0};
        return MsMonLogEventInternal(Type, ProcessId, ProcessStartTime, NULL, ThreadId, NULL, 0,
                                     Flags, Status, 0, Category, Value0, Value1,
                                     Text, Detail, OperationId, &empty);
    }
    while (offset < AvailableBytes) {
        MSMON_PAYLOAD chunk;
        ULONG remaining = AvailableBytes - (ULONG)offset;
        ULONG bytes = min(remaining, MSMON_PAYLOAD_CHUNK_BYTES);
        chunk.OperationId = OperationId;
        chunk.TotalBytes = TotalBytes;
        chunk.ByteOffset = offset;
        chunk.ChunkIndex = (ULONG)(offset / MSMON_PAYLOAD_CHUNK_BYTES);
        chunk.ChunkCount = (ULONG)chunkCount;
        chunk.Kind = PayloadKind;
        chunk.Data = (const UCHAR*)Payload + offset;
        chunk.ByteCount = bytes;
        NTSTATUS status = MsMonLogEventInternal(Type, ProcessId, ProcessStartTime, NULL, ThreadId, NULL, 0,
                                                Flags | (AvailableBytes < TotalBytes ? MsMonFlagPayloadPartial : 0),
                                                Status, 0, Category, Value0, Value1,
                                                Text, Detail, OperationId, &chunk);
        if (!NT_SUCCESS(status)) return status;
        offset += bytes;
    }
    return STATUS_SUCCESS;
}

NTSTATUS MsMonReadEvents(PVOID Output, ULONG MaximumBytes, ULONG TimeoutMilliseconds, PULONG BytesRead)
{
    ULONG count = 0;
    LARGE_INTEGER timeout;
    KIRQL oldIrql;
    *BytesRead = 0;
    if (Output == NULL || MaximumBytes < MSMON_MAX_EVENT_RECORD_BYTES) return STATUS_INVALID_PARAMETER;
    KeAcquireSpinLock(&gQueue.Lock, &oldIrql);
    if (IsListEmpty(&gQueue.Head)) KeResetEvent(&gQueue.DataAvailable);
    KeReleaseSpinLock(&gQueue.Lock, oldIrql);
    timeout.QuadPart = -((LONGLONG)TimeoutMilliseconds * 10000LL);
    if (TimeoutMilliseconds != 0) {
        (VOID)KeWaitForSingleObject(&gQueue.DataAvailable, Executive, KernelMode, FALSE, &timeout);
    }
    KeAcquireSpinLock(&gQueue.Lock, &oldIrql);
    while (!IsListEmpty(&gQueue.Head)) {
        PLIST_ENTRY entry = gQueue.Head.Flink;
        PMSMON_EVENT_BLOCK block = CONTAINING_RECORD(entry, MSMON_EVENT_BLOCK, Link);
        ULONG recordBytes = block->Event.Size;
        if (recordBytes > MaximumBytes - count) break;
        RemoveEntryList(entry);
        RtlCopyMemory((PUCHAR)Output + count, &block->Event, recordBytes);
        ExFreePoolWithTag(block, MSMON_POOL_TAG);
        InterlockedDecrement(&gQueue.Queued);
        InterlockedAdd64(&gQueue.QueuedBytes, -(LONG64)recordBytes);
        count += recordBytes;
    }
    if (IsListEmpty(&gQueue.Head)) KeResetEvent(&gQueue.DataAvailable);
    KeReleaseSpinLock(&gQueue.Lock, oldIrql);
    *BytesRead = count;
    return STATUS_SUCCESS;
}

VOID MsMonGetStatistics(PMSMON_STATISTICS Statistics)
{
    KIRQL oldIrql;
    RtlZeroMemory(Statistics, sizeof(*Statistics));
    KeAcquireSpinLock(&gQueue.Lock, &oldIrql);
    Statistics->SessionId = gQueue.SessionId;
    Statistics->QueuedEvents = (ULONGLONG)gQueue.Queued;
    Statistics->QueuedBytes = (ULONGLONG)gQueue.QueuedBytes;
    Statistics->DroppedEvents = (ULONGLONG)gQueue.Dropped;
    Statistics->QueueRecordLimit = gQueue.QueueRecordLimit;
    Statistics->QueueByteLimit = gQueue.QueueByteLimit;
    KeReleaseSpinLock(&gQueue.Lock, oldIrql);
    Statistics->TrackedProcesses = MsMonTrackedProcessCount();
}
