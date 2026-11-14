#include "kf.h"

/*
 * Fixed ring of recent decisions for protected processes: allows, denials and audits.
 *
 * A client can repeat one refused request hundreds of times a second, which would
 * overrun the ring and drop everything else. An event identical to one logged less
 * than a second ago (same process, target, action, flags, value, rule and path) is
 * counted instead of stored; the count is written as one REPEAT summary (Generation =
 * how many were collapsed) when the key next appears after its window, or when the
 * ring is read.
 */

#define KF_REPEAT_SLOTS 128u
#define KF_REPEAT_WINDOW 10000000LL   /* 1 s in 100 ns units */

typedef struct _KF_REPEAT_SLOT {
    KFILTER_EVENT Event;    /* the last event stored for this key */
    LONGLONG WindowStart;
    LONGLONG Last;
    ULONG Suppressed;
    BOOLEAN Used;
} KF_REPEAT_SLOT;

typedef struct _KF_EVENT_RING {
    KSPIN_LOCK Lock;
    PKFILTER_EVENT Buffer;
    KF_REPEAT_SLOT* Repeat;
    ULONG Count;
    ULONG Next;
    ULONG Dropped;
} KF_EVENT_RING;

static KF_EVENT_RING gRing;
static BOOLEAN gRingInitialized;

NTSTATUS KfEventsInitialize(VOID)
{
    KeInitializeSpinLock(&gRing.Lock);
    gRing.Buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                   (SIZE_T)KFILTER_RING_CAPACITY * sizeof(KFILTER_EVENT),
                                   KFILTER_POOL_TAG);
    if (gRing.Buffer == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    gRing.Repeat = ExAllocatePool2(POOL_FLAG_NON_PAGED, (SIZE_T)KF_REPEAT_SLOTS * sizeof(KF_REPEAT_SLOT),
                                   KFILTER_POOL_TAG);
    if (gRing.Repeat == NULL) {
        ExFreePoolWithTag(gRing.Buffer, KFILTER_POOL_TAG);
        gRing.Buffer = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(gRing.Buffer, (SIZE_T)KFILTER_RING_CAPACITY * sizeof(KFILTER_EVENT));
    RtlZeroMemory(gRing.Repeat, (SIZE_T)KF_REPEAT_SLOTS * sizeof(KF_REPEAT_SLOT));
    gRing.Count = 0;
    gRing.Next = 0;
    gRing.Dropped = 0;
    gRingInitialized = TRUE;
    return STATUS_SUCCESS;
}

VOID KfEventsUninitialize(VOID)
{
    PKFILTER_EVENT buffer;
    KF_REPEAT_SLOT* repeat;
    KIRQL oldIrql;

    KeAcquireSpinLock(&gRing.Lock, &oldIrql);
    buffer = gRing.Buffer;
    repeat = gRing.Repeat;
    gRing.Buffer = NULL;
    gRing.Repeat = NULL;
    gRing.Count = 0;
    gRing.Next = 0;
    gRingInitialized = FALSE;
    KeReleaseSpinLock(&gRing.Lock, oldIrql);
    if (buffer != NULL) ExFreePoolWithTag(buffer, KFILTER_POOL_TAG);
    if (repeat != NULL) ExFreePoolWithTag(repeat, KFILTER_POOL_TAG);
}

/* Append one event to the ring; the lock is held. */
static VOID KfRingPushLocked(const KFILTER_EVENT* Event)
{
    gRing.Buffer[gRing.Next] = *Event;
    gRing.Next = (gRing.Next + 1) % KFILTER_RING_CAPACITY;
    if (gRing.Count < KFILTER_RING_CAPACITY) {
        gRing.Count++;
    } else {
        gRing.Dropped++;
    }
}

/* Write a slot's collapsed count as a REPEAT summary; the lock is held. */
static VOID KfRepeatFlushLocked(KF_REPEAT_SLOT* Slot)
{
    PKFILTER_EVENT summary;

    if (!Slot->Used || Slot->Suppressed == 0) return;
    summary = &gRing.Buffer[gRing.Next];   /* written in place: no second copy on the stack */
    KfRingPushLocked(&Slot->Event);
    summary->Flags |= KFILTER_EVENT_FLAG_REPEAT;
    summary->Generation = Slot->Suppressed;
    summary->Timestamp = (ULONG64)Slot->Last;
    Slot->Suppressed = 0;
}

static BOOLEAN KfSameEvent(const KFILTER_EVENT* Left, const KFILTER_EVENT* Right)
{
    SIZE_T length;

    if (Left->ProcessId != Right->ProcessId || Left->Target != Right->Target ||
        Left->Action != Right->Action || Left->Flags != Right->Flags ||
        Left->Value != Right->Value || Left->RuleId != Right->RuleId || Left->Status != Right->Status) {
        return FALSE;
    }
    for (length = 0; length < KFILTER_MAX_NAME && Left->Path[length] != L'\0'; length++);
    return RtlCompareMemory(Left->Path, Right->Path, (length + 1) * sizeof(WCHAR)) == (length + 1) * sizeof(WCHAR);
}

static ULONG KfEventHash(const KFILTER_EVENT* Event)
{
    ULONG hash = 2166136261u;
    ULONG index;
    ULONG fields[7];

    fields[0] = Event->ProcessId; fields[1] = Event->Target; fields[2] = Event->Action;
    fields[3] = Event->Flags; fields[4] = Event->Value; fields[5] = Event->RuleId;
    fields[6] = (ULONG)Event->Status;
    for (index = 0; index < 7; index++) hash = (hash ^ fields[index]) * 16777619u;
    for (index = 0; index < KFILTER_MAX_NAME && Event->Path[index] != L'\0'; index++) {
        hash = (hash ^ Event->Path[index]) * 16777619u;
    }
    return hash;
}

/* The file name of Image (or of ProcessId's image when Image is NULL) into Output. */
static VOID KfEventImage(HANDLE ProcessId, PCWSTR Image, PWCHAR Output)
{
    WCHAR buffer[KFILTER_MAX_NAME];
    ULONG length = 0;
    ULONG start = 0;
    ULONG index;

    Output[0] = L'\0';
    if (Image == NULL) {
        length = KfProcessImageOf(ProcessId, buffer, KFILTER_MAX_NAME);
        Image = buffer;
    } else {
        while (length < KFILTER_MAX_NAME - 1 && Image[length] != L'\0') length++;
    }
    for (index = 0; index < length; index++) {
        if (Image[index] == L'\\' || Image[index] == L'/') start = index + 1;
    }
    for (index = 0; start + index < length && index < KFILTER_MAX_IMAGE - 1; index++) {
        Output[index] = Image[start + index];
    }
    Output[index] = L'\0';
}

static VOID KfLogEventImage(HANDLE ProcessId, ULONG Target, ULONG Action, ULONG Flags, NTSTATUS Status,
                            ULONG Value, ULONG RuleId, PCUNICODE_STRING Path, PCWSTR Image)
{
    KFILTER_EVENT event;
    KF_REPEAT_SLOT* slot;
    LARGE_INTEGER timestamp;
    KIRQL oldIrql;
    USHORT characters = 0;

    if (!gRingInitialized) return;
    if (Path != NULL && Path->Buffer != NULL) {
        USHORT length = Path->Length / sizeof(WCHAR);
        characters = length < (KFILTER_MAX_NAME - 1) ? length : (KFILTER_MAX_NAME - 1);
    }

    KeQuerySystemTime(&timestamp);
    RtlZeroMemory(&event, sizeof(event));
    event.Timestamp = (ULONG64)timestamp.QuadPart;
    event.ProcessId = HandleToULong(ProcessId);
    event.Target = Target;
    event.Action = Action;
    event.Flags = Flags;
    event.Status = Status;
    event.Value = Value;
    event.RuleId = RuleId;
    event.Generation = KfPolicyGeneration();
    if (characters != 0) {
        RtlCopyMemory(event.Path, Path->Buffer, (SIZE_T)characters * sizeof(WCHAR));
        event.Path[characters] = L'\0';
    }
    KfEventImage(ProcessId, Image, event.Image);

    KeAcquireSpinLock(&gRing.Lock, &oldIrql);
    if (gRing.Buffer == NULL || gRing.Repeat == NULL) {
        KeReleaseSpinLock(&gRing.Lock, oldIrql);
        return;
    }
    slot = &gRing.Repeat[KfEventHash(&event) % KF_REPEAT_SLOTS];
    if (slot->Used && timestamp.QuadPart - slot->WindowStart < KF_REPEAT_WINDOW && KfSameEvent(&slot->Event, &event)) {
        slot->Suppressed++;
        slot->Last = timestamp.QuadPart;
        KeReleaseSpinLock(&gRing.Lock, oldIrql);
        return;
    }
    KfRepeatFlushLocked(slot);
    KfRingPushLocked(&event);
    slot->Event = event;
    slot->WindowStart = timestamp.QuadPart;
    slot->Last = timestamp.QuadPart;
    slot->Suppressed = 0;
    slot->Used = TRUE;
    KeReleaseSpinLock(&gRing.Lock, oldIrql);
}

VOID KfLogEventFor(HANDLE ProcessId, ULONG Target, ULONG Action, ULONG Flags, NTSTATUS Status,
                   ULONG Value, ULONG RuleId, PCUNICODE_STRING Path)
{
    KfLogEventImage(ProcessId, Target, Action, Flags, Status, Value, RuleId, Path, NULL);
}

VOID KfLogEvent(ULONG Target, ULONG Action, ULONG Flags, NTSTATUS Status, ULONG Value,
                ULONG RuleId, PCUNICODE_STRING Path)
{
    KfLogEventFor(PsGetCurrentProcessId(), Target, Action, Flags, Status, Value, RuleId, Path);
}

ULONG KfReadEvents(PKFILTER_EVENT Output, ULONG MaximumEvents)
{
    ULONG count = 0;
    ULONG index;
    LARGE_INTEGER now;
    KIRQL oldIrql;

    if (!gRingInitialized || Output == NULL || MaximumEvents == 0) return 0;

    KeQuerySystemTime(&now);
    KeAcquireSpinLock(&gRing.Lock, &oldIrql);
    /* Counts whose window has closed are written now, so a reader is never more than a
     * second behind a repeated event. */
    for (index = 0; gRing.Repeat != NULL && index < KF_REPEAT_SLOTS; index++) {
        if (now.QuadPart - gRing.Repeat[index].WindowStart >= KF_REPEAT_WINDOW) {
            KfRepeatFlushLocked(&gRing.Repeat[index]);
        }
    }
    while (count < MaximumEvents && gRing.Count > 0) {
        ULONG tail = (gRing.Next + KFILTER_RING_CAPACITY - gRing.Count) % KFILTER_RING_CAPACITY;
        Output[count] = gRing.Buffer[tail];
        gRing.Count--;
        count++;
    }
    KeReleaseSpinLock(&gRing.Lock, oldIrql);
    return count;
}

VOID KfClearEvents(VOID)
{
    KIRQL oldIrql;

    if (!gRingInitialized) return;
    KeAcquireSpinLock(&gRing.Lock, &oldIrql);
    gRing.Count = 0;
    gRing.Next = 0;
    gRing.Dropped = 0;
    if (gRing.Repeat != NULL) RtlZeroMemory(gRing.Repeat, (SIZE_T)KF_REPEAT_SLOTS * sizeof(KF_REPEAT_SLOT));
    KeReleaseSpinLock(&gRing.Lock, oldIrql);
}

VOID KfLogBpfDecision(HANDLE ProcessId, ULONG Target, ULONG Action, ULONG Flags, NTSTATUS Status,
                      ULONG Value, ULONG RuleId, PCUNICODE_STRING Path, PCWSTR Image)
{
    KfCountDecision(Action, Flags);
    KfLogEventImage(ProcessId, Target, Action, Flags, Status, Value, RuleId, Path,
                    Image != NULL && Image[0] != L'\0' ? Image : NULL);
}

ULONG KfDroppedEventCount(VOID)
{
    ULONG dropped;
    KIRQL oldIrql;

    if (!gRingInitialized) return 0;
    KeAcquireSpinLock(&gRing.Lock, &oldIrql);
    dropped = gRing.Dropped;
    KeReleaseSpinLock(&gRing.Lock, oldIrql);
    return dropped;
}
