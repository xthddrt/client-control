#include "kf.h"

/*
 * Policy storage, immutable generations and the decision path.
 *
 * A config is allocated once, validated, then published. Readers take a
 * reference under the spin lock and release it after matching; the old
 * generation is freed only when its last reader releases. The matching code is
 * in match.c so the control tool can run exactly the same algorithm.
 *
 * A generation also holds the per-Play state of its counted rules (uses taken, the
 * highest open phase) and the rule index that keeps a lookup short with thousands
 * of rules.
 */

/* Candidate rules for one request; more than this and every rule is checked. */
#define KF_MAX_CANDIDATES 64u

typedef struct _KF_CONFIG_REF {
    volatile LONG RefCount;
    volatile LONG Phase;      /* the highest open phase */
    volatile LONG* Used;      /* uses taken: one per rule, then one per network rule */
    ULONG* IndexMemory;       /* Index.Keys, Index.KeyRules and Index.Globs */
    KF_RULE_INDEX Index;
    KFILTER_CONFIG Config;    /* last: only RuleCount rules are allocated */
} KF_CONFIG_REF, *PKF_CONFIG_REF;

static PKF_CONFIG_REF gConfig;
static KSPIN_LOCK gConfigLock;
static volatile LONG gAllowed;
static volatile LONG gDenied;
static volatile LONG gAudited;
static volatile LONG gWouldDeny;
static volatile LONG gNameFailures;
static volatile LONG gMissingContexts;
static volatile LONG gSidFailures;
static volatile ULONG gGeneration;

static ULONG KfLength(PCWSTR Value)
{
    ULONG length = 0;
    if (Value == NULL) return 0;
    while (length < KFILTER_MAX_NAME && Value[length] != L'\0') length++;
    return length;
}

static VOID KfConfigRelease(PKF_CONFIG_REF Config)
{
    if (Config == NULL) return;
    if (InterlockedDecrement(&Config->RefCount) == 0) {
        if (Config->Used != NULL) ExFreePoolWithTag((PVOID)Config->Used, KFILTER_POOL_TAG);
        if (Config->IndexMemory != NULL) ExFreePoolWithTag(Config->IndexMemory, KFILTER_POOL_TAG);
        ExFreePoolWithTag(Config, KFILTER_POOL_TAG);
    }
}

static PKF_CONFIG_REF KfConfigAcquire(VOID)
{
    PKF_CONFIG_REF config;
    KIRQL oldIrql;

    KeAcquireSpinLock(&gConfigLock, &oldIrql);
    config = gConfig;
    if (config != NULL) InterlockedIncrement(&config->RefCount);
    KeReleaseSpinLock(&gConfigLock, oldIrql);
    return config;
}

static BOOLEAN KfRootMatches(PCWSTR Root, PCUNICODE_STRING ImagePath)
{
    ULONG rootLength;
    ULONG imageLength;

    if (Root == NULL || ImagePath == NULL || ImagePath->Buffer == NULL) return FALSE;
    rootLength = KfLength(Root);
    if (rootLength == 0) return FALSE;
    imageLength = ImagePath->Length / sizeof(WCHAR);
    if (imageLength < rootLength) return FALSE;
    if (!KfMatchGlob(Root, rootLength, ImagePath->Buffer, rootLength)) return FALSE;
    return imageLength == rootLength || ImagePath->Buffer[rootLength] == L'\\' ||
           ImagePath->Buffer[rootLength] == L'/';
}

NTSTATUS KfPolicyInitialize(VOID)
{
    KeInitializeSpinLock(&gConfigLock);
    gConfig = NULL;
    gAllowed = 0;
    gDenied = 0;
    gAudited = 0;
    gWouldDeny = 0;
    gNameFailures = 0;
    gMissingContexts = 0;
    gSidFailures = 0;
    gGeneration = 0;
    return STATUS_SUCCESS;
}

/* Restore every counted rule of the live generation and close every phase but the first. */
VOID KfPolicyResetCounts(VOID)
{
    PKF_CONFIG_REF config = KfConfigAcquire();
    ULONG index;

    if (config == NULL) return;
    for (index = 0; index < config->Config.RuleCount + config->Config.NetworkRuleCount; index++) {
        InterlockedExchange(&config->Used[index], 0);
    }
    InterlockedExchange(&config->Phase, 1);
    KfConfigRelease(config);
}

/*
 * Whether a rule with this Count field may allow one more request, taking the use if so.
 * Slot is its entry in Used. A standing rule (Count 0) always may; a counted rule while
 * its phase is open and it has uses left. Using an OPENS rule opens the next phase. A Peek
 * (a metadata query) takes no use: the stat before each open must not spend the open's.
 */
static BOOLEAN KfCountTake(PKF_CONFIG_REF Config, ULONG Count, ULONG Slot, BOOLEAN Peek)
{
    ULONG uses = (Count & KFILTER_COUNT_USES) >> KFILTER_COUNT_USES_SHIFT;
    ULONG phase = Count & KFILTER_COUNT_PHASE;
    LONG taken;
    LONG open;

    if (Count == 0) return TRUE;
    if ((ULONG)Config->Phase < phase) return FALSE;
    if (Peek) return (ULONG)Config->Used[Slot] < uses;
    do {
        taken = Config->Used[Slot];
        if ((ULONG)taken >= uses) return FALSE;
    } while (InterlockedCompareExchange(&Config->Used[Slot], taken + 1, taken) != taken);
    if ((Count & KFILTER_COUNT_OPENS) != 0) {
        do {
            open = Config->Phase;
            if ((ULONG)open > phase) break;
        } while (InterlockedCompareExchange(&Config->Phase, (LONG)(phase + 1), open) != open);
    }
    return TRUE;
}

/* The rules to try for Path, in rule order: Candidates[0..count), or every rule when
 * *All is set (the index returned too many). */
static ULONG KfCandidates(PKF_CONFIG_REF Config, PCWSTR Path, ULONG PathLength,
                          ULONG* Candidates, BOOLEAN* All)
{
    ULONG count = KfIndexCandidates(&Config->Index, Path, PathLength, Candidates, KF_MAX_CANDIDATES);
    *All = count > KF_MAX_CANDIDATES;
    return *All ? Config->Config.RuleCount : count;
}

VOID KfPolicyUninitialize(VOID)
{
    PKF_CONFIG_REF old;
    KIRQL oldIrql;

    KeAcquireSpinLock(&gConfigLock, &oldIrql);
    old = gConfig;
    gConfig = NULL;
    KeReleaseSpinLock(&gConfigLock, oldIrql);
    KfConfigRelease(old);
}

/* A Count field is valid when it is 0, or names a phase and at least one use. On a deny or
 * audit rule it limits how many requests the rule decides before it steps aside. */
static BOOLEAN KfCountValid(ULONG Count, ULONG Action)
{
    if (Count == 0) return TRUE;
    return (Action == KFilterActionAllow || Action == KFilterActionDeny || Action == KFilterActionAudit) &&
           (Count & KFILTER_COUNT_PHASE) != 0 && (Count & KFILTER_COUNT_USES) != 0;
}

/* The requesting program's image, loaded on first use: most policies name no image. */
typedef struct _KF_IMAGE_REF {
    HANDLE ProcessId;
    BOOLEAN Loaded;
    ULONG Length;
    WCHAR Buffer[KFILTER_MAX_NAME];
} KF_IMAGE_REF;

static BOOLEAN KfImageRuleMatches(KF_IMAGE_REF* Image, const wchar_t* Pattern)
{
    if (Pattern[0] == L'\0') return TRUE;
    if (!Image->Loaded) {
        Image->Length = KfProcessImageOf(Image->ProcessId, Image->Buffer, KFILTER_MAX_NAME);
        Image->Loaded = TRUE;
    }
    return KfImageMatches(Pattern, Image->Buffer, Image->Length) != 0;
}

/* addr= (KFILTER_RULE_ADDRESS): peer, thread-peer and system rules only, not with module=, 1 to 16 ranges from low
 * to high, each absolute or relative to one of Value's comma-separated module file name patterns; no ranges
 * otherwise. */
static BOOLEAN KfAddressValid(const KFILTER_RULE* Rule, ULONG ValueLength)
{
    ULONG index, modules = 0, start = 0;
    if ((Rule->Flags & KFILTER_RULE_ADDRESS) == 0) return Rule->AddressCount == 0;
    if ((Rule->Flags & KFILTER_RULE_MODULE) != 0 || Rule->AddressCount == 0 || Rule->AddressCount > KFILTER_MAX_ADDRESS ||
        (Rule->Targets != KFILTER_TARGET_PEER && Rule->Targets != KFILTER_TARGET_THREAD_PEER &&
         Rule->Targets != KFILTER_TARGET_SYSTEM)) {
        return FALSE;
    }
    for (index = 0; ValueLength != 0 && index <= ValueLength; index++) {
        if (index < ValueLength && (Rule->Value[index] == L'\\' || Rule->Value[index] == L'/')) return FALSE;
        if (index < ValueLength && Rule->Value[index] != L',') continue;
        if (index == start) return FALSE;   /* an empty pattern */
        modules++;
        start = index + 1;
    }
    for (index = 0; index < Rule->AddressCount; index++) {
        if (Rule->Address[index].Low > Rule->Address[index].High || Rule->AddressModule[index] > modules) return FALSE;
    }
    return TRUE;
}

static NTSTATUS KfValidateConfig(const KFILTER_CONFIG* Config, ULONG Length)
{
    ULONG index;
    ULONG allowedTargets = KFILTER_TARGET_FILE | KFILTER_TARGET_DIR |
                           KFILTER_TARGET_REGISTRY | KFILTER_TARGET_PROCESS |
                           KFILTER_TARGET_VOLUME | KFILTER_TARGET_DEVICE |
                           KFILTER_TARGET_PIPE | KFILTER_TARGET_NETWORK |
                           KFILTER_TARGETS_OUTSIDE | KFILTER_TARGETS_RULE_ONLY;
    /* Rules that name a program (a C:\ path allowed) and rules whose rights are access masks. */
    const ULONG programTargets = KFILTER_TARGETS_OUTSIDE | KFILTER_TARGET_PEER | KFILTER_TARGET_THREAD_PEER |
                                 KFILTER_TARGET_THREAD;
    const ULONG accessTargets = KFILTER_TARGETS_OUTSIDE | KFILTER_TARGET_PEER | KFILTER_TARGET_THREAD_PEER;

    if (Config == NULL || Length < KFILTER_CONFIG_SIZE(0)) return STATUS_INVALID_PARAMETER;
    if (Config->AbiVersion != KFILTER_ABI_VERSION) return STATUS_REVISION_MISMATCH;
    if (Config->RuleCount > KFILTER_MAX_RULES || Length < KFILTER_CONFIG_SIZE(Config->RuleCount)) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Config->Mode > KFILTER_MODE_BLOCK) return STATUS_INVALID_PARAMETER;
    if (Config->RuleCount > KFILTER_MAX_RULES ||
        Config->ProtectedCount > KFILTER_MAX_PROTECTED ||
        Config->NetworkRuleCount > KFILTER_MAX_NET_RULES) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Config->PackageSidLength > KFILTER_MAX_SID ||
        (Config->PackageSidLength != 0 &&
         (!RtlValidSid((PSID)Config->PackageSid) ||
          RtlLengthSid((PSID)Config->PackageSid) != Config->PackageSidLength))) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Config->Mode == KFILTER_MODE_BLOCK) {
        ULONG required = KFILTER_REG_DEVICE;
        if ((Config->Flags & (KFILTER_CFG_BLOCK_FILES | KFILTER_CFG_BLOCK_VOLUME_SERIAL)) != 0)
            required |= KFILTER_REG_MINIFILTER;
        if ((Config->Flags & KFILTER_CFG_BLOCK_REGISTRY) != 0) required |= KFILTER_REG_REGISTRY;
        if ((Config->Flags & (KFILTER_CFG_BLOCK_PROCESS_MEMORY | KFILTER_CFG_BLOCK_PROCESS_SIGNALS |
                              KFILTER_CFG_BLOCK_PROCESS_QUERIES)) != 0) required |= KFILTER_REG_OBJECT;
        if ((Config->Flags & KFILTER_CFG_BLOCK_PROCESS_CREATE) != 0) required |= KFILTER_REG_PROCESS;
        if ((Config->Flags & KFILTER_CFG_BLOCK_RAW_DISK) != 0) required |= KFILTER_REG_DISK;
        if ((Config->Flags & KFILTER_CFG_BLOCK_NETWORK) != 0) required |= KFILTER_REG_NETWORK;
#ifndef _WIN32
        /* Linux: only the BPF layer decides these (registry from Wine's requests, adapters
         * through netlink); without it block mode is refused rather than claimed. */
        if ((Config->Flags & KFILTER_CFG_BLOCK_VOLUME_SERIAL) != 0) required |= KFILTER_REG_BPF;
        if ((Config->Flags & KFILTER_CFG_BLOCK_NETWORK_ADAPTER) != 0) required |= KFILTER_REG_NSI;
#endif
        if ((KfDriverRegisteredMask() & required) != required) return STATUS_DEVICE_NOT_READY;
        /* Block mode never claims rules no layer enforces; audit mode loads them. */
        if (KfPolicyUnenforced(Config, KfDriverRegisteredMask(), &index) != 0) return STATUS_NOT_SUPPORTED;
    }
    if (Config->Root[0] != L'\0') {
        ULONG rootLength = KfLength(Config->Root);
        ULONG rootIndex;
        if (rootLength < 2 || rootLength >= KFILTER_MAX_NAME ||
            (Config->Root[0] != L'\\' && Config->Root[0] != L'/')) return STATUS_INVALID_PARAMETER;
        for (rootIndex = 0; rootIndex < rootLength; rootIndex++) {
            if (Config->Root[rootIndex] == L'*') return STATUS_INVALID_PARAMETER;
        }
    }
    for (index = 0; index < Config->ProtectedCount; index++) {
        ULONG length = KfLength(Config->Protected[index]);
        if (length == 0 || length >= KFILTER_MAX_NAME) return STATUS_INVALID_PARAMETER;
    }
    for (index = 0; index < Config->RuleCount; index++) {
        const KFILTER_RULE* rule = &Config->Rules[index];
        ULONG length = KfLength(rule->Path);
        ULONG valueLength = KfLengthBounded(rule->Value, KFILTER_MAX_VALUE);
        if (rule->Action != KFilterActionAllow && rule->Action != KFilterActionDeny &&
            rule->Action != KFilterActionAudit) return STATUS_INVALID_PARAMETER;
        if (rule->Targets == 0 || (rule->Targets & ~allowedTargets) != 0) return STATUS_INVALID_PARAMETER;
        /* Outside-process rules carry raw access masks and are not mixed with other targets;
         * a rule-only target is its rule's only one. */
        if ((rule->Targets & KFILTER_TARGETS_OUTSIDE) != 0) {
            if ((rule->Targets & ~KFILTER_TARGETS_OUTSIDE) != 0) return STATUS_INVALID_PARAMETER;
        } else if ((rule->Targets & KFILTER_TARGETS_RULE_ONLY) != 0 && (rule->Targets & (rule->Targets - 1)) != 0) {
            return STATUS_INVALID_PARAMETER;
        } else if ((rule->Targets & accessTargets) == 0 &&
                   (rule->Rights & ~(KFILTER_RIGHTS_ALL | ((rule->Targets & ~(KFILTER_TARGET_FILE | KFILTER_TARGET_DIR)) == 0
                                                               ? KFILTER_RIGHTS_FILE_NAMED : 0))) != 0) {
            return STATUS_INVALID_PARAMETER;   /* lock, chdir and touch: file and dir rules only */
        }
        if (rule->Action == KFilterActionAllow && rule->Rights == 0) return STATUS_INVALID_PARAMETER;
        if (rule->Account > KFILTER_ACCOUNT_SYSTEM) return STATUS_INVALID_PARAMETER;
        if (!KfCountValid(rule->Count, rule->Action)) return STATUS_INVALID_PARAMETER;
        if ((rule->Flags & ~(KFILTER_RULE_EXACT | KFILTER_RULE_HIDE | KFILTER_RULE_MODULE | KFILTER_RULE_ADDRESS |
                             KFILTER_RULE_PSEUDO)) != 0 ||
            ((rule->Flags & KFILTER_RULE_PSEUDO) != 0 && rule->Targets != KFILTER_TARGET_PEER) ||
            ((rule->Flags & KFILTER_RULE_MODULE) != 0 &&
             (valueLength == 0 || (rule->Targets & (KFILTER_TARGET_REGISTRY | KFILTER_TARGET_DEVICE)) != 0)) ||
            !KfAddressValid(rule, valueLength)) {
            return STATUS_INVALID_PARAMETER;
        }
        if ((rule->Extensions & ~(KFILTER_EXT_EXE | KFILTER_EXT_DLL | KFILTER_EXT_SYS |
                                  KFILTER_EXT_OCX | KFILTER_EXT_OTHER)) != 0) {
            return STATUS_INVALID_PARAMETER;
        }
        /* A DNS rule names a host (no separator); a program rule may name a C:\ path. */
        if (length < 1 || length >= KFILTER_MAX_NAME || (length < 2 && rule->Targets != KFILTER_TARGET_DNS) ||
            (rule->Path[0] != L'\\' && rule->Path[0] != L'/' && rule->Targets != KFILTER_TARGET_DNS &&
             !((rule->Targets & programTargets) != 0 && length >= 3 && rule->Path[1] == L':' &&
               rule->Path[2] == L'\\')) ||
            KfPathEndsWithSeparator(rule->Path, length)) {
            return STATUS_INVALID_PARAMETER;
        }
        if (valueLength >= KFILTER_MAX_VALUE ||
            KfLengthBounded(rule->Risk, KFILTER_MAX_RISK) >= KFILTER_MAX_RISK ||
            KfLengthBounded(rule->Image, KFILTER_MAX_IMAGE) >= KFILTER_MAX_IMAGE) {
            return STATUS_INVALID_PARAMETER;
        }
        if ((rule->Targets & KFILTER_TARGET_DEVICE) != 0 && rule->Action == KFilterActionAllow) {
            ULONG character;
            if ((rule->Flags & KFILTER_RULE_EXACT) == 0 ||
                rule->Rights != KFILTER_RIGHT_RAW_DEVICE ||
                ((rule->Count & KFILTER_COUNT_USES) == 0 && KfDeviceDefaultDecided(rule->Path, length)) ||
                rule->Risk[0] == L'\0') {
                return STATUS_INVALID_PARAMETER;
            }
            for (character = 0; character < length; character++) {
                if (rule->Path[character] == L'*') return STATUS_INVALID_PARAMETER;
            }
            if (valueLength != 0) {
                /* 0x%08X, or (an ioctl's argument, Linux) 0x%08X:0x%08X */
                if ((valueLength != 10 && valueLength != 21) || rule->Value[0] != L'0' || rule->Value[1] != L'x' ||
                    (valueLength == 21 && (rule->Value[10] != L':' || rule->Value[11] != L'0' || rule->Value[12] != L'x'))) {
                    return STATUS_INVALID_PARAMETER;
                }
                for (character = 2; character < valueLength; character++) {
                    WCHAR digit = rule->Value[character];
                    if (character >= 10 && character <= 12) continue;
                    if (!((digit >= L'0' && digit <= L'9') ||
                          (digit >= L'a' && digit <= L'f') ||
                          (digit >= L'A' && digit <= L'F'))) {
                        return STATUS_INVALID_PARAMETER;
                    }
                }
            }
        }
    }
    for (index = 0; index < Config->NetworkRuleCount; index++) {
        const KFILTER_NET_RULE* rule = &Config->Network[index];
        if (rule->Action != KFilterActionAllow && rule->Action != KFilterActionDeny &&
            rule->Action != KFilterActionAudit) return STATUS_INVALID_PARAMETER;
        BOOLEAN message = rule->Rights != 0 && (rule->Rights & ~KFILTER_RIGHTS_MESSAGE) == 0;
        /* unix= (ABI 12): a send to an AF_UNIX peer, named by Unix alone; no other rule names one. */
        BOOLEAN unixPeer = rule->Family == KFILTER_NET_FAMILY_UNIX;
        ULONG unixLength = KfLengthBounded(rule->Unix, KFILTER_MAX_VALUE);
        if (unixPeer ? rule->Rights != KFILTER_RIGHT_SEND || unixLength == 0 || unixLength >= KFILTER_MAX_VALUE ||
                           rule->Unix[0] != L'/' || (rule->PrefixLength | rule->Port | rule->Protocol) != 0
                     : rule->Unix[0] != L'\0') return STATUS_INVALID_PARAMETER;
        if (rule->Family != 4 && rule->Family != 6 && !(message && (rule->Family == 0 || unixPeer))) return STATUS_INVALID_PARAMETER;
        if (rule->PrefixLength > (rule->Family == 4 ? 32u : 128u)) return STATUS_INVALID_PARAMETER;
        if (rule->Protocol != 0 && rule->Protocol != 6 && rule->Protocol != 17) return STATUS_INVALID_PARAMETER;
        /* A rule is a connection rule (connect, listen) or a message rule (send, receive). */
        if ((!message && (rule->Rights & ~(KFILTER_RIGHT_CONNECT | KFILTER_RIGHT_LISTEN)) != 0) ||
            (rule->Action == KFilterActionAllow && rule->Rights == 0)) return STATUS_INVALID_PARAMETER;
        if (rule->MatchLength > KFILTER_MAX_MATCH || (rule->SizeMax != 0 && rule->SizeMax < rule->SizeMin) ||
            (rule->IndexMax != 0 && rule->IndexMax < rule->IndexMin) ||
            (!message && (rule->MatchLength | rule->SizeMin | rule->SizeMax | rule->IndexMin | rule->IndexMax) != 0) ||
            (!message && rule->Module[0] != L'\0') || KfLengthBounded(rule->Module, KFILTER_MAX_IMAGE) >= KFILTER_MAX_IMAGE) {
            return STATUS_INVALID_PARAMETER;
        }
        if (!KfCountValid(rule->Count, rule->Action) ||
            KfLengthBounded(rule->Risk, KFILTER_MAX_RISK) >= KFILTER_MAX_RISK ||
            KfLengthBounded(rule->Image, KFILTER_MAX_IMAGE) >= KFILTER_MAX_IMAGE) {
            return STATUS_INVALID_PARAMETER;
        }
    }
    return STATUS_SUCCESS;
}

NTSTATUS KfPolicySetConfig(const KFILTER_CONFIG* Config, ULONG Length)
{
    PKF_CONFIG_REF next;
    PKF_CONFIG_REF old;
    KIRQL oldIrql;
    NTSTATUS status;
    SIZE_T size;
    ULONG rules;

    if (Config != NULL && Length >= KFILTER_CONFIG_SIZE(0) &&
        (Config->Flags & KFILTER_CFG_BLOCK_RAW_DISK) != 0 && KfDiskDegraded()) {
        status = KfDiskRearm();
        if (!NT_SUCCESS(status) && Config->Mode == KFILTER_MODE_BLOCK) return status;
    }
    status = KfValidateConfig(Config, Length);
    if (!NT_SUCCESS(status)) return status;

    rules = Config->RuleCount;
    size = FIELD_OFFSET(KF_CONFIG_REF, Config) + KFILTER_CONFIG_SIZE(rules);
    next = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, KFILTER_POOL_TAG);
    if (next == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(next, size);
    RtlCopyMemory(&next->Config, Config, KFILTER_CONFIG_SIZE(rules));
    next->Config.AbiVersion = KFILTER_ABI_VERSION;
    next->RefCount = 1;
    next->Phase = 1;
    next->Used = ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                 sizeof(LONG) * ((SIZE_T)rules + Config->NetworkRuleCount + 1),
                                 KFILTER_POOL_TAG);
    next->IndexMemory = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(ULONG) * 3 * ((SIZE_T)rules + 1),
                                        KFILTER_POOL_TAG);
    if (next->Used == NULL || next->IndexMemory == NULL) {
        KfConfigRelease(next);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    next->Index.Keys = next->IndexMemory;
    next->Index.KeyRules = next->IndexMemory + rules + 1;
    next->Index.Globs = next->IndexMemory + 2 * ((SIZE_T)rules + 1);
    next->Index.KeyCount = KfIndexBuild(next->Config.Rules, rules,
                                        next->IndexMemory, next->IndexMemory + rules + 1,
                                        next->IndexMemory + 2 * ((SIZE_T)rules + 1),
                                        &next->Index.GlobCount);

    KeAcquireSpinLock(&gConfigLock, &oldIrql);
    old = gConfig;
    next->Config.Generation = (old != NULL ? old->Config.Generation : 0) + 1;
    gGeneration = next->Config.Generation;
    gConfig = next;
    KeReleaseSpinLock(&gConfigLock, oldIrql);
    KfConfigRelease(old);
    return STATUS_SUCCESS;
}

ULONG KfPolicyMode(VOID)
{
    PKF_CONFIG_REF config = KfConfigAcquire();
    ULONG mode;
    if (config == NULL) return KFILTER_MODE_OFF;
    mode = config->Config.Mode;
    KfConfigRelease(config);
    return mode;
}

ULONG KfPolicyGeneration(VOID)
{
    PKF_CONFIG_REF config = KfConfigAcquire();
    ULONG generation;
    if (config == NULL) return 0;
    generation = config->Config.Generation;
    KfConfigRelease(config);
    return generation;
}

BOOLEAN KfPolicyFlag(ULONG Flag)
{
    PKF_CONFIG_REF config = KfConfigAcquire();
    BOOLEAN set;
    if (config == NULL) return FALSE;
    set = (config->Config.Flags & Flag) != 0;
    KfConfigRelease(config);
    return set;
}

BOOLEAN KfPolicyBlockVolumeSerial(VOID) { return KfPolicyFlag(KFILTER_CFG_BLOCK_VOLUME_SERIAL); }
BOOLEAN KfPolicyBlockProcessMemory(VOID) { return KfPolicyFlag(KFILTER_CFG_BLOCK_PROCESS_MEMORY); }
BOOLEAN KfPolicyBlockRawDisk(VOID) { return KfPolicyFlag(KFILTER_CFG_BLOCK_RAW_DISK); }
BOOLEAN KfPolicyBlockNetwork(VOID) { return KfPolicyFlag(KFILTER_CFG_BLOCK_NETWORK); }
BOOLEAN KfPolicyBlockNetworkAdapter(VOID) { return KfPolicyFlag(KFILTER_CFG_BLOCK_NETWORK_ADAPTER); }
BOOLEAN KfPolicyBlockFiles(VOID) { return KfPolicyFlag(KFILTER_CFG_BLOCK_FILES); }
BOOLEAN KfPolicyBlockRegistry(VOID) { return KfPolicyFlag(KFILTER_CFG_BLOCK_REGISTRY); }
BOOLEAN KfPolicyBlockProcessCreate(VOID) { return KfPolicyFlag(KFILTER_CFG_BLOCK_PROCESS_CREATE); }
BOOLEAN KfPolicyDefaultDeny(VOID) { return KfPolicyFlag(KFILTER_CFG_DEFAULT_DENY); }

BOOLEAN KfPolicyRawDiskDegraded(VOID)
{
    PKF_CONFIG_REF config = KfConfigAcquire();
    BOOLEAN degraded;
    if (config == NULL) return FALSE;
    degraded = KfRawDiskDegraded(config->Config.Mode, config->Config.Flags,
                                 KfDiskDegraded()) != 0;
    KfConfigRelease(config);
    return degraded;
}

BOOLEAN KfPolicyMatchesProtectedName(PCUNICODE_STRING ImagePath)
{
    PKF_CONFIG_REF config;
    BOOLEAN matched = FALSE;
    ULONG index;

    if (ImagePath == NULL || ImagePath->Buffer == NULL || ImagePath->Length == 0) return FALSE;
    config = KfConfigAcquire();
    if (config == NULL) return FALSE;
    if (config->Config.Root[0] != L'\0' && KfRootMatches(config->Config.Root, ImagePath)) {
        matched = TRUE;
    }
    for (index = 0; index < config->Config.ProtectedCount && !matched; index++) {
        ULONG nameLength = KfLength(config->Config.Protected[index]);
        ULONG imageLength = ImagePath->Length / sizeof(WCHAR);
        if (nameLength == 0 || nameLength > imageLength) continue;
        if (KfNameMatchesSuffix(ImagePath->Buffer, imageLength,
                                config->Config.Protected[index], nameLength)) {
            matched = TRUE;
        }
    }
    KfConfigRelease(config);
    return matched;
}

BOOLEAN KfPolicyIsUnderRoot(PCUNICODE_STRING ImagePath)
{
    PKF_CONFIG_REF config = KfConfigAcquire();
    BOOLEAN matched;
    if (config == NULL) return FALSE;
    matched = config->Config.Root[0] != L'\0' && KfRootMatches(config->Config.Root, ImagePath);
    KfConfigRelease(config);
    return matched;
}

BOOLEAN KfPolicyPackageSidMatches(const UCHAR* Sid, ULONG SidLength)
{
    PKF_CONFIG_REF config = KfConfigAcquire();
    BOOLEAN matches;
    if (config == NULL) return FALSE;
    matches = config->Config.PackageSidLength == 0 ||
              (Sid != NULL && SidLength == config->Config.PackageSidLength &&
               RtlCompareMemory(Sid, config->Config.PackageSid, SidLength) == SidLength);
    KfConfigRelease(config);
    return matches;
}

BOOLEAN KfPolicyHasProcessRules(VOID)
{
    PKF_CONFIG_REF config = KfConfigAcquire();
    BOOLEAN found = FALSE;
    ULONG index;
    if (config == NULL) return FALSE;
    for (index = 0; index < config->Config.RuleCount; index++) {
        if ((config->Config.Rules[index].Targets & KFILTER_TARGET_PROCESS) != 0) {
            found = TRUE;
            break;
        }
    }
    KfConfigRelease(config);
    return found;
}

/*
 * HANDLE, OPEN and LAUNCH rules name an outside process by image path and account. The
 * first matching rule of the target whose rights meet Requested (and, if counted, has a
 * use left in an open phase) decides: an allow grants its rights; no rule grants none,
 * so the built-in block stands. *RuleIdOut and *FlagsOut say which rule granted
 * (KFILTER_EVENT_FLAG_COUNTED for a counted one) or, when none did, which counted rule
 * matched but was spent (KFILTER_EVENT_FLAG_EXHAUSTED).
 */
ULONG KfPolicyOutsideRights(ULONG Target, PCUNICODE_STRING ImagePath, BOOLEAN IsSystem,
                            ULONG Requested, ULONG* RuleIdOut, ULONG* FlagsOut)
{
    KF_IMAGE_REF image;
    PKF_CONFIG_REF config;
    WCHAR normalized[KFILTER_MAX_NAME];
    ULONG candidates[KF_MAX_CANDIDATES];
    ULONG length;
    ULONG rights = 0;
    ULONG count;
    ULONG position;
    BOOLEAN all;
    BOOLEAN risk = FALSE;

    *RuleIdOut = 0;
    *FlagsOut = 0;
    image.ProcessId = PsGetCurrentProcessId();
    image.Loaded = FALSE;
    image.Length = 0;
    if (ImagePath == NULL || ImagePath->Buffer == NULL || ImagePath->Length == 0) return 0;
    length = KfNormalizeName(ImagePath->Buffer, ImagePath->Length / sizeof(WCHAR),
                             normalized, KFILTER_MAX_NAME);
    if (length == 0) return 0;
    config = KfConfigAcquire();
    if (config == NULL) return 0;
    count = KfCandidates(config, normalized, length, candidates, &all);
    for (position = 0; position < count; position++) {
        ULONG index = all ? position : candidates[position];
        const KFILTER_RULE* rule = &config->Config.Rules[index];
        if ((rule->Targets & Target) == 0 || (rule->Rights & Requested) == 0) continue;
        if (rule->Account == KFILTER_ACCOUNT_SYSTEM && !IsSystem) continue;
        if (rule->Image[0] != L'\0' && !KfImageRuleMatches(&image, rule->Image)) continue;
        if ((rule->Flags & KFILTER_RULE_EXACT) != 0
                ? !KfMatchGlob(rule->Path, KfLength(rule->Path), normalized, length)
                : !KfPathMatches(rule->Path, KfLength(rule->Path), normalized, length)) continue;
        if (!KfCountTake(config, rule->Count, index, FALSE)) {
            if (*RuleIdOut == 0) {
                *RuleIdOut = rule->RuleId;
                *FlagsOut = KFILTER_EVENT_FLAG_EXHAUSTED;
            }
            continue;
        }
        if (rule->Action == KFilterActionAllow) {
            rights = rule->Rights;
            risk = rule->Risk[0] != L'\0';
        }
        *RuleIdOut = rule->RuleId;
        *FlagsOut = rule->Count != 0 ? KFILTER_EVENT_FLAG_COUNTED : 0;
        break;
    }
    KfConfigRelease(config);
    if (risk) {
        KfLogEvent(Target, KFilterActionRisk, 0, STATUS_SUCCESS, Requested, *RuleIdOut, ImagePath);
    }
    return rights;
}

BOOLEAN KfPolicyLaunchBroker(PCUNICODE_STRING ImagePath, BOOLEAN IsSystem)
{
    ULONG ruleId;
    ULONG flags;
    BOOLEAN granted = (KfPolicyOutsideRights(KFILTER_TARGET_LAUNCH, ImagePath, IsSystem,
                                             KFILTER_RIGHT_CREATE, &ruleId, &flags) &
                       KFILTER_RIGHT_CREATE) != 0;
    if (ruleId != 0) {
        KfLogEvent(KFILTER_TARGET_LAUNCH, granted ? KFilterActionAllow : KFilterActionDeny, flags,
                   granted ? STATUS_SUCCESS : STATUS_ACCESS_DENIED, KFILTER_RIGHT_CREATE, ruleId,
                   ImagePath);
    }
    return granted;
}

/*
 * RegNtPreEnumerateValueKey carries only an index, not the value name, so a
 * value-scoped deny cannot be evaluated per value. A key with any value-scoped
 * deny is reported so the caller can refuse value enumeration in block mode:
 * RegEnumValue returns the data, not just the name.
 */
BOOLEAN KfPolicyValueEnumerationDenied(PCUNICODE_STRING KeyPath, ULONG* RuleIdOut)
{
    PKF_CONFIG_REF config;
    ULONG candidates[KF_MAX_CANDIDATES];
    ULONG count;
    BOOLEAN all;
    BOOLEAN denied;

    if (RuleIdOut != NULL) *RuleIdOut = 0;
    if (KeyPath == NULL || KeyPath->Buffer == NULL || KeyPath->Length == 0) return FALSE;
    config = KfConfigAcquire();
    if (config == NULL) return FALSE;
    count = KfCandidates(config, KeyPath->Buffer, KeyPath->Length / sizeof(WCHAR), candidates, &all);
    denied = KfRegistryValueEnumerationDeniedIn(config->Config.Rules, all ? NULL : candidates, count,
                                                KeyPath->Buffer, KeyPath->Length / sizeof(WCHAR),
                                                RuleIdOut) != 0;
    KfConfigRelease(config);
    return denied;
}

static ULONG KfTargetRights(ULONG Target, ULONG DesiredAccess)
{
    switch (Target) {
    case KFILTER_TARGET_FILE:
    case KFILTER_TARGET_PIPE:
        return KfRightsFromCreateAccess(DesiredAccess, 0);
    case KFILTER_TARGET_DIR:
        return KfRightsFromCreateAccess(DesiredAccess, 1);
    case KFILTER_TARGET_REGISTRY:
        return KfRightsFromRegistryAccess(DesiredAccess);
    default:
        return 0;
    }
}

BOOLEAN KfDecideWithRights(ULONG Target, PCUNICODE_STRING Path, ULONG Rights,
                           PCUNICODE_STRING Value, ULONG VolumeClass,
                           ULONG* RuleIdOut, BOOLEAN* NameFailureOut, ULONG* ActionOut,
                           ULONG EventValue)
{
    PKF_CONFIG_REF config;
    ULONG logValue = Target == KFILTER_TARGET_DEVICE ? EventValue : Rights;
    ULONG action = 0;
    ULONG ruleId = 0;
    ULONG exhausted = 0;
    ULONG exhaustedFlag = 0;
    ULONG candidates[KF_MAX_CANDIDATES];
    ULONG count;
    ULONG position;
    ULONG mode;
    BOOLEAN all = FALSE;
    BOOLEAN counted = FALSE;
    BOOLEAN risk = FALSE;
    BOOLEAN strict;
    BOOLEAN nameFailure = FALSE;
    BOOLEAN spentAllow = FALSE;
    BOOLEAN ruleOnly;
    WCHAR normalized[KFILTER_MAX_NAME];
    ULONG normalizedLength = 0;
    WCHAR valueNormalized[KFILTER_MAX_VALUE];
    ULONG valueLength = 0;
    KF_MATCH_INPUT input;
    KF_IMAGE_REF image;

    if (RuleIdOut != NULL) *RuleIdOut = 0;
    if (NameFailureOut != NULL) *NameFailureOut = FALSE;
    if (ActionOut != NULL) *ActionOut = 0;
    if (!KfProcessIsProtectedCurrent()) return FALSE;
    /* A request for none of the mapped rights is still a request; only a rule naming
     * `open` allows it. */
    if (Rights == 0) Rights = KFILTER_RIGHT_OPEN;

    if (Path == NULL || Path->Buffer == NULL || Path->Length == 0) {
        nameFailure = TRUE;
        KfCountNameFailure();
    } else {
        if (Target == KFILTER_TARGET_FILE || Target == KFILTER_TARGET_DIR ||
            Target == KFILTER_TARGET_PIPE) {
            normalizedLength = KfNormalizeName(Path->Buffer, Path->Length / sizeof(WCHAR),
                                               normalized, KFILTER_MAX_NAME);
        } else {
            normalizedLength = KfCopyExactName(Path->Buffer, Path->Length / sizeof(WCHAR),
                                               normalized, KFILTER_MAX_NAME);
        }
        if (normalizedLength == 0) {
            nameFailure = TRUE;
            KfCountNameFailure();
        }
    }
    if (Value != NULL && Value->Buffer != NULL && Value->Length != 0) {
        valueLength = KfCopyExactName(Value->Buffer, Value->Length / sizeof(WCHAR),
                                      valueNormalized, KFILTER_MAX_VALUE);
        if (valueLength == 0) {
            nameFailure = TRUE;
            KfCountNameFailure();
        }
    }

    config = KfConfigAcquire();
    if (config == NULL) return FALSE;
    mode = config->Config.Mode;
    if (mode == KFILTER_MODE_OFF ||
        ((Target == KFILTER_TARGET_FILE || Target == KFILTER_TARGET_DIR ||
          Target == KFILTER_TARGET_PIPE) &&
         (config->Config.Flags & KFILTER_CFG_BLOCK_FILES) == 0) ||
        (Target == KFILTER_TARGET_REGISTRY &&
         (config->Config.Flags & KFILTER_CFG_BLOCK_REGISTRY) == 0) ||
        (Target == KFILTER_TARGET_PROCESS &&
         (config->Config.Flags & KFILTER_CFG_BLOCK_PROCESS_CREATE) == 0) ||
        (Target == KFILTER_TARGET_VOLUME &&
         (config->Config.Flags & KFILTER_CFG_BLOCK_VOLUME_SERIAL) == 0)) {
        KfConfigRelease(config);
        return FALSE;
    }

    input.Target = Target;
    input.Rights = Rights;
    input.Path = normalizedLength != 0 ? normalized : NULL;
    input.PathLength = normalizedLength;
    input.Value = valueLength != 0 ? valueNormalized : NULL;
    input.ValueLength = valueLength;
    input.Image = NULL;
    input.ImageLength = 0;
    image.ProcessId = PsGetCurrentProcessId();
    image.Loaded = FALSE;
    image.Length = 0;

    strict = (config->Config.Flags & KFILTER_CFG_DEFAULT_DENY) != 0;
    ruleOnly = KfRuleOnly(Target, input.Path, normalizedLength) != 0;
    if (KfPolicyRawDiskDegraded()) action = KFilterActionDeny;
    if (Target == KFILTER_TARGET_DEVICE && mode == KFILTER_MODE_BLOCK && KfDeviceDegraded()) {
        action = KFilterActionDeny;
    }
    if (nameFailure && mode == KFILTER_MODE_BLOCK && !ruleOnly) action = KFilterActionDeny;
    count = action == 0 ? KfCandidates(config, input.Path, normalizedLength, candidates, &all) : 0;
    for (position = 0; action == 0 && position < count; position++) {
        ULONG index = all ? position : candidates[position];
        const KFILTER_RULE* rule = &config->Config.Rules[index];
        if (rule->Image[0] != L'\0' && !image.Loaded) {
            (VOID)KfImageRuleMatches(&image, rule->Image);
            input.Image = image.Buffer;
            input.ImageLength = image.Length;
        }
        if (!KfRuleMatches(rule, &input)) continue;
        if (!KfCountTake(config, rule->Count, index,
                         Rights == KFILTER_RIGHT_QUERY &&
                             (Target & (KFILTER_TARGET_FILE | KFILTER_TARGET_DIR | KFILTER_TARGET_PIPE)) != 0)) {
            if (exhausted == 0) exhausted = rule->RuleId;
            if (rule->Action == KFilterActionAllow) spentAllow = TRUE;
            continue;
        }
        action = rule->Action;
        ruleId = rule->RuleId;
        counted = rule->Count != 0;
        risk = action == KFilterActionAllow && rule->Risk[0] != L'\0';
    }

    /* Rule-only: no rule, no decision (allowed, not logged), unless its counted allow is spent. */
    if (action == 0 && ruleOnly) {
        if (!spentAllow) {
            KfConfigRelease(config);
            return FALSE;
        }
        action = KFilterActionDeny;
    }

    /* Strict mode has no built-in allowance: a child process needs a rule too. */
    if (action == 0 && !strict && Target == KFILTER_TARGET_PROCESS &&
        config->Config.Root[0] != L'\0' && KfRootMatches(config->Config.Root, Path)) {
        action = KFilterActionAllow;
    }
    if (action == 0 && Target == KFILTER_TARGET_VOLUME) {
        action = (VolumeClass == 1 || VolumeClass == 8) ? KFilterActionDeny : KFilterActionAllow;
    }
    /* Raw-device access is deny-by-default whenever the device layer is active;
     * only an explicit allow rule may permit it, with or without default-deny. */
    if (action == 0 && Target == KFILTER_TARGET_DEVICE) {
        action = KFilterActionDeny;
    }
    if (action == 0) {
        action = (config->Config.Flags & KFILTER_CFG_DEFAULT_DENY) != 0
                     ? KFilterActionDeny : KFilterActionAllow;
    }
    KfConfigRelease(config);

    if (NameFailureOut != NULL) *NameFailureOut = nameFailure;
    if (RuleIdOut != NULL) *RuleIdOut = ruleId;
    if (ActionOut != NULL) *ActionOut = action;

    if (action == KFilterActionAllow) {
        InterlockedIncrement(&gAllowed);
        if (risk) {
            KfLogEvent(Target, KFilterActionRisk, 0, STATUS_SUCCESS, logValue, ruleId,
                       (Path != NULL && Path->Buffer != NULL) ? Path : NULL);
        }
        KfLogEvent(Target, KFilterActionAllow, counted ? KFILTER_EVENT_FLAG_COUNTED : 0, STATUS_SUCCESS,
                   logValue, ruleId, (Path != NULL && Path->Buffer != NULL) ? Path : NULL);
        return FALSE;
    }
    /* A default denial says which counted rule matched but was spent. */
    if (ruleId == 0 && exhausted != 0) {
        ruleId = exhausted;
        exhaustedFlag = KFILTER_EVENT_FLAG_EXHAUSTED;
    }
    if (action == KFilterActionAudit) {
        InterlockedIncrement(&gAudited);
        KfLogEvent(Target, KFilterActionAudit,
                   nameFailure ? KFILTER_EVENT_FLAG_NAME_FAILURE : 0,
                   STATUS_SUCCESS, logValue, ruleId,
                   (Path != NULL && Path->Buffer != NULL) ? Path : NULL);
        return FALSE;
    }
    if (mode == KFILTER_MODE_BLOCK) {
        InterlockedIncrement(&gDenied);
        KfLogEvent(Target, KFilterActionDeny,
                   (nameFailure ? KFILTER_EVENT_FLAG_NAME_FAILURE : 0) | exhaustedFlag,
                   STATUS_ACCESS_DENIED, logValue, ruleId,
                   (Path != NULL && Path->Buffer != NULL) ? Path : NULL);
        return TRUE;
    }
    InterlockedIncrement(&gAudited);
    InterlockedIncrement(&gWouldDeny);
    KfLogEvent(Target, KFilterActionAudit,
               KFILTER_EVENT_FLAG_WOULD_DENY | exhaustedFlag |
                   (nameFailure ? KFILTER_EVENT_FLAG_NAME_FAILURE : 0),
               STATUS_ACCESS_DENIED, logValue, ruleId,
               (Path != NULL && Path->Buffer != NULL) ? Path : NULL);
    return FALSE;
}

BOOLEAN KfDecide(ULONG Target, PCUNICODE_STRING Path, ULONG DesiredAccess,
                 PCUNICODE_STRING Value, ULONG VolumeClass,
                 ULONG* RuleIdOut, BOOLEAN* NameFailureOut)
{
    return KfDecideWithRights(Target, Path, KfTargetRights(Target, DesiredAccess),
                              Value, VolumeClass, RuleIdOut, NameFailureOut, NULL, 0);
}

static BOOLEAN KfIsLoopback(ULONG Family, const UCHAR* Address)
{
    ULONG index;
    if (Family == 4) return Address[0] == 127;
    for (index = 0; index < 15; index++) {
        if (Address[index] != 0) return FALSE;
    }
    return Address[15] == 1;
}

ULONG KfPolicyNetworkDecide(HANDLE ProcessId, ULONG Family, ULONG Protocol, ULONG RemotePort,
                            const UCHAR* Address, ULONG Right, ULONG* RuleIdOut, ULONG* FlagsOut)
{
    PKF_CONFIG_REF config;
    ULONG action;
    ULONG index;
    KF_IMAGE_REF image;

    image.ProcessId = ProcessId;
    image.Loaded = FALSE;
    image.Length = 0;

    if (RuleIdOut != NULL) *RuleIdOut = 0;
    *FlagsOut = 0;
    if (Address == NULL || (Family != 4 && Family != 6)) return KFilterActionDeny;
    config = KfConfigAcquire();
    if (config == NULL) return KFilterActionAllow;
    if ((config->Config.Flags & KFILTER_CFG_BLOCK_NETWORK) == 0) {
        KfConfigRelease(config);
        return KFilterActionAllow;
    }
    if (KfPolicyRawDiskDegraded()) {
        KfConfigRelease(config);
        return KFilterActionDeny;
    }
    if ((config->Config.Flags & KFILTER_CFG_NET_ALLOW_LOOPBACK) != 0 && KfIsLoopback(Family, Address)) {
        KfConfigRelease(config);
        return KFilterActionAllow;
    }
    action = (config->Config.Flags & KFILTER_CFG_NET_DEFAULT_ALLOW) != 0
                 ? KFilterActionAllow : KFilterActionDeny;
    for (index = 0; index < config->Config.NetworkRuleCount; index++) {
        const KFILTER_NET_RULE* rule = &config->Config.Network[index];
        if (!KfNetworkRuleMatches(rule, Family, Protocol, RemotePort, Address, Right)) continue;
        if (rule->Image[0] != L'\0' && !KfImageRuleMatches(&image, rule->Image)) continue;
        if (!KfCountTake(config, rule->Count, config->Config.RuleCount + index, FALSE)) {
            if (*FlagsOut == 0) {
                *FlagsOut = KFILTER_EVENT_FLAG_EXHAUSTED;
                if (RuleIdOut != NULL) *RuleIdOut = rule->RuleId;
            }
            continue;
        }
        action = rule->Action;
        if (RuleIdOut != NULL) *RuleIdOut = rule->RuleId;
        *FlagsOut = (rule->Count != 0 ? KFILTER_EVENT_FLAG_COUNTED : 0) |
                    (action == KFilterActionAllow && rule->Risk[0] != L'\0' ? KFILTER_EVENT_FLAG_RISK : 0);
        break;
    }
    KfConfigRelease(config);
    return action;
}

/* Copies the live generation when it fits in Capacity bytes; returns the bytes it needs. */
ULONG KfPolicyGetConfig(PKFILTER_CONFIG Config, ULONG Capacity)
{
    PKF_CONFIG_REF config;
    ULONG size = (ULONG)KFILTER_CONFIG_SIZE(0);

    config = KfConfigAcquire();
    if (config != NULL) size = (ULONG)KFILTER_CONFIG_SIZE(config->Config.RuleCount);
    if (Capacity >= size) {
        RtlZeroMemory(Config, size);
        Config->AbiVersion = KFILTER_ABI_VERSION;
        if (config != NULL) RtlCopyMemory(Config, &config->Config, size);
    }
    if (config != NULL) KfConfigRelease(config);
    return size;
}

VOID KfPolicyGetStatus(PKFILTER_STATUS Status)
{
    PKF_CONFIG_REF config;
    KIRQL oldIrql;

    RtlZeroMemory(Status, sizeof(*Status));
    Status->AbiVersion = KFILTER_ABI_VERSION;
    KeAcquireSpinLock(&gConfigLock, &oldIrql);
    config = gConfig;
    if (config != NULL) {
        Status->Mode = config->Config.Mode;
        Status->Flags = config->Config.Flags;
        Status->RuleCount = config->Config.RuleCount;
        Status->ProtectedCount = config->Config.ProtectedCount;
        Status->NetworkRuleCount = config->Config.NetworkRuleCount;
        Status->PolicyGeneration = config->Config.Generation;
    }
    KeReleaseSpinLock(&gConfigLock, oldIrql);
    Status->Allowed = (ULONG)gAllowed;
    Status->Denied = (ULONG)gDenied;
    Status->Audited = (ULONG)gAudited;
    Status->WouldDeny = (ULONG)gWouldDeny;
    Status->NameFailures = (ULONG)gNameFailures;
    Status->MissingContexts = (ULONG)gMissingContexts;
    Status->DroppedEvents = KfDroppedEventCount();
    Status->TrackedProcesses = KfProcessTrackedCount();
    Status->SidFailures = (ULONG)gSidFailures;
    Status->Degraded = KfDiskDegraded() ? KFILTER_STATUS_DEGRADED_RAW_DISK : 0;
    if (KfDeviceDegraded()) Status->Degraded |= KFILTER_STATUS_DEGRADED_DEVICE;
}

VOID KfCountNameFailure(VOID) { InterlockedIncrement(&gNameFailures); }
VOID KfCountMissingContext(VOID) { InterlockedIncrement(&gMissingContexts); }
VOID KfCountSidFailure(VOID) { InterlockedIncrement(&gSidFailures); }
VOID KfCountDenied(VOID) { InterlockedIncrement(&gDenied); }

VOID KfCountDecision(ULONG Action, ULONG Flags)
{
    if ((Flags & KFILTER_EVENT_FLAG_NAME_FAILURE) != 0) InterlockedIncrement(&gNameFailures);
    if (Action == KFilterActionAllow) {
        InterlockedIncrement(&gAllowed);
    } else if (Action == KFilterActionDeny) {
        InterlockedIncrement(&gDenied);
    } else if (Action == KFilterActionAudit) {
        InterlockedIncrement(&gAudited);
        if ((Flags & KFILTER_EVENT_FLAG_WOULD_DENY) != 0) InterlockedIncrement(&gWouldDeny);
    }
}
