/* Windows kernel C has no built-in wchar_t; everywhere else it is the compiler's. */
#if defined(_WIN32) && !defined(__cplusplus) && !defined(_WCHAR_T_DEFINED)
typedef unsigned short wchar_t;
#define _WCHAR_T_DEFINED
#endif
#include "match.h"

/* File access bits (avoid windows.h in this OS-free unit). */
#define KF_FILE_READ_DATA 0x00000001u
#define KF_FILE_WRITE_DATA 0x00000002u
#define KF_FILE_APPEND_DATA 0x00000004u
#define KF_FILE_READ_EA 0x00000008u
#define KF_FILE_WRITE_EA 0x00000010u
#define KF_FILE_EXECUTE 0x00000020u
#define KF_FILE_READ_ATTRIBUTES 0x00000080u
#define KF_FILE_WRITE_ATTRIBUTES 0x00000100u
#define KF_DELETE 0x00010000u
#define KF_WRITE_DAC 0x00040000u
#define KF_WRITE_OWNER 0x00080000u
#define KF_SYNCHRONIZE 0x00100000u
#define KF_GENERIC_READ 0x80000000u
#define KF_GENERIC_WRITE 0x40000000u
#define KF_GENERIC_EXECUTE 0x20000000u
#define KF_GENERIC_ALL 0x10000000u
#define KF_MAXIMUM_ALLOWED 0x02000000u

/* Registry access bits. */
#define KF_KEY_QUERY_VALUE 0x0001u
#define KF_KEY_SET_VALUE 0x0002u
#define KF_KEY_CREATE_SUB_KEY 0x0004u
#define KF_KEY_ENUMERATE_SUB_KEYS 0x0008u
#define KF_KEY_NOTIFY 0x0010u
#define KF_KEY_CREATE_LINK 0x0020u
#define KF_READ_CONTROL 0x00020000u

/* Create dispositions and options (winnt.h values; this OS-free unit includes no headers). */
#define KF_FILE_SUPERSEDE 0x00000000u
#define KF_FILE_CREATE 0x00000002u
#define KF_FILE_OVERWRITE 0x00000004u
#define KF_FILE_OVERWRITE_IF 0x00000005u
#define KF_FILE_DELETE_ON_CLOSE 0x00001000u

#define KF_FILE_RIGHTS (KFILTER_RIGHT_READ | KFILTER_RIGHT_WRITE | KFILTER_RIGHT_EXECUTE | \
                        KFILTER_RIGHT_DELETE | KFILTER_RIGHT_RENAME | KFILTER_RIGHT_SET_SECURITY)
#define KF_DIR_RIGHTS (KF_FILE_RIGHTS | KFILTER_RIGHT_ENUMERATE)
#define KF_REGISTRY_RIGHTS (KFILTER_RIGHT_READ | KFILTER_RIGHT_WRITE | KFILTER_RIGHT_DELETE | \
                            KFILTER_RIGHT_RENAME | KFILTER_RIGHT_SET_SECURITY | KFILTER_RIGHT_ENUMERATE)

static wchar_t KfUpcase(wchar_t Value)
{
    return (Value >= L'a' && Value <= L'z') ? (wchar_t)(Value - (L'a' - L'A')) : Value;
}

static int KfIsSeparator(wchar_t Value)
{
    return Value == L'\\' || Value == L'/';
}

static KF_ULONG KfStringLength(const wchar_t* Value)
{
    KF_ULONG length = 0;
    if (Value == 0) return 0;
    while (Value[length] != L'\0') length++;
    return length;
}

KF_ULONG KfLengthBounded(const wchar_t* Value, KF_ULONG Maximum)
{
    KF_ULONG length = 0;
    if (Value == 0 || Maximum == 0) return 0;
    while (length < Maximum && Value[length] != L'\0') length++;
    return length;
}

/*
 * Policy paths are prefixes: a rule for a directory/key must match the object
 * itself and anything below it. A trailing * already expresses that; otherwise
 * try the exact glob and then the same glob with "\*" appended. This is the
 * boundary-safe fix for the original full-match-only behavior.
 */
KF_ULONG KfPathMatches(const wchar_t* Pattern, KF_ULONG PatternLength,
                            const wchar_t* Text, KF_ULONG TextLength)
{
    wchar_t extended[KFILTER_MAX_NAME + 2];
    if (KfMatchGlob(Pattern, PatternLength, Text, TextLength)) return 1;
    if (PatternLength == 0 || Pattern[PatternLength - 1] == L'*') return 0;
    if (PatternLength + 3 > KFILTER_MAX_NAME + 2) return 0;
    for (KF_ULONG index = 0; index < PatternLength; index++) extended[index] = Pattern[index];
    /* A Linux pattern ("/...") owns '/' boundaries; an NT pattern owns '\\'. */
    extended[PatternLength] = Pattern[0] == L'/' ? L'/' : L'\\';
    extended[PatternLength + 1] = L'*';
    extended[PatternLength + 2] = L'\0';
    return KfMatchGlob(extended, PatternLength + 2, Text, TextLength);
}

KF_ULONG KfNameMatchesSuffix(const wchar_t* Path, KF_ULONG PathLength,
                                  const wchar_t* Suffix, KF_ULONG SuffixLength)
{
    KF_ULONG start;

    if (Path == 0 || Suffix == 0 || SuffixLength == 0 || PathLength < SuffixLength) return 0;
    start = PathLength - SuffixLength;
    if (!KfMatchGlob(Suffix, SuffixLength, Path + start, SuffixLength)) return 0;
    /* A policy name normally carries its own leading separator. A caller that
     * supplies a bare image name still has to land on a name boundary. */
    if (KfIsSeparator(Suffix[0])) return 1;
    return start == 0 || KfIsSeparator(Path[start - 1]);
}

KF_ULONG KfMatchGlob(const wchar_t* Pattern, KF_ULONG PatternLength,
                          const wchar_t* Text, KF_ULONG TextLength)
{
    KF_ULONG pattern = 0;
    KF_ULONG text = 0;
    KF_ULONG star = (KF_ULONG)-1;
    KF_ULONG mark = 0;
    int exactCase;

    if (Pattern == 0 || Text == 0) return 0;
    /* Linux paths are case-sensitive: an allow for /x/game must not cover /x/GAME. */
    exactCase = PatternLength != 0 && Pattern[0] == L'/';
    while (text < TextLength) {
        if (pattern < PatternLength && Pattern[pattern] == L'*') {
            star = ++pattern;
            mark = text;
            continue;
        }
        if (pattern < PatternLength &&
            (exactCase ? Pattern[pattern] == Text[text]
                       : KfUpcase(Pattern[pattern]) == KfUpcase(Text[text]))) {
            pattern++;
            text++;
            continue;
        }
        if (star != (KF_ULONG)-1) {
            pattern = star;
            text = ++mark;
            continue;
        }
        return 0;
    }
    while (pattern < PatternLength && Pattern[pattern] == L'*') pattern++;
    return pattern == PatternLength ? 1u : 0u;
}

KF_ULONG KfNormalizeName(const wchar_t* Path, KF_ULONG PathLength,
                              wchar_t* Output, KF_ULONG OutputCapacity)
{
    KF_ULONG index;
    KF_ULONG length;
    KF_ULONG lastSeparator = (KF_ULONG)-1;

    if (Path == 0 || Output == 0 || OutputCapacity == 0) return 0;
    if (PathLength > OutputCapacity - 1) return 0;
    for (index = 0; index < PathLength; index++) {
        if (Path[index] == L'\\' || Path[index] == L'/') lastSeparator = index;
    }
    length = 0;
    /* Streams and trailing dots/spaces are NT naming; a Linux name may legally contain
     * ':' or end in '.', and kfilterd resolves the path before it gets here. */
    if (PathLength != 0 && Path[0] == L'/') {
        for (index = 0; index < PathLength; index++) Output[length++] = Path[index];
        Output[length] = L'\0';
        return length;
    }
    for (index = 0; index < PathLength; index++) {
        /* A stream suffix starts at the first ':' after the last separator.
         * `foo.exe::$DATA` therefore matches the `foo.exe` rule. */
        if (Path[index] == L':' && lastSeparator != (KF_ULONG)-1 && index > lastSeparator) break;
        Output[length++] = Path[index];
    }
    while (length > 0 && (Output[length - 1] == L' ' || Output[length - 1] == L'.')) length--;
    Output[length] = L'\0';
    return length;
}

KF_ULONG KfCopyExactName(const wchar_t* Name, KF_ULONG NameLength,
                              wchar_t* Output, KF_ULONG OutputCapacity)
{
    KF_ULONG index;

    if (Name == 0 || Output == 0 || OutputCapacity == 0) return 0;
    if (NameLength > OutputCapacity - 1) return 0;
    for (index = 0; index < NameLength; index++) Output[index] = Name[index];
    Output[NameLength] = L'\0';
    return NameLength;
}

/* Every device request matches on its control code, including an open (zero), so
 * a value= rule can authorize the open that a value= control rule needs. */
KF_ULONG KfDeviceValueText(KF_ULONG Code, wchar_t* Buffer, KF_ULONG Capacity)
{
    static const wchar_t digits[] = L"0123456789ABCDEF";
    KF_ULONG index;

    if (Buffer == 0 || Capacity < 11) return 0;
    Buffer[0] = L'0';
    Buffer[1] = L'x';
    for (index = 0; index < 8; index++) {
        Buffer[2 + index] = digits[(Code >> (28 - 4 * index)) & 0xFu];
    }
    Buffer[10] = L'\0';
    return 10;
}

int KfDeviceDecisionRequired(KF_ULONG MajorFunction, KF_ULONG RequestorMode)
{
    if (MajorFunction == 0x0Fu) return 1;
    return (MajorFunction == 0x00u || MajorFunction == 0x0Eu) && RequestorMode == 1u;
}

/*
 * The disk/volume filter also owns raw data transfer: a handle opened directly
 * on the disk or volume can read or write sectors or issue FSCTLs without any
 * control code, so those user-mode requests must reach the device rules too.
 */
int KfDiskDecisionRequired(KF_ULONG MajorFunction, KF_ULONG RequestorMode)
{
    if (KfDeviceDecisionRequired(MajorFunction, RequestorMode)) return 1;
    return RequestorMode == 1u &&
           (MajorFunction == 0x03u || MajorFunction == 0x04u || MajorFunction == 0x0Du);
}

int KfScsiLinkMissing(KF_ULONG Status)
{
    return Status == 0xC0000034u || Status == 0xC000003Au;
}

/*
 * A rule path ending in a separator can never match an object name: the
 * prefix matcher appends "\*" to a pattern whose last character is already a
 * separator, so only a doubled separator could match. Reject it at parse time.
 */
int KfPathEndsWithSeparator(const wchar_t* Path, KF_ULONG Length)
{
    if (Path == 0 || Length == 0) return 1;
    return Path[Length - 1] == L'\\' || Path[Length - 1] == L'/';
}

KF_ULONG KfExtensionMask(const wchar_t* Path, KF_ULONG PathLength)
{
    KF_ULONG index = PathLength;
    KF_ULONG dot = (KF_ULONG)-1;
    KF_ULONG nameLength;

    if (Path == 0) return KFILTER_EXT_OTHER;
    while (index > 0) {
        wchar_t value = Path[index - 1];
        if (value == L'\\' || value == L'/') break;
        if (value == L'.') {
            dot = index - 1;
            break;
        }
        index--;
    }
    if (dot == (KF_ULONG)-1 || dot + 1 >= PathLength) return KFILTER_EXT_OTHER;
    nameLength = PathLength - dot - 1;
    if (nameLength == 3 && KfMatchGlob(L"exe", 3, Path + dot + 1, 3)) return KFILTER_EXT_EXE;
    if (nameLength == 3 && KfMatchGlob(L"dll", 3, Path + dot + 1, 3)) return KFILTER_EXT_DLL;
    if (nameLength == 3 && KfMatchGlob(L"sys", 3, Path + dot + 1, 3)) return KFILTER_EXT_SYS;
    if (nameLength == 3 && KfMatchGlob(L"ocx", 3, Path + dot + 1, 3)) return KFILTER_EXT_OCX;
    return KFILTER_EXT_OTHER;
}

KF_ULONG KfRightsFromCreateAccess(KF_ULONG DesiredAccess, int Directory)
{
    KF_ULONG rights = 0;

    if ((DesiredAccess & (KF_GENERIC_ALL | KF_MAXIMUM_ALLOWED)) != 0) {
        return Directory ? KF_DIR_RIGHTS : KF_FILE_RIGHTS;
    }
    /* Attributes only (GetFileAttributes, NtQueryAttributesFile): a metadata query, as a Linux
     * stat. kfilterctl gives query to every rule with read, so those decide as before. */
    if ((DesiredAccess & KF_FILE_READ_ATTRIBUTES) != 0 &&
        (DesiredAccess & ~(KF_FILE_READ_ATTRIBUTES | KF_READ_CONTROL | KF_SYNCHRONIZE)) == 0) {
        return KFILTER_RIGHT_QUERY;
    }
    if (Directory) {
        if ((DesiredAccess & (KF_FILE_READ_DATA | KF_FILE_READ_EA | KF_FILE_READ_ATTRIBUTES |
                              KF_GENERIC_READ | KF_GENERIC_EXECUTE)) != 0) {
            rights |= KFILTER_RIGHT_READ;
        }
        if ((DesiredAccess & (KF_FILE_READ_DATA | KF_GENERIC_READ)) != 0) {
            rights |= KFILTER_RIGHT_ENUMERATE;
        }
        if ((DesiredAccess & (KF_FILE_WRITE_DATA | KF_FILE_APPEND_DATA | KF_FILE_WRITE_EA |
                              KF_FILE_WRITE_ATTRIBUTES | KF_GENERIC_WRITE)) != 0) {
            rights |= KFILTER_RIGHT_WRITE;
        }
        if ((DesiredAccess & (KF_FILE_EXECUTE | KF_GENERIC_EXECUTE)) != 0) {
            rights |= KFILTER_RIGHT_EXECUTE;
        }
    } else {
        if ((DesiredAccess & (KF_FILE_READ_DATA | KF_FILE_READ_EA | KF_FILE_READ_ATTRIBUTES |
                              KF_GENERIC_READ)) != 0) {
            rights |= KFILTER_RIGHT_READ;
        }
        if ((DesiredAccess & (KF_FILE_WRITE_DATA | KF_FILE_APPEND_DATA |
                              KF_FILE_WRITE_EA | KF_FILE_WRITE_ATTRIBUTES |
                              KF_GENERIC_WRITE)) != 0) {
            rights |= KFILTER_RIGHT_WRITE;
        }
        if ((DesiredAccess & (KF_FILE_EXECUTE | KF_GENERIC_EXECUTE)) != 0) rights |= KFILTER_RIGHT_EXECUTE;
    }
    if ((DesiredAccess & KF_DELETE) != 0) rights |= KFILTER_RIGHT_DELETE;
    if ((DesiredAccess & (KF_WRITE_DAC | KF_WRITE_OWNER)) != 0) rights |= KFILTER_RIGHT_SET_SECURITY;
    return rights;
}

/*
 * A create can destroy existing data even when the handle itself asks only for
 * read access: FILE_SUPERSEDE/FILE_CREATE/FILE_OVERWRITE/FILE_OVERWRITE_IF
 * replace or truncate the file, and FILE_DELETE_ON_CLOSE deletes it at cleanup.
 * Fold those requests into the rights before the policy decision so a read-only
 * allow cannot authorize them.
 */
KF_ULONG KfCreateRights(KF_ULONG DesiredAccess, KF_ULONG Options, int Directory)
{
    KF_ULONG rights = KfRightsFromCreateAccess(DesiredAccess, Directory);
    KF_ULONG disposition = (Options >> 24) & 0xFFu;

    if (disposition == KF_FILE_SUPERSEDE || disposition == KF_FILE_CREATE ||
        disposition == KF_FILE_OVERWRITE || disposition == KF_FILE_OVERWRITE_IF) {
        rights |= KFILTER_RIGHT_WRITE;
    }
    if ((Options & KF_FILE_DELETE_ON_CLOSE) != 0) rights |= KFILTER_RIGHT_DELETE;
    return rights;
}

KF_ULONG KfCreateRightsForMajor(KF_ULONG DesiredAccess, KF_ULONG Options,
                                     KF_ULONG MajorFunction, int Directory)
{
    return MajorFunction == 0
        ? KfCreateRights(DesiredAccess, Options, Directory)
        : KfRightsFromCreateAccess(DesiredAccess, Directory);
}

KF_ULONG KfRightsFromRegistryAccess(KF_ULONG DesiredAccess)
{
    KF_ULONG rights = 0;

    if ((DesiredAccess & (KF_GENERIC_ALL | KF_MAXIMUM_ALLOWED)) != 0) return KF_REGISTRY_RIGHTS;
    /* Enumeration is its own right: a read-only allow must not grant it.
     * KEY_EXECUTE is KEY_READ, so the generic form needs read and enumerate
     * too; leaving it unmapped returned zero rights and skipped both checks. */
    if ((DesiredAccess & (KF_KEY_QUERY_VALUE | KF_KEY_NOTIFY |
                          KF_READ_CONTROL | KF_GENERIC_READ | KF_GENERIC_EXECUTE)) != 0) {
        rights |= KFILTER_RIGHT_READ;
    }
    if ((DesiredAccess & (KF_KEY_ENUMERATE_SUB_KEYS | KF_GENERIC_READ |
                          KF_GENERIC_EXECUTE)) != 0) {
        rights |= KFILTER_RIGHT_ENUMERATE;
    }
    if ((DesiredAccess & (KF_KEY_SET_VALUE | KF_KEY_CREATE_SUB_KEY | KF_KEY_CREATE_LINK |
                          KF_GENERIC_WRITE)) != 0) {
        rights |= KFILTER_RIGHT_WRITE;
    }
    if ((DesiredAccess & KF_DELETE) != 0) rights |= KFILTER_RIGHT_DELETE;
    if ((DesiredAccess & (KF_WRITE_DAC | KF_WRITE_OWNER)) != 0) rights |= KFILTER_RIGHT_SET_SECURITY;
    return rights;
}

KF_ULONG KfRightsFromSection(KF_ULONG PageProtection)
{
    KF_ULONG rights = 0;

    /* Executable mappings need execute, not raw FILE_READ_DATA. */
    if ((PageProtection & 0x000000F0u) != 0) {
        rights = KFILTER_RIGHT_EXECUTE;
        /* PAGE_EXECUTE_READWRITE (0x40) and PAGE_EXECUTE_WRITECOPY (0x80)
         * also imply write. */
        if ((PageProtection & 0x000000CCu) != 0) rights |= KFILTER_RIGHT_WRITE;
        return rights;
    }
    if ((PageProtection & 0x0000000Eu) != 0) {
        rights = KFILTER_RIGHT_READ;
        if ((PageProtection & 0x0000000Cu) != 0) rights |= KFILTER_RIGHT_WRITE;
    }
    if (rights == 0) rights = KFILTER_RIGHT_READ;
    return rights;
}

/* shortcut: all control operations require read+write, refine per control code
 * if compatibility requires it. */
KF_ULONG KfRightsFromControlOperation(void)
{
    return KFILTER_RIGHT_READ | KFILTER_RIGHT_WRITE;
}

/* WFP reports an IPv4 address as a host-order number (0x7F000001 is
 * 127.0.0.1); policy rules hold InetPtonW's wire-order bytes. Write the four
 * octets in wire order so both sides compare the same layout. */
KF_ULONG KfIpv4Bytes(KF_ULONG Value, unsigned char* Output)
{
    if (Output == 0) return 0;
    Output[0] = (unsigned char)(Value >> 24);
    Output[1] = (unsigned char)(Value >> 16);
    Output[2] = (unsigned char)(Value >> 8);
    Output[3] = (unsigned char)Value;
    return 4;
}

int KfImageMatches(const wchar_t* Pattern, const wchar_t* Image, KF_ULONG ImageLength)
{
    KF_ULONG patternLength = KfLengthBounded(Pattern, KFILTER_MAX_IMAGE);
    KF_ULONG index;
    KF_ULONG start = 0;
    int whole = 0;

    if (patternLength == 0) return 1;
    if (Image == 0 || ImageLength == 0) return 0;
    for (index = 0; index < patternLength; index++) {
        if (Pattern[index] == L'\\' || Pattern[index] == L'/') whole = 1;
    }
    if (!whole) {
        for (index = 0; index < ImageLength; index++) {
            if (Image[index] == L'\\' || Image[index] == L'/') start = index + 1;
        }
    }
    /* A file-name pattern never starts with '/', so it is matched without case. */
    return KfMatchGlob(Pattern, patternLength, Image + start, ImageLength - start) != 0;
}

int KfRuleMatches(const KFILTER_RULE* Rule, const KF_MATCH_INPUT* Input)
{
    KF_ULONG pathLength;
    const wchar_t* path;
    KF_ULONG valueLength;
    const wchar_t* value;

    if (Rule == 0 || Input == 0) return 0;
    if (Rule->Action == KFilterActionAllow && Rule->Rights == 0) return 0;
    if ((Rule->Targets & Input->Target) == 0) return 0;
    /* addr= meets only the BPF layer's decisions on memory: no input here carries an address. */
    if ((Rule->Flags & KFILTER_RULE_ADDRESS) != 0) return 0;

    if (Input->Target == KFILTER_TARGET_FILE || Input->Target == KFILTER_TARGET_DIR ||
        Input->Target == KFILTER_TARGET_PIPE) {
        KF_ULONG extension;
        if (Input->Path == 0 || Input->PathLength == 0) return 0;
        path = Input->Path;
        pathLength = Input->PathLength;
        extension = KfExtensionMask(path, pathLength);
        if (Rule->Extensions != 0 && (Rule->Extensions & extension) == 0) return 0;
    } else {
        path = Input->Path;
        pathLength = Input->PathLength;
    }

    if (Rule->Action == KFilterActionAllow) {
        /* An allow must cover every requested right; an empty request is not
         * authorized because it may represent an access form not mapped yet. */
        if (Input->Rights == 0 || (Input->Rights & ~Rule->Rights) != 0) return 0;
    } else if (Rule->Rights != 0 && Input->Rights != 0 &&
               (Input->Rights & Rule->Rights) == 0) {
        return 0;
    }
    if (path == 0 || pathLength == 0) return 0;
    if ((Rule->Flags & KFILTER_RULE_EXACT) != 0) {
        if (!KfMatchGlob(Rule->Path, KfStringLength(Rule->Path), path, pathLength)) return 0;
    } else if (!KfPathMatches(Rule->Path, KfStringLength(Rule->Path), path, pathLength)) {
        return 0;
    }

    if (Rule->Value[0] != L'\0') {
        value = Input->Value;
        valueLength = Input->ValueLength;
        if (value == 0 || valueLength == 0) return 0;
        if (!KfMatchGlob(Rule->Value, KfStringLength(Rule->Value), value, valueLength)) return 0;
    }
    if (Rule->Image[0] != L'\0' && !KfImageMatches(Rule->Image, Input->Image, Input->ImageLength)) return 0;
    return 1;
}

int KfNetworkRuleMatchesImage(const KFILTER_NET_RULE* Rule, KF_ULONG Family,
                              KF_ULONG Protocol, KF_ULONG RemotePort,
                              const unsigned char* Address, KF_ULONG Right,
                              const wchar_t* Image, KF_ULONG ImageLength)
{
    if (!KfNetworkRuleMatches(Rule, Family, Protocol, RemotePort, Address, Right)) return 0;
    return KfImageMatches(Rule->Image, Image, ImageLength);
}

int KfNetworkRuleMatches(const KFILTER_NET_RULE* Rule, KF_ULONG Family,
                         KF_ULONG Protocol, KF_ULONG RemotePort,
                         const unsigned char* Address, KF_ULONG Right)
{
    KF_ULONG fullBytes;
    KF_ULONG remainder;
    KF_ULONG index;

    if (Rule == 0 || Address == 0 || Rule->Family != Family) return 0;
    if (Rule->PrefixLength > (Family == 4 ? 32u : Family == 6 ? 128u : 0u)) return 0;
    if (Rule->Protocol != 0 && Rule->Protocol != Protocol) return 0;
    if (Rule->Port != 0 && Rule->Port != RemotePort) return 0;
    if (Rule->Action == KFilterActionAllow) {
        if (Rule->Rights == 0 || Right == 0 || (Right & ~Rule->Rights) != 0) return 0;
    } else if (Rule->Rights != 0 && Right != 0 && (Rule->Rights & Right) == 0) {
        return 0;
    }

    fullBytes = Rule->PrefixLength / 8;
    remainder = Rule->PrefixLength % 8;
    for (index = 0; index < fullBytes; index++) {
        if (Address[index] != Rule->Address[index]) return 0;
    }
    if (remainder != 0) {
        unsigned char mask = (unsigned char)(0xFFu << (8 - remainder));
        if ((Address[fullBytes] & mask) != (Rule->Address[fullBytes] & mask)) return 0;
    }
    return 1;
}

int KfRegistryValueEnumerationDenied(const KFILTER_RULE* Rules, KF_ULONG RuleCount,
                                     const wchar_t* KeyPath, KF_ULONG KeyPathLength,
                                     KF_ULONG* RuleIdOut)
{
    return KfRegistryValueEnumerationDeniedIn(Rules, 0, RuleCount, KeyPath, KeyPathLength, RuleIdOut);
}

/* Order 0 means every rule, 0..OrderCount-1. */
int KfRegistryValueEnumerationDeniedIn(const KFILTER_RULE* Rules, const KF_ULONG* Order,
                                       KF_ULONG OrderCount,
                                       const wchar_t* KeyPath, KF_ULONG KeyPathLength,
                                       KF_ULONG* RuleIdOut)
{
    KF_MATCH_INPUT input;
    KF_ULONG position;
    int pathMatch;

    if (RuleIdOut != 0) *RuleIdOut = 0;
    if (Rules == 0 || KeyPath == 0 || KeyPathLength == 0) return 0;
    input.Target = KFILTER_TARGET_REGISTRY;
    input.Rights = KFILTER_RIGHT_READ | KFILTER_RIGHT_ENUMERATE;
    input.Path = KeyPath;
    input.PathLength = KeyPathLength;
    input.Value = 0;
    input.ValueLength = 0;

    for (position = 0; position < OrderCount; position++) {
        const KFILTER_RULE* rule = &Rules[Order != 0 ? Order[position] : position];
        if ((rule->Targets & KFILTER_TARGET_REGISTRY) == 0) continue;
        if (rule->Value[0] != L'\0') {
            /* The rule's path scope is the one KfRuleMatches uses: an exact rule covers
             * only its own key, every other rule covers the keys below it too. */
            pathMatch = (rule->Flags & KFILTER_RULE_EXACT) != 0
                            ? KfMatchGlob(rule->Path, KfStringLength(rule->Path),
                                          KeyPath, KeyPathLength) != 0
                            : KfPathMatches(rule->Path, KfStringLength(rule->Path),
                                            KeyPath, KeyPathLength) != 0;
            if (rule->Action == KFilterActionDeny &&
                (rule->Rights == 0 || (rule->Rights & input.Rights) != 0) && pathMatch) {
                if (RuleIdOut != 0) *RuleIdOut = rule->RuleId;
                return 1;
            }
            continue;
        }
        if (KfRuleMatches(rule, &input)) {
            if (rule->Action == KFilterActionDeny) {
                if (RuleIdOut != 0) *RuleIdOut = rule->RuleId;
                return 1;
            }
            return 0;
        }
    }
    return 0;
}

/* FNV-1a over the upcased characters, so the hash is as case-insensitive as KfMatchGlob. */
#define KF_HASH_START 2166136261u
#define KF_HASH_STEP(hash, value) (((hash) ^ (KF_ULONG)KfUpcase(value)) * 16777619u)

static int KfRuleIndexable(const KFILTER_RULE* Rule, KF_ULONG* KeyOut)
{
    KF_ULONG length = KfStringLength(Rule->Path);
    KF_ULONG hash = KF_HASH_START;
    KF_ULONG index;

    /* A trailing separator would match on a boundary the lookup does not try. */
    if (length == 0 || KfIsSeparator(Rule->Path[length - 1])) return 0;
    for (index = 0; index < length; index++) {
        if (Rule->Path[index] == L'*') return 0;
        hash = KF_HASH_STEP(hash, Rule->Path[index]);
    }
    *KeyOut = hash;
    return 1;
}

/* Heap sort of (key, rule) pairs by key, then rule. */
static int KfPairLess(const KF_ULONG* Keys, const KF_ULONG* Rules, KF_ULONG A, KF_ULONG B)
{
    return Keys[A] < Keys[B] || (Keys[A] == Keys[B] && Rules[A] < Rules[B]);
}

static void KfPairSwap(KF_ULONG* Keys, KF_ULONG* Rules, KF_ULONG A, KF_ULONG B)
{
    KF_ULONG key = Keys[A];
    KF_ULONG rule = Rules[A];
    Keys[A] = Keys[B];
    Rules[A] = Rules[B];
    Keys[B] = key;
    Rules[B] = rule;
}

static void KfPairSift(KF_ULONG* Keys, KF_ULONG* Rules, KF_ULONG Root, KF_ULONG Count)
{
    for (;;) {
        KF_ULONG child = 2 * Root + 1;
        if (child >= Count) return;
        if (child + 1 < Count && KfPairLess(Keys, Rules, child, child + 1)) child++;
        if (!KfPairLess(Keys, Rules, Root, child)) return;
        KfPairSwap(Keys, Rules, Root, child);
        Root = child;
    }
}

KF_ULONG KfIndexBuild(const KFILTER_RULE* Rules, KF_ULONG RuleCount,
                           KF_ULONG* Keys, KF_ULONG* KeyRules,
                           KF_ULONG* Globs, KF_ULONG* GlobCountOut)
{
    KF_ULONG keys = 0;
    KF_ULONG globs = 0;
    KF_ULONG index;

    for (index = 0; index < RuleCount; index++) {
        KF_ULONG key;
        if (KfRuleIndexable(&Rules[index], &key)) {
            Keys[keys] = key;
            KeyRules[keys] = index;
            keys++;
        } else {
            Globs[globs++] = index;
        }
    }
    for (index = keys / 2; index > 0; index--) KfPairSift(Keys, KeyRules, index - 1, keys);
    for (index = keys; index > 1; index--) {
        KfPairSwap(Keys, KeyRules, 0, index - 1);
        KfPairSift(Keys, KeyRules, 0, index - 1);
    }
    *GlobCountOut = globs;
    return keys;
}

/* Append the rules filed under Key; Out is sorted afterwards. */
static KF_ULONG KfIndexAdd(const KF_RULE_INDEX* Index, KF_ULONG Key, KF_ULONG* Out,
                                KF_ULONG Count, KF_ULONG Capacity)
{
    KF_ULONG low = 0;
    KF_ULONG high = Index->KeyCount;

    while (low < high) {
        KF_ULONG middle = low + (high - low) / 2;
        if (Index->Keys[middle] < Key) low = middle + 1;
        else high = middle;
    }
    for (; low < Index->KeyCount && Index->Keys[low] == Key; low++) {
        if (Count >= Capacity) return Capacity + 1;
        Out[Count++] = Index->KeyRules[low];
    }
    return Count;
}

KF_ULONG KfIndexCandidates(const KF_RULE_INDEX* Index, const wchar_t* Path,
                                KF_ULONG PathLength, KF_ULONG* Out,
                                KF_ULONG Capacity)
{
    KF_ULONG hash = KF_HASH_START;
    KF_ULONG count = 0;
    KF_ULONG index;
    KF_ULONG kept;

    if (Index->GlobCount > Capacity) return Capacity + 1;
    for (index = 0; index < Index->GlobCount; index++) Out[count++] = Index->Globs[index];
    for (index = 0; Path != 0 && index <= PathLength; index++) {
        if (index == PathLength || (KfIsSeparator(Path[index]) && index > 0)) {
            count = KfIndexAdd(Index, hash, Out, count, Capacity);
            if (count > Capacity) return count;
        }
        if (index < PathLength) hash = KF_HASH_STEP(hash, Path[index]);
    }
    /* Insertion sort (the list is short), dropping repeats left by hash collisions. */
    for (index = 1; index < count; index++) {
        KF_ULONG value = Out[index];
        KF_ULONG position = index;
        while (position > 0 && Out[position - 1] > value) {
            Out[position] = Out[position - 1];
            position--;
        }
        Out[position] = value;
    }
    kept = 0;
    for (index = 0; index < count; index++) {
        if (kept == 0 || Out[kept - 1] != Out[index]) Out[kept++] = Out[index];
    }
    return kept;
}

int KfRawDiskDegraded(KF_ULONG Mode, KF_ULONG Flags, int AttachFailed)
{
    return Mode == KFILTER_MODE_BLOCK &&
           (Flags & KFILTER_CFG_BLOCK_RAW_DISK) != 0 && AttachFailed != 0;
}

int KfRuleOnly(KF_ULONG Target, const wchar_t* Path, KF_ULONG PathLength)
{
    static const wchar_t anon[] = L"/anon/";
    KF_ULONG index;
    if ((Target & KFILTER_TARGETS_RULE_ONLY) != 0) return 1;
    if ((Target & (KFILTER_TARGET_FILE | KFILTER_TARGET_DIR | KFILTER_TARGET_PIPE)) == 0 || Path == 0 || PathLength < 6) return 0;
    for (index = 0; index < 6; index++) {
        if (Path[index] != anon[index]) return 0;
    }
    return 1;
}

int KfDeviceDefaultDecided(const wchar_t* Path, KF_ULONG PathLength)
{
#ifdef _WIN32
    return 1;
#else
    /* The three /net names are whole paths; the rest prefixes, as kfilter.bpf.c's identity_device(); "/dev/" last. */
    static const wchar_t* const named[] = { L"/net/ioctl", L"/net/netlink/route", L"/net/netlink/sock_diag",
                                            L"/dev/hidraw", L"/dev/sg", L"/dev/bsg/", L"/dev/bus/usb/", L"/dev/nvme",
                                            L"/dev/" };
    const KF_ULONG count = sizeof(named) / sizeof(named[0]);
    KF_ULONG index, at;
    if (PathLength == 0 || Path[0] != L'/') return 1;   /* a Windows device name (a Windows policy read here) */
    for (index = 0; index < PathLength; index++) {
        if (Path[index] == L'*') return 1;
    }
    for (index = 0; index < count; index++) {
        for (at = 0; named[index][at] != 0 && at < PathLength && Path[at] == named[index][at]; at++) {}
        if (named[index][at] == 0 && (index >= 3 || at == PathLength)) break;
    }
    if (index < count - 1) return 1;
    if (index == count) return 0;
    /* Any other /dev name may be a block device (block-raw-disk): devtmpfs makes them directly in /dev. */
    for (at = 5; at < PathLength; at++) {
        if (Path[at] == L'/') return 0;
    }
    return 1;
#endif
}

int KfAdmissionCreationDenied(KF_ULONG Mode, KF_ULONG Status)
{
    return Mode == KFILTER_MODE_BLOCK &&
           (Status == 0xC000009Au || Status == 0xC0000225u);
}

KF_ULONG KfPolicyUnenforced(const KFILTER_CONFIG* Config, KF_ULONG Registered, KF_ULONG* RuleIdOut)
{
    KF_ULONG reasons = 0;
    KF_ULONG first = 0;
    KF_ULONG index;
    /* Only kfilterd's BPF layer sees each message (Windows has no message layer). */
    int bpf = (Registered & KFILTER_REG_BPF) != 0;
#ifdef _WIN32
    KF_ULONG threadLayer = KFILTER_REG_OBJECT;
#else
    KF_ULONG threadLayer = KFILTER_REG_BPF;   /* Wine's thread handles are wineserver requests */
#endif

    if (!bpf && (Config->Flags & KFILTER_CFG_MESSAGE_DEFAULT_DENY) != 0) reasons |= KFILTER_STATUS_DEGRADED_MESSAGE;
    if (!bpf && (Config->Flags & KFILTER_CFG_BLOCK_FILE_QUERIES) != 0) reasons |= KFILTER_STATUS_DEGRADED_QUERY;
    if (!bpf && (Config->Flags & KFILTER_CFG_BLOCK_DIRECT_SYSCALL) != 0) reasons |= KFILTER_STATUS_DEGRADED_SYSTEM;
    if (!bpf && (Config->Flags & (KFILTER_CFG_BLOCK_PROCESS_SIGNALS | KFILTER_CFG_BLOCK_PROCESS_QUERIES)) != 0)
        reasons |= KFILTER_STATUS_DEGRADED_MEMORY;
    for (index = 0; index < Config->NetworkRuleCount && index < KFILTER_MAX_NET_RULES; index++) {
        const KFILTER_NET_RULE* rule = &Config->Network[index];
        int message = rule->Rights != 0 && (rule->Rights & ~KFILTER_RIGHTS_MESSAGE) == 0;
        KF_ULONG reason = 0;
        if (message && !bpf) reason = KFILTER_STATUS_DEGRADED_MESSAGE;
#ifndef _WIN32
        /* nftables matches the launch cgroup, not the program: image= needs the BPF layer. */
        if (!message && !bpf && rule->Image[0] != L'\0') reason = KFILTER_STATUS_DEGRADED_NETWORK;
#endif
        if (reason != 0 && first == 0) first = rule->RuleId;
        reasons |= reason;
    }
    for (index = 0; index < Config->RuleCount && index < KFILTER_MAX_RULES; index++) {
        const KFILTER_RULE* rule = &Config->Rules[index];
        KF_ULONG reason = 0;
        if ((rule->Targets & (KFILTER_TARGET_THREAD_HANDLE | KFILTER_TARGET_THREAD_OPEN)) != 0 &&
            (Registered & threadLayer) == 0) reason = KFILTER_STATUS_DEGRADED_MEMORY;
        /* Linux-only targets: kfilterd's BPF layer alone decides them (Windows never does). */
        if (!bpf && (rule->Targets & (KFILTER_TARGET_PEER | KFILTER_TARGET_THREAD_PEER)) != 0) reason = KFILTER_STATUS_DEGRADED_MEMORY;
        if (!bpf && (rule->Targets & KFILTER_TARGET_SYSTEM) != 0) reason = KFILTER_STATUS_DEGRADED_SYSTEM;
        if (!bpf && (rule->Targets & KFILTER_TARGET_DNS) != 0) reason = KFILTER_STATUS_DEGRADED_MESSAGE;
        if (!bpf && (rule->Targets & KFILTER_TARGET_THREAD) != 0) reason = KFILTER_STATUS_DEGRADED_THREAD;
        /* module= names the calling module, which only the BPF layer sees: elsewhere such a deny
         * or audit never applies (an allow that never applies refuses more, never less). So do lock, chdir and
         * touch, which only its hooks decide. */
        if (!bpf && reason == 0 && rule->Action != KFilterActionAllow &&
            ((rule->Flags & KFILTER_RULE_MODULE) != 0 ||
             ((rule->Targets & (KFILTER_TARGET_FILE | KFILTER_TARGET_DIR)) != 0 && (rule->Rights & KFILTER_RIGHTS_FILE_NAMED) != 0))) {
            reason = (rule->Targets & KFILTER_TARGET_PROCESS) != 0 ? KFILTER_STATUS_DEGRADED_PROCESS
                                                                     : KFILTER_STATUS_DEGRADED_FILES;
        }
        if (reason == 0) continue;
        if (first == 0) first = rule->RuleId;
        reasons |= reason;
    }
    if (RuleIdOut != 0) *RuleIdOut = first;
    return reasons;
}

KF_ULONG KfNetworkEventFlags(KF_ULONG Action, KF_ULONG Mode)
{
    return KFILTER_EVENT_FLAG_NETWORK |
           ((Action == KFilterActionDeny && Mode == KFILTER_MODE_AUDIT)
                ? KFILTER_EVENT_FLAG_WOULD_DENY : 0);
}

KF_ULONG KfNetworkEventValue(KF_ULONG Action, KF_ULONG Right, KF_ULONG Port)
{
    /* RISK names the granted right; every other record names the remote port. */
    return Action == KFilterActionRisk ? Right : Port;
}

int KfNetworkUnregisterComplete(long Status)
{
    return Status == 0 || (KF_ULONG)Status == 0xC0220001u;
}

