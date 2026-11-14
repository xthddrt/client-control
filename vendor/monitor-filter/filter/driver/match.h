#pragma once

#include "kfilter.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * OS-free policy matching. This file is compiled into the driver and into the
 * control tool's self-test/simulator, so both use exactly one implementation.
 * No kernel or Win32 headers; only <wchar.h>-level types.
 */

typedef struct _KF_MATCH_INPUT {
    KF_ULONG Target;
    KF_ULONG Rights;
    const wchar_t* Path;
    KF_ULONG PathLength;
    const wchar_t* Value;
    KF_ULONG ValueLength;
    const wchar_t* Image;     /* the requesting program's image path; may be empty */
    KF_ULONG ImageLength;
} KF_MATCH_INPUT;

/* A rule's image= pattern against the requesting program. An empty pattern matches every
 * program; otherwise a pattern with a separator is matched (any case) against the whole
 * image path and one without against its file name. An unknown image matches no pattern. */
int KfImageMatches(const wchar_t* Pattern, const wchar_t* Image, KF_ULONG ImageLength);

KF_ULONG KfMatchGlob(const wchar_t* Pattern, KF_ULONG PatternLength,
                          const wchar_t* Text, KF_ULONG TextLength);

KF_ULONG KfLengthBounded(const wchar_t* Value, KF_ULONG Maximum);

KF_ULONG KfExtensionMask(const wchar_t* Path, KF_ULONG PathLength);

/* Copy and normalize for matching: strip an ADS/stream suffix and trailing
 * dots/spaces. Returns the copied length, or 0 when the buffer is too small. */
KF_ULONG KfNormalizeName(const wchar_t* Path, KF_ULONG PathLength,
                              wchar_t* Output, KF_ULONG OutputCapacity);

/* Copy a registry value name without file-path normalization. */
KF_ULONG KfCopyExactName(const wchar_t* Name, KF_ULONG NameLength,
                              wchar_t* Output, KF_ULONG OutputCapacity);

/* Canonical rule value for a device request: the control code, or zero for an
 * open. Always ten characters, so `value=0x00000000` can pin the open a control
 * needs. Returns the written length, or 0 when Capacity is too small. */
KF_ULONG KfDeviceValueText(KF_ULONG Code, wchar_t* Buffer, KF_ULONG Capacity);
int KfDeviceDecisionRequired(KF_ULONG MajorFunction, KF_ULONG RequestorMode);
/* Device decisions plus user-mode READ/WRITE/FILE_SYSTEM_CONTROL: the disk and
 * volume filters own raw data transfer as well as control codes. */
int KfDiskDecisionRequired(KF_ULONG MajorFunction, KF_ULONG RequestorMode);
int KfScsiLinkMissing(KF_ULONG Status);
/* True when a rule path ends with a separator (or is empty), i.e. can never
 * match: prefix matching would require a doubled separator in the object name. */
int KfPathEndsWithSeparator(const wchar_t* Path, KF_ULONG Length);

/* Boundary-safe path-prefix match: the rule matches the object and anything
 * below it, on a separator boundary. Exposed for policy queries that carry no
 * value name. */
KF_ULONG KfPathMatches(const wchar_t* Pattern, KF_ULONG PatternLength,
                            const wchar_t* Text, KF_ULONG TextLength);

/* Case-insensitive suffix match that must start at the beginning of the text or
 * just after a separator. A suffix that already starts with a separator owns
 * its boundary. */
KF_ULONG KfNameMatchesSuffix(const wchar_t* Path, KF_ULONG PathLength,
                                  const wchar_t* Suffix, KF_ULONG SuffixLength);

KF_ULONG KfRightsFromCreateAccess(KF_ULONG DesiredAccess, int Directory);
/* The same, plus the rights a create's disposition/options imply: an overwrite
 * or supersede is WRITE, and FILE_DELETE_ON_CLOSE is DELETE. */
KF_ULONG KfCreateRights(KF_ULONG DesiredAccess, KF_ULONG Options, int Directory);
/* Only IRP_MJ_CREATE carries a disposition; other create types use access only. */
KF_ULONG KfCreateRightsForMajor(KF_ULONG DesiredAccess, KF_ULONG Options,
                                     KF_ULONG MajorFunction, int Directory);
KF_ULONG KfRightsFromRegistryAccess(KF_ULONG DesiredAccess);
KF_ULONG KfRightsFromSection(KF_ULONG PageProtection);
KF_ULONG KfRightsFromControlOperation(void);

/* Write the four wire-order octets of an IPv4 address given as a host-order
 * number (the form WFP supplies) so it matches InetPtonW's byte layout. */
KF_ULONG KfIpv4Bytes(KF_ULONG Value, unsigned char* Output);

int KfRuleMatches(const KFILTER_RULE* Rule, const KF_MATCH_INPUT* Input);
int KfNetworkRuleMatches(const KFILTER_NET_RULE* Rule, KF_ULONG Family,
                         KF_ULONG Protocol, KF_ULONG RemotePort,
                         const unsigned char* Address, KF_ULONG Right);
/* KfNetworkRuleMatches plus the rule's image= against the requesting program. */
int KfNetworkRuleMatchesImage(const KFILTER_NET_RULE* Rule, KF_ULONG Family,
                              KF_ULONG Protocol, KF_ULONG RemotePort,
                              const unsigned char* Address, KF_ULONG Right,
                              const wchar_t* Image, KF_ULONG ImageLength);
int KfRegistryValueEnumerationDenied(const KFILTER_RULE* Rules, KF_ULONG RuleCount,
                                     const wchar_t* KeyPath, KF_ULONG KeyPathLength,
                                     KF_ULONG* RuleIdOut);
/* The same, over only the rules listed in Order (ascending rule indexes), e.g. the
 * candidates KfIndexCandidates returned for the key. */
int KfRegistryValueEnumerationDeniedIn(const KFILTER_RULE* Rules, const KF_ULONG* Order,
                                       KF_ULONG OrderCount,
                                       const wchar_t* KeyPath, KF_ULONG KeyPathLength,
                                       KF_ULONG* RuleIdOut);

/*
 * Rule index. A rule path without a wildcard matches only a request path equal to it or
 * below it, so it is filed under the hash of its path; a request looks up the hash of
 * every prefix of its path that ends on a separator. Wildcard rules are always candidates.
 * The candidates come back in rule order, so first-match evaluation is unchanged.
 */
typedef struct _KF_RULE_INDEX {
    const KF_ULONG* Keys;      /* path hashes, ascending */
    const KF_ULONG* KeyRules;  /* the rule index for each key; ascending within a hash */
    KF_ULONG KeyCount;
    const KF_ULONG* Globs;     /* wildcard rules, ascending */
    KF_ULONG GlobCount;
} KF_RULE_INDEX;

/* Fill Keys/KeyRules/Globs (each RuleCount long) for Rules; returns the key count and
 * stores the glob count. */
KF_ULONG KfIndexBuild(const KFILTER_RULE* Rules, KF_ULONG RuleCount,
                           KF_ULONG* Keys, KF_ULONG* KeyRules,
                           KF_ULONG* Globs, KF_ULONG* GlobCountOut);

/* The rules that may match Path, ascending and without repeats. Returns the count, or
 * Capacity + 1 when they do not fit (the caller then checks every rule). */
KF_ULONG KfIndexCandidates(const KF_RULE_INDEX* Index, const wchar_t* Path,
                                KF_ULONG PathLength, KF_ULONG* Out,
                                KF_ULONG Capacity);
int KfRawDiskDegraded(KF_ULONG Mode, KF_ULONG Flags, int AttachFailed);
/* A request decided only by a rule naming it (KFILTER_TARGETS_RULE_ONLY, or a file named /anon/...):
 * without one it is allowed and not logged. */
int KfRuleOnly(KF_ULONG Target, const wchar_t* Path, KF_ULONG PathLength);
/* A device rule path that a decision made with no rule can name (refused then), so an allow there must be counted
 * (uses=N). Linux: identity character devices, names directly in /dev (block devices), /net/ioctl and the netlink
 * queries; any other '/' path (a GPU in /dev/dri, /anon/..., a plain file) is decided only where a rule names it.
 * Windows device names (and every path on Windows), and patterns, count as such paths. */
int KfDeviceDefaultDecided(const wchar_t* Path, KF_ULONG PathLength);
int KfAdmissionCreationDenied(KF_ULONG Mode, KF_ULONG Status);
/* The rules in Config that no layer in Registered (KFILTER_REG_*) can enforce, as
 * KFILTER_STATUS_DEGRADED_* bits (0: none): message rules and message-default deny without
 * the BPF layer, thread-handle rules without the object (Windows) or BPF (Linux) layer, and
 * without BPF image= network rules (Linux) and every Linux-only target (KFILTER_TARGETS_RULE_ONLY).
 * *RuleIdOut: the first such rule, 0 for a flag. */
KF_ULONG KfPolicyUnenforced(const KFILTER_CONFIG* Config, KF_ULONG Registered, KF_ULONG* RuleIdOut);
KF_ULONG KfNetworkEventFlags(KF_ULONG Action, KF_ULONG Mode);
KF_ULONG KfNetworkEventValue(KF_ULONG Action, KF_ULONG Right, KF_ULONG Port);
int KfNetworkUnregisterComplete(long Status);

#ifdef __cplusplus
}
#endif
