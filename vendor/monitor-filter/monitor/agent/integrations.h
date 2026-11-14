#pragma once

#include "telemetry.h"

#include <cstddef>
#include <unordered_map>

/* kfilter's own ABI headers, never a copy: a layout change must break this build, not the link. */
#ifdef _WIN32
#include <winioctl.h>   /* CTL_CODE, so kfilter.h defines the KFILTER_IOCTL_* codes */
#endif
#include "../../filter/driver/kfilter.h"
#ifndef _WIN32
#include "../../filter/linux/kfilter_socket.h"
#endif

/* KFilterDecisionEvent decodes ABI 9 fields (Image, BROKERED, MESSAGE, REPEAT, RISK, DIRECT, the
 * rule-only targets) and KFilterRuleText ABI 10's addr= ranges and ABI 11's peer value= and rights (its pseudo-rights
 * are access bits, printed as access=), and KFilterNetRuleText ABI 12's unix= peer; review them before following a bump.
 * abi/abi_test.c pins the same layouts for both OSes. */
static_assert(KFILTER_ABI_VERSION == 12u, "msmon's kfilter decision parser follows ABI 12");
static_assert(sizeof(KFILTER_EVENT) == (sizeof(wchar_t) == 2 ? 1192u : 2344u), "KFILTER_EVENT layout");
static_assert(offsetof(KFILTER_EVENT, Image) == 40u + KFILTER_MAX_NAME * sizeof(wchar_t), "KFILTER_EVENT.Image");
static_assert(sizeof(KFILTER_STATUS) == 80u && sizeof(KFILTER_READ_REQUEST) == 8u, "KFILTER_STATUS layout");

/* A decision about a process kfilter guards (its family): msmon tracks it too. */
struct KFilterFamilyProcess {
    DWORD pid;
    uint64_t timestamp;   /* the decision's; a process started after it is a reused PID */
};

/* sequence is required: every decision must carry a non-zero per-source sequence. ruleText is the
 * rule RuleId names in the policy generation the reader holds (empty when unknown). */
TelemetryEvent KFilterDecisionEvent(const KFILTER_EVENT& event, uint64_t sessionId, uint64_t sequence,
                                    const std::wstring& ruleText = {});
/* allow, deny, would_deny (audit mode denial), audit (audit rule) or risk. */
const wchar_t* KFilterDecisionName(const KFILTER_EVENT& event);
/* ProcessId names a member of kfilter's protected family (not an outside process or a creator). */
bool KFilterDecisionNamesFamily(const KFILTER_EVENT& event);
std::wstring KFilterRuleText(const KFILTER_RULE& rule);
std::wstring KFilterNetRuleText(const KFILTER_NET_RULE& rule);
std::wstring KFilterStatusDetail(const KFILTER_STATUS& status, const KFILTER_STATUS* start);
std::wstring IntegrationCoverageState(bool etwEnabled, const std::wstring& kfilterState);

/* The ring survives across agent runs: only decisions stamped at or after the session start
 * belong to this session. Events at the boundary are included. */
bool KFilterDecisionInSession(const KFILTER_EVENT& event, uint64_t sessionStart);

class KFilterReader {
public:
    KFilterReader(uint64_t sessionId, uint64_t sessionStart);
    ~KFilterReader();

    bool Open(KFILTER_STATUS& status, std::wstring& state, std::wstring& detail);
    /* Reads until the ring is empty (bounded so one pass cannot starve the driver reader). The
     * ring is destructive and single-consumer: nothing else (kfilterctl watch/clear) may read it. */
    bool Drain(std::vector<TelemetryEvent>& events, std::vector<KFilterFamilyProcess>& family, std::wstring& error);
    /* Visible so the offline regression can exercise the session filter, numbering and rule text. */
    void ConvertBatch(const KFILTER_EVENT* batch, unsigned count, std::vector<TelemetryEvent>& events,
                      std::vector<KFilterFamilyProcess>* family = nullptr);
    void SetRules(const KFILTER_CONFIG& config);
    bool Status(KFILTER_STATUS& status, std::wstring& error);
    void Close();

private:
    /* GET_CONFIG: the policy's rule text by RuleId, for the generation decisions name. */
    bool LoadRules(std::wstring& error);

    uint64_t sessionId_;
    uint64_t sessionStart_;
    uint64_t sequence_ = 0;
    ULONG rulesGeneration_ = 0;
    ULONG failedGeneration_ = 0;
    std::unordered_map<ULONG, std::wstring> rules_;
    std::vector<KFILTER_EVENT> buffer_;
#ifdef _WIN32
    HANDLE handle_ = INVALID_HANDLE_VALUE;
#else
    /* Request/reply over KFILTER_SOCKET_PATH; one connection per request, see integrations.cpp. */
    bool Call(uint32_t code, const void* input, uint32_t inputLength, void* output, uint32_t capacity,
              uint32_t& bytes, std::wstring& error);
    bool open_ = false;
#endif
};
