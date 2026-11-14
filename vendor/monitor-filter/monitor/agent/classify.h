#pragma once

#include "telemetry.h"
#include <map>
#include <unordered_map>

/* An agent record with sequence 0 is observer coverage, not a session event; every other
 * record carries the per-source identity tools/verify_log.py counts. */
bool CountsAsSessionEvent(const TelemetryEvent& event);

class OutsideClassifier {
public:
    OutsideClassifier(std::wstring clientDos, std::wstring clientNt,
                      std::wstring windowsDos, std::wstring windowsNt);
    void Classify(TelemetryEvent& event) const;

private:
    std::wstring clientDos_;
    std::wstring clientNt_;
    std::wstring windowsDos_;
    std::wstring windowsNt_;
};

class SessionSummary {
public:
    void Add(const TelemetryEvent& event);
    void SetInitiallyTracked(uint64_t count) { initiallyTracked_ = count; }
    std::string Json(const MSMON_STATISTICS& statistics, uint64_t etwDropped,
                     uint64_t driverGaps, uint64_t etwGaps) const;

private:
    uint64_t events_ = 0;
    uint64_t initiallyTracked_ = 0;
    uint64_t trackedStarts_ = 0;
    uint64_t outsideEvents_ = 0;
    uint64_t hardwareEvents_ = 0;
    uint64_t blackCatEvents_ = 0;
    uint64_t payloadBytes_ = 0;
    uint64_t payloadUnavailable_ = 0;
    uint64_t payloadDuplicateChunks_ = 0;
    struct PayloadProgress {
        uint32_t chunkCount = 0;
        bool invalid = false;
        std::map<ULONG, bool> chunks;
    };
    /* Only series that have not completed yet are retained. */
    std::map<uint64_t, PayloadProgress> payloadProgress_;
    uint64_t payloadOperations_ = 0;
    uint64_t completePayloads_ = 0;
    std::map<std::string, uint64_t> categories_;
    std::map<DWORD, uint64_t> processes_;
    std::map<DWORD, uint64_t> targets_;
    std::map<std::wstring, uint64_t> modules_;
};

/* The session-event accounting the agent writes to session_meta.json and coverage.json: the
 * summary, the total and the per-type counts move together, so they cannot drift apart. */
void AccountSessionEvent(SessionSummary& summary, const TelemetryEvent& event,
                         uint64_t& totalEvents,
                         std::unordered_map<unsigned long, uint64_t>& eventCounts);
