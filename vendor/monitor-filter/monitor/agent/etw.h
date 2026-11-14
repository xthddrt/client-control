#pragma once

#include "telemetry.h"
#ifdef _WIN32
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#endif
#include <deque>
#include <mutex>
#include <thread>

/* A WQL query with its quoted strings and numbers replaced (metadata mode; the Linux WMI probe uses it too). */
std::wstring SanitizeQuery(const std::wstring& query);

struct ProcessFacts {
    bool ok = false;
    uint64_t created = 0;
    DWORD parent = 0;
    std::wstring image;
};

class EtwCollector {
public:
    EtwCollector(ProcessScope& scope, EventQueue& queue, uint64_t sessionId, bool capturePayloads,
                 const std::vector<std::wstring>& scopeRoots);
    ~EtwCollector();
    bool Start(std::string& error);
    void Stop();
    const std::vector<std::wstring>& Warnings() const { return warnings_; }

    /* Hold an event until its process-start record arrives. created is the
     * incarnation captured with the event (0 = identity was not established). */
    void Defer(TelemetryEvent&& event, uint64_t created);
    /* Re-emit events that arrived before the driver's process-start record, only
     * for the incarnation each was captured for. Returns how many were emitted;
     * the rest stay pending and expire as unattributed. */
    size_t ReplayProcess(DWORD pid);
    /* Remember a connection's owner only while it is the live tracked
     * incarnation, and resolve a cached owner only while that same incarnation
     * is still tracked. */
    bool RememberTcpOwner(uint64_t tcb, DWORD pid, uint64_t created, const std::wstring& endpoints);
    void ForgetTcpOwner(uint64_t tcb);
    bool TcpOwner(uint64_t tcb, DWORD& pid, uint64_t& created, std::wstring& endpoints) const;
    bool ResolveTcpOwner(uint64_t tcb, DWORD providerPid, const ProcessFacts& facts,
                         std::wstring& endpoints, DWORD& pid, uint64_t& created);
    /* Expire unmatched events and emit an etw_unattributed coverage record. */
    void ExpirePending(uint64_t nowTick);
    uint64_t PendingCount() const;
    uint64_t UnattributedCount() const { return unattributed_.load(); }
    uint64_t PendingOverflow() const { return pendingOverflow_.load(); }
    uint64_t LostEvents() const { return lostEvents_.load(); }
    uint64_t ParseFailures() const { return parseFailures_.load(); }
    static constexpr int PROVIDERS = 5;
    uint64_t Received(int index) const { return index >= 0 && index < PROVIDERS ? received_[index].load() : 0; }
    uint64_t Parsed(int index) const { return index >= 0 && index < PROVIDERS ? parsed_[index].load() : 0; }
    uint64_t Emitted(int index) const { return index >= 0 && index < PROVIDERS ? emitted_[index].load() : 0; }
    uint64_t Deferred(int index) const { return index >= 0 && index < PROVIDERS ? deferred_[index].load() : 0; }
    uint64_t Expired(int index) const { return index >= 0 && index < PROVIDERS ? expired_[index].load() : 0; }

private:
#ifdef _WIN32
    static ULONG WINAPI BufferCallback(PEVENT_TRACE_LOGFILEW logfile);
    void OnRecord(PEVENT_RECORD record);
    void OnTcpRecord(PEVENT_RECORD record, const TRACE_EVENT_INFO* info);
    void OnCodeIntegrityRecord(PEVENT_RECORD record, const TRACE_EVENT_INFO* info);
    void EnableProvider(const GUID& provider, const std::wstring& name, ULONGLONG anyKeyword = 0,
                        const std::vector<USHORT>& eventIds = {}, bool stacks = true);
    bool MayBelongToClient(DWORD pid, uint64_t nowFileTime);
    ProcessFacts FactsForPid(DWORD pid);
#endif
    void Emit(TelemetryEvent&& event);
    std::wstring ProviderName(unsigned long type) const;

    struct CandidateDecision {
        ProcessFacts facts;
        uint64_t checkedTick = 0;
        bool candidate = false;
        bool classified = false;
    };

    struct PendingEvent {
        TelemetryEvent event;
        uint64_t created = 0;
        uint64_t deadline = 0;
    };

    ProcessScope& scope_;
    EventQueue& queue_;
    std::vector<std::wstring> scopeRoots_;
    /* Touched only by OnRecord on the ETW worker thread. */
    std::unordered_map<DWORD, CandidateDecision> candidates_;
    uint64_t sessionId_;
    bool capturePayloads_ = true;
#ifdef _WIN32
    TRACEHANDLE session_ = 0;
    TRACEHANDLE trace_ = 0;
    std::wstring loggerName_;
    std::vector<BYTE> properties_;
#endif
    std::thread worker_;
    std::atomic<uint64_t> sequence_{0};
    std::atomic<uint64_t> unattributed_{0};
    std::atomic<uint64_t> pendingOverflow_{0};
    std::atomic<uint64_t> lostEvents_{0};
    std::atomic<uint64_t> parseFailures_{0};
    std::atomic<uint64_t> received_[PROVIDERS]{};
    std::atomic<uint64_t> parsed_[PROVIDERS]{};
    std::atomic<uint64_t> emitted_[PROVIDERS]{};
    std::atomic<uint64_t> deferred_[PROVIDERS]{};
    std::atomic<uint64_t> expired_[PROVIDERS]{};
    struct TcpConnection {
        DWORD pid = 0;
        uint64_t created = 0;
        std::wstring endpoints;
    };
    /* TCP connection (TCB) -> tracked owner and addresses; touched only on the ETW worker thread. */
    std::unordered_map<uint64_t, TcpConnection> tcbConnections_;
    mutable std::mutex pendingMutex_;
    std::mutex emitMutex_;
    std::deque<PendingEvent> pending_;
    std::vector<std::wstring> warnings_;
    bool started_ = false;
};
