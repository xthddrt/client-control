#include "etw.h"
#ifdef _WIN32
#include "rpc_names.h"
#include <tdh.h>
#include <winternl.h>
#endif
#include <algorithm>
#include <cstddef>
#include <cstring>
#include <sstream>

#ifdef _WIN32
#ifndef TRACE_LEVEL_VERBOSE
#define TRACE_LEVEL_VERBOSE 5
#endif

static const GUID WMI_ACTIVITY = { 0x1418ef04, 0xb0b4, 0x4623, { 0xbf, 0x7e, 0xd7, 0x4a, 0xb4, 0x7b, 0xbd, 0xaa } };
static const GUID DNS_CLIENT = { 0x1c95126e, 0x7eea, 0x49a9, { 0xa3, 0xfe, 0xa3, 0x78, 0xb0, 0x3d, 0xdb, 0x4d } };
static const GUID RPC_EVENTS = { 0x6ad52b32, 0xd609, 0x4be9, { 0xae, 0x07, 0xce, 0x8d, 0xae, 0x93, 0x7e, 0x39 } };
static const GUID TCPIP_EVENTS = { 0x2f07e2ee, 0x15db, 0x40f1, { 0x90, 0xef, 0x9d, 0x7b, 0xa2, 0x82, 0x18, 0x8a } };
static const GUID CODE_INTEGRITY_EVENTS = { 0x4ee76bd8, 0x3cf4, 0x44a0, { 0xa0, 0xac, 0x39, 0x37, 0x64, 0x3e, 0x37, 0xa3 } };

/*
 * Microsoft-Windows-TCPIP keywords ConnectPath | ClosePath | ReceivePath |
 * Global | TcpipDiagnosis | TcpipTcb.  ReceivePath and Global are chatty on
 * their own; the event-ID filter keeps only the lifecycle events below.
 */
static const ULONGLONG TCPIP_KEYWORDS = 0x0000000400000000ull | 0x0000001000000000ull | 0x0000000200000000ull |
                                        0x0000008000000000ull | 0x80ull | 0x4ull;
#endif

/* Counter slot per provider; -1 for types that are not provider events. */
static int ProviderIndex(unsigned long type)
{
    switch (type) {
    case MsMonEtwWmi: return 0;
    case MsMonEtwDns: return 1;
    case MsMonEtwRpc: return 2;
    case MsMonEtwTcp: return 3;
    case MsMonEtwCodeIntegrity: return 4;
    default: return -1;
    }
}

std::wstring SanitizeQuery(const std::wstring& query)
{
    std::wstring output;
    output.reserve(query.size());
    wchar_t quote = 0;
    bool redacted = false;
    bool number = false;
    auto identifier = [](wchar_t c) {
        return (c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') || c == L'_';
    };
    for (size_t index = 0; index < query.size(); index++) {
        wchar_t c = query[index];
        if (quote != 0) {
            if (c == quote) {
                output.push_back(c);
                quote = 0;
            } else if (!redacted) {
                output.push_back(L'?');
                redacted = true;
            }
            continue;
        }
        if (c == L'\'' || c == L'\"') {
            output.push_back(c);
            quote = c;
            redacted = false;
            number = false;
        } else if (c >= L'0' && c <= L'9') {
            bool partOfIdentifier = (index != 0 && identifier(query[index - 1])) ||
                                    (index + 1 < query.size() && identifier(query[index + 1]));
            if (partOfIdentifier) {
                output.push_back(c);
            } else if (!number) {
                output.push_back(L'#');
            }
            number = !partOfIdentifier;
        } else {
            output.push_back(c);
            number = false;
        }
    }
    if (output.size() > 1800) output.resize(1800);
    return output;
}

#ifdef _WIN32
/*
 * TCP connection lifecycle events kept from Microsoft-Windows-TCPIP.  Each
 * names who ended a connection and how: a local close or abort, a
 * disconnect with its status, a shutdown with its reason, or a
 * retransmission, keep-alive or disconnect timeout.
 */
static const wchar_t* TcpEventName(USHORT id)
{
    switch (id) {
    case 1017: return L"accept_completed";
    case 1033: return L"connect_completed";
    case 1034: return L"connect_failed";
    case 1045: return L"connect_timeout";
    case 1183: return L"connect_reset";
    case 1186: return L"connect_retransmit";
    case 1038: return L"close_issued";
    case 1039: return L"abort_issued";
    case 1040: return L"abort_completed";
    case 1043: return L"disconnect_completed";
    case 1044: return L"shutdown_initiated";
    case 1046: return L"retransmit_timeout";
    case 1047: return L"keepalive_timeout";
    case 1048: return L"disconnect_timeout";
    case 1201: return L"finwait2_timeout";
    case 1176: return L"fin_received";
    case 1184: return L"reset_received";
    case 1479: return L"reset_sent";
    default: return nullptr;
    }
}

static bool TcpTerminalEvent(USHORT id)
{
    switch (id) {
    case 1034: case 1040: case 1043: case 1045: case 1046: case 1047: case 1048:
    case 1183: case 1184: case 1201: case 1479:
        return true;
    default:
        return false;
    }
}

static const std::vector<USHORT> TCPIP_EVENT_IDS = {
    1017, 1033, 1034, 1038, 1039, 1040, 1043, 1044, 1045, 1046, 1047, 1048, 1183, 1186,
    1176, 1184, 1201, 1479
};
static const std::vector<USHORT> CODE_INTEGRITY_EVENT_IDS = {3076, 3077};
#endif

static const ULONG ETW_PENDING_LIMIT = 4096;
static const ULONG ETW_PENDING_MILLISECONDS = 5000;

#ifdef _WIN32
static const ULONG ETW_CANDIDATE_RECHECK_MILLISECONDS = 1000;
static const int ETW_CANDIDATE_ANCESTOR_DEPTH = 4;

/*
 * Deferring every untracked PID would turn the log into a system-wide WMI/DNS/
 * RPC feed.  The race this queue fixes is narrow -- an ETW event from a client
 * process that started moments before the driver's process-start record
 * reaches the agent.  Deferring every recently started process let RPC traffic
 * from unrelated short-lived processes fill the bounded queue and evict the
 * client's own early events, so only processes that can belong to the client
 * tree are deferred: one whose image, or a recent ancestor's image, is under
 * the scope root, or whose parent is already tracked.
 */
static ProcessFacts QueryProcessFacts(DWORD pid)
{
    using QueryInformationProcess = NTSTATUS (NTAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    static const auto query = reinterpret_cast<QueryInformationProcess>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
    ProcessFacts facts;
    FILETIME creation{}, exitTime{}, kernelTime{}, userTime{};

    if (pid == 0 || pid == 4) return facts;
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process == NULL) return facts;
    if (GetProcessTimes(process, &creation, &exitTime, &kernelTime, &userTime)) {
        facts.created = (static_cast<uint64_t>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime;
        facts.ok = facts.created != 0;
    }
    std::vector<wchar_t> path(32768);
    DWORD size = static_cast<DWORD>(path.size());
    if (QueryFullProcessImageNameW(process, 0, path.data(), &size)) facts.image.assign(path.data(), size);
    PROCESS_BASIC_INFORMATION basic{};
    if (query != nullptr && NT_SUCCESS(query(process, ProcessBasicInformation, &basic, sizeof(basic), nullptr))) {
        /* Reserved3 is InheritedFromUniqueProcessId. */
        facts.parent = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(basic.Reserved3));
    }
    CloseHandle(process);
    return facts;
}

static bool UnderRoot(const std::wstring& root, const std::wstring& path)
{
    if (root.empty() || path.size() <= root.size()) return false;
    if (_wcsnicmp(path.c_str(), root.c_str(), root.size()) != 0) return false;
    return path[root.size()] == L'\\';
}

static const EVENT_PROPERTY_INFO* FindProperty(const TRACE_EVENT_INFO* info, const std::wstring& name)
{
    for (ULONG index = 0; index < info->TopLevelPropertyCount; index++) {
        const auto& property = info->EventPropertyInfoArray[index];
        const wchar_t* propertyName = reinterpret_cast<const wchar_t*>(
            reinterpret_cast<const BYTE*>(info) + property.NameOffset);
        if (name == propertyName) return &property;
    }
    return nullptr;
}

static bool PropertyData(PEVENT_RECORD record, const TRACE_EVENT_INFO* info,
                         const std::wstring& name, std::vector<BYTE>& data)
{
    if (FindProperty(info, name) == nullptr) return false;
    PROPERTY_DATA_DESCRIPTOR descriptor{};
    descriptor.PropertyName = reinterpret_cast<ULONGLONG>(const_cast<wchar_t*>(name.c_str()));
    descriptor.ArrayIndex = ULONG_MAX;
    ULONG size = 0;
    if (TdhGetPropertySize(record, 0, nullptr, 1, &descriptor, &size) != ERROR_SUCCESS || size == 0) {
        return false;
    }
    data.resize(size);
    return TdhGetProperty(record, 0, nullptr, 1, &descriptor, size, data.data()) == ERROR_SUCCESS;
}

static bool PropertyString(PEVENT_RECORD record, const TRACE_EVENT_INFO* info,
                           const std::wstring& name, std::wstring& output)
{
    const auto* property = FindProperty(info, name);
    std::vector<BYTE> data;
    if (property == nullptr || (property->Flags & PropertyStruct) != 0 ||
        !PropertyData(record, info, name, data)) return false;
    USHORT type = property->nonStructType.InType;
    if (type == TDH_INTYPE_UNICODESTRING) {
        size_t characters = data.size() / sizeof(wchar_t);
        const wchar_t* value = reinterpret_cast<const wchar_t*>(data.data());
        while (characters != 0 && value[characters - 1] == L'\0') characters--;
        output.assign(value, value + characters);
        return true;
    }
    if (type == TDH_INTYPE_ANSISTRING) {
        size_t length = data.size();
        while (length != 0 && data[length - 1] == 0) length--;
        if (length == 0) {
            output.clear();
            return true;
        }
        int wide = MultiByteToWideChar(CP_ACP, 0, reinterpret_cast<const char*>(data.data()),
                                       static_cast<int>(length), nullptr, 0);
        if (wide <= 0) return false;
        output.resize(static_cast<size_t>(wide));
        MultiByteToWideChar(CP_ACP, 0, reinterpret_cast<const char*>(data.data()),
                            static_cast<int>(length), output.data(), wide);
        return true;
    }
    return false;
}

static bool PropertyNumber(PEVENT_RECORD record, const TRACE_EVENT_INFO* info,
                           const std::wstring& name, uint64_t& output)
{
    std::vector<BYTE> data;
    if (!PropertyData(record, info, name, data)) return false;
    output = 0;
    size_t size = data.size();
    if (size != 1 && size != 2 && size != 4 && size != 8) return false;
    std::memcpy(&output, data.data(), size);
    return true;
}

static bool PropertyGuid(PEVENT_RECORD record, const TRACE_EVENT_INFO* info,
                         const std::wstring& name, std::wstring& output)
{
    const auto* property = FindProperty(info, name);
    std::vector<BYTE> data;
    GUID guid{};
    if (property == nullptr || (property->Flags & PropertyStruct) != 0 ||
        property->nonStructType.InType != TDH_INTYPE_GUID ||
        !PropertyData(record, info, name, data) || data.size() != sizeof(guid)) return false;
    std::memcpy(&guid, data.data(), sizeof(guid));
    output = RpcGuidText(guid);
    return true;
}

static void AppendField(std::wstring& target, const std::wstring& name, const std::wstring& value)
{
    if (value.empty()) return;
    if (!target.empty()) target += L";";
    target += name + L"=" + value;
}
#endif

EtwCollector::EtwCollector(ProcessScope& scope, EventQueue& queue, uint64_t sessionId, bool capturePayloads,
                           const std::vector<std::wstring>& scopeRoots)
    : scope_(scope), queue_(queue), scopeRoots_(scopeRoots), sessionId_(sessionId), capturePayloads_(capturePayloads) {}

#ifdef _WIN32
ProcessFacts EtwCollector::FactsForPid(DWORD pid)
{
    const uint64_t nowTick = GetTickCount64();
    auto cached = candidates_.find(pid);
    if (cached != candidates_.end() && nowTick - cached->second.checkedTick < ETW_CANDIDATE_RECHECK_MILLISECONDS) {
        return cached->second.facts;
    }

    ProcessFacts facts = QueryProcessFacts(pid);
    CandidateDecision decision;
    decision.facts = facts;
    decision.checkedTick = nowTick;
    if (candidates_.size() >= 4096) candidates_.clear();
    candidates_[pid] = decision;
    return facts;
}

bool EtwCollector::MayBelongToClient(DWORD pid, uint64_t nowFileTime)
{
    const uint64_t window = static_cast<uint64_t>(ETW_PENDING_MILLISECONDS) * 10000ULL;
    const uint64_t nowTick = GetTickCount64();
    auto cached = candidates_.find(pid);
    if (cached != candidates_.end() && cached->second.classified &&
        nowTick - cached->second.checkedTick < ETW_CANDIDATE_RECHECK_MILLISECONDS) {
        return cached->second.candidate && nowFileTime >= cached->second.facts.created &&
               nowFileTime - cached->second.facts.created <= window;
    }

    ProcessFacts node = FactsForPid(pid);
    CandidateDecision decision;
    decision.facts = node;
    decision.checkedTick = nowTick;
    decision.classified = true;
    if (node.ok && nowFileTime >= node.created && nowFileTime - node.created <= window) {
        for (int depth = 0; depth <= ETW_CANDIDATE_ANCESTOR_DEPTH; depth++) {
            if (std::any_of(scopeRoots_.begin(), scopeRoots_.end(),
                            [&](const std::wstring& root) { return UnderRoot(root, node.image); })) {
                decision.candidate = true;
                break;
            }
            if (node.parent == 0 || node.parent == 4) break;
            if (scope_.IsTracked(node.parent)) {
                decision.candidate = true;
                break;
            }
            ProcessFacts parent = QueryProcessFacts(node.parent);
            /* A parent created after its child is a reused PID, not the real parent. */
            if (!parent.ok || parent.created > node.created) break;
            node = std::move(parent);
        }
    }
    candidates_[pid] = decision;
    return decision.candidate;
}

EtwCollector::~EtwCollector()
{
    Stop();
}

ULONG WINAPI EtwCollector::BufferCallback(PEVENT_TRACE_LOGFILEW logfile)
{
    if (logfile != nullptr && logfile->Context != nullptr) {
        auto* self = static_cast<EtwCollector*>(logfile->Context);
        uint64_t lost = logfile->LogfileHeader.EventsLost;
        uint64_t current = self->lostEvents_.load();
        while (lost > current &&
               !self->lostEvents_.compare_exchange_weak(current, lost)) {
        }
    }
    return TRUE;
}

void EtwCollector::EnableProvider(const GUID& provider, const std::wstring& name, ULONGLONG anyKeyword,
                                  const std::vector<USHORT>& eventIds, bool stacks)
{
    ENABLE_TRACE_PARAMETERS parameters{};
    parameters.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
    parameters.EnableProperty = stacks ? EVENT_ENABLE_PROPERTY_STACK_TRACE : 0;

    /* An event-ID filter keeps a chatty provider's other events out of the session entirely. */
    std::vector<BYTE> filterBuffer;
    EVENT_FILTER_DESCRIPTOR filter{};
    if (!eventIds.empty()) {
        filterBuffer.resize(FIELD_OFFSET(EVENT_FILTER_EVENT_ID, Events) + eventIds.size() * sizeof(USHORT));
        auto* ids = reinterpret_cast<EVENT_FILTER_EVENT_ID*>(filterBuffer.data());
        ids->FilterIn = TRUE;
        ids->Count = static_cast<USHORT>(eventIds.size());
        std::memcpy(ids->Events, eventIds.data(), eventIds.size() * sizeof(USHORT));
        filter.Ptr = reinterpret_cast<ULONGLONG>(filterBuffer.data());
        filter.Size = static_cast<ULONG>(filterBuffer.size());
        filter.Type = EVENT_FILTER_TYPE_EVENT_ID;
        parameters.EnableFilterDesc = &filter;
        parameters.FilterDescCount = 1;
    }

    /*
     * Verbose with no keyword mask asks the provider for all events it can
     * produce.  Some useful providers emit events at verbose level or with a
     * zero keyword mask; the previous Information/all-bits request silently
     * excluded those.  The agent-side PID filter still limits what is written.
     */
    ULONG status = EnableTraceEx2(session_, &provider, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                  TRACE_LEVEL_VERBOSE, anyKeyword, 0, 0, &parameters);
    if (status != ERROR_SUCCESS && parameters.EnableProperty != 0) {
        parameters.EnableProperty = 0;
        status = EnableTraceEx2(session_, &provider, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                TRACE_LEVEL_VERBOSE, anyKeyword, 0, 0, &parameters);
    }
    if (status != ERROR_SUCCESS && parameters.FilterDescCount != 0) {
        /* Without the filter the agent still keeps only the listed events; it just receives more. */
        parameters.EnableFilterDesc = nullptr;
        parameters.FilterDescCount = 0;
        status = EnableTraceEx2(session_, &provider, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                TRACE_LEVEL_VERBOSE, anyKeyword, 0, 0, &parameters);
    }
    if (status != ERROR_SUCCESS) {
        warnings_.push_back(L"ETW provider unavailable: " + name + L" (Win32 " + std::to_wstring(status) + L")");
    }
}

bool EtwCollector::Start(std::string& error)
{
    loggerName_ = L"MsMon-Outside-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
                  std::to_wstring(GetTickCount64());
    properties_.resize(sizeof(EVENT_TRACE_PROPERTIES) + (loggerName_.size() + 1) * sizeof(wchar_t));
    auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(properties_.data());
    properties->Wnode.BufferSize = static_cast<ULONG>(properties_.size());
    properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    /*
     * ClientContext 2 = system time (100ns FILETIME).  The JSON writer decodes
     * EventHeader.TimeStamp as a FILETIME; the old value 3 (CPU cycle counter)
     * produced 1601-era timestamps for every ETW event.
     */
    properties->Wnode.ClientContext = 2;
    properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    ULONG status = StartTraceW(&session_, loggerName_.c_str(), properties);
    if (status != ERROR_SUCCESS) {
        error = "StartTrace failed with Win32 " + std::to_string(status);
        return false;
    }
    started_ = true;
    EnableProvider(WMI_ACTIVITY, L"Microsoft-Windows-WMI-Activity");
    EnableProvider(DNS_CLIENT, L"Microsoft-Windows-DNS-Client");
    EnableProvider(RPC_EVENTS, L"Microsoft-Windows-RPC");
    EnableProvider(TCPIP_EVENTS, L"Microsoft-Windows-TCPIP", TCPIP_KEYWORDS, TCPIP_EVENT_IDS, false);
    EnableProvider(CODE_INTEGRITY_EVENTS, L"Microsoft-Windows-CodeIntegrity", 0,
                   CODE_INTEGRITY_EVENT_IDS, false);

    EVENT_TRACE_LOGFILEW log{};
    log.LoggerName = loggerName_.data();
    log.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    log.EventRecordCallback = [](PEVENT_RECORD record) {
        static_cast<EtwCollector*>(record->UserContext)->OnRecord(record);
    };
    log.BufferCallback = EtwCollector::BufferCallback;
    log.Context = this;
    trace_ = OpenTraceW(&log);
    if (trace_ == INVALID_PROCESSTRACE_HANDLE) {
        error = "OpenTrace failed with Win32 " + std::to_string(GetLastError());
        Stop();
        return false;
    }
    worker_ = std::thread([this] {
        (void)ProcessTrace(&trace_, 1, nullptr, nullptr);
    });
    return true;
}

void EtwCollector::Stop()
{
    if (started_) {
        auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(properties_.data());
        (void)ControlTraceW(session_, loggerName_.c_str(), properties, EVENT_TRACE_CONTROL_STOP);
        started_ = false;
    }
    if (worker_.joinable()) worker_.join();
    if (trace_ != 0 && trace_ != INVALID_PROCESSTRACE_HANDLE) {
        (void)CloseTrace(trace_);
        trace_ = 0;
    }
    session_ = 0;
}
#endif

void EtwCollector::Emit(TelemetryEvent&& event)
{
    if (!event.stackAddresses.empty() && event.stackPid != 0) {
        event.modules = scope_.ResolveStack(event.stackPid, event.stackAddresses.data(),
                                            event.stackAddresses.size(), &event.stackUnresolved);
        if (!event.modules.empty()) event.header.Attribution = MsMonAttributionStackResolved;
    }
    /*
     * OnRecord runs on the ETW worker, while ReplayProcess/ExpirePending run
     * on the collector thread.  Assigning the sequence and pushing must be
     * one ordered operation, otherwise the writer can observe sequence 2
     * before sequence 1 and abort.
     */
    std::lock_guard<std::mutex> lock(emitMutex_);
    event.header.Sequence = sequence_.fetch_add(1) + 1;
    const int slot = ProviderIndex(event.header.Type);
    if (slot >= 0) emitted_[slot].fetch_add(1);
    queue_.Push(std::move(event));
}

#ifdef _WIN32
void EtwCollector::OnRecord(PEVENT_RECORD record)
{
    ULONG type;
    if (IsEqualGUID(record->EventHeader.ProviderId, WMI_ACTIVITY)) {
        type = MsMonEtwWmi;
    } else if (IsEqualGUID(record->EventHeader.ProviderId, DNS_CLIENT)) {
        type = MsMonEtwDns;
    } else if (IsEqualGUID(record->EventHeader.ProviderId, RPC_EVENTS)) {
        type = MsMonEtwRpc;
    } else if (IsEqualGUID(record->EventHeader.ProviderId, TCPIP_EVENTS)) {
        type = MsMonEtwTcp;
    } else if (IsEqualGUID(record->EventHeader.ProviderId, CODE_INTEGRITY_EVENTS)) {
        type = MsMonEtwCodeIntegrity;
    } else {
        return;
    }
    received_[ProviderIndex(type)].fetch_add(1);

    ULONG infoSize = 0;
    (void)TdhGetEventInformation(record, 0, nullptr, nullptr, &infoSize);
    if (infoSize == 0) {
        parseFailures_.fetch_add(1);
        return;
    }
    std::vector<BYTE> infoBuffer(infoSize);
    auto* info = reinterpret_cast<TRACE_EVENT_INFO*>(infoBuffer.data());
    if (TdhGetEventInformation(record, 0, nullptr, info, &infoSize) != ERROR_SUCCESS) {
        parseFailures_.fetch_add(1);
        return;
    }
    parsed_[ProviderIndex(type)].fetch_add(1);
    if (type == MsMonEtwTcp) {
        OnTcpRecord(record, info);
        return;
    }
    if (type == MsMonEtwCodeIntegrity) {
        OnCodeIntegrityRecord(record, info);
        return;
    }

    DWORD nativePid = record->EventHeader.ProcessId;
    DWORD attributedPid = nativePid;
    uint64_t number = 0;
    if (PropertyNumber(record, info, L"ClientProcessId", number) && number <= MAXDWORD) {
        attributedPid = static_cast<DWORD>(number);
    }

    TelemetryEvent event;
    event.source = "etw";
    event.header.Size = sizeof(event.header);
    event.header.Version = MSMON_PROTOCOL_VERSION;
    event.header.Type = type;
    event.header.Flags = MsMonFlagObserverRecord;
    event.header.Timestamp = static_cast<uint64_t>(record->EventHeader.TimeStamp.QuadPart);
    event.header.SessionId = sessionId_;
    event.header.ProcessId = attributedPid;
    event.header.ProcessStartTime = 0;
    event.header.ThreadId = record->EventHeader.ThreadId;
    event.header.Attribution = MsMonAttributionProcessOnly;
    event.header.Value0 = record->EventHeader.EventDescriptor.Id;
    if (nativePid != attributedPid) {
        event.header.Flags |= MsMonFlagServiceCorrelated;
        event.header.Attribution = MsMonAttributionServiceCorrelated;
    }

    std::wstring value;
    if (type == MsMonEtwWmi) {
        PropertyString(record, info, L"Namespace", event.text);
        if (event.text.empty()) PropertyString(record, info, L"NamespaceName", event.text);
        if (event.text.empty()) PropertyString(record, info, L"ProviderName", event.text);
        if (PropertyString(record, info, L"Operation", value)) AppendField(event.detail, L"operation", value);
        if (PropertyString(record, info, L"Query", value)) {
            AppendField(event.detail, L"query", capturePayloads_ ? value : SanitizeQuery(value));
        }
        if (PropertyString(record, info, L"QueryLanguage", value)) AppendField(event.detail, L"language", value);
        if (PropertyNumber(record, info, L"OperationId", number)) event.header.Value1 = number;
        if (PropertyNumber(record, info, L"StatusCode", number)) event.header.Status = static_cast<LONG>(number);
    } else if (type == MsMonEtwDns) {
        PropertyString(record, info, L"QueryName", event.text);
        if (PropertyNumber(record, info, L"QueryType", number)) {
            AppendField(event.detail, L"query_type", std::to_wstring(number));
        }
        if (PropertyNumber(record, info, L"QueryOptions", number)) {
            AppendField(event.detail, L"query_options", std::to_wstring(number));
        }
    } else {
        PropertyString(record, info, L"Endpoint", event.text);
        if (event.text.empty()) PropertyString(record, info, L"Protocol", event.text);
        bool hasOperation = false;
        for (const auto& property : RpcOpnumProperties()) {
            if (PropertyNumber(record, info, property, number)) {
                hasOperation = true;
                break;
            }
        }
        bool hasInterface = PropertyGuid(record, info, L"InterfaceUuid", value) ||
                            PropertyString(record, info, L"InterfaceUuid", value);
        if (hasOperation) AppendField(event.detail, L"op", std::to_wstring(number));
        if (hasInterface) {
            AppendField(event.detail, L"interface_uuid", value);
            std::wstring service;
            std::wstring method;
            if (hasOperation && RpcOperationName(value, number, service, method)) {
                AppendField(event.detail, L"interface", service);
                AppendField(event.detail, L"operation", method);
            } else {
                AppendField(event.detail, L"interface", value);
                if (hasOperation) AppendField(event.detail, L"operation", std::to_wstring(number));
            }
        } else if (hasOperation) {
            AppendField(event.detail, L"operation", std::to_wstring(number));
        }
    }

    /*
     * Retain raw stack addresses rather than resolving immediately.  If the
     * event is deferred until its process-start record arrives, image-load
     * records may also arrive in that window and make the stack resolvable.
     */
    for (USHORT index = 0; index < record->ExtendedDataCount; index++) {
        const auto& extended = record->ExtendedData[index];
        if (extended.DataSize < sizeof(uint64_t)) continue;
        if (extended.ExtType == EVENT_HEADER_EXT_TYPE_STACK_TRACE64) {
            const auto* stack = reinterpret_cast<const EVENT_EXTENDED_ITEM_STACK_TRACE64*>(extended.DataPtr);
            size_t count = (extended.DataSize - sizeof(uint64_t)) / sizeof(uint64_t);
            if (count > 256) count = 256;
            event.stackPid = nativePid;
            event.stackAddresses.assign(stack->Address, stack->Address + count);
        } else if (extended.ExtType == EVENT_HEADER_EXT_TYPE_STACK_TRACE32) {
            const auto* stack = reinterpret_cast<const EVENT_EXTENDED_ITEM_STACK_TRACE32*>(extended.DataPtr);
            size_t count = (extended.DataSize - sizeof(uint64_t)) / sizeof(uint32_t);
            if (count > 256) count = 256;
            event.stackPid = nativePid;
            event.stackAddresses.reserve(count);
            for (size_t frame = 0; frame < count; frame++) {
                event.stackAddresses.push_back(stack->Address[frame]);
            }
        }
    }

    /* An immediate emit is proof of identity, so it must not use the one-second
     * candidate cache: a PID reused inside that window would be attributed to
     * the old client. FactsForPid stays for MayBelongToClient only. */
    const ProcessFacts current = QueryProcessFacts(attributedPid);
    if (!current.ok || !scope_.IsTracked(attributedPid, current.created)) {
        FILETIME nowFileTime;
        ULARGE_INTEGER now;
        GetSystemTimeAsFileTime(&nowFileTime);
        now.LowPart = nowFileTime.dwLowDateTime;
        now.HighPart = nowFileTime.dwHighDateTime;
        if (!MayBelongToClient(attributedPid, now.QuadPart)) {
            /* Long-running or unrelated process: out of scope, as before. */
            return;
        }
        Defer(std::move(event), current.ok ? current.created : 0);
        return;
    }

    event.header.ProcessStartTime = current.created;
    Emit(std::move(event));
}

/* SOCKADDR_IN or SOCKADDR_IN6: little-endian family, then the port in network byte order. */
static std::wstring FormatSocketAddress(const std::vector<BYTE>& data)
{
    if (data.size() >= 8 && data[0] == 2 && data[1] == 0) {
        wchar_t text[32];
        swprintf_s(text, L"%u.%u.%u.%u:%u", static_cast<unsigned>(data[4]), static_cast<unsigned>(data[5]),
                   static_cast<unsigned>(data[6]), static_cast<unsigned>(data[7]),
                   static_cast<unsigned>((data[2] << 8) | data[3]));
        return text;
    }
    if (data.size() >= 24 && data[0] == 23 && data[1] == 0) {
        std::wstring text = L"[";
        for (size_t index = 0; index < 16; index += 2) {
            wchar_t group[8];
            swprintf_s(group, L"%x", static_cast<unsigned>((data[8 + index] << 8) | data[9 + index]));
            if (index != 0) text += L':';
            text += group;
        }
        return text + L"]:" + std::to_wstring((data[2] << 8) | data[3]);
    }
    return L"?";
}

void EtwCollector::OnTcpRecord(PEVENT_RECORD record, const TRACE_EVENT_INFO* info)
{
    const USHORT id = record->EventHeader.EventDescriptor.Id;
    const wchar_t* name = TcpEventName(id);
    if (name == nullptr) return;
    uint64_t number = 0;
    uint64_t tcb = 0;
    DWORD pid = 0;
    (void)PropertyNumber(record, info, L"Tcb", tcb);
    if (PropertyNumber(record, info, L"ProcessId", number) && number <= MAXDWORD) pid = static_cast<DWORD>(number);

    std::vector<BYTE> address;
    std::wstring endpoints;
    if (PropertyData(record, info, L"LocalAddress", address) || PropertyData(record, info, L"LocalSockAddr", address)) {
        endpoints = FormatSocketAddress(address) + L" -> ";
        if (PropertyData(record, info, L"RemoteAddress", address) || PropertyData(record, info, L"RemoteSockAddr", address)) {
            endpoints += FormatSocketAddress(address);
        } else {
            endpoints += L"?";
        }
    }

    /*
     * Connect and accept events name the owning process; later events for the
     * same connection often carry PID 0 (they run in system context) and the
     * FIN-delivery event carries no addresses, so the connection's TCB pointer
     * carries the owner and addresses forward.
     */
    DWORD ownerPid = 0;
    uint64_t ownerStart = 0;
    if (!ResolveTcpOwner(tcb, pid, QueryProcessFacts(pid), endpoints, ownerPid, ownerStart)) return;

    TelemetryEvent event;
    event.source = "etw";
    event.header.Size = sizeof(event.header);
    event.header.Version = MSMON_PROTOCOL_VERSION;
    event.header.Type = MsMonEtwTcp;
    event.header.Flags = MsMonFlagObserverRecord;
    event.header.Timestamp = static_cast<uint64_t>(record->EventHeader.TimeStamp.QuadPart);
    event.header.SessionId = sessionId_;
    event.header.ProcessId = ownerPid;
    event.header.ProcessStartTime = ownerStart;
    event.header.ThreadId = record->EventHeader.ThreadId;
    event.header.Attribution = MsMonAttributionProcessOnly;
    event.header.Value0 = id;
    event.header.Value1 = tcb;
    if (PropertyNumber(record, info, L"Status", number)) event.header.Status = static_cast<LONG>(number);
    event.text = endpoints.empty() ? L"?" : endpoints;
    event.detail = L"event=" + std::wstring(name);
    if (PropertyNumber(record, info, L"RexmitCount", number)) AppendField(event.detail, L"rexmit", std::to_wstring(number));
    if (PropertyNumber(record, info, L"Reason", number)) AppendField(event.detail, L"reason", std::to_wstring(number));
    Emit(std::move(event));
    if (TcpTerminalEvent(id)) ForgetTcpOwner(tcb);
}

void EtwCollector::OnCodeIntegrityRecord(PEVENT_RECORD record, const TRACE_EVENT_INFO* info)
{
    const USHORT id = record->EventHeader.EventDescriptor.Id;
    if (id != 3076 && id != 3077) return;

    TelemetryEvent event;
    event.source = "etw";
    event.header.Size = sizeof(event.header);
    event.header.Version = MSMON_PROTOCOL_VERSION;
    event.header.Type = MsMonEtwCodeIntegrity;
    event.header.Flags = MsMonFlagObserverRecord;
    event.header.Timestamp = static_cast<uint64_t>(record->EventHeader.TimeStamp.QuadPart);
    event.header.SessionId = sessionId_;
    event.header.ProcessId = record->EventHeader.ProcessId;
    event.header.ProcessStartTime = scope_.StartTime(event.header.ProcessId);
    event.header.ThreadId = record->EventHeader.ThreadId;
    event.header.Attribution = MsMonAttributionUnknown;
    event.header.Value0 = id;
    event.component = L"WDAC";
    event.detail = L"decision=" + std::wstring(id == 3076 ? L"would_block" : L"blocked") +
                   L";event_id=" + std::to_wstring(id);

    std::wstring value;
    if (PropertyString(record, info, L"File Name", event.text) ||
        PropertyString(record, info, L"FileNameBuffer", event.text) ||
        PropertyString(record, info, L"FileName", event.text) ||
        PropertyString(record, info, L"ImageName", event.text)) {
    }
    if (PropertyString(record, info, L"PolicyNameBuffer", value) ||
        PropertyString(record, info, L"PolicyName", value)) AppendField(event.detail, L"policy", value);
    if (PropertyString(record, info, L"PolicyID", value) ||
        PropertyString(record, info, L"PolicyIdBuffer", value) ||
        PropertyString(record, info, L"PolicyId", value)) AppendField(event.detail, L"policy_id", value);
    uint64_t number = 0;
    if (PropertyNumber(record, info, L"Status", number)) event.header.Status = static_cast<LONG>(number);
    Emit(std::move(event));
}

#endif

void EtwCollector::Defer(TelemetryEvent&& event, uint64_t created)
{
    const uint64_t deadline = GetTickCount64() + ETW_PENDING_MILLISECONDS;
    const int slot = ProviderIndex(event.header.Type);
    std::lock_guard<std::mutex> lock(pendingMutex_);
    if (pending_.size() >= ETW_PENDING_LIMIT) {
        pending_.pop_front();
        pendingOverflow_.fetch_add(1);
    }
    pending_.push_back({ std::move(event), created, deadline });
    if (slot >= 0) deferred_[slot].fetch_add(1);
}

size_t EtwCollector::ReplayProcess(DWORD pid)
{
    std::vector<TelemetryEvent> ready;
    {
        std::lock_guard<std::mutex> lock(pendingMutex_);
        for (auto it = pending_.begin(); it != pending_.end();) {
            /* Only the incarnation the event was captured for may release it:
             * a reused PID must not inherit another process's deferred event. */
            if (it->event.header.ProcessId != pid || it->created == 0 ||
                !scope_.IsTracked(pid, it->created)) {
                ++it;
                continue;
            }
            if (it->event.header.ProcessStartTime == 0) it->event.header.ProcessStartTime = it->created;
            ready.push_back(std::move(it->event));
            it = pending_.erase(it);
        }
    }
    const size_t emitted = ready.size();
    for (auto& event : ready) Emit(std::move(event));
    return emitted;
}

bool EtwCollector::RememberTcpOwner(uint64_t tcb, DWORD pid, uint64_t created,
                                    const std::wstring& endpoints)
{
    if (tcb == 0 || pid == 0 || created == 0 || !scope_.IsTracked(pid, created)) return false;
    if (tcbConnections_.size() >= 16384) tcbConnections_.clear();
    auto& connection = tcbConnections_[tcb];
    connection.pid = pid;
    connection.created = created;
    if (!endpoints.empty()) connection.endpoints = endpoints;
    return true;
}

void EtwCollector::ForgetTcpOwner(uint64_t tcb)
{
    tcbConnections_.erase(tcb);
}

bool EtwCollector::TcpOwner(uint64_t tcb, DWORD& pid, uint64_t& created, std::wstring& endpoints) const
{
    auto found = tcb != 0 ? tcbConnections_.find(tcb) : tcbConnections_.end();
    if (found == tcbConnections_.end()) return false;
    /* The cached owner must still be the tracked incarnation, not a reused PID. */
    if (found->second.created == 0 ||
        !scope_.IsTracked(found->second.pid, found->second.created)) {
        return false;
    }
    pid = found->second.pid;
    created = found->second.created;
    endpoints = found->second.endpoints;
    return true;
}

bool EtwCollector::ResolveTcpOwner(uint64_t tcb, DWORD providerPid, const ProcessFacts& facts,
                                   std::wstring& endpoints, DWORD& pid, uint64_t& created)
{
    const uint64_t providerStart = facts.ok ? facts.created : 0;
    if (providerPid != 0 && tcb != 0) {
        (void)RememberTcpOwner(tcb, providerPid, providerStart, endpoints);
    }
    if (providerPid != 0) {
        if (providerStart != 0 && scope_.IsTracked(providerPid, providerStart)) {
            pid = providerPid;
            created = providerStart;
            return true;
        }
        /* The record names a process that is not the validated client.  Do not
         * let it borrow the cached owner of another connection that happened to
         * reuse this TCB address, and drop the stale mapping. */
        ForgetTcpOwner(tcb);
        return false;
    }
    DWORD cachedPid = 0;
    uint64_t cachedStart = 0;
    std::wstring cachedEndpoints;
    if (!TcpOwner(tcb, cachedPid, cachedStart, cachedEndpoints)) return false;
    pid = cachedPid;
    created = cachedStart;
    if (endpoints.empty()) endpoints = cachedEndpoints;
    return true;
}

void EtwCollector::ExpirePending(uint64_t nowTick)
{
    std::vector<TelemetryEvent> expired;
    {
        std::lock_guard<std::mutex> lock(pendingMutex_);
        for (auto it = pending_.begin(); it != pending_.end();) {
            if (it->deadline <= nowTick) {
                expired.push_back(std::move(it->event));
                it = pending_.erase(it);
            } else {
                ++it;
            }
        }
    }
    for (auto& original : expired) {
        const int slot = ProviderIndex(original.header.Type);
        if (slot >= 0) expired_[slot].fetch_add(1);
        TelemetryEvent event;
        event.source = "etw";
        event.header.Size = sizeof(event.header);
        event.header.Version = MSMON_PROTOCOL_VERSION;
        event.header.Type = MsMonEtwUnattributed;
        event.header.Flags = MsMonFlagObserverRecord;
        event.header.Timestamp = original.header.Timestamp;
        event.header.SessionId = sessionId_;
        event.header.ProcessId = original.header.ProcessId;
        event.header.ThreadId = original.header.ThreadId;
        event.header.Value0 = original.header.Type;
        event.header.Value1 = original.header.Value0;
        event.header.Attribution = MsMonAttributionUnknown;
        event.text = ProviderName(original.header.Type);
        event.detail = L"reason=no_process_start;event_id=" + std::to_wstring(original.header.Value0) +
                       L";original_pid=" + std::to_wstring(original.header.ProcessId);
        event.outsideClient = true;
        Emit(std::move(event));
        unattributed_.fetch_add(1);
    }
}

uint64_t EtwCollector::PendingCount() const
{
    std::lock_guard<std::mutex> lock(pendingMutex_);
    return static_cast<uint64_t>(pending_.size());
}

std::wstring EtwCollector::ProviderName(unsigned long type) const
{
    switch (type) {
    case MsMonEtwWmi: return L"Microsoft-Windows-WMI-Activity";
    case MsMonEtwDns: return L"Microsoft-Windows-DNS-Client";
    case MsMonEtwRpc: return L"Microsoft-Windows-RPC";
    case MsMonEtwTcp: return L"Microsoft-Windows-TCPIP";
    case MsMonEtwCodeIntegrity: return L"Microsoft-Windows-CodeIntegrity";
    default: return L"unknown";
    }
}
