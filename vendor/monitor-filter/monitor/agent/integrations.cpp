#include "integrations.h"
#include <memory>
#include <new>
#include <sstream>

#ifndef _WIN32
#include <sys/socket.h>
#include <sys/un.h>

static std::wstring ErrnoText(int error)
{
    const char* name = strerrorname_np(error);
    return L"errno " + std::to_wstring(error) + (name != nullptr ? L" " + LinuxWide(name) : L"");
}

static bool SendAll(int fd, const void* data, size_t size)
{
    const char* cursor = static_cast<const char*>(data);
    while (size != 0) {
        ssize_t sent = send(fd, cursor, size, MSG_NOSIGNAL);
        if (sent < 0 && errno == EINTR) continue;
        if (sent <= 0) return false;
        cursor += sent;
        size -= static_cast<size_t>(sent);
    }
    return true;
}

static bool ReceiveAll(int fd, void* data, size_t size)
{
    char* cursor = static_cast<char*>(data);
    while (size != 0) {
        ssize_t got = recv(fd, cursor, size, 0);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) {
            if (got == 0) errno = ECONNRESET;
            return false;
        }
        cursor += got;
        size -= static_cast<size_t>(got);
    }
    return true;
}

/* A fresh connection per request works whether or not kfilterd keeps connections open. */
bool KFilterReader::Call(uint32_t code, const void* input, uint32_t inputLength, void* output, uint32_t capacity,
                         uint32_t& bytes, std::wstring& error)
{
    bytes = 0;
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        error = ErrnoText(errno);
        return false;
    }
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    std::strncpy(address.sun_path, KFILTER_SOCKET_PATH, sizeof(address.sun_path) - 1);
    KFILTER_SOCKET_REQUEST request{code, inputLength, capacity, 0};
    KFILTER_SOCKET_REPLY reply{};
    bool ok = connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0 &&
              SendAll(fd, &request, sizeof(request)) &&
              (inputLength == 0 || SendAll(fd, input, inputLength)) &&
              ReceiveAll(fd, &reply, sizeof(reply));
    if (!ok) {
        error = ErrnoText(errno) + L";path=" + LinuxWide(KFILTER_SOCKET_PATH);
    } else if (reply.Error != 0) {
        error = L"kfilterd " + ErrnoText(static_cast<int>(reply.Error));
        ok = false;
    } else if (reply.OutputLength > capacity) {
        error = L"oversized reply";
        ok = false;
    } else if (reply.OutputLength != 0 && !ReceiveAll(fd, output, reply.OutputLength)) {
        error = ErrnoText(errno);
        ok = false;
    } else {
        bytes = reply.OutputLength;
    }
    close(fd);
    return ok;
}
#endif


static std::wstring HexValue(unsigned long value)
{
    wchar_t buffer[16];
    swprintf_s(buffer, L"0x%08lX", value);
    return buffer;
}

/* A fixed wchar_t array from kfilter: bounded, as a full array has no terminator. */
template <size_t N>
static std::wstring Bounded(const wchar_t (&value)[N])
{
    return std::wstring(value, wcsnlen(value, N));
}

static const wchar_t* KFilterTargetName(unsigned long target)
{
    switch (target) {
    case KFILTER_TARGET_FILE: return L"file";
    case KFILTER_TARGET_DIR: return L"dir";
    case KFILTER_TARGET_REGISTRY: return L"registry";
    case KFILTER_TARGET_PROCESS: return L"process";
    case KFILTER_TARGET_VOLUME: return L"volume";
    case KFILTER_TARGET_DEVICE: return L"device";
    case KFILTER_TARGET_PIPE: return L"pipe";
    case KFILTER_TARGET_NETWORK: return L"network";
    case KFILTER_TARGET_HANDLE: return L"handle";
    case KFILTER_TARGET_LAUNCH: return L"launch";
    case KFILTER_TARGET_OPEN: return L"open";
    case KFILTER_TARGET_THREAD_HANDLE: return L"thread-handle";
    case KFILTER_TARGET_THREAD_OPEN: return L"thread-open";
    case KFILTER_TARGET_PEER: return L"peer";
    case KFILTER_TARGET_THREAD_PEER: return L"thread-peer";
    case KFILTER_TARGET_SYSTEM: return L"system";
    case KFILTER_TARGET_DNS: return L"dns";
    case KFILTER_TARGET_THREAD: return L"thread";
    default: return L"unknown";
    }
}

static const wchar_t* KFilterActionName(unsigned long action)
{
    switch (action) {
    case KFilterActionAudit: return L"audit";
    case KFilterActionAllow: return L"allow";
    case KFilterActionDeny: return L"deny";
    case KFilterActionRisk: return L"RISK";
    default: return L"unknown";
    }
}

/* kfilterctl's rights names (tool/kfilterctl.cpp RightsText), so rule text reads like the policy. */
static std::wstring RightsText(unsigned long rights)
{
    static const struct { unsigned long bit; const wchar_t* name; } names[] = {
        {KFILTER_RIGHT_READ, L"read"}, {KFILTER_RIGHT_WRITE, L"write"}, {KFILTER_RIGHT_EXECUTE, L"execute"},
        {KFILTER_RIGHT_DELETE, L"delete"}, {KFILTER_RIGHT_RENAME, L"rename"},
        {KFILTER_RIGHT_SET_SECURITY, L"set-security"}, {KFILTER_RIGHT_ENUMERATE, L"enumerate"},
        {KFILTER_RIGHT_QUERY, L"query"}, {KFILTER_RIGHT_CREATE, L"create"}, {KFILTER_RIGHT_CONNECT, L"connect"},
        {KFILTER_RIGHT_LISTEN, L"listen"}, {KFILTER_RIGHT_RAW_DEVICE, L"raw-device"}, {KFILTER_RIGHT_OPEN, L"open"},
        {KFILTER_RIGHT_SEND, L"send"}, {KFILTER_RIGHT_RECEIVE, L"receive"}, {KFILTER_RIGHT_LOCK, L"lock"},
        {KFILTER_RIGHT_CHDIR, L"chdir"}, {KFILTER_RIGHT_TOUCH, L"touch"},
    };
    std::wstring text;
    for (const auto& entry : names) {
        if ((rights & entry.bit) != 0) text += (text.empty() ? L"" : L",") + std::wstring(entry.name);
    }
    return text;
}

/* Value holds a Windows process/thread access mask on these targets, not kfilter rights. */
static bool AccessMaskTarget(unsigned long target)
{
    return ((target & KFILTER_TARGETS_OUTSIDE) != 0 && target != KFILTER_TARGET_LAUNCH) ||
           target == KFILTER_TARGET_PEER || target == KFILTER_TARGET_THREAD_PEER;
}

static std::wstring CountText(unsigned long count)
{
    if (count == 0) return L"";
    return L" uses=" + std::to_wstring((count & KFILTER_COUNT_USES) >> KFILTER_COUNT_USES_SHIFT) +
           L" phase=" + std::to_wstring(count & KFILTER_COUNT_PHASE) +
           ((count & KFILTER_COUNT_OPENS) != 0 ? L" opens" : L"");
}

/* An addr= rule's ranges as kfilterctl prints them: absolute, or after the module of Value's list they name. */
static std::wstring AddressText(const KFILTER_RULE& rule)
{
    std::vector<std::wstring> modules;
    std::wstringstream list(Bounded(rule.Value));
    for (std::wstring module; std::getline(list, module, L',');) modules.push_back(module);
    std::wstring text;
    for (unsigned long index = 0; index < rule.AddressCount && index < KFILTER_MAX_ADDRESS; index++) {
        const unsigned module = rule.AddressModule[index];
        wchar_t range[48];
        swprintf_s(range, L"0x%llx-0x%llx", static_cast<unsigned long long>(rule.Address[index].Low),
                   static_cast<unsigned long long>(rule.Address[index].High));
        text += (index != 0 ? L"," : L"") + (module != 0 && module <= modules.size() ? modules[module - 1] + L"+" : L"") + range;
    }
    return text;
}

std::wstring KFilterRuleText(const KFILTER_RULE& rule)
{
    std::wstring text = std::wstring(KFilterActionName(rule.Action)) + L" " + KFilterTargetName(rule.Targets) +
                        L" " + Bounded(rule.Path);
    text += AccessMaskTarget(rule.Targets) ? L" access=" + HexValue(rule.Rights) : L" rights=" + RightsText(rule.Rights);
    if ((rule.Flags & KFILTER_RULE_ADDRESS) != 0) text += L" addr=" + AddressText(rule);
    else if (rule.Value[0] != L'\0') text += ((rule.Flags & KFILTER_RULE_MODULE) != 0 ? L" module=" : L" value=") + Bounded(rule.Value);
    if (rule.Image[0] != L'\0') text += L" image=" + Bounded(rule.Image);
    if (rule.Risk[0] != L'\0') text += L" risk=" + Bounded(rule.Risk);
    if (rule.Extensions != 0) text += L" ext=" + HexValue(rule.Extensions);
    if (rule.Account == KFILTER_ACCOUNT_SYSTEM) text += L" account=system";
    if ((rule.Flags & KFILTER_RULE_EXACT) != 0) text += L" exact";
    if ((rule.Flags & KFILTER_RULE_HIDE) != 0) text += L" hide";
    return text + CountText(rule.Count);
}

std::wstring KFilterNetRuleText(const KFILTER_NET_RULE& rule)
{
    std::wstring address;
    wchar_t part[8];
    if (rule.Family == 4) {
        for (int index = 0; index < 4; index++) {
            swprintf_s(part, L"%u", static_cast<unsigned>(rule.Address[index]));
            address += (index != 0 ? L"." : L"") + std::wstring(part);
        }
    } else if (rule.Family == 6) {
        for (int index = 0; index < 16; index += 2) {
            swprintf_s(part, L"%x", static_cast<unsigned>(rule.Address[index] << 8 | rule.Address[index + 1]));
            address += (index != 0 ? L":" : L"") + std::wstring(part);
        }
    } else if (rule.Family == KFILTER_NET_FAMILY_UNIX) {
        address = L"unix=" + Bounded(rule.Unix);   /* a send to an AF_UNIX peer (ABI 12) */
    } else {
        address = L"any";
    }
    std::wstring text = std::wstring(KFilterActionName(rule.Action)) + L" network " + address;
    if (rule.Family == 4 || rule.Family == 6) text += L"/" + std::to_wstring(rule.PrefixLength);
    if (rule.Protocol != 0) text += rule.Protocol == 6 ? L" tcp" : rule.Protocol == 17 ? L" udp" :
                                    L" proto=" + std::to_wstring(rule.Protocol);
    if (rule.Port != 0) text += L" port=" + std::to_wstring(rule.Port);
    text += L" rights=" + (rule.Rights != 0 ? RightsText(rule.Rights) : std::wstring(L"connect,listen"));
    if (rule.Image[0] != L'\0') text += L" image=" + Bounded(rule.Image);
    if (rule.Risk[0] != L'\0') text += L" risk=" + Bounded(rule.Risk);
    if (rule.SizeMax != 0) text += L" size=" + std::to_wstring(rule.SizeMin) + L"-" + std::to_wstring(rule.SizeMax);
    if (rule.IndexMax != 0) text += L" index=" + std::to_wstring(rule.IndexMin) + L"-" + std::to_wstring(rule.IndexMax);
    if (rule.MatchLength != 0) {
        text += L" match=";
        for (unsigned long index = 0; index < rule.MatchLength && index < KFILTER_MAX_MATCH; index++) {
            swprintf_s(part, L"%02X", static_cast<unsigned>(rule.Match[index]));
            text += part;
        }
        text += L"@" + std::to_wstring(rule.MatchOffset);
    }
    if (rule.Module[0] != L'\0') text += L" module=" + Bounded(rule.Module);
    return text + CountText(rule.Count);
}

const wchar_t* KFilterDecisionName(const KFILTER_EVENT& event)
{
    switch (event.Action) {
    case KFilterActionAllow: return L"allow";
    case KFilterActionDeny: return L"deny";
    case KFilterActionRisk: return L"risk";
    case KFilterActionAudit: return (event.Flags & KFILTER_EVENT_FLAG_WOULD_DENY) != 0 ? L"would_deny" : L"audit";
    default: return L"unknown";
    }
}

/* A Windows access mask (a handle crossing) or a refusal code, not kfilter rights: every
 * outside target but LAUNCH, and a PROCESS decision that is not a process start. */
static bool AccessMaskDecision(const KFILTER_EVENT& event)
{
    return AccessMaskTarget(event.Target) ||
           (event.Target == KFILTER_TARGET_PROCESS && (event.Flags & KFILTER_EVENT_FLAG_PROCESS_CREATE) == 0);
}

bool KFilterDecisionNamesFamily(const KFILTER_EVENT& event)
{
    if (event.ProcessId == 0) return false;
    /* Handle crossings are logged in the requester's context, and a DuplicateHandle caller may be
     * an outside process (object.c, kb_handle_request); a broker launches for the client. */
    if (AccessMaskDecision(event) || event.Target == KFILTER_TARGET_LAUNCH) return false;
    if ((event.Flags & KFILTER_EVENT_FLAG_PROCESS_CREATE) != 0) {
#ifdef _WIN32
        return false;   /* logged in the creator's context: ProcessId is not the new process */
#else
        return event.Action != KFilterActionDeny;   /* a refused exec leaves an outside program outside */
#endif
    }
    return true;
}

TelemetryEvent KFilterDecisionEvent(const KFILTER_EVENT& source, uint64_t sessionId, uint64_t sequence,
                                    const std::wstring& ruleText)
{
    TelemetryEvent event;
    event.source = "agent";
    event.header.Size = sizeof(event.header);
    event.header.Version = MSMON_PROTOCOL_VERSION;
    event.header.Type = MsMonKfilterDecision;
    event.header.Flags = MsMonFlagObserverRecord;
    event.header.Sequence = sequence;
    event.header.Timestamp = source.Timestamp;
    event.header.SessionId = sessionId;
    event.header.ProcessId = source.ProcessId;
    event.header.Status = source.Status;
    event.header.DesiredAccess = source.Value;
    event.header.Attribution = MsMonAttributionUnknown;
    event.header.Value0 = source.Target;
    event.header.Value1 = source.RuleId;
    event.component = L"kfilter.sys";
    event.text = Bounded(source.Path);

    const unsigned long flags = source.Flags;
    const bool message = (flags & KFILTER_EVENT_FLAG_MESSAGE) != 0;
    const std::wstring decision = KFilterDecisionName(source);
    const std::wstring target = KFilterTargetName(source.Target);
    const std::wstring layer = message ? L"message" :
                               (flags & KFILTER_EVENT_FLAG_PROCESS_CREATE) != 0 ? L"process_create" : target;
    /* Value: a device decision's IOCTL, a message's byte count, a network decision's remote port
     * (RISK: the right), a handle crossing's access mask, otherwise the requested rights. */
    std::wstring value;
    if (source.Target == KFILTER_TARGET_DEVICE) {
        value = L";ioctl=" + HexValue(source.Value);
    } else if (message) {
        value = L";bytes=" + std::to_wstring(source.Value);
    } else if (source.Target == KFILTER_TARGET_NETWORK && source.Action != KFilterActionRisk) {
        value = L";port=" + std::to_wstring(source.Value);
    } else if (AccessMaskDecision(source)) {
        value = L";access=" + HexValue(source.Value);
    } else {
        value = L";rights=" + HexValue(source.Value) + L";rights_names=" + RightsText(source.Value);
    }
    /* The program's file name may hold ';' or '=': percent-encoded so it cannot forge a field. */
    std::wstring image;
    for (wchar_t ch : Bounded(source.Image)) {
        image += ch == L'%' ? L"%25" : ch == L';' ? L"%3B" : ch == L'=' ? L"%3D" : std::wstring(1, ch);
    }
    static const struct { unsigned long bit; const wchar_t* name; } flagNames[] = {
        {KFILTER_EVENT_FLAG_WOULD_DENY, L"would_deny"}, {KFILTER_EVENT_FLAG_NAME_FAILURE, L"name_failure"},
        {KFILTER_EVENT_FLAG_MISSING_CONTEXT, L"missing_context"}, {KFILTER_EVENT_FLAG_NETWORK, L"network"},
        {KFILTER_EVENT_FLAG_PROCESS_CREATE, L"process_create"}, {KFILTER_EVENT_FLAG_MEMORY_READ, L"memory_read"},
        {KFILTER_EVENT_FLAG_MEMORY_DUP, L"memory_dup"}, {KFILTER_EVENT_FLAG_COUNTED, L"counted"},
        {KFILTER_EVENT_FLAG_REPEAT, L"repeat"}, {KFILTER_EVENT_FLAG_EXHAUSTED, L"exhausted"},
        {KFILTER_EVENT_FLAG_RISK, L"risk"}, {KFILTER_EVENT_FLAG_BROKERED, L"brokered"},
        {KFILTER_EVENT_FLAG_MESSAGE, L"message"}, {KFILTER_EVENT_FLAG_DIRECT, L"direct"},
    };
    std::wstring names;
    for (const auto& entry : flagNames) {
        if ((flags & entry.bit) != 0) names += (names.empty() ? L"" : L"|") + std::wstring(entry.name);
    }
    /* Under REPEAT, Generation is the number of identical decisions collapsed into this one. */
    const bool repeat = (flags & KFILTER_EVENT_FLAG_REPEAT) != 0;
    /* Fixed keys first (schema/event-v1.json checks them); rule= is last: rule text may hold ';'. */
    event.detail = L"action=" + decision +
                   L";layer=" + layer +
                   L";target=" + target +
                   L";rule_id=" + std::to_wstring(source.RuleId) +
                   value +
                   L";image=" + image +
                   L";pid=" + std::to_wstring(source.ProcessId) +
                   L";brokered=" + ((flags & KFILTER_EVENT_FLAG_BROKERED) != 0 ? L"1" : L"0") +
                   (repeat ? L";repeat=" : L";generation=") + std::to_wstring(source.Generation) +
                   L";decision=" + decision +
                   L";kfilter_action=" + KFilterActionName(source.Action) +
                   L";target_id=" + std::to_wstring(source.Target) +
                   L";action_id=" + std::to_wstring(source.Action) +
                   L";flags=" + HexValue(flags) +
                   L";flags_names=" + names +
                   L";rule=" + ruleText;
    return event;
}

std::wstring KFilterStatusDetail(const KFILTER_STATUS& status, const KFILTER_STATUS* start)
{
    const wchar_t* mode = status.Mode == KFILTER_MODE_OFF ? L"off" : status.Mode == KFILTER_MODE_AUDIT ? L"audit" :
                          status.Mode == KFILTER_MODE_BLOCK ? L"block" : L"unknown";
    const uint64_t droppedDelta = start != nullptr && status.DroppedEvents >= start->DroppedEvents ?
        status.DroppedEvents - start->DroppedEvents : 0;
    std::wstring detail = L"abi=" + std::to_wstring(status.AbiVersion) +
                          L";mode=" + mode +
                          L";mode_id=" + std::to_wstring(status.Mode) +
                          L";flags=" + HexValue(status.Flags) +
                          L";rules=" + std::to_wstring(status.RuleCount) +
                          L";network_rules=" + std::to_wstring(status.NetworkRuleCount) +
                          L";protected=" + std::to_wstring(status.ProtectedCount) +
                          L";tracked=" + std::to_wstring(status.TrackedProcesses) +
                          L";policy_generation=" + std::to_wstring(status.PolicyGeneration) +
                          L";session_tag=" + std::to_wstring(status.SessionTag) +
                          L";allowed=" + std::to_wstring(status.Allowed) +
                          L";denied=" + std::to_wstring(status.Denied) +
                          L";audited=" + std::to_wstring(status.Audited) +
                          L";would_deny=" + std::to_wstring(status.WouldDeny) +
                          L";name_failures=" + std::to_wstring(status.NameFailures) +
                          L";missing_contexts=" + std::to_wstring(status.MissingContexts) +
                          L";sid_failures=" + std::to_wstring(status.SidFailures) +
                          L";dropped_events=" + std::to_wstring(status.DroppedEvents) +
                          L";dropped_delta=" + std::to_wstring(droppedDelta) +
                          L";registered=" + HexValue(status.Registered) +
                          L";degraded=" + HexValue(status.Degraded);
    /* A different tag: kfilter restarted, so its counters (and the ring) started over. */
    if (start != nullptr && start->SessionTag != status.SessionTag) detail += L";session_changed=1";
    return detail;
}

std::wstring IntegrationCoverageState(bool etwEnabled, const std::wstring& kfilterState)
{
    return std::wstring(etwEnabled ? L"etw=wmi,dns,rpc,tcp,codeintegrity" : L"etw=disabled") +
           L";kfilter=" + kfilterState +
           L";wdac=" + (etwEnabled ? L"etw" : L"disabled");
}

bool KFilterDecisionInSession(const KFILTER_EVENT& event, uint64_t sessionStart)
{
    return event.Timestamp >= sessionStart;
}

KFilterReader::KFilterReader(uint64_t sessionId, uint64_t sessionStart)
    : sessionId_(sessionId), sessionStart_(sessionStart) {}

KFilterReader::~KFilterReader()
{
    Close();
}

void KFilterReader::Close()
{
#ifdef _WIN32
    if (handle_ != INVALID_HANDLE_VALUE) {
        CloseHandle(handle_);
        handle_ = INVALID_HANDLE_VALUE;
    }
#else
    open_ = false;
#endif
}

bool KFilterReader::Status(KFILTER_STATUS& status, std::wstring& error)
{
    status = {};
#ifdef _WIN32
    DWORD bytes = 0;
    if (handle_ == INVALID_HANDLE_VALUE ||
        !DeviceIoControl(handle_, KFILTER_IOCTL_GET_STATUS, nullptr, 0,
                         &status, sizeof(status), &bytes, nullptr)) {
        error = L"Win32 " + std::to_wstring(GetLastError());
        return false;
    }
#else
    uint32_t bytes = 0;
    if (!open_) {
        error = L"not open";
        return false;
    }
    if (!Call(KFILTER_OP_GET_STATUS, nullptr, 0, &status, sizeof(status), bytes, error)) return false;
#endif
    if (bytes != sizeof(status)) {
        error = L"short status response";
        return false;
    }
    return true;
}

void KFilterReader::SetRules(const KFILTER_CONFIG& config)
{
    rules_.clear();
    for (ULONG index = 0; index < config.RuleCount; index++) {
        rules_[config.Rules[index].RuleId] = KFilterRuleText(config.Rules[index]);
    }
    for (ULONG index = 0; index < config.NetworkRuleCount; index++) {
        rules_[config.Network[index].RuleId] = KFilterNetRuleText(config.Network[index]);
    }
    rulesGeneration_ = config.Generation;
}

bool KFilterReader::LoadRules(std::wstring& error)
{
    KFILTER_STATUS status{};
    if (!Status(status, error)) return false;
    if (status.RuleCount > KFILTER_MAX_RULES) {
        error = L"invalid rule count";
        return false;
    }
    /* Only the rules in use come back: KFILTER_CONFIG_SIZE(RuleCount) bytes, Rules[] last. */
    const size_t capacity = KFILTER_CONFIG_SIZE(status.RuleCount);
    std::unique_ptr<unsigned char[]> buffer(new (std::nothrow) unsigned char[capacity]);
    if (!buffer) {
        error = L"no memory for the policy";
        return false;
    }
#ifdef _WIN32
    DWORD bytes = 0;
    if (!DeviceIoControl(handle_, KFILTER_IOCTL_GET_CONFIG, nullptr, 0, buffer.get(), static_cast<DWORD>(capacity),
                         &bytes, nullptr)) {
        error = L"Win32 " + std::to_wstring(GetLastError());
        return false;
    }
#else
    uint32_t bytes = 0;
    if (!Call(KFILTER_OP_GET_CONFIG, nullptr, 0, buffer.get(), static_cast<uint32_t>(capacity), bytes, error)) {
        return false;
    }
#endif
    const KFILTER_CONFIG* config = reinterpret_cast<const KFILTER_CONFIG*>(buffer.get());
    if (bytes < KFILTER_CONFIG_SIZE(0) || config->RuleCount > KFILTER_MAX_RULES ||
        bytes < KFILTER_CONFIG_SIZE(config->RuleCount) || config->NetworkRuleCount > KFILTER_MAX_NET_RULES) {
        error = L"invalid policy response";
        return false;
    }
    SetRules(*config);
    return true;
}

bool KFilterReader::Open(KFILTER_STATUS& status, std::wstring& state, std::wstring& detail)
{
#ifdef _WIN32
    handle_ = CreateFileW(L"\\\\.\\KFilter", GENERIC_READ, 0, nullptr, OPEN_EXISTING,
                          FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle_ == INVALID_HANDLE_VALUE) {
        state = L"kfilter_unavailable";
        detail = L"Win32 " + std::to_wstring(GetLastError());
        return false;
    }
#else
    open_ = true;
#endif
    std::wstring error;
    if (!Status(status, error)) {
        state = L"kfilter_unavailable";
        detail = std::move(error);
        Close();
        return false;
    }
    if (status.AbiVersion != KFILTER_ABI_VERSION) {
        state = L"kfilter_unsupported";
        detail = L"abi=" + std::to_wstring(status.AbiVersion) + L";required=" + std::to_wstring(KFILTER_ABI_VERSION);
        Close();
        return false;
    }
    state = L"kfilter_available";
    detail = KFilterStatusDetail(status, nullptr);
#ifndef _WIN32
    /* kfilterd: become the ring's only reader (READ_EVENTS pops); the tag set by monfilter stays. */
    KFILTER_SESSION_REQUEST own{0, KFILTER_SESSION_OWN_EVENTS, 0};
    uint32_t ownBytes = 0;
    if (!Call(KFILTER_OP_SET_SESSION, &own, sizeof(own), nullptr, 0, ownBytes, error)) {
        detail += L";ring_owner=unclaimed;ring_owner_error=" + error;
    }
#endif
    /* Rule text is a convenience: decisions are still read without it. */
    if (!LoadRules(error)) detail += L";rule_text=unavailable;rule_text_error=" + error;
    return true;
}

void KFilterReader::ConvertBatch(const KFILTER_EVENT* batch, unsigned count, std::vector<TelemetryEvent>& events,
                                 std::vector<KFilterFamilyProcess>* family)
{
    for (unsigned index = 0; index < count; index++) {
        const KFILTER_EVENT& source = batch[index];
        /* Stale decisions from an earlier run are neither written nor numbered. */
        if (!KFilterDecisionInSession(source, sessionStart_)) continue;
        /* A REPEAT summary's Generation is a count: its rule text comes from the policy held now. */
        const bool repeat = (source.Flags & KFILTER_EVENT_FLAG_REPEAT) != 0;
        std::wstring ruleText;
        if (source.RuleId != 0 && (repeat || source.Generation == rulesGeneration_)) {
            auto found = rules_.find(source.RuleId);
            if (found != rules_.end()) ruleText = found->second;
        }
        events.push_back(KFilterDecisionEvent(source, sessionId_, ++sequence_, ruleText));
        if (family != nullptr && KFilterDecisionNamesFamily(source)) {
            family->push_back({static_cast<DWORD>(source.ProcessId), source.Timestamp});
        }
    }
}

bool KFilterReader::Drain(std::vector<TelemetryEvent>& events, std::vector<KFilterFamilyProcess>& family,
                          std::wstring& error)
{
    /* 512 per read; at most four rings' worth per pass so the driver reader is never starved. */
    if (buffer_.empty()) buffer_.resize(512);
    unsigned total = 0;
    bool reloaded = false;
    for (;;) {
        KFILTER_READ_REQUEST request{};
        request.MaximumEvents = static_cast<KF_ULONG>(buffer_.size());
        const uint32_t capacity = static_cast<uint32_t>(buffer_.size() * sizeof(KFILTER_EVENT));
#ifdef _WIN32
        DWORD bytes = 0;
        if (!DeviceIoControl(handle_, KFILTER_IOCTL_READ_EVENTS, &request, sizeof(request),
                             buffer_.data(), capacity, &bytes, nullptr)) {
            error = L"Win32 " + std::to_wstring(GetLastError());
            return false;
        }
#else
        uint32_t bytes = 0;
        if (!Call(KFILTER_OP_READ_EVENTS, &request, sizeof(request), buffer_.data(), capacity, bytes, error)) {
            return false;
        }
#endif
        if (bytes % sizeof(KFILTER_EVENT) != 0) {
            error = L"invalid event response size";
            return false;
        }
        const unsigned count = bytes / sizeof(KFILTER_EVENT);
        /* A new policy generation: fetch its rule text once per pass (a failure is retried only
         * when yet another generation appears). */
        for (unsigned index = 0; !reloaded && index < count; index++) {
            const KFILTER_EVENT& event = buffer_[index];
            if ((event.Flags & KFILTER_EVENT_FLAG_REPEAT) == 0 && event.Generation != rulesGeneration_ &&
                event.Generation != failedGeneration_) {
                std::wstring ignored;
                if (!LoadRules(ignored)) failedGeneration_ = event.Generation;
                reloaded = true;
            }
        }
        ConvertBatch(buffer_.data(), count, events, &family);
        total += count;
        if (count < buffer_.size() || total >= 4 * KFILTER_RING_CAPACITY) return true;
    }
}
