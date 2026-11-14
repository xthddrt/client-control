// kfilterctl - configure, test, launch and observe kfilter.sys.
//
// Usage:
//   kfilterctl status
//   kfilterctl check <file>
//   kfilterctl policy <file> [--no-track]
//   kfilterctl default [--no-track]
//   kfilterctl on | audit | off
//   kfilterctl stop                (Linux: off, unpin the BPF layer, kfilterd exits)
//   kfilterctl session <tag>       (Linux: the tag kfilterd reports with its decisions)
//   kfilterctl track
//   kfilterctl clear
//   kfilterctl watch [seconds]
//   kfilterctl self-test
//   kfilterctl launch <exe> [args...] [--no-network] [--appcontainer <profile>] [--hostname <name>]
//                     [--program <Windows program>] [--uname26] [--time-offset <seconds>] [--private-proc]
//                     [--user <account>] [--trap-cpuid] [--trap-rdtsc] [--cpuid-mask <leaves>]
//                     [--trap-log <file>] (Linux)

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>
#include <ntddscsi.h>
#include <ntddndis.h>
#include <sddl.h>
#include <aclapi.h>
#include <userenv.h>
#include <tlhelp32.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
/* Linux: kfilterd's socket replaces the device; see linux_compat.h. */
#include "linux_compat.h"
#include <dirent.h>
#include <climits>
#endif
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cwchar>
#include <cwctype>
#include <memory>
#include <string>
#include <vector>
#include <algorithm>
#include <iterator>
#include <fstream>
#include <filesystem>
#include "../driver/kfilter.h"
#include "../driver/match.h"
#ifndef _WIN32
#include "../linux/bpf/kfilter_bpf.h"   /* KB_WINE_REQUESTS: the Wine requests /system/wine/<request> names */
#endif

/* printf length for ULONG/DWORD: 32-bit `unsigned long` on Windows, `unsigned int` on Linux. */
#ifdef _WIN32
#define KF_U "lu"
#define KF_X "lx"
#else
#define KF_U "u"
#define KF_X "x"
#endif

#ifndef _WIN32
/* `check`, `policy`, `default` and `launch` take Linux policies: '/' paths only.
 * self-test, simulate and evaluate also read Windows policies and captures. */
static bool gLinuxPaths = false;
#endif

/* ParsePolicy's rules from here on are implicit (strict file queries' ancestor directories). */
static ULONG gFirstImplicit = KFILTER_MAX_RULES;

/* A policy path is absolute when it starts with the NT separator (or '/' on Linux). */
static bool PolicyAbsolute(wchar_t first)
{
#ifdef _WIN32
    return first == L'\\';
#else
    return first == L'\\' || first == L'/';
#endif
}

/* A Windows image under Wine is named by its DOS path (C:\...). */
static bool DrivePath(const std::wstring& path)
{
    return path.size() >= 3 && ((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')) &&
           path[1] == L':' && path[2] == L'\\';
}

static std::string WideToUtf8(const std::wstring& value)
{
    if (value.empty()) return {};
    int needed = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), (int)value.size(), nullptr, 0, nullptr, nullptr);
    std::string output(needed > 0 ? needed : 0, '\0');
    if (needed > 0) WideCharToMultiByte(CP_UTF8, 0, value.c_str(), (int)value.size(), output.data(), needed, nullptr, nullptr);
    return output;
}

static std::wstring Utf8ToWide(const std::string& value)
{
    if (value.empty()) return {};
    int needed = MultiByteToWideChar(CP_UTF8, 0, value.data(), (int)value.size(), nullptr, 0);
    std::wstring output(needed > 0 ? needed : 0, L'\0');
    if (needed > 0) MultiByteToWideChar(CP_UTF8, 0, value.data(), (int)value.size(), output.data(), needed);
    return output;
}

#ifdef _WIN32
static std::wstring ToNtPath(const std::wstring& path, std::string& error)
{
    if (path.size() >= 2 && path[1] == L':') {
        wchar_t drive[3] = { path[0], L':', L'\0' };
        wchar_t device[32768];
        DWORD length = QueryDosDeviceW(drive, device, (DWORD)(sizeof(device) / sizeof(device[0])));
        if (length == 0) {
            error = "QueryDosDevice failed";
            return {};
        }
        std::wstring result = device;
        result += path.substr(2);
        while (result.size() > 1 && result.back() == L'\\') result.pop_back();
        return result;
    }
    if (path.rfind(L"\\\\", 0) == 0 || path.rfind(L"\\Device\\", 0) == 0) return path;
    error = "path must be a drive path or an NT device path";
    return {};
}

static bool Ioctl(HANDLE device, DWORD code, void* input, DWORD inputLength,
                  void* output, DWORD outputLength, DWORD* returned)
{
    DWORD bytes = 0;
    if (!DeviceIoControl(device, code, input, inputLength, output, outputLength, &bytes, nullptr)) return false;
    if (returned != nullptr) *returned = bytes;
    return true;
}

static HANDLE OpenDevice()
{
    HANDLE device = CreateFileA(KFILTER_USER_PATH, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (device == INVALID_HANDLE_VALUE) {
        std::fprintf(stderr, "Cannot open %s (Win32 error %lu).\n", KFILTER_USER_PATH, GetLastError());
        std::fprintf(stderr, "The driver must be installed, signed and started; run this elevated.\n");
    }
    return device;
}
#else
/* Linux paths are used as they are; NT device paths only outside Linux policies. */
static std::wstring ToNtPath(const std::wstring& path, std::string& error)
{
    if (!path.empty() && path[0] == L'/') {
        std::wstring result = path;
        while (result.size() > 1 && result.back() == L'/') result.pop_back();
        return result;
    }
    if (!gLinuxPaths && (path.rfind(L"\\\\", 0) == 0 || path.rfind(L"\\Device\\", 0) == 0)) return path;
    error = gLinuxPaths ? "Linux policies take absolute '/' paths, not drive or NT device paths"
                        : "drive paths need Windows (QueryDosDevice); use an NT device path";
    return {};
}
#endif

static const char* ModeName(ULONG mode)
{
    switch (mode) {
    case KFILTER_MODE_OFF: return "off";
    case KFILTER_MODE_AUDIT: return "audit";
    case KFILTER_MODE_BLOCK: return "block";
    default: return "unknown";
    }
}

static const char* TargetName(ULONG target)
{
    switch (target) {
    case KFILTER_TARGET_FILE: return "file";
    case KFILTER_TARGET_DIR: return "dir";
    case KFILTER_TARGET_REGISTRY: return "registry";
    case KFILTER_TARGET_VOLUME: return "volume";
    case KFILTER_TARGET_PROCESS: return "process";
    case KFILTER_TARGET_DEVICE: return "device";
    case KFILTER_TARGET_PIPE: return "pipe";
    case KFILTER_TARGET_NETWORK: return "network";
    case KFILTER_TARGET_HANDLE: return "handle";
    case KFILTER_TARGET_OPEN: return "open";
    case KFILTER_TARGET_LAUNCH: return "launch";
    case KFILTER_TARGET_THREAD_HANDLE: return "thread-handle";
    case KFILTER_TARGET_THREAD_OPEN: return "thread-open";
    case KFILTER_TARGET_PEER: return "peer";
    case KFILTER_TARGET_THREAD_PEER: return "thread-peer";
    case KFILTER_TARGET_SYSTEM: return "system";
    case KFILTER_TARGET_DNS: return "dns";
    case KFILTER_TARGET_THREAD: return "thread";
    default: return "?";
    }
}

static const char* ActionName(ULONG action)
{
    switch (action) {
    case KFilterActionAudit: return "audit";
    case KFilterActionAllow: return "allow";
    case KFilterActionDeny: return "deny";
    case KFilterActionRisk: return "RISK";
    default: return "?";
    }
}

static std::wstring RightsText(ULONG rights)
{
    std::wstring text;
    if (rights & KFILTER_RIGHT_READ) text += L"read,";
    if (rights & KFILTER_RIGHT_WRITE) text += L"write,";
    if (rights & KFILTER_RIGHT_EXECUTE) text += L"execute,";
    if (rights & KFILTER_RIGHT_DELETE) text += L"delete,";
    if (rights & KFILTER_RIGHT_RENAME) text += L"rename,";
    if (rights & KFILTER_RIGHT_SET_SECURITY) text += L"set-security,";
    if (rights & KFILTER_RIGHT_ENUMERATE) text += L"enumerate,";
    if (rights & KFILTER_RIGHT_QUERY) text += L"query,";
    if (rights & KFILTER_RIGHT_CREATE) text += L"create,";
    if (rights & KFILTER_RIGHT_CONNECT) text += L"connect,";
    if (rights & KFILTER_RIGHT_LISTEN) text += L"listen,";
    if (rights & KFILTER_RIGHT_RAW_DEVICE) text += L"raw-device,";
    if (rights & KFILTER_RIGHT_OPEN) text += L"open,";
    if (rights & KFILTER_RIGHT_SEND) text += L"send,";
    if (rights & KFILTER_RIGHT_RECEIVE) text += L"receive,";
    if (rights & KFILTER_RIGHT_LOCK) text += L"lock,";
    if (rights & KFILTER_RIGHT_CHDIR) text += L"chdir,";
    if (rights & KFILTER_RIGHT_TOUCH) text += L"touch,";
    if (!text.empty()) text.pop_back();
    return text;
}

/* Access rights of handle rules, as Windows defines them for processes and threads. */
struct AccessName { const char* name; ULONG bit; };
static const AccessName kStandardAccess[] = {
    { "delete", DELETE }, { "read-control", READ_CONTROL }, { "write-dac", WRITE_DAC },
    { "write-owner", WRITE_OWNER }, { "synchronize", SYNCHRONIZE },
};
static const AccessName kProcessAccess[] = {
    { "terminate", PROCESS_TERMINATE }, { "create-thread", PROCESS_CREATE_THREAD },
    { "vm-operation", PROCESS_VM_OPERATION }, { "vm-read", PROCESS_VM_READ },
    { "vm-write", PROCESS_VM_WRITE }, { "dup-handle", PROCESS_DUP_HANDLE },
    { "create-process", PROCESS_CREATE_PROCESS }, { "set-quota", PROCESS_SET_QUOTA },
    { "set-information", PROCESS_SET_INFORMATION }, { "query-information", PROCESS_QUERY_INFORMATION },
    { "suspend-resume", PROCESS_SUSPEND_RESUME },
    { "query-limited-information", PROCESS_QUERY_LIMITED_INFORMATION },
    { "set-limited-information", PROCESS_SET_LIMITED_INFORMATION },
};
static const AccessName kThreadAccess[] = {
    { "terminate", THREAD_TERMINATE }, { "suspend-resume", THREAD_SUSPEND_RESUME },
    { "get-context", THREAD_GET_CONTEXT }, { "set-context", THREAD_SET_CONTEXT },
    { "set-information", THREAD_SET_INFORMATION }, { "query-information", THREAD_QUERY_INFORMATION },
    { "set-thread-token", THREAD_SET_THREAD_TOKEN }, { "impersonate", THREAD_IMPERSONATE },
    { "direct-impersonation", THREAD_DIRECT_IMPERSONATION },
    { "set-limited-information", THREAD_SET_LIMITED_INFORMATION },
    { "query-limited-information", THREAD_QUERY_LIMITED_INFORMATION },
};

/* Peer rules' pseudo-rights (ABI 11): another program's windows and input, by name only (KFILTER_RULE_PSEUDO; a mask
 * with their bits names none). */
static const AccessName kPeerAccess[] = {
    { "window-query", KFILTER_ACCESS_WINDOW_QUERY }, { "window-set", KFILTER_ACCESS_WINDOW_SET },
    { "window-message", KFILTER_ACCESS_WINDOW_MESSAGE }, { "input", KFILTER_ACCESS_INPUT },
};

static std::wstring AccessRightsText(ULONG rights, bool thread, bool peer = false)
{
    std::wstring text;
    const AccessName* table = thread ? kThreadAccess : kProcessAccess;
    size_t count = thread ? std::size(kThreadAccess) : std::size(kProcessAccess);
    for (size_t index = 0; index < count; index++) {
        if (rights & table[index].bit) { text += Utf8ToWide(table[index].name) + L","; rights &= ~table[index].bit; }
    }
    for (const auto& entry : kPeerAccess) {
        if (peer && !thread && (rights & entry.bit)) { text += Utf8ToWide(entry.name) + L","; rights &= ~entry.bit; }
    }
    for (const auto& entry : kStandardAccess) {
        if (rights & entry.bit) { text += Utf8ToWide(entry.name) + L","; rights &= ~entry.bit; }
    }
    if (rights != 0) {
        wchar_t hex[16];
        swprintf_s(hex, L"0x%lx,", (unsigned long)rights);
        text += hex;
    }
    if (!text.empty()) text.pop_back();
    return text;
}

static std::string DegradedText(ULONG degraded)
{
    static const struct { ULONG bit; const char* name; } names[] = {
        { KFILTER_STATUS_DEGRADED_RAW_DISK, "raw-disk" },
        { KFILTER_STATUS_DEGRADED_ADAPTER, "network-adapter" },
        { KFILTER_STATUS_DEGRADED_DEVICE, "device" },
        { KFILTER_STATUS_DEGRADED_FILES, "files" },
        { KFILTER_STATUS_DEGRADED_REGISTRY, "registry" },
        { KFILTER_STATUS_DEGRADED_PROCESS, "process-create" },
        { KFILTER_STATUS_DEGRADED_MEMORY, "process-memory/thread-handles" },
        { KFILTER_STATUS_DEGRADED_NETWORK, "network" },
        { KFILTER_STATUS_DEGRADED_MESSAGE, "messages" },
        { KFILTER_STATUS_DEGRADED_VOLUME, "volume-identity" },
        { KFILTER_STATUS_FAIL_OPEN, "fail-open (enforcement ends with kfilterd)" },
        { KFILTER_STATUS_DEGRADED_QUERY, "metadata-queries" },
        { KFILTER_STATUS_DEGRADED_SYSTEM, "system" },
        { KFILTER_STATUS_DEGRADED_THREAD, "thread-create" },
        { KFILTER_STATUS_DEGRADED_WINE, "wine (an install whose protocol kfilter does not decode)" },
    };
    std::string text;
    for (const auto& name : names) {
        if ((degraded & name.bit) == 0) continue;
        if (!text.empty()) text += ", ";
        text += name.name;
    }
    return text;
}

/* Block mode is refused for a policy with rules no layer in Registered enforces (kfilterd and
 * the driver refuse it too); audit mode loads it and says what goes undecided. */
static bool PolicyEnforceable(const KFILTER_CONFIG& config, ULONG registered)
{
    ULONG rule = 0;
    ULONG unenforced = KfPolicyUnenforced(&config, registered, &rule);
    if (unenforced == 0) return true;
    bool block = config.Mode == KFILTER_MODE_BLOCK;
    std::fprintf(stderr, "%s: the policy has rules no available layer enforces (%s; first rule %" KF_U ")%s\n",
                 block ? "Refusing block mode" : "warning", DegradedText(unenforced).c_str(), rule,
                 block ? "" : "; audit mode loads them undecided");
    return !block;
}

#ifndef _WIN32
/*
 * `check`'s warnings about rules whose reach is easy to mistake on Linux: a system rule reaching /system/wine/ with a
 * star (or as its parent) meets only the Wine requests kfilter decided before every request was, one whose fixed text
 * reaches into the request names decides each request it begins (needed ones too); a peer or thread-peer rule without
 * rights= meets every access kfilter decides on that program, kinds a later version adds too; a pattern matching
 * \@unknown (a handle kfilter cannot name) does not decide requests through such handles: only rules naming it do; a
 * rule on \@unknown-window or \@unknown-thread meets nothing without a pseudo-right, and its deny also meets the
 * program's own windows and threads kfilter did not see made; a rule naming a signal or ptrace mode meets nothing when its
 * value= cannot match the kernel's text, its rights= exclude the access the decision asks, or it is a thread-peer rule.
 */
/* Whether value= glob Pattern ('*' only, without case) matches some Form ("signal:0x", "ptrace:0x") followed by eight
 * hexadecimal digits, the kernel's text for a signal or ptrace mode (kfilter.bpf.c reach_value). */
static bool ReachValueFits(const std::wstring& pattern, const char* form)
{
    uint32_t can = 1;   /* bit p: the pattern read so far can end at text position p (0 to 17) */
    for (wchar_t c : pattern) {
        if (c == L'*') {
            can = can == 0 ? 0 : 0x3FFFFu & (~0u << __builtin_ctz(can));
            continue;
        }
        uint32_t fits = 0;
        for (int p = 0; p < 17; p++) fits |= (uint32_t)(p < 9 ? (wint_t)towlower(c) == (wint_t)form[p] : iswxdigit(c) != 0) << p;
        can = (can & fits) << 1;
    }
    return (can & 1u << 17) != 0;
}

/*
 * In-process calls (kfilter_bpf.h KB_UP_CALLS): /system/ntdll names only the ntdll.so calls kfilter decides, and a class
 * only of one that has classes, in decimal as the kernel writes it; /system/win32k/<function>/<key> only a keyed
 * function's key, in the kernel's text (0x%08x lowercase, decimal, @self, @other, @desktop, @unknown), and only with the
 * function named before any star; a deny on @other leaves the windows kfilter cannot place to a rule naming @unknown,
 * which no wildcard meets and no allow can vouch for; the probes of NtUserCallHwndParam, NtUserMessageCall and
 * NtQueryVirtualMemory cost each Wine program a trap a call; a deny of a whole ntdll.so call, or of all of them, refuses
 * what the program's own runtime asks too; a /system/wmi rule on a class (or a star) does not meet its methods
 * (ExecMethod: /system/wmi/<class>/<method>).
 */
static void InprocWarnings(const KFILTER_CONFIG& config, const KFILTER_RULE& rule, const std::string& name,
                           std::vector<std::string>& warnings)
{
    struct Call { const char* library; const char* name; uint32_t kind; };
#define KB_UP_CALL(library, name, kind, right) {#library, #name, kind},
    static const Call calls[] = {KB_UP_CALLS(KB_UP_CALL)};
#undef KB_UP_CALL
    const std::string path = WideToUtf8(std::wstring(rule.Path, KfLengthBounded(rule.Path, KFILTER_MAX_NAME)));
    const size_t star = path.find('*');
    const std::string head = path.substr(0, star);
    auto digits = [](const std::string& text, bool sign) {
        const size_t first = sign && !text.empty() && text[0] == '-' ? 1 : 0;
        return text.size() > first && text.find_first_not_of("0123456789", first) == std::string::npos;
    };
    if (path.rfind("/system/wmi/", 0) == 0 && (rule.Flags & KFILTER_RULE_EXACT) == 0 && head.find('/', 12) == std::string::npos) {
        warnings.push_back(name + " meets queries, not a class's methods: ExecMethod is /system/wmi/<class>/<method>, "
                                  "decided only by rules naming a class's methods");
    }
    /* Whether Win32kApply attaches Function (/system/<space>/<name>) for this rule (bpf_loader.cpp KfBpfUprobeFunctions). */
    auto attaches = [&](const std::string& space, const std::string& function) {
        const std::string keys = function + "/";
        const std::wstring wide(function.begin(), function.end());
        if (head.size() < space.size() || head.compare(0, space.size(), space) != 0) return false;
        if (head.compare(0, keys.size(), keys) == 0) return true;
        if (space == "/system/ntdll") return star != std::string::npos ? keys.compare(0, head.size(), head) == 0 : path == space || path == function;
        return KfPathMatches(rule.Path, KfLengthBounded(rule.Path, KFILTER_MAX_NAME), wide.c_str(), (KF_ULONG)wide.size()) != 0;
    };
    static const struct { const char* space; const char* function; const char* why; } hot[] = {
        {"/system/win32k", "NtUserCallHwndParam", "which Wine programs call many times a frame (GetWindowLong, GetWindowRect, "
                                                  "ClientToScreen)"},
        {"/system/win32k", "NtUserMessageCall", "which each SendMessage and DefWindowProc goes through"},
        {"/system/ntdll", "NtQueryVirtualMemory", "which each VirtualQuery goes through (runtimes and allocators ask it often)"}};
    for (const auto& call : hot) {
        if (!attaches(call.space, std::string(call.space) + "/" + call.function)) continue;
        warnings.push_back(name + " probes " + call.function + ", " + call.why + ": while it is loaded each call in every Wine "
                           "process takes a trap (1-2 us)");
    }
    auto matches = [&](const std::wstring& text) {
        return KfPathMatches(rule.Path, KfLengthBounded(rule.Path, KFILTER_MAX_NAME), text.c_str(), (KF_ULONG)text.size()) != 0;
    };
    if (rule.Action == KFilterActionDeny && head.rfind("/system/ntdll", 0) == 0 && rule.Value[0] == L'\0' &&
        (rule.Flags & KFILTER_RULE_ADDRESS) == 0 && matches(L"/system/ntdll/NtSystemDebugControl") &&
        matches(L"/system/ntdll/NtQueryVirtualMemory/2")) {
        warnings.push_back(name + " refuses every ntdll.so call kfilter decides (NtQueryInformationProcess, "
                                  "NtQueryVirtualMemory, ...) the program makes, its runtime's too (Wine's own are not "
                                  "decided); name a call and its class");
    }
    const bool ntdll = path.rfind("/system/ntdll/", 0) == 0, win32k = path.rfind("/system/win32k/", 0) == 0;
    if (win32k && star != std::string::npos && head.find('/', 15) == std::string::npos &&
        path.find('/', star) != std::string::npos) {
        warnings.push_back(name + " meets nothing: a key (/system/win32k/<function>/<key>) is decided only by rules naming "
                                  "its function before any star");
    }
    if (!ntdll && !win32k) return;
    const size_t base = ntdll ? 14 : 15, slash = path.find('/', base);
    const std::string function = path.substr(base, slash == std::string::npos ? std::string::npos : slash - base);
    const std::string key = slash == std::string::npos ? "" : path.substr(slash + 1);
    if (function.find('*') != std::string::npos) return;
    const Call* call = nullptr;
    std::string decided;
    for (const Call& entry : calls) {
        if ((strcmp(entry.library, "ntdll") == 0) != ntdll || (!ntdll && entry.kind == 0)) continue;
        if (function == entry.name) call = &entry;
        decided += std::string(decided.empty() ? "" : ", ") + entry.name;
    }
    const bool classed = call && (call->kind == KB_UP_CLASS || call->kind == KB_UP_CLASS2 || call->kind == KB_UP_MEMORY);
    if (ntdll && !call) {
        warnings.push_back(name + " meets nothing: kfilter decides only these ntdll.so calls: " + decided);
    } else if (ntdll && !key.empty() && !classed) {
        warnings.push_back(name + " meets nothing: " + function + " has no class (/system/ntdll/" + function + " alone)");
    } else if (ntdll && !key.empty() && key.find('*') == std::string::npos && !digits(key, false)) {
        warnings.push_back(name + " meets nothing: the kernel names a class in decimal (/system/ntdll/" + function + "/7)");
    } else if (ntdll && key.empty() && star == std::string::npos && rule.Action == KFilterActionDeny &&
               (classed || call->kind == 0) && (rule.Flags & KFILTER_RULE_ADDRESS) == 0) {
        warnings.push_back(name + " refuses every " + function + " call the program makes, its runtime's at start too (Wine's "
                                  "own are not decided); name " + (call->kind == KB_UP_MEMORY ? "an addr= range" : "a class") +
                                  " if that is not meant");
    }
    if (!win32k || key.empty()) return;
    const uint32_t kind = call ? call->kind : 0;
    const bool literal = key.find('*') == std::string::npos;
    if (!call) {
        warnings.push_back(name + " meets nothing: only these win32u.so calls have keys: " + decided);
    } else if (literal && kind == KB_UP_VKEY && (key.size() != 10 || key.compare(0, 2, "0x") != 0 ||
                                                 key.find_first_not_of("0123456789abcdef", 2) != std::string::npos)) {
        warnings.push_back(name + " meets nothing: the kernel names a virtual key 0x%08x, lowercase (0x00000070 for VK_F1, "
                                  "0x0000007a for VK_F11)");
    } else if (literal && (kind == KB_UP_FORMAT || kind == KB_UP_HOOK) && !digits(key, kind == KB_UP_HOOK)) {
        warnings.push_back(name + " meets nothing: the kernel names " + (kind == KB_UP_HOOK ? "a hook id" : "a clipboard format") +
                           " in decimal");
    } else if (literal && kind == KB_UP_WINDOW && key != "@self" && key != "@other" && key != "@desktop" && key != "@unknown") {
        warnings.push_back(name + " meets nothing: the kernel names a window by its owner: @self, @other, @desktop or @unknown");
    } else if (kind == KB_UP_WINDOW && key == "@other" && rule.Action == KFilterActionDeny) {
        const std::wstring unplaced = L"/system/win32k/" + std::wstring(function.begin(), function.end()) + L"/@unknown";
        bool named = false;
        for (ULONG index = 0; index < config.RuleCount; index++) {
            const KFILTER_RULE& other = config.Rules[index];
            named = named || (other.Targets == KFILTER_TARGET_SYSTEM && other.Action != KFilterActionAllow &&
                              wcschr(other.Path, L'*') == nullptr &&
                              KfPathMatches(other.Path, KfLengthBounded(other.Path, KFILTER_MAX_NAME), unplaced.c_str(),
                                            (KF_ULONG)unplaced.size()));
        }
        if (!named) {
            warnings.push_back(name + " leaves the windows kfilter cannot place (made before kfilterd started, or by a Wine it "
                                      "does not decode) to a rule naming /system/win32k/" + function + "/@unknown");
        }
    } else if (kind == KB_UP_WINDOW && key == "@unknown" && rule.Action == KFilterActionAllow) {
        warnings.push_back(name + " is an allow on a window kfilter cannot place, which no allow can vouch for: it is not "
                                  "loaded");
    } else if (kind == KB_UP_WINDOW && !literal && matches(L"/system/win32k/" + std::wstring(function.begin(), function.end()) +
                                                           L"/@unknown")) {
        warnings.push_back(name + " matches @unknown without naming it: a window kfilter cannot place is decided only by "
                                  "rules naming /system/win32k/" + function + "/@unknown");
    }
}

static std::vector<std::string> PolicyWarnings(const KFILTER_CONFIG& config)
{
#define KB_WNAME_TEXT(name, right) #name,
    static const char* const requests[] = {KB_WINE_REQUESTS(KB_WNAME_TEXT)};
#undef KB_WNAME_TEXT
    static const std::wstring space = L"/system/wine/";
    std::vector<std::string> warnings;
    for (ULONG index = 0; index < config.RuleCount; index++) {
        const KFILTER_RULE& rule = config.Rules[index];
        const std::wstring path(rule.Path, KfLengthBounded(rule.Path, KFILTER_MAX_NAME));
        const std::string name = "rule " + std::to_string(rule.RuleId) + " (" + WideToUtf8(path) + ")";
        const size_t head = std::min(path.find(L'*'), path.size());
        const bool wild = head < path.size();
        if (rule.Targets == KFILTER_TARGET_SYSTEM && head <= space.size() && space.compare(0, head, path, 0, head) == 0 &&
            (wild || path == L"/system" || path == L"/system/wine")) {
            warnings.push_back(name + " meets only the Wine requests kfilter decided before every request was; name a "
                                      "request (/system/wine/<request>) to decide another");
        } else if (rule.Targets == KFILTER_TARGET_SYSTEM && wild && path.compare(0, space.size(), space) == 0) {
            const std::string fixed = WideToUtf8(path.substr(space.size(), head - space.size()));
            std::string named;
            int count = 0;
            for (const char* request : requests) {
                if (std::strncmp(request, fixed.c_str(), fixed.size()) != 0) continue;
                if (count++ < 3) named += std::string(count > 1 ? ", " : "") + request;
            }
            if (count != 0) {
                warnings.push_back(name + " decides each of the " + std::to_string(count) + " Wine requests it begins (" + named +
                                   (count > 3 ? ", ..." : "") + "), ones every Wine program needs too");
            }
        }
        const bool placeholder = rule.Targets == KFILTER_TARGET_PEER &&
                                 (_wcsicmp(rule.Path, L"\\@unknown-window") == 0 || _wcsicmp(rule.Path, L"\\@unknown-thread") == 0);
        if (placeholder && (rule.Flags & KFILTER_RULE_PSEUDO) == 0) {
            warnings.push_back(name + " meets nothing: a window or thread kfilter cannot place is decided only by rules "
                                      "naming a pseudo-right (window-query, window-set, window-message, input)");
        } else if (placeholder && rule.Action != KFilterActionAllow) {
            warnings.push_back(name + " also meets the program's own windows and threads kfilter did not see made (before "
                                      "kfilterd started): it can refuse the program's requests on itself");
        }
        /* value=signal:... or ptrace:... on a peer rule (kfilterd's NamesReach): it meets only that signal or mode, its
         * rights= still narrowing it (a signal asks terminate, a kill(pid, 0) probe query-limited-information, a READ check
         * query-information); a thread-peer one meets nothing (both are decided on a process). */
        const bool signal = _wcsnicmp(rule.Value, L"signal:", 7) == 0, mode = _wcsnicmp(rule.Value, L"ptrace:", 7) == 0;
        const bool reach = rule.Targets == KFILTER_TARGET_PEER && (signal || mode);
        const std::wstring value(rule.Value, KfLengthBounded(rule.Value, KFILTER_MAX_VALUE));
        if (reach && !ReachValueFits(value, signal ? "signal:0x" : "ptrace:0x")) {
            warnings.push_back(name + " meets nothing: the kernel names a signal or ptrace mode signal:0x%08X or ptrace:0x%08X "
                                      "(eight hexadecimal digits), which its value= cannot match");
        } else if (reach && rule.Rights != 0 &&
                   (rule.Rights & (signal ? PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION : PROCESS_QUERY_INFORMATION)) == 0) {
            warnings.push_back(name + " meets nothing: " +
                               (signal ? "a signal asks terminate (a kill(pid, 0) probe query-limited-information)"
                                       : "a ptrace READ check asks query-information") +
                               ", which its rights= exclude");
        } else if (reach && (rule.Flags & KFILTER_RULE_PSEUDO) != 0) {
            warnings.push_back(name + " names a pseudo-right, which a rule naming a signal or ptrace mode never meets: it meets "
                                      "no window, message or input decision");
        }
        if (rule.Targets == KFILTER_TARGET_THREAD_PEER && (signal || mode)) {
            warnings.push_back(name + " meets nothing: signals and ptrace checks are decided on a process; name the signal "
                                      "or mode on a peer rule");
        }
        if ((rule.Targets == KFILTER_TARGET_PEER || rule.Targets == KFILTER_TARGET_THREAD_PEER) && rule.Rights == 0 &&
            rule.Action != KFilterActionAllow && !placeholder && !signal && !mode) {
            warnings.push_back(name + " has no rights=: it meets every access kfilter decides on that program, also kinds a "
                                      "later version decides; name the rights it is for");
        }
        if ((rule.Targets == KFILTER_TARGET_PEER || rule.Targets == KFILTER_TARGET_THREAD_PEER) && wild &&
            KfPathMatches(rule.Path, (KF_ULONG)path.size(), L"\\@unknown", 9)) {
            warnings.push_back(name + " matches \\@unknown without naming it: requests through a handle kfilter cannot name "
                                      "are decided only by rules naming \\@unknown");
        }
        if (placeholder && rule.Action == KFilterActionAllow) {
            warnings.push_back(name + " is an allow on a window or thread kfilter cannot place, which no allow can vouch for: "
                                      "it is not loaded");
        }
        if (rule.Targets == KFILTER_TARGET_SYSTEM) InprocWarnings(config, rule, name, warnings);
    }
    /* unix= message rules: decided only with block-network on, as every message rule. A refused send is a write error the
     * X11, D-Bus and PulseAudio (PipeWire) client libraries treat as fatal (xcb, libdbus and libpulse drop the connection; a
     * skipped X11 request also puts its numbering out of step), so a deny on such a socket without match= or index= ends the
     * connection at its first refusal, and one on Wine's server socket (its fd passing) every Wine program of the family.
     * A unix= glob matches the whole name, and a connected peer is named by its bound path with symlinks resolved. */
    static const struct { const wchar_t* glob; const wchar_t* sample; bool wine; } sockets[] = {
        {L"/tmp/.X11-unix/X*", L"/tmp/.X11-unix/X0", false}, {L"/@/tmp/.X11-unix/X*", L"/@/tmp/.X11-unix/X0", false},
        {L"/run/user/*/bus", L"/run/user/1000/bus", false}, {L"/run/dbus/system_bus_socket", L"/run/dbus/system_bus_socket", false},
        {L"/run/user/*/pulse/native", L"/run/user/1000/pulse/native", false},
        {L"/run/user/*/pipewire-0", L"/run/user/1000/pipewire-0", false},
        {L"/tmp/.wine-*/server-*/socket", L"/tmp/.wine-1000/server-10305-1b17/socket", true}};
    for (ULONG index = 0; index < config.NetworkRuleCount && index < KFILTER_MAX_NET_RULES; index++) {
        const KFILTER_NET_RULE& rule = config.Network[index];
        if (rule.Family != KFILTER_NET_FAMILY_UNIX) continue;
        const std::wstring peer(rule.Unix, KfLengthBounded(rule.Unix, KFILTER_MAX_VALUE));
        const std::string name = "rule " + std::to_string(rule.RuleId) + " (unix=" + WideToUtf8(peer) + ")";
        if ((config.Flags & KFILTER_CFG_BLOCK_NETWORK) == 0)
            warnings.push_back(name + " meets nothing: message rules are decided only with block-network on");
        bool desktop = false, wine = false;
        for (const auto& socket : sockets) {
            const bool meets = KfMatchGlob(peer.c_str(), (KF_ULONG)peer.size(), socket.sample, (KF_ULONG)wcslen(socket.sample)) ||
                               KfMatchGlob(socket.glob, (KF_ULONG)wcslen(socket.glob), peer.c_str(), (KF_ULONG)peer.size());
            (socket.wine ? wine : desktop) |= meets;
        }
        if (wine && (rule.Action == KFilterActionDeny || rule.Count != 0)) {
            warnings.push_back(name + " meets Wine's server connection (/tmp/.wine-<uid>/server-*/socket): a refused send ends "
                                      "every Wine program of the family");
        } else if (desktop && rule.Action == KFilterActionDeny && rule.MatchLength == 0 && rule.IndexMax == 0) {
            warnings.push_back(name + " refuses sends to an X11, D-Bus or PulseAudio socket without match= or index=: the "
                                      "client drops its connection at the first refusal (a kill switch)");
        }
        const std::string text = WideToUtf8(peer), fixed = text.substr(0, text.find('*'));
        std::error_code error;
        if (fixed.size() == text.size() && text.rfind("/@", 0) != 0 && std::filesystem::is_directory(text, error)) {
            warnings.push_back(name + " meets nothing: unix= matches the peer's whole name, and " + text + " is a directory (" +
                               text + "/* for the sockets in it)");
        }
        const std::string directory = fixed.substr(0, fixed.rfind('/'));
        const std::filesystem::path resolved = directory.empty() || fixed.rfind("/@", 0) == 0
                                                   ? std::filesystem::path()
                                                   : std::filesystem::canonical(directory, error);
        if (!error && !resolved.empty() && resolved.string() != directory) {
            warnings.push_back(name + " names its peer through a symlink: a send on a connected socket names it " +
                               resolved.string() + text.substr(directory.size()) + " (its bound path, symlinks resolved), so "
                               "this rule meets only sendto's to the name as written");
        }
    }
    return warnings;
}
#endif

/* Linux: msmon-agent owns the decision ring (KFILTER_SESSION_OWN_EVENTS) and reads take events
 * off it, so kfilterd refuses other readers with EBUSY. */
static void ExplainRingRefusal()
{
#ifndef _WIN32
    if (errno == EBUSY) {
        std::fprintf(stderr, "The decision ring belongs to a running monitor session (msmon-agent); reading or\n"
                             "clearing it here would take decisions out of its log. Follow the kfilter_decision\n"
                             "records in the msmon session log instead.\n");
    }
#endif
}

static int ShowStatus(HANDLE device)
{
    KFILTER_STATUS status{};
    if (!Ioctl(device, KFILTER_IOCTL_GET_STATUS, nullptr, 0, &status, sizeof(status), nullptr)) {
        std::fprintf(stderr, "GET_STATUS failed: %" KF_U "\n", GetLastError());
        return 1;
    }
    std::printf("mode:              %s\n", ModeName(status.Mode));
    std::printf("flags:             0x%" KF_X "%s%s%s%s%s%s%s%s%s%s%s\n", status.Flags,
                (status.Flags & KFILTER_CFG_BLOCK_FILES) ? " files" : "",
                (status.Flags & KFILTER_CFG_BLOCK_REGISTRY) ? " registry" : "",
                (status.Flags & KFILTER_CFG_BLOCK_VOLUME_SERIAL) ? " volume-serial" : "",
                (status.Flags & KFILTER_CFG_BLOCK_PROCESS_MEMORY) ? " process-memory" : "",
                (status.Flags & KFILTER_CFG_BLOCK_PROCESS_CREATE) ? " process-create" : "",
                (status.Flags & KFILTER_CFG_BLOCK_RAW_DISK) ? " raw-disk" : "",
                (status.Flags & KFILTER_CFG_BLOCK_NETWORK) ? " network" : "",
                (status.Flags & KFILTER_CFG_BLOCK_NETWORK_ADAPTER) ? " network-adapter" : "",
                (status.Flags & KFILTER_CFG_BLOCK_FILE_QUERIES) ? " file-queries" : "",
                (status.Flags & KFILTER_CFG_BLOCK_DIRECT_SYSCALL) ? " direct-syscall" : "",
                (status.Flags & KFILTER_CFG_DEFAULT_DENY) ? " default-deny" : "");
    std::printf("generation:        %" KF_U "\n", status.PolicyGeneration);
    std::printf("rules:             %" KF_U " (%" KF_U " network)\n", status.RuleCount, status.NetworkRuleCount);
    std::printf("protected names:   %" KF_U "\n", status.ProtectedCount);
    std::printf("tracked processes: %" KF_U "\n", status.TrackedProcesses);
    std::printf("decisions:         allowed=%" KF_U " denied=%" KF_U " audited=%" KF_U " would-deny=%" KF_U "\n",
                status.Allowed, status.Denied, status.Audited, status.WouldDeny);
    std::printf("failures:          names=%" KF_U " missing-context=%" KF_U " sid=%" KF_U "\n",
                status.NameFailures, status.MissingContexts, status.SidFailures);
    std::printf("events dropped:    %" KF_U "\n", status.DroppedEvents);
    if (status.Degraded != 0) std::printf("degraded:          %s\n", DegradedText(status.Degraded).c_str());
    std::printf("session tag:       %016llx\n", (unsigned long long)status.SessionTag);
    std::printf("registered:        %s%s%s%s%s%s%s%s%s\n",
                (status.Registered & KFILTER_REG_MINIFILTER) ? "minifilter " : "",
                (status.Registered & KFILTER_REG_REGISTRY) ? "registry " : "",
                (status.Registered & KFILTER_REG_OBJECT) ? "object " : "",
                (status.Registered & KFILTER_REG_PROCESS) ? "process " : "",
                (status.Registered & KFILTER_REG_DISK) ? "disk " : "",
                (status.Registered & KFILTER_REG_NETWORK) ? "network " : "",
                (status.Registered & KFILTER_REG_NSI) ? "nsi " : "",
                (status.Registered & KFILTER_REG_DEVICE) ? "device " : "",
                (status.Registered & KFILTER_REG_BPF) ? "bpf" : "");
    if ((status.Mode == KFILTER_MODE_BLOCK) &&
        ((status.Registered & KFILTER_REG_MINIFILTER) == 0 ||
         (status.Registered & KFILTER_REG_PROCESS) == 0)) {
        std::printf("WARNING: block mode with a required layer missing\n");
    }
    return 0;
}

static bool ShowEvents(HANDLE device, int seconds)
{
    ULONGLONG end = GetTickCount64() + (ULONGLONG)seconds * 1000;
    std::vector<KFILTER_EVENT> events(512);
    do {
        KFILTER_READ_REQUEST request{};
        request.MaximumEvents = (ULONG)events.size();
        DWORD bytes = 0;
        if (!Ioctl(device, KFILTER_IOCTL_READ_EVENTS, &request, sizeof(request),
                   events.data(), (DWORD)(events.size() * sizeof(KFILTER_EVENT)), &bytes)) {
            std::fprintf(stderr, "READ_EVENTS failed: %" KF_U "\n", GetLastError());
            ExplainRingRefusal();
            return false;
        }
        size_t count = bytes / sizeof(KFILTER_EVENT);
        for (size_t index = 0; index < count; index++) {
            const KFILTER_EVENT& event = events[index];
            FILETIME fileTime;
            fileTime.dwLowDateTime = (DWORD)event.Timestamp;
            fileTime.dwHighDateTime = (DWORD)(event.Timestamp >> 32);
            SYSTEMTIME local{};
            FileTimeToSystemTime(&fileTime, &local);
            SYSTEMTIME system{};
            SystemTimeToTzSpecificLocalTime(nullptr, &local, &system);
            std::string program = WideToUtf8(std::wstring(event.Image, KfLengthBounded(event.Image, KFILTER_MAX_IMAGE)));
            if ((event.Flags & KFILTER_EVENT_FLAG_BROKERED) != 0) program += "(brokered)";
            std::printf("%02u:%02u:%02u.%03u pid=%" KF_U " %-16s %-8s %-5s flags=0x%" KF_X " rule=%" KF_U " gen=%" KF_U " status=0x%08lx value=0x%" KF_X " %s\n",
                        system.wHour, system.wMinute, system.wSecond, system.wMilliseconds,
                        event.ProcessId, program.empty() ? "-" : program.c_str(), TargetName(event.Target), ActionName(event.Action),
                        event.Flags, event.RuleId, event.Generation, (unsigned long)event.Status,
                        event.Value, WideToUtf8(event.Path).c_str());
        }
        // A full batch means more are waiting: keep reading (a Wine start alone logs thousands).
        if (count == events.size() && GetTickCount64() < end) continue;
        if (GetTickCount64() >= end) break;
        Sleep(250);
    } while (true);
    return true;
}

static void Trim(std::string& value)
{
    size_t first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) { value.clear(); return; }
    size_t last = value.find_last_not_of(" \t\r\n");
    value = value.substr(first, last - first + 1);
}

static std::vector<std::string> Split(const std::string& line, char separator)
{
    std::vector<std::string> parts;
    std::string current;
    for (char value : line) {
        if (value == separator) { parts.push_back(current); current.clear(); }
        else current.push_back(value);
    }
    parts.push_back(current);
    for (auto& part : parts) Trim(part);
    return parts;
}

static std::vector<std::string> SplitWhitespace(const std::string& line)
{
    std::vector<std::string> parts;
    size_t index = 0;
    while (index < line.size()) {
        while (index < line.size() && (line[index] == ' ' || line[index] == '\t')) index++;
        size_t start = index;
        while (index < line.size() && line[index] != ' ' && line[index] != '\t') index++;
        if (index > start) parts.push_back(line.substr(start, index - start));
    }
    return parts;
}

static bool ParseRights(const std::string& value, ULONG& rights, std::string& error)
{
    rights = 0;
    for (const auto& part : Split(value, ',')) {
        if (part == "read") rights |= KFILTER_RIGHT_READ;
        else if (part == "write") rights |= KFILTER_RIGHT_WRITE;
        else if (part == "execute") rights |= KFILTER_RIGHT_EXECUTE;
        else if (part == "delete") rights |= KFILTER_RIGHT_DELETE;
        else if (part == "rename") rights |= KFILTER_RIGHT_RENAME;
        else if (part == "set-security") rights |= KFILTER_RIGHT_SET_SECURITY;
        else if (part == "enumerate") rights |= KFILTER_RIGHT_ENUMERATE;
        else if (part == "query") rights |= KFILTER_RIGHT_QUERY;
        else if (part == "create") rights |= KFILTER_RIGHT_CREATE;
        else if (part == "connect") rights |= KFILTER_RIGHT_CONNECT;
        else if (part == "listen") rights |= KFILTER_RIGHT_LISTEN;
        else if (part == "raw-device") rights |= KFILTER_RIGHT_RAW_DEVICE;
        else if (part == "open") rights |= KFILTER_RIGHT_OPEN;
        else if (part == "send") rights |= KFILTER_RIGHT_SEND;
        else if (part == "receive") rights |= KFILTER_RIGHT_RECEIVE;
        else if (part == "lock") rights |= KFILTER_RIGHT_LOCK;
        else if (part == "chdir") rights |= KFILTER_RIGHT_CHDIR;
        else if (part == "touch") rights |= KFILTER_RIGHT_TOUCH;
        else if (!part.empty()) { error = "unknown right '" + part + "'"; return false; }
    }
    return true;
}

/* Access rights for handle rules: process (or thread) right names, standard right names,
 * or a hex mask such as 0x1000; on peer rules also the pseudo-rights (kPeerAccess: *Pseudo is set). */
static bool ParseAccessRights(const std::string& value, bool thread, ULONG& rights, std::string& error, bool peer = false,
                              bool* pseudo = nullptr)
{
    rights = 0;
    const AccessName* table = thread ? kThreadAccess : kProcessAccess;
    size_t count = thread ? std::size(kThreadAccess) : std::size(kProcessAccess);
    for (const auto& part : Split(value, ',')) {
        if (part.empty()) continue;
        bool found = false;
        for (size_t index = 0; index < count && !found; index++) {
            if (part == table[index].name) { rights |= table[index].bit; found = true; }
        }
        for (const auto& entry : kPeerAccess) {
            if (!found && peer && !thread && part == entry.name) {
                rights |= entry.bit;
                found = true;
                if (pseudo != nullptr) *pseudo = true;
            }
        }
        for (const auto& entry : kStandardAccess) {
            if (!found && part == entry.name) { rights |= entry.bit; found = true; }
        }
        if (!found && part.size() > 2 && part[0] == '0' && (part[1] == 'x' || part[1] == 'X')) {
            char* end = nullptr;
            unsigned long mask = strtoul(part.c_str() + 2, &end, 16);
            if (end != nullptr && *end == '\0' && mask != 0) { rights |= mask; found = true; }
        }
        if (!found) { error = std::string("unknown ") + (thread ? "thread" : "process") + " right '" + part + "'"; return false; }
    }
    return true;
}

/* phase=, uses= and opens make a rule counted (KFILTER_COUNT_*): uses defaults to 1 and
 * phase to 1. Returns false on a malformed field; sets *handled when the field is one of them. */
static bool ParseCountField(const std::string& field, ULONG& count, bool& handled, std::string& error)
{
    handled = true;
    if (field.rfind("phase=", 0) == 0) {
        int phase = atoi(field.substr(6).c_str());
        if (phase < 1 || phase > (int)KFILTER_COUNT_PHASE) { error = "phase must be 1..65535"; return false; }
        count = (count & ~KFILTER_COUNT_PHASE) | (ULONG)phase;
    } else if (field.rfind("uses=", 0) == 0) {
        int uses = atoi(field.substr(5).c_str());
        if (uses < 1 || uses > (int)(KFILTER_COUNT_USES >> KFILTER_COUNT_USES_SHIFT)) { error = "uses must be 1..32767"; return false; }
        count = (count & ~KFILTER_COUNT_USES) | ((ULONG)uses << KFILTER_COUNT_USES_SHIFT);
    } else if (field == "opens") {
        count |= KFILTER_COUNT_OPENS;
    } else if (field.rfind("step=", 0) == 0 || field == "optional") {
        error = "step= and optional were replaced by phase=, uses= and opens"; return false;
    } else {
        handled = false;
    }
    return true;
}

/* A counted rule without phase= or uses= gets phase 1 / one use. */
static ULONG CompleteCount(ULONG count)
{
    if (count == 0) return 0;
    if ((count & KFILTER_COUNT_PHASE) == 0) count |= 1;
    if ((count & KFILTER_COUNT_USES) == 0) count |= 1u << KFILTER_COUNT_USES_SHIFT;
    return count;
}

static std::wstring CountText(ULONG count)
{
    if (count == 0) return L"";
    std::wstring text = L" phase=" + std::to_wstring(count & KFILTER_COUNT_PHASE) +
                        L" uses=" + std::to_wstring((count & KFILTER_COUNT_USES) >> KFILTER_COUNT_USES_SHIFT);
    if (count & KFILTER_COUNT_OPENS) text += L" opens";
    return text;
}

static bool ParseExtensions(const std::string& value, ULONG& mask, std::string& error)
{
    mask = 0;
    for (const auto& part : Split(value, ',')) {
        if (part == "exe") mask |= KFILTER_EXT_EXE;
        else if (part == "dll") mask |= KFILTER_EXT_DLL;
        else if (part == "sys") mask |= KFILTER_EXT_SYS;
        else if (part == "ocx") mask |= KFILTER_EXT_OCX;
        else if (part == "other" || part == "mui" || part == "nls" || part == "drv" || part == "icc") mask |= KFILTER_EXT_OTHER;
        else if (!part.empty()) { error = "unknown extension '" + part + "'"; return false; }
    }
    return true;
}

static bool ParseRisk(const std::string& field, wchar_t* output, std::string& error)
{
    std::wstring reason = Utf8ToWide(field.substr(5));
    if (reason.empty() || reason.size() >= KFILTER_MAX_RISK) {
        error = "risk needs a reason shorter than 64 characters";
        return false;
    }
    wcscpy_s(output, KFILTER_MAX_RISK, reason.c_str());
    return true;
}

/* image=<glob>: the program a rule applies to (see KFILTER_RULE.Image). */
static bool ParseImage(const std::string& field, wchar_t* output, std::string& error)
{
    std::wstring image = Utf8ToWide(field.substr(6));
    if (image.empty() || image.size() >= KFILTER_MAX_IMAGE) {
        error = "image needs a program name or path pattern shorter than 64 characters";
        return false;
    }
    wcscpy_s(output, KFILTER_MAX_IMAGE, image.c_str());
    return true;
}

/* LOW[-HIGH], hexadecimal with or without 0x: a lone address is one byte. */
static bool ParseHexRange(const std::string& text, KF_UINT64& low, KF_UINT64& high)
{
    auto number = [](std::string digits, KF_UINT64& value) {
        if (digits.rfind("0x", 0) == 0 || digits.rfind("0X", 0) == 0) digits.erase(0, 2);
        if (digits.empty() || digits.size() > 16 || digits.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos)
            return false;
        value = strtoull(digits.c_str(), nullptr, 16);
        return true;
    };
    size_t dash = text.find('-');
    return number(text.substr(0, dash), low) && number(dash == std::string::npos ? text : text.substr(dash + 1), high) &&
           low <= high;
}

/* addr=RANGE[,RANGE...] (peer, thread-peer and system rules): up to 16 memory ranges, each LOW-HIGH (absolute) or
 * MODULE+LOW-HIGH (from the image base of MODULE, a file name pattern, in the target program). The ranges go to
 * rule.Address, the modules they name to rule.Value, comma-separated. */
static bool ParseAddress(const std::string& field, KFILTER_RULE& rule, std::string& error)
{
    error = "addr= takes up to 16 comma-separated ranges, each 0xLOW-0xHIGH or MODULE+0xLOW-0xHIGH (hexadecimal, "
            "LOW <= HIGH; MODULE a file name pattern without a path), once per rule";
    const std::string list = field.substr(5);
    std::vector<std::string> modules;
    if (list.empty() || (rule.Flags & KFILTER_RULE_ADDRESS) != 0) return false;
    for (size_t start = 0; start <= list.size();) {
        const size_t end = std::min(list.find(',', start), list.size());
        const std::string item = list.substr(start, end - start);
        start = end + 1;
        const size_t plus = item.rfind('+');
        const std::string module = plus == std::string::npos ? "" : item.substr(0, plus);
        KF_UINT64 low = 0, high = 0;
        if (rule.AddressCount >= KFILTER_MAX_ADDRESS || (plus != std::string::npos && module.empty()) ||
            module.find_first_of("\\/,") != std::string::npos ||
            !ParseHexRange(plus == std::string::npos ? item : item.substr(plus + 1), low, high)) {
            return false;
        }
        size_t place = 0;
        if (!module.empty()) {
            place = (size_t)(std::find(modules.begin(), modules.end(), module) - modules.begin()) + 1;
            if (place > modules.size()) modules.push_back(module);
        }
        rule.AddressModule[rule.AddressCount] = (unsigned char)place;
        rule.Address[rule.AddressCount].Low = low;
        rule.Address[rule.AddressCount++].High = high;
    }
    std::string names;
    for (const std::string& module : modules) names += (names.empty() ? "" : ",") + module;
    const std::wstring value = Utf8ToWide(names);
    if (value.size() >= KFILTER_MAX_VALUE) {
        error = "addr= names more modules than fit in 127 characters";
        return false;
    }
    wcscpy_s(rule.Value, KFILTER_MAX_VALUE, value.c_str());
    rule.Flags |= KFILTER_RULE_ADDRESS;
    error.clear();
    return true;
}

/* addr= as the policy writes it: each range, after the module (rule.Value's list) it is relative to. */
static std::wstring AddressText(const KFILTER_RULE& rule)
{
    std::vector<std::wstring> modules;
    const std::wstring value(rule.Value, KfLengthBounded(rule.Value, KFILTER_MAX_VALUE));
    for (size_t start = 0; !value.empty() && start <= value.size();) {
        const size_t end = std::min(value.find(L',', start), value.size());
        modules.push_back(value.substr(start, end - start));
        start = end + 1;
    }
    std::wstring text;
    for (ULONG index = 0; index < rule.AddressCount && index < KFILTER_MAX_ADDRESS; index++) {
        wchar_t range[48];
        swprintf(range, 48, L"0x%llx-0x%llx", (unsigned long long)rule.Address[index].Low,
                 (unsigned long long)rule.Address[index].High);
        const size_t module = rule.AddressModule[index];
        text += std::wstring(index != 0 ? L"," : L"") + (module != 0 && module <= modules.size() ? modules[module - 1] + L"+" : L"") +
                range;
    }
    return text;
}

static bool IsRiskImage(const std::wstring& path)
{
    static const wchar_t* names[] = {
        L"wbemprox.dll", L"fastprox.dll", L"wbemcomn.dll", L"wbemsvc.dll", L"rpcrt4.dll",
        L"iphlpapi.dll", L"hid.dll", L"pdh.dll", L"wtsapi32.dll", L"netapi32.dll",
        L"sspicli.dll", L"grap64.dll", L"grap-core64.aes", L"grap-updater.aes", L"blackcat64.sys",
        L"MachineIdLib.dll", L"tbs.dll", L"nvapi64.dll", L"atiadlxx.dll", L"setupapi.dll",
        L"cfgmgr32.dll", L"wlanapi.dll", L"dhcpcsvc.dll"
    };
    size_t slash = path.find_last_of(L'\\');
    std::wstring name = slash == std::wstring::npos ? path : path.substr(slash + 1);
    for (const wchar_t* candidate : names) {
        if (KfMatchGlob(candidate, (ULONG)wcslen(candidate), name.c_str(), (ULONG)name.size())) return true;
    }
    return false;
}

static std::wstring RiskVolumeRoot(const std::wstring& path)
{
    static const wchar_t prefix[] = L"\\Device\\HarddiskVolume";
    if (_wcsnicmp(path.c_str(), prefix, wcslen(prefix)) != 0) return L"\\Device\\HarddiskVolume3";
    size_t slash = path.find(L'\\', wcslen(prefix));
    return slash == std::wstring::npos ? path : path.substr(0, slash);
}

static bool RuleNeedsRisk(const KFILTER_RULE& rule)
{
    if ((rule.Targets & KFILTER_TARGET_DEVICE) != 0) return true;
    if ((rule.Targets & (KFILTER_TARGET_HANDLE | KFILTER_TARGET_OPEN |
                         KFILTER_TARGET_THREAD_HANDLE | KFILTER_TARGET_THREAD_OPEN)) != 0) return true;
    if ((rule.Targets & KFILTER_TARGET_FILE) == 0) return false;
    ULONG pathExtension = KfExtensionMask(rule.Path, (ULONG)wcslen(rule.Path));
    if ((rule.Extensions == 0 || (rule.Extensions & pathExtension) != 0) && IsRiskImage(rule.Path)) return true;
    struct RiskImage { const wchar_t* path; ULONG extension; };
    static const RiskImage images[] = {
        { L"\\Windows\\System32\\wbemprox.dll", KFILTER_EXT_DLL },
        { L"\\Windows\\System32\\fastprox.dll", KFILTER_EXT_DLL },
        { L"\\Windows\\System32\\wbemcomn.dll", KFILTER_EXT_DLL },
        { L"\\Windows\\System32\\wbemsvc.dll", KFILTER_EXT_DLL },
        { L"\\Windows\\System32\\rpcrt4.dll", KFILTER_EXT_DLL },
        { L"\\Windows\\System32\\iphlpapi.dll", KFILTER_EXT_DLL },
        { L"\\Windows\\System32\\hid.dll", KFILTER_EXT_DLL },
        { L"\\Windows\\System32\\pdh.dll", KFILTER_EXT_DLL },
        { L"\\Windows\\System32\\wtsapi32.dll", KFILTER_EXT_DLL },
        { L"\\Windows\\System32\\netapi32.dll", KFILTER_EXT_DLL },
        { L"\\Windows\\System32\\sspicli.dll", KFILTER_EXT_DLL },
        { L"\\Windows\\System32\\wbem\\wbemprox.dll", KFILTER_EXT_DLL },
        { L"\\Windows\\System32\\wbem\\fastprox.dll", KFILTER_EXT_DLL },
        { L"\\Nexon\\Library\\maplestorycw\\appdata\\grap64.dll", KFILTER_EXT_DLL },
        { L"\\Nexon\\Library\\maplestorycw\\appdata\\grap-core64.aes", KFILTER_EXT_OTHER },
        { L"\\Nexon\\Library\\maplestorycw\\appdata\\grap-updater.aes", KFILTER_EXT_OTHER },
        { L"\\Nexon\\Library\\maplestorycw\\appdata\\MachineIdLib.dll", KFILTER_EXT_DLL },
        { L"\\Windows\\System32\\tbs.dll", KFILTER_EXT_DLL },
        { L"\\Windows\\System32\\nvapi64.dll", KFILTER_EXT_DLL },
        { L"\\Windows\\System32\\atiadlxx.dll", KFILTER_EXT_DLL },
        { L"\\Windows\\System32\\setupapi.dll", KFILTER_EXT_DLL },
        { L"\\Windows\\System32\\cfgmgr32.dll", KFILTER_EXT_DLL },
        { L"\\Windows\\System32\\wlanapi.dll", KFILTER_EXT_DLL },
        { L"\\Windows\\System32\\dhcpcsvc.dll", KFILTER_EXT_DLL },
        { L"\\Windows\\System32\\drivers\\BlackCat64.sys", KFILTER_EXT_SYS },
    };
    ULONG patternLength = (ULONG)wcslen(rule.Path);
    std::wstring volume = RiskVolumeRoot(rule.Path);
    for (const auto& image : images) {
        if (rule.Extensions != 0 && (rule.Extensions & image.extension) == 0) continue;
        std::wstring candidates[2] = { volume + image.path, volume + image.path };
        size_t count = 1;
        if (image.path == wcsstr(image.path, L"\\Windows\\System32")) {
            candidates[1].replace(volume.size(), wcslen(L"\\Windows\\System32"), L"\\Windows\\SysWOW64");
            count = 2;
        }
        for (size_t index = 0; index < count; index++) {
            const std::wstring& candidate = candidates[index];
            bool matches = (rule.Flags & KFILTER_RULE_EXACT) != 0
                ? KfMatchGlob(rule.Path, patternLength, candidate.c_str(), (ULONG)candidate.size()) != 0
                : KfPathMatches(rule.Path, patternLength, candidate.c_str(), (ULONG)candidate.size()) != 0;
            if (matches) return true;
        }
    }
    return false;
}

/* Checked decimal port: digits only, whole string consumed, 0-65535. */
static bool ParsePort(const std::string& text, ULONG& port)
{
    ULONG value = 0;
    if (text.empty()) return false;
    for (char c : text) {
        if (c < '0' || c > '9') return false;
        value = value * 10 + (ULONG)(c - '0');
        if (value > 65535) return false;
    }
    port = value;
    return true;
}

/* Checked decimal prefix length: digits only, whole string, 0-128. The
 * family-specific limit (32/128) is applied once ip= decides the family. */
static bool ParsePrefix(const std::wstring& text, ULONG& prefix)
{
    ULONG value = 0;
    if (text.empty()) return false;
    for (wchar_t c : text) {
        if (c < L'0' || c > L'9') return false;
        value = value * 10 + (ULONG)(c - L'0');
        if (value > 128) return false;
    }
    prefix = value;
    return true;
}

static bool ParseNetworkRule(const std::vector<std::string>& fields, ULONG action,
                             KFILTER_CONFIG* config, std::string& error)
{
    KFILTER_NET_RULE rule{};
    bool hasRights = false;
    rule.Action = action;
    for (size_t index = 2; index < fields.size(); index++) {
        const std::string& field = fields[index];
        if (field.rfind("ip=", 0) == 0) {
            std::wstring address = Utf8ToWide(field.substr(3));
            size_t slash = address.find(L'/');
            bool hasPrefix = slash != std::wstring::npos;
            if (hasPrefix) {
                /* An explicit /0 must stay 0: it is a valid any-address rule,
                 * not a missing prefix. */
                if (!ParsePrefix(address.substr(slash + 1), rule.PrefixLength)) {
                    error = "network prefix must be a complete number in 0-32/128";
                    return false;
                }
                address = address.substr(0, slash);
            }
            IN_ADDR v4{};
            IN6_ADDR v6{};
            if (InetPtonW(AF_INET, address.c_str(), &v4) == 1) {
                rule.Family = 4;
                if (!hasPrefix) rule.PrefixLength = 32;
                else if (rule.PrefixLength > 32) {
                    error = "network IPv4 prefix must be 0-32";
                    return false;
                }
                memcpy(rule.Address, &v4, 4);
            } else if (InetPtonW(AF_INET6, address.c_str(), &v6) == 1) {
                rule.Family = 6;
                if (!hasPrefix) rule.PrefixLength = 128;
                memcpy(rule.Address, &v6, 16);
            } else {
                error = "network ip is not IPv4/IPv6";
                return false;
            }
        } else if (field.rfind("port=", 0) == 0) {
            if (!ParsePort(field.substr(5), rule.Port)) {
                error = "network port must be a complete number in 0-65535";
                return false;
            }
        } else if (field.rfind("proto=", 0) == 0) {
            std::string proto = field.substr(6);
            if (proto == "tcp") rule.Protocol = 6;
            else if (proto == "udp") rule.Protocol = 17;
            else if (proto == "any") rule.Protocol = 0;
            else { error = "network proto must be tcp/udp/any"; return false; }
        } else if (field.rfind("rights=", 0) == 0) {
            hasRights = true;
            if (!ParseRights(field.substr(7), rule.Rights, error)) return false;
            if ((rule.Rights & ~(KFILTER_RIGHT_CONNECT | KFILTER_RIGHT_LISTEN)) != 0) {
                error = "network rights must be connect and/or listen";
                return false;
            }
        } else if (field.rfind("risk=", 0) == 0) {
            if (!ParseRisk(field, rule.Risk, error)) return false;
        } else if (field.rfind("image=", 0) == 0) {
            if (!ParseImage(field, rule.Image, error)) return false;
        } else {
            bool handled = false;
            if (!ParseCountField(field, rule.Count, handled, error)) return false;
            if (!handled) {
                error = "unknown network field '" + field + "'";
                return false;
            }
        }
    }
    rule.Count = CompleteCount(rule.Count);
    if (rule.Family == 0) { error = "network rule needs ip="; return false; }
    if (rule.PrefixLength > (rule.Family == 4 ? 32u : 128u)) { error = "network prefix too long"; return false; }
    if (action == KFilterActionAllow && (!hasRights || rule.Rights == 0)) {
        error = "allow network rule needs nonzero rights=";
        return false;
    }
    if (action == KFilterActionAllow && rule.Risk[0] == L'\0') {
        error = "allow network rule needs risk=<reason>";
        return false;
    }
    /* An allow is an exception for one reviewed endpoint: one host, one port and protocol,
     * connect only, counted. Ranges, any-port and listen stay possible for deny rules only. */
    if (action == KFilterActionAllow &&
        (rule.PrefixLength != (rule.Family == 4 ? 32u : 128u) || rule.Port == 0 || rule.Protocol == 0 ||
         rule.Rights != KFILTER_RIGHT_CONNECT || (rule.Count & KFILTER_COUNT_USES) == 0)) {
        error = "allow network rule must be one host ip (/32 or /128) with port=, proto=tcp|udp, "
                "rights=connect and uses=N";
        return false;
    }
    if (config->NetworkRuleCount >= KFILTER_MAX_NET_RULES) { error = "too many network rules"; return false; }
    rule.RuleId = 10000 + config->NetworkRuleCount + 1;
    config->Network[config->NetworkRuleCount++] = rule;
    return true;
}

/* "A-B" or "N" (N = A = B); bounds 1..2^31. */
static bool ParseRange(const std::string& text, ULONG& low, ULONG& high)
{
    size_t dash = text.find('-');
    std::string a = dash == std::string::npos ? text : text.substr(0, dash);
    std::string b = dash == std::string::npos ? text : text.substr(dash + 1);
    auto number = [](const std::string& digits, ULONG& value) {
        if (digits.empty() || digits.size() > 10) return false;
        unsigned long long parsed = 0;
        for (char c : digits) {
            if (c < '0' || c > '9') return false;
            parsed = parsed * 10 + (unsigned long long)(c - '0');
        }
        if (parsed == 0 || parsed > 0x7FFFFFFFull) return false;
        value = (ULONG)parsed;
        return true;
    };
    return number(a, low) && number(b, high) && low <= high;
}

/*
 * deny|message|[ip=A[/P]]|[port=N]|[proto=tcp|udp]|[rights=send,receive]|[size=A-B]|
 *     [index=A-B]|[match=HEX[@OFFSET]]|[image=...]|[module=...]|[uses=N]|[phase=P]|[opens]|[risk=...]
 * deny|message|unix=PATH|[size=A-B]|[index=A-B]|[match=HEX[@OFFSET]]|[image=...]|[module=...]|...
 * Decides each message a protected program sends (default) or receives on a connection,
 * after the connection itself was allowed. Receives are decided before their data exists,
 * so size= and match= apply to sends only. module= (Linux, under Wine) names the program's
 * DLL or EXE whose code made the call. unix= (Linux, ABI 12) instead decides each send to an AF_UNIX peer, a glob on
 * its whole name (/tmp/.X11-unix/X5, /@name for an abstract one): a connected socket's peer by its bound path with
 * symlinks resolved, a sendto's by the address as written (a relative one from the cwd); only unix= rules meet those.
 */
static bool ParseMessageRule(const std::vector<std::string>& fields, ULONG action,
                             KFILTER_CONFIG* config, std::string& error)
{
    KFILTER_NET_RULE rule{};
    rule.Action = action;
    rule.Rights = KFILTER_RIGHT_SEND;
    bool ip = false;
    for (size_t index = 2; index < fields.size(); index++) {
        const std::string& field = fields[index];
        if (field.rfind("unix=", 0) == 0) {
            const std::wstring peer = Utf8ToWide(field.substr(5));
            if (peer.empty() || peer[0] != L'/' || peer.size() >= KFILTER_MAX_VALUE) {
                error = "unix= takes the peer's address as a path shorter than 128 characters: /tmp/.X11-unix/X5, or "
                        "/@name for an abstract one";
                return false;
            }
            wcscpy_s(rule.Unix, KFILTER_MAX_VALUE, peer.c_str());
        } else if (field.rfind("ip=", 0) == 0) {
            ip = true;
            std::wstring address = Utf8ToWide(field.substr(3));
            size_t slash = address.find(L'/');
            bool hasPrefix = slash != std::wstring::npos;
            if (hasPrefix) {
                if (!ParsePrefix(address.substr(slash + 1), rule.PrefixLength)) {
                    error = "message ip prefix must be a complete number in 0-32/128";
                    return false;
                }
                address = address.substr(0, slash);
            }
            IN_ADDR v4{};
            IN6_ADDR v6{};
            if (InetPtonW(AF_INET, address.c_str(), &v4) == 1) {
                rule.Family = 4;
                if (!hasPrefix) rule.PrefixLength = 32;
                if (rule.PrefixLength > 32) { error = "message IPv4 prefix must be 0-32"; return false; }
                memcpy(rule.Address, &v4, 4);
            } else if (InetPtonW(AF_INET6, address.c_str(), &v6) == 1) {
                rule.Family = 6;
                if (!hasPrefix) rule.PrefixLength = 128;
                memcpy(rule.Address, &v6, 16);
            } else {
                error = "message ip is not IPv4/IPv6";
                return false;
            }
        } else if (field.rfind("port=", 0) == 0) {
            if (!ParsePort(field.substr(5), rule.Port)) { error = "message port must be 0-65535"; return false; }
        } else if (field.rfind("proto=", 0) == 0) {
            std::string proto = field.substr(6);
            if (proto == "tcp") rule.Protocol = 6;
            else if (proto == "udp") rule.Protocol = 17;
            else if (proto == "any") rule.Protocol = 0;
            else { error = "message proto must be tcp/udp/any"; return false; }
        } else if (field.rfind("rights=", 0) == 0) {
            if (!ParseRights(field.substr(7), rule.Rights, error)) return false;
            if (rule.Rights == 0 || (rule.Rights & ~KFILTER_RIGHTS_MESSAGE) != 0) {
                error = "message rights are send and/or receive";
                return false;
            }
        } else if (field.rfind("size=", 0) == 0) {
            if (!ParseRange(field.substr(5), rule.SizeMin, rule.SizeMax)) {
                error = "size= takes a byte count or a range A-B (1 or more)";
                return false;
            }
        } else if (field.rfind("index=", 0) == 0) {
            if (!ParseRange(field.substr(6), rule.IndexMin, rule.IndexMax)) {
                error = "index= takes a message number or a range A-B (1 = the first)";
                return false;
            }
        } else if (field.rfind("match=", 0) == 0) {
            std::string text = field.substr(6);
            size_t at = text.find('@');
            std::string hex = at == std::string::npos ? text : text.substr(0, at);
            if (hex.rfind("0x", 0) == 0 || hex.rfind("0X", 0) == 0) hex = hex.substr(2);
            if (hex.empty() || hex.size() % 2 != 0 || hex.size() / 2 > KFILTER_MAX_MATCH) {
                error = "match= takes 1 to 16 bytes of hex, e.g. match=0A1B2C@4";
                return false;
            }
            for (size_t i = 0; i < hex.size(); i += 2) {
                char* end = nullptr;
                std::string pair = hex.substr(i, 2);
                unsigned long byte = strtoul(pair.c_str(), &end, 16);
                if (end == nullptr || *end != '\0') { error = "match= bytes must be hex"; return false; }
                rule.Match[i / 2] = (unsigned char)byte;
            }
            rule.MatchLength = (ULONG)(hex.size() / 2);
            if (at != std::string::npos) {
                ULONG low = 0, high = 0;
                std::string offset = text.substr(at + 1);
                if (offset == "0") {
                    rule.MatchOffset = 0;
                } else if (!ParseRange(offset, low, high) || low != high || low > 4096) {
                    error = "match= offset must be 0-4096";
                    return false;
                } else {
                    rule.MatchOffset = low;
                }
            }
        } else if (field.rfind("image=", 0) == 0) {
            if (!ParseImage(field, rule.Image, error)) return false;
        } else if (field.rfind("module=", 0) == 0) {
            std::wstring module = Utf8ToWide(field.substr(7));
            if (module.empty() || module.size() >= KFILTER_MAX_IMAGE || module.find_first_of(L"\\/") != std::wstring::npos) {
                error = "module= takes a DLL or EXE file name pattern (no path) shorter than 64 characters";
                return false;
            }
            wcscpy_s(rule.Module, KFILTER_MAX_IMAGE, module.c_str());
        } else if (field.rfind("risk=", 0) == 0) {
            if (!ParseRisk(field, rule.Risk, error)) return false;
        } else {
            bool handled = false;
            if (!ParseCountField(field, rule.Count, handled, error)) return false;
            if (!handled) { error = "unknown message field '" + field + "'"; return false; }
        }
    }
    rule.Count = CompleteCount(rule.Count);
    if (rule.Unix[0] != L'\0') {
        if (ip || rule.Port != 0 || rule.Protocol != 0) { error = "unix= names the peer alone: no ip=, port= or proto="; return false; }
        if (rule.Rights != KFILTER_RIGHT_SEND) { error = "unix= decides sends only (rights=send)"; return false; }
        rule.Family = KFILTER_NET_FAMILY_UNIX;
    }
    if ((rule.Rights & KFILTER_RIGHT_RECEIVE) != 0 && (rule.SizeMax != 0 || rule.MatchLength != 0)) {
        error = "size= and match= decide sends only: a receive is decided before its data arrives";
        return false;
    }
    if (rule.MatchLength != 0 && rule.MatchOffset + rule.MatchLength > 4096) {
        error = "match= must lie within the first 4096 bytes of a message";
        return false;
    }
    if (config->NetworkRuleCount >= KFILTER_MAX_NET_RULES) { error = "too many network rules"; return false; }
    rule.RuleId = 10000 + config->NetworkRuleCount + 1;
    config->Network[config->NetworkRuleCount++] = rule;
#ifndef _WIN32
    (void)0;
#else
    std::fprintf(stderr, "note: message rule %" KF_U " is enforced only by the Linux BPF layer\n", rule.RuleId);
#endif
    return true;
}

#ifndef _WIN32
/* /system/syscall/<name>: the calls of this kernel's two tables (linux/bpf/kfilter_syscalls.h), and those every
 * process makes all the time, which only a rule naming their argument decides. */
struct SyscallName {
    const char* name;
    bool hot;
};
static const SyscallName kSyscallNames[] = {
#define KB_SYSCALL(abi, nr, name, key, argument, mask, address, length, query, hot) {name, hot != 0},
#include "../linux/bpf/kfilter_syscalls.h"
#undef KB_SYSCALL
};

/* The call a /system/syscall/... path names literally (its second segment, with no '*'), "" for any other path. */
static std::string SyscallOf(const std::wstring& path)
{
    static const std::wstring space = L"/system/syscall/";
    if (path.compare(0, space.size(), space) != 0) return "";
    const std::wstring name = path.substr(space.size(), path.find(L'/', space.size()) - space.size());
    return name.find(L'*') == std::wstring::npos ? WideToUtf8(name) : "";
}

static bool SyscallHot(const std::string& name)
{
    for (const SyscallName& call : kSyscallNames) {
        if (name == call.name) return call.hot;
    }
    return false;
}

/* A rule on a hot call that does not name its argument (/system/syscall/futex, /system/syscall/futex/x...) would
 * refuse every one of Wine's waits or signal masks: the kernel never lets it meet them, so it is refused here. */
static bool SyscallScoped(const std::wstring& path)
{
    const std::string name = SyscallOf(path);
    if (name.empty() || !SyscallHot(name)) return true;
    const size_t key = 16 + Utf8ToWide(name).size() + 1;   /* past "/system/syscall/<name>/" */
    return path.size() > key && path[key - 1] == L'/' && path[key] != L'*';
}
#endif

static bool ParsePolicy(const std::wstring& path, KFILTER_CONFIG* config, std::string& error)
{
    FILE* file = nullptr;
    if (_wfopen_s(&file, path.c_str(), L"rb") != 0 || file == nullptr) { error = "cannot open policy file"; return false; }
    std::string raw;
    char buffer[4096];
    size_t read;
    while ((read = fread(buffer, 1, sizeof(buffer), file)) > 0) raw.append(buffer, read);
    fclose(file);
    if (raw.size() >= 3 && (unsigned char)raw[0] == 0xEF && (unsigned char)raw[1] == 0xBB && (unsigned char)raw[2] == 0xBF) raw.erase(0, 3);

    memset(config, 0, sizeof(*config));
    config->AbiVersion = KFILTER_ABI_VERSION;
    config->Mode = KFILTER_MODE_AUDIT;
    config->Flags = KFILTER_CFG_NET_ALLOW_LOOPBACK;

    size_t offset = 0;
    while (offset <= raw.size()) {
        size_t end = raw.find('\n', offset);
        std::string line = raw.substr(offset, end == std::string::npos ? std::string::npos : end - offset);
        offset = (end == std::string::npos) ? raw.size() + 1 : end + 1;
        Trim(line);
        if (line.empty() || line[0] == '#') continue;
        auto fields = Split(line, '|');
        if (fields.size() == 1) fields = SplitWhitespace(line);
        const std::string& verb = fields[0];

        if (verb == "mode") {
            if (fields.size() < 2) { error = "mode needs audit|block|off"; return false; }
            if (fields[1] == "audit") config->Mode = KFILTER_MODE_AUDIT;
            else if (fields[1] == "block") config->Mode = KFILTER_MODE_BLOCK;
            else if (fields[1] == "off") config->Mode = KFILTER_MODE_OFF;
            else { error = "unknown mode"; return false; }
            continue;
        }
        if (verb == "root") {
            if (fields.size() < 2) { error = "root needs a path"; return false; }
            std::wstring nt = ToNtPath(Utf8ToWide(fields[1]), error);
            if (nt.empty() || nt.size() >= KFILTER_MAX_NAME) { if (error.empty()) error = "root path too long"; return false; }
            if (nt.find(L'*') != std::wstring::npos) { error = "root must not contain a wildcard"; return false; }
            wcscpy_s(config->Root, KFILTER_MAX_NAME, nt.c_str());
            continue;
        }
        if (verb == "appcontainer") {
            if (fields.size() < 2) { error = "appcontainer needs a profile name"; return false; }
#ifndef _WIN32
            /* No package SIDs on Linux: `kfilterctl launch` puts the family in the kfilter
             * cgroup instead. Loadable, not enforced. */
            std::fprintf(stderr, "note: appcontainer %s is not enforced on Linux\n", fields[1].c_str());
            continue;
#else
            PSID sid = nullptr;
            HRESULT hr = DeriveAppContainerSidFromAppContainerName(Utf8ToWide(fields[1]).c_str(), &sid);
            if (FAILED(hr) || sid == nullptr) { error = "invalid AppContainer profile name"; return false; }
            ULONG length = GetLengthSid(sid);
            if (length > KFILTER_MAX_SID) { FreeSid(sid); error = "AppContainer SID too long"; return false; }
            memcpy(config->PackageSid, sid, length);
            config->PackageSidLength = length;
            FreeSid(sid);
            continue;
#endif
        }
        if (verb == "protect") {
            if (fields.size() < 2) { error = "protect needs an image name"; return false; }
            if (config->ProtectedCount >= KFILTER_MAX_PROTECTED) { error = "too many protect entries"; return false; }
            std::wstring name = Utf8ToWide(fields[1]);
            if (name.empty() || name.size() + (PolicyAbsolute(name[0]) ? 0u : 1u) >= KFILTER_MAX_NAME) { error = "protect name too long"; return false; }
#ifndef _WIN32
            /* '/' names a Linux executable; anything else is a Windows program run under Wine,
             * matched on its Windows image (protect MapleStory.exe or protect \MapleStory.exe). */
            if (!PolicyAbsolute(name[0])) name.insert(name.begin(), L'\\');
#else
            if (name[0] != L'\\') name.insert(name.begin(), L'\\');
#endif
            wcscpy_s(config->Protected[config->ProtectedCount], KFILTER_MAX_NAME, name.c_str());
            config->ProtectedCount++;
            continue;
        }
        if (verb == "block-files") { if (fields.size() > 1 && fields[1] == "off") config->Flags &= ~KFILTER_CFG_BLOCK_FILES; else config->Flags |= KFILTER_CFG_BLOCK_FILES; continue; }
        if (verb == "block-registry") { if (fields.size() > 1 && fields[1] == "off") config->Flags &= ~KFILTER_CFG_BLOCK_REGISTRY; else config->Flags |= KFILTER_CFG_BLOCK_REGISTRY; continue; }
        if (verb == "block-volume-serial") { if (fields.size() > 1 && fields[1] == "off") config->Flags &= ~KFILTER_CFG_BLOCK_VOLUME_SERIAL; else config->Flags |= KFILTER_CFG_BLOCK_VOLUME_SERIAL; continue; }
        if (verb == "block-process-memory") { if (fields.size() > 1 && fields[1] == "off") config->Flags &= ~KFILTER_CFG_BLOCK_PROCESS_MEMORY; else config->Flags |= KFILTER_CFG_BLOCK_PROCESS_MEMORY; continue; }
        if (verb == "block-process-create") { if (fields.size() > 1 && fields[1] == "off") config->Flags &= ~KFILTER_CFG_BLOCK_PROCESS_CREATE; else config->Flags |= KFILTER_CFG_BLOCK_PROCESS_CREATE; continue; }
        if (verb == "block-raw-disk") { if (fields.size() > 1 && fields[1] == "off") config->Flags &= ~KFILTER_CFG_BLOCK_RAW_DISK; else config->Flags |= KFILTER_CFG_BLOCK_RAW_DISK; continue; }
        if (verb == "block-network") { if (fields.size() > 1 && fields[1] == "off") config->Flags &= ~KFILTER_CFG_BLOCK_NETWORK; else config->Flags |= KFILTER_CFG_BLOCK_NETWORK; continue; }
        if (verb == "block-network-adapter") { if (fields.size() > 1 && fields[1] == "off") config->Flags &= ~KFILTER_CFG_BLOCK_NETWORK_ADAPTER; else config->Flags |= KFILTER_CFG_BLOCK_NETWORK_ADAPTER; continue; }
        if (verb == "block-file-queries") {
#ifndef _WIN32   /* Windows already decides attributes-only creates as query */
            if (fields.size() > 1 && fields[1] == "off") config->Flags &= ~KFILTER_CFG_BLOCK_FILE_QUERIES;
            else config->Flags |= KFILTER_CFG_BLOCK_FILE_QUERIES;
#endif
            continue;
        }
        if (verb == "block-process-signals" || verb == "block-process-queries") {
#ifndef _WIN32   /* Linux's BPF layer: signals and PTRACE_MODE_READ checks across the family's boundary */
            const ULONG flag = verb == "block-process-signals" ? KFILTER_CFG_BLOCK_PROCESS_SIGNALS : KFILTER_CFG_BLOCK_PROCESS_QUERIES;
            if (fields.size() > 1 && fields[1] == "off") config->Flags &= ~flag;
            else config->Flags |= flag;
#endif
            continue;
        }
        if (verb == "block-direct-syscall") {
#ifndef _WIN32   /* on Windows a direct syscall is an ordinary NT syscall, decided as any other */
            if (fields.size() > 1 && fields[1] == "off") config->Flags &= ~KFILTER_CFG_BLOCK_DIRECT_SYSCALL;
            else config->Flags |= KFILTER_CFG_BLOCK_DIRECT_SYSCALL;
#endif
            continue;
        }
        if (verb == "default-deny") {
            if (fields.size() > 1 && fields[1] == "off") config->Flags &= ~KFILTER_CFG_DEFAULT_DENY;
            else config->Flags |= KFILTER_CFG_DEFAULT_DENY;
            continue;
        }
        if (verb == "network-default") {
            if (fields.size() < 2 || (fields[1] != "allow" && fields[1] != "deny")) { error = "network-default needs allow|deny"; return false; }
            if (fields[1] == "allow") config->Flags |= KFILTER_CFG_NET_DEFAULT_ALLOW;
            else config->Flags &= ~KFILTER_CFG_NET_DEFAULT_ALLOW;
            continue;
        }
        if (verb == "message-default") {
            if (fields.size() < 2 || (fields[1] != "allow" && fields[1] != "deny")) { error = "message-default needs allow|deny"; return false; }
            if (fields[1] == "deny") config->Flags |= KFILTER_CFG_MESSAGE_DEFAULT_DENY;
            else config->Flags &= ~KFILTER_CFG_MESSAGE_DEFAULT_DENY;
            continue;
        }
        if (verb == "network-loopback") {
            if (fields.size() > 1 && fields[1] == "off") config->Flags &= ~KFILTER_CFG_NET_ALLOW_LOOPBACK;
            else config->Flags |= KFILTER_CFG_NET_ALLOW_LOOPBACK;
            continue;
        }

        if (verb != "allow" && verb != "deny" && verb != "audit") {
            error = "unknown directive '" + verb + "'"; return false;
        }
        if (fields.size() < 2) { error = "rule needs a target"; return false; }
        ULONG action = verb == "allow" ? KFilterActionAllow
                     : verb == "deny" ? KFilterActionDeny : KFilterActionAudit;
        if (fields[1] == "network") {
            if (!ParseNetworkRule(fields, action, config, error)) return false;
            continue;
        }
        if (fields[1] == "message") {
            if (!ParseMessageRule(fields, action, config, error)) return false;
            continue;
        }

        KFILTER_RULE rule{};
        rule.Action = action;
        rule.RuleId = config->RuleCount + 1;
        if (fields[1] == "file") rule.Targets = KFILTER_TARGET_FILE;
        else if (fields[1] == "dir") rule.Targets = KFILTER_TARGET_DIR;
        else if (fields[1] == "registry") rule.Targets = KFILTER_TARGET_REGISTRY;
        else if (fields[1] == "process") rule.Targets = KFILTER_TARGET_PROCESS;
        else if (fields[1] == "volume") rule.Targets = KFILTER_TARGET_VOLUME;
        else if (fields[1] == "device") rule.Targets = KFILTER_TARGET_DEVICE;
        else if (fields[1] == "pipe") rule.Targets = KFILTER_TARGET_PIPE;
        else if (fields[1] == "handle") rule.Targets = KFILTER_TARGET_HANDLE;
        else if (fields[1] == "open") rule.Targets = KFILTER_TARGET_OPEN;
        else if (fields[1] == "launch") rule.Targets = KFILTER_TARGET_LAUNCH;
        else if (fields[1] == "thread-handle") rule.Targets = KFILTER_TARGET_THREAD_HANDLE;
        else if (fields[1] == "thread-open") rule.Targets = KFILTER_TARGET_THREAD_OPEN;
        else if (fields[1] == "peer") rule.Targets = KFILTER_TARGET_PEER;
        else if (fields[1] == "thread-peer") rule.Targets = KFILTER_TARGET_THREAD_PEER;
        else if (fields[1] == "system") rule.Targets = KFILTER_TARGET_SYSTEM;
        else if (fields[1] == "dns") rule.Targets = KFILTER_TARGET_DNS;
        else if (fields[1] == "thread") rule.Targets = KFILTER_TARGET_THREAD;
        else { error = "unknown target '" + fields[1] + "'"; return false; }
        bool outside = (rule.Targets & KFILTER_TARGETS_OUTSIDE) != 0;
        bool peer = rule.Targets == KFILTER_TARGET_PEER || rule.Targets == KFILTER_TARGET_THREAD_PEER;
        /* handle, open, launch, peer and thread rules name a program; a dns rule names a host. */
        bool program = outside || peer || rule.Targets == KFILTER_TARGET_THREAD;
        bool dns = rule.Targets == KFILTER_TARGET_DNS;
        bool access = (outside && rule.Targets != KFILTER_TARGET_LAUNCH) || peer;
        bool thread = rule.Targets == KFILTER_TARGET_THREAD_HANDLE || rule.Targets == KFILTER_TARGET_THREAD_OPEN ||
                      rule.Targets == KFILTER_TARGET_THREAD_PEER;

        if (fields.size() < 3 || fields[2].empty()) { error = "rule needs a path"; return false; }
        std::wstring pathValue = Utf8ToWide(fields[2]);
        if (pathValue.empty() || pathValue.size() + (PolicyAbsolute(pathValue[0]) ? 0u : 1u) >= KFILTER_MAX_NAME) { error = "rule path too long"; return false; }
#ifndef _WIN32
        if (gLinuxPaths) {
            /* Registry rules name NT keys (\REGISTRY\...), decided by the BPF layer from
             * Wine's requests. handle/open/launch rules name the other program: a Linux
             * path, or under Wine its Windows image (C:\... or a pattern starting with \).
             * file and pipe rules also name Wine's NT objects (\??\PhysicalDrive0, \??\pipe\x,
             * \Device\Afd), which the BPF layer decides from Wine's open_file_object and
             * create_named_pipe, and volume rules Wine's volume queries on them (get_volume_info:
             * \??\C:, \Device\Volume). Every other path is a Linux path. */
            const bool ntObject = (rule.Targets == KFILTER_TARGET_FILE || rule.Targets == KFILTER_TARGET_PIPE ||
                                   rule.Targets == KFILTER_TARGET_VOLUME) &&
                                  pathValue[0] == L'\\';
            bool windowsName = ntObject || rule.Targets == KFILTER_TARGET_REGISTRY || program || dns;
            if (rule.Targets == KFILTER_TARGET_REGISTRY && pathValue[0] != L'\\') {
                error = "registry rule paths are NT key names (\\REGISTRY\\...): " + fields[2];
                return false;
            }
            if (program && !PolicyAbsolute(pathValue[0]) && !DrivePath(pathValue)) {
                error = "handle, open, launch, peer and thread rules name a Linux path, a C:\\ path or a \\ pattern: " + fields[2];
                return false;
            }
            if (dns && PolicyAbsolute(pathValue[0])) {
                error = "dns rules name a host (wpad, *.example.com), not a path: " + fields[2];
                return false;
            }
            if (!windowsName && pathValue[0] != L'/') {
                error = "Linux rule paths start with '/' (or name a Wine NT object starting with \\, file, pipe and volume rules only): " + fields[2];
                return false;
            }
        }
        if (!dns && !PolicyAbsolute(pathValue[0]) && !(program && DrivePath(pathValue))) {
            pathValue.insert(pathValue.begin(), gLinuxPaths ? L'/' : L'\\');
        }
#else
        if (!dns && pathValue[0] != L'\\') pathValue.insert(pathValue.begin(), L'\\');
#endif
        if (KfPathEndsWithSeparator(pathValue.c_str(), (unsigned long)pathValue.size())) {
            error = "rule path must not end with a separator";
            return false;
        }
#ifndef _WIN32
        if (rule.Targets == KFILTER_TARGET_SYSTEM && !SyscallScoped(pathValue)) {
            error = "every process calls " + SyscallOf(pathValue) + " all the time: a rule on it names its argument "
                    "(/system/syscall/" + SyscallOf(pathValue) + "/<key>; a deny of every call would stop Wine): " + fields[2];
            return false;
        }
#endif
        /* WQL class names have no case: WMI decisions name the class lowercased. */
        if (rule.Targets == KFILTER_TARGET_SYSTEM && pathValue.rfind(L"/system/wmi/", 0) == 0) {
            for (wchar_t& c : pathValue) c = (wchar_t)towlower(c);
        }
        wcscpy_s(rule.Path, KFILTER_MAX_NAME, pathValue.c_str());
        bool hasRights = false;
        bool hasUses = false;
        if (rule.Targets == KFILTER_TARGET_DEVICE && action == KFilterActionAllow) {
            hasRights = true;
            rule.Rights = KFILTER_RIGHT_RAW_DEVICE;
            rule.Flags |= KFILTER_RULE_EXACT;
        }

        for (size_t index = 3; index < fields.size(); index++) {
            const std::string& field = fields[index];
            bool handled = false;
            if (!ParseCountField(field, rule.Count, handled, error)) return false;
            if (handled) {
                if (field.rfind("uses=", 0) == 0) hasUses = true;
                continue;
            } else if (field.rfind("rights=", 0) == 0) {
                hasRights = true;
                bool pseudo = false;
                bool parsed = access ? ParseAccessRights(field.substr(7), thread, rule.Rights, error,
                                                         rule.Targets == KFILTER_TARGET_PEER, &pseudo)
                                     : ParseRights(field.substr(7), rule.Rights, error);
                if (!parsed) return false;
                if (pseudo) rule.Flags |= KFILTER_RULE_PSEUDO;
            } else if (field.rfind("risk=", 0) == 0) {
                if (!ParseRisk(field, rule.Risk, error)) return false;
            } else if (field.rfind("image=", 0) == 0) {
                if (!ParseImage(field, rule.Image, error)) return false;
            } else if (field.rfind("account=", 0) == 0) {
                if (!outside) { error = "account= applies only to handle, open and launch rules"; return false; }
                if (field.substr(8) == "system") rule.Account = KFILTER_ACCOUNT_SYSTEM;
                else if (field.substr(8) == "any") rule.Account = KFILTER_ACCOUNT_ANY;
                else { error = "account must be system or any"; return false; }
            } else if (field.rfind("addr=", 0) == 0) {
                if (!peer && rule.Targets != KFILTER_TARGET_SYSTEM) {
                    error = "addr= applies to peer, thread-peer and system rules"; return false;
                }
                if ((rule.Flags & KFILTER_RULE_MODULE) != 0 || rule.Value[0] != L'\0') {
                    error = "addr= cannot be combined with value= or module="; return false;
                }
                if (!ParseAddress(field, rule, error)) return false;
            } else if (peer && field.rfind("value=", 0) == 0) {
                /* Linux (ABI 11): a window message, offset or key (0x%08X), or the Wine request a decision on what a
                 * handle at any offset reaches names; a glob, without case. */
                std::wstring value = Utf8ToWide(field.substr(6));
                if (value.empty() || value.size() >= KFILTER_MAX_VALUE) { error = "value= needs a value shorter than 128"; return false; }
                if ((rule.Flags & KFILTER_RULE_ADDRESS) != 0) { error = "addr= cannot be combined with value= or module="; return false; }
                wcscpy_s(rule.Value, KFILTER_MAX_VALUE, value.c_str());
            } else if (outside || peer) {
                error = "handle, open, launch and peer rules take only rights=, account=, risk=, image=, phase=, uses=, opens "
                        "and (peer rules) addr= and value="; return false;
            } else if (field.rfind("ext=", 0) == 0) {
                if (!ParseExtensions(field.substr(4), rule.Extensions, error)) return false;
            } else if (field.rfind("value=", 0) == 0) {
                std::wstring value = Utf8ToWide(field.substr(6));
                if (value.size() >= KFILTER_MAX_VALUE) { error = "value name too long"; return false; }
                if ((rule.Flags & KFILTER_RULE_MODULE) != 0) { error = "value= and module= cannot be combined"; return false; }
                if ((rule.Flags & KFILTER_RULE_ADDRESS) != 0) { error = "addr= cannot be combined with value= or module="; return false; }
                if (rule.Targets == KFILTER_TARGET_DEVICE && action == KFilterActionAllow) {
                    /* 0x<ioctl>, or 0x<ioctl>:0x<its argument's first 32 bits> (Linux), eight hexadecimal digits each */
                    auto hex = [&](size_t at) {
                        if (value.size() < at + 10 || value[at] != L'0' || value[at + 1] != L'x') return false;
                        for (size_t digit = at + 2; digit < at + 10; digit++) {
                            if (!iswxdigit(value[digit])) return false;
                        }
                        return true;
                    };
                    const bool argument = value.size() == 21 && value[10] == L':' && hex(11);
                    if (!hex(0) || (value.size() != 10 && !argument)) {
                        error = "device value must be 0x followed by eight hexadecimal digits (and :0x and eight more)";
                        return false;
                    }
                    ULONG ioctl = wcstoul(value.c_str() + 2, nullptr, 16);
                    if (argument) {
                        swprintf_s(rule.Value, KFILTER_MAX_VALUE, L"0x%08lX:0x%08lX", (unsigned long)ioctl,
                                   (unsigned long)wcstoul(value.c_str() + 13, nullptr, 16));
                    } else {
                        swprintf_s(rule.Value, KFILTER_MAX_VALUE, L"0x%08lX", (unsigned long)ioctl);
                    }
                } else {
                    wcscpy_s(rule.Value, KFILTER_MAX_VALUE, value.c_str());
                }
            } else if (field == "exact") {
                rule.Flags |= KFILTER_RULE_EXACT;
            } else if (field == "hide") {
                if (action != KFilterActionDeny) { error = "hide applies to deny rules"; return false; }
                rule.Flags |= KFILTER_RULE_HIDE;
            } else if (field.rfind("module=", 0) == 0) {
                /* Value holds the module pattern: registry and device rules use it for their value. */
                std::wstring module = Utf8ToWide(field.substr(7));
                if (rule.Targets == KFILTER_TARGET_REGISTRY || rule.Targets == KFILTER_TARGET_DEVICE) {
                    error = "module= does not apply to registry and device rules"; return false;
                }
                if (module.empty() || module.size() >= KFILTER_MAX_VALUE) { error = "module= needs a pattern shorter than 128"; return false; }
                if ((rule.Flags & KFILTER_RULE_ADDRESS) != 0) { error = "addr= cannot be combined with value= or module="; return false; }
                if (rule.Value[0] != L'\0') { error = "value= and module= cannot be combined"; return false; }
                wcscpy_s(rule.Value, KFILTER_MAX_VALUE, module.c_str());
                rule.Flags |= KFILTER_RULE_MODULE;
            } else if (field == "data-only") {
                hasRights = true;
                rule.Rights = KFILTER_RIGHT_READ | KFILTER_RIGHT_WRITE;
            } else if (field == "execute-only") {
                hasRights = true;
                rule.Rights = KFILTER_RIGHT_EXECUTE;
            } else if (!field.empty()) {
                error = "unknown rule field '" + field + "'"; return false;
            }
        }
        if (action == KFilterActionAllow && (!hasRights || rule.Rights == 0)) {
            error = "allow rule needs nonzero rights=";
            return false;
        }
        if ((rule.Rights & KFILTER_RIGHTS_FILE_NAMED) != 0 && !access &&
            (rule.Targets & ~(KFILTER_TARGET_FILE | KFILTER_TARGET_DIR)) != 0) {
            error = "rights lock, chdir and touch apply to file and dir rules";
            return false;
        }
        rule.Count = CompleteCount(rule.Count);
        if (outside && action != KFilterActionAllow) {
            error = "handle, open and launch rules are exceptions: only allow is meaningful";
            return false;
        }
        if (rule.Targets == KFILTER_TARGET_LAUNCH && rule.Rights != KFILTER_RIGHT_CREATE) {
            error = "launch rules take rights=create";
            return false;
        }
        if (rule.Targets == KFILTER_TARGET_DEVICE && action == KFilterActionAllow &&
            (pathValue.find(L'*') != std::wstring::npos ||
             (!hasUses && KfDeviceDefaultDecided(pathValue.c_str(), (KF_ULONG)pathValue.size())) ||
             rule.Rights != KFILTER_RIGHT_RAW_DEVICE)) {
            error = "allow device rule needs an exact name, raw-device rights and uses=N "
                    "(uses= is optional only on a path no rule-less decision names, such as /dev/dri/...)";
            return false;
        }
        if (action == KFilterActionAllow && RuleNeedsRisk(rule) && rule.Risk[0] == L'\0') {
            error = "allow rule for a known identity risk needs risk=<reason>";
            return false;
        }
        /* No rights= on a deny or audit: every right (an access-mask rule: 0, any access). */
        if (!hasRights && !access) rule.Rights = KFILTER_RIGHTS_ALL;
        /* Metadata (query): whoever may act on a file may stat it (Wine stats before each open),
         * and a read deny hides it too (Windows decided attributes-only creates as read). */
        const ULONG acting = KFILTER_RIGHT_READ | KFILTER_RIGHT_WRITE | KFILTER_RIGHT_EXECUTE | KFILTER_RIGHT_ENUMERATE |
                             KFILTER_RIGHT_DELETE | KFILTER_RIGHT_RENAME | KFILTER_RIGHT_SET_SECURITY;
        if ((rule.Targets & (KFILTER_TARGET_FILE | KFILTER_TARGET_DIR | KFILTER_TARGET_PIPE)) != 0 &&
            (rule.Rights & (action == KFilterActionAllow ? acting : KFILTER_RIGHT_READ)) != 0) {
            rule.Rights |= KFILTER_RIGHT_QUERY;
        }
        if (config->RuleCount >= KFILTER_MAX_RULES) { error = "too many rules"; return false; }
        config->Rules[config->RuleCount++] = rule;
    }
    gFirstImplicit = config->RuleCount;
#ifndef _WIN32
    /* Strict file queries: the directories above what may be used can be stat'ed (realpath,
     * Wine's path lookups), up to the first wildcard. Listed after every explicit rule, so an
     * explicit deny still wins; "/" itself is never decided. */
    const ULONG strictQueries = KFILTER_CFG_BLOCK_FILE_QUERIES | KFILTER_CFG_DEFAULT_DENY;
    if ((config->Flags & strictQueries) == strictQueries) {
        std::vector<std::wstring> used{ config->Root }, added;
        for (ULONG index = 0; index < gFirstImplicit; index++) {
            const KFILTER_RULE& rule = config->Rules[index];
            if (rule.Action == KFilterActionAllow &&
                (rule.Targets & (KFILTER_TARGET_FILE | KFILTER_TARGET_DIR | KFILTER_TARGET_PIPE)) != 0) used.push_back(rule.Path);
        }
        for (const std::wstring& path : used) {
            size_t star = path.find(L'*');
            for (size_t end = path.find(L'/', 1); end != std::wstring::npos && end < star; end = path.find(L'/', end + 1)) {
                std::wstring ancestor = path.substr(0, end);
                if (std::find(added.begin(), added.end(), ancestor) != added.end()) continue;
                if (config->RuleCount >= KFILTER_MAX_RULES) { error = "too many rules"; return false; }
                added.push_back(ancestor);
                KFILTER_RULE& rule = config->Rules[config->RuleCount];
                rule = KFILTER_RULE{};
                rule.Action = KFilterActionAllow;
                rule.Targets = KFILTER_TARGET_DIR;
                rule.Rights = KFILTER_RIGHT_QUERY;
                rule.Flags = KFILTER_RULE_EXACT;
                rule.RuleId = ++config->RuleCount;
                wcscpy_s(rule.Path, KFILTER_MAX_NAME, ancestor.c_str());
            }
        }
    }
#endif

    if (config->ProtectedCount == 0 && config->Root[0] == L'\0') {
        error = "policy has neither protect entries nor a root";
        return false;
    }
#ifndef _WIN32
    if (gLinuxPaths) {
        struct { ULONG flag; const char* name; } bpfOnly[] = {
            { KFILTER_CFG_BLOCK_REGISTRY, "block-registry" },
            { KFILTER_CFG_BLOCK_VOLUME_SERIAL, "block-volume-serial" },
            { KFILTER_CFG_BLOCK_NETWORK_ADAPTER, "block-network-adapter" },
            { KFILTER_CFG_BLOCK_PROCESS_MEMORY, "block-process-memory" },
            { KFILTER_CFG_BLOCK_FILE_QUERIES, "block-file-queries" },
            { KFILTER_CFG_BLOCK_DIRECT_SYSCALL, "block-direct-syscall" },
            { KFILTER_CFG_BLOCK_PROCESS_SIGNALS, "block-process-signals" },
            { KFILTER_CFG_BLOCK_PROCESS_QUERIES, "block-process-queries" },
        };
        for (const auto& entry : bpfOnly) {
            if ((config->Flags & entry.flag) != 0) {
                std::fprintf(stderr, "note: %s is enforced only by kfilterd's BPF layer\n", entry.name);
            }
        }
    }
#endif
    return true;
}

#ifndef _WIN32
/* What `check` says beyond parsing: rules that load but do not do what they seem to. */
static void CheckWarnings(const KFILTER_CONFIG& config)
{
    for (ULONG index = 0; index < config.RuleCount; index++) {
        const KFILTER_RULE& rule = config.Rules[index];
        if (rule.Targets != KFILTER_TARGET_SYSTEM) continue;
        const std::string name = SyscallOf(rule.Path);
        bool known = name.empty();
        for (const SyscallName& call : kSyscallNames) known = known || name == call.name;
        if (!known) {
            std::fprintf(stderr, "warning: rule %" KF_U " names /system/syscall/%s, which neither of this kernel's syscall "
                                 "tables has (an ia32 call goes by its x86_64 name): it decides nothing\n",
                         rule.RuleId, name.c_str());
        }
        /* Wine's wineserver requests and replies: a refused one (EPERM) ends the Wine process (only EFAULT is safe). */
        for (const char* channel : {"read", "write", "readv", "writev", "recvmsg", "sendmsg", "close"}) {
            if (name != channel) continue;
            std::fprintf(stderr, "warning: rule %" KF_U " names /system/syscall/%s: Wine sends its wineserver requests and "
                                 "reads the replies with such calls (a refused one ends the Wine process), and each one a "
                                 "protected program makes is a decision while the rule is loaded\n",
                         rule.RuleId, name.c_str());
        }
        if (rule.Action == KFilterActionDeny && wcsncmp(rule.Path, L"/system/statfs", 14) == 0) {
            std::fprintf(stderr, "warning: rule %" KF_U " refuses statfs: Wine checks filesystem types with it (a refused "
                                 "one can break its file and volume calls)\n", rule.RuleId);
        }
    }
}
#endif

struct PolicyDecision {
    ULONG Action;
    ULONG RuleId;
};

#ifndef _WIN32
/*
 * Linux: simulate and evaluate run kfilterd's own decision path (driver/policy.c through
 * posix_shim.h), so an offline answer is the runtime one: first match with counted rules and
 * phases, image= rules, name failures. Declared with plain types because linux_compat.h's
 * HANDLE is not the shim's. (Windows cannot link policy.c into a user-mode tool; it keeps
 * the matcher-only EvaluatePolicy below.)
 */
struct KfOfflineString {   /* posix_shim.h UNICODE_STRING: Length in bytes */
    uint16_t Length;
    uint16_t MaximumLength;
    const wchar_t* Buffer;
};
static std::wstring gOfflineImage;   /* the requesting program, for image= rules */
extern "C" {
int32_t KfPolicyInitialize(void);
int32_t KfPolicySetConfig(const KFILTER_CONFIG* Config, ULONG Length);
uint8_t KfDecideWithRights(ULONG Target, const KfOfflineString* Path, ULONG Rights, const KfOfflineString* Value,
                           ULONG VolumeClass, ULONG* RuleIdOut, uint8_t* NameFailureOut, ULONG* ActionOut,
                           ULONG EventValue);
uint8_t KfPolicyValueEnumerationDenied(const KfOfflineString* KeyPath, ULONG* RuleIdOut);
/* What policy.c needs from the rest of kfilterd: offline every layer is up, the request is
 * a protected program's, and nothing is logged. (The BPF bench links kfilterd's own.) */
#ifndef KFILTERCTL_WITH_DAEMON
ULONG KfDriverRegisteredMask(void) { return 0xFFFFFFFFu; }
uint8_t KfDiskDegraded(void) { return 0; }
int32_t KfDiskRearm(void) { return 0; }
uint8_t KfDeviceDegraded(void) { return 0; }
uint8_t KfProcessIsProtectedCurrent(void) { return 1; }
void* PsGetCurrentProcessId(void) { return (void*)1; }
ULONG KfProcessTrackedCount(void) { return 0; }
ULONG KfDroppedEventCount(void) { return 0; }
void KfLogEvent(ULONG, ULONG, ULONG, int32_t, ULONG, ULONG, const KfOfflineString*) {}
ULONG KfProcessImageOf(void*, wchar_t* Buffer, ULONG Capacity)
{
    if (Buffer == nullptr || Capacity == 0) return 0;
    ULONG length = (ULONG)std::min<size_t>(gOfflineImage.size(), Capacity - 1);
    wmemcpy(Buffer, gOfflineImage.data(), length);
    Buffer[length] = L'\0';
    return length;
}
#endif
}

/* Publishes Config as the live generation: counted rules start over. */
static bool OfflineLoad(const KFILTER_CONFIG& config)
{
    static const bool initialized = KfPolicyInitialize() >= 0;
    /* Hand-built configs (self-test) may leave AbiVersion unset; kfilterctl always sends it. */
    size_t size = KFILTER_CONFIG_SIZE(config.RuleCount <= KFILTER_MAX_RULES ? config.RuleCount : 0);
    std::unique_ptr<char[]> copy(new char[size]);
    memcpy(copy.get(), &config, size);
    ((KFILTER_CONFIG*)copy.get())->AbiVersion = KFILTER_ABI_VERSION;
    int32_t status = initialized ? KfPolicySetConfig((const KFILTER_CONFIG*)copy.get(), (ULONG)size) : -1;
    if (status < 0) std::fprintf(stderr, "the decision path refused the policy (0x%08x)\n", (unsigned)status);
    return status >= 0;
}

static PolicyDecision OfflineDecide(ULONG target, const std::wstring& path, ULONG rights,
                                    const std::wstring& value, bool registryEnumeration, ULONG volumeClass)
{
    KfOfflineString name{ (uint16_t)std::min<size_t>(path.size() * sizeof(wchar_t), 0xFFF0), 0, path.c_str() };
    KfOfflineString valueName{ (uint16_t)std::min<size_t>(value.size() * sizeof(wchar_t), 0xFFF0), 0, value.c_str() };
    ULONG ruleId = 0;
    ULONG action = 0;
    if (registryEnumeration && target == KFILTER_TARGET_REGISTRY && KfPolicyValueEnumerationDenied(&name, &ruleId)) {
        return { KFilterActionDeny, ruleId };
    }
    (void)KfDecideWithRights(target, path.empty() ? nullptr : &name, rights, value.empty() ? nullptr : &valueName,
                             volumeClass, &ruleId, nullptr, &action, 0);
    /* 0: the layer is off for this target, so it allows. */
    return { action != 0 ? action : (ULONG)KFilterActionAllow, ruleId };
}
#endif

static PolicyDecision EvaluatePolicy(const KFILTER_CONFIG& config, ULONG target,
                                     const std::wstring& path, ULONG rights,
                                     const std::wstring& value, bool registryEnumeration = false,
                                     ULONG volumeClass = 0)
{
#ifndef _WIN32
    if (!OfflineLoad(config)) return { KFilterActionDeny, 0 };
    return OfflineDecide(target, path, rights, value, registryEnumeration, volumeClass);
#else
    wchar_t normalized[KFILTER_MAX_NAME]{};
    wchar_t valueName[KFILTER_MAX_VALUE]{};
    ULONG length = 0;
    ULONG valueLength = 0;

    if (config.Mode == KFILTER_MODE_OFF) return { KFilterActionAllow, 0 };
    if (((target == KFILTER_TARGET_FILE || target == KFILTER_TARGET_DIR ||
          target == KFILTER_TARGET_PIPE) &&
         (config.Flags & KFILTER_CFG_BLOCK_FILES) == 0) ||
        (target == KFILTER_TARGET_REGISTRY && (config.Flags & KFILTER_CFG_BLOCK_REGISTRY) == 0) ||
        (target == KFILTER_TARGET_PROCESS && (config.Flags & KFILTER_CFG_BLOCK_PROCESS_CREATE) == 0) ||
        (target == KFILTER_TARGET_VOLUME && (config.Flags & KFILTER_CFG_BLOCK_VOLUME_SERIAL) == 0)) {
        return { KFilterActionAllow, 0 };
    }
    if (!path.empty()) {
        if (target == KFILTER_TARGET_FILE || target == KFILTER_TARGET_DIR ||
            target == KFILTER_TARGET_PIPE) {
            length = KfNormalizeName(path.c_str(), (ULONG)path.size(), normalized, KFILTER_MAX_NAME);
        } else {
            length = KfCopyExactName(path.c_str(), (ULONG)path.size(), normalized, KFILTER_MAX_NAME);
        }
    }
    if (!value.empty()) {
        valueLength = KfCopyExactName(value.c_str(), (ULONG)value.size(), valueName, KFILTER_MAX_VALUE);
    }
    if ((length == 0 || (!value.empty() && valueLength == 0)) && config.Mode == KFILTER_MODE_BLOCK) {
        return { KFilterActionDeny, 0 };
    }
    KF_MATCH_INPUT input{};
    input.Target = target;
    input.Rights = rights != 0 ? rights : KFILTER_RIGHT_OPEN;   /* as the driver does */
    input.Path = length != 0 ? normalized : nullptr;
    input.PathLength = length;
    input.Value = valueLength != 0 ? valueName : nullptr;
    input.ValueLength = valueLength;

    if (registryEnumeration && target == KFILTER_TARGET_REGISTRY && length != 0) {
        ULONG ruleId = 0;
        if (KfRegistryValueEnumerationDenied(config.Rules, config.RuleCount,
                                             normalized, length, &ruleId)) {
            return { KFilterActionDeny, ruleId };
        }
    }
    for (ULONG index = 0; index < config.RuleCount; index++) {
        const KFILTER_RULE& rule = config.Rules[index];
        if (KfRuleMatches(&rule, &input)) return { rule.Action, rule.RuleId };
    }
    if (KfRuleOnly(target, input.Path, length)) return { KFilterActionAllow, 0 };
    if (target == KFILTER_TARGET_PROCESS && (config.Flags & KFILTER_CFG_DEFAULT_DENY) == 0 &&
        config.Root[0] != L'\0' && length != 0 &&
        KfPathMatches(config.Root, (ULONG)wcslen(config.Root), normalized, length)) {
        return { KFilterActionAllow, 0 };
    }
    if (target == KFILTER_TARGET_VOLUME) {
        /* The minifilter intercepts FileFsVolumeInformation (1) and
         * FileFsObjectIdInformation (8), which carry the volume identity; those
         * are denied, other volume classes are not queried by this layer. */
        return { (ULONG)((volumeClass == 1 || volumeClass == 8) ? KFilterActionDeny
                                                               : KFilterActionAllow), 0 };
    }
    if (target == KFILTER_TARGET_DEVICE) return { KFilterActionDeny, 0 };
    return { (ULONG)((config.Flags & KFILTER_CFG_DEFAULT_DENY) != 0 ? KFilterActionDeny : KFilterActionAllow), 0 };
#endif
}

static const char* DecisionName(ULONG action, ULONG mode)
{
    if (action == KFilterActionDeny && mode == KFILTER_MODE_AUDIT) return "would-deny";
    return ActionName(action);
}

static int HexDigit(char value)
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

static void AppendUtf8(std::string& output, ULONG value)
{
    if (value <= 0x7F) {
        output.push_back((char)value);
    } else if (value <= 0x7FF) {
        output.push_back((char)(0xC0 | (value >> 6)));
        output.push_back((char)(0x80 | (value & 0x3F)));
    } else {
        output.push_back((char)(0xE0 | (value >> 12)));
        output.push_back((char)(0x80 | ((value >> 6) & 0x3F)));
        output.push_back((char)(0x80 | (value & 0x3F)));
    }
}

static bool JsonString(const std::string& line, const std::string& name, std::string& output)
{
    std::string marker = "\"" + name + "\":\"";
    size_t position = line.find(marker);
    if (position == std::string::npos) return false;
    position += marker.size();
    output.clear();
    while (position < line.size()) {
        char value = line[position++];
        if (value == '"') return true;
        if (value != '\\') {
            output.push_back(value);
            continue;
        }
        if (position >= line.size()) return false;
        char escaped = line[position++];
        switch (escaped) {
        case '"': output.push_back('"'); break;
        case '\\': output.push_back('\\'); break;
        case '/': output.push_back('/'); break;
        case 'b': output.push_back('\b'); break;
        case 'f': output.push_back('\f'); break;
        case 'n': output.push_back('\n'); break;
        case 'r': output.push_back('\r'); break;
        case 't': output.push_back('\t'); break;
        case 'u': {
            if (position + 4 > line.size()) return false;
            ULONG codepoint = 0;
            for (int index = 0; index < 4; index++) {
                int digit = HexDigit(line[position + index]);
                if (digit < 0) return false;
                codepoint = (codepoint << 4) | (ULONG)digit;
            }
            position += 4;
            AppendUtf8(output, codepoint);
            break;
        }
        default: return false;
        }
    }
    return false;
}

static bool JsonNumber(const std::string& line, const std::string& name, ULONGLONG& output)
{
    std::string marker = "\"" + name + "\":";
    size_t position = line.find(marker);
    if (position == std::string::npos) return false;
    position += marker.size();
    size_t end = position;
    while (end < line.size() && line[end] >= '0' && line[end] <= '9') end++;
    if (end == position) return false;
    output = _strtoui64(line.c_str() + position, nullptr, 10);
    return true;
}

static ULONG EventRights(const std::string& type, ULONG target, ULONG desiredAccess, ULONG options)
{
    if (type == "file_create") {
        return KfCreateRights((ULONG)desiredAccess, options, target == KFILTER_TARGET_DIR);
    }
    if (type == "registry_open" || type == "registry_create") {
        return KfRightsFromRegistryAccess((ULONG)desiredAccess);
    }
    if (type.find("enumerate") != std::string::npos || type.find("dir") != std::string::npos) {
        return KFILTER_RIGHT_ENUMERATE;
    }
    if (type.find("security") != std::string::npos) return KFILTER_RIGHT_SET_SECURITY;
    if (type.find("write") != std::string::npos || type.find("set") != std::string::npos) {
        return KFILTER_RIGHT_WRITE;
    }
    if (type.find("delete") != std::string::npos) return KFILTER_RIGHT_DELETE;
    if (type.find("rename") != std::string::npos || type.find("link") != std::string::npos) {
        return KFILTER_RIGHT_RENAME;
    }
    return KFILTER_RIGHT_READ;
}

static int SimulatePolicy(const std::wstring& policyPath, const std::wstring& logPath,
                          const std::vector<DWORD>& processIds, ULONGLONG maximumEvents)
{
    std::unique_ptr<KFILTER_CONFIG> config(new KFILTER_CONFIG());
    std::string error;
    if (!ParsePolicy(policyPath, config.get(), error)) {
        std::fprintf(stderr, "%s: %s\n", WideToUtf8(policyPath).c_str(), error.c_str());
        return 1;
    }
    std::ifstream input{std::filesystem::path(logPath)};
    if (!input) {
        std::fprintf(stderr, "cannot open capture\n");
        return 1;
    }
#ifndef _WIN32
    /* One generation for the whole capture: counted rules are spent as they are at runtime. */
    if (!OfflineLoad(*config)) return 1;
#endif
    ULONGLONG processed = 0;
    ULONGLONG denied = 0;
    std::string line;
    while (std::getline(input, line)) {
        if (maximumEvents != 0 && processed >= maximumEvents) break;
        std::string type;
        if (!JsonString(line, "type", type)) continue;
        bool isFile = type.rfind("file_", 0) == 0;
        bool isRegistry = type.rfind("registry_", 0) == 0;
        if (!isFile && !isRegistry) continue;
        ULONGLONG pid = 0;
        if (JsonNumber(line, "process_id", pid) && !processIds.empty() &&
            std::find(processIds.begin(), processIds.end(), (DWORD)pid) == processIds.end()) {
            continue;
        }
        std::string path;
        /*
         * A missing or empty path is a name failure, not a skipped event: the
         * driver denies such a protected request in block mode, so replay it as
         * an empty path and let EvaluatePolicy apply the same gate.
         */
        (VOID)JsonString(line, "text", path);
        ULONGLONG access = 0;
        (VOID)JsonNumber(line, "desired_access", access);
        ULONGLONG options = 0;
        (VOID)JsonNumber(line, "value0", options);
        ULONG target = isRegistry ? KFILTER_TARGET_REGISTRY
                                  : (type.find("dir") != std::string::npos ? KFILTER_TARGET_DIR : KFILTER_TARGET_FILE);
        std::string value;
        if (!JsonString(line, "value_name", value)) (VOID)JsonString(line, "value", value);
#ifndef _WIN32
        std::string program;
        (VOID)JsonString(line, "process_path", program);
        gOfflineImage = Utf8ToWide(program);
        PolicyDecision decision = OfflineDecide(target, Utf8ToWide(path),
                                                EventRights(type, target, (ULONG)access, (ULONG)options),
                                                Utf8ToWide(value),
                                                isRegistry && type.find("enumerate") != std::string::npos, 0);
#else
        PolicyDecision decision = EvaluatePolicy(*config, target, Utf8ToWide(path),
                                                 EventRights(type, target, (ULONG)access, (ULONG)options),
                                                 Utf8ToWide(value),
                                                 isRegistry && type.find("enumerate") != std::string::npos);
#endif
        processed++;
        if (decision.Action == KFilterActionDeny) denied++;
        std::printf("rule=%" KF_U " action=%s type=%s path=%s\n", decision.RuleId,
                    DecisionName(decision.Action, config->Mode), type.c_str(), path.c_str());
    }
    std::printf("simulation: events=%llu denied=%llu allowed-or-audit=%llu\n",
                processed, denied, processed - denied);
    return 0;
}

static int EvaluatePolicyCommand(const std::wstring& policyPath, const std::wstring& targetName,
                                 const std::wstring& path, const std::wstring& rightsName,
                                 const std::wstring& value)
{
    ULONG target = targetName == L"file" ? KFILTER_TARGET_FILE
                 : targetName == L"dir" ? KFILTER_TARGET_DIR
                 : targetName == L"registry" ? KFILTER_TARGET_REGISTRY
                 : targetName == L"process" ? KFILTER_TARGET_PROCESS
                 : targetName == L"pipe" ? KFILTER_TARGET_PIPE
                 : targetName == L"volume" ? KFILTER_TARGET_VOLUME
                 : targetName == L"device" ? KFILTER_TARGET_DEVICE
                 : targetName == L"system" ? KFILTER_TARGET_SYSTEM
                 : targetName == L"dns" ? KFILTER_TARGET_DNS
                 : targetName == L"thread" ? KFILTER_TARGET_THREAD : 0;
    if (target == 0) {
        std::fprintf(stderr, "evaluate target must be file/dir/registry/process/pipe/volume/device/system/dns/thread\n");
        return 2;
    }
    ULONG rights = 0;
    std::string error;
    if (!ParseRights(WideToUtf8(rightsName), rights, error) || rights == 0) {
        std::fprintf(stderr, "evaluate needs nonzero rights\n");
        return 2;
    }
    std::unique_ptr<KFILTER_CONFIG> config(new KFILTER_CONFIG());
    if (!ParsePolicy(policyPath, config.get(), error)) {
        std::fprintf(stderr, "%s: %s\n", WideToUtf8(policyPath).c_str(), error.c_str());
        return 1;
    }
    /* `evaluate volume` models the volume-identity query (FileFsVolumeInformation,
     * class 1), which is the query the minifilter denies. */
    PolicyDecision decision = EvaluatePolicy(*config, target, path, rights, value, false,
                                             target == KFILTER_TARGET_VOLUME ? 1u : 0u);
    std::printf("%s rule=%" KF_U "\n", DecisionName(decision.Action, config->Mode), decision.RuleId);
    return 0;
}

static void PrintPolicy(const KFILTER_CONFIG& config)
{
    std::printf("ok: mode=%s rules=%" KF_U " (%" KF_U " network) protected=%" KF_U " flags=0x%" KF_X " sid-bytes=%" KF_U "\n",
                ModeName(config.Mode), config.RuleCount, config.NetworkRuleCount,
                config.ProtectedCount, config.Flags, config.PackageSidLength);
    if (config.Root[0] != L'\0') std::printf("root: %s\n", WideToUtf8(config.Root).c_str());
    std::printf("evaluation order (first match wins):\n");
    for (ULONG index = 0; index < config.RuleCount; index++) {
        const KFILTER_RULE& rule = config.Rules[index];
        bool access = ((rule.Targets & KFILTER_TARGETS_OUTSIDE) != 0 && rule.Targets != KFILTER_TARGET_LAUNCH) ||
                      rule.Targets == KFILTER_TARGET_PEER || rule.Targets == KFILTER_TARGET_THREAD_PEER;
        std::wstring rights = access ? AccessRightsText(rule.Rights, rule.Targets == KFILTER_TARGET_THREAD_HANDLE ||
                                                                         rule.Targets == KFILTER_TARGET_THREAD_OPEN ||
                                                                         rule.Targets == KFILTER_TARGET_THREAD_PEER,
                                                        (rule.Flags & KFILTER_RULE_PSEUDO) != 0)
                                     : RightsText(rule.Rights);
        if (rule.Account == KFILTER_ACCOUNT_SYSTEM) rights += L" account=system";
        rights += CountText(rule.Count);
        if (rule.Flags & KFILTER_RULE_EXACT) rights += L" exact";
        if (rule.Flags & KFILTER_RULE_HIDE) rights += L" hide";
        if (index >= gFirstImplicit) rights += L" implicit";
        if (rule.Flags & KFILTER_RULE_MODULE) rights += L" module=" + std::wstring(rule.Value);
        if (rule.Flags & KFILTER_RULE_ADDRESS) rights += L" addr=" + AddressText(rule);
        if (rule.Risk[0] != L'\0') rights += L" risk=" + std::wstring(rule.Risk);
        if (rule.Image[0] != L'\0') rights += L" image=" + std::wstring(rule.Image);
        std::printf("  %3" KF_U " %-5s %-8s rights=%-30s ext=0x%02" KF_X " value=%-16s %s\n",
                    rule.RuleId, ActionName(rule.Action), TargetName(rule.Targets),
                    WideToUtf8(rights).c_str(), rule.Extensions,
                    (rule.Flags & (KFILTER_RULE_MODULE | KFILTER_RULE_ADDRESS)) != 0 ? "" : WideToUtf8(rule.Value).c_str(),
                    WideToUtf8(rule.Path).c_str());
    }
    for (ULONG index = 0; index < config.NetworkRuleCount; index++) {
        const KFILTER_NET_RULE& rule = config.Network[index];
        std::wstring risk = rule.Risk[0] != L'\0' ? L" risk=" + std::wstring(rule.Risk) : L"";
        if (rule.Image[0] != L'\0') risk += L" image=" + std::wstring(rule.Image);
        if ((rule.Rights & KFILTER_RIGHTS_MESSAGE) != 0) {
            risk += L" message rights=" + RightsText(rule.Rights);
            if (rule.SizeMax != 0) risk += L" size=" + std::to_wstring(rule.SizeMin) + L"-" + std::to_wstring(rule.SizeMax);
            if (rule.IndexMax != 0) risk += L" index=" + std::to_wstring(rule.IndexMin) + L"-" + std::to_wstring(rule.IndexMax);
            if (rule.MatchLength != 0) {
                wchar_t hex[3];
                risk += L" match=";
                for (ULONG i = 0; i < rule.MatchLength && i < KFILTER_MAX_MATCH; i++) {
                    swprintf(hex, 3, L"%02X", rule.Match[i]);
                    risk += hex;
                }
                risk += L"@" + std::to_wstring(rule.MatchOffset);
            }
            if (rule.Module[0] != L'\0') risk += L" module=" + std::wstring(rule.Module);
            if (rule.Unix[0] != L'\0') risk += L" unix=" + std::wstring(rule.Unix);
        }
        std::printf("  %3" KF_U " %-5s network family=%" KF_U " prefix=%" KF_U " proto=%" KF_U " port=%" KF_U "%s%s\n",
                    rule.RuleId, ActionName(rule.Action), rule.Family, rule.PrefixLength,
                    rule.Protocol, rule.Port, WideToUtf8(CountText(rule.Count)).c_str(),
                    WideToUtf8(risk).c_str());
    }
}

/* STATUS_NOT_FOUND, the driver's confirmed policy non-match, maps to
 * ERROR_NOT_FOUND. A PID that exited between the snapshot and the request is
 * STATUS_INVALID_CID or STATUS_INVALID_PARAMETER. Every other result (name
 * resolution, SID mismatch, table full) means a protected process may be left
 * untracked, so it is counted as a failure. A successful call includes an
 * idempotent duplicate admission and counts as tracked. */
enum TrackOutcome {
    TrackOutcomeTracked = 0,
    TrackOutcomeIgnored = 1,
    TrackOutcomeFailed = 2
};

static TrackOutcome ClassifyTrackResult(BOOL ok, DWORD error)
{
    if (ok) return TrackOutcomeTracked;
    if (error == ERROR_NOT_FOUND || error == ERROR_INVALID_PARAMETER ||
        error == ERROR_INVALID_HANDLE) return TrackOutcomeIgnored;
    return TrackOutcomeFailed;
}

static bool ShouldRollback(ULONG mode, int failures)
{
    return mode == KFILTER_MODE_BLOCK && failures != 0;
}

#ifdef _WIN32
static int TrackProtected(HANDLE device)
{
    int tracked = 0;
    int failures = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 1;
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (entry.th32ProcessID == 0 || entry.th32ProcessID == 4) continue;
            KFILTER_TRACK_REQUEST request{};
            request.ProcessId = entry.th32ProcessID;
            request.Generation = 0;
            BOOL ok = Ioctl(device, KFILTER_IOCTL_TRACK_PID, &request, sizeof(request), nullptr, 0, nullptr);
            switch (ClassifyTrackResult(ok, ok ? 0 : GetLastError())) {
            case TrackOutcomeTracked:
                tracked++;
                break;
            case TrackOutcomeFailed:
                failures++;
                break;
            default:
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    std::printf("tracked %d running process(es), %d failure(s)\n", tracked, failures);
    return failures;
}
#else
static int TrackProtected(HANDLE device)
{
    int tracked = 0;
    int failures = 0;
    DIR* proc = opendir("/proc");
    if (proc == nullptr) return 1;
    struct dirent* entry;
    while ((entry = readdir(proc)) != nullptr) {
        char* end = nullptr;
        unsigned long pid = strtoul(entry->d_name, &end, 10);
        if (end == entry->d_name || *end != '\0' || pid <= 1 || pid == (unsigned long)getpid()) continue;
        KFILTER_TRACK_REQUEST request{};
        request.ProcessId = (ULONG)pid;
        BOOL ok = Ioctl(device, KFILTER_IOCTL_TRACK_PID, &request, sizeof(request), nullptr, 0, nullptr);
        switch (ClassifyTrackResult(ok, ok ? 0 : GetLastError())) {
        case TrackOutcomeTracked: tracked++; break;
        case TrackOutcomeFailed: failures++; break;
        default: break;
        }
    }
    closedir(proc);
    std::printf("tracked %d running process(es), %d failure(s)\n", tracked, failures);
    return failures;
}
#endif

static bool SetConfig(HANDLE device, const KFILTER_CONFIG& config)
{
    /* Only the rules in use go to the driver. */
    if (!Ioctl(device, KFILTER_IOCTL_SET_CONFIG, (void*)&config, (DWORD)KFILTER_CONFIG_SIZE(config.RuleCount),
               nullptr, 0, nullptr)) {
        std::fprintf(stderr, "SET_CONFIG failed: %" KF_U "\n", GetLastError());
        return false;
    }
    return true;
}

static bool GetConfig(HANDLE device, KFILTER_CONFIG* config)
{
    if (!Ioctl(device, KFILTER_IOCTL_GET_CONFIG, nullptr, 0, config, sizeof(*config), nullptr)) {
        std::fprintf(stderr, "GET_CONFIG failed: %" KF_U "\n", GetLastError());
        return false;
    }
    return true;
}

#ifdef _WIN32
static std::wstring DefaultPolicyPath()
{
    wchar_t path[MAX_PATH];
    DWORD length = GetModuleFileNameW(nullptr, path, (DWORD)(sizeof(path) / sizeof(path[0])));
    if (length != 0) {
        std::wstring candidate(path, length);
        size_t slash = candidate.find_last_of(L'\\');
        if (slash != std::wstring::npos) {
            std::wstring next = candidate.substr(0, slash + 1) + L"default-policy.txt";
            if (GetFileAttributesW(next.c_str()) != INVALID_FILE_ATTRIBUTES) return next;
        }
    }
    return L"policy\\default-policy.txt";
}
#else
static std::wstring ExecutableDirectory()
{
    char path[PATH_MAX];
    ssize_t length = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (length <= 0) return {};
    std::wstring directory = Utf8ToWide(std::string(path, (size_t)length));
    size_t slash = directory.find_last_of(L'/');
    return slash == std::wstring::npos ? std::wstring() : directory.substr(0, slash + 1);
}

static std::wstring DefaultPolicyPath()
{
    std::wstring directory = ExecutableDirectory();
    std::wstring next = directory + L"linux-default-policy.txt";
    if (!directory.empty() && access(WideToUtf8(next).c_str(), R_OK) == 0) return next;
    return L"policy/linux-default-policy.txt";
}
#endif

static bool SetMode(HANDLE device, ULONG mode)
{
    std::unique_ptr<KFILTER_CONFIG> config(new KFILTER_CONFIG());
    if (!GetConfig(device, config.get())) return false;
    if (mode == KFILTER_MODE_BLOCK) {
        KFILTER_STATUS status{};
        if (!Ioctl(device, KFILTER_IOCTL_GET_STATUS, nullptr, 0, &status, sizeof(status), nullptr)) {
            std::fprintf(stderr, "GET_STATUS failed: %" KF_U "\n", GetLastError());
            return false;
        }
        if ((status.Registered & KFILTER_REG_DEVICE) == 0) {
            std::fprintf(stderr, "Refusing block mode: device layer is not registered.\n");
            return false;
        }
        struct LayerCheck { ULONG flag; ULONG registration; const char* name; } checks[] = {
            { KFILTER_CFG_BLOCK_FILES, KFILTER_REG_MINIFILTER, "minifilter" },
            { KFILTER_CFG_BLOCK_REGISTRY, KFILTER_REG_REGISTRY, "registry" },
            { KFILTER_CFG_BLOCK_PROCESS_MEMORY, KFILTER_REG_OBJECT, "object" },
            { KFILTER_CFG_BLOCK_PROCESS_CREATE, KFILTER_REG_PROCESS, "process" },
            { KFILTER_CFG_BLOCK_RAW_DISK, KFILTER_REG_DISK, "disk" },
            { KFILTER_CFG_BLOCK_NETWORK, KFILTER_REG_NETWORK, "network" },
#ifndef _WIN32
            /* Linux: the BPF layer is the only one that decides these. */
            { KFILTER_CFG_BLOCK_VOLUME_SERIAL, KFILTER_REG_BPF, "BPF (volume identity)" },
            { KFILTER_CFG_BLOCK_NETWORK_ADAPTER, KFILTER_REG_NSI, "BPF (network adapter)" },
#endif
        };
        for (const auto& check : checks) {
            if ((config->Flags & check.flag) != 0 &&
                (status.Registered & check.registration) == 0) {
                std::fprintf(stderr, "Refusing block mode: %s layer is not registered.\n", check.name);
                return false;
            }
        }
    }
    ULONG previousMode = config->Mode;
    config->Mode = mode;
    if (mode != KFILTER_MODE_OFF) {
        KFILTER_STATUS status{};
        if (!Ioctl(device, KFILTER_IOCTL_GET_STATUS, nullptr, 0, &status, sizeof(status), nullptr)) {
            std::fprintf(stderr, "GET_STATUS failed: %" KF_U "\n", GetLastError());
            return false;
        }
        if (!PolicyEnforceable(*config, status.Registered)) return false;
    }
    if (!SetConfig(device, *config)) return false;
    {
        int trackingFailures = TrackProtected(device);
        if (ShouldRollback(mode, trackingFailures)) {
            config->Mode = previousMode;
            (VOID)SetConfig(device, *config);
            std::fprintf(stderr, "Mode change rolled back: a protected process could not be admitted.\n");
            return false;
        }
        if (trackingFailures != 0) {
            std::fprintf(stderr, "Warning: %d protected process admission failure(s); mode remains %s.\n",
                         trackingFailures, ModeName(mode));
        }
    }
    return true;
}

#ifdef _WIN32
/* A shipped policy file beside the executable, or the copy in the source tree. */
static std::wstring ShippedPolicyPath(const wchar_t* name)
{
    wchar_t modulePath[MAX_PATH];
    if (GetModuleFileNameW(nullptr, modulePath, MAX_PATH) == 0) return {};
    std::wstring directory = modulePath;
    size_t slash = directory.find_last_of(L'\\');
    if (slash == std::wstring::npos) return {};
    directory.resize(slash + 1);
    const std::wstring candidates[] = {
        directory + name,
        directory + L"..\\..\\..\\policy\\" + name,
    };
    for (const auto& candidate : candidates) {
        std::ifstream probe{std::filesystem::path(candidate)};
        if (probe.good()) return candidate;
    }
    return {};
}
#else
/* A shipped policy file beside the executable, or the copy in the source tree. */
static std::wstring ShippedPolicyPath(const wchar_t* name)
{
    std::wstring directory = ExecutableDirectory();
    if (directory.empty()) return {};
    const std::wstring candidates[] = {
        directory + name,
        directory + L"../../policy/" + name,   // build/linux/kfilterctl
    };
    for (const auto& candidate : candidates) {
        std::ifstream probe{std::filesystem::path(candidate)};
        if (probe.good()) return candidate;
    }
    return {};
}
#endif

static int SelfTest()
{
    int failures = 0;
    auto expect = [&failures](const char* name, bool actual, bool wanted) {
        if (actual != wanted) {
            std::printf("FAIL %s\n", name);
            failures++;
        }
    };

    struct TestCase {
        const wchar_t* pattern;
        const wchar_t* text;
        bool expected;
    } globs[] = {
        { L"\\Device\\HarddiskVolume*", L"\\Device\\HarddiskVolume3\\Windows\\x.dll", true },
        { L"\\Device\\HarddiskVolume*", L"\\Device\\HarddiskVolume3x", true },
        { L"*\\Windows\\System32\\*.dll", L"\\Device\\HarddiskVolume3\\Windows\\System32\\ntdll.dll", true },
        { L"*\\Windows\\System32\\*.dll", L"\\Device\\HarddiskVolume3\\Windows\\System32\\ntdll.exe", false },
    };
    for (const auto& test : globs) {
        bool actual = KfMatchGlob(test.pattern, (unsigned long)wcslen(test.pattern),
                                  test.text, (unsigned long)wcslen(test.text)) != 0;
        expect("glob", actual, test.expected);
    }
    wchar_t unterminatedValue[KFILTER_MAX_VALUE + 1];
    for (unsigned long index = 0; index < KFILTER_MAX_VALUE; index++) unterminatedValue[index] = L'x';
    unterminatedValue[KFILTER_MAX_VALUE] = L'Z';
    expect("bounded value scan",
           KfLengthBounded(unterminatedValue, KFILTER_MAX_VALUE) == KFILTER_MAX_VALUE &&
               unterminatedValue[KFILTER_MAX_VALUE] == L'Z', true);
    wchar_t unterminatedRisk[KFILTER_MAX_RISK + 1];
    for (unsigned long index = 0; index < KFILTER_MAX_RISK; index++) unterminatedRisk[index] = L'x';
    unterminatedRisk[KFILTER_MAX_RISK] = L'Z';
    expect("bounded risk scan",
           KfLengthBounded(unterminatedRisk, KFILTER_MAX_RISK) == KFILTER_MAX_RISK &&
               unterminatedRisk[KFILTER_MAX_RISK] == L'Z', true);
    expect("bounded terminated scan", KfLengthBounded(L"short", 10) == 5, true);
    wchar_t normalized[KFILTER_MAX_NAME];
    unsigned long length = KfNormalizeName(L"\\Device\\HarddiskVolume3\\x.exe::$DATA",
                                           (unsigned long)wcslen(L"\\Device\\HarddiskVolume3\\x.exe::$DATA"),
                                           normalized, KFILTER_MAX_NAME);
    expect("ADS normalization",
           length != 0 && wcscmp(normalized, L"\\Device\\HarddiskVolume3\\x.exe") == 0, true);
    expect("ADS extension", KfExtensionMask(normalized, length) == KFILTER_EXT_EXE, true);

    /* Image-name suffixes must land on a name boundary, with or without the
     * leading separator the policy parser adds. */
    expect("protected suffix matches",
           KfNameMatchesSuffix(L"\\Device\\HarddiskVolume3\\tmp\\maplestorycw.exe",
                               (unsigned long)wcslen(L"\\Device\\HarddiskVolume3\\tmp\\maplestorycw.exe"),
                               L"\\maplestorycw.exe",
                               (unsigned long)wcslen(L"\\maplestorycw.exe")) != 0, true);
    expect("protected suffix rejects a longer name",
           KfNameMatchesSuffix(L"\\Device\\HarddiskVolume3\\tmp\\notmaplestorycw.exe",
                               (unsigned long)wcslen(L"\\Device\\HarddiskVolume3\\tmp\\notmaplestorycw.exe"),
                               L"\\maplestorycw.exe",
                               (unsigned long)wcslen(L"\\maplestorycw.exe")) == 0, true);
    expect("bare suffix needs a separator",
           KfNameMatchesSuffix(L"\\Device\\HarddiskVolume3\\tmp\\notmaplestorycw.exe",
                               (unsigned long)wcslen(L"\\Device\\HarddiskVolume3\\tmp\\notmaplestorycw.exe"),
                               L"maplestorycw.exe",
                               (unsigned long)wcslen(L"maplestorycw.exe")) == 0, true);
    expect("execute rights",
           KfRightsFromCreateAccess(FILE_EXECUTE, 0) == KFILTER_RIGHT_EXECUTE, true);
    expect("mixed rights",
           KfRightsFromCreateAccess(FILE_READ_DATA | FILE_EXECUTE, 0) ==
               (KFILTER_RIGHT_READ | KFILTER_RIGHT_EXECUTE), true);
    expect("attributes-only create is a query",
           KfRightsFromCreateAccess(FILE_READ_ATTRIBUTES | SYNCHRONIZE, 0) == KFILTER_RIGHT_QUERY &&
               KfRightsFromCreateAccess(FILE_READ_ATTRIBUTES | FILE_READ_DATA, 0) == KFILTER_RIGHT_READ, true);

    KFILTER_RULE rule{};
    KF_MATCH_INPUT input{};
    rule.Action = KFilterActionDeny;
    rule.Targets = KFILTER_TARGET_FILE;
    rule.Rights = KFILTER_RIGHT_READ;
    wcscpy_s(rule.Path, KFILTER_MAX_NAME, L"\\Device\\HarddiskVolume*\\Windows\\System32");
    input.Target = KFILTER_TARGET_FILE;
    input.Rights = KFILTER_RIGHT_READ | KFILTER_RIGHT_EXECUTE;
    input.Path = L"\\Device\\HarddiskVolume3\\Windows\\System32\\x.dll";
    input.PathLength = (unsigned long)wcslen(input.Path);
    expect("mixed-open deny intersect", KfRuleMatches(&rule, &input) != 0, true);
    input.Rights = KFILTER_RIGHT_EXECUTE;
    expect("execute-only open", KfRuleMatches(&rule, &input) == 0, true);

    /* Allow-subset: an allow grants only the rights it lists. */
    KFILTER_RULE allowRead{};
    allowRead.Action = KFilterActionAllow;
    allowRead.Targets = KFILTER_TARGET_FILE;
    allowRead.Rights = KFILTER_RIGHT_READ;
    wcscpy_s(allowRead.Path, KFILTER_MAX_NAME, L"\\Device\\HarddiskVolume*\\Docs");
    KFILTER_RULE denyRead = allowRead;
    denyRead.Action = KFilterActionDeny;

    input.Path = L"\\Device\\HarddiskVolume3\\Docs\\a.txt";
    input.PathLength = (unsigned long)wcslen(input.Path);
    input.Rights = KFILTER_RIGHT_READ;
    expect("allow subset: read is covered", KfRuleMatches(&allowRead, &input) != 0, true);
    input.Rights = KFILTER_RIGHT_READ | KFILTER_RIGHT_ENUMERATE;
    expect("allow subset: read does not imply enumerate",
           KfRuleMatches(&allowRead, &input) == 0, true);

    /* Deny-intersect: one overlapping right denies a mixed open. */
    input.Rights = KFILTER_RIGHT_READ | KFILTER_RIGHT_EXECUTE;
    expect("deny intersect: mixed read+execute", KfRuleMatches(&denyRead, &input) != 0, true);
    input.Rights = KFILTER_RIGHT_EXECUTE;
    expect("deny intersect: execute only", KfRuleMatches(&denyRead, &input) == 0, true);

    /* Prefix boundary: Docs must not cover Docs2 and must cover itself. */
    input.Path = L"\\Device\\HarddiskVolume3\\Docs2\\a.txt";
    input.PathLength = (unsigned long)wcslen(input.Path);
    input.Rights = KFILTER_RIGHT_READ;
    expect("prefix boundary: Docs2 is outside Docs", KfRuleMatches(&allowRead, &input) == 0, true);
    input.Path = L"\\Device\\HarddiskVolume3\\Docs";
    input.PathLength = (unsigned long)wcslen(input.Path);
    expect("prefix boundary: the directory itself", KfRuleMatches(&allowRead, &input) != 0, true);

    /* Directory enumeration is not a file read. */
    KFILTER_RULE dirEnumerate{};
    dirEnumerate.Action = KFilterActionAllow;
    dirEnumerate.Targets = KFILTER_TARGET_DIR;
    dirEnumerate.Rights = KFILTER_RIGHT_ENUMERATE;
    wcscpy_s(dirEnumerate.Path, KFILTER_MAX_NAME, L"\\Device\\HarddiskVolume*\\Docs");
    input.Target = KFILTER_TARGET_DIR;
    input.Rights = KFILTER_RIGHT_ENUMERATE;
    expect("directory enumerate", KfRuleMatches(&dirEnumerate, &input) != 0, true);
    input.Rights = KFILTER_RIGHT_READ;
    expect("directory read is not enumerate", KfRuleMatches(&dirEnumerate, &input) == 0, true);
    input.Target = KFILTER_TARGET_FILE;
    input.Rights = KFILTER_RIGHT_ENUMERATE;
    expect("directory rule does not apply to a file", KfRuleMatches(&dirEnumerate, &input) == 0, true);

    /* ADS normalization feeds a normalized path to the matcher. */
    wchar_t adsPath[KFILTER_MAX_NAME];
    unsigned long adsLength = KfNormalizeName(L"\\Device\\HarddiskVolume3\\Docs\\a.exe::$DATA",
                                              (unsigned long)wcslen(L"\\Device\\HarddiskVolume3\\Docs\\a.exe::$DATA"),
                                              adsPath, KFILTER_MAX_NAME);
    input.Target = KFILTER_TARGET_FILE;
    input.Rights = KFILTER_RIGHT_READ;
    input.Path = adsPath;
    input.PathLength = adsLength;
    expect("ADS path matches the plain file rule",
           adsLength != 0 && KfRuleMatches(&allowRead, &input) != 0, true);

    /* A registry value rule only matches the named value (and needs one). */
    KFILTER_RULE valueRule{};
    valueRule.Action = KFilterActionDeny;
    valueRule.Targets = KFILTER_TARGET_REGISTRY;
    valueRule.Rights = KFILTER_RIGHT_READ;
    wcscpy_s(valueRule.Path, KFILTER_MAX_NAME, L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Cryptography");
    wcscpy_s(valueRule.Value, KFILTER_MAX_VALUE, L"MachineGuid");
    input.Target = KFILTER_TARGET_REGISTRY;
    input.Path = L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Cryptography";
    input.PathLength = (unsigned long)wcslen(input.Path);
    input.Value = L"MachineGuid";
    input.ValueLength = (unsigned long)wcslen(input.Value);
    expect("registry value match", KfRuleMatches(&valueRule, &input) != 0, true);
    input.Value = L"ProductId";
    input.ValueLength = (unsigned long)wcslen(input.Value);
    expect("registry value mismatch", KfRuleMatches(&valueRule, &input) == 0, true);
    input.Value = nullptr;
    input.ValueLength = 0;
    expect("registry value required", KfRuleMatches(&valueRule, &input) == 0, true);

    {
        wchar_t exact[KFILTER_MAX_VALUE];
        unsigned long exactLength = KfCopyExactName(L"Secret:Value", 12, exact, KFILTER_MAX_VALUE);
        expect("registry value preserves colon",
               exactLength == 12 && wcscmp(exact, L"Secret:Value") == 0, true);
        wcscpy_s(valueRule.Value, KFILTER_MAX_VALUE, L"Secret:Value");
        input.Value = exact;
        input.ValueLength = exactLength;
        expect("registry colon value match", KfRuleMatches(&valueRule, &input) != 0, true);
        input.Value = L"Secret";
        input.ValueLength = 6;
        expect("registry colon value exact non-match", KfRuleMatches(&valueRule, &input) == 0, true);

        exactLength = KfCopyExactName(L"Trailing.  ", 11, exact, KFILTER_MAX_VALUE);
        expect("registry value preserves trailing dots and spaces",
               exactLength == 11 && wcscmp(exact, L"Trailing.  ") == 0, true);
        wcscpy_s(valueRule.Value, KFILTER_MAX_VALUE, L"Trailing.  ");
        input.Value = exact;
        input.ValueLength = exactLength;
        expect("registry trailing value match", KfRuleMatches(&valueRule, &input) != 0, true);
        input.Value = L"Trailing";
        input.ValueLength = 8;
        expect("registry trailing value exact non-match", KfRuleMatches(&valueRule, &input) == 0, true);

        wchar_t overlong[KFILTER_MAX_VALUE];
        for (unsigned long index = 0; index < KFILTER_MAX_VALUE; index++) overlong[index] = L'x';
        expect("registry overlong value rejected",
               KfCopyExactName(overlong, KFILTER_MAX_VALUE, exact, KFILTER_MAX_VALUE) == 0, true);
    }

    /* A zero-right allow must never match (it used to match everything). */
    KFILTER_RULE zeroAllow = allowRead;
    zeroAllow.Rights = 0;
    input.Target = KFILTER_TARGET_FILE;
    input.Rights = KFILTER_RIGHTS_ALL;
    expect("zero-right allow never matches", KfRuleMatches(&zeroAllow, &input) == 0, true);

    /* Registry enumeration is an independent right. */
    expect("registry read mapping",
           KfRightsFromRegistryAccess(KEY_QUERY_VALUE) == KFILTER_RIGHT_READ, true);
    expect("registry enumerate mapping",
           KfRightsFromRegistryAccess(KEY_ENUMERATE_SUB_KEYS) == KFILTER_RIGHT_ENUMERATE, true);
    expect("registry mixed mapping",
           KfRightsFromRegistryAccess(KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS) ==
               (KFILTER_RIGHT_READ | KFILTER_RIGHT_ENUMERATE), true);
    /* KEY_READ includes KEY_ENUMERATE_SUB_KEYS; GENERIC_READ expands to it. */
    expect("registry KEY_READ mapping",
           KfRightsFromRegistryAccess(KEY_READ) ==
               (KFILTER_RIGHT_READ | KFILTER_RIGHT_ENUMERATE), true);
    /* KEY_EXECUTE is KEY_READ, so the generic form must map the same way. */
    expect("registry GENERIC_EXECUTE mapping",
           KfRightsFromRegistryAccess(GENERIC_EXECUTE) ==
               (KFILTER_RIGHT_READ | KFILTER_RIGHT_ENUMERATE), true);

    KFILTER_RULE registryRead{};
    registryRead.Action = KFilterActionAllow;
    registryRead.Targets = KFILTER_TARGET_REGISTRY;
    registryRead.Rights = KFILTER_RIGHT_READ;
    wcscpy_s(registryRead.Path, KFILTER_MAX_NAME, L"\\REGISTRY\\MACHINE\\SOFTWARE\\Vendor");
    input.Target = KFILTER_TARGET_REGISTRY;
    input.Path = L"\\REGISTRY\\MACHINE\\SOFTWARE\\Vendor\\Product";
    input.PathLength = (unsigned long)wcslen(input.Path);
    input.Value = nullptr;
    input.ValueLength = 0;
    input.Rights = KFILTER_RIGHT_ENUMERATE;
    expect("read-only allow does not grant enumerate",
           KfRuleMatches(&registryRead, &input) == 0, true);
    input.Rights = KFILTER_RIGHT_READ;
    expect("read-only allow covers a read", KfRuleMatches(&registryRead, &input) != 0, true);
    input.Rights = KfRightsFromRegistryAccess(GENERIC_EXECUTE);
    expect("GENERIC_EXECUTE needs read+enumerate",
           KfRuleMatches(&registryRead, &input) == 0, true);
    registryRead.Rights = KFILTER_RIGHT_ENUMERATE;
    input.Rights = KFILTER_RIGHT_READ;
    expect("enumerate-only allow does not grant read",
           KfRuleMatches(&registryRead, &input) == 0, true);
    KFILTER_RULE registryDeny = registryRead;
    registryDeny.Action = KFilterActionDeny;
    registryDeny.Rights = KFILTER_RIGHT_READ;
    input.Rights = KFILTER_RIGHT_READ | KFILTER_RIGHT_ENUMERATE;
    expect("deny intersect: mixed read+enumerate",
           KfRuleMatches(&registryDeny, &input) != 0, true);
    input.Rights = KFILTER_RIGHT_ENUMERATE;
    expect("deny intersect: enumerate only", KfRuleMatches(&registryDeny, &input) == 0, true);

    /* A GENERIC_READ open requests enumerate too; the allow must list it. */
    KFILTER_RULE registryWrite{};
    registryWrite.Action = KFilterActionAllow;
    registryWrite.Targets = KFILTER_TARGET_REGISTRY;
    registryWrite.Rights = KFILTER_RIGHT_READ | KFILTER_RIGHT_WRITE | KFILTER_RIGHT_ENUMERATE;
    wcscpy_s(registryWrite.Path, KFILTER_MAX_NAME, L"\\REGISTRY\\MACHINE\\SOFTWARE\\Vendor");
    input.Rights = KFILTER_RIGHT_READ | KFILTER_RIGHT_ENUMERATE;
    expect("registry allow covers read+enumerate", KfRuleMatches(&registryWrite, &input) != 0, true);
    registryWrite.Rights = KFILTER_RIGHT_READ | KFILTER_RIGHT_WRITE;
    expect("registry allow without enumerate does not cover it",
           KfRuleMatches(&registryWrite, &input) == 0, true);

    /* Executable section protections require the independent write right. */
    expect("section execute read",
           KfRightsFromSection(PAGE_EXECUTE_READ) == KFILTER_RIGHT_EXECUTE, true);
    expect("section execute read-write",
           KfRightsFromSection(PAGE_EXECUTE_READWRITE) ==
               (KFILTER_RIGHT_EXECUTE | KFILTER_RIGHT_WRITE), true);
    expect("section execute write-copy",
           KfRightsFromSection(PAGE_EXECUTE_WRITECOPY) ==
               (KFILTER_RIGHT_EXECUTE | KFILTER_RIGHT_WRITE), true);

    /* Set-security is an independent right: a write allow does not grant it. */
    {
        KFILTER_RULE securityAllow = allowRead;
        securityAllow.Rights = KFILTER_RIGHT_READ | KFILTER_RIGHT_WRITE;
        input.Target = KFILTER_TARGET_FILE;
        input.Path = L"\\Device\\HarddiskVolume3\\Docs\\a.txt";
        input.PathLength = (unsigned long)wcslen(input.Path);
        input.Value = nullptr;
        input.ValueLength = 0;
        input.Rights = KFILTER_RIGHT_SET_SECURITY;
        expect("write allow does not grant set-security",
               KfRuleMatches(&securityAllow, &input) == 0, true);
        securityAllow.Rights = KFILTER_RIGHT_SET_SECURITY;
        expect("set-security allow covers it", KfRuleMatches(&securityAllow, &input) != 0, true);
        KFILTER_RULE securityDeny = securityAllow;
        securityDeny.Action = KFilterActionDeny;
        input.Rights = KFILTER_RIGHT_READ | KFILTER_RIGHT_SET_SECURITY;
        expect("set-security deny intersect", KfRuleMatches(&securityDeny, &input) != 0, true);
        input.Rights = KFILTER_RIGHT_READ;
        expect("set-security deny is not read", KfRuleMatches(&securityDeny, &input) == 0, true);
    }

    /* WFP's host-order IPv4 number must land in the byte order rules use.
     * Compare against InetPtonW's runtime output so the check is not folded. */
    {
        unsigned char bytes[4] = { 0, 0, 0, 0 };
        IN_ADDR v4{};
        expect("ipv4 rule text parses", InetPtonW(AF_INET, L"10.1.2.3", &v4) == 1, true);
        (VOID)KfIpv4Bytes(0x0A010203u, bytes);
        expect("ipv4 bytes match InetPtonW", memcmp(bytes, &v4, 4) == 0, true);
        expect("ipv4 loopback rule text parses", InetPtonW(AF_INET, L"127.0.0.1", &v4) == 1, true);
        (VOID)KfIpv4Bytes(0x7F000001u, bytes);
        expect("ipv4 loopback bytes match InetPtonW", memcmp(bytes, &v4, 4) == 0, true);
    }

    /* Network rules reuse the same right-set matcher. */
    KFILTER_RULE netConnect{};
    netConnect.Action = KFilterActionAllow;
    netConnect.Targets = KFILTER_TARGET_NETWORK;
    netConnect.Rights = KFILTER_RIGHT_CONNECT;
    wcscpy_s(netConnect.Path, KFILTER_MAX_NAME, L"ip=10.0.0.0/8");
    input.Target = KFILTER_TARGET_NETWORK;
    input.Path = L"ip=10.0.0.0/8";
    input.PathLength = (unsigned long)wcslen(input.Path);
    input.Rights = KFILTER_RIGHT_CONNECT;
    expect("network connect allow", KfRuleMatches(&netConnect, &input) != 0, true);
    input.Rights = KFILTER_RIGHT_LISTEN;
    expect("network connect is not listen", KfRuleMatches(&netConnect, &input) == 0, true);
    KFILTER_RULE netListen = netConnect;
    netListen.Action = KFilterActionDeny;
    netListen.Rights = KFILTER_RIGHT_LISTEN;
    input.Rights = KFILTER_RIGHT_CONNECT | KFILTER_RIGHT_LISTEN;
    expect("network listen deny intersect", KfRuleMatches(&netListen, &input) != 0, true);

    /* Network rights are connect/listen only, and risky allows need a reason. */
    {
        ULONG rights = 0;
        std::string error;
        expect("network rights parse",
               ParseRights("connect,listen", rights, error) &&
                   rights == (KFILTER_RIGHT_CONNECT | KFILTER_RIGHT_LISTEN), true);
        rights = 0;
        expect("network single right parse",
               ParseRights("listen", rights, error) && rights == KFILTER_RIGHT_LISTEN, true);
        std::unique_ptr<KFILTER_CONFIG> configHolder(new KFILTER_CONFIG());
        KFILTER_CONFIG& config = *configHolder;
        /* An allow is one host, port and protocol, connect only, counted, with a reason;
         * each broken case below changes or drops exactly one of those fields. */
        const std::vector<std::string> exact = { "allow", "network", "ip=203.0.113.10/32", "port=443",
                                                 "proto=tcp", "rights=connect", "uses=2", "risk=login" };
        expect("exact counted network allow accepted",
               ParseNetworkRule(exact, KFilterActionAllow, &config, error), true);
        expect("exact IPv6 network allow accepted",
               ParseNetworkRule({ "allow", "network", "ip=2001:db8::1", "port=8484", "proto=tcp",
                                  "rights=connect", "uses=1", "risk=login" }, KFilterActionAllow, &config, error), true);
        struct AllowCase { size_t field; const char* value; const char* name; };
        AllowCase broken[] = {
            { 2, "ip=203.0.113.0/24", "network allow refuses a range" },
            { 2, "ip=::/0", "network allow refuses any address" },
            { 3, "port=0", "network allow refuses any port" },
            { 4, "proto=any", "network allow refuses any protocol" },
            { 5, "rights=connect,listen", "network allow refuses listen" },
            { 5, "rights=read", "network allow rejects file rights" },
            { 5, "", "network allow needs rights" },
            { 6, "", "network allow refuses a standing rule" },
            { 7, "", "network allow refuses missing risk" },
        };
        for (const auto& test : broken) {
            std::vector<std::string> fields;
            for (size_t index = 0; index < exact.size(); index++) {
                if (index != test.field) fields.push_back(exact[index]);
                else if (test.value[0] != '\0') fields.push_back(test.value);
            }
            expect(test.name, ParseNetworkRule(fields, KFilterActionAllow, &config, error) == false, true);
        }
        expect("network deny may cover a range",
               ParseNetworkRule({ "deny", "network", "ip=10.0.0.0/8" }, KFilterActionDeny, &config, error), true);

        struct PortCase { const char* field; bool expected; ULONG value; };
        PortCase ports[] = {
            { "port=not-a-port", false, 0 },
            { "port=", false, 0 },
            { "port=80x", false, 0 },
            { "port=-1", false, 0 },
            { "port=65536", false, 0 },
            { "port=+80", false, 0 },
            { "port= 80", false, 0 },
            { "port=0x50", false, 0 },
            { "port=0", true, 0 },
            { "port=65535", true, 65535 },
            { "port=80", true, 80 },
        };
        for (const auto& test : ports) {
            std::unique_ptr<KFILTER_CONFIG> portConfigHolder(new KFILTER_CONFIG());
            KFILTER_CONFIG& portConfig = *portConfigHolder;
            std::vector<std::string> fields = { "deny", "network", "ip=10.0.0.0/8", test.field };
            bool ok = ParseNetworkRule(fields, KFilterActionDeny, &portConfig, error);
            expect("network port parse", ok == test.expected, true);
            if (ok) expect("network port value", portConfig.Network[0].Port == test.value, true);
        }

        struct PrefixCase { const char* ip; bool expected; ULONG value; ULONG family; };
        PrefixCase prefixes[] = {
            { "ip=0.0.0.0/0", true, 0, 4 },
            { "ip=10.1.2.3", true, 32, 4 },
            { "ip=10.1.2.3/32", true, 32, 4 },
            { "ip=10.1.2.3/33", false, 0, 0 },
            { "ip=10.1.2.3/", false, 0, 0 },
            { "ip=10.1.2.3/8x", false, 0, 0 },
            { "ip=10.1.2.3/-1", false, 0, 0 },
            { "ip=10.1.2.3/+8", false, 0, 0 },
            { "ip=10.1.2.3/ 8", false, 0, 0 },
            { "ip=::/0", true, 0, 6 },
            { "ip=::1/128", true, 128, 6 },
            { "ip=::1/129", false, 0, 0 },
        };
        for (const auto& test : prefixes) {
            std::unique_ptr<KFILTER_CONFIG> prefixConfigHolder(new KFILTER_CONFIG());
            KFILTER_CONFIG& prefixConfig = *prefixConfigHolder;
            std::vector<std::string> fields = { "deny", "network", test.ip };
            bool ok = ParseNetworkRule(fields, KFilterActionDeny, &prefixConfig, error);
            expect("network prefix parse", ok == test.expected, true);
            if (ok) {
                expect("network prefix value",
                       prefixConfig.Network[0].PrefixLength == test.value, true);
                expect("network prefix family",
                       prefixConfig.Network[0].Family == test.family, true);
            }
        }

        KFILTER_RULE risky{};
        risky.Action = KFilterActionAllow;
        risky.Targets = KFILTER_TARGET_FILE;
        risky.Rights = KFILTER_RIGHT_EXECUTE;
        wcscpy_s(risky.Path, KFILTER_MAX_NAME, L"\\Device\\HarddiskVolume*\\Windows\\System32\\wbemprox.dll");
        expect("WMI allow needs risk", RuleNeedsRisk(risky), true);
        wcscpy_s(risky.Path, KFILTER_MAX_NAME, L"\\Device\\HarddiskVolume*\\Windows\\SysWOW64");
        risky.Extensions = KFILTER_EXT_DLL;
        expect("broad WOW64 allow needs risk", RuleNeedsRisk(risky), true);
        wcscpy_s(risky.Path, KFILTER_MAX_NAME, L"\\Device\\HarddiskVolume*\\Windows\\System32\\version.dll");
        expect("ordinary DLL allow does not need risk", RuleNeedsRisk(risky) == false, true);
        risky.Targets = KFILTER_TARGET_HANDLE;
        expect("handle allow needs risk", RuleNeedsRisk(risky), true);
        expect("risk action is stable", KFilterActionRisk == 4, true);
    }

    /* Rename/link destinations are authorized as their own file request: the
     * destination must sit in an allowed tree and the allow must grant rename. */
    {
        KFILTER_RULE treeAllow{};
        treeAllow.Action = KFilterActionAllow;
        treeAllow.Targets = KFILTER_TARGET_FILE;
        treeAllow.Rights = KFILTER_RIGHT_READ | KFILTER_RIGHT_WRITE | KFILTER_RIGHT_RENAME;
        wcscpy_s(treeAllow.Path, KFILTER_MAX_NAME, L"\\Device\\HarddiskVolume*\\Nexon\\Library\\maplestorycw");
        KFILTER_RULE outsideDeny{};
        outsideDeny.Action = KFilterActionDeny;
        outsideDeny.Targets = KFILTER_TARGET_FILE;
        outsideDeny.Rights = KFILTER_RIGHT_RENAME;
        wcscpy_s(outsideDeny.Path, KFILTER_MAX_NAME, L"\\Device\\HarddiskVolume*\\Users\\*");

        input.Target = KFILTER_TARGET_FILE;
        input.Rights = KFILTER_RIGHT_RENAME;
        input.Path = L"\\Device\\HarddiskVolume3\\Nexon\\Library\\maplestorycw\\save.dat";
        input.PathLength = (unsigned long)wcslen(input.Path);
        expect("rename destination inside the tree",
               KfRuleMatches(&treeAllow, &input) != 0, true);
        input.Path = L"\\Device\\HarddiskVolume3\\Users\\Public\\save.dat";
        input.PathLength = (unsigned long)wcslen(input.Path);
        expect("rename destination outside the tree",
               KfRuleMatches(&treeAllow, &input) == 0, true);
        expect("rename destination denied outside the tree",
               KfRuleMatches(&outsideDeny, &input) != 0, true);
        treeAllow.Rights = KFILTER_RIGHT_READ | KFILTER_RIGHT_WRITE;
        input.Path = L"\\Device\\HarddiskVolume3\\Nexon\\Library\\maplestorycw\\save.dat";
        input.PathLength = (unsigned long)wcslen(input.Path);
        expect("rename destination needs the rename right",
               KfRuleMatches(&treeAllow, &input) == 0, true);
    }

    /* Raw-device requests use first-match order and need the raw-device right. */
    {
        KFILTER_RULE deviceAllow{};
        deviceAllow.Action = KFilterActionAllow;
        deviceAllow.Targets = KFILTER_TARGET_DEVICE;
        deviceAllow.Rights = KFILTER_RIGHT_RAW_DEVICE;
        wcscpy_s(deviceAllow.Path, KFILTER_MAX_NAME, L"\\Device\\HarddiskVolume3");
        KFILTER_RULE deviceDeny = deviceAllow;
        deviceDeny.Action = KFilterActionDeny;
        deviceDeny.Rights = 0; /* deny/audit with no rights applies to every request */

        auto decide = [](const KFILTER_RULE* rules, size_t count,
                         const KF_MATCH_INPUT* deviceInput) -> ULONG {
            for (size_t index = 0; index < count; index++) {
                if (KfRuleMatches(&rules[index], deviceInput) != 0) return rules[index].Action;
            }
            return 0;
        };
        KFILTER_RULE device[2] = { deviceAllow, deviceDeny };
        input.Target = KFILTER_TARGET_DEVICE;
        input.Rights = KFILTER_RIGHT_RAW_DEVICE;
        input.Path = L"\\Device\\HarddiskVolume3";
        input.PathLength = (unsigned long)wcslen(input.Path);
        expect("raw-device first match wins",
               decide(device, 2, &input) == KFilterActionAllow, true);
        input.Rights = KFILTER_RIGHT_READ;
        expect("raw-device allow needs the raw-device right",
               decide(device, 2, &input) == KFilterActionDeny, true);
    }

    {
        const ULONG fileRights = KFILTER_RIGHT_READ | KFILTER_RIGHT_WRITE | KFILTER_RIGHT_EXECUTE |
                                 KFILTER_RIGHT_DELETE | KFILTER_RIGHT_RENAME | KFILTER_RIGHT_SET_SECURITY;
        const ULONG dirRights = fileRights | KFILTER_RIGHT_ENUMERATE;
        const ULONG registryRights = KFILTER_RIGHT_READ | KFILTER_RIGHT_WRITE | KFILTER_RIGHT_DELETE |
                                     KFILTER_RIGHT_RENAME | KFILTER_RIGHT_SET_SECURITY | KFILTER_RIGHT_ENUMERATE;
        expect("file GENERIC_ALL mapping",
               KfRightsFromCreateAccess(GENERIC_ALL, 0) == fileRights, true);
        expect("directory GENERIC_ALL mapping",
               KfRightsFromCreateAccess(GENERIC_ALL, 1) == dirRights, true);
        expect("registry GENERIC_ALL mapping",
               KfRightsFromRegistryAccess(GENERIC_ALL) == registryRights, true);
        expect("file MAXIMUM_ALLOWED mapping",
               KfRightsFromCreateAccess(MAXIMUM_ALLOWED, 0) == fileRights, true);
        expect("directory MAXIMUM_ALLOWED mapping",
               KfRightsFromCreateAccess(MAXIMUM_ALLOWED, 1) == dirRights, true);
        expect("registry MAXIMUM_ALLOWED mapping",
               KfRightsFromRegistryAccess(MAXIMUM_ALLOWED) == registryRights, true);
        expect("directory read EA",
               (KfRightsFromCreateAccess(FILE_READ_EA, 1) & KFILTER_RIGHT_READ) != 0, true);
        expect("directory write EA",
               (KfRightsFromCreateAccess(FILE_WRITE_EA, 1) & KFILTER_RIGHT_WRITE) != 0, true);
        expect("directory execute independent",
               KfRightsFromCreateAccess(FILE_EXECUTE, 1) == KFILTER_RIGHT_EXECUTE, true);
        expect("directory generic read includes attributes",
               KfRightsFromCreateAccess(GENERIC_READ, 1) ==
                   (KFILTER_RIGHT_READ | KFILTER_RIGHT_ENUMERATE), true);
        expect("directory generic execute includes traverse",
               KfRightsFromCreateAccess(GENERIC_EXECUTE, 1) ==
                   (KFILTER_RIGHT_READ | KFILTER_RIGHT_EXECUTE), true);
        expect("registry create link is write",
               (KfRightsFromRegistryAccess(0x20) & KFILTER_RIGHT_WRITE) != 0, true);

        KFILTER_RULE full{};
        full.Action = KFilterActionAllow;
        full.Targets = KFILTER_TARGET_FILE;
        full.Rights = fileRights;
        wcscpy_s(full.Path, KFILTER_MAX_NAME, L"\\Device\\HarddiskVolume*\\Docs");
        KF_MATCH_INPUT fullInput{};
        fullInput.Target = KFILTER_TARGET_FILE;
        fullInput.Rights = KfRightsFromCreateAccess(MAXIMUM_ALLOWED, 0);
        fullInput.Path = L"\\Device\\HarddiskVolume3\\Docs\\a.txt";
        fullInput.PathLength = (ULONG)wcslen(fullInput.Path);
        expect("full-control file allow", KfRuleMatches(&full, &fullInput) != 0, true);
        full.Rights = KFILTER_RIGHT_EXECUTE;
        expect("maximum allowed is not execute-only",
               KfRuleMatches(&full, &fullInput) == 0, true);
        full.Targets = KFILTER_TARGET_DIR;
        full.Rights = dirRights;
        fullInput.Target = KFILTER_TARGET_DIR;
        fullInput.Rights = KfRightsFromCreateAccess(GENERIC_ALL, 1);
        expect("full-control directory allow", KfRuleMatches(&full, &fullInput) != 0, true);
        full.Targets = KFILTER_TARGET_REGISTRY;
        full.Rights = registryRights;
        fullInput.Target = KFILTER_TARGET_REGISTRY;
        fullInput.Rights = KfRightsFromRegistryAccess(GENERIC_ALL);
        expect("full-control registry allow", KfRuleMatches(&full, &fullInput) != 0, true);
        fullInput.Rights = 0;
        expect("zero-right allow rejected", KfRuleMatches(&full, &fullInput) == 0, true);

        for (ULONG prefixLength : { 510u, 511u }) {
            std::wstring pattern(prefixLength, L'x');
            std::wstring descendant = pattern + L"\\child";
            expect("maximum-length prefix descendant",
                   KfPathMatches(pattern.c_str(), prefixLength, descendant.c_str(),
                                 (ULONG)descendant.size()) != 0, true);
        }
    }

    {
        KFILTER_RULE ordered[2]{};
        ordered[0].Action = KFilterActionAllow;
        ordered[0].Targets = KFILTER_TARGET_REGISTRY;
        ordered[0].Rights = KFILTER_RIGHT_READ | KFILTER_RIGHT_ENUMERATE;
        ordered[0].RuleId = 1;
        wcscpy_s(ordered[0].Path, KFILTER_MAX_NAME, L"\\REGISTRY\\MACHINE\\Key");
        ordered[1] = ordered[0];
        ordered[1].Action = KFilterActionDeny;
        ordered[1].RuleId = 2;
        wcscpy_s(ordered[1].Value, KFILTER_MAX_VALUE, L"Secret");
        ULONG ruleId = 0;
        expect("earlier key allow controls value enumeration",
               KfRegistryValueEnumerationDenied(ordered, 2, L"\\REGISTRY\\MACHINE\\Key", (ULONG)wcslen(L"\\REGISTRY\\MACHINE\\Key"), &ruleId) == 0,
               true);
        KFILTER_RULE reversed[2] = { ordered[1], ordered[0] };
        expect("value deny before key allow blocks enumeration",
               KfRegistryValueEnumerationDenied(reversed, 2, L"\\REGISTRY\\MACHINE\\Key", (ULONG)wcslen(L"\\REGISTRY\\MACHINE\\Key"), &ruleId) != 0 &&
                   ruleId == 2, true);
        reversed[0].Rights = KFILTER_RIGHT_WRITE;
        expect("write-only value deny does not block enumeration",
               KfRegistryValueEnumerationDenied(reversed, 2, L"\\REGISTRY\\MACHINE\\Key", (ULONG)wcslen(L"\\REGISTRY\\MACHINE\\Key"), &ruleId) == 0,
               true);

        std::unique_ptr<KFILTER_CONFIG> exactHolder(new KFILTER_CONFIG());

        KFILTER_CONFIG& exact = *exactHolder;
        exact.Mode = KFILTER_MODE_AUDIT;
        exact.Flags = KFILTER_CFG_BLOCK_REGISTRY;
        exact.RuleCount = 1;
        exact.Rules[0].Action = KFilterActionDeny;
        exact.Rules[0].Targets = KFILTER_TARGET_REGISTRY;
        exact.Rules[0].Rights = KFILTER_RIGHTS_ALL;
        exact.Rules[0].RuleId = 9;
        wcscpy_s(exact.Rules[0].Path, KFILTER_MAX_NAME, L"\\REGISTRY\\MACHINE\\Secret:Key.  ");
        PolicyDecision decision = EvaluatePolicy(exact, KFILTER_TARGET_REGISTRY,
                                                 L"\\REGISTRY\\MACHINE\\Secret:Key.  ",
                                                 KFILTER_RIGHT_READ, L"");
        expect("registry key colon and trailing characters preserved",
               decision.Action == KFilterActionDeny && decision.RuleId == 9, true);
        decision = EvaluatePolicy(exact, KFILTER_TARGET_REGISTRY, L"\\REGISTRY\\MACHINE\\Secret",
                                  KFILTER_RIGHT_READ, L"");
        expect("registry distinct key not collapsed",
               decision.Action == KFilterActionAllow, true);
    }

    {
        KFILTER_NET_RULE network{};
        network.Action = KFilterActionAllow;
        network.Family = 4;
        network.Protocol = 6;
        network.PrefixLength = 32;
        network.Port = 443;
        network.Rights = KFILTER_RIGHT_CONNECT;
        network.RuleId = 10001;
        network.Address[0] = 10;
        network.Address[1] = 1;
        network.Address[2] = 2;
        network.Address[3] = 3;
        UCHAR address[16] = { 10, 1, 2, 3 };
        expect("WFP host-order port 443",
               KfNetworkRuleMatches(&network, 4, 6, 443, address, KFILTER_RIGHT_CONNECT) != 0, true);
        expect("WFP swapped port does not match",
               KfNetworkRuleMatches(&network, 4, 6, 47873, address, KFILTER_RIGHT_CONNECT) == 0, true);
        expect("network protocol mismatch",
               KfNetworkRuleMatches(&network, 4, 17, 443, address, KFILTER_RIGHT_CONNECT) == 0, true);
        network.PrefixLength = 8;
        address[0] = 11;
        expect("network prefix mismatch",
               KfNetworkRuleMatches(&network, 4, 6, 443, address, KFILTER_RIGHT_CONNECT) == 0, true);
        expect("raw-disk failure degrades block mode",
               KfRawDiskDegraded(KFILTER_MODE_BLOCK, KFILTER_CFG_BLOCK_RAW_DISK, 1) != 0, true);
        expect("raw-disk failure does not degrade audit mode",
               KfRawDiskDegraded(KFILTER_MODE_AUDIT, KFILTER_CFG_BLOCK_RAW_DISK, 1) == 0, true);
        expect("raw-disk disabled ignores failure",
               KfRawDiskDegraded(KFILTER_MODE_BLOCK, 0, 1) == 0, true);
    }

    {
        std::unique_ptr<KFILTER_CONFIG> replayHolder(new KFILTER_CONFIG());
        KFILTER_CONFIG& replay = *replayHolder;
        replay.Mode = KFILTER_MODE_AUDIT;
        replay.Flags = KFILTER_CFG_BLOCK_FILES;
        replay.RuleCount = 1;
        replay.Rules[0].Action = KFilterActionAllow;
        replay.Rules[0].Targets = KFILTER_TARGET_FILE;
        replay.Rules[0].Rights = KFILTER_RIGHT_EXECUTE;
        replay.Rules[0].RuleId = 4;
        wcscpy_s(replay.Rules[0].Path, KFILTER_MAX_NAME, L"\\Device\\HarddiskVolume*\\Windows\\System32");
        PolicyDecision decision = EvaluatePolicy(replay, KFILTER_TARGET_FILE,
                                                 L"\\Device\\HarddiskVolume3\\Windows\\System32\\x.dll",
                                                 KFILTER_RIGHT_READ, L"");
        expect("targeted replay unmatched access allowed", decision.Action == KFilterActionAllow, true);
        replay.Flags |= KFILTER_CFG_DEFAULT_DENY;
        decision = EvaluatePolicy(replay, KFILTER_TARGET_FILE,
                                  L"\\Device\\HarddiskVolume3\\Windows\\System32\\x.dll",
                                  KFILTER_RIGHT_READ, L"");
        expect("default-deny replay unmatched read denied", decision.Action == KFilterActionDeny, true);
        decision = EvaluatePolicy(replay, KFILTER_TARGET_FILE,
                                  L"\\Device\\HarddiskVolume3\\Windows\\System32\\x.dll",
                                  KFILTER_RIGHT_EXECUTE, L"");
        expect("execute-only replay allow", decision.Action == KFilterActionAllow && decision.RuleId == 4, true);

        ULONG rights = 0;
        std::string error;
        expect("query right parses", ParseRights("query", rights, error) && rights == KFILTER_RIGHT_QUERY &&
                                         RightsText(rights) == L"query", true);

        wchar_t tempDirectory[MAX_PATH];
        DWORD tempLength = GetTempPathW(MAX_PATH, tempDirectory);
        expect("self-test temp path", tempLength != 0 && tempLength < MAX_PATH, true);
        if (tempLength != 0 && tempLength < MAX_PATH) {
            std::wstring policyPath = std::wstring(tempDirectory) + L"kfilter-self-test-policy.txt";
            {
                std::ofstream policy{std::filesystem::path(policyPath)};
                policy << "mode audit\nprotect \\x.exe\n";
            }
            std::unique_ptr<KFILTER_CONFIG> parsed(new KFILTER_CONFIG());
            expect("parser targeted default", ParsePolicy(policyPath, parsed.get(), error) &&
                   (parsed->Flags & KFILTER_CFG_DEFAULT_DENY) == 0 &&
                   (parsed->Flags & KFILTER_CFG_NET_ALLOW_LOOPBACK) != 0, true);
            auto parses = [&](const char* text) {
                std::ofstream policy{std::filesystem::path(policyPath)};
                policy << text;
                policy.close();
                return ParsePolicy(policyPath, parsed.get(), error);
            };
            expect("riskless WMI allow rejected",
                   !parses("protect \\x.exe\nallow|file|\\Device\\HarddiskVolume*\\Windows\\System32\\wbemprox.dll|rights=execute\n"), true);
            expect("risked WMI allow accepted",
                   parses("protect \\x.exe\nallow|file|\\Device\\HarddiskVolume*\\Windows\\System32\\wbemprox.dll|rights=execute|risk=wmi\n"), true);
            expect("riskless broad DLL allow rejected",
                   !parses("protect \\x.exe\nallow|file|\\Device\\HarddiskVolume*\\Windows\\System32|rights=execute|ext=dll\n"), true);
            expect("riskless handle allow rejected",
                   !parses("protect \\x.exe\nallow|handle|\\Device\\HarddiskVolume*\\Windows\\System32\\csrss.exe|rights=vm-read\n"), true);
            expect("risked handle allow accepted",
                   parses("protect \\x.exe\nallow|handle|\\Device\\HarddiskVolume*\\Windows\\System32\\csrss.exe|rights=vm-read|risk=handle\n"), true);
            expect("empty risk rejected",
                   !parses("protect \\x.exe\nallow|file|\\Device\\HarddiskVolume*\\Windows\\System32\\wbemprox.dll|rights=execute|risk=\n"), true);
            expect("exact counted device allow accepted",
                   parses("protect \\x.exe\nallow|device|\\Device\\MountPointManager|value=0x006d0008|uses=1|risk=volume-ids\n") &&
                       parsed->Rules[0].Flags == KFILTER_RULE_EXACT &&
                       parsed->Rules[0].Rights == KFILTER_RIGHT_RAW_DEVICE &&
                       wcscmp(parsed->Rules[0].Value, L"0x006D0008") == 0, true);
            {
                KF_MATCH_INPUT deviceInput{};
                deviceInput.Target = KFILTER_TARGET_DEVICE;
                deviceInput.Rights = KFILTER_RIGHT_RAW_DEVICE;
                deviceInput.Path = L"\\Device\\MountPointManager";
                deviceInput.PathLength = (ULONG)wcslen(deviceInput.Path);
                deviceInput.Value = L"0x006D0008";
                deviceInput.ValueLength = (ULONG)wcslen(deviceInput.Value);
                expect("device IOCTL matches",
                       KfRuleMatches(&parsed->Rules[0], &deviceInput) != 0, true);
                deviceInput.Value = L"0x006D0018";
                deviceInput.ValueLength = (ULONG)wcslen(deviceInput.Value);
                expect("different device IOCTL does not match",
                       KfRuleMatches(&parsed->Rules[0], &deviceInput) == 0, true);
            }
            expect("standing device allow rejected",
                   !parses("protect \\x.exe\nallow|device|\\Device\\Nsi|risk=adapter\n"), true);
            expect("wildcard device allow rejected",
                   !parses("protect \\x.exe\nallow|device|\\Device\\*|uses=1|risk=adapter\n"), true);
            expect("riskless device allow rejected",
                   !parses("protect \\x.exe\nallow|device|\\Device\\Nsi|uses=1\n"), true);
            expect("malformed device IOCTL rejected",
                   !parses("protect \\x.exe\nallow|device|\\Device\\Nsi|value=1|uses=1|risk=adapter\n"), true);
            expect("device allow before broad deny decides",
                   parses("protect \\x.exe\nallow|device|\\Device\\Nsi|uses=1|risk=adapter\ndeny|device|\\Device\n") &&
                       EvaluatePolicy(*parsed, KFILTER_TARGET_DEVICE, L"\\Device\\Nsi",
                                      KFILTER_RIGHT_RAW_DEVICE, L"").Action == KFilterActionAllow, true);
            expect("device allow after broad deny is unreachable",
                   parses("protect \\x.exe\ndeny|device|\\Device\nallow|device|\\Device\\Nsi|uses=1|risk=adapter\n") &&
                       EvaluatePolicy(*parsed, KFILTER_TARGET_DEVICE, L"\\Device\\Nsi",
                                      KFILTER_RIGHT_RAW_DEVICE, L"").Action == KFilterActionDeny, true);
            expect("internal device control is decided in kernel mode",
                   KfDeviceDecisionRequired(0x0F, 0) != 0, true);
            expect("create is decided only in user mode",
                   KfDeviceDecisionRequired(0x00, 1) != 0 &&
                       KfDeviceDecisionRequired(0x00, 0) == 0, true);
            expect("device control requires user mode",
                   KfDeviceDecisionRequired(0x0E, 1) != 0 &&
                       KfDeviceDecisionRequired(0x0E, 0) == 0, true);
            expect("read is not a device decision",
                   KfDeviceDecisionRequired(0x03, 1) == 0, true);
            expect("raw read, write and FSCTL are disk decisions",
                   KfDiskDecisionRequired(0x03, 1) != 0 &&
                       KfDiskDecisionRequired(0x04, 1) != 0 &&
                       KfDiskDecisionRequired(0x0D, 1) != 0, true);
            expect("raw data requests from kernel mode are not",
                   KfDiskDecisionRequired(0x03, 0) == 0 &&
                       KfDiskDecisionRequired(0x04, 0) == 0 &&
                       KfDiskDecisionRequired(0x0D, 0) == 0, true);
            expect("the disk predicate keeps create and control",
                   KfDiskDecisionRequired(0x00, 1) != 0 &&
                       KfDiskDecisionRequired(0x0E, 1) != 0 &&
                       KfDiskDecisionRequired(0x0F, 0) != 0, true);
            expect("an unrelated IRP is not a disk decision",
                   KfDiskDecisionRequired(0x02, 1) == 0, true);
            expect("missing SCSI links are harmless",
                   KfScsiLinkMissing(0xC0000034u) && KfScsiLinkMissing(0xC000003Au), true);
            expect("SCSI attachment failures are not missing links",
                   !KfScsiLinkMissing(0xC0000033u) &&
                       !KfScsiLinkMissing(0xC0000022u) &&
                       !KfScsiLinkMissing(0xC0000001u) &&
                       !KfScsiLinkMissing(0xC000009Au), true);
            /* A rule path ending in a separator can never match: the prefix
             * matcher would append "\*" after it. */
            expect("a rule path with a trailing backslash is rejected",
                   !parses("protect \\x.exe\ndeny|file|\\Device\\HarddiskVolume9\\Games\\\n"), true);
            expect("a rule path with a trailing slash is rejected",
                   !parses("protect \\x.exe\ndeny|registry|\\REGISTRY\\MACHINE\\X/\n"), true);
            expect("a device allow path with a trailing separator is rejected",
                   !parses("protect \\x.exe\nallow|device|\\Device\\Nsi\\|uses=1|risk=adapter\n"), true);
            expect("the same file rule without the trailing separator parses",
                   parses("protect \\x.exe\ndeny|file|\\Device\\HarddiskVolume9\\Games\n"), true);
            /* image=: a rule for one program; uses= on a deny blocks that many requests. */
            expect("image= parses",
                   parses("protect \\x.exe\ndeny|registry|\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Cryptography|value=MachineGuid|image=grap-core64.aes\n") &&
                       wcscmp(parsed->Rules[0].Image, L"grap-core64.aes") == 0, true);
            expect("image= too long rejected",
                   !parses("protect \\x.exe\ndeny|file|\\Device\\X|image=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.exe\n"), true);
            expect("network image= parses",
                   parses("protect \\x.exe\ndeny|network|ip=10.0.0.0/8|image=DwarfAxe.exe\n") &&
                       wcscmp(parsed->Network[0].Image, L"DwarfAxe.exe") == 0, true);
            expect("counted deny parses (block once)",
                   parses("protect \\x.exe\ndeny|file|\\Device\\X|uses=1\n") &&
                       ((parsed->Rules[0].Count & KFILTER_COUNT_USES) >> KFILTER_COUNT_USES_SHIFT) == 1 &&
                       (parsed->Rules[0].Count & KFILTER_COUNT_PHASE) == 1, true);
            expect("message rule parses",
                   parses("protect \\x.exe\ndeny|message|ip=10.1.2.3|port=8484|proto=tcp|size=10-200|index=2-3|match=0A1B@4|image=MapleStory.exe|uses=1\n") &&
                       parsed->Network[0].Rights == KFILTER_RIGHT_SEND && parsed->Network[0].Family == 4 &&
                       parsed->Network[0].SizeMin == 10 && parsed->Network[0].SizeMax == 200 &&
                       parsed->Network[0].IndexMin == 2 && parsed->Network[0].IndexMax == 3 &&
                       parsed->Network[0].MatchLength == 2 && parsed->Network[0].Match[0] == 0x0A &&
                       parsed->Network[0].Match[1] == 0x1B && parsed->Network[0].MatchOffset == 4, true);
            expect("message rule without ip matches any address",
                   parses("protect \\x.exe\ndeny|message|match=FF\n") && parsed->Network[0].Family == 0 &&
                       parsed->Network[0].MatchOffset == 0, true);
            expect("receive rules take no size or match",
                   !parses("protect \\x.exe\ndeny|message|rights=receive|size=1-5\n") &&
                       parses("protect \\x.exe\ndeny|message|rights=send,receive|index=1\n"), true);
            expect("message rights are send and receive only",
                   !parses("protect \\x.exe\ndeny|message|rights=connect\n") &&
                       !parses("protect \\x.exe\ndeny|message|match=ABC\n") &&
                       !parses("protect \\x.exe\ndeny|message|size=9-3\n"), true);
            expect("module= parses on message rules only, as a file name",
                   parses("protect \\x.exe\ndeny|message|module=grap64.dll\n") &&
                       wcscmp(parsed->Network[0].Module, L"grap64.dll") == 0 &&
                       !parses("protect \\x.exe\ndeny|message|module=C:\\x\\grap64.dll\n") &&
                       !parses("protect \\x.exe\ndeny|network|ip=1.2.3.4|module=grap64.dll\n"), true);
            {
                const std::string longPeer = "protect \\x.exe\ndeny|message|unix=/" + std::string(127, 'x') + "\n";
                expect("unix= parses on message rules as the peer alone, sends only, and loads",
                       parses("protect \\x.exe\ndeny|message|unix=/@/tmp/.X11-unix/X5|match=6C00@0|index=2-9|image=x.exe\n") &&
                           parsed->Network[0].Family == KFILTER_NET_FAMILY_UNIX && parsed->Network[0].Rights == KFILTER_RIGHT_SEND &&
                           wcscmp(parsed->Network[0].Unix, L"/@/tmp/.X11-unix/X5") == 0 && parsed->Network[0].MatchLength == 2 &&
                           parsed->Network[0].IndexMax == 9 && OfflineLoad(*parsed) &&
                           !parses("protect \\x.exe\ndeny|message|ip=10.0.0.1|unix=/x\n") &&
                           !parses("protect \\x.exe\ndeny|message|unix=/x|port=6000\n") &&
                           !parses("protect \\x.exe\ndeny|message|unix=/x|proto=tcp\n") &&
                           !parses("protect \\x.exe\ndeny|message|unix=/x|rights=send,receive\n") &&
                           !parses("protect \\x.exe\ndeny|message|unix=tmp/x\n") && !parses(longPeer.c_str()) &&
                           !parses("protect \\x.exe\ndeny|network|unix=/x\n"), true);
                const bool loads = parses("protect \\x.exe\ndeny|message|unix=/@kf\n") && OfflineLoad(*parsed);
                parsed->Network[0].Port = 6000;
                const bool withPort = OfflineLoad(*parsed);
                parsed->Network[0].Port = 0;
                parsed->Network[0].Family = 4;
                expect("the decision path takes unix= alone on a unix message rule, on no other",
                       loads && !withPort && !OfflineLoad(*parsed), true);
            }
            expect("message-default deny parses",
                   parses("protect \\x.exe\nmessage-default deny\n") &&
                       (parsed->Flags & KFILTER_CFG_MESSAGE_DEFAULT_DENY) != 0, true);
            expect("counted network deny parses",
                   parses("protect \\x.exe\ndeny|network|ip=10.0.0.0/8|uses=3\n") &&
                       ((parsed->Network[0].Count & KFILTER_COUNT_USES) >> KFILTER_COUNT_USES_SHIFT) == 3, true);
            {
                const wchar_t* game = L"C:\\Nexon\\Library\\maplestorycw\\appdata\\MapleStory.exe";
                ULONG gameLength = (ULONG)wcslen(game);
                expect("image name matches the file name in any case",
                       KfImageMatches(L"maplestory.EXE", game, gameLength) == 1 &&
                           KfImageMatches(L"Maple*.exe", game, gameLength) == 1 &&
                           KfImageMatches(L"grap-core64.aes", game, gameLength) == 0, true);
                expect("image pattern with a separator matches the whole path",
                       KfImageMatches(L"C:\\Nexon\\*\\MapleStory.exe", game, gameLength) == 1 &&
                           KfImageMatches(L"*\\appdata\\MapleStory.exe", game, gameLength) == 1 &&
                           KfImageMatches(L"\\MapleStory.exe", game, gameLength) == 0, true);
                expect("empty image pattern matches; unknown image matches no pattern",
                       KfImageMatches(L"", nullptr, 0) == 1 && KfImageMatches(L"x.exe", nullptr, 0) == 0, true);
                KFILTER_RULE rule{};
                rule.Action = KFilterActionDeny;
                rule.Targets = KFILTER_TARGET_REGISTRY;
                rule.Rights = KFILTER_RIGHTS_ALL;
                wcscpy_s(rule.Path, KFILTER_MAX_NAME, L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Cryptography");
                wcscpy_s(rule.Value, KFILTER_MAX_VALUE, L"MachineGuid");
                wcscpy_s(rule.Image, KFILTER_MAX_IMAGE, L"grap-core64.aes");
                const wchar_t* key = L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Cryptography";
                const wchar_t* grap = L"C:\\Nexon\\Library\\maplestorycw\\appdata\\grap-core64.aes";
                KF_MATCH_INPUT input{};
                input.Target = KFILTER_TARGET_REGISTRY;
                input.Rights = KFILTER_RIGHT_READ;
                input.Path = key;
                input.PathLength = (ULONG)wcslen(key);
                input.Value = L"MachineGuid";
                input.ValueLength = 11;
                input.Image = grap;
                input.ImageLength = (ULONG)wcslen(grap);
                bool forGrap = KfRuleMatches(&rule, &input) != 0;
                input.Image = game;
                input.ImageLength = gameLength;
                bool forGame = KfRuleMatches(&rule, &input) != 0;
                expect("an image= rule applies only to that program", forGrap && !forGame, true);
            }
#ifndef _WIN32
            {
                bool linux = gLinuxPaths;
                gLinuxPaths = true;
                expect("Linux: a bare protect name is a Windows program",
                       parses("protect MapleStory.exe\nprotect /wine64\n") &&
                           wcscmp(parsed->Protected[0], L"\\MapleStory.exe") == 0 &&
                           wcscmp(parsed->Protected[1], L"/wine64") == 0, true);
                expect("Linux: registry rules are NT key names",
                       parses("protect MapleStory.exe\ndeny|registry|\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Cryptography|value=MachineGuid\n") &&
                           !parses("protect MapleStory.exe\ndeny|registry|/etc/x\n"), true);
                expect("Linux: open rules may name a Windows program",
                       parses("protect MapleStory.exe\nallow|open|C:\\Program Files (x86)\\Nexon\\*\\nexon_client.exe|rights=terminate|risk=launcher\n") &&
                           wcscmp(parsed->Rules[0].Path, L"C:\\Program Files (x86)\\Nexon\\*\\nexon_client.exe") == 0, true);
                expect("Linux: file rules still need Linux paths",
                       !parses("protect MapleStory.exe\ndeny|file|C:\\windows\\system32\n"), true);
                expect("Linux: peer, thread-peer, system, dns and thread rules; block-direct-syscall",
                       parses("protect MapleStory.exe\nblock-direct-syscall on\n"
                              "deny|thread-peer|\\MapleStory.exe|rights=get-context|image=grap-core64.aes\n"
                              "audit|peer|\\*\n"
                              "allow|system|/system/uname|rights=query\n"
                              "deny|dns|wpad.*\n"
                              "allow|thread|C:\\*\\MapleStory.exe|rights=create|uses=50\n") &&
                           parsed->Rules[0].Targets == KFILTER_TARGET_THREAD_PEER &&
                           parsed->Rules[0].Rights == THREAD_GET_CONTEXT &&
                           parsed->Rules[1].Targets == KFILTER_TARGET_PEER && parsed->Rules[1].Rights == 0 &&
                           parsed->Rules[2].Targets == KFILTER_TARGET_SYSTEM && parsed->Rules[2].Rights == KFILTER_RIGHT_QUERY &&
                           parsed->Rules[3].Targets == KFILTER_TARGET_DNS && wcscmp(parsed->Rules[3].Path, L"wpad.*") == 0 &&
                           parsed->Rules[4].Targets == KFILTER_TARGET_THREAD &&
                           wcscmp(parsed->Rules[4].Path, L"C:\\*\\MapleStory.exe") == 0 &&
                           (parsed->Flags & KFILTER_CFG_BLOCK_DIRECT_SYSCALL) != 0 &&
                           OfflineLoad(*parsed) && !parses("protect MapleStory.exe\ndeny|dns|/wpad\n"), true);
                /* Device allows: uses= may be left out only where no rule means no decision (a GPU's
                 * per-frame ioctls would spend a count); identity devices, /dev names, /net queries keep it. */
                expect("Linux: a device allow leaves out uses= only on a path decided by rules alone",
                       parses("protect MapleStory.exe\nallow|device|/dev/dri/renderD128|value=0xC0106446|risk=gpu\n"
                              "allow|device|/anon/[userfaultfd]|risk=uffd\nallow|device|/home/u/f|risk=file\n"
                              "allow|device|/dev/hidraw0|uses=1|risk=hid\ndeny|device|/dev/dri/*\n") &&
                           parsed->Rules[0].Count == 0 && OfflineLoad(*parsed) &&
                           !parses("protect MapleStory.exe\nallow|device|/net/netlink/route|value=0x00000012|risk=adapter\n") &&
                           !parses("protect MapleStory.exe\nallow|device|/net/ioctl|risk=adapter\n") &&
                           !parses("protect MapleStory.exe\nallow|device|/dev/sda|risk=disk\n") &&
                           !parses("protect MapleStory.exe\nallow|device|/dev/hidraw0|risk=hid\n") &&
                           !parses("protect MapleStory.exe\nallow|device|/dev/bus/usb/001/002|risk=usb\n") &&
                           !parses("protect MapleStory.exe\nallow|device|/dev/bsg/0:0:0:0|risk=scsi\n") &&
                           KfDeviceDefaultDecided(L"/dev/dri/*", 10) && !KfDeviceDefaultDecided(L"/net/netlink", 12) &&
                           !KfDeviceDefaultDecided(L"/dev", 4), true);
                /* An ioctl's argument (ABI 11): 0x<ioctl>:0x<its argument's first 32 bits>, eight digits each. */
                expect("Linux: a device value may name an ioctl's argument",
                       parses("protect MapleStory.exe\nallow|device|/dev/dri/renderD128|value=0xc0106446:0x00000002|risk=gpu\n"
                              "deny|device|/dev/dri/renderD128|value=0xC0106446:0x00000001\n") &&
                           wcscmp(parsed->Rules[0].Value, L"0xC0106446:0x00000002") == 0 && OfflineLoad(*parsed) &&
                           !parses("protect MapleStory.exe\nallow|device|/dev/dri/renderD128|value=0xC0106446:2|risk=gpu\n") &&
                           !parses("protect MapleStory.exe\nallow|device|/dev/dri/renderD128|value=0xC0106446;0x00000002|risk=gpu\n"),
                       true);
                expect("Linux: WMI rules name the class lowercased",
                       parses("protect MapleStory.exe\ndeny|system|/system/wmi/Win32_BIOS\n") &&
                           wcscmp(parsed->Rules[0].Path, L"/system/wmi/win32_bios") == 0, true);
                /* /system/syscall/<name>[/<key>]: a hot call is ruled only with its argument; any other name loads. */
                expect("Linux: syscall rules; a hot call only with its argument",
                       parses("protect MapleStory.exe\ndeny|system|/system/syscall/futex/9|image=MapleStory.exe\n"
                              "deny|system|/system/syscall/rt_sigprocmask/0\ndeny|system|/system/syscall/fcntl\n"
                              "deny|system|/system/syscall/f*\ndeny|system|/system/syscall/rt_sigaction/5\n") &&
                           OfflineLoad(*parsed) &&
                           !parses("protect MapleStory.exe\ndeny|system|/system/syscall/futex\n") &&
                           !parses("protect MapleStory.exe\ndeny|system|/system/syscall/futex/*\n") &&
                           !parses("protect MapleStory.exe\ndeny|system|/system/syscall/rt_sigprocmask|image=x.exe\n") &&
                           !parses("protect MapleStory.exe\ndeny|system|/system/syscall/select/\n") &&
                           SyscallOf(L"/system/syscall/fcntl/6") == "fcntl" && SyscallOf(L"/system/syscall/f*") == "" &&
                           SyscallHot("poll") && SyscallHot("futex") && !SyscallHot("fcntl"), true);
                /* ABI 11: lock, chdir and touch lie outside a rule's every-right default and name file and dir decisions
                 * only; the switches for signals and READ checks across the family's boundary. */
                expect("Linux: rights lock, chdir and touch on file and dir rules; block-process-signals and -queries",
                       parses("protect MapleStory.exe\nblock-process-signals\nblock-process-queries\n"
                              "deny|file|/home/*/.wine*/*.lock|rights=lock\ndeny|dir|/home/u/secret|rights=chdir,enumerate\n"
                              "deny|file|/x\nallow|file|/y|rights=read,touch\n") &&
                           parsed->Rules[0].Rights == KFILTER_RIGHT_LOCK &&
                           parsed->Rules[1].Rights == (KFILTER_RIGHT_CHDIR | KFILTER_RIGHT_ENUMERATE) &&
                           parsed->Rules[2].Rights == KFILTER_RIGHTS_ALL &&
                           RightsText(parsed->Rules[3].Rights) == L"read,query,touch" &&
                           (parsed->Flags & KFILTER_CFG_BLOCK_PROCESS_SIGNALS) != 0 &&
                           (parsed->Flags & KFILTER_CFG_BLOCK_PROCESS_QUERIES) != 0 && OfflineLoad(*parsed) &&
                           !parses("protect MapleStory.exe\ndeny|system|/system/uname|rights=lock\n") &&
                           !parses("protect MapleStory.exe\ndeny|pipe|/@x|rights=chdir\n") &&
                           !parses("protect MapleStory.exe\ndeny|registry|\\REGISTRY\\X|rights=touch\n") &&
                           parses("protect MapleStory.exe\nblock-process-signals\nblock-process-signals off\n") &&
                           (parsed->Flags & KFILTER_CFG_BLOCK_PROCESS_SIGNALS) == 0, true);
                /* addr= (ABI 10): up to 16 ranges in one rule, absolute or from a module of the target program. */
                std::string sixteen;
                for (int i = 1; i <= 16; i++) {
                    sixteen += std::string(i > 1 ? "," : "") + (i % 2 == 0 ? "ntdll.dll+" : "") + "0x" + std::to_string(i) +
                               "000-0x" + std::to_string(i) + "fff";
                }
                expect("Linux: addr= on peer, thread-peer and system rules, a list of 16 over two modules",
                       parses(("protect MapleStory.exe\n"
                               "deny|peer|C:\\*\\MapleStory.exe|rights=vm-read|addr=MapleStory.exe+0x1000-0x1FFF|image=grap-core64.aes\n"
                               "deny|peer|C:\\*\\MapleStory.exe|rights=vm-write,vm-operation|addr=0x140000000-0x14FFFFFFF\n"
                               "deny|thread-peer|C:\\*\\MapleStory.exe|rights=set-context|addr=MapleStory.exe+0x1000-0x1FFF\n"
                               "deny|system|/system/wine/self/read_process_memory|addr=1000,grap-core64.aes+0-0xfff\n"
                               "audit|peer|\\@unknown|addr=" + sixteen + "\n").c_str()) &&
                           parsed->Rules[0].Flags == KFILTER_RULE_ADDRESS && parsed->Rules[0].Rights == 0x10 &&
                           parsed->Rules[0].AddressCount == 1 && parsed->Rules[0].AddressModule[0] == 1 &&
                           parsed->Rules[0].Address[0].Low == 0x1000 && parsed->Rules[0].Address[0].High == 0x1FFF &&
                           wcscmp(parsed->Rules[0].Value, L"MapleStory.exe") == 0 && parsed->Rules[1].AddressModule[0] == 0 &&
                           parsed->Rules[1].Value[0] == L'\0' && parsed->Rules[1].Address[0].High == 0x14FFFFFFFull &&
                           parsed->Rules[2].Targets == KFILTER_TARGET_THREAD_PEER && parsed->Rules[2].Rights == 0x10 &&
                           parsed->Rules[3].Address[0].Low == 0x1000 && parsed->Rules[3].Address[0].High == 0x1000 &&
                           AddressText(parsed->Rules[3]) == L"0x1000-0x1000,grap-core64.aes+0x0-0xfff" &&
                           parsed->Rules[4].AddressCount == 16 && parsed->Rules[4].AddressModule[1] == 1 &&
                           parsed->Rules[4].AddressModule[2] == 0 && wcscmp(parsed->Rules[4].Value, L"ntdll.dll") == 0 &&
                           OfflineLoad(*parsed), true);
                const std::string longName = std::string(50, 'm');
                expect("Linux: addr= refuses other targets, value= and module=, bad ranges, a 17th range and a second addr=",
                       !parses("protect MapleStory.exe\ndeny|file|/x|addr=0-1\n") &&
                           !parses("protect MapleStory.exe\nallow|handle|\\x.exe|rights=vm-read|risk=r|addr=0-1\n") &&
                           !parses("protect MapleStory.exe\ndeny|system|/system/uname|value=x|addr=0-1\n") &&
                           !parses("protect MapleStory.exe\ndeny|system|/system/uname|addr=0-1|value=x\n") &&
                           !parses("protect MapleStory.exe\ndeny|system|/system/uname|addr=0-1|module=x.dll\n") &&
                           !parses("protect MapleStory.exe\ndeny|system|/system/uname|module=x.dll|addr=0-1\n") &&
                           !parses("protect MapleStory.exe\ndeny|peer|\\x.exe|addr=0x2000-0x1000\n") &&
                           !parses("protect MapleStory.exe\ndeny|peer|\\x.exe|addr=\n") &&
                           !parses("protect MapleStory.exe\ndeny|peer|\\x.exe|addr=0-1,\n") &&
                           !parses("protect MapleStory.exe\ndeny|peer|\\x.exe|addr=0x1g\n") &&
                           !parses("protect MapleStory.exe\ndeny|peer|\\x.exe|addr=0x10000000000000000\n") &&
                           !parses("protect MapleStory.exe\ndeny|peer|\\x.exe|addr=+0-1\n") &&
                           !parses("protect MapleStory.exe\ndeny|peer|\\x.exe|addr=C:\\x\\a.dll+0-1\n") &&
                           !parses("protect MapleStory.exe\ndeny|peer|\\x.exe|addr=0-1|addr=2-3\n") &&
                           !parses(("protect MapleStory.exe\ndeny|peer|\\x.exe|addr=" + sixteen + ",0-1\n").c_str()) &&
                           !parses(("protect MapleStory.exe\ndeny|peer|\\x.exe|addr=" + longName + "a+0-1," + longName + "b+0-1," +
                                    longName + "c+0-1\n").c_str()), true);
                /* ABI 11: peer pseudo-rights by name, flagged (peer rules alone: thread-peer and handle rules refuse the
                 * names; a hex mask with their bits still parses, unflagged, as it did), value= on peer and thread-peer
                 * rules (not with addr=), printed back. */
                expect("Linux: pseudo-rights and value= on peer and thread-peer rules",
                       parses("protect MapleStory.exe\n"
                              "deny|peer|C:\\*\\MapleStory.exe|rights=window-message|value=0x0000004A|image=grap-core64.aes\n"
                              "audit|peer|\\@unknown-window|rights=window-query,window-set,input\n"
                              "deny|thread-peer|C:\\*\\MapleStory.exe|value=get_thread_*\n"
                              "deny|peer|C:\\*\\MapleStory.exe|rights=terminate|value=assign_job\n") &&
                           parsed->Rules[0].Rights == KFILTER_ACCESS_WINDOW_MESSAGE &&
                           parsed->Rules[0].Flags == KFILTER_RULE_PSEUDO &&
                           wcscmp(parsed->Rules[0].Value, L"0x0000004A") == 0 &&
                           parsed->Rules[1].Rights == (KFILTER_ACCESS_WINDOW_QUERY | KFILTER_ACCESS_WINDOW_SET | KFILTER_ACCESS_INPUT) &&
                           parsed->Rules[1].Flags == KFILTER_RULE_PSEUDO &&
                           AccessRightsText(parsed->Rules[1].Rights, false, true) == L"window-query,window-set,input" &&
                           AccessRightsText(KFILTER_ACCESS_INPUT, false) == L"0x10000000" &&
                           parsed->Rules[2].Targets == KFILTER_TARGET_THREAD_PEER && parsed->Rules[2].Rights == 0 &&
                           wcscmp(parsed->Rules[2].Value, L"get_thread_*") == 0 && parsed->Rules[3].Rights == 0x1 &&
                           parsed->Rules[2].Flags == 0 && parsed->Rules[3].Flags == 0 && OfflineLoad(*parsed) &&
                           parses("protect MapleStory.exe\ndeny|peer|\\x.exe|rights=0x1fffff\ndeny|peer|\\x.exe|rights=0xF0004000\n") &&
                           parsed->Rules[0].Flags == 0 && parsed->Rules[1].Rights == 0xF0004000u && parsed->Rules[1].Flags == 0 &&
                           !parses("protect MapleStory.exe\ndeny|thread-peer|\\x.exe|rights=window-message\n") &&
                           !parses("protect MapleStory.exe\nallow|handle|\\x.exe|rights=input|risk=r\n") &&
                           !parses("protect MapleStory.exe\ndeny|peer|\\x.exe|value=x|addr=0-1\n") &&
                           !parses("protect MapleStory.exe\ndeny|peer|\\x.exe|addr=0-1|value=x\n") &&
                           !parses("protect MapleStory.exe\ndeny|peer|\\x.exe|value=\n") &&
                           parses("protect MapleStory.exe\nallow|handle|\\x.exe|rights=0x4000|risk=r\n"), true);
                /* A signal or ptrace mode inside the family (kfilterd gives these rules a target of their own). */
                expect("Linux: value=signal: and ptrace: on peer rules, no rights-less warning for them",
                       parses("protect MapleStory.exe\n"
                              "deny|peer|C:\\*\\MapleStory.exe|value=signal:0x00000013|image=grap-core64.aes\n"
                              "audit|peer|C:\\*\\MapleStory.exe|rights=query-information|value=ptrace:0x00000009\n") &&
                           wcscmp(parsed->Rules[0].Value, L"signal:0x00000013") == 0 && parsed->Rules[0].Rights == 0 &&
                           wcscmp(parsed->Rules[1].Value, L"ptrace:0x00000009") == 0 && PolicyWarnings(*parsed).empty(),
                       true);
                std::vector<std::string> reaches;
                const bool reached = parses("protect MapleStory.exe\n"
                                            "deny|peer|C:\\*|rights=window-message|value=signal:*\n"
                                            "deny|peer|C:\\*|rights=terminate|value=ptrace:0x00000009\n"
                                            "deny|peer|C:\\*|value=signal:10\n"
                                            "deny|thread-peer|C:\\*|value=signal:0x0000000A\n"
                                            "deny|peer|C:\\*|rights=terminate,window-message|value=signal:0x0000000A\n"
                                            "deny|peer|C:\\*|value=Signal:0x0000000a\n"
                                            "deny|peer|C:\\*|value=signal:0x0000001*\n"
                                            "audit|peer|C:\\*|value=ptrace:*9\n"
                                            "deny|peer|C:\\*|rights=query-limited-information|value=signal:0x00000000\n"
                                            "deny|peer|C:\\*|value=signal:*x*\n"
                                            "deny|peer|C:\\*|value=signal:0x*g\n");
                if (reached) reaches = PolicyWarnings(*parsed);
                expect("Linux: check warns of signal and ptrace rules that meet nothing (a value the kernel never writes, "
                       "rights excluding the access, a thread-peer rule) and of a pseudo-right on one",
                       reached && reaches.size() == 6 &&
                           reaches[0].rfind("rule 1 (C:\\*) meets nothing: a signal asks terminate", 0) == 0 &&
                           reaches[1].rfind("rule 2 (C:\\*) meets nothing: a ptrace READ check asks", 0) == 0 &&
                           reaches[2].rfind("rule 3 (C:\\*) meets nothing: the kernel names", 0) == 0 &&
                           reaches[3].rfind("rule 4 (C:\\*) meets nothing: signals and ptrace checks", 0) == 0 &&
                           reaches[4].rfind("rule 5 (C:\\*) names a pseudo-right", 0) == 0 &&
                           reaches[5].rfind("rule 11 (C:\\*) meets nothing: the kernel names", 0) == 0, true);
                /* check's warnings: broad and reaching rules under /system/wine, peer rules without rights=, a
                 * pattern matching \@unknown; rules that name what they decide get none. */
                std::vector<std::string> warnings;
                const bool warned = parses("protect MapleStory.exe\n"
                                           "deny|system|/system/wine/*\n"
                                           "deny|system|/system/wine\n"
                                           "deny|system|/system/wine/get_mess*\n"
                                           "deny|system|/system/wine/get_message\n"
                                           "deny|peer|C:\\*\\MapleStory.exe\n"
                                           "deny|peer|\\*|rights=vm-read\n"
                                           "deny|peer|\\@unknown|rights=vm-read\n"
                                           "deny|system|/system/sysinfo\n");
                if (warned) warnings = PolicyWarnings(*parsed);
                expect("Linux: check warns about broad /system/wine rules, rights-less peer rules and \\@unknown patterns",
                       warned && warnings.size() == 5 && warnings[0].rfind("rule 1 (/system/wine/*) meets only", 0) == 0 &&
                           warnings[1].rfind("rule 2 (/system/wine) meets only", 0) == 0 &&
                           warnings[2].rfind("rule 3 (/system/wine/get_mess*) decides each of the 2 Wine requests it begins "
                                             "(get_message, get_message_reply)", 0) == 0 &&
                           warnings[3].rfind("rule 5 (C:\\*\\MapleStory.exe) has no rights=", 0) == 0 &&
                           warnings[4].rfind("rule 6 (\\*) matches \\@unknown", 0) == 0, true);
                const bool placeholders = parses("protect MapleStory.exe\n"
                                                 "allow|peer|\\@unknown-window|rights=window-set\n"
                                                 "deny|peer|\\@unknown-thread|rights=window-message\n"
                                                 "deny|peer|\\@unknown-window\n"
                                                 "deny|peer|\\@unknown-window|rights=0x40000000\n");
                if (placeholders) warnings = PolicyWarnings(*parsed);
                expect("Linux: check warns that an allow on \\@unknown-window is not loaded, that a deny there meets the "
                       "program's own unplaced windows, and that one without a pseudo-right meets nothing",
                       placeholders && warnings.size() == 4 &&
                           warnings[0].rfind("rule 1 (\\@unknown-window) is an allow on a window or thread", 0) == 0 &&
                           warnings[1].rfind("rule 2 (\\@unknown-thread) also meets the program's own windows", 0) == 0 &&
                           warnings[2].rfind("rule 3 (\\@unknown-window) meets nothing", 0) == 0 &&
                           warnings[3].rfind("rule 4 (\\@unknown-window) meets nothing", 0) == 0, true);
                const bool inproc = parses("protect MapleStory.exe\n"
                                           "deny|system|/system/ntdll/NtCreateFile\n"
                                           "deny|system|/system/ntdll/NtCreateThreadEx/1\n"
                                           "deny|system|/system/ntdll/NtQueryInformationProcess/0x7\n"
                                           "deny|system|/system/ntdll/NtQueryInformationProcess\n"
                                           "deny|system|/system/ntdll/NtQueryInformationProcess/7\n"
                                           "deny|system|/system/ntdll/NtQueryVirtualMemory|addr=0x1000-0x1FFF\n"
                                           "deny|system|/system/win32k/NtUserGetCursorPos/1\n"
                                           "deny|system|/system/win32k/NtUserGetAsyncKeyState/0x70\n"
                                           "deny|system|/system/win32k/NtUserGetAsyncKeyState/0x00000070\n"
                                           "deny|system|/system/win32k/NtUserSetWindowsHookEx/-1\n"
                                           "deny|system|/system/win32k/NtUserGetClassName/other\n"
                                           "deny|system|/system/win32k/NtUserInternalGetWindowText/@other\n"
                                           "deny|system|/system/win32k/NtUserGetDC/@other\n"
                                           "audit|system|/system/win32k/NtUserGetDC/@unknown\n"
                                           "deny|system|/system/win32k/NtUserCallHwndParam/@other\n"
                                           "deny|system|/system/wmi/Win32_Process\n"
                                           "deny|system|/system/wmi/Win32_Process/Create\n"
                                           "deny|system|/system/wmi/win32_bios|exact\n");
                if (inproc) warnings = PolicyWarnings(*parsed);
                expect("Linux: check warns of in-process rules that meet nothing (an ntdll.so call kfilter does not decide, "
                       "a class of a call without classes or not in decimal, a key of a call without keys or not in the "
                       "kernel's text), a deny of a whole ntdll.so call, @other without @unknown, NtUserCallHwndParam's "
                       "probe and a WMI class rule that meets no method",
                       inproc && warnings.size() == 12 &&
                           warnings[0].rfind("rule 1 (/system/ntdll/NtCreateFile) meets nothing: kfilter decides only", 0) == 0 &&
                           warnings[1].rfind("rule 2 (/system/ntdll/NtCreateThreadEx/1) meets nothing: NtCreateThreadEx has "
                                             "no class", 0) == 0 &&
                           warnings[2].rfind("rule 3 (/system/ntdll/NtQueryInformationProcess/0x7) meets nothing: the kernel "
                                             "names a class in decimal", 0) == 0 &&
                           warnings[3].rfind("rule 4 (/system/ntdll/NtQueryInformationProcess) refuses every", 0) == 0 &&
                           warnings[4].rfind("rule 6 (/system/ntdll/NtQueryVirtualMemory) probes NtQueryVirtualMemory", 0) == 0 &&
                           warnings[5].rfind("rule 7 (/system/win32k/NtUserGetCursorPos/1) meets nothing: only these", 0) == 0 &&
                           warnings[6].rfind("rule 8 (/system/win32k/NtUserGetAsyncKeyState/0x70) meets nothing: the kernel "
                                             "names a virtual key", 0) == 0 &&
                           warnings[7].rfind("rule 11 (/system/win32k/NtUserGetClassName/other) meets nothing: the kernel "
                                             "names a window", 0) == 0 &&
                           warnings[8].rfind("rule 12 (/system/win32k/NtUserInternalGetWindowText/@other) leaves the windows",
                                             0) == 0 &&
                           warnings[9].rfind("rule 15 (/system/win32k/NtUserCallHwndParam/@other) probes NtUserCallHwndParam",
                                             0) == 0 &&
                           warnings[10].rfind("rule 15 (/system/win32k/NtUserCallHwndParam/@other) leaves the windows", 0) == 0 &&
                           warnings[11].rfind("rule 16 (/system/wmi/win32_process) meets queries, not a class's methods", 0) == 0,
                       true);
                const bool broad = parses("protect MapleStory.exe\n"
                                          "deny|system|/system/win32k/NtUserGetAsyncKeyState/0x0000007A\n"
                                          "deny|system|/system/win32k/NtUserGetAsyncKeyState/0x0000007a\n"
                                          "deny|system|/system/ntdll\n"
                                          "deny|system|/system/ntdll/*\n"
                                          "audit|system|/system/ntdll/*/35\n"
                                          "deny|system|/system/win32k/*/@other\n"
                                          "deny|system|/system/win32k/NtUserMessageCall/@other\n"
                                          "allow|system|/system/win32k/NtUserGetDC/@unknown|rights=query\n"
                                          "deny|system|/system/win32k/NtUserGetDC/@*\n");
                if (broad) warnings = PolicyWarnings(*parsed);
                expect("Linux: check warns of an uppercase virtual key, a deny of every ntdll.so call, a pattern probing "
                       "NtQueryVirtualMemory or NtUserMessageCall, a star before a function's key, an allow on @unknown and "
                       "a pattern matching @unknown without naming it",
                       broad && warnings.size() == 11 &&
                           warnings[0].rfind("rule 1 (/system/win32k/NtUserGetAsyncKeyState/0x0000007A) meets nothing: the "
                                             "kernel names a virtual key 0x%08x, lowercase", 0) == 0 &&
                           warnings[1].rfind("rule 3 (/system/ntdll) probes NtQueryVirtualMemory", 0) == 0 &&
                           warnings[2].rfind("rule 3 (/system/ntdll) refuses every ntdll.so call", 0) == 0 &&
                           warnings[3].rfind("rule 4 (/system/ntdll/*) probes NtQueryVirtualMemory", 0) == 0 &&
                           warnings[4].rfind("rule 4 (/system/ntdll/*) refuses every ntdll.so call", 0) == 0 &&
                           warnings[5].rfind("rule 5 (/system/ntdll/*/35) probes NtQueryVirtualMemory", 0) == 0 &&
                           warnings[6].rfind("rule 6 (/system/win32k/*/@other) meets nothing: a key", 0) == 0 &&
                           warnings[7].rfind("rule 7 (/system/win32k/NtUserMessageCall/@other) probes NtUserMessageCall", 0) == 0 &&
                           warnings[8].rfind("rule 7 (/system/win32k/NtUserMessageCall/@other) leaves the windows", 0) == 0 &&
                           warnings[9].rfind("rule 8 (/system/win32k/NtUserGetDC/@unknown) is an allow on a window", 0) == 0 &&
                           warnings[10].rfind("rule 9 (/system/win32k/NtUserGetDC/@*) matches @unknown without naming it", 0) == 0,
                       true);
                const bool unixRules = parses("protect MapleStory.exe\nblock-network on\n"
                                              "deny|message|unix=/@/tmp/.X11-unix/X5\n"
                                              "deny|message|unix=/run/user/*/bus|image=grap-core64.aes\n"
                                              "deny|message|unix=/*\n"
                                              "deny|message|unix=/run/user/1000/pulse/native|match=0000@0\n"
                                              "deny|message|unix=/tmp/.X11-unix/X5|index=1\n"
                                              "audit|message|unix=/tmp/.X11-unix/X5\n"
                                              "deny|message|unix=/@kf-other\n");
                if (unixRules) warnings = PolicyWarnings(*parsed);
                expect("Linux: check warns of a unix= deny on an X11, D-Bus or Pulse socket without match= or index= (not "
                       "an audit, not another socket), and of one meeting Wine's server socket",
                       unixRules && warnings.size() == 3 &&
                           warnings[0].rfind("rule 10001 (unix=/@/tmp/.X11-unix/X5) refuses sends to an X11", 0) == 0 &&
                           warnings[1].rfind("rule 10002 (unix=/run/user/*/bus) refuses sends", 0) == 0 &&
                           warnings[2].rfind("rule 10003 (unix=/*) meets Wine's server connection", 0) == 0, true);
                std::error_code made;
                const std::filesystem::path scratch = std::filesystem::canonical(std::filesystem::temp_directory_path()) /
                                                      ("kfilterctl-self-test-" + std::to_string(getpid()));
                std::filesystem::create_directories(scratch / "real", made);
                std::filesystem::create_directory_symlink(scratch / "real", scratch / "link", made);
                const std::string base = scratch.string();
                const std::string named = "protect MapleStory.exe\nblock-network on\n"
                                          "deny|message|unix=" + base + "/link/kf|size=1-2\n"
                                          "deny|message|unix=" + base + "/real/kf|size=1-2\n"
                                          "deny|message|unix=" + base + "/real\n"
                                          "deny|message|unix=/tmp/.wine-1000/*/socket|match=00@0\n"
                                          "allow|message|unix=/tmp/.wine-*/server-*/socket|uses=1\n"
                                          "deny|message|unix=/tmp/.X11-unix/X5|size=100000-200000\n";
                const bool unixNamed = !made && parses(named.c_str());
                if (unixNamed) warnings = PolicyWarnings(*parsed);
                std::filesystem::remove_all(scratch, made);
                expect("Linux: check warns of a unix= rule through a symlink (a connected send names it resolved), on a "
                       "directory (the whole name), and meeting Wine's server socket even with match= or as a counted allow",
                       unixNamed && warnings.size() == 5 &&
                           warnings[0] == "rule 10001 (unix=" + base + "/link/kf) names its peer through a symlink: a send on a "
                                          "connected socket names it " + base + "/real/kf (its bound path, symlinks resolved), "
                                          "so this rule meets only sendto's to the name as written" &&
                           warnings[1].rfind("rule 10003 (unix=" + base + "/real) meets nothing: unix= matches the peer's whole "
                                             "name", 0) == 0 &&
                           warnings[2].rfind("rule 10004 (unix=/tmp/.wine-1000/*/socket) meets Wine's server connection", 0) == 0 &&
                           warnings[3].rfind("rule 10005 (unix=/tmp/.wine-*/server-*/socket) meets Wine's server connection", 0) == 0 &&
                           warnings[4].rfind("rule 10006 (unix=/tmp/.X11-unix/X5) refuses sends to an X11", 0) == 0, true);
                expect("Linux: check warns of a unix= rule without block-network",
                       parses("protect MapleStory.exe\naudit|message|unix=/@kf-other\n") && PolicyWarnings(*parsed).size() == 1 &&
                           PolicyWarnings(*parsed)[0] == "rule 10001 (unix=/@kf-other) meets nothing: message rules are decided "
                                                         "only with block-network on", true);
                expect("Linux: check has no in-process warning for the live loop's win32k and WMI rules",
                       parses("protect MapleStory.exe\ndeny|system|/system/win32k/NtUserGetClassName|exact|image=MapleStory.exe\n"
                              "deny|system|/system/win32k/NtUserBuildHwndList|exact\ndeny|system|/system/wmi/@other|exact\n"
                              "deny|system|/system/wmi/win32_bios|exact\n") &&
                           PolicyWarnings(*parsed).empty(), true);
                expect("Linux: hide on deny rules, module= on non-registry rules",
                       parses("protect MapleStory.exe\ndeny|file|/home/*/.steam|hide\n"
                              "deny|thread|\\MapleStory.exe|module=inject*.dll\n") &&
                           parsed->Rules[0].Flags == KFILTER_RULE_HIDE && parsed->Rules[1].Flags == KFILTER_RULE_MODULE &&
                           wcscmp(parsed->Rules[1].Value, L"inject*.dll") == 0 && OfflineLoad(*parsed) &&
                           !parses("protect MapleStory.exe\nallow|file|/x|rights=read|hide\n") &&
                           !parses("protect MapleStory.exe\ndeny|registry|\\REGISTRY\\MACHINE\\X|module=x.dll\n"), true);
                /* Metadata queries: query comes with every acting right of an allow and with read of a
                 * deny; strict file queries add the ancestors (exact, after every rule); queries spend no
                 * use of a counted allow; the flag needs the BPF layer. */
                const char* queries = "protect /x\nblock-files on\nblock-file-queries on\n"
                                      "allow|file|/home/u/.wine/*|rights=read\nallow|file|/home/u/out|rights=write\n"
                                      "deny|file|/home/u/secret|rights=read\ndeny|file|/home/u/nowrite|rights=write\n"
                                      "allow|file|/home/u/once|rights=read|uses=1\n";
                bool loose = parses(queries) && parsed->RuleCount == 5;
                bool strict = parses((std::string(queries) + "default-deny on\n").c_str()) && OfflineLoad(*parsed);
                auto decide = [](ULONG target, const wchar_t* path, ULONG rights, ULONG action, ULONG ruleId) {
                    PolicyDecision decision = OfflineDecide(target, path, rights, L"", false, 0);
                    return decision.Action == action && decision.RuleId == ruleId;
                };
                const ULONG query = KFILTER_RIGHT_QUERY, file = KFILTER_TARGET_FILE, dir = KFILTER_TARGET_DIR;
                ULONG unenforcedRule = 0;
                expect("Linux: file queries implied, ancestors allowed, uses kept",
                       loose && strict && parsed->RuleCount == 8 && parsed->Rules[0].Rights == (KFILTER_RIGHT_READ | query) &&
                           parsed->Rules[1].Rights == (KFILTER_RIGHT_WRITE | query) &&
                           parsed->Rules[2].Rights == (KFILTER_RIGHT_READ | query) && parsed->Rules[3].Rights == KFILTER_RIGHT_WRITE &&
                           wcscmp(parsed->Rules[5].Path, L"/home") == 0 && wcscmp(parsed->Rules[7].Path, L"/home/u/.wine") == 0 &&
                           parsed->Rules[6].Targets == dir && parsed->Rules[6].Rights == query &&
                           parsed->Rules[6].Flags == KFILTER_RULE_EXACT &&
                           decide(file, L"/home/u/.wine/x", query, KFilterActionAllow, 1) &&
                           decide(file, L"/home/u/out", query, KFilterActionAllow, 2) &&
                           decide(file, L"/home/u/secret", query, KFilterActionDeny, 3) &&
                           decide(file, L"/home/u/nowrite", query, KFilterActionDeny, 0) &&
                           decide(dir, L"/home/u", query, KFilterActionAllow, 7) &&
                           decide(dir, L"/home/u/other", query, KFilterActionDeny, 0) &&
                           decide(file, L"/home/u/once", query, KFilterActionAllow, 5) &&
                           decide(file, L"/home/u/once", query, KFilterActionAllow, 5) &&
                           decide(file, L"/home/u/once", KFILTER_RIGHT_READ, KFilterActionAllow, 5) &&
                           decide(file, L"/home/u/once", KFILTER_RIGHT_READ, KFilterActionDeny, 0) &&
                           KfPolicyUnenforced(parsed.get(), KFILTER_REG_MINIFILTER, &unenforcedRule) == KFILTER_STATUS_DEGRADED_QUERY &&
                           KfPolicyUnenforced(parsed.get(), KFILTER_REG_BPF, &unenforcedRule) == 0, true);
                gLinuxPaths = linux;
            }
#endif
            expect("the trailing separator helper",
                   KfPathEndsWithSeparator(L"\\Dir\\", (unsigned long)wcslen(L"\\Dir\\")) != 0 &&
                       KfPathEndsWithSeparator(L"/Dir/", (unsigned long)wcslen(L"/Dir/")) != 0 &&
                       KfPathEndsWithSeparator(L"\\Dir", (unsigned long)wcslen(L"\\Dir")) == 0, true);
            /* The shipped default policy is the documented install path: it must
             * parse, and its two MachineIdLib allows must carry the risk reason
             * the snippet documents. */
            {
                std::wstring shippedPath = ShippedPolicyPath(L"default-policy.txt");
                expect("shipped default policy is available", !shippedPath.empty(), true);
                if (!shippedPath.empty()) {
                    std::unique_ptr<KFILTER_CONFIG> shipped(new KFILTER_CONFIG());
                    std::string shippedError;
                    const bool shippedParsed = ParsePolicy(shippedPath, shipped.get(), shippedError);
                    expect("shipped default policy parses", shippedParsed, true);
                    if (shippedParsed) {
                        unsigned machineIdRules = 0;
                        for (ULONG index = 0; index < shipped->RuleCount; index++) {
                            const KFILTER_RULE& shippedRule = shipped->Rules[index];
                            if (shippedRule.Targets != KFILTER_TARGET_FILE) continue;
                            const wchar_t* leaf = wcsrchr(shippedRule.Path, L'\\');
                            if (leaf == nullptr || _wcsicmp(leaf + 1, L"MachineIdLib.dll") != 0) continue;
                            machineIdRules++;
                            expect("shipped MachineIdLib allow carries risk",
                                   shippedRule.Risk[0] != L'\0', true);
                        }
                        expect("shipped default policy names both MachineIdLib allows",
                               machineIdRules == 2, true);
                    }
                }
            }
            /*
             * A snippet template is only useful if it matches the device, the open
             * and the control the probe and the driver actually see. Read the
             * shipped lines instead of copying them, so a stale template fails.
             */
            {
                const ULONG mountPointsCode = CTL_CODE(0x0000006D, 2, METHOD_BUFFERED, FILE_ANY_ACCESS);
                std::wstring snippet = ShippedPolicyPath(L"device-policy-snippet.txt");
                expect("device policy snippet is available", !snippet.empty(), true);
                if (!snippet.empty()) {
                    std::vector<std::string> rows;
                    {
                        std::ifstream stream{std::filesystem::path(snippet)};
                        std::string line;
                        while (std::getline(stream, line)) {
                            if (line.rfind("# allow|device|", 0) == 0) rows.push_back(line.substr(2));
                        }
                    }
                    auto field = [](const std::string& row, size_t index) -> std::string {
                        size_t start = 0;
                        for (size_t seen = 0; seen < index; seen++) {
                            size_t pipe = row.find('|', start);
                            if (pipe == std::string::npos) return std::string();
                            start = pipe + 1;
                        }
                        size_t end = row.find('|', start);
                        return row.substr(start, end == std::string::npos ? std::string::npos : end - start);
                    };
                    auto pathOf = [&](const std::string& row) { return Utf8ToWide(field(row, 2)); };
                    auto rowsFor = [&](const std::wstring& match, std::string& openRow, std::string& controlRow) {
                        openRow.clear();
                        controlRow.clear();
                        for (const auto& row : rows) {
                            if (pathOf(row).find(match) == std::wstring::npos) continue;
                            std::string value = field(row, 3);
                            if (value == "value=0x00000000") openRow = row;
                            else if (value.rfind("value=", 0) == 0) controlRow = row;
                        }
                    };

                    struct DeviceTemplate {
                        const char* label;
                        const wchar_t* match;
                        ULONG code;
                    } templates[] = {
                        { "device template mount point", L"\\Device\\MountPointManager", mountPointsCode },
                        { "device template storage adapter", L"\\Device\\RaidPort0",
                          (ULONG)IOCTL_SCSI_GET_INQUIRY_DATA },
                        { "device template network adapter", L"adapter-GUID",
                          (ULONG)IOCTL_NDIS_QUERY_GLOBAL_STATS },
                    };
                    wchar_t openValue[16];
                    wchar_t codeValue[16];
                    expect("device open value is the canonical zero",
                           KfDeviceValueText(0, openValue, RTL_NUMBER_OF(openValue)) == 10 &&
                               wcscmp(openValue, L"0x00000000") == 0, true);
                    expect("device control value is the canonical IOCTL",
                           KfDeviceValueText(mountPointsCode, codeValue, RTL_NUMBER_OF(codeValue)) == 10 &&
                               wcscmp(codeValue, L"0x006D0008") == 0, true);

                    unsigned checked = 0;
                    for (const auto& device : templates) {
                        std::string openRow;
                        std::string controlRow;
                        rowsFor(device.match, openRow, controlRow);
                        std::string name = device.label;
                        expect((name + " open row present").c_str(), !openRow.empty(), true);
                        expect((name + " control row present").c_str(), !controlRow.empty(), true);
                        if (openRow.empty() || controlRow.empty()) continue;
                        checked++;
                        expect((name + " pair names one device").c_str(),
                               pathOf(openRow) == pathOf(controlRow), true);
                        std::wstring path = pathOf(controlRow);
                        wchar_t canonical[16];
                        swprintf_s(canonical, L"0x%08lX", (unsigned long)device.code);

                        /* Both rows merged: the open and its documented control are
                         * allowed, each by its own row, and any other control reaches
                         * the broad deny. */
                        std::string merged = "protect \\x.exe\n" + openRow + "\n" + controlRow +
                                             "\ndeny|device|\\Device\n";
                        expect((name + " rows parse").c_str(), parses(merged.c_str()), true);
                        PolicyDecision open = EvaluatePolicy(*parsed, KFILTER_TARGET_DEVICE, path,
                                                            KFILTER_RIGHT_RAW_DEVICE, openValue);
                        expect((name + " open is allowed by the open row").c_str(),
                               open.Action == KFilterActionAllow && open.RuleId == 1, true);
                        PolicyDecision control = EvaluatePolicy(*parsed, KFILTER_TARGET_DEVICE, path,
                                                                KFILTER_RIGHT_RAW_DEVICE, canonical);
                        expect((name + " control is allowed by its own row").c_str(),
                               control.Action == KFilterActionAllow && control.RuleId == 2, true);
                        expect((name + " other control reaches the broad deny").c_str(),
                               EvaluatePolicy(*parsed, KFILTER_TARGET_DEVICE, path,
                                              KFILTER_RIGHT_RAW_DEVICE, L"0x00000001").Action ==
                                   KFilterActionDeny,
                               true);

                        /* The control row alone leaves the open denied, so the pair is
                         * what makes the route usable. */
                        std::string alone = "protect \\x.exe\n" + controlRow + "\ndeny|device|\\Device\n";
                        expect((name + " control row alone parses").c_str(), parses(alone.c_str()), true);
                        expect((name + " control row alone leaves the open denied").c_str(),
                               EvaluatePolicy(*parsed, KFILTER_TARGET_DEVICE, path,
                                              KFILTER_RIGHT_RAW_DEVICE, openValue).Action ==
                                   KFilterActionDeny,
                               true);
                        expect((name + " control row alone still allows its code").c_str(),
                               EvaluatePolicy(*parsed, KFILTER_TARGET_DEVICE, path,
                                              KFILTER_RIGHT_RAW_DEVICE, canonical).Action ==
                                   KFilterActionAllow,
                               true);
                    }
                    expect("every valued device template was checked", checked == 3, true);

                    /* The storage path must be the canonical name the driver stores,
                     * not the \GLOBAL??\ScsiN: link it enumerated. */
                    std::string storageOpen;
                    std::string storageControl;
                    rowsFor(L"\\Device\\RaidPort0", storageOpen, storageControl);
                    std::wstring storagePath = pathOf(storageControl);
                    const std::wstring scsiPrefix = L"\\Device\\Scsi";
                    bool scsiLink = storagePath.size() > scsiPrefix.size() &&
                                    storagePath.compare(0, scsiPrefix.size(), scsiPrefix) == 0 &&
                                    storagePath[scsiPrefix.size()] >= L'0' &&
                                    storagePath[scsiPrefix.size()] <= L'9';
                    expect("device template path is not a ScsiN link",
                           !storagePath.empty() && !scsiLink && storagePath.back() != L':', true);
                    wchar_t target[1024] = {};
                    if (QueryDosDeviceW(L"Scsi0:", target, (DWORD)RTL_NUMBER_OF(target)) != 0) {
                        std::wstring resolved = target;
                        if (resolved.rfind(L"\\Device\\RaidPort", 0) == 0) {
                            expect("device template uses the canonical Scsi0 target",
                                   storagePath == resolved, true);
                        }
                    }
                }
            }
            const char* newRiskModules[] = {
                "MachineIdLib.dll", "tbs.dll", "nvapi64.dll", "atiadlxx.dll",
                "setupapi.dll", "cfgmgr32.dll", "wlanapi.dll", "dhcpcsvc.dll"
            };
            for (const char* module : newRiskModules) {
                std::string moduleRule = "protect \\x.exe\nallow|file|\\Device\\HarddiskVolume3\\Windows\\System32\\" +
                                         std::string(module) + "|rights=read";
                expect("new identity module requires risk", !parses((moduleRule + "\n").c_str()), true);
                expect("new identity module accepts risk", parses((moduleRule + "|risk=identity\n").c_str()), true);
            }
            const char* riskyPaths[] = {
                "\\Device\\HarddiskVolume4\\Windows\\System32\\RPCRT4.DLL",
                "\\Device\\HarddiskVolume3\\Windows\\System32\\wbem\\wbemprox.dll",
                "\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\wbem\\wbemprox.dll",
                "\\Device\\HarddiskVolume4\\Nexon\\Library\\maplestorycw",
            };
            for (const char* path : riskyPaths) {
                std::string policyText = "protect \\x.exe\nallow|file|" + std::string(path) + "|rights=read,execute";
                expect("riskless module or parent rejected", !parses((policyText + "\n").c_str()), true);
                expect("risked module or parent accepted", parses((policyText + "|risk=identity\n").c_str()), true);
            }
            expect("ordinary DLL remains riskless",
                   parses("protect \\x.exe\nallow|file|\\Device\\HarddiskVolume4\\Windows\\System32\\version.dll|rights=read\n"), true);
            expect("module name on another target remains riskless",
                   parses("protect \\x.exe\nallow|registry|\\REGISTRY\\MACHINE\\Software\\rpcrt4.dll|rights=read\n"), true);
            expect("excluded module extension remains riskless",
                   parses("protect \\x.exe\nallow|file|\\Device\\HarddiskVolume4\\Windows\\System32\\rpcrt4.dll|rights=execute|ext=exe\n"), true);
            std::string longRelative(511, 'a');
            expect("511-char relative rule path is rejected, not fatal",
                   !parses(("protect \\x.exe\nallow|file|" + longRelative + "|rights=read\n").c_str()), true);
            expect("510-char relative rule path is accepted",
                   parses(("protect \\x.exe\nallow|file|" + std::string(510, 'a') + "|rights=read\n").c_str()), true);
            expect("511-char protect name is rejected, not fatal",
                   !parses(("protect " + longRelative + "\n").c_str()), true);
            expect("512-char prefixed rule path is still rejected",
                   !parses(("protect \\x.exe\nallow|file|\\" + longRelative + "|rights=read\n").c_str()), true);
            expect("read-only pipe policy permits a pipe create",
                   parses("mode block\nprotect \\x.exe\ndefault-deny on\nblock-files on\n"
                          "allow|pipe|\\Device\\NamedPipe\\foo|rights=read|uses=1|risk=pipe\n") &&
                       EvaluatePolicy(*parsed, KFILTER_TARGET_PIPE, L"\\Device\\NamedPipe\\foo",
                                      KfCreateRightsForMajor(GENERIC_READ, 0, 0x01u, 0), L"").Action ==
                           KFilterActionAllow, true);
            expect("read-only mailslot policy permits a mailslot create",
                   parses("mode block\nprotect \\x.exe\ndefault-deny on\nblock-files on\n"
                          "allow|pipe|\\Device\\Mailslot\\foo|rights=read|uses=1|risk=pipe\n") &&
                       EvaluatePolicy(*parsed, KFILTER_TARGET_PIPE, L"\\Device\\Mailslot\\foo",
                                      KfCreateRightsForMajor(GENERIC_READ, 0, 0x13u, 0), L"").Action ==
                           KFilterActionAllow, true);
            expect("read-only file policy still denies overwrite",
                   parses("mode block\nprotect \\x.exe\ndefault-deny on\nblock-files on\n"
                          "allow|file|\\Device\\HarddiskVolume3\\Docs\\a.txt|rights=read\n") &&
                       EvaluatePolicy(*parsed, KFILTER_TARGET_FILE, L"\\Device\\HarddiskVolume3\\Docs\\a.txt",
                                      KfCreateRightsForMajor(GENERIC_READ, 5u << 24, 0x00u, 0), L"").Action ==
                           KFilterActionDeny, true);
            (VOID)DeleteFileW(policyPath.c_str());

            /* Parse the per-address network text, then match the parsed rule:
             * a hand-built KFILTER_NET_RULE would not catch ip/prefix/port/
             * rights parser regressions. */
            std::wstring networkPath = std::wstring(tempDirectory) + L"kfilter-self-test-network.txt";
            {
                std::ofstream policy{std::filesystem::path(networkPath)};
                policy << "mode block\nprotect \\x.exe\nblock-network on\n"
                          "allow|network|ip=1.2.3.4/32|port=443|proto=tcp|rights=connect|uses=1|risk=test\n";
            }
            std::unique_ptr<KFILTER_CONFIG> netConfig(new KFILTER_CONFIG());
            bool parsedNet = ParsePolicy(networkPath, netConfig.get(), error);
            expect("parsed per-address network policy",
                   parsedNet && netConfig->NetworkRuleCount == 1, true);
            if (parsedNet && netConfig->NetworkRuleCount == 1) {
                UCHAR listed[16] = { 1, 2, 3, 4 };
                UCHAR unlisted[16] = { 1, 2, 3, 5 };
                expect("parsed per-address allow matches",
                       KfNetworkRuleMatches(&netConfig->Network[0], 4, 6, 443, listed,
                                            KFILTER_RIGHT_CONNECT) != 0, true);
                expect("parsed per-address allow rejects other address",
                       KfNetworkRuleMatches(&netConfig->Network[0], 4, 6, 443, unlisted,
                                            KFILTER_RIGHT_CONNECT) == 0, true);
            }
            (VOID)DeleteFileW(networkPath.c_str());
        }
    }

    {
        KFILTER_RULE enumerationRules[2]{};
        enumerationRules[0].Action = KFilterActionDeny;
        enumerationRules[0].Targets = KFILTER_TARGET_REGISTRY;
        enumerationRules[0].Rights = KFILTER_RIGHT_READ;
        enumerationRules[0].RuleId = 7;
        wcscpy_s(enumerationRules[0].Path, KFILTER_MAX_NAME, L"\\REGISTRY\\MACHINE\\Key");
        wcscpy_s(enumerationRules[0].Value, KFILTER_MAX_VALUE, L"Secret");
        enumerationRules[1] = enumerationRules[0];
        enumerationRules[1].Action = KFilterActionAllow;
        enumerationRules[1].Rights = KFILTER_RIGHT_READ | KFILTER_RIGHT_ENUMERATE;
        enumerationRules[1].RuleId = 8;
        enumerationRules[1].Value[0] = L'\0';
        ULONG ruleId = 0;
        expect("read-only value deny blocks enumeration",
               KfRegistryValueEnumerationDenied(enumerationRules, 2, L"\\REGISTRY\\MACHINE\\Key",
                                                (ULONG)wcslen(L"\\REGISTRY\\MACHINE\\Key"), &ruleId) != 0 &&
                   ruleId == 7, true);
        enumerationRules[0].Rights = KFILTER_RIGHT_WRITE;
        expect("write-only value deny permits enumeration",
               KfRegistryValueEnumerationDenied(enumerationRules, 2, L"\\REGISTRY\\MACHINE\\Key",
                                                (ULONG)wcslen(L"\\REGISTRY\\MACHINE\\Key"), &ruleId) == 0, true);
        KFILTER_RULE earlierAllow[2] = { enumerationRules[1], enumerationRules[0] };
        earlierAllow[1].Rights = KFILTER_RIGHT_READ;
        expect("earlier key allow controls enumeration",
               KfRegistryValueEnumerationDenied(earlierAllow, 2, L"\\REGISTRY\\MACHINE\\Key",
                                                (ULONG)wcslen(L"\\REGISTRY\\MACHINE\\Key"), &ruleId) == 0, true);
        KF_MATCH_INPUT enumInput{};
        enumInput.Target = KFILTER_TARGET_REGISTRY;
        enumInput.Rights = KFILTER_RIGHT_READ | KFILTER_RIGHT_ENUMERATE;
        enumInput.Path = L"\\REGISTRY\\MACHINE\\Key";
        enumInput.PathLength = (ULONG)wcslen(L"\\REGISTRY\\MACHINE\\Key");
        enumerationRules[1].Rights = KFILTER_RIGHT_READ;
        expect("read-only key allow does not cover enumeration",
               KfRuleMatches(&enumerationRules[1], &enumInput) == 0, true);
        /* An exact value deny covers its own key only: the allow above governs the subkey. */
        enumerationRules[0].Rights = KFILTER_RIGHT_READ;
        enumerationRules[0].Flags = KFILTER_RULE_EXACT;
        expect("exact value deny does not block descendant enumeration",
               KfRegistryValueEnumerationDenied(enumerationRules, 2,
                   L"\\REGISTRY\\MACHINE\\Key\\Sub",
                   (ULONG)wcslen(L"\\REGISTRY\\MACHINE\\Key\\Sub"), &ruleId) == 0,
               true);
        expect("exact value deny still blocks its key enumeration",
               KfRegistryValueEnumerationDenied(enumerationRules, 2,
                   L"\\REGISTRY\\MACHINE\\Key",
                   (ULONG)wcslen(L"\\REGISTRY\\MACHINE\\Key"), &ruleId) != 0 && ruleId == 7,
               true);
    }

    expect("block table-full admission refused",
           KfAdmissionCreationDenied(KFILTER_MODE_BLOCK, 0xC000009Au) != 0, true);
    expect("block missing-image admission refused",
           KfAdmissionCreationDenied(KFILTER_MODE_BLOCK, 0xC0000225u) != 0, true);
    expect("audit admission failure not refused",
           KfAdmissionCreationDenied(KFILTER_MODE_AUDIT, 0xC0000225u) == 0, true);
    expect("unrelated status does not force admission refusal",
           KfAdmissionCreationDenied(KFILTER_MODE_BLOCK, 0xC0000022u) == 0, true);
    expect("block tracking failure rolls back", ShouldRollback(KFILTER_MODE_BLOCK, 1), true);
    expect("audit tracking failure does not roll back", !ShouldRollback(KFILTER_MODE_AUDIT, 1), true);
    expect("off tracking failure does not roll back", !ShouldRollback(KFILTER_MODE_OFF, 1), true);
    expect("duplicate admission is success",
           ClassifyTrackResult(TRUE, 0) == TrackOutcomeTracked, true);
    expect("confirmed nonmatch ignored",
           ClassifyTrackResult(FALSE, ERROR_NOT_FOUND) == TrackOutcomeIgnored, true);
    expect("exited process ignored",
           ClassifyTrackResult(FALSE, ERROR_INVALID_PARAMETER) == TrackOutcomeIgnored, true);
    expect("removed PID handle ignored",
           ClassifyTrackResult(FALSE, ERROR_INVALID_HANDLE) == TrackOutcomeIgnored, true);
    expect("name resolution failure not ignored",
           ClassifyTrackResult(FALSE, ERROR_GEN_FAILURE) == TrackOutcomeFailed, true);
    expect("access failure not ignored",
           ClassifyTrackResult(FALSE, ERROR_ACCESS_DENIED) == TrackOutcomeFailed, true);
    expect("full table not ignored",
           ClassifyTrackResult(FALSE, ERROR_NOT_ENOUGH_MEMORY) == TrackOutcomeFailed, true);
    expect("table resources not ignored",
           ClassifyTrackResult(FALSE, ERROR_NO_SYSTEM_RESOURCES) == TrackOutcomeFailed, true);
    expect("control operations need read and write",
           KfRightsFromControlOperation() == (KFILTER_RIGHT_READ | KFILTER_RIGHT_WRITE), true);

    expect("MapleStory suffix positive",
           KfNameMatchesSuffix(L"\\Device\\HarddiskVolume3\\tmp\\MapleStory.exe",
                               (ULONG)wcslen(L"\\Device\\HarddiskVolume3\\tmp\\MapleStory.exe"),
                               L"\\MapleStory.exe", (ULONG)wcslen(L"\\MapleStory.exe")) != 0, true);
    expect("NotMapleStory suffix negative",
           KfNameMatchesSuffix(L"\\Device\\HarddiskVolume3\\tmp\\NotMapleStory.exe",
                               (ULONG)wcslen(L"\\Device\\HarddiskVolume3\\tmp\\NotMapleStory.exe"),
                               L"\\MapleStory.exe", (ULONG)wcslen(L"\\MapleStory.exe")) == 0, true);

    expect("deny audit network event is would-deny",
           (KfNetworkEventFlags(KFilterActionDeny, KFILTER_MODE_AUDIT) &
            (KFILTER_EVENT_FLAG_NETWORK | KFILTER_EVENT_FLAG_WOULD_DENY)) ==
               (KFILTER_EVENT_FLAG_NETWORK | KFILTER_EVENT_FLAG_WOULD_DENY), true);
    expect("explicit audit block network event is not would-deny",
           KfNetworkEventFlags(KFilterActionAudit, KFILTER_MODE_BLOCK) == KFILTER_EVENT_FLAG_NETWORK, true);
    expect("explicit audit audit network event is not would-deny",
           KfNetworkEventFlags(KFilterActionAudit, KFILTER_MODE_AUDIT) == KFILTER_EVENT_FLAG_NETWORK, true);
    expect("deny block network event is not would-deny",
           KfNetworkEventFlags(KFilterActionDeny, KFILTER_MODE_BLOCK) == KFILTER_EVENT_FLAG_NETWORK, true);
    expect("network risk connect value is the right",
           KfNetworkEventValue(KFilterActionRisk, KFILTER_RIGHT_CONNECT, 443) == KFILTER_RIGHT_CONNECT, true);
    expect("network risk listen value is the right",
           KfNetworkEventValue(KFilterActionRisk, KFILTER_RIGHT_LISTEN, 443) == KFILTER_RIGHT_LISTEN, true);
    expect("network allow value stays the port",
           KfNetworkEventValue(KFilterActionAllow, KFILTER_RIGHT_CONNECT, 443) == 443, true);
    expect("network deny value stays the port",
           KfNetworkEventValue(KFilterActionDeny, KFILTER_RIGHT_CONNECT, 443) == 443, true);
    expect("network audit value stays the port",
           KfNetworkEventValue(KFilterActionAudit, KFILTER_RIGHT_CONNECT, 443) == 443, true);
    expect("callout unregister success is complete",
           KfNetworkUnregisterComplete(0) != 0, true);
    expect("callout already absent is complete",
           KfNetworkUnregisterComplete(static_cast<long>(0xC0220001)) != 0, true);
    expect("callout in use is not complete",
           KfNetworkUnregisterComplete(static_cast<long>(0xC022000A)) == 0, true);
    expect("busy callout is not complete",
           KfNetworkUnregisterComplete(static_cast<long>(0x80000011)) == 0, true);
    expect("ordinary unregister failure is not complete",
           KfNetworkUnregisterComplete(static_cast<long>(0xC0000001)) == 0, true);

    {
        std::unique_ptr<KFILTER_CONFIG> offlineHolder(new KFILTER_CONFIG());
        KFILTER_CONFIG& offline = *offlineHolder;
        offline.Mode = KFILTER_MODE_AUDIT;
        offline.Flags = KFILTER_CFG_BLOCK_FILES;
        offline.RuleCount = 1;
        offline.Rules[0].Action = KFilterActionDeny;
        offline.Rules[0].Targets = KFILTER_TARGET_FILE;
        offline.Rules[0].Rights = KFILTER_RIGHT_READ;
        offline.Rules[0].RuleId = 4;
        wcscpy_s(offline.Rules[0].Path, KFILTER_MAX_NAME, L"\\Device\\HarddiskVolume*\\Docs");
        PolicyDecision decision = EvaluatePolicy(offline, KFILTER_TARGET_FILE,
                                                 L"\\Device\\HarddiskVolume3\\Docs\\a.txt",
                                                 KFILTER_RIGHT_READ, L"");
        expect("audit replay labels would-deny",
               decision.Action == KFilterActionDeny &&
                   strcmp(DecisionName(decision.Action, offline.Mode), "would-deny") == 0, true);
        offline.Mode = KFILTER_MODE_OFF;
        decision = EvaluatePolicy(offline, KFILTER_TARGET_FILE,
                                  L"\\Device\\HarddiskVolume3\\Docs\\a.txt", KFILTER_RIGHT_READ, L"");
        expect("mode off replay allows", decision.Action == KFilterActionAllow, true);
        offline.Mode = KFILTER_MODE_AUDIT;
        offline.Flags = 0;
        decision = EvaluatePolicy(offline, KFILTER_TARGET_FILE,
                                  L"\\Device\\HarddiskVolume3\\Docs\\a.txt", KFILTER_RIGHT_READ, L"");
        expect("disabled file layer replay allows", decision.Action == KFilterActionAllow, true);
        offline.Mode = KFILTER_MODE_BLOCK;
        offline.Flags = KFILTER_CFG_BLOCK_FILES;
        decision = EvaluatePolicy(offline, KFILTER_TARGET_FILE, L"", KFILTER_RIGHT_READ, L"");
        expect("block replay missing name denies", decision.Action == KFilterActionDeny, true);
        offline.Mode = KFILTER_MODE_AUDIT;
        offline.Flags = KFILTER_CFG_BLOCK_FILES | KFILTER_CFG_DEFAULT_DENY;
        decision = EvaluatePolicy(offline, KFILTER_TARGET_FILE, L"", KFILTER_RIGHT_READ, L"");
        expect("audit replay missing name reports would-deny",
               decision.Action == KFilterActionDeny &&
                   strcmp(DecisionName(decision.Action, offline.Mode), "would-deny") == 0, true);

        memset(&offline, 0, sizeof(offline));
        offline.Mode = KFILTER_MODE_BLOCK;
        offline.Flags = KFILTER_CFG_BLOCK_REGISTRY;
        offline.RuleCount = 2;
        offline.Rules[0].Action = KFilterActionDeny;
        offline.Rules[0].Targets = KFILTER_TARGET_REGISTRY;
        offline.Rules[0].Rights = KFILTER_RIGHT_READ;
        offline.Rules[0].RuleId = 7;
        wcscpy_s(offline.Rules[0].Path, KFILTER_MAX_NAME, L"\\REGISTRY\\MACHINE\\Key");
        wcscpy_s(offline.Rules[0].Value, KFILTER_MAX_VALUE, L"Secret");
        offline.Rules[1] = offline.Rules[0];
        offline.Rules[1].Action = KFilterActionAllow;
        offline.Rules[1].Rights = KFILTER_RIGHT_READ | KFILTER_RIGHT_ENUMERATE;
        offline.Rules[1].RuleId = 8;
        offline.Rules[1].Value[0] = L'\0';
        decision = EvaluatePolicy(offline, KFILTER_TARGET_REGISTRY, L"\\REGISTRY\\MACHINE\\Key",
                                  KFILTER_RIGHT_ENUMERATE, L"", true);
        expect("registry enumeration replay uses conservative helper",
               decision.Action == KFilterActionDeny && decision.RuleId == 7, true);
        decision = EvaluatePolicy(offline, KFILTER_TARGET_REGISTRY, L"\\REGISTRY\\MACHINE\\Key",
                                  KFILTER_RIGHT_READ, L"");
        expect("plain registry open uses ordinary rules",
               decision.Action == KFilterActionAllow && decision.RuleId == 8, true);
        offline.Rules[0].Rights = KFILTER_RIGHT_WRITE;
        decision = EvaluatePolicy(offline, KFILTER_TARGET_REGISTRY, L"\\REGISTRY\\MACHINE\\Key",
                                  KFILTER_RIGHT_ENUMERATE, L"", true);
        expect("write-only value deny replay allows enumeration",
               decision.Action == KFilterActionAllow && decision.RuleId == 8, true);
    }

    {
        /* Rule index: the candidates come back in rule order and include every rule that can match. */
        std::unique_ptr<KFILTER_RULE[]> rules(new KFILTER_RULE[4]());
        const wchar_t* paths[] = { L"\\REGISTRY\\MACHINE\\Software\\A", L"\\Device\\HarddiskVolume*\\Windows",
                                   L"\\registry\\machine\\software", L"\\REGISTRY\\MACHINE\\Software\\AB" };
        for (ULONG index = 0; index < 4; index++) wcscpy_s(rules[index].Path, KFILTER_MAX_NAME, paths[index]);
        ULONG keys[4], keyRules[4], globList[4], globCount = 0;
        ULONG keyCount = KfIndexBuild(rules.get(), 4, keys, keyRules, globList, &globCount);
        expect("index files literal rules by path", keyCount == 3 && globCount == 1, true);
        KF_RULE_INDEX ruleIndex{ keys, keyRules, keyCount, globList, globCount };
        ULONG out[8];
        const wchar_t* request = L"\\REGISTRY\\MACHINE\\SOFTWARE\\A\\Sub";
        ULONG count = KfIndexCandidates(&ruleIndex, request, (ULONG)wcslen(request), out, 8);
        expect("index candidates in rule order", count == 3 && out[0] == 0 && out[1] == 1 && out[2] == 2, true);
        request = L"\\REGISTRY\\MACHINE\\Software\\ABC";
        count = KfIndexCandidates(&ruleIndex, request, (ULONG)wcslen(request), out, 8);
        expect("index matches on a separator boundary", count == 2 && out[0] == 1 && out[1] == 2, true);
        count = KfIndexCandidates(&ruleIndex, request, (ULONG)wcslen(request), out, 1);
        expect("index overflow asks for a full scan", count == 2, true);

        std::string error;
        ULONG field = 0;
        bool handled = false;
        expect("uses= parses", ParseCountField("uses=5", field, handled, error) && handled, true);
        expect("opens parses", ParseCountField("opens", field, handled, error) && handled, true);
        expect("counted rule defaults to phase 1",
               CompleteCount(field) == (1u | (5u << KFILTER_COUNT_USES_SHIFT) | KFILTER_COUNT_OPENS), true);
        expect("step= is refused", !ParseCountField("step=3", field, handled, error), true);
        ULONG accessRights = 0;
        expect("handle rights by name and hex",
               ParseAccessRights("synchronize,0x1000", false, accessRights, error) &&
                   accessRights == (SYNCHRONIZE | 0x1000), true);
        expect("thread handle rights",
               ParseAccessRights("suspend-resume", true, accessRights, error) &&
                   accessRights == THREAD_SUSPEND_RESUME, true);
        expect("open right parses", ParseRights("open", accessRights, error) && accessRights == KFILTER_RIGHT_OPEN, true);

        KFILTER_RULE exactRule{};
        exactRule.Action = KFilterActionAllow;
        exactRule.Targets = KFILTER_TARGET_REGISTRY;
        exactRule.Rights = KFILTER_RIGHT_READ;
        exactRule.Flags = KFILTER_RULE_EXACT;
        wcscpy_s(exactRule.Path, KFILTER_MAX_NAME, L"\\REGISTRY\\MACHINE");
        KF_MATCH_INPUT exactInput{};
        exactInput.Target = KFILTER_TARGET_REGISTRY;
        exactInput.Rights = KFILTER_RIGHT_READ;
        exactInput.Path = L"\\Registry\\Machine";
        exactInput.PathLength = (ULONG)wcslen(exactInput.Path);
        expect("exact rule matches its own path", KfRuleMatches(&exactRule, &exactInput) != 0, true);
        exactInput.Path = L"\\REGISTRY\\MACHINE\\SOFTWARE";
        exactInput.PathLength = (ULONG)wcslen(exactInput.Path);
        expect("exact rule does not match below its path", KfRuleMatches(&exactRule, &exactInput) == 0, true);
    }

    {
        /* Volume identity: only the classes the minifilter intercepts are denied. */
        std::unique_ptr<KFILTER_CONFIG> volumeHolder(new KFILTER_CONFIG());
        KFILTER_CONFIG& volume = *volumeHolder;
        volume.Mode = KFILTER_MODE_BLOCK;
        volume.Flags = KFILTER_CFG_BLOCK_VOLUME_SERIAL;
        PolicyDecision decision = EvaluatePolicy(volume, KFILTER_TARGET_VOLUME,
                                                 L"\\Device\\HarddiskVolume3",
                                                 KFILTER_RIGHT_RAW_DEVICE, L"", false, 1);
        expect("volume serial class is denied", decision.Action == KFilterActionDeny, true);
        decision = EvaluatePolicy(volume, KFILTER_TARGET_VOLUME, L"\\Device\\HarddiskVolume3",
                                  KFILTER_RIGHT_RAW_DEVICE, L"", false, 8);
        expect("volume object-id class is denied", decision.Action == KFilterActionDeny, true);
        decision = EvaluatePolicy(volume, KFILTER_TARGET_VOLUME, L"\\Device\\HarddiskVolume3",
                                  KFILTER_RIGHT_RAW_DEVICE, L"", false, 3);
        expect("other volume class is allowed", decision.Action == KFilterActionAllow, true);
        volume.Flags |= KFILTER_CFG_BLOCK_RAW_DISK;
        decision = EvaluatePolicy(volume, KFILTER_TARGET_DEVICE, L"\\Device\\HarddiskVolume3",
                                  KFILTER_RIGHT_RAW_DEVICE, L"");
        expect("unmatched device request is denied", decision.Action == KFilterActionDeny, true);

        /* Control operations request read+write; a read-only or execute-only
         * create context cannot satisfy that set. */
        KFILTER_RULE controlAllow = allowRead;
        controlAllow.Rights = KfRightsFromControlOperation();
        input.Target = KFILTER_TARGET_FILE;
        input.Path = L"\\Device\\HarddiskVolume3\\Docs\\a.txt";
        input.PathLength = (ULONG)wcslen(input.Path);
        input.Value = nullptr;
        input.ValueLength = 0;
        input.Rights = KfRightsFromControlOperation();
        expect("control request covered by read+write allow",
               KfRuleMatches(&controlAllow, &input) != 0, true);
        controlAllow.Rights = KFILTER_RIGHT_READ;
        expect("read-only allow does not cover a control request",
               KfRuleMatches(&controlAllow, &input) == 0, true);
        controlAllow.Rights = KFILTER_RIGHT_EXECUTE;
        expect("execute-only allow does not cover a control request",
               KfRuleMatches(&controlAllow, &input) == 0, true);
    }

    {
        /* A create's disposition can destroy data while the handle asks only for
         * read access. The effective rights must carry WRITE for an overwrite or
         * supersede and DELETE for delete-on-close, so a read-only allow cannot
         * authorize the create. The disposition lives in the high byte; Win32
         * CREATE_ALWAYS is FILE_OVERWRITE_IF. */
        const ULONG dispositionOpen = 1u << 24;
        const ULONG dispositionOverwrite = 4u << 24;
        const ULONG dispositionOverwriteIf = 5u << 24;
        const ULONG deleteOnClose = 0x00001000u;
        expect("create_always carries write",
               (KfCreateRights(GENERIC_READ, dispositionOverwriteIf, 0) &
                KFILTER_RIGHT_WRITE) != 0, true);
        expect("file_overwrite carries write",
               (KfCreateRights(GENERIC_READ, dispositionOverwrite, 0) &
                KFILTER_RIGHT_WRITE) != 0, true);
        expect("delete-on-close carries delete",
               (KfCreateRights(GENERIC_READ, deleteOnClose, 0) &
                KFILTER_RIGHT_DELETE) != 0, true);
        expect("plain open keeps read only",
               KfCreateRights(GENERIC_READ, dispositionOpen, 0) == KFILTER_RIGHT_READ, true);
        expect("read-only pipe create keeps read",
               KfCreateRightsForMajor(GENERIC_READ, 0, 0x01u, 0) == KFILTER_RIGHT_READ, true);
        expect("read-only mailslot create keeps read",
               KfCreateRightsForMajor(GENERIC_READ, 0, 0x13u, 0) == KFILTER_RIGHT_READ, true);
        expect("real create still folds its disposition",
               (KfCreateRightsForMajor(GENERIC_READ, dispositionOverwriteIf, 0x00u, 0) &
                KFILTER_RIGHT_WRITE) != 0, true);
        expect("replay create_always carries write",
               (EventRights("file_create", KFILTER_TARGET_FILE, GENERIC_READ,
                            dispositionOverwriteIf) & KFILTER_RIGHT_WRITE) != 0, true);

        std::unique_ptr<KFILTER_CONFIG> createHolder(new KFILTER_CONFIG());
        KFILTER_CONFIG& create = *createHolder;
        create.Mode = KFILTER_MODE_BLOCK;
        create.Flags = KFILTER_CFG_DEFAULT_DENY | KFILTER_CFG_BLOCK_FILES;
        create.RuleCount = 1;
        create.Rules[0].Action = KFilterActionAllow;
        create.Rules[0].Targets = KFILTER_TARGET_FILE;
        create.Rules[0].Rights = KFILTER_RIGHT_READ;
        create.Rules[0].Flags = KFILTER_RULE_EXACT;
        wcscpy_s(create.Rules[0].Path, KFILTER_MAX_NAME, L"\\Device\\HarddiskVolume3\\Docs\\a.txt");
        const wchar_t* createPath = L"\\Device\\HarddiskVolume3\\Docs\\a.txt";
        ULONG createAlways = KfCreateRights(GENERIC_READ, dispositionOverwriteIf, 0);
        PolicyDecision decision = EvaluatePolicy(create, KFILTER_TARGET_FILE, createPath, createAlways, L"");
        expect("read-only allow denies create_always", decision.Action == KFilterActionDeny, true);
        ULONG plainOpen = KfCreateRights(GENERIC_READ, dispositionOpen, 0);
        decision = EvaluatePolicy(create, KFILTER_TARGET_FILE, createPath, plainOpen, L"");
        expect("read-only allow permits a plain read open", decision.Action == KFilterActionAllow, true);
        ULONG deleteClose = KfCreateRights(GENERIC_READ, deleteOnClose, 0);
        decision = EvaluatePolicy(create, KFILTER_TARGET_FILE, createPath, deleteClose, L"");
        expect("read-only allow denies delete-on-close", decision.Action == KFilterActionDeny, true);
        create.Rules[0].Rights = KFILTER_RIGHT_READ | KFILTER_RIGHT_WRITE;
        decision = EvaluatePolicy(create, KFILTER_TARGET_FILE, createPath, createAlways, L"");
        expect("read+write allow permits create_always", decision.Action == KFilterActionAllow, true);
    }

    {
        /* Linux paths: '/' boundaries, case-sensitive, no NT stream or trailing-dot stripping. */
        auto matches = [](const wchar_t* pattern, const wchar_t* text) {
            return KfPathMatches(pattern, (ULONG)wcslen(pattern), text, (ULONG)wcslen(text)) != 0;
        };
        expect("linux prefix matches below", matches(L"/opt/game", L"/opt/game/x.so"), true);
        expect("linux prefix is boundary-safe", matches(L"/opt/game", L"/opt/gamer/x.so"), false);
        expect("linux paths are case-sensitive", matches(L"/opt/game", L"/opt/GAME/x.so"), false);
        expect("nt paths stay case-insensitive", matches(L"\\Device\\X", L"\\device\\x\\y"), true);
        wchar_t name[32];
        expect("linux name keeps ':' and a trailing dot",
               KfNormalizeName(L"/a/b:c.", 7, name, 32) == 7 && wcscmp(name, L"/a/b:c.") == 0, true);
        expect("linux protect name matches on '/'",
               KfNameMatchesSuffix(L"/usr/bin/wine64", 15, L"/wine64", 7) != 0 &&
                   KfNameMatchesSuffix(L"/usr/bin/notwine64", 18, L"wine64", 6) == 0, true);
        KFILTER_RULE rules[1]{};
        rules[0].Action = KFilterActionAllow;
        rules[0].Targets = KFILTER_TARGET_FILE;
        rules[0].Rights = KFILTER_RIGHT_READ;
        wcscpy_s(rules[0].Path, KFILTER_MAX_NAME, L"/opt/game");
        ULONG keys[1], keyRules[1], globs[1], globCount = 0, found[4];
        KF_RULE_INDEX index{};
        index.Keys = keys;
        index.KeyRules = keyRules;
        index.Globs = globs;
        index.KeyCount = KfIndexBuild(rules, 1, keys, keyRules, globs, &globCount);
        index.GlobCount = globCount;
        expect("linux rule indexed on '/' prefixes",
               KfIndexCandidates(&index, L"/opt/game/lib/x.so", 18, found, 4) == 1 && found[0] == 0, true);
    }

    {
        /* Rules no layer enforces: message rules need the BPF layer (none on Windows). */
        std::unique_ptr<KFILTER_CONFIG> holder(new KFILTER_CONFIG());
        KFILTER_CONFIG& config = *holder;
        config.NetworkRuleCount = 1;
        config.Network[0].Action = KFilterActionDeny;
        config.Network[0].Rights = KFILTER_RIGHT_SEND;
        config.Network[0].RuleId = 7;
        ULONG rule = 0;
        expect("message rule unenforced without BPF",
               KfPolicyUnenforced(&config, KFILTER_REG_NETWORK, &rule) == KFILTER_STATUS_DEGRADED_MESSAGE && rule == 7, true);
        expect("message rule enforced by BPF", KfPolicyUnenforced(&config, KFILTER_REG_BPF, &rule) == 0, true);
        config.NetworkRuleCount = 0;
        config.Flags = KFILTER_CFG_MESSAGE_DEFAULT_DENY;
        expect("message-default deny unenforced without BPF",
               KfPolicyUnenforced(&config, 0, &rule) == KFILTER_STATUS_DEGRADED_MESSAGE && rule == 0, true);
        config.Flags = 0;
        config.RuleCount = 1;
        config.Rules[0].Targets = KFILTER_TARGET_SYSTEM;
        config.Rules[0].RuleId = 3;
        expect("a Linux-only rule needs the BPF layer",
               KfPolicyUnenforced(&config, KFILTER_REG_NETWORK, &rule) == KFILTER_STATUS_DEGRADED_SYSTEM && rule == 3 &&
                   KfPolicyUnenforced(&config, KFILTER_REG_BPF, &rule) == 0, true);
        config.Rules[0].Targets = KFILTER_TARGET_FILE;
        config.Rules[0].Action = KFilterActionDeny;
        config.Rules[0].Flags = KFILTER_RULE_MODULE;
        expect("a module= deny needs the BPF layer",
               KfPolicyUnenforced(&config, KFILTER_REG_MINIFILTER, &rule) == KFILTER_STATUS_DEGRADED_FILES && rule == 3 &&
                   KfPolicyUnenforced(&config, KFILTER_REG_BPF, &rule) == 0, true);
        config.Rules[0].Flags = 0;
        config.Rules[0].Rights = KFILTER_RIGHT_LOCK;
        expect("a lock deny needs the BPF layer",
               KfPolicyUnenforced(&config, KFILTER_REG_MINIFILTER, &rule) == KFILTER_STATUS_DEGRADED_FILES && rule == 3 &&
                   KfPolicyUnenforced(&config, KFILTER_REG_BPF, &rule) == 0, true);
        config.Rules[0].Rights = 0;
        config.RuleCount = 0;
        config.Flags = KFILTER_CFG_BLOCK_PROCESS_SIGNALS;
        expect("block-process-signals needs the BPF layer",
               KfPolicyUnenforced(&config, KFILTER_REG_OBJECT, &rule) == KFILTER_STATUS_DEGRADED_MEMORY &&
                   KfPolicyUnenforced(&config, KFILTER_REG_BPF, &rule) == 0, true);
        config.Flags = 0;
        config.RuleCount = 1;
        config.Rules[0].Targets = KFILTER_TARGET_PEER;
        config.Rules[0].Flags = KFILTER_RULE_ADDRESS;
        expect("an addr= deny needs the BPF layer",
               KfPolicyUnenforced(&config, KFILTER_REG_OBJECT, &rule) == KFILTER_STATUS_DEGRADED_MEMORY && rule == 3 &&
                   KfPolicyUnenforced(&config, KFILTER_REG_BPF, &rule) == 0, true);
        config.Rules[0].Flags = 0;
        config.Rules[0].Targets = KFILTER_TARGET_THREAD_HANDLE;
        expect("thread-handle rule needs its layer",
               KfPolicyUnenforced(&config, KFILTER_REG_NETWORK, &rule) == KFILTER_STATUS_DEGRADED_MEMORY && rule == 3, true);
#ifndef _WIN32
        expect("thread-handle rule enforced by BPF", KfPolicyUnenforced(&config, KFILTER_REG_BPF, &rule) == 0, true);

        /* simulate decides as kfilterd does: a counted allow is spent across one capture. */
        config.RuleCount = 1;
        config.Mode = KFILTER_MODE_BLOCK;
        config.Flags = KFILTER_CFG_BLOCK_FILES | KFILTER_CFG_DEFAULT_DENY;
        config.ProtectedCount = 1;
        wcscpy_s(config.Protected[0], KFILTER_MAX_NAME, L"/game");
        config.Rules[0] = KFILTER_RULE{};
        config.Rules[0].Action = KFilterActionAllow;
        config.Rules[0].Targets = KFILTER_TARGET_FILE;
        config.Rules[0].Rights = KFILTER_RIGHT_READ;
        config.Rules[0].RuleId = 1;
        config.Rules[0].Count = CompleteCount(1u << KFILTER_COUNT_USES_SHIFT);
        wcscpy_s(config.Rules[0].Path, KFILTER_MAX_NAME, L"/etc/hostname");
        bool loaded = OfflineLoad(config);
        PolicyDecision first = OfflineDecide(KFILTER_TARGET_FILE, L"/etc/hostname", KFILTER_RIGHT_READ, L"", false, 0);
        PolicyDecision second = OfflineDecide(KFILTER_TARGET_FILE, L"/etc/hostname", KFILTER_RIGHT_READ, L"", false, 0);
        expect("offline decision spends a counted allow",
               loaded && first.Action == KFilterActionAllow && first.RuleId == 1 && second.Action == KFilterActionDeny, true);
        wcscpy_s(config.Rules[0].Image, KFILTER_MAX_IMAGE, L"MapleStory.exe");
        config.Rules[0].Count = 0;
        loaded = OfflineLoad(config);
        gOfflineImage = L"C:\\Nexon\\Library\\maplestorycw\\appdata\\MapleStory.exe";
        first = OfflineDecide(KFILTER_TARGET_FILE, L"/etc/hostname", KFILTER_RIGHT_READ, L"", false, 0);
        gOfflineImage = L"C:\\windows\\notepad.exe";
        second = OfflineDecide(KFILTER_TARGET_FILE, L"/etc/hostname", KFILTER_RIGHT_READ, L"", false, 0);
        gOfflineImage.clear();
        expect("offline decision applies image= rules",
               loaded && first.Action == KFilterActionAllow && second.Action == KFilterActionDeny, true);
        /* Rule-only requests (and /anon files): no rule, no decision even in strict mode; a spent counted allow refuses. */
        config.Rules[0] = KFILTER_RULE{};
        config.Rules[0].Action = KFilterActionAllow;
        config.Rules[0].Targets = KFILTER_TARGET_THREAD;
        config.Rules[0].Rights = KFILTER_RIGHT_CREATE;
        config.Rules[0].RuleId = 1;
        config.Rules[0].Count = CompleteCount(1u << KFILTER_COUNT_USES_SHIFT);
        wcscpy_s(config.Rules[0].Path, KFILTER_MAX_NAME, L"C:\\*");
        loaded = OfflineLoad(config);
        PolicyDecision system = OfflineDecide(KFILTER_TARGET_SYSTEM, L"/system/uname", KFILTER_RIGHT_QUERY, L"", false, 0);
        PolicyDecision anon = OfflineDecide(KFILTER_TARGET_FILE, L"/anon/memfd:x", KFILTER_RIGHT_READ, L"", false, 0);
        PolicyDecision file = OfflineDecide(KFILTER_TARGET_FILE, L"/etc/x", KFILTER_RIGHT_READ, L"", false, 0);
        first = OfflineDecide(KFILTER_TARGET_THREAD, L"C:\\x\\MapleStory.exe", KFILTER_RIGHT_CREATE, L"", false, 0);
        second = OfflineDecide(KFILTER_TARGET_THREAD, L"C:\\x\\MapleStory.exe", KFILTER_RIGHT_CREATE, L"", false, 0);
        expect("rule-only requests need a rule to be decided",
               loaded && system.Action == KFilterActionAllow && system.RuleId == 0 && anon.Action == KFilterActionAllow &&
                   file.Action == KFilterActionDeny && first.Action == KFilterActionAllow && first.RuleId == 1 &&
                   second.Action == KFilterActionDeny, true);
        /* No offline request carries an address: an addr= rule never matches, the rule after it decides. */
        config.Rules[0] = KFILTER_RULE{};
        config.Rules[0].Action = KFilterActionDeny;
        config.Rules[0].Targets = KFILTER_TARGET_PEER;
        config.Rules[0].RuleId = 1;
        config.Rules[0].Flags = KFILTER_RULE_ADDRESS;
        config.Rules[0].AddressCount = 1;
        config.Rules[0].Address[0].High = ~0ull;
        wcscpy_s(config.Rules[0].Path, KFILTER_MAX_NAME, L"C:\\*");
        config.Rules[1] = config.Rules[0];
        config.Rules[1].Action = KFilterActionAudit;
        config.Rules[1].RuleId = 2;
        config.Rules[1].Flags = 0;
        config.Rules[1].AddressCount = 0;
        config.RuleCount = 2;
        loaded = OfflineLoad(config);
        first = OfflineDecide(KFILTER_TARGET_PEER, L"C:\\x\\MapleStory.exe", 0x10, L"", false, 0);
        expect("an addr= rule never matches offline", loaded && first.Action == KFilterActionAudit && first.RuleId == 2, true);
        config.RuleCount = 1;
#endif
    }

    if (failures == 0) std::printf("self-test: PASS\n");
    return failures == 0 ? 0 : 1;
}

#ifdef _WIN32
static bool ApplyAcl(const std::wstring& path, PSID sid)
{
    PACL oldDacl = nullptr;
    PACL newDacl = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    EXPLICIT_ACCESSW access{};
    access.grfAccessPermissions = GENERIC_READ | GENERIC_EXECUTE | GENERIC_WRITE;
    access.grfAccessMode = GRANT_ACCESS;
    access.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    access.Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
    access.Trustee.ptstrName = (LPWSTR)sid;
    if (GetNamedSecurityInfoW((LPWSTR)path.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                              nullptr, nullptr, &oldDacl, nullptr, &descriptor) != ERROR_SUCCESS) return false;
    if (SetEntriesInAclW(1, &access, oldDacl, &newDacl) != ERROR_SUCCESS) {
        LocalFree(descriptor);
        return false;
    }
    DWORD result = SetNamedSecurityInfoW((LPWSTR)path.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                                         nullptr, nullptr, newDacl, nullptr);
    LocalFree(newDacl);
    LocalFree(descriptor);
    return result == ERROR_SUCCESS;
}

static bool LaunchContained(const std::wstring& image, const std::wstring& arguments,
                            bool network, const std::wstring& profile)
{
    const wchar_t* profileName = profile.c_str();
    PSID sid = nullptr;
    HRESULT hr = CreateAppContainerProfile(profileName, L"kfilter", L"kfilter containment profile",
                                           nullptr, 0, &sid);
    if (FAILED(hr)) {
        if (hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)) {
            hr = DeriveAppContainerSidFromAppContainerName(profileName, &sid);
        }
        if (FAILED(hr) || sid == nullptr) {
            std::fprintf(stderr, "AppContainer profile failed: 0x%08lx\n", (unsigned long)hr);
            return false;
        }
    }

    std::string conversionError;
    std::wstring root = image;
    size_t slash = root.find_last_of(L'\\');
    if (slash != std::wstring::npos) root = root.substr(0, slash);
    if (!root.empty() && !ApplyAcl(root, sid)) {
        std::fprintf(stderr, "warning: could not grant AppContainer access to %s (error %lu)\n",
                     WideToUtf8(root).c_str(), GetLastError());
    }

    wchar_t localAppData[MAX_PATH];
    DWORD localLength = GetEnvironmentVariableW(L"LOCALAPPDATA", localAppData, MAX_PATH);
    std::wstring privateTemp;
    if (localLength != 0 && localLength < MAX_PATH) {
        privateTemp = std::wstring(localAppData, localLength) + L"\\kfilter\\Temp";
        CreateDirectoryW((std::wstring(localAppData, localLength) + L"\\kfilter").c_str(), nullptr);
        CreateDirectoryW(privateTemp.c_str(), nullptr);
        ApplyAcl(privateTemp, sid);
    }

    PSID capability = nullptr;
    ConvertStringSidToSidW(L"S-1-15-3-1", &capability); // internetClient
    SID_AND_ATTRIBUTES capabilities[1]{};
    ULONG capabilityCount = 0;
    if (network && capability != nullptr) {
        capabilities[0].Sid = capability;
        capabilities[0].Attributes = SE_GROUP_ENABLED;
        capabilityCount = 1;
    }
    SECURITY_CAPABILITIES security{};
    security.AppContainerSid = sid;
    security.Capabilities = capabilityCount ? capabilities : nullptr;
    security.CapabilityCount = capabilityCount;

    SIZE_T attributeSize = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attributeSize);
    std::vector<BYTE> attributeBuffer(attributeSize);
    LPPROC_THREAD_ATTRIBUTE_LIST attributes = (LPPROC_THREAD_ATTRIBUTE_LIST)attributeBuffer.data();
    if (!InitializeProcThreadAttributeList(attributes, 1, 0, &attributeSize) ||
        !UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                                   &security, sizeof(security), nullptr, nullptr)) {
        std::fprintf(stderr, "process attribute setup failed: %lu\n", GetLastError());
        DeleteProcThreadAttributeList(attributes);
        if (capability) LocalFree(capability);
        FreeSid(sid);
        return false;
    }

    /*
     * Register before the create: in block mode the driver only lets the
     * registered launcher start a protected-image process. Registration is a
     * referenced PEPROCESS in the driver and dies with this process.
     */
    HANDLE device = OpenDevice();
    if (device == INVALID_HANDLE_VALUE) {
        std::fprintf(stderr, "Launch is refused: the driver is not available.\n");
        DeleteProcThreadAttributeList(attributes);
        if (capability) LocalFree(capability);
        FreeSid(sid);
        return false;
    }
    if (!Ioctl(device, KFILTER_IOCTL_REGISTER_LAUNCHER, nullptr, 0, nullptr, 0, nullptr)) {
        std::fprintf(stderr, "Launcher registration failed: %lu\n", GetLastError());
        CloseHandle(device);
        DeleteProcThreadAttributeList(attributes);
        if (capability) LocalFree(capability);
        FreeSid(sid);
        return false;
    }

    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.lpAttributeList = attributes;
    PROCESS_INFORMATION process{};
    std::wstring commandLine = L"\"" + image + L"\"";
    if (!arguments.empty()) commandLine += L" " + arguments;
    std::vector<wchar_t> commandBuffer(commandLine.begin(), commandLine.end());
    commandBuffer.push_back(L'\0');

    std::wstring oldTemp, oldTmp;
    wchar_t envValue[32768];
    DWORD envLength = GetEnvironmentVariableW(L"TEMP", envValue, 32768);
    if (envLength != 0 && envLength < 32768) oldTemp.assign(envValue, envLength);
    envLength = GetEnvironmentVariableW(L"TMP", envValue, 32768);
    if (envLength != 0 && envLength < 32768) oldTmp.assign(envValue, envLength);
    if (!privateTemp.empty()) {
        SetEnvironmentVariableW(L"TEMP", privateTemp.c_str());
        SetEnvironmentVariableW(L"TMP", privateTemp.c_str());
    }

    BOOL created = CreateProcessW(image.c_str(), commandBuffer.data(), nullptr, nullptr, FALSE,
                                  CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
                                  nullptr, root.empty() ? nullptr : root.c_str(),
                                  &startup.StartupInfo, &process);
    if (!privateTemp.empty()) {
        SetEnvironmentVariableW(L"TEMP", oldTemp.empty() ? nullptr : oldTemp.c_str());
        SetEnvironmentVariableW(L"TMP", oldTmp.empty() ? nullptr : oldTmp.c_str());
    }
    DeleteProcThreadAttributeList(attributes);
    if (capability) LocalFree(capability);
    if (!created) {
        std::fprintf(stderr, "CreateProcess failed: %lu\n", GetLastError());
        CloseHandle(device);
        FreeSid(sid);
        return false;
    }

    HANDLE job = CreateJobObjectW(nullptr, nullptr);
    if (job != nullptr) {
        /*
         * Keep the group for future UI/limit policy. Do not set
         * KILL_ON_JOB_CLOSE here: this one-shot tool closes the job handle when
         * it returns, which would kill the game. A persistent kfilterd must own
         * the job for lifetime containment.
         */
        AssignProcessToJobObject(job, process.hProcess);
    }

    bool admitted = false;
    {
        KFILTER_ADMIT_REQUEST request{};
        request.ProcessId = process.dwProcessId;
        request.Generation = 0;
        wchar_t actual[MAX_PATH];
        DWORD actualLength = MAX_PATH;
        if (QueryFullProcessImageNameW(process.hProcess, 0, actual, &actualLength)) {
            std::wstring nt = ToNtPath(std::wstring(actual, actualLength), conversionError);
            wcsncpy_s(request.ImagePath, KFILTER_MAX_NAME, nt.c_str(), _TRUNCATE);
        }
        if (sid != nullptr && GetLengthSid(sid) <= KFILTER_MAX_SID) {
            request.SidLength = GetLengthSid(sid);
            CopySid(KFILTER_MAX_SID, request.Sid, sid);
        }
        if (request.ImagePath[0] == L'\0') {
            std::fprintf(stderr, "Could not resolve the suspended process image path; refusing admission.\n");
            TerminateProcess(process.hProcess, 1);
            CloseHandle(device);
            CloseHandle(process.hThread);
            CloseHandle(process.hProcess);
            if (job) CloseHandle(job);
            FreeSid(sid);
            return false;
        }
        admitted = Ioctl(device, KFILTER_IOCTL_ADMIT_PROCESS, &request, sizeof(request), nullptr, 0, nullptr);
        if (!admitted) std::fprintf(stderr, "ADMIT_PROCESS failed: %lu\n", GetLastError());
    }
    CloseHandle(device);

    if (!admitted) {
        TerminateProcess(process.hProcess, 1);
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        if (job) CloseHandle(job);
        FreeSid(sid);
        return false;
    }
    ResumeThread(process.hThread);
    std::printf("launched pid=%lu container=yes network=%s\n", process.dwProcessId,
                network ? "temporary-internetClient" : "off");
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    if (job) CloseHandle(job);
    FreeSid(sid);
    return true;
}
#endif

static void Usage()
{
    std::printf("Usage:\n"
                "  kfilterctl status\n"
                "  kfilterctl check <file>\n"
                "  kfilterctl policy <file> [--no-track]\n"
                "  kfilterctl default [--no-track]\n"
                "  kfilterctl on | audit | off\n"
                "  kfilterctl stop                                                  (Linux: off, unpin, kfilterd exits)\n"
                "  kfilterctl session <tag>                                         (Linux: tag this run's decisions)\n"
                "  kfilterctl track\n"
                "  kfilterctl allow-launch <launcher.exe> <starts> [seconds]\n"
                "  kfilterctl block-connection <socket-inode> [send|receive|both]   (Linux)\n"
                "  kfilterctl unblock-connection <socket-inode>                     (Linux)\n"
                "  kfilterctl clear\n"
                "  kfilterctl watch [seconds]\n"
                "  kfilterctl self-test\n"
                "  kfilterctl simulate <policy> <jsonl> [--pid n] [--max n]\n"
                "  kfilterctl evaluate <policy> <target> <path> <rights> [value]\n"
                "  kfilterctl launch <exe> [args...] [--no-network] [--appcontainer <profile>]\n"
                "                  [--hostname <name>]   (Linux: the session's own host name)\n"
                "                  [--program <Windows program>]   (Linux: what a Wine loader or a script\n"
                "                  runs; by default wine's first .exe argument, a script's .exe names)\n"
                "                  Linux hiding and containment (docs/LINUX.md):\n"
                "                  [--uname26] [--time-offset <seconds>] [--private-proc] [--user <account>]\n"
                "                  [--trap-cpuid] [--trap-rdtsc] [--cpuid-mask <leaves>] [--trap-log <file>]\n");
}

int wmain(int argc, wchar_t** argv)
{
    SetConsoleOutputCP(CP_UTF8);
    if (argc < 2) { Usage(); return 2; }
    std::wstring command = argv[1];
    bool track = true;
    bool network = true;
    std::wstring profile = L"MapleStoryCW";
    for (int index = 2; index < argc; index++) {
        if (wcscmp(argv[index], L"--no-track") == 0) track = false;
        if (wcscmp(argv[index], L"--no-network") == 0) network = false;
        if (wcscmp(argv[index], L"--appcontainer") == 0 && index + 1 < argc) profile = argv[++index];
    }
    if (command == L"help" || command == L"--help" || command == L"-h") { Usage(); return 0; }
    if (command == L"self-test") return SelfTest();
    if (command == L"launch") {
        if (argc < 3) { Usage(); return 2; }
#ifndef _WIN32
        /* Arguments stay separate: Linux exec takes a vector, not a command line. */
        gLinuxPaths = true;
        if (wcsncmp(argv[2], L"--", 2) == 0) { Usage(); return 2; }   /* the program comes first */
        return LaunchLinux(argv[2], argc, argv, 3, network);
#else
        std::wstring arguments;
        for (int index = 3; index < argc; index++) {
            if (wcscmp(argv[index], L"--no-network") == 0) continue;
        if (wcscmp(argv[index], L"--appcontainer") == 0) {
            if (index + 1 >= argc || argv[index + 1][0] == L'\0') {
                std::fprintf(stderr, "--appcontainer needs a profile name\n");
                return 2;
            }
            index++;
            continue;
        }
            if (!arguments.empty()) arguments += L" ";
            arguments += argv[index];
        }
        return LaunchContained(argv[2], arguments, network, profile) ? 0 : 1;
#endif
    }
    if (command == L"check") {
        if (argc < 3) { std::fprintf(stderr, "check needs a policy file\n"); return 2; }
#ifndef _WIN32
        gLinuxPaths = true;
#endif
        std::unique_ptr<KFILTER_CONFIG> config(new KFILTER_CONFIG());
        std::string error;
        if (!ParsePolicy(argv[2], config.get(), error)) {
            std::fprintf(stderr, "%s: %s\n", WideToUtf8(argv[2]).c_str(), error.c_str());
            return 1;
        }
        PrintPolicy(*config);
#ifndef _WIN32
        CheckWarnings(*config);
#endif
        /* Every layer this OS has: Windows has no message layer; Linux needs kfilterd's BPF one. */
#ifdef _WIN32
        const ULONG layers = 0xFFFFFFFFu & ~KFILTER_REG_BPF;
#else
        const ULONG layers = 0xFFFFFFFFu;
        for (const std::string& warning : PolicyWarnings(*config)) std::fprintf(stderr, "warning: %s\n", warning.c_str());
#endif
        return PolicyEnforceable(*config, layers) ? 0 : 1;
    }
    if (command == L"simulate") {
        if (argc < 4) { std::fprintf(stderr, "simulate needs a policy and capture\n"); return 2; }
        std::vector<DWORD> processIds;
        ULONGLONG maximumEvents = 0;
        for (int index = 4; index < argc; index++) {
            if (wcscmp(argv[index], L"--pid") == 0 && index + 1 < argc) {
                processIds.push_back((DWORD)wcstoul(argv[++index], nullptr, 10));
            } else if (wcscmp(argv[index], L"--max") == 0 && index + 1 < argc) {
                maximumEvents = _wcstoui64(argv[++index], nullptr, 10);
            } else {
                std::fprintf(stderr, "unknown simulate option\n");
                return 2;
            }
        }
        return SimulatePolicy(argv[2], argv[3], processIds, maximumEvents);
    }
    if (command == L"evaluate") {
        if (argc < 6) { std::fprintf(stderr, "evaluate needs policy/target/path/rights\n"); return 2; }
        return EvaluatePolicyCommand(argv[2], argv[3], argv[4], argv[5], argc >= 7 ? argv[6] : L"");
    }

    HANDLE device = OpenDevice();
    if (device == INVALID_HANDLE_VALUE) return 1;
    int result = 0;

    if (command == L"status") {
        result = ShowStatus(device);
    } else if (command == L"policy" || command == L"default") {
#ifndef _WIN32
        gLinuxPaths = true;
#endif
        std::wstring path = (command == L"default") ? DefaultPolicyPath() : (argc >= 3 ? argv[2] : L"");
        if (path.empty()) { std::fprintf(stderr, "policy needs a file path\n"); result = 2; }
        else {
            std::unique_ptr<KFILTER_CONFIG> config(new KFILTER_CONFIG());
            std::unique_ptr<KFILTER_CONFIG> previous(new KFILTER_CONFIG());
            std::string error;
            KFILTER_STATUS status{};
            if (!ParsePolicy(path, config.get(), error)) {
                std::fprintf(stderr, "%s: %s\n", WideToUtf8(path).c_str(), error.c_str());
                result = 1;
            } else if (!Ioctl(device, KFILTER_IOCTL_GET_STATUS, nullptr, 0, &status, sizeof(status), nullptr)) {
                std::fprintf(stderr, "GET_STATUS failed: %" KF_U "\n", GetLastError());
                result = 1;
            } else if (!PolicyEnforceable(*config, status.Registered)) {
                result = 1;
            } else if (!GetConfig(device, previous.get()) || !SetConfig(device, *config)) {
                result = 1;
            } else {
                int trackingFailures = track ? TrackProtected(device) : 0;
                if (ShouldRollback(config->Mode, trackingFailures)) {
                    (VOID)SetConfig(device, *previous);
                    std::fprintf(stderr, "Policy rolled back: a protected process could not be admitted.\n");
                    result = 1;
                } else if (!GetConfig(device, config.get())) {
                    result = 1;
                } else {
                    if (trackingFailures != 0) {
                        std::fprintf(stderr, "Warning: %d protected process admission failure(s); mode remains %s.\n",
                                     trackingFailures, ModeName(config->Mode));
                    }
                    std::printf("policy applied: mode=%s rules=%" KF_U " protected=%" KF_U " generation=%" KF_U "\n",
                                ModeName(config->Mode), config->RuleCount, config->ProtectedCount,
                                config->Generation);
                }
            }
        }
    } else if (command == L"on") {
        result = SetMode(device, KFILTER_MODE_BLOCK) ? 0 : 1;
    } else if (command == L"audit") {
        result = SetMode(device, KFILTER_MODE_AUDIT) ? 0 : 1;
    } else if (command == L"off") {
        result = SetMode(device, KFILTER_MODE_OFF) ? 0 : 1;
    } else if (command == L"stop") {
        /* Linux: the explicit end of block mode. Any other kfilterd exit keeps enforcing. */
        if (!Ioctl(device, KFILTER_IOCTL_SHUTDOWN, nullptr, 0, nullptr, 0, nullptr)) {
            std::fprintf(stderr, "SHUTDOWN failed: %" KF_U "\n", GetLastError());
            result = 1;
        } else {
            std::printf("kfilterd stopped: policy off, BPF layer unpinned\n");
        }
    } else if (command == L"session") {
        KFILTER_SESSION_REQUEST request{};
        wchar_t* end = nullptr;
        request.SessionTag = argc >= 3 ? wcstoull(argv[2], &end, 0) : 0;
        if (request.SessionTag == 0 || end == nullptr || *end != L'\0') {
            std::fprintf(stderr, "session needs a non-zero tag (decimal, or hexadecimal with 0x)\n");
            result = 2;
        } else if (!Ioctl(device, KFILTER_IOCTL_SET_SESSION, &request, sizeof(request), nullptr, 0, nullptr)) {
            std::fprintf(stderr, "SET_SESSION failed: %" KF_U "\n", GetLastError());
            result = 1;
        } else {
            std::printf("session tag: %016llx\n", (unsigned long long)request.SessionTag);
        }
    } else if (command == L"track") {
        result = TrackProtected(device);
    } else if (command == L"allow-launch") {
        KFILTER_ALLOW_LAUNCH_REQUEST request{};
        std::wstring creator = argc >= 3 ? argv[2] : L"";
        int starts = argc >= 4 ? _wtoi(argv[3]) : 0;
        request.ArmSeconds = argc >= 5 ? static_cast<unsigned long>(_wtoi(argv[4])) : 120;
        if (request.ArmSeconds == 0 || request.ArmSeconds > 600) request.ArmSeconds = 120;
        if (creator.empty() || creator.find(L'\\') != std::wstring::npos || creator.size() >= KFILTER_MAX_NAME) {
            std::fprintf(stderr, "allow-launch needs the launcher's file name, e.g. nexon_client.exe\n");
            result = 2;
        } else if (starts < 1 || starts > 8) {
            std::fprintf(stderr, "allow-launch needs the number of starts to allow, 1 to 8\n");
            result = 2;
        } else {
            request.Starts = static_cast<unsigned long>(starts);
            wcscpy_s(request.CreatorName, creator.c_str());
            if (!Ioctl(device, KFILTER_IOCTL_ALLOW_LAUNCH, &request, sizeof(request), nullptr, 0, nullptr)) {
                std::fprintf(stderr, "ALLOW_LAUNCH failed: %" KF_U "\n", GetLastError());
                result = 1;
            } else {
                std::wprintf(L"The next %lu start(s) from %ls are allowed within %lu seconds; every later "
                             L"start is refused. One-time relaxation steps start over from step 1.\n",
                             (unsigned long)request.Starts, creator.c_str(), (unsigned long)request.ArmSeconds);
            }
        }
    } else if (command == L"block-connection" || command == L"unblock-connection") {
        /* A live connection by its socket inode (socket:[N] in watch and in msmon's log). */
        KFILTER_CONNECTION_REQUEST request{};
        std::wstring inode = argc >= 3 ? argv[2] : L"";
        std::wstring direction = argc >= 4 ? argv[3] : L"both";
        if (inode.rfind(L"socket:[", 0) == 0 && !inode.empty() && inode.back() == L']') inode = inode.substr(8, inode.size() - 9);
        wchar_t* end = nullptr;
        request.SocketInode = inode.empty() ? 0 : wcstoull(inode.c_str(), &end, 10);
        if (command == L"block-connection") {
            request.Directions = direction == L"send" ? KFILTER_RIGHT_SEND
                               : direction == L"receive" ? KFILTER_RIGHT_RECEIVE
                               : direction == L"both" ? KFILTER_RIGHTS_MESSAGE : 0;
        }
        if (request.SocketInode == 0 || end == nullptr || *end != L'\0' ||
            (command == L"block-connection" && request.Directions == 0)) {
            std::fprintf(stderr, "%ls needs a socket inode (N or socket:[N]) and send|receive|both\n", command.c_str());
            result = 2;
        } else if (!Ioctl(device, KFILTER_IOCTL_BLOCK_CONNECTION, &request, sizeof(request), nullptr, 0, nullptr)) {
            std::fprintf(stderr, "BLOCK_CONNECTION failed: %" KF_U "\n", GetLastError());
            result = 1;
        } else {
            std::wprintf(L"socket:[%llu]: %ls\n", (unsigned long long)request.SocketInode,
                         request.Directions == 0 ? L"unblocked"
                         : request.Directions == KFILTER_RIGHTS_MESSAGE ? L"every send and receive is refused"
                         : request.Directions == KFILTER_RIGHT_SEND ? L"every send is refused" : L"every receive is refused");
        }
    } else if (command == L"clear") {
        if (!Ioctl(device, KFILTER_IOCTL_CLEAR_EVENTS, nullptr, 0, nullptr, 0, nullptr)) {
            std::fprintf(stderr, "CLEAR_EVENTS failed: %" KF_U "\n", GetLastError());
            ExplainRingRefusal();
            result = 1;
        }
    } else if (command == L"watch") {
        int seconds = argc >= 3 ? _wtoi(argv[2]) : 10;
        if (!ShowEvents(device, seconds)) result = 1;
    } else {
        Usage();
        result = 2;
    }
    CloseHandle(device);
    return result;
}

#ifndef _WIN32
int main(int argc, char** argv)
{
    std::vector<std::wstring> wide;
    std::vector<wchar_t*> pointers;
    for (int index = 0; index < argc; index++) wide.push_back(Utf8ToWide(argv[index]));
    for (auto& value : wide) pointers.push_back(value.data());
    pointers.push_back(nullptr);
    return wmain(argc, pointers.data());
}
#endif
