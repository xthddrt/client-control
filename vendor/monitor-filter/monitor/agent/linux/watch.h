#pragma once
/*
 * Watchpoints (--watch, watch.cpp; docs/LINUX.md "Watchpoints"): the watches the agent was given, the address each one
 * has in a process, and the records of what the kernel counted (bpf/watch.bpf.c). Header-only, so
 * tests/linux_watch_test.cpp checks it offline.
 */
#include "session.h"
#include "pe.h"
#include "bpf/watch_bpf.h"
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <strings.h>
#include <utility>
#include <vector>

/* One --watch WHERE:LENGTH:ACCESS. WHERE is MODULE+0xOFFSET, from the base of that module in every tracked process that
 * has it loaded, or 0xADDRESS, in every tracked process. */
struct WatchSpec {
    std::string text;      /* as given */
    std::string module;    /* "" for an absolute address */
    uint64_t offset = 0;   /* from the module's base, or the address */
    uint32_t length = 0;   /* 1, 2, 4 or 8 */
    bool write = false;    /* w: writes; r and rw: reads and writes (x86 has no data breakpoint on reads alone) */
};

/* x86 has 4 debug registers per thread, and a thread can match every watch. */
constexpr size_t kWatchMax = 4;

/* "0x" and 1 to 16 hex digits. */
inline bool WatchNumber(const std::string& text, uint64_t& value)
{
    if (text.size() < 3 || text.size() > 18 || (text.compare(0, 2, "0x") != 0 && text.compare(0, 2, "0X") != 0) ||
        text.find_first_not_of("0123456789abcdefABCDEF", 2) != std::string::npos)
        return false;
    value = std::strtoull(text.c_str() + 2, nullptr, 16);
    return true;
}

/* Adds one --watch to Specs: "" or why it is refused. */
inline std::string WatchAdd(std::vector<WatchSpec>& specs, const std::string& text)
{
    const std::string usage = " (--watch MODULE+0xOFFSET:LENGTH:ACCESS or 0xADDRESS:LENGTH:ACCESS, e.g. MapleStory.exe+0x1238:8:rw)";
    const std::string what = "--watch " + text + ": ";
    std::vector<std::string> parts;
    size_t at = 0;
    for (size_t end; (end = text.find(':', at)) != std::string::npos; at = end + 1) parts.push_back(text.substr(at, end - at));
    parts.push_back(text.substr(at));
    if (parts.size() != 3) return what + "not WHERE:LENGTH:ACCESS" + usage;
    WatchSpec spec;
    spec.text = text;
    const size_t plus = parts[0].rfind('+');
    if (plus != std::string::npos) spec.module = parts[0].substr(0, plus);
    if (plus == 0 || !WatchNumber(parts[0].substr(plus == std::string::npos ? 0 : plus + 1), spec.offset))
        return what + "WHERE is not MODULE+0xOFFSET or 0xADDRESS (hexadecimal)" + usage;
    if (!spec.module.empty() && spec.offset >= 0x100000000ull) return what + "the offset is past 4 GiB (no PE image is that large)";
    if (parts[1] != "1" && parts[1] != "2" && parts[1] != "4" && parts[1] != "8")
        return what + "LENGTH is not 1, 2, 4 or 8: an x86 data breakpoint watches 1, 2, 4 or 8 bytes";
    spec.length = static_cast<uint32_t>(parts[1][0] - '0');
    /* The kernel takes the last page below 0x800000000000 (TASK_SIZE_MAX) for kernel space and refuses a breakpoint there. */
    if (spec.module.empty() && (spec.offset == 0 || spec.offset > 0x7ffffffff000ull - spec.length))
        return what + "the address is not a user-space address (0x1 to 0x7fffffffefff)";
    if (spec.offset % spec.length != 0)
        return what + (spec.module.empty() ? "the address" : "the offset") + " is not a multiple of LENGTH: an x86 data breakpoint" +
               " watches aligned bytes (split the range into aligned 1, 2, 4 or 8-byte watches)";
    if (parts[2] == "w") spec.write = true;
    else if (parts[2] != "r" && parts[2] != "rw") return what + "ACCESS is not r, w or rw" + usage;
    for (const WatchSpec& other : specs) {
        if (other.text == text) return what + "given twice";
    }
    if (specs.size() >= kWatchMax) return what + "more than 4 watches: x86 has 4 debug registers per thread";
    specs.push_back(spec);
    return {};
}

/* The name a PE image is watched by: its file's name, or the export name of one found in anonymous memory. */
inline const char* WatchModuleName(const PeRanges::Range& range)
{
    if (range.path.empty()) return range.image ? range.image->name.c_str() : "";
    const size_t slash = range.path.rfind('/');
    return range.path.c_str() + (slash == std::string::npos ? 0 : slash + 1);
}

/* The address Spec watches in a process whose PE images are Images (nullptr: not scanned yet): an absolute address as
 * given, else the offset from the base of the module's first load (names compared without case), 0 while it is not
 * loaded. */
inline uint64_t WatchResolve(const WatchSpec& spec, const PeRanges* images)
{
    if (spec.module.empty()) return spec.offset;
    if (images == nullptr) return 0;
    for (const PeRanges::Range& range : images->ranges) {
        if (strcasecmp(WatchModuleName(range), spec.module.c_str()) == 0) return range.base + spec.offset;
    }
    return 0;
}

/* Resolves every spec anew into Addresses (one per spec, 0: not watched): the watches whose address changed (a new
 * process, a module loaded, moved or unloaded), each with the address it had. */
inline std::vector<std::pair<size_t, uint64_t>> WatchResolveAll(const std::vector<WatchSpec>& specs, const PeRanges* images,
                                                                std::vector<uint64_t>& addresses)
{
    std::vector<std::pair<size_t, uint64_t>> changed;
    addresses.resize(specs.size(), 0);
    for (size_t index = 0; index < specs.size(); index++) {
        const uint64_t address = WatchResolve(specs[index], images);
        if (address == addresses[index]) continue;
        changed.emplace_back(index, addresses[index]);
        addresses[index] = address;
    }
    return changed;
}

inline std::wstring WatchHex(uint64_t value)
{
    wchar_t text[24];
    swprintf(text, 24, L"0x%llx", static_cast<unsigned long long>(value));
    return text;
}

/* "address=;length=;access=" of a watch at Address: access w, or rw (an x86 data breakpoint on reads also traps writes). */
inline std::wstring WatchShape(const WatchSpec& spec, uint64_t address)
{
    return L"address=" + WatchHex(address) + L";length=" + std::to_wstring(spec.length) + L";access=" + (spec.write ? L"w" : L"rw");
}

/* A watch record of process Pid (the caller sets start; timestamp 0 is now): process_handle watch:<spec> on the process
 * itself (its own memory). */
inline LinuxRecord WatchBase(const WatchSpec& spec, DWORD pid, DWORD tid, uint64_t address)
{
    LinuxRecord record;
    record.sensor = MSMON_SENSOR_LINUX_EBPF_MEMORY;
    record.type = MsMonProcessHandle;
    record.pid = pid;
    record.tid = tid;
    record.target = pid;
    record.value0 = address;
    record.text = L"watch:" + LinuxWide(spec.text);
    return record;
}

/* A watch's address in a process changed (WatchResolveAll): watch_attached at Address (previous= the one it left), or
 * watch_detached when its module is no longer loaded (Address 0). */
inline LinuxRecord WatchMoved(const WatchSpec& spec, DWORD pid, uint64_t previous, uint64_t address)
{
    LinuxRecord record = WatchBase(spec, pid, 0, address ? address : previous);
    record.detail = (address ? L"watch_attached;" : L"watch_detached;reason=module_unloaded;") + WatchShape(spec, record.value0);
    if (!spec.module.empty()) record.detail += L";module_base=" + WatchHex(record.value0 - spec.offset);
    if (address && previous) record.detail += L";previous=" + WatchHex(previous);
    return record;
}

/* The breakpoint of a watch could not be opened on thread Tid (errno Error): watch_conflict (side=watch: its 4 debug
 * registers are taken, by its tracer's ptrace breakpoints: wineserver's for a SetThreadContext with debug registers),
 * else watch_failed. Either is written once per thread and watch: the breakpoint is not retried. */
inline LinuxRecord WatchOpenFailed(const WatchSpec& spec, DWORD pid, DWORD tid, uint64_t address, int error)
{
    LinuxRecord record = WatchBase(spec, pid, tid, address);
    record.status = -error;
    record.detail = (error == ENOSPC ? L"watch_conflict;side=watch;" : L"watch_failed;") + WatchShape(spec, address) +
                    L";errno=" + std::to_wstring(error);
    return record;
}

/* ";ip_module=<module>+0x<offset>" for an address inside one of Images, else "". */
inline std::wstring WatchIpModule(const PeRanges* images, uint64_t ip)
{
    const PeRanges::Range* range = images ? images->Find(ip) : nullptr;
    if (range == nullptr || *WatchModuleName(*range) == '\0') return {};
    return L";ip_module=" + LinuxWide(WatchModuleName(*range)) + L"+" + WatchHex(ip - range->base);
}

/* The record of one key watch.bpf.c counted. A watch's hits by one thread at one ip in one second (Spec its watch):
 * watch_hit, value0 the address, value1 the hits. A tracer's debug-register writes that failed ENOSPC on the thread
 * (Spec nullptr): watch_conflict;side=program, status -ENOSPC, value0 the value written, value1 the writes. Images: the
 * process's PE images (nullptr: none), naming ip's module. The caller sets start and timestamp. */
inline LinuxRecord WatchRecord(const WatchSpec* spec, const mm_watch_key& key, const mm_watch_hit& hit, const PeRanges* images)
{
    const std::wstring count =
        L";count=" + std::to_wstring(hit.count) + L";span_us=" + std::to_wstring((hit.last_ns - hit.first_ns) / 1000);
    if (spec == nullptr) {
        LinuxRecord record;
        record.sensor = MSMON_SENSOR_LINUX_EBPF_MEMORY;
        record.type = MsMonProcessHandle;
        record.pid = key.tgid;
        record.tid = key.tid;
        record.target = key.tgid;
        record.status = -ENOSPC;
        record.value0 = key.ip;
        record.value1 = hit.count;
        record.text = L"watch_conflict";
        record.detail = L"watch_conflict;side=program;register=dr" + std::to_wstring(key.addr) + L";value=" + WatchHex(key.ip) +
                        L";tracer_pid=" + std::to_wstring(hit.actor) + count;
        return record;
    }
    LinuxRecord record = WatchBase(*spec, key.tgid, key.tid, key.addr);
    record.value1 = hit.count;
    record.detail = L"watch_hit;" + WatchShape(*spec, key.addr) + L";ip=" + WatchHex(key.ip) + WatchIpModule(images, key.ip) + count;
    return record;
}

/* Key's breakpoint (Spec its watch) passed MM_WATCH_CAP hits in one second, at ip among others: watch_throttled; the
 * caller closes it for good on that thread and sets start. Images: as WatchRecord's. */
inline LinuxRecord WatchThrottled(const WatchSpec& spec, const mm_watch_key& key, const PeRanges* images)
{
    LinuxRecord record = WatchBase(spec, key.tgid, key.tid, key.addr);
    record.value1 = MM_WATCH_CAP;
    record.detail = L"watch_throttled;" + WatchShape(spec, key.addr) + L";cap=" + std::to_wstring(MM_WATCH_CAP) + L";ip=" +
                    WatchHex(key.ip) + WatchIpModule(images, key.ip);
    return record;
}

/* A key's second is over and 1 s more has passed: no program still holds it, so it is read and deleted. */
inline bool WatchDue(uint32_t second, uint64_t bootNs)
{
    return static_cast<uint64_t>(second) + 2 <= bootNs / 1000000000ull;
}
