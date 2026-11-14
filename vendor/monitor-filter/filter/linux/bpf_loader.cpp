// kfilterd's kernel layer: loads linux/bpf/kfilter.bpf.c (embedded at build time),
// compiles each policy into its maps, keeps the kernel's protected set and the daemon's
// (procs.cpp) in step, and feeds kernel decisions into the decision ring (events.c).
//
// Without KFILTER_BPF (no clang at build time) every entry point reports the layer
// unavailable and kfilterd uses fanotify and nftables, as before.

#include "kf_linux.h"
#include "bpf/kfilter_bpf.h"

#include "../driver/match.h"

#include <arpa/inet.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <sys/socket.h>
#include <dirent.h>
#include <elf.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cinttypes>
#include <condition_variable>
#include <fstream>
#include <set>
#include <sstream>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <tuple>
#include <vector>

/* kb_wnamed: the Wine requests a system rule names past /system/wine/ (KB_WINE_ROOT), its fixed text (the path before
 * any '*') /system/wine/ and more: a literal rule the request it names, a pattern every request its fixed text begins. */
void KfBpfWineNamed(const KFILTER_CONFIG* config, uint64_t named[KB_WNAMED_WORDS])
{
#define KB_WNAME_TEXT(name, right) #name,
    static const char* const names[] = {KB_WINE_REQUESTS(KB_WNAME_TEXT)};
#undef KB_WNAME_TEXT
    static_assert(sizeof(names) / sizeof(names[0]) == KB_REQ_COUNT, "a name for every request");
    static const std::string space = "/system/wine/";
    std::fill(named, named + KB_WNAMED_WORDS, 0);
    for (ULONG index = 0; index < config->RuleCount; index++) {
        const KFILTER_RULE& rule = config->Rules[index];
        if (rule.Targets != KFILTER_TARGET_SYSTEM) continue;
        const std::string path = KfNarrow(std::wstring(rule.Path, KfLengthBounded(rule.Path, KFILTER_MAX_NAME)));
        const size_t head = std::min(path.find('*'), path.size());
        if (head <= space.size() || path.compare(0, space.size(), space) != 0) continue;
        const std::string fixed = path.substr(space.size(), head - space.size());
        for (unsigned req = 0; req < KB_REQ_COUNT; req++) {
            if (head == path.size() ? fixed == names[req] : strncmp(names[req], fixed.c_str(), fixed.size()) == 0)
                named[req / 64] |= 1ull << (req % 64);
        }
    }
}

/* A system rule whose fixed text (before any '*') reaches into a keyed space, /system/wine/<request>/ of a request
 * with keyed decisions or /system/rpc: it meets those (KB_TARGET_KEYED) and nothing else; no other rule meets them. */
bool KfBpfKeyedRule(const KFILTER_RULE& rule, const std::string& path)
{
#define KB_WNAME_TEXT(name, right) #name,
    static const char* const names[] = {KB_WINE_REQUESTS(KB_WNAME_TEXT)};
#undef KB_WNAME_TEXT
    static const unsigned keyed[] = KB_KEYED_REQUESTS;
    if (rule.Targets != KFILTER_TARGET_SYSTEM) return false;
    const std::string fixed = path.substr(0, path.find('*'));
    if (fixed.rfind("/system/rpc", 0) == 0) return true;
    for (unsigned req : keyed) {
        if (fixed.rfind("/system/wine/" + std::string(names[req]) + "/", 0) == 0) return true;
    }
    return false;
}

/* What a refused win32u.so function returns when that is not 0 (FALSE, NULL, nothing found). */
static uint32_t Win32kFailure(const std::string& name)
{
    if (name.rfind("NtGdiDdDDI", 0) == 0 || name == "NtUserBuildHwndList" || name == "NtUserBuildNameList" ||
        name == "NtUserBuildPropList" || name == "NtUserEnumDisplayDevices" || name == "NtUserDisplayConfigGetDeviceInfo")
        return 0xC0000022u;   /* STATUS_ACCESS_DENIED */
    if (name == "NtUserQueryDisplayConfig" || name == "NtUserGetDisplayConfigBufferSizes") return 5;   /* ERROR_ACCESS_DENIED */
    return 0;
}

/*
 * The functions of a Wine install's win32u.so or ntdll.so (Ntdll; Exports: its exported functions) that Config's system
 * rules name, each with its kb_win32k cookie but for the function's slot, machine and install (kfilter_bpf.h KB_UP_*):
 * a win32u.so export a rule matches as /system/win32k/<function> (what it decides as before keys existed), and a keyed
 * one (KB_UP_CALLS) a rule's fixed text (before any '*') reaches the keys of, /system/win32k/<function>/ (KB_UP_KEYED),
 * skipping what no rule can meet: the function's own decision, its window key's @self or @desktop (KB_UP_SKIP_*);
 * an ntdll.so function of KB_UP_CALLS alone (no other is decided), named by a rule on /system/ntdll, /system/ntdll/
 * <function> or one of its classes, or a pattern whose fixed text begins one of those (or /system/ntdll/<function>/),
 * never one stopping short of /system/ntdll. It may name more than a rule meets (a pattern after the function's name),
 * never less.
 */
std::map<std::string, uint64_t> KfBpfUprobeFunctions(const KFILTER_CONFIG* config, bool ntdll,
                                                     const std::map<std::string, uint64_t>& exports)
{
    struct Call { const char* library; const char* name; uint32_t kind, right; };
#define KB_UP_CALL(library, name, kind, right) {#library, #name, kind, right},
    static const Call calls[] = {KB_UP_CALLS(KB_UP_CALL)};
#undef KB_UP_CALL
    const std::string space = ntdll ? "/system/ntdll" : "/system/win32k";
    std::map<std::string, uint64_t> named;
    std::set<std::string> decided;   /* win32u.so functions a rule can meet as /system/win32k/<function> */
    std::map<std::string, uint64_t> reached;   /* ... and the window keys one can meet (KB_UP_SKIP_SELF, _DESKTOP clear) */
    for (ULONG index = 0; index < config->RuleCount && index < KFILTER_MAX_RULES; index++) {
        const KFILTER_RULE& rule = config->Rules[index];
        if (rule.Targets != KFILTER_TARGET_SYSTEM) continue;
        const std::wstring wide(rule.Path, KfLengthBounded(rule.Path, KFILTER_MAX_NAME));
        const std::string path = KfNarrow(wide), head = path.substr(0, path.find('*'));
        if (head.size() < space.size() || head.compare(0, space.size(), space) != 0) continue;
        const bool wild = head.size() < path.size();
        for (const Call& call : calls) {
            if ((strcmp(call.library, "ntdll") == 0) != ntdll || exports.count(call.name) == 0) continue;
            const std::string function = space + "/" + call.name, keys = function + "/";
            const bool reaches = head.compare(0, keys.size(), keys) == 0;
            if (!ntdll && reaches) named[call.name] |= KB_UP_COOKIE(call.kind, 0, 0) | KB_UP_KEYED;
            for (const auto& [key, bit] : {std::make_pair("@self", KB_UP_SKIP_SELF), std::make_pair("@desktop", KB_UP_SKIP_DESKTOP)}) {
                const std::wstring keyed = KfWide(keys + key);
                if (!ntdll && reaches && call.kind == KB_UP_WINDOW &&
                    KfPathMatches(rule.Path, KfLengthBounded(rule.Path, KFILTER_MAX_NAME), keyed.c_str(), (KF_ULONG)keyed.size()))
                    reached[call.name] |= bit;
            }
            if (ntdll && (reaches || (wild ? keys.compare(0, head.size(), head) == 0 : path == space || path == function)))
                named[call.name] |= KB_UP_COOKIE(call.kind, 0, call.right) | KB_UP_NTDLL | 0xC0000022ull << 32;
        }
        for (auto export_ = exports.begin(); !ntdll && export_ != exports.end(); ++export_) {
            const std::wstring function = L"/system/win32k/" + KfWide(export_->first);
            if (KfPathMatches(rule.Path, KfLengthBounded(rule.Path, KFILTER_MAX_NAME), function.c_str(), (KF_ULONG)function.size())) {
                named.emplace(export_->first, 0);
                decided.insert(export_->first);
            }
        }
    }
    if (!ntdll) {
        for (auto& [name, cookie] : named) {
            cookie |= (uint64_t)Win32kFailure(name) << 32;
            /* A keyed function no rule meets itself, or whose own windows or the desktop no key rule meets, skips that. */
            if ((cookie & KB_UP_KEYED) != 0 && decided.count(name) == 0) cookie |= KB_UP_SKIP_FUNCTION;
            if ((cookie & KB_UP_KEYED) != 0 && KB_UP_KIND(cookie) == KB_UP_WINDOW)
                cookie |= (KB_UP_SKIP_SELF | KB_UP_SKIP_DESKTOP) & ~reached[name];
        }
    }
    return named;
}

namespace {

template <typename Ehdr, typename Phdr>
bool WineDispatcher(const std::string& file, uint64_t select, uint64_t& start, uint64_t& end)
{
    Ehdr eh;
    if (file.size() < sizeof(eh)) return false;
    memcpy(&eh, file.data(), sizeof(eh));
    if (eh.e_phentsize != sizeof(Phdr) || eh.e_phoff + (uint64_t)eh.e_phnum * sizeof(Phdr) > file.size()) return false;
    std::vector<Phdr> segments(eh.e_phnum);
    memcpy(segments.data(), file.data() + eh.e_phoff, segments.size() * sizeof(Phdr));
    auto address = [&](uint64_t offset) -> uint64_t {   /* a file offset's address, 0 in no loaded segment */
        for (const Phdr& p : segments) {
            if (p.p_type == PT_LOAD && offset >= p.p_offset && offset - p.p_offset < p.p_filesz) return offset - p.p_offset + p.p_vaddr;
        }
        return 0;
    };
    auto offsetOf = [&](uint64_t vaddr) -> uint64_t {
        for (const Phdr& p : segments) {
            if (p.p_type == PT_LOAD && vaddr >= p.p_vaddr && vaddr - p.p_vaddr <= p.p_filesz) return vaddr - p.p_vaddr + p.p_offset;
        }
        return 0;
    };
    auto word = [&](uint64_t at) {
        uint32_t value = 0;
        if (at + 4 <= file.size()) memcpy(&value, file.data() + at, 4);
        return value;
    };
    const uint64_t here = address(select);
    for (const Phdr& p : segments) {
        /* .eh_frame_hdr: version 1, its pointer (4 bytes), the count (udata4), a table of sdata4 pairs from its start. */
        if (p.p_type != PT_GNU_EH_FRAME || p.p_offset + 12 > file.size()) continue;
        const unsigned char* h = (const unsigned char*)file.data() + p.p_offset;
        if (h[0] != 1 || (h[1] & 0x07) != 0x03 || h[2] != 0x03 || h[3] != 0x3b) return false;
        const uint64_t count = word(p.p_offset + 8);
        uint64_t below = 0, above = UINT64_MAX;
        for (uint64_t i = 0; i < count && p.p_offset + 12 + 8 * i + 8 <= file.size(); i++) {
            const uint64_t location = p.p_vaddr + (int64_t)(int32_t)word(p.p_offset + 12 + 8 * i);
            if (location <= here && location > below) below = location;
            if (location > here && location < above) above = location;
        }
        if (here == 0 || below == 0 || above == UINT64_MAX || above - below > 0x2000) return false;
        start = offsetOf(below);
        end = offsetOf(above);
        return start != 0 && end > start;
    }
    return false;
}

} // namespace

/*
 * Wine's syscall dispatcher in an ntdll.so (its bytes) as file offsets [Start, End): the function holding its one
 * service table selection (shr $8,%ebx; and $0x30,%ebx, in x86_64 and i386 builds alike), bounded by the function starts
 * of its .eh_frame_hdr table (a stripped build names it by no symbol; in Wine 9's, which does, it is
 * __wine_syscall_dispatcher). False when that is not found once.
 */
bool KfWineDispatcher(const std::string& file, uint64_t& start, uint64_t& end)
{
    static const std::string select("\xc1\xeb\x08\x83\xe3\x30", 6);
    const size_t at = file.find(select);
    start = end = 0;
    if (at == std::string::npos || file.find(select, at + 1) != std::string::npos || file.size() < EI_NIDENT ||
        memcmp(file.data(), ELFMAG, SELFMAG) != 0)
        return false;
    return file[EI_CLASS] == ELFCLASS64 ? WineDispatcher<Elf64_Ehdr, Elf64_Phdr>(file, at, start, end)
                                        : WineDispatcher<Elf32_Ehdr, Elf32_Phdr>(file, at, start, end);
}

/*
 * The wineserver protocol an x86_64 ntdll.so (its bytes) speaks: the number its version check passes
 * server_protocol_error ("version mismatch %d/%d": `mov $N,%edx` next to the lea of that text) and compares the
 * server's with (`cmp $N,%reg`); else 930 for Wine 11.0's build string; 0 when neither is found.
 */
unsigned KfWineProtocol(const std::string& file)
{
    const unsigned fallback = file.find(std::string("wine-11.0\0", 10)) != std::string::npos ? KB_WINE_PROTOCOL : 0;
    Elf64_Ehdr eh;
    if (file.size() < sizeof(eh) || memcmp(file.data(), ELFMAG, SELFMAG) != 0 || file[EI_CLASS] != ELFCLASS64) return fallback;
    memcpy(&eh, file.data(), sizeof(eh));
    if (eh.e_shentsize != sizeof(Elf64_Shdr) || eh.e_shoff + (uint64_t)eh.e_shnum * sizeof(Elf64_Shdr) > file.size())
        return fallback;
    std::vector<Elf64_Shdr> sections(eh.e_shnum);
    memcpy(sections.data(), file.data() + eh.e_shoff, sections.size() * sizeof(Elf64_Shdr));
    auto address = [&](uint64_t offset) -> uint64_t {   /* a file offset's virtual address, 0: in no section loaded */
        for (const Elf64_Shdr& section : sections) {
            if (section.sh_type == SHT_PROGBITS && section.sh_addr != 0 && offset >= section.sh_offset &&
                offset < section.sh_offset + section.sh_size)
                return offset - section.sh_offset + section.sh_addr;
        }
        return 0;
    };
    auto byte = [&](size_t at) { return (unsigned char)file[at]; };
    auto word = [&](size_t at) {
        uint32_t value;
        memcpy(&value, file.data() + at, sizeof(value));
        return value;
    };
    auto compared = [&](uint32_t value) {   /* cmp $value,%r32: 81 f8+r, 3d (eax), 41 81 f8+r (r8d-r15d) */
        for (size_t at = file.find(std::string((const char*)&value, 4)); at != std::string::npos;
             at = file.find(std::string((const char*)&value, 4), at + 1)) {
            if ((at >= 1 && byte(at - 1) == 0x3d) || (at >= 2 && byte(at - 2) == 0x81 && byte(at - 1) >= 0xf8)) return true;
        }
        return false;
    };
    const size_t text = file.find("version mismatch %d/%d");
    const uint64_t target = text == std::string::npos ? 0 : address(text);
    for (size_t at = 0; target != 0 && at + 7 <= file.size(); at++) {
        if (byte(at) != 0x48 || byte(at + 1) != 0x8d || byte(at + 2) != 0x3d) continue;   /* lea disp32(%rip),%rdi */
        const uint64_t next = address(at + 7);
        if (next == 0 || next + (int32_t)word(at + 3) != target) continue;
        // The mov closest to the lea: before it, then after.
        for (size_t distance = 1; distance <= 32; distance++) {
            for (size_t mov : {at - std::min(at, distance + 4), at + 6 + distance}) {
                if (mov + 5 > file.size() || byte(mov) != 0xba) continue;   /* mov $imm32,%edx */
                const uint32_t value = word(mov + 1);
                if (value >= 100 && value < 100000 && compared(value)) return value;
            }
        }
    }
    return fallback;
}

/* ---- /system/syscall/<name>: the entry points a policy names (kfilter_syscalls.h), attached only for those ---- */

namespace {

struct SyscallStub {
    const char* program;    /* its fmod_ret program in kfilter.bpf.c */
    const char* function;   /* the entry point */
    int group;              /* the entry point's prototype: 0 `regs`, 1 `__unused` */
    const char* names;      /* the calls it serves, space-separated */
};

const SyscallStub kSyscallStubs[] = {
#define KB_STUB(program, function, group, names) {#program, #function, group, names},
#include "bpf/kfilter_syscalls.h"
#undef KB_STUB
};

/* Each table's calls: number, name and key kind (kfilter.bpf.c's KB_KEY_*, KB_KEY_AT above it). */
struct SyscallRow {
    uint32_t abi, nr;
    const char* name;
    uint32_t key;
};

#define KB_X64 0
#define KB_IA32 1
const SyscallRow kSyscallRows[] = {
#define KB_SYSCALL(abi, nr, name, key, argument, mask, address, length, query, hot) {abi, nr, name, key},
#include "bpf/kfilter_syscalls.h"
#undef KB_SYSCALL
};
#undef KB_X64
#undef KB_IA32

/* The key a rule's text names for a call of Kind as kb_syscall_decide writes it (decimal, 0x<hex>, a wait's any, child
 * or group as 0, 1, 2); false for text the kernel never writes, which meets no decision. */
bool SyscallKey(uint32_t kind, const std::string& text, uint32_t& key)
{
    if (kind == 3 || kind == 4) {
        static const char* const classes[] = {"any", "child", "group"};
        for (uint32_t which = 0; which < 3; which++) {
            if (text == classes[which]) key = which;
        }
        return text == "any" || text == "child" || text == "group";
    }
    const bool hex = kind == 2;
    if (text.empty() || (hex && text.compare(0, 2, "0x") != 0)) return false;
    char* end = nullptr;
    const long long value = hex ? (long long)strtoull(text.c_str() + 2, &end, 16) : strtoll(text.c_str(), &end, 10);
    if (*end != 0 || (hex && text.size() == 2)) return false;
    key = (uint32_t)value;
    return true;
}

/* Calls every process makes all the time: only a rule naming their argument decides them. */
const std::set<std::string>& HotSyscalls()
{
    static const std::set<std::string> hot = [] {
        std::set<std::string> names;
#define KB_SYSCALL(abi, nr, name, key, argument, mask, address, length, query, hot) if (hot) names.insert(name);
#include "bpf/kfilter_syscalls.h"
#undef KB_SYSCALL
        return names;
    }();
    return hot;
}

/* A system rule's path names call Name: its fixed head (before any '*') reaches into /system/syscall/<Name> (a hot
 * call's: past /system/syscall/<Name>/, its argument), so a wildcard right after /system/ or /system/syscall/ attaches
 * nothing. */
bool NamesSyscall(const std::string& path, const std::string& name)
{
    static const std::string space = "/system/syscall/";
    const std::string head = path.substr(0, path.find('*')), call = space + name;
    if (head.compare(0, space.size(), space) != 0 || head.size() <= space.size()) return false;
    if (HotSyscalls().count(name) != 0) return head.compare(0, call.size() + 1, call + "/") == 0 && head.size() > call.size() + 1;
    /* A literal path names the call or one of its keys; a wildcard's head may also stop inside the name. */
    const bool wild = head.size() < path.size();
    return path == call || head.compare(0, call.size() + 1, call + "/") == 0 || (wild && call.compare(0, head.size(), head) == 0);
}

} // namespace

/* What Config's system rules name of each call, by ia32 << 9 | number (kb_syscall_keys, per rule set): any key (the call
 * itself or a parent, a wildcard, more than KB_SYSCALL_KEYS keys), or the literal keys they name. It may name more than a
 * rule meets (a decision is then made that no rule meets), never less. */
std::map<uint32_t, kb_syscall_named> KfBpfSyscallKeys(const KFILTER_CONFIG* config)
{
    std::map<uint32_t, kb_syscall_named> named;
    for (ULONG index = 0; index < config->RuleCount && index < KFILTER_MAX_RULES; index++) {
        const KFILTER_RULE& rule = config->Rules[index];
        if (rule.Targets != KFILTER_TARGET_SYSTEM || wcsncmp(rule.Path, L"/system/syscall/", 16) != 0) continue;
        const std::string path = KfNarrow(std::wstring(rule.Path, KfLengthBounded(rule.Path, KFILTER_MAX_NAME)));
        for (const SyscallRow& row : kSyscallRows) {
            if (!NamesSyscall(path, row.name)) continue;
            kb_syscall_named& entry = named[row.abi << 9 | row.nr];
            const std::string call = "/system/syscall/" + std::string(row.name) + "/";
            uint32_t key = 0;
            if (path.find('*') != std::string::npos || path.compare(0, call.size(), call) != 0) entry.any = 1;
            else if (!SyscallKey(row.key & 0x7F, path.substr(call.size()), key)) continue;
            else if (entry.count >= KB_SYSCALL_KEYS) entry.any = 1;
            else if (std::find(entry.key, entry.key + entry.count, key) == entry.key + entry.count) entry.key[entry.count++] = key;
        }
    }
    return named;
}

/* The target a decision on one of the kernel's own targets (kfilter_bpf.h KB_TARGET_KEYED ... KB_TARGET_SIGNAL) is
 * logged as. */
uint32_t KfBpfPublicTarget(uint32_t target)
{
    if (target == KB_TARGET_KEYED || target == KB_TARGET_SYSTEM_VALUE) return KFILTER_TARGET_SYSTEM;
    if (target == KB_TARGET_PEER_VALUE || target == KB_TARGET_WINDOW || target == KB_TARGET_SIGNAL) return KFILTER_TARGET_PEER;
    if (target == KB_TARGET_THREAD_VALUE) return KFILTER_TARGET_THREAD_PEER;
    if (target == KB_TARGET_ARGUMENT) return KFILTER_TARGET_DEVICE;
    return target;
}

/* The fmod_ret programs (kfilter.bpf.c's kb_s_*) Config's system rules name, attached while the policy is in force. */
std::vector<std::string> KfBpfSyscallPrograms(const KFILTER_CONFIG* config)
{
    std::vector<std::string> paths, programs;
    for (ULONG index = 0; index < config->RuleCount && index < KFILTER_MAX_RULES; index++) {
        const KFILTER_RULE& rule = config->Rules[index];
        if (rule.Targets != KFILTER_TARGET_SYSTEM || wcsncmp(rule.Path, L"/system/syscall/", 16) != 0) continue;
        paths.push_back(KfNarrow(std::wstring(rule.Path, KfLengthBounded(rule.Path, KFILTER_MAX_NAME))));
    }
    if (paths.empty()) return programs;
    for (const SyscallStub& stub : kSyscallStubs) {
        std::istringstream names(stub.names);
        bool named = false;
        for (std::string name; !named && names >> name;) {
            for (const std::string& path : paths) named = named || NamesSyscall(path, name);
        }
        if (named) programs.push_back(stub.program);
    }
    return programs;
}

#ifndef KFILTER_BPF
bool KfBpfStart(uint32_t&) { return false; }
bool KfBpfActive() { return false; }
NTSTATUS KfBpfApply(const KFILTER_CONFIG*) { return STATUS_SUCCESS; }
void KfBpfResetCounts() {}
void KfBpfProtect(pid_t, const std::wstring&) {}
void KfBpfUnprotect(pid_t) {}
void KfBpfAllowLaunch(const std::wstring&, ULONG, ULONG) {}
ULONG KfBpfDropped() { return 0; }
NTSTATUS KfBpfBlockConnection(uint64_t, ULONG) { return STATUS_DEVICE_NOT_READY; }
bool KfBpfPin() { return false; }
void KfBpfUnpin() {}
uint32_t KfBpfDegraded() { return 0; }
#else
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <elf.h>
#include <signal.h>
#include <iterator>
#include "kfilter_bpf_object.h"   /* kKfilterBpfObject[], generated by build.sh */

#ifndef PIDFD_THREAD
#define PIDFD_THREAD O_EXCL
#endif

namespace {

struct Layer {
    bpf_object* object = nullptr;
    ring_buffer* ring = nullptr;
    std::vector<bpf_link*> links;
    std::vector<std::string> names;   /* the program of each link */
    uint32_t degraded = 0;            /* KFILTER_STATUS_DEGRADED_* of programs that did not attach */
    uint32_t gatesLost = 0;           /* OptionalGates of ABI 11's programs that did not attach */
    int config = -1, launch = -1, tasks = -1, drops = -1, procs = -1, blocked = -1, mods = -1;
    int ranges = -1, bases = -1, modseq = -1;   /* addr= rules: their ranges, module bases and table counts */
    int wnamed = -1;                            /* the Wine requests system rules name (kb_wnamed) */
    int unixNames = -1;                         /* message rules' unix= patterns (kb_unix_names) */
    /* The two rule sets (kfilter.bpf.c): a policy is written into the one not in force, then kb_live flips. */
    int rules[2] = {-1, -1}, literal[2] = {-1, -1}, globs[2] = {-1, -1}, net[2] = {-1, -1}, used[2] = {-1, -1},
        phase[2] = {-1, -1};
    int live = -1;
    int ruleSets = -1;   /* kb_rule_sets: an update of it is the grace period after a switch */
    __u32 set = 0;   /* the set in force */
    std::mutex lock;   /* one policy rewrite at a time */
};
Layer gLayer;
bool gActive = false;
bool gBenchLayer = false;   /* KfBpfBench's object: policies compile into its maps, nothing is ever attached */

int MapFd(const char* name)
{
    bpf_map* map = bpf_object__find_map_by_name(gLayer.object, name);
    return map != nullptr ? bpf_map__fd(map) : -1;
}

kb_key LiteralKey(const std::string& path)
{
    kb_key key{KB_FNV_INIT, KB_DJB_INIT, static_cast<__u32>(path.size())};
    for (unsigned char c : path) {
        key.fnv = kb_fnv_step(key.fnv, c);
        key.djb = kb_djb_step(key.djb, c);
    }
    return key;
}

struct KeyLess {
    bool operator()(const kb_key& left, const kb_key& right) const
    {
        return std::tie(left.fnv, left.djb, left.len) < std::tie(right.fnv, right.djb, right.len);
    }
};

/* ---- module tables (kb_mods) for module= rules and the caller on message events ---- */

struct PeCode {
    uint64_t low, high, base;   /* an executable range of the module mapped at base */
    uint32_t bits;              /* module= patterns its file name matches */
    std::string name;
};

/* A mapped PE file (Wine's own DLLs too): where addr= module ranges start. */
struct PeImage {
    uint64_t base;
    uint32_t size;
    std::wstring name;
};

/* A PE file: its SizeOfImage (0: not PE) and its length. */
struct PeFile {
    uint32_t image = 0;
    uint64_t length = 0;
};

struct Modules {
    std::mutex lock;
    std::condition_variable wake;
    std::map<pid_t, std::vector<PeCode>> code;   /* watched programs */
    std::set<pid_t> dirty;
    std::vector<std::wstring> patterns;          /* module= and addr= module patterns; index = bit */
    uint32_t gen = 0;                            /* patterns' list, as kb_ranges and kb_bases carry it */
    std::map<std::pair<std::string, uint64_t>, PeFile> sizes;   /* by file and inode */
};
Modules gModules;

/* SizeOfImage and length of a PE file (SizeOfImage 0 when it is not one). */
PeFile PeSizeOfImage(const std::string& path)
{
    PeFile pe;
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) return pe;
    pe.length = (uint64_t)file.tellg();
    unsigned char dos[0x40] = {};
    if (!file.seekg(0) || !file.read(reinterpret_cast<char*>(dos), sizeof(dos)) || dos[0] != 'M' || dos[1] != 'Z') return pe;
    uint32_t lfanew = dos[0x3c] | dos[0x3d] << 8 | dos[0x3e] << 16 | (uint32_t)dos[0x3f] << 24;
    unsigned char nt[24 + 60] = {};   /* signature, file header, optional header to SizeOfImage */
    if (lfanew > (1u << 20) || !file.seekg(lfanew) || !file.read(reinterpret_cast<char*>(nt), sizeof(nt))) return pe;
    if (memcmp(nt, "PE\0\0", 4) != 0) return pe;
    const unsigned char* size = nt + 24 + 56;
    pe.image = size[0] | size[1] << 8 | size[2] << 16 | (uint32_t)size[3] << 24;
    return pe;
}

/* Wine's own modules and the prefix's windows directory: the caller is the code that
 * called into them (msmon's caller_module skips the same). */
bool SystemModule(const std::string& path)
{
    std::string lower = path;
    for (char& c : lower) c = (char)tolower((unsigned char)c);
    return lower.find("/lib/wine/") != std::string::npos || lower.find("/lib64/wine/") != std::string::npos ||
           lower.find("/drive_c/windows/") != std::string::npos;
}

/* The executable ranges of Pid's own PE modules, from /proc/<pid>/maps: a module is an image view
 * of a PE file, mapped at offset 0 with code (an executable mapping) within SizeOfImage of it (Wine
 * often copies sections into anonymous memory); a view of the whole file is data (MapViewOfFile,
 * LoadLibraryEx as a data file), not a module. Images: every module, Wine's too, from the lowest
 * address. */
std::vector<PeCode> ReadModules(pid_t pid, std::vector<PeImage>& images)
{
    struct Line {
        uint64_t low, high, offset, inode;
        bool exec;
        std::string path;
    };
    std::vector<Line> lines;
    std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
    std::string text;
    while (std::getline(maps, text)) {
        std::istringstream fields(text);
        std::string range, perms, offset, device, path;
        uint64_t inode = 0;
        if (!(fields >> range >> perms >> offset >> device >> inode)) continue;
        std::getline(fields >> std::ws, path);
        Line line{};
        if (sscanf(range.c_str(), "%" SCNx64 "-%" SCNx64, &line.low, &line.high) != 2) continue;
        line.offset = strtoull(offset.c_str(), nullptr, 16);
        line.inode = inode;
        line.exec = perms.size() > 2 && perms[2] == 'x';
        line.path = path;
        lines.push_back(line);
    }
    std::vector<PeCode> code;
    std::vector<std::wstring> patterns;
    {
        std::lock_guard<std::mutex> guard(gModules.lock);
        patterns = gModules.patterns;
    }
    for (const Line& image : lines) {
        if (image.offset != 0 || image.path.empty() || image.path[0] != '/') continue;
        PeFile pe;
        {
            std::lock_guard<std::mutex> guard(gModules.lock);
            auto key = std::make_pair(image.path, image.inode);
            auto found = gModules.sizes.find(key);
            if (found == gModules.sizes.end()) found = gModules.sizes.emplace(key, PeSizeOfImage(image.path)).first;
            pe = found->second;
        }
        const uint32_t size = pe.image;
        if (size == 0 || image.high - image.low >= pe.length) continue;   /* not PE, or a view of the whole file */
        if (std::none_of(lines.begin(), lines.end(), [&](const Line& line) {
                return line.exec && line.high > image.low && line.low < image.low + size;
            })) continue;   /* no code: a data view of its head */
        std::string name = image.path.substr(image.path.find_last_of('/') + 1);
        std::wstring wide = KfWide(name);
        images.push_back({image.low, size, wide});
        if (SystemModule(image.path)) continue;
        uint32_t bits = 0;
        for (size_t index = 0; index < patterns.size() && index < KB_MOD_BITS; index++) {
            if (KfImageMatches(patterns[index].c_str(), wide.c_str(), (KF_ULONG)wide.size())) bits |= 1u << index;
        }
        for (const Line& line : lines) {
            if (!line.exec || line.high <= image.low || line.low >= image.low + size) continue;
            code.push_back({std::max(line.low, image.low), std::min(line.high, image.low + size), image.low, bits, name});
        }
    }
    std::sort(code.begin(), code.end(), [](const PeCode& a, const PeCode& b) { return a.low < b.low; });
    return code;
}

void WmiProbe(pid_t pid, bool fresh);

/* Rereads Pid's modules into kb_mods (clearing dirty) and kb_bases if it is still watched. */
void RefreshModules(pid_t pid)
{
    __u32 key = (__u32)pid, seq = 0, now = 0;
    bpf_map_lookup_elem(gLayer.modseq, &key, &seq);   /* before the maps are read: a change after it makes them stale */
    std::vector<PeImage> images;
    std::vector<PeCode> code = ReadModules(pid, images);
    WmiProbe(pid, false);   /* a wbemprox.dll loaded before the policy named WMI, or before kfilterd */
    std::lock_guard<std::mutex> guard(gModules.lock);
    if (gModules.code.count(pid) == 0) return;
    kb_base bases{};
    bases.seq = seq;
    bases.gen = gModules.gen;
    for (size_t index = 0; index < gModules.patterns.size() && index < KB_MOD_BITS; index++) {
        for (const PeImage& image : images) {
            if (!KfImageMatches(gModules.patterns[index].c_str(), image.name.c_str(), (KF_ULONG)image.name.size())) continue;
            bases.present |= 1u << index;
            bases.base[index] = image.base;
            bases.size[index] = image.size;
            break;
        }
    }
    bpf_map_update_elem(gLayer.bases, &key, &bases, BPF_ANY);
    /* A module mapped while the maps were read: read them again. */
    if (bpf_map_lookup_elem(gLayer.modseq, &key, &now) == 0 && now != seq) {
        gModules.dirty.insert(pid);
        gModules.wake.notify_one();
    }
    if (code.size() > KB_MODS) {
        fprintf(stderr, "kfilterd: pid %d has %zu module code ranges; module= sees the first %d\n", pid, code.size(),
                KB_MODS);
        code.resize(KB_MODS);
    }
    kb_mods value{};
    value.count = (__u32)code.size();
    for (size_t index = 0; index < code.size(); index++) value.m[index] = {code[index].low, code[index].high, code[index].bits, 0};
    bpf_map_update_elem(gLayer.mods, &key, &value, BPF_ANY);
    gModules.code[pid] = std::move(code);
}

/* Keeps module tables current: a reread at most every 200 ms per burst of mappings, and
 * every 2 s for tables whose request event was lost. */
void ModulesWorker()
{
    for (;;) {
        std::set<pid_t> pids;
        {
            std::unique_lock<std::mutex> guard(gModules.lock);
            gModules.wake.wait_for(guard, std::chrono::seconds(2), [] { return !gModules.dirty.empty(); });
            // Every pass, not only an idle one: a JIT program keeps the set busy, and a table whose request event was
            // lost would stay stale (an addr= deny then meets every access to that program).
            for (const auto& entry : gModules.code) {
                __u32 key = (__u32)entry.first, seq = 0;
                kb_mods value{};
                kb_base bases{};
                if ((bpf_map_lookup_elem(gLayer.mods, &key, &value) == 0 && value.dirty) ||
                    (bpf_map_lookup_elem(gLayer.modseq, &key, &seq) == 0 &&
                     (bpf_map_lookup_elem(gLayer.bases, &key, &bases) != 0 || bases.seq != seq)))
                    gModules.dirty.insert(entry.first);
            }
        }
        /* Let the mapping that asked finish before its maps are read. */
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        {
            std::lock_guard<std::mutex> guard(gModules.lock);
            pids.swap(gModules.dirty);
        }
        for (pid_t pid : pids) RefreshModules(pid);
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
    }
}

void ModulesAsk(pid_t pid)
{
    std::lock_guard<std::mutex> guard(gModules.lock);
    if (gModules.code.count(pid) == 0) return;
    gModules.dirty.insert(pid);
    gModules.wake.notify_one();
}

/* Starts keeping Pid's module table if it is a Wine program. */
void ModulesWatch(pid_t pid)
{
    if (!KfWineLoader(KfExePath(pid))) return;
    std::lock_guard<std::mutex> guard(gModules.lock);
    if (gModules.code.count(pid) != 0) return;
    gModules.code[pid];
    kb_mods value{};
    value.dirty = 1;   /* no events until the first read */
    __u32 key = (__u32)pid, zero = 0;
    bpf_map_update_elem(gLayer.mods, &key, &value, BPF_ANY);
    bpf_map_update_elem(gLayer.modseq, &key, &zero, BPF_ANY);
    bpf_map_delete_elem(gLayer.bases, &key);   /* an earlier kfilterd's, or a reused pid's: not current */
    gModules.dirty.insert(pid);
    gModules.wake.notify_one();
}

void WmiForget(pid_t pid);
std::string Lower(std::string text);

void ModulesForget(pid_t pid)
{
    WmiForget(pid);
    std::lock_guard<std::mutex> guard(gModules.lock);
    gModules.code.erase(pid);
    gModules.dirty.erase(pid);
    __u32 key = (__u32)pid;
    bpf_map_delete_elem(gLayer.mods, &key);
    bpf_map_delete_elem(gLayer.modseq, &key);
    bpf_map_delete_elem(gLayer.bases, &key);
}

/* ---- uprobes: Windows calls Wine answers in the program's own process (kb_win32k on win32u.so and ntdll.so)
 * and WMI queries (kb_wmi on wbemprox.dll's IWbemServices methods), decided as /system/win32k/<function>,
 * /system/ntdll/<function> and /system/wmi/<class> where a rule names those namespaces ---- */

struct Uprobes {
    std::mutex lock;
    std::vector<bpf_link*> win32k;   /* one per win32u.so and ntdll.so, in every process that maps it */
    std::vector<std::tuple<std::string, std::vector<unsigned long>, std::vector<__u64>>> plan;   /* their paths, offsets, cookies */
    uint32_t win32kDegraded = 0;     /* KFILTER_STATUS_DEGRADED_SYSTEM: a function the rules name is not probed */
    bool attachFailed = false;       /* some of win32k's functions are not probed */
    bool wmi = false;                /* a rule names /system/wmi */
    std::map<pid_t, std::map<std::string, bpf_link*>> queries;   /* kb_wmi by program and wbemprox path (null: not probed) */
    std::map<std::string, std::pair<std::vector<uint64_t>, bool>> methods;   /* by wbemprox path: WmiMethods, i386 */
};
Uprobes gUprobes;

/* The /system/syscall entry points attached for the policy in force (KfBpfSyscallPrograms), by program. */
struct Syscalls {
    std::mutex lock;
    std::map<std::string, bpf_link*> links;
    std::set<std::string> unloaded;   /* entry points this kernel lacks, or whose prototype is not their group's */
    uint32_t degraded = 0;            /* KFILTER_STATUS_DEGRADED_SYSTEM: a call a rule names is not decided */
    bool applied = false;             /* SyscallApply ran: a taken-over layer's kb_s_* pins may go */
};
Syscalls gSyscalls;

/* Before the load: an entry point this kernel's BTF lacks, or whose prototype is not its group's (a tail call needs the
 * decision program's), is left unloaded rather than fail the whole layer, and a rule naming its call leaves the system
 * class degraded. A group whose decision program cannot load leaves all of its entry points unloaded. */
void SyscallTargets()
{
    btf* vmlinux = btf__load_vmlinux_btf();
    std::map<std::string, std::string> parameter;   /* entry point -> its prototype's one parameter */
    for (__u32 id = 1; vmlinux != nullptr && id < btf__type_cnt(vmlinux); id++) {
        const btf_type* type = btf__type_by_id(vmlinux, id);
        if (!btf_is_func(type)) continue;
        const char* name = btf__name_by_offset(vmlinux, type->name_off);
        if (strncmp(name, "__x64_sys_", 10) != 0 && strncmp(name, "__ia32_", 7) != 0 && strncmp(name, "__do_sys_", 9) != 0 &&
            strncmp(name, "__do_compat_sys_", 16) != 0)
            continue;
        const btf_type* proto = btf__type_by_id(vmlinux, type->type);
        if (proto == nullptr || !btf_is_func_proto(proto) || btf_vlen(proto) != 1) continue;
        parameter[name] = btf__name_by_offset(vmlinux, btf_params(proto)[0].name_off);
    }
    btf__free(vmlinux);
    auto fits = [&](const char* function, int group) {
        auto found = parameter.find(function);
        return found != parameter.end() && found->second == (group == 0 ? "regs" : "__unused");
    };
    const bool deciders[2] = {fits(KB_SYSCALL_DECIDER0, 0), fits(KB_SYSCALL_DECIDER1, 1)};
    for (int group = 0; group < 2; group++) {
        bpf_program* decider = bpf_object__find_program_by_name(gLayer.object, group == 0 ? "kb_syscall" : "kb_syscall1");
        if (decider != nullptr && !deciders[group]) bpf_program__set_autoload(decider, false);
    }
    std::lock_guard<std::mutex> guard(gSyscalls.lock);
    for (const SyscallStub& stub : kSyscallStubs) {
        if (deciders[stub.group] && fits(stub.function, stub.group)) continue;
        bpf_program* program = bpf_object__find_program_by_name(gLayer.object, stub.program);
        if (program != nullptr) bpf_program__set_autoload(program, false);
        gSyscalls.unloaded.insert(stub.program);
    }
    if (!gSyscalls.unloaded.empty()) {
        fprintf(stderr, "kfilterd: %zu syscall entry points are not on this kernel as built for; rules naming their calls "
                        "are not decided\n", gSyscalls.unloaded.size());
    }
}

/* After the load: each group's decision program into its tail call map (a pinned map an earlier kfilterd filled now
 * calls this build's). */
void SyscallTails()
{
    for (int group = 0; group < 2; group++) {
        bpf_program* decider = bpf_object__find_program_by_name(gLayer.object, group == 0 ? "kb_syscall" : "kb_syscall1");
        const int map = MapFd(group == 0 ? "kb_syscall_tail0" : "kb_syscall_tail1");
        const int fd = decider != nullptr && bpf_program__autoload(decider) ? bpf_program__fd(decider) : -1;
        const __u32 zero = 0;
        if (fd >= 0 && map >= 0 && bpf_map_update_elem(map, &zero, &fd, BPF_ANY) == 0) continue;
        fprintf(stderr, "kfilterd: syscall decision program %d is not in place (%s); rules naming its calls are not decided\n",
                group, strerror(errno));
        std::lock_guard<std::mutex> guard(gSyscalls.lock);
        for (const SyscallStub& stub : kSyscallStubs) {
            if (stub.group == group) gSyscalls.unloaded.insert(stub.program);
        }
    }
}

void DestroyLinks(std::vector<bpf_link*> links);

/* The entry points Config's rules name attached, the others detached; a named one that cannot be leaves the system class
 * degraded. Each attached entry point costs every process on the system a trampoline on that call. */
void SyscallApply(const KFILTER_CONFIG* config)
{
    std::set<std::string> wanted;
    for (const std::string& program : KfBpfSyscallPrograms(config)) wanted.insert(program);
    std::lock_guard<std::mutex> guard(gSyscalls.lock);
    std::vector<bpf_link*> gone;
    for (auto entry = gSyscalls.links.begin(); entry != gSyscalls.links.end();) {
        if (wanted.count(entry->first) != 0) {
            ++entry;
            continue;
        }
        if (bpf_link__pin_path(entry->second) != nullptr) bpf_link__unpin(entry->second);
        gone.push_back(entry->second);
        entry = gSyscalls.links.erase(entry);
    }
    DestroyLinks(gone);
    gSyscalls.applied = true;
    gSyscalls.degraded = 0;
    for (const std::string& name : wanted) {
        if (gSyscalls.links.count(name) != 0) continue;
        bpf_program* program = bpf_object__find_program_by_name(gLayer.object, name.c_str());
        bpf_link* link = !gBenchLayer && program != nullptr && gSyscalls.unloaded.count(name) == 0 &&
                                 bpf_program__autoload(program) ? bpf_program__attach(program) : nullptr;
        if (link == nullptr) {
            fprintf(stderr, "kfilterd: %s did not attach; the calls it serves are not decided\n", name.c_str());
            gSyscalls.degraded = KFILTER_STATUS_DEGRADED_SYSTEM;
            continue;
        }
        gSyscalls.links[name] = link;
    }
}

/* The exported functions of an ELF shared object (.dynsym) with their file offsets. */
template <typename Ehdr, typename Shdr, typename Sym>
void ElfExports(const std::vector<char>& f, std::map<std::string, uint64_t>& out)
{
    Ehdr eh;
    if (f.size() < sizeof(eh) || memcmp(f.data(), ELFMAG, SELFMAG) != 0) return;
    memcpy(&eh, f.data(), sizeof(eh));
    if (eh.e_shentsize != sizeof(Shdr) || eh.e_shoff + (uint64_t)eh.e_shnum * sizeof(Shdr) > f.size()) return;
    std::vector<Shdr> sh(eh.e_shnum);
    memcpy(sh.data(), f.data() + eh.e_shoff, sh.size() * sizeof(Shdr));
    for (const Shdr& table : sh) {
        if (table.sh_type != SHT_DYNSYM || table.sh_link >= sh.size()) continue;
        const uint64_t strings = sh[table.sh_link].sh_offset;
        const uint64_t end = std::min<uint64_t>(f.size(), table.sh_offset + table.sh_size);
        for (uint64_t at = table.sh_offset; at + sizeof(Sym) <= end; at += sizeof(Sym)) {
            Sym sym;
            memcpy(&sym, f.data() + at, sizeof(sym));
            if ((sym.st_info & 0xf) != STT_FUNC || sym.st_shndx == SHN_UNDEF || sym.st_shndx >= sh.size() ||
                strings + sym.st_name >= f.size())
                continue;
            const char* name = f.data() + strings + sym.st_name;
            out[std::string(name, strnlen(name, f.size() - (strings + sym.st_name)))] =
                sym.st_value - sh[sym.st_shndx].sh_addr + sh[sym.st_shndx].sh_offset;
        }
    }
}

std::map<std::string, uint64_t> ElfExports(const std::string& path, bool& i386)
{
    std::ifstream in(path, std::ios::binary);
    const std::vector<char> file((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    std::map<std::string, uint64_t> exports;
    i386 = file.size() > EI_CLASS && file[EI_CLASS] == ELFCLASS32;
    if (i386) ElfExports<Elf32_Ehdr, Elf32_Shdr, Elf32_Sym>(file, exports);
    else ElfExports<Elf64_Ehdr, Elf64_Shdr, Elf64_Sym>(file, exports);
    return exports;
}

/* A system rule whose fixed head (before any '*') lies in Space ("/system/win32k"): only such
 * rules make the uprobes, so a broad /system/... rule does not put breakpoints in every Wine process. */
bool NamesSpace(const KFILTER_RULE& rule, const std::wstring& space)
{
    if (rule.Targets != KFILTER_TARGET_SYSTEM) return false;
    std::wstring path(rule.Path, KfLengthBounded(rule.Path, KFILTER_MAX_NAME));
    std::wstring head = path.substr(0, path.find(L'*'));
    return head.compare(0, space.size(), space) == 0 && (head.size() == space.size() || head[space.size()] == L'/');
}

/* Destroys Links (each detach waits for the kernel) away from the caller. */
void DestroyLinks(std::vector<bpf_link*> links)
{
    if (links.empty()) return;
    std::thread([links] {
        for (bpf_link* link : links) bpf_link__destroy(link);
    }).detach();
}

/* kb_win32k on the win32u.so and ntdll.so functions Config's system rules name (KfBpfUprobeFunctions), in every Wine
 * install kfilter decodes (x86_64-unix and i386-unix): attached to the file, so every process, present and future,
 * gets them; the program returns at once for any task but a protected program's. Each install's syscall dispatcher
 * goes into kb_dispatch (KfWineDispatcher). A function a literal rule names that a library lacks (an ntdll.so one
 * kfilter does not decide, a key or class of a function that has none), an ntdll.so rule in an install whose
 * dispatcher was not found, or a failed attach leaves the system class degraded. */
void Win32kApply(const KFILTER_CONFIG* config, const std::vector<std::string>& wineDirs)
{
    struct Call { const char* library; const char* name; uint32_t kind, right; };
#define KB_UP_CALL(library, name, kind, right) {#library, #name, kind, right},
    static const Call calls[] = {KB_UP_CALLS(KB_UP_CALL)};
#undef KB_UP_CALL
    std::vector<const KFILTER_RULE*> rules;
    bool ntdllRules = false;
    for (ULONG index = 0; index < config->RuleCount; index++) {
        const bool ntdll = NamesSpace(config->Rules[index], L"/system/ntdll");
        if (ntdll || NamesSpace(config->Rules[index], L"/system/win32k")) rules.push_back(&config->Rules[index]);
        ntdllRules |= ntdll;
    }
    struct Library {
        std::string path;
        bool ntdll;
        __u32 slot;                                /* kb_dispatch's: 2 * install + i386 */
        std::map<std::string, uint64_t> exports;
        std::map<std::string, uint64_t> named;     /* KfBpfUprobeFunctions */
    };
    std::vector<Library> libraries;
    uint32_t degraded = 0;
    const int dispatch = MapFd("kb_dispatch");
    for (size_t install = 0; install < wineDirs.size() && install < KB_WINE_DIRS; install++) {
        for (const char* arch : {"x86_64-unix", "i386-unix"}) {
            const __u32 slot = (__u32)(2 * install + (arch[0] == 'i'));
            for (const bool ntdll : {false, true}) {
                const std::string path = wineDirs[install] + "lib/wine/" + arch + (ntdll ? "/ntdll.so" : "/win32u.so");
                if (rules.empty() || access(path.c_str(), R_OK) != 0) continue;
                bool i386 = false;
                Library library{path, ntdll, slot, ElfExports(path, i386), {}};
                library.named = KfBpfUprobeFunctions(config, ntdll, library.exports);
                libraries.push_back(library);
                if (!ntdll) continue;
                std::ifstream in(path, std::ios::binary);
                const std::string file((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
                uint64_t start = 0, end = 0;
                if (!KfWineDispatcher(file, start, end)) {
                    fprintf(stderr, "kfilterd: no syscall dispatcher found in %s: its calls of ntdll.so's functions are not "
                                    "decided, win32u.so's by their return into ntdll.so\n", path.c_str());
                    if (ntdllRules) degraded = KFILTER_STATUS_DEGRADED_SYSTEM;
                }
                const kb_dispatch found = {start, end};
                bpf_map_update_elem(dispatch, &slot, &found, BPF_ANY);
            }
        }
    }
    for (const KFILTER_RULE* rule : rules) {
        const std::string path = KfNarrow(std::wstring(rule->Path, KfLengthBounded(rule->Path, KFILTER_MAX_NAME)));
        const bool ntdll = path.rfind("/system/ntdll/", 0) == 0;
        const size_t base = ntdll ? 14 : 15, slash = path.find('/', base);
        if (path.find('*') != std::string::npos || path.size() <= base) continue;   /* a pattern, or the whole space */
        const std::string name = path.substr(base, slash == std::string::npos ? std::string::npos : slash - base);
        uint32_t kind = 0;
        bool decided = !ntdll;   /* any win32u.so export; ntdll.so's KB_UP_CALLS */
        for (const Call& call : calls) {
            if (name != call.name || (strcmp(call.library, "ntdll") == 0) != ntdll) continue;
            kind = call.kind;
            decided = true;
        }
        /* A key needs a keyed function; a class, a function with one (NtGet/SetContextThread are valued, not keyed). */
        if (slash != std::string::npos && (kind == 0 || kind == KB_UP_CONTEXT)) decided = false;
        bool everywhere = true, any = false;
        for (const Library& library : libraries) {
            if (library.ntdll != ntdll) continue;
            any = true;
            everywhere = everywhere && library.exports.count(name) != 0;
        }
        if (!decided || !everywhere || !any) {
            fprintf(stderr, "kfilterd: rule %u: %s is no call kfilter decides in every Wine install's %s; it is not decided\n",
                    (unsigned)rule->RuleId, path.c_str(), ntdll ? "ntdll.so" : "win32u.so");
            degraded = KFILTER_STATUS_DEGRADED_SYSTEM;
        }
    }
    if (!rules.empty() && libraries.empty()) {
        fprintf(stderr, "kfilterd: system rules name /system/win32k or /system/ntdll but no Wine 11 library was found\n");
        degraded = KFILTER_STATUS_DEGRADED_SYSTEM;
    }
    std::set<std::string> functions;   /* every library's, one kb_w32names slot each */
    std::vector<std::tuple<std::string, std::vector<unsigned long>, std::vector<__u64>>> plan;
    std::map<std::string, __u32> slots;
    for (const Library& library : libraries) {
        for (const auto& entry : library.named) functions.insert(entry.first);
    }
    bool full = false;
    for (const std::string& name : functions) {
        if (slots.size() >= KB_W32_NAMES || name.size() >= KB_W32_NAME) {
            full = true;
            continue;
        }
        const __u32 slot = (__u32)slots.size();
        slots[name] = slot;
    }
    for (const Library& library : libraries) {
        const bool i386 = library.path.find("/i386-unix/") != std::string::npos;
        std::vector<unsigned long> offsets;
        std::vector<__u64> cookies;
        for (const auto& [name, cookie] : library.named) {
            if (slots.count(name) == 0) continue;
            offsets.push_back(library.exports.at(name));
            cookies.push_back(cookie | slots[name] | (i386 ? KB_UP_I386 : 0) | KB_UP_COOKIE(0, library.slot, 0));
        }
        if (!offsets.empty()) plan.emplace_back(library.path, offsets, cookies);
    }
    std::lock_guard<std::mutex> guard(gUprobes.lock);
    if (plan != gUprobes.plan) {
        for (bpf_link* link : gUprobes.win32k) {
            if (bpf_link__pin_path(link) != nullptr) bpf_link__unpin(link);   /* now: KfBpfPin reuses the names */
        }
        DestroyLinks(gUprobes.win32k);
        gUprobes.win32k.clear();
        gUprobes.plan = plan;
        gUprobes.attachFailed = full;
        const int names = MapFd("kb_w32names");
        for (const auto& [name, slot] : slots) {
            kb_w32name value{};
            memcpy(value.name, name.data(), name.size());
            bpf_map_update_elem(names, &slot, &value, BPF_ANY);
        }
        bpf_program* program = gBenchLayer ? nullptr : bpf_object__find_program_by_name(gLayer.object, "kb_win32k");
        for (auto& [path, offsets, cookies] : plan) {
            bpf_uprobe_multi_opts opts{};
            opts.sz = sizeof(opts);
            opts.offsets = offsets.data();
            opts.cookies = cookies.data();
            opts.cnt = offsets.size();
            bpf_link* link = program ? bpf_program__attach_uprobe_multi(program, -1, path.c_str(), nullptr, &opts) : nullptr;
            if (link == nullptr) {
                fprintf(stderr, "kfilterd: kb_win32k did not attach to %s (%s); its functions are not decided\n",
                        path.c_str(), strerror(errno));
                gUprobes.attachFailed = true;
                continue;
            }
            gUprobes.win32k.push_back(link);
        }
    }
    gUprobes.win32kDegraded = degraded | (gUprobes.attachFailed ? KFILTER_STATUS_DEGRADED_SYSTEM : 0);
}

/* The IWbemServices vtable entries kb_wmi decides, by KB_WMI_* (kfilter_bpf.h), and their names. */
const struct { unsigned entry; const char* name; } kWmiMethods[KB_WMI_METHODS] = {
    {20, "ExecQuery"}, {21, "ExecQueryAsync"}, {6, "GetObject"}, {18, "CreateInstanceEnum"}, {24, "ExecMethod"}};

/* File offsets of kWmiMethods in the wbemprox.dll at Path (0: not found; all 0 without ExecQuery), and
 * whether it is i386 code. Found through the DWARF Wine builds its DLLs with, as msmon's PeWmiMethods
 * does: wbem_services_vtbl's location (DW_OP_addr), then the table's entries. shortcut: a build without
 * DWARF, or naming the table through .debug_str, is not found (degraded); parse .debug_info then. */
std::vector<uint64_t> WmiMethods(const std::string& path, bool& i386)
{
    std::vector<uint64_t> found(KB_WMI_METHODS, 0);
    std::ifstream in(path, std::ios::binary);
    const std::vector<char> file((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    auto inFile = [&](uint64_t offset, uint64_t size) { return offset <= file.size() && size <= file.size() - offset; };
    auto get = [&](uint64_t offset, unsigned width) {
        uint64_t value = 0;
        if (inFile(offset, width)) memcpy(&value, file.data() + offset, width);
        return value;
    };
    if (!inFile(0, 0x40)) return found;
    const uint64_t nt = get(0x3c, 4);
    if (!inFile(nt, 24 + 0x60) || memcmp(file.data() + nt, "PE\0\0", 4) != 0) return found;
    const unsigned width = get(nt + 24, 2) == 0x20b ? 8 : 4;
    i386 = get(nt + 4, 2) == 0x14c;
    const uint64_t imageBase = width == 8 ? get(nt + 24 + 24, 8) : get(nt + 24 + 28, 4);
    const uint64_t table = nt + 24 + get(nt + 20, 2), count = get(nt + 6, 2);
    /* An RVA's file offset (Code: inside an executable section), 0 when it has none. */
    auto offsetOf = [&](uint64_t rva, bool code) -> uint64_t {
        for (uint64_t header = table; header < table + count * 40 && inFile(header, 40); header += 40) {
            const uint64_t va = get(header + 12, 4), size = get(header + 16, 4), raw = get(header + 20, 4);
            if (rva >= va && rva - va < size && (!code || (get(header + 36, 4) & 0x20000020u) != 0)) return raw + (rva - va);
        }
        return 0;
    };
    static const char kName[] = "wbem_services_vtbl";
    for (auto at = file.begin(); (at = std::search(at, file.end(), kName, kName + sizeof(kName))) != file.end(); ++at) {
        const uint64_t name = (uint64_t)(at - file.begin()) + sizeof(kName);
        for (uint64_t scan = name; scan < name + 32 && inFile(scan, 2 + width); scan++) {
            if ((unsigned char)file[scan] != width + 1 || file[scan + 1] != 0x03) continue;   /* exprloc: DW_OP_addr */
            for (unsigned method = 0; method < KB_WMI_METHODS; method++) {
                const uint64_t entry = offsetOf(get(scan + 2, width) - imageBase + kWmiMethods[method].entry * width, false);
                found[method] = entry ? offsetOf(get(entry, width) - imageBase, true) : 0;
            }
            if (found[KB_WMI_EXEC_QUERY] != 0) return found;
        }
    }
    return std::vector<uint64_t>(KB_WMI_METHODS, 0);
}

/* kb_wmi on the IWbemServices methods of each wbemprox.dll Pid has executable, once per mapping (Fresh: a new load,
 * whose code an earlier probe no longer reaches). Only while a rule names /system/wmi. */
void WmiProbe(pid_t pid, bool fresh)
{
    std::set<std::string> loaded;
    {
        std::lock_guard<std::mutex> guard(gUprobes.lock);
        if (!gUprobes.wmi) return;
    }
    std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
    for (std::string line; std::getline(maps, line);) {
        const size_t slash = line.find('/');
        if (slash == std::string::npos || line.find(" r-xp ") == std::string::npos) continue;
        std::string path = line.substr(slash);
        std::string lower = Lower(path);
        if (lower.size() >= 13 && lower.compare(lower.size() - 13, 13, "/wbemprox.dll") == 0) loaded.insert(path);
    }
    std::lock_guard<std::mutex> guard(gUprobes.lock);
    for (const std::string& path : loaded) {
        std::map<std::string, bpf_link*>& probes = gUprobes.queries[pid];
        if (probes.count(path) != 0 && !fresh) continue;   /* probed, or tried */
        bpf_link*& link = probes[path];
        auto found = gUprobes.methods.find(path);
        if (found == gUprobes.methods.end()) {
            bool i386 = false;
            std::vector<uint64_t> offsets = WmiMethods(path, i386);
            found = gUprobes.methods.emplace(path, std::make_pair(offsets, i386)).first;
        }
        if (link != nullptr) DestroyLinks({link});
        link = nullptr;
        std::vector<unsigned long> offsets;
        std::vector<__u64> cookies;
        std::string missing;
        for (unsigned method = 0; method < KB_WMI_METHODS; method++) {
            if (found->second.first[method] == 0) {
                missing += std::string(missing.empty() ? "" : ", ") + kWmiMethods[method].name;
                continue;
            }
            offsets.push_back(found->second.first[method]);
            cookies.push_back(method | (found->second.second ? KB_UP_I386 : 0));
        }
        bpf_uprobe_multi_opts opts{};
        opts.sz = sizeof(opts);
        opts.offsets = offsets.data();
        opts.cookies = cookies.data();
        opts.cnt = offsets.size();
        bpf_program* program = gBenchLayer ? nullptr : bpf_object__find_program_by_name(gLayer.object, "kb_wmi");
        if (!offsets.empty() && program != nullptr) link = bpf_program__attach_uprobe_multi(program, pid, path.c_str(), nullptr, &opts);
        if (link == nullptr && !offsets.empty() && program != nullptr && errno == ESRCH) {
            probes.erase(path);   /* the program is gone: nothing left undecided */
        } else if (link == nullptr) {
            fprintf(stderr, "kfilterd: WMI queries of pid %d are not decided: %s%s\n", pid, path.c_str(),
                    offsets.empty() ? " has no ExecQuery kfilterd can find" : " could not be probed");
        } else if (!missing.empty()) {
            /* shortcut: decided but not degraded; a wbemprox lacking some methods is not one Wine ships. */
            fprintf(stderr, "kfilterd: WMI calls of pid %d not decided: %s in %s\n", pid, missing.c_str(), path.c_str());
        }
    }
}

/* KB_EV_WMI: once the thread whose mprotect made wbemprox's code executable has stopped (so the
 * mprotect is done), probe the program's IWbemServices methods and resume it, within a second whatever happens.
 * shortcut: these probes are not pinned, so WMI queries go undecided once kfilterd exits (a restarted
 * kfilterd probes the running programs again as it rereads their modules); pin them per program if
 * block mode must hold WMI across a kfilterd restart. */
void WmiStopped(pid_t tgid, pid_t tid)
{
    const std::string stat = "/proc/" + std::to_string(tgid) + "/task/" + std::to_string(tid) + "/stat";
    for (int tries = 0; tries < 1000; tries++) {
        std::ifstream file(stat);
        std::string text((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        const size_t close = text.rfind(") ");
        if (close == std::string::npos || close + 2 >= text.size() || text[close + 2] == 'T' || text[close + 2] == 't') break;
        usleep(1000);
    }
    WmiProbe(tgid, true);
    kill(tgid, SIGCONT);
    __u32 key = (__u32)tgid;
    bpf_map_delete_elem(MapFd("kb_wmi_stopped"), &key);
}

/* Resumes every program kb_wmi_stopped still holds: at start, those a killed kfilterd left stopped
 * (its policy, once adopted, probes them again); at exit, those whose WmiStopped dies with us.
 * shortcut: a layer that was not pinned (audit mode) is gone with a killed kfilterd, and its stopped
 * programs stay stopped; record them outside the layer if audit-mode crashes matter. */
void WmiResumeAll()
{
    const int map = MapFd("kb_wmi_stopped");
    std::vector<__u32> stopped;
    __u32 key = 0, next = 0;
    for (__u32* previous = nullptr; bpf_map_get_next_key(map, previous, &next) == 0; previous = &key) {
        stopped.push_back(next);
        key = next;
    }
    for (__u32 tgid : stopped) {
        kill((pid_t)tgid, SIGCONT);
        bpf_map_delete_elem(map, &tgid);
    }
}

void WmiForget(pid_t pid)
{
    std::vector<bpf_link*> links;
    {
        std::lock_guard<std::mutex> guard(gUprobes.lock);
        auto found = gUprobes.queries.find(pid);
        if (found == gUprobes.queries.end()) return;
        for (const auto& entry : found->second) {
            if (entry.second != nullptr) links.push_back(entry.second);
        }
        gUprobes.queries.erase(found);
    }
    DestroyLinks(links);
}

/* " caller=module+0xOFFSET" for a message event's caller, "" when unknown. */
std::string Caller(pid_t pid, uint64_t address)
{
    if (address == 0) return "";
    std::lock_guard<std::mutex> guard(gModules.lock);
    auto found = gModules.code.find(pid);
    if (found == gModules.code.end()) return "";
    for (const PeCode& code : found->second) {
        if (address < code.low || address >= code.high) continue;
        char offset[32];
        snprintf(offset, sizeof(offset), "+0x%" PRIx64, address - code.base);
        return " caller=" + code.name + offset;
    }
    return "";
}

/* A message decision: direction, endpoint, connection, number, size, caller and first bytes. */
std::wstring Message(const kb_event& e)
{
    const unsigned family = e.ppid >> 8;
    const unsigned protocol = e.ppid & 0xff;
    char text[INET6_ADDRSTRLEN] = "?";
    inet_ntop(family == 6 ? AF_INET6 : AF_INET, e.path, text, sizeof(text));
    // A unix send names its peer as a connect to it is named: "send unix /@/tmp/.X11-unix/X5 socket:[...] ...".
    const std::string peer = family == KFILTER_NET_FAMILY_UNIX
                                 ? "unix " + std::string(&e.path[KB_MSG_NAME], strnlen(&e.path[KB_MSG_NAME], KB_PATH - KB_MSG_NAME))
                                 : (protocol == 17 ? "udp " : protocol == 6 ? "tcp " : "ip ") +
                                       (family == 6 ? "[" + std::string(text) + "]" : std::string(text)) + ":" +
                                       std::to_string(e.port);
    std::string formatted = std::string(e.rights == KFILTER_RIGHT_RECEIVE ? "receive " : "send ") + peer +
                            " socket:[" + std::to_string((unsigned long long)e.inode) +
                            "] #" + std::to_string(e.index) + " len=" + std::to_string(e.size) +
                            Caller((pid_t)e.tgid, e.caller);
    if (e.shown != 0) {
        static const char hex[] = "0123456789abcdef";
        formatted += " data=";
        for (unsigned i = 0; i < e.shown && i < KB_MSG_SHOWN; i++) {
            unsigned char byte = (unsigned char)e.path[16 + i];
            formatted += hex[byte >> 4];
            formatted += hex[byte & 15];
        }
        if (e.size > e.shown) formatted += "...";
    }
    return KfWide(formatted);
}

std::wstring Address(const kb_event& e)
{
    const unsigned family = e.ppid >> 8;
    const unsigned protocol = e.ppid & 0xff;
    char text[INET6_ADDRSTRLEN] = "?";
    inet_ntop(family == 6 ? AF_INET6 : AF_INET, e.path, text, sizeof(text));
    // A RISK record's value is the right (as network.c logs it); the port travels apart.
    std::string formatted = std::string(protocol == 17 ? "udp " : protocol == 6 ? "tcp " : "ip ") +
                            (family == 6 ? "[" + std::string(text) + "]" : std::string(text)) + ":" +
                            std::to_string(e.action == KFilterActionRisk ? e.port : e.value);
    return KfWide(formatted);
}

int OnEvent(void*, void* data, size_t size)
{
    if (size < sizeof(kb_event)) return 0;
    const kb_event& e = *static_cast<const kb_event*>(data);
    switch (e.kind) {
    case KB_EV_DECISION: {
        std::wstring path = (e.flags & KFILTER_EVENT_FLAG_MESSAGE) != 0 ? Message(e)
                            : e.target == KFILTER_TARGET_NETWORK
                                ? Address(e)
                                : KfWide(std::string(e.path, strnlen(e.path, sizeof(e.path))));
        UNICODE_STRING name;
        name.Length = name.MaximumLength = (USHORT)(path.size() * sizeof(WCHAR) > 0xFFF0 ? 0xFFF0 : path.size() * sizeof(WCHAR));
        name.Buffer = (PWSTR)path.c_str();
        std::wstring image = KfWide(std::string(e.image, strnlen(e.image, sizeof(e.image))));
        KfLogBpfDecision(UlongToHandle(e.tgid), KfBpfPublicTarget(e.target), e.action, e.flags, e.status, e.value, e.rule_id,
                         path.empty() ? NULL : &name, image.c_str());
        break;
    }
    case KB_EV_PROTECT:
        KfProcessMirror((pid_t)e.tgid, true);
        ModulesWatch((pid_t)e.tgid);
        break;
    case KB_EV_EXIT:
        KfProcessMirror((pid_t)e.tgid, false);
        ModulesForget((pid_t)e.tgid);
        break;
    case KB_EV_MODULES:
        ModulesAsk((pid_t)e.tgid);
        break;
    case KB_EV_WMI:
        std::thread(WmiStopped, (pid_t)e.tgid, (pid_t)e.value).detach();
        break;
    default:
        break;
    }
    return 0;
}

int PrintLibbpf(enum libbpf_print_level level, const char* format, va_list args)
{
    if (level == LIBBPF_DEBUG) return 0;
    return vfprintf(stderr, format, args);
}

/* Every thread of Tgid, as pidfds (task storage is keyed by a pidfd). */
std::vector<int> ThreadFds(pid_t tgid)
{
    std::vector<int> fds;
    std::string directory = "/proc/" + std::to_string(tgid) + "/task";
    DIR* tasks = opendir(directory.c_str());
    if (tasks == nullptr) {
        int fd = (int)syscall(SYS_pidfd_open, tgid, 0);
        if (fd >= 0) fds.push_back(fd);
        return fds;
    }
    while (struct dirent* entry = readdir(tasks)) {
        if (entry->d_name[0] == '.') continue;
        pid_t tid = (pid_t)strtol(entry->d_name, nullptr, 10);
        int fd = (int)syscall(SYS_pidfd_open, tid, tid == tgid ? 0 : PIDFD_THREAD);
        if (fd >= 0) fds.push_back(fd);
    }
    closedir(tasks);
    return fds;
}

/* The Wine installs: those whose 64-bit ntdll.so speaks wineserver protocol 930, which kfilter.bpf.c decodes, and
 * whether there is another (KFILTER_STATUS_DEGRADED_WINE: its programs are named, their Wine requests not decided). */
struct WineInstalls {
    std::vector<std::string> decoded;
    bool undecoded = false;
};

WineInstalls FindWine()
{
    static const char* roots[] = {"/opt/wine-stable", "/opt/wine-staging", "/opt/wine-devel", "/usr/local"};
    WineInstalls installs;
    for (const char* root : roots) {
        std::string ntdll = std::string(root) + "/lib/wine/x86_64-unix/ntdll.so";
        FILE* file = fopen(ntdll.c_str(), "rb");
        if (file == nullptr) continue;
        std::string data;
        char buffer[1 << 16];
        size_t read;
        while ((read = fread(buffer, 1, sizeof(buffer), file)) > 0) data.append(buffer, read);
        fclose(file);
        const unsigned protocol = KfWineProtocol(data);
        if (protocol == KB_WINE_PROTOCOL && installs.decoded.size() < KB_WINE_DIRS) {
            installs.decoded.push_back(std::string(root) + "/");
            continue;
        }
        installs.undecoded = true;
        fprintf(stderr, "kfilterd: %s speaks wineserver protocol %u, not %u: its programs' registry, handle, peer, "
                        "/system/wine and NT object requests are not decided (degraded: wine)\n",
                root, protocol, (unsigned)KB_WINE_PROTOCOL);
    }
    return installs;
}

/* The decoded Wine installs, in the layer's config from kfilterd's start (not only with a policy):
 * a program started before the first policy has its key and object handles named all along. */
void SetWineDirs(kb_cfg& cfg, const std::vector<std::string>& dirs)
{
    cfg.wine_dir_count = 0;
    for (const std::string& dir : dirs) {
        if (cfg.wine_dir_count >= KB_WINE_DIRS || dir.size() >= KB_WINE_DIR) continue;
        memcpy(cfg.wine_dirs[cfg.wine_dir_count], dir.data(), dir.size());
        cfg.wine_dir_len[cfg.wine_dir_count++] = (__u32)dir.size();
    }
}

const WineInstalls& Wine()
{
    static const WineInstalls installs = FindWine();
    return installs;
}

const std::vector<std::string>& WineDirs()
{
    return Wine().decoded;
}

std::string Lower(std::string text)
{
    for (char& c : text) {
        if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
    }
    return text;
}

/* Records a running Wine process's Windows image in kb_procs, so the kernel does not name
 * (and so admit or refuse) a program that was already running before the layer started:
 * restarting kfilterd in block mode must not kill a running client. Such a program stays
 * unprotected unless kfilterd protects it (track/launch). */
void NameRunningWine(pid_t pid)
{
    std::string image = KfNarrow(KfProgramImage(pid));
    if (image.empty() || KfWineLoader(KfWide(image)) || image.size() >= KB_PROG) return;
    if (image[0] == '/') return;   // argv[0] not rewritten yet: the kernel names it
    kb_proc proc{};
    memcpy(proc.image, image.data(), image.size());
    proc.ilen = (__u32)image.size();
    size_t separator = image.find_last_of('\\');
    proc.ibase = separator == std::string::npos ? 0 : (__u32)(separator + 1);
    proc.device_host = Lower(image.substr(proc.ibase)) == "winedevice.exe";
    __u32 key = (__u32)pid;
    bpf_map_update_elem(gLayer.procs, &key, &proc, BPF_NOEXIST);
}

/* Wine processes and wineservers that were running before the layer: the exec hook did not
 * see them start. */
void MarkWine()
{
    DIR* proc = opendir("/proc");
    if (proc == nullptr) return;
    while (struct dirent* entry = readdir(proc)) {
        pid_t pid = (pid_t)strtol(entry->d_name, nullptr, 10);
        if (pid <= 0) continue;
        std::wstring exe = KfExePath(pid);
        size_t slash = exe.find_last_of(L'/');
        std::wstring name = slash == std::wstring::npos ? exe : exe.substr(slash + 1);
        __u32 role = name == L"wineserver" ? KB_ROLE_WINESERVER : KfWineLoader(exe) ? KB_ROLE_WINE : KB_ROLE_NONE;
        if (role == KB_ROLE_NONE) continue;
        if (role == KB_ROLE_WINE) NameRunningWine(pid);
        int threads = 0, marked = 0;
        for (int fd : ThreadFds(pid)) {
            kb_task value{};
            if (bpf_map_lookup_elem(gLayer.tasks, &fd, &value) != 0) value = kb_task{};
            value.role = role;
            if (role == KB_ROLE_WINESERVER) value.guarded = 0;
            threads++;
            if (bpf_map_update_elem(gLayer.tasks, &fd, &value, BPF_ANY) == 0) marked++;
            close(fd);
        }
        // Wine programs already running: their requests are decoded from here on (see the tuning report).
        fprintf(stderr, "kfilterd: running %s %d (%s): %d of %d thread(s) marked\n",
                role == KB_ROLE_WINESERVER ? "wineserver" : "Wine program", (int)pid, KfNarrow(exe).c_str(), marked, threads);
    }
    closedir(proc);
}

/* A taken-over layer's protected processes: their KB_EV_PROTECT went to the previous
 * kfilterd, so this one's process mirror and module tables (module= rules) start them now. */
void AdoptProtected()
{
    DIR* proc = opendir("/proc");
    if (proc == nullptr) return;
    while (struct dirent* entry = readdir(proc)) {
        pid_t pid = (pid_t)strtol(entry->d_name, nullptr, 10);
        if (pid <= 0) continue;
        int pidfd = (int)syscall(SYS_pidfd_open, pid, 0);
        if (pidfd < 0) continue;
        kb_task task{};
        kb_proc process{};
        __u32 key = (__u32)pid;
        bool guarded = bpf_map_lookup_elem(gLayer.tasks, &pidfd, &task) == 0 &&
                       (task.guarded || (task.role == KB_ROLE_WINE &&
                                         bpf_map_lookup_elem(gLayer.procs, &key, &process) == 0 && process.guarded));
        close(pidfd);
        if (!guarded) continue;
        KfProcessMirror(pid, true);
        ModulesWatch(pid);
    }
    closedir(proc);
}

void Close()
{
    if (gLayer.ring != nullptr) ring_buffer__free(gLayer.ring);
    gLayer.ring = nullptr;
    for (bpf_link* link : gLayer.links) bpf_link__destroy(link);
    gLayer.links.clear();
    gLayer.names.clear();
    if (gLayer.object != nullptr) bpf_object__close(gLayer.object);
    gLayer.object = nullptr;
}

/* ---- fail closed: pins in bpffs keep a block-mode layer enforcing after kfilterd exits ---- */

const char kPinRoot[] = "/sys/fs/bpf/kfilter";

std::string PinPath(const char* kind, const std::string& name)
{
    return std::string(kPinRoot) + "/" + kind + "/" + name;
}

/* Every map but the object's own data sections, which another build must not inherit. */
bool Pinnable(const bpf_map* map)
{
    return !bpf_map__is_internal(map);
}

/* Removes the pins under kPinRoot/Kind not named in Keep (another kfilterd's, another build's), but those whose name
 * starts with Kept. */
void RemovePins(const char* kind, const std::set<std::string>& keep, const char* kept = nullptr)
{
    std::string directory = std::string(kPinRoot) + "/" + kind;
    DIR* pins = opendir(directory.c_str());
    if (pins == nullptr) return;
    while (struct dirent* entry = readdir(pins)) {
        if (entry->d_name[0] == '.' || keep.count(entry->d_name) != 0) continue;
        if (kept != nullptr && strncmp(entry->d_name, kept, strlen(kept)) == 0) continue;
        unlink((directory + "/" + entry->d_name).c_str());
    }
    closedir(pins);
}

/* The maps' fds, and the rule set in force (a taken-over layer's). False when one is missing. */
bool LayerMaps()
{
    gLayer.config = MapFd("kb_config");
    for (int set = 0; set < 2; set++) {
        const std::string b = set != 0 ? "_b" : "";
        gLayer.rules[set] = MapFd(("kb_rules" + b).c_str());
        gLayer.literal[set] = MapFd(("kb_literal" + b).c_str());
        gLayer.globs[set] = MapFd(("kb_globs" + b).c_str());
        gLayer.net[set] = MapFd(("kb_netrules" + b).c_str());
        gLayer.used[set] = MapFd(("kb_used" + b).c_str());
        gLayer.phase[set] = MapFd(("kb_phase" + b).c_str());
    }
    gLayer.live = MapFd("kb_live");
    gLayer.ruleSets = MapFd("kb_rule_sets");
    gLayer.launch = MapFd("kb_launch_pass");
    gLayer.tasks = MapFd("kb_tasks");
    gLayer.drops = MapFd("kb_drops");
    gLayer.procs = MapFd("kb_procs");
    gLayer.blocked = MapFd("kb_blocked");
    gLayer.mods = MapFd("kb_mods");
    gLayer.ranges = MapFd("kb_ranges");
    gLayer.bases = MapFd("kb_bases");
    gLayer.modseq = MapFd("kb_modseq");
    gLayer.wnamed = MapFd("kb_wnamed");
    gLayer.unixNames = MapFd("kb_unix_names");
    const __u32 zero = 0;
    __u32 live = 0;
    gLayer.set = bpf_map_lookup_elem(gLayer.live, &zero, &live) == 0 && live == 1 ? 1 : 0;
    for (int set = 0; set < 2; set++) {
        if (gLayer.rules[set] < 0 || gLayer.literal[set] < 0 || gLayer.globs[set] < 0 || gLayer.net[set] < 0 ||
            gLayer.used[set] < 0 || gLayer.phase[set] < 0) return false;
    }
    return gLayer.config >= 0 && gLayer.live >= 0 && gLayer.ruleSets >= 0 && gLayer.ranges >= 0 && gLayer.bases >= 0 &&
           gLayer.modseq >= 0 && gLayer.wnamed >= 0 && gLayer.unixNames >= 0;
}

/* Restores every count of rule set Set and closes every phase but the first; false when a write failed. */
bool ResetCounts(__u32 set)
{
    const __u32 zero = 0;
    bool written = true;
    for (__u32 slot = 0; slot < KB_RULES + KB_NET; slot++) {
        written &= bpf_map_update_elem(gLayer.used[set], &slot, &zero, BPF_ANY) == 0;
    }
    kb_state state{1, 0};
    return bpf_map_update_elem(gLayer.phase[set], &zero, &state, BPF_ANY) == 0 && written;
}

/* A layer pinned before the rule sets keeps its policy in set 0, its wildcard and network rules bounded by cfg's
 * counts only: these programs stop at an end mark, so one is written after each list. */
void EndMarks()
{
    kb_cfg old{};
    const __u32 zero = 0, end = KB_GLOB_END;
    const kb_net none{};
    if (bpf_map_lookup_elem(gLayer.config, &zero, &old) != 0) return;
    if (old.glob_count < KB_GLOBS) bpf_map_update_elem(gLayer.globs[0], &old.glob_count, &end, BPF_ANY);
    if (old.net_count < KB_NET) bpf_map_update_elem(gLayer.net[0], &old.net_count, &none, BPF_ANY);
}

const char kReachProgram[] = "kb_wine_reach";   /* kb_file_permission's tail call (kb_reach) */

/* Opens and loads the object; Reuse: on the maps a previous kfilterd pinned (its protected
 * tasks, Wine state and policy carry over). */
bool Load(bool reuse)
{
    gLayer.object = bpf_object__open_mem(kKfilterBpfObject, sizeof(kKfilterBpfObject), nullptr);
    if (gLayer.object == nullptr) {
        perror("kfilterd: bpf_object__open_mem");
        return false;
    }
    bpf_map* map = nullptr;
    bpf_object__for_each_map(map, gLayer.object) {
        if (reuse && Pinnable(map)) bpf_map__set_pin_path(map, PinPath("maps", bpf_map__name(map)).c_str());
    }
    SyscallTargets();
    if (int error = bpf_object__load(gLayer.object); error != 0) {
        fprintf(stderr, "kfilterd: BPF layer did not load%s (%s)\n", reuse ? " on the pinned maps" : "",
                strerror(-error));
        Close();
        return false;
    }
    // kb_file_permission's tail call (kb_reach): what a Wine request reaches past its own decision.
    const __u32 zero = 0;
    const int reach = bpf_program__fd(bpf_object__find_program_by_name(gLayer.object, kReachProgram));
    if (reach < 0 || bpf_map_update_elem(bpf_object__find_map_fd_by_name(gLayer.object, "kb_reach"), &zero, &reach, BPF_ANY) != 0) {
        fprintf(stderr, "kfilterd: BPF layer did not load (kb_reach: %s)\n", strerror(errno));
        Close();
        return false;
    }
    return true;
}

/* Generic netlink families' names by id into kb_genl, from the controller (CTRL_CMD_GETFAMILY dump), for
 * /net/netlink/generic/<name>/<command>. shortcut: read at each policy load; a family registered after it (a module
 * loaded later) is named by its id until the next load. */
void GenlFamilies()
{
    const int map = MapFd("kb_genl");
    const int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
    if (fd < 0 || map < 0) {
        if (fd >= 0) close(fd);
        return;
    }
    struct {
        nlmsghdr header;
        genlmsghdr genl;
    } request{};
    request.header.nlmsg_len = sizeof(request);
    request.header.nlmsg_type = GENL_ID_CTRL;
    request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    request.genl.cmd = CTRL_CMD_GETFAMILY;
    request.genl.version = 1;
    std::vector<char> buffer(1 << 16);
    for (bool done = send(fd, &request, sizeof(request), 0) < 0; !done;) {
        int got = (int)recv(fd, buffer.data(), buffer.size(), 0);
        if (got <= 0) break;
        for (nlmsghdr* message = (nlmsghdr*)buffer.data(); NLMSG_OK(message, got); message = NLMSG_NEXT(message, got)) {
            if (message->nlmsg_type == NLMSG_DONE || message->nlmsg_type == NLMSG_ERROR) {
                done = true;
                break;
            }
            __u32 id = 0;
            kb_genl_name name{};
            int left = (int)message->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);
            for (nlattr* attribute = (nlattr*)((char*)NLMSG_DATA(message) + GENL_HDRLEN);
                 left >= (int)sizeof(nlattr) && attribute->nla_len >= sizeof(nlattr) && attribute->nla_len <= left;
                 left -= NLA_ALIGN(attribute->nla_len), attribute = (nlattr*)((char*)attribute + NLA_ALIGN(attribute->nla_len))) {
                const char* payload = (const char*)attribute + NLA_HDRLEN;
                if ((attribute->nla_type & NLA_TYPE_MASK) == CTRL_ATTR_FAMILY_ID) id = *(const __u16*)payload;
                if ((attribute->nla_type & NLA_TYPE_MASK) == CTRL_ATTR_FAMILY_NAME)
                    strncpy(name.name, payload, std::min<size_t>(sizeof(name.name) - 1, attribute->nla_len - NLA_HDRLEN));
            }
            if (id != 0 && name.name[0] != 0) bpf_map_update_elem(map, &id, &name, BPF_ANY);
        }
    }
    close(fd);
}

/* A peer rule naming a signal or PTRACE_MODE_READ mode inside the family (value=signal:0x..., ptrace:0x...), which alone
 * meets those decisions (KB_TARGET_SIGNAL). */
bool NamesReach(const kb_rule& rule, const std::string& value)
{
    const std::string lower = Lower(value);
    return rule.targets == KFILTER_TARGET_PEER && rule.vlen != 0 &&
           (lower.rfind("signal:", 0) == 0 || lower.rfind("ptrace:", 0) == 0);
}

/* The ABI 11 decisions a rule (its kernel copy, path, value and the bytes before its first '*') names: a space whose
 * root its fixed head reaches, or a right only rules naming it hold (kb_gates). */
__u32 RuleGates(const kb_rule& rule, const std::string& path, const std::string& value, size_t head)
{
    auto names = [&](const char* space, __u32 target) {
        const size_t n = strlen(space);
        // A system rule's value= (KB_TARGET_SYSTEM_VALUE) still names its space.
        return (rule.targets & ~KB_TARGET_SYSTEM_VALUE) == target && head >= n && path.compare(0, n, space) == 0;
    };
    const __u32 files = KFILTER_TARGET_FILE | KFILTER_TARGET_DIR, system = KFILTER_TARGET_SYSTEM;
    __u32 gates = 0;
    if ((rule.targets & files) != 0 && (rule.rights & KFILTER_RIGHT_LOCK) != 0) gates |= KB_GATE_LOCK;
    if ((rule.targets & KFILTER_TARGET_DIR) != 0 && (rule.rights & KFILTER_RIGHT_CHDIR) != 0) gates |= KB_GATE_CHDIR;
    if ((rule.targets & files) != 0 && (rule.rights & KFILTER_RIGHT_TOUCH) != 0) gates |= KB_GATE_TOUCH;
    if (rule.targets == KFILTER_TARGET_PIPE && (rule.rights & KFILTER_RIGHT_LISTEN) != 0) gates |= KB_GATE_LISTEN;
    if (NamesReach(rule, value)) gates |= KB_GATE_PEER;
    static const struct { const char* space; __u32 gate; } spaces[] = {
        {"/system/fcntl", KB_GATE_FCNTL}, {"/system/socket/shutdown", KB_GATE_SHUTDOWN},
        {"/system/socketpair", KB_GATE_SOCKETPAIR}, {"/system/rlimit", KB_GATE_RLIMIT}, {"/system/task", KB_GATE_TASK},
        {"/system/cred", KB_GATE_CRED}, {"/system/capability", KB_GATE_CAPABILITY},
        {"/system/namespace", KB_GATE_NAMESPACE}, {"/system/memory/low", KB_GATE_LOW},
        {"/system/ipc/create", KB_GATE_IPC}, {"/system/fork", KB_GATE_FORK}, {"/system/ptrace", KB_GATE_PTRACE},
        {"/system/kernel", KB_GATE_KERNEL}, {"/system/prctl", KB_GATE_PRCTL}, {"/system/statfs", KB_GATE_STATFS},
    };
    for (const auto& entry : spaces) {
        if (names(entry.space, system)) gates |= entry.gate;
    }
    if (names("/net/ioctl/", KFILTER_TARGET_DEVICE) && head > 11) gates |= KB_GATE_SOCKET_IOCTL;
    if (names("/net/netlink/", KFILTER_TARGET_DEVICE)) {
        // A family past route's and sock_diag's queries, or a message type under one (/net/netlink/<family>/<type>).
        const std::string family = path.substr(13, std::min(head, path.find('/', 13)) - 13);
        if (!family.empty() && (path.find('/', 13) < head || (family != "route" && family != "sock_diag")))
            gates |= KB_GATE_NETLINK;
    }
    if (rule.targets == KFILTER_TARGET_DEVICE && value.find(':') != std::string::npos) gates |= KB_GATE_ARGUMENT;
    return gates;
}

/* Programs whose failure to attach leaves only these KFILTER_STATUS_DEGRADED_* classes
 * undecided; any other program is the layer itself (protection, Wine, exec, opens). */
uint32_t OptionalClasses(const std::string& program)
{
    const uint32_t files = KFILTER_STATUS_DEGRADED_FILES, memory = KFILTER_STATUS_DEGRADED_MEMORY,
                   network = KFILTER_STATUS_DEGRADED_NETWORK, message = KFILTER_STATUS_DEGRADED_MESSAGE,
                   registry = KFILTER_STATUS_DEGRADED_REGISTRY, query = KFILTER_STATUS_DEGRADED_QUERY,
                   system = KFILTER_STATUS_DEGRADED_SYSTEM;
    static const std::map<std::string, uint32_t> classes = {
        {"kb_file_receive", files}, {"kb_path_unlink", files}, {"kb_path_rmdir", files}, {"kb_path_mkdir", files},
        {"kb_path_mknod", files}, {"kb_path_symlink", files}, {"kb_path_link", files}, {"kb_path_rename", files},
        {"kb_path_truncate", files}, {"kb_file_truncate", files}, {"kb_path_chmod", files}, {"kb_path_chown", files},
        {"kb_inode_setxattr", files}, {"kb_inode_removexattr", files}, {"kb_inode_setattr", files},
        {"kb_mmap_file", files}, {"kb_file_mprotect", files},
        // Metadata queries, watches and the statfs log: block-files without them is still decided at the open.
        {"kb_inode_getattr", query}, {"kb_inode_access", query}, {"kb_inode_readlink", query},
        {"kb_inode_getxattr", query}, {"kb_inode_listxattr", query}, {"kb_path_notify", query}, {"kb_sb_statfs", query},
        {"kb_file_ioctl", KFILTER_STATUS_DEGRADED_DEVICE | KFILTER_STATUS_DEGRADED_RAW_DISK |
                              KFILTER_STATUS_DEGRADED_VOLUME | KFILTER_STATUS_DEGRADED_ADAPTER},
        {"kb_file_ioctl_compat", KFILTER_STATUS_DEGRADED_DEVICE | KFILTER_STATUS_DEGRADED_RAW_DISK |
                                     KFILTER_STATUS_DEGRADED_VOLUME | KFILTER_STATUS_DEGRADED_ADAPTER},
        {"kb_ptrace", memory}, {"kb_task_kill", memory}, {"kb_task_prctl", memory}, {"kb_kernel_read_file", memory},
        {"kb_bpf", memory}, {"kb_perf_event_open", memory},
        // splice into a Wine request pipe: kernels without error injection cannot refuse it.
        {"kb_vmsplice", memory | registry}, {"kb_splice", memory | registry}, {"kb_tee", memory | registry},
        {"kb_vmsplice32", memory | registry}, {"kb_splice32", memory | registry}, {"kb_tee32", memory | registry},
        // Faulting Wine's request data in before it is decoded: without it a name can fail at random.
        {"kb_prefault_writev", registry}, {"kb_prefault_writev32", registry},
        {"kb_socket_post_create", network}, {"kb_socket_connect", network}, {"kb_socket_sendmsg", network | message},
        {"kb_socket_recvmsg", message}, {"kb_socket_bind", network}, {"kb_socket_listen", network},
        {"kb_socket_accept", network}, {"kb_inet_conn_request", network}, {"kb_sock_rcv_skb", network},
        {"kb_netlink_send", KFILTER_STATUS_DEGRADED_ADAPTER},
        // Rule-only system decisions (/system/...), the ioctls io_uring passes through, pipe creators.
        {"kb_uname", system}, {"kb_uname32", system}, {"kb_olduname32", system}, {"kb_oldolduname32", system},
        {"kb_sysinfo", system}, {"kb_sysinfo32", system}, {"kb_arch_prctl", system}, {"kb_arch_prctl32", system},
        {"kb_socket_create", system}, {"kb_anon_create", system}, {"kb_key_permission", system},
        {"kb_ipc_permission", system}, {"kb_uring_cmd", KFILTER_STATUS_DEGRADED_DEVICE}, {"kb_pipe_alloc", files},
        {"kb_task_setscheduler", system}, {"kb_task_setnice", system}, {"kb_task_setioprio", system},
        {"kb_socket_getsockopt", system}, {"kb_socket_setsockopt", system}, {"kb_socket_getsockname", system},
        {"kb_socket_getpeername", system}, {"kb_sb_mount", system}, {"kb_sb_umount", system},
        {"kb_sb_pivotroot", system}, {"kb_move_mount", system}, {"kb_syslog", system}, {"kb_settime", system},
    };
    auto found = classes.find(program);
    return found == classes.end() ? 0 : found->second;
}

/* OptionalGates' kinds beside kb_gates' bits: block-process-signals' SIGIO decisions, and data memory (KB_MEMORY_DATA). */
const uint32_t kGateSignals = 1u << 30, kGateData = 1u << 31;

/* ABI 11's programs, decided only while a rule names their kind (kb_gates): one that does not attach takes away those
 * kinds alone, so a policy naming none of them loads as before and block mode is refused for one that names one. */
uint32_t OptionalGates(const std::string& program)
{
    static const std::map<std::string, uint32_t> gates = {
        {"kb_file_lock", KB_GATE_LOCK}, {"kb_file_fcntl", KB_GATE_FCNTL | KB_GATE_PEER | kGateSignals},
        {"kb_file_set_fowner", KB_GATE_PEER | kGateSignals}, {"kb_file_send_sigiotask", KB_GATE_PEER | kGateSignals},
        {"kb_socket_shutdown", KB_GATE_SHUTDOWN}, {"kb_socket_socketpair", KB_GATE_SOCKETPAIR},
        {"kb_unix_stream_connect", KB_GATE_LISTEN}, {"kb_unix_may_send", KB_GATE_LISTEN},
        {"kb_task_setrlimit", KB_GATE_RLIMIT}, {"kb_task_prlimit", KB_GATE_RLIMIT}, {"kb_task_getscheduler", KB_GATE_TASK},
        {"kb_task_getioprio", KB_GATE_TASK}, {"kb_task_getpgid", KB_GATE_TASK}, {"kb_task_getsid", KB_GATE_TASK},
        {"kb_task_setpgid", KB_GATE_TASK}, {"kb_task_fix_setuid", KB_GATE_CRED}, {"kb_task_fix_setgid", KB_GATE_CRED},
        {"kb_task_fix_setgroups", KB_GATE_CRED}, {"kb_capset", KB_GATE_CRED}, {"kb_capget", KB_GATE_CRED},
        {"kb_capable", KB_GATE_CAPABILITY}, {"kb_userns_create", KB_GATE_NAMESPACE}, {"kb_shm_alloc", KB_GATE_IPC},
        {"kb_msg_queue_alloc", KB_GATE_IPC}, {"kb_sem_alloc", KB_GATE_IPC}, {"kb_ptrace_traceme", KB_GATE_PTRACE},
        {"kb_kernel_module_request", KB_GATE_KERNEL}, {"kb_kernel_load_data", KB_GATE_KERNEL},
        {"kb_mmap_addr", KB_GATE_LOW | kGateData},
    };
    auto found = gates.find(program);
    return found == gates.end() ? 0 : found->second;
}

/* The registered layer a degraded class takes away, so block mode with it is refused. */
uint32_t RegisteredLayers(uint32_t degraded)
{
    uint32_t layers = KFILTER_REG_BPF | KFILTER_REG_MINIFILTER | KFILTER_REG_PROCESS | KFILTER_REG_DISK |
                      KFILTER_REG_DEVICE | KFILTER_REG_NETWORK | KFILTER_REG_OBJECT | KFILTER_REG_REGISTRY |
                      KFILTER_REG_NSI;
    static const struct { uint32_t degraded, layer; } lost[] = {
        {KFILTER_STATUS_DEGRADED_FILES, KFILTER_REG_MINIFILTER}, {KFILTER_STATUS_DEGRADED_MEMORY, KFILTER_REG_OBJECT},
        {KFILTER_STATUS_DEGRADED_NETWORK, KFILTER_REG_NETWORK}, {KFILTER_STATUS_DEGRADED_ADAPTER, KFILTER_REG_NSI},
        {KFILTER_STATUS_DEGRADED_DEVICE, KFILTER_REG_DEVICE}, {KFILTER_STATUS_DEGRADED_RAW_DISK, KFILTER_REG_DISK},
    };
    for (const auto& entry : lost) {
        if ((degraded & entry.degraded) != 0) layers &= ~entry.layer;
    }
    return layers;
}

/* A clean exit leaves no stale daemon pid in a pinned layer (it is exempt from ptrace decisions)
 * and no program stopped for WMI probing. */
void ForgetDaemon()
{
    if (!gActive) return;
    kb_cfg config{};
    const __u32 zero = 0;
    if (bpf_map_lookup_elem(gLayer.config, &zero, &config) != 0) return;
    config.daemon_tgid = 0;
    bpf_map_update_elem(gLayer.config, &zero, &config, BPF_ANY);
    WmiResumeAll();
}

/* The process holding socket:[Inode] is protected (in the kernel's own state). */
bool ProtectedSocket(uint64_t inode)
{
    const std::string wanted = "socket:[" + std::to_string((unsigned long long)inode) + "]";
    DIR* proc = opendir("/proc");
    if (proc == nullptr) return false;
    bool found = false;
    while (!found) {
        struct dirent* entry = readdir(proc);
        if (entry == nullptr) break;
        pid_t pid = (pid_t)strtol(entry->d_name, nullptr, 10);
        if (pid <= 0) continue;
        std::string directory = "/proc/" + std::to_string(pid) + "/fd";
        DIR* fds = opendir(directory.c_str());
        if (fds == nullptr) continue;
        bool holds = false;
        while (struct dirent* fd = readdir(fds)) {
            char target[64];
            ssize_t length = readlink((directory + "/" + fd->d_name).c_str(), target, sizeof(target) - 1);
            if (length > 0 && wanted.compare(0, std::string::npos, target, (size_t)length) == 0) {
                holds = true;
                break;
            }
        }
        closedir(fds);
        if (!holds) continue;
        int pidfd = (int)syscall(SYS_pidfd_open, pid, 0);
        kb_task task{};
        kb_proc process{};
        __u32 key = (__u32)pid;
        if (pidfd >= 0 && bpf_map_lookup_elem(gLayer.tasks, &pidfd, &task) == 0) {
            found = task.guarded || (task.role == KB_ROLE_WINE &&
                                     bpf_map_lookup_elem(gLayer.procs, &key, &process) == 0 && process.guarded);
        }
        if (pidfd >= 0) close(pidfd);
    }
    closedir(proc);
    return found;
}

} // namespace

/* kfilterd.cpp declares these weak (KeepAcrossExit, GET_STATUS). */
bool KfBpfPin();
void KfBpfUnpin();
uint32_t KfBpfDegraded();

/*
 * Loads and attaches every program. The programs that make the layer (protection, Wine,
 * exec, opens) are all or nothing, so a half-attached layer never claims enforcement; any
 * other program that does not attach leaves its decision classes degraded (KfBpfDegraded)
 * and their layers unregistered, so block mode with them is refused. A layer a previous
 * kfilterd pinned (block mode) is taken over: its maps, so protection and policy carry on,
 * and its links are replaced by this build's once they are attached.
 */
bool KfBpfStart(uint32_t& registered)
{
    libbpf_set_print(PrintLibbpf);
    bool resume = access(PinPath("maps", "kb_config").c_str(), F_OK) == 0;
    const bool marked = access(PinPath("maps", "kb_live").c_str(), F_OK) == 0;   /* pinned with the rule sets */
    if (!Load(resume)) {
        if (!resume || !Load(false)) {
            fprintf(stderr, "kfilterd: using fanotify and nftables\n");
            return false;
        }
        // Its links keep enforcing on their own maps until a policy replaces the pins or
        // `kfilterctl off`/`stop` removes them.
        fprintf(stderr, "kfilterd: the pinned BPF layer in %s is another build's; it stays until replaced\n", kPinRoot);
        resume = false;
    }
    if (!LayerMaps()) {
        fprintf(stderr, "kfilterd: BPF layer maps missing; using fanotify and nftables\n");
        Close();
        return false;
    }
    if (resume && !marked) EndMarks();
    SyscallTails();
    bpf_program* program = nullptr;
    bpf_object__for_each_program(program, gLayer.object) {
        const std::string name = bpf_program__name(program);
        if (bpf_program__type(program) == BPF_PROG_TYPE_KPROBE) continue;   /* uprobes: per policy and program */
        if (name == kReachProgram) continue;   /* a tail call's target, not attached */
        if (name.rfind("kb_s_", 0) == 0 || name.rfind("kb_syscall", 0) == 0) continue;   /* syscalls: per policy (SyscallApply) */
        bpf_link* link = bpf_program__attach(program);
        if (link == nullptr && OptionalGates(name) != 0) {
            fprintf(stderr, "kfilterd: BPF program %s did not attach (%s); block mode is refused for rules naming its "
                            "decisions\n", name.c_str(), strerror(errno));
            gLayer.gatesLost |= OptionalGates(name);
            continue;
        }
        if (link == nullptr) {
            const int error = errno;
            const uint32_t classes = OptionalClasses(name);
            fprintf(stderr, "kfilterd: BPF program %s did not attach (%s)%s\n", name.c_str(), strerror(error),
                    classes != 0 ? "; its decisions are degraded" : "; using fanotify and nftables");
            if (classes == 0) {
                Close();
                return false;
            }
            gLayer.degraded |= classes;
            continue;
        }
        gLayer.links.push_back(link);
        gLayer.names.push_back(name);
    }
    gLayer.ring = ring_buffer__new(MapFd("kb_events"), OnEvent, nullptr, nullptr);
    if (gLayer.ring == nullptr) {
        perror("kfilterd: ring_buffer__new");
        Close();
        return false;
    }
    kb_cfg config{};
    const __u32 zero = 0;
    // A taken-over layer keeps deciding by its policy until kfilterd adopts or replaces it.
    if (resume) bpf_map_lookup_elem(gLayer.config, &zero, &config);
    config.daemon_tgid = (__u32)getpid();
    SetWineDirs(config, WineDirs());
    bpf_map_update_elem(gLayer.config, &zero, &config, BPF_ANY);
    gActive = true;
    atexit(ForgetDaemon);
    std::thread([] {
        for (;;) ring_buffer__poll(gLayer.ring, 1000);
    }).detach();
    std::thread(ModulesWorker).detach();
    /* The kernel layer covers what fanotify, the proc connector and nftables did, and the
     * process-memory (object) layer they could not. */
    registered |= RegisteredLayers(gLayer.degraded);
    MarkWine();
    if (resume) AdoptProtected();
    if (resume) WmiResumeAll();
    fprintf(stderr, "kfilterd: BPF layer attached (%zu programs)\n", gLayer.links.size());
    if (gLayer.degraded != 0) fprintf(stderr, "kfilterd: BPF layer degraded 0x%x\n", gLayer.degraded);
    // Replace the previous kfilterd's links now: both sets attached would decide twice.
    if (resume && KfBpfPin()) fprintf(stderr, "kfilterd: took over the pinned BPF layer in %s\n", kPinRoot);
    return true;
}

/* The BPF test bench (filter/tests/linux_bpf_bench.cpp): Object, a bench build it loaded with nothing attached and
 * no map pinned, takes the layer's place, so KfBpfApply compiles policies into its maps as kfilterd does; Registered
 * gains the layers an attached layer would register (KfBpfStart). */
bool KfBpfBench(bpf_object* object, uint32_t& registered)
{
    gBenchLayer = true;
    gLayer.object = object;
    gActive = LayerMaps();
    if (gActive) registered |= RegisteredLayers(gLayer.degraded);
    return gActive;
}

/* The bench: the module pattern list's generation, which a kb_bases entry carries to be current for addr= rules. */
uint32_t KfBpfModuleGeneration()
{
    std::lock_guard<std::mutex> guard(gModules.lock);
    return gModules.gen;
}

/* The bench: Pid's module tables read now, as ModulesWorker reads a watched program's (kb_modseq from 0). */
void KfBpfModulesRead(pid_t pid)
{
    {
        std::lock_guard<std::mutex> guard(gModules.lock);
        gModules.code[pid];
    }
    const __u32 key = (__u32)pid, zero = 0;
    bpf_map_update_elem(gLayer.modseq, &key, &zero, BPF_NOEXIST);
    RefreshModules(pid);
}

/* The bench: what KfBpfStart does to a layer pinned before the rule sets that it takes over. */
void KfBpfEndMarks()
{
    EndMarks();
}

/* Pins the attached links and their maps under /sys/fs/bpf/kfilter, replacing whatever an
 * earlier kfilterd pinned there; the layer then outlives kfilterd. Idempotent. */
bool KfBpfPin()
{
    if (!gActive) return false;
    for (const std::string& directory : {std::string(kPinRoot), std::string(kPinRoot) + "/maps",
                                         std::string(kPinRoot) + "/links"}) {
        if (mkdir(directory.c_str(), 0700) != 0 && errno != EEXIST) {
            fprintf(stderr, "kfilterd: %s: %s (is bpffs mounted on /sys/fs/bpf?)\n", directory.c_str(), strerror(errno));
            return false;
        }
    }
    std::set<std::string> maps, links;
    bpf_map* map = nullptr;
    bpf_object__for_each_map(map, gLayer.object) {
        if (!Pinnable(map)) continue;
        const std::string name = bpf_map__name(map);
        maps.insert(name);
        if (bpf_map__is_pinned(map)) continue;
        const std::string path = PinPath("maps", name);
        unlink(path.c_str());   // another build's map
        if (int error = bpf_map__pin(map, path.c_str()); error != 0) {
            fprintf(stderr, "kfilterd: cannot pin %s (%s)\n", path.c_str(), strerror(-error));
            return false;
        }
    }
    for (size_t index = 0; index < gLayer.links.size(); index++) {
        links.insert(gLayer.names[index]);
        if (bpf_link__pin_path(gLayer.links[index]) != nullptr) continue;
        const std::string path = PinPath("links", gLayer.names[index]);
        unlink(path.c_str());   // the previous kfilterd's link: ours is already attached
        if (int error = bpf_link__pin(gLayer.links[index], path.c_str()); error != 0) {
            fprintf(stderr, "kfilterd: cannot pin %s (%s)\n", path.c_str(), strerror(-error));
            return false;
        }
    }
    {
        std::lock_guard<std::mutex> guard(gUprobes.lock);
        for (size_t index = 0; index < gUprobes.win32k.size(); index++) {
            // shortcut: a kfilterd taking a pinned layer over drops these with the old links before its
        // adopted policy attaches its own, so win32k calls go undecided for that moment; keep pins
        // named kb_win32k_* until Win32kApply ran if that moment matters.
        const std::string name = "kb_win32k_" + std::to_string(index);
            links.insert(name);
            if (bpf_link__pin_path(gUprobes.win32k[index]) != nullptr) continue;
            const std::string path = PinPath("links", name);
            unlink(path.c_str());
            if (int error = bpf_link__pin(gUprobes.win32k[index], path.c_str()); error != 0) {
                fprintf(stderr, "kfilterd: cannot pin %s (%s)\n", path.c_str(), strerror(-error));
                return false;
            }
        }
    }
    bool syscallsApplied;
    {
        std::lock_guard<std::mutex> guard(gSyscalls.lock);
        syscallsApplied = gSyscalls.applied;
        for (const auto& [name, link] : gSyscalls.links) {
            links.insert(name);
            if (bpf_link__pin_path(link) != nullptr) continue;
            const std::string path = PinPath("links", name);
            unlink(path.c_str());
            if (int error = bpf_link__pin(link, path.c_str()); error != 0) {
                fprintf(stderr, "kfilterd: cannot pin %s (%s)\n", path.c_str(), strerror(-error));
                return false;
            }
        }
    }
    RemovePins("maps", maps);
    // A taken-over layer's syscall entry points stay until the adopted policy attaches this build's (SyscallApply): its
    // calls stay decided meanwhile (their stubs tail-call this build's decision programs), and by the policy still in
    // the maps if adoption fails.
    RemovePins("links", links, syscallsApplied ? nullptr : "kb_s_");
    return true;
}

/* Removes every pin (ours and any earlier kfilterd's): the layer ends with kfilterd again. */
void KfBpfUnpin()
{
    if (gLayer.object != nullptr) {
        for (bpf_link* link : gLayer.links) {
            if (bpf_link__pin_path(link) != nullptr) bpf_link__unpin(link);
        }
        std::lock_guard<std::mutex> guard(gUprobes.lock);
        for (bpf_link* link : gUprobes.win32k) {
            if (bpf_link__pin_path(link) != nullptr) bpf_link__unpin(link);
        }
        std::lock_guard<std::mutex> syscalls(gSyscalls.lock);
        for (const auto& entry : gSyscalls.links) {
            if (bpf_link__pin_path(entry.second) != nullptr) bpf_link__unpin(entry.second);
        }
        bpf_map* map = nullptr;
        bpf_object__for_each_map(map, gLayer.object) {
            if (bpf_map__is_pinned(map)) bpf_map__unpin(map, nullptr);
        }
    }
    RemovePins("links", {});
    RemovePins("maps", {});
    rmdir((std::string(kPinRoot) + "/links").c_str());
    rmdir((std::string(kPinRoot) + "/maps").c_str());
    rmdir(kPinRoot);
}

uint32_t KfBpfDegraded()
{
    if (!gActive) return 0;
    std::lock_guard<std::mutex> guard(gUprobes.lock);
    uint32_t wmi = 0;   /* a running program's wbemprox not probed while a rule names /system/wmi */
    for (const auto& program : gUprobes.queries) {
        for (const auto& probe : program.second) {
            if (gUprobes.wmi && probe.second == nullptr) wmi = KFILTER_STATUS_DEGRADED_SYSTEM;
        }
    }
    std::lock_guard<std::mutex> syscalls(gSyscalls.lock);
    return gLayer.degraded | gUprobes.win32kDegraded | wmi | gSyscalls.degraded |
           (Wine().undecoded ? KFILTER_STATUS_DEGRADED_WINE : 0);
}

bool KfBpfActive()
{
    return gActive;
}

/*
 * Compiles Config into the maps. A rule the kernel cannot hold (a path of 256 bytes or
 * more, more than KB_GLOBS wildcard rules, counting the literal rules past KB_PER_PATH on
 * one path, which go to the glob list) refuses block mode; audit mode loads without it and says so.
 */
NTSTATUS KfBpfApply(const KFILTER_CONFIG* config)
{
    if (!gActive) return STATUS_SUCCESS;
    std::lock_guard<std::mutex> guard(gLayer.lock);
    std::vector<kb_rule> rules;
    std::vector<__u32> globs;
    std::map<kb_key, kb_slots, KeyLess> literal;
    std::string problem;
    std::string root;
    const ULONG targets = KFILTER_TARGET_FILE | KFILTER_TARGET_DIR | KFILTER_TARGET_PIPE | KFILTER_TARGET_DEVICE |
                          KFILTER_TARGET_PROCESS | KFILTER_TARGET_HANDLE | KFILTER_TARGET_LAUNCH | KFILTER_TARGET_OPEN |
                          KFILTER_TARGET_REGISTRY | KFILTER_TARGET_VOLUME | KFILTER_TARGET_THREAD_HANDLE |
                          KFILTER_TARGET_THREAD_OPEN |   // thread handles: Wine's, decided from wineserver requests
                          KFILTER_TARGETS_RULE_ONLY;
    std::vector<std::wstring> patterns;   /* module= patterns of rules and message rules, addr= modules, each a bit */
    auto moduleBit = [&](const std::wstring& module) -> __u32 {
        auto found = std::find(patterns.begin(), patterns.end(), module);
        if (found != patterns.end()) return 1u << (found - patterns.begin());
        if (patterns.size() >= KB_MOD_BITS) {
            problem = "more than " + std::to_string(KB_MOD_BITS) + " module= patterns and addr= modules";
            return 0;
        }
        patterns.push_back(module);
        return 1u << (patterns.size() - 1);
    };
    // module= and message-rule patterns take the first slots and addr= modules the ones after them, so an addr= rule
    // never moves a module= rule's bit (the kernel's module tables keep the old bits until each is reread).
    for (ULONG index = 0; index < config->RuleCount; index++) {
        const KFILTER_RULE& source = config->Rules[index];
        if ((source.Targets & targets) != 0 && (source.Flags & KFILTER_RULE_MODULE) != 0)
            moduleBit(std::wstring(source.Value, KfLengthBounded(source.Value, KFILTER_MAX_VALUE)));
    }
    for (ULONG index = 0; index < config->NetworkRuleCount && index < KB_NET; index++) {
        std::wstring module(config->Network[index].Module, KfLengthBounded(config->Network[index].Module, KFILTER_MAX_IMAGE));
        if (!module.empty()) moduleBit(module);
    }
    std::vector<std::pair<__u32, kb_ranges>> addressRules;   /* addr= rules' ranges by rule slot */
    __u32 named = 0;   /* targets the loaded rules name */
    __u32 ioctlRules = 0;
    __u32 memoryRules = 0, mapRules = 0, selfRules = 0;
    __u32 wmiRules = 0;
    __u32 gates = 0;   /* kb_gates: ABI 11's decisions some rule names */
    for (ULONG index = 0; index < config->RuleCount; index++) {
        const KFILTER_RULE& source = config->Rules[index];
        if ((source.Targets & targets) == 0) continue;
        std::string path = KfNarrow(std::wstring(source.Path, KfLengthBounded(source.Path, KFILTER_MAX_NAME)));
        if (NamesSpace(source, L"/system/wmi")) wmiRules |= 1;   /* lowercased by kfilterctl, as kb_wmi_decide names */
        /* Its fixed text past /system/wmi/<class>/ (KB_ROOT there): a method decision it can meet. */
        if (NamesSpace(source, L"/system/wmi") && path.substr(0, path.find('*')).find('/', 12) != std::string::npos)
            wmiRules |= KB_WMI_METHOD_RULES;
        std::string value = KfNarrow(std::wstring(source.Value, KfLengthBounded(source.Value, KFILTER_MAX_VALUE)));
        std::string image = KfNarrow(std::wstring(source.Image, KfLengthBounded(source.Image, KFILTER_MAX_IMAGE)));
        // Linux paths; NT names for registry keys; Windows images (C:\... or \...) for the
        // programs handle/open/launch/peer/thread rules name; host names for dns rules (matched
        // without case, as NT names); Wine's NT objects (\??\..., \Device\...) for file and pipe
        // rules (kb_nt_object). A \Device\HarddiskVolume file path matches nothing.
        bool nt = (source.Targets & (KFILTER_TARGET_REGISTRY | KFILTER_TARGETS_OUTSIDE | KFILTER_TARGET_PEER |
                                     KFILTER_TARGET_THREAD_PEER | KFILTER_TARGET_THREAD)) != 0 ||
                  ((source.Targets & (KFILTER_TARGET_FILE | KFILTER_TARGET_PIPE | KFILTER_TARGET_VOLUME)) != 0 &&
                   path[0] == '\\');
        if (path.empty() || (path[0] != '/' && source.Targets != KFILTER_TARGET_DNS &&
                             !(nt && (path[0] == '\\' || (path.size() > 2 && path[1] == ':'))))) continue;
        if (path.size() >= KB_PATTERN || value.size() >= KB_VALUE || image.size() >= KB_IMAGE) {
            problem = "rule " + std::to_string(source.RuleId) + " path, value or image is too long for the kernel layer";
            continue;
        }
        kb_rule rule{};
        rule.action = source.Action;
        rule.targets = source.Targets;
        rule.rights = source.Rights;
        // A pipe deny or audit without rights= names every right but listen, which AF_UNIX servers' decisions ask for:
        // rules written before those decisions keep meeting what they met.
        if (rule.targets == KFILTER_TARGET_PIPE && rule.action != KFilterActionAllow && rule.rights == KFILTER_RIGHTS_ALL)
            rule.rights &= ~KFILTER_RIGHT_LISTEN;
        rule.ext = source.Extensions;
        rule.rule_id = source.RuleId;
        rule.account = source.Account;
        rule.count = source.Count;
        rule.flags = source.Flags;
        rule.risk = source.Risk[0] != L'\0';
        rule.plen = (__u32)path.size();
        rule.vlen = (__u32)value.size();
        if ((source.Flags & KFILTER_RULE_MODULE) != 0) {
            // Value is the module= pattern: the kernel matches its bit, not the value.
            rule.vlen = 0;
            rule.mbit = moduleBit(std::wstring(source.Value, KfLengthBounded(source.Value, KFILTER_MAX_VALUE)));
            if (rule.mbit == 0) continue;   // past the limit: left out (block mode is refused below)
        }
        kb_ranges ranges{};
        if ((source.Flags & KFILTER_RULE_ADDRESS) != 0) {
            // Value lists the modules of the addr= ranges, which go beside the rule (kb_ranges): one slot for them all.
            rule.vlen = 0;
            std::vector<std::wstring> modules;
            const std::wstring list(source.Value, KfLengthBounded(source.Value, KFILTER_MAX_VALUE));
            for (size_t start = 0; !list.empty() && start <= list.size();) {
                const size_t end = std::min(list.find(L',', start), list.size());
                modules.push_back(list.substr(start, end - start));
                start = end + 1;
            }
            bool fits = addressRules.size() < KB_ADDRESS_RULES;
            if (!fits) problem = "more than " + std::to_string(KB_ADDRESS_RULES) + " addr= rules";
            ranges.count = std::min<__u32>(source.AddressCount, KB_RANGES);
            for (__u32 index = 0; index < ranges.count; index++) {
                ranges.lo[index] = source.Address[index].Low;
                ranges.hi[index] = source.Address[index].High;
                const size_t module = source.AddressModule[index];
                if (module == 0 || module > modules.size()) continue;
                const __u32 bit = moduleBit(modules[module - 1]);
                if (bit == 0) fits = false;   // past the module pattern limit (block mode is refused below)
                else ranges.module[index] = (__u8)(__builtin_ctz(bit) + 1);
            }
            if (!fits) continue;
        }
        // The decisions only rules naming them meet (kfilter_bpf.h KB_TARGET_KEYED): a window, message or input decision
        // only a peer rule naming its pseudo-right by name (a rule without rights= or with a mask keeps meeting exactly
        // the accesses it met; one naming no other right meets no handle access); value= rules meet the decisions
        // value= alone names; a rule reaching into a keyed space meets keyed decisions, and an allow cannot vouch for a
        // window or thread kfilter cannot place (\@unknown-window, \@unknown-thread: not loaded). A peer rule naming a
        // signal or ptrace mode (value=signal:..., ptrace:...) meets only those decisions (KB_TARGET_SIGNAL, below), none
        // of these.
        const bool reach = NamesReach(rule, value);
        const bool valued = !reach && !value.empty() && (source.Flags & (KFILTER_RULE_MODULE | KFILTER_RULE_ADDRESS)) == 0;
        if (!reach && (source.Targets == KFILTER_TARGET_PEER || source.Targets == KFILTER_TARGET_THREAD_PEER)) {
            if ((source.Flags & KFILTER_RULE_PSEUDO) != 0)
                rule.targets = (source.Rights & ~KFILTER_ACCESS_PSEUDO) != 0 ? rule.targets | KB_TARGET_WINDOW : KB_TARGET_WINDOW;
            if (valued) rule.targets |= source.Targets == KFILTER_TARGET_PEER ? KB_TARGET_PEER_VALUE : KB_TARGET_THREAD_VALUE;
            if (source.Action == KFilterActionAllow && (Lower(path) == "\\@unknown-window" || Lower(path) == "\\@unknown-thread"))
                continue;
        }
        // Nor for a win32u.so call on a window kfilter cannot place (/system/win32k/<function>/@unknown, KB_NAMED_ONLY).
        if (source.Targets == KFILTER_TARGET_SYSTEM && source.Action == KFilterActionAllow && path.rfind("/system/win32k/", 0) == 0 &&
            path.size() > 24 && path.compare(path.size() - 9, 9, "/@unknown") == 0)
            continue;
        if (source.Targets == KFILTER_TARGET_SYSTEM && valued) rule.targets |= KB_TARGET_SYSTEM_VALUE;
        if (KfBpfKeyedRule(source, path)) rule.targets |= KB_TARGET_KEYED;
        rule.wild = path.find('*') != std::string::npos;
        rule.head = (__u32)std::min(path.find('*'), path.size());
        rule.ilen = (__u32)image.size();
        rule.iwhole = image.find_first_of("\\/") != std::string::npos;
        memcpy(rule.path, path.data(), path.size());
        memcpy(rule.value, value.data(), value.size());
        memcpy(rule.image, image.data(), image.size());
        const __u32 slot = (__u32)rules.size();
        // NT names match without case: the kernel hashes them lowercased. A literal parent shorter than a decision's
        // space root (KB_ROOT: /system or /system/wine for a Wine request only rules naming it decide) does not meet it.
        kb_slots* slots = rule.wild ? nullptr : &literal[LiteralKey(path[0] == '/' ? path : Lower(path))];
        if (slots != nullptr && slots->count < KB_PER_PATH) {
            slots->slot[slots->count++] = slot;
        } else {
            // A wildcard rule, or a literal one past KB_PER_PATH on its path (one rule per program
            // on /system/wine/open_directory): the glob list matches a literal pattern the same way.
            if (globs.size() >= KB_GLOBS) {
                problem = "more than " + std::to_string(KB_GLOBS) + " wildcard rules (and literal rules past " +
                          std::to_string(KB_PER_PATH) + " on one path)";
                continue;
            }
            globs.push_back(slot);
        }
        rules.push_back(rule);
        if ((source.Flags & KFILTER_RULE_ADDRESS) != 0) addressRules.push_back({slot, ranges});
        if (source.Targets == KFILTER_TARGET_DEVICE && rule.action != KFilterActionAllow) ioctlRules = 1;
        // A system rule whose fixed head (before any '*') and /system/memory/ agree can name
        // executable anonymous memory: only then is each such mapping classified and decided.
        // File mappings (/system/map) and requests on its own pseudo handles (/system/wine/self) only
        // where a rule names that space itself: a broad /system/* must not start deciding every mmap.
        const size_t head = std::min(path.find('*'), path.size());
        auto canName = [&](const std::string& space) {
            return source.Targets == KFILTER_TARGET_SYSTEM &&
                   path.compare(0, std::min(head, space.size()), space, 0, std::min(head, space.size())) == 0;
        };
        auto names = [&](const std::string& space) {
            return source.Targets == KFILTER_TARGET_SYSTEM && head >= space.size() && path.compare(0, space.size(), space) == 0;
        };
        if (canName("/system/memory/")) memoryRules |= 1;
        if (names("/system/map")) mapRules = 1;
        if (names("/system/wine/self")) selfRules = 1;
        gates |= RuleGates(rule, path, value, head);
        // The decisions of a target of the kernel's own (kfilter_bpf.h KB_TARGET_ARGUMENT): only these rules meet them.
        if (rule.targets == KFILTER_TARGET_DEVICE && value.find(':') != std::string::npos) rules.back().targets = KB_TARGET_ARGUMENT;
        if (reach) rules.back().targets = KB_TARGET_SIGNAL;
        // After those: a policy whose only peer rules name a signal or ptrace mode sends no peer request to the matcher.
        named |= rules.back().targets;
        for (const char* kind : {"/system/memory/private/", "/system/memory/shared/"}) {
            // Data memory: the fixed text past the kind can be r, rw or none (a wildcard's head a start of one). rx, rwx and
            // /system/memory/private/* name executable memory only and must not make every mmap and mprotect a decision.
            const std::string base = kind;
            if (source.Targets != KFILTER_TARGET_SYSTEM || head <= base.size() || path.compare(0, base.size(), base) != 0) continue;
            const std::string named = path.substr(base.size(), head - base.size());
            if (rule.wild ? std::string("rw").rfind(named, 0) == 0 || std::string("none").rfind(named, 0) == 0
                          : named == "r" || named == "rw" || named == "none")
                memoryRules |= KB_MEMORY_DATA;
        }
    }
    root = KfNarrow(std::wstring(config->Root, KfLengthBounded(config->Root, KFILTER_MAX_NAME)));
    while (root.size() > 1 && root.back() == '/') root.pop_back();
    if (!root.empty() && root[0] == '/' && root.size() >= KB_PATTERN) {
        problem = "root is too long for the kernel layer";
    }
    for (ULONG index = 0; index < config->ProtectedCount; index++) {
        std::string name = KfNarrow(std::wstring(config->Protected[index],
                                                 KfLengthBounded(config->Protected[index], KFILTER_MAX_NAME)));
        if (!name.empty() && name.size() >= KB_NAME) {
            problem = "protect name " + name + " is too long for the kernel layer";
            break;
        }
    }
    for (ULONG index = 0; index < config->NetworkRuleCount && index < KB_NET; index++) {
        const KFILTER_NET_RULE& source = config->Network[index];
        if (KfNarrow(std::wstring(source.Image, KfLengthBounded(source.Image, KFILTER_MAX_IMAGE))).size() >= KB_IMAGE ||
            KfNarrow(std::wstring(source.Unix, KfLengthBounded(source.Unix, KFILTER_MAX_VALUE))).size() >= KB_VALUE) {
            problem = "network rule " + std::to_string(source.RuleId) + " image or unix= is too long for the kernel layer";
        }
        // unix= sends are named only where a rule can decide them: message rules apply with block-network.
        if (source.Family == KFILTER_NET_FAMILY_UNIX && (config->Flags & KFILTER_CFG_BLOCK_NETWORK) != 0) gates |= KB_GATE_UNIX_MESSAGE;
    }
    if ((gLayer.gatesLost & (gates | (memoryRules & KB_MEMORY_DATA ? kGateData : 0) |
                             (config->Flags & KFILTER_CFG_BLOCK_PROCESS_SIGNALS ? kGateSignals : 0))) != 0)
        problem = "a rule or switch names decisions an ABI 11 program that did not attach makes";
    if (!problem.empty()) {
        fprintf(stderr, "kfilterd: %s\n", problem.c_str());
        if (config->Mode == KFILTER_MODE_BLOCK) return STATUS_INSUFFICIENT_RESOURCES;
        fprintf(stderr, "kfilterd: audit mode loaded without those rules; block mode is refused\n");
    }

    // The rules go into the rule set not in force, which no decision reads, and one word then switches every
    // decision to them: rewritten in place, a decision during a reload met old and new rules mixed (the bench
    // refused an allowed program by the old policy's deny in 1 decision of 10 during back-to-back reloads).
    const __u32 next = gLayer.set ^ 1;
    bool written = true;   /* every write took: a set written in part is never switched to */
    // addr= ranges of set Next by rule slot (next << 16 | slot), stamped with the module pattern list their module
    // slots belong to (kb_bases entries of an older list are not current for them). The policy before last's entries
    // leave first: kb_ranges holds two sets of KB_ADDRESS_RULES (added before they left, 700 addr= rules whose places
    // moved lost their ranges by the third load, and a deny without ranges met every access).
    __u32 gen;
    {
        std::lock_guard<std::mutex> guard(gModules.lock);
        gen = gModules.patterns == patterns ? gModules.gen : gModules.gen + 1;
    }
    std::set<__u32> rangeKeys;
    for (const auto& entry : addressRules) rangeKeys.insert(next << 16 | entry.first);
    std::vector<__u32> staleRanges;
    __u32 rangeAt = 0, rangeNext = 0;
    for (void* prior = nullptr; bpf_map_get_next_key(gLayer.ranges, prior, &rangeNext) == 0; prior = &rangeAt) {
        if (rangeNext >> 16 == next && rangeKeys.count(rangeNext) == 0) staleRanges.push_back(rangeNext);
        rangeAt = rangeNext;
    }
    for (__u32 old : staleRanges) written &= bpf_map_delete_elem(gLayer.ranges, &old) == 0;
    for (auto& entry : addressRules) {
        const __u32 rangeKey = next << 16 | entry.first;
        entry.second.gen = gen;
        written &= bpf_map_update_elem(gLayer.ranges, &rangeKey, &entry.second, BPF_ANY) == 0;
    }
    // The policy before last's literal keys leave first: the hash holds KB_RULES keys, which one policy can fill
    // (added before they left, 9,000 literal denies loaded two loads after another 9,000 lost 1,619 of them).
    std::vector<kb_key> stale;
    kb_key key{}, nextKey{};
    void* previous = nullptr;
    while (bpf_map_get_next_key(gLayer.literal[next], previous, &nextKey) == 0) {
        if (literal.count(nextKey) == 0) stale.push_back(nextKey);
        key = nextKey;
        previous = &key;
    }
    for (const auto& old : stale) written &= bpf_map_delete_elem(gLayer.literal[next], &old) == 0;
    for (__u32 slot = 0; slot < rules.size(); slot++) {
        written &= bpf_map_update_elem(gLayer.rules[next], &slot, &rules[slot], BPF_ANY) == 0;
    }
    for (__u32 index = 0; index <= globs.size() && index < KB_GLOBS; index++) {
        const __u32 slot = index < globs.size() ? globs[index] : KB_GLOB_END;
        written &= bpf_map_update_elem(gLayer.globs[next], &index, &slot, BPF_ANY) == 0;
    }
    for (const auto& entry : literal) {
        written &= bpf_map_update_elem(gLayer.literal[next], &entry.first, &entry.second, BPF_ANY) == 0;
    }
    // What the rules of set Next name of each syscall (kb_syscall_keys, next << 10 | ia32 << 9 | number): its stale
    // entries leave first, as kb_literal's do.
    const int syscallKeys = MapFd("kb_syscall_keys");
    const std::map<uint32_t, kb_syscall_named> namedKeys = KfBpfSyscallKeys(config);
    std::vector<__u32> staleCalls;
    __u32 callAt = 0, callNext = 0;
    for (void* prior = nullptr; bpf_map_get_next_key(syscallKeys, prior, &callNext) == 0; prior = &callAt) {
        if (callNext >> 10 == next && namedKeys.count(callNext & 0x3FF) == 0) staleCalls.push_back(callNext);
        callAt = callNext;
    }
    for (__u32 old : staleCalls) written &= bpf_map_delete_elem(syscallKeys, &old) == 0;
    for (const auto& entry : namedKeys) {
        const __u32 index = next << 10 | entry.first;
        written &= bpf_map_update_elem(syscallKeys, &index, &entry.second, BPF_ANY) == 0;
    }
    const __u32 netCount = config->NetworkRuleCount < KB_NET ? config->NetworkRuleCount : KB_NET;
    for (__u32 index = 0; index < KB_NET; index++) {
        // Zeroed from the last rule on: the end, and no rule of a longer earlier policy after it, which a kfilterd
        // before the rule sets would still read up to the count in kb_config when it takes this layer over.
        kb_net rule{};
        if (index >= netCount) {
            written &= bpf_map_update_elem(gLayer.net[next], &index, &rule, BPF_ANY) == 0;
            continue;
        }
        const KFILTER_NET_RULE& source = config->Network[index];
        rule.action = source.Action;
        rule.family = source.Family;
        rule.protocol = source.Protocol;
        rule.prefix = source.PrefixLength;
        rule.port = source.Port;
        rule.rule_id = source.RuleId;
        rule.rights = source.Rights;
        rule.count = source.Count;
        rule.risk = source.Risk[0] != L'\0';
        memcpy(rule.address, source.Address, sizeof(rule.address));
        std::string image = KfNarrow(std::wstring(source.Image, KfLengthBounded(source.Image, KFILTER_MAX_IMAGE)));
        rule.size_min = source.SizeMin;
        rule.size_max = source.SizeMax;
        rule.index_min = source.IndexMin;
        rule.index_max = source.IndexMax;
        rule.match_off = source.MatchOffset;
        rule.match_len = source.MatchLength <= sizeof(rule.match) ? source.MatchLength : 0;
        memcpy(rule.match, source.Match, sizeof(rule.match));
        if (source.Family == KFILTER_NET_FAMILY_UNIX) {
            // unix= beside the rule (kb_unix_names), its set's slot rewritten with it; one too long matches nothing
            // (block mode was refused above).
            const std::string unixName = KfNarrow(std::wstring(source.Unix, KfLengthBounded(source.Unix, KFILTER_MAX_VALUE)));
            kb_unix_name name{};
            if (unixName.size() < KB_VALUE) {
                name.len = (__u32)unixName.size();
                memcpy(name.path, unixName.data(), unixName.size());
            }
            const __u32 nameKey = next * KB_NET + index;
            written &= bpf_map_update_elem(gLayer.unixNames, &nameKey, &name, BPF_ANY) == 0;
        }
        std::wstring module(source.Module, KfLengthBounded(source.Module, KFILTER_MAX_IMAGE));
        if (!module.empty()) {
            auto bit = std::find(patterns.begin(), patterns.end(), module);
            // A pattern past the limit matches nothing (block mode was refused above).
            if (bit == patterns.end()) rule.prefix = 129;
            else rule.mbit = 1u << (bit - patterns.begin());
        }
        if (image.size() >= KB_IMAGE) {
            // Dropping the image would widen the rule to every program; audit mode loads it
            // matching nothing (block mode was refused above).
            rule.action = KFilterActionDeny;
            rule.rights = KFILTER_RIGHT_CONNECT | KFILTER_RIGHT_LISTEN;
            rule.prefix = 129;   // matches nothing
        } else {
            rule.ilen = (__u32)image.size();
            rule.iwhole = image.find_first_of("\\/") != std::string::npos;
            memcpy(rule.image, image.data(), image.size());
        }
        written &= bpf_map_update_elem(gLayer.net[next], &index, &rule, BPF_ANY) == 0;
    }
    written &= ResetCounts(next);
    // kb_wnamed holds the requests either policy names until the new one's cfg is written (a bit only lets a request
    // be decided, by the rules in force), then the new policy's.
    uint64_t wineNamed[KB_WNAMED_WORDS];
    KfBpfWineNamed(config, wineNamed);
    for (__u32 index = 0; index < KB_WNAMED_WORDS; index++) {
        __u64 bits = 0;
        bpf_map_lookup_elem(gLayer.wnamed, &index, &bits);
        bits |= wineNamed[index];
        written &= bpf_map_update_elem(gLayer.wnamed, &index, &bits, BPF_ANY) == 0;
    }
    const __u32 zero = 0;
    // kb_gates holds both policies' gates across the switch, so a kind either names is decided by the rule set in force;
    // the new policy's alone after it (left as both, the old kinds' decisions would only cost, meeting no rule).
    __u32 oldGates = 0;
    bpf_map_lookup_elem(MapFd("kb_gates"), &zero, &oldGates);
    const __u32 bothGates = oldGates | gates;
    written &= bpf_map_update_elem(MapFd("kb_gates"), &zero, &bothGates, BPF_ANY) == 0;
    if (!written || bpf_map_update_elem(gLayer.live, &zero, &next, BPF_ANY) != 0) {
        fprintf(stderr, "kfilterd: the BPF layer's maps did not take the policy; the one in force stays\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    gLayer.set = next;
    {
        std::lock_guard<std::mutex> guard(gModules.lock);
        if (gModules.patterns != patterns) {
            gModules.patterns = patterns;
            gModules.gen = gen;
            for (const auto& entry : gModules.code) gModules.dirty.insert(entry.first);
            gModules.wake.notify_one();
        }
    }

    kb_cfg cfg{};
    cfg.enabled = 1;
    cfg.mode = config->Mode;
    cfg.flags = config->Flags | (addressRules.empty() ? 0 : KB_CFG_ADDRESS);
    cfg.generation = KfPolicyGeneration();
    cfg.rule_count = (__u32)rules.size();
    cfg.targets = named;
    cfg.ioctl_rules = ioctlRules;
    cfg.memory_rules = memoryRules;
    cfg.wmi_rules = wmiRules;
    cfg.map_rules = mapRules;
    cfg.self_rules = selfRules;
    cfg.glob_count = (__u32)globs.size();
    cfg.net_count = netCount;
    for (__u32 index = 0; index < cfg.net_count; index++) {
        // INET sends and receives only: a policy whose message rules all name unix= decides no INET message.
        if ((config->Network[index].Rights & KFILTER_RIGHTS_MESSAGE) != 0 && config->Network[index].Family != KFILTER_NET_FAMILY_UNIX)
            cfg.msg_count++;
    }
    cfg.daemon_tgid = (__u32)getpid();
    if (!root.empty() && root[0] == '/' && root.size() < KB_PATTERN) {
        memcpy(cfg.root, root.data(), root.size());
        cfg.root_len = (__u32)root.size();
    }
    for (ULONG index = 0; index < config->ProtectedCount && cfg.name_count < KB_NAMES; index++) {
        std::string name = KfNarrow(std::wstring(config->Protected[index],
                                                 KfLengthBounded(config->Protected[index], KFILTER_MAX_NAME)));
        if (name.empty() || name.size() >= KB_NAME) continue;
        memcpy(cfg.names[cfg.name_count], name.data(), name.size());
        cfg.name_len[cfg.name_count++] = (__u32)name.size();
    }
    const std::vector<std::string>& wineDirs = WineDirs();
    if (!gBenchLayer) Win32kApply(config, wineDirs);
    SyscallApply(config);   /* attaches nothing in the bench (gBenchLayer) */
    bool newlyWmi;
    {
        std::lock_guard<std::mutex> guard(gUprobes.lock);
        newlyWmi = wmiRules && !gUprobes.wmi;
        gUprobes.wmi = wmiRules != 0;
    }
    if (newlyWmi) {
        // Programs that already have wbemprox.dll: their module tables are reread, which probes it.
        std::lock_guard<std::mutex> guard(gModules.lock);
        for (const auto& entry : gModules.code) gModules.dirty.insert(entry.first);
        gModules.wake.notify_one();
    }
    SetWineDirs(cfg, wineDirs);
    bpf_map_update_elem(gLayer.config, &zero, &cfg, BPF_ANY);
    for (__u32 index = 0; index < KB_WNAMED_WORDS; index++) {
        const __u64 bits = wineNamed[index];
        bpf_map_update_elem(gLayer.wnamed, &index, &bits, BPF_ANY);
    }
    bpf_map_update_elem(MapFd("kb_gates"), &zero, &gates, BPF_ANY);
    if ((gates & KB_GATE_NETLINK) != 0) GenlFamilies();
    // The next policy overwrites the old set: first every decision that started on it ends. Decisions are
    // non-sleepable programs, and an update of a map of maps returns only once every such program running has
    // ended (the kernel's synchronize_rcu_expedited, about 20 us; also on one CPU, where membarrier skips it).
    if (bpf_map_update_elem(gLayer.ruleSets, &zero, &gLayer.rules[0], BPF_ANY) != 0) {
        perror("kfilterd: no grace period after the rule set switch (kb_rule_sets); waiting 100 ms instead");
        usleep(100000);
    }
    return STATUS_SUCCESS;
}

void KfBpfResetCounts()
{
    if (!gActive) return;
    ResetCounts(gLayer.set);
}

/* Marks every thread of Tgid protected; Expect is the launch handshake image, if any. */
void KfBpfProtect(pid_t tgid, const std::wstring& expect)
{
    if (!gActive) return;
    kb_task value{};
    value.guarded = 1;
    std::string image = KfNarrow(expect);
    if (!image.empty() && image.size() < KB_PATH) {
        memcpy(value.expect, image.data(), image.size());
        value.expect_len = (__u32)image.size();
    }
    for (int fd : ThreadFds(tgid)) {
        kb_task old{};
        if (bpf_map_lookup_elem(gLayer.tasks, &fd, &old) == 0) value.role = old.role;
        bpf_map_update_elem(gLayer.tasks, &fd, &value, BPF_ANY);
        close(fd);
    }
    // Wine processes: wineserver charges the process's requests to it by this entry. The kernel may be writing the
    // same entry (a Linux program's name at its exec): left alone when already protected, made only when missing, so
    // a stale copy read here never overwrites the kernel's newer one.
    __u32 key = (__u32)tgid;
    kb_proc proc{};
    if (bpf_map_lookup_elem(gLayer.procs, &key, &proc) != 0) {
        proc = kb_proc{};
        proc.guarded = 1;
        if (bpf_map_update_elem(gLayer.procs, &key, &proc, BPF_NOEXIST) != 0 &&
            bpf_map_lookup_elem(gLayer.procs, &key, &proc) == 0 && !proc.guarded) {
            proc.guarded = 1;
            bpf_map_update_elem(gLayer.procs, &key, &proc, BPF_EXIST);
        }
    } else if (!proc.guarded) {
        proc.guarded = 1;
        bpf_map_update_elem(gLayer.procs, &key, &proc, BPF_EXIST);
    }
    ModulesWatch(tgid);
}

void KfBpfUnprotect(pid_t tgid)
{
    if (!gActive) return;
    for (int fd : ThreadFds(tgid)) {
        kb_task old{};
        if (bpf_map_lookup_elem(gLayer.tasks, &fd, &old) == 0 && old.role != KB_ROLE_NONE) {
            old.guarded = 0;   // still a Wine process or wineserver, no longer protected
            bpf_map_update_elem(gLayer.tasks, &fd, &old, BPF_ANY);
        } else {
            bpf_map_delete_elem(gLayer.tasks, &fd);
        }
        close(fd);
    }
    __u32 key = (__u32)tgid;
    kb_proc proc{};
    if (bpf_map_lookup_elem(gLayer.procs, &key, &proc) == 0) {
        proc.guarded = 0;
        bpf_map_update_elem(gLayer.procs, &key, &proc, BPF_ANY);
    }
    ModulesForget(tgid);
}

void KfBpfAllowLaunch(const std::wstring& creator, ULONG starts, ULONG seconds)
{
    if (!gActive) return;
    kb_launch pass{};
    std::string name = KfNarrow(creator);
    if (name.empty() || name.size() >= KB_CREATOR) return;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    pass.until_ns = (__u64)now.tv_sec * 1000000000ull + (__u64)now.tv_nsec + (__u64)seconds * 1000000000ull;
    pass.left = starts;
    pass.creator_len = (__u32)name.size();
    memcpy(pass.creator, name.data(), name.size());
    const __u32 zero = 0;
    bpf_map_update_elem(gLayer.launch, &zero, &pass, BPF_ANY);
}

/* Blocks (Directions 0: lifts) a protected program's connection by its socket inode. Fails
 * rather than report a block that does nothing: no BPF layer, not block mode with
 * block-network, no protected program holding that socket, or the table full. The entry
 * goes when the socket is freed. */
NTSTATUS KfBpfBlockConnection(uint64_t socketInode, ULONG directions)
{
    if (!gActive) return STATUS_DEVICE_NOT_READY;
    __u64 key = socketInode;
    if (directions == 0) return bpf_map_delete_elem(gLayer.blocked, &key) == 0 ? STATUS_SUCCESS : STATUS_NOT_FOUND;
    kb_cfg config{};
    const __u32 zero = 0;
    if (bpf_map_lookup_elem(gLayer.config, &zero, &config) != 0 || !config.enabled ||
        config.mode != KFILTER_MODE_BLOCK || (config.flags & KFILTER_CFG_BLOCK_NETWORK) == 0) {
        fprintf(stderr, "kfilterd: block-connection needs block mode with block-network on\n");
        return STATUS_NOT_SUPPORTED;
    }
    if ((directions & KFILTER_RIGHT_RECEIVE) != 0 && (gLayer.degraded & KFILTER_STATUS_DEGRADED_MESSAGE) != 0) {
        fprintf(stderr, "kfilterd: block-connection: receives are not decided (kb_socket_recvmsg did not attach)\n");
        return STATUS_NOT_SUPPORTED;
    }
    if (!ProtectedSocket(socketInode)) return STATUS_NOT_FOUND;
    __u32 value = directions;
    return bpf_map_update_elem(gLayer.blocked, &key, &value, BPF_ANY) == 0 ? STATUS_SUCCESS
                                                                            : STATUS_INSUFFICIENT_RESOURCES;
}

ULONG KfBpfDropped()
{
    if (!gActive) return 0;
    int cpus = libbpf_num_possible_cpus();
    if (cpus <= 0) return 0;
    std::vector<__u64> values((size_t)cpus);
    const __u32 zero = 0;
    if (bpf_map_lookup_elem(gLayer.drops, &zero, values.data()) != 0) return 0;
    __u64 total = 0;
    for (__u64 value : values) total += value;
    return (ULONG)total;
}
#endif
