// Root: kfilter's BPF matching on synthetic decisions (tests/bpf_bench.sh). Loads only the bench program of
// build/linux/bpf/kfilter_bench.bpf.o (linux/bpf/kfilter.bpf.c built with KB_TEST_BENCH) on fresh, unpinned
// maps and attaches nothing, so a running kfilterd is untouched. A policy goes through kfilterctl's parser,
// kfilterd's validation (KfPolicySetConfig) and its BPF compiler (KfBpfApply), as `kfilterctl policy` does; a
// decision runs with BPF_PROG_TEST_RUN, and the event the kernel logs names the rule that decided.
//
// A case is a policy and the decisions it must come to (see Case). Ad hoc, on any policy file:
//   kfilter-bpf-bench POLICY TARGET RIGHTS IMAGE PATH [VALUE [LISTED]]
//   e.g. POLICY system 0x80 'C:\Nexon\...\grap-core64.aes' /system/sysinfo

#define KB_TEST_BENCH
#include "../linux/kf_linux.h"
#include "../linux/bpf/kfilter_bpf.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <string>
#include <set>
#include <thread>
#include <vector>

bool KfBpfBench(bpf_object* object, uint32_t& registered);                               /* bpf_loader.cpp */
uint32_t KfBpfModuleGeneration();                                                         /* bpf_loader.cpp */
void KfBpfModulesRead(pid_t pid);                                                         /* bpf_loader.cpp */
void KfBpfEndMarks();                                                                     /* bpf_loader.cpp */
void KfBpfWineNamed(const KFILTER_CONFIG* config, uint64_t named[]);                      /* bpf_loader.cpp */
std::vector<std::string> KfBpfSyscallPrograms(const KFILTER_CONFIG* config);              /* bpf_loader.cpp */
std::map<uint32_t, kb_syscall_named> KfBpfSyscallKeys(const KFILTER_CONFIG* config);      /* bpf_loader.cpp */
bool BenchParsePolicy(const char* path, KFILTER_CONFIG* config, std::string& error);   /* linux_bpf_bench_policy.cpp */

namespace {

int gFailures = 0;

void Expect(const std::string& name, bool value)
{
    if (!value) {
        std::printf("FAIL %s\n", name.c_str());
        gFailures++;
    }
}

struct Bench {
    std::string path;                  /* kfilter_bench.bpf.o */
    bpf_object* object = nullptr;
    int program = -1;
    int pipe = -1;                     /* kb_bench_pipe: kb_bench.wine 9 */
    int syscall = -1;                  /* kb_bench_syscall: 6 */
    int helper = -1;                   /* kb_bench_helper: 7 */
    int net = -1;                      /* kb_bench_net: 8 */
    ring_buffer* ring = nullptr;
    std::vector<kb_event> events;   /* the decisions the last request logged */
} gBench;

int OnEvent(void*, void* data, size_t size)
{
    if (size >= sizeof(kb_event) && ((const kb_event*)data)->kind == KB_EV_DECISION) {
        gBench.events.push_back(*(const kb_event*)data);
    }
    return 0;
}

bool Open(const char* path)
{
    gBench.path = path;
    gBench.object = bpf_object__open_file(path, nullptr);
    if (gBench.object == nullptr) return false;
    bpf_program* program = nullptr;
    bpf_object__for_each_program(program, gBench.object) {
        const std::string name = bpf_program__name(program);
        bpf_program__set_autoload(program, name == "kb_bench_decide" || name == "kb_bench_hold" || name == "kb_bench_pipe" ||
                                               name == "kb_bench_syscall" ||
                                               name == "kb_bench_helper" || name == "kb_bench_net" ||
                                               name == "kb_syscall" ||
                                               name == "kb_syscall1" || name == "kb_s_x64_sys_read" ||
                                               name == "kb_s_x64_sys_futex");
    }
    bpf_map__set_max_entries(bpf_object__find_map_by_name(gBench.object, "kb_events"), 1 << 20);
    if (bpf_object__load(gBench.object) != 0) return false;
    gBench.program = bpf_program__fd(bpf_object__find_program_by_name(gBench.object, "kb_bench_decide"));
    gBench.pipe = bpf_program__fd(bpf_object__find_program_by_name(gBench.object, "kb_bench_pipe"));
    gBench.syscall = bpf_program__fd(bpf_object__find_program_by_name(gBench.object, "kb_bench_syscall"));
    gBench.helper = bpf_program__fd(bpf_object__find_program_by_name(gBench.object, "kb_bench_helper"));
    gBench.net = bpf_program__fd(bpf_object__find_program_by_name(gBench.object, "kb_bench_net"));
    /* An entry point's tail call takes its group's decision program (the kernel refuses a mismatched prototype). */
    const __u32 zero = 0;
    for (int group = 0; group < 2; group++) {
        const int decider = bpf_program__fd(bpf_object__find_program_by_name(gBench.object, group ? "kb_syscall1" : "kb_syscall"));
        Expect(std::string("syscall decision program ") + std::to_string(group) + " goes in its tail map",
               bpf_map_update_elem(bpf_object__find_map_fd_by_name(gBench.object, group ? "kb_syscall_tail1" : "kb_syscall_tail0"),
                                   &zero, &decider, BPF_ANY) == 0);
    }
    gBench.ring = ring_buffer__new(bpf_object__find_map_fd_by_name(gBench.object, "kb_events"), OnEvent, nullptr, nullptr);
    return gBench.program >= 0 && gBench.pipe >= 0 && gBench.syscall >= 0 && gBench.helper >= 0 && gBench.net >= 0 &&
           gBench.ring != nullptr && KfBpfBench(gBench.object, gKfRegisteredMask);
}

using Config = std::unique_ptr<KFILTER_CONFIG>;

/* Text as `kfilterctl policy` reads it; null when it does not parse. */
Config Parse(const std::string& text)
{
    char path[] = "/tmp/kfilter-bench-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) return nullptr;
    bool written = write(fd, text.data(), text.size()) == (ssize_t)text.size();
    close(fd);
    Config config(new KFILTER_CONFIG());
    std::string error;
    bool parsed = written && BenchParsePolicy(path, config.get(), error);
    unlink(path);
    if (!parsed) std::printf("policy does not parse: %s\n", error.c_str());
    return parsed ? std::move(config) : nullptr;
}

/* Loads Config as kfilterd's SET_CONFIG does before its network table: KfPolicySetConfig, then KfBpfApply. */
bool Load(const KFILTER_CONFIG* config)
{
    NTSTATUS status = KfPolicySetConfig(config, KFILTER_CONFIG_SIZE(config->RuleCount));
    if (NT_SUCCESS(status)) status = KfBpfApply(config);
    if (!NT_SUCCESS(status)) std::printf("policy refused: 0x%08x\n", (unsigned)status);
    return NT_SUCCESS(status);
}

bool Apply(const std::string& text)
{
    Config config = Parse(text);
    return config && Load(config.get());
}

struct Request {
    uint32_t target;
    uint32_t rights;
    std::string image;   /* as Wine names the program; "" for one it has not named */
    std::string path;
    uint32_t value = 0;
    uint32_t listed = 0;
    kb_access access{};          /* listed KB_ADDRESSED: what the decision reaches */
    std::vector<uint32_t> wine{};   /* a Wine request header (16 words) decided as the request pipe's hook does */
    std::vector<std::pair<const void*, uint32_t>> chunks{};   /* its data, one writev iovec each (2: the reply) */
    uint32_t kind = 1;           /* with wine: kb_bench.wine (2: a reply, 3: a module table change, 4: registry and
                                  * NT object decoders, 5: then the second pass, 6: a syscall, 7: an ABI 11 decision
                                  * function, 8: a network decision, 9: the write through the request pipe's hook) */
    bool compat = false;         /* kind 9: an ia32 writev (8-byte iovecs, below 4 GiB) */
    std::string text{};          /* the decision's value text (a peer decision's signal), for value= rules */
};

struct Result {
    bool ran = false;
    bool decided = false;   /* false: the hook passes the request undecided */
    int verdict = 0;
    bool logged = false;
    kb_event event{};       /* the last decision logged */
    uint32_t ibase = 0;
    uint32_t duration = 0;  /* kind 8: ns the decision took, as the program measured it */
};

Result Decide(const Request& request)
{
    kb_bench bench{};
    bench.target = request.target;
    bench.rights = request.rights;
    bench.value = request.value;
    bench.listed = request.listed;
    bench.len = (uint32_t)std::min(request.path.size(), sizeof(bench.path) - 1);
    memcpy(bench.path, request.path.data(), bench.len);
    bench.ilen = (uint32_t)std::min(request.image.size(), sizeof(bench.image) - 1);
    memcpy(bench.image, request.image.data(), bench.ilen);
    bench.vlen = (uint32_t)std::min(request.text.size(), sizeof(bench.value_text) - 1);
    memcpy(bench.value_text, request.text.data(), bench.vlen);
    bench.access = request.access;
    std::vector<iovec> vector(1);   /* the writev: the header, then each data chunk */
    if (!request.wine.empty()) {
        bench.wine = request.kind;
        memcpy(bench.request, request.wine.data(), std::min(request.wine.size(), (size_t)16) * sizeof(uint32_t));
        vector[0] = {bench.request, 64};
        for (const auto& chunk : request.chunks) vector.push_back({const_cast<void*>(chunk.first), chunk.second});
        bench.iov = (uint64_t)(uintptr_t)vector.data();
        bench.count = (uint32_t)vector.size();
        bench.data = request.chunks.empty() ? 0 : (uint64_t)(uintptr_t)request.chunks[0].first;
        if (request.kind == 9 && request.chunks.empty()) bench.iov = (uint64_t)(uintptr_t)bench.request;   /* a write */
    }
    /* An ia32 writev: header, chunks and 8-byte iovecs copied below 4 GiB. */
    static uint8_t* low = (uint8_t*)mmap(nullptr, 1 << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
    if (request.compat && low != MAP_FAILED) {
        uint32_t at = 64 * 8;   /* the iovecs first */
        for (size_t i = 0; i < vector.size() && at + vector[i].iov_len <= (1u << 20); i++) {
            memcpy(low + at, vector[i].iov_base, vector[i].iov_len);
            const uint32_t small[2] = {(uint32_t)(uintptr_t)(low + at), (uint32_t)vector[i].iov_len};
            memcpy(low + i * 8, small, sizeof(small));
            at += (uint32_t)vector[i].iov_len;
        }
        bench.iov = (uint64_t)(uintptr_t)(vector.size() > 1 ? low : low + 64 * 8);
        bench.compat = 1;
    }
    bpf_test_run_opts options{};
    options.sz = sizeof(options);
    options.ctx_in = &bench;
    options.ctx_size_in = sizeof(bench);
    gBench.events.clear();
    Result result;
    const int program = request.kind == 6 ? gBench.syscall : request.kind == 7 ? gBench.helper : request.kind == 8 ? gBench.net
                        : request.kind == 9 ? gBench.pipe : gBench.program;
    result.ran = bpf_prog_test_run_opts(program, &options) == 0 && options.retval == 0;
    if (request.kind == 8) result.duration = bench.request[15];
    ring_buffer__consume(gBench.ring);
    result.decided = bench.decided != 0;
    result.verdict = bench.verdict;
    result.ibase = bench.ibase;
    if (!gBench.events.empty()) {
        result.logged = true;
        result.event = gBench.events.back();
    }
    return result;
}

std::string Describe(const Result& result)
{
    char text[200];
    std::snprintf(text, sizeof(text), "ran %d decided %d verdict %d; event %s action %u rule %u flags 0x%x image '%s'",
                  result.ran, result.decided, result.verdict, result.logged ? "logged" : "none", result.event.action,
                  result.event.rule_id, result.event.flags, result.logged ? result.event.image : "");
    return text;
}

/* What a decision must come to: Action 0 is allowed with nothing logged (a rule-only request no rule names). */
void ExpectDecision(const std::string& name, const Request& request, uint32_t action, uint32_t rule, uint32_t flags = 0)
{
    Result result = Decide(request);
    bool good = result.ran && (result.verdict != 0) == (action == KFilterActionDeny) && result.logged == (action != 0) &&
                (action == 0 || (result.decided && result.event.action == action && result.event.rule_id == rule &&
                                 (result.event.flags & flags) == flags));
    if (!good) std::printf("  %s: %s\n", name.c_str(), Describe(result).c_str());
    Expect(name, good);
}

const char kAll[] = "read,write,execute,delete,rename,set-security,enumerate,query,create,connect,listen,raw-device,open";

/* The programs as Wine names them (argv[0] after Wine's loader rewrote it), from the live block loop. */
const char kGrap[] = "C:\\Nexon\\Library\\maplestorycw\\appdata\\grap\\grap-core64.aes";
const char kDwarf[] = "C:\\Nexon\\Library\\maplestorycw\\appdata\\.\\NxOverlay\\DwarfAxe.exe";
const char kNexon[] = "C:\\Program Files (x86)\\Nexon\\Nexon Launcher\\bin\\nexon_client\\nexon_client.exe";
const char kMaple[] = "C:\\Nexon\\Library\\maplestorycw\\appdata\\MapleStory.exe";
const char kDevice[] = "C:\\windows\\system32\\winedevice.exe";
const char kExplorer[] = "C:\\windows\\system32\\explorer.exe";

/* The head of the live block loop's policies (relax/live_block.py policy_text): switches, msmon's handle allow
 * and the two exceptions. */
std::string Head()
{
    return "mode block\n"
           "protect MapleStory.exe\nprotect grap-core64.aes\nprotect DwarfAxe.exe\nprotect nexon_client.exe\n"
           "block-files\nblock-file-queries\nblock-registry\nblock-volume-serial\nblock-network-adapter\n"
           "block-process-create\nblock-process-memory\nblock-raw-disk\nblock-network\nnetwork-default allow\n"
           "allow|handle|/usr/local/bin/msmon-agent|rights=vm-operation,vm-read,vm-write|risk=msmon\n"
           "allow|system|/system/wine/self/terminate_thread|rights=write|exact\n"
           "allow|system|/system/wine/self/terminate_process|rights=write|exact\n";
}

/* Count rules shaped like the live loop's denies: literal file, dir, registry and volume denies under shared
 * parents, system denies scoped to programs (8 on a path, as the loop compacts them), and Globs wildcard rules,
 * system ones among them. Variant moves the paths, as the loop's steady and change policies differ. */
std::string Filler(int count, int globs, int variant)
{
    static const char* programs[] = {"services.exe", "start.exe", "plugplay.exe", "explorer.exe",
                                     "wineboot.exe", "winemenubuilder.exe", "nexon_runtime.exe", "grap-updater.aes"};
    std::string text;
    const std::string v = std::to_string(variant);
    for (int i = 0; i < globs; i++) {
        const std::string n = std::to_string(i);
        switch (i % 4) {
        case 0: text += "deny|file|/home/*/.cache/v" + v + "/k" + n + "/*\n"; break;
        case 1: text += "deny|registry|\\Registry\\User\\*\\Software\\V" + v + "x" + n + "\\*\n"; break;
        case 2: text += "deny|system|/system/wine/*_v" + v + "_" + n + "|image=" + programs[i % 8] + "\n"; break;
        default: text += "deny|dir|/proc/*/task/" + v + n + "|exact\n"; break;
        }
    }
    int system = 0;
    for (int i = 0; i < count - globs; i++) {
        const std::string n = std::to_string(i);
        switch (i % 6) {
        case 0: text += "deny|file|/sys/devices/system/cpu/cpu" + std::to_string(i % 16) + "/v" + v + "/f" + n + "|exact\n"; break;
        case 1: text += "deny|registry|\\Registry\\Machine\\Software\\Vendor" + std::to_string(i % 40) + "\\v" + v + "\\Key" + n + "|exact\n"; break;
        case 2: text += "deny|dir|/home/user/.wine/drive_c/d" + std::to_string(i % 30) + "/v" + v + "s" + n + "\n"; break;
        case 3: text += "deny|volume|/media/v" + v + "/m" + n + "|exact\n"; break;
        case 4:
            text += "deny|system|/system/wine/q" + v + "_" + std::to_string(system / 8) + "|image=" + programs[system % 8] + "\n";
            system++;
            break;
        default: text += "deny|file|/etc/v" + v + "/c" + std::to_string(i % 50) + "/x" + n + "\n"; break;
        }
    }
    return text;
}

/* The tail: device allows and volume allows (relax/live_block.py policy_text). */
std::string Tail()
{
    return "allow|device|/dev/dri/renderD128|rights=raw-device|exact|uses=32767|risk=needed\n"
           "allow|volume|/*|rights=" + std::string(kAll) + "\n"
           "allow|volume|\\*|rights=" + std::string(kAll) + "\n";
}

/* The policy the block loop meant to load at 00:07 (relax/live_block.py at b3144d4): per-program allows of
 * /system/sysinfo for the programs that used it, Extra other allows ahead of them, about 7,000 denies with the
 * deny for everyone among the last, a non-exact rule on the parent /system, and a wildcard rule that matches
 * /system/sysinfo for another program ahead of every allow. (What it loaded had the denies first: compact()'s
 * (allows, denies) went to policy_text(denies, allows) swapped until 04cbf1d, which the refusals at 00:07 were.) */
std::string SysinfoPolicy(int extra, int fillerBefore, int variant)
{
    std::string text = Head();
    text += "deny|system|/system/sys*|image=services.exe\n";
    for (int i = 0; i < extra; i++) {
        text += "allow|system|/system/wine/open_key_" + std::to_string(i) + "|exact|rights=" + kAll + "|image=MapleStory.exe\n";
    }
    for (const char* image : {"grap-core64.aes", "DwarfAxe.exe", "MapleStory.exe", "nexon_client.exe", "winedevice.exe"}) {
        text += std::string("allow|system|/system/sysinfo|exact|rights=") + kAll + "|image=" + image + "\n";
    }
    text += "allow|system|/system/sched|exact|rights=" + std::string(kAll) + "|image=grap-core64.aes\n";
    text += Filler(fillerBefore, 120, variant);
    text += "audit|system|/system|image=plugplay.exe\n";
    text += "deny|system|/system/sysinfo|exact\n";
    text += "deny|system|/system/sched|exact\n";
    text += Filler(400, 0, variant + 100);
    return text + Tail();
}

/* The id kfilterctl gives Line, a rule of Text: its place among the rules (no network or message rules here). */
uint32_t RuleOf(const std::string& text, const std::string& line)
{
    uint32_t rule = 0;
    for (size_t index = 0; index < text.size();) {
        size_t end = text.find('\n', index);
        if (end == std::string::npos) end = text.size();
        const std::string current = text.substr(index, end - index);
        if (current.rfind("allow|", 0) == 0 || current.rfind("deny|", 0) == 0 || current.rfind("audit|", 0) == 0) rule++;
        if (current == line) return rule;
        index = end + 1;
    }
    return 0;
}

/* The block loop's report, in the order it meant: Wine programs refused /system/sysinfo although an image= allow for
 * each came before the deny for everyone, in a policy of about 7,000 rules. */
void SysinfoCase()
{
    const std::string text = SysinfoPolicy(3, 7000, 1);
    Expect("sysinfo policy loads", Apply(text));
    const uint32_t deny = RuleOf(text, "deny|system|/system/sysinfo|exact");
    const uint32_t first = RuleOf(text, std::string("allow|system|/system/sysinfo|exact|rights=") + kAll + "|image=grap-core64.aes");
    Expect("sysinfo rule ids found", deny > 7000 && first > 0);
    const struct { const char* image; uint32_t rule; } allowed[] = {
        {kGrap, first}, {kDwarf, first + 1}, {kMaple, first + 2}, {kNexon, first + 3}, {kDevice, first + 4}};
    for (const auto& entry : allowed) {
        const std::string name = std::string("sysinfo allowed to ") + entry.image;
        ExpectDecision(name, {KFILTER_TARGET_SYSTEM, KFILTER_RIGHT_QUERY, entry.image, "/system/sysinfo"},
                       KFilterActionAllow, entry.rule);
        // A system decision that asks for no right is decided as open, which the allows name too.
        ExpectDecision(name + " (no right)", {KFILTER_TARGET_SYSTEM, 0, entry.image, "/system/sysinfo"},
                       KFilterActionAllow, entry.rule);
    }
    ExpectDecision("sysinfo refused to explorer.exe", {KFILTER_TARGET_SYSTEM, KFILTER_RIGHT_QUERY, kExplorer, "/system/sysinfo"},
                   KFilterActionDeny, deny);
    ExpectDecision("sysinfo refused to an unnamed program", {KFILTER_TARGET_SYSTEM, KFILTER_RIGHT_QUERY, "", "/system/sysinfo"},
                   KFilterActionDeny, deny);
    ExpectDecision("the wildcard rule ahead of the allows decides its program",
                   {KFILTER_TARGET_SYSTEM, KFILTER_RIGHT_QUERY, "C:\\windows\\system32\\services.exe", "/system/sysinfo"},
                   KFilterActionDeny, RuleOf(text, "deny|system|/system/sys*|image=services.exe"));
    ExpectDecision("sched (write) allowed to grap-core64.aes", {KFILTER_TARGET_SYSTEM, KFILTER_RIGHT_WRITE, kGrap, "/system/sched"},
                   KFilterActionAllow, RuleOf(text, "allow|system|/system/sched|exact|rights=" + std::string(kAll) + "|image=grap-core64.aes"));
    ExpectDecision("sched (write) refused to DwarfAxe.exe", {KFILTER_TARGET_SYSTEM, KFILTER_RIGHT_WRITE, kDwarf, "/system/sched"},
                   KFilterActionDeny, RuleOf(text, "deny|system|/system/sched|exact"));
    Result named = Decide({KFILTER_TARGET_SYSTEM, KFILTER_RIGHT_QUERY, kNexon, "/system/sysinfo"});
    Expect("a Windows image is named from its last backslash", named.ibase == std::string(kNexon).rfind('\\') + 1);
}

/* Literal rules past KB_PER_PATH on one path go to the wildcard list: image= still scopes them, and an allow there
 * still comes before the deny that follows it. */
void SpillCase()
{
    std::string text = Head();
    for (int i = 1; i <= 10; i++) text += "deny|system|/system/wine/open_directory|image=p" + std::to_string(i) + ".exe\n";
    for (int i = 1; i <= 9; i++) {
        text += "allow|system|/system/wine/open_key|rights=" + std::string(kAll) + "|image=a" + std::to_string(i) + ".exe\n";
    }
    text += "deny|system|/system/wine/open_key\n";
    text += Filler(6000, 150, 7) + Tail();
    Expect("spill policy loads", Apply(text));
    for (int i : {1, 8, 9, 10}) {
        const std::string image = "C:\\x\\p" + std::to_string(i) + ".exe";
        ExpectDecision("open_directory refused to p" + std::to_string(i) + " (past 8: wildcard list)",
                       {KFILTER_TARGET_SYSTEM, KFILTER_RIGHT_QUERY, image, "/system/wine/open_directory"}, KFilterActionDeny,
                       RuleOf(text, "deny|system|/system/wine/open_directory|image=p" + std::to_string(i) + ".exe"));
    }
    ExpectDecision("open_directory left to a program no rule names",
                   {KFILTER_TARGET_SYSTEM, KFILTER_RIGHT_QUERY, "C:\\x\\p11.exe", "/system/wine/open_directory"}, 0, 0);
    for (int i : {1, 8, 9}) {
        ExpectDecision("open_key allowed to a" + std::to_string(i) + " before the deny",
                       {KFILTER_TARGET_SYSTEM, KFILTER_RIGHT_QUERY, "C:\\x\\a" + std::to_string(i) + ".exe", "/system/wine/open_key"},
                       KFilterActionAllow,
                       RuleOf(text, "allow|system|/system/wine/open_key|rights=" + std::string(kAll) + "|image=a" + std::to_string(i) + ".exe"));
    }
    ExpectDecision("open_key refused to another program", {KFILTER_TARGET_SYSTEM, KFILTER_RIGHT_QUERY, kGrap, "/system/wine/open_key"},
                   KFilterActionDeny, RuleOf(text, "deny|system|/system/wine/open_key"));
}

/* A counted device allow under a deny|device rule (every ioctl is then decided where a rule names it) refuses
 * once its uses are spent, with its id and EXHAUSTED: the live loop's GPU at uses=32767. */
void DeviceCase()
{
    const std::string allow = "allow|device|/dev/dri/renderD128|rights=raw-device|exact|uses=3|risk=needed";
    const std::string text = Head() + "deny|device|/net/ioctl|image=nexon_runtime.exe\n" + allow + "\n";
    Expect("device policy loads", Apply(text));
    const Request ioctl{KFILTER_TARGET_DEVICE, KFILTER_RIGHT_RAW_DEVICE, kMaple, "/dev/dri/renderD128", 0xC0106442, 1};
    for (int i = 1; i <= 3; i++) {
        ExpectDecision("GPU ioctl " + std::to_string(i) + " allowed by the counted allow", ioctl, KFilterActionAllow,
                       RuleOf(text, allow), KFILTER_EVENT_FLAG_COUNTED);
    }
    ExpectDecision("GPU ioctl refused once the counted allow is spent", ioctl, KFilterActionDeny, RuleOf(text, allow),
                   KFILTER_EVENT_FLAG_EXHAUSTED);
    ExpectDecision("another device's ioctl left alone", {KFILTER_TARGET_DEVICE, KFILTER_RIGHT_RAW_DEVICE, kMaple, "/dev/snd/pcmC0D0p", 1, 1},
                   0, 0);
    // Every policy load restores the counts (the live loop loads one at each channel change).
    Expect("device policy loads again", Apply(text));
    ExpectDecision("GPU ioctl allowed again after a policy load", ioctl, KFilterActionAllow, RuleOf(text, allow),
                   KFILTER_EVENT_FLAG_COUNTED);
    // Without uses= (a path only rules decide): never spent.
    const std::string uncounted = "allow|device|/dev/dri/renderD128|rights=raw-device|exact|risk=needed";
    const std::string uncountedText = Head() + "deny|device|/net/ioctl|image=nexon_runtime.exe\n" + uncounted + "\n";
    Expect("uncounted device policy loads", Apply(uncountedText));
    Result result;
    int allowed = 0;
    for (int i = 0; i < 100; i++) {
        result = Decide(ioctl);
        allowed += result.ran && result.verdict == 0 && result.logged && result.event.action == KFilterActionAllow &&
                   result.event.rule_id == RuleOf(uncountedText, uncounted) && (result.event.flags & KFILTER_EVENT_FLAG_COUNTED) == 0;
    }
    Expect("an uncounted device allow is never spent", allowed == 100);
}

kb_key LiteralKey(const std::string& path)   /* bpf_loader.cpp's, for a '/' path */
{
    kb_key key{KB_FNV_INIT, KB_DJB_INIT, (uint32_t)path.size()};
    for (unsigned char c : path) {
        key.fnv = kb_fnv_step(key.fnv, c);
        key.djb = kb_djb_step(key.djb, c);
    }
    return key;
}

/* A literal entry whose slot holds another path's rule of the same length (a hash collision, or what the in-place
 * reload gave a decision for a moment): a candidate's own path is compared, so that rule decides nothing. */
void LiteralCase()
{
    const std::string deny = "deny|system|/system/sysinfo|exact";
    const std::string text = Head() + deny + "\n";
    Expect("literal policy loads", Apply(text));
    const __u32 zero = 0;
    __u32 set = 0, slot = 0;
    bpf_map_lookup_elem(bpf_object__find_map_fd_by_name(gBench.object, "kb_live"), &zero, &set);
    const std::string b = set == 1 ? "_b" : "";
    const int rules = bpf_object__find_map_fd_by_name(gBench.object, ("kb_rules" + b).c_str());
    const int literal = bpf_object__find_map_fd_by_name(gBench.object, ("kb_literal" + b).c_str());
    kb_rule rule{};
    while (slot < KB_RULES && bpf_map_lookup_elem(rules, &slot, &rule) == 0 && rule.rule_id != RuleOf(text, deny)) slot++;
    kb_slots slots{};
    slots.count = 1;
    slots.slot[0] = slot;
    const kb_key key = LiteralKey("/system/syslogx");   /* as long as /system/sysinfo */
    Expect("literal entry written", rule.rule_id == RuleOf(text, deny) && bpf_map_update_elem(literal, &key, &slots, BPF_ANY) == 0);
    ExpectDecision("another path's rule in a literal entry decides nothing",
                   {KFILTER_TARGET_SYSTEM, KFILTER_RIGHT_QUERY, kGrap, "/system/syslogx"}, 0, 0);
    ExpectDecision("its own path still meets it", {KFILTER_TARGET_SYSTEM, KFILTER_RIGHT_QUERY, kGrap, "/system/sysinfo"},
                   KFilterActionDeny, RuleOf(text, deny));
}

/* A policy's literal rules all go into the rule set it is loaded into, whatever the policy before last left there:
 * the hash holds KB_RULES paths, as many as one policy can have (written before the old paths left, 9,000 literal
 * denies after another 9,000 lost 1,619, which then decided nothing). */
void CapacityCase()
{
    auto denies = [](const char* tag) {
        std::string text = Head();
        for (int i = 0; i < 9000; i++) text += std::string("deny|file|/kf-cap-") + tag + "/f" + std::to_string(i) + "|exact\n";
        return text;
    };
    const std::string text = denies("c");
    Expect("capacity: a policy of 9,000 literal denies loads", Apply(denies("a")));
    Expect("capacity: a small policy loads into the other set", Apply(Head()));
    Expect("capacity: 9,000 other literal denies load into the first one's set", Apply(text));
    const uint32_t first = RuleOf(text, "deny|file|/kf-cap-c/f0|exact");
    int missing = 0;
    for (int i = 0; i < 9000; i++) {
        const std::string path = "/kf-cap-c/f" + std::to_string(i);
        Result result = Decide({KFILTER_TARGET_FILE, KFILTER_RIGHT_READ, kMaple, path});
        if (result.ran && result.verdict != 0 && result.logged && result.event.rule_id == first + (uint32_t)i) continue;
        if (missing++ == 0) std::printf("  capacity: %s: %s\n", path.c_str(), Describe(result).c_str());
    }
    if (missing != 0) std::printf("  capacity: %d of 9000 literal denies decide nothing\n", missing);
    Expect("capacity: every literal deny of the policy in force decides", missing == 0);
}

/* A rule set's network rules are zeroed from its policy's last on: a kfilterd before the rule sets that takes the
 * layer over reads set 0 up to kb_config's count, and must not meet a longer earlier policy's rules there. */
void NetEndCase()
{
    auto rules = [](int count) {
        std::string text = Head();
        for (int i = 0; i < count; i++) text += "deny|network|ip=10." + std::to_string(i) + ".0.0/16\n";
        return text;
    };
    Expect("network end: a policy of 5 network rules loads", Apply(rules(5)));
    Expect("network end: one of none loads into the other set", Apply(rules(0)));
    Expect("network end: one of 1 loads into the first one's set", Apply(rules(1)));
    const __u32 zero = 0;
    __u32 set = 0;
    bpf_map_lookup_elem(bpf_object__find_map_fd_by_name(gBench.object, "kb_live"), &zero, &set);
    const int net = bpf_object__find_map_fd_by_name(gBench.object, set == 1 ? "kb_netrules_b" : "kb_netrules");
    int left = 0;
    for (__u32 index = 1; index < KB_NET; index++) {
        kb_net rule{}, none{};
        left += bpf_map_lookup_elem(net, &index, &rule) != 0 || memcmp(&rule, &none, sizeof(rule)) != 0;
    }
    Expect("network end: nothing after the last network rule", left == 0);
}

/*
 * A load returns only once no decision that started before its switch still runs, so the next load may rewrite
 * that set: kb_bench_hold, a non-sleepable reader as an LSM hook's decision is, keeps KfBpfApply waiting after it
 * wrote kb_config until the bench ends it. ReloadCase cannot show this: its decisions are sleepable, which no RCU
 * grace period waits for, and take microseconds, so none spans two loads; it tests the switch.
 */
void GraceCase()
{
    if (std::thread::hardware_concurrency() < 2) {
        std::printf("  grace: skipped (one CPU: the reader would hold it)\n");
        return;
    }
    Config config = Parse(Head() + "deny|system|/system/sysinfo|exact\n");
    const int holds = bpf_object__find_map_fd_by_name(gBench.object, "kb_bench_holds");
    const int cfgMap = bpf_object__find_map_fd_by_name(gBench.object, "kb_config");
    const int hold = bpf_program__fd(bpf_object__find_program_by_name(gBench.object, "kb_bench_hold"));
    Expect("grace: set up", config && holds >= 0 && cfgMap >= 0 && hold >= 0);
    if (!config || holds < 0 || cfgMap < 0 || hold < 0) return;
    const __u32 zero = 0, one = 1;
    auto state = [&](__u32 key) {
        __u32 value = 0;
        bpf_map_lookup_elem(holds, &key, &value);
        return value;
    };
    auto generation = [&] {
        kb_cfg cfg{};
        bpf_map_lookup_elem(cfgMap, &zero, &cfg);
        return cfg.generation;
    };
    const auto millisecond = std::chrono::milliseconds(1);
    bpf_map_update_elem(holds, &zero, &zero, BPF_ANY);
    bpf_map_update_elem(holds, &one, &zero, BPF_ANY);
    std::thread holder([&] {
        bpf_test_run_opts options{};
        options.sz = sizeof(options);
        bpf_prog_test_run_opts(hold, &options);
    });
    for (int i = 0; i < 2000 && state(0) != 1; i++) std::this_thread::sleep_for(millisecond);
    const __u32 before = generation();
    std::atomic<bool> returned{false};
    bool loaded = false;
    std::thread loader([&] {
        loaded = Load(config.get());
        returned = true;
    });
    for (int i = 0; i < 2000 && generation() == before && !returned; i++) std::this_thread::sleep_for(millisecond);
    std::this_thread::sleep_for(20 * millisecond);   /* without the grace period it returns at once */
    const bool held = state(0) == 1, waited = !returned;
    bpf_map_update_elem(holds, &one, &one, BPF_ANY);
    loader.join();
    holder.join();
    Expect("grace: the reader held while the load wrote kb_config", held);
    Expect("grace: a load waits for a decision that started before its switch", waited);
    Expect("grace: it returns once that decision ended", loaded && state(0) == 2);
}

double Milliseconds(std::chrono::steady_clock::duration duration)
{
    return std::chrono::duration<double, std::milli>(duration).count();
}

/*
 * Policy reloads while decisions run: the loop loads its steady and change policies in turn, where the allows sit
 * at different places. Every decision in between must come to what both policies say: allowed to grap-core64.aes
 * by an allow, refused to explorer.exe by the deny. This tests the switch (GraceCase the grace period).
 */
void ReloadCase(int loads)
{
    const std::string texts[2] = {SysinfoPolicy(3, 7000, 1), SysinfoPolicy(9, 7011, 2)};
    Config configs[2] = {Parse(texts[0]), Parse(texts[1])};
    Expect("reload policies parse", configs[0] && configs[1]);
    if (!configs[0] || !configs[1]) return;
    Expect("reload: first policy loads", Load(configs[0].get()));
    std::atomic<bool> done{false};
    std::atomic<int> decisions{0}, wrong{0}, refused{0};
    std::vector<std::string> samples[2];
    std::thread decider([&] {
        while (!done) {
            const bool allowed = decisions % 2 == 0;
            Result result = Decide({KFILTER_TARGET_SYSTEM, KFILTER_RIGHT_QUERY, allowed ? kGrap : kExplorer, "/system/sysinfo"});
            const bool good = result.ran && result.logged && (result.verdict == 0) == allowed &&
                              result.event.action == (allowed ? KFilterActionAllow : KFilterActionDeny);
            decisions++;
            if (!good) {
                if (samples[allowed].size() < 3) samples[allowed].push_back((allowed ? "grap-core64.aes: " : "explorer.exe: ") + Describe(result));
                wrong++;
                if (allowed) refused++;
            }
        }
    });
    double total = 0, longest = 0;
    for (int load = 1; load <= loads; load++) {
        auto start = std::chrono::steady_clock::now();
        bool loaded = Load(configs[load % 2].get());
        double took = Milliseconds(std::chrono::steady_clock::now() - start);
        total += took;
        longest = std::max(longest, took);
        Expect("reload " + std::to_string(load) + " loads", loaded);
    }
    done = true;
    decider.join();
    std::printf("  reload: %d loads of %u and %u rules, %.1f ms each on average (longest %.1f); %d decisions in between, "
                "%d wrong (%d of them refusals of an allowed program)\n", loads, (unsigned)configs[0]->RuleCount,
                (unsigned)configs[1]->RuleCount, total / loads, longest, decisions.load(), wrong.load(), refused.load());
    for (const auto& kind : samples) {
        for (const std::string& sample : kind) std::printf("    %s\n", sample.c_str());
    }
    Expect("no decision during a reload sees the two policies mixed", wrong == 0);
}

/* ---- addr= rules (ABI 10) ---- */

const uint32_t kTarget = 0x3FFFFF01;   /* MapleStory.exe's tgid in the maps the cases write: no process has it */

int MapOf(const char* name)
{
    return bpf_object__find_map_fd_by_name(gBench.object, name);
}

/* A decision of grap-core64.aes on Path (another program's image, or a system path) reaching [At, At + Bytes) of
 * kTarget's memory, as a hook would make it; Only: a decision only addr= rules meet. */
Request Memory(uint32_t target, uint32_t rights, const std::string& path, uint64_t at, uint64_t bytes, bool only = false)
{
    Request request{target, rights, kGrap, path, 0, 1u | KB_ADDRESSED | (only ? KB_ADDRESS_ONLY : 0u)};
    request.access.target = kTarget;
    request.access.count = 1;
    request.access.lo[0] = at;
    request.access.hi[0] = at + bytes - 1;
    return request;
}

/* kb_bases for kTarget: MapleStory.exe (module pattern 0) at Base, Size bytes, read when kb_modseq was Seq, for
 * pattern list Gen; kb_modseq is Now. */
void Bases(uint64_t base, uint32_t size, uint32_t seq, uint32_t now, uint32_t gen)
{
    kb_base bases{};
    bases.seq = seq;
    bases.gen = gen;
    bases.present = 1;
    bases.base[0] = base;
    bases.size[0] = size;
    Expect("kb_bases written", bpf_map_update_elem(MapOf("kb_bases"), &kTarget, &bases, BPF_ANY) == 0 &&
                                   bpf_map_update_elem(MapOf("kb_modseq"), &kTarget, &now, BPF_ANY) == 0);
}

/* The event a decision logged names what it reached after its path. */
void ExpectReached(const std::string& name, const Request& request, const std::string& text)
{
    Result result = Decide(request);
    const bool good = result.logged && std::string(result.event.path).find(text) != std::string::npos;
    if (!good) std::printf("  %s: path '%s'\n", name.c_str(), result.event.path);
    Expect(name, good);
}

/* Overlap at a range's edges; a decision that carries no address after one that did (the stale marker); an
 * unknown address; decisions only addr= rules meet; system rules. */
void AddressCase()
{
    const std::string range = "deny|peer|C:\\*\\MapleStory.exe|rights=vm-read|addr=0x140001000-0x140001FFF|image=grap-core64.aes";
    const std::string old = "deny|peer|C:\\*\\explorer.exe|image=grap-core64.aes";
    const std::string uname = "deny|system|/system/uname|addr=0-0xFFFFFFFFFFFFFFFF";
    const std::string self = "deny|system|/system/wine/self/read_process_memory|addr=0x10000-0x1FFFF";
    const std::string text = Head() + range + "\n" + old + "\n" + uname + "\n" + self + "\n";
    Expect("addr= policy loads", Apply(text));
    const uint32_t deny = RuleOf(text, range);
    ExpectDecision("addr=: a read inside the range", Memory(KFILTER_TARGET_PEER, 0x10, kMaple, 0x140001010, 2),
                   KFilterActionDeny, deny);
    ExpectReached("addr=: its event names the address and size", Memory(KFILTER_TARGET_PEER, 0x10, kMaple, 0x140001010, 2),
                  "MapleStory.exe addr=0x0000000140001010+2");
    ExpectDecision("addr=: a read ending just before the range", Memory(KFILTER_TARGET_PEER, 0x10, kMaple, 0x140000FFF, 1), 0, 0);
    ExpectDecision("addr=: a read whose last byte is the range's first (a+len-1 == LO)",
                   Memory(KFILTER_TARGET_PEER, 0x10, kMaple, 0x140000FFF, 2), KFilterActionDeny, deny);
    ExpectDecision("addr=: a read of the range's last byte", Memory(KFILTER_TARGET_PEER, 0x10, kMaple, 0x140001FFF, 1),
                   KFilterActionDeny, deny);
    ExpectDecision("addr=: a read just past the range (a == HI+1)", Memory(KFILTER_TARGET_PEER, 0x10, kMaple, 0x140002000, 1), 0, 0);
    ExpectDecision("addr=: the same request again without an address (the last one's stays in kb_accesses)",
                   {KFILTER_TARGET_PEER, 0x10, kGrap, kMaple, 0, 1}, 0, 0);
    Request unknown = Memory(KFILTER_TARGET_PEER, 0x10, kMaple, 0, 1);
    unknown.access.count = 0;
    unknown.access.unknown = 1;
    ExpectDecision("addr=: an unknown address meets a deny", unknown, KFilterActionDeny, deny);
    ExpectReached("addr=: its event says so", unknown, "MapleStory.exe addr=?");
    ExpectDecision("addr=: a decision only addr= rules decide passes a rights-less rule by",
                   Memory(KFILTER_TARGET_PEER, 0x10, kExplorer, 0x1000, 4, true), 0, 0);
    ExpectDecision("addr=: that rule decides what it decided before", {KFILTER_TARGET_PEER, 0x10, kGrap, kExplorer, 0, 1},
                   KFilterActionDeny, RuleOf(text, old));
    ExpectDecision("addr=: a system decision that reaches no memory",
                   {KFILTER_TARGET_SYSTEM, KFILTER_RIGHT_QUERY, kGrap, "/system/uname"}, 0, 0);
    ExpectDecision("addr=: a program reading itself inside the range",
                   Memory(KFILTER_TARGET_SYSTEM, KFILTER_RIGHT_QUERY, "/system/wine/self/read_process_memory", 0x10010, 4),
                   KFilterActionDeny, RuleOf(text, self));
    ExpectDecision("addr=: ... and outside it",
                   Memory(KFILTER_TARGET_SYSTEM, KFILTER_RIGHT_QUERY, "/system/wine/self/read_process_memory", 0x20000, 4), 0, 0);
}

/* An allow before a deny: an allow decides only what lies within its ranges, a deny whatever overlaps them; an unknown
 * address passes the allow by. */
void AddressOrderCase()
{
    const std::string allow = "allow|peer|C:\\*\\MapleStory.exe|rights=vm-read|addr=0x140001800-0x1400018FF|image=grap-core64.aes";
    const std::string deny = "deny|peer|C:\\*\\MapleStory.exe|rights=vm-read|addr=0x140001000-0x140001FFF|image=grap-core64.aes";
    const std::string text = Head() + allow + "\n" + deny + "\n";
    Expect("addr= order policy loads", Apply(text));
    ExpectDecision("addr= order: the allow's range", Memory(KFILTER_TARGET_PEER, 0x10, kMaple, 0x140001810, 4),
                   KFilterActionAllow, RuleOf(text, allow));
    ExpectDecision("addr= order: the deny's range", Memory(KFILTER_TARGET_PEER, 0x10, kMaple, 0x140001010, 4),
                   KFilterActionDeny, RuleOf(text, deny));
    ExpectDecision("addr= order: an access touching both is not the allow's (bytes past it are the deny's)",
                   Memory(KFILTER_TARGET_PEER, 0x10, kMaple, 0x1400017F0, 0x20), KFilterActionDeny, RuleOf(text, deny));
    Request two = Memory(KFILTER_TARGET_PEER, 0x10, kMaple, 0x140001810, 4);
    two.access.count = 2;
    two.access.lo[1] = 0x140001010;
    two.access.hi[1] = 0x140001013;
    ExpectDecision("addr= order: ... nor one with a second range outside it", two, KFilterActionDeny, RuleOf(text, deny));
    two.access.lo[1] = 0x1400018F0;
    two.access.hi[1] = 0x1400018FF;
    ExpectDecision("addr= order: two ranges within it", two, KFilterActionAllow, RuleOf(text, allow));
    Request unknown = Memory(KFILTER_TARGET_PEER, 0x10, kMaple, 0, 1);
    unknown.access.count = 0;
    unknown.access.unknown = 1;
    ExpectDecision("addr= order: an unknown address is not allowed", unknown, KFilterActionDeny, RuleOf(text, deny));
}

/* Module-relative ranges: from the module's base, cut at its SizeOfImage; a module the current table shows absent
 * matches nothing; a stale table, one of another pattern list, no table and a target kfilter cannot name are
 * unknown (a deny matches, an allow does not). */
void AddressModuleCase()
{
    const std::string allow = "allow|peer|C:\\*\\MapleStory.exe|rights=vm-read|addr=MapleStory.exe+0x2000-0x2FFF|image=grap-core64.aes";
    const std::string code = "deny|peer|C:\\*\\MapleStory.exe|rights=vm-read|"
                             "addr=MapleStory.exe+0x1000-0x1FFF,MapleStory.exe+0x4000-0x7FFF|image=grap-core64.aes";
    const std::string absent = "deny|peer|C:\\*\\MapleStory.exe|rights=vm-read|addr=notloaded.dll+0-0xFFFFFFFF|image=grap-core64.aes";
    const std::string text = Head() + allow + "\n" + code + "\n" + absent + "\n";
    Expect("addr= module policy loads", Apply(text));
    const uint64_t base = 0x140000000;
    const uint32_t gen = KfBpfModuleGeneration();
    Bases(base, 0x6000, 5, 5, gen);
    ExpectDecision("module: inside the first range", Memory(KFILTER_TARGET_PEER, 0x10, kMaple, base + 0x1010, 2),
                   KFilterActionDeny, RuleOf(text, code));
    ExpectDecision("module: inside the second range", Memory(KFILTER_TARGET_PEER, 0x10, kMaple, base + 0x5800, 2),
                   KFilterActionDeny, RuleOf(text, code));
    ExpectDecision("module: past SizeOfImage the range has ended", Memory(KFILTER_TARGET_PEER, 0x10, kMaple, base + 0x6800, 2), 0, 0);
    ExpectDecision("module: elsewhere in the image (and the module not loaded matches nothing)",
                   Memory(KFILTER_TARGET_PEER, 0x10, kMaple, base + 0x10, 2), 0, 0);
    ExpectDecision("module: the allow's range", Memory(KFILTER_TARGET_PEER, 0x10, kMaple, base + 0x2010, 2),
                   KFilterActionAllow, RuleOf(text, allow));
    Bases(base, 0x6000, 5, 6, gen);   /* the program mapped an image after kfilterd read its maps */
    ExpectDecision("module: a stale table meets the deny", Memory(KFILTER_TARGET_PEER, 0x10, kMaple, base + 0x10, 2),
                   KFilterActionDeny, RuleOf(text, code));
    ExpectDecision("module: ... and passes the allow by", Memory(KFILTER_TARGET_PEER, 0x10, kMaple, base + 0x2010, 2),
                   KFilterActionDeny, RuleOf(text, code));
    Bases(base, 0x6000, 5, 5, gen + 1);   /* read for another pattern list */
    ExpectDecision("module: a table of another pattern list is not current",
                   Memory(KFILTER_TARGET_PEER, 0x10, kMaple, base + 0x10, 2), KFilterActionDeny, RuleOf(text, code));
    Expect("kb_bases entry removed", bpf_map_delete_elem(MapOf("kb_bases"), &kTarget) == 0);
    ExpectDecision("module: no table", Memory(KFILTER_TARGET_PEER, 0x10, kMaple, base + 0x10, 2), KFilterActionDeny,
                   RuleOf(text, code));
    Bases(base, 0x6000, 5, 5, gen);
    Request unnamed = Memory(KFILTER_TARGET_PEER, 0x10, kMaple, base + 0x10, 2);
    unnamed.access.target = 0;
    ExpectDecision("module: a target kfilter cannot name", unnamed, KFilterActionDeny, RuleOf(text, code));
    ExpectDecision("module: current again", Memory(KFILTER_TARGET_PEER, 0x10, kMaple, base + 0x10, 2), 0, 0);
}

/* Capacity: 9 addr= rules on one literal path (the 9th goes to the wildcard list) and 320 ranges in 20 wildcard
 * rules, one slot each. */
void AddressSpillCase()
{
    std::string text = Head();
    std::vector<std::string> literal;
    for (int i = 1; i <= 9; i++) {
        char rule[256];
        std::snprintf(rule, sizeof(rule), "deny|peer|%s|rights=vm-read|addr=0x15000%d000-0x15000%dfff|image=grap-core64.aes",
                      kMaple, i, i);
        literal.push_back(rule);
        text += literal.back() + "\n";
    }
    std::string last;
    for (int rule = 1; rule <= 20; rule++) {
        std::string ranges;
        for (int i = 0; i < 16; i++) {
            char item[64];
            const unsigned long long at = 0x160000000ull + (unsigned long long)(rule * 16 + i) * 0x1000;
            std::snprintf(item, sizeof(item), "%s0x%llx-0x%llx", i != 0 ? "," : "", at, at + 0xFFF);
            ranges += item;
        }
        last = "deny|peer|C:\\*\\MapleStory.exe|rights=vm-write|addr=" + ranges + "|image=grap-core64.aes";
        text += last + "\n";
    }
    Expect("9 addr= rules on one path and 320 ranges in 20 wildcard rules load", Apply(text));
    ExpectDecision("the 9th addr= rule on one path decides", Memory(KFILTER_TARGET_PEER, 0x10, kMaple, 0x150009800, 4),
                   KFilterActionDeny, RuleOf(text, literal[8]));
    ExpectDecision("the 1st too", Memory(KFILTER_TARGET_PEER, 0x10, kMaple, 0x150001800, 4), KFilterActionDeny,
                   RuleOf(text, literal[0]));
    ExpectDecision("the 16th range of the 20th list rule",
                   Memory(KFILTER_TARGET_PEER, 0x20, kMaple, 0x160000000ull + (20 * 16 + 15) * 0x1000ull + 0x10, 4),
                   KFilterActionDeny, RuleOf(text, last));
}

/* A Wine request (16 header words) with its data in one chunk, as the bench's process (grap-core64.aes) makes it. */
Request Wine(std::vector<uint32_t> header, const void* data = nullptr, uint32_t size = 0)
{
    Request request{0, 0, kGrap, ""};
    header.resize(16);
    request.wine = header;
    if (data != nullptr) request.chunks.push_back({data, size});
    return request;
}

/*
 * Wine requests through kb_wine_query, as the request pipe's hook decides them: the address and size of a read and
 * a write, VirtualQueryEx's APC, a hardware breakpoint, a request with no address after one with an address (the
 * stale marker), a handle kfilter cannot name (\@unknown: rules naming it alone), one a get_process_info reply
 * named (kb_learnt: addr= rules alone use it), and its own memory by pseudo handle. Handles of this process: 0x100
 * to MapleStory.exe (kTarget), 0x104 to a thread of it, 0x108 not seen made, 0x10C named by a reply.
 */
/* kTarget named MapleStory.exe, and this process's handles 0x100 to it and 0x104 to a thread of it. */
void TargetHandles()
{
    const __u32 self = (__u32)getpid();
    kb_proc target{};
    target.ilen = (__u32)strlen(kMaple);
    target.ibase = (__u32)std::string(kMaple).rfind('\\') + 1;
    memcpy(target.image, kMaple, target.ilen);
    const kb_ohandle process{kTarget, 0, 0x1FFFFF, 0}, thread{kTarget, 1, 0x1FFFFF, 0};
    const kb_hkey_id processId{self, 0x100}, threadId{self, 0x104};
    Expect("handles written", bpf_map_update_elem(MapOf("kb_procs"), &kTarget, &target, BPF_ANY) == 0 &&
                                  bpf_map_update_elem(MapOf("kb_ohandles"), &processId, &process, BPF_ANY) == 0 &&
                                  bpf_map_update_elem(MapOf("kb_ohandles"), &threadId, &thread, BPF_ANY) == 0);
}

void AddressRequestCase()
{
    const __u32 self = (__u32)getpid();
    const kb_hkey_id learntId{self, 0x10C};
    TargetHandles();
    Expect("learnt handle written", bpf_map_update_elem(MapOf("kb_learnt"), &learntId, &kTarget, BPF_ANY) == 0);
    const std::string read = "deny|peer|C:\\*\\MapleStory.exe|rights=vm-read|addr=0x140001000-0x140001FFF|image=grap-core64.aes";
    const std::string query = "deny|peer|C:\\*\\MapleStory.exe|rights=query-information|addr=0x140001000-0x140001FFF|image=grap-core64.aes";
    const std::string breakpoint = "deny|thread-peer|C:\\*\\MapleStory.exe|rights=set-context|addr=0x140001000-0x140001FFF|image=grap-core64.aes";
    const std::string unknown = "deny|peer|\\@unknown|rights=query-information|addr=0x140005000-0x140005FFF|image=grap-core64.aes";
    const std::string any = "deny|peer|C:\\*\\MapleStory.exe|addr=0x140003000-0x140003FFF|image=grap-core64.aes";
    const std::string own = "deny|system|/system/wine/self/read_process_memory|addr=0x10000-0x1FFFF|image=grap-core64.aes";
    const std::string text = Head() + read + "\n" + query + "\n" + breakpoint + "\n" + unknown + "\n" + any + "\n" + own + "\n";
    Expect("addr= request policy loads", Apply(text));
    ExpectDecision("request: read_process_memory inside (reply_size bytes)", Wine({84, 0, 2, 0x100, 0x40001010, 1}),
                   KFilterActionDeny, RuleOf(text, read));
    ExpectReached("request: its event", Wine({84, 0, 2, 0x100, 0x40001010, 1}), "MapleStory.exe addr=0x0000000140001010+2");
    ExpectDecision("request: read_process_memory outside", Wine({84, 0, 2, 0x100, 0x40002010, 1}), 0, 0);
    ExpectDecision("request: write_process_memory (request_size bytes) meets a rights-less addr= rule",
                   Wine({85, 4, 0, 0x100, 0x40003FFE, 1}), KFilterActionDeny, RuleOf(text, any));
    ExpectDecision("request: get_process_info right after it carries no address", Wine({9, 0, 0, 0x100}), 0, 0);
    uint64_t apc[8] = {6 /* APC_VIRTUAL_QUERY */, 0x140001010};
    ExpectDecision("request: VirtualQueryEx inside", Wine({19, 64, 0, 0x100}, apc, sizeof(apc)), KFilterActionDeny,
                   RuleOf(text, query));
    apc[1] = 0x140002010;
    ExpectDecision("request: VirtualQueryEx outside", Wine({19, 64, 0, 0x100}, apc, sizeof(apc)), 0, 0);
    std::vector<uint8_t> context(1720);
    const uint32_t head[2] = {0x8664, 0x10 /* SERVER_CTX_DEBUG_REGISTERS */};
    const uint64_t dr0 = 0x140001010, dr7 = 0x10001;   /* DR0 enabled, a 1-byte write watch */
    memcpy(context.data(), head, sizeof(head));
    memcpy(context.data() + 824, &dr0, sizeof(dr0));
    memcpy(context.data() + 824 + 40, &dr7, sizeof(dr7));
    ExpectDecision("request: a hardware breakpoint inside", Wine({106, 1720, 0, 0x104}, context.data(), 1720),
                   KFilterActionDeny, RuleOf(text, breakpoint));
    const uint64_t cleared = 0;
    memcpy(context.data() + 824 + 40, &cleared, sizeof(cleared));
    ExpectDecision("request: breakpoints cleared carry no address", Wine({106, 1720, 0, 0x104}, context.data(), 1720), 0, 0);
    apc[1] = 0x140005010;
    ExpectDecision("request: VirtualQueryEx through a handle kfilter cannot name: \\@unknown",
                   Wine({19, 64, 0, 0x108}, apc, sizeof(apc)), KFilterActionDeny, RuleOf(text, unknown));
    apc[1] = 0x140001010;
    ExpectDecision("request: ... a rule naming MapleStory.exe does not meet it", Wine({19, 64, 0, 0x108}, apc, sizeof(apc)), 0, 0);
    ExpectDecision("request: GetMappedFileName through a handle a reply named: addr= rules on that program",
                   Wine({75, 0, 0, 0x10C, 0x40001010, 1}), KFilterActionDeny, RuleOf(text, query));
    ExpectDecision("request: reading itself by pseudo handle", Wine({84, 0, 4, 0xFFFFFFFF, 0x10010, 0}), KFilterActionDeny,
                   RuleOf(text, own));
    // The learnt target serves addr= rules alone: a rights-less peer deny without addr= meets requests through a
    // handle kfilter named, never through one a reply named; \@unknown is met by rules naming it alone, not by a
    // wildcard that matches it (\*: these requests were not decided before it); get_image_view_info is only addr=
    // rules' to meet.
    const std::string wild = "deny|peer|\\*|image=grap-core64.aes";
    const std::string everything = "deny|peer|C:\\*\\MapleStory.exe|image=grap-core64.aes";
    const std::string active = "deny|peer|C:\\*\\explorer.exe|rights=vm-read|addr=0-0xF|image=nobody.exe";
    const std::string plain = Head() + wild + "\n" + everything + "\n" + active + "\n";
    Expect("rights-less policy loads", Apply(plain));
    ExpectDecision("learnt: a rights-less deny does not meet a request through a handle a reply named",
                   Wine({75, 0, 0, 0x10C, 0x40001010, 1}), 0, 0);
    ExpectDecision("learnt: ... nor a query through it", Wine({9, 0, 0, 0x10C}), 0, 0);
    ExpectDecision("learnt: it meets the same request through a handle kfilter named", Wine({75, 0, 0, 0x100, 0x40001010, 1}),
                   KFilterActionDeny, RuleOf(plain, everything));
    ExpectDecision("unknown: \\* meets the path \\@unknown in any other decision",
                   {KFILTER_TARGET_PEER, 0x400, kGrap, "\\@unknown", 0, 1}, KFilterActionDeny, RuleOf(plain, wild));
    ExpectDecision("unknown: ... not a query through a handle kfilter cannot name", Wine({9, 0, 0, 0x108}), 0, 0);
    ExpectDecision("unknown: ... nor VirtualQueryEx through it", Wine({19, 64, 0, 0x108}, apc, sizeof(apc)), 0, 0);
    ExpectDecision("learnt: get_image_view_info is met by addr= rules alone", Wine({70, 0, 0, 0x100, 0x40001010, 1}), 0, 0);
}

/* A vararg split over iovecs, which wineserver joins: so does kfilter (kb_request_data), so a context or an APC whose
 * address lies past the first chunk is decided on its whole; chunks that do not add up to request_size are refused as
 * a write Wine never makes. And an i386 program's context, whose debug registers are 32-bit. */
void AddressSplitCase()
{
    TargetHandles();
    const std::string query = "deny|peer|C:\\*\\MapleStory.exe|rights=query-information|addr=0x140001000-0x140001FFF|image=grap-core64.aes";
    const std::string breakpoint = "deny|thread-peer|C:\\*\\MapleStory.exe|rights=set-context|"
                                   "addr=0x140001000-0x140001FFF,0x40001000-0x40001FFF|image=grap-core64.aes";
    const std::string text = Head() + query + "\n" + breakpoint + "\n";
    Expect("split policy loads", Apply(text));
    std::vector<uint8_t> context(1720);
    const uint32_t head[2] = {0x8664, 0x10 /* SERVER_CTX_DEBUG_REGISTERS */};
    uint64_t dr0 = 0x140005010;
    const uint64_t dr7 = 0x10001;   /* DR0 enabled */
    memcpy(context.data(), head, sizeof(head));
    memcpy(context.data() + 824, &dr0, sizeof(dr0));
    memcpy(context.data() + 824 + 40, &dr7, sizeof(dr7));
    auto split = [](std::vector<uint32_t> header, const uint8_t* data, uint32_t first, uint32_t size) {
        Request request = Wine(header);
        request.chunks = {{data, first}, {data + first, size - first}};
        return request;
    };
    ExpectDecision("split: a whole context with its breakpoint outside", Wine({106, 1720, 0, 0x104}, context.data(), 1720), 0, 0);
    ExpectDecision("split: the same context in two chunks (824 and 896 bytes)",
                   split({106, 1720, 0, 0x104}, context.data(), 824, 1720), 0, 0);
    dr0 = 0x140001010;
    memcpy(context.data() + 824, &dr0, sizeof(dr0));
    ExpectDecision("split: its breakpoint inside, split in the middle of DR0", split({106, 1720, 0, 0x104}, context.data(), 828, 1720),
                   KFilterActionDeny, RuleOf(text, breakpoint));
    uint64_t apc[8] = {6 /* APC_VIRTUAL_QUERY */, 0x140005010};
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(apc);
    ExpectDecision("split: a whole VirtualQueryEx outside", Wine({19, 64, 0, 0x100}, apc, sizeof(apc)), 0, 0);
    ExpectDecision("split: its type alone in the first chunk", split({19, 64, 0, 0x100}, bytes, 8, 64), 0, 0);
    apc[1] = 0x140001010;
    ExpectDecision("split: ... and inside", split({19, 64, 0, 0x100}, bytes, 8, 64), KFilterActionDeny, RuleOf(text, query));
    // A first chunk of 824 bytes where the header says 1720: no writev Wine makes, refused (a would-be split past
    // what kfilter decided), and logged as a raw request.
    Result shortWrite = Decide(Wine({106, 1720, 0, 0x104}, context.data(), 824));
    Expect("split: chunks short of request_size are refused as a raw request",
           shortWrite.ran && shortWrite.decided && shortWrite.verdict != 0 && shortWrite.logged &&
               shortWrite.event.target == KFILTER_TARGET_PROCESS && shortWrite.event.value == 0x4000 &&
               shortWrite.event.rule_id == 0);
    Result longWrite = Decide(split({19, 60, 0, 0x100}, bytes, 8, 64));
    Expect("split: ... and so are chunks past it", longWrite.ran && longWrite.decided && longWrite.verdict != 0 &&
                                                       longWrite.event.value == 0x4000);
    std::vector<uint8_t> i386(1720);
    const uint32_t head32[2] = {0x14c, 0x10}, dr7_32 = 0x10001;
    uint32_t dr0_32 = 0x40001010;
    memcpy(i386.data(), head32, sizeof(head32));
    memcpy(i386.data() + 824, &dr0_32, sizeof(dr0_32));
    memcpy(i386.data() + 824 + 20, &dr7_32, sizeof(dr7_32));   /* dr7 after dr0-dr3 and dr6, 4 bytes each */
    ExpectDecision("i386 context: a breakpoint inside", Wine({106, 1720, 0, 0x104}, i386.data(), 1720), KFilterActionDeny,
                   RuleOf(text, breakpoint));
    dr0_32 = 0x40005010;
    memcpy(i386.data() + 824, &dr0_32, sizeof(dr0_32));
    ExpectDecision("i386 context: a breakpoint outside", Wine({106, 1720, 0, 0x104}, i386.data(), 1720), 0, 0);
    // Two contexts (WoW64: native and wow64), 3,440 bytes in three chunks: the second one's breakpoint decides.
    std::vector<uint8_t> two(2 * 1720);
    memcpy(two.data() + 1720, i386.data(), 1720);
    dr0_32 = 0x40001010;
    memcpy(two.data() + 1720 + 824, &dr0_32, sizeof(dr0_32));
    Request three = Wine({106, 3440, 0, 0x104});
    three.chunks = {{two.data(), 1000}, {two.data() + 1000, 2000}, {two.data() + 3000, 440}};
    ExpectDecision("split: a second context's breakpoint across three chunks", three, KFilterActionDeny, RuleOf(text, breakpoint));
}

/* Rules naming \@unknown past KB_PER_PATH on that path go to the wildcard list, where a decision on \@unknown still
 * meets them; a wildcard rule that matches \@unknown never does. */
void UnknownSpillCase()
{
    std::string rules;
    for (int i = 1; i <= 8; i++) rules += "deny|peer|\\@unknown|image=p" + std::to_string(i) + ".exe\n";
    const std::string mine = "deny|peer|\\@unknown|image=grap-core64.aes";
    const std::string wild = "deny|peer|\\@unknow*|image=grap-core64.aes";
    const std::string text = Head() + wild + "\n" + rules + mine + "\n";
    Expect("unknown spill policy loads", Apply(text));
    ExpectDecision("the 9th rule naming \\@unknown decides a query through a handle kfilter cannot name",
                   Wine({9, 0, 0, 0x108}), KFilterActionDeny, RuleOf(text, mine));
}

/* A decision on memory that a rule without addr= makes logs its bare path, as before addr= (the loop's tools match
 * it, and repeats collapse); one an addr= rule makes adds what it reached. */
void EventPathCase()
{
    TargetHandles();
    const std::string peer = "deny|peer|C:\\*\\MapleStory.exe|rights=vm-read|image=grap-core64.aes";
    const std::string range = "deny|peer|C:\\*\\MapleStory.exe|rights=vm-write|addr=0x140001000-0x140001FFF|image=grap-core64.aes";
    const std::string text = Head() + range + "\n" + peer + "\n";
    Expect("event path policy loads", Apply(text));
    Result read = Decide(Wine({84, 0, 2, 0x100, 0x40001010, 1}));
    Expect("event path: a rule without addr= logs the bare path",
           read.logged && read.event.rule_id == RuleOf(text, peer) && std::string(read.event.path) == kMaple);
    ExpectReached("event path: an addr= rule's adds the address", Wine({85, 4, 0, 0x100, 0x40001010, 1}),
                  "MapleStory.exe addr=0x0000000140001010+4");
}

/* Wine requests as kb_bench.wine 2 and 3 run them: wineserver's reply to this thread's pending request, and a change
 * of this program's module table (Request 0: code made executable; else a request it sent). */
Request Reply(const void* reply)
{
    Request request = Wine({0}, reply, 64);
    request.kind = 2;
    return request;
}

Request ModuleChange(uint32_t req)
{
    Request request = Wine({req});
    request.kind = 3;
    return request;
}

/* What wineserver's replies teach, read as kb_wineserver_pipe reads them (kb_learnt): a get_process_info reply names
 * the process behind a handle kfilter could not name, for the addr= decisions after it (decided on \@unknown's ranges
 * until then), and a get_thread_info reply a thread handle's; one naming the requester itself makes no peer of it.
 * Handles of this process: 0x120 and 0x128 process handles, 0x124 a thread handle, none seen made. */
void LearnCase()
{
    TargetHandles();
    const __u32 self = (__u32)getpid(), winpid = 0x3F0, selfWinpid = 0x3F4;
    Expect("learn: Windows ids written", bpf_map_update_elem(MapOf("kb_wintids"), &winpid, &kTarget, BPF_ANY) == 0 &&
                                             bpf_map_update_elem(MapOf("kb_wintids"), &selfWinpid, &self, BPF_ANY) == 0);
    const std::string query = "deny|peer|C:\\*\\MapleStory.exe|rights=query-information|addr=0x140001000-0x140001FFF|image=grap-core64.aes";
    const std::string unknown = "deny|peer|\\@unknown|rights=query-information|addr=0x140005000-0x140005FFF|image=grap-core64.aes";
    const std::string itself = "deny|peer|C:\\*\\grap-core64.aes|rights=query-information|addr=0-0xFFFFFFFFFFFFFFFF|image=grap-core64.aes";
    const std::string text = Head() + query + "\n" + unknown + "\n" + itself + "\n";
    Expect("learn policy loads", Apply(text));
    uint64_t apc[8] = {6 /* APC_VIRTUAL_QUERY */, 0x140001010};
    ExpectDecision("learn: VirtualQueryEx through a handle not named yet meets \\@unknown's ranges alone",
                   Wine({19, 64, 0, 0x120}, apc, sizeof(apc)), 0, 0);
    Decide(Wine({9, 0, 0, 0x120}));   /* get_process_info: kept for its reply */
    uint32_t reply[16] = {0, 0, winpid};   /* status, reply_size, pid@0x8 */
    Expect("learn: wineserver's reply is read for it", Decide(Reply(reply)).decided);
    ExpectDecision("learn: then the addr= rule on the program it named decides",
                   Wine({19, 64, 0, 0x120}, apc, sizeof(apc)), KFilterActionDeny, RuleOf(text, query));
    Decide(Wine({14, 0, 0, 0x124}));   /* get_thread_info */
    Decide(Reply(reply));
    const kb_hkey_id thread{self, 0x124};
    __u32 learnt = 0;
    Expect("learn: a get_thread_info reply names the thread's process",
           bpf_map_lookup_elem(MapOf("kb_learnt"), &thread, &learnt) == 0 && learnt == kTarget);
    Decide(Wine({9, 0, 0, 0x128}));
    reply[2] = selfWinpid;
    Decide(Reply(reply));
    ExpectDecision("learn: a reply naming the requester itself makes no peer decision",
                   Wine({19, 64, 0, 0x128}, apc, sizeof(apc)), 0, 0);
}

/* ---- every Wine request decidable as /system/wine/<request> ---- */

/* Every request of protocol 930 by number (kfilter_bpf.h); the right its decision asks for, by its name: query to read
 * or open, create, else write. */
#define KB_WNAME_TEXT(name, right) #name,
const char* const kRequests[] = {KB_WINE_REQUESTS(KB_WNAME_TEXT)};
#undef KB_WNAME_TEXT

uint32_t RightOf(const std::string& name)
{
    for (const char* prefix : {"get", "query", "enum", "list", "is_", "find_", "check_", "compare_", "open_"}) {
        if (name.rfind(prefix, 0) == 0) return KFILTER_RIGHT_QUERY;
    }
    return name.rfind("create_", 0) == 0 ? KFILTER_RIGHT_CREATE : KFILTER_RIGHT_WRITE;
}

/* The requests kfilter decided before every request was (kfilter.bpf.c kb_wreqs), by how: their decisions stay. */
enum Row { kNamed, kHandle, kThread, kPlain, kCreate, kOpen, kEither };
Row RowOf(uint32_t req)
{
    switch (req) {
    case 8: case 17: case 18: case 105: case 106: return kThread;
    case 7: case 9: case 10: case 11: case 12: case 13: case 19: case 70: case 75: case 82: case 84: case 85:
    case 291: case 292: return kHandle;
    case 16: case 76: case 151: case 154: case 157: case 222: case 234: case 235: case 236: case 241: case 244:
        return kPlain;
    case 30: case 36: case 40: case 63: case 239: case 242: return kCreate;
    case 33: case 38: case 43: case 64: case 171: case 178: case 240: case 243: return kOpen;
    case 220: return kEither;
    default: return kNamed;
    }
}

/* Index: each request number names its own request, past the kernel's old 24-byte names (the 30 characters of
 * get_window_children_from_point), with the right its name says; a number past the protocol decides nothing. Every
 * request without a row of its own, through rules naming each. */
void WineIndexCase()
{
    std::string text = Head();
    for (const char* name : kRequests) text += std::string("deny|system|/system/wine/") + name + "|image=grap-core64.aes\n";
    Expect("index policy loads", Apply(text));
    const uint32_t base = RuleOf(text, std::string("deny|system|/system/wine/") + kRequests[0] + "|image=grap-core64.aes");
    int wrong = 0, named = 0;
    for (uint32_t req = 0; req < KB_REQ_COUNT; req++) {
        if (RowOf(req) != kNamed) continue;
        named++;
        Result result = Decide(Wine({req}));
        const std::string path = std::string("/system/wine/") + kRequests[req];
        if (result.ran && result.decided && result.verdict != 0 && result.logged && result.event.rule_id == base + req &&
            path == result.event.path && result.event.rights == RightOf(kRequests[req]))
            continue;
        if (wrong++ < 5) std::printf("  index %u (%s): %s path '%s' rights 0x%x\n", req, kRequests[req],
                                     Describe(result).c_str(), result.event.path, result.event.rights);
    }
    Expect("index: every request without a row of its own (261) is decided by the rule naming it", wrong == 0 && named == 261);
    for (uint32_t req : {306u, 307u, 511u, 0xFFFFu, 0x80000000u}) {
        ExpectDecision("index: request number " + std::to_string(req) + " decides nothing", Wine({req}), 0, 0);
    }
}

/* kb_wnamed, the gate: a request without a row of its own is decided only where some rule names it past
 * /system/wine/ (a literal path, or a pattern whose fixed text reaches into its name); rules that reach /system/wine/
 * only as a parent or with a star at once keep meeting exactly what they met (a row's request), never select,
 * init_thread, close_handle or get_message. */
void WineNamedCase()
{
    const std::string broad[] = {"deny|system|/system", "deny|system|/system/wine", "deny|system|/system/wine/*",
                                 "deny|system|/system/*", "deny|system|/system/w*", "deny|system|/system/wine/*/x"};
    std::string text = Head();
    for (const std::string& rule : broad) text += rule + "\n";
    const std::string message = "audit|system|/system/wine/get_message|image=grap-core64.aes";
    const std::string keys = "deny|system|/system/wine/get_key*|image=grap-core64.aes";
    const std::string timerWrite = "deny|system|/system/wine/open_timer|rights=write";
    const std::string timer = "deny|system|/system/wine/open_timer|rights=query|image=grap-core64.aes";
    const std::string event = "deny|system|/system/wine/create_timer|image=MapleStory.exe";
    text += message + "\n" + keys + "\n" + timerWrite + "\n" + timer + "\n" + event + "\n";
    Expect("named policy loads", Apply(text));
    ExpectDecision("named: a broad rule (the literal parent /system, which KB_WINE_ROOT skips only for requests without a "
                   "row of their own) still decides a request with a row of its own (list_processes)", Wine({76}),
                   KFilterActionDeny, RuleOf(text, broad[0]));
    ExpectDecision("named: ... and any other system decision under it", {KFILTER_TARGET_SYSTEM, KFILTER_RIGHT_QUERY, kGrap,
                   "/system/sysinfo"}, KFilterActionDeny, RuleOf(text, broad[0]));
    for (uint32_t req : {29u /* select */, 6u /* init_thread */, 21u /* close_handle */, 125u /* get_message_reply */}) {
        ExpectDecision(std::string("named: no broad rule meets ") + kRequests[req], Wine({req}), 0, 0);
    }
    ExpectDecision("named: get_message by the rule naming it, past every broad one", Wine({122}), KFilterActionAudit,
                   RuleOf(text, message));
    ExpectDecision("named: get_key_state by a pattern reaching into its name", Wine({190}), KFilterActionDeny, RuleOf(text, keys));
    ExpectDecision("named: ... get_key_value too (a registry request: its own decision is /system/wine first)", Wine({92}),
                   KFilterActionDeny, RuleOf(text, keys));
    ExpectDecision("named: open_timer is a query: a write rule passes it by", Wine({101}), KFilterActionDeny, RuleOf(text, timer));
    Result created = Decide(Wine({100}));
    Expect("named: a rule for another program (create_timer, image=MapleStory.exe) decides nothing here",
           created.ran && !created.logged && created.verdict == 0);
    Result query = Decide(Wine({122}));
    Expect("named: get_message asks query", query.logged && query.event.rights == KFILTER_RIGHT_QUERY);
    // The gate's bits: the requests these rules name, and only those (a row's request needs none).
    std::vector<__u64> bits(KB_WNAMED_WORDS), expected(KB_WNAMED_WORDS);
    for (uint32_t req : {122u, 92u, 190u, 101u, 100u}) expected[req / 64] |= 1ull << (req % 64);
    for (__u32 word = 0; word < KB_WNAMED_WORDS; word++) bpf_map_lookup_elem(MapOf("kb_wnamed"), &word, &bits[word]);
    Expect("named: kb_wnamed holds exactly the named requests", bits == expected);
    uint64_t computed[KB_WNAMED_WORDS] = {};
    Config config = Parse(text);
    if (config) KfBpfWineNamed(config.get(), computed);
    Expect("named: kfilterd computes the same bits", config && std::vector<__u64>(computed, computed + KB_WNAMED_WORDS) == expected);
    // A policy without them: every bit goes, and get_message is no decision again.
    Expect("named: a policy naming none loads", Apply(Head() + broad[2] + "\n"));
    for (__u32 word = 0; word < KB_WNAMED_WORDS; word++) bpf_map_lookup_elem(MapOf("kb_wnamed"), &word, &bits[word]);
    Expect("named: no bit is left", bits == std::vector<__u64>(KB_WNAMED_WORDS));
    ExpectDecision("named: get_message decides nothing again", Wine({122}), 0, 0);
}

/* UTF-16 of Text. */
std::vector<uint8_t> Utf16(const std::string& text)
{
    std::vector<uint8_t> bytes;
    for (char c : text) {
        bytes.push_back((uint8_t)c);
        bytes.push_back(0);
    }
    return bytes;
}

/* An objattr (rootdir, attributes, sd_len, name_len; no sd) naming Name, as Wine sends a create's. */
std::vector<uint8_t> Objattr(const std::string& name)
{
    const std::vector<uint8_t> text = Utf16(name);
    const uint32_t head[4] = {0, 0, 0, (uint32_t)text.size()};
    std::vector<uint8_t> bytes((const uint8_t*)head, (const uint8_t*)head + sizeof(head));
    bytes.insert(bytes.end(), text.begin(), text.end());
    return bytes;
}

/* A request whose data comes in chunks of the sizes listed, the rest in the last one. */
Request Chunked(std::vector<uint32_t> header, const std::vector<uint8_t>& data, std::vector<uint32_t> sizes, uint32_t kind = 1)
{
    Request request = Wine(header);
    request.kind = kind;
    uint32_t at = 0;
    for (uint32_t size : sizes) {
        request.chunks.push_back({data.data() + at, size});
        at += size;
    }
    if (at < data.size()) request.chunks.push_back({data.data() + at, (uint32_t)(data.size() - at)});
    return request;
}

/* A name split across chunks (wine_server_call lets a program chunk its data as it likes) is decided whole, as
 * wineserver reads it: a named object's open and create, a registry key, an NT object. */
void WineSplitNameCase()
{
    const std::string mutex = "deny|system|/system/wine/open_mutex/Global\\Cheat|image=grap-core64.aes";
    const std::string created = "deny|system|/system/wine/create_event/Local\\Marker|image=grap-core64.aes";
    const std::string key = "deny|registry|\\Registry\\Machine\\Software\\Cheat\\Engine";
    const std::string pipe = "deny|pipe|\\??\\pipe\\cheatpipe";
    const std::string text = Head() + mutex + "\n" + created + "\n" + key + "\n" + pipe + "\n";
    Expect("split name policy loads", Apply(text));
    const std::vector<uint8_t> name = Utf16("Global\\Cheat");
    const uint32_t size = (uint32_t)name.size();
    ExpectDecision("split name: open_mutex whole", Chunked({38, size}, name, {}), KFilterActionDeny, RuleOf(text, mutex));
    ExpectDecision("split name: open_mutex in two chunks", Chunked({38, size}, name, {8}), KFilterActionDeny, RuleOf(text, mutex));
    ExpectDecision("split name: ... split inside a character", Chunked({38, size}, name, {7}), KFilterActionDeny,
                   RuleOf(text, mutex));
    ExpectDecision("split name: ... in five chunks", Chunked({38, size}, name, {1, 3, 5, 7}), KFilterActionDeny,
                   RuleOf(text, mutex));
    const std::vector<uint8_t> attributes = Objattr("Local\\Marker");
    const uint32_t objattr = (uint32_t)attributes.size();
    ExpectDecision("split name: create_event, the objattr header alone in the first chunk",
                   Chunked({30, objattr}, attributes, {16}), KFilterActionDeny, RuleOf(text, created));
    const std::vector<uint8_t> keyName = Utf16("\\Registry\\Machine\\Software\\Cheat\\Engine");
    ExpectDecision("split name: open_key, a key name split after Cheat",
                   Chunked({87, (uint32_t)keyName.size(), 0, 0, 0x20019}, keyName, {64}, 4), KFilterActionDeny,
                   RuleOf(text, key));
    const std::vector<uint8_t> pipeName = Utf16("\\??\\pipe\\cheatpipe");
    ExpectDecision("split name: open_file_object of a named pipe, split", 
                   Chunked({45, (uint32_t)pipeName.size(), 0, 0x120089}, pipeName, {10}, 4), KFilterActionDeny,
                   RuleOf(text, pipe));
}

/* Handles kb_hkeys names: get/set_security_object on any of them (a key, an NT object opened by name, a named pipe, an
 * object directory) is a registry decision on its name, as it was before kfilter kept their kinds: the file and pipe
 * rules on their names never meet it. The names come from the opens' replies, as kb_wineserver_pipe reads them. */
void SecurityObjectCase()
{
    const std::string anyKey = "deny|registry|\\*|rights=set-security|image=grap-core64.aes";
    const std::string pipeQuery = "deny|pipe|\\??\\pipe\\x|rights=query|image=grap-core64.aes";
    const std::string fileSet = "deny|file|\\Device\\Foo|rights=set-security|image=grap-core64.aes";
    const std::string text = Head() + pipeQuery + "\n" + fileSet + "\n" + anyKey + "\n";
    Expect("security policy loads", Apply(text));
    auto opened = [&](uint32_t req, const std::string& name, uint32_t handle) {
        const std::vector<uint8_t> data = req == 239 ? Objattr(name) : Utf16(name);
        const uint32_t size = (uint32_t)data.size();
        /* open_file_object: access, attributes, rootdir; open_key: parent, access; create_directory: access */
        const std::vector<uint32_t> header = req == 45 ? std::vector<uint32_t>{req, size, 0, 0x120089, 0, 0}
                                           : req == 87 ? std::vector<uint32_t>{req, size, 0, 0, 0x20019, 0}
                                                       : std::vector<uint32_t>{req, size, 0, 0xF000F};
        Result open = Decide(Chunked(header, data, {}, 4));
        uint32_t reply[16] = {0, 0, handle};
        Result recorded = Decide(Reply(reply));
        return open.ran && open.verdict == 0 && recorded.decided;
    };
    Expect("security: a pipe, a device and a key opened, a directory created",
           opened(45, "\\??\\pipe\\x", 0x200) && opened(45, "\\Device\\Foo", 0x204) &&
               opened(87, "\\Registry\\Machine\\Software\\K", 0x208) && opened(239, "\\BaseNamedObjects\\D", 0x20C));
    Result pipeRead = Decide(Chunked({233, 0, 0, 0x200, 4}, {}, {}, 4));
    Expect("security: GetSecurityInfo on the pipe is a registry read, not the pipe rule's query",
           pipeRead.verdict == 0 && pipeRead.logged && pipeRead.event.target == KFILTER_TARGET_REGISTRY &&
               pipeRead.event.rights == KFILTER_RIGHT_READ);
    Result pipeSet = Decide(Chunked({232, 0, 0, 0x200, 4}, {}, {}, 4));
    Expect("security: SetSecurityInfo on the pipe is the registry's set-security",
           pipeSet.verdict != 0 && pipeSet.event.target == KFILTER_TARGET_REGISTRY && pipeSet.event.rule_id == RuleOf(text, anyKey));
    Result fileSetResult = Decide(Chunked({232, 0, 0, 0x204, 4}, {}, {}, 4));
    Expect("security: SetSecurityInfo on \\Device\\Foo too (the file rule does not meet it)",
           fileSetResult.verdict != 0 && fileSetResult.event.target == KFILTER_TARGET_REGISTRY &&
               fileSetResult.event.rule_id == RuleOf(text, anyKey));
    Result keySet = Decide(Chunked({232, 0, 0, 0x208, 4}, {}, {}, 4));
    Expect("security: a key's", keySet.verdict != 0 && keySet.event.target == KFILTER_TARGET_REGISTRY &&
                                    keySet.event.rule_id == RuleOf(text, anyKey));
    Result keyRead = Decide(Chunked({233, 0, 0, 0x208, 4}, {}, {}, 4));
    Expect("security: ... a read of it", keyRead.verdict == 0 && keyRead.logged && keyRead.event.target == KFILTER_TARGET_REGISTRY &&
                                           keyRead.event.rights == KFILTER_RIGHT_READ);
    Result directory = Decide(Chunked({233, 0, 0, 0x20C, 4}, {}, {}, 4));
    Expect("security: an object directory's is a registry read too", directory.verdict == 0 && directory.logged &&
                                                                        directory.event.target == KFILTER_TARGET_REGISTRY);
    Result hooked = Decide(Chunked({233, 0, 0, 0x200, 4}, {}, {}, 9));
    Expect("security: ... through the request pipe's hook too", hooked.verdict == 0 && hooked.logged &&
                                                                   hooked.event.target == KFILTER_TARGET_REGISTRY);
    Result unnamed = Decide(Chunked({233, 0, 0, 0x2FC, 4}, {}, {}, 4));
    Expect("security: a handle kfilter did not name is no decision", unnamed.ran && !unnamed.decided && !unnamed.logged);
}

/* Replies whose first field is a handle to no process or thread are recorded so (kb_xhandles, object_maker), now
 * also queue_apc's, get_process_idle_event's, lock_file's and the rest of Wine 11's list; create_device's reply has no
 * fields. A driver's handle to a process from a kernel object pointer (get_kernel_object_handle) names that process
 * for addr= rules alone (kb_learnt) when the pointer was set for a handle to it (set_kernel_object_ptr): every other
 * rule meets requests through it on \\@unknown, as before kfilter followed kernel objects. */
void ObjectReplyCase()
{
    TargetHandles();
    const __u32 self = (__u32)getpid();
    uint32_t reply[16] = {0, 0, 0x300};
    for (uint32_t req : {19u, 24u, 53u, 79u, 113u, 118u, 133u, 135u, 174u, 259u, 297u, 302u, 303u, 251u}) {
        reply[2] = 0x300 + req * 4;
        Decide(Chunked({req, 0}, {}, {}, 4));
        Decide(Reply(reply));
        const kb_hkey_id id{self, reply[2]};
        __u32 marked = 0;
        const bool other = bpf_map_lookup_elem(MapOf("kb_xhandles"), &id, &marked) == 0;
        Expect(std::string("object reply: ") + kRequests[req] + (req == 251 ? " records nothing" : " is no process or thread"),
               other == (req != 251));
    }
    const std::string query = "deny|peer|C:\\*\\MapleStory.exe|rights=query-limited-information|image=grap-core64.aes";
    const std::string text = Head() + query + "\n";
    Expect("kernel object policy loads", Apply(text));
    ExpectDecision("kernel object: the rule meets a request through a handle to MapleStory.exe",
                   Chunked({9, 0, 0, 0x100}, {}, {}, 9), KFilterActionDeny, RuleOf(text, query));
    const uint64_t pointer = 0x7f0012345670ull;
    Decide(Chunked({255, 0, 0, 0x4, 0x100, 0, (uint32_t)pointer, (uint32_t)(pointer >> 32)}, {}, {}, 4));   /* handle 0x100 */
    Decide(Chunked({258, 0, 0, 0x4, (uint32_t)pointer, (uint32_t)(pointer >> 32), 0x1FFFFF}, {}, {}, 4));
    uint32_t handle[16] = {0, 0, 0x400};
    Decide(Reply(handle));
    const kb_hkey_id id{self, 0x400};
    kb_ohandle record{};
    __u32 learnt = 0;
    Expect("kernel object: the driver's new handle names MapleStory.exe for addr= rules alone",
           bpf_map_lookup_elem(MapOf("kb_learnt"), &id, &learnt) == 0 && learnt == kTarget &&
               bpf_map_lookup_elem(MapOf("kb_ohandles"), &id, &record) != 0);
    ExpectDecision("kernel object: a rule naming MapleStory.exe does not meet a request through it",
                   Chunked({9, 0, 0, 0x400}, {}, {}, 9), 0, 0);
    Decide(Chunked({255, 0, 0, 0x4, 0x2FC, 0, (uint32_t)pointer, (uint32_t)(pointer >> 32)}, {}, {}, 4));   /* not one */
    Decide(Chunked({258, 0, 0, 0x4, (uint32_t)pointer, (uint32_t)(pointer >> 32), 0x1FFFFF}, {}, {}, 4));
    handle[2] = 0x404;
    Decide(Reply(handle));
    const kb_hkey_id unknown{self, 0x404};
    Expect("kernel object: a pointer set again for a handle kfilter cannot name reaches nothing it knows",
           bpf_map_lookup_elem(MapOf("kb_ohandles"), &unknown, &record) != 0 &&
               bpf_map_lookup_elem(MapOf("kb_learnt"), &unknown, &learnt) != 0);
}

/* Handles of this process to itself (kb_ohandles): 0x1F0 its process, 0x1F4 a thread of it. */
bool OwnHandles()
{
    const __u32 self = (__u32)getpid();
    const kb_ohandle process{self, 0, 0x1FFFFF, 0}, thread{self, 1, 0x1FFFFF, 0};
    const kb_hkey_id processId{self, 0x1F0}, threadId{self, 0x1F4};
    return bpf_map_update_elem(MapOf("kb_ohandles"), &processId, &process, BPF_ANY) == 0 &&
           bpf_map_update_elem(MapOf("kb_ohandles"), &threadId, &thread, BPF_ANY) == 0;
}

/* Request Req as a protected program (Image) makes it on itself, decided as kfilter decided it before every request
 * was when it has a row of its own (Path: the system path it is decided on, Right: its right); OwnHandles first. */
Request SelfRequest(uint32_t req, const std::string& image, std::string& path, uint32_t& right)
{
    static const std::vector<uint8_t> named = Utf16("kfbench"), attributes = Objattr("kfbench");
    const Row row = RowOf(req);
    Request request = Wine({req});
    request.image = image;
    path = std::string("/system/wine/") + kRequests[req];
    right = req == 84 ? KFILTER_RIGHT_QUERY : RightOf(kRequests[req]);   /* a read is a query */
    if (row == kHandle || row == kEither) request.wine[3] = 0x1F0;
    if (row == kThread) request.wine[3] = 0x1F4;
    if (req == 16) request.wine[12] = 0x40;   /* set_thread_info: hiding from a debugger */
    if (row == kCreate || row == kOpen) {
        const std::vector<uint8_t>& data = row == kCreate ? attributes : named;
        request.wine[1] = (uint32_t)data.size();
        request.chunks = {{data.data(), (uint32_t)data.size()}};
        path += "/kfbench";
    }
    return request;
}

/* Rules reaching /system/wine/ with a star at once or as its parent meet exactly the requests kfilter decided before
 * every request was, each made on itself: every row's (get_image_view_info's only with an addr= rule), with the event
 * path it had, and no other. */
void WineBroadCase()
{
    for (const char* broad : {"deny|system|/system/wine/*", "deny|system|/system/*", "deny|system|/system"}) {
        const std::string text = Head() + broad + "\n";
        Expect(std::string("broad policy loads: ") + broad, Apply(text) && OwnHandles());
        int wrong = 0, rows = 0;
        for (uint32_t req = 0; req < KB_REQ_COUNT; req++) {
            std::string path;
            uint32_t right = 0;
            Result result = Decide(SelfRequest(req, kGrap, path, right));
            const bool row = RowOf(req) != kNamed && req != 70;
            rows += row;
            const bool good = result.ran && (row ? result.verdict != 0 && result.logged && result.event.rule_id == RuleOf(text, broad) &&
                                                       path == result.event.path   /* the event text it always had */
                                                 : !result.logged && result.verdict == 0);
            if (!good && wrong++ < 5) std::printf("  broad %s: %s %s\n", broad, kRequests[req], Describe(result).c_str());
        }
        Expect(std::string("broad: ") + broad + " decides the 44 rows' requests and no other", wrong == 0 && rows == 44);
    }
}

/* The live loop's policies (KFILTER_BENCH_LIVE: files, ':' between them): each request a protected program makes on
 * itself is decided as before every request was decidable (the same rule and verdict as the system decision on its
 * path, which is what kfilter decided it by), and each request that was not decided before still is not. */
void LivePolicyCase()
{
    const char* list = getenv("KFILTER_BENCH_LIVE");
    if (list == nullptr || *list == '\0') {
        std::printf("  live policies: skipped (KFILTER_BENCH_LIVE names none)\n");
        return;
    }
    std::string files(list);
    for (size_t start = 0; start < files.size();) {
        const size_t end = std::min(files.find(':', start), files.size());
        const std::string file = files.substr(start, end - start);
        start = end + 1;
        std::FILE* in = std::fopen(file.c_str(), "rb");
        std::string text;
        for (int c; in != nullptr && (c = std::fgetc(in)) != EOF;) text += (char)c;
        if (in != nullptr) std::fclose(in);
        if (!Apply(text)) {
            Expect("live policy loads: " + file, false);
            continue;
        }
        Expect("live: own handles written", OwnHandles());
        // The programs it protects, and every program its /system/wine rules name.
        std::set<std::string> images;
        for (size_t at = 0; at < text.size();) {
            size_t stop = text.find('\n', at);
            if (stop == std::string::npos) stop = text.size();
            const std::string line = text.substr(at, stop - at);
            at = stop + 1;
            if (line.rfind("protect ", 0) == 0) images.insert(line.substr(8));
            const size_t image = line.find("|image=");
            if (line.find("/system/wine") != std::string::npos && image != std::string::npos)
                images.insert(line.substr(image + 7, line.find('|', image + 7) - image - 7));
        }
        int same = 0, differ = 0, quiet = 0, loud = 0, decidedBefore = 0;
        for (const std::string& program : images) {
            const std::string image = "C:\\x\\" + program;
            for (uint32_t req = 0; req < KB_REQ_COUNT; req++) {
                std::string path;
                uint32_t right = 0;
                const Request request = SelfRequest(req, image, path, right);
                if (RowOf(req) == kNamed || req == 70 /* get_image_view_info: addr= rules alone */) {
                    Result result = Decide(request);
                    if (result.ran && !result.decided && !result.logged && result.verdict == 0) quiet++;
                    else if (loud++ < 5) std::printf("  live %s: %s by %s decided: %s\n", file.c_str(), kRequests[req],
                                                     program.c_str(), Describe(result).c_str());
                    continue;
                }
                Result now = Decide(request);
                Result before = Decide({KFILTER_TARGET_SYSTEM, right, image, path, 0, 1});
                decidedBefore += before.logged;
                if (now.ran && before.ran && now.verdict == before.verdict && now.logged == before.logged &&
                    (!now.logged || (now.event.rule_id == before.event.rule_id && now.event.action == before.event.action)))
                    same++;
                else if (differ++ < 5) std::printf("  live %s: %s by %s: now %s; before %s\n", file.c_str(), kRequests[req],
                                                   program.c_str(), Describe(now).c_str(), Describe(before).c_str());
            }
        }
        std::printf("  live %s: %zu programs; requests decided before: %d the same, %d not (%d by a rule); "
                    "the others: %d undecided, %d decided\n", file.c_str(), images.size(), same, differ, decidedBefore,
                    quiet, loud);
        Expect("live: every request decided before keeps its rule and verdict: " + file, differ == 0 && same > 0);
        Expect("live: every request decidable now was not before, and is not under it: " + file, loud == 0 && quiet > 0);
    }
}

/*
 * Module bases as kfilterd reads them (KfBpfModulesRead), from this process's own maps: kfbench.exe mapped whole (a
 * data view, as MapViewOfFile or GetFileVersionInfo maps an exe) below its image view (header and code) is not the
 * module. Code made executable (JIT, unpacking) and a data view leave the table current; an image view Wine registers
 * makes it stale (a module-relative deny then meets any address) until the table is read again.
 */
void ModuleTableCase()
{
    char directory[] = "/tmp/kfilter-bench-XXXXXX";
    if (mkdtemp(directory) == nullptr) {
        Expect("module table: a directory for kfbench.exe", false);
        return;
    }
    const std::string file = std::string(directory) + "/kfbench.exe";
    std::vector<char> pe(0x3000);
    pe[0] = 'M';
    pe[1] = 'Z';
    pe[0x3c] = 0x40;   /* e_lfanew */
    memcpy(&pe[0x40], "PE\0\0", 4);
    const uint32_t sizeOfImage = 0x4000;
    memcpy(&pe[0x40 + 24 + 56], &sizeOfImage, 4);
    const int fd = open(file.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0600);
    const bool written = fd >= 0 && write(fd, pe.data(), pe.size()) == (ssize_t)pe.size();
    char* data = (char*)mmap((void*)0x5e0000000000, 0x3000, PROT_READ, MAP_SHARED | MAP_FIXED_NOREPLACE, fd, 0);
    char* image = (char*)mmap((void*)0x5e0000100000, 0x1000, PROT_READ, MAP_PRIVATE | MAP_FIXED_NOREPLACE, fd, 0);
    char* code = image == MAP_FAILED ? (char*)MAP_FAILED
                                     : (char*)mmap(image + 0x1000, 0x1000, PROT_READ | PROT_EXEC,
                                                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (fd >= 0) close(fd);
    const bool mapped = written && data != MAP_FAILED && image != MAP_FAILED && code != MAP_FAILED;
    Expect("module table: kfbench.exe mapped as data and as an image", mapped);
    const std::string rule = "deny|peer|C:\\*\\MapleStory.exe|rights=vm-read|addr=kfbench.exe+0x1000-0x1FFF|image=grap-core64.aes";
    const std::string text = Head() + rule + "\n";
    if (mapped && Apply(text)) {
        const __u32 self = (__u32)getpid();
        auto read = [&](const char* at) {
            Request request = Memory(KFILTER_TARGET_PEER, 0x10, kMaple, (uint64_t)(uintptr_t)at, 2);
            request.access.target = self;
            return request;
        };
        KfBpfModulesRead(self);
        ExpectDecision("module table: the image view's code", read(image + 0x1010), KFilterActionDeny, RuleOf(text, rule));
        ExpectDecision("module table: the data view below it is not the module", read(data + 0x1010), 0, 0);
        Decide(ModuleChange(0));
        ExpectDecision("module table: code made executable leaves it current", read(data + 0x1010), 0, 0);
        kb_mods mods{};
        Expect("module table: ... and asks for a reread (module= code ranges)",
               bpf_map_lookup_elem(MapOf("kb_mods"), &self, &mods) == 0 && mods.dirty != 0);
        Decide(ModuleChange(67));   /* map_view: a data view */
        ExpectDecision("module table: a data view registered leaves it current", read(data + 0x1010), 0, 0);
        Decide(ModuleChange(KB_REQ_MAP_IMAGE_VIEW));
        ExpectDecision("module table: an image view registered makes it stale", read(data + 0x1010), KFilterActionDeny,
                       RuleOf(text, rule));
        KfBpfModulesRead(self);
        ExpectDecision("module table: current again once read", read(data + 0x1010), 0, 0);
    }
    if (data != MAP_FAILED) munmap(data, 0x3000);
    if (image != MAP_FAILED) munmap(image, 0x2000);
    unlink(file.c_str());
    rmdir(directory);
}

/*
 * A layer a kfilterd before the rule sets pinned, taken over (KfBpfStart, resuming without kb_live's pin): its maps
 * become set 0, inner maps of this build's maps of maps, and its wildcard and network rules, bounded only by
 * kb_config's counts there, get end marks, so the stale entries past those counts decide nothing.
 */
void AdoptCase()
{
    const __u32 zero = 0;
    __u32 live = 1;
    const std::string text = Head() + "deny|system|/system/wine/q*|image=services.exe\ndeny|network|ip=10.0.0.0/8\n";
    for (int load = 0; load < 2 && live != 0; load++) {
        Expect("adopt: the old layer's policy loads", Apply(text));
        bpf_map_lookup_elem(MapOf("kb_live"), &zero, &live);
    }
    kb_cfg cfg{};
    kb_rule stale{};
    kb_net staleNet{};
    const __u32 staleSlot = KB_RULES - 1;
    const char pattern[] = "/system/sysinfo*";
    stale.action = KFilterActionDeny;
    stale.targets = KFILTER_TARGET_SYSTEM;
    stale.rule_id = 4242;
    stale.wild = 1;
    stale.plen = sizeof(pattern) - 1;
    memcpy(stale.path, pattern, stale.plen);
    staleNet.action = KFilterActionDeny;
    staleNet.family = 4;
    staleNet.rule_id = 4243;
    Expect("adopt: set 0 holds the old policy, with stale rules past its counts",
           live == 0 && bpf_map_lookup_elem(MapOf("kb_config"), &zero, &cfg) == 0 &&
           bpf_map_update_elem(MapOf("kb_rules"), &staleSlot, &stale, BPF_ANY) == 0 &&
           bpf_map_update_elem(MapOf("kb_globs"), &cfg.glob_count, &staleSlot, BPF_ANY) == 0 &&
           bpf_map_update_elem(MapOf("kb_netrules"), &cfg.net_count, &staleNet, BPF_ANY) == 0);
    bpf_object* adopted = bpf_object__open_file(gBench.path.c_str(), nullptr);
    bool reused = adopted != nullptr;
    for (const char* name : {"kb_rules", "kb_literal", "kb_globs", "kb_netrules", "kb_used", "kb_phase", "kb_config", "kb_events"}) {
        reused = reused && bpf_map__reuse_fd(bpf_object__find_map_by_name(adopted, name), MapOf(name)) == 0;
    }
    bpf_program* program = nullptr;
    if (adopted != nullptr) {
        bpf_object__for_each_program(program, adopted) {
            bpf_program__set_autoload(program, std::string(bpf_program__name(program)) == "kb_bench_decide");
        }
    }
    const bool loaded = reused && bpf_object__load(adopted) == 0;
    Expect("adopt: this build loads on the old layer's set 0 maps", loaded);
    uint32_t registered = 0;
    if (loaded && KfBpfBench(adopted, registered)) {
        const int primary = gBench.program;
        gBench.program = bpf_program__fd(bpf_object__find_program_by_name(adopted, "kb_bench_decide"));
        const Request sysinfo{KFILTER_TARGET_SYSTEM, KFILTER_RIGHT_QUERY, kGrap, "/system/sysinfo"};
        ExpectDecision("adopt: without end marks a stale wildcard entry decides", sysinfo, KFilterActionDeny, 4242);
        KfBpfEndMarks();
        ExpectDecision("adopt: with them it decides nothing", sysinfo, 0, 0);
        kb_net end{}, none{};
        Expect("adopt: the network rules end at the count",
               bpf_map_lookup_elem(MapOf("kb_netrules"), &cfg.net_count, &end) == 0 && memcmp(&end, &none, sizeof(end)) == 0);
        gBench.program = primary;
    }
    Expect("adopt: the bench's own layer again", KfBpfBench(gBench.object, gKfRegisteredMask));
    if (adopted != nullptr) bpf_object__close(adopted);
}

/* A module= rule keeps its pattern's bit whatever addr= rules come before it (the kernel's module tables keep the old
 * bits until each is reread): addr= modules take the slots after module= patterns. */
void ModuleBitCase()
{
    const std::string module = "deny|system|/system/wine/q|module=x.dll";
    const std::string address = "deny|peer|C:\\*\\MapleStory.exe|rights=vm-read|addr=y.dll+0-0xFFF";
    auto bitOf = [&](const std::string& text) {
        const __u32 zero = 0;
        __u32 set = 0, slot = 0;
        bpf_map_lookup_elem(MapOf("kb_live"), &zero, &set);
        const int rules = MapOf(set == 1 ? "kb_rules_b" : "kb_rules");
        kb_rule rule{};
        while (slot < KB_RULES && bpf_map_lookup_elem(rules, &slot, &rule) == 0 && rule.rule_id != RuleOf(text, module)) slot++;
        return rule.rule_id == RuleOf(text, module) ? rule.mbit : 0u;
    };
    const std::string alone = Head() + module + "\n", after = Head() + address + "\n" + module + "\n";
    Expect("module bit: a module= rule alone loads", Apply(alone));
    const uint32_t bit = bitOf(alone);
    Expect("module bit: after an addr= rule naming another module it loads", Apply(after));
    Expect("module bit: ... with the same bit", bit != 0 && bitOf(after) == bit);
}

/* kb_ranges holds two rule sets' addr= rules: loads whose addr= rules sit at other places keep each rule's ranges
 * (written before the policy before last's left, the third load's last rules lost theirs, and a deny without ranges
 * met every access, outside them too). */
void AddressReloadCase()
{
    for (int load = 0; load < 3; load++) {
        std::string text = Head();
        for (int i = 0; i < load * 1100; i++) text += "deny|file|/kf-reload/f" + std::to_string(i) + "|exact\n";
        for (int i = 0; i < 1000; i++) {
            text += "deny|peer|C:\\t\\p" + std::to_string(i) + ".exe|rights=vm-read|addr=0x7000000000-0x7000000FFF\n";
        }
        Expect("addr= reload " + std::to_string(load + 1) + " loads", Apply(text));
        int wrong = 0;
        for (int i : {0, 47, 48, 500, 999}) {
            const std::string target = "C:\\t\\p" + std::to_string(i) + ".exe";
            const uint32_t rule = RuleOf(text, "deny|peer|" + target + "|rights=vm-read|addr=0x7000000000-0x7000000FFF");
            Result inside = Decide(Memory(KFILTER_TARGET_PEER, 0x10, target, 0x7000000010, 4));
            Result outside = Decide(Memory(KFILTER_TARGET_PEER, 0x10, target, 0x10, 4));
            const bool good = inside.verdict != 0 && inside.logged && inside.event.rule_id == rule &&
                              outside.verdict == 0 && !outside.logged;
            if (!good && wrong++ == 0) std::printf("  addr= reload %d: p%d: %s; %s\n", load + 1, i, Describe(inside).c_str(),
                                                   Describe(outside).c_str());
        }
        Expect("addr= reload " + std::to_string(load + 1) + ": each rule keeps its ranges", wrong == 0);
    }
    size_t entries = 0;
    __u32 key = 0, next = 0;
    for (void* prior = nullptr; bpf_map_get_next_key(MapOf("kb_ranges"), prior, &next) == 0; prior = &key) {
        key = next;
        entries++;
    }
    Expect("addr= reload: kb_ranges holds the two sets' rules alone", entries == 2000);
}

/* ---- what a Wine request reaches past its own decision: windows, thread ids, handles at any offset, keys ---- */

/* A Wine request decided as kb_file_permission decides it in full (kb_bench.wine 5): its own decision, then the second
 * pass's bookkeeping and decisions on what it reaches (kb_wine_note, kb_handle_request, kb_wine_decide). */
Request Full(std::vector<uint32_t> header, const void* data = nullptr, uint32_t size = 0)
{
    Request request = Wine(std::move(header), data, size);
    request.kind = 5;
    return request;
}

const uint32_t kExplorerTgid = 0x3FFFFF02;   /* explorer.exe's tgid in the maps the cases write */

/* Programs, windows and thread ids the cases name: MapleStory.exe (kTarget) with window index 0x42 at generation 3 and
 * thread 0x500, explorer.exe with window 0x4C (generation 2) and thread 0x508, this program with window 0x44 and thread
 * 0x504, the desktop's window 0x46 (no program's); kTarget's handles 0x100 (process) and 0x104 (thread). */
void WindowsAndThreads()
{
    TargetHandles();
    const __u32 self = (__u32)getpid();
    kb_proc explorer{};
    explorer.ilen = (__u32)strlen(kExplorer);
    explorer.ibase = (__u32)std::string(kExplorer).rfind('\\') + 1;
    memcpy(explorer.image, kExplorer, explorer.ilen);
    const struct { __u32 index; kb_window window; } windows[] = {
        {0x42, {3, kTarget}}, {0x44, {5, self}}, {0x46, {1, KB_WINDOW_SHARED}}, {0x4C, {2, kExplorerTgid}}};
    const struct { __u32 tid, tgid; } threads[] = {{0x500, kTarget}, {0x504, self}, {0x508, kExplorerTgid}};
    bool written = bpf_map_update_elem(MapOf("kb_procs"), &kExplorerTgid, &explorer, BPF_ANY) == 0;
    for (const auto& entry : windows) written &= bpf_map_update_elem(MapOf("kb_windows"), &entry.index, &entry.window, BPF_ANY) == 0;
    for (const auto& entry : threads) written &= bpf_map_update_elem(MapOf("kb_wintids"), &entry.tid, &entry.tgid, BPF_ANY) == 0;
    Expect("windows and thread ids written", written);
}

/* Every decision Request logs, in order. */
std::vector<kb_event> Events(const Request& request)
{
    Decide(request);
    return gBench.events;
}

/*
 * Another program's windows and threads (F3b, F3c): a message to a thread id, a window by its full handle, by its low
 * 16 bits and with the high word 0xFFFF, of a stale generation (\@unknown-window), a thread kfilter cannot place
 * (\@unknown-thread), the requester's own and the desktop's (no decision), two-window and two-thread requests; the
 * pseudo-rights only rules naming them meet (a rights-less peer deny does not), value= on them (the message, the
 * key), an allow naming a placeholder and a wildcard matching one meet nothing.
 */
void WindowCase()
{
    WindowsAndThreads();
    const std::string copydata = "deny|peer|C:\\*\\MapleStory.exe|rights=window-message|value=0x0000004A|image=grap-core64.aes";
    const std::string reads = "audit|peer|C:\\*\\MapleStory.exe|rights=window-query,window-set|image=grap-core64.aes";
    const std::string unknownWindow = "deny|peer|\\@unknown-window|rights=window-set|image=grap-core64.aes";
    const std::string allowThread = "allow|peer|\\@unknown-thread|rights=window-message|image=grap-core64.aes";
    const std::string unknownThread = "deny|peer|\\@unknown-thread|rights=window-message|image=grap-core64.aes";
    const std::string wildInput = "deny|peer|\\*|rights=input|image=grap-core64.aes";
    const std::string input = "deny|peer|C:\\*\\MapleStory.exe|rights=input|image=grap-core64.aes";
    const std::string explorer = "audit|peer|C:\\*\\explorer.exe|rights=window-message|image=grap-core64.aes";
    const std::string everything = "deny|peer|C:\\*\\MapleStory.exe|image=grap-core64.aes";
    const std::string text = Head() + copydata + "\n" + reads + "\n" + unknownWindow + "\n" + allowThread + "\n" +
                             unknownThread + "\n" + wildInput + "\n" + input + "\n" + explorer + "\n" + everything + "\n";
    Expect("window policy loads", Apply(text));
    const uint32_t message = 119, getInfo = 146, setPos = 155, tree = 154, hotkey = 185, attach = 187, setParent = 149;
    /* send_message: id, type, flags, win, msg@0x1c */
    ExpectDecision("window: WM_COPYDATA to MapleStory.exe's thread meets value=0x0000004A", Full({message, 0, 0, 0x500, 0, 0, 0, 0x4A}),
                   KFilterActionDeny, RuleOf(text, copydata));
    ExpectDecision("window: WM_GETTEXT to it: no rule names the message, the rights-less deny never meets a pseudo-right",
                   Full({message, 0, 0, 0x500, 0, 0, 0, 0x0D}), 0, 0);
    ExpectDecision("window: a message to its own thread is no decision", Full({message, 0, 0, 0x504, 0, 0, 0, 0x4A}), 0, 0);
    ExpectDecision("window: to explorer.exe's thread", Full({message, 0, 0, 0x508, 0, 0, 0, 0x10}), KFilterActionAudit,
                   RuleOf(text, explorer));
    ExpectDecision("window: to a thread kfilter cannot place: \\@unknown-thread, its allow not loaded",
                   Full({message, 0, 0, 0x9998, 0, 0, 0, 0x4A}), KFilterActionDeny, RuleOf(text, unknownThread));
    ExpectReached("window: ... its event names the placeholder", Full({message, 0, 0, 0x9998, 0, 0, 0, 0x4A}), "\\@unknown-thread");
    /* get_window_info: handle, offset; set_window_pos: handle@0x14 */
    ExpectDecision("window: GetWindowLong on MapleStory.exe's window, the full handle", Full({getInfo, 0, 0, 0x30042, (uint32_t)-16}),
                   KFilterActionAudit, RuleOf(text, reads));
    ExpectDecision("window: ... its low 16 bits alone", Full({getInfo, 0, 0, 0x42, (uint32_t)-16}), KFilterActionAudit, RuleOf(text, reads));
    ExpectDecision("window: ... high word 0xFFFF", Full({getInfo, 0, 0, 0xFFFF0042, (uint32_t)-16}), KFilterActionAudit, RuleOf(text, reads));
    ExpectDecision("window: SetWindowPos on it (handle at 0x14)", Full({setPos, 0, 0, 0, 0, 0x30042}), KFilterActionAudit,
                   RuleOf(text, reads));
    ExpectDecision("window: a stale generation is \\@unknown-window", Full({setPos, 0, 0, 0, 0, 0x40042}), KFilterActionDeny,
                   RuleOf(text, unknownWindow));
    ExpectDecision("window: a window kfilter never saw made too", Full({setPos, 0, 0, 0, 0, 0x10050}), KFilterActionDeny,
                   RuleOf(text, unknownWindow));
    const __u32 goneIndex = 0x4E;
    const kb_window gone{1, 0x3FFFFF0E};   /* a program that exited (no kb_procs entry): a stale owner */
    Expect("window: a stale owner written", bpf_map_update_elem(MapOf("kb_windows"), &goneIndex, &gone, BPF_ANY) == 0);
    ExpectDecision("window: a window whose owner exited is \\@unknown-window", Full({setPos, 0, 0, 0, 0, 0x1004E}),
                   KFilterActionDeny, RuleOf(text, unknownWindow));
    ExpectDecision("window: its own window is no decision", Full({setPos, 0, 0, 0, 0, 0x50044}), 0, 0);
    ExpectDecision("window: the desktop's window is no program's", Full({tree, 0, 0, 0x10046}), 0, 0);
    ExpectDecision("window: a hotkey on MapleStory.exe's window is input", Full({hotkey, 0, 0, 0x30042, 1, 0, 0x70}),
                   KFilterActionDeny, RuleOf(text, input));
    /* attach_thread_input: tid_from, tid_to; set_parent: handle, parent */
    ExpectDecision("window: AttachThreadInput from its own thread to MapleStory.exe's: the second id decides",
                   Full({attach, 0, 0, 0x504, 0x500, 1}), KFilterActionDeny, RuleOf(text, input));
    Expect("window: ... once when both ids are MapleStory.exe's", Events(Full({attach, 0, 0, 0x500, 0x500, 1})).size() == 1);
    ExpectDecision("window: an unplaced thread's input: a wildcard matching \\@unknown-thread does not meet it",
                   Full({attach, 0, 0, 0x504, 0x9998, 1}), 0, 0);
    ExpectDecision("window: its own window made MapleStory.exe's child: the parent decides", Full({setParent, 0, 0, 0x50044, 0x30042}),
                   KFilterActionAudit, RuleOf(text, reads));
    std::vector<kb_event> both = Events(Full({setParent, 0, 0, 0x2004C, 0x30042}));
    Expect("window: explorer.exe's window made MapleStory.exe's child: each program decided (the rights-less deny meets "
           "neither)", both.size() == 1 && both[0].rule_id == RuleOf(text, reads) &&
               std::string(both[0].path) == kMaple && both[0].value == KFILTER_ACCESS_WINDOW_SET);
    ExpectDecision("window: the rights-less deny still meets what it met before (get_process_info)", Wine({9, 0, 0, 0x100}),
                   KFilterActionDeny, RuleOf(text, everything));
    // Without a rule naming a pseudo-right no window or thread decision is made at all (kb_cfg's gate).
    const std::string plain = Head() + everything + "\n";
    Expect("window: a policy without pseudo-rights loads", Apply(plain));
    kb_cfg cfg{};
    const __u32 zero = 0;
    Expect("window: ... and its gate is off", bpf_map_lookup_elem(MapOf("kb_config"), &zero, &cfg) == 0 &&
                                                 (cfg.targets & KB_TARGET_WINDOW) == 0);
    ExpectDecision("window: ... a message to MapleStory.exe is no decision", Full({message, 0, 0, 0x500, 0, 0, 0, 0x4A}), 0, 0);
    ExpectDecision("window: ... a stale window neither", Full({setPos, 0, 0, 0, 0, 0x40042}), 0, 0);
}

/* Window owners recorded from wineserver's replies (kb_windows): create_window names its creator, get_desktop_window the
 * desktop's windows (no program's), each at the generation its handle carries. */
void WindowOwnerCase()
{
    const __u32 self = (__u32)getpid();
    Expect("window owner policy loads", Apply(Head()));
    Decide(Full({142 /* create_window */, 0, 0, 0, 0, 0}));
    uint32_t reply[16] = {0, 0, 0x00070048};
    Expect("window owner: create_window's reply is read for it", Decide(Reply(reply)).decided);
    __u32 index = 0x48;
    kb_window window{};
    Expect("window owner: its handle's index names its creator at its generation",
           bpf_map_lookup_elem(MapOf("kb_windows"), &index, &window) == 0 && window.gen == 7 && window.tgid == self);
    Decide(Full({144 /* get_desktop_window */, 0, 0, 1}));
    uint32_t desktop[16] = {0, 0, 0x00020020, 0x00020022};
    Decide(Reply(desktop));
    kb_window top{}, messages{};
    const __u32 topIndex = 0x20, messageIndex = 0x22;
    Expect("window owner: the desktop's windows are no program's",
           bpf_map_lookup_elem(MapOf("kb_windows"), &topIndex, &top) == 0 && top.tgid == KB_WINDOW_SHARED && top.gen == 2 &&
               bpf_map_lookup_elem(MapOf("kb_windows"), &messageIndex, &messages) == 0 && messages.tgid == KB_WINDOW_SHARED);
}

/*
 * A handle at any offset (F3a): assign_job's and process_in_job's process at 0x10, new_thread's at 0xc, get_thread_info,
 * get_thread_times and cancel_sync on a thread, get_process_idle_event, decided on the program the handle reaches with
 * the access wineserver asks; only rules with value= meet them (the request's name), not a rights-less deny, not one
 * whose rights cover the access (both meet what they met before); \@unknown for a handle kfilter cannot name; none on
 * its own process. new_thread's reply still names the new thread.
 */
void HandleOffsetCase()
{
    TargetHandles();
    Expect("own handles written", OwnHandles());
    const std::string job = "deny|peer|C:\\*\\MapleStory.exe|value=assign_job|image=grap-core64.aes";
    const std::string threads = "deny|thread-peer|C:\\*\\MapleStory.exe|value=get_thread_*|image=grap-core64.aes";
    const std::string created = "audit|peer|C:\\*\\MapleStory.exe|rights=create-thread|value=new_thread|image=grap-core64.aes";
    const std::string unknown = "deny|peer|\\@unknown|value=new_thread|image=grap-core64.aes";
    const std::string unknownJob = "deny|peer|\\@unknown|value=assign_job|image=grap-core64.aes";
    const std::string query = "deny|peer|C:\\*\\MapleStory.exe|rights=query-information|image=grap-core64.aes";
    const std::string everything = "deny|thread-peer|C:\\*\\MapleStory.exe|image=grap-core64.aes";
    const std::string text = Head() + job + "\n" + threads + "\n" + created + "\n" + unknown + "\n" + unknownJob + "\n" + query +
                             "\n" + everything + "\n";
    Expect("handle offset policy loads", Apply(text));
    ExpectDecision("offset: AssignProcessToJobObject on MapleStory.exe (process at 0x10)", Full({285, 0, 0, 0x300, 0x100}),
                   KFilterActionDeny, RuleOf(text, job));
    Result assigned = Decide(Full({285, 0, 0, 0x300, 0x100}));
    Expect("offset: ... as peer, with PROCESS_SET_QUOTA | PROCESS_TERMINATE",
           assigned.event.target == KB_TARGET_PEER_VALUE && assigned.event.rights == 0x101 &&
               std::string(assigned.event.path) == kMaple);
    ExpectDecision("offset: its own process is no decision", Full({285, 0, 0, 0x300, 0xFFFFFFFF}), 0, 0);
    ExpectDecision("offset: IsProcessInJob (query-information): a rights-ful rule without value= does not meet it",
                   Full({286, 0, 0, 0x300, 0x100}), 0, 0);
    ExpectDecision("offset: WaitForInputIdle (get_process_idle_event) neither", Full({118, 0, 0, 0x100}), 0, 0);
    ExpectDecision("offset: GetThreadInformation on its thread (the access it asks)", Full({14, 0, 0, 0x104, 0x40}),
                   KFilterActionDeny, RuleOf(text, threads));
    Result info = Decide(Full({14, 0, 0, 0x104, 0x40}));
    Expect("offset: ... as thread-peer, THREAD_QUERY_INFORMATION", info.event.target == KB_TARGET_THREAD_VALUE &&
                                                                    info.event.rights == 0x40);
    Result limited = Decide(Full({14, 0, 0, 0x104, 0}));
    Expect("offset: Wine's own NtQueryInformationThread (access 0) asks THREAD_QUERY_LIMITED_INFORMATION, as wineserver does",
           limited.verdict != 0 && limited.event.rule_id == RuleOf(text, threads) && limited.event.rights == 0x800);
    Result all = Decide(Full({14, 0, 0, 0x104, 0x1FFFFF}));
    Expect("offset: ... and of THREAD_ALL_ACCESS only the query rights", all.verdict != 0 && all.event.rights == 0x840);
    ExpectDecision("offset: GetThreadTimes", Full({15, 0, 0, 0x104}), KFilterActionDeny, RuleOf(text, threads));
    ExpectDecision("offset: CancelSynchronousIo: its value names another request", Full({131, 0, 0, 0x104}), 0, 0);
    ExpectDecision("offset: a thread in MapleStory.exe (new_thread, process at 0xc)", Full({2, 0, 0, 0x100, 0x1FFFFF}),
                   KFilterActionAudit, RuleOf(text, created));
    ExpectDecision("offset: through a handle kfilter cannot name: \\@unknown", Full({2, 0, 0, 0x108, 0x1FFFFF}),
                   KFilterActionDeny, RuleOf(text, unknown));
    ExpectDecision("offset: its own new thread is no decision", Full({2, 0, 0, 0xFFFFFFFF, 0x1FFFFF}), 0, 0);
    const kb_hkey_id childId{(__u32)getpid(), 0x10C};
    const kb_ohandle child{0, 0, 0x1FFFFF, 0x7F0};   /* new_process's handle to a child not started yet */
    Expect("offset: a new child's handle written", bpf_map_update_elem(MapOf("kb_ohandles"), &childId, &child, BPF_ANY) == 0);
    ExpectDecision("offset: CreateProcess's first thread in its child is no decision", Full({2, 0, 0, 0x10C, 0x1FFFFF}), 0, 0);
    ExpectDecision("offset: assign_job through a handle kfilter cannot name: \\@unknown", Full({285, 0, 0, 0x300, 0x108}),
                   KFilterActionDeny, RuleOf(text, unknownJob));
    ExpectDecision("offset: ... through the child's, before it starts (Chromium's job): no decision", Full({285, 0, 0, 0x300, 0x10C}), 0, 0);
    uint32_t reply[16] = {0, 0, 0x7770, 0x1F8};   /* tid, handle */
    Decide(Reply(reply));
    __u32 tid = 0x7770, learnt = 0;
    Expect("offset: new_thread's reply still names the new thread",
           bpf_map_lookup_elem(MapOf("kb_wintids"), &tid, &learnt) == 0 && learnt == (__u32)getpid());
    ExpectDecision("offset: the rights-less thread-peer deny still meets get_thread_context as before", Wine({105, 0, 0, 0x104}),
                   KFilterActionDeny, RuleOf(text, everything));
}

/* UTF-16 bytes of Text appended to Data. */
void AppendUtf16(std::vector<uint8_t>& data, const std::string& text)
{
    const std::vector<uint8_t> bytes = Utf16(text);
    data.insert(data.end(), bytes.begin(), bytes.end());
}

/* new_process's data: objattr (no name), no handles or jobs, the startup info (96 bytes: curdir, dllpath, imagepath
 * lengths at +64) and its strings. */
std::vector<uint8_t> StartupData(const std::string& image)
{
    std::vector<uint8_t> data(16 + 96, 0);
    const std::string curdir = "C:\\x\\", dllpath = "";
    const uint32_t lengths[3] = {(uint32_t)curdir.size() * 2, (uint32_t)dllpath.size() * 2, (uint32_t)image.size() * 2};
    memcpy(data.data() + 16 + 64, lengths, sizeof(lengths));
    AppendUtf16(data, curdir);
    AppendUtf16(data, image);
    AppendUtf16(data, image + " --x");   /* the command line */
    return data;
}

/* kb_hkeys: Handle of this program named Name (an NT object kfilter named), Kind. */
void NameHandle(uint32_t handle, const std::string& name, uint32_t kind)
{
    const kb_hkey_id id{(__u32)getpid(), handle};
    kb_hkey key{};
    key.len = (__u32)name.size();
    key.kind = kind;
    memcpy(key.path, name.data(), name.size());
    Expect("handle named " + name, bpf_map_update_elem(MapOf("kb_hkeys"), &id, &key, BPF_ANY) == 0);
}

/*
 * Keyed decisions (F3d): /system/wine/<request>/<key>, met only by rules whose fixed text reaches past
 * /system/wine/<request>/ (KB_TARGET_KEYED), after the request's own decision, which keeps its path, rules and event
 * text: a rule on /system/wine/set_hook|exact still meets set_hook and nothing past it.
 */
void KeyedCase()
{
    NameHandle(0x200, "\\??\\PhysicalDrive0", KB_HKEY_FILE);
    NameHandle(0x204, "\\Device\\Foo", KB_HKEY_FILE);
    const std::string hook = "deny|system|/system/wine/set_hook/13/global|image=grap-core64.aes";
    const std::string bare = "audit|system|/system/wine/set_hook|exact|image=grap-core64.aes";
    const std::string key = "deny|system|/system/wine/get_key_state/0x00000070";
    const std::string all = "audit|system|/system/wine/get_key_state/all|image=grap-core64.aes";
    const std::string unnamed = "audit|system|/system/wine/ioctl/@unknown/*|image=grap-core64.aes";
    const std::string inject = "deny|system|/system/wine/send_hardware_message/injected/keyboard|value=0x00000041";
    const std::string cursor = "deny|system|/system/wine/set_cursor/pos|image=grap-core64.aes";
    const std::string raw = "deny|system|/system/wine/update_rawinput_devices/inputsink";
    const std::string clipboard = "deny|system|/system/wine/get_clipboard_data/13";
    const std::string clipboardBare = "audit|system|/system/wine/get_clipboard_data|image=grap-core64.aes";
    const std::string storage = "deny|system|/system/wine/ioctl/\\??\\PhysicalDrive0/0x002d1400";
    const std::string volume = "deny|system|/system/wine/ioctl/\\??\\C:/*";
    const std::string read = "deny|system|/system/wine/read/\\Device\\Foo";
    const std::string written = "deny|system|/system/wine/write/\\Device\\Foo|image=grap-core64.aes";
    const std::string cheat = "deny|system|/system/wine/new_process/C:\\x\\cheat.exe*";
    const std::string debug = "deny|system|/system/wine/new_process/*/debug";
    const std::string text = Head() + hook + "\n" + bare + "\n" + key + "\n" + all + "\n" + inject + "\n" + cursor + "\n" + raw +
                             "\n" + clipboard + "\n" + clipboardBare + "\n" + storage + "\n" + volume + "\n" + read + "\n" +
                             cheat + "\n" + debug + "\n" + unnamed + "\n" + written + "\n";
    Expect("keyed policy loads", Apply(text));
    std::vector<kb_event> events = Events(Full({198, 0, 0, 13, 0, 0}));
    Expect("keyed: SetWindowsHookEx(WH_KEYBOARD_LL) global: the request's own decision (its exact rule, its path), then "
           "the key's", events.size() == 2 && events[0].rule_id == RuleOf(text, bare) &&
               std::string(events[0].path) == "/system/wine/set_hook" && events[1].rule_id == RuleOf(text, hook) &&
               events[1].action == KFilterActionDeny && std::string(events[1].path) == "/system/wine/set_hook/13/global" &&
               events[1].target == KB_TARGET_KEYED);
    events = Events(Full({198, 0, 0, 13, 0, 0x500}));
    Expect("keyed: a thread hook: the exact rule alone, on its own path", events.size() == 1 &&
                                                                           events[0].action == KFilterActionAudit &&
                                                                           std::string(events[0].path) == "/system/wine/set_hook");
    ExpectReached("keyed: WH_MSGFILTER (-1) of a process", Full({198, 0, 0, 0xFFFFFFFF, 0x40, 0}), "/system/wine/set_hook");
    Request filterHook = Full({198, 0, 0, 0xFFFFFFFF, 0x40, 0});
    std::string message = "deny|system|/system/wine/set_hook/-1/process|image=grap-core64.aes";
    Expect("keyed: a negative hook id policy loads", Apply(Head() + message + "\n"));
    ExpectDecision("keyed: ... /system/wine/set_hook/-1/process", filterHook, KFilterActionDeny, RuleOf(Head() + message + "\n", message));
    Expect("keyed policy loads again", Apply(text));
    ExpectDecision("keyed: GetKeyState(VK_F1)", Full({190, 0, 0, 0, 0x70}), KFilterActionDeny, RuleOf(text, key));
    ExpectDecision("keyed: another key", Full({190, 0, 0, 0, 0x41}), 0, 0);
    ExpectDecision("keyed: the whole table", Full({190, 0, 0, 0, 0xFFFFFFFF}), KFilterActionAudit, RuleOf(text, all));
    ExpectReached("keyed: ... /system/wine/get_key_state/all", Full({190, 0, 0, 0, 0xFFFFFFFF}), "/system/wine/get_key_state/all");
    /* send_hardware_message: win, input (type@0x10, vkey@0x14), flags@0x38 */
    std::vector<uint32_t> injected = {121, 0, 0, 0, 1, 0x41};
    injected.resize(16);
    injected[14] = 1;
    ExpectDecision("keyed: SendInput of 'A' (injected keyboard, value=the key)", Full(injected), KFilterActionDeny, RuleOf(text, inject));
    injected[5] = 0x42;
    ExpectDecision("keyed: ... of 'B'", Full(injected), 0, 0);
    injected[5] = 0x41;
    injected[14] = 0;
    ExpectDecision("keyed: real input of 'A' (hardware)", Full(injected), 0, 0);
    ExpectDecision("keyed: SetCursorPos", Full({279, 0, 0, 0x04}), KFilterActionDeny, RuleOf(text, cursor));
    ExpectDecision("keyed: ClipCursor", Full({279, 0, 0, 0x08}), 0, 0);
    ExpectDecision("keyed: a position and a clip in one request: each decided", Full({279, 0, 0, 0x0C}), KFilterActionDeny,
                   RuleOf(text, cursor));
    const uint32_t sink[3] = {1 | 6 << 16, 0x100, 0}, normal[3] = {1 | 6 << 16, 0, 0};
    ExpectDecision("keyed: raw input in the background (RIDEV_INPUTSINK)", Full({282, 12}, sink, 12), KFilterActionDeny,
                   RuleOf(text, raw));
    ExpectDecision("keyed: raw input in the foreground", Full({282, 12}, normal, 12), 0, 0);
    ExpectDecision("keyed: CF_UNICODETEXT read (its bare rule audits first)", Full({211, 0, 0, 13}), KFilterActionDeny,
                   RuleOf(text, clipboard));
    ExpectDecision("keyed: CF_TEXT: the bare rule alone", Full({211, 0, 0, 1}), KFilterActionAudit, RuleOf(text, clipboardBare));
    /* ioctl: code, async (handle@0x10); read: async */
    ExpectDecision("keyed: IOCTL_STORAGE_QUERY_PROPERTY on \\??\\PhysicalDrive0", Full({138, 0, 0, 0x002d1400, 0x200}),
                   KFilterActionDeny, RuleOf(text, storage));
    ExpectReached("keyed: ... its event", Full({138, 0, 0, 0x002d1400, 0x200}), "/system/wine/ioctl/\\??\\PhysicalDrive0/0x002d1400");
    ExpectDecision("keyed: another code on it", Full({138, 0, 0, 0x00070000, 0x200}), 0, 0);
    ExpectReached("keyed: a handle kfilter did not name", Full({138, 0, 0, 0x00070000, 0x2FC}), "/system/wine/ioctl/@unknown/0x00070000");
    ExpectDecision("keyed: a read of \\Device\\Foo", Full({136, 0, 0, 0, 0x204}), KFilterActionDeny, RuleOf(text, read));
    const uint32_t bytes = 0x12345678;
    ExpectDecision("keyed: a write to it", Full({137, 4, 0, 0, 0x204}, &bytes, 4), KFilterActionDeny, RuleOf(text, written));
    /* create_file names a handle for keyed rules (kb_fnames): \??\C: opened as a file, then an ioctl on it */
    const std::vector<uint8_t> attributes = Objattr("\\??\\C:");
    Decide(Full({44, (uint32_t)attributes.size(), 0, 0x80100000}, attributes.data(), (uint32_t)attributes.size()));
    uint32_t opened[16] = {0, 0, 0x208};
    Decide(Reply(opened));
    ExpectDecision("keyed: an ioctl on a volume opened with create_file", Full({138, 0, 0, 0x00070000, 0x208}), KFilterActionDeny,
                   RuleOf(text, volume));
    const std::vector<uint8_t> child = StartupData("C:\\x\\cheat.exe");
    ExpectDecision("keyed: CreateProcess of cheat.exe (new_process, its image in the startup info)",
                   Full({0, (uint32_t)child.size(), 0, 0, 0, 0, 0, 0, 0x1FFFFF, 0, (uint32_t)child.size() - 16}, child.data(),
                        (uint32_t)child.size()), KFilterActionDeny, RuleOf(text, cheat));
    const std::vector<uint8_t> ok = StartupData("C:\\x\\ok.exe");
    std::vector<uint32_t> debugged = {0, (uint32_t)ok.size(), 0, 0, 0x110, 0x120, 0, 0, 0x1FFFFF, 0, (uint32_t)ok.size() - 16};
    ExpectDecision("keyed: ok.exe under a debugger with a parent of its choice", Full(debugged, ok.data(), (uint32_t)ok.size()),
                   KFilterActionDeny, RuleOf(text, debug));
    ExpectReached("keyed: ... its path", Full(debugged, ok.data(), (uint32_t)ok.size()),
                  "/system/wine/new_process/C:\\x\\ok.exe/spoofed-parent/debug");
    debugged[4] = 0;
    debugged[5] = 0;
    ExpectDecision("keyed: ok.exe plainly", Full(debugged, ok.data(), (uint32_t)ok.size()), 0, 0);
    // Rules reaching /system/wine/ broadly, or a request name but not past it, never meet a key (only the rule turning
    // keyed decisions on is keyed); the requests they met before they still meet, with the event text they had.
    const std::string broad[] = {"deny|system|/system", "deny|system|/system/*", "deny|system|/system/wine/*",
                                 "deny|system|/system/wine/set_*l", "deny|system|/system/w*"};
    const std::string named = "deny|system|/system/wine/get_k*|image=grap-core64.aes";
    std::string wide = Head() + "deny|system|/system/wine/set_hook/99/global|image=nobody.exe\n";
    for (const std::string& rule : broad) wide += rule + "\n";
    wide += named + "\n";
    Expect("keyed: a broad policy loads", Apply(wide));
    ExpectDecision("keyed: no broad rule meets a hook or its key", Full({198, 0, 0, 13, 0, 0}), 0, 0);
    ExpectDecision("keyed: ... nor a cursor's", Full({279, 0, 0, 0x04}), 0, 0);
    events = Events(Full({190, 0, 0, 0, 0x70}));
    Expect("keyed: a pattern reaching into get_key_state's name meets the request as before, with its path",
           events.size() == 1 && events[0].rule_id == RuleOf(wide, named) && std::string(events[0].path) == "/system/wine/get_key_state");
}

/* A DCE/RPC PDU: version 5, Type, the header's other fields zero; a request's context and opnum, a bind's first context
 * and interface. */
std::vector<uint8_t> RpcPdu(uint8_t type, uint16_t context, uint16_t opnum, const uint8_t (&uuid)[16])
{
    std::vector<uint8_t> pdu(type == 0 ? 24 : 52, 0);
    pdu[0] = 5;
    pdu[2] = type;
    pdu[4] = 0x10;   /* little-endian */
    if (type == 0) {
        memcpy(&pdu[20], &context, 2);
        memcpy(&pdu[22], &opnum, 2);
    } else {
        pdu[24] = 1;   /* one context */
        memcpy(&pdu[28], &context, 2);
        memcpy(&pdu[32], uuid, 16);
    }
    return pdu;
}

/* RPC calls on a named pipe whose bind kfilter saw: /system/rpc/<interface uuid>/<opnum>, by write and by
 * FSCTL_PIPE_TRANSCEIVE; none before a bind, on another context, or on a handle that is no pipe. */
void RpcCase()
{
    NameHandle(0x210, "\\??\\pipe\\svcctl", KB_HKEY_PIPE);
    NameHandle(0x214, "\\Device\\Foo", KB_HKEY_FILE);
    const uint8_t svcctl[16] = {0x81, 0xbb, 0x7a, 0x36, 0x44, 0x98, 0xf1, 0x35, 0xad, 0x32, 0x98, 0xf0, 0x38, 0x00, 0x10, 0x03};
    const std::string start = "deny|system|/system/rpc/367abb81-9844-35f1-ad32-98f038001003/19|image=grap-core64.aes";
    const std::string any = "audit|system|/system/rpc/367abb81-9844-35f1-ad32-98f038001003/*|image=grap-core64.aes";
    const std::string text = Head() + "deny|system|/system/*\n" + start + "\n" + any + "\n";
    Expect("rpc policy loads", Apply(text));
    const std::vector<uint8_t> call = RpcPdu(0, 0, 19, svcctl), other = RpcPdu(0, 0, 15, svcctl);
    const std::vector<uint8_t> bind = RpcPdu(11, 0, 0, svcctl), elsewhere = RpcPdu(0, 1, 19, svcctl);
    auto write = [](uint32_t handle, const std::vector<uint8_t>& pdu) {
        return Full({137, (uint32_t)pdu.size(), 0, 0, handle}, pdu.data(), (uint32_t)pdu.size());
    };
    ExpectDecision("rpc: RStartServiceW before a bind is no decision", write(0x210, call), 0, 0);
    ExpectDecision("rpc: the bind is none either", write(0x210, bind), 0, 0);
    ExpectDecision("rpc: then RStartServiceW (opnum 19)", write(0x210, call), KFilterActionDeny, RuleOf(text, start));
    ExpectReached("rpc: ... its event", write(0x210, call), "/system/rpc/367abb81-9844-35f1-ad32-98f038001003/19");
    ExpectDecision("rpc: another operation of svcctl", write(0x210, other), KFilterActionAudit, RuleOf(text, any));
    ExpectDecision("rpc: a context the bind did not make", write(0x210, elsewhere), 0, 0);
    ExpectDecision("rpc: by FSCTL_PIPE_TRANSCEIVE", Full({138, (uint32_t)call.size(), 0, 0x0011C017, 0x210}, call.data(),
                                                         (uint32_t)call.size()), KFilterActionDeny, RuleOf(text, start));
    Decide(write(0x214, bind));
    ExpectDecision("rpc: a handle that is no named pipe", write(0x214, call), 0, 0);
    // A new handle at the same value is not the bound pipe.
    Decide(Full({44, 0, 0, 0}));
    uint32_t reused[16] = {0, 0, 0x210};
    Decide(Reply(reused));
    NameHandle(0x210, "\\??\\pipe\\svcctl", KB_HKEY_PIPE);
    ExpectDecision("rpc: a handle given out again forgets its bind", write(0x210, call), 0, 0);
}

/* Values on the request's own decision (get_thread_context's flags, register_hotkey's key), and decisions value= alone
 * makes (SYSTEM_VALUE: set_thread_info's other masks, each of adjust_token_privileges' privileges): a rule without
 * value= decides as before, never the latter. */
void ValueCase()
{
    TargetHandles();
    Expect("own handles written", OwnHandles());
    const std::string debugRegisters = "deny|system|/system/wine/get_thread_context|value=0x00000010|image=grap-core64.aes";
    const std::string contexts = "audit|system|/system/wine/get_thread_context|image=grap-core64.aes";
    const std::string peerRegisters = "deny|thread-peer|C:\\*\\MapleStory.exe|rights=get-context|value=0x00000010|image=grap-core64.aes";
    const std::string hidden = "audit|system|/system/wine/set_thread_info|exact|image=grap-core64.aes";
    const std::string priority = "deny|system|/system/wine/set_thread_info|value=0x00000001|image=grap-core64.aes";
    const std::string debug = "deny|system|/system/wine/adjust_token_privileges|value=0x00000014|image=grap-core64.aes";
    const std::string adjust = "audit|system|/system/wine/adjust_token_privileges|image=grap-core64.aes";
    const std::string hotkey = "deny|system|/system/wine/register_hotkey|value=0x00000070|image=grap-core64.aes";
    const std::string volume = "deny|system|/system/wine/get_volume_info|value=0x00000003|image=grap-core64.aes";
    const std::string text = Head() + debugRegisters + "\n" + contexts + "\n" + peerRegisters + "\n" + hidden + "\n" + priority +
                             "\n" + debug + "\n" + adjust + "\n" + hotkey + "\n" + volume + "\n";
    Expect("value policy loads", Apply(text));
    /* get_thread_context: handle, context, flags@0x14 */
    ExpectDecision("value: its own debug registers (flags 0x10)", Full({105, 0, 0, 0x1F4, 0, 0x10}), KFilterActionDeny,
                   RuleOf(text, debugRegisters));
    ExpectDecision("value: its control registers: the rule without value= as before", Full({105, 0, 0, 0x1F4, 0, 0x01}),
                   KFilterActionAudit, RuleOf(text, contexts));
    ExpectDecision("value: MapleStory.exe's debug registers", Full({105, 0, 0, 0x104, 0, 0x10}), KFilterActionDeny,
                   RuleOf(text, peerRegisters));
    ExpectDecision("value: MapleStory.exe's control registers", Full({105, 0, 0, 0x104, 0, 0x01}), 0, 0);
    /* set_thread_info: mask@0x30 */
    std::vector<uint32_t> info = {16, 0, 0, 0x1F4};
    info.resize(16);
    info[12] = 0x40;
    ExpectDecision("value: ThreadHideFromDebugger: as before", Full(info), KFilterActionAudit, RuleOf(text, hidden));
    info[12] = 0x01;
    ExpectDecision("value: SetThreadPriority: value= alone", Full(info), KFilterActionDeny, RuleOf(text, priority));
    info[12] = 0x02;
    ExpectDecision("value: SetThreadAffinityMask: no rule names it (the exact rule never meets it)", Full(info), 0, 0);
    /* adjust_token_privileges: handle, disable_all, get_modified_state; privileges (luid low, high, attributes) */
    const uint32_t two[6] = {8, 0, 2, 20, 0, 2}, one[3] = {8, 0, 2};
    std::vector<kb_event> events = Events(Full({222, 24, 0, 0xFFFFFFFA}, two, 24));
    Expect("value: SeDebugPrivilege second of two: the rule without value= once, then the LUID's",
           events.size() == 2 && events[0].rule_id == RuleOf(text, adjust) && events[1].rule_id == RuleOf(text, debug) &&
               events[1].action == KFilterActionDeny);
    events = Events(Full({222, 12, 0, 0xFFFFFFFA}, one, 12));
    Expect("value: SeSecurityPrivilege alone: as before", events.size() == 1 && events[0].rule_id == RuleOf(text, adjust));
    ExpectDecision("value: RegisterHotKey(VK_F1)", Full({185, 0, 0, 0, 1, 0, 0x70}), KFilterActionDeny, RuleOf(text, hotkey));
    ExpectDecision("value: RegisterHotKey(VK_F2)", Full({185, 0, 0, 0, 1, 0, 0x71}), 0, 0);
    std::vector<uint32_t> query = {52, 0, 0, 0x2FC};
    query.resize(16);
    query[14] = 3;
    ExpectDecision("value: a volume's size (FileFsSizeInformation)", Full(query), KFilterActionDeny, RuleOf(text, volume));
    query[14] = 4;
    ExpectDecision("value: its device information", Full(query), 0, 0);
}

/* Same: a decision as kfilter made it before what a request reaches past its own was decided (Before: the request's own
 * decision alone, kb_bench.wine 1), the same verdict, event count, rule, action and path. */
bool Same(const Request& request, std::string& why)
{
    Request own = request;
    own.kind = 1;
    Result was = Decide(own);
    const std::vector<kb_event> before = gBench.events;
    Result now = Decide(request);
    const std::vector<kb_event> after = gBench.events;
    bool same = was.verdict == now.verdict && before.size() == after.size();
    for (size_t i = 0; same && i < before.size(); i++) {
        same = before[i].rule_id == after[i].rule_id && before[i].action == after[i].action &&
               before[i].target == after[i].target && std::string(before[i].path) == after[i].path;
    }
    if (!same) why = "before " + Describe(was) + " (" + std::to_string(before.size()) + " events); now " + Describe(now) + " (" +
                     std::to_string(after.size()) + ")";
    return same;
}

/*
 * The live loop's policies (KFILTER_BENCH_LIVE) and what a request reaches past its own decision: none of their rules
 * names a pseudo-right, value= or a keyed space, so each program's every request, made on itself and reaching
 * MapleStory.exe (its window 0x30042, its thread 0x500, its process and thread handles 0x100 and 0x104), comes to the
 * very decisions it came to before (verdict, rule, event path), with K3's and K4's gates off (the policies open none), and
 * again with every gate on (rules of each new kind of both lanes for another program added): none of the policy's rules
 * meets a new decision. new_thread and
 * new_process, never decided, stay undecided.
 */
uint32_t Gates();   /* kb_gates (K4's cases) */

void LiveReachCase()
{
    const char* list = getenv("KFILTER_BENCH_LIVE");
    if (list == nullptr || *list == '\0') return;
    WindowsAndThreads();
    const std::string others = "deny|peer|C:\\*|rights=window-query,window-set,window-message,input|image=nobody.exe\n"
                               "deny|peer|\\@unknown-window|rights=window-set|image=nobody.exe\n"
                               "deny|peer|\\@unknown-thread|rights=window-message|image=nobody.exe\n"
                               "deny|peer|C:\\*|value=*|image=nobody.exe\n"
                               "deny|thread-peer|C:\\*|value=*|image=nobody.exe\n"
                               "deny|system|/system/wine/set_hook/*|image=nobody.exe\n"
                               "deny|system|/system/rpc/*|image=nobody.exe\n"
                               "deny|system|/system/wine/adjust_token_privileges|value=*|image=nobody.exe\n"
                               /* K4's kinds */
                               "deny|system|/system/syscall/getrandom|image=nobody.exe\n"
                               "deny|system|/system/fcntl/*|image=nobody.exe\ndeny|system|/system/task/*|image=nobody.exe\n"
                               "deny|system|/system/memory/private/rw|image=nobody.exe\n"
                               "deny|file|/kf-live/*|rights=lock,touch|image=nobody.exe\n"
                               "deny|dir|/kf-live|rights=chdir|image=nobody.exe\n"
                               "deny|pipe|/@kf-live|rights=listen|image=nobody.exe\n"
                               "deny|device|/net/ioctl/0x*|image=nobody.exe\n"
                               "deny|device|/dev/kf-live|value=0x00005401:0x00000000|image=nobody.exe\n"
                               "deny|peer|C:\\*|value=signal:*|image=nobody.exe\n"
                               "deny|peer|C:\\*|value=ptrace:*|image=nobody.exe\n";
    std::string files(list);
    for (size_t start = 0, active = 0; start < files.size(); active = !active) {
        const size_t end = std::min(files.find(':', start), files.size());
        const std::string file = files.substr(start, end - start);
        if (active) start = end + 1;   /* each file twice: its gates off, then on */
        std::FILE* in = std::fopen(file.c_str(), "rb");
        std::string text;
        for (int c; in != nullptr && (c = std::fgetc(in)) != EOF;) text += (char)c;
        if (in != nullptr) std::fclose(in);
        if (!Apply(active ? text + "\n" + others : text) || !OwnHandles()) {
            Expect("live reach: policy loads: " + file, false);
            continue;
        }
        kb_cfg cfg{};
        const __u32 zero = 0;
        const __u32 own = KB_TARGET_KEYED | KB_TARGET_PEER_VALUE | KB_TARGET_THREAD_VALUE | KB_TARGET_SYSTEM_VALUE |
                          KB_TARGET_WINDOW;
        Expect(std::string("live reach: K3's gates ") + (active ? "on: " : "off: ") + file,
               bpf_map_lookup_elem(MapOf("kb_config"), &zero, &cfg) == 0 &&
                   ((cfg.targets & own) == own) == (active != 0) && (active || (cfg.targets & own) == 0));
        /* K4's: kb_gates, data memory, syscall entry points (the live policies open none of them). */
        Config parsed = Parse(active ? text + "\n" + others : text);
        const bool k4 = Gates() != 0 && (cfg.memory_rules & KB_MEMORY_DATA) != 0 && parsed &&
                        !KfBpfSyscallPrograms(parsed.get()).empty();
        const bool k4Shut = Gates() == 0 && (cfg.memory_rules & KB_MEMORY_DATA) == 0 && parsed &&
                            KfBpfSyscallPrograms(parsed.get()).empty() && KfBpfSyscallKeys(parsed.get()).empty();
        Expect(std::string("live reach: K4's gates ") + (active ? "on: " : "off: ") + file, active ? k4 : k4Shut);
        std::set<std::string> images;
        for (size_t at = 0; at < text.size();) {
            size_t stop = text.find('\n', at);
            if (stop == std::string::npos) stop = text.size();
            const std::string line = text.substr(at, stop - at);
            at = stop + 1;
            if (line.rfind("protect ", 0) == 0) images.insert(line.substr(8));
            const size_t image = line.find("|image=");
            if (image != std::string::npos) images.insert(line.substr(image + 7, line.find('|', image + 7) - image - 7));
        }
        int same = 0, differ = 0;
        for (const std::string& program : images) {
            for (uint32_t req = 0; req < KB_REQ_COUNT; req++) {
                const bool handles = req == 27 || req == 28 || req == 23 || req == 293 || req == 294;   /* kind 1 skips */
                for (uint32_t field : {0u, 0x30042u, 0x500u, 0x100u, 0x104u}) {
                    if (handles && field != 0) continue;
                    Request request = Full({req, 0, 0, field, field, field});
                    request.image = "C:\\x\\" + program;
                    std::string why;
                    bool good = Same(request, why);
                    if ((req == KB_REQ_NEW_THREAD || req == KB_REQ_NEW_PROCESS) && good) {
                        Result result = Decide(request);
                        good = !result.logged && result.verdict == 0;
                        why = "decided: " + Describe(result);
                    }
                    if (good) same++;
                    else if (differ++ < 5) std::printf("  live reach %s: %s by %s at 0x%x: %s\n", file.c_str(), kRequests[req],
                                                       program.c_str(), field, why.c_str());
                }
            }
        }
        std::printf("  live reach %s (gates %s): %zu programs, %d requests come to the decisions they came to before, %d do "
                    "not\n", file.c_str(), active ? "on" : "off", images.size(), same, differ);
        Expect("live reach: every request decided as before: " + file, differ == 0 && same > 0);
    }
}

/* ---- the request pipe's hook itself (kb_bench.wine 9): kb_wine_request, both passes, kb_file_permission's dispatch ---- */

/* A request written as Wine writes it (Data in chunks of Sizes, the rest in the last; none: a plain write), decided by the
 * request pipe hook's own code. Data must outlive the request. */
Request Pipe(std::vector<uint32_t> header, const std::vector<uint8_t>& data = {}, std::vector<uint32_t> sizes = {})
{
    header.resize(16);
    header[1] = (uint32_t)data.size();
    return Chunked(std::move(header), data, std::move(sizes), 9);
}

/* An objattr naming Name behind a security descriptor of Sd bytes (Wine sends the descriptor a program gives). */
std::vector<uint8_t> ObjattrSd(const std::string& name, uint32_t sd)
{
    const std::vector<uint8_t> text = Utf16(name);
    const uint32_t head[4] = {0, 0, sd, (uint32_t)text.size()};
    std::vector<uint8_t> bytes((const uint8_t*)head, (const uint8_t*)head + sizeof(head));
    bytes.resize(bytes.size() + sd, 0x5A);
    bytes.insert(bytes.end(), text.begin(), text.end());
    return bytes;
}

/*
 * Requests as the request pipe's hook decides them, the code the live hook runs (kb_wine_request, its second pass after
 * an allowed system decision, the registry, NT object, handle and system dispatch, then what a request reaches): an
 * objattr name past the first 4 KiB of its data (behind a large security descriptor) decided whole as before the join,
 * not undecided and not a name failure; a get_thread_info reply still teaching kb_learnt when a rule names
 * get_thread_info; a rights-less peer deny meeting every access it met (masks of the pseudo-rights' old bits too); a
 * rule naming input meeting no handle open, a mask covering every process right no window or input decision; a split
 * name through ia32 iovecs.
 */
void PipeCase()
{
    WindowsAndThreads();
    kb_proc target{};
    target.ilen = (__u32)strlen(kMaple);
    target.ibase = (__u32)std::string(kMaple).rfind('\\') + 1;
    target.guarded = 1;   /* a protected program: another's handle open of it is a peer decision */
    memcpy(target.image, kMaple, target.ilen);
    const __u32 winpid = 0x3F0;
    Expect("pipe: MapleStory.exe protected, its pid written",
           bpf_map_update_elem(MapOf("kb_procs"), &kTarget, &target, BPF_ANY) == 0 &&
               bpf_map_update_elem(MapOf("kb_wintids"), &winpid, &kTarget, BPF_ANY) == 0);
    const std::string mutex = "deny|system|/system/wine/create_mutex/Global\\Cheat|image=grap-core64.aes";
    const std::string key = "deny|registry|\\Registry\\Machine\\Software\\Cheat";
    const std::string pipe = "deny|pipe|\\??\\pipe\\cheatpipe";
    const std::string cheat = "deny|system|/system/wine/new_process/C:\\x\\cheat.exe|image=grap-core64.aes";
    const std::string split = "deny|system|/system/wine/open_mutex/Global\\Split|image=grap-core64.aes";
    const std::string threadInfo = "deny|system|/system/wine/get_thread_info|image=nobody.exe";
    const std::string text = Head() + mutex + "\n" + key + "\n" + pipe + "\n" + cheat + "\n" + split + "\n" + threadInfo + "\n";
    Expect("pipe policy loads", Apply(text));
    for (uint32_t sd : {64u, 4072u, 4104u, 8192u}) {
        const std::string at = " (security descriptor of " + std::to_string(sd) + " bytes)";
        const std::vector<uint8_t> created = ObjattrSd("Global\\Cheat", sd);
        ExpectDecision("pipe: create_mutex refused by its name" + at, Pipe({KB_REQ_CREATE_MUTEX, 0, 0, 0x1F0001}, created),
                       KFilterActionDeny, RuleOf(text, mutex));
        const std::vector<uint8_t> cheatKey = ObjattrSd("\\Registry\\Machine\\Software\\Cheat", sd);
        ExpectDecision("pipe: create_key refused by its name" + at, Pipe({KB_REQ_CREATE_KEY, 0, 0, 0xF003F}, cheatKey),
                       KFilterActionDeny, RuleOf(text, key));
        const std::vector<uint8_t> legit = ObjattrSd("\\Registry\\Machine\\Software\\Legit", sd);
        Result allowed = Decide(Pipe({KB_REQ_CREATE_KEY, 0, 0, 0xF003F}, legit));
        Expect("pipe: another key's create allowed, no name failure" + at,
               allowed.ran && allowed.verdict == 0 && allowed.logged && (allowed.event.flags & KFILTER_EVENT_FLAG_NAME_FAILURE) == 0);
        const std::vector<uint8_t> named = ObjattrSd("\\??\\pipe\\cheatpipe", sd);
        ExpectDecision("pipe: create_named_pipe refused by its name" + at, Pipe({KB_REQ_CREATE_NAMED_PIPE, 0, 0, 0x120196}, named),
                       KFilterActionDeny, RuleOf(text, pipe));
        std::vector<uint8_t> child = ObjattrSd("", sd);
        const std::vector<uint8_t> startup = StartupData("C:\\x\\cheat.exe");
        child.insert(child.end(), startup.begin() + 16, startup.end());
        ExpectDecision("pipe: new_process of cheat.exe by its image" + at,
                       Pipe({0, 0, 0, 0, 0, 0, 0, 0, 0x1FFFFF, 0, (uint32_t)(child.size() - 16 - sd)}, child),
                       KFilterActionDeny, RuleOf(text, cheat));
    }
    const std::vector<uint8_t> splitName = Utf16("Global\\Split");
    Request ia32 = Pipe({KB_REQ_OPEN_MUTEX, 0, 0, 0x1F0001}, splitName, {6, 3});
    ia32.compat = true;
    ExpectDecision("pipe: an ia32 writev, the name split across three chunks", ia32, KFilterActionDeny, RuleOf(text, split));
    /* get_thread_info through a handle kfilter cannot name, allowed by its own decision (a rule names the request for
     * another program): wineserver's reply still names the thread's process. */
    Decide(Pipe({KB_REQ_GET_THREAD_INFO, 0, 0, 0x140, 0x40}));
    const uint32_t reply[16] = {0, 0, winpid};
    Expect("pipe: get_thread_info's reply is read after its allowed decision", Decide(Reply(reply)).decided);
    const kb_hkey_id learntId{(__u32)getpid(), 0x140};
    __u32 learnt = 0;
    Expect("pipe: ... and names the thread's process (kb_learnt)",
           bpf_map_lookup_elem(MapOf("kb_learnt"), &learntId, &learnt) == 0 && learnt == kTarget);
    /* Peer rules and the pseudo-rights' bits. */
    const std::string everything = "deny|peer|C:\\*\\MapleStory.exe|image=grap-core64.aes";
    const std::string peers = Head() + everything + "\n";
    Expect("pipe: a rights-less peer deny loads", Apply(peers));
    for (uint32_t access : {0x10u, 0x4000u, 0x200000u, 0x400000u, 0x800000u, 0x1FFFFFu}) {
        char name[96];
        std::snprintf(name, sizeof(name), "pipe: the rights-less deny refuses OpenProcess(0x%x) as before", access);
        ExpectDecision(name, Pipe({KB_REQ_OPEN_PROCESS, 0, 0, winpid, access}), KFilterActionDeny, RuleOf(peers, everything));
    }
    const uint32_t hotkey = 185, attach = 187;
    ExpectDecision("pipe: ... and no window or input decision", Pipe({hotkey, 0, 0, 0x30042, 1, 0, 0x70}), 0, 0);
    const std::string input = "deny|peer|C:\\*\\MapleStory.exe|rights=input|image=grap-core64.aes";
    const std::string mask = "deny|peer|C:\\*\\MapleStory.exe|rights=0x1fffff|image=grap-core64.aes";
    const std::string inputs = Head() + input + "\n";
    Expect("pipe: a deny naming input loads", Apply(inputs));
    ExpectDecision("pipe: it refuses a hotkey on MapleStory.exe's window", Pipe({hotkey, 0, 0, 0x30042, 1, 0, 0x70}),
                   KFilterActionDeny, RuleOf(inputs, input));
    for (uint32_t access : {0x1FFFFFu, 0x02000000u, 0x10000000u, 0x4000u}) {
        char name[96];
        std::snprintf(name, sizeof(name), "pipe: ... but no OpenProcess(0x%x)", access);
        ExpectDecision(name, Pipe({KB_REQ_OPEN_PROCESS, 0, 0, winpid, access}), 0, 0);
    }
    const std::string masks = Head() + mask + "\n";
    Expect("pipe: a deny with a mask of every process right loads", Apply(masks));
    ExpectDecision("pipe: it refuses OpenProcess(0x10)", Pipe({KB_REQ_OPEN_PROCESS, 0, 0, winpid, 0x10}), KFilterActionDeny,
                   RuleOf(masks, mask));
    ExpectDecision("pipe: ... but no hotkey", Pipe({hotkey, 0, 0, 0x30042, 1, 0, 0x70}), 0, 0);
    ExpectDecision("pipe: ... and no AttachThreadInput", Pipe({attach, 0, 0, 0x504, 0x500, 1}), 0, 0);
}

/* ---- decisions kfilter did not make before ABI 11: only rules naming them meet them ---- */

/* A space's root (KB_ROOT): a literal parent shorter than it and a wildcard rule whose fixed head is shorter do not meet
 * a decision in the space, rules naming it do; old decisions meet the same rules as before. A hot syscall's root lies
 * past its name, so only rules naming its argument meet it. */
void RootCase()
{
    /* kfilterctl refuses rules on a hot call that do not name its argument: the first two are set here. */
    const std::string text = Head() + "deny|system|/system/*\n" + "deny|system|/system\n" + "deny|system|/system/sys*\n" +
                             "audit|system|/system/syscall/rt_sigaction|image=MapleStory.exe\n" +
                             "deny|system|/system/syscall/*|image=DwarfAxe.exe\n" +
                             "deny|system|/kf-root/a|image=grap-core64.aes\n" + "deny|system|/kf-root/b|image=grap-core64.aes\n" +
                             "deny|system|/system/syscall/futex/9|image=grap-core64.aes\n";
    Config config = Parse(text);
    Expect("root policy parses", config != nullptr);
    if (!config) return;
    wcscpy(config->Rules[RuleOf(text, "deny|system|/kf-root/a|image=grap-core64.aes") - 1].Path, L"/system/syscall/futex");
    wcscpy(config->Rules[RuleOf(text, "deny|system|/kf-root/b|image=grap-core64.aes") - 1].Path, L"/system/syscall/futex/*");
    Expect("root policy loads", Load(config.get()));
    const uint32_t syscallRoot = KB_ROOT(15);
    ExpectDecision("root: /system/* and the parent /system do not meet a syscall decision",
                   {KFILTER_TARGET_SYSTEM, KFILTER_RIGHT_WRITE, kGrap, "/system/syscall/getrandom/0x1", 0, syscallRoot}, 0, 0);
    ExpectDecision("root: a rule on the syscall's own path meets it",
                   {KFILTER_TARGET_SYSTEM, KFILTER_RIGHT_WRITE, kMaple, "/system/syscall/rt_sigaction/5", 0, syscallRoot},
                   KFilterActionAudit, RuleOf(text, "audit|system|/system/syscall/rt_sigaction|image=MapleStory.exe"));
    ExpectDecision("root: a wildcard whose head names the space meets it",
                   {KFILTER_TARGET_SYSTEM, KFILTER_RIGHT_WRITE, kDwarf, "/system/syscall/getrandom/0x1", 0, syscallRoot},
                   KFilterActionDeny, RuleOf(text, "deny|system|/system/syscall/*|image=DwarfAxe.exe"));
    ExpectDecision("root: an old decision still meets /system/*", {KFILTER_TARGET_SYSTEM, KFILTER_RIGHT_QUERY, kGrap, "/system/uname"},
                   KFilterActionDeny, RuleOf(text, "deny|system|/system/*"));
    const uint32_t hotRoot = KB_ROOT(std::string("/system/syscall/futex/").size() + 1);
    ExpectDecision("root: a hot call's parent and a wildcard over its argument do not meet it",
                   {KFILTER_TARGET_SYSTEM, KFILTER_RIGHT_WRITE, kGrap, "/system/syscall/futex/0", 0, hotRoot}, 0, 0);
    ExpectDecision("root: a rule naming a hot call's argument meets it",
                   {KFILTER_TARGET_SYSTEM, KFILTER_RIGHT_WRITE, kGrap, "/system/syscall/futex/9", 0, hotRoot},
                   KFilterActionDeny, RuleOf(text, "deny|system|/system/syscall/futex/9|image=grap-core64.aes"));
}

/* KB_TARGET_SIGNAL: a peer decision of a new kind (a signal, a ptrace READ check) meets only peer rules naming one
 * (value=signal:0x..., ptrace:0x...), so the live loop's rights-less peer denies and its rights= ones
 * (query-limited-information for get_process_info) keep meeting the Wine requests they met, and a peer rule with another
 * value= (a window message's number) meets none. Values set here directly; ValueCrossCase writes them as policy text. */
void ValueNamedCase()
{
    const std::string plain = "deny|peer|C:\\*\\MapleStory.exe|image=grap-core64.aes";
    const std::string rights = "deny|peer|C:\\*\\MapleStory.exe|rights=terminate,query-limited-information|image=DwarfAxe.exe";
    const std::string valued = "deny|peer|C:\\*\\MapleStory.exe|rights=terminate|image=nexon_client.exe";
    const std::string message = "deny|peer|C:\\*\\MapleStory.exe|image=MapleStory.exe";
    const std::string mode = "deny|peer|C:\\*\\MapleStory.exe|image=winedevice.exe";
    const std::string text = Head() + plain + "\n" + rights + "\n" + valued + "\n" + message + "\n" + mode + "\n";
    Config config = Parse(text);
    Expect("value-named policy parses", config != nullptr);
    if (!config) return;
    wcscpy(config->Rules[RuleOf(text, valued) - 1].Value, L"signal:0x00000009");
    wcscpy(config->Rules[RuleOf(text, message) - 1].Value, L"0x00000009");    /* a window message's number */
    wcscpy(config->Rules[RuleOf(text, mode) - 1].Value, L"ptrace:0x00000009");
    Expect("value-named policy loads", Load(config.get()));
    const uint32_t named = KB_TARGET_SIGNAL;
    ExpectDecision("value: a rights-less peer deny does not meet a signal",
                   {named, 0x1, kGrap, kMaple, 0, 1, {}, {}, {}, 1, false, "signal:0x00000009"}, 0, 0);
    ExpectDecision("value: a peer deny naming terminate without a value does not meet it",
                   {named, 0x1, kDwarf, kMaple, 0, 1, {}, {}, {}, 1, false, "signal:0x00000009"}, 0, 0);
    ExpectDecision("value: a peer rule naming the signal meets it",
                   {named, 0x1, kNexon, kMaple, 0, 1, {}, {}, {}, 1, false, "signal:0x00000009"},
                   KFilterActionDeny, RuleOf(text, valued));
    ExpectDecision("value: another signal passes it", {named, 0x1, kNexon, kMaple, 0, 1, {}, {}, {}, 1, false,
                                                       "signal:0x00000013"}, 0, 0);
    ExpectDecision("value: a peer rule with a message's value= does not meet the signal of that number",
                   {named, 0x1, kMaple, kMaple, 0, 1, {}, {}, {}, 1, false, "signal:0x00000009"}, 0, 0);
    ExpectDecision("value: nor does one naming the READ mode of that number",
                   {named, 0x1, kDevice, kMaple, 0, 1, {}, {}, {}, 1, false, "signal:0x00000009"}, 0, 0);
    ExpectDecision("value: which meets that mode", {named, 0x400, kDevice, kMaple, 0, 1, {}, {}, {}, 1, false, "ptrace:0x00000009"},
                   KFilterActionDeny, RuleOf(text, mode));
    ExpectDecision("value: the rights-less deny still meets a Wine request on the program",
                   {KFILTER_TARGET_PEER, 0x10, kGrap, kMaple, 0, 1}, KFilterActionDeny, RuleOf(text, plain));
    ExpectDecision("value: the rights= deny still meets query-limited-information requests",
                   {KFILTER_TARGET_PEER, 0x1000, kDwarf, kMaple, 0, 1}, KFilterActionDeny, RuleOf(text, rights));
}

/* New rights: a file rule without rights= covers every right but lock, chdir and touch; a pipe deny without rights= is
 * loaded without listen (an AF_UNIX server's decision), so the live loop's display denies keep refusing only connects. */
void RightsCase()
{
    const std::string text = Head() + "deny|file|/kf-rights/a\n" + "deny|file|/kf-rights/b|rights=lock\n" +
                             "deny|dir|/kf-rights/d\n" + "deny|dir|/kf-rights/e|rights=chdir\n" +
                             "deny|pipe|/@/tmp/.X11-unix/X0|exact\n" + "deny|pipe|/@/tmp/.X11-unix/X6|rights=listen|exact\n";
    Expect("rights policy loads", Apply(text));
    ExpectDecision("rights: a file deny without rights= does not meet a lock", {KFILTER_TARGET_FILE, KFILTER_RIGHT_LOCK, kMaple,
                                                                                "/kf-rights/a", 0, 1}, 0, 0);
    ExpectDecision("rights: ... still refuses a read", {KFILTER_TARGET_FILE, KFILTER_RIGHT_READ, kMaple, "/kf-rights/a"},
                   KFilterActionDeny, RuleOf(text, "deny|file|/kf-rights/a"));
    ExpectDecision("rights: rights=lock refuses a lock", {KFILTER_TARGET_FILE, KFILTER_RIGHT_LOCK, kMaple, "/kf-rights/b", 0, 1},
                   KFilterActionDeny, RuleOf(text, "deny|file|/kf-rights/b|rights=lock"));
    ExpectDecision("rights: a dir deny without rights= does not meet a chdir", {KFILTER_TARGET_DIR, KFILTER_RIGHT_CHDIR, kMaple,
                                                                                "/kf-rights/d", 0, 1}, 0, 0);
    ExpectDecision("rights: rights=chdir refuses one", {KFILTER_TARGET_DIR, KFILTER_RIGHT_CHDIR, kMaple, "/kf-rights/e", 0, 1},
                   KFilterActionDeny, RuleOf(text, "deny|dir|/kf-rights/e|rights=chdir"));
    ExpectDecision("rights: a pipe deny without rights= does not meet an AF_UNIX listen",
                   {KFILTER_TARGET_PIPE, KFILTER_RIGHT_LISTEN, kMaple, "/@/tmp/.X11-unix/X0", 0, 1}, 0, 0);
    ExpectDecision("rights: ... still refuses a connect", {KFILTER_TARGET_PIPE, KFILTER_RIGHT_CONNECT, kMaple, "/@/tmp/.X11-unix/X0"},
                   KFilterActionDeny, RuleOf(text, "deny|pipe|/@/tmp/.X11-unix/X0|exact"));
    ExpectDecision("rights: rights=listen refuses a listen", {KFILTER_TARGET_PIPE, KFILTER_RIGHT_LISTEN, kMaple,
                                                              "/@/tmp/.X11-unix/X6", 0, 1},
                   KFilterActionDeny, RuleOf(text, "deny|pipe|/@/tmp/.X11-unix/X6|rights=listen|exact"));
}

/* ---- /system/syscall/<name>[/<key>] (F4) ---- */

/* Syscall Nr of an x86_64 (Compat 0) or ia32 program, decided as its entry point's program decides it. */
Request Syscall(const std::string& image, uint32_t nr, uint32_t compat, std::vector<uint64_t> arguments)
{
    Request request{KFILTER_TARGET_SYSTEM, 0, image, ""};
    request.wine.assign(16, 0);
    request.wine[0] = nr;
    request.wine[1] = compat;
    for (size_t i = 0; i < arguments.size() && i < 6; i++) {
        request.wine[2 + 2 * i] = (uint32_t)arguments[i];
        request.wine[3 + 2 * i] = (uint32_t)(arguments[i] >> 32);
    }
    request.kind = 6;
    return request;
}

/* The decision's path, from the event a deciding rule logged. */
void ExpectPath(const std::string& name, const Request& request, const std::string& path)
{
    Result result = Decide(request);
    const bool good = result.logged && std::string(result.event.path) == path;
    if (!good) std::printf("  %s: path '%s' (%s)\n", name.c_str(), result.logged ? result.event.path : "", Describe(result).c_str());
    Expect(name, good);
}

/* Each table's names and keys (an ia32 call under its x86_64 name), a zero-argument call, addr= on munmap, a hot call met
 * only by a rule naming its argument, and wildcards written before the space that never meet it. */
void SyscallCase()
{
    const std::string text = Head() + "deny|system|/system/*|image=services.exe\n" + "audit|system|/system\n" +
                             "deny|system|/system/syscall/rt_sigaction/5|image=MapleStory.exe\n" +
                             "deny|system|/system/syscall/fcntl/6\n" +
                             "deny|system|/system/syscall/getrandom|image=grap-core64.aes\n" +
                             "deny|system|/system/syscall/munmap|addr=0x7000000000-0x7000000FFF\n" +
                             "deny|system|/system/syscall/futex/9|image=MapleStory.exe\n" +
                             "audit|system|/system/syscall/getpid\n" + "audit|system|/system/syscall/wait4/any\n" +
                             "deny|system|/system/syscall/connect|image=MapleStory.exe\n" +
                             "deny|system|/system/syscall/socket/16|image=MapleStory.exe\n" +
                             "audit|system|/system/syscall/shmdt\n" + "audit|system|/system/syscall/rt_sigreturn\n" +
                             "audit|system|/system/syscall/sigreturn\n" +
                             "deny|system|/system/syscall/select/3|image=MapleStory.exe\n";
    Expect("syscall policy loads", Apply(text));
    const uint32_t sigaction = RuleOf(text, "deny|system|/system/syscall/rt_sigaction/5|image=MapleStory.exe");
    ExpectDecision("syscall: rt_sigaction(SIGTRAP) refused (x86_64)", Syscall(kMaple, 13, 0, {5, 0x1000}), KFilterActionDeny,
                   sigaction);
    ExpectDecision("syscall: ... and through the ia32 entry", Syscall(kMaple, 174, 1, {5, 0x1000}), KFilterActionDeny, sigaction);
    ExpectPath("syscall: its event names the call and its signal", Syscall(kMaple, 13, 0, {5}), "/system/syscall/rt_sigaction/5");
    ExpectDecision("syscall: rt_sigaction(SIGSEGV) left alone (/system/* and /system do not meet it)",
                   Syscall(kMaple, 13, 0, {11}), 0, 0);
    ExpectDecision("syscall: the legacy ia32 sigaction is its own name", Syscall(kMaple, 67, 1, {5}), 0, 0);
    const uint32_t setlk = RuleOf(text, "deny|system|/system/syscall/fcntl/6");
    ExpectDecision("syscall: fcntl(F_SETLK) refused", Syscall(kGrap, 72, 0, {3, 6}), KFilterActionDeny, setlk);
    ExpectDecision("syscall: ... and as ia32 fcntl64", Syscall(kGrap, 221, 1, {3, 6}), KFilterActionDeny, setlk);
    ExpectDecision("syscall: fcntl(F_GETFL) left alone", Syscall(kGrap, 72, 0, {3, 3}), 0, 0);
    const uint32_t random = RuleOf(text, "deny|system|/system/syscall/getrandom|image=grap-core64.aes");
    ExpectDecision("syscall: getrandom refused to its program", Syscall(kGrap, 318, 0, {0x1000, 16, 1}), KFilterActionDeny, random);
    ExpectPath("syscall: its flags in hex", Syscall(kGrap, 318, 0, {0x1000, 16, 1}), "/system/syscall/getrandom/0x1");
    ExpectDecision("syscall: getrandom left to another", Syscall(kDwarf, 318, 0, {0x1000, 16, 1}), 0, 0);
    const uint32_t unmap = RuleOf(text, "deny|system|/system/syscall/munmap|addr=0x7000000000-0x7000000FFF");
    ExpectDecision("syscall: munmap inside an addr= range refused", Syscall(kMaple, 11, 0, {0x7000000800, 0x1000}),
                   KFilterActionDeny, unmap);
    ExpectDecision("syscall: ... and as ia32 munmap below 4 GiB, outside it", Syscall(kMaple, 91, 1, {0x10000, 0x1000}), 0, 0);
    ExpectDecision("syscall: munmap outside it left alone", Syscall(kMaple, 11, 0, {0x10000, 0x1000}), 0, 0);
    const uint32_t futex = RuleOf(text, "deny|system|/system/syscall/futex/9|image=MapleStory.exe");
    ExpectDecision("syscall: a hot call met by a rule naming its argument (FUTEX_WAIT_BITSET, private)",
                   Syscall(kMaple, 202, 0, {0x1000, 9 | 128}), KFilterActionDeny, futex);
    ExpectDecision("syscall: ... and as ia32 futex_time64", Syscall(kMaple, 422, 1, {0x1000, 9}), KFilterActionDeny, futex);
    ExpectDecision("syscall: another futex op left alone", Syscall(kMaple, 202, 0, {0x1000, 0}), 0, 0);
    ExpectDecision("syscall: a zero-argument call (getpid, both tables' entry)", Syscall(kGrap, 39, 0, {}), KFilterActionAudit,
                   RuleOf(text, "audit|system|/system/syscall/getpid"));
    ExpectDecision("syscall: ... from ia32", Syscall(kGrap, 20, 1, {}), KFilterActionAudit,
                   RuleOf(text, "audit|system|/system/syscall/getpid"));
    ExpectDecision("syscall: wait4 for any child", Syscall(kGrap, 61, 0, {(uint64_t)-1}), KFilterActionAudit,
                   RuleOf(text, "audit|system|/system/syscall/wait4/any"));
    ExpectDecision("syscall: wait4 for a group is another key", Syscall(kGrap, 61, 0, {0}), 0, 0);
    ExpectDecision("syscall: services.exe's /system/* deny does not meet a syscall", Syscall("C:\\windows\\system32\\services.exe",
                                                                                     318, 0, {0, 0, 1}), 0, 0);
    ExpectDecision("syscall: a number no table has passes", Syscall(kGrap, 500, 0, {}), 0, 0);
    /* ia32: socketcall and ipc as the call they carry, its keys from its argument block (32-bit pointers), the LFS lock
     * commands as x86_64's, the old select's nfds from its block, the compat sigreturns' entry points. */
    uint32_t* low = (uint32_t*)mmap(nullptr, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
    Expect("syscall: memory an ia32 call can point to", low != MAP_FAILED);
    if (low == MAP_FAILED) return;
    const uint64_t block = (uint64_t)(uintptr_t)low;
    low[0] = 16;   /* socket(AF_NETLINK, ...); select(3, ...) */
    low[1] = 3;
    const uint32_t connect = RuleOf(text, "deny|system|/system/syscall/connect|image=MapleStory.exe");
    ExpectDecision("syscall: socketcall(SYS_CONNECT) is connect", Syscall(kMaple, 102, 1, {3, block}), KFilterActionDeny, connect);
    ExpectDecision("syscall: ... and so is ia32's own connect", Syscall(kMaple, 362, 1, {5, 0, 16}), KFilterActionDeny, connect);
    ExpectDecision("syscall: socketcall(SYS_SOCKET, AF_NETLINK) is socket/16", Syscall(kMaple, 102, 1, {1, block}),
                   KFilterActionDeny, RuleOf(text, "deny|system|/system/syscall/socket/16|image=MapleStory.exe"));
    ExpectPath("syscall: ... by its event", Syscall(kMaple, 102, 1, {1, block}), "/system/syscall/socket/16");
    ExpectDecision("syscall: socketcall(SYS_SOCKET, AF_INET) is another key", Syscall(kMaple, 102, 1, {1, block + 4}), 0, 0);
    ExpectDecision("syscall: ipc(SHMDT) is shmdt, its version aside", Syscall(kGrap, 117, 1, {22 | 1u << 16, 0, 0, 0, 0x1000}),
                   KFilterActionAudit, RuleOf(text, "audit|system|/system/syscall/shmdt"));
    ExpectDecision("syscall: fcntl64(F_SETLK64) is fcntl/6", Syscall(kGrap, 221, 1, {3, 13}), KFilterActionDeny, setlk);
    ExpectDecision("syscall: ia32's old select by the nfds in its block", Syscall(kMaple, 82, 1, {block + 4}), KFilterActionDeny,
                   RuleOf(text, "deny|system|/system/syscall/select/3|image=MapleStory.exe"));
    ExpectDecision("syscall: ia32 rt_sigreturn", Syscall(kGrap, 173, 1, {}), KFilterActionAudit,
                   RuleOf(text, "audit|system|/system/syscall/rt_sigreturn"));
    ExpectDecision("syscall: ia32 sigreturn", Syscall(kGrap, 119, 1, {}), KFilterActionAudit,
                   RuleOf(text, "audit|system|/system/syscall/sigreturn"));
    munmap(low, 4096);
    /* What the rules name of each call (kb_syscall_keys, the rule set in force): a call none names, or a key none names,
     * is not decided. */
    auto named = [](uint32_t ia32, uint32_t nr, kb_syscall_named& entry) {
        const __u32 zero = 0;
        __u32 live = 0;
        bpf_map_lookup_elem(MapOf("kb_live"), &zero, &live);
        const __u32 index = live << 10 | ia32 << 9 | nr;
        entry = kb_syscall_named{};
        return bpf_map_lookup_elem(MapOf("kb_syscall_keys"), &index, &entry) == 0;
    };
    kb_syscall_named entry{};
    Expect("syscall keys: futex names key 9 alone, in both tables",
           named(0, 202, entry) && !entry.any && entry.count == 1 && entry.key[0] == 9 && named(1, 422, entry) &&
               !entry.any && entry.count == 1 && entry.key[0] == 9);
    Expect("syscall keys: fcntl key 6", named(0, 72, entry) && !entry.any && entry.count == 1 && entry.key[0] == 6);
    Expect("syscall keys: wait4 the any class", named(0, 61, entry) && !entry.any && entry.count == 1 && entry.key[0] == 0);
    Expect("syscall keys: getrandom and connect any key", named(0, 318, entry) && entry.any && named(0, 42, entry) && entry.any);
    Expect("syscall keys: socket key 16", named(0, 41, entry) && !entry.any && entry.count == 1 && entry.key[0] == 16);
    Expect("syscall keys: a call no rule names has none", !named(0, 0, entry) && !named(1, 3, entry));
    Expect("syscall keys: two policies without syscall rules leave none",
           Apply(Head()) && Apply(Head()) && !named(0, 202, entry) && !named(0, 72, entry));
}

/* ---- ABI 11's hooks (F5): each space's decisions, met only by rules naming the space ---- */

uint32_t Gates()
{
    const __u32 zero = 0;
    __u32 gates = 0;
    bpf_map_lookup_elem(MapOf("kb_gates"), &zero, &gates);
    return gates;
}

/* A system decision of ABI 11 on Path in a space Root bytes long, as its hook makes it. */
Request Space(const std::string& image, const std::string& path, uint32_t root, uint32_t rights = KFILTER_RIGHT_WRITE)
{
    return {KFILTER_TARGET_SYSTEM, rights, image, path, 0, 1 | KB_ROOT(root)};
}

/* One of ABI 11's decision functions (kb_bench_helper), for the program Image. */
Request Helper(const std::string& image, std::vector<uint32_t> arguments)
{
    Request request{KFILTER_TARGET_SYSTEM, 0, image, ""};
    request.wine.assign(16, 0);
    for (size_t i = 0; i < arguments.size() && i < 16; i++) request.wine[i] = arguments[i];
    request.kind = 7;
    return request;
}

/* A Wine process the kernel names Image (protected or not), for decisions whose actor is not the calling task. */
void Process(uint32_t tgid, const std::string& image, bool guarded)
{
    kb_proc proc{};
    proc.guarded = guarded;
    proc.ilen = (uint32_t)image.size();
    proc.ibase = (uint32_t)image.find_last_of('\\') + 1;
    memcpy(proc.image, image.data(), image.size());
    Expect("kb_procs written", bpf_map_update_elem(MapOf("kb_procs"), &tgid, &proc, BPF_ANY) == 0);
}

void HookSpacesCase()
{
    const std::string text = Head() + "deny|system|/system/*\n" + "deny|system|/system/socket/*\n" + "deny|system|/system/ipc/shm/*\n" +
                             "deny|system|/system/memory/*\n" + "deny|system|/system/sched\n" + "deny|system|/system/f*\n" +
                             "deny|system|/system/fcntl/setown\n" + "deny|system|/system/socket/shutdown|image=MapleStory.exe\n" +
                             "deny|system|/system/socketpair/unix/*\n" + "deny|system|/system/task/*\n" +
                             "deny|system|/system/cred/setuid\n" + "deny|system|/system/capability/sys_admin\n" +
                             "deny|system|/system/namespace/user\n" + "deny|system|/system/memory/low\n" +
                             "deny|system|/system/ipc/create/shm/*\n" + "deny|system|/system/ptrace/traceme\n" +
                             "deny|system|/system/kernel/module/*\n" + "deny|system|/system/fork|image=MapleStory.exe\n" +
                             "deny|system|/system/rlimit/nofile/other\n";
    Expect("hook spaces policy loads", Apply(text));
    const uint32_t wanted = KB_GATE_FCNTL | KB_GATE_SHUTDOWN | KB_GATE_SOCKETPAIR | KB_GATE_TASK | KB_GATE_CRED |
                            KB_GATE_CAPABILITY | KB_GATE_NAMESPACE | KB_GATE_LOW | KB_GATE_IPC | KB_GATE_PTRACE |
                            KB_GATE_KERNEL | KB_GATE_FORK | KB_GATE_RLIMIT;
    Expect("hook spaces: the gates of the spaces the rules name, no other", Gates() == wanted);
    const struct { const char* path; uint32_t root; const char* rule; } spaces[] = {
        {"/system/fcntl/setown", 13, "deny|system|/system/fcntl/setown"},
        {"/system/socket/shutdown/wr", 23, "deny|system|/system/socket/shutdown|image=MapleStory.exe"},
        {"/system/socketpair/unix/stream/0", 18, "deny|system|/system/socketpair/unix/*"},
        {"/system/task/getpgid", 12, "deny|system|/system/task/*"},
        {"/system/cred/setuid", 12, "deny|system|/system/cred/setuid"},
        {"/system/capability/sys_admin", 18, "deny|system|/system/capability/sys_admin"},
        {"/system/namespace/user", 17, "deny|system|/system/namespace/user"},
        {"/system/memory/low", 18, "deny|system|/system/memory/low"},
        {"/system/ipc/create/shm/00001234", 18, "deny|system|/system/ipc/create/shm/*"},
        {"/system/ptrace/traceme", 14, "deny|system|/system/ptrace/traceme"},
        {"/system/kernel/module/net-pf-9", 14, "deny|system|/system/kernel/module/*"},
    };
    for (const auto& space : spaces) {
        ExpectDecision(std::string("hook spaces: ") + space.path + " meets the rule naming it", Space(kMaple, space.path, space.root),
                       KFilterActionDeny, RuleOf(text, space.rule));
    }
    ExpectDecision("hook spaces: /system/socket/* does not meet a shutdown", Space(kGrap, "/system/socket/shutdown/wr", 23), 0, 0);
    ExpectDecision("hook spaces: /system/* and /system/f* do not meet /system/fcntl/notify", Space(kGrap, "/system/fcntl/notify", 13), 0, 0);
    ExpectDecision("hook spaces: /system/ipc/shm/* does not meet a creation", Space(kGrap, "/system/ipc/create/msg/00000000", 18), 0, 0);
    ExpectDecision("hook spaces: /system/socket/* still meets a socket", Space(kGrap, "/system/socket/inet/stream/6", 0, KFILTER_RIGHT_CREATE),
                   KFilterActionDeny, RuleOf(text, "deny|system|/system/*"));
    ExpectDecision("hook spaces: a fork refused to its program", Helper(kMaple, {1}), KFilterActionDeny,
                   RuleOf(text, "deny|system|/system/fork|image=MapleStory.exe"));
    ExpectDecision("hook spaces: ... left to another (/system/f* does not meet it)", Helper(kGrap, {1}), 0, 0);
    ExpectDecision("hook spaces: prlimit64 of another process's open files refused", Helper(kGrap, {2, 7, 1, KFILTER_RIGHT_WRITE}),
                   KFilterActionDeny, RuleOf(text, "deny|system|/system/rlimit/nofile/other"));
    ExpectPath("hook spaces: its path names the resource", Helper(kGrap, {2, 7, 1, KFILTER_RIGHT_WRITE}), "/system/rlimit/nofile/other");
    ExpectDecision("hook spaces: its own left alone", Helper(kGrap, {2, 7, 0, KFILTER_RIGHT_WRITE}), 0, 0);
    Expect("hook spaces: a policy naming none of them sets no gate", Apply(Head()) && Gates() == 0);
}

/* Signals of the kinds kfilter did not decide (kb_reach_decide, for kill and SIGIO): inside the family only peer rules
 * with a value= (the signal) meet them; across its boundary block-process-signals asks for a HANDLE grant. The calling
 * task is the target; an actor is a Wine process the bench names (protected) or init (outside). */
void SignalCase()
{
    const uint32_t actor = 0x3FFFFF02;
    Process(actor, kGrap, true);
    const std::string plain = "deny|peer|C:\\*\\MapleStory.exe|image=grap-core64.aes";
    const std::string stop = "deny|peer|C:\\*\\MapleStory.exe|rights=terminate|image=grap-core64.aes";
    const std::string probe = "audit|peer|C:\\*\\MapleStory.exe|rights=query-limited-information|image=grap-core64.aes";
    const std::string text = Head() + plain + "\n" + stop + "\n" + probe + "\n";
    Config config = Parse(text);
    Expect("signal policy parses", config != nullptr);
    if (!config) return;
    wcscpy(config->Rules[RuleOf(text, stop) - 1].Value, L"signal:0x00000013");    /* SIGSTOP */
    wcscpy(config->Rules[RuleOf(text, probe) - 1].Value, L"signal:0x00000000");   /* kill(pid, 0) */
    Expect("signal policy loads", Load(config.get()) && (Gates() & KB_GATE_PEER) != 0);
    const uint32_t into = 2;   /* KB_REACH_INTO: the target task is protected */
    ExpectDecision("signal: SIGSTOP into the family refused by the peer rule naming it", Helper(kMaple, {3, actor, 0x1, 19, into}),
                   KFilterActionDeny, RuleOf(text, stop));
    ExpectPath("signal: its event names the target program and the signal", Helper(kMaple, {3, actor, 0x1, 19, into}),
               std::string(kMaple) + " signal=0x00000013");
    ExpectDecision("signal: SIGKILL passes (the rights-less peer deny does not meet a signal)", Helper(kMaple, {3, actor, 0x1, 9, into}), 0, 0);
    ExpectDecision("signal: a probe met by the rule naming it", Helper(kMaple, {3, actor, 0x1000, 0, into}), KFilterActionAudit,
                   RuleOf(text, probe));
    ExpectDecision("signal: from outside, without block-process-signals, not decided", Helper(kMaple, {3, 1, 0x1, 9, into}), 0, 0);
    const std::string init = KfNarrow(KfExePath(1));
    const std::string guarded = "block-process-signals\nallow|handle|" + init + "|rights=terminate|risk=init\n";
    const std::string handleText = Head() + guarded;
    Expect("signal: block-process-signals loads", Apply(handleText));
    ExpectDecision("signal: from init, granted terminate", Helper(kMaple, {3, 1, 0x1, 15, into}), KFilterActionAllow,
                   RuleOf(handleText, "allow|handle|" + init + "|rights=terminate|risk=init"));
    ExpectDecision("signal: init's probe is not granted query-limited-information", Helper(kMaple, {3, 1, 0x1000, 0, into}),
                   KFilterActionDeny, 0);
    Expect("signal: without the grant", Apply(Head() + "block-process-signals\n"));
    ExpectDecision("signal: from outside refused", Helper(kMaple, {3, 1, 0x1, 15, into}), KFilterActionDeny, 0);
    Process(actor, kGrap, false);
}

/* ---- finer decisions in the hooks kfilter had (F6) ---- */

/* An allowed device ioctl Cmd on Path decided again by its argument (kb_ioctl_argument), which Param points to (null: none). */
Request Argument(const std::string& image, const std::string& path, uint32_t cmd, const uint32_t* param)
{
    const uint64_t at = (uint64_t)(uintptr_t)param;
    Request request = Helper(image, {10, cmd, (uint32_t)at, (uint32_t)(at >> 32)});
    request.target = KFILTER_TARGET_DEVICE;
    request.path = path;
    return request;
}

/* Bytes for a decision function's kernel-memory argument (kb_bench.value_text): a netlink message, a sockaddr. */
Request WithBytes(Request request, const std::string& bytes)
{
    request.text = bytes;
    return request;
}

std::string Bytes(std::initializer_list<unsigned> values)
{
    std::string bytes;
    for (unsigned value : values) bytes += (char)value;
    return bytes;
}

/* prctl options, data memory with addr=, statfs, socket ioctls, every netlink family (generic by name), ioctl
 * arguments, AF_UNIX binds, touch; each met only by rules naming it, the live loop's own rules on the same paths
 * keeping what they met. */
void ExtendCase()
{
    const std::string text = Head() + "deny|system|/system/prctl/0x001a\n" +
                             "audit|system|/system/prctl/0x0019|image=grap-core64.aes\n" +
                             "deny|system|/system/memory/private\n" + "deny|system|/system/memory/private/*|image=DwarfAxe.exe\n" +
                             "deny|system|/system/memory/private/rw|addr=0x7000000000-0x7000000FFF\n" +
                             "deny|system|/system/memory/shared/none|image=MapleStory.exe\n" +
                             "deny|system|/system/statfs/kf-statfs/*\n" + "deny|device|/net/ioctl|image=MapleStory.exe\n" +
                             "deny|device|/net/ioctl/0x00008901\n" + "deny|device|/net/netlink/route|image=MapleStory.exe\n" +
                             "deny|device|/net/netlink/route/24\n" + "deny|device|/net/netlink/generic/kftest*\n" +
                             "deny|device|/net/netlink/audit/*|image=grap-core64.aes\n" +
                             "deny|device|/dev/dri/renderD128|value=0xC0106446:0x00000002\n" +
                             "allow|device|/dev/dri/renderD128|rights=raw-device|exact|uses=3|risk=gpu\n" +
                             "deny|pipe|/@kf-squat|rights=listen\n" + "deny|pipe|/@kf-other\n" + "deny|file|/kf-touch|rights=touch\n";
    Expect("extend policy loads", Apply(text));
    const uint32_t wanted = KB_GATE_PRCTL | KB_GATE_STATFS | KB_GATE_SOCKET_IOCTL | KB_GATE_NETLINK | KB_GATE_ARGUMENT |
                            KB_GATE_LISTEN | KB_GATE_TOUCH;
    kb_cfg cfg{};
    const __u32 zero = 0;
    bpf_map_lookup_elem(MapOf("kb_config"), &zero, &cfg);
    Expect("extend: the gates of the kinds the rules name", Gates() == wanted && cfg.memory_rules == (1 | KB_MEMORY_DATA));
    ExpectDecision("extend: PR_SET_TSC refused", Helper(kMaple, {4, 0x1a}), KFilterActionDeny, RuleOf(text, "deny|system|/system/prctl/0x001a"));
    ExpectPath("extend: its path", Helper(kMaple, {4, 0x1a}), "/system/prctl/0x001a");
    ExpectDecision("extend: PR_GET_TSC audited for its program", Helper(kGrap, {4, 0x19}), KFilterActionAudit,
                   RuleOf(text, "audit|system|/system/prctl/0x0019|image=grap-core64.aes"));
    ExpectDecision("extend: PR_SET_NAME left alone", Helper(kMaple, {4, 15}), 0, 0);
    const uint32_t rw = RuleOf(text, "deny|system|/system/memory/private/rw|addr=0x7000000000-0x7000000FFF");
    ExpectDecision("extend: mprotect RW inside the addr= range refused", Helper(kGrap, {5, 0x00000800, 0x70, 0x00000900, 0x70, 3, 0}),
                   KFilterActionDeny, rw);
    ExpectPath("extend: ... as /system/memory/private/rw with what it reached", Helper(kGrap, {5, 0x00000800, 0x70, 0x00000900, 0x70, 3, 0}),
               "/system/memory/private/rw addr=0x0000007000000800+256");
    ExpectDecision("extend: outside it left alone (the literal parent and /system/memory/private/* do not meet it)",
                   Helper(kDwarf, {5, 0x10000, 0, 0x11000, 0, 3, 0}), 0, 0);
    ExpectDecision("extend: an unknown place meets the addr= deny (fail closed)", Helper(kGrap, {5, 0, 0, 0x1000, 0, 3, 0}),
                   KFilterActionDeny, rw);
    ExpectDecision("extend: shared memory protected to none", Helper(kMaple, {5, 0x10000, 0, 0x11000, 0, 0, 1}), KFilterActionDeny,
                   RuleOf(text, "deny|system|/system/memory/shared/none|image=MapleStory.exe"));
    ExpectDecision("extend: executable memory still meets the literal parent", Helper(kGrap, {5, 0, 0, 0x1000, 0, 5, 0}),
                   KFilterActionDeny, RuleOf(text, "deny|system|/system/memory/private"));
    ExpectDecision("extend: statfs under a named path", Space(kMaple, "/system/statfs/kf-statfs/x", 14, KFILTER_RIGHT_QUERY),
                   KFilterActionDeny, RuleOf(text, "deny|system|/system/statfs/kf-statfs/*"));
    ExpectDecision("extend: statfs elsewhere", Space(kMaple, "/system/statfs/home", 14, KFILTER_RIGHT_QUERY), 0, 0);
    ExpectDecision("extend: FIOSETOWN on a socket refused",
                   {KFILTER_TARGET_DEVICE, KFILTER_RIGHT_RAW_DEVICE, kGrap, "/net/ioctl/0x00008901", 0x8901, 1 | KB_ROOT(11)},
                   KFilterActionDeny, RuleOf(text, "deny|device|/net/ioctl/0x00008901"));
    ExpectDecision("extend: the live loop's /net/ioctl deny does not meet another socket ioctl",
                   {KFILTER_TARGET_DEVICE, KFILTER_RIGHT_RAW_DEVICE, kMaple, "/net/ioctl/0x00008902", 0x8902, 1 | KB_ROOT(11)}, 0, 0);
    ExpectDecision("extend: ... and still meets SIOCGIF* as before",
                   {KFILTER_TARGET_DEVICE, KFILTER_RIGHT_RAW_DEVICE, kMaple, "/net/ioctl", 0x8913},
                   KFilterActionDeny, RuleOf(text, "deny|device|/net/ioctl|image=MapleStory.exe"));
    const std::string header(16, '\0');
    ExpectDecision("extend: RTM_NEWROUTE refused by the rule naming it", WithBytes(Helper(kMaple, {6, 0, 24}), header),
                   KFilterActionDeny, RuleOf(text, "deny|device|/net/netlink/route/24"));
    ExpectDecision("extend: the live loop's /net/netlink/route deny does not meet another route message",
                   WithBytes(Helper(kMaple, {6, 0, 26}), header), 0, 0);
    ExpectDecision("extend: an audit message", WithBytes(Helper(kGrap, {6, 9, 1000}), header), KFilterActionDeny,
                   RuleOf(text, "deny|device|/net/netlink/audit/*|image=grap-core64.aes"));
    const kb_genl_name name{"kftest"};
    const __u32 family = 0x3F0;
    Expect("extend: a generic family named", bpf_map_update_elem(MapOf("kb_genl"), &family, &name, BPF_ANY) == 0);
    ExpectPath("extend: a message to a generic family by name", WithBytes(Helper(kGrap, {6, 16, family}), header + Bytes({7, 1, 0, 0})),
               "/net/netlink/generic/kftest/7");
    ExpectPath("extend: looking a generic family up by name",
               WithBytes(Helper(kGrap, {6, 16, 0x10}), header + Bytes({3, 1, 0, 0, 11, 0, 2, 0}) + std::string("kftest\0", 7)),
               "/net/netlink/generic/kftest");
    const std::string gpu = "/dev/dri/renderD128";
    const uint32_t two = 2, one = 1;
    ExpectDecision("extend: an ioctl argument refused by the rule naming it", Argument(kMaple, gpu, 0xC0106446, &two),
                   KFilterActionDeny, RuleOf(text, "deny|device|/dev/dri/renderD128|value=0xC0106446:0x00000002"));
    ExpectDecision("extend: another argument meets no rule (the counted allow without a value= spends nothing)",
                   Argument(kMaple, gpu, 0xC0106446, &one), 0, 0);
    for (int use = 1; use <= 3; use++) {
        ExpectDecision("extend: the command itself meets the counted allow " + std::to_string(use),
                       {KFILTER_TARGET_DEVICE, KFILTER_RIGHT_RAW_DEVICE, kMaple, gpu, 0xC0106446, 1}, KFilterActionAllow,
                       RuleOf(text, "allow|device|/dev/dri/renderD128|rights=raw-device|exact|uses=3|risk=gpu"));
    }
    const std::string squat = Bytes({1, 0, 0}) + "kf-squat", other = Bytes({1, 0, 0}) + "kf-other";
    ExpectDecision("extend: an abstract bind refused by a listen rule", WithBytes(Helper(kMaple, {7, (uint32_t)squat.size()}), squat),
                   KFilterActionDeny, RuleOf(text, "deny|pipe|/@kf-squat|rights=listen"));
    ExpectDecision("extend: a pipe deny without rights= does not meet a bind", WithBytes(Helper(kMaple, {7, (uint32_t)other.size()}), other),
                   0, 0);
    ExpectDecision("extend: utimensat with no times refused by touch", {KFILTER_TARGET_FILE, KFILTER_RIGHT_TOUCH, kMaple, "/kf-touch", 0, 1},
                   KFilterActionDeny, RuleOf(text, "deny|file|/kf-touch|rights=touch"));
}

/* PTRACE_MODE_READ checks (kb_reach_decide with QUERY): inside the family only peer rules with a value= (the mode) meet
 * them, so the live loop's query-information denies keep meeting only the Wine requests they met; across the boundary
 * block-process-queries asks for a grant. */
void PtraceReadCase()
{
    const uint32_t actor = 0x3FFFFF03;
    Process(actor, kGrap, true);
    const std::string named = "deny|peer|C:\\*\\MapleStory.exe|rights=query-information|image=grap-core64.aes";
    const std::string live = "deny|peer|C:\\*\\MapleStory.exe|rights=query-information|image=DwarfAxe.exe";
    const std::string text = Head() + named + "\n" + live + "\n";
    Config config = Parse(text);
    Expect("ptrace READ policy parses", config != nullptr);
    if (!config) return;
    wcscpy(config->Rules[RuleOf(text, named) - 1].Value, L"ptrace:0x00000009");   /* PTRACE_MODE_READ_FSCREDS: /proc/<pid>/maps */
    Expect("ptrace READ policy loads", Load(config.get()));
    const uint32_t query = 4 | 2;   /* KB_REACH_QUERY | KB_REACH_INTO */
    ExpectDecision("ptrace READ: maps of a family member refused by the rule naming its mode",
                   Helper(kMaple, {3, actor, 0x400, 9, query}), KFilterActionDeny, RuleOf(text, named));
    ExpectPath("ptrace READ: its event names the mode", Helper(kMaple, {3, actor, 0x400, 9, query}),
               std::string(kMaple) + " ptrace=0x00000009");
    ExpectDecision("ptrace READ: another mode passes", Helper(kMaple, {3, actor, 0x400, 0x11, query}), 0, 0);
    Process(actor, kDwarf, true);
    ExpectDecision("ptrace READ: a query-information deny without a value= does not meet it",
                   Helper(kMaple, {3, actor, 0x400, 9, query}), 0, 0);
    const std::string init = KfNarrow(KfExePath(1));
    const std::string grantText = Head() + "block-process-queries\nallow|handle|" + init + "|rights=query-information|risk=init\n";
    Expect("ptrace READ: block-process-queries loads", Apply(grantText));
    ExpectDecision("ptrace READ: init granted", Helper(kMaple, {3, 1, 0x400, 9, query}), KFilterActionAllow,
                   RuleOf(grantText, "allow|handle|" + init + "|rights=query-information|risk=init"));
    Expect("ptrace READ: without the grant", Apply(Head() + "block-process-queries\n"));
    ExpectDecision("ptrace READ: from outside refused", Helper(kMaple, {3, 1, 0x400, 9, query}), KFilterActionDeny, 0);
    Expect("ptrace READ: without block-process-queries", Apply(Head()));
    ExpectDecision("ptrace READ: not decided", Helper(kMaple, {3, 1, 0x400, 9, query}), 0, 0);
    Process(actor, kDwarf, false);
}

uint32_t MemoryRules()
{
    kb_cfg cfg{};
    const __u32 zero = 0;
    bpf_map_lookup_elem(MapOf("kb_config"), &zero, &cfg);
    return cfg.memory_rules;
}

/* Data memory is decided only while a rule names a data protection: the live loop's executable-memory rules (rx and rwx
 * for nexon_client.exe and winedevice.exe) leave every non-executable mmap and mprotect undecided. */
void MemoryGateCase()
{
    const std::string rx = "deny|system|/system/memory/private/rx|exact|image=nexon_client.exe";
    const std::string exec = Head() + "deny|system|/system/memory/private/rwx|exact|image=nexon_client.exe\n" +
                             "deny|system|/system/memory/private/rwx|exact|image=winedevice.exe\n" + rx + "\n" +
                             "deny|system|/system/memory/shared/rwx\n" + "deny|system|/system/memory/private/*|image=DwarfAxe.exe\n" +
                             "deny|system|/system/memory/private/rx*|image=MapleStory.exe\n";
    Expect("memory gate: the loop's executable-memory rules load and decide executable memory alone",
           Apply(exec) && MemoryRules() == 1);
    ExpectDecision("memory gate: an RW mprotect is not decided under them", Helper(kNexon, {5, 0x10000, 0, 0x11000, 0, 3, 0}), 0, 0);
    ExpectDecision("memory gate: executable memory is", Helper(kNexon, {5, 0, 0, 0x1000, 0, 5, 0}), KFilterActionDeny,
                   RuleOf(exec, rx));
    for (const char* data : {"/system/memory/private/rw", "/system/memory/private/r", "/system/memory/shared/none",
                             "/system/memory/private/r*", "/system/memory/shared/n*", "/system/memory/private/rw*"}) {
        Expect(std::string("memory gate: ") + data + " decides data memory",
               Apply(Head() + "deny|system|" + data + "\n") && MemoryRules() == (1 | KB_MEMORY_DATA));
    }
}

/* A non-executable anonymous mmap is decided where the kernel placed it (kb_map_stash at lsm/mmap_file, kb_map_stashed at
 * lsm/mmap_addr), and in its own syscall only: the stash a failed mmap left is cleared by the next mmap. */
void StashCase()
{
    const std::string rw = "deny|system|/system/memory/private/rw|addr=0x7000000000-0x7000000FFF|image=MapleStory.exe";
    const std::string text = Head() + rw + "\n";
    Expect("stash policy loads", Apply(text));
    const uint32_t anonymous = 0x22;   /* MAP_PRIVATE | MAP_ANONYMOUS */
    auto stash = [](uint32_t prot, uint32_t flags, uint32_t data, uint32_t length) {
        return Decide(Helper(kMaple, {8, prot, flags, data, length})).ran;
    };
    auto placed = [](uint64_t at) { return Helper(kMaple, {9, (uint32_t)at, (uint32_t)(at >> 32)}); };
    Expect("stash: a hint-less RW mmap of 4 KiB", stash(3, anonymous, 1, 0x1000));
    ExpectDecision("stash: placed outside the addr= range, left alone", placed(0x10000), 0, 0);
    Expect("stash: another", stash(3, anonymous, 1, 0x1000));
    ExpectDecision("stash: placed inside it, refused at its real address", placed(0x7000000800), KFilterActionDeny, RuleOf(text, rw));
    Expect("stash: another", stash(3, anonymous, 1, 0x1000));
    ExpectPath("stash: its event says where", placed(0x7000000800), "/system/memory/private/rw addr=0x0000007000000800+4096");
    Expect("stash: an mmap that failed before its address, then a file mapping",
           stash(3, anonymous, 1, 0) && stash(1, 0x2 /* MAP_PRIVATE */, 0, 0));
    ExpectDecision("stash: the file mapping's address is no data decision", placed(0x7000000800), 0, 0);
}

/* An ioctl's argument (kb_ioctl_argument, KB_TARGET_ARGUMENT): met only by device rules whose value names one, never by a
 * value= glob over the command written before arguments were decided, and its event names the argument. */
void ArgumentCase()
{
    const std::string allow = "allow|device|/dev/dri/renderD128|rights=raw-device|exact|value=0xC0106446|uses=32767|risk=gpu";
    const std::string glob = "deny|device|/dev/dri/renderD128|value=0xC01064*";
    const std::string named = "deny|device|/dev/dri/renderD128|value=0xC0106446:0x00000001";
    const std::string every = "audit|device|/dev/dri/renderD129|value=*";
    const std::string text = Head() + allow + "\n" + glob + "\n" + named + "\n" + every + "\n";
    Expect("argument policy loads", Apply(text) && (Gates() & KB_GATE_ARGUMENT) != 0);
    const std::string gpu = "/dev/dri/renderD128";
    const uint32_t two = 2, one = 1;
    ExpectDecision("argument: the command meets its allow as before", {KFILTER_TARGET_DEVICE, KFILTER_RIGHT_RAW_DEVICE, kMaple,
                                                                         gpu, 0xC0106446, 1}, KFilterActionAllow, RuleOf(text, allow));
    ExpectDecision("argument: ... and another command the glob", {KFILTER_TARGET_DEVICE, KFILTER_RIGHT_RAW_DEVICE, kMaple, gpu,
                                                                  0xC0106447, 1}, KFilterActionDeny, RuleOf(text, glob));
    ExpectDecision("argument: the glob behind the command's allow does not meet its argument",
                   Argument(kMaple, gpu, 0xC0106446, &two), 0, 0);
    ExpectDecision("argument: the rule naming it refuses it", Argument(kMaple, gpu, 0xC0106446, &one), KFilterActionDeny,
                   RuleOf(text, named));
    ExpectPath("argument: its event names the argument after the path", Argument(kMaple, gpu, 0xC0106446, &one),
               gpu + " arg=0x00000001");
    ExpectDecision("argument: an audit of every command (value=*) does not meet one", Argument(kMaple, "/dev/dri/renderD129",
                                                                                               0xC0106446, &one), 0, 0);
    ExpectDecision("argument: an unreadable one meets no rule naming a value", Argument(kMaple, gpu, 0xC0106446, nullptr), 0, 0);
}

/* Text loaded with the bench's process not kfilterd (KfBpfApply names the loader so), for decisions the bench's own task
 * makes as a family member reaching another process. */
bool ApplyNotDaemon(const std::string& text)
{
    kb_cfg cfg{};
    const __u32 zero = 0;
    if (!Apply(text) || bpf_map_lookup_elem(MapOf("kb_config"), &zero, &cfg) != 0) return false;
    cfg.daemon_tgid = 0;
    return bpf_map_update_elem(MapOf("kb_config"), &zero, &cfg, BPF_ANY) == 0;
}

/* AF_UNIX servers (kb_unix_listen, from a listen, an accept, a connect or a datagram reaching the socket): one of the
 * program's on an abstract name is its pipe listen on /@name, met only by pipe rules naming listen. */
void UnixListenCase()
{
    const std::string named = "deny|pipe|/@kf-squat|rights=listen";
    const std::string text = Head() + named + "\n" + "deny|pipe|/@kf-other\n";
    Expect("unix listen policy loads", Apply(text) && (Gates() & KB_GATE_LISTEN) != 0);
    const std::string squat = Bytes({0}) + "kf-squat", other = Bytes({0}) + "kf-other";
    ExpectDecision("unix listen: a squatted abstract name refused", WithBytes(Helper(kMaple, {14}), squat), KFilterActionDeny,
                   RuleOf(text, named));
    ExpectPath("unix listen: as /@name", WithBytes(Helper(kMaple, {14}), squat), "/@kf-squat");
    ExpectDecision("unix listen: a pipe deny without rights= does not meet it", WithBytes(Helper(kMaple, {14}), other), 0, 0);
}

/* A file's SIGIO owner set across the family's boundary (kb_owner_decide: F_SETOWN, F_SETOWN_EX, FIOSETOWN, SIOCSPGRP)
 * is decided as the SIGIO its setter sends, since a socket's softirq raises it where nothing can be decided. */
void OwnerCase()
{
    const std::string init = KfNarrow(KfExePath(1));
    const std::string grant = "allow|open|" + init + "|rights=terminate|risk=init";
    Expect("owner: block-process-signals loads", ApplyNotDaemon(Head() + "block-process-signals\n"));
    ExpectDecision("owner: the family making init (outside) a file's owner refused", Helper(kMaple, {11, 1}), KFilterActionDeny, 0);
    ExpectDecision("owner: ... and init's process group, by its leader", Helper(kMaple, {11, (uint32_t)-1}), KFilterActionDeny, 0);
    ExpectDecision("owner: its own process is no reach", Helper(kMaple, {11, (uint32_t)getpid()}), 0, 0);
    const std::string text = Head() + "block-process-signals\n" + grant + "\n";
    Expect("owner: with an open grant of terminate", ApplyNotDaemon(text));
    ExpectDecision("owner: granted", Helper(kMaple, {11, 1}), KFilterActionAllow, RuleOf(text, grant));
    Expect("owner: without block-process-signals", ApplyNotDaemon(Head()));
    ExpectDecision("owner: not decided", Helper(kMaple, {11, 1}), 0, 0);
}

/* A file's SIGIO owner inside the family (kb_owner_decide, as F_SETOWN, FIOSETOWN and SIOCSPGRP call it): owner_decide's
 * gate, its owner's task found and protected, signal_reach's sender, then the peer rule naming SIGIO. The owner is a child
 * of the bench's (a task of its own), protected and named DwarfAxe.exe for the case. */
void OwnerFamilyCase()
{
    const pid_t child = fork();
    if (child == 0) {
        pause();
        _exit(0);
    }
    const int pidfd = child > 0 ? (int)syscall(SYS_pidfd_open, child, 0) : -1;
    kb_task task{};
    task.guarded = 1;
    Expect("owner family: a protected child", pidfd >= 0 && bpf_map_update_elem(MapOf("kb_tasks"), &pidfd, &task, BPF_ANY) == 0);
    Process((uint32_t)child, kDwarf, true);
    const std::string sigio = "deny|peer|C:\\*\\DwarfAxe.exe|rights=terminate|value=signal:0x0000001D|image=MapleStory.exe";
    const std::string text = Head() + sigio + "\n";
    Expect("owner family: the rule naming SIGIO loads, the peer gate on", ApplyNotDaemon(text) && (Gates() & KB_GATE_PEER) != 0);
    const Request owner = Helper(kMaple, {11, (uint32_t)child});
    ExpectDecision("owner family: MapleStory.exe making DwarfAxe.exe a file's owner meets it", owner, KFilterActionDeny,
                   RuleOf(text, sigio));
    ExpectPath("owner family: ... its event", owner, std::string(kDwarf) + " signal=0x0000001D");
    const __u32 tid = (__u32)syscall(SYS_gettid), client = 0x3FFFFF04;
    Expect("owner family: a winedevice thread serving a client", bpf_map_update_elem(MapOf("kb_serving"), &tid, &client, BPF_ANY) == 0);
    ExpectDecision("owner family: ... is not the setter (never decided)", owner, 0, 0);
    bpf_map_delete_elem(MapOf("kb_serving"), &tid);
    Expect("owner family: block-process-signals without the rule", ApplyNotDaemon(Head() + "block-process-signals\n") &&
                                                                    (Gates() & KB_GATE_PEER) == 0);
    ExpectDecision("owner family: ... decides no SIGIO inside the family", owner, 0, 0);
    Expect("owner family: neither", ApplyNotDaemon(Head()));
    ExpectDecision("owner family: not decided", owner, 0, 0);
    Process((uint32_t)child, kDwarf, false);
    if (child > 0) {
        kill(child, SIGKILL);
        waitpid(child, nullptr, 0);
    }
    if (pidfd >= 0) close(pidfd);
}

/* Who sends a signal or makes a READ check (kb_signal_reach, kb_read_reach), as begin() charges a request: never
 * wineserver for itself, and a winedevice thread for the client it serves. The target is init (outside the family). */
void ReachSenderCase()
{
    const uint32_t client = 0x3FFFFF04;
    Expect("sender: block-process-signals and -queries load",
           ApplyNotDaemon(Head() + "block-process-signals\nblock-process-queries\n"));
    ExpectDecision("sender: the family's probe of init refused", Helper(kMaple, {12, 1, 0, 0, 0}), KFilterActionDeny, 0);
    ExpectDecision("sender: wineserver's own probe is never decided", Helper(kMaple, {12, 1, 0, 0, KB_ROLE_WINESERVER}), 0, 0);
    ExpectDecision("sender: the family's READ check on init refused", Helper(kMaple, {13, 1, 9, 0, 0}), KFilterActionDeny, 0);
    ExpectDecision("sender: wineserver's own, outside a request, is Wine's", Helper(kMaple, {13, 1, 9, 0, KB_ROLE_WINESERVER}),
                   0, 0);
    Process(client, kExplorer, false);
    const __u32 tid = (__u32)syscall(SYS_gettid);
    Expect("sender: a winedevice thread serving explorer.exe",
           bpf_map_update_elem(MapOf("kb_serving"), &tid, &client, BPF_ANY) == 0);
    ExpectDecision("sender: its READ check is explorer.exe's (outside to outside)", Helper(kMaple, {13, 1, 9, 0, 0}), 0, 0);
    ExpectDecision("sender: its signals are never decided", Helper(kMaple, {12, 1, 0, 0, 0}), 0, 0);
    bpf_map_delete_elem(MapOf("kb_serving"), &tid);
}

/* A read through a handle kfilter cannot name, decided when wineserver reaches the target's task (kb_unknown_peer): at
 * the first reach, with its event; Wine 11's fallbacks for the same request after a refused process_vm_readv (ptrace,
 * /proc/<pid>/mem) meet that verdict without another event (they passed before, so the read did); the reply ends it.
 * The target is init, named MapleStory.exe; 0x108 is a handle not seen made. */
void UnknownReachCase()
{
    const uint32_t init = 1;
    Process(init, kMaple, false);
    const std::string read = "deny|peer|C:\\*\\MapleStory.exe|rights=vm-read|addr=0x140001000-0x140001FFF|image=grap-core64.aes";
    const std::string text = Head() + read + "\n";
    Expect("unknown reach policy loads", Apply(text));
    ExpectDecision("unknown reach: a read through a handle not seen made waits for wineserver's reach",
                   Wine({84, 0, 2, 0x108, 0x40001010, 1}), 0, 0);
    const Request reach = Helper(kGrap, {17, init});
    ExpectDecision("unknown reach: its first reach refused", reach, KFilterActionDeny, RuleOf(text, read));
    const Result fallback = Decide(reach);
    Expect("unknown reach: its fallback refused too, without another event",
           fallback.ran && fallback.verdict != 0 && !fallback.logged);
    const uint32_t reply[16] = {};
    Decide(Reply(reply));
    ExpectDecision("unknown reach: the reply ends the request", reach, 0, 0);
    ExpectDecision("unknown reach: a read outside the range", Wine({84, 0, 2, 0x108, 0x40002010, 1}), 0, 0);
    ExpectDecision("unknown reach: ... passes at its first reach", reach, 0, 0);
    ExpectDecision("unknown reach: ... and at its fallback", reach, 0, 0);
    bpf_map_delete_elem(MapOf("kb_procs"), &init);
}

/* ---- network decisions while policies reload (the block loop's question) ---- */

/* A network decision of grap-core64.aes as its hook makes it (kb_bench_net): What 1 connect, 2 send, 3 receive, 4 UDP
 * send through the peer cache, 5 UDP datagram received in softirq through it. */
Request Net(uint32_t what, uint32_t protocol, uint32_t port, std::array<uint8_t, 4> ip, uint32_t size = 0, uint32_t index = 0,
            const std::string& bytes = "")
{
    Request request{KFILTER_TARGET_NETWORK, 0, kGrap, ""};
    request.wine.assign(16, 0);
    request.wine[0] = what;
    request.wine[1] = 4;
    request.wine[2] = protocol;
    request.wine[3] = port;
    memcpy(&request.wine[4], ip.data(), 4);
    request.wine[8] = size;
    request.wine[9] = index;
    request.kind = 8;
    request.text = bytes;
    return request;
}

/* A send of grap-core64.aes to the AF_UNIX peer whose sun_path is SunPath (a leading NUL: an abstract name), named as
 * kb_socket_sendmsg names it (kb_bench_net 6): Sendto a sendto's address, else a connected peer bound to it. */
Request UnixSend(const std::string& sunPath, bool sendto, uint32_t size, uint32_t index, const std::string& bytes)
{
    Request request = Net(6, 0, 0, {0, 0, 0, 0}, size, index, bytes);
    request.wine[1] = sendto ? 1 : 0;
    request.path = sunPath;
    return request;
}

/* A DNS query for Name, type A, as a resolver sends it. */
std::string DnsQuery(const std::string& name)
{
    std::string query = Bytes({0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0});
    for (size_t start = 0; start <= name.size();) {
        const size_t dot = std::min(name.find('.', start), name.size());
        query += (char)(dot - start);
        query += name.substr(start, dot - start);
        start = dot + 1;
    }
    return query + Bytes({0, 0, 1, 0, 1});
}

std::string ReadFile(const std::string& path)
{
    std::FILE* file = std::fopen(path.c_str(), "rb");
    std::string text;
    for (int c; file != nullptr && (c = std::fgetc(file)) != EOF;) text += (char)c;
    if (file != nullptr) std::fclose(file);
    return text;
}

struct Times {
    std::vector<uint32_t> in, out;   /* ns, decisions made while a load ran and outside loads */
};

std::string Summary(std::vector<uint32_t> times)
{
    if (times.empty()) return "none";
    std::sort(times.begin(), times.end());
    double total = 0;
    for (uint32_t time : times) total += time;
    char text[160];
    std::snprintf(text, sizeof(text), "%zu, mean %.0f ns, median %u, p99 %u, max %u", times.size(), total / (double)times.size(),
                  times[times.size() / 2], times[times.size() * 99 / 100], times.back());
    return text;
}

/*
 * Can a policy swap refuse or stall a network decision? Two large policies (the live loop's steady and change ones when
 * given: about 7,800 file, registry and system rules each, network-default allow) load back to back while another thread
 * makes every network decision through the network decision functions the hooks call: a TCP connect, a send and a
 * receive on it, a UDP send to a resolver through the peer cache with a DNS query, the resolver's answer received in
 * softirq through the cache, a datagram from a peer the cache does not hold. Without and then with message rules (audits
 * that decide every send and receive without refusing). None of those may be refused; the decision times inside loads
 * are reported against those outside. The two policies also disagree: the first refuses connects to one address and
 * sends on port 8443, the second connects to another and receives on 8443, and with message rules each refuses sends to
 * its own AF_UNIX peer (unix=); a decision made between two loads must come to what the policy then in force says (one
 * that overlaps a load, to what either says).
 */
void NetReloadCase(const std::string& firstPath, const std::string& secondPath, int loads)
{
    std::string base[2];
    if (!firstPath.empty()) {
        base[0] = ReadFile(firstPath);
        base[1] = ReadFile(secondPath);
        Expect("net reload: the policy files read", !base[0].empty() && !base[1].empty());
        if (base[0].empty() || base[1].empty()) return;
    } else {
        base[0] = SysinfoPolicy(3, 7800, 1) + "network-loopback off\n";
        base[1] = SysinfoPolicy(9, 7811, 2) + "network-loopback off\n";
    }
    /* Rules that decide every send and receive (and the query's name) without refusing one. */
    const std::string messages = "deny|message|port=443|match=DEAD@0\naudit|message|rights=send,receive|port=443\n"
                                 "audit|message|rights=send|port=53\naudit|dns|*.nexon.com\n";
    /* What the two policies disagree on: by policy, connects to one address and messages one way on port 8443. */
    const std::string disagree[2] = {"deny|network|ip=198.51.100.7/32\n", "deny|network|ip=198.51.100.8/32\n"};
    /* ... and, with message rules, sends to one AF_UNIX peer or the other (unix=, ABI 12). */
    const std::string disagreeMessages[2] = {"deny|message|rights=send|port=8443\ndeny|message|unix=/@kf-first\n",
                                             "deny|message|rights=receive|port=8443\ndeny|message|unix=/@kf-second\n"};
    const std::array<uint8_t, 4> server{93, 184, 216, 34}, resolver{8, 8, 8, 8}, other{9, 9, 9, 9};
    const std::array<uint8_t, 4> first{198, 51, 100, 7}, second{198, 51, 100, 8};
    const std::string query = DnsQuery("nxsm-cdn.nexon.com");
    /* Pass 2: only the first policy has a unix= rule, so the unix gate opens and shuts with the loads. */
    for (int pass = 0; pass < 3; pass++) {
        const bool withMessages = pass == 1;
        Config configs[2];
        for (int policy = 0; policy < 2; policy++) {
            const std::string unixOnly = pass == 2 && policy == 0 ? "deny|message|unix=/@kf-first\n" : "";
            configs[policy] = Parse(base[policy] + disagree[policy] + (withMessages ? messages + disagreeMessages[policy] : unixOnly));
        }
        const std::string label = withMessages ? "net reload (message rules)" : pass == 2 ? "net reload (unix= in one policy)"
                                                                                         : "net reload";
        Expect(label + ": policies parse", configs[0] && configs[1]);
        if (!configs[0] || !configs[1] || !Load(configs[0].get())) return;
        const std::vector<uint8_t> fresh(bpf_map__value_size(bpf_object__find_map_by_name(gBench.object, "kb_bench_socks")));
        const __u32 zero = 0;
        bpf_map_update_elem(MapOf("kb_bench_socks"), &zero, fresh.data(), BPF_ANY);   /* an empty peer cache */
        static const char* const kinds[] = {"connect", "send", "receive", "UDP send", "DNS query", "datagram, cached peer",
                                            "datagram, new peer", "connect to the first's", "connect to the second's",
                                            "send on 8443", "receive on 8443", "unix send to the first's",
                                            "unix send to the second's"};
        /* Kinds 7-12: refused by policy 0 or 1 (or neither: -1). */
        const int refusedBy[6] = {0, 1, withMessages ? 0 : -1, withMessages ? 1 : -1, pass != 0 ? 0 : -1, withMessages ? 1 : -1};
        std::atomic<bool> done{false};
        std::atomic<int> epoch{0};   /* odd while a load runs; the policy in force is (epoch / 2) % 2 */
        std::atomic<int> refused{0}, failed{0}, wrong{0}, checked{0};
        Times times[13];
        std::string sample, wrongSample;
        std::thread decider([&] {
            for (uint32_t n = 1; !done; n++) {
                const Request requests[] = {Net(1, 6, 443, server), Net(2, 6, 443, server, 120, n), Net(3, 6, 443, server, 0, n),
                                            Net(4, 17, 53, resolver),
                                            Net(2, 17, 53, resolver, (uint32_t)query.size(), n, query),
                                            Net(5, 17, 53, resolver), Net(5, 17, 53, other),
                                            Net(1, 6, 443, first), Net(1, 6, 443, second),
                                            Net(2, 6, 8443, server, 120, n), Net(3, 6, 8443, server, 0, n),
                                            UnixSend(std::string(1, '\0') + "kf-first", false, 12, n, "x"),
                                            UnixSend(std::string(1, '\0') + "kf-second", true, 12, n, "x")};
                for (int kind = 0; kind < 13; kind++) {
                    const int before = epoch;
                    Result result = Decide(requests[kind]);
                    const int after = epoch;
                    if (!result.ran) failed++;
                    if (kind < 7 && result.verdict != 0) {
                        if (refused++ == 0) sample = std::string(kinds[kind]) + ": " + Describe(result);
                    }
                    if (kind >= 7 && before == after && before % 2 == 0) {
                        checked++;
                        if ((result.verdict != 0) != (refusedBy[kind - 7] == (before / 2) % 2) && wrong++ == 0)
                            wrongSample = std::string(kinds[kind]) + " under policy " + std::to_string((before / 2) % 2) +
                                          ": " + Describe(result);
                    }
                    (before % 2 != 0 || before != after ? times[kind].in : times[kind].out).push_back(result.duration);
                }
            }
        });
        double longest = 0;
        for (int load = 1; load <= loads; load++) {
            epoch++;
            auto start = std::chrono::steady_clock::now();
            const bool loaded = Load(configs[load % 2].get());
            longest = std::max(longest, Milliseconds(std::chrono::steady_clock::now() - start));
            epoch++;
            Expect(label + ": load " + std::to_string(load), loaded);
            std::this_thread::sleep_for(std::chrono::milliseconds(5));   /* decisions outside loads to compare with */
        }
        done = true;
        decider.join();
        /* The live loop's policies (when given): no ABI 11 gate open, data memory undecided (their rx and rwx rules). */
        for (int policy = 0; !firstPath.empty() && pass == 0 && policy < 2; policy++) {
            Expect(label + ": policy " + std::to_string(policy) + " opens no ABI 11 gate and decides no data memory",
                   Load(configs[policy].get()) && Gates() == 0 && (MemoryRules() & KB_MEMORY_DATA) == 0);
        }
        std::printf("  %s: %d loads of %u and %u rules (longest %.1f ms), %d refused%s%s; of %d decisions between loads, %d "
                    "against the policy in force%s%s\n", label.c_str(), loads, (unsigned)configs[0]->RuleCount,
                    (unsigned)configs[1]->RuleCount, longest, refused.load(), sample.empty() ? "" : ": ", sample.c_str(),
                    checked.load(), wrong.load(), wrongSample.empty() ? "" : ": ", wrongSample.c_str());
        Times all;
        for (int kind = 0; kind < 13; kind++) {
            std::printf("    %s: during loads %s; outside %s\n", kinds[kind], Summary(times[kind].in).c_str(),
                        Summary(times[kind].out).c_str());
            all.in.insert(all.in.end(), times[kind].in.begin(), times[kind].in.end());
            all.out.insert(all.out.end(), times[kind].out.begin(), times[kind].out.end());
        }
        std::printf("    all: during loads %s; outside %s\n", Summary(all.in).c_str(), Summary(all.out).c_str());
        Expect(label + ": every decision ran", failed == 0 && !all.in.empty() && !all.out.empty());
        Expect(label + ": no network decision both policies allow is refused while they reload", refused == 0);
        Expect(label + ": every decision between loads comes to what the policy in force says", checked > 0 && wrong == 0);
    }
}

/* ---- calls Wine answers in the program's own process (K5: kb_win32k's kb_up_decide, kb_wmi's ExecMethod) ---- */

/* Wine 11.0's x86_64 ntdll.so: its syscall dispatcher (KfWineDispatcher), the return after the call into a function, and
 * a return elsewhere in ntdll.so (Wine's own call of one of its functions). */
const kb_dispatch kWine11 = {0x4019c, 0x40514};
const uint64_t kDispatched = 0x4034a, kInNtdll = 0x3ea6c;

/* kb_w32names: the functions kfilterd would have attached, by slot; kb_dispatch: install 0 x86_64's dispatcher found,
 * install 0 i386's (slot 1) not. */
const char* const kUpNames[] = {"NtUserGetAsyncKeyState", "NtUserGetClassName", "NtUserInternalGetWindowText",
                                "NtUserSetWindowsHookEx", "NtUserGetClipboardData", "NtQueryInformationProcess",
                                "NtQuerySystemInformation", "NtQueryVirtualMemory", "NtSetContextThread", "NtUserCallHwndParam"};
enum { kAsyncKey, kClassName, kWindowText, kHook, kClipboard, kProcessInfo, kSystemInfo, kVirtualMemory, kSetContext, kHwndParam };

void UpTables()
{
    bool written = true;
    for (__u32 slot = 0; slot < sizeof(kUpNames) / sizeof(kUpNames[0]); slot++) {
        kb_w32name name{};
        strncpy(name.name, kUpNames[slot], sizeof(name.name) - 1);
        written &= bpf_map_update_elem(MapOf("kb_w32names"), &slot, &name, BPF_ANY) == 0;
    }
    const __u32 found = 0, missing = 1;
    const kb_dispatch none{};
    written &= bpf_map_update_elem(MapOf("kb_dispatch"), &found, &kWine11, BPF_ANY) == 0 &&
               bpf_map_update_elem(MapOf("kb_dispatch"), &missing, &none, BPF_ANY) == 0;
    Expect("kb_w32names and kb_dispatch written", written);
}

/* A cookie as Win32kApply makes it: Slot's function of win32u.so (or Ntdll), its kind, keys named or not, install 0's
 * library (Library 1: the one whose dispatcher was not found), its right. */
uint64_t Cookie(uint32_t slot, uint32_t kind, bool keyed, bool ntdll = false, uint32_t library = 0, uint32_t right = 0)
{
    return slot | KB_UP_COOKIE(kind, library, right) | (keyed ? KB_UP_KEYED : 0) | (ntdll ? KB_UP_NTDLL : 0) |
           (library & 1 ? KB_UP_I386 : 0);
}

/* A call kb_win32k decides, by Image (kb_bench_helper 15): Key its key argument, Where its return, Address and Handle
 * NtQueryVirtualMemory's (Address: a CONTEXT for NtSet/GetContextThread). */
Request Up(const std::string& image, uint64_t cookie, uint64_t key, uint64_t where = kDispatched, uint64_t address = 0,
           uint64_t handle = 0)
{
    std::vector<uint32_t> words = {15};
    for (uint64_t value : {cookie, key, address, handle, where}) {
        words.push_back((uint32_t)value);
        words.push_back((uint32_t)(value >> 32));
    }
    return Helper(image, words);
}

/* KfBpfUprobeFunctions' cookie for Function under Text, with its kb_w32names slot. */
uint64_t AttachedCookie(const std::string& text, const std::string& function, uint32_t slot)
{
    Config config = Parse(text);
    const std::map<std::string, uint64_t> exports = {{"NtUserCallHwndParam", 1}, {"NtUserGetClassName", 2}, {function, 3}};
    const std::map<std::string, uint64_t> named = config ? KfBpfUprobeFunctions(config.get(), false, exports)
                                                         : std::map<std::string, uint64_t>();
    return named.count(function) != 0 ? named.at(function) | slot : 0;
}

/*
 * What no rule can meet is skipped (NtUserCallHwndParam is called each frame on the program's own window): a function
 * attached for its keys alone makes no decision of its own (a star after /system/, which attaches nothing, does not meet
 * it, as before keys existed), its own window and the desktop none without a rule naming them; a window kfilter cannot
 * place (@unknown) is met by rules naming it alone, no wildcard, and no allow naming it is loaded.
 */
void InprocSkipCase()
{
    const std::string other = "deny|system|/system/win32k/NtUserCallHwndParam/@other";
    const std::string broad = "audit|system|/system/*|image=MapleStory.exe";
    const std::string keysOnly = Head() + other + "\n" + broad + "\n";
    const uint64_t skipped = AttachedCookie(keysOnly, "NtUserCallHwndParam", kHwndParam);
    Expect("inproc skip: a function attached for its keys alone skips its own decision, its own windows and the desktop",
           (skipped & (KB_UP_KEYED | KB_UP_SKIP_FUNCTION | KB_UP_SKIP_SELF | KB_UP_SKIP_DESKTOP)) ==
               (KB_UP_KEYED | KB_UP_SKIP_FUNCTION | KB_UP_SKIP_SELF | KB_UP_SKIP_DESKTOP));
    Expect("inproc skip: ... policy loads", Apply(keysOnly));
    ExpectDecision("inproc skip: its own window: no decision (not /system/*'s either)", Up(kMaple, skipped, 0x50044), 0, 0);
    ExpectDecision("inproc skip: the desktop: none", Up(kMaple, skipped, 0x10046), 0, 0);
    ExpectDecision("inproc skip: another program's window refused", Up(kMaple, skipped, 0x2004C), KFilterActionDeny,
                   RuleOf(keysOnly, other));
    const std::string keys = "audit|system|/system/win32k/NtUserCallHwndParam/*";
    const std::string named = Head() + other + "\n" + keys + "\n";
    const uint64_t reached = AttachedCookie(named, "NtUserCallHwndParam", kHwndParam);
    Expect("inproc skip: a rule reaching @self and @desktop keeps them",
           Apply(named) && (reached & (KB_UP_SKIP_SELF | KB_UP_SKIP_DESKTOP)) == 0 && (reached & KB_UP_SKIP_FUNCTION) != 0);
    ExpectDecision("inproc skip: ... its own window decided", Up(kMaple, reached, 0x50044), KFilterActionAudit, RuleOf(named, keys));
    ExpectPath("inproc skip: ... as @self", Up(kMaple, reached, 0x50044), "/system/win32k/NtUserCallHwndParam/@self");
    const std::string function = "audit|system|/system/win32k/NtUserCallHwndParam|image=MapleStory.exe";
    const std::string both = Head() + other + "\n" + function + "\n";
    const uint64_t decided = AttachedCookie(both, "NtUserCallHwndParam", kHwndParam);
    const std::vector<kb_event> once = Apply(both) ? Events(Up(kMaple, decided, 0x50044)) : std::vector<kb_event>();
    Expect("inproc skip: a rule on the function keeps its own decision, the @self key still skipped (one event)",
           (decided & KB_UP_SKIP_FUNCTION) == 0 && (decided & KB_UP_SKIP_SELF) != 0 && once.size() == 1 &&
               once[0].rule_id == RuleOf(both, function) && std::string(once[0].path) == "/system/win32k/NtUserCallHwndParam");
    Expect("inproc skip: the live shape (a function rule, no key) attaches as before: no skip bit",
           AttachedCookie(Head() + "deny|system|/system/win32k/NtUserGetClassName|exact\n", "NtUserGetClassName", kClassName) ==
               kClassName);
    const uint64_t className = Cookie(kClassName, KB_UP_WINDOW, true);
    const std::string star = "deny|system|/system/win32k/NtUserGetClassName/*";
    const std::string vouch = "allow|system|/system/win32k/NtUserGetClassName/@unknown|rights=query";
    const std::string wild = Head() + vouch + "\n" + star + "\n";
    Expect("inproc skip: an allow naming @unknown loads as nothing", Apply(wild));
    ExpectDecision("inproc skip: a wildcard does not meet @unknown, and the allow naming it is not loaded",
                   Up(kGrap, className, 0x10050), 0, 0);
    ExpectDecision("inproc skip: ... it meets another program's window", Up(kGrap, className, 0x30042), KFilterActionDeny,
                   RuleOf(wild, star));
    const std::string unknown = "deny|system|/system/win32k/NtUserGetClassName/@unknown";
    const std::string literal = Head() + vouch + "\n" + unknown + "\n";
    ExpectDecision("inproc skip: a deny naming @unknown meets it, past the allow naming it", Apply(literal) ?
                   Up(kGrap, className, 0x10050) : Request{}, KFilterActionDeny, RuleOf(literal, unknown));
}

/*
 * win32u.so's keyed calls and ntdll.so's (F7): a key (a virtual key, a window by its owner, a hook id, a clipboard format)
 * decided after the function's own decision, as before keys existed, and met only by rules naming the function's keys
 * (not a rule on the function, not a star right after /system/win32k/); ntdll.so's /system/ntdll/<function>[/<class>],
 * met by rules on the function or its class, never by a star right after /system/ or by /system; NtQueryVirtualMemory on the program's own memory with addr=, not
 * on another's; NtSetContextThread's ContextFlags as value=; only a call returning through the dispatcher, a win32u.so
 * one by its return into ntdll.so where the dispatcher was not found, an ntdll.so one not at all there.
 */
void InprocCase()
{
    WindowsAndThreads();
    UpTables();
    const std::string f1 = "deny|system|/system/win32k/NtUserGetAsyncKeyState/0x00000070|image=MapleStory.exe";
    const std::string f11Upper = "deny|system|/system/win32k/NtUserGetAsyncKeyState/0x0000007A|image=MapleStory.exe";
    const std::string f11 = "audit|system|/system/win32k/NtUserGetAsyncKeyState/0x0000007a|image=MapleStory.exe";
    const std::string className = "deny|system|/system/win32k/NtUserGetClassName|exact|image=grap-core64.aes";
    const std::string other = "deny|system|/system/win32k/NtUserInternalGetWindowText/@other";
    const std::string unknown = "audit|system|/system/win32k/NtUserInternalGetWindowText/@unknown";
    const std::string desktop = "audit|system|/system/win32k/NtUserInternalGetWindowText/@desktop";
    const std::string hook = "deny|system|/system/win32k/NtUserSetWindowsHookEx/13";
    const std::string filter = "audit|system|/system/win32k/NtUserSetWindowsHookEx/-1";
    const std::string text16 = "deny|system|/system/win32k/NtUserGetClipboardData/13";
    const std::string space = "audit|system|/system/win32k/*|image=DwarfAxe.exe";
    const std::string debugPort = "deny|system|/system/ntdll/NtQueryInformationProcess/7";
    const std::string system = "deny|system|/system/ntdll/NtQuerySystemInformation|image=grap-core64.aes";
    const std::string memory = "deny|system|/system/ntdll/NtQueryVirtualMemory|addr=0x140001000-0x140001FFF";
    const std::string context = "deny|system|/system/ntdll/NtSetContextThread|value=0x0010001*";
    const std::string broad = "deny|system|/system/*|image=nexon_client.exe";
    const std::string parent = "deny|system|/system|image=nexon_client.exe";
    const std::string text = Head() + f1 + "\n" + f11Upper + "\n" + f11 + "\n" + className + "\n" + other + "\n" + unknown + "\n" + desktop + "\n" + hook + "\n" +
                             filter + "\n" +
                             text16 + "\n" + space + "\n" + debugPort + "\n" + system + "\n" + memory + "\n" + context + "\n" +
                             broad + "\n" + parent + "\n";
    Expect("in-process policy loads", Apply(text));
    const uint64_t asyncKey = Cookie(kAsyncKey, KB_UP_VKEY, true);
    ExpectDecision("inproc: GetAsyncKeyState(VK_F1) refused to MapleStory.exe", Up(kMaple, asyncKey, 0x70), KFilterActionDeny,
                   RuleOf(text, f1));
    ExpectPath("inproc: ... on its key", Up(kMaple, asyncKey, 0x70), "/system/win32k/NtUserGetAsyncKeyState/0x00000070");
    ExpectDecision("inproc: VK_A allowed", Up(kMaple, asyncKey, 0x41), 0, 0);
    ExpectDecision("inproc: VK_F11 (0x7A) met by its lowercase key alone (the kernel's 0x%08x), not 0x0000007A",
                   Up(kMaple, asyncKey, 0x7A), KFilterActionAudit, RuleOf(text, f11));
    ExpectPath("inproc: ... named 0x0000007a", Up(kMaple, asyncKey, 0x7A), "/system/win32k/NtUserGetAsyncKeyState/0x0000007a");
    ExpectDecision("inproc: VK_F1 not keyed without a rule naming its keys (KB_UP_KEYED)",
                   Up(kMaple, Cookie(kAsyncKey, KB_UP_VKEY, false), 0x70), 0, 0);
    ExpectDecision("inproc: a rule on the function still decides first, whatever the key",
                   Up(kGrap, Cookie(kClassName, KB_UP_WINDOW, true), 0x50044), KFilterActionDeny, RuleOf(text, className));
    ExpectPath("inproc: ... on the function's path", Up(kGrap, Cookie(kClassName, KB_UP_WINDOW, true), 0x50044),
               "/system/win32k/NtUserGetClassName");
    const uint64_t windowText = Cookie(kWindowText, KB_UP_WINDOW, true);
    ExpectDecision("inproc: its own window's title", Up(kGrap, windowText, 0x50044), 0, 0);
    ExpectDecision("inproc: MapleStory.exe's window's title refused (@other)", Up(kGrap, windowText, 0x30042), KFilterActionDeny,
                   RuleOf(text, other));
    ExpectPath("inproc: ... named @other", Up(kGrap, windowText, 0x30042), "/system/win32k/NtUserInternalGetWindowText/@other");
    ExpectDecision("inproc: ... by its low 16 bits too", Up(kGrap, windowText, 0x42), KFilterActionDeny, RuleOf(text, other));
    ExpectDecision("inproc: explorer.exe's window (@other)", Up(kGrap, windowText, 0x2004C), KFilterActionDeny, RuleOf(text, other));
    ExpectDecision("inproc: HWND_BROADCAST is every program's (@other)", Up(kGrap, windowText, 0xFFFF), KFilterActionDeny,
                   RuleOf(text, other));
    ExpectDecision("inproc: a window kfilter cannot place is @unknown", Up(kGrap, windowText, 0x10050), KFilterActionAudit,
                   RuleOf(text, unknown));
    ExpectDecision("inproc: ... a stale generation too", Up(kGrap, windowText, 0x40042), KFilterActionAudit, RuleOf(text, unknown));
    ExpectDecision("inproc: the desktop's window is @desktop", Up(kGrap, windowText, 0x10046), KFilterActionAudit,
                   RuleOf(text, desktop));
    ExpectPath("inproc: ... and no window (the screen) too", Up(kGrap, windowText, 0),
               "/system/win32k/NtUserInternalGetWindowText/@desktop");
    ExpectDecision("inproc: a global WH_KEYBOARD_LL hook (13) refused", Up(kGrap, Cookie(kHook, KB_UP_HOOK, true), 13),
                   KFilterActionDeny, RuleOf(text, hook));
    ExpectPath("inproc: WH_MSGFILTER (-1) signed", Up(kGrap, Cookie(kHook, KB_UP_HOOK, true), 0xFFFFFFFF),
               "/system/win32k/NtUserSetWindowsHookEx/-1");
    ExpectDecision("inproc: CF_UNICODETEXT (13) refused", Up(kGrap, Cookie(kClipboard, KB_UP_FORMAT, true), 13),
                   KFilterActionDeny, RuleOf(text, text16));
    const std::vector<kb_event> spaced = Events(Up(kDwarf, Cookie(kWindowText, KB_UP_WINDOW, true), 0x50044));
    Expect("inproc: /system/win32k/* meets the function alone, not its keys (one event, the function's)",
           spaced.size() == 1 && spaced[0].rule_id == RuleOf(text, space) &&
               std::string(spaced[0].path) == "/system/win32k/NtUserInternalGetWindowText");
    ExpectDecision("inproc: /system/* meets a win32u.so function as before", Up(kNexon, Cookie(kHwndParam, KB_UP_WINDOW, true), 0x44),
                   KFilterActionDeny, RuleOf(text, broad));
    /* The caller: a return outside the dispatcher (Wine's own call), outside ntdll.so, through an install whose
     * dispatcher was not found. */
    ExpectDecision("inproc: VK_F1 from elsewhere in ntdll.so (not through the dispatcher) not decided",
                   Up(kMaple, asyncKey, 0x70, kInNtdll), 0, 0);
    ExpectDecision("inproc: ... from outside ntdll.so neither", Up(kMaple, asyncKey, 0x70, ~0ull), 0, 0);
    ExpectDecision("inproc: where the dispatcher was not found, a win32u.so call returning into ntdll.so is decided",
                   Up(kMaple, Cookie(kAsyncKey, KB_UP_VKEY, true, false, 1), 0x70, kInNtdll), KFilterActionDeny, RuleOf(text, f1));
    /* ntdll.so */
    const uint64_t processInfo = Cookie(kProcessInfo, KB_UP_CLASS2, false, true);
    ExpectDecision("inproc: NtQueryInformationProcess(ProcessDebugPort) refused", Up(kGrap, processInfo, 7), KFilterActionDeny,
                   RuleOf(text, debugPort));
    ExpectPath("inproc: ... on its class", Up(kGrap, processInfo, 7), "/system/ntdll/NtQueryInformationProcess/7");
    ExpectDecision("inproc: ProcessBasicInformation allowed", Up(kGrap, processInfo, 0), 0, 0);
    ExpectDecision("inproc: ... /system/* and /system do not meet it", Up(kNexon, processInfo, 0), 0, 0);
    ExpectDecision("inproc: ProcessDebugPort from Wine's own code (elsewhere in ntdll.so) not decided",
                   Up(kGrap, processInfo, 7, kInNtdll), 0, 0);
    ExpectDecision("inproc: ... nor where the dispatcher was not found",
                   Up(kGrap, Cookie(kProcessInfo, KB_UP_CLASS2, false, true, 1), 7, kInNtdll), 0, 0);
    const uint64_t systemInfo = Cookie(kSystemInfo, KB_UP_CLASS, false, true);
    ExpectDecision("inproc: a rule on the function meets each of its classes", Up(kGrap, systemInfo, 5), KFilterActionDeny,
                   RuleOf(text, system));
    ExpectDecision("inproc: ... its program's only", Up(kMaple, systemInfo, 5), 0, 0);
    const uint64_t virtualMemory = Cookie(kVirtualMemory, KB_UP_MEMORY, false, true);
    ExpectDecision("inproc: VirtualQuery inside the addr= range refused", Up(kGrap, virtualMemory, 0, kDispatched, 0x140001800, ~0ull),
                   KFilterActionDeny, RuleOf(text, memory));
    ExpectReached("inproc: ... its event names the address", Up(kGrap, virtualMemory, 0, kDispatched, 0x140001800, ~0ull),
                  "/system/ntdll/NtQueryVirtualMemory/0 addr=0x0000000140001800+1");
    ExpectDecision("inproc: outside it allowed", Up(kGrap, virtualMemory, 0, kDispatched, 0x140000800, ~0ull), 0, 0);
    ExpectDecision("inproc: another process's memory is its APC's decision (queue_apc), not this",
                   Up(kGrap, virtualMemory, 0, kDispatched, 0x140001800, 0x100), 0, 0);
    static uint8_t contexts[2][0x40] = {};
    const uint32_t debugRegisters = 0x0010001F, full = 0x0010000B;
    memcpy(&contexts[0][0x30], &debugRegisters, 4);
    memcpy(&contexts[1][0x30], &full, 4);
    const uint64_t setContext = Cookie(kSetContext, KB_UP_CONTEXT, false, true, 0, 1);
    ExpectDecision("inproc: SetThreadContext with the debug registers refused (value=ContextFlags)",
                   Up(kGrap, setContext, 0, kDispatched, (uint64_t)(uintptr_t)contexts[0]), KFilterActionDeny, RuleOf(text, context));
    ExpectDecision("inproc: ... without them allowed", Up(kGrap, setContext, 0, kDispatched, (uint64_t)(uintptr_t)contexts[1]), 0, 0);
    static uint8_t context32[0x10] = {};
    memcpy(context32, &debugRegisters, 4);   /* i386: first in the CONTEXT */
    const uint64_t setContext32 = Cookie(kSetContext, KB_UP_CONTEXT, false, true, 0, 1) | KB_UP_I386;
    ExpectDecision("inproc: ... an i386 CONTEXT's", Up(kGrap, setContext32, 0, kDispatched, (uint64_t)(uintptr_t)context32),
                   KFilterActionDeny, RuleOf(text, context));
    Result write = Decide(Up(kGrap, setContext, 0, kDispatched, (uint64_t)(uintptr_t)contexts[0]));
    Expect("inproc: NtSetContextThread asks write", write.logged && write.event.rights == KFILTER_RIGHT_WRITE);
    InprocSkipCase();
}

/* A UTF-16 string with its NUL, kept for the bench's kernel reads. */
const uint8_t* Wide(const std::string& text)
{
    static std::vector<std::vector<uint8_t>> kept;
    std::vector<uint8_t> bytes = Utf16(text);
    bytes.push_back(0);
    bytes.push_back(0);
    kept.push_back(bytes);
    return kept.back().data();
}

/* kb_wmi_decide as kb_wmi calls it (kb_bench_helper 16): Query a WQL query or (Path) an object path, Method ExecMethod's. */
Request Wmi(const std::string& image, const std::string& query, bool path, const std::string& method = "")
{
    const uint64_t text = (uint64_t)(uintptr_t)Wide(query), name = method.empty() ? 0 : (uint64_t)(uintptr_t)Wide(method);
    return Helper(image, {16, (uint32_t)text, (uint32_t)(text >> 32), path, (uint32_t)name, (uint32_t)(name >> 32)});
}

/* ExecMethod calls whose name cannot be built: no object path, a method no method can be named, one too long. */
std::vector<Request> MalformedMethods(const std::string& image)
{
    const uint64_t name = (uint64_t)(uintptr_t)Wide("Create");
    return {Helper(image, {16, 0, 0, 1, (uint32_t)name, (uint32_t)(name >> 32)}), Wmi(image, "Win32_Process", true, "Cre ate"),
            Wmi(image, "Win32_Process", true, std::string(70, 'x'))};
}

/* IWbemServices::ExecMethod (F7): /system/wmi/<class>/<method>, lowercase, execute, met only by rules naming a class's
 * methods; a rule on the class (not exact) still meets its queries alone, as before methods were decided. */
void WmiMethodCase()
{
    const std::string create = "deny|system|/system/wmi/win32_process/create";
    const std::string methods = "audit|system|/system/wmi/win32_service/*";
    const std::string bios = "deny|system|/system/wmi/win32_bios";
    const std::string all = "audit|system|/system/wmi/*|image=DwarfAxe.exe";
    const std::string text = Head() + create + "\n" + methods + "\n" + bios + "\n" + all + "\n";
    Expect("wmi method policy loads", Apply(text));
    ExpectDecision("wmi: Win32_Process.Create refused", Wmi(kGrap, "Win32_Process", true, "Create"), KFilterActionDeny,
                   RuleOf(text, create));
    ExpectPath("wmi: ... on /system/wmi/<class>/<method>", Wmi(kGrap, "Win32_Process", true, "Create"),
               "/system/wmi/win32_process/create");
    Result execute = Decide(Wmi(kGrap, "Win32_Process", true, "Create"));
    Expect("wmi: ... asking execute", execute.logged && execute.event.rights == KFILTER_RIGHT_EXECUTE);
    ExpectDecision("wmi: an instance's method by its class", Wmi(kGrap, "Win32_Service.Name=\"x\"", true, "StopService"),
                   KFilterActionAudit, RuleOf(text, methods));
    ExpectDecision("wmi: another method of Win32_Process allowed", Wmi(kGrap, "Win32_Process", true, "GetOwner"), 0, 0);
    ExpectDecision("wmi: the rule on Win32_BIOS meets its queries", Wmi(kGrap, "SELECT * FROM Win32_BIOS", false),
                   KFilterActionDeny, RuleOf(text, bios));
    ExpectDecision("wmi: ... and GetObject", Wmi(kGrap, "Win32_BIOS", true), KFilterActionDeny, RuleOf(text, bios));
    ExpectDecision("wmi: ... not its methods", Wmi(kGrap, "Win32_BIOS", true, "Reset"), 0, 0);
    ExpectDecision("wmi: /system/wmi/* meets queries", Wmi(kDwarf, "SELECT * FROM Win32_Process", false), KFilterActionAudit,
                   RuleOf(text, all));
    ExpectDecision("wmi: ... not methods", Wmi(kDwarf, "Win32_Process", true, "GetOwner"), 0, 0);
    ExpectDecision("wmi: a method's name no method has is a name failure (refused)", Wmi(kGrap, "Win32_Process", true, "Cre ate"),
                   KFilterActionDeny, 0, KFILTER_EVENT_FLAG_NAME_FAILURE);
    const std::string classes = Head() + bios + "\n" + all + "\n";
    Expect("wmi: class rules alone load", Apply(classes));
    for (const Request& call : MalformedMethods(kGrap))
        ExpectDecision("wmi: with no rule naming a method, no method is decided, a name failure neither", call, 0, 0);
    ExpectDecision("wmi: ... and queries still are", Wmi(kGrap, "SELECT * FROM Win32_BIOS", false), KFilterActionDeny,
                   RuleOf(classes, bios));
}

/*
 * The live loop's policies (KFILTER_BENCH_LIVE) and K5: each /system/win32k/<function> rule decides, through
 * kb_up_decide on a call returning through the dispatcher, exactly what the system decision on its path decided before
 * (the rule, the verdict, the event), for each program they name, and the same where the dispatcher was not found;
 * attached as KfBpfUprobeFunctions names them (no key: the policies name none); with keys forced on (a rule for another
 * program naming them) no live rule meets a key. Their ntdll.so calls and ExecMethod are decided by none of their rules.
 */
void LiveInprocCase()
{
    const char* list = getenv("KFILTER_BENCH_LIVE");
    if (list == nullptr || *list == '\0') return;
    std::string files(list);
    for (size_t start = 0; start < files.size();) {
        const size_t end = std::min(files.find(':', start), files.size());
        const std::string file = files.substr(start, end - start);
        start = end + 1;
        const std::string text = ReadFile(file);
        Config config = Parse(text);
        if (!config || !Load(config.get())) {
            Expect("live inproc: policy loads: " + file, false);
            continue;
        }
        WindowsAndThreads();
        UpTables();
        std::set<std::string> images, functions;
        for (size_t at = 0; at < text.size();) {
            size_t stop = text.find('\n', at);
            if (stop == std::string::npos) stop = text.size();
            const std::string line = text.substr(at, stop - at);
            at = stop + 1;
            if (line.rfind("protect ", 0) == 0) images.insert(line.substr(8));
            const size_t image = line.find("|image=");
            if (image != std::string::npos) images.insert(line.substr(image + 7, line.find('|', image + 7) - image - 7));
            const size_t named = line.find("|/system/win32k/");
            if (named != std::string::npos) functions.insert(line.substr(named + 16, line.find('|', named + 1) - named - 16));
        }
        /* What Win32kApply would attach for this policy, every function of KB_UP_CALLS exported. */
        std::map<std::string, uint64_t> exports;
        for (const std::string& function : functions) exports[function] = 1;
#define KB_UP_EXPORT(library, name, kind, right) exports[#name] = 1;
        KB_UP_CALLS(KB_UP_EXPORT)
#undef KB_UP_EXPORT
        const std::map<std::string, uint64_t> win32k = KfBpfUprobeFunctions(config.get(), false, exports);
        const std::map<std::string, uint64_t> ntdll = KfBpfUprobeFunctions(config.get(), true, exports);
        bool keyless = ntdll.empty();
        for (const auto& [name, cookie] : win32k) keyless = keyless && (cookie & KB_UP_KEYED) == 0;
        std::set<std::string> attached;
        for (const auto& entry : win32k) attached.insert(entry.first);
        Expect("live inproc: the functions its rules name are attached, keyless, no ntdll.so call: " + file,
               attached == functions && keyless);
        int same = 0, differ = 0, quiet = 0, loud = 0;
        __u32 slot = 0;
        for (const auto& [name, bits] : win32k) {
            kb_w32name value{};
            strncpy(value.name, name.c_str(), sizeof(value.name) - 1);
            bpf_map_update_elem(MapOf("kb_w32names"), &slot, &value, BPF_ANY);
            uint32_t kind = 0;
#define KB_UP_KIND_OF(library, function, which, right) if (name == #function) kind = which;
            KB_UP_CALLS(KB_UP_KIND_OF)
#undef KB_UP_KIND_OF
            for (const std::string& program : images) {
                const std::string image = "C:\\x\\" + program;
                for (uint64_t key : {0x70ull, 0x30042ull, 0x50044ull}) {
                    Result before = Decide({KFILTER_TARGET_SYSTEM, KFILTER_RIGHT_QUERY, image, "/system/win32k/" + name, 0, 1});
                    const std::vector<kb_event> was = gBench.events;
                    const uint64_t own = bits | slot;
                    for (const uint64_t cookie : std::initializer_list<uint64_t>{own, own | KB_UP_COOKIE(0, 1, 0) | KB_UP_I386,
                                                                             own | KB_UP_KEYED | KB_UP_COOKIE(kind, 0, 0)}) {
                        Result now = Decide(Up(image, cookie, key, cookie & KB_UP_I386 ? kInNtdll : kDispatched));
                        const std::vector<kb_event> is = gBench.events;
                        bool good = now.ran && now.verdict == before.verdict && is.size() == was.size();
                        for (size_t i = 0; good && i < is.size(); i++) {
                            good = is[i].rule_id == was[i].rule_id && is[i].action == was[i].action &&
                                   std::string(is[i].path) == was[i].path;
                        }
                        if (good) same++;
                        else if (differ++ < 5) std::printf("  live inproc %s: %s by %s: now %s; before %s\n", file.c_str(),
                                                           name.c_str(), program.c_str(), Describe(now).c_str(),
                                                           Describe(before).c_str());
                    }
                }
            }
            slot++;
        }
        /* ntdll.so's calls (each class kind and a few classes), ExecMethod: no live rule meets them. */
        const __u32 ntdllSlot = slot;
        kb_w32name value{};
        strncpy(value.name, "NtQueryInformationProcess", sizeof(value.name) - 1);
        bpf_map_update_elem(MapOf("kb_w32names"), &ntdllSlot, &value, BPF_ANY);
        for (const std::string& program : images) {
            const std::string image = "C:\\x\\" + program;
            for (uint64_t key : {0ull, 5ull, 7ull, 11ull, 17ull, 30ull, 31ull, 35ull}) {
                Result result = Decide(Up(image, Cookie(ntdllSlot, KB_UP_CLASS2, false, true), key));
                if (result.ran && !result.logged && result.verdict == 0) quiet++;
                else if (loud++ < 5) std::printf("  live inproc %s: ntdll class %llu by %s: %s\n", file.c_str(),
                                                 (unsigned long long)key, program.c_str(), Describe(result).c_str());
            }
            for (const char* method : {"Create", "Terminate", "GetOwner"}) {
                Result result = Decide(Wmi(image, "Win32_Process", true, method));
                if (result.ran && !result.logged && result.verdict == 0) quiet++;
                else if (loud++ < 5) std::printf("  live inproc %s: Win32_Process.%s by %s: %s\n", file.c_str(), method,
                                                 program.c_str(), Describe(result).c_str());
            }
            for (const Request& call : MalformedMethods(image)) {
                Result result = Decide(call);
                if (result.ran && !result.logged && result.verdict == 0) quiet++;
                else if (loud++ < 5) std::printf("  live inproc %s: a malformed ExecMethod by %s: %s\n", file.c_str(),
                                                 program.c_str(), Describe(result).c_str());
            }
        }
        std::printf("  live inproc %s: %zu win32k functions, %zu programs: %d calls decided as before, %d not; ntdll.so "
                    "calls and methods: %d undecided, %d decided\n", file.c_str(), functions.size(), images.size(), same,
                    differ, quiet, loud);
        Expect("live inproc: each win32k call decided as before (dispatcher, none found, keys on): " + file,
               differ == 0 && (functions.empty() || same > 0));
        Expect("live inproc: no ntdll.so call or method decided: " + file, loud == 0 && quiet > 0);
        /* NtUserCallHwndParam on the program's own window (each frame) with a rule on other programs' windows added: as
         * kfilterd attaches it (nothing to decide), against deciding the function and @self as K5 first did. */
        Config hwnd = Parse(text + "\ndeny|system|/system/win32k/NtUserCallHwndParam/@other\n");
        if (!hwnd || !Load(hwnd.get())) {
            Expect("live inproc: the policy with an @other rule loads: " + file, false);
            continue;
        }
        UpTables();
        const uint64_t skip = KfBpfUprobeFunctions(hwnd.get(), false, exports)["NtUserCallHwndParam"] | kHwndParam;
        double ns[2] = {};
        bool undecided = true;
        for (int which = 0; which < 2; which++) {
            const Request call = Up(kMaple, which ? Cookie(kHwndParam, KB_UP_WINDOW, true) : skip, 0x50044);
            const auto start = std::chrono::steady_clock::now();
            for (int i = 0; i < 2000; i++) {
                Result result = Decide(call);
                undecided = undecided && result.ran && !result.logged && result.verdict == 0;
            }
            ns[which] = std::chrono::duration<double, std::nano>(std::chrono::steady_clock::now() - start).count() / 2000;
        }
        std::printf("  live inproc %s: NtUserCallHwndParam on its own window with an @other rule: %.0f ns a bench call as "
                    "attached, %.0f ns deciding the function and @self (the difference is the decisions skipped)\n",
                    file.c_str(), ns[0], ns[1]);
        Expect("live inproc: ... its own window decided by nothing, and skipped: " + file,
               undecided && (skip & (KB_UP_SKIP_FUNCTION | KB_UP_SKIP_SELF)) == (KB_UP_SKIP_FUNCTION | KB_UP_SKIP_SELF));
    }
}

/* No link on the system runs one of the bench's programs: the loader compiles policies into the bench's maps and
 * attaches nothing (a policy naming a syscall whose entry point the bench loaded must not attach it). */
void AttachedNothingCase()
{
    std::vector<__u32> ids;
    bpf_program* program = nullptr;
    bpf_object__for_each_program(program, gBench.object) {
        if (bpf_program__fd(program) < 0) continue;
        bpf_prog_info info{};
        __u32 length = sizeof(info);
        if (bpf_prog_get_info_by_fd(bpf_program__fd(program), &info, &length) == 0) ids.push_back(info.id);
    }
    int attached = 0;
    for (__u32 id = 0; bpf_link_get_next_id(id, &id) == 0;) {
        const int fd = bpf_link_get_fd_by_id(id);
        bpf_link_info info{};
        __u32 length = sizeof(info);
        if (fd >= 0 && bpf_link_get_info_by_fd(fd, &info, &length) == 0 &&
            std::find(ids.begin(), ids.end(), info.prog_id) != ids.end()) attached++;
        if (fd >= 0) close(fd);
    }
    Expect("the bench attached none of its programs", !ids.empty() && attached == 0);
}

/* ---- the request-filter lane (K2, K3) and the syscall lane (K4) side by side: each new kind met only by rules naming it ---- */

const uint32_t kOwnTargets = KB_TARGET_KEYED | KB_TARGET_PEER_VALUE | KB_TARGET_THREAD_VALUE | KB_TARGET_SYSTEM_VALUE |
                             KB_TARGET_WINDOW;   /* K3's kernel-only targets: its gates in kb_config.targets */

kb_cfg LayerConfig()
{
    kb_cfg cfg{};
    const __u32 zero = 0;
    bpf_map_lookup_elem(MapOf("kb_config"), &zero, &cfg);
    return cfg;
}

/* kb_wnamed (K2's gate): some request without a row of its own is named. */
bool WineNamedAny()
{
    __u64 any = 0;
    for (__u32 word = 0; word < KB_WNAMED_WORDS; word++) {
        __u64 bits = 0;
        bpf_map_lookup_elem(MapOf("kb_wnamed"), &word, &bits);
        any |= bits;
    }
    return any != 0;
}

/* The rule line of rule Id in Text (RuleOf's inverse; network and message rules are numbered apart); "" for none. */
std::string LineOf(const std::string& text, uint32_t id)
{
    uint32_t rule = 0;
    for (size_t index = 0; index < text.size();) {
        size_t end = text.find('\n', index);
        if (end == std::string::npos) end = text.size();
        const std::string current = text.substr(index, end - index);
        const bool net = current.find("|network|") != std::string::npos || current.find("|message|") != std::string::npos;
        if (!net && (current.rfind("allow|", 0) == 0 || current.rfind("deny|", 0) == 0 || current.rfind("audit|", 0) == 0)) rule++;
        if (id != 0 && rule == id) return current;
        index = end + 1;
    }
    return "";
}

uint32_t RequestOf(const std::string& name)
{
    for (uint32_t req = 0; req < KB_REQ_COUNT; req++) {
        if (name == kRequests[req]) return req;
    }
    return KB_REQ_COUNT;
}

/*
 * K3's value= on peer rules (a window message's number, a request reaching a handle at any offset) and K4's
 * (value=signal:0x%08X, ptrace:0x%08X: a signal, a file's SIGIO owner and a PTRACE_MODE_READ check inside the family),
 * written as policy text and read by kfilterctl's parser: a K3 value= rule never meets a signal, SIGIO or READ decision,
 * even value=* or a message of the signal's number; a K4 one never meets a window, message or handle-offset decision, nor
 * a Wine request on the program (it has no rights=). The calling task is MapleStory.exe; an actor is a family member the
 * bench names. Each lane's gate opens for its own rules alone.
 */
void ValueCrossCase()
{
    WindowsAndThreads();
    const uint32_t grap = 0x3FFFFF06, dwarf = 0x3FFFFF07;
    Process(grap, kGrap, true);
    Process(dwarf, kDwarf, true);
    const std::string message = "deny|peer|C:\\*\\MapleStory.exe|rights=window-message|value=0x00000013|image=grap-core64.aes";
    const std::string anyValue = "deny|peer|C:\\*\\MapleStory.exe|value=*|image=grap-core64.aes";
    const std::string signal = "deny|peer|C:\\*\\MapleStory.exe|rights=terminate|value=signal:0x00000013|image=DwarfAxe.exe";
    const std::string sigio = "audit|peer|C:\\*\\MapleStory.exe|value=signal:0x0000001d|image=DwarfAxe.exe";   /* any case */
    const std::string mode = "deny|peer|C:\\*\\MapleStory.exe|rights=query-information|value=ptrace:0x00000009|image=DwarfAxe.exe";
    const std::string anySignal = "deny|peer|C:\\*\\MapleStory.exe|value=signal:*|image=DwarfAxe.exe";
    const std::string k3 = message + "\n" + anyValue + "\n", k4 = signal + "\n" + sigio + "\n" + mode + "\n" + anySignal + "\n";
    const std::string text = Head() + k3 + k4;
    Expect("value cross: the policy parses and loads, K3's window gate and K4's peer gate on",
           Apply(text) && OwnHandles() && (Gates() & KB_GATE_PEER) != 0 && (LayerConfig().targets & KB_TARGET_WINDOW) != 0);
    const uint32_t into = 2, query = 4 | into, owner = 1 | into;   /* KB_REACH_INTO, with KB_REACH_QUERY or KB_REACH_SIGIO */
    ExpectDecision("value cross: SIGSTOP into MapleStory.exe meets the rule naming it", Helper(kMaple, {3, dwarf, 0x1, 19, into}),
                   KFilterActionDeny, RuleOf(text, signal));
    ExpectPath("value cross: ... its event", Helper(kMaple, {3, dwarf, 0x1, 19, into}), std::string(kMaple) + " signal=0x00000013");
    ExpectDecision("value cross: ... never a message of its number (0x13) or value=*", Helper(kMaple, {3, grap, 0x1, 19, into}), 0, 0);
    ExpectDecision("value cross: a SIGIO owner set to MapleStory.exe meets the rule naming SIGIO (its case aside)",
                   Helper(kMaple, {3, dwarf, 0x1, 29, owner}), KFilterActionAudit, RuleOf(text, sigio));
    ExpectPath("value cross: ... its event", Helper(kMaple, {3, dwarf, 0x1, 29, owner}), std::string(kMaple) + " signal=0x0000001D");
    ExpectDecision("value cross: ... never K3's value=*", Helper(kMaple, {3, grap, 0x1, 29, owner}), 0, 0);
    ExpectDecision("value cross: a READ check of /proc/<pid>/maps meets the rule naming its mode",
                   Helper(kMaple, {3, dwarf, 0x400, 9, query}), KFilterActionDeny, RuleOf(text, mode));
    ExpectPath("value cross: ... its event", Helper(kMaple, {3, dwarf, 0x400, 9, query}), std::string(kMaple) + " ptrace=0x00000009");
    ExpectDecision("value cross: ... never K3's value=*", Helper(kMaple, {3, grap, 0x400, 9, query}), 0, 0);
    ExpectDecision("value cross: SIGKILL meets value=signal:*", Helper(kMaple, {3, dwarf, 0x1, 9, into}), KFilterActionDeny,
                   RuleOf(text, anySignal));
    /* K3's decisions, made by grap-core64.aes and by DwarfAxe.exe (send_message: thread id, message@0x1c; assign_job:
     * the process handle at 0x10). */
    const uint32_t send = RequestOf("send_message"), job = RequestOf("assign_job"), info = RequestOf("get_process_info");
    auto as = [](Request request, const char* image) {
        request.image = image;
        return request;
    };
    ExpectDecision("value cross: message 0x13 to MapleStory.exe's thread meets K3's rule", Full({send, 0, 0, 0x500, 0, 0, 0, 0x13}),
                   KFilterActionDeny, RuleOf(text, message));
    ExpectDecision("value cross: ... never K4's signal rules", as(Full({send, 0, 0, 0x500, 0, 0, 0, 0x13}), kDwarf), 0, 0);
    ExpectDecision("value cross: assign_job on MapleStory.exe meets K3's value=*", Full({job, 0, 0, 0x300, 0x100}),
                   KFilterActionDeny, RuleOf(text, anyValue));
    ExpectDecision("value cross: ... never K4's value=signal:*", as(Full({job, 0, 0, 0x300, 0x100}), kDwarf), 0, 0);
    ExpectDecision("value cross: K4's rights-less value=signal:* does not meet a Wine request on the program",
                   as(Wine({info, 0, 0, 0x100}), kDwarf), 0, 0);
    ExpectDecision("value cross: nor does K3's value=*", Wine({info, 0, 0, 0x100}), 0, 0);
    /* Each lane's rules alone: the other lane's gate stays shut, and its decisions are not made. */
    Expect("value cross: K3's rules alone leave K4's peer gate shut", Apply(Head() + k3) && (Gates() & KB_GATE_PEER) == 0);
    ExpectDecision("value cross: ... and no signal is decided", Helper(kMaple, {3, grap, 0x1, 19, into}), 0, 0);
    Expect("value cross: K4's rules alone leave K3's gates shut", Apply(Head() + k4) && (LayerConfig().targets & kOwnTargets) == 0);
    ExpectDecision("value cross: ... and no message is decided", as(Full({send, 0, 0, 0x500, 0, 0, 0, 0x13}), kDwarf), 0, 0);
    Process(grap, kGrap, false);
    Process(dwarf, kDwarf, false);
}

/*
 * /system/syscall (K4) and /system/wine (K2's named requests, K3's keyed ones): a rule in one space never meets the
 * other's decisions, and a pattern written before both (/system/s*) meets neither, while it still meets what it met.
 */
void SpaceCrossCase()
{
    const std::string getrandom = "deny|system|/system/syscall/getrandom|image=grap-core64.aes";
    const std::string calls = "audit|system|/system/syscall/*|image=grap-core64.aes";
    const std::string message = "deny|system|/system/wine/get_message|image=DwarfAxe.exe";
    const std::string gets = "deny|system|/system/wine/get_*|image=DwarfAxe.exe";
    const std::string keyed = "deny|system|/system/wine/set_hook/*|image=DwarfAxe.exe";
    const std::string sys = "audit|system|/system/s*|image=nexon_client.exe";
    const std::string text = Head() + getrandom + "\n" + calls + "\n" + message + "\n" + gets + "\n" + keyed + "\n" + sys + "\n";
    Expect("space cross: the policy loads, the syscall key filter, kb_wnamed and the keyed target on",
           Apply(text) && WineNamedAny() && (LayerConfig().targets & KB_TARGET_KEYED) != 0);
    auto call = [](const char* image) { return Syscall(image, 318 /* getrandom */, 0, {0x1000, 16, 1}); };
    ExpectDecision("space cross: getrandom meets the rule naming it", call(kGrap), KFilterActionDeny, RuleOf(text, getrandom));
    ExpectDecision("space cross: ... never a /system/wine rule", call(kDwarf), 0, 0);
    ExpectDecision("space cross: ... nor /system/s*", call(kNexon), 0, 0);
    const uint32_t getMessage = RequestOf("get_message"), atom = RequestOf("get_atom_information");
    auto request = [](uint32_t req, const char* image) {
        Request wine = Wine({req});
        wine.image = image;
        return wine;
    };
    ExpectDecision("space cross: get_message meets the rule naming it", request(getMessage, kDwarf), KFilterActionDeny,
                   RuleOf(text, message));
    ExpectDecision("space cross: get_atom_information the pattern naming it", request(atom, kDwarf), KFilterActionDeny, RuleOf(text, gets));
    ExpectDecision("space cross: ... never a /system/syscall rule", request(getMessage, kGrap), 0, 0);
    ExpectDecision("space cross: ... nor /system/s*", request(getMessage, kNexon), 0, 0);
    const uint32_t hook = RequestOf("set_hook");   /* id@0xc, pid@0x10, tid@0x14 */
    Request global = Full({hook, 0, 0, 13, 0, 0});
    global.image = kDwarf;
    ExpectDecision("space cross: a global hook meets the keyed rule", global, KFilterActionDeny, RuleOf(text, keyed));
    global.image = kGrap;
    ExpectDecision("space cross: ... never /system/syscall/*", global, 0, 0);
    ExpectDecision("space cross: /system/s* still meets /system/sysinfo", {KFILTER_TARGET_SYSTEM, KFILTER_RIGHT_QUERY, kNexon, "/system/sysinfo"},
                   KFilterActionAudit, RuleOf(text, sys));
}

/* A K3 keyed rule (and every other K3 kind) opens no K4 gate and attaches no syscall entry point; K4's rules open none of
 * K3's gates and name no Wine request. */
void GateCrossCase()
{
    const std::string k3 = "deny|system|/system/wine/set_hook/*\n"
                           "deny|system|/system/wine/ioctl/*\n"
                           "deny|system|/system/wine/new_process/*\n"
                           "deny|system|/system/rpc/*\n"
                           "deny|system|/system/wine/adjust_token_privileges|value=*\n"
                           "deny|peer|C:\\*|rights=window-query,window-set,window-message,input\n"
                           "deny|peer|C:\\*|value=*\n"
                           "deny|thread-peer|C:\\*|value=*\n";
    Config config = Parse(Head() + k3);
    Expect("gate cross: K3's rules load and open its gates", config && Load(config.get()) &&
                                                             (LayerConfig().targets & kOwnTargets) == kOwnTargets);
    Expect("gate cross: ... and none of K4's (no gate, no data memory, no syscall)",
           Gates() == 0 && (MemoryRules() & KB_MEMORY_DATA) == 0 && config && KfBpfSyscallPrograms(config.get()).empty() &&
               KfBpfSyscallKeys(config.get()).empty());
    const std::string k4 = "deny|system|/system/syscall/getrandom\n"
                           "deny|system|/system/fcntl/*\ndeny|system|/system/task/*\ndeny|system|/system/prctl/*\n"
                           "deny|system|/system/memory/private/rw\ndeny|system|/system/memory/low\n"
                           "deny|file|/kf-cross/*|rights=lock,touch\ndeny|dir|/kf-cross|rights=chdir\n"
                           "deny|pipe|/@kf-cross|rights=listen\ndeny|device|/net/ioctl/0x*\n"
                           "deny|device|/net/netlink/generic/*\ndeny|device|/dev/kf-cross|value=0x00005401:0x00000000\n"
                           "deny|peer|C:\\*|value=signal:*\ndeny|peer|C:\\*|value=ptrace:*\n";
    Expect("gate cross: K4's rules load and open its gates", Apply(Head() + k4) && Gates() != 0 &&
                                                             (MemoryRules() & KB_MEMORY_DATA) != 0);
    Expect("gate cross: ... and none of K3's or K2's", (LayerConfig().targets & kOwnTargets) == 0 && !WineNamedAny());
    /* Rules of a target of the kernel's own alone name no public one: no peer request or ioctl goes to the matcher. */
    Expect("gate cross: signal and ptrace rules alone leave the peer target off",
           Apply(Head() + "deny|peer|C:\\*|value=signal:*\ndeny|peer|C:\\*|value=ptrace:*\n") &&
               (Gates() & KB_GATE_PEER) != 0 && (LayerConfig().targets & KFILTER_TARGET_PEER) == 0 &&
               (LayerConfig().targets & KB_TARGET_SIGNAL) != 0);
    Expect("gate cross: an argument rule alone leaves the device target off",
           Apply(Head() + "deny|device|/dev/kf-cross|value=0x00005401:0x00000000\n") && (Gates() & KB_GATE_ARGUMENT) != 0 &&
               (LayerConfig().targets & KFILTER_TARGET_DEVICE) == 0 && (LayerConfig().targets & KB_TARGET_ARGUMENT) != 0);
}

/*
 * The kinds of decision kfilter made before either lane (d34f633's: every Wine request with a row of its own, made on
 * itself and on MapleStory.exe through its handles; system, file, dir, pipe, registry and device decisions), made by this
 * build, come to the same verdict, rule, target and event path with rules of every new kind of both lanes, for every
 * program, put before the rules that decide them as without them: none meets an existing decision. The K4 switches are on
 * too. Both runs use this build: that they equal d34f633's own is the other cases' and the live policies' check.
 */
void EveryKindCase()
{
    WindowsAndThreads();
    const std::string base = "deny|system|/system/*|image=grap-core64.aes\n"
                             "audit|system|/system|image=DwarfAxe.exe\n"
                             "deny|peer|C:\\*\\MapleStory.exe|image=DwarfAxe.exe\n"
                             "deny|thread-peer|C:\\*\\MapleStory.exe|image=DwarfAxe.exe\n"
                             "deny|file|/kf-every/*\n"
                             "deny|dir|/kf-every-dir\n"
                             "deny|pipe|/@/tmp/.X11-unix/X0|exact\n"
                             "deny|registry|\\Registry\\Machine\\Software\\KfEvery\n"
                             "deny|device|/dev/kf-every|value=0x00005401\n"
                             "deny|device|/net/netlink/route|image=MapleStory.exe\n"
                             "deny|device|/net/ioctl|image=MapleStory.exe\n";
    const std::string every = "block-process-signals\nblock-process-queries\n"
                              /* K2 */
                              "deny|system|/system/wine/get_message\ndeny|system|/system/wine/get_atom_*\n"
                              /* K3 */
                              "deny|peer|C:\\*|rights=window-query,window-set,window-message,input\n"
                              "deny|peer|\\@unknown-window|rights=window-set\ndeny|peer|\\@unknown-thread|rights=window-message\n"
                              "deny|peer|C:\\*|value=assign_job\ndeny|thread-peer|C:\\*|value=get_thread_times\n"
                              "deny|system|/system/wine/set_hook/*\ndeny|system|/system/wine/ioctl/*\n"
                              "deny|system|/system/wine/new_process/*\ndeny|system|/system/rpc/*\n"
                              "deny|system|/system/wine/adjust_token_privileges|value=SeDebugPrivilege\n"
                              /* K4 */
                              "deny|system|/system/syscall/getrandom\ndeny|system|/system/syscall/uname\n"
                              "deny|system|/system/syscall/futex/9\n"
                              "deny|system|/system/fcntl/*\ndeny|system|/system/socket/shutdown/*\n"
                              "deny|system|/system/socketpair/*\ndeny|system|/system/rlimit/*\ndeny|system|/system/task/*\n"
                              "deny|system|/system/cred/*\ndeny|system|/system/capability/*\ndeny|system|/system/namespace/*\n"
                              "deny|system|/system/memory/low\ndeny|system|/system/memory/private/rw\n"
                              "deny|system|/system/ipc/create/*\ndeny|system|/system/fork\ndeny|system|/system/ptrace/*\n"
                              "deny|system|/system/kernel/*\ndeny|system|/system/prctl/*\ndeny|system|/system/statfs*\n"
                              "deny|file|/kf-every/*|rights=lock,touch\ndeny|dir|/kf-every-dir|rights=chdir\n"
                              "deny|pipe|/@*|rights=listen\ndeny|device|/net/netlink/generic/*\n"
                              "deny|device|/net/netlink/route/18\ndeny|device|/net/ioctl/0x*\n"
                              "deny|device|/dev/kf-every|value=0x00005401:0x00000000\n"
                              "deny|peer|C:\\*|value=signal:*\ndeny|peer|C:\\*|value=ptrace:*\n"
                              /* K6 */
                              "deny|message|unix=/*\n";
    const std::string before = Head() + base, after = Head() + every + base;
    std::vector<std::pair<std::string, Request>> requests;
    for (uint32_t req = 0; req < KB_REQ_COUNT; req++) {
        if (RowOf(req) == kNamed) continue;
        std::string path;
        uint32_t right = 0;
        requests.push_back({std::string(kRequests[req]) + " on itself", SelfRequest(req, kGrap, path, right)});
        if (RowOf(req) == kHandle || RowOf(req) == kThread || RowOf(req) == kEither) {
            Request reach = Wine({req, 0, 0, RowOf(req) == kThread ? 0x104u : 0x100u});
            if (req == 16) reach.wine[12] = 0x40;
            reach.image = kDwarf;
            requests.push_back({std::string(kRequests[req]) + " on MapleStory.exe", reach});
        }
    }
    const struct { uint32_t target, rights; const char* image; const char* path; uint32_t value; } plain[] = {
        {KFILTER_TARGET_SYSTEM, KFILTER_RIGHT_QUERY, kGrap, "/system/uname", 0},
        {KFILTER_TARGET_SYSTEM, KFILTER_RIGHT_QUERY, kDwarf, "/system/sysinfo", 0},
        {KFILTER_TARGET_SYSTEM, KFILTER_RIGHT_CREATE, kGrap, "/system/socket/inet/stream/6", 0},
        {KFILTER_TARGET_SYSTEM, KFILTER_RIGHT_WRITE, kGrap, "/system/memory/private/rwx", 0},
        {KFILTER_TARGET_SYSTEM, KFILTER_RIGHT_WRITE, kDwarf, "/system/arch_prctl/0x1002", 0},
        {KFILTER_TARGET_FILE, KFILTER_RIGHT_READ, kMaple, "/kf-every/f", 0},
        {KFILTER_TARGET_FILE, KFILTER_RIGHT_WRITE, kMaple, "/kf-every/f", 0},
        {KFILTER_TARGET_DIR, KFILTER_RIGHT_ENUMERATE, kMaple, "/kf-every-dir", 0},
        {KFILTER_TARGET_PIPE, KFILTER_RIGHT_CONNECT, kMaple, "/@/tmp/.X11-unix/X0", 0},
        {KFILTER_TARGET_REGISTRY, KFILTER_RIGHT_QUERY, kMaple, "\\Registry\\Machine\\Software\\KfEvery", 0},
        {KFILTER_TARGET_DEVICE, KFILTER_RIGHT_RAW_DEVICE, kMaple, "/dev/kf-every", 0x5401},
        {KFILTER_TARGET_DEVICE, KFILTER_RIGHT_RAW_DEVICE, kMaple, "/net/netlink/route", 18},
        {KFILTER_TARGET_DEVICE, KFILTER_RIGHT_RAW_DEVICE, kMaple, "/net/ioctl", 0x8913},
    };
    for (const auto& entry : plain) {
        requests.push_back({std::string(entry.path) + " by " + entry.image,
                            Request{entry.target, entry.rights, entry.image, entry.path, entry.value}});
    }
    struct Outcome {
        bool ran, logged;
        int verdict;
        uint32_t action, target;
        std::string rule, path;
    };
    auto decide = [&](const std::string& text) {
        std::vector<Outcome> outcomes;
        for (const auto& entry : requests) {
            Result result = Decide(entry.second);
            outcomes.push_back({result.ran, result.logged, result.verdict, result.logged ? result.event.action : 0,
                                result.logged ? result.event.target : 0, result.logged ? LineOf(text, result.event.rule_id) : "",
                                result.logged ? result.event.path : ""});
        }
        return outcomes;
    };
    Expect("every kind: the policy before loads", Apply(before) && OwnHandles());
    TargetHandles();
    const std::vector<Outcome> was = decide(before);
    Expect("every kind: the policy with every new kind loads, each lane's gates open",
           Apply(after) && OwnHandles() && (LayerConfig().targets & kOwnTargets) == kOwnTargets &&
               WineNamedAny() && Gates() != 0 && (MemoryRules() & KB_MEMORY_DATA) != 0);
    TargetHandles();
    const std::vector<Outcome> now = decide(after);
    int same = 0, differ = 0, decided = 0;
    for (size_t i = 0; i < requests.size() && i < now.size(); i++) {
        const Outcome& a = was[i];
        const Outcome& b = now[i];
        const bool good = a.ran && b.ran && a.logged == b.logged && a.verdict == b.verdict && a.action == b.action &&
                          a.target == b.target && a.rule == b.rule && a.path == b.path;
        decided += a.logged;
        if (good) same++;
        else if (differ++ < 5)
            std::printf("  every kind: %s: before %d %s '%s' (%s); now %d %s '%s' (%s)\n", requests[i].first.c_str(), a.verdict,
                        a.logged ? "logged" : "none", a.path.c_str(), a.rule.c_str(), b.verdict, b.logged ? "logged" : "none",
                        b.path.c_str(), b.rule.c_str());
    }
    std::printf("  every kind: %zu decisions of existing kinds (%d by a rule) the same with every new kind's rules put first as "
                "without them, %d not\n",
                requests.size(), decided, differ);
    Expect("every kind: each decision of an existing kind as without the new rules", differ == 0 && same == (int)requests.size() && decided > 60);
}

/* ---- sends to AF_UNIX peers (K6, ABI 12: message rules naming unix=) ---- */

/* The id kfilterctl gives Line, a network or message rule of Text (RuleOf's for those, from 10001). */
uint32_t NetRuleOf(const std::string& text, const std::string& line)
{
    uint32_t rule = 10000;
    for (size_t index = 0; index < text.size();) {
        size_t end = text.find('\n', index);
        if (end == std::string::npos) end = text.size();
        const std::string current = text.substr(index, end - index);
        const size_t bar = current.find('|');
        if (bar != std::string::npos && (current.compare(bar, 9, "|network|") == 0 || current.compare(bar, 9, "|message|") == 0))
            rule++;
        if (current == line) return rule;
        index = end + 1;
    }
    return 0;
}

/* Request is let through with no message decision (a sendto's pipe connect decision may log its own event). */
bool NoMessage(const Request& request)
{
    Result result = Decide(request);
    bool none = result.ran && result.verdict == 0;
    for (const kb_event& event : gBench.events) none = none && (event.flags & KFILTER_EVENT_FLAG_MESSAGE) == 0;
    return none;
}

void ExpectNoMessage(const std::string& name, const Request& request)
{
    Expect(name, NoMessage(request));
}

/* The peer a unix send's event names (its path from KB_MSG_NAME). */
void ExpectPeer(const std::string& name, const Request& request, const std::string& peer)
{
    Result result = Decide(request);
    const std::string named = result.logged ? std::string(&result.event.path[KB_MSG_NAME]) : "";
    if (named != peer) std::printf("  %s: peer '%s' (%s)\n", name.c_str(), named.c_str(), Describe(result).c_str());
    Expect(name, named == peer);
}

/*
 * A send to an AF_UNIX peer is a message decision on the peer's name (a connect's pipe text: /@name for an abstract one,
 * the path, a sendto's relative path from the cwd), met only by unix= rules (never by an INET message rule on any
 * address, before or after them) with size=, index=, match= and image=; one no unix= rule names is undecided, unlogged.
 * unix= rules open their gate alone and leave INET messages undecided where no INET message rule is loaded.
 */
void UnixMessageCase()
{
    char cwd[256] = "";
    Expect("unix message: the bench's cwd", getcwd(cwd, sizeof(cwd)) != nullptr);
    const std::string byMatch = "deny|message|unix=/@kf-x11|match=6C00@0", bySize = "deny|message|unix=/tmp/kf-path|size=100-200";
    const std::string byIndex = "deny|message|unix=/@kf-*|index=3", byImage = "deny|message|unix=/@kf-x11|image=DwarfAxe.exe";
    const std::string audited = "audit|message|unix=/@kf-x11", relative = "deny|message|unix=" + std::string(cwd) + "/kf-rel";
    const std::string inet = "deny|message|rights=send", network = "deny|network|ip=0.0.0.0/0";
    const std::string inetOnly = Head() + inet + "\n" + network + "\n";
    const std::string text = Head() + byMatch + "\n" + bySize + "\n" + byIndex + "\n" + byImage + "\n" + audited + "\n" + relative +
                             "\n" + inet + "\n" + network + "\n";
    const std::string x11 = Bytes({0}) + "kf-x11", other = Bytes({0}) + "kf-other";
    const std::string setup = Bytes({0x6C, 0, 11, 0}), request = Bytes({0x42, 0});
    const std::array<uint8_t, 4> server{93, 184, 216, 34};
    Expect("unix message: INET message rules alone open no unix gate", Apply(inetOnly) && (Gates() & KB_GATE_UNIX_MESSAGE) == 0);
    ExpectDecision("unix message: an INET message rule on any address meets no unix send", UnixSend(x11, false, 12, 1, setup), 0, 0);
    Expect("unix message: unix= rules load and open their gate, counted as no INET message rule",
           Apply(text) && (Gates() & KB_GATE_UNIX_MESSAGE) != 0 && LayerConfig().msg_count == 1);
    ExpectDecision("unix message: refused by match= (a connected peer's abstract name)", UnixSend(x11, false, 12, 1, setup),
                   KFilterActionDeny, NetRuleOf(text, byMatch), KFILTER_EVENT_FLAG_MESSAGE);
    ExpectPeer("unix message: the event names the peer /@name", UnixSend(x11, false, 12, 1, setup), "/@kf-x11");
    ExpectDecision("unix message: refused by match= (a sendto's)", UnixSend(x11, true, 12, 1, setup), KFilterActionDeny,
                   NetRuleOf(text, byMatch));
    ExpectDecision("unix message: other bytes to it audited", UnixSend(x11, false, 2, 1, request), KFilterActionAudit,
                   NetRuleOf(text, audited));
    Request dwarf = UnixSend(x11, false, 2, 1, request);
    dwarf.image = kDwarf;
    ExpectDecision("unix message: image=", dwarf, KFilterActionDeny, NetRuleOf(text, byImage));
    ExpectDecision("unix message: size= on a path", UnixSend("/tmp/kf-path", true, 150, 1, request), KFilterActionDeny,
                   NetRuleOf(text, bySize));
    ExpectPeer("unix message: the event names the path", UnixSend("/tmp/kf-path", true, 150, 1, request), "/tmp/kf-path");
    Request unterminated = UnixSend("/tmp/kf-pathXYZ", true, 150, 1, request);
    unterminated.wine[2] = 12;   /* the address's length covers "/tmp/kf-path" and no NUL: the kernel names no more */
    ExpectPeer("unix message: a sendto's path ends at its address's length, not at a NUL past it", unterminated, "/tmp/kf-path");
    /* A sendto's pipe connect decision (no pipe rule: the default allow, logged) and then no message decision. */
    ExpectDecision("unix message: outside size=", UnixSend("/tmp/kf-path", true, 50, 1, request), KFilterActionAllow, 0);
    ExpectNoMessage("unix message: ... no message decision", UnixSend("/tmp/kf-path", true, 50, 1, request));
    ExpectDecision("unix message: the abstract /@/tmp/kf-path is not the path", UnixSend(Bytes({0}) + "/tmp/kf-path", true, 150, 1, request),
                   KFilterActionAllow, 0);
    ExpectNoMessage("unix message: ... no message decision", UnixSend(Bytes({0}) + "/tmp/kf-path", true, 150, 1, request));
    ExpectDecision("unix message: index=", UnixSend(other, false, 2, 3, request), KFilterActionDeny, NetRuleOf(text, byIndex));
    ExpectDecision("unix message: another index", UnixSend(other, false, 2, 2, request), 0, 0);
    ExpectDecision("unix message: a sendto's relative path, from the cwd", UnixSend("kf-rel", true, 2, 1, request),
                   KFilterActionDeny, NetRuleOf(text, relative));
    ExpectDecision("unix message: an INET send meets its INET rule, after every unix= rule", Net(2, 6, 443, server, 12, 1, setup),
                   KFilterActionDeny, NetRuleOf(text, inet));
    Expect("unix message: without block-network unix= rules open no gate (no unix send is named)",
           Apply(Head() + "block-network off\n" + byMatch + "\n") && Gates() == 0);
    Expect("unix message: a policy of unix= rules alone opens their gate alone and counts no INET message rule",
           Apply(Head() + byMatch + "\n") && LayerConfig().msg_count == 0 && Gates() == KB_GATE_UNIX_MESSAGE);
    ExpectDecision("unix message: ... and decides no INET send", Net(2, 6, 443, server, 12, 1, setup), 0, 0);
    /* As the hook: a sendto is its pipe connect decision first; an event shows no unix send's bytes. */
    const std::string pipe = "deny|pipe|/tmp/kf-pipe|rights=connect", watched = "audit|message|unix=/tmp/kf-*";
    const std::string connects = Head() + pipe + "\n" + watched + "\n";
    Expect("unix message: a pipe rule and a unix= rule load", Apply(connects));
    ExpectDecision("unix message: a sendto refused by its pipe connect decision is not a message decision",
                   UnixSend("/tmp/kf-pipe", true, 2, 1, request), KFilterActionDeny, RuleOf(connects, pipe));
    Result shown = Decide(UnixSend("/tmp/kf-other", true, 2, 1, request));
    Expect("unix message: an allowed sendto's message decided, its bytes not shown (data=)",
           shown.logged && shown.event.rule_id == NetRuleOf(connects, watched) && shown.event.shown == 0 &&
               std::string(&shown.event.path[KB_MSG_NAME]) == "/tmp/kf-other");
    Expect("unix message: an INET message audit loads", Apply(Head() + "audit|message|port=443\n"));
    Result inetShown = Decide(Net(2, 6, 443, server, 12, 1, setup));
    Expect("unix message: ... an INET send's bytes still shown", inetShown.logged && inetShown.event.shown == 4);
    /* A module= past KB_MOD_BITS: the loader's "matches nothing" (prefix 129), on a unix= rule too (audit mode loads it). */
    std::string overflow = "mode audit\nprotect MapleStory.exe\nblock-network\n";
    for (int i = 0; i < KB_MOD_BITS; i++) overflow += "audit|message|port=1|module=m" + std::to_string(i) + ".dll\n";
    overflow += "audit|message|unix=/@kf-x11|module=past.dll\n";
    Expect("unix message: a policy past the module= limit loads in audit mode", Apply(overflow));
    ExpectDecision("unix message: ... its unix= rule past the limit meets nothing", UnixSend(x11, false, 12, 1, setup), 0, 0);
}

/*
 * The live loop's policies name no unix peer: their unix gate stays shut and a unix send meets no message rule (a sendto
 * comes to its pipe connect decision alone, as before unix= existed); with unix= rules
 * put before all of theirs (meeting every unix send), each INET connect, send and receive of each program they protect is
 * decided as without them.
 */
void LiveUnixCase()
{
    const char* list = getenv("KFILTER_BENCH_LIVE");
    if (list == nullptr || *list == '\0') return;
    const std::string files(list);
    const std::array<uint8_t, 4> server{93, 184, 216, 34}, resolver{8, 8, 8, 8};
    const std::string unixRules = "deny|message|unix=/*\naudit|message|unix=/@*\n";
    for (size_t start = 0; start < files.size();) {
        const size_t end = std::min(files.find(':', start), files.size());
        const std::string file = files.substr(start, end - start);
        start = end + 1;
        const std::string text = ReadFile(file);
        std::set<std::string> images;
        std::string head, rules;   /* the directives, then the rules (unix= rules go between them) */
        for (size_t at = 0; at < text.size();) {
            size_t stop = text.find('\n', at);
            if (stop == std::string::npos) stop = text.size();
            const std::string line = text.substr(at, stop - at);
            at = stop + 1;
            if (line.rfind("protect ", 0) == 0) images.insert(line.substr(8));
            (line.find('|') == std::string::npos ? head : rules) += line + "\n";
        }
        std::vector<Request> inet, unixSends;
        for (const std::string& program : images) {
            for (Request request : {Net(1, 6, 443, server), Net(2, 6, 443, server, 120, 3, Bytes({0x16, 3, 1})),
                                    Net(3, 6, 443, server, 0, 3), Net(2, 17, 53, resolver, 40, 1, DnsQuery("nexon.com"))}) {
                request.image = "C:\\x\\" + program;
                inet.push_back(request);
            }
            for (Request request : {UnixSend(Bytes({0}) + "/tmp/.X11-unix/X5", false, 12, 1, Bytes({0x6C, 0, 11, 0})),
                                    UnixSend("/tmp/.X11-unix/X5", true, 12, 1, Bytes({0x6C, 0, 11, 0})),
                                    UnixSend("/run/user/1000/bus", true, 16, 2, "AUTH EXTERNAL")}) {
                request.image = "C:\\x\\" + program;
                unixSends.push_back(request);
            }
        }
        std::vector<Result> before;
        int undecided = 0;
        const bool loaded = Apply(text) && (Gates() & KB_GATE_UNIX_MESSAGE) == 0;
        for (const Request& request : inet) before.push_back(Decide(request));
        for (const Request& request : unixSends) {
            /* No message decision; a sendto comes to its pipe connect decision alone (/run/user/1000/bus: their pipe deny). */
            Result result = Decide(request);
            bool message = false;
            for (const kb_event& event : gBench.events) message = message || (event.flags & KFILTER_EVENT_FLAG_MESSAGE) != 0;
            const int connect = request.wine[1] ? Decide({KFILTER_TARGET_PIPE, KFILTER_RIGHT_CONNECT, request.image, request.path}).verdict
                                                : 0;
            undecided += result.ran && !message && result.verdict == connect;
        }
        const bool named = Apply(head + unixRules + rules);
        int same = 0, differ = 0, refused = 0;
        for (size_t i = 0; i < inet.size(); i++) {
            Result now = Decide(inet[i]);
            if (now.ran && before[i].ran && now.verdict == before[i].verdict && now.logged == before[i].logged &&
                (!now.logged || (now.event.rule_id == before[i].event.rule_id && now.event.action == before[i].event.action)))
                same++;
            else if (differ++ < 5)
                std::printf("  live unix %s: INET %u by %s: now %s; before %s\n", file.c_str(), inet[i].wine[0],
                            inet[i].image.c_str(), Describe(now).c_str(), Describe(before[i]).c_str());
        }
        for (const Request& request : unixSends) refused += Decide(request).verdict != 0;
        std::printf("  live unix %s: %zu programs; unix sends undecided %d of %zu; with unix= rules first: INET decisions %d the "
                    "same, %d not; unix sends refused %d\n", file.c_str(), images.size(), undecided, unixSends.size(), same,
                    differ, refused);
        Expect("live unix: the policy loads with its unix gate shut, and a unix send meets no message rule: " + file,
               loaded && !unixSends.empty() && undecided == (int)unixSends.size());
        Expect("live unix: with unix= rules first, every INET decision as before, every unix send refused: " + file,
               named && differ == 0 && same == (int)inet.size() && refused == (int)unixSends.size());
    }
}

uint32_t TargetOf(const std::string& name)
{
    static const struct { const char* name; uint32_t target; } targets[] = {
        {"file", KFILTER_TARGET_FILE}, {"dir", KFILTER_TARGET_DIR}, {"registry", KFILTER_TARGET_REGISTRY},
        {"process", KFILTER_TARGET_PROCESS}, {"volume", KFILTER_TARGET_VOLUME}, {"device", KFILTER_TARGET_DEVICE},
        {"pipe", KFILTER_TARGET_PIPE}, {"peer", KFILTER_TARGET_PEER}, {"thread-peer", KFILTER_TARGET_THREAD_PEER},
        {"system", KFILTER_TARGET_SYSTEM}, {"dns", KFILTER_TARGET_DNS}, {"thread", KFILTER_TARGET_THREAD}};
    for (const auto& entry : targets) {
        if (name == entry.name) return entry.target;
    }
    return 0;
}

} // namespace

int main(int argc, char** argv)
{
    if (geteuid() != 0) {
        std::printf("kfilter-bpf-bench: needs root (it loads BPF programs)\n");
        return 2;
    }
    std::string self(argv[0]);
    std::string object = self.substr(0, self.rfind('/') + 1) + "bpf/kfilter_bench.bpf.o";
    if (!NT_SUCCESS(KfPolicyInitialize()) || !Open(object.c_str())) {
        std::printf("kfilter-bpf-bench: cannot load %s\n", object.c_str());
        return 2;
    }
    std::string netPolicies[2];
    if (argc == 4 && std::string(argv[1]) == "--net-policies") {
        netPolicies[0] = argv[2];
        netPolicies[1] = argv[3];
        argc = 1;
    }
    if (argc >= 6) {
        if (!Apply(ReadFile(argv[1]))) return 1;
        Request request{TargetOf(argv[2]), (uint32_t)strtoul(argv[3], nullptr, 0), argv[4], argv[5]};
        if (argc > 6) request.value = (uint32_t)strtoul(argv[6], nullptr, 0);
        if (argc > 7) request.listed = (uint32_t)strtoul(argv[7], nullptr, 0);
        std::printf("%s\n", Describe(Decide(request)).c_str());
        return 0;
    }
    SysinfoCase();
    SpillCase();
    DeviceCase();
    LiteralCase();
    CapacityCase();
    NetEndCase();
    GraceCase();
    AddressCase();
    AddressOrderCase();
    AddressModuleCase();
    AddressSpillCase();
    AddressRequestCase();
    AddressSplitCase();
    WineIndexCase();
    WineNamedCase();
    WineSplitNameCase();
    SecurityObjectCase();
    ObjectReplyCase();
    WineBroadCase();
    LivePolicyCase();
    UnknownSpillCase();
    EventPathCase();
    LearnCase();
    UnknownReachCase();
    ModuleTableCase();
    AdoptCase();
    ModuleBitCase();
    AddressReloadCase();
    WindowCase();
    WindowOwnerCase();
    HandleOffsetCase();
    KeyedCase();
    RpcCase();
    ValueCase();
    PipeCase();
    LiveReachCase();
    RootCase();
    ValueNamedCase();
    RightsCase();
    SyscallCase();
    HookSpacesCase();
    SignalCase();
    ExtendCase();
    PtraceReadCase();
    MemoryGateCase();
    StashCase();
    ArgumentCase();
    UnixListenCase();
    OwnerCase();
    OwnerFamilyCase();
    ReachSenderCase();
    ValueCrossCase();
    SpaceCrossCase();
    GateCrossCase();
    EveryKindCase();
    InprocCase();
    WmiMethodCase();
    LiveInprocCase();
    UnixMessageCase();
    LiveUnixCase();
    ReloadCase(20);
    NetReloadCase(netPolicies[0], netPolicies[1], 20);
    AttachedNothingCase();   /* last: after every policy the cases loaded (the loop's name /system/wmi and win32k calls) */
    std::printf(gFailures == 0 ? "kfilter BPF bench passed\n" : "kfilter BPF bench: %d failures\n", gFailures);
    return gFailures == 0 ? 0 : 1;
}
