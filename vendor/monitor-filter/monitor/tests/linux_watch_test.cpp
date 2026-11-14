/* Offline checks of the watchpoints' agent side (agent/linux/watch.h): --watch parsing and what it refuses (x86 data
 * breakpoints: 1, 2, 4 or 8 aligned bytes, 4 per thread), where a watch is in a process (msmon's PE image list), its
 * re-resolution when the module moves or goes, and the records of what the kernel counted per (thread, ip, second) or
 * found past the hit cap. The kernel side (bpf/watch.bpf.c, the breakpoints, the cap, the ENOSPC conflict, the fds) is
 * checked by tests/linux_watch_test.sh (root), the cost by tests/linux_budget_test.sh (root). */
#include "../agent/linux/watch.h"
#include <iostream>

static bool Check(bool condition, const char* message)
{
    if (!condition) std::cerr << "FAIL: " << message << "\n";
    return condition;
}

static bool Refused(const std::string& text, const char* why)
{
    std::vector<WatchSpec> specs;
    const std::string error = WatchAdd(specs, text);
    if (!error.empty() && error.find(why) != std::string::npos && specs.empty()) return true;
    std::cerr << "FAIL: --watch " << text << " should be refused with \"" << why << "\", got \"" << error << "\"\n";
    return false;
}

int main()
{
    bool ok = true;

    /* Accepted: a module-relative watch, an absolute one, r watched as rw, w alone, 0X and upper-case digits. */
    std::vector<WatchSpec> specs;
    ok &= Check(WatchAdd(specs, "MapleStory.exe+0x1238:8:rw").empty(), "MapleStory.exe+0x1238:8:rw is accepted");
    ok &= Check(WatchAdd(specs, "0x7ffe0320:4:r").empty(), "an absolute address is accepted");
    ok &= Check(WatchAdd(specs, "ntdll.dll+0X1A:2:w").empty(), "0X and upper-case digits are accepted");
    ok &= Check(WatchAdd(specs, "hidden.dll+0x0:1:w").empty(), "offset 0 of a module is accepted");
    ok &= Check(specs.size() == 4, "four watches");
    ok &= Check(specs[0].module == "MapleStory.exe" && specs[0].offset == 0x1238 && specs[0].length == 8 && !specs[0].write,
                "module, offset, length and rw");
    ok &= Check(specs[1].module.empty() && specs[1].offset == 0x7ffe0320 && specs[1].length == 4 && !specs[1].write,
                "an absolute address; r is watched as rw");
    ok &= Check(specs[2].offset == 0x1a && specs[2].length == 2 && specs[2].write, "w watches writes alone");
    std::vector<WatchSpec> full = specs;
    const std::string fifth = WatchAdd(full, "0x1000:8:w");
    ok &= Check(fifth.find("more than 4 watches") != std::string::npos && full.size() == 4, "a fifth watch is refused");
    std::vector<WatchSpec> twice = {specs[0]};
    ok &= Check(WatchAdd(twice, "MapleStory.exe+0x1238:8:rw").find("given twice") != std::string::npos, "a watch given twice");

    /* Refused, each with its reason. */
    ok &= Refused("MapleStory.exe+0x1234:8:rw", "not a multiple of LENGTH");   /* 0x1234 is 4-aligned, not 8 */
    ok &= Refused("0x7ffe0322:4:w", "not a multiple of LENGTH");
    ok &= Refused("MapleStory.exe+0x1238:16:rw", "LENGTH is not 1, 2, 4 or 8");
    ok &= Refused("MapleStory.exe+0x1238:3:rw", "LENGTH is not 1, 2, 4 or 8");
    ok &= Refused("MapleStory.exe+0x1238:8:x", "ACCESS is not r, w or rw");
    ok &= Refused("MapleStory.exe+0x1238:8:wr", "ACCESS is not r, w or rw");
    ok &= Refused("MapleStory.exe+0x1238:8", "not WHERE:LENGTH:ACCESS");
    ok &= Refused("MapleStory.exe+0x1238:8:rw:x", "not WHERE:LENGTH:ACCESS");
    ok &= Refused("MapleStory.exe+1238:8:rw", "hexadecimal");
    ok &= Refused("MapleStory.exe+0x:8:rw", "hexadecimal");
    ok &= Refused("MapleStory.exe+0x12g8:8:rw", "hexadecimal");
    ok &= Refused("+0x1238:8:rw", "hexadecimal");
    ok &= Refused("MapleStory.exe:8:rw", "hexadecimal");
    ok &= Refused("0x0:8:rw", "not a user-space address");
    ok &= Refused("0xffff888000000000:8:rw", "not a user-space address");
    ok &= Refused("0x800000000000:8:rw", "not a user-space address");
    ok &= Refused("0xfffffffffffffff8:8:rw", "not a user-space address");   /* address + length wraps */
    /* The last page below 0x800000000000 is kernel space to the kernel's breakpoint check (EINVAL on every thread). */
    ok &= Refused("0x7ffffffff008:8:w", "not a user-space address");
    ok &= Refused("0x7ffffffff000:1:w", "not a user-space address");
    ok &= Refused("0x7fffffffffff:1:w", "not a user-space address");
    std::vector<WatchSpec> top;
    ok &= Check(WatchAdd(top, "0x7fffffffeff8:8:w").empty() && WatchAdd(top, "0x7fffffffefff:1:w").empty(),
                "the last bytes below that page are accepted");
    ok &= Refused("MapleStory.exe+0x100000000:8:rw", "past 4 GiB");

    /* Resolution against a process's PE images: the file's name without case, the export name of an image found in
     * anonymous memory, nothing for a module not loaded; an absolute address everywhere. */
    auto image = [](const char* name) {
        auto pe = std::make_shared<PeImage>();
        pe->name = name;
        pe->sizeOfImage = 0x10000;
        return std::shared_ptr<const PeImage>(pe);
    };
    PeRanges before;
    before.ranges.push_back({0x140000000, 0x140800000, image(""), "/home/u/.wine/drive_c/Nexon/MapleStory.exe"});
    before.ranges.push_back({0x180000000, 0x180010000, image("hidden.dll")});
    before.ranges.push_back({0x6fffff000000, 0x6fffff200000, image("ntdll.dll"), "/opt/wine-stable/lib/wine/x86_64-windows/ntdll.dll"});
    std::vector<WatchSpec> one;
    WatchAdd(one, "maplestory.EXE+0x1238:8:rw");
    ok &= Check(WatchResolve(one[0], &before) == 0x140001238, "a module by its file's name, without case");
    ok &= Check(WatchResolve(specs[3], &before) == 0x180000000, "an anonymous image by its export name");
    ok &= Check(WatchResolve(specs[2], &before) == 0x6fffff00001a, "a Wine builtin by its file's name");
    ok &= Check(WatchResolve(one[0], nullptr) == 0, "no image list yet: not watched");
    ok &= Check(WatchResolve(specs[1], nullptr) == 0x7ffe0320 && WatchResolve(specs[1], &before) == 0x7ffe0320,
                "an absolute address is watched in every process");
    PeRanges other;
    other.ranges.push_back({0x140000000, 0x140800000, image(""), "/home/u/.wine/drive_c/Nexon/DwarfAxe.exe"});
    ok &= Check(WatchResolve(specs[0], &other) == 0, "a module the process has not loaded");

    /* Re-resolution: a new process takes every watch it has; the same images change nothing; a module that moved takes
     * its watch along (previous= the address it left); a module unloaded drops it. */
    std::vector<uint64_t> addresses;
    auto changed = WatchResolveAll(specs, &before, addresses);
    ok &= Check(changed.size() == 4 && addresses == std::vector<uint64_t>({0x140001238, 0x7ffe0320, 0x6fffff00001a, 0x180000000}),
                "a new process: every watch resolved");
    ok &= Check(WatchResolveAll(specs, &before, addresses).empty(), "the same images: nothing changes");
    PeRanges moved = before;
    moved.ranges[0].base = 0x150000000;
    moved.ranges[0].end = 0x150800000;
    changed = WatchResolveAll(specs, &moved, addresses);
    ok &= Check(changed.size() == 1 && changed[0].first == 0 && changed[0].second == 0x140001238 && addresses[0] == 0x150001238,
                "the module moved: its watch follows it");
    LinuxRecord record = WatchMoved(specs[0], 77, changed[0].second, addresses[0]);
    ok &= Check(record.type == MsMonProcessHandle && record.sensor == MSMON_SENSOR_LINUX_EBPF_MEMORY && record.pid == 77 &&
                    record.target == 77 && record.value0 == 0x150001238 && record.text == L"watch:MapleStory.exe+0x1238:8:rw",
                "watch_attached: process_handle on the process itself, value0 the address");
    ok &= Check(record.detail == L"watch_attached;address=0x150001238;length=8;access=rw;module_base=0x150000000;"
                                 L"previous=0x140001238",
                "watch_attached after a move names the address it left");
    PeRanges unloaded = moved;
    unloaded.ranges.erase(unloaded.ranges.begin() + 1);
    changed = WatchResolveAll(specs, &unloaded, addresses);
    ok &= Check(changed.size() == 1 && changed[0].first == 3 && addresses[3] == 0, "the module unloaded: its watch is dropped");
    record = WatchMoved(specs[3], 77, changed[0].second, 0);
    ok &= Check(record.value0 == 0x180000000 &&
                    record.detail == L"watch_detached;reason=module_unloaded;address=0x180000000;length=1;access=w;"
                                     L"module_base=0x180000000",
                "watch_detached names the address it left");
    record = WatchMoved(specs[1], 77, 0, 0x7ffe0320);
    ok &= Check(record.detail == L"watch_attached;address=0x7ffe0320;length=4;access=rw", "an absolute watch has no module base");

    /* A native DLL Wine loaded is also a PE in anonymous memory (its sections read there, the image named by its export
     * name): freed and loaded again elsewhere, that copy goes with the file image, so the watch follows the reload. */
    const std::string dllPath = "/home/u/.wine/drive_c/Nexon/game.dll";
    const PeRanges::Range file1{0x180000000, 0x180010000, image("game.dll"), dllPath};
    const PeRanges::Range copy1{0x180000000, 0x180010000, image("game.dll")};
    const PeRanges::Range file2{0x6ffff0000000, 0x6ffff0010000, image("game.dll"), dllPath};
    const PeRanges::Range mapped{0x7f0000000000, 0x7f0000010000, image("mapped.dll")};
    std::vector<WatchSpec> dll;
    WatchAdd(dll, "game.dll+0x3000:8:w");
    const PeRanges kept{{copy1, file2}};
    ok &= Check(WatchResolve(dll[0], &kept) == 0x180003000, "a copy kept after the free would hold the watch on the freed base");
    std::vector<PeRanges::Range> anon = {copy1, mapped};
    PeForgetGone(PeRanges{{file1}}, PeRanges{{file1}}, anon);
    ok &= Check(anon.size() == 2, "a file image still loaded keeps its anonymous copy");
    PeForgetGone(PeRanges{{file1}}, PeRanges{{file2}}, anon);
    ok &= Check(anon.size() == 1 && anon[0].base == mapped.base, "a file image gone takes its anonymous copy along, and nothing else");
    const PeRanges now{{file2, mapped}};
    ok &= Check(WatchResolve(dll[0], &now) == 0x6ffff0003000, "the watch follows the reload");

    /* A breakpoint that could not be opened on a thread: its debug registers taken (ENOSPC), or another errno. */
    record = WatchOpenFailed(specs[0], 77, 78, 0x140001238, ENOSPC);
    ok &= Check(record.tid == 78 && record.status == -ENOSPC &&
                    record.detail == L"watch_conflict;side=watch;address=0x140001238;length=8;access=rw;errno=28",
                "the thread's debug registers are taken: watch_conflict side=watch");
    record = WatchOpenFailed(specs[0], 77, 78, 0x140001238, EACCES);
    ok &= Check(record.status == -EACCES && record.detail.rfind(L"watch_failed;", 0) == 0, "another errno: watch_failed");

    /* The collapse: one record per (thread, ip, watch, second) the kernel counted, ip named in its module when it lies in
     * one; a key is read once its second is over and one more has passed. */
    mm_watch_key key{};
    key.tid = 78;
    key.tgid = 77;
    key.second = 1000;
    key.watch = 0;
    key.ip = 0x140005678;
    key.addr = 0x140001238;
    mm_watch_hit hit{};
    hit.count = 1000;
    hit.first_ns = 1000000000000ull;
    hit.last_ns = 1000002500000ull;
    record = WatchRecord(&specs[0], key, hit, &before);
    ok &= Check(record.type == MsMonProcessHandle && record.pid == 77 && record.tid == 78 && record.target == 77 &&
                    record.value0 == 0x140001238 && record.value1 == 1000 && record.status == 0 &&
                    record.text == L"watch:MapleStory.exe+0x1238:8:rw",
                "watch_hit: value0 the address, value1 the hits");
    ok &= Check(record.detail == L"watch_hit;address=0x140001238;length=8;access=rw;ip=0x140005678;"
                                 L"ip_module=MapleStory.exe+0x5678;count=1000;span_us=2500",
                "watch_hit names ip's module and offset");
    key.ip = 0x7f0000001000;
    record = WatchRecord(&specs[0], key, hit, &before);
    ok &= Check(record.detail.find(L";ip=0x7f0000001000;count=1000;") != std::wstring::npos &&
                    record.detail.find(L"ip_module") == std::wstring::npos,
                "an ip in no PE image (Wine's unix side) has no module");
    record = WatchRecord(&specs[0], key, hit, nullptr);
    ok &= Check(record.detail.find(L"ip_module") == std::wstring::npos, "no image list: no module");

    /* A breakpoint the kernel reported past its cap (watch_over): watch_throttled names the hot instruction. */
    key.ip = 0x140005678;
    record = WatchThrottled(specs[0], key, &before);
    ok &= Check(record.type == MsMonProcessHandle && record.pid == 77 && record.tid == 78 && record.target == 77 &&
                    record.value0 == 0x140001238 && record.value1 == MM_WATCH_CAP && record.status == 0 &&
                    record.text == L"watch:MapleStory.exe+0x1238:8:rw",
                "watch_throttled: value0 the address, value1 the cap");
    ok &= Check(record.detail == L"watch_throttled;address=0x140001238;length=8;access=rw;cap=10000;ip=0x140005678;"
                                 L"ip_module=MapleStory.exe+0x5678",
                "watch_throttled names the cap and the instruction");
    key.watch = MM_WATCH_CONFLICT;
    key.ip = 0x140001238;
    key.addr = 3;
    hit.count = 2;
    hit.actor = 4242;
    record = WatchRecord(nullptr, key, hit, &before);
    ok &= Check(record.type == MsMonProcessHandle && record.text == L"watch_conflict" && record.pid == 77 && record.tid == 78 &&
                    record.status == -ENOSPC && record.value0 == 0x140001238 && record.value1 == 2,
                "a tracer's failed debug-register write: watch_conflict");
    ok &= Check(record.detail == L"watch_conflict;side=program;register=dr3;value=0x140001238;tracer_pid=4242;count=2;span_us=2500",
                "watch_conflict side=program names the register, the value and the tracer");
    ok &= Check(!WatchDue(1000, 1000999999999ull) && !WatchDue(1000, 1001999999999ull) && WatchDue(1000, 1002000000000ull),
                "a key is due 2 s after its second began");

    std::cout << (ok ? "linux watch test: PASS" : "linux watch test: FAIL") << "\n";
    return ok ? 0 : 1;
}
