#!/bin/sh
# Watchpoints under a real kernel (--watch, agent/linux/watch.cpp; needs root: run it in a VM or the agreed test window,
# `sudo tests/linux_watch_test.sh` after ./build.sh tests). tests/fixtures/watch_probe.c writes the addresses of two of its
# variables and waits; the agent watches them in the probe (--pid, 0xCOUNTER:4:w and 0xFLAG:8:rw). Then the probe writes
# COUNTER 1000 times, reads FLAG 500 times and writes it once, starts a thread that writes COUNTER 100 times, a thread
# that writes it 1,000,000 times, and has a tracer write DR0-DR3 of its main thread as wineserver does for a Windows
# program's SetThreadContext. Expected: watch_attached at both addresses; watch_hit records adding up to 1000 (main
# thread, COUNTER), 501 (main thread, FLAG, at two ips at least) and 100 (the thread started after the agent attached);
# the hot thread's COUNTER breakpoint closed at the hit cap (one watch_throttled record, its hits past 10,000 and far
# below 1,000,000); watch_conflict side=watch for both watches on a thread whose 4 debug registers a tracer took before
# the agent started (ENOSPC); the main thread's DR2 write failing ENOSPC (the watches hold 2 of its registers) and its
# watch_conflict side=program record naming DR2, the value and the tracer; the agent's breakpoint fds (a perf event and
# a BPF link each) 2 fewer per watch once the late thread ended and none left for the probe once it exited;
# watch_losses hits_full=0; a log verify_log.py accepts. A session without --watch has none of it, and there the same
# tracer takes all four registers.
# Under Wine (Wine 11.0 at WINE_ROOT, default /opt/wine-stable, clang and ld -m i386pep; Wine runs as $SUDO_USER in a
# temporary prefix, never as root; skipped without them): tests/fixtures/watch_wine_probe.c's variable is watched as
# watch_wine_probe.exe+RVA, resolved from its PE image (watch_attached at module_base= + RVA, module_base the base of
# the exe's image_load); its 1000 writes are watch_hit records naming ip_module=watch_wine_probe.exe+0x...; its
# SetThreadContext with debug registers, which wineserver carries out with ptrace, fails (ERROR_DISK_FULL, 112) at DR3
# (the watch holds one register), recorded as watch_conflict side=program register=dr3 by another process
# (wineserver). Then tests/fixtures/watch_wine_dll.c's variable, watched as watch_wine_dll.dll+RVA, follows the DLL
# loaded, freed and loaded again at another base (its old base taken): watch_attached at the second base (previous= the
# first, or a watch_detached between), 100 hits there, none of the 50 writes at the old address counted, and the main
# thread, whose registers wineserver holds now, side=watch for it.
set -u
cd "$(dirname "$0")/.."
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 2; }
[ -x build/linux/watch_probe ] && [ -x build/linux/msmon-agent ] || { echo "build first (./build.sh tests)"; exit 2; }
work=$(mktemp -d)
probe=
agent=
wine_root=${WINE_ROOT:-/opt/wine-stable}
user=${SUDO_USER:-}
wdir=
# A Wine command as $SUDO_USER in the Wine session's own prefix, with a clean environment (no display, no prompts).
runw() {
    runuser -u "$user" -- env -i HOME="$wdir/home" USER="$user" PATH="$wine_root/bin:/usr/bin:/bin" \
        WINEPREFIX="$wdir/prefix" WINEDEBUG=-all WINEDLLOVERRIDES="mscoree=;mshtml=;winemenubuilder.exe=d" "$@"
}
cleanup() {
    [ -n "$agent" ] && kill "$agent" 2>/dev/null
    [ -n "$probe" ] && kill "$probe" 2>/dev/null
    [ -n "$wdir" ] && runw timeout 30 wineserver -k >/dev/null 2>&1
    if [ -n "${MSMON_KEEP_WORK:-}" ]; then echo "kept $work $wdir"; else rm -rf "$work" ${wdir:+"$wdir"}; fi
}
trap cleanup EXIT
fail=0
# Waits for a file the probe creates (60 s at most).
await() {
    for _ in $(seq 1 600); do [ -e "$1" ] && return 0; sleep 0.1; done
    return 1
}
# A symbol's RVA in a PE file ("0x..."), or nothing.
rva_of() {   # $1 = file, $2 = symbol
    va=$(nm "$1" | awk -v name="$2" '$3 == name {print $1}')
    base=$(objdump -p "$1" | awk '$1 == "ImageBase" {print $2}')
    [ -n "$va" ] && [ -n "$base" ] && printf '0x%x' $((0x$va - 0x$base))
}
# The agent's perf event and BPF link fds (a breakpoint is one of each): "perf=N link=M".
fds() {
    targets=$(ls -l "/proc/$agent/fd" 2>/dev/null | awk '{print $NF}')
    echo "perf=$(printf '%s\n' "$targets" | grep -c 'anon_inode:\[perf_event\]')" \
        "link=$(printf '%s\n' "$targets" | grep -cE 'anon_inode:bpf[_-]link')"
}

session() {   # $1 = name, $2 = watch (with the --watch flags) or off
    dir=$work/$1
    mkdir -p "$dir"
    build/linux/watch_probe "$dir" >"$dir/probe.log" 2>&1 &
    probe=$!
    for _ in $(seq 1 100); do [ -s "$dir/addresses" ] && break; sleep 0.1; done
    [ -s "$dir/addresses" ] || { echo "FAIL $1: the probe wrote no addresses"; cat "$dir/probe.log"; fail=1; return; }
    counter=$(sed -n 's/.*counter=\(0x[0-9a-f]*\).*/\1/p' "$dir/addresses")
    flag=$(sed -n 's/.*flag=\(0x[0-9a-f]*\).*/\1/p' "$dir/addresses")
    watches=
    [ "$2" = watch ] && watches="--watch $counter:4:w --watch $flag:8:rw"
    # shellcheck disable=SC2086
    build/linux/msmon-agent --pid "$probe" --output "$dir/events.jsonl" --max-file-mb 0 --stop-file "$dir/stop" \
        --wait-ms 100 --no-etw $watches >"$dir/agent.log" 2>&1 &
    agent=$!
    for _ in $(seq 1 60); do grep -q Registered "$dir/agent.log" && break; sleep 0.5; done
    grep -q Registered "$dir/agent.log" || { echo "FAIL $1: the agent did not register"; tail -n 40 "$dir/agent.log"; fail=1; }
    sleep 1   # the watch thread opens the breakpoints within its first ticks (100 ms)
    touch "$dir/go"
    # The agent's fds while the late thread holds its breakpoints, once it ended (closed within a tick), once the probe exited.
    await "$dir/late_written" && sleep 0.3 && echo "late_running $(fds)" >>"$dir/fds"
    touch "$dir/late_end"
    await "$dir/late_joined" && sleep 0.5 && echo "late_ended $(fds)" >>"$dir/fds"
    touch "$dir/continue"
    wait "$probe" || { echo "FAIL $1: the probe exited $?"; cat "$dir/probe.log"; fail=1; }
    probe=
    sleep 3   # the last second's counts are read 2 s after it
    echo "probe_exited $(fds)" >>"$dir/fds"
    touch "$dir/stop"
    wait "$agent" || { echo "FAIL $1: the agent exited $?"; tail -n 40 "$dir/agent.log"; fail=1; }
    agent=
    python3 tools/verify_log.py "$dir/events.jsonl" >"$dir/verify.json" || { echo "FAIL $1: verify_log rejected the log"; fail=1; }
    python3 - "$dir" "$2" <<'PY' || { fail=1; echo "--- $1 agent.log (tail)"; tail -n 40 "$dir/agent.log"; }
import json, re, sys
directory, mode = sys.argv[1:3]
events = [json.loads(line) for line in open(directory + "/events.jsonl") if line.strip()]
def fields(name):
    return dict(item.split("=", 1) for item in open(directory + "/" + name).read().split())
found, result = fields("addresses"), fields("result")
pid, main, parked, late = int(found["pid"]), int(found["main"]), int(found["parked"]), int(result["late"])
hot = int(result["hot"])
counter, flag = int(found["counter"], 16), int(found["flag"], 16)
register, errno, tracer = int(result["conflict_register"]), int(result["conflict_errno"]), int(result["tracer"])
watch = [e for e in events if e["type"] == "process_handle" and e.get("text", "").startswith("watch")]
coverage = {e["text"]: e for e in events if e["type"] == "coverage"}
problems = []
# The agent's breakpoint fds above what it holds once the probe exited: 2 watches on the main and late threads, the late
# thread's closed at its end, the main thread's at the exit (the parked thread's could not be opened).
counts = {}
for line in open(directory + "/fds"):
    name, *rest = line.split()
    counts[name] = dict((kind, int(value)) for kind, value in (item.split("=") for item in rest))
want = {"late_running": 4, "late_ended": 2, "probe_exited": 0} if mode == "watch" else \
    {"late_running": 0, "late_ended": 0, "probe_exited": 0}
if set(counts) != set(want):
    problems.append("the agent's fds were not counted at %s: %s" % (sorted(want), counts))
else:
    for kind in ("perf", "link"):
        above = dict((name, counts[name][kind] - counts["probe_exited"][kind]) for name in want)
        if above != want:
            problems.append("the agent's %s fds above those at the probe's exit: %s, want %s" % (kind, above, want))
if mode == "off":
    if watch or "watch_active" in coverage or "watch_losses" in coverage:
        problems.append("watch records without --watch")
    if register != -1:
        problems.append("without watches the tracer's DR%d write failed (errno %d)" % (register, errno))
else:
    def hits(tid, address):
        return [e for e in watch if e["detail"].startswith("watch_hit;") and e["thread_id"] == tid and e["value0"] == address
                and e["process_id"] == pid]
    def total(records):
        return sum(e["value1"] for e in records)
    if ";hit_cap=10000;" not in coverage.get("watch_active", {}).get("detail", ""):
        problems.append("no watch_active coverage record with hit_cap=10000: %s" % coverage.get("watch_active"))
    attached = {e["value0"] for e in watch if e["detail"].startswith("watch_attached;") and e["process_id"] == pid}
    if attached != {counter, flag}:
        problems.append("watch_attached at %s, want %s" % (sorted(map(hex, attached)), [hex(counter), hex(flag)]))
    if total(hits(main, counter)) != 1000:
        problems.append("main thread COUNTER: %d hits, want 1000" % total(hits(main, counter)))
    ips = {re.search(r";ip=(0x[0-9a-f]+);", e["detail"]).group(1) for e in hits(main, flag)}
    if total(hits(main, flag)) != 501 or len(ips) < 2:
        problems.append("main thread FLAG: %d hits at %d ips, want 501 (500 reads, 1 write) at 2 ips" %
                        (total(hits(main, flag)), len(ips)))
    records = {}
    for e in hits(main, counter):
        ip = re.search(r";ip=(0x[0-9a-f]+);", e["detail"]).group(1)
        records[ip] = records.get(ip, 0) + 1
    if not records or max(records.values()) > 2:
        problems.append("the main thread's writes (milliseconds long) in %s records per ip: not one per ip and second" % records)
    if total(hits(late, counter)) != 100:
        problems.append("the thread started later: %d hits, want 100 (followed within 100 ms)" % total(hits(late, counter)))
    # The hot thread's 1,000,000 writes: its COUNTER breakpoint closed at the cap (the kernel reports the 10,000th hit
    # of a second; the agent closes it within milliseconds), its FLAG breakpoint (no hits) kept.
    throttled = [e for e in watch if e["detail"].startswith("watch_throttled;")]
    if [(e["thread_id"], e["value0"]) for e in throttled] != [(hot, counter)] or \
            not all(";cap=10000;ip=0x" in e["detail"] and e["value1"] == 10000 for e in throttled):
        problems.append("watch_throttled: %s, want one for the hot thread's COUNTER" % [e["detail"] for e in throttled])
    if not 10000 < total(hits(hot, counter)) < 100000:
        problems.append("the hot thread: %d hits of its 1,000,000 writes, want the cap's 10,000 and the agent's reaction" %
                        total(hits(hot, counter)))
    blocked = {e["value0"] for e in watch if e["detail"].startswith("watch_conflict;side=watch;") and e["thread_id"] == parked
               and e["status"] == -28}
    if blocked != {counter, flag}:
        problems.append("the parked thread (4 ptrace breakpoints): side=watch conflicts at %s" % sorted(map(hex, blocked)))
    if (register, errno) != (2, 28):
        problems.append("the tracer's writes on the watched main thread: DR%d failed with errno %d, want DR2 ENOSPC" % (register, errno))
    program = [e for e in watch if e["text"] == "watch_conflict" and e["thread_id"] == main and e["status"] == -28]
    if not any(e["detail"].startswith("watch_conflict;side=program;register=dr2;value=0x10010;tracer_pid=%d;" % tracer) for e in program):
        problems.append("no watch_conflict side=program register=dr2 by the tracer: %s" % [e["detail"] for e in program])
    if any(e["detail"].startswith("watch_failed;") for e in watch):
        problems.append("watch_failed records: %s" % [e["detail"] for e in watch if e["detail"].startswith("watch_failed;")])
    if coverage.get("watch_losses", {}).get("detail") != "hits_full=0":
        problems.append("watch_losses: %s" % coverage.get("watch_losses"))
for problem in problems:
    print("FAIL %s: %s" % (mode, problem))
print("%s: %d records, %d watch records" % (mode, len(events), len(watch)))
sys.exit(1 if problems else 0)
PY
}

wine_session() {
    clang=$(command -v clang-18 || command -v clang || true)
    if [ ! -x "$wine_root/bin/wine" ] || [ -z "$user" ] || [ "$user" = root ] || [ -z "$clang" ] ||
        ! ld -V 2>/dev/null | grep -q i386pep; then
        echo "SKIP wine: needs Wine 11.0 at $wine_root (WINE_ROOT), sudo from a normal user, clang and ld -m i386pep"
        return
    fi
    wdir=$(runuser -u "$user" -- mktemp -d /tmp/msmon-watch.XXXXXX) || { echo "FAIL wine: no work directory"; fail=1; return; }
    exe=$wdir/scope/watch_wine_probe.exe
    dll=$wdir/scope/watch_wine_dll.dll
    pe_flags="-target x86_64-w64-windows-gnu -O2 -ffreestanding -fno-stack-protector -fno-builtin"
    # shellcheck disable=SC2086
    runw mkdir -p "$wdir/home" "$wdir/scope" && mkdir -p "$wdir/out" &&
        "$clang" $pe_flags -c tests/fixtures/watch_wine_probe.c -o "$wdir/out/probe.o" &&
        ld -m i386pep --subsystem console -e start -o "$wdir/out/probe.exe" "$wdir/out/probe.o" \
            "$wine_root/lib/wine/x86_64-windows/libkernel32.a" &&
        "$clang" $pe_flags -c tests/fixtures/watch_wine_dll.c -o "$wdir/out/dll.o" &&
        ld -m i386pep --dll -e DllMainCRTStartup -o "$wdir/out/watch_wine_dll.dll" "$wdir/out/dll.o" &&
        runw cp "$wdir/out/probe.exe" "$exe" && runw cp "$wdir/out/watch_wine_dll.dll" "$dll" && runw chmod 755 "$exe" "$dll" ||
        { echo "FAIL wine: cannot build watch_wine_probe.exe and watch_wine_dll.dll"; fail=1; return; }
    rva=$(rva_of "$exe" msmon_watched)
    dll_rva=$(rva_of "$dll" msmon_dll_watched)
    [ -n "$rva" ] && [ -n "$dll_rva" ] || { echo "FAIL wine: no msmon_watched or msmon_dll_watched (or ImageBase)"; fail=1; return; }
    if ! runw timeout 600 wineboot -i >"$wdir/out/wineboot.log" 2>&1 || ! runw timeout 120 wineserver -w; then
        echo "FAIL wine: wineboot -i"; tail -n 20 "$wdir/out/wineboot.log"; fail=1; return
    fi
    build/linux/msmon-agent --scope-root "$wdir/scope" --prefix "$wdir/prefix" --output "$wdir/out/events.jsonl" \
        --stop-file "$wdir/out/stop" --max-file-mb 0 --wait-ms 100 --no-etw --watch "watch_wine_probe.exe+$rva:8:w" \
        --watch "watch_wine_dll.dll+$dll_rva:8:w" >"$wdir/out/agent.log" 2>&1 &
    agent=$!
    for _ in $(seq 1 60); do grep -q Registered "$wdir/out/agent.log" && break; sleep 0.5; done
    grep -q Registered "$wdir/out/agent.log" || { echo "FAIL wine: the agent did not register"; tail -n 40 "$wdir/out/agent.log"; fail=1; }
    runw timeout 120 wine "$exe" >"$wdir/out/probe.txt" 2>&1 ||
        { echo "FAIL wine: watch_wine_probe.exe exited $?"; cat "$wdir/out/probe.txt"; fail=1; }
    runw timeout 30 wineserver -k
    sleep 3
    touch "$wdir/out/stop"
    wait "$agent" || { echo "FAIL wine: the agent exited $?"; tail -n 40 "$wdir/out/agent.log"; fail=1; }
    agent=
    python3 tools/verify_log.py "$wdir/out/events.jsonl" >"$wdir/out/verify.json" ||
        { echo "FAIL wine: verify_log rejected the log"; fail=1; }
    python3 - "$wdir/out" "$rva" "$dll_rva" <<'PY' || { fail=1; echo "--- wine agent.log (tail)"; tail -n 40 "$wdir/out/agent.log"; }
import json, re, sys
out, rva, dll_rva = sys.argv[1], int(sys.argv[2], 16), int(sys.argv[3], 16)
events = [json.loads(line) for line in open(out + "/events.jsonl") if line.strip()]
said = open(out + "/probe.txt", errors="replace").read()
probe = {e["process_id"] for e in events if e["type"] == "image_load" and e.get("text", "").endswith("/scope/watch_wine_probe.exe")}
watch = [e for e in events if e.get("process_id") in probe and e["type"] == "process_handle" and e.get("text", "").startswith("watch")]
mine = [e for e in watch if e["text"] == "watch:watch_wine_probe.exe+%#x:8:w" % rva]
dll = [e for e in watch if e["text"] == "watch:watch_wine_dll.dll+%#x:8:w" % dll_rva]
def number(e, key):
    found = re.search(r"(?:^|;)" + key + r"=(0x[0-9a-f]+|\d+)", e["detail"])
    return int(found.group(1), 0) if found else None
def bases(name):   # where the probe's process loaded a scope file, as its image_load records say
    return {e["value0"] for e in events if e["type"] == "image_load" and e.get("process_id") in probe and
            e.get("text", "").endswith("/scope/" + name)}
problems = []
attached = [e for e in mine if e["detail"].startswith("watch_attached;")]
if not probe:
    problems.append("watch_wine_probe.exe was not tracked")
elif not any(number(e, "module_base") in bases("watch_wine_probe.exe") and e["value0"] == number(e, "module_base") + rva
             for e in attached):
    problems.append("no watch_attached at the base of watch_wine_probe.exe's image_load (%s) + %#x: %s" %
                    (sorted(map(hex, bases("watch_wine_probe.exe"))), rva, [e["detail"] for e in attached]))
hits = [e for e in mine if e["detail"].startswith("watch_hit;")]
if sum(e["value1"] for e in hits) != 1000:
    problems.append("%d hits of msmon_watched, want 1000" % sum(e["value1"] for e in hits))
if not hits or not all(";ip_module=watch_wine_probe.exe+0x" in e["detail"] for e in hits):
    problems.append("hits whose ip is not named in watch_wine_probe.exe: %s" % [e["detail"] for e in hits][:4])
# The DLL loaded, freed, its old base taken and loaded again: the watch follows it there (the move closes the old
# breakpoint, so the 50 writes at the old address are not hits) and the main thread, whose registers wineserver holds
# since its SetThreadContext, cannot take it.
moved = re.search(r"dll=moved old=(0x[0-9a-f]+) new=(0x[0-9a-f]+)", said)
if not moved:
    problems.append("watch_wine_dll.dll was not loaded again elsewhere: %r" % said.strip())
else:
    old, new = int(moved.group(1), 16), int(moved.group(2), 16)
    loads = bases("watch_wine_dll.dll")
    if not {old - dll_rva, new - dll_rva} <= loads:
        problems.append("the DLL's loads at %#x and %#x are not both image_load records: %s" %
                        (old - dll_rva, new - dll_rva, sorted(map(hex, loads))))
    at = dict((e["value0"], e) for e in dll if e["detail"].startswith("watch_attached;") and
              number(e, "module_base") == e["value0"] - dll_rva)
    left = number(at[new], "previous") == old if new in at else False
    left = left or any(e["detail"].startswith("watch_detached;reason=module_unloaded;") and e["value0"] == old for e in dll)
    if old not in at or new not in at or not left:
        problems.append("the DLL's watch did not follow it from %#x to %#x (watch_attached with previous=, or a "
                        "watch_detached between): %s" % (old, new, [e["detail"] for e in dll if not e["detail"].startswith("watch_hit;")]))
    landed = dict((address, sum(e["value1"] for e in dll if e["detail"].startswith("watch_hit;") and e["value0"] == address))
                  for address in (old, new))
    if landed != {old: 0, new: 100}:
        problems.append("the DLL's variable: %d hits at its new address (want 100), %d at its old one (want 0)" %
                        (landed[new], landed[old]))
    main = {e["thread_id"] for e in hits}
    if not any(e["detail"].startswith("watch_conflict;side=watch;") and e["status"] == -28 and e["thread_id"] in main
               for e in dll):
        problems.append("no side=watch conflict for the DLL's watch on the main thread %s" % sorted(main))
if "set_context=failed error=112" not in said:
    problems.append("SetThreadContext with debug registers while a watch holds one: %r (want error 112)" % said.strip())
conflicts = [e for e in watch if e["text"] == "watch_conflict" and e["status"] == -28 and
             e["detail"].startswith("watch_conflict;side=program;register=dr3;value=0x0;")]
if not conflicts or any(not number(e, "tracer_pid") or number(e, "tracer_pid") in probe for e in conflicts):
    problems.append("no watch_conflict side=program register=dr3 by another process: %s" %
                    [e["detail"] for e in watch if e["text"] == "watch_conflict"])
for problem in problems:
    print("FAIL wine: " + problem)
print("wine: %d records, %d watch records of watch_wine_probe.exe" % (len(events), len(watch)))
sys.exit(1 if problems else 0)
PY
}

session watch watch
session off off
wine_session
[ "$fail" = 0 ] && echo "linux watch test: PASS" || echo "linux watch test: FAIL"
exit "$fail"
