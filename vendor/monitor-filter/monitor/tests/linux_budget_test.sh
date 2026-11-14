#!/bin/sh
# msmon's CPU budget (root, for an agreed test window; never against the real client, and tests/run_offline.sh does
# not run it: `sudo tests/linux_budget_test.sh` after ./build.sh tests). msmon was taken out of the live loop at about
# 105% of a core, which slowed the game (relax/live_block.py NO_MSMON, 2026-11-12 17:21: Esc and LEAVE STORE missed).
# build/linux/budget_probe makes CALLS calls each of rt_sigprocmask, a failing futex wait and poll (kernel aggregates:
# the game's hottest calls) untracked, then tracked by a fresh agent (its copy runs in the agent's scope). It fails when
# the agent's CPU over the tracked run (utime + stime of /proc/<pid>/stat) is above AGENT_CPU_PCT percent of one core
# (default 25), when tracking adds more than CALL_NS_MAX ns to a call (default 1000: the BPF programs' cost, charged to
# the caller), or when a call's kernel summaries do not add up to its syscall_counts.
# Native helpers (a browser's busy I/O): a copy of /bin/sh in the scope starts `probe io CALLS` from outside it (a native
# helper), CALLS eventfd writes and reads and CALLS AF_UNIX sends and receives under the same agent. It fails when tracking
# adds more than NATIVE_NS_MAX ns to an eventfd write, an eventfd read or a send and its receive (default 1000:
# native_io's aggregate at each exit), when the agent passes AGENT_CPU_PCT over that run, when the helper has more than
# 8 sampled records a second (its 4 keys' first calls: no record per call), or when its write, read, sendto and
# recvfrom calls in samples and summaries do not add up to its syscall_counts. The same `probe io` run outside the scope
# with the agent on: it fails when the agent adds more than UNTRACKED_NS_MAX ns to another process's call (default 30:
# a task-storage lookup at its exit, no tracked-map lookup). A kept browser (the hand-off's Chrome stays a native
# helper for its whole life): `probe browser BROWSER_SECONDS` (default 10) as a native helper, an assumed steady 300
# opens and 100 memfd_create a second, which stay records; it fails when the agent passes BROWSER_CPU_PCT (default 5)
# over that run or the helper's opens and memfd_create are not recorded.
# --watch (docs/LINUX.md "Watchpoints"): `probe watch` makes ROUNDS futex round trips between two threads on one CPU,
# then STORES stores to one variable, tracked by an agent without --watch and by one watching that variable and three
# others (4 watches, every thread). It fails when the watches add more than PINGPONG_NS_MAX ns to a round trip
# (default 4000: two switches of threads holding 4 breakpoints each, about 1 µs a switch estimated), more than
# STORE_MS_MAX ms to the stores (default 100: the hit cap closes the breakpoint after 10,000 traps of about a
# microsecond), when the stores' breakpoint is not closed (watch_throttled), or when that agent passes AGENT_CPU_PCT.
# Before msmon goes back into the live loop (at the loop's next natural relaunch, without --no-msmon), also by hand:
# 5 minutes of play with it on, Esc and LEAVE STORE answering as they do without it, and msmon-agent under the same
# CPU budget in `top -p <pid>` (the frame-time check against the 17:21 incident).
set -u
cd "$(dirname "$0")/.."
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 2; }
[ -x build/linux/budget_probe ] && [ -x build/linux/msmon-agent ] || { echo "build first (./build.sh tests)"; exit 2; }
calls=${CALLS:-1000000}
stores=${STORES:-10000000}
rounds=${ROUNDS:-100000}
work=$(mktemp -d)
agent=
trap '[ -n "$agent" ] && kill "$agent" 2>/dev/null; if [ -n "${MSMON_KEEP_WORK:-}" ]; then echo "kept $work"; else rm -rf "$work"; fi' EXIT
mkdir -p "$work/scope"
cp build/linux/budget_probe "$work/scope/probe"
mkdir -p "$work/outside"
cp build/linux/budget_probe "$work/outside/probe"
cp /bin/sh "$work/scope/sh"
"$work/scope/probe" "$calls" >"$work/untracked.txt" || { echo "FAIL: the untracked probe exited $?"; exit 1; }
"$work/outside/probe" io "$calls" >"$work/native-untracked.txt" || { echo "FAIL: the untracked io probe exited $?"; exit 1; }
build/linux/msmon-agent --scope-root "$work/scope" --output "$work/events.jsonl" --max-file-mb 0 --stop-file "$work/stop" \
    --wait-ms 100 --no-etw >"$work/agent.log" 2>&1 &
agent=$!
for _ in $(seq 1 60); do grep -q Registered "$work/agent.log" && break; sleep 0.5; done
grep -q Registered "$work/agent.log" || { echo "FAIL: the agent did not register"; tail -n 40 "$work/agent.log"; exit 1; }
ticks() { awk '{ print $14 + $15 }' "/proc/$agent/stat"; }
before=$(ticks)
started=$(date +%s%N)
"$work/scope/probe" "$calls" >"$work/tracked.txt" || { echo "FAIL: the tracked probe exited $?"; exit 1; }
ended=$(date +%s%N)
after=$(ticks)
native_started=$(date +%s%N)
"$work/scope/sh" -c "$work/outside/probe io $calls >$work/native-tracked.txt; true" ||
    { echo "FAIL: the native helper's io probe exited $?"; exit 1; }
native_ticks=$(($(ticks) - after))
native_elapsed=$(($(date +%s%N) - native_started))
"$work/outside/probe" io "$calls" >"$work/native-outside.txt" || { echo "FAIL: the outside io probe exited $?"; exit 1; }
browser_before=$(ticks)
browser_started=$(date +%s%N)
"$work/scope/sh" -c "$work/outside/probe browser ${BROWSER_SECONDS:-10} >$work/browser.txt; true" ||
    { echo "FAIL: the native helper's browser probe exited $?"; exit 1; }
browser_ticks=$(($(ticks) - browser_before))
browser_elapsed=$(($(date +%s%N) - browser_started))
sleep 2
touch "$work/stop"
wait "$agent" || { echo "FAIL: agent exited $?"; tail -n 40 "$work/agent.log"; exit 1; }
agent=
python3 - "$work" "$calls" "$((after - before))" "$(getconf CLK_TCK)" "$((ended - started))" \
    "${AGENT_CPU_PCT:-25}" "${CALL_NS_MAX:-1000}" "$native_ticks" "$native_elapsed" "${NATIVE_NS_MAX:-1000}" \
    "${UNTRACKED_NS_MAX:-30}" "$browser_ticks" "$browser_elapsed" "${BROWSER_CPU_PCT:-5}" <<'PY'
import json, re, sys
work, calls, ticks, hertz, elapsed, cpu_max, ns_max, native_ticks, native_elapsed, native_max, untracked_max, \
    browser_ticks, browser_elapsed, browser_max = sys.argv[1], *map(int, sys.argv[2:])
problems = []
untracked = {k: float(v) for k, v in re.findall(r"(\w+)=([\d.]+)", open(work + "/untracked.txt").read())}
tracked = {k: float(v) for k, v in re.findall(r"(\w+)=([\d.]+)", open(work + "/tracked.txt").read())}
cpu = 100.0 * ticks / hertz / (elapsed / 1e9)
print("budget: agent %.1f%% of a core over %.2f s (budget %d%%)" % (cpu, elapsed / 1e9, cpu_max))
if cpu > cpu_max:
    problems.append("the agent used %.1f%% of a core (budget %d%%)" % (cpu, cpu_max))
events = [json.loads(line) for line in open(work + "/events.jsonl") if line.strip()]
pids = {e["process_id"] for e in events if e["type"] == "process_start" and e.get("text", "").endswith("/scope/probe")}
if not pids:
    problems.append("the tracked probe was not tracked")
for call in ("rt_sigprocmask", "futex", "poll"):
    added = tracked[call] - untracked[call]
    print("budget: %s %.0f ns untracked, %.0f ns tracked (+%.0f ns, budget %d)" % (call, untracked[call], tracked[call], added, ns_max))
    if added > ns_max:
        problems.append("tracking adds %.0f ns to a %s call (budget %d ns)" % (added, call, ns_max))
    counted = sum(int(found.group(1)) for e in events if e.get("process_id") in pids and e["type"] == "coverage" and
                  e["text"] == "syscall_counts" for found in [re.search(r";%s=(\d+)" % call, e["detail"])] if found)
    summed = sum(e["value1"] for e in events if e.get("process_id") in pids and e.get("text") == "system:" + call and
                 "aggregate=kernel" in e.get("detail", ""))
    if counted < calls or summed != counted:
        problems.append("%s: syscall_counts %d, summaries %d (the probe made %d)" % (call, counted, summed, calls))
# The native helper: its added cost per call, the agent's CPU, its sampled records, its calls accounted for.
untracked = {k: float(v) for k, v in re.findall(r"(\w+)=([\d.]+)", open(work + "/native-untracked.txt").read())}
tracked = {k: float(v) for k, v in re.findall(r"(\w+)=([\d.]+)", open(work + "/native-tracked.txt").read())}
for call in ("eventfd_write", "eventfd_read", "unix_send_recv"):
    added = tracked[call] - untracked[call]
    print("budget native: %s %.0f ns untracked, %.0f ns as a native helper (+%.0f ns, budget %d)" %
          (call, untracked[call], tracked[call], added, native_max))
    if added > native_max:
        problems.append("a native helper's %s costs %.0f ns more tracked (budget %d ns)" % (call, added, native_max))
cpu = 100.0 * native_ticks / hertz / (native_elapsed / 1e9)
print("budget native: agent %.1f%% of a core over %.2f s (budget %d%%)" % (cpu, native_elapsed / 1e9, cpu_max))
if cpu > cpu_max:
    problems.append("the agent used %.1f%% of a core over the native helper's I/O (budget %d%%)" % (cpu, cpu_max))
helper = {e["process_id"] for e in events if e["type"] == "process_start" and e.get("text", "").endswith("/outside/probe") and
          "probe io " in e.get("detail", "") and ";attribution=native_helper;native_depth=1" in e.get("detail", "")}
if not helper:
    problems.append("the io probe was not tracked as a native helper")
mine = [e for e in events if e.get("process_id") in helper]
sampled = [e for e in mine if ";native_io=sampled;" in e.get("detail", "")]
if len(sampled) > 8 * (native_elapsed / 1e9 + 2):
    problems.append("%d sampled records over %.1f s (want at most 8 a second)" % (len(sampled), native_elapsed / 1e9))
def number(e, key):
    found = re.search(r"(?:^|;)" + key + r"=(\d+)", e.get("detail", ""))
    return int(found.group(1)) if found else 0
for call in ("write", "read", "sendto", "recvfrom"):
    records = [e for e in mine if re.search(r"(?:^|;)syscall=%s;" % call, e.get("detail", ""))]
    total = sum(number(e, "repeats_before") + (0 if "repeats_tail" in e["detail"] else 1) for e in records)
    counted = sum(number(e, call) for e in mine if e["type"] == "coverage" and e["text"] == "syscall_counts")
    if counted < calls or total != counted:
        problems.append("native %s: %d calls in samples and summaries, %d in syscall_counts (the probe made at least %d)" %
                        (call, total, counted, calls))
# Another process's reads, writes, sends and receives with the agent on: no tracked-map lookup at their exits.
outside = {k: float(v) for k, v in re.findall(r"(\w+)=([\d.]+)", open(work + "/native-outside.txt").read())}
for call in ("eventfd_write", "eventfd_read", "unix_send_recv"):
    added = outside[call] - untracked[call]
    print("budget outside: %s %.0f ns with the agent off, %.0f ns on (+%.0f ns, budget %d)" %
          (call, untracked[call], outside[call], added, untracked_max))
    if added > untracked_max:
        problems.append("the agent adds %.0f ns to another process's %s (budget %d ns)" % (added, call, untracked_max))
# A kept browser's steady opens and memfd_create: records, so the agent's CPU is what bounds them.
cpu = 100.0 * browser_ticks / hertz / (browser_elapsed / 1e9)
browser = {e["process_id"] for e in events if e["type"] == "process_start" and "probe browser " in e.get("detail", "") and
           ";attribution=native_helper;native_depth=1" in e.get("detail", "")}
mine = [e for e in events if e.get("process_id") in browser]
print("budget browser: agent %.1f%% of a core over %.1f s (budget %d%%), %d records (%.0f a second)" %
      (cpu, browser_elapsed / 1e9, browser_max, len(mine), len(mine) / (browser_elapsed / 1e9)))
if cpu > browser_max:
    problems.append("the agent used %.1f%% of a core over a kept browser's opens (budget %d%%)" % (cpu, browser_max))
if not browser or not any(e["type"] == "file_create" and e.get("text") == "memfd:budget" for e in mine) or \
        not any(e["type"] == "file_create" and e.get("text", "").endswith("/stat") for e in mine):
    problems.append("the browser probe's opens and memfd_create were not recorded as a native helper's")
for problem in problems:
    print("FAIL budget: " + problem)
sys.exit(1 if problems else 0)
PY
status=$?

# The --watch rows: `probe watch` under a fresh agent without --watch, then under one with 4 watches.
address() {   # $1 = symbol, $2 = bytes past it
    printf '0x%x' $((0x$(nm build/linux/budget_probe | awk -v name="$1" '$3 == name {print $1}') + $2))
}
watch_run() {   # $1 = name; the rest: the agent's --watch flags
    name=$1
    shift
    rm -f "$work/stop"
    build/linux/msmon-agent --scope-root "$work/scope" --output "$work/$name.jsonl" --max-file-mb 0 --stop-file "$work/stop" \
        --wait-ms 100 --no-etw "$@" >"$work/$name.log" 2>&1 &
    agent=$!
    for _ in $(seq 1 60); do grep -q Registered "$work/$name.log" && break; sleep 0.5; done
    grep -q Registered "$work/$name.log" || { echo "FAIL: the $name agent did not register"; tail -n 40 "$work/$name.log"; return 1; }
    before=$(ticks)
    started=$(date +%s%N)
    "$work/scope/probe" watch "$stores" "$rounds" >"$work/$name.txt" || { echo "FAIL: the $name probe exited $?"; return 1; }
    echo "ticks=$(($(ticks) - before)) elapsed=$(($(date +%s%N) - started))" >>"$work/$name.txt"
    sleep 3   # the last second's counts are read 2 s after it
    touch "$work/stop"
    wait "$agent" || { echo "FAIL: the $name agent exited $?"; tail -n 40 "$work/$name.log"; return 1; }
    agent=
}
watch_run watch-off && watch_run watch-on --watch "$(address watched 0):4:w" --watch "$(address idle 0):8:w" \
    --watch "$(address idle 8):8:w" --watch "$(address idle 16):8:w" &&
    python3 - "$work" "$(getconf CLK_TCK)" "$(address watched 0)" "${AGENT_CPU_PCT:-25}" "${PINGPONG_NS_MAX:-4000}" \
        "${STORE_MS_MAX:-100}" <<'PY' || status=1
import json, re, sys
work, hertz, watched = sys.argv[1], int(sys.argv[2]), int(sys.argv[3], 16)
cpu_max, pingpong_max, store_max = map(int, sys.argv[4:7])
def numbers(name):
    return {k: float(v) for k, v in re.findall(r"(\w+)=([\d.]+)", open(work + "/" + name + ".txt").read())}
off, on = numbers("watch-off"), numbers("watch-on")
problems = []
cpu = 100.0 * on["ticks"] / hertz / (on["elapsed"] / 1e9)
print("budget --watch: agent %.1f%% of a core over %.2f s (budget %d%%)" % (cpu, on["elapsed"] / 1e9, cpu_max))
if cpu > cpu_max:
    problems.append("the agent used %.1f%% of a core with 4 watches (budget %d%%)" % (cpu, cpu_max))
added = on["pingpong"] - off["pingpong"]
print("budget --watch: a futex round trip of two threads on one CPU %.0f ns without watches, %.0f ns with 4 (+%.0f ns, "
      "budget %d)" % (off["pingpong"], on["pingpong"], added, pingpong_max))
if added > pingpong_max:
    problems.append("4 watches add %.0f ns to a round trip of two switches (budget %d ns)" % (added, pingpong_max))
added = on["store_ms"] - off["store_ms"]
print("budget --watch: %d stores to a watched address %.1f ms without watches, %.1f ms with (+%.1f ms, budget %d)" %
      (on["stores"], off["store_ms"], on["store_ms"], added, store_max))
if added > store_max:
    problems.append("the watch adds %.1f ms to the stores (budget %d ms: the hit cap)" % (added, store_max))
events = [json.loads(line) for line in open(work + "/watch-on.jsonl") if line.strip()]
watch = [e for e in events if e["type"] == "process_handle" and e.get("text", "").startswith("watch:")]
if not any(e["detail"].startswith("watch_throttled;") and e["value0"] == watched for e in watch):
    problems.append("the stores' breakpoint was not closed at the hit cap (no watch_throttled at %#x)" % watched)
others = [e["detail"] for e in watch if e["detail"].startswith("watch_hit;") and e["value0"] != watched]
if others:
    problems.append("hits at addresses no thread touches: %s" % others[:4])
for problem in problems:
    print("FAIL budget --watch: " + problem)
sys.exit(1 if problems else 0)
PY
[ "$status" = 0 ] && echo "linux budget test: PASS" || echo "linux budget test: FAIL"
exit "$status"
