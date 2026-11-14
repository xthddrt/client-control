#!/bin/sh
# Runtime check of the eBPF sensors (needs root; run in a VM: `sudo tests/linux_ebpf_test.sh`
# after ./build.sh tests). The agent watches a temporary scope; a probe started there does one of
# each action and must be recorded with byte counts, a failing status, kernel paths and
# resolved stacks. Then the same probe under --no-ebpf must still be recorded by the
# fanotify/proc-connector sensors.
set -u
cd "$(dirname "$0")/.."
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 2; }
[ -x build/linux/linux_ebpf_probe ] || { echo "build first (./build.sh tests)"; exit 2; }
work=$(mktemp -d)
trap 'if [ -n "${MSMON_KEEP_WORK:-}" ]; then echo "kept $work"; else rm -rf "$work"; fi' EXIT
fail=0
# Each kernel-sensor upgrade keeps its part of this test in tests/ebpf_checks/<upgrade>.sh (functions
# <upgrade>_session, run in every session after the probe while the agent still runs, and <upgrade>_end,
# run after all sessions; they may set fail=1) and check_<upgrade>.py (check(), run by check()).
upgrades="payload netattr packets wineserver parity sysall gaps unixproto scope"
for upgrade in $upgrades; do . "tests/ebpf_checks/$upgrade.sh"; done

run_session() {   # $1 = name, rest = agent flags
    name=$1
    shift
    scope="$work/$name/scope"
    extra="$work/$name/extra"   # a second scope root (parity.sh runs the ia32 probe there)
    mkdir -p "$scope/files" "$extra"
    cp build/linux/linux_ebpf_probe "$scope/probe"
    # --max-file-mb 0: one events.jsonl (check() reads only it); the Wine run alone writes ~70 MB.
    build/linux/msmon-agent --scope-root "$scope" --extra-root "$extra" --output "$work/$name/events.jsonl" \
        --max-file-mb 0 --stop-file "$work/$name/stop" --wait-ms 100 --no-etw "$@" >"$work/$name/agent.log" 2>&1 &
    agent=$!
    # Loading and verifying the BPF programs takes a few seconds; the agent prints
    # "Registered" once its sensors are live.
    for _ in $(seq 1 60); do grep -q Registered "$work/$name/agent.log" && break; sleep 0.5; done
    MSMON_AGENT_PID=$agent "$scope/probe" "$scope/files" || { echo "FAIL $name: probe exited $?"; fail=1; }
    for upgrade in $upgrades; do "${upgrade}_session"; done
    sleep 2
    touch "$work/$name/stop"
    wait "$agent" || { echo "FAIL $name: agent exited $?"; cat "$work/$name/agent.log"; fail=1; }
    python3 tools/verify_log.py "$work/$name/events.jsonl" >"$work/$name/verify.json" ||
        { echo "FAIL $name: verify_log rejected the log"; fail=1; }
}

check() {   # $1 = name, $2 = mode (ebpf | nopayloads | fallback)
    # On failure show the end of the agent's stderr (libbpf and the verifier log land there).
    python3 - "$work/$1/events.jsonl" "$2" "$work/$1/scope/probe" <<'PY' || { fail=1; echo "--- $1 agent.log (tail)"; tail -n 80 "$work/$1/agent.log"; }
import json, sys
path, mode, probe = sys.argv[1:4]
events = [json.loads(line) for line in open(path) if line.strip()]
coverage = {e["text"] for e in events if e.get("type") == "coverage"}
pids = {e["process_id"] for e in events if e["type"] == "process_start" and probe in (e.get("text", "") + e.get("process_path", ""))}
# The probe's forked child is tracked as inherited.
pids |= {e["process_id"] for e in events if e["type"] == "process_start" and e.get("parent_process_id") in pids}
mine = [e for e in events if e.get("process_id") in pids]
def has(kind, test=lambda e: True):
    return any(e["type"] == kind and test(e) for e in mine)
problems = []
if not pids:
    problems.append("the probe was not tracked")
expect = {
    "file_create": lambda e: e["text"].endswith("/probe-a.txt"),
    "file_write": lambda e: e["value0"] > 0 or mode == "fallback",
    "file_read": lambda e: e["value0"] > 0 or mode == "fallback",
    "file_set_information": lambda e: "unlink" in e["detail"],
}
if mode in ("ebpf", "nopayloads"):
    expect.update({
        "file_close": lambda e: e["text"].endswith("/probe-a.txt"),
        "file_set_security": lambda e: e["text"].endswith("/probe-b.txt"),
        "file_section": lambda e: e["text"].endswith("/probe-b.txt") and e["value1"] & 4,
        "image_load": lambda e: e["text"].endswith("/probe-b.txt"),
        "network_connect": lambda e: e["text"].startswith("127.0.0.1:"),
        "network_accept": lambda e: e["text"].startswith("127.0.0.1:"),
        "network_flow_close": lambda e: True,
        "thread_start": lambda e: True,
        "thread_exit": lambda e: True,
        "process_exit": lambda e: True,
        "process_handle": lambda e: "process_vm_readv" in e["detail"],
    })
    if "ebpf_active" not in coverage:
        problems.append("no ebpf_active coverage record")
    if not any(e["type"] == "file_set_information" and "rename;to" in e["detail"] and e["text"].endswith("/probe-b.txt") for e in mine):
        problems.append("no rename;to record for probe-b.txt")
    if not any(e["type"] == "file_create" and e["status"] != 0 and e["text"].endswith("probe-missing.txt") for e in mine):
        problems.append("the failed open has no nonzero status")
    tails = [e for e in mine if e["type"] == "file_create" and "repeats_tail" in e["detail"] and e["text"].endswith("probe-missing.txt")]
    if not tails or any(e["status"] == 0 for e in tails):
        problems.append("the repeats_tail of failed opens has no errno: %s" % [e["status"] for e in tails])
    if not any(e.get("stack_frames", 0) > 0 and e["modules"] for e in mine):
        problems.append("no stack resolved to a module")
    if not any(e["type"] == "process_start" and e["value1"] == 0 and e.get("flags", 0) & 2 for e in mine):
        problems.append("the forked child was not tracked as inherited")
    # 100 preads of probe-burst.txt: a few full records, the rest counted, nothing lost.
    import re
    def count(e, key):
        found = re.search(key + r"=(\d+)", e["detail"])
        return int(found.group(1)) if found else 0
    burst = [e for e in mine if e["type"] == "file_read" and e["text"].endswith("/probe-burst.txt") and "pread64" in e["detail"]]
    total = sum(1 + count(e, "repeats_before") for e in burst if "repeats_tail" not in e["detail"])
    total += sum(count(e, "repeats_before") for e in burst if "repeats_tail" in e["detail"])
    if total != 100 or len(burst) > 20:
        problems.append("burst: %d pread records accounting for %d calls (want 100 calls in <= 20 records)" % (len(burst), total))
    opens = [e for e in mine if e["type"] == "file_create" and e["text"].endswith("/probe-burst.txt") and e["value0"] == 0]
    if not any(e["status"] == 0 for e in opens) or not any(e["status"] != 0 for e in opens):
        problems.append("the failing repeat of a successful open was not recorded")
    for word in ("bind;", "listen;"):
        if not any(e["type"] == "network_accept" and e["detail"].startswith(word) for e in mine):
            problems.append("no " + word + " record")
    if not any(e["type"] == "network_connect" and "sendmsg;" in e["detail"] and e["text"].startswith("127.0.0.1:") for e in mine):
        problems.append("no sendmsg record with its UDP peer")
    if not any(e["type"] == "network_accept" and "recvmsg;" in e["detail"] and e["text"].startswith("127.0.0.1:") for e in mine):
        problems.append("no recvmsg record with its UDP source")
    if not any(e["type"] == "process_handle" and e["detail"].startswith("prctl;") for e in mine):
        problems.append("no prctl record")
    if not any(e["type"] == "process_handle" and e["detail"].startswith("pidfd_open;") for e in mine):
        problems.append("no pidfd_open record")
    news = {
        "uname": lambda e: e["type"] == "file_query_information" and e["text"] == "system:uname" and e["category"] == "hardware_identity",
        "sysinfo": lambda e: e["type"] == "file_query_information" and e["text"] == "system:sysinfo",
        "socket": lambda e: e["type"] == "file_create" and e["detail"].startswith("socket;family=2;type=1;") and e["text"].startswith("socket:["),
        "shutdown": lambda e: e["type"] == "network_flow_close" and e["detail"].startswith("shutdown;how=1;"),
        "inotify_add_watch": lambda e: e["type"] == "file_directory_control" and e["detail"].startswith("inotify_add_watch;") and e["text"].endswith("/files"),
        "memfd_create": lambda e: e["type"] == "file_create" and "syscall=memfd_create" in e["detail"] and "probe-memfd" in e["text"],
        "fsync": lambda e: e["type"] == "file_flush" and e["text"].endswith("/probe-sync.txt"),
        "shmget": lambda e: e["type"] == "file_section" and e["text"].startswith("sysv_shm:key="),
        "shmat": lambda e: e["type"] == "file_section" and e["text"].startswith("sysv_shm:id="),
        # Syscall completeness: new calls, refused clones, the catch-all counts and full command lines.
        "userfaultfd": lambda e: e["type"] == "file_create" and e["text"].startswith("userfaultfd:["),
        "bpf": lambda e: e["type"] == "file_query_information" and e["text"] == "system:bpf",
        "arch_prctl": lambda e: e["type"] == "process_handle" and e["detail"].startswith("arch_prctl;option=4113;"),
        "clone_failed": lambda e: e["type"] == "process_start" and e["detail"].startswith("clone_failed;syscall=clone3;") and e["status"] != 0,
        "getxattrat": lambda e: e["type"] == "file_query_ea" and "syscall=getxattrat;" in e["detail"] and e["text"].endswith("/files"),
        "lsm_list_modules": lambda e: e["text"] == "system:lsm_list_modules",
        "msgget": lambda e: e["type"] == "file_section" and e["text"].startswith("sysv_msg:key="),
        # getcpu is a kernel aggregate now: its calls are recorded=1, with summaries (system:getcpu) adding up to 3.
        "syscall_counts getcpu=3": lambda e: e["type"] == "coverage" and e["text"] == "syscall_counts" and
            e["detail"].startswith("recorded=1;") and ";getcpu=3;" in e["detail"] + ";",
        "getcpu summary": lambda e: e["text"] == "system:getcpu" and e["detail"].startswith("repeats_tail;syscall=getcpu;aggregate=kernel;"),
        "full argv and env": lambda e: e["type"] == "process_start" and "a" * 580 + "msmon-tail" in e["detail"] and
            ";env:WINEDEBUG=-all" in e["detail"],
        "two-thread pread tail": lambda e: "pread64" in e["detail"] and re.search(r"repeat_tids=\d+,\d+;", e["detail"]),
        # Kernel events (kev.bpf.h): ring I/O, signals, trapped instructions, capabilities, module requests, credentials.
        "io_uring openat": lambda e: e["type"] == "file_create" and e["detail"].startswith("via=io_uring;op=openat;") and
            e["text"].endswith("/probe-uring.txt") and e["status"] == 0,
        "io_uring write of 6 bytes": lambda e: e["type"] == "file_write" and e["detail"].startswith("via=io_uring;op=write;res=6;") and
            e["text"].endswith("/probe-uring.txt") and e["value0"] == 6,
        "aio pwrite": lambda e: e["type"] == "file_write" and e["detail"].startswith("via=aio;") and e["text"].endswith("/probe-aio.txt"),
        "io_uring_setup": lambda e: e["type"] == "file_create" and e["text"].startswith("io_uring_setup:["),
        "signal_received SIGUSR2 from the child": lambda e: e["type"] == "process_handle" and
            e["detail"].startswith("signal_received;signal=12;") and e.get("target_process_id") in pids,
        "rdtsc fault": lambda e: e["text"] == "system:rdtsc" and ";source=sigsegv" in e["detail"],
        # The probe traps RDTSC twice at one ip, as kfshim does per read under --trap-rdtsc: both collapse.
        "rdtsc repeats_tail": lambda e: e["text"] == "system:rdtsc" and e["detail"].startswith("repeats_tail;syscall=insn;"),
        "prctl(PR_SET_TSC) repeats_tail": lambda e: e["type"] == "process_handle" and e["detail"].startswith("repeats_tail;syscall=prctl;"),
        "keyctl": lambda e: e["text"] == "system:keyctl",
        "module_request net-pf-12": lambda e: e["type"] == "process_handle" and e["text"] == "net-pf-12" and
            e["detail"].startswith("module_request;"),
        "capability check": lambda e: e["type"] == "process_handle" and e["detail"].startswith("capability;cap="),
        "cred_change to nobody": lambda e: e["type"] == "process_handle" and e["detail"].startswith("cred_change;uid=0->65534;"),
        "anon_pe image": lambda e: e["type"] == "image_load" and e["text"].startswith("anon_pe:msmonprobe.dll@") and
            "source=anonymous_pe;timestamp=0x5eadbeef;" in e["detail"],
    }
    flags = open("/proc/cpuinfo").read().split()
    if "cpuid_fault" in flags:
        news["cpuid fault"] = lambda e: e["text"] == "system:cpuid" and ";leaf=0x0;" in e["detail"] and ";source=sigsegv" in e["detail"]
    if "umip" in flags:
        news["umip sgdt"] = lambda e: e["text"] == "system:sgdt" and ";source=umip_emulated" in e["detail"]
    if mode == "ebpf":   # --page-faults
        for kind in ("file_read", "file_write"):
            news["page_fault " + kind] = lambda e, kind=kind: e["type"] == kind and e["detail"].startswith("via=page_fault;") and \
                e["text"].endswith("/probe-shared.txt")
    for name, test in news.items():
        if not any(test(e) for e in mine):
            problems.append("no " + name + " record")
    remotes = {re.search(r"remote=(\w+)", e["detail"]).group(1) for e in mine if e["detail"].startswith("process_vm_readv;remote=")}
    if len(remotes) < 51:
        problems.append("process_vm_readv: %d distinct remote addresses recorded (want 51: none collapsed)" % len(remotes))
    if mode == "nopayloads":   # --native-depth 0: a native program leaves tracking at its exec
        native = {e["process_id"] for e in mine if e["type"] == "process_exit" and "untracked;native_exec" in e["detail"]}
        if not native:
            problems.append("the child that exec'd /bin/true was not untracked")
        elif any(e["process_id"] in native and e["type"].startswith("file_") for e in mine):
            problems.append("records from /bin/true after it left scope")
    else:   # a native helper: still tracked, its opens recorded, its reads only sampled from kernel aggregates
        native = {e["process_id"] for e in mine if e["type"] == "process_start" and ";attribution=native_helper;native_depth=1" in e["detail"]}
        if not native:
            problems.append("the child that exec'd /bin/true is not a native helper")
        elif not any(e["process_id"] in native and e["type"] == "file_create" for e in mine):
            problems.append("no open record of the native helper /bin/true (its loader's libc)")
        elif any(e["process_id"] in native and e["type"] in ("file_read", "file_write") and ";native_io=sampled;" not in e["detail"]
                 and "repeats_tail" not in e["detail"] for e in mine):
            problems.append("a read or write of the native helper /bin/true recorded per call")
    losses = [e for e in events if e["type"] == "coverage" and e["text"] == "ebpf_losses"]
    if not losses or "pending_overwrite=" not in losses[-1]["detail"]:
        problems.append("no ebpf_losses coverage record")
    else:
        print("%s: ebpf_losses %s" % (mode, losses[-1]["detail"]))
else:
    if "bpf_unavailable" not in coverage:
        problems.append("no bpf_unavailable coverage record under --no-ebpf")
    if "ebpf_active" in coverage:
        problems.append("ebpf_active although --no-ebpf was given")
for kind, test in expect.items():
    if not has(kind, test):
        problems.append("no " + kind)
import importlib
sys.path.insert(0, "tests/ebpf_checks")
for upgrade in ("payload", "netattr", "packets", "wineserver", "parity", "sysall", "gaps", "unixproto", "scope"):
    importlib.import_module("check_" + upgrade).check(mode, path, events, mine, pids, coverage, problems)
for problem in problems:
    print("FAIL %s: %s" % (mode, problem))
print("%s: %d records, %d from the probe" % (mode, len(events), len(mine)))
sys.exit(1 if problems else 0)
PY
}

run_session ebpf --page-faults
check ebpf ebpf
run_session nopayloads --no-payloads --native-depth 0
check nopayloads nopayloads
run_session fallback --no-ebpf
check fallback fallback

for upgrade in $upgrades; do "${upgrade}_end"; done

[ "$fail" = 0 ] && echo "linux ebpf test: PASS" || echo "linux ebpf test: FAIL"
exit "$fail"
