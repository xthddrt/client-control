"""The gaps upgrade, called by tests/linux_ebpf_test.sh check() (actions: tests/fixtures/probe_gaps.h and gaps.sh):
- a process's own fault signals (self_signal; kernel aggregates per signal, code and ip page): the int3 (SI_KERNEL),
  the DR0 hit (trap_hwbkpt, dr6 bit 0), the guard-page storm (segv_accerr: 1000 faults in at most 10 records), the
  seccomp trap (sys_seccomp naming getpgrp) and syscall user dispatch (sys_user_dispatch);
- calls stopped before sys_enter: seccomp:getppid (5, in syscall_counts too) and dispatch:getppid;
- direct syscalls from anonymous executable memory: the uname record and the getpid summary say direct_syscall=1;
- per-address detail: 3 remote iovecs, move_pages' 2 pages (query=1), 3 /proc/<pid>/mem reads at 3 addresses kept
  apart and naming the child as target;
- the output side of a sendfile into a socket (out=socket:[...]);
- exit codes: the gaps child's 42, the sysall child's 7;
- the whole environment at exec (process_environment of /bin/true: WINEDEBUG's value, HOME's withheld);
- outside_access of the untracked reader on the tracked target (attach for /proc/<pid>/mem and process_vm_readv, an
  audited read for maps, never stat's NOAUDIT check);
- the Wine-named copy joined at its exec in a directory under the scope (scope=wine_exec_cwd);
- the stand-in (or real) kfilterd protected: kill(pid, 0) refused, self_protection_denied=kill;protected=kfilterd;
- the library the probe loaded and unloaded: image_unload;source=maps_poll;
- ebpf_losses' new counters: uring_unfinished=0, ucall_unreported present;
- outside_access and self_signal are observer coverage records, none of the stand-in kfilterd's reads;
- held counts written while their key sits idle (twice.txt, before idle-marker's open) and at the stop (held.txt);
- a detail past the string limit flagged truncated_detail, an environment past 64 KiB env_truncated=, an exec that
  leaves the maps poll's old image unreported."""
import os
import re


def check(mode, path, events, mine, pids, coverage, problems):
    if mode == "fallback":
        return
    session = os.path.dirname(path)

    def number(e, key):
        found = re.search(r"(?:^|;)" + key + r"=(-?0x[0-9a-f]+|-?\d+)", e.get("detail", ""))
        return int(found.group(1), 0) if found else None

    def has(records, test):
        return any(test(e) for e in records)

    def faults(name, code_name):
        """Faults of one signal and code: 1 per first record, repeats_before per summary; and the records."""
        records = [e for e in mine if e["type"] == "coverage" and e.get("text") == "self_signal" and
                   ";name=%s;" % name in e.get("detail", "") and ";code_name=%s;" % code_name in e.get("detail", "") + ";"]
        calls = sum(number(e, "repeats_before") if e["detail"].startswith("repeats_tail;") else 1 for e in records)
        return calls, records

    for name, code_name, what in (("sigtrap", "si_kernel", "the int3"), ("sigtrap", "trap_hwbkpt", "the DR0 hit"),
                                  ("sigsys", "sys_seccomp", "the seccomp trap"),
                                  ("sigsys", "sys_user_dispatch", "the syscall user dispatch stop")):
        if not faults(name, code_name)[0]:
            problems.append("gaps: no self_signal %s/%s record (%s)" % (name, code_name, what))
    if not has(mine, lambda e: e.get("text") == "self_signal" and ";name=sigtrap;" in e["detail"] and
               ";code_name=trap_hwbkpt;" in e["detail"] and (number(e, "dr6") or 0) & 1):
        problems.append("gaps: the DR0 hit's record does not say dr6 bit 0")
    if not has(mine, lambda e: e.get("text") == "self_signal" and ";name=sigsys;" in e["detail"] and
               ";code_name=sys_seccomp;" in e["detail"] and number(e, "syscall") == 111):
        problems.append("gaps: the seccomp trap's record does not name getpgrp (111)")
    storm, records = faults("sigsegv", "segv_accerr")
    if storm != 1000 or len(records) > 10:
        problems.append("gaps: the guard-page storm is %d faults in %d records (want 1000 in at most 10)" % (storm, len(records)))

    def summed(text):
        return sum(e["value1"] for e in mine if e.get("text") == text and "aggregate=kernel" in e.get("detail", ""))

    if summed("system:seccomp:getppid") != 5:
        problems.append("gaps: system:seccomp:getppid summaries count %d calls (want 5)" % summed("system:seccomp:getppid"))
    if summed("system:dispatch:getppid") < 1:
        problems.append("gaps: no system:dispatch:getppid summary")
    if not has(mine, lambda e: e["type"] == "coverage" and e["text"] == "syscall_counts" and ";seccomp:getppid=5" in e["detail"] + ";"):
        problems.append("gaps: syscall_counts lacks seccomp:getppid=5")
    if not has(mine, lambda e: "syscall=uname;" in e.get("detail", "") and ";direct_syscall=1" in e["detail"]):
        problems.append("gaps: the uname from anonymous memory is not direct_syscall=1")
    if sum(e["value1"] for e in mine if e.get("text") == "system:getpid" and ";direct_syscall=1;" in e.get("detail", "")) != 3:
        problems.append("gaps: no getpid summary of the 3 direct calls (direct_syscall=1)")
    if has(mine, lambda e: ";direct_syscall=1" in e.get("detail", "") and "syscall=uname;" not in e["detail"] and
           e.get("text") != "system:getpid"):
        problems.append("gaps: a call from ELF code flagged direct_syscall=1")

    if not has(mine, lambda e: e.get("detail", "").startswith("process_vm_readv;") and
               re.search(r";remote_iov=0x[0-9a-f]+:0x8,0x[0-9a-f]+:0x8,0x[0-9a-f]+:0x4;", e["detail"])):
        problems.append("gaps: no process_vm_readv record listing its 3 remote iovecs with their lengths")
    if not has(mine, lambda e: e.get("detail", "").startswith("move_pages;") and
               re.search(r";pages=0x[0-9a-f]+,0x[0-9a-f]+;query=1", e["detail"])):
        problems.append("gaps: no move_pages record with its 2 pages and query=1")
    reads = [e for e in mine if e["type"] == "file_read" and re.search(r"^/proc/\d+/mem$", e.get("text", "")) and
             "syscall=pread64;" in e.get("detail", "")]
    if len({e["value1"] for e in reads}) < 3 or not all(e.get("target_process_id") in pids for e in reads):
        problems.append("gaps: /proc/<pid>/mem reads at %d addresses, targets %s (want 3 kept apart, naming the child)" %
                        (len({e["value1"] for e in reads}), sorted({e.get("target_process_id") for e in reads})))
    if not has(mine, lambda e: e["type"] == "file_read" and "syscall=sendfile;" in e.get("detail", "") and
               e.get("text", "").endswith("/probe-gaps.txt") and ";out=socket:[" in e["detail"] and e["value0"] == 5):
        problems.append("gaps: no sendfile record naming its output socket (out=socket:[ino]) with 5 bytes")

    for status in (42, 7):
        if not has(mine, lambda e: e["type"] == "process_exit" and ";exit_status=%d" % status in ";" + e.get("detail", "")):
            problems.append("gaps: no process_exit with exit_status=%d" % status)
    if not has(mine, lambda e: e["type"] == "coverage" and e["text"] == "process_environment" and
               "WINEDEBUG=-all" in e["detail"] and "HOME=withheld:1" in e["detail"]):
        problems.append("gaps: no process_environment of /bin/true (WINEDEBUG=-all shown, HOME withheld)")

    try:
        target = int(open(os.path.join(session, "gaps-target.pid")).read())
    except (OSError, ValueError):
        target = None
    outside = [e for e in events if e.get("process_id") == target and e.get("detail", "").startswith(("outside_access;", "repeats_tail;syscall=outside_access;"))]
    for call, mode_names in (("openat", "attach|fscreds"), ("process_vm_readv", "attach|realcreds"), ("openat", "read|fscreds")):
        if not any(";call=%s;" % call in e["detail"] and ";mode_names=%s;" % mode_names in e["detail"] for e in outside):
            problems.append("gaps: no outside_access %s (%s) of the reader on the tracked target" % (call, mode_names))
    if any("noaudit" in e["detail"] for e in outside):
        problems.append("gaps: an outside_access record of a NOAUDIT check (/proc/<pid>/stat)")
    observed = [e for e in events if e.get("detail", "").startswith(("outside_access;", "repeats_tail;syscall=outside_access;",
                                                                   "self_signal;", "repeats_tail;syscall=self_signal;"))]
    if any(e["type"] != "coverage" or not e.get("flags", 0) & 0x20 for e in observed):
        problems.append("gaps: an outside_access or self_signal record that is no observer coverage record (a reader would "
                        "take it for the tracked process's own handle)")
    try:
        stand_in = int(open(os.path.join(session, "kfilterd.stand_in")).read())
    except (OSError, ValueError):
        stand_in = None
    if stand_in and any(";actor_pid=%d;" % stand_in in e["detail"] for e in observed):
        problems.append("gaps: the stand-in kfilterd's reads of a tracked probe are outside_access records")
    if not has(events, lambda e: e["type"] == "process_start" and ";scope=wine_exec_cwd:" in e.get("detail", "") and
               e["detail"].split(";scope=wine_exec_cwd:")[1].split(";")[0].endswith("/scope/files")):
        problems.append("gaps: wine-preloader exec'd in scope/files did not join at its exec (scope=wine_exec_cwd)")
    try:
        refused = open(os.path.join(session, "kill0.status")).read().strip() == "1"
    except OSError:
        refused = False
    if not refused or not has(events, lambda e: e.get("detail", "").startswith("self_protection_denied=kill;protected=kfilterd")):
        problems.append("gaps: kill(kfilterd, 0) from the tracked tree was not refused and recorded (protected=kfilterd)")
    if not has(events, lambda e: e["type"] == "file_section" and e.get("detail", "").startswith("image_unload;source=maps_poll;") and
               e.get("text", "").endswith("/libmsmonprobe.so")):
        problems.append("gaps: no image_unload;source=maps_poll of libmsmonprobe.so")
    # The agent's bookkeeping: held counts written while their key sits idle, and at the stop; a detail cut at the
    # string limit flagged; an environment past 64 KiB says so; an exec starts the maps poll's image list over.
    marker = [index for index, e in enumerate(events) if e["type"] == "file_create" and e.get("text", "").endswith("/idle-marker")]
    tails = [index for index, e in enumerate(events) if e.get("detail", "").startswith("repeats_tail;") and
             e.get("text", "").endswith("/twice.txt")]
    if not marker or not tails or min(tails) > marker[0]:
        problems.append("gaps: twice.txt's held count was not written while its key sat idle (before idle-marker's open)")
    if not has(events, lambda e: e.get("detail", "").startswith("repeats_tail;") and e.get("text", "").endswith("/held.txt")):
        problems.append("gaps: held.txt's held count (its reader still running) was not written at the stop")
    if not has(events, lambda e: e["type"] == "process_start" and e.get("text", "").endswith("/true") and
               "b" * 100 in e.get("detail", "") and e.get("flags", 0) & 0x800):
        problems.append("gaps: /bin/true's 2000-byte argument is not a record flagged truncated_detail (0x800)")
    environment = [e for e in events if e["type"] == "coverage" and e.get("text") == "process_environment"]
    if not has(environment, lambda e: "env_truncated=" in e["detail"]) or not has(environment, lambda e: "HUGE=withheld:" in e["detail"]) or \
            has(environment, lambda e: "HUGE=eee" in e["detail"]):
        problems.append("gaps: no process_environment of the 70 KB environment saying env_truncated= (HUGE withheld)")
    try:
        sleeper = int(open(os.path.join(session, "gaps-exec.pid")).read())
    except (OSError, ValueError):
        sleeper = None
    if has(events, lambda e: e.get("process_id") == sleeper and e.get("detail", "").startswith("image_unload;source=maps_poll;") and
           e.get("text", "").endswith("/gaps-target")):
        problems.append("gaps: the maps poll took gaps-target's exec of /bin/sleep for an unload of its old image")
    losses = [e for e in events if e["type"] == "coverage" and e["text"] == "ebpf_losses"]
    if not losses or number(losses[-1], "uring_unfinished") != 0 or number(losses[-1], "ucall_unreported") is None:
        problems.append("gaps: ebpf_losses lacks uring_unfinished=0 or ucall_unreported: %s" % (losses[-1]["detail"] if losses else None))
