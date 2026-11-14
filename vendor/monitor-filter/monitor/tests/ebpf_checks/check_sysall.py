"""Every syscall recorded (agent/linux/sysagg.h, monitor.bpf.c sys_agg), called by tests/linux_ebpf_test.sh check():
- kernel aggregates (repeats_tail;syscall=<call>;aggregate=kernel;<key>=;repeats_before=;errors=;repeat_offsets=) for
  the probe's hot and once counted-only calls (probe_sysall.h): rt_sigprocmask by how, failing futex waits by op with
  their errors, anonymous memory that is not executable (mmap, mprotect R and NONE, madvise, munmap with their
  ranges), mremap of executable memory flagged prot=0x5, brk, fcntl F_GETFL, getrandom, a child's exit_group code 7
  (before its process_exit) and syscall 511 (ENOSYS); no per-call record of that memory;
- records for the rare ones: fcntl F_SETLK/F_SETOWN/F_SETSIG/F_ADD_SEALS/F_NOTIFY, flock, chdir, umask, the SIGTRAP
  handler (rt_sigaction), wait4 of the child, and prctl's names (PR_SET_NAME, PR_SET_VMA);
- syscall_counts holds the aggregated calls as recorded=1, ebpf_losses its new counters at 0, ebpf_active aggregated=;
- the ia32 probe: old_mmap (a struct) as mmap records (its file and its anonymous memory), its mprotect, munmap,
  _llseek, fcntl (55) and rt_sigprocmask as ia32 aggregates, fcntl64(F_SETLK64) as a record, its exit_group code."""
import re


def check(mode, path, events, mine, pids, coverage, problems):
    if mode == "fallback":
        return

    def number(e, key):
        found = re.search(r"(?:^|;)" + key + r"=(0x[0-9a-f]+|\d+)", e.get("detail", ""))
        return int(found.group(1), 0) if found else -1

    def summaries(records, name, test=lambda e: True):
        return [e for e in records if e["text"] == "system:" + name and "aggregate=kernel" in e.get("detail", "") and test(e)]

    def total(records, name, test=lambda e: True):
        return sum(e["value1"] for e in summaries(records, name, test))

    def has(records, test):
        return any(test(e) for e in records)

    if total(mine, "rt_sigprocmask", lambda e: number(e, "how") == 0) < 1000:
        problems.append("sysall: rt_sigprocmask how=0x0 summaries count fewer than the probe's 1000 calls")
    if sum(number(e, "errors") for e in summaries(mine, "futex", lambda e: number(e, "op") == 0x80)) < 10:
        problems.append("sysall: no futex op=0x80 summary with the 10 failed waits as errors")
    memory = {"mmap": "prot=0x3;", "mprotect": "prot=0x1;", "madvise": "advice=0x4;", "munmap": ""}
    for name, key in memory.items():
        if not summaries(mine, name, lambda e: key in e["detail"] and e["type"] == "file_section" and "repeat_offsets=" in e["detail"]):
            problems.append("sysall: no file_section %s summary %swith its range" % (name, key))
    if not summaries(mine, "mprotect", lambda e: "prot=0x0;" in e["detail"]):
        problems.append("sysall: no mprotect prot=0x0 (PROT_NONE) summary")
    # The probe's one mremap of 4 KiB to 8 KiB: value0 the two lengths, not the span between the two ranges.
    if not summaries(mine, "mremap", lambda e: number(e, "prot") == 5 and "repeat_offsets=" in e["detail"] and
                     number(e, "repeats_before") == 1 and e["value0"] == 4096 + 8192):
        problems.append("sysall: no mremap summary flagging the executable source (prot=0x5) with its ranges and bytes")
    for name, key, value in (("brk", None, None), ("fcntl", "cmd", 3), ("getrandom", "flags", 1), ("nr511", None, None)):
        if not summaries(mine, name, lambda e: key is None or number(e, key) == value):
            problems.append("sysall: no %s summary%s" % (name, "" if key is None else " %s=%#x" % (key, value)))
    if not summaries(mine, "nr511", lambda e: number(e, "errors") >= 1):
        problems.append("sysall: syscall 511 (ENOSYS) summary without its error")
    if any(e["type"] == "file_section" and e["text"].startswith(("mprotect:", "anonymous")) and not e["value1"] & 4
           for e in mine):
        problems.append("sysall: a per-call record of anonymous memory that is not executable (the kernel aggregates it)")
    exits = {e["process_id"]: index for index, e in enumerate(events) if e["type"] == "process_exit" and e["process_id"] in pids}
    sevens = [index for index, e in enumerate(events) if e.get("process_id") in pids and e["text"] == "system:exit_group" and
              number(e, "code") == 7]
    if not sevens or not any(index < exits.get(events[index]["process_id"], -1) for index in sevens):
        problems.append("sysall: no exit_group code=0x7 summary of the child before its process_exit")

    for command in (6, 8, 10, 1026, 1033):   # F_SETLK, F_SETOWN, F_SETSIG, F_NOTIFY, F_ADD_SEALS
        if not has(mine, lambda e: e["type"] == "file_device_control" and "syscall=fcntl;" in e["detail"] and e["value0"] == command):
            problems.append("sysall: no fcntl record for command %d" % command)
    if not has(mine, lambda e: e["type"] == "file_device_control" and "syscall=flock;" in e["detail"] and
               e["text"].endswith("/probe-lock.txt") and e["value0"] == 2):
        problems.append("sysall: no flock(LOCK_EX) record on probe-lock.txt")
    if not has(mine, lambda e: e["type"] == "file_query_information" and "syscall=chdir;" in e["detail"] and e["text"].endswith("/files")):
        problems.append("sysall: no chdir record naming the directory")
    if not has(mine, lambda e: e["type"] == "process_handle" and e["detail"].startswith("umask;option=18;")):
        problems.append("sysall: no umask(022) record")
    if not has(mine, lambda e: e["type"] == "process_handle" and e["detail"].startswith("rt_sigaction;option=5;")):
        problems.append("sysall: no rt_sigaction record for the SIGTRAP handler")
    if not has(mine, lambda e: e["type"] == "process_handle" and e["detail"].startswith("wait4;") and
               e.get("target_process_id") in pids):
        problems.append("sysall: no wait4 record naming the child")
    if not has(mine, lambda e: e["detail"].startswith("prctl;option=15;") and ";name=msmon-sysall" in e["detail"]):
        problems.append("sysall: no prctl(PR_SET_NAME) record with the name")
    if not has(mine, lambda e: e["detail"].startswith("prctl;option=1398164801;") and ";vma_name=msmon-vma" in e["detail"]):
        problems.append("sysall: no prctl(PR_SET_VMA) record with the range's name")

    if not has(mine, lambda e: e["type"] == "coverage" and e["text"] == "syscall_counts" and e["detail"].startswith("recorded=1;")
               and number(e, "rt_sigprocmask") >= 1000):
        problems.append("sysall: syscall_counts does not hold the aggregated rt_sigprocmask calls as recorded=1")
    losses = [e for e in events if e["type"] == "coverage" and e["text"] == "ebpf_losses"]
    if not losses or any(number(losses[-1], key) != 0 for key in ("pending_full", "counts_full", "agg_full", "unadmitted")):
        problems.append("sysall: ebpf_losses lacks pending_full/counts_full/agg_full/unadmitted at 0: %s" %
                        (losses[-1]["detail"] if losses else None))
    if not any(e["type"] == "coverage" and e["text"] == "ebpf_active" and "aggregated=" in e["detail"] for e in events):
        problems.append("sysall: ebpf_active does not say aggregated=")

    ia32 = {e["process_id"] for e in events if e["type"] == "process_start" and
            "ia32_probe" in e.get("text", "") + e.get("process_path", "")}
    if not ia32:
        return   # check_parity.py reports the missing ia32 probe
    rec = [e for e in events if e.get("process_id") in ia32]
    if not has(rec, lambda e: e["type"] == "file_section" and e["text"].endswith("/ia32-a.txt") and "syscall=mmap;" in e["detail"]
               and re.search(r";args=0x0,0x2000,0x5,0x2,", e["detail"])):
        problems.append("sysall: ia32 old_mmap of ia32-a.txt not recorded as mmap with its struct's arguments")
    if not has(rec, lambda e: e["type"] == "file_section" and e["text"] == "anonymous" and re.search(r";args=0x0,0x2000,0x3,0x22,", e["detail"])):
        problems.append("sysall: ia32 old_mmap of anonymous memory not recorded")
    for name, key, value in (("ia32:mprotect", "prot", 1), ("ia32:munmap", None, None), ("ia32:_llseek", "whence", 2),
                             ("ia32:fcntl", "cmd", 3), ("ia32:rt_sigprocmask", "how", 0), ("ia32:exit_group", "code", 0)):
        if not summaries(rec, name, lambda e: key is None or number(e, key) == value):
            problems.append("sysall: no %s summary%s" % (name, "" if key is None else " %s=%#x" % (key, value)))
    if not has(rec, lambda e: e["type"] == "file_device_control" and "syscall=fcntl;" in e["detail"] and e["value0"] == 13 and
               e["text"].endswith("/ia32-a.txt")):
        problems.append("sysall: ia32 fcntl64(F_SETLK64) not recorded")
