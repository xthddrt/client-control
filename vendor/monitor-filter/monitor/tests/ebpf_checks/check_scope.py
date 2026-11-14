"""The scope upgrade, called by tests/linux_ebpf_test.sh check() (actions: scope.sh, tests/fixtures/scope_hop.sh,
scope_launch.sh and scope_wrapper.sh):
- the hand-off chain (forked by winebrowser.exe) tracked as a native helper to depth 8, its exec at depth 9 untracked;
  at depth 6 (python3) its connect, its sends and receives and its file writes as records sampled from kernel aggregates
  (native_io=sampled, the socket's endpoints, the file named by its open) and summaries (system:write, ino=, inode_type=) whose calls
  add up to its syscall_counts, its open and rename as records;
- the same chain forked by hop-runner untracked at --native-depth + 1 (3: depth 4; --native-depth 0: depth 1);
- the launch wrapper joined at its first exec (scope=kfilter_launch:launch-<launcher pid>) and recorded in full: its
  write, its grep child's read, its exec of /bin/true, none of them a native helper's."""
import os
import re


def check(mode, path, events, mine, pids, coverage, problems):
    if mode == "fallback":
        return
    session = os.path.dirname(path)
    scope = os.path.join(session, "scope")

    def number(e, key):
        found = re.search(r"(?:^|;)" + key + r"=(-?0x[0-9a-f]+|-?\d+)", e.get("detail", ""))
        return int(found.group(1), 0) if found else 0

    def chain(folder):
        """The pid that ran a chain's hops (one process, an exec per hop), and its exec records by native depth."""
        hop = "scope_hop.sh 1 " + os.path.join(scope, "files", folder) + " "
        starts = [e for e in events if e["type"] == "process_start" and e.get("value1") == 1 and
                  e["detail"].startswith("/bin/sh ") and hop in e["detail"]]   # not the runner's "-c" line
        if not starts:
            return None, {}
        pid = starts[0]["process_id"]
        depths = {number(e, "native_depth"): e for e in events if e.get("process_id") == pid and
                  e["type"] == "process_start" and e.get("value1") == 1 and ";native_depth=" in e["detail"]}
        return pid, depths

    def untracked(pid):
        return any(e["type"] == "process_exit" and e.get("process_id") == pid and "untracked;native_exec" in e["detail"]
                   for e in events)

    handoff, depths = chain("handoff")
    if handoff is None:
        problems.append("scope: the hand-off chain's first hop has no exec record")
    else:
        if sorted(depths) != list(range(1, 9)):
            problems.append("scope: the hand-off chain's native depths %s (want 1-8)" % sorted(depths))
        if not untracked(handoff):
            problems.append("scope: the hand-off chain was not untracked at depth 9")
        if "python3" not in depths.get(6, {}).get("text", ""):
            problems.append("scope: depth 6 of the hand-off chain is not python3: %s" % depths.get(6, {}).get("text"))
        own = [e for e in events if e.get("process_id") == handoff]
        port = open(os.path.join(session, "scope.port")).read().strip()
        hop = "/files/handoff/hop.txt"
        sampled = [e for e in own if ";native_io=sampled;ino=" in e["detail"]]
        endpoints = re.compile(r";endpoints=127\.0\.0\.1:\d+ -> 127\.0\.0\.1:" + port + r"(;|$)")
        tests = {
            "connect": lambda e: e["type"] == "network_connect" and e["text"] == "127.0.0.1:" + port,
            "open of hop.txt": lambda e: e["type"] == "file_create" and e["text"].endswith(hop) and e["status"] == 0,
            "rename of hop.txt": lambda e: e["type"] == "file_set_information" and "rename;to" in e["detail"] and
                hop in e["text"],
            "sampled write of hop.txt": lambda e: e in sampled and e["type"] == "file_write" and e["text"].endswith(hop),
            "sampled send with its endpoints": lambda e: e in sampled and "syscall=sendto;" in e["detail"] and
                endpoints.search(e["detail"]),
            "sampled receive": lambda e: e in sampled and "syscall=recvfrom;" in e["detail"] and e["text"].startswith("socket:[") and
                ";inode_type=socket" in e["detail"],
            "write summary": lambda e: e["text"] == "system:write" and ";aggregate=kernel;ino=" in e["detail"] and
                ";inode_type=file;" in e["detail"] and ";attribution=native_helper" in e["detail"],
        }
        for what, test in tests.items():
            if not any(test(e) for e in own):
                problems.append("scope: no %s record from the hand-off chain at depth 6" % what)
        if any(e["type"] in ("file_read", "file_write") and e not in sampled and "repeats_tail" not in e["detail"] and
               not e["detail"].startswith("via=") for e in own):
            problems.append("scope: a native helper's read or write recorded per call (not sampled)")
        # Every write: sampled records (1 each, with the agent's own repeats) and kernel summaries (repeats_before).
        writes = [e for e in own if re.search(r"(?:^|;)syscall=write;", e["detail"])]
        total = sum(number(e, "repeats_before") + (0 if "repeats_tail" in e["detail"] else 1) for e in writes)
        counted = sum(number(e, "write") for e in own if e["type"] == "coverage" and e["text"] == "syscall_counts")
        if total < 10 or total != counted:
            problems.append("scope: the hand-off's writes: %d in records and summaries, %d in syscall_counts (want equal, >= 10)"
                            % (total, counted))

    plain, depths = chain("plain")
    keep = 0 if mode == "nopayloads" else 3   # --native-depth 0 in that session, else the default
    if plain is None and keep:
        problems.append("scope: the plain chain's first hop has no exec record")
    elif plain is not None:
        if sorted(depths) != list(range(1, keep + 1)) or not untracked(plain):
            problems.append("scope: the plain chain kept depths %s, untracked=%s (want 1-%d, then untracked)" %
                            (sorted(depths), untracked(plain), keep))
        if any(e.get("process_id") == plain and e["type"] == "network_connect" for e in events):
            problems.append("scope: the plain chain's connect at depth 6 was recorded")

    launcher = open(os.path.join(session, "scope.launcher")).read().strip()
    if launcher == "skipped":
        print("scope: no cgroup for the launch wrapper (mkdir under /sys/fs/cgroup/kfilter failed): skipped")
        return
    joined = [e for e in events if e["type"] == "process_start" and
              ";scope=kfilter_launch:launch-" + launcher in e.get("detail", "")]
    if not joined:
        problems.append("scope: the launch wrapper did not join at its first exec (scope=kfilter_launch:launch-%s)" % launcher)
        return
    wrapper = joined[0]["process_id"]
    out = os.path.join(scope, "files", "launch", "launch-out.txt")
    family = {wrapper} | {e["process_id"] for e in events if e["type"] == "process_start" and e.get("parent_process_id") == wrapper}
    own = [e for e in events if e.get("process_id") in family]
    tests = {
        "exec of the wrapper": lambda e: e["process_id"] == wrapper and e["type"] == "process_start" and e.get("value1") == 1 and
            "/wrapper " in e["detail"],
        "write of launch-out.txt": lambda e: e["process_id"] == wrapper and e["type"] == "file_write" and e["text"] == out,
        "grep's read of launch-out.txt": lambda e: e["process_id"] != wrapper and e["type"] == "file_read" and e["text"] == out,
        "exec of /bin/true": lambda e: e["process_id"] == wrapper and e["type"] == "process_start" and e.get("value1") == 1 and
            e["text"].endswith("/true"),
    }
    for what, test in tests.items():
        if not any(test(e) for e in own):
            problems.append("scope: no %s record in the launch" % what)
    if any(";attribution=native_helper" in e.get("detail", "") or ";native_io=" in e.get("detail", "") for e in own):
        problems.append("scope: the launch wrapper's programs were recorded as native helpers")
