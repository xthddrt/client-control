# The gaps upgrade (sourced by tests/linux_ebpf_test.sh; checks in check_gaps.py): what the probe cannot do from
# inside, while the agent runs: an untracked copy of it (outside the scope) reads a tracked one's memory and maps
# (outside_access), a Wine-named copy is exec'd in a directory under the scope (it joins at that exec), a stand-in
# kfilterd (a root process of that name, unless the real one runs) that the tracked probe may not signal and whose reads
# of a tracked probe are no outside_access, and a library
# a tracked probe loads and unloads (the maps poll's image_unload). And the agent's own bookkeeping: a file read twice
# then left 12 s (its held count written while the key sits idle, before the marker it opens), a file read twice by a
# probe still running at the stop (written at the stop), an exec of /bin/true with a 2000-byte argument (its record's
# detail cut: truncated_detail) and over 64 KiB of environment (env_truncated=), an exec of /bin/sleep (no maps-poll
# unload of the old image). Not under --no-ebpf.
gaps_session() {
    [ "$name" = fallback ] && return 0
    echo twice >"$scope/files/twice.txt"
    echo held >"$scope/files/held.txt"
    "$scope/probe" --twice "$scope/files/twice.txt" 12 "$scope/files/idle-marker" &
    idle=$!
    outside="$work/$name/outside"
    mkdir -p "$outside"
    cp build/linux/linux_ebpf_probe "$outside/probe"
    cp build/linux/linux_ebpf_probe "$outside/wine-preloader"
    cp build/linux/linux_ebpf_probe "$scope/gaps-target"
    cp build/linux/libmsmonprobe.so "$scope/libmsmonprobe.so"
    kfilterd_pid=$(pgrep -x kfilterd | head -n 1)
    stand_in=
    if [ -z "$kfilterd_pid" ]; then
        cp build/linux/linux_ebpf_probe "$outside/kfilterd"
        "$outside/kfilterd" --kfilterd "$work/$name/kfilterd-read.pid" &
        stand_in=$!
        kfilterd_pid=$stand_in
        echo "$stand_in" >"$work/$name/kfilterd.stand_in"
    fi
    echo "$kfilterd_pid" >"$work/$name/kfilterd.pid"
    "$scope/gaps-target" --sleep 4 &
    target=$!
    echo "$target" >"$work/$name/gaps-target.pid"
    sleep 1
    "$outside/probe" --read "$target" || { echo "FAIL $name: the outside reader exited $?"; fail=1; }
    wait "$target"
    (cd "$scope/files" && "$outside/wine-preloader" --sleep 1) || { echo "FAIL $name: wine-preloader exited $?"; fail=1; }
    "$scope/gaps-target" --unload "$scope/libmsmonprobe.so" || { echo "FAIL $name: --unload exited $?"; fail=1; }
    # By now (over 6 s) the agent has found the stand-in (it looks again every 5 s): signalling it is refused, and its
    # reads of a tracked process are a monitor's, no outside_access.
    "$scope/gaps-target" --kill0 "$kfilterd_pid"
    echo "$?" >"$work/$name/kill0.status"
    if [ -n "$stand_in" ]; then
        "$scope/gaps-target" --sleep 2 &
        echo "$!" >"$work/$name/kfilterd-read.pid"
        wait "$!"
    fi
    [ -n "$stand_in" ] && kill "$stand_in" 2>/dev/null
    HUGE=$(head -c 70000 /dev/zero | tr '\0' e) "$scope/gaps-target" --exec /bin/true "$(head -c 2000 /dev/zero | tr '\0' b)"
    "$scope/gaps-target" --exec /bin/sleep 3 &
    echo "$!" >"$work/$name/gaps-exec.pid"
    wait "$!"
    wait "$idle"
    "$scope/probe" --twice "$scope/files/held.txt" 20 &
    gaps_holders="${gaps_holders:-} $!"
    return 0
}
gaps_end() { for holder in ${gaps_holders:-}; do kill "$holder" 2>/dev/null; done; }
