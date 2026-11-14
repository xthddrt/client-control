# The scope upgrade (sourced by tests/linux_ebpf_test.sh; checks in check_scope.py): native helpers past --native-depth,
# their I/O, and the launch wrapper. A copy of /bin/sh named winebrowser.exe under the scope (Wine names a process after
# its image) forks a chain of hops (tests/fixtures/scope_hop.sh), each exec one native depth deeper: python3 at depth 6
# connects to a local listener, sends and receives, writes a file in 10 calls and renames it; /bin/true at depth 9 is
# past the hand-off's 8. The same chain forked by a copy named hop-runner leaves at --native-depth + 1. A wrapper
# started as kfilterctl launch's child (tests/fixtures/scope_launch.sh: in kfilter/launch-<launcher pid> before its
# exec) writes a file, runs grep on it and execs /bin/true. Not under --no-ebpf.
scope_session() {
    [ "$name" = fallback ] && return 0
    mkdir -p "$scope/files/handoff" "$scope/files/plain" "$scope/files/launch"
    cp /bin/sh "$scope/winebrowser.exe"
    cp /bin/sh "$scope/hop-runner"
    hop=$(pwd)/tests/fixtures/scope_hop.sh
    rm -f "$work/$name/scope.port"
    python3 - "$work/$name/scope.port" <<'PY' &
import socket, sys
listener = socket.socket()
listener.bind(("127.0.0.1", 0))
listener.listen(4)
listener.settimeout(20)
open(sys.argv[1], "w").write(str(listener.getsockname()[1]))
try:
    while True:
        peer, _ = listener.accept()
        peer.recv(4096)
        peer.sendall(b"ok")
        peer.close()
except OSError:
    pass
PY
    scope_listener=$!
    for _ in $(seq 1 20); do [ -s "$work/$name/scope.port" ] && break; sleep 0.1; done
    port=$(cat "$work/$name/scope.port")
    # "; true": the shell forks the first hop (a last simple command would be exec'd in the shell itself)
    "$scope/winebrowser.exe" -c "/bin/sh $hop 1 $scope/files/handoff $port; true" ||
        { echo "FAIL $name: the hand-off chain exited $?"; fail=1; }
    "$scope/hop-runner" -c "/bin/sh $hop 1 $scope/files/plain $port; true" ||
        { echo "FAIL $name: the plain chain exited $?"; fail=1; }
    cp tests/fixtures/scope_wrapper.sh "$work/$name/wrapper"
    chmod 755 "$work/$name/wrapper"
    sh tests/fixtures/scope_launch.sh "$work/$name/wrapper" "$scope/files/launch" &
    launcher=$!
    wait "$launcher"
    status=$?
    if [ "$status" = 125 ]; then echo skipped >"$work/$name/scope.launcher"; else echo "$launcher" >"$work/$name/scope.launcher"; fi
    [ "$status" = 0 ] || [ "$status" = 125 ] || { echo "FAIL $name: the launch wrapper exited $status"; fail=1; }
    kill "$scope_listener" 2>/dev/null
    return 0
}
scope_end() { :; }
