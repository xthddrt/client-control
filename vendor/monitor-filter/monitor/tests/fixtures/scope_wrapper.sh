#!/bin/sh
# The launch wrapper tests/ebpf_checks/scope.sh starts as kfilterctl launch's child (scope_launch.sh), as
# nexon-launcher is: writes DIR/launch-out.txt, runs grep on it, execs /bin/true.
echo wrapper >"$1/launch-out.txt"
grep -c wrapper "$1/launch-out.txt" >/dev/null
exec /bin/true
