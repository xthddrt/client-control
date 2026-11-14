#!/bin/sh
# scope_launch.sh PROGRAM [ARG...] (tests/ebpf_checks/scope.sh, root): starts PROGRAM as kfilterctl launch starts the
# launch wrapper (filter/tool/linux_client.cpp): its forked child joins the session cgroup
# /sys/fs/cgroup/kfilter/launch-<this shell's pid> before it execs PROGRAM; the cgroup goes when PROGRAM has ended.
cgroup=/sys/fs/cgroup/kfilter/launch-$$
mkdir -p /sys/fs/cgroup/kfilter && mkdir "$cgroup" || exit 125
/bin/sh -c 'echo $$ >"$0/cgroup.procs" && exec "$@"' "$cgroup" "$@"
status=$?
rmdir "$cgroup"
exit "$status"
