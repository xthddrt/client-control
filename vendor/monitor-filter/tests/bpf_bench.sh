#!/bin/sh
# Root: kfilter's BPF test bench (filter/tests/linux_bpf_bench.cpp): the kernel layer's own decision code run
# on synthetic requests with BPF_PROG_TEST_RUN, on fresh unpinned maps with nothing attached, so a running
# kfilterd is untouched. Builds filter/ with its tests first (as the user sudo ran it for, so the build tree
# stays theirs), then runs the bench's cases. Skips without root or without a BPF toolchain. Arguments go to the bench
# (--net-policies A B: the network reload case between two policy files instead of its own).
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
if [ "$(id -u)" != 0 ]; then
    echo "bpf_bench: skipped (needs root: it loads BPF programs)"
    exit 0
fi
if [ -n "${SUDO_USER:-}" ]; then
    sudo -u "$SUDO_USER" sh "$root/filter/build.sh" tests >/dev/null
else
    sh "$root/filter/build.sh" tests >/dev/null
fi
bench="$root/filter/build/linux/kfilter-bpf-bench"
if [ ! -x "$bench" ]; then
    echo "bpf_bench: skipped (no BPF build: clang, bpftool and the libbpf headers are needed)"
    exit 0
fi
exec "$bench" "$@"
