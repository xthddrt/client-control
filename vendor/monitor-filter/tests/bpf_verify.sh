#!/bin/sh
# Root: verify-loads every program of kfilter's and msmon's BPF objects (watch.bpf.o: --watch's own) (tests/bpf_verify.c: fresh,
# unpinned maps, nothing attached, so a running layer is untouched) and prints each program's verified
# instructions. Fails when an object does not load or a program passes 990,000 (the kernel stops at
# 1,000,000). Skips without root or without a BPF build (build.sh first).
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
if [ "$(id -u)" != 0 ]; then
    echo "bpf_verify: skipped (needs root: it loads BPF programs)"
    exit 0
fi
objects=""
for object in "$root/filter/build/linux/bpf/kfilter.bpf.o" "$root/monitor/build/linux/bpf/monitor.bpf.o" \
              "$root/monitor/build/linux/bpf/watch.bpf.o"; do
    if [ -f "$object" ]; then objects="$objects $object"; else echo "bpf_verify: no $object"; fi
done
if [ -z "$objects" ]; then
    echo "bpf_verify: skipped (no BPF build: run build.sh first)"
    exit 0
fi
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
if [ -e /usr/lib/x86_64-linux-gnu/libbpf.so ]; then libbpf=-lbpf; else libbpf=-l:libbpf.so.1; fi
${CC:-gcc} -O2 -Wall -o "$out/bpf_verify" "$root/tests/bpf_verify.c" $libbpf
status=0
for object in $objects; do
    "$out/bpf_verify" "$object" > "$out/counts" || status=1
    cat "$out/counts"
    awk '$3 == "verified" && $2 > 990000 { print "bpf_verify: " $1 " verifies at " $2 " of the kernel'"'"'s 1,000,000"; over = 1 }
         END { exit over }' "$out/counts" || status=1
done
[ $status = 0 ] && echo "bpf_verify: every program loads"
exit $status
