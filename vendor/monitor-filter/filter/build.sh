#!/bin/sh
# Linux build: kfilterd and kfilterctl into build/linux/. `build.sh tests` also builds the test
# binaries (tests/run_offline.sh runs them). Installs and starts nothing.
set -eu
cd "$(dirname "$0")"
out=build/linux
mkdir -p "$out/obj"
CC=${CC:-gcc}
CXX=${CXX:-g++}
FLAGS="-O2 -Wall -Wextra -Wno-unused-parameter"

$CC -std=gnu11 $FLAGS -c driver/match.c -o "$out/obj/match.o"
# policy.c allocates a config with only RuleCount rules behind its fixed header;
# GCC's bounds check sees the full-size type and warns about every field.
$CC -std=gnu11 $FLAGS -Wno-array-bounds -c driver/policy.c -o "$out/obj/policy.o"
$CC -std=gnu11 $FLAGS -c driver/events.c -o "$out/obj/events.o"
# BPF LSM layer preflight: clang (CLANG=), bpftool (BPFTOOL=), libbpf headers (LIBBPF_INCLUDE=)
# and the running kernel's BTF. Without them kfilterd is built without it and uses fanotify
# and nftables only.
CLANG=${CLANG:-$(command -v clang-18 || command -v clang || true)}
BPFTOOL=${BPFTOOL:-$(command -v bpftool || { [ -x /usr/sbin/bpftool ] && echo /usr/sbin/bpftool; } || true)}
LIBBPF_INCLUDE=${LIBBPF_INCLUDE:-/usr/include}
BPF_CFLAGS=""
BPF_LIBS=""
if [ -n "$CLANG" ] && [ -n "$BPFTOOL" ] && [ -f "$LIBBPF_INCLUDE/bpf/libbpf.h" ] && [ -r /sys/kernel/btf/vmlinux ]; then
    mkdir -p "$out/bpf"
    "$BPFTOOL" btf dump file /sys/kernel/btf/vmlinux format c > "$out/bpf/vmlinux.h"
    "$CLANG" -g -O2 -target bpf -mcpu=v3 -D__TARGET_ARCH_x86 -Wno-missing-declarations -I "$out/bpf" \
        -I "$LIBBPF_INCLUDE" -c linux/bpf/kfilter.bpf.c -o "$out/bpf/kfilter.debug.o"
    "$BPFTOOL" gen object "$out/bpf/kfilter.bpf.o" "$out/bpf/kfilter.debug.o"
    python3 - "$out/bpf/kfilter.bpf.o" "$out/bpf/kfilter_bpf_object.h" <<'PY'
import sys
data = open(sys.argv[1], "rb").read()
rows = ",\n".join(",".join(str(b) for b in data[i:i + 32]) for i in range(0, len(data), 32))
open(sys.argv[2], "w").write("static const unsigned char kKfilterBpfObject[] = {\n" + rows + "\n};\n")
PY
    BPF_CFLAGS="-DKFILTER_BPF -I$out/bpf -I$LIBBPF_INCLUDE"
    if [ -e /usr/lib/x86_64-linux-gnu/libbpf.so ]; then BPF_LIBS=-lbpf; else BPF_LIBS=-l:libbpf.so.1; fi
    echo "BPF LSM layer: built ($out/bpf/kfilter.bpf.o)"
else
    echo "BPF LSM layer: NOT built (need clang, bpftool, libbpf headers and /sys/kernel/btf/vmlinux):" >&2
    echo "  sudo apt install clang-18 libbpf-dev linux-tools-common linux-tools-\$(uname -r)" >&2
fi
for source in kfilterd procs fanotify net; do
    $CXX -std=c++17 $FLAGS -c "linux/$source.cpp" -o "$out/obj/$source.o"
done
# shellcheck disable=SC2086
$CXX -std=c++17 $FLAGS $BPF_CFLAGS -c linux/bpf_loader.cpp -o "$out/obj/bpf_loader.o"
# shellcheck disable=SC2086
$CXX -o "$out/kfilterd" "$out/obj/kfilterd.o" "$out/obj/procs.o" "$out/obj/fanotify.o" "$out/obj/net.o" \
    "$out/obj/bpf_loader.o" "$out/obj/policy.o" "$out/obj/events.o" "$out/obj/match.o" -lpthread $BPF_LIBS
# The CPUID/RDTSC trap shim (`launch --trap-*`), per ELF class under ld.so's $LIB names. It declares
# the libc it uses, so i386 needs only the 32-bit libc runtime, which Wine's i386 side needs anyway.
for abi in 64:x86_64-linux-gnu 32:i386-linux-gnu; do
    libc=/lib/${abi#*:}/libc.so.6
    mkdir -p "$out/shim/lib/${abi#*:}"
    if [ -e "$libc" ] && $CC -m"${abi%%:*}" $FLAGS -fPIC -shared -nostdlib -ffreestanding -fno-stack-protector \
        -Wl,-z,defs linux/shim/kfshim.c "$libc" -o "$out/shim/lib/${abi#*:}/libkfshim.so"; then :
    else echo "trap shim: no ${abi#*:} build ($libc or $CC -m${abi%%:*} missing)" >&2; fi
done
$CXX -std=c++17 $FLAGS -c tool/linux_client.cpp -o "$out/obj/linux_client.o"
# simulate and evaluate decide through policy.c, as kfilterd does.
$CXX -std=c++17 $FLAGS tool/kfilterctl.cpp "$out/obj/linux_client.o" "$out/obj/policy.o" "$out/obj/match.o" -lpthread -o "$out/kfilterctl"
if [ "${1:-}" = tests ]; then
# The daemon's logic and socket protocol, checked without root (no fanotify marks).
$CXX -std=c++17 $FLAGS -DKFILTERD_NO_MAIN -c linux/kfilterd.cpp -o "$out/obj/kfilterd-nomain.o"
# shellcheck disable=SC2086
$CXX -std=c++17 $FLAGS tests/linux_daemon_test.cpp "$out/obj/kfilterd-nomain.o" "$out/obj/procs.o" \
    "$out/obj/fanotify.o" "$out/obj/net.o" "$out/obj/bpf_loader.o" "$out/obj/policy.o" "$out/obj/events.o" \
    "$out/obj/match.o" "$out/obj/linux_client.o" -lpthread $BPF_LIBS -o "$out/kfilterd-test"
# The action probe tests/linux_lsm_test.sh runs under `kfilterctl launch`, and its i386 rows (no C library needed).
$CC -O2 -Wall -o "$out/lsm-probe" tests/linux_lsm_probe.c
# launch's environment allowlist and trap-shim directory, the shim's CPUID answers (no trap armed), and
# the CPUID probe tests/linux_launch_test.sh runs natively and trapped.
$CXX -std=c++17 $FLAGS tests/linux_launch_env_test.cpp "$out/obj/linux_client.o" -o "$out/launch-test"
$CC -std=gnu11 $FLAGS tests/linux_shim_test.c -o "$out/shim-test"
$CC -O2 -Wall -o "$out/cpuid-probe" tests/linux_cpuid_probe.c
$CC -m32 -O2 -Wall -static -nostdlib -ffreestanding -fno-stack-protector -fno-pie -no-pie -o "$out/lsm-probe32" \
    tests/linux_lsm_probe32.c || echo "lsm-probe32: no i386 build ($CC -m32)" >&2
# The BPF test bench (../tests/bpf_bench.sh, root): the kernel layer again with its test programs
# (KB_TEST_BENCH), and the driver that decides with them under policies kfilterctl's parser reads.
if [ -n "$BPF_CFLAGS" ]; then
    "$CLANG" -g -O2 -target bpf -mcpu=v3 -D__TARGET_ARCH_x86 -DKB_TEST_BENCH -Wno-missing-declarations -I "$out/bpf" \
        -I "$LIBBPF_INCLUDE" -c linux/bpf/kfilter.bpf.c -o "$out/bpf/kfilter_bench.debug.o"
    "$BPFTOOL" gen object "$out/bpf/kfilter_bench.bpf.o" "$out/bpf/kfilter_bench.debug.o"
    $CXX -std=c++17 $FLAGS -c tests/linux_bpf_bench_policy.cpp -o "$out/obj/linux_bpf_bench_policy.o"
    # shellcheck disable=SC2086
    $CXX -std=c++17 $FLAGS $BPF_CFLAGS tests/linux_bpf_bench.cpp "$out/obj/linux_bpf_bench_policy.o" \
        "$out/obj/kfilterd-nomain.o" "$out/obj/procs.o" "$out/obj/fanotify.o" "$out/obj/net.o" "$out/obj/bpf_loader.o" \
        "$out/obj/policy.o" "$out/obj/events.o" "$out/obj/match.o" "$out/obj/linux_client.o" -lpthread $BPF_LIBS \
        -o "$out/kfilter-bpf-bench"
fi
fi

cp policy/linux-default-policy.txt policy/default-policy.txt policy/contain-policy.txt \
   policy/device-policy-snippet.txt linux/kfilterd.service "$out/"

echo
echo "Outputs:"
echo "  $out/kfilterd"
echo "  $out/kfilterctl"
echo "  $out/linux-default-policy.txt"
echo "  $out/kfilterd.service"
