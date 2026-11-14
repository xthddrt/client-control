#!/usr/bin/env bash
# Linux build (see docs/LINUX.md): the agent with its in-process sensors into build/linux/.
# `build.sh tests` also builds the test binaries (tests/run_offline.sh runs them).
set -euo pipefail
root="$(cd "$(dirname "$0")" && pwd)"
cd "$root"
out=build/linux
mkdir -p "$out" build/tests
cxx="${CXX:-g++}"
flags=(-std=c++17 -O2 -Wall -Wextra -pthread)
shared=(agent/telemetry.cpp agent/classify.cpp agent/integrations.cpp agent/rpc_names.cpp agent/etw.cpp
        agent/linux/etw_stub.cpp agent/linux/platform.cpp)
sensors=(agent/linux/session.cpp agent/linux/fanotify.cpp agent/linux/proc_connector.cpp
         agent/linux/images.cpp agent/linux/net.cpp agent/linux/bpf.cpp
         agent/linux/pe.cpp agent/linux/dns.cpp agent/linux/packets.cpp agent/linux/wineserver.cpp agent/linux/watch.cpp)

# eBPF preflight: clang (CLANG=), bpftool (BPFTOOL=), libbpf headers (LIBBPF_INCLUDE=) and the
# running kernel's BTF. Without them the agent is built without its kernel sensors and falls back
# to fanotify, the proc connector and /proc polling.
clang="${CLANG:-$(command -v clang-18 || command -v clang || true)}"
bpftool="${BPFTOOL:-$(command -v bpftool || { [ -x /usr/sbin/bpftool ] && echo /usr/sbin/bpftool; } || true)}"
libbpf_include="${LIBBPF_INCLUDE:-/usr/include}"
bpf_flags=()
if [ -n "$clang" ] && [ -n "$bpftool" ] && [ -f "$libbpf_include/bpf/libbpf.h" ] && [ -r /sys/kernel/btf/vmlinux ]; then
    mkdir -p "$out/bpf"
    "$bpftool" btf dump file /sys/kernel/btf/vmlinux format c > "$out/bpf/vmlinux.h"
    # The sensors' object, and the watchpoints' (loaded only with --watch).
    for object in monitor:kMonitorBpfObject watch:kWatchBpfObject; do
        name=${object%%:*}
        "$clang" -g -O2 -target bpf -D__TARGET_ARCH_x86 -Wno-missing-declarations -I "$out/bpf" -I "$libbpf_include" \
            -c "agent/linux/bpf/$name.bpf.c" -o "$out/bpf/$name.debug.o"
        "$bpftool" gen object "$out/bpf/$name.bpf.o" "$out/bpf/$name.debug.o"
        python3 - "$out/bpf/$name.bpf.o" "$out/bpf/${name}_bpf_object.h" "${object#*:}" <<'PY'
import sys
data = open(sys.argv[1], "rb").read()
rows = ",\n".join(",".join(str(b) for b in data[i:i + 32]) for i in range(0, len(data), 32))
open(sys.argv[2], "w").write("static const unsigned char " + sys.argv[3] + "[] = {\n" + rows + "\n};\n")
PY
    done
    if [ -e /usr/lib/x86_64-linux-gnu/libbpf.so ] || [ -n "${LIBBPF_LIB:-}" ]; then libbpf_link="${LIBBPF_LIB:--lbpf}"; else libbpf_link=-l:libbpf.so.1; fi
    bpf_flags=(-DMSMON_BPF -I "$out/bpf" -I "$libbpf_include" "$libbpf_link")
    echo "eBPF sensors: built ($out/bpf/monitor.bpf.o, $out/bpf/watch.bpf.o)"
else
    echo "eBPF sensors: NOT built (need clang, bpftool, libbpf headers and /sys/kernel/btf/vmlinux):" >&2
    echo "  sudo apt install clang-18 libbpf-dev linux-tools-common linux-tools-\$(uname -r)" >&2
fi

"$cxx" "${flags[@]}" -o "$out/msmon-agent" agent/agent.cpp "${shared[@]}" "${sensors[@]}" "${bpf_flags[@]}"
[ "${1:-}" = tests ] || { echo "built: $out/msmon-agent"; exit 0; }

# Test binaries (tests/run_offline.sh runs the offline ones; the root tests use the probes).
# The action probe tests/linux_ebpf_test.sh runs as root, and the load tests/linux_budget_test.sh measures.
"${CC:-gcc}" -O2 -Wall -pthread -o "$out/linux_ebpf_probe" tests/fixtures/linux_ebpf_probe.c -ldl
"${CC:-gcc}" -O2 -Wall -shared -fPIC -o "$out/libmsmonprobe.so" tests/fixtures/probe_lib.c
"${CC:-gcc}" -O2 -Wall -pthread -no-pie -o "$out/budget_probe" tests/fixtures/budget_probe.c   # -no-pie: nm gives its --watch addresses
"${CC:-gcc}" -O2 -Wall -pthread -o "$out/watch_probe" tests/fixtures/watch_probe.c   # tests/linux_watch_test.sh
"$cxx" "${flags[@]}" -o "$out/integration_regression" tests/integration_regression.cpp "${shared[@]}"
"$cxx" "${flags[@]}" -o "$out/linux_pe_test" tests/linux_pe_test.cpp agent/linux/pe.cpp
"$cxx" "${flags[@]}" -o "$out/linux_packets_test" tests/linux_packets_test.cpp agent/linux/packets.cpp "${shared[@]}"
"$cxx" "${flags[@]}" -o "$out/wineserver_test" tests/wineserver_test.cpp agent/linux/wineserver.cpp "${shared[@]}"
"$cxx" "${flags[@]}" -o "$out/linux_sysagg_test" tests/linux_sysagg_test.cpp
"$cxx" "${flags[@]}" -o "$out/linux_unix_test" tests/linux_unix_test.cpp agent/rpc_names.cpp
"$cxx" "${flags[@]}" -o "$out/linux_watch_test" tests/linux_watch_test.cpp agent/linux/pe.cpp "${shared[@]}"
# Freestanding probes (no 32-bit libc needed): the fake Wine clients tests/ebpf_checks/wineserver.sh runs and
# the ia32 probe tests/ebpf_checks/parity.sh runs.
fake=(-O2 -Wall -static -nostdlib -ffreestanding -fno-stack-protector -fno-pie -no-pie)
"${CC:-gcc}" "${fake[@]}" -o "$out/ws_fake_client" tests/fixtures/ws_fake_client.c
"${CC:-gcc}" -m32 "${fake[@]}" -o "$out/ws_fake_client32" tests/fixtures/ws_fake_client.c 2>/dev/null ||
    { rm -f "$out/ws_fake_client32"; echo "ws_fake_client32: not built (gcc -m32 failed); the root test skips the ia32 client"; }
"${CC:-gcc}" -m32 "${fake[@]}" -o "$out/ia32_probe" tests/fixtures/ia32_probe.c 2>/dev/null ||
    { rm -f "$out/ia32_probe"; echo "ia32_probe: not built (gcc -m32 failed); the root test skips the ia32 checks"; }
echo "built: $out/msmon-agent and the test binaries"
