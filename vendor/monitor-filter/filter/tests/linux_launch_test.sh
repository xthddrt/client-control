#!/bin/sh
# Runtime check of kfilterd + kfilterctl launch (the plan's audit/block check).
# Needs root: `sudo tests/linux_launch_test.sh` after ./build.sh tests. It starts its own
# kfilterd, so stop any running one first. A fanotify denial reaches the client as
# EPERM ("Operation not permitted").
set -u
cd "$(dirname "$0")/.."
bin=build/linux
policy=$(mktemp)
log=$(mktemp)
launched=$(mktemp)   # trapped launches' "launched ... shim=DIR" lines: those directories are removed at the end
fail=0
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 2; }

"$bin/kfilterd" 2>"$log" &
daemon=$!
# Verifying the BPF layer takes several seconds before the socket appears.
for _ in $(seq 1 120); do [ -S /run/kfilter.sock ] && break; sleep 0.5; done

write_policy() {
    cat >"$policy" <<EOF
mode $1
protect /cat
protect /lsm-probe
protect /cpuid-probe
protect MapleStory.exe
block-files on
deny|file|/etc/hostname
deny|system|/system/arch_prctl/0x1012/1
EOF
}

write_policy audit
"$bin/kfilterctl" policy "$policy" --no-track || fail=1
"$bin/kfilterctl" clear
"$bin/kfilterctl" launch /bin/cat /etc/hostname >/dev/null || { echo "FAIL audit mode blocked the read"; fail=1; }
"$bin/kfilterctl" watch 1 | grep -q 'audit .*flags=0x1 .*/etc/hostname' || { echo "FAIL no WOULD_DENY event"; fail=1; }

write_policy block
"$bin/kfilterctl" policy "$policy" --no-track || fail=1
if "$bin/kfilterctl" launch /bin/cat /etc/hostname >/dev/null 2>&1; then
    echo "FAIL block mode allowed the read"; fail=1
fi
"$bin/kfilterctl" launch /bin/cat /etc/os-release >/dev/null || { echo "FAIL block mode denied an unlisted file"; fail=1; }
# A protected name started outside the launcher is tracked too (as on Windows when
# block-process-create is off), so a plain cat is held to the same rule.
if /bin/cat /etc/hostname >/dev/null 2>&1; then echo "FAIL a protected image outside launch escaped"; fail=1; fi

# The client's environment is the allowlist: sudo's variables (SUDO_COMMAND spells out this launch), the
# old trap variable and the rest stay behind; the session's, Wine's and --keep-env's reach it.
env=$(SUDO_COMMAND="$PWD/$bin/kfilterctl launch" KFILTER_TRAP=cpuid MAIL=/var/mail/x DISPLAY=:9 LANG=C.UTF-8 \
      WINEPREFIX=/tmp/kf-prefix KF_EXTRA_ONE=1 "$bin/kfilterctl" launch /bin/cat /proc/self/environ \
      --keep-env 'KF_EXTRA_*' 2>/dev/null | tr '\0' '\n')
echo "$env" | grep -q '^SUDO_\|^KFILTER_TRAP=\|^MAIL=' && { echo "FAIL the client's environment kept: $env"; fail=1; }
for want in 'DISPLAY=:9' 'LANG=C.UTF-8' 'WINEPREFIX=/tmp/kf-prefix' 'KF_EXTRA_ONE=1' 'HOME=/.*' 'PATH=.*'; do
    echo "$env" | grep -qx -- "$want" || { echo "FAIL the client's environment lacks $want: $env"; fail=1; }
done
# The trap shim's configuration reaches the client beside its preload path, never in its environment,
# and its maps show the directory's copy of the shim, not the build's path.
env=$("$bin/kfilterctl" launch /bin/cat /proc/self/environ --trap-rdtsc 2>>"$launched" | tr '\0' '\n')
shimdir=$(echo "$env" | sed -n 's|^LD_PRELOAD=\(/tmp/kfshim\.[^/]*\)/\$LIB/libkfshim\.so$|\1|p')
{ [ -n "$shimdir" ] && [ "$(cat "$shimdir/config")" = rdtsc ] && ! echo "$env" | grep -q 'KFILTER_TRAP\|rdtsc'; } ||
    { echo "FAIL the trap configuration: LD_PRELOAD dir '$shimdir', environment: $env"; fail=1; }
grep -q " shim=$shimdir\$" "$launched" || { echo "FAIL launch did not name the shim directory: $(cat "$launched")"; fail=1; }
maps=$("$bin/kfilterctl" launch /bin/cat /proc/self/maps --trap-rdtsc 2>>"$launched")
echo "$maps" | grep -q '/tmp/kfshim\.[^/]*/lib/x86_64-linux-gnu/libkfshim\.so' && ! echo "$maps" | grep -q "$PWD" ||
    { echo "FAIL the trapped client's maps: $maps"; fail=1; }

# Trapped CPUID is what the hardware answers, under the arch_prctl deny (the shim never untraps): the
# leaves that differ between cores from the core the thread runs on, the leaves past each range by the
# vendor's rule (needs cpuid_fault).
if grep -qw cpuid_fault /proc/cpuinfo; then
    "$bin/kfilterctl" clear
    native=$("$bin/cpuid-probe")
    trapped=$("$bin/kfilterctl" launch "$bin/cpuid-probe" --trap-cpuid 2>>"$launched")
    [ -n "$native" ] && [ "$native" = "$trapped" ] ||
        { echo "FAIL trapped CPUID differs from the hardware's:"; echo "$native"; echo "trapped:"; echo "$trapped"; fail=1; }
    "$bin/kfilterctl" watch 1 | grep -q 'arch_prctl/0x1012/1' && { echo "FAIL the trapped probe tried to untrap"; fail=1; }
fi

# Hiding and containment: the client sees its own host name, a 2.6 release, uptime 10 days ahead,
# the root of a cgroup namespace and no /proc/1; the trap shim masks the CPUID brand string and logs
# each leaf and RDTSC; the arch_prctl rule keeps CPUID faulting on. --user runs a dedicated account.
trapdir=$(mktemp -d)
chmod 777 "$trapdir"
before=$(cut -d. -f1 /proc/uptime)
out=$("$bin/kfilterctl" launch "$bin/lsm-probe" identity --hostname kf-test --uname26 --time-offset 864000 \
      --private-proc --trap-rdtsc --cpuid-mask 0x80000002-0x80000004 --trap-log "$trapdir/trap.log" 2>&1)
echo "$out" >>"$launched"
for want in 'nodename=kf-test ' 'release=2\.6\.' 'cgroup=0::/ cgroupfs=own ' 'pid1=hidden' 'brand=$' 'cpuid_untrap=denied'; do
    echo "$out" | grep -q -- "$want" || { echo "FAIL launch hiding: no '$want' in: $out"; fail=1; }
done
uptime=$(echo "$out" | sed -n 's/.* uptime=\([0-9]*\) .*/\1/p')
[ "${uptime:-0}" -ge $((before + 864000)) ] || { echo "FAIL --time-offset: uptime ${uptime:-?}, host $before"; fail=1; }
grep -q 'bits=64 insn=cpuid leaf=0x80000003 subleaf=0x0 masked=1 first' "$trapdir/trap.log" &&
    grep -q 'insn=rdtsc count=3$' "$trapdir/trap.log" || { echo "FAIL trap log:"; cat "$trapdir/trap.log"; fail=1; }
cp "$bin/lsm-probe" "$trapdir/lsm-probe"
chmod 755 "$trapdir/lsm-probe"
"$bin/kfilterctl" launch "$trapdir/lsm-probe" identity --user nobody --private-proc 2>&1 |
    grep -q "uid=$(id -u nobody) .*pid1=hidden" || { echo "FAIL --user nobody"; fail=1; }
# The --user account need not read the build's shim: launch preloads its own copy.
mkdir -m 700 "$trapdir/shim" && cp -r "$bin/shim/lib" "$trapdir/shim/" && cp "$bin/kfilterctl" "$trapdir/"
out=$("$trapdir/kfilterctl" launch "$trapdir/lsm-probe" identity --user nobody --trap-rdtsc --trap-log "$trapdir/nobody.log" 2>&1)
echo "$out" >>"$launched"
echo "$out" | grep -q "uid=$(id -u nobody) " && grep -q 'insn=rdtsc' "$trapdir/nobody.log" ||
    { echo "FAIL --user nobody with a build shim it cannot read: $out"; fail=1; }
rm -rf "$trapdir"

# A Wine loader (a stand-in named wine) or a script that runs one is admitted for the
# protected Windows program it is asked to run, and only then.
fake=$(mktemp -d)
chmod 755 "$fake"
cp /bin/true "$fake/wine"
printf '#!/bin/sh\nexec "%s/wine" start MapleStory.exe\n' "$fake" >"$fake/nexon-launcher"
printf '#!/bin/sh\nexec "%s/wine" notepad.exe\n' "$fake" >"$fake/other-launcher"
chmod 755 "$fake/wine" "$fake/nexon-launcher" "$fake/other-launcher"
admitted() { "$bin/kfilterctl" launch "$@" >/dev/null 2>"$fake/err" && ! grep -q ADMIT_PROCESS "$fake/err"; }
admitted "$fake/wine" 'C:\Nexon\Library\maplestorycw\MapleStory.exe' || { echo "FAIL wine refused for a protected program"; fail=1; }
admitted "$fake/nexon-launcher" --program 'C:\Nexon\Library\maplestorycw\MapleStory.exe' ||
    { echo "FAIL launcher script refused for a protected program"; fail=1; }
admitted "$fake/wine" 'C:\windows\notepad.exe' && { echo "FAIL wine admitted for an unprotected program"; fail=1; }
admitted "$fake/nexon-launcher" || { echo "FAIL launcher script refused for the protected program it names"; fail=1; }
admitted "$fake/other-launcher" && { echo "FAIL launcher script admitted for an unprotected program"; fail=1; }
admitted /bin/true --program 'C:\Nexon\Library\maplestorycw\MapleStory.exe' &&
    { echo "FAIL a plain binary admitted as a loader"; fail=1; }
rm -rf "$fake"

# Fail closed: block mode outlives kfilterd (pinned BPF links), a restarted kfilterd adopts
# the saved policy, and only `kfilterctl stop` ends it.
kill "$daemon"
wait "$daemon"
if /bin/cat /etc/hostname >/dev/null 2>&1; then echo "FAIL block mode ended with kfilterd"; fail=1; fi
"$bin/kfilterd" 2>>"$log" &
daemon=$!
for _ in $(seq 1 120); do [ -S /run/kfilter.sock ] && break; sleep 0.5; done
"$bin/kfilterctl" status | grep -q '^mode: *block' || { echo "FAIL restarted kfilterd did not adopt block mode"; fail=1; }
"$bin/kfilterctl" stop >/dev/null || { echo "FAIL kfilterctl stop"; fail=1; }
wait "$daemon"
/bin/cat /etc/hostname >/dev/null 2>&1 || { echo "FAIL enforcement outlived kfilterctl stop"; fail=1; }
rm -f "$policy"
sed -n 's|^launched .* shim=\(/tmp/kfshim\.[^ /]*\)$|\1|p' "$launched" | while read -r dir; do rm -rf "$dir"; done
rm -f "$launched"
[ "$fail" = 0 ] && echo "linux launch test: PASS" || { cat "$log"; echo "linux launch test: FAIL"; }
rm -f "$log"
exit "$fail"
