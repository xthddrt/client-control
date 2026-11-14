#!/bin/sh
# Runtime check of kfilter under Wine (needs root and Wine 11 at /opt/wine-stable; stop any
# running kfilterd first): `sudo tests/linux_wine_test.sh` after ./build.sh tests.
#
# A throwaway Wine prefix, owned by the user who ran sudo, runs Wine's own reg.exe and
# cmd.exe, protected by their Windows names (`protect reg.exe`), started directly with
# `wine` (not through kfilterctl launch). It checks that kfilter decides what the Windows
# program does, not what Wine does for it:
#   - registry: a value-scoped deny (MachineGuid) refuses the query; an allowed value reads;
#     a key create under a denied key is refused; a counted deny (uses=1) refuses only the
#     first run; an image= rule for another program does not touch reg.exe;
#   - brokered files: `cmd /c type` of a denied file fails although wineserver, not cmd.exe,
#     opens it, and the event names cmd.exe with the brokered flag;
#   - audit mode: the denied query succeeds and is logged as would-deny for reg.exe;
#   - admission: with block-process-create, reg.exe started outside a launch is refused, and
#     admitted once through `kfilterctl allow-launch start.exe 1 30` (its creator under Wine);
#     `kfilterctl launch wine reg.exe` is admitted, `kfilterctl launch wine notepad.exe` is not;
#   - launch hiding and traps: 64- and 32-bit cmd.exe run under --hostname, --uname26,
#     --time-offset, --private-proc, --trap-cpuid and --trap-rdtsc, and both shim builds log;
#   - driver loads: winedevice's winebth.sys and wineusb.sys refused at a fresh wineserver's boot
#     (the default policy only audits them) are refused there (wineusb.sys loads first), slow the boot
#     by under 3 s and end no winedevice.exe but the one hosting wineusb with winebus (Wine 11 runs a
#     driver whose section it could not make executable, so that host ends: winebus 1067, winebth
#     never started); the services' states are printed for the default policy's choice;
#   - module=: cscript.exe's WinHttpRequest sends through a copy of winhttp.dll outside Wine's
#     install (its builtin marker renamed, so Wine loads it as a native DLL, as a game's own):
#     a send deny for module=winhttp.dll refuses it and names the caller; one for Wine's own
#     jscript.dll does not apply.
# The user's own prefixes are never touched.
set -u
cd "$(dirname "$0")/.."
bin=build/linux
wine=/opt/wine-stable/bin/wine
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 2; }
[ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ] || { echo "run with sudo from your user account"; exit 2; }
[ -x "$wine" ] || { echo "needs Wine at $wine"; exit 2; }
[ -x "$bin/kfilterd" ] || { echo "build first (./build.sh tests)"; exit 2; }
home=$(getent passwd "$SUDO_USER" | cut -d: -f6)
work=$(mktemp -d)
chmod 755 "$work"
prefix="$work/prefix"
log="$work/kfilterd.log"
fail=0

as_user() {
    runuser -u "$SUDO_USER" -- env HOME="$home" WINEPREFIX="$prefix" WINEDEBUG=-all \
        WINEDLLOVERRIDES='mscoree,mshtml=;winemenubuilder.exe=d' DISPLAY= WAYLAND_DISPLAY= "$@"
}

cleanup() {
    as_user /opt/wine-stable/bin/wineserver -k >/dev/null 2>&1
    "$bin/kfilterctl" off >/dev/null 2>&1
    [ -n "${server:-}" ] && kill "$server" 2>/dev/null
    [ -n "${daemon:-}" ] && kill "$daemon" 2>/dev/null && wait "$daemon" 2>/dev/null
    rm -rf "$work"
}
trap cleanup EXIT

echo "secret-contents" >"$work/secret.txt"
chmod 644 "$work/secret.txt"
mkdir -p "$prefix"
chown "$SUDO_USER" "$prefix"

rm -f /run/kfilter.sock
"$bin/kfilterd" 2>>"$log" &
daemon=$!
for _ in $(seq 1 60); do [ -S /run/kfilter.sock ] && break; sleep 0.5; done
"$bin/kfilterctl" status | grep -q 'registered:.*bpf' || { echo "FAIL: kfilterd did not attach the BPF layer"; tail -20 "$log"; exit 1; }

echo "creating a test Wine prefix (a minute or two)..."
as_user timeout 600 "$wine" wineboot -i >/dev/null 2>&1 || { echo "FAIL: wineboot"; exit 1; }
as_user /opt/wine-stable/bin/wineserver -p 600 >/dev/null 2>&1

policy() {   # $1 = mode, $2 = block-process-create on|off, $3 = extra rules
    cat >"$work/policy.txt" <<POLICY
mode $1
protect reg.exe
protect cmd.exe
protect cscript.exe
block-files on
block-registry on
block-process-create $2
block-network on
network-default allow
network-loopback off
${3:-}
deny|registry|\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Cryptography|value=MachineGuid
deny|registry|\\REGISTRY\\USER\\*\\Software\\KfilterTestDenied
deny|registry|\\REGISTRY\\USER\\*\\Software\\KfilterTest|value=Once|uses=1
deny|registry|\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion|value=CurrentBuild|image=cmd.exe
deny|file|$work/secret.txt
POLICY
    "$bin/kfilterctl" policy "$work/policy.txt" --no-track >/dev/null 2>&1 || { echo "FAIL $1: policy rejected"; fail=1; }
    "$bin/kfilterctl" clear >/dev/null 2>&1
}

reg() { as_user "$wine" reg.exe "$@" >"$work/out.txt" 2>&1; }
expect_fail() { if reg "$@"; then echo "FAIL: reg $* succeeded"; fail=1; fi; }
expect_ok() { reg "$@" || { echo "FAIL: reg $* failed: $(cat "$work/out.txt")"; fail=1; }; }
# Wine's reg.exe prints nothing (and exits 0) when reading a value fails: what matters is
# whether the value reached the program.
query() { reg query "$1" /v "$2"; grep -q "$2" "$work/out.txt"; }
expect_hidden() { if query "$@"; then echo "FAIL: reg query $* read the value"; fail=1; fi; }
expect_shown() { query "$@" || { echo "FAIL: reg query $* did not read the value: $(cat "$work/out.txt")"; fail=1; }; }

# A value nothing else reads, for the counted deny (Wine's start-up reads ProductName).
as_user "$wine" reg.exe add 'HKCU\Software\KfilterTest' /v Once /d one /f >/dev/null 2>&1
crypto='HKLM\Software\Microsoft\Cryptography'
# The "game DLL": winhttp.dll copied into the prefix, loaded for WinHttpRequest instead of
# Wine's own.
mkdir -p "$prefix/drive_c/kftest"
cp /opt/wine-stable/lib/wine/x86_64-windows/winhttp.dll "$prefix/drive_c/kftest/winhttp.dll"
marker=$(grep -boa 'Wine builtin DLL' "$prefix/drive_c/kftest/winhttp.dll" | head -1 | cut -d: -f1)
printf 'Kfilter test DLL' | dd of="$prefix/drive_c/kftest/winhttp.dll" bs=1 seek="$marker" conv=notrunc 2>/dev/null
chown -R "$SUDO_USER" "$prefix/drive_c/kftest"
as_user "$wine" reg.exe add 'HKCR\CLSID\{2087c2f4-2cef-4953-a8ab-66779b670495}\InprocServer32' /ve /d 'C:\kftest\winhttp.dll' /f >/dev/null 2>&1
hport=$((20000 + $$ % 20000))
# The pause lets kfilterd read the new module's code ranges (it does so within ~50 ms).
cat >"$work/get.js" <<JS
var r = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
WScript.Sleep(1000);
r.Open("GET", "http://127.0.0.1:$hport/", false);
try { r.Send(); WScript.Echo("status " + r.Status); } catch (e) { WScript.Echo("failed"); }
JS
chmod 644 "$work/get.js"
http() {
    as_user env WINEDLLOVERRIDES='mscoree,mshtml=;winemenubuilder.exe=d;winhttp=n' \
        "$wine" cscript.exe //nologo "Z:$(echo "$work/get.js" | tr / '\\')" 2>&1
}
version='HKLM\Software\Microsoft\Windows NT\CurrentVersion'

# Each Wine start logs about a thousand events: clear the ring before a step whose events
# are checked, and read it right after.
events() { "$bin/kfilterctl" watch 1; }
policy block off
"$bin/kfilterctl" clear >/dev/null 2>&1
expect_hidden "$crypto" MachineGuid
events | grep 'reg.exe' | grep 'deny ' | grep -i 'registry' | grep -qi 'Cryptography' ||
    { echo "FAIL: no registry deny event for reg.exe on Cryptography"; fail=1; }
expect_shown "$version" CurrentVersion
"$bin/kfilterctl" clear >/dev/null 2>&1
expect_fail add 'HKCU\Software\KfilterTestDenied' /v x /d y /f
events | grep 'deny ' | grep -i 'registry' | grep -qi 'KfilterTestDenied' ||
    { echo "FAIL: no registry deny event for the denied key"; fail=1; }
expect_hidden 'HKCU\Software\KfilterTest' Once
expect_shown 'HKCU\Software\KfilterTest' Once
expect_shown "$version" CurrentBuild
"$bin/kfilterctl" clear >/dev/null 2>&1
out=$(as_user "$wine" cmd.exe /c type "Z:$(echo "$work/secret.txt" | tr / '\\')" 2>&1)
echo "$out" | grep -q secret-contents && { echo "FAIL: cmd.exe read the denied file"; fail=1; }
events | grep 'cmd.exe(brokered)' | grep 'deny ' | grep -q 'secret.txt' ||
    { echo "FAIL: no brokered file deny event for cmd.exe"; fail=1; }

policy audit off
"$bin/kfilterctl" clear >/dev/null 2>&1
expect_shown "$crypto" MachineGuid
events | grep 'reg.exe' | grep 'audit ' | grep 'flags=0x1 ' | grep -qi 'Cryptography' ||
    { echo "FAIL audit: no would-deny event for reg.exe"; fail=1; }

runuser -u "$SUDO_USER" -- python3 -m http.server --bind 127.0.0.1 "$hport" >/dev/null 2>&1 &
server=$!
sleep 1
policy block off "deny|message|port=$hport|rights=send|module=WinHTTP.dll"
"$bin/kfilterctl" clear >/dev/null 2>&1
http | grep -q '^failed' || { echo "FAIL module: the send from winhttp.dll was not refused"; fail=1; }
events | grep 'cscript.exe' | grep 'deny ' | grep -q 'caller=winhttp.dll+0x' ||
    { echo "FAIL module: no send deny event naming caller=winhttp.dll"; fail=1; }
policy block off "deny|message|port=$hport|rights=send|module=jscript.dll
audit|message|port=$hport|rights=send"
"$bin/kfilterctl" clear >/dev/null 2>&1
http | grep -q '^status 200' || { echo "FAIL module: a deny for Wine's own jscript.dll refused the send"; fail=1; }
events | grep 'cscript.exe' | grep 'audit ' | grep -q 'caller=winhttp.dll+0x' ||
    { echo "FAIL module: no audit event naming caller=winhttp.dll"; fail=1; }
kill "$server" 2>/dev/null

# `wine reg.exe` starts reg.exe from Wine's start.exe: that is the creator the pass names.
policy block on
"$bin/kfilterctl" clear >/dev/null 2>&1
expect_hidden "$version" CurrentVersion
events | grep 'reg.exe' | grep 'deny ' | grep -q 'process' ||
    { echo "FAIL admission: no refused start for reg.exe"; fail=1; }
"$bin/kfilterctl" allow-launch start.exe 1 30 >/dev/null 2>&1 || { echo "FAIL admission: allow-launch"; fail=1; }
expect_shown "$version" CurrentVersion
expect_hidden "$version" CurrentVersion

# `kfilterctl launch wine reg.exe ...`: the loader is admitted for the protected program it
# runs (its first .exe argument), so reg.exe needs no pass; a loader asked to run an
# unprotected program is refused before it execs.
launch() {
    env HOME="$home" WINEPREFIX="$prefix" WINEDEBUG=-all WINEDLLOVERRIDES='mscoree,mshtml=;winemenubuilder.exe=d' \
        DISPLAY= WAYLAND_DISPLAY= "$bin/kfilterctl" launch "$wine" "$@" >"$work/out.txt" 2>&1
}
launch reg.exe query "$version" /v CurrentVersion
grep -q CurrentVersion "$work/out.txt" || { echo "FAIL launch: wine reg.exe not admitted: $(cat "$work/out.txt")"; fail=1; }
if launch notepad.exe || ! grep -q 'ADMIT_PROCESS failed' "$work/out.txt"; then
    echo "FAIL launch: wine admitted for an unprotected program"; fail=1
fi

# The launch's hiding and trap options under Wine: 64-bit and 32-bit cmd.exe (an i386 process here)
# run with their own host name, a 2.6 uname, shifted uptime, a private /proc, and CPUID and RDTSC
# faulting answered by the shim, whose two builds both log. wineserver starts inside, so stop it first.
as_user /opt/wine-stable/bin/wineserver -k >/dev/null 2>&1
mkdir "$work/trap"
chown "$SUDO_USER" "$work/trap"
for cmd in cmd.exe 'C:\windows\syswow64\cmd.exe'; do
    launch "$cmd" /c exit 7 --hostname kf-wine --uname26 --time-offset 864000 --private-proc --trap-cpuid \
        --trap-rdtsc --trap-log "$work/trap/trap.log"
    [ $? = 7 ] || { printf 'FAIL hiding: %s under the launch options: %s\n' "$cmd" "$(cat "$work/out.txt")"; fail=1; }
    sed -n 's|^launched .* shim=\(/tmp/kfshim\.[^ /]*\)$|\1|p' "$work/out.txt" >>"$work/shims"
done
for want in 'bits=64 insn=cpuid' 'bits=32 insn=cpuid' 'insn=rdtsc'; do
    grep -q "$want" "$work/trap/trap.log" 2>/dev/null || { echo "FAIL trap shim under Wine: no '$want'"; fail=1; }
done
as_user /opt/wine-stable/bin/wineserver -k >/dev/null 2>&1
while read -r dir; do rm -rf "$dir"; done <"$work/shims"

# Driver loads refused at boot: a fresh, persistent wineserver whose winedevice.exe start their drivers
# under the policy; the milliseconds `cmd /c exit` takes and the winedevice.exe left running (all but the
# refused drivers' host, which Wine 11 ends: it calls a driver whose section mprotect to execute was refused).
boot() {
    as_user /opt/wine-stable/bin/wineserver -k >/dev/null 2>&1
    policy block off "$1"
    as_user /opt/wine-stable/bin/wineserver -p 600 >/dev/null 2>&1
    begin=$(date +%s%N)
    as_user "$wine" cmd.exe /c exit 0 >/dev/null 2>&1
    sleep 5   # services.exe starts the drivers' hosts after the boot
    echo "$(( ($(date +%s%N) - begin) / 1000000 - 5000 )) $(pgrep -c -u "$SUDO_USER" -x winedevice.exe)"
}
# shellcheck disable=SC2046
set -- $(boot '')
quick=$1 hosts=$2
# shellcheck disable=SC2046
set -- $(boot 'deny|file|/*/winebth.sys|rights=execute|image=winedevice.exe
deny|file|/*/wineusb.sys|rights=execute|image=winedevice.exe')
"$bin/kfilterctl" watch 1 | grep 'winedevice.exe' | grep 'deny ' | grep -E -q '/(winebth|wineusb)\.sys$' ||
    { echo "FAIL driver deny: no refusal of winedevice's winebth.sys or wineusb.sys"; fail=1; }
[ "$1" -le $((quick + 3000)) ] || { echo "FAIL driver deny: the boot took $1 ms, $quick without"; fail=1; }
[ "$2" -ge $((hosts - 1)) ] || { echo "FAIL driver deny: $2 winedevice.exe running, $hosts without"; fail=1; }
echo "driver deny: $2 winedevice.exe running, $hosts without"
for service in winebth wineusb winebus winehid; do
    echo "driver deny: $service: $(as_user "$wine" sc query "$service" 2>&1 | grep -i 'state\|exit_code' | tr -s ' \r\n' ' ')"
done
as_user /opt/wine-stable/bin/wineserver -k >/dev/null 2>&1

[ "$fail" = 0 ] && echo "linux wine test: PASS" || { tail -20 "$log"; echo "linux wine test: FAIL"; }
exit "$fail"
