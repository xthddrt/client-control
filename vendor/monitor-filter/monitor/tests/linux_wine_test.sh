#!/bin/sh
# End-to-end check with real Wine (root only; run in a VM: `sudo tests/linux_wine_test.sh` after ./build.sh tests).
# A fresh temporary WINEPREFIX owned by the invoking user ($SUDO_USER) is initialised, copies of Wine's
# reg.exe, tasklist.exe, sc.exe and wmic.exe go into a scope directory, and the agent records `reg query`,
# `reg add`, `tasklist`, `sc query` (RPC to services.exe over the svcctl pipe) and `wmic` (in-process WMI)
# run there, plus the prefix's winedevice.exe loading its builtin drivers. The prefix is booted before the agent
# starts (as a running Nexon Launcher's is): its winedevice.exe joins late, so its drivers are reconstructed
# (reconstructed=1) and its IRPs still name their driver; services.exe (and plugplay.exe, rpcss.exe, explorer.exe and
# svchost.exe, the other RPC brokers) joins as a broker, so the winedevice.exe
# that `sc start http` makes afterwards is tracked from fork (and services.exe's new_process request for it is
# decoded: image and Windows command line). Every Wine command runs as $SUDO_USER, never as root. The log must verify and hold
# the wineserver-decoded registry and process-enumeration records of those processes, PE frames in their
# modules, and the decoder's coverage notes. Function probes (uprobes group): cscript.exe fetches https from a local
# TLS server through WinHTTP and schannel (x64 and the 32-bit syswow64 copy), whose GnuTLS plaintext must be
# tls_plaintext payloads; rundll32 user32.dll,GetAsyncKeyState gives a system:NtUserGetAsyncKeyState record with
# rundll32.exe in its PE frames; tasklist's NtQuerySystemInformation(SystemProcessInformation) and wmic's WQL
# (IWbemServices::ExecQuery) are recorded. Every wineserver request: none of Wine's own request-pipe writes is
# rejected (ws_rejected 0), select is a kernel aggregate, and tests/fixtures/ws_wine_probe.c's VirtualAlloc and
# PAGE_NOACCESS page are in anonymous-memory summaries with their range, its three VirtualQuery each a
# system:NtQueryVirtualMemory record of its page (a fourth on the first page none), its walk of 256 pages at most 64
# records a second and kernel summaries for the rest, a copy of it loaded as a library and freed an unmap_view with
# image_unload=1, its PostMessage to another process's window (the prefix uses the null graphics driver) a
# send_message naming that process. The agent runs with --window-probes: the probe's GetWindowLongA of the peer's window
# (by its whole handle, its low word, and its low word with 0xffff as high word) are NtUserCallHwndParam records naming
# the peer, its PostMessage an NtUserPostMessage record naming it, and its 100000 GetWindowLongA of its own window none;
# their time per call, run once before the agent starts (no probes) and once under it, is the window probes' cost
# per call (printed: the figure for turning them on by default). The prefix and its wineserver are removed at the end.
# WINE_ROOT (default /opt/wine-stable) points at another Wine 11.0 install.
set -u
cd "$(dirname "$0")/.."
[ "$(id -u)" = 0 ] || { echo "run as root (sudo)"; exit 2; }
user=${SUDO_USER:-}
[ -n "$user" ] && [ "$user" != root ] || { echo "run through sudo from a normal user: Wine never runs as root here"; exit 2; }
wine_root=${WINE_ROOT:-/opt/wine-stable}
[ -x "$wine_root/bin/wine" ] || { echo "no Wine at $wine_root (set WINE_ROOT)"; exit 2; }
[ -x build/linux/msmon-agent ] || { echo "build first (./build.sh tests)"; exit 2; }

work=$(runuser -u "$user" -- mktemp -d /tmp/msmon-wine.XXXXXX) || exit 2
prefix=$work/prefix
scope=$work/scope
out=$work/out
agent=
tls=
# A clean environment: no DISPLAY (no window), no Mono/Gecko prompts, nothing in the user's real HOME.
runw() {
    runuser -u "$user" -- env -i HOME="$work/home" USER="$user" PATH="$wine_root/bin:/usr/bin:/bin" \
        WINEPREFIX="$prefix" WINEDEBUG=-all WINEDLLOVERRIDES="mscoree=;mshtml=;winemenubuilder.exe=d" "$@"
}
cleanup() {
    [ -n "$agent" ] && kill "$agent" 2>/dev/null
    [ -n "$tls" ] && kill "$tls" 2>/dev/null
    runw timeout 30 wineserver -k >/dev/null 2>&1
    if [ -n "${MSMON_KEEP_WORK:-}" ]; then echo "kept $work"; else rm -rf "$work"; fi
}
trap cleanup EXIT
fail=0

runw mkdir -p "$work/home" "$scope"
mkdir -p "$out"
if ! runw timeout 600 wineboot -i >"$work/wineboot.log" 2>&1 || ! runw timeout 120 wineserver -w ||
    [ ! -f "$prefix/system.reg" ]; then
    echo "FAIL: wineboot -i did not create $prefix"; tail -n 20 "$work/wineboot.log"; exit 1
fi
# Windows without a display: the null driver (ws_wine_probe.exe's peer makes a window).
runw timeout 120 wine reg.exe add 'HKCU\Software\Wine\Drivers' /v Graphics /d null /f >/dev/null 2>&1 &&
    runw timeout 120 wineserver -w || { echo "FAIL: cannot select the null graphics driver"; exit 1; }
# Wine swaps a file carrying the "Wine builtin DLL" signature (DOS stub, offset 0x40) for its own copy in
# lib/wine, so the process would map nothing under the scope. Overwriting the signature makes Wine load
# the scope copy as a native PE; the code is unchanged.
for exe in reg.exe tasklist.exe sc.exe wmic.exe; do
    runw cp "$wine_root/lib/wine/x86_64-windows/$exe" "$scope/$exe" &&
        printf 'msmon test copy\0' | runw dd of="$scope/$exe" bs=1 seek=64 conv=notrunc status=none &&
        runw chmod +x "$scope/$exe" ||
        { echo "FAIL: cannot copy $exe into the scope"; exit 1; }
done
# The wineserver rows' Windows probe (tests/fixtures/ws_wine_probe.c), linked against Wine's import libraries.
clang=$(command -v clang-18 || command -v clang || true)
wlib=$wine_root/lib/wine/x86_64-windows
if [ -n "$clang" ] && ld -V 2>/dev/null | grep -q i386pep &&
    "$clang" -target x86_64-w64-windows-gnu -O2 -ffreestanding -fno-stack-protector -fno-builtin \
        -c tests/fixtures/ws_wine_probe.c -o "$work/ws_wine_probe.o" &&
    ld -m i386pep --subsystem console -e start -o "$work/ws_wine_probe.exe" "$work/ws_wine_probe.o" \
        "$wlib/libkernel32.a" "$wlib/libuser32.a" && chmod 755 "$work/ws_wine_probe.exe" &&
    runw cp "$work/ws_wine_probe.exe" "$scope/ws_wine_probe.exe"; then
    wsprobe=1
else
    wsprobe=0
    echo "SKIP: ws_wine_probe.exe not built (needs clang and ld -m i386pep): its memory and window message rows"
fi

# The prefix runs before the agent starts: a persistent wineserver, and the first Wine command boots its services
# (wineboot, services.exe, winedevice.exe loading mountmgr.sys and the other builtin drivers). The agent's prefix
# poll then finds services.exe and winedevice.exe after all of that. reg query still starts from a tracked
# launcher in the scope (the eBPF probe's --exec). A subdirectory: the agent takes the first executable directly
# under the scope root for the client.
runw mkdir -p "$scope/bin" && runw cp build/linux/linux_ebpf_probe "$scope/bin/launcher" ||
    { echo "FAIL: cannot copy the launcher into the scope"; exit 1; }
runw wineserver -p 600 && runw timeout 120 wine cmd /c exit >"$work/boot.log" 2>&1 ||
    { echo "FAIL: cannot boot the prefix before the agent"; cat "$work/boot.log"; exit 1; }
# The window probes' baseline: 100000 GetWindowLongA of the probe's own window with no probe attached.
[ "$wsprobe" = 1 ] && runw timeout 120 wine "$scope/ws_wine_probe.exe" bench >"$out/bench.txt" 2>&1
# --max-file-mb 0: one events.jsonl (the check reads only it); the ia32 Wine loaders alone write tens of MB.
build/linux/msmon-agent --scope-root "$scope" --prefix "$prefix" --output "$out/events.jsonl" --stop-file "$out/stop" \
    --max-file-mb 0 --wait-ms 100 --no-etw --window-probes >"$out/agent.log" 2>&1 &
agent=$!
for _ in $(seq 1 60); do grep -q Registered "$out/agent.log" && break; sleep 0.5; done
grep -q Registered "$out/agent.log" || { echo "FAIL: the agent did not register"; tail -n 40 "$out/agent.log"; exit 1; }

runw timeout 120 "$scope/bin/launcher" --exec wine "$scope/reg.exe" query 'HKLM\Software\Microsoft\Windows NT\CurrentVersion' /v ProductName \
    >"$out/query.txt" 2>&1 || { echo "FAIL: reg query exited $?"; cat "$out/query.txt"; fail=1; }
runw timeout 120 wine "$scope/reg.exe" add 'HKCU\Software\MsmonTest' /v probe /d hello /f >"$out/add.txt" 2>&1 ||
    { echo "FAIL: reg add exited $?"; cat "$out/add.txt"; fail=1; }
runw timeout 120 wine "$scope/tasklist.exe" >"$out/tasklist.txt" 2>&1 ||
    { echo "FAIL: tasklist exited $?"; cat "$out/tasklist.txt"; fail=1; }
runw timeout 120 wine "$scope/sc.exe" query eventlog >"$out/sc.txt" 2>&1 ||
    { echo "FAIL: sc query exited $?"; cat "$out/sc.txt"; fail=1; }
runw timeout 120 wine "$scope/wmic.exe" bios get serialnumber >"$out/wmic.txt" 2>&1 ||
    { echo "FAIL: wmic exited $?"; cat "$out/wmic.txt"; fail=1; }
# TLS through Wine's schannel (secur32.so -> libgnutls) to a local server with a self-signed certificate (ignored by
# SslErrorIgnoreFlags): the request and the reply in plaintext. The server sends Content-Length, so no read waits.
runw openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/tls.key" -out "$work/tls.crt" -days 1 -subj /CN=localhost \
    >/dev/null 2>&1 || { echo "FAIL: openssl req"; fail=1; }
python3 - "$work" <<'PY' &
import http.server, ssl, sys
class Reply(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "15")
        self.end_headers()
        self.wfile.write(b"msmon-tls-reply")
    def log_message(self, *args):
        pass
server = http.server.HTTPServer(("127.0.0.1", 0), Reply)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(sys.argv[1] + "/tls.crt", sys.argv[1] + "/tls.key")
server.socket = context.wrap_socket(server.socket, server_side=True)
open(sys.argv[1] + "/tls.port", "w").write(str(server.server_address[1]))
server.serve_forever()
PY
tls=$!
for _ in $(seq 1 20); do [ -s "$work/tls.port" ] && break; sleep 0.5; done
port=$(cat "$work/tls.port" 2>/dev/null)
printf '%s\r\n' 'var r = new ActiveXObject("WinHttp.WinHttpRequest.5.1");' 'r.SetTimeouts(10000, 10000, 10000, 10000);' \
    'r.Open("GET", WScript.Arguments(0), false);' 'r.Option(4) = 0x3300;' 'r.Send();' 'WScript.Echo(r.Status + " " + r.ResponseText);' |
    runw tee "$prefix/drive_c/msmon-tls.js" >/dev/null
for cscript in cscript 'C:\windows\syswow64\cscript.exe'; do
    runw timeout 120 "$scope/bin/launcher" --exec wine "$cscript" //nologo 'C:\msmon-tls.js' "https://127.0.0.1:$port/msmon-tls" \
        >>"$out/tls.txt" 2>&1 || { echo "FAIL: $cscript https exited $?"; cat "$out/tls.txt"; fail=1; }
done
grep -c "200 msmon-tls-reply" "$out/tls.txt" | grep -qx 2 || { echo "FAIL: cscript did not fetch over TLS twice"; cat "$out/tls.txt"; fail=1; }
# A Windows-level call Wine answers from shared memory (no syscall, no wineserver request).
runw timeout 120 "$scope/bin/launcher" --exec wine rundll32 user32.dll,GetAsyncKeyState >"$out/rundll32.txt" 2>&1 ||
    { echo "FAIL: rundll32 exited $?"; cat "$out/rundll32.txt"; fail=1; }
# Anonymous memory (VirtualAlloc read-write, VirtualProtect PAGE_NOACCESS: kernel aggregates with their range), three
# VirtualQuery (each address its record), a library loaded and freed (an image unload) and a message posted to another
# process's window (send_message naming that process).
if [ "$wsprobe" = 1 ]; then
    runw timeout 120 "$scope/bin/launcher" --exec wine "$scope/ws_wine_probe.exe" >"$out/wsprobe.txt" 2>&1 ||
        { echo "FAIL: ws_wine_probe.exe exited $?"; cat "$out/wsprobe.txt"; fail=1; }
fi
# iphlpapi asks nsiproxy.sys (the late winedevice.exe) through \\.\Nsi: create and ioctl IRPs.
runw timeout 120 wine ipconfig >"$out/ipconfig.txt" 2>&1 || { echo "FAIL: ipconfig exited $?"; cat "$out/ipconfig.txt"; fail=1; }
# MoveFile and DeleteFile are done by wineserver (set_fd_name_info; delete on close): cmd.exe's own rename record,
# and wineserver's rename syscall naming cmd.exe as the client it served.
runw timeout 120 "$scope/bin/launcher" --exec wine cmd /c 'echo x> C:\msmon-t.txt & ren C:\msmon-t.txt msmon-u.txt & del C:\msmon-u.txt' \
    >"$out/cmd.txt" 2>&1 || { echo "FAIL: cmd ren/del exited $?"; cat "$out/cmd.txt"; fail=1; }
# A driver service of its own group: services.exe (joined by the poll) starts a new winedevice.exe for it.
runw timeout 120 wine sc start http >"$out/http.txt" 2>&1 || { echo "FAIL: sc start http exited $?"; cat "$out/http.txt"; fail=1; }
sleep 2
runw timeout 30 wineserver -k   # persistent (-p): ends the throwaway prefix's services and drivers
sleep 2
touch "$out/stop"
wait "$agent" || { echo "FAIL: agent exited $?"; tail -n 40 "$out/agent.log"; fail=1; }
agent=
python3 tools/verify_log.py "$out/events.jsonl" >"$out/verify.json" || { echo "FAIL: verify_log rejected the log"; fail=1; }

python3 - "$out/events.jsonl" "$out/query.txt" "$out/wsprobe.txt" "$out/bench.txt" <<'PY' || { fail=1; echo "--- agent.log (tail)"; tail -n 40 "$out/agent.log"; }
import base64, json, os, re, sys
path, query, wsprobe, bench = sys.argv[1:5]
events = [json.loads(line) for line in open(path) if line.strip()]
printed = open(query, errors="replace").read()
problems = []


def pids(name):
    """The Wine processes that mapped the scope copy of name (under Wine the image is the loader)."""
    return {e["process_id"] for e in events if e["type"] == "image_load" and e.get("text", "").endswith("/scope/" + name)}


def value(e):
    """The registry value as text: the agent's decoded_value, else the payload; None without one."""
    if isinstance(e.get("decoded_value"), str):
        return e["decoded_value"].rstrip("\0")
    if "payload" in e:
        return base64.b64decode(e["payload"]["data"]).decode("utf-16-le", "replace").rstrip("\0")
    return None


def key(e, tail):
    return e.get("text", "").lower().endswith(tail.lower())


def name(e):
    return e.get("detail", "").split(";")[0]


reg, tasklist = pids("reg.exe"), pids("tasklist.exe")
if not reg:
    problems.append("no image_load of scope/reg.exe: reg.exe was not tracked")
if not tasklist:
    problems.append("no image_load of scope/tasklist.exe: tasklist.exe was not tracked")
mine = [e for e in events if e.get("process_id") in reg | tasklist]
of_reg = [e for e in mine if e["process_id"] in reg]
current = r"\Software\Microsoft\Windows NT\CurrentVersion"
expect = {
    "registry_open of HKLM" + current: lambda e: e["type"] == "registry_open" and key(e, current) and e["status"] == 0,
    "registry_query of ProductName with the value reg.exe printed": lambda e: e["type"] == "registry_query" and
        key(e, current) and name(e) == "ProductName" and bool(value(e)) and value(e) in printed,
    r"registry_create or registry_open of HKCU\Software\MsmonTest": lambda e: e["type"] in ("registry_create", "registry_open")
        and key(e, r"\Software\MsmonTest") and e["status"] == 0,
    "registry_set_value of probe = hello (REG_SZ)": lambda e: e["type"] == "registry_set_value" and
        key(e, r"\Software\MsmonTest") and name(e) == "probe" and value(e) == "hello" and e["value1"] == 1,
    # Wine's start-up opens it before the thread's TEB is in use (ws_early), and reads its reply then too.
    r"registry_create of HKCU\Software\Wine\DllOverrides, with its reply": lambda e: e["type"] in
        ("registry_create", "registry_open") and key(e, r"\Software\Wine\DllOverrides") and
        "no_reply" not in e.get("detail", ""),
}
for what, test in expect.items():
    if not any(test(e) for e in of_reg):
        problems.append("reg.exe: no " + what)
if not any(e["type"] == "file_query_information" and e.get("text") == "system:list_processes" and e["process_id"] in tasklist
           for e in mine):
    problems.append("tasklist.exe: no file_query_information system:list_processes (process enumeration)")


def pe_frames(e):
    found = re.search(r";pe_frames=(\d+)", e.get("detail", ""))
    return int(found.group(1)) if found else 0


if not any(pe_frames(e) and any(m.lower().endswith((".exe", ".dll")) for m in e.get("modules") or []) for e in mine):
    problems.append("no record of reg.exe/tasklist.exe with pe_frames and a PE module (.exe/.dll) in modules")
notes = {e["text"]: e.get("detail", "") for e in events if e["type"] == "coverage"}
if ";wineserver=on" not in notes.get("ebpf_active", ""):
    problems.append("ebpf_active does not say wineserver=on: %s" % notes.get("ebpf_active"))
if "protocol=930" not in notes.get("wineserver_requests", ""):
    problems.append("no wineserver_requests coverage note (unavailable: %s)" % notes.get("wineserver_requests_unavailable"))
if not any(e["type"] == "coverage" and e["text"] == "wineserver_decoder" and "active=1" in e.get("detail", "")
           and e["process_id"] in reg for e in events):
    problems.append("no wineserver_decoder coverage record with active=1 for reg.exe")
sc, wmic = pids("sc.exe"), pids("wmic.exe")
if not any(e["type"] == "etw_rpc" and e["process_id"] in sc and e.get("text") == "\\pipe\\svcctl" and
           "interface=SCM/svcctl;operation=ROpenSCManagerW" in e.get("detail", "") for e in events):
    problems.append("sc.exe: no etw_rpc ROpenSCManagerW on \\pipe\\svcctl")
if not any(e["type"] == "file_write" and e["process_id"] in sc and e.get("text", "").lower() == "\\??\\pipe\\svcctl"
           for e in events):
    problems.append("sc.exe: no file_write on \\??\\pipe\\svcctl")
if not any(e["type"] == "etw_wmi" and e["process_id"] in wmic and e.get("text") == "com:WbemLocator" for e in events):
    problems.append("wmic.exe: no etw_wmi com:WbemLocator (COM activation)")
if not any(e["type"] == "etw_wmi" and e["process_id"] in wmic and e.get("text") == "module:wbemprox.dll" for e in events):
    problems.append("wmic.exe: no etw_wmi module:wbemprox.dll (provider load)")
drivers = [e for e in events if e["type"] == "etw_code_integrity" and "driver_load" in e.get("detail", "")]
late = {e["process_id"] for e in drivers if ";reconstructed=1" in e.get("detail", "")}
if not any(e.get("component", "").lower() == "mountmgr.sys" and "attribution=brokered_winedevice" in e.get("detail", "")
           and e["process_id"] in late for e in drivers):
    problems.append("late winedevice.exe: no reconstructed driver_load of mountmgr.sys with component (%d driver loads: %s)"
                    % (len(drivers), sorted({(e.get("component"), e["process_id"]) for e in drivers})))
if not any(e["type"] == "file_device_control" and e.get("component") and "irp=ioctl" in e.get("detail", "")
           and e["process_id"] in late for e in events):
    problems.append("late winedevice.exe: no file_device_control IRP record with a component")
if not any(e.get("component", "").lower() == "http.sys" and ";reconstructed=1" not in e.get("detail", "") and
           "attribution=brokered_winedevice" in e.get("detail", "") for e in drivers):
    problems.append("winedevice.exe started by services.exe after the join: no live driver_load of http.sys (not "
                    "tracked from fork)")
if not any(e["type"] == "process_handle" and e.get("detail", "").startswith("new_process;win_pid=") and
           re.search(r";win_image=[^;]*winedevice\.exe;", e["detail"], re.I) and ";win_cmdline=" in e["detail"] for e in events):
    problems.append("services.exe: no new_process record of winedevice.exe with its image and Windows command line")
renamed = {e["process_id"] for e in events if e["type"] == "file_set_information" and
           e.get("detail", "").startswith("rename;to;ws=set_fd_name_info;") and e.get("text", "").lower().endswith("\\msmon-u.txt")}
if not renamed:
    problems.append("cmd.exe: no file_set_information rename;to of C:\\msmon-u.txt decoded from set_fd_name_info")
elif not any(e["type"] == "file_set_information" and e.get("target_process_id") in renamed and
             ";served_request=wineserver:set_fd_name_info;attribution=brokered_wineserver" in e.get("detail", "")
             for e in events):
    problems.append("wineserver: no rename syscall record served for cmd.exe (served_pid, brokered_wineserver)")
tls = [e for e in events if e.get("payload", {}).get("kind") == "tls_plaintext"]
for what, arch, kind, data in [("request", "x86_64", "file_write", b"GET /msmon-tls HTTP/1.1"),
                               ("request", "i386", "file_write", b"GET /msmon-tls HTTP/1.1"),
                               ("reply", "x86_64", "file_read", b"msmon-tls-reply")]:
    if not any(e["type"] == kind and e.get("text", "").startswith("tls:session=") and data in base64.b64decode(e["payload"]["data"])
               and ";arch=" + arch + ";" in e.get("detail", "") for e in tls):
        problems.append("cscript.exe (%s): no %s tls_plaintext payload holding %r (%d tls_plaintext records)" % (arch, kind, data, len(tls)))
if not any(e["type"] == "file_query_information" and e.get("text") == "system:NtUserGetAsyncKeyState" and
           any(m.lower().endswith("/rundll32.exe") for m in e.get("modules") or []) for e in events):
    problems.append("rundll32.exe: no system:NtUserGetAsyncKeyState record with rundll32.exe in its PE frames")
if not any(e["type"] == "file_query_information" and e.get("text") == "system:NtQuerySystemInformation" and
           "class_name=SystemProcessInformation" in e.get("detail", "") and e["process_id"] in tasklist for e in events):
    problems.append("tasklist.exe: no system:NtQuerySystemInformation record of SystemProcessInformation")
if not any(e["type"] == "etw_wmi" and e["process_id"] in wmic and e.get("text", "").lower() == "query:win32_bios" and
           "operation=exec_query;query=" in e.get("detail", "") for e in events):
    problems.append("wmic.exe: no etw_wmi query:Win32_BIOS with its WQL (ExecQuery probe)")
if not any(e["type"] == "image_load" and e.get("text", "").lower().endswith("/plugplay.exe") for e in events):
    problems.append("plugplay.exe, a broker of the prefix booted before the agent, was not joined (no image_load)")
# Every wineserver request (M1) under real Wine: none of Wine's own writes is a rejected request-pipe write, and the
# hot requests are kernel aggregates.
rejected = [e for e in events if e.get("detail", "").startswith("request_pipe_rejected;")]
if rejected:
    problems.append("Wine's own request-pipe writes rejected (%d), e.g. %s" % (len(rejected), rejected[0]["detail"]))
losses = [e for e in events if e["type"] == "coverage" and e["text"] == "ebpf_losses"]
if not losses or not re.search(r"(^|;)ws_rejected=0(;|$)", losses[-1]["detail"]):
    problems.append("ebpf_losses ws_rejected is not 0: %s" % (losses[-1]["detail"] if losses else None))
if not any(e.get("text") == "system:select" and ";aggregate=kernel;ws=select;" in e.get("detail", "") for e in events):
    problems.append("no kernel summary of the select request (system:select ...;aggregate=kernel;ws=select;)")


def span(e):
    found = re.search(r";repeat_offsets=0x([0-9a-f]+)-0x([0-9a-f]+)", e.get("detail", ""))
    return (int(found.group(1), 16), int(found.group(2), 16)) if found else (1, 0)


# ws_wine_probe.exe (M3, M1): its VirtualAlloc and VirtualProtect in anonymous-memory summaries with their range, and
# its PostMessage to the peer's window naming the peer.
if os.path.exists(wsprobe):
    said = open(wsprobe, errors="replace").read()
    found = re.search(r"alloc=0x([0-9a-f]{16})", said)
    probe = pids("ws_wine_probe.exe")
    memory = [e for e in events if e.get("process_id") in probe and e["type"] == "file_section" and
              e.get("text") in ("system:mmap", "system:mprotect") and "aggregate=kernel" in e.get("detail", "")]
    if "probe=ok" not in said or not found:
        problems.append("ws_wine_probe.exe did not finish: %r" % said[-200:])
    else:
        area = int(found.group(1), 16)
        if not any(span(e)[0] <= area and area + 0x10000 <= span(e)[1] for e in memory):
            problems.append("ws_wine_probe.exe: no mmap/mprotect summary whose range holds its VirtualAlloc at %#x" % area)
        if not any(e["text"] == "system:mprotect" and ";prot=0x0;" in e["detail"] and span(e)[0] <= area and
                   area + 0x1000 <= span(e)[1] for e in memory):
            problems.append("ws_wine_probe.exe: no mprotect prot=0x0 summary holding its PAGE_NOACCESS page at %#x" % area)
    if not any(e["type"] == "file_query_information" and e.get("text") == "system:send_message" and
               e.get("process_id") in probe and ";type=posted;" in e.get("detail", "") and ";msg=0x401;" in e["detail"] and
               e.get("target_process_id") in probe - {e["process_id"]} for e in events):
        problems.append("ws_wine_probe.exe: no send_message of its posted 0x401 naming the peer as the target")
    # WP-M3: NtQueryVirtualMemory keyed by its page (3 VirtualQuery in a row, 3 records), and the copy it loaded as a
    # library and freed: unmap_view of that image view is an unload.
    if found:
        queried = {int(m.group(1), 16) for e in events if e.get("process_id") in probe and e.get("text") == "system:NtQueryVirtualMemory"
                   for m in [re.search(r";args=0x[0-9a-f]+,0x([0-9a-f]+),", e.get("detail", ""))] if m}
        wanted = {int(found.group(1), 16) + page * 0x1000 for page in range(3)}
        if not wanted <= queried:
            problems.append("ws_wine_probe.exe: NtQueryVirtualMemory records at %s, not each of %s" %
                            (sorted(map(hex, queried & wanted)), sorted(map(hex, wanted))))
        if int(found.group(1), 16) + 0x10 in queried:
            problems.append("ws_wine_probe.exe: a query of a page already recorded that second has a record of its own")
    # Its walk of 256 pages: at most 64 records a second, the rest kernel summaries over the walked pages, all counted.
    walk = re.search(r"walk=0x([0-9a-f]+)", said)
    if walk:
        base = int(walk.group(1), 16)
        inside = lambda address: base <= address < base + 0x100000
        records = [e for e in events if e.get("process_id") in probe and e.get("text") == "system:NtQueryVirtualMemory" and
                   not e.get("detail", "").startswith("repeats_tail;")
                   for m in [re.search(r";args=0x[0-9a-f]+,0x([0-9a-f]+),", e.get("detail", ""))] if m and inside(int(m.group(1), 16))]
        summaries = [e for e in events if e.get("process_id") in probe and e.get("text") == "system:NtQueryVirtualMemory" and
                     ";aggregate=kernel;" in e.get("detail", "")]
        summed = sum(e["value1"] for e in summaries)
        if len(records) > 128 or len(records) + summed < 256 or \
                not any(re.search(r";repeat_offsets=0x([0-9a-f]+)-", e["detail"]) and
                        inside(int(re.search(r";repeat_offsets=0x([0-9a-f]+)-", e["detail"]).group(1), 16)) for e in summaries):
            problems.append("ws_wine_probe.exe: its 256-page walk is %d records and %d calls in kernel summaries "
                            "(want at most 64 a second, the rest summarized over the walked pages)" % (len(records), summed))
    # WP-M4 window probes: the peer's window by its three handle forms (each its own record, the peer as target), the
    # posted message, none of the 100000 calls on its own window; the cost per call with and without the probes.
    self_hwnd = re.search(r"self=0x([0-9a-f]+)", said)
    peer_hwnd = re.search(r"peer=0x([0-9a-f]+)", said)
    calls = [e for e in events if e.get("process_id") in probe and e.get("text") == "system:NtUserCallHwndParam"]
    def first_arg(e):
        found = re.search(r";args=0x([0-9a-f]+),", e.get("detail", ""))
        return int(found.group(1), 16) if found else None
    if self_hwnd and peer_hwnd:
        own, other = int(self_hwnd.group(1), 16), int(peer_hwnd.group(1), 16)
        low = other & 0xffff
        forms = {first_arg(e) & 0xffffffff for e in calls if e.get("target_process_id") in probe - {e["process_id"]} and
                 "class_name=GetWindowLongA" in e.get("detail", "") and ";owner_pid=" in e["detail"]}
        if not {other & 0xffffffff, low, 0xffff0000 | low} <= forms:
            problems.append("ws_wine_probe.exe: NtUserCallHwndParam of the peer's window by %s, not each of %s" %
                            (sorted(map(hex, forms)), [hex(other), hex(low), hex(0xffff0000 | low)]))
        if any(first_arg(e) is not None and first_arg(e) & 0xffff == own & 0xffff for e in calls):
            problems.append("ws_wine_probe.exe: NtUserCallHwndParam records of its own window (the kernel's owner filter)")
        if not any(e.get("text") == "system:NtUserPostMessage" and e.get("process_id") in probe and
                   e.get("target_process_id") in probe - {e["process_id"]} and ",0x401," in e.get("detail", "") for e in events):
            problems.append("ws_wine_probe.exe: no NtUserPostMessage record of its posted 0x401 naming the peer")
    else:
        problems.append("ws_wine_probe.exe printed no self= and peer= windows: %r" % said[-200:])
    probed = re.search(r"hwndparam_ns=(\d+)", said)
    base = re.search(r"hwndparam_ns=(\d+)", open(bench, errors="replace").read()) if os.path.exists(bench) else None
    if probed and base:
        print("wine: window probes cost %d ns per NtUserCallHwndParam call (%d ns with the probe, %d without)" %
              (int(probed.group(1)) - int(base.group(1)), int(probed.group(1)), int(base.group(1))))
    if "unload=ok" not in said:
        problems.append("ws_wine_probe.exe could not load and free a copy of itself as a library: %r" % said[-200:])
    elif not any(e["type"] == "file_section" and e.get("process_id") in probe and e.get("detail", "").startswith("unmap_view;") and
                 ";image_unload=1" in e["detail"] and "msmon-unload" in e.get("text", "").lower() for e in events):
        problems.append("ws_wine_probe.exe: no unmap_view;...;image_unload=1 of msmon-unload.dll")
for problem in problems:
    print("FAIL wine: " + problem)
if problems:
    kinds = {}
    for e in mine:
        kinds[e["type"]] = kinds.get(e["type"], 0) + 1
    print("records of reg.exe/tasklist.exe by type: %s" % kinds)
    for e in of_reg:
        if e["type"].startswith("registry_"):
            print("  %s %s [%s] status=%s value=%r" % (e["type"], e.get("text"), e.get("detail", "")[:60], e.get("status"), value(e)))
print("wine: %d records, %d from reg.exe/tasklist.exe" % (len(events), len(mine)))
sys.exit(1 if problems else 0)
PY

[ "$fail" = 0 ] && echo "linux wine test: PASS" || echo "linux wine test: FAIL"
exit "$fail"
