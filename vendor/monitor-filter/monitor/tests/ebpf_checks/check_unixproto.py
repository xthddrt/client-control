"""The unixproto upgrade, called by tests/linux_ebpf_test.sh check() (actions: tests/fixtures/probe_unix.h and
unixproto.sh), against a private Xvfb:
- the probe's X11 requests: QueryExtension(XTEST) split over iovecs named with its extension, the 8 KiB ChangeProperty
  with its window, property and length, the GetInputFocus past the 4 KiB walk an unparsed summary, the QueryPointer
  after it named (the walk kept step), the server's replies a received summary, six NoOperation in one write as one
  record and a summary of five with 20 bytes;
- the display's extension table (x11_display status=ok with XTEST), so xdpyinfo's extension requests are named
  <EXTENSION>.<request> and xdotool's XTEST.FakeInput is (its key withheld);
- dbus-send's Hello and ListNames on the system bus, the method_return and NameAcquired it received (framed in the
  kernel, each named from its start) and its SASL handshake's calls summarized (operation=sasl);
- pactl's commands and the server's REPLY when a PulseAudio server ran for the invoking user.
Run as a script on the --log-content session (unixproto_end): the probe's X11 bytes are payloads (its QueryExtension's
name in them, the 8 KiB write capped with content_cap and hashed) and its SIOCGIFHWADDR has arg_bytes ("lo")."""
import base64
import json
import os
import re
import sys


def tool_pids(events, tool):
    return {e["process_id"] for e in events if e["type"] in ("process_start", "image_load") and
            (e.get("text", "") + " " + e.get("process_path", "")).rstrip().endswith("/" + tool)}


def unix(events, pids, interface):
    return [e for e in events if e["type"] == "etw_rpc" and e.get("process_id") in pids and
            ";interface=%s;" % interface in ";" + e.get("detail", "")]


def operations(records, received=False):
    found = set()
    for e in records:
        m = re.search(r"(?:^|;)operation=([^;]*)", e.get("detail", ""))
        if m and (";direction=received" in e["detail"]) == received:
            found.add(m.group(1))
    return found


def check(mode, path, events, mine, pids, coverage, problems):
    if mode == "fallback":
        return
    session = os.path.dirname(path)
    if not os.path.exists(os.path.join(session, "unixproto.display")):
        print("%s: unixproto skipped (no Xvfb)" % mode)
        return
    displays = [e for e in events if e["type"] == "coverage" and e.get("text") == "x11_display"]
    if not any(";status=ok;" in e.get("detail", "") and re.search(r"(^|[;,=])XTEST:\d+", e["detail"]) for e in displays):
        problems.append("unixproto: no x11_display status=ok naming XTEST: %s" % [e.get("detail") for e in displays])
    probe = unix(events, tool_pids(events, "x11-probe"), "x11")
    def has(test, records=probe):
        return any(test(e) for e in records)
    expect = {
        "QueryExtension split over iovecs named with extension=XTEST": lambda e: "operation=QueryExtension;extension=XTEST;" in e["detail"],
        "ChangeProperty with its property, type and length": lambda e: re.search(
            r"operation=ChangeProperty;window=0x[0-9a-f]+;property=0x27;type=0x1f;format=8;length=8192;", e["detail"]),
        "the GetInputFocus past the 4 KiB walk as an unparsed summary": lambda e: e["detail"].startswith("repeats_tail;") and
            ";operation=unparsed;direction=sent;" in e["detail"] and int(re.search(r"repeat_bytes=(\d+)", e["detail"]).group(1)) >= 4,
        "QueryPointer after the write past 4 KiB": lambda e: ";operation=QueryPointer;" in ";" + e["detail"],
        "the server's replies as a received summary": lambda e: ";operation=reply;direction=received;" in e["detail"],
        "the first of six NoOperation in one write sampled": lambda e: not e["detail"].startswith("repeats_tail;") and
            (";" + e["detail"]).startswith(";interface=x11;operation=NoOperation;"),
        "the other five NoOperation summarized with their 20 bytes (the sampled one's left out)": lambda e:
            ";operation=NoOperation;direction=sent;" in e["detail"] and ";repeats_before=5;repeat_bytes=20;" in e["detail"],
    }
    for what, test in expect.items():
        if not has(test):
            problems.append("unixproto: x11-probe: no %s (%d x11 records)" % (what, len(probe)))
    shown = operations(unix(events, tool_pids(events, "xdpyinfo"), "x11"))
    if not any("." in op for op in shown):
        problems.append("unixproto: xdpyinfo: no extension request named <EXTENSION>.<request>: %s" % sorted(shown))
    xdotool = unix(events, tool_pids(events, "xdotool"), "x11")
    if xdotool and not has(lambda e: ";operation=XTEST.FakeInput;type=KeyPress;" in ";" + e["detail"] and ";input=withheld" in e["detail"],
                          xdotool):
        problems.append("unixproto: xdotool: no XTEST.FakeInput KeyPress with its key withheld: %s" % sorted(operations(xdotool)))
    bus = unix(events, tool_pids(events, "dbus-send"), "dbus_system")
    if os.path.exists(os.path.join(session, "dbus.txt")) and "array [" in open(os.path.join(session, "dbus.txt")).read():
        sent, received = operations(bus), operations(bus, True)
        if not {"org.freedesktop.DBus.Hello", "org.freedesktop.DBus.ListNames"} <= sent or \
                not {"method_return", "org.freedesktop.DBus.NameAcquired"} <= received:
            problems.append("unixproto: dbus-send: sent %s, received %s" % (sorted(sent), sorted(received)))
        if not any(e["detail"].startswith("repeats_tail;") and ";operation=sasl;" in e["detail"] for e in bus):
            problems.append("unixproto: dbus-send: no summary of its SASL handshake's calls (operation=sasl)")
    if os.path.exists(os.path.join(session, "unixproto.pulse")):
        pulse = unix(events, tool_pids(events, "pactl"), "pulse")
        if not {"AUTH", "GET_SERVER_INFO"} <= operations(pulse) or "REPLY" not in operations(pulse, True):
            problems.append("unixproto: pactl: sent %s, received %s" % (sorted(operations(pulse)), sorted(operations(pulse, True))))


def content(path):
    """The --log-content session: X11 bytes as capped, hashed payloads; a socket ioctl's argument struct."""
    events = [json.loads(line) for line in open(path) if line.strip()]
    pids = tool_pids(events, "x11-probe")
    mine = [e for e in events if e.get("process_id") in pids]
    problems = []
    notes = {e["text"]: e.get("detail", "") for e in events if e["type"] == "coverage"}
    if ";content=on;" not in notes.get("ebpf_active", "") + ";":
        problems.append("ebpf_active does not say content=on: %s" % notes.get("ebpf_active"))
    payloads = [e for e in mine if e.get("payload", {}).get("kind") == "network_data" and "service=x11" in e.get("detail", "")]
    if not any(b"XTEST" in base64.b64decode(e["payload"]["data"]) and ";content_sha256=" in e["detail"] for e in payloads):
        problems.append("no X11 payload holding the QueryExtension's XTEST with content_sha256 (%d x11 payloads)" % len(payloads))
    if not any("payload_stop=content_cap" in e["detail"] and ";content_bytes=8220;" in e["detail"] for e in payloads):
        problems.append("the 8 KiB ChangeProperty write is not capped (payload_stop=content_cap, content_bytes=8220)")
    if not any(e["type"] == "file_device_control" and ";arg_bytes=6c6f00" in e.get("detail", "") for e in mine):
        problems.append("SIOCGIFHWADDR has no arg_bytes starting with \"lo\"")
    for problem in problems:
        print("FAIL content: " + problem)
    print("content: %d records, %d from the X11 probe" % (len(events), len(mine)))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(content(sys.argv[1]))
