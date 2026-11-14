"""Payload upgrade checks (tests/linux_ebpf_test.sh check()): the bytes tests/fixtures/probe_payload.h sends
and receives come back out of the log exactly as network_data payload series, its DNS query is an etw_dns
record, glibc's lookup (sendmmsg query, recvfrom response) gives a 3006 and a 3008 etw_dns, a MSG_PEEK read carries no payload, a sendmmsg past 1 MiB is partial with its tail msg_missing, a
netlink reply is captured, AF_UNIX sends to desktop services are named (etw_rpc), and --no-payloads leaves no
bytes and no etw_dns."""
import base64

BIG = bytes(index % 251 for index in range(20000))
WIDE = bytes(index % 241 for index in range(60000))
QUERY = bytes([0x4d, 0x53, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 11]) + b"msmon-probe" + bytes([7]) + b"example" + bytes([0, 0, 1, 0, 1])
# (what, bytes, record type, syscall, detail fragment)
WANTED = [
    ("TCP send", b"msmon-payload-ping-0123456789", "file_write", "sendto", ";endpoints=127.0.0.1:"),
    ("TCP recv", b"msmon-payload-ping-0123456789", "file_read", "recvfrom", ";endpoints=127.0.0.1:"),
    ("TCP writev", b"msmon-payload-pong", "file_write", "writev", ""),
    ("TCP read", b"msmon-payload-pong", "file_read", "read", ""),
    ("TCP sendmsg", b"msmon-payload-tcpmsg", "file_write", "sendmsg", ";endpoints=127.0.0.1:"),
    ("TCP recvmsg", b"msmon-payload-tcpmsg", "file_read", "recvmsg", ";endpoints=127.0.0.1:"),
    ("sendmmsg 60000-byte message 16", WIDE, "file_write", "sendmmsg", ";msg=16"),
    ("TCP 20000-byte send", BIG, "file_write", "sendto", ""),
    ("TCP 20000-byte recv", BIG, "file_read", "recvfrom", ""),
    ("UDP sendmsg", b"msmon-payload-datagram", "network_connect", "sendmsg", ""),
    ("UDP recvmsg", b"msmon-payload-datagram", "network_accept", "recvmsg", ""),
    ("sendmmsg message 0", b"msmon-payload-mmsg-a", "file_write", "sendmmsg", ";msg=0"),
    ("sendmmsg message 1", b"msmon-payload-mmsg-bb", "file_write", "sendmmsg", ";msg=1"),
    ("recvmmsg message 0", b"msmon-payload-mmsg-a", "file_read", "recvmmsg", ";msg=0"),
    ("recvmmsg message 1", b"msmon-payload-mmsg-bb", "file_read", "recvmmsg", ";msg=1"),
    ("DNS query", QUERY, "network_connect", "sendto", ""),
    ("::1 TCP send", b"msmon-payload-v6-tcp", "file_write", "sendto", ";endpoints=[::1]:"),
    ("::1 TCP recv", b"msmon-payload-v6-tcp", "file_read", "recvfrom", " -> [::1]:"),
    ("::1 UDP sendto", b"msmon-payload-v6-udp", "network_connect", "sendto", ""),
    ("::1 UDP recvfrom", b"msmon-payload-v6-udp", "network_accept", "recvfrom", ""),
]


def args(record):
    """The six syscall arguments from the detail's args= field."""
    for field in record.get("detail", "").split(";"):
        if field.startswith("args="):
            return [int(value, 16) for value in field[5:].split(",")]
    return []


def check(mode, path, events, mine, pids, coverage, problems):
    if mode == "nopayloads":
        if any("payload" in e or e["type"] == "etw_dns" for e in events):
            problems.append("payload bytes or etw_dns records although --no-payloads was given")
        if "payload_capture_disabled" not in coverage:
            problems.append("no payload_capture_disabled coverage record")
        return
    if mode != "ebpf":
        return
    series = {}
    for e in mine:
        if e.get("payload", {}).get("kind") == "network_data":
            series.setdefault(e["payload"]["operation_id"], []).append(e)

    def joined(records):
        records = sorted(records, key=lambda r: r["payload"]["chunk_index"])
        return b"".join(base64.b64decode(r["payload"]["data"]) for r in records)

    ops = [(records[0], joined(records), len(records) == records[0]["payload"]["chunk_count"])
           for records in series.values()]
    for name, blob, kind, call, extra in WANTED:
        if not any(data == blob and complete and first["type"] == kind and "syscall=" + call + ";" in first["detail"]
                   and extra in first["detail"] for first, data, complete in ops):
            problems.append("no exact payload for the " + name)
    if not any(len(records) == 3 and joined(records) == BIG for records in series.values()):
        problems.append("the 20000-byte transfer is not one series of three 8 KiB chunks")
    # The one partial series is message 17 of the 20 x 60000-byte sendmmsg: 1 MiB - 17 * 60000 = 28576
    # bytes captured, cut to three whole 8 KiB chunks.
    if not all(complete or ";payload_stop=" in first["detail"] for first, _, complete in ops):
        problems.append("an incomplete payload series without payload_stop")
    if not any(first["detail"].find(";msg=17;payload_missing=35424;payload_stop=limit") >= 0 and data == WIDE[:24576]
               and first["payload"]["chunk_count"] == 8 and "payload_partial" in first.get("flags_names", [])
               for first, data, _ in ops):
        problems.append("no partial series (payload_stop=limit) for sendmmsg message 17")
    if not any("syscall=sendmmsg;" in e.get("detail", "") and e["detail"].startswith("payload_limit;")
               and e["detail"].endswith(";msg_missing=18-19") and "payload_unavailable" in e.get("flags_names", [])
               and "payload_input" in e.get("flags_names", []) for e in mine):
        problems.append("no payload_unavailable record with msg_missing=18-19 for the sendmmsg tail")
    if not any(first["type"] == "file_read" and "syscall=recvmsg;" in first["detail"] and ";netlink=0" in first["detail"]
               and complete and len(data) >= 16 and int.from_bytes(data[4:6], "little") == 16 for first, data, complete in ops):
        problems.append("no complete netlink RTM_NEWLINK reply payload")
    if any(first["text"].startswith(("pipe:", "unix:")) for first, _, _ in ops):
        problems.append("a pipe or AF_UNIX transfer carries a payload")
    peeks = [e for e in mine if "syscall=recvfrom;" in e.get("detail", "") and len(args(e)) == 6 and args(e)[3] & 2]
    if not peeks:
        problems.append("no recvfrom record of the MSG_PEEK read")
    if any("payload" in e for e in peeks):
        problems.append("a MSG_PEEK read carries a payload")
    query_ops = {first["operation_id"] for first, data, _ in ops if data == QUERY}
    if not any(e["type"] == "etw_dns" and e["text"] == "msmon-probe.example" and e["value0"] == 3006 and
               "query_type=1;dns_id=19795;" in e["detail"] and "server=127.0.0.53:53" in e["detail"] and
               e["operation_id"] in query_ops for e in mine):
        problems.append("no etw_dns record for the DNS query")
    # glibc res_send (getaddrinfo): connected UDP, A + AAAA in one sendmmsg (no address: the port is the
    # socket's), each answer read with recvfrom.
    def dns(value0, call, extra, fragment):
        ops_of = {first["operation_id"] for first, _, _ in ops
                  if "syscall=" + call + ";" in first["detail"] and extra in first["detail"]}
        return any(e["type"] == "etw_dns" and e["text"] == "msmon-probe.example" and e["value0"] == value0 and
                   fragment in e["detail"] and "transport=udp;server=127.0.0.53:53" in e["detail"] and
                   e["operation_id"] in ops_of for e in mine)
    if not dns(3006, "sendmmsg", ";msg=", "query_type="):
        problems.append("no etw_dns query (3006) from glibc's sendmmsg")
    if not dns(3008, "recvfrom", "", ";rcode="):
        problems.append("no etw_dns response (3008) with rcode= from glibc's recvfrom")
    if "payload_capture_enabled" not in coverage:
        problems.append("no payload_capture_enabled coverage record")
    # AF_UNIX desktop services: the requests named from the first bytes (etw_rpc on the endpoint), the I/O labelled.
    for endpoint, fragment in [("unix:@msmon-probe/pulse/native", "interface=pulse;operation=GET_CLIENT_INFO_LIST;"),
                               ("unix:@msmon-probe/bus", "interface=dbus_session;operation=ListNames;"
                                                         "destination=org.freedesktop.DBus;path=/org/freedesktop/DBus;"),
                               ("unix:@msmon-probe/.X11-unix/X9", "interface=x11;operation=QueryExtension;extension=RECORD;")]:
        if not any(e["type"] == "etw_rpc" and e.get("text") == endpoint and e["detail"].startswith(fragment) for e in mine):
            problems.append("no etw_rpc %s on %s" % (fragment, endpoint))
    if not any(e["type"] == "file_write" and ";service=pulse;peer=unix:@msmon-probe/pulse/native" in e.get("detail", "")
               for e in mine):
        problems.append("the PulseAudio socket's sendmsg does not name its service")
