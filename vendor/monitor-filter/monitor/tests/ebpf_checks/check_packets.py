"""Packet capture checks (packets upgrade), called by tests/linux_ebpf_test.sh check(): the probe's
loopback exchanges (tests/fixtures/probe_packets.h) must be in the pcapng with their exact bytes."""
import hashlib
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from linux_packets_test import fields, read_pcapng, transport  # noqa: E402

MARKERS = {b"msmon-pkt-ping\n": 6, b"msmon-pkt-pong\n": 6, b"msmon-pkt-udp-probe!": 17,
           b"msmon-pkt-v6-tcp!": 6, b"msmon-pkt-v6-udp!": 17}


def check(mode, path, events, mine, pids, coverage, problems):
    pcap = pathlib.Path(path).with_suffix(".pcapng")
    if mode != "ebpf":
        want = "packet_capture_disabled" if mode == "nopayloads" else "packet_capture_unavailable"
        if want not in coverage:
            problems.append("packets: no %s coverage record" % want)
        if list(pcap.parent.glob(pcap.name + "*")):
            problems.append("packets: %s written in mode %s" % (pcap.name, mode))
        return
    if "packet_capture_active" not in coverage:
        problems.append("packets: no packet_capture_active coverage record")
        return
    notes = [(e["text"], fields(e.get("detail", ""))) for e in events if e.get("type") == "coverage"]
    parts = [detail for text, detail in notes if text == "packet_capture_part"]
    totals = [detail for text, detail in notes if text == "packet_capture"]
    if not parts or len(totals) != 1:
        problems.append("packets: %d packet_capture_part and %d packet_capture notes" % (len(parts), len(totals)))
        return
    packets = []
    for part in parts:
        file = pcap.parent / part["path"]
        try:
            _, found = read_pcapng(file)
        except (OSError, ValueError) as error:
            problems.append("packets: %s" % error)
            continue
        if part["sha256"] != hashlib.sha256(file.read_bytes()).hexdigest() or int(part["packets"]) != len(found):
            problems.append("packets: %s does not match its packet_capture_part note" % part["path"])
        packets += found
    if int(totals[0]["packets"]) != len(packets):
        problems.append("packets: packet_capture counts %s packets, the parts hold %d" % (totals[0]["packets"], len(packets)))
    if "final_read" in totals[0]:
        problems.append("packets: the BPF thread did not detach and read the ring before the totals")
    for packet in packets:
        packet["protocol"], packet["flags"], packet["payload"] = transport(packet["data"])
        packet["fields"] = fields(packet["comment"])
    for marker, protocol in MARKERS.items():
        directions = {p["direction"] for p in packets if p["protocol"] == protocol and p["payload"] == marker}
        if directions != {1, 2}:
            problems.append("packets: %r seen in directions %s (want in and out)" % (marker, sorted(directions)))
    if not all(p["data"][0] >> 4 == 6 for p in packets if p["payload"] in (b"msmon-pkt-v6-tcp!", b"msmon-pkt-v6-udp!")):
        problems.append("packets: the ::1 exchange is not captured as IPv6")
    # Wine's shape (probe_packets_wine): the child named wineserver connected, the probe read the
    # server's hello through its copy and closed it; that close must not drop the held handshake.
    wine = {p["fields"].get("cookie") for p in packets if p["payload"] == b"msmon-pkt-wine-hello" and p["direction"] == 1}
    held = [p for p in packets if p["protocol"] == 6 and p["fields"].get("cookie") in wine and "held" in p["fields"]]
    if not any(p["direction"] == 2 and p["flags"] & 0x12 == 0x02 for p in held) or \
            not any(p["payload"] == b"msmon-pkt-wine-hello" for p in held):
        problems.append("packets: the wineserver-made socket lacks its held SYN or the server's first bytes")
    if any(p["fields"].get("wineserver") in (None, p["fields"].get("pid")) for p in held):
        problems.append("packets: a held packet of the wineserver-made socket does not name its wineserver and owner")
    owners = {int(p["fields"].get("pid", 0)) for p in packets}
    # The ia32 probe (parity.sh, run from the extra root) is tracked too and sends its own UDP datagram.
    ia32 = {e["process_id"] for e in events if e["type"] == "process_start" and
            "ia32_probe" in e.get("text", "") + e.get("process_path", "")}
    if not owners or not owners <= set(pids) | ia32:
        problems.append("packets: pids %s are not the probe's %s" % (sorted(owners), sorted(pids)))

    def flags_of(marker):   # (direction, TCP flags) of the packets of the socket that sent marker
        cookies = {p["fields"].get("cookie") for p in packets if p["payload"] == marker and p["direction"] == 2}
        return [(p["direction"], p["flags"]) for p in packets if p["protocol"] == 6 and p["fields"].get("cookie") in cookies]

    client, server = flags_of(b"msmon-pkt-ping\n"), flags_of(b"msmon-pkt-pong\n")
    for name, seen, test in (
        ("client SYN", client, lambda d, f: d == 2 and f & 0x12 == 0x02),
        ("client SYN-ACK", client, lambda d, f: d == 1 and f & 0x12 == 0x12),
        ("client FIN", client, lambda d, f: d == 2 and f & 0x01),
        ("server FIN", server, lambda d, f: d == 2 and f & 0x01),
    ):
        if not any(test(d, f) for d, f in seen):
            problems.append("packets: no %s of the probe's TCP pair" % name)
