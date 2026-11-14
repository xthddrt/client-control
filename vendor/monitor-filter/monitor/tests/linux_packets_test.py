#!/usr/bin/env python3
"""linux_packets_test.py - the pcapng parts agent/linux/packets.cpp writes.

Runs build/linux/linux_packets_test (tests/linux_packets_test.cpp feeds made-up kernel packet
records) and checks the parts and notes. read_pcapng and transport are also used by
tests/linux_ebpf_test.sh on the real capture.
"""

import hashlib
import pathlib
import struct
import subprocess
import sys
import tempfile

DRIVER = pathlib.Path(__file__).resolve().parents[1] / "build" / "linux" / "linux_packets_test"


def options(raw):
    found, offset = {}, 0
    while offset + 4 <= len(raw):
        code, size = struct.unpack_from("<HH", raw, offset)
        if code == 0:
            break
        found[code] = raw[offset + 4:offset + 4 + size]
        offset += 4 + (size + 3) // 4 * 4
    return found


def read_pcapng(path):
    """(linktype, tsresol) per interface, and the packets of one little-endian pcapng file."""
    data = pathlib.Path(path).read_bytes()
    interfaces, packets, offset = [], [], 0
    while offset < len(data):
        kind, length = struct.unpack_from("<II", data, offset)
        if length < 12 or offset + length > len(data) or struct.unpack_from("<I", data, offset + length - 4)[0] != length:
            raise ValueError("%s: bad block at %d" % (path, offset))
        body = data[offset + 8:offset + length - 4]
        if kind == 0x0A0D0D0A and struct.unpack_from("<I", body)[0] != 0x1A2B3C4D:
            raise ValueError("%s: not a little-endian section" % path)
        if kind == 1:
            interfaces.append((struct.unpack_from("<H", body)[0], options(body[8:]).get(9, b"\x06")[0]))
        elif kind == 6:
            _, high, low, cap, orig = struct.unpack_from("<5I", body)
            found = options(body[20 + (cap + 3) // 4 * 4:])
            packets.append({"time": high << 32 | low, "data": body[20:20 + cap], "orig_len": orig,
                            "direction": struct.unpack("<I", found[2])[0] & 3 if 2 in found else 0,
                            "comment": found.get(1, b"").decode()})
        offset += length
    return interfaces, packets


def transport(ip):
    """(protocol, TCP flags, payload) of a raw IPv4 or IPv6 packet without extension headers."""
    if ip[0] >> 4 == 4:
        start, protocol, end = (ip[0] & 15) * 4, ip[9], struct.unpack_from(">H", ip, 2)[0]
    else:
        start, protocol, end = 40, ip[6], 40 + struct.unpack_from(">H", ip, 4)[0]
    segment = ip[start:end]
    if protocol == 6:
        return protocol, segment[13], segment[(segment[12] >> 4) * 4:]
    return protocol, 0, segment[8:] if protocol == 17 else b""


def fields(detail):
    return dict(item.split("=", 1) for item in detail.split(";") if "=" in item)


def check(condition, name):
    if not condition:
        raise SystemExit("FAIL: " + name)


def main():
    if not DRIVER.exists():
        print("linux packets test: skipped (no %s)" % DRIVER)
        return 0
    with tempfile.TemporaryDirectory() as temporary:
        output = subprocess.run([str(DRIVER), temporary], capture_output=True, text=True, check=True).stdout
        lines = output.splitlines()
        game, server = (int(value.split("=")[1]) for value in lines[-1].split())
        notes = [line.split("\t", 1) for line in lines[:-1]]
        parts = [fields(detail) for text, detail in notes if text == "packet_capture_part"]
        totals = [fields(detail) for text, detail in notes if text == "packet_capture"]
        check(notes[0][0] == "packet_capture_active" and fields(notes[0][1])["linktype"] == "101", "the start note")
        check([part["path"] for part in parts] == ["events.pcapng", "events.pcapng.1"], "two parts, named like the events parts")
        packets = []
        for part in parts:
            path = pathlib.Path(temporary) / part["path"]
            interfaces, found = read_pcapng(path)
            check(interfaces == [(101, 7)], "one raw-IP interface stamped in 100 ns units")
            check(part["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest(), part["path"] + " hash")
            check(int(part["packets"]) == len(found) and int(part["file_bytes"]) == path.stat().st_size, part["path"] + " counts")
            packets += found
        data = [packet["data"] for packet in packets]
        check(data == [b"game-out-1", b"held-syn", b"held-synack", b"game-out-2", b"held-4", b"game-in-4", b"late-4",
                       b"x" * 5000, b"game-out-3"],
              "held packets come out at attribution, launcher and unattributed ones never: %r" % [d[:12] for d in data])
        check([packet["direction"] for packet in packets] == [2, 2, 1, 2, 2, 1, 1, 1, 2], "epb_flags directions")
        check(all(packet["comment"].startswith("pid=%d;" % game) for packet in packets), "every packet names the client pid")
        check(all(("held=1" in packet["comment"]) == (packet["data"] in (b"held-syn", b"held-synack", b"held-4"))
                  for packet in packets), "held packets are marked")
        check([("wineserver=%d" % server) in packet["comment"] for packet in packets] ==
              [False, True, True, True, True, True, True, False, False], "the wineserver that used a socket is named")
        check("pending_skipped=3" in packets[3]["comment"], "packets the kernel skipped while held are counted")
        cut = packets[7]
        check(cut["orig_len"] == 70000 and "gso_segs=48" in cut["comment"], "a cut GSO packet keeps its length")
        check(len(totals) == 1, "one packet_capture totals note")
        want = {"parts": "2", "packets": "9", "truncated": "1", "gso_packets": "1", "attributed_sockets": "2",
                "unattributed_sockets": "4", "unattributed_packets": "5", "held_overflow": "1", "pending_skipped": "3",
                "ring_drops": "7"}
        check("final_read" not in totals[0], "no BPF thread polls here: nothing to wait for")
        check(all(totals[0][key] == value for key, value in want.items()), "totals %r" % totals[0])
    print("linux packets test: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
