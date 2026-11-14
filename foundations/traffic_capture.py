"""Loss-aware pcap/pcapng parsing and TCP byte-stream reassembly."""

from datetime import datetime, timezone
import ipaddress
from pathlib import Path
import struct


def timestamp_ns(value):
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value * 1_000_000_000)
    text = str(value)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return int(parsed.timestamp() * 1_000_000_000)


def timestamp_text(value):
    if value is None:
        return None
    seconds, nanoseconds = divmod(value, 1_000_000_000)
    return datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") + f".{nanoseconds:09d}Z"


def _options(data, endian):
    result = {}
    offset = 0
    while offset + 4 <= len(data):
        code, length = struct.unpack_from(endian + "HH", data, offset)
        offset += 4
        if code == 0:
            break
        if offset + length > len(data):
            raise ValueError("pcapng option exceeds its block")
        result.setdefault(code, []).append(data[offset:offset + length])
        offset += (length + 3) & ~3
    return result


def _comment_fields(comment):
    result = {}
    for part in comment.split(";"):
        key, separator, value = part.partition("=")
        if separator:
            result[key] = value
    return result


def _resolution(option):
    if not option:
        return 1_000_000
    value = option[0]
    return (2 ** (value & 0x7F)) if value & 0x80 else (10 ** (value & 0x7F))


def read_capture(path):
    """Return captured frames in file order, retaining raw bytes and pcapng attribution."""
    path = Path(path)
    return parse_capture(path.read_bytes(), path)


def parse_capture(data, source="capture"):
    if len(data) < 4:
        raise ValueError(f"{source}: empty or truncated capture")
    if data[:4] == b"\x0a\x0d\x0d\x0a":
        packets = _read_pcapng(data, source)
    else:
        packets = _read_pcap(data, source)
    for index, packet in enumerate(packets):
        packet["capture_index"] = index
        packet["evidence"] = {"file": str(source), "capture_index": index}
        metadata = packet.get("metadata", {})
        packet["process_id"] = int(metadata["pid"]) if metadata.get("pid", "").isdecimal() else None
        packet["process_name"] = metadata.get("process")
        packet["socket_inode"] = metadata.get("socket")
        packet["socket_cookie"] = metadata.get("cookie")
        packet.update(parse_network(packet["data"], packet["linktype"], packet.get("original_length")))
    return packets


def _read_pcap(data, path):
    magic = data[:4]
    formats = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
        b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
        b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
    }
    if magic not in formats or len(data) < 24:
        raise ValueError(f"{path}: unsupported pcap header")
    endian, resolution = formats[magic]
    _, _, _, _, _, linktype = struct.unpack_from(endian + "HHIIII", data, 4)
    packets = []
    offset = 24
    while offset < len(data):
        if offset + 16 > len(data):
            raise ValueError(f"{path}: truncated pcap packet header at {offset}")
        high, low, captured, original = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        if captured > original or offset + captured > len(data):
            raise ValueError(f"{path}: invalid pcap packet length at {offset - 16}")
        stamp = high * resolution + low
        packets.append({
            "time_ns": stamp * 1_000_000_000 // resolution,
            "data": data[offset:offset + captured],
            "original_length": original,
            "linktype": linktype,
            "direction_flag": 0,
            "comment": "",
            "metadata": {},
        })
        offset += captured
    return packets


def _read_pcapng(data, path):
    packets = []
    interfaces = []
    endian = "<"
    offset = 0
    while offset < len(data):
        if offset + 12 > len(data):
            raise ValueError(f"{path}: truncated pcapng block at {offset}")
        kind_raw = data[offset:offset + 4]
        if kind_raw == b"\x0a\x0d\x0d\x0a":
            if offset + 16 > len(data):
                raise ValueError(f"{path}: truncated section header")
            bom = data[offset + 8:offset + 12]
            if bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise ValueError(f"{path}: unsupported pcapng byte order")
            interfaces = []
        kind = struct.unpack_from(endian + "I", kind_raw)[0]
        length = struct.unpack_from(endian + "I", data, offset + 4)[0]
        if length < 12 or length % 4 or offset + length > len(data):
            raise ValueError(f"{path}: invalid pcapng block length at {offset}")
        if struct.unpack_from(endian + "I", data, offset + length - 4)[0] != length:
            raise ValueError(f"{path}: pcapng block length footer differs at {offset}")
        body = data[offset + 8:offset + length - 4]
        if kind == 1:
            if len(body) < 8:
                raise ValueError(f"{path}: truncated interface description")
            linktype = struct.unpack_from(endian + "H", body)[0]
            resolution = _resolution(_options(body[8:], endian).get(9, [None])[0])
            interfaces.append((linktype, resolution))
        elif kind == 6:
            if len(body) < 20:
                raise ValueError(f"{path}: truncated enhanced packet block")
            interface, high, low, captured, original = struct.unpack_from(endian + "IIIII", body)
            if interface >= len(interfaces) or captured > original or 20 + captured > len(body):
                raise ValueError(f"{path}: invalid enhanced packet block")
            linktype, resolution = interfaces[interface]
            raw = body[20:20 + captured]
            options = _options(body[20 + ((captured + 3) & ~3):], endian)
            flags = struct.unpack_from(endian + "I", options.get(2, [bytes(4)])[0])[0]
            comment = options.get(1, [b""])[0].decode("utf-8", "replace")
            packets.append({
                "time_ns": ((high << 32) | low) * 1_000_000_000 // resolution,
                "data": raw,
                "original_length": original,
                "linktype": linktype,
                "direction_flag": flags & 3,
                "comment": comment,
                "metadata": _comment_fields(comment),
            })
        elif kind == 3:
            if not interfaces or len(body) < 4:
                raise ValueError(f"{path}: simple packet without an interface")
            original = struct.unpack_from(endian + "I", body)[0]
            captured = min(original, len(body) - 4)
            packets.append({
                "time_ns": None,
                "data": body[4:4 + captured],
                "original_length": original,
                "linktype": interfaces[0][0],
                "direction_flag": 0,
                "comment": "",
                "metadata": {},
            })
        offset += length
    return packets


def parse_network(frame, linktype, original_length=None):
    """Decode the network/transport envelope without touching the payload."""
    result = {"complete_capture": original_length is None or len(frame) == original_length}
    if linktype == 1:
        if len(frame) < 14:
            return result
        protocol = struct.unpack_from(">H", frame, 12)[0]
        offset = 14
        while protocol in (0x8100, 0x88A8):
            if len(frame) < offset + 4:
                return result
            protocol = struct.unpack_from(">H", frame, offset + 2)[0]
            offset += 4
        if protocol == 0x0800:
            version = 4
        elif protocol == 0x86DD:
            version = 6
        else:
            return result
        ip = frame[offset:]
    elif linktype == 113:
        if len(frame) < 16:
            return result
        version = 4 if frame[14:16] == b"\x08\x00" else 6 if frame[14:16] == b"\x86\xdd" else 0
        ip = frame[16:]
    elif linktype == 276:
        if len(frame) < 20:
            return result
        version = 4 if frame[:2] == b"\x08\x00" else 6 if frame[:2] == b"\x86\xdd" else 0
        ip = frame[20:]
    elif linktype == 101:
        ip = frame
        version = ip[0] >> 4 if ip else 0
    else:
        return result
    if version == 4:
        if len(ip) < 20 or ip[0] >> 4 != 4:
            return result
        header = (ip[0] & 15) * 4
        if header < 20 or len(ip) < header:
            return result
        total = struct.unpack_from(">H", ip, 2)[0]
        if total < header or total > len(ip):
            result["complete_capture"] = False
            total = len(ip)
        fragment = struct.unpack_from(">H", ip, 6)[0]
        result.update({
            "ip_version": 4,
            "source_ip": str(ipaddress.ip_address(ip[12:16])),
            "destination_ip": str(ipaddress.ip_address(ip[16:20])),
            "ip_protocol": ip[9],
            "fragmented": bool(fragment & 0x3FFF),
        })
        if result["fragmented"]:
            return result
        transport = ip[header:total]
    elif version == 6:
        if len(ip) < 40 or ip[0] >> 4 != 6:
            return result
        total = 40 + struct.unpack_from(">H", ip, 4)[0]
        if total > len(ip):
            result["complete_capture"] = False
            total = len(ip)
        next_header = ip[6]
        offset = 40
        while next_header in (0, 43, 44, 51, 60):
            if offset + 2 > total:
                return result
            following = ip[offset]
            if next_header == 44:
                result["fragmented"] = True
                return result
            length = (ip[offset + 1] + 2) * 8 if next_header == 51 else (ip[offset + 1] + 1) * 8
            if length < 8 or offset + length > total:
                return result
            offset += length
            next_header = following
        result.update({
            "ip_version": 6,
            "source_ip": str(ipaddress.ip_address(ip[8:24])),
            "destination_ip": str(ipaddress.ip_address(ip[24:40])),
            "ip_protocol": next_header,
            "fragmented": False,
        })
        transport = ip[offset:total]
    else:
        return result
    protocol = result["ip_protocol"]
    if protocol == 6:
        if len(transport) < 20:
            return result
        header = (transport[12] >> 4) * 4
        if header < 20 or header > len(transport):
            return result
        result.update({
            "transport_protocol": "tcp",
            "source_port": struct.unpack_from(">H", transport)[0],
            "destination_port": struct.unpack_from(">H", transport, 2)[0],
            "sequence": struct.unpack_from(">I", transport, 4)[0],
            "acknowledgement": struct.unpack_from(">I", transport, 8)[0],
            "tcp_flags": transport[13],
            "payload": transport[header:],
        })
    elif protocol == 17:
        if len(transport) < 8:
            return result
        length = struct.unpack_from(">H", transport, 4)[0]
        if length < 8:
            return result
        result["complete_capture"] &= length <= len(transport)
        result.update({
            "transport_protocol": "udp",
            "source_port": struct.unpack_from(">H", transport)[0],
            "destination_port": struct.unpack_from(">H", transport, 2)[0],
            "payload": transport[8:min(length, len(transport))],
        })
    return result


def _signed_sequence_delta(value, reference):
    delta = (value - reference) & 0xFFFFFFFF
    return delta - 0x100000000 if delta & 0x80000000 else delta


def reassemble_tcp(packets):
    """Return directional streams with first-capture-wins bytes and explicit gaps/conflicts.

    Socket cookies keep reused endpoint tuples apart. Without cookies, a new SYN starts a
    new generation. No bytes are invented for absent packets or packet payload truncation.
    """
    ordered = sorted(
        (packet for packet in packets if packet.get("transport_protocol") == "tcp"),
        key=lambda packet: (packet["time_ns"] is None, packet["time_ns"] or 0, packet["capture_index"]),
    )
    generations = {}
    connections = {}
    for packet in ordered:
        source = (packet["source_ip"], packet["source_port"])
        destination = (packet["destination_ip"], packet["destination_port"])
        metadata = packet.get("metadata", {})
        cookie = metadata.get("cookie")
        base = ("cookie", cookie) if cookie else ("endpoints", packet.get("process_id"), tuple(sorted((source, destination))))
        flags = packet.get("tcp_flags", 0)
        generation = generations.get(base, 0)
        key = (base, generation)
        existing = connections.get(key)
        repeated_syn = existing and any(
            old.get("sequence") == packet.get("sequence") and old.get("tcp_flags", 0) & 0x02
            for old in existing["packets"]
        )
        if flags & 0x02 and not flags & 0x10 and existing and not repeated_syn:
            generation += 1
            generations[base] = generation
            key = (base, generation)
        generations.setdefault(base, generation)
        connection = connections.setdefault(key, {"packets": [], "directions": {}})
        connection["packets"].append(packet)
        if packet.get("payload"):
            direction = connection["directions"].setdefault((source, destination), [])
            direction.append(packet)

    streams = []
    for (base, generation), connection in connections.items():
        for (source, destination), segments in connection["directions"].items():
            reference = segments[0]["sequence"]
            placed = []
            for packet in segments:
                start = _signed_sequence_delta(packet["sequence"], reference)
                placed.append((start, start + len(packet["payload"]), packet))
            origin = min(item[0] for item in placed)
            placed = [(start - origin, end - origin, packet) for start, end, packet in placed]
            by_position = sorted(enumerate(placed), key=lambda item: (item[1][0], item[0]))
            clusters = []
            cluster_ends = []
            for _, item in by_position:
                start, end, _ = item
                if clusters and start <= cluster_ends[-1]:
                    clusters[-1].append(item)
                    cluster_ends[-1] = max(cluster_ends[-1], end)
                else:
                    clusters.append([item])
                    cluster_ends.append(end)
            runs = []
            gaps = []
            conflicts = []
            retransmitted = 0
            previous_end = None
            for cluster in clusters:
                first = min(item[0] for item in cluster)
                last = max(item[1] for item in cluster)
                if previous_end is not None and first > previous_end:
                    gaps.append({"stream_offset": previous_end, "length": first - previous_end})
                previous_end = last
                data = bytearray(last - first)
                known = bytearray(last - first)
                contributors = set()
                for start, end, packet in sorted(cluster, key=lambda item: (
                    item[2]["time_ns"] is None, item[2]["time_ns"] or 0, item[2]["capture_index"]
                )):
                    contributors.add(packet["capture_index"])
                    payload = packet["payload"]
                    for index, byte in enumerate(payload):
                        position = start - first + index
                        if known[position]:
                            retransmitted += 1
                            if data[position] != byte:
                                conflicts.append({
                                    "stream_offset": first + position,
                                    "first_hex": f"{data[position]:02x}",
                                    "later_hex": f"{byte:02x}",
                                    "later_packet": packet["capture_index"],
                                })
                            continue
                        data[position] = byte
                        known[position] = 1
                run_start = 0
                for position in range(len(known) + 1):
                    if position != len(known) and known[position]:
                        continue
                    if position > run_start:
                        runs.append({
                            "stream_offset": first + run_start,
                            "data": bytes(data[run_start:position]),
                            "segment_indexes": sorted(contributors),
                        })
                    while position < len(known) and not known[position]:
                        position += 1
                    run_start = position
                if not all(known):
                    gaps.append({"stream_offset": first, "length": len(known), "internal_capture_holes": True})
            streams.append({
                "connection": {"identity": base, "generation": generation},
                "source": source,
                "destination": destination,
                "packets": connection["packets"],
                "segments": segments,
                "runs": runs,
                "gaps": gaps,
                "overlap_conflicts": conflicts,
                "retransmitted_bytes": retransmitted,
                "sequence_origin": "lowest_observed_payload_sequence",
                "first_sequence": (reference + origin) & 0xFFFFFFFF,
            })
    return streams


def self_test():
    packets = []
    sequence = 1000
    pieces = [(0, b"ab"), (2, b"cd"), (1, b"bcde"), (4, b"ef")]
    for index, (delta, payload) in enumerate(pieces):
        packets.append({
            "transport_protocol": "tcp", "source_ip": "127.0.0.1", "destination_ip": "127.0.0.2",
            "source_port": 1000, "destination_port": 2000, "sequence": sequence + delta,
            "payload": payload, "time_ns": index, "capture_index": index, "metadata": {"cookie": "1"},
        })
    stream = reassemble_tcp(packets)[0]
    assert b"".join(run["data"] for run in stream["runs"]) == b"abcdef"
    assert stream["retransmitted_bytes"] == 4 and not stream["gaps"] and not stream["overlap_conflicts"]
    packets[2]["payload"] = b"bXde"
    stream = reassemble_tcp(packets)[0]
    assert stream["overlap_conflicts"] and stream["runs"][0]["data"] == b"abcdef"
    nested = [
        dict(packets[0], sequence=1000, payload=b"abcdef", capture_index=10),
        dict(packets[0], sequence=1002, payload=b"cd", capture_index=11),
        dict(packets[0], sequence=1005, payload=b"f", capture_index=12),
    ]
    stream = reassemble_tcp(nested)[0]
    assert len(stream["runs"]) == 1 and stream["runs"][0]["data"] == b"abcdef"
    print("PASS: split/combined TCP bytes, nested retransmissions, gaps, and conflicting overlap evidence.")


if __name__ == "__main__":
    self_test()
