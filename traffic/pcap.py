"""Classic pcap and pcapng readers with link/network/transport decoding.

Supported capture sources:
  * classic pcap (microsecond and nanosecond, both byte orders)
  * pcapng (SHB/IDB/EPB/SPB, per-interface timestamp resolution, EPB options)
  * monitor-filter's LINKTYPE_RAW pcapng parts and its pid/socket comments

Only parsing is done here. TCP stream reconstruction is in tcp.py.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

from .util import sha256_file


PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}

LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LOOP = 108
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229
LINKTYPE_LINUX_SLL2 = 276

MAX_BLOCK_BYTES = 128 * 1024 * 1024


@dataclass
class Packet:
    source_file: str
    source_index: int
    time_ns: int | None
    linktype: int
    src: str | None = None
    dst: str | None = None
    sport: int | None = None
    dport: int | None = None
    protocol: str | None = None
    ip_version: int | None = None
    payload: bytes = b""
    tcp: dict | None = None
    udp: dict | None = None
    epb_direction: str | None = None
    process: dict | None = None
    socket: dict | None = None
    captured_len: int | None = None
    original_len: int | None = None
    truncated: bool = False
    comment: str | None = None
    comment_fields: dict = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    @property
    def flow_key(self):
        if self.protocol is None or self.src is None or self.dst is None:
            return None
        return (
            self.protocol,
            self.src,
            self.sport,
            self.dst,
            self.dport,
        )

    def summary(self):
        return {
            "source": self.source_file,
            "source_index": self.source_index,
            "time_ns": self.time_ns,
            "src": self.src,
            "sport": self.sport,
            "dst": self.dst,
            "dport": self.dport,
            "protocol": self.protocol,
            "payload_bytes": len(self.payload),
            "epb_direction": self.epb_direction,
            "process": self.process,
            "socket": self.socket,
            "truncated": self.truncated,
            "notes": list(self.notes),
        }


@dataclass
class CaptureInventory:
    packets: list[Packet] = field(default_factory=list)
    files: list[dict] = field(default_factory=list)
    notes: list[dict] = field(default_factory=list)

    def add_note(self, source, reason, detail=None):
        record = {"source": str(source), "reason": reason}
        if detail is not None:
            record["detail"] = detail
        self.notes.append(record)


def _parse_options(raw: bytes, endian="<"):
    options = {}
    offset = 0
    while offset + 4 <= len(raw):
        code, length = struct.unpack_from(endian + "HH", raw, offset)
        offset += 4
        if code == 0 or offset + length > len(raw):
            break
        value = raw[offset:offset + length]
        offset += length + ((4 - length % 4) % 4)
        options.setdefault(code, []).append(value)
    return options


def _ts_ns(seconds, fraction, units):
    return int(seconds) * 1_000_000_000 + (int(fraction) * 1_000_000_000) // int(units)


def _read_pcap(path: Path, inventory: CaptureInventory):
    data = Path(path).read_bytes()
    if len(data) < 24:
        inventory.add_note(path, "pcap_too_short", {"bytes": len(data)})
        return
    magic = data[:4]
    endian, units = PCAP_MAGICS[magic]
    # Global header after magic: version(4), thiszone(4), sigfigs(4), snaplen(4), network(4)
    try:
        version_major, version_minor, _zone, _sigfigs, _snaplen, linktype = struct.unpack_from(
            endian + "HHIIII", data, 4
        )
    except struct.error:
        inventory.add_note(path, "pcap_header_invalid")
        return
    offset = 24
    index = 0
    truncated_file = False
    while offset + 16 <= len(data):
        ts_sec, ts_frac, incl_len, orig_len = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        if incl_len > MAX_BLOCK_BYTES or offset + incl_len > len(data):
            truncated_file = True
            break
        frame = data[offset:offset + incl_len]
        offset += incl_len
        packet = _parse_frame(
            path, index, _ts_ns(ts_sec, ts_frac, units), linktype, frame, orig_len
        )
        inventory.packets.append(packet)
        index += 1
    if truncated_file:
        inventory.add_note(path, "pcap_truncated_at_packet", {"packets_read": index})
    inventory.files.append({
        "path": str(path),
        "format": "pcap",
        "bytes": len(data),
        "sha256": sha256_file(path),
        "linktype": linktype,
        "version": f"{version_major}.{version_minor}",
        "packets": index,
    })


def _read_pcapng(path: Path, inventory: CaptureInventory):
    data = Path(path).read_bytes()
    offset = 0
    endian = "<"
    interfaces = []
    packet_index = 0
    truncated_file = False
    section = 0
    while offset + 12 <= len(data):
        block_type = struct.unpack_from(endian + "I", data, offset)[0]
        if block_type == 0x0A0D0D0A:
            # Section Header Block: the byte-order magic selects this section's endian.
            if offset + 12 > len(data):
                break
            bom = data[offset + 8:offset + 12]
            if bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                inventory.add_note(path, "pcapng_bad_byte_order_magic", {"offset": offset})
                break
            section += 1
            interfaces = []
        try:
            block_total = struct.unpack_from(endian + "I", data, offset + 4)[0]
        except struct.error:
            break
        if block_total < 12 or block_total > MAX_BLOCK_BYTES or offset + block_total > len(data):
            truncated_file = True
            break
        body = data[offset + 8:offset + block_total - 4]
        if block_type == 0x0A0D0D0A:
            # Interface list applies to the new section only.
            interfaces = []
        elif block_type == 1:  # IDB
            if len(body) < 8:
                inventory.add_note(path, "pcapng_idb_short", {"offset": offset})
            else:
                linktype, _reserved, snaplen = struct.unpack_from(endian + "HHI", body, 0)
                options = _parse_options(body[8:], endian)
                resolution = 1_000_000  # default microseconds
                if 9 in options and options[9]:
                    value = options[9][0][0]
                    if value & 0x80:
                        resolution = 1 << (value & 0x7f)
                    else:
                        resolution = 10 ** (value & 0x7f)
                interfaces.append({
                    "linktype": linktype,
                    "snaplen": snaplen,
                    "resolution": resolution,
                    "options": {key: [value.hex() for value in values] for key, values in options.items()},
                })
        elif block_type == 6:  # EPB
            if len(body) < 20:
                inventory.add_note(path, "pcapng_epb_short", {"offset": offset})
            else:
                interface_id, ts_high, ts_low, cap_len, orig_len = struct.unpack_from(
                    endian + "IIIII", body, 0
                )
                if interface_id >= len(interfaces):
                    inventory.add_note(path, "pcapng_epb_unknown_interface", {
                        "offset": offset, "interface_id": interface_id,
                    })
                else:
                    interface = interfaces[interface_id]
                    data_offset = 20
                    if data_offset + cap_len > len(body):
                        truncated_file = True
                        break
                    frame = body[data_offset:data_offset + cap_len]
                    option_offset = data_offset + cap_len + ((4 - cap_len % 4) % 4)
                    options = _parse_options(body[option_offset:], endian)
                    comment = None
                    if 1 in options and options[1]:
                        comment = options[1][0].decode("utf-8", "replace")
                    direction = None
                    if 2 in options and len(options[2][0]) >= 4:
                        flags = struct.unpack_from(endian + "I", options[2][0], 0)[0]
                        direction = {1: "inbound", 2: "outbound"}.get(flags & 0x3)
                    timestamp = (int(ts_high) << 32) | int(ts_low)
                    if interface["resolution"]:
                        time_ns = (timestamp * 1_000_000_000) // int(interface["resolution"])
                    else:
                        time_ns = None
                    packet = _parse_frame(
                        path, packet_index, time_ns, interface["linktype"], frame, orig_len
                    )
                    packet.comment = comment
                    packet.epb_direction = direction
                    packet.comment_fields = _comment_fields(comment)
                    if packet.comment_fields.get("pid"):
                        packet.process = {
                            "pid": packet.comment_fields["pid"],
                            "name": packet.comment_fields.get("process"),
                            "attribution": "pcapng_socket_owner",
                        }
                    if packet.comment_fields.get("socket") or packet.comment_fields.get("cookie"):
                        inode = packet.comment_fields.get("socket")
                        if isinstance(inode, str):
                            import re as _re
                            match = _re.search(r"\[(\d+)\]", inode)
                            inode = int(match.group(1)) if match else inode
                        packet.socket = {
                            "inode": inode,
                            "cookie": packet.comment_fields.get("cookie"),
                            "wineserver": packet.comment_fields.get("wineserver"),
                            "held": packet.comment_fields.get("held"),
                        }
                    inventory.packets.append(packet)
                    packet_index += 1
        elif block_type == 3:  # Simple Packet Block (no timestamp)
            if interfaces and len(body) >= 4:
                orig_len = struct.unpack_from(endian + "I", body, 0)[0]
                frame = body[4:]
                packet = _parse_frame(path, packet_index, None, interfaces[0]["linktype"], frame, orig_len)
                inventory.packets.append(packet)
                packet_index += 1
        offset += block_total
    if truncated_file:
        inventory.add_note(path, "pcapng_truncated_at_block", {"blocks_read": packet_index})
    inventory.files.append({
        "path": str(path),
        "format": "pcapng",
        "bytes": len(data),
        "sha256": sha256_file(path),
        "sections": section,
        "interfaces": interfaces,
        "packets": packet_index,
    })


def _comment_fields(comment):
    fields = {}
    if not comment:
        return fields
    for item in comment.split(";"):
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        if key == "pid":
            try:
                value = int(value)
            except ValueError:
                pass
        fields[key] = value
    return fields


def _read_uint(data, offset, size, endian="<"):
    if offset + size > len(data):
        return None
    if size == 1:
        return data[offset]
    if size == 2:
        return struct.unpack_from(endian + "H", data, offset)[0]
    if size == 4:
        return struct.unpack_from(endian + "I", data, offset)[0]
    if size == 8:
        return struct.unpack_from(endian + "Q", data, offset)[0]
    raise ValueError(size)


def _link_payload(data, linktype):
    """Return (ethertype or None, network bytes, notes)."""
    notes = []
    if linktype == LINKTYPE_ETHERNET:
        if len(data) < 14:
            return None, b"", ["ethernet_short"]
        ethertype = struct.unpack_from(">H", data, 12)[0]
        offset = 14
        while ethertype in (0x8100, 0x88A8, 0x9100):
            if offset + 4 > len(data):
                return None, b"", ["vlan_short"]
            ethertype = struct.unpack_from(">H", data, offset + 2)[0]
            offset += 4
        return ethertype, data[offset:], notes
    if linktype == LINKTYPE_LINUX_SLL:
        if len(data) < 16:
            return None, b"", ["sll_short"]
        return struct.unpack_from(">H", data, 14)[0], data[16:], notes
    if linktype == LINKTYPE_LINUX_SLL2:
        if len(data) < 20:
            return None, b"", ["sll2_short"]
        return struct.unpack_from(">H", data, 0)[0], data[20:], notes
    if linktype in (LINKTYPE_RAW, LINKTYPE_IPV4, LINKTYPE_IPV6):
        return None, data, notes
    if linktype in (LINKTYPE_NULL, LINKTYPE_LOOP):
        if len(data) < 4:
            return None, b"", ["null_short"]
        family_le = struct.unpack_from("<I", data, 0)[0]
        family_be = struct.unpack_from(">I", data, 0)[0]
        family = family_le if family_le in (2, 10, 24, 28, 30) else family_be
        if family == 2:
            return 0x0800, data[4:], notes
        if family in (10, 24, 28, 30):
            return 0x86DD, data[4:], notes
        return None, data[4:], ["null_family_unknown"]
    return None, b"", [f"unsupported_linktype_{linktype}"]


def _parse_frame(path, index, time_ns, linktype, frame, orig_len):
    packet = Packet(
        source_file=str(path),
        source_index=index,
        time_ns=time_ns,
        linktype=linktype,
        captured_len=len(frame),
        original_len=orig_len,
        truncated=len(frame) < (orig_len or 0),
    )
    ethertype, network, notes = _link_payload(frame, linktype)
    packet.notes.extend(notes)
    if not network:
        return packet
    version = network[0] >> 4
    if ethertype == 0x0800 or (ethertype is None and version == 4):
        _parse_ipv4(packet, network)
    elif ethertype == 0x86DD or (ethertype is None and version == 6):
        _parse_ipv6(packet, network)
    else:
        packet.notes.append(f"ethertype_{ethertype if ethertype is not None else 'unknown'}")
    return packet


def _parse_ipv4(packet, data):
    if len(data) < 20:
        packet.notes.append("ipv4_short")
        return
    version = data[0] >> 4
    ihl = (data[0] & 0x0F) * 4
    if version != 4 or ihl < 20 or ihl > len(data):
        packet.notes.append("ipv4_header_invalid")
        return
    total_length = struct.unpack_from(">H", data, 2)[0]
    protocol = data[9]
    flags_fragment = struct.unpack_from(">H", data, 6)[0]
    fragment_offset = flags_fragment & 0x1FFF
    more_fragments = bool(flags_fragment & 0x2000)
    packet.ip_version = 4
    packet.src = ".".join(str(byte) for byte in data[12:16])
    packet.dst = ".".join(str(byte) for byte in data[16:20])
    if total_length < ihl:
        packet.notes.append("ipv4_total_length_invalid")
        return
    payload = data[ihl:min(total_length, len(data))]
    if len(payload) + ihl < total_length:
        packet.notes.append("ipv4_capture_truncated")
    if fragment_offset or more_fragments:
        packet.notes.append("ipv4_fragment")
        if fragment_offset:
            return
    if protocol == 6:
        _parse_tcp(packet, payload)
    elif protocol == 17:
        _parse_udp(packet, payload)
    else:
        packet.notes.append(f"ip_protocol_{protocol}")


def _parse_ipv6(packet, data):
    if len(data) < 40:
        packet.notes.append("ipv6_short")
        return
    if data[0] >> 4 != 6:
        packet.notes.append("ipv6_version_invalid")
        return
    payload_length = struct.unpack_from(">H", data, 4)[0]
    next_header = data[6]
    packet.ip_version = 6
    packet.src = ":".join(f"{struct.unpack_from('>H', data, offset)[0]:x}" for offset in (8, 10, 12, 14, 16, 18, 20, 22))
    packet.dst = ":".join(f"{struct.unpack_from('>H', data, offset)[0]:x}" for offset in (24, 26, 28, 30, 32, 34, 36, 38))
    end = min(40 + payload_length, len(data))
    offset = 40
    fragment = False
    while next_header in (0, 43, 44, 51, 60):
        if offset + 2 > end:
            packet.notes.append("ipv6_extension_short")
            return
        header_length = (data[offset + 1] + 1) * 8
        if next_header == 44:
            fragment = True
            if len(data) < offset + 8:
                packet.notes.append("ipv6_fragment_short")
                return
            fragment_offset = struct.unpack_from(">H", data, offset + 2)[0] >> 3
            if fragment_offset:
                packet.notes.append("ipv6_fragment_nonfirst")
                return
        elif next_header == 51:
            header_length = (data[offset + 1] + 2) * 4
        next_header = data[offset]
        offset += header_length
        if offset > end:
            packet.notes.append("ipv6_extension_invalid")
            return
    if fragment:
        packet.notes.append("ipv6_fragment")
    payload = data[offset:end]
    if next_header == 6:
        _parse_tcp(packet, payload)
    elif next_header == 17:
        _parse_udp(packet, payload)
    elif next_header == 50:
        packet.notes.append("ipv6_esp_opaque")
    else:
        packet.notes.append(f"ipv6_next_header_{next_header}")


def _parse_tcp(packet, data):
    if len(data) < 20:
        packet.notes.append("tcp_short")
        return
    sport, dport, seq, ack = struct.unpack_from(">HHII", data, 0)
    data_offset = (data[12] >> 4) * 4
    flags = data[13]
    if data_offset < 20 or data_offset > len(data):
        packet.notes.append("tcp_header_invalid")
        return
    payload = data[data_offset:]
    packet.protocol = "tcp"
    packet.sport = sport
    packet.dport = dport
    packet.payload = payload
    packet.tcp = {
        "seq": seq,
        "ack": ack,
        "header_length": data_offset,
        "flags": {
            "fin": bool(flags & 0x01),
            "syn": bool(flags & 0x02),
            "rst": bool(flags & 0x04),
            "psh": bool(flags & 0x08),
            "ack": bool(flags & 0x10),
            "urg": bool(flags & 0x20),
        },
        "window": struct.unpack_from(">H", data, 14)[0],
    }


def _parse_udp(packet, data):
    if len(data) < 8:
        packet.notes.append("udp_short")
        return
    sport, dport, length = struct.unpack_from(">HHH", data, 0)
    if length < 8:
        packet.notes.append("udp_length_invalid")
        return
    packet.protocol = "udp"
    packet.sport = sport
    packet.dport = dport
    packet.payload = data[8:min(length, len(data))]
    if len(data) < length:
        packet.notes.append("udp_capture_truncated")
    packet.udp = {"length": length}


def discover_capture_files(paths):
    """Expand files/directories into pcap/pcapng parts, stable order."""
    result = []
    for value in paths:
        path = Path(value)
        if path.is_dir():
            candidates = []
            for pattern in ("*.pcap", "*.pcapng"):
                candidates.extend(path.glob(pattern))
            # monitor-filter stores parts as events.pcapng.1, events.pcapng.2, ...
            for candidate in path.iterdir():
                if candidate.is_file() and candidate.name.startswith("events.pcapng"):
                    candidates.append(candidate)
            unique = {}
            for candidate in candidates:
                if candidate.is_file():
                    unique[str(candidate.resolve())] = candidate
            def part_key(candidate):
                name = candidate.name
                suffix = name.rsplit(".", 1)[-1]
                return (name.rsplit(".", 1)[0], int(suffix) if suffix.isdigit() else 0, name)
            result.extend(sorted(unique.values(), key=part_key))
        elif path.is_file():
            result.append(path)
    return result


def read_packets(paths):
    inventory = CaptureInventory()
    for path in discover_capture_files(paths):
        path = Path(path)
        try:
            with open(path, "rb") as handle:
                magic = handle.read(4)
        except OSError as error:
            inventory.add_note(path, "open_failed", {"error": str(error)})
            continue
        if magic in PCAP_MAGICS:
            _read_pcap(path, inventory)
        elif magic == b"\x0a\x0d\x0d\x0a":
            _read_pcapng(path, inventory)
        else:
            inventory.add_note(path, "unknown_capture_format", {"magic": magic.hex()})
    inventory.packets.sort(key=lambda packet: (
        packet.time_ns if packet.time_ns is not None else 0,
        packet.source_file,
        packet.source_index,
    ))
    return inventory
