"""Synthetic capture builders used by the offline tests."""

from __future__ import annotations

import base64
import json
import socket
import struct
from pathlib import Path

from traffic.decode import PLAIN_TO_WIRE
from traffic.transport import SEND_MASK, get_new_iv, high_short, keystream


def game_body(opcode, values=None, length=36, fill=0):
    body = bytearray([fill] * length)
    struct.pack_into("<H", body, 0, opcode)
    for offset, raw in (values or {}).items():
        body[offset:offset + len(raw)] = raw
    return bytes(body)


def seal_frame(body, iv, layer=0):
    opcode = struct.unpack_from("<H", body, 0)[0]
    wire = bytearray(body)
    wire[0:2] = struct.pack("<H", PLAIN_TO_WIRE.get(opcode, opcode))
    stream = keystream(iv, len(wire), layer)
    ciphertext = bytes(left ^ right for left, right in zip(wire, stream))
    w0 = high_short(iv) ^ SEND_MASK
    w1 = w0 ^ len(ciphertext)
    return struct.pack("<HH", w0, w1) + ciphertext


def ipv4_tcp(src, dst, sport, dport, seq, ack, flags, payload=b""):
    tcp = struct.pack(
        ">HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0
    ) + payload
    total = 20 + len(tcp)
    ip = struct.pack(
        ">BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 6, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    )
    return ip + tcp


def ipv4_udp(src, dst, sport, dport, payload=b""):
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    total = 20 + len(udp)
    ip = struct.pack(
        ">BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 17, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    )
    return ip + udp


def dns_query(name, query_type=1, identifier=0x1234):
    labels = b"".join(bytes([len(part)]) + part.encode("ascii") for part in name.split(".")) + b"\x00"
    return struct.pack(">HHHHHH", identifier, 0x0100, 1, 0, 0, 0) + labels + struct.pack(">HH", query_type, 1)


def ethernet(ip):
    return b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00" + ip


def write_pcap(path, packets, start_seconds=1_700_000_000):
    """packets: list of (seconds_float, bytes)"""
    out = bytearray()
    out += struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for seconds, frame in packets:
        whole = int(seconds)
        micros = int(round((seconds - whole) * 1_000_000))
        if micros >= 1_000_000:
            whole += 1
            micros -= 1_000_000
        out += struct.pack("<IIII", whole, micros, len(frame), len(frame))
        out += frame
    Path(path).write_bytes(out)
    return path


def _block(block_type, body):
    total = len(body) + 12
    return struct.pack("<II", block_type, total) + body + struct.pack("<I", total)


def _option(code, value):
    return struct.pack("<HH", code, len(value)) + value + b"\x00" * ((4 - len(value) % 4) % 4)


def write_pcapng(path, packets, comment=None, linktype=101):
    """packets: list of (time_ns, bytes). Writes one interface with 100 ns resolution."""
    shb = _block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb_body = struct.pack("<HHI", linktype, 0, 65536)
    idb_body += _option(9, b"\x07") + _option(0, b"")
    out = bytearray(shb + _block(1, idb_body))
    for time_ns, frame in packets:
        stamp = time_ns // 100
        epb_body = struct.pack("<IIIII", 0, stamp >> 32, stamp & 0xFFFFFFFF, len(frame), len(frame))
        epb_body += frame + b"\x00" * ((4 - len(frame) % 4) % 4)
        epb_body += _option(2, struct.pack("<I", 2))
        if comment:
            epb_body += _option(1, comment.encode("utf-8"))
        epb_body += _option(0, b"")
        out += _block(6, epb_body)
    Path(path).write_bytes(out)
    return path


def write_plaintext_capture(path, sends, session_id="synthetic-session", pid=4242,
                            start_ns=1_700_000_000_000_000_000):
    """sends: list of (time_ns, body, construction_id)."""
    lines = []
    lines.append({
        "schema_version": 1, "session_id": session_id, "kind": "session_start",
        "wall_time_ns": start_ns, "monotonic_ns": 1, "pid": pid, "tid": pid,
        "event_index": 0, "module_base": "0x140000000",
        "pe_timestamp": 0x6AEB667B, "sendpacket_rva": "0x1661780",
        "constructor_rva": "0x7614b0", "duration_seconds": 60,
    })
    index = 1
    for send_index, (time_ns, body, construction_id) in enumerate(sends):
        opcode = struct.unpack_from("<H", body, 0)[0]
        if construction_id:
            lines.append({
                "schema_version": 1, "session_id": session_id, "kind": "constructor",
                "wall_time_ns": time_ns - 1000, "monotonic_ns": index, "pid": pid,
                "tid": pid, "event_index": index, "construction_id": construction_id,
                "packet": 0x1000 + send_index * 0x100,
                "packet_va": hex(0x1000 + send_index * 0x100),
                "opcode": hex(opcode), "deep_gap": False,
                "registers": {"rcx": "0x1000", "rdx": hex(opcode), "rsp": "0x7000"},
                "caller": {"address": "0x140001234", "rva": "0x1234"},
                "return_stack": [{"address": "0x140001234", "rva": "0x1234"}],
            })
            lines.append({
                "schema_version": 1, "session_id": session_id, "kind": "field_change",
                "wall_time_ns": time_ns - 500, "monotonic_ns": index, "pid": pid,
                "tid": pid, "event_index": index, "construction_id": construction_id,
                "opcode": hex(opcode), "packet_va": hex(0x1000 + send_index * 0x100),
                "previous_length": 2, "length": len(body), "body": body.hex(),
                "rip_after_write": "0x14000abcd", "rva_after_write": "0xabcd",
                "registers": {"rcx": "0x1000", "rdx": "0x10", "rsp": "0x7000"},
                "caller": {"address": "0x14000abcd", "rva": "0xabcd"},
                "return_stack": [{"address": "0x14000abcd", "rva": "0xabcd"}],
                "floating_registers": "00" * 512,
            })
        lines.append({
            "schema_version": 1, "session_id": session_id, "kind": "send",
            "wall_time_ns": time_ns, "monotonic_ns": index + 1, "pid": pid, "tid": pid,
            "event_index": index + 1, "direction": "client_to_server",
            "construction_id": construction_id, "constructor_missing": construction_id is None,
            "opcode": hex(opcode), "packet_va": hex(0x1000 + send_index * 0x100),
            "body_va": hex(0x1008 + send_index * 0x100), "length": len(body),
            "body": body.hex(), "registers": {"rcx": "0x1000", "rsp": "0x7000"},
            "caller": {"address": "0x140001234", "rva": "0x1234"},
            "return_stack": [{"address": "0x140001234", "rva": "0x1234"}],
            "dropped": False,
        })
        index += 2
    lines.append({
        "schema_version": 1, "session_id": session_id, "kind": "session_end",
        "wall_time_ns": start_ns + 60_000_000_000, "monotonic_ns": index, "pid": pid,
        "tid": pid, "event_index": index,
        "counts": {"events": index, "sends": len(sends), "constructors": len(sends)},
    })
    Path(path).write_text("\n".join(json.dumps(line) for line in lines) + "\n", encoding="utf-8")
    return path


def tls_client_hello(host):
    host_bytes = host.encode("ascii") if isinstance(host, str) else host
    sni = struct.pack(">H", len(host_bytes) + 3) + b"\x00" + struct.pack(">H", len(host_bytes)) + host_bytes
    extension = struct.pack(">HH", 0, len(sni)) + sni
    hello = (
        b"\x03\x03" + b"\x00" * 32 + b"\x00"
        + struct.pack(">H", 2) + b"\x00\x2f"
        + b"\x01\x00"
        + struct.pack(">H", len(extension)) + extension
    )
    handshake = b"\x01" + struct.pack(">I", len(hello))[1:] + hello
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


def tls_record(content_type, payload):
    return bytes([content_type]) + b"\x03\x03" + struct.pack(">H", len(payload)) + payload


def ng_s_response(payload, key=42):
    from traffic.decode import ngs_cipher
    return base64.b64encode(ngs_cipher.encrypt_response(
        json.dumps(payload).encode("utf-8"), key
    )).decode("ascii")
