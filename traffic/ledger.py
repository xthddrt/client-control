"""Build one ordered, evidence-labelled client->server ledger from captures."""

from __future__ import annotations

import base64
import ipaddress
import json
import time
import uuid
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from .decode import (
    GAME_OPCODES,
    decode_dns_query,
    decode_game,
    decode_http_request,
    decode_ngs_response,
    tls_client_hello_sni,
)
from .game import decrypt_frames, join_frames, parse_frames
from .monitor import load_monitor
from .ngs import load_ngs
from .pcap import read_packets
from .plaintext import load_plaintext
from .policy import evaluate, load_policy
from .tcp import assemble
from .util import (
    as_bytes,
    canonical_json,
    format_ns,
    merge_ranges,
    sha256_bytes,
    subtract_ranges,
)

SCHEMA = "client-control.traffic/v1"
MAX_CHUNK_BYTES = 64 * 1024
DEFAULT_JOIN_WINDOW_NS = 5_000_000_000
LIMITATIONS = [
    "A pcap/pcapng capture records packets, not the application's intent; a dropped packet has no wire frame.",
    "TCP gaps are reported and never filled with zero bytes. A message spanning a gap is marked incomplete.",
    "The observed wire opcode is an alias for some opcodes. It is mapped only where docs/guides/PACKETS.md records evidence.",
    "Transport decryption requires a unique IV seed from two consecutive headers; otherwise only ciphertext is kept.",
    "NGS request bodies use a device-bound cipher that is not broken here; only their exact bytes and HTTP metadata are recorded.",
    "TLS application data is recorded as opaque records unless a proxy or a TLS plaintext source supplies the plaintext.",
    "Plaintext constructor/register/stack evidence exists only when the in-process capture was armed for that process/thread.",
    "Missing fields are marked missing. Timing alone is not offered as proof of a crash or malfunction cause.",
]


@dataclass
class Ledger:
    records: list[dict] = field(default_factory=list)
    flows: list[dict] = field(default_factory=list)
    decisions: list[dict] = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    session: dict = field(default_factory=dict)


def _id(prefix, *parts):
    digest = sha256_bytes(canonical_json(parts).encode("utf-8"))[:20]
    return f"{prefix}-{digest}"


def _hex(value):
    return None if value is None else f"0x{value:x}"


def _basename(path):
    if not path:
        return None
    return str(path).replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]


def _process_index(monitor, plaintext):
    index = {}
    for event in monitor.processes:
        if event.get("kind") == "process_start" and event.get("pid"):
            index[event["pid"]] = {
                "pid": event["pid"],
                "name": _basename(event.get("path")),
                "path": event.get("path"),
                "time_ns": event.get("time_ns"),
                "source": event.get("source"),
            }
    start = plaintext.session_start or {}
    pid = start.get("pid")
    if pid is not None and pid not in index:
        index[pid] = {
            "pid": pid,
            "name": "MapleStory.exe" if start.get("constructor_rva") else None,
            "path": None,
            "source": start.get("source_file"),
        }
    return index


def _process_record(pid=None, name=None, path=None, attribution="missing", missing_reason=None,
                    build=None, candidates=None):
    record = {
        "pid": pid,
        "name": name or _basename(path),
        "path": path,
        "attribution": attribution,
    }
    if build:
        record["build"] = build
        if build.get("pe_timestamp") is not None:
            record["build_timestamp"] = build.get("pe_timestamp")
        if build.get("module_base") is not None:
            record["module_base"] = build.get("module_base")
    if candidates:
        record["candidates"] = candidates
    if missing_reason:
        record["missing_reason"] = missing_reason
    return record


def _build_index(plaintext, monitor, profile):
    build = {}
    start = plaintext.session_start or {}
    if start.get("pe_timestamp") is not None:
        build.update({
            "pe_timestamp": start.get("pe_timestamp"),
            "module_base": start.get("module_base"),
            "sendpacket_rva": start.get("sendpacket_rva"),
            "constructor_rva": start.get("constructor_rva"),
            "source": "client-control outgoing session_start",
        })
    if profile:
        pe = profile.get("pe") or {}
        if "pe_timestamp" not in build and pe.get("timestamp") is not None:
            build.update({
                "pe_timestamp": pe.get("timestamp"),
                "image_size": pe.get("size_of_image"),
                "source": "foundations/profile.json",
            })
        build.setdefault("profile_process", profile.get("process_name"))
    meta = monitor.session_meta or {}
    if meta:
        for key in ("client_version", "client_sha256", "build_commit", "build_info_sha256"):
            if meta.get(key):
                build[key] = meta[key]
        build.setdefault("source", "monitor session_meta")
    return build


def _source_sessions(plaintext, monitor):
    sessions = []
    start = plaintext.session_start or {}
    if start.get("session_id"):
        sessions.append({
            "kind": "client_control_outgoing",
            "session_id": start.get("session_id"),
            "pid": start.get("pid"),
            "source": start.get("source_file"),
        })
    meta = monitor.session_meta or monitor.manifest or {}
    if meta.get("session_uuid") or meta.get("session_id"):
        sessions.append({
            "kind": "monitor_session",
            "session_uuid": meta.get("session_uuid"),
            "session_id": meta.get("session_id"),
            "test_id": meta.get("test_id"),
            "started_utc": meta.get("started_utc"),
        })
    return sessions


def _flow_process(flow, monitor, plaintext, process_index):
    if flow.process and flow.process.get("pid"):
        pid = flow.process.get("pid")
        known = process_index.get(pid, {})
        return _process_record(
            pid=pid,
            name=flow.process.get("name") or known.get("name"),
            path=known.get("path"),
            attribution="pcapng_socket_owner",
            candidates=flow.process.get("candidates"),
        )
    # Match a monitor network call or flow event by remote endpoint and time.
    candidates = []
    start = flow.c2s.first_time_ns if flow.c2s else None
    end = flow.c2s.last_time_ns if flow.c2s else None
    for call in monitor.calls:
        if call.endpoint is None or flow.server is None:
            continue
        if tuple(call.endpoint) != tuple(flow.server):
            continue
        if call.pid is None:
            continue
        if start is not None and call.time_ns is not None:
            if call.time_ns < start - 10_000_000_000 or call.time_ns > (end or start) + 10_000_000_000:
                continue
        candidates.append(call)
    if candidates:
        candidates.sort(key=lambda call: abs((call.time_ns or 0) - (start or 0)))
        call = candidates[0]
        known = process_index.get(call.pid, {})
        return _process_record(
            pid=call.pid,
            name=known.get("name"),
            path=known.get("path"),
            attribution="monitor_network_call",
        )
    # Plaintext capture PID is a game-process fallback only when the endpoints are
    # consistent with the capture; the caller decides that, not this function.
    return _process_record(
        attribution="missing",
        missing_reason="no pcapng socket owner and no monitor network call matched this flow",
    )


def _message_transport(flow, process, destination_override=None, protocol="tcp"):
    destination = dict(destination_override or {})
    if flow is not None and flow.server and not destination_override:
        destination["ip"] = flow.server[0]
        destination["port"] = flow.server[1]
    source = None
    if flow is not None and flow.client:
        source = {"ip": flow.client[0], "port": flow.client[1]}
    return {
        "protocol": protocol,
        "direction": "client_to_server",
        "source": source,
        "destination": destination or None,
        "socket": (flow.sockets[0] if flow is not None and flow.sockets else None),
        "capture": {
            "source": "pcap",
            "flow": {
                "client": list(flow.client) if flow and flow.client else None,
                "server": list(flow.server) if flow and flow.server else None,
                "protocol": flow.protocol if flow else None,
                "connection_index": flow.connection_index if flow else None,
            },
        },
    }


def _message_base(ledger_session_id, build, source_sessions, record_id, time_ns,
                  process, transport, protocol, raw, message_fields, decode_status,
                  reconstruction, provenance, notes, transmitted=True):
    return {
        "schema": SCHEMA,
        "record_type": "message",
        "ledger_session_id": ledger_session_id,
        "message_id": record_id,
        "time_ns": time_ns,
        "time_utc": format_ns(time_ns),
        "source_sessions": source_sessions,
        "build": build,
        "process": process,
        "transport": transport,
        "message": {
            "protocol": protocol,
            "direction": "client_to_server",
            "type": message_fields.get("type"),
            "raw_bytes_hex": raw.hex() if raw is not None else None,
            "raw_bytes_length": len(raw) if raw is not None else None,
            "raw_bytes_sha256": sha256_bytes(raw) if raw is not None else None,
            "raw_bytes_encoding": message_fields.get("encoding", "plaintext"),
            "fields": message_fields.get("fields", []),
            "unparsed": message_fields.get("unparsed", []),
            "decode_status": decode_status,
            "notes": message_fields.get("notes", []),
        },
        "reconstruction": reconstruction,
        "provenance": provenance,
        "transmitted": transmitted,
        "notes": notes,
    }


def _game_type(opcode, decoded):
    return {
        "opcode": opcode,
        "opcode_hex": _hex(opcode),
        "name": decoded.get("name"),
        "confidence": decoded.get("confidence"),
        "evidence": decoded.get("evidence", []),
    }


def _game_message(game_frame, item, send, plaintext, flow, monitor, process,
                  ledger_session_id, build, source_sessions, decryption):
    if send is not None and (process or {}).get("pid") is None and send.pid is not None:
        process = _process_record(
            pid=send.pid,
            name=build.get("profile_process") or "MapleStory.exe",
            attribution="client_control_send",
            build=build,
        )
    if send is not None:
        body = send.body
        opcode = send.opcode
        decoded = decode_game(body, opcode)
        construction = plaintext.construction_for(send)
        provenance = {
            "in_process": True,
            "send": {
                "source": send.source_file,
                "source_index": send.source_index,
                "session_id": send.session_id,
                "pid": send.pid,
                "tid": send.tid,
                "time_ns": send.time_ns,
                "opcode": send.opcode_hex,
                "length": len(send.body),
                "registers": send.registers,
                "caller": send.caller,
                "return_stack": send.return_stack,
                "dropped": send.dropped,
            },
            "constructor": None,
            "serialization_steps": [],
            "memory_activity": None,
            "inputs": {
                "send_registers": send.registers,
                "constructor_registers": None,
                "documented_roles": {
                    "rcx": "COutPacket pointer at SendPacket and constructor",
                    "rdx": "opcode at the constructor",
                },
                "note": "Other register arguments are preserved raw; their roles are not assumed.",
            },
            "plaintext_match": {
                "frame_index": game_frame.index,
                "time_delta_ns": None,
                "method": "body suffix and opcode matched the wire frame",
            },
            "missing": [],
            "evidence": [f"client-control:{send.source_file}:{send.source_index}"],
        }
        if construction is not None:
            steps = construction.steps()
            provenance["constructor"] = {
                "construction_id": construction.construction_id,
                "source": construction.source_file,
                "source_index": construction.source_index,
                "time_ns": construction.time_ns,
                "opcode": _hex(construction.opcode),
                "packet_va": construction.packet_va,
                "registers": construction.registers,
                "caller": construction.caller,
                "return_stack": construction.return_stack,
                "field_change_count": len(steps),
                "evidence": [f"client-control:{construction.source_file}:{construction.source_index}"],
            }
            provenance["inputs"]["constructor_registers"] = construction.registers
            provenance["serialization_steps"] = steps
            provenance["memory_activity"] = {
                "field_change_count": len(steps),
                "step_bodies": len([step for step in steps if step.get("body_hex")]),
                "note": "Each step is a length-watch snapshot of the plaintext body; changed_ranges compares consecutive snapshots.",
            }
            if not steps:
                provenance["missing"].append({
                    "field": "serialization_steps",
                    "reason": "deep in-process length tracing was not enabled for this opcode",
                })
        else:
            provenance["missing"].append({
                "field": "constructor",
                "reason": "the send record has no linked constructor in this capture",
            })
        encoding = "plaintext"
        transmitted = not send.dropped
        raw = body
    else:
        body = item.plaintext if item is not None else None
        opcode = item.opcode if item is not None else None
        decoded = decode_game(body, opcode) if body is not None and opcode is not None else {
            "name": None, "confidence": "unknown", "evidence": [],
            "fields": [], "unparsed": [], "notes": ["frame could not be decrypted or mapped"],
        }
        provenance = {
            "in_process": False,
            "send": None,
            "constructor": None,
            "serialization_steps": [],
            "memory_activity": None,
            "inputs": None,
            "plaintext_match": None,
            "missing": [
                {"field": "send", "reason": "no SendPacket record matched this wire frame"},
                {"field": "inputs", "reason": "register/memory inputs require an in-process capture"},
                {"field": "constructor", "reason": "constructor evidence requires an in-process capture"},
                {"field": "registers", "reason": "registers are available only in-process"},
                {"field": "return_stack", "reason": "caller stack is available only in-process"},
            ],
            "evidence": [f"pcap:{game_frame.stream.src}:{game_frame.stream.sport}->{game_frame.stream.dst}:{game_frame.stream.dport}",
                         f"frame:{game_frame.index}"],
        }
        encoding = "plaintext" if body is not None else "wire_ciphertext"
        transmitted = True
        raw = body if body is not None else game_frame.ciphertext
    reconstruction = {
        "wire": game_frame.summary(),
        "split": game_frame.split,
        "combined": game_frame.combined,
        "retransmitted": any(segment.classification in ("retransmission", "conflict", "partial_overlap")
                             for segment in game_frame.segments),
        "segments": game_frame.source_refs,
        "decryption": {
            "status": item.status if item else "missing",
            "iv": item.iv if item else None,
            "wire_alias": _hex(item.alias) if item and item.alias is not None else None,
            "opcode_confidence": item.opcode_confidence if item else None,
            "layer": item.layer if item else None,
        } if item else {"status": "missing"},
        "stream_gaps": list(game_frame.stream.gaps()),
        "remaining_missing_ranges": [],
    }
    if game_frame.stream.gaps():
        provenance["missing"].append({
            "field": "stream_bytes",
            "reason": "TCP capture has gaps; frames spanning a gap are not emitted as complete messages",
            "ranges": list(game_frame.stream.gaps()),
        })
    type_record = _game_type(opcode, decoded) if opcode is not None else {
        "opcode": None, "opcode_hex": None, "name": None, "confidence": "unknown",
        "evidence": ["decryption did not yield a mapped opcode"],
    }
    fields = {
        "type": type_record,
        "encoding": encoding,
        "fields": decoded.get("fields", []),
        "unparsed": decoded.get("unparsed", []),
        "notes": decoded.get("notes", []),
    }
    transport = _message_transport(flow, process, protocol="maplestory_game")
    transport["socket"] = (flow.sockets[0] if flow.sockets else None)
    message_id = _id("ccm", "game", send.source_file if send else game_frame.stream.src,
                     send.source_index if send else game_frame.index,
                     send.time_ns if send else game_frame.first_time_ns,
                     sha256_bytes(raw) if raw is not None else None)
    return _message_base(
        ledger_session_id, build, source_sessions, message_id,
        send.time_ns if send and send.time_ns is not None else game_frame.first_time_ns,
        process, transport, "maplestory_game", raw, fields,
        decoded.get("decode_status", "unknown"), reconstruction, provenance,
        decoded.get("notes", []), transmitted=transmitted,
    ), (game_frame.offset, game_frame.offset + 4 + game_frame.length)


def _send_only_message(send, plaintext, process, ledger_session_id, build,
                       source_sessions, reason):
    if (process or {}).get("pid") is None and send.pid is not None:
        process = _process_record(
            pid=send.pid,
            name=build.get("profile_process") or "MapleStory.exe",
            attribution="client_control_send",
            build=build,
        )
    decoded = decode_game(send.body, send.opcode)
    construction = plaintext.construction_for(send)
    steps = construction.steps() if construction else []
    provenance = {
        "in_process": True,
        "send": {
            "source": send.source_file,
            "source_index": send.source_index,
            "session_id": send.session_id,
            "pid": send.pid,
            "tid": send.tid,
            "time_ns": send.time_ns,
            "opcode": send.opcode_hex,
            "length": len(send.body),
            "registers": send.registers,
            "caller": send.caller,
            "return_stack": send.return_stack,
            "dropped": send.dropped,
        },
        "constructor": None,
        "serialization_steps": steps,
        "memory_activity": {"field_change_count": len(steps)} if steps else None,
        "inputs": {
            "send_registers": send.registers,
            "constructor_registers": construction.registers if construction else None,
            "documented_roles": {
                "rcx": "COutPacket pointer at SendPacket and constructor",
                "rdx": "opcode at the constructor",
            },
            "note": "Other register arguments are preserved raw; their roles are not assumed.",
        },
        "plaintext_match": None,
        "missing": [{
            "field": "wire_frame",
            "reason": reason,
        }],
        "evidence": [f"client-control:{send.source_file}:{send.source_index}"],
    }
    if construction is not None:
        provenance["constructor"] = {
            "construction_id": construction.construction_id,
            "source": construction.source_file,
            "source_index": construction.source_index,
            "time_ns": construction.time_ns,
            "opcode": _hex(construction.opcode),
            "packet_va": construction.packet_va,
            "registers": construction.registers,
            "caller": construction.caller,
            "return_stack": construction.return_stack,
            "field_change_count": len(steps),
        }
    else:
        provenance["missing"].append({
            "field": "constructor",
            "reason": "the send record has no linked constructor in this capture",
        })
    transport = {
        "protocol": "maplestory_game",
        "direction": "client_to_server",
        "source": None,
        "destination": None,
        "socket": None,
        "capture": {"source": "in_process_only", "note": "no matching wire frame was available"},
    }
    message_id = _id("ccm", "send", send.source_file, send.source_index, send.time_ns,
                     sha256_bytes(send.body))
    return _message_base(
        ledger_session_id, build, source_sessions, message_id, send.time_ns,
        process, transport, "maplestory_game", send.body,
        {"type": _game_type(send.opcode, decoded), "encoding": "plaintext",
         "fields": decoded.get("fields", []), "unparsed": decoded.get("unparsed", []),
         "notes": decoded.get("notes", [])},
        decoded.get("decode_status", "unknown"),
        {"wire": None, "split": False, "combined": False, "retransmitted": False,
         "segments": [], "decryption": {"status": "not_available"}},
        provenance, decoded.get("notes", []), transmitted=not send.dropped,
    ), None


def _tls_records(stream):
    records = []
    for run_start, run_end in stream.runs():
        offset = run_start
        while offset + 5 <= run_end:
            content_type = stream.data[offset]
            version = int.from_bytes(stream.data[offset + 1:offset + 3], "big")
            length = int.from_bytes(stream.data[offset + 3:offset + 5], "big")
            if content_type not in (20, 21, 22, 23) or version < 0x0300 or length > 0x4800:
                break
            end = offset + 5 + length
            if end > run_end:
                break
            payload = bytes(stream.data[offset + 5:end])
            records.append({
                "offset": offset,
                "end": end,
                "content_type": content_type,
                "version": version,
                "length": length,
                "payload": payload,
                "wire": bytes(stream.data[offset:end]),
                "segments": stream.contributing_segments(offset, end),
                "first_time_ns": stream.first_time_for(offset, end),
                "last_time_ns": stream.last_time_for(offset, end),
            })
            offset = end
    return records


def _http_requests(stream):
    requests = []
    for run_start, run_end in stream.runs():
        offset = run_start
        while offset < run_end:
            window = bytes(stream.data[offset:run_end])
            header_end = window.find(b"\r\n\r\n")
            if header_end < 0:
                break
            parsed = decode_http_request(window[:header_end + 4])
            content_length = parsed.get("declared_body_length")
            if content_length is None:
                content_length = 0
            total = parsed["header_bytes"] + content_length
            if total > len(window):
                break
            end = offset + total
            requests.append({
                "offset": offset,
                "end": end,
                "request": parsed,
                "wire": bytes(stream.data[offset:end]),
                "segments": stream.contributing_segments(offset, end),
                "first_time_ns": stream.first_time_for(offset, end),
                "last_time_ns": stream.last_time_for(offset, end),
            })
            offset = end
            if total == 0:
                break
    return requests


def _sni_for_flow(flow):
    if flow.c2s is None:
        return None
    for record in _tls_records(flow.c2s):
        if record["content_type"] == 22:
            sni = tls_client_hello_sni(record["wire"])
            if sni:
                return sni
    return None


def _monitor_fallback_flows(monitor, calls=None):
    """Build synthetic streams from monitor network_data sends."""
    groups = {}
    for call in (monitor.calls if calls is None else calls):
        if call.direction != "send" or not call.data:
            continue
        key = (call.pid, call.socket_inode, call.endpoint)
        groups.setdefault(key, []).append(call)
    flows = []
    for (pid, inode, endpoint), calls in groups.items():
        calls.sort(key=lambda call: (call.time_ns or 0, call.source_index))
        data = b"".join(call.data for call in calls)
        if not data:
            continue
        # A small shim object with the Stream surface used by the decoders.
        stream = _SyntheticStream(
            src="monitor",
            sport=0,
            dst=(calls[0].endpoint[0] if calls[0].endpoint else "unknown"),
            dport=(calls[0].endpoint[1] if calls[0].endpoint else 0),
            data=bytearray(data),
            coverage=[(0, len(data))],
            first_time_ns=calls[0].time_ns,
            last_time_ns=calls[-1].time_ns,
        )
        flow = _SyntheticFlow(stream=stream, pid=pid, inode=inode,
                              remote=endpoint or calls[0].endpoint)
        flows.append(flow)
    return flows


class _SyntheticStream:
    def __init__(self, src, sport, dst, dport, data, coverage, first_time_ns, last_time_ns):
        self.src = src
        self.sport = sport
        self.dst = dst
        self.dport = dport
        self.data = data
        self.coverage = coverage
        self.first_time_ns = first_time_ns
        self.last_time_ns = last_time_ns
        self._segments = []

    def runs(self):
        return list(self.coverage)

    def gaps(self):
        return []

    def missing_ranges(self, start, end):
        return []

    def contributing_segments(self, start, end):
        return []

    def first_time_for(self, start, end):
        return self.first_time_ns

    def last_time_for(self, start, end):
        return self.last_time_ns


class _SyntheticFlow:
    def __init__(self, stream, pid, inode, remote):
        self.protocol = "tcp"
        self.client = None
        self.server = remote
        self.connection_index = 0
        self.process = {"pid": pid, "name": None, "attribution": "monitor_network_data"}
        self.sockets = [{"inode": inode}]
        self.c2s = stream
        self.s2c = None

    @property
    def endpoints(self):
        return (("monitor", 0), self.server)

    def summary(self):
        return {
            "protocol": "tcp",
            "endpoints": [list(endpoint) if endpoint else None for endpoint in self.endpoints],
            "client": None,
            "server": list(self.server) if self.server else None,
            "process": self.process,
            "sockets": self.sockets,
            "c2s": {
                "src": self.c2s.src,
                "dst": self.c2s.dst,
                "unique_bytes": len(self.c2s.data),
                "coverage": self.c2s.coverage,
                "note": "synthetic stream from monitor network_data sends; no TCP sequence numbers or retransmissions",
            },
            "s2c": None,
        }


def _monitor_metadata_flows(monitor, pcap_flows, ledger_session_id, build,
                            source_sessions, process_index=None):
    """Flow records for monitor lifecycle events not represented by a pcap flow."""
    pcap_keys = set()
    pcap_inodes = set()
    for flow in pcap_flows:
        if flow.client and flow.server:
            pcap_keys.add(tuple(sorted((tuple(flow.client), tuple(flow.server)))))
        for socket in flow.sockets:
            if socket.get("inode") is not None:
                pcap_inodes.add(socket["inode"])
    records = []
    seen = set()
    for event in monitor.flows:
        if event.kind not in ("network_connect", "network_accept", "network_flow_established"):
            continue
        if event.local and event.remote:
            key = (event.pid, event.socket_inode,
                   tuple(sorted((tuple(event.local), tuple(event.remote)))))
            if tuple(sorted((tuple(event.local), tuple(event.remote)))) in pcap_keys:
                continue
        else:
            key = (event.pid, event.socket_inode, event.local, event.remote)
        if event.socket_inode is not None and event.socket_inode in pcap_inodes:
            continue
        if key in seen:
            continue
        seen.add(key)
        protocol = "tcp"
        if event.value1:
            number = (int(event.value1) >> 32) & 0xFF
            protocol = {6: "tcp", 17: "udp", 1: "icmp"}.get(number, "unknown")
        record = {
            "schema": SCHEMA,
            "record_type": "flow",
            "ledger_session_id": ledger_session_id,
            "flow_id": _id("flow", "monitor", key),
            "time_ns": event.time_ns,
            "time_utc": format_ns(event.time_ns),
            "source_sessions": source_sessions,
            "build": build,
            "process": {
                "pid": event.pid,
                "name": (process_index or {}).get(event.pid, {}).get("name"),
                "path": (process_index or {}).get(event.pid, {}).get("path"),
                "attribution": "monitor_flow_event",
            },
            "transport": {
                "protocol": protocol,
                "direction": "client_to_server",
                "source": {"ip": event.local[0], "port": event.local[1]} if event.local else None,
                "destination": {"ip": event.remote[0], "port": event.remote[1]} if event.remote else None,
                "socket": {"inode": event.socket_inode},
                "capture": {"source": "monitor_event"},
            },
            "flow": {
                "protocol": protocol,
                "source": "monitor_flow_event",
                "event": event.summary(),
                "raw_bytes_available": False,
                "note": "Monitor lifecycle metadata only; this source/session did not supply packet bytes.",
            },
        }
        records.append(record)
    return records


def _monitor_extra_flows(monitor, pcap_flows, window_ns=5_000_000_000):
    """Monitor send calls not covered by a pcap flow; pcap remains the primary source."""
    ranges = []
    for flow in pcap_flows:
        if flow.server is None:
            continue
        start = flow.c2s.first_time_ns if flow.c2s else None
        end = flow.c2s.last_time_ns if flow.c2s else None
        ranges.append((tuple(flow.server), start, end, flow.sockets))
    selected = []
    for call in monitor.calls:
        if call.direction != "send" or not call.data:
            continue
        covered = False
        for server, start, end, sockets in ranges:
            if call.endpoint is not None and tuple(call.endpoint) == server:
                if call.time_ns is None or start is None:
                    covered = True
                elif start - window_ns <= call.time_ns <= (end or start) + window_ns:
                    covered = True
            if call.socket_inode is not None and any(
                socket.get("inode") == call.socket_inode for socket in sockets
            ):
                covered = True
            if covered:
                break
        if not covered:
            selected.append(call)
    return _monitor_fallback_flows(monitor, selected)


def _process_synthetic_flow(flow, process, ledger_session_id, build_info,
                            source_sessions, monitor, plaintext, matched_send_orders,
                            include_chunks):
    records = [_flow_record(flow, process, ledger_session_id, build_info, source_sessions)]
    c2s = flow.c2s
    if c2s is None or not c2s.data:
        return records
    first = bytes(c2s.data[:8])
    is_tls = len(first) >= 3 and first[0] in (20, 21, 22, 23) and first[1] == 0x03
    covered = []
    if is_tls:
        for tls_record in _tls_records(c2s):
            message, span = _tls_message(
                flow, tls_record, process, ledger_session_id, build_info,
                source_sessions, sni=tls_client_hello_sni(tls_record["wire"]),
            )
            message.setdefault("reconstruction", {})["capture_source"] = "monitor_network_data"
            records.append(message)
            if span:
                covered.append(span)
    else:
        frames, frame_notes = parse_frames(c2s)
        decryption = decrypt_frames(frames, plaintext.sends)
        matches, _, _ = join_frames(frames, decryption, plaintext.sends, 5_000_000_000)
        for frame in frames:
            match = matches.get(frame.index)
            send = match["send"] if match else None
            item = decryption.by_index().get(frame.index)
            if send is not None:
                matched_send_orders.add(match["order"])
            if send is None and (item is None or item.plaintext is None):
                continue
            message, span = _game_message(
                frame, item, send, plaintext, flow, monitor, process,
                ledger_session_id, build_info, source_sessions, decryption,
            )
            message.setdefault("reconstruction", {})["capture_source"] = "monitor_network_data"
            records.append(message)
            if span:
                covered.append(span)
    if include_chunks:
        records.extend(_chunk_records(
            flow, process, ledger_session_id, build_info, source_sessions,
            merge_ranges(covered), ["unclaimed bytes in a monitor network_data flow"],
        ))
    return records


def _tls_message(flow, record, process, ledger_session_id, build, source_sessions,
                 sni=None):
    content_type = record["content_type"]
    if content_type == 22 and sni is None:
        sni = tls_client_hello_sni(record["wire"])
    kind = {
        20: "tls_change_cipher_spec",
        21: "tls_alert",
        22: "tls_handshake",
        23: "tls_application_data",
    }.get(content_type, "tls_record")
    fields = []
    type_record = {
        "opcode": None,
        "opcode_hex": None,
        "name": kind,
        "confidence": "confirmed",
        "evidence": ["tls_record_header"],
    }
    if content_type == 22:
        handshake_type = record["payload"][0] if record["payload"] else None
        fields.append({
            "name": "handshake_type",
            "offset": 5,
            "size": 1,
            "kind": "u8",
            "value": handshake_type,
            "raw_hex": record["wire"][5:6].hex(),
            "confidence": "confirmed",
            "evidence": ["tls_record_header"],
        })
        if sni:
            fields.append({
                "name": "server_name",
                "offset": 5,
                "size": len(sni),
                "kind": "string",
                "value": sni,
                "confidence": "confirmed",
                "evidence": ["TLS ClientHello server_name extension"],
            })
            type_record["name"] = "tls_client_hello"
            type_record["confidence"] = "confirmed"
    destination = {"port": 443}
    if sni:
        destination["host"] = sni
    elif flow.server:
        destination["ip"] = flow.server[0]
        destination["port"] = flow.server[1]
    transport = _message_transport(flow, process, destination_override=destination,
                                   protocol="tls")
    reconstruction = {
        "wire": {
            "tls_offset": record["offset"],
            "tls_length": record["length"],
            "content_type": content_type,
            "version": f"0x{record['version']:04x}",
            "wire_hex": record["wire"].hex(),
            "segments": [
                {"source": segment.packet.source_file, "source_index": segment.packet.source_index,
                 "classification": segment.classification}
                for segment in record["segments"]
            ],
        },
        "split": len(record["segments"]) > 1,
        "combined": False,
        "retransmitted": any(segment.classification in ("retransmission", "conflict", "partial_overlap")
                             for segment in record["segments"]),
    }
    provenance = {
        "in_process": False,
        "send": None,
        "constructor": None,
        "serialization_steps": [],
        "memory_activity": None,
        "missing": [{
            "field": "plaintext",
            "reason": "TLS application data is opaque in this capture; use the NGS proxy log or --tls-keylog",
        }] if content_type == 23 else [],
        "evidence": ["pcap TLS record"],
    }
    message_id = _id("ccm", "tls", flow.server, record["offset"], record["first_time_ns"],
                     sha256_bytes(record["wire"]))
    return _message_base(
        ledger_session_id, build, source_sessions, message_id, record["first_time_ns"],
        process, transport, "tls", record["wire"],
        {"type": type_record, "encoding": "tls_ciphertext",
         "fields": fields, "unparsed": [], "notes": []},
        "opaque" if content_type == 23 else "partial",
        reconstruction, provenance, []), (record["offset"], record["end"])


def _http_message(flow, request, process, ledger_session_id, build, source_sessions):
    parsed = request["request"]
    destination = {"port": flow.server[1] if flow.server else None}
    if parsed.get("host"):
        host, _, port = str(parsed["host"]).partition(":")
        destination["host"] = host
        if port.isdigit():
            destination["port"] = int(port)
    elif flow.server:
        destination["ip"] = flow.server[0]
    type_record = {
        "opcode": None, "opcode_hex": None,
        "name": "http_request", "confidence": "confirmed",
        "evidence": ["HTTP/1.x request line"],
    }
    fields = [
        {"name": "method", "offset": None, "size": None, "kind": "string",
         "value": parsed.get("method"), "confidence": "confirmed", "evidence": ["request line"]},
        {"name": "target", "offset": None, "size": None, "kind": "string",
         "value": parsed.get("target"), "confidence": "confirmed", "evidence": ["request line"]},
        {"name": "host", "offset": None, "size": None, "kind": "string",
         "value": parsed.get("host"), "confidence": "confirmed", "evidence": ["Host header"]},
    ]
    transport = _message_transport(flow, process, destination_override=destination,
                                   protocol="http_cleartext")
    reconstruction = {
        "wire": {"stream_offset": request["offset"], "length": len(request["wire"]),
                 "wire_hex": request["wire"].hex(),
                 "segments": [
                     {"source": segment.packet.source_file, "source_index": segment.packet.source_index,
                      "classification": segment.classification}
                     for segment in request["segments"]
                 ]},
        "split": len(request["segments"]) > 1,
        "combined": False,
        "retransmitted": any(segment.classification in ("retransmission", "conflict", "partial_overlap")
                             for segment in request["segments"]),
    }
    provenance = {
        "in_process": False, "send": None, "constructor": None,
        "serialization_steps": [], "memory_activity": None,
        "missing": [],
        "evidence": ["pcap cleartext HTTP request"],
    }
    message_id = _id("ccm", "http", flow.server, request["offset"], request["first_time_ns"],
                     sha256_bytes(request["wire"]))
    return _message_base(
        ledger_session_id, build, source_sessions, message_id, request["first_time_ns"],
        process, transport, "http_cleartext", request["wire"],
        {"type": type_record, "encoding": "http", "fields": fields,
         "unparsed": [], "notes": parsed.get("notes", [])},
        "complete" if parsed.get("complete") else "partial",
        reconstruction, provenance, parsed.get("notes", [])), (request["offset"], request["end"])


def _ngs_message(message, flow, sni, process, ledger_session_id, build, source_sessions):
    decoded = message.decoded_response
    fields = [
        {"name": "method", "offset": None, "size": None, "kind": "string",
         "value": message.method, "confidence": "confirmed", "evidence": ["proxy request"]},
        {"name": "host", "offset": None, "size": None, "kind": "string",
         "value": message.host, "confidence": "confirmed", "evidence": ["proxy request"]},
        {"name": "path", "offset": None, "size": None, "kind": "string",
         "value": message.path, "confidence": "confirmed", "evidence": ["proxy request"]},
    ]
    if decoded:
        # Flatten the already-decoded response so field names are queryable.
        for name, value in (decoded.items() if isinstance(decoded, dict) else []):
            fields.append({
                "name": f"response.{name}",
                "offset": None,
                "size": None,
                "kind": type(value).__name__,
                "value": value if not isinstance(value, (dict, list)) else None,
                "entry_count": len(value) if isinstance(value, (dict, list)) else None,
                "confidence": "supported" if name in (
                    "emergency_stop", "config_changed", "detected", "subfeature",
                    "signature", "module_crc", "auth_cycle", "terminate_message",
                    "lifetoken", "csauthtoken",
                ) else "unresolved",
                "evidence": ["foundations/ngs_cipher.py"],
            })
    destination = {"host": message.host, "port": 443, "path": message.path}
    if flow is not None and flow.server:
        # The proxy log's destination is the NGS host, not the local proxy hop.
        destination["observed_flow_endpoint"] = {
            "ip": flow.server[0], "port": flow.server[1],
        }
    transport = _message_transport(flow, process, destination_override=destination,
                                   protocol=message.protocol)
    reconstruction = {
        "wire": {
            "proxy_source": message.source_file,
            "proxy_index": message.source_index,
            "request_bytes": len(message.request_body),
            "request_body_base64": base64.b64encode(message.request_body).decode("ascii"),
            "response_status": message.response_status,
            "response_bytes": len(message.response_body),
            "request_body_decoding": "opaque_device_bound_cipher",
        },
        "split": False,
        "combined": False,
        "retransmitted": False,
    }
    missing = [{
        "field": "request_plaintext",
        "reason": "the NGS client->server body cipher is device-bound and not broken in this repository",
    }] if message.request_body else []
    if message.time_ns is None:
        missing.append({
            "field": "time",
            "reason": "this proxy log format has no timestamp; order is source-file order only",
        })
    provenance = {
        "in_process": False, "send": None, "constructor": None,
        "serialization_steps": [], "memory_activity": None,
        "missing": missing,
        "evidence": [f"proxy:{message.source_file}:{message.source_index}"],
    }
    type_record = {
        "opcode": None,
        "opcode_hex": None,
        "name": "ngs_request" if message.ngs_host else "http_proxy_request",
        "confidence": "confirmed",
        "evidence": ["proxy request metadata"],
    }
    message_id = _id("ccm", "ngs", message.source_file, message.source_index,
                     message.time_ns, sha256_bytes(message.request_body))
    return _message_base(
        ledger_session_id, build, source_sessions, message_id, message.time_ns,
        process, transport, message.protocol, message.request_body,
        {"type": type_record, "encoding": "ngs_request_ciphertext",
         "fields": fields, "unparsed": [{
             "offset": 0, "size": len(message.request_body),
             "reason": "request body ciphertext is preserved exactly; its plaintext is not available",
         }] if message.request_body else [],
         "notes": [message.decode_error] if message.decode_error else []},
        "opaque" if message.request_body else "metadata_only",
        reconstruction, provenance, [], transmitted=True,
    ), None


def _chunk_records(flow, process, ledger_session_id, build, source_sessions,
                   covered_ranges, notes):
    records = []
    if flow.c2s is None:
        return records
    stream = flow.c2s
    for start, end in stream.runs():
        for chunk_start, chunk_end in subtract_ranges((start, end), covered_ranges):
            for piece_start in range(chunk_start, chunk_end, MAX_CHUNK_BYTES):
                piece_end = min(piece_start + MAX_CHUNK_BYTES, chunk_end)
                data = bytes(stream.data[piece_start:piece_end])
                segments = stream.contributing_segments(piece_start, piece_end)
                transport = _message_transport(flow, process, protocol="tcp")
                reconstruction = {
                    "wire": {"stream_offset": piece_start, "length": len(data),
                             "classification": "unclaimed_transport_bytes"},
                    "segments": [
                        {"source": segment.packet.source_file,
                         "source_index": segment.packet.source_index,
                         "classification": segment.classification,
                         "seq": segment.seq}
                        for segment in segments
                    ],
                    "split": len(segments) > 1,
                    "combined": False,
                    "retransmitted": any(segment.classification in (
                        "retransmission", "conflict", "partial_overlap") for segment in segments),
                    "stream_gaps": list(stream.gaps()),
                }
                message_id = _id("chk", flow.server, piece_start, len(data), sha256_bytes(data))
                record = _message_base(
                    ledger_session_id, build, source_sessions, message_id,
                    stream.first_time_for(piece_start, piece_end), process, transport,
                    "unknown_tcp", data,
                    {"type": {"opcode": None, "opcode_hex": None, "name": None,
                              "confidence": "unknown",
                              "evidence": ["no verified application decoder claimed these bytes"]},
                     "encoding": "transport_payload",
                     "fields": [], "unparsed": [{
                         "offset": 0, "size": len(data),
                         "reason": "unclaimed transport bytes; protocol/type remain unknown",
                     }], "notes": notes},
                    "unknown", reconstruction,
                    {"in_process": False, "send": None, "constructor": None,
                     "serialization_steps": [], "memory_activity": None,
                     "missing": [{"field": "application_decoder",
                                  "reason": "no verified decoder claimed this byte range"}],
                     "evidence": ["pcap transport bytes"]},
                    notes, transmitted=True,
                )
                record["record_type"] = "transport_chunk"
                records.append(record)
    return records


def _gap_records(flow, process, ledger_session_id, build, source_sessions):
    records = []
    if flow.c2s is None:
        return records
    stream = flow.c2s
    for start, end in stream.gaps():
        record = {
            "schema": SCHEMA,
            "record_type": "capture_gap",
            "ledger_session_id": ledger_session_id,
            "message_id": _id("gap", flow.server, start, end),
            "time_ns": stream.first_time_ns,
            "time_utc": format_ns(stream.first_time_ns),
            "source_sessions": source_sessions,
            "build": build,
            "process": process,
            "transport": _message_transport(flow, process, protocol="tcp"),
            "message": {
                "protocol": "tcp",
                "direction": "client_to_server",
                "type": {"opcode": None, "opcode_hex": None, "name": "capture_gap",
                         "confidence": "confirmed",
                         "evidence": ["TCP sequence-space coverage"]},
                "raw_bytes_hex": None,
                "raw_bytes_length": end - start,
                "raw_bytes_encoding": "missing",
                "fields": [],
                "unparsed": [],
                "decode_status": "missing",
                "notes": ["No captured bytes exist for this sequence range."],
            },
            "reconstruction": {
                "stream_offset_start": start,
                "stream_offset_end": end,
                "missing_bytes": end - start,
                "reason": "TCP gap: retransmission missing, capture dropped, or stream started mid-flight",
            },
            "provenance": {"missing": [{"field": "bytes", "reason": "capture gap"}]},
            "transmitted": None,
        }
        records.append(record)
    return records


def _udp_client_to_server(packet):
    if packet.epb_direction == "outbound":
        return True
    if packet.epb_direction == "inbound":
        return False
    if packet.src is None or packet.dst is None:
        return None
    try:
        src_address = ipaddress.ip_address(packet.src)
        dst_address = ipaddress.ip_address(packet.dst)
        src_local = src_address.is_private or src_address.is_loopback or src_address.is_link_local
        dst_local = dst_address.is_private or dst_address.is_loopback or dst_address.is_link_local
    except ValueError:
        src_local = dst_local = False
    if src_local != dst_local:
        return src_local
    service_dst = packet.dport in (53, 80, 123, 443, 8080, 8443)
    service_src = packet.sport in (53, 80, 123, 443, 8080, 8443)
    if service_dst != service_src:
        return service_dst
    return None


def _udp_message(packet, ledger_session_id, build, source_sessions, monitor):
    direction = _udp_client_to_server(packet)
    if direction is not True or not packet.payload:
        return None
    process = _process_record(attribution="missing",
                              missing_reason="no socket owner comment on this UDP packet")
    if packet.process:
        process = _process_record(
            pid=packet.process.get("pid"), name=packet.process.get("name"),
            attribution="pcapng_socket_owner", build=build,
        )
    else:
        for call in monitor.calls:
            if call.endpoint and tuple(call.endpoint) == (packet.dst, packet.dport):
                if call.time_ns is None or packet.time_ns is None:
                    continue
                if abs(call.time_ns - packet.time_ns) <= 5_000_000_000:
                    process = _process_record(
                        pid=call.pid, attribution="monitor_network_call", build=build,
                    )
                    break
    decoded = decode_dns_query(packet.payload) if packet.dport == 53 else None
    if decoded and decoded.get("ok") and not decoded.get("response"):
        type_record = {
            "opcode": None, "opcode_hex": None, "name": "dns_query",
            "confidence": "confirmed", "evidence": ["DNS header and question section"],
        }
        fields = [
            {"name": "query", "offset": 12, "size": None, "kind": "string",
             "value": decoded.get("question"), "confidence": "confirmed",
             "evidence": ["DNS question name"]},
            {"name": "qtype", "offset": 12, "size": None, "kind": "u16",
             "value": decoded.get("qtype"), "confidence": "confirmed",
             "evidence": ["DNS question type"]},
            {"name": "transaction_id", "offset": 0, "size": 2, "kind": "u16",
             "value": decoded.get("id"), "confidence": "confirmed",
             "evidence": ["DNS header"]},
        ]
        decode_status = "complete"
    else:
        type_record = {
            "opcode": None, "opcode_hex": None, "name": "udp_datagram",
            "confidence": "unknown", "evidence": ["no verified UDP application decoder"],
        }
        fields = []
        decode_status = "opaque"
    destination = {"ip": packet.dst, "port": packet.dport}
    transport = {
        "protocol": "udp",
        "direction": "client_to_server",
        "source": {"ip": packet.src, "port": packet.sport},
        "destination": destination,
        "socket": None,
        "capture": {"source": "pcap", "source_index": packet.source_index,
                    "source_file": packet.source_file},
    }
    reconstruction = {
        "wire": {
            "source": packet.source_file,
            "source_index": packet.source_index,
            "wire_hex": packet.payload.hex(),
        },
        "split": False,
        "combined": False,
        "retransmitted": False,
        "stream_gaps": [],
    }
    provenance = {
        "in_process": False, "send": None, "constructor": None,
        "serialization_steps": [], "memory_activity": None,
        "missing": [
            {"field": "constructor", "reason": "UDP capture has no in-process construction record"},
            {"field": "registers", "reason": "registers are available only in-process"},
        ],
        "evidence": [f"pcap:{packet.source_file}:{packet.source_index}"],
    }
    message_id = _id("ccm", "udp", packet.source_file, packet.source_index,
                     packet.time_ns, sha256_bytes(packet.payload))
    return _message_base(
        ledger_session_id, build, source_sessions, message_id, packet.time_ns,
        process, transport, "udp", packet.payload,
        {"type": type_record, "encoding": "transport_payload",
         "fields": fields, "unparsed": [] if fields else [{
             "offset": 0, "size": len(packet.payload),
             "reason": "UDP payload has no verified application decoder",
         }], "notes": []},
        decode_status, reconstruction, provenance, [], transmitted=True,
    )


def _flow_record(flow, process, ledger_session_id, build, source_sessions):
    record = {
        "schema": SCHEMA,
        "record_type": "flow",
        "ledger_session_id": ledger_session_id,
        "flow_id": _id("flow", flow.endpoints, flow.connection_index),
        "time_ns": flow.c2s.first_time_ns if flow.c2s else None,
        "time_utc": format_ns(flow.c2s.first_time_ns if flow.c2s else None),
        "source_sessions": source_sessions,
        "build": build,
        "process": process,
        "transport": _message_transport(flow, process, protocol="tcp"),
        "flow": flow.summary(),
    }
    return record


def _flow_event_record(event, ledger_session_id, build, source_sessions):
    return {
        "schema": SCHEMA,
        "record_type": "flow_event",
        "ledger_session_id": ledger_session_id,
        "event_id": _id("evt", event.source_file, event.source_index, event.kind),
        "time_ns": event.time_ns,
        "time_utc": format_ns(event.time_ns),
        "source_sessions": source_sessions,
        "build": build,
        "process": {"pid": event.pid, "attribution": "monitor_event"},
        "event": event.summary(),
    }


def _external_decision_record(decision, ledger_session_id, build, source_sessions,
                               source_kind):
    if source_kind == "monitor":
        payload = decision.summary()
        time_ns = decision.time_ns
        source_file = decision.source_file
        source_index = decision.source_index
    else:
        payload = decision.summary()
        time_ns = decision.time_ns
        source_file = decision.source_file
        source_index = decision.source_index
    return {
        "schema": SCHEMA,
        "record_type": "filter_decision",
        "ledger_session_id": ledger_session_id,
        "decision_id": _id("dec", source_kind, source_file, source_index),
        "time_ns": time_ns,
        "time_utc": format_ns(time_ns),
        "source_sessions": source_sessions,
        "build": build,
        "source_kind": source_kind,
        "process": {
            "pid": payload.get("pid") if source_kind == "monitor" else None,
            "attribution": "monitor_kfilter" if source_kind == "monitor" else "ngs_proxy",
        },
        "decision": payload,
    }


def _notice_record(notice, ledger_session_id, build, source_sessions):
    return {
        "schema": SCHEMA,
        "record_type": "notice",
        "ledger_session_id": ledger_session_id,
        "notice_id": _id("note", notice),
        "time_ns": notice.get("time_ns"),
        "source_sessions": source_sessions,
        "build": build,
        "notice": notice,
    }


def _annotate_missing(record):
    provenance = record.setdefault("provenance", {})
    missing = provenance.setdefault("missing", [])
    fields = {item.get("field") for item in missing}
    process = record.get("process") or {}
    transport = record.get("transport") or {}
    if process.get("pid") is None and "process" not in fields:
        missing.append({
            "field": "process",
            "reason": process.get("missing_reason")
            or "the capture source did not identify a process for this message",
        })
    if not transport.get("socket") and "socket" not in fields:
        missing.append({
            "field": "socket",
            "reason": "the capture source did not identify the socket for this message",
        })
    if not transport.get("destination") and "destination" not in fields:
        missing.append({
            "field": "destination",
            "reason": "the destination could not be established without guessing",
        })


def build(pcap_paths=None, plaintext_paths=None, monitor_paths=None, ngs_paths=None,
          policy_path=None, client_endpoint=None, include_chunks=True,
          join_window_ns=DEFAULT_JOIN_WINDOW_NS, label=None, profile_path=None):
    pcap_paths = pcap_paths or []
    plaintext_paths = plaintext_paths or []
    monitor_paths = monitor_paths or []
    ngs_paths = ngs_paths or []
    started_ns = time.time_ns()
    ledger_session_id = uuid.uuid4().hex
    packets = read_packets(pcap_paths)
    plaintext = load_plaintext(plaintext_paths)
    monitor = load_monitor(monitor_paths)
    ngs = load_ngs(ngs_paths)
    profile = None
    if profile_path:
        profile = json.loads(Path(profile_path).read_text(encoding="utf-8"))
    elif (Path(__file__).resolve().parent.parent / "foundations" / "profile.json").is_file():
        profile = json.loads((Path(__file__).resolve().parent.parent / "foundations" / "profile.json").read_text(encoding="utf-8"))
    build_info = _build_index(plaintext, monitor, profile)
    process_index = _process_index(monitor, plaintext)
    source_sessions = _source_sessions(plaintext, monitor)
    policy = load_policy(policy_path) if policy_path else None
    records = []
    flows_out = []
    decisions = []
    all_notes = []
    all_notes.extend(packets.notes)
    all_notes.extend(monitor.notes)
    all_notes.extend(ngs.notes)
    all_notes.extend(plaintext.notes)

    flows, tcp_notes = assemble(packets.packets, client_endpoint)
    all_notes.extend(tcp_notes)
    sends_by_id = {index: send for index, send in enumerate(plaintext.sends)}
    matched_send_orders = set()
    game_protocol_flows = []
    tls_flows = []
    tls_by_host = {}

    for flow in flows:
        process = _flow_process(flow, monitor, plaintext, process_index)
        flow_record = _flow_record(flow, process, ledger_session_id, build_info, source_sessions)
        records.append(flow_record)
        c2s = flow.c2s
        covered = []
        if c2s is None or not c2s.data:
            continue
        first = bytes(c2s.data[:min(8, len(c2s.data))])
        is_tls = len(first) >= 3 and first[0] in (20, 21, 22, 23) and first[1] == 0x03
        is_http = first[:8].split(b" ", 1)[0] in (
            b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH", b"CONNECT", b"TRACE", b"PRI",
        )
        if is_tls:
            tls_flows.append((flow, process))
            sni = _sni_for_flow(flow)
            if sni:
                tls_by_host.setdefault(sni.lower(), []).append((flow, process))
            for tls_record in _tls_records(c2s):
                message, span = _tls_message(
                    flow, tls_record, process, ledger_session_id, build_info,
                    source_sessions, sni=sni,
                )
                records.append(message)
                if span:
                    covered.append(span)
            records.extend(_gap_records(flow, process, ledger_session_id, build_info, source_sessions))
            if include_chunks:
                records.extend(_chunk_records(
                    flow, process, ledger_session_id, build_info, source_sessions,
                    merge_ranges(covered), ["unclaimed bytes in a TLS flow"],
                ))
            continue
        if is_http:
            for request in _http_requests(c2s):
                message, span = _http_message(
                    flow, request, process, ledger_session_id, build_info, source_sessions
                )
                records.append(message)
                if span:
                    covered.append(span)
            records.extend(_gap_records(flow, process, ledger_session_id, build_info, source_sessions))
            if include_chunks:
                records.extend(_chunk_records(
                    flow, process, ledger_session_id, build_info, source_sessions,
                    merge_ranges(covered), ["unclaimed bytes in a cleartext HTTP flow"],
                ))
            continue
        frames, frame_notes = parse_frames(c2s)
        for note in frame_notes:
            note = dict(note)
            note["flow"] = {"server": list(flow.server) if flow.server else None}
            note["time_ns"] = c2s.first_time_ns
            all_notes.append(note)
        decryption = decrypt_frames(frames, plaintext.sends)
        matches, unmatched_frames, unmatched_sends = join_frames(
            frames, decryption, plaintext.sends, window_ns=join_window_ns
        )
        if frames:
            game_protocol_flows.append((flow, process, frames, decryption, matches))
        dec_by_index = decryption.by_index()
        for frame in frames:
            match = matches.get(frame.index)
            send = match["send"] if match else None
            if send is not None:
                matched_send_orders.add(match["order"])
            item = dec_by_index.get(frame.index)
            if send is None and (item is None or item.plaintext is None):
                # Keep the exact wire bytes as unclaimed transport bytes. Do not
                # invent a message from an undecrypted frame.
                continue
            message, span = _game_message(
                frame, item, send, plaintext, flow, monitor, process,
                ledger_session_id, build_info, source_sessions, decryption,
            )
            if match:
                message["provenance"]["plaintext_match"]["time_delta_ns"] = match["time_delta_ns"]
            records.append(message)
            if span:
                covered.append(span)
        records.extend(_gap_records(flow, process, ledger_session_id, build_info, source_sessions))
        if include_chunks:
            reasons = ["bytes not claimed by a complete/decrypted game frame"]
            if decryption.status in ("ambiguous_seed", "no_seed"):
                reasons.append(f"decryption status: {decryption.status}")
            records.extend(_chunk_records(
                flow, process, ledger_session_id, build_info, source_sessions,
                merge_ranges(covered), reasons,
            ))

    # Monitor-only fallback: when the pcap has no flow, or when monitor captured
    # a socket the pcap filter did not see, use the syscall send stream. It has
    # no sequence numbers, but it preserves the exact bytes and process identity.
    extra_flows = (
        _monitor_fallback_flows(monitor) if not flows
        else _monitor_extra_flows(monitor, flows)
    )
    for flow in extra_flows:
        pid = flow.process.get("pid")
        known = process_index.get(pid, {})
        process = _process_record(
            pid=pid, name=known.get("name"), path=known.get("path"),
            attribution="monitor_network_data", build=build_info,
        )
        records.extend(_process_synthetic_flow(
            flow, process, ledger_session_id, build_info, source_sessions,
            monitor, plaintext, matched_send_orders, include_chunks,
        ))

    # Plaintext sends with no matching wire frame are still part of the record:
    # a filtered/dropped send must not disappear from the ledger.
    for order, send in enumerate(plaintext.sends):
        if order in matched_send_orders:
            continue
        pid = send.pid
        known = process_index.get(pid, {})
        process = _process_record(
            pid=pid, name=known.get("name"), path=known.get("path"),
            attribution="client_control_send", build=build_info,
        )
        reason = "packet was dropped by the live filter" if send.dropped else (
            "no wire frame with matching body and time was present in the pcap"
        )
        message, _ = _send_only_message(
            send, plaintext, process, ledger_session_id, build_info,
            source_sessions, reason,
        )
        records.append(message)

    # NGS proxy records: the request is the client->server message; the decoded
    # response is retained as evidence on the same record.
    for ngs_message in ngs.messages:
        flow = None
        process = _process_record(
            attribution="missing",
            missing_reason="the proxy log does not contain a process identity",
        )
        host = (ngs_message.host or "").lower()
        candidates = tls_by_host.get(host)
        if not candidates:
            for sni, values in tls_by_host.items():
                if host and (sni == host or sni.endswith("." + host) or host.endswith("." + sni)):
                    candidates = values
                    break
        sni = None
        if candidates:
            if ngs_message.time_ns is not None:
                candidates = sorted(
                    candidates,
                    key=lambda item: abs((item[0].c2s.first_time_ns or 0) - ngs_message.time_ns),
                )
            flow, process = candidates[0]
            sni = host
            if process.get("attribution") == "missing":
                process = _process_record(
                    attribution="tls_flow_match",
                    missing_reason="proxy log has no PID; process is inferred from the matching TLS flow",
                )
        message, _ = _ngs_message(
            ngs_message, flow, sni, process, ledger_session_id, build_info, source_sessions
        )
        if ngs_message.decoded_response is not None:
            message["response_evidence"] = {
                "decoded": ngs_message.decoded_response,
                "status": ngs_message.response_status,
                "response_body_sha256": sha256_bytes(ngs_message.response_body),
                "response_body_length": len(ngs_message.response_body),
                "decoding": "ngs_cipher response cipher",
            }
        records.append(message)

    # UDP is not part of the game's TCP stream, but DNS and other datagrams are
    # still client->server traffic and are kept with exact payload bytes.
    for packet in packets.packets:
        if packet.protocol != "udp":
            continue
        udp_record = _udp_message(
            packet, ledger_session_id, build_info, source_sessions, monitor
        )
        if udp_record is not None:
            records.append(udp_record)
        elif packet.payload:
            all_notes.append({
                "reason": "udp_direction_ambiguous",
                "source": packet.source_file,
                "source_index": packet.source_index,
                "src": f"{packet.src}:{packet.sport}",
                "dst": f"{packet.dst}:{packet.dport}",
                "time_ns": packet.time_ns,
            })

    # Monitor flow events and TCP lifecycle events are evidence for timing and
    # crashes, not application messages.
    for event in monitor.flows + monitor.tcp_events:
        records.append(_flow_event_record(
            event, ledger_session_id, build_info, source_sessions
        ))
    records.extend(_monitor_metadata_flows(
        monitor, flows, ledger_session_id, build_info, source_sessions, process_index
    ))
    for decision in monitor.decisions:
        records.append(_external_decision_record(
            decision, ledger_session_id, build_info, source_sessions, "monitor"
        ))
    for decision in ngs.decisions:
        records.append(_external_decision_record(
            decision, ledger_session_id, build_info, source_sessions, "ngs_proxy"
        ))
    for note in all_notes:
        note.setdefault("time_ns", None)
        records.append(_notice_record(note, ledger_session_id, build_info, source_sessions))

    for record in records:
        if record.get("record_type") == "message":
            _annotate_missing(record)

    # Policy evaluation: every message gets a decision, including "default".
    if policy is not None:
        for record in records:
            if record.get("record_type") != "message":
                continue
            decision = evaluate(policy, record)
            record["filter"] = {
                "policy": decision["policy"],
                "matched": decision["matched"],
                "rule_id": decision["rule_id"],
                "action": decision["action"],
                "reason": decision["reason"],
                "missing_evidence": decision["missing_evidence"],
                "simulated_offline": True,
            }
            decisions.append({
                "schema": SCHEMA,
                "record_type": "filter_decision",
                "ledger_session_id": ledger_session_id,
                "message_id": record.get("message_id"),
                "time_ns": record.get("time_ns"),
                "time_utc": record.get("time_utc"),
                "process": record.get("process"),
                "protocol": (record.get("message") or {}).get("protocol"),
                "type": ((record.get("message") or {}).get("type") or {}),
                "destination": (record.get("transport") or {}).get("destination"),
                "decision": decision,
                "simulated_offline": True,
            })

    # Deterministic order: timed records first, then untimed proxy records in
    # source order. Session is always record 0.
    priority = {
        "flow_event": 0, "filter_decision": 1, "message": 2,
        "transport_chunk": 3, "capture_gap": 4, "flow": 5, "notice": 6,
    }
    timed = [record for record in records if record.get("time_ns") is not None]
    untimed = [record for record in records if record.get("time_ns") is None]
    def wire_order(record):
        wire = (record.get("reconstruction") or {}).get("wire") or {}
        return (
            wire.get("frame_index", wire.get("stream_offset", wire.get("tls_offset", 0))) or 0,
            wire.get("stream_offset", 0) or 0,
        )

    timed.sort(key=lambda record: (
        record.get("time_ns"),
        priority.get(record.get("record_type"), 9),
        wire_order(record),
        str(record.get("message_id") or record.get("flow_id") or record.get("notice_id")),
    ))
    untimed.sort(key=lambda record: (
        priority.get(record.get("record_type"), 9),
        str(record.get("message_id") or record.get("flow_id") or record.get("notice_id")),
    ))
    ordered = timed + untimed
    for index, record in enumerate(ordered):
        record["order"] = index
    session_record = {
        "schema": SCHEMA,
        "record_type": "session",
        "order": -1,
        "ledger_session_id": ledger_session_id,
        "label": label,
        "created_ns": started_ns,
        "created_utc": format_ns(started_ns),
        "build": build_info,
        "source_sessions": source_sessions,
        "policy": policy.summary() if policy else None,
        "inputs": {
            "pcap": packets.files,
            "plaintext": plaintext.files,
            "monitor": monitor.files,
            "ngs": ngs.files,
        },
        "capture_notes": all_notes,
        "limitations": LIMITATIONS,
    }
    # Deduplicate identical notices by content.
    seen = set()
    unique_ordered = []
    for record in ordered:
        key = canonical_json({k: v for k, v in record.items() if k != "order"})
        if key in seen:
            continue
        seen.add(key)
        unique_ordered.append(record)
    for index, record in enumerate(unique_ordered):
        record["order"] = index
    counts = Counter(record.get("record_type") for record in unique_ordered)
    protocol_counts = Counter(
        (record.get("message") or {}).get("protocol")
        for record in unique_ordered if record.get("record_type") == "message"
    )
    process_counts = Counter(
        (record.get("process") or {}).get("name") or "<unknown>"
        for record in unique_ordered if record.get("record_type") == "message"
    )
    decode_counts = Counter(
        (record.get("message") or {}).get("decode_status")
        for record in unique_ordered if record.get("record_type") == "message"
    )
    filter_counts = Counter(
        (record.get("filter") or {}).get("action")
        for record in unique_ordered if record.get("record_type") == "message" and record.get("filter")
    )
    summary = {
        "schema": SCHEMA,
        "ledger_session_id": ledger_session_id,
        "label": label,
        "created_ns": started_ns,
        "created_utc": format_ns(started_ns),
        "build": build_info,
        "record_counts": dict(counts),
        "message_protocols": dict(protocol_counts),
        "message_processes": dict(process_counts),
        "decode_status": dict(decode_counts),
        "filter_actions": dict(filter_counts),
        "sources": {
            "pcap_files": packets.files,
            "plaintext_files": plaintext.files,
            "monitor_files": monitor.files,
            "ngs_files": ngs.files,
        },
        "source_summaries": {
            "plaintext": plaintext.summary(),
            "monitor": monitor.summary(),
            "ngs": ngs.summary(),
        },
        "capture_notes": all_notes,
        "limitations": LIMITATIONS,
        "policy": policy.summary() if policy else None,
    }
    flows_summary = [record for record in unique_ordered if record.get("record_type") == "flow"]
    return Ledger(
        records=unique_ordered,
        flows=flows_summary,
        decisions=decisions,
        summary=summary,
        session=session_record,
    )


def write_ledger(ledger, out_dir):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    from .util import write_jsonl
    records = [ledger.session] + sorted(ledger.records, key=lambda record: record.get("order", 0))
    write_jsonl(out_dir / "ledger.jsonl", records)
    write_jsonl(out_dir / "decisions.jsonl", ledger.decisions)
    (out_dir / "flows.json").write_text(
        json.dumps(ledger.flows, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out_dir / "summary.json").write_text(
        json.dumps(ledger.summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out_dir / "manifest.json").write_text(
        json.dumps({
            "schema": SCHEMA,
            "ledger_session_id": ledger.session.get("ledger_session_id"),
            "created_utc": ledger.session.get("created_utc"),
            "records": len(ledger.records) + 1,
            "decisions": len(ledger.decisions),
            "summary": "summary.json",
            "ledger": "ledger.jsonl",
        }, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return out_dir


def load_records(path):
    path = Path(path)
    if path.is_dir():
        path = path / "ledger.jsonl"
    records = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records
