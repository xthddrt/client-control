"""Ingest monitor-filter session bundles: network bytes, flows, TCP events, decisions."""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from pathlib import Path

from .util import file_identity, iter_jsonl, parse_time_ns, read_json


ENDPOINT_RE = re.compile(
    r"([0-9a-fA-F:.\[\]]+):(\d+)\s*->\s*([0-9a-fA-F:.\[\]]+):(\d+)"
)
SOCKET_RE = re.compile(r"socket:\[(\d+)\]")


@dataclass
class NetworkCall:
    operation_id: int | None
    source_file: str
    source_index: int
    time_ns: int | None
    pid: int | None
    tid: int | None
    method: str
    direction: str
    endpoint: tuple | None
    socket_inode: int | None
    data: bytes
    complete: bool
    total_bytes: int | None
    missing_reason: str | None
    detail: str | None
    text: str | None
    flags: int | None

    def summary(self):
        return {
            "operation_id": self.operation_id,
            "source": self.source_file,
            "source_index": self.source_index,
            "time_ns": self.time_ns,
            "pid": self.pid,
            "tid": self.tid,
            "method": self.method,
            "direction": self.direction,
            "endpoint": list(self.endpoint) if self.endpoint else None,
            "socket_inode": self.socket_inode,
            "bytes": len(self.data),
            "complete": self.complete,
            "total_bytes": self.total_bytes,
            "missing_reason": self.missing_reason,
        }


@dataclass
class FlowEvent:
    kind: str
    source_file: str
    source_index: int
    time_ns: int | None
    pid: int | None
    tid: int | None
    local: tuple | None
    remote: tuple | None
    socket_inode: int | None
    flow_id: int | None
    value1: int | None
    detail: str | None
    text: str | None
    service_correlated: bool = False

    def summary(self):
        return {
            "kind": self.kind,
            "time_ns": self.time_ns,
            "pid": self.pid,
            "tid": self.tid,
            "local": list(self.local) if self.local else None,
            "remote": list(self.remote) if self.remote else None,
            "socket_inode": self.socket_inode,
            "flow_id": self.flow_id,
            "value1": self.value1,
            "detail": self.detail,
            "service_correlated": self.service_correlated,
            "source": self.source_file,
            "source_index": self.source_index,
        }


@dataclass
class MonitorDecision:
    source_file: str
    source_index: int
    time_ns: int | None
    pid: int | None
    action: str | None
    layer: str | None
    target: str | None
    rule_id: int | None
    text: str | None
    detail: str | None
    desired_access: int | None
    value0: int | None
    value1: int | None

    def summary(self):
        return {
            "time_ns": self.time_ns,
            "pid": self.pid,
            "action": self.action,
            "layer": self.layer,
            "target": self.target,
            "rule_id": self.rule_id,
            "text": self.text,
            "detail": self.detail,
            "desired_access": self.desired_access,
            "value0": self.value0,
            "value1": self.value1,
            "source": self.source_file,
            "source_index": self.source_index,
        }


@dataclass
class MonitorCapture:
    calls: list[NetworkCall] = field(default_factory=list)
    flows: list[FlowEvent] = field(default_factory=list)
    tcp_events: list[FlowEvent] = field(default_factory=list)
    decisions: list[MonitorDecision] = field(default_factory=list)
    dns: list[dict] = field(default_factory=list)
    tls_plaintext: list[NetworkCall] = field(default_factory=list)
    processes: list[dict] = field(default_factory=list)
    images: list[dict] = field(default_factory=list)
    files: list[dict] = field(default_factory=list)
    notes: list[dict] = field(default_factory=list)
    session_meta: dict | None = None
    manifest: dict | None = None
    event_count: int = 0

    def summary(self):
        return {
            "files": self.files,
            "event_count": self.event_count,
            "network_calls": len(self.calls),
            "flow_events": len(self.flows),
            "tcp_events": len(self.tcp_events),
            "decisions": len(self.decisions),
            "dns": len(self.dns),
            "tls_plaintext_calls": len(self.tls_plaintext),
            "processes": len(self.processes),
            "images": len(self.images),
            "session_meta": self.session_meta,
            "notes": self.notes,
        }


def _kv(detail):
    result = {}
    if not detail:
        return result
    for item in detail.split(";"):
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        if key and key not in result:
            result[key] = value
    return result


def _endpoint(text):
    if not text:
        return None, None
    match = ENDPOINT_RE.search(text)
    if not match:
        return None, None
    return (match.group(1), int(match.group(2))), (match.group(3), int(match.group(4)))


def _event_parts(directory: Path):
    parts = []
    for candidate in directory.iterdir():
        if not candidate.is_file():
            continue
        if candidate.name == "events.jsonl":
            parts.append((0, candidate))
        elif candidate.name.startswith("events.jsonl.") and candidate.name[len("events.jsonl."):].isdigit():
            parts.append((int(candidate.name[len("events.jsonl."):]), candidate))
    return [path for _, path in sorted(parts)]


def _decode_payload_chunks(records):
    chunks = []
    for record in records:
        payload = record.get("payload") or {}
        data = payload.get("data")
        if data is None:
            continue
        try:
            raw = base64.b64decode(data, validate=False)
        except Exception:
            return None, "payload_base64_invalid"
        chunks.append({
            "offset": payload.get("byte_offset", 0),
            "index": payload.get("chunk_index", 0),
            "count": payload.get("chunk_count", 1),
            "final": payload.get("final_chunk", False),
            "data": raw,
            "payload": payload,
        })
    chunks.sort(key=lambda chunk: (chunk["offset"], chunk["index"]))
    if not chunks:
        return None, "payload_has_no_chunks"
    total = chunks[0]["payload"].get("total_bytes")
    output = bytearray()
    expected = 0
    complete = True
    for chunk in chunks:
        if chunk["offset"] != expected:
            # Never insert fabricated bytes into the syscall stream.
            return None, f"payload_gap_at_offset_{chunk['offset']}_expected_{expected}"
        output.extend(chunk["data"])
        expected += len(chunk["data"])
    if total is not None and expected != total:
        complete = False
    return bytes(output), None if complete else "payload_chunks_incomplete_or_out_of_order"


def _signal_name(record):
    type_name = record.get("type")
    if type_name in ("network_data", "tls_plaintext", "ipc_data"):
        return type_name
    payload = record.get("payload") or {}
    if payload:
        return payload.get("kind") or "payload"
    return type_name or "payload"


def _is_input(record):
    flags = record.get("flags") or 0
    names = record.get("flags_names") or ""
    return bool(flags & 0x200) or "payload_input" in str(names)


def _read_events(path, records, capture, operations):
    for line_number, record in records:
        capture.event_count += 1
        type_name = record.get("type")
        time_ns = parse_time_ns(record.get("timestamp"))
        pid = record.get("process_id")
        tid = record.get("thread_id")
        if type_name in ("process_start", "process_exit", "image_load"):
            target = capture.processes if type_name.startswith("process_") else capture.images
            target.append({
                "kind": type_name,
                "time_ns": time_ns,
                "pid": pid,
                "path": record.get("text"),
                "detail": record.get("detail"),
                "value0": record.get("value0"),
                "value1": record.get("value1"),
                "source": str(path),
                "source_index": line_number,
            })
            continue
        if type_name in ("network_connect", "network_accept", "network_flow_established",
                         "network_flow_close"):
            local, remote = _endpoint(record.get("text"))
            if local is None:
                local, remote = _endpoint(record.get("detail"))
            socket_match = SOCKET_RE.search(record.get("text") or "")
            capture.flows.append(FlowEvent(
                kind=type_name,
                source_file=str(path),
                source_index=line_number,
                time_ns=time_ns,
                pid=pid,
                tid=tid,
                local=local,
                remote=remote,
                socket_inode=int(socket_match.group(1)) if socket_match else None,
                flow_id=record.get("value0"),
                value1=record.get("value1"),
                detail=record.get("detail"),
                text=record.get("text"),
                service_correlated=bool((record.get("flags") or 0) & 0x10),
            ))
            continue
        if type_name == "etw_tcp":
            local, remote = _endpoint(record.get("text"))
            if local is None:
                local, remote = _endpoint(record.get("detail"))
            capture.tcp_events.append(FlowEvent(
                kind="etw_tcp",
                source_file=str(path),
                source_index=line_number,
                time_ns=time_ns,
                pid=pid,
                tid=tid,
                local=local,
                remote=remote,
                socket_inode=None,
                flow_id=None,
                value1=record.get("value1"),
                detail=record.get("detail"),
                text=record.get("text"),
            ))
            continue
        if type_name == "kfilter_decision":
            detail = record.get("detail") or ""
            kv = _kv(detail)
            capture.decisions.append(MonitorDecision(
                source_file=str(path),
                source_index=line_number,
                time_ns=time_ns,
                pid=pid,
                action=kv.get("action") or kv.get("decision"),
                layer=kv.get("layer"),
                target=kv.get("target"),
                rule_id=record.get("value1"),
                text=record.get("text"),
                detail=detail,
                desired_access=record.get("desired_access"),
                value0=record.get("value0"),
                value1=record.get("value1"),
            ))
            continue
        if type_name == "etw_dns":
            capture.dns.append({
                "time_ns": time_ns,
                "pid": pid,
                "query": record.get("text"),
                "detail": record.get("detail"),
                "value0": record.get("value0"),
                "source": str(path),
                "source_index": line_number,
            })
            continue
        if type_name in ("network_data", "tls_plaintext"):
            operation_id = record.get("operation_id")
            if operation_id is None:
                payload = record.get("payload") or {}
                operation_id = payload.get("operation_id")
            if operation_id is None:
                capture.notes.append({
                    "source": str(path), "index": line_number,
                    "reason": "payload_record_without_operation_id",
                })
                continue
            operations.setdefault((type_name, operation_id), []).append(record)


def _finish_operations(capture, operations):
    for (kind, operation_id), records in operations.items():
        records.sort(key=lambda record: (
            parse_time_ns(record.get("timestamp")) or 0, record.get("sequence") or 0
        ))
        data, missing = _decode_payload_chunks(records)
        if data is None:
            capture.notes.append({
                "reason": "payload_decode_failed",
                "operation_id": operation_id,
                "detail": missing,
            })
            continue
        first = records[0]
        detail = first.get("detail") or ""
        text = first.get("text") or ""
        local, remote = _endpoint(detail)
        if local is None:
            local, remote = _endpoint(text)
        socket_match = SOCKET_RE.search(text + ";" + detail)
        flags = first.get("flags") or 0
        direction = "send" if _is_input(first) or "send" in (detail or "") else "receive"
        call = NetworkCall(
            operation_id=operation_id,
            source_file=str(first.get("_source_file", "")),
            source_index=first.get("record_index", 0),
            time_ns=parse_time_ns(first.get("timestamp")),
            pid=first.get("process_id"),
            tid=first.get("thread_id"),
            method=kind,
            direction=direction,
            endpoint=remote,
            socket_inode=int(socket_match.group(1)) if socket_match else None,
            data=data,
            complete=missing is None,
            total_bytes=(first.get("payload") or {}).get("total_bytes"),
            missing_reason=missing,
            detail=detail,
            text=text,
            flags=flags,
        )
        if not call.complete:
            capture.notes.append({
                "reason": "payload_operation_incomplete",
                "operation_id": operation_id,
                "detail": call.missing_reason,
                "bytes_available": len(call.data),
                "total_bytes": call.total_bytes,
            })
        if kind == "tls_plaintext":
            capture.tls_plaintext.append(call)
        else:
            capture.calls.append(call)


def load_monitor(paths):
    capture = MonitorCapture()
    directories = []
    files = []
    for value in paths:
        path = Path(value)
        if path.is_dir():
            directories.append(path)
            manifest = path / "manifest.json"
            meta = path / "session_meta.json"
            if manifest.is_file():
                capture.manifest = read_json(manifest)
            if meta.is_file():
                capture.session_meta = read_json(meta)
            parts = _event_parts(path)
            if parts:
                files.extend(parts)
            else:
                capture.notes.append({"source": str(path), "reason": "no_events_jsonl_parts"})
        elif path.is_file():
            files.append(path)
    operations = {}
    for path in files:
        capture.files.append(file_identity(path))
        annotated = []
        for line_number, record in iter_jsonl(path):
            record["_source_file"] = str(path)
            annotated.append((line_number, record))
        _read_events(path, annotated, capture, operations)
    _finish_operations(capture, operations)
    for collection in (capture.calls, capture.flows, capture.tcp_events, capture.decisions,
                       capture.tls_plaintext):
        collection.sort(key=lambda item: (
            item.time_ns if item.time_ns is not None else 0,
            getattr(item, "source_index", 0),
        ))
    return capture
