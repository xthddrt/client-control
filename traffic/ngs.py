"""Ingest NGS/HTTPS proxy logs (client-control ngs-mitm.py / ngs-proxy.py)."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from pathlib import Path

from .decode import decode_ngs_response
from .util import file_identity, iter_jsonl, parse_time_ns


def _b64decode(value):
    if value is None:
        return b""
    if isinstance(value, str):
        value = value.encode("ascii", "ignore")
    try:
        return base64.b64decode(value, validate=False)
    except Exception:
        return b""


@dataclass
class NgsMessage:
    source_file: str
    source_index: int
    time_ns: int | None
    order_basis: str
    kind: str
    method: str | None
    host: str | None
    path: str | None
    request_headers: dict
    request_body: bytes
    response_status: int | None
    response_headers: dict
    response_body: bytes
    decoded_response: dict | None
    decode_error: str | None
    raw: dict = field(default_factory=dict)

    @property
    def ngs_host(self):
        host = self.host or ""
        return host.startswith("x-") and host.endswith(".ngs.nexon.com")

    @property
    def protocol(self):
        return "ngs_https" if self.ngs_host else "http_proxy_observed"

    def summary(self):
        return {
            "source": self.source_file,
            "source_index": self.source_index,
            "time_ns": self.time_ns,
            "order_basis": self.order_basis,
            "method": self.method,
            "host": self.host,
            "path": self.path,
            "protocol": self.protocol,
            "request_bytes": len(self.request_body),
            "response_status": self.response_status,
            "response_bytes": len(self.response_body),
            "decoded_response": self.decoded_response is not None,
            "decode_error": self.decode_error,
        }


@dataclass
class NgsDecision:
    source_file: str
    source_index: int
    time_ns: int | None
    request: dict
    decision: dict
    raw: dict = field(default_factory=dict)

    def summary(self):
        return {
            "source": self.source_file,
            "source_index": self.source_index,
            "time_ns": self.time_ns,
            "request": self.request,
            "decision": self.decision,
        }


@dataclass
class NgsCapture:
    messages: list[NgsMessage] = field(default_factory=list)
    decisions: list[NgsDecision] = field(default_factory=list)
    files: list[dict] = field(default_factory=list)
    notes: list[dict] = field(default_factory=list)

    def summary(self):
        return {
            "files": self.files,
            "messages": len(self.messages),
            "decisions": len(self.decisions),
            "ngs_hosts": sum(1 for message in self.messages if message.ngs_host),
            "notes": self.notes,
        }


def _headers_dict(headers):
    if isinstance(headers, dict):
        return dict(headers)
    if isinstance(headers, list):
        result = {}
        for item in headers:
            if isinstance(item, dict):
                result[item.get("name", "")] = item.get("value", "")
            elif isinstance(item, (list, tuple)) and len(item) == 2:
                result[str(item[0])] = str(item[1])
        return result
    return {}


def _record_to_message(record, source_file, index, order_basis="log_sequence"):
    request = record.get("request") or {}
    response = record.get("response") or {}
    request_body = _b64decode(request.get("body_base64"))
    response_body = _b64decode(response.get("body_base64"))
    decoded = record.get("decoded_response")
    decode_error = record.get("decode_error")
    if decoded is None and response_body:
        result = decode_ngs_response(response_body)
        if result.get("ok"):
            decoded = result.get("payload")
        else:
            decode_error = result.get("error")
    time_ns = parse_time_ns(record.get("timestamp") or record.get("wall_time_ns"))
    return NgsMessage(
        source_file=source_file,
        source_index=index,
        time_ns=time_ns,
        order_basis=order_basis if time_ns is not None else "source_order_missing_timestamp",
        kind=record.get("kind", "response"),
        method=request.get("method"),
        host=request.get("host") or request.get("pretty_host"),
        path=request.get("path"),
        request_headers=_headers_dict(request.get("headers")),
        request_body=request_body,
        response_status=response.get("status") or response.get("status_code"),
        response_headers=_headers_dict(response.get("headers")),
        response_body=response_body,
        decoded_response=decoded,
        decode_error=decode_error,
        raw=record,
    )


def _load_mitm(path, capture, start_index):
    try:
        from mitmproxy.io import FlowReader
    except Exception as error:
        capture.notes.append({"source": str(path), "reason": "mitmproxy_unavailable", "error": str(error)})
        return start_index
    index = start_index
    try:
        with open(path, "rb") as handle:
            for flow in FlowReader(handle).stream():
                request = flow.request
                response = flow.response
                record = {
                    "kind": "response" if response is not None else "error",
                    "timestamp": getattr(request, "timestamp_start", None),
                    "request": {
                        "method": request.method,
                        "host": request.pretty_host,
                        "path": request.path,
                        "headers": dict(request.headers),
                        "body_base64": base64.b64encode(request.content or b"").decode("ascii"),
                    },
                }
                if response is not None:
                    record["response"] = {
                        "status": response.status_code,
                        "headers": dict(response.headers),
                        "body_base64": base64.b64encode(response.content or b"").decode("ascii"),
                    }
                else:
                    record["error"] = str(flow.error)
                capture.messages.append(_record_to_message(record, str(path), index))
                index += 1
    except Exception as error:
        capture.notes.append({"source": str(path), "reason": "mitm_read_failed", "error": str(error)})
    return index


def _discover(paths):
    result = []
    for value in paths:
        path = Path(value)
        if path.is_dir():
            for candidate in sorted(path.iterdir()):
                if candidate.is_file() and (
                    candidate.suffix in (".jsonl", ".mitm") or "ngs" in candidate.name.lower()
                ):
                    result.append(candidate)
        elif path.is_file():
            result.append(path)
    return result


def load_ngs(paths):
    capture = NgsCapture()
    for path in _discover(paths):
        capture.files.append(file_identity(path))
        if path.suffix == ".mitm":
            _load_mitm(path, capture, 0)
            continue
        index = 0
        for line_number, record in iter_jsonl(path):
            if not isinstance(record, dict):
                capture.notes.append({
                    "source": str(path), "index": line_number,
                    "reason": "record_is_not_an_object",
                })
                continue
            if record.get("kind") == "filter_decision":
                capture.decisions.append(NgsDecision(
                    source_file=str(path),
                    source_index=line_number,
                    time_ns=parse_time_ns(record.get("timestamp") or record.get("wall_time_ns")),
                    request=record.get("request") or {},
                    decision=record.get("decision") or {},
                    raw=record,
                ))
                continue
            if record.get("kind") not in ("response", "error"):
                capture.notes.append({
                    "source": str(path), "index": line_number,
                    "reason": "unrecognised_ngs_record_kind",
                    "kind": record.get("kind"),
                })
                continue
            capture.messages.append(_record_to_message(record, str(path), index))
            index += 1
    capture.messages.sort(key=lambda message: (
        message.time_ns if message.time_ns is not None else 1 << 62,
        message.source_file,
        message.source_index,
    ))
    return capture
