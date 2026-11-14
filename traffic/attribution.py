"""Socket-to-process attribution sidecar produced by ``python -m traffic capture``.

The sidecar is a JSONL record per observed socket/peer, with first/last timestamps.
Ingest matches a pcap flow by protocol, endpoint pair, optional socket inode, and
time overlap. Multiple different owners are reported as ambiguous, never merged.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path

from .archive import extract_bundle
from .util import file_identity, iter_jsonl, parse_time_ns


@dataclass
class AttributionRecord:
    protocol: str
    local: tuple
    remote: tuple
    pid: int
    name: str | None
    path: str | None
    socket_inode: int | None
    first_seen_ns: int | None
    last_seen_ns: int | None
    observations: int = 1
    source_file: str | None = None
    source_index: int | None = None

    def summary(self):
        return {
            "protocol": self.protocol,
            "local": list(self.local),
            "remote": list(self.remote),
            "pid": self.pid,
            "name": self.name,
            "path": self.path,
            "socket_inode": self.socket_inode,
            "first_seen_ns": self.first_seen_ns,
            "last_seen_ns": self.last_seen_ns,
            "observations": self.observations,
            "source": self.source_file,
            "source_index": self.source_index,
        }


@dataclass
class AttributionCapture:
    records: list[AttributionRecord] = field(default_factory=list)
    files: list[dict] = field(default_factory=list)
    notes: list[dict] = field(default_factory=list)

    def summary(self):
        return {
            "files": self.files,
            "records": len(self.records),
            "notes": self.notes,
        }


def _endpoint(value):
    if not isinstance(value, (list, tuple)) or len(value) != 2:
        return None
    try:
        return (str(value[0]), int(value[1]))
    except (TypeError, ValueError):
        return None


def _discover(paths):
    result = []
    for value in paths:
        path = Path(value)
        if path.is_dir():
            result.extend(sorted(path.glob("attribution*.jsonl")))
        elif path.is_file():
            result.append(path)
    return result


def _read_attribution_file(path, capture):
    capture.files.append(file_identity(path))
    for line_number, record in iter_jsonl(path):
        if record.get("kind") not in (None, "attribution"):
            continue
        local = _endpoint(record.get("local"))
        remote = _endpoint(record.get("remote"))
        pid = record.get("pid")
        if local is None or remote is None or pid is None:
            capture.notes.append({
                "source": str(path),
                "index": line_number,
                "reason": "attribution_record_missing_endpoint_or_pid",
            })
            continue
        capture.records.append(AttributionRecord(
            protocol=str(record.get("protocol") or "tcp").lower(),
            local=local,
            remote=remote,
            pid=int(pid),
            name=record.get("name"),
            path=record.get("path"),
            socket_inode=(
                int(record["socket_inode"]) if record.get("socket_inode") is not None else None
            ),
            first_seen_ns=parse_time_ns(record.get("first_seen_ns") or record.get("first_seen")),
            last_seen_ns=parse_time_ns(record.get("last_seen_ns") or record.get("last_seen")),
            observations=int(record.get("observations") or 1),
            source_file=str(path),
            source_index=line_number,
        ))


def load_attribution(paths):
    capture = AttributionCapture()
    for value in paths:
        path = Path(value)
        if path.is_file() and path.suffix.lower() == ".zip":
            directory, extracted = extract_bundle(path)
            try:
                sub = load_attribution(extracted)
                capture.records.extend(sub.records)
                capture.files.extend(sub.files)
                capture.notes.extend(sub.notes)
            finally:
                shutil.rmtree(directory, ignore_errors=True)
            capture.files.append(file_identity(path))
            continue
        for candidate in _discover([path]):
            _read_attribution_file(candidate, capture)
    return capture


def _overlaps(record, start_ns, end_ns, window_ns=5_000_000_000):
    if record.first_seen_ns is None and record.last_seen_ns is None:
        return True
    if start_ns is None and end_ns is None:
        return True
    record_start = record.first_seen_ns if record.first_seen_ns is not None else record.last_seen_ns
    record_end = record.last_seen_ns if record.last_seen_ns is not None else record.first_seen_ns
    if record_start is None or record_end is None:
        return True
    return record_start - window_ns <= (end_ns or start_ns) and record_end + window_ns >= (start_ns or end_ns)


def match_flow(capture, flow):
    """Return (process, candidates) for one pcap flow from the sidecar."""
    if capture is None or flow is None or flow.client is None or flow.server is None:
        return None, []
    start = flow.c2s.first_time_ns if flow.c2s else None
    end = flow.c2s.last_time_ns if flow.c2s else None
    client = tuple(flow.client)
    server = tuple(flow.server)
    inodes = {
        socket.get("inode") for socket in (flow.sockets or [])
        if socket.get("inode") is not None
    }
    candidates = []
    for record in capture.records:
        if record.protocol != "tcp":
            continue
        if (record.local, record.remote) not in ((client, server), (server, client)):
            continue
        if inodes and record.socket_inode is not None and record.socket_inode not in inodes:
            continue
        if not _overlaps(record, start, end):
            continue
        candidates.append(record)
    if not candidates:
        return None, []
    pids = {record.pid for record in candidates}
    if len(pids) > 1:
        return {
            "pid": None,
            "name": None,
            "path": None,
            "attribution": "ambiguous",
            "candidates": [record.summary() for record in candidates],
        }, candidates
    best = max(candidates, key=lambda record: (record.observations, record.last_seen_ns or 0))
    return {
        "pid": best.pid,
        "name": best.name,
        "path": best.path,
        "attribution": "tcpdump_proc_attribution",
        "socket_inode": best.socket_inode,
        "evidence": [f"attribution:{best.source_file}:{best.source_index}"],
    }, candidates
