"""Load client-control's plaintext SendPacket/constructor JSONL captures.

Both the schema-versioned outgoing logger and the older packet-observe/drop/focus
JSONL are accepted. The schema-versioned records keep their construction IDs;
legacy records are linked by packet VA and time.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

from .util import as_bytes, as_int, file_identity, iter_jsonl, parse_time_ns, sha256_file


@dataclass
class PlainSend:
    source_file: str
    source_index: int
    time_ns: int | None
    pid: int | None
    tid: int | None
    opcode: int
    body: bytes
    construction_id: str | None = None
    dropped: bool = False
    registers: dict | None = None
    caller: dict | None = None
    return_stack: list | None = None
    session_id: str | None = None
    raw: dict = field(default_factory=dict)

    @property
    def opcode_hex(self):
        return f"0x{self.opcode:x}"

    def summary(self):
        return {
            "source": self.source_file,
            "source_index": self.source_index,
            "session_id": self.session_id,
            "time_ns": self.time_ns,
            "pid": self.pid,
            "tid": self.tid,
            "opcode": self.opcode_hex,
            "length": len(self.body),
            "construction_id": self.construction_id,
            "dropped": self.dropped,
            "sha256": hashlib.sha256(self.body).hexdigest(),
        }


@dataclass
class Construction:
    construction_id: str
    source_file: str
    source_index: int
    time_ns: int | None
    tid: int | None
    opcode: int
    packet_va: str | None
    registers: dict | None = None
    caller: dict | None = None
    return_stack: list | None = None
    field_changes: list[dict] = field(default_factory=list)
    raw: dict = field(default_factory=dict)

    def steps(self):
        steps = []
        previous = None
        for index, change in enumerate(sorted(self.field_changes, key=lambda item: (
            item.get("event_index", 0), item.get("time_ns") or 0
        ))):
            body = as_bytes(change.get("body"))
            step = {
                "step_index": index,
                "time_ns": change.get("time_ns"),
                "length": change.get("length"),
                "previous_length": change.get("previous_length"),
                "delta_bytes": (
                    None if change.get("previous_length") is None or change.get("length") is None
                    else change["length"] - change["previous_length"]
                ),
                "write_rip": change.get("rip_after_write"),
                "write_rva": change.get("rva_after_write"),
                "body_hex": body.hex() if body is not None else None,
                "registers": change.get("registers"),
                "caller": change.get("caller"),
                "return_stack": change.get("return_stack"),
                "floating_registers": change.get("floating_registers"),
                "changed_ranges": [],
                "evidence": [f"client-control:{self.source_file}:{change.get('event_index')}"],
            }
            if body is not None and previous is not None:
                limit = max(len(body), len(previous))
                ranges = []
                start = None
                for offset in range(limit):
                    left = previous[offset] if offset < len(previous) else None
                    right = body[offset] if offset < len(body) else None
                    if left != right and start is None:
                        start = offset
                    elif left == right and start is not None:
                        ranges.append((start, offset))
                        start = None
                if start is not None:
                    ranges.append((start, limit))
                step["changed_ranges"] = [
                    {
                        "offset": begin,
                        "size": end - begin,
                        "before_hex": previous[begin:end].hex(),
                        "after_hex": body[begin:end].hex(),
                    }
                    for begin, end in ranges
                ]
            steps.append(step)
            if body is not None:
                previous = body
        return steps


@dataclass
class PlaintextCapture:
    sends: list[PlainSend] = field(default_factory=list)
    constructions: dict[str, Construction] = field(default_factory=dict)
    notices: list[dict] = field(default_factory=list)
    session_start: dict | None = None
    session_end: dict | None = None
    files: list[dict] = field(default_factory=list)
    notes: list[dict] = field(default_factory=list)

    def construction_for(self, send):
        if send.construction_id:
            return self.constructions.get(send.construction_id)
        # Legacy fallback: latest constructor at the same packet VA before the send.
        matches = [
            construction for construction in self.constructions.values()
            if construction.packet_va and construction.packet_va == send.raw.get("packet_va")
            and construction.time_ns is not None and send.time_ns is not None
            and construction.time_ns <= send.time_ns
        ]
        if not matches:
            return None
        return max(matches, key=lambda construction: construction.time_ns)

    def summary(self):
        return {
            "files": self.files,
            "sends": len(self.sends),
            "dropped_sends": sum(1 for send in self.sends if send.dropped),
            "constructions": len(self.constructions),
            "notices": len(self.notices),
            "session_start": self.session_start,
            "session_end": self.session_end,
            "notes": self.notes,
        }


def _discover(paths):
    result = []
    for value in paths:
        path = Path(value)
        if path.is_dir():
            for candidate in sorted(path.glob("*.jsonl")):
                if any(token in candidate.name for token in (
                    "outgoing-events", "packets-", "drop-events", "interaction-events",
                    "death-events", "32b-events", "focus", "session",
                )):
                    result.append(candidate)
        elif path.is_file():
            result.append(path)
    return result


def _legacy_time(record):
    return parse_time_ns(record.get("wall_time_ns") or record.get("timestamp") or record.get("monotonic_ns"))


def _normalise_send(record, source_file, source_index, legacy, capture):
    opcode = as_int(record.get("opcode"))
    body = as_bytes(record.get("body"), b"")
    if opcode is None and len(body) >= 2:
        opcode = int.from_bytes(body[:2], "little")
    if opcode is None:
        capture.notes.append({
            "source": source_file,
            "index": source_index,
            "reason": "send_without_opcode",
        })
        return None
    construction_id = record.get("construction_id")
    if legacy:
        construction_id = None
    return PlainSend(
        source_file=source_file,
        source_index=source_index,
        time_ns=_legacy_time(record),
        pid=record.get("pid"),
        tid=record.get("tid"),
        opcode=opcode,
        body=body,
        construction_id=construction_id,
        dropped=bool(record.get("dropped", False)),
        registers=record.get("registers"),
        caller=record.get("caller"),
        return_stack=record.get("return_stack") or record.get("return_stack_rvas"),
        session_id=record.get("session_id"),
        raw=record,
    )


def _add_field_change(capture, record, source_file, source_index, legacy):
    construction_id = record.get("construction_id")
    if construction_id and construction_id in capture.constructions:
        change = {
            "event_index": record.get("event_index", source_index),
            "time_ns": _legacy_time(record),
            "length": record.get("length"),
            "previous_length": record.get("previous_length"),
            "body": record.get("body"),
            "rip_after_write": record.get("rip_after_write") or record.get("rip"),
            "rva_after_write": record.get("rva_after_write"),
            "registers": record.get("registers"),
            "caller": record.get("caller"),
            "return_stack": record.get("return_stack"),
            "floating_registers": record.get("floating_registers"),
            "source": source_file,
        }
        capture.constructions[construction_id].field_changes.append(change)
        return True
    if legacy:
        packet_va = record.get("packet_va")
        candidates = [
            construction for construction in capture.constructions.values()
            if construction.packet_va == packet_va
        ]
        if candidates:
            candidates[-1].field_changes.append({
                "event_index": source_index,
                "time_ns": _legacy_time(record),
                "length": record.get("length"),
                "previous_length": record.get("previous_length"),
                "body": record.get("body"),
                "rip_after_write": record.get("rip"),
                "rva_after_write": record.get("rva_after_write"),
                "registers": record.get("registers"),
                "caller": record.get("caller"),
                "return_stack": record.get("return_stack"),
                "source": source_file,
            })
            return True
    capture.notes.append({
        "source": source_file,
        "index": source_index,
        "reason": "field_change_without_construction",
        "construction_id": construction_id,
        "packet_va": record.get("packet_va"),
    })
    return False


def load_plaintext(paths):
    capture = PlaintextCapture()
    for path in _discover(paths):
        source_file = str(path)
        identity = file_identity(path)
        capture.files.append(identity)
        for line_number, record in iter_jsonl(path):
            kind = record.get("kind")
            direction = record.get("direction")
            schema = record.get("schema_version")
            if schema == 1:
                if kind == "session_start":
                    capture.session_start = dict(record, source_file=source_file, source_line=line_number)
                elif kind == "session_end":
                    capture.session_end = dict(record, source_file=source_file, source_line=line_number)
                elif kind == "constructor":
                    construction_id = record.get("construction_id")
                    if not construction_id:
                        capture.notes.append({
                            "source": source_file, "index": line_number,
                            "reason": "constructor_without_id",
                        })
                        continue
                    capture.constructions[construction_id] = Construction(
                        construction_id=construction_id,
                        source_file=source_file,
                        source_index=line_number,
                        time_ns=_legacy_time(record),
                        tid=record.get("tid"),
                        opcode=as_int(record.get("opcode"), 0),
                        packet_va=record.get("packet_va") or record.get("packet"),
                        registers=record.get("registers"),
                        caller=record.get("caller"),
                        return_stack=record.get("return_stack"),
                        raw=record,
                    )
                elif kind == "field_change":
                    _add_field_change(capture, record, source_file, line_number, False)
                elif kind == "send":
                    send = _normalise_send(record, source_file, line_number, False, capture)
                    if send:
                        capture.sends.append(send)
                elif kind == "notice":
                    capture.notices.append(dict(record, source_file=source_file, source_line=line_number))
                continue
            # Legacy packet-observe/drop/focus records.
            if direction == "constructor":
                packet_va = record.get("packet_va")
                construction_id = f"legacy:{Path(source_file).name}:{line_number}"
                capture.constructions[construction_id] = Construction(
                    construction_id=construction_id,
                    source_file=source_file,
                    source_index=line_number,
                    time_ns=_legacy_time(record),
                    tid=record.get("tid"),
                    opcode=as_int(record.get("opcode"), 0),
                    packet_va=packet_va,
                    registers=record.get("registers"),
                    caller=record.get("caller"),
                    return_stack=record.get("return_stack"),
                    raw=record,
                )
            elif direction in ("field_trace", "field_change"):
                _add_field_change(capture, record, source_file, line_number, True)
            elif direction == "client_to_server":
                send = _normalise_send(record, source_file, line_number, True, capture)
                if send:
                    nested = record.get("constructor")
                    if isinstance(nested, dict):
                        construction_id = f"legacy-embedded:{Path(source_file).name}:{line_number}"
                        capture.constructions[construction_id] = Construction(
                            construction_id=construction_id,
                            source_file=source_file,
                            source_index=line_number,
                            time_ns=_legacy_time(nested) or send.time_ns,
                            tid=nested.get("tid", send.tid),
                            opcode=as_int(nested.get("opcode"), send.opcode),
                            packet_va=nested.get("packet_va") or send.raw.get("packet_va"),
                            registers=nested.get("registers"),
                            caller=nested.get("caller"),
                            return_stack=nested.get("return_stack"),
                            raw=nested,
                        )
                        send.construction_id = construction_id
                    for trace in record.get("field_trace") or []:
                        if isinstance(trace, dict):
                            _add_field_change(
                                capture, dict(trace, packet_va=send.raw.get("packet_va")),
                                source_file, line_number, True,
                            )
                    capture.sends.append(send)
            elif direction in ("observer_notice", "notice") or record.get("event"):
                capture.notices.append(dict(record, source_file=source_file, source_line=line_number))
            elif record.get("capture_start"):
                capture.session_start = dict(record, source_file=source_file, source_line=line_number)
    # Link legacy sends to their constructor by packet VA/time.
    for send in capture.sends:
        if send.construction_id is None:
            construction = capture.construction_for(send)
            if construction is not None:
                send.construction_id = construction.construction_id
    capture.sends.sort(key=lambda send: (
        send.time_ns if send.time_ns is not None else 0,
        send.source_file,
        send.source_index,
    ))
    return capture


def send_suffix_matches(send, plaintext):
    """True when the plaintext after the two opcode bytes equals this send's."""
    if send.body[:2] == plaintext[:2]:
        return send.body[2:] == plaintext[2:]
    return send.body[2:] == plaintext[2:]


def send_time_span(capture):
    times = [send.time_ns for send in capture.sends if send.time_ns is not None]
    return (min(times), max(times)) if times else (None, None)
