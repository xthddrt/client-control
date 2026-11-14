"""Evidence-first reports for a timestamp, a message, or a crash window."""

from __future__ import annotations

from collections import Counter

from .util import format_ns


def _message_summary(record):
    message = record.get("message") or {}
    message_type = message.get("type") or {}
    provenance = record.get("provenance") or {}
    send = provenance.get("send") or {}
    return {
        "message_id": record.get("message_id"),
        "order": record.get("order"),
        "time_ns": record.get("time_ns"),
        "time_utc": record.get("time_utc"),
        "process": record.get("process"),
        "protocol": message.get("protocol"),
        "type": message_type,
        "length": message.get("raw_bytes_length"),
        "decode_status": message.get("decode_status"),
        "direction": message.get("direction"),
        "in_process": provenance.get("in_process"),
        "constructor_present": provenance.get("constructor") is not None,
        "serialization_steps": len(provenance.get("serialization_steps") or []),
        "send_registers_present": bool(send.get("registers")),
        "return_stack_present": bool(send.get("return_stack")),
        "wire_present": (record.get("reconstruction") or {}).get("wire") is not None,
        "transmitted": record.get("transmitted"),
        "filter": record.get("filter"),
        "missing_evidence": provenance.get("missing") or [],
        "split": (record.get("reconstruction") or {}).get("split"),
        "combined": (record.get("reconstruction") or {}).get("combined"),
        "retransmitted": (record.get("reconstruction") or {}).get("retransmitted"),
    }


def explain(records, at_ns, window_ns=5_000_000_000, pid=None, max_messages=200):
    start_ns = at_ns - window_ns
    end_ns = at_ns + window_ns
    window = []
    for record in records:
        if record.get("record_type") == "session":
            continue
        time_ns = record.get("time_ns")
        if time_ns is None or not (start_ns <= time_ns <= end_ns):
            continue
        if pid is not None:
            process = record.get("process") or {}
            if process.get("pid") not in (None, pid):
                continue
        window.append(record)
    window.sort(key=lambda record: (record.get("time_ns") or 0, record.get("order") or 0))
    messages = [record for record in window if record.get("record_type") == "message"]
    chunks = [record for record in window if record.get("record_type") == "transport_chunk"]
    gaps = [record for record in window if record.get("record_type") == "capture_gap"]
    events = [record for record in window if record.get("record_type") == "flow_event"]
    notices = [record for record in window if record.get("record_type") == "notice"]
    decisions = [record for record in window if record.get("record_type") == "filter_decision"]
    before = [
        record for record in records
        if record.get("record_type") == "message" and record.get("time_ns") is not None
        and record["time_ns"] < start_ns
    ]
    before.sort(key=lambda record: (record.get("time_ns") or 0, record.get("order") or 0))
    last_before = before[-10:]
    message_summaries = [_message_summary(record) for record in messages[:max_messages]]
    missing_counts = Counter()
    for summary in message_summaries:
        for item in summary["missing_evidence"]:
            missing_counts[item.get("field") or "unknown"] += 1
    filter_actions = Counter(
        (summary.get("filter") or {}).get("action")
        for summary in message_summaries if summary.get("filter")
    )
    dropped = [
        summary for summary in message_summaries
        if (summary.get("filter") or {}).get("action") == "drop"
        or summary.get("transmitted") is False
    ]
    return {
        "at_ns": at_ns,
        "at_utc": format_ns(at_ns),
        "window_ns": window_ns,
        "window_start_utc": format_ns(start_ns),
        "window_end_utc": format_ns(end_ns),
        "pid_filter": pid,
        "counts": {
            "window_records": len(window),
            "messages": len(messages),
            "transport_chunks": len(chunks),
            "capture_gaps": len(gaps),
            "flow_events": len(events),
            "policy_decisions": len(decisions),
            "notices": len(notices),
        },
        "messages": message_summaries,
        "transport_chunks": [
            {
                "message_id": record.get("message_id"),
                "time_ns": record.get("time_ns"),
                "time_utc": record.get("time_utc"),
                "length": (record.get("message") or {}).get("raw_bytes_length"),
                "protocol": (record.get("message") or {}).get("protocol"),
                "notes": (record.get("message") or {}).get("notes"),
            }
            for record in chunks[:max_messages]
        ],
        "capture_gaps": [
            {
                "message_id": record.get("message_id"),
                "time_ns": record.get("time_ns"),
                "missing_bytes": (record.get("reconstruction") or {}).get("missing_bytes"),
                "reason": (record.get("reconstruction") or {}).get("reason"),
            }
            for record in gaps
        ],
        "flow_events": [record.get("event") for record in events],
        "policy_decisions": [
            {
                "time_ns": record.get("time_ns"),
                "time_utc": record.get("time_utc"),
                "source_kind": record.get("source_kind"),
                "decision": record.get("decision"),
            }
            for record in decisions[:max_messages]
        ],
        "notices": [record.get("notice") for record in notices[:max_messages]],
        "last_messages_before_window": [_message_summary(record) for record in last_before],
        "missing_evidence_counts": dict(missing_counts),
        "filter_actions": dict(filter_actions),
        "policy_dropped_or_absent": dropped,
        "assessment": {
            "statement": (
                "This report lists captured evidence and timing around the requested instant. "
                "It does not prove that any message, instruction, or filter decision caused a crash or malfunction."
            ),
            "what_to_check": [
                "Compare the last pre-event messages with their constructor/serializer and wire-match completeness.",
                "Check whether a policy action was 'drop' or a send is marked transmitted=false.",
                "Check flow_event reset/close/retransmit records and capture_gap records in the same window.",
                "Treat a missing constructor or wire frame as missing evidence, not as proof that the message was absent.",
            ],
        },
    }


def trace(records, message_id):
    match = next((record for record in records if record.get("message_id") == message_id), None)
    if match is None:
        return None
    result = {
        "message_id": message_id,
        "record": match,
        "filter_decision": match.get("filter"),
    }
    provenance = match.get("provenance") or {}
    construction = provenance.get("constructor")
    if construction:
        related = [
            record for record in records
            if record.get("record_type") == "message"
            and (record.get("provenance") or {}).get("constructor", {}).get("construction_id")
            == construction.get("construction_id")
        ]
        result["same_construction_messages"] = [
            {
                "message_id": record.get("message_id"),
                "time_ns": record.get("time_ns"),
                "opcode": ((record.get("message") or {}).get("type") or {}).get("opcode_hex"),
            }
            for record in related
        ]
    return result


def format_text(report):
    lines = [
        f"Evidence window: {report['window_start_utc']} .. {report['window_end_utc']} "
        f"(at {report['at_utc']}, +/- {report['window_ns'] / 1e9:.1f}s)",
        f"Counts: {report['counts']}",
        "",
        "Messages in window (oldest first):",
    ]
    if not report["messages"]:
        lines.append("  (none)")
    for item in report["messages"]:
        message_type = item.get("type") or {}
        process = item.get("process") or {}
        evidence = []
        if item.get("in_process"):
            evidence.append("in-process")
        if item.get("constructor_present"):
            evidence.append(f"ctor+{item.get('serialization_steps')} steps")
        if item.get("wire_present"):
            evidence.append("wire")
        if item.get("filter"):
            evidence.append(f"filter={item['filter'].get('action')}/{item['filter'].get('rule_id')}")
        lines.append(
            f"  {item.get('time_utc')} {item.get('message_id')} "
            f"{process.get('name') or '<process missing>'} "
            f"{message_type.get('name') or '<type unknown>'}"
            f"({message_type.get('opcode_hex') or '-'}) len={item.get('length')} "
            f"decode={item.get('decode_status')} evidence={','.join(evidence) or 'none'}"
        )
        if item.get("missing_evidence"):
            lines.append(f"    missing: {', '.join(str(value.get('field')) for value in item['missing_evidence'])}")
    lines.extend(["", "Last messages before the window:"])
    if not report["last_messages_before_window"]:
        lines.append("  (none)")
    for item in report["last_messages_before_window"]:
        message_type = item.get("type") or {}
        lines.append(
            f"  {item.get('time_utc')} {item.get('message_id')} "
            f"{message_type.get('name') or '<type unknown>'} len={item.get('length')}"
        )
    lines.extend(["", "Flow events in window:"])
    if not report["flow_events"]:
        lines.append("  (none)")
    for event in report["flow_events"]:
        lines.append(
            f"  {format_ns(event.get('time_ns'))} {event.get('kind')} "
            f"pid={event.get('pid')} local={event.get('local')} remote={event.get('remote')} "
            f"detail={event.get('detail')}"
        )
    lines.extend(["", "Policy/enforcement decisions in window:"])
    if not report["policy_decisions"]:
        lines.append("  (none)")
    for item in report["policy_decisions"]:
        decision = item.get("decision") or {}
        lines.append(
            f"  {item.get('time_utc')} {item.get('source_kind')} "
            f"action={decision.get('action')} rule={decision.get('rule_id')} "
            f"{decision.get('text') or ''}"
        )
    lines.extend(["", "Capture gaps in window:"])
    if not report["capture_gaps"]:
        lines.append("  (none)")
    for gap in report["capture_gaps"]:
        lines.append(f"  {gap.get('time_ns')} missing={gap.get('missing_bytes')} {gap.get('reason')}")
    lines.extend([
        "",
        "Assessment:",
        f"  {report['assessment']['statement']}",
    ])
    for item in report["assessment"]["what_to_check"]:
        lines.append(f"  - {item}")
    return "\n".join(lines)
