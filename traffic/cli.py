"""Command line entry point: python -m traffic ..."""

from __future__ import annotations

import argparse
import json
import sys
import unittest
from pathlib import Path

from .explain import explain, format_text, trace
from .ledger import build, load_records, write_ledger
from .policy import evaluate, load_policy, policy_to_kfilter
from .util import format_ns, parse_time_ns, write_jsonl


def _add_inputs(parser):
    parser.add_argument("--pcap", action="append", default=[], metavar="PATH",
                        help="pcap/pcapng file or directory; repeatable")
    parser.add_argument("--capture", action="append", default=[], metavar="PATH",
                        help="client-control send/constructor JSONL file or directory; repeatable")
    parser.add_argument("--monitor", action="append", default=[], metavar="PATH",
                        help="monitor-filter session bundle, events.jsonl, or directory; repeatable")
    parser.add_argument("--ngs", action="append", default=[], metavar="PATH",
                        help="ngs-mitm.py / ngs-proxy.py JSONL or .mitm file; repeatable")


def _cmd_ingest(args):
    ledger = build(
        pcap_paths=args.pcap,
        plaintext_paths=args.capture,
        monitor_paths=args.monitor,
        ngs_paths=args.ngs,
        policy_path=args.policy,
        client_endpoint=tuple(args.client_endpoint.rsplit(":", 1)) if args.client_endpoint else None,
        include_chunks=not args.no_chunks,
        join_window_ns=int(args.join_window * 1_000_000_000),
        label=args.label,
        profile_path=args.profile,
    )
    out = write_ledger(ledger, args.out)
    print(f"WROTE {out}")
    print(json.dumps(ledger.summary.get("record_counts", {}), sort_keys=True))
    print(json.dumps(ledger.summary.get("message_protocols", {}), sort_keys=True))
    if ledger.summary.get("filter_actions"):
        print(f"filter actions: {json.dumps(ledger.summary['filter_actions'], sort_keys=True)}")
    if args.print_messages:
        _print_messages(ledger.records)
    return 0


def _message_matches(record, args):
    if record.get("record_type") != "message":
        return False
    message = record.get("message") or {}
    message_type = message.get("type") or {}
    process = record.get("process") or {}
    if args.process:
        value = process.get("name") or ""
        if args.process.lower() not in value.lower():
            return False
    if args.protocol and message.get("protocol") != args.protocol:
        return False
    if args.opcode:
        expected = int(args.opcode, 0)
        if (message_type.get("opcode") or -1) != expected:
            return False
    if args.type:
        value = (message_type.get("name") or "").lower()
        if args.type.lower() not in value:
            return False
    if args.decode_status and message.get("decode_status") != args.decode_status:
        return False
    if args.after and (record.get("time_ns") or 0) < parse_time_ns(args.after):
        return False
    if args.before and (record.get("time_ns") or 0) > parse_time_ns(args.before):
        return False
    return True


def _print_messages(records):
    for record in records:
        if record.get("record_type") != "message":
            continue
        message = record.get("message") or {}
        message_type = message.get("type") or {}
        process = record.get("process") or {}
        print(
            f"{record.get('time_utc') or '<no time>'} {record.get('message_id')} "
            f"{process.get('name') or '<process missing>'} {message.get('protocol')} "
            f"{message_type.get('name') or '<type unknown>'} "
            f"{message_type.get('opcode_hex') or '-'} len={message.get('raw_bytes_length')} "
            f"decode={message.get('decode_status')} "
            f"wire={((record.get('reconstruction') or {}).get('wire') is not None)} "
            f"filter={(record.get('filter') or {}).get('action') or '-'}"
        )


def _cmd_show(args):
    records = load_records(args.ledger)
    if args.json:
        selected = [record for record in records if _message_matches(record, args)]
        print(json.dumps(selected[:args.limit], indent=2, sort_keys=True))
        return 0
    count = 0
    for record in records:
        if not _message_matches(record, args):
            continue
        message = record.get("message") or {}
        message_type = message.get("type") or {}
        process = record.get("process") or {}
        print(
            f"{record.get('time_utc') or '<no time>'} {record.get('message_id')} "
            f"{process.get('name') or '<process missing>'} {message.get('protocol')} "
            f"{message_type.get('name') or '<type unknown>'} "
            f"{message_type.get('opcode_hex') or '-'} len={message.get('raw_bytes_length')} "
            f"decode={message.get('decode_status')} "
            f"split={((record.get('reconstruction') or {}).get('split'))} "
            f"combined={((record.get('reconstruction') or {}).get('combined'))} "
            f"filter={(record.get('filter') or {}).get('action') or '-'}"
        )
        count += 1
        if count >= args.limit:
            break
    if count == 0:
        print("no matching messages", file=sys.stderr)
    return 0


def _cmd_explain(args):
    records = load_records(args.ledger)
    at_ns = parse_time_ns(args.at)
    if at_ns is None:
        raise SystemExit(f"cannot parse --at value {args.at!r}")
    report = explain(
        records, at_ns,
        window_ns=int(args.window * 1_000_000_000),
        pid=args.pid,
    )
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(format_text(report))
    return 0


def _cmd_trace(args):
    records = load_records(args.ledger)
    result = trace(records, args.id)
    if result is None:
        print(f"message {args.id!r} not found", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _cmd_filter(args):
    records = load_records(args.ledger)
    policy = load_policy(args.policy)
    decisions = []
    output = []
    for record in records:
        if record.get("record_type") == "session":
            output.append(record)
            continue
        if record.get("record_type") != "message":
            output.append(record)
            continue
        decision = evaluate(policy, record)
        record = dict(record)
        record["filter"] = {
            "policy": decision["policy"],
            "matched": decision["matched"],
            "rule_id": decision["rule_id"],
            "action": decision["action"],
            "reason": decision["reason"],
            "missing_evidence": decision["missing_evidence"],
            "simulated_offline": True,
        }
        output.append(record)
        decisions.append({
            "ledger_session_id": record.get("ledger_session_id"),
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
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    write_jsonl(out / "ledger.jsonl", output)
    write_jsonl(out / "decisions.jsonl", decisions)
    (out / "summary.json").write_text(
        json.dumps({
            "schema": "client-control.traffic/v1",
            "policy": policy.summary(),
            "messages": sum(1 for record in output if record.get("record_type") == "message"),
            "decisions": len(decisions),
            "actions": {
                action: sum(1 for decision in decisions if decision["decision"]["action"] == action)
                for action in ("allow", "drop", "audit")
            },
        }, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"WROTE {out} decisions={len(decisions)}")
    return 0


def _cmd_kfilter(args):
    policy = load_policy(args.policy)
    text = policy_to_kfilter(policy)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"WROTE {args.out}")
    else:
        print(text, end="")
    return 0


def _cmd_selftest(args):
    start = Path(__file__).resolve().parent
    suite = unittest.defaultTestLoader.discover(str(start / "tests"), pattern="test_*.py")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


def build_parser():
    parser = argparse.ArgumentParser(
        prog="python -m traffic",
        description="Ordered, evidence-labelled client->server traffic ledger.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    ingest = sub.add_parser("ingest", help="build a ledger from capture sources")
    _add_inputs(ingest)
    ingest.add_argument("--out", required=True, metavar="DIR")
    ingest.add_argument("--policy", metavar="FILE", help="evaluate this filter policy on every message")
    ingest.add_argument("--client-endpoint", metavar="IP:PORT",
                        help="override client endpoint when a pcap has no SYN/local-address evidence")
    ingest.add_argument("--no-chunks", action="store_true",
                        help="do not emit transport_chunk records for unclaimed bytes")
    ingest.add_argument("--join-window", type=float, default=5.0,
                        help="plaintext/wire join window in seconds (default 5)")
    ingest.add_argument("--label", help="operator label stored in the session record")
    ingest.add_argument("--profile", metavar="FILE", help="override foundations/profile.json")
    ingest.add_argument("--print-messages", action="store_true")
    ingest.set_defaults(func=_cmd_ingest)

    show = sub.add_parser("show", help="list messages from a ledger")
    show.add_argument("ledger", metavar="DIR_OR_LEDGER_JSONL")
    show.add_argument("--process")
    show.add_argument("--protocol")
    show.add_argument("--opcode")
    show.add_argument("--type")
    show.add_argument("--decode-status")
    show.add_argument("--after")
    show.add_argument("--before")
    show.add_argument("--limit", type=int, default=200)
    show.add_argument("--json", action="store_true")
    show.set_defaults(func=_cmd_show)

    explain_parser = sub.add_parser("explain", help="report evidence around a timestamp")
    explain_parser.add_argument("ledger", metavar="DIR_OR_LEDGER_JSONL")
    explain_parser.add_argument("--at", required=True, help="ISO-8601, epoch seconds, or nanoseconds")
    explain_parser.add_argument("--window", type=float, default=5.0, help="seconds before and after")
    explain_parser.add_argument("--pid", type=int)
    explain_parser.add_argument("--json", action="store_true")
    explain_parser.set_defaults(func=_cmd_explain)

    trace_parser = sub.add_parser("trace", help="print one message's full provenance chain")
    trace_parser.add_argument("ledger", metavar="DIR_OR_LEDGER_JSONL")
    trace_parser.add_argument("--id", required=True, dest="id")
    trace_parser.set_defaults(func=_cmd_trace)

    filter_parser = sub.add_parser("filter", help="evaluate a policy over an existing ledger")
    filter_parser.add_argument("ledger", metavar="DIR_OR_LEDGER_JSONL")
    filter_parser.add_argument("--policy", required=True)
    filter_parser.add_argument("--out", required=True, metavar="DIR")
    filter_parser.set_defaults(func=_cmd_filter)

    kfilter = sub.add_parser("kfilter-policy", help="emit the kfilter message-rule subset")
    kfilter.add_argument("--policy", required=True)
    kfilter.add_argument("--out")
    kfilter.set_defaults(func=_cmd_kfilter)

    selftest = sub.add_parser("selftest", help="run the offline unit tests")
    selftest.set_defaults(func=_cmd_selftest)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
