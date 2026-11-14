"""Build an ordered, evidence-linked traffic ledger from client-control and msmon captures."""

import argparse
import base64
from collections import Counter, defaultdict
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import struct
import sys
import uuid
import zipfile
import zlib

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "foundations"))
import ngs_cipher
from packet_fields import decode_game_body
from traffic_capture import parse_capture, reassemble_tcp, timestamp_ns, timestamp_text
from traffic_policy import Policy
from traffic_protocols import (PLAIN_TO_WIRE, decode_dns_datagram, decode_http_run, decode_maple_run,
                               decode_tls_run)


SCHEMA = "client-control.traffic.v1"
ZERO_CHAIN = "0" * 64


def raw_bytes(data, scope, complete=True, total=None):
    if data is None:
        return {"present": False, "scope": scope, "complete": False}
    data = bytes(data)
    return {
        "present": True,
        "encoding": "base64",
        "data": base64.b64encode(data).decode("ascii"),
        "bytes": len(data),
        "total_bytes": len(data) if total is None else total,
        "sha256": hashlib.sha256(data).hexdigest(),
        "scope": scope,
        "complete": complete and len(data) == (len(data) if total is None else total),
    }


def parse_detail(text):
    return dict(part.split("=", 1) for part in (text or "").split(";") if "=" in part)


def socket_name(text):
    match = re.search(r"socket:\[(\d+)\]", text or "")
    return match.group(1) if match else None


def endpoint(text):
    if not text:
        return None
    match = re.match(r"(?:\[([^]]+)\]|([^:]+)):(\d+)$", text)
    if not match:
        return {"text": text}
    return {"address": match.group(1) or match.group(2), "port": int(match.group(3))}


def endpoint_pair(text):
    if not text or " -> " not in text:
        return None, None
    left, right = text.split(" -> ", 1)
    return endpoint(left), endpoint(right)


def verify_chain_line(line, previous, source):
    record = json.loads(line)
    chain = record.get("chain")
    marker = f',"chain":"{chain}"}}'
    if not isinstance(chain, str) or not line.endswith(marker):
        raise ValueError(f"{source}: missing final SHA-256 chain")
    original = line[:-len(marker)] + "}"
    expected = hashlib.sha256((previous + original).encode()).hexdigest()
    if chain != expected:
        raise ValueError(f"{source}: SHA-256 chain mismatch")
    return record, chain


class RecordStore:
    def __init__(self, output, inputs):
        self.output = Path(output)
        self.output.mkdir(parents=True, mode=0o700, exist_ok=False)
        os.chmod(self.output, 0o700)
        self.session_id = uuid.uuid4().hex
        self.database = sqlite3.connect(self.output / ".records.sqlite")
        self.database.execute("CREATE TABLE records (ordinal INTEGER PRIMARY KEY, time_ns INTEGER, json TEXT NOT NULL)")
        self.ordinal = 0
        self.counts = Counter()
        self.inputs = inputs
        self.complete = True
        self.decoded_complete = True

    def add(self, record, time_ns=None):
        self.ordinal += 1
        record.setdefault("schema", SCHEMA)
        record.setdefault("ledger_session_id", self.session_id)
        record.setdefault("record_id", f"r{self.ordinal}")
        if time_ns is not None:
            record.setdefault("time_ns", time_ns)
            record.setdefault("time_utc", timestamp_text(time_ns))
        record["input_order"] = self.ordinal
        kind = record.get("kind", "unknown")
        self.counts[kind] += 1
        if kind == "message":
            status = record.get("decode", {}).get("status", "unknown")
            self.counts[f"decode_{status}"] += 1
            if status not in ("decoded", "plaintext"):
                self.decoded_complete = False
        if record.get("complete") is False or record.get("raw", {}).get("complete") is False:
            self.complete = False
        self.database.execute(
            "INSERT INTO records (ordinal, time_ns, json) VALUES (?, ?, ?)",
            (self.ordinal, time_ns, json.dumps(record, separators=(",", ":"), ensure_ascii=True)),
        )
        return record["record_id"]

    def finish(self):
        path = self.output / "traffic.jsonl"
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        chain = ZERO_CHAIN
        index = 0
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            for _, encoded in self.database.execute(
                "SELECT time_ns, json FROM records ORDER BY time_ns IS NULL, time_ns, ordinal"
            ):
                record = json.loads(encoded)
                index += 1
                record["record_index"] = index
                record["ordering"] = {
                    "basis": "source_timestamp_then_input_order",
                    "input_order": record["input_order"],
                    "tie_break_is_causal": False,
                }
                original = json.dumps(record, separators=(",", ":"), ensure_ascii=True)
                chain = hashlib.sha256((chain + original).encode()).hexdigest()
                stream.write(original[:-1] + ',"chain":"' + chain + '"}\n')
        self.database.close()
        (self.output / ".records.sqlite").unlink()
        summary = {
            "schema": SCHEMA,
            "ledger_session_id": self.session_id,
            "records": index,
            "counts": dict(sorted(self.counts.items())),
            "complete_capture_claim": False,
            "all_observed_bytes_complete": self.complete,
            "all_messages_fully_decoded": self.decoded_complete,
            "completeness_note": "Completeness is limited by each source's documented coverage and recorded gaps; unknown decodes remain unknown.",
            "inputs": self.inputs,
            "final_chain": chain,
        }
        summary_path = self.output / "summary.json"
        descriptor = os.open(summary_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(summary, stream, indent=2, sort_keys=True)
            stream.write("\n")
        return summary


class ProcessIndex:
    def __init__(self):
        self.starts = defaultdict(list)
        self.exits = defaultdict(list)
        self.build = {}

    def event(self, record):
        pid = record.get("process_id")
        if pid is None:
            return
        if record.get("type") == "process_start":
            self.starts[pid].append(record)
        elif record.get("type") == "process_exit":
            self.exits[pid].append(record)

    def lookup(self, pid, time_ns=None, fallback_name=None):
        candidates = self.starts.get(pid, [])
        selected = None
        for record in candidates:
            start = timestamp_ns(record.get("timestamp"))
            if time_ns is None or start is None or start <= time_ns:
                selected = record
        if selected is None and fallback_name is None:
            return {"pid": pid, "name": None, "evidence": "process_start_not_found"}
        result = {
            "pid": pid,
            "name": fallback_name or (selected or {}).get("process_path") or (selected or {}).get("text"),
            "path": (selected or {}).get("process_path") or (selected or {}).get("text"),
            "start_time": (selected or {}).get("process_start_time"),
            "evidence": "msmon_process_start" if selected else "capture_comment_only",
        }
        if selected is not None and time_ns is not None:
            started = timestamp_ns(selected.get("timestamp"))
            for exit_record in self.exits.get(pid, []):
                exited = timestamp_ns(exit_record.get("timestamp"))
                if exited is not None and (started is None or started <= exited) and exited < time_ns:
                    return {"pid": pid, "name": fallback_name, "path": None,
                            "evidence": "process_exited_before_observation",
                            "previous_incarnation_start": selected.get("process_start_time")}
        if result["name"] and ("MapleStory.exe" in result["name"] or fallback_name == "MapleStory.exe"):
            result["game_build"] = self.build.get("game")
        return result


class TraceIndex:
    def __init__(self):
        self.sends = []
        self.by_tail = defaultdict(list)
        self.constructors = {}
        self.fields = defaultdict(list)
        self.sessions = {}

    def add(self, record):
        kind = record.get("kind") or record.get("direction")
        if kind == "session_start" and "session_id" in record:
            self.sessions[record["session_id"]] = record
        if kind == "constructor":
            identifier = record.get("construction_id")
            if identifier:
                self.constructors[identifier] = record
        elif kind in ("field_change", "field_trace"):
            identifier = record.get("construction_id")
            if identifier:
                self.fields[identifier].append(record)
        if record.get("direction") == "client_to_server" and record.get("body"):
            try:
                body = bytes.fromhex(record["body"])
            except ValueError:
                return
            record["_body_bytes"] = body
            record["_time_ns"] = timestamp_ns(record.get("wall_time_ns", record.get("timestamp")))
            self.sends.append(record)
            if len(body) >= 2:
                self.by_tail[hashlib.sha256(body[2:]).digest()].append(record)

    def match(self, plaintext, time_ns, pid=None):
        if plaintext is None or len(plaintext) < 2:
            return None
        candidates = [
            record for record in self.by_tail.get(hashlib.sha256(plaintext[2:]).digest(), [])
            if len(record["_body_bytes"]) == len(plaintext)
            and record["_body_bytes"][2:] == plaintext[2:]
            and (pid is None or record.get("pid") in (None, pid))
        ]
        if not candidates:
            return None
        if time_ns is None:
            selected = candidates[0]
        else:
            selected = min(candidates, key=lambda record: abs((record["_time_ns"] or time_ns) - time_ns))
        return {
            "chain": self.chain(selected),
            "correlation": {
                "method": "same_length_and_plaintext_after_wire_opcode",
                "candidate_count": len(candidates),
                "ambiguous_duplicate_bodies": len(candidates) > 1,
                "causal_claim": False,
            },
        }

    def chain(self, send):
        identifier = send.get("construction_id")
        constructor = self.constructors.get(identifier) or send.get("constructor")
        changes = list(self.fields.get(identifier, [])) or list(send.get("field_trace", []))
        changes.sort(key=lambda record: record.get("event_index", record.get("index", 0)))
        serializers = []
        previous = None
        for change in changes:
            body = bytes.fromhex(change["body"]) if change.get("body") else None
            write = None
            if previous is not None and body is not None:
                differences = [index for index, (left, right) in enumerate(zip(previous, body)) if left != right]
                if len(previous) != len(body):
                    differences = list(range(min(len(previous), len(body)), max(len(previous), len(body))))
                write = [{"offset": index, "before": previous[index] if index < len(previous) else None,
                          "after": body[index] if index < len(body) else None} for index in differences]
            serializers.append({
                "event_index": change.get("event_index", change.get("index")),
                "previous_length": change.get("previous_length"),
                "length": change.get("length"),
                "body_hex": change.get("body"),
                "changed_bytes": write,
                "rip_after_write": change.get("rip_after_write", change.get("rip")),
                "rva_after_write": change.get("rva_after_write"),
                "registers": change.get("registers"),
                "floating_registers": change.get("floating_registers"),
                "return_stack": change.get("return_stack"),
                "evidence": "hardware_length_watchpoint_snapshot",
            })
            if body is not None:
                previous = body
        send_evidence = {key: value for key, value in send.items() if not key.startswith("_")}
        return {
            "construction_id": identifier,
            "constructor": constructor,
            "serialization_steps": serializers,
            "send": send_evidence,
            "constructor_evidence": "linked" if constructor else "missing",
            "serialization_evidence": "observed" if serializers else "not_captured_enable_deep_opcode",
            "memory_evidence": "present" if send.get("memory") or send.get("full_memory_diff") else "not_captured",
            "inputs": {
                "constructor_opcode": (constructor or {}).get("opcode"),
                "send_rcx": (send.get("registers") or {}).get("rcx"),
                "packet_va": send.get("packet_va"),
                "body_va": send.get("body_va"),
            },
        }


class LedgerBuilder:
    def __init__(self, output, policy=None, client_ips=()):
        self.inputs = []
        self.store = RecordStore(output, self.inputs)
        self.policy = policy or Policy()
        self.client_ips = set(client_ips)
        self.processes = ProcessIndex()
        self.traces = TraceIndex()
        self.pending_packets = []

    def input(self, path, kind):
        path = Path(path)
        digest = hashlib.sha256()
        if path.is_dir():
            files = sorted(file for file in path.rglob("*") if file.is_file())
            size = 0
            for file in files:
                file_digest = hashlib.sha256()
                with file.open("rb") as stream:
                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        file_digest.update(block)
                content_hash = file_digest.hexdigest()
                size += file.stat().st_size
                digest.update(file.relative_to(path).as_posix().encode() + b"\0" + content_hash.encode())
        else:
            size = path.stat().st_size
            with path.open("rb") as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(block)
        self.inputs.append({"kind": kind, "path": str(path), "bytes": size, "sha256": digest.hexdigest()})

    def packet_direction(self, packet):
        if packet.get("direction_flag") == 2:
            return "client_to_server", "pcapng_epb_flags"
        if packet.get("direction_flag") == 1:
            return "server_to_client", "pcapng_epb_flags"
        source = packet.get("source_ip")
        destination = packet.get("destination_ip")
        if source in self.client_ips:
            return "client_to_server", "operator_client_ip"
        if destination in self.client_ips:
            return "server_to_client", "operator_client_ip"
        return "unknown", "direction_unavailable"

    def packet_process(self, packet):
        return self.processes.lookup(packet.get("process_id"), packet.get("time_ns"), packet.get("process_name"))

    def packet_socket(self, packet, direction=None):
        source = endpoint(f"{packet.get('source_ip')}:{packet.get('source_port')}") if packet.get("source_ip") else None
        destination = endpoint(f"{packet.get('destination_ip')}:{packet.get('destination_port')}") if packet.get("destination_ip") else None
        return {
            "inode": packet.get("socket_inode"),
            "cookie": packet.get("socket_cookie"),
            "protocol": packet.get("transport_protocol"),
            "source": source,
            "destination": destination,
            "local": source if direction == "client_to_server" else destination if direction == "server_to_client" else None,
            "remote": destination if direction == "client_to_server" else source if direction == "server_to_client" else None,
        }

    def add_message(self, decoded, raw, plaintext, time_ns, process, socket, direction, evidence,
                    raw_scope, session=None, transport=None, trace=None, time_end_ns=None, observed_decision=None):
        message = {
            "process": process.get("name") if isinstance(process, dict) else process,
            "pid": process.get("pid") if isinstance(process, dict) else None,
            "protocol": decoded.get("protocol"),
            "type": decoded.get("type"),
            "direction": direction,
            "fields": decoded.get("fields", {}),
            "destination": (socket or {}).get("remote"),
        }
        if observed_decision is None:
            evaluation = self.policy.decide(message)
            evaluation.update({"stage": "offline_observation", "applied": False, "original_traffic_unchanged": True})
        else:
            evaluation = dict(observed_decision)
            evaluation.update({"stage": "captured_live_decision", "applied": True})
        record = {
            "kind": "message",
            "session": session,
            "process": process,
            "game_build": (process or {}).get("game_build") if isinstance(process, dict) else None,
            "socket": socket,
            "direction": direction,
            "time_end_ns": time_end_ns,
            "time_end_utc": timestamp_text(time_end_ns),
            "transport": transport,
            "raw": raw_bytes(raw, raw_scope),
            "plaintext": raw_bytes(plaintext, "application_plaintext") if plaintext is not None else {
                "present": False, "complete": False, "reason": decoded.get("status", "plaintext_unavailable"),
            },
            "decode": decoded,
            "trace": trace,
            "evidence": evidence,
            "policy_evaluation": evaluation,
        }
        return self.store.add(record, time_ns)

    def add_trace(self, path):
        self.input(path, "ptrace_jsonl")
        with Path(path).open(encoding="utf-8") as stream:
            records = [json.loads(line) for line in stream if line.strip()]
        for record in records:
            self.traces.add(record)
        for record in records:
            kind = record.get("kind") or record.get("direction")
            time_ns = timestamp_ns(record.get("wall_time_ns", record.get("timestamp")))
            session = record.get("session_id")
            start = self.traces.sessions.get(session, {})
            build = dict(start.get("game_build") or {"pe_timestamp": start.get("pe_timestamp")})
            build.update({"module_base": start.get("module_base"), "sendpacket_rva": start.get("sendpacket_rva"),
                          "constructor_rva": start.get("constructor_rva")})
            process = {"pid": record.get("pid"), "name": "MapleStory.exe", "game_build": build,
                       "evidence": "ptrace_capture"}
            if record.get("direction") == "client_to_server" and record.get("body"):
                body = bytes.fromhex(record["body"])
                decoded = decode_game_body(body)
                trace = self.traces.chain(record)
                observed = record.get("filter_decision")
                if observed is None and record.get("dropped"):
                    observed = {"action": "drop", "effective_action": "drop", "forward": False,
                                "rule_id": None, "reason": "legacy dropped=true; original rule unavailable"}
                identifier = self.add_message(
                    decoded, body, body, time_ns, process, None, "client_to_server",
                    [{"file": str(path), "event_index": record.get("event_index", record.get("index"))}],
                    "COutPacket_plaintext", session=session, trace=trace, observed_decision=observed,
                )
                record["_ledger_message_id"] = identifier
                if observed is not None:
                    self.store.add({"kind": "filter_decision", "message_id": identifier, "session_id": session,
                                    "process": process, "decision": observed, "applied": True,
                                    "evidence": [{"file": str(path), "event_index": record.get("event_index", record.get("index"))}]}, time_ns)
            else:
                self.store.add({
                    "kind": "trace_event", "trace_kind": kind, "session_id": session,
                    "process": process, "game_build": build, "trace": record,
                    "socket": {"address": record.get("socket_va"), "identity_kind": "user_space_socket_object"}
                    if record.get("socket_va") else None,
                }, time_ns)

    def add_capture(self, path):
        self.input(path, "packet_capture")
        self.add_capture_data(Path(path).read_bytes(), str(path))

    def add_capture_data(self, data, source):
        packets = parse_capture(data, source)
        for packet in packets:
            direction, direction_evidence = self.packet_direction(packet)
            raw = packet.pop("data")
            payload = packet.get("payload")
            record = {
                "kind": "packet",
                "process": self.packet_process(packet),
                "socket": self.packet_socket(packet, direction),
                "direction": direction,
                "direction_evidence": direction_evidence,
                "raw": raw_bytes(raw, "captured_link_frame", packet["complete_capture"], packet.get("original_length")),
                "transport_payload": raw_bytes(payload, "transport_payload", packet["complete_capture"])
                if payload is not None else {"present": False, "complete": packet["complete_capture"]},
                "packet": {key: value for key, value in packet.items() if key not in ("payload", "evidence", "metadata")},
                "capture_metadata": packet.get("metadata"),
                "evidence": [packet["evidence"]],
            }
            self.store.add(record, packet.get("time_ns"))
        self.pending_packets.extend(
            packet for packet in packets if packet.get("transport_protocol") == "tcp"
        )
        for packet in packets:
            if packet.get("transport_protocol") != "udp" or not packet.get("payload"):
                continue
            direction, evidence = self.packet_direction(packet)
            decoded = decode_dns_datagram(packet["payload"]) if packet.get("destination_port") == 53 or packet.get("source_port") == 53 else None
            if decoded is None:
                decoded = {"protocol": "udp", "type": None, "name": None, "status": "unknown", "fields": {},
                           "unresolved_ranges": [{"offset": 0, "length": len(packet["payload"])}]}
            self.add_message(
                decoded, packet["payload"], packet["payload"], packet.get("time_ns"), self.packet_process(packet),
                self.packet_socket(packet, direction), direction, [packet["evidence"]], "udp_datagram_payload",
                transport={"datagram": True, "direction_evidence": evidence},
            )

    def frame_provenance(self, stream, run, offset, length):
        absolute = run["stream_offset"] + offset
        first_sequence = stream["first_sequence"]
        evidence = []
        times = []
        pids = set()
        for packet in stream["segments"]:
            delta = (packet["sequence"] - first_sequence) & 0xFFFFFFFF
            if delta & 0x80000000:
                delta -= 0x100000000
            start = delta
            end = start + len(packet["payload"])
            if start < absolute + length and end > absolute:
                evidence.append(packet["evidence"])
                if packet.get("time_ns") is not None:
                    times.append(packet["time_ns"])
                if packet.get("process_id") is not None:
                    pids.add(packet["process_id"])
        return evidence, min(times) if times else None, max(times) if times else None, sorted(pids)

    def add_stream(self, stream, source):
        first = stream["segments"][0]
        direction, direction_evidence = self.packet_direction(first)
        for gap in stream["gaps"]:
            self.store.complete = False
            self.store.add({"kind": "coverage", "coverage": "missing_tcp_bytes", "socket": self.packet_socket(first, direction),
                            "gap": gap, "evidence": [first["evidence"]]}, first.get("time_ns"))
        for conflict in stream["overlap_conflicts"]:
            self.store.complete = False
            self.store.add({"kind": "coverage", "coverage": "conflicting_tcp_overlap", "socket": self.packet_socket(first, direction),
                            "conflict": conflict, "resolution": "first_captured_byte_kept",
                            "evidence": [first["evidence"]]}, first.get("time_ns"))
        for run in stream["runs"]:
            data = run["data"]
            result = decode_maple_run(data, direction)
            if not result["recognized"]:
                result = decode_tls_run(data)
            if not result["recognized"]:
                result = decode_http_run(data)
            if not result["recognized"]:
                evidence, start, end, _ = self.frame_provenance(stream, run, 0, len(data))
                decoded = {"protocol": "tcp", "type": None, "name": None, "status": "unknown", "fields": {},
                           "unresolved_ranges": [{"offset": 0, "length": len(data)}]}
                self.add_message(decoded, data, data, start, self.packet_process(first), self.packet_socket(first, direction),
                                 direction, evidence, "contiguous_tcp_bytes", transport={"reassembly": "unknown_protocol"},
                                 time_end_ns=end)
                continue
            for frame in result["frames"]:
                evidence, start, end, pids = self.frame_provenance(stream, run, frame["offset"], len(frame["raw"]))
                process = self.packet_process(first)
                if len(pids) > 1:
                    process = dict(process)
                    process["attribution_conflict_pids"] = pids
                decoded = frame["decode"]
                trace = self.traces.match(frame.get("plaintext"), start, first.get("process_id")) if decoded.get("protocol") == "maple" else None
                if trace and not process.get("game_build"):
                    traced_send = trace["chain"]["send"]
                    traced_start = self.traces.sessions.get(traced_send.get("session_id"), {})
                    process = dict(process)
                    process.update({"pid": process.get("pid") or traced_send.get("pid"),
                                    "name": process.get("name") or "MapleStory.exe",
                                    "game_build": traced_start.get("game_build") or {
                                        "pe_timestamp": traced_start.get("pe_timestamp"),
                                        "module_base": traced_start.get("module_base"),
                                    }, "evidence": "pcap_plus_ptrace_correlation"})
                self.add_message(
                    decoded, frame["raw"], frame.get("plaintext"), start, process, self.packet_socket(first, direction), direction,
                    evidence, "reconstructed_tcp_message", transport={
                        "stream_offset": run["stream_offset"] + frame["offset"],
                        "retransmitted_bytes_in_stream": stream["retransmitted_bytes"],
                        "direction_evidence": direction_evidence,
                        "cipher_evidence": result.get("cipher_evidence"),
                    }, trace=trace, time_end_ns=end,
                )
            if result["unparsed"]:
                offset = result.get("problem", {}).get("offset", len(data) - len(result["unparsed"]))
                evidence, start, end, _ = self.frame_provenance(stream, run, offset, len(result["unparsed"]))
                decoded = {"protocol": result["frames"][0]["decode"]["protocol"] if result["frames"] else "tcp",
                           "type": None, "name": None, "status": "incomplete", "fields": {},
                           "unresolved_ranges": [{"offset": 0, "length": len(result["unparsed"])}]}
                self.add_message(decoded, result["unparsed"], result["unparsed"], start, self.packet_process(first),
                                 self.packet_socket(first, direction), direction, evidence, "unframed_tcp_tail",
                                 transport={"framing_problem": result["problem"]}, time_end_ns=end)

    def add_msmon(self, source):
        self.input(source, "msmon_bundle")
        source = Path(source)
        if source.is_dir():
            parts = sorted(source.glob("events.jsonl*"), key=lambda path: (
                int(path.suffix[1:]) if path.suffix[1:].isdecimal() else 0
            ))
            captures = [(path.name, path.read_bytes()) for path in source.glob("events.pcapng*")]
            manifest_path = source / "manifest.json"
            manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
            readers = [(str(path), path.read_bytes()) for path in parts]
        elif zipfile.is_zipfile(source):
            with zipfile.ZipFile(source) as archive:
                names = archive.namelist()
                parts = sorted((name for name in names if Path(name).name.startswith("events.jsonl")),
                               key=lambda name: (len(name), name))
                captures = [(name, archive.read(name)) for name in names if Path(name).name.startswith("events.pcapng")]
                manifest = json.loads(archive.read("manifest.json")) if "manifest.json" in names else {}
                readers = [(name, archive.read(name)) for name in parts]
        else:
            readers = [(str(source), source.read_bytes())]
            captures = []
            manifest = {}
        if manifest:
            self.processes.build["game"] = {
                "client_sha256": manifest.get("client_sha256"),
                "client_version": manifest.get("client_version"),
                "session_uuid": manifest.get("session_uuid"),
                "evidence": "msmon_manifest",
            }
        operations = {}
        stream_breaks = []
        previous = ZERO_CHAIN
        for name, content in readers:
            for number, line in enumerate(content.decode("utf-8").splitlines(), 1):
                if not line:
                    continue
                record, previous = verify_chain_line(line, previous, f"{name}:{number}")
                self.processes.event(record)
                payload = record.get("payload")
                if payload and payload.get("kind") in ("network_data", "tls_plaintext"):
                    key = (record.get("session_id"), payload.get("operation_id"))
                    operation = operations.setdefault(key, {"records": [], "chunks": {}})
                    operation["records"].append(record)
                    offset = int(payload["byte_offset"])
                    chunk = base64.b64decode(payload["data"], validate=True)
                    if len(chunk) != int(payload.get("byte_count", len(chunk))):
                        raise ValueError(f"{name}:{number}: payload byte count differs")
                    if offset in operation["chunks"] and operation["chunks"][offset] != chunk:
                        raise ValueError(f"{name}:{number}: conflicting payload chunks")
                    operation["chunks"][offset] = chunk
                elif (record.get("payload_unavailable") or record.get("flags", 0) & 0x80) and record.get("type") in (
                    "file_read", "file_write", "network_connect", "network_accept"
                ):
                    key = (record.get("session_id"), ("unavailable", record.get("record_index", number)))
                    operations.setdefault(key, {"records": [], "chunks": {}})["records"].append(record)
                elif record.get("type") == "observer_sequence_gap":
                    self.store.complete = False
                    stream_breaks.append(timestamp_ns(record.get("timestamp")))
                    self.store.add({"kind": "coverage", "coverage": "msmon_sequence_gap", "gap": record,
                                    "evidence": [{"file": name, "line": number, "chain": record["chain"]}]},
                                   timestamp_ns(record.get("timestamp")))
                elif record.get("type") in ("coverage", "coverage_usage"):
                    fields = parse_detail(record.get("detail"))
                    loss = any(
                        value.isdecimal() and int(value) > 0 and any(token in key for token in (
                            "drop", "missing", "incomplete", "truncated", "unavailable", "unattributed", "skipped",
                            "overwrite", "full", "fault",
                        )) for key, value in fields.items()
                    ) or fields.get("final_read") == "timed_out"
                    self.store.complete = self.store.complete and not loss
                    self.store.add({"kind": "coverage", "coverage": record.get("text"),
                                    "loss_evidence": loss, "observation": record,
                                    "evidence": [{"file": name, "line": number, "chain": record["chain"]}]},
                                   timestamp_ns(record.get("timestamp")))
                elif record.get("type") in ("kfilter_decision", "etw_tcp", "network_flow_close", "process_exit"):
                    process = self.processes.lookup(record.get("process_id"), timestamp_ns(record.get("timestamp")))
                    self.store.add({
                        "kind": "filter_decision" if record.get("type") == "kfilter_decision" else "socket_lifecycle",
                        "session_id": record.get("session_id"), "process": process,
                        "socket": {"inode": socket_name(record.get("text")), "cookie": record.get("value1"),
                                   "endpoints": record.get("text")},
                        "decision": parse_detail(record.get("detail")) if record.get("type") == "kfilter_decision" else None,
                        "observation": record,
                        "causal_note": "The record itself is evidence; temporal proximity alone does not establish causality.",
                        "evidence": [{"file": name, "line": number, "chain": record["chain"]}],
                    }, timestamp_ns(record.get("timestamp")))
        for (session, operation_id), operation in operations.items():
            self.add_msmon_operation(session, operation_id, operation, source)
        self.add_msmon_streams(operations, source, stream_breaks)
        for name, content in sorted(captures):
            self.add_capture_data(content, f"{source}!{name}")

    def add_msmon_operation(self, session, operation_id, operation, source):
        records = operation["records"]
        first = min(records, key=lambda record: record.get("record_index", 0))
        time_ns = timestamp_ns(first.get("timestamp"))
        process = self.processes.lookup(first.get("process_id"), time_ns)
        detail = parse_detail(first.get("detail"))
        local, remote = endpoint_pair(detail.get("endpoints"))
        direction = "client_to_server" if "payload_input" in first.get("flags_names", []) or first.get("flags", 0) & 0x200 else "server_to_client"
        socket = {
            "inode": socket_name(first.get("text")) or socket_name(first.get("detail")),
            "protocol": detail.get("proto") or "tcp",
            "local": local,
            "remote": remote,
            "source": local,
            "destination": remote,
        }
        payload = first.get("payload") or {
            "kind": "network_data", "total_bytes": abs(int(first.get("value0") or 0)),
        }
        total = int(payload["total_bytes"])
        chunks = operation["chunks"]
        complete = total == 0
        if chunks:
            cursor = 0
            complete = True
            for offset in sorted(chunks):
                if offset != cursor:
                    complete = False
                    break
                cursor += len(chunks[offset])
            complete = complete and cursor == total
        raw = b"".join(chunks[offset] for offset in sorted(chunks)) if complete else None
        record = {
            "kind": "socket_operation",
            "session_id": session,
            "operation_id": operation_id,
            "process": process,
            "game_build": process.get("game_build"),
            "socket": socket,
            "direction": direction,
            "raw": raw_bytes(raw, "socket_call_payload", complete, total) if raw is not None else {
                "present": True, "scope": "socket_call_chunks", "complete": False, "total_bytes": total,
                "chunks": [{"offset": offset, **raw_bytes(chunk, "payload_chunk")} for offset, chunk in sorted(chunks.items())],
            },
            "payload_kind": payload["kind"],
            "syscall": {key: first.get(key) for key in ("type", "detail", "value0", "value1", "status", "thread_id",
                                                        "modules", "stack_frames", "stack_unresolved")},
            "evidence": [{"file": str(source), "record_index": item.get("record_index"), "chain": item.get("chain")}
                         for item in records],
            "complete": complete,
        }
        self.store.add(record, time_ns)
        first["_ledger_complete"] = complete
        first["_ledger_raw"] = raw
        first["_ledger_socket"] = socket
        first["_ledger_direction"] = direction
        first["_ledger_process"] = process

    def add_msmon_streams(self, operations, source, stream_breaks):
        groups = defaultdict(list)
        unlocated_gap = any(value is None for value in stream_breaks)
        for (session, _), operation in operations.items():
            first = min(operation["records"], key=lambda record: record.get("record_index", 0))
            payload_kind = first.get("payload", {}).get("kind", "network_data")
            socket = first["_ledger_socket"]
            key = (session, first.get("process_id"), socket.get("inode"), str(socket.get("remote")),
                   first["_ledger_direction"], payload_kind)
            groups[key].append(operation)
        for key, grouped in groups.items():
            grouped.sort(key=lambda operation: timestamp_ns(min(
                operation["records"], key=lambda record: record.get("record_index", 0)
            ).get("timestamp")) or 0)
            runs = []
            current = []
            for operation in grouped:
                first = min(operation["records"], key=lambda record: record.get("record_index", 0))
                current_time = timestamp_ns(first.get("timestamp"))
                previous_time = None
                if current:
                    previous = min(current[-1]["records"], key=lambda record: record.get("record_index", 0))
                    previous_time = timestamp_ns(previous.get("timestamp"))
                crossed_gap = previous_time is not None and current_time is not None and any(
                    value is not None and previous_time < value <= current_time for value in stream_breaks
                )
                if current and (unlocated_gap or crossed_gap):
                    runs.append(current)
                    current = []
                if first["_ledger_complete"] and first["_ledger_raw"]:
                    current.append(operation)
                    continue
                if current:
                    runs.append(current)
                    current = []
                if not first["_ledger_complete"]:
                    self.store.complete = False
                    self.store.add({"kind": "coverage", "coverage": "socket_stream_break",
                                    "reason": "incomplete_payload_operation", "process": first["_ledger_process"],
                                    "socket": first["_ledger_socket"], "operation_id": first.get("operation_id"),
                                    "evidence": [{"file": str(source)}]}, timestamp_ns(first.get("timestamp")))
            if current:
                runs.append(current)
            for run_operations in runs:
                ranges = []
                joined = bytearray()
                for operation in run_operations:
                    first = min(operation["records"], key=lambda record: record.get("record_index", 0))
                    data = first["_ledger_raw"]
                    start = len(joined)
                    joined += data
                    ranges.append((start, len(joined), first))
                first = ranges[0][2]
                last = ranges[-1][2]
                payload_kind = first.get("payload", {}).get("kind", "network_data")
                if payload_kind == "tls_plaintext":
                    result = decode_http_run(joined)
                else:
                    result = decode_maple_run(joined, first["_ledger_direction"])
                    if not result["recognized"]:
                        result = decode_tls_run(joined)
                    if not result["recognized"]:
                        result = decode_http_run(joined)
                if not result["recognized"]:
                    result = {"frames": [{
                        "offset": 0, "raw": bytes(joined), "plaintext": bytes(joined),
                        "decode": {"protocol": "tcp", "type": None, "name": None, "status": "unknown", "fields": {},
                                   "unresolved_ranges": [{"offset": 0, "length": len(joined)}]},
                    }], "unparsed": b"", "problem": None, "cipher_evidence": None}
                frames = list(result["frames"])
                if result["unparsed"]:
                    offset = result.get("problem", {}).get("offset", len(joined) - len(result["unparsed"]))
                    frames.append({"offset": offset, "raw": result["unparsed"], "plaintext": result["unparsed"],
                                   "decode": {"protocol": "tcp", "type": None, "name": None, "status": "incomplete",
                                              "fields": {}, "unresolved_ranges": [{"offset": 0, "length": len(result["unparsed"])}]}})
                for frame in frames:
                    start = frame["offset"]
                    end = start + len(frame["raw"])
                    contributors = [record for low, high, record in ranges if low < end and high > start]
                    times = [timestamp_ns(record.get("timestamp")) for record in contributors]
                    times = [value for value in times if value is not None]
                    evidence = [{"file": str(source), "record_index": record.get("record_index"),
                                 "operation_id": record.get("operation_id"), "chain": record.get("chain")}
                                for record in contributors]
                    self.add_message(
                        frame["decode"], frame["raw"], frame.get("plaintext"), min(times) if times else None,
                        first["_ledger_process"], first["_ledger_socket"], first["_ledger_direction"], evidence,
                        "reconstructed_socket_message", session=key[0],
                        transport={"source": "msmon_socket_operations", "payload_kind": payload_kind,
                                   "operation_ids": [record.get("operation_id") for record in contributors],
                                   "cipher_evidence": result.get("cipher_evidence")},
                        time_end_ns=max(times) if times else None,
                    )

    def add_ngs(self, path):
        self.input(path, "mitm_jsonl")
        with Path(path).open(encoding="utf-8") as stream:
            records = [json.loads(line) for line in stream if line.strip()]
        request_ids = {event.get("flow_id") for event in records if event.get("kind") == "request" and event.get("flow_id")}
        for event in records:
            kind = event.get("kind")
            request = event.get("request", event)
            request_present = kind == "request" or (
                kind in ("response", "error") and request.get("body_base64") is not None
                and event.get("flow_id") not in request_ids
            )
            if request_present:
                body = base64.b64decode(request.get("body_base64", ""), validate=True)
                host = request.get("host")
                headers = request.get("headers", {})
                target = request.get("path")
                protocol = request.get("scheme", "https")
                decoded = {
                    "protocol": protocol,
                    "type": f"{request.get('method', 'UNKNOWN')} {target}",
                    "name": "ngs_request" if host and host.endswith(".ngs.nexon.com") else "http_request",
                    "status": "request_ciphertext" if host and host.startswith("x-") and host.endswith(".ngs.nexon.com") else "plaintext",
                    "fields": {"method": request.get("method"), "target": target, "host": host, "headers": headers},
                    "unresolved_ranges": [{"offset": 0, "length": len(body), "reason": "NGS request cipher unresolved"}]
                    if host and host.startswith("x-") and host.endswith(".ngs.nexon.com") and body else [],
                    "raw_scope_note": "Exact application body; original TLS records and HTTP framing require packet evidence.",
                }
                socket = {"remote": {"host": host, "port": 443}, "protocol": "tcp",
                          "inode": event.get("socket_inode"), "cookie": event.get("socket_cookie")}
                process = event.get("process") or {"pid": None, "name": None, "evidence": "mitm_process_unavailable"}
                message_id = self.add_message(decoded, body, body, timestamp_ns(event.get("timestamp")), process, socket,
                                 "client_to_server", [{"file": str(path), "kind": kind}], "http_request_body",
                                 session=event.get("session_id"), transport={"proxy": "mitmproxy", "flow_id": event.get("flow_id")},
                                 trace=None, observed_decision=event.get("decision"))
                if event.get("decision"):
                    self.store.add({"kind": "filter_decision", "decision": event["decision"], "message_id": message_id,
                                    "flow_id": event.get("flow_id"), "session_id": event.get("session_id"),
                                    "process": process, "socket": socket, "request": request,
                                    "evidence": [{"file": str(path)}]}, timestamp_ns(event.get("timestamp")))
            if kind == "error":
                self.store.add({"kind": "proxy_error", "session_id": event.get("session_id"),
                                "process": event.get("process"), "socket": {"inode": event.get("socket_inode")},
                                "error": event.get("error"), "flow_id": event.get("flow_id"),
                                "decision": event.get("decision"), "evidence": [{"file": str(path)}]},
                               timestamp_ns(event.get("timestamp")))
            if kind != "response" or "response" not in event:
                continue
            response = event["response"]
            body = base64.b64decode(response.get("body_base64", ""), validate=True)
            host = request.get("host")
            decoded_body = None
            error = event.get("decode_error")
            if host and host.startswith("x-") and host.endswith(".ngs.nexon.com") and body and not event.get("blocked"):
                try:
                    decoded_body = ngs_cipher.decrypt_response(body, want="json")
                    error = None
                except (ValueError, TypeError, json.JSONDecodeError, zlib.error) as decode_error:
                    error = str(decode_error)
            fields = decoded_body if isinstance(decoded_body, dict) else {
                "status": response.get("status"), "headers": response.get("headers", {}),
            }
            decoded = {
                "protocol": request.get("scheme", "https"),
                "type": f"{request.get('method', 'UNKNOWN')} {request.get('path')} response",
                "name": "ngs_response" if host and host.endswith(".ngs.nexon.com") else "http_response",
                "status": "decoded" if decoded_body is not None else "undecoded",
                "fields": fields,
                "decode_error": error,
                "unresolved_ranges": [] if decoded_body is not None else [{"offset": 0, "length": len(body)}],
            }
            socket = {"remote": {"host": host, "port": 443}, "protocol": "tcp",
                      "inode": event.get("socket_inode"), "cookie": event.get("socket_cookie")}
            process = event.get("process") or {"pid": None, "name": None, "evidence": "mitm_process_unavailable"}
            self.add_message(decoded, body, json.dumps(decoded_body, separators=(",", ":")).encode()
                             if decoded_body is not None else None,
                             timestamp_ns(event.get("timestamp")), process, socket, "server_to_client",
                             [{"file": str(path), "kind": "response"}], "http_response_body",
                             session=event.get("session_id"), transport={"proxy": "mitmproxy", "flow_id": event.get("flow_id"), "blocked": event.get("blocked")})

    def finish(self):
        for stream in reassemble_tcp(self.pending_packets):
            self.add_stream(stream, "combined_capture")
        self.store.add({
            "kind": "ledger_session",
            "ledger_session_id": self.store.session_id,
            "inputs": self.inputs,
            "policy": {"sha256": self.policy.sha256, "source": self.policy.source, "document": self.policy.document},
            "coverage_note": "No capture source proves all traffic; read coverage records and summary before drawing conclusions.",
        })
        return self.store.finish()


def verify_ledger(path):
    path = Path(path)
    if path.is_dir():
        path = path / "traffic.jsonl"
    previous = ZERO_CHAIN
    count = 0
    with path.open(encoding="utf-8") as stream:
        for number, line in enumerate(stream, 1):
            line = line.rstrip("\r\n")
            if not line:
                continue
            record, previous = verify_chain_line(line, previous, f"{path}:{number}")
            count += 1
            if record.get("record_index") != count:
                raise ValueError(f"{path}:{number}: non-consecutive record index")
    return {"records": count, "final_chain": previous}


def show_record(path, identifier, explain=False):
    path = Path(path)
    if path.is_dir():
        path = path / "traffic.jsonl"
    records = [json.loads(line) for line in path.open(encoding="utf-8") if line.strip()]
    target = next((record for record in records if record.get("record_id") == identifier or
                   str(record.get("record_index")) == str(identifier)), None)
    if target is None:
        raise ValueError(f"No ledger record {identifier}.")
    result = {"record": target}
    if explain:
        process = (target.get("process") or {}).get("pid")
        socket = (target.get("socket") or {}).get("inode")
        related = []
        for record in records:
            if record is target:
                continue
            same_process = process is not None and (record.get("process") or {}).get("pid") == process
            same_socket = socket is not None and (record.get("socket") or {}).get("inode") == socket
            if record.get("kind") in ("socket_lifecycle", "trace_event", "coverage") and (same_process or same_socket):
                related.append(record)
        result["related_direct_observations"] = related
        result["causal_conclusion"] = "not_established"
        result["causal_note"] = (
            "Constructor, register, stack, serialization, memory, socket, and filter records are shown as observed. "
            "No crash cause is inferred from timing alone; an explicit linked error or independent experiment is still required."
        )
    return result


def _pcapng_fixture(path, frames):
    def option(code, data):
        return struct.pack("<HH", code, len(data)) + data + bytes((-len(data)) % 4)

    def block(kind, body):
        return struct.pack("<II", kind, len(body) + 12) + body + struct.pack("<I", len(body) + 12)

    data = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    data += block(1, struct.pack("<HHI", 101, 0, 65536) + option(9, b"\x09") + struct.pack("<I", 0))
    for index, (sequence, payload) in enumerate(frames):
        source = ipaddress_bytes("10.0.0.1")
        destination = ipaddress_bytes("10.0.0.2")
        tcp = struct.pack(">HHIIBBHHH", 12345, 8484, sequence, 0, 5 << 4, 0x18, 65535, 0, 0) + payload
        ip = struct.pack(">BBHHHBBH", 0x45, 0, 20 + len(tcp), index, 0x4000, 64, 6, 0) + source + destination + tcp
        comment = f"pid=100;process=MapleStory.exe;socket=socket:[55];cookie=77".encode()
        body = struct.pack("<IIIII", 0, 0, index + 1, len(ip), len(ip)) + ip + bytes((-len(ip)) % 4)
        body += option(2, struct.pack("<I", 2)) + option(1, comment) + struct.pack("<I", 0)
        data += block(6, body)
    path.write_bytes(data)


def ipaddress_bytes(text):
    return bytes(int(part) for part in text.split("."))


def self_test():
    from traffic_protocols import load_wire
    import tempfile

    wire = load_wire()
    pickup = bytearray(36)
    struct.pack_into("<H", pickup, 0, 0x32B)
    struct.pack_into("<I", pickup, 15, 0x143FF)
    frames = []
    current = bytes.fromhex("02000000")
    for plain in (bytes(pickup), b"\x70\x00\x05"):
        wire_body = bytearray(plain)
        plaintext_opcode = struct.unpack_from("<H", wire_body)[0]
        struct.pack_into("<H", wire_body, 0, PLAIN_TO_WIRE.get(plaintext_opcode, plaintext_opcode))
        word0 = wire._hs(current) ^ wire.SEND_MASK
        encrypted = wire.decrypt_body(current, bytes(wire_body), 0)
        frames.append(struct.pack("<HH", word0, word0 ^ len(wire_body)) + encrypted)
        current = wire.tc.getNewIv(current, wire.TABLE)
    joined = b"".join(frames)
    cut = len(frames[0]) - 3
    with tempfile.TemporaryDirectory() as temporary:
        temporary = Path(temporary)
        capture = temporary / "game.pcapng"
        _pcapng_fixture(capture, [
            (1000, joined[:5]),
            (1005, joined[5:cut]),
            (1000, joined[:8]),
            (1000 + cut, joined[cut:]),
        ])
        trace = temporary / "trace.jsonl"
        session = "test-session"
        constructor = {
            "kind": "constructor", "session_id": session, "event_index": 1, "wall_time_ns": 1_000_000_000,
            "pid": 100, "tid": 100, "construction_id": "test-session:1", "packet_va": "0x1000",
            "opcode": "0x32b", "registers": {"rdx": "0x32b"}, "return_stack": [],
        }
        send = {
            "kind": "send", "direction": "client_to_server", "session_id": session, "event_index": 3,
            "wall_time_ns": 1_000_000_000, "pid": 100, "tid": 100, "construction_id": "test-session:1",
            "opcode": "0x32b", "body": pickup.hex(), "packet_va": "0x1000", "registers": {"rcx": "0x1000"},
        }
        field = {
            "kind": "field_change", "session_id": session, "event_index": 2, "wall_time_ns": 1_000_000_000,
            "pid": 100, "tid": 100, "construction_id": "test-session:1", "opcode": "0x32b",
            "previous_length": 15, "length": 19, "body": pickup[:19].hex(), "registers": {"rax": "0x143ff"},
        }
        with trace.open("w") as stream:
            for record in (constructor, field, send):
                stream.write(json.dumps(record) + "\n")
        output = temporary / "ledger"
        builder = LedgerBuilder(output)
        builder.add_trace(trace)
        builder.add_capture(capture)
        summary = builder.finish()
        verified = verify_ledger(output)
        assert verified["records"] == summary["records"]
        records = [json.loads(line) for line in (output / "traffic.jsonl").open()]
        messages = [record for record in records if record.get("kind") == "message"]
        wire_pickup = next(record for record in messages if record.get("raw", {}).get("scope") == "reconstructed_tcp_message"
                           and record.get("decode", {}).get("type") == "0x32b")
        assert base64.b64decode(wire_pickup["raw"]["data"]) == frames[0]
        assert wire_pickup["decode"]["fields"]["drop_object_id"] == 0x143FF
        assert wire_pickup["decode"]["type"] == "0x32b"
        assert wire_pickup["decode"]["wire_alias"] == "0xfbd0"
        assert wire_pickup["trace"]["chain"]["constructor"]["construction_id"] == "test-session:1"
        assert wire_pickup["trace"]["correlation"]["method"] == "same_length_and_plaintext_after_wire_opcode"
        assert not any(record.get("kind") == "coverage" and record.get("coverage") == "missing_tcp_bytes" for record in records)
        assert summary["counts"]["message"] == 3
        shown = show_record(output, wire_pickup["record_id"], explain=True)
        assert shown["causal_conclusion"] == "not_established"

        part_one = temporary / "part1.pcapng"
        part_two = temporary / "part2.pcapng"
        _pcapng_fixture(part_one, [(1000, joined[:cut])])
        _pcapng_fixture(part_two, [(1000 + cut, joined[cut:])])
        split_output = temporary / "split-ledger"
        split_builder = LedgerBuilder(split_output)
        split_builder.add_capture(part_one)
        split_builder.add_capture(part_two)
        split_summary = split_builder.finish()
        assert verify_ledger(split_output)["records"] == split_summary["records"]
        split_records = [json.loads(line) for line in (split_output / "traffic.jsonl").open()]
        split_pickup = next(record for record in split_records if record.get("kind") == "message"
                            and record.get("decode", {}).get("type") == "0x32b")
        assert base64.b64decode(split_pickup["raw"]["data"]) == frames[0]
        assert split_pickup["decode"]["fields"]["drop_object_id"] == 0x143FF
        split_files = {item["file"] for item in split_pickup["evidence"]}
        assert str(part_one) in split_files and str(part_two) in split_files
        assert split_summary["counts"]["message"] == 2
        assert not any(record.get("coverage") == "missing_tcp_bytes" for record in split_records)

        bundle = temporary / "rotated"
        bundle.mkdir()
        _pcapng_fixture(bundle / "events.pcapng.1", [(1000, joined[:cut])])
        _pcapng_fixture(bundle / "events.pcapng.2", [(1000 + cut, joined[cut:])])
        rotated_output = temporary / "rotated-ledger"
        rotated_builder = LedgerBuilder(rotated_output)
        rotated_builder.add_msmon(bundle)
        rotated_summary = rotated_builder.finish()
        assert verify_ledger(rotated_output)["records"] == rotated_summary["records"]
        rotated_records = [json.loads(line) for line in (rotated_output / "traffic.jsonl").open()]
        rotated_pickup = next(record for record in rotated_records if record.get("kind") == "message"
                              and record.get("decode", {}).get("type") == "0x32b")
        assert base64.b64decode(rotated_pickup["raw"]["data"]) == frames[0]
        assert rotated_pickup["decode"]["fields"]["drop_object_id"] == 0x143FF
        rotated_files = {item["file"] for item in rotated_pickup["evidence"]}
        assert any(name.endswith("events.pcapng.1") for name in rotated_files)
        assert any(name.endswith("events.pcapng.2") for name in rotated_files)
        assert rotated_summary["counts"]["message"] == 2

        tls_first = b"\x17\x03\x03" + struct.pack(">H", 9000) + b"a" * 9000
        tls_second = b"\x16\x03\x03\x00\x00"
        socket_parts = (tls_first[:9000], tls_first[9000:] + tls_second)
        events = []
        chain = ZERO_CHAIN
        for operation_id, operation_data in enumerate(socket_parts, 1):
            for offset in range(0, len(operation_data), 8192):
                chunk = operation_data[offset:offset + 8192]
                record = {
                    "session_id": 1, "record_index": len(events) + 1, "type": "file_write",
                    "timestamp": f"2026-01-01T00:00:00.{len(events):06d}Z", "process_id": 100,
                    "process_path": "MapleStory.exe", "flags": 0x200, "flags_names": ["payload_input"],
                    "operation_id": operation_id, "value0": len(operation_data), "text": "socket:[55]",
                    "detail": "endpoints=10.0.0.1:12345 -> 10.0.0.2:8484",
                    "payload": {"kind": "network_data", "operation_id": operation_id, "total_bytes": len(operation_data),
                                "byte_offset": offset, "chunk_index": offset // 8192, "chunk_count": (len(operation_data) + 8191) // 8192,
                                "final_chunk": offset + len(chunk) == len(operation_data),
                                "data": base64.b64encode(chunk).decode()},
                }
                original = json.dumps(record, separators=(",", ":"))
                chain = hashlib.sha256((chain + original).encode()).hexdigest()
                events.append(original[:-1] + ',"chain":"' + chain + '"}')
        record = {
            "session_id": 1, "record_index": len(events) + 1, "type": "file_write",
            "timestamp": "2026-01-01T00:00:01.000000Z", "process_id": 100, "flags": 0x280,
            "payload_unavailable": True, "operation_id": 3, "value0": 5, "text": "socket:[55]",
            "detail": "payload_ring_full;endpoints=10.0.0.1:12345 -> 10.0.0.2:8484",
        }
        original = json.dumps(record, separators=(",", ":"))
        chain = hashlib.sha256((chain + original).encode()).hexdigest()
        events.append(original[:-1] + ',"chain":"' + chain + '"}')
        msmon = temporary / "events.jsonl"
        msmon.write_text("\n".join(events) + "\n")
        second_output = temporary / "msmon-ledger"
        second = LedgerBuilder(second_output)
        second.add_msmon(msmon)
        second_summary = second.finish()
        second_records = [json.loads(line) for line in (second_output / "traffic.jsonl").open()]
        tls_messages = [record for record in second_records if record.get("decode", {}).get("protocol") == "tls"]
        assert len(tls_messages) == 2 and base64.b64decode(tls_messages[0]["raw"]["data"]) == tls_first
        assert second_summary["counts"]["socket_operation"] == 3
        assert any(record.get("coverage") == "socket_stream_break" for record in second_records)

        gapped = [json.loads(line) for line in events]
        for record in gapped:
            record.pop("chain", None)
        gapped.insert(2, {"type": "observer_sequence_gap", "timestamp": "2026-01-01T00:00:00.000001500Z",
                          "session_id": 1, "missing_events": 1})
        gap_chain = ZERO_CHAIN
        gap_lines = []
        for index, record in enumerate(gapped, 1):
            record["record_index"] = index
            original = json.dumps(record, separators=(",", ":"))
            gap_chain = hashlib.sha256((gap_chain + original).encode()).hexdigest()
            gap_lines.append(original[:-1] + ',"chain":"' + gap_chain + '"}')
        gap_input = temporary / "events-gap.jsonl"
        gap_input.write_text("\n".join(gap_lines) + "\n")
        gap_output = temporary / "gap-ledger"
        gap_builder = LedgerBuilder(gap_output)
        gap_builder.add_msmon(gap_input)
        gap_builder.finish()
        gap_records = [json.loads(line) for line in (gap_output / "traffic.jsonl").open()]
        assert not any(record.get("decode", {}).get("protocol") == "tls" for record in gap_records)
        assert any(record.get("coverage") == "msmon_sequence_gap" for record in gap_records)
    print("PASS: packets and msmon chunks -> whole messages -> fields -> constructor chain -> coverage -> chained ledger.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build", help="Build a private traffic.jsonl and summary.json.")
    build.add_argument("output", type=Path)
    build.add_argument("--pcap", action="append", default=[], type=Path, help="pcap/pcapng; repeat for rotated parts")
    build.add_argument("--trace", action="append", default=[], type=Path, help="client-control packet JSONL")
    build.add_argument("--msmon", action="append", default=[], type=Path, help="msmon bundle, zip, or events.jsonl")
    build.add_argument("--ngs", action="append", default=[], type=Path, help="ngs-proxy/ngs-mitm JSONL")
    build.add_argument("--policy", type=Path, help="Evaluate this JSON policy offline; never changes captured traffic")
    build.add_argument("--client-ip", action="append", default=[], help="Direction hint for captures without pcapng flags")
    for command in (commands.add_parser("verify", help="Verify a ledger hash chain"),):
        command.add_argument("ledger", type=Path)
    show = commands.add_parser("show", help="Print one complete message/evidence chain")
    show.add_argument("ledger", type=Path)
    show.add_argument("record", help="record_id or record_index")
    show.add_argument("--explain", action="store_true", help="Include direct related observations without a timing-only causal claim")
    commands.add_parser("self-test", help="Run synthetic end-to-end checks")
    args = parser.parse_args(argv)
    if args.command == "self-test":
        self_test()
        return 0
    if args.command == "verify":
        print(json.dumps(verify_ledger(args.ledger), indent=2))
        return 0
    if args.command == "show":
        print(json.dumps(show_record(args.ledger, args.record, args.explain), indent=2))
        return 0
    if not any((args.pcap, args.trace, args.msmon, args.ngs)):
        parser.error("build needs at least one --pcap, --trace, --msmon, or --ngs input")
    builder = LedgerBuilder(args.output, Policy.load(args.policy), args.client_ip)
    for source in args.trace:
        builder.add_trace(source)
    for source in args.msmon:
        builder.add_msmon(source)
    for source in args.pcap:
        builder.add_capture(source)
    for source in args.ngs:
        builder.add_ngs(source)
    summary = builder.finish()
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, struct.error, json.JSONDecodeError) as error:
        print(f"Traffic ledger failed: {error}", file=sys.stderr)
        raise SystemExit(1)
