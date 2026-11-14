#!/usr/bin/env python3
"""Verify an msmon-compatible events.jsonl chain and payload chunks.

Copied from monitor-filter's ``monitor/tools/verify_log.py`` so client-control
can verify the event log itself. Source revision is recorded in PROVENANCE.md.
"""

import argparse
import base64
import hashlib
import json
import struct
from pathlib import Path

CHUNK_BYTES = 8192


def validate_decoded(record, raw):
    if "decoded_value" not in record:
        return
    payload = record["payload"]
    decoded = record["decoded_value"]
    if payload["chunk_count"] != 1:
        raise ValueError("friendly decoding is only valid for a complete single chunk")
    if payload["kind"] == "registry_value":
        value_type = record.get("value1")
        if value_type in {1, 2, 6}:
            expected = raw.decode("utf-16-le").rstrip("\0")
        elif value_type == 7:
            expected = [part for part in raw.decode("utf-16-le").split("\0") if part]
        elif value_type == 4 and len(raw) == 4:
            expected = struct.unpack("<I", raw)[0]
        elif value_type == 11 and len(raw) == 8:
            expected = struct.unpack("<Q", raw)[0]
        else:
            return
        if decoded != expected:
            raise ValueError("decoded registry value does not match raw bytes")
    elif payload["kind"] == "volume_information" and isinstance(decoded, dict):
        serial = struct.unpack_from("<I", raw, 8)[0]
        label_length = struct.unpack_from("<I", raw, 12)[0]
        label = raw[18:18 + label_length].decode("utf-16-le")
        if decoded.get("volume_serial_number") != serial or decoded.get("volume_serial_hex") != f"{serial:08X}":
            raise ValueError("decoded volume serial does not match raw bytes")
        if decoded.get("volume_label") != label:
            raise ValueError("decoded volume label does not match raw bytes")


def verify(paths):
    previous = "0" * 64
    lines = 0
    events = 0
    gaps = 0
    payload_bytes = 0
    last_sequences = {}
    payloads = {}
    for path in paths:
        with Path(path).open("r", encoding="utf-8") as stream:
            for number, line in enumerate(stream, 1):
                raw_line = line.rstrip("\r\n")
                record = json.loads(raw_line)
                chain = record.get("chain")
                if not isinstance(chain, str) or len(chain) != 64:
                    raise ValueError(f"{path}:{number}: missing SHA-256 chain")
                marker = f',"chain":"{chain}"}}'
                if not raw_line.endswith(marker):
                    raise ValueError(f"{path}:{number}: chain is not the final property")
                original = raw_line[:-len(marker)] + "}"
                expected = hashlib.sha256((previous + original).encode("utf-8")).hexdigest()
                if chain != expected:
                    raise ValueError(f"{path}:{number}: hash-chain mismatch")
                if record.get("protocol", 1) not in {1, 2, 3, 4}:
                    raise ValueError(f"{path}:{number}: unsupported protocol")
                if "record_index" in record and record["record_index"] != lines + 1:
                    raise ValueError(f"{path}:{number}: non-consecutive record index")
                if "outside_client" in record and not isinstance(record["outside_client"], bool):
                    raise ValueError(f"{path}:{number}: outside_client must be Boolean")
                previous = chain
                lines += 1

                if "payload" in record:
                    payload = record["payload"]
                    try:
                        operation = int(payload["operation_id"])
                        total = int(payload["total_bytes"])
                        offset = int(payload["byte_offset"])
                        index = int(payload["chunk_index"])
                        count = int(payload["chunk_count"])
                        data = base64.b64decode(payload["data"], validate=True)
                    except (KeyError, ValueError, TypeError) as exc:
                        raise ValueError(f"{path}:{number}: invalid payload encoding") from exc
                    if operation == 0 or operation != record.get("operation_id"):
                        raise ValueError(f"{path}:{number}: mismatched payload operation ID")
                    if count == 0 or index >= count or offset != index * CHUNK_BYTES:
                        raise ValueError(f"{path}:{number}: invalid payload chunk position")
                    expected_chunks = 1 if total == 0 else (total + CHUNK_BYTES - 1) // CHUNK_BYTES
                    if count != expected_chunks or len(data) > CHUNK_BYTES or offset + len(data) > total:
                        raise ValueError(f"{path}:{number}: inconsistent payload size")
                    if index + 1 < count and len(data) != CHUNK_BYTES:
                        raise ValueError(f"{path}:{number}: short non-final payload chunk")
                    if payload["final_chunk"] != (index + 1 == count):
                        raise ValueError(f"{path}:{number}: inconsistent final-chunk marker")
                    if payload["final_chunk"] and offset + len(data) != total:
                        raise ValueError(f"{path}:{number}: final chunk does not complete the payload")
                    if payload["kind"] not in {"registry_value", "volume_information", "network_data", "ipc_data",
                                               "tls_plaintext"}:
                        raise ValueError(f"{path}:{number}: unsupported payload kind")
                    group = payloads.setdefault(operation, {"count": count, "chunks": {}})
                    if group["count"] != count:
                        raise ValueError(f"{path}:{number}: payload chunk count changed")
                    if index in group["chunks"]:
                        raise ValueError(f"{path}:{number}: duplicate payload chunk")
                    if index != len(group["chunks"]):
                        raise ValueError(f"{path}:{number}: missing or out-of-order payload chunk")
                    group["chunks"][index] = data
                    payload_bytes += len(data)
                    try:
                        validate_decoded(record, data)
                    except (UnicodeDecodeError, struct.error, ValueError) as exc:
                        raise ValueError(f"{path}:{number}: {exc}") from exc

                if record.get("type") == "observer_sequence_gap":
                    missing = int(record["missing_events"])
                    if missing <= 0:
                        raise ValueError(f"{path}:{number}: invalid sequence gap")
                    gaps += missing
                elif "sequence" in record:
                    sequence = int(record["sequence"])
                    if sequence < 0:
                        raise ValueError(f"{path}:{number}: negative event sequence")
                    if sequence == 0:
                        continue
                    source = record.get("source", "driver")
                    last_sequence = last_sequences.get(source)
                    if last_sequence is not None and sequence <= last_sequence:
                        raise ValueError(f"{path}:{number}: non-increasing {source} sequence")
                    last_sequences[source] = sequence
                    events += 1
    complete = sum(len(group["chunks"]) == group["count"] for group in payloads.values())
    return {
        "files": len(paths),
        "lines": lines,
        "events": events,
        "missing_events": gaps,
        "payload_operations": len(payloads),
        "complete_payload_operations": complete,
        "incomplete_payload_operations": len(payloads) - complete,
        "payload_bytes": payload_bytes,
        "final_chain": previous,
    }


def main():
    parser = argparse.ArgumentParser(description="Validate an msmon-compatible JSONL chain and payloads.")
    parser.add_argument("logs", nargs="+", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.logs), indent=2))


if __name__ == "__main__":
    main()
