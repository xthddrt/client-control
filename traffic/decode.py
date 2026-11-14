"""Field decoders. Every field carries its own confidence and evidence tag.

Offsets are relative to the application body and include the two-byte opcode,
matching the convention used in docs/guides/PACKETS.md (for example 0x32b+0x0f).
A layout with no verified offsets stays unparsed; bytes are never assigned
semantic names by position alone.
"""

from __future__ import annotations

import importlib.util
import json
import struct
from pathlib import Path

from .util import subtract_ranges

FOUNDATIONS = Path(__file__).resolve().parent.parent / "foundations"


def _load(name, filename):
    path = FOUNDATIONS / filename
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ngs_cipher = _load("traffic_ngs_cipher", "ngs_cipher.py")

# Wire aliases observed in one earlier session (docs/guides/PACKETS.md:99).
# They are evidence for that session, not universal opcode values.
WIRE_ALIASES = {
    0x70: 0x70,
    0xDA82: 0xDB,
    0xF6C7: 0xE1,
    0x8E7C: 0xE7,
    0xD088: 0x13F,
    0xAA27: 0x1A7,
    0xD5FD: 0x1EF,
    0xF70D: 0x2FE,
    0xFBD0: 0x32B,
    0xA817: 0x407,
}
PLAIN_TO_WIRE = {plain: wire for wire, plain in WIRE_ALIASES.items()}


def alias_to_opcode(alias, body_length=None):
    """Map a decrypted wire opcode alias to the plaintext opcode when evidenced."""
    if alias == 0xD5FD and body_length is not None and body_length != 14:
        return None
    return WIRE_ALIASES.get(alias)


def _field(name, offset, size, kind, confidence, evidence, note=None):
    value = {
        "name": name,
        "offset": offset,
        "size": size,
        "kind": kind,
        "confidence": confidence,
        "evidence": list(evidence),
    }
    if note:
        value["note"] = note
    return value


# Documentation-derived layouts. A field name starting with unknown_ is a
# placeholder for bytes whose meaning is not established; it is still reported
# with its exact offset and value so a later rule can match it.
GAME_OPCODES = {
    0xE1: {
        "name": "melee_attack",
        "confidence": "confirmed",
        "evidence": ["docs/guides/PACKETS.md:68"],
        "variants": [130, 232, 240],
        "fields": [
            _field("opcode", 0, 2, "u16", "confirmed", ["docs/guides/PACKETS.md:68"]),
            _field("target_identifier", 0x20, 4, "u32", "supported",
                   ["docs/guides/PACKETS.md:68"],
                   "Meaning as a mob identifier is not proven."),
            _field("critical", 0x87, 1, "u8", "supported", ["docs/guides/PACKETS.md:68"]),
            _field("damage", 0x88, 4, "u32", "supported", ["docs/guides/PACKETS.md:68"],
                   "Width inferred from the serializer path; confirm against a captured variant."),
        ],
    },
    0xDB: {
        "name": "movement_sync",
        "confidence": "confirmed",
        "evidence": ["docs/guides/PACKETS.md:69"],
        "fields": [
            _field("opcode", 0, 2, "u16", "confirmed", ["docs/guides/PACKETS.md:69"]),
            _field("header_u8", 2, 1, "u8", "supported", ["docs/guides/PACKETS.md:69"]),
            _field("header_u32_a", 3, 4, "u32", "supported", ["docs/guides/PACKETS.md:69"]),
            _field("header_u32_b", 7, 4, "u32", "supported", ["docs/guides/PACKETS.md:69"]),
            _field("header_u8_b", 11, 1, "u8", "supported", ["docs/guides/PACKETS.md:69"]),
        ],
    },
    0x2FE: {
        "name": "movement_state",
        "confidence": "confirmed",
        "evidence": ["docs/guides/PACKETS.md:70"],
        "fields": [
            _field("opcode", 0, 2, "u16", "confirmed", ["docs/guides/PACKETS.md:70"]),
            _field("source_u32", 2, 4, "u32", "supported", ["docs/guides/PACKETS.md:70"],
                   "Read from r12+0x3a0 in the constructor path."),
            _field("source_u16", 6, 2, "u16", "supported", ["docs/guides/PACKETS.md:70"]),
            _field("flags", 8, 1, "u8", "supported", ["docs/guides/PACKETS.md:70"]),
        ],
    },
    0xE7: {
        "name": "game_state_report",
        "confidence": "unresolved",
        "evidence": ["docs/guides/PACKETS.md:71"],
        "fields": [_field("opcode", 0, 2, "u16", "confirmed", ["docs/guides/PACKETS.md:71"])],
    },
    0x70: {
        "name": "timestamp_context",
        "confidence": "supported",
        "evidence": ["docs/guides/PACKETS.md:72"],
        "variants": [11],
        "fields": [
            _field("opcode", 0, 2, "u16", "confirmed", ["docs/guides/PACKETS.md:72"]),
            _field("subtype", 2, 1, "u8", "supported", ["docs/guides/PACKETS.md:72"]),
            _field("tick", 3, 4, "u32", "supported", ["docs/guides/PACKETS.md:72"]),
            _field("context", 7, 4, "u32", "supported", ["docs/guides/PACKETS.md:72"]),
        ],
    },
    0x13F: {
        "name": "structured_state_report",
        "confidence": "unresolved",
        "evidence": ["docs/guides/PACKETS.md:73"],
        "fields": [_field("opcode", 0, 2, "u16", "confirmed", ["docs/guides/PACKETS.md:73"])],
    },
    0x1A7: {
        "name": "batched_metric_event",
        "confidence": "unresolved",
        "evidence": ["docs/guides/PACKETS.md:74"],
        "fields": [_field("opcode", 0, 2, "u16", "confirmed", ["docs/guides/PACKETS.md:74"])],
    },
    0x1EF: {
        "name": "report_family",
        "confidence": "unresolved",
        "evidence": ["docs/guides/PACKETS.md:75"],
        "variants": [14, 149, 174, 160],
        "fields": [_field("opcode", 0, 2, "u16", "confirmed", ["docs/guides/PACKETS.md:75"])],
        "notes": ["Structurally different reports share this opcode; do not apply one global name or layout."],
    },
    0x32B: {
        "name": "pickup_request",
        "confidence": "confirmed",
        "evidence": ["docs/guides/PACKETS.md:76", "docs/guides/32B.md"],
        "variants": [36],
        "fields": [
            _field("opcode", 0, 2, "u16", "confirmed", ["docs/guides/PACKETS.md:76"]),
            _field("unknown_02", 2, 1, "u8", "unresolved", ["docs/guides/PACKETS.md:76"]),
            _field("unknown_03", 3, 4, "u32", "unresolved", ["docs/guides/PACKETS.md:76"]),
            _field("unknown_07", 7, 4, "u32", "unresolved", ["docs/guides/PACKETS.md:76"]),
            _field("unknown_0b", 0x0B, 2, "u16", "unresolved", ["docs/guides/PACKETS.md:76"]),
            _field("unknown_0d", 0x0D, 2, "u16", "unresolved", ["docs/guides/PACKETS.md:76"]),
            _field("drop_object_id", 0x0F, 4, "u32", "confirmed",
                   ["docs/guides/PACKETS.md:76", "docs/guides/PACKETS.md:224"]),
            _field("item_specific_metadata", 0x13, 4, "u32", "supported",
                   ["docs/guides/PACKETS.md:231"],
                   "Zero for meso and nonzero for items in the labelled pickup run."),
            _field("unknown_17", 0x17, 1, "u8", "unresolved", ["docs/guides/PACKETS.md:76"]),
            _field("context_18", 0x18, 4, "u32", "unresolved",
                   ["docs/guides/PACKETS.md:231"], "Repeated value 721204 in six pickups."),
            _field("context_1c", 0x1C, 4, "u32", "unresolved",
                   ["docs/guides/PACKETS.md:231"], "Repeated value 721204 in six pickups."),
            _field("unknown_20", 0x20, 4, "u32", "unresolved", ["docs/guides/PACKETS.md:231"],
                   "Not proven to be meso amount or item quantity."),
        ],
    },
    0x407: {
        "name": "unresolved_407",
        "confidence": "unresolved",
        "evidence": ["docs/guides/PACKETS.md:77"],
        "fields": [_field("opcode", 0, 2, "u16", "confirmed", ["docs/guides/PACKETS.md:77"])],
    },
    0x326: {
        "name": "request_echo_456",
        "confidence": "unresolved",
        "evidence": ["docs/guides/PACKETS.md:78"],
        "variants": [12],
        "fields": [
            _field("opcode", 0, 2, "u16", "confirmed", ["docs/guides/PACKETS.md:78"]),
            _field("context", 2, 2, "u16", "supported", ["docs/guides/PACKETS.md:78"],
                   "Observed value 0x2b6."),
            _field("arg_u8_a", 4, 1, "u8", "supported", ["docs/guides/PACKETS.md:78"]),
            _field("arg_u8_b", 5, 1, "u8", "supported", ["docs/guides/PACKETS.md:78"]),
            _field("arg_u32", 6, 4, "u32", "supported", ["docs/guides/PACKETS.md:78"]),
        ],
    },
    0x265: {
        "name": "rare_state_265",
        "confidence": "unresolved",
        "evidence": ["docs/guides/PACKETS.md:79"],
        "fields": [_field("opcode", 0, 2, "u16", "confirmed", ["docs/guides/PACKETS.md:79"])],
    },
    0x266: {
        "name": "rare_state_266",
        "confidence": "unresolved",
        "evidence": ["docs/guides/PACKETS.md:80"],
        "fields": [_field("opcode", 0, 2, "u16", "confirmed", ["docs/guides/PACKETS.md:80"])],
    },
    0x2EF: {
        "name": "periodic_status_report",
        "confidence": "unresolved",
        "evidence": ["docs/guides/PACKETS.md:81"],
        "variants": [14],
        "fields": [
            _field("opcode", 0, 2, "u16", "confirmed", ["docs/guides/PACKETS.md:81"]),
            _field("value_a", 2, 4, "u32", "supported", ["docs/guides/PACKETS.md:81"]),
            _field("value_b", 6, 4, "u32", "supported", ["docs/guides/PACKETS.md:81"]),
            _field("value_c", 10, 4, "u32", "supported", ["docs/guides/PACKETS.md:81"]),
        ],
    },
    0x2A5: {
        "name": "input_event_container",
        "confidence": "confirmed",
        "evidence": ["docs/guides/PACKETS.md:242"],
        "fields": [
            _field("opcode", 0, 2, "u16", "confirmed", ["docs/guides/PACKETS.md:250"]),
            _field("header_flag", 2, 1, "u8", "confirmed", ["docs/guides/PACKETS.md:250"]),
            _field("header_value_a", 3, 8, "u64", "confirmed", ["docs/guides/PACKETS.md:250"]),
            _field("header_value_b", 11, 8, "u64", "confirmed", ["docs/guides/PACKETS.md:250"]),
            _field("record_count", 19, 2, "u16", "confirmed", ["docs/guides/PACKETS.md:250"]),
        ],
        "notes": [
            "Record serialization sizes are not established, so only the container header is decoded.",
            "Producer purpose and record field meanings remain unresolved.",
        ],
    },
}


KNOWN_OPCODE_NAMES = {opcode: spec["name"] for opcode, spec in GAME_OPCODES.items()}


def _parse_scalar(kind, raw):
    if kind == "u8":
        return raw[0]
    if kind == "u16":
        return struct.unpack("<H", raw)[0]
    if kind == "u32":
        return struct.unpack("<I", raw)[0]
    if kind == "u64":
        return struct.unpack("<Q", raw)[0]
    if kind == "i32":
        return struct.unpack("<i", raw)[0]
    if kind == "bytes":
        return raw.hex()
    if kind.startswith("string_u16"):
        if len(raw) < 2:
            return None
        length = struct.unpack("<H", raw[:2])[0]
        return raw[2:2 + length].decode("utf-8", "replace")
    return raw.hex()


def decode_game(body, opcode=None):
    """Decode one plaintext application body. Unknown bytes stay unparsed."""
    body = bytes(body)
    if len(body) < 2:
        return {
            "opcode": opcode,
            "name": None,
            "confidence": "unknown",
            "decode_status": "unknown",
            "fields": [],
            "unparsed": [{"offset": 0, "size": len(body), "reason": "body shorter than an opcode"}],
            "notes": ["No complete opcode is present."],
            "body_length": len(body),
        }
    actual_opcode = struct.unpack_from("<H", body, 0)[0] if opcode is None else int(opcode)
    spec = GAME_OPCODES.get(actual_opcode)
    result = {
        "opcode": actual_opcode,
        "opcode_hex": f"0x{actual_opcode:x}",
        "name": spec["name"] if spec else None,
        "confidence": spec["confidence"] if spec else "unknown",
        "evidence": list(spec.get("evidence", [])) if spec else [],
        "decode_status": "unknown",
        "body_length": len(body),
        "fields": [],
        "unparsed": [],
        "notes": list(spec.get("notes", [])) if spec else [],
    }
    if spec is None:
        result["unparsed"] = [{
            "offset": 0,
            "size": len(body),
            "reason": "opcode has no verified field layout in this repository",
        }]
        return result
    if "variants" in spec and len(body) not in spec["variants"]:
        result["decode_status"] = "variant_unconfirmed"
        result["known_variants"] = list(spec["variants"])
        result["unparsed"] = [{
            "offset": 0,
            "size": len(body),
            "reason": f"observed length {len(body)} is not one of the verified variants",
        }]
        return result
    covered = []
    missing = []
    for field in spec["fields"]:
        offset, size = field["offset"], field["size"]
        chunk = body[offset:offset + size]
        entry = {
            "name": field["name"],
            "offset": offset,
            "size": size,
            "kind": field["kind"],
            "confidence": field["confidence"],
            "evidence": list(field["evidence"]),
        }
        if field.get("note"):
            entry["note"] = field["note"]
        if len(chunk) == size:
            value = _parse_scalar(field["kind"], chunk)
            entry["value"] = value
            entry["raw_hex"] = chunk.hex()
            covered.append((offset, offset + size))
        else:
            entry["value"] = None
            entry["missing"] = {
                "reason": "field extends past the observed body",
                "expected_bytes": size,
                "actual_bytes": len(chunk),
            }
            missing.append(entry["name"])
        result["fields"].append(entry)
    result["unparsed"] = [
        {"offset": start, "size": end - start,
         "reason": "bytes not covered by a verified field layout"}
        for start, end in subtract_ranges((0, len(body)), covered)
    ]
    if missing:
        result["decode_status"] = "partial"
    elif result["unparsed"]:
        result["decode_status"] = "partial"
    else:
        result["decode_status"] = "complete"
    return result


def field_value(decoded, name=None, offset=None, size=None):
    for field in decoded.get("fields", []):
        if name is not None and field.get("name") == name:
            return field.get("value")
        if offset is not None and field.get("offset") == offset:
            if size is None or field.get("size") == size:
                return field.get("value")
    return None


def decode_http_request(data, redact=True):
    data = bytes(data)
    split = data.find(b"\r\n\r\n")
    if split < 0:
        head, body = data, b""
        complete = False
    else:
        head, body = data[:split], data[split + 4:]
        complete = True
    lines = head.split(b"\r\n")
    request_line = lines[0].decode("latin-1", "replace") if lines else ""
    parts = request_line.split(" ")
    headers = []
    sensitive = {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-nxl", "passport"}
    for line in lines[1:]:
        if b":" not in line:
            continue
        name, value = line.split(b":", 1)
        header_name = name.decode("latin-1", "replace").strip()
        header_value = value.decode("latin-1", "replace").strip()
        headers.append({
            "name": header_name,
            "value": "<redacted>" if redact and header_name.lower() in sensitive else header_value,
        })
    host = next((header["value"] for header in headers if header["name"].lower() == "host"), None)
    content_length = next((header["value"] for header in headers if header["name"].lower() == "content-length"), None)
    return {
        "complete": complete,
        "request_line": request_line,
        "method": parts[0] if parts else None,
        "target": parts[1] if len(parts) > 1 else None,
        "version": parts[2] if len(parts) > 2 else None,
        "host": host,
        "headers": headers,
        "header_bytes": len(head) + (4 if complete else 0),
        "body": body,
        "body_length": len(body),
        "declared_body_length": int(content_length) if content_length and content_length.isdigit() else None,
        "notes": [] if complete else ["HTTP header terminator not found in the captured bytes"],
    }


def decode_ngs_response(raw):
    try:
        payload = ngs_cipher.decrypt_response(raw, want="json")
    except Exception as error:  # cipher, gzip, or JSON failure
        return {"ok": False, "error": f"{type(error).__name__}: {error}"}
    if not isinstance(payload, dict):
        return {"ok": True, "payload": payload, "fields": [], "notes": ["decoded body is not a JSON object"]}
    fields = []
    for name, value in payload.items():
        confidence = "supported"
        note = None
        if name in ("emergency_stop", "config_changed", "auth_cycle"):
            kind = "integer"
        elif name == "detected":
            kind = "list"
            note = f"{len(value)} entries" if isinstance(value, list) else None
        elif name in ("subfeature", "signature", "module_crc"):
            kind = "object"
            note = f"{len(value)} entries" if isinstance(value, (dict, list)) else None
        elif name in ("terminate_message", "lifetoken", "csauthtoken"):
            kind = "string"
        else:
            kind = type(value).__name__
            confidence = "unresolved"
        fields.append({
            "name": name,
            "kind": kind,
            "value": value if not isinstance(value, (dict, list)) else None,
            "entry_count": len(value) if isinstance(value, (dict, list)) else None,
            "confidence": confidence,
            "evidence": ["foundations/ngs_cipher.py", "docs/research/03-ngsx-control-plane-FINDINGS.md"],
        })
        if note:
            fields[-1]["note"] = note
    return {"ok": True, "payload": payload, "fields": fields}


def tls_client_hello_sni(data):
    """Return the SNI hostname from a TLS ClientHello record, or None."""
    data = bytes(data)
    offset = 0
    while offset + 5 <= len(data):
        content_type = data[offset]
        version = struct.unpack_from(">H", data, offset + 1)[0]
        length = struct.unpack_from(">H", data, offset + 3)[0]
        if offset + 5 + length > len(data):
            return None
        body = data[offset + 5:offset + 5 + length]
        offset += 5 + length
        if content_type != 22 or version < 0x0300:
            continue
        if not body or body[0] != 1 or len(body) < 4:
            continue
        # Handshake header is type(1)+length(3); ClientHello starts at body[4].
        # ClientHello: legacy_version(2), random(32), session_id, ciphers, compression
        pos = 4 + 2 + 32
        if pos >= len(body):
            return None
        session_len = body[pos]
        pos += 1 + session_len
        if pos + 2 > len(body):
            return None
        cipher_len = struct.unpack_from(">H", body, pos)[0]
        pos += 2 + cipher_len
        if pos >= len(body):
            return None
        compression_len = body[pos]
        pos += 1 + compression_len
        if pos + 2 > len(body):
            return None
        extensions_len = struct.unpack_from(">H", body, pos)[0]
        pos += 2
        end = min(pos + extensions_len, len(body))
        while pos + 4 <= end:
            ext_type, ext_len = struct.unpack_from(">HH", body, pos)
            pos += 4
            ext = body[pos:pos + ext_len]
            pos += ext_len
            if ext_type != 0 or len(ext) < 2:
                continue
            list_len = struct.unpack_from(">H", ext, 0)[0]
            cursor = 2
            while cursor + 3 <= min(2 + list_len, len(ext)):
                name_type = ext[cursor]
                name_len = struct.unpack_from(">H", ext, cursor + 1)[0]
                cursor += 3
                name = ext[cursor:cursor + name_len]
                cursor += name_len
                if name_type == 0 and name:
                    return name.decode("ascii", "replace")
    return None


def decode_dns_query(payload):
    payload = bytes(payload)
    if len(payload) < 12:
        return {"ok": False, "error": "DNS header shorter than 12 bytes"}
    identifier, flags, qdcount, ancount, nscount, arcount = struct.unpack_from(">HHHHHH", payload, 0)
    if qdcount < 1:
        return {"ok": True, "id": identifier, "questions": [], "answers": ancount}
    offset = 12
    labels = []
    while offset < len(payload):
        length = payload[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0:
            return {"ok": False, "error": "compressed question name is not parsed"}
        labels.append(payload[offset:offset + length].decode("ascii", "replace"))
        offset += length
    qtype = qclass = None
    if offset + 4 <= len(payload):
        qtype, qclass = struct.unpack_from(">HH", payload, offset)
    return {
        "ok": True,
        "id": identifier,
        "flags": flags,
        "response": bool(flags & 0x8000),
        "question": ".".join(labels),
        "qtype": qtype,
        "qclass": qclass,
        "answer_count": ancount,
        "authority_count": nscount,
        "additional_count": arcount,
    }
