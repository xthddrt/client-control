"""Whole-message framing and conservative protocol decoding over contiguous bytes."""

import importlib.util
import json
from pathlib import Path
import struct

from packet_fields import decode_game_body


MAX_GAME_BODY = 16 * 1024 * 1024
KNOWN_OUTGOING = {
    0x70, 0xDB, 0xE1, 0xE7, 0xF4, 0xF5, 0x13F, 0x1A7, 0x1EF,
    0x233, 0x234, 0x235, 0x265, 0x266, 0x2A5, 0x2EF, 0x2FE, 0x326, 0x32B, 0x407,
}


def load_wire():
    path = Path(__file__).resolve().parent.parent / "analysis" / "wire-session-decrypt.py"
    spec = importlib.util.spec_from_file_location("client_control_wire", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _maple_frames(data):
    frames = []
    offset = 0
    problem = None
    while offset + 4 <= len(data):
        word0, word1 = struct.unpack_from("<HH", data, offset)
        length = word0 ^ word1
        if length == 0 or length > MAX_GAME_BODY:
            problem = {"offset": offset, "reason": "invalid_frame_length", "declared_length": length}
            break
        if offset + 4 + length > len(data):
            problem = {
                "offset": offset,
                "reason": "incomplete_frame",
                "declared_length": length,
                "captured_length": len(data) - offset - 4,
            }
            break
        raw = data[offset:offset + 4 + length]
        frames.append({"offset": offset, "word0": word0, "body": raw[4:], "raw": raw})
        offset += 4 + length
    if problem is None and offset != len(data):
        problem = {"offset": offset, "reason": "trailing_header_bytes", "captured_length": len(data) - offset}
    return frames, problem


def _start_layer(wire, iv, body):
    candidates = []
    known = []
    for layer in (0, 1):
        plain = wire.decrypt_body(iv, body, layer)
        if len(plain) >= 2:
            opcode = struct.unpack_from("<H", plain)[0]
            if opcode < 0x400:
                candidates.append(layer)
            if opcode in KNOWN_OUTGOING:
                known.append(layer)
    if len(known) == 1:
        return known[0], "known_opcode"
    if len(candidates) == 1:
        return candidates[0], "opcode_range_heuristic"
    return wire.detect_start_layer(iv, body), "ambiguous_legacy_heuristic"


def decode_maple_run(data, direction):
    """Decode all complete frames in one gap-free run; never scan for plausible resynchronization."""
    frames, problem = _maple_frames(data)
    result = {
        "recognized": False,
        "frames": [],
        "problem": problem,
        "unparsed": data,
        "cipher_evidence": None,
    }
    if len(frames) < 2 or direction not in ("client_to_server", "server_to_client"):
        return result
    wire = load_wire()
    mask = wire.SEND_MASK if direction == "client_to_server" else wire.RECV_MASK
    seed = None
    for index in range(min(len(frames) - 1, 8)):
        candidates = wire.seed_iv(frames[index]["word0"], frames[index + 1]["word0"], mask)
        if len(candidates) == 1:
            seed = (index, candidates[0])
            break
    if seed is None:
        result["problem"] = problem or {"reason": "no_unique_iv_seed"}
        return result
    result["recognized"] = True
    result["cipher_evidence"] = {
        "algorithm": "AES-256-OFB" if direction == "client_to_server" else "XOR-IV0",
        "seed_frame": seed[0],
        "seed_iv": seed[1].hex(),
        "seed_source": "two_consecutive_headers_unique",
    }
    start_layer = 0
    layer_known = direction == "server_to_client"
    if direction == "client_to_server":
        for index in range(seed[0], len(frames)):
            if len(frames[index]["body"]) >= 16:
                iv = seed[1]
                for _ in range(index - seed[0]):
                    iv = wire.tc.getNewIv(iv, wire.TABLE)
                start_layer, evidence = _start_layer(wire, iv, frames[index]["body"])
                layer_known = evidence != "ambiguous_legacy_heuristic"
                result["cipher_evidence"]["start_layer"] = start_layer
                result["cipher_evidence"]["start_layer_evidence"] = evidence
                break
        if not layer_known:
            result["cipher_evidence"]["start_layer"] = None
            result["cipher_evidence"]["start_layer_evidence"] = "unavailable_or_ambiguous"
    iv = seed[1]
    for index in range(seed[0], len(frames)):
        frame = frames[index]
        synced = (wire._hs(iv) ^ mask) == frame["word0"]
        can_decrypt = synced and layer_known
        plain = (
            wire.decrypt_body_recv(iv, frame["body"])
            if direction == "server_to_client"
            else wire.decrypt_body(iv, frame["body"], start_layer)
        ) if can_decrypt else None
        decoded = decode_game_body(plain, direction) if can_decrypt else {
            "protocol": "maple",
            "type": None,
            "name": None,
            "status": "iv_out_of_sync" if not synced else "cipher_layer_unknown",
            "fields": {},
            "unresolved_ranges": [{"offset": 0, "length": len(frame["body"])}],
        }
        decoded["iv"] = iv.hex()
        decoded["iv_synced"] = synced
        decoded["cipher_evidence"] = result["cipher_evidence"]
        item = dict(frame)
        item["plaintext"] = plain
        item["decode"] = decoded
        result["frames"].append(item)
        iv = wire.tc.getNewIv(iv, wire.TABLE)
    for frame in frames[:seed[0]]:
        item = dict(frame)
        item["plaintext"] = None
        item["decode"] = {
            "protocol": "maple", "type": None, "name": None, "status": "iv_seed_not_reached",
            "fields": {}, "unresolved_ranges": [{"offset": 0, "length": len(frame["body"])}],
        }
        result["frames"].insert(0, item)
    result["frames"].sort(key=lambda frame: frame["offset"])
    result["unparsed"] = data[problem["offset"]:] if problem is not None else b""
    return result


def decode_tls_run(data):
    records = []
    offset = 0
    names = {20: "change_cipher_spec", 21: "alert", 22: "handshake", 23: "application_data", 24: "heartbeat"}
    while offset + 5 <= len(data):
        content_type = data[offset]
        version = struct.unpack_from(">H", data, offset + 1)[0]
        length = struct.unpack_from(">H", data, offset + 3)[0]
        if content_type not in names or not 0x0300 <= version <= 0x0304 or length > 18432:
            break
        if offset + 5 + length > len(data):
            break
        raw = data[offset:offset + 5 + length]
        records.append({
            "offset": offset,
            "raw": raw,
            "plaintext": None,
            "decode": {
                "protocol": "tls",
                "type": names[content_type],
                "name": names[content_type],
                "status": "encrypted" if content_type == 23 else "metadata_only",
                "fields": {"content_type": content_type, "legacy_version": f"0x{version:x}", "payload_length": length},
                "unresolved_ranges": [{"offset": 5, "length": length, "reason": "TLS ciphertext"}],
            },
        })
        offset += len(raw)
    recognized = bool(records) and offset > 0
    return {
        "recognized": recognized,
        "frames": records,
        "problem": None if offset == len(data) else {"offset": offset, "reason": "incomplete_or_non_tls_bytes"},
        "unparsed": data[offset:],
    }


def _headers(block):
    lines = block.split(b"\r\n")
    first = lines[0].decode("iso-8859-1")
    headers = {}
    for line in lines[1:]:
        name, separator, value = line.partition(b":")
        if not separator:
            continue
        key = name.decode("iso-8859-1").lower()
        text = value.strip().decode("iso-8859-1")
        headers[key] = headers[key] + ", " + text if key in headers else text
    return first, headers


def decode_http_run(data):
    messages = []
    offset = 0
    methods = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ", b"CONNECT ")
    while offset < len(data):
        if not data.startswith(methods + (b"HTTP/",), offset):
            break
        end = data.find(b"\r\n\r\n", offset)
        if end < 0:
            break
        first, headers = _headers(data[offset:end])
        header_end = end + 4
        if "transfer-encoding" in headers:
            messages.append({
                "offset": offset,
                "raw": data[offset:header_end],
                "plaintext": data[offset:header_end],
                "decode": {
                    "protocol": "http", "type": first, "name": first, "status": "partial",
                    "reason": "transfer_encoded_body_not_reassembled",
                    "fields": {"headers": headers}, "unresolved_ranges": [],
                },
            })
            offset = header_end
            break
        try:
            length = int(headers.get("content-length", "0"))
        except ValueError:
            length = -1
        if length < 0 or header_end + length > len(data):
            break
        raw = data[offset:header_end + length]
        parts = first.split(" ", 2)
        fields = {"headers": headers}
        if not first.startswith("HTTP/"):
            fields.update({"method": parts[0], "target": parts[1] if len(parts) > 1 else None})
            message_type = first
        else:
            fields["status"] = int(parts[1]) if len(parts) > 1 and parts[1].isdecimal() else None
            message_type = first
        if "host" in headers:
            fields["host"] = headers["host"]
        messages.append({
            "offset": offset,
            "raw": raw,
            "plaintext": raw,
            "decode": {
                "protocol": "http", "type": message_type, "name": message_type, "status": "decoded",
                "fields": fields,
                "unresolved_ranges": [{"offset": header_end - offset, "length": length}] if length else [],
            },
        })
        offset += len(raw)
    return {
        "recognized": bool(messages),
        "frames": messages,
        "problem": None if offset == len(data) else {"offset": offset, "reason": "incomplete_or_non_http_bytes"},
        "unparsed": data[offset:],
    }


def _dns_name(data, offset):
    labels = []
    next_offset = None
    for _ in range(128):
        if offset >= len(data):
            return None, None
        length = data[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                return None, None
            target = ((length & 0x3F) << 8) | data[offset + 1]
            if target >= offset:
                return None, None
            next_offset = next_offset or offset + 2
            offset = target
            continue
        if length & 0xC0:
            return None, None
        offset += 1
        if length == 0:
            return ".".join(labels), next_offset or offset
        if length > 63 or offset + length > len(data):
            return None, None
        labels.append("".join(chr(byte) if 32 <= byte < 127 and chr(byte) not in ".;" else f"\\{byte:03d}"
                              for byte in data[offset:offset + length]))
        offset += length
    return None, None


def decode_dns_datagram(data):
    if len(data) < 12:
        return None
    identifier, flags, questions, answers = struct.unpack_from(">HHHH", data)
    if questions == 0 or questions > 16:
        return None
    offset = 12
    decoded_questions = []
    for _ in range(questions):
        name, offset = _dns_name(data, offset)
        if name is None or offset + 4 > len(data):
            return None
        query_type, query_class = struct.unpack_from(">HH", data, offset)
        offset += 4
        decoded_questions.append({"name": name, "type": query_type, "class": query_class})
    return {
        "protocol": "dns",
        "type": "response" if flags & 0x8000 else "query",
        "name": "dns_response" if flags & 0x8000 else "dns_query",
        "status": "partial" if answers else "decoded",
        "fields": {
            "id": identifier, "flags": flags, "questions": decoded_questions,
            "answer_count": answers, "rcode": flags & 15,
        },
        "unresolved_ranges": [{"offset": offset, "length": len(data) - offset}] if offset < len(data) else [],
    }


def self_test():
    body = bytearray(36)
    struct.pack_into("<H", body, 0, 0x32B)
    struct.pack_into("<I", body, 15, 99)
    wire = load_wire()
    iv = bytes.fromhex("02000000")
    encoded = []
    current = iv
    for plain in (bytes(body), b"\x70\x00\x05"):
        word0 = wire._hs(current) ^ wire.SEND_MASK
        encrypted = wire.decrypt_body(current, plain, 0)
        encoded.append(struct.pack("<HH", word0, word0 ^ len(plain)) + encrypted)
        current = wire.tc.getNewIv(current, wire.TABLE)
    result = decode_maple_run(b"".join(encoded), "client_to_server")
    assert result["recognized"] and len(result["frames"]) == 2
    assert result["frames"][0]["plaintext"] == bytes(body)
    assert result["frames"][0]["decode"]["fields"]["drop_object_id"] == 99
    short_frames = []
    current = iv
    for plain in (b"\x70\x00\x05", b"\x70\x00\x06"):
        word0 = wire._hs(current) ^ wire.SEND_MASK
        encrypted = wire.decrypt_body(current, plain, 0)
        short_frames.append(struct.pack("<HH", word0, word0 ^ len(plain)) + encrypted)
        current = wire.tc.getNewIv(current, wire.TABLE)
    short_result = decode_maple_run(b"".join(short_frames), "client_to_server")
    assert short_result["frames"][0]["plaintext"] is None
    assert short_result["frames"][0]["decode"]["status"] == "cipher_layer_unknown"
    tls = b"\x17\x03\x03\x00\x03abc" + b"\x16\x03\x03\x00\x00"
    assert len(decode_tls_run(tls)["frames"]) == 2
    http = b"POST /v2 HTTP/1.1\r\nHost: x-csauth.ngs.nexon.com\r\nContent-Length: 3\r\n\r\nabc"
    decoded = decode_http_run(http)
    assert decoded["frames"][0]["raw"] == http and decoded["frames"][0]["decode"]["fields"]["method"] == "POST"
    combined = decode_http_run(http + http)
    assert len(combined["frames"]) == 2 and all(frame["decode"]["fields"]["method"] == "POST" for frame in combined["frames"])
    dns = bytearray(12) + b"\x03foo\x07example\x03com\x00" + struct.pack(">HH", 1, 1)
    struct.pack_into(">HHHH", dns, 0, 7, 0x0100, 1, 0)
    assert decode_dns_datagram(dns)["fields"]["questions"][0]["name"] == "foo.example.com"
    print("PASS: MapleStory, TLS, HTTP, and DNS whole-message decoding.")


if __name__ == "__main__":
    self_test()
