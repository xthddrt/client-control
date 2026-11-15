"""Build-scoped MapleStory message names and evidence-labelled field decoders."""

import struct


OUTGOING_NAMES = {
    0x70: "update_rate_report",
    0xDB: "movement_synchronization",
    0xE1: "melee_attack",
    0x2A5: "input_event_batch",
    0x2FE: "movement_state",
    0x32B: "pickup_request",
}
INCOMING_NAMES = {
    0x471: "drop_spawn",
    0x472: "drop_remove",
    0x8B: "pickup_credit",
}
CONFIRMED_NAMES = set(OUTGOING_NAMES.values()) | set(INCOMING_NAMES.values()) | {"identifier_report"}
FIELD_EVIDENCE = "docs/guides/PACKETS.md; fingerprinted build 0x6AEB667B"


def _integer(body, offset, size, signed=False):
    return int.from_bytes(body[offset:offset + size], "little", signed=signed)


def _put(fields, details, body, name, offset, size, signed=False, evidence=FIELD_EVIDENCE):
    if offset + size > len(body):
        return False
    raw = body[offset:offset + size]
    fields[name] = _integer(body, offset, size, signed)
    details[name] = {
        "offset": offset,
        "size": size,
        "raw_hex": raw.hex(),
        "signed": signed,
        "evidence": evidence,
    }
    return True


def _unresolved_ranges(body, details):
    covered = []
    for detail in details.values():
        start = detail["offset"]
        covered.append((start, start + detail["size"]))
    covered.sort()
    ranges = []
    cursor = 0
    for start, end in covered:
        if start > cursor:
            ranges.append({"offset": cursor, "length": start - cursor})
        cursor = max(cursor, end)
    if cursor < len(body):
        ranges.append({"offset": cursor, "length": len(body) - cursor})
    return ranges


def _input_batch(body, fields, details):
    if not _put(fields, details, body, "header_flag", 2, 1):
        return "partial"
    _put(fields, details, body, "header_value_a", 3, 8)
    _put(fields, details, body, "header_value_b", 11, 8)
    if not _put(fields, details, body, "record_count", 19, 2):
        return "partial"
    records = []
    offset = 21
    for index in range(fields["record_count"]):
        if offset + 5 > len(body):
            return "partial"
        identifier = _integer(body, offset, 4)
        kind = body[offset + 4]
        record = {"index": index, "offset": offset, "identifier": identifier, "type": kind}
        start = offset
        offset += 5
        if kind == 0:
            size = 10
        elif kind == 1:
            size = 13
        elif kind == 2:
            size = 1
        elif kind == 3:
            if offset + 2 > len(body):
                return "partial"
            length = _integer(body, offset, 2)
            record["string_length"] = length
            size = 2 + length
        else:
            record["unknown_tail_offset"] = offset
            records.append(record)
            fields["records"] = records
            return "partial"
        if offset + size > len(body):
            records.append(record)
            fields["records"] = records
            return "partial"
        raw = body[offset:offset + size]
        record["data_hex"] = raw.hex()
        record["length"] = offset + size - start
        if kind == 0:
            record["value"] = _integer(raw, 0, 8)
            record["flags"] = list(raw[8:10])
        elif kind == 1:
            record["value"] = _integer(raw, 0, 4)
            record["flag"] = raw[4]
            record["coordinates"] = [_integer(raw, 5 + i * 2, 2) for i in range(4)]
        elif kind == 2:
            record["marker"] = raw[0]
        elif kind == 3:
            record["string_hex"] = raw[2:].hex()
        records.append(record)
        offset += size
    fields["records"] = records
    fields["trailing_bytes"] = len(body) - offset
    return "decoded" if offset == len(body) else "partial"


def decode_game_body(body, direction="client_to_server"):
    """Decode only fields established for the saved build; retain all other bytes as unknown."""
    body = bytes(body)
    if len(body) < 2:
        return {
            "protocol": "maple",
            "type": None,
            "name": None,
            "status": "missing_opcode",
            "fields": {},
            "field_details": {},
            "unresolved_ranges": [{"offset": 0, "length": len(body)}],
        }
    opcode = _integer(body, 0, 2)
    fields = {"opcode": opcode}
    details = {}
    _put(fields, details, body, "opcode", 0, 2)
    names = INCOMING_NAMES if direction == "server_to_client" else OUTGOING_NAMES
    name = names.get(opcode)
    status = "unknown" if name is None else "partial"

    if opcode == 0x70:
        if len(body) == 11 and body[2] == 5:
            _put(fields, details, body, "subtype", 2, 1)
            _put(fields, details, body, "tick_ms", 3, 4)
            _put(fields, details, body, "update_count", 7, 4)
            status = "decoded"
        elif len(body) >= 3 and body[2] == 13:
            name = "identifier_report"
            _put(fields, details, body, "subtype", 2, 1)
            if len(body) >= 5:
                length = _integer(body, 3, 2)
                _put(fields, details, body, "identifier_length", 3, 2)
                end = 5 + length
                if end <= len(body):
                    raw = body[5:end]
                    fields["identifier_hex"] = raw.hex()
                    details["identifier"] = {"offset": 5, "size": length, "raw_hex": raw.hex(),
                                             "signed": False, "evidence": FIELD_EVIDENCE}
                    try:
                        fields["identifier"] = raw.decode("ascii")
                    except UnicodeDecodeError:
                        status = "partial"
                    if _put(fields, details, body, "flag", end, 1) and end + 1 == len(body) and "identifier" in fields:
                        status = "decoded"
                    else:
                        status = "partial"
                else:
                    status = "partial"
            else:
                status = "partial"
        else:
            name = None
            status = "unknown"
    elif opcode == 0x181:
        if _put(fields, details, body, "field_0x02", 2, 4):
            if len(body) == 6:
                status = "decoded"
            elif fields["field_0x02"] == 2:
                status = "decoded" if _put(fields, details, body, "field_0x06", 6, 4) and len(body) == 10 else "partial"
    elif opcode == 0xE1:
        _put(fields, details, body, "field_0x20", 0x20, 4)
        _put(fields, details, body, "target_identifier", 0x7D, 4)
        _put(fields, details, body, "critical", 0x87, 1)
        _put(fields, details, body, "damage", 0x88, 4, signed=True)
    elif opcode == 0x32B:
        for field_name, offset, size in (
            ("field_0x02", 0x02, 1),
            ("field_0x03", 0x03, 4),
            ("field_0x07", 0x07, 4),
            ("field_0x0b", 0x0B, 2),
            ("field_0x0d", 0x0D, 2),
            ("drop_object_id", 0x0F, 4),
            ("field_0x13", 0x13, 4),
            ("field_0x17", 0x17, 1),
            ("field_0x18", 0x18, 4),
            ("field_0x1c", 0x1C, 4),
            ("field_0x20", 0x20, 4),
        ):
            _put(fields, details, body, field_name, offset, size)
        if len(body) == 36:
            status = "decoded"
    elif opcode == 0x2A5:
        status = _input_batch(body, fields, details)
    elif opcode == 0x471:
        _put(fields, details, body, "drop_object_id", 0x04, 4)
        _put(fields, details, body, "drop_value", 0x15, 4)
        _put(fields, details, body, "target_identifier", 0x2A, 4)
    elif opcode == 0x472:
        _put(fields, details, body, "drop_object_id", 0x02, 4)
    elif opcode == 0x8B:
        if _put(fields, details, body, "credit_type", 0x04, 1):
            if fields["credit_type"] == 1:
                _put(fields, details, body, "meso_amount", 0x06, 4)
            elif fields["credit_type"] == 0:
                _put(fields, details, body, "item_template", 0x05, 4)
                _put(fields, details, body, "item_quantity", 0x09, 4)
    elif opcode == 0x3F3:
        _put(fields, details, body, "target_identifier", 0x02, 4)
        _put(fields, details, body, "hp_candidate", 0x06, 1)
        name = "mob_hp_candidate"
        details["hp_candidate"]["evidence"] += "; candidate only, not authoritative server HP"

    return {
        "protocol": "maple",
        "type": f"0x{opcode:x}",
        "name": name,
        "name_status": "confirmed" if name in CONFIRMED_NAMES else "candidate" if name else "unknown",
        "status": status,
        "fields": fields,
        "field_details": details,
        "unresolved_ranges": _unresolved_ranges(body, details),
        "build_scope": "PE timestamp 0x6AEB667B; reanchor before applying these offsets to another build",
    }


def self_test():
    pickup = bytearray(36)
    struct.pack_into("<H", pickup, 0, 0x32B)
    struct.pack_into("<I", pickup, 0x0F, 0x143FF)
    decoded = decode_game_body(pickup)
    assert decoded["name"] == "pickup_request"
    assert decoded["fields"]["drop_object_id"] == 0x143FF
    assert decoded["status"] == "decoded"
    assert decode_game_body(b"\x01", direction="client_to_server")["status"] == "missing_opcode"
    unknown = decode_game_body(b"\xff\xff\x01")
    assert unknown["type"] == "0xffff" and unknown["name"] is None
    assert unknown["unresolved_ranges"][-1] == {"offset": 2, "length": 1}
    report = decode_game_body(bytes.fromhex("70 00 05 82 53 72 09 90 0f 00 00"))
    assert report["name"] == "update_rate_report" and report["status"] == "decoded"
    assert report["fields"]["tick_ms"] == 158487426 and report["fields"]["update_count"] == 3984
    assert not report["unresolved_ranges"]
    other_report = decode_game_body(bytes.fromhex("70 00 01 00"))
    assert other_report["name"] is None and other_report["status"] == "unknown"
    identifier = b"2d8289ae-04ce-3764-b14b-2d2e64a32bed"
    identifier_report = decode_game_body(struct.pack("<HBH", 0x70, 13, len(identifier)) + identifier + b"\x00")
    assert identifier_report["name"] == "identifier_report" and identifier_report["status"] == "decoded"
    assert identifier_report["fields"]["identifier"] == identifier.decode() and identifier_report["fields"]["flag"] == 0
    assert not identifier_report["unresolved_ranges"]
    assert decode_game_body(struct.pack("<HBH", 0x70, 13, len(identifier)) + identifier)["status"] == "partial"
    message = decode_game_body(bytes.fromhex("81 01 02 00 00 00 99 55 00 00"))
    assert message["name"] is None and message["status"] == "decoded"
    assert message["fields"]["field_0x02"] == 2 and message["fields"]["field_0x06"] == 0x5599
    assert not message["unresolved_ranges"]
    short_message = decode_game_body(bytes.fromhex("81 01 03 00 00 00"))
    assert short_message["fields"] == {"opcode": 0x181, "field_0x02": 3}
    assert short_message["status"] == "decoded" and not short_message["unresolved_ranges"]
    assert decode_game_body(bytes.fromhex("81 01 02 00 00 00 99 55"))["status"] == "partial"
    assert decode_game_body(bytes.fromhex("81 01 02 00 00 00 99 55 00 00 00"))["status"] == "partial"
    assert decode_game_body(bytes.fromhex("81 01 03 00 00 00 00"))["unresolved_ranges"] == [{"offset": 6, "length": 1}]
    batch = bytearray(21)
    struct.pack_into("<H", batch, 0, 0x2A5)
    struct.pack_into("<H", batch, 19, 1)
    batch += struct.pack("<IB", 0x200, 0) + bytes(10)
    decoded = decode_game_body(batch)
    assert decoded["status"] == "decoded" and decoded["fields"]["records"][0]["identifier"] == 0x200
    print("PASS: build-scoped opcode names, bounded fields, unknown bytes, and input batches.")


if __name__ == "__main__":
    self_test()
