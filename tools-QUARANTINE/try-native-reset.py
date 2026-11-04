"""Read-only portal discovery and fail-closed native-reset destination validation."""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
import types


DIRECTORY = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("character_resolver", DIRECTORY / "locate-character.py")
character = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(character)


def _cstring(reader, address, limit=256):
    if not address:
        return ""
    value = bytearray()
    for offset in range(limit):
        byte = reader.read(address + offset, 1)
        if byte == b"\0":
            return value.decode("utf-8", errors="replace")
        value.extend(byte)
    raise RuntimeError(f"Portal name at {character.hexadecimal(address)} exceeds {limit} bytes.")


def portal_snapshot(reader, pid, base, profile):
    layout = profile["portal_layout"]
    manager = reader.qword(base + character.number(layout["manager_global_rva"]))
    if not manager:
        raise RuntimeError("No current portal manager.")
    expected_vtable = base + character.number(layout["manager_vtable_rva"])
    if reader.qword(manager) != expected_vtable:
        raise RuntimeError("Portal manager type differs from the fingerprinted build.")
    array = reader.qword(manager + character.number(layout["array_pointer"]))
    count = 0 if not array else reader.unpack("<I", array + layout["array_count_offset"])[0]
    if not 0 <= count <= 4096 or count and not array:
        raise RuntimeError(f"Invalid portal array/count: array={array:#x}, count={count}.")
    entry_size = layout["entry_size"]
    if entry_size != 16:
        raise RuntimeError(f"Unsupported portal entry size {entry_size}.")

    portals = []
    null_slots = []
    for index in range(count):
        entry = array + index * entry_size
        record = reader.qword(entry + character.number(layout["entry_object_pointer"]))
        if not record:
            null_slots.append(index)
            continue
        excluded = reader.unpack(
            "<B", record + character.number(layout["record_accessor_exclusion"])
        )[0]
        if excluded:
            null_slots.append(index)
            continue
        name_pointer = reader.qword(record + character.number(layout["record_name_pointer"]))
        portal_type = reader.unpack("<I", record + character.number(layout["record_type"]))[0]
        if portal_type > 100:
            raise RuntimeError(f"Portal {index} has implausible type {portal_type}.")
        destination_fallback = reader.unpack(
            "<I", record + character.number(layout["record_destination_fallback"])
        )[0]
        x = reader.unpack("<i", record + character.number(layout["record_x"]))[0]
        y = reader.unpack("<i", record + character.number(layout["record_y"]))[0]
        if y != reader.unpack("<i", record + character.number(layout["record_y"]))[0]:
            raise RuntimeError(f"Portal {index} changed while being read.")
        portals.append({
            "index": index,
            "id": reader.unpack("<I", record + character.number(layout["record_id"]))[0],
            "name": _cstring(reader, name_pointer),
            "type": portal_type,
            "x": x,
            "y": y,
            "usable": portal_type in (2, 7) or destination_fallback != 0,
        })
    if reader.qword(manager + character.number(layout["array_pointer"])) != array:
        raise character.SnapshotChanged("Portal array changed during the read.")

    type_two = [portal for portal in portals if portal["type"] == 2]
    edges = {"left": [], "right": []}
    if type_two:
        edges["left"] = [min(type_two, key=lambda portal: portal["x"])["index"]]
        edges["right"] = [max(type_two, key=lambda portal: portal["x"])["index"]]
    return {
        "read_only": True,
        "pid": pid,
        "module_base": character.hexadecimal(base),
        "manager": character.hexadecimal(manager),
        "array": character.hexadecimal(array),
        "slot_count": count,
        "null_slots": null_slots,
        "portals": portals,
        "type_2_edge_candidates": edges,
    }


def snapshot_token(records):
    stable = {
        "array": records["array"],
        "slot_count": records["slot_count"],
        "null_slots": records.get("null_slots", []),
        "portals": records["portals"],
    }
    encoded = json.dumps(stable, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def destination(player, records, index, token):
    if token != snapshot_token(records):
        raise ValueError("Portal snapshot token is stale; refresh the portal list.")
    if player["pid"] != records["pid"] or player["module_base"] != records["module_base"]:
        raise ValueError("Player and portal snapshots belong to different contexts.")
    if not player["foothold"]["has_foothold_pointer"]:
        raise ValueError("Stand still on solid ground before choosing a portal.")
    matches = [portal for portal in records["portals"] if portal["index"] == index]
    if len(matches) != 1:
        raise ValueError(f"Portal index {index} is not present exactly once.")
    portal = matches[0]
    if portal["type"] == 0:
        raise ValueError("Spawn points are view-only destinations.")
    if not portal["usable"]:
        raise ValueError("Portal is not a usable destination on this map.")
    return {
        "portal_index": index,
        "portal_id": portal["id"],
        "x": portal["x"],
        "y": portal["y"],
        "expected_controller": player["controller"],
        "expected_portal_token": token,
    }


def verify_native_code(reader, base, settings):
    start = base + character.number(settings["rva"])
    code = reader.read(start, character.number(settings["size"]))
    if hashlib.sha256(code).hexdigest() != settings["sha256"]:
        raise RuntimeError("Native reset function differs from the researched build.")
    boundary = reader.read(
        base + character.number(settings["update_boundary_rva"]),
        len(bytes.fromhex(settings["update_boundary_bytes"])),
    )
    if boundary.hex() != settings["update_boundary_bytes"].lower():
        raise RuntimeError("Native reset update boundary differs from the researched build.")


def run(args, profile):
    pid = args.pid if args.pid is not None else character.find_pid(profile["process_name"])
    if Path(f"/proc/{pid}/comm").read_text().strip() != profile["process_name"]:
        raise RuntimeError(f"Selected PID does not identify {profile['process_name']}.")
    reader = character.Reader(pid)
    try:
        base, _ = character.find_image(reader, pid, profile)
        verify_native_code(reader, base, profile["native_reset"])
        player = character.snapshot(reader, pid, base, profile)
        records = portal_snapshot(reader, pid, base, profile)
        if player["controller"].lower() != args.expected_controller.lower():
            raise RuntimeError("Character controller changed; refusing a stale destination.")
        target = destination(player, records, args.portal_index, args.expected_portal_token)
        fresh_player = character.snapshot(reader, pid, base, profile)
        fresh_records = portal_snapshot(reader, pid, base, profile)
        destination(fresh_player, fresh_records, args.portal_index, args.expected_portal_token)
        if fresh_player["controller"] != player["controller"]:
            raise character.SnapshotChanged("Character controller changed during validation.")
        if args.execute:
            raise RuntimeError(
                "The original native-call register/stack sequence was omitted from the redacted "
                "drop; --execute is disabled rather than guessing a process-memory call."
            )
        print(json.dumps({"validated": True, "executed": False, "destination": target}, indent=2))
        print("Offline/dry-run validation only; no native call or server acceptance is claimed.")
    finally:
        reader.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int)
    parser.add_argument("--expected-controller", required=True)
    parser.add_argument("--portal-index", type=int, required=True)
    parser.add_argument("--expected-portal-token", required=True)
    parser.add_argument("--initial-only", action="store_true")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    if args.portal_index < 0:
        parser.error("--portal-index cannot be negative.")
    profile = json.loads((DIRECTORY / "profile.json").read_text())
    run(args, profile)


portal_module = types.SimpleNamespace(
    character=character,
    portal_snapshot=portal_snapshot,
    snapshot_token=snapshot_token,
)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, struct.error) as error:
        print(f"Native portal validation failed: {error}", file=sys.stderr)
        sys.exit(1)
