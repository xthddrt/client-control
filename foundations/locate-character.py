"""Read-only resolver for the specifically fingerprinted MapleStory build."""

import argparse
import json
import math
import os
from pathlib import Path
import struct
import sys
import time


class SnapshotChanged(RuntimeError):
    pass


def number(value):
    return int(value, 0)


def hexadecimal(value):
    return f"0x{value:X}"


def find_pid(process_name):
    matches = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            name = (entry / "comm").read_text().strip()
        except (FileNotFoundError, ProcessLookupError):
            continue
        except PermissionError:
            print(f"Cannot inspect {entry / 'comm'}: permission denied", file=sys.stderr)
            continue
        if name == process_name:
            matches.append(int(entry.name))
    if len(matches) != 1:
        raise RuntimeError(
            f"Expected one {process_name} process; found {matches}. "
            "Start the game, or select its current PID with --pid."
        )
    return matches[0]


class Reader:
    def __init__(self, pid):
        self.fd = os.open(f"/proc/{pid}/mem", os.O_RDONLY)

    def close(self):
        os.close(self.fd)

    def read(self, address, size):
        data = os.pread(self.fd, size, address)
        if len(data) != size:
            raise RuntimeError(f"Short read at {hexadecimal(address)}")
        return data

    def unpack(self, fmt, address):
        return struct.unpack(fmt, self.read(address, struct.calcsize(fmt)))

    def qword(self, address):
        return self.unpack("<Q", address)[0]

    def protected(self, wrapper, size):
        before = self.read(wrapper, 24)
        backing = struct.unpack_from("<Q", before, 8)[0]
        if not backing:
            raise SnapshotChanged(f"Null encoded-value backing at {hexadecimal(wrapper)}")
        block = self.read(backing, 16 if size == 8 else 12)
        if self.read(wrapper, 24) != before:
            raise SnapshotChanged(f"Wrapper changed at {hexadecimal(wrapper)}")
        key = block[size]
        checksum = 0x9A65
        decoded = bytearray()
        for byte in block[:size]:
            key = key or 42
            decoded.append(byte ^ key)
            key = (byte + key + 42) & 255
            checksum = (((checksum >> 13) + key) | (checksum << 3)) & 65535
        checksum_offset = 12 if size == 8 else 8
        if struct.unpack_from("<H", block, checksum_offset)[0] != checksum:
            raise SnapshotChanged(f"Checksum mismatch at {hexadecimal(wrapper)}")
        if before[4] != block[size + 1] or before[16] != block[size + 2]:
            raise SnapshotChanged(f"Metadata mismatch at {hexadecimal(wrapper)}")
        value = struct.unpack("<d" if size == 8 else "<i", decoded)[0]
        if not math.isfinite(value):
            raise RuntimeError(f"Nonfinite coordinate at {hexadecimal(wrapper)}")
        return {
            "wrapper": hexadecimal(wrapper),
            "backing": hexadecimal(backing),
            "value": value,
        }

    def protected_integer(self, address):
        seed, encoded, expected = self.unpack("<III", address)
        masked = seed ^ 0xBAADF00D
        checksum = (((masked >> 5) | (masked << 27)) + encoded) & 0xFFFFFFFF
        if checksum != expected:
            raise SnapshotChanged(f"Integer checksum mismatch at {hexadecimal(address)}")
        value = (((encoded << 5) | (encoded >> 27)) & 0xFFFFFFFF) ^ seed
        return value - 0x100000000 if value & 0x80000000 else value

    def protected_pointer(self, address):
        a, b, c, d, expected = self.unpack("<IIIII", address)

        def right(value):
            return ((value >> 5) | (value << 27)) & 0xFFFFFFFF

        def left(value):
            return ((value << 5) | (value >> 27)) & 0xFFFFFFFF

        checksum = (right(0xBAADF00D ^ a) + c) & 0xFFFFFFFF
        checksum = (right(checksum ^ b) + d) & 0xFFFFFFFF
        if checksum != expected:
            raise SnapshotChanged(f"Pointer checksum mismatch at {hexadecimal(address)}")
        return (left(c) ^ a) | ((left(d) ^ b) << 32)


def find_image(reader, pid, profile):
    candidates = set()
    with open(f"/proc/{pid}/maps") as stream:
        for line in stream:
            parts = line.split(None, 5)
            if len(parts) != 6 or int(parts[2], 16) != 0:
                continue
            path = parts[5].strip().removesuffix(" (deleted)")
            if Path(path).name.lower() == profile["process_name"].lower():
                candidates.add(int(parts[0].split("-")[0], 16))
    matches = []
    rejected = []
    for base in sorted(candidates):
        try:
            if reader.read(base, 2) != b"MZ":
                raise ValueError("missing DOS header")
            pe_offset = reader.unpack("<I", base + 0x3C)[0]
            if pe_offset > 0x1000:
                raise ValueError("unexpected PE header offset")
            pe = base + pe_offset
            if reader.read(pe, 4) != b"PE\0\0":
                raise ValueError("missing PE signature")
            expected = profile["pe"]
            actual = {
                "machine": reader.unpack("<H", pe + 4)[0],
                "timestamp": reader.unpack("<I", pe + 8)[0],
                "size_of_image": reader.unpack("<I", pe + 24 + 56)[0],
            }
            if any(actual[key] != number(value) for key, value in expected.items()):
                raise ValueError("executable header differs from the saved build")
            for fingerprint in profile["code_fingerprints"]:
                address = base + number(fingerprint["rva"])
                code = bytes.fromhex(fingerprint["bytes"])
                if reader.read(address, len(code)) != code:
                    raise ValueError(f"code differs: {fingerprint['name']}")
        except (OSError, RuntimeError, ValueError) as error:
            rejected.append(f"{hexadecimal(base)}: {error}")
            continue
        matches.append(base)
    if len(matches) != 1:
        raise RuntimeError(
            f"Expected one validated loaded image; found {list(map(hexadecimal, matches))}. "
            f"Rejected candidates: {rejected}. "
            "The game may not be unpacked yet, or its build changed. Do not reuse offsets blindly."
        )
    return matches[0], rejected


def snapshot(reader, pid, base, profile):
    rvas = {key: number(value) for key, value in profile["rvas"].items()}
    char = {key: number(value) for key, value in profile["character_offsets"].items()}
    ctrl = {key: number(value) for key, value in profile["controller_offsets"].items()}
    body_offsets = profile["body_offsets"]
    root = base + rvas["character_global"]
    actor = reader.qword(root)
    if not actor:
        raise RuntimeError("No character context: enter the game world before resolving.")
    vector = reader.qword(actor + char["vector_interface"])
    body = reader.qword(actor + char["physics_body"])
    if not vector or not body:
        raise RuntimeError("Character has no validated movement vector or physics body.")
    controller = vector - ctrl["interface_adjustment"]
    if reader.qword(vector) != base + rvas["movement_vector_vtable"]:
        raise RuntimeError("Movement-vector type differs from the validated implementation.")
    if reader.qword(vector + 0x100):
        raise RuntimeError("Forwarded movement vector is not covered by this profile.")
    identifier = reader.unpack("<I", actor + char["identifier"])[0]
    user = reader.qword(body + number(body_offsets["user_data"]))
    if not user or reader.unpack("<I", user)[0] != identifier:
        raise SnapshotChanged("Character and physics-body identifiers do not match.")
    cached_x = reader.protected(actor + char["cached_x"], 4)
    cached_y = reader.protected(actor + char["cached_y"], 4)
    movement = {
        name: reader.protected(controller + ctrl[name], 8)
        for name in (
            "world_x_pre_copy", "world_x_post_copy",
            "foothold_relative_position", "foothold_relative_velocity",
            "foothold_relative_position_secondary",
        )
    }
    x_fields = {
        offset: {
            "address": hexadecimal(body + number(offset)),
            "value": reader.unpack("<f", body + number(offset))[0],
        }
        for offset in body_offsets["x_fields"]
    }
    foothold_address = controller + ctrl["encoded_foothold_pointer"]
    foothold = reader.protected_pointer(foothold_address)
    ground = {
        "encoded_pointer_address": hexadecimal(foothold_address),
        "has_foothold_pointer": bool(foothold),
        "address": hexadecimal(foothold),
    }
    if foothold:
        offsets = {key: number(value) for key, value in profile["foothold_offsets"].items()}
        ground.update({
            "endpoints": {
                key: reader.unpack("<i", foothold + offsets[key])[0]
                for key in ("x1", "y1", "x2", "y2")
            },
            "cosine": reader.unpack("<d", foothold + offsets["cosine"])[0],
            "sine": reader.unpack("<d", foothold + offsets["sine"])[0],
            "length": reader.unpack("<d", foothold + offsets["length"])[0],
        })
    if (
        reader.qword(root) != actor
        or reader.qword(actor + char["vector_interface"]) != vector
        or reader.qword(actor + char["physics_body"]) != body
        or reader.protected_pointer(foothold_address) != foothold
    ):
        raise SnapshotChanged("Character, movement controller, or foothold changed during the read.")
    return {
        "read_only": True,
        "pid": pid,
        "module_base": hexadecimal(base),
        "character_global": hexadecimal(root),
        "character": hexadecimal(actor),
        "character_id": identifier,
        "vector_interface": hexadecimal(vector),
        "controller": hexadecimal(controller),
        "physics_body": hexadecimal(body),
        "cached_x": cached_x,
        "cached_y": cached_y,
        "movement": movement,
        "physics_x_fields": x_fields,
        "foothold": ground,
        "notice": "Heap addresses and encoded-value backing allocations are snapshots, not reusable pointers.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, help="Current game PID; otherwise auto-detect.")
    args = parser.parse_args()
    profile = json.loads(Path(__file__).with_name("profile.json").read_text())
    pid = args.pid if args.pid is not None else find_pid(profile["process_name"])
    with open(f"/proc/{pid}/comm") as stream:
        if stream.read().strip() != profile["process_name"]:
            raise RuntimeError("Selected PID does not identify MapleStory.exe.")
    reader = Reader(pid)
    try:
        base, rejected = find_image(reader, pid, profile)
        for attempt in range(3):
            try:
                result = snapshot(reader, pid, base, profile)
                result["rejected_image_candidates"] = rejected
                print(json.dumps(result, indent=2, allow_nan=False))
                return
            except SnapshotChanged as error:
                if attempt == 2:
                    raise
                print(f"Live snapshot changed; retrying: {error}", file=sys.stderr)
                time.sleep(0.01)
    finally:
        reader.close()


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, struct.error) as error:
        print(f"Cannot resolve character: {error}", file=sys.stderr)
        sys.exit(1)
