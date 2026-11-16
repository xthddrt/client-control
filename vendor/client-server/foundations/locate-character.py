"""Read-only resolver for the specifically fingerprinted MapleStory build."""

import os
from pathlib import Path
import struct
import sys


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
