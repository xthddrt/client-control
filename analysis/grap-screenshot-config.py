"""Read the live GRAP screenshot configuration without collecting images or a broad memory dump."""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import struct
import time


DIRECTORY = Path(__file__).resolve().parent
PROFILE_PATH = DIRECTORY.parent / "foundations" / "grap-core-profile.json"


def parse_config_record(data):
    values = {}
    for name in ("capture_cool_time", "capture_limit", "quality", "width"):
        key = name.encode()
        start = data.find(key)
        if start < 0 or start + len(key) + 4 > len(data):
            raise ValueError(f"Missing {name}")
        length = struct.unpack_from("<I", data, start + len(key))[0]
        end = start + len(key) + 4 + length
        if length > 16 or end > len(data):
            raise ValueError(f"Invalid {name} length")
        raw = data[start + len(key) + 4:end]
        if not raw.isdigit():
            raise ValueError(f"Non-numeric {name}")
        values[name] = int(raw)
    return values


def self_test():
    data = bytes.fromhex(
        "00004041e6faff6f0000500c220b00000000500c220b00000000160800006803000013000000010046810200000013f000000100000009380000000000000400000011000000636170747572655f636f6f6c5f74696d6501000000360d000000636170747572655f6c696d697403000000313030070000007175616c69747902000000353005000000776964746804000000313238300120f000000500000026cd0100000000000100000004000000686173680a0000003078613830393864383501cccd0100000000000100000004000000686173680a000000307836616434613133380190ce0100000000000100000004000000686173680a000000307834"
    )
    assert parse_config_record(data) == {"capture_cool_time": 6, "capture_limit": 100, "quality": 50, "width": 1280}
    try:
        parse_config_record(b"width\x00\x00\x04\x00")
        raise AssertionError("Invalid field length accepted")
    except ValueError:
        pass
    print("PASS: bounded GRAP screenshot settings and malformed lengths.")


def snapshot(pid, output=None):
    profile = json.loads(PROFILE_PATH.read_text())
    spec = importlib.util.spec_from_file_location("grap_image_check", DIRECTORY.parent / "foundations" / "locate-character.py")
    character = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(character)
    reader = character.Reader(pid)
    result = None
    bytes_scanned = skipped = 0
    try:
        base, _ = character.find_image(reader, pid, profile)
        maps = []
        with open(f"/proc/{pid}/maps") as stream:
            for line in stream:
                parts = line.split()
                start, end = (int(value, 16) for value in parts[0].split("-"))
                if not parts[1].startswith("r") or end - start > 128 * 1024 * 1024:
                    skipped += 1
                    continue
                maps.append((start, end, parts[5] if len(parts) >= 6 else None))
        for start, end, mapping in maps:
            position = start
            tail = b""
            try:
                while position < end and result is None:
                    block = reader.read(position, min(1024 * 1024, end - position))
                    bytes_scanned += len(block)
                    data = tail + block
                    for needle in (b"capture_cool_time", b"capture_limit", b"quality", b"width"):
                        if needle not in data:
                            break
                    else:
                        origin = position - len(tail) + data.index(b"capture_cool_time") - 32
                        excerpt = reader.read(origin, 256)
                        values = parse_config_record(excerpt)
                        width = excerpt.index(b"width")
                        end_of_width = width + 5 + 4 + struct.unpack_from("<I", excerpt, width + 5)[0]
                        excerpt = excerpt[:end_of_width]
                        result = {
                            "schema": "client-control.grap-screenshot-config.v1",
                            "status": "found",
                            "pid": pid,
                            "wall_time_ns": time.time_ns(),
                            "module_base": hex(base),
                            "pe_timestamp": profile["pe"]["timestamp"],
                            "image_sha256": profile["image_sha256"],
                            "excerpt_address": hex(origin),
                            "mapping": mapping,
                            "excerpt_hex": excerpt.hex(),
                            "feature_id_0x3809_present": struct.pack("<I", 14345) in excerpt,
                            "decoded": values,
                            "proof_limits": "Configuration and field encoding only; no capture, image, upload, or server receipt is proven.",
                        }
                    tail = data[-32:]
                    position += len(block)
            except (OSError, RuntimeError, ValueError):
                skipped += 1
                continue
    finally:
        reader.close()
    if result is None:
        result = {
            "schema": "client-control.grap-screenshot-config.v1",
            "status": "not_found",
            "pid": pid,
            "wall_time_ns": time.time_ns(),
            "module_base": hex(base),
            "pe_timestamp": profile["pe"]["timestamp"],
            "image_sha256": profile["image_sha256"],
            "decoded": None,
            "proof_limits": "No supported configuration was found in the covered mappings. This does not prove the feature is absent or disabled.",
        }
    result["scan"] = {
        "scope": "readable mappings up to 128 MiB; not a complete memory scan",
        "bytes_scanned": bytes_scanned,
        "skipped_or_unreadable_mappings": skipped,
        "screen_or_image_contents_read": False,
    }
    encoded = json.dumps(result, indent=2) + "\n"
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(encoded)
        if os.geteuid() == 0 and "SUDO_UID" in os.environ and "SUDO_GID" in os.environ:
            os.chown(output, int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"]))
    print(encoded, end="")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pid", type=int)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    snapshot(args.pid, args.output)


if __name__ == "__main__":
    import sys
    if sys.argv[1:] == ["--self-test"]:
        self_test()
    else:
        main()
