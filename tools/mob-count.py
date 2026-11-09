"""Read-only CMob scanner emitting the position GUI's MOBS status contract."""

import argparse
import importlib.util
import json
import math
from pathlib import Path
import signal
import struct
import sys
import threading


DIRECTORY = Path(__file__).resolve().parent
FOUNDATIONS = DIRECTORY.parent / "foundations"


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, FOUNDATIONS / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


character = _load("character_resolver", "locate-character.py")
mob_profile = _load("mob_profile", "mob_profile.py")


def writable_regions(pid, maximum_size=512 << 20):
    regions = []
    with open(f"/proc/{pid}/maps") as stream:
        for line in stream:
            fields = line.split()
            if len(fields) < 2 or "rw" not in fields[1]:
                continue
            low, high = (int(value, 16) for value in fields[0].split("-"))
            if high - low <= maximum_size and low < 0x7F0000000000:
                regions.append((low, high))
    return regions


def scan_mob_x(reader, regions, mob_vtable, offsets, chunk_size=16 << 20):
    needle = struct.pack("<Q", mob_vtable)
    candidates = set()
    for low, high in regions:
        for start in range(low, high, chunk_size):
            try:
                data = reader.read(start, min(chunk_size, high - start))
            except (OSError, RuntimeError):
                continue
            offset = data.find(needle)
            while offset != -1:
                address = start + offset
                if address % 8 == 0:
                    candidates.add(address)
                offset = data.find(needle, offset + 8)

    positions = []
    for mob in candidates:
        try:
            controller_pointer = reader.qword(mob + offsets["ctrl_a"])
            if controller_pointer < 0x20:
                continue
            controller = controller_pointer - 0x20
            x = reader.protected(controller + offsets["x"], 8)["value"]
            y = reader.protected(controller + offsets["y"], 8)["value"]
            if math.isfinite(x) and math.isfinite(y) and abs(x) < 100000 and abs(y) < 100000:
                positions.append(x)
        except (OSError, RuntimeError, ValueError, struct.error, OverflowError):
            continue
    return positions


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pid", type=int)
    parser.add_argument("--interval", type=float, default=2.0)
    args = parser.parse_args()
    if not math.isfinite(args.interval) or args.interval <= 0:
        parser.error("--interval must be finite and greater than zero.")

    profile = json.loads((FOUNDATIONS / "profile.json").read_text())
    if Path(f"/proc/{args.pid}/comm").read_text().strip() != profile["process_name"]:
        raise RuntimeError(f"Selected PID does not identify {profile['process_name']}.")
    offsets = mob_profile.load_mob_offsets(profile)
    reader = character.Reader(args.pid)
    stop = threading.Event()

    def request_stop(*_):
        stop.set()

    def control_stdin():
        for line in sys.stdin:
            if line.strip() == "stop":
                break
        stop.set()

    for number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(number, request_stop)
    threading.Thread(target=control_stdin, daemon=True).start()
    try:
        base, _ = character.find_image(reader, args.pid, profile)
        mob_vtable = base + offsets["cmob_vtable_rva"]
        while not stop.is_set():
            positions = scan_mob_x(reader, writable_regions(args.pid), mob_vtable, offsets)
            if positions:
                print(
                    f"MOBS {len(positions)} xmin={round(min(positions))} xmax={round(max(positions))}",
                    flush=True,
                )
            else:
                print("MOBS 0", flush=True)
            stop.wait(args.interval)
    finally:
        reader.close()


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, struct.error) as error:
        print(f"Mob scan failed: {error}", file=sys.stderr)
        sys.exit(1)
