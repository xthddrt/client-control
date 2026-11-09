"""Generate and test 100 unique near-maximum base-damage RNG states."""

import ctypes
import importlib.util
import json
import os
from pathlib import Path
import signal
import struct
import sys
import time


DIRECTORY = Path(__file__).resolve().parent
TOOLS = DIRECTORY.parent / "tools"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


model = load("attack_rng", DIRECTORY / "attack-rng-observe.py")
solver = load("rng_state_solver", TOOLS / "rng-state-solver.py")
experiment = load("rng_state_override", TOOLS / "rng-state-override.py")
observer = model.observer
shared = model.shared
character = model.character
PROFILE = model.PROFILE
SENDPACKET_RVA = 0x1661780
SELECTOR_RVA = model.SELECTOR_RVA
MELEE_OPCODE = 0xE1
DAMAGE_OFFSET = 0x88


def make_candidates(count=100):
    candidates = []
    for index in range(count):
        roll2 = 0xFFFFFFFF - index % 2
        roll4 = index * 0x00100000
        words = solver.state_for_rolls({2: roll2, 4: roll4}, index)
        state = bytearray(0x2C)
        for offset, word in zip((0, 8, 0x24), words):
            struct.pack_into("<I", state, offset, word)
        expected_rolls, _ = model.rng_rolls(state)
        candidates.append({
            "index": index, "words": list(words), "roll2": roll2, "roll4": roll4,
            "expected_rolls": expected_rolls,
        })
    if len({tuple(candidate["words"]) for candidate in candidates}) != count:
        raise RuntimeError("Candidate states are not unique.")
    if len({tuple(candidate["expected_rolls"]) for candidate in candidates}) != count:
        raise RuntimeError("Candidate roll sequences are not unique.")
    return candidates


def completed_indices(path):
    try:
        lines = Path(path).read_text().splitlines()
    except FileNotFoundError:
        return set()
    return {
        record["index"] for line in lines if line.strip()
        for record in [json.loads(line)] if "index" in record
    }


def run(pid, duration, candidate_path, output):
    candidates = json.loads(Path(candidate_path).read_text())
    done = completed_indices(output)
    remaining = [candidate for candidate in candidates if candidate["index"] not in done]
    if not remaining:
        print("All candidates have already been tested.", flush=True)
        return
    reader = character.Reader(pid)
    base, _ = character.find_image(reader, pid, PROFILE)
    shared.verify_code(reader, base, PROFILE["polearm_attacks"])
    context_root = base + character.number(PROFILE["incoming_display"]["calculator_context_global_rva"])
    targets = {base + SENDPACKET_RVA: 0, base + SELECTOR_RVA: 1}
    attached = stopped = False
    saved = None
    deliver = 0
    stopping = False
    current = None
    original_state = None
    original_stats = None
    restore_pending = False

    def request_stop(signum, frame):
        nonlocal stopping
        stopping = True

    def restore_state():
        nonlocal restore_pending
        if restore_pending:
            experiment.write_memory(pid, original_stats, original_state)
            if reader.read(original_stats, 0x2C) != original_state:
                raise RuntimeError("Original RNG state did not restore exactly.")
            restore_pending = False

    handlers = {number: signal.signal(number, request_stop) for number in (signal.SIGINT, signal.SIGTERM)}
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    stream = os.fdopen(descriptor, "w", encoding="utf-8")
    try:
        status = dict(line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines())
        if int(status["TracerPid"]) or status["State"].strip()[0] in "Tt":
            raise RuntimeError("Game is already traced or paused.")
        observer.ptrace(pid, 0x4206)
        attached = True
        observer.ptrace(pid, 0x4207)
        state = observer.wait_stop(pid, 1)
        stopped = True
        deliver = shared.pending_signal(pid, state, targets)
        saved = {
            slot: observer.ptrace(pid, 3, 848 + slot * 8) & 0xFFFFFFFFFFFFFFFF
            for slot in (0, 1, 6, 7)
        }
        control = saved[7]
        for address, slot in targets.items():
            if control & (3 << (slot * 2)):
                raise RuntimeError(f"Hardware breakpoint slot {slot} is occupied.")
            observer.ptrace(pid, 6, 848 + slot * 8, address)
            control = (control & ~((0xF << (16 + slot * 4)) | (3 << (slot * 2)))) | (1 << (slot * 2))
        observer.ptrace(pid, 6, 848 + 7 * 8, control)
        observer.ptrace(pid, 7, 0, deliver)
        deliver = 0
        stopped = False
        print(f"ARMED pid={pid}: testing {len(remaining)} candidates; original state restored after each attack.", flush=True)
        started = time.monotonic()
        while not stopping and remaining and time.monotonic() - started < duration:
            try:
                state = observer.wait_stop(pid, 0.1)
            except TimeoutError:
                continue
            stopped = True
            number = os.WSTOPSIG(state)
            if number != signal.SIGTRAP:
                observer.ptrace(pid, 7, 0, number)
                stopped = False
                continue
            registers = observer.Registers()
            observer.ptrace(pid, 12, 0, ctypes.addressof(registers))
            if not shared.owns_trap(pid, registers, targets):
                deliver = number
                raise RuntimeError("Trap did not belong to the maximum-roll search.")
            slot = targets[registers.rip]
            if slot == 1:
                if current is None:
                    current = remaining[0]
                    context = reader.qword(context_root)
                    stats = reader.qword(context + 0x2998) if context else 0
                    if not stats:
                        raise RuntimeError("No RNG state context.")
                    original_state = reader.read(stats, 0x2C)
                    original_stats = stats
                    if original_state[0x10:0x1C] != bytes(12):
                        raise RuntimeError("RNG object is locked; refusing a concurrent state write.")
                    modified = bytearray(original_state)
                    for offset, word in zip((0, 8, 0x24), current["words"]):
                        struct.pack_into("<I", modified, offset, word)
                    experiment.write_memory(pid, stats, modified)
                    if reader.read(stats, 0x2C) != modified:
                        raise RuntimeError("Candidate state did not read back exactly.")
                    restore_pending = True
            else:
                packet = registers.rcx
                opcode = reader.unpack("<I", packet + 0x434)[0]
                if opcode == MELEE_OPCODE and current is not None:
                    length = reader.unpack("<I", packet + 0x428)[0]
                    if not 2 <= length <= 4096:
                        raise RuntimeError(f"Invalid melee packet length {length}.")
                    body = reader.read(packet + 8, length)
                    restore_state()
                    damage = struct.unpack_from("<i", body, DAMAGE_OFFSET)[0] if len(body) >= DAMAGE_OFFSET + 4 else None
                    record = {
                        "index": current["index"], "pid": pid, "timestamp": time.time(),
                        "words": current["words"], "roll2": current["roll2"], "roll4": current["roll4"],
                        "expected_rolls": current["expected_rolls"], "damage": damage,
                        "body": body.hex(), "state_restored": not restore_pending,
                    }
                    stream.write(json.dumps(record, separators=(",", ":")) + "\n")
                    stream.flush()
                    print(f"SEARCH {current['index'] + 1}/{len(candidates)} damage={damage} roll4={current['roll4']:#x}", flush=True)
                    remaining.pop(0)
                    current = None
            observer.ptrace(pid, 6, 848 + 6 * 8, 0)
            observer.ptrace(pid, 7)
            stopped = False
    except (OSError, RuntimeError, ValueError, struct.error) as error:
        stream.write(json.dumps({"fatal_error": str(error)}) + "\n")
        stream.flush()
        raise
    finally:
        cleanup_error = None
        if attached:
            try:
                if not stopped:
                    observer.ptrace(pid, 0x4207)
                    state = observer.wait_stop(pid, 1)
                    stopped = True
                    deliver = shared.pending_signal(pid, state, targets)
                try:
                    restore_state()
                finally:
                    if saved is not None:
                        for slot in (7, 0, 1, 6):
                            observer.ptrace(pid, 6, 848 + slot * 8, saved[slot])
                    observer.ptrace(pid, 17, 0, deliver)
                print("DETACHED: original debug registers restored.", flush=True)
            except (OSError, RuntimeError) as error:
                cleanup_error = error
                print(f"DETACH incomplete: {error}", file=sys.stderr, flush=True)
        stream.close()
        reader.close()
        for number, handler in handlers.items():
            signal.signal(number, handler)
        print(f"WROTE {output}: remaining={len(remaining)}", flush=True)
        if cleanup_error is not None:
            raise cleanup_error
    if remaining:
        raise RuntimeError(f"Only {len(candidates) - len(remaining)} candidates completed; JSONL was saved for resume.")


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "generate":
        if len(sys.argv) != 3:
            raise SystemExit("Usage: rng-max-search.py generate OUT.json")
        output = Path(sys.argv[2])
        candidates = make_candidates()
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(candidates, stream, indent=1)
        print(f"WROTE {output}: 100 unique states and 100 unique 11-roll sequences.")
        return
    if len(sys.argv) != 6:
        raise SystemExit("Usage: rng-max-search.py run PID|auto SECONDS CANDIDATES.json OUT.jsonl")
    duration = float(sys.argv[3])
    if not 1 <= duration <= 3600:
        raise SystemExit("Use a capture duration from 1 to 3600 seconds.")
    pid = character.find_pid(PROFILE["process_name"]) if sys.argv[2] == "auto" else int(sys.argv[2])
    run(pid, duration, sys.argv[4], sys.argv[5])


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, struct.error) as error:
        print(f"Maximum-roll search failed: {error}", file=sys.stderr)
        sys.exit(1)
