"""Record outgoing packets, combat state, and optional full-memory changes around drops."""

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
FOUNDATIONS = DIRECTORY.parent / "foundations"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


model = load("attack_rng", DIRECTORY / "attack-rng-observe.py")
dataset = load("rng_dataset", DIRECTORY / "rng-dataset.py")
memory_watch = load("memory_watch", FOUNDATIONS / "memory-watch.py")
observer = model.observer
shared = model.shared
character = model.character
PROFILE = model.PROFILE
SENDPACKET_RVA = 0x1661780
SELECTOR_RVA = model.SELECTOR_RVA
MELEE_OPCODE = 0xE1
DAMAGE_OFFSET = 0x88
MOVEMENT_OPCODES = {0xDB, 0x2FE}
DROP_EVENT_OPCODES = {0x32B, 0x13B}
MAX_PACKET_BYTES = 16 * 1024 * 1024


def state_words(state):
    return [struct.unpack_from("<I", state, offset)[0] for offset in (0, 8, 0x24)]


def full_memory_due(opcode, last_time, interval, now):
    return opcode in DROP_EVENT_OPCODES or now - last_time >= interval


def run(pid, duration, output, full_memory=False):
    reader = character.Reader(pid)
    base, _ = character.find_image(reader, pid, PROFILE)
    shared.verify_code(reader, base, PROFILE["polearm_attacks"])
    root = base + character.number(PROFILE["rvas"]["character_global"])
    context_root = base + character.number(PROFILE["incoming_display"]["calculator_context_global_rva"])
    targets = {base + SENDPACKET_RVA: 0, base + SELECTOR_RVA: 1}
    attached = stopped = False
    saved = None
    deliver = 0
    stopping = False
    pending = None
    last_memory = None
    last_full_memory = None
    last_full_memory_time = 0.0
    full_memory_interval = float(os.environ.get("FULL_MEMORY_INTERVAL", "5.0"))
    if full_memory_interval < 0:
        raise ValueError("FULL_MEMORY_INTERVAL must be nonnegative.")
    packets = 0
    attacks = 0

    def request_stop(signum, frame):
        nonlocal stopping
        stopping = True

    handlers = {number: signal.signal(number, request_stop) for number in (signal.SIGINT, signal.SIGTERM)}
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
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
        print(f"ARMED pid={pid}: recording outgoing packets and state changes for {duration}s.", flush=True)
        started = time.monotonic()
        while not stopping and time.monotonic() - started < duration:
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
                raise RuntimeError("Trap did not belong to the drop observer.")
            slot = targets[registers.rip]
            if slot == 1:
                actor = reader.qword(root)
                if actor:
                    before, state_error = dataset.read_state(reader, context_root)
                    pending = {
                        "timestamp": time.time(),
                        "action": reader.unpack("<i", actor + character.number(
                            PROFILE["polearm_attacks"]["temporary_action_offset"]
                        ))[0],
                        "memory": model.memory_state(reader, root, context_root),
                    }
                    if before is not None:
                        pending["predicted_rolls"] = model.rng_rolls(before)[0]
                    if state_error is not None:
                        pending["state_error"] = state_error
                    last_memory = pending["memory"]
                    if full_memory and last_full_memory is None:
                        last_full_memory = memory_watch.snapshot(reader, pid)
                        last_full_memory_time = time.monotonic()
            else:
                packet = registers.rcx
                opcode = reader.unpack("<I", packet + 0x434)[0]
                length = reader.unpack("<I", packet + 0x428)[0]
                if not 2 <= length <= MAX_PACKET_BYTES:
                    raise RuntimeError(f"Invalid packet length {length} for opcode {opcode:#x}.")
                body = reader.read(packet + 8, length)
                record = {
                    "index": packets, "timestamp": time.time(), "pid": pid,
                    "direction": "client_to_server", "opcode": hex(opcode),
                    "length": length, "body": body.hex(),
                    "caller_rva": hex(reader.qword(registers.rsp) - base),
                    "packet_va": hex(packet), "body_va": hex(packet + 8),
                    "return_stack_rvas": [hex(reader.qword(registers.rsp + index * 8) - base) for index in range(8)],
                }
                packets += 1
                detailed = opcode == MELEE_OPCODE or (attacks and opcode not in MOVEMENT_OPCODES)
                if detailed:
                    current = model.memory_state(reader, root, context_root)
                    record["memory"] = current
                    if last_memory is not None:
                        record["changed_regions"] = {
                            name: model.changed_runs(last_memory["regions"].get(name), current["regions"].get(name))
                            for name in current["regions"]
                        }
                    last_memory = current
                    if full_memory and full_memory_due(opcode, last_full_memory_time, full_memory_interval, time.monotonic()):
                        current_full_memory = memory_watch.snapshot(reader, pid)
                        record["full_memory_diff"] = memory_watch.diff(last_full_memory, current_full_memory)
                        record["full_memory_interval_seconds"] = full_memory_interval
                        last_full_memory = current_full_memory
                        last_full_memory_time = time.monotonic()
                else:
                    before, state_error = dataset.read_state(reader, context_root)
                    record["rng_words"] = state_words(before) if before is not None else None
                    if state_error is not None:
                        record["state_error"] = state_error
                if opcode == MELEE_OPCODE:
                    attacks += 1
                    record["attack_index"] = attacks
                    record["damage"] = struct.unpack_from("<i", body, DAMAGE_OFFSET)[0] if len(body) >= DAMAGE_OFFSET + 4 else None
                    if pending is not None:
                        after = record["memory"]
                        analysis = model.analyze_rng(pending["memory"]["regions"]["stats_2998"], after["regions"]["stats_2998"])
                        record["selector"] = pending
                        record["eleven_step_match"] = analysis["eleven_step_match"]
                        record["matching_transitions"] = analysis["matching_transitions"]
                    pending = None
                    print(f"ATTACK {attacks} damage={record['damage']} state_match={record.get('eleven_step_match')}", flush=True)
                elif detailed:
                    print(f"PACKET {packets} opcode={opcode:#x} length={length} changed_regions={list(record.get('changed_regions', {}))}", flush=True)
                stream.write(json.dumps(record, separators=(",", ":")) + "\n")
                stream.flush()
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
                if saved is not None:
                    for slot in (7, 0, 1, 6):
                        observer.ptrace(pid, 6, 848 + slot * 8, saved[slot])
                observer.ptrace(pid, 17, 0, deliver)
                print("DETACHED: original debug registers restored; no memory writes.", flush=True)
            except (OSError, RuntimeError) as error:
                cleanup_error = error
                print(f"DETACH incomplete: {error}", file=sys.stderr, flush=True)
        stream.close()
        reader.close()
        for number, handler in handlers.items():
            signal.signal(number, handler)
        print(f"WROTE {output}: packets={packets} attacks={attacks}", flush=True)
        if cleanup_error is not None:
            raise cleanup_error


def main():
    full_memory = "--full-memory" in sys.argv
    arguments = [argument for argument in sys.argv if argument != "--full-memory"]
    if len(arguments) != 4:
        raise SystemExit("Usage: drop-observe.py [--full-memory] PID|auto SECONDS OUT.jsonl")
    duration = float(arguments[2])
    if not 1 <= duration <= 3600:
        raise SystemExit("Use a capture duration from 1 to 3600 seconds.")
    pid = character.find_pid(PROFILE["process_name"]) if arguments[1] == "auto" else int(arguments[1])
    run(pid, duration, arguments[3], full_memory)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, struct.error) as error:
        print(f"Drop observation failed: {error}", file=sys.stderr)
        sys.exit(1)
