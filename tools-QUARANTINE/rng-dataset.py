"""Record a streaming dataset of melee RNG states, predicted rolls, and damage."""

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


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


model = load("attack_rng", DIRECTORY / "attack-rng-observe.py")
observer = model.observer
shared = model.shared
character = model.character
PROFILE = model.PROFILE
SENDPACKET_RVA = 0x1661780
SELECTOR_RVA = model.SELECTOR_RVA
MELEE_OPCODE = 0xE1
DAMAGE_OFFSET = 0x88


def state_words(state):
    return [struct.unpack_from("<I", state, offset)[0] for offset in (0, 8, 0x24)]


def read_state(reader, context_root):
    try:
        context = reader.qword(context_root)
        stats = reader.qword(context + 0x2998) if context else 0
        if not stats:
            return None, "No RNG state context."
        return reader.read(stats, 0x2C), None
    except (OSError, RuntimeError) as error:
        return None, str(error)


def existing_attack_count(path):
    try:
        lines = Path(path).read_text().splitlines()
    except FileNotFoundError:
        return 0
    return sum(json.loads(line).get("index") is not None for line in lines if line.strip())


def run(pid, duration, output, count):
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
    attacks = existing_attack_count(output)

    def request_stop(signum, frame):
        nonlocal stopping
        stopping = True

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
        print(f"ARMED pid={pid}: recording {count} melee attacks to {output}; no memory writes.", flush=True)
        started = time.monotonic()
        while not stopping and attacks < count and time.monotonic() - started < duration:
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
                raise RuntimeError("Trap did not belong to the RNG dataset recorder.")
            slot = targets[registers.rip]
            if slot == 1:
                actor = reader.qword(root)
                if actor:
                    before, state_error = read_state(reader, context_root)
                    pending = {
                        "selector_timestamp": time.time(),
                        "action": reader.unpack("<i", actor + character.number(
                            PROFILE["polearm_attacks"]["temporary_action_offset"]
                        ))[0],
                        "pre_state": before.hex() if before is not None else None,
                        "pre_words": state_words(before) if before is not None else None,
                        "predicted_rolls": model.rng_rolls(before)[0] if before is not None else None,
                    }
                    if state_error is not None:
                        pending["state_error"] = state_error
            else:
                packet = registers.rcx
                opcode = reader.unpack("<I", packet + 0x434)[0]
                if opcode == MELEE_OPCODE:
                    length = reader.unpack("<I", packet + 0x428)[0]
                    if not 2 <= length <= 4096:
                        raise RuntimeError(f"Invalid melee packet length {length}.")
                    body = reader.read(packet + 8, length)
                    damage = struct.unpack_from("<i", body, DAMAGE_OFFSET)[0] if len(body) >= DAMAGE_OFFSET + 4 else None
                    after, state_error = read_state(reader, context_root)
                    selector = pending
                    pending = None
                    record = {
                        "index": attacks, "pid": pid, "module_base": hex(base),
                        "packet_timestamp": time.time(), "length": length,
                        "damage": damage,
                        "body": body.hex(),
                        "post_state": after.hex() if after is not None else None,
                        "post_words": state_words(after) if after is not None else None,
                    }
                    if selector is not None:
                        record.update(selector)
                    else:
                        record.update({
                            "selector_timestamp": None, "action": None,
                            "pre_state": None, "pre_words": None, "predicted_rolls": None,
                        })
                    if state_error is not None:
                        record["state_error"] = state_error
                    if selector is not None and selector["pre_state"] is not None and after is not None:
                        analysis = model.analyze_rng(selector["pre_state"], after.hex())
                        record["eleven_step_match"] = analysis["eleven_step_match"]
                        record["matching_transitions"] = analysis["matching_transitions"]
                    else:
                        record["eleven_step_match"] = None
                        record["matching_transitions"] = None
                    stream.write(json.dumps(record, separators=(",", ":")) + "\n")
                    stream.flush()
                    attacks += 1
                    print(
                        f"ATTACK {attacks}/{count} damage={record['damage']} "
                        f"state_match={record['eleven_step_match']} "
                        f"transitions={record['matching_transitions']}", flush=True,
                    )
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
        print(f"WROTE {output}: attacks={attacks}", flush=True)
        if cleanup_error is not None:
            raise cleanup_error
    if attacks < count:
        raise RuntimeError(f"Captured only {attacks} of {count} attacks; partial JSONL was saved.")


def main():
    if len(sys.argv) not in (4, 5):
        raise SystemExit("Usage: rng-dataset.py PID|auto SECONDS OUT.jsonl [COUNT]")
    duration = float(sys.argv[2])
    if not 1 <= duration <= 3600:
        raise SystemExit("Use a capture duration from 1 to 3600 seconds.")
    count = int(sys.argv[4]) if len(sys.argv) == 5 else 100
    if not 1 <= count <= 1000:
        raise SystemExit("Use an attack count from 1 to 1000.")
    pid = character.find_pid(PROFILE["process_name"]) if sys.argv[1] == "auto" else int(sys.argv[1])
    run(pid, duration, sys.argv[3], count)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, struct.error) as error:
        print(f"RNG dataset capture failed: {error}", file=sys.stderr)
        sys.exit(1)
