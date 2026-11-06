"""Test native, unchanged, and maximum damage rolls on three melee attacks."""

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


observer = load("reset_observer", DIRECTORY / "observe-position-reset.py")
shared = load("attack_observer", DIRECTORY / "overhead-attacks.py")
character = observer.character
PROFILE = json.loads((DIRECTORY / "profile.json").read_text())
SENDPACKET_RVA = 0x1661780
DAMAGE_ROLL_RVA = 0x2AC9A9
DAMAGE_ROLL_INSTRUCTION = bytes.fromhex("660f2fd1")
MELEE_OPCODE = 0xE1
DAMAGE_OFFSET = 0x88


def replacement_roll(stage, original):
    if stage == "unchanged":
        return original
    if stage == "override":
        return 0xFFFFFFFF
    return None


def run(pid, duration, output):
    reader = character.Reader(pid)
    base, _ = character.find_image(reader, pid, PROFILE)
    if reader.read(base + DAMAGE_ROLL_RVA, len(DAMAGE_ROLL_INSTRUCTION)) != DAMAGE_ROLL_INSTRUCTION:
        raise RuntimeError("Damage-roll instruction differs from the researched build.")
    targets = {base + SENDPACKET_RVA: 0, base + DAMAGE_ROLL_RVA: 1}
    attached = stopped = False
    saved = None
    deliver = 0
    stopping = False
    complete = False
    stage = "native"
    done = {name: False for name in ("native", "unchanged", "override")}
    roll_events = []
    packets = []

    def request_stop(signum, frame):
        nonlocal stopping
        stopping = True

    handlers = {number: signal.signal(number, request_stop) for number in (signal.SIGINT, signal.SIGTERM)}
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
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
        print(
            f"ARMED pid={pid}: attack the same mob three times: native, unchanged roll, maximum roll. "
            "Record all three displayed damage values.",
            flush=True,
        )
        started = time.monotonic()
        while not stopping and not complete and time.monotonic() - started < duration:
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
                raise RuntimeError("Trap did not belong to the damage-roll experiment.")
            slot = targets[registers.rip]
            if slot == 1:
                if not done[stage]:
                    original = registers.rdx & 0xFFFFFFFF
                    replacement = replacement_roll(stage, original)
                    event = {
                        "stage": stage, "timestamp": time.time(),
                        "original": original, "replacement": replacement,
                    }
                    if replacement is not None:
                        registers.rdx = replacement
                        observer.ptrace(pid, 13, 0, ctypes.addressof(registers))
                        check = observer.Registers()
                        observer.ptrace(pid, 12, 0, ctypes.addressof(check))
                        if bytes(check) != bytes(registers):
                            raise RuntimeError("Damage-roll register update did not read back exactly.")
                        event["readback"] = check.rdx & 0xFFFFFFFF
                    roll_events.append(event)
                    done[stage] = True
                    replacement_text = hex(replacement) if replacement is not None else None
                    print(
                        f"ROLL stage={stage} original={original:#x} replacement={replacement_text}",
                        flush=True,
                    )
            else:
                packet = registers.rcx
                opcode = reader.unpack("<I", packet + 0x434)[0]
                if opcode == MELEE_OPCODE:
                    length = reader.unpack("<I", packet + 0x428)[0]
                    if not DAMAGE_OFFSET + 4 <= length <= 4096:
                        raise RuntimeError(f"Invalid melee packet length {length}.")
                    body = reader.read(packet + 8, length)
                    damage = struct.unpack_from("<i", body, DAMAGE_OFFSET)[0]
                    packets.append({
                        "stage": stage, "timestamp": time.time(),
                        "damage": damage, "roll_observed": done[stage],
                    })
                    print(f"PACKET stage={stage} damage={damage}", flush=True)
                    if stage == "native":
                        stage = "unchanged"
                        print("Attack the same mob again for the unchanged-write control.", flush=True)
                    elif stage == "unchanged":
                        if not done[stage]:
                            raise RuntimeError("Unchanged-control packet arrived before its roll observation.")
                        stage = "override"
                        print("Attack the same mob again for the maximum-roll test.", flush=True)
                    else:
                        if not done[stage]:
                            raise RuntimeError("Override packet arrived before its roll modification.")
                        complete = True
            observer.ptrace(pid, 6, 848 + 6 * 8, 0)
            observer.ptrace(pid, 7)
            stopped = False
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
                print("DETACHED: original debug registers restored.", flush=True)
            except (OSError, RuntimeError) as error:
                cleanup_error = error
                print(f"DETACH incomplete: {error}", file=sys.stderr, flush=True)
        result = {
            "pid": pid, "module_base": hex(base), "complete": complete,
            "roll_events": roll_events, "packets": packets,
            "visual_confirmation_required": "Compare all three displayed results; packet damage alone does not prove server acceptance.",
        }
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(result, stream, indent=1)
        reader.close()
        for number, handler in handlers.items():
            signal.signal(number, handler)
        print(f"WROTE {output}: packets={len(packets)} roll_events={len(roll_events)}", flush=True)
        if cleanup_error is not None:
            raise cleanup_error
    if not complete:
        raise RuntimeError("Three melee attacks were not completed; partial results were saved.")


def main():
    if len(sys.argv) != 4:
        raise SystemExit("Usage: rng-damage-override.py PID SECONDS OUT.json")
    duration = float(sys.argv[2])
    if not 1 <= duration <= 600:
        raise SystemExit("Use a capture duration from 1 to 600 seconds.")
    run(int(sys.argv[1]), duration, sys.argv[3])


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError) as error:
        print(f"Damage-roll experiment failed: {error}", file=sys.stderr)
        sys.exit(1)
