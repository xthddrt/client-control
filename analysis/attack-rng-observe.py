"""Correlate sword melee packets, damage, and pre/post-attack memory snapshots."""

import ctypes
import hashlib
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
TOOLS = DIRECTORY.parent / "tools"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


observer = load("reset_observer", FOUNDATIONS / "observe-position-reset.py")
shared = load("attack_observer", TOOLS / "overhead-attacks.py")
character = observer.character
PROFILE = json.loads((FOUNDATIONS / "profile.json").read_text())
SENDPACKET_RVA = 0x1661780
SELECTOR_RVA = character.number(PROFILE["polearm_attacks"]["selector_rva"])
ROLL_SCALER_RVA = character.number(PROFILE["incoming_display"]["range_sampler_rva"])
MELEE_DAMAGE_RETURN_RVA = 0x2AD633
RNG_CORE_RVA = character.number(PROFILE["incoming_display"]["rng_core_rva"])
MELEE_OPCODE = 0xE1
DAMAGE_OFFSET = 0x88


def memory_state(reader, root, context_root):
    actor = reader.qword(root)
    context = reader.qword(context_root)
    state = {"actor": hex(actor), "context": hex(context), "regions": {}}
    if actor:
        state["regions"]["actor"] = reader.read(actor, 0x2000).hex()
    if context:
        state["regions"]["context"] = reader.read(context, 0x3000).hex()
        for name, offset in (("stats_2350", 0x2350), ("stats_2998", 0x2998)):
            pointer = reader.qword(context + offset)
            state[name] = hex(pointer)
            if pointer:
                state["regions"][name] = reader.read(pointer, 0x400).hex()
    return state


def changed_runs(before, after):
    if before is None or after is None:
        return None
    left = bytes.fromhex(before)
    right = bytes.fromhex(after)
    if len(left) != len(right):
        raise RuntimeError("Memory snapshot size changed.")
    offsets = [index for index, (a, b) in enumerate(zip(left, right)) if a != b]
    runs = []
    for offset in offsets:
        if runs and offset == runs[-1][1] + 1:
            runs[-1][1] = offset
        else:
            runs.append([offset, offset])
    return [
        {"offset": start, "before": left[start:end + 1].hex(), "after": right[start:end + 1].hex()}
        for start, end in runs[:256]
    ]


RNG_WORD_OFFSETS = (0, 4, 8, 0x20, 0x24, 0x28)


def rng_rolls(state, count=11):
    current = bytearray(state[:0x2C])
    if len(current) != 0x2C:
        raise ValueError("RNG state must contain at least 44 bytes.")
    rolls = []
    for _ in range(count):
        first = struct.unpack_from("<I", current, 0)[0]
        second = struct.unpack_from("<I", current, 8)[0]
        third = struct.unpack_from("<I", current, 0x24)[0]
        next_first = (
            (((first >> 8) ^ ((first << 17) & 0xFFFFFFFF)) & 0x1FFFFF)
            ^ ((first << 17) & 0xFFFFFFFF) ^ (first >> 11)
        ) & 0xFFFFFFFF
        next_second = (
            (((second >> 23) ^ ((second << 4) & 0xFFFFFFFF)) & 0x7F)
            ^ (second >> 25) ^ ((second << 4) & 0xFFFFFFFF)
        ) & 0xFFFFFFFF
        next_third = (
            ((((third << 12) & 0xFFFFFFFF) ^ (third >> 6)) & 0x1FFF)
            ^ (third >> 19) ^ ((third << 12) & 0xFFFFFFFF)
        ) & 0xFFFFFFFF
        roll = next_first ^ next_second ^ next_third
        struct.pack_into("<I", current, 0, next_first)
        struct.pack_into("<I", current, 4, second)
        struct.pack_into("<I", current, 8, next_second)
        struct.pack_into("<I", current, 0x20, first)
        struct.pack_into("<I", current, 0x24, next_third)
        struct.pack_into("<I", current, 0x28, third)
        rolls.append(roll)
    return rolls, current


def analyze_rng(before, after):
    if before is None or after is None:
        return None
    initial = bytes.fromhex(before)
    observed = bytes.fromhex(after)
    result = {"matching_transitions": None}
    current = initial
    for count in range(1, 33):
        rolls, current = rng_rolls(current, 1)
        if all(struct.unpack_from("<I", current, offset)[0] == struct.unpack_from("<I", observed, offset)[0]
               for offset in RNG_WORD_OFFSETS):
            result["matching_transitions"] = count
            break
    rolls, predicted = rng_rolls(initial)
    result.update({
        "eleven_step_match": all(struct.unpack_from("<I", predicted, offset)[0] == struct.unpack_from("<I", observed, offset)[0]
                                 for offset in RNG_WORD_OFFSETS),
        "predicted_rolls": rolls,
        "damage_multipliers": [0.1 + (roll / 2**32) * 1.1 for roll in rolls],
        "predicted_state": predicted.hex(),
        "observed_state": observed[:0x2C].hex(),
    })
    return result


def run(pid, duration, output):
    reader = character.Reader(pid)
    base, _ = character.find_image(reader, pid, PROFILE)
    shared.verify_code(reader, base, PROFILE["polearm_attacks"])
    scaler = PROFILE["incoming_display"]
    scaler_code = reader.read(base + ROLL_SCALER_RVA, character.number(scaler["range_sampler_size"]))
    if hashlib.sha256(scaler_code).hexdigest() != scaler["range_sampler_sha256"]:
        raise RuntimeError("Roll scaler differs from the researched build.")
    core_code = reader.read(base + RNG_CORE_RVA, character.number(scaler["rng_core_size"]))
    if hashlib.sha256(core_code).hexdigest() != scaler["rng_core_sha256"]:
        raise RuntimeError("RNG core differs from the researched build.")
    root = base + character.number(PROFILE["rvas"]["character_global"])
    context_root = base + character.number(scaler["calculator_context_global_rva"])
    targets = {
        base + SENDPACKET_RVA: 0, base + SELECTOR_RVA: 1,
        base + ROLL_SCALER_RVA: 2, base + RNG_CORE_RVA: 3,
    }
    attached = stopped = False
    saved = None
    deliver = 0
    stopping = False
    pending = []
    attacks = []
    roll_observations = []
    histogram = {}
    started = time.monotonic()

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
            for slot in (0, 1, 2, 3, 6, 7)
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
        print(f"ARMED pid={pid}: selector and melee capture for {duration}s; no memory writes.", flush=True)
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
                raise RuntimeError("Trap did not belong to the RNG observer.")
            slot = targets[registers.rip]
            if slot == 1:
                actor = reader.qword(root)
                if actor:
                    memory = memory_state(reader, root, context_root)
                    predicted_rolls, _ = rng_rolls(bytes.fromhex(memory["regions"]["stats_2998"]))
                    pending.append({
                        "timestamp": time.time(),
                        "action": reader.unpack("<i", actor + character.number(
                            PROFILE["polearm_attacks"]["temporary_action_offset"]
                        ))[0],
                        "memory": memory,
                        "predicted_rolls": predicted_rolls,
                        "damage_multipliers": [0.1 + (roll / 2**32) * 1.1 for roll in predicted_rolls],
                    })
                    print(f"PREDICT next_11={[hex(roll) for roll in predicted_rolls]}", flush=True)
                    if len(pending) > 32:
                        raise RuntimeError("Too many unmatched attack selectors.")
            elif slot == 2:
                counter = registers.r12 & 0xFFFFFFFF
                caller_rva = reader.qword(registers.rsp) - base
                event = {
                    "kind": "scaler", "timestamp": time.time(),
                    "caller_rva": hex(caller_rva),
                    "counter_r12": counter,
                    "roll": registers.rcx & 0xFFFFFFFF,
                }
                if caller_rva == MELEE_DAMAGE_RETURN_RVA:
                    event["roll_index"] = counter % 11
                roll_observations.append(event)
                if len(roll_observations) > 1000:
                    raise RuntimeError("Roll capture exceeded 1000 unmatched events.")
            elif slot == 3:
                context = reader.qword(context_root)
                stats = reader.qword(context + 0x2998) if context else 0
                if registers.rcx == stats:
                    roll_observations.append({
                        "kind": "rng_core", "timestamp": time.time(),
                        "caller_rva": hex(reader.qword(registers.rsp) - base),
                        "rng_address": hex(registers.rcx),
                        "state_before": reader.read(registers.rcx, 0x2C).hex(),
                    })
                    if len(roll_observations) > 1000:
                        raise RuntimeError("Roll capture exceeded 1000 unmatched events.")
            else:
                packet = registers.rcx
                opcode = reader.unpack("<I", packet + 0x434)[0]
                histogram[opcode] = histogram.get(opcode, 0) + 1
                if opcode == MELEE_OPCODE:
                    length = reader.unpack("<I", packet + 0x428)[0]
                    if not 2 <= length <= 4096:
                        raise RuntimeError(f"Invalid melee packet length {length}.")
                    body = reader.read(packet + 8, length)
                    if len(body) < DAMAGE_OFFSET + 4:
                        raise RuntimeError("Melee packet is shorter than the damage field.")
                    before = pending.pop() if pending else None
                    pending.clear()
                    after = memory_state(reader, root, context_root)
                    changes = None
                    rng = None
                    if before is not None:
                        changes = {
                            name: changed_runs(before["memory"]["regions"].get(name), after["regions"].get(name))
                            for name in after["regions"]
                        }
                        rng = analyze_rng(
                            before["memory"]["regions"].get("stats_2998"),
                            after["regions"].get("stats_2998"),
                        )
                        for event in roll_observations:
                            if event["kind"] == "rng_core":
                                event["prediction_match"] = (
                                    character.number(event["rng_address"]) == character.number(before["memory"]["stats_2998"])
                                )
                            else:
                                matches = [index for index, roll in enumerate(before["predicted_rolls"]) if roll == event["roll"]]
                                event["predicted_indices"] = matches
                                event["prediction_match"] = bool(matches)
                                if event.get("roll_index") is not None:
                                    event["predicted_roll"] = before["predicted_rolls"][event["roll_index"]]
                    attack = {
                        "index": len(attacks), "timestamp": time.time(),
                        "length": length, "body": body.hex(),
                        "damage": struct.unpack_from("<i", body, DAMAGE_OFFSET)[0],
                        "selector": before, "post_memory": after, "changes": changes,
                        "rng": rng, "roll_observations": roll_observations,
                    }
                    roll_observations = []
                    attacks.append(attack)
                    print(
                        f"ATTACK {len(attacks)} damage={attack['damage']} "
                        f"paired_selector={before is not None} bytes={length} "
                        f"rng_11_step_match={rng and rng['eleven_step_match']} "
                        f"rng_transitions={rng and rng['matching_transitions']} "
                        f"roll_sites={[event.get('caller_rva', event['kind']) for event in attack['roll_observations']]} "
                        f"roll_matches={[event.get('prediction_match') for event in attack['roll_observations']]}", flush=True,
                    )
                    if len(attacks) >= 1000:
                        raise RuntimeError("Attack capture exceeded its 1000-event limit.")
            observer.ptrace(pid, 6, 848 + 6 * 8, 0)
            observer.ptrace(pid, 7)
            stopped = False
    finally:
        if attached:
            if not stopped:
                observer.ptrace(pid, 0x4207)
                state = observer.wait_stop(pid, 1)
                deliver = shared.pending_signal(pid, state, targets)
            if saved is not None:
                for slot in (7, 0, 1, 2, 3, 6):
                    observer.ptrace(pid, 6, 848 + slot * 8, saved[slot])
            observer.ptrace(pid, 17, 0, deliver)
            print("DETACHED: original debug registers restored; no memory writes.", flush=True)
        result = {
            "pid": pid, "module_base": hex(base), "observation_only": True,
            "damage_evidence": "Outgoing melee body offset 0x88, previously matched to displayed sword damage.",
            "memory_regions": {
                "actor": "0x2000 bytes", "context": "0x3000 bytes",
                "stats_2350": "0x400 bytes", "stats_2998": "0x400 bytes",
            },
            "attacks": attacks, "unmatched_selectors": pending,
            "unmatched_roll_observations": roll_observations,
            "packet_histogram": {hex(key): value for key, value in histogram.items()},
        }
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(result, stream, indent=1)
        reader.close()
        for number, handler in handlers.items():
            signal.signal(number, handler)
        print(f"WROTE {output}: attacks={len(attacks)} unmatched_selectors={len(pending)}", flush=True)


def main():
    if len(sys.argv) != 4:
        raise SystemExit("Usage: attack-rng-observe.py PID SECONDS OUT.json")
    duration = float(sys.argv[2])
    if not 1 <= duration <= 600:
        raise SystemExit("Use a capture duration from 1 to 600 seconds.")
    run(int(sys.argv[1]), duration, sys.argv[3])


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError) as error:
        print(f"RNG observation failed: {error}", file=sys.stderr)
        sys.exit(1)
