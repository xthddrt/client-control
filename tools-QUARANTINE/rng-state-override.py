"""Test native, unchanged, and repeatedly replayed RNG state words on melee attacks."""

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
REPLAY_WORDS = (0x0C2418D6, 0xCDF84FE7, 0x5E613E0A)


class Iov(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("length", ctypes.c_size_t)]


libc = ctypes.CDLL(None, use_errno=True)
libc.process_vm_writev.restype = ctypes.c_ssize_t


def write_memory(pid, address, data):
    data = bytes(data)
    buffer = ctypes.create_string_buffer(data, len(data))
    local = Iov(ctypes.cast(buffer, ctypes.c_void_p), len(data))
    remote = Iov(address, len(data))
    if libc.process_vm_writev(pid, ctypes.byref(local), 1, ctypes.byref(remote), 1, 0) != len(data):
        raise OSError(ctypes.get_errno(), "process_vm_writev failed")


def state_for_stage(stage, original, replay_words=REPLAY_WORDS):
    if stage == "unchanged":
        return bytes(original)
    if stage == "override":
        modified = bytearray(original)
        for offset, value in zip((0, 8, 0x24), replay_words):
            struct.pack_into("<I", modified, offset, value)
        return bytes(modified)
    return None


def state_words(state):
    return [struct.unpack_from("<I", state, offset)[0] for offset in (0, 8, 0x24)]


def run(pid, duration, output, replays=1, replay_words=REPLAY_WORDS):
    reader = character.Reader(pid)
    base, _ = character.find_image(reader, pid, PROFILE)
    shared.verify_code(reader, base, PROFILE["polearm_attacks"])
    context_root = base + character.number(PROFILE["incoming_display"]["calculator_context_global_rva"])
    targets = {base + SENDPACKET_RVA: 0, base + SELECTOR_RVA: 1}
    attached = stopped = False
    saved = None
    deliver = 0
    stopping = False
    complete = False
    stage = "native"
    done = {name: False for name in ("native", "unchanged", "override")}
    state_events = []
    packets = []
    restore_pending = False
    override_original = None
    override_stats = None

    def request_stop(signum, frame):
        nonlocal stopping
        stopping = True

    def restore_override():
        nonlocal restore_pending
        if restore_pending:
            write_memory(pid, override_stats, override_original)
            if reader.read(override_stats, 0x2C) != override_original:
                raise RuntimeError("Original RNG state did not restore exactly.")
            restore_pending = False
            print("RESTORED: complete original RNG object read back exactly.", flush=True)

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
            f"ARMED pid={pid}: attack the same mob with native state, unchanged state, then "
            f"replayed state {replays} time(s). Record every displayed damage value.",
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
                raise RuntimeError("Trap did not belong to the RNG-state experiment.")
            slot = targets[registers.rip]
            if slot == 1:
                if not done[stage]:
                    context = reader.qword(context_root)
                    stats = reader.qword(context + 0x2998) if context else 0
                    if not stats:
                        raise RuntimeError("No RNG state context.")
                    original = reader.read(stats, 0x2C)
                    if original[0x10:0x1C] != bytes(12):
                        raise RuntimeError("RNG object is locked; refusing a concurrent state write.")
                    modified = state_for_stage(stage, original, replay_words)
                    event = {
                        "stage": stage, "timestamp": time.time(), "stats": hex(stats),
                        "original_words": state_words(original), "original_state": original.hex(),
                        "predicted_next_roll": model.rng_rolls(original, 1)[0][0],
                    }
                    if modified is not None:
                        write_memory(pid, stats, modified)
                        readback = reader.read(stats, 0x2C)
                        if readback != modified:
                            raise RuntimeError("RNG state write did not read back exactly.")
                        event["modified_words"] = state_words(modified)
                        event["readback_state"] = readback.hex()
                        event["modified_next_roll"] = model.rng_rolls(modified, 1)[0][0]
                        if stage == "override":
                            override_original = original
                            override_stats = stats
                            restore_pending = True
                    state_events.append(event)
                    done[stage] = True
                    print(
                        f"STATE stage={stage} original={[hex(word) for word in event['original_words']]} "
                        f"modified={event.get('modified_words') and [hex(word) for word in event['modified_words']]}",
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
                        "damage": damage, "state_observed": done[stage],
                    })
                    print(f"PACKET stage={stage} damage={damage}", flush=True)
                    if not done[stage]:
                        raise RuntimeError(f"{stage} packet arrived before its state observation.")
                    if stage == "native":
                        stage = "unchanged"
                        print("Attack the same mob again for the unchanged-state control.", flush=True)
                    elif stage == "unchanged":
                        stage = "override"
                        print("Attack the same mob again for the replayed-state test.", flush=True)
                    else:
                        restore_override()
                        completed_replays = sum(packet["stage"] == "override" for packet in packets)
                        if completed_replays >= replays:
                            complete = True
                        else:
                            done["override"] = False
                            print(f"Attack the same mob again for replay {completed_replays + 1} of {replays}.", flush=True)
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
                try:
                    restore_override()
                finally:
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
            "state_restored": not restore_pending, "replays_requested": replays,
            "replay_words": list(replay_words),
            "state_events": state_events, "packets": packets,
            "visual_confirmation_required": "Compare every displayed result; packet damage alone does not prove server acceptance.",
        }
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(result, stream, indent=1)
        reader.close()
        for number, handler in handlers.items():
            signal.signal(number, handler)
        print(f"WROTE {output}: packets={len(packets)} state_events={len(state_events)}", flush=True)
        if cleanup_error is not None:
            raise cleanup_error
    if not complete:
        raise RuntimeError(f"Only {len(packets)} of {replays + 2} melee attacks completed; partial results were saved.")


def main():
    if len(sys.argv) not in (4, 5, 8):
        raise SystemExit("Usage: rng-state-override.py PID|auto SECONDS OUT.json [REPLAYS [WORD0 WORD1 WORD2]]")
    duration = float(sys.argv[2])
    if not 1 <= duration <= 600:
        raise SystemExit("Use a capture duration from 1 to 600 seconds.")
    replays = int(sys.argv[4]) if len(sys.argv) >= 5 else 1
    if not 1 <= replays <= 10:
        raise SystemExit("Use 1 to 10 replay attacks.")
    replay_words = tuple(int(value, 0) for value in sys.argv[5:8]) if len(sys.argv) == 8 else REPLAY_WORDS
    if any(not 0 <= value <= 0xFFFFFFFF for value in replay_words):
        raise SystemExit("Replay state words must be 32-bit integers.")
    pid = character.find_pid(PROFILE["process_name"]) if sys.argv[1] == "auto" else int(sys.argv[1])
    run(pid, duration, sys.argv[3], replays, replay_words)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError) as error:
        print(f"RNG-state experiment failed: {error}", file=sys.stderr)
        sys.exit(1)
