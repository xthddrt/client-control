"""Test one 0x32b field override with native control and post-send restoration."""

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
experiment = load("rng_state_override", DIRECTORY / "rng-state-override.py")
observer = model.observer
shared = model.shared
character = model.character
PROFILE = model.PROFILE
SENDPACKET_RVA = 0x1661780
FOCUS_OPCODE = 0x32B


def run(pid, duration, output, offset, size, value):
    if not 0 <= value < 1 << (size * 8):
        raise ValueError("Override value does not fit the selected field size.")
    reader = character.Reader(pid)
    base, _ = character.find_image(reader, pid, PROFILE)
    targets = {base + SENDPACKET_RVA: 0}
    attached = stopped = False
    saved = None
    deliver = 0
    stopping = False
    complete = False
    events = []
    original_field = None
    restore_pending = False

    def request_stop(signum, frame):
        nonlocal stopping
        stopping = True

    def restore_original():
        nonlocal restore_pending
        if restore_pending:
            experiment.write_memory(pid, restore_address, original_field)
            if reader.read(restore_address, size) != original_field:
                raise RuntimeError("Original field did not restore exactly.")
            restore_pending = False
            print("RESTORED: original field bytes read back exactly.", flush=True)

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
        if control & 3:
            raise RuntimeError("Hardware breakpoint slot 0 is occupied.")
        if control & (3 << 2):
            raise RuntimeError("Hardware breakpoint slot 1 is occupied.")
        observer.ptrace(pid, 6, 848, base + SENDPACKET_RVA)
        control = (control & ~0xF0003) | 1
        observer.ptrace(pid, 6, 848 + 7 * 8, control)
        observer.ptrace(pid, 7, 0, deliver)
        deliver = 0
        stopped = False
        print(f"ARMED pid={pid}: first 0x32b native, second overrides offset {offset:#x} size {size} to {value:#x}.", flush=True)
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
                raise RuntimeError("Trap did not belong to the 0x32b override experiment.")
            if targets[registers.rip] == 1:
                restore_original()
                complete = True
                stopped = False
                break
            packet = registers.rcx
            opcode = reader.unpack("<I", packet + 0x434)[0]
            if opcode != FOCUS_OPCODE:
                observer.ptrace(pid, 6, 848 + 6 * 8, 0)
                observer.ptrace(pid, 7)
                stopped = False
                continue
            length = reader.unpack("<I", packet + 0x428)[0]
            if not offset + size <= length <= 16 * 1024 * 1024:
                raise RuntimeError(f"Invalid packet length {length} for field offset {offset:#x}.")
            body = reader.read(packet + 8, length)
            event = {
                "timestamp": time.time(), "opcode": hex(opcode), "length": length,
                "body": body.hex(), "caller_rva": hex(reader.qword(registers.rsp) - base),
                "packet_va": hex(packet), "body_va": hex(packet + 8),
            }
            if not events:
                event["stage"] = "native"
                events.append(event)
                print("NATIVE 0x32b captured; next 0x32b will be modified.", flush=True)
            else:
                original_field = body[offset:offset + size]
                modified_field = value.to_bytes(size, "little")
                restore_address = packet + 8 + offset
                experiment.write_memory(pid, restore_address, modified_field)
                if reader.read(restore_address, size) != modified_field:
                    raise RuntimeError("Override field did not read back exactly.")
                restore_pending = True
                event.update({
                    "stage": "override", "offset": hex(offset), "size": size,
                    "original_field": original_field.hex(), "modified_field": modified_field.hex(),
                    "readback_field": modified_field.hex(),
                })
                return_rva = reader.qword(registers.rsp) - base
                targets[base + return_rva] = 1
                event["return_rva"] = hex(return_rva)
                observer.ptrace(pid, 6, 848 + 8, base + return_rva)
                control = (control & ~(0xF << 4)) | (1 << 2)
                observer.ptrace(pid, 6, 848 + 7 * 8, control)
                events.append(event)
                print(f"OVERRIDE wrote {modified_field.hex()} at {offset:#x}; restoring after SendPacket returns.", flush=True)
            observer.ptrace(pid, 6, 848 + 6 * 8, 0)
            observer.ptrace(pid, 7)
            stopped = False
    except (OSError, RuntimeError, ValueError, struct.error) as error:
        events.append({"fatal_error": str(error)})
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
                    restore_original()
                finally:
                    if saved is not None:
                        for slot in (7, 0, 1, 6):
                            observer.ptrace(pid, 6, 848 + slot * 8, saved[slot])
                    observer.ptrace(pid, 17, 0, deliver)
                print("DETACHED: original debug registers restored.", flush=True)
            except (OSError, RuntimeError) as error:
                cleanup_error = error
                print(f"DETACH incomplete: {error}", file=sys.stderr, flush=True)
        result = {"pid": pid, "complete": complete, "restored": not restore_pending, "events": events}
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(result, stream, indent=1)
        reader.close()
        for number, handler in handlers.items():
            signal.signal(number, handler)
        print(f"WROTE {output}: events={len(events)} complete={complete}", flush=True)
        if cleanup_error is not None:
            raise cleanup_error
    if not complete:
        raise RuntimeError("Native and override packets were not both captured; partial results were saved.")


def main():
    if len(sys.argv) != 7:
        raise SystemExit("Usage: alter-observe.py PID|auto SECONDS OUT.json OFFSET SIZE VALUE")
    duration = float(sys.argv[2])
    if not 1 <= duration <= 3600:
        raise SystemExit("Use a capture duration from 1 to 3600 seconds.")
    offset = int(sys.argv[4], 0)
    size = int(sys.argv[5], 0)
    value = int(sys.argv[6], 0)
    if offset < 0:
        raise SystemExit("Field offset must be nonnegative.")
    if not 1 <= size <= 4:
        raise SystemExit("Field size must be 1 to 4 bytes.")
    pid = character.find_pid(PROFILE["process_name"]) if sys.argv[1] == "auto" else int(sys.argv[1])
    run(pid, duration, sys.argv[3], offset, size, value)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, struct.error) as error:
        print(f"0x32b override failed: {error}", file=sys.stderr)
        sys.exit(1)
