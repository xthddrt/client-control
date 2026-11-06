"""Identify code that writes the attack-correlated candidate RNG words."""

import ctypes
import importlib.util
import json
import os
from pathlib import Path
import signal
import sys
import time


DIRECTORY = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("attack_observer", DIRECTORY / "overhead-attacks.py")
shared = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(shared)
observer = shared.observer
character = shared.character
PROFILE = json.loads((DIRECTORY / "profile.json").read_text())


def fired_watchpoint_slots(dr6, slots=(0, 1)):
    return [slot for slot in slots if dr6 & (1 << slot)]


def run(pid, duration, output):
    reader = character.Reader(pid)
    base, _ = character.find_image(reader, pid, PROFILE)
    context = reader.qword(base + character.number(PROFILE["incoming_display"]["calculator_context_global_rva"]))
    stats = reader.qword(context + 0x2998)
    if not stats:
        raise RuntimeError("No candidate state context.")
    targets = {stats: 0, stats + 0x20: 1}
    attached = stopped = False
    saved = None
    deliver = 0
    stopping = False
    events = []

    def request_stop(signum, frame):
        nonlocal stopping
        stopping = True

    handlers = {number: signal.signal(number, request_stop) for number in (signal.SIGINT, signal.SIGTERM)}
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        observer.ptrace(pid, 0x4206)
        attached = True
        observer.ptrace(pid, 0x4207)
        state = observer.wait_stop(pid, 1)
        stopped = True
        deliver = shared.pending_signal(pid, state)
        saved = {
            slot: observer.ptrace(pid, 3, 848 + slot * 8) & 0xFFFFFFFFFFFFFFFF
            for slot in (0, 1, 6, 7)
        }
        control = saved[7]
        for address, slot in targets.items():
            if control & (3 << (slot * 2)):
                raise RuntimeError(f"Hardware watchpoint slot {slot} is occupied.")
            observer.ptrace(pid, 6, 848 + slot * 8, address)
            control = (
                control & ~((0xF << (16 + slot * 4)) | (3 << (slot * 2)))
            ) | (1 << (slot * 2)) | (1 << (16 + slot * 4)) | (3 << (18 + slot * 4))
        observer.ptrace(pid, 6, 848 + 7 * 8, control)
        observer.ptrace(pid, 7, 0, deliver)
        deliver = 0
        stopped = False
        print(f"ARMED pid={pid}: watching {stats:#x} and {stats + 0x20:#x} for four-byte writes.", flush=True)
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
            dr6 = observer.ptrace(pid, 3, 848 + 6 * 8)
            fired = fired_watchpoint_slots(dr6, targets.values())
            if len(fired) != 1:
                deliver = number
                raise RuntimeError("Trap did not belong to exactly one RNG write watchpoint.")
            slot = fired[0]
            registers = observer.Registers()
            observer.ptrace(pid, 12, 0, ctypes.addressof(registers))
            event = {
                "timestamp": time.time(),
                "slot": slot,
                "watched_address": hex(stats + slot * 0x20),
                "rip_after_write": hex(registers.rip),
                "rva_after_write": hex(registers.rip - base),
                "code_before": reader.read(registers.rip - 15, 15).hex(),
                "registers": {
                    name: hex(getattr(registers, name))
                    for name in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rbp", "rsp")
                },
                "state": reader.read(stats, 0x30).hex(),
                "stack": reader.read(registers.rsp, 0x40).hex(),
            }
            events.append(event)
            print(f"WRITE slot={slot} rip_after={event['rva_after_write']} state={event['state']}", flush=True)
            if len(events) >= 100:
                raise RuntimeError("Write-watch capture exceeded 100 events.")
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
                    deliver = shared.pending_signal(pid, state)
                    if os.WSTOPSIG(state) == signal.SIGTRAP:
                        dr6 = observer.ptrace(pid, 3, 848 + 6 * 8)
                        if len(fired_watchpoint_slots(dr6, targets.values())) == 1:
                            deliver = 0
                if saved is not None:
                    for slot in (7, 0, 1, 6):
                        observer.ptrace(pid, 6, 848 + slot * 8, saved[slot])
                observer.ptrace(pid, 17, 0, deliver)
                print("DETACHED: original debug registers restored; no memory writes.", flush=True)
            except (OSError, RuntimeError) as error:
                cleanup_error = error
                print(f"DETACH incomplete: {error}", file=sys.stderr, flush=True)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump({"pid": pid, "stats": hex(stats), "events": events}, stream, indent=1)
        reader.close()
        for number, handler in handlers.items():
            signal.signal(number, handler)
        print(f"WROTE {output}: events={len(events)}", flush=True)
        if cleanup_error is not None:
            raise cleanup_error


if __name__ == "__main__":
    try:
        if len(sys.argv) != 4:
            raise SystemExit("Usage: rng-write-watch.py PID SECONDS OUT.json")
        run(int(sys.argv[1]), float(sys.argv[2]), sys.argv[3])
    except (OSError, RuntimeError, ValueError) as error:
        print(f"RNG write observation failed: {error}", file=sys.stderr)
        sys.exit(1)
