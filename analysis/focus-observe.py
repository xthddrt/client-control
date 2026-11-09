"""Capture only 0x32b and pickup candidates with full-memory diffs and caller tracing."""

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
memory_watch = load("memory_watch", FOUNDATIONS / "memory-watch.py")
observer = model.observer
shared = model.shared
character = model.character
PROFILE = model.PROFILE
SENDPACKET_RVA = 0x1661780
FOCUS_OPCODES = {0x32B, 0x407, 0x13B}


def run(pid, duration, output):
    reader = character.Reader(pid)
    base, _ = character.find_image(reader, pid, PROFILE)
    target = base + SENDPACKET_RVA
    targets = {target: 0}
    last_full_memory = memory_watch.snapshot(reader, pid)
    attached = stopped = False
    saved = None
    deliver = 0
    stopping = False
    events = 0

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
            for slot in (0, 6, 7)
        }
        if saved[7] & 3:
            raise RuntimeError("Hardware breakpoint slot 0 is occupied.")
        observer.ptrace(pid, 6, 848, target)
        control = (saved[7] & ~0xF0003) | 1
        observer.ptrace(pid, 6, 848 + 7 * 8, control)
        observer.ptrace(pid, 7, 0, deliver)
        deliver = 0
        stopped = False
        print(f"ARMED pid={pid}: focused 0x32b/pickup capture for {duration}s.", flush=True)
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
                raise RuntimeError("Trap did not belong to the focused observer.")
            packet = registers.rcx
            opcode = reader.unpack("<I", packet + 0x434)[0]
            if opcode not in FOCUS_OPCODES:
                observer.ptrace(pid, 6, 848 + 6 * 8, 0)
                observer.ptrace(pid, 7)
                stopped = False
                continue
            length = reader.unpack("<I", packet + 0x428)[0]
            if not 2 <= length <= 16 * 1024 * 1024:
                raise RuntimeError(f"Invalid packet length {length} for opcode {opcode:#x}.")
            body = reader.read(packet + 8, length)
            current = memory_watch.snapshot(reader, pid)
            record = {
                "index": events, "timestamp": time.time(), "pid": pid,
                "direction": "client_to_server", "opcode": hex(opcode),
                "length": length, "body": body.hex(),
                "caller_rva": hex(reader.qword(registers.rsp) - base),
                "packet_va": hex(packet), "body_va": hex(packet + 8),
                "return_stack_rvas": [hex(reader.qword(registers.rsp + index * 8) - base) for index in range(8)],
                "full_memory_diff": memory_watch.diff(last_full_memory, current),
            }
            events += 1
            stream.write(json.dumps(record, separators=(",", ":")) + "\n")
            stream.flush()
            last_full_memory = current
            print(f"EVENT {events} opcode={opcode:#x} length={length} changed_chunks={record['full_memory_diff']['changed_chunk_count']}", flush=True)
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
                    for slot in (7, 0, 6):
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
        print(f"WROTE {output}: focused_events={events}", flush=True)
        if cleanup_error is not None:
            raise cleanup_error


def main():
    if len(sys.argv) != 4:
        raise SystemExit("Usage: focus-observe.py PID|auto SECONDS OUT.jsonl")
    duration = float(sys.argv[2])
    if not 1 <= duration <= 3600:
        raise SystemExit("Use a capture duration from 1 to 3600 seconds.")
    pid = character.find_pid(PROFILE["process_name"]) if sys.argv[1] == "auto" else int(sys.argv[1])
    run(pid, duration, sys.argv[3])


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, struct.error) as error:
        print(f"Focused observation failed: {error}", file=sys.stderr)
        sys.exit(1)
