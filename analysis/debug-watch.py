"""Record one hardware execution breakpoint or four-byte write watch without changing client memory."""

import argparse
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import signal
import time


DIRECTORY = Path(__file__).resolve().parent
FOUNDATIONS = DIRECTORY.parent / "foundations"
TOOLS = DIRECTORY.parent / "tools"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


shared = load("debug_watch_shared", TOOLS / "overhead-attacks.py")
observer = shared.observer
character = shared.character
PROFILE = json.loads((FOUNDATIONS / "profile.json").read_text())


def watch_control(control, execute=False):
    control = (control & ~0xF000F) | 1
    return control if execute else control | (1 << 16) | (3 << 18)


def matches_condition(reader, registers, condition):
    if condition is None:
        return True
    offset, expected = condition
    return reader.unpack("<I", registers.rdx + offset)[0] == expected


def self_test():
    class ConditionReader:
        def unpack(self, fmt, address):
            assert fmt == "<I" and address == 0x1010
            return (2,)
    registers = argparse.Namespace(rdx=0x1000)
    assert matches_condition(ConditionReader(), registers, (0x10, 2))
    assert not matches_condition(ConditionReader(), registers, (0x10, 3))
    assert matches_condition(ConditionReader(), registers, None)
    control = watch_control(0)
    assert control & 3 == 1
    assert (control >> 16) & 3 == 1
    assert (control >> 18) & 3 == 3
    assert watch_control(0xFFF0FFFF) & 0xFFF00000 == 0xFFF00000
    assert watch_control(0xFFF0FFFF, execute=True) == 0xFFF0FFF1
    print("PASS: execution and four-byte write watches preserve unrelated debug controls.")


def run(pid, address, duration, output, execute=False, once=False, condition=None, read_rdx=0, read_rdi=0, profile=PROFILE):
    reader = character.Reader(pid)
    base, _ = character.find_image(reader, pid, profile)
    attached = stopped = False
    saved = None
    deliver = 0
    stopping = False
    events = []
    watch_hits = 0
    condition_values = {}
    cleanup_error = None
    mode = "execute" if execute else "write"

    def request_stop(signum, frame):
        nonlocal stopping
        stopping = True

    handlers = {number: signal.signal(number, request_stop) for number in (signal.SIGINT, signal.SIGTERM)}
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        observer.ptrace(pid, 0x4206)
        attached = True
        observer.ptrace(pid, 0x4207)
        state = observer.wait_stop(pid, 1)
        stopped = True
        deliver = shared.pending_signal(pid, state)
        saved = {slot: observer.ptrace(pid, 3, 848 + slot * 8) & 0xFFFFFFFFFFFFFFFF for slot in (0, 6, 7)}
        if saved[7] & 3:
            raise RuntimeError("Hardware watchpoint slot 0 is occupied.")
        observer.ptrace(pid, 6, 848, address)
        observer.ptrace(pid, 6, 848 + 7 * 8, watch_control(saved[7], execute))
        observer.ptrace(pid, 7, 0, deliver)
        deliver = 0
        stopped = False
        print(f"ARMED pid={pid}: {mode} at {address:#x}", flush=True)
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
            if not dr6 & 1:
                deliver = number
                raise RuntimeError(f"Unexpected trap without the watched slot: DR6={dr6:#x}")
            watch_hits += 1
            registers = observer.Registers()
            observer.ptrace(pid, 12, 0, ctypes.addressof(registers))
            if not matches_condition(reader, registers, condition):
                actual = reader.unpack("<I", registers.rdx + condition[0])[0]
                key = str(actual)
                condition_values[key] = condition_values.get(key, 0) + 1
                observer.ptrace(pid, 6, 848 + 6 * 8, 0)
                observer.ptrace(pid, 7)
                stopped = False
                continue
            rva = registers.rip - base if 0 <= registers.rip - base < int(profile["pe"]["size_of_image"], 0) else None
            event = {
                "wall_time_ns": time.time_ns(),
                "monotonic_ns": time.monotonic_ns(),
                "mode": mode,
                "watched_address": hex(address),
                "rip": hex(registers.rip),
                "rva": hex(rva) if rva is not None else None,
                "registers": {name: hex(getattr(registers, name)) for name in (
                    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11",
                    "r12", "r13", "r14", "r15", "rbp", "rsp",
                )},
                "stack": reader.read(registers.rsp, 0x40).hex(),
            }
            for register, size in (("rdx", read_rdx), ("rdi", read_rdi)):
                if size:
                    event[f"{register}_bytes"] = reader.read(getattr(registers, register), size).hex()
            if execute:
                event["code_at_entry"] = reader.read(registers.rip, 15).hex()
            else:
                event["code_before"] = reader.read(registers.rip - 15, 15).hex()
                event["value_after_write"] = reader.read(address, 4).hex()
            events.append(event)
            if once:
                stopping = True
            if len(events) >= 256:
                raise RuntimeError("Debug-watch capture exceeded 256 events.")
            observer.ptrace(pid, 6, 848 + 6 * 8, 0)
            observer.ptrace(pid, 7)
            stopped = False
    except (OSError, RuntimeError, ValueError) as error:
        cleanup_error = error
    finally:
        if attached:
            try:
                if not stopped:
                    observer.ptrace(pid, 0x4207)
                    state = observer.wait_stop(pid, 1)
                    stopped = True
                    deliver = shared.pending_signal(pid, state)
                    if os.WSTOPSIG(state) == signal.SIGTRAP:
                        dr6 = observer.ptrace(pid, 3, 848 + 6 * 8)
                        if dr6 & 1:
                            deliver = 0
                if saved is not None:
                    for slot in (7, 0, 6):
                        observer.ptrace(pid, 6, 848 + slot * 8, saved[slot])
                observer.ptrace(pid, 17, 0, deliver)
                print("DETACHED: original debug registers restored; no client memory writes.", flush=True)
            except (OSError, RuntimeError) as error:
                cleanup_error = cleanup_error or error
                print(f"DETACH incomplete: {error}", flush=True)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump({
                "schema": "client-control.debug-watch.v1",
                "pid": pid,
                "module_base": hex(base),
                "pe_timestamp": profile["pe"]["timestamp"],
                "address": hex(address),
                "mode": mode,
                "condition": {"offset": condition[0], "equals": condition[1]} if condition else None,
                "read_rdx_bytes": read_rdx,
                "read_rdi_bytes": read_rdi,
                "duration_seconds": duration,
                "watch_hits": watch_hits,
                "matched_events": len(events),
                "condition_mismatches": sum(condition_values.values()),
                "condition_values": condition_values,
                "events": events,
                "error": str(cleanup_error) if cleanup_error else None,
            }, stream, indent=2)
            stream.write("\n")
        if os.geteuid() == 0 and "SUDO_UID" in os.environ and "SUDO_GID" in os.environ:
            os.chown(output, int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"]))
        reader.close()
        for number, handler in handlers.items():
            signal.signal(number, handler)
        print(f"WROTE {output}: events={len(events)}", flush=True)
    if cleanup_error is not None:
        raise cleanup_error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pid", type=int)
    parser.add_argument("address", type=lambda value: int(value, 0))
    parser.add_argument("seconds", type=float)
    parser.add_argument("output", type=Path)
    parser.add_argument("--execute", action="store_true", help="Break at an address instead of watching four-byte writes")
    parser.add_argument("--once", action="store_true", help="Stop after the first matching event")
    parser.add_argument("--rdx-dword", metavar="OFFSET=VALUE", help="On execute, record only if dword at RDX+OFFSET equals VALUE")
    parser.add_argument("--read-rdx", type=int, default=0, metavar="BYTES", help="Also read up to 4096 bytes at RDX on a matching event")
    parser.add_argument("--read-rdi", type=int, default=0, metavar="BYTES", help="Also read up to 4096 bytes at RDI on a matching event")
    parser.add_argument("--profile", type=Path, default=FOUNDATIONS / "profile.json", help="Build-specific image validation profile")
    args = parser.parse_args()
    if args.seconds <= 0:
        parser.error("seconds must be positive")
    if not 0 <= args.read_rdx <= 4096 or not 0 <= args.read_rdi <= 4096:
        parser.error("--read-rdx/--read-rdi must be 0-4096")
    condition = None
    if args.rdx_dword:
        offset, separator, expected = args.rdx_dword.partition("=")
        if not separator:
            parser.error("--rdx-dword needs OFFSET=VALUE")
        try:
            condition = (int(offset, 0), int(expected, 0))
        except ValueError:
            parser.error("--rdx-dword needs integer OFFSET and VALUE")
    if (condition is not None or args.read_rdx or args.read_rdi) and not args.execute:
        parser.error("--rdx-dword, --read-rdx, and --read-rdi require --execute")
    profile = json.loads(args.profile.read_text())
    run(args.pid, args.address, args.seconds, args.output, args.execute, args.once, condition, args.read_rdx, args.read_rdi, profile)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError) as error:
        print(f"Debug observation failed: {error}", file=os.sys.stderr)
        raise SystemExit(1)
