"""Send one exact 0x32b replay immediately after its original send."""

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
SEIZE = 0x4206
INTERRUPT = 0x4207
CONT = 7
DETACH = 17
GETREGS = 12
SETREGS = 13
PEEK = 3
POKE = 6
DEBUG_BASE = 848
SENDPACKET_RVA = 0x1661780
INBOUND_CALL_RVA = 0x1665364
PICKUP_OPCODE = 0x32B
OBJECT_SIZE = 0x500
RESPONSE_SECONDS = 2.0
FRESH_TICK = "--fresh-tick" in sys.argv
RF = 0x10000


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


base_tools = load("outgoing_capture", DIRECTORY / "outgoing-packet-capture.py")
shared = load("attack_observer", TOOLS / "overhead-attacks.py")
observer = base_tools.observer
character = observer.character
execution_control = base_tools.execution_control
disable_control = base_tools.disable_control


def sequence_timings(original_entry, original_return, replay_entry, replay_return):
    values = (
        original_entry, original_return, replay_entry, replay_return,
    )
    if not all(isinstance(value, int) for value in values):
        raise ValueError("Every replay stage needs a monotonic timestamp.")
    timings = {
        "original_send_ns": original_return - original_entry,
        "original_entry_to_replay_entry_ns": replay_entry - original_entry,
        "original_return_to_replay_entry_ns": replay_entry - original_return,
        "replay_send_ns": replay_return - replay_entry,
        "original_return_to_replay_return_ns": replay_return - original_return,
        "total_sequence_ns": replay_return - original_entry,
    }
    if any(value < 0 for value in timings.values()):
        raise ValueError("Replay timestamps are not ordered.")
    return timings


def drop_id(body):
    return body[15:19].hex() if len(body) >= 19 else None


def fresh_tick_body(body):
    if len(body) < 7:
        raise ValueError("0x32b body is too short for the tick field.")
    before = struct.unpack_from("<I", body, 3)[0]
    after = (before + 1) & 0xFFFFFFFF
    modified = bytearray(body)
    struct.pack_into("<I", modified, 3, after)
    change = {
        "offset": 3,
        "size": 4,
        "before": body[3:7].hex(),
        "after": modified[3:7].hex(),
        "before_u32": before,
        "after_u32": after,
    }
    return bytes(modified), change


def read_incoming(reader, address):
    header = reader.read(address, 0x28)
    data = struct.unpack_from("<Q", header, 0x10)[0]
    total_length = struct.unpack_from("<I", header, 0x18)[0]
    payload_length = struct.unpack_from("<I", header, 0x20)[0]
    cursor = struct.unpack_from("<I", header, 0x24)[0]
    if not data or not 2 <= payload_length <= base_tools.MAX_PACKET_BYTES:
        raise RuntimeError(
            f"Invalid CInPacket layout: data={data:#x}, payload_length={payload_length}, cursor={cursor}."
        )
    body = reader.read(data + 4, payload_length)
    return {
        "packet_va": hex(address),
        "data_va": hex(data),
        "total_length": total_length,
        "payload_length": payload_length,
        "cursor": cursor,
        "wire_header": reader.read(data, 4).hex(),
        "body": body.hex(),
        "opcode": hex(struct.unpack_from("<H", body)[0]),
    }


def copy_registers(registers):
    copied = observer.Registers()
    ctypes.memmove(ctypes.addressof(copied), ctypes.addressof(registers), ctypes.sizeof(copied))
    return copied


def self_test():
    timings = sequence_timings(100, 160, 170, 190)
    assert timings == {
        "original_send_ns": 60,
        "original_entry_to_replay_entry_ns": 70,
        "original_return_to_replay_entry_ns": 10,
        "replay_send_ns": 20,
        "original_return_to_replay_return_ns": 30,
        "total_sequence_ns": 90,
    }
    control = disable_control(execution_control(0, 0), 1)
    assert control == 1
    control = execution_control(disable_control(control, 0), 1)
    assert control == 4
    assert drop_id(bytes.fromhex("2b03015069b70f0000000085013101de430100a5c087c0")) == "de430100"
    source = bytes.fromhex("2b0301ffffffff")
    changed, change = fresh_tick_body(source)
    assert changed[:3] == source[:3] and changed[7:] == source[7:]
    assert change["before_u32"] == 0xFFFFFFFF and change["after_u32"] == 0
    header = bytearray(0x28)
    struct.pack_into("<Q", header, 0x10, 0x1000)
    struct.pack_into("<I", header, 0x18, 8)
    struct.pack_into("<I", header, 0x20, 4)
    struct.pack_into("<I", header, 0x24, 0)

    class FakeReader:
        def read(self, address, size):
            data = {
                0: bytes(header),
                0x1000: b"\x04\x00\x00\x00",
                0x1004: b"\x8b\x00\x01\x02",
            }[address]
            assert len(data) == size
            return data

    incoming = read_incoming(FakeReader(), 0)
    assert incoming["opcode"] == "0x8b" and incoming["body"] == "8b000102"
    for values in ((200, 100, 300, 400), (100, 200, 300, None)):
        try:
            sequence_timings(*values)
        except ValueError:
            pass
        else:
            raise AssertionError("Invalid replay timing was accepted")
    print("PASS: replay timing, debug control, drop ID, and invalid-stage checks.")


def run(pid, duration, output):
    reader = character.Reader(pid)
    profile = json.loads((FOUNDATIONS / "profile.json").read_text())
    base, _ = character.find_image(reader, pid, profile)
    target = base + SENDPACKET_RVA
    inbound_target = base + INBOUND_CALL_RVA
    for address, expected in (
        (target, "48894c24084883ec"),
        (inbound_target, "488d542460488b8c24a0000000e8"),
    ):
        if reader.read(address, len(bytes.fromhex(expected))) != bytes.fromhex(expected):
            reader.close()
            raise RuntimeError(f"Packet hook fingerprint differs at {address:#x}.")
    status = dict(line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines())
    if int(status["TracerPid"]) or status["State"].strip()[0] in "Tt":
        reader.close()
        raise RuntimeError("Game is already traced or paused.")

    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        memfd = os.open(f"/proc/{pid}/mem", os.O_RDWR)
    except Exception:
        reader.close()
        raise

    attached = stopped = False
    saved = None
    deliver = 0
    stopping = False
    complete = False
    detached = False
    packet = None
    snapshot = None
    return_address = None
    stage = "entry"
    events = []
    result = {}
    error = None
    started = time.monotonic()

    def request_stop(signum, frame):
        nonlocal stopping
        stopping = True

    handlers = {number: signal.signal(number, request_stop) for number in (signal.SIGINT, signal.SIGTERM)}

    def record(name, registers, body):
        event = {
            "stage": name,
            "wall_time_ns": time.time_ns(),
            "monotonic_ns": time.monotonic_ns(),
            "pid": pid,
            "opcode": hex(PICKUP_OPCODE),
            "packet_va": hex(packet),
            "drop_id": drop_id(body),
            "registers": base_tools.register_values(registers),
        }
        events.append(event)
        return event

    def restore_snapshot():
        if packet is not None and snapshot is not None:
            if os.pwrite(memfd, snapshot, packet) != len(snapshot):
                raise RuntimeError("Packet snapshot restore was short.")
            if os.pread(memfd, len(snapshot), packet) != snapshot:
                raise RuntimeError("Packet snapshot restore did not read back exactly.")

    try:
        observer.ptrace(pid, SEIZE)
        attached = True
        observer.ptrace(pid, INTERRUPT)
        state = observer.wait_stop(pid, 1)
        stopped = True
        targets = {target: 0, inbound_target: 2}
        deliver = shared.pending_signal(pid, state, targets)
        saved = {
            slot: observer.ptrace(pid, PEEK, DEBUG_BASE + slot * 8) & 0xFFFFFFFFFFFFFFFF
            for slot in (0, 1, 2, 6, 7)
        }
        control = saved[7]
        for slot in (0, 1, 2):
            if control & (3 << (slot * 2)):
                raise RuntimeError(f"Hardware breakpoint slot {slot} is occupied.")
        control = execution_control(execution_control(disable_control(control, 1), 0), 2)
        observer.ptrace(pid, POKE, DEBUG_BASE, target)
        observer.ptrace(pid, POKE, DEBUG_BASE + 2 * 8, inbound_target)
        observer.ptrace(pid, POKE, DEBUG_BASE + 7 * 8, control)
        observer.ptrace(pid, POKE, DEBUG_BASE + 6 * 8, 0)
        observer.ptrace(pid, CONT, 0, deliver)
        deliver = 0
        stopped = False
        print(f"ARMED pid={pid}: perform one pickup; its exact 0x32b will be replayed once.", flush=True)

        while not stopping and (
            not complete and time.monotonic() - started < duration
            or complete and time.monotonic() < observe_until
        ):
            try:
                state = observer.wait_stop(pid, 0.1)
            except TimeoutError:
                continue
            stopped = True
            number = os.WSTOPSIG(state)
            if number != signal.SIGTRAP:
                observer.ptrace(pid, CONT, 0, number)
                stopped = False
                continue
            registers = observer.Registers()
            observer.ptrace(pid, GETREGS, 0, ctypes.addressof(registers))
            debug_status = observer.ptrace(pid, PEEK, DEBUG_BASE + 6 * 8)

            if registers.rip == inbound_target and debug_status & 4:
                incoming = read_incoming(reader, registers.rsp + 0x60)
                incoming.update({
                    "stage": "server_to_client",
                    "wall_time_ns": time.time_ns(),
                    "monotonic_ns": time.monotonic_ns(),
                    "pid": pid,
                })
                events.append(incoming)
                observer.ptrace(pid, POKE, DEBUG_BASE + 6 * 8, 0)
                observer.ptrace(pid, CONT)
                stopped = False
                continue

            if stage == "entry":
                if registers.rip != target or not debug_status & 1:
                    raise RuntimeError("Trap did not belong to the pickup replay entry breakpoint.")
                opcode, body = base_tools.read_packet(reader, registers.rcx)
                if opcode != PICKUP_OPCODE:
                    observer.ptrace(pid, POKE, DEBUG_BASE + 6 * 8, 0)
                    observer.ptrace(pid, CONT)
                    stopped = False
                    continue
                packet = registers.rcx
                snapshot = os.pread(memfd, OBJECT_SIZE, packet)
                if len(snapshot) != OBJECT_SIZE:
                    raise RuntimeError("Could not read the complete outgoing packet object.")
                return_address = reader.qword(registers.rsp)
                original_registers = copy_registers(registers)
                record("original_entry", registers, body)
                original_entry_ns = events[-1]["monotonic_ns"]
                observer.ptrace(pid, POKE, DEBUG_BASE + 8, return_address)
                observer.ptrace(pid, POKE, DEBUG_BASE + 7 * 8, execution_control(disable_control(control, 0), 1))
                stage = "original_return"
            elif stage == "original_return":
                if registers.rip != return_address or not debug_status & 2:
                    raise RuntimeError("Trap did not belong to the original SendPacket return.")
                original_return_registers = copy_registers(registers)
                record("original_return", registers, body)
                original_return_ns = events[-1]["monotonic_ns"]
                restore_snapshot()
                replay_body = body
                result["field_changes"] = []
                if FRESH_TICK:
                    replay_body, change = fresh_tick_body(body)
                    tick_bytes = replay_body[3:7]
                    if os.pwrite(memfd, tick_bytes, packet + 8 + 3) != len(tick_bytes):
                        raise RuntimeError("Fresh-tick write was short.")
                    if os.pread(memfd, len(replay_body), packet + 8) != replay_body:
                        raise RuntimeError("Fresh-tick body did not read back exactly.")
                    result["field_changes"].append(change)
                result["replay_body"] = replay_body.hex()
                result["replay_body_sha256"] = hashlib.sha256(replay_body).hexdigest()
                replay_registers = copy_registers(original_registers)
                replay_registers.eflags &= ~RF
                observer.ptrace(pid, SETREGS, 0, ctypes.addressof(replay_registers))
                record("replay_entry", replay_registers, replay_body)
                replay_entry_ns = events[-1]["monotonic_ns"]
                stage = "replay_return"
            elif stage == "replay_return":
                if registers.rip != return_address or not debug_status & 2:
                    raise RuntimeError("Trap did not belong to the replay SendPacket return.")
                record("replay_return", registers, replay_body)
                replay_return_ns = events[-1]["monotonic_ns"]
                restore_snapshot()
                observer.ptrace(pid, SETREGS, 0, ctypes.addressof(original_return_registers))
                observer.ptrace(pid, POKE, DEBUG_BASE + 8, saved[1])
                observer.ptrace(pid, POKE, DEBUG_BASE + 7 * 8, control)
                result["timings"] = sequence_timings(
                    original_entry_ns, original_return_ns, replay_entry_ns, replay_return_ns,
                )
                result["original_return_rax"] = hex(original_return_registers.rax)
                result["replay_return_rax"] = hex(registers.rax)
                complete = True
                stage = "observe"
                observe_until = time.monotonic() + RESPONSE_SECONDS
            observer.ptrace(pid, POKE, DEBUG_BASE + 6 * 8, 0)
            observer.ptrace(pid, CONT)
            stopped = False
    except (OSError, RuntimeError, ValueError, struct.error) as caught:
        error = str(caught)
    finally:
        result.update({
            "pid": pid,
            "module_base": hex(base),
            "opcode": hex(PICKUP_OPCODE),
            "drop_id": drop_id(body) if packet is not None else None,
            "body": body.hex() if packet is not None else None,
            "body_sha256": hashlib.sha256(body).hexdigest() if packet is not None else None,
            "complete": complete,
            "events": events,
            "error": error,
        })
        if attached:
            try:
                if not stopped:
                    observer.ptrace(pid, INTERRUPT)
                    state = observer.wait_stop(pid, 1)
                    stopped = True
                    signal_targets = {target: 0, inbound_target: 2}
                    if return_address is not None:
                        signal_targets[return_address] = 1
                    deliver = shared.pending_signal(pid, state, signal_targets)
                try:
                    if packet is not None and not complete and stage != "entry":
                        restore_snapshot()
                finally:
                    try:
                        if saved is not None:
                            for slot in (7, 0, 1, 2, 6):
                                observer.ptrace(pid, POKE, DEBUG_BASE + slot * 8, saved[slot])
                    finally:
                        observer.ptrace(pid, DETACH, 0, deliver)
                detached = True
                print("DETACHED: original debug registers restored.", flush=True)
            except (OSError, RuntimeError) as cleanup_error:
                result["cleanup_error"] = str(cleanup_error)
                print(f"DETACH incomplete: {cleanup_error}", file=sys.stderr, flush=True)
        result["detached"] = detached
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(result, stream, indent=2)
        os.close(memfd)
        reader.close()
        for number, handler in handlers.items():
            signal.signal(number, handler)
    if error is not None:
        raise RuntimeError(error)
    if not complete:
        raise RuntimeError("No complete original/replay pair was captured; partial JSON was saved.")
    if not detached:
        raise RuntimeError("Replay completed, but detach could not be verified.")
    print("REPLAY COMPLETE " + json.dumps(result["timings"], sort_keys=True), flush=True)
    print(f"WROTE {output}", flush=True)
    return result


def main():
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return
    if len(sys.argv) not in (4, 5) or len(sys.argv) == 5 and sys.argv[4] != "--fresh-tick":
        raise SystemExit("Usage: replay-32b.py PID|auto SECONDS OUT.json [--fresh-tick]")
    duration = float(sys.argv[2])
    if not 1 <= duration <= 600:
        raise SystemExit("Use a capture duration from 1 to 600 seconds.")
    profile = json.loads((FOUNDATIONS / "profile.json").read_text())
    pid = character.find_pid(profile["process_name"]) if sys.argv[1] == "auto" else int(sys.argv[1])
    run(pid, duration, sys.argv[3])


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, struct.error) as error:
        print(f"0x32b replay failed: {error}", file=sys.stderr)
        raise SystemExit(1)
