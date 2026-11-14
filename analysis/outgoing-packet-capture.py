"""Capture outgoing MapleStory packets and construction timelines, with optional policy suppression."""

import argparse
import ctypes
import errno
import importlib.util
import json
import os
from pathlib import Path
import signal
import struct
import sys
import time
import types
import uuid


DIRECTORY = Path(__file__).resolve().parent
FOUNDATIONS = DIRECTORY.parent / "foundations"
SEIZE = 0x4206
INTERRUPT = 0x4207
SETOPTIONS = 0x4200
GETEVENTMSG = 0x4201
CONT = 7
DETACH = 17
GETREGS = 12
SETREGS = 13
GETFPREGS = 14
PEEK = 3
POKE = 6
DEBUG_BASE = 848
WAIT_ALL = 0x40000000
PTRACE_O_TRACECLONE = 1 << 3
PTRACE_O_TRACEEXIT = 1 << 6
PTRACE_EVENT_CLONE = 3
PTRACE_EVENT_EXIT = 6
PTRACE_EVENT_STOP = 0x80
PTRACE_OPTIONS = PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXIT
SENDPACKET_RVA = 0x1661780
COUTPACKET_CTOR_RVA = 0x7614B0
MAX_PACKET_BYTES = 16 * 1024 * 1024
STACK_QWORDS = 8


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


observer = load("outgoing_ptrace", FOUNDATIONS / "observe-position-reset.py")
character = observer.character
packet_fields = load("outgoing_packet_fields", FOUNDATIONS / "packet_fields.py")
traffic_policy = load("outgoing_traffic_policy", FOUNDATIONS / "traffic_policy.py")


def packet_decision(policy, process_name, pid, opcode, body, drop_opcode=None):
    decoded = packet_fields.decode_game_body(body)
    message = {
        "process": {"name": process_name}, "pid": pid, "protocol": "maple",
        "type": decoded["type"], "direction": "client_to_server",
        "fields": decoded["fields"], "destination": None,
    }
    decision = policy.decide(message)
    if drop_opcode is not None and opcode == drop_opcode:
        decision = {
            "action": "drop", "effective_action": "drop", "forward": False,
            "matched": True, "rule_id": "legacy:drop-opcode", "rule_index": None,
            "reason": "--drop-opcode", "mode": "enforce", "policy_sha256": policy.sha256,
        }
    return decoded, decision


def execution_control(control, slot):
    return (
        control & ~((0xF << (16 + slot * 4)) | (3 << (slot * 2)))
    ) | (1 << (slot * 2))


def length_watch_control(control, slot=2):
    return (
        control & ~((0xF << (16 + slot * 4)) | (3 << (slot * 2)))
    ) | (1 << (slot * 2)) | (1 << (16 + slot * 4)) | (3 << (18 + slot * 4))


def disable_control(control, slot):
    return control & ~((0xF << (16 + slot * 4)) | (3 << (slot * 2)))


def original_debug_state(current):
    original = dict(current)
    for slot in range(4):
        if original[slot] == 0:
            original[7] = disable_control(original[7], slot)
    return original


def valid_intermediate_length(length):
    return 0 <= length <= MAX_PACKET_BYTES


def validate_length(length):
    if not 2 <= length <= MAX_PACKET_BYTES:
        raise ValueError(f"Invalid outgoing packet length {length}.")
    return length


def watch_conflict(watches, tid, construction_id):
    existing = watches.get(tid)
    if existing is not None and existing["construction_id"] != construction_id:
        return existing
    return None


class Constructions:
    def __init__(self, session_id):
        self.session_id = session_id
        self.next_id = 1
        self.active = {}
        self.unmatched = []

    def start(self, tid, packet, opcode):
        key = (tid, packet)
        replaced = self.active.pop(key, None)
        if replaced is not None:
            replaced["unmatched_reason"] = "constructor_replaced"
            self.unmatched.append(replaced)
        construction = {
            "construction_id": f"{self.session_id}:{self.next_id}",
            "tid": tid,
            "packet": packet,
            "packet_va": hex(packet),
            "opcode": hex(opcode),
            "deep_gap": False,
        }
        self.next_id += 1
        self.active[key] = construction
        return construction, replaced

    def finish(self, tid, packet):
        return self.active.pop((tid, packet), None)

    def drop_thread(self, tid):
        dropped = []
        for key in list(self.active):
            if key[0] == tid:
                construction = self.active.pop(key)
                construction["unmatched_reason"] = "thread_exit"
                self.unmatched.append(construction)
                dropped.append(construction)
        return dropped

    def drain(self):
        for key in list(self.active):
            construction = self.active.pop(key)
            construction["unmatched_reason"] = "not_sent"
            self.unmatched.append(construction)


def read_packet(reader, address):
    opcode = reader.unpack("<I", address + 0x434)[0]
    length = validate_length(reader.unpack("<I", address + 0x428)[0])
    return opcode, reader.read(address + 8, length)


def packet_diagnostics(reader, packet):
    result = {"packet_va": hex(packet)}
    for name, address, size in (
        ("metadata", packet + 0x408, 0x38),
        ("body_prefix", packet + 8, 64),
    ):
        try:
            result[name] = reader.read(address, size).hex()
        except (OSError, RuntimeError) as error:
            result[name + "_error"] = str(error)
    return result


def register_values(registers):
    return {name: hex(getattr(registers, name)) for name, _ in registers._fields_}


def stack_values(reader, registers, base, image_size):
    try:
        raw = reader.read(registers.rsp, STACK_QWORDS * 8)
        words = struct.unpack(f"<{STACK_QWORDS}Q", raw)
    except (OSError, RuntimeError, struct.error) as error:
        return [{"stack_address": hex(registers.rsp), "error": str(error)}]
    values = []
    for value in words:
        rva = value - base
        values.append({
            "address": hex(value),
            "rva": hex(rva) if 0 <= rva < image_size else None,
        })
    return values


def add_context(record, reader, registers, base, image_size):
    record["registers"] = register_values(registers)
    stack = stack_values(reader, registers, base, image_size)
    record["caller"] = stack[0]
    record["return_stack"] = stack


def floating_registers(tid):
    raw = ctypes.create_string_buffer(512)
    observer.ptrace(tid, GETFPREGS, 0, ctypes.addressof(raw))
    return raw.raw.hex()


def wait_any(timeout):
    # Caller blocks SIGCHLD, so a stop that lands between the two waitpid calls stays pending.
    tid, status = os.waitpid(-1, os.WNOHANG | os.WUNTRACED | WAIT_ALL)
    if not tid:
        signal.sigtimedwait({signal.SIGCHLD}, timeout)
        tid, status = os.waitpid(-1, os.WNOHANG | os.WUNTRACED | WAIT_ALL)
    if not tid:
        raise TimeoutError()
    return tid, status


def self_test():
    armed = execution_control(execution_control(0, 0), 1)
    watched = length_watch_control(armed)
    assert watched & 0x15 == 0x15
    assert watched & (1 << 24)
    assert watched & (3 << 26) == 3 << 26
    assert execution_control(watched, 0) & 5 == 5
    cleared = disable_control(watched, 2)
    assert cleared & 0x15 == 5 and cleared & (0xF << 24) == 0
    null_state = original_debug_state({0: 0, 1: 0, 2: 0, 3: 0, 6: 0, 7: 0x55})
    assert null_state[7] == 0
    assert valid_intermediate_length(0) and valid_intermediate_length(1)
    assert valid_intermediate_length(MAX_PACKET_BYTES)
    assert not valid_intermediate_length(MAX_PACKET_BYTES + 1)
    validate_length(2)
    validate_length(MAX_PACKET_BYTES)
    for invalid in (0, 1, MAX_PACKET_BYTES + 1):
        try:
            validate_length(invalid)
        except ValueError:
            pass
        else:
            raise AssertionError("Invalid packet length was accepted")

    constructions = Constructions("test")
    first, _ = constructions.start(10, 0x1000, 0xE1)
    second, replaced = constructions.start(10, 0x1000, 0xE1)
    assert first["construction_id"] != second["construction_id"]
    assert replaced == first and constructions.unmatched[0] == first
    assert constructions.finish(10, 0x1000) == second
    third, _ = constructions.start(10, 0x2000, 0x32B)
    assert constructions.drop_thread(10) == [third]
    fourth, _ = constructions.start(11, 0x3000, 0x407)
    constructions.drain()
    assert constructions.unmatched[-1] == fourth
    conflict = watch_conflict({10: second}, 10, fourth["construction_id"])
    assert conflict == second
    assert watch_conflict({10: second}, 11, fourth["construction_id"]) is None

    class StackReader:
        def read(self, address, size):
            assert size == STACK_QWORDS * 8
            return struct.pack(f"<{STACK_QWORDS}Q", 0x140001234, *range(STACK_QWORDS - 1))

    class BrokenReader:
        def read(self, address, size):
            raise OSError(errno.EFAULT, "unreadable")

    frame = types.SimpleNamespace(rsp=0x7000)
    stack = stack_values(StackReader(), frame, 0x140000000, 0x2000000)
    assert len(stack) == STACK_QWORDS
    assert stack[0] == {"address": "0x140001234", "rva": "0x1234"}
    assert stack[1]["rva"] is None
    broken = stack_values(BrokenReader(), frame, 0x140000000, 0x2000000)
    assert broken[0]["stack_address"] == "0x7000" and "error" in broken[0]
    body = bytearray(36)
    struct.pack_into("<H", body, 0, 0x32B)
    struct.pack_into("<I", body, 0x0F, 99)
    policy = traffic_policy.Policy({"version": 1, "rules": [{
        "id": "test-drop", "action": "drop", "process": "MapleStory.exe", "protocol": "maple",
        "type": "0x32b", "field": {"name": "drop_object_id", "equals": 99},
    }]})
    decoded, decision = packet_decision(policy, "MapleStory.exe", 10, 0x32B, body)
    assert decoded["fields"]["drop_object_id"] == 99 and decision["effective_action"] == "drop"
    struct.pack_into("<I", body, 0x0F, 100)
    _, decision = packet_decision(policy, "MapleStory.exe", 10, 0x32B, body)
    assert decision["forward"]
    print("PASS: debug control, packet bounds, construction correlation, deep-watch conflicts, stack reads, and policy fields.")


def run(pid, duration, output, deep_opcodes, drop_opcode=None, profile=None, policy=None):
    if policy is None:
        policy = traffic_policy.Policy()
    if profile is None:
        profile = json.loads((FOUNDATIONS / "profile.json").read_text())
    reader = character.Reader(pid)
    base, _ = character.find_image(reader, pid, profile)
    image_size = character.number(profile["pe"]["size_of_image"])
    fingerprints = (
        (SENDPACKET_RVA, "48894c24084883ec"),
        (COUTPACKET_CTOR_RVA + 0x3A, "899134040000"),
    )
    for rva, expected in fingerprints:
        wanted = bytes.fromhex(expected)
        if reader.read(base + rva, len(wanted)) != wanted:
            reader.close()
            raise RuntimeError(f"Outgoing packet hook fingerprint differs at RVA {rva:#x}.")

    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except Exception:
        reader.close()
        raise
    stream = os.fdopen(descriptor, "w", encoding="utf-8")
    session_id = uuid.uuid4().hex
    constructions = Constructions(session_id)
    targets = {base + SENDPACKET_RVA: 0, base + COUTPACKET_CTOR_RVA: 1}
    counts = {
        "events": 0, "sends": 0, "constructors": 0, "linked_sends": 0,
        "field_changes": 0, "notices": 0, "send_errors": 0, "deep_gaps": 0, "dropped": 0,
    }
    attached = set()
    stopped = set()
    saved = {}
    armed_control = {}
    pending = {}
    wait_states = {}
    watches = {}
    send_errors = 0
    deep_gaps = 0
    fatal_error = None
    cleanup_errors = []
    stopping = False

    def event(kind, tid):
        return {
            "schema_version": 1,
            "session_id": session_id,
            "kind": kind,
            "wall_time_ns": time.time_ns(),
            "monotonic_ns": time.monotonic_ns(),
            "pid": pid,
            "tid": tid,
        }

    def write(record):
        # Flushed on the 5 s status tick and on close, not per line, to keep traced threads stopped for less time.
        record["event_index"] = counts["events"]
        counts["events"] += 1
        stream.write(json.dumps(record, separators=(",", ":")) + "\n")

    def notice(tid, name, registers=None, details=None, send_failure=False, deep_failure=False):
        nonlocal send_errors, deep_gaps
        record = event("notice", tid)
        record["notice"] = name
        if registers is not None:
            add_context(record, reader, registers, base, image_size)
        if details:
            record.update(details)
        write(record)
        counts["notices"] += 1
        if send_failure:
            send_errors += 1
            counts["send_errors"] = send_errors
        if deep_failure:
            deep_gaps += 1
            counts["deep_gaps"] = deep_gaps
        print(f"NOTICE tid={tid} event={name}", flush=True)

    def pending_signal(tid, status):
        if status >> 16:
            return 0
        number = os.WSTOPSIG(status)
        if number == signal.SIGTRAP:
            registers = observer.Registers()
            observer.ptrace(tid, GETREGS, 0, ctypes.addressof(registers))
            slot = targets.get(registers.rip)
            debug_status = observer.ptrace(tid, PEEK, DEBUG_BASE + 6 * 8)
            if slot is not None and debug_status & (1 << slot):
                return 0
            if tid in watches and debug_status & 4:
                return 0
        return number

    def stop(tid):
        if tid in stopped:
            return
        observer.ptrace(tid, INTERRUPT)
        status = observer.wait_stop(tid, 2)
        stopped.add(tid)
        wait_states[tid] = status
        pending[tid] = pending_signal(tid, status)

    def resume(tid):
        signal_to_deliver = pending.pop(tid, 0)
        observer.ptrace(tid, CONT, 0, signal_to_deliver)
        stopped.discard(tid)
        wait_states.pop(tid, None)

    def arm_stopped_thread(tid):
        current = {
            slot: observer.ptrace(tid, PEEK, DEBUG_BASE + slot * 8) & 0xFFFFFFFFFFFFFFFF
            for slot in (0, 1, 2, 3, 6, 7)
        }
        # Linux zeroes ptrace debug registers on clone, so each thread's original state is its own.
        saved[tid] = original_debug_state(current)
        control = saved[tid][7]
        for address, slot in targets.items():
            if current[slot] != address:
                if control & (3 << (slot * 2)) and current[slot] != 0:
                    raise RuntimeError(
                        f"Thread {tid} hardware breakpoint slot {slot} is occupied by "
                        f"{current[slot]:#x}, not {address:#x}; DR7={control:#x}."
                    )
                observer.ptrace(tid, POKE, DEBUG_BASE + slot * 8, address)
            control = execution_control(control, slot)
        if deep_opcodes and control & (3 << 4):
            raise RuntimeError(
                f"Thread {tid} already uses deep-trace watchpoint slot 2 at {current[2]:#x}."
            )
        observer.ptrace(tid, POKE, DEBUG_BASE + 7 * 8, control)
        armed_control[tid] = control

    def clear_watch(tid):
        if tid not in watches:
            return
        watches.pop(tid)
        observer.ptrace(tid, POKE, DEBUG_BASE + 2 * 8, saved[tid][2])
        observer.ptrace(tid, POKE, DEBUG_BASE + 7 * 8, armed_control[tid])

    def set_watch(tid, construction, registers):
        conflict = watch_conflict(watches, tid, construction["construction_id"])
        if conflict is not None:
            construction["deep_gap"] = True
            notice(
                tid, "deep_trace_gap", registers,
                {
                    "construction_id": construction["construction_id"],
                    "blocked_by": conflict["construction_id"],
                    "reason": "overlapping selected packets on one thread",
                },
                deep_failure=True,
            )
            return
        packet = construction["packet"]
        if (packet + 0x428) % 4:
            # A 4-byte DR watch on a misaligned address is rejected by the kernel with EINVAL.
            construction["deep_gap"] = True
            notice(
                tid, "deep_trace_gap", registers,
                {"construction_id": construction["construction_id"], "reason": "length field not 4-byte aligned"},
                deep_failure=True,
            )
            return
        observer.ptrace(tid, POKE, DEBUG_BASE + 2 * 8, packet + 0x428)
        observer.ptrace(tid, POKE, DEBUG_BASE + 7 * 8, length_watch_control(armed_control[tid]))
        watches[tid] = {
            "construction_id": construction["construction_id"],
            "packet": packet,
            "opcode": construction["opcode"],
            "previous_length": None,
        }

    def event_message(tid):
        value = ctypes.c_ulonglong()
        observer.ptrace(tid, GETEVENTMSG, 0, ctypes.addressof(value))
        return value.value

    def attach_existing_threads():
        while True:
            new_tids = [
                int(entry.name) for entry in sorted(
                    Path(f"/proc/{pid}/task").iterdir(), key=lambda entry: int(entry.name)
                ) if int(entry.name) not in attached
            ]
            if not new_tids:
                return
            for tid in new_tids:
                try:
                    observer.ptrace(tid, SEIZE)
                    attached.add(tid)
                    stop(tid)
                except OSError as error:
                    if error.errno == errno.ESRCH:
                        attached.discard(tid)
                        stopped.discard(tid)
                        continue
                    raise

    def remove_thread(tid):
        constructions.drop_thread(tid)
        attached.discard(tid)
        stopped.discard(tid)
        saved.pop(tid, None)
        armed_control.pop(tid, None)
        pending.pop(tid, None)
        wait_states.pop(tid, None)
        watches.pop(tid, None)

    def attach_clone(parent, new_tid):
        # The auto-attached child stops on its own; a PTRACE_INTERRUPT here would queue a second stop.
        attached.add(new_tid)
        try:
            status = observer.wait_stop(new_tid, 2)
            stopped.add(new_tid)
            wait_states[new_tid] = status
            arm_stopped_thread(new_tid)
            pending[new_tid] = pending_signal(new_tid, status)
            resume(new_tid)
        except (OSError, RuntimeError) as error:
            if not os.path.exists(f"/proc/{new_tid}"):
                remove_thread(new_tid)
                return
            notice(parent, "clone_arm_error", details={"new_tid": new_tid, "error": str(error)}, send_failure=True)
            raise RuntimeError(f"Could not arm cloned thread {new_tid}: {error}") from error

    def handle_trap(tid, number, status):
        registers = observer.Registers()
        observer.ptrace(tid, GETREGS, 0, ctypes.addressof(registers))
        debug_status = observer.ptrace(tid, PEEK, DEBUG_BASE + 6 * 8)
        handled_watch = False

        if debug_status & 4 and tid in watches:
            handled_watch = True
            watch = watches[tid]
            packet = watch["packet"]
            length = reader.unpack("<I", packet + 0x428)[0]
            record = event("field_change", tid)
            record.update({
                "construction_id": watch["construction_id"],
                "opcode": watch["opcode"],
                "packet_va": hex(packet),
                "previous_length": watch["previous_length"],
                "length": length,
                "rip_after_write": hex(registers.rip),
                "rva_after_write": hex(registers.rip - base) if 0 <= registers.rip - base < image_size else None,
            })
            add_context(record, reader, registers, base, image_size)
            try:
                record["floating_registers"] = floating_registers(tid)
            except OSError as error:
                record["floating_registers_error"] = str(error)
                notice(tid, "floating_register_read_error", details={"construction_id": watch["construction_id"], "error": str(error)}, deep_failure=True)
            if valid_intermediate_length(length):
                record["body"] = reader.read(packet + 8, length).hex()
            else:
                record["body"] = None
                record["length_error"] = f"Invalid intermediate length {length}."
                construction = constructions.active.get((tid, packet))
                if construction is not None:
                    construction["deep_gap"] = True
                notice(tid, "invalid_intermediate_length", registers, {"construction_id": watch["construction_id"], "length": length}, deep_failure=True)
                clear_watch(tid)
            write(record)
            counts["field_changes"] += 1
            watch["previous_length"] = length

        slot = targets.get(registers.rip)
        if slot is None or not debug_status & (1 << slot):
            if not handled_watch:
                notice(tid, "unexpected_trap", registers, {"debug_status": hex(debug_status), "wait_status": hex(status)})
                pending[tid] = number
        elif slot == 1:
            packet = registers.rcx
            opcode = registers.rdx & 0xFFFFFFFF
            construction, replaced = constructions.start(tid, packet, opcode)
            if replaced is not None:
                stale = watches.get(tid)
                if stale is not None and stale["construction_id"] == replaced["construction_id"]:
                    # The old packet at this address was never sent; its watch would block this thread forever.
                    clear_watch(tid)
            record = event("constructor", tid)
            record.update(construction)
            if replaced is not None:
                record["replaces_construction_id"] = replaced["construction_id"]
            add_context(record, reader, registers, base, image_size)
            write(record)
            counts["constructors"] += 1
            if opcode in deep_opcodes:
                set_watch(tid, construction, registers)
        else:
            packet = registers.rcx
            try:
                opcode, body = read_packet(reader, packet)
            except (OSError, RuntimeError, ValueError, struct.error) as error:
                if getattr(error, "errno", None) == errno.ESRCH:
                    raise
                details = packet_diagnostics(reader, packet)
                details["error"] = str(error)
                notice(tid, "send_read_error", registers, details, send_failure=True)
                watch = watches.get(tid)
                if watch is not None and watch["packet"] == packet:
                    notice(tid, "deep_trace_gap", details={"construction_id": watch["construction_id"], "reason": "final send could not be read"}, deep_failure=True)
                    clear_watch(tid)
            else:
                construction = constructions.finish(tid, packet)
                record = event("send", tid)
                record.update({
                    "direction": "client_to_server",
                    "construction_id": construction["construction_id"] if construction is not None else None,
                    "constructor_missing": construction is None,
                    "opcode": hex(opcode),
                    "packet_va": hex(packet),
                    "body_va": hex(packet + 8),
                    "length": len(body),
                    "body": body.hex(),
                })
                add_context(record, reader, registers, base, image_size)
                decoded, decision = packet_decision(
                    policy, profile["process_name"], pid, opcode, body, drop_opcode,
                )
                record["decode"] = decoded
                record["filter_decision"] = decision
                record["destination_evidence"] = "unavailable_at_SendPacket"
                dropped = not decision["forward"]
                record["dropped"] = dropped
                if dropped:
                    return_address = reader.qword(registers.rsp)
                    if not return_address:
                        raise RuntimeError("Cannot drop a packet with no SendPacket return address.")
                    registers.rip = return_address
                    registers.rsp = (registers.rsp + 8) & 0xFFFFFFFFFFFFFFFF
                    registers.rax = 1
                    observer.ptrace(tid, SETREGS, 0, ctypes.addressof(registers))
                    check = observer.Registers()
                    observer.ptrace(tid, GETREGS, 0, ctypes.addressof(check))
                    if check.rip != return_address or check.rsp != registers.rsp or check.rax != 1:
                        raise RuntimeError("Packet-drop register update did not read back exactly.")
                    counts["dropped"] += 1
                    print(f"DROP opcode={opcode:#x} length={len(body)}", flush=True)
                write(record)
                counts["sends"] += 1
                if construction is not None:
                    counts["linked_sends"] += 1
                elif opcode in deep_opcodes:
                    notice(tid, "deep_trace_gap", registers, {"opcode": hex(opcode), "packet_va": hex(packet), "reason": "selected send had no constructor"}, deep_failure=True)
                watch = watches.get(tid)
                if watch is not None and watch["packet"] == packet:
                    clear_watch(tid)
        observer.ptrace(tid, POKE, DEBUG_BASE + 6 * 8, 0)
        resume(tid)

    def handle(tid, status):
        if os.WIFEXITED(status) or os.WIFSIGNALED(status):
            remove_thread(tid)
            return
        if not os.WIFSTOPPED(status):
            raise RuntimeError(f"Unexpected wait status {status:#x} for thread {tid}.")
        event_code = status >> 16

        if tid not in attached:
            # Child's first stop arrived before its parent's clone event.
            attached.add(tid)
            stopped.add(tid)
            wait_states[tid] = status
            notice(tid, "late_clone_thread", details={"wait_status": hex(status)}, send_failure=event_code != PTRACE_EVENT_STOP)
            arm_stopped_thread(tid)
            pending[tid] = pending_signal(tid, status)
            resume(tid)
            return

        stopped.add(tid)
        wait_states[tid] = status
        if event_code == PTRACE_EVENT_CLONE:
            new_tid = event_message(tid)
            if new_tid not in attached:
                attach_clone(tid, new_tid)
            resume(tid)
            return
        if event_code == PTRACE_EVENT_EXIT or (
            event_code == PTRACE_EVENT_STOP and os.WSTOPSIG(status) == signal.SIGTRAP
        ):
            resume(tid)
            return
        if event_code:
            notice(tid, "unexpected_ptrace_event", details={"wait_status": hex(status)})
            resume(tid)
            return

        number = os.WSTOPSIG(status)
        if number != signal.SIGTRAP:
            pending[tid] = number
            resume(tid)
            return
        handle_trap(tid, number, status)

    def request_stop(signum, frame):
        nonlocal stopping
        stopping = True

    handlers = {number: signal.signal(number, request_stop) for number in (signal.SIGINT, signal.SIGTERM)}
    old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGCHLD})
    try:
        start = event("session_start", pid)
        start.update({
            "module_base": hex(base),
            "pe_timestamp": profile["pe"]["timestamp"],
            "game_build": {"process_name": profile["process_name"], "observed_date": profile["observed_date"],
                           **profile["pe"], "code_fingerprints_verified": True},
            "sendpacket_rva": hex(SENDPACKET_RVA),
            "constructor_rva": hex(COUTPACKET_CTOR_RVA),
            "deep_opcodes": [hex(opcode) for opcode in sorted(deep_opcodes)],
            "drop_opcode": hex(drop_opcode) if drop_opcode is not None else None,
            "policy": {"sha256": policy.sha256, "source": policy.source, "document": policy.document},
            "destination_evidence": "unavailable_at_SendPacket",
            "duration_seconds": duration,
            "max_packet_bytes": MAX_PACKET_BYTES,
        })
        write(start)
        attach_existing_threads()
        if not attached:
            raise RuntimeError("No MapleStory threads could be attached.")
        for tid in sorted(attached):
            arm_stopped_thread(tid)
            observer.ptrace(tid, SETOPTIONS, 0, PTRACE_OPTIONS)
        print(
            f"ARMED pid={pid} threads={len(attached)} deep_opcodes={sorted(deep_opcodes)} "
            f"drop_opcode={hex(drop_opcode) if drop_opcode is not None else None}", flush=True,
        )
        started = time.monotonic()
        last_status = started
        for tid in sorted(attached):
            resume(tid)

        while attached and not stopping and time.monotonic() - started < duration:
            now = time.monotonic()
            if now - last_status >= 5:
                stream.flush()
                print(f"TRAFFIC {counts} attached_threads={len(attached)}", flush=True)
                last_status = now
            try:
                tid, status = wait_any(0.1)
            except TimeoutError:
                continue
            except ChildProcessError:
                for tid in list(attached):
                    remove_thread(tid)
                break
            try:
                handle(tid, status)
            except OSError as error:
                if error.errno != errno.ESRCH:
                    raise
                remove_thread(tid)
                notice(tid, "thread_vanished", details={"error": str(error)})
        if not attached:
            notice(pid, "target_exited")
    except (OSError, RuntimeError, ValueError, struct.error) as error:
        fatal_error = str(error)
    finally:
        done = set()
        while attached - done:
            tid = min(attached - done)
            done.add(tid)
            try:
                if not os.path.exists(f"/proc/{tid}"):
                    remove_thread(tid)
                    continue
                if tid not in stopped:
                    stop(tid)
                if wait_states.get(tid, 0) >> 16 == PTRACE_EVENT_CLONE:
                    # Never armed, so it is detached later in this loop with nothing to restore.
                    attached.add(event_message(tid))
                deliver = pending.pop(tid, None)
                if deliver is None and tid in wait_states:
                    deliver = pending_signal(tid, wait_states[tid])
                if tid in saved:
                    for slot in (7, 0, 1, 2, 3, 6):
                        observer.ptrace(tid, POKE, DEBUG_BASE + slot * 8, saved[tid][slot])
                observer.ptrace(tid, DETACH, 0, deliver or 0)
                stopped.discard(tid)
                wait_states.pop(tid, None)
            except (OSError, RuntimeError) as error:
                if (
                    not os.path.exists(f"/proc/{tid}")
                    or getattr(error, "errno", None) == errno.ESRCH
                    or "exited while waiting for a ptrace stop" in str(error)
                ):
                    remove_thread(tid)
                    continue
                cleanup_errors.append(f"thread {tid}: {error}")
        constructions.drain()
        summary = event("session_end", pid)
        summary.update({
            "counts": dict(counts),
            "send_complete": fatal_error is None and send_errors == 0 and not cleanup_errors,
            "deep_complete": (fatal_error is None and deep_gaps == 0) if deep_opcodes else None,
            "unmatched_constructors": constructions.unmatched,
            "cleanup_success": not cleanup_errors,
            "cleanup_errors": cleanup_errors,
            "fatal_error": fatal_error,
        })
        try:
            write(summary)
        except (OSError, RuntimeError) as error:
            cleanup_errors.append(f"summary: {error}")
        stream.close()
        reader.close()
        signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
        for number, handler in handlers.items():
            signal.signal(number, handler)
        if cleanup_errors:
            print("DETACH errors: " + "; ".join(cleanup_errors), file=sys.stderr, flush=True)
        else:
            print("DETACHED: original debug registers restored on all attached threads.", flush=True)
        print(f"WROTE {output}: {counts}", flush=True)
    if fatal_error is not None:
        raise RuntimeError(fatal_error)
    if cleanup_errors:
        raise RuntimeError("Capture cleanup was incomplete; inspect session_end in the JSONL output.")
    return summary


def main():
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pid")
    parser.add_argument("seconds", type=float)
    parser.add_argument("output", type=Path)
    parser.add_argument("--deep-opcode", action="append", default=[], type=lambda value: int(value, 0))
    parser.add_argument("--drop-opcode", type=lambda value: int(value, 0), default=None)
    parser.add_argument("--policy", type=Path, default=None, help="JSON process/type/field policy; audit mode never drops")
    args = parser.parse_args()
    if not 1 <= args.seconds <= 3600:
        parser.error("Use a capture duration from 1 to 3600 seconds.")
    deep_opcodes = set(args.deep_opcode)
    if any(not 0 <= opcode <= 0xFFFFFFFF for opcode in deep_opcodes):
        parser.error("Deep opcodes must be 32-bit integers.")
    if args.drop_opcode is not None and not 0 <= args.drop_opcode <= 0xFFFFFFFF:
        parser.error("Drop opcode must be a 32-bit integer.")
    profile = json.loads((FOUNDATIONS / "profile.json").read_text())
    pid = character.find_pid(profile["process_name"]) if args.pid == "auto" else int(args.pid)
    run(pid, args.seconds, args.output, deep_opcodes, args.drop_opcode, profile, traffic_policy.Policy.load(args.policy))


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, struct.error) as error:
        print(f"Outgoing packet capture failed: {error}", file=sys.stderr)
        raise SystemExit(1)
