"""Observe plaintext packet boundaries, with optional scoped test overrides."""

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
SEIZE = 0x4206
INTERRUPT = 0x4207
CONT = 7
DETACH = 17
DEBUG_BASE = 848
MAX_PACKET_BYTES = 1024 * 1024
SENDPACKET_RVA = 0x1661780
INBOUND_CALL_RVA = 0x1665364
COUTPACKET_CTOR_RVA = 0x7614B0
WAIT_ALL = 0x40000000


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


shared = load("attack_observer", DIRECTORY / "overhead-attacks.py")
override_tools = load("rng_state_override", DIRECTORY / "rng-state-override.py")
rng = load("rng_dataset", DIRECTORY / "rng-dataset.py")
observer = shared.observer
character = shared.character
RNG_GENERATOR_RVA = 0x7AC850


def read_rng_state(reader, context_root):
    context = reader.qword(context_root)
    stats = reader.qword(context + 0x2998) if context else 0
    if not stats:
        raise RuntimeError("No RNG state context.")
    return stats, reader.read(stats, 0x2C)


def rng_record(state, rolls=False):
    result = {"rng_state": state.hex(), "rng_words": rng.state_words(state)}
    if rolls:
        result["predicted_rolls"] = rng.model.rng_rolls(state)[0]
    return result


def restore_edit(pid, reader, edit):
    if edit.get("kind") != "rng_state":
        restored = restore_scalar(
            pid, reader, edit["address"], edit["size"], edit["modified"], edit["original"]
        )
        return restored, {
            "kind": "packet_field", "field": hex(edit["offset"]),
            "original": edit["original"], "modified": edit["modified"],
        }
    before = reader.read(edit["address"], 0x2C)
    override_tools.write_memory(pid, edit["address"], edit["original"])
    after = reader.read(edit["address"], 0x2C)
    return after == edit["original"], {
        "kind": "rng_state", "attack_stage": edit["attack_stage"],
        "state_address": hex(edit["address"]), "original_state": edit["original"].hex(),
        "replacement_state": edit["replacement"].hex(), "state_before_restore": before.hex(),
        "state_after_restore": after.hex(), "advanced_state_match": before == edit["advanced"],
        "state_restored": after == edit["original"],
    }


def read_packet(reader, address, opcode_address, length_address, body_offset=8):
    opcode = reader.unpack("<I", address + opcode_address)[0]
    length = reader.unpack("<I", address + length_address)[0]
    if not 2 <= length <= MAX_PACKET_BYTES:
        raise RuntimeError(f"Invalid packet length {length} at {address:#x}.")
    return opcode, reader.read(address + body_offset, length)


def read_incoming(reader, address):
    header = reader.read(address, 0x28)
    data = struct.unpack_from("<Q", header, 0x10)[0]
    total_length = struct.unpack_from("<I", header, 0x18)[0]
    payload_length = struct.unpack_from("<I", header, 0x20)[0]
    cursor = struct.unpack_from("<I", header, 0x24)[0]
    if not data or not 2 <= payload_length <= MAX_PACKET_BYTES:
        raise RuntimeError(
            f"Invalid CInPacket layout: data={data:#x}, payload_length={payload_length}, cursor={cursor}."
        )
    return {
        "packet_va": hex(address),
        "data_va": hex(data),
        "total_length": total_length,
        "payload_length": payload_length,
        "cursor": cursor,
        "wire_header": reader.read(data, 4).hex(),
        "body": reader.read(data + 4, payload_length).hex(),
    }


def length_watch_control(control):
    return (control & ~((0xF << 28) | (3 << 6))) | (1 << 6) | (1 << 28) | (3 << 30)


INBOUND_RETURN_RVA = 0x1665376


def read_meso_drop(body):
    if len(body) != 115 or struct.unpack_from("<H", body)[0] != 0x471:
        return None
    object_id = struct.unpack_from("<I", body, 0x04)[0]
    amount = struct.unpack_from("<I", body, 0x15)[0]
    if not object_id or not amount or not struct.unpack_from("<I", body, 0x2A)[0]:
        return None
    return object_id, amount


def read_hp_candidate(body):
    if len(body) != 11 or struct.unpack_from("<H", body)[0] != 0x3F3:
        return None
    identifier = struct.unpack_from("<I", body, 2)[0]
    value = body[6]
    return (identifier, value) if identifier and value else None


PICKUP_EXPERIMENTS = {
    2: (0x03, 4), 3: (0x07, 4), 4: (0x0B, 2), 5: (0x0D, 2),
    6: (0x13, 4), 7: (0x17, 1), 8: (0x18, 4), 9: (0x1C, 4),
    10: (0x20, 4), 11: (0x02, 1),
}


def write_scalar(pid, reader, address, size, value):
    if size not in (1, 2, 4) or not 0 <= value < 1 << (size * 8):
        raise ValueError(f"Override value {value} does not fit in {size} bytes.")
    fmt = {1: "B", 2: "H", 4: "I"}[size]
    original = reader.unpack("<" + fmt, address)[0]
    override_tools.write_memory(pid, address, struct.pack("<" + fmt, value))
    if reader.unpack("<" + fmt, address)[0] != value:
        raise RuntimeError(f"Override readback failed at {address:#x}.")
    return original


def restore_scalar(pid, reader, address, size, expected, original):
    fmt = {1: "B", 2: "H", 4: "I"}[size]
    if reader.unpack("<" + fmt, address)[0] != expected:
        return False
    override_tools.write_memory(pid, address, struct.pack("<" + fmt, original))
    return reader.unpack("<" + fmt, address)[0] == original


def wait_any(timeout):
    deadline = time.monotonic() + timeout
    while True:
        tid, status = os.waitpid(-1, os.WNOHANG | os.WUNTRACED | WAIT_ALL)
        if tid:
            return tid, status
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        time.sleep(min(0.001, remaining))


def run(pid, duration, output):
    mode = int(os.environ.get("TEST_MODE", "0"), 0)
    if mode not in range(13):
        raise ValueError("TEST_MODE must be 0, 1 (0x471 meso doubling), 2–11 (single 0x32b field), or 12 (zero 0x3f3 HP candidate).")
    duplicate_flag = os.environ.get("DUPLICATE_32B", "0")
    if duplicate_flag not in ("0", "1"):
        raise ValueError("DUPLICATE_32B must be 0 or 1.")
    duplicate_enabled = duplicate_flag == "1"
    if duplicate_enabled and mode:
        raise ValueError("DUPLICATE_32B cannot be combined with TEST_MODE field experiments.")
    rng_mode = os.environ.get("RNG_MODE", "off")
    if rng_mode not in ("off", "observe", "replay", "both"):
        raise ValueError("RNG_MODE must be off, observe, replay, or both.")
    if rng_mode != "off" and (mode or duplicate_enabled):
        raise ValueError("RNG_MODE cannot be combined with TEST_MODE or DUPLICATE_32B experiments.")
    replay_words = os.environ.get("RNG_REPLAY_WORDS", "").split()
    if replay_words:
        if rng_mode not in ("replay", "both") or len(replay_words) != 3:
            raise ValueError("RNG_REPLAY_WORDS requires RNG_MODE=replay/both and exactly three state words.")
        replay_words = tuple(int(word, 0) for word in replay_words)
        if any(not 0 <= word <= 0xFFFFFFFF for word in replay_words):
            raise ValueError("RNG_REPLAY_WORDS values must be 32-bit integers.")
    else:
        replay_words = None
    reader = character.Reader(pid)
    profile = json.loads((DIRECTORY / "profile.json").read_text())
    base, _ = character.find_image(reader, pid, profile)
    fingerprints = (
        (SENDPACKET_RVA, "48894c24084883ec"),
        (INBOUND_CALL_RVA, "488d542460488b8c24a0000000e8"),
        (COUTPACKET_CTOR_RVA + 0x3A, "899134040000"),
        (0x7615A0, "40534883ec20488b"),
    )
    if rng_mode != "off":
        fingerprints += ((RNG_GENERATOR_RVA, "40534883ec20488bd933c065488b0c25"),)
        shared.verify_code(reader, base, profile["polearm_attacks"])
    for rva, expected in fingerprints:
        if reader.read(base + rva, len(bytes.fromhex(expected))).hex() != expected:
            raise RuntimeError(f"Packet hook fingerprint differs at RVA {rva:#x}; refusing to attach.")
    targets = {
        base + SENDPACKET_RVA: 0,
        base + INBOUND_CALL_RVA: 1,
        base + COUTPACKET_CTOR_RVA: 2,
    }
    if rng_mode != "off":
        rva = RNG_GENERATOR_RVA if rng_mode == "observe" else rng.model.SELECTOR_RVA
        targets[base + rva] = 3
    stop_targets = dict(targets)
    if rng_mode == "both":
        stop_targets[base + RNG_GENERATOR_RVA] = 3
    context_root = base + character.number(
        profile["incoming_display"]["calculator_context_global_rva"]
    )
    status = dict(line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines())
    if int(status["TracerPid"]) or status["State"].strip()[0] in "Tt":
        raise RuntimeError("Game is already traced or paused.")
    attached = {}
    saved = {}
    stopped = set()
    pending = {}
    constructors = {}
    watches = {}
    inbound_edits = {}
    outbound_edits = {}
    meso_drops = {}
    duplicate_state = {}
    duplicate_armed = False
    experiment = PICKUP_EXPERIMENTS.get(mode)
    experiment_state = {"native": False, "done": False}
    rng_source = None
    rng_source_address = None
    rng_attack_count = 0
    rng_slots = {}
    rng_pending = {}
    counts = {
        "client_to_server": 0, "server_to_client": 0, "constructor": 0, "field_trace": 0,
        "rng_selector": 0, "rng_generator": 0, "observer_notice": 0,
    }
    seen_notices = set()
    stopping = False

    def request_stop(signum, frame):
        nonlocal stopping
        stopping = True

    handlers = {number: signal.signal(number, request_stop) for number in (signal.SIGINT, signal.SIGTERM)}
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    stream = os.fdopen(descriptor, "w", encoding="utf-8")

    def write(record):
        stream.write(json.dumps(record, separators=(",", ":")) + "\n")
        stream.flush()

    if mode or duplicate_enabled or rng_mode != "off":
        write({
            "direction": "capture_start", "timestamp": time.time(), "pid": pid,
            "test_mode": mode, "rng_mode": rng_mode, "replay_words": replay_words,
            "test_field": "0x06" if mode == 12 else "duplicate" if duplicate_enabled else (hex(experiment[0]) if experiment else "0x15"),
            "duplicate_32b": duplicate_enabled,
        })
        if duplicate_enabled:
            print("DUPLICATE_32B=1: duplicate the first pickup immediately after the original send returns.", flush=True)
        elif mode == 12:
            print("TEST_MODE=12: zero one nonzero 0x3f3+6 value and restore it after dispatch.", flush=True)
        elif mode == 1:
            print("TEST_MODE=1: double meso amount in 0x471; 0x32b remains native.", flush=True)
        elif mode:
            print(
                f"TEST_MODE={mode}: first pickup native; next pickup increments {experiment[0]:#x} "
                f"by one, restores after sending, and leaves the drop object ID unchanged.",
                flush=True,
            )
        elif rng_mode in ("replay", "both"):
            scope = "every attack after the native control" if replay_words else "the second attack"
            print(f"First attack native; replay state before damage selection on {scope}.", flush=True)

    def stop(tid):
        if tid in stopped:
            return
        observer.ptrace(tid, INTERRUPT)
        state = observer.wait_stop(tid, 2)
        stopped.add(tid)
        thread_targets = stop_targets
        if rng_mode == "both" and tid in rng_slots:
            thread_targets = {address: slot for address, slot in targets.items() if slot < 2}
            thread_targets.update({address: slot for slot, address in rng_slots[tid].items()})
        pending[tid] = shared.pending_signal(tid, state, thread_targets)

    def resume(tid):
        signal_to_deliver = pending.pop(tid, 0)
        observer.ptrace(tid, CONT, 0, signal_to_deliver)
        stopped.discard(tid)

    def arm(tid):
        stop(tid)
        saved[tid] = {
            slot: observer.ptrace(tid, 3, DEBUG_BASE + slot * 8) & 0xFFFFFFFFFFFFFFFF
            for slot in (0, 1, 2, 3, 6, 7)
        }
        control = saved[tid][7]
        if control & (3 << 6):
            raise RuntimeError(f"Thread {tid} already uses hardware breakpoint slot 3.")
        for address, slot in targets.items():
            if control & (3 << (slot * 2)):
                raise RuntimeError(f"Thread {tid} already uses hardware breakpoint slot {slot}.")
            observer.ptrace(tid, 6, DEBUG_BASE + slot * 8, address)
            control = (control & ~((0xF << (16 + slot * 4)) | (3 << (slot * 2)))) | (1 << (slot * 2))
        if rng_mode != "off":
            slot3 = next(address for address, slot in targets.items() if slot == 3)
            rng_slots[tid] = {3: slot3}
            if rng_mode == "both":
                rng_slots[tid][2] = base + COUTPACKET_CTOR_RVA
        observer.ptrace(tid, 6, DEBUG_BASE + 7 * 8, control)
        saved[tid]["armed_control"] = control
        resume(tid)

    def switch_rng_slots(current_tid, slot2_rva, slot3_rva):
        addresses = {2: base + slot2_rva, 3: base + slot3_rva}
        for tid in list(attached):
            if tid == current_tid:
                continue
            stop(tid)
            for slot, address in addresses.items():
                observer.ptrace(tid, 6, DEBUG_BASE + slot * 8, address)
                rng_slots[tid][slot] = address
            resume(tid)
        for slot, address in addresses.items():
            observer.ptrace(current_tid, 6, DEBUG_BASE + slot * 8, address)
            rng_slots[current_tid][slot] = address

    def select_rng(tid, timestamp, registers):
        nonlocal rng_source, rng_source_address, rng_attack_count
        if tid in rng_pending:
            return None
        if rng_attack_count >= 2 and replay_words is None:
            if rng_mode == "both":
                switch_rng_slots(tid, COUTPACKET_CTOR_RVA, RNG_GENERATOR_RVA)
            return None
        stats, original = read_rng_state(reader, context_root)
        if original[0x10:0x1C] != bytes(12):
            raise RuntimeError("RNG object is locked; refusing a concurrent state write.")
        rng_attack_count += 1
        stage = "native" if rng_attack_count == 1 else "replay"
        if stage == "native":
            rng_source, rng_source_address = original, stats
        elif stats != rng_source_address:
            raise RuntimeError("RNG state address changed between native and replay attacks.")
        effective = original if stage == "native" else (
            override_tools.state_for_stage("override", original, replay_words)
            if replay_words is not None else rng_source
        )
        event = {
            "direction": "rng_selector", "timestamp": timestamp, "pid": pid, "tid": tid,
            "rng_stage": stage, "attack_ordinal": rng_attack_count,
            "state_address": hex(stats), **rng_record(original, True),
            "caller": stack(registers)[0],
        }
        attack = {
            "selector_timestamp": timestamp, "rng_stage": stage, "attack_ordinal": rng_attack_count,
            "state_address": hex(stats), "pre_state": effective.hex(),
            "pre_words": rng.state_words(effective), "predicted_rolls": rng.model.rng_rolls(effective)[0],
        }
        if stage == "replay":
            kind = "fixed_words" if replay_words is not None else "first_attack"
            event.update({
                "replay_kind": kind, "replay_source_state": effective.hex(),
                "replay_source_words": rng.state_words(effective),
                "effective_words": rng.state_words(effective),
            })
            attack.update({
                "replay_kind": kind, "pre_replay_state": original.hex(),
                "replay_source_state": effective.hex(),
            })
            outbound_edits[tid] = {
                "kind": "rng_state", "attack_stage": stage, "address": stats,
                "original": original, "replacement": effective,
                "advanced": rng.model.rng_rolls(effective)[1],
            }
            override_tools.write_memory(pid, stats, effective)
            if reader.read(stats, 0x2C) != effective:
                raise RuntimeError("RNG state write did not read back exactly.")
            event["readback_verified"] = True
            if rng_mode == "both":
                switch_rng_slots(tid, COUTPACKET_CTOR_RVA, RNG_GENERATOR_RVA)
                event["generator_trace_armed"] = True
        rng_pending[tid] = attack
        print(f"RNG {stage.upper()} words={[hex(word) for word in rng.state_words(effective)]}", flush=True)
        return event

    def generator_event(tid, timestamp, registers):
        state = reader.read(registers.rcx, 0x2C)
        return {
            "direction": "rng_generator", "timestamp": timestamp, "pid": pid, "tid": tid,
            "state_address": hex(registers.rcx), "caller": hex(reader.qword(registers.rsp)),
            "caller_rva": hex(reader.qword(registers.rsp) - base), **rng_record(state),
            "next_roll": rng.model.rng_rolls(state, 1)[0][0],
        }

    def attach_rng(record):
        try:
            stats, state = read_rng_state(reader, context_root)
            record.update({"state_address": hex(stats), **rng_record(state)})
        except (OSError, RuntimeError) as error:
            record["rng_state_error"] = str(error)

    def clear_watch(tid):
        if tid not in watches:
            return
        observer.ptrace(tid, 6, DEBUG_BASE + 3 * 8, saved[tid][3])
        observer.ptrace(tid, 6, DEBUG_BASE + 7 * 8, saved[tid]["armed_control"])
        watches.pop(tid)

    def finish_watch(tid):
        observer.ptrace(tid, 6, DEBUG_BASE + 3 * 8, saved[tid][3])
        observer.ptrace(tid, 6, DEBUG_BASE + 7 * 8, saved[tid]["armed_control"])
        watches[tid]["finished"] = True

    def set_watch(tid, packet, opcode):
        if tid in watches:
            raise RuntimeError("A watched packet was replaced before it was sent.")
        control = length_watch_control(saved[tid]["armed_control"])
        observer.ptrace(tid, 6, DEBUG_BASE + 3 * 8, packet + 0x428)
        observer.ptrace(tid, 6, DEBUG_BASE + 7 * 8, control)
        watches[tid] = {
            "packet": packet, "opcode": opcode, "previous_length": 0, "fields": [],
            "expected_length": {0x32B: 36, 0x407: 20}[int(opcode, 0)],
        }

    def packet_diagnostics(packet):
        result = {"packet_va": hex(packet)}
        for name, address, size in (("metadata", packet + 0x408, 0x38), ("body_prefix", packet + 8, 64)):
            try:
                result[name] = reader.read(address, size).hex()
            except (OSError, RuntimeError) as error:
                result[name + "_error"] = str(error)
        return result

    def stack(registers):
        return [hex(reader.qword(registers.rsp + index * 8)) for index in range(8)]

    def notice(tid, event, registers=None, debug_status=None, state=None, details=None):
        key = (tid, event, registers.rip if registers is not None else None)
        if key in seen_notices:
            return
        seen_notices.add(key)
        counts["observer_notice"] += 1
        record = {
            "timestamp": time.time(), "pid": pid, "tid": tid,
            "direction": "observer_notice", "event": event,
            "index": counts["observer_notice"],
        }
        if registers is not None:
            record["rip"] = hex(registers.rip)
        if debug_status is not None:
            record["debug_status"] = hex(debug_status)
        if state is not None:
            record["wait_status"] = hex(state)
        if details:
            record.update(details)
        write(record)
        print(f"NOTICE tid={tid} event={event} rip={record.get('rip')}", flush=True)

    COUTPACKET_DTOR_RVA = 0x7615A0

    def start_duplicate(tid):
        state = duplicate_state[tid]
        state["first_return"] = time.time()
        state["first_return_monotonic"] = time.monotonic()
        state["post_first"] = reader.read(state["packet"], 0x500)
        state["caller_registers"] = observer.Registers()
        ctypes.memmove(
            ctypes.addressof(state["caller_registers"]), ctypes.addressof(registers),
            ctypes.sizeof(state["caller_registers"]),
        )
        state["clone"] = (registers.rsp - 0x1000) & ~0xF
        state["stage"] = "constructing"
        observer.ptrace(tid, 6, DEBUG_BASE + 7 * 8, saved[tid]["armed_control"] & ~(1 << 4))
        registers.rip = base + COUTPACKET_CTOR_RVA
        registers.rcx = state["clone"]
        registers.rdx = 0x32B
        observer.ptrace(tid, 13, 0, ctypes.addressof(registers))
        observer.ptrace(tid, 6, DEBUG_BASE + 6 * 8, 0)
        resume(tid)

    def prepare_second(tid):
        state = duplicate_state[tid]
        clone = state["clone"]
        override_tools.write_memory(pid, clone + 8, state["body"])
        _, second_body = read_packet(reader, clone, 0x434, 0x428)
        if second_body != state["body"]:
            raise RuntimeError("Duplicate plaintext differs from the original; refusing to send it.")
        state["second_body"] = second_body
        state["stage"] = "sending"
        observer.ptrace(tid, 6, DEBUG_BASE + 7 * 8, saved[tid]["armed_control"])
        registers.rip = base + SENDPACKET_RVA
        registers.rcx = clone
        observer.ptrace(tid, 13, 0, ctypes.addressof(registers))
        state["second_start"] = time.time()
        state["second_start_monotonic"] = time.monotonic()
        observer.ptrace(tid, 6, DEBUG_BASE + 6 * 8, 0)
        resume(tid)

    def finish_send(tid):
        state = duplicate_state[tid]
        state["second_done_monotonic"] = time.monotonic()
        state["stage"] = "destroying"
        registers.rip = base + COUTPACKET_DTOR_RVA
        registers.rcx = state["clone"]
        observer.ptrace(tid, 13, 0, ctypes.addressof(registers))
        observer.ptrace(tid, 6, DEBUG_BASE + 6 * 8, 0)
        resume(tid)

    def finish_duplicate(tid):
        state = duplicate_state.pop(tid)
        restored_object = reader.read(state["packet"], 0x500) == state["post_first"]
        observer.ptrace(tid, 13, 0, ctypes.addressof(state["caller_registers"]))
        observer.ptrace(tid, 6, DEBUG_BASE, base + SENDPACKET_RVA)
        observer.ptrace(tid, 6, DEBUG_BASE + 7 * 8, saved[tid]["armed_control"])
        second_start_monotonic = state["second_start_monotonic"]
        second_done_monotonic = state["second_done_monotonic"]
        result = {
            "timestamp": state["second_start"], "pid": pid, "tid": tid, "direction": "duplicate_send",
            "packet_va": hex(state["clone"]), "original_packet_va": hex(state["packet"]),
            "body": state["second_body"].hex(),
            "identical_to_original": state["second_body"] == state["body"],
            "first_entry": state["first_entry"], "first_return": state["first_return"],
            "second_start": state["second_start"], "second_done": time.time(),
            "first_return_to_second_start_us": round(
                (second_start_monotonic - state["first_return_monotonic"]) * 1_000_000, 3
            ),
            "second_call_us": round((second_done_monotonic - second_start_monotonic) * 1_000_000, 3),
            "total_us": round((second_done_monotonic - state["first_entry_monotonic"]) * 1_000_000, 3),
            "restored_object": restored_object, "clone_disposed": True, "completed": True,
        }
        write(result)
        print(
            f"DUPLICATE first_return_to_second_start_us={result['first_return_to_second_start_us']} "
            f"second_call_us={result['second_call_us']} restored_object={restored_object}",
            flush=True,
        )
        observer.ptrace(tid, 6, DEBUG_BASE + 6 * 8, 0)
        resume(tid)

    def restore_duplicate(tid):
        state = duplicate_state.pop(tid, None)
        if state is None:
            return
        restored = None
        if "post_first" in state:
            restored = reader.read(state["packet"], 0x500) == state["post_first"]
        write({
            "timestamp": time.time(), "pid": pid, "tid": tid, "direction": "duplicate_cleanup",
            "restored_object": restored, "clone_disposed": False, "completed": False,
            "reason": "duplicate call in flight" if "second_start" in state else "before second send",
        })

    try:
        for entry in sorted(Path(f"/proc/{pid}/task").iterdir(), key=lambda entry: int(entry.name)):
            tid = int(entry.name)
            try:
                observer.ptrace(tid, SEIZE)
            except OSError as error:
                if error.errno == 3:
                    continue
                raise
            attached[tid] = True
            try:
                arm(tid)
            except RuntimeError as error:
                if tid == pid or "already uses hardware breakpoint slot" not in str(error):
                    raise
                notice(tid, "breakpoint_occupied", details={"error": str(error)})
                try:
                    for slot in (7, 0, 1, 2, 3, 6):
                        observer.ptrace(tid, 6, DEBUG_BASE + slot * 8, saved[tid][slot])
                    observer.ptrace(tid, DETACH, 0, pending.pop(tid, 0))
                except OSError as detach_error:
                    if detach_error.errno != 3:
                        raise
                attached.pop(tid, None)
                saved.pop(tid, None)
                stopped.discard(tid)
                watches.pop(tid, None)
        if not attached:
            raise RuntimeError("No game threads could be attached.")
        behavior = (
            "Duplicate the first 0x32b once with no field edits." if duplicate_enabled
            else f"RNG_MODE={rng_mode}: replay the selected words on every attack after the native control; restore after each send."
            if replay_words is not None
            else f"RNG_MODE={rng_mode}: replay the second attack and restore its original state after sending."
            if rng_mode in ("replay", "both")
            else "Log combat RNG generator calls; no memory writes." if rng_mode == "observe"
            else "No memory or packet writes." if mode == 0 else "Scoped test overrides enabled."
        )
        print(
            f"ARMED pid={pid} threads={len(attached)}: plaintext sends, constructors, and inbound dispatch "
            f"for {duration}s. {behavior}",
            flush=True,
        )
        started = time.monotonic()
        last_status = started
        while not stopping and time.monotonic() - started < duration:
            now = time.monotonic()
            if any(
                state.get("second_start_monotonic") and now - state["second_start_monotonic"] > 2
                for state in duplicate_state.values()
            ):
                raise RuntimeError("Duplicate SendPacket did not return within two seconds.")
            if now - last_status >= 5:
                print(f"TRAFFIC {counts} attached_threads={len(attached)}", flush=True)
                last_status = now
            try:
                tid, state = wait_any(0.1)
            except TimeoutError:
                continue
            if tid not in attached:
                continue
            if os.WIFEXITED(state) or os.WIFSIGNALED(state) or (os.WIFSTOPPED(state) and state >> 16 == 5):
                notice(tid, "thread_exit", state=state)
                edit = outbound_edits.get(tid)
                if edit is not None:
                    restored, details = restore_edit(pid, reader, edit)
                    write({
                        "timestamp": time.time(), "pid": pid, "tid": tid,
                        "direction": "outbound_exit_restore", "test_mode": mode,
                        "restored": restored, **details,
                    })
                    if restored:
                        outbound_edits.pop(tid)
                    else:
                        raise RuntimeError(f"{details['kind']} did not restore after thread exit.")
                attached.pop(tid, None)
                stopped.discard(tid)
                saved.pop(tid, None)
                pending.pop(tid, None)
                watches.pop(tid, None)
                rng_slots.pop(tid, None)
                rng_pending.pop(tid, None)
                continue
            if not os.WIFSTOPPED(state):
                raise RuntimeError(f"Unexpected wait status {state:#x} for thread {tid}.")
            stopped.add(tid)
            number = os.WSTOPSIG(state)
            if number != signal.SIGTRAP:
                pending[tid] = number
                resume(tid)
                continue
            registers = observer.Registers()
            observer.ptrace(tid, 12, 0, ctypes.addressof(registers))
            debug_status = observer.ptrace(tid, 3, DEBUG_BASE + 6 * 8)
            if (
                duplicate_enabled and tid in duplicate_state and debug_status & 1
                and registers.rip == duplicate_state[tid]["return_address"]
            ):
                stage = duplicate_state[tid]["stage"]
                if stage == "first_pending":
                    start_duplicate(tid)
                elif stage == "constructing":
                    prepare_second(tid)
                elif stage == "sending":
                    finish_send(tid)
                else:
                    finish_duplicate(tid)
                continue
            if tid in inbound_edits and debug_status & 2 and registers.rip == base + INBOUND_RETURN_RVA:
                edit = inbound_edits.pop(tid)
                restored = restore_scalar(
                    pid, reader, edit["address"], edit["size"], edit["modified"], edit["original"]
                )
                write({
                    "timestamp": time.time(), "pid": pid, "tid": tid, "direction": "inbound_restore",
                    "test_mode": mode, "object_id": hex(edit["object_id"]),
                    "original_amount": edit["original"], "modified_amount": edit["modified"],
                    "restored": restored,
                })
                observer.ptrace(tid, 6, DEBUG_BASE + 8, base + INBOUND_CALL_RVA)
                observer.ptrace(tid, 6, DEBUG_BASE + 6 * 8, 0)
                resume(tid)
                continue
            if (
                tid in outbound_edits and debug_status & 1
                and registers.rip == outbound_edits[tid].get("return_address")
            ):
                edit = outbound_edits[tid]
                restored, details = restore_edit(pid, reader, edit)
                write({
                    "timestamp": time.time(), "pid": pid, "tid": tid, "direction": "outbound_restore",
                    "test_mode": mode, "restored": restored, **details,
                })
                if restored:
                    outbound_edits.pop(tid)
                observer.ptrace(tid, 6, DEBUG_BASE, base + SENDPACKET_RVA)
                observer.ptrace(tid, 6, DEBUG_BASE + 6 * 8, 0)
                if not restored:
                    raise RuntimeError(f"{details['kind']} did not restore exactly.")
                if edit["kind"] == "rng_state" and rng_mode == "both":
                    switch_rng_slots(tid, RNG_GENERATOR_RVA, rng.model.SELECTOR_RVA)
                resume(tid)
                continue
            if debug_status & 8 and rng_mode == "off":
                if tid not in watches:
                    notice(tid, "unexpected_length_watch", registers, debug_status, state)
                    pending[tid] = number
                    resume(tid)
                    continue
                watch = watches[tid]
                length = reader.unpack("<I", watch["packet"] + 0x428)[0]
                if length < watch["previous_length"] or length > watch["expected_length"]:
                    details = packet_diagnostics(watch["packet"])
                    details.update({"length": length, "previous_length": watch["previous_length"]})
                    notice(tid, "invalid_intermediate_length", registers, debug_status, state, details)
                    clear_watch(tid)
                    observer.ptrace(tid, 6, DEBUG_BASE + 6 * 8, 0)
                    resume(tid)
                    continue
                if length > 2:
                    body = reader.read(watch["packet"] + 8, length)
                    field = {
                        "timestamp": time.time(), "pid": pid, "tid": tid, "direction": "field_trace",
                        "opcode": watch["opcode"], "packet_va": hex(watch["packet"]),
                        "rip": hex(registers.rip), "previous_length": watch["previous_length"],
                        "length": length, "body": body.hex(),
                    }
                    watch["fields"].append(field)
                    counts["field_trace"] += 1
                    field["index"] = counts["field_trace"]
                    write(field)
                watch["previous_length"] = length
                if length == watch["expected_length"]:
                    finish_watch(tid)
                observer.ptrace(tid, 6, DEBUG_BASE + 6 * 8, 0)
                resume(tid)
                continue
            slot = targets.get(registers.rip)
            if rng_mode == "both" and tid in rng_slots:
                dynamic = {address: number for number, address in rng_slots[tid].items()}
                if registers.rip in dynamic:
                    slot = dynamic[registers.rip]
                elif slot in (2, 3):
                    slot = None
            if slot is None or not debug_status & (1 << slot):
                notice(tid, "unexpected_trap", registers, debug_status, state)
                pending[tid] = number
                resume(tid)
                continue
            timestamp = time.time()
            if slot in (2, 3) and registers.rip == base + RNG_GENERATOR_RVA:
                record = generator_event(tid, timestamp, registers)
            elif slot == 3:
                record = select_rng(tid, timestamp, registers)
                if record is None:
                    observer.ptrace(tid, 6, DEBUG_BASE + 6 * 8, 0)
                    resume(tid)
                    continue
            if slot == 0:
                packet = registers.rcx
                try:
                    opcode, body = read_packet(reader, packet, 0x434, 0x428)
                except (OSError, RuntimeError, struct.error) as error:
                    details = packet_diagnostics(packet)
                    details["error"] = str(error)
                    if tid in watches:
                        details["field_trace"] = watches[tid]["fields"]
                        clear_watch(tid)
                    notice(tid, "invalid_outgoing", registers, debug_status, state, details)
                    observer.ptrace(tid, 6, DEBUG_BASE + 6 * 8, 0)
                    resume(tid)
                    continue
                if duplicate_enabled and not duplicate_armed and opcode == 0x32B:
                    duplicate_armed = True
                    duplicate_state[tid] = {
                        "packet": packet, "snapshot": reader.read(packet, 0x500), "body": body,
                        "return_address": reader.qword(registers.rsp),
                        "first_entry": timestamp, "first_entry_monotonic": time.monotonic(),
                        "stage": "first_pending",
                    }
                    observer.ptrace(tid, 6, DEBUG_BASE, duplicate_state[tid]["return_address"])
                record = {
                    "timestamp": timestamp, "pid": pid, "tid": tid, "direction": "client_to_server",
                    "opcode": hex(opcode), "body": body.hex(), "length": len(body),
                    "packet_va": hex(packet), "body_va": hex(packet + 8),
                    "caller": stack(registers)[0], "return_stack": stack(registers),
                }
                if opcode == 0x32B and struct.unpack_from("<I", body, 0x0F)[0] in meso_drops:
                    record["meso_amount"] = meso_drops[struct.unpack_from("<I", body, 0x0F)[0]]
                if experiment and opcode == 0x32B:
                    if not experiment_state["native"]:
                        experiment_state["native"] = True
                        record["experiment_stage"] = "native"
                    elif not experiment_state["done"]:
                        offset, size = experiment
                        original = struct.unpack_from({1: "B", 2: "H", 4: "I"}[size], body, offset)[0]
                        modified = (original + 1) & ((1 << (size * 8)) - 1)
                        outbound_edits[tid] = {
                            "address": packet + 8 + offset, "offset": offset, "size": size,
                            "original": original, "modified": modified,
                            "return_address": reader.qword(registers.rsp),
                        }
                        record["native_body"] = body.hex()
                        record["experiment_stage"] = "override"
                        record["override"] = {
                            "field": hex(offset), "original": original, "modified": modified,
                        }
                        write_scalar(pid, reader, packet + 8 + offset, size, modified)
                        body = reader.read(packet + 8, len(body))
                        record["body"] = body.hex()
                        observer.ptrace(tid, 6, DEBUG_BASE, outbound_edits[tid]["return_address"])
                        experiment_state["done"] = True
                        print(
                            f"OVERRIDE 0x32b field={offset:#x} original={original} modified={modified}",
                            flush=True,
                        )
                    else:
                        record["experiment_stage"] = "control_after_override"
                if (tid, packet) in constructors:
                    record["constructor"] = constructors[(tid, packet)]
                if tid in watches:
                    record["field_trace"] = watches[tid]["fields"]
                    clear_watch(tid)
                if opcode == 0xE1:
                    record.update(rng_pending.pop(tid, {}))
                    if record.get("rng_stage") == "replay":
                        edit = outbound_edits[tid]
                        edit["return_address"] = reader.qword(registers.rsp)
                        observer.ptrace(tid, 6, DEBUG_BASE, edit["return_address"])
                    record["damage"] = struct.unpack_from("<i", body, 0x88)[0] if len(body) >= 0x8C else None
                    record["critical"] = body[0x87] if len(body) >= 0x88 else None
                    record["target_identifier"] = struct.unpack_from("<I", body, 0x7D)[0] if len(body) >= 0x81 else None
                    if rng_mode != "off":
                        attach_rng(record)
                        record["post_state"] = record.get("rng_state")
                        record["post_words"] = record.get("rng_words")
                    print(
                        f"ATTACK damage={record['damage']} stage={record.get('rng_stage', 'untraced')} "
                        f"record_id={body[0x20:0x24].hex()}", flush=True,
                    )
                elif opcode not in (0xDB, 0x2FE):
                    print(f"OUT tid={tid} opcode={opcode:#x} length={len(body)}", flush=True)
            elif slot == 1:
                packet = registers.rsp + 0x60
                record = read_incoming(reader, packet)
                if mode == 12:
                    candidate = read_hp_candidate(bytes.fromhex(record["body"]))
                    if candidate:
                        identifier, value = candidate
                        address = int(record["data_va"], 0) + 4 + 0x06
                        inbound_edits[tid] = {
                            "address": address, "size": 1, "object_id": identifier,
                            "original": value, "modified": 0,
                        }
                        record["native_body"] = record["body"]
                        record["override"] = {"field": "0x06", "original": value, "modified": 0}
                        if write_scalar(pid, reader, address, 1, 0) != value:
                            raise RuntimeError("0x3f3 value changed before the override.")
                        record["body"] = reader.read(
                            int(record["data_va"], 0) + 4, record["payload_length"]
                        ).hex()
                        observer.ptrace(tid, 6, DEBUG_BASE + 8, base + INBOUND_RETURN_RVA)
                        print(f"OVERRIDE 0x3f3 object={identifier:#x} value={value}->0", flush=True)
                drop = read_meso_drop(bytes.fromhex(record["body"]))
                if drop:
                    object_id, amount = drop
                    meso_drops.setdefault(object_id, amount)
                    record["meso_amount"] = amount
                    if mode == 1:
                        modified = amount * 2
                        address = int(record["data_va"], 0) + 4 + 0x15
                        inbound_edits[tid] = {
                            "address": address, "size": 4, "object_id": object_id,
                            "original": amount, "modified": modified,
                        }
                        record["native_body"] = record["body"]
                        record["override"] = {
                            "field": "0x15", "original": amount, "modified": modified,
                        }
                        if write_scalar(pid, reader, address, 4, modified) != amount:
                            raise RuntimeError("0x471 meso amount changed before the override.")
                        record["body"] = reader.read(
                            int(record["data_va"], 0) + 4, record["payload_length"]
                        ).hex()
                        observer.ptrace(tid, 6, DEBUG_BASE + 8, base + INBOUND_RETURN_RVA)
                        print(f"OVERRIDE 0x471 object={object_id:#x} meso={amount}->{modified}", flush=True)
                record.update({
                    "timestamp": timestamp, "pid": pid, "tid": tid, "direction": "server_to_client",
                    "socket_va": hex(registers.rcx), "length": len(bytes.fromhex(record["body"])),
                })
                body = bytes.fromhex(record["body"])
                opcode = struct.unpack_from("<H", body)[0]
                record["opcode"] = hex(opcode)
                if rng_mode != "off" and opcode in (0x3F3, 0x471):
                    attach_rng(record)
                    if opcode == 0x3F3 and len(body) == 11:
                        record["target_identifier"] = struct.unpack_from("<I", body, 2)[0]
                        record["hp_candidate"] = body[6]
                    elif opcode == 0x471 and len(body) >= 0x2E:
                        record["drop_object_id"] = struct.unpack_from("<I", body, 4)[0]
                        record["drop_value"] = struct.unpack_from("<I", body, 0x15)[0]
                        record["target_identifier"] = struct.unpack_from("<I", body, 0x2A)[0]
            elif slot == 2:
                packet = registers.rcx
                opcode = registers.rdx & 0xFFFFFFFF
                record = {
                    "timestamp": timestamp, "pid": pid, "tid": tid, "direction": "constructor",
                    "opcode": hex(opcode), "packet_va": hex(packet),
                    "caller": stack(registers)[0], "return_stack": stack(registers),
                }
                constructors[(tid, packet)] = record
                if rng_mode == "off" and opcode in (0x32B, 0x407):
                    set_watch(tid, packet, hex(opcode))
            counts[record["direction"]] += 1
            record["index"] = counts[record["direction"]]
            write(record)
            observer.ptrace(tid, 6, DEBUG_BASE + 6 * 8, 0)
            resume(tid)
    finally:
        cleanup_errors = []
        for tid in list(attached):
            try:
                stop(tid)
                had_duplicate = tid in duplicate_state
                restore_duplicate(tid)
                if had_duplicate and pending.get(tid) == signal.SIGTRAP:
                    pending[tid] = 0
                for direction, edits in (("inbound", inbound_edits), ("outbound", outbound_edits)):
                    edit = edits.get(tid)
                    if edit is None:
                        continue
                    try:
                        restored, details = restore_edit(pid, reader, edit)
                        write({
                            "timestamp": time.time(), "pid": pid, "tid": tid,
                            "direction": direction + "_cleanup_restore", "test_mode": mode,
                            "restored": restored, **details,
                        })
                        if restored:
                            edits.pop(tid)
                        else:
                            cleanup_errors.append(f"thread {tid}: {direction} buffer was not restored")
                    except (OSError, RuntimeError) as error:
                        cleanup_errors.append(f"thread {tid}: {direction} restore failed: {error}")
                    if pending.get(tid) == signal.SIGTRAP:
                        pending[tid] = 0
                if tid in saved:
                    for slot in (7, 0, 1, 2, 3, 6):
                        observer.ptrace(tid, 6, DEBUG_BASE + slot * 8, saved[tid][slot])
                observer.ptrace(tid, DETACH, 0, pending.pop(tid, 0))
            except (OSError, RuntimeError) as error:
                cleanup_errors.append(f"thread {tid}: {error}")
        stream.close()
        reader.close()
        for number, handler in handlers.items():
            signal.signal(number, handler)
        if cleanup_errors:
            print("DETACH errors: " + "; ".join(cleanup_errors), file=sys.stderr, flush=True)
        else:
            print("DETACHED: original debug registers restored on all attached threads.", flush=True)
        print(f"WROTE {output}: {counts}", flush=True)


def main():
    if len(sys.argv) != 4:
        raise SystemExit("Usage: packet-observe.py PID|auto SECONDS OUT.jsonl")
    duration = float(sys.argv[2])
    if not 1 <= duration <= 3600:
        raise SystemExit("Use a capture duration from 1 to 3600 seconds.")
    pid = character.find_pid("MapleStory.exe") if sys.argv[1] == "auto" else int(sys.argv[1])
    run(pid, duration, sys.argv[3])


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, struct.error) as error:
        print(f"Packet observation failed: {error}", file=sys.stderr)
        raise SystemExit(1)
