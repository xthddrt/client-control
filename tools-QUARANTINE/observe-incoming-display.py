"""Observe local-character damage/MISS display branches without changing outcomes."""

import argparse
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
SPEC = importlib.util.spec_from_file_location("attack_observer", DIRECTORY / "overhead-attacks.py")
shared = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(shared)
observer = shared.observer
character = shared.character


def verify_code(reader, base, settings, decision=False, results=False):
    names = ["player_function", "miss_renderer"]
    if decision:
        names.extend(("hit_caller_function", "calculator_wrapper", "avoidance_function"))
    if results:
        names.extend(("stat_accessor", "hp_update_block", "result_serializer"))
    for name in names:
        data = reader.read(
            base + character.number(settings[f"{name}_rva"]),
            character.number(settings[f"{name}_size"]),
        )
        if hashlib.sha256(data).hexdigest() != settings[f"{name}_sha256"]:
            raise RuntimeError(f"Incoming display {name} differs from the researched build.")


def read_event(reader, registers, root, base, kind, settings=None):
    actor = reader.qword(root)
    if not actor:
        return None
    if kind in ("comparison", "decision"):
        if settings is None:
            raise RuntimeError("Decision observation requires the fingerprinted frame profile.")
        target = reader.qword(registers.rsp + 0xF0)
        if (
            target != actor
            or reader.qword(registers.rsp + 0xA8)
            != base + character.number(settings["avoidance_wrapper_return_rva"])
            or reader.qword(registers.rsp + 0x108)
            != base + character.number(settings["calculator_caller_return_rva"])
        ):
            return None
    else:
        target = registers.rcx if kind == "entry" else registers.r12
        if target != actor:
            return None
    event = {"kind": kind, "actor": hex(actor)}
    if kind in ("comparison", "decision"):
        caller_frame = reader.qword(registers.rsp + 0x118)
        event.update({
            "decision_frame": hex(registers.rsp),
            "caller_frame": hex(caller_frame),
            "expected_frame": hex(caller_frame - 0x1B7),
        })
        if kind == "comparison":
            event["input_fields"] = {
                name: reader.unpack("<i", address)[0]
                for name, address in (
                    ("first_object_0", registers.rbx),
                    ("first_object_a8", registers.rbx + 0xA8),
                    ("first_object_1c8", registers.rbx + 0x1C8),
                    ("first_object_258", registers.rbx + 0x258),
                    ("second_object_1c", registers.rsi + 0x1C),
                    ("second_object_10", registers.rsi + 0x10),
                )
            }
        else:
            status = registers.rax & 0xFFFFFFFF
            if status not in (1, 2, 3):
                raise RuntimeError(f"Unexpected native decision status {status}.")
            event["status"] = status
    elif kind == "entry":
        event.update({
            "signed_value": ctypes.c_int32(registers.rdx & 0xFFFFFFFF).value,
            "r8d": registers.r8 & 0xFFFFFFFF,
            "r9d": registers.r9 & 0xFFFFFFFF,
            "stack_arguments_5_to_6": [
                reader.unpack("<i", registers.rsp + offset)[0]
                for offset in (0x28, 0x30)
            ],
            "caller_return_rva": hex(reader.qword(registers.rsp) - base),
            "expected_frame": hex(registers.rsp - 0x4F),
        })
    else:
        value = reader.unpack("<i", registers.rbp + 0x5F)[0]
        if kind == "miss_display" and value != 0:
            raise RuntimeError("MISS branch has a nonzero display argument; refusing to classify it.")
        if kind == "damage_display" and value >= 0:
            raise RuntimeError("Damage branch has a nonnegative argument; refusing to classify it.")
        event.update({
            "signed_value": value,
            "frame": hex(registers.rbp),
            "x": ctypes.c_int32(registers.rdx & 0xFFFFFFFF).value,
            "y": ctypes.c_int32(registers.r8 & 0xFFFFFFFF).value,
            "r9": registers.r9,
            "caller_return_rva": hex(reader.qword(registers.rbp + 0x4F) - base),
        })
    return event


def comparison_values(raw):
    if len(raw) != 512:
        raise RuntimeError("Unexpected x86-64 floating-point register snapshot size.")
    return {
        name: struct.unpack_from("<d", raw, 160 + 16 * index)[0]
        for name, index in (
            ("scaled_draw", 0), ("score_b", 6), ("score_a", 8),
            ("difference_a_minus_b", 9), ("upper_multiplier", 11),
            ("secondary_draw", 12), ("tertiary_draw", 13),
        )
    }


def current_stats(reader, base, settings):
    context = reader.qword(base + character.number(settings["calculator_context_global_rva"]))
    if not context:
        raise RuntimeError("No current stat context.")
    stats = reader.qword(context + character.number(settings["stat_context_offset"]))
    if not stats:
        raise RuntimeError("No current character stats.")
    return stats


def read_result_event(reader, registers, root, base, kind, settings):
    if kind == "decision":
        return read_event(reader, registers, root, base, kind, settings)
    actor = reader.qword(root)
    if not actor:
        return None
    stats = current_stats(reader, base, settings)
    hp_address = stats + character.number(settings["hp_value_offset"])
    event = {"kind": kind, "actor": hex(actor)}
    if kind == "hp_update":
        if registers.rbx != stats:
            return None
        if not registers.rbp & 0x400:
            raise RuntimeError("HP writer reached without the expected HP stat-mask bit.")
        event.update({
            "hp_before": reader.protected_integer(hp_address),
            "hp_new": ctypes.c_int32(registers.rdi & 0xFFFFFFFF).value,
            "stat_mask": registers.rbp & 0xFFFFFFFF,
        })
    elif kind == "hit_entry":
        if registers.rcx != actor:
            return None
        event.update({
            "caller_frame": hex(registers.rsp - 0x9E8),
            "caller_return_rva": hex(reader.qword(registers.rsp) - base),
            "hp": reader.protected_integer(hp_address),
            "argument_7_present": bool(reader.qword(registers.rsp + 0x38)),
            "numeric_arguments": {
                "edx": ctypes.c_int32(registers.rdx & 0xFFFFFFFF).value,
                "r8d": ctypes.c_int32(registers.r8 & 0xFFFFFFFF).value,
                "r9d": ctypes.c_int32(registers.r9 & 0xFFFFFFFF).value,
                **{
                    f"argument_{number}": reader.unpack("<i", registers.rsp + offset)[0]
                    for number, offset in ((5, 0x28), (6, 0x30), (8, 0x40),
                                           (9, 0x48), (10, 0x50), (11, 0x58))
                },
            },
        })
    elif kind == "serialized_result":
        if registers.r15 != actor:
            return None
        if registers.rcx != registers.rbp + 0x240:
            raise RuntimeError("Hit-result argument does not match the fingerprinted caller frame.")
        status, damage, base_damage = reader.unpack("<iii", registers.rcx + 0x30)
        event.update({
            "caller_frame": hex(registers.rbp),
            "status": status, "damage": damage, "base_damage": base_damage,
            "descriptor": reader.unpack("<i", registers.rcx + 4)[0],
            "working_damage": reader.unpack("<i", registers.rcx + 8)[0],
            "hp": reader.protected_integer(hp_address),
        })
    else:
        raise RuntimeError(f"Unknown result-observation event: {kind}.")
    return event


def observe(args, profile):
    pid = args.pid if args.pid is not None else character.find_pid(profile["process_name"])
    if Path(f"/proc/{pid}/comm").read_text().strip() != profile["process_name"]:
        raise RuntimeError("Selected PID does not identify MapleStory.exe.")
    reader = character.Reader(pid)
    attached = stopped = False
    saved = None
    deliver = 0
    stopping = False
    events = []
    outcomes = misses = 0
    frames = {}
    comparisons = {}
    invocations = {}
    completed_at = None

    def request_stop(signum, frame):
        nonlocal stopping
        stopping = True

    handlers = {
        number: signal.signal(number, request_stop)
        for number in (signal.SIGINT, signal.SIGTERM)
    }
    try:
        base, _ = character.find_image(reader, pid, profile)
        settings = profile["incoming_display"]
        verify_code(reader, base, settings, args.decision or args.results, args.results)
        root = base + character.number(profile["rvas"]["character_global"])
        addresses = {
            base + character.number(settings["player_function_rva"]): (0, "entry"),
            base + character.number(settings["miss_call_rva"]): (1, "miss_display"),
            base + character.number(settings["damage_call_rva"]): (2, "damage_display"),
        }
        if args.decision:
            addresses = {
                base + character.number(settings["avoidance_compare_rva"]): (0, "comparison"),
                base + character.number(settings["avoidance_result_rva"]): (1, "decision"),
                base + character.number(settings["miss_call_rva"]): (2, "miss_display"),
                base + character.number(settings["damage_call_rva"]): (3, "damage_display"),
            }
        elif args.results:
            addresses = {
                base + character.number(settings["hit_caller_function_rva"]): (0, "hit_entry"),
                base + character.number(settings["avoidance_result_rva"]): (1, "decision"),
                base + character.number(settings["result_serialize_call_rva"]): (2, "serialized_result"),
                base + character.number(settings["hp_write_rva"]): (3, "hp_update"),
            }
        targets = {address: slot for address, (slot, kind) in addresses.items()}
        status = dict(
            line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines()
        )
        if int(status["TracerPid"]) or status["State"].strip()[0] in "Tt":
            raise RuntimeError("Game already traced/paused. Turn overhead-only off and detach CE.")
        observer.ptrace(pid, 0x4206)
        attached = True
        observer.ptrace(pid, 0x4207)
        state = observer.wait_stop(pid, 1)
        stopped = True
        deliver = shared.pending_signal(pid, state)
        character.snapshot(reader, pid, base, profile)
        if args.results:
            stats = current_stats(reader, base, settings)
            reader.protected_integer(stats + character.number(settings["hp_value_offset"]))
        saved = {
            slot: observer.ptrace(pid, 3, 848 + slot * 8) & 0xFFFFFFFFFFFFFFFF
            for slot in (0, 1, 2, 3, 6, 7)
        }
        for slot in targets.values():
            if saved[7] & (3 << (slot * 2)):
                raise RuntimeError(f"Hardware breakpoint slot {slot} is occupied.")
        control = saved[7]
        for address, slot in targets.items():
            observer.ptrace(pid, 6, 848 + slot * 8, address)
            control = (
                control & ~((0xF << (16 + slot * 4)) | (3 << (slot * 2)))
            ) | (1 << (slot * 2))
        observer.ptrace(pid, 6, 848 + 7 * 8, control)
        observer.ptrace(pid, 7, 0, deliver)
        deliver = 0
        stopped = False
        print(
            f"ARMED pid={pid}: observe incoming attacks now; "
            f"{'collision origins, native results and HP updates' if args.results else 'decision comparisons/status plus actual displays' if args.decision else 'local display branches only'}; "
            "all arguments and outcomes remain unchanged.",
            flush=True,
        )
        started = time.monotonic()
        while not stopping and time.monotonic() - started < args.seconds:
            if completed_at is not None and time.monotonic() - completed_at >= 1:
                break
            try:
                state = observer.wait_stop(pid, 0.05)
            except TimeoutError:
                continue
            stopped = True
            number = os.WSTOPSIG(state)
            if state >> 16:
                raise RuntimeError(f"Unexpected ptrace event {state >> 16}.")
            if number != signal.SIGTRAP:
                observer.ptrace(pid, 7, 0, number)
                stopped = False
                continue
            registers = observer.Registers()
            observer.ptrace(pid, 12, 0, ctypes.addressof(registers))
            if not shared.owns_trap(pid, registers, targets):
                deliver = number
                raise RuntimeError("Trap did not belong to the incoming-display observer.")
            kind = addresses[registers.rip][1]
            read = read_result_event if args.results else read_event
            event = read(reader, registers, root, base, kind, settings)
            if event is not None:
                event["elapsed"] = round(time.monotonic() - started, 3)
                event["rva"] = hex(registers.rip - base)
                if args.results:
                    event["index"] = len(events)
                    if kind == "hit_entry":
                        invocations[event["caller_frame"]] = event
                    elif kind == "decision":
                        entry = invocations.get(event["caller_frame"])
                        if entry is not None and entry["kind"] == "hit_entry":
                            event["entry_index"] = entry["index"]
                        invocations[event["caller_frame"]] = event
                    elif kind == "serialized_result":
                        source = invocations.pop(event["caller_frame"], None)
                        if source is not None and source["actor"] == event["actor"]:
                            event[f"{'decision' if source['kind'] == 'decision' else 'entry'}_index"] = source["index"]
                            if "entry_index" in source:
                                event["entry_index"] = source["entry_index"]
                        outcomes += 1
                        misses += event["status"] == 2
                elif kind == "comparison":
                    raw = ctypes.create_string_buffer(512)
                    observer.ptrace(pid, 14, 0, ctypes.addressof(raw))
                    event["comparison"] = comparison_values(raw.raw)
                    event["index"] = len(events)
                    comparisons[event["decision_frame"]] = event
                elif kind == "decision":
                    event["index"] = len(events)
                    comparison = comparisons.pop(event["decision_frame"], None)
                    if comparison is not None and comparison["actor"] == event["actor"]:
                        event["comparison_index"] = comparison["index"]
                    frames[event["expected_frame"]] = event
                elif kind == "entry":
                    event["index"] = len(events)
                    frames[event["expected_frame"]] = event
                else:
                    same_caller = not args.decision or event["caller_return_rva"] == settings[
                        "observed_hit_caller_return_rva"
                    ]
                    entry = frames.pop(event["frame"], None) if same_caller else None
                    if entry is not None and entry["actor"] == event["actor"]:
                        if entry["kind"] == "decision":
                            event["decision_index"] = entry["index"]
                            caller_frame = character.number(entry["caller_frame"])
                            event["calculator_status"], event["calculator_damage"] = reader.unpack(
                                "<ii", caller_frame + 8
                            )
                            event["base_numeric_damage"] = reader.unpack("<i", caller_frame + 0x38)[0]
                        else:
                            event["entry_index"] = entry["index"]
                    outcomes += 1
                    misses += kind == "miss_display"
                events.append(event)
                print(json.dumps(event, sort_keys=True), flush=True)
                if (
                    len(events) >= 1000 or len(frames) > 128 or len(comparisons) > 128
                    or len(invocations) > 128
                ):
                    raise RuntimeError("Observation volume exceeded its bounded capture limits.")
            if outcomes >= args.events:
                if args.results:
                    if completed_at is None:
                        completed_at = time.monotonic()
                else:
                    break
            observer.ptrace(pid, 7)
            stopped = False
        result = {
            "observation_only": True, "pid": pid, "module_base": hex(base),
            "events": events,
            "decision_observation": args.decision,
            "result_observation": args.results,
            "notice": "Native code observations; server authority and semantic field names remain unproved.",
        }
        if args.results:
            result.update({
                "serialized_outcomes": outcomes, "status_2_results": misses,
                "hp_updates": sum(event["kind"] == "hp_update" for event in events),
            })
        else:
            result.update({
                "display_outcomes": outcomes, "miss_displays": misses,
                "damage_displays": outcomes - misses,
            })
        if args.output is not None:
            args.output.write_text(json.dumps(result, indent=2) + "\n")
        if args.results:
            print(f"RESULT: serialized_outcomes={outcomes} status_2={misses} HP_updates={result['hp_updates']}", flush=True)
        else:
            print(f"RESULT: display_outcomes={outcomes} MISS={misses} damage={outcomes - misses}", flush=True)
        return result
    finally:
        try:
            if attached:
                if not stopped:
                    observer.ptrace(pid, 0x4207)
                    state = observer.wait_stop(pid, 1)
                    deliver = shared.pending_signal(pid, state, targets)
                if saved is not None:
                    for slot in (7, 0, 1, 2, 3, 6):
                        observer.ptrace(pid, 6, 848 + slot * 8, saved[slot])
                observer.ptrace(pid, 17, 0, deliver)
                print("DETACHED: original debug registers restored; no outcomes changed.", flush=True)
        finally:
            reader.close()
            for number, handler in handlers.items():
                signal.signal(number, handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int)
    parser.add_argument("--seconds", type=float, default=120)
    parser.add_argument("--events", type=int, default=30)
    parser.add_argument("--output", type=Path)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--decision", action="store_true", help="Correlate guarded native comparisons/status with displays.")
    modes.add_argument("--results", action="store_true", help="Observe hit origins, structured results and HP updates without payload dumps.")
    args = parser.parse_args()
    if not 1 <= args.seconds <= 180 or not 1 <= args.events <= 100:
        parser.error("Use 1..180 seconds and 1..100 displayed outcomes.")
    observe(args, json.loads((DIRECTORY / "profile.json").read_text()))


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError) as error:
        print(f"Incoming-display observation failed: {error}", file=sys.stderr)
        sys.exit(1)
