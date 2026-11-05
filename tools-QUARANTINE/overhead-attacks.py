"""Shared scoped polearm-overhead and ordinary-collision MISS helper."""

import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import sys
import time


DIRECTORY = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "reset_observer", DIRECTORY / "observe-position-reset.py"
)
observer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(observer)
character = observer.character


class CollisionCycle:
    def __init__(self, misses_before_normal=0):
        if misses_before_normal < 0:
            raise ValueError("Misses before a normal collision cannot be negative.")
        self.limit = misses_before_normal
        self.remaining = misses_before_normal

    @property
    def forcing(self):
        return self.limit == 0 or self.remaining > 0

    def complete(self):
        if self.limit:
            self.remaining = self.remaining - 1 if self.remaining else self.limit


def load_collision():
    spec = importlib.util.spec_from_file_location(
        "collision_trial", DIRECTORY / "try-collision-miss.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def eligible(context, settings):
    category = context["weapon_id"] // 10000
    common = (
        context["actor"] != 0
        and context["frame_actor"] == context["actor"]
        and category in settings["weapon_categories"]
        and context["weapon_type"] == category - 100
        and context["family"] in settings["families"]
    )
    if not common:
        return False
    if context["path"] == "basic":
        return (
            context["skill_pointer"] == context["skill_register"] == 0
            and context["skill_id"] == context["skill_id_register"] == 0
            and context["weapon_id"] == context["weapon_register"]
        )
    return (
        context["path"] == "skill"
        and str(context["skill_id"]) in settings["skills"]
        and context["skill_pointer"] != 0
        and context["skill_pointer"] == context["skill_register"]
        and context["skill_id"] == context["skill_id_register"] == context["skill_object_id"]
        and context["skill_level"] == context["skill_level_register"] > 0
        and context["family"] == context["family_register"]
    )


def selected_action(action, context, settings, force):
    if force and eligible(context, settings) and action in settings["stab_actions"]:
        return settings["replacement_action"]
    return action


def verify_code(reader, base, settings):
    names = ["selector", "caller"]
    if settings.get("skill_selector_return_rva") is not None:
        names.append("skill_caller")
    for name in names:
        code = reader.read(
            base + character.number(settings[f"{name}_rva"]),
            character.number(settings[f"{name}_size"]),
        )
        if hashlib.sha256(code).hexdigest() != settings[f"{name}_sha256"]:
            raise RuntimeError(f"Attack {name} differs from the researched build.")


def read_context(reader, registers, root, settings, path):
    actor = reader.qword(root)
    if not actor:
        return None
    context = {
        "path": path,
        "actor": actor,
        "weapon_id": reader.unpack(
            "<I", actor + character.number(settings["weapon_id_offset"])
        )[0],
        "family": reader.unpack(
            "<I", actor + character.number(settings["action_family_offset"])
        )[0],
    }
    if path == "basic":
        context.update({
            "frame_actor": reader.qword(registers.rbp - 0x70),
            "skill_pointer": reader.qword(registers.rbp - 0x68),
            "skill_register": registers.r15,
            "skill_id": reader.unpack("<I", registers.rbp - 0x74)[0],
            "skill_id_register": registers.r13 & 0xFFFFFFFF,
            "weapon_register": registers.r14 & 0xFFFFFFFF,
            "weapon_type": registers.rsi & 0xFFFFFFFF,
        })
    else:
        if not registers.r14 or not registers.rsi:
            return None
        parameters = reader.qword(registers.r14 + 0x40)
        if not parameters:
            return None
        context.update({
            "frame_actor": reader.qword(registers.rbp + 7),
            "skill_pointer": reader.qword(parameters + 8),
            "skill_register": registers.rsi,
            "skill_id": reader.unpack("<I", parameters + 0x14)[0],
            "skill_id_register": registers.rbx & 0xFFFFFFFF,
            "skill_object_id": reader.unpack("<I", registers.rsi + 8)[0],
            "skill_level": reader.unpack("<I", parameters + 0x18)[0],
            "skill_level_register": registers.r12 & 0xFFFFFFFF,
            "weapon_type": registers.rdi & 0xFFFFFFFF,
            "family_register": registers.r13 & 0xFFFFFFFF,
        })
    return context


def owns_trap(pid, registers, targets):
    slot = targets.get(registers.rip)
    return slot is not None and bool(observer.ptrace(pid, 3, 848 + 6 * 8) & (1 << slot))


def pending_signal(pid, state, targets=None):
    if state >> 16:
        return 0
    number = os.WSTOPSIG(state)
    if number == signal.SIGTRAP and targets is not None:
        registers = observer.Registers()
        observer.ptrace(pid, 12, 0, ctypes.addressof(registers))
        if owns_trap(pid, registers, targets):
            return 0
    return number


def run(args, profile):
    pid = args.pid if args.pid is not None else character.find_pid(profile["process_name"])
    if Path(f"/proc/{pid}/comm").read_text().strip() != profile["process_name"]:
        raise RuntimeError("Selected PID does not identify MapleStory.exe.")
    reader = character.Reader(pid)
    attached = stopped = False
    saved = None
    deliver = 0
    stopping = False
    seen = changed = 0
    collisions = 0
    pending = {}
    collision = None
    cycle = CollisionCycle(args.misses_before_normal)

    def request_stop(signum, frame):
        nonlocal stopping
        stopping = True

    previous_handlers = {
        number: signal.signal(number, request_stop)
        for number in (signal.SIGINT, signal.SIGTERM)
    }
    try:
        base, _ = character.find_image(reader, pid, profile)
        settings = profile["polearm_attacks"]
        root = base + character.number(profile["rvas"]["character_global"])
        targets = {}
        if args.observe_selector:
            verify_code(reader, base, settings)
            targets = {base + character.number(settings["selector_rva"]): 0}
        elif args.force_overhead or not args.force_collision_miss:
            verify_code(reader, base, settings)
            targets = {
                base + character.number(settings["selector_return_rva"]): 0,
            }
            if settings.get("skill_selector_return_rva") is not None:
                targets[base + character.number(settings["skill_selector_return_rva"])] = 1
        if args.force_collision_miss:
            collision = load_collision()
            collision_settings = profile["incoming_display"]
            collision.verify_collision_code(reader, base, collision_settings)
            collision_slot = 2 if targets else 1
            targets.update({
                base + character.number(collision_settings["avoidance_result_rva"]): collision_slot,
            })
        slots = sorted(set(targets.values()))
        status = dict(
            line.split(":", 1)
            for line in Path(f"/proc/{pid}/status").read_text().splitlines()
        )
        if int(status["TracerPid"]) or status["State"].strip()[0] in "Tt":
            raise RuntimeError("Game already traced/paused. Detach CE and finish movement first.")
        observer.ptrace(pid, 0x4206)
        attached = True
        observer.ptrace(pid, 0x4207)
        state = observer.wait_stop(pid, 1)
        stopped = True
        deliver = pending_signal(pid, state)
        character.snapshot(reader, pid, base, profile)
        original_actor = reader.qword(root)
        saved = {
            slot: observer.ptrace(pid, 3, 848 + slot * 8) & 0xFFFFFFFFFFFFFFFF
            for slot in (*slots, 6, 7)
        }
        debug_control = saved[7]
        for target, slot in targets.items():
            if saved[7] & (3 << (slot * 2)):
                raise RuntimeError(f"Hardware breakpoint slot {slot} is occupied.")
        for target, slot in targets.items():
            observer.ptrace(pid, 6, 848 + slot * 8, target)
            debug_control = (
                debug_control & ~((0xF << (16 + slot * 4)) | (3 << (slot * 2)))
            ) | (1 << (slot * 2))
        observer.ptrace(pid, 6, 848 + 7 * 8, debug_control)
        observer.ptrace(pid, 7, 0, deliver)
        deliver = 0
        stopped = False
        print(
            f"ARMED pid={pid} overhead_only={args.force_overhead}; "
            f"collision_miss={args.force_collision_miss} misses_before_normal={cycle.limit}; "
            f"allow_active_attack_record={args.allow_active_attack_record}; "
            "strict local-player scopes; shared tables/code unchanged.",
            flush=True,
        )
        started = time.monotonic()
        deadline = started + args.seconds if args.seconds else None
        while not stopping and (deadline is None or time.monotonic() < deadline):
            if args.control_stdin and select.select([sys.stdin], [], [], 0)[0]:
                command = sys.stdin.readline()
                if not command or command.strip() == "stop":
                    break
                raise RuntimeError(f"Unknown controller command: {command.strip()!r}")
            try:
                state = observer.wait_stop(pid, 0.05)
            except TimeoutError:
                continue
            stopped = True
            stop_signal = os.WSTOPSIG(state)
            if state >> 16:
                raise RuntimeError(f"Unexpected ptrace event {state >> 16}.")
            if stop_signal != signal.SIGTRAP:
                observer.ptrace(pid, 7, 0, stop_signal)
                stopped = False
                continue
            registers = observer.Registers()
            observer.ptrace(pid, 12, 0, ctypes.addressof(registers))
            if not owns_trap(pid, registers, targets):
                deliver = stop_signal
                raise RuntimeError("Trap did not belong to the scoped attack breakpoint.")
            if collision is not None:
                if reader.qword(root) != original_actor:
                    raise RuntimeError("Local character changed; collision override stopped.")
                if targets[registers.rip] == collision_slot:
                    context = collision.collision_context(
                        reader, registers, root, base, collision_settings
                    )
                    if context is not None and collision.eligible(
                        context, collision_settings, args.allow_active_attack_record
                    ):
                        native = context["status"]
                        forcing = cycle.forcing
                        effective = 2 if forcing else native
                        if effective != native:
                            registers.rax = effective
                            observer.ptrace(pid, 13, 0, ctypes.addressof(registers))
                            check = observer.Registers()
                            observer.ptrace(pid, 12, 0, ctypes.addressof(check))
                            if bytes(check) != bytes(registers):
                                raise RuntimeError("Collision register update did not read back exactly.")
                        collisions += 1
                        cycle.complete()
                        print("COLLISION " + json.dumps({
                            "index": collisions, "native_status": native,
                            "effective_status": effective, "forcing": forcing,
                            "attack_record_status": context["attack_record_status"],
                            "miss_limit": cycle.limit, "remaining": cycle.remaining,
                            "next_forced": cycle.forcing,
                        }, sort_keys=True), flush=True)
                    else:
                        print("COLLISION-SKIP " + json.dumps({
                            "native_status": context.get("status") if context else None,
                            "monster_present": context.get("monster_present") if context else None,
                            "attack_record_status": context.get("attack_record_status") if context else None,
                            "attack_record_absent": context.get("attack_record_absent") if context else None,
                        }, sort_keys=True), flush=True)
                    observer.ptrace(pid, 7)
                    stopped = False
                    continue
            if args.observe_selector:
                seen += 1
                skill = registers.r8
                print(
                    f"SELECTOR {seen}: " + json.dumps({
                        "return_rva": hex(reader.qword(registers.rsp) - base),
                        "action": registers.rax & 0xFFFFFFFF,
                        "actor": hex(reader.qword(root)),
                        "family": registers.rcx & 0xFFFFFFFF,
                        "weapon_type": registers.rdx & 0xFFFFFFFF,
                        "skill_pointer": hex(skill),
                        "skill_id": reader.unpack("<I", skill + 8)[0] if skill else 0,
                        "skill_level": registers.r9 & 0xFFFFFFFF,
                        "registers": {
                            name: hex(getattr(registers, name))
                            for name in ("rbp", "rbx", "rsi", "rdi", "r12", "r13", "r14", "r15")
                        },
                    }, sort_keys=True),
                    flush=True,
                )
                if args.attacks and seen >= args.attacks:
                    break
                observer.ptrace(pid, 7)
                stopped = False
                continue
            path = "basic" if targets[registers.rip] == 0 else "skill"
            context = read_context(reader, registers, root, settings, path)
            action = registers.rax & 0xFFFFFFFF
            if context is not None and eligible(context, settings):
                seen += 1
                replacement = selected_action(action, context, settings, args.force_overhead)
                if replacement != action:
                    registers.rax = replacement
                    observer.ptrace(pid, 13, 0, ctypes.addressof(registers))
                    changed += 1
                print(
                    f"ATTACK {seen}: original={action} selected={replacement} "
                    f"weapon={context['weapon_id']} skill={context['skill_id']} "
                    f"elapsed={time.monotonic() - started:.3f}s",
                    flush=True,
                )
            else:
                print(
                    f"UNCHANGED: original={action}; attack outside the supported local polearm scope. "
                    + json.dumps(context, sort_keys=True),
                    flush=True,
                )
            if args.attacks and seen >= args.attacks:
                break
            observer.ptrace(pid, 7)
            stopped = False
        print(
            f"RESULT: {'selector_entries' if args.observe_selector else 'eligible_attacks'}={seen} "
            f"redirected_stabs={changed} "
            f"collisions={collisions} "
            f"elapsed={time.monotonic() - started:.3f}s",
            flush=True,
        )
        if args.attacks and seen < args.attacks:
            raise RuntimeError(f"Only observed {seen} of {args.attacks} requested attacks.")
    finally:
        try:
            if attached:
                if not stopped:
                    observer.ptrace(pid, 0x4207)
                    state = observer.wait_stop(pid, 1)
                    stopped = True
                    deliver = pending_signal(pid, state, targets)
                if saved is not None:
                    for slot in (7, *slots, 6):
                        observer.ptrace(pid, 6, 848 + slot * 8, saved[slot])
                observer.ptrace(pid, 17, 0, deliver)
                print("DETACHED: native overrides off; debug registers restored.", flush=True)
        finally:
            reader.close()
            for number, handler in previous_handlers.items():
                signal.signal(number, handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int)
    parser.add_argument("--force-overhead", action="store_true", help="Redirect eligible stabs before attack processing.")
    parser.add_argument("--force-collision-miss", action="store_true", help="Force MISS on the verified local collision path.")
    parser.add_argument("--allow-active-attack-record", action="store_true", help="Also test collisions with an active attack record; default preserves the absent-only gate.")
    parser.add_argument("--misses-before-normal", type=int, default=0, help="N collision misses, one native collision, repeat; 0 means continuous.")
    parser.add_argument("--seconds", type=float, default=90, help="Observation duration; 0 requires --control-stdin.")
    parser.add_argument("--attacks", type=int, default=0, help="Stop after this many eligible attacks.")
    parser.add_argument("--control-stdin", action="store_true", help="Accept stop/EOF from the GUI controller.")
    parser.add_argument("--observe-selector", action="store_true", help="Observe shared selector inputs/callers without changing selections.")
    args = parser.parse_args()
    if not 0 <= args.seconds <= 3600 or args.seconds == 0 and not args.control_stdin:
        parser.error("--seconds must be 1..3600, or 0 with --control-stdin.")
    if args.attacks < 0:
        parser.error("--attacks cannot be negative.")
    if args.misses_before_normal < 0 or args.misses_before_normal and not args.force_collision_miss:
        parser.error("--misses-before-normal requires collision MISS and cannot be negative.")
    if args.allow_active_attack_record and not args.force_collision_miss:
        parser.error("--allow-active-attack-record requires --force-collision-miss.")
    if args.observe_selector and (args.force_overhead or args.force_collision_miss):
        parser.error("--observe-selector cannot change attack selections.")
    profile = json.loads((DIRECTORY / "profile.json").read_text())
    run(args, profile)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError) as error:
        print(f"Native override failed: {error}", file=sys.stderr)
        sys.exit(1)
