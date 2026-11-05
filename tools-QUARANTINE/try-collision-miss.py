"""Validation gates for the scoped local-collision MISS override."""

import importlib.util
from pathlib import Path


DIRECTORY = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("incoming_display", DIRECTORY / "observe-incoming-display.py")
display = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(display)
character = display.character


def verify_collision_code(reader, base, settings):
    display.verify_code(reader, base, settings, decision=True)


def collision_context(reader, registers, root, base, settings):
    event = display.read_event(reader, registers, root, base, "decision", settings)
    if event is None:
        return None
    monster = registers.r13
    attack_record = registers.r14
    if monster:
        reader.read(monster, 4)
    attack_status = (
        reader.unpack(
            "<I", attack_record + character.number(settings["attack_record_status_offset"])
        )[0]
        if attack_record else 0
    )
    event.update({
        "monster_present": bool(monster),
        "monster_state": character.hexadecimal(monster),
        "attack_record_absent": not attack_record or attack_status == 0,
        "attack_record": character.hexadecimal(attack_record),
        "attack_record_status": attack_status,
    })
    return event


def _number(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def eligible(context, settings, allow_active_attack_record=False):
    return (
        context is not None
        and context.get("kind") == "decision"
        and _number(context.get("actor", 0)) != 0
        and context.get("monster_present") is True
        and (allow_active_attack_record or context.get("attack_record_absent") is True)
        and context.get("status") in (1, 2, 3)
        and _number(context.get("caller_frame", 0))
        == _number(context.get("expected_frame", 0)) + 0x1B7
    )
