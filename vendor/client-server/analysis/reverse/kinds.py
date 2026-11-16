"""Recover the first kind constant written by C 0x1ef build sites."""

from __future__ import annotations

import re

from .annotate import call_target
from .image import MAPLESTORY_TIMESTAMP

CTOR = 0x7614B0
SEND = 0x1661780
ENCODE4 = 0x761960
ENCODE_BUFFER = 0x761EA0
SLOT = r"(r[sb]p(?: [+-] 0x[0-9a-f]+)?)"
STORE_IMM = re.compile(r"dword ptr \[" + SLOT + r"\], (0x[0-9a-f]+|\d+)$")
STORE_REG = re.compile(r"dword ptr \[" + SLOT + r"\], (e[a-z]+|r\d+d)$")
LOAD_SLOT = re.compile(r"rdx, \[" + SLOT + r"\]$")
EXPECTED_BUILDERS = {0x98BBF0: 1, 0xD15B10: 0x76, 0xD15860: 0x76}


def opcode_before(image, call):
    for ins in reversed(image.decode_to(call)[-12:]):
        ops = ins.op_str.split(", ")
        if ins.mnemonic == "mov" and ops[0] in ("edx", "rdx"):
            if ops[1].startswith("0x") or ops[1].isdigit():
                return int(ops[1], 0)
            return None
        if ins.mnemonic in ("xor", "lea") and ops[0] in ("edx", "rdx"):
            return None
    return None


def stored_value(stores, registers, slot):
    value = stores.get(slot)
    if isinstance(value, str) and value.startswith("reg:"):
        return registers.get(value[4:], value)
    return value


def helper_encodes_buffer(image, target):
    bounds = image.func(target)
    if bounds and bounds[1] - bounds[0] > 0x1000:
        return False
    end = bounds[1] if bounds else target + 0x40
    return any(call_target(ins) is not None and call_target(ins) - image.base == ENCODE_BUFFER
               for ins in image.disasm(target, end, count=12))


def first_buffer_kind(image, site):
    bounds = image.func(site)
    if not bounds:
        return None
    stores, registers, last = {}, {}, None
    seen = False
    for ins in image.disasm(bounds[0], bounds[1]):
        at = ins.address - image.base
        match = STORE_IMM.fullmatch(ins.op_str)
        if ins.mnemonic == "mov" and match:
            stores[match.group(1)] = int(match.group(2), 0)
        match = STORE_REG.fullmatch(ins.op_str)
        if ins.mnemonic == "mov" and match:
            stores[match.group(1)] = "reg:" + match.group(2)
        match = LOAD_SLOT.fullmatch(ins.op_str)
        if ins.mnemonic == "lea" and match:
            last = match.group(1)
        ops = ins.op_str.split(", ")
        if ins.mnemonic == "mov" and len(ops) == 2 and (ops[1].startswith("0x") or ops[1].isdigit()):
            registers[ops[0]] = int(ops[1], 0)
        if at == site:
            seen = True
            continue
        if not seen:
            continue
        target = call_target(ins)
        target = target - image.base if target is not None else None
        if target == ENCODE_BUFFER:
            return stored_value(stores, registers, last)
        if target is not None and last is not None and helper_encodes_buffer(image, target):
            value = stored_value(stores, registers, last)
            if value is not None:
                return value
        if target == ENCODE4:
            return "Encode4"
        if target in (SEND, 0x763560):
            return None
    return None


def kind_sites(image, opcode=0x1EF):
    if image.timestamp != MAPLESTORY_TIMESTAMP:
        raise ValueError(f"kind-site addresses require PE timestamp {MAPLESTORY_TIMESTAMP:#x}")
    out = []
    for site in sorted(image.callers.get(CTOR, ())):
        if opcode_before(image, site) != opcode:
            continue
        bounds = image.func(site)
        if bounds:
            out.append({"site": site, "builder": bounds[0], "kind": first_buffer_kind(image, site)})
    return out


def check(sites):
    found = {site["builder"]: site["kind"] for site in sites}
    missing = {builder: kind for builder, kind in EXPECTED_BUILDERS.items() if found.get(builder) != kind}
    if missing:
        raise AssertionError("kind-site checks failed: " + ", ".join(
            f"{builder:#x} != {kind:#x}" for builder, kind in missing.items()))
    return {f"{builder:#x}": kind for builder, kind in EXPECTED_BUILDERS.items()}
