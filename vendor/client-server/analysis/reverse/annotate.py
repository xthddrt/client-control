"""Disassembly annotated with packet calls, imports, strings and method slots."""

from __future__ import annotations

import re
import struct

DECODERS = {
    0x75C8E0: "CInPacket::Decode1",
    0x75C980: "CInPacket::Decode2",
    0x75CA20: "CInPacket::Decode4",
    0x75CD10: "CInPacket::Decode8",
    0x75CDB0: "CInPacket::DecodeDouble",
    0x75CE50: "CInPacket::DecodeStr",
    0x75D080: "CInPacket::DecodeBuffer",
}
ENCODERS = {
    0x7614B0: "COutPacket::ctor",
    0x7617D0: "COutPacket::Encode1",
    0x7618D0: "COutPacket::Encode2",
    0x761960: "COutPacket::Encode4",
    0x761B50: "COutPacket::Encode8",
    0x761BB0: "COutPacket::EncodeDouble",
    0x761C10: "COutPacket::EncodeStr",
    0x761EA0: "COutPacket::EncodeBuffer",
    0x1661780: "COutPacket::SendPacket",
}
PACKET_CALLS = DECODERS | ENCODERS
RIP = re.compile(r"\[rip ([+-]) 0x([0-9a-f]+)\]")


def call_target(ins):
    if ins.mnemonic in ("call", "jmp") and ins.op_str.startswith("0x"):
        return int(ins.op_str, 16)
    return None


def rip_target(ins, base):
    match = RIP.search(ins.op_str)
    if not match:
        return None
    offset = int(match.group(2), 16) * (1 if match.group(1) == "+" else -1)
    return ins.address + ins.size + offset - base


def format_instruction(image, ins):
    rva = ins.address - image.base
    parts = [f"{rva:#09x}: {ins.mnemonic:7} {ins.op_str}"]
    target = call_target(ins)
    if target is not None:
        target -= image.base
        label = PACKET_CALLS.get(target)
        parts.append(f"; -> {target:#x}" + (f" {label}" if label else ""))
    target = rip_target(ins, image.base)
    if target is not None:
        parts.append(f"; @{target:#x}")
        note = image.imports.get(target) or image.text_at(target)
        if note:
            parts.append(note)
        elif image.rdata[0] <= target < image.rdata[1] and target + 8 <= len(image.img):
            value = struct.unpack_from("<Q", image.img, target)[0] - image.base
            if value in image.start_set:
                parts.append(f"slot -> {value:#x}")
    return " ".join(parts)


def disassembly(image, start, end=None, count=None):
    return [format_instruction(image, ins) for ins in image.disasm(start, end, count)]


def decode_calls(image, start, end=None):
    out = []
    for ins in image.disasm(start, end):
        target = call_target(ins)
        if target is not None and target - image.base in DECODERS:
            out.append((ins.address - image.base, DECODERS[target - image.base]))
    return out
