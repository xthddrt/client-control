"""Trace outgoing packet constructors and encoders in the fingerprinted executable."""

import argparse
import bisect
import struct
from pathlib import Path

import capstone
from capstone import x86


COUTPACKET_CTOR = 0x7614B0
SENDPACKET = 0x1661780
ENCODERS = {
    0x7617D0: "Encode1",
    0x7618D0: "Encode2",
    0x761960: "Encode4",
    0x761B50: "Encode8",
    0x761BB0: "EncodeDouble",
    0x761C10: "EncodeString",
    0x761EA0: "EncodeBuffer",
}
OBSERVED_OPCODES = (
    0x70, 0xDB, 0xE1, 0xE7, 0xF4, 0xF5, 0x13F, 0x1A7, 0x1EF,
    0x233, 0x234, 0x235, 0x265, 0x266, 0x2A5, 0x2EF, 0x2FE, 0x326, 0x32B, 0x407,
)


class Image:
    def __init__(self, path):
        self.path = Path(path)
        with self.path.open("rb") as stream:
            header = stream.read(4096)
            pe = struct.unpack_from("<I", header, 0x3C)[0]
            if header[:2] != b"MZ" or header[pe:pe + 4] != b"PE\0\0":
                raise ValueError("Expected a PE executable.")
            if struct.unpack_from("<H", header, pe + 4)[0] != 0x8664:
                raise ValueError("Expected an x86-64 executable.")
            section_count = struct.unpack_from("<H", header, pe + 6)[0]
            optional_size = struct.unpack_from("<H", header, pe + 20)[0]
            optional = pe + 24
            if struct.unpack_from("<H", header, optional)[0] != 0x20B:
                raise ValueError("Expected a PE32+ executable.")
            self.base = struct.unpack_from("<Q", header, optional + 24)[0]
            self.timestamp = struct.unpack_from("<I", header, pe + 8)[0]
            self.sections = []
            for index in range(section_count):
                offset = optional + optional_size + 40 * index
                name = header[offset:offset + 8].rstrip(b"\0").decode("ascii")
                virtual_size, rva, raw_size, raw = struct.unpack_from("<IIII", header, offset + 8)
                self.sections.append((name, rva, virtual_size, raw, raw_size))
            self.data = {
                name: self._read_section(stream, rva, raw_size, raw)[:virtual_size]
                for name, rva, virtual_size, raw, raw_size in self.sections
            }
        self.text = self.data[".text"]
        self.text_rva = next(section[1] for section in self.sections if section[0] == ".text")
        self.functions = sorted(
            (start, end) for start, end, _ in struct.iter_unpack("<III", self.data[".pdata"])
        )
        self.function_starts = [start for start, _ in self.functions]
        self.disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.disassembler.detail = True
        if self.read(SENDPACKET, 8) != bytes.fromhex("48894c24084883ec"):
            raise ValueError("SendPacket fingerprint differs; re-anchor the protocol offsets.")
        if self.read(COUTPACKET_CTOR + 0x3A, 6) != bytes.fromhex("899134040000"):
            raise ValueError("COutPacket constructor fingerprint differs; re-anchor the offsets.")

    @staticmethod
    def _read_section(stream, rva, raw_size, raw):
        stream.seek(raw)
        data = stream.read(raw_size)
        if len(data) != raw_size:
            raise ValueError(f"Short executable section at RVA {rva:#x}.")
        return data

    def read(self, rva, size):
        for name, start, virtual_size, raw, raw_size in self.sections:
            if start <= rva and rva + size <= start + min(virtual_size, raw_size):
                offset = rva - start
                return self.data[name][offset:offset + size]
        raise ValueError(f"Unmapped executable bytes at RVA {rva:#x} ({size:#x} bytes).")

    def function(self, rva):
        index = bisect.bisect_right(self.function_starts, rva) - 1
        if index < 0:
            return None
        start, end = self.functions[index]
        return (start, end) if start <= rva < end else None

    def instructions(self, start, end):
        data = self.read(start, end - start)
        return list(self.disassembler.disasm(data, self.base + start))

    def call_candidates(self, target):
        needle = self.base + target
        for offset in range(len(self.text) - 5):
            if self.text[offset] != 0xE8:
                continue
            displacement = struct.unpack_from("<i", self.text, offset + 1)[0]
            if self.base + self.text_rva + offset + 5 + displacement == needle:
                rva = self.text_rva + offset
                function = self.function(rva)
                if function is not None:
                    yield function

    @staticmethod
    def immediate_call(instruction):
        return (
            instruction.mnemonic == "call"
            and instruction.operands
            and instruction.operands[0].type == x86.X86_OP_IMM
            and instruction.operands[0].imm
        )

    @staticmethod
    def preceding_edx(instructions, index):
        for instruction in reversed(instructions[max(0, index - 20):index]):
            if instruction.mnemonic == "call":
                return None
            if not instruction.operands or instruction.operands[0].type != x86.X86_OP_REG:
                continue
            if instruction.operands[0].reg not in (x86.X86_REG_EDX, x86.X86_REG_RDX):
                continue
            if instruction.mnemonic == "mov" and instruction.operands[1].type == x86.X86_OP_IMM:
                return instruction.operands[1].imm
            return None
        return None

    @staticmethod
    def arguments(instructions, index):
        arguments = {}
        groups = (
            ("edx", "rdx", "dx", "dl"),
            ("r8d", "r8", "r8w", "r8b"),
            ("r9d", "r9", "r9w", "r9b"),
            ("rcx", "ecx", "cx", "cl"),
        )
        for instruction in reversed(instructions[max(0, index - 8):index]):
            for names in groups:
                if names[0] in arguments:
                    continue
                for name in names:
                    if instruction.op_str.startswith(name + ", "):
                        value = instruction.op_str.split(", ", 1)[1]
                        if instruction.mnemonic in ("mov", "lea", "movzx", "movsxd"):
                            arguments[names[0]] = f"{name}={value}"
                        elif instruction.mnemonic == "xor" and value == name:
                            arguments[names[0]] = f"{name}=0"
                        break
        return " ".join(arguments.values())

    def analyze(self, function):
        instructions = self.instructions(*function)
        opcodes = set()
        lines = []
        for index, instruction in enumerate(instructions):
            target = self.immediate_call(instruction)
            if not target:
                continue
            rva = target - self.base
            if rva == COUTPACKET_CTOR:
                opcode = self.preceding_edx(instructions, index)
                opcodes.add(opcode)
                lines.append((instruction.address, f"COutPacket(opcode={opcode and hex(opcode)})"))
            elif rva == SENDPACKET:
                lines.append((instruction.address, f"SendPacket {self.arguments(instructions, index)}"))
            elif rva in ENCODERS:
                lines.append((instruction.address, f"{ENCODERS[rva]} {self.arguments(instructions, index)}"))
        return opcodes, lines


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("--opcode", type=lambda value: int(value, 0), action="append")
    parser.add_argument("--function", type=lambda value: int(value, 0), action="append")
    args = parser.parse_args()
    image = Image(args.image)
    wanted = set(args.opcode or OBSERVED_OPCODES)
    functions = set(image.call_candidates(COUTPACKET_CTOR))
    functions.update(image.call_candidates(SENDPACKET))
    for rva in args.function or ():
        function = image.function(rva)
        if function is None:
            raise ValueError(f"No exception-table function contains {rva:#x}.")
        functions.add(function)
    print(f"image={args.image} timestamp={image.timestamp:#x} functions={len(image.functions)}")
    found = set()
    for start, end in sorted(functions):
        opcodes, lines = image.analyze((start, end))
        if not lines or not (opcodes & wanted or args.function and (start, end) in [
            image.function(rva) for rva in args.function
        ]):
            continue
        found.update(opcode for opcode in opcodes if opcode is not None)
        names = ", ".join("dynamic" if opcode is None else hex(opcode) for opcode in sorted(opcodes, key=lambda value: value or -1))
        print(f"\nfunction {start:#x}..{end:#x} constructors: {names}")
        for address, text in lines:
            print(f"  {address - image.base:#x}: {text}")
    print("\nNo direct constant constructor found for:", ", ".join(hex(opcode) for opcode in sorted(wanted - found)))


if __name__ == "__main__":
    main()
