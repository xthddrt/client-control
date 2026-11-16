#!/usr/bin/env python3
"""Where a Windows DLL/EXE uses a string, and what a function there does (imports, strings, calls).

    .venv/bin/python analysis/pe-xrefs.py <file.dll> --string "/prod/playtime-accumulator?project="
    .venv/bin/python analysis/pe-xrefs.py <file.dll> --function 0x18ef0
    .venv/bin/python analysis/pe-xrefs.py <file.dll> --exports

--string finds the text (UTF-16 and ASCII) and every RIP-relative lea that points at it, with the
function around each one. --function prints that function's instructions that call something,
use an import, a string, or a large constant (the readable skeleton). x64 PE files only. Used for
CrashReporter.dll (docs/guides/PROTOCOL.md); MapleStory.exe has its own map
(analysis/client-origins.py).
"""

from __future__ import annotations

import argparse
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from analysis.reverse.image import Image  # noqa: E402


class Pe(Image):
    def lea_refs(self, target):
        t0, t1 = self.text
        for m in re.finditer(rb"[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]", self.img[t0:t1]):
            at = t0 + m.start()
            if at + 7 + struct.unpack_from("<i", self.img, at + 3)[0] == target:
                yield at

    def skeleton(self, start, end):
        for ins in self.md.disasm(self.img[start:end], self.base + start):
            rva = ins.address - self.base
            m = re.search(r"\[rip ([+-]) 0x([0-9a-f]+)\]", ins.op_str)
            if m:
                target = ins.address + ins.size + (1 if m[1] == "+" else -1) * int(m[2], 16) - self.base
                note = self.imports.get(target) or self.text_at(target)
                if note:
                    yield f"{rva:#x}: {ins.mnemonic} -> {note}"
            elif ins.mnemonic == "call" and ins.op_str.startswith("0x"):
                yield f"{rva:#x}: call {int(ins.op_str, 16) - self.base:#x}"
            elif re.search(r", 0x[0-9a-f]{3,}$", ins.op_str):
                yield f"{rva:#x}: {ins.mnemonic} {ins.op_str}"


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("file")
    ap.add_argument("--string", action="append", default=[])
    ap.add_argument("--function", action="append", default=[], type=lambda v: int(v, 0))
    ap.add_argument("--exports", action="store_true")
    args = ap.parse_args()
    pe = Pe(args.file)
    if args.exports:
        exports = pe.pe.DIRECTORY_ENTRY_EXPORT.symbols if hasattr(pe.pe, "DIRECTORY_ENTRY_EXPORT") else []
        for e in exports:
            print(f"{e.address:#x} {e.name.decode() if e.name else e.ordinal}")
    for text in args.string:
        for encoded in (text.encode("utf-16-le") + b"\0\0", text.encode() + b"\0"):
            for m in re.finditer(re.escape(encoded), pe.img):
                refs = [f"{r:#x} in {pe.func(r)[0]:#x}" if pe.func(r) else f"{r:#x}" for r in pe.lea_refs(m.start())]
                print(f"{text!r} at {m.start():#x}: used at {', '.join(refs) or 'nowhere (direct lea)'}")
    for rva in args.function:
        f = pe.func(rva)
        if not f:
            print(f"{rva:#x}: not inside a function of the .pdata table")
            continue
        print(f"== function {f[0]:#x}-{f[1]:#x}")
        print("\n".join(pe.skeleton(*f)))


if __name__ == "__main__":
    main()
