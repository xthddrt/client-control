"""Recover server-opcode dispatch routes from the profiled MapleStory.exe."""

from __future__ import annotations

import struct
from collections import defaultdict
from dataclasses import dataclass, field

from traffic.protocol import NAMES

from .annotate import DECODERS, call_target
from .image import MAPLESTORY_TIMESTAMP

EXPECTED = {
    0x5AC: 0x1B00F90,
    0x22D: 0x2A75220,
    0x1A9: 0x2127880,
    0x0E: 0x1BD25A0,
    0x44: 0x1BCB570,
    0x340: 0x29CDE20,
}


@dataclass
class Entry:
    opcode: int
    dispatcher: str
    handler: int | None
    case: int | None = None
    path: tuple[int, ...] = field(default_factory=tuple)
    note: str = ""


def jump_table(image, first, count, offsets, index=None):
    for i in range(count):
        slot = struct.unpack_from("<I", image.img, offsets + 4 * (image.img[index + i] if index is not None else i))[0]
        yield first + i, slot


def resolve_case(image, case, dispatcher):
    if case in image.start_set and case != dispatcher:
        return case, (case,), "function"
    bounds = image.func(dispatcher)
    if not bounds or not bounds[0] <= case < bounds[1]:
        return case, (case,), "case"
    seen = set()
    current = case
    for _ in range(5):
        if current in seen:
            break
        seen.add(current)
        path = []
        for ins in image.disasm(current, min(current + 0x100, bounds[1]), count=40):
            target = call_target(ins)
            if target is None:
                if ins.mnemonic == "ret":
                    break
                continue
            target -= image.base
            if target in DECODERS:
                continue
            if not image.text[0] <= target < image.text[1]:
                continue
            path.append(target)
            if ins.mnemonic == "call" or target in image.start_set or not bounds[0] <= target < bounds[1]:
                return target, (case, *path), "call" if ins.mnemonic == "call" else "jump"
            break
        else:
            break
        if not path:
            break
        current = path[0]
    return case, (case,), "inline"


def table_entries(image, first, count, offsets, label, dispatcher, *, index=None, default=None):
    out = []
    for opcode, case in jump_table(image, first, count, offsets, index):
        if case == default:
            continue
        handler, path, note = resolve_case(image, case, dispatcher)
        out.append(Entry(opcode, label, handler, case, path, note))
    return out


def direct(opcode, dispatcher, handler, *, case=None, path=(), note="range"):
    return Entry(opcode, dispatcher, handler, case, tuple(path) or (handler,), note)


def static_entries(image):
    if image.timestamp != MAPLESTORY_TIMESTAMP:
        raise ValueError(f"dispatch tables require PE timestamp {MAPLESTORY_TIMESTAMP:#x}")
    out = []
    out += table_entries(image, 0, 0x62, 0x1BC8978, "login-stage 0x1bc83d0", 0x1BC83D0,
                         index=0x1BC8A00, default=0x1BC88FA)
    out += table_entries(image, 0x72, 0x32C, 0x2D7F144, "context 0x2d7bfb0", 0x2D7BFB0,
                         default=0x2D7F030)
    out += table_entries(image, 0x1AD, 0x80, 0x18B3918, "field 0x18b1840", 0x18B1840,
                         default=0x18B35E4)
    out += table_entries(image, 0x4D5, 0xDA, 0x18B3B18, "field 0x18b1840", 0x18B1840,
                         index=0x18B3B84, default=0x18B35E4)

    for opcode in range(0x53, 0x72):
        out.append(direct(opcode, "login/field ranged", 0x1C0E260))
    for opcode in range(0x1A9, 0x1AD):
        handler = 0x2127880 if opcode == 0x1A9 else 0x21277E0
        path = (0x21277E0, handler) if handler != 0x21277E0 else (handler,)
        out.append(direct(opcode, "login/field set-field 0x21277e0", handler, path=path))
    out.append(direct(0x22D, "user pool 0x2a74140", 0x2A75220, case=0x2A742A7,
                      path=(0x2A74140, 0x2A75220)))
    handler, path, note = resolve_case(image, 0x2A7428D, 0x2A74140)
    out.append(Entry(0x22E, "user pool 0x2a74140", handler, 0x2A7428D, path, note))
    for opcode in range(0x22F, 0x29D):
        if 0x281 <= opcode <= 0x288:
            out.append(direct(opcode, "user pool / common pets", 0x2830770,
                              path=(0x2A75DF0, 0x2830770)))
        else:
            out.append(direct(opcode, "user pool / common", 0x2A75DF0))
    out += table_entries(image, 0x29D, 0x31, 0x2A76B10, "user pool / remote 0x2a76560", 0x2A76560,
                         index=0x2A76B50)
    out += table_entries(image, 0x2A8, 0x27, 0x2A76A74, "user pool / remote attacks 0x2a76560", 0x2A76560)
    out += table_entries(image, 0x2CF, 0xD3, 0x295E818, "user pool / local 0x295b640", 0x295B640,
                         default=0x295E7AF)
    out.append(direct(0x3A2, "user pool 0x2a74140", 0x2A74140, note="range endpoint"))
    for opcode in range(0x452, 0x46C):
        out.append(direct(opcode, "field / NPC pool", 0x1F020B0))
    for opcode in range(0x471, 0x473):
        out.append(direct(opcode, "field / drop pool", 0x1833060))
    for opcode in range(0x5F5, 0x5F8):
        handler = 0x1A91430 if opcode == 0x5F5 else 0x1A91820
        path = (0x1A91820, handler) if handler != 0x1A91820 else (handler,)
        out.append(direct(opcode, "field / key bindings", handler, path=path))
    for opcode, handler in ((0x5F8, 0x1BDB580), (0x61F, 0x1BDCA40),
                            (0x624, 0x1BCC220), (0xFBE, 0x1BCBF30)):
        out.append(direct(opcode, "login-stage ranged", handler))
    return sorted(out, key=lambda e: (e.opcode, e.dispatcher, e.case or 0, e.handler or 0))


def check(entries):
    missing = {opcode: handler for opcode, handler in EXPECTED.items()
               if not any(e.opcode == opcode and e.handler == handler for e in entries)}
    if missing:
        raise AssertionError("dispatch checks failed: " + ", ".join(
            f"S {opcode:#x} != {handler:#x}" for opcode, handler in missing.items()))
    return {f"S {opcode:#x}": handler for opcode, handler in EXPECTED.items()}


def markdown(entries):
    covered = {e.opcode for e in entries}
    unresolved = [Entry(opcode, "not recovered from static tables", None, note="see VM-dispatch notes in server-messages.md")
                  for (side, opcode) in sorted(NAMES, key=lambda key: key[1])
                  if side == "S" and opcode not in covered]
    lines = [
        "# Server-message dispatch map",
        "",
        f"Generated read-only from MapleStory.exe PE timestamp `{MAPLESTORY_TIMESTAMP:#x}` with",
        "`analysis/re-tool.py dispatch APPDATA/MapleStory.exe --markdown docs/reference/server-dispatch.md --check`.",
        "Addresses are RVAs. `case` is the jump-table destination; `handler/path` follows the first direct",
        "non-decoder call or tail jump. An `inline` handler is code inside the dispatcher, not a separate",
        "function. Range routes and overlapping login/context/field routes are separate rows. Themida-VM",
        "dispatch is not reverse engineered; known opcodes with no recovered static route are listed last.",
        "See `server-messages.md` and `sign-in.md` for the supporting evidence and remaining limits.",
        "",
        "| Opcode | Name | Dispatcher | Case RVA | Handler/path | How |",
        "|---:|---|---|---:|---|---|",
    ]
    for e in sorted(entries + unresolved, key=lambda e: (e.opcode, e.dispatcher, e.case or 0)):
        name = NAMES.get(("S", e.opcode), ("",))[0]
        path = " -> ".join(f"{v:#x}" for v in (e.path or ((e.handler,) if e.handler else ())))
        lines.append(f"| S {e.opcode:#x} | {name} | {e.dispatcher} | {e.case:#x} | {path or '—'} | {e.note} |" if e.case is not None
                     else f"| S {e.opcode:#x} | {name} | {e.dispatcher} | — | {path or '—'} | {e.note} |")
    lines += ["", f"Static route rows: {len(entries)}. Known opcodes without a recovered static route: {len(unresolved)}.", ""]
    return "\n".join(lines)
