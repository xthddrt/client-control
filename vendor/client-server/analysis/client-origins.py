#!/usr/bin/env python3
"""Where each client->server game message comes from, read from MapleStory.exe on disk.

    .venv/bin/python analysis/client-origins.py [--exe PATH] [--recording proxy-*.jsonl ...]
        [--json captures/client-origins.json] [--markdown docs/reference/client-messages.md]

Static only: the file is read, the game is not touched. For this build
(foundations/profile.json; addresses from docs/guides/PACKETS.md):

- every message is made by the COutPacket constructor (0x7614b0) with the
  opcode in edx; each such call is a build site;
- after it, the builder appends fields with Encode1/2/4/8, EncodeStr,
  EncodeBuffer, EncodeDouble and sends with SendPacket (0x1661780); the fields
  are listed in code order (branches and loops are not followed: a field that
  only some paths write is still listed once, and other calls between the
  constructor and the send are listed as "call <rva>", since they may add
  fields of their own);
- origin: the builder's callers are followed upwards until a function that is
  called through a method table (a C++ virtual method: an event handler);
  methods of one table belong to one class, named when the file kept its RTTI;
- parts of the client: builders are grouped by where they sit in the code (a
  compiler keeps one source file's functions together; a gap of more than
  REGION_GAP bytes starts a new part); a part is labelled only by the named
  messages (traffic/protocol.py) it builds;
- with --recording, the fixed-size layouts are checked against the decrypted
  messages of proxy recordings (traffic/stream.py), opcode by opcode. A layout
  with a loop (a movement path) or a branch that adds fields shows as not
  explained: the fields are in code order, not per path.

Opcodes the recordings saw but no constructor call builds with a constant are
reported too: they are made in the protected (virtualised) code or with a
computed opcode.
"""

from __future__ import annotations

import argparse
import json
import re
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from analysis.reverse.image import Image as PEImage  # noqa: E402
from traffic.protocol import NAMES  # noqa: E402

EXE = Path.home() / ".wine-nexon/drive_c/Nexon/Library/maplestorycw/appdata/MapleStory.exe"
BASE = 0x140000000
PE_TIMESTAMP = 0x6AEB667B
CTOR = 0x7614B0
SEND = 0x1661780
ENCODERS = {0x7617D0: ("u8", 1), 0x7618D0: ("u16", 2), 0x761960: ("u32", 4), 0x761B50: ("u64", 8),
            0x761BB0: ("double", 8), 0x761C10: ("str", None), 0x761EA0: ("bytes", None)}
ENCODER_BYTES = 0x761EA0
OPCODE_RANGE = (0x70, 0x432)
REGION_GAP = 0x10000
HELPER_DEPTH = 2   # helpers that write fields are looked into this many levels down   # 0x70 is the lowest client opcode seen; 0xC7 + 876 table entries - 1
MAX_UP = 6


class Image(PEImage):
    def __init__(self, path):
        try:
            super().__init__(path, expected_timestamp=PE_TIMESTAMP)
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc

    def decode_from(self, at, end):
        return list(self.disasm(at, end))


def call_target(ins):
    if ins.mnemonic == "call" and ins.op_str.startswith("0x"):
        return int(ins.op_str, 16) - BASE
    return None


def field_calls(image, code, stop_at_send=True, depth=0):
    """Fields written by a run of instructions: encoder calls (raw byte runs with their constant
    length when r8 is set just before), helpers that write fields themselves (two levels down).
    Returns (fields, sends); other calls are left out: they write no field of this packet."""
    fields, sends, r8 = [], False, None
    for ins in code:
        ops = ins.op_str.split(", ")
        if ins.mnemonic == "mov" and ops[0] in ("r8d", "r8") and (ops[1].startswith("0x") or ops[1].isdigit()):
            r8 = int(ops[1], 0)
        target = call_target(ins)
        if target is None:
            continue
        if target == CTOR and stop_at_send:
            break
        if target == SEND:
            sends = True
            if stop_at_send:
                break
            continue
        if target == ENCODER_BYTES:
            fields.append(f"bytes[{r8}]" if r8 is not None else "bytes")
        elif target in ENCODERS:
            fields.append(ENCODERS[target][0])
        else:
            inner = helper_fields(image, target, depth + 1) if depth < HELPER_DEPTH else None
            if inner:
                fields.append({"via": f"{target:#x}", "fields": inner})
        r8 = None
    return fields, sends


_helpers = {}


def helper_fields(image, target, depth):
    key = (target, depth)
    if key in _helpers:
        return _helpers[key]
    _helpers[key] = None   # (recursion guard)
    func = image.func(target)
    result = None
    if func and func[1] - func[0] < 0x2000:
        fields, _ = field_calls(image, image.decode_from(func[0], func[1]), stop_at_send=False, depth=depth)
        result = fields or None
    _helpers[key] = result
    return result


def build_sites(image):
    """{opcode: [site]}; a site: builder function, fields in code order, whether it sends."""
    sites, dynamic = defaultdict(list), []
    for call in sorted(image.callers[CTOR]):
        func = image.func(call)
        if not func:
            continue
        before = image.decode_to(call)
        after = image.decode_from(call, func[1])
        if not after or call_target(after[0]) != CTOR:
            continue
        ins, fstart = after[0], func[0]
        if True:
            opcode = None
            for prev in reversed(before[-12:]):
                ops = prev.op_str.split(", ")
                if prev.mnemonic == "mov" and ops[0] in ("edx", "rdx"):
                    if ops[1].startswith("0x") or ops[1].isdigit():
                        opcode = int(ops[1], 0)
                    break
                if prev.mnemonic in ("xor", "lea") and ops[0] in ("edx", "rdx"):
                    break
            fields, sends = field_calls(image, after[1:])
            site = {"site": ins.address - BASE, "builder": fstart, "fields": fields, "sends": sends}
            if opcode is not None and OPCODE_RANGE[0] <= opcode <= OPCODE_RANGE[1]:
                sites[opcode].append(site)
            else:
                dynamic.append({**site, "edx": opcode})
    return sites, dynamic


def origin(image, fstart):
    """Walk the callers up to the first methods called through a table; their tables and classes."""
    found, frontier, seen, path_len = {}, [fstart], {fstart}, {fstart: 0}
    while frontier:
        f = frontier.pop(0)
        if image.slots.get(f):
            for slot in image.slots[f]:
                table, name = image.table_of(slot)
                found.setdefault(table, {"table": table, "class": name, "methods": set(), "depth": path_len[f]})
                found[table]["methods"].add(f)
            continue
        if path_len[f] >= MAX_UP:
            continue
        for call in image.callers.get(f, []):
            caller = image.func(call)
            if caller and caller[0] not in seen:
                seen.add(caller[0])
                path_len[caller[0]] = path_len[f] + 1
                frontier.append(caller[0])
    if found:
        nearest = min(t["depth"] for t in found.values())
        found = {k: t for k, t in found.items() if t["depth"] == nearest}
    return sorted(found.values(), key=lambda t: t["table"]), len(seen)


def fixed_size(fields, top=True):
    sizes = {name: size for name, size in ENCODERS.values()}
    total = 2 if top else 0
    for field in fields:
        if isinstance(field, dict):
            inner = fixed_size(field["fields"], top=False)
            if inner is None:
                return None
            total += inner
        elif field.startswith("bytes[") and field[6:-1].isdigit():
            total += int(field[6:-1])
        elif sizes.get(field) is None:
            return None
        else:
            total += sizes[field]
    return total


def flat(fields):
    out = []
    for field in fields:
        out.extend([f"<{field['via']}:"] + flat(field["fields"]) + [">"] if isinstance(field, dict) else [field])
    return out


def observed(recordings):
    lengths = defaultdict(Counter)
    for path in recordings:
        for line in open(path, encoding="utf-8"):
            if '"kind":"message"' not in line or '"client_to_server"' not in line:
                continue
            record = json.loads(line)
            if record.get("opcode"):
                lengths[int(record["opcode"], 16)][record["length"]] += 1
    return lengths


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--exe", default=str(EXE))
    ap.add_argument("--recording", action="append", default=[], help="decoded proxy recording (repeatable)")
    ap.add_argument("--json", default=str(ROOT / "captures/client-origins.json"))
    ap.add_argument("--markdown", help="also write a markdown report here")
    args = ap.parse_args()

    image = Image(args.exe)
    sites, dynamic = build_sites(image)
    seen = observed(args.recording)
    tables = {}
    report = []
    for opcode in sorted(set(sites) | set(seen)):
        entry = {"opcode": f"0x{opcode:x}", "name": NAMES.get(("C", opcode), (None,))[0],
                 "seen": sum(seen[opcode].values()), "seen_lengths": sorted(seen[opcode]),
                 "sites": [], "origins": []}
        builders = sorted({s["builder"] for s in sites.get(opcode, [])})
        for s in sites.get(opcode, []):
            size = fixed_size(s["fields"])
            entry["sites"].append({"site": f"{s['site']:#x}", "builder": f"{s['builder']:#x}",
                                   "fields": s["fields"], "sends_in_builder": s["sends"],
                                   "fixed_length": size,
                                   "length_matches": (size in seen[opcode]) if size and seen[opcode] else None})
        for builder in builders:
            found, explored = origin(image, builder)
            for t in found:
                key = t["table"]
                tables.setdefault(key, {"table": f"{key:#x}", "class": t["class"], "opcodes": set()})
                tables[key]["opcodes"].add(opcode)
                entry["origins"].append({"builder": f"{builder:#x}", "table": f"{key:#x}", "class": t["class"],
                                         "methods": sorted(f"{m:#x}" for m in t["methods"]),
                                         "steps_up": t["depth"]})
        if not sites.get(opcode):
            entry["note"] = "no constant constructor call: protected (virtualised) code or a computed opcode"
        if seen[opcode] and sites.get(opcode):
            fixed = {s["fixed_length"] for s in entry["sites"]}
            variable = None in fixed
            unexplained = sorted(n for n in seen[opcode] if n not in fixed)
            entry["recorded_lengths_explained"] = (
                "all" if not unexplained else
                "variable-length site" if variable else f"not {unexplained[:6]}")
        report.append(entry)
    groups = sorted(({"table": t["table"], "class": t["class"], "opcodes": sorted(f"0x{o:x}" for o in t["opcodes"])}
                     for t in tables.values()), key=lambda g: -len(g["opcodes"]))
    builders = sorted({(int(s["builder"], 16), m["opcode"]) for m in report for s in m["sites"]})
    regions = []
    for start, opcode in builders:
        if not regions or start - regions[-1]["last"] > REGION_GAP:
            regions.append({"first": start, "last": start, "opcodes": set()})
        regions[-1]["last"] = start
        regions[-1]["opcodes"].add(opcode)
    by_op = {m["opcode"]: m for m in report}
    regions = [{"code": f"{r['first']:#x}-{r['last']:#x}", "opcodes": sorted(r["opcodes"], key=lambda o: int(o, 16)),
                "named": sorted(f"{o} {by_op[o]['name']}" for o in r["opcodes"] if by_op[o]["name"]),
                "seen": sum(by_op[o]["seen"] for o in r["opcodes"])} for r in regions]
    out = {"exe_pe_timestamp": f"{PE_TIMESTAMP:#x}", "messages": report, "regions": regions, "classes": groups,
           "dynamic_sites": [{**d, "site": f"{d['site']:#x}", "builder": f"{d['builder']:#x}"} for d in dynamic]}
    Path(args.json).parent.mkdir(parents=True, exist_ok=True)
    Path(args.json).write_text(json.dumps(out, indent=1))
    summarize(out, args.markdown)


def summarize(out, markdown):
    msgs = out["messages"]
    built = [m for m in msgs if m["sites"]]
    checked = [m for m in msgs if m.get("recorded_lengths_explained")]
    lines = [
        f"{len(built)} client opcodes are built at {sum(len(m['sites']) for m in built)} sites "
        f"({len(out['dynamic_sites'])} more sites take a computed opcode).",
        f"{sum(1 for m in built if m['origins'])} of them trace up to a method of a class "
        f"({len(out['classes'])} method tables; {sum(1 for g in out['classes'] if g['class'])} with a class name).",
        f"Parts of the client (builders grouped by place in the code): {len(out['regions'])}; "
        f"{sum(1 for r in out['regions'] if r['named'])} build a named message.",
        f"Seen in the recordings: {sum(1 for m in msgs if m['seen'])} opcodes; "
        f"seen without a constant build site: {[m['opcode'] for m in msgs if m['seen'] and not m['sites']]}.",
        f"Recorded lengths against the static layouts: all explained by a fixed layout for "
        f"{sum(1 for m in checked if m['recorded_lengths_explained'] == 'all')} opcodes, a variable-length "
        f"site for {sum(1 for m in checked if m['recorded_lengths_explained'] == 'variable-length site')}, "
        f"not explained for {[m['opcode'] for m in checked if m['recorded_lengths_explained'].startswith('not')]}.",
    ]
    print("\n".join(lines))
    if not markdown:
        return
    md = ["# Client messages: where each comes from", "",
          "Generated by `analysis/client-origins.py` from MapleStory.exe build "
          f"{out['exe_pe_timestamp']} (static: the file on disk). Fields are in code order; a "
          "`call` between them may add fields of its own; branches are not followed.", "",
          *[f"- {line}" for line in lines], "",
          "## By part of the client", "",
          "Builders grouped by place in the code. A part is labelled only by the named messages it builds.", "",
          "| Code range | Opcodes | Seen messages | Named messages built here | All opcodes |", "|---|---|---|---|---|"]
    for r in out["regions"]:
        md.append(f"| {r['code']} | {len(r['opcodes'])} | {r['seen'] or ''} | {', '.join(r['named'])} | "
                  f"{' '.join(r['opcodes'][:20])}{' ...' if len(r['opcodes']) > 20 else ''} |")
    md += ["", "## Method tables with three or more opcodes", "",
           "| Table | Class | Opcodes |", "|---|---|---|"]
    for g in out["classes"]:
        if len(g["opcodes"]) >= 3 or g["class"]:
            md.append(f"| {g['table']} | {g['class'] or ''} | {' '.join(g['opcodes'])} |")
    md += ["", "## By opcode", "",
           "| Opcode | Name | Seen | Builder(s) | Fields (first site) | Fixed length (recorded lengths explained) | Origin (class / table, steps up) |",
           "|---|---|---|---|---|---|---|"]
    for m in msgs:
        first = m["sites"][0] if m["sites"] else None
        builders = sorted({s["builder"] for s in m["sites"]})
        shown = flat(first["fields"]) if first else []
        fields = " ".join(shown[:16]) + (" ..." if len(shown) > 16 else "") if first else m.get("note", "")
        size = "" if not first or first["fixed_length"] is None else str(first["fixed_length"])
        size += f" ({m['recorded_lengths_explained']})" if m.get("recorded_lengths_explained") else ""
        origins = sorted({(o["class"] or o["table"], o["steps_up"]) for o in m["origins"]})[:3]
        md.append(f"| {m['opcode']} | {m['name'] or ''} | {m['seen'] or ''} | {' '.join(builders[:3])}"
                  f"{' ...' if len(builders) > 3 else ''} | {fields} | {size} | "
                  f"{'; '.join(f'{c} ({d})' for c, d in origins)} |")
    Path(markdown).parent.mkdir(parents=True, exist_ok=True)
    Path(markdown).write_text("\n".join(md) + "\n")
    print(f"WROTE {markdown}")


if __name__ == "__main__":
    main()
