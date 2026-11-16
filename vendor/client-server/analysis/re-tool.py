#!/usr/bin/env python3
"""Read-only PE analysis: disassembly, xrefs, dispatch maps, kind sites and hosts."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from analysis.reverse import Image, MAPLESTORY_TIMESTAMP  # noqa: E402
from analysis.reverse.annotate import disassembly  # noqa: E402
from analysis.reverse.dispatch import check as check_dispatch  # noqa: E402
from analysis.reverse.dispatch import markdown as dispatch_markdown, static_entries  # noqa: E402
from analysis.reverse.hosts import markdown as hosts_markdown, scan  # noqa: E402
from analysis.reverse.kinds import check as check_kinds, kind_sites  # noqa: E402


def integer(value):
    return int(value, 0)


def image(args, profiled=False):
    return Image(args.file, cache=args.cache,
                 expected_timestamp=MAPLESTORY_TIMESTAMP if profiled else None)


def write(path, text):
    if path:
        Path(path).write_text(text, encoding="utf-8")
    else:
        print(text)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--cache", help="optional trusted index cache, normally under captures/")
    sub = parser.add_subparsers(dest="command", required=True)

    dis = sub.add_parser("dis", help="annotated disassembly of a function or address range")
    dis.add_argument("file")
    dis.add_argument("rva", type=integer)
    dis.add_argument("--end", type=integer)
    dis.add_argument("--count", type=int)

    func = sub.add_parser("func", help="function bounds, direct callers, method slots and RTTI")
    func.add_argument("file")
    func.add_argument("rva", type=integer)

    refs = sub.add_parser("xrefs", help="direct calls, RIP-relative references and absolute pointers")
    refs.add_argument("file")
    refs.add_argument("rva", type=integer)

    dispatch = sub.add_parser("dispatch", help="generate the profiled server-opcode dispatch map")
    dispatch.add_argument("file")
    dispatch.add_argument("--markdown")
    dispatch.add_argument("--check", action="store_true")

    kinds = sub.add_parser("kinds", help="recover C 0x1ef first-buffer kind constants")
    kinds.add_argument("file")
    kinds.add_argument("--opcode", type=integer, default=0x1EF)
    kinds.add_argument("--check", action="store_true")

    hosts = sub.add_parser("hosts", help="list host strings in binaries or an appdata directory")
    hosts.add_argument("paths", nargs="+")
    hosts.add_argument("--markdown")

    args = parser.parse_args()
    if args.command == "hosts":
        results = scan(args.paths)
        if args.markdown:
            write(args.markdown, hosts_markdown(results))
        else:
            for path, values in sorted(results.items()):
                for value, count in sorted(values.items()):
                    print(f"{path}\t{value}\t{count}")
        return

    im = image(args, profiled=args.command in ("dispatch", "kinds"))
    if args.command == "dis":
        print("\n".join(disassembly(im, args.rva, args.end, args.count)))
    elif args.command == "func":
        bounds = im.func(args.rva)
        print("function", " ".join(hex(v) for v in bounds) if bounds else "not in .pdata")
        for at in sorted(im.callers.get(args.rva, ())):
            caller = im.func(at)
            print(f"call {at:#x} in {caller[0]:#x}" if caller else f"call {at:#x} outside .pdata")
        for slot in sorted(im.slots.get(args.rva, ())):
            table, name = im.table_of(slot)
            print(f"slot {slot:#x} table {table:#x} class {name or 'unknown'}")
    elif args.command == "xrefs":
        for at in sorted(im.callers.get(args.rva, ())):
            print(f"call {at:#x}")
        for at in im.rip_refs(args.rva):
            print(f"rip {at:#x}")
        for at in im.absolute_refs(args.rva):
            print(f"absolute {at:#x}")
    elif args.command == "dispatch":
        entries = static_entries(im)
        if args.check:
            for opcode, handler in check_dispatch(entries).items():
                print(f"checked {opcode} -> {handler:#x}", file=sys.stderr)
        write(args.markdown, dispatch_markdown(entries))
    elif args.command == "kinds":
        sites = kind_sites(im, args.opcode)
        for site in sites:
            kind = site["kind"]
            print(f"site {site['site']:#x} builder {site['builder']:#x} kind "
                  + (f"{kind:#x}" if isinstance(kind, int) else str(kind)))
        if args.check:
            for builder, kind in check_kinds(sites).items():
                print(f"checked {builder} -> {kind:#x}", file=sys.stderr)


if __name__ == "__main__":
    main()
