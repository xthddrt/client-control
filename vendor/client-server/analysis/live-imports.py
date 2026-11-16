#!/usr/bin/env python3
"""Name the function pointers the running game holds: module!export for each 8-byte slot.

    sudo .venv/bin/python -I analysis/live-imports.py <pid> <rva> ...
    sudo .venv/bin/python -I analysis/live-imports.py <pid> 0x3359000-0x335c000 0x3b72000-0x3c17000

Themida wiped MapleStory.exe's import names on disk, and the game looks up ~250 more Windows
functions itself at start-up (the table at .data 0x3c08290-0x3c08a88). This reads the slots' values
from the live process (RVAs of build 0x6AEB667B; image base 0x140000000) and names each pointer
from the export table of the DLL file it lands in.

Read-only: it only reads /proc/<pid>/maps and /proc/<pid>/mem (needs root for the latter). It
never writes, attaches, stops or injects; the game cannot see it (no handle is opened inside Windows).
A single RVA prints whatever it points at; a lo-hi range prints only slots that land on a named
export outside MapleStory.exe.
"""

import bisect
import functools
import struct
import sys

import pefile

BASE = 0x140000000
MODULE_SUFFIXES = (".dll", ".exe", ".drv", ".so")


def main():
    pid = int(sys.argv[1])
    slots = []   # (rva, from_range)
    for arg in sys.argv[2:]:
        if "-" in arg:
            lo, hi = (int(x, 16) for x in arg.split("-"))
            slots += [(a, True) for a in range(lo, hi, 8)]
        else:
            slots.append((int(arg, 16), False))

    maps = []
    for line in open(f"/proc/{pid}/maps"):
        parts = line.split()
        lo, hi = (int(x, 16) for x in parts[0].split("-"))
        maps.append((lo, hi, int(parts[2], 16), parts[5] if len(parts) > 5 else ""))
    mods = sorted((lo, path) for lo, hi, off, path in maps
                  if path.lower().endswith(MODULE_SUFFIXES) and off == 0)
    starts = [lo for lo, _ in mods]
    end = max(hi for _, hi, _, _ in maps)

    @functools.lru_cache(None)
    def exports(path):
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(directories=[0])
        symbols = getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", [])
        return {e.address: (e.name or b"#%d" % e.ordinal).decode() for e in symbols}

    def where(ptr):
        """(file name, export name or None) of the module mapped at or below ptr; None outside all."""
        i = bisect.bisect_right(starts, ptr) - 1
        if i < 0 or ptr > end:
            return None
        lo, path = mods[i]
        if path.endswith(".so"):
            return path, f"+{ptr - lo:#x}"
        try:
            name = exports(path).get(ptr - lo)
        except Exception as e:   # a module file pefile cannot read
            name = f"(pe error {e})"
        return path.rsplit("/", 1)[-1], name or f"+{ptr - lo:#x}"

    with open(f"/proc/{pid}/mem", "rb", 0) as mem:
        for rva, from_range in slots:
            mem.seek(BASE + rva)
            ptr = struct.unpack("<Q", mem.read(8))[0]
            if ptr < 0x10000 or ptr >> 48:   # not a pointer
                continue
            found = where(ptr)
            if from_range and (not found or found[0] == "MapleStory.exe" or found[1].startswith("+")):
                continue
            print(f"{rva:#x} -> {ptr:#x} " + (f"{found[0]}!{found[1]}" if found else "?"))


if __name__ == "__main__":
    main()
