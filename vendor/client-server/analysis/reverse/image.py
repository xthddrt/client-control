"""PE image, function, call, cross-reference, method-table and RTTI indexes."""

from __future__ import annotations

import bisect
import hashlib
import os
import pickle
import re
import struct
from collections import defaultdict
from pathlib import Path

import capstone
import pefile

MAPLESTORY_TIMESTAMP = 0x6AEB667B
CACHE_VERSION = 1
RIP_PATTERN = re.compile(
    rb"[\x40-\x4f]?(?:[\x01\x03\x21\x23\x29\x2b\x31\x33\x38\x3a\x39\x3b\x63\x84\x85\x87\x88\x89\x8a\x8b\x8d\x8f\xc0\xc1\xc6\xc7])([\x05\x0d\x15\x1d\x25\x2d\x35\x3d])"
)


class Image:
    def __init__(self, path, *, cache=None, expected_timestamp=None):
        self.path = Path(path)
        self.cache = Path(cache) if cache else None
        self.digest = self._digest()
        self.pe = pefile.PE(str(self.path), fast_load=True)
        if self.pe.OPTIONAL_HEADER.Magic != 0x20B:
            raise ValueError(f"{self.path}: only x64 PE files are supported")
        self.timestamp = self.pe.FILE_HEADER.TimeDateStamp
        if expected_timestamp is not None and self.timestamp != expected_timestamp:
            raise ValueError(
                f"{self.path}: PE timestamp {self.timestamp:#x}, expected {expected_timestamp:#x}; "
                "the dispatch addresses belong to one build"
            )
        self.pe.parse_data_directories(directories=[1])
        self.img = self.pe.get_memory_mapped_image()
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.sections = {
            s.Name.rstrip(b"\0").decode(errors="replace"): (s.VirtualAddress, s.VirtualAddress + s.Misc_VirtualSize)
            for s in self.pe.sections
        }
        self.text = self.sections.get(".text", (0, 0))
        self.rdata = self.sections.get(".rdata", (0, 0))
        self.imports = {
            i.address - self.base: f"{d.dll.decode(errors='replace')}!{(i.name or b'#' + str(i.ordinal).encode()).decode(errors='replace')}"
            for d in getattr(self.pe, "DIRECTORY_ENTRY_IMPORT", [])
            for i in d.imports
        }
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        cached = self._load_cache()
        if cached:
            self.funcs = cached["funcs"]
            self.callers = cached["callers"]
            self.slots = cached["slots"]
            self._rip_index = cached.get("rip_index")
        else:
            self.funcs = self._read_functions()
            self.callers, self.slots = self._build_pointer_indexes()
            self._rip_index = None
            self._save_cache()
        self.starts = [f[0] for f in self.funcs]
        self.start_set = set(self.starts)

    def _digest(self):
        digest = hashlib.sha256()
        with self.path.open("rb") as f:
            for block in iter(lambda: f.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()

    def _read_functions(self):
        if ".pdata" not in self.sections:
            return []
        lo, hi = self.sections[".pdata"]
        entries = {
            struct.unpack_from("<III", self.img, a)[:2]
            for a in range(lo, hi - 11, 12)
        }
        t0, t1 = self.text
        return sorted((a, b) for a, b in entries if a and t0 <= a < b <= t1)

    def _build_pointer_indexes(self):
        callers, slots = defaultdict(list), defaultdict(list)
        t0, t1 = self.text
        starts = {f[0] for f in self.funcs}
        for m in re.finditer(rb"\xe8", self.img[t0:t1]):
            at = t0 + m.start()
            if at + 5 > len(self.img):
                continue
            target = at + 5 + struct.unpack_from("<i", self.img, at + 1)[0]
            if target in starts:
                callers[target].append(at)
        r0, r1 = self.rdata
        for at in range(r0, r1 - 7, 8):
            target = struct.unpack_from("<Q", self.img, at)[0] - self.base
            if target in starts:
                slots[target].append(at)
        return dict(callers), dict(slots)

    def _load_cache(self):
        if not self.cache or not self.cache.exists():
            return None
        with self.cache.open("rb") as f:
            data = pickle.load(f)
        if data.get("version") != CACHE_VERSION or data.get("sha256") != self.digest:
            return None
        return data

    def _save_cache(self):
        if not self.cache:
            return
        self.cache.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "version": CACHE_VERSION,
            "sha256": self.digest,
            "funcs": self.funcs,
            "callers": self.callers,
            "slots": self.slots,
            "rip_index": self._rip_index,
        }
        tmp = self.cache.with_name(self.cache.name + ".tmp")
        with tmp.open("wb") as f:
            pickle.dump(data, f, protocol=pickle.HIGHEST_PROTOCOL)
        os.replace(tmp, self.cache)

    @property
    def rip_index(self):
        if self._rip_index is None:
            index = defaultdict(list)
            t0, t1 = self.text
            data = self.img[t0:t1]
            for m in RIP_PATTERN.finditer(data):
                disp_at = m.end()
                if disp_at + 4 > len(data):
                    continue
                disp = struct.unpack_from("<i", data, disp_at)[0]
                instruction = t0 + m.start()
                target = t0 + disp_at + 4 + disp
                index[target].append(instruction)
            self._rip_index = dict(index)
            self._save_cache()
        return self._rip_index

    def func(self, rva):
        i = bisect.bisect_right(self.starts, rva) - 1
        if i >= 0 and self.funcs[i][0] <= rva < self.funcs[i][1]:
            return self.funcs[i]
        return None

    def disasm(self, start, end=None, count=None):
        if end is None:
            func = self.func(start)
            end = func[1] if func else min(start + 0x400, len(self.img))
        for i, ins in enumerate(self.md.disasm(self.img[start:end], self.base + start)):
            if count is not None and i >= count:
                break
            yield ins

    def decode_to(self, at, back=64):
        func = self.func(at)
        if not func:
            return []
        for start in range(max(at - back, func[0]), at):
            code = list(self.md.disasm(self.img[start:at], self.base + start))
            if code and code[-1].address + code[-1].size == self.base + at:
                return code
        return []

    def rip_refs(self, target):
        return tuple(self.rip_index.get(target, ()))

    def absolute_refs(self, target):
        needle = struct.pack("<Q", self.base + target)
        return tuple(m.start() for m in re.finditer(re.escape(needle), self.img))

    def table_of(self, slot):
        r0, r1 = self.rdata
        at = slot
        while at - 8 >= r0 and struct.unpack_from("<Q", self.img, at - 8)[0] - self.base in self.start_set:
            at -= 8
        name = None
        if at - 8 >= 0:
            col = struct.unpack_from("<Q", self.img, at - 8)[0] - self.base
            if r0 <= col < r1 and col + 16 <= len(self.img):
                sig, _, _, td = struct.unpack_from("<IIII", self.img, col)
                if sig == 1 and 0 < td < len(self.img) - 16:
                    raw = self.img[td + 16:td + 136].split(b"\0")[0]
                    if raw.startswith(b".?A"):
                        name = raw.decode(errors="replace")
        return at, name

    def text_at(self, rva, limit=120):
        if not 0 <= rva < len(self.img):
            return None
        raw = self.img[rva:rva + limit]
        ascii_raw = raw.split(b"\0", 1)[0]
        if len(ascii_raw) >= 4 and all(32 <= c < 127 for c in ascii_raw):
            return repr(ascii_raw.decode("ascii"))
        wide = re.match(rb"((?:[\x20-\x7e]\x00){3,})\x00\x00", raw)
        if wide:
            return "L" + repr(wide.group(1).decode("utf-16-le"))
        return None
