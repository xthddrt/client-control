#!/usr/bin/env python3
"""URLs the game's programs fetched through WinINet, from Wine's web cache: address, reply headers, reply.

    .venv/bin/python analysis/wininet-cache.py [--prefix ~/.wine-nexon] [--host execute-api]

WinINet (Windows' web library, used for example by CrashReporter.dll) keeps an index of every URL it
fetched, with the reply headers, in INetCache/Content.IE5/index.dat, and the reply bodies in files
next to it (Wine often leaves them empty). This reads TLS traffic's addresses and replies without
decrypting anything. Request bodies (POST) are not kept.
"""

from __future__ import annotations

import argparse
import re
from collections import defaultdict
from pathlib import Path


def entries(index):
    """(url, cache file name, reply headers) for each URL entry of an index.dat."""
    data = index.read_bytes()
    for m in re.finditer(rb"URL ", data):
        block = data[m.start():m.start() + 4096]
        url = re.search(rb"(https?://[\x21-\x7e]+)\x00", block)
        if not url:
            continue
        rest = block[url.end():]
        name = re.match(rb"[\x00\x80-\xff]*([\x21-\x7e]+)\x00", rest)   # filler bytes (0xdeadbe) come first
        headers = re.search(rb"HTTP/1\.[01] [\x20-\x7e\r\n]+?\r\n\r\n", rest)
        yield (url.group(1).decode(), name.group(1).decode() if name else None,
               headers.group(0).decode().strip() if headers else None)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--prefix", default=str(Path.home() / ".wine-nexon"))
    ap.add_argument("--host", default="", help="only URLs containing this text")
    args = ap.parse_args()
    for cache in Path(args.prefix, "drive_c/users").glob("*/AppData/Local/Microsoft/Windows/INetCache/Content.IE5"):
        files = defaultdict(list)
        for f in cache.glob("*/*"):
            files[re.sub(r"(\[\d+\]|[0-9A-Z]{8})$", "", f.name)].append(f)
        for url, name, headers in entries(cache / "index.dat"):
            if args.host not in url:
                continue
            base = re.sub(r"\[\d+\]$", "", name or "")
            copies = sorted(files.get(base, []), key=lambda f: f.stat().st_mtime)
            body = next((f for f in reversed(copies) if f.stat().st_size), None)
            print(f"== {url}")
            print(f"   cache files: {len(copies)}" + (f", newest {copies[-1].name}" if copies else ""))
            if headers:
                print("   " + headers.replace("\r\n", "\n   "))
            if body:
                print(f"   body ({body.name}, {body.stat().st_size} B): {body.read_bytes()[:400]!r}")


if __name__ == "__main__":
    main()
