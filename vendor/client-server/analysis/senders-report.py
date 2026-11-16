#!/usr/bin/env python3
"""Which module of the game family makes each send, per server: from a kfilterctl watch log.

    .venv/bin/python analysis/senders-report.py captures/senders-<stamp>.log \
        [--recording captures/proxy-<stamp>.jsonl ...]

A proxy recording, if given, names each server address by the TLS server name (SNI) the
client asked for, and marks the game's own servers by their port. A caller in MapleStory.exe
is placed in its PE section (.text, or the Themida-protected sections).
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

SEND = re.compile(r"^(?P<time>\S+) pid=(?P<pid>\d+) (?P<image>\S+)\s+network\s+audit .*? send (?P<proto>tcp|udp) "
                  r"(?P<peer>\S+) socket:\[\d+\] #\d+ len=(?P<len>\d+)(?: caller=(?P<caller>\S+))?")
# MapleStory.exe build 0x6AEB667B (analysis/client-origins.py checks the build)
SECTIONS = [(0x1000, 0x3359000, ".text"), (0x3D83000, 0x3E19000, "packed section"),
            (0x3E1B000, 0x3E5B000, ".vm_sec"), (0x3EC2000, 0x52AE000, ".themida"), (0x52AE000, 0x5F2E000, ".boot")]


def place(caller):
    if not caller:
        return "no module (code outside every loaded module)"
    module, _, offset = caller.partition("+")
    if module.lower() == "maplestory.exe" and offset:
        rva = int(offset, 16)
        for start, end, name in SECTIONS:
            if start <= rva < end:
                return f"{module} {name}"
    return module


def names_from(recordings):
    names = {}
    for path in recordings:
        opened = {}
        for line in open(path, encoding="utf-8"):
            if '"kind":"data"' in line:
                continue
            record = json.loads(line)
            if record["kind"] == "connection_open":
                opened[record["conn"]] = record["destination"][0]
            elif record["kind"] == "tls_client_hello" and record.get("sni") and record["conn"] in opened:
                names[opened[record["conn"]]] = record["sni"]
    return names


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("log")
    ap.add_argument("--recording", action="append", default=[])
    args = ap.parse_args()
    names = names_from(args.recording)
    table = defaultdict(Counter)
    sizes = Counter()
    for line in open(args.log, encoding="utf-8", errors="replace"):
        m = SEND.match(line)
        if not m:
            continue
        ip, _, port = m["peer"].rpartition(":")
        port = int(port)
        server = ("game server" if 8400 <= port <= 8999 and port != 8913 else names.get(ip, ip)) + f" :{port}/{m['proto']}"
        key = (m["image"], server)
        table[key][place(m["caller"])] += 1
        sizes[key] += int(m["len"])
    print(f"{'program':<16} {'server':<58} {'sends':>6} {'bytes':>9}  module making the send")
    for (image, server), callers in sorted(table.items(), key=lambda kv: -sum(kv[1].values())):
        total = sum(callers.values())
        first = True
        for caller, count in callers.most_common():
            print(f"{image if first else '':<16} {server if first else '':<58} "
                  f"{count:>6} {sizes[(image, server)] if first else '':>9}  {caller}")
            first = False


if __name__ == "__main__":
    main()
