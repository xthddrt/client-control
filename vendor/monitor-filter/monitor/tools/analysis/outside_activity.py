#!/usr/bin/env python3
"""Command lines, file reads outside the client folder, and registry writes outside the game's own settings."""

import argparse
import collections
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from common import dos_path, iter_events, registry_key, short_image  # noqa: E402

# The launcher passes a login token after -nxl; never print it.
TOKEN = re.compile(r"(-nxl\s+)\S+")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("session_dir")
    parser.add_argument("--own-settings", default=r"Wizet\MapleStoryClassic",
                        help="registry path fragment treated as the game's own settings and skipped")
    parser.add_argument("--limit", type=int, default=15)
    args = parser.parse_args()

    commands = []
    reads = collections.defaultdict(collections.Counter)
    writes = collections.defaultdict(collections.Counter)
    for event in iter_events(args.session_dir):
        kind = event.get("type")
        image = short_image(event.get("process_path"))
        text = event.get("text") or ""
        if kind == "process_start":
            commands.append((event.get("process_id"), short_image(text), TOKEN.sub(r"\1<token>", event.get("detail") or "")[:220]))
        elif kind == "file_read":
            path = dos_path(text)
            if "maplestorycw" not in path.lower():
                reads[image]["\\".join(path.split("\\")[:6])] += 1
        elif kind in ("registry_set_value", "registry_delete", "registry_rename", "registry_create"):
            key = registry_key(text)
            if args.own_settings.lower() in key.lower():
                continue
            writes[image][(kind.replace("registry_", ""), key, event.get("detail") or "")] += 1

    print("== command lines (launcher token redacted)")
    for row in commands:
        print("  ", row)
    print("\n== file reads outside the client folder, by process and folder")
    for image, counter in reads.items():
        print(" ", image)
        for folder, count in counter.most_common(args.limit):
            print(f"     {count:7} {folder}")
    print(f"\n== registry writes outside {args.own_settings}")
    for image, counter in writes.items():
        print(" ", image)
        for key, count in counter.most_common(args.limit * 3):
            print(f"     {count:4} {key}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
