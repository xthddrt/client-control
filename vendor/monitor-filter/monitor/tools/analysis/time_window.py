#!/usr/bin/env python3
"""Everything tracked processes did between two UTC times, with the module that made each request."""

import argparse
import collections
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from common import caller_module, dos_path, hhmmss, iter_lines, short_image  # noqa: E402

NOISY = {"registry_query", "registry_open", "registry_set_value", "file_read", "file_cleanup", "file_close",
         "file_query_information", "file_section", "etw_rpc"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("session_dir")
    parser.add_argument("start", help="UTC start, HH:MM:SS[.fff]")
    parser.add_argument("end", help="UTC end, HH:MM:SS[.fff]")
    parser.add_argument("--all", action="store_true", help="also list high-volume types (reads, queries, RPC)")
    parser.add_argument("--limit", type=int, default=200, help="maximum events listed")
    args = parser.parse_args()

    stamp = re.compile(r'"timestamp":"[^"]*T([0-9:.]+)Z"')

    def clock_ms(text, end):
        """HH:MM:SS[.fff] to milliseconds; a fractionless end covers its whole second."""
        head, _, fraction = text.partition(".")
        hours, minutes, seconds = (int(part) for part in head.split(":"))
        if fraction:
            milliseconds = int(fraction.ljust(3, "0")[:3])
        else:
            milliseconds = 999 if end else 0
        return ((hours * 60 + minutes) * 60 + seconds) * 1000 + milliseconds

    start_ms = clock_ms(args.start, False)
    end_ms = clock_ms(args.end, True)
    counts = collections.Counter()
    listed = 0
    for line in iter_lines(args.session_dir):
        match = stamp.search(line)
        if not match or not (start_ms <= clock_ms(match.group(1), False) <= end_ms):
            continue
        event = json.loads(line)
        kind = event.get("type")
        image = short_image(event.get("process_path")) or str(event.get("process_id"))
        caller = caller_module(event) if event.get("modules") else ""
        counts[(image, kind, caller)] += 1
        if (kind in NOISY and not args.all) or listed >= args.limit:
            continue
        listed += 1
        target = short_image(event.get("text")) if (kind or "").endswith("handle") else dos_path(event.get("text"))[-70:]
        extra = []
        if event.get("detail"):
            extra.append(event["detail"][:60])
        if event.get("status_name") not in (None, "STATUS_SUCCESS"):
            extra.append(event["status_name"])
        if event.get("component"):
            extra.append("component=" + event["component"])
        if event.get("stack_unresolved"):
            extra.append(f"unresolved={event['stack_unresolved']}")
        print(f"{hhmmss(event.get('timestamp'))} {image:16} {kind:24} {caller:28} {target}  {' '.join(extra)}")
    print(f"\n== counts {args.start}..{args.end} by (process, type, calling module)")
    for key, count in counts.most_common(40):
        print(f"   {count:7} {key}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
