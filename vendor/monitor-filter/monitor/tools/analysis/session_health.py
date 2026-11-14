#!/usr/bin/env python3
"""Overview of one session: tracked processes, drops and gaps, BlackCat, collector stats, busiest seconds."""

import argparse
import collections
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from common import hhmmss, iter_events, short_image  # noqa: E402
from session_activity import incarnation_at, incarnation_spans  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("session_dir")
    args = parser.parse_args()

    spans = incarnation_spans(args.session_dir)
    starts, exits, gaps, statistics, coverage = [], [], [], [], []
    per_second = collections.Counter()
    per_process = collections.defaultdict(collections.Counter)
    blackcat = collections.Counter()
    images = {}
    for event in iter_events(args.session_dir):
        kind = event.get("type")
        timestamp = event.get("timestamp")
        if kind == "observer_sequence_gap":
            gaps.append((event.get("source"), event.get("after_sequence"), event.get("missing_events")))
            continue
        if kind == "coverage":
            text = event.get("text") or ""
            if text == "driver_statistics":
                statistics.append((hhmmss(timestamp), event.get("detail")))
            elif "blackcat" in text or text in ("session_start", "driver_pump", "etw_accounting", "file_snapshots"):
                coverage.append((hhmmss(timestamp), text, (event.get("detail") or "")[:160]))
            continue
        pid = event.get("process_id") or 0
        created = event.get("process_start_time") or incarnation_at(spans, pid, timestamp or "") or 0
        identity = (pid, created)
        if event.get("process_path"):
            images.setdefault(identity, short_image(event["process_path"]))
        if kind == "process_start":
            images[identity] = short_image(event.get("text"))
            starts.append((hhmmss(timestamp), pid, event.get("parent_process_id"), event.get("flags_names"), images[identity]))
        elif kind == "process_exit":
            exits.append((hhmmss(timestamp), pid))
        if event.get("source") == "driver" and timestamp:
            per_second[timestamp[:19]] += 1
        if event.get("component"):
            blackcat[(images.get(identity, pid), kind)] += 1
        per_process[identity][kind] += 1

    print("== tracked process starts (UTC)")
    for row in starts:
        print("  ", row)
    print("== exits:", exits)
    print("== coverage records")
    for row in coverage:
        print("  ", row)
    print("== periodic driver statistics")
    for row in statistics:
        print("  ", row)
    print(f"== sequence gaps: {len(gaps)}, missing events: {sum(gap[2] or 0 for gap in gaps)}")
    for row in gaps[:20]:
        print("  ", row)
    print("== busiest seconds (driver events/s):", per_second.most_common(6))
    print("== BlackCat-attributed events by (process, type):", blackcat.most_common(10))
    print("== events per process")
    for (pid, created), counter in sorted(per_process.items(), key=lambda item: -sum(item[1].values()))[:10]:
        print(f"   {pid:>6}@{created:<10} {images.get((pid, created), '?'):20} {sum(counter.values()):8}  {counter.most_common(5)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
