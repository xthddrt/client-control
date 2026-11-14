#!/usr/bin/env python3
"""Why registry/volume payloads were not captured: counts by event type, status and recorded reason."""

import argparse
import collections
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from common import iter_events  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("session_dir")
    args = parser.parse_args()

    reasons, kinds, statuses, samples = collections.Counter(), collections.Counter(), collections.Counter(), {}
    for event in iter_events(args.session_dir, contains="payload_unavailable"):
        if "payload_unavailable" not in (event.get("flags_names") or []):
            continue
        detail = event.get("detail") or ""
        reason = detail.split(";")[0] if detail else "(none)"
        reasons[reason] += 1
        kinds[event.get("type")] += 1
        statuses[event.get("status_name")] += 1
        samples.setdefault(reason, (event.get("type"), event.get("status_name"), (event.get("text") or "")[-70:], detail[:120]))
    print("by type:", kinds.most_common(8))
    print("by status:", statuses.most_common(8))
    print("by reason:")
    for reason, count in reasons.most_common(15):
        print(f"   {count:8} {reason}  e.g. {samples[reason]}")
    print("\nSTATUS_OBJECT_NAME_NOT_FOUND means the value does not exist: the query is logged, there was nothing to capture.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
