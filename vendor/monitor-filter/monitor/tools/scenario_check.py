#!/usr/bin/env python3
"""Compare a session's sensor-usage.json with tests/scenarios/<name>.json."""

import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("session_dir")
    parser.add_argument("--scenario", default=None)
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    directory = pathlib.Path(args.session_dir).resolve()
    with open(directory / "manifest.json", "r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    scenario = args.scenario or manifest.get("scenario", "other")
    expected_path = ROOT / "tests" / "scenarios" / f"{scenario}.json"
    usage_path = directory / "sensor-usage.json"
    if not expected_path.exists():
        print(f"no scenario file {expected_path}", file=sys.stderr)
        return 1
    if not usage_path.exists():
        print("sensor-usage.json is missing; run tools/sensor_report.py --write first", file=sys.stderr)
        return 1
    with open(expected_path, "r", encoding="utf-8") as handle:
        expected = set(json.load(handle).get("sensors", []))
    with open(usage_path, "r", encoding="utf-8") as handle:
        usage = json.load(handle)
    observed = {item["sensor_id"]: item for item in usage.get("sensors", [])}

    results = []
    for sensor_id in sorted(expected):
        item = observed.get(sensor_id)
        if item is None:
            results.append({"sensor_id": sensor_id, "status": "failing", "reason": "not instrumented"})
        elif item.get("activity") == "observed":
            results.append({"sensor_id": sensor_id, "status": "verified"})
        elif item.get("activity") in ("disabled", "unsupported"):
            results.append({"sensor_id": sensor_id, "status": "unavailable", "reason": item.get("activity")})
        else:
            results.append({"sensor_id": sensor_id, "status": "failing", "reason": item.get("activity")})
    for sensor_id, item in observed.items():
        if sensor_id not in expected and item.get("activity") == "observed":
            results.append({"sensor_id": sensor_id, "status": "unexpected"})

    summary = {
        "schema_version": 1,
        "session_uuid": manifest.get("session_uuid", ""),
        "scenario": scenario,
        "results": results,
    }
    if args.write:
        with open(directory / "scenario_results.json", "w", encoding="utf-8") as handle:
            json.dump(summary, handle, indent=2)
            handle.write("\n")
    if args.json:
        print(json.dumps(summary, indent=2))
        return 0
    counts = {}
    for item in results:
        counts[item["status"]] = counts.get(item["status"], 0) + 1
    print(f"scenario {scenario}: " + ", ".join(f"{key}={value}" for key, value in sorted(counts.items())))
    for item in results:
        print(f"  {item['status']:12} {item['sensor_id']}" + (f" ({item['reason']})" if item.get("reason") else ""))
    return 0 if not any(item["status"] == "failing" for item in results) else 1


if __name__ == "__main__":
    sys.exit(main())
