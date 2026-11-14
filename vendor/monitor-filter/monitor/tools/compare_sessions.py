#!/usr/bin/env python3
"""Compare two or more verified session bundles without a database."""

import argparse
import hashlib
import json
import pathlib
import sys


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def load_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def verify(directory):
    manifest = load_json(directory / "manifest.json")
    checksums = load_json(directory / "checksums.json")
    errors = []
    parts = checksums.get("parts", [])
    for part in parts:
        path = directory / part["name"]
        if not path.exists():
            errors.append(f"missing {part['name']}")
        elif sha256_file(path) != part["sha256"]:
            errors.append(f"hash mismatch {part['name']}")
    # session_pack computes bundle_sha256 over the manifest plus every part so
    # the manifest (which supplies everything compared below) cannot be edited
    # without detection; the schema check does not cover it.
    expected = checksums.get("bundle_sha256")
    if not expected:
        errors.append("missing bundle_sha256")
    else:
        material = sha256_file(directory / "manifest.json") + "".join(
            part["sha256"] for part in parts)
        if hashlib.sha256(material.encode("ascii")).hexdigest() != expected:
            errors.append("manifest hash mismatch")
    return manifest, errors


def sensors(directory):
    path = directory / "sensor-usage.json"
    if not path.exists():
        return {}
    data = load_json(path)
    return {item.get("sensor_id"): item for item in data.get("sensors", [])}


def summarize(manifest, directory):
    return {
        "test_id": manifest.get("test_id"),
        "session_uuid": manifest.get("session_uuid"),
        "machine": manifest.get("machine_label"),
        "scenario": manifest.get("scenario"),
        "iteration": manifest.get("iteration"),
        "client_version": manifest.get("client_version"),
        "build_commit": manifest.get("build_commit"),
        "outcome": manifest.get("outcome"),
        "events": manifest.get("record_count"),
        "driver_dropped": manifest.get("driver_dropped_events"),
        "driver_gaps": manifest.get("driver_sequence_gaps"),
        "etw_gaps": manifest.get("etw_sequence_gaps"),
        "sensors": sensors(directory),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("sessions", nargs="+", help="session bundle directories")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    summaries = []
    errors = []
    for item in args.sessions:
        directory = pathlib.Path(item).resolve()
        try:
            manifest, part_errors = verify(directory)
        except (OSError, KeyError, json.JSONDecodeError) as exc:
            errors.append(f"{directory}: {exc}")
            continue
        errors.extend(f"{directory}: {error}" for error in part_errors)
        summaries.append(summarize(manifest, directory))
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    if len(summaries) < 2:
        print("need at least two sessions", file=sys.stderr)
        return 1

    baseline = summaries[0]
    result = {"baseline": baseline["test_id"], "sessions": summaries, "changes": []}
    for current in summaries[1:]:
        change = {
            "test_id": current["test_id"],
            "events_delta": (current["events"] or 0) - (baseline["events"] or 0),
            "driver_dropped_delta": (current["driver_dropped"] or 0) - (baseline["driver_dropped"] or 0),
            "driver_gaps_delta": (current["driver_gaps"] or 0) - (baseline["driver_gaps"] or 0),
            "etw_gaps_delta": (current["etw_gaps"] or 0) - (baseline["etw_gaps"] or 0),
            "sensor_changes": [],
        }
        for sensor_id, before in baseline["sensors"].items():
            after = current["sensors"].get(sensor_id)
            if after is None:
                change["sensor_changes"].append({"sensor_id": sensor_id, "from": before.get("activity"), "to": "missing"})
                continue
            if (before.get("activity"), before.get("health"), before.get("verification")) != (
                    after.get("activity"), after.get("health"), after.get("verification")):
                change["sensor_changes"].append({
                    "sensor_id": sensor_id,
                    "from": [before.get("activity"), before.get("health"), before.get("verification")],
                    "to": [after.get("activity"), after.get("health"), after.get("verification")],
                })
        result["changes"].append(change)

    if args.json:
        print(json.dumps(result, indent=2))
        return 0

    print(f"{'test_id':48} {'scenario':12} {'events':>9} {'drops':>7} {'gaps':>6} outcome")
    for item in summaries:
        print(f"{str(item['test_id'])[:48]:48} {str(item['scenario'])[:12]:12} "
              f"{item['events'] or 0:9} {item['driver_dropped'] or 0:7} "
              f"{item['driver_gaps'] or 0:6} {item['outcome']}")
    for change in result["changes"]:
        print(f"\n{change['test_id']}: events {change['events_delta']:+}, "
              f"drops {change['driver_dropped_delta']:+}, gaps {change['driver_gaps_delta']:+}")
        for sensor in change["sensor_changes"]:
            print(f"  {sensor['sensor_id']}: {sensor['from']} -> {sensor['to']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
