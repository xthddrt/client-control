#!/usr/bin/env python3
"""Build sensor-usage.json from a session bundle and the sensor map."""

import argparse
import datetime
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
MAP = ROOT / "coverage" / "sensor-map.json"


def load(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("session_dir")
    parser.add_argument("--scenario", default=None)
    parser.add_argument("--write", action="store_true", help="write sensor-usage.json")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--drop-ratio", type=float, default=0.001)
    args = parser.parse_args()

    directory = pathlib.Path(args.session_dir).resolve()
    manifest_path = directory / "manifest.json"
    if not manifest_path.exists():
        manifest_path = directory / "session_meta.json"
    manifest = load(manifest_path)
    scenario = args.scenario or manifest.get("scenario", "other")
    coverage_path = directory / "coverage.json"
    coverage = load(coverage_path) if coverage_path.exists() else {}
    driver = coverage.get("driver", {})
    agent = coverage.get("agent", {})
    agent_counts = {int(key): int(value) for key, value in agent.get("event_counts", {}).items()}
    supported = bool(coverage.get("driver_supported"))
    sensor_map = load(MAP)["sensors"]

    event_by_name = {item["event_type"]: item for item in sensor_map if item.get("kind") == "event"}
    event_by_id = {item["type_id"]: item for item in sensor_map if item.get("kind") == "event"}
    expected_file = ROOT / "tests" / "scenarios" / f"{scenario}.json"
    expected = set()
    if expected_file.exists():
        expected = set(load(expected_file).get("sensors", []))

    def counters(type_id):
        if not isinstance(type_id, int):
            return 0, 0
        if type_id >= 100 and type_id in agent_counts:
            return agent_counts[type_id], 0
        if not supported:
            return 0, 0
        attempted = driver.get("event_attempted", [])
        dropped = driver.get("event_dropped", [])
        return (attempted[type_id] if type_id < len(attempted) else 0,
                dropped[type_id] if type_id < len(dropped) else 0)

    def health(attempted, dropped):
        if attempted <= 0:
            return "unknown"
        if dropped <= 0:
            return "ok"
        return "degraded" if dropped / attempted > args.drop_ratio else "lossy"

    results = []
    for item in sensor_map:
        sensor_id = item["sensor_id"]
        kind = item["kind"]
        attempted = dropped = entered = logged = 0
        activity = "not_instrumented"
        health_state = "unknown"
        registration = ""

        if kind == "event":
            type_id = item.get("type_id")
            attempted, dropped = counters(type_id)
            # Linux logs etw_tcp from its kernel sensors, so --no-etw does not silence it there.
            if item["event_type"].startswith("etw_") and attempted == 0 and not manifest.get("config", {}).get("etw", True):
                activity = "disabled"
            elif not supported:
                activity = "unsupported" if not coverage else "not_instrumented"
            elif attempted > 0:
                activity = "observed"
            else:
                activity = "enabled_not_observed"
            health_state = health(attempted, dropped)
        elif kind == "callback":
            slot = item.get("slot", 0)
            entered_list = driver.get("sensor_entered", [])
            logged_list = driver.get("sensor_logged", [])
            entered = entered_list[slot] if slot < len(entered_list) else 0
            logged = logged_list[slot] if slot < len(logged_list) else 0
            for name in item.get("event_types", []):
                type_id = event_by_name.get(name, {}).get("type_id")
                a, d = counters(type_id)
                attempted += a
                dropped += d
            if not supported:
                activity = "unsupported" if not coverage else "not_instrumented"
            elif logged > 0:
                activity = "observed"
            elif entered > 0:
                activity = "skipped"
            else:
                activity = "enabled_not_observed"
            health_state = health(attempted, dropped)
        elif kind == "registration":
            slot = item.get("slot", 0)
            statuses = driver.get("registration_status", [])
            status = statuses[slot] if slot < len(statuses) else 0
            failed = int(driver.get("registration_failed", 0)) & (1 << slot)
            succeeded = int(driver.get("registration_ok", 0)) & (1 << slot)
            if not supported:
                activity = "unsupported" if not coverage else "not_instrumented"
            elif failed:
                activity = "registration_failed"
                registration = f"0x{status & 0xFFFFFFFF:08X}"
            elif succeeded:
                activity = "observed"
                registration = "ok"
            else:
                activity = "enabled_not_observed"
        elif kind == "agent":
            providers = {entry.get("name"): entry for entry in agent.get("etw_providers", [])}
            provider = providers.get(item.get("provider"), {})
            entered = provider.get("received", 0)
            logged = provider.get("emitted", 0)
            attempted = entered
            dropped = provider.get("expired", 0)
            if not manifest.get("config", {}).get("etw", True):
                activity = "disabled"
            elif logged > 0:
                activity = "observed"
            elif entered > 0:
                activity = "skipped"
            else:
                activity = "enabled_not_observed"
            if agent.get("etw_lost", 0):
                health_state = "lossy"
            elif attempted > 0:
                health_state = health(attempted, dropped)
            else:
                health_state = "ok"

        expected_for = scenario in item.get("expected_in", []) or sensor_id in expected
        if sensor_id in expected:
            verification = "verified" if activity == "observed" else "failing"
        else:
            verification = "unverified"

        results.append({
            "sensor_id": sensor_id,
            "kind": kind,
            "implementation": item.get("implementation", ""),
            "event_types": item.get("event_types", [item.get("event_type")] if item.get("event_type") else []),
            "entered": entered,
            "logged": logged,
            "attempted": attempted,
            "dropped": dropped,
            "registration_status": registration,
            "activity": activity,
            "health": health_state,
            "verification": verification,
            "mapped": True,
            "expected_for_scenario": expected_for,
        })

    usage = {
        "schema_version": 1,
        "session_uuid": manifest.get("session_uuid", ""),
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scenario": scenario,
        "sensors": results,
    }
    if args.write:
        with open(directory / "sensor-usage.json", "w", encoding="utf-8") as handle:
            json.dump(usage, handle, indent=2)
            handle.write("\n")

    if args.json:
        print(json.dumps(usage, indent=2))
        return 0

    counts = {}
    for item in results:
        counts[item["activity"]] = counts.get(item["activity"], 0) + 1
    print(f"session {manifest.get('test_id')} scenario {scenario}")
    print("activity:", ", ".join(f"{key}={value}" for key, value in sorted(counts.items())))
    for item in results:
        if item["activity"] in ("observed", "skipped", "registration_failed") or item["verification"] == "failing":
            print(f"  {item['sensor_id']:34} {item['activity']:22} {item['health']:9} {item['verification']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
