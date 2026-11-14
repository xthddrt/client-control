#!/usr/bin/env python3
"""Build a local SQLite catalog from session manifests.  Derived, rebuildable."""

import argparse
import json
import pathlib
import sqlite3
import sys


SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    session_uuid TEXT PRIMARY KEY,
    test_id TEXT, session_label TEXT, machine_label TEXT, scenario TEXT,
    iteration INTEGER, phase TEXT, started_utc TEXT, ended_utc TEXT,
    outcome TEXT, client_version TEXT, client_sha256 TEXT, build_commit TEXT,
    driver_sha256 TEXT, agent_sha256 TEXT, os_version TEXT,
    payload_mode TEXT, etw INTEGER, record_count INTEGER, raw_bytes INTEGER,
    chain_head TEXT, sensitivity TEXT, bundle_path TEXT
);
CREATE TABLE IF NOT EXISTS parts (
    session_uuid TEXT, name TEXT, bytes INTEGER, sha256 TEXT,
    PRIMARY KEY (session_uuid, name)
);
CREATE TABLE IF NOT EXISTS event_counts (
    session_uuid TEXT, type TEXT, count INTEGER,
    PRIMARY KEY (session_uuid, type)
);
CREATE TABLE IF NOT EXISTS sensors (
    session_uuid TEXT, sensor_id TEXT, activity TEXT, health TEXT,
    verification TEXT, entered INTEGER, logged INTEGER,
    attempted INTEGER, dropped INTEGER,
    PRIMARY KEY (session_uuid, sensor_id)
);
CREATE TABLE IF NOT EXISTS scenario_results (
    session_uuid TEXT, sensor_id TEXT, status TEXT, reason TEXT,
    PRIMARY KEY (session_uuid, sensor_id)
);
"""


def load(path):
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return json.load(handle)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default="sessions")
    parser.add_argument("--db", default="catalog.sqlite")
    args = parser.parse_args()

    root = pathlib.Path(args.root).resolve()
    manifests = sorted(root.rglob("manifest.json"))
    db = sqlite3.connect(args.db)
    db.executescript(SCHEMA)
    indexed = 0
    for manifest_path in manifests:
        try:
            manifest = load(manifest_path)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"skip {manifest_path}: {exc}", file=sys.stderr)
            continue
        directory = manifest_path.parent
        uuid = manifest.get("session_uuid")
        if not uuid:
            continue
        db.execute("DELETE FROM sessions WHERE session_uuid=?", (uuid,))
        for table in ("parts", "event_counts", "sensors", "scenario_results"):
            db.execute(f"DELETE FROM {table} WHERE session_uuid=?", (uuid,))
        config = manifest.get("config", {})
        environment = manifest.get("environment", {})
        db.execute(
            "INSERT INTO sessions VALUES (" + ",".join(["?"] * 23) + ")",
            (
                uuid, manifest.get("test_id"), manifest.get("session_label"),
                manifest.get("machine_label"), manifest.get("scenario"),
                manifest.get("iteration"), manifest.get("phase"),
                manifest.get("started_utc"), manifest.get("ended_utc"),
                manifest.get("outcome"), manifest.get("client_version"),
                manifest.get("client_sha256"), manifest.get("build_commit"),
                manifest.get("driver_sha256"), manifest.get("agent_sha256"),
                environment.get("os_version"), config.get("payload_mode"),
                1 if config.get("etw") else 0, manifest.get("record_count"),
                manifest.get("raw_bytes"), manifest.get("chain_head"),
                manifest.get("sensitivity"), str(directory),
            ),
        )
        for part in manifest.get("parts", []):
            db.execute("INSERT OR REPLACE INTO parts VALUES (?,?,?,?)",
                       (uuid, part.get("name"), part.get("bytes"), part.get("sha256")))
        census_path = directory / "derived" / "census.json"
        if census_path.exists():
            census = load(census_path)
            for event_type, count in census.get("type", {}).items():
                db.execute("INSERT OR REPLACE INTO event_counts VALUES (?,?,?)",
                           (uuid, event_type, count))
        usage_path = directory / "sensor-usage.json"
        if usage_path.exists():
            usage = load(usage_path)
            for item in usage.get("sensors", []):
                db.execute("INSERT OR REPLACE INTO sensors VALUES (?,?,?,?,?,?,?,?,?)",
                           (uuid, item.get("sensor_id"), item.get("activity"),
                            item.get("health"), item.get("verification"),
                            item.get("entered", 0), item.get("logged", 0),
                            item.get("attempted", 0), item.get("dropped", 0)))
        scenario_path = directory / "scenario_results.json"
        if scenario_path.exists():
            results = load(scenario_path)
            for item in results.get("results", []):
                db.execute("INSERT OR REPLACE INTO scenario_results VALUES (?,?,?,?)",
                           (uuid, item.get("sensor_id"), item.get("status"), item.get("reason", "")))
        indexed += 1
    db.commit()
    print(f"indexed {indexed} sessions into {pathlib.Path(args.db).resolve()}")
    db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
