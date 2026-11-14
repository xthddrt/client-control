#!/usr/bin/env python3
"""Finalize an agent session directory into an immutable, verifiable bundle.

The agent writes events.jsonl, summary.json, session_meta.json and (later)
coverage.json.  This tool verifies the chain, adds environment/notes/census,
writes manifest.json and checksums.json, and optionally compresses the bundle.
Raw JSONL is never modified.
"""

import argparse
import datetime
import hashlib
import json
import os
import pathlib
import platform
import subprocess
import sys
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
VERIFY = ROOT / "tools" / "verify_log.py"
VALIDATE = ROOT / "tools" / "validate_schema.py"


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def load_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=False)
        handle.write("\n")


def event_parts(directory):
    parts = []
    for path in directory.glob("events.jsonl*"):
        suffix = path.name[len("events.jsonl"):]
        order = int(suffix[1:]) if suffix.startswith(".") and suffix[1:].isdigit() else 0
        parts.append((order, path))
    return [path for _, path in sorted(parts)]


def chain_head(parts):
    head = "0" * 64
    count = 0
    for path in parts:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                count += 1
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(record.get("chain"), str):
                    head = record["chain"]
    return head, count


def verify_chain(parts, skip):
    if skip or not parts:
        return []
    result = subprocess.run(
        [sys.executable, str(VERIFY)] + [str(path) for path in parts],
        capture_output=True, text=True
    )
    return [] if result.returncode == 0 else [result.stdout.strip(), result.stderr.strip()]


def census(parts):
    counts = {"type": {}, "source": {}, "category": {}, "status": {}, "flags": {}, "process": {}}
    for path in parts:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                for field, key in (("type", "type"), ("source", "source"),
                                   ("category", "category"), ("status", "status_name")):
                    value = str(record.get(key, "unknown"))
                    counts[field][value] = counts[field].get(value, 0) + 1
                flags = record.get("flags", 0)
                counts["flags"][str(flags)] = counts["flags"].get(str(flags), 0) + 1
                process = record.get("process_path") or str(record.get("process_id", 0))
                if process:
                    counts["process"][process] = counts["process"].get(process, 0) + 1
    return counts


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("session_dir", help="directory written by msmon-agent --log-dir")
    parser.add_argument("--output", help="compressed bundle path (default <session>.zip)")
    parser.add_argument("--no-compress", action="store_true")
    parser.add_argument("--skip-verify", action="store_true")
    parser.add_argument("--sensitivity", choices=["metadata", "payload", "secrets"])
    args = parser.parse_args()

    directory = pathlib.Path(args.session_dir).resolve()
    meta_path = directory / "session_meta.json"
    if not meta_path.exists():
        print(f"missing {meta_path}", file=sys.stderr)
        return 1
    meta = load_json(meta_path)
    if meta.get("outcome") in (None, "", "in_progress"):
        meta["outcome"] = "incomplete"

    parts = event_parts(directory)
    if not parts:
        print("no events.jsonl parts found", file=sys.stderr)
        return 1

    errors = verify_chain(parts, args.skip_verify)
    if errors:
        print("chain verification failed:", file=sys.stderr)
        for error in errors:
            if error:
                print(error, file=sys.stderr)
        return 1

    head, record_count = chain_head(parts)
    raw_bytes = sum(path.stat().st_size for path in parts)

    derived = directory / "derived"
    derived.mkdir(exist_ok=True)
    write_json(derived / "census.json", census(parts))

    environment = {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "os_version": platform.version(),
        "python": sys.version.split()[0],
        "captured_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "hostname": platform.node(),
    }
    write_json(directory / "environment.json", environment)

    notes = directory / "notes.md"
    if not notes.exists():
        notes.write_text(
            f"# Session {meta.get('test_id', '')}\n\n"
            f"- scenario: {meta.get('scenario', '')}\n"
            f"- phase: {meta.get('phase', '')}\n"
            f"- outcome: {meta.get('outcome', '')}\n"
            f"- machine: {meta.get('machine_label', '')}\n"
            f"- client: {meta.get('client_root', '')} (version: {meta.get('client_version') or 'unknown'})\n"
            f"- build: {meta.get('build_commit', '')}\n\n"
            "Operator notes go here.\n",
            encoding="utf-8"
        )

    sensitivity = args.sensitivity
    if sensitivity is None:
        # The Linux agent says "secrets" itself: its payloads are the client's socket bytes.
        sensitivity = meta.get("sensitivity") or (
            "payload" if meta.get("config", {}).get("payload_mode") == "full" else "metadata")

    coverage = directory / "coverage.json"
    if coverage.exists():
        sensor_report = ROOT / "tools" / "sensor_report.py"
        if sensor_report.exists():
            scenario = meta.get("scenario", "other")
            result = subprocess.run([sys.executable, str(sensor_report), str(directory),
                                     "--scenario", scenario, "--write"],
                                    capture_output=True, text=True)
            if result.returncode != 0:
                print("sensor report failed:", file=sys.stderr)
                print(result.stdout, file=sys.stderr)
                print(result.stderr, file=sys.stderr)

    local_build_info = ROOT / "build" / "build-info.json"
    if local_build_info.exists():
        build_info = load_json(local_build_info)
        manifest_driver = meta.get("driver_sha256", "")
        manifest_agent = meta.get("agent_sha256", "")
        meta["build_info_local"] = build_info
        if meta.get("build_commit") in (None, "", "unknown"):
            meta["build_commit"] = build_info.get("commit", "unknown")
        meta["provenance_match"] = bool(
            manifest_driver and manifest_agent and
            manifest_driver == build_info.get("driver_sha256") and
            manifest_agent == build_info.get("agent_sha256")
        )
        if manifest_driver and build_info.get("driver_sha256") and not meta["provenance_match"]:
            meta["stale_build_info"] = True

    all_parts = []
    for path in sorted(directory.rglob("*")):
        if not path.is_file():
            continue
        if path.name in ("manifest.json", "checksums.json", "bundle.sha256"):
            continue
        if path.suffix == ".zip":
            continue
        all_parts.append({
            "name": path.relative_to(directory).as_posix(),
            "bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        })

    manifest = dict(meta)
    manifest.update({
        "schema_version": 1,
        "sensitivity": sensitivity,
        "environment": environment,
        "parts": all_parts,
        "record_count": record_count,
        "raw_bytes": raw_bytes,
        "part_count": len(parts),
        "chain_head": head,
    })
    write_json(directory / "manifest.json", manifest)

    manifest_hash = sha256_file(directory / "manifest.json")
    bundle_material = manifest_hash + "".join(part["sha256"] for part in all_parts)
    bundle_hash = hashlib.sha256(bundle_material.encode("ascii")).hexdigest()
    checksums = {
        "schema_version": 1,
        "session_uuid": manifest.get("session_uuid", ""),
        "parts": all_parts,
        "chain_head": head,
        "record_count": record_count,
        "bundle_sha256": bundle_hash,
    }
    write_json(directory / "checksums.json", checksums)
    (directory / "bundle.sha256").write_text(bundle_hash + "\n", encoding="ascii")

    validate = subprocess.run([sys.executable, str(VALIDATE), "--session", str(directory)],
                              capture_output=True, text=True)
    if validate.returncode != 0:
        print("schema validation failed:", file=sys.stderr)
        print(validate.stdout, file=sys.stderr)
        print(validate.stderr, file=sys.stderr)
        return 1

    print(f"session {manifest.get('test_id')}")
    print(f"records {record_count}  parts {len(parts)}  raw_bytes {raw_bytes}")
    print(f"outcome {manifest.get('outcome')}  sensitivity {sensitivity}")
    print(f"chain_head {head}")
    print(f"bundle_sha256 {bundle_hash}")

    if not args.no_compress:
        output = pathlib.Path(args.output) if args.output else directory.with_suffix(".zip")
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(directory.rglob("*")):
                if path.is_file() and path != output:
                    archive.write(path, path.relative_to(directory).as_posix())
        print(f"compressed {output} ({output.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
