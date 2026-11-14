#!/usr/bin/env python3
"""Compare a controlled fixture session with a Procmon-style oracle CSV.

This is deliberately a class-level diff, not a claim of per-event equality.
Export Procmon with Operation, Path, Result, PID columns, filter to the fixture
PID/path, then run this against the session bundle.
"""

import argparse
import csv
import json
import pathlib
import sys


OPERATION_MAP = (
    ("createfile", "file_create"),
    ("openfile", "file_create"),
    ("readfile", "file_read"),
    ("writefile", "file_write"),
    ("closefile", "file_close"),
    ("setendoffile", "file_set_information"),
    ("setrename", "file_set_information"),
    ("setdisposition", "file_set_information"),
    ("setbasicinformation", "file_set_information"),
    ("querybasicinformation", "file_query_information"),
    ("querystandardinformation", "file_query_information"),
    ("queryfileinformation", "file_query_information"),
    ("querysecurity", "file_query_security"),
    ("regopenkey", "registry_open"),
    ("regqueryvalue", "registry_query"),
    ("regsetvalue", "registry_set_value"),
    ("regdeletevalue", "registry_delete"),
    ("regdeletekey", "registry_delete"),
    ("regenumkey", "registry_enumerate"),
    ("regenumvalue", "registry_enumerate"),
    ("tcpconnect", "network_connect"),
    ("tcpsend", "network_flow_established"),
    ("tcpreceive", "network_flow_established"),
)


def oracle_class(operation):
    lowered = "".join(ch for ch in operation.lower() if ch.isalnum())
    for needle, event in OPERATION_MAP:
        if needle in lowered:
            return event
    return "oracle:" + operation.strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--session", required=True)
    parser.add_argument("--oracle", required=True, help="Procmon CSV export")
    parser.add_argument("--pid", type=int, default=0)
    parser.add_argument("--path-contains", default="")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    directory = pathlib.Path(args.session).resolve()
    census_path = directory / "derived" / "census.json"
    if census_path.exists():
        ours = set(json.loads(census_path.read_text(encoding="utf-8")).get("type", {}))
    else:
        ours = set()
        for part in sorted(directory.glob("events.jsonl*")):
            with open(part, "r", encoding="utf-8") as handle:
                for line in handle:
                    try:
                        ours.add(json.loads(line).get("type", "unknown"))
                    except json.JSONDecodeError:
                        continue

    oracle = set()
    with open(args.oracle, "r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        columns = {name.lower(): name for name in (reader.fieldnames or [])}
        operation_key = columns.get("operation")
        path_key = columns.get("path") or columns.get("detail")
        pid_key = columns.get("pid") or columns.get("process id")
        if not operation_key:
            print("oracle CSV needs an Operation column", file=sys.stderr)
            return 1
        for row in reader:
            if args.pid and pid_key:
                try:
                    if int(row.get(pid_key, "0")) != args.pid:
                        continue
                except ValueError:
                    continue
            if args.path_contains and path_key and args.path_contains.lower() not in row.get(path_key, "").lower():
                continue
            oracle.add(oracle_class(row.get(operation_key, "")))

    comparable = {item for item in ours if item.startswith(("file_", "registry_", "network_"))}
    missing = sorted(oracle - comparable)
    extra = sorted(comparable - oracle)
    result = {"missing_classes": missing, "extra_classes": extra, "oracle_classes": sorted(oracle)}
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"oracle classes: {len(oracle)}  our comparable classes: {len(comparable)}")
        for item in missing:
            print(f"  missing from our log: {item}")
        for item in extra:
            print(f"  observed only by us: {item}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
