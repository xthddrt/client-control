#!/usr/bin/env python3
"""Validate event JSONL and session bundles against the documented schema subset.

The standard library has no full JSON Schema engine.  This validator implements
exactly the keywords used by `schema/*.json`: type, const, enum, pattern,
minLength, maxLength, minimum, maximum, required, properties,
additionalProperties, items, allOf, oneOf. Anything else is ignored, and the docs say so.
"""

import argparse
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_EVENT_SCHEMA = ROOT / "schema" / "event-v1.json"
SESSION_SCHEMA = ROOT / "schema" / "session-v1.json"
CHECKSUMS_SCHEMA = ROOT / "schema" / "checksums-v1.json"
SENSOR_SCHEMA = ROOT / "schema" / "sensor-usage-v1.json"
COVERAGE_SCHEMA = ROOT / "schema" / "coverage-v1.json"


def type_matches(value, expected):
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "null":
        return value is None
    return True


def validate(value, schema, path="$", errors=None):
    errors = [] if errors is None else errors
    if schema is True or schema == {}:
        return errors
    if schema is False:
        errors.append(f"{path}: not allowed")
        return errors

    expected = schema.get("type")
    if expected is not None:
        types = expected if isinstance(expected, list) else [expected]
        if not any(type_matches(value, item) for item in types):
            errors.append(f"{path}: expected {expected}, got {type(value).__name__}")
            return errors

    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: expected const {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: {value!r} not in enum")
    if isinstance(value, str):
        if "pattern" in schema and not re.search(schema["pattern"], value):
            errors.append(f"{path}: does not match {schema['pattern']}")
        if "minLength" in schema and len(value) < schema["minLength"]:
            errors.append(f"{path}: shorter than {schema['minLength']}")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            errors.append(f"{path}: longer than {schema['maxLength']}")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path}: below minimum {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(f"{path}: above maximum {schema['maximum']}")

    if isinstance(value, dict):
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{path}: missing required {key}")
        properties = schema.get("properties", {})
        for key, child in properties.items():
            if key in value:
                validate(value[key], child, f"{path}.{key}", errors)
        additional = schema.get("additionalProperties", True)
        if additional is False:
            for key in value:
                if key not in properties:
                    errors.append(f"{path}: unexpected property {key}")
        elif isinstance(additional, dict):
            for key, child in value.items():
                if key not in properties:
                    validate(child, additional, f"{path}.{key}", errors)

    if isinstance(value, list) and "items" in schema:
        for index, item in enumerate(value):
            validate(item, schema["items"], f"{path}[{index}]", errors)

    for key in ("allOf",):
        for child in schema.get(key, []):
            validate(value, child, path, errors)
    if "oneOf" in schema:
        branch_errors = [validate(value, child, path, []) for child in schema["oneOf"]]
        matches = sum(1 for item in branch_errors if not item)
        if matches != 1:
            errors.append(f"{path}: expected exactly one oneOf match, got {matches}")
            if matches == 0 and branch_errors:
                errors.extend(min(branch_errors, key=len))
    return errors


def load_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def validate_jsonl(path, schema, allow_legacy=False):
    errors = []
    count = 0
    with open(path, "r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            count += 1
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                errors.append(f"{path}:{number}: invalid JSON: {exc}")
                continue
            if allow_legacy and "schema_version" not in record:
                continue
            for error in validate(record, schema, f"{path}:{number}"):
                errors.append(error)
    return count, errors


def validate_bundle(directory):
    directory = pathlib.Path(directory)
    errors = []
    counts = {}
    for name, schema_path in (
        ("manifest.json", SESSION_SCHEMA),
        ("checksums.json", CHECKSUMS_SCHEMA),
        ("sensor-usage.json", SENSOR_SCHEMA),
        ("coverage.json", COVERAGE_SCHEMA),
    ):
        path = directory / name
        if not path.exists():
            if name in ("sensor-usage.json", "coverage.json"):
                continue
            errors.append(f"{path}: missing")
            continue
        errors.extend(validate(load_json(path), load_json(schema_path), name))
    schema = load_json(DEFAULT_EVENT_SCHEMA)
    for part in sorted(directory.glob("events.jsonl*")):
        count, part_errors = validate_jsonl(part, schema)
        counts[part.name] = count
        errors.extend(part_errors)
    return counts, errors


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("path", nargs="?", help="JSONL file or session directory")
    parser.add_argument("--schema", default=str(DEFAULT_EVENT_SCHEMA))
    parser.add_argument("--session", help="session bundle directory")
    parser.add_argument("--allow-legacy", action="store_true", help="skip records without schema_version")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if args.session or (args.path and pathlib.Path(args.path).is_dir()):
        directory = args.session or args.path
        counts, errors = validate_bundle(directory)
        result = {"ok": not errors, "records": counts, "errors": errors[:200]}
    elif args.path:
        schema = load_json(args.schema)
        count, errors = validate_jsonl(args.path, schema, args.allow_legacy)
        result = {"ok": not errors, "records": count, "errors": errors[:200]}
    else:
        parser.error("provide a JSONL file or --session DIRECTORY")

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"records={result['records']} errors={len(result['errors'])}")
        for error in result["errors"][:50]:
            print(error)
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
