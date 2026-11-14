"""Small shared helpers: time, hashes, JSONL, interval and match primitives."""

from __future__ import annotations

import datetime as _dt
import fnmatch
import hashlib
import ipaddress
import json
import os
from pathlib import Path


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def read_json(path: Path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def iter_jsonl(path: Path):
    """Yield (line_number, object) for non-empty JSONL lines."""
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for number, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"{path}:{number}: invalid JSON: {error}") from error
            yield number, value


def write_jsonl(path: Path, records) -> int:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with open(path, "w", encoding="utf-8") as handle:
        for record in records:
            handle.write(canonical_json(record) + "\n")
            count += 1
    return count


def as_int(value, default=None):
    """Accept ints, decimal strings, and 0x-prefixed hex strings."""
    if value is None:
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    text = str(value).strip()
    if not text:
        return default
    try:
        return int(text, 0)
    except ValueError:
        return default


def as_bytes(value, default=None):
    if value is None:
        return default
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    text = str(value).strip()
    if text.startswith("0x"):
        text = text[2:]
    try:
        return bytes.fromhex(text)
    except ValueError:
        return default


def parse_time_ns(value, default=None):
    """Accept epoch seconds (int/float), nanoseconds, ISO-8601, or None."""
    if value is None:
        return default
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        number = float(value)
        # Values below 1e11 are seconds; below 1e14 are milliseconds; else ns.
        if abs(number) < 1e11:
            return int(number * 1_000_000_000)
        if abs(number) < 1e14:
            return int(number * 1_000_000)
        return int(number)
    text = str(value).strip()
    if not text:
        return default
    try:
        return int(text)
    except ValueError:
        pass
    try:
        parsed = _dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return default
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_dt.timezone.utc)
    return int(parsed.timestamp() * 1_000_000_000)


def format_ns(time_ns):
    if time_ns is None:
        return None
    return _dt.datetime.fromtimestamp(time_ns / 1_000_000_000, tz=_dt.timezone.utc).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def glob_match(value, pattern) -> bool:
    if value is None or pattern is None:
        return False
    return fnmatch.fnmatchcase(str(value).replace("\\", "/"), str(pattern).replace("\\", "/"))


def cidr_match(address, network) -> bool:
    try:
        return ipaddress.ip_address(address) in ipaddress.ip_network(str(network), strict=False)
    except ValueError:
        return False


def merge_ranges(ranges):
    """Merge (start, end) half-open ranges; end > start."""
    ordered = sorted((int(a), int(b)) for a, b in ranges if b > a)
    out = []
    for start, end in ordered:
        if out and start <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], end))
        else:
            out.append((start, end))
    return out


def subtract_ranges(outer, cuts):
    """Return the parts of one (start,end) outer range not covered by cuts."""
    start, end = outer
    out = []
    cursor = start
    for cut_start, cut_end in merge_ranges(cuts):
        if cut_end <= cursor or cut_start >= end:
            continue
        if cut_start > cursor:
            out.append((cursor, min(cut_start, end)))
        cursor = max(cursor, cut_end)
        if cursor >= end:
            break
    if cursor < end:
        out.append((cursor, end))
    return out


def ensure_parent(path: Path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def file_identity(path: Path):
    path = Path(path)
    stat = path.stat()
    return {
        "path": str(path),
        "bytes": stat.st_size,
        "sha256": sha256_file(path),
    }


def env_flag(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() not in ("", "0", "false", "no", "off")
