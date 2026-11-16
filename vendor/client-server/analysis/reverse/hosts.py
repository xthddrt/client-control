"""Hosts, URLs, IP addresses and their explicit ports embedded in binaries."""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

HOST = re.compile(
    r"(?:https?|wss?|ftp)://[^\s<>\"']{3,300}"
    r"|(?<![A-Za-z0-9_.-])(?:[a-z0-9-]+\.)+(?:com|net|io|org|co(?:\.kr)?|kr|jp|tw|gg|cn|cloud)(?::\d{2,5})?(?![A-Za-z0-9])"
    r"|(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?(?![\d.])",
    re.I,
)
ASCII_STRING = re.compile(rb"[\x20-\x7e]{3,}")
WIDE_STRING = re.compile(rb"(?:[\x20-\x7e]\x00){3,}")
BINARY_SUFFIXES = {".exe", ".dll", ".aes", ".sys", ".bin"}


def strings(data):
    ascii_matches = list(ASCII_STRING.finditer(data))
    for match in ascii_matches:
        yield match.group().decode("ascii")
    remaining = bytearray(data)
    for match in ascii_matches:
        remaining[match.start():match.end()] = bytes(match.end() - match.start())
    for match in WIDE_STRING.finditer(remaining):
        yield match.group().decode("utf-16-le")


URL_HEAD = re.compile(
    r"^(?P<scheme>(?:https?|wss?|ftp)://)(?P<host>(?:[a-z0-9-]+\.)+(?:com|net|io|org|co(?:\.kr)?|kr|jp|tw|gg|cn|cloud))(?P<rest>.*)$",
    re.I,
)


def clean(value):
    value = value.rstrip(".,);]}")
    if "://" not in value:
        return value
    match = URL_HEAD.match(value)
    if not match:
        return None
    rest = match.group("rest")
    port = re.match(r":\d{2,5}", rest)
    prefix = match.group("scheme") + match.group("host") + (port.group() if port else "")
    if port:
        rest = rest[port.end():]
    if rest and not rest.startswith(("/", "?", "#")):
        rest = ""
    rest = rest.split("\\", 1)[0]
    certificate = re.match(r"(/[^?#]*\.(?:crt|crl))", rest, re.I)
    if certificate:
        rest = certificate.group(1)
    return prefix + rest


def valid(value):
    host = value.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
        return all(int(part) <= 255 for part in host.split("."))
    return True


def find_hosts(data):
    found = Counter()
    for text in strings(data):
        for match in HOST.finditer(text):
            value = clean(match.group())
            if value and valid(value):
                found[value] += 1
    return found


def endpoint(value):
    kind = "url" if "://" in value else "ip" if value[0].isdigit() else "domain"
    try:
        parsed = urlsplit(value if "://" in value else "//" + value)
        return kind, parsed.hostname or "", parsed.port
    except ValueError:
        return kind, "", None


def input_files(paths):
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            for child in sorted(path.rglob("*")):
                if child.is_file() and child.suffix.lower() in BINARY_SUFFIXES and "Data" not in child.parts:
                    yield child
        elif path.is_file():
            yield path


def scan(paths):
    return {str(path): find_hosts(path.read_bytes()) for path in input_files(paths)}


def markdown(results):
    lines = [
        "# Hosts compiled into the game binaries",
        "",
        "Generated read-only with `analysis/re-tool.py hosts APPDATA --markdown docs/reference/compiled-hosts.md`.",
        "Values are string-shape candidates from ASCII and UTF-16 data, not confirmed endpoints; four-part",
        "version numbers can resemble IPs. Ports are reported only when written next to a host; integer-only",
        "port constants are not guessed. No capture or account data is used.",
        "",
    ]
    for path, values in sorted(results.items()):
        lines += [f"## `{Path(path).name}`", ""]
        if not values:
            lines += ["No matching host strings found.", ""]
            continue
        lines += ["| Value | Kind | Host | Port | Occurrences |", "|---|---|---|---:|---:|"]
        for value, count in sorted(values.items()):
            kind, host, port = endpoint(value)
            safe = value.replace("`", "\\`").replace("|", "\\|")
            lines.append(f"| `{safe}` | {kind} | `{host}` | {port or '—'} | {count} |")
        lines.append("")
    return "\n".join(lines)
