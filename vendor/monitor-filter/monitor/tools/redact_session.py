#!/usr/bin/env python3
"""Create a redacted derived bundle.  The raw bundle is never modified."""

import argparse
import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
PACK = ROOT / "tools" / "session_pack.py"

# The account name in a profile path, a user SID, and IP literals: none may
# survive into a bundle that is handed to someone else. IPv6 needs at least
# four groups (or a "::") so clock times such as 10:00:21 are left alone.
IDENTIFYING = re.compile(r"\\Users\\[^\\]+|S-1-5-21(?:-\d+){3,}", re.I)
# The WFP formatter writes IPv6 as exactly eight uncompressed groups followed
# directly by ":port" (driver/network.c), which the general expression below
# cannot match: the port's ':' also looks like a group separator.
IPV6_UNCOMPRESSED = re.compile(
    r"(?<![0-9A-Fa-f:])\[?(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\]?(?::\d{1,5})?(?![0-9A-Fa-f:])"
)
IP_LITERAL = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    r"|(?<![0-9A-Fa-f:])(?:(?:[0-9A-Fa-f]{1,4}:){3,7}[0-9A-Fa-f]{1,4}|[0-9A-Fa-f:]*::[0-9A-Fa-f:]*)"
    r"(?![0-9A-Fa-f:])"
)


def redact_identifying(text):
    if not isinstance(text, str) or not text:
        return text
    if IDENTIFYING.search(text):
        return "<redacted-path>"
    text = IPV6_UNCOMPRESSED.sub("<redacted-ip>", text)
    return IP_LITERAL.sub("<redacted-ip>", text)


def redact_value(value, keep_paths):
    """Apply redact_identifying to every string in a JSON-shaped value.

    Dictionary keys are transformed too (summary.by_module is keyed by full
    module paths); numeric collisions are summed so two profile-path modules
    keep their combined count.
    """
    if isinstance(value, str):
        return value if keep_paths else redact_identifying(value)
    if isinstance(value, list):
        return [redact_value(item, keep_paths) for item in value]
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            new_key = redact_value(key, keep_paths) if isinstance(key, str) else key
            new_item = redact_value(item, keep_paths)
            if (new_key in redacted and isinstance(redacted[new_key], (int, float))
                    and isinstance(new_item, (int, float))):
                redacted[new_key] += new_item
            else:
                redacted[new_key] = new_item
        return redacted
    return value



# process_environment: the variables the agent shows without --log-environment (sysagg.h EnvironmentParts).
ENVIRONMENT_SHOWN = ("WINE", "LD_", "DXVK_", "VKD3D_", "MESA_", "__GL_", "PROTON_", "DISPLAY=", "WAYLAND_DISPLAY=",
                     "env_truncated=")
# Window messages that carry the user's typing (wineserver.cpp KeyboardMessage).
KEYBOARD_MESSAGES = set(range(0x100, 0x10a)) | set(range(0x10d, 0x110)) | {0x286, 0x290, 0x291, 0xff}


def redact_environment(detail):
    """--log-environment: every value but Wine's, the loader's and the graphics stack's withheld, as without it."""
    def item(variable):
        name, equals, value = variable.partition("=")
        if not equals or variable.startswith(ENVIRONMENT_SHOWN) or value.startswith("withheld:"):
            return variable
        return f"{name}=withheld:{len(value.encode('utf-8'))}"
    return ";".join(item(variable) for variable in detail.split(";"))


def redact_keys(record, detail):
    """--log-real-input: the user's keys withheld as the agent withholds them without it (send_hardware_message's vkey
    and scan, a keyboard message's wparam and lparam and its args in a window probe's record, an X11 key's detail)."""
    msg = re.search(r"(?:^|;)msg=(0x[0-9a-f]+)", detail)
    keyboard = bool(msg) and int(msg.group(1), 16) in KEYBOARD_MESSAGES
    fields = ("vkey=", "scan=") + (("wparam=", "lparam=") if keyboard else ()) + \
        (("detail=",) if record.get("type") == "etw_rpc" and "interface=x11;" in detail else ())
    detail = redact_detail(detail, fields)
    probe = re.match(r"call=(NtUserMessageCall|NtUserPostMessage);args=([^;]*)", detail)
    if probe:
        args = probe.group(2).split(",")
        if len(args) > 3 and args[1].startswith("0x") and int(args[1], 16) in KEYBOARD_MESSAGES:
            args[2] = args[3] = "<redacted>"
            detail = detail[:probe.start(2)] + ",".join(args) + detail[probe.end(2):]
    return detail


def redact_detail(detail, fields=("query=", "answers=")):
    parts = []
    for field in detail.split(";"):
        if field.startswith(fields):
            parts.append(field.split("=", 1)[0] + "=<redacted>")
        else:
            parts.append(field)
    return ";".join(parts)


def redact_record(record, keep_paths, keep_commands):
    had_payload = "payload" in record
    record.pop("payload", None)
    if had_payload:
        # The agent writes a friendly copy of the same bytes next to the payload
        # (decoded_value, telemetry.cpp AppendDecodedValue); dropping only the
        # Base64 chunk would leave the exact registry value, volume serial or
        # label in the bundle this tool exists to make safe to share.
        record.pop("decoded_value", None)
        record["payload_redacted"] = True
    if record.get("type") == "etw_wmi":
        record["detail"] = redact_detail(record.get("detail", ""))
    elif record.get("type") == "etw_dns":
        record["text"] = "<redacted-dns>"
        record["detail"] = redact_detail(record.get("detail", ""))
    detail = record.get("detail", "")
    # --log-content: an ioctl's argument struct (a MAC address), the hash of the bytes a payload held, and a clipboard
    # hash (a short copied secret is guessable from it) say what the user's data was.
    if any(field in detail for field in ("arg_bytes=", "content_sha256=", "ws=set_clipboard_data", "ws=get_clipboard_data")):
        record["detail"] = detail = redact_detail(detail, ("arg_bytes=", "content_sha256=") +
                                                  (("sha256=",) if "_clipboard_data" in detail else ()))
    if record.get("type") == "coverage" and record.get("text") == "process_environment":
        record["detail"] = detail = redact_environment(detail)
    if any(field in detail for field in ("vkey=", "wparam=", "detail=", "call=NtUserMessageCall", "call=NtUserPostMessage")):
        record["detail"] = detail = redact_keys(record, detail)
    if ("ws=get_window_text" in detail or "ws=set_window_text" in detail) and ";text=" in detail:
        # A window's title (wineserver.cpp: read or set) is the last field and may itself hold ';'.
        record["detail"] = detail.split(";text=", 1)[0] + ";text=<redacted>"
    if not keep_paths:
        record["process_path"] = ""
        # text/detail carry the same NT/registry paths (and endpoints) the
        # bundle is being shared to hide; replace the identifying parts.
        for field in ("text", "detail"):
            if field in record:
                record[field] = redact_identifying(record[field])
        if isinstance(record.get("modules"), list):
            record["modules"] = [redact_value(module, False) for module in record["modules"]]
    if not keep_commands and record.get("type") == "process_start":
        record["detail"] = "<redacted-command-line>"
    detail = record.get("detail", "")
    if not keep_commands and ";win_cmdline=" in detail:
        # A child's Windows command line (wineserver new_process) is the last field and may hold ';'.
        record["detail"] = detail.split(";win_cmdline=", 1)[0] + ";win_cmdline=<redacted-command-line>"
    return record


METADATA_FILES = ("session_meta.json", "summary.json", "coverage.json",
                  "sensor-usage.json", "scenario_results.json")


def copy_metadata(source, destination, keep_paths):
    """Copy the sidecar JSON, redacting every string when paths are not kept."""
    for name in METADATA_FILES:
        path = source / name
        if not path.exists():
            continue
        output = destination / name
        if keep_paths:
            shutil.copy2(path, output)
            continue
        metadata = json.loads(path.read_text(encoding="utf-8"))
        output.write_text(json.dumps(redact_value(metadata, False), indent=2) + "\n",
                          encoding="utf-8")


def rewrite(parts, destination, keep_paths, keep_commands):
    chain = "0" * 64
    index = 0
    for part in parts:
        output = destination / part.name
        with open(part, "r", encoding="utf-8") as source, open(output, "w", encoding="utf-8") as target:
            for line in source:
                line = line.strip()
                if not line:
                    continue
                record = redact_record(json.loads(line), keep_paths, keep_commands)
                record.pop("chain", None)
                index += 1
                record["record_index"] = index
                original = json.dumps(record, separators=(",", ":"), ensure_ascii=True)
                chain = hashlib.sha256((chain + original).encode("utf-8")).hexdigest()
                target.write(original[:-1] + ',"chain":"' + chain + '"}\n')
    return chain, index


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("session_dir")
    parser.add_argument("--output", default=None)
    parser.add_argument("--keep-paths", action="store_true")
    parser.add_argument("--keep-commands", action="store_true")
    parser.add_argument("--no-compress", action="store_true")
    args = parser.parse_args()

    source = pathlib.Path(args.session_dir).resolve()
    destination = pathlib.Path(args.output).resolve() if args.output else source.with_name(source.name + "-redacted")
    if destination.exists():
        print(f"refusing to overwrite {destination}", file=sys.stderr)
        return 1
    destination.mkdir(parents=True)

    parts = []
    for path in source.glob("events.jsonl*"):
        suffix = path.name[len("events.jsonl"):]
        order = int(suffix[1:]) if suffix.startswith(".") and suffix[1:].isdigit() else 0
        parts.append((order, path))
    parts = [path for _, path in sorted(parts)]

    chain, count = rewrite(parts, destination, args.keep_paths, args.keep_commands)
    copy_metadata(source, destination, args.keep_paths)
    meta_path = destination / "session_meta.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    meta["redacted"] = True
    meta["redaction_mode"] = "metadata"
    meta["sensitivity"] = "metadata"   # the payloads, DNS names and window titles are gone
    meta["events"] = count
    meta["record_count"] = count
    meta_path.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")

    command = [sys.executable, str(PACK), str(destination)]
    if args.no_compress:
        command.append("--no-compress")
    result = subprocess.run(command)
    if result.returncode != 0:
        return result.returncode
    print(f"redacted bundle: {destination}")
    print(f"chain_head {chain} records {count}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
