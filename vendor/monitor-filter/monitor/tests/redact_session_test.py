#!/usr/bin/env python3
"""redact_session_test.py - a redacted bundle must not keep the payload's decoded copy.

The agent writes a friendly decoded_value beside a registry or volume payload
(agent/telemetry.cpp AppendDecodedValue). Removing only the Base64 payload left
the same MachineGuid, registry secret, volume serial or label in the "redacted"
bundle, so this drives the production redact_record through rewrite().
"""

import json
import pathlib
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
import redact_session  # noqa: E402

DECODED_SECRET = "machine-guid-4f1c9e2a"
VOLUME_LABEL = "SYSTEM-RESTORE"
VOLUME_SERIAL_HEX = "3A2B1C0F"


def check(condition, name):
    if not condition:
        raise SystemExit(f"FAIL: {name}")


def records():
    return [
        {
            "type": "registry_set_value", "timestamp": "t1", "process_id": 7,
            "text": "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Cryptography",
            "detail": "value MachineGuid", "operation_id": 3,
            "payload": {"kind": "registry_value", "encoding": "base64", "data": "QQBCAEMA",
                        "operation_id": 3, "total_bytes": 6, "byte_offset": 0,
                        "chunk_index": 0, "chunk_count": 1, "final_chunk": True},
            "decoded_value": DECODED_SECRET,
        },
        {
            "type": "file_query_volume_information", "timestamp": "t2", "process_id": 7,
            "text": "\\Device\\HarddiskVolume3", "operation_id": 4,
            "payload": {"kind": "volume_information", "encoding": "base64", "data": "AAAA",
                        "operation_id": 4, "total_bytes": 3, "byte_offset": 0,
                        "chunk_index": 0, "chunk_count": 1, "final_chunk": True},
            "decoded_value": {"volume_serial_number": 975903759,
                              "volume_serial_hex": VOLUME_SERIAL_HEX,
                              "volume_creation_time": "2026-10-01T00:00:00.000Z",
                              "volume_label": VOLUME_LABEL},
        },
        {
            "type": "process_start", "timestamp": "t3", "process_id": 7,
            "text": "C:\\client.exe", "detail": "client.exe -play",
        },
    ]


def main():
    with tempfile.TemporaryDirectory() as temporary:
        root = pathlib.Path(temporary)
        source = root / "session"
        source.mkdir()
        destination = root / "redacted"
        destination.mkdir()
        with open(source / "events.jsonl", "w", encoding="utf-8") as stream:
            for record in records():
                stream.write(json.dumps(record) + "\n")

        chain, count = redact_session.rewrite([source / "events.jsonl"], destination, False, False)
        check(count == len(records()), f"all records are rewritten (got {count})")
        check(re.fullmatch(r"[0-9a-f]{64}", chain) is not None, "the rewrite returns a chain head")

        text = (destination / "events.jsonl").read_text(encoding="utf-8")
        lines = [line for line in text.splitlines() if line.strip()]
        check(len(lines) == count, "one output line per input record")
        for name in ('"payload"', '"decoded_value"', DECODED_SECRET, VOLUME_SERIAL_HEX, VOLUME_LABEL):
            check(name not in text, f"the redacted bundle no longer contains {name}")

        redacted = [json.loads(line) for line in lines]
        check(redacted[0]["text"] == "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Cryptography" and
              redacted[0]["process_id"] == 7 and redacted[0]["payload_redacted"] is True,
              "the registry record keeps its metadata and says the payload was dropped")
        check(redacted[1]["type"] == "file_query_volume_information" and
              redacted[1]["payload_redacted"] is True,
              "the volume record keeps its metadata and says the payload was dropped")
        check(redacted[2]["text"] == "C:\\client.exe" and redacted[2].get("payload_redacted") is None,
              "a record without a payload is otherwise unchanged")
        check([record["record_index"] for record in redacted] == [1, 2, 3],
              "records are renumbered in write order")
        check(all(re.fullmatch(r"[0-9a-f]{64}", record["chain"]) for record in redacted),
              "every output record carries the new chain")

    with tempfile.TemporaryDirectory() as temporary:
        root = pathlib.Path(temporary)
        source = root / "session"
        source.mkdir()
        destination = root / "redacted"
        destination.mkdir()
        identifying = [
            {"type": "file_read", "timestamp": "t1", "process_id": 7,
             "text": "\\Device\\HarddiskVolume3\\Users\\alice\\Documents\\notes.txt",
             "detail": "read"},
            {"type": "registry_query", "timestamp": "t2", "process_id": 7,
             "text": "\\REGISTRY\\USER\\S-1-5-21-111-222-333-1001\\Software",
             "detail": "value"},
            {"type": "network_connect", "timestamp": "t3", "process_id": 7,
             "text": "10.0.0.5:52000 -> 1.2.3.4:443",
             "detail": "tcp"},
            {"type": "file_read", "timestamp": "t4", "process_id": 7,
             "text": "C:\\client.exe",
             "detail": "\\Device\\HarddiskVolume3\\Users\\alice\\Documents\\notes.txt"},
            {"type": "etw_dns", "timestamp": "t5", "process_id": 7, "text": "login.example",
             "detail": "query_type=1;dns_id=7;rcode=0;answers=CNAME edge.secret-cdn.example|A 5.6.7.8;"
                       "transport=udp;server=127.0.0.53:53"},
            {"type": "file_query_information", "timestamp": "t6", "process_id": 7,
             "text": "system:get_window_text",
             "detail": "ws=get_window_text;handle=0x10020;text=Chat - MyCharacter;whisper"},
            {"type": "process_handle", "timestamp": "t7", "process_id": 7, "text": "",
             "detail": "new_process;win_pid=3100;win_cmdline=open https://x.example/?code=secret;state=1"},
            {"type": "file_query_information", "timestamp": "t8", "process_id": 7, "text": "system:set_window_text",
             "detail": "ws=set_window_text;handle=0x10050;text=Inbox - alice;draft"},
            {"type": "file_device_control", "timestamp": "t9", "process_id": 7, "text": "socket:[9]",
             "detail": "syscall=ioctl;ret=0;arg_bytes=6c6f0000c0ffee"},
            {"type": "file_query_information", "timestamp": "t10", "process_id": 7, "text": "system:set_clipboard_data",
             "detail": "ws=set_clipboard_data;format=13;bytes=14;sha256=f52fbd32"},
            {"type": "file_write", "timestamp": "t11", "process_id": 7, "text": "socket:[10]",
             "detail": "syscall=write;content_bytes=20;content_sha256=0badc0de;service=x11"},
            {"type": "coverage", "timestamp": "t12", "process_id": 7, "text": "process_environment",
             "detail": "WINEPREFIX=/prefix;GITHUB_TOKEN=ghp_abcDEF123secret;HOME=withheld:9;DISPLAY=:5;env_truncated=65536"},
            {"type": "file_query_information", "timestamp": "t13", "process_id": 7, "text": "system:send_hardware_message",
             "detail": "ws=send_hardware_message;input=keyboard;vkey=0x41;scan=0x1e;flags=0x0;window=0x10020;injected=0"},
            {"type": "file_query_information", "timestamp": "t14", "process_id": 7, "text": "system:get_message",
             "detail": "ws=get_message;win=0x10020;msg=0x102;type=0;wparam=0x61;lparam=0x1e0001;x=0"},
            {"type": "file_query_information", "timestamp": "t15", "process_id": 7, "text": "system:get_message",
             "detail": "ws=get_message;win=0x10020;msg=0x200;type=0;wparam=0x1;lparam=0x500050;x=0"},
            {"type": "etw_rpc", "timestamp": "t16", "process_id": 7, "text": "unix:@/tmp/.X11-unix/X5",
             "detail": "interface=x11;operation=XTEST.FakeInput;type=KeyPress;root=0x2a;x=100;y=200;detail=38;syscall=writev"},
            {"type": "file_query_information", "timestamp": "t17", "process_id": 7, "text": "system:NtUserPostMessage",
             "detail": "call=NtUserPostMessage;args=0x10020,0x100,0x41,0x1e0001,0x0,0x0;owner_pid=5"},
        ]
        with open(source / "events.jsonl", "w", encoding="utf-8") as stream:
            for record in identifying:
                stream.write(json.dumps(record) + "\n")

        redact_session.rewrite([source / "events.jsonl"], destination, False, False)
        text = (destination / "events.jsonl").read_text(encoding="utf-8")
        for secret in ("Users", "S-1-5-21-", "10.0.0.5", "1.2.3.4"):
            check(secret not in text, f"the redacted bundle still contains {secret}")
        redacted = [json.loads(line) for line in text.splitlines() if line.strip()]
        check(redacted[0]["text"] == "<redacted-path>", "a profile path is replaced")
        check(redacted[1]["text"] == "<redacted-path>", "a user SID path is replaced")
        check(redacted[2]["text"] == "<redacted-ip>:52000 -> <redacted-ip>:443",
              "network endpoints are replaced")
        check(redacted[3]["text"] == "C:\\client.exe" and
              redacted[3]["detail"] == "<redacted-path>",
              "a profile path in detail replaces the whole field")

        kept = root / "kept"
        kept.mkdir()
        redact_session.rewrite([source / "events.jsonl"], kept, True, False)
        kept_text = (kept / "events.jsonl").read_text(encoding="utf-8")
        kept_records = [json.loads(line) for line in kept_text.splitlines() if line.strip()]
        check(kept_records[0]["text"] == identifying[0]["text"] and
              kept_records[1]["text"] == identifying[1]["text"] and
              kept_records[2]["text"] == identifying[2]["text"] and
              kept_records[3]["detail"] == identifying[3]["detail"],
              "--keep-paths leaves paths and endpoints intact")
        check(kept_records[4]["text"] == "<redacted-dns>" and "secret-cdn" not in kept_text and
              "answers=<redacted>" in kept_records[4]["detail"],
              "DNS names and answers are redacted even with --keep-paths")
        check(kept_records[5]["detail"] == "ws=get_window_text;handle=0x10020;text=<redacted>" and
              "MyCharacter" not in kept_text and "whisper" not in kept_text,
              "window titles are redacted even with --keep-paths")
        check(kept_records[6]["detail"] == "new_process;win_pid=3100;win_cmdline=<redacted-command-line>",
              "a child's Windows command line is redacted without --keep-commands")
        check(kept_records[7]["detail"] == "ws=set_window_text;handle=0x10050;text=<redacted>" and "Inbox" not in kept_text,
              "a title a program sets is redacted too")
        check(kept_records[8]["detail"] == "syscall=ioctl;ret=0;arg_bytes=<redacted>" and
              kept_records[9]["detail"] == "ws=set_clipboard_data;format=13;bytes=14;sha256=<redacted>" and
              kept_records[10]["detail"] == "syscall=write;content_bytes=20;content_sha256=<redacted>;service=x11",
              "--log-content's ioctl bytes, content and clipboard hashes are redacted")
        check(kept_records[11]["detail"] == "WINEPREFIX=/prefix;GITHUB_TOKEN=withheld:19;HOME=withheld:9;DISPLAY=:5;"
                                           "env_truncated=65536" and "ghp_" not in kept_text,
              "--log-environment's values are withheld but Wine's, the loader's and the graphics stack's")
        check(kept_records[12]["detail"] == "ws=send_hardware_message;input=keyboard;vkey=<redacted>;scan=<redacted>;"
                                           "flags=0x0;window=0x10020;injected=0" and
              kept_records[13]["detail"] == "ws=get_message;win=0x10020;msg=0x102;type=0;wparam=<redacted>;lparam=<redacted>;x=0" and
              kept_records[14]["detail"] == identifying[14]["detail"] and
              kept_records[15]["detail"] == "interface=x11;operation=XTEST.FakeInput;type=KeyPress;root=0x2a;x=100;y=200;"
                                           "detail=<redacted>;syscall=writev" and
              kept_records[16]["detail"] == "call=NtUserPostMessage;args=0x10020,0x100,<redacted>,<redacted>,0x0,0x0;owner_pid=5",
              "--log-real-input's keys are redacted (a mouse message's parameters kept)")
    with tempfile.TemporaryDirectory() as temporary:
        root = pathlib.Path(temporary)
        source = root / "session"
        source.mkdir()
        destination = root / "redacted"
        destination.mkdir()
        # Both record types legitimately omit text/detail; redaction must not add
        # null values, which the event schema (string) and session_pack reject.
        observers = [
            {"type": "observer_sequence_gap", "source": "etw", "after_sequence": 10,
             "before_sequence": 13, "missing_events": 2},
            {"type": "observer_summary", "session_id": 1, "events": 2},
        ]
        with open(source / "events.jsonl", "w", encoding="utf-8") as stream:
            for record in observers:
                stream.write(json.dumps(record) + "\n")

        redact_session.rewrite([source / "events.jsonl"], destination, False, False)
        output = destination / "events.jsonl"
        text = output.read_text(encoding="utf-8")
        redacted = [json.loads(line) for line in text.splitlines() if line.strip()]
        check(all("text" not in record and "detail" not in record for record in redacted),
              "redaction must not add null text/detail to a record that omits them")
        validation = subprocess.run(
            [sys.executable,
             str(pathlib.Path(__file__).resolve().parents[1] / "tools" / "validate_schema.py"),
             str(output)],
            capture_output=True, text=True)
        check(validation.returncode == 0,
              "the redacted events fail schema validation: " + validation.stdout + validation.stderr)
    with tempfile.TemporaryDirectory() as temporary:
        root = pathlib.Path(temporary)
        source = root / "session"
        source.mkdir()
        destination = root / "redacted"
        destination.mkdir()
        endpoints = ("2001:0db8:0000:0000:0000:0000:0000:0001:443 -> "
                     "fe80:0000:0000:0000:0202:b3ff:fe1e:8329:52000")
        bracketed = ("[2001:0db8:0000:0000:0000:0000:0000:0001]:443 -> "
                     "[fe80:0000:0000:0000:0202:b3ff:fe1e:8329]:52000")
        with open(source / "events.jsonl", "w", encoding="utf-8") as stream:
            for index, value in enumerate((endpoints, bracketed), 1):
                stream.write(json.dumps({"type": "network_connect", "timestamp": f"t{index}",
                                         "process_id": 7, "text": value,
                                         "detail": "tcp"}) + "\n")

        redact_session.rewrite([source / "events.jsonl"], destination, False, False)
        text = (destination / "events.jsonl").read_text(encoding="utf-8")
        for secret in ("2001", "0db8", "fe80", "8329"):
            check(secret not in text, f"the redacted bundle still contains {secret}")
        redacted = [json.loads(line) for line in text.splitlines() if line.strip()]
        check(redacted[0]["text"] == "<redacted-ip> -> <redacted-ip>",
              "uncompressed IPv6 endpoints are replaced")
        check(redacted[1]["text"] == "<redacted-ip> -> <redacted-ip>",
              "bracketed IPv6 endpoints and their ports are replaced")
        check(redact_session.redact_identifying("10:00:21 -> 10:00:22") == "10:00:21 -> 10:00:22",
              "clock-like strings are not over-matched")

    with tempfile.TemporaryDirectory() as temporary:
        root = pathlib.Path(temporary)
        source = root / "session"
        source.mkdir()
        destination = root / "redacted"
        destination.mkdir()
        modules = [r"\Device\HarddiskVolume3\Users\alice\AppData\Local\evil.dll",
                   r"\Device\HarddiskVolume3\Windows\System32\ntdll.dll"]
        with open(source / "events.jsonl", "w", encoding="utf-8") as stream:
            stream.write(json.dumps({"type": "file_read", "timestamp": "t1",
                                     "process_id": 7, "text": r"C:\client.exe",
                                     "detail": "read", "modules": modules}) + "\n")

        redact_session.rewrite([source / "events.jsonl"], destination, False, False)
        text = (destination / "events.jsonl").read_text(encoding="utf-8")
        check("Users" not in text and "alice" not in text,
              "the redacted event still contains a profile-path module")
        redacted = [json.loads(line) for line in text.splitlines() if line.strip()]
        check(redacted[0]["modules"][1] == modules[1],
              "a module outside the profile keeps its path")

        kept = root / "kept"
        kept.mkdir()
        redact_session.rewrite([source / "events.jsonl"], kept, True, False)
        check("alice" in (kept / "events.jsonl").read_text(encoding="utf-8"),
              "--keep-paths preserves module paths")

    with tempfile.TemporaryDirectory() as temporary:
        root = pathlib.Path(temporary)
        source = root / "session"
        source.mkdir()
        destination = root / "redacted"
        destination.mkdir()
        (source / "session_meta.json").write_text(json.dumps({
            "client_root": r"C:\Users\alice\Nexon",
            "scope_root": r"C:\Users\alice\Nexon\appdata"}), encoding="utf-8")
        (source / "summary.json").write_text(json.dumps({
            "events": 10,
            "by_module": {r"C:\Users\alice\a.dll": 3,
                          r"C:\Users\bob\b.dll": 5,
                          r"C:\Windows\System32\ntdll.dll": 2}}), encoding="utf-8")

        redact_session.copy_metadata(source, destination, False)
        meta = (destination / "session_meta.json").read_text(encoding="utf-8")
        summary = (destination / "summary.json").read_text(encoding="utf-8")
        check("Users" not in meta and "alice" not in meta,
              "redacted session metadata still contains a profile path")
        check("Users" not in summary and "alice" not in summary and "bob" not in summary,
              "redacted summary still contains a profile path")
        data = json.loads(summary)
        check(data["by_module"] == {"<redacted-path>": 8,
                                    r"C:\Windows\System32\ntdll.dll": 2},
              "colliding redacted module keys keep their combined count")

        kept = root / "kept"
        kept.mkdir()
        redact_session.copy_metadata(source, kept, True)
        kept_summary = (kept / "summary.json").read_text(encoding="utf-8")
        check("alice" in (kept / "session_meta.json").read_text(encoding="utf-8") and
              "alice" in kept_summary and "bob" in kept_summary,
              "--keep-paths preserves metadata paths")

    with tempfile.TemporaryDirectory() as temporary:
        root = pathlib.Path(temporary)
        source = root / "session"
        source.mkdir()
        destination = root / "redacted"
        meta = {
            "session_uuid": "00000000-0000-0000-0000-000000000001",
            "session_id": 1,
            "test_id": "c39",
            "scenario": "test",
            "phase": "steady",
            "machine_label": "vm",
            "started_utc": "2026-11-02T10:00:00Z",
            "ended_utc": "2026-11-02T10:00:01Z",
            "outcome": "completed",
            "client_version": "1",
            "agent_sha256": "",
            "driver_sha256": "",
            "build_commit": "",
            "config": {"payload_mode": "metadata", "etw": False,
                       "queue_records": 1, "queue_bytes": 1},
            "client_root": r"C:\Users\alice\Nexon",
            "scope_root": r"C:\Users\alice\Nexon\appdata",
        }
        event = {
            "protocol": 1, "schema_version": 1, "source": "driver", "sequence": 1,
            "timestamp": "2026-11-02T10:00:00.000Z", "session_id": 1, "type_id": 1,
            "type": "file_read", "process_id": 7, "flags": 0, "status": 0,
            "category": "client_data", "outside_client": False,
            "attribution": "process_only", "value0": 0, "value1": 0,
            "operation_id": 0, "text": r"C:\client.exe", "detail": "read",
            "component": "",
            "modules": [r"\Device\HarddiskVolume3\Users\alice\AppData\Local\evil.dll"],
        }
        (source / "session_meta.json").write_text(json.dumps(meta), encoding="utf-8")
        (source / "summary.json").write_text(json.dumps({
            "events": 8,
            "by_module": {r"C:\Users\alice\a.dll": 3,
                          r"C:\Users\bob\b.dll": 5}}), encoding="utf-8")
        (source / "events.jsonl").write_text(json.dumps(event) + "\n", encoding="utf-8")

        old_argv = sys.argv
        sys.argv = ["redact_session.py", str(source), "--output", str(destination),
                    "--no-compress"]
        try:
            result = redact_session.main()
        finally:
            sys.argv = old_argv
        check(result == 0, f"redacted bundle main succeeds ({result})")
        for name in ("events.jsonl", "session_meta.json", "summary.json"):
            text = (destination / name).read_text(encoding="utf-8")
            check("Users" not in text and "alice" not in text and "bob" not in text,
                  f"{name} in the redacted bundle still contains a profile path")
        check(json.loads((destination / "summary.json").read_text(encoding="utf-8"))["by_module"] ==
              {"<redacted-path>": 8}, "full redaction merges module counts")

        kept = root / "kept"
        sys.argv = ["redact_session.py", str(source), "--output", str(kept),
                    "--no-compress", "--keep-paths"]
        try:
            result = redact_session.main()
        finally:
            sys.argv = old_argv
        check(result == 0, f"redacted bundle main with --keep-paths succeeds ({result})")
        check("alice" in (kept / "events.jsonl").read_text(encoding="utf-8") and
              "alice" in (kept / "session_meta.json").read_text(encoding="utf-8") and
              "alice" in (kept / "summary.json").read_text(encoding="utf-8") and
              "bob" in (kept / "summary.json").read_text(encoding="utf-8"),
              "--keep-paths preserves the full bundle")

    print("redact_session regression passed")


if __name__ == "__main__":
    main()
