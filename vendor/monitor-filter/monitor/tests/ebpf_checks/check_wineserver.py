"""Wineserver upgrade checks (tests/linux_ebpf_test.sh check()): the fake Wine clients of wineserver.sh
must be decoded into Windows-parity records (ebpf), the same without payloads (nopayloads), and nothing
may come from the decoder under --no-ebpf (fallback)."""
import base64
import os
import re


def check(mode, path, events, mine, pids, coverage, problems):
    if mode == "fallback":
        if coverage & {"wineserver_requests", "wineserver_decoder"}:
            problems.append("wineserver: decoder coverage records under --no-ebpf")
        if any(";ws=ioctl;" in e.get("detail", "") for e in events):
            problems.append("wineserver: request records under --no-ebpf")
        return
    active = [e.get("detail", "") for e in events if e["type"] == "coverage" and e["text"] == "ebpf_active"]
    if "wineserver_requests" not in coverage:
        problems.append("wineserver: no wineserver_requests coverage note (ebpf_active: %s)" % active)
    names = ["ws_fake_client"] + (["ws_fake_client32"] if os.path.exists("build/linux/ws_fake_client32") else [])
    for name in names:
        ids = {e.get("process_id") for e in events if e["type"] == "process_start" and e.get("text", "").endswith("/" + name)}
        if not ids:
            problems.append("wineserver: %s was not tracked" % name)
            continue
        recs = [e for e in events if e.get("process_id") in ids]

        def has(kind, test, what):
            if not any(e["type"] == kind and test(e) for e in recs):
                problems.append("wineserver: %s: no %s %s" % (name, kind, what))

        def value(e):
            """The payload as text, or None (no payload)."""
            if "payload" not in e:
                return None
            return base64.b64decode(e["payload"]["data"]).decode("utf-16-le", "replace")

        def payload_ok(e):
            if mode == "ebpf":
                return value(e) == "hello" and e["payload"]["final_chunk"] and e.get("decoded_value") == "hello"
            return "payload" not in e and not e.get("payload_unavailable")

        has("coverage", lambda e: e["text"] == "wineserver_decoder" and "active=1" in e["detail"] and
            "protocol=930" in e["detail"], "wineserver_decoder active=1")
        has("registry_open", lambda e: e["text"] == "\\Registry\\Machine\\Software\\MsmonProbe" and
            e["desired_access"] == 0x20019 and e["status"] == 0, "of \\Registry\\Machine\\Software\\MsmonProbe")
        has("registry_set_value", lambda e: e["text"].endswith("\\MsmonProbe") and e["detail"] == "Probe" and
            e["value0"] == 10 and e["value1"] == 1 and payload_ok(e), "of Probe = hello (%s)" % mode)
        has("registry_query", lambda e: e["text"].endswith("\\MsmonProbe") and e["detail"] == "Probe" and payload_ok(e),
            "of Probe = hello (%s)" % mode)
        has("process_handle", lambda e: "open_process;win_pid=2457" in e["detail"] and e["desired_access"] == 16,
            "open_process of win_pid=2457 with desired_access 16")
        has("process_handle", lambda e: e["detail"].startswith("read_process_memory;") and e["value0"] == 1 and
            e["value1"] == 16, "read_process_memory of 16 bytes")
        has("file_create", lambda e: e["text"] == "/tmp/msmon-probe.txt" and "nt=\\??\\unix\\tmp\\msmon-probe.txt" in e["detail"],
            "of /tmp/msmon-probe.txt with nt=")
        has("network_connect", lambda e: e["text"] == "127.0.0.1:9" and e["detail"].startswith("connect;family=2;ws=ioctl;afd=connect") and
            ";pending" in e["detail"] and e["status"] == 0x103 and e["value0"] == 0, "to 127.0.0.1:9 (STATUS_PENDING)")
        # Every request is recorded (M1): counted as recorded=1, the formerly counted-only ones decoded generically.
        for counted in (";query_event=2", ";select=200", ";unknown=1"):
            has("coverage", lambda e: e["text"] == "wineserver_request_counts" and e["detail"].startswith("recorded=1;") and
                counted in e["detail"], "wineserver_request_counts recorded=1 with %s" % counted[1:])
        if any(e["type"] == "coverage" and e["text"] == "wineserver_request_counts" and e["detail"].startswith("recorded=0;")
               for e in recs):
            problems.append("wineserver: %s: a request counted only (recorded=0)" % name)
        has("file_query_information", lambda e: e["text"] == "system:query_event" and e["detail"].startswith("ws=query_event;handle=0x0;"),
            "system:query_event (generic)")
        has("file_query_information", lambda e: e["text"] == "system:send_message" and
            "type=other_process;to_tid=2457;win=0x10077;msg=0x4a;" in e["detail"] and ";data_bytes=10;sha256=" in e["detail"],
            "send_message WM_COPYDATA to another thread with its data hashed")
        has("file_query_information", lambda e: e["text"] == "system:get_message" and ";msg=0x100;type=hardware;input=withheld;" in e["detail"]
            and "wparam" not in e["detail"], "get_message WM_KEYDOWN without its key")
        has("file_device_control", lambda e: e["value0"] == 0x2d1400 and e["value1"] == 12 and
            e["detail"].startswith("ioctl;ws=ioctl;handle=0x2c;code=0x2d1400;out_size=8;out_bytes=8;sha256="),
            "ioctl IOCTL_STORAGE_QUERY_PROPERTY with its answer hashed")
        has("file_query_information", lambda e: e["text"] == "system:unknown" and e["detail"].startswith("ws=unknown;req=400;unknown@0xc=0x7")
            and e["status"] == 0xC0000002, "request 400 as unknown")
        has("file_query_information", lambda e: e["text"] == "system:send_hardware_message" and
            e["detail"].startswith("ws=send_hardware_message;input=keyboard;flags=0x0;window=0x0;injected=0") and "vkey" not in e["detail"],
            "a real key without its key")
        has("file_query_information", lambda e: e["text"] == "system:get_async_result" and ";out_bytes=10;sha256=" in e["detail"],
            "get_async_result with its output hashed")
        has("file_device_control", lambda e: e["detail"].startswith("irp_result;irp=unknown;status=0x0;information=5;out_bytes=5;sha256="),
            "set_irp_result with its output hashed")
        has("file_write", lambda e: e["detail"].startswith("request_pipe_rejected;reason=size;syscall=write;") and ";count=32;" in e["detail"],
            "a 32-byte write on the request pipe rejected")
        # select x200: its first call recorded (sampled, again after each drain), the others in kernel summaries; a
        # sample within the agent's repeat window of the one before is in the agent's repeats (repeats_before of the
        # next sampled record, or its repeats_tail without aggregate=kernel).
        def repeats(e):
            found = re.search(r";repeats_before=(\d+)", e["detail"])
            return int(found.group(1)) if found else 0

        selects = [e for e in recs if e["text"] == "system:select" and
                   (e["detail"].startswith("ws=select;") or "syscall=wineserver:select;" in e["detail"])]
        sampled = [e for e in selects if ";aggregate=sampled" in e["detail"]]
        summaries = [e for e in selects if ";aggregate=kernel;ws=select;flags=0x2;" in e["detail"]]
        calls = sum(e["value1"] if e["detail"].startswith("repeats_tail;") else 1 + repeats(e) for e in selects)
        if not sampled or not summaries or calls != 200:
            problems.append("wineserver: %s: select x200 not 200 = %d: sampled %d, summaries %s, agent repeats %s" %
                            (name, calls, len(sampled), [e["value1"] for e in summaries],
                             [repeats(e) for e in selects if "aggregate=kernel" not in e["detail"]]))
        if name == "ws_fake_client":   # its 64-byte vararg read apart from the header is not taken for a header
            has("file_create", lambda e: e["text"] == "/msmon-served-probe" and
                ";served_request=wineserver:query_mutex;" in e["detail"], "of /msmon-served-probe served for query_mutex")
            has("file_write", lambda e: e["detail"].startswith("request_pipe_rejected;reason=splice;syscall=splice;") and
                ";count=8;" in e["detail"], "a splice into the request pipe rejected")
            has("file_write", lambda e: e["detail"].startswith("request_pipe_rejected;reason=other_call;syscall=pwritev2;") and
                ";count=1;" in e["detail"], "a pwritev2 into the request pipe rejected")
