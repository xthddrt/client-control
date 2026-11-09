"""Log raw proxied communication and block selected host/path prefixes."""

import base64
import json
import os
from pathlib import Path
import sys
import time

from mitmproxy import ctx, http


MAX_BODY = 1024 * 1024
SENSITIVE_HEADERS = {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-nxl", "passport"}
stream = None
stream_path = None
blocked_rules = []


def load(loader):
    global blocked_rules
    loader.add_option("ngs_log", str, "", "Raw JSONL capture path; may contain credentials.")
    loader.add_option("ngs_block", str, "", "Comma-separated host:path prefixes to reject locally.")
    blocked_rules = [value.strip() for value in ctx.options.ngs_block.split(",") if value.strip()]
    if any(":" not in value for value in blocked_rules):
        raise ValueError("Each NGS block rule must be host:path-prefix.")


def unload():
    if stream is not None:
        stream.close()


def redacted_headers(headers):
    return {name: "<redacted>" if name.lower() in SENSITIVE_HEADERS else value for name, value in headers.items()}


def request_record(request):
    content = request.content or b""
    if len(content) > MAX_BODY:
        raise RuntimeError(f"Request exceeds the {MAX_BODY}-byte capture limit.")
    return {
        "method": request.method,
        "host": request.pretty_host,
        "path": request.path,
        "headers": redacted_headers(request.headers),
        "body_base64": base64.b64encode(content).decode("ascii"),
    }


def blocked(request, rules=None):
    rules = blocked_rules if rules is None else rules
    return any(
        request.pretty_host == rule.split(":", 1)[0]
        and request.path.startswith(rule.split(":", 1)[1])
        for rule in rules
    )


def emit(event):
    global stream, stream_path
    path = ctx.options.ngs_log
    if not path:
        return
    if stream is None or stream_path != path:
        if stream is not None:
            stream.close()
        stream = os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600), "a", encoding="utf-8")
        stream_path = path
    stream.write(json.dumps(event, separators=(",", ":")) + "\n")
    stream.flush()


def request(flow):
    if blocked(flow.request):
        flow.metadata["client_control_blocked"] = True
        flow.response = http.Response.make(403, b"Blocked by client-control policy.")


def response(flow):
    if flow.response is None:
        return
    content = flow.response.content or b""
    if len(content) > MAX_BODY:
        raise RuntimeError(f"Response exceeds the {MAX_BODY}-byte capture limit.")
    is_blocked = bool(flow.metadata.get("client_control_blocked"))
    emit({
        "kind": "response", "timestamp": time.time(),
        "request": request_record(flow.request),
        "response": {
            "status": flow.response.status_code,
            "headers": redacted_headers(flow.response.headers),
            "body_base64": base64.b64encode(content).decode("ascii"),
        },
        "blocked": is_blocked,
    })
    print(
        f"NGS {flow.request.method} {flow.request.pretty_host}{flow.request.path} "
        f"request={len(flow.request.content or b'')} response={len(content)} blocked={is_blocked}",
        flush=True,
    )


def error(flow):
    emit({"kind": "error", "timestamp": time.time(), "request": request_record(flow.request), "error": str(flow.error)})


def self_test():
    request = type("Request", (), {"pretty_host": "x-config.ngs.nexon.com", "path": "/v1"})()
    rules = ["x-config.ngs.nexon.com:/v1"]
    assert blocked(request, rules)
    request.path = "/v2"
    assert not blocked(request, rules)
    request.path = "/v1/config"
    assert blocked(request, rules)
    print("PASS: exact-host and path-prefix filtering without payload decoding.")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
    else:
        raise SystemExit("Run with mitmdump -s ngs-proxy.py, or --self-test.")
