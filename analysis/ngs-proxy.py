"""Log proxied communication and apply ordered message/host-path policies."""

import base64
import json
import os
from pathlib import Path
import sys
import time
import uuid

from mitmproxy import ctx, http

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "foundations"))
from traffic_policy import Policy
from process_sockets import SocketOwnerResolver


MAX_BODY = 1024 * 1024
SENSITIVE_HEADERS = {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-nxl", "passport"}
stream = None
stream_path = None
blocked_rules = []
policy = Policy()
session_id = uuid.uuid4().hex
socket_owners = SocketOwnerResolver()


def load(loader):
    global blocked_rules, policy
    loader.add_option("ngs_log", str, "", "Raw JSONL capture path; may contain credentials.")
    loader.add_option("ngs_block", str, "", "Comma-separated host:path prefixes to reject locally.")
    loader.add_option("traffic_policy", str, "", "JSON process/protocol/destination/type/field policy.")
    blocked_rules = [value.strip() for value in ctx.options.ngs_block.split(",") if value.strip()]
    if any(":" not in value for value in blocked_rules):
        raise ValueError("Each NGS block rule must be host:path-prefix.")
    policy = Policy.load(ctx.options.traffic_policy or None)


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
        "scheme": request.scheme,
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


def request_decision(request, process=None, engine=None):
    engine = engine or policy
    message = {
        "process": process,
        "protocol": request.scheme,
        "type": f"{request.method} {request.path}",
        "direction": "client_to_server",
        "destination": {"host": request.pretty_host, "port": request.port},
        "fields": {"method": request.method, "target": request.path, "host": request.pretty_host},
    }
    return engine.decide(message)


def request(flow):
    process = flow.metadata.get("process") or socket_owners.lookup(flow.client_conn.address)
    flow.metadata["process"] = process
    flow.metadata["socket_inode"] = process.get("socket_inode")
    decision = request_decision(flow.request, process)
    legacy_block = blocked(flow.request)
    decision["legacy_block"] = legacy_block
    if legacy_block:
        decision.update({"action": "drop", "effective_action": "drop", "forward": False,
                         "rule_id": "legacy:ngs_block", "reason": "ngs_block host/path prefix"})
    flow.metadata["client_control_decision"] = decision
    flow.metadata["client_control_blocked"] = not decision["forward"]
    emit({
        "kind": "request", "timestamp": time.time(), "flow_id": flow.id, "session_id": session_id,
        "process": process, "socket_inode": process.get("socket_inode"),
        "request": request_record(flow.request), "decision": decision,
        "raw_scope": "exact_application_body_not_original_TLS_or_HTTP_framing",
    })
    if not decision["forward"]:
        flow.response = http.Response.make(403, b"Blocked by client-control policy.")


def response(flow):
    if flow.response is None:
        return
    content = flow.response.content or b""
    if len(content) > MAX_BODY:
        raise RuntimeError(f"Response exceeds the {MAX_BODY}-byte capture limit.")
    is_blocked = bool(flow.metadata.get("client_control_blocked"))
    emit({
        "kind": "response", "timestamp": time.time(), "flow_id": flow.id, "session_id": session_id,
        "process": flow.metadata.get("process"), "socket_inode": flow.metadata.get("socket_inode"),
        "decision": flow.metadata.get("client_control_decision"), "request": request_record(flow.request),
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
    emit({"kind": "error", "timestamp": time.time(), "flow_id": flow.id, "session_id": session_id,
          "process": flow.metadata.get("process"), "decision": flow.metadata.get("client_control_decision"),
          "request": request_record(flow.request), "error": str(flow.error)})


def self_test():
    request = type("Request", (), {"pretty_host": "x-config.ngs.nexon.com", "path": "/v1"})()
    rules = ["x-config.ngs.nexon.com:/v1"]
    assert blocked(request, rules)
    request.path = "/v2"
    assert not blocked(request, rules)
    request.path = "/v1/config"
    assert blocked(request, rules)
    request.method = "POST"
    request.scheme = "https"
    request.port = 443
    engine = Policy({"version": 1, "rules": [{
        "id": "config", "action": "drop", "protocol": "https",
        "destination": {"host": "x-*.ngs.nexon.com", "port": 443},
        "field": {"name": "target", "equals": "/v1/config"},
    }]})
    assert request_decision(request, engine=engine)["effective_action"] == "drop"
    request.path = "/v2"
    assert request_decision(request, engine=engine)["forward"]
    global policy, emit
    original_policy, original_emit = policy, emit
    events = []
    try:
        policy = engine
        emit = events.append
        request.path = "/v1/config"
        request.content = b"exact-request-body"
        request.headers = {}
        flow = type("Flow", (), {})()
        flow.id = "flow-1"
        flow.request = request
        flow.metadata = {"process": {"name": "nexon_client.exe"}}
        flow.response = None
        globals()["request"](flow)
        assert flow.response.status_code == 403
        assert events[0]["kind"] == "request" and events[0]["flow_id"] == "flow-1"
        assert base64.b64decode(events[0]["request"]["body_base64"]) == b"exact-request-body"
        assert events[0]["decision"]["effective_action"] == "drop"
    finally:
        policy, emit = original_policy, original_emit
    print("PASS: proxy policy and request hook log exact bytes before a local 403.")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
    else:
        raise SystemExit("Run with mitmdump -s ngs-proxy.py, or --self-test.")
