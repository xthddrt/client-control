"""Observe or neutralize NGS control-plane responses in mitmproxy."""

import base64
import json
import os
from pathlib import Path
import sys
import zlib

from mitmproxy import ctx, http

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "foundations"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import ngs_cipher
from traffic.policy import evaluate, load_policy
from traffic.sockets import SocketOwnerResolver


MAX_BODY = 4 * 1024 * 1024
SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "proxy-authorization", "x-api-key"}
stream = None
stream_path = None
policy = None
socket_owners = SocketOwnerResolver()


def load(loader):
    global policy
    loader.add_option("ngs_neutralize", bool, False, "Rewrite NGS responses to a clean control state.")
    loader.add_option("ngs_log", str, "", "JSONL capture path; may contain credentials.")
    loader.add_option("traffic_policy", str, "", "client-control traffic policy JSON for requests.")
    policy = load_policy(ctx.options.traffic_policy) if ctx.options.traffic_policy else None


def redacted_headers(headers):
    return {
        name: "<redacted>" if name.lower() in SENSITIVE_HEADERS else value
        for name, value in headers.items()
    }


def neutralize(payload):
    changed = {}
    for name in ("emergency_stop", "config_changed"):
        if name in payload and payload[name] != 0:
            changed[name] = {"before": payload[name], "after": 0}
            payload[name] = 0
    if "detected" in payload and payload["detected"] != []:
        changed["detected"] = {"before": payload["detected"], "after": []}
        payload["detected"] = []
    for name in ("subfeature", "signature"):
        if name in payload and payload[name]:
            empty = type(payload[name])()
            changed[name] = {"before": "nonempty", "after": "empty"}
            payload[name] = empty
    return changed


def emit(event):
    global stream, stream_path
    path = ctx.options.ngs_log
    if not path:
        return
    if stream is None or stream_path != path:
        if stream is not None:
            stream.close()
        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        stream = os.fdopen(descriptor, "a", encoding="utf-8")
        stream_path = path
    stream.write(json.dumps(event, sort_keys=True) + "\n")
    stream.flush()


def request_record(request):
    content = request.content
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


def _policy_message(request, process):
    content = request.content or b""
    host = request.pretty_host
    protocol = "ngs_https" if host.endswith(".ngs.nexon.com") else "http_proxy_observed"
    return {
        "message_id": f"proxy:{time.time_ns()}",
        "process": process or {
            "pid": None, "name": None, "path": None,
            "attribution": "missing",
            "missing_reason": "mitmproxy sees the proxied flow, not a Windows process identity",
        },
        "transport": {
            "protocol": protocol,
            "direction": "client_to_server",
            "destination": {"host": host, "port": request.port, "path": request.path},
        },
        "message": {
            "protocol": protocol,
            "raw_bytes_hex": content.hex(),
            "raw_bytes_length": len(content),
            "type": {
                "opcode": None, "opcode_hex": None,
                "name": "ngs_request" if host.endswith(".ngs.nexon.com") else "http_proxy_request",
                "confidence": "confirmed",
            },
            "fields": [
                {"name": "method", "value": request.method, "confidence": "confirmed"},
                {"name": "host", "value": host, "confidence": "confirmed"},
                {"name": "path", "value": request.path, "confidence": "confirmed"},
            ],
            "decode_status": "metadata_only" if content else "complete",
        },
    }


def request(flow: http.HTTPFlow):
    process = socket_owners.lookup(getattr(flow.client_conn, "address", None))
    flow.metadata["client_control_process"] = process
    decision = evaluate(policy, _policy_message(flow.request, process)) if policy is not None else None
    flow.metadata["client_control_decision"] = decision
    event = {
        "kind": "request",
        "timestamp": time.time(),
        "wall_time_ns": time.time_ns(),
        "flow_id": flow.id,
        "process": process,
        "request": request_record(flow.request),
        "decision": decision,
        "raw_scope": "exact_application_body_not_original_TLS_or_HTTP_framing",
    }
    emit(event)
    if decision is not None and decision["action"] == "drop":
        flow.metadata["client_control_blocked"] = True
        flow.metadata["client_control_reason"] = decision.get("rule_id")
        flow.response = http.Response.make(403, b"Blocked by client-control policy.")


def response(flow: http.HTTPFlow):
    host = flow.request.pretty_host
    if not (host.startswith("x-") and host.endswith(".ngs.nexon.com")):
        return
    event = {
        "kind": "response",
        "timestamp": time.time(),
        "wall_time_ns": time.time_ns(),
        "flow_id": flow.id,
        "process": flow.metadata.get("client_control_process"),
        "decision": flow.metadata.get("client_control_decision"),
        "request": request_record(flow.request),
    }
    if flow.response is None:
        event["error"] = "No response."
        emit(event)
        return
    content = flow.response.content
    if len(content) > MAX_BODY:
        raise RuntimeError(f"Response exceeds the {MAX_BODY}-byte capture limit.")
    event["response"] = {
        "status": flow.response.status_code,
        "headers": redacted_headers(flow.response.headers),
        "body_base64": base64.b64encode(content).decode("ascii"),
    }
    try:
        payload = ngs_cipher.decrypt_response(content, want="json")
    except (ValueError, zlib.error, json.JSONDecodeError) as error:
        event["decode_error"] = str(error)
    else:
        event["decoded_response"] = payload
        if ctx.options.ngs_neutralize and isinstance(payload, dict):
            changed = neutralize(payload)
            if changed:
                raw = ngs_cipher._as_raw(content)
                encoded = json.dumps(payload, separators=(",", ":")).encode()
                flow.response.content = ngs_cipher.encrypt_response(
                    encoded, ngs_cipher.recover_key(raw), raw[:2]
                )
                event["neutralized"] = changed
                event["rewritten_response"] = payload
    emit(event)
    print(
        f"NGS {flow.request.method} {host}{flow.request.path} "
        f"request={len(flow.request.content)} response={len(content)} "
        f"neutralized={list(event.get('neutralized', {}))}"
    )


def error(flow: http.HTTPFlow):
    if flow.request.pretty_host.endswith(".ngs.nexon.com"):
        emit({
            "kind": "error",
            "timestamp": time.time(),
            "wall_time_ns": time.time_ns(),
            "flow_id": flow.id,
            "process": flow.metadata.get("client_control_process"),
            "decision": flow.metadata.get("client_control_decision"),
            "request": request_record(flow.request),
            "error": str(flow.error),
        })


def unload():
    if stream is not None:
        stream.close()


def self_test():
    original = ngs_cipher.decrypt_response(ngs_cipher.encrypt_response(
        json.dumps({
            "emergency_stop": 1, "config_changed": 1, "detected": ["test"],
            "subfeature": {"0x1": 1}, "signature": ["rule"],
            "module_crc": {"grap64.dll": 123}, "lifetoken": "preserve",
        }).encode(), 42
    ), want="json")
    payload = dict(original)
    changed = neutralize(payload)
    assert set(changed) == {"emergency_stop", "config_changed", "detected", "subfeature", "signature"}
    assert payload["module_crc"] == original["module_crc"]
    assert payload["lifetoken"] == "preserve"
    encoded = ngs_cipher.encrypt_response(json.dumps(payload).encode(), 42)
    assert ngs_cipher.decrypt_response(encoded, want="json") == payload
    headers = http.Headers(authorization="secret", user_agent="test")
    assert redacted_headers(headers)["authorization"] == "<redacted>"
    print("PASS: NGS response neutralization and wire round-trip preserve non-target fields.")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
    else:
        raise SystemExit("Run with mitmdump -s ngs-mitm.py, or --self-test.")
