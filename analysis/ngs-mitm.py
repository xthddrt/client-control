"""Log/filter requests and observe or neutralize NGS control-plane responses in mitmproxy."""

import base64
import copy
import json
import os
from pathlib import Path
import sys
import time
import uuid
import zlib

from mitmproxy import ctx, http

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "foundations"))
import ngs_cipher
from traffic_policy import Policy
from process_sockets import SocketOwnerResolver


MAX_BODY = 4 * 1024 * 1024
SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "proxy-authorization", "x-api-key"}
stream = None
stream_path = None
policy = Policy()
session_id = uuid.uuid4().hex
socket_owners = SocketOwnerResolver()


def load(loader):
    global policy
    loader.add_option("ngs_neutralize", bool, False, "Rewrite NGS responses to a clean control state.")
    loader.add_option("ngs_screenshot_filter", bool, False, "Disable only GRAP feature 0x0F013 in x-config responses.")
    loader.add_option("ngs_log", str, "", "JSONL capture path; may contain credentials.")
    loader.add_option("traffic_policy", str, "", "JSON process/protocol/destination/type/field policy.")
    policy = Policy.load(ctx.options.traffic_policy or None)


def redacted_headers(headers):
    return {
        name: "<redacted>" if name.lower() in SENSITIVE_HEADERS else value
        for name, value in headers.items()
    }


def disable_screenshot(payload):
    changed = {}
    for name in ("subfeature", "signature"):
        if name in payload and not isinstance(payload[name], dict):
            raise ValueError(f"Unexpected NGS {name} structure; refusing screenshot rewrite.")
    entries = payload.get("signature", {}).get("0x0F013", [])
    if not isinstance(entries, list) or any(not isinstance(entry, dict) for entry in entries):
        raise ValueError("Unexpected 0x0F013 structure; refusing screenshot rewrite.")
    features = payload.get("subfeature", {})
    if features.get("0x0F013") not in (None, 0):
        changed["subfeature"] = {"before": features["0x0F013"], "after": 0}
        features["0x0F013"] = 0
    for index, entry in enumerate(entries):
        if "l" in entry and entry["l"] != 0:
            changed.setdefault("signature", []).append({"index": index, "id": entry.get("id"), "before": entry["l"], "after": 0})
            entry["l"] = 0
    return changed


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


def decode_client_request(body):
    """Test the response cipher on a client request without assuming it applies."""
    if not body:
        return {"status": "empty"}
    result = {"cipher_attempted": "ngs_response_algorithm", "direction": "client_to_server"}
    try:
        plaintext = ngs_cipher.decrypt_response(body)
        result["status"] = "decrypted"
        result["plaintext_base64"] = base64.b64encode(plaintext).decode("ascii")
        result["same_algorithm_as_server_response"] = True
        try:
            result["decoded_request"] = json.loads(plaintext)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            result["status"] = "decrypted_non_json"
            result["json_error"] = str(error)
    except (ValueError, TypeError, zlib.error) as error:
        result.update({"status": "undecoded", "error": str(error)})
    return result


def request(flow: http.HTTPFlow):
    flow.metadata["ngs_original_host"] = flow.request.pretty_host
    process = flow.metadata.get("process") or socket_owners.lookup(flow.client_conn.address)
    flow.metadata["process"] = process
    flow.metadata["socket_inode"] = process.get("socket_inode")
    host = flow.request.pretty_host
    fields = {"method": flow.request.method, "target": flow.request.path, "host": host}
    request_decode = None
    if host.startswith("x-") and host.endswith(".ngs.nexon.com"):
        request_decode = decode_client_request(flow.request.content or b"")
        if "decoded_request" in request_decode:
            fields["payload"] = request_decode["decoded_request"]
    decision = policy.decide({
        "process": process, "protocol": flow.request.scheme,
        "type": f"{flow.request.method} {flow.request.path}", "direction": "client_to_server",
        "destination": {"host": host, "port": flow.request.port}, "fields": fields,
    })
    flow.metadata["client_control_decision"] = decision
    flow.metadata["client_control_blocked"] = not decision["forward"]
    event = {
        "kind": "request", "timestamp": time.time(), "flow_id": flow.id, "session_id": session_id,
        "process": process, "socket_inode": process.get("socket_inode"),
        "request": request_record(flow.request), "decision": decision,
        "raw_scope": "exact_application_body_not_original_TLS_or_HTTP_framing",
    }
    if request_decode is not None:
        event["client_decode"] = request_decode
    emit(event)
    if not decision["forward"]:
        flow.response = http.Response.make(403, b"Blocked by client-control policy.")


def response(flow: http.HTTPFlow):
    host = flow.metadata.get("ngs_original_host") or flow.request.pretty_host
    is_ngs = host.startswith("x-") and host.endswith(".ngs.nexon.com")
    event = {"kind": "response", "timestamp": time.time(), "flow_id": flow.id, "session_id": session_id,
             "original_host": host, "process": flow.metadata.get("process"), "socket_inode": flow.metadata.get("socket_inode"),
             "decision": flow.metadata.get("client_control_decision"), "request": request_record(flow.request)}
    if flow.response is None:
        event["error"] = "No response."
        emit(event)
        return
    content = flow.response.content or b""
    if len(content) > MAX_BODY:
        raise RuntimeError(f"Response exceeds the {MAX_BODY}-byte capture limit.")
    event["response"] = {
        "status": flow.response.status_code,
        "headers": redacted_headers(flow.response.headers),
        "body_base64": base64.b64encode(content).decode("ascii"),
    }
    if flow.metadata.get("client_control_blocked"):
        event["blocked"] = True
        event["decode_error"] = "blocked_before_transmission"
        emit(event)
        return
    if not is_ngs:
        event["decode_status"] = "not_applicable"
        emit(event)
        print(f"HTTP {flow.request.method} {host}{flow.request.path} response={len(content)}", flush=True)
        return
    try:
        payload = ngs_cipher.decrypt_response(content, want="json")
    except (ValueError, zlib.error, json.JSONDecodeError) as error:
        event["decode_error"] = str(error)
    else:
        event["decoded_response"] = copy.deepcopy(payload)
        if ctx.options.ngs_screenshot_filter:
            event["screenshot_filter"] = {"matched": False, "forward": True, "action": "allow"}
        screenshot_changes = {}
        if (ctx.options.ngs_screenshot_filter and isinstance(payload, dict)
                and host == "x-config.ngs.nexon.com" and flow.request.path == "/v1"):
            screenshot_changes = disable_screenshot(payload)
            event["screenshot_filter"].update({
                "matched": bool(screenshot_changes),
                "action": "modify" if screenshot_changes else "allow",
                "changes": screenshot_changes,
            })
        changed = neutralize(payload) if ctx.options.ngs_neutralize and isinstance(payload, dict) else {}
        if screenshot_changes or changed:
            raw = ngs_cipher._as_raw(content)
            encoded = json.dumps(payload, separators=(",", ":")).encode()
            flow.response.content = ngs_cipher.encrypt_response(
                encoded, ngs_cipher.recover_key(raw), raw[:2]
            )
            if changed:
                event["neutralized"] = changed
            event["rewritten_response"] = payload
            event["rewritten_response_body_base64"] = base64.b64encode(flow.response.content).decode("ascii")
    emit(event)
    print(
        f"NGS {flow.request.method} {host}{flow.request.path} "
        f"request={len(flow.request.content)} response={len(content)} "
        f"neutralized={list(event.get('neutralized', {}))}"
    )


def error(flow: http.HTTPFlow):
    emit({
        "kind": "error", "timestamp": time.time(), "flow_id": flow.id, "session_id": session_id,
        "process": flow.metadata.get("process"), "decision": flow.metadata.get("client_control_decision"),
        "request": request_record(flow.request), "error": str(flow.error),
    })


def unload():
    if stream is not None:
        stream.close()


def self_test():
    global emit, policy
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

    config = {
        "subfeature": {"0x0F013": 1, "0x06010": 1},
        "signature": {
            "0x0F013": [{"id": 14345, "l": 1, "s": {
                "capture_limit": "100", "width": "1280", "quality": "50", "capture_cool_time": "6",
            }}],
            "0x06010": [{"id": 123, "l": 1, "s": {"rule": "unchanged"}}],
        },
        "unrelated": {"preserve": [1, "exact-value"]},
    }
    wire = ngs_cipher.encrypt_response(json.dumps(config).encode(), 42)
    original_policy = policy
    original_options, original_emit = getattr(ctx, "options", None), emit
    events = []
    try:
        ctx.options = type("Options", (), {"ngs_neutralize": False, "ngs_screenshot_filter": True})()
        emit = events.append
        http_request = http.Request.make("POST", "https://x-config.ngs.nexon.com/v1", b"request-body")
        flow = type("Flow", (), {})()
        flow.id, flow.request, flow.metadata = "screenshot-test", http_request, {}
        flow.response = http.Response.make(200, wire)
        response(flow)
        filtered = ngs_cipher.decrypt_response(flow.response.content, want="json")
        assert filtered["subfeature"] == {"0x0F013": 0, "0x06010": 1}
        assert filtered["signature"]["0x0F013"][0]["l"] == 0
        assert filtered["signature"]["0x0F013"][0]["s"] == config["signature"]["0x0F013"][0]["s"]
        assert filtered["signature"]["0x06010"] == config["signature"]["0x06010"]
        assert filtered["unrelated"] == config["unrelated"]
        assert disable_screenshot(filtered) == {}
        event = events[0]
        assert event["decoded_response"] == config
        assert base64.b64decode(event["response"]["body_base64"]) == wire
        assert base64.b64decode(event["rewritten_response_body_base64"]) == flow.response.content
        assert event["screenshot_filter"]["matched"] and event["screenshot_filter"]["forward"]
        assert event["screenshot_filter"]["action"] == "modify"
        try:
            disable_screenshot({"signature": {"0x0F013": {}}})
            raise AssertionError("Malformed screenshot config was accepted")
        except ValueError:
            pass
        trial = decode_client_request(wire)
        assert trial["status"] == "decrypted" and trial["decoded_request"] == config
        assert base64.b64decode(trial["plaintext_base64"]) == json.dumps(config).encode()
        assert decode_client_request(b"not-valid-ngs")["status"] == "undecoded"
        request_flow = type("Flow", (), {})()
        request_flow.id = "request-decode-test"
        request_flow.request = http.Request.make("POST", "https://x-csauth.ngs.nexon.com/v2", wire)
        request_flow.metadata = {"process": {"name": "grap-core64.aes"}}
        request_flow.response = None
        request(request_flow)
        assert events[-1]["client_decode"]["status"] == "decrypted"
        assert request_flow.response is None
        request_flow.id = "request-decode-failure"
        request_flow.request = http.Request.make("POST", "https://x-csauth.ngs.nexon.com/v2", b"not-valid-ngs")
        request(request_flow)
        assert events[-1]["client_decode"]["status"] == "undecoded"
        assert "decoded_request" not in events[-1]["client_decode"]
        policy = Policy({"version": 1, "rules": [{
            "id": "decoded-field", "action": "drop", "protocol": "https",
            "field": {"name": "payload.subfeature.0x0F013", "equals": 1},
        }]})
        request_flow.id = "decoded-field-drop"
        request_flow.request = http.Request.make("POST", "https://x-csauth.ngs.nexon.com/v2", wire)
        request_flow.response = None
        request(request_flow)
        assert events[-1]["decision"]["rule_id"] == "decoded-field"
        assert not events[-1]["decision"]["forward"] and request_flow.response.status_code == 403
        launcher_flow = type("Flow", (), {})()
        launcher_flow.id = "launcher-response"
        launcher_flow.request = http.Request.make("GET", "https://launcher.example/v1")
        launcher_flow.metadata = {"process": {"name": "nexon_launcher.exe"}}
        launcher_flow.response = http.Response.make(200, b"plain-response")
        response(launcher_flow)
        assert base64.b64decode(events[-1]["response"]["body_base64"]) == b"plain-response"
        assert events[-1]["decode_status"] == "not_applicable"
    finally:
        policy = original_policy
        if original_options is None:
            del ctx.options
        else:
            ctx.options = original_options
        emit = original_emit
    headers = http.Headers(authorization="secret", user_agent="test")
    assert redacted_headers(headers)["authorization"] == "<redacted>"
    print("PASS: NGS neutralization and screenshot-only rewrite preserve unrelated fields and log exact before/after bytes.")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
    else:
        raise SystemExit("Run with mitmdump -s ngs-mitm.py, or --self-test.")
