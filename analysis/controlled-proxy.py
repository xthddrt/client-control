"""Shared HTTP/HTTPS and raw-TCP capture with conservative client-to-server decoding."""

import base64
import hashlib
import importlib.util
from pathlib import Path
import sys
import time

from mitmproxy import http, tcp, udp


DIRECTORY = Path(__file__).resolve().parent
sys.path.insert(0, str(DIRECTORY.parent / "foundations"))
_spec = importlib.util.spec_from_file_location("client_control_ngs_mitm", DIRECTORY / "ngs-mitm.py")
ngs_mitm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ngs_mitm)
from process_sockets import SocketOwnerResolver
from traffic_protocols import decode_dns_datagram, decode_http_run, decode_maple_run, decode_tls_run


MAX_DECODE_BYTES = 32 * 1024 * 1024
flows = {}
udp_flows = {}
socket_owners = SocketOwnerResolver()


def load(loader):
    ngs_mitm.load(loader)


def request(flow: http.HTTPFlow):
    ngs_mitm.request(flow)


def response(flow: http.HTTPFlow):
    ngs_mitm.response(flow)


def error(flow: http.HTTPFlow):
    ngs_mitm.error(flow)


def endpoint(address):
    if not address:
        return None
    return {"address": address[0], "port": int(address[1])}


def decode_stream(data, direction):
    """Recognize a contiguous stream; never scan past an unparsed suffix."""
    if not data:
        return {"protocol": "tcp", "recognized": False, "frames": [], "problem": {"reason": "empty_stream"}, "unparsed": b""}
    for protocol, decoder in (("tls", decode_tls_run), ("http", decode_http_run), ("maple", decode_maple_run)):
        result = decoder(data, direction) if protocol == "maple" else decoder(data)
        if result["recognized"]:
            result["protocol"] = protocol
            return result
    return {
        "protocol": "tcp", "recognized": False, "frames": [],
        "problem": {"reason": "unrecognized_stream"}, "unparsed": data,
    }


def state_for(flow):
    if flow.id not in flows:
        tcp_start(flow)
    return flows[flow.id]


def tcp_start(flow):
    process = flow.metadata.get("process")
    if isinstance(process, str):
        process = {"name": process, "evidence": "mitmproxy_process_metadata"}
    process = process or socket_owners.lookup(flow.client_conn.peername)
    destination = endpoint(flow.server_conn.address)
    decision = ngs_mitm.policy.decide({
        "process": process, "protocol": "tcp", "type": "TCP", "direction": "client_to_server",
        "destination": destination, "fields": {},
    })
    state = {
        "flow": flow, "process": process, "destination": destination,
        "decision": decision, "forward": decision["forward"],
        "raw": {"client_to_server": bytearray(), "server_to_client": bytearray()},
        "chunks": {"client_to_server": [], "server_to_client": []},
        "indices": {"client_to_server": 0, "server_to_client": 0},
        "total": {"client_to_server": 0, "server_to_client": 0},
        "truncated": {"client_to_server": False, "server_to_client": False},
    }
    flows[flow.id] = state
    ngs_mitm.emit({
        "kind": "tcp_start", "timestamp": time.time(), "flow_id": flow.id,
        "session_id": ngs_mitm.session_id, "process": process,
        "client": endpoint(flow.client_conn.peername), "destination": destination,
        "decision": decision, "coverage": "raw_tcp_proxy_observation_not_uninstrumented_paths",
    })
    if not decision["forward"]:
        flow.kill()


def tcp_message(flow):
    state = state_for(flow)
    message = flow.messages[-1]
    direction = "client_to_server" if message.from_client else "server_to_client"
    content = bytes(message.content)
    offset = state["total"][direction]
    index = state["indices"][direction]
    state["indices"][direction] += 1
    state["total"][direction] += len(content)
    timestamp_ns = int(message.timestamp * 1_000_000_000)
    if len(state["raw"][direction]) < MAX_DECODE_BYTES:
        accepted = min(len(content), MAX_DECODE_BYTES - len(state["raw"][direction]))
        state["raw"][direction].extend(content[:accepted])
        state["chunks"][direction].append({
            "offset": offset, "end": offset + accepted, "time_ns": timestamp_ns, "chunk_index": index,
        })
        if accepted < len(content):
            state["truncated"][direction] = True
    else:
        state["truncated"][direction] = True
    ngs_mitm.emit({
        "kind": "tcp_data", "timestamp": message.timestamp, "flow_id": flow.id,
        "session_id": ngs_mitm.session_id, "process": state["process"],
        "client": endpoint(flow.client_conn.peername), "destination": state["destination"],
        "direction": direction, "chunk_index": index, "stream_offset": offset,
        "raw_base64": base64.b64encode(content).decode("ascii"),
        "sha256": hashlib.sha256(content).hexdigest(), "bytes": len(content),
        "raw_scope": "exact_tcp_stream_chunk_not_network_packet_or_retransmission",
        "forward": state["forward"], "forward_evidence": "unchanged_proxy_content" if state["forward"] else "connection_killed_before_forwarding",
        "server_receipt_proven": False,
    })


def frame_time(state, direction, frame):
    start = frame["offset"]
    end = start + len(frame["raw"])
    contributors = [chunk for chunk in state["chunks"][direction] if chunk["offset"] < end and chunk["end"] > start]
    times = [chunk["time_ns"] for chunk in contributors]
    return {
        "time_ns": min(times) if times else None,
        "time_end_ns": max(times) if times else None,
        "operation_ids": [f"{state['flow'].id}:{direction}:{chunk['chunk_index']}" for chunk in contributors],
        "time_evidence": "contributing_tcp_chunk_times" if times else "unavailable",
    }


def finish(flow, error=None):
    state = flows.pop(flow.id, None)
    if state is None:
        return
    for direction in ("client_to_server", "server_to_client"):
        data = bytes(state["raw"][direction])
        decoded = decode_stream(data, direction)
        frames = []
        for frame in decoded["frames"]:
            decode = frame.get("decode") or {}
            evaluation = ngs_mitm.policy.decide({
                "process": state["process"], "protocol": decode.get("protocol", decoded["protocol"]),
                "type": decode.get("type"), "direction": direction,
                "destination": state["destination"], "fields": decode.get("fields", {}),
            })
            evaluation.update({
                "stage": "post_forward_observation", "applied": False,
                "original_traffic_unchanged": True,
            })
            frames.append({
                "offset": frame["offset"],
                "raw_base64": base64.b64encode(frame["raw"]).decode("ascii"),
                "plaintext_base64": base64.b64encode(frame["plaintext"]).decode("ascii") if frame.get("plaintext") is not None else None,
                "decode": decode, "policy_evaluation": evaluation,
                **frame_time(state, direction, frame),
            })
        ngs_mitm.emit({
            "kind": "tcp_decode", "timestamp": time.time(), "flow_id": flow.id,
            "session_id": ngs_mitm.session_id, "process": state["process"],
            "client": endpoint(flow.client_conn.peername), "destination": state["destination"],
            "direction": direction, "protocol": decoded["protocol"], "recognized": decoded["recognized"],
            "frames": frames, "problem": decoded.get("problem"),
            "unparsed_base64": base64.b64encode(decoded.get("unparsed", b"")).decode("ascii"),
            "decode_bytes": len(data), "captured_stream_bytes": state["total"][direction],
            "decode_window_truncated": state["truncated"][direction],
            "cipher_evidence": decoded.get("cipher_evidence"),
        })
    ngs_mitm.emit({
        "kind": "tcp_end", "timestamp": time.time(), "flow_id": flow.id,
        "session_id": ngs_mitm.session_id, "process": state["process"],
        "client": endpoint(flow.client_conn.peername), "destination": state["destination"],
        "bytes": state["total"], "decode_window_truncated": state["truncated"], "error": error,
    })


def tcp_end(flow):
    finish(flow)


def tcp_error(flow):
    finish(flow, str(flow.error) if flow.error else "unknown TCP error")


def udp_start(flow):
    process = flow.metadata.get("process")
    if isinstance(process, str):
        process = {"name": process, "evidence": "mitmproxy_process_metadata"}
    process = process or socket_owners.lookup(flow.client_conn.peername)
    destination = endpoint(flow.server_conn.address)
    decision = ngs_mitm.policy.decide({
        "process": process, "protocol": "udp", "type": "UDP", "direction": "client_to_server",
        "destination": destination, "fields": {},
    })
    udp_flows[flow.id] = {"process": process, "destination": destination, "decision": decision,
                          "forward": decision["forward"], "indices": {}, "total": {}}
    ngs_mitm.emit({
        "kind": "udp_start", "timestamp": time.time(), "flow_id": flow.id,
        "session_id": ngs_mitm.session_id, "process": process,
        "client": endpoint(flow.client_conn.peername), "destination": destination,
        "transport_protocol": "udp", "decision": decision,
        "coverage": "raw_udp_proxy_observation_not_uninstrumented_paths",
    })
    if not decision["forward"]:
        flow.kill()


def udp_message(flow):
    state = udp_flows[flow.id]
    message = flow.messages[-1]
    direction = "client_to_server" if message.from_client else "server_to_client"
    content = bytes(message.content)
    index = state["indices"].get(direction, 0)
    state["indices"][direction] = index + 1
    state["total"][direction] = state["total"].get(direction, 0) + len(content)
    client = endpoint(flow.client_conn.peername)
    decoded = decode_dns_datagram(content) if (
        (state["destination"] or {}).get("port") == 53 or (client or {}).get("port") == 53
    ) else None
    evaluation = ngs_mitm.policy.decide({
        "process": state["process"], "protocol": decoded.get("protocol", "udp") if decoded else "udp",
        "type": decoded.get("type") if decoded else None, "direction": direction,
        "destination": state["destination"], "fields": decoded.get("fields", {}) if decoded else {},
    })
    evaluation.update({"stage": "post_forward_observation", "applied": False, "original_traffic_unchanged": True})
    ngs_mitm.emit({
        "kind": "udp_data", "timestamp": message.timestamp, "flow_id": flow.id,
        "session_id": ngs_mitm.session_id, "process": state["process"],
        "client": client, "destination": state["destination"], "transport_protocol": "udp",
        "direction": direction, "datagram_index": index,
        "raw_base64": base64.b64encode(content).decode("ascii"),
        "sha256": hashlib.sha256(content).hexdigest(), "bytes": len(content),
        "raw_scope": "exact_udp_datagram", "decode": decoded, "policy_evaluation": evaluation,
        "forward": state["forward"], "forward_evidence": "unchanged_proxy_content" if state["forward"] else "flow_killed_before_forwarding",
        "server_receipt_proven": False,
    })


def udp_end(flow, error=None):
    state = udp_flows.pop(flow.id, None)
    if state is None:
        return
    ngs_mitm.emit({
        "kind": "udp_end", "timestamp": time.time(), "flow_id": flow.id,
        "session_id": ngs_mitm.session_id, "process": state["process"],
        "client": endpoint(flow.client_conn.peername), "destination": state["destination"],
        "transport_protocol": "udp", "bytes": state["total"], "error": error,
    })


def udp_error(flow):
    udp_end(flow, str(flow.error) if flow.error else "unknown UDP error")


def unload():
    for flow in list(flows.values()):
        finish(flow, "proxy_shutdown")
    for flow in list(udp_flows.values()):
        udp_end(flow, "proxy_shutdown")
    ngs_mitm.unload()
