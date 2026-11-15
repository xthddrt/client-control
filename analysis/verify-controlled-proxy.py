"""Verify shared HTTP/raw-TCP capture and client-to-server decoding on loopback only."""

import argparse
import base64
import http.client
import http.server
import json
import os
from pathlib import Path
import runpy
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "foundations"))
from traffic_protocols import PLAIN_TO_WIRE, load_wire
from mitmproxy.io import FlowReader
from mitmproxy.tcp import TCPFlow
from mitmproxy.udp import UDPFlow


CONFIG = {
    "subfeature": {"0x0F013": 1, "0x06010": 1},
    "signature": {"0x0F013": [{"id": 14345, "l": 1, "s": {
        "capture_limit": "100", "width": "1280", "quality": "50", "capture_cool_time": "6",
    }}]},
    "unrelated": {"preserve": [1, "exact-value"]},
}


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def maple_fixture():
    wire = load_wire()
    pickup = bytearray(36)
    struct.pack_into("<H", pickup, 0, 0x32B)
    struct.pack_into("<I", pickup, 0x0F, 99)
    current = bytes.fromhex("02000000")
    frames = []
    for plain in (bytes(pickup), b"\x70\x00\x05"):
        body = bytearray(plain)
        struct.pack_into("<H", body, 0, PLAIN_TO_WIRE.get(struct.unpack_from("<H", body)[0], struct.unpack_from("<H", body)[0]))
        word0 = wire._hs(current) ^ wire.SEND_MASK
        encrypted = wire.decrypt_body(current, bytes(body), 0)
        frames.append(struct.pack("<HH", word0, word0 ^ len(body)) + encrypted)
        current = wire.tc.getNewIv(current, wire.TABLE)
    return b"".join(frames)


def verify(output):
    cipher = runpy.run_path(str(ROOT / "foundations/ngs_cipher.py"), run_name="controlled_proxy_cipher")
    encoded = maple_fixture()
    wire = cipher["encrypt_response"](json.dumps(CONFIG).encode(), 42)

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            reply = wire if body == wire else b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(reply)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(reply)

        def log_message(self, *args):
            pass

    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            received = bytearray()
            while len(received) < len(encoded):
                chunk = self.request.recv(65536)
                if not chunk:
                    break
                received.extend(chunk)
            assert bytes(received) == encoded
            self.request.sendall(b"raw-ack")

    class Datagram(socketserver.BaseRequestHandler):
        def handle(self):
            data, client = self.request
            assert data in (dns_query, b"plain-udp")
            client.sendto(b"udp-ack", self.client_address)

    dns_query = bytearray(12) + b"\x03foo\x07example\x03com\x00" + struct.pack(">HH", 1, 1)
    struct.pack_into(">HHHH", dns_query, 0, 7, 0x0100, 1, 0)
    dns_query = bytes(dns_query)
    http_server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    raw_server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo)
    udp_server = socketserver.ThreadingUDPServer(("127.0.0.1", 0), Datagram)
    threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in (http_server, raw_server, udp_server)]
    for thread in threads:
        thread.start()
    http_port, raw_port, udp_port = free_port(), free_port(), free_port()
    with tempfile.TemporaryDirectory(prefix="controlled-proxy-", dir=ROOT / "captures") as temporary:
        temporary = Path(temporary)
        log_path = temporary / "events.jsonl"
        flow_path = temporary / "flows.mitm"
        with (temporary / "proxy.log").open("wb") as proxy_log:
            proxy = subprocess.Popen([
                str(ROOT / ".venv/bin/mitmdump"), "-s", str(ROOT / "analysis/controlled-proxy.py"),
                "--set", "rawtcp=true", "--set", "connection_strategy=lazy", "--set", "keep_host_header=true",
                "--set", "ngs_neutralize=false", "--set", f"ngs_log={log_path}",
                "--mode", f"reverse:http://127.0.0.1:{http_server.server_port}@{http_port}",
                "--mode", f"reverse:tcp://127.0.0.1:{raw_server.server_address[1]}@{raw_port}",
                "--mode", f"reverse:udp://127.0.0.1:{udp_server.server_address[1]}@{udp_port}",
                "-w", str(flow_path),
            ], cwd=ROOT, stdout=proxy_log, stderr=subprocess.STDOUT)
            try:
                time.sleep(1)
                for body in (wire, b"not-valid-ngs"):
                    connection = http.client.HTTPConnection("127.0.0.1", http_port, timeout=5)
                    connection.request("POST", "/v2", body=body, headers={"Host": "x-csauth.ngs.nexon.com"})
                    response = connection.getresponse()
                    received = response.read()
                    connection.close()
                    assert response.status == 200
                    assert received == (wire if body == wire else b"ok")
                connection = http.client.HTTPConnection("127.0.0.1", http_port, timeout=5)
                connection.request("POST", "/launcher", body=b"plain-request", headers={"Host": "launcher.example"})
                response = connection.getresponse()
                assert response.read() == b"ok"
                connection.close()
                with socket.create_connection(("127.0.0.1", raw_port), timeout=5) as client:
                    client.settimeout(5)
                    client.sendall(encoded[:5])
                    time.sleep(0.05)
                    client.sendall(encoded[5:])
                    reply = client.recv(64)
                    if reply != b"raw-ack":
                        (ROOT / "captures/controlled-proxy-failure.log").write_bytes((temporary / "proxy.log").read_bytes())
                        (ROOT / "captures/controlled-proxy-failure.jsonl").write_bytes(log_path.read_bytes())
                        print("Raw TCP reply mismatch:", repr(reply))
                    assert reply == b"raw-ack"
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.settimeout(5)
                    for datagram in (dns_query, b"plain-udp"):
                        client.sendto(datagram, ("127.0.0.1", udp_port))
                        assert client.recv(64) == b"udp-ack"
            finally:
                (ROOT / "captures/controlled-proxy-last.log").write_bytes((temporary / "proxy.log").read_bytes())
                if log_path.exists():
                    (ROOT / "captures/controlled-proxy-last.jsonl").write_bytes(log_path.read_bytes())
                proxy.terminate()
                try:
                    proxy.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proxy.kill()
                    proxy.wait(timeout=5)
        for server in (http_server, raw_server, udp_server):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=2)
        events = [json.loads(line) for line in log_path.read_text().splitlines()]
        tcp_decode = [event for event in events if event["kind"] == "tcp_decode" and event["direction"] == "client_to_server"]
        frames = [frame for event in tcp_decode for frame in event["frames"]]
        assert len(frames) == 2
        assert frames[0]["decode"]["type"] == "0x32b" and frames[0]["decode"]["fields"]["drop_object_id"] == 99
        assert frames[1]["decode"]["type"] == "0x70"
        assert all(frame["policy_evaluation"]["applied"] is False for frame in frames)
        assert all(frame["policy_evaluation"]["stage"] == "post_forward_observation" for frame in frames)
        requests = [event for event in events if event["kind"] == "request"]
        success = next(event for event in requests if event.get("client_decode", {}).get("status") == "decrypted")
        failure = next(event for event in requests if event.get("client_decode", {}).get("status") == "undecoded")
        assert success["client_decode"]["decoded_request"] == CONFIG
        assert base64.b64decode(success["client_decode"]["plaintext_base64"]) == json.dumps(CONFIG).encode()
        assert base64.b64decode(failure["request"]["body_base64"]) == b"not-valid-ngs"
        launcher = next(event for event in events if event["kind"] == "response" and event["request"]["host"] == "launcher.example")
        assert base64.b64decode(launcher["response"]["body_base64"]) == b"ok"
        ledger_module = runpy.run_path(str(ROOT / "analysis/traffic-ledger.py"), run_name="controlled_proxy_ledger")
        builder = ledger_module["LedgerBuilder"](temporary / "ledger")
        builder.add_ngs(log_path)
        builder.finish()
        ledger = [json.loads(line) for line in (temporary / "ledger/traffic.jsonl").open()]
        raw_chunks = [row for row in ledger if row["kind"] == "socket_operation"]
        assert b"".join(base64.b64decode(row["raw"]["data"]) for row in raw_chunks
                        if row["direction"] == "client_to_server" and row["socket"]["protocol"] == "tcp") == encoded
        maple_messages = [row for row in ledger if row["kind"] == "message" and row.get("decode", {}).get("protocol") == "maple"]
        assert len(maple_messages) == 2
        assert all(row["policy_evaluation"]["applied"] is False for row in maple_messages)
        ngs_request = next(row for row in ledger if row["kind"] == "message" and row["direction"] == "client_to_server"
                           and row["decode"].get("request_decode", {}).get("status") == "decrypted")
        assert base64.b64decode(ngs_request["plaintext"]["data"]) == json.dumps(CONFIG).encode()
        assert ngs_request["decode"]["fields"]["payload"] == CONFIG
        with flow_path.open("rb") as stream:
            flows = list(FlowReader(stream).stream())
        raw_flow = next(flow for flow in flows if isinstance(flow, TCPFlow))
        assert b"".join(message.content for message in raw_flow.messages if message.from_client) == encoded
        assert b"".join(message.content for message in raw_flow.messages if not message.from_client) == b"raw-ack"
        udp_events = [event for event in events if event["kind"] == "udp_data" and event["direction"] == "client_to_server"]
        assert [base64.b64decode(event["raw_base64"]) for event in udp_events] == [dns_query, b"plain-udp"]
        assert all(event["decode"] is None for event in udp_events)
        assert all(event["policy_evaluation"]["applied"] is False for event in udp_events)
        udp_records = [row for row in ledger if row["kind"] == "message" and row["decode"].get("protocol") == "udp"]
        assert any(base64.b64decode(row["raw"]["data"]) == b"plain-udp" for row in udp_records)
        udp_flow = next(flow for flow in flows if isinstance(flow, UDPFlow))
        assert [message.content for message in udp_flow.messages if message.from_client] == [dns_query, b"plain-udp"]
        assert [message.content for message in udp_flow.messages if not message.from_client] == [b"udp-ack", b"udp-ack"]
        evidence = {
            "schema": "client-control.controlled-proxy-offline.v1",
            "scope": "real_local_mitmdump_and_loopback_servers_only",
            "raw_maple_client_hex": encoded.hex(),
            "decoded_frames": [{"type": frame["decode"]["type"], "fields": frame["decode"]["fields"]} for frame in frames],
            "raw_tcp_round_trip_verified": True,
            "split_and_combined_stream_reassembled": True,
            "udp_datagrams_hex": [dns_query.hex(), b"plain-udp".hex()],
            "udp_round_trip_verified": True,
            "unknown_udp_protocols_preserved": True,
            "ngs_synthetic_client_decode": success["client_decode"],
            "ngs_failed_client_decode_status": failure["client_decode"]["status"],
            "non_ngs_http_response_preserved": True,
            "ledger_raw_and_message_links_verified": True,
            "policy_stage": "post_forward_observation",
            "policy_applied_at_proxy": False,
            "live_maple_story_or_Nexon_tested": False,
            "real_NGS_request_cipher_proven": False,
        }
        output.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(evidence, stream, indent=2)
            stream.write("\n")
        print(json.dumps({"output": str(output), "maple_frames": len(frames),
                          "raw_tcp_chunks": len(raw_chunks), "NGS_request_trial": success["client_decode"]["status"],
                          "NGS_unknown_trial": failure["client_decode"]["status"]}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    verify(args.output)


if __name__ == "__main__":
    main()
