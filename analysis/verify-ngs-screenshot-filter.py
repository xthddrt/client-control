"""Verify the screenshot-only NGS rewrite through a real local mitmproxy, never Nexon."""

import argparse
import base64
import http.server
import json
import os
from pathlib import Path
import runpy
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "foundations"))
import ngs_cipher


CONFIG = {
    "subfeature": {"0x0F013": 1, "0x06010": 1},
    "signature": {
        "0x0F013": [{"id": 14345, "l": 1, "s": {
            "capture_limit": "100", "width": "1280", "quality": "50", "capture_cool_time": "6",
        }}],
        "0x06010": [{"id": 123, "l": 1, "s": {"rule": "unchanged"}}],
    },
    "unrelated": {"preserve": [1, "exact-value"]},
}


def verify(output):
    wire = ngs_cipher.encrypt_response(json.dumps(CONFIG).encode(), 42)

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            assert self.rfile.read(int(self.headers.get("Content-Length", "0"))) == b"request-body"
            self.send_response(200)
            self.send_header("Content-Length", str(len(wire)))
            self.end_headers()
            self.wfile.write(wire)

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        proxy_port = sock.getsockname()[1]
    with tempfile.TemporaryDirectory(prefix="ngs-screenshot-filter-", dir=ROOT / "captures") as temporary:
        temporary = Path(temporary)
        log_path = temporary / "events.jsonl"
        with (temporary / "proxy.log").open("wb") as proxy_log:
            proxy = subprocess.Popen([
                str(ROOT / ".venv/bin/mitmdump"), "-s", str(ROOT / "analysis/ngs-mitm.py"),
                "--listen-host", "127.0.0.1", "--listen-port", str(proxy_port),
                "--set", "connection_strategy=lazy", "--set", "ngs_neutralize=false",
                "--set", "ngs_screenshot_filter=true", "--set", f"ngs_log={log_path}",
                "--set", "keep_host_header=true",
                "--set", f"map_remote=|http://x-config[.]ngs[.]nexon[.]com/v1|http://127.0.0.1:{server.server_port}/v1",
            ], cwd=ROOT, stdout=proxy_log, stderr=subprocess.STDOUT)
            try:
                time.sleep(1)
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{proxy_port}"}))
                with opener.open("http://x-config.ngs.nexon.com/v1", data=b"request-body", timeout=5) as response:
                    received = response.read()
                filtered = ngs_cipher.decrypt_response(received, want="json")
                events = [json.loads(line) for line in log_path.read_text().splitlines()]
                event = next(item for item in events if item["kind"] == "response")
                assert filtered["subfeature"] == {"0x0F013": 0, "0x06010": 1}
                assert filtered["signature"]["0x0F013"][0]["l"] == 0
                assert filtered["signature"]["0x0F013"][0]["s"] == CONFIG["signature"]["0x0F013"][0]["s"]
                assert filtered["signature"]["0x06010"] == CONFIG["signature"]["0x06010"]
                assert filtered["unrelated"] == CONFIG["unrelated"]
                assert base64.b64decode(event["response"]["body_base64"]) == wire
                assert base64.b64decode(event["rewritten_response_body_base64"]) == received
                assert event["decoded_response"] == CONFIG
                assert event["original_host"] == "x-config.ngs.nexon.com"
                assert event["screenshot_filter"]["action"] == "modify" and event["screenshot_filter"]["forward"]
                ledger_module = runpy.run_path(str(ROOT / "analysis/traffic-ledger.py"), run_name="screenshot_filter_ledger")
                builder = ledger_module["LedgerBuilder"](temporary / "ledger")
                builder.add_ngs(log_path)
                builder.finish()
                ledger = [json.loads(line) for line in (temporary / "ledger/traffic.jsonl").open()]
                decision = next(row for row in ledger if row["kind"] == "filter_decision" and "forwarded_raw" in row)
                assert base64.b64decode(decision["original_raw"]["data"]) == wire
                assert base64.b64decode(decision["forwarded_raw"]["data"]) == received
                assert decision["original_decoded_response"] == CONFIG
                assert decision["rewritten_decoded_response"] == filtered
                assert decision["original_host"] == "x-config.ngs.nexon.com"
                response_message = next(row for row in ledger if row["kind"] == "message" and row["direction"] == "server_to_client")
                assert response_message["policy_evaluation"]["action"] == "modify"
                evidence = {
                    "schema": "client-control.grap-screenshot-filter-offline.v1",
                    "scope": "local_loopback_only_no_Nexon_connection_or_credentials",
                    "request_body": "request-body",
                    "original_decoded_response": CONFIG,
                    "original_wire_base64": base64.b64encode(wire).decode(),
                    "filtered_decoded_response": filtered,
                    "received_wire_base64": base64.b64encode(received).decode(),
                    "decision": event["screenshot_filter"],
                    "mitmproxy_version": subprocess.check_output([str(ROOT / ".venv/bin/mitmdump"), "--version"], text=True).strip().splitlines()[0],
                    "verified": ["real_mitmdump_addon_load", "real_http_request_response", "original_and_rewritten_exact_bytes",
                                 "only_0x0F013_enable_flags_changed", "parameters_and_unrelated_features_preserved"],
                    "live_client_effect_verified": False,
                }
                output.parent.mkdir(parents=True, exist_ok=True)
                descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                    json.dump(evidence, stream, indent=2)
                    stream.write("\n")
                print(json.dumps({"output": str(output), "decision": event["screenshot_filter"]}, indent=2))
            finally:
                proxy.terminate()
                try:
                    proxy.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proxy.kill()
                    proxy.wait(timeout=3)
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    verify(args.output)


if __name__ == "__main__":
    main()
