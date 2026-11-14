from __future__ import annotations

import base64
import json
import struct
import tempfile
import unittest
from pathlib import Path

from traffic.decode import PLAIN_TO_WIRE, decode_game, tls_client_hello_sni
from traffic.game import decrypt_frames, join_frames, parse_frames
from traffic.ledger import build, write_ledger
from traffic.plaintext import load_plaintext
from traffic.monitor import load_monitor
from traffic.ngs import load_ngs
from traffic.pcap import read_packets
from traffic.policy import evaluate, load_policy, policy_to_kfilter
from traffic.tcp import assemble
from traffic.transport import SEND_MASK, get_new_iv, high_short

from traffic.tests.helpers import (
    ethernet,
    game_body,
    dns_query,
    ipv4_tcp,
    ipv4_udp,
    ng_s_response,
    seal_frame,
    tls_client_hello,
    tls_record,
    write_pcap,
    write_pcapng,
    write_plaintext_capture,
)


BASE_NS = 1_700_000_000_000_000_000
CLIENT = ("10.0.0.2", 50000)
SERVER = ("203.0.113.5", 8585)


def _game_pcap(tmp, include_second_segment=True, start_ns=BASE_NS):
    body1 = game_body(0x32B, {0x0F: struct.pack("<I", 0x143FF), 0x13: b"\x01\x00\x00\x00"})
    body2 = game_body(0x32B, {0x0F: struct.pack("<I", 0x14400), 0x13: b"\x01\x00\x00\x00"})
    iv0 = bytes.fromhex("01020304")
    iv1 = get_new_iv(iv0)
    frame1 = seal_frame(body1, iv0)
    frame2 = seal_frame(body2, iv1)
    split_at = 20
    segment1 = frame1[:split_at]
    segment2 = frame1[split_at:] + frame2
    packets = []
    t = start_ns / 1e9
    packets.append((t + 0.000, ethernet(ipv4_tcp(CLIENT[0], SERVER[0], CLIENT[1], SERVER[1], 1000, 0, 0x02))))
    packets.append((t + 0.001, ethernet(ipv4_tcp(SERVER[0], CLIENT[0], SERVER[1], CLIENT[1], 5000, 1001, 0x12))))
    packets.append((t + 0.002, ethernet(ipv4_tcp(CLIENT[0], SERVER[0], CLIENT[1], SERVER[1], 1001, 5001, 0x10))))
    packets.append((t + 0.003, ethernet(ipv4_tcp(CLIENT[0], SERVER[0], CLIENT[1], SERVER[1], 1001, 5001, 0x18, segment1))))
    if include_second_segment:
        packets.append((t + 0.004, ethernet(ipv4_tcp(CLIENT[0], SERVER[0], CLIENT[1], SERVER[1], 1001 + split_at, 5001, 0x18, segment2))))
        packets.append((t + 0.005, ethernet(ipv4_tcp(CLIENT[0], SERVER[0], CLIENT[1], SERVER[1], 1001 + split_at, 5001, 0x18, segment2))))
    pcap = tmp / "game.pcap"
    write_pcap(pcap, packets)
    plaintext = tmp / "outgoing.jsonl"
    write_plaintext_capture(
        plaintext,
        [(start_ns + 3_000_000, body1, "s1:1"), (start_ns + 4_000_000, body2, "s1:2")],
        start_ns=start_ns,
    )
    return pcap, plaintext, body1, body2, frame1, frame2


class PcapAndReassemblyTest(unittest.TestCase):
    def test_reassembles_split_combined_and_retransmitted_frames(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            pcap, plaintext, body1, body2, frame1, frame2 = _game_pcap(tmp)
            inventory = read_packets([pcap])
            self.assertEqual(len(inventory.packets), 6)
            flows, notes = assemble(inventory.packets)
            self.assertEqual(len(flows), 1)
            flow = flows[0]
            self.assertEqual(flow.client, CLIENT)
            self.assertEqual(flow.server, SERVER)
            frames, notices = parse_frames(flow.c2s)
            self.assertEqual(len(frames), 2, notices)
            self.assertTrue(frames[0].split)
            self.assertTrue(frames[1].combined)
            self.assertFalse(frames[1].split)
            self.assertTrue(any(segment.classification == "retransmission" for segment in flow.c2s.segments))
            self.assertEqual(flow.c2s.conflict_bytes, 0)
            self.assertEqual(frames[0].ciphertext, frame1[4:])
            self.assertEqual(frames[1].ciphertext, frame2[4:])
            decryption = decrypt_frames(frames)
            self.assertEqual(decryption.status, "seeded")
            self.assertEqual(decryption.frames[0].opcode, 0x32B)
            self.assertEqual(decryption.frames[1].opcode, 0x32B)
            sends = load_plaintext([plaintext]).sends
            joined, unmatched, unmatched_sends = join_frames(
                frames, decryption, sends, window_ns=5_000_000_000
            )
            self.assertEqual(unmatched_sends, [])
            self.assertEqual(len(joined), 2)

    def test_gap_is_reported_not_zero_filled(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            pcap, plaintext, *_ = _game_pcap(tmp, include_second_segment=False)
            inventory = read_packets([pcap])
            flows, _ = assemble(inventory.packets)
            frames, notices = parse_frames(flows[0].c2s)
            self.assertEqual(frames, [])
            self.assertTrue(any(note["reason"] == "incomplete_frame" for note in notices))
            self.assertEqual(bytes(flows[0].c2s.data), flows[0].c2s.data[:len(flows[0].c2s.data)])
            self.assertFalse(any(b != 0 for b in flows[0].c2s.data[len(flows[0].c2s.data):]))

    def test_pcapng_monitor_comment_and_timestamp(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            frame = ipv4_tcp(CLIENT[0], SERVER[0], CLIENT[1], SERVER[1], 1001, 5001, 0x18, b"hello")
            path = tmp / "events.pcapng"
            write_pcapng(path, [(BASE_NS + 123, frame)], comment="pid=4242;process=MapleStory.exe;socket=socket:[99];cookie=7")
            inventory = read_packets([path])
            self.assertEqual(len(inventory.packets), 1)
            packet = inventory.packets[0]
            self.assertEqual(packet.process["pid"], 4242)
            self.assertEqual(packet.process["name"], "MapleStory.exe")
            self.assertEqual(packet.socket["inode"], 99)
            self.assertEqual(packet.epb_direction, "outbound")
            self.assertEqual(packet.payload, b"hello")
            self.assertEqual(packet.time_ns // 100, (BASE_NS + 123) // 100)


class DecodeTest(unittest.TestCase):
    def test_pickup_layout(self):
        body = game_body(0x32B, {
            0x0F: struct.pack("<I", 0x143FF),
            0x13: struct.pack("<I", 1),
            0x18: struct.pack("<I", 721204),
            0x1C: struct.pack("<I", 721204),
        })
        decoded = decode_game(body)
        self.assertEqual(decoded["name"], "pickup_request")
        self.assertEqual(decoded["decode_status"], "complete")
        fields = {field["name"]: field["value"] for field in decoded["fields"]}
        self.assertEqual(fields["drop_object_id"], 0x143FF)
        self.assertEqual(fields["item_specific_metadata"], 1)
        self.assertEqual(fields["context_18"], 721204)

    def test_unknown_opcode_stays_unparsed(self):
        body = struct.pack("<H", 0x1234) + b"\xaa\xbb\xcc"
        decoded = decode_game(body)
        self.assertEqual(decoded["confidence"], "unknown")
        self.assertEqual(decoded["decode_status"], "unknown")
        self.assertEqual(decoded["unparsed"][0]["size"], len(body))

    def test_tls_sni(self):
        # Minimal ClientHello with one server_name extension.
        host = b"x-config.ngs.nexon.com"
        sni = struct.pack(">H", len(host) + 3) + b"\x00" + struct.pack(">H", len(host)) + host
        ext = struct.pack(">HH", 0, len(sni)) + sni
        hello = (
            b"\x03\x03" + b"\x00" * 32 + b"\x00" + struct.pack(">H", 2) + b"\x00\x2f"
            + b"\x01\x00" + struct.pack(">H", len(ext)) + ext
        )
        body = b"\x01" + struct.pack(">I", len(hello))[1:] + hello
        record = b"\x16\x03\x01" + struct.pack(">H", len(body)) + body
        self.assertEqual(tls_client_hello_sni(record), host.decode())


class LedgerTest(unittest.TestCase):
    def test_end_to_end_game_ledger(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            pcap, plaintext, body1, body2, frame1, frame2 = _game_pcap(tmp)
            ledger = build(pcap_paths=[pcap], plaintext_paths=[plaintext])
            messages = [record for record in ledger.records if record.get("record_type") == "message"]
            self.assertEqual(len(messages), 2)
            first = messages[0]
            self.assertEqual(first["message"]["type"]["opcode"], 0x32B)
            self.assertEqual(first["message"]["type"]["name"], "pickup_request")
            self.assertEqual(bytes.fromhex(first["message"]["raw_bytes_hex"]), body1)
            self.assertTrue(first["reconstruction"]["split"])
            self.assertTrue(first["reconstruction"]["combined"])
            self.assertTrue(first["reconstruction"]["retransmitted"])
            self.assertTrue(first["provenance"]["in_process"])
            self.assertIsNotNone(first["provenance"]["constructor"])
            self.assertGreaterEqual(len(first["provenance"]["serialization_steps"]), 1)
            self.assertTrue(first["provenance"]["send"]["registers"])
            self.assertTrue(first["provenance"]["send"]["return_stack"])
            fields = {field["name"]: field.get("value") for field in first["message"]["fields"]}
            self.assertEqual(fields["drop_object_id"], 0x143FF)
            second = messages[1]
            self.assertEqual(bytes.fromhex(second["message"]["raw_bytes_hex"]), body2)
            self.assertEqual(
                {field["name"]: field.get("value") for field in second["message"]["fields"]}["drop_object_id"],
                0x14400,
            )

    def test_ingest_policy_attaches_every_decision(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            pcap, plaintext, *_ = _game_pcap(tmp)
            policy_data = {
                "default": "allow",
                "rules": [{
                    "id": "audit-pickup",
                    "action": "audit",
                    "match": {
                        "protocol": ["maplestory_game"],
                        "type": {"opcode": "0x32b"},
                        "field": [{"name": "drop_object_id", "equals": "0x143ff"}],
                    },
                }],
            }
            policy_path = tmp / "policy.json"
            policy_path.write_text(json.dumps(policy_data))
            ledger = build(pcap_paths=[pcap], plaintext_paths=[plaintext], policy_path=policy_path)
            messages = [record for record in ledger.records if record.get("record_type") == "message"]
            self.assertEqual(len(messages), 2)
            self.assertEqual(messages[0]["filter"]["rule_id"], "audit-pickup")
            self.assertEqual(messages[0]["filter"]["action"], "audit")
            self.assertTrue(messages[0]["filter"]["simulated_offline"])
            self.assertEqual(messages[1]["filter"]["rule_id"], None)
            self.assertEqual(len(ledger.decisions), 2)
            self.assertTrue(all(decision["simulated_offline"] for decision in ledger.decisions))

    def test_dropped_send_without_wire_is_still_recorded(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            pcap, plaintext, body1, body2, *_ = _game_pcap(tmp, include_second_segment=False)
            # Rewrite the second send as dropped and remove the first frame match by
            # changing its body suffix so the in-process record cannot be joined.
            lines = plaintext.read_text().splitlines()
            changed = []
            for line in lines:
                record = json.loads(line)
                if record.get("kind") == "send" and record.get("opcode") == hex(0x32B):
                    if record["length"] == len(body2):
                        record["dropped"] = True
                        record["body"] = (body2[:2] + b"\xff" * (len(body2) - 2)).hex()
                changed.append(json.dumps(record))
            plaintext.write_text("\n".join(changed) + "\n")
            ledger = build(pcap_paths=[pcap], plaintext_paths=[plaintext])
            messages = [record for record in ledger.records if record.get("record_type") == "message"]
            dropped = [record for record in messages if record.get("transmitted") is False]
            self.assertTrue(dropped)
            self.assertTrue(any(
                "dropped" in str(record.get("provenance", {}).get("missing", [])) for record in dropped
            ))

    def test_ngs_log_records_request_and_decoded_response(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            response = ng_s_response({
                "emergency_stop": 1,
                "detected": ["x"],
                "module_crc": {"grap64.dll": 3004574433},
            })
            log = tmp / "ngs.jsonl"
            log.write_text(json.dumps({
                "kind": "response",
                "timestamp": BASE_NS / 1e9,
                "request": {
                    "method": "POST", "host": "x-config.ngs.nexon.com",
                    "path": "/v1/config", "headers": {"authorization": "<redacted>"},
                    "body_base64": base64.b64encode(b"opaque-request").decode(),
                },
                "response": {
                    "status": 200, "headers": {},
                    "body_base64": response,
                },
            }) + "\n")
            capture = load_ngs([log])
            self.assertEqual(len(capture.messages), 1)
            self.assertIsNotNone(capture.messages[0].decoded_response)
            ledger = build(ngs_paths=[log])
            messages = [record for record in ledger.records if record.get("record_type") == "message"]
            self.assertEqual(len(messages), 1)
            message = messages[0]
            self.assertEqual(message["message"]["protocol"], "ngs_https")
            self.assertEqual(message["message"]["type"]["name"], "ngs_request")
            self.assertEqual(bytes.fromhex(message["message"]["raw_bytes_hex"]), b"opaque-request")
            self.assertIn("response_evidence", message)
            self.assertEqual(message["response_evidence"]["decoded"]["emergency_stop"], 1)
            self.assertTrue(any(
                item["field"] == "request_plaintext"
                for item in message["provenance"]["missing"]
            ))

    def test_monitor_network_data_fallback(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            body = game_body(0x2EF, {2: struct.pack("<I", 2), 6: struct.pack("<I", 33), 10: struct.pack("<I", 185)}, length=14)
            body2 = game_body(0x2EF, {2: struct.pack("<I", 2), 6: struct.pack("<I", 34), 10: struct.pack("<I", 186)}, length=14)
            iv = bytes.fromhex("0a0b0c0d")
            frame = seal_frame(body, iv) + seal_frame(body2, get_new_iv(iv))
            payload = base64.b64encode(frame).decode()
            events = tmp / "events.jsonl"
            events.write_text("\n".join([
                json.dumps({
                    "type": "process_start", "timestamp": "2023-11-14T22:13:20.000Z",
                    "process_id": 4242, "thread_id": 4242, "text": "/game/MapleStory.exe",
                }),
                json.dumps({
                    "type": "network_data", "timestamp": "2023-11-14T22:13:21.000Z",
                    "process_id": 4242, "thread_id": 4242, "sequence": 1,
                    "operation_id": 10, "flags": 0x200, "flags_names": "payload_input|payload_present",
                    "detail": "endpoints=10.0.0.2:50000 -> 203.0.113.5:8585;socket:[99]",
                    "text": "socket:[99]", "payload": {
                        "kind": "network_data", "encoding": "base64", "data": payload,
                        "operation_id": 10, "total_bytes": len(frame), "byte_offset": 0,
                        "chunk_index": 0, "chunk_count": 1, "final_chunk": True,
                    },
                }),
                json.dumps({
                    "type": "network_flow_close", "timestamp": "2023-11-14T22:13:22.000Z",
                    "process_id": 4242, "thread_id": 4242, "text": "10.0.0.2:50000 -> 203.0.113.5:8585",
                    "detail": "close;reason=test", "value0": 99,
                }),
                json.dumps({
                    "type": "kfilter_decision", "timestamp": "2023-11-14T22:13:22.100Z",
                    "process_id": 4242, "thread_id": 4242, "value1": 10001,
                    "text": "send tcp 203.0.113.5:8585 socket:[99] #1 len=14",
                    "detail": "action=deny;layer=message;target=network;rule_id=10001;bytes=14;image=MapleStory.exe",
                }),
            ]) + "\n")
            capture = load_monitor([events])
            self.assertEqual(len(capture.calls), 1)
            self.assertEqual(capture.calls[0].data, frame)
            self.assertEqual(capture.calls[0].direction, "send")
            self.assertEqual(capture.calls[0].endpoint, SERVER)
            self.assertEqual(capture.calls[0].socket_inode, 99)
            self.assertEqual(len(capture.decisions), 1)
            self.assertEqual(capture.decisions[0].action, "deny")
            ledger = build(monitor_paths=[events])
            messages = [record for record in ledger.records if record.get("record_type") == "message"]
            self.assertEqual(len(messages), 2)
            self.assertEqual(messages[0]["message"]["type"]["opcode"], 0x2EF)
            fields = {field["name"]: field.get("value") for field in messages[0]["message"]["fields"]}
            self.assertEqual(fields["value_c"], 185)
            fields2 = {field["name"]: field.get("value") for field in messages[1]["message"]["fields"]}
            self.assertEqual(fields2["value_c"], 186)


class UdpAndMonitorMetadataTest(unittest.TestCase):
    def test_dns_query_is_recorded_with_exact_payload(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            payload = dns_query("x-config.ngs.nexon.com")
            frame = ethernet(ipv4_udp("10.0.0.2", "8.8.8.8", 53000, 53, payload))
            path = tmp / "dns.pcap"
            write_pcap(path, [(BASE_NS / 1e9, frame)])
            ledger = build(pcap_paths=[path])
            messages = [record for record in ledger.records if record.get("record_type") == "message"]
            self.assertEqual(len(messages), 1, ledger.summary.get("capture_notes"))
            message = messages[0]
            self.assertEqual(message["message"]["protocol"], "udp")
            self.assertEqual(message["message"]["type"]["name"], "dns_query")
            self.assertEqual(bytes.fromhex(message["message"]["raw_bytes_hex"]), payload)
            fields = {field["name"]: field.get("value") for field in message["message"]["fields"]}
            self.assertEqual(fields["query"], "x-config.ngs.nexon.com")
            self.assertEqual(fields["qtype"], 1)

    def test_incomplete_payload_gap_never_inserts_zero_bytes(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            events = tmp / "events.jsonl"
            records = []
            for offset, data in ((0, b"abc"), (2, b"def")):
                records.append(json.dumps({
                    "type": "network_data", "timestamp": "2023-11-14T22:13:21.000Z",
                    "process_id": 4242, "thread_id": 4242, "sequence": offset,
                    "operation_id": 10, "flags": 0x200, "flags_names": "payload_input|payload_present",
                    "detail": "endpoints=10.0.0.2:50000 -> 203.0.113.5:8585;socket:[99]",
                    "text": "socket:[99]", "payload": {
                        "kind": "network_data", "encoding": "base64",
                        "data": base64.b64encode(data).decode(),
                        "operation_id": 10, "total_bytes": 6, "byte_offset": offset,
                        "chunk_index": offset, "chunk_count": 2,
                        "final_chunk": offset == 2,
                    },
                }))
            events.write_text("\n".join(records) + "\n")
            capture = load_monitor([events])
            self.assertEqual(capture.calls, [])
            self.assertTrue(any("payload_gap" in note.get("detail", "") for note in capture.notes))

    def test_monitor_flow_metadata_and_decision_are_records(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            events = tmp / "events.jsonl"
            events.write_text("\n".join([
                json.dumps({
                    "type": "network_flow_established", "timestamp": "2023-11-14T22:13:21.000Z",
                    "process_id": 4242, "thread_id": 4242,
                    "text": "10.0.0.2:50000 -> 203.0.113.5:8585",
                    "detail": "connect;family=2;type=1", "value0": 99,
                    "value1": (6 << 32) | (50000 << 16) | 8585,
                }),
                json.dumps({
                    "type": "network_flow_close", "timestamp": "2023-11-14T22:13:22.000Z",
                    "process_id": 4242, "thread_id": 4242,
                    "text": "10.0.0.2:50000 -> 203.0.113.5:8585",
                    "detail": "close;reason=test;bytes_sent=10;bytes_received=20", "value0": 99,
                }),
                json.dumps({
                    "type": "kfilter_decision", "timestamp": "2023-11-14T22:13:22.100Z",
                    "process_id": 4242, "thread_id": 4242, "value1": 10001,
                    "text": "send tcp 203.0.113.5:8585 socket:[99] #1 len=14",
                    "detail": "action=deny;layer=message;target=network;rule_id=10001;bytes=14;image=MapleStory.exe",
                }),
            ]) + "\n")
            ledger = build(monitor_paths=[events])
            types = [record.get("record_type") for record in ledger.records]
            self.assertIn("flow", types)
            self.assertIn("filter_decision", types)
            flow = next(record for record in ledger.records if record.get("record_type") == "flow")
            self.assertEqual(flow["flow"]["source"], "monitor_flow_event")
            decision = next(record for record in ledger.records if record.get("record_type") == "filter_decision")
            self.assertEqual(decision["decision"]["action"], "deny")


class MonitorCoverageTest(unittest.TestCase):
    def test_monitor_does_not_duplicate_a_pcap_flow_but_adds_uncovered_one(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            pcap, plaintext, *_ = _game_pcap(tmp)
            body = game_body(0x2EF, {
                2: struct.pack("<I", 2), 6: struct.pack("<I", 33), 10: struct.pack("<I", 185),
            }, length=14)
            iv = bytes.fromhex("11121314")
            frame = seal_frame(body, iv) + seal_frame(body, get_new_iv(iv))

            def record(operation, payload, detail):
                return {
                    "type": "network_data", "timestamp": "2023-11-14T22:13:21.000Z",
                    "process_id": 999, "thread_id": 999, "operation_id": operation,
                    "flags": 0x200, "flags_names": "payload_input|payload_present",
                    "detail": detail, "text": "socket:[777]", "payload": {
                        "kind": "network_data", "encoding": "base64",
                        "data": base64.b64encode(payload).decode(), "operation_id": operation,
                        "total_bytes": len(payload), "byte_offset": 0,
                        "chunk_index": 0, "chunk_count": 1, "final_chunk": True,
                    },
                }

            events = tmp / "events.jsonl"
            events.write_text("\n".join([
                json.dumps(record(1, b"abc", "endpoints=10.0.0.2:50000 -> 203.0.113.5:8585;socket:[777]")),
                json.dumps(record(2, frame, "endpoints=10.0.0.2:50001 -> 203.0.113.9:443;socket:[777]")),
            ]) + "\n")
            ledger = build(pcap_paths=[pcap], plaintext_paths=[plaintext], monitor_paths=[events])
            flows = [record for record in ledger.records if record.get("record_type") == "flow"]
            self.assertEqual(len(flows), 2)
            messages = [record for record in ledger.records if record.get("record_type") == "message"]
            self.assertEqual(len(messages), 4)
            synthetic = [record for record in messages if (record.get("reconstruction") or {}).get("capture_source") == "monitor_network_data"]
            self.assertEqual(len(synthetic), 2)
            self.assertTrue(all(record["transport"]["destination"]["port"] == 443 for record in synthetic))


class TlsNgsTest(unittest.TestCase):
    def test_tls_client_hello_sni_matches_the_ngs_proxy_request(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            client = ("10.0.0.7", 51000)
            server = ("203.0.113.20", 443)
            host = "x-config.ngs.nexon.com"
            hello = tls_client_hello(host)
            app = tls_record(23, b"opaque")
            t0 = BASE_NS / 1e9
            packets = [
                (t0, ethernet(ipv4_tcp(client[0], server[0], client[1], server[1], 1000, 0, 0x02))),
                (t0 + 0.001, ethernet(ipv4_tcp(server[0], client[0], server[1], client[1], 5000, 1001, 0x12))),
                (t0 + 0.002, ethernet(ipv4_tcp(client[0], server[0], client[1], server[1], 1001, 5001, 0x18, hello))),
                (t0 + 0.003, ethernet(ipv4_tcp(client[0], server[0], client[1], server[1], 1001 + len(hello), 5001, 0x18, app))),
            ]
            pcap = tmp / "tls.pcap"
            write_pcap(pcap, packets)
            log = tmp / "ngs.jsonl"
            log.write_text(json.dumps({
                "kind": "response", "timestamp": t0 + 0.0025,
                "request": {
                    "method": "POST", "host": host, "path": "/v1/config",
                    "headers": {}, "body_base64": "",
                },
                "response": {"status": 200, "headers": {},
                             "body_base64": ng_s_response({"emergency_stop": 1})},
            }) + "\n")
            ledger = build(pcap_paths=[pcap], ngs_paths=[log])
            messages = [record for record in ledger.records if record.get("record_type") == "message"]
            tls = [record for record in messages if record["message"]["protocol"] == "tls"]
            self.assertTrue(any(record["message"]["type"]["name"] == "tls_client_hello" for record in tls))
            ngs = [record for record in messages if record["message"]["protocol"] == "ngs_https"]
            self.assertEqual(len(ngs), 1)
            destination = ngs[0]["transport"]["destination"]
            self.assertEqual(destination["host"], host)
            self.assertEqual(destination["port"], 443)
            self.assertEqual(destination["observed_flow_endpoint"]["ip"], server[0])
            self.assertEqual(ngs[0]["response_evidence"]["decoded"]["emergency_stop"], 1)


class PolicyTest(unittest.TestCase):
    def _message(self):
        body = game_body(0x32B, {0x0F: struct.pack("<I", 0x143FF)})
        return {
            "message_id": "ccm-test",
            "process": {"pid": 42, "name": "MapleStory.exe", "path": "C:/game/MapleStory.exe"},
            "transport": {
                "protocol": "maplestory_game",
                "destination": {"ip": "203.0.113.5", "port": 8585},
            },
            "message": {
                "protocol": "maplestory_game",
                "raw_bytes_hex": body.hex(),
                "type": {"opcode": 0x32B, "opcode_hex": "0x32b", "name": "pickup_request",
                         "confidence": "confirmed"},
                "fields": decode_game(body)["fields"],
                "decode_status": "complete",
            },
        }

    def test_rule_matches_process_protocol_destination_type_field(self):
        policy_data = {
            "schema": "client-control.traffic-filter/v1",
            "default": "allow",
            "rules": [{
                "id": "drop-pickup-143ff",
                "action": "drop",
                "match": {
                    "process": {"name": "MapleStory.exe"},
                    "protocol": ["maplestory_game"],
                    "destination": {"ip": "203.0.113.0/24", "port": 8585},
                    "type": {"opcode": "0x32b", "name": "pickup_request"},
                    "field": [{"name": "drop_object_id", "equals": "0x143ff"}],
                    "size": {"min": 36, "max": 36},
                },
            }],
        }
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "policy.json"
            path.write_text(json.dumps(policy_data))
            policy = load_policy(path)
            decision = evaluate(policy, self._message())
            self.assertTrue(decision["matched"])
            self.assertEqual(decision["action"], "drop")
            self.assertEqual(decision["rule_id"], "drop-pickup-143ff")

    def test_missing_destination_does_not_match_or_guess(self):
        policy_data = {
            "default": "allow",
            "rules": [{
                "id": "dest-rule", "action": "drop",
                "match": {"destination": {"host": "x-config.ngs.nexon.com"}},
            }],
        }
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "policy.json"
            path.write_text(json.dumps(policy_data))
            policy = load_policy(path)
            message = self._message()
            message["transport"]["destination"] = None
            decision = evaluate(policy, message)
            self.assertFalse(decision["matched"])
            self.assertEqual(decision["action"], "allow")
            self.assertTrue(decision["evaluated_rules"][0]["missing_evidence"])

    def test_kfilter_translation_marks_unsupported_dimensions(self):
        policy_data = {
            "default": "allow",
            "rules": [{
                "id": "n", "action": "audit",
                "match": {
                    "process": {"name": "MapleStory.exe"},
                    "protocol": ["maplestory_game"],
                    "destination": {"ip": "203.0.113.5", "port": 8585},
                    "type": {"opcode": "0x1ef"},
                },
            }],
        }
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "policy.json"
            path.write_text(json.dumps(policy_data))
            text = policy_to_kfilter(load_policy(path))
            self.assertIn("protect MapleStory.exe", text)
            self.assertIn("image=MapleStory.exe", text)
            self.assertIn("ip=203.0.113.5", text)
            self.assertIn("port=8585", text)
            self.assertIn("not fully translated", text)


class ExplainTest(unittest.TestCase):
    def test_explain_reports_evidence_not_causality(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            pcap, plaintext, *_ = _game_pcap(tmp)
            ledger = build(pcap_paths=[pcap], plaintext_paths=[plaintext])
            write_ledger(ledger, tmp / "out")
            from traffic.explain import explain, format_text

            report = explain(ledger.records, BASE_NS + 4_000_000, window_ns=10_000_000_000)
            self.assertGreaterEqual(report["counts"]["messages"], 1)
            text = format_text(report)
            self.assertIn("does not prove", text)
            self.assertIn("Capture gaps", text)


if __name__ == "__main__":
    unittest.main()
