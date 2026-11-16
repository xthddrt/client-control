import importlib.util
import json
import struct
import tempfile
import unittest
from pathlib import Path

from traffic.tests.test_proxy import table_message
from traffic.timeline import Message, by_connection, messages, parse_type

spec = importlib.util.spec_from_file_location(
    "message_timing", Path(__file__).resolve().parents[2] / "analysis" / "message-timing.py")
timing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(timing)


def record(conn, side, time_ns, body, opcode=None, wire=None):
    out = {"kind": "message", "direction": "client_to_server" if side == "C" else "server_to_client",
           "time_ns": time_ns, "length": len(body), "body_hex": body.hex(), "conn": conn}
    if opcode is not None:
        out["opcode"] = f"0x{opcode:x}"
    if wire is not None:
        out["wire_opcode"] = f"0x{wire:04x}"
    return out


class TimelineTest(unittest.TestCase):
    def test_resolves_client_opcodes_by_table_and_login_rule(self):
        lines = [
            {"kind": "handshake", "time_ns": 1, "length": 19, "body_hex": "", "conn": 1},
            {"kind": "data", "conn": 1, "direction": "client_to_server", "time_ns": 2, "hex": "00"},
            record(1, "S", 3, table_message([0x1234, 0x4321]), opcode=0x32),
            record(1, "C", 4, b"\x21\x43\x01", wire=0x4321),                       # table position 1 -> 0xc8
            record(1, "C", 5, b"\x99\x99", wire=0x9999),                           # not in the table
            {"kind": "handshake", "time_ns": 6, "length": 52, "body_hex": "", "conn": 2},
            record(2, "C", 7, b"\xe7\x02", wire=0x2E7),                            # login server: as on the wire
            record(2, "S", 8, b"\x1a\x00", opcode=0x1A),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "proxy-test.jsonl"
            path.write_text("".join(json.dumps(r, separators=(",", ":")) + "\n" for r in lines) + '{"kind":"message"')
            got = list(messages([str(path)]))
        self.assertEqual([(m.conn, m.side, m.opcode) for m in got],
                         [(1, "S", 0x32), (1, "C", 0xC8), (1, "C", None), (2, "C", 0x2E7), (2, "S", 0x1A)])
        self.assertEqual(got[-1].name, "login_ping")
        self.assertEqual(got[1].body, b"\x21\x43\x01")
        self.assertEqual(got[1].label, "C 0xc8")

    def test_parse_type(self):
        self.assertEqual(parse_type("C:0x9c"), ("C", 0x9C))
        self.assertEqual(parse_type("s 0x1b"), ("S", 0x1B))
        with self.assertRaises(ValueError):
            parse_type("X:1")


def msg(conn, side, opcode, ms, payload=b""):
    return Message("rec", conn, int(ms * 1e6), side, opcode, 2 + len(payload),
                   (struct.pack("<H", opcode) + payload).hex())


class TimingTest(unittest.TestCase):
    def setUp(self):
        items = []
        for i in range(5):   # S 0x165 every 10 s; C 0x177 answers 60 ms later only when V = -1
            value = -1 if i % 2 else -2
            items.append(msg(1, "S", 0x165, i * 10_000, struct.pack("<i", value)))
            if value == -1:
                items.append(msg(1, "C", 0x177, i * 10_000 + 60, struct.pack("<i", -2)))
        self.conns = by_connection(items)

    def test_spec_filter(self):
        spec = timing.Spec("S:0x165:value=-1")
        self.assertEqual(sum(spec.matches(m) for m in self.conns[("rec", 1)]), 2)

    def test_pair_by_field(self):
        out = timing.pair(self.conns, timing.Spec("S:0x165"), timing.Spec("C:0x177"), 2.0, by="value")
        self.assertIn("| -1 | 2 | 2/2 | 60.0 | 60.0 | 60.0 |", out)
        self.assertIn("| -2 | 3 | 0/3 |", out)

    def test_periods(self):
        out = timing.periods(self.conns, [timing.Spec("S:0x165")], 1)
        self.assertIn("| S:0x165 | 5 | 1 | 4 | 10.00 | 10.00 | 10.00 | 0.0 |", out)

    def test_around_against_chance(self):
        out = timing.around(self.conns, timing.Spec("C:0x177"), 0.1, 5)
        self.assertIn("| S 0x165 | client_value_check | 1.00 |", out)

    def test_values_changes(self):
        out = timing.values(self.conns, timing.Spec("S:0x165"), "value")
        self.assertIn("-2 -> -1: 2", out)
        self.assertIn("None -> -2: 1", out)


if __name__ == "__main__":
    unittest.main()
