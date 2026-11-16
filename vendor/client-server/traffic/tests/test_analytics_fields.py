"""Analytics record parsing (csv lists, memory dumps, process list), tls-keys.py --fields and sizes,
and the jyp descrambler, on synthetic data only."""

from __future__ import annotations

import base64
import contextlib
import importlib.util
import io
import json
import struct
import unittest
from pathlib import Path

from traffic import tls12

REPO = Path(__file__).resolve().parents[2]


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, REPO / "analysis" / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


tls_keys = load("tls_keys", "tls-keys.py")
jyp = load("jyp_decode", "jyp-decode.py")


def process_list(base, entries, start=0x40):
    """A buffer holding a SYSTEM_PROCESS_INFORMATION list at `start`, the list's address being `base`."""
    buf, o = bytearray(start), start
    for i, (pid, ppid, threads, name) in enumerate(entries):
        raw = name.encode("utf-16-le")
        size = (0x100 + 0x50 * threads + len(raw) + 7) // 8 * 8
        e = bytearray(size)
        struct.pack_into("<II", e, 0, 0 if i == len(entries) - 1 else size, threads)
        struct.pack_into("<HH4xQ", e, 0x38, len(raw), len(raw) + 2, base + (o - start) + 0x100 + 0x50 * threads)
        struct.pack_into("<QQI", e, 0x50, pid, ppid, 77)
        e[0x100 + 0x50 * threads:0x100 + 0x50 * threads + len(raw)] = raw
        buf += e
        o += size
    return bytes(buf + bytes(64))


class AnalyticsFieldsTest(unittest.TestCase):
    def test_csv_rows(self):
        ies = {"mouseEventHeader": "time,x,y,event,device", "mouseEvents": ["1,2,3,LD,-1"], "keyEventHeader": "time,event,key,device"}
        self.assertEqual(tls12.csv_rows("NXLog_InputEventSequence", ies),
                         {"mouseEvents": [{"time": "1", "x": "2", "y": "3", "event": "LD", "device": "-1"}], "keyEvents": []})
        rows = tls12.csv_rows("ETC_MSInputEvent", {"keydatas": ["5,65,256,0,1,10,20"]})["keydatas"]
        self.assertEqual((rows[0]["vk"], rows[0]["msg"], rows[0]["y"]), ("65", "256", "20"))

    def test_bu_dump_and_process_list(self):
        snap = process_list(0x7000000, [(0x20, 0x10, 2, "first.exe"), (0x24, 0x20, 1, "second.exe")])
        payload = {"bu_t": 1, "bu_d": base64.b64encode(struct.pack("<Q", 0x143bda7b0)).decode() + "|" + base64.b64encode(snap).decode()}
        addr, raw = tls12.bu_dump(payload)
        self.assertEqual((addr, raw), (0x143bda7b0, snap))
        procs = tls12.process_snapshot(raw)
        self.assertEqual([(e["pid"], e["ppid"], e["threads"], e["handles"], e["name"]) for e in procs],
                         [(0x20, 0x10, 2, 77, "first.exe"), (0x24, 0x20, 1, 77, "second.exe")])
        self.assertEqual(tls12.process_snapshot(bytes(4096)), [])

    def test_fields_summary_is_masked(self):
        snap = process_list(0x7000000, [(0x20, 0x10, 1, "secretprogram.exe")])
        bu = base64.b64encode(struct.pack("<Q", 0x143bda7b0)).decode() + "|" + base64.b64encode(snap).decode()
        recs = [{"type": "ETC_MSMouseEvent", "ETC_MSMouseEvent": {"mousedatas": ["900,1234,567,512,,", "0,1,2,513,HND|1,FID|80"], "charname": "Somebody"}},
                {"type": "ETC_MSInputEvent", "ETC_MSInputEvent": {"keydatas": ["1794000000000,65,256,0,1,10,20"]}},
                {"type": "ETC_BU_CData", "ETC_BU_CData": {"bu_t": 1, "bu_a": 1, "bu_i": 0, "bu_d": bu}},
                {"type": "stability", "stability": {"stage": 8, "prevStage": 7, "comment": "GC:InitGr2D", "elapsedtime": 126, "errorCode": -9999}}]
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            tls_keys.fields_summary([(i * 10**9, len(json.dumps(r)), r) for i, r in enumerate(recs)])
        text = out.getvalue()
        for expected in ("'move': 1, 'left down': 1", "'HND': 1", "1 distinct keys", "RVA 0x3bda7b0",
                         "(32, 16, 1, 77, 'secr…(17)')", "GC:InitGr2D"):
            self.assertIn(expected, text)
        for secret in ("Somebody", "secretprogram", "1234", "1794000000000"):
            self.assertNotIn(secret, text)


class JypTest(unittest.TestCase):
    def test_mt19937_matches_the_standard(self):
        self.assertEqual(jyp.mt19937(5489, 1), [3499211612])   # std::mt19937's default seed and first output

    def test_decode_round_trip(self):
        seed = 0x1234abcd
        ck, sk = jyp.keys(seed)
        frame = lambda fid, body: struct.pack("<II", 8 + len(body), fid) + body
        hello = frame(0x113, struct.pack("<IIII", 1, 0x8d2cf844, seed, 2))
        c2s = hello + jyp.xor(frame(0x166, b"os and cpu" * 20) + frame(0x167, b"x"), ck)
        s2c = frame(0x95, bytes(20)) + frame(0x11b, b"") + jyp.xor(frame(0x9a, b"settings") + b"\x10\x00", sk)
        out = jyp.decode(c2s, s2c)
        self.assertEqual([(f, len(b)) for f, b in out["c2s"]], [(0x113, 16), (0x166, 200), (0x167, 1)])
        self.assertEqual(out["s2c"], [(0x95, bytes(20)), (0x11b, b""), (0x9a, b"settings")])
        with self.assertRaises(ValueError):
            jyp.decode(frame(0x99, bytes(16)), b"")


if __name__ == "__main__":
    unittest.main()
