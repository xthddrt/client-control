"""TLS 1.2 AES-GCM key check and decryption on a synthetic recording (made-up keys, no real data)."""

from __future__ import annotations

import hashlib
import json
import os
import pickle
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from traffic import tls12

REPO = Path(__file__).resolve().parents[2]
MASTER = hashlib.sha384(b"synthetic master secret").digest()
CLIENT_RANDOM = hashlib.sha256(b"synthetic client random").digest()
SERVER_RANDOM = hashlib.sha256(b"synthetic server random").digest()
SESSION_ID = hashlib.sha256(b"synthetic session id").digest()
HOST = b"analytics.example"
BODY = (b'{"type":"NXLog_InputEventSequence","NXLog_InputEventSequence":{"x":1}}\n'
        b'{"type":"ETC_MSMouseEvent","ETC_MSMouseEvent":{"name":"Somebody"}}\n')
REQUEST = (b"POST /upload HTTP/1.1\r\nContent-Type: application/x-ndjson\r\n"
           b"Content-Length: %d\r\n\r\n" % len(BODY) + BODY)
REPLY = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"


def record(kind, body):
    return bytes([kind]) + b"\x03\x03" + struct.pack(">H", len(body)) + body


def handshake(kind, body):
    return record(22, bytes([kind]) + len(body).to_bytes(3, "big") + body)


def client_hello():
    name = b"\x00" + struct.pack(">H", len(HOST)) + HOST
    sni = struct.pack(">HHH", 0, len(name) + 2, len(name)) + name
    return handshake(1, b"\x03\x03" + CLIENT_RANDOM + b"\x00" + b"\x00\x02\xc0\x30" + b"\x01\x00"
                     + struct.pack(">H", len(sni)) + sni)


def server_hello():
    return handshake(2, b"\x03\x03" + SERVER_RANDOM + bytes([len(SESSION_ID)]) + SESSION_ID + b"\xc0\x30\x00")


def sealed(key_salt, plains):
    """CCS, then each (type, plaintext) as an AES-GCM record with sequence numbers from 0."""
    key, salt = key_salt
    out = record(20, b"\x01")
    for seq, (kind, plain) in enumerate(plains):
        explicit = struct.pack(">Q", seq)
        aad = explicit + bytes([kind]) + b"\x03\x03" + struct.pack(">H", len(plain))
        out += record(kind, explicit + AESGCM(key).encrypt(salt + explicit, plain, aad))
    return out


def write_recording(path):
    s = {"suite": 0xc030, "client_random": CLIENT_RANDOM, "server_random": SERVER_RANDOM}
    ks = tls12.keys(MASTER, s)
    finished = b"\x14\x00\x00\x0c" + bytes(12)
    up = client_hello() + sealed(ks["c2s"], [(22, finished), (23, REQUEST[:40]), (23, REQUEST[40:])])
    down = server_hello() + sealed(ks["s2c"], [(22, finished), (23, REPLY)])
    lines = [{"kind": "connection_open", "conn": 7, "destination": ["192.0.2.1", 443]},
             {"kind": "connection_open", "conn": 8, "destination": ["192.0.2.2", 443]},
             {"kind": "data", "conn": 8, "direction": "client_to_server", "hex": client_hello().replace(HOST, b"otherhost.example").hex()},
             {"kind": "data", "conn": 7, "direction": "client_to_server", "hex": up[:150].hex()},
             {"kind": "data", "conn": 7, "direction": "server_to_client", "hex": down.hex()},
             {"kind": "data", "conn": 7, "direction": "client_to_server", "hex": up[150:].hex()}]
    with open(path, "w") as f:
        for i, line in enumerate(lines):
            f.write(json.dumps({**line, "time_ns": i}, separators=(",", ":")) + "\n")


class Tls12Test(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.rec = os.path.join(self.dir.name, "proxy.jsonl")
        write_recording(self.rec)

    def tearDown(self):
        self.dir.cleanup()

    def test_verify_and_decrypt(self):
        conns = tls12.read_recording(self.rec, HOST.decode())
        self.assertEqual(list(conns), [7])
        s = tls12.session(conns[7])
        self.assertEqual((s["client_random"], s["session_id"], s["suite"]), (CLIENT_RANDOM, SESSION_ID, 0xc030))
        self.assertTrue(tls12.verify(MASTER, s))
        self.assertFalse(tls12.verify(bytes(48), s))
        plain = tls12.decrypt(conns[7], MASTER, s)
        (t, line, hdr, body), = tls12.http_messages(plain["c2s"])
        self.assertEqual((line, body), ("POST /upload HTTP/1.1", BODY))
        self.assertEqual([r["type"] for r in tls12.ndjson(body)], ["NXLog_InputEventSequence", "ETC_MSMouseEvent"])
        self.assertEqual(tls12.http_messages(plain["s2c"])[0][1], "HTTP/1.1 200 OK")
        self.assertEqual(tls12.mask({"name": "Somebody", "short": "Abcd", "n": 123456789, "x": 5}),
                         {"name": "Some…(8)", "short": "Ab…(4)", "n": "1234…(9d)", "x": 5})

    def test_cli_find_and_decrypt(self):
        scan = os.path.join(self.dir.name, "scan.pkl")
        with open(scan, "wb") as f:   # the master secret 8-byte aligned among other bytes, as tls-memscan.py saves it
            pickle.dump({"blocks": {0x1000: os.urandom(64) + MASTER + os.urandom(64)}}, f)
        keylog = os.path.join(self.dir.name, "keylog")
        tool = [sys.executable, str(REPO / "analysis/tls-keys.py")]
        run = dict(capture_output=True, text=True, check=True)
        out = subprocess.run(tool + ["needles", self.rec, "--sni", HOST.decode()], **run).stdout
        self.assertEqual(out.split(), [CLIENT_RANDOM.hex(), SERVER_RANDOM.hex(), SESSION_ID.hex()])
        subprocess.run(tool + ["find", self.rec, scan, "--keylog", keylog, "--sni", HOST.decode()], **run)
        self.assertEqual(os.stat(keylog).st_mode & 0o777, 0o600)
        self.assertEqual(open(keylog).read(), f"CLIENT_RANDOM {CLIENT_RANDOM.hex()} {MASTER.hex()}\n")
        out = subprocess.run(tool + ["decrypt", self.rec, "--keylog", keylog, "--sni", HOST.decode()], **run).stdout
        self.assertIn("record types: {'NXLog_InputEventSequence': 1, 'ETC_MSMouseEvent': 1}", out)
        self.assertNotIn("Somebody", out)
        out = subprocess.run(tool + ["sizes", self.rec, "--keylog", keylog, "--sni", HOST.decode()], **run).stdout
        self.assertIn(f"conn 7 (key in keylog): 1 requests, {len(REQUEST)} bytes", out)
        refused = subprocess.run(tool + ["decrypt", self.rec, "--keylog", keylog, "--plaintext",
                                         str(REPO / "plain.jsonl")], capture_output=True, text=True)
        self.assertNotEqual(refused.returncode, 0)
        self.assertFalse((REPO / "plain.jsonl").exists())


if __name__ == "__main__":
    unittest.main()
