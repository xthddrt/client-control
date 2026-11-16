#!/usr/bin/env python3
"""Decode port 47611 (nmconew64.dll, Nexon messenger core "NMCO") from proxy recordings.

    .venv/bin/python analysis/nmco-decode.py captures/proxy-<stamp>.jsonl ...
    .venv/bin/python analysis/nmco-decode.py --check captures/proxy-*.jsonl*

Wire (RVAs in nmconew64.dll; reader 0x17ded0, stream 0x17c660):
  u16 BE length of the rest | u16 BE packet type | u8 0x18 stream magic | u24 BE stream length |
  block: u8 flags (1 zlib, 2 encrypted, 4 CRC) | u24 BE body size | u32 BE key | u32 BE field check | body
Cipher (0x187a10): per LE word i, p[i] = T[i % 16] ^ c[i] ^ p[i-1] ^ key, T = 16 words at .data 0x2afac0.
Body fields: u32 LE, u8, text = u16 count + UTF-16LE.

Prints one line per message with NP12 tokens masked (first 4 characters and the length): the tokens
carry the account number and are live credentials. --check only counts messages that parse with no
bytes left over.
"""

from __future__ import annotations

import argparse
import json
import struct
import time
from collections import defaultdict

PORT = 47611
T = struct.unpack("<16I", bytes.fromhex(
    "7815fc401f6c3b1119ca8983d86c19e2891490746615ab4aa0128c7bcdff1800"
    "4b70abcc0f8c5a7b91b813aa079841deaebcff1234ba5f5f99acf51001ddc1b1"))
CLASSES = {   # factory registration 0xd6c70
    **dict.fromkeys((0x0b, 0x0f, 0x10, 0x14, 0x33), "CUSignInPacket"),
    **dict.fromkeys((0x0c, 0x11, 0x34), "CUSignInReplyPacket"),
    **dict.fromkeys((0x0d, 0x35), "CUSignOutPacket"), **dict.fromkeys((0x0e, 0x36), "CUSignOutReplyPacket"),
    0x12: "CUSecurityLoginCNRequest", 0x13: "CUSecurityLoginCNReply",
    **dict.fromkeys((0x15, 0x17, 0x18), "CUUpdateSession2Packet"), 0x16: "CUUpdateSessionReplyPacket",
    0x2d: "CURequestOldFashionInfo", 0x2e: "CURequestOldFashionInfoReply",
    0x31: "CUGameTokenRequest2", 0x32: "CUGameTokenReply2",
    0x37: "CUGetPasswordHashKey", 0x38: "CUGetPasswordHashKeyReply",
    0x39: "CUPCBangLogin", 0x3a: "CUPCBangLoginReply",
    0x3f: "CUTPATokenLogin", 0x40: "CUTPATokenLoginReply",
    0x41: "CUPlugTokenLogin", 0x42: "CUPlugTokenLoginReply",
}


def decrypt(data, key):
    out, prev = bytearray(data), 0
    for i in range(len(data) // 4):
        prev = T[i & 15] ^ struct.unpack_from("<I", data, 4 * i)[0] ^ prev ^ key
        struct.pack_into("<I", out, 4 * i, prev)
    return bytes(out)


def parse(frame):
    ptype = struct.unpack_from(">H", frame, 2)[0]
    stream = frame[4:]
    if stream[0] != 0x18:
        raise ValueError("no stream magic")
    block = stream[4:4 + int.from_bytes(stream[1:4], "big")]
    flags, key = block[0], int.from_bytes(block[4:8], "big")
    body = decrypt(block[12:], key) if flags & 2 else block[12:]
    return ptype, flags, body


class Reader:
    def __init__(self, body):
        self.b, self.o = body, 0

    def u8(self):
        self.o += 1
        return self.b[self.o - 1]

    def u32(self):
        self.o += 4
        return struct.unpack_from("<I", self.b, self.o - 4)[0]

    def text(self):
        n = struct.unpack_from("<H", self.b, self.o)[0]
        self.o += 2 + 2 * n
        return self.b[self.o - 2 * n:self.o].decode("utf-16-le")


def fields(ptype, body):
    r = Reader(body)
    if ptype == 0x18:     # CUUpdateSession2Packet v2, read 0xde450
        f = dict(version=r.u32(), flag=r.u8(), game_code=hex(r.u32()), text=r.text(), token=r.text())
    elif ptype == 0x16:   # CUUpdateSessionReplyPacket, read 0xde720
        f = dict(result=r.u32(), message=r.text(), token=r.text(), a=r.u32(), b=r.u32(), next_refresh_s=r.u32())
    else:
        return {}, body
    return f, body[r.o:]


def mask(value):
    return f"{value[:4]}…({len(value)} chars)" if isinstance(value, str) and value.startswith("NP12") else value


def frames(paths):
    """Yield (time_ns, direction, frame bytes) of every port-47611 message in the recordings."""
    for path in paths:
        conns, buffers = set(), defaultdict(bytearray)
        for line in open(path, encoding="utf-8"):
            if '"connection_open"' in line:
                r = json.loads(line)
                if r["destination"][1] == PORT:
                    conns.add(r["conn"])
            elif '"kind":"data"' in line:
                r = json.loads(line)
                if r["conn"] not in conns:
                    continue
                buf = buffers[(r["conn"], r["direction"])]
                buf.extend(bytes.fromhex(r["hex"]))
                while len(buf) >= 4 and len(buf) >= 4 + struct.unpack_from(">H", buf, 0)[0]:
                    size = 4 + struct.unpack_from(">H", buf, 0)[0]
                    yield r["time_ns"], r["direction"], bytes(buf[:size])
                    del buf[:size]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("recordings", nargs="+")
    ap.add_argument("--check", action="store_true", help="count messages that parse with nothing left over")
    args = ap.parse_args()
    total = clean = 0
    for time_ns, direction, frame in frames(args.recordings):
        total += 1
        try:
            ptype, flags, body = parse(frame)
            f, rest = fields(ptype, body)
        except (ValueError, IndexError, struct.error, UnicodeDecodeError) as e:
            print(f"unparsed {direction} message of {len(frame)} bytes: {e}")
            continue
        clean += bool(f) and not rest.rstrip(b"\0")
        if not args.check:
            stamp = time.strftime("%H:%M:%S", time.localtime(time_ns / 1e9))
            print(f"{stamp} {'C>S' if direction == 'client_to_server' else 'S>C'} type {ptype:#04x} "
                  f"{CLASSES.get(ptype, '?')} " + " ".join(f"{k}={mask(v)}" for k, v in f.items()))
    print(f"{clean}/{total} messages parsed with no bytes left over")


if __name__ == "__main__":
    main()
