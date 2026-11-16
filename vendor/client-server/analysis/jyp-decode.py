#!/usr/bin/env python3
"""Descramble and split a recorded jypc.dll connection (Nexon "jyp" performance telemetry, TCP 9994).

    .venv/bin/python analysis/jyp-decode.py captures/proxy-<stamp>.jsonl [--port 9994]

No recording has one yet (it talks at about 1 in 10 game starts; docs/guides/PROTOCOL.md, "jypc.dll").
Read from jypc.dll 1.1.0.5 (RVAs in it; connection thread 0x10520, receive 0x10150):

- Frame: u32 LE total length (header included), u32 LE id, body. Both directions.
- The server speaks first: id 0x95 (20-byte body) or 0x15a (u8 flag). After 0x95 the client queues
  its hello (24 bytes, sent in clear): u32 24, u32 0x113, u32 r1, u32 0x8d2cf844, u32 seed, u32 r2
  (three random values; likely byte for byte: the serializer 0x11000 -> 0x11060 copies the 24-byte
  struct, then writes its size first).
- std::mt19937 seeded with `seed`: its first 29 outputs (116 bytes, LE words) are the client's key
  (.data 0x74700), the next 29 the server's (0x74680). Every client byte after the hello is XOR-ed with
  key[i % 116], i counting from 0 over the whole stream (0x10c90); server bytes are in clear until the
  end of the server's 0x11b frame, then XOR-ed the same way with the server key (0x103c9, 0x102ec).
  Scrambling, not encryption: the hello carries the seed.

Prints one line per frame: direction, id, length (bodies hold hardware and timing data: not printed).
"""

from __future__ import annotations

import argparse
import json
import random
import struct
from collections import defaultdict

HELLO_ID, SERVER_HELLO_IDS, SCRAMBLE_ID = 0x113, (0x95, 0x15a), 0x11b


def mt19937(seed, n):
    """First n outputs of std::mt19937(seed) (init_genrand; Python's own seeding differs, its generator does not)."""
    mt = [seed & 0xffffffff]
    for i in range(1, 624):
        mt.append((0x6c078965 * (mt[-1] ^ (mt[-1] >> 30)) + i) & 0xffffffff)
    r = random.Random()
    r.setstate((3, tuple(mt) + (624,), None))
    return [r.getrandbits(32) for _ in range(n)]


def keys(seed):
    """(client key, server key), 116 bytes each."""
    words = mt19937(seed, 58)
    return struct.pack("<29I", *words[:29]), struct.pack("<29I", *words[29:])


def xor(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def frames(buf):
    """[(id, body)] of complete frames; a trailing partial frame is left out."""
    out, o = [], 0
    while o + 8 <= len(buf):
        size, fid = struct.unpack_from("<II", buf, o)
        if size < 8 or o + size > len(buf):
            break
        out.append((fid, buf[o + 8:o + size]))
        o += size
    return out


def decode(c2s, s2c):
    """{"c2s": [(id, body)], "s2c": [...]} of one connection's two byte streams."""
    hello = frames(c2s[:24])
    if not hello or hello[0][0] != HELLO_ID:
        raise ValueError("the client stream does not start with the 0x113 hello")
    client_key, server_key = keys(struct.unpack_from("<I", c2s, 16)[0])
    clear, o = [], 0   # server frames up to and including 0x11b are in clear
    for fid, body in frames(s2c):
        clear.append((fid, body))
        o += 8 + len(body)
        if fid == SCRAMBLE_ID:
            return {"c2s": hello + frames(xor(c2s[24:], client_key)), "s2c": clear + frames(xor(s2c[o:], server_key))}
    return {"c2s": hello + frames(xor(c2s[24:], client_key)), "s2c": clear}


def streams(path, port):
    """{conn: {"client_to_server": bytes, "server_to_client": bytes}} of the recording's connections to `port`."""
    conns, data = set(), defaultdict(lambda: defaultdict(bytearray))
    for line in open(path, encoding="utf-8"):
        if '"connection_open"' in line:
            r = json.loads(line)
            if r["destination"][1] == port:
                conns.add(r["conn"])
        elif '"kind":"data"' in line:
            r = json.loads(line)
            if r["conn"] in conns:
                data[r["conn"]][r["direction"]] += bytes.fromhex(r["hex"])
    return {c: data[c] for c in sorted(conns)}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("recording")
    ap.add_argument("--port", type=int, default=9994)
    args = ap.parse_args()
    conns = streams(args.recording, args.port)
    for c, d in conns.items():
        try:
            out = decode(bytes(d["client_to_server"]), bytes(d["server_to_client"]))
        except ValueError as e:
            print(f"conn {c}: {e}")
            continue
        print(f"== conn {c}")
        for direction in ("s2c", "c2s"):
            for fid, body in out[direction]:
                print(f"{direction} id {fid:#x} {len(body)} bytes")
    print(f"{len(conns)} connections to port {args.port}")


if __name__ == "__main__":
    main()
