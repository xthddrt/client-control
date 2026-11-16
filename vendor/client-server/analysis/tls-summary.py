#!/usr/bin/env python3
"""What a recorded TLS connection shows without decrypting it: records, client fingerprint, certificates.

    .venv/bin/python analysis/tls-summary.py captures/proxy-<stamp>.jsonl --sni <server name> [--all]
    .venv/bin/python analysis/tls-summary.py captures/proxy-<stamp>.jsonl --conn <n>

For each matching connection (the first one unless --all): the TLS record sequence with times and
lengths (application data lengths are the HTTP sizes plus the cipher's overhead: 24 bytes for TLS 1.2
AES-GCM), the ClientHello's cipher suites, extensions and groups (which TLS library sent it), and,
for TLS 1.2, the server's certificate chain (TLS 1.3 encrypts it).
"""

from __future__ import annotations

import argparse
import json
import struct

from cryptography import x509

RECORD = {20: "ChangeCipherSpec", 21: "Alert", 22: "Handshake", 23: "AppData"}
HANDSHAKE = {1: "ClientHello", 2: "ServerHello", 4: "NewSessionTicket", 8: "EncryptedExtensions",
             11: "Certificate", 12: "ServerKeyExchange", 14: "ServerHelloDone", 16: "ClientKeyExchange"}


def records(data):
    i = 0
    while i + 5 <= len(data):
        kind, version, length = data[i], *struct.unpack(">HH", data[i + 1:i + 5])
        yield kind, version, data[i + 5:i + 5 + length]
        i += 5 + length


def client_hello(body):
    p = 4 + 2 + 32
    p += 1 + body[p]
    n = struct.unpack(">H", body[p:p + 2])[0]
    suites = [struct.unpack(">H", body[p + 2 + i:p + 4 + i])[0] for i in range(0, n, 2)]
    p += 2 + n
    p += 1 + body[p]
    end = p + 2 + struct.unpack(">H", body[p:p + 2])[0]
    p += 2
    extensions = {}
    while p + 4 <= end:
        kind, length = struct.unpack(">HH", body[p:p + 4])
        extensions[kind] = body[p + 4:p + 4 + length]
        p += 4 + length
    return suites, extensions


def certificates(body):
    q = 4 + 3
    while q < len(body):
        n = int.from_bytes(body[q:q + 3], "big")
        yield x509.load_der_x509_certificate(body[q + 3:q + 3 + n])
        q += 3 + n


def summary(lines):
    out, t0 = [], None
    for record in lines:
        if record["kind"] != "data":
            if record["kind"] in ("connection_open", "tls_client_hello", "connection_close"):
                out.append(f"{record['kind']}: " + json.dumps({k: record[k] for k in ("destination", "sni", "bytes")
                                                               if k in record}))
            continue
        t0 = t0 or record["time_ns"]
        data = bytes.fromhex(record["hex"])
        parts = []
        for kind, version, body in records(data):
            name = RECORD.get(kind, str(kind))
            if kind == 22 and body:
                name += "/" + HANDSHAKE.get(body[0], "encrypted")
                if body[0] == 1:
                    suites, ext = client_hello(body)
                    out.append(f"  ClientHello suites {[hex(s) for s in suites]}")
                    out.append(f"  ClientHello extensions {sorted(ext)}; ALPN {ext.get(16)}; "
                               f"TLS 1.3 offered: {43 in ext}; groups {ext.get(10, b'').hex()}")
                if body[0] == 11:
                    for cert in certificates(body):
                        out.append(f"  certificate {cert.subject.rfc4514_string()} | issuer "
                                   f"{cert.issuer.rfc4514_string()} | {cert.not_valid_before_utc.date()} to "
                                   f"{cert.not_valid_after_utc.date()}")
            parts.append(f"{name}(v{version:#x}, {len(body)})")
        out.append(f"{(record['time_ns'] - t0) / 1e6:10.1f} ms {record['direction']:<16} {len(data):>6} B  "
                   + " ".join(parts))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("recording")
    ap.add_argument("--sni")
    ap.add_argument("--conn", type=int)
    ap.add_argument("--all", action="store_true")
    args = ap.parse_args()
    conns, wanted = {}, set()
    for line in open(args.recording, encoding="utf-8"):
        if '"kind":"message"' in line:
            continue
        record = json.loads(line)
        if "conn" not in record:
            continue
        conns.setdefault(record["conn"], []).append(record)
        if (args.conn is not None and record["conn"] == args.conn) or \
           (args.sni and record["kind"] == "tls_client_hello" and record.get("sni") == args.sni):
            wanted.add(record["conn"])
    for conn in sorted(wanted)[:None if args.all else 1]:
        print(f"== conn {conn}")
        print("\n".join(summary(conns[conn])))


if __name__ == "__main__":
    main()
