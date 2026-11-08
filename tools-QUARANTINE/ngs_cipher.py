#!/usr/bin/env python3
"""
ngs_cipher.py -- NGS-X HTTP control-plane body cipher (MapleStory Classic World / GRAP).

Discovered 2026-10-29 (see ../REPLICATION-GUIDE.md and ../FINDINGS.md).

SCOPE
-----
This breaks the SERVER -> CLIENT ("response") direction of every
    POST https://x-*.ngs.nexon.com/...
body. Those responses carry GRAP's entire control plane: the detection
subfeature map, pushed YARA rules, screenshot-surveillance config, the
expected module CRCs, and the emergency_stop / detected[] kill switch.

The CLIENT -> SERVER ("request") direction uses a STRONGER, position-dependent
keystream (device-bound, lives inside the Themida-wrapped grap modules) and is
NOT handled here -- that is a separate, open target.

THE RESPONSE CIPHER (fully reverse-engineered)
----------------------------------------------
On the wire the body is base64(text). base64-decode it to raw bytes C, then:

    1. The plaintext is gzip(JSON)  ->  magic 1f 8b 08 00 ...
    2. The transform is a single-byte XOR over the whole buffer, EXCEPT the
       first two bytes are a 2-byte header that replaces the gzip magic
       1f 8b (varies per message). On the wire:
           C[0], C[1]  = 2-byte header (NOT 1f 8b)
           C[2:]       = XOR_K( gzip_stream[2:] ),  gzip_stream[0:2] = 1f 8b
       and C[2] == XOR_K(0x08) because gzip byte[2] (CM) is always 0x08.
    3. Therefore the key is recovered with ZERO guessing:
           K = C[2] XOR 0x08
       Then gzip = b"\x1f\x8b" + bytes(c ^ K for c in C)[2:]
       and   JSON = gunzip(gzip).

   The gzip CRC-32 trailer validates the result, so a successful gunzip is
   proof the key is correct (no heuristics needed).

WHY IT'S WEAK: single-byte XOR over a gzip stream leaves long runs of the XOR
key wherever the compressed data has runs of a constant byte -- which is how
the cipher was first spotted (6-byte repeats visible in the base64).

USAGE
-----
    from ngs_cipher import decrypt_response
    plaintext_json_bytes = decrypt_response(raw_or_base64)

    # CLI: pipe a base64 body on stdin
    echo '<base64 body>' | python3 ngs_cipher.py
"""

import base64
import json
import sys
import zlib

GZIP_MAGIC = b"\x1f\x8b"
GZIP_CM = 0x08  # deflate; gzip byte[2] is always 0x08 -> our key anchor


def _as_raw(data):
    """Accept raw bytes, or base64 str/bytes as seen on the wire."""
    if isinstance(data, str):
        data = data.strip().encode()
    try:
        return base64.b64decode(data, validate=True)
    except Exception:
        return bytes(data)


def recover_key(raw: bytes) -> int:
    """K = C[2] XOR 0x08  (gzip CM byte is always 0x08)."""
    if len(raw) < 3:
        raise ValueError("body too short")
    return raw[2] ^ GZIP_CM


def decrypt_response(data, want="bytes"):
    """
    Decrypt an NGS-X response body. `data` may be raw bytes or the base64 text
    straight off the wire. Returns gunzipped plaintext (JSON) bytes, or a dict
    if want='json'.
    """
    raw = _as_raw(data)
    K = recover_key(raw)
    xored = bytes(c ^ K for c in raw)
    gz = GZIP_MAGIC + xored[2:]
    plain = zlib.decompress(gz, 16 + zlib.MAX_WBITS)  # CRC-validated
    if want == "json":
        return json.loads(plain)
    return plain


# Backwards-compatible alias (older scripts imported `decrypt`)
def decrypt(data):
    try:
        return decrypt_response(data)
    except Exception as e:
        return b"<<decrypt-fail " + str(e).encode() + b">>"


def encrypt_response(plain_bytes: bytes, key: int, header2: bytes = b"\x00\x00") -> bytes:
    """
    Re-encrypt a (possibly modified) plaintext into a wire body, so a MITM addon
    can rewrite responses. gzip(plain) then single-byte XOR; the first two output
    bytes carry `header2` (any value -- the client only uses C[2:]). Returns
    base64 text ready for the wire. Any key 1..255 decrypts correctly because K
    is self-describing via C[2]^0x08.
    """
    import gzip
    import io
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as f:
        f.write(plain_bytes)
    gz = buf.getvalue()                 # 1f 8b 08 00 ...
    body = bytes(header2) + gz[2:]      # replace magic with 2-byte header
    out = bytes(c ^ key for c in body)
    return base64.b64encode(out)


if __name__ == "__main__":
    data = sys.stdin.read()
    try:
        plain = decrypt_response(data)
        try:
            print(json.dumps(json.loads(plain), indent=2))
        except Exception:
            sys.stdout.buffer.write(plain)
    except Exception as e:
        print(f"decrypt failed: {e}", file=sys.stderr)
        sys.exit(1)
