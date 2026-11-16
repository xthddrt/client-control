"""MapleStory transport cipher: IV roll, frame seed search, frame bodies, opcode table.

Read from the client's own code (MapleStory.exe build 0x6AEB667B):
- 0x75d970 transforms a body in blocks: the first min(len, 1456) bytes (4 fewer
  when the body is over 0xff00), then 1460 at a time; each block starts again
  from the frame's IV.
- Mode 1 (0x140cea430) is AES-256-OFB from the IV repeated four times: client
  sends, and the login server's replies.
- Mode 2 (0x140763a70) subtracts iv[0] from every byte: channel server replies.
- The channel server's opcode table (inbound 0x32) is DES-EDE2 ECB with the
  16-byte key at .rdata 0x34d3ee8 (code 0x166d411).
"""

from __future__ import annotations

import importlib.util
import struct
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

FOUNDATIONS = Path(__file__).resolve().parent.parent / "foundations"
STATIC_KEY = bytes.fromhex("0f0000001b000000c500000046000000f3000000be000000ff00000075000000")
SEND_MASK = 0x00DF
RECV_MASK = 0xFFFE


def _load_transport():
    path = FOUNDATIONS / "transport-cipher.py"
    spec = importlib.util.spec_from_file_location("traffic_transport_cipher", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


transport_cipher = _load_transport()
SHUFFLE_TABLE = transport_cipher._load_shuffle_table(FOUNDATIONS / "transport-shuffle-table.bin")
_CIPHER = Cipher(algorithms.AES(STATIC_KEY), modes.ECB())


def _encrypt_block(block):
    encryptor = _CIPHER.encryptor()
    return encryptor.update(block) + encryptor.finalize()


def high_short(iv):
    return (iv[3] << 8) | iv[2]


def get_new_iv(iv):
    return transport_cipher.getNewIv(iv, SHUFFLE_TABLE)


def keystream(iv4, length, start_layer):
    block = _encrypt_block(bytes(iv4) * 4)
    if start_layer:
        block = _encrypt_block(block)
    out = bytearray()
    while len(out) < length:
        out.extend(block)
        block = _encrypt_block(block)
    return bytes(out[:length])


def _blocks(length):
    first = min(length, 0x5B0) - (4 if length > 0xFF00 else 0)
    sizes = [first] if length else []
    left = length - first
    while left > 0:
        sizes.append(min(left, 0x5B4))
        left -= sizes[-1]
    return sizes


def decrypt_body(iv4, body, start_layer=0):
    """AES-OFB body (mode 1); the keystream restarts from the IV at every block."""
    stream = b"".join(keystream(iv4, size, start_layer) for size in _blocks(len(body)))
    return bytes(left ^ right for left, right in zip(body, stream))


def decrypt_recv(iv4, body):
    """Channel server reply body (mode 2): each byte minus iv[0]."""
    key = iv4[0]
    return bytes((byte - key) & 0xFF for byte in body)


OPCODE_TABLE_KEY = b"G0dD@mnN#H@ckEr!"
OPCODE_TABLE_BASE = 0xC7   # table entry i is the wire value of client opcode 0xC7 + i


def opcode_table(body):
    """Decrypt inbound 0x32 (u32 size + DES-EDE2 ECB text "n|v1|v2|...") to {wire value: opcode}, else None."""
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES

    if len(body) < 14 or struct.unpack_from("<I", body, 2)[0] != len(body) - 6 or (len(body) - 6) % 8:
        return None
    key = OPCODE_TABLE_KEY + OPCODE_TABLE_KEY[:8]   # DES-EDE2 as a 24-byte EDE3 key
    decryptor = Cipher(TripleDES(key), modes.ECB()).decryptor()
    # the text ends at its first NUL; the padding after it is not always zero (2026-11-15: 8 of 52 tables)
    text = (decryptor.update(body[6:]) + decryptor.finalize()).split(b"\0", 1)[0]
    try:
        values = [int(item) for item in text.decode("ascii").split("|")]
    except (UnicodeDecodeError, ValueError):
        return None
    if not values or values[0] != len(values) - 1:
        return None
    return {wire: OPCODE_TABLE_BASE + index for index, wire in enumerate(values[1:])}


def client_opcode(wire, table):
    """Real client opcode for a wire value: below 0xC7 sent as is, else its table position."""
    if wire < OPCODE_TABLE_BASE:
        return wire, "unmapped_range"
    if table is None:
        return None, "no_table"
    if wire not in table:
        return None, "not_in_table"
    return table[wire], "connection_table"


def seed_iv(w0, w1, mask=SEND_MASK):
    """Return all IVs that satisfy two consecutive frame headers."""
    i2 = (w0 ^ mask) & 0xFF
    i3 = ((w0 ^ mask) >> 8) & 0xFF
    result = []
    for a in range(256):
        for b in range(256):
            iv = bytes([a, b, i2, i3])
            if (high_short(get_new_iv(iv)) ^ mask) == w1:
                result.append(iv)
    return result
