"""MapleStory transport cipher: IV roll, frame seed search, AES-256-OFB body."""

from __future__ import annotations

import importlib.util
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


def decrypt_body(iv4, body, start_layer):
    stream = keystream(iv4, len(body), start_layer)
    return bytes(left ^ right for left, right in zip(body, stream))


def decrypt_recv(iv4, body):
    """Inbound body is a single-byte XOR with iv[0] in the observed build."""
    key = iv4[0]
    return bytes(byte ^ key for byte in body)


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
