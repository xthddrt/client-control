"""Decode one game TCP connection, both directions, from its first byte.

Used live by the proxy and offline by `python -m traffic proxy-decode`.

- Handshake: the server speaks first, unencrypted: u16 length + body (19 bytes
  on channel servers, 52 on the login server). Two 4-byte windows of the body
  are the client's and the server's starting IVs; a window is used only when
  it fits the first frame header of that direction.
- Client->server: AES-OFB in blocks (transport.decrypt_body).
- Server->client: AES-OFB on the login server, iv[0] subtraction on channel
  servers; the decoder takes the one whose first frames all have opcodes below
  0x1000 (the other gives random 16-bit values) and records that choice.
- Client opcodes below 0xC7 go out as they are; the rest are renamed through
  the connection's table (inbound 0x32), so opcode = 0xC7 + table position.
- A connection that starts with a TLS ClientHello is recorded with its SNI.
"""

from __future__ import annotations

import struct

from .decode import tls_client_hello_sni
from .game import MAX_FRAME_BYTES
from .protocol import name_of, purpose_of
from .transport import (
    RECV_MASK,
    SEND_MASK,
    client_opcode,
    decrypt_body,
    decrypt_recv,
    get_new_iv,
    high_short,
    opcode_table,
    seed_iv,
)

SEED_WAIT_FRAMES = 8
CIPHER_CHECK_FRAMES = 4
PLAUSIBLE_OPCODE = 0x1000
LOGIN_HANDSHAKE_BYTES = 52   # the login server's handshake body; channel servers send 19
CIPHERS = {"aes_ofb": decrypt_body, "subtract_iv0": decrypt_recv}


class _Side:
    def __init__(self, direction, mask):
        self.direction = direction
        self.mask = mask
        self.buffer = bytearray()
        self.pending = []          # (w0, ciphertext, time_ns)
        self.iv = None
        self.key_source = None
        self.cipher = "aes_ofb" if direction == "client_to_server" else None
        self.cipher_evidence = None
        self.status = "waiting_for_key"
        self.index = 0

    def fits(self, iv, count):
        for w0, _, _ in self.pending[:count]:
            if (high_short(iv) ^ self.mask) != w0:
                return False
            iv = get_new_iv(iv)
        return True


class ConnectionDecoder:
    def __init__(self, header_search=False):
        # header_search tries all 65,536 seeds (about a second in Python): offline only,
        # for recordings that start mid-connection; a live connection has its handshake.
        self.header_search = header_search
        self.client = _Side("client_to_server", SEND_MASK)
        self.server = _Side("server_to_client", RECV_MASK)
        self.handshake = None
        self.handshake_state = "waiting"   # waiting / found / none
        self.table = None
        self.tls_sni = None

    # --- input -------------------------------------------------------------
    def feed(self, direction, data, time_ns):
        """Return the records completed by this data, in order."""
        out = []
        if direction == "server_to_client" and self.handshake_state == "waiting":
            self.server.buffer.extend(data)
            data = b""
            if self.client.buffer or self.client.pending:
                self.handshake_state = "none"
            elif len(self.server.buffer) >= 2:
                length = struct.unpack_from("<H", self.server.buffer, 0)[0]
                if not 8 <= length <= 0x200:
                    self.handshake_state = "none"
                elif len(self.server.buffer) >= 2 + length:
                    self.handshake = bytes(self.server.buffer[2:2 + length])
                    del self.server.buffer[:2 + length]
                    self.handshake_state = "found"
                    out.append({"kind": "handshake", "time_ns": time_ns, "length": length,
                                "body_hex": self.handshake.hex()})
        elif direction == "client_to_server" and self.handshake_state == "waiting":
            self.handshake_state = "none"   # the client spoke first: not a game connection start
            if data[:1] == b"\x16" and data[1:2] == b"\x03":
                self.tls_sni = tls_client_hello_sni(data)
                for side in (self.client, self.server):
                    side.status = "tls"
                out.append({"kind": "tls_client_hello", "time_ns": time_ns, "sni": self.tls_sni})
        side = self.client if direction == "client_to_server" else self.server
        if side.status not in ("waiting_for_key", "decrypting"):
            return out
        side.buffer.extend(data)
        if direction == "server_to_client" and self.handshake_state == "waiting":
            return out
        return out + self._frames(side, time_ns)

    # --- framing and keys ---------------------------------------------------
    def _frames(self, side, time_ns):
        out = []
        while len(side.buffer) >= 4:
            w0, w1 = struct.unpack_from("<HH", side.buffer, 0)
            length = w0 ^ w1
            if length < 2 or length > MAX_FRAME_BYTES:
                side.status = "not_game_framing"
                return out + [self._notice(side, time_ns, f"declared frame length {length}")]
            if length >= 0xFF00 and side.iv is not None:
                # 0x75d970 treats bodies over 0xff00 specially; their header is not known yet
                side.status = "large_frame_unsupported"
                return out + [self._notice(side, time_ns, f"frame of {length} bytes or more")]
            if len(side.buffer) < 4 + length:
                break
            side.pending.append((w0, bytes(side.buffer[4:4 + length]), time_ns))
            del side.buffer[:4 + length]
        if side.iv is None and side.pending:
            self._find_key(side)
            if side.status != "waiting_for_key":
                return out + [self._notice(side, time_ns, f"{len(side.pending)} frames held")]
        if side.iv is not None and side.cipher is None:
            self._choose_cipher(side)
            if side.status != "waiting_for_key":
                return out + [self._notice(side, time_ns, f"{len(side.pending)} frames held")]
        if side.iv is None or side.cipher is None:
            return out
        side.status = "decrypting"
        for w0, ciphertext, frame_time in side.pending:
            if (high_short(side.iv) ^ side.mask) != w0:
                side.status = "iv_desync"
                out.append(self._notice(side, frame_time, f"frame {side.index} header {w0:#06x}"))
                break
            out.extend(self._message(side, CIPHERS[side.cipher](side.iv, ciphertext), frame_time))
            side.iv = get_new_iv(side.iv)
            side.index += 1
        side.pending = []
        return out

    def _find_key(self, side):
        windows = []
        if self.handshake:
            windows = [self.handshake[i:i + 4] for i in range(len(self.handshake) - 3)]
        fits = {iv for iv in windows if side.fits(iv, 1)}
        if len(fits) > 1:   # several windows fit the first header: the second one decides
            fits = {iv for iv in fits if side.fits(iv, 2)} if len(side.pending) >= 2 else fits
        if len(fits) == 1:
            side.iv, side.key_source = fits.pop(), "handshake"
            return
        if len(fits) > 1:
            if len(side.pending) >= 2:
                side.status = "ambiguous_key"
            return
        if not self.header_search:
            if self.handshake_state != "waiting":
                side.status = "no_key"
            return
        if len(side.pending) < 2:
            return
        fits = [iv for iv in seed_iv(side.pending[0][0], side.pending[1][0], side.mask)
                if side.fits(iv, SEED_WAIT_FRAMES)]
        if len(fits) == 1:
            side.iv, side.key_source = fits[0], "header_search"
        elif not fits:
            side.status = "no_key"
        elif len(side.pending) >= SEED_WAIT_FRAMES:
            side.status = "ambiguous_key"

    def _choose_cipher(self, side):
        frames = side.pending[:CIPHER_CHECK_FRAMES]
        passing = []
        for name, function in CIPHERS.items():
            iv, ok = side.iv, True
            for _, ciphertext, _ in frames:
                body = function(iv, ciphertext)
                if len(body) < 2 or struct.unpack_from("<H", body, 0)[0] >= PLAUSIBLE_OPCODE:
                    ok = False
                    break
                iv = get_new_iv(iv)
            if ok:
                passing.append(name)
        if len(passing) == 1 and len(frames) >= 2:
            side.cipher = passing[0]
            side.cipher_evidence = f"only cipher with opcodes below 0x1000 in the first {len(frames)} frames"
        elif not passing:
            side.status = "cipher_unknown"
        elif len(frames) >= CIPHER_CHECK_FRAMES:
            side.status = "cipher_ambiguous"

    # --- records ------------------------------------------------------------
    def _message(self, side, body, time_ns):
        wire = struct.unpack_from("<H", body, 0)[0]
        record = {"kind": "message", "direction": side.direction, "index": side.index,
                  "time_ns": time_ns, "length": len(body)}
        out = [record]
        if side is self.client:
            opcode, source = client_opcode(wire, self.table)
            if opcode is None and self.table is None and len(self.handshake or b"") == LOGIN_HANDSHAKE_BYTES:
                # the login server sends no opcode table; its client opcodes match the static builders as they
                # are (0x2e7 at 6 bytes, 0x1ef at 22: 2/2, docs/reference/sign-in.md)
                opcode, source = wire, "login_server_not_renamed"
            record["wire_opcode"] = f"0x{wire:04x}"
        else:
            opcode, source = wire, "server_opcodes_are_not_renamed"
            table = opcode_table(body)
            if table is not None:
                self.table = table
                out.append({"kind": "opcode_table", "time_ns": time_ns, "entries": len(table),
                            "message_index": side.index})
        name, confidence = name_of(side.direction, opcode)
        record.update({
            "opcode": f"0x{opcode:x}" if opcode is not None else None,
            "opcode_source": source,
            "name": name, "name_confidence": confidence, "purpose": purpose_of(side.direction, opcode)[0],
            "iv": side.iv.hex(), "key_source": side.key_source, "cipher": side.cipher,
            "body_hex": body.hex(),
        })
        return out

    def _notice(self, side, time_ns, detail):
        return {"kind": "decode_notice", "time_ns": time_ns, "direction": side.direction,
                "status": side.status, "detail": detail}

    def summary(self):
        return {
            "handshake": self.handshake_state,
            "tls_sni": self.tls_sni,
            "opcode_table_entries": len(self.table) if self.table else None,
            **{side.direction: {"messages": side.index, "status": side.status,
                                "key_source": side.key_source, "cipher": side.cipher,
                                "cipher_evidence": side.cipher_evidence}
               for side in (self.client, self.server)},
        }
