"""Every game message of one or more proxy recordings, in order, with its real opcode.

    from traffic.timeline import messages
    for m in messages(["captures/proxy-<stamp>.jsonl"]):
        print(m.time_ns, m.label, m.name, m.body[:8].hex())

Reads the `message` records the proxy (traffic/proxy.py) wrote; raw `data` lines are skipped
without parsing, so a 500 MB recording takes a few seconds. Client opcodes the recording left
unresolved are resolved here the way traffic/stream.py does it now: through the connection's own
S 0x32 opcode table, or, on the login server (52-byte handshake, no table), as they are on the
wire. Names and purpose groups are traffic/protocol.py's current ones, not the ones stored in the
recording when it was made. Re-decode an old recording first (`python -m traffic proxy-decode`)
when its connections were never decoded at all.
"""

from __future__ import annotations

import json
from typing import NamedTuple

from .protocol import NAMES, PURPOSE
from .stream import LOGIN_HANDSHAKE_BYTES
from .transport import client_opcode, opcode_table

SIDE = {"client_to_server": "C", "server_to_client": "S"}


class Message(NamedTuple):
    path: str
    conn: int
    time_ns: int
    side: str            # "C" client to server, "S" server to client
    opcode: int | None   # None: a client opcode no table resolves
    length: int
    body_hex: str        # the whole body, opcode included (fields offsets count from it)

    @property
    def body(self):
        return bytes.fromhex(self.body_hex)

    @property
    def connection(self):
        """(recording, conn): conn numbers restart in every recording."""
        return self.path, self.conn

    @property
    def label(self):
        return f"{self.side} " + (f"0x{self.opcode:x}" if self.opcode is not None else "?")

    @property
    def name(self):
        entry = NAMES.get((self.side, self.opcode))
        return entry[0] if entry else None

    @property
    def purpose(self):
        return PURPOSE.get((self.side, self.opcode), (None,))[0]


def parse_type(text):
    """'C:0x9c', 'C 0x9c' or 'c9c' -> ("C", 0x9c)."""
    text = text.strip().replace(":", " ")
    side, number = (text.split() + [""])[:2] if " " in text else (text[:1], text[1:])
    if side.upper() not in ("C", "S") or not number:
        raise ValueError(f"message type {text!r}: expected C:0x.. or S:0x..")
    return side.upper(), int(number, 16)


def messages(paths):
    """Yield a Message for every decoded game message of the recordings, file by file, in file order."""
    for path in paths:
        tables, login = {}, set()
        with open(path, encoding="utf-8", errors="replace") as source:
            for line in source:
                if line.startswith('{"kind":"data"'):
                    continue
                if line.startswith('{"kind":"handshake"'):
                    record = json.loads(line)
                    if record["length"] == LOGIN_HANDSHAKE_BYTES:
                        login.add(record["conn"])
                    continue
                if not line.startswith('{"kind":"message"'):
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:   # the last line of a recording still being written
                    continue
                conn, side = record["conn"], SIDE[record["direction"]]
                body_hex = record.get("body_hex") or ""
                opcode = int(record["opcode"], 16) if record.get("opcode") else None
                if side == "S" and opcode == 0x32:
                    tables[conn] = opcode_table(bytes.fromhex(body_hex))
                if opcode is None and record.get("wire_opcode"):
                    wire = int(record["wire_opcode"], 16)
                    opcode = client_opcode(wire, tables.get(conn))[0]
                    if opcode is None and tables.get(conn) is None and conn in login:
                        opcode = wire   # login server: no table, opcodes as they are (stream.py)
                yield Message(path, conn, record["time_ns"], side, opcode, record["length"], body_hex)


def by_connection(stream):
    """{(recording, conn): [Message, ...]} in time order."""
    out = {}
    for m in stream:
        out.setdefault(m.connection, []).append(m)
    for items in out.values():
        items.sort(key=lambda m: m.time_ns)
    return out
