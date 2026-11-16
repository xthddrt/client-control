"""Field parsers for game messages whose layouts were worked out.

    from traffic.fields import parse
    parse("C", 0x9c, body)   # -> {"debug_registers": [0, 0, 0, 0, 0, 0], ...} or None (no parser)

`body` is the whole decoded body, the two opcode bytes included (for client messages they are the
wire value, not the opcode); parsing starts after them. Every parser names the doc that explains the
layout (DOCS). Bytes a parser does not read come back as "unparsed_hex"; a body too short for its
layout gives "parse_error": nothing is guessed.
"""

from __future__ import annotations

import struct

ORIGINS = "docs/reference/client-message-origins.md"
SERVER = "docs/reference/server-messages.md"
SIGN_IN = "docs/reference/sign-in.md"

MARKER = 123456789          # C 0x9c's section separator
GOLDEN = 0x9E3779B9         # C 0x9c mixes the copied range's address with it
MASK32 = 0xFFFFFFFF


def _crc_table():
    """The MSB-first CRC-32 table (poly 0x04C11DB7) the client keeps at RVA 0x3b72360."""
    table = []
    for i in range(256):
        c = i << 24
        for _ in range(8):
            c = ((c << 1) ^ 0x04C11DB7) & MASK32 if c & 0x80000000 else (c << 1) & MASK32
        table.append(c)
    return table


CRC_TABLE = _crc_table()


def crc32_msb(data, crc=0):
    """MSB-first CRC-32, init 0, no final XOR: the client's checksum (C 0x77, C 0x70 subtype 1)."""
    for byte in data:
        crc = ((crc << 8) & MASK32) ^ CRC_TABLE[(crc >> 24) ^ byte]
    return crc


_COUNTER_OF_CRC = None


def send_counter(crc):
    """C 0x70 subtype 1: the u16 send counter whose crc32_msb is this value, else None."""
    global _COUNTER_OF_CRC
    if _COUNTER_OF_CRC is None:
        _COUNTER_OF_CRC = {crc32_msb(struct.pack("<H", k)): k for k in range(65536)}
    return _COUNTER_OF_CRC.get(crc)


def unscramble_debug_registers(f1, f2, f3, f4, f5):
    """Dr0-Dr3 from the five scrambled values of C 0x9c and C 0x70 subtypes 1/2 (random r = f1 ^ T[0x1b])."""
    t, r = CRC_TABLE, f1 ^ CRC_TABLE[0x1B]
    return [f2 ^ t[0x7F] ^ r, f3 ^ t[6] ^ r, ((f4 + t[4]) & MASK32) ^ r, ((f5 - t[0xD2]) & MASK32) ^ r]


def scramble_debug_registers(dr, r):
    """The client's side of unscramble_debug_registers (for tests)."""
    t = CRC_TABLE
    return [r ^ t[0x1B], dr[0] ^ r ^ t[0x7F], dr[1] ^ r ^ t[6], ((dr[2] ^ r) - t[4]) & MASK32,
            ((dr[3] ^ r) + t[0xD2]) & MASK32]


def process_scan_status(key, length, value):
    """C 0x9c section 5 (0xd070d0): 0 = no scan this time, 1 = all processes scanned, 2 = none could be opened."""
    status = ((((value ^ key) - 0xD9B30E6C + key - 0xD9B30E6B + (key >> 6)) & MASK32) ^ 0xA0A0B0B0)
    return length ^ key, status


class Reader:
    def __init__(self, body):
        self.body, self.at = body, 2

    def _take(self, fmt):
        value = struct.unpack_from(fmt, self.body, self.at)[0]
        self.at += struct.calcsize(fmt)
        return value

    def u8(self): return self._take("<B")
    def u16(self): return self._take("<H")
    def u32(self): return self._take("<I")
    def i32(self): return self._take("<i")
    def u64(self): return self._take("<Q")
    def f64(self): return self._take("<d")

    def raw(self, n):
        if self.at + n > len(self.body):
            raise struct.error(f"{n} bytes at {self.at}, body has {len(self.body)}")
        value = self.body[self.at:self.at + n]
        self.at += n
        return value

    def str(self):
        return self.raw(self.u16()).decode("latin-1")

    def marker(self):
        value = self.u32()
        if value != MARKER:
            raise struct.error(f"expected marker 123456789 at {self.at - 4}, got {value}")

    def until_marker(self):
        end = self.body.find(struct.pack("<I", MARKER), self.at)
        if end < 0:
            raise struct.error(f"no marker after {self.at}")
        value = self.raw(end - self.at)
        self.at += 4
        return value

    def rest(self):
        return self.raw(len(self.body) - self.at)


PARSERS = {}   # (side, opcode) -> parser(Reader) -> dict
DOCS = {}      # (side, opcode) -> where the layout is explained


def parser(side, opcodes, doc):
    def register(function):
        for opcode in opcodes:
            PARSERS[(side, opcode)] = function
            DOCS[(side, opcode)] = doc
        return function
    return register


def parse(side, opcode, body):
    """Fields of one message as a dict, or None when no parser exists for (side 'C'/'S', opcode)."""
    function = PARSERS.get((side, opcode))
    if function is None:
        return None
    reader = Reader(body)
    try:
        out = function(reader)
    except (struct.error, UnicodeDecodeError) as error:
        return {"parse_error": str(error)}
    if reader.at < len(body):
        out["unparsed_hex"] = body[reader.at:].hex()
    return out


# --- the 10-second check --------------------------------------------------------------------------

@parser("S", [0x1B], f"{ORIGINS}: C 0x9c answers S 0x1b")
def _s_1b(r):
    return {"checksum_address": r.u64(), "checksum_length": r.u32(), "tag": r.u32(),
            "copy_address": r.u64(), "copy_length": r.u32(), "flag": r.u8(), "one": r.u8(),
            "challenge": r.u64(), "previous_challenge": r.u64()}


@parser("C", [0x9C], f"{ORIGINS}: C 0x9c answers S 0x1b")
def _c_9c(r):
    out = {"version": r.u32()}
    r.marker()
    out.update(shift_key=r.u16(), protected_u64=r.u64(), checksum=r.u32())
    r.marker()
    out.update(tag=r.u32(), copy_address=r.u64(), copy_length=r.u32())
    out["copy_hex"] = r.raw(out["copy_length"]).hex()
    out["copy_address_echo"] = r.u64() ^ GOLDEN
    r.marker()
    out["flag_section_hex"] = r.until_marker().hex()
    scrambled = [r.u32() for _ in range(5)]
    out["debug_registers"] = unscramble_debug_registers(*scrambled) + [r.u32(), r.u32()]   # Dr0-3, Dr6, Dr7
    r.marker()
    scan = r.until_marker()
    if len(scan) == 12:
        out["process_scan_length"], out["process_scan_status"] = process_scan_status(*struct.unpack("<III", scan))
    else:
        out["process_scan_hex"] = scan.hex()
    # client_challenge comes back as the next S 0x1b previous_challenge; challenge_answer is from protected code
    out.update(chain_flag=r.u8(), challenge_answer=r.u64(), client_challenge=r.u64(), socket_value=r.u32(),
               input_events_a=r.u32(), input_events_b=r.u32(), counter_42ec=r.u32())
    return out


# --- C 0x70 client_context_report ---------------------------------------------------------------

@parser("C", [0x70], f"{ORIGINS}: C 0x70 client_context_report")
def _c_70(r):
    subtype = r.u8()
    out = {"subtype": subtype}
    if subtype in (1, 2):
        out.update(version=r.u32(), a=r.u32(), a_again=r.u32(), two=r.u32())
        if subtype == 1:
            out["zero"] = r.u8()   # subtype 2 (47 bytes) has no such byte
        out["debug_registers"] = unscramble_debug_registers(*[r.u32() for _ in range(5)]) + [r.u32(), r.u32()]
        if subtype == 1:
            out["send_counter"] = send_counter(out["a"])   # sent when counter % 31 == 0
    elif subtype == 4:
        out["value"] = r.u32()
    elif subtype == 5:
        out.update(game_clock_ms=r.u32(), frame_counter=r.u32())
    elif subtype == 13:
        out.update(uuid=r.str(), zero=r.u8())
    return out


@parser("S", [0x20], f"{ORIGINS}: C 0x70 client_context_report")
def _s_20(r):
    return {"request": r.u8()}   # 5 -> C 0x70 subtype 5, 0x0c -> subtype 13


# --- the 6-minute chain --------------------------------------------------------------------------

@parser("C", [0x407], f"{ORIGINS}: C 0x407 / S 0x381")
def _c_407(r):
    out = {"new_value": r.u32(), "v2_low16": r.u16(), "unknown_6_10": r.raw(5).hex(), "v2_bits16_23": r.u8(),
           "unknown_12": r.u8(), "check": r.u8(), "tail": r.u32()}
    out["previous_v2_low24"] = out["v2_low16"] | out["v2_bits16_23"] << 16   # = previous S 0x381 v2 & 0xffffff
    return out


@parser("S", [0x381], f"{ORIGINS}: C 0x407 / S 0x381")
def _s_381(r):
    return {"v1": r.u32(), "zero_1": r.u32(), "v2": r.u32(), "zero_2": r.u32()}


# --- answers to server questions ----------------------------------------------------------------

RESOLUTION_MODES = {1: "800x600", 2: "1024x768", 3: "1366x768", 4: "1280x720", 5: "1920x1080", 6: "1920x1200"}


@parser("C", [0x161], f"{ORIGINS}: Channel entry, map loads and sign-in (C 0x161)")
def _c_161(r):
    mode, first, second = r.u16(), r.u32(), r.u32()
    return {"mode": mode, "mode_name": RESOLUTION_MODES.get(mode), "width": first // 10000,
            "height": first % 10000, "second_matches": second == first}


@parser("S", [0x165], f"{SERVER}: Your own character and map loads (S 0x165)")
def _s_165(r):
    return {"value": r.i32()}   # C 0x177 follows only when the client's own value differs


@parser("C", [0x177], f"{ORIGINS}: Channel entry, map loads and sign-in (C 0x177)")
def _c_177(r):
    return {"value": r.i32()}


@parser("C", [0xBA], f"{ORIGINS}: C 0xba input_idle_flag")
def _c_ba(r):
    return {"input": r.u8()}   # 0 = no input for 5 s, 1 = input again


# --- channel entry and the world -------------------------------------------------------------------

@parser("S", [0x5F5], f"{SERVER}: Channel entry (S 0x5f5)")
def _s_5f5(r):
    presets = []
    for _ in range(4):
        presets.append("default" if r.u8() else [(r.u8(), r.u32()) for _ in range(89)])
    out = {"presets": presets, "bound_keys": [sum(1 for t, a in p if t or a) if p != "default" else None
                                              for p in presets]}
    if r.u8():
        out["quick_slots"] = [r.u32() for _ in range(32)]
    return out


@parser("S", [0x2B9], f"{SERVER}: World (S 0x2b9)")
def _s_2b9(r):
    out = {"character_id": r.u32(), "effect": r.u8()}
    if out["effect"] == 1:   # skill use; other types are not laid out
        out.update(skill_id=r.u32(), user_level=r.u32(), skill_level=r.u32())
    return out


@parser("S", [0x472], f"{SERVER}: World (S 0x472)")
def _s_472(r):
    out = {"drop_id": r.u32(), "how": r.u8()}
    if out["how"] == 2:
        out["picker_id"] = r.u32()
    return out


# --- reports --------------------------------------------------------------------------------------

DECOY_OPCODES = (0x1EF, 0x1F9, 0x1FA, 0x202)


@parser("C", DECOY_OPCODES, f"{ORIGINS}: C 0x1ef event_report; C 0x1f9 / 0x1fa / 0x202 decoy_report")
def _c_1ef(r):
    kind = r.u32()
    out = {"kind": kind}
    if kind == 1:
        out["skills"] = [(r.u32(), r.u32(), r.u32()) for _ in range(r.u32())]   # id, level, check
    elif kind == 2:
        out["records"] = [(r.u32(), r.u32()) for _ in range(r.u32())]          # id, check2
    elif kind == 0x27:
        out.update(counter=r.u64(), zero=r.u32(), value=r.u32())
    elif kind == 0x52:
        out["equipment"] = [(r.u32(), r.u64()) for _ in range(r.u32())]        # slot, item id
    elif kind == 0x76:
        out["cheat_engine_found"] = r.u8()
    elif kind == 0x20:
        out["values"] = [r.u32() for _ in range(3)]
    elif kind == 0x3F:   # the real C 0x1f9 (builder 0xd0f800); the doc had not seen it yet
        out["first"] = r.u64()
        out["entries"] = [[r.u64() for _ in range(6)] for _ in range(r.u32())]
    elif kind == 0x65:
        out.update(a=r.u32(), b=r.u32())
        out["decoy"] = len(r.body) == 14 and out["a"] < 10 and out["b"] < 15
    return out


@parser("C", [0x13F], f"{ORIGINS}: C 0x13f sent_packet_counter")
def _c_13f(r):
    out = {"reset": r.u8()}
    out["built"] = [(r.u32(), [(r.u32(), r.u32()) for _ in range(r.u32())]) for _ in range(r.u32())]
    out["sent"] = [(r.u32(), r.u32()) for _ in range(r.u32())]   # opcode, count (SendPacket's own count)
    return out


@parser("C", [0x1A7], f"{ORIGINS}: C 0x1a7 skill_check_report")
def _c_1a7(r):
    return {"skills": [(r.u32(), r.u32()) for _ in range(r.u32())],
            "checked": [(r.u32(), r.u32(), r.u32()) for _ in range(r.u32())]}   # id, level, check


@parser("C", [0xBE], f"{ORIGINS}: C 0xbe hourly_activity_summary")
def _c_be(r):
    return {"one": r.u32(), "minutes": r.u32(), "active_minutes": r.u32(), "place_bucket": r.u32()}


@parser("C", [0x1C3], f"{ORIGINS}: C 0x1c3 own_character_report")
def _c_1c3(r):
    return {"character_id": r.u32(), "character_name": r.str()}


@parser("C", [0x1F3], f"{ORIGINS}: C 0x1f3 key_sequence_fingerprint")
def _c_1f3(r):
    return {"subtype": r.u32(), "sequences": [(r.u32(), r.str()) for _ in range(r.u32())]}   # key-code XOR, MD5


# --- join logs (one burst C 0x421, 0x420, 0x41f, 0x422 after S 0x194) ----------------------------------

@parser("S", [0x194], f"{ORIGINS}: Join logs C 0x421, 0x420, 0x41f, 0x422, then C 0x425")
def _s_194(r):
    return {"log_id": r.str()}


@parser("C", [0x421], f"{ORIGINS}: Join logs C 0x421, 0x420, 0x41f, 0x422, then C 0x425")
def _c_421(r):
    return {"kind": r.u32(), "log_id_and_counter": r.str()}   # S 0x194's log id + a counter


@parser("C", [0x41F, 0x420, 0x422], f"{ORIGINS}: Join logs C 0x421, 0x420, 0x41f, 0x422, then C 0x425")
def _c_join_log(r):
    # the shared header (0x512580); what follows differs per opcode and is left unparsed
    return {"time": r.str(), "world": r.u32(), "account": r.u32(), "id": r.u32(), "small_value": r.u32(),   # 9 or 5
            "character_name": r.str(), "zero_1": r.u32(), "kind": r.u32(), "zero_2": r.u32(), "zero_3": r.u32(),
            "tag": r.str(), "minus_one": r.i32(), "zero_4": r.u8()}   # kind 1 first channel, 3 timer


# --- sign-in ------------------------------------------------------------------------------------

@parser("S", [0x44], f"{SIGN_IN}: Server messages (S 0x44)")
def _s_44(r):
    out = {"world_id": r.u32()}
    out["channels"] = [(r.u8(), r.u8()) for _ in range(r.u32())]   # index, flag
    out["load"] = [(r.u32(), r.u8()) for _ in range(r.u8())]       # load, state
    return out


@parser("C", [0x75], f"{SIGN_IN}: Client messages (C 0x75)")
def _c_75(r):
    return {"zero": r.u8(), "world_id": r.u32(), "account_string_set": r.u8(), "cached_setting": r.u8()}


def brief(fields, width=200):
    """One line of fields for a listing; long lists shown by their length."""
    parts = []
    for key, value in fields.items():
        if isinstance(value, list) and len(str(value)) > 60:
            value = f"[{len(value)} items]"
        elif isinstance(value, int) and value > 0xFFFF and key not in ("width", "height"):
            value = hex(value)
        parts.append(f"{key}={value}")
    line = " ".join(parts)
    return line if len(line) <= width else line[:width - 3] + "..."
