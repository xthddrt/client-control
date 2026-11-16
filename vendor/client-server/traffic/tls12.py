"""TLS 1.2 AES-GCM connections in proxy recordings: master-secret check, decryption, HTTP split.

The game's analytics library (NexonAnalytics64.dll, its own OpenSSL) negotiates TLS 1.2 with an
AES-GCM suite. With a connection's 48-byte master secret (read from the game's memory by
analysis/tls-memscan.py, found by analysis/tls-keys.py) every record of a recording
(captures/proxy-*.jsonl, traffic/proxy.py) can be decrypted. Keys are kept in the standard
SSLKEYLOGFILE format (`CLIENT_RANDOM <client random hex> <master secret hex>`, as Wireshark reads it).
The end of the file parses the upload's NDJSON records: csv lists, ETC_BU_CData memory dumps and the
Windows process list inside the first one (docs/guides/PROTOCOL.md, "Analytics").
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import hmac
import json
import os
import struct
import zlib
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .decode import tls_client_hello_sni

# AES-GCM cipher suites (RFC 5288/5289): AES key length, PRF hash.
SUITES = {0x009c: (16, hashlib.sha256), 0x009d: (32, hashlib.sha384),
          0xc02b: (16, hashlib.sha256), 0xc02c: (32, hashlib.sha384),
          0xc02f: (16, hashlib.sha256), 0xc030: (32, hashlib.sha384)}
REPO = Path(__file__).resolve().parent.parent


def records(chunks):
    """[(time_ns, bytes)] of one direction -> [(time_ns, type, version, body)]; a trailing partial record is left out."""
    buf, out = b"", []
    for time_ns, data in chunks:
        buf += data
        while len(buf) >= 5:
            n = struct.unpack_from(">H", buf, 3)[0]
            if len(buf) < 5 + n:
                break
            out.append((time_ns, buf[0], buf[1:3], buf[5:5 + n]))
            buf = buf[5 + n:]
    return out


def read_recording(path, sni=None):
    """{conn: {"c2s": [(time_ns, bytes)], "s2c": [...], "closed": bool}} for the recording's TCP 443
    connections (only those whose ClientHello names `sni`, when given)."""
    conns, other = {}, set()
    with open(path, encoding="utf-8") as f:
        for line in f:
            if '"kind":"data"' in line:
                r = json.loads(line)
                conn = conns.get(r["conn"])
                if conn is None:
                    continue
                data = bytes.fromhex(r["hex"])
                if r["direction"] == "client_to_server":
                    # shortcut: a ClientHello split over two reads keeps the connection, whatever its name
                    if sni and not conn["c2s"] and tls_client_hello_sni(data) not in (sni, None):
                        del conns[r["conn"]]
                        other.add(r["conn"])
                        continue
                    conn["c2s"].append((r["time_ns"], data))
                else:
                    conn["s2c"].append((r["time_ns"], data))
            elif '"kind":"connection_open"' in line:
                r = json.loads(line)
                if r["destination"][1] == 443:
                    conns[r["conn"]] = {"c2s": [], "s2c": [], "closed": False}
            elif '"kind":"connection_close"' in line:
                r = json.loads(line)
                if r["conn"] in conns:
                    conns[r["conn"]]["closed"] = True
    return conns


def session(conn):
    """Randoms, session id, suite and the client's encrypted Finished record (or None if the
    handshake is incomplete or not TLS 1.2 AES-GCM)."""
    s = {}
    for _, kind, _, body in records(conn["c2s"]):
        if kind == 22 and body[:1] == b"\x01":
            s["client_random"] = body[6:38]
            break
    for _, kind, _, body in records(conn["s2c"]):
        if kind == 22 and body[:1] == b"\x02":
            s["server_random"] = body[6:38]
            sid = body[38]
            s["session_id"] = body[39:39 + sid]
            s["suite"] = struct.unpack_from(">H", body, 39 + sid)[0]
            break
    finished = encrypted(conn["c2s"])
    if len(s) < 4 or s["suite"] not in SUITES or not finished:
        return None
    s["finished"] = finished[0][1:]
    return s


def encrypted(chunks):
    """[(time_ns, type, version, body)] of the records after ChangeCipherSpec; the first is Finished (seq 0)."""
    recs = records(chunks)
    for i, rec in enumerate(recs):
        if rec[1] == 20:
            return recs[i + 1:]
    return []


def _p_hash(h, secret, seed, n):
    out, a = b"", seed
    while len(out) < n:
        a = hmac.new(secret, a, h).digest()
        out += hmac.new(secret, a + seed, h).digest()
    return out[:n]


def keys(master, s):
    """{"c2s": (key, salt), "s2c": (key, salt)} from the master secret (RFC 5246 6.3, RFC 5288 3)."""
    klen, h = SUITES[s["suite"]]
    kb = _p_hash(h, master, b"key expansion" + s["server_random"] + s["client_random"], 2 * klen + 8)
    return {"c2s": (kb[:klen], kb[2 * klen:2 * klen + 4]), "s2c": (kb[klen:2 * klen], kb[2 * klen + 4:])}


def open_record(key_salt, seq, kind, version, body):
    """Plaintext of one AES-GCM record; raises cryptography's InvalidTag if the key is wrong."""
    key, salt = key_salt
    aad = struct.pack(">Q", seq) + bytes([kind]) + version + struct.pack(">H", len(body) - 24)
    return AESGCM(key).decrypt(salt + body[:8], body[8:], aad)


def verify(master, s):
    """True if `master` decrypts the client's Finished record (the GCM tag proves the key)."""
    try:
        open_record(keys(master, s)["c2s"], 0, *s["finished"])
        return True
    except Exception:
        return False


def decrypt(conn, master, s=None):
    """{"c2s"/"s2c": [(time_ns, type, plaintext or None if it fails)]} after Finished."""
    s = s or session(conn)
    ks, out = keys(master, s), {}
    for d in ("c2s", "s2c"):
        out[d] = []
        for seq, (t, kind, version, body) in enumerate(encrypted(conn[d])):
            try:
                plain = open_record(ks[d], seq, kind, version, body)
            except Exception:
                plain = None
            if seq:
                out[d].append((t, kind, plain))
    return out


def read_keylog(path):
    """{client_random: master} from an SSLKEYLOGFILE (other line kinds are ignored)."""
    out = {}
    if os.path.exists(path):
        for line in open(path, encoding="ascii"):
            parts = line.split()
            if len(parts) == 3 and parts[0] == "CLIENT_RANDOM":
                out[bytes.fromhex(parts[1])] = bytes.fromhex(parts[2])
    return out


def private_file(path, mode="w"):
    """Open (create or truncate) a file only its owner can read, mode 600. Refuses paths in this
    repository except the git-ignored captures/, so keys and plaintext never reach git."""
    path = Path(path).resolve()
    if path.is_relative_to(REPO) and not path.is_relative_to(REPO / "captures"):
        raise SystemExit(f"{path}: secrets stay out of the repository; use captures/ or a folder outside it")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(fd, 0o600)
    return os.fdopen(fd, mode)


def http_messages(recs):
    """[(time_ns, type, plaintext)] of one direction -> [(time_ns, start line, {header: value}, body)]."""
    buf, start_t, out = b"", None, []
    for t, kind, plain in recs:
        if kind != 23 or plain is None:
            continue
        if not buf:
            start_t = t
        buf += plain
        while (end := buf.find(b"\r\n\r\n")) >= 0:
            head = buf[:end].decode("latin1").split("\r\n")
            hdr = {k.strip().lower(): v.strip() for k, _, v in (h.partition(":") for h in head[1:])}
            rest = buf[end + 4:]
            if "content-length" in hdr:
                n = int(hdr["content-length"])
                if len(rest) < n:
                    break
                body, buf = rest[:n], rest[n:]
            elif hdr.get("transfer-encoding", "").lower() == "chunked":
                body, pos, done = b"", 0, False
                while (eol := rest.find(b"\r\n", pos)) >= 0:
                    size = int(rest[pos:eol].split(b";")[0], 16)
                    if len(rest) < eol + 4 + size:
                        break
                    body += rest[eol + 2:eol + 2 + size]
                    pos = eol + 4 + size
                    if size == 0:
                        done = True
                        break
                if not done:
                    break
                buf = rest[pos:]
            else:
                body, buf = b"", rest
            enc = hdr.get("content-encoding", "").lower()
            if enc == "gzip":
                body = gzip.decompress(body)
            elif enc == "deflate":
                body = zlib.decompress(body)
            out.append((start_t, head[0], hdr, body))
            start_t = t
    return out


def ndjson(body):
    """The JSON records of a newline-delimited JSON body; a line that does not parse gives {"type": "<unparsed>"}."""
    for line in body.split(b"\n"):
        if line.strip():
            try:
                yield json.loads(line)
            except ValueError:
                yield {"type": "<unparsed>"}


def mask(v):
    """Printable shape of a value: strings keep their length and at most half (up to 4) of their
    characters, numbers under 100000 (codes, coordinates) are kept, longer numbers keep 4 digits,
    lists keep 3 items."""
    if isinstance(v, str):
        return v if len(v) <= 2 else f"{v[:min(4, len(v) // 2)]}…({len(v)})"
    if isinstance(v, bool) or v is None:
        return v
    if isinstance(v, (int, float)):
        return v if abs(v) < 100000 else f"{str(v)[:4]}…({len(str(v))}d)"
    if isinstance(v, list):
        return [mask(x) for x in v[:3]] + ([f"…+{len(v) - 3}"] if len(v) > 3 else [])
    if isinstance(v, dict):
        return {k: mask(x) for k, x in v.items()}
    return type(v).__name__


# The analytics upload's NDJSON records (docs/guides/PROTOCOL.md, "Analytics"). Field names of the
# comma-separated lists; NXLog_InputEventSequence names its own (mouseEventHeader "time,x,y,event,device").
CSV_FIELDS = {"ETC_MSMouseEvent": {"mousedatas": "age_ms,x,y,msg,extra1,extra2"},
              "ETC_MSInputEvent": {"keydatas": "time,vk,msg,state,count,x,y"}}


def csv_rows(kind, payload):
    """{list name: [{field: value}]} of a record's comma-separated lists."""
    lists = CSV_FIELDS.get(kind) or {k[:-6] + "s": v for k, v in payload.items() if k.endswith("EventHeader")}
    return {k: [dict(zip(h.split(","), e.split(","))) for e in payload.get(k, [])] for k, h in lists.items()}


def bu_dump(payload):
    """(object address, object bytes) of an ETC_BU_CData record: `bu_d` is base64(u64 LE address) | base64(bytes)."""
    ptr, raw = (base64.b64decode(x, validate=True) for x in payload["bu_d"].split("|"))
    return struct.unpack("<Q", ptr)[0], raw


def _utf16(buf, off, n):
    if n == 0 or n % 2 or not 0 <= off <= len(buf) - n:
        return None
    try:
        s = buf[off:off + n].decode("utf-16-le")
    except UnicodeDecodeError:
        return None
    return s if s.isprintable() else None


def _process(buf, o):
    nxt, threads = struct.unpack_from("<II", buf, o)
    nlen, nmax, name_ptr = struct.unpack_from("<HH4xQ", buf, o + 0x38)
    pid, ppid = struct.unpack_from("<QQ", buf, o + 0x50)
    return dict(offset=o, next=nxt, threads=threads, pid=pid, ppid=ppid, name_len=nlen, name_max=nmax,
                name_ptr=name_ptr, create_time=struct.unpack_from("<Q", buf, o + 0x20)[0],
                handles=struct.unpack_from("<I", buf, o + 0x60)[0], virtual_size=struct.unpack_from("<Q", buf, o + 0x78)[0],
                working_set=struct.unpack_from("<Q", buf, o + 0x90)[0], private=struct.unpack_from("<Q", buf, o + 0xc8)[0])


def process_snapshot(buf):
    """Entries of a Windows x64 SYSTEM_PROCESS_INFORMATION list (NtQuerySystemInformation class 5)
    copied somewhere inside `buf` (the first ETC_BU_CData dump holds one).

    Entry layout: u32 NextEntryOffset, u32 threads, +0x20 FILETIME create time, +0x38 UNICODE_STRING
    image name (u16 length, u16 max, pointer), +0x50 pid, +0x58 parent pid, +0x60 handles, +0x78 virtual
    size, +0x90 working set, +0xc8 private bytes, +0x100 threads x 0x50 bytes. The first entry whose name
    pointer can sit right after its thread array (where the list puts it) gives the list's address; the
    chain is then followed by NextEntryOffset and every name read through that address (None when the
    bytes were overwritten). create_time is a FILETIME (100 ns since 1601)."""
    base = start = None
    for o in range(0, len(buf) - 0x100, 8):
        e = _process(buf, o)
        name_off = o + 0x100 + 0x50 * e["threads"]
        if (0 < e["threads"] < 4096 and e["pid"] % 4 == 0 and e["ppid"] % 4 == 0 and e["name_max"] >= e["name_len"]
                and (e["next"] == 0 or e["next"] >= name_off - o + e["name_len"])
                and _utf16(buf, name_off, e["name_len"])):
            base, start = e["name_ptr"] - name_off, o
            break
    out, o = [], start
    while o is not None and o + 0x100 <= len(buf):
        e = _process(buf, o)
        if not (0 < e["threads"] < 4096 and e["pid"] < 2**32 and e["pid"] % 4 == 0 and e["ppid"] < 2**32):
            break
        e["name"] = _utf16(buf, e["name_ptr"] - base, e["name_len"])
        out.append(e)
        o = o + e["next"] if e["next"] else None
    return out
