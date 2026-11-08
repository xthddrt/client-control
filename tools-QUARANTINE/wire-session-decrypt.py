#!/usr/bin/env python3
"""
wire-session-decrypt.py -- PASSIVE offline decryptor for MSCW transport (PM-96).

Decrypts a full captured session from a pcap with NO live client, NO key trap, and
NO handshake -- purely from ciphertext.

Seeded entirely from recovered constants:
  * STATIC AES-256 key (proven cross-session, PM-96):
        0f0000001b000000c500000046000000f3000000be000000ff00000075000000
  * verMask = 0x00df   ->  word0 = ((iv[3]<<8)|iv[2]) ^ verMask
  * getNewIv roll (tools/transport-cipher.py, proven vs real code, PM-94)

IV seeding (ciphertext-only, UNIQUE): two consecutive frame headers W0,W1 satisfy
  highshort(iv)^verMask == W0  and  highshort(getNewIv(iv))^verMask == W1
Only 2 IV bytes are free (iv[0],iv[1]); the chain pins them to a single value.
Then getNewIv rolls forward for the whole stream. start_layer (KS0 vs KS1) is
detected once by decoding the first long frame both ways and taking the sane opcode.

Usage: wire-session-decrypt.py <pcap> [--max N]
"""
import sys, os, struct, json, argparse
from collections import defaultdict, Counter
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HERE = os.path.dirname(os.path.abspath(__file__))
import importlib.util
_spec = importlib.util.spec_from_file_location("tc", os.path.join(HERE, "transport-cipher.py"))
tc = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(tc)
TABLE = tc._load_shuffle_table(os.path.join(HERE, "transport-shuffle-table.bin"))

STATIC_KEY = bytes.fromhex("0f0000001b000000c500000046000000f3000000be000000ff00000075000000")
VERMASK = 0x00df
_cipher = Cipher(algorithms.AES(STATIC_KEY), modes.ECB())
def _enc(block):
    encryptor = _cipher.encryptor()
    return encryptor.update(block) + encryptor.finalize()
def _hs(iv): return (iv[3] << 8) | iv[2]

def parse_pcap(path):
    f = open(path, "rb"); magic = f.read(4)
    endian = "<" if magic[:1] == b'\xd4' or magic == b'\x4d\x3c\xb2\xa1' else ">"
    nano = magic in (b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d')
    gh = f.read(20)
    linktype = struct.unpack(endian + "I", gh[16:20])[0]  # EN10MB=1, LINUX_SLL=113, SLL2=276
    segs = []
    while True:
        ph = f.read(16)
        if len(ph) < 16: break
        ts, tu, incl, orig = struct.unpack(endian + "IIII", ph)
        d = f.read(incl)
        # strip link layer -> locate IPv4 header start + ethertype
        if linktype == 1:            # Ethernet
            if len(d) < 14 or d[12:14] != b'\x08\x00': continue
            ip = d[14:]
        elif linktype == 113:        # Linux cooked SLL (16B hdr, proto @14)
            if len(d) < 16 or d[14:16] != b'\x08\x00': continue
            ip = d[16:]
        elif linktype == 276:        # Linux cooked SLL2 (20B hdr, proto @0)
            if len(d) < 20 or d[0:2] != b'\x08\x00': continue
            ip = d[20:]
        else:
            continue
        if len(ip) < 20 or ip[9] != 6: continue   # IPv4 proto 6 = TCP
        ihl = (ip[0] & 0xf) * 4
        src = ".".join(map(str, ip[12:16])); dst = ".".join(map(str, ip[16:20]))
        tcp = ip[ihl:]
        if len(tcp) < 20: continue
        sport, dport = struct.unpack(">HH", tcp[0:4])
        seq = struct.unpack(">I", tcp[4:8])[0]
        doff = (tcp[12] >> 4) * 4
        payload = tcp[doff:]
        if payload:
            t = ts + tu * (1e-9 if nano else 1e-6)
            segs.append((t, src, sport, dst, dport, seq, payload))
    return segs

def reassemble(segs):
    """Proper TCP reassembly: place each segment at its sequence offset and
    dedup overlapping retransmits (later-write-wins). A naive seq- or time-
    ordered join duplicates retransmitted bytes and corrupts the stream."""
    flows = defaultdict(list)
    for t, s, sp, d, dp, seq, pl in segs:
        flows[(s, sp, d, dp)].append((t, seq, pl))
    streams = {}
    timestamps = {}
    for k, lst in flows.items():
        lst.sort(key=lambda x: x[0])  # arrival order -> later writes win on overlap
        base = lst[0][1]
        buf = {}  # relative offset -> byte
        times = {}
        maxoff = 0
        for t, seq, pl in lst:
            rel = (seq - base) & 0xffffffff
            if rel > 0x80000000:  # seq wrapped below base
                rel -= 0x100000000
            for i, byte in enumerate(pl):
                buf[rel + i] = byte
                times[rel + i] = t
            maxoff = max(maxoff, rel + len(pl))
        out = bytearray(maxoff)
        for off, byte in buf.items():
            if 0 <= off < maxoff:
                out[off] = byte
        streams[k] = bytes(out)
        timestamps[k] = times
    return streams, timestamps

def parse_frames(stream, times=None):
    off = 0; frames = []
    while off + 4 <= len(stream):
        w0, w1 = struct.unpack("<HH", stream[off:off + 4])
        blen = w0 ^ w1
        if blen == 0 or off + 4 + blen > len(stream): break
        timestamp = times.get(off) if times is not None else None
        frames.append((w0, stream[off + 4:off + 4 + blen], timestamp))
        off += 4 + blen
    return frames, off, len(stream)

def keystream(iv4, n, start_layer):
    b = _enc(iv4 * 4)
    if start_layer: b = _enc(b)
    out = b""
    while len(out) < n: out += b; b = _enc(b)
    return out[:n]

def decrypt_body(iv4, body, start_layer):
    ks = keystream(iv4, len(body), start_layer)
    return bytes(body[i] ^ ks[i] for i in range(len(body)))

def decrypt_body_recv(iv4, body):
    """Inbound (s->c) body cipher: a single-byte XOR with iv[0] applied to the
    whole body. Proven on co2.pcap (PM-99): recv is NOT AES-OFB -- the AES
    contexts seen at 0x140cea1b0 are inner PCOM object layers, not the wire
    cipher. 96.6% of recv frames decode to clean plaintext under this model."""
    k = iv4[0]
    return bytes(b ^ k for b in body)

def seed_iv(w0, w1, mask=VERMASK):
    i2 = (w0 ^ mask) & 0xff; i3 = ((w0 ^ mask) >> 8) & 0xff
    out = []
    for a in range(256):
        for b in range(256):
            iv = bytes([a, b, i2, i3])
            if (_hs(tc.getNewIv(iv, TABLE)) ^ mask) == w1:
                out.append(iv)
    return out

def detect_start_layer(iv4, body):
    for sl in (0, 1):
        pt = decrypt_body(iv4, body, sl)
        if len(pt) >= 2 and (pt[0] | (pt[1] << 8)) < 0x400:
            return sl
    return 0

def decrypt_direction(frames, label, mask=VERMASK, max_n=None):
    out = []
    if len(frames) < 2:
        print(f"[{label}] <2 frames, cannot chain-seed"); return out
    seed = None
    for j in range(min(len(frames) - 1, 8)):
        c = seed_iv(frames[j][0], frames[j + 1][0], mask)
        if len(c) == 1:
            seed = (j, c[0]); break
    if not seed:
        print(f"[{label}] no unique chain seed in first frames"); return out
    j0, iv = seed
    recv = (mask == 0xfffe)
    sl = 0
    if not recv:
        for k in range(j0, len(frames)):
            if len(frames[k][1]) >= 16:
                ivk = iv
                for _ in range(k - j0): ivk = tc.getNewIv(ivk, TABLE)
                sl = detect_start_layer(ivk, frames[k][1]); break
    cipher = "recv-xor-iv0" if recv else f"aes-ofb-L{sl}"
    print(f"[{label}] seeded@frame{j0} iv={iv.hex()} mask={mask:#06x} cipher={cipher}")
    cur = iv
    for i in range(j0, len(frames)):
        if max_n and (i - j0) >= max_n: break
        w0, body, timestamp = frames[i]
        synced = ((_hs(cur) ^ mask) == w0)
        pt = decrypt_body_recv(cur, body) if recv else decrypt_body(cur, body, sl)
        op = (pt[0] | (pt[1] << 8)) if len(pt) >= 2 else None
        out.append({"i": i, "time": timestamp, "word0": w0, "len": len(body), "opcode": op,
                    "iv": cur.hex(), "synced": synced, "plain": pt.hex()})
        cur = tc.getNewIv(cur, TABLE)
    return out

RECV_MASK = 0xfffe
SEND_MASK = 0x00df
SERVER_PORTS = (8550, 8559, 8560, 8566, 8575, 8585, 8595)  # legacy hint only; ports rotate per session

def _is_lan(ip):
    return ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.") or ip == "127.0.0.1"

def _dir_mask(src_ep):
    """Direction mask by IP, not port (ports rotate every session). A frame whose
    SOURCE is the remote server is recv (s->c, mask 0xfffe); a LAN-sourced frame is
    send (c->s, mask 0x00df). Falls back to the stale port list only if both ends
    look non-LAN (e.g. a proxy<->server capture with two routable IPs)."""
    if _is_lan(src_ep[0]):
        return SEND_MASK
    # src is remote: recv, unless the *other* heuristic (port) disagrees strongly
    return RECV_MASK

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap"); ap.add_argument("--max", type=int, default=None)
    args = ap.parse_args()
    segs = parse_pcap(args.pcap)
    streams, timestamps = reassemble(segs)
    bytes_by_conn = Counter()
    for (s, sp, d, dp), data in streams.items():
        key = tuple(sorted([(s, sp), (d, dp)]))
        bytes_by_conn[key] += len(data)
    if not bytes_by_conn:
        print("no TCP data"); return
    (ep1, ep2), _ = bytes_by_conn.most_common(1)[0]
    dirA = streams.get((ep1[0], ep1[1], ep2[0], ep2[1]), b"")
    dirB = streams.get((ep2[0], ep2[1], ep1[0], ep1[1]), b"")
    timesA = timestamps.get((ep1[0], ep1[1], ep2[0], ep2[1]), {})
    timesB = timestamps.get((ep2[0], ep2[1], ep1[0], ep1[1]), {})
    maskA = _dir_mask(ep1); maskB = _dir_mask(ep2)
    fA, consA, totA = parse_frames(dirA, timesA)
    fB, consB, totB = parse_frames(dirB, timesB)
    print(f"conn {ep1} <-> {ep2}")
    print(f"  dirA {ep1}->{ep2}: {len(dirA)}B framed={consA}/{totA} frames={len(fA)} mask={maskA:#06x}")
    print(f"  dirB {ep2}->{ep1}: {len(dirB)}B framed={consB}/{totB} frames={len(fB)} mask={maskB:#06x}")
    res = {"dirA": decrypt_direction(fA, "A", maskA, args.max),
           "dirB": decrypt_direction(fB, "B", maskB, args.max)}
    outp = args.pcap + ".decrypted.json"
    json.dump(res, open(outp, "w"), indent=1)
    for d in ("dirA", "dirB"):
        print(f"\n--- {d} decoded (first 14) ---")
        for r in res[d][:14]:
            flag = "" if r["synced"] else " !resync"
            print(f"  op={r['opcode']:#06x} len={r['len']:<4} iv={r['iv']}{flag} plain[:14]={r['plain'][:28]}")
    print(f"\nwrote {outp}")

if __name__ == "__main__":
    main()
