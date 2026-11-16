#!/usr/bin/env python3
"""Decrypt the game's analytics upload (TLS 1.2 AES-GCM) with master secrets read from the game's memory.

    # 1. needles of the open analytics connections that have no key yet
    .venv/bin/python analysis/tls-keys.py needles captures/proxy-<stamp>.jsonl --keylog captures/analytics.keylog > captures/tls-needles.txt
    # 2. read-only memory read (root)
    sudo .venv/bin/python -I analysis/tls-memscan.py <game pid> captures/tls-scan-<n>.pkl @captures/tls-needles.txt
    # 3. master secrets, each proven on a recorded record, added to an SSLKEYLOGFILE (mode 600)
    .venv/bin/python analysis/tls-keys.py find captures/proxy-<stamp>.jsonl captures/tls-scan-*.pkl --keylog captures/analytics.keylog
    # 4. requests, replies and NDJSON record types, values masked; --fields adds a masked summary of
    #    each record type's fields (csv lists, memory dumps and the process list in them, stages)
    .venv/bin/python analysis/tls-keys.py decrypt captures/proxy-<stamp>.jsonl --keylog captures/analytics.keylog [--fields] [--until "YYYY-MM-DD HH:MM:SS"] [--plaintext FILE]
    # without keys: each connection's requests by size, which tells the record types apart
    .venv/bin/python analysis/tls-keys.py sizes captures/proxy-<stamp>.jsonl [--keylog FILE]

`analysis/tls-keys-watch.sh` runs 1-3 soon after each new analytics connection. Only connections that
were open when the memory was read can be decrypted (OpenSSL wipes the secrets after closing).
`find` accepts a 48-byte window of the scan as a key only if it authenticates the client's encrypted
Finished record (the AES-GCM tag), so a key in the keylog is never a guess. `decrypt` prints masked
values (4 characters, small numbers); `--plaintext FILE` writes everything in clear to a mode-600 file
outside git. `--fields` prints counts, value ranges and small codes only (see fields_summary).
The record formats are in docs/guides/PROTOCOL.md ("Analytics"). Keylogs, scans and plaintext hold account data: keep them in captures/ or outside
the repository (the tools refuse other places in it).
"""

from __future__ import annotations

import argparse
import collections
import datetime
import json
import math
import pickle
import re
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from traffic import tls12  # noqa: E402

ANALYTICS = "public.api.nexon.com"
IMAGE_BASE = 0x140000000   # MapleStory.exe; ETC_BU_CData addresses are its globals
WM = {256: "key down", 257: "key up", 260: "syskey down", 261: "syskey up", 512: "move", 513: "left down",
      514: "left up", 515: "left double", 516: "right down", 517: "right up", 518: "right double",
      519: "middle down", 520: "middle up", 521: "middle double", 522: "wheel", 526: "h-wheel"}
# Request sizes (TLS plaintext: HTTP headers + NDJSON body) of the record types, from the decrypted
# 2026-11-15 upload; the analytics library sends one record type per request (the dumps three at once).
SIZE_CLASSES = [(1000, "under 1 KB"), (2600, "1-2.6 KB: InputEventSequence or SdkSummary"), (4500, "2.6-4.5 KB"),
                (20000, "4.5-20 KB"), (28000, "20-28 KB: MSMouseEvent or MSInputEvent batch"), (50000, "28-50 KB"),
                (60000, "50-60 KB: the three ETC_BU_CData dumps"), (math.inf, "over 60 KB")]


def sessions(conns):
    return {c: s for c, s in ((c, tls12.session(v)) for c, v in sorted(conns.items())) if s}


def cmd_needles(args, conns, keylog):
    for c, s in sessions(conns).items():
        if not conns[c]["closed"] and s["client_random"] not in keylog:
            print(s["client_random"].hex(), s["server_random"].hex(), s["session_id"].hex())


def cmd_find(args, conns, keylog):
    todo = {c: s for c, s in sessions(conns).items() if s["client_random"] not in keylog}
    found, seen = {}, set()
    for path in args.scans:
        scan = pickle.load(open(path, "rb"))   # our own tls-memscan.py output only
        wanted = set(scan.get("needles", ()))  # the connections the scan was made for (all if unknown)
        targets = {c: s for c, s in todo.items() if c not in found and (not wanted or s["client_random"] in wanted)}
        for block in scan["blocks"].values():
            for off in range(0, len(block) - 47, 8):
                cand = block[off:off + 48]
                if cand in seen or cand.count(0) > 8:   # secrets are random: few zero bytes
                    continue
                seen.add(cand)
                for c, s in list(targets.items()):
                    if tls12.verify(cand, s):
                        found[c] = cand
                        del targets[c]
                        print(f"conn {c}: master secret found in {path} and verified on its Finished record")
    keylog.update({todo[c]["client_random"]: k for c, k in found.items()})
    with tls12.private_file(args.keylog) as f:
        f.writelines(f"CLIENT_RANDOM {r.hex()} {k.hex()}\n" for r, k in keylog.items())
    print(f"{len(found)} of {len(todo)} connections without a key found; {len(keylog)} keys in {args.keylog}")


def counts(values, n=8):
    return dict(collections.Counter(values).most_common(n))


def fields_summary(recs):
    """Masked summary of the decrypted records [(time_ns, raw line length, record)]: per type its share
    of the bytes and timing, then each type's fields: csv lists by field (codes and ranges, no
    coordinates or times), the memory dumps (address, size, the process list in the first), stages."""
    recs, by = sorted(recs, key=lambda x: x[0]), collections.defaultdict(list)
    for t, n, r in recs:
        by[r.get("type", "?")].append((t, n, r.get(r.get("type"))))
    total = sum(n for _, n, _ in recs) or 1
    print(f"\n== fields: {len(recs)} records, {total} bytes")
    for kind, rows in sorted(by.items(), key=lambda kv: -sum(x[1] for x in kv[1])):
        b, ts = sum(x[1] for x in rows), sorted({x[0] for x in rows})
        gaps = [(y - x) / 1e9 for x, y in zip(ts, ts[1:])]
        print(f"{kind}: {len(rows)} records, {b} bytes ({100 * b / total:.1f}%), median record "
              f"{statistics.median(x[1] for x in rows):.0f} B" + (f", median gap {statistics.median(gaps):.0f} s" if gaps else ""))
    payloads = {k: [p for _, _, p in v if isinstance(p, dict)] for k, v in by.items()}

    if ies := payloads.get("NXLog_InputEventSequence"):
        lists = [tls12.csv_rows("NXLog_InputEventSequence", p) for p in ies]
        mouse = [e for x in lists for e in x.get("mouseEvents", [])]
        span = [(int(x["mouseEvents"][-1]["time"]) - int(x["mouseEvents"][0]["time"])) / 1000
                for x in lists if len(x.get("mouseEvents", [])) > 1]
        print(f"\nNXLog_InputEventSequence: header {ies[0].get('mouseEventHeader')!r}; {len(mouse)} mouse events,"
              f" event {counts(e.get('event') for e in mouse)}, device {counts(e.get('device') for e in mouse)};"
              f" median time covered per record {statistics.median(span) if span else 0:.1f} s")
        print("   other lists:", {k: sum(len(x.get(k, [])) for x in lists) for k in ("keyEvents", "gamepadEvents")},
              {k: sum(len(p.get(k, [])) for p in ies) for k in ("actions", "mousedeltas")},
              "inputloglevel", counts(p.get("inputloglevel") for p in ies), "resolution", counts(tls12.mask(p.get("resolution")) for p in ies))
        print("   settings:", {k: v for k, v in ies[0].items() if k.startswith("opt_")})
    if mm := payloads.get("ETC_MSMouseEvent"):
        md = [e for p in mm for e in tls12.csv_rows("ETC_MSMouseEvent", p)["mousedatas"]]
        print(f"\nETC_MSMouseEvent: {len(md)} entries (age_ms,x,y,msg,extra1,extra2), msg",
              counts(WM.get(int(e["msg"]), e["msg"]) for e in md), "extra1", counts(e.get("extra1", "").split("|")[0] for e in md),
              "extra2", counts(e.get("extra2", "").split("|")[0] for e in md),
              f"oldest entry {max(int(e['age_ms']) for e in md) / 1000:.0f} s")
        for k in ("eventcount", "inputplacetype", "screenwidth", "screenheight", "charlevel", "mapleworldid", "ispcroom"):
            print(f"   {k}:", counts(json.dumps(tls12.mask(p.get(k))) for p in mm))
    if ki := payloads.get("ETC_MSInputEvent"):
        kd = [e for p in ki for e in tls12.csv_rows("ETC_MSInputEvent", p)["keydatas"]]
        print(f"\nETC_MSInputEvent: {len(kd)} entries (time,vk,msg,state,count,x,y), msg",
              counts(WM.get(int(e["msg"]), e["msg"]) for e in kd), f"{len({e['vk'] for e in kd})} distinct keys,",
              "state", counts(e.get("state") for e in kd), "count", counts(e.get("count") for e in kd))
        for k in ("datasize", "deviceresolution", "inputeventtype", "key_pid", "key_vid"):
            print(f"   {k}:", counts(json.dumps(tls12.mask(p.get(k))) for p in ki))
    if bu := payloads.get("ETC_BU_CData"):
        dumps = collections.defaultdict(list)
        for p in bu:
            addr, raw = tls12.bu_dump(p)
            dumps[(p.get("bu_t"), addr)].append(raw)
        print("\nETC_BU_CData (bu_d = base64 address | base64 object bytes):")
        for (bt, addr), raws in sorted(dumps.items(), key=lambda kv: kv[0][0]):
            where = f"RVA {addr - IMAGE_BASE:#x}" if 0 <= addr - IMAGE_BASE < 0x10000000 else tls12.mask(addr)
            print(f"   bu_t {bt}: {len(raws)} dumps of the object at {where}, sizes {counts(len(r) for r in raws)}")
            snaps = [tls12.process_snapshot(r) for r in raws]
            for snap in {json.dumps([(e["pid"], e["ppid"]) for e in s]): s for s in snaps if s}.values():
                print(f"      process list ({len(snap)} entries, pid/parent/threads/handles/name):",
                      [(e["pid"], e["ppid"], e["threads"], e["handles"], tls12.mask(e["name"])) for e in snap])
    if st := payloads.get("stability"):
        print("\nstability (stage <- previous: comment, elapsed ms):")
        for p in st:
            c = str(p.get("comment"))
            print(f"   {p.get('stage')} <- {p.get('prevStage')}: {c if re.fullmatch(r'GC:[A-Za-z0-9]+', c) else tls12.mask(c)},"
                  f" {tls12.mask(p.get('elapsedtime'))}, error {p.get('errorCode')}")
    if ss := payloads.get("NXLog_SdkSummary"):
        req, sent = collections.Counter(), collections.Counter()
        for p in ss:
            req.update({m["typename"]: m["count"] for m in p.get("requested_messages", [])})
            sent.update({m["typename"]: m["count"] for m in p.get("sent_messages", [])})
        period = counts(round((datetime.datetime.fromisoformat(p["end_datetime"].replace("Z", "+00:00"))
                               - datetime.datetime.fromisoformat(p["begin_datetime"].replace("Z", "+00:00"))).total_seconds())
                        for p in ss if "begin_datetime" in p)
        print(f"\nNXLog_SdkSummary: {len(ss)} records, period s {period}\n   requested {dict(req)}\n   sent      {dict(sent)}")
    # strings that could be file names, URLs or window text, by JSON path (the old privacy check)
    hits = collections.Counter()

    def walk(o, path):
        if isinstance(o, dict):
            for k, v in o.items():
                walk(v, f"{path}.{k}")
        elif isinstance(o, list):
            for v in o:
                walk(v, path + "[]")
        elif isinstance(o, str) and re.search(r"\.exe|\.dll|title|clip|window|https?:|[A-Za-z]{3,} [A-Za-z]{3,}", o, re.I):
            hits[path] += 1
    for _, _, r in recs:
        walk(r, "")
    print("\nstrings like file names, URLs or text, by path:", dict(hits.most_common(20)))


def cmd_sizes(args, conns, keylog):
    """Each connection's requests by size, without keys: client records less than 50 ms apart are one request."""
    total = collections.Counter()
    for c, v in sorted(conns.items()):
        sizes, last = [], None
        for t, kind, _, body in tls12.encrypted(v["c2s"])[1:]:
            if kind != 23:
                continue
            if last is not None and t - last < 50e6:
                sizes[-1] += len(body) - 24   # TLS 1.2 AES-GCM: 8-byte explicit nonce + 16-byte tag
            else:
                sizes.append(len(body) - 24)
            last = t
        kinds = collections.Counter(next(label for top, label in SIZE_CLASSES if n < top) for n in sizes)
        total.update(kinds)
        s = tls12.session(v)
        note = " (key in keylog)" if s and s["client_random"] in keylog else ""
        print(f"conn {c}{note}: {len(sizes)} requests, {sum(sizes)} bytes: {dict(kinds)}")
    print("all:", dict(total))


def cmd_decrypt(args, conns, keylog):
    out = tls12.private_file(args.plaintext) if args.plaintext else None
    until = datetime.datetime.fromisoformat(args.until).timestamp() * 1e9 if args.until else math.inf
    types, examples, recs = collections.Counter(), {}, []
    for c, s in sessions(conns).items():
        master = keylog.get(s["client_random"])
        if master is None:
            continue
        plain = tls12.decrypt(conns[c], master, s)
        failed = sum(p is None for d in plain.values() for _, _, p in d)
        print(f"== conn {c}: {len(plain['c2s'])} records up, {len(plain['s2c'])} down, {failed} failed")
        for d in ("c2s", "s2c"):
            for i, (t, line, hdr, body) in enumerate(tls12.http_messages(plain[d])):
                if t > until:
                    continue
                ndjson = "ndjson" in hdr.get("content-type", "")
                lines = list(tls12.ndjson(body)) if ndjson else []
                count = collections.Counter(r.get("type", "?") for r in lines)
                types.update(count)
                for r in lines:
                    examples.setdefault(r.get("type", "?"), r)
                if ndjson and d == "c2s":
                    recs += [(t, len(raw) + 1, r) for raw, r in zip((x for x in body.split(b"\n") if x.strip()), lines)]
                print(f"{time.strftime('%H:%M:%S', time.localtime(t / 1e9))} {d} {line.split('?')[0]}"
                      f" {len(body)} B {dict(count) if count else ''}")
                if i == 0:
                    print("   headers", json.dumps(tls12.mask(hdr), ensure_ascii=False))
                if out:
                    out.write(json.dumps({"conn": c, "direction": d, "time_ns": t, "start": line, "headers": hdr,
                                          "body": body.decode("utf-8", "replace")}, ensure_ascii=False) + "\n")
    print("record types:", dict(types.most_common()))
    for kind, r in examples.items():
        print(f"example {kind}:", json.dumps(tls12.mask(r), ensure_ascii=False)[:600])
    if args.fields:
        fields_summary(recs)
    if out:
        out.close()
        print("plaintext written to", args.plaintext)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("needles", "find", "decrypt", "sizes"):
        p = sub.add_parser(name)
        p.add_argument("recording")
        if name == "find":
            p.add_argument("scans", nargs="+")
        p.add_argument("--keylog", required=name in ("find", "decrypt"), default="/dev/null")
        p.add_argument("--sni", default=ANALYTICS)
        if name == "decrypt":
            p.add_argument("--plaintext", help="also write every message in clear to this mode-600 file (captures/ or outside the repository)")
            p.add_argument("--fields", action="store_true", help="masked summary of each record type's fields")
            p.add_argument("--until", help='leave out messages after this local time ("YYYY-MM-DD HH:MM:SS")')
    args = ap.parse_args()
    conns = tls12.read_recording(args.recording, args.sni)
    globals()["cmd_" + args.cmd](args, conns, tls12.read_keylog(args.keylog))


if __name__ == "__main__":
    main()
