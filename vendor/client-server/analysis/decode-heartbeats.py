#!/usr/bin/env python3
"""
decode-heartbeats.py — decode the x-csauth/v2 kill-switch heartbeat stream from
a mitmproxy dump, and summarize cadence + kill-switch state over time.

The heartbeat uses the SAME cipher as the big NGS-X config blobs:
    wire body = base64( [2-byte header] + single_byte_XOR( gzip(JSON) ) )
    key K = C[2] ^ 0x08   (gzip CM byte is always 0x08; self-describing)

Usage:
    python3 decode-heartbeats.py <dump.mitm> [--json OUT] [--full]
"""
import sys, os, base64, zlib, json, argparse, datetime

def dec(body: bytes) -> dict:
    t = body.decode("ascii")
    C = base64.b64decode(t + "=" * (-len(t) % 4))
    K = C[2] ^ 0x08
    g = b"\x1f\x8b" + bytes(c ^ K for c in C)[2:]
    return json.loads(zlib.decompress(g, 16 + zlib.MAX_WBITS))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dump")
    ap.add_argument("--json", metavar="OUT", help="write decoded heartbeat corpus to JSON")
    ap.add_argument("--full", action="store_true", help="print every decoded heartbeat in full")
    a = ap.parse_args()

    from mitmproxy.io import FlowReader
    rows = []
    with open(a.dump, "rb") as f:
        for fl in FlowReader(f).stream():
            if not hasattr(fl, "request"):
                continue
            r = fl.request
            if "x-csauth" in r.pretty_host and r.path == "/v2" and fl.response and fl.response.content:
                ts = fl.response.timestamp_start or r.timestamp_start
                try:
                    rows.append((ts, len(fl.response.content), dec(fl.response.content)))
                except Exception as e:
                    rows.append((ts, len(fl.response.content), {"_decode_error": str(e)}))
    rows.sort(key=lambda x: x[0])

    print(f"# {len(rows)} x-csauth/v2 heartbeats\n")
    prev = None
    anomalies = []
    for ts, L, j in rows:
        dt = f"+{ts-prev:5.1f}s" if prev else "  base "
        prev = ts
        hhmmss = datetime.datetime.fromtimestamp(ts).strftime("%H:%M:%S")
        flag = ""
        if j.get("config_changed"):   flag += " <<< CONFIG_CHANGED"
        if j.get("detected"):         flag += f" <<<<< DETECTED {j['detected']}"
        if j.get("emergency_stop"):   flag += " <<<<<<< EMERGENCY_STOP"
        if flag:
            anomalies.append((hhmmss, j))
        line = (f"{hhmmss} {dt} len={L} cfg={j.get('config_changed')} "
                f"estop={j.get('emergency_stop')} det={j.get('detected')}{flag}")
        print(json.dumps(j, indent=1) if a.full else line)

    print(f"\n# anomalies (config_changed/detected/emergency_stop set): {len(anomalies)}")
    for hhmmss, j in anomalies:
        print(f"#   {hhmmss} cfg={j.get('config_changed')} det={j.get('detected')} estop={j.get('emergency_stop')}")

    if a.json:
        out = [{"ts": ts, "iso": datetime.datetime.fromtimestamp(ts).isoformat(),
                "wire_len": L, "decoded": j} for ts, L, j in rows]
        with open(a.json, "w") as f:
            json.dump(out, f, indent=1)
        print(f"\n# wrote {len(out)} heartbeats -> {a.json}")

if __name__ == "__main__":
    main()
