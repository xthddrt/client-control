#!/usr/bin/env python3
"""All traffic of the game's programs, by category and direction, as Markdown.

    .venv/bin/python analysis/traffic-breakdown.py captures/proxy-<stamp>.jsonl ... \
        [--pcap captures/proxy-<stamp>-other.pcap ...] > docs/reference/traffic-breakdown.md

TCP comes from the proxy recordings (every IPv4 TCP connection of the game's programs: game
servers decoded, HTTPS by server name). Everything else (UDP, QUIC, ICMP, IPv6) comes from the
other-packets pcaps, read with tshark. Categories are matched by server name, then port; what each
one is and who sends it comes from docs/guides/PROTOCOL.md (CATEGORIES below).
"""

from __future__ import annotations

import argparse
import json
import shutil
import statistics
import subprocess
import time
from collections import defaultdict
from pathlib import Path

# (match, category, sender, what it is, how far it can be read)
# match: "sni:<name>", "port:<n>", "ports:<a>-<b>"; the first match wins.
CATEGORIES = [
    ("game:8484", "Game: login server", "MapleStory.exe",
     "sign-in, world and character choice", "decoded both ways"),
    ("game:*", "Game: channel servers", "MapleStory.exe",
     "everything in the game world: maps, players, shops, chat, checks",
     "decoded both ways (docs/reference/message-breakdown.md)"),
    ("sni:public.api.nexon.com", "Analytics", "NexonAnalytics64.dll",
     "Nexon's analytics library: large uploads", "HTTPS: server name and sizes only"),
    ("sni:x-csauth.ngs.nexon.com", "Anti-cheat check-in", "grap-communicator64.aes",
     "NGS anti-cheat authentication/heartbeat, about once a minute", "HTTPS: server name and sizes only"),
    ("sni:x-config.ngs.nexon.com", "Anti-cheat settings", "NGS anti-cheat",
     "anti-cheat configuration downloads", "HTTPS: server name and sizes only"),
    ("sni:68bd384lrg.execute-api.ap-northeast-1.amazonaws.com", "Crash reporter play-time counter",
     "CrashReporter.dll (through WinINet)",
     "settings at game start, then an anonymous GET every 10 min (PROTOCOL.md)",
     "HTTPS, read from the code and Wine's web cache"),
    ("sni:bolo7yechd.execute-api.ap-northeast-1.amazonaws.com", "Crash reports",
     "CrashReportClient.exe / CrashReporter.dll", "crash upload settings and crash logs",
     "HTTPS, read from the code and Wine's web cache"),
    ("port:47611", "Nexon messenger/session", "nmconew64.dll",
     "session refresh: one 821-byte request, one 828-byte reply", "framing and first layer decoded"),
    ("port:8913", "Ping service", "nexon_x64.dll in the game; the launcher",
     "plain text registration, then ping/pong", "plain text"),
]


def classify(conn):
    port = (conn.get("destination") or [None, None])[1]
    sni = conn.get("sni") or ""
    for match, *rest in CATEGORIES:
        kind, _, value = match.partition(":")
        if kind == "game" and conn.get("game_handshake") and (value == "*" or port == int(value)):
            return rest
        if kind == "sni" and sni == value:
            return rest
        if kind == "port" and port == int(value):
            return rest
    name = f"HTTPS {sni}" if sni else f"port {port}"
    return [f"Other: {name}", conn.get("process") or "?", "not identified", "?"]


def connections(paths):
    conns = {}
    for path in paths:
        for line in open(path, encoding="utf-8"):
            if '"kind":"message"' in line:
                continue
            record = json.loads(line)
            if "conn" not in record:
                continue
            conn = conns.setdefault((path, record["conn"]), {"bytes": defaultdict(int)})
            kind = record["kind"]
            if kind == "data":
                conn.setdefault("first", record["time_ns"])
                conn["last"] = record["time_ns"]
                conn["bytes"][record["direction"]] += len(record["hex"]) // 2
            elif kind.startswith("connection_") and kind != "connection_close":
                conn["destination"] = record.get("destination")
                conn["process"] = (record.get("process") or {}).get("name")
            elif kind == "connection_close":
                conn["closed"] = True
            elif kind == "tls_client_hello":
                conn["sni"] = record.get("sni")
            elif kind == "handshake":
                conn["game_handshake"] = True
    return [c for c in conns.values() if "first" in c]


def udp_conversations(pcaps):
    """[(peer, protocol, frames up, bytes up, frames down, bytes down, first time)] from tshark."""
    if not pcaps or not shutil.which("tshark"):
        return None
    rows = defaultdict(lambda: [0, 0, 0, 0, None, set()])
    for pcap in pcaps:
        out = subprocess.run(["tshark", "-r", pcap, "-T", "fields", "-E", "separator=\t", "-e", "frame.time_epoch",
                              "-e", "ip.src", "-e", "ip.dst", "-e", "udp.srcport", "-e", "udp.dstport",
                              "-e", "frame.len", "-e", "_ws.col.Protocol"],
                             capture_output=True, text=True, check=False).stdout
        for line in out.splitlines():
            t, src, dst, sport, dport, length, proto = (line.split("\t") + [""] * 7)[:7]
            if not src:
                continue
            # the local side is the private address (172.16/10./192.168.)
            up = src.startswith(("10.", "172.16.", "192.168."))
            peer = f"{dst if up else src}:{dport if up else sport}"
            row = rows[peer]
            row[0 if up else 2] += 1
            row[1 if up else 3] += int(length)
            row[4] = min(row[4] or float(t), float(t))
            row[5].add(proto)
    return [(peer, ",".join(sorted(r[5])), *r[:4], r[4]) for peer, r in sorted(rows.items(), key=lambda kv: kv[1][4])]


def human(n):
    return f"{n / 1e6:.2f} MB" if n >= 1e5 else f"{n / 1e3:.1f} KB"


def markdown(paths, pcaps):
    conns = connections(paths)
    t0 = min(c["first"] for c in conns)
    t1 = max(c["last"] for c in conns)
    hours = (t1 - t0) / 3.6e12
    groups = defaultdict(list)
    info = {}
    for c in conns:
        category, *rest = classify(c)
        groups[category].append(c)
        info[category] = rest
    up = {k: sum(c["bytes"].get("client_to_server", 0) for c in v) for k, v in groups.items()}
    down = {k: sum(c["bytes"].get("server_to_client", 0) for c in v) for k, v in groups.items()}
    total_up, total_down = sum(up.values()), sum(down.values())
    stamp = lambda ns: time.strftime("%Y-%m-%d %H:%M", time.localtime(ns / 1e9))
    out = [
        "# All traffic of the game's programs, by category and direction\n",
        f"From {', '.join(Path(p).name for p in paths)}: {stamp(t0)} to {stamp(t1)} ({hours:.1f} hours), "
        f"{len(conns)} TCP connections. Generated by analysis/traffic-breakdown.py. \"Up\" = this PC to the server "
        "(client to server), \"down\" = server to this PC. Sizes are the bytes inside TCP (TLS included), "
        "not counting TCP/IP headers.\n",
        f"\n**Total: {human(total_up)} up, {human(total_down)} down.**\n",
        "\n## By category\n",
        "| Category | Sender | Connections | Up | Up share | Up per hour | Down | Down share | Down per hour |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    order = sorted(groups, key=lambda k: -(up[k] + down[k]))
    for k in order:
        out.append(f"| {k} | {info[k][0]} | {len(groups[k])} | {human(up[k])} | {100 * up[k] / total_up:.1f}% | "
                   f"{human(up[k] / hours)} | {human(down[k])} | {100 * down[k] / total_down:.1f}% | "
                   f"{human(down[k] / hours)} |")
    out += ["\n## What each category is\n",
            "| Category | What it is | How far it can be read | Pattern |", "|---|---|---|---|"]
    for k in order:
        v = sorted(groups[k], key=lambda c: c["first"])
        gaps = [(b["first"] - a["first"]) / 1e9 for a, b in zip(v, v[1:])]
        dur = statistics.median((c["last"] - c["first"]) / 1e9 for c in v)
        per_up = statistics.median(c["bytes"].get("client_to_server", 0) for c in v)
        per_down = statistics.median(c["bytes"].get("server_to_client", 0) for c in v)
        pattern = (f"a new connection every {statistics.median(gaps):.0f} s (median), " if gaps else "") + \
                  f"each {human(per_up)} up / {human(per_down)} down, open {dur:.0f} s (medians)"
        out.append(f"| {k} | {info[k][1]} | {info[k][2]} | {pattern} |")
    open_now = [c for c in conns if not c.get("closed")]
    out.append(f"\n{len(open_now)} connections were still open at the end of the recordings; their bytes so far are "
               "counted. Connections opened before a recording started are not in it.\n")
    udp = udp_conversations(pcaps)
    out.append("\n## Everything that is not TCP (UDP, QUIC, ICMP, IPv6)\n")
    if udp is None:
        out.append("No pcap given, or tshark is not installed.\n")
    elif not udp:
        out.append(f"None in {', '.join(Path(p).name for p in pcaps)}.\n")
    else:
        out += ["| Peer | Protocol | First seen | Packets up | Bytes up | Packets down | Bytes down |",
                "|---|---|---|---:|---:|---:|---:|"]
        for peer, proto, fu, bu, fd, bd, first in udp:
            out.append(f"| {peer} | {proto} | {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(first))} | "
                       f"{fu} | {bu:,} | {fd} | {bd:,} |")
    return "\n".join(out) + "\n"


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("recordings", nargs="+")
    ap.add_argument("--pcap", action="append", default=[])
    args = ap.parse_args()
    print(markdown(args.recordings, args.pcap), end="")
