#!/usr/bin/env python3
"""When game messages come, what comes with them, and what they carry, from proxy recordings.

    REC = captures/proxy-<stamp>.jsonl (one or more; client opcodes resolved by traffic/timeline.py)
    TYPE = C:0x9c or S:0x1b, optionally with a field filter: C:0x70:subtype=5, S:0x165:value=-1;
           'any' = every message (show REC --type any --conn N: one connection's whole timeline)

    message-timing.py periods REC... [--type TYPE ...]          gaps per connection: median, p10, p90
    message-timing.py around REC... --type TYPE [--window 2]    what comes before / after, against chance
    message-timing.py pair REC... REQUEST ANSWER [--window 2] [--by FIELD]
                                                                request -> answer rate and delay
    message-timing.py show REC... --type TYPE ... [--before N --after N] [--fields] [--limit N]
                                                                occurrences (with context), the timeline
    message-timing.py values REC... --type TYPE --field FIELD   value counts and changes per connection
    message-timing.py who REC... --type TYPE [--offset 2]       a leading u32 id: own character, a player
                                                                in the room, an NPC, a drop?
    message-timing.py input-rate REC                            analytics upload gaps vs C 0x9c input counts

Gaps and windows are per connection (conn numbers restart in each recording). `around` compares each
neighbour type's share of occurrences with its share at random instants of the same connections
(20 per occurrence, fixed seed): a type that is there far more often than by chance is tied to it.
`pair` matches each request to the first unused answer after it in the same connection. Fields come
from traffic/fields.py, which names the doc of each layout. Timing is evidence of a link, not proof.
"""

from __future__ import annotations

import argparse
import bisect
import random
import statistics
import struct
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from traffic.fields import PARSERS, brief, parse  # noqa: E402
from traffic.protocol import NAMES  # noqa: E402
from traffic.timeline import by_connection, messages, parse_type  # noqa: E402

ANALYTICS_SNI = "public.api.nexon.com"


class Spec:
    """A message type with an optional field filter: 'C:0x70:subtype=5'; 'any' is every message."""

    def __init__(self, text):
        self.text, self.key, self.field = text, None, None
        if text == "any":
            return
        head, _, condition = text.partition("=")
        parts = head.replace(" ", ":").split(":")
        self.key = parse_type(":".join(parts[:2]))
        self.field = parts[2] if len(parts) > 2 and condition else None
        self.value = _value(condition) if self.field else None

    def matches(self, m):
        if self.key is None:
            return True
        if (m.side, m.opcode) != self.key:
            return False
        return self.field is None or _value(str(fields_of(m).get(self.field))) == self.value


def _value(text):
    try:
        return int(text, 0)
    except ValueError:
        return text


def fields_of(m):
    return parse(m.side, m.opcode, m.body) or {}


def load(paths, keep):
    """{connection: [Message]}; bodies kept only for the types in keep (and those with a field parser)."""
    keep = set(keep) | set(PARSERS)
    return by_connection(m if (m.side, m.opcode) in keep else m._replace(body_hex="")
                         for m in messages(paths))


def quantiles(values):
    values = sorted(values)
    q = lambda p: values[int(p * (len(values) - 1))]  # noqa: E731
    return q(0.1), statistics.median(values), q(0.9)


def label(key):
    return f"{key[0]} 0x{key[1]:x}" if key[1] is not None else f"{key[0]} ?"


def stamp(time_ns):
    return datetime.fromtimestamp(time_ns / 1e9, timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


# --- periods ----------------------------------------------------------------------------------------

def periods(conns, specs, minimum):
    times, first = defaultdict(lambda: defaultdict(list)), defaultdict(list)
    for conn, items in conns.items():
        start = items[0].time_ns
        for m in items:
            for spec in specs or [None]:
                if spec is None or spec.matches(m):
                    name = spec.text if spec else label((m.side, m.opcode))
                    if not times[name][conn]:
                        first[name].append((m.time_ns - start) / 1e9)
                    times[name][conn].append(m.time_ns)
    rows = []
    for name, per_conn in times.items():
        gaps = [(b - a) / 1e9 for ts in per_conn.values() for a, b in zip(ts, ts[1:])]
        count = sum(len(ts) for ts in per_conn.values())
        if count < minimum:
            continue
        p10, med, p90 = quantiles(gaps) if gaps else (None, None, None)
        rows.append((count, name, len(per_conn), len(gaps), p10, med, p90, statistics.median(first[name])))
    out = ["| type | count | connections | gaps | p10 s | median s | p90 s | first after conn start s (median) |",
           "|---|---:|---:|---:|---:|---:|---:|---:|"]
    fmt = lambda v: "" if v is None else f"{v:.2f}"  # noqa: E731
    for count, name, n_conns, n_gaps, p10, med, p90, start in sorted(rows, key=lambda r: -r[0]):
        out.append(f"| {name} | {count} | {n_conns} | {n_gaps} | {fmt(p10)} | {fmt(med)} | {fmt(p90)} | {start:.1f} |")
    return "\n".join(out)


# --- around -------------------------------------------------------------------------------------------

def around(conns, spec, window, top, samples=20, seed=1):
    events = [(conn, m.time_ns) for conn, items in conns.items() for m in items if spec.matches(m)]
    index = {conn: [m.time_ns for m in items] for conn, items in conns.items()}
    rng = random.Random(seed)
    baseline = [(conn, rng.randint(conns[conn][0].time_ns, conns[conn][-1].time_ns))
                for conn, _ in events for _ in range(samples)]
    w = int(window * 1e9)

    def shares(points, skip_self):
        before, after = Counter(), Counter()
        for conn, t in points:
            items, ts = conns[conn], index[conn]
            lo, mid, hi = bisect.bisect_left(ts, t - w), bisect.bisect_left(ts, t), bisect.bisect_right(ts, t + w)
            before.update({(m.side, m.opcode) for m in items[lo:mid]})
            # the occurrence itself sits at t: leave it out of "after" for the real events
            after.update({(m.side, m.opcode) for m in items[mid:hi]
                          if not (skip_self and m.time_ns == t and spec.matches(m))})
        return {k: v / max(len(points), 1) for k, v in before.items()}, \
            {k: v / max(len(points), 1) for k, v in after.items()}

    (eb, ea), (bb, ba) = shares(events, True), shares(baseline, False)
    out = [f"{spec.text}: {len(events)} occurrences on {len({c for c, _ in events})} connections; "
           f"window {window} s; share of occurrences with the type nearby vs at random instants"]
    for title, ev, base in (("before", eb, bb), ("after", ea, ba)):
        out.append(f"\n{title}:\n| type | name | occurrences | chance |\n|---|---|---:|---:|")
        for key in sorted(ev, key=lambda k: -(ev[k] - base.get(k, 0)))[:top]:
            out.append(f"| {label(key)} | {(NAMES.get(key) or ('',))[0]} | {ev[key]:.2f} | {base.get(key, 0):.2f} |")
    return "\n".join(out)


# --- pair ---------------------------------------------------------------------------------------------

def pair(conns, request, answer, window, by=None):
    w = int(window * 1e9)
    groups = defaultdict(lambda: {"n": 0, "paired": 0, "delays": []})
    answers = unanswered = 0
    for items in conns.values():
        used = set()
        for i, m in enumerate(items):
            if answer.matches(m):
                answers += 1
            if not request.matches(m):
                continue
            group = groups[fields_of(m).get(by) if by else request.text]
            group["n"] += 1
            for j in range(i + 1, len(items)):
                a = items[j]
                if a.time_ns - m.time_ns > w:
                    break
                if j not in used and answer.matches(a):
                    used.add(j)
                    group["paired"] += 1
                    group["delays"].append((a.time_ns - m.time_ns) / 1e6)
                    break
        unanswered += sum(1 for j, a in enumerate(items) if answer.matches(a) and j not in used)
    out = [f"{request.text} -> {answer.text} within {window} s; {answers} answers in all, "
           f"{unanswered} not after a request",
           f"| {by or 'request'} | requests | answered | p10 ms | median ms | p90 ms |", "|---|---:|---:|---:|---:|---:|"]
    for key, g in sorted(groups.items(), key=lambda kv: -kv[1]["n"]):
        q = quantiles(g["delays"]) if g["delays"] else ("", "", "")
        out.append(f"| {key} | {g['n']} | {g['paired']}/{g['n']} | "
                   + " | ".join(f"{v:.1f}" if v != "" else "" for v in q) + " |")
    return "\n".join(out)


# --- show / values ------------------------------------------------------------------------------------

def show(conns, specs, before, after, with_fields, limit, only_conn=None):
    """Each occurrence on one line, or with --before/--after a block of its connection's neighbours."""
    hits = sorted((m.time_ns, conn, i) for conn, items in conns.items() for i, m in enumerate(items)
                  if (only_conn is None or conn[1] == only_conn) and any(s.matches(m) for s in specs))
    context = before or after
    out = []
    for t, conn, i in hits[:limit]:
        items = conns[conn]
        if context:
            out.append(f"===== {stamp(t)} {Path(conn[0]).name} conn {conn[1]}")
        for j in range(max(0, i - before), min(len(items), i + after + 1)):
            m = items[j]
            where = f"{(m.time_ns - t) / 1e6:+10.0f} ms" if context else f"{stamp(t)} conn {conn[1]:>3}"
            line = f"{'*' if j == i else ' '} {where} {m.label:>7} {m.name or '':<28} {m.length:>6}"
            fields = fields_of(m) if with_fields and m.body_hex else None
            out.append(line + (" " + brief(fields) if fields else ""))
    if len(hits) > limit:
        out.append(f"... {len(hits) - limit} more (--limit)")
    return "\n".join(out)


def values(conns, spec, field):
    counts, changes = Counter(), Counter()
    for items in conns.values():
        last = None
        for m in items:
            if spec.matches(m):
                value = fields_of(m).get(field)
                value = tuple(value) if isinstance(value, list) else value
                counts[value] += 1
                changes[(last, value)] += 1
                last = value
    out = [f"{spec.text} {field}: value counts", *(f"  {v}: {n}" for v, n in counts.most_common(20)),
           "previous -> value within a connection (None = first)",
           *(f"  {a} -> {b}: {n}" for (a, b), n in changes.most_common(20))]
    return "\n".join(out)


# --- who: whose id leads a message --------------------------------------------------------------------

# the server messages that say who is in the room (bodies kept for who())
ROOM_TYPES = {("S", 0x22D), ("S", 0x22E), ("S", 0x452), ("S", 0x471), ("S", 0x209), ("S", 0x1A9)}


def who(conns, spec, offset=2):
    """Is the u32 at `offset` of each message own character / player in the room / one who left / NPC / drop?"""
    def u32(m, at):
        b = m.body
        return struct.unpack_from("<I", b, at)[0] if len(b) >= at + 4 else None

    kinds = Counter()
    for items in conns.values():
        # own character: the id of S 0x209 with bytes 6-7 = 01 01, sent for you once per map load
        own = Counter(u32(m, 2) for m in items if (m.side, m.opcode) == ("S", 0x209) and m.body[6:8] == b"\1\1")
        own = own.most_common(1)[0][0] if own else None
        room, ever, npcs, drops = set(), set(), set(), set()
        for m in items:
            key = (m.side, m.opcode)
            if key == ("S", 0x1A9):   # set_field: a new map
                room, npcs, drops = set(), set(), set()
            elif key == ("S", 0x22D):
                room.add(u32(m, 6))
                ever.add(u32(m, 6))
            elif key == ("S", 0x22E):
                room.discard(u32(m, 2))
            elif key == ("S", 0x452):
                npcs.add(u32(m, 2))
            elif key == ("S", 0x471):
                drops.add(u32(m, 4))
            if spec.matches(m):
                i = u32(m, offset)
                kinds["own" if i == own else "room" if i in room else "left_room" if i in ever
                      else "npc" if i in npcs else "drop" if i in drops else "other"] += 1
    total = sum(kinds.values())
    return f"{spec.text}: u32 at offset {offset} of {total} messages\n" + "\n".join(
        f"  {kind}: {n} ({100 * n / total:.0f}%)" for kind, n in kinds.most_common())


# --- input rate -----------------------------------------------------------------------------------------

def input_rate(path, big=8000):
    """Do analytics uploads come sooner when there is more input? (C 0x9c counts input events per 10 s.)"""
    import json
    analytics, posts = set(), []
    with open(path, encoding="utf-8", errors="replace") as source:
        for line in source:
            if line.startswith('{"kind":"tls_client_hello"'):
                record = json.loads(line)
                if record.get("sni") == ANALYTICS_SNI:
                    analytics.add(record["conn"])
            elif line.startswith('{"kind":"data"') and '"client_to_server"' in line:
                record = json.loads(line)
                if record["conn"] in analytics and len(record["hex"]) // 2 > big:
                    posts.append([record["time_ns"], len(record["hex"]) // 2])
    inputs = sorted((m.time_ns, fields_of(m).get("input_events_a", 0))
                    for m in messages([path]) if (m.side, m.opcode) == ("C", 0x9c))
    merged = []   # records under 1 s apart are one upload
    for t, size in sorted(posts):
        if merged and t - merged[-1][0] < 1e9:
            merged[-1][1] += size
        else:
            merged.append([t, size])
    times = [t for t, _ in inputs]
    rows = []
    for (t0, _), (t1, _) in zip(merged, merged[1:]):
        gap = (t1 - t0) / 1e9
        if gap > 2000:   # a pause in the recording, not an upload interval
            continue
        n = sum(a for _, a in inputs[bisect.bisect_right(times, t0):bisect.bisect_right(times, t1)])
        rows.append((gap, n / gap))
    if len(rows) < 8 or not inputs:
        return f"too little data: {len(merged)} uploads, {len(inputs)} C 0x9c"
    rows.sort(key=lambda r: r[1])
    q = len(rows) // 4
    out = [f"{len(merged)} analytics uploads over {big} bytes, {len(inputs)} C 0x9c; "
           f"inputs per second overall {sum(a for _, a in inputs) / ((times[-1] - times[0]) / 1e9):.2f}",
           f"correlation(gap, input rate) {statistics.correlation([g for g, _ in rows], [r for _, r in rows]):.3f}",
           "| input-rate quarter | inputs/s (median) | gap s (median) |", "|---|---:|---:|"]
    for i in range(4):
        part = rows[i * q:(i + 1) * q] if i < 3 else rows[3 * q:]
        out.append(f"| {i + 1} | {statistics.median(r[1] for r in part):.2f} | {statistics.median(r[0] for r in part):.0f} |")
    return "\n".join(out)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("periods", "around", "pair", "show", "values", "who", "input-rate"):
        p = sub.add_parser(name)
        p.add_argument("recordings", nargs="+")
        if name in ("periods", "show"):
            p.add_argument("--type", action="append", type=Spec, default=[], required=name == "show")
        if name in ("around", "values", "who"):
            p.add_argument("--type", type=Spec, required=True)
        if name in ("around", "pair"):
            p.add_argument("--window", type=float, default=2.0)
    sub.choices["periods"].add_argument("--min", type=int, default=1, help="leave out types seen fewer times")
    sub.choices["around"].add_argument("--top", type=int, default=12)
    sub.choices["pair"].add_argument("--by", help="group requests by this field of theirs")
    sub.choices["show"].add_argument("--before", type=int, default=0)
    sub.choices["show"].add_argument("--after", type=int, default=0)
    sub.choices["show"].add_argument("--fields", action="store_true")
    sub.choices["show"].add_argument("--limit", type=int, default=50)
    sub.choices["show"].add_argument("--conn", type=int, help="only this connection number (e.g. the login server's)")
    sub.choices["values"].add_argument("--field", required=True)
    sub.choices["who"].add_argument("--offset", type=int, default=2, help="body offset of the u32 id (opcode included)")
    args = parser.parse_args(argv)

    if args.command == "input-rate":
        return "\n".join(input_rate(p) for p in args.recordings)
    if args.command == "pair":
        if len(args.recordings) < 3:
            parser.error("pair: REC... REQUEST ANSWER")
        *args.recordings, request, answer = args.recordings
        request, answer = Spec(request), Spec(answer)
        return pair(load(args.recordings, [request.key, answer.key]), request, answer, args.window, args.by)
    specs = args.type if isinstance(args.type, list) else [args.type]
    conns = load(args.recordings, [s.key for s in specs] + list(ROOM_TYPES))
    if args.command == "periods":
        return periods(conns, specs, args.min)
    if args.command == "around":
        return around(conns, args.type, args.window, args.top)
    if args.command == "show":
        return show(conns, specs, args.before, args.after, args.fields, args.limit, args.conn)
    if args.command == "who":
        return who(conns, args.type, args.offset)
    return values(conns, args.type, args.field)


if __name__ == "__main__":
    print(main())
