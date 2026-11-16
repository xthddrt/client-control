"""Controlled transparent proxy for the game's client<->server TCP connections.

analysis/game-proxy.sh redirects this PC's outgoing TCP to the game's server
ports here (nftables REDIRECT). For each connection the proxy:

- finds the real destination (SO_ORIGINAL_DST) and the local program that
  opened it, and evaluates the filter policy: a matching "drop" refuses the
  connection; anything else is forwarded;
- forwards every byte unchanged in both directions and records it;
- decodes both directions as they arrive (stream.ConnectionDecoder): every
  message with its real opcode, or the reason it could not be decoded.

Single game messages are never dropped or changed here: the send cipher's IV
rolls once per frame, so removing one frame would break every later frame.
A matching message rule is recorded with "enforced": false; message blocking
belongs to the in-process SendPacket filter (analysis/capture-outgoing.sh).

"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import sys
import struct
import time
from collections import Counter
from pathlib import Path

from .policy import evaluate
from .protocol import name_of, purpose_of
from .sockets import SocketOwnerResolver
from .stream import ConnectionDecoder

SO_ORIGINAL_DST = 80


def original_destination(sock):
    raw = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    port, address = struct.unpack_from("!2xH4s", raw)
    return socket.inet_ntoa(address), port


class Recorder:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = open(self.path, "a", encoding="utf-8", buffering=1)
        os.chmod(self.path, 0o600)   # raw game traffic: tokens and account data

    failed = None

    def write(self, record):
        """Never raises: a failed write (disk full) stops recording, not forwarding."""
        if self.failed:
            return
        record.setdefault("time_ns", time.time_ns())
        try:
            self.handle.write(json.dumps(record, separators=(",", ":")) + "\n")
        except (OSError, ValueError) as error:
            self.failed = str(error)
            print(f"RECORDING STOPPED: {error}; connections are still forwarded", file=sys.stderr, flush=True)

    def close(self):
        self.handle.close()


class GameProxy:
    def __init__(self, recorder, policy=None, mark=None, resolve=original_destination,
                 owner=None):
        self.recorder = recorder
        self.policy = policy
        self.mark = mark
        self.resolve = resolve
        # A fresh resolver per lookup: its cache is keyed by address, and ports get reused.
        self.owner = owner or (lambda address: SocketOwnerResolver().lookup(address))
        self.listen_address = None
        self.next_id = 1
        self.active = set()   # handler tasks of the connections still open

    def _decide(self, view):
        if self.policy is None:
            return None
        decision = evaluate(self.policy, view)
        return {"rule_id": decision["rule_id"], "action": decision["action"],
                "reason": decision["reason"]}

    async def handle(self, reader, writer):
        task = asyncio.current_task()
        self.active.add(task)
        try:
            await self._handle(reader, writer)
        finally:
            self.active.discard(task)

    async def _handle(self, reader, writer):
        conn = self.next_id
        self.next_id += 1
        client_sock = writer.get_extra_info("socket")
        client = writer.get_extra_info("peername")[:2]
        record = {"conn": conn, "client": list(client)}
        try:
            destination = self.resolve(client_sock)
        except OSError as error:
            self.recorder.write({"kind": "connection_refused", **record,
                                 "reason": f"no original destination: {error}"})
            writer.close()
            return
        if tuple(destination) == tuple(self.listen_address or ()):
            self.recorder.write({"kind": "connection_refused", **record,
                                 "reason": "connection made to the proxy itself"})
            writer.close()
            return
        # The local socket still exists while the client waits, so its owner is findable.
        process = await asyncio.get_running_loop().run_in_executor(None, self.owner, client)
        record.update(destination=list(destination), process=process)
        transport = {"protocol": "tcp", "destination": {"ip": destination[0], "port": destination[1]}}
        decision = self._decide({"message_id": f"conn-{conn}", "process": process,
                                 "transport": transport})
        if decision and decision["action"] == "drop":
            self.recorder.write({"kind": "connection_refused", **record, "decision": decision})
            writer.transport.abort()
            return
        upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            upstream.setblocking(False)
            if self.mark is not None:
                upstream.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, self.mark)
            await asyncio.get_running_loop().sock_connect(upstream, tuple(destination))
            up_reader, up_writer = await asyncio.open_connection(sock=upstream)
        except OSError as error:
            upstream.close()
            self.recorder.write({"kind": "connection_failed", **record, "error": str(error),
                                 "decision": decision})
            writer.transport.abort()
            return
        for sock in (client_sock, upstream):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.recorder.write({"kind": "connection_open", **record, "decision": decision})
        decoder = ConnectionDecoder()
        totals = Counter()

        def observe(direction, data, time_ns):
            try:
                decode(direction, data, time_ns)
            except Exception as error:   # decoding or a policy must never stop forwarding
                self.recorder.write({"kind": "decode_notice", "conn": conn, "direction": direction,
                                     "status": "decoder_error", "detail": repr(error)})
                observing[0] = False

        observing = [True]

        def decode(direction, data, time_ns):
            for item in decoder.feed(direction, data, time_ns):
                item["conn"] = conn
                if item["kind"] == "message" and self.policy is not None:
                    message = {"message_id": f"conn-{conn}-{direction}-{item['index']}",
                               "process": process, "transport": transport,
                               "message": {"protocol": "maplestory_game",
                                           "raw_bytes_hex": item["body_hex"],
                                           "type": {"opcode": item["opcode"]}}}
                    found = self._decide(message)
                    if found and found["rule_id"]:
                        item["decision"] = {**found, "enforced": False}
                self.recorder.write(item)

        async def pump(src, dst, direction):
            try:
                while data := await src.read(65536):
                    dst.write(data)           # forward first; recording never delays the game
                    time_ns = time.time_ns()
                    totals[direction] += len(data)
                    self.recorder.write({"kind": "data", "conn": conn, "direction": direction,
                                         "time_ns": time_ns, "hex": data.hex()})
                    if observing[0]:
                        observe(direction, data, time_ns)
                    await dst.drain()
                if dst.can_write_eof():
                    dst.write_eof()
            except Exception as error:   # never leave one direction stuck: end both
                totals[direction + "_error"] = repr(error)
                dst.transport.abort()

        await asyncio.gather(
            pump(reader, up_writer, "client_to_server"),
            pump(up_reader, writer, "server_to_client"),
        )
        for side in (writer, up_writer):
            side.close()
        self.recorder.write({"kind": "connection_close", "conn": conn,
                             "bytes": dict(totals), "decode": decoder.summary()})

    async def serve_until_stopped(self, host, port, stop, say=print):
        """Serve until `stop` is set; then take no new connections and let the open ones end on their own
        (a game connection cut here drops the game to its login screen: 2026-11-15 13:21). `stop` set a
        second time cuts the ones still open."""
        server = await self.serve(host, port)
        say(f"LISTENING {host}:{port} RECORDING {self.recorder.path}")
        await stop.wait()
        server.close()
        if self.active:
            stop.clear()
            self.recorder.write({"kind": "proxy_draining", "open": len(self.active)})
            say(f"DRAINING {len(self.active)} open connection(s): no new ones taken; they end on their own "
                "(stop again to cut them)")
            drained = asyncio.ensure_future(asyncio.gather(*self.active, return_exceptions=True))
            second = asyncio.ensure_future(stop.wait())
            await asyncio.wait([drained, second], return_when=asyncio.FIRST_COMPLETED)
            second.cancel()
        return len(self.active)

    async def serve(self, host, port):
        server = await asyncio.start_server(self.handle, host, port)
        self.listen_address = server.sockets[0].getsockname()[:2]
        self.recorder.write({"kind": "proxy_start", "listen": list(self.listen_address),
                             "mark": self.mark,
                             "policy": self.policy.summary() if self.policy else None})
        return server


def decode_recording(source, target, header_search=True):
    """Decode a recording's data records again with the current decoders.

    Every non-decode record is kept as it is; message, handshake, opcode_table,
    tls_client_hello and decode_notice records are rebuilt. header_search is on:
    offline time does not matter, and it decodes connections joined mid-way.
    """
    decoders = {}
    rebuilt = {"message", "handshake", "opcode_table", "tls_client_hello", "decode_notice"}
    with open(source, encoding="utf-8") as src, open(target, "w", encoding="utf-8") as dst:
        os.chmod(target, 0o600)
        for line in src:
            record = json.loads(line)
            if record["kind"] in rebuilt:
                continue
            if record["kind"] == "connection_close" and record["conn"] in decoders:
                record["decode"] = decoders[record["conn"]].summary()
            dst.write(json.dumps(record, separators=(",", ":")) + "\n")
            if record["kind"] != "data":
                continue
            decoder = decoders.setdefault(record["conn"], ConnectionDecoder(header_search))
            for item in decoder.feed(record["direction"], bytes.fromhex(record["hex"]),
                                     record["time_ns"]):
                item["conn"] = record["conn"]
                dst.write(json.dumps(item, separators=(",", ":")) + "\n")
    return {conn: decoder.summary() for conn, decoder in decoders.items()}


def report(path):
    """Per-connection summary of a recording, as text: both directions' opcodes and names."""
    conns = {}
    for line in open(path, encoding="utf-8"):
        record = json.loads(line)
        conn = record.get("conn")
        if conn is None:
            continue
        item = conns.setdefault(conn, {"opcodes": Counter(), "sizes": {}, "events": []})
        kind = record["kind"]
        if kind == "message":
            key = (record["direction"], record["opcode"] or f"wire {record.get('wire_opcode')}")
            item["opcodes"][key] += 1
            item["sizes"].setdefault(key, set()).add(record["length"])
        elif kind != "data":
            item["events"].append(record)
    lines = []
    for conn, item in sorted(conns.items()):
        opened = next((e for e in item["events"] if e["kind"].startswith("connection_")
                       and e["kind"] != "connection_close"), {})
        closed = next((e for e in item["events"] if e["kind"] == "connection_close"), {})
        process = opened.get("process") or {}
        lines.append(f"conn {conn}: {opened.get('kind', '?')} -> "
                     f"{':'.join(map(str, opened.get('destination', ['?'])))} "
                     f"by {process.get('name')} (pid {process.get('pid')})"
                     + (f", rule {opened['decision']['rule_id']}: {opened['decision']['action']}"
                        if opened.get("decision") and opened["decision"]["rule_id"] else ""))
        if closed:
            lines.append(f"  bytes {closed.get('bytes')}")
            decode = closed.get("decode") or {}
            for direction in ("client_to_server", "server_to_client"):
                side = decode.get(direction)
                if side:
                    lines.append(f"  {direction}: {side['messages']} messages, {side['status']}, "
                                 f"key {side['key_source']}, cipher {side['cipher']}")
        for event in item["events"]:
            if event["kind"] == "decode_notice":
                lines.append(f"  notice {event.get('direction')}: {event['status']} ({event['detail']})")
            elif event["kind"] == "tls_client_hello":
                lines.append(f"  TLS to {event['sni']}")
            elif event["kind"] == "opcode_table":
                lines.append(f"  opcode table: {event['entries']} client opcodes renamed")
        for (direction, op), count in item["opcodes"].most_common(20):
            sizes = sorted(item["sizes"][(direction, op)])
            arrow = "C>S" if direction == "client_to_server" else "S>C"
            known = op.startswith("0x")
            name = (name_of(direction, int(op, 16))[0] if known else None) or ""
            purpose = (purpose_of(direction, int(op, 16))[0] if known else None) or ""
            lines.append(f"  {arrow} {op:>8} {name:<28} {purpose:<16} x{count} sizes {sizes[:6]}"
                         f"{' ...' if len(sizes) > 6 else ''}")
    return "\n".join(lines) + "\n"
