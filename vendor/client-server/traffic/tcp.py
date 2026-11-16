"""Sequence-aware TCP reconstruction.

The assembler keeps the first-seen byte for an offset (what the receiver had
available first), records retransmissions and conflicting overlaps instead of
silently overwriting them, and never fills a hole with zeros. Frames or HTTP
messages that cross a hole are marked incomplete.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from .pcap import Packet
from .util import merge_ranges, subtract_ranges


def signed32(value):
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def _is_local(address):
    try:
        value = ipaddress.ip_address(address)
    except (ValueError, TypeError):
        return False
    return value.is_private or value.is_loopback or value.is_link_local


@dataclass
class Segment:
    index: int
    packet: Packet
    seq: int
    rel_start: int
    payload: bytes
    classification: str = "new"
    new_bytes: int = 0
    overlap_bytes: int = 0
    conflict_bytes: int = 0
    before_base: bool = False

    @property
    def rel_end(self):
        return self.rel_start + len(self.payload)


@dataclass
class Stream:
    src: str
    sport: int
    dst: str
    dport: int
    segments: list[Segment] = field(default_factory=list)
    data: bytearray = field(default_factory=bytearray)
    coverage: list[tuple[int, int]] = field(default_factory=list)
    base_seq: int | None = None
    captured_payload_bytes: int = 0
    retransmissions: int = 0
    overlap_bytes: int = 0
    conflict_bytes: int = 0
    out_of_order_segments: int = 0
    before_base_segments: int = 0
    packet_count: int = 0
    first_time_ns: int | None = None
    last_time_ns: int | None = None

    @property
    def key(self):
        return (self.src, self.sport, self.dst, self.dport)

    def gaps(self):
        if not self.data:
            return []
        return subtract_ranges((0, len(self.data)), self.coverage)

    def runs(self):
        return list(self.coverage)

    def missing_ranges(self, start, end):
        return subtract_ranges((start, end), self.coverage)

    def slice_covered(self, start, end):
        if start < 0 or end > len(self.data) or start >= end:
            return None
        if self.missing_ranges(start, end):
            return None
        return bytes(self.data[start:end])

    def contributing_segments(self, start, end):
        result = []
        for segment in self.segments:
            if segment.rel_start < end and segment.rel_end > start:
                result.append(segment)
        return result

    def first_time_for(self, start, end):
        times = [
            segment.packet.time_ns for segment in self.contributing_segments(start, end)
            if segment.packet.time_ns is not None
        ]
        return min(times) if times else None

    def last_time_for(self, start, end):
        times = [
            segment.packet.time_ns for segment in self.contributing_segments(start, end)
            if segment.packet.time_ns is not None
        ]
        return max(times) if times else None

    def summary(self):
        return {
            "src": self.src,
            "sport": self.sport,
            "dst": self.dst,
            "dport": self.dport,
            "base_seq": self.base_seq,
            "packet_count": self.packet_count,
            "segments": len(self.segments),
            "payload_bytes_captured": self.captured_payload_bytes,
            "unique_bytes": len(self.data),
            "coverage": self.coverage,
            "gaps": self.gaps(),
            "gap_bytes": sum(end - start for start, end in self.gaps()),
            "retransmissions": self.retransmissions,
            "overlap_bytes": self.overlap_bytes,
            "conflict_bytes": self.conflict_bytes,
            "out_of_order_segments": self.out_of_order_segments,
            "before_base_segments": self.before_base_segments,
            "first_time_ns": self.first_time_ns,
            "last_time_ns": self.last_time_ns,
        }


@dataclass
class Flow:
    protocol: str
    endpoints: tuple
    packets: list[Packet] = field(default_factory=list)
    client: tuple | None = None
    server: tuple | None = None
    client_confidence: str = "unknown"
    client_reasons: list[str] = field(default_factory=list)
    c2s: Stream | None = None
    s2c: Stream | None = None
    connection_index: int = 0
    process: dict | None = None
    sockets: list[dict] = field(default_factory=list)

    @property
    def client_key(self):
        return (self.client, self.server)

    def summary(self):
        return {
            "protocol": self.protocol,
            "endpoints": list(self.endpoints),
            "client": list(self.client) if self.client else None,
            "server": list(self.server) if self.server else None,
            "client_confidence": self.client_confidence,
            "client_reasons": self.client_reasons,
            "connection_index": self.connection_index,
            "process": self.process,
            "sockets": self.sockets,
            "c2s": self.c2s.summary() if self.c2s else None,
            "s2c": self.s2c.summary() if self.s2c else None,
        }


def _split_at_syn(packets):
    """Split a reused 4-tuple at a fresh SYN (no ACK) after traffic has begun."""
    groups = [[]]
    seen_data = False
    for packet in packets:
        flags = (packet.tcp or {}).get("flags", {})
        if flags.get("syn") and not flags.get("ack") and seen_data and groups[-1]:
            groups.append([])
            seen_data = False
        groups[-1].append(packet)
        if packet.payload:
            seen_data = True
    return [group for group in groups if group]


def _infer_client(packets, explicit_client=None):
    if explicit_client:
        host, port = explicit_client
        return (host, int(port)), "explicit", ["client endpoint supplied by the caller"]
    endpoints = []
    for packet in packets:
        if packet.src is None:
            continue
        for endpoint in ((packet.src, packet.sport), (packet.dst, packet.dport)):
            if endpoint not in endpoints:
                endpoints.append(endpoint)
    if len(endpoints) != 2:
        return None, "unknown", ["not exactly two endpoints in the flow"]
    a, b = endpoints
    scores = {a: 0, b: 0}
    reasons = []
    for packet in packets:
        flags = (packet.tcp or {}).get("flags", {})
        source = (packet.src, packet.sport)
        if flags.get("syn") and not flags.get("ack"):
            scores[source] += 10
            reasons.append(f"SYN from {source[0]}:{source[1]}")
        if packet.epb_direction == "outbound":
            scores[source] += 8
        elif packet.epb_direction == "inbound":
            scores[(packet.dst, packet.dport)] += 8
    local_a = _is_local(a[0])
    local_b = _is_local(b[0])
    if local_a != local_b:
        scores[a if local_a else b] += 3
        reasons.append("one endpoint is a private/loopback address")
    # A well-known service port is normally the server side. This is a tie-breaker
    # only; a capture with SYN or direction flags never needs it.
    from .live import is_service_port
    service_a = is_service_port(a[1])
    service_b = is_service_port(b[1])
    if service_a != service_b:
        scores[b if service_a else a] += 2
        reasons.append("one endpoint uses a well-known service port")
    if scores[a] == scores[b]:
        return None, "ambiguous", reasons + ["no SYN, capture direction, or local-address evidence"]
    client = a if scores[a] > scores[b] else b
    confidence = "strong" if abs(scores[a] - scores[b]) >= 8 else "weak"
    return client, confidence, reasons


def _assemble_stream(packets, src, sport, dst, dport):
    stream = Stream(src=src, sport=sport, dst=dst, dport=dport)
    relevant = [
        packet for packet in packets
        if packet.protocol == "tcp" and packet.src == src and packet.sport == sport
        and packet.dst == dst and packet.dport == dport
    ]
    stream.packet_count = len(relevant)
    payload_packets = [packet for packet in relevant if packet.payload]
    if not payload_packets:
        return stream
    first_payload = payload_packets[0]
    reference = first_payload.tcp["seq"]
    deltas = [signed32(packet.tcp["seq"] - reference) for packet in payload_packets]
    syn = next(
        (
            packet for packet in relevant
            if packet.tcp.get("flags", {}).get("syn") and not packet.tcp.get("flags", {}).get("ack")
        ),
        None,
    )
    if syn is not None:
        base = (syn.tcp["seq"] + 1) & 0xFFFFFFFF
    else:
        base = (reference + min(deltas)) & 0xFFFFFFFF
    stream.base_seq = base
    max_end = 0
    for packet in payload_packets:
        seq = packet.tcp["seq"]
        rel = signed32(seq - base)
        if packet.tcp.get("flags", {}).get("syn"):
            rel += 1
        payload = packet.payload
        segment = Segment(
            index=len(stream.segments),
            packet=packet,
            seq=seq,
            rel_start=rel,
            payload=payload,
        )
        stream.segments.append(segment)
        stream.captured_payload_bytes += len(payload)
        if packet.time_ns is not None:
            stream.first_time_ns = (
                packet.time_ns if stream.first_time_ns is None else min(stream.first_time_ns, packet.time_ns)
            )
            stream.last_time_ns = (
                packet.time_ns if stream.last_time_ns is None else max(stream.last_time_ns, packet.time_ns)
            )
        if rel < 0:
            segment.before_base = True
            stream.before_base_segments += 1
            continue
        end = rel + len(payload)
        if end > len(stream.data):
            stream.data.extend(b"\x00" * (end - len(stream.data)))
        overlap = []
        for cov_start, cov_end in stream.coverage:
            start = max(rel, cov_start)
            stop = min(end, cov_end)
            if start < stop:
                overlap.append((start, stop))
        covered_bytes = sum(stop - start for start, stop in overlap)
        conflict = 0
        for start, stop in overlap:
            current = stream.data[start:stop]
            incoming = payload[start - rel:stop - rel]
            if current != incoming:
                conflict += sum(1 for left, right in zip(current, incoming) if left != right)
        segment.overlap_bytes = covered_bytes
        segment.conflict_bytes = conflict
        if covered_bytes == 0:
            segment.classification = "new"
        elif covered_bytes == len(payload):
            segment.classification = "retransmission" if conflict == 0 else "conflict"
        else:
            segment.classification = "partial_overlap"
        if conflict:
            stream.conflict_bytes += conflict
        if covered_bytes:
            stream.overlap_bytes += covered_bytes
            if covered_bytes == len(payload) and conflict == 0:
                stream.retransmissions += 1
        # First-seen wins; a conflict is recorded but never silently replaced.
        for new_start, new_end in subtract_ranges((rel, end), overlap):
            stream.data[new_start:new_end] = payload[new_start - rel:new_end - rel]
            segment.new_bytes += new_end - new_start
        if rel < max_end:
            stream.out_of_order_segments += 1
        stream.coverage = merge_ranges(stream.coverage + [(rel, end)])
        max_end = max(max_end, end)
    return stream


def assemble(packets, explicit_client=None):
    """Return (flows, notes). One Flow per TCP connection attempt/4-tuple."""
    notes = []
    groups = {}
    for packet in packets:
        if packet.protocol != "tcp" or packet.src is None:
            continue
        endpoints = tuple(sorted([
            (packet.src, packet.sport),
            (packet.dst, packet.dport),
        ]))
        groups.setdefault(endpoints, []).append(packet)
    flows = []
    for endpoints, flow_packets in groups.items():
        flow_packets.sort(key=lambda packet: (
            packet.time_ns if packet.time_ns is not None else 0,
            packet.source_file,
            packet.source_index,
        ))
        for connection_index, group in enumerate(_split_at_syn(flow_packets)):
            client, confidence, reasons = _infer_client(group, explicit_client)
            if client is None:
                notes.append({
                    "reason": "client_direction_ambiguous",
                    "endpoints": [list(endpoint) for endpoint in endpoints],
                    "detail": reasons,
                })
                flow = Flow(
                    protocol="tcp",
                    endpoints=endpoints,
                    packets=group,
                    client=None,
                    server=None,
                    client_confidence=confidence,
                    client_reasons=reasons,
                    connection_index=connection_index,
                )
                flows.append(flow)
                continue
            server = endpoints[0] if endpoints[1] == client else endpoints[1]
            flow = Flow(
                protocol="tcp",
                endpoints=endpoints,
                packets=group,
                client=client,
                server=server,
                client_confidence=confidence,
                client_reasons=reasons,
                connection_index=connection_index,
            )
            flow.c2s = _assemble_stream(group, client[0], client[1], server[0], server[1])
            flow.s2c = _assemble_stream(group, server[0], server[1], client[0], client[1])
            # Attribution comes from the capture's socket owner comments. Multiple
            # owners on one 4-tuple are kept as candidates, never collapsed silently.
            processes = {}
            sockets = {}
            for packet in group:
                if packet.process:
                    key = (packet.process.get("pid"), packet.process.get("name"))
                    processes[key] = packet.process
                if packet.socket:
                    sockets[(packet.socket.get("inode"), packet.socket.get("cookie"))] = packet.socket
            if len(processes) == 1:
                flow.process = next(iter(processes.values()))
            elif processes:
                flow.process = {
                    "pid": None,
                    "name": None,
                    "attribution": "ambiguous",
                    "candidates": list(processes.values()),
                }
            flow.sockets = list(sockets.values())
            flows.append(flow)
    return flows, notes
