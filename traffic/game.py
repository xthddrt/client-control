"""MapleStory frame extraction, transport decryption, and plaintext join."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from .decode import GAME_OPCODES, alias_to_opcode
from .transport import (
    SEND_MASK,
    decrypt_body,
    get_new_iv,
    high_short,
    seed_iv,
)

MAX_FRAME_BYTES = 0x10000


@dataclass
class Frame:
    index: int
    stream: object
    offset: int
    w0: int
    w1: int
    length: int
    ciphertext: bytes
    wire_frame: bytes
    segments: list
    first_time_ns: int | None
    last_time_ns: int | None
    split: bool = False
    combined: bool = False

    @property
    def source_refs(self):
        return [
            {
                "source": segment.packet.source_file,
                "source_index": segment.packet.source_index,
                "time_ns": segment.packet.time_ns,
                "seq": segment.seq,
                "classification": segment.classification,
                "process": segment.packet.process,
            }
            for segment in self.segments
        ]

    def summary(self):
        return {
            "frame_index": self.index,
            "stream_offset": self.offset,
            "header": {"w0": self.w0, "w1": self.w1, "length": self.length},
            "header_hex": self.wire_frame[:4].hex(),
            "ciphertext_hex": self.ciphertext.hex(),
            "wire_frame_hex": self.wire_frame.hex(),
            "first_time_ns": self.first_time_ns,
            "last_time_ns": self.last_time_ns,
            "split": self.split,
            "combined": self.combined,
            "segments": self.source_refs,
        }


@dataclass
class FrameDecryption:
    frame_index: int
    status: str
    iv: str | None = None
    synced: bool | None = None
    alias: int | None = None
    opcode: int | None = None
    opcode_confidence: str | None = None
    plaintext: bytes | None = None
    layer: int | None = None
    error: str | None = None
    evidence: list = field(default_factory=list)

    def summary(self):
        return {
            "frame_index": self.frame_index,
            "status": self.status,
            "iv": self.iv,
            "synced": self.synced,
            "wire_alias": f"0x{self.alias:x}" if self.alias is not None else None,
            "opcode": f"0x{self.opcode:x}" if self.opcode is not None else None,
            "opcode_confidence": self.opcode_confidence,
            "plaintext_hex": self.plaintext.hex() if self.plaintext is not None else None,
            "layer": self.layer,
            "error": self.error,
            "evidence": list(self.evidence),
        }


@dataclass
class Decryption:
    status: str
    mask: int = SEND_MASK
    seed_index: int | None = None
    seed_iv: str | None = None
    start_layer: int | None = None
    layer_confidence: str | None = None
    layer_scores: dict | None = None
    frames: list[FrameDecryption] = field(default_factory=list)
    notices: list[dict] = field(default_factory=list)

    def by_index(self):
        return {frame.frame_index: frame for frame in self.frames}

    def summary(self):
        return {
            "status": self.status,
            "mask": self.mask,
            "seed_index": self.seed_index,
            "seed_iv": self.seed_iv,
            "start_layer": self.start_layer,
            "layer_confidence": self.layer_confidence,
            "layer_scores": self.layer_scores,
            "notices": self.notices,
            "frames": [frame.summary() for frame in self.frames],
        }


def parse_frames(stream):
    """Extract complete [w0 w1 body] frames from covered runs of a stream."""
    frames = []
    notices = []
    for run_start, run_end in stream.runs():
        offset = run_start
        while offset + 4 <= run_end:
            w0, w1 = struct.unpack_from("<HH", stream.data, offset)
            length = w0 ^ w1
            if length < 2 or length > MAX_FRAME_BYTES:
                notices.append({
                    "reason": "invalid_frame_length",
                    "stream_offset": offset,
                    "declared_length": length,
                    "note": "no resynchronisation attempted; the remaining stream in this run is not parsed",
                })
                break
            expected_end = offset + 4 + length
            if expected_end > run_end:
                missing = stream.missing_ranges(offset, expected_end)
                if not missing and expected_end > len(stream.data):
                    missing = [(len(stream.data), expected_end)]
                notices.append({
                    "reason": "incomplete_frame",
                    "stream_offset": offset,
                    "declared_length": length,
                    "available_body_bytes": max(0, run_end - offset - 4),
                    "missing_ranges": missing,
                })
                break
            ciphertext = bytes(stream.data[offset + 4:expected_end])
            wire_frame = bytes(stream.data[offset:expected_end])
            segments = stream.contributing_segments(offset, expected_end)
            frame = Frame(
                index=len(frames),
                stream=stream,
                offset=offset,
                w0=w0,
                w1=w1,
                length=length,
                ciphertext=ciphertext,
                wire_frame=wire_frame,
                segments=segments,
                first_time_ns=stream.first_time_for(offset, expected_end),
                last_time_ns=stream.last_time_for(offset, expected_end),
                split=len(segments) > 1,
            )
            # A pure retransmission does not split a message; a segment that
            # contributes new bytes does. Keep every segment in source_refs.
            effective = [
                segment for segment in segments
                if segment.classification != "retransmission" or segment.new_bytes > 0
            ]
            frame.split = len(effective) > 1
            frames.append(frame)
            offset = expected_end
        if offset < run_end:
            notices.append({
                "reason": "trailing_or_unparsed_bytes",
                "stream_offset": offset,
                "bytes": run_end - offset,
            })
    usage = {}
    for frame in frames:
        for segment in frame.segments:
            if segment.classification == "retransmission" and segment.new_bytes == 0:
                continue
            usage.setdefault(segment.index, set()).add(frame.index)
    for frame in frames:
        frame.combined = any(len(usage.get(segment.index, ())) > 1 for segment in frame.segments)
    return frames, notices


def _frame_plaintext(frame, iv, layer):
    body = decrypt_body(iv, frame.ciphertext, layer)
    alias = struct.unpack_from("<H", body, 0)[0] if len(body) >= 2 else None
    return body, alias


def _send_index(sends):
    index = {}
    for order, send in enumerate(sends):
        index.setdefault((len(send.body), send.body[2:]), []).append((order, send))
    return index


def _score_layer(frames, seed_index, seed_iv_value, layer, send_index):
    score = 0
    known = 0
    suffix_matches = 0
    iv = seed_iv_value
    for frame in frames[seed_index:seed_index + 24]:
        if (high_short(iv) ^ SEND_MASK) != frame.w0:
            break
        body, alias = _frame_plaintext(frame, iv, layer)
        if alias is not None:
            mapped = alias_to_opcode(alias, len(body))
            if mapped in GAME_OPCODES:
                score += 3
                known += 1
            elif alias < 0x400:
                score += 1
            if send_index:
                if send_index.get((len(body), body[2:])):
                    score += 100
                    suffix_matches += 1
        iv = get_new_iv(iv)
    return {
        "score": score,
        "known_aliases": known,
        "plaintext_suffix_matches": suffix_matches,
    }


def _decrypt_candidate(frames, seed_index, seed_iv_value, layer, layer_scores, plaintext_sends):
    result = Decryption(
        status="seeded",
        seed_index=seed_index,
        seed_iv=seed_iv_value.hex(),
        start_layer=layer,
        layer_confidence="strong" if layer_scores["plaintext_suffix_matches"] else "supported",
        layer_scores=layer_scores,
    )
    current = seed_iv_value
    desynced = False
    for frame in frames:
        if frame.index < seed_index:
            result.frames.append(FrameDecryption(
                frame_index=frame.index,
                status="before_seed",
                error="the unique IV seed starts at a later frame",
            ))
            continue
        if desynced:
            result.frames.append(FrameDecryption(
                frame_index=frame.index,
                status="after_iv_desync",
                error="the IV chain did not match this frame; later frames were not decrypted",
            ))
            continue
        if (high_short(current) ^ SEND_MASK) != frame.w0:
            desynced = True
            result.status = "iv_desync"
            result.notices.append({
                "reason": "iv_desync",
                "frame_index": frame.index,
                "expected_word0": (high_short(current) ^ SEND_MASK),
                "observed_word0": frame.w0,
            })
            result.frames.append(FrameDecryption(
                frame_index=frame.index,
                status="iv_desync",
                iv=current.hex(),
                synced=False,
                error="frame header did not match the rolling IV",
            ))
            continue
        body, alias = _frame_plaintext(frame, current, layer)
        mapped = alias_to_opcode(alias, len(body)) if alias is not None else None
        if mapped is not None:
            opcode = mapped
            confidence = "wire_alias_confirmed"
            evidence = ["docs/guides/PACKETS.md:99"]
        elif alias is not None and alias in GAME_OPCODES:
            opcode = alias
            confidence = "looks_like_plaintext_unverified"
            evidence = ["opcode value matches a known plaintext opcode but no wire-alias mapping exists"]
        else:
            opcode = None
            confidence = "unmapped_wire_opcode"
            evidence = ["first two decrypted bytes are not in the observed alias table"]
        result.frames.append(FrameDecryption(
            frame_index=frame.index,
            status="decrypted",
            iv=current.hex(),
            synced=True,
            alias=alias,
            opcode=opcode,
            opcode_confidence=confidence,
            plaintext=body,
            layer=layer,
            evidence=evidence,
        ))
        current = get_new_iv(current)
    return result


def decrypt_frames(frames, plaintext_sends=None):
    """Recover the IV from consecutive headers and decrypt the frame chain.

    If more than one seed or start layer is equally supported, decryption is
    refused (status ambiguous) instead of choosing one by guesswork.
    """
    if not frames:
        return Decryption(status="no_frames")
    send_index = _send_index(plaintext_sends or [])
    candidates = []
    for index in range(min(len(frames) - 1, 8)):
        seeds = seed_iv(frames[index].w0, frames[index + 1].w0)
        for seed in seeds:
            candidates.append((index, seed))
    if not candidates:
        return Decryption(
            status="no_seed",
            notices=[{"reason": "no unique IV seed from the first eight frame pairs"}],
        )
    unique = {}
    for index, seed in candidates:
        unique[(index, seed)] = (index, seed)
    candidates = list(unique.values())
    scored = []
    for index, seed in candidates:
        layer_scores = {}
        for layer in (0, 1):
            layer_scores[layer] = _score_layer(frames, index, seed, layer, send_index)
        best_layer = max(
            (0, 1),
            key=lambda layer: (
                layer_scores[layer]["plaintext_suffix_matches"],
                layer_scores[layer]["known_aliases"],
                layer_scores[layer]["score"],
                -layer,
            ),
        )
        other_layer = 1 - best_layer
        # A layer is selected only when something distinguishes it from the
        # alternative. Two equal zero scores mean the cipher layer is unknown.
        if (
            layer_scores[best_layer]["score"] == 0
            and layer_scores[other_layer]["score"] == 0
        ):
            scored.append((index, seed, None, layer_scores[best_layer], layer_scores))
            continue
        if (
            layer_scores[best_layer]["score"] == layer_scores[other_layer]["score"]
            and layer_scores[best_layer]["plaintext_suffix_matches"] == 0
        ):
            scored.append((index, seed, None, layer_scores[best_layer], layer_scores))
            continue
        scored.append((index, seed, best_layer, layer_scores[best_layer], layer_scores))
    scored.sort(key=lambda item: (
        -item[3]["plaintext_suffix_matches"],
        -item[3]["known_aliases"],
        -item[3]["score"],
        item[0],
    ))
    best = scored[0]
    if len(scored) > 1:
        second = scored[1]
        if (
            best[3]["plaintext_suffix_matches"] == second[3]["plaintext_suffix_matches"]
            and best[3]["known_aliases"] == second[3]["known_aliases"]
            and best[3]["score"] == second[3]["score"]
        ):
            return Decryption(
                status="ambiguous_seed",
                notices=[{
                    "reason": "multiple IV seeds or layers are equally supported",
                    "candidates": [
                        {"seed_index": index, "seed_iv": seed.hex(), "layer": layer,
                         "score": score}
                        for index, seed, layer, score, _ in scored[:4]
                    ],
                }],
            )
    index, seed, layer, score, all_scores = best
    if layer is None:
        return Decryption(
            status="layer_ambiguous",
            notices=[{
                "reason": "the cipher layer cannot be distinguished; no plaintext was claimed",
                "seed_index": index,
                "seed_iv": seed.hex(),
                "layer_scores": {str(key): value for key, value in all_scores.items()},
            }],
        )
    result = _decrypt_candidate(frames, index, seed, layer, score, plaintext_sends)
    # If a plaintext send exists for the same body length and suffix, record the
    # verification even if the alias mapping itself is not in the table.
    if plaintext_sends:
        for item in result.frames:
            if item.plaintext is None:
                continue
            matches = [
                send.opcode for send in plaintext_sends
                if len(send.body) == len(item.plaintext) and send.body[2:] == item.plaintext[2:]
            ]
            if matches:
                item.evidence.append("plaintext body suffix matched a SendPacket record")
                if item.opcode is None and len(set(matches)) == 1:
                    item.opcode = matches[0]
                    item.opcode_confidence = "recovered_from_plaintext_send"
    result.layer_scores = {
        str(key): value for key, value in (all_scores or {}).items()
    }
    return result


def join_frames(frames, decryption, sends, window_ns=5_000_000_000):
    """One-to-one match of decrypted frames to plaintext SendPacket records."""
    by_frame = decryption.by_index()
    used = set()
    matches = {}
    unmatched = []
    send_index = _send_index(sends)
    for frame in frames:
        item = by_frame.get(frame.index)
        if item is None or item.plaintext is None:
            unmatched.append({
                "frame_index": frame.index,
                "reason": "frame was not decrypted",
                "plaintext_status": item.status if item else "missing",
            })
            continue
        candidates = []
        for order, send in send_index.get((len(item.plaintext), item.plaintext[2:]), []):
            if order in used:
                continue
            if item.opcode is not None and send.opcode != item.opcode:
                continue
            delta = None
            if frame.first_time_ns is not None and send.time_ns is not None:
                delta = abs(send.time_ns - frame.first_time_ns)
                if delta > window_ns:
                    continue
            candidates.append((delta if delta is not None else window_ns + 1, order, send))
        if not candidates:
            unmatched.append({
                "frame_index": frame.index,
                "reason": "no plaintext send matched the decrypted body suffix and opcode",
            })
            continue
        candidates.sort(key=lambda item: (item[0], item[1]))
        delta, order, send = candidates[0]
        used.add(order)
        matches[frame.index] = {
            "send": send,
            "time_delta_ns": delta,
            "order": order,
        }
    unmatched_sends = [
        {"send": send, "order": order}
        for order, send in enumerate(sends)
        if order not in used
    ]
    return matches, unmatched, unmatched_sends
