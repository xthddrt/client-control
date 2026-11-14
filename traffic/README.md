# Ordered client→server traffic ledger

`traffic/` builds one ordered record of every captured client→server byte from
MapleStory, its launcher, NGS and helpers. It is self-contained: no checkout of
another repository is required. It joins:

- raw packets (`pcap` / `pcapng`), including msmon-compatible session pcapng;
- in-process plaintext `SendPacket` records (the schema-v1 outgoing logger and
  older `packet-observe`/`drop-observe`/`focus-observe` JSONL);
- session events (`network_data` syscall bytes, flow lifecycle, `etw_tcp`,
  `kfilter_decision`, DNS) with the format reader and chain verifier vendored in
  `traffic/vendor/`;
- NGS proxy logs (`ngs-mitm.py`, `ngs-proxy.py`, `.mitm`);
- its own `traffic capture` output: dumpcap/tcpdump pcap plus a `/proc`
  attribution sidecar.

It then reconstructs TCP streams, splits and combines application messages,
decrypts the game transport where the IV chain is uniquely recoverable, decodes
only documented fields, and attaches constructor/register/stack/serializer
evidence where the in-process capture supplied it.

Missing evidence is a first-class value. A message with no constructor, no wire
frame, an ambiguous IV seed, an unmapped wire opcode, or an opaque TLS body says
so. It is never given a guessed name or a fabricated byte.

## Quick start

```bash
# 1a. Standalone capture: tcpdump bytes + /proc process attribution.
python3 -m traffic capture --seconds 300 --out captures/session-20261113

# 1b. Optional: plaintext SendPacket evidence and a live policy for the game.
analysis/capture-outgoing.sh 300 --deep-opcode 0x32b

# 1c. Optional: an existing msmon-compatible session directory/file, or NGS log.
# 2. Build one ledger from whatever sources you have.
.venv/bin/python -m traffic ingest \
  --pcap captures/session-20261113/capture.pcap \
  --attribution captures/session-20261113/attribution.jsonl \
  --capture captures/outgoing-events-20261113-120000.jsonl \
  --session <optional-session-bundle> \
  --ngs captures/ngs-events-20261113-120000.jsonl \
  --out captures/ledger-20261113

# 3. Read it.
.venv/bin/python -m traffic show captures/ledger-20261113 --opcode 0x32b
.venv/bin/python -m traffic trace captures/ledger-20261113 --id <message-id>
.venv/bin/python -m traffic explain captures/ledger-20261113 \
  --at 2026-11-13T12:04:33.250Z --window 5
```

Run the offline checks with:

```bash
.venv/bin/python -m traffic selftest
```

If the virtual environment is not present, `python3 -m traffic ...` works when
the direct dependencies in `requirements.txt` are installed.

## Output

`ingest` writes a directory:

| File | Contents |
|---|---|
| `ledger.jsonl` | One session record followed by ordered records. |
| `decisions.jsonl` | One decision per evaluated message when `--policy` is used. |
| `flows.json` | Flow summaries and reconstruction statistics. |
| `summary.json` | Input hashes, counts, decode/process/protocol totals, capture notes, limitations. |
| `manifest.json` | Small index to the files above. |

Record types:

- `session` — ledger ID, source sessions, build identity, input file hashes,
  policy identity, limitations.
- `message` — one application message (game frame, TLS record, HTTP request,
  NGS request, UDP/DNS datagram).
- `transport_chunk` — exact client→server bytes no verified decoder claimed.
- `capture_gap` — a TCP sequence range with no captured bytes.
- `flow` — a TCP/UDP flow summary, with client/server inference and socket
  attribution.
- `flow_event` — monitor connect/accept/close/reset/retransmit evidence.
- `filter_decision` — an ingested `kfilter_decision` or NGS proxy decision.
- `notice` — parser/capture limitation, never a silent drop.

### Message fields

Each `message` contains:

```json
{
  "message_id": "ccm-...",
  "time_ns": 1700000000003000000,
  "time_utc": "2023-11-14T22:13:20.003000Z",
  "process": {"pid": 4242, "name": "MapleStory.exe", "path": "...", "build": {}},
  "transport": {
    "protocol": "maplestory_game",
    "direction": "client_to_server",
    "source": {"ip": "10.0.0.2", "port": 50000},
    "destination": {"ip": "203.0.113.5", "port": 8585},
    "socket": {"inode": 99, "cookie": "7"}
  },
  "message": {
    "type": {"opcode": 811, "opcode_hex": "0x32b",
             "name": "pickup_request", "confidence": "confirmed",
             "evidence": ["docs/guides/PACKETS.md:76"]},
    "raw_bytes_hex": "...",
    "raw_bytes_length": 36,
    "raw_bytes_sha256": "...",
    "raw_bytes_encoding": "plaintext",
    "fields": [{"name": "drop_object_id", "offset": 15, "size": 4,
                "value": 82943, "confidence": "confirmed"}],
    "unparsed": [],
    "decode_status": "complete"
  },
  "reconstruction": {
    "wire": {"frame_index": 0, "header": {"w0": 1, "w1": 38, "length": 36}},
    "split": true, "combined": true, "retransmitted": true,
    "decryption": {"status": "seeded", "wire_alias": "0xfbd0"}
  },
  "provenance": {
    "in_process": true,
    "send": {"tid": 4242, "registers": {}, "caller": {}, "return_stack": []},
    "constructor": {"construction_id": "...", "registers": {}, "caller": {}},
    "serialization_steps": [{"length": 36, "changed_ranges": []}],
    "memory_activity": {"field_change_count": 1},
    "missing": []
  },
  "transmitted": true,
  "filter": {"action": "allow", "rule_id": null, "simulated_offline": true}
}
```

## Reconstruction rules

- TCP segments are placed by sequence number, not arrival order.
- Overlapping retransmissions are recorded. Identical bytes are counted as a
  retransmission; differing overlapping bytes are a `conflict` and the
  first-seen byte is kept, because the receiver had it first. Conflicts are never
  silently overwritten.
- Out-of-order segments fill holes and are counted.
- A hole is a `capture_gap` record. The ledger never zero-fills it. A frame or
  TLS record crossing a hole is left as `transport_chunk` plus a notice.
- One TCP segment can carry several game frames (`combined`) and one frame can
  span several segments (`split`). Both are reported per message.
- The game frame is `[u16 w0][u16 w1][body]`, `length = w0 XOR w1`.
- A plaintext `SendPacket` is joined to a wire frame only when the bytes after
  the two opcode bytes match and the times are within `--join-window` (default
  5 s). The join is one-to-one; unmatched sends and frames are both reported.
- Plaintext sends with no wire frame (filter drop, missing pcap, capture gap)
  remain in the ledger with `transmitted: false` or a missing-wire reason.

## Game transport decode

- The send body cipher is AES-256-OFB with the build's IV roll. The IV is seeded
  from two consecutive frame headers. When several seeds fit the headers, a
  candidate is chosen only if known wire aliases or a matching plaintext send
  distinguish it; otherwise decryption is refused.
- If more than one seed or cipher layer is equally supported, decryption is
  refused and the ciphertext is preserved (`ambiguous_seed` / `layer_ambiguous`).
- The decrypted first two bytes are the observed **wire alias**, not always the
  plaintext opcode. The alias table is the one evidenced in
  `docs/guides/PACKETS.md` (`0xe1→0xf6c7`, `0x32b→0xfbd0`, ...). An unmapped
  alias stays `unmapped_wire_opcode`.
- Field offsets are from the start of the application body and include the
  two-byte opcode, matching `0x32b+0x0f` in the existing guide.
- Only layouts with documentary evidence are decoded. Uncovered ranges are in
  `message.unparsed`; fields named `unknown_*` are exact bytes with unresolved
  meaning.

## Provenance and crash/malfunction reports

`provenance` is the evidence chain:

- send time, TID, PID, opcode, length, registers, caller return address, and
  return stack;
- constructor record (RVA, packet VA, registers, caller, stack);
- serialization steps from the length-watch (`field_change`): intermediate
  lengths, changed byte ranges, write RIP/RVA, registers, floating registers;
- the wire frame, its TCP segments, retransmission/overlap status, and whether
  decryption was seeded or refused.

`traffic trace DIR --id ID` prints one message and all messages sharing its
construction. `traffic explain DIR --at TIME --window N` prints the messages,
flow lifecycle, policy decisions, gaps and missing-evidence counts around an
instant. Its assessment explicitly says that timing and presence are evidence,
not proof of causality.

## Filtering before transmission

The policy schema is JSON (`client-control.traffic-filter/v1`). Rules are
first-match. A dimension that names missing evidence does not match; it never
falls back to a guess.

```json
{
  "schema": "client-control.traffic-filter/v1",
  "name": "audit telemetry family",
  "default": "allow",
  "rules": [
    {
      "id": "audit-1ef",
      "action": "audit",
      "description": "log, never suppress",
      "match": {
        "process": {"name": "MapleStory.exe"},
        "protocol": ["maplestory_game"],
        "destination": {"ip": "203.0.113.0/24", "port": 8585},
        "type": {"opcode": "0x1ef"},
        "size": {"min": 2, "max": 65535}
      }
    }
  ]
}
```

Supported match dimensions:

- `process`: `name`/`path` glob, `pid`, `build_timestamp`, `module_base`
- `protocol`: transport/application protocol list
- `destination`: `host` glob, `ip`/`cidr`, `port`, `path_prefix`
- `type`: `opcode`, `name`, `confidence`
- `field`: decoded field by `name` or `offset`/`size`, with `equals`,
  `not_equals`, `in`, `mask`+`value`, `min`/`max`, `hex_prefix`
- `raw`: `match_hex` at `offset`
- `size`: byte length range

Every evaluation returns a decision record. `decisions.jsonl` contains the full
rule-by-rule trail, including `missing_evidence`. Offline ingest/filter only
marks the ledger; it never rewrites captured bytes.

### Live game hook

`analysis/outgoing-packet-capture.py --filter-policy FILE` evaluates every
`SendPacket` before it is transmitted:

- process: `/proc/<pid>/comm`, exe and the build from `profile.json`;
- type/field: the plaintext opcode and `decode_game` fields;
- destination: current established TCP peers from the process's socket table,
  with an `ss -tnp` fallback for Wine sessions where the game process does not
  own the socket fd. If `SendPacket` has several peers, destination is ambiguous
  and a destination rule does not match (the decision records why);
- action `drop` reuses the existing register-safe return-to-caller drop; action
  `audit` only logs. All non-matching traffic takes the original path unchanged.

The wrapper is:

```bash
analysis/capture-outgoing.sh 300 --filter-policy traffic/examples/audit-game.json
```

### NGS/launcher hook

`analysis/ngs-proxy.py` accepts `--set ngs_policy=FILE` (and `ngs_scope=ngs|all`).
It evaluates the request path/host/method before forwarding; `drop` returns a
local 403, `audit` only logs. The NGS client→server body cipher is device-bound
and remains opaque; no field value is invented from it. `ngs-mitm.py` now records
timestamps so proxy events can be ordered.

### Kernel bridge

`python -m traffic kfilter-policy --policy FILE` emits a kfilter-compatible
message-policy fragment. It is only an export: client-control does not run or
require kfilter. kfilter sees ciphertext at the syscall boundary, so decoded
opcodes/fields and dynamic hosts are emitted as explicit "not translated"
comments. The supported subset is process image, IP/port/protocol, size, and an
explicit raw byte match, with `message-default allow|deny`.

## Source-specific limits

- **Classic pcap** has no process identity. The ledger can still infer the
  client direction from SYN, capture direction, private address or service port,
  but Process is `missing` unless a matching monitor call or plaintext send
  supplies it. Use `--client-endpoint IP:PORT` when inference is ambiguous.
- **msmon-compatible pcapng** process/socket fields come from EPB comments. They
  name the socket owner, not necessarily the process that sent a specific
  packet.
- **monitor `network_data`** is a syscall send stream: exact bytes and PID, but
  no TCP sequence numbers or retransmissions. It is used as a fallback only for
  sockets the pcap did not cover; pcap remains the primary reconstruction.
- **Windows session logs** currently contain WFP/ETW flow metadata and kfilter
  decisions, not packet payloads. A Windows-only session therefore yields flow
  and decision records without reconstructable bytes until a packet source is
  added. Linux session logs provide `events.pcapng` and syscall bytes.
- **NGS request bodies** are not decryptable here. Only exact bytes, method,
  host, path, headers and the decoded server response are recorded.
- **TLS** application data is opaque unless a proxy or TLS plaintext source
  supplies it. ClientHello/SNI is parsed.
- **In-process evidence** exists only for threads armed by the ptrace observer.
  Deep serializer steps exist only for opcodes passed to `--deep-opcode`.
- Captures can have gaps. See `capture_gap`, `capture_notes`,
  `summary.capture_notes`, and monitor's own coverage/drop counters.

## Standalone capture vs. session import

`python -m traffic capture` needs only Linux, `tcpdump`, `/proc`, and permission
to read the socket table. It writes `capture.pcap`, `attribution.jsonl` and
`capture.json`. Process attribution is a periodic snapshot; a short-lived socket
or a Wine broker-owned fd can be missing or ambiguous, and the ledger marks it
that way.

`--session` (also accepted as `--monitor`) imports an already-produced
msmon-compatible bundle. The event schema and chain verifier are vendored in
`traffic/vendor/`, so no monitor-filter checkout, Python path, daemon or driver
is needed. Use `--verify-session` to verify the hash chain before ingesting.

## Tests

The offline suite in `traffic/tests/` covers:

- pcap and pcapng parsing, monitor comments, 100 ns timestamps;
- TCP split/combined/retransmitted/overlapping segments and gap reporting;
- IV seeding, alias mapping, plaintext join, packet field decode;
- constructor/field-change provenance;
- dropped-send preservation;
- NGS response cipher and opaque request;
- monitor `network_data` fallback, flow metadata and decisions;
- policy matching by process/protocol/destination/type/field and missing-evidence
  refusal;
- kfilter translation warnings;
- DNS/UDP records;
- `explain` evidence-vs-causality wording;
- standalone attribution matching and the vendored chain verifier.

`python -m traffic selftest` runs them without root, a game client, network
access or another repository.
