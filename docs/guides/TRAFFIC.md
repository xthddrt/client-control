# Ordered client→server traffic ledger

The `traffic/` package builds a single ordered record from game pcaps, plaintext
`SendPacket` captures, session bundles, NGS proxy logs, and its own standalone
tcpdump capture. It is self-contained: the session schema/chain verifier it uses
are vendored in `traffic/vendor/`, so no monitor-filter checkout is needed. It
reassembles split/combined/retransmitted TCP messages, decrypts the game
transport where the IV is uniquely recoverable, joins wire frames to in-process
constructors, decodes only documented fields, and marks every missing piece of
evidence explicitly.

Full usage, schema, source limits and policy dimensions:
[`traffic/README.md`](../../traffic/README.md).

## Common commands

```bash
# Standalone capture: dumpcap/tcpdump bytes + periodic /proc socket attribution.
python3 -m traffic capture --seconds 300 --out captures/session

# Build a ledger.
.venv/bin/python -m traffic ingest \
  --pcap captures/session/capture.pcap \
  --attribution captures/session/attribution.jsonl \
  --capture captures/outgoing-events-*.jsonl \
  --session <optional-msmon-compatible-bundle> \
  --ngs captures/ngs-events-*.jsonl \
  --out captures/ledger

# Inspect messages; filter by process/protocol/opcode/type/decode status/time.
.venv/bin/python -m traffic show captures/ledger --opcode 0x32b
.venv/bin/python -m traffic show captures/ledger --protocol maplestory_game --json

# One message's constructor, registers, stack, serializer steps and wire frame.
.venv/bin/python -m traffic trace captures/ledger --id <message-id>

# Evidence around a crash or malfunction time (not a causal claim).
.venv/bin/python -m traffic explain captures/ledger --at 2026-11-13T12:04:33Z --window 5

# Evaluate a policy offline; raw bytes are never rewritten.
.venv/bin/python -m traffic filter captures/ledger \
  --policy traffic/examples/audit-game.json --out captures/ledger-filtered

# Emit an optional kfilter-compatible policy fragment (no runtime dependency).
.venv/bin/python -m traffic kfilter-policy \
  --policy traffic/examples/audit-game.json --out captures/kfilter-messages.policy
```

## Live filtering

The game process hook is the existing `SendPacket` observer:

```bash
analysis/capture-outgoing.sh 300 --filter-policy traffic/examples/audit-game.json
```

Every decision is in the JSONL; only an explicit `drop` action suppresses the
packet. The NGS proxy hook is:

```bash
.venv/bin/mitmdump -s analysis/ngs-proxy.py \
  --set ngs_log=captures/ngs-raw.jsonl \
  --set ngs_policy=traffic/examples/audit-ngs.json
```

The kernel bridge and its limits (ciphertext at the syscall boundary, dynamic
hosts and decoded fields not translated) are documented in
[`traffic/README.md`](../../traffic/README.md). Windows session logs provide flow
metadata and decisions, not packet payloads, so use the standalone Linux capture
or a separate packet capture there.
