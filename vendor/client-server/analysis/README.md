# Capture, decode and blocking entry points

Run these from the repository root after installing `requirements.txt`.

## All game connections (proxy)

```bash
# Every connection of the game's Wine programs (and TCP 8400-8999) until Ctrl-C.
analysis/game-proxy.sh [--policy FILE]
.venv/bin/python -m traffic proxy-report captures/proxy-<stamp>.jsonl
```

See the main README for what is recorded, decrypted and controlled.

## Game process

```bash
# Plaintext SendPacket JSONL + raw full-duplex pcap.
analysis/capture-outgoing.sh 300

# Evaluate every packet before transmission; only an explicit drop suppresses it.
analysis/capture-outgoing.sh 300 --filter-policy traffic/examples/audit-game.json

# Record construction field writes for selected opcodes as well.
analysis/capture-outgoing.sh 300 --deep-opcode 0x32b
```

`outgoing-packet-capture.py` resolves the loaded image against
`foundations/profile.json`, arms hardware breakpoints at this build's
`SendPacket` and constructor RVAs, logs exact plaintext and caller context, and
restores every debug register on detach.

## NGS / HTTPS

```bash
# Raw request/response logging, policy decisions and host/path blocking.
.venv/bin/mitmdump -s analysis/ngs-proxy.py \
  --set ngs_log=captures/ngs-raw.jsonl \
  --set ngs_policy=traffic/examples/audit-ngs.json

# Log and decode server→client control-plane responses; optional neutralization.
.venv/bin/mitmdump -s analysis/ngs-mitm.py \
  --set ngs_log=captures/ngs-events.jsonl \
  --set ngs_neutralize=true

# Full Wine launcher workflow for ngs-mitm.py.
analysis/launch-ngs-mitm.sh
```

Offline decoders:

```bash
.venv/bin/python analysis/decode-flows.py captures/ngs-flows.mitm --json captures/ngs-decoded.json
.venv/bin/python analysis/decode-heartbeats.py captures/ngs-flows.mitm --json captures/heartbeats.json
```

## Analytics upload (TLS 1.2, keys from the game's memory)

```bash
# Needles of the open analytics connections, a read-only memory read (root), keys proven on the
# recording, then the requests and NDJSON record types with values masked.
.venv/bin/python analysis/tls-keys.py needles captures/proxy-<stamp>.jsonl --keylog captures/analytics.keylog > captures/tls-needles.txt
sudo .venv/bin/python -I analysis/tls-memscan.py <game pid> captures/tls-scan-1.pkl @captures/tls-needles.txt
.venv/bin/python analysis/tls-keys.py find captures/proxy-<stamp>.jsonl captures/tls-scan-1.pkl --keylog captures/analytics.keylog
.venv/bin/python analysis/tls-keys.py decrypt captures/proxy-<stamp>.jsonl --keylog captures/analytics.keylog [--plaintext FILE]

# The first three steps a minute after each new analytics connection (needs passwordless sudo -n).
analysis/tls-keys-watch.sh captures/proxy-<stamp>.jsonl <game pid> captures/analytics.keylog
```

`tls-memscan.py` only reads `/proc/<pid>/mem` (no attach, no writes); the game cannot see it.
Only connections open at the time of the read can be decrypted. Scans, keylogs (standard
`SSLKEYLOGFILE`) and plaintext are written mode 600 and refused inside the repository except
`captures/`. Details: `docs/guides/PROTOCOL.md`, "Decrypting the analytics upload".

## Offline pcap

```bash
.venv/bin/python analysis/wire-session-decrypt.py captures/game.pcap
```

The script seeds the send IV from two consecutive headers, rolls it through the
session, and writes `<pcap>.decrypted.json`. Inbound bodies use the observed
single-byte XOR with `iv[0]`.

## Self-checks

```bash
.venv/bin/python -m traffic selftest
.venv/bin/python analysis/outgoing-packet-capture.py --self-test
.venv/bin/python analysis/ngs-proxy.py --self-test
.venv/bin/python analysis/ngs-mitm.py --self-test
```
