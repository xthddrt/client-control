# Analysis and decryption

Runnable decoders, packet and memory observers, capture wrappers, and research experiments. Run commands from the repository root with the project virtual environment.

## Decoding

```bash
.venv/bin/python analysis/wire-session-decrypt.py captures/game.pcap
.venv/bin/python analysis/decode-flows.py captures/ngs-flows.mitm --json captures/ngs-decoded.json
.venv/bin/python analysis/decode-heartbeats.py captures/ngs-flows.mitm --json captures/heartbeats.json
```

`ngs-mitm.py` and `launch-ngs-mitm.sh` provide the live GRAP control-plane proxy workflow. See the [replication guide](../docs/research/05-ngsx-control-plane-REPLICATION.md).

To disable only the screenshot feature without the generic ruleset rewrite, close MapleStory and the launcher, then use:

```bash
NGS_SCREENSHOT_FILTER=1 NGS_NEUTRALIZE=false analysis/launch-ngs-mitm.sh
```

This opt-in changes only `0x0F013` enable flags in `x-config/v1` responses and logs exact original/rewritten bytes and decisions. Live client suppression is not yet verified; request-body screenshot fields remain undecoded. See the [screenshot configuration/filter audit](../docs/research/outgoing/20261115-grap-screenshot-filter.md). Reproduce the real local-proxy check without contacting Nexon:

```bash
.venv/bin/python analysis/verify-ngs-screenshot-filter.py captures/ngs-screenshot-filter-reproduction.json
```

`ngs-proxy.py` separately provides raw JSONL communication logging and exact-host/path-prefix blocking without payload decoding:

```bash
.venv/bin/mitmdump -s analysis/ngs-proxy.py \
  --set ngs_log=captures/ngs-raw.jsonl \
  --set ngs_block=example.com:/blocked-prefix
```

Raw captures can contain sensitive request and response bodies; keep them in the Git-ignored `captures/` directory.

## Packet and interaction research

- `protocol-static.py`: static packet constructor and serializer analysis.
- `debug-watch.py`: read-only execution/write watches with register, stack, and restoration evidence; `--profile` selects the matching image-validation profile.
- `grap-screenshot-config.py`: bounded live screenshot-configuration snapshot; `--self-test` checks its field parser. It does not collect screen contents.
- `watch-grap-screenshots.sh`: per-thread GRAP `BitBlt` caller watch with restoration/error summaries. A call is not automatically a surveillance event.
- `capture-packets.sh` and `capture-outgoing.sh`: plaintext packet capture.
- `capture-drops.sh`, `capture-interaction.sh`, `capture-32b.sh`, and `capture-death.sh`: focused interaction captures.
- `packet-observe.py`, `outgoing-packet-capture.py`, `drop-observe.py`, `focus-observe.py`, and `replay-32b.py`: underlying observation and experiment drivers.

See the [packet](../docs/guides/PACKETS.md), [interaction](../docs/guides/INTERACTION.md), [pickup](../docs/guides/32B.md), and [death/drop](../docs/guides/DEATH.md) guides.

## RNG research

`attack-rng-observe.py`, `rng-write-watch.py`, `rng-dataset.py`, `rng-max-search.py`, and `rng-damage-override.py` contain the observation and experimental workflows behind the supported RNG interface in `tools/damage-rng.py`. See the [RNG guide](../docs/guides/DAMAGE-RNG.md).

Captures remain in the Git-ignored `captures/` directory. Experimental modification and replay modes retain their existing warnings and are not routine read-only checks.

## Controlled session proxy

`controlled-proxy.py` and `launch-controlled-proxy.sh` provide process-selective HTTP/HTTPS, raw TCP, and UDP capture with exact-byte evidence and conservative client-to-server decoding. Defaults forward traffic unchanged; no generic GRAP neutralization is enabled by this launcher.

```bash
analysis/launch-controlled-proxy.sh
# Source the printed captures/controlled-*/env.sh before the normal MapleMarket command.
```

Use `NGS_SCREENSHOT_FILTER=1` for the scoped config rewrite or `TRAFFIC_POLICY=/path/policy.json` for explicit policies. Raw message policy observations are marked post-forward; use `capture-outgoing.sh` for MapleStory suppression before `SendPacket`. The separate NGS client cipher is not assumed decoded.

Full setup, evidence scope, and MapleMarket handoff: [controlled proxy](../docs/research/outgoing/20261115-controlled-proxy.md). Verify with real loopback HTTP, TCP, and UDP flows:

```bash
.venv/bin/python analysis/verify-controlled-proxy.py captures/controlled-proxy-reproduction.json
```

## Ordered traffic ledger

`traffic-ledger.py` joins packet captures, msmon socket payloads, ptrace construction traces, and NGS proxy events into one timestamp-ordered, SHA-256-chained JSONL record. The full monitor/filter implementation is vendored under `vendor/monitor-filter/`; no sibling checkout, submodule, or separately installed monitor-filter package is used.

Build and test the internal sensor/filter copy:

```bash
python3 vendor/monitor-filter/monfilter.py build
python3 vendor/monitor-filter/monfilter.py test
```

For full-family capture, run `python3 vendor/monitor-filter/monfilter.py run` (or its documented `--attach` mode) and use the resulting session below. Its root-only eBPF/kernel sensors, build prerequisites, safety limits, and real-client validation status remain those documented in `vendor/monitor-filter/README.md`; building it does not load a driver or start enforcement.

Build the ordered ledger from any combination of internal-capture sources:

```bash
python3 analysis/traffic-ledger.py build captures/traffic-ledger \
  --msmon /path/to/session-or.zip \
  --pcap captures/outgoing-session-YYYYMMDD-HHMMSS.pcap \
  --trace captures/outgoing-events-YYYYMMDD-HHMMSS.jsonl \
  --ngs captures/ngs-events-YYYYMMDD-HHMMSS.jsonl
python3 analysis/traffic-ledger.py verify captures/traffic-ledger
python3 analysis/traffic-ledger.py capture-check captures/traffic-ledger
python3 analysis/traffic-ledger.py show captures/traffic-ledger r42 --explain
.venv/bin/python analysis/traffic-ledger.py analyze-operation captures/traffic-ledger r42 \
  --output evidence/outgoing/SESSION-r42.json
python3 analysis/traffic-ledger.py self-test
```

The output directory is newly created mode `0700`; files are mode `0600`. `traffic.jsonl` retains exact captured bytes as Base64 plus SHA-256 and source references. `summary.json` separately reports observed-byte completeness and decode completeness. Neither is a claim that the sensors saw all traffic.

`capture-check` verifies raw-byte hashes and fails on known missing ranges, incomplete payloads, source-reported loss, unknown direction, or missing process identity. A pass covers all observed outgoing raw bytes without a known gap; it is not a claim of absolute coverage against an uninstrumented path, and it does not require successful decryption.

`analyze-operation` saves one outgoing operation as a reproducible JSON evidence bundle: original monitor event, process/image loads, exact stack-address/image-range analysis when recorded, raw and decoded message observations, containing packets, and integrity checks. Optional `--image`, repeated `--code RVA`, and `--references RVA` add fingerprint-checked static disassembly and caller/data-reference evidence; these remain static candidates unless runtime tracing links them. `frame_analysis[].current_field_decode` reapplies the current decoder with a uniquely linked runtime opcode while retaining the historical decode. See the worked [r374 case](../docs/research/outgoing/20261114T210123Z-r374.md) and [0x181 case](../docs/research/outgoing/20261114T225004-r48422.md). Review raw bytes and paths for sensitive content before committing future bundles.

- pcap/pcapng input retains raw frames, pcapng process/socket comments, TCP splits, combined sends, retransmissions, conflicting overlaps, and missing ranges. MapleStory, TLS, HTTP/1, UDP, and DNS envelopes are framed conservatively; gaps stop framing rather than trigger a guessed resynchronization.
- msmon input verifies its hash chain, rebuilds 8 KiB payload chunks, joins complete socket operations, and breaks protocol streams at `payload_unavailable`. Its own sequence gaps and kfilter decisions remain evidence records.
- ptrace input links `COutPacket` sends to constructors, field-watch snapshots, changed bytes, registers, stacks, and any captured memory. Missing deep traces say `not_captured_enable_deep_opcode`. A unique length-and-body wire match recovers the construction opcode and applies its field decoder; duplicate candidates remain ambiguous rather than inheriting a type.
- NGS input keeps exact application bodies and request/response flow IDs. Response rewrites retain the original message plus a linked `filter_decision` with exact forwarded bytes and both decoded versions. Original TLS/HTTP framing still requires packet evidence. The NGS request/attestation cipher remains unresolved; responses decode only when `ngs_cipher` validates them.
- `show --explain` returns direct linked observations and `causal_conclusion: not_established` unless further evidence exists. Timing proximity alone is never called a crash cause.

### Live message policy

Policies are JSON, evaluated in order. `allow`, `audit`, and `drop` are supported; default is allow. Audit mode turns a drop into a logged `would_drop` and forwards the message. A selector whose evidence is unavailable does not match.

```json
{
  "version": 1,
  "mode": "audit",
  "default": "allow",
  "rules": [
    {
      "id": "one-pickup",
      "action": "drop",
      "process": "MapleStory.exe",
      "protocol": "maple",
      "type": "0x32b",
      "field": {"name": "drop_object_id", "equals": "0x143ff"},
      "reason": "scoped research fixture"
    },
    {
      "id": "ngs-config",
      "action": "audit",
      "process": "nexon_client.exe",
      "protocol": "https",
      "destination": {"host": "x-config.ngs.nexon.com", "port": 443},
      "field": {"name": "target", "equals": "/v1"}
    }
  ]
}
```

Use it for game sends or the existing NGS launcher workflow:

```bash
analysis/capture-outgoing.sh 300 --deep-opcode 0x32b --policy /path/policy.json
TRAFFIC_POLICY=/path/policy.json analysis/launch-ngs-mitm.sh
```

Game drops occur before `SendPacket`, so no encrypted frame is sent and the rolling IV is not advanced. Destination is unavailable at that hook and is recorded as such; use the proxy layer for destination rules. The proxy resolves a unique non-wineserver process through the client socket inode, or marks attribution unavailable/ambiguous. Existing `--drop-opcode` and `ngs_block` options remain supported. Live client behavior and safety of dropping any message still require a separate controlled run.
