# Analysis and decryption

Runnable decoders, packet and memory observers, capture wrappers, and research experiments. Run commands from the repository root with the project virtual environment.

## Decoding

```bash
.venv/bin/python analysis/wire-session-decrypt.py captures/game.pcap
.venv/bin/python analysis/decode-flows.py captures/ngs-flows.mitm --json captures/ngs-decoded.json
.venv/bin/python analysis/decode-heartbeats.py captures/ngs-flows.mitm --json captures/heartbeats.json
```

`ngs-mitm.py` and `launch-ngs-mitm.sh` provide the live GRAP control-plane proxy workflow. See the [replication guide](../docs/research/05-ngsx-control-plane-REPLICATION.md).

`ngs-proxy.py` separately provides raw JSONL communication logging and exact-host/path-prefix blocking without payload decoding:

```bash
.venv/bin/mitmdump -s analysis/ngs-proxy.py \
  --set ngs_log=captures/ngs-raw.jsonl \
  --set ngs_block=example.com:/blocked-prefix
```

Raw captures can contain sensitive request and response bodies; keep them in the Git-ignored `captures/` directory.

## Packet and interaction research

- `protocol-static.py`: static packet constructor and serializer analysis.
- `capture-packets.sh` and `capture-outgoing.sh`: plaintext packet capture.
- `capture-drops.sh`, `capture-interaction.sh`, `capture-32b.sh`, and `capture-death.sh`: focused interaction captures.
- `packet-observe.py`, `outgoing-packet-capture.py`, `drop-observe.py`, `focus-observe.py`, and `replay-32b.py`: underlying observation and experiment drivers.

See the [packet](../docs/guides/PACKETS.md), [interaction](../docs/guides/INTERACTION.md), [pickup](../docs/guides/32B.md), and [death/drop](../docs/guides/DEATH.md) guides.

## RNG research

`attack-rng-observe.py`, `rng-write-watch.py`, `rng-dataset.py`, `rng-max-search.py`, and `rng-damage-override.py` contain the observation and experimental workflows behind the supported RNG interface in `tools/damage-rng.py`. See the [RNG guide](../docs/guides/DAMAGE-RNG.md).

Captures remain in the Git-ignored `captures/` directory. Experimental modification and replay modes retain their existing warnings and are not routine read-only checks.
