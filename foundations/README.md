# Foundations

Shared building blocks used by the analysis scripts and applicable tools. These modules are not the main user-facing entrypoints.

- `ngs_cipher.py`: GRAP control-plane response decryption and encryption.
- `transport-cipher.py` and `transport-shuffle-table.bin`: validated transport IV rolling.
- `locate-character.py` and `observe-position-reset.py`: build-checked client resolution, memory reading, and ptrace helpers.
- `mob_profile.py`: strict mob-offset parsing.
- `memory-watch.py`: writable-memory snapshots and diffs.
- `profile.json`: the single build-specific profile shared by all callers.
- `packet_fields.py`: bounded, evidence-labelled MapleStory type/field decoding for the fingerprinted build.
- `traffic_capture.py`: pcap/pcapng parsing and loss-aware TCP reassembly.
- `traffic_protocols.py`: conservative MapleStory/TLS/HTTP/DNS whole-message framing.
- `traffic_policy.py`: ordered process/protocol/destination/type/field decisions with default-allow and audit mode.
- `process_sockets.py`: unique non-broker process attribution through `/proc` socket inodes.

Start with the [packet guide](../docs/guides/PACKETS.md), [control-plane replication guide](../docs/research/05-ngsx-control-plane-REPLICATION.md), or [dependency inventory](../docs/DEPENDENCIES.md).
