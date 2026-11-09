# Foundations

Shared building blocks used by the analysis scripts and applicable tools. These modules are not the main user-facing entrypoints.

- `ngs_cipher.py`: GRAP control-plane response decryption and encryption.
- `transport-cipher.py` and `transport-shuffle-table.bin`: validated transport IV rolling.
- `locate-character.py` and `observe-position-reset.py`: build-checked client resolution, memory reading, and ptrace helpers.
- `mob_profile.py`: strict mob-offset parsing.
- `memory-watch.py`: writable-memory snapshots and diffs.
- `profile.json`: the single build-specific profile shared by all callers.

Start with the [packet guide](../docs/guides/PACKETS.md), [control-plane replication guide](../docs/research/05-ngsx-control-plane-REPLICATION.md), or [dependency inventory](../docs/DEPENDENCIES.md).
