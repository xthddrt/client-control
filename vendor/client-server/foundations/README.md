# Foundations

Shared primitives used by `traffic` and the live capture hooks.

- `transport-cipher.py`, `transport-shuffle-table.bin` — validated transport IV
  rolling for the game send cipher.
- `ngs_cipher.py` — NGS server→client response decrypt/encrypt.
- `locate-character.py` — read-only `/proc/<pid>/mem` reader and loaded-image
  resolver for `profile.json`.
- `observe-position-reset.py` — ptrace register access, stop waiting and
  error-checked requests used by the send observer.
- `profile.json` — the single build-specific identity checked before any RVA is
  used: process name, PE header fields and code fingerprints.

`locate-character.py` and `profile.json` are reduced to what the communication
tracker needs. Gameplay offsets from the source repository are not carried over.

A build change invalidates every RVA. `find_image` must reject the new binary
until the profile is re-derived from evidence.
