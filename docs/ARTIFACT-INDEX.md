# Artifact Index

Annotated inventory of the repository. Everything is redacted (see `REDACTION-NOTES.md`) and scoped to a closed research LAN. Paths below are relative to the repository root.

## Start here

| Path | What |
|---|---|
| `README.md` | Findings, capabilities, limitations, and repository navigation |
| `foundations/README.md` | Shared building blocks |
| `analysis/README.md` | Decryption and research workflows |
| `tools/README.md` | Applicable tools and main entrypoints |
| `requirements.txt` | Pinned third-party Python packages |
| `DEPENDENCIES.md` | Direct caller/artifact inventory and recovery status |

## foundations/ — shared building blocks

| Path | What |
|---|---|
| `ngs_cipher.py` | GRAP control-plane response cipher helpers and CLI |
| `transport-cipher.py`, `transport-shuffle-table.bin` | Transport IV rolling and validated 256-byte permutation |
| `locate-character.py` | Build-checked live character/controller resolution |
| `observe-position-reset.py` | Shared character resolver, registers, checked ptrace, bounded wait |
| `mob_profile.py` | Strict mob-offset parsing and validation |
| `memory-watch.py` | Writable-memory snapshots and before/after diffs |
| `profile.json` | Single build-specific profile used by all callers |
| `packet_fields.py` | Evidence-labelled build-scoped packet types and bounded field decoders |
| `traffic_capture.py` | pcap/pcapng parsing and loss-aware TCP reassembly |
| `traffic_protocols.py` | MapleStory/TLS/HTTP/DNS framing with unknown and incomplete evidence markers |
| `traffic_policy.py` | Shared ordered live/offline message policy engine |
| `process_sockets.py` | Conservative process attribution through socket inodes under Wine |

## analysis/ — decryption and research

### Wire and GRAP decoding

| Path | What |
|---|---|
| `wire-session-decrypt.py` | Passive full-duplex pcap decryptor |
| `traffic-ledger.py` | Ordered chained traffic record joining packets, msmon payloads, construction traces, NGS events, and policy evidence |
| `decode-flows.py` | Decode captured control-plane flows |
| `decode-heartbeats.py` | Decode `x-csauth` heartbeats |
| `ngs-mitm.py` | NGS request logger and live response decoder/neutralizer |
| `ngs-proxy.py` | Raw communication logger with exact-host/path-prefix blocking |
| `launch-ngs-mitm.sh` | Persistent proxy and proxied Nexon launcher |

### Packet, interaction, and experimental research

| Path | What |
|---|---|
| `protocol-static.py` | Static outgoing constructor, encoder, and SendPacket extractor |
| `packet-observe.py` | Plaintext send/receive and constructor observer |
| `outgoing-packet-capture.py` | Rich outgoing logger with optional single-opcode suppression |
| `drop-observe.py` | Outgoing packet and memory differential recorder |
| `focus-observe.py` | Focused pickup packet and memory recorder |
| `alter-observe.py` | Scoped pickup-field experiment with restoration |
| `replay-32b.py` | One-shot pickup replay experiment |
| `sendpacket-observe.py` | Passive send-path tap |
| `edit-melee-swap.py` | Disconnect-prone melee experiments |
| `grap-core-crash.py` | Failed historical core-crash experiment; not recommended |

### RNG observation and experiments

| Path | What |
|---|---|
| `attack-rng-observe.py` | Attack/damage correlation, state prediction, and shared RNG model |
| `rng-write-watch.py` | Identify RNG state writers with hardware watchpoints |
| `rng-dataset.py` | Streaming attack/RNG dataset recorder with resume |
| `rng-max-search.py` | Candidate generation and resumable maximum-damage search |
| `rng-damage-override.py` | Narrow single-roll override experiment |

### Capture and experiment wrappers

| Path | What |
|---|---|
| `capture-packets.sh`, `capture-outgoing.sh` | Plaintext and rich outgoing packet capture |
| `capture-drops.sh`, `capture-interaction.sh` | Drop and broad interaction capture |
| `capture-32b.sh`, `capture-death.sh` | Focused pickup and mob-death capture |
| `capture-rng.sh` | Auto-PID RNG dataset capture |
| `duplicate-pickup.sh`, `replay-32b.sh` | Scoped pickup replay experiments |
| `replay-rng-drops.sh` | Fixed-state RNG/drop experiment |
| `run-rng-max-search.sh` | Auto-PID maximum-damage search |

## tools/ — applicable capabilities

| Path | What |
|---|---|
| `position-gui.py` | PySide6 GUI orchestration, hotkeys, portals, toggles, and panic controls |
| `launch-game.py`, `hotkeys.py` | GUI launch and passive evdev hotkey support |
| `mob-count.py` | Read-only mob scanner used by the GUI |
| `try-native-reset.py` | Portal discovery and validation; native execution remains blocked |
| `vac-sprites.py` | Mob VAC and park engine |
| `atkspeed.py`, `atkspeed-frames.py` | Attack-rate experiments and animation-frame timer mechanism |
| `overhead-attacks.py` | Overhead-hitbox and collision-MISS capabilities |
| `observe-incoming-display.py`, `try-collision-miss.py` | Incoming display observation and collision gates |
| `damage-rng.py` | Supported solve/replay/capture/search/analyze entrypoint |
| `rng-state-solver.py` | GF(2) solver for roll targets |
| `rng-state-override.py` | Exact state writes, replay, and restoration |
| `rng-roll-override.py` | Solver-generated replay by roll and index |
| `m2-detour.py` | M2 integrity-read detour with documented limits |
| `sendpacket-drop.py` | Selective SendPacket suppression |
| `shield-blackout-v3.sh`, `v3-stop.sh` | Telemetry shield and cleanup |

## docs/guides/ — current workflows

| Path | What |
|---|---|
| `DAMAGE-RNG.md` | Supported RNG toolkit guide |
| `PACKETS.md` | Current packet boundaries, layouts, capture, and experiments |
| `INTERACTION.md` | Full interaction/drop-origin capture |
| `32B.md` | Focused pickup construction and field capture |
| `DEATH.md` | Mob-death and drop-communication capture |

## docs/research/ — findings and project records

| Path | What |
|---|---|
| `00-RETROSPECTIVE.md` | Technical story and environment caveats |
| `01-THE-ARSENAL.md` | Per-capability mechanisms, evidence, and limits |
| `HANDOFF.md` | Cross-computer resume point |
| `LIVE-VALIDATION.md` | Sequential live results and remaining work |
| `PATCH-RECOVERY-GUIDE.md` | Patch recovery history |
| `RECOVERY-PLAN.md` | Consolidated recovery plan |
| `01-strategic-index-anti-disconnect.md` | Disconnect mechanisms, packet map, and GRAP architecture |
| `02-ngsx-control-plane-README.md` | Control-plane overview |
| `03-ngsx-control-plane-FINDINGS.md` | Cipher and detection-map findings |
| `04-ngsx-control-plane-ANALYSIS.md` | CRC, screenshot, and request-cipher analysis |
| `05-ngsx-control-plane-REPLICATION.md` | Control-plane capture and decode reproduction |
| `06-crc-ngs-historical-context.md` | Historical CRC/NGS context |
| `07-blackcipher64-ngs-static-report.md` | NGS-X / grap-core64 static report |

## Evidence and assets

| Path | What |
|---|---|
| `evidence/decoded-x-update-2026-10-29.json` | Decrypted control-plane x-update |
| `evidence/heartbeat-corpus-inworld-2026-10-29.json` | In-world heartbeat corpus |
| `evidence/module-crc-expected-2026-10-29.json` | Expected module CRC table |
| `evidence/ngs-control-plane-decoded-summary.txt` | Decoded-channel summary |
| `evidence/ratetest-dc-decrypted-20261031.json` | Attack-rate disconnect evidence |
| `assets/ms_showcase_redacted.gif` | Redacted capability showcase |
| `captures/` | Local-only captures; Git-ignored and not part of the public evidence set |

## Historical names not shipped

`header-cipher.py`, `vm-lift.py`, `reanchor.py`, `dr-scrub.py`, `code-integrity-probe.py`, `nxcap.py`, raw pcaps, and other narrative-only artifacts are not present. They remain documented as history rather than being replaced with invented implementations.
