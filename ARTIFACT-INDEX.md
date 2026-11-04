# Artifact Index

Annotated inventory of this drop. Everything is redacted (see `REDACTION-NOTES.md`) and
scoped to a closed research LAN.

## Narrative (start here)
| File | What |
|------|------|
| `README.md` | Front page — the teaser + the arsenal + crown jewels, ranked |
| `00-RETROSPECTIVE.md` | Full story, environment-first, honest accounting |
| `01-THE-ARSENAL.md` | Per-capability deep dive (addresses, mechanism, evidence, limits) |

## docs/ — explanatory source material
| File | What |
|------|------|
| `01-strategic-index-anti-disconnect.md` | Strategic index: 3 DC mechanisms, packet map, GRAP architecture |
| `02-ngsx-control-plane-README.md` | Control-plane crack: overview |
| `03-ngsx-control-plane-FINDINGS.md` | Control-plane crack: findings (cipher, detection map) |
| `04-ngsx-control-plane-ANALYSIS.md` | Control-plane crack: deep analysis (CRC table, screenshot path) |
| `05-ngsx-control-plane-REPLICATION.md` | How to reproduce the control-plane decode |
| `06-crc-ngs-historical-context.md` | Operator-supplied CRC/NGS historical context |
| `07-blackcipher64-ngs-static-report.md` | NGS-X / grap-core64 static RE report |

## evidence/ — decrypted captures
| File | What |
|------|------|
| `decoded-x-update-2026-10-29.json` | Decrypted control-plane x-update (module-CRC table source) |
| `heartbeat-corpus-inworld-2026-10-29.json` | In-world heartbeat corpus (screenshot-exfil size bumps) |
| `module-crc-expected-2026-10-29.json` | Server's expected per-module CRC table |
| `ngs-control-plane-decoded-summary.txt` | Human-readable summary of the decoded channel |
| `ratetest-dc-decrypted-20261031.json` | Decrypted capture around an attack-rate DC (DC-3 evidence) |

## tools-QUARANTINE/ — the tools (read the index before running anything)

### Crypto / wire
| File | Lines | What |
|------|------:|------|
| `wire-session-decrypt.py` | 235 | Passive full-duplex pcap decryptor (AES-256-OFB, static key, self-seeding IV) |
| `ngs_cipher.py` | 130 | Shared cipher helpers (transport + header + recv) |
| `decode-flows.py` | 75 | Decode captured control-plane flows |
| `decode-heartbeats.py` | 73 | Decode `x-csauth` heartbeats |

### In-game arsenal
| File | Lines | What |
|------|------:|------|
| `vac-sprites.py` | 925 | Mob VAC + park engine with `--dry`; basic X-only live-validated, other modes pending |
| `position-gui.py` | 1911 | PySide6 control GUI (hotkeys, read-only portals, toggles, panic kill); unavailable native controls disabled |
| `overhead-attacks.py` | 409 | Overhead-hitbox forcing + collision gates; selector observation validated, MISS unverified |
| `observe-incoming-display.py` | 432 | Live incoming-packet display (read side) |
| `atkspeed.py` | 267 | ~3× attack-speed override |
| `atkspeed-frames.py` | 111 | Animation-frame-timer attack-rate mechanism |
| `locate-character.py` | 284 | Resolve live character/controller addresses |
| `edit-melee-swap.py` | 202 | Melee opcode/write experiments |

### Evasion / anti-DC
| File | Lines | What |
|------|------:|------|
| `m2-detour.py` | 245 | M2 echo-loop detour: hide a `.text` patch from the server-directed read |
| `sendpacket-drop.py` | 166 | Stealth DR0 telemetry drop (`0x1ef`) at SendPacket |
| `sendpacket-observe.py` | 120 | Passive send-path tap |
| `grap-core-crash.py` | 231 | grap-core64 crash-kill (NtWriteFile E9 detour) |

## Consolidated recovery artifacts

`RECOVERY-PLAN.md` records the plan-2-based recovery and objective additions from plan 1. `LIVE-VALIDATION.md` records subsequent sequential live results, exact code corrections, and remaining work. `requirements.txt` lists third-party Python packages. `tools-QUARANTINE/DEPENDENCIES.md` is the authoritative caller/artifact inventory and recovery-status matrix.

| File | What |
|------|------|
| `transport-cipher.py`, `transport-shuffle-table.bin` | Offline transport IV rolling and the validated 256-byte permutation |
| `observe-position-reset.py` | Shared character resolver, register layout, checked ptrace, bounded wait |
| `mob_profile.py`, `mob-count.py` | Strict mob-offset validation and read-only GUI mob scanning |
| `try-collision-miss.py` | Collision gates recovered from live disassembly; native forcing remains unverified |
| `try-native-reset.py` | Read-only portal snapshots and destination validation; native execute refuses an omitted call sequence |
| `launch-game.py`, `hotkeys.py` | Validated UMU/preload orchestration and passive evdev Qt hotkeys |
