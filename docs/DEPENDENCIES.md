# Dependency and recovery inventory

Shared primitives and `profile.json` live in `foundations/`; decoders, capture drivers, and experiments live in `analysis/`; applicable capabilities and the supported RNG entrypoint live in `tools/`. See `ARTIFACT-INDEX.md` for the complete path map.

This inventory covers direct dependencies of the shipped scripts, not every historical filename mentioned in the narratives. Recovered modules are source-level reconstructions from the shipped callers and `profile.json`; offline validation does not establish live client behavior.

## Local offline environment

The checkout now has a project `.venv` with the exact tested versions pinned in `requirements.txt`. Recreate it with:

```bash
python3 -m venv --system-site-packages .venv
.venv/bin/python -m pip install -r requirements.txt
```

The installed environment passed byte-compilation, all recovered-module imports, decoder CLI checks, M2 Keystone/Capstone assembly and disassembly, synthetic full-duplex pcap decryption, and PySide6 offscreen GUI startup. Use `.venv/bin/python` for the scripts. This environment satisfies Python dependencies only; it does not provide native binaries or every low-level layout. See `research/LIVE-VALIDATION.md` for live results and remaining blockers.

## Build identity

The saved profile was observed on 2026-10-25 and describes `MapleStory.exe` with PE machine `0x8664`, timestamp `0x6AE292F1`, image size `0x5E88000`, preferred image base `0x140000000`, and six code fingerprints. The narratives identify the anti-cheat as NGS-X 1.5.3.1. `locate-character.py` checks the PE identity and code fingerprints before resolving addresses. Exact per-script capture dates and independent validation states are not present in the single-commit drop, so no per-file live/offline provenance label is inferred.

## Direct runtime dependencies

| Artifact | Direct caller(s) | Role | Recovery status |
|---|---|---|---|
| `transport-cipher.py` | `wire-session-decrypt.py` | Four-round transport IV roll and strict table loading | Reconstructed; offline known-answer checked |
| `transport-shuffle-table.bin` | `wire-session-decrypt.py`, `transport-cipher.py` | Standard 256-byte MapleStory shuffle permutation | Restored; length/permutation checked |
| `observe-position-reset.py` | `atkspeed.py`, `edit-melee-swap.py`, `overhead-attacks.py`, `sendpacket-drop.py`, `sendpacket-observe.py` | Character resolver export, x86-64 registers, checked ptrace, bounded stop waiting | Reconstructed; offline layout/helper checked; no attach performed |
| `mob_profile.py` | `vac-sprites.py`, `mob-count.py` | Strict conversion and schema validation for `profile.json` mob offsets | Reconstructed; offline parsing checked |
| `mob-count.py` | `position-gui.py` (subprocess) | Read-only CMob scan and `MOBS N [xmin=X xmax=Y]` output | Reconstructed; invalid-controller handling fixed; live scan validated with 17 mobs |
| `try-collision-miss.py` | `overhead-attacks.py` | Collision fingerprint/context and local MISS eligibility gates | Gates recovered from live disassembly (`r13`, `r14+0x140`); native forcing remains unverified |
| `try-native-reset.py` | `position-gui.py` | Read-only portal snapshots/tokens/destination validation and native CLI contract | Read-only discovery validated with 24 records/eight usable destinations; **`--execute` blocked** because the native register/stack call sequence was omitted |
| `launch-game.py` | `position-gui.py` | UMU environment, process/preload checks, private launch log | Reconstructed; missing-artifact refusal checked; actual launch blocked by absent game/preload |
| `hotkeys.py` | `position-gui.py` | Qt signals and passive Linux evdev listener | Reconstructed and imported; current host has zero readable evdev devices exposing every GUI binding, so global hotkeys remain unavailable |
| `dl.py` | `m2-detour.py verify` | Read the omitted pristine memory dump for offline cross-checking | **Not included / not reconstructed**; no dump or reader contract is present |
| `damage-rng.py` | Operator CLI | Unified solve, replay, capture, search, and analysis workflow | Offline self-test passed; live replay and 100-state search validated |
| `rng-state-solver.py` | `damage-rng.py`, `rng-roll-override.py`, `rng-max-search.py` | GF(2) solver for single and simultaneous roll targets | Known targets, salts, critical states, and multi-target states checked |
| `rng-state-override.py` | `damage-rng.py`, `rng-roll-override.py` | Exact state write/readback, replay, and complete 44-byte restoration; optional incoming drop tracing | Repeated 22/30/34 damage and forced-critical experiments passed; `TRACE_DROPS=1` adds read-only `0x3f3`/`0x471` without a generator breakpoint; three-hook replay/drop/detach child check passed; live validation pending |
| `replay-rng-drops.sh` | Operator CLI | Reusable auto-PID capture of 100 fixed-state damaging attacks with unique JSON and terminal-log outputs | Three-hook live capture survived two repeated critical attacks and logged their drops; 130-byte swing handling and 100-attack mode added; full run pending |
| `rng-roll-override.py` | Operator CLI | Solver-generated replay by target roll and index | Two forced critical strikes confirmed |
| `rng-dataset.py` | `damage-rng.py`, `capture-rng.sh` | Streaming attack-dataset recorder with resume and variable packet lengths | 100-attack JSONL dataset captured |
| `rng-max-search.py` | `damage-rng.py`, `run-rng-max-search.sh` | Near-maximum candidate generation and resumable search | All 100 candidates completed; maximum observed damage 34 |
| `drop-observe.py` | `capture-drops.sh`, `capture-interaction.sh` | Outgoing packet and client-memory differential recorder for drop research | 70-attack capture completed; optional full-memory mode added |
| `capture-drops.sh` | Operator CLI | Auto-PID/endpoint full-duplex pcap and state-change capture for kill/drop/pickup | Full-duplex drop session captured and decrypted |
| `memory-watch.py` | `drop-observe.py --full-memory` | Full writable-memory chunk snapshots and before/after diffs | Real modified-memory self-check passed |
| `capture-interaction.sh` | Operator CLI | Full writable-memory plus full-duplex interaction capture for drop-origin analysis | Multiple sessions captured/decrypted; throttling added for responsiveness |
| `focus-observe.py` | `capture-32b.sh` | Focused 0x32b/pickup-only packet and full-memory differential recorder | Compile/import checked; focused live capture pending |
| `capture-32b.sh` | Operator CLI | Auto-PID/endpoint focused 0x32b and pickup capture | Shell syntax checked; focused live capture pending |
| `alter-observe.py` | `capture-32b.sh` with `ALTER_32B=1` | Native/override 0x32b field test with post-send restoration | Compile/import checked; override experiment pending |
| `capture-death.sh` | Operator CLI | Lightweight full-duplex mob-death and drop-communication capture | 37 attacks, 11 `0x32b` events, and full-duplex pcap captured |
| `packet-observe.py` | `capture-packets.sh` | All-current-thread plaintext send/receive and constructor observer | Normal packet capture preserved; repeated-state drop experiments use `rng-state-override.py` instead |
| `capture-packets.sh` | Operator CLI | Auto-PID plaintext packet-capture wrapper with streamed private JSONL and driver-error logs | Live packet capture passed; obsolete `RNG_MODE`/`RNG_REPLAY_WORDS` invocations are rejected in favor of the simpler replayer |
| `duplicate-pickup.sh` | `capture-packets.sh` with `DUPLICATE_32B=1` | One-shot duplicate pickup wrapper with microsecond timing | Shell syntax checked; live duplicate result pending |
| `protocol-static.py` | Operator CLI | Static outgoing constructor, encoder, and SendPacket call-site extractor | Fingerprint checks, compilation, and live-image analysis passed |
| `outgoing-packet-capture.py` | `capture-outgoing.sh` | Rich outgoing plaintext/constructor logger with optional single-opcode suppression and pre-send policy evaluation | Other-session live capture completed 100 sends and 24 deep-field changes; child test passed one allowed packet, one logged drop, and clean detach; policy hook is offline-tested and needs a live run |
| `capture-outgoing.sh` | Operator CLI | Auto-PID/endpoint wrapper for rich outgoing capture, deep tracing, one-opcode filtering, and `--filter-policy` | Shell syntax and invalid/repeated-option rejection passed; defaults to no packet suppression |
| `traffic/` (`python -m traffic`) | Operator CLI; `outgoing-packet-capture.py`, `ngs-proxy.py` | Ordered pcap/pcapng/plaintext/monitor/NGS ledger, TCP reassembly, transport/field decode, provenance, explain/trace, policy evaluation and kfilter translation | Offline synthetic suite passes; no live game run performed |

`observe-incoming-display.py` reaches `observe-position-reset.py` and `try-collision-miss.py` transitively through `overhead-attacks.py`. These are not additional direct dependencies.

The IV transform and shuffle bytes match the documented MapleStory `getNewIV` structure, including the 32-bit rotate-left by three after each round. The public [MapleLib `MapleCrypto.cs`](https://github.com/hadeutscher/MapleLib/blob/master/MapleCryptoLib/MapleCrypto.cs) and [`CryptoConstants.cs`](https://github.com/hadeutscher/MapleLib/blob/master/MapleCryptoLib/CryptoConstants.cs) provide an independent algorithm/table cross-check; the saved MSCW notes supply the build address and seed.

## External artifacts and optional packages

| Artifact/package | Needed by | Status |
|---|---|---|
| `native-speedhack-v13.so` | `launch-game.py`, GUI launch/process cleanup | Not shipped; launch and GUI launch control refuse to proceed |
| `native-speedhack-v13.speed` | GUI speed controls | Not shipped; speed reads report unavailable instead of creating a default |
| `shield-blackout-v3.sh`, `v3-stop.sh` | GUI shield controls | Not shipped; both controls are explicitly disabled |
| Configured UMU/Proton/Wine prefix and Nexon executables | `launch-game.py` | Machine-specific paths remain in `profile.json`; absent on this host |
| `cryptography` | `wire-session-decrypt.py` | Replaces the former `Crypto.Cipher.AES` import; project environment 50.0.2 |
| `PySide6` | `position-gui.py`, `hotkeys.py` | Required for GUI only; project environment 6.12.0 |
| `capstone`, `keystone-engine` | `m2-detour.py` | Required for assembly/disassembly; project environment 5.0.9 / 0.9.2 |
| `mitmproxy` | `decode-flows.py`, `decode-heartbeats.py` | Required for capture decoding; project environment 12.3.1 |

Third-party Python requirements are pinned in root `requirements.txt`. No package was installed into the system Python environment; the verified project `.venv` remains available for local use.

## Historical names intentionally not restored

`header-cipher.py`, `vm-lift.py`, `reanchor.py`, `dr-scrub.py`, `code-integrity-probe.py`, `enumerate-mob-positions.py`, raw pcaps, and other narrative-only probes are not direct dependencies of the shipped runtime callers. Their algorithms or data are not sufficiently included to reproduce the original artifacts faithfully; they remain absent rather than being replaced with invented implementations.
