# Dependency and recovery inventory

This inventory covers direct dependencies of the shipped scripts, not every historical filename mentioned in the narratives. Recovered modules are source-level reconstructions from the shipped callers and `profile.json`; offline validation does not establish live client behavior.

## Local offline environment

The checkout now has a project `.venv` with the exact tested versions pinned in `requirements.txt`. Recreate it with:

```bash
python3 -m venv --system-site-packages .venv
.venv/bin/python -m pip install -r requirements.txt
```

The installed environment passed byte-compilation, all recovered-module imports, decoder CLI checks, M2 Keystone/Capstone assembly and disassembly, synthetic full-duplex pcap decryption, and PySide6 offscreen GUI startup. Use `.venv/bin/python` for the scripts. This environment satisfies Python dependencies only; it does not provide native binaries or every low-level layout. See `LIVE-VALIDATION.md` for live results and remaining blockers.

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
| `rng-state-override.py` | `damage-rng.py`, `rng-roll-override.py` | Exact state write/readback, replay, and complete 44-byte restoration | Repeated 22/30/34 damage and forced-critical experiments passed |
| `rng-roll-override.py` | Operator CLI | Solver-generated replay by target roll and index | Two forced critical strikes confirmed |
| `rng-dataset.py` | `damage-rng.py`, `capture-rng.sh` | Streaming attack-dataset recorder with resume and variable packet lengths | 100-attack JSONL dataset captured |
| `rng-max-search.py` | `damage-rng.py`, `run-rng-max-search.sh` | Near-maximum candidate generation and resumable search | All 100 candidates completed; maximum observed damage 34 |

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
