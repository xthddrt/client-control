# Consolidated recovery and Linux-readiness plan

## Decision and scope

Plan 2 is the base: restore the omitted direct runtime dependencies where the shipped callers and saved profile define their contracts, repair portable paths, and verify only offline behavior. The repository is a redacted research drop for a closed research LAN, not a self-contained application. No live game, anti-cheat, firewall, ptrace, process-kill, or process-memory-write operation is part of verification.

From plan 1, the objective additions are an explicit third-party dependency manifest, a complete omitted-module inventory, removal of pre-redaction absolute paths, and a fresh redaction review. Script-relative paths are preferable to plan 1's global `RESEARCH_DIR`: they need no configuration and match the already portable callers. Per-script provenance headers are not added because exact per-file capture dates and validation states are not recoverable from this single-commit drop; the inventory will record the known build fingerprint and honest recovery status instead.

The upstream repository contains one import commit and the same files as this workspace. It provides no omitted implementations or later fixes. Missing historical narratives, captures, firewall scripts, native preload binaries, and unrelated tools will not be fabricated.

## Implementation

### 1. Recover passive transport-cipher support

- Add `tools-QUARANTINE/transport-cipher.py` with strict four-byte IV and 256-byte permutation validation plus the documented four-round `getNewIv` transform (seed `0xc65053f2`, rotate-left 3, and custom fourth-round expression).
- Add `tools-QUARANTINE/transport-shuffle-table.bin` containing the standard MapleStory 256-entry shuffle table cited by the research notes. Validate length and permutation, and use a known-answer vector rather than merely checking that the function runs.
- Replace the unused-elsewhere `Crypto.Cipher.AES` dependency in `wire-session-decrypt.py` with the installed `cryptography` AES ECB primitive. Keep capture parsing and decryption behavior unchanged.

### 2. Restore shared Linux and read-only helpers

- Add `observe-position-reset.py` to expose `locate-character.py` as `character`, define the x86-64 `user_regs_struct` layout as `Registers`, check `ptrace` return values with `ctypes` errno, and bound `wait_stop` using `waitpid(..., WNOHANG)` and a monotonic deadline.
- Add `mob_profile.py` to require exactly the offsets consumed by `vac-sprites.py` and `mob-count.py`, reject missing/unknown/non-integral values, and convert documented numeric strings with `int(value, 0)`.
- Add `mob-count.py` as a read-only scanner using the existing validated image/profile and protected-value reader. Emit the GUI contract `MOBS N [xmin=X xmax=Y]`, support a PID argument and clean `stop`/EOF handling, and never write process memory.

### 3. Restore scoped combat and portal helpers

- Add `try-collision-miss.py` with `verify_collision_code`, `collision_context`, and `eligible`, reusing `observe-incoming-display.py` fingerprint verification and event decoding. Preserve the local-actor, expected-call-frame, monster-present, attack-record-absent, and native-status gates; status `2` remains the only forced result and no server acceptance is claimed. Live disassembly subsequently established `r13` as monster state and `r14+0x140` as the attack-record status field; the forcing path remains unverified until its breakpoint-delivery issue is resolved.
- Add `try-native-reset.py` with portal enumeration, stable snapshot tokens, destination validation, controller/snapshot staleness checks, and the CLI used by `position-gui.py`. Require the saved function and update-boundary fingerprints and provide an offline validation/dry-run path. The original native-call register/stack sequence is absent, so `--execute` must refuse explicitly after validation and the GUI teleport control must remain disabled; do not invent a process-memory call.

### 4. Restore orchestration and repair callers

- Add `launch-game.py` with `expand_user`, `PRELOAD_LIBRARY`, executable/preload validation, process discovery, `preload_loaded`, and `launch_game`. Return the `subprocess.Popen` and private log path expected by the GUI. Refuse to launch while the omitted native preload is unavailable rather than silently starting a different configuration.
- Add `hotkeys.py` with the GUI's Linux evdev key constants, labels, and `QThread` signals. Fail with a clear message when evdev devices or permission are unavailable; do not add a desktop-specific fallback.
- Replace every pre-redaction absolute workspace path in callers with paths relative to each script. Point park, mob-count, and core controls at shipped files.
- Explicitly disable the unavailable shield controls and native-preload launch path in the GUI. Do not invent firewall rules or a preload binary. Keep process-kill controls unchanged and unexercised.

### 5. Add recovery metadata and review redaction

- Add root `requirements.txt` covering third-party imports actually used by the shipped and recovered Python code: `cryptography`, `PySide6`, `capstone`, `keystone-engine`, and `mitmproxy`. Use compatible lower bounds based on the APIs used; do not claim uninstalled packages were tested.
- Add `tools-QUARANTINE/DEPENDENCIES.md` with every omitted direct runtime module, its callers and role, native/external artifacts, current recovery status, and the build identity from `profile.json`. Distinguish shipped, reconstructed, unavailable, and offline-only validated artifacts.
- Update the artifact index and redaction notes to reflect recovered files and the new review. Scan documentation, evidence, and source for live account/session identifiers and the removed pre-redaction workspace paths. Preserve intentional technical constants and redaction placeholders.

## Verification

- Byte-compile every Python source file with caches directed to a temporary directory.
- Import all recovered support modules without attaching to a process; import the GUI only with PySide6 available and hotkeys disabled.
- Run offline assertions for table validation, IV known answers, AES compatibility, mob-profile parsing, register size, bounded-wait behavior, portal token/destination validation, collision gates, process-name parsing, and launcher refusal on missing artifacts.
- Run the documented `ngs_cipher.py` decode sample and an encrypt/decrypt round trip.
- Generate a minimal synthetic pcap and exercise `wire-session-decrypt.py` end to end without a game or network connection.
- If PySide6 can be installed in an isolated temporary environment without changing the project environment, inspect GUI startup with `QT_QPA_PLATFORM=offscreen`, hotkeys disabled, and no live process. Otherwise report the GUI runtime check as blocked.
- Review the final workspace for generated caches, logs, clones, and other verification artifacts and remove only artifacts created by this recovery.

## Remaining limits

Offline checks establish interface consistency and deterministic helper behavior, not live correctness. Native portal execution remains blocked because its calling sequence was omitted. Collision gates have since been recovered from live disassembly, but forcing remains unverified. Other live client behavior, server acceptance, anti-cheat outcomes, and evdev/device behavior remain unverified. See `LIVE-VALIDATION.md` for confirmed live results, corrections made during sequential testing, and the remaining recovery order.
