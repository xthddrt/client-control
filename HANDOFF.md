# MSCW NGS/GRAP research handoff

Date: 2026-11-05
Branch delivered to `main` after review/merge.

This is the authoritative resume point for work on another computer. It separates live evidence from static validation, failed experiments, and unfinished research. Do not infer that every tool in the repository works.

For the completed damage-RNG workflow, start with `DAMAGE-RNG.md` and `tools-QUARANTINE/damage-rng.py`. Its `solve`, `replay`, `capture`, `search`, `analyze`, and `self-test` commands package the results below.

## Environment and build identity

Recovered tools target this unpacked client build:

- PE timestamp: `0x6AEB667B`
- Image size: `0x5F2E000`
- Image base: `0x140000000`
- Character global: `0x3bda828`
- Movement-controller vtable: `0x34113a8`
- CMob vtable: `0x3516c98`
- SendPacket RVA: `0x1661780`
- Attack selector RVA: `0x859480`
- Selector caller RVA: `0x2982aa0`
- Sword action field: `0x7ec`, action ID `0`

If the new computer has different PE metadata, stop and reanchor. Do not reuse RVAs blindly. Historical PIDs in this document are examples, not reusable process IDs.

The tested prefix and launcher were:

- Wine prefix: `/home/richard/.wine-nexon`
- Launcher: `/home/richard/.wine-nexon/drive_c/Program Files (x86)/Nexon/Nexon Launcher/nexon_launcher.exe`
- Game: `/home/richard/.wine-nexon/drive_c/Nexon/Library/maplestorycw/appdata/MapleStory.exe`

Adjust `tools-QUARANTINE/launch-ngs-mitm.sh` if the other installation differs.

## Setup

```bash
git clone https://github.com/xthddrt/mscw-ngs-grap-research.git
cd mscw-ngs-grap-research
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m pip check
```

The venv and `captures/` are Git-ignored. Captures may contain credentials, tokens, memory, and private traffic. They are local-only, normally mode `0600`, and must not be committed or pasted publicly.

## What is proven working

| Capability | Evidence and exact scope |
|---|---|
| Character/CMob resolution | Validated live character snapshot and a populated mob scan. |
| VAC and park | X-only VAC, X pinning, Y with foothold synchronization, controller-B hold, and a one-slot park/release were demonstrated. Multiplayer visuals were not tested. |
| Collision MISS | One forced MISS followed by one normal damaging hit was visually confirmed. |
| Sword attack-frame timing | Five attacks at 1.2× produced 13 timer writes and 527 ms saved without a watchdog disconnect. |
| SendPacket observation/drop | Full melee packets are observable. Two `0x1ef` packets were dropped over four minutes without a disconnect. |
| M2 integrity-read detour | Active detour plus a harmless padding substitution survived 240 seconds with no disconnect, then restored detour, payload, and cave. This does not prove concealment of every possible sampled address. |
| Network telemetry shield | Two Nexon shield connections closed; a 120-second soak had zero MapleStory HTTPS/8484 connections and zero game-channel losses. |
| NGS proxy and response rewriting | Live `x-update`, `x-init`, and two `x-csauth` issue requests returned HTTP 200. `x-init` had `signature` and `subfeature` neutralized, and the character entered the world through the proxy. |
| Attack/damage correlation | Four sword attacks showed 26, 24, 21, and 20 damage. All four matched the outgoing damage field and had paired selectors and pre/post memory snapshots. |

### M2 addresses

- Detour: `0x1416689a1`
- Return: `0x1416689aa`
- Cave: `0x14335891a .. 0x143359000`
- Test padding byte: `0x1402b5449`, original `0xcc`, test value `0x90`

M2 is currently **off** and the original bytes were restored.

### Network shield scope

`shield-blackout-v3.sh` finds the MapleStory and wineserver cgroups and rejects their outbound TCP destination ports 443 and 8484. It does not block game ports 8563/8913 or unrelated applications. It is not a plaintext logger and does not stop local GRAP scanning, in-band opcode `0x1ef`, server-directed integrity reads, or server-side gameplay validation.

Use only in-session; lower it before logout/login because the telemetry flush can be synchronous:

```bash
sudo tools-QUARANTINE/shield-blackout-v3.sh MapleStory.exe
# Stop and remove its dedicated firewall chain:
sudo tools-QUARANTINE/v3-stop.sh
```

`v3-stop.sh` prints counters before removing the chain. Newer starts also emit rate-limited kernel logs with prefix `MSCW_NGS_SHIELD`; every rejection is counted even if logging is rate-limited:

```bash
journalctl -k -g MSCW_NGS_SHIELD -f
sudo iptables -nvL MSCW_NGS_SHIELD
```

### NGS proxy and response neutralization

`ngs-mitm.py` logs exact NGS requests and decoded responses. With `ngs_neutralize=true`, it also:

- pins `emergency_stop=0` when present;
- pins `detected=[]` when present;
- pins `config_changed=0` when present;
- empties `subfeature` and `signature` while preserving their container types;
- preserves `module_crc` and unrelated fields.

This does not decode the separate client-to-server NGS request/attestation cipher and does not affect raw gameplay validation.

To run a proxied session, fully close MapleStory and the launcher, then:

```bash
tools-QUARANTINE/launch-ngs-mitm.sh
```

The script starts mitmproxy on `127.0.0.1:8080`, copies the mitmproxy CA to `C:\mitm-ca.pem` in the Wine prefix, launches Nexon with proxy/CA environment variables, and leaves the proxy running until Ctrl+C. The indefinite proxy lifetime is intentional: process-based monitoring exited during a launcher handoff.

Live evidence from PID 400403:

- `x-update.ngs.nexon.com/v2`: HTTP 200; no field change needed.
- `x-init.ngs.nexon.com/v1`: HTTP 200; `signature` and `subfeature` neutralized.
- Two `x-csauth.ngs.nexon.com/v1/issue` calls: HTTP 200.
- Character entered the world and had an active connection to `127.0.0.1:8080`.

Logs are written as `captures/ngs-events-<timestamp>.jsonl`, `ngs-flows-<timestamp>.mitm`, and `ngs-proxy-<timestamp>.log`.

## Failed or limited experiments

### GRAP-core crash

The approved `grap-core-crash.py arm --go` test installed the `NtWriteFile` detour, but the core was still alive at the first check. MapleStory exited 42 seconds later and restarted with a new core. The user observed additional restarts. This did **not** reproduce the original author's aged-session core-kill result and is not viable for normal gameplay. Do not retry it as a routine blocker.

### SSL plaintext observer

An experimental OpenSSL observer was abandoned after thread-specific occupied debug-register slots and zero captured writes. The file was removed. It is not part of the delivered toolkit. NGS request/attestation plaintext remains unresolved.

### HP/result observer

Static live-memory checks recovered and fingerprinted:

- Context global `0x3bda7b0`
- Stat accessor `0x2d7feb0`
- HP field `0x67`, mask `0x800`
- HP block `0x319c9a`, writer `0x319cb0`
- Result serializer `0x2aa710`, call `0x296e3b3`

The protected-integer algorithm itself was unchanged. A 120-second result observer timed out without a hit, so live result/HP correlation remains **unverified**. An earlier mistaken constructor call was corrected before any capture.

### Packet capture limitations

The first combat pcap used only ports 8563/8913 and contained 16 tiny keepalive segments (80 payload bytes), not the attack stream. On the relevant session, MapleStory had **no 8563 connection** and instead used `44.234.162.36:8484` plus `8913`. Future captures must include 8484 and should re-check current sockets rather than assuming fixed endpoints.

`wire-session-decrypt.py` works offline and on historical captures, but its connection chooser selected the small launcher stream in that pcap. A future capture with multiple active connections may need explicit connection selection rather than blindly using the largest byte count.

## RNG investigation: exact current state

### Established earlier

- Melee packets are 232 bytes and body offset `0x88` matched displayed sword damage.
- Editing that field from native 25 to 23 did not change the resulting 25. Do not repeat packet-only damage rewrites.
- Equipped versus unequipped weapon damage on the same mob was 20 versus 5. Weapon stats affect the client prediction, while the server recomputes or validates the result.
- The old `stats+0x60`/`stats+0x90` candidates did not change, and the old range sampler/damage helper did not fire. RNG origin was not established.

### New correlated capture

`attack-rng-observe.py` sets main-thread execute breakpoints at SendPacket and the attack selector. For each melee attack it stores:

- the full melee body and damage at `0x88`;
- action and selector timestamp;
- pre/post actor memory (`0x2000` bytes);
- pre/post calculator context (`0x3000` bytes);
- pre/post stat candidates at context offsets `0x2350` and `0x2998` (`0x400` bytes each);
- changed runs between pre and post states.

Validated sequence: **26, 24, 21, 20**, all with action 0 and paired selectors. No memory was modified and debug registers were restored.

The local capture is `captures/attack-rng-400403.json` on the original computer and is intentionally not committed.

### Earlier candidate memory findings

- `stats_2350` had no changes in these four attacks.
- `stats_2998` changed 12 bytes at `+0x00` and 12 bytes at `+0x20` on every attack.
- Every post-state matched the next attack's pre-state, so these are continuous stateful values, not random unrelated noise.
- Actor changes were dominated by action/timer/position fields.
- The common three-word `CRand32` formula and a one-transition reimplementation from `0x7ac850` did not reproduce the next state. A single transition was not the right comparison: the melee routine fills 11 rolls per attack.

### RNG object and algorithm recovered statically

The current executable establishes the missing link: `0x2d80710` returns the object at `context+0x2998`, and a melee-related path passes that exact pointer to the generator at `0x7ac850`. Thus `stats_2998` is the confirmed client RNG object, not merely a changing candidate.

The generator's three input words are at object offsets `0x00`, `0x08`, and `0x24`. Each call updates those words plus snapshots at `0x04`, `0x20`, and `0x28`, exactly explaining the two 12-byte change runs. Live captures show 11 transitions per basic melee attack, but they can span multiple callers. A statically traced damage routine has an 11-call array loop, yet the current basic attacks did not execute its scaler at `0x2d3ba0` or its result write at `0x2ad8a9`. One returned roll in the verified melee caller is overwritten without being used. Therefore RNG advancement is proven, but damage consumption is not.

`attack-rng-observe.py` implements the exact transition, predicts 11 transitions per attack, records all 11 rolls, and checks all six state/snapshot words. Its offline self-checks pass. Successive live captures reproduced the 11-step state transition; the latest capture matched 7/7 attacks after selector pairing was corrected. The observer now also has filtered breakpoints at the generator and shared scaler to identify the actual callers. No damage-roll claim is based on these state predictions alone.

`rng-write-watch.py` identifies data-watchpoint hits through `DR6` and records the watched address, post-write RIP/RVA, preceding code bytes, registers, stack, and updated state. Its live capture recorded 100 events/50 complete transitions. Every writer was in `0x7ac850`, and every saved stack identified caller `0x2ac76f`. That routine fills the 11-roll array at `0x2ac76a`; the current hit's roll is loaded at `0x2ac9a2` and consumed by the subsequent inline range calculation.

### Controlled damage-roll override: negative result

`rng-damage-override.py` tested three attacks at `0x2ac9a9`, after the critical-hit check and immediately after the current damage roll was loaded:

| Stage | Roll operation | Outgoing packet damage | Displayed damage |
|---|---|---:|---:|
| Native | No modification, original `1218335471` | 20 | 20 |
| Unchanged control | Wrote `2029730638` back and verified exact readback | 23 | 23 |
| Override | Changed `1795405682` to `4294967295` and verified exact readback | 18 | 18 |

The maximum roll did not change either the outgoing damage or displayed damage. This rules out that individual roll as the final damage-control input, but not the entire three-word state. The later whole-state replay below is the broader and more decisive experiment.

### Repeated three-word state replay: positive client-side result

`rng-state-override.py` next wrote the previously observed state `0c2418d6, cdf84fe7, 5e613e0a`, whose next roll is `fdc9f1d2` and whose earlier outgoing/displayed damage was 22. A native attack and unchanged-state control were followed by four independent replays. Each replay wrote the same triple, generated the same next roll, restored the complete original 44-byte RNG object, and verified every write/restoration.

| Stage | Outgoing packet damage | Displayed damage |
|---|---:|---:|
| Native | 19 | 19 |
| Unchanged control | 24 | 24 |
| Replay 1 | 22 | 22 |
| Replay 2 | 22 | 22 |
| Replay 3 | 22 | 22 |
| Replay 4 | 22 | 22 |

This is strong evidence that the three state words deterministically affect the client-side damage calculation and outgoing/displayed result. It supersedes the earlier broader inference that RNG state adjustment was not useful. The narrow single-roll negative result and the whole-state positive result are compatible: the final damage depends on a different roll or combination of rolls from the generated sequence.

Server HP loss has not yet been decoded, so server acceptance remains unproven. Outgoing/displayed determinism does not distinguish a client prediction from a server-confirmed result. A second replay state and inbound HP correlation are the next independent checks.

### Critical roll and unique-state reproduction of 30 damage

Roll index 4 is the 5% critical roll: `predicted_rolls[4] / 2^32 < 0.05`. Across 125 valid dataset attacks, every critical flag at packet byte `0x87 = 1` followed that rule and every noncritical attack did not. Two solver-generated states with index-4 roll 1 then produced two displayed critical strikes, confirming the mapping. Base damage correlates most strongly with roll index 2 in the same-mob dataset.

`rng-state-solver.py` was extended to solve simultaneous roll targets. Four unique triples preserved the first five rolls from the 30-damage critical hit, including roll 2 and critical roll 4. Every run completed and restored the original RNG object:

| Replayed triple | Native/unchanged damage | Replayed outgoing/displayed damage |
|---|---|---:|
| `fadbcf10 95db8810 76cf1a80` | 23 / 26 | 30 |
| `fadbcf11 95db8810 76cf1a80` | 20 / 21 | 30 |
| `fadbcf12 95db8810 76cf1a80` | 16 / 22 | 30 |
| `fadbcf13 95db8810 76cf1a80` | 22 / 22 | 30 |

This demonstrates deterministic damage reproduction with four previously unseen state triples, not merely replaying one memorized state. Captures are `captures/rng-30-0xfadbcf10.json` through `rng-30-0xfadbcf13.json`.

The multi-target solver then combined roll 2 `0xffffffff` with critical roll 4 `0`. The resulting state `b95365e0 e2793d38 000000d0` produced outgoing/displayed damage 33. Across 32 salted state variants satisfying those two targets, all 11 resulting rolls were identical, leaving no further roll variation to optimize under those constraints. This is the maximum identified for the current mob/equipment setup, not a proven game-wide maximum or a proof that every damage-affecting stat is understood.

### 100-state maximum-damage search

`rng-max-search.py` generated 100 unique state triples with roll 2 equal to `0xffffffff` or `0xfffffffe` and roll 4 below the 5% critical threshold, with 100 distinct 11-roll sequences. All 100 candidates completed and every original RNG object was restored. Results: 19 attacks reached 34, 17 reached 33, 22 reached 32, 25 reached 31, seven reached 30, and the rest were lower or had no damage field. No candidate reached 35. Example 34-damage state: `178e8921 a8fc3ce8 000000e4`, with roll 2 `0xfffffffe` and roll 4 `0x00100000`. Full candidates/results are in `captures/rng-max-100-candidates.json` and `captures/rng-max-100-results.jsonl`.

## Resume the RNG experiment here

1. Preserve `captures/rng-state-replay.json`: four identical replays produced 22 while native/unchanged attacks produced 19 and 24.
2. Replay a different known state and determine whether its earlier damage is also reproduced. Do not claim a general state-to-damage mapping from one triple alone.
3. Decode inbound mob-HP changes or use another authoritative health/death measurement to determine whether replayed damage is accepted by the server rather than only displayed.
4. If server acceptance is confirmed, map which generated rolls and stat inputs determine final damage before attempting any generalized RNG surfing or state-selection tool.

Example commands:

```bash
# Dedicated directory for tcpdump's restricted user:
sudo install -d -m 700 -o tcpdump -g tcpdump /tmp/mscw-capture
sudo tcpdump -i any -nn -s0 -w /tmp/mscw-capture/game-combat.pcap \
  'tcp port 8484 or tcp port 8913 or tcp port 8563'

# In another terminal, after locating the current PID and entering the world:
.venv/bin/python tools-QUARANTINE/rng-write-watch.py PID 180 captures/rng-writes.json

# For broader pre/post state and damage correlation:
.venv/bin/python tools-QUARANTINE/attack-rng-observe.py PID 600 captures/attack-rng.json

# After Ctrl+C on tcpdump, make the capture readable by the current user:
sudo install -m 600 -o "$USER" -g "$USER" \
  /tmp/mscw-capture/game-combat.pcap captures/game-combat.pcap
.venv/bin/python tools-QUARANTINE/wire-session-decrypt.py captures/game-combat.pcap
```

Run only one ptrace observer at a time. Stop observers with SIGINT and verify detachment/debug-register restoration. Do not run the failed GRAP-core crash, forged melee edits, or candidate seed edits as routine tests.

## File inventory added or changed in this recovery

- `shield-blackout-v3.sh`, `v3-stop.sh`: cgroup-scoped telemetry blocking, counters, logging, and cleanup.
- `ngs-mitm.py`: NGS request logging, response decoding, and optional neutralization.
- `launch-ngs-mitm.sh`: persistent proxy and proxied Nexon launch.
- `attack-rng-observe.py`: paired selector/melee packets, damage, and pre/post memory.
- `rng-write-watch.py`: writer identification for candidate state words.
- `position-gui.py`: exact shield-process matching instead of substring false positives.
- `observe-incoming-display.py`, `profile.json`: statically recovered HP/result anchors and HP mask.
- `LIVE-VALIDATION.md`, `PATCH-RECOVERY-GUIDE.md`, `ARTIFACT-INDEX.md`, `HANDOFF.md`: evidence and resume documentation.

## Remaining non-RNG work

- Native portal execution is still disabled because the native reset ABI is unknown; read-only discovery works.
- HP/result live validation is incomplete.
- Native speedhack preload and `.speed` file are absent.
- Global hotkeys lack a compatible readable evdev device.
- Full M2 offline `verify` still lacks `dl.py` and a pristine dump, although live detour tests passed.
- `atkspeed.py` forged melee and `edit-melee-swap.py` remain disconnect-prone and are not safe recovery targets.
- Server-side gameplay validation and NGS request/attestation encryption remain unsolved.
