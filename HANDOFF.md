# MSCW NGS/GRAP research handoff

Date: 2026-11-05
Branch delivered to `main` after review/merge.

This is the authoritative resume point for work on another computer. It separates live evidence from static validation, failed experiments, and unfinished research. Do not infer that every tool in the repository works.

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

### Candidate memory findings

- `stats_2350` had no changes in these four attacks.
- `stats_2998` changed 12 bytes at `+0x00` and 12 bytes at `+0x20` on every attack.
- Every post-state matched the next attack's pre-state, so these are continuous stateful values, not random unrelated noise.
- Actor changes were dominated by action/timer/position fields.
- The common three-word `CRand32` formula did **not** reproduce the next state.
- The shift/mask transition reimplemented from disassembly at `0x7ac850` also did **not** reproduce the next state.

Therefore these words are candidates only. They are **not confirmed damage RNG seeds**, and no adjustable seed has been proven.

`rng-write-watch.py` was then built to place write watchpoints on the first words of those two regions and record writer RIP, registers, stack, and updated bytes. It armed at `0x18685070` and `0x18685090`, but the client exited before the requested attack. No writer instruction was captured, and no live breakpoint remains.

## Resume the RNG experiment here

1. Start the proxy and enter a map with mobs using the same sword and no equipment changes.
2. Confirm the current MapleStory PID and all current remote ports with `ss -tnp`.
3. Start raw capture on the actual ports. Include 8484 and 8913; add the current channel port if different.
4. Arm `rng-write-watch.py`.
5. Attack once, record the displayed damage, and inspect each writer RVA with Capstone.
6. Identify the writer's exact algorithm before considering any state modification.
7. Reproduce several consecutive transitions offline. Then test **prediction without modification**: predict the next legitimate damage and compare it with the server/displayed result.
8. Only after a proven prediction, decide whether RNG surfing/timing is feasible. Do not edit a candidate seed based only on its changing value.

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
