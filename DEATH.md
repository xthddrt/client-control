# Full-duplex mob-death and drop capture

Use this module to identify the actual mob-death and drop-communication path rather than assuming that `0x32b` is the drop.

## Run

```bash
tools-QUARANTINE/capture-death.sh 180
```

Kill one mob at a time and record each outcome:

```text
Kill #: mob type, drop item/no drop, quantity, approximate pickup time
```

Include both no-drop kills and item-drop kills. Pick up each drop before killing the next mob when possible.

## What is recorded

- Every outgoing packet with timestamp, opcode, length, full body, caller RVA, packet/body addresses, and an eight-entry return stack.
- Combat selector details, damage, and combat-RNG state when relevant.
- Every incoming server packet in the full-duplex pcap.
- Timestamped offline-decrypted frames when IV recovery succeeds.

The observer does not perform full writable-memory scans, modify packets, or modify game memory. This avoids the full-memory pickup lag.

## Output

- `death-events-*.jsonl` — outgoing packets and combat/state changes.
- `death-session-*.pcap` — all client/server traffic on current endpoints.
- `death-session-*.pcap.decrypted.json` — timestamped decrypted frames.
- `death-driver-*.log` and `death-decode-*.log` — capture and decryption diagnostics.

Captures can contain private traffic, tokens, and memory. They are normally mode `0600` and must not be committed.

## Analysis method

First align each kill with its melee `0xe1` packet. Then compare no-drop and drop kills to distinguish:

- a mob-death notification from a drop spawn;
- a client-originated death/drop proposal from a server-originated drop;
- the actual pickup request from the server's inventory response.

`0x32b` was evaluated against the other opcodes and is now confirmed as the pickup request. With the death/drop path identified, use the scoped `TEST_MODE` experiments in `PACKETS.md` to test individual pickup fields while comparing the server's `0x8b` credit.

For direct inbound plaintext rather than transformed pcap opcodes, use `tools-QUARANTINE/capture-packets.sh 120`. The current receive hook is `0x1665364`, immediately before the call to `0x1667bc0`; the old `0x1638d40` anchor is not valid for this build. See `PACKETS.md` for the verified layouts and current opcode inventory.

A successful 45-second run captured five complete `0x32b` sends and all 55 field writes. A subsequent 90-second run matched six reported pickups with six `0x32b` sends and twelve `0x471` messages (two per drop). The confirmed path is: server `0x471` creates the drop with object ID at `0x04`, meso amount or item template at `0x15`, and killed target identifier at `0x2a`; client `0x32b` requests pickup with the drop object ID at `0x0f`; server `0x8b` credits the reward, with meso marked by `1` at `0x04` and amount at `0x06`, and items marked by `0` at `0x04`, template at `0x05`, and quantity at `0x09`; server `0x472` repeats the drop object ID at `0x02` and confirms/removes the picked-up object. Three `0x3f3` groups from the earlier run match target identifiers at melee `0x7d` and reach zero on the killing hits, making them the current mob HP/death candidates. Their decrements do not consistently equal displayed damage, so they do not yet prove the server's damage calculation.

## Killing-hit packets versus other traffic

The three killing hits in `packets-20261106-222916.jsonl` use the same `0xe1` melee format as non-killing hits: 232-byte damaging packets, the same action identifier and `User Melee` text, and the same hit-record structure. Damage at `0x88`, critical state at `0x87`, the target identifier at `0x7d`, and ordinary timing/position/RNG fields vary; there is no distinct kill opcode or kill flag in the checked fields. The final damage is not always a critical strike, and a critical strike also occurs on a non-killing hit. The 130-byte swings lack the `0x88` damage field and are not killing hits.

| Kill | Final damage | Critical at `0x87` | `0x3f3` zero after attack | First `0x471` after attack | Last outgoing before `0x3f3` zero | Last outgoing before `0x471` |
|---|---:|---:|---:|---:|---|---|
| 1 | 24 | 1 | 128 ms | 136 ms | `0x2a5`, 57 ms after attack | `0x2a5`, 57 ms after attack |
| 2 | 23 | 0 | 149 ms | 157 ms | `0x2fe`, 124 ms after attack | `0x2fe`, 124 ms after attack |
| 3 | 18 | 0 | 64 ms | 153 ms | No other outgoing packet before the zero | `0x13f`, 133 ms after attack and after the zero |

The killing `0xe1` is therefore the last attack/damage packet, not necessarily the last outgoing packet before death or drops. The current HP/death candidate is the `0x3f3` value reaching zero; `0x471` is the subsequent server-created drop notification. `0x2a5` is strongly supported as a batched mouse/keyboard input-event container: its records include `WM_MOUSEMOVE` (`0x200`), `WM_LBUTTONDOWN` (`0x201`), `WM_LBUTTONUP` (`0x202`), and virtual-key codes for Left Arrow, Shift, and Right Arrow. Its four bodies in this sequence are input history, not death/drop messages, and none contains the killed target identifier. `0x13f` also appears before the kills and is not a new kill-specific packet.

## Combat RNG replay versus death and drops

Use the existing repeated-state replayer with one additional read-only incoming hook:

```bash
tools-QUARANTINE/replay-rng-drops.sh 600
```

The wrapper auto-detects the current MapleStory PID on every invocation, handles sudo and output ownership, and creates unique timestamped JSON and terminal-log files under `captures/`. Use the same command after restarting MapleStory; no PID or filename edits are needed.

`FIXED_ONLY=1` skips the native/unchanged controls: exactly 100 damaging attacks use the same three state words, with roll 2 `0xfffffffe` and critical roll 4 `0x00100000`. Every replay restores its complete original state after the attack is sent. Non-damaging melee variants, including the observed 130-byte swing, are recorded in `non_damage_packets` and do not count toward the 100. Target IDs, positions, and timing remain native, so packets to different mobs are not byte-for-byte identical. The fixed triple previously produced 34 and, in the latest live run, 36 critical damage twice; absolute damage depends on current character stats.

`TRACE_DROPS=1` hooks only incoming `0x3f3`/`0x471` in addition to the existing selector/send hooks. The generator breakpoint was removed after three clients exited immediately after arming; the exact fatal mechanism is not proven. The result includes full melee bodies, damage, critical flags, HP candidates, drop contents, and predicted/actual combat states for comparison between attack and drop creation. It does not record individual generator callers. The observer remains attached for two seconds after the final replay to receive the last server response. This combined live drop comparison remains unverified; repeated client damage alone does not prove server acceptance or drop causation.
