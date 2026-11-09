# Packet decoding: current build

## What is verified

The original packet-boundary method works, but several inherited addresses and packet names were stale or only hypotheses. Use the current build's addresses below, not the old `ProcessPacket` address `0x1638d40`.

### Outgoing boundary

`SendPacket` is RVA `0x1661780`. Its argument is a plaintext `COutPacket` before transport and opcode transformation:

- opcode: `+0x434`, 32-bit;
- encoded length: `+0x428`, 32-bit;
- inline body: `+0x8`, including the opcode as its first two bytes.

The current `COutPacket` constructor is RVA `0x7614b0`. Its `edx` argument is the opcode. The following serializer addresses were verified by disassembly:

| Routine | RVA | Behavior |
|---|---:|---|
| `Encode1` | `0x7617d0` | Appends one byte and advances length by one. |
| `Encode2` | `0x7618d0` | Appends a little-endian 16-bit value. |
| `Encode4` | `0x761960` | Appends a little-endian 32-bit value. |
| `Encode8` | `0x761b50` | Appends a little-endian 64-bit value. |
| `EncodeBuffer` | `0x761ea0` | Appends `r8d` bytes from `rdx`. |
| double encoder | `0x761bb0` | Appends an eight-byte floating-point value from `xmm1`. |
| string encoder | `0x761c10` | Appends a 16-bit length followed by the string bytes. |

`analysis/protocol-static.py` enumerates constructor calls, these encoder calls, and direct `SendPacket` calls by function. For example:

```bash
.venv/bin/python analysis/protocol-static.py \
  /home/bob/.wine-nexon/drive_c/Nexon/Library/maplestorycw/appdata/MapleStory.exe \
  --opcode 0xe1 --opcode 0x13f --function 0xfb90d0
```

A computed opcode is reported as `dynamic`; absence of a direct constant constructor is not proof that a packet does not exist. Value expressions are static source expressions, not claims about their runtime values.

### Incoming boundary

The current receive path is:

```text
0x16650f0: frame handling
  -> 0x75d440: construct CInPacket
  -> 0x75c6d0: copy the completed packet
  -> 0x75d970: transform/decrypt the body and advance the rolling IV
  -> 0x1665364: prepare the CInPacket argument
  -> 0x1665371: call 0x1667bc0, the VM-backed packet dispatcher
```

The observer hooks `0x1665364`, immediately before the dispatcher call. The live records have:

- data pointer at `CInPacket+0x10`;
- total buffer length at `+0x18` = payload length + 4;
- payload length at `+0x20`;
- cursor at `+0x24` = 4;
- payload at `data+4`, with the opcode in its first two bytes.

The old pcap decoder remains useful for transport ciphertext, but its first two bytes must not be treated as semantic opcode IDs. The direct inbound records instead had low-range opcodes such as `0x3dc`, `0x3e7`, `0x29d`, and `0x282`.

All 9,320 events in the first all-thread capture occurred on the main game TID even though the other threads were armed. That is the observed threading behavior for this path in this session; the inherited blanket statement that this receive hook must be on a separate network thread is not supported by this capture.

## Observed client-to-server packets

Meanings are limited to what static code and live correlation support. A constructor record is not a send: one `0x1a7` constructor ran 3,003 times while only three `0x1a7` packets were sent.

| Opcode | Confirmed layout and behavior | Meaning status |
|---|---|---|
| `0xe1` | Usually 232 bytes; also 130/240-byte forms. Varying 32-bit identifier at body `0x20`; critical flag at `0x87`; damage at `0x88`. | Melee attack, confirmed. The `0x20` identifier is not yet proven to be a mob ID. |
| `0xdb` | Starts with `Encode1`, `Encode4`, `Encode4`, `Encode1`, followed by nested movement data. | Movement/synchronization, confirmed by constructor and bodies. |
| `0x2fe` | High-frequency movement/state records. Constructor `0x1d43ab1`; first fields include a 32-bit value from `r12+0x3a0`, a 16-bit value, flags, then movement blocks. | Movement/state stream, confirmed. |
| `0xe7` | 160-byte report in current captures. One constructor is `0x296e39f`, followed by send at `0x296e3bf`. | Periodic game-state report; exact report name unresolved. |
| `0x70` | Observed 11-byte subtype-5 form: byte `5`, a 32-bit tick-like value, and a 32-bit context value. Other subtypes exist. | Timestamp/context message family; not enough evidence for one universal name. |
| `0x13f` | Constructor `0x2dd93d9`; starts with one byte, followed by fixed-width values from a tree-like structure. Observed length 27. | Structured state report; exact event unresolved. |
| `0x1a7` | Variable-length batch/report. Two construction paths at `0x2dd7b82` and `0x2dd81c0`; observed lengths 22 and 30. | Batched metric/event records; exact record names unresolved. |
| `0x1ef` | A family of structurally different reports, not one uniform 160-byte packet. One 14-byte path at `0x2edc693` contains constant `0x65` and two context values; another capture contained 174 bytes. | Must be labeled per call site, not globally called telemetry. |
| `0x32b` | Always 36 bytes so far. Constructor `0x145052bf6`; send caller `0x14504dd6a`. After the opcode, the observed serializer writes `u8, u32, u32, u16, u16, u32, u32, u8, u32, u32, u32`. The value at `0x0f` is the drop object ID from `0x471`. | Pickup request, confirmed by six user-reported pickups. The `0x03` identifier and other metadata remain unresolved; `0x20` is not the meso amount or item quantity. |
| `0x407` | One earlier 20-byte observation; no direct constant constructor found in the static scan. | Unresolved; no live occurrence in the newest capture. |
| `0x326` | 12 bytes: context value `0x2b6`, two bytes from arguments, and a 32-bit argument. Constructor `0x1ed7839`. | Request echoed as inbound `0x456` with the same body. Exact feature name unresolved. |
| `0x265` | One 74-byte observation, with scalar/vector data. Constructor `0x2d0f748`; send caller `0x142d0f8fd`. | Unresolved rare state/field message. |
| `0x266` | One 22-byte observation immediately after `0x265`. Constructor `0x2d0fa6e`; send caller `0x142d0fad8`. | Unresolved rare state/field message. |
| `0x2ef` | 14 bytes; observed body after opcode is three 32-bit values `2`, `33`, `185`. Sent at roughly ten-second intervals. | Periodic status report; exact meaning unresolved. |

### Melee serializer path

The captured `0xe1` path at `0x2982aa0` constructs the packet at `0x2985eb6`, then calls:

| RVA | Role established from the code |
|---:|---|
| `0xfb90d0` | Serialize the fixed attack header using 1-, 2-, and 4-byte fields and a length-prefixed string. |
| `0xfb9050` | Serialize a collection header, then invoke the per-hit serializer for each record. |
| `0xfb8ca0` | Serialize one hit: two 32-bit fields, a byte-sized subcount, per-subrecord flags and a 64-bit value, then additional position/result fields. |
| `0x8af4f0` | Serialize trailing state and optional records. |
| `0x1661780` | Send the completed plaintext packet. |

The generic melee helper layouts can be printed with `--function 0xfb90d0`, `--function 0xfb9050`, or `--function 0xfb8ca0`. Conditional fields must be checked against the captured variant rather than assuming that every branch executes.

### Observed wire aliases

These are transforms observed in one earlier session, not semantic opcode names or universal constants. Matching packets had identical bytes after the first two opcode bytes.

| Plaintext | Wire value | Evidence |
|---|---|---|
| `0x70` | `0x70` | Observed subtype-5 packet. |
| `0xdb` | `0xda82` | Repeated body matches. |
| `0xe1` | `0xf6c7` | Repeated melee body matches. |
| `0xe7` | `0x8e7c` | Repeated body matches. |
| `0x13f` | `0xd088` | Repeated body matches. |
| `0x1a7` | `0xaa27` | Observed body matches. |
| `0x1ef` | `0xd5fd` | Exact 14-byte body match; does not label the separate 149-byte `0x9c` path. |
| `0x2fe` | `0xf70d` | Repeated body matches. |
| `0x32b` | `0xfbd0` | Repeated body matches. |
| `0x407` | `0xa817` | Single observed match. |

## Live capture

```bash
analysis/capture-packets.sh 120
```

### Outgoing logger and one-opcode filter

For the richer outgoing logger built in the other session, use:

```bash
analysis/capture-outgoing.sh 300
```

This records outgoing plaintext bodies, timestamps, thread IDs, registers, caller stacks, constructor links, and a raw full-duplex pcap. `outgoing-events-*.jsonl` contains the semantic send/constructor records, `outgoing-session-*.pcap` contains the network traffic, and `outgoing-driver-*.log` contains terminal diagnostics. Newly created threads are tracked, and `--deep-opcode HEX` optionally records detailed construction field writes for selected opcodes.

The default performs no packet-content modification. To suppress exactly one outgoing opcode while logging it, add:

```bash
analysis/capture-outgoing.sh 300 --drop-opcode 0x1ef
```

Only that opcode is redirected to return `TRUE` from `SendPacket` without transmitting. Its record has `dropped: true`; all other packets have `dropped: false`, and the incoming raw pcap is unchanged. `counts.dropped` and `session_start.drop_opcode` record the experiment configuration. The wrapper rejects repeated or invalid drop options before sudo.

Use one filter at a time and treat the result as phase-specific: a packet that can be dropped during combat may be required at login, a portal, or a later heartbeat. `send_complete` reports observer health, not that dropping was safe for gameplay. A previous four-minute test dropped two `0x1ef` messages without a disconnect, but that does not prove every `0x1ef` form is nonessential.

This logger covers the MapleStory game process, not every launcher/NGS protocol. Use the NGS proxy for HTTPS control traffic. The pcap uses endpoints discovered at startup, so a later reconnect to a different endpoint needs another capture. `capture-packets.sh` remains the simpler full-duplex plaintext observer; do not run two ptrace observers concurrently.

### Repeated combat state versus drops

Use the existing repeated-state replayer, not the packet observer, for this experiment:

```bash
analysis/replay-rng-drops.sh 600
```

The same command works after restarting MapleStory. It auto-detects the current PID and creates unique timestamped JSON and terminal-log files under `captures/`, including the exact error when a run fails.

`FIXED_ONLY=1` skips controls and performs exactly 100 damaging attacks with the same three RNG words. Each attack's original complete state is restored after sending. Non-damaging variants such as the observed 130-byte swing are logged separately rather than aborting or counting as attacks. Target identifiers and timing remain native, so packets to different mobs are not byte-for-byte identical. Use one mob type and record each kill's drop.

`TRACE_DROPS=1` adds only the read-only incoming `0x3f3`/`0x471` hook. The generator breakpoint was removed after three clients exited immediately after arming; the logs do not prove whether anti-cheat or another breakpoint fault caused those exits. The result uses the three-hook send/selector/incoming configuration instead. `death_drop_events` includes HP candidates, drop contents, and current state words. `packets` includes complete melee bodies, damage, critical flags, target identifiers, predicted eleven-transition states, and actual post-attack states. Comparing packet and drop snapshots can reveal state changes without a generator breakpoint; it does not identify individual generator callers or prove server acceptance/drop causation. A child-process check passed native/unchanged/fixed replay, exact restoration, drop/HP capture, final-response capture, and clean detachment. Live client stability remains to be verified.

With no `TEST_MODE`, the packet observer remains read-only. The following opt-in experiments use a native control followed by one scoped edit, with readback and guarded restoration:

| `TEST_MODE` | Experiment |
|---|---|
| `1` | Double the meso amount at `0x471+0x15` before client dispatch; do not edit `0x32b`. |
| `2` | Increment the unresolved identifier at `0x32b+0x03`. |
| `3` | Change the zero field at `0x32b+0x07` to one. |
| `4` | Increment the position-like 16-bit field at `0x32b+0x0b`. |
| `5` | Increment the position-like 16-bit field at `0x32b+0x0d`. |
| `6` | Increment the item-specific metadata at `0x32b+0x13`; zero becomes one for meso. |
| `7` | Change the flag at `0x32b+0x17` from one to two. |
| `8` | Increment the context value at `0x32b+0x18`. |
| `9` | Increment the context value at `0x32b+0x1c`. |
| `10` | Increment the unresolved metadata at `0x32b+0x20`; this is not a confirmed quantity. |
| `11` | Change the flag at `0x32b+0x02` from one to two. |
| `12` | Change one nonzero `0x3f3+6` value to zero before dispatch, preserving the object ID and restoring after dispatch. |

For example, `TEST_MODE=10 analysis/capture-packets.sh 90` tests the unresolved `0x20` field. The first pickup is native and the next is modified once; later pickups remain controls. The drop object ID at `0x0f` is not edited. Compare `native_body`, `body`, `override`, `inbound_restore`/`outbound_restore`, and the resulting `0x8b` credit. No result should be called a quantity change unless the credit demonstrates it. These experiments can alter client state, fail validation, or disconnect; the read-only mode is the default.

### Result: `TEST_MODE=1`

The first live experiment used a meso drop whose native amount was `6`. Both `0x471` messages were changed to `12` before dispatch, and both `inbound_restore` records returned `restored=true`. The subsequent `0x32b` remained native and used the original drop object ID `0x143ff` at `0x0f`. The server then sent `0x8b` with meso type `1` and amount `6` at `0x06`, not `12`, before `0x472` removed the same drop object. Therefore, editing the incoming `0x471` amount changed the client-side packet but did not change the server's credited reward in this test. Whether the altered amount is visibly displayed depends on the client's rendering and must be observed separately.

### Result: `TEST_MODE=2`

The second experiment changed `0x32b+0x03` from `263978048` to `263978049` while leaving the drop object ID `0x1444a` unchanged. `outbound_restore` returned `restored=true`. The subsequent `0x8b` credited the original `9` mesos at `0x06`, and `0x472` removed the same drop normally. Incrementing `0x03` therefore had no observed effect on the credit; its actual meaning remains unresolved, and this single increment does not prove that every value is ignored.

## Duplicate pickup experiment

```bash
analysis/duplicate-pickup.sh 90
```

This enables `DUPLICATE_32B=1` with `TEST_MODE=0`, so no field experiments are applied. The first `0x32b` completes normally, then an identical second packet is issued through the normal `SendPacket` routine. Only the first pickup is duplicated; later pickups remain controls.

The `duplicate_send` record contains `first_return_to_second_start_us`, `second_call_us`, `total_us`, and `identical_to_original`. Timing is measured at the native send-call boundary, not at the server. A separate `COutPacket` is constructed for the duplicate and destroyed after its send, rather than reusing the original packet after its first send. The original object and caller registers are preserved, with `restored_object` recording whether the original object still matches its post-first-send state. A `duplicate_cleanup` record indicates an incomplete or interrupted experiment instead of claiming success. The first replay attempt ended in game exit code 9; whether that was an anti-replay shutdown or a native replay failure remains unproven, and a retry may still be rejected. Use `0x8b` and `0x472` to determine the actual result.

The wrapper authenticates with sudo, auto-detects the current MapleStory PID, and writes a private `captures/packets-*.jsonl` file. Terminal output and errors are also saved to `captures/packets-*.log`. `ARMED` confirms that recording has started. The observer streams JSONL rather than retaining packets in memory and does not perform full-memory scans. Thread exits and unexpected traps are recorded as `observer_notice` events rather than automatically discarding the remaining capture. A worker with an already-occupied hardware breakpoint is restored and skipped with a `breakpoint_occupied` notice; a conflict on the main thread still stops safely.

It records:

- plaintext sends, bodies, callers, and thread IDs;
- packet constructors and, where the buffer matches, their corresponding sends;
- inbound `CInPacket` buffers and framing fields;
- intermediate field writes for `0x32b` and `0x407` through a targeted `+0x428` length watchpoint.

In default read-only mode, no packet or game-memory bytes are changed. Opt-in test modes explicitly modify scoped packet fields, verify the write, and attempt guarded restoration. Hardware debug registers are restored on detach. The current thread set is armed; a thread created later can require another capture if it uses these paths. A hardware breakpoint has a small pause at each observed call, so unusually high packet rates can still affect responsiveness.

The initial 120-second capture completed with 1,372 sends, 3,433 inbound buffers, 4,515 constructor events, and `TracerPid=0` after detach. Watchpoint control and preservation of the execute breakpoints were then verified with child-process trap tests. A later 45.02-second capture recorded 538 sends, 1,165 inbound buffers, 2,080 constructor events, five complete `0x32b` sends, and all 55 corresponding field writes. Two workers with occupied breakpoints were restored and skipped; no invalid final send occurred, and detachment again left `TracerPid=0`.

## Combat and confirmed drop/pickup path

The 45-second capture included 13 melee attacks and three reported kills. Three `0x3f3` object groups matched the kills. Each identifier also appears at `0x7d` in the corresponding outgoing melee body, and the byte at `0x3f3+6` reaches zero after the killing hit. This is the current mob HP/death candidate. Its decrements do not consistently equal displayed damage at `0xe1+0x88`, so the server's damage calculation remains unproven.

A later 90-second capture matched six reported pickups with six `0x32b` sends and twelve `0x471` messages (two per drop):

```text
Server creates drop: 0x471
Client requests pickup: 0x32b
Server credits meso/item: 0x8b
Server confirms/removes the picked-up object: 0x472
```

| Field | Confirmed meaning from the labeled run |
|---|---|
| `0x471+0x04` | Drop object ID. |
| `0x471+0x15` | Meso amount or item template: 8, 9, 11, 2060000 (arrows), 4000003 (mushroom spore), or 4000004 (red shell). |
| `0x471+0x2a` | Killed target identifier, matching the corresponding `0x3f3` group. |
| `0x32b+0x0f` | Drop object ID from `0x471`. |
| `0x8b+0x04` | `1` for meso credit and `0` for item credit in all six labeled examples. |
| `0x8b+0x06` | Meso amount: 8, 9, or 11. |
| `0x8b+0x05` | Item template: 2060000, 4000003, or 4000004. |
| `0x8b+0x09` | Item quantity: 18 arrows, 1 mushroom spore, or 1 red shell. |
| `0x472+0x02` | Drop object ID being confirmed/removed. |

The server supplies the meso amount or item template before the client requests pickup. This path provides no evidence that `0x32b` chooses the drop contents or its RNG. The `0x32b` field at `0x13` was zero for meso and nonzero for items, making it item-specific metadata rather than a proven item template. The repeated values at `0x18` and `0x1c` were `721204` for all six pickups; their meaning is unresolved. The final `0x20` value did not equal the meso amount or item quantity.

Additional outgoing packets in the earlier 45-second capture:

| Opcode | Evidence | Current interpretation |
|---|---|---|
| `0xf4` | One 14-byte report; no drop-object ID found. | Unresolved. |
| `0xf5` | One 55-byte packet with human-readable chat-like text. | Text/social message, not a drop creation packet. |
| `0x233`, `0x234`, `0x235` | Long length-prefixed encoded-string payloads; no drop-object IDs found. | Exact feature unresolved. |
| `0x2a5` | Large variable-length binary records, 223–3625 bytes; no drop-object IDs found. | Strongly supported as batched input events, not death/drop traffic. |

### `0x2a5`: input-event container

The constructor at `0x2ee4540` writes a one-byte header, two 64-bit header values, and a counted sequence of typed records. The structure established from the code and live bodies is:

```text
u16 opcode = 0x2a5
u8  header_flag
u64 header_value_a
u64 header_value_b
u16 record_count
records[record_count]
```

The 56-byte source records start with a 32-bit identifier and an 8-bit type. Their type-specific serializers at `0x2e1ac0` are:

| Type | Record-relative fields after the identifier and type |
|---|---|
| `0` | `u64` at `+0x28`, `u8` at `+0x30`, `u8` at `+0x31`. |
| `1` | `u32` at `+0x10`, `u8` at `+0x14`, four `u16` values at `+0x18`, `+0x1c`, `+0x20`, `+0x24`. |
| `2` | One byte at `+0x05`. |
| `3` | A 16-bit string length at `+0x08`, followed by that many bytes. |

`0x7635a0` reserves the count field, the per-record loop increments it, and `0x763580` writes the final count back. The observed count of 200 therefore means 200 records, not a flag.

The strongest semantic evidence is in the type-0/type-1 records:

- `512` / `0x200` = `WM_MOUSEMOVE`.
- `513` / `0x201` = `WM_LBUTTONDOWN`.
- `514` / `0x202` = `WM_LBUTTONUP`.
- `37` / `0x25` = Left Arrow (`VK_LEFT`).
- `16` / `0x10` = Shift (`VK_SHIFT`).
- `39` / `0x27` = Right Arrow (`VK_RIGHT`).

Thus the four `0x2a5` messages after the first kill are batched mouse/keyboard input history, not mob-death or drop messages. Their timing is compatible with flushing an input buffer, and none contains the killed mob identifier. This is most consistent with input telemetry/history rather than gameplay-state or drop generation. The exact producer purpose, header fields, coordinate fields, type-2 marker bytes, and type-3 opaque string data are not fully assigned meanings yet.

## What remains unresolved

- Whether the changing value in `0x3f3` is authoritative mob HP, and why its decrements differ from displayed damage.
- The semantic name and object source of `0x407`, and the meanings of the `0x32b` fields other than the drop object ID at `0x0f`.
- Whether the server trusts any `0x32b` metadata beyond the drop object ID. No controlled field edit has been performed or validated.
- Exact user-facing meanings of the structured report families and rare `0x265`/`0x266` messages.
- Static extraction cannot by itself name a dynamically constructed or VM-generated packet; it must be correlated with the live body and action.
