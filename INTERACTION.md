# Full interaction and drop-origin capture

`tools-QUARANTINE/capture-interaction.sh` is the broad interaction recorder for investigating whether drops or other outcomes originate on the client or arrive from the server.

## Run

```bash
tools-QUARANTINE/capture-interaction.sh 120
```

The wrapper requests sudo authentication, auto-detects the single running `MapleStory.exe`, discovers its current remote endpoints and ports, and records for the selected duration. Kill a mob and pick up its item during the window. Use a short interaction when practical: full-memory diffs can produce large files.

## What is captured

- **Every outgoing packet:** timestamp, opcode, length, full body, caller RVA, packet/body addresses, and an eight-entry return stack for construction analysis.
- **Combat-specific state:** selector details, the three combat RNG words, all 11 predicted rolls, damage, and transition validation.
- **Full writable-memory diffs:** every readable/writable region under `0x7f0000000000`, with per-region maximum size 512 MiB. Changed 1 MiB chunks are saved with before/after bytes after combat and subsequent nonmovement packets.
- **Full-duplex network traffic:** a pcap containing both client-to-server and server-to-client communication on the current game endpoints.
- **Offline-decrypted traffic:** `wire-session-decrypt.py` attempts to recover plaintext and now records a timestamp for every decrypted frame.

No NGS HTTP proxy is used, and no packets or game memory are modified. Ptrace execution breakpoints observe `SendPacket` and the melee selector; debug registers are restored afterward.

To keep the game responsive, full-memory scans default to one snapshot every five seconds plus immediate snapshots for `0x32b` and `0x13b` drop candidates. Combat-state snapshots and every outgoing packet body are still recorded, and full-duplex pcap is continuous. Memory changes between snapshots appear in the next diff rather than pausing the main thread after every packet. Set `FULL_MEMORY_INTERVAL` to tune the interval, or to `0` for the original per-packet behavior. For smaller logs, use a larger interval such as `FULL_MEMORY_INTERVAL=15`.

## Output

Files use the `interaction-` prefix in `captures/`:

- `interaction-events-*.jsonl` — outgoing packets, combat state, and full-memory diffs.
- `interaction-session-*.pcap` — full-duplex network capture.
- `interaction-session-*.pcap.decrypted.json` — timestamped decrypted frames when IV recovery succeeds.
- `interaction-driver-*.log` and `interaction-decode-*.log` — diagnostics.

Captures can contain credentials, tokens, memory, and private traffic. They are local-only, normally mode `0600`, and must not be committed.

## Reading drop-origin evidence

A client-originated drop would require evidence such as a client-created drop object, item/reward data, or an outgoing drop proposal before the server acknowledges it. A server-originated drop would appear as an inbound drop/spawn or inventory update without an earlier client-generated reward.

The packet timeline distinguishes a drop proposal from a pickup request. The memory diff shows whether relevant client objects or state are created before the server update. Both are needed: a visual item on screen alone does not prove where the reward was generated.

Full-memory snapshots are not atomic across every game thread, so torn or concurrent changes are possible. They are corroborating evidence, not a complete proof by themselves. The pcap shows actual server communication but does not expose server-side RNG or server memory.

`drop-observe.py` supplies the lightweight combat/packet recorder used by `capture-drops.sh`. Its `--full-memory` mode, used by `capture-interaction.sh`, adds the broader memory differ in `memory-watch.py`.
