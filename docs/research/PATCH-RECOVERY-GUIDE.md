# Patch recovery guide

## Purpose

This guide records what actually worked when recovering the MSCW NGS/GRAP research tools after a client update. It is written for future patches and for people guiding an AI agent through them.

The main lesson is simple: **prove one small thing at a time. Do not guess an address, an offset, or a server response.**

Use the current report in `LIVE-VALIDATION.md` for exact results and remaining blockers.

## Start here: what worked

| Area | What worked |
|---|---|
| Python environment | A project `.venv` with pinned dependencies made the tools reproducible instead of depending on random system packages. |
| Portable paths | Scripts now find files relative to themselves, not to the original author's home directory. |
| Offline decoders | Transport IV recovery, NGS response decoding, and full-duplex pcap decoding were verified without a game. |
| Character resolution | New PE metadata, function fingerprints, character global, and controller vtable were found and validated with a real snapshot. |
| CMob discovery | A controller-getter breakpoint identified the real CMob vtable. The scanner then found 19 mobs. |
| VAC | X-only movement, pinning, Y with foothold sync, controller-B holds, and a one-slot park/release were demonstrated. |
| Collision MISS | The first hit was forced to MISS and the second was allowed to damage the player. The operator confirmed the visual result. |
| SendPacket observation | The new SendPacket address was found and the observer captured real packets. |
| Packet dropping | Two real `0x1ef` packets were dropped; other packets passed through. |
| M2 detour | An empty detour installed/restored, a padding-byte substitution returned the original byte, and an active detour survived 240 seconds before complete restoration. |
| Attack frames | A sword action was identified as action 0. The action offset changed to `0x7ec`, and the 1.2× modifier produced five attacks, 13 writes, and 527 ms saved. |
| Selector observation | A normal sword attack was observed without changing its selection. |
| Damage analysis | The client predicts damage using weapon stats, but editing the packet's damage field did not change the displayed result. This showed that the server also recomputes or validates damage. |
| Network shield | Rebuilt cgroup-scoped scripts blocked Nexon HTTPS/8484 telemetry for 120 seconds with no game-channel loss. |
| NGS proxy | Live `x-update`, `x-init`, and `x-csauth` calls returned HTTP 200. `x-init` had signature/subfeature maps neutralized and the character entered the world. |
| Attack/RNG capture | Four sword attacks (26, 24, 21, 20) matched the melee damage field and produced paired pre/post memory snapshots. Candidate state transitions remain unconfirmed. |

These are limited proofs, not a claim that every tool is complete. Native portal execution, live HP/result decoding, native preload, and global hotkeys remain incomplete. Shield scripts are now restored.

## Concepts in plain English

### Client memory versus the server

Changing client memory is not the same as changing the server. A client can display one value while the server keeps another. A real capability requires evidence that the server accepts the result, not just a successful memory write.

### RVA and VA

An RVA is an address relative to the executable's image base. A VA is the address in the running process. ASLR and updates can move code, so old addresses must be proven again.

### Vtable

A vtable is a table of function pointers used by C++ objects. It helps identify an object's type. Finding a vtable is often more reliable than guessing an object's layout.

### Protected values

Some positions and stats are encoded rather than stored as ordinary numbers. The writer must reproduce the client's encoding and checksum. Otherwise the game may reject the value or crash.

### Ptrace and hardware breakpoints

Ptrace lets us stop a thread and inspect registers or memory. A hardware breakpoint triggers at a chosen instruction. These are useful for differential analysis, but every test must restore the original debug registers and detach.

### Dry-run and unchanged-value tests

A dry-run reads and calculates without writing. An unchanged-value write puts the original value back and checks that the client still accepts it. These tests catch bad encodings and bad addresses before a real modification.

### Server authority

The server can ignore a packet edit even when the client accepts the edited memory. The client may predict a value, but the server can independently calculate or validate the final result.

## The recovery method that worked

### 1. Validate the build before touching offsets

Record the PE timestamp, image size, machine type, and function fingerprints. If they do not match the saved build, stop and reanchor. Do not run old code blindly.

### 2. Reanchor code with evidence

Use several independent methods:

- Search for exact instruction sequences from known functions.
- Use unique prologues and function hashes.
- Follow direct calls and RIP-relative references.
- Inspect constructor and getter callers.

For this patch, all six original fingerprints were found at new addresses. Other functions were recovered from their callers, not assumed to have the same shift.

### 3. Recover data structures from live objects

Once a function is identified, inspect the object it operates on:

- Read the vtable.
- Check identifiers and parent/child relationships.
- Decode existing values before writing.
- Compare before, during, and after an action.

The CMob vtable was recovered by observing a controller getter during a real kill. This was faster and more reliable than broad heap scans.

### 4. Start with read-only behavior

Validate character resolution, portal discovery, mob counting, and packet observation before enabling writes. A working read-only observer is often the best way to find a structure or calling convention.

### 5. Use the smallest possible write test

Progress in this order:

1. Dry-run.
2. Unchanged-value write and readback.
3. One small real write.
4. One controlled functional test.
5. Only then consider broader behavior.

If a test fails, keep the failure and its evidence. Do not hide it by weakening a safety gate or making a guess.

### 6. Validate client and server outcomes separately

Record both of these:

- What changed in the client.
- What the server accepted or rejected.

Examples:

- A controller-A position change can be visual only.
- A controller-B park can persist after release.
- A packet damage edit can be ignored by the server.

### 7. Restore everything after each test

Restore debug registers, detours, cave bytes, packet payloads, registers, and stack state. Stop other ptrace tools before starting another one. A clean restoration is part of the test, not an optional extra.

### 8. Keep a disconnect watchdog

Log the game channel and the exact time it disappears. A successful write and a disconnect are different events and should be recorded separately.

## What did not work or is not proven

- Blindly scanning for vtables and hoping they are right.
- Assuming a constant address shift works for every function.
- Editing only the final damage value in a packet and expecting the server to accept it.
- Calling a function successful because it imports or the GUI starts.
- Treating a client-side visual change as proof of a server-side change.
- Running fatal GRAP-core operations, forged melee edits, or blocking filters as routine tests.

## Future patch runbook

1. Create a static inventory of the new installation and save the old profile for comparison.
2. Run the offline decoder and import checks first.
3. Validate the PE identity and reanchor the code fingerprints.
4. Recover the character global and controller vtable using identifier getters and object relationships.
5. Validate protected-value decoding before writing.
6. Recover the CMob vtable with a controller-getter breakpoint.
7. Restore read-only portal and mob discovery.
8. Reanchor SendPacket and verify observation before dropping.
9. Restore VAC in this order: X, pinning, Y with foothold sync, controller-B, then park.
10. Revalidate collision observation before forcing one MISS and one native hit.
11. Revalidate attack-frame action IDs and offsets before enabling the modifier.
12. Test M2 empty first, then one harmless substitution, then an active soak before restoring.
13. Rebuild the shield against current game/Wine cgroups and verify the NGS proxy with real HTTP 200 responses.
14. Leave native portal, HP/result support, preload, and hotkeys for separate targeted work if they are required.
15. Commit the exact evidence, not just the code changes.

## What to give an AI agent next time

Provide all of these in the first prompt:

- Repo path and the guide/report paths.
- Client path, PID, and build metadata if known.
- Map and current weapon/action.
- What you can do in-game: attack, take a hit, kill a mob, change map, restart, or unequip.
- The exact capability to recover first.
- Any forbidden actions and safety constraints.
- Whether the agent may write memory, attach ptrace, change firewall state, install packages, or push commits.
- What evidence you will provide: displayed damage, visual MISS, mob positions, or another observable result.

Ask the agent to explain proposed anchors before editing, then prove each step with logs and a minimal test. Ask for a clear failure report when evidence is missing instead of a guessed implementation.

## Reusable prompt template

```text
We need recover <function> on the current client build <PE timestamp/image size>.

Repo: <path>
Guide: <PATCH-RECOVERY-GUIDE.md>
Client PID: <pid>
Map: <map>
Weapon/action: <weapon and action id if known>
Permissions/constraints: <authorized test environment and forbidden actions>

Work one function at a time:
1. Validate the build read-only and explain each proposed address with evidence.
2. Validate existing decoding and unchanged-value writes.
3. Run the smallest dry-run or read-only observer.
4. Run one controlled write with before/after logs and a channel watchdog.
5. Restore registers, detours, payloads, and stack state.
6. Record what is proven, what failed, and what remains unverified.

Do not guess offsets or claim success from imports alone. Stop on fingerprint mismatch,
invalid decoding, or a disconnect. Commit only after the relevant evidence is captured.
```

## Good follow-up questions to answer before starting

- What exactly should count as success for this function?
- What can the operator do in-game to create the required event?
- Which actions are forbidden or too destructive?
- What evidence should be logged for a future patch?
- What should the agent do when the evidence is inconclusive?
- Should the agent commit, push, or only document the changes?

The shortest path to a working state is not more guesses. It is better evidence, one controlled experiment at a time.
