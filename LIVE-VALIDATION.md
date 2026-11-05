# Live validation and remaining suite work

Date: 2026-11-04
Scope: sequential tests against the operator's running client in an authorized research environment. PIDs below are historical test identifiers and change across launches.

## Current state

The complete suite is **not yet live-ready**. Several read-only and experimental paths are now confirmed working, with real fixes made from live code/disassembly. Other paths remain partial, unverified, blocked by omitted native information, or deliberately untested because they are destructive or known to cause disconnects.

The client entered maintenance before the final collision-MISS breakpoint issue could be resolved. No live test should be treated as proof of server acceptance, anti-cheat inertness, or safety on another build.

## Environment and offline readiness

- A project `.venv` contains the exact versions pinned in `requirements.txt`; it is excluded from Git.
- All recovered support modules imported successfully.
- All Python sources byte-compiled successfully.
- Decoder CLI checks, M2 Keystone/Capstone assembly, synthetic full-duplex pcap decryption, and PySide6 offscreen GUI startup passed.
- The host has no readable evdev device exposing every GUI binding, so global hotkeys remain unavailable.
- The configured game/UMU/Proton paths and native speedhack preload are absent from the source drop.

## Confirmed live results

| Function | Result | Evidence and fixes |
|---|---|---|
| Client build and memory compatibility | **PASS** | `locate-character.py` validated the PE identity and six code fingerprints, then resolved character, controller, and physics body. |
| Read-only portal discovery | **PASS after fixes** | Found 24 records and validated eight usable destinations with stable snapshot tokens. The original reconstruction used the wrong manager global/vtable and count layout. |
| Read-only mob scanner | **PASS after fix** | Reported `MOBS 17 xmin=-480 xmax=1390` on a populated map and exited cleanly. Added invalid-controller validation and `OverflowError` handling for false-positive vtable candidates. |
| Outbound packet observer | **PASS after RVA fix** | Captured opcodes `0x13f` and `0x70`, including length data, and detached with debug registers restored. Real SendPacket RVA is `0x1660ab0`, not `0x1660360`. |
| Incoming damage/MISS display observer | **PASS** | Captured two damaging hits and their display branches: `display_outcomes=2`, `MISS=0`, `damage=2`. A later decision capture also correlated comparison, native `status=1`, and display event. |
| Attack selector observation | **PASS** | Captured a normal non-polearm attack (`family=1`, `weapon_type=30`, no skill), with zero redirected actions. Observation is weapon-agnostic; overhead forcing is not. |
| M2 inert detour | **PASS for empty payload only** | Installed a 160-byte cave/83-byte stub with `payload=0`, read it back, then restored the original detour bytes and zeroed the cave. No gameplay or anti-cheat payload was enabled. |
| GRAP-core analysis and crash dry-run | **PASS read-only** | Resolved the current core, ntdll, NtWriteFile entry, and code cave; `arm` printed a valid plan without `--go`. The fatal patch was not executed. |
| VAC dry-run and encoder checks | **PASS** | Added `--dry`, which suppresses the sole `process_vm_writev` path. Selection and both encoders passed with 8,785 simulated writes and no failures. |
| VAC unchanged-value write self-test | **PASS** | Wrote a mob's unchanged X back once and verified readback before the movement loop. |
| Basic X-only VAC | **PASS for the tested case** | One mob moved from display X 249 to player X 128 with one write and no failures. No Y, controller-B, or pinning writes were enabled. |
| Attack-frame dry observation | **PASS** | Captured three normal attacks using supported action IDs 16 and 17; no polearm was required for these actions. |
| Attack-frame 1.2× modifier | **PASS for the tested case** | Two attacks, four timer writes, zero rewrites, and 228 ms of game time saved. |
| SendPacket drop pass-through | **PARTIAL** | Five non-target SendPacket traps passed through and zero packets were dropped. No `0x1ef` appeared, so actual dropping is still unverified. |
| Collision decision observation | **PASS** | The incoming observer captured comparison fields, native status, and resulting display. This proves the decision breakpoint can work in the observer. |
| Collision-MISS forcing | **UNRESOLVED** | Gates were implemented from live disassembly, but the forcing run produced no `COLLISION` or `COLLISION-SKIP` events. The cause was not isolated before maintenance. No forced MISS is claimed. |

## Live-derived code corrections

### Portal layout

The fingerprinted minimap caller at RVA `0x2500695` showed that its manager comes from RVA `0x3be6728`. The live manager vtable is RVA `0x35192f8`. The previous values pointed to a map-name string and a vtable with no candidates.

The parser now uses:

- `manager_global_rva = 0x3be6728`
- `manager_vtable_rva = 0x35192f8`
- a 32-bit count at `array-8`
- the accessor exclusion byte at record `+0xb8`
- the destination fallback at record `+0x40`
- direct destination support for types 2 and 7, or the fallback field when nonzero

Native portal execution is still disabled; these fixes cover read-only discovery and destination validation only.

### SendPacket

The real SendPacket function is at RVA `0x1660ab0`. It saves the packet pointer, reads opcode `+0x434`, and performs the documented send-path checks. The old RVA `0x1660360` contains unrelated code.

The constant was corrected in:

- `sendpacket-observe.py`
- `sendpacket-drop.py`
- `atkspeed.py`

Only the observer and drop pass-through were subsequently tested. `atkspeed.py` itself was not run.

### Collision gates

Disassembly of the avoidance function and its wrapper established:

- `r13` points to a non-null monster-state structure during the tested collision.
- `r14` is the attack record.
- an active attack record has a nonzero value at `r14+0x140`; the wrapper changes a computed MISS back to damage in that case.
- the captured active record value was 335, so that hit was correctly ineligible for the scoped override.

`try-collision-miss.py` now derives `monster_present` and `attack_record_absent` from these values, and `profile.json` records `attack_record_status_offset = 0x140`. `overhead-attacks.py` also logs `COLLISION-SKIP` diagnostics for ineligible events.

The forcing path still needs a successful live test. The last forcing runs did not reach either log path, so the next investigation is breakpoint/thread/event delivery—not weakening the gates.

### VAC safety and testing

`vac-sprites.py` now supports `--dry`, which returns success for simulated writes without calling `process_vm_writev`. Its final message distinguishes dry runs from live writes.

## Remaining work, in order

### 1. Resolve collision-MISS delivery and then test one forced MISS

The incoming decision observer captured native decisions, but `overhead-attacks.py --force-collision-miss` did not reach either collision log branch. On a client with confirmed damaging hits:

1. Compare the two paths' target addresses, DR2 setup/readback, thread IDs, and stop handling.
2. Log trap delivery before eligibility evaluation.
3. Confirm whether each hit has an active attack record; do not broaden eligibility merely to force a result.
4. Test one forced MISS followed by one native collision, then verify the display and register readback.

Until then, collision forcing is unverified.

### 2. Implement native portal execution

Read-only portal discovery works, but `try-native-reset.py --execute` still refuses because the original native-call register/stack sequence is absent. Recover the exact ABI from the fingerprinted native reset function at RVA `0xa46750` and its update boundary, then:

- preserve controller, map, portal-token, and stale-snapshot checks;
- validate target coordinates against the actual controller bounds;
- test `--initial-only` with no automatic retry;
- do not claim server acceptance without evidence.

### 3. Complete VAC/park validation

Only basic X-only VAC is confirmed. Test separately:

- post-copy X pinning and velocity suppression;
- Y movement with valid foothold synchronization;
- controller-B holds;
- park release, snap-back detection, and whether movement persists;
- ownership/controllership filtering. Current scans reported zero owned mobs, so the ownership field or map conditions need review before park can be validated.

### 4. Verify an actual packet drop

The drop tool passed non-target packets but saw no `0x1ef`. Verify one real target drop with appropriate logging and a controlled duration. Do not substitute an unknown opcode merely to force a demonstration.

### 5. Triage remaining packet/melee experiments

- `atkspeed.py` has the corrected SendPacket RVA but was not run. Its forged melee approach is documented as disconnect-prone.
- `edit-melee-swap.py` was not run, and its hardcoded melee RVA `0x2979607` is stale in the tested process.
- Any further test needs a fresh code anchor and strict packet/decision limits; server-side validation and DC-3 remain credible risks.

### 6. Complete M2 and GRAP-core work

- M2 was validated only with an empty payload. Payload substitution and anti-cheat outcomes remain untested.
- Full M2 `verify` still lacks `dl.py` and its pristine memory dump.
- The GRAP-core fatal `--go` operation was deliberately not executed. It requires a separate explicit destructive-test decision and a recovery/relaunch plan.

### 7. Repair remaining incoming-result support

An HP-context read failed with `No current stat context`. The `--results` path and HP update correlation therefore remain unverified even though ordinary and decision display observation work.

### 8. Restore host-dependent functionality

- Native speedhack preload and `.speed` file are absent; launch and speed controls remain disabled.
- Shield scripts are absent; shield controls remain disabled.
- Global hotkeys need an accessible evdev device supporting all bindings.
- Overhead forcing needs a compatible weapon/action profile if it is to be tested; ordinary selector observation already works.

## Resume protocol

Continue one function at a time. Start each launch with the read-only resolver, then portal/mob scans, then passive observers, then the smallest relevant dry-run or unchanged-value test. Do not run multiple ptrace tools simultaneously. Restore debug registers and temporary patches after every test, and keep destructive core, process-kill, firewall, and forged-packet actions out of routine validation.

## 2026-11-05 patch update

### New build recovery

The updated client has PE timestamp `0x6AEB667B` and image size `0x5F2E000`. All six original function fingerprints changed addresses but were found byte-for-byte at new RVAs. The character global was rederived as `0x3bda828`, and the movement-vector vtable as `0x34113a8`. The reanchored resolver produces a valid in-world snapshot.

Collision/display functions were reanchored independently: player display `0x280ce60`, MISS renderer `0xe9d250`, hit caller `0x296acb0`, calculator wrapper `0x2b2fb0`, and avoidance function `0x2b50c0`. Decision comparison/result addresses are `0x2b5289` and `0x2b5403`. A real hit validated comparison, native status, and display correlation.

### CMob and VAC

A controller-getter breakpoint identified the actual CMob vtable as `0x3516c98`. The mob scanner subsequently reported `MOBS 19 xmin=-639 xmax=1548`. Earlier broad vtable scans were unnecessary once the runtime getter was used correctly.

Progressive VAC validation produced:

- Dry-run selection and both encoder self-tests with no write failures.
- Unchanged-value write/readback success.
- X-only VAC reaching player X during the hold.
- Post-copy X and velocity pinning holding X immediately after detach.
- Y plus player-foothold synchronization holding both coordinates exactly.
- Controller-B hold reaching both coordinates, followed by post-detach movement.
- A one-slot park/release cycle where controller B remained at X=1059 after release while controller A moved elsewhere. This supports a persistent server-side park, but multiplayer visuals were not tested.

### Collision MISS

Collision-only mode was changed to use DR1, matching the proven decision observer. An explicit `--allow-active-attack-record` flag was added while preserving the absent-only default gate. The test cycle then produced:

- First hit: native 1, effective 2, forced MISS.
- Second hit: native 1, effective 1, native damage.

The operator visually confirmed the first MISS and second damaging hit. Collision-MISS is therefore working on this build with the opt-in active-record scope.

### SendPacket and remaining work

SendPacket was reanchored to `0x1661780` in the observer, dropper, and attack-speed packet script. The observer captured 38 traps and two opcodes on this build. A four-minute drop test then dropped two `0x1ef` packets across 1,450 traps, with no `dc_at` recorded. Pass-through and an actual target drop are therefore both validated.

M2 was reanchored to detour `0x1416689a1` and cave `0x14335891a`. The empty detour installed and restored correctly. A padding-byte payload at `0x1402b5449` was changed from `0xcc` to `0x90`, and direct cave execution verified that the integrity-read substitution returned the original `0xcc`. All detours, payloads, cave bytes, registers, and stack state were restored.

The attack selector was reanchored to `0x859480`, with caller `0x2982aa0` and return `0x2982f57`. A normal sword attack returned action 0, outside the old polearm-only filter. Action 0 was added to the frame-speed module, and live capture showed the action field moved from `0x7e8` to `0x7ec`. The dry observer then captured one attack and two frames. The 1.2× modifier produced five attacks, 13 timer writes, 527 ms saved, and no disconnect or watchdog event.

### Damage and RNG investigation

`sendpacket-observe.py` now captures full 232-byte melee packets instead of truncating them at 64 bytes. A damage-related field at body offset `0x88` was confirmed against displayed values. Changing that field from native 25 to 23 produced an exact readback, but the displayed result remained 25, so the packet edit did not change the authoritative damage outcome.

A weapon differential then showed 20 with the weapon equipped and 5 with it unequipped on the same mob. This proves that the client computes a prediction using weapon stats, while the server also recomputes or validates the result. It does not prove where the random roll originates. The checked RNG state fields at `stats+0x60` and `stats+0x90` did not change after an attack, and the range sampler/damage helper did not fire during the tested sword attack. The outgoing roll and any adjustable seed remain unidentified.

Native portal execution is still not implemented. The new update boundary is `0x283717d`, but the exact reset ABI is not recovered. HP/result support, native preload, shield scripts, and global hotkeys remain pending or unverified. No fatal GRAP-core operation was executed.
