# ANALYSIS — study of the decoded GRAP control plane

Deep read of the historical `ngs-control-plane-full-2026-10-29.json` decode
(client 1.5.3.1), done 2026-10-29. This is the "Option D" study: what GRAP actually
detects, how it's structured, and what it means for our OPSEC and the bypass tracks.
Remaining `data/` paths below identify historical research artifacts, not current
repository paths; shipped redacted evidence is under `../../evidence/`, and raw
captures and the full decode are not included.

---

## 1. Shape of the ruleset

- **`subfeature`** (97 entries): the master enable map. Code format `0xFFSSS`
  (feature family + sub-id), value = enable level `0/1/2` (0 = off). Families:
  | Family | # | Levels | Likely role (inferred from signature co-codes) |
  |---|---|---|---|
  | 0x01 | 5 | 2 | core/init |
  | 0x02 | 20 | 1,2 | time/threshold + behavioral (has `threshold_minutes`) |
  | 0x03 | 5 | 2 | **module-integrity targets** (DLL allow/verify lists) |
  | 0x05 | 5 | 1 | **hash-matched module scans** |
  | 0x06 | 7 | 1 | **YARA scanning** (in-proc + external-proc) |
  | 0x07 | 3 | 1 | — |
  | 0x09 | 3 | 2 | — |
  | 0x0A | 3 | 2 | — |
  | 0x0B | 17 | 0,1,2 | large family; 1 disabled (0x0B08B) |
  | 0x0C | 1 | 2 | — |
  | 0x0D | 2 | 1 | — |
  | 0x0E | 12 | 0,1,2 | **big hash blocklist** (0x0E050); 2 disabled (0x0E0A0, 0x0E0B0) |
  | 0x0F | 14 | 1 | **surveillance/output** (screenshots 0x0F013, hash sigs 0x0F020) |
  - **Only 3 of 97 are disabled:** `0x0B08B`, `0x0E0A0`, `0x0E0B0`.

- **`signature`** (1,381 payload entries across 14 categories): the actual
  detection content attached to features.

## 2. The detection payloads (what GRAP hunts)

### Hash blocklists — 1,274 of the 1,381 entries
- **`0x0E050` — 1,225 32-bit hashes** (`0x0011a371`, …). A large known-bad
  blocklist (modules/drivers). The bulk of GRAP's signal is a plain hash sweep.
- `0x0F020` (18), `0x05050` (15), `0x05010` (1): smaller targeted hash lists.
- **Takeaway:** most detection is hash equality. A renamed/recompiled tool whose
  bytes differ won't match — but anything shipped unmodified from a known source
  will.

### YARA rules — 105 total
- **`0x06010` (56 in-process rules):** names map to a who's-who of MapleStory
  tooling — bots (`MT_MapleAI`, `MT_ManiaBot`, `MT_Nitro`, `MT_AutoMS`),
  trainers (`HT_TrainerB`), injectors (`HT_SLInjection`, `HT_maplieDLL`),
  bypass tools (`HT_NxBypass`, `HT_MarioNGSBypass`), **packet tools
  (`HT_NewMapleShark`, `HT_PacketHook`, `HT_MXDNvHid`)**, WZ tools
  (`HT_HaRepacker`), VM/remote (`VM_VMWare`, `MC_Multiplicity`,
  `MC_InputDirector`, `MC_R_RemotePC_Client`).
- **`0x06060` (15 `ExtProc_*` rules):** scan **external processes** for runtime
  fingerprints: **`ExtProc_Themida`**, `ExtProc_PyInstaller`, `ExtProc_PyConsole`,
  `ExtProc_Py2exe`, `ExtProc_NuitkaPy/One/Pack`, `ExtProc_AutoHotkey_*`,
  `ExtProc_dotNet_SingleFileHost`, `ExtProc_SVMP_Packer`.
- **`0x06061` (33 depth rules):** library-level automation fingerprints —
  `Vision_OpenCV`, `Vision_TesseractOCR`, `Control_pyautogui_*`, `Control_pynput`,
  `Control_Interception`, `Control_ClassDD`, `Control_AHI`, plus `Depth_MT_*`
  app-specific variants.
- **`0x06030` (1):** `HT_doyuin`.

### Decoded rule bodies (the ones that matter to us)
- **`HT_PacketHook`** matches these literal strings (so DON'T ship a tool
  containing them): `"PacketHookTests.exe"`, `"MAPLE_NGS_TEST_IMAGE"`,
  `"TLS/JSON hooks modify NGS code and are detected"`,
  `"Replace identifiers observed by the HWID hooks"`, `"Attach NGS callback"`.
  → This is literally Nexon's own red-team harness signature. It confirms GRAP
  watches for **TLS/JSON hook tampering and HWID-hook identifier replacement**.
- **`ExtProc_Themida`** matches only the UTF-16 string `"Themida"` in an external
  process. Trivial to trip if a Themida-packed helper runs **inside the prefix**.
- **`HT_NewMapleShark`** matches MapleShark's UTF-16 UI strings
  (`"MapleShark"`, `"Checking for updates"`, `"Initializing MapleStory AES Keys"`).
- **`Control_pynput` / `ExtProc_PyInstaller/PyConsole`** match Python-tooling
  artifacts (`site-packages\pynput\...`, `PYINSTALLER_...`, `Py_Main`+`python*.dll`).

### Module-integrity target lists (not hashes — names)
- **`0x03010` (verify these 7):** `ZLZ64.dll`, `nexon_api_x64.dll`,
  `nmcogame64.dll`, `nmconew64.dll`, `steam_api64.dll`, `MachineIdLib.dll`,
  **`MapleStory.exe`**. → GRAP integrity-checks the main EXE and these DLLs.
- **`0x03020` (6):** `PCOM.dll`, `Resman.dll`, `NameSpace.dll`, `Canvas.dll`,
  `Shape2D.dll`, `ZLZ64.dll` (the Wizet engine DLLs).

### Behavioral thresholds
- `0x02051` / `0x02080` / `0x02090`: `threshold_minutes = 3`. Some checks only
  fire after a 3-minute window (consistent with the "delayed enforcement"
  behavior seen elsewhere).

### Surveillance
- **`0x0F013`:** periodic screenshots — `capture_limit 100`, `width 1280`,
  `quality 50`, `capture_cool_time 6` (seconds). GRAP can grab up to 100 frames
  of the player's screen and upload them.

---

## 3. OPSEC implications for THIS project

1. **Our Linux-native tooling is likely invisible to the YARA/ExtProc scans.**
   `vac-sprites.py`, `position-gui.py`, the shield, and the MITM run as **native
   Linux processes**. GRAP (a Windows module under Wine) enumerates **Windows
   processes in the prefix** — it almost certainly cannot see native Linux PIDs.
   The `ExtProc_*`/`Control_*`/`HT_*` process scans are aimed at Windows hack
   tools. **Keep tooling native-Linux and out of the prefix.** (Worth an explicit
   test, but this is a strong structural advantage we didn't have named before.)
2. **The `/proc/pid/mem` write vehicle leaves no module on disk** → no hash to
   match in the 1,225-entry blocklist, no YARA target. Memory-only tampering
   dodges the entire signature catalog; detection there must be behavioral/server-
   side (which is exactly the DC-3 wall).
3. **Do not run Themida-packed, PyInstaller, or AHK helpers *inside the prefix*** —
   those are the `ExtProc_*` triggers. Our devirt/analysis tooling must stay on
   the Linux side.
4. **`HT_PacketHook` names the exact technique we care about** ("TLS/JSON hooks
   modify NGS code and are detected"). In-client TLS/JSON hooking is a named,
   signatured path → our **MITM-on-the-network approach is better** precisely
   because it doesn't hook the client.
5. **GRAP integrity-checks `MapleStory.exe` + 6 engine DLLs by name (0x03010/20)**
   and holds expected CRCs (`x-update` module_crc). On-disk `.text` patching of
   those is risky; memory patching after load + CRC-spoofing (we have the
   expected values) is the safer route — and ties directly to the OnAliveReq /
   integrity-checker devirt target.

## 4. What this buys the bypass tracks

- **Track A (inertness):** the rewrite table in `FINDINGS.md` plus this catalog
  means we can both (a) pin the kill switch/detections clean *and* (b) know
  exactly which features to zero in `subfeature` if we want surgical disabling
  instead of blanket suppression.
- **Track B (tamper w/o DC):** confirms the client-side catalog is signature/hash
  heavy and **evadable by staying memory-only + native-Linux**; the real wall
  remains server-side behavioral (DC-3), untouched by any of this.
- **Devirt track (`plan.md`):** `0x03010` + `module_crc` give us the integrity
  checker's *reference data*; devirting the checker (OnAliveReq) is what lets us
  satisfy it with patched modules.

## 5. Caveats

- One capture, one version (1.5.3.1). The hash lists and rules update server-side
  (`config_changed` triggers a re-pull); re-capture after any GRAP update.
- Feature-family roles above are **inferred** from which signature categories
  co-occur with which codes, not from GRAP's source. Treat as a working map.
- "Invisible to GRAP" for native-Linux tooling is a strong hypothesis from the
  Windows-process-scan design, not yet an empirical test.

---

## 6. Live kill-switch heartbeat (x-csauth/v2) — decoded in-world 2026-10-29

The per-cycle heartbeat uses the **same cipher** as the big config blobs
(`base64 → [2-byte header] → single-byte-XOR → gzip(JSON)`, key `K = C[2]^0x08`).
Earlier it looked undecodable only because the capture *log* truncates bodies;
pulled raw from the `.mitm` dump it decodes cleanly. **GRAP's live kill switch is
now fully readable on the wire.**

**Full field set (every heartbeat):**
```json
{"csauthtoken":"<19-char, rotates every beat>",
 "config_changed":0, "auth_cycle":60, "emergency_stop":0,
 "terminate_message":"An abnormal behavior has been detected.",
 "detected":[]}
```

**Observed behavior (42 beats, ~45 min, one in-world session):**
- **Cadence: a rock-steady 64.0s wall-clock** between beats. The `auth_cycle:60`
  field is nominal; the client's real poll interval is ~64s.
- **`config_changed=1` fires ONCE, on the first beat of the session** (the
  "pull your config now" signal), then `0` for the entire session.
- **204-vs-208 byte length difference is NOT semantic** — it's just gzip output
  jitter from the random `csauthtoken`; both lengths carry identical field sets.
- **`detected:[]` / `emergency_stop:0`** the whole clean session.

**Gameplay-reactivity test (operator drove events):** channel change, map change,
combat, cash-shop/UI open, normal play — **none** produced a `config_changed`
flip, an off-cadence beat, or a detection. **The control plane is purely
time-driven (64s poll); it is independent of in-game actions.** Any detection
push therefore originates from GRAP's own scanners firing, not from gameplay.

**Why this matters for the rewriter (Track A):** the live rewrite target is tiny
and fixed — pin `emergency_stop:0`, `detected:[]`, `config_changed:0` on this 64s
beat and the kill switch can never trip client-side. The rotating `csauthtoken`
must be preserved verbatim per-beat (echo the server's own value). Because the
beat is time-driven and reactivity is nil, a passthrough rewriter has a trivial,
predictable job: same cipher, same 6-field shape, 3 pinned booleans/arrays.

---

## 7. Deliberate detection-trip (2026-10-29) — ExtProc YARA scanners vs. live in-session processes

**Goal:** empirically test whether GRAP's `0x06060` ExtProc_* YARA rules
(subfeature level 1 = ENABLED) actually fire against sibling processes in the
*live game session*, and if so, capture what a real kill looks like on the
x-csauth/v2 heartbeat wire.

**Method (both triggers run as siblings of the game inside the SAME wineserver):**
The only correct injection path is `nsenter` into the game's mount+pid namespaces
so the spawned Wine process joins the existing wineserver (verified single
wineserver, `pgrep -c wineserver == 1`). Launching via `umu-run` instead spawns a
*second* pressure-vessel container with a private `/tmp` and a SECOND wineserver
that GRAP cannot enumerate — an invalid test (and a prefix-corruption risk).

Two triggers, each carrying the exact byte signatures the rules match:

1. **`ExtProc_Themida`** — custom marker `themida_marker.exe` with the UTF-16
   `"Themida\0\0"` string (`54 00 68 00 65 00 6D 00 69 00 64 00 61 00 00 00`) at
   a known offset; rule condition is `any of them`. In-session ~**9 min**.
2. **`ExtProc_AutoHotkey_2N`** — the *genuine* AutoHotkey v1.1.37.02
   `AutoHotkeyU64.exe`, which contains all four required wide strings
   (`"Window: %s"`, `"Keybd hook: %s"`, `"Mouse hook: %s"`,
   `"Modifiers (GetKeyState() now) = %s"`) and installs real keyboard+mouse
   hooks. Launched 23:23:42 with display vars added to the nsenter env
   (`DISPLAY=:0 WAYLAND_DISPLAY=wayland-0 XAUTHORITY=/run/pressure-vessel/Xauthority
   XDG_RUNTIME_DIR=/run/user/1000`); confirmed alive and hooked, wineserver count
   stayed 1. In-session ~**5 min** observed.

**Result — NO DETECTION.** Across the entire window both processes stayed alive,
the game stayed connected, and every x-csauth/v2 heartbeat remained clean:

```
23:23:54 + 64.0s len=208 cfg=0 estop=0 det=[]
23:24:57 + 64.0s len=208 cfg=0 estop=0 det=[]
23:26:00 + 64.0s len=208 cfg=0 estop=0 det=[]
23:27:06 + 64.0s len=204 cfg=0 estop=0 det=[]
```

No `detected[]` entry, no `emergency_stop`, no `config_changed` flip, no
`terminate_message`, no disconnect — with a Themida-signatured process present
~9 min and a real signatured+hooking AutoHotkey present ~5 min, both well past
multiple 64s poll cycles.

**Interpretation (honest, bounded):** GRAP's ExtProc YARA scanners did **not**
detect sibling Wine processes injected via nsenter, even ones carrying the exact
matching signatures and (for AHK) live input hooks. Plausible causes, not yet
disambiguated:
- The ExtProc enumeration likely walks the Win32 process/snapshot API
  (`CreateToolhelp32Snapshot` / `NtQuerySystemInformation`) and under Wine may not
  see, or may not scan the memory of, processes it didn't itself observe starting —
  especially ones attached to the wineserver out-of-band via nsenter.
- OR the scan cadence for `0x06060` exceeds the observation window (unlikely given
  the 64s control-plane poll, but not excluded).
- OR enforcement is threshold/corroboration-based and a single ExtProc hit does not
  by itself trip the kill switch.

**This is NOT "GRAP is blind."** It is a concrete, reproducible negative:
*signature-carrying sibling processes injected via nsenter do not trip the
ExtProc path within ~5-9 min.* The in-process (`0x06010`) and module-integrity
paths are untested by this experiment and remain live concerns.

**Artifacts:** `themida_marker.c/.exe`, `ahk/AutoHotkeyU64.exe`, `ahk/trigger.ahk`,
nsenter launch env (`game.env` + display vars), heartbeat log excerpt above.

### 7a. Full-field re-decode of the AHK-window heartbeats + csauthtoken structure

The live monitor only prints `config_changed`/`emergency_stop`/`detected`. A
full field-by-field re-decode of every beat during the AHK window
(23:23:52 → 23:30:16, 11 beats) confirms the negative with no blind spots:

- Field-key union across all beats = exactly `{auth_cycle, config_changed,
  csauthtoken, detected, emergency_stop, terminate_message}` — **no hidden/extra
  field ever appears.**
- `auth_cycle=60` constant; `config_changed=0`; `emergency_stop=0`; `detected=[]`.
- `terminate_message="An abnormal behavior has been detected."` is present on
  EVERY beat (clean ones too) — it is a **static client-side template string, not
  a live trigger.** The trip signal is `detected[]`/`emergency_stop`, never the
  message's presence.

**New structural finding — `csauthtoken` is NOT fully random.** Its trailing 8
hex chars are a **monotonic counter** that advances ~`0xf9e0` (≈63,970) per 64s
beat ≈ **~1000 units/sec → a millisecond-resolution timestamp/counter**. The
leading bytes rotate randomly; the tail ticks like a clock:

```
23:27:04 tail=89c61ac4   +0xfa0d
23:28:08 tail=89c714a4   +0xf9e0
23:29:12 tail=89c80e91   +0xf9ed
23:30:16 tail=89c90883   +0xf9f2
```

**Rewriter implication:** a naïve freeze/replay of `csauthtoken` would desync this
monotonic counter and is therefore server-detectable. The planned PASSTHROUGH
design (forward the server's token verbatim, pin only the 3 booleans/arrays) keeps
the counter correct for free — this is the correct and only safe approach.

---

## 8. x-init / x-config / x-update decoded + compared (2026-10-29, gd-decode-xinit-xupdate)

All three bootstrap endpoints use the **same cipher** as the heartbeat. Decoded
from the live dump:

### Endpoint shapes
| endpoint | wire B | decoded B | distinguishing content |
|---|---|---|---|
| `x-init.ngs.nexon.com/v1`   | 42692 | 151949 | **adds `lifetoken`** (UUID, 36ch); `signature` has **12** categories |
| `x-config.ngs.nexon.com/v1` | 42260 | 152851 | no lifetoken; `signature` has **14** categories (+`0x0F013`,`0x0F020`) |
| `x-update.ngs.nexon.com/v2` |   260 |    230 | tiny; **`module_crc` integrity table** + CDN url |

**Answer to "is x-init a superset of x-config?" → NO (cross-superset).** They carry
an **identical 97-entry `subfeature`** map, but differ in opposite directions:
- x-init uniquely adds **`lifetoken`** (the session life UUID).
- x-config uniquely adds signature categories **`0x0F013` (screenshot exfil)** and
  **`0x0F020`** (an additional id→hash blocklist). So x-config is the one that
  actually carries the screenshot/exfil feature config; x-init does not.

### x-update = the module-CRC integrity table (answer to the todo's 1st question → YES)
`x-update/v2` is tiny and carries the **full expected-CRC table** for the 4 GRAP
modules, plus the CDN base and poll timeout:
```json
"url": "https://x-cdn.ngs.nexon.com/1.5.3.1/windows/x64",
"timeout": 40, "retry": 0, "emergency_stop": 0,
"module_crc": {
  "grap-core64.aes":         816866722,   // 0x30B8B2A2
  "grap64.dll":             3004574433,   // 0xB317B4E1
  "grap-communicator64.aes": 391528369,   // 0x17566FB1
  "BlackCat64.sys":         3943112960    // 0xEB147AC0
}
```
These are the server-side **expected** CRC32s. Any on-disk patch to these 4 files
must reproduce the matching CRC or spoof the attestation that reports it. (The
attestation itself travels in the device-bound REQUEST cipher — still unbroken.)
Persisted: `data/module-crc-expected-2026-10-29.json`.

### 0x0F013 screenshot-exfil config (also advances gd-screenshot-exfil)
```json
[{"id":14345,"l":1,"s":{
    "capture_limit":"100","width":"1280",
    "capture_cool_time":"6","quality":"50"}}]
```
Screenshot exfil is **ENABLED** (`l:1`): up to **100** captures/session, **1280px**
wide, JPEG **quality 50**, **6s cooldown** between captures. This is the mechanism
behind the periodic ~+500-byte request-body bumps seen during play (ANALYSIS §7
note / PM-76). The images ride the client→server request cipher.

### 0x0F020
A second id→hash map (~many entries, each `{id, s:{hash:0x...}, l:1}`) — a
supplementary hash blocklist distinct from the 1225-entry `0x0E050`.

Persisted decoded blobs: `data/decoded-x-init-2026-10-29.json`,
`data/decoded-x-config-2026-10-29.json`, `data/decoded-x-update-2026-10-29.json`.

---

## 9. Screenshot-exfil wire path mapped (2026-10-29, gd-screenshot-exfil)

Config says exfil is enabled (§8, 0x0F013). Wire-side confirmation from the live
dump (79 x-csauth/v2 request bodies over ~80 min):

- **One exfil channel only.** ALL client→server GRAP data rides
  `x-csauth.ngs.nexon.com/v2` request bodies. There is **no dedicated screenshot
  upload endpoint** (max request body anywhere = 30260 B, all on /v2).
- **Baseline attestation ≈ 10080 B** (±24 B jitter) at the 64s cadence.
- **Login/startup burst 22:14–22:19:** +18.7–20.2 KB over the baseline — the
  initial full module attestation + first screenshot batch — decaying to baseline
  by 22:20:56.
- **Steady-state screenshot uploads = periodic bumps** of **+~500 B** (22:44–22:49
  cluster, 23:01) and **+~828 B** (23:13:11, 23:24:55) at irregular multi-minute
  gaps (NOT the 6 s `capture_cool_time`, which is only the minimum capture
  spacing; uploads are batched/occasional and small because quality 50 @ 1280px is
  chunked across beats).
- **Cross-check vs. the detection-trip (§7):** the +828 B bumps at 23:13:11 and
  23:24:55 occurred *inside* the AHK/Themida window — and identical +500/+828 B
  bumps also occur with no injected process present. This **confirms request-size
  bumps are screenshot uploads, not a detection signal**, and independently
  reinforces the §7 no-detection result.
- **Contents unreadable:** the images travel inside the device-bound REQUEST
  cipher (still unbroken — see FINDINGS open target #2). We have fully mapped the
  *channel, cadence, size envelope, and trigger config*, but not the plaintext.

**Net:** screenshot exfil is characterized end-to-end except for payload
decryption, which is gated on the request-cipher / VM-devirt track (plan.md).

---

## 10. Request-cipher differential corpus + a keystream-reuse weakness (2026-10-29, gd-request-cipher-corpus)

Built a labeled corpus of all 80 client→server `x-csauth/v2` request bodies
(`data/request-cipher-corpus/`, `index.json` + `stats.json`), classified
baseline / screenshot-bump / login-attest by size delta over the 10064 B baseline.

**Structure probe (base64 → binary ciphertext):**
- Wire body is **base64** (printable ratio 1.0); decode → binary at ~0.75×.
- Decoded entropy **~7.53** (baseline) / 7.67 (login) — **below the 8.0 of a strong
  cipher**; heavy byte bias (χ² ≈ 27769 vs ~255 uniform; 0x00/0xF0/0xF1 dominant).
- No gzip magic; the response cipher does **not** apply → a distinct cipher.
- 0 positions are constant across ALL baseline beats (no trivially-fixed header).

**The weakness — epoch-based keystream reuse (two-time-pad):**
Pairwise positional byte-identity between baseline beats is **bimodal**:
| pair type | identical bytes |
|---|---|
| same "epoch" (e.g. 22:59:19 / 23:28:07 / 23:34:31) | **~71–72%** |
| different epoch | ~0.5–7% |

The request body is **NOT re-encrypted fresh each beat.** Within an epoch ~71% of
the ciphertext is static and only a small region (token/counter/timestamp) rotates;
full re-keying happens occasionally between epochs. Therefore **XOR of two
same-epoch beats cancels the static keystream over ~71% of the body**, leaving
`plaintext_a ⊕ plaintext_b` — a classic keystream-reuse break attackable by
crib-dragging known plaintext (module filenames from §8, fixed attestation struct
headers, the known 3DES key `G0dD@mnN#H@ckEr!`, device IDs).

**Plan impact:** this downgrades the long-standing assumption that the request /
attestation cipher is "unbreakable without VM devirt." There is now a **statistical
shortcut** (two-time-pad crib-drag) worth a dedicated attempt BEFORE/alongside the
Triton lifter. Corpus + stats are staged for that effort.

## 11. Request-cipher two-time-pad analysis (2026-10-29, crib-drag-request)

Dedicated attempt to cash in the §10 keystream-reuse weakness and recover request
plaintext without VM devirt. The historical `crib-drag-request.py` experiment and
`request-cipher-corpus/recovered/` artifacts are not shipped in this repository. **Honest verdict up front: the reuse is
real and fully characterised, but NO plaintext was recovered. Not broken.**

### 11.1 Refined epoch structure
Clustering the 62 baseline bodies by pairwise byte-identity (union-find, join at
>50% identity) gives **15 multi-member epochs + 19 singletons = 34 groups**. An
"epoch" is a set of beats that share the SAME reused keystream.

Key correction to the §10 picture: **epochs are NOT contiguous in time.** The
largest group is `222408 / 224320 / 225047 / 225151 / 231415` — spanning 22:24→23:14
with unrelated beats interleaved. So the keystream is not a monotonic per-session
roll; it is drawn from a **recurring pool / content-keyed seed** that repeats across
time. Across all 62 baselines every byte position still takes ≥13 distinct values
(≈ the number of keystream variants in the capture window). Mean pairwise identity
inside the largest epoch is **64.1%**; intersection static across all 5 members is
**47.2%** (3570/7563 bytes).

Screenshot-bump bodies DO share epochs with baselines (same keystream, bigger
plaintext): e.g. bump `221952` ≡ baseline `225151` keystream (65.2% identical),
`224632`≡`231207` (59.6%), `231311`≡`223032` (59.6%). Login-attest bodies share no
epoch with each other or with baselines (each freshly keyed; also 3× the size).

### 11.2 Cipher class — confirmed byte-granular XOR stream cipher
Within an epoch, `C1 ⊕ C2` is **sparse** (≈36% nonzero for the first pair), i.e.
plaintexts are mostly identical and the keystream cancels → stream, not block.
Decisive granularity proof: the diff-run-length histogram between two members is
dominated by **385 single-byte runs** (plus 2–3B and longer runs), and diff-run
boundaries are **not 8/16-aligned**. A one-byte plaintext change flips exactly one
ciphertext byte ⇒ additive/XOR stream cipher with **per-position keystream reuse**
inside an epoch. (Autocorrelation also shows a strong lag-28 peak, 5.9% vs 0.39%
random — a ~28-byte *plaintext record array*, not a 28-byte repeating XOR key: per-
column entropy stays ~6.8, and a period-28 modal-key decrypt does not collapse
entropy.)

### 11.3 Static vs rotating byte map (largest epoch, n=7563)
Persisted to `recovered/static-rotating-map.json`.
- Byte **[0]** static (constant header byte within epoch).
- **[1–26]** rotating — 26-byte per-beat token/nonce at the very front.
- **[247–278]** rotating — second 32-byte token/field.
- Interleaved rotating fields on a ~28-byte stride through `~1114–2300` (the record
  array; XOR there shows cascading `ff00 fe00 fc00 f800 f000 8000` bit-mask patterns
  = differenced little-endian counters/measurements, **not text**).
- Two large dynamic blobs: rotating runs of **389** and **453** bytes (the biggest
  single rotating zone spans `[2045–5171]` once small static islands are merged out).
- Remaining **47.2%** is static across the whole epoch.

### 11.4 What was tried to recover plaintext — all negative
1. **Two-time-pad crib-drag** of every known crib (module filenames, 3DES key
   `G0dD@mnN#H@ckEr!`, `1.5.3.1/windows/x64`, the lifetoken UUID, `csauthtoken`,
   `deviceId`, PNG/BMP/JPEG magics) in both ASCII and UTF-16LE, across all 10
   intra-epoch `C1⊕C2` streams, **restricted to fully-rotating (nonzero) spans** so
   that "crib-through-zero" artifacts are excluded. **0 coherent hits** (naive
   printable matching yields ~15k artifacts, all random letter-salad once a real-
   token filter is applied).
2. **N-time-pad modal-keystream** recovery (assume the modal plaintext byte per
   column is 0x00 → K = modal ciphertext, decrypt all 5 members): recovered bytes
   are high-entropy with no meaningful ASCII runs (longest tokens like `OOEHSI`,
   `6[?tW` are noise).
3. **Embedded capture-time known-plaintext.** The beat time is known exactly from
   the filename. Searched ASCII `HHMMSS` / `HH:MM:SS` and binary unix32/unix64/
   FILETIME deltas (all tz −12…+12) and **validated every candidate for cross-member
   keystream consistency**: **0 consistent timestamp fields.** The one raw-`HHMMSS`
   hit at off 569 was a coincidence (that offset is static, not a clock).
4. **Bump⊕baseline same-keystream pairs** (same K, different/larger P — the ideal
   two-time-pad case): crib-dragging image magics / headers / filenames over the
   35–50% nonzero XOR also yields nothing coherent.

### 11.5 Why it is blocked, and the honest verdict
The reuse is genuine but the two-time-pad gives no leverage here because of a clean
split:
- **Static region (47–64%)**: same keystream AND same plaintext across the epoch, so
  `C1⊕C2 = 0` — XOR cancels *both* P and K. This is exactly where the cribs live
  (module names, headers, device/version strings), but you cannot separate P from K
  by XOR alone. You would need two same-keystream beats whose plaintext *differs*
  inside this region — which does not occur among baselines (that's why it's static),
  and the bump bodies, which do differ, expose only `P_base ⊕ P_bump` with *both*
  sides unknown.
- **Rotating region (the differing bytes)**: `C1⊕C2 = P1⊕P2` is valid here, but the
  differing plaintext is high-entropy **nonce / monotonic-counter / measurement-hash**
  material (confirmed by the cascading-bit-mask XOR signature and by matching no crib,
  no timestamp, no image header). There is no low-entropy or known-plaintext anchor
  to pin either operand.

**Verdict: NOT broken via two-time-pad.** Concretely recovered plaintext bytes: **0**.
What IS now established with numbers: (a) it is a byte-granular XOR/additive stream
cipher; (b) keystream is reused across a recurring, non-time-contiguous epoch pool
(15 epochs over 62 baselines, 64% intra-epoch identity); (c) the static/rotating map
and the front-token layout (`[1–26]`, `[247–278]`, ~28B record stride, two ~400B
blobs). **Still blocking:** one trustworthy known-plaintext/known-keystream anchor.
The only realistic paths to that anchor remain (i) recovering a single epoch's
keystream from the VM/devirt (Triton lifter) and replaying it across all same-epoch
beats — now cheap given the epoch map — or (ii) a chosen-plaintext oracle that forces
a known field into the static region under a reused keystream. The statistical
shortcut alone does not finish the break.

---

## 12. Clean shields-down cold-launch baseline (2026-10-30, gd-complete-capture)

Captured one full cold cycle (launcher → login → in-world park) through the MITM
with **all shields down** (no NGS firewall rules) so every NGS-X flow completes
with no firewall-induced gaps. Persistent artifacts now live under the project
(not /tmp). The raw `nexon-cold-golden-2026-10-30.mitm` capture and historical `nxcap.py` addon are not shipped.

**Completeness — every bootstrap endpoint present, in order:**
`x-update/v2` (module-CRC table) → `x-init/v1` (+lifetoken) → `x-config/v1`
(+screenshot/0x0F013) → `x-csauth/v1/issue` ×2 → `x-csauth/v2` heartbeats.
Plus grap-core (54.238.121.146) polls and nxl.log/nxfs telemetry.

**Full heartbeat lifecycle captured cleanly (6 beats):**
```
00:00:32 base    config_changed=1  emergency_stop=0  detected=[]   <- FIRST beat
00:01:35 +62.7s  config_changed=0  ...
00:02:38 +63.3s  config_changed=0  ...
... (steady 63s cadence, all clean)
```
This **confirms the session-start model**: `config_changed=1` fires on exactly the
first beat of a fresh session, then `0` thereafter — matching the mid-session
inference in §6, now proven from a cold start.

**Cross-session stability finding:** the `module_crc` table in this cold cycle is
**byte-identical** to the 2026-10-29 mid-session capture
(`grap-core64.aes=0x30B8B2A2, grap64.dll=0xB317B4E1,
grap-communicator64.aes=0x17566FB1, BlackCat64.sys=0xEB147AC0`). The expected
CRCs are **stable across sessions/launches, not per-session randomized** — so a
module patch must reproduce a fixed, known target CRC (good news for any patching
effort).
