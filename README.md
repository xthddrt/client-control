# 🧩 Taking apart MapleStory's NGS-X / GRAP anti-cheat on Linux

*Authorized research on our own client/account, running the Windows client under
Proton/Wine on Linux. This is the highlight reel — the full write-up, evidence, and
tooling are in the drop. Every claim below is backed by decoded wire captures in
[`evidence/`](evidence/).*

---

## ⚔️ First, what we can actually do to the game

Before the anti-cheat internals, the headline: a **working, live, GUI-driven arsenal** —

- **Mob VAC** — drag on-screen monsters into melee and kill them across the platform.
- **Server-side mob PARK** — *relocate a monster on the server* so it stays where you put
  it and stays killable after the tool detaches. (The surprising one.)
- **~3× attack speed** — triple cadence via the animation-frame timer, DC-safe.
- **Always-MISS** — force incoming monster attacks to resolve as MISS; zero damage.
- **Overhead-hitbox forcing** — force the large polearm AoE on every swing.

<p align="center">
  <img src="assets/ms_showcase_redacted.gif" alt="MSCW arsenal showcase — live mob vac, server-side park, attack-speed, and more" width="720">
</p>

And under the hood, the capability that makes all packet work possible: a **passive,
full-duplex wire decryptor** — AES-256-OFB transport with a **static session key** and an
**IV that self-seeds from two consecutive headers**, so we read *and forge* both
directions **from a pcap alone** (no handshake, no key trap). Below opcode level, we
**devirtualized the Themida VM** (133,450 steps → native) to recover the object cipher +
MAC byte-exact.

Now, the anti-cheat we read our way into:

---

## 📸 The anti-cheat screenshots your desktop — and we decoded the exact settings

GRAP's server→client control channel pushes a detection ruleset to the client. One of
its 97 features, **`0x0F013`**, is a **screenshot-surveillance** config. We decrypted it
straight off the wire. Verbatim, this is the packet the server sends the client:

```json
"0x0F013": [
  { "id": 14345, "l": 1, "s": {
      "capture_limit":    "100",     // up to 100 screen grabs per session
      "width":            "1280",    // downscaled to 1280 px wide
      "quality":          "50",      // JPEG quality 50
      "capture_cool_time": "6"       // min 6 seconds between captures
  }}
]
```

`l: 1` means **enabled**. The images are then **batched into the client's normal
heartbeat** — there is *no* dedicated upload endpoint. We watched them go out: the
`x-csauth/v2` request body sits at a steady **~10 KB baseline** and periodically bumps
by **+500–830 bytes** — those bumps *are* the screenshot uploads, chunked across beats
because quality-50 @ 1280px is small. We mapped the **channel, cadence, size envelope,
and trigger config end-to-end**.

> **What we did *not* do:** read a captured image. The client→server upload rides a
> separate **device-bound cipher** we did not break. We proved the *mechanism* and its
> exact parameters — not the picture contents.

---

## 🪞 It hunts other programs for the same packer it's built on

Among the pushed YARA rules is one that scans **external processes** for the commercial
**Themida** protector:

```yara
rule ExtProc_Themida {
    strings:
        $themida = "Themida" wide      // UTF-16 "Themida" in another process
    condition:
        $themida
}
```

The irony: **the MapleStory client itself ships wrapped in a Themida VM.** It's looking
for the thing it's made of.

And `ExtProc_Themida` is just one of **15 `ExtProc_*` process scanners**. The full
roster of packers/runtimes GRAP fingerprints in *other* running processes:

| GRAP looks for… | Rule |
|---|---|
| Themida-packed binaries | `ExtProc_Themida` |
| PyInstaller bundles | `ExtProc_PyInstaller` |
| Python consoles | `ExtProc_PyConsole` |
| py2exe bundles | `ExtProc_Py2exe` |
| Nuitka-compiled Python | `ExtProc_NuitkaPy` / `NuitkaOne` / `NuitkaPack` |
| AutoHotkey scripts | `ExtProc_AutoHotkey_1N/2N`, `ExtProc_AHK_11/16/WIN_17` |
| .NET single-file apps | `ExtProc_dotNet_SingleFileHost` |
| SVMP-packed binaries | `ExtProc_SVMP_Packer` |
| Generic / fallback | `ExtProc_General` |

But the part that reads like a **community hall of fame** is the in-process set. GRAP
ships named YARA rules for specific, real MapleStory tools. The **`MT_*` bot/macro
roster** (MapleStory tools):

| Tool class | Rules |
|---|---|
| AI / vision bots | `MT_MapleAI`, `MT_MushroomAI`, `MT_PyYoloVioleta` |
| Macro bots | `MT_ManiaBot` / `MT_MANIA`, `MT_Nitro`, `MT_AutoMS`, `MT_EclipseBot`, `MT_AIO`, `MT_mapleRobot`, `MT_CNBotPy`, `MT_AHK_mapleautobot_1` |
| Key/input macros | `MT_KeySender`, `MT_AHIMushroomMacro`, `MT_BTM_MXD` |
| Recorders / misc | `MT_ClientRecorder`, `MT_LieAnswerTool`, `MT_eeartale`, `MT_nannan`, `MT_AHKSpotify`, `MT_PyChrome`, `MT_URL_MapleStoryBot`, `MT_RandomApp` |

…and the **`HT_*` hack-tool roster** (injectors, trainers, bypasses, packet tools):

| Tool class | Rules |
|---|---|
| Packet tools | `HT_NewMapleShark`, `HT_PacketHook`, `HT_MXDNvHid` |
| Injectors / DLLs | `HT_SLInjection`, `HT_maplieDLL`, `HT_Xdll`, `HT_VersionDLL`, `HT_Version` |
| Bypass tools | `HT_NxBypass`, `HT_MarioNGSBypass` |
| Trainers / hacks | `HT_TrainerB`, `HT_EZMaple`, `HT_BMapleX`, `HT_GMHand`, `HT_ClientWorkAux` |
| WZ / asset tools | `HT_HaRepacker` |
| Others | `HT_AhnHelper`, `HT_msusa`, `HT_Yoomoah`, `HT_Smilelin` / `HT_smilelin0419`, `HT_doyuin` |

Plus **33 automation-library rules** (`Vision_OpenCV`, `Vision_TesseractOCR`,
`Vision_ahkfindtext`, `Control_pyautogui_*`, `Control_pynput`, `Control_Interception`,
`Control_ClassDD`, `Control_AHI`), multi-client rules (`MC_Multiplicity`,
`MC_InputDirector`, `MC_R_RemotePC_Client`), VM rules (`VM_VMWare`), and — our favorite —
a literal **`rule PleaseKickMe`**.

One rule, `HT_PacketHook`, even carries **Nexon's own red-team harness strings**
(`"PacketHookTests.exe"`, `"TLS/JSON hooks modify NGS code and are detected"`) — a map
of the exact techniques they expect attackers to use.

---

## 🔓 The entire server→client control plane was cleartext behind a **one-byte** key

The response cipher turned out to be:

```
body = base64( XOR_K( gzip( JSON ) ) )
```

…where the single key byte **`K` is self-describing** — derivable directly from the
third ciphertext byte. **No brute force, no handshake.** With that one observation,
*every* server→client message becomes readable:

- the **kill switch** (`emergency_stop`, `detected[]`, `terminate_message`),
- the full **97-feature detection map**,
- pushed **YARA rules** (all 105 of them),
- the **screenshot-surveillance config** above,
- and the server's **expected CRCs** for each anti-cheat module:

```json
"module_crc": {
  "grap-core64.aes":         816866722,
  "grap64.dll":             3004574433,
  "grap-communicator64.aes":  391528369,
  "BlackCat64.sys":         3943112960
}
```

---

## ⏱️ The heartbeat is boring on purpose — and that's the finding

Over **43 consecutive beats** in-world we measured a **rock-steady 64-second** cadence.
Changing channels, fighting, opening menus — none of it moved the needle. The
enforcement channel is **purely time-driven**; detection pushes come from GRAP's own
scanners, never from what you do in-game. Knowing what *doesn't* get watched in-band is
as useful as knowing what does.

---

## 🔌 Three different disconnects everyone keeps mistaking for one

We separated "getting kicked" into **three independent mechanisms**, on three different
paths, with three different timeouts and three different reset rules:

| DC | Mechanism | Timeout | Resets on… |
|---|---|---|---|
| **DC-1** | Client **code-integrity** sweep (`.text` + DR-register report) | ~4 min | patch removal |
| **DC-2** | **Core-liveness** audit | ~80 s | module reload |
| **DC-3** | Server-side **gameplay-plausibility** score | variable | *full relaunch only* |

Almost every "the anti-cheat is unbeatable" dead end in the community is really **two of
these being conflated**. We have a proven-DC-safe **M2 echo-loop detour** that hides a
`.text` patch from DC-1's server-directed memory read, plus a telemetry-drop vehicle
(stealth DR0 drop of `0x1ef` at SendPacket) that doesn't DC — though neither fully
neutralizes DC-1 yet (see the retrospective).

---

## 🧱 Where the wall actually is — and why MSCW is different

We can read **both halves** of the live traffic (full-duplex transport decryptor,
207-opcode receive vocabulary), **hide a client-side code patch** from the integrity
check, and **silence the detection/telemetry** side. And on the *client-trusted*
mechanics — vac, server-side park, ~3× attack speed, Always-MISS, overhead hitbox — we
win cleanly. What we **can't** do from the client is lie to the **server** about
gameplay: push the attack rate to 3× and hold it, and the server sends a **RST ~38
seconds in**.

**This is the headline for anyone coming from classic MapleStory private-server /
old-GMS hacking:** MapleStory Classic World leans on **server-side validation far more
heavily than the client-trust era we're all used to.** Classic Maple hacking lived and
died on the client — edit a value in memory, spoof a packet, and the server believed
you. On MSCW, the client-side game is mostly *winnable* (we demonstrated integrity-patch
concealment and telemetry inertness), but it buys you little against the server, because
**the server re-derives and sanity-checks the gameplay that used to be taken on faith.**
Attack cadence, movement plausibility, and rate are scored server-side on a path that
**only a full relaunch resets** (DC-3). We threw our best full-duplex tooling at it and
the server still cut us off in under a minute.

**Bottom line: the authority that matters lives server-side, and in MSCW that authority
is wide and has proven genuinely difficult to beat.** That's not a gap in our tooling —
it's the correct design, and it's the single biggest thing that separates MSCW from the
classic-hacking playbook. The one proven crack in that wall is the **mob-park
asymmetry** — monster position *is* server-relocatable while your own is not — and that
is exactly where a "tamper without DC" hunt should start.

**The specifics, for the record:**

- **Self-position is authoritative.** The *echo* X field may lie, but the *fragment* X
  field is policed for continuity — a constant +1024 east is tolerated ~1 min, then
  anti-warp DC. No free self-teleport. (A sub-threshold drift band may exist; untested.)
- **Packet content is validated.** A naive opcode/content edit (e.g. the `0xd3` test)
  DCs on server-side validation — immune to any amount of client-side devirt.
- **The screenshot *request* cipher is device-bound and unbroken.** We see the
  surveillance happen; we can't read the images.
- **⚠️ No kernel driver was loaded.** `BlackCat64.sys` doesn't load under Wine/Proton,
  so our tamper surface is **artificially large**. Several results may not generalize to
  a real Windows client with the driver active — treat every "✅ live" as "✅ live *in
  this environment*."

---

## 📖 The deep dive — capabilities, addresses, evidence

> Everything below was demonstrated **live, in-world, on a protected retail client
> (NGS-X 1.5.3.1; no BlackCat kernel driver runs or is needed under Linux/Proton)**.
> Where something only works to a point, we say exactly where the wall is.

---

## TL;DR

| # | Capability | What it does in-game | Status |
|---|------------|----------------------|--------|
| 1 | **Full-duplex wire decryption from pure ciphertext** | Read *and forge* every packet in both directions with **no handshake capture, no key trap** — the session key is static and the IV self-seeds from two consecutive headers | ✅ live, byte-exact |
| 2 | **Themida VM devirtualization** | Lifted 133,450 VM steps out of the opcode-cipher VM into readable native logic; recovered the object cipher + 16-bit MAC byte-exact | ✅ offline, validated |
| 3 | **GRAP control-plane crack** | Decrypt + rewrite the anti-cheat's own server→client channel: its **kill switch**, its **97-feature detection map**, its **105 YARA rules**, its **screenshot config**, its **expected module CRCs** | ✅ live MITM |
| 4 | **Mob VAC** | Drag on-screen monsters into melee range and kill them from across the platform | ✅ live |
| 5 | **Server-side mob PARK** | *Relocate a monster on the server* so it stays where you put it — and stays killable after the tool detaches | ✅ live (surprising) |
| 6 | **~3× attack speed** | Triple attack cadence, decoupled from the 2× movement speedhack | ✅ live, DC-safe |
| 7 | **Always-MISS** | Force incoming monster attacks to resolve as MISS — take zero damage | ✅ live-validated |
| 8 | **Overhead-hitbox forcing** | Force every polearm swing to the large overhead AoE instead of the small stab | ✅ live |
| 9 | **Active inline MITM proxy** | Transparent, DC-safe live packet-tamper framework with pluggable addons | ✅ live |

And the part that matters most for anyone continuing: **we also mapped exactly where
all of this stops working** — see *Where the wall actually is*.

---

## 🔓 The crown jewel: we read the wire with nothing but ciphertext

Classic MapleStory crypto, done properly and then fully unwound:

- **Transport body cipher = AES-256-OFB.** Software T-table implementation; master
  key in the classic MapleStory every-4th-byte layout. The block function, the OFB
  XOR loop, and the custom `getNewIv` roll were all recovered from a memory dump and
  **proven byte-exact against the real code** (1000/1000 under emulation).
- **The AES-256 key is STATIC across sessions.** An *old* session's captured packet
  decrypts byte-exact under *this* session's key. No per-session trap needed.
- **The IV self-seeds.** `word0 = ((iv[3]<<8) | iv[2]) ^ 0x00df`. Two consecutive
  packet headers pin the full 4-byte IV to a single value (unique over 2¹⁶), and
  `getNewIv` links consecutive sends — so from a **pure pcap** we recover the IV
  chain and decrypt everything.
- **Inbound (server→client) is even cheaper:** body = single-byte XOR with `iv[0]`.
- **Deliverable:** `tools-QUARANTINE/wire-session-decrypt.py` — a *passive* pcap
  decryptor. Validated full-duplex on live traffic. 5/5 trap-captured client→server
  packets recovered from ciphertext alone; 207-opcode inbound vocabulary catalogued.

Then we went **below** the opcode layer. The opcode-swap / integrity primitive is
Themida-VM-resident, so we **devirtualized the VM**: a Triton guided-symbolic lifter,
seeded from a live snapshot, folded the Themida stack machine and drove **133,450
steps** into native cleartext. The transform turned out to be a 4-byte self-keying
tag cipher + 16-bit MAC at `0x140348ca0` — recovered to `header-cipher.py`, which
**decrypts *and forges*** and matched **16/16 distinct live wire packets**.

---

## ⚔️ The in-game arsenal (the fun part)

All driven by a PySide6 control GUI (`tools-QUARANTINE/position-gui.py`) with global
Wayland/evdev hotkeys, a kill-process panic button, teleport/position-reset, and portals.

### Mob VAC — `vac-sprites.py`
Continuously hold the client's **display position** (controller-A X at ~60 Hz) plus a
**foothold-sync** (controller-B + foothold pointer) at the player's spot. The melee
target-selector then picks the on-screen monsters you dragged in, and the `0xe1` melee
packet reports a hit position **the server validates as in-range** → the kills credit
normally. We hold **X only** (keep Y honest) so the mob never leaves its foothold and
triggers the off-foothold knockback crash.

### Server-side mob PARK — `vac-sprites.py`
The genuinely surprising result. Holding the controller-B position **relocates the
monster server-side**: it persists at the spot you chose and **stays killable after the
tool detaches**. The GUI does parallel holds, snap-back filtering, and glide. Monster
position is server-*relocatable* — an asymmetry we did not expect (contrast with your
*own* position, which is server-authoritative; see below).

### ~3× attack speed — `atkspeed.py`
The real attack-rate governor is an **animation-frame timer** (`actor+0xb70/0xb74`).
Rewriting the remaining-frame count on each attack action yields ~3× attacks, cleanly
decoupled from the 2× movement speedhack. Client-trusted, DC-safe, emits naturally
legit packets (no forging).

### Always-MISS — `overhead-attacks.py` family
Incoming-collision avoidance: force the damage result to status `2 = MISS`. Live-
validated by 30-hit tests matching the on-screen miss count. You take zero damage.

### Overhead-hitbox forcing — `overhead-attacks.py`
Force every polearm swing to the **large overhead AoE** instead of the small stab —
one hook drives both the hitbox and the animation.

---

## 🧰 Active MITM: we can tamper live, without getting kicked

`tools-QUARANTINE/` ships the pieces of an **inline, transparent, DC-safe** proxy:
iptables REDIRECT + `SO_ORIGINAL_DST`, ciphertext-only IV seeding from live wire,
OnAliveReq identified every ~9 s, byte-exact pass-through, pluggable addons. It ran
end-to-end against the live game with **zero disconnects**. One built addon zeroes the
hardware-debug-register report region inside the integrity heartbeat (`dr-scrub.py`) —
keystream-free, length-preserving.

---

## Where to go next

| Read | For |
|------|-----|
| **[`01-THE-ARSENAL.md`](01-THE-ARSENAL.md)** | Per-capability deep dive: addresses, mechanism, evidence, limits |
| **[`DAMAGE-RNG.md`](DAMAGE-RNG.md)** | Deterministic RNG solver, state replay, datasets, critical strikes, and the 34-damage search |
| **[`PACKETS.md`](PACKETS.md)** | Current plaintext send/receive hooks, outgoing layouts, serializer paths, and packet-capture status |
| **[`INTERACTION.md`](INTERACTION.md)** | Full writable-memory and full-duplex capture for drop-origin analysis |
| **[`32B.md`](32B.md)** | Focused 0x32b/pickup construction, field, and full-memory capture |
| **[`DEATH.md`](DEATH.md)** | Full-duplex mob-death and drop-communication capture |
| **[`00-RETROSPECTIVE.md`](00-RETROSPECTIVE.md)** | Full technical story, environment-first, honest accounting |
| **[`ARTIFACT-INDEX.md`](ARTIFACT-INDEX.md)** | Every doc, capture, and tool, annotated |
| **[`docs/`](docs/)** | Strategic index, control-plane crack, NGS-X static report |
| **[`evidence/`](evidence/)** | Decrypted captures: detection map, CRC table, heartbeat corpus |
| **[`tools-QUARANTINE/`](tools-QUARANTINE/)** | The tools. **Quarantined for a reason — read the index first.** |

**Evidence tags** used throughout: `[C]` = reproduced from the client/dumps ·
`[R]` = runtime-observed live · `[H]` = hypothesis / not yet proven.

> ⚠️ `tools-QUARANTINE/` contains working game-manipulation and anti-cheat-evasion code
> for a **closed research LAN**. It is not for use against live Nexon services.
