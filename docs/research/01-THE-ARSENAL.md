# 01 — The Arsenal

Per-capability breakdown of everything demonstrated against the live MapleStory Classic
World client (NGS-X 1.5.3.1). For each: what it does, how it works, the addresses/anchors,
the evidence, and the honest limit.

> Build note: the client content build updated once mid-project (addresses were
> re-derived against the live, unpacked image each time — on-disk bytes are
> Themida/WinLicense-encrypted and cannot be patched statically). Image base
> `0x140000000`, no ASLR drift. `.text` ≈ `0x140001000–0x14334b000`. All "live"
> results were obtained with **no kernel driver loaded** (`BlackCat64.sys` does not
> load under Wine/Proton), which enlarges the tamper surface — see each limit.
>
> Tags: `[C]` reproduced from client/dumps · `[R]` runtime-observed live · `[H]` hypothesis.

---

## A. Wire capabilities (crypto)

### A1. Transport cipher — AES-256-OFB, fully recovered `[C][R]`
- **Block function** `0x140cea1b0` (software T-tables at `0x143be6cf0/70f0/74f0/78f0`;
  `[rcx+0]=Nk=8`, master key at `rcx+4` in classic every-4th-byte layout).
- **OFB XOR loop** `0x140cec110`; `iv16 = iv4 × 4`; keystream starts at `KS1 = AES(AES(iv16))`.
- **IV roll** `getNewIv` entry `0x140cec5f0` (routine `0x140cec5f9`): custom, build-specific
  (shuffle table `0x143ba9f40`, seed `0xc65053f2`, rol 3, `nv[3]=nv[3]-nv[0]+T[in]`). Python
  port proven vs unicorn emulation **1000/1000** (`validate-getnewiv.py`).
- **Key is STATIC across sessions** `[C]` — an old session's op=156 packet decrypts byte-exact
  under this session's key. No per-session trap required.
- **Header** `[word0][word0^len]`; `word0 = ((iv[3]<<8)|iv[2]) ^ verMask`, `verMask = 0x00df`.
  Two consecutive headers pin the full IV uniquely (over 2¹⁶); `getNewIv` links consecutive sends.
- **Inbound (s→c)** body = single-byte XOR with `iv[0]`; recv `verMask = 0xfffe`; getNewIv reused.
- **Deliverable:** `wire-session-decrypt.py` — passive, full-duplex pcap decryptor. 5/5
  trap-captured c→s packets recovered from **pure ciphertext**; inbound 96.6–98.8% clean,
  100% header sync. Helpers mirrored in `ngs_cipher.py`.
- **Limit:** reading bodies ≠ beating content validation. The server still checks what you say.

### A2. Themida VM devirtualization → object cipher + MAC `[C]`
- The opcode/integrity primitive is VM-resident. A **Triton guided-symbolic lifter**, seeded
  from a live DR0 snapshot at the send-path VM edge (`0x141664a10 → 0x144bb1e36`, a verified
  Themida vmenter), folded the Themida stack machine (dispatch core `0x1447d7aa6`) and drove
  **133,450 steps** into native cleartext.
- **Finding:** no separate opcode-swap *table*. The transform is a native **4-byte self-keying
  tag cipher + 16-bit MAC** at `0x140348ca0` (XOR, inc `0x2a`, seed `buf[4]`; MAC seed `0x9a65`;
  integrity gate `ok=0x140348ebf` / `fail=0x140348e1b`; ~70 callers = shared VERIFY primitive).
- **Recovered to `header-cipher.py`** — decrypts **and forges**. Validated 4/4 vs native and
  **16/16** vs distinct live wire packets, both directions round-trip.
- **Reusable:** the lifter (`vm-lift.py`, Triton 1.0.x) traverses 35k+ VM insns / 796 handlers
  without choking — the tool, not just the result, is the deliverable.
- **Limit:** devirt reads logic; it does not grant server trust and did not, by itself,
  neutralize any DC mechanism.

### A3. GRAP control-plane crack `[R]`
- `body = base64(XOR_K(gzip(JSON)))`, `K = ciphertext[2] ^ 0x08` (self-describing).
- Reads **all** server→client control: kill switch (`emergency_stop`/`detected[]`), 97-feature
  detection map, **105 YARA rules**, screenshot config (`0x0F013`), expected module CRCs.
- Tools: `decode-flows.py`, `decode-heartbeats.py`. Evidence: `evidence/decoded-*`,
  `module-crc-expected-*`, `ngs-control-plane-decoded-summary.txt`.
- **Limit:** the **request/attestation** direction is device-bound and **unbroken**. A crib-drag
  on its keystream-reuse weakness recovered keystream structure but **0 plaintext** — it needs
  one known-plaintext anchor (realistically from further VM devirt).

---

## B. In-game mechanics (the cheats)

### B1. Mob VAC `[R]` — `vac-sprites.py`
- **Mechanism:** hold the client **display position** (controller-A X) at ~60 Hz + a foothold-sync
  (controller-B + foothold pointer; encoded at controller+0x2b0 / plain at +0x2c8) at the player's
  spot. Melee target-selection then picks the dragged-in mobs; the `0xe1` melee packet reports a
  near-player hit the **server validates as in-range** → kills credit.
- **Crash-avoidance:** hold **X only**, keep Y real, so the mob stays on its foothold (off-foothold
  Y induces a knockback crash).
- **Limit:** works because the resulting hit is genuinely in-range at report time; it is not forging
  out-of-range kills.

### B2. Server-side mob PARK `[R]` — `vac-sprites.py`
- **Mechanism:** holding the controller-B position + foothold at a chosen spot **relocates the
  monster server-side** — it persists there and stays killable **after the tool detaches**.
- GUI: parallel holds, snap-back filtering, `--glide` for smooth relocation, logging.
- **Why it matters:** monster position is server-*relocatable* while **your own** position is not —
  a real, exploitable asymmetry and the best lead for the "server-trusted field" hunt.

### B3. ~3× attack speed `[R]` — `atkspeed.py` / `atkspeed-frames.py`
- **Mechanism:** the attack-rate governor is an animation-frame timer (`actor+0xb70/0xb74`). On each
  new frame of an attack action (ids 10/13/14/19/20) write remaining/FACTOR (≈1.5 atop 2× speed ⇒ ~3×).
  Only the local actor and attack actions are touched.
- **Safety:** client-trusted; emits naturally legit packets (no forging) → DC-safe.
- **Contrast:** *forged* 3× cadence (duplicate injected hits) is deduped and RSTs in ~38 s (DC-3).

### B4. Always-MISS `[R]` — `overhead-attacks.py` family
- **Mechanism:** incoming-collision avoidance forces the damage result to status `2 = MISS`
  (avoidance wrapper return `0x2b26d8`, gated on monster_present & attack_record_absent).
- **Validation:** 30-hit tests matched on-screen MISS counts. Net effect: zero incoming damage.

### B5. Overhead-hitbox forcing `[R]` — `overhead-attacks.py`
- **Mechanism:** force every polearm swing to the large overhead AoE instead of the small stab; one
  hook drives both hitbox and animation.

### B6. Orchestration — `position-gui.py`
- PySide6 GUI: global Wayland/evdev hotkeys, kill-process panic button, teleport, position-reset,
  portals, and toggles/parameters for every capability above. `observe-incoming-display.py` is the
  read-side companion (live incoming-packet display).

---

## C. Evasion / anti-disconnect

### C1. Active inline MITM proxy `[R]`
- Transparent iptables REDIRECT + `SO_ORIGINAL_DST`; ciphertext-only IV seed from live wire;
  OnAliveReq identified every ~9 s; byte-exact pass-through; pluggable addons. Ran end-to-end
  **DC-safe**.
- **DR-scrub addon** (`dr-scrub.py`): zeroes the hardware-debug-register report region `[28:44]`
  inside the OnAliveReq integrity heartbeat — keystream-free (AES-OFB additive), length-preserving,
  9/9 offline tests. Live A/B showed our ptrace HW DRs read the **Wine shadow** context, not the
  report — so the scrub guards a window our method never dirties (no-op safeguard, not a prereq).

### C2. Telemetry drop `[R]` — `sendpacket-drop.py`
- Stealth DR0 drop of the `0x1ef` telemetry opcode at SendPacket `0x141660360` — no DC.
- Companion: `sendpacket-observe.py` (passive send-path tap). `grap-core-crash.py` can crash-kill
  `grap-core64` (NtWriteFile E9 detour) on aged sessions without DC.

### C3. M2 echo-loop detour `[R]` — `m2-detour.py`
- Echo-loop detour (`0x141667cd1`) + substitution table that hides a `.text` patch from the
  **server-directed memory read** inside DC-1. Proven DC-safe (soaked 70 s+ / 8 OnAliveReq cycles).
- **Honest limit:** proven DC-safe, **not** yet proven to "save" a sampled byte → DC-1 `.text`-patch
  freedom is not yet won.

---

## D. The walls (what did NOT fall)

| Wall | Evidence | Implication |
|------|----------|-------------|
| Self-position (fragment X) | +1024 east tolerated ~1 min → DC (anti-warp) | No free self-teleport |
| Attack-rate legitimacy | forged 3× cadence → RST ~38 s | Only client-trusted speed is safe |
| Packet content | `0xd3` edit → immediate DC | Devirt doesn't beat content validation |
| Screenshot request cipher | device-bound, crib-drag 0 plaintext | Can't read exfil'd images |
| DC-1 `.text` freedom | server-directed read can catch patches; M2 not yet proven to save a byte | Anti-DC `.text` patching unfinished |

**The throughline:** MSCW enforces far more **server-side** than classic-MapleStory hacking
assumes. Client-trusted mechanics fall cleanly; server-authoritative ones hold. The mob-park
asymmetry is the proof that trusted-field gaps exist — and the best next lead.
