# 00 — Retrospective

A reverse-engineering campaign against **MapleStory Classic World (MSCW)** and its
anti-cheat, **NGS-X / GRAP** (Nexon Game Security X), run as authorized research on a
closed, isolated LAN. This document is the honest story: what we built, what fell, what
held, and — critically — the environment caveat that frames every result.

---

## 0. Environment first (the caveat that colors everything)

- **Platform:** the client runs under **Wine/Proton on Linux**, not native Windows.
- **No kernel driver:** NGS-X's kernel component **`BlackCat64.sys` does not load** under
  Wine/Proton. The retail build advertises "GRAP/NGS-X 1.5.3.1 + BlackCat driver," but the
  ring-0 enforcement half is absent in our setup.
- **Consequence:** the user-mode tamper surface is **artificially large**. Memory reads,
  hardware breakpoints, inline hooks, and `/proc/PID/mem` dumps that a loaded driver might
  detect or block were available to us. **Several "✅ live" results may not generalize to a
  real Windows client with the driver active.** Every capability below should be read as
  "demonstrated *in this environment*."
- **Build:** NGS-X 1.5.3.1 (or a near-identical sibling); image base `0x140000000`, no ASLR
  drift; `.text` ≈ `0x140001000–0x14334b000`; Themida VM RWX ≈ `0x143eb3000–0x14526d000`.
  The on-disk EXE is Themida/WinLicense-protected — **patch live, never on-disk**. A content
  update mid-project forced re-deriving RVAs (automated via `reanchor.py`).

This honesty is not hedging for its own sake. It is the single most important thing for
anyone continuing the work: know which wins are *platform artifacts* and which are *real
protocol/design breaks*. The crypto breaks (below) are design breaks. Some of the tamper
conveniences are platform artifacts.

---

## 1. The crypto breaks (design breaks — these travel)

### Transport cipher — AES-256-OFB, broken end to end
Live correlation of plaintext send buffers vs true on-wire bytes proved the transport is
**classic MapleStory crypto**: a 4-byte rolling-IV header and a length-preserving IV-keyed
body. We then recovered the whole thing from a memory dump: the AES-256 T-table block
function (`0x140cea1b0`), the OFB XOR loop (`0x140cec110`), and a **custom** `getNewIv` roll
(`0x140cec5f9`) — the IV roll proven byte-exact against the real code **1000/1000** under
emulation.

Two results make this devastating rather than merely complete:
1. **The AES-256 key is static across sessions** — an old capture decrypts under a new
   session's key.
2. **The IV self-seeds from ciphertext** — two consecutive headers pin the full IV
   (`word0 = ((iv[3]<<8)|iv[2]) ^ 0x00df`, unique over 2¹⁶), and `getNewIv` chains sends.

So `wire-session-decrypt.py` is a **passive** decryptor: feed it a pcap, get plaintext, both
directions, with no handshake and no key trap. Inbound bodies are even cheaper (single-byte
XOR with `iv[0]`). A 207-opcode inbound vocabulary was catalogued.

### Themida VM devirtualization — the opcode/MAC primitive
The opcode-swap/integrity primitive is **Themida-VM-resident**. Rather than fight the VM at
runtime (Magicmida/ScyllaHide unpack and anti-anti-debug; they do **not** devirtualize), we
built a **static guided-symbolic lifter** in Triton, seeded from one short live DR0 snapshot,
and ran it **offline against a `/proc/PID/mem` dump** (already unpacked). It folded the
Themida stack machine and drove **133,450 steps** into native cleartext.

The payoff: the transform is a native **4-byte self-keying tag cipher + 16-bit MAC** at
`0x140348ca0` (a shared VERIFY primitive, ~70 callers). Recovered to `header-cipher.py`,
which decrypts **and forges**, validated 4/4 vs native and **16/16** vs live wire packets.
The reusable `vm-lift.py` — not just the one result — is the deliverable.

### GRAP control-plane crack
The anti-cheat's own server→client channel uses a self-describing cipher
(`base64(XOR_K(gzip(JSON)))`, `K = ciphertext[2]^0x08`). We read and (via MITM) can rewrite:
the **kill switch**, the **97-feature detection map**, the **105 YARA rules**, the
**screenshot config** (`0x0F013`: limit 100, 1280px, q50, 6 s cooltime, enabled — exfil
batched into `x-csauth/v2`), and the **expected module-CRC table**. The one direction we did
**not** break is the device-bound **request/attestation** cipher; a crib-drag on its
keystream-reuse weakness recovered structure but **0 plaintext**.

---

## 2. The in-game arsenal (demonstrated live)

Full mechanism/addresses in **`01-THE-ARSENAL.md`**. In brief, all orchestrated by a PySide6
GUI (`position-gui.py`):

- **Mob VAC** — drag on-screen mobs into melee via held display-position + foothold-sync; the
  `0xe1` hit is genuinely in-range at report time, so the server credits kills.
- **Server-side mob PARK** — holding controller-B position **relocates the monster
  server-side**; it persists and stays killable after detach. (The surprising asymmetry.)
- **~3× attack speed** — rewrite the animation-frame timer; client-trusted, DC-safe.
- **Always-MISS** — force incoming damage to status `2 = MISS`; zero damage taken.
- **Overhead-hitbox forcing** — force the large polearm AoE on every swing.
- **Active MITM proxy** + **telemetry drop** + **M2 `.text`-hiding detour** — DC-safe evasion
  scaffolding.

---

## 3. What held — the server-side wall

MSCW relies on **server-side authority much more heavily than the classic-MapleStory hacking
scene expects**, and that is exactly what defeats the biggest-sounding attacks:

- **Self-position is authoritative.** Echo X may lie; fragment X is policed for continuity
  (+1024 east tolerated ~1 min, then anti-warp DC). No free self-teleport.
- **Attack-rate legitimacy is validated.** Forged 3× cadence → server RST ~38 s. Only
  client-trusted speed is safe.
- **Packet content is validated.** A naive `0xd3` edit DCs immediately — immune to client-side
  devirt.

The clean dividing line: **client-trusted mechanics fall; server-authoritative mechanics
hold.** The mob-park result proves trusted-field asymmetries exist — which is the entire
reason Track B ("tamper without DC") is a *hunt* and not a dead end.

---

## 4. The three disconnect mechanisms (never conflate)

- **DC-1 — code-integrity:** OnAliveReq `.text` sweep (~4 min) + a **server-directed arbitrary
  memory read** (the `+68` "digest" is really a read primitive that *can* catch `.text`
  patches). OnAliveReq relocated to `0x141667b80` this build; 6-section `0x9C` report mapped
  off-wire (we decrypt it). DR report = 16 plaintext zero bytes at `[28:44]`.
- **DC-2 — core-liveness:** grap-core heartbeat (~79 s / ~1 s).
- **DC-3 — server gameplay-suspicion:** content/rate validation; recovers only on full relaunch.

Progress against DC-1: the **M2 echo-loop detour** (`m2-detour.py`) hides a `.text` patch from
the server-directed read and is **proven DC-safe** (8 OnAliveReq cycles) — but **not yet proven
to save a sampled byte**, so `.text`-patch freedom is not yet won. The **DR-scrub** addon turned
out to guard a window our Wine/ptrace method never dirties (shadow-context finding) — a correct
no-op, and a useful threat-model correction.

---

## 5. Where to push next

1. **DC-1 digest known-plaintext** — recover the salted `+68` digest algorithm via controlled
   tamper diffing → the biggest Goal-A win (`.text`-patch freedom).
2. **Transport request/attestation cipher** — one known-plaintext anchor (via more VM devirt)
   collapses the whole epoch by keystream replay; crib map is staged.
3. **Server-trusted-field hunt (Track B)** — start from the mob-park asymmetry; look for other
   fields the server relocates/accepts without continuity policing.
4. **Recv semantics** — label X/Y/HP/stance in the 207-opcode inbound vocabulary by diffing
   per-object streams against known on-screen actions (`recv-timeline.py` ready).

---

## 6. Reproduction & preservation

- **`POST-UPDATE-RECOVERY.md`** (in source) runbook: hash-check → mem-dump → `reanchor.py`
  (relocates all RVA anchors by recompile-robust interior signatures) → re-validate wire on a
  fresh pcap. Methodology and captured pcaps survive updates; only RVAs break, and they
  recover in one command. The ported ciphers are pure Python and address-independent.
- **Research and applicable tools require caution** (`analysis/` and `tools/`): this is working
  game-manipulation and anti-cheat-evasion code for a closed research LAN, not for use against
  live services.
