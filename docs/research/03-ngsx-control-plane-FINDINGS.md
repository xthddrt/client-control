# FINDINGS — what the NGS-X control plane contains

Decoded from the archived flow dump on 2026-10-29. The full 524 KB decode is not
shipped; the redacted summary is `../../evidence/ngs-control-plane-decoded-summary.txt`.
Client version **1.5.3.1**.

The server→client channel is GRAP's control plane. Five endpoints, all now
cleartext:

---

## 1. `x-update/v2` — integrity baseline (the CRC oracle)

```json
{"url":"https://x-cdn.ngs.nexon.com/1.5.3.1/windows/x64","retry":0,"timeout":40,
 "module_crc":{
    "grap-core64.aes":        816866722,
    "grap64.dll":            3004574433,
    "grap-communicator64.aes": 391528369,
    "BlackCat64.sys":        3943112960},
 "emergency_stop":0}
```

- **`module_crc`** = the server's **expected CRCs** for each GRAP module. This is
  the reference an integrity check compares against. Knowing them means a patched
  module can be made to still report a matching CRC (if the check is client-side)
  — or we can see immediately if a module was updated server-side.
- **`BlackCat64.sys`** is a **kernel driver** — GRAP has a ring-0 component.
- `emergency_stop` present here too (global kill switch).

## 2. `x-init/v1` and `x-config/v1` — the detection ruleset

- **`subfeature`**: 97 detection features with enable levels (0=off, 1/2=on).
  Only **3 are disabled**: `0x0B08B`, `0x0E0B0`, `0x0E0A0`. The other 94 are live.
- **`signature`**: 14 feature categories carrying actual detection payloads,
  including:
  - **YARA rules** — e.g. `rule HT_doyuin` (matches a hack-tool path string
    `C:\douyin_...`) and **`rule ExtProc_Themida`** (GRAP scans *external
    processes* for Themida — directly relevant to our own tooling).
  - **`0x0F013` screenshot surveillance**: `{"capture_limit":"100","width":"1280",
    "capture_cool_time":"6","quality":"50"}` — GRAP periodically **screenshots the
    player** (up to 100, 1280px wide, q50, 6 s cooldown) and can upload them.
  - **`0x0F020` hash signatures**: lists of module hashes (`0xc87ed562`, …) to match.
- `lifetoken` (session GUID), `auth_cycle` 60 s, `terminate_message`
  "An abnormal behavior has been detected." (the string shown on a GRAP kick).

## 3. `x-csauth/v1/issue` — passport issuance

```json
{"csauthtoken":"<redacted-token>"}
```
The per-session auth token the launcher mints (the `-nxl` passport is built from
this). See `position-research/LAUNCHER-BYPASS-INVESTIGATION.md`.

## 4. `x-csauth/v2` — the heartbeat / kill switch

```json
{"csauthtoken":"…","config_changed":0,"auth_cycle":60,"emergency_stop":0,
 "terminate_message":"An abnormal behavior has been detected.","detected":[]}
```
Polled every `auth_cycle` (60 s). **This is the live enforcement channel.** The
fields that matter:
- **`emergency_stop`** — set to 1 to kill the client.
- **`detected`** — array of detections; non-empty ⇒ enforcement.
- **`config_changed`** — tells the client to re-pull `x-config/v1`.

**Empirically verified live in-world (2026-10-29, 43 beats over ~45 min — see
`04-ngsx-control-plane-ANALYSIS.md §6`, `../../evidence/heartbeat-corpus-inworld-2026-10-29.json`):**
- Real poll cadence is a **rock-steady 64.0 s** wall-clock (the `auth_cycle:60`
  value is nominal). Decode with `analysis/decode-heartbeats.py <dump.mitm>`.
- **`config_changed=1` fires once, on the first beat of the session**, then `0`.
- The **204-vs-208 byte wire-length difference is NOT semantic** — pure gzip
  jitter from the rotating `csauthtoken`.
- **No gameplay reactivity:** channel/map change, combat, cash-shop/UI, normal
  play produced zero `config_changed` flips and no off-cadence beats. The channel
  is purely time-driven; detection pushes come from GRAP's own scanners, not game
  actions.
- A rewriter must **echo the server's rotating `csauthtoken` verbatim per beat**;
  only the three state fields need pinning.

---

## Why this is the strongest Track-A asset so far

With the MITM in path and `foundations/ngs_cipher.py`'s `encrypt_response`, we can **rewrite
these server→client responses before the client sees them**:

| Rewrite | Effect |
|---|---|
| Pin `emergency_stop:0` everywhere | neutralize the global GRAP kill switch |
| Pin `detected:[]` on every `x-csauth/v2` | suppress any pushed detection |
| Pin `config_changed:0` | stop the client re-pulling updated detection configs |
| Zero the `subfeature` map / strip `signature` | disarm detections at the source |
| Keep the known `module_crc` | present expected CRCs for patched modules |

This is **cleaner and finer-grained than the IP-blackhole shield**: the client's
auth still "succeeds" (no RSTs, no handshake failures), it just never receives a
detection or a stop. It is a per-field GRAP-neutralization vehicle.

**Scope limit (unchanged):** this is Track-A (GRAP/telemetry inertness). It does
**not** touch the server-authoritative gameplay wall (DC-3 on `:8913`), which is
inferred from gameplay packets, not from this HTTPS channel.

---

## Open targets (next)

1. **Live response-rewriter.** Turn `encrypt_response` into an active mitmproxy
   addon that pins the "clean" fields. Built primitive, not yet deployed — the
   next deliberate step (operator decision pending).
2. **Request/attestation cipher.** The client→server bodies (what GRAP *reports
   about us*, and how the passport is requested) use a stronger, position-
   dependent keystream with a device-bound key inside the Themida-wrapped grap
   modules. Reading/forging it is a separate effort that ties into the
   opcrypt / VM-devirtualization track in `plan.md`.
3. **`BlackCat64.sys`.** Kernel driver — its own attack surface; out of scope here
   but noted for the GRAP architecture map.
