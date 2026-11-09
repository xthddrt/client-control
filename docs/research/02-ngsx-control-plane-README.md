# NGS-X CONTROL-PLANE CRACK — master index

**Status:** ✅ Server→client control-plane cipher fully broken and reproducible.
**Date:** 2026-10-29 · **Session:** `<redacted-session-id>` · **Target:** MapleStory Classic World (MSCW), NGS-X/GRAP, client 1.5.3.1 x64.
**Context:** Authorized security research on the operator's own closed LAN / own account / own client.

---

## TL;DR — what this folder is

We put a MITM proxy on the client's **NGS-X HTTPS auth/telemetry channel**
(`x-*.ngs.nexon.com`) and broke the response-body cipher. That channel is
**GRAP's entire control plane**. Every server→client message is now readable
(and rewritable): the kill switch (`emergency_stop`/`detected[]`), the full
97-entry detection feature map, pushed **YARA rules**, the **screenshot-
surveillance** config, and the **expected module CRCs** for the GRAP binaries.

The cipher is trivial: **`body = base64( XOR_K( gzip(JSON) ) )`** with a single
byte `K` that is self-describing (`K = ciphertext[2] ^ 0x08`). No brute force.

This is the highest-value Track-A (GRAP-inertness) asset produced so far. The
whole result can be re-derived from scratch using `05-ngsx-control-plane-REPLICATION.md`.

---

## Current repository layout

```text
foundations/ngs_cipher.py                  ← cipher primitives + CLI
analysis/decode-flows.py                   ← decrypt responses in a .mitm dump
analysis/decode-heartbeats.py              ← heartbeat decode + cadence/anomaly summary
analysis/ngs-mitm.py                       ← live logger and response decoder/neutralizer
analysis/launch-ngs-mitm.sh                ← proxy and proxied launcher
docs/research/03-ngsx-control-plane-FINDINGS.md
docs/research/04-ngsx-control-plane-ANALYSIS.md
docs/research/05-ngsx-control-plane-REPLICATION.md
evidence/                                  ← redacted decoded evidence; raw captures stay local
```

## Quick verification (proves the whole chain in 5 s)

Run from the repository root:

```bash
# decode one synthetic body with a redacted token:
printf '%s' 'KioiKioqKioo1R+n6yDoGjpuVQ/Gk6ANJWsulWkORrkbAxwxY3yLotVEcNocRVLpVuIdVEP42Kq6j3lvSoUikYcT+WqU4leg5A28omrcGvqQWlTbGeI0EQmJbKJ1dvnY9j5v57ma6E+e7JuxXjvpib6wUxwJOJWNeGfI/CtIKD7B2ZRV1BnzwcfRKQO6nYqOKioq' | .venv/bin/python foundations/ngs_cipher.py
# re-decode a captured flow dump:
.venv/bin/python analysis/decode-flows.py captures/nexon-flows-2026-10-29.mitm --json /tmp/replay.json
```

## What is NOT solved (open targets)

- **Request cipher** (client→server attestation). Stronger, position-dependent
  keystream, device-bound key inside the Themida-wrapped grap modules. This is
  what GRAP *reports about us*; reading it needs the opcrypt/VM-devirt track.
- **Live response-rewriting** is built (`encrypt_response`) but not yet wired
  into an active addon — that is the next deliberate step (see FINDINGS §"Next").

## Provenance

Grew out of `position-research/LAUNCHER-BYPASS-INVESTIGATION.md` (same MITM rig,
originally for launcher-free start). CONTINUATION-LOG entries: **PM-73** (crack),
PM-70/71/72 (network audit + shield expansion that preceded it).

### 2026-10-29 collection batch (gd-* todos)
- `04-ngsx-control-plane-ANALYSIS.md` §7 detection-trip, §7a heartbeat full-field + csauthtoken counter,
  §8 x-init/x-config/x-update decode + module-CRC table, §9 screenshot-exfil path,
  §10 request-cipher corpus + keystream-reuse weakness.
- `../../evidence/decoded-x-update-2026-10-29.json` — shipped redacted x-update blob; other raw decoded bootstrap blobs are not shipped.
- `../../evidence/module-crc-expected-2026-10-29.json` — server-expected GRAP module CRC32s.
- The historical request-cipher corpus (80 labeled bodies + index/stats) is not shipped.
