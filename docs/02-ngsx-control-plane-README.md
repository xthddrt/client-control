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
whole result can be re-derived from scratch using `REPLICATION-GUIDE.md`.

---

## Folder layout

```
NGS-X-CONTROL-PLANE-CRACK/
├── README.md                 ← you are here (index + TL;DR)
├── REPLICATION-GUIDE.md      ← step-by-step: zero → decrypted control plane
├── FINDINGS.md               ← what the control plane contains + why it matters
├── ANALYSIS.md               ← deep study of the decode: full detection catalog + OPSEC implications
├── tools/
│   ├── ngs_cipher.py         ← the cipher (decrypt_response / encrypt_response) + CLI
│   ├── decode-flows.py       ← decrypt every response in a .mitm dump
│   ├── decode-heartbeats.py  ← decode the x-csauth/v2 kill-switch heartbeat stream + cadence/anomaly summary
│   ├── nxcap.py              ← mitmproxy capture addon (logs nexon hosts)
│   └── relaunch-launcher-proxied.sh  ← launch the Nexon launcher through the proxy
├── setup/
│   └── mitmproxy-ca-cert.pem ← the CA the client was made to trust (copy into prefix)
├── data/
│   ├── nexon-flows-2026-10-29.mitm         ← RAW flow dump (source of truth)
│   ├── nexon-flows-inworld-2026-10-29.mitm ← RAW in-world session dump (43 heartbeats, gameplay-reactivity test)
│   ├── heartbeat-corpus-inworld-2026-10-29.json ← decoded heartbeat corpus (ts + fields, 43 beats)
│   ├── nexon-capture-live.log              ← human-readable capture log
│   ├── ngs-control-plane-full-2026-10-29.json   ← FULL decoded control plane (524 KB)
│   └── ngs-control-plane-decoded-summary.txt    ← short decoded summary
└── samples/
    └── response-ciphertext-samples.md      ← 3 real bodies + hand-worked key derivation
```

## Quick verification (proves the whole chain in 5 s)

```bash
cd tools
# decode one synthetic body with a redacted token:
printf '%s' 'KioiKioqKioo1R+n6yDoGjpuVQ/Gk6ANJWsulWkORrkbAxwxY3yLotVEcNocRVLpVuIdVEP42Kq6j3lvSoUikYcT+WqU4leg5A28omrcGvqQWlTbGeI0EQmJbKJ1dvnY9j5v57ma6E+e7JuxXjvpib6wUxwJOJWNeGfI/CtIKD7B2ZRV1BnzwcfRKQO6nYqOKioq' | python3 ngs_cipher.py
# re-decode the entire archived dump:
python3 decode-flows.py ../data/nexon-flows-2026-10-29.mitm --json /tmp/replay.json
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
- `ANALYSIS.md` §7 detection-trip, §7a heartbeat full-field + csauthtoken counter,
  §8 x-init/x-config/x-update decode + module-CRC table, §9 screenshot-exfil path,
  §10 request-cipher corpus + keystream-reuse weakness.
- `data/decoded-x-{init,config,update}-2026-10-29.json` — decoded bootstrap blobs.
- `data/module-crc-expected-2026-10-29.json` — server-expected GRAP module CRC32s.
- `data/request-cipher-corpus/` — 80 labeled request bodies + index.json + stats.json
  (keystream-reuse / two-time-pad attack lead).
