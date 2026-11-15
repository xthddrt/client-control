# GRAP 0x0F013: configuration, origination, and scoped filter

## Bottom line

The screenshot configuration is real and present in the current GRAP core. Its values match the original report: capture limit `100`, width `1280`, JPEG quality `50`, and cooldown `6`.

The original claim that heartbeat size increases **are screenshot uploads is not proven**. The old analysis measured encrypted client request bodies but did not identify their plaintext image fields or link them to a capture serializer. The evidence supports a capture capability and upload candidates, not a completed capture-to-wire decode.

A scoped, opt-in `x-config` response filter is now implemented and verified through a real local mitmproxy instance. It disables only feature `0x0F013`; it does not suppress heartbeats or erase unrelated detection features. **The running game has not been put through this filter, so actual suppression on a live client is not yet verified.**

## This is not MapleStory opcode 0x181

The relevant communication is NGS HTTPS traffic, not the previously analyzed MapleStory game message:

```text
server -> client: x-config.ngs.nexon.com/v1 response
                   -> GRAP feature 0x0F013 configuration
local capture path -> not fully identified
client -> server: x-csauth.ngs.nexon.com/v2 request bodies
                   -> encrypted attestation/upload candidates; image fields not decoded
```

The response-body cipher is decoded and rewritable. The separate client-to-server request/attestation cipher remains unbroken. `analysis/decode-heartbeats.py` decodes **server responses**, not the client’s upload bodies.

## Live configuration evidence

[20261115-grap-screenshot-config.json](../../../evidence/outgoing/20261115-grap-screenshot-config.json)

A bounded read-only scan of GRAP core PID `1392465` found the current native configuration at `0x9c3172c`. The module base is `0x400000`, PE timestamp is `0x6a9984cf`, and the on-disk build hash recorded in the profile is `2c24777e1b7e7e81e0ca4a4d5e1fc6acd68ef6abcd3e2ee3a339554fbc3b8ec3`.

Exact bounded excerpt:

```text
01 00 46 81 02 00 00 00 13 f0 00 00 01 00 00 00
09 38 00 00 00 00 00 00 04 00 00 00 11 00 00 00
63 61 70 74 75 72 65 5f 63 6f 6f 6c 5f 74 69 6d
65 01 00 00 00 36 0d 00 00 00 63 61 70 74 75 72
65 5f 6c 69 6d 69 74 03 00 00 00 31 30 30 07 00
00 00 71 75 61 6c 69 74 79 02 00 00 00 35 30 05
00 00 00 77 69 64 74 68 04 00 00 00 31 32 38 30
```

The bytes `09 38` are little-endian `0x3809`, decimal `14345`. The four ASCII keys are followed by a little-endian string length and numeric ASCII value. The snapshot parser validates those lengths and digits rather than assuming strings at arbitrary offsets. The other leading bytes are unassigned native metadata; they are not interpreted as flags, timestamps, or identifiers. The record's presence does not prove that a capture has fired.

The scan covered `162,762,752` bytes and skipped or could not read 67 mappings, including mappings larger than 128 MiB. It was not a complete memory scan. No screenshot or desktop contents were collected.

Reproduce against a matching live core:

```bash
python3 analysis/grap-screenshot-config.py --self-test
sudo -n .venv/bin/python analysis/grap-screenshot-config.py CORE_PID \
  --output captures/grap-screenshot-config.json
```

`foundations/grap-core-profile.json` validates the PE identity and import metadata. It deliberately does not use the earlier virtualized instruction address as a fingerprint because that code changed across process launches.

## Capture origination: what was found

The core imports `BitBlt` from `GDI32.dll`. Its import-table address is `0x26ea910`; in the observed process it resolved to `0x6ffffe0ecd20`. There are no direct `call`/`jmp` instructions through that import slot in the scanned core image. An indirect register load was observed in one virtualized routine, but its instruction address was not stable across launches.

A 120-second execution watch covered all 17 GRAP-core threads present at launch:

- `watch_hits: 0`;
- `matched_events: 0`;
- `failures: 0`;
- every per-thread record has `error: null`;
- debug registers were restored and each observer detached.

[20261115-grap-bitblt-summary.json](../../../evidence/outgoing/20261115-grap-bitblt-summary.json)

This is a bounded negative result for **this one API in this one process and time window**. It does not rule out `PrintWindow`, DXGI, another process, a driver, or a later capture. It does not show when or why an upload is constructed. The environment restarted MapleStory and GRAP during the investigation; no causal relationship to an observer is claimed, and only the validated completed watch is used here.

Reproduce without reading image contents:

```bash
analysis/watch-grap-screenshots.sh CORE_PID 120 captures/grap-bitblt
```

The wrapper writes private per-thread registers/stacks and a summary. It uses the existing `debug-watch.py` implementation and a build-specific profile. New threads created after launch are outside its coverage. An API call would still require caller and data-flow analysis before being labeled surveillance.

## Scoped configuration filter

`analysis/ngs-mitm.py` now supports `ngs_screenshot_filter`, default `false`. On an exact `x-config.ngs.nexon.com/v1` response, the opt-in filter:

- changes `subfeature["0x0F013"]` to `0` when present and enabled;
- changes each `signature["0x0F013"][i]["l"]` to `0` when present and enabled;
- preserves `id`, `capture_limit`, `width`, `quality`, `capture_cool_time`, all other feature codes, and unrelated fields;
- refuses an unexpected feature-container shape instead of guessing;
- re-encrypts the response with the existing validated NGS response cipher;
- logs `matched`, `action`, `forward`, and exact changes;
- preserves the original decoded response, original response bytes, and rewritten response bytes.

The request hook records the original NGS host in flow metadata so an upstream URL rewrite does not lose the destination used by response filtering. This is independent of the generic `ngs_neutralize` option, whose behavior is unchanged.

For a scoped launch, fully close MapleStory and the Nexon launcher first, then run:

```bash
NGS_SCREENSHOT_FILTER=1 NGS_NEUTRALIZE=false analysis/launch-ngs-mitm.sh
```

`NGS_NEUTRALIZE=false` prevents the wrapper's historical blanket ruleset/kill-switch rewriting. The screenshot option alone does not drop any request. Do not replace it with a blanket `x-csauth/v2` block: that would also interrupt the control channel and unrelated attestation traffic.

The launcher must be started through the proxy. The current already-running session cannot be retrofitted through this workflow. The wrapper does not close or restart those processes automatically.

## Offline verification actually performed

[20261115-grap-screenshot-filter-offline.json](../../../evidence/outgoing/20261115-grap-screenshot-filter-offline.json)

A real `mitmdump 12.3.1` process loaded `analysis/ngs-mitm.py`. A local loopback HTTP server returned an encrypted synthetic configuration containing the original screenshot settings, another feature, and an unrelated nested value. The proxy forwarded the request and returned a rewritten encrypted response.

Verified results:

- `subfeature["0x0F013"]`: `1 -> 0`;
- screenshot entry `l`: `1 -> 0`;
- screenshot parameters: unchanged;
- other feature `0x06010`: unchanged;
- unrelated nested value: unchanged;
- logged original body equals the exact server fixture;
- logged rewritten body equals the exact bytes returned to the local client;
- decision: `matched: true`, `action: "modify"`, `forward: true`.

Reproduce the real local-proxy verification and run the direct response-hook and cipher tests:

```bash
.venv/bin/python analysis/verify-ngs-screenshot-filter.py \
  captures/ngs-screenshot-filter-reproduction.json
.venv/bin/python analysis/ngs-mitm.py --self-test
.venv/bin/python analysis/ngs-proxy.py --self-test
bash -n analysis/launch-ngs-mitm.sh analysis/watch-grap-screenshots.sh
```

The verifier creates a unique local output and refuses to overwrite an existing one. Its synthetic output should match the saved offline evidence byte-for-byte on the recorded tool version. It also feeds the actual proxy log through `traffic-ledger.py` and verifies the original message, linked filter decision, original/forwarded exact bytes, and original/rewritten decoded JSON.

The offline fixture contains no Nexon credentials and did not contact Nexon. It verifies the rewrite and logging path, not the game’s response to a disabled feature.

## Remaining evidence needed

A live proxied launch must confirm that the client accepts `l: 0` and that screenshot production stops while unrelated traffic continues. The original and rewritten responses and subsequent request sizes should be compared without inferring image contents from size alone.

For actual upload origination, capture a natural screenshot event at the producing API, follow its buffer through encoding and serialization into the request builder, and link that exact request to the proxy record. Until then, image fields, capture cadence, upload contents, and server-side handling remain unknown. Blocking or modifying them is not established as safe.
