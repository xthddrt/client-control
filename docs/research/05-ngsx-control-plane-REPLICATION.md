# REPLICATION GUIDE — from zero to a decrypted GRAP control plane

Goal: reproduce the crack end-to-end on a fresh machine/session. Two halves:
**(A)** capture the NGS-X HTTPS traffic via MITM, **(B)** decrypt it. If you only
want to *re-verify* the cipher, skip to §C (works offline against the archived
dump).

Environment used: Bazzite (Fedora atomic), Wine/Proton prefix `~/Games/nexx`
(GE-Proton11-11) launched via `umu-run`. System Python 3.14. mitmproxy installed
user-level.

---

## A. Capture the NGS-X traffic (MITM)

The key enabler: the Nexon launcher backend makes its HTTPS calls with Python
`requests`/urllib3 (`User-Agent: Python-urllib/3.x`). `requests` honors proxy
env vars **and** a custom CA bundle, so no binary patching is needed — just
point the launcher's env at a proxy and hand it our CA.

1. **Install mitmproxy** (user-level; do not touch the read-only system Python):
   ```bash
   pip install --user mitmproxy          # provides ~/.local/bin/mitmdump
   ~/.local/bin/mitmdump --version       # confirm
   ```
   First run of mitmdump generates the CA at `~/.mitmproxy/mitmproxy-ca-cert.pem`
   (a copy is archived in `setup/`).

2. **Copy the CA into the Wine prefix** so the launcher can load it by a
   DOS path:
   ```bash
   cp ~/.mitmproxy/mitmproxy-ca-cert.pem "$HOME/Games/nexx/drive_c/mitm-ca.pem"
   ```

3. **Start the capture proxy and proxied launcher** with the shipped wrapper:
   ```bash
   analysis/launch-ngs-mitm.sh
   ```
   The wrapper uses `analysis/ngs-mitm.py`, listens on `127.0.0.1:8080`, sets
   `connection_strategy=lazy`, writes flow/event logs under `captures/`, and
   supplies the proxy and CA environment to the launcher. Adjust its
   machine-specific prefix and launcher paths first.
   `connection_strategy=lazy` matters: it defers upstream TLS until the client
   speaks, which avoids SNI/handshake issues with the pinned-ish NGS hosts.

4. **Launch ONLY the launcher through the proxy** (bare — no speedhack wrapper).
   The wrapper sets the critical environment:
   ```bash
   export HTTP_PROXY=http://127.0.0.1:8080  HTTPS_PROXY=http://127.0.0.1:8080
   export http_proxy=http://127.0.0.1:8080  https_proxy=http://127.0.0.1:8080
   export REQUESTS_CA_BUNDLE='C:\mitm-ca.pem'  CURL_CA_BUNDLE='C:\mitm-ca.pem'
   export SSL_CERT_FILE='C:\mitm-ca.pem'       NODE_EXTRA_CA_CERTS='C:\mitm-ca.pem'
   ```
   If the account session is cached, the launcher **auto-mints and auto-launches
   the game** — no manual login/Play needed. The game inherits the proxy env, so
   its NGS-X auth/telemetry HTTPS (`x-init`, `x-csauth`, `x-config`, `x-update`)
   also flows through mitmdump.

5. **Endpoints you should see** (host `x-*.ngs.nexon.com`):
   | Endpoint | Role |
   |---|---|
   | `x-update.ngs.nexon.com/v2` | version + **module CRC** list + emergency_stop |
   | `x-init.ngs.nexon.com/v1` | lifetoken + **subfeature map** + pushed **YARA** signatures |
   | `x-csauth.ngs.nexon.com/v1/issue` | passport/csauthtoken issuance |
   | `x-csauth.ngs.nexon.com/v2` | heartbeat: emergency_stop / detected[] / config_changed |
   | `x-config.ngs.nexon.com/v1` | full detection config (subfeature + signatures) |

   Only `x-*` bodies are ciphered; `nxl.nxfs`/`nxl.log` launcher calls are plain.

> Notes: gameplay sockets (`:8913`, `:8566`, `166.117.x`) are raw TCP, NOT
> proxied — only HTTPS honors the proxy env. The game held `x-csauth/v2`
> connections open through the proxy for the whole session with no DC.

---

## B. Decrypt (the actual crack)

### How it was discovered
1. The captured response bodies are base64. Decoding them showed **6-byte runs
   of a single byte** (e.g. `4b 4b 4b 4b 4b 4b`) at a fixed offset, with the run
   byte *differing per message*. Real AES/TLS never does that → weak cipher.
2. XORing a sample by its run byte revealed `08 00 00 00 00 00 00 ff 35 8d ...`
   and the tail-bytes were **identical across different messages** → a **gzip
   stream** (`1f 8b 08 00 <mtime> 00 ff` + deflate). The first two wire bytes are
   a 2-byte header replacing the `1f 8b` magic.
3. Since gzip byte[2] (CM) is always `0x08`, the key is **`K = C[2] ^ 0x08`** —
   recovered with zero guessing; the gzip CRC-32 then validates the plaintext.

### The algorithm (see `foundations/ngs_cipher.py`)
```
raw = base64_decode(wire_body)
K   = raw[2] ^ 0x08
gz  = b"\x1f\x8b" + bytes(c ^ K for c in raw)[2:]
json = gunzip(gz)
```

### Decode a whole dump
Run from the repository root:
```bash
.venv/bin/python analysis/decode-flows.py captures/nexon-flows-2026-10-29.mitm --json /tmp/out.json
```

### Rewrite responses (for live neutralization — built, not yet deployed)
`ngs_cipher.encrypt_response(plaintext, key, header2)` returns a wire-ready body.
A MITM addon can parse a response, force `emergency_stop=0` / `detected=[]` /
zero the `subfeature` map, re-encrypt, and pass it on. Any key 1..255 is valid
because the client recovers K from `C[2]^0x08`.

---

## C. Offline re-verification (no game, no proxy)

Run from the repository root:
```bash
# 1) synthetic hand sample (decodes to a redacted token):
printf '%s' 'KioiKioqKioo1R+n6yDoGjpuVQ/Gk6ANJWsulWkORrkbAxwxY3yLotVEcNocRVLpVuIdVEP42Kq6j3lvSoUikYcT+WqU4leg5A28omrcGvqQWlTbGeI0EQmJbKJ1dvnY9j5v57ma6E+e7JuxXjvpib6wUxwJOJWNeGfI/CtIKD7B2ZRV1BnzwcfRKQO6nYqOKioq' | .venv/bin/python foundations/ngs_cipher.py
# 2) full captured dump:
.venv/bin/python analysis/decode-flows.py captures/nexon-flows-2026-10-29.mitm | head
```
Expected: clean JSON with `csauthtoken`, `emergency_stop`, `detected`, etc.
Only mitmproxy is required (`pip install --user mitmproxy`) for step 2; step 1
needs just the Python stdlib.

---

## Gotchas / provenance

- `pip` trap from the broader plan is unrelated here; this needs only `mitmproxy`.
- The launcher must be started **bare** through the proxied env (not via the
  speedhack wrapper) so it inherits the proxy + CA cleanly.
- The `-nxl` passport captured during the run is a short-lived account credential
  — kept out of this archive on purpose (recapture per §A if ever needed).
- Request/attestation bodies will NOT decode with this tool — different, harder
  cipher (open target).
