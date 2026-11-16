# client-server

Track and block MapleStory client, launcher, NGS and helper-program traffic in one
ordered, evidence-labelled record.

This repository is the communication-only subset of
[`xthddrt/client-control`](https://github.com/xthddrt/client-control). Gameplay
manipulation, RNG, VAC and other in-game tools are intentionally not included.
System-wide capture/enforcement remains the separate
[`xthddrt/monitor-filter`](https://github.com/xthddrt/monitor-filter) project;
`traffic` ingests its session bundles.

**Start here:** [`docs/COMMUNICATIONS.md`](docs/COMMUNICATIONS.md) is the overview of everything the game
communicates (who, which way, how much, what it means, how sure, what is unknown).

## What is here

| Path | Purpose |
|---|---|
| `analysis/game-proxy.sh`, `traffic/proxy.py`, `traffic/stream.py`, `traffic/protocol.py` | Capture of every connection of the game family: allow/refuse by policy, every byte recorded, game messages decrypted and named both ways. |
| `traffic/` | Ordered client→server ledger: pcap/pcapng and monitor ingestion, TCP reassembly, transport decryption, packet decoding, provenance, policy evaluation, kfilter translation. |
| `analysis/capture-senders.sh`, `analysis/senders-report.py` | Which Windows module of the game family makes each send (monitor-filter's kfilter in audit mode), per server. |
| `analysis/client-origins.py` | Static map of every client message: builder code, fields in order, the event handler and part of the client it comes from ([`docs/reference/client-messages.md`](docs/reference/client-messages.md)). |
| `analysis/message-breakdown.py`, `analysis/traffic-breakdown.py` | Generated tables: every game message type by direction and group ([`docs/reference/message-breakdown.md`](docs/reference/message-breakdown.md)); all traffic by category and direction ([`docs/reference/traffic-breakdown.md`](docs/reference/traffic-breakdown.md)). |
| `analysis/tls-summary.py`, `analysis/wininet-cache.py`, `analysis/pe-xrefs.py` | Reading HTTPS without decrypting it: TLS records, client fingerprint and certificates; the URLs and replies kept in Wine's WinINet cache; where a DLL uses a string and what the function does. |
| `analysis/tls-keys.py`, `analysis/tls-memscan.py`, `analysis/tls-keys-watch.sh`, `traffic/tls12.py` | Decrypting the analytics upload (TLS 1.2 AES-GCM) with keys read from the running game's memory (read-only, needs sudo; only connections open at the read); values masked by default. |
| `analysis/outgoing-packet-capture.py` | Live `SendPacket` observer with pre-send policy filtering. |
| `analysis/capture-outgoing.sh` | Wrapper: game plaintext JSONL plus a raw full-duplex pcap. |
| `analysis/ngs-proxy.py` | NGS/HTTPS request/response logging, host/path blocking and policy enforcement. |
| `analysis/ngs-mitm.py` | NGS control-plane logging, response decoding and optional neutralization. |
| `analysis/decode-flows.py` | Offline decoder for captured NGS mitmproxy flows. |
| `analysis/decode-heartbeats.py` | Offline `x-csauth/v2` heartbeat decoder and cadence check. |
| `analysis/wire-session-decrypt.py` | Passive full-duplex game pcap decryptor. |
| `foundations/` | Transport IV roll, NGS response cipher, build-validated image resolver, ptrace helpers and the build profile. |

The `traffic` schema still uses the `client-control.traffic/v1` and
`client-control.traffic-filter/v1` names so existing capture files and policies
stay readable.

## Quick start

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# Verify the port without a client, root or network.
.venv/bin/python -m traffic selftest

# Build a ledger from any combination of sources.
.venv/bin/python -m traffic ingest \
  --pcap captures/outgoing-session-*.pcap \
  --capture captures/outgoing-events-*.jsonl \
  --monitor ~/monfilter-sessions/<run>/<session> \
  --ngs captures/ngs-events-*.jsonl \
  --out captures/ledger

.venv/bin/python -m traffic show captures/ledger --opcode 0x32b
.venv/bin/python -m traffic trace captures/ledger --id <message-id>
```

Capture of every connection the game family makes (MapleStory, the launcher,
the anti-cheat, the overlay), decoded both ways:

```bash
analysis/game-proxy.sh                                   # until Ctrl-C
analysis/game-proxy.sh --policy traffic/examples/audit-game.json
.venv/bin/python -m traffic proxy-report captures/proxy-<stamp>.jsonl
.venv/bin/python -m traffic proxy-decode captures/proxy-<stamp>.jsonl   # again, with newer decoders
```

- **What is taken.** Every Wine program of `~/.wine-nexon` is moved into a user
  scope as it starts (already-running ones too). All its IPv4 TCP, any port,
  goes through the proxy; TCP to ports 8400-8999 from anything too. Every other
  packet of the scope (UDP, QUIC, ICMP, IPv6) goes to
  `captures/proxy-<stamp>-other.pcap` (`traffic ingest --pcap` reads it).
  Loopback is local IPC and is not taken. Rules and scope are undone on exit.
- **What is recorded** in `captures/proxy-<stamp>.jsonl` (mode 0600; it holds
  login tokens and hardware ids): `connection_open` (real destination, local
  program), `data` (exact bytes, each direction, nanosecond time), `handshake`,
  `opcode_table`, `message` (one decrypted message, either direction: real
  opcode, name if known, body), `tls_client_hello` (server name),
  `decode_notice`, `connection_close`.
- **Decoding** (`traffic/stream.py`, from the client's own code; see
  [`docs/guides/PROTOCOL.md`](docs/guides/PROTOCOL.md)): keys from the
  handshake, AES-OFB in 1456/1460-byte blocks for client messages and login
  replies, `iv[0]` subtraction for channel replies, client opcodes through the
  connection's DES-encrypted opcode table. Checked on six full connections:
  every frame both ways; 53/53 SendPacket bodies; 28/28 table positions.
- **Names** (`traffic/protocol.py`): 65 message types with their evidence,
  89% of all messages in a scraper session. Unnamed messages keep their opcode
  and bytes.
- **Control** is per connection: a matching `drop` refuses it. Message rules
  (opcode, size, raw bytes) are evaluated and recorded with
  `"enforced": false`: removing one frame breaks the IV chain. Use the
  in-process filter below to drop single messages.
- **Not decrypted:** TLS/QUIC (needs a certificate the game trusts) and the
  raw TCP 47611/58880 protocols.

Live game capture and pre-send blocking (note: the game reports the CPU's
debug registers to the server every ~10 s, message C 0x9c in
[`docs/guides/PROTOCOL.md`](docs/guides/PROTOCOL.md), so the hardware
breakpoints this observer sets are visible to Nexon):

```bash
analysis/capture-outgoing.sh 300 \
  --filter-policy traffic/examples/audit-game.json
```

Every evaluated `SendPacket` gets a logged decision; only an explicit `drop` rule
suppresses the packet. See [`traffic/README.md`](traffic/README.md) for the full
schema, source limits, decode rules and policy dimensions.

NGS/HTTPS tracking and blocking:

```bash
.venv/bin/mitmdump -s analysis/ngs-proxy.py \
  --set ngs_log=captures/ngs-raw.jsonl \
  --set ngs_policy=traffic/examples/audit-ngs.json
```

`analysis/launch-ngs-mitm.sh` starts the NGS control-plane proxy for a Wine
session. Its request-body cipher is device-bound and intentionally left opaque;
only exact bytes and metadata are recorded.

Passive pcap decryption:

```bash
.venv/bin/python analysis/wire-session-decrypt.py captures/game.pcap
```

## Scope limits

- A pcap records packets, not application intent; a dropped or filtered packet
  has no wire frame. Gaps are reported, never zero-filled.
- Transport decryption requires a unique IV seed from two consecutive frame
  headers; otherwise ciphertext is preserved and labelled ambiguous.
- NGS client→server bodies are device-bound ciphertext; server→client responses
  are decoded.
- TLS application data is opaque unless a proxy or TLS plaintext source supplies
  it.
- In-process registers, constructors and stacks exist only while the ptrace
  observer is attached.
- `analysis/` and the live hooks use build-specific RVAs in
  `foundations/profile.json`. If the client build changes, re-derive and validate
  them before use.

The packet guide in [`docs/guides/PACKETS.md`](docs/guides/PACKETS.md) preserves
the source repository's evidence line numbers. Some experimental capture
wrappers it mentions are not part of this communication-only port.

## Authorization

Use only on your own client/account or an isolated research environment you are
authorized to inspect. Captures can contain credentials, tokens, private traffic
and memory; keep them in the Git-ignored `captures/` directory.
