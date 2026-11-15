# Controlled client/server proxy and decode workflow

## What is built

`analysis/controlled-proxy.py` and `analysis/launch-controlled-proxy.sh` provide a standalone, process-selective controlled proxy inside `client-control`. They use the repository's pinned mitmproxy and existing transport/policy helpers; no sibling `monitor-filter` checkout is used.

The default process list covers MapleStory, known Nexon/GRAP helpers, and native Python processes used by MapleMarket:

```text
MapleStory.exe, grap-core64.aes, grap-communicator64.aes,
nexon_client.exe, nexon_launcher.exe, nexon_runtime.exe, NGService.exe,
python, python3
```

`CONTROLLED_PROCESSES` replaces that comma-separated list when a live run discovers a differently named helper. This is **selected-process coverage**, not proof of every process, kernel path, or uninstrumented protocol. The first MapleMarket run must confirm which processes actually matched.

Default behavior is **forward unchanged**. The launcher does not enable generic GRAP neutralization, screenshot filtering, or request dropping unless explicitly requested.

## Start for MapleMarket

Prerequisites are the pinned `.venv`, sudo access for the local redirector, and the existing mitmproxy CA. The launcher copies the CA certificate to `C:\mitm-ca.pem` in the existing Wine prefix.

Start the controlled proxy without launching anything else:

```bash
analysis/launch-controlled-proxy.sh
```

The output includes a session directory such as `captures/controlled-YYYYMMDD-HHMMSS/`. In the terminal that will run MapleMarket:

```bash
source /home/bob/Downloads/client-control/captures/controlled-YYYYMMDD-HHMMSS/env.sh
```

Then use the normal MapleMarket command. On this installation, its entry point is `/home/bob/Downloads/MapleMarket/task_runner.py`; use the existing arguments for the current scraping job rather than inventing a new route.

The proxy can also run the command itself:

```bash
analysis/launch-controlled-proxy.sh -- <normal MapleMarket command and arguments>
```

The tool does **not** change `DISPLAY`, `WAYLAND_DISPLAY`, or other display configuration. `env.sh` supplies the CA bundle and unsets explicit HTTP-proxy variables because local redirection is used instead. It does not launch, restart, or close the game automatically.

The local redirector was started and stopped successfully using a deliberately nonexistent process name. Actual MapleMarket process matching and live traffic coverage remain to be tested.

## Evidence recorded

HTTP and HTTPS request/response events include exact application bodies, redacted sensitive headers, process attribution, endpoints, and ordered policy decisions. Original TLS records and HTTP framing still require packet/socket evidence.

Raw TCP events include:

- session, process, local endpoint, and original destination;
- direction, exact stream offset, and chunk index;
- exact bytes as Base64 plus SHA-256;
- forwarding status, with no claim of server receipt;
- contributing chunk identities for each reconstructed frame.

UDP events retain exact datagram boundaries, direction, endpoints, process, and hashes. Unknown UDP protocols remain unknown. DNS fields are decoded only with supporting structural/port evidence.

At TCP flow end or proxy shutdown, complete contiguous streams are passed to conservative TLS, HTTP, and MapleStory decoders. MapleStory client→server messages use the existing header framing, IV synchronization, and field decoders. Split and combined TCP input is reconstructed; retransmissions are not additional proxy stream bytes. Unknown aliases, incomplete frames, and cipher failures remain marked.

The current TCP decode window is 32 MiB per direction. Raw chunks continue to be logged beyond that window; the decode record explicitly marks truncation. Live raw chunks are recorded immediately, while complete-stream decoding currently occurs at flow end or shutdown rather than claiming real-time field visibility.

`flows.mitm` retains the proxy's native HTTP/TCP/UDP flows. `events.jsonl` is the structured evidence stream. Both are private local captures and can contain credentials or other sensitive content.

## Client-to-server decode trial

Every nonempty `x-*.ngs.nexon.com` client request receives a `client_decode` record. The tool tests the known response algorithm without assuming it applies:

- `decrypted`: gzip-validated plaintext recovered, with exact `plaintext_base64`;
- `decrypted_non_json`: plaintext recovered, but JSON parsing failed;
- `undecoded`: the algorithm failed, with the error retained;
- `empty`: no request body was present.

A successful JSON decode also supplies `decoded_request` and permits field-scoped policy matching under `payload`. A failure does not become a fabricated message type or field. A synthetic success proves the tool path, **not** that real NGS client requests use the response cipher. Their real request/attestation cipher remains unresolved until a live result or origination trace proves otherwise.

Non-NGS HTTP responses are logged but are not passed through the NGS response decoder. This preserves MapleMarket's native HTTP traffic without assigning it NGS semantics.

## Filtering boundaries

HTTP requests and decoded fields can use the existing ordered `TRAFFIC_POLICY` engine. The existing `NGS_SCREENSHOT_FILTER=1` option still performs the separate, scoped `x-config/v1` response rewrite. For this controlled launcher, `NGS_NEUTRALIZE` defaults to `false`.

Raw TCP/UDP connection-level policy is evaluated at flow start. Decoded raw TCP messages and UDP datagrams currently record **post-forward policy observations** with `applied: false`; the proxy does not pretend that a late decode can retract a transmission. It also does not simulate a UDP drop by sending an empty datagram.

For MapleStory opcode/field suppression before transmission, continue using the existing constructor hook after the game is running:

```bash
analysis/capture-outgoing.sh 300 --policy /path/to/policy.json
```

Do not run a second ptrace observer over the same target concurrently. The proxy and constructor traces are complementary evidence sources; unknown destinations at `SendPacket` remain unavailable until linked to socket/proxy evidence.

## Build the ordered record

The proxy event log can be supplied to the existing ledger along with packet, socket-monitor, and constructor evidence:

```bash
python3 analysis/traffic-ledger.py build captures/controlled-ledger \
  --ngs captures/controlled-YYYYMMDD-HHMMSS/events.jsonl \
  --msmon /path/to/session-or.zip \
  --pcap captures/outgoing-session-YYYYMMDD-HHMMSS.pcap \
  --trace captures/outgoing-events-YYYYMMDD-HHMMSS.jsonl
python3 analysis/traffic-ledger.py verify captures/controlled-ledger
```

TCP stream chunks become socket-operation records. Decoded frames become linked message records with their contributing chunk identities and times. UDP datagrams retain their exact boundaries. Raw proxy policy observations remain marked `applied: false`; captured live decisions retain their actual stage/application state.

## Local verification

Run the real local proxy verifier:

```bash
.venv/bin/python analysis/verify-controlled-proxy.py \
  captures/controlled-proxy-reproduction.json
```

It starts real mitmproxy listeners and loopback servers, never Nexon. It verifies:

- split and combined MapleStory client→server frames;
- exact raw TCP forwarding and a returned reply;
- exact UDP datagram forwarding, including unknown-protocol preservation;
- successful synthetic client-request decoding and an explicitly failed trial;
- non-NGS HTTP response preservation;
- native mitmproxy HTTP/TCP/UDP flow records;
- ordered-ledger raw bytes, decoded fields, links, and policy stages.

Saved evidence: [20261115-controlled-proxy-offline.json](../../../evidence/outgoing/20261115-controlled-proxy-offline.json).

Additional checks:

```bash
.venv/bin/python analysis/ngs-mitm.py --self-test
.venv/bin/python analysis/ngs-proxy.py --self-test
.venv/bin/python analysis/traffic-ledger.py self-test
bash -n analysis/launch-controlled-proxy.sh
```

No live MapleMarket, MapleStory, or Nexon result is claimed from these local fixtures. The next meaningful test is a MapleMarket session through the controlled proxy, followed by inspection of actual process matches, request decode statuses, raw stream completeness, and unknown fields.
