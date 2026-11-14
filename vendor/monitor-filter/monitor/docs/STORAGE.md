# Session storage and cross-PC workflow

Raw JSONL is the archival source of truth. A session bundle is immutable after finalization. Manifests are authoritative; catalogs and reports are rebuildable.

## Bundle layout

```text
sessions/
  2026/10/28/
    20261028T124255Z__vm-win11-01__login__iter01__a1b2c3d4/
      manifest.json
      environment.json
      notes.md
      events.jsonl
      events.jsonl.1
      events.pcapng
      events.pcapng.1
      summary.json
      coverage.json
      sensor-usage.json
      derived/
        census.json
      checksums.json
      bundle.sha256
```

`events.pcapng[.N]` (Linux, packet capture: docs/LINUX.md) holds the client's packets; each part is chained into the log by a `packet_capture_part` record with its SHA-256, first and last time, and listed in `checksums.json`. Parts rotate at the same size as the events parts but on their own byte count, so `events.pcapng.N` and `events.jsonl.N` are not paired. `redact_session.py` never copies it.

`manifest.json` carries the labels, client/build fingerprints, configuration, sensitivity, parts, record count, and chain head. `checksums.json` carries per-part SHA-256 and the bundle hash. `bundle.sha256` is a convenience copy.

## Workflow

1. Record to local disk:
   ```bat
   msmon-agent.exe --client "C:\Nexon\Library\maplestorycw" ^
       --log-dir "C:\msmon-sessions" --session-label "login-01" ^
       --scenario login --phase steady --iteration 1 ^
       --machine-label "vm-win11-01"
   ```
2. Stop the collector normally. The agent writes `summary.json`, `session_meta.json`, and (with the coverage build) `coverage.json`.
3. Finalize:
   ```bat
   python tools\session_pack.py "C:\msmon-sessions\<bundle>"
   ```
   This verifies the chain, writes census/environment/notes, validates the schema, and creates `<bundle>.zip`.
4. Explicitly copy/upload the zip or directory to the chosen shared store.
5. Re-run `python tools\validate_schema.py --session <bundle>` and, if needed, `python tools\verify_log.py <parts>` on the destination.
6. Compare sessions:
   ```bat
   python tools\compare_sessions.py <bundle-a> <bundle-b>
   ```
7. Build the optional local catalog when the number of sessions makes file scanning slow:
   ```bat
   python tools\index_sessions.py --root C:\msmon-sessions --db C:\msmon-sessions\catalog.sqlite
   ```
8. Create a redacted derived bundle for sharing:
   ```bat
   python tools\redact_session.py <bundle> --no-compress
   ```
   The raw bundle is never modified; the redacted copy gets a new chain and manifest.
   It drops each payload together with its `decoded_value`, the agent's plaintext
   copy of the same bytes (registry value or volume serial and label), and replaces
   WMI query text, DNS names, paths and command lines per the flags.

## Transfer policy

Bundles can contain registry values, hardware identifiers, paths, command lines, DNS names, and WMI query text. They are **not** uploaded automatically.

Linux bundles recorded with payload capture (the default) also hold every byte the client sent and received on its network sockets: login tokens, passwords and chat sent without encryption, server addresses, and interface and MAC data from netlink replies. The agent marks them `sensitivity=secrets` (`session_meta.json`, copied into the manifest); treat them like credentials. With payloads on, records of wineserver `get_window_text` also carry window titles (`text=`: character names, chat or other windows of the prefix). A bundle recorded with `--log-content` (any payload mode) also holds AF_UNIX and pipe bytes (X11, D-Bus, PulseAudio: the cookies clients send, clipboard and window contents a client exchanges, and the user's keystrokes: X11 key events, an input method's calls, a launcher's IPC with a typed password), DRM and socket ioctl structs (MAC addresses) and clipboard hashes, and is marked `sensitivity=secrets` too. So is a bundle recorded with `--log-environment` (every environment variable's value: a token the user exported) or `--log-real-input` (the user's keys passing wineserver and X11 requests), whatever the payload mode. `redact_session.py` drops the payloads, the DNS names and answers, the window titles, ioctl argument bytes and the content and clipboard hashes, withholds `process_environment` values but Wine's, the loader's and the graphics stack's (`NAME=withheld:<bytes>`, as without `--log-environment`) and the keys (`vkey=`, `scan=`, a keyboard message's `wparam=`/`lparam=` and window-probe arguments, an X11 key's `detail=`), and marks the copy `sensitivity=metadata`.

- Keep `sensitivity=payload` and `sensitivity=secrets` bundles in an access-controlled store.
- `--no-payloads` produces `sensitivity=metadata` (on Linux it also stops socket byte capture); prefer it for broad sharing.
- `events.pcapng[.N]` holds the client's packets with their full bytes (traffic in clear, credentials included): never share it; `--no-packets` or `--no-payloads` leaves it out.
- Never record directly into a live-synced folder. Finalize locally, then copy the immutable zip.
- Do not sync a writable catalog or a live event file between PCs.

### Optional shared stores

| Store | Use when |
|---|---|
| OneDrive/SharePoint folder | small total volume, one or two testers |
| S3-compatible (R2/B2/S3) via `rclone`/`aws s3 cp` | large/parallel workloads, long retention |
| git-annex/DVC | small fixtures only; not raw multi-GB sessions |

## Sizing

A measured session: 325,259 records, 241 MB, 119 seconds, ~740 B/record, peak 54,618 records/s. A 30-minute capture is roughly 3-5 GB raw and 300-600 MB compressed. Budget for the raw bundle plus one compressed copy.

## Retention

- Raw bundles: 90 days by default, configurable.
- Derived census/coverage/report: may be retained longer.
- Redacted bundles: separate derived copies; never replace the raw original.
- `sessions/` and `*.jsonl` are excluded from git.

## Integrity

- `verify_log.py` checks the record chain and payload chunking.
- `session_pack.py` runs it before writing the manifest.
- `checksums.json` records every part hash; `compare_sessions.py` re-verifies before comparing.
- Keep `checksums.json` (or the final `bundle.sha256`) separately if later tamper detection matters.
