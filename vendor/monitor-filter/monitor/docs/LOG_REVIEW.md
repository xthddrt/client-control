# Session log review

Review of a real capture: `analysis/outside-actions-v2.jsonl` (Kimi's filtered
extract of the 2026-10-28 session, `session_id 134336946412071800`). The raw
chained log and its final summary were not kept, so drop counters and coverage
records could not be checked. Numbers below were computed from the 325,259
records in the extract.

## Shape of the session

| Metric | Value |
|---|---|
| Wall clock | 12:42:55.687Z to 12:44:54.820Z, 119 s |
| Records in extract | 325,259 (241 MB, ~740 B/record) |
| Driver sequence reached | 479,535, so ~157,000 records were filtered out as inside-client |
| Average / peak rate | ~4,000/s average, **54,618 records in the second 12:43:04** |
| Sources | driver 322,437, etw 2,822 |
| Payload operations | 10,805, all complete; 4 multi-chunk (max 32,144 B) |

Top types: `file_read` 143,006, `registry_query` 118,745,
`file_query_information` 17,325, `registry_open` 14,456, `file_create` 10,673,
`file_cleanup` 9,606, `registry_enumerate` 3,529, `etw_rpc` 2,696,
`registry_set_value` 2,516.

Status: 216,351 success, 103,319 `STATUS_OBJECT_NAME_NOT_FOUND`, 2,093
`STATUS_BUFFER_OVERFLOW`, 1,258 `STATUS_PENDING`, 1,167 `STATUS_MORE_ENTRIES`,
573 path-not-found creates, 180 `STATUS_NO_MORE_ENTRIES`.

Flags: 100,230 records carried `payload_unavailable` (30.8% of the log) and
13,666 carried `missing_path` (7.4% of file events).

## What the client actually did

### 1. It reads other applications' executables, in full

`MapleStory.exe` (PID 5540) issued 142,562 of 143,006 read events and 587 MB of
reads in 119 s. Reads are 4 KiB IRPs walking whole files:

- `opencode-cli.exe`: 33,104 reads, offsets 0 to 246,919,560 in exact 4,096-byte
  steps (247 MB, the whole file).
- `OpenCode.exe` ~30k reads, `Kimi Code.exe` ~27k, `nexon_client.exe` ~19k, then
  GameBar, Xbox Game Bar widgets, Claude `cowork-svc.exe`, Defender `NisSrv.exe`,
  Chrome, Edge, Acer Care Center.

Sequential whole-file reads of unrelated running applications is image
fingerprinting, i.e. the client (or the anti-cheat injected into it) enumerating
what else is running by hashing other binaries. This is the most significant
outside-client behaviour in the capture and it is worth its own analysis pass;
`file_read` records currently dominate the log, which makes that hard.

### 2. It polls ~3,900 nonexistent UI window-position values

94,667 of the 103,319 name-not-found results are queries under
`\REGISTRY\USER\S-1-5-21-...-1001\Software\Wizet\MapleStoryClassic` for values
named `uiWndX<id>` / `uiWndY<id>`. Each distinct value was queried 24 times in
119 s (~5 s period), and almost none exist. That is a client-side loop that
saves/restores window positions for every window id it knows, whether or not the
value exists. It costs the client time and produced 29% of the log.

### 3. Anti-cheat attribution never fired

No record had a non-empty `component`, and no driver-sourced record was
`stack_resolved`; all 2,778 `stack_resolved` records are ETW. Either
`BlackCat64.sys` was not loaded during this session or the stack matcher never
matched. Also, `grap\NGService.exe` never appeared: the GRAP images in use are
`grap\grap-core64.aes` and `grap\grap-updater.aes`, which were tracked only
because they inherited scope from the game process. The hard-coded image list is
stale for this installation.

### 4. Data quality issues that were fixable in code

- 100,230 `payload_unavailable` records, of which ~2,100 are normal
  two-pass/enumeration protocol (`BUFFER_OVERFLOW`, `BUFFER_TOO_SMALL`,
  `MORE_ENTRIES`, `NO_MORE_ENTRIES`) mislabelled as failures. Five
  volume-information probes are in this group; the follow-up call logged the
  real serial.
- 13,666 file events had no path, concentrated in `file_query_information`
  (7,802 of 17,325, 45%) and `file_read` (4,995). The cache-only name lookup is
  the cause.
- `registry_set_value` appears twice per operation (pre-op input payload with
  `STATUS_PENDING`, post-op result), correlated only by `operation_id`.
- Volume serials repeat: 84 decoded records all report volume 3 as
  `0xa8c881b5`.
- The extract has no coverage, gap, drop or summary records, so an abrupt end
  (the session lasted 2 minutes) cannot be distinguished from a clean stop.

## Changes made after this review

- `driver/registry.c`: two-pass and enumeration-continuation statuses are logged
  as metadata, not as unavailable payloads.
- `driver/file_filter.c`: volume-information two-pass probes are logged as
  metadata; the generic pre-operation now uses
  `FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP`, so a cache miss may resolve
  through the file system when the filter manager considers it safe.
- `agent/agent.cpp`: a `driver_statistics` coverage record every 30 s with
  queue, queue-bytes, drop and tracked-process counters, so a session that dies
  still shows pressure and loss.

Volume-information capture was verified to have worked in this capture (100
payloads, 84 decoded serials), so the review of that path is about safety, not
lost data.

## Recommended next (not implemented)

Ordered by value for the next capture:

1. **Coalesce sequential reads.** One record per (file, direction, window) with
   `records`, `bytes`, `first_offset`, `last_offset`, `sequential` would replace
   ~140,000 records with a few hundred and still show that 247 MB of
   `opencode-cli.exe` was read. Keep `sequence_first`/`sequence_last` and a
   folded-count in the record so `verify_log.py` can account for the removed
   sequence numbers. Do it in the agent, where a bug cannot bugcheck the host.
2. **Trim default fields.** `"modules":[]`, `"component":""`, `"detail":""`,
   `"target_process_id":0`, `"parent_process_id":0` and friends are emitted on
   every record. Omitting empty/default members cuts roughly a quarter to a
   third of the bytes, which directly reduces queue pressure and log size.
3. **Aggregate repeated registry probes.** A per-(pid, key, value, status)
   counter flushed every few seconds would turn the 94,667 window-position
   probes into a handful of records without losing the finding.
4. **Merge set-value pairs** by `operation_id` in the agent, and memoise volume
   serials per volume.
5. **Size the queue for the observed burst.** 16,384 records / 64 MiB holds
   about 0.3 s at 54k events/s. Either cut volume first (1 and 3) or capture with
   `--queue-records 32768 --queue-mb 128`, and always keep the new periodic
   statistics records.
6. **Validate BlackCat attribution** on a run where `BlackCat64.sys` is loaded:
   confirm the `blackcat_loaded` coverage record appears, that a known
   BlackCat-originated operation is labelled, and keep coverage records in
   derived extracts.
7. **Update the image list** to the GRAP names actually in use
   (`grap-core64.aes`, `grap-updater.aes`) and document that `.aes` images are
   PE payloads, not data files.
8. **Split verbosity per event class** (`--file-read=off|aggregate|all`), so a
   question about registry or network behaviour does not pay for 143,000 read
   records.

## Identity evidence after every run

Append the session's identity-relevant events and the complete current risk-rule table:

```bat
python tools\analysis\identity_log.py --bundle <session-bundle> --policy ..\filter\policy\default-policy.txt --out ..\filter\policy\identity-log.md
```

The tool reads the session bundle, including KFilter RISK decisions; it does not compete with the collector for KFilter's destructive event ring.
