# Log schema (v1)

This is the human-readable contract for `events.jsonl`, the session bundle, and the derived files. The machine-readable form is `schema/event-v1.json` plus `schema/session-v1.json`, `schema/checksums-v1.json`, and `schema/sensor-usage-v1.json`. `tools/validate_schema.py` implements the documented subset of JSON Schema used here.

The raw JSONL chain is authoritative. Manifest, catalog, reports, and redacted bundles are derived.

## 1. Record envelope

Every line is one JSON object. Telemetry records carry the common fields below; chained `observer_sequence_gap` and `observer_summary` records carry only `type`, `record_index`, `chain`, and their control/summary fields.

| Field | Meaning |
|---|---|
| `protocol` | Binary/event protocol version (currently 4). |
| `schema_version` | JSON schema version (1). |
| `source` | `driver`, `etw`, or `agent`. |
| `sequence` | Per-source sequence. Gaps are reported as `observer_sequence_gap`. |
| `timestamp` | UTC string decoded from FILETIME. |
| `session_id` | Random 64-bit numeric session ID (binary field). |
| `type` / `type_id` | Event name and numeric ID. |
| `process_id`, `process_start_time`, `process_path` | Requesting process identity. |
| `parent_process_id`, `thread_id` | Parent and thread identity. |
| `target_process_id`, `target_process_start_time` | Handle/network target identity. |
| `flags` / `flags_names` | Bitmask and decoded names. |
| `status` / `status_name` / `status_hex` | NTSTATUS value, decoded name, hex. |
| `desired_access` / `desired_access_hex` | Access mask and hex. |
| `category` | `unknown`, `client_data`, `windows_runtime`, `external_process`, `browser_interaction`, `hardware_identity`, `user_data`, `registry`, `network`, `ipc`. |
| `outside_client` | Classification heuristic, not proof: true for every record whose category is not `client_data` (the target is outside the client's own files), including the client's own reads of system files. It says nothing about which process acted. |
| `attribution` | `unknown`, `process_only`, `stack_resolved`, `service_correlated`, `static_evidence`. |
| `value0`, `value1` | Type-specific integers (below). |
| `operation_id` | Links payload chunks. |
| `text`, `detail`, `component` | Type-specific strings, detail fields, resolved component. |
| `modules` | Resolved image paths in stack order, innermost first, deduplicated (up to 8). Linux: a Wine thread's syscall records list the PE (Windows-side) frames before the unix frames (`pe_frames=N` in `detail`, see docs/LINUX.md "PE frames"). |
| `payload` | Optional Base64 chunk (below). |
| `payload_unavailable` | Payload could not be captured safely, or (reason `query_failed` first in the detail, as the Windows driver writes it) the value query itself failed, so there was no value to capture. |
| `record_index` | Writer order across rotated parts. |
| `chain` | SHA-256 chain over the previous chain and this record without `chain`. |

The session UUID is **not** repeated on every line. It lives in `manifest.json` and the `session_context` coverage record; join via `session_id`.

## 2. Event types

### Process, thread, image

| ID | Type | `text` | `detail` | `value0` / `value1` |
|---|---|---|---|---|
| 1 | `process_start` | image path | command line | start time |
| 2 | `process_exit` | — | — | start time |
| 3 | `thread_start` | — | — | — |
| 4 | `thread_exit` | — | — | — |
| 5 | `image_load` | image path | — | base address / size (Linux: one record per PE load, base = its header mapping, size = `SizeOfImage`) |
| 6 | `process_handle` | target image | — | operation / granted access |
| 7 | `thread_handle` | target image | — | operation / granted access |

A `process_start` whose `status` is not 0 did not start a live image: on Windows another driver (kfilter) refused the creation (`CreationStatus`, e.g. `STATUS_ACCESS_DENIED`; only a refusal by a driver called before msmon is visible); on Linux the exec failed (`exec_failed` in `detail`). The agent does not track it as a running process.

### Files and devices

`text` is the NT path unless missing. `status` is the operation result.

| ID | Type | `value0` | `value1` |
|---|---|---|---|
| 10 | `file_create` | create options | returned information |
| 11 | `file_read` | length | byte offset |
| 12 | `file_write` | length | byte offset |
| 13 | `file_set_information` | information class | — |
| 14 | `file_directory_control` | information class | minor function |
| 15 | `file_cleanup` | — | — |
| 16 | `file_device_control` | IOCTL code | input length |
| 17 | `file_system_control` | FSCTL code | input length |
| 18 | `file_query_volume_information` | information class | — |
| 19 | `file_query_information` | information class | — |
| 34 | `file_section` | sync type | page protection |
| 35 | `file_close` | — | — |
| 36 | `file_flush` | — | — |
| 37 | `file_query_security` | security information mask | — |
| 38 | `file_set_security` | security information mask | — |
| 39 | `file_query_ea` | — | — |
| 40 | `file_set_ea` | — | — |

Volume information may carry a `volume_information` payload. File contents and per-page mapped I/O are not captured.

### Registry

`text` is the key path; `detail` is the value name when available.

| ID | Type | `value0` | `value1` |
|---|---|---|---|
| 20 | `registry_open` | — | — |
| 21 | `registry_create` | — | — |
| 22 | `registry_set_value` | data size | value type |
| 23 | `registry_delete` | — | — |
| 24 | `registry_rename` | — | — |
| 25 | `registry_query` | value index/class | value type |
| 26 | `registry_enumerate` | index/class | value type |

Set/query values may carry a `registry_value` payload. Enumerated names come from the post-operation result where the layout is known. On Linux registry_* come from wineserver requests (docs/LINUX.md "Wineserver requests").

### Network

| ID | Type | `text` | `detail` | `value0` / `value1` |
|---|---|---|---|---|
| 30 | `network_connect` | endpoints | protocol/local/remote | flow ID / packed ports |
| 31 | `network_accept` | endpoints | protocol/local/remote | flow ID / packed ports |
| 32 | `network_flow_established` | endpoints | protocol/local/remote | flow ID / packed ports |
| 33 | `network_flow_close` | endpoints | protocol/local/remote | flow ID / packed ports |

No TLS plaintext. On Linux (docs/LINUX.md "Kernel sensor upgrades"): socket bytes are `network_data`
payloads on the I/O records, DNS names are `etw_dns`, TCP lifecycle is `etw_tcp`, the client's packets
go to `events.pcapng`, and a connection wineserver made for a Wine process is attributed to that process
by `network_flow_established`/`network_flow_close` records flagged `service_correlated`.

### ETW

| ID | Type | `text` | `detail` | `value0` / `value1` |
|---|---|---|---|---|
| 100 | `etw_wmi` | namespace/provider | operation/query/language | provider event ID / operation ID |
| 101 | `etw_dns` | query name | query type/options; Linux: `query_type`, `dns_id`, `rcode`, `answers`, `transport`, `server` | provider event ID; Linux: 3006 query sent, 3008 response received (`operation_id` = the payload parsed) |
| 102 | `etw_rpc` | endpoint/protocol | service/interface, operation/method, raw interface UUID and opnum | provider event ID |
| 103 | `etw_unattributed` | provider name | reason/event ID/PID | original type / original event ID |
| 104 | `etw_tcp` | endpoints | connection event and reason | provider event ID / TCB pointer (Linux: socket cookie; event ID 0 for `state_change` and `retransmit`, see `docs/LINUX.md`) |
| 105 | `etw_code_integrity` | blocked or audited image path | `would_block` or `blocked`, event/policy metadata | CodeIntegrity event ID (3076/3077) |

WMI query text is preserved in full-payload mode; `--no-payloads` sanitizes it. Result rows are unavailable. CodeIntegrity events are system-wide and do not establish client causality. `--no-etw` disables them with the other ETW sensors.

### Enforcement integrations

| ID | Type | Source/component | Fields |
|---|---|---|---|
| 120 | `kfilter_decision` | `agent` / `kfilter.sys` | `text` is the decision's object (path, registry key, endpoint; for a message the direction, endpoint, `socket:[inode]`, position and first bytes). `process_id` is the program kfilter decided for (under Wine the client a broker worked for); `process_start_time` is filled when msmon tracks that process incarnation (0 otherwise). `value0` is the target ID, `value1` the rule ID, `desired_access` kfilter's `Value`. `detail` is described below. |

`kfilter_decision` `detail` (checked by `schema/event-v1.json`). The first keys come in this order:

| Key | Meaning |
|---|---|
| `action` | `allow`, `deny` (enforced), `would_deny` (audit mode: denied once the policy is in block mode), `audit` (an audit rule matched) or `risk` (a rule with `risk=` was used; an extra record beside the decision) |
| `layer` | `message` (a per-message decision), `process_create`, otherwise the target |
| `target` | `file`, `dir`, `registry`, `process`, `volume`, `device`, `pipe`, `network`, `handle`, `launch`, `open`, `thread-handle`, `thread-open` |
| `rule_id` | kfilter's stable rule ID (non-network rules are numbered 1, 2, ... in policy order; network rules from 10001); 0: no rule matched (the default decided) |
| `rights` + `rights_names` / `access` / `port` / `ioctl` / `bytes` | the requested rights (hex, then kfilterctl's names); `access=`: a Windows access mask (hex) on `handle`/`open`/`thread-*` targets and on `process` decisions that are not process starts (handle crossings, refusal codes, exec checks); `port=`: a network decision's remote port (a `risk` network record carries `rights`); a device decision's IOCTL; or a message's byte count |
| `image` | file name of the program that made the request (under Wine its Windows image, e.g. `MapleStory.exe`), with `%`, `;` and `=` percent-encoded (`%25`, `%3B`, `%3D`); empty when unknown |
| `pid` | kfilter's process ID (the same as `process_id`) |
| `brokered` | 1: a broker (wineserver, winedevice) did it on the client's behalf and it was decided as the client's (Linux) |
| `repeat` or `generation` | `repeat=N`: a summary of N identical decisions collapsed within a second; otherwise `generation=` the policy generation that decided |

Then `decision` (same as `action`, kept for older readers), `kfilter_action` (kfilter's raw action: `audit`, `allow`, `deny`, `RISK`), `target_id`, `action_id`, `flags` (hex) and `flags_names` (`|`-separated: `would_deny`, `name_failure`, `missing_context`, `network`, `process_create`, `memory_read`, `memory_dup`, `counted`, `repeat`, `exhausted`, `risk`, `brokered`, `message`). `rule=` is always last and runs to the end of `detail` (it may hold `;`): the rule's text as kfilterctl prints it (`deny file C:\... rights=read image=... uses=1 phase=1`, `allow network 10.0.0.0/8 tcp port=443 rights=connect`), taken from the policy (GET_CONFIG) of the generation that decided; empty when unknown.

KFilter status coverage records (`kfilter_status`) include mode, rule counts, generation, session tag, counters, and dropped-event deltas. They are written at the start, at the end, and every 30 seconds in between when kfilter's dropped-event count or session tag changed (`session_changed=1`: kfilter restarted, its counters started over). `rule_text=unavailable` on the first one means the policy could not be read, so `rule=` stays empty. A `kfilter_family_tracked` coverage record (`pid`, `process_start_time`, `path`) names a process msmon started tracking because kfilter decided for it (the protected family can live outside the client root). The agent drains kfilter's decision ring until it is empty on every pass (at most four ring capacities per pass); the ring is single-consumer, so `kfilterctl watch` and `kfilterctl clear` must not run during a session. A KFilter denial can precede and prevent the monitor's native post-operation callback, so a paired native failure record is not guaranteed.

### Coverage

| ID | Type | Meaning |
|---|---|---|
| 110 | `coverage` | `text` is the record name (`session_context`, `coverage_manifest`, `session_start`, `etw_accounting`, etc.); `detail` is `key=value` fields or a message. |
| 111 | `coverage_usage` | Driver and agent sensor counters (Phase 3). |

Linux also writes what a tracked process went through but did not decide as observer (`0x20`) coverage records of it, never as its own `process_handle` (whose `process_id` is always the actor): `self_signal` (its own fault signals; value0 the fault address, value1 the signal) and `outside_access` (an untracked process's ptrace access check on it: `process_id` the tracked target, `target_process_id` the outside actor, `actor_exe=` its executable), each with its `repeats_tail` summaries (docs/LINUX.md "Kernel events"); `x11_display` and `process_environment` are of this kind too.

## 3. Flags

| Bit | Name | Meaning |
|---|---|---|
| 0x00000001 | `explicit_track` | Registered explicitly or by image match. |
| 0x00000002 | `inherited_track` | Child of a tracked process. |
| 0x00000004 | `truncated_path` | Path was truncated. |
| 0x00000008 | `missing_path` | Name unavailable at this IRQL/context. |
| 0x00000010 | `service_correlated` | ETW client PID differs from the native service; on Linux, a `network_flow_established`/`network_flow_close` for the process using a socket another tracked process (wineserver) made (docs/LINUX.md "Socket join"). |
| 0x00000020 | `observer_record` | Agent/ETW record. |
| 0x00000040 | `payload_present` | Payload chunk follows. |
| 0x00000080 | `payload_unavailable` | Payload could not be captured. |
| 0x00000100 | `payload_final_chunk` | Final chunk of an operation. |
| 0x00000200 | `payload_input` | Captured input (e.g., set-value). |
| 0x00000400 | `payload_partial` | More bytes exist than this chunk. |
| 0x00000800 | `truncated_detail` | Linux: the detail was cut at the record's string limit (1024 characters, 768 with a payload chunk). |

## 4. Payloads

Payloads are Base64, chunked at 8 KiB. Fields: `kind`, `encoding`, `data`, `operation_id`, `total_bytes`, `byte_offset`, `chunk_index`, `chunk_count`, `final_chunk`. Kinds: `registry_value`, `volume_information`, `network_data`, `ipc_data` (Linux: a Wine named pipe or device read/write, an RPC request stub), `tls_plaintext` (Linux: the plaintext of one GnuTLS record call of Wine's schannel, on a `tls:session=` record). Values above the 8-MiB protocol limit are marked unavailable; values above 64 KiB are partial.

`network_data` (Linux) is what one send/receive call moved on a network socket (with `--log-content`, on an AF_UNIX socket or a pipe too): `total_bytes` is the call's result (one message of `sendmmsg`/`recvmmsg`, `msg=N` in the detail), each chunk record repeats the call's I/O record, and `payload_input` marks sent bytes. At most 1 MiB is captured per call; a partial series holds whole 8 KiB chunks only and its detail has `payload_missing=<bytes>;payload_stop=limit|ring_full|fault|steps|truncated|chunks_lost|content_cap` (`content_cap`: an AF_UNIX or pipe message past its first 8 KiB, whose captured bytes the record's `content_bytes=;content_sha256=` cover). A call with no captured chunk is one record with `payload_unavailable` and its reason first in the detail; `sendmmsg`/`recvmmsg` messages after the capture stopped get one such record with `msg_missing=<first>-<last>`.

Reconstruct by grouping `operation_id`, sorting `byte_offset`, and concatenating `data` until `total_bytes` is reached. A complete operation has contiguous chunks from 0 to `chunk_count - 1`.

## 5. Session labels

| Field | Values |
|---|---|
| `session_uuid` | Random 128-bit UUID string (manifest/context only). |
| `session_id` | Random 64-bit numeric binary session ID. |
| `session_label` | Operator label, sanitized. |
| `test_id` | Unique directory/test label. |
| `scenario` | `startup`, `login`, `gameplay`, `cash_shop`, `file_io`, `registry`, `wmi`, `dns`, `rpc`, `network`, `ipc`, `idle`, `shutdown`, `mixed`, `other`. |
| `phase` | `startup`, `steady`, `shutdown`. |
| `outcome` | `completed`, `agent_stopped`, `agent_killed`, `driver_stopped`, `crash`, `timeout`, `unknown`. Packer maps `in_progress` to `incomplete`. |
| `machine_label` | Operator/host name, sanitized. |
| `machine_id_hash` | SHA-256 of MachineGuid + system volume serial (raw values never stored). |
| `sensitivity` | `metadata`, `payload`, `secrets`. |

## 6. Compatibility and legacy

- Telemetry `schema_version` is 1. Records without it are legacy v4 logs; `validate_schema.py --allow-legacy` skips them. Observer control/summary records are part of schema v1 without carrying the full telemetry envelope.
- Existing fields are preserved. New fields are additive.
- The binary event header is unchanged: `session_id` stays 64-bit.
- The event identity is `(session_uuid, source, sequence)`.

## 7. Known blind spots

Per-page mapped I/O, file/pipe/mailslot payloads, memory/APC/remote-thread operations, UI/clipboard/input, direct hardware/firmware APIs, broker/COM/DPAPI correlation, TLS plaintext, pre-start activity, and events lost under overload. A zero event count is not proof that an operation did not happen.

## 8. Derived files

- `manifest.json` — labels, client/build fingerprints, configuration, sensitivity, parts, record count, chain head (`schema/session-v1.json`).
- `checksums.json` — per-part SHA-256, chain head, bundle hash (`schema/checksums-v1.json`).
- `coverage.json` — driver per-type/per-sensor counters and agent ETW/writer counters (`schema/coverage-v1.json`).
- `sensor-usage.json` — activity/health/verification per sensor (`schema/sensor-usage-v1.json`).
- `derived/census.json` — event/source/category/status/process counts.
- `environment.json`, `notes.md` — context for the session.
- `scenario_results.json` — expected/observed/failing/unexpected fixture results.

All of these are derived from the raw chain and may be rebuilt. `manifest.json` and `checksums.json` are the bundle's integrity source of truth.
