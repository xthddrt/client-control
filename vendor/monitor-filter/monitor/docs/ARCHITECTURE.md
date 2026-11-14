# Architecture and coverage

## Data path

Protocol v4 uses self-delimiting `MSMON_EVENT_HEADER` records with bounded UTF-16 metadata, an optional source component, and optional raw payloads. Each text field is capped at 2,048 bytes, each record at 16,384 bytes, and each payload chunk at 8,192 bytes. Payload records include an operation ID, total byte length, byte offset, and chunk index/count. The collector validates all sizes, offsets, versions, session IDs, string/payload bounds, and source sequences.

The driver assigns session, source-sequence, and operation IDs and queues records in a bounded nonpaged list. Defaults are 16,384 records and 64 MiB, with maxima of 32,768 records and 128 MiB. The collector drains up to 1 MiB per IOCTL. ETW uses a separate bounded queue and source sequence. Allocation failure, event-context failure, or a full queue advances the source sequence and increments drop counters; missing chunks make payload operations incomplete. On Ctrl+C, the collector stops new driver tracking and drains the remaining queue before final statistics. This is not lossless capture.

A single agent writer assigns consecutive record indexes and chains every JSON object with SHA-256. Rotated files continue the chain. Payloads are Base64 encoded, and complete operations can be reconstructed in chunk order. Friendly decodings are provided only when the entire value is present in one chunk. The chain detects later modification only when the trusted final hash is retained separately.

The agent writes an immutable session bundle when `--log-dir` is used: events, summary, coverage, metadata, environment, notes, a manifest of parts/hashes, and checksums. The session UUID is separate from the 64-bit binary session ID; event identity is `(session_uuid, source, sequence)`. The field dictionary is `docs/LOG_SCHEMA.md`; bundle/transfer rules are `docs/STORAGE.md`.

The driver exposes `MSMON_IOCTL_COVERAGE` with per-event-type attempted/dropped counters, per-callback entered/logged counters, skip reasons, and registration status for each init call. The agent writes `coverage.json` and a chained `coverage_usage` record. This is execution evidence, not proof of correctness; `docs/COVERAGE.md` defines the activity/health/verification model.

## Process scope and identity

The collector translates the configured DOS **scope root** to an NT device path. `--client` names the installation/classification root; if the executable is in an `appdata` child, the agent auto-detects that child as the scope root. `--scope-root` overrides it explicitly. The driver tracks any executable image beneath the scope root, not a hard-coded filename list; this includes PE payloads with non-`.exe` extensions such as the GRAP `.aes` images. Up to three extra roots (`--extra-root`) are tracked the same way; by default the agent adds `%ProgramData%\Nexon\NGS`, where the NGS security service runs after the service control manager starts it, outside the client scope and process tree. Children of tracked processes inherit tracking, including processes created while BlackCat is on the stack. At startup, the collector resolves full image paths and creation times, then registers matching processes and descendants iteratively. Explicit `--pid` scope is separate. PID + creation time is the intended process key; PID-only metadata still has weaker identity during PID reuse.

Root configuration and registration use a passive-level mutex. Event-time process lookups use a spin lock and bounded nonpaged entries. Basename matching alone is not treated as publisher identity, and no Authenticode claim is made for the modified private-server installation.

## Event sources

### Object access

`ObRegisterCallbacks` observes process and thread handle creation/duplication for tracked source processes. Events include target PID, target creation time/image where available, original desired access, granted access, and completion status. A handle-open event does not prove a later `ReadProcessMemory`, and handles opened before monitoring or through protected/brokered paths may be missed. No access bits are stripped.

### Files and devices

The minifilter logs create results and uses pre-operation cached name references for post-operation read/write, query/set information, directory control, cleanup/close, flush, query/set security, query/set EA, section acquisition, file-system control, device control, and volume-information results. Cache-only lookup avoids unsafe filesystem name queries; missing cache entries produce `MsMonFlagMissingPath`.

Named-pipe and mailslot creates are covered: the filter registers `FLTFL_REGISTRATION_SUPPORT_NPFS_MSFS` and the NPFS/MSFS create callbacks, and classifies `\Device\NamedPipe` and `\Device\Mailslot` paths as IPC. Read/write events on those handles are also seen. Pipe/mailslot contents are not captured. Section acquisition records the sync type and page protection, but per-page mapped reads/writes and paging I/O remain outside coverage. Arbitrary non-filesystem device IOCTLs are not all visible to a minifilter.

For `FileFsVolumeInformation`, the driver uses Filter Manager buffer decoding/locking at APC_LEVEL or below. It records the raw returned buffer when valid and the collector decodes `FILE_FS_VOLUME_INFORMATION`, including the exact volume serial number, creation time, and label. Failed queries, invalid lengths, and unsafe-IRQL cases produce `payload_unavailable` instead of unsafe access or fabricated values.

### Registry

Pre-operation callbacks copy bounded key/value metadata into nonpaged call contexts. Set-value input bytes are captured during their valid pre-operation window and linked to final status through an operation ID. Post-operation callbacks emit actual status and free contexts.

Successful value queries and enumeration support Partial, Full, Align64, and multi-value layouts with checked offsets and lengths. Common key/value enumeration layouts also retain the returned names. Value bytes and types are retained up to 64 KiB; larger values are explicitly partial, and values above the 8-MiB protocol limit are marked unavailable. Failed, partial, unsupported, or unsafe results are marked unavailable rather than read beyond valid output. The collector adds friendly decoding for common string, multi-string, DWORD, and QWORD types while retaining Base64 for every value.

### Network

WFP callouts cover ALE connect and receive/accept plus flow-established IPv4/IPv6 layers. Events carry flow IDs, endpoints, protocol, and packed ports. Associated flow contexts produce close events and are removed during teardown. Callouts permit traffic and do not capture packet payloads or decrypt TLS.

### BlackCat kernel attribution

`driver/attribution.c` uses Auxiliary Kernel Library module enumeration at PASSIVE_LEVEL to record BlackCat's image base and size. Any image named `BlackCat<digits>.sys` matches (`BlackCat1.sys` on current installs). The load-image callback records the range as soon as the driver loads, before its `DriverEntry` runs, and logs `blackcat_loaded`; the map also refreshes at session start and through a once-per-second agent IOCTL. Event-time checks use `RtlCaptureStackBackTrace` and accept only a direct address within that image. Direct matches carry the loaded image's name as `component` and `stack_resolved`; unrelated system activity does not inherit the component. Work BlackCat does inside the kernel without passing through these callbacks (its own callbacks, memory access, scanning) is not observable here.

Module attribution inside a tracked process uses the requesting thread's user-mode stack. For handle, registry, and file create/write/control/set-information events, `driver/events.c` walks up to 24 user-mode return addresses with `RtlWalkFrameChain` and stores them in the record (`StackOffset`/`StackFrames`, formerly a zeroed `Reserved` field). The walk runs only at PASSIVE_LEVEL, for user-mode requests, on the requesting thread of the attributed process; per-I/O events such as reads and closes carry no stack. The agent resolves the addresses against that process's image-load records into `modules` (innermost first) and reports `stack_frames` and `stack_unresolved`. Unresolved user-mode frames are code outside any image the agent saw load: unbacked memory, or modules loaded before tracking began for processes registered at agent start.

Direct evidence is collected in process, object, file, registry, and WFP callbacks. BlackCat-created processes are registered for continued tracking, and WFP accepts direct BlackCat stack matches in addition to tracked PIDs. File completion contexts preserve requestor identity across asynchronous completion. There is still no thread-lineage map or BlackCat device-stack attachment. Queued work items, DPCs on shared worker threads, protected code, and BlackCat device IRPs outside those callbacks remain uncovered. A BlackCat frame proves BlackCat participation, not MapleStory-to-BlackCat causality.

### ETW and attribution

The collector creates a uniquely named private real-time trace session. It enables WMI Activity, DNS Client, and RPC providers at verbose level with no keyword mask, and records provider failures as coverage warnings. It does not stop or modify other trace sessions. Verbose/all-event enabling can increase volume; the agent-side PID filter limits what is written, and the ETW queue/drop counters remain visible.

An ETW event whose PID is not yet in the agent's process scope is deferred for a short window instead of being discarded, but only when that process was created inside the same window. Long-running unrelated processes remain out of scope and are dropped, so a busy machine does not fill the queue or the log with system-wide WMI/DNS/RPC noise. If the driver process-start record arrives, the event is replayed; if it does not, an `etw_unattributed` coverage record is emitted with the provider, event ID, and PID. The collector also records ETW session lost-event counts and TDH parse failures. This closes the startup race where WMI/DNS/RPC activity occurred before the process-start record was drained.

TCP connection lifecycle comes from `Microsoft-Windows-TCPIP`, enabled with an event-ID filter so only these events reach the session: connect and accept completed, connect failed, retransmitted, refused or reset, close and abort issued, disconnect completed, shutdown initiated (with its NTSTATUS reason), FIN received from the remote, RST received, RST sent (with the stack's reason code), and retransmission, keep-alive, disconnect and FIN-WAIT-2 timeouts. They are logged as `etw_tcp` with `event=<name>` in `detail`, the endpoints in `text`, the event ID in `value0` and the connection's TCB pointer in `value1`. Connect and accept events name the owning process; later events for the same connection often run in system context with PID 0, and the FIN event has no addresses, so the agent carries the owner and endpoints forward by TCB. Only connections owned by tracked processes are written. This answers who ended a connection: `fin_received` before the client's own `close_issued` means the remote closed it; `reset_received` means the remote reset it; a `close_issued` or `abort_issued` with no prior FIN or RST means the client closed it; a timeout event means traffic stopped.

`Microsoft-Windows-CodeIntegrity` events 3076 and 3077 are logged as `etw_code_integrity` with `would_block` and `blocked` decisions. They bypass client-PID filtering because CodeIntegrity can run in System or a service. Their timestamps, native PIDs, paths, and policy metadata support correlation but do not prove which process requested the image load.

### KFilter decisions

When `\\.\KFilter` is available with ABI 4, the agent drains its decision ring during normal collection and shutdown. Each `kfilter_decision` preserves the decision timestamp, PID, path, status, target, action, flags, rights, rule ID, and generation. Decisions stamped before the session start are discarded (the ring is shared across runs), so a restart does not carry an earlier run's decisions into the new session. `WOULD_DENY` is emitted as `would_deny`, not as an enforced block. Start/final status and drop deltas are included in coverage. An absent, incompatible, stopped, or unreadable KFilter disables only this integration.

The ring is a single-consumer destructive read: do not run `kfilterctl watch` or `clear` while the agent collects. KFilter can deny a pre-operation before the lower-altitude monitor sees it, so the decision record may be the only record of that attempt. Allowed activity continues through the existing monitor sensors.

The agent also keeps copies of small text files (`.ini`, `.log`, `.txt`, `.json`, `.xml`, `.cfg`, at most 256 KB each) that tracked processes write under the client root or `%LOCALAPPDATA%\Nexon` / `%APPDATA%\Nexon`. The client writes short-lived diagnostics such as `_ms_report.ini` when a server connection drops and deletes them within a second. A copy is taken 150 ms after the last write, at most once every 2 s per file, into `snapshots\` in the session bundle, and a `file_snapshot` coverage record logs its path, size and SHA-256 so the hash chain covers it. A file already gone is logged as `file_snapshot_missed`. A session keeps at most 2,000 copies or 64 MB.

WMI can be correlated through `ClientProcessId` even when the event arrives from a service. Full-payload mode preserves the original query text; `--no-payloads` restores literal sanitization. WMI Activity does not supply result rows, and RPC/ALPC payloads are not available through these providers. DNS names and RPC endpoint metadata remain potentially sensitive.

Where ETW supplies supported stack extended data, the collector retains the raw addresses until the event is emitted, then resolves them against image-load ranges and records up to eight module paths. This lets late image-load records improve deferred events. Attribution is labeled `stack_resolved`, `service_correlated`, `process_only`, or `unknown`. Kernel callback context alone does not identify the calling DLL, and module resolution is not symbol or subroutine resolution.

## Classification and summaries

The classifier preserves raw metadata and adds `outside_client`, a category, and attribution. Hardware-related rules cover selected WMI classes/properties, registry key/value names, volume-information operations, and storage/device paths. Exact registry/volume values show what Windows returned, but still do not prove retention or transmission. Other hardware categories remain heuristics, and unknown remains unknown.

The final observer summary groups events by category, PID, target PID, and resolved module. It includes source drops/gaps, payload bytes, complete and incomplete payload operations, unavailable events, and duplicate chunks. It is evidence for a later policy tool, not an enforcement policy or proof of exfiltration.

## What full capture cannot mean

The monitor does not capture every CPU instruction, function call, in-memory transition, process/window enumeration without a handle, UI intent, or game-state semantic. It does not capture generic file contents, named-pipe payloads, ALPC/COM payloads, all RPC associations, all browser-broker activity, packet payloads, WMI result rows, direct adapter-API return buffers, activity before monitor startup, or events lost under overload. Pre-existing browser interaction through Explorer or another broker may remain unattributed.

Protected components and direct user-mode hardware APIs can lack a supported attributable event. Adding injection, SSDT hooks, client patching, or GRAP bypass is outside this project. Server-side code is not needed to build the monitor, but server-dependent gameplay paths cannot be certified without a runnable environment.

## Reliability requirements

The deliverable is a development prototype with limited installation and callback-registration measurements recorded in `docs/SIGNING_GATE.md`. Before production use it needs the full isolated VM load/unload checklist, Driver Verifier, payload and queue stress tests, buffer-failure tests, PID-reuse testing, WFP/minifilter coexistence checks, formal IRQL and lifetime review, independent security review, and a proper production signing/deployment process.
