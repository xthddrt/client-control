# Implementation notes — Gate 0 / Gate 1 slice

> **Logging/sensor-usage update:** the schema, portable bundle, coverage IOCTL, sensor map, fixture, catalog, and redaction tools from the reconciled final plan are implemented. See `docs/LOG_SCHEMA.md`, `docs/STORAGE.md`, `docs/COVERAGE.md`, `coverage/sensor-map.json`, and `tools/`. Runtime driver verification still requires the isolated VM.

**Base commit:** `41a058da9aaa565a10472b7657f072c739e8e82c`
**Status:** source changes applied. The user-mode agent and kernel driver both compile cleanly with MSVC `/W4 /WX` against WDK 10.0.26100; the driver output is `build\Release\driver\msmon.sys`. `InfVerif` syntax validation passes; `InfVerif /w` flags the legacy `DIRID 12` destination (not a load blocker for the test-VM procedure). The original slice had no runtime testing; later limited installation and callback-registration measurements are recorded in `docs/SIGNING_GATE.md`, with the full VM checklist still outstanding.
**Purpose:** first implementation slice from the merged plan, reconciled with the independent branch. Use this file to compare behavior and file-level changes.

---

## 1. What this slice implements

### Gate 0 — deployment and scope correctness

1. **Two roots**
   - `--client` is now the installation/classification root.
   - `--scope-root` explicitly sets the process scope.
   - If `--scope-root` is omitted and `MapleStory.exe` is found under `<client>\appdata`, the agent auto-detects `appdata` as the scope root.
   - The driver receives the scope root; the classifier receives the installation root.
2. **All executable images under the scope root**
   - The driver no longer matches four hard-coded image names. `MsMonImageUnderRoot` tracks any process image beneath the configured scope root, including PE payloads with non-`.exe` extensions such as GRAP `.aes`.
   - The agent's startup snapshot uses the same prefix rule.
   - The current agent process is excluded from startup tracking.
3. **BlackCat-created children**
   - A process created while BlackCat is on the stack is now added to the tracked set before its process-start event is logged, so subsequent file/registry/network/handle events are not lost.
4. **Root validation**
   - If no `MapleStory.exe` exists under the selected scope root and no `--pid` is supplied, the agent exits with an explicit error instead of opening a session that can never track the game.
   - If the executable exists but the game is not running, the agent prints a waiting message and continues.
5. **INF**
   - `ServiceType=2` (`SERVICE_FILE_SYSTEM_DRIVER`).
   - `Dependencies=FltMgr`.
   - `LoadOrderGroup="FSFilter Activity Monitor"`.
6. **Coverage manifest**
   - The agent writes a `coverage_manifest` record at session start with scope/inside roots, enabled callback families, ETW configuration, payload mode, and explicit blind spots (per-page mmap I/O, pipe/mailslot payloads, memory, UI, hardware, broker, TLS).
7. **Compat is no longer built by default**
   - `build.cmd` builds only the main monitor.
   - `build.cmd --with-compat` builds the legacy compat driver/tool.
   - `compat/README.md` now states that `SYSINFO_ENABLE_TRACE_HOOKS` defaults to 1 in `trace.c`, while the runtime gate is off; `[unsafe]` can enable it. Do not load compat for normal coverage.

### Gate 1 — correctness and accounting for existing coverage

8. **File requestor context**
   - `MSMON_FILE_CONTEXT` carries the pre-op requestor PID/TID, tracking decision, name information, and desired access into post-op.
   - File post-op no longer re-checks `PsGetCurrentProcessId()` for attribution.
   - `PostCreate` uses the desired access captured in pre-create instead of reading `SecurityContext` after the create.
   - Context is released on normal, draining, and error paths.
   - Untracked processes are rejected before allocating a context, avoiding a nonpaged-pool allocation for every unrelated system file operation.
9. **ETW deferred attribution**
   - An ETW event whose PID is not yet in `ProcessScope` is deferred for up to 5 seconds instead of being silently dropped.
   - Deferral is limited to processes whose creation time is inside the same 5-second window. Long-running unrelated processes are still dropped as before; otherwise every WMI/DNS/RPC event on the system would expire into an `etw_unattributed` record and swamp the log.
   - When the driver process-start record arrives, matching pending events are replayed.
   - Expired events produce an `etw_unattributed` coverage record with provider/event ID/PID, **not** the original sensitive query text.
   - Pending events retain raw stack addresses so late image-load records can resolve them at emit time.
10. **ETW configuration and accounting**
    - WMI Activity, DNS Client, and RPC are enabled at verbose level with no keyword mask.
    - ETW queue drain now loops until empty instead of one 8,192-event batch.
    - A buffer callback records ETW session `EventsLost`; TDH parse failures are counted.
    - Final `etw_accounting` record reports unattributed, pending overflow, pending after, lost events, parse failures, and queue drops.
11. **Queue drop sequence — verified, no code change**
    - **Correction:** the original code already assigns `block->Event.Sequence = ++gQueue.Sequence` *before* the queue-full check. A dropped record therefore consumes a sequence number and the next queued record creates a visible gap. The earlier review claim that queue drops do not create gaps was wrong.
    - I initially added a second increment; it was reverted. `driver/events.c` is unchanged from the baseline in this slice.
12. **Process path in every event**
    - `ProcessScope::Path` and `TelemetryEvent.processPath` add `process_path` to each JSON record.
    - Process-exit events capture the path before removing the scope entry.
13. **Event type**
    - Added `MsMonEtwUnattributed = 103` (no struct/version change).

### Reconciled from the independent implementation (partial Gate 2)

14. **Named pipes and mailslots**
    - The filter now sets `FLTFL_REGISTRATION_SUPPORT_NPFS_MSFS` and registers `IRP_MJ_CREATE_NAMED_PIPE` / `IRP_MJ_CREATE_MAILSLOT`; `\Device\NamedPipe` and `\Device\Mailslot` are classified as IPC.
    - Pipe/mailslot contents remain out of scope; reads/writes are metadata-only.
15. **Extended file operations**
    - Added close, flush, query/set security, query/set EA, and acquire-for-section-synchronization callbacks, with event types 34–40.
    - Section acquisition uses `FLT_FILE_NAME_QUERY_CACHE_ONLY` so a name lookup can never issue file system I/O in the paging path. Per-page mapped I/O remains uncovered.
16. **Registry enumeration results**
    - Common enumerate-key and enumerate-value layouts retain the returned key/value name even in metadata mode.
    - Values above 64 KiB remain explicitly partial; values above the 8-MiB protocol limit are marked `payload_too_large` instead of generating an unbounded chunk burst.
17. **WFP BlackCat attribution**
    - Direct BlackCat stack matches are accepted in addition to tracked PIDs.
18. **Allocation-drop accounting**
    - `MsMonEventsNoteDropped` advances the driver sequence and increments `Dropped` when a file/registry/object context or a process registration fails, so the gap is visible.
19. **ETW wall-clock timestamps**
    - `ClientContext = 2` (system time) is required because `Timestamp()` decodes `EventHeader.TimeStamp` as a FILETIME. The baseline value `3` (CPU cycle counter) produced 1601-era timestamps for every ETW event.

---

## 2. Files changed

| File | Change |
|---|---|
| `driver/file_filter.c` | Per-operation requestor context; post-op PID/TID; pre-op desired access; allocation only for tracked/BlackCat requestors; NPFS/mailslot; close/flush/security/EA/section callbacks. |
| `driver/process.c` | `MsMonImageUnderRoot` replaces the hard-coded image list; BlackCat-created children are tracked; registration failures advance the sequence. |
| `driver/events.c` | `MsMonEventsNoteDropped` (sequence gap + drop counter). Existing queue-full sequence behavior verified correct. |
| `driver/registry.c` | Enumerated key/value names; metadata-mode names; 8-MiB limit with explicit partial/unavailable; drop accounting. |
| `driver/network.c` | Direct BlackCat stack matches accepted by WFP callouts. |
| `driver/object.c` | Context allocation failures advance the sequence and drop counter. |
| `driver/msmon.h` | `MsMonEventsNoteDropped` declaration. |
| `driver/msmon.inf` | `ServiceType=2`, `Dependencies=FltMgr`, load-order group. |
| `include/msmon_protocol.h` | `MsMonEtwUnattributed = 103`; file event types 34–40; 8-MiB payload limit. |
| `agent/agent.cpp` | `--scope-root`; auto `appdata` scope; all-images startup tracking; coverage manifest; process_path; ETW replay/expiry; drain loop; ETW accounting. |
| `agent/etw.h` | Pending queue, deferred replay/expiry, lost/parse counters, emit ordering mutex. |
| `agent/etw.cpp` | Deferred attribution, raw stack retention, verbose/all-provider enable, lost-event buffer callback, drain/accounting. |
| `agent/telemetry.h` | `processPath`, raw stack fields, `ProcessScope::Path`. |
| `agent/telemetry.cpp` | `ProcessScope::Path`, `process_path` JSON, `etw_unattributed` type name. |
| `build.cmd` | Main build by default; compat only with `--with-compat`. |
| `README.md` | Build/collect/scope/coverage updates; 64 KiB registry cap; compat opt-in. |
| `docs/ARCHITECTURE.md` | Root/all-image scope; named-pipe coverage explicitly false; ETW deferral/accounting. |
| `docs/TEST_VM.md` | New INF/root/async/ETW/queue tests; compat opt-in. |
| `compat/README.md` | Corrected compile-time gate description. |

---

## 3. Reconciliation with the independent branch

The independent branch is available at `C:\Users\CrestEndo\OneDrive\Desktop\Kimi\msc-outside-monitor` (uncommitted changes over the same base commit). It was compared file-by-file. This tree keeps the stronger scope and ETW design and adopts the other branch's extended file/registry/WFP coverage.

Decisions:

- **Scope:** keep `--client` + `--scope-root` and all-PE-under-scope. The other branch keeps a hard-coded image list (adding the three GRAP `.aes` names) and auto-detects `appdata`; its behavior is a subset.
- **ETW:** keep the deferred queue with an emit-ordering mutex, raw-stack retention, a recent-process admission filter, and `etw_unattributed` records. The other branch assigns sequence before pushing without a lock and resolves stacks before deferral, so it can emit out of order and cannot use late image loads.
- **File context:** keep `FltGetRequestorProcessId` in pre-op; the other branch uses `PsGetCurrentProcessId`. Both carry identity into post-op, but the requestor API is the correct identity for asynchronous or kernel-issued I/O.
- **Queue drops:** keep the verified baseline behavior (sequence assigned before the queue-full check). The other branch adds a `MsMonEventsNoteDropped` helper for context/registration failures; adopted.
- **Manifest:** keep the `coverage_manifest` schema, updated to `minifilter_npfs=true`, `file_section_acquire=true`, and `registry_enum_names=true`.
- **Coverage:** adopt NPFS/mailslot, close/flush/security/EA/section, registry enumeration names, 8-MiB value bound, WFP BlackCat, and drop accounting. Pipe/mailslot callbacks read create-only options and security context only for `IRP_MJ_CREATE`.
- **ETW/output:** adopted `ClientContext = 2`; did not adopt the `etw_unmatched_events` summary field or unconditional `process_path` fill (which can misattribute a reused PID).

1. **`--client` semantics**
   - Old: `--client` was the process root (`...\appdata`).
   - New: `--client` is the installation/classification root; `appdata` is auto-detected for scope. Passing `...\appdata` still works.
   - If the other branch changed root handling differently, reconcile both into a single root model. Do not keep two competing auto-detection paths.

2. **All-image tracking**
   - Old: four exact images.
   - New: any executable image under the scope root. This deliberately includes `.aes` and renamed helpers.
   - If the other branch added a configurable image list, merge it into this prefix rule; do not revert to a hard-coded list.

3. **INF**
   - If the other branch also changed the INF, keep `ServiceType=2` and `Dependencies=FltMgr`; verify the chosen `LoadOrderGroup` and altitude.

4. **File filter**
   - The other AI may also have introduced a requestor context. Merge on the concept, not the struct name. Ensure:
     - requestor PID/TID captured at pre-op;
     - post-op never re-checks current PID for attribution;
     - name info released exactly once;
     - untracked operations do not allocate a context.

5. **ETW**
   - The other AI may have a deferred queue with different timeout/limit. Keep one implementation. Preserve:
     - no silent drop for unmatched PID;
     - `etw_unattributed` without sensitive query text;
     - sequence assigned at emit under a single ordering lock;
     - drain-to-empty and lost/parse counters.

6. **Coverage manifest**
   - If the other branch emits a structured manifest, keep one schema and include both roots and the same blind-spot booleans.

7. **Queue drop sequence**
   - **Do not add a second increment.** The original code assigns the sequence before the queue-full check, so drops already create a gap. Keep existing behavior; add only per-source counters if the other branch has them.

---

## 4. Not implemented in this slice

These remain open and should not be assumed covered:

- per-page mapped reads/writes, section creation/release (section acquire is metadata-only);
- directory enumeration *results*, rename targets, set/query information buffers; file security/EA payloads beyond the security-information mask;
- registry hive operations, key security, query-key results beyond names, set-value caps other than the 8-MiB bound;
- memory read/write/protect/section/APC/remote-thread events;
- desktop handles and target thread IDs;
- broker/service/COM/DPAPI correlation;
- UI/clipboard/input/hardware/API sensor;
- per-event-type driver loss counters (`attempted/emitted/context_failed`) beyond queue/context drops;
- queue priority/source-side inside-client aggregation;
- ETW provider expansion beyond WMI/DNS/RPC;
- HMAC/signature/top-N summaries;
- runtime driver tests.

---

## 5. Build and test status

**Built.** The full solution builds with Visual Studio 2022 Community 17.14.43, MSVC 14.44.35207, WDK 10.1.26100.6584, and the Spectre-mitigated libraries:

- `build\Release\driver\msmon.sys` — 47,104 bytes, `/W4 /WX`, Qspectre, 0 warnings/errors.
- `build\Release\agent\msmon-agent.exe` — 174,080 bytes, 0 warnings/errors.
- `msmon-agent.exe --help` works.
- Invalid `--client` root validation works; a valid root reaches the expected `\\.\MsMon` open failure when the driver is not loaded.
- `InfVerif` syntax validation passes; `Inf2Cat /os:10_X64,10_VB_X64` generates `msmon.cat` with no errors/warnings. `InfVerif /w` reports the legacy `DIRID 12` destination (expected for this non-PnP minifilter INF; not a load blocker for the test-VM procedure).

The driver has **not** been installed or runtime-tested on this host; doing so would require test-signing and an isolated VM.

Before relying on it:

1. Build with `build.cmd` on the isolated VM (or copy the signed package).
2. Install the signed INF on the isolated VM; confirm `fltmc` altitude and `ServiceType=2`.
3. Run the checklist in `docs/TEST_VM.md`, including:
   - parent vs appdata scope;
   - valid root but game not running;
   - all-image/`.aes` tracking;
   - overlapped file attribution;
   - NPFS/mailslot, close/flush/security/EA/section;
   - registry enumeration names and the 8-MiB bound;
   - early ETW event replay and expiry;
   - queue overflow sequence gap;
   - Driver Verifier load/unload.
4. Only then update the README/runtime claims.

---

## 6. Known risks / review notes

- **Verbose ETW** can materially increase event volume; the PID filter and queue counters limit output but not provider delivery. If it is too noisy, make verbose/all-keyword a CLI option and keep Information as the default.
- **Pending ETW memory** is bounded at 4,096 events; overflow is counted but the oldest event is dropped without an individual record.
- **File context allocation** is now avoided for untracked operations, but every tracked file I/O still allocates nonpaged pool. Measure under the 54k/s burst.
- **All-image tracking** may track unrelated tools placed under `appdata`; this is intentional for completeness but should be documented.
- **`MsMonImageUnderRoot`** uses a prefix + separator check; long paths and reparse points are not resolved.
- **`process_path`** is agent-side JSON only; driver event consumers must not assume it exists in the binary protocol.
- **NPFS/mailslot registration** increases the operations the filter sees system-wide. The pre-op still rejects untracked requestors before allocating, but the callback itself now runs for every pipe/mailslot operation; measure on a busy host.
- **Section acquisition** uses cache-only name lookup and logs metadata only. Missing paths are expected for some mappings; per-page mapped I/O is not captured.
- **Registry result names** point into the post-operation result buffer and are copied synchronously into the event; they must never be retained past that callback.
- **No `MSMON_PROTOCOL_VERSION` bump.** The protocol additions are event types 34–40 and 103 plus a payload-length constant; old agents would classify the new types as unknown. If binary compatibility matters, bump to v5.

---

## 7. Reconciliation checklist for the other AI's implementation

- [x] Compare `--client`/`--scope-root` behavior; choose one root model. **Kept the two-root model; the other branch's auto-detect is a subset.**
- [x] Compare image discovery; keep all-PE-under-scope. **Kept; the other branch's hard-coded `.aes` list is a subset.**
- [x] Compare INF changes; keep ServiceType=2/FltMgr. **Identical fixes.**
- [x] Compare file context; keep pre-op requestor identity. **Kept `FltGetRequestorProcessId`; the other branch uses the current PID.**
- [x] Compare ETW deferral; keep no silent drops and one emit order. **Kept this design; did not adopt the lock-free emit or pre-deferral stack resolution.**
- [x] Compare queue drop sequence; verified sequence-before-drop and added `MsMonEventsNoteDropped` for context/registration failures.
- [x] Compare coverage manifest field names. **Kept one schema, now `minifilter_npfs=true` and `file_section_acquire=true`.**
- [x] Merge docs claims; named-pipe coverage is now real. **Updated architecture/README/test docs.**
- [x] Build both branches on a real WDK machine before merging. **Both built; this merged tree rebuilt cleanly.**
- [ ] Re-run the fixture matrix / VM checklist after the merge.
