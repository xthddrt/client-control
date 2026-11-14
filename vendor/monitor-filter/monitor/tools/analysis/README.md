# Session analysis scripts

Read-only scripts for answering questions about one session bundle. Each takes the bundle folder
(for example `C:\msmon-sessions\20261029T195007Z__desktop-07i2bmc__login__iter01__2a50cdd9`) and prints
to the console. They need only the Python 3 standard library.

## Where the data is

A session bundle is one folder under the agent's `--log-dir` (`C:\msmon-sessions` with the test harness):

| File | Contents |
|---|---|
| `events.jsonl`, `events.jsonl.1`, `.2`, … | One JSON event per line, rotated every 64 MB. Read in that order; every line has `record_index` and a `chain` hash (`tools/verify_log.py` checks it). |
| `summary.json` | Totals, drops, and counts by process, category and module |
| `coverage.json` | Sensor registration and counters, per-provider ETW statistics |
| `session_meta.json` | Start and end time, roots, build hashes |
| `snapshots\` | Copies of small text files the client wrote (see `docs/ARCHITECTURE.md`); newer sessions only |

Field meanings are in `docs/LOG_SCHEMA.md` and `schema/event-v1.json`. Conventions worth knowing:

- Timestamps are UTC.
- Paths are kernel device paths: `\Device\HarddiskVolume3\…` is `C:\…` on the original test host. `common.dos_path` converts them and replaces the user name.
- `modules` is the requesting thread's call stack, innermost first; the first non-Windows module is the code that asked (`common.caller_module`, which on Linux also skips Wine's own modules, the prefix's `windows` directory and system libraries; Wine records list the PE frames before the unix ones). `stack_unresolved` counts user-mode frames in no loaded image.
- `etw_tcp` events carry `event=<name>` in `detail`; see `network_timeline.py` for how to read who closed a connection.

## Scripts

| Script | Answers |
|---|---|
| `session_health.py SESSION` | Which processes were tracked and when, sequence gaps and drops, BlackCat load, collector statistics, busiest seconds, events per process |
| `session_activity.py SESSION [--show PID --sections a,b]` | Per-process summary of everything outside the process: files by location, writes, deletes, pipes, device IOCTLs, registry reads and writes, identity reads, network, DNS, WMI, TCP, handles to other processes, non-Windows images, BlackCat events. Writes `activity.json` into the bundle; `--report activity.json --show PID` prints one process without re-reading the log. |
| `module_attribution.py SESSION [--process MapleStory.exe]` | Which module inside the process opened other processes (with granted rights), read identity data, sent device IOCTLs and opened outside executables |
| `network_timeline.py SESSION [--no-loopback]` | Chronological DNS, connections, flows, TCP close reasons, process start/exit and file snapshots, plus each flow's lifetime |
| `time_window.py SESSION START END [--all]` | Every event in a UTC window (`19:52:19.5 19:52:21`) with its calling module; high-volume reads and queries are counted but not listed unless `--all` |
| `outside_activity.py SESSION` | Command lines (launcher token redacted), file reads outside the client folder, registry writes outside the game's own settings |
| `payload_unavailable.py SESSION` | Why registry or volume values were not captured |
| `identity_log.py --bundle SESSION --policy POLICY --out LOG` | Append WMI/DNS/RPC, identity, connection, driver-load and RISK events plus every current `risk=` rule to the kfilter identity log. Run after every captured game session. |

Typical order: `session_health.py`, then `session_activity.py`, then the narrower scripts for a question.
The game sessions are large (hundreds of MB), so each script takes a minute or two.

## Before sharing a bundle

Bundles contain the launcher login token (process command line), the Windows account SID and user
name in paths, the local IP address, and captured registry values that include machine identifiers.
Linux bundles also hold the client's socket bytes (`network_data` payloads: tokens, chat, MAC data).
Make a redacted copy with `tools/redact_session.py` before handing a bundle to anyone else, or record
with `--no-payloads`.

## Regression tests

`tools/windows-test/regression/` holds the scripts used to verify the collector on a test host (elevated,
driver loaded, client installed at `C:\Nexon\Library\maplestorycw`):

| Script | Checks |
|---|---|
| `parallel_burst.ps1 [-Workers 4 -Count 250000]` | No drops under a burst of tracked file reads (uses `burst.ps1`) |
| `attribution_test.ps1` | Handle, registry and file events from a tracked child name the modules that made them |
| `net_snap_test.ps1` | `etw_tcp` distinguishes remote FIN, remote reset, local close and refusal; a short-lived `.ini` under `%LOCALAPPDATA%\Nexon` is copied to `snapshots\` |
