# msc-outside-monitor

Application-scoped Windows telemetry for the MapleStoryCW client, with a WDM kernel/minifilter driver, an elevated Win32 collector, ETW correlation, chained JSONL output, and a static inventory of the supplied installation.

The monitor observes an exact client installation, its descendants, and configured Nexon helpers. It does not inject code, hook SSDTs, patch the client, bypass GRAP/Nexon security, disable driver signing, or decrypt network traffic. By default it records registry values (up to 64 KiB each) and volume-information results; these payloads can contain hardware identifiers and registry secrets. Generic file contents and network payloads are not captured.

## What it captures

| Source | Events |
|---|---|
| Process/thread/image callbacks | start/exit, PID and creation time, ancestry, image path, command line when available, module base/size |
| Object callbacks | process/thread handle creation and duplication, target PID/image, requested and granted access, result |
| Filesystem minifilter | create, non-paging read/write, query/set information, directory control, cleanup/close, flush, security/EA, section acquire, named-pipe/mailslot, visible FS/device controls, volume-information results |
| Registry callbacks | open/create, query/enumerate, set/delete/rename, key/value names including common enumeration results, type/size, operation result, and value bytes up to 64 KiB |
| Windows Filtering Platform | IPv4/IPv6 connect/accept and flow establish/close, flow ID, endpoints, protocol, ports, PID |
| WMI Activity ETW | correlated client PID, namespace/provider/operation, and original query text in full-payload mode |
| DNS Client ETW | correlated query name and query metadata |
| RPC ETW | correlated endpoint/operation metadata where client attribution is available |
| CodeIntegrity ETW | WDAC audit (`3076`) and enforced (`3077`) image decisions, including BlackCat blocks |
| Optional KFilter device | deny/audit decisions with rule, rights, generation, path, PID, and drop accounting |

For `BlackCat64.sys`, the driver maps the kernel image and checks the active kernel stack. Direct matches are emitted with component `BlackCat64.sys` and `stack_resolved` attribution. This proves BlackCat participated in the operation, not that MapleStory requested it. BlackCat-created children are tracked, and WFP accepts direct BlackCat stack matches. Queued work, shared worker threads, protected code, and BlackCat device IRPs outside existing callbacks remain unattributed.

Registry values are emitted as Base64 bytes with friendly decoding for common string, multi-string, DWORD, and QWORD types. Volume results include raw bytes plus the exact serial number, creation time, and label when the returned structure is valid. Large values use linked 8-KiB chunks; values larger than 64 KiB are explicitly partial, and values above the 8-MiB protocol limit are marked unavailable.

Records are classified as client data, Windows runtime, external process, browser interaction, hardware identity, user data, registry, network, IPC, or unknown. Capturing a request or returned value does not prove that MapleStory retained or transmitted it. This is broad OS telemetry, not a guarantee of every instruction, function call, service-mediated action, or hardware read.

## Build

Requirements: Visual Studio 2022 with MSVC and the Windows Kernel Mode Driver toolset, plus Windows SDK 10.0.26100.

```bat
build.cmd
```

Outputs:

- `build\Release\driver\msmon.sys`
- `build\Release\driver\msmon.inf`
- `build\Release\agent\msmon-agent.exe`

The default build is unsigned development output. Do not load it on a production machine. Use the isolated test-VM procedure in `docs/TEST_VM.md`. The user-mode agent and kernel driver both compile cleanly with MSVC `/W4 /WX` against WDK 10.0.26100, and `InfVerif` syntax validation passes. Limited installation and callback-registration measurements are recorded in `docs/SIGNING_GATE.md`; they are not a substitute for the full VM checklist. `InfVerif /w` also reports DIRID 12 in the legacy minifilter INF.

`docs/RELIABILITY.md` records the driver defects found while investigating host bugchecks on stop/unload and under network load, together with the fixes. Read it before loading a build.

## Collect

Run elevated in the test VM after properly signing and starting the driver. Start the collector before launching the game:

```bat
msmon-agent.exe --client "C:\Nexon\Library\maplestorycw" ^
    --log-dir "C:\msmon-sessions" --session-label "login-01" ^
    --scenario login --phase steady --iteration 1 --machine-label "vm-win11-01"
```

`--client` names the installation/classification root. The agent auto-detects
`appdata` as the process scope when the executable is there. Use
`--scope-root` to override the process scope explicitly, or pass the original
`...\appdata` path directly. `--output` still writes a single log outside a
bundle for compatibility.

Options:

- `--log-dir DIRECTORY` writes an immutable session bundle with labels, summary, coverage, and metadata;
- `--session-label LABEL`, `--scenario NAME`, `--phase NAME`, `--iteration N`, `--machine-label NAME` label the session;
- `--test-id ID` overrides the generated bundle directory/test ID;
- `--outcome-override NAME` overrides the computed outcome (use only for killed sessions);
- `--compact` omits decoded status/flag/access fields;
- `--extra-root DIRECTORY` adds another tracked root (up to three). Without it, `%ProgramData%\Nexon\NGS` is added when it exists, so the NGS security service is tracked;
- `--scope-root DIRECTORY` explicitly sets the process scope (the folder containing the client executable);
- `--pid PID` explicitly tracks another existing process;
- `--wait-ms N` sets the empty-queue wait, capped by the driver at one second;
- `--max-file-mb N` rotates output after the threshold with a continuing hash chain;
- `--queue-records N` and `--queue-mb N` adjust bounded driver buffering;
- `--stop-file FILE` stops tracking, drains queued events, and writes the final summary when the file appears;
- `--no-etw` disables the private ETW session, including CodeIntegrity decisions, and records a coverage warning;
- `--no-payloads` disables exact registry/volume payloads and restores sanitized WMI queries;
- `--no-packets` (Linux) writes no pcapng packet capture (`events.pcapng`); `--no-payloads` turns it off too;
- `--once` reads one driver batch and exits.

KFilter collection is automatic and optional. Its absence, an ABI mismatch, or a read failure records coverage without stopping other sensors. Do not use `kfilterctl watch` or `clear` during collection because they compete for the same destructive ring. A KFilter pre-operation denial need not have a paired native monitor record. CodeIntegrity records are system-wide and do not prove client causality; enforced BlackCat policy should prevent `blackcat_loaded` and BlackCat stack attribution.

Local drive-letter paths are translated to the NT device paths seen by kernel process callbacks. The process scope contains `MapleStory.exe` and its helpers; any executable image beneath the scope root is tracked, and descendants inherit tracking. Existing unrelated browsers and services are logged as interaction targets, not monitored wholesale. The session log contains a `coverage_manifest` record listing the scope/inside roots and the sensors that are actually enabled, so a missing event class is not mistaken for proof of no activity.

Every output line has a consecutive record index and a SHA-256 chain. Driver and ETW sequence numbers remain independent; gaps and queue drops are visible. Validate rotated logs in order:

```bat
python tools\verify_log.py session.jsonl session.jsonl.1
```

The verifier checks the chain, Base64 payloads, chunk ordering/completeness, and friendly decoded values. The final observer summary groups events by category, process, target process, and resolved module and reports complete and incomplete payload operations. Keep the final chain separately if later modification detection matters.

## Session bundles

Finalize a bundle after the agent stops:

```bat
python tools\session_pack.py "C:\msmon-sessions\<bundle>"
python tools\validate_schema.py --session "C:\msmon-sessions\<bundle>"
python tools\compare_sessions.py <bundle-a> <bundle-b>
```

`session_pack.py` verifies the chain, writes `manifest.json`, `checksums.json`, `environment.json`, `notes.md`, and `derived/census.json`, and creates a compressed copy. The schema and field dictionary are in `docs/LOG_SCHEMA.md`; transfer/retention rules are in `docs/STORAGE.md`. Raw logs can contain registry values, hardware identifiers, DNS names, and WMI query text; transfer is explicit, never automatic.

## Sensor coverage

The driver exposes `MSMON_IOCTL_COVERAGE`; the agent writes `coverage.json` and a chained `coverage_usage` record. Build the report:

```bat
python tools\sensor_report.py <bundle> --scenario file_io --write
python tools\scenario_check.py <bundle> --scenario file_io --write
```

`coverage/sensor-map.json` maps sensor IDs to source implementation and expected scenarios. Build the controlled fixture with `build.cmd --with-fixtures`, run it under the matching scenario, and use `tools/oracle_diff.py` against a Procmon export to find operation classes the monitor never saw. See `docs/COVERAGE.md` for the activity/health/verification model and limits.

## Static client inventory

The analysis script requires Python and `pefile`:

```bat
python tools\analyze_client.py C:\Nexon\Library\maplestorycw analysis\pe-inventory.json
```

The committed inventory covers all 391 supplied files and 46 PE images, including PE-formatted GRAP `.aes` payloads. No proprietary client binaries are included here. The installation contains no original C/C++ source or symbols; import analysis is not a complete decompilation.

## Linux

```sh
./build.sh
sudo build/linux/msmon-agent --client /opt/client --log-dir /var/tmp/msmon-sessions
```

The Linux agent has no driver: fanotify, the process-events connector and `/proc` polling produce the same records and bundle format, so the Python tools work unchanged. Without root it still writes a verified log but records fanotify and the connector as unavailable. Registry, ETW and BlackCat sensors do not exist there. `driver/`, `tools/windows-test/` and the PowerShell tests are Windows-only. See `docs/LINUX.md` for sensors and coverage limits.
On Linux the eBPF sensors also log every byte the client sends and receives on its network sockets (`network_data` payloads) and the DNS names in them (`etw_dns`); such logs hold secrets (`sensitivity=secrets`), and `--no-payloads` turns this off.

## Safety and privacy

Use only on systems and software you are authorized to inspect. Logs can contain exact hardware identifiers, registry secrets, command lines, paths, process relationships, network endpoints, DNS names, and original WMI queries. Use synthetic data in tests, restrict log access, define a retention period, and never commit real payload logs. The control device is administrator-only, and the driver is not hidden or hardened against tampering.
