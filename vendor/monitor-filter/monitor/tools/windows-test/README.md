# Windows test harness

Local, machine-specific scripts used to load, run and tear down the driver on a
Windows 11 test host. They are **not** part of the product build and are not portable:
the client path (`C:\Nexon\Library\maplestorycw`), `C:\Nexon\ms-test` and
`C:\msmon-sessions` are hardcoded. The repo path is taken from the script location. Read `docs/SIGNING_GATE.md`
before expecting handle or network events.

| Script | Purpose |
|---|---|
| `install-driver.ps1` | first install: create the test certificate if missing, test-sign the build, register the service as a minifilter (altitude 370030, `FltMgr`), start it; stages outside `System32` if the deployment path is not writable |
| `swap-driver.ps1` | replace a running build with the current one: verify hash against `build/build-info.json`, sign, stop, deploy, start |
| `start-agent.ps1` | start `msmon-agent.exe` detached with a stop file |
| `stop-collector.ps1` | create the stop file, wait for a clean drain, print the summary, verify the chain |
| `probe-signing-gate.ps1` | regression probe for `ObRegisterCallbacks` / WFP registration; refuses builds without `/INTEGRITYCHECK`, prints the registration slots from `coverage.json` |
| `sysmon/verify-processaccess.ps1` | prove Sysmon's `ProcessAccess` path works, then restore the tight config |
| `sysmon/export-events.ps1` | dump Sysmon events to NDJSON next to a session bundle |
| `sysmon/client-only.xml` | Sysmon config filtered to the client path: ProcessAccess, NetworkConnect, DnsQuery, FileCreate, RegistryEvent, process create/terminate |

Regression tests for the collector (burst drops, module attribution, TCP close reasons, file
snapshots) are in `regression/`; see `tools/analysis/README.md`.

All of these require an elevated shell. `install-driver.ps1`, `swap-driver.ps1` and
`probe-signing-gate.ps1` create and trust a self-signed test certificate; remove it and
uninstall the driver when finished.
