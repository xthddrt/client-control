# Runtime sensor accounting

The driver and agent report which monitoring paths executed. This proves execution, not correctness: a controlled scenario is required for a "verified working" claim.

## Counters

`MSMON_IOCTL_COVERAGE` returns `MSMON_COVERAGE` (`include/msmon_coverage.h`):

- `EventAttempted[128]` / `EventDropped[128]`: records/chunks per event type.
- `SensorEntered[64]`: callback/operation invocations.
- `SensorLogged[64]`: invocations that emitted at least one record.
- Skip counters: untracked, unsafe IRQL, missing name, allocation, process tracking, queue. Each counts the callout/operation invocations it filtered, in the same unit as `SensorEntered`.
- `RegistrationOk` / `RegistrationFailed` bitmasks and `RegistrationStatus[64]`.
- `BlackCatMatches` and `PayloadCaptured[4]` (payload chunks captured, by payload kind).

Session counters reset at session start. `RegistrationOk`, `RegistrationFailed`, and `RegistrationStatus` are recorded at driver load and kept across sessions, so a coverage report read after a session still shows registration results. The agent writes `coverage.json` and emits a chained `coverage_usage` record (type 111).

## Status model

Three independent axes:

**Activity** — `observed`, `enabled_not_observed`, `skipped`, `disabled`, `registration_failed`, `unsupported`, `not_applicable`, `not_instrumented`.

**Health** — `ok`, `lossy` (any drop/loss), `degraded` (drop ratio > 0.1% by default), `unknown`. The threshold is configurable in `tools/sensor_report.py --drop-ratio`.

**Verification** — `verified`, `failing`, `unverified`, from `tests/scenarios/*.json`.

`mapped` and `expected_for_scenario` are flags, not states. A sensor may be `observed + lossy + unverified`.

Do not read a zero as dead code. A sensor needs several covering sessions and code review before removal.

## Sensor map

`coverage/sensor-map.json` maps stable sensor IDs to source implementation, event types, expected scenarios, and status (`active`, `blind_spot`, `planned`, `compiled_out`). Regenerate with:

```bat
python tools\generate_sensor_map.py
```

## Report

```bat
python tools\sensor_report.py <session> --scenario file_io --write
python tools\scenario_check.py <session> --scenario file_io --write
```

`sensor-usage.json` contains activity, health, verification, entered/logged, attempted/dropped, registration status, and scenario expectation. `scenario_results.json` lists verified/failing/unavailable/unexpected sensors.

## Controlled scenarios and oracle

Build the fixture only when needed:

```bat
build.cmd --with-fixtures
build\fixtures\sensor_probe.exe file
build\fixtures\sensor_probe.exe registry
build\fixtures\sensor_probe.exe ipc
build\fixtures\sensor_probe.exe network
powershell -NoProfile -ExecutionPolicy Bypass -File tests\fixtures\wmi_probe.ps1
```

Run the fixture while collecting with the matching `--scenario`. `sensor_report.py` then marks expected sensors `verified` or `failing`.

For unknown gaps, export Procmon (Operation, Path, Result, PID) filtered to the fixture PID/path:

```bat
python tools\oracle_diff.py --session <bundle> --oracle procmon.csv --pid 1234
```

`missing_classes` are operations the oracle saw and we did not; `extra_classes` are ours only. This is a class-level diff, not proof about every instance.

## Limits

- Counters prove execution, not correctness or coverage completeness.
- Offline tools are not instrumented by driver counters; their versions are in the manifest.
- Payload decoding and classifier counters are represented indirectly (summary/census); the driver counters are the authoritative execution evidence.
- A missing map entry is `not_instrumented`, not proof of absence.
