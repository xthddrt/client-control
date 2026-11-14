# Callback registration findings (measured)

Measured 2026-10-29 on Windows 11 build 26200, Secure Boot off, `TESTSIGNING` on.
The test-signed driver loaded and attached as a minifilter at altitude 370030.
These limited registration measurements are not a full runtime certification.

## Object callbacks: image was not linked with `/INTEGRITYCHECK`

| Registration | Sensor slot | NTSTATUS | Meaning |
|---|---|---|---|
| `ObRegisterCallbacks` (process) | 23 | `0xC0000022` | `STATUS_ACCESS_DENIED` |
| `ObRegisterCallbacks` (thread) | 24 | `0xC0000022` | `STATUS_ACCESS_DENIED` |
| process/thread/image notify, minifilter, registry | 20-27 | `0x00000000` | success |

Both object slots receive the status from the single `ObRegisterCallbacks` call in
`driver/object.c`. While that call fails, `process_handle` and `thread_handle` events
are unavailable. The failure is disclosed as `registration_failed` rather than
silently treated as no activity.

| Attempt | Result |
|---|---|
| Test-signed (Code Signing EKU only), `TESTSIGNING` on | `0xC0000022` |
| Self-signed with Code Signing **and** `1.3.6.1.4.1.311.61.1.1` (Kernel Mode Code Signing) EKU, `TESTSIGNING` on | `0xC0000022` |

Both measured builds were linked without `/INTEGRITYCHECK`, so the image did not carry
`IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY` (`0x0080`). `ObRegisterCallbacks` returns
`STATUS_ACCESS_DENIED` for callbacks in an image without that flag regardless of the
certificate, which matches the EKU change having no effect. These results are not
evidence that a Microsoft-issued signature is required.

`driver/msmon.vcxproj` now links with `/INTEGRITYCHECK`, and `build.cmd` records the
flag as `driver_force_integrity` in `build/build-info.json`.

## Result with `/INTEGRITYCHECK` (measured)

Measured 2026-10-29 on a second host (Acer Aspire C24-1650, Windows build 26200),
Secure Boot off, `TESTSIGNING` on. Build `6465015` (`driver_force_integrity: true`)
was test-signed with a self-signed Code Signing certificate (no Kernel Mode Code
Signing EKU) and installed with `install-driver.ps1`. A 10-second agent session
(`reg-check-20261029-105410`) read the registration slots from `coverage.json`:

| Registration | Sensor slot | NTSTATUS |
|---|---|---|
| process/thread/image notify, minifilter, registry | 20-27 | `0x00000000` |
| `ObRegisterCallbacks` (process, thread) | 23-24 | `0x00000000` |
| WFP callouts (connect, accept, flow; v4 and v6) | 28-33 | `0x00000000` |
| `FwpmEngineOpen` | 34 | `0x00000000` |

`registration_failed` was 0 and the `coverage_manifest` listed every callback,
including all six WFP layers. A Microsoft-issued signature is not needed to register
object callbacks under `TESTSIGNING`; the missing `/INTEGRITYCHECK` flag was the cause.
This verifies registration only: handle and network events still need to be checked
against controlled activity (`TEST_VM.md` checklist).

## WFP result: layer-registration defect, not signing evidence

The initial run also returned `0xC0220004` for all six WFP layer slots (28-33),
while `FwpmEngineOpen` succeeded. That status is `STATUS_FWP_LAYER_NOT_FOUND`,
not a signing error.

The cause was in `MsMonAddCallout`: `FWPM_CALLOUT.applicableLayer` was zeroed but
never assigned before `FwpmCalloutAdd`. The driver now assigns the layer GUID passed
to that function. The initial `0xC0220004` results must not be used as evidence for
a WFP signing gate. With the fix, all six layers register (see the measured result
above).

## Repro

`tools/windows-test/probe-signing-gate.ps1` refuses a build whose hash does not match
`build-info.json` or whose `driver_force_integrity` is not `true`, then signs and deploys
that exact build, runs a uniquely identified agent session, and prints the registration
slots. On a `/INTEGRITYCHECK` build all object and WFP slots are expected to report
`0x00000000`; any failure should be decoded and investigated on its own rather than
attributed to signing.

## Options

1. **Build with `/INTEGRITYCHECK`** (the default now). Verified to clear the
   object-callback denial under `TESTSIGNING`.
2. **Microsoft attestation signing** (Partner Center; requires an EV certificate) is
   needed only to load on machines without `TESTSIGNING`, not to register callbacks.
3. **Sysmon** (`tools/windows-test/sysmon/`) can cross-check process-handle access and
   connect/DNS telemetry. Its `ProcessAccess`
   event was observed with source image, target image, and granted access mask. It is
   not a replacement for the driver's thread-handle, duplication, accept, flow-lifetime,
   or BlackCat attribution events.
4. Patching kernel code integrity is out of scope and is not implemented here.

## Consequence for coverage claims

Do not read an empty `network_*` class or a missing `process_handle` class in a log as
"the client did not do it". Check the registration entries in `sensor-usage.json` and
`coverage.json`. The `coverage_manifest` derives its callback list from the driver's
registration bitmask when the coverage IOCTL is available, including individual WFP
layers; with an older driver it reports registration as unknown.
