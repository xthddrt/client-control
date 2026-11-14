# Implementation status (v4 branch)

Branch: `feature/containment-v4`, based on `eff419c`.

This is the code half of the v4 plan. It builds with MSVC `/W4 /WX` against WDK
10.0.26100. It has **not** been loaded, signed, installed, or run on a test VM. Treat
every runtime claim as unverified until Gate 0/1 of the plan is executed.

## Implemented in this branch

- ABI 4 policy:
  - independent file/registry rights plus create, connect, listen and raw-device
    rights (`query` is reserved and is not a policy-language right);
  - file, dir, registry, process, volume, device, pipe and network targets;
  - registry `value=` matching and checked multi-value queries;
  - rule IDs that are stable per policy generation (assigned from rule order),
    policy generations and bounded network rules;
  - optional AppContainer package-SID pinning and explicit allow rights.
- Shared OS-free `match.c` used by the driver, `kfilterctl self-test`, `evaluate`
  and `simulate`; policy paths are prefix matches (`dir` and descendants), not
  full-path-only matches. Offline replay applies mode/layer gates and the same
  conservative registry value-enumeration helper as the driver.
- Process identity: referenced `PEPROCESS`, PID, creation time, full image,
  AppContainer SID and policy generation. Package-SID pinning, actual-creator
  checks, ordered child-image decisions and idempotent audit-mode admission.
  Only a child that passes every identity check (actual creator and declared
  parent protected, package and parent SID match) and receives an allow or
  audit rule is added to the family. A child the policy would deny, or whose
  identity check failed, is never inserted, so an audit-to-block switch cannot
  promote it. Image-name matching is boundary-checked: a `protect` entry
  matches only a full file name, not a longer name that ends with it.
  A root image created by an unprotected parent in block mode is refused
  unless the creator is the launcher registered through
  `KFILTER_IOCTL_REGISTER_LAUNCHER`; the launcher creates suspended and then
  admits through `ADMIT_PROCESS`. When a package SID is configured, a
  protected-name image must also carry that AppContainer SID; a mismatch is
  refused in block mode before the launcher path, so an outside process cannot
  start an untracked copy. The registration is a referenced `PEPROCESS`,
  so PID reuse cannot inherit it, and it is cleared when that process exits.
  Table-full and missing-image admission failures refuse both child and root-image
  creation in block mode independently of the process-create policy flag.
- File enforcement: create, named-pipe/mailslot create, read/write, set-info,
  set-security, directory control, section acquisition and NPFS/MSFS;
  stream-handle contexts; missing name/context fail closed. Rename and hard-link
  sources are authorized again under the current policy with the rename right,
  independently of create-time rights; the source name is resolved with a full
  name query rather than the name cache. Destinations are resolved relative to
  `RootDirectory` and authorized separately; both decisions preserve the
  file/directory target, and an unresolvable name fails closed in block mode.
  `IRP_MJ_SET_SECURITY` is authorized with the independent set-security right
  against the context's recorded file/directory class, so a handle opened
  without `WRITE_DAC`/`WRITE_OWNER` (or before the current generation) fails
  closed. Volume rules govern identity queries. Device-control,
  internal-device-control and filesystem-control requests are no longer skipped:
  they request read+write against the stream-handle context, so a missing or
  stale context (and a handle opened read-only or execute-only) fails closed in
  block mode. There is no per-control-code mapping yet, and FSCTL behavior has
  not been run on a VM.
- Registry enforcement: Ex and non-Ex open/create, single/multi-value query,
  enumerate, set, delete, correctly resolved rename, load/save/restore and key
  security; per-value matching and WOW64 paths. Value names are copied exactly,
  including colons and trailing dots/spaces; unrepresentable names fail closed
  in block mode. Enumeration maps to the independent `enumerate` right, not
  `read`; `KEY_READ` and `GENERIC_READ`/`GENERIC_EXECUTE` request read and
  enumerate together. `RegNtPreEnumerateValueKey` carries no value name, so a
  key covered by any value-scoped deny refuses value enumeration in block mode:
  `RegEnumValue` returns the value data, not just its name.
- Object enforcement: process and thread handles, create and duplicate, dangerous
  rights stripped, kernel handles skipped, duplication in both directions. A
  duplicate whose object, source and destination are all unprotected is left
  untouched; only a duplicate with at least one protected endpoint is filtered.
- Raw storage: dynamic attachment to existing and later-arriving disk/volume
  interfaces, canonical device names via `ObQueryNameString`, PnP removal under
  a per-device `IO_REMOVE_LOCK` plus a global rundown reference, and a device
  decision for every protected-process raw open, read, write, device-control,
  internal-device-control and filesystem-control request. Only requests whose
  file object carries an empty remaining name (a handle opened directly on the
  disk or volume) are treated as raw; ordinary file creates and I/O belong to
  the minifilter. This closes the raw handle opened in audit mode, or before
  tracking, that would otherwise stay readable and writable after block mode
  starts. An unmatched device
  request is denied whenever the layer is active, independently of
  default-deny; only an explicit device allow rule permits it. The layer is
  unavailable for block-mode activation when no filter attached or an attach
  (including table exhaustion) failed. A post-activation failure leaves the layer
  degraded and fails protected decisions closed. Re-arm keeps working filters
  attached, retries interface enumeration, and clears degradation only after success.
- Control tool: `TRACK_PID` classification is performed by the driver. A confirmed
  policy non-match is `STATUS_NOT_FOUND` (the tool ignores it); an image-name or
  stored-image failure is `STATUS_UNSUCCESSFUL` and a full table is
  `STATUS_INSUFFICIENT_RESOURCES`, both counted as failures. Duplicate admission
  is success. Block activation rolls back on tracking failure; OFF and AUDIT still
  apply and report failures. Policy application prints the generation read back
  from the driver.
- WFP: ALE connect, listen and receive-accept callouts for IPv4/IPv6, static
  IP/prefix/port/protocol and connect/listen rules, loopback exception and
  audit/block behavior. IPv4 addresses are converted from the host-order number
  WFP supplies into the wire-order bytes rules carry before prefix and loopback
  matching.
- Launcher: AppContainer profile, root/temp ACL grant, private `TEMP`/`TMP`,
  `SECURITY_CAPABILITIES`, suspended launch, `REGISTER_LAUNCHER` followed by the
  driver `ADMIT_PROCESS` handshake, temporary `internetClient` capability for
  the compatibility spike.
- Tests: `kfilterctl self-test` (including rename-destination rights, exact
  registry value names, set-security subset behavior, GENERIC_EXECUTE mapping,
  IPv4 byte-order conversion, parsed per-address network rules, tracking-status
  classification, empty-path replay, volume identity classes, control-operation
  rights, image-name boundary matching and raw-device first-match cases),
  `kfilterctl check`, and a synthetic
  `tests/probe.cpp` (`kfilter-probe.exe`) for read/process/duplicate/child/
  spawn-read/delayed-read/registry/registry-multi/registry-enum/volume/
  directory/raw/pipe/network/rename/link/fsctl probes plus a `security` probe that
  re-applies the object's own DACL with `SetNamedSecurityInfoW` and a `duplicate`
  probe that duplicates a handle into a target pid, duplicates it back and reads
  through it, so stripped rights show up as a denial in all four directions. The
  `fsctl` probe opens with read+write, sleeps, then issues
  `FSCTL_GET_COMPRESSION` so an FSCTL on an already-open handle can be tried
  after a block-mode switch.
- INF: minifilter service model (`ServiceType=2`, `Dependencies=FltMgr`,
  `FSFilter Activity Monitor`).

## Not implemented or not validated

- `build.cmd`, `self-test` and `check` validate compilation, policy parsing and
  the shared matcher only. They do not validate runtime containment, AppContainer
  or real-client compatibility, signing, VM behavior, Driver Verifier, or
  anti-cheat compatibility.
- Rename/link source and destination authorization, set-security enforcement,
  the unmatched raw-device denial, raw read/write authorization on a handle
  opened before block mode, and the new read+write authorization of FSCTL/device
  control on an already-open handle are covered by offline self-test and probe
  fixtures only; no runtime run has exercised them. There is no per-control-code
  mapping, so a control operation on a read-only handle is denied in block mode
  until that is reviewed.
- The launcher registration, the block-mode refusal of a protected image
  started by anything but the registered launcher, and the block-mode refusal
  of a protected image whose package SID does not match the configured package
  are code-reviewed and build-verified only. So is the registry
  value-enumeration refusal for keys covered by a `value=` deny. All are VM
  steps in `docs/TEST_VM.md`.
- Children created indirectly through an unprotected broker (a service, COM/WMI
  activation, Task Scheduler) have an unprotected creator and declared parent,
  so the process callback never evaluates them and they run uncontained. Only
  direct child creation is checked.
- Reparse points and junctions inside an allowed tree are matched by the name as
  opened, not by the final target.
- File and registry handles duplicated in from an unprotected process are
  refused only by the missing-stream-context rule, not by an object callback:
  process and thread handles are the only object types under `ObRegisterCallbacks`.
- No driver load, VM run, Driver Verifier, signing, or install. `InfVerif /w` still
  reports the legacy non-PnP DIRID 12 destination; review it, do not treat it as a
  load blocker without a VM test.
- ALPC/COM payload mediation and tamper resistance against kernel-mode code
  that removes or bypasses callbacks are not implemented.
- AppContainer compatibility with the real client, GRAP, CEF overlay, NGS/BlackCat,
  the official Nexon Launcher, and elevation requirements is unknown. The launcher
  ACLs only the image directory and private temp; it is a spike.
- Driver WFP rules are static IP/prefix/port rules, not FQDN resolution, and the
  callout can only look up a pid, not a creation time, so pid reuse can
  misattribute a flow. The containment policy keeps `block-network off` until
  reviewed per-address allows are merged. Dynamic FQDN mediation is not
  implemented; the rule-generation script and actual address changes are untested here.
- There is no `kfilterd` service, no persistent job object, no automatic
  family-stop/audit recovery, and no tray/GUI. The one-shot launcher does not hold a
  kill-on-close job.
- Dynamic raw volume attachment is untested and may interfere with file-system
  stacks; test on a disposable VM before using it.
- The default and containment policies are audit mode. Block mode requires the
  audit loop and refuses configured layers that did not register.
- The monitor is not coupled to the branch; no monitor capture was replayed against
  this exact policy.

## Build

```bat
build.cmd
build\Release\tool\kfilterctl.exe self-test
build\Release\tool\kfilterctl.exe check policy\contain-policy.txt
```

Outputs:

- `build\Release\driver\kfilter.sys`
- `build\Release\driver\kfilter.inf`
- `build\Release\tool\kfilterctl.exe`
- `build\Release\tool\default-policy.txt` and `contain-policy.txt`
- `build\Release\tests\kfilter-probe.exe`

## VM test order

1. Sign and install on a disposable VM; verify `fltmc` altitude, service type and
   dependency.
2. `kfilterctl status`; start with `mode off`.
3. `kfilterctl default` or `policy policy\contain-policy.txt` in audit; watch.
4. Run `kfilter-probe` from inside the client tree for each operation; record
   expected allow/deny.
5. Run the real client under the monitor; review would-deny and missing-context
   counters before switching to block.
6. Only then test `kfilterctl launch` (AppContainer) and WFP; treat failures as gate
   failures, not policy tweaks.
