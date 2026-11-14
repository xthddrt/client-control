# Test procedure

The driver has not been run in kernel mode yet. `build.cmd`, `self-test` and
`check` are build/user-mode checks and say nothing about runtime containment,
AppContainer or client compatibility, signing, VM behavior, Driver Verifier or
anti-cheat compatibility. Do not first load the driver on a machine you care
about, and do not load it while the game is running.

## Prepare

1. Disposable Windows x64 VM, current snapshot, no production account signed in.
2. Visual Studio 2022 + WDK + Windows SDK 10.0.26100, then `build.cmd`.
3. Enable test signing in the VM, reboot, and sign `kfilter.sys` with a test
   certificate (or use a properly signed build). Do not disable Secure Boot.
4. Install `kfilter.inf` so the minifilter instance and altitude `385700` are
   registered, or create the service manually:
   `sc.exe create kfilter type= kernel binPath= C:\kfilter\kfilter.sys`.

## Load and baseline

```bat
sc.exe start kfilter
kfilterctl.exe status
```

Expect `mode: off`, `registered: minifilter registry object process`, plus
`disk` and (when the WFP callouts registered) `network`. If `minifilter` is
missing, the driver will not have loaded: check altitude conflicts and the INF
install. If `disk` is missing, at least one disk/volume attach failed; block
mode will refuse to activate until that is resolved.

## Audit first

```bat
kfilterctl.exe default
kfilterctl.exe status
kfilterctl.exe watch 60
```

- Start the client with no policy enforcement expected: `mode: audit`, counters
  `denied=0`.
- Confirm the audit stream shows the rules you expect (`WOULD_DENY`), and that
  `tracked processes` covers the client and its children (`grap-core64.aes`,
  `DwarfAxe.exe`).
- If nothing is tracked, run `kfilterctl.exe track` after the client starts.

## Then block

```bat
kfilterctl.exe on
```

Verify:

1. `kfilterctl.exe watch 60` while the client starts and logs in. Denied file
   creates should be for other applications' binaries and driver images, not for
   the client's own tree or `System32\*.dll`.
2. The client still reaches its login screen and can play. If it fails to start,
   switch back with `kfilterctl.exe audit` and find the first denied path that
   the client needs (usually a DLL or config under a path the allow list misses).
3. Volume serial blocking: query the volume serial from the protected process
   and confirm `STATUS_ACCESS_DENIED`; querying size/attributes still works.
4. Process memory: from the protected process, opening another process with
   `PROCESS_VM_READ` must succeed with that access removed; reading through it
   must fail. `PROCESS_QUERY_LIMITED_INFORMATION` must still work.
5. Registry: a denied prefix returns access denied; the client's own
   `HKCU\Software\Wizet` access still works. With an allow that has only
   `rights=read`, `RegQueryValueExW` still works but `RegEnumKeyExW` /
   `RegEnumValueW` must fail; add `rights=enumerate` to permit enumeration.
   With `contain-policy.txt` in block mode, run
   `kfilter-probe.exe registry-enum "SOFTWARE\Microsoft\Windows NT\CurrentVersion" ProductId`:
   it must be denied even though the key has a read+enumerate allow, because a
   `value=` deny covers the key and `RegEnumValue` returns value data. In audit
   mode the same call must succeed and log a registry WOULD_DENY.
6. Process creation: add a temporary `protect \cmd.exe` to the policy, start
   `cmd.exe`, and run `notepad.exe` from it. In block mode the child must fail
   with access denied and appear as a `process` deny in
   `kfilterctl.exe watch`; its own tree (`%SystemRoot%\System32\...`) is what the
   default rules deny, so use a policy that allows `\Device\HarddiskVolume*\`
   for the test if you need a positive control.
7. Start the client in block mode and confirm its own helpers (`grap`,
   `DwarfAxe.exe`) still start. If they do not, the process allow rule for the
   client tree is wrong or the images moved.
8. Crash handling: with `deny|process|\SystemRoot\*` active, `WerFault.exe`
   cannot start from the client, so no crash dumps are produced. Decide whether
   that is acceptable before filing a bug report.
9. Containment root: load `policy\contain-policy.txt` and start the client with
   `kfilterctl.exe launch C:\Nexon\Library\maplestorycw\<client.exe>`. Confirm in
   `kfilterctl.exe status` that the launched process and its approved children
   are tracked without any `protect` entry. Starting the same image normally
   must be refused in block mode because it lacks the launcher admission and
   required AppContainer SID. Then check that a denied read inside the client
   returns access denied only for paths outside the tree.
10. Raw disk: from a protected process, `CreateFile("\\.\PhysicalDrive0", ...)`
    must fail in block mode and appear as a `device` deny in `watch`. Use a test
    program rather than the client. Also open `\\.\C:` and confirm a
    `DeviceIoControl(IOCTL_STORAGE_QUERY_PROPERTY)` and
    `IOCTL_DISK_GET_DRIVE_LAYOUT_EX` are denied, and that an explicit
    `allow|device|...|rights=raw-device` rule permits the named device.
    Confirm normal disk I/O (copy a large file) is unaffected while the filter
    is attached.
    Handle transition: in audit mode run `kfilter-probe.exe raw \\.\C: 15000`
    from the protected tree, switch to block mode before the delay expires, and
    confirm the read after the delay is DENIED. A handle opened before block mode
    must not stay usable.
    Control-operation transition: open a client-tree file with read+write in
    audit mode, run `kfilter-probe.exe fsctl <path> 15000`, switch to block
    before the delay expires, and confirm the FSCTL is DENIED. FSCTL
    authorization (read+write, no per-control-code mapping yet) is not runtime
    validated here.
11. WMI: from a protected process, a `Get-WmiObject Win32_BIOS` call must fail
    or return nothing because `wbemprox.dll` cannot load; check `watch` for the
    module deny. Confirm the client still starts and logs in.
    Run `kfilter-idprobe.exe` inside the protected family: every disk, NSI, NDIS,
    MountPointManager, SCSI and HID route must be BLOCKED, while SMBIOS, the token
    machine SID and CPUID are FLAG. The same probe outside the family is the
    positive control. Block activation must refuse when the device layer is degraded.
    Every use of a risk-bearing allow must produce a separate RISK event with the
    same rule ID and object path as its ALLOW event.
12. Unload: stop and start the driver ten times with the disk and device filters attached.
    No bugcheck and no hung unload; `verifier /standard /all /driver kfilter.sys`
    must stay clean.
    Also hold a control call in flight across the unload. With a degraded disk layer
    (one volume or disk attach failed, `status` shows `degraded: raw-disk`), run
    `kfilterctl policy policy\default-policy.txt` in a loop while stopping the
    service: each call must either succeed before the drain or fail cleanly, and no
    device-interface arrival afterwards may bugcheck. The source order that keeps this safe:
    in-flight control IRPs are drained before any layer is torn down, and
    `KfDiskUninitialize` clears `gDiskDriver` so a late rearm cannot register
    notifications against the unloaded driver.
13. Audit-to-block admission: in audit mode, run the probe from the protected
    tree and use `spawn-read <outside-probe> 15000 <outside-readable-file>` to
    start a child whose image the process rules deny. Confirm the audit deny,
    switch to block before the delay expires, and confirm the child was never
    added to the tracked family. Its delayed read must remain ALLOWED: a denied
    read means the audit-only child was incorrectly promoted into containment.
14. Duplication: start the probe inside and outside the protected tree and choose
    running protected and unprotected target PIDs. Run `duplicate <target-pid>`
    for all four directions. Outside-to-outside and protected-to-protected must
    be ALLOWED with the read access intact; outside-to-protected and
    protected-to-outside must be DENIED because the cross-family handle loses
    `PROCESS_VM_READ` (or the required duplication access).
15. Launcher-scoped creation: in block mode, start the client image directly
    from Explorer or `cmd` (no `kfilterctl launch`). The create must fail with
    access denied and appear as a `process` deny. Then run
    `kfilterctl.exe launch <exe>`: it must still start, the process must appear
    in `status`, and a second copy started through an unprotected broker (for
    example a scheduled task) must fail. Exit and restart `kfilterctl` and
    confirm a stale registration is not accepted (the stored launcher process
    is gone, so a direct launch fails again).

## Lifecycle

1. `kfilterctl.exe off`, then `sc.exe start`/`stop` the driver ten times while
   `kfilterctl.exe watch` is running in another window. No bugcheck, no hung
   unload.
2. `fltmc unload kfilter` must succeed and leave no registered minifilter or
   control device. Restart with `sc.exe start kfilter` and repeat the check.
3. Kill `kfilterctl` while it holds the device open; the driver must stay loaded
   and answer a new `status`.

## Driver Verifier

```
verifier /standard /all /driver kfilter.sys
```

Repeat load, audit, block, stop. Address every finding before moving on:
pool leaks on the config swap, IRQL violations in the minifilter pre-op, and
object callback lifetime are the likely ones.

## Recovery

If the client breaks or the machine misbehaves:

```bat
kfilterctl.exe audit
kfilterctl.exe off
sc.exe stop kfilter
```

If the driver is running but the tool cannot open the device, boot the snapshot;
the policy is in-memory only and does not survive a reboot.

## What to report back

Keep the `kfilterctl status` output, a `watch` excerpt around the first failure,
and the exact rule that was active. Those three make a bad policy reproducible;
the driver itself has no persistent state.
