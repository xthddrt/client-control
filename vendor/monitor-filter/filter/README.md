# kernel-filter

> **v5 branch / ABI 5: built, not runtime-validated.** This branch adds independent
> operation rights, stream-handle decisions, process/token and AppContainer identity,
> registry value rules, dynamic device filtering, WFP callouts, risk-bearing
> rules, an AppContainer launcher, a shared matcher with `self-test`, and a synthetic probe. `build.cmd`,
> `self-test` and `check` are build and user-mode checks only: they do not validate
> runtime containment, AppContainer or real-client compatibility, signing, VM
> behavior, Driver Verifier, or anti-cheat compatibility. The driver has not been
> signed, installed, loaded or VM-tested. See `docs/IMPLEMENTATION_V4.md` before
> using it.

A Windows kernel driver that limits what one application is allowed to look at
outside its own data.

It was written for a case where a game client (and the anti-cheat injected into
it) read the full binaries of other running applications, enumerated hardware
through the registry, and queried volume serial numbers. This repository
contains the enforcement half of the monitor:

- `kfilter.sys` - minifilter + registry callback + process-handle callback +
  process-creation refusal, driven by an ordered rule list, default audit-only.
- `kfilterctl.exe` - loads a text policy, enables blocking, tracks running
  processes, prints recent decisions, runs the shared matcher self-test, and can
  launch a process under an AppContainer with a suspended admission handshake.
- `build\Release\tests\kfilter-probe.exe` - synthetic probe for file/process/child/
  registry/volume/directory/raw/pipe/network boundaries.
- `policy/default-policy.txt` - the policy derived from real captures of the
  client (see `docs/POLICY.md`).
- `policy/strict-policy.txt` - allowlist variant: deny every file and registry
  access outside the listed roots.
- `policy/contain-policy.txt` - containment by root and AppContainer package: the
  client must be started with `kfilterctl launch` so its process token carries the
  configured package SID. A normally started copy is refused in block mode. The
  contained family may only touch the client tree plus the Windows loader surface.
- `tools/Analyze-Reachability.ps1` - turns captures into a table of every
  outside program the client reached, and the rules that do not cover them yet.
- `tools/Build-Policy.ps1` - turns a monitor JSONL capture into a candidate
  policy and a report of what the application touched.
- `tools/Simulate-Policy.ps1` - replays a capture against a policy and reports
  rule hits plus what stays readable.

## Read this first

This is an enforcement driver. It is easy to break an application with it, and
it cannot win an arms race against a kernel-mode anti-cheat.

- **It is not a sandbox.** It filters file opens, registry access, volume
  information queries, process-handle access and raw-storage requests on
  attached disk/volume devices. It does not stop kernel-mode code, ALPC/COM, or
  an anti-cheat that removes or bypasses the callbacks.
- **The anti-cheat may notice.** Blocking a game's telemetry or process scan can
  cause it to fail, to terminate the game, or to treat the machine as tampered
  with. That can end in an account ban under the game's terms. Decide whether
  you accept that before running in block mode.
- **Audit mode exists for a reason.** The driver starts in audit mode: every
  rule that would deny is recorded and nothing is blocked. Review with
  `kfilterctl watch` before flipping to block.
- **Systems can break.** A wrong rule can stop the client from loading a DLL or
  reading a config file. Keep the recovery path in `docs/TEST_VM.md` at hand.
  Missing names/contexts and required-layer failures fail closed in block mode.
- **Test signing required.** The build output is unsigned. Use a disposable VM
  with test signing, or a properly signed build, and never disable driver
  signature enforcement on a production machine.

## What it enforces

| Layer | Mechanism | What a rule can do |
|---|---|---|
| Files/directories | minifilter pre-create and handle contexts | apply independent read/write/execute/delete/rename/enumerate rights |
| Volume identity | minifilter pre-query-volume-information | apply volume rules to volume/object-ID information queries |
| Registry | `CmRegisterCallbackEx` | apply key/value rules to open/query/multi-query/enumerate/set/delete/rename; `read` and `enumerate` are independent rights |
| Process inspection | `ObRegisterCallbacks` | remove terminate, create-thread, VM, duplication, set-information, query (thread limited-information included), context, impersonation and suspend rights from handles outside the protected set |
| Process creation | `PsSetCreateProcessNotifyRoutineEx` | apply ordered create rules and verify creator, parent and package identity |
| Raw disks/volumes | dynamically attached upper device filters | apply device rules to raw opens, reads, writes, device/internal-device control and filesystem control on handles opened directly on the disk/volume |
| Identity devices | upper filters on NSI, MountPointManager, SCSI, NDIS, HID and USB devices | deny protected creates and controls by default; exact counted device rules may relax one device or IOCTL |
| Pipes/mailslots | NPFS/MSFS create callbacks | apply pipe rules to ordinary and special create operations |
| Network | six WFP ALE callouts | apply IP/port/protocol rules to connect, listen and receive-accept |

Rules are evaluated **top to bottom, first match wins**. Allow rules must state
nonzero `rights=` and cover all requested rights. Legacy `data-only` maps to
read+write rights; a deny with read rights also matches a mixed read+execute open.
Allows for known identity channels, cross-process handles and network endpoints require
`risk=<reason>`; each use emits a separate RISK event in addition to its ALLOW event.
Device allows use `raw-device` implicitly and also require an exact device name,
`uses=N` (on Linux not where only rules decide, see docs/LINUX.md), and optionally a
canonical `value=0x........` IOCTL.

## Build

Requirements: Visual Studio 2022 with the WDK (kernel mode driver toolset) and
Windows SDK 10.0.26100.

```bat
build.cmd
```

Outputs:

- `build\Release\driver\kfilter.sys`
- `build\Release\driver\kfilter.inf`
- `build\Release\tool\kfilterctl.exe`
- `build\Release\tool\default-policy.txt` and `contain-policy.txt`
- `build\Release\tests\kfilter-probe.exe` and `kfilter-idprobe.exe`

No signing, installation or service creation is performed by the build.

## Install (test VM)

1. Test-sign `kfilter.sys` (or use a properly signed build) and install the INF
   so the minifilter instance and altitude `385700` are registered.
2. `sc.exe create kfilter type= kernel binPath= C:\path\kfilter.sys` and
   `sc.exe start kfilter` if you are not using the INF.
3. Confirm the device answers:

```bat
kfilterctl.exe status
```

## Use

```bat
:: 0. Validate a policy file without loading the driver.
kfilterctl.exe check policy\default-policy.txt

:: 1. Load the policy in audit mode (the file says "mode audit").
kfilterctl.exe default

:: 2. Watch what blocking would do. Nothing is denied yet.
kfilterctl.exe watch 30

:: 3. Start the client, then track it if it started before the policy.
kfilterctl.exe track

:: 4. When the audit output is only what you expect to block:
kfilterctl.exe on
kfilterctl.exe watch 30

:: 5. Stop enforcing, or stop the driver.
kfilterctl.exe off
sc.exe stop kfilter
```

There is also an allowlist variant, `policy/strict-policy.txt`, which permits
only the client tree, its publisher, the Windows loader paths and the minimum
registry surface, and denies every other file and registry access, including
non-PE data. It has to be grown in audit mode; see `docs/POLICY.md`.

`kfilterctl status` reports mode, rule and protected counts, tracked processes,
allow/deny/audit counters and how many decision events were dropped. The decision
ring is a single-consumer drain: do not run `kfilterctl watch` or `clear` while
`msmon-agent` is collecting KFilter decisions.

## Policy format

One directive per line, `#` comments, fields separated by `|` so paths with
spaces work:

```
mode audit
root C:\Nexon\Library\maplestorycw
appcontainer MapleStoryCW
protect \MapleStory.exe
block-files on
block-registry on
block-volume-serial on
block-process-memory on
block-process-create on
block-network off

allow|file|\Device\HarddiskVolume*\Nexon\Library\maplestorycw|rights=read,write,execute,delete,rename,set-security
allow|file|\Device\HarddiskVolume*\Windows\System32|rights=execute|ext=dll
deny|file|\Device\HarddiskVolume*\Program Files|ext=exe,dll,sys,ocx|data-only
deny|registry|\REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Enum
audit|registry|\REGISTRY\MACHINE\SOFTWARE\Microsoft\SystemCertificates

allow|process|\Device\HarddiskVolume*\Nexon\Library\maplestorycw|rights=create
deny|process|\Device\HarddiskVolume*
deny|process|\SystemRoot\*
```

- `*` matches any characters; it is the only wildcard. `\Device\HarddiskVolume*`
  handles the volume number changing between boots.
- `root <path>` sets a containment root. `appcontainer <profile>` also requires
  the derived package SID on admitted and inherited processes.
- `rights=` is required and nonzero for every allow. Available rights are
  `read`, `write`, `execute`, `delete`, `rename`, `set-security`, `enumerate`,
  `create`, `connect`, `listen` and `raw-device` where applicable.
  Deny/audit rules default to all rights when omitted; on Linux that excludes
  `lock`, `chdir` and `touch` (named only), and a `pipe` deny or audit without
  `rights=` excludes `listen`.
- `ext=exe,dll,sys,ocx,other` restricts a file rule by extension class.
- Legacy `data-only` means read+write rights, not an exemption for mixed
  read+execute opens. `execute-only` means execute rights.
- `audit` rules always allow and record. `deny` rules block in `mode block` and
  record `WOULD_DENY` in `mode audit`.
- Process rules use the create right in first-match order. Both actual creator
  and declared parent must be protected for family inheritance.
- Paths are NT paths (`\Device\HarddiskVolume3\...`, `\REGISTRY\...`), not
  `C:\...`.

## Static network policy

The containment policy ships with `block-network off` because no endpoint
addresses have been reviewed. Enable it only after merging reviewed per-address
allow rules and setting `network-default deny`. Dynamic FQDN mediation is not
implemented. Generate a candidate fragment with:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\Install-NetworkPolicy.ps1 `
  -StaticAddresses 203.0.113.10/32 -Port 443 -Protocol tcp -Out network-policy-rules.txt
```

Review and merge the fragment into the policy and run `kfilterctl check`. No
runtime installation, firewall change, or network validation is performed by the build.

## Analysing a capture

`tools/Analyze-Reachability.ps1` takes one or more monitor captures (rotation
parts are picked up automatically) and reports, per outside program, how the
client reached it: executed, loaded as a module, or file read/open. For each
target it evaluates the current policy and prints candidate rules for anything
uncovered.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\Analyze-Reachability.ps1 `
  -Log "C:\msmon-logs\00-baseline-v2.jsonl;C:\msmon-logs\01-manual-supported.jsonl" `
  -Policy policy\default-policy.txt -Out reachability.md -OutPolicy rules.txt
```

Pass several captures separated by `;` in one argument. The report also lists
each session's dropped-event count, because a capture with a high drop count
cannot be treated as complete coverage.

## Limits worth knowing

- Pure execute-only opens do not request read/write rights, but a mixed
  read+execute open matches a read deny. This is a policy boundary, not a way
  to distinguish every loader access from an intentional file hash.
- Registry rules gate access, not content: a key opened before the policy was
  applied is covered by the query/enumerate classes, but a handle opened with
  full access elsewhere in the same process is not retroactively revoked. A
  read allow does not grant enumeration; grant `enumerate` explicitly.
- Raw-disk filtering covers the disk and volume devices the driver could attach
  to. If any attach fails (including table exhaustion) the disk layer reports
  itself unavailable, so block mode refuses to activate rather than leaving a
  disk unprotected.
- Process memory blocking only removes access at handle creation; it does not
  stop a process that already holds a read handle.
- Process creation: only images under the client's own tree may be started;
  `ROUTE.EXE`, `chrome.exe`, `WerFault.exe` and helpers from outside
  directories are refused. Blocking `WerFault` also means no crash dumps while
  it is active. In block mode a protected image started from outside the family
  is refused unless the creator is the launcher registered by
  `kfilterctl launch`, so double-clicking or a scheduled task cannot start an
  uncontained copy. A protected-name image whose AppContainer SID does not
  match the configured package is refused in block mode as well.
- Children created through an unprotected broker (a service, COM/WMI activation,
  Task Scheduler) are attributed to the broker, not to the client, and are not
  contained. Only direct child creation is checked.
- WMI, DX diagnostics and adapter/session enumeration are blocked by refusing to
  load `wbemprox`/`fastprox`/`dxdiagn`/`wlanapi`/`dhcpcsvc`/`wtsapi32` into the
  client (contain policy). That is module-level, not a general RPC block.
- CPUID, MSR and direct firmware-table queries (`NtQuerySystemInformation`)
  remain outside the driver's reach.
- Driver network rules use static addresses, not DNS names. An allow must name
  one host (/32 or /128), port, tcp or udp, `rights=connect`, `uses=N` and `risk=`;
  ranges are for deny rules only. The containment
  policy leaves network blocking off until reviewed per-address allows are added;
  dynamic FQDN mediation is not implemented.
- Standalone minifilter detach is allowed; `fltmc unload` and service stop can
  both unregister the filter. Runtime unload behavior has not been validated.

## Linux

The same repository builds for Linux (Ubuntu 24.04, kernel 7.0), with the client run
under Wine 11. `kfilterd` replaces the driver. Its main layer is a BPF LSM program that
decides every operation of the protected programs in the kernel; fanotify, the proc
connector and nftables remain as a fallback. It reuses `driver/policy.c`,
`driver/events.c` and `driver/match.c`, so the policy language and decisions are the
same, with Linux paths for files.

Under Wine the BPF layer decides what the Windows program does, not what Wine does for
it:

- **Opens, connects and memory access by Wine's processes.** wineserver's file opens,
  socket connects, memory reads and signals, and winedevice's device work, are charged
  to the program they serve.
- **Registry.** Registry rules are enforced from the program's requests to wineserver.
- **Naming.** Every process is named by its Windows image (`MapleStory.exe`). Rules can
  be scoped to one program with `image=`, and `protect` takes Windows program names.
- **Messages.** Every message the game sends on an allowed connection can be decided on
  its own (`message` rules: peer, size, position, byte pattern, program, and the DLL whose code made the call). A single live
  connection can be cut with `kfilterctl block-connection`.

Thread-handle and thread-open rules are decided on Wine's thread requests by the BPF layer
(a refusal fails the whole request; Wine cannot strip rights).

```sh
./build.sh
sudo build/linux/kfilterd &
sudo build/linux/kfilterctl policy policy/linux-default-policy.txt
sudo build/linux/kfilterctl launch /opt/wine-stable/bin/wine 'C:\path\MapleStory.exe'
```

Built and unit-checked. The root tests (`tests/linux_lsm_test.sh`,
`tests/linux_launch_test.sh`, `tests/linux_wine_test.sh`) check it at runtime; it has not
been run against the real client. See `docs/LINUX.md` for the layer map, policy
differences and limits.

## Documentation

- `docs/DESIGN.md` - architecture, decision path, lifetime and IRQL rules.
- `docs/POLICY.md` - what the capture showed and why each default rule exists.
- `docs/TEST_VM.md` - the validation and recovery procedure.
- `docs/LINUX.md` - the Linux build: kfilterd, policy differences and limits.
