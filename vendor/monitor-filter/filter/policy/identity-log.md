# kfilter strict run: identity log

Started 2026-10-31 (zero-relaxation run after the 21:51 reboot). Owner's rule: anything that
would let the game or its subprograms identify the machine or user stays blocked no matter
what; every relaxation is checked for identity before it is approved, and every possible
identity issue is recorded here. After every captured run, append its evidence with:

```bat
python ..\monitor\tools\analysis\identity_log.py --bundle <session-bundle> --policy policy\default-policy.txt --out policy\identity-log.md
```

Severity:
- **none**: the relaxation gives the game no information about the machine or user.
- **flag**: the relaxation itself exposes nothing, but it enables code or a channel that can
  gather identity; whatever that code asks for through files or the registry is still filtered.
- **exposed**: the relaxation lets identifying data reach the game. (None so far.)

## Hard blocks (never relaxed)

46 deny rules ahead of every relaxation in `default-policy.txt` (first match wins):
MachineGuid; ComputerName; Tcpip host/domain values; Tcpip and Tcpip6 interface keys;
NetworkList; network-adapter class keys; HARDWARE\DESCRIPTION, ACPI and DEVICEMAP; device Enum;
MountedDevices; IDConfigDB; SystemInformation; Windows product ID, digital product IDs,
install date/time, registered owner/organisation; ProfileList; Winlogon default user/domain;
NetworkCards; Windows Update SusClientId; machine/user DiagTrack; SQMClient; MountPoints2;
Valve, Blizzard/Battle.net, Epic, Riot, EA, Ubisoft and XboxLive account keys; the user's
Volatile Environment, IdentityCRL, User Shell Folders, Shell Folders; the four WMI client DLLs;
volume serial number; raw disk and NSI access. Network is default-deny with no standing allows.

## Outside kfilter's reach (cannot be blocked by any kfilter rule)

| Channel | What it can reveal | How it gets out |
|---|---|---|
| CPU instructions (CPUID/MSR) | CPU model, features, some IDs | no OS call at all |
| Firmware tables (NtQuerySystemInformation) | SMBIOS: BIOS, board, system serials | system call, not a file or registry open |
| GPU adapter APIs | GPU and display-device identifiers | graphics API, not a file or registry open |
| Process/module lists | running software and loaded modules | system/window enumeration without another process handle |
| Windows services over RPC/ALPC (wtsapi32, netapi32, hand-written RPC, ...) | logged-on user name, computer and domain name, hardware data | the service reads it and answers; kfilter sees neither |
| Device opens outside file systems (HID, ...) | device identifiers | not on a filtered volume |
| Anything the anti-cheat driver collects in the kernel | anything | kernel code; outside kfilter's scope |

## Relaxations and their identity assessment

| Step | Relaxation | Identity | Note |
|---|---|---|---|
| Z1 | launcher (nexon_client) thread + process handles to the game, full, 1 each | none | access INTO the game; reduces isolation, not identity |
| Z1, Z5, Z11 | csrss process handle full ×10, thread handle full ×6 | none | Windows subsystem registering/connecting the game; access INTO the game |
| Z2 | csrss vm-read of the game ×1 | none | Windows reads the game's memory |
| Z3 | Appinfo (svchost, SYSTEM) may start the game ×1; launch pass 2 starts | none | who may start the game; the elevated copy runs as administrator (all its requests still filtered) |
| Z4 | Appinfo thread + process handles to the elevated copy, full, 1 each | none | access INTO the game |
| Z6–Z7 | winmm.dll, WzMss.dll find + map | none | program code |
| Z6–Z7 | MachineIdLib.dll find + map | **flag** | the game's machine-ID library: its file/registry reads stay filtered (identity keys hard-denied); it can still use the out-of-reach channels above |
| Z8–Z10 | nexon_api_x64.dll find + map | none | program code |
| Z9–Z10 | HKLM\...\CurrentVersion\SideBySide, read+enumerate, exact, ×14 | none | component-store settings |
| Z18 | SideBySide\AssemblyStorageRoots, enumerate, exact, ×2 | none | component-store locations |
| auto | CrashReporter.dll, libcurl.dll, NxOverlay_x64.dll, steam_api64.dll, ZLZ64.dll find + map | none | game program code |
| Z21, Z26 | WinSxS common-controls and gdiplus folders, traverse, exact, 1 each | none | Windows component folders, traverse only (cannot list) |
| auto | comctl32.dll, GdiPlus.dll (WinSxS) find + map | none | Windows program code |
| auto | wininet.dll find + map ×2 | none | Windows internet library; network is still fully blocked |
| auto | IPHLPAPI.DLL find + map | **flag** | IP helper: can read adapter details incl. MAC through the network service (out of reach) |
| auto | grap64.dll find + map | **flag** | the anti-cheat: will try to fingerprint; file/registry reads stay filtered |
| auto | pdh.dll find + map | **flag** | performance counters: can list running processes and hardware counters |
| auto | hid.dll find + map | **flag** | HID devices: device opens may be outside kfilter; device-ID keys (Enum) are hard-denied |
| auto | tdh.dll find + map | none | event-trace decoding |
| auto | wtsapi32.dll find + map | **flag** | session API: can ask a Windows service for the logged-on user name (RPC, out of reach) |
| auto | dinput8.dll find + map | none | input |
| auto | netapi32.dll find | **flag** | network management API: can ask Windows services for computer, domain and workgroup names (RPC, out of reach) |

## Denied and never relaxed (the game got past them)

PcaSvc's access to the game; Appinfo handing the elevated copy's handles back to the
launcher; Defender's and ipf_helper's queries of the game; apphelp.dll; MUI policy settings;
the user hive's root; Session Manager and other early loader registry reads.

## Automatic additions

Rows below are appended by the step automation (one per DLL it relaxes) and reviewed.
| auto | netapi32.dll map | **flag** | network management API: computer/domain names via Windows services (out of reach) |
| auto | nmcogame64.dll find | none | program code (Nexon messenger/game module; its network use is blocked) |
| auto | version.dll find | none | program code |
| auto | nmcogame64.dll (map) | none | program code |
| auto | version.dll (map) | none | program code |
| auto | libcrypto-3-x64.dll (find) | none | program code |
| auto | libssl-3-x64.dll (find) | none | program code |
| auto | bcrypt.dll (find) | none | program code |
| auto | libcrypto-3-x64.dll (map) | none | program code |
| auto | libssl-3-x64.dll (map) | none | program code |
| auto | bcrypt.dll (map) | none | program code |
| auto | vcruntime140.dll (find) | none | program code |
| auto | dxgi.dll (find) | none | program code |
| auto | D3DX9_43.dll (find) | none | program code |
| auto | vcruntime140.dll (map) | none | program code |
| auto | D3DX9_43.dll (map) | none | program code |
| auto | dxgi.dll (map) | none | program code |
| auto | sspicli.dll (find) | **flag** | security API: can return the logged-on user name |
| auto | powrprof.dll (find) | none | program code |
| auto | sspicli.dll (map) | **flag** | security API: can return the logged-on user name |
| auto | netutils.dll (find) | none | program code |
| auto | powrprof.dll (map) | none | program code |
| auto | netutils.dll (map) | none | program code |
| auto | umpdc.dll (find) | none | program code |
| auto | msasn1.dll (find) | none | program code |
| auto | umpdc.dll (map) | none | program code |
| auto | msasn1.dll (map) | none | program code |
| Z27 | HKLM root key itself, exact, requested rights (incl. write) x19 | none | root key holds no values; every key opened through it is still checked by full path; ComputerName etc. stay hard-denied |
| Z28 | WinSock2\Parameters (CurrentControlSet name), exact, read+write+delete+set-security+enumerate x1 | none | protocol-catalog settings only; write limited to this key (integrity, not identity); network still blocked |
| Z29 | WinSock2\Parameters (ControlSet001 name), same rights x1 | none | same key as Z28 under its other name |

## Current risk= rules

Every risk-bearing rule in `default-policy.txt`; read/find and execute/map entries are listed together.
Each use emits a separate RISK event in addition to the ordinary ALLOW event.

| Rule(s) | risk= | Why flagged |
|---|---|---|
| Launcher process + thread handles, full ×1 each | cross-process-handle | handle crosses a process boundary |
| csrss process handle full ×10 and thread handle full ×6 | cross-process-handle | handle crosses a process boundary |
| csrss process handle vm-read ×1 | cross-process-handle | handle crosses a process boundary |
| Appinfo process + thread handles, full ×1 each | cross-process-handle | handle crosses a process boundary |
| IPHLPAPI.DLL find + map | adapter-mac | adapter/MAC APIs remain available outside NSI's covered queries |
| grap64.dll find + map | anti-cheat | anti-cheat fingerprinting and kernel component |
| pdh.dll find + map | process-list | performance counters can enumerate processes and hardware |
| hid.dll find + map | device-id | HID device identifiers may be reached outside filtered volumes |
| wtsapi32.dll find + map | session-user | WTS RPC can reveal session user/domain information |
| netapi32.dll find + map | host-name | workstation RPC can reveal computer/domain information |
| sspicli.dll find + map | user-name | security APIs can return the logged-on user |
