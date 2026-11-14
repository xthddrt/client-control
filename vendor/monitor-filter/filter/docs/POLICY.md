# Policy rationale

The default policy comes from monitor captures of the client, not from a
generic template. This page records the measurements so a rule can be traced
back to observed behaviour.

## Captures reviewed

| capture | parts | records | driver drops | notes |
|---|---|---|---|---|
| `00-baseline.jsonl` | 3 | 257,710 | not reported | Session ended without a summary |
| `00-baseline-v2.jsonl` | 2 | 460,053 | 117,736 | Summary present; the extract used earlier came from this session |
| `01-manual-supported.jsonl` | 1 | 344,590 | 111,027 | Summary present |
| `02-wdac-blackcat.jsonl` | 2 | 383,269 | not reported | Stopped without a summary |
| `direct-launch-attempt.jsonl` | 1 | 19,358 | not reported | Short launch attempt, includes browser launch |

Coverage limits that apply to every capture:

- **Object callbacks were unavailable** in all five sessions, so process and
  thread handle opens are not observable. Handle-based reaches are not in the
  data at all.
- **WFP network callbacks were unavailable**, so there are no connect/accept
  events; only ETW DNS/RPC/WMI records exist.
- **`BlackCat64.sys` was never loaded** (`blackcat_not_loaded`, device discovery
  matches=0), so no kernel anti-cheat attribution was possible.
- Two sessions report roughly 110k dropped driver events each. Counts below are
  therefore lower bounds, and a 250 MB capture is not complete coverage.

The first session analysed (`134336946412071800`, `00-baseline-v2`) covered
12:42:55Z to 12:44:54Z and is the source of the per-event numbers elsewhere in
this document.

## Observed file access

`MapleStory.exe` issued 142,562 of the session's 143,006 read events and read
587 MB in 4 KiB IRPs. The reads were sequential whole-file walks of other
applications' binaries:

| Target | Reads | Approx. bytes | Notes |
|---|---|---|---|
| `...\AppData\Roaming\ai.opencode.desktop\cli\...\opencode-cli.exe` | 33,104 | 247 MB | offsets 0 to 246,919,560, step 4,096 |
| `...\AppData\Local\Programs\@opencodedesktop\OpenCode.exe` | 29,840 | ~122 MB | whole file |
| `...\AppData\Local\Programs\Kimi Code\Kimi Code.exe` | 26,834 | ~110 MB | whole file |
| `...\Program Files (x86)\Nexon\Nexon Launcher\...\nexon_client.exe` | 18,615 | ~76 MB | same publisher |
| `...\WindowsApps\Microsoft.GamingApp...\GameBar.exe` and widgets | 7,062 | | overlay detection |
| Claude `cowork-svc.exe`, Defender `NisSrv.exe`, Edge, Edge WebView, Chrome, Acer Care Center | ~8,000 | | other running applications |
| `...\Windows\System32\vmcompute.exe`, `vmwp.exe` | 1,544 | | VM detection |
| `...\Windows\System32\drivers\*.sys`, `DriverStore` | 6,165 | | driver inventory |
| `...\Windows\System32\explorer.exe`, `winlogon.exe`, `services.exe`, `smss.exe`, `audiodg.exe`, `spoolsv.exe`, ... | ~2,600 | | running-process inventory |

This is why the policy denies data reads of `exe,dll,sys,ocx` under other
vendors' trees and specifically under `Windows\System32\drivers` and for
`System32\*.exe`, while allowing `System32\*.dll` so image loads keep working.

The client also read `\Windows\System32\drivers\etc\hosts` and
`...\spool\drivers\color\sRGB Color Space Profile.icm`; both are left to the
generic rules (hosts is under `System32` and is not an `exe`, so it is allowed).

## Outside programs reached (all five captures)

`tools/Analyze-Reachability.ps1` defines a reach as one of: the client executes
another image, loads another image into itself, or opens/reads another
program's files. Aggregated over all captures:

| outside program | kind | events | MB read | policy |
|---|---|---|---|---|
| Kimi Code | Program | 101,825 | 394.7 | deny |
| Nexon Launcher | Program | 89,787 | 342.2 | deny (see note) |
| OpenCode desktop | Program | 81,375 | 315.2 | deny |
| ai.opencode.desktop | AppData | 74,020 | 288.7 | deny |
| Intel (LocalLow cache) | AppData | 61,006 | 1.2 | deny |
| Microsoft Edge | Program | 12,107 | 41.0 | deny |
| Xbox Game Bar overlay | Store app | 10,902 | 41.2 | deny |
| Office ClickToRun | Shared | 8,426 | 31.9 | deny |
| Xbox Gaming App | Store app | 8,350 | 32.1 | deny |
| Host App Service | AppData | 7,354 | 28.0 | deny |
| Windows Defender | ProgramData | 7,325 | 23.6 | deny |
| Google Chrome | Program | 5,659 | 9.4 | deny |
| `D3DSCache` | AppData | 5,280 | 3.1 | **allow** |
| ExpressVPN | Program | 5,035 | 15.0 | deny |
| `storport.sys` | Driver | 4,648 | 0.0 | deny |

Executed by the client: `System32\ROUTE.EXE` (4 launches across the captures,
parent `MapleStory.exe`), `Program Files\Google\Chrome\Application\chrome.exe`
(1) and `System32\WerFault.exe` (1), both from the direct-launch capture.
Loaded into a client process: Defender's `MpOAV.dll` (8 loads) and Nexon's
`nexon_x64.dll` (4). Both are now denied as data reads; image-load rules are
separate, so the loader still works where the policy allows it.

Per-process attribution:

| client process | reaches |
|---|---|
| `MapleStory.exe` | Everything above except the Chrome rows; Kimi 101,089, Nexon 88,070, OpenCode 80,725, ai.opencode 73,942, Intel 61,006 |
| `grap-core64.aes` | Google 3,140, Nexon 2,274, Microsoft 2,209, Git 2,003, Visual Studio 1,730 |
| `grap-updater.aes`, `DwarfAxe.exe` | low hundreds each |

So the binary scanning is not only the game process: GRAP's `grap-core64.aes`
also reads other vendors' binaries, and DwarfAxe reads its own overlay data.

Two notes on the policy:

- `D3DSCache` is allowed on purpose. It is the client's own Direct3D shader
  cache; denying it forces a recompile on every launch and stutters without
  blocking any outside program.
- The Nexon Launcher reads (89,787 events, 342 MB) were previously allowed as
  "publisher". The allow was removed: the launcher is a different program, and
  its binaries are now treated like any other vendor's. Pure execute-only
  opens do not match the read+write denies, but mixed read+execute opens do.

The same data contained 36 opens of `\Device\Harddisk0\DR0` by client
processes. A minifilter cannot see those raw-device opens, so `disk.c` now
attaches upper filters to existing and later-arriving disk/volume interfaces
and applies device rules to identity-bearing operations.

No rule candidates were left uncovered: every reach above is matched by a deny
rule except `D3DSCache`, which is explicitly allowed.

## Host identity reached outside the file allow list

Three vectors were visible in the captures and needed mechanisms beyond a
minifilter. All three are now enforced.

### Raw physical disk

`grap-core64.aes` opened `\Device\Harddisk0\DR0` with access `0x12019F`
(read/write plus attribute rights) seven times, and every open succeeded. On
those handles:

| IOCTL | meaning | results |
|---|---|---|
| `0x2D1400` | `IOCTL_STORAGE_QUERY_PROPERTY` (device descriptor) | 7 succeeded, 7 failed |
| `0x7C088` | `SMART_RCV_DRIVE_DATA` (identify data) | 4 failed |

`IOCTL_STORAGE_QUERY_PROPERTY` returns the storage device descriptor, which
contains the disk serial number. A minifilter never sees these IRPs, so a small
upper filter is attached to `\Device\HarddiskN\DR0`; it refuses opens from
protected processes and passes everything else through.

### WMI and diagnostic DLLs

152 ETW WMI events from the client, in `\\.\ROOT\CIMV2` and
`ROOT\SecurityCenter2`. The second namespace is the anti-virus/firewall product
enumeration. The proxies that implement the query are loaded into the calling
process:

| module | loads | what it enables |
|---|---|---|
| `wbemprox.dll` | 8 | WMI queries |
| `fastprox.dll` | 8 | WMI object marshalling |
| `dxdiagn.dll` | 4 | DirectX diagnostic hardware data |
| `wlanapi.dll` | 7 | wireless adapter enumeration |
| `dhcpcsvc.dll` / `dhcpcsvc6.dll` | 21 / 13 | DHCP/interface configuration |
| `wtsapi32.dll` | 21 | session enumeration |
| `netapi32.dll` | 26 | network/session enumeration |
| `IPHLPAPI.DLL` | 29 | adapter enumeration (left allowed) |

The containment policy denies loading the first seven; `IPHLPAPI` is left alone
because socket setup and interface selection can depend on it, so adapter
enumeration through that path remains a residual.

### Not observable, therefore not claimed

CPUID, MSR reads and direct `NtQuerySystemInformation` firmware tables were not
intercepted in these captures. CPUID requires a hypervisor and firmware-table
interception would require a different mechanism. Network now has WFP callouts;
the supplied containment policy leaves driver IP blocking off until reviewed
per-address allows are merged. Dynamic FQDN mediation is not implemented.

## Observed registry access

| Prefix | Events | Decision |
|---|---|---|
| `HKCU\Software\Wizet` | 100,227 | allow (own settings) |
| `HKLM\SOFTWARE\Microsoft\Windows NT` | 2,570 | allow (version, AppCompat) |
| `HKLM\SYSTEM\ControlSet001\Services` | 2,387 | allow (WinSock/Dnscache only, by narrower rules) |
| `HKLM\SYSTEM\ControlSet001\Enum` | 1,161 | deny (PnP hardware IDs) |
| `HKLM\SOFTWARE\Microsoft\SystemCertificates` | 983 | audit (WinVerifyTrust may need it) |
| `HKLM\SOFTWARE\Microsoft\Cryptography` | 947 | audit (crypto OIDs) |
| `HKCU\Software\Microsoft` | 795 | unchanged |
| `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters` | ~200 | deny (network identity) |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices` | 166 | deny (audio device IDs) |
| `...\Explorer\FolderDescriptions`, `UserAssist`, `RecentDocs` | ~900 | deny (user activity) |
| `...\Uninstall` (both views) | not top-30 | deny (installed software) |
| `...\Control\Class\{4d36e968-...}` | 75 | deny (display adapter) |

The 94,667 failing queries under `HKCU\Software\Wizet` were the client's own
`uiWndX<id>` / `uiWndY<id>` polling loop, not a privacy problem: the key is
allowed so that loop is untouched.

## Observed volume and network

- 22 volume-information queries, classes 1 (volume information), 3 (size), 5
  (attributes) and 7 (full size). 84 decoded results, volume 3 serial
  `0xa8c881b5`.
- The policy denies classes 1 and 8 for protected processes only. Size and
  attribute queries still work, so disk-space checks are unaffected.

DNS lookups in the same session went to Nexon endpoints
(`x-csauth.ngs.nexon.com`, `public.api.nexon.com`, `config.na.nexon.com`,
`us-sso.nexon.io`, `x-init.ngs.nexon.com`, `x-config.ngs.nexon.com`,
`login-mscw.maplestory.nexon.net`, `ccu-edge.nexon.io`, `jyp.nexon.com`) plus an
AWS API Gateway host. No endpoint addresses have been reviewed, so the supplied
containment policy leaves driver network blocking off. Reviewed per-address rules
can be generated separately; dynamic FQDN mediation is not implemented.

## Tuning

1. Start in `mode audit`, run the client through a normal session, and read
   `kfilterctl watch`.
2. A deny rule shows up as `audit ... flags=0x1` (`WOULD_DENY`). If something
   breaks later, the same rule is the first suspect.
3. To exempt a path, add an `allow` rule **above** the deny it should override.
4. To only observe a rule, change `deny` to `audit`.
5. Flip `mode audit` to `mode block` when the output contains only what you
   intend to stop, then `kfilterctl policy default` again (or `kfilterctl on`
   to keep the loaded rules and change only the mode).

## Memory locations instead of whole processes (Linux)

A `peer` rule without `addr=` refuses every memory access of its kind, e.g. all
of the anti-cheat's reads of the game. `addr=` (Linux BPF layer, ABI 10)
narrows a `peer`, `thread-peer` or `system` rule to memory ranges, so one
location is refused and the rest of the access goes on:

```
# grap-core64.aes may not read one page of MapleStory.exe's image (wherever it is loaded)
deny|peer|C:\*\MapleStory.exe|rights=vm-read|addr=MapleStory.exe+0x1000-0x1FFF|image=grap-core64.aes
# nobody in the family writes into this absolute range of the game's memory
deny|peer|C:\*\MapleStory.exe|rights=vm-write,vm-operation|addr=0x140000000-0x14FFFFFFF
```

Up to 16 ranges per rule, comma-separated, each absolute or `MODULE+0xLOW-0xHIGH`
(offsets from that module's image base in the target). Reads, writes,
VirtualQueryEx and the other remote memory calls, GetMappedFileName, hardware
breakpoints set with SetThreadContext and native `process_vm_*` and
`/proc/<pid>/mem` access carry the address (a ptrace attach reaches every
address); an unknown address or module base matches denies only. An allow
with `addr=` decides only accesses that lie within its ranges, a deny any that
overlaps them. Offline (`kfilterctl simulate`/`evaluate`) an `addr=` rule never
matches. The details are in LINUX.md (`peer` rules, `addr=`).

## Strict mode: everything outside the allow list

`policy/strict-policy.txt` inverts the default. Instead of naming other
applications to deny, it names what the client may read at all:

1. `allow|file|\Device\HarddiskVolume*|execute-only` - image loads anywhere.
   The flag makes the rule match only opens that carry `FILE_EXECUTE`, and
   mapping a DLL does not read file data through the filter.
2. The client tree, its publisher, `Windows` loader paths (`dll`/`other` only,
   so reading `System32\*.exe` and `System32\drivers\*.sys` stays denied),
   fonts and its temp directory.
3. The minimum registry surface: its own keys, WinSock/Dnscache, locale,
   version and activation contexts.
4. Two catch-alls: `deny|file|\Device\HarddiskVolume*` and
   `deny|registry|\REGISTRY`.

That last pair is what changes the model: non-PE documents, caches, other
users' data and every registry key not listed above are denied, not just other
applications' binaries.

Expect to iterate. In audit mode every rule that would deny is recorded but
allowed; run a full client session, and each `WOULD_DENY` that the client then
fails on is a missing allow line. Only switch the file to `mode block` when the
denies are all intended.

Even in strict mode the driver cannot block:

- WMI/RPC queries: the WMI service does the reading, not the client process;
- SMBIOS/firmware tables, CPUID, MSR and GPU adapter APIs;
- storage operations not covered by the dynamic device filters or their rules;
- ALPC/COM and named-pipe contents, and network names outside static driver
  rules or the separately installed Windows Firewall policy;
- window and message enumeration, `NtQuerySystemInformation` process/module
  lists (these are not file or registry access);
- kernel-mode code, including an anti-cheat driver, which bypasses all of the
  above and can unregister these callbacks.

## Measured coverage of the default policy

`tools/Simulate-Policy.ps1` replays a capture through the rule list the same
way the driver evaluates it. On 40,000 sampled events from the 2026-10-28
capture (PID 5540):

| | |
|---|---|
| File events | 12,023 |
| Registry events | 27,148 |
| Events without a path | 829 |
| Denied | 4,678 (11.7% of the sample) |

Denials concentrated where the policy is aimed: `System32\drivers` (2,583),
PnP `ControlSet001\Enum` (1,161), `System32\*.exe` (431), `MMDevices` (227),
`FolderDescriptions` (150), `HARDWARE` (47), `Program Files` (44). The rest of
the sample matched an allow rule (its own `Software\Wizet` key 8,169,
`System32\*.dll` 4,672, `Windows NT\CurrentVersion` 2,565) or no rule at all
(16,371, 41%).

That is the expected shape of a targeted policy: it removes the identity and
inventory reads, not every file on the machine. For "deny everything outside
the allow list" use `policy/strict-policy.txt`.

The replay exposed two real gaps, both now fixed:

- `AppData\LocalLow` was not covered by the default deny list (3,031 file
  events, mostly Intel graphics cache under `LocalLow\Intel`). Added.
- `RegNtPreOpenKeyEx` / `RegNtPreCreateKeyEx` can pass a name relative to
  `RootObject`; the capture contains thousands of such events with bare names
  like `Certificates`, `CTLs` or a display class GUID. The driver now resolves
  the parent key with `CmCallbackGetKeyObjectID(RootObject)` before matching,
  and counts the event as a name failure if the combined path does not fit.

The monitor has the same limitation in its own logs: those bare names are
relative opens it recorded without the parent path, so any analysis of registry
paths should treat a name without a leading `\` as unresolved rather than as a
key that lives at the root.

## Regenerating from a new capture

`tools/Build-Policy.ps1` (a wrapper over `tools/kfilter_policy.py`, which needs
Python 3) reads a monitor JSONL and produces a report plus a candidate policy:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\Build-Policy.ps1 `
  -Log C:\logs\session.jsonl -ProcessId 5540 `
  -ClientRoot '\Device\HarddiskVolume3\Nexon\Library\maplestorycw' `
  -Out generated-policy.txt -Report generated-report.md
```

It buckets the application's own tree, its publisher (`\Nexon\`), Windows and
everything else, then emits deny rules for the other-application buckets, a
data-only catch-all, and allow rules for the own tree, Nexon and the Windows
loader paths. The generated file is a starting point, not a replacement for the
curated policy: review the report and merge the lines you want, keeping each
allow rule above the deny rule it should override. The driver accepts at most
64 rules and `kfilterctl check` verifies a file before it is loaded.

## Recovery, if the client stops working in block mode

```bat
kfilterctl.exe audit        :: stop blocking, keep observing
kfilterctl.exe off          :: stop enforcing entirely
sc.exe stop kfilter         :: unload the driver
```
