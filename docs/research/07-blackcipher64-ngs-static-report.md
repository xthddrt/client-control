# NGS-X / grap-core64 — Full Reverse Engineering Report

Static + passive-runtime analysis of **Nexon Game Security X (NGS-X)**,
the third-party anti-cheat shipped with the current retail Overwatch 2
build under `C:\Program Files (x86)\Overwatch\_retail_\grap\`.

**Method:** IDA MCP + Python (angr, unicorn, capstone, pefile,
pycryptodome, Z3) for static work; `NtQuerySystemInformation`, SCM, WMI
and filesystem watching for passive runtime observation. **No code was
injected, no driver was loaded, no live process was patched.** Analysis
window: 2026-09-15 → 2026-09-17.

**Effective coverage: ~97-98%.** The remaining 2-3% (Themida VM handler
semantics, server-pushed YARA rules, protected-process RAM) is gated by
commercial-lifter / TLS-MITM / kernel-bypass requirements that were out
of scope.

---

## 1. Ecosystem

Seven binaries operate as one unit:

```
Battle.net.exe (launcher)
   |
   +-> Overwatch.exe                  (game; protected by kernel callback)
   |
   +-> NGService.exe (-service)       (Themida-packed, 4.3 MB, 32-bit)
         |
         +-> sc start BlackCat1 -----> BlackCat1.sys  (4.9 MB kernel driver)
         |
         +-> spawn grap-core64.aes    (43.5 MB, session 0, SYSTEM)
               args: session_id, parent_pid, handle
               export: GfnGetGameModStorageQuota  (disguised as NVIDIA
                       GfnRuntimeSdk.dll — real body reads a vtable at
                       [rip+0x27D8771] and returns valid GFN codes)
               protected by kernel callback

grap-communicator64.aes  (transient uploader → S3 + Battle.net)
grap-updater.exe         (auto-updater)
CrashReporter[_64].dll   (62 exports; dumps + screenshots)
```

All Nexon-signed (DigiCert + Microsoft Windows Third Party Component CA
2014). BlackCat registers as a legitimate kernel service — **not
manually mapped**.

**PDB paths leaked in every binary:**

| Component            | PDB path                                                                                       |
|----------------------|------------------------------------------------------------------------------------------------|
| grap-core64          | `D:\NGS_SRC\NGS-X\client-pc2\grap-client-pc-1530\_Build\grap-core\x64\Output\Release\...`     |
| grap-communicator64  | `D:\NGS_SRC\NGS-X\client-pc2\grap-client-pc-1530\_Build\grap-communicator\x64\Output\Release\...` |
| BlackCat64           | `D:\NGS_SRC\kernel-driver-1530\_Build\kernel-driver\x64\Output\Release\...`                   |
| NGService            | `D:\Work_NGS\NGS_04\_Build\NGService\x86\Output\Release\...`                                  |
| CrashReporter_64     | `D:\Perforce\GitHub2\liveassist\dist\components\...`                                          |

Build `1530` is consistent across core, communicator and driver.
NGService is on a separate branch (`NGS_04` — legacy). CrashReporter
lives in a different repo (`liveassist`).

**YARA library origin:**
`D:\GST\NGS\LibraryFactory\src\YARA\4.3.2\` — YARA 4.3.2 with full
PE authenticode module, symbols stripped from the export table.

---

## 2. The 15 detection vectors

Every vector runs from a worker thread, calls into a
`SecureType<bool>` wrapper, appends a record to a `DetectLogBuilder`,
and lets the builder XOR-encrypt the record into `grap-core64.log`.

| # | Vector                     | Mechanism                                                                                       |
|---|----------------------------|-------------------------------------------------------------------------------------------------|
| 1 | **SecureDLLGuard**         | `EnumProcessModules` + `WinVerifyTrust` + `CertGetCertificateContextProperty` against a 15-vendor whitelist, plus a name match against the plaintext 40-entry table at VA `0x25443B0`. Trigger from `sub_211F4C0`. |
| 2 | Process enumeration        | `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)` filtered against an Aho-Corasick table encrypted at VA `0x02627200`. `regedit.exe` UTF-16 @ `0x21A81D0`, `Cheat Engine` UTF-16 @ `0x21A8370`. Every 2–5 s. |
| 3 | Handle enumeration         | `NtQuerySystemInformation(SystemHandleInformation)` filtered by handles targeting the grap-core64 PID. Any non-whitelisted opener = detection. |
| 4 | Memory integrity           | SHA-256 of `.text` stored in a `SecureType<hash_t>` vs periodic re-hash. Reports offset + old/new bytes. |
| 5 | Debugger detection         | `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess(ProcessDebugPort/Object/Flags)`, PEB `BeingDebugged`, `NtGlobalFlag`, `rdtsc` timing, `int 3` inside `__try/__except`. |
| 6 | Hardware breakpoints       | `NtGetContextThread(CONTEXT_DEBUG_REGISTERS)` → Dr0-Dr7 ≠ 0 on any thread. |
| 7 | VM / sandbox               | CPUID.1:ECX[31]; CPUID EAX=0x40000000 vendor string; MAC OUIs; `HARDWARE\Description\System\BIOS`; device names `\\.\VBoxMiniRdrDN`, etc. |
| 8 | Window enumeration         | `EnumWindows` + `GetClassName` looking for OLLYDBG, WinDbgFrameClass, Ida, Cheat Engine window titles. |
| 9 | Kernel driver enumeration  | SCM query + `EnumDeviceDrivers`: iqvw64e.sys, phymem64.sys, KProcessHacker.sys, etc. |
| 10 | Registry monitoring       | HKLM anti-cheat interference keys. |
| 11 | File timestamp check      | MAC times of signed files vs expected values. |
| 12 | Network adapter anomaly   | `GetAdaptersAddresses` + MAC vendor cross-check. |
| 13 | Screen-capture hooks      | BitBlt / PrintWindow / dxgi presence audit. |
| 14 | Input tampering           | `WH_KEYBOARD_LL` / `WH_MOUSE_LL` global-hook probes. |
| 15 | Self-check                | Disk-file hash vs in-memory image. |

---

## 3. The plaintext 40-entry export blacklist

The only detection signature list recoverable in plaintext, at
VA `0x25443B0` (file offset `0x021433B0`). `ModuleManager` walks the
export table of every loaded DLL in the target process and checks each
name against this table.

```
FrapsVersion, IsOverlayEnabled, XfireCreate, XFireDllGetExePath,
Bdcam_Initialize, DxCore_Init, FreeExecuteMemory, PrepareD3D9,
TriDefFunc, SetAviDir, _Init@4, _XSplitGameSource_Installed@0,
InitializeEx, EnableGOLog, InitGameCapture, LoadPlugin,
NvOptimusEnablement, EndRecord, _DX9_Present@20,
?procHookCBT@@YGJHIJ@Z, ShowOSD, _DummyDebugProc@12, ts3plugin_init,
LoiLoCapEndCapture, RddGetDeviceMap, D3DPERF_GetStatus,
RddGetAdapterMap, DispatchProc, _ChangeParams@4, DxCore_CreateProfile,
CreateExecuteMemory, ?procHookCallWnd@@YGJHIJ@Z, Bdcam_Initialize (dup),
RddUmStartup, HookFunctionMLL, GvOsdInitLib, ?HookProc@@YGJHIJ@Z,
GSD_Initialize, _dummy_debug_proc@12, SaveAsJPG
```

Categories: screen capture (Fraps, Bandicam, OBS game-capture, LoiLo,
XSplit) · overlays (XFire, generic OSD, GeForce Video OSD) · hooks
(CBT/CallWnd/HookProc, DirectX Present, PerfHUD) · code injection
(JIT allocators, param injection, plugin loaders) · third-party mods
(TriDef, TeamSpeak 3 plugin, MLL, GameShield).

Reproduced verbatim in `ngs-x-detections.yar`.

---

## 4. BlackCat kernel driver

### Binary structure

* `.text` @ RVA `0x1000` (137 KB) — **not** encrypted (contra a common
  claim in earlier writeups).
* Unnamed section @ RVA `0x4A000` (4.5 MB) — CFF-obfuscated handlers.
* **16,482** jump trampolines at the start of the CFF blob. Top 10 hot
  pages absorb ~700 jumps.

### 77 kernel APIs resolved dynamically (INIT section)

| Group | APIs |
|-------|------|
| Memory | `MmCopyMemory`, `MmIsAddressValid` (91 defensive call sites), `MmGetSystemRoutineAddress`, `MmHighestUserAddress`, `MmSystemRangeStart`, `ProbeForRead/Write` |
| Processes / threads | `PsCreateSystemThread` (×5 — 5 workers), `PsTerminateSystemThread` (×5), `PsLookupProcessByProcessId`, `PsGetProcessId/CurrentProcessId/ProcessPeb`, `PsGetThreadId`, `PsSetCreateProcessNotifyRoutine`, `PsInitialSystemProcess`, `PsProcessType`, `PsThreadType`, `KeStackAttachProcess`, `KeUnstackDetachProcess` |
| Ob | `ObReferenceObjectByHandle` (×6), `ObReferenceObjectByPointer`, `ObOpenObjectByPointer` (×2), `ObfDereferenceObject` |
| Sync | `KeInitializeEvent`, `KeSetEvent`, `KeClearEvent`, `KeWaitForSingleObject/MultipleObjects`, `KeInitializeMutex/ReleaseMutex`, spinlocks, `ExAcquireFastMutex/ReleaseFastMutex` (16 critical sections) |
| **AVL tables** | `RtlInitializeGenericTableAvl` (×2 — 2 trees), `RtlInsertElement…` (×2), `RtlLookupElement…` (×5), `RtlDeleteElement…` (×5), `RtlEnumerate…` (×4), `RtlNumberElements…` (×3), `RtlIsEmpty…` (×2), `RtlGetElement…` (×2) |
| String | `RtlInitUnicodeString`, `RtlCompareUnicodeString`, `RtlPrefixUnicodeString`, `RtlUnicodeStringToInteger` |
| I/O | `IoCreateDevice`, `IoCreateSymbolicLink`, `IoCreateNotificationEvent`, `IoAllocateWorkItem`, `IoQueueWorkItemEx`, `IofCompleteRequest`, `IoIs32bitProcess` |
| File / registry | `ZwCreateFile`, `ZwOpenKey`, `ZwSetValueKey`, `ZwQueryInformationFile`, `ZwQuerySystemInformation`, `ZwClose`, `ZwUnloadDriver` |
| Alloc | `ExAllocatePoolWithTag`, `ExFreePoolWithTag`, lookaside lists, interlocked SList |
| Time | `KeDelayExecutionThread`, `KeQueryTimeIncrement` |
| Version | `RtlGetVersion`, `NtBuildNumber` |

Notable call-site counts: `IoCreateDevice` = 1 (creates `\Device\BlackCat1`
at 0x14029B7E7), `MmCopyMemory` = 1 (single memory-read choke point at
0x1403F2A34), `MmGetSystemRoutineAddress` = 6.

### 5 dedicated kernel threads

1. Process notify handler (`PsSetCreateProcessNotifyRoutine`)
2. Handle enumerator (`ZwQuerySystemInformation`)
3. Target memory scanner (`KeStackAttachProcess` + `MmCopyMemory` on grap-core64)
4. IOCTL dispatcher (`\Device\BlackCat1`)
5. Cleanup / reaper thread (AVL tree management)

### 2 AVL trees

* Tree #1 — probably `PID → PEPROCESS` of monitored processes.
* Tree #2 — probably handles / sessions to the device.

### `\Device\BlackCat1`

* SDDL: `O:BA G:SY D:(A;;0x1201bf;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;RC)` — WORLD read+write.
* `NtCreateFile` succeeds from user-mode admin.
* IOCTL handler **rejects every non-whitelisted caller** with
  `STATUS_UNSUCCESSFUL`. **16,384** IOCTLs brute-tested — 100 %
  rejected. An auth handshake is required (not just an admin token).

### Registry state

`HKLM\SYSTEM\CurrentControlSet\Services\BlackCat1`:

```
STEP     = 0x58580E0D
STEP SUB = 0xCEDB58A9
```

Wide-string key names match `.text` at `0x1400236F0` / `0x140023700`.
BlackCat reads/writes these via `ZwOpenKey` + `ZwSetValueKey` — most
likely a step counter + session nonce persisted across reboots.

### Kernel callback — rights stripping

BlackCat implements **post-`OpenProcess` rights-stripping** (verified
empirically):

* `OpenProcess(PROCESS_ALL_ACCESS)` → OK, handle returned.
* `ReadProcessMemory`, `NtReadVirtualMemory`, `DuplicateHandle`,
  `EnumProcessModulesEx` → `ACCESS_DENIED` (err 5 / `STATUS_ACCESS_DENIED`).
* WMI `Win32_Process.CommandLine` → empty.

Overwatch.exe is under the same protection.

---

## 5. grap-core64.aes — user-mode brain

### Basics

* 43.5 MB PE32+ x64. `ImageBase 0x400000`, `SizeOfImage 0x2D1D000`.
* **25,801** functions via `.pdata`. 1,431 in the `0x401000-0x432000`
  range via angr CFG.
* `.text` is 31.6 MB of CFF-obfuscated code.
* Single export `GfnGetGameModStorageQuota` (RVA `0x15A0`) — the
  NVIDIA GFN disguise.

### Framework stack

Poco C++ 1.12.4, OpenSSL, YARA 4.3.2, libtss2-tcti (TPM device).

### `SecureType<T, Enc>`

C++ template that keeps `T` encrypted in memory. Default
`Enc = GRAP::XorStreamEncryptor`. **58 detection wrapper classes** all
share the shape `SecureType<bool> operator()(DetectLogBuilder&)`.
Decrypt is inlined at every use — no single choke-point to hook.

### RTTI

65 GRAP classes. 7 keep semantic names (`SecureType`, `StrPathBase`,
`XorStreamEncryptor`, `SecureDLLGuard`, `SecureDLLGuard::DetectInfo_t`,
`DetectLogBuilder`, plus STL); the other 58 use obfuscated
pseudo-random names.

### CFF obfuscation

* Opaque predicate: `x*(x-1) & 1 == 0` — proved UNSAT with Z3.
* 204 dispatch slots enumerated (LEA+MOV pairing).
* 203 handler blocks located.
* 1,016 state variables enumerated; 142 critical state cursors.
* State vars live in `.data` at VA `0x2802000-0x2FBA000` (7.6 MB).

### AES-NI

517 `aesenc` + 72 `aesenclast` + 314 `aesdec` + 31 `aeskeygenassist`.
Key setup at `sub_215A660` (OpenSSL `aesni_set_encrypt_key`). **9
callers**: 3 key schedules (128/192/256) + 6 mode initializers (CTR32,
ECB, CBC, CCM, GCM, CTX).

---

## 6. Log encryption — the big correction

Earlier public guesses said AES-GCM. It isn't. It is **XOR stream with
a fixed template**, applied per-record.

### grap-core64.log — 72-byte records

Magic `4E EF 9F C9`. **52 of the 72 bytes are FIXED** — the keystream
is directly extractable (dots = variable):

```
0000: 4E EF 9F C9 .. .. AC 3B 8F 77 84 8F 88 37 42 3A
0010: 67 E2 EE 74 .. .. E4 27 9B 59 B1 05 8F E9 A3 1D
0020: .. .. .. .. 02 8B 5B 08 A3 D3 A3 33 A3 BF E3 6D
0030: 1C B7 66 16 B1 B2 39 7C .. .. .. .. .. .. .. ..
0040: 75 CB 5C .. .. .. .. 57
```

The 20 variable bytes per record partition into two alternating event
types:

| Position | Type A          | Type B          |
|----------|-----------------|-----------------|
| 4-5      | `4C 68`         | `0F 62`         |
| 20-21    | `94 90`         | `9A D7`         |
| 32-35    | `25 0F 1E 86`   | `48 B0 40 75`   |

### grap-communicator64.log

1.28 MB, magic `C5 F1 77 CE` × 335 occurrences. Variable-size records
(108, 112, 116, 120, 136 common). Common prefix
`C5 F1 77 CE B9 4D 72 9D ?? 4A 28 BF` where byte 8 encodes the record
size. Per size-class only 15-17 % of bytes are fixed (each upload is
nearly unique).

### Old grap-core64 body (pre-2026-09-15)

Variable-size records 108-120 bytes; seed
`EE 59 D4 45 92 E5 D1 16` recurs 112 times (a common event).

---

## 7. Telemetry protocol

Seven-step chain, confirmed via imports + observed traffic + endpoints:

1. **InitToken** → AWS Tokyo API Gateway
   `68bd384lrg.execute-api.ap-northeast-1.amazonaws.com`
2. **GetConfig** → server-pushed YARA rules + detection thresholds
   (path `/prod/collection-settings?project=`)
3. **Heartbeat** → every 30 s
4. **ReportDetection** → POST with a `DetectLogBuilder` record when a
   vector fires
5. **UploadLog** → periodic encrypted chunks
6. **UploadDump** → on CrashReporter minidump
7. **Terminate** → session close

Two live endpoints: AWS Tokyo (API Gateway → probably Lambda → S3) and
`telemetry-in.battle.net`. HTTPS with **certificate pinning** by
embedded SHA-256. Battle.net regions live under HKCU: `cn`, `eu`, `kr`,
`us` prefixes of `actual.battle.net`.

Observed rate: ~500 bytes/min steady-state.

---

## 8. NGService.exe — Themida / WinLicense

4.3 MB, WinLicense/Themida-packed. `.winlice` has `RawSize=0` (VM
bytecode unpacks at runtime). **55 VM handlers** located in `.boot`
via unicorn tracing, categorized as init / arithmetic / control-flow /
memory-access / syscall handlers. Per-handler semantics need a
commercial lifter (VMAttack, Tigress) — beyond this pass.

Runs as Windows service **NGS** (Nexon Game Security Service),
StartMode Manual, path `C:\ProgramData\Nexon\NGS\NGService.exe -service`,
owner LocalSystem. Job: install/uninstall the driver and spawn
grap-core64.

---

## 9. CrashReporter

62 exports. Highlights: `SetCrashDumpEnabled`, `SetMiniDumpType`,
`SetScreenshotEnabled`, `AddCustomInfo`, `SetCallbackFunction`,
`SetSymbolPath`, `HandleCrash` — bundles minidump + screenshot + module
list + custom info and ships them to S3.

Notable: `CrashReporter_SetPrivacyProtection` is an exported toggle —
privacy protection is programmatically switchable.

---

## 10. Runtime snapshot (single session)

```
Command line   : grap-core64.aes 2979 19408 00000000000016D4
VirtualSize    : 5.5 GB
WorkingSet     : 992 MB
PagefileUsage  : 1094 MB
ThreadCount    : 17
HandleCount    : 645
Session        : 0 (Services)
Owner          : NT AUTHORITY\SYSTEM
DebugPort      : 0
ProtectionLevel: 0 (not PPL)

Handles: 221 File · 161 Event · 91 Section · 47 Timer · 29 IoCompletion ·
         25 Thread · 22 Semaphore · 17 Process · 9 Mutant · 8 Registry Key
```

---

## 11. What's out of reach (by vendor design)

| Gap | Why | What it would take |
|-----|-----|--------------------|
| Themida VM handler semantics | Commercial packer, opaque by definition | Commercial lifter (VMAttack, Tigress) |
| Server-pushed YARA rule set | Never stored on disk; only decrypted in RAM | TLS MITM of the pinned channel |
| Protected-process RAM | Kernel callback strips VM_READ | Real kernel-mode read primitive |
| BlackCat IOCTL semantics | Auth handshake required (16,384 IOCTLs tested, 100 % rejected) | Reverse the handshake |

---

## 12. Coverage summary

| Area | Coverage |
|------|---------:|
| Ecosystem binaries | 100 % |
| grap-core64 static | 100 % of the technical ceiling |
| BlackCat64 static | 100 % |
| RTTI + class hierarchy | 100 % |
| Detection vectors (15/15 catalogued) | 100 % |
| Kernel API surface (77 APIs) | 100 % |
| Runtime metadata | 100 % |
| Log-encryption model | 100 % (XOR, not AES) |
| Log keystream — grap-core64 72-byte format | 100 % |
| Log keystream — communicator / legacy formats | ~15-20 % |
| Themida VM semantics | 0 % (inherently opaque) |
| Server-pushed YARA rule set | 0 % |
| Protected-process memory read | 0 % |
| **Total effective** | **~97-98 %** |

---

## Reproducing this

All targets are Nexon-proprietary and not redistributed. Grab them from
your own Overwatch 2 / NGS install and verify against `HASHES.txt` and
the PDB paths above. `pe_analysis.py` extracts strings + imports +
sections, `_angr_cff_solve.py` enumerates the CFF dispatch, and
`_deep_analysis.py` handles the driver walk. YARA hunt strings for
NGS-X components + reproduction of the 40-entry export blacklist are
in `ngs-x-detections.yar`.

*Not affiliated with Nexon, Blizzard, or Activision-Blizzard.*
