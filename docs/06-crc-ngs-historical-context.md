# A MESSAGE TO THE AGENT

# MapleStory Anti-Cheat Research Context
## Historical CRC Protections, NGS/BlackCipher, and Modern MSCW/GRAP Architecture

**Research date:** 28 October 2026  
**Primary target:** MapleStory Classic World (MSCW), Windows  
**Secondary context:** Historical GMS/KMS anti-cheat systems  
**Research focus:** Client integrity, CRC, NGS-X/GRAP, IPC architecture, and trust boundaries

---

# 1. Purpose and Research Scope

This document provides technical and historical context for an ongoing investigation into Nexon's MapleStory anti-cheat architecture.

The immediate objective is to understand the security boundaries present in the current MapleStory Classic World client, particularly:

- Embedded client-side integrity checking.
- CRC and related executable-integrity mechanisms.
- NGS-X/GRAP component responsibilities.
- Interprocess communication between security components.
- Security-session initialization, validation, and enforcement.
- The relationship between client-side detection and backend validation.

Treat this document as research context, not as verified documentation of the current executable.

**Critical distinction:** Regular Global MapleStory and MapleStory Classic World are separate client builds. Historical findings about `MapleStory.exe`, MSCRC, HackShield, or BlackCipher must not automatically be applied to MSCW.

All findings should be classified as:

- **CONFIRMED:** Directly supported by official documentation or reproducible evidence.
- **RESEARCHER-OBSERVED:** Reported in technical reverse-engineering research but not independently reproduced here.
- **USER-REPORTED:** Observed by the person conducting the current investigation.
- **HYPOTHESIS:** Plausible explanation requiring verification.
- **UNKNOWN:** Insufficient evidence.

# 2. Historical Timeline

## 2005–2008: GameGuard and Early Memory Modification

Early MapleStory versions used nProtect GameGuard.

Historical cheating categories included:

- Manipulation of movement and player state.
- Monster-position manipulation.
- Unauthorized combat-related changes.
- External memory editing.
- Packet manipulation.
- Gameplay automation.

The relevant distinction is that memory manipulation and server-side exploits targeted different trust boundaries.

Successful local modification did not necessarily imply that the server accepted the modified state.

Early anti-cheat protection largely centered on identifying unauthorized software and restricting process manipulation.

## 2009: Transition to HackShield

MapleStory transitioned from nProtect GameGuard to AhnLab HackShield.

Verified examples:

- MapleStorySEA implemented HackShield Pro with client v0.68 on 25 February 2009.
- Korean MapleStory documented replacement of nProtect with HackShield for Online Game 2.0 following v1.2.72.

HackShield incorporated user-mode and kernel-mode protection, process monitoring, security-component integrity checking, and game-side integration.

Sources:

- https://www.maplesea.com/news_events/view/hackshield_initialization_error
- https://archive.maplestory.nexon.com/News/Inspection/78310

## 2010–2013: MSCRC, HackShield CRC, and Client Reverse Engineering

Historical MapleStory research distinguishes two integrity-protection categories:

**MSCRC:** Integrity checking implemented within the MapleStory client.

**HSCRC:** Integrity checking associated with HackShield.

These mechanisms were conceptually separate.

Defeating HackShield's integrity checks did not necessarily disable MapleStory's embedded checks, and vice versa.

The public GMS v95.1 analysis identifies:

- `CSecurityClient`
- `CSecurityClient::InitModule`
- `CSecurityClient::StartModule`
- `CSecurityClient::Update`
- `CWvsApp::Run`
- `Crc32::GetCrc32`
- `Crc32::GetCrc32_VMCRC`
- `Crc32::GetCrc32_VMTABLE`

It also documents security checks integrated into ordinary application execution.

Some integrity-related logic was associated with routines such as `CWvsContext::OnEnterField`.

These names are historical reverse-engineering artifacts, not confirmed symbols in contemporary MSCW.

Primary technical reference:

https://github.com/Maxcloud/MapleResearch

The repository explicitly describes its own analysis as a work in progress.

## 2014–2022: BlackCipher / NGS

BlackCipher became part of Nexon's established anti-cheat ecosystem.

Historical NGS architectures involved external processes and game-side security integration.

Research and community observations document:

- Process and module inspection.
- Memory-integrity verification.
- Anti-cheat process lifecycle management.
- Client security callbacks.
- Detection reporting and possible delayed enforcement.

The presence of an external anti-cheat process did not eliminate embedded client integrity protections.

## March 2023: Major Security Disclosures

This is one of the strongest sources for understanding Nexon's anti-cheat architecture.

On 16 March 2023, Nexon explicitly identified three complementary client-defense mechanisms:

1. CRC checks covering client code and data regions.
2. Client-code obfuscation.
3. NGS (Nexon Game Security).

Nexon also stated that it expanded CRC coverage as new game code and data were introduced.

Official source:

https://notice.nexon.com/Notice/NoticeView?sn=140474

On 15 March 2023, Nexon acknowledged limitations in client/server validation, including some skills and maps for which expected protections had not been applied.

Source:

https://maplestory.nexon.com/News/Notice/All/140445

On 19 March 2023, Nexon reported:

- Expanding client-modification verification on 18 March.
- Observing changed cheating patterns involving executable modification.
- Attempts to evade client-data modification monitoring.
- NGS detections followed by potentially delayed account restrictions.

Source:

https://maplestory.nexon.com/News/Notice/All/140493

**Key conclusion:** Nexon treats executable integrity, anti-cheat detection, and server-side validation as distinct security layers.

## September 2024: Modern 64-bit Client Research

A reverse engineer published a first-person account titled *Maplestory Hax 1337*.

The author reported:

- Direct modifications to executable instructions triggered integrity checks and immediate termination.
- Reverse engineering of a memory-copy operation associated with integrity checking.
- A reported integrity-view mismatch in which executable modifications were no longer immediately detected by the same local mechanism.
- Independent inspection from BlackCipher64.
- Further experimentation with module enumeration.
- Delayed bans and uncertainty about remaining detection mechanisms.

This is self-reported research, not independently verified evidence of a complete NGS bypass.

Source:

https://tangled.org/tonyd.tngl.sh/blog/blob/c02ba8caf0ae6f99da938b84f9c185bdaae92fbc/content/posts/maplestory-hax-1337.md

## August–October 2026: MSCW and GRAP

During 2026, independent research documented the NGS-X/GRAP architecture used in a MapleStory Classic test client.

MapleStory Classic World entered Founder's Access on 6 October 2026 and publicly launched on 21 October 2026.

In an October 7 Reddit report, a private-server developer claimed to have defeated `grap64` sufficiently to communicate with a custom server.

That claim has not been independently verified and does not establish a complete GRAP bypass against production servers.

Sources:

https://github.com/dspp779/CyderBits/blob/main/docs/games/maplestory/maplestory-classic-ngs-x-grap-architecture.md

https://www.reddit.com/r/mapleservers/comments/1wzu6kl/first_milestone_for_a_classics_private_server/

---

# 3. Technical Background: CRC

## 3.1 What CRC Protects

CRC (Cyclic Redundancy Check) calculates a checksum over a selected byte sequence.

A basic CRC32 integrity operation can be represented as:

`observed_crc = CRC32(memory_region)`

The result is compared with an expected value.

A mismatch indicates that the measured bytes differ in a way detectable by the checksum.

CRC32 is computationally inexpensive but is not cryptographically collision-resistant.

Its practical usefulness as an anti-cheat mechanism depends on:

- Which memory regions are measured.
- How expected values are established.
- Whether legitimate runtime changes are normalized.
- Whether measurement occurs periodically or on demand.
- Whether the measurement source is trustworthy.
- Whether the checker itself is protected.
- How the result is reported and enforced.

## 3.2 Different Forms of Integrity Checking

**File integrity checking**

Checks executable or library contents on disk.

**Runtime executable integrity**

Checks selected executable code regions after loading.

**Runtime data integrity**

Checks selected data regions subject to expected invariants.

**Server-side consistency validation**

Independently validates gameplay state and operations. This is not necessarily CRC-based.

These mechanisms must not be conflated.

For example, an executable can remain unmodified while ordinary writable game-state variables are changed.

Likewise, an on-disk file can remain intact while executable memory changes after loading.

## 3.3 Why Historical MSCRC Matters

The historical importance of MSCRC is that MapleStory could detect executable modifications independently of HackShield.

This introduced multiple integrity boundaries.

A process-memory write being permitted by Windows does not establish that integrity verification was defeated.

Historically, researchers investigated the integrity-checking logic itself, including whether the checker observed the same executable bytes that the CPU actually executed.

This is a general measurement-trust problem.

A checksum algorithm does not independently establish that its input accurately represents the protected execution state.

## 3.4 Known Limitations

Even effective CRC protection cannot guarantee:

- Complete coverage of every executable region.
- Detection of every possible data modification.
- Authentication of the measurement origin.
- Integrity of the checking code.
- Validity of server-side gameplay state.
- Immediate enforcement after detection.

A stronger cryptographic hash would not automatically address incomplete coverage or an untrustworthy measurement source.

## 3.5 What Is Unknown About MSCW

There is currently insufficient verified public evidence to establish:

- Whether MSCW retains historical MSCRC mechanisms.
- Whether MSCW uses a newly implemented code-integrity engine.
- Whether CRC checking is embedded directly in `MSCW/MapleStory.exe`.
- Whether `MapleSecurePC64.dll` participates in CRC verification.
- Whether GRAP performs independent code-integrity measurements.
- Whether embedded integrity results are passed to GRAP through IPC.
- Whether the backend independently verifies integrity-session evidence.

Do not assume historical CRC mechanisms are present merely because the game is called MapleStory.

---

# 4. MSCW Windows Distribution

The current Steam distribution lists separate conventional MapleStory and MSCW executable paths.

Relevant files include:

```text
MapleStory.exe
NGClient64.aes

MSCW/
    MapleStory.exe
    MapleSecurePC64.dll
    grap64.dll

    grap/
        grap-core64.aes
        grap-communicator64.aes
        grap-updater.aes
        NGService.exe
        BlackCat64.sys
```

Source:

https://steamdb.info/depot/216151/apps/

This is distribution evidence only.

A file appearing in the depot does not establish:

- Whether it loads during a particular session.
- Its exact responsibilities.
- Its execution privileges.
- Whether it is mandatory.
- Whether it runs continuously.

**Important version distinction:**

The August 2026 GRAP investigation analyzed a client named `Maplestory_Classic.exe`, described as Unity-based.

The October 2026 MSCW distribution uses `MSCW/MapleStory.exe`.

Do not assume identical internal architecture, offsets, function implementations, or loading relationships.

Identify the exact binary version, hash, module list, and build date before applying historical findings.

---

# 5. Known GRAP Architecture

The following component roles come from the August 2026 CyderBits reverse-engineering investigation.

They were established through some combination of static PE analysis, imports, symbols, strings, and Wine/CrossOver runtime tracing.

They have not been independently validated against the current research machine.

## 5.1 `grap64.dll`

Role: Game-facing integration component.

The analysis identified functionality related to:

- NGS-X initialization.
- Runtime lifecycle management.
- Service coordination.
- Startup and update handling.

Strings associated with initialization, running, and resetting suggest a lifecycle interface, but do not independently establish every function's implementation.

## 5.2 `grap-communicator64.aes`

Role: Communication component loaded into the game process in the observed build.

Despite the `.aes` extension, it is a Windows PE component.

Observed/imported capabilities include:

- Named-pipe communication.
- Event objects.
- Mutexes.
- Shared memory / file mappings.
- Handle duplication.
- Asynchronous I/O.

Its role is particularly relevant to investigating the boundary between game-side security integration and external detection.

## 5.3 `grap-core64.aes`

Role: Separate user-mode detection engine.

The researcher identified capabilities relating to:

- Process enumeration.
- Module inspection.
- Process memory inspection.
- Driver and device inspection.
- HID and device-interface enumeration.
- System handle inspection.
- Detection-log construction.

Evidence included imports, internal type strings, and observed runtime behavior.

The existence of these capabilities does not establish which checks run continuously or what data is sent to Nexon.

## 5.4 `NGService.exe`

Role: Windows service and launcher.

Observed responsibilities include:

- Signature verification using `WinVerifyTrust`.
- Launching GRAP updater components.
- Launching the GRAP core.
- Coordinating service-related startup operations.

The researcher reported an NGS service under:

`C:\ProgramData\Nexon\NGS\NGService.exe`

The current machine should be checked independently.

## 5.5 `grap-updater.aes`

Role: Component preparation and updating.

The analysis identified file-management, process-launching, and update-related capabilities.

## 5.6 `BlackCat64.sys`

Role: Kernel-mode component.

Static imports indicate capabilities associated with:

- Process creation notifications.
- Kernel-level process lookup.
- Memory inspection.
- Device interfaces.
- Kernel worker threads.

In the documented Wine/CrossOver environment, gameplay and GRAP communication were observed without loading the driver.

This establishes that the analyzed configuration could operate without the kernel driver.

It does **not** establish that the driver is optional in every supported Windows environment, nor that kernel enforcement can be disabled without consequences.

---

# 6. GRAP IPC Architecture

## 6.1 Observed Named Pipe

The August 2026 analysis reported an IPC endpoint:

`\\.\pipe\grap-core64\2982`

In that build:

- `2982` represented a game code.
- `grap-communicator64.aes` acted as the pipe client.
- `grap-core64.aes` acted as the pipe server.

The researcher observed the communicator attempting to connect before the core had created the pipe, followed by successful creation and connection.

The exact game code and pipe namespace must be independently verified in the current build.

## 6.2 Session and Synchronization Objects

Observed examples included:

`Local\grap-core-mutex-2982`

`Local\grap-core-32`

The latter was associated with a game process ID in the observed session.

Other object names contained generated identifiers whose exact purpose remains unverified.

Potential responsibilities include process/session synchronization and singleton management.

## 6.3 Reported Core Launch Arguments

The analysis observed core launch arguments consistent with:

`grap-core64.aes <GameCode> <GamePid> <EventHandle>`

These represent observed command-line data, not an established complete protocol specification.

## 6.4 Conceptual Architecture

```text
MSCW game process
  |
  +-- grap64.dll
  |     Game-facing initialization
  |
  +-- grap-communicator64.aes
        |
        | Named pipe / IPC
        v
      grap-core64.aes
        |
        +-- Process/module inspection
        +-- Memory inspection
        +-- Driver/device inspection
        +-- Detection telemetry

NGService.exe
  |
  +-- Signature verification
  +-- GRAP updater launching
  +-- GRAP core launching

BlackCat64.sys
  |
  +-- Conditional kernel functionality
```

This is a logical component model, not a verified complete call graph.

Primary reference:

https://github.com/dspp779/CyderBits/blob/main/docs/games/maplestory/maplestory-classic-ngs-x-grap-architecture.md

Supplementary component research:

https://github.com/dspp779/CyderBits/blob/main/docs/games/maplestory/classic-grap-ngs-x.md

---

# 7. Important Security Boundaries

Four separate security properties should be investigated.

## 7.1 Game Executable Integrity

Question:

Does MSCW independently establish that its protected executable code remains authentic?

Relevant considerations:

- Embedded integrity checking.
- Executable-region measurement.
- Runtime data invariants.
- Security callbacks.
- Obfuscation.
- Local detection reporting.

## 7.2 GRAP Detection-Engine Integrity

Question:

How is the integrity and legitimacy of the independent GRAP engine established?

Relevant considerations:

- Binary signature verification.
- Launch provenance.
- Process identity.
- Lifecycle verification.
- Intercomponent dependencies.

## 7.3 IPC Session Authenticity

Question:

How do the GRAP components establish the identities and session membership of their communication peers?

Relevant considerations:

- Named-pipe access control.
- Object security descriptors.
- Peer identity.
- Per-process and per-session binding.
- Message authenticity.
- Session freshness.
- Failure-state handling.

The existence of a named pipe or predictable object name does not establish a vulnerability.

## 7.4 Backend Validation

Question:

Which local security claims are independently verified by backend systems?

Relevant considerations:

- Game-session identity.
- Anti-cheat readiness.
- Detection reporting.
- Security-session status.
- Server-side gameplay validation.
- Delayed enforcement.

A local anti-cheat component reporting a healthy state does not automatically prove that the backend accepts that state as authoritative.

---

# 8. Historical Attack Categories

The following categories are useful for understanding the evolution of the threat model.

They are not confirmed vulnerabilities in modern GRAP.

| Historical category | General objective | Relevant security boundary |
|---|---|---|
| Ordinary memory editing | Change local game-state data | Runtime state and server validation |
| Executable modification | Change game logic | Code integrity |
| Runtime instrumentation | Observe or intercept application behavior | Process and module integrity |
| CRC measurement manipulation | Undermine confidence in integrity measurements | Measurement authenticity |
| Anti-cheat execution interference | Disrupt detection or reporting | Component lifecycle |
| Packet manipulation | Influence client/server communication | Protocol and server validation |
| External visual automation | Automate interaction without accessing process memory | Behavioral enforcement |
| Privileged access | Operate beyond ordinary user-mode visibility | OS and kernel trust |
| IPC trust compromise | Undermine assumptions about component identity or session validity | Intercomponent authentication |

A useful historical pattern is that attackers increasingly targeted the assumptions behind security measurements, rather than merely modifying client data.

However, the existence of an attack category should never be treated as evidence of a working exploit.

---

# 9. Existing Researcher Observation

The current researcher reports the following behavior on an actual machine:

**USER-REPORTED:**

- The game runs with NGS active.
- Process memory can be read.
- Ordinary game-state memory can be modified.

**NOT YET ESTABLISHED:**

- That executable code can be modified without detection.
- That the game's embedded integrity checks have been defeated.
- That GRAP detection has been evaded.
- That no telemetry is recorded.
- That modifications remain undetected over long observation periods.
- That the server accepts arbitrary modified state.
- That GRAP IPC authentication is vulnerable.
- That security-session attestation can be compromised.

The ability to modify ordinary writable game-state data is compatible with an otherwise functioning executable-integrity mechanism.

This observation should not be characterized as a CRC or NGS bypass without further evidence.

---

# 10. Current Research Priorities

## Priority 1: Establish the Exact MSCW Build

Determine:

- Exact executable path.
- Product and file versions.
- SHA-256 hashes of relevant modules.
- Compilation/build metadata where available.
- Loaded modules during a normal session.
- Whether the components documented in August 2026 are present and loaded.

Do not reuse historical offsets or assumptions across builds.

## Priority 2: Identify Embedded Client Integrity Responsibilities

Determine whether there is evidence of checks implemented independently of GRAP.

Useful evidence includes:

- Static references to checksum or integrity functionality.
- Security-related imports and module relationships.
- Read-only call-stack observations.
- Security-component initialization.
- Ordinary runtime security-related events.

Do not assume a CRC routine is security-sensitive solely because it implements a CRC algorithm. CRC is also used for ordinary data processing.

## Priority 3: Map GRAP IPC

Create a verified IPC inventory identifying:

- Named pipes.
- Events.
- Mutexes.
- Shared-memory mappings.
- Object owners.
- Participating processes.
- Security descriptors and access permissions.
- Connection and disconnection timing.

Distinguish what Windows enforces from what the application protocol enforces.

## Priority 4: Reconstruct the Security-Session Lifecycle

Observe normal startup and shutdown.

Build a timestamped sequence covering:

`Launch → Initialization → Service coordination → Core startup → IPC connection → Active session → Shutdown`

Determine which transitions are actually evidenced by runtime traces and which are inferred.

## Priority 5: Understand Measurement and Reporting Boundaries

Establish whether there is evidence of:

- Client-originated security status.
- GRAP-originated integrity measurements.
- Independent GRAP process inspection.
- Detection reporting.
- Backend communication.
- Server-side validation.

Avoid assuming a particular IPC message carries security attestation without evidence.

---

# 11. Questions the Agent Should Answer

1. Is there verified evidence of embedded executable-integrity checking in the current MSCW executable?

2. Does `MapleSecurePC64.dll` perform security checks, and what evidence supports that interpretation?

3. Is GRAP responsible for all observed process-integrity monitoring, or are checks independently implemented in the game?

4. Which GRAP components execute within the game process versus independently?

5. Does the current build reproduce the named-pipe and service architecture documented in August 2026?

6. What security principals can access the observed IPC objects?

7. How are communication peers and game-session identities authenticated?

8. Are integrity measurements and security-session state represented in distinct communication paths?

9. Which findings can be established from passive runtime traces, and which remain unknown?

10. Which historical MapleStory security mechanisms have demonstrable counterparts in the current MSCW build?

---

# 12. Required Research Methodology

Use existing artifacts and previous investigation results before repeating work.

Prefer:

- Static binary analysis.
- PE metadata inspection.
- Module dependency analysis.
- Read-only process inspection.
- Passive Windows event tracing.
- Process and service lifecycle observation.
- IPC object and permission inspection.
- Correlation of runtime evidence with static findings.

Do not treat imports, strings, or PDB paths as proof that code paths execute at runtime.

Do not treat a successful local operation as proof that security detection was evaded.

Keep experiments observational unless a separate authorized, isolated test environment is available.

For every technical claim, record:

| Field | Meaning |
|---|---|
| Component | Binary or process involved |
| Build | Exact version/hash |
| Observation | What actually occurred |
| Evidence | Trace, code reference, or source |
| Confidence | Confirmed, observed, hypothesized |
| Limitations | What remains unknown |
| Next validation | Non-invasive way to obtain stronger evidence |

---

# 13. Key References

## A. Official Nexon Documentation

**[S1] Nexon, anti-cheat architecture and CRC disclosure, 16 March 2023**

https://notice.nexon.com/Notice/NoticeView?sn=140474

Establishes CRC, obfuscation, and NGS as distinct complementary defenses. Also discusses behavioral detection and enforcement.

**[S2] Nexon, client/server validation limitations, 15 March 2023**

https://maplestory.nexon.com/News/Notice/All/140445

Documents weaknesses in gameplay validation and Nexon's response to cheating.

**[S3] Nexon, expanded client-integrity checks, 19 March 2023**

https://maplestory.nexon.com/News/Notice/All/140493

Confirms expanded client-modification verification and describes changed evasion patterns detected by NGS.

**[S4] MapleStorySEA, HackShield introduction, February 2009**

https://www.maplesea.com/news_events/view/hackshield_initialization_error

Official confirmation of the historical GameGuard/HackShield transition in MapleStorySEA.

**[S5] Korean MapleStory archive, HackShield transition**

https://archive.maplestory.nexon.com/News/Inspection/78310

Documents replacement of nProtect with HackShield in the Korean client.

## B. Historical Reverse Engineering

**[S6] MapleResearch, GMS v95.1 analysis**

https://github.com/Maxcloud/MapleResearch

Contains historical analysis of embedded security logic, `CSecurityClient`, CRC-related routines, and HackShield integration.

The work is incomplete and specific to historical client builds.

**[S7] Maplestory Hax 1337, 3 September 2024**

https://tangled.org/tonyd.tngl.sh/blog/blob/c02ba8caf0ae6f99da938b84f9c185bdaae92fbc/content/posts/maplestory-hax-1337.md

First-person research involving 64-bit MapleStory, integrity checking, BlackCipher, and protocol analysis.

Treat operational claims as researcher-reported.

## C. Modern GRAP / MSCW

**[S8] CyderBits, NGS-X/GRAP architecture, updated 8 August 2026**

https://github.com/dspp779/CyderBits/blob/main/docs/games/maplestory/maplestory-classic-ngs-x-grap-architecture.md

Primary public reference for the GRAP component structure, IPC endpoints, process roles, and observed Wine/CrossOver behavior.

**[S9] CyderBits, GRAP component inventory**

https://github.com/dspp779/CyderBits/blob/main/docs/games/maplestory/classic-grap-ngs-x.md

Additional PE metadata, component relationships, and signatures.

**[S10] SteamDB, MapleStory depot manifest**

https://steamdb.info/depot/216151/apps/

Documents distributed game binaries, including the separate MSCW installation and GRAP files.

**[S11] Community report, claimed GRAP defeat, 7 October 2026**

https://www.reddit.com/r/mapleservers/comments/1wzu6kl/first_milestone_for_a_classics_private_server/

Contains an unverified claim from a private-server developer.

Do not use this as proof of a complete GRAP bypass.

---

# 14. Working Hypotheses

The following are hypotheses only.

**H1: Embedded client integrity exists independently of GRAP.**

Motivation: Historical MSCRC and Nexon's layered-defense disclosures.

Evidence required: Direct analysis of the current MSCW executable.

**H2: GRAP performs additional integrity and environmental checks.**

Motivation: Static and runtime evidence of inspection capabilities in the GRAP core.

Evidence required: Observable check behavior or stronger code-level evidence.

**H3: Security-session information crosses the game/core IPC boundary.**

Motivation: The communicator/core architecture and documented named pipe.

Evidence required: Evidence establishing the semantics and origin of security-related state, not simply pipe connectivity.

**H4: Backend validation imposes additional constraints beyond local anti-cheat status.**

Motivation: Nexon's historical disclosures concerning layered defenses and server-side validation.

Evidence required: Authoritative documentation or observations demonstrating specific validation responsibilities.

**H5: The current MSCW build differs materially from the August 2026 test build.**

Motivation: Differences in executable identity and packaging.

Evidence required: Version-aware binary and runtime comparison.

---

# 15. Instructions for the Receiving Agent

You are continuing an existing, technically advanced MapleStory Classic World security investigation.

Use this document as historical and architectural context.

Do not assume the historical conclusions apply directly to the current client.

Your first action should be to inspect the existing investigation record and identify what has already been established.

Then:

1. Verify the exact current executable and security-component versions.
2. Separate confirmed findings from claims inherited from public research.
3. Determine the strongest available evidence concerning embedded CRC/integrity protection.
4. Establish the actual GRAP component and IPC topology on the current machine.
5. Identify the most important unresolved questions about client integrity and IPC authentication.
6. Recommend the next evidence-producing, non-invasive research steps.

Prioritize **evidence quality over the number of hypotheses**.

Do not conclude that a security boundary is broken based only on accessible memory, predictable IPC object names, or a missing immediate anti-cheat response.

## Expected Deliverables

Produce four outputs:

**A. Architecture report**

A precise component and trust-boundary map for the current MSCW build.

**B. Integrity-protection report**

Distinguish embedded client integrity, GRAP monitoring, and backend enforcement.

**C. IPC research report**

Document observed endpoints, participating processes, access controls, session lifecycle, and unknown authentication properties.

**D. Research backlog**

Provide a prioritized list of unanswered questions, including evidence required, confidence levels, and proposed observational validation methods.

## Central Research Question

**Does the current MSCW client independently enforce executable integrity, and how does that protection interact with GRAP's detection engine, IPC security-session state, and backend validation?**

The objective is to establish the actual security architecture, not to presume that any particular protection is bypassed or vulnerable.