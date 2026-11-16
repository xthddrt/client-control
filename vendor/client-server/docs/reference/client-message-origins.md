# Where the client's reports and checks come from

What each client-to-server message of the integrity, identity, telemetry and formerly "unknown" groups
carries, what makes the game send it, and the code that builds it. From the 2026-11-15 recordings
(proxy-20261115-130134, -132117, -134015, -204932) and MapleStory.exe build 0x6AEB667B (addresses
are RVAs; image base 0x140000000). Body offsets start after the 2-byte opcode.

**Confirmed** = the code and the recordings agree, with the counts given. **Likely** = reasoned, not
checked against every field. Names and short notes are in `traffic/protocol.py`; counts per type in
`docs/reference/message-breakdown.md`. Personal values (account number, ids, MACs, character name)
are left out.

`traffic/fields.py` decodes the layouts below (debug registers and the process-scan status included);
`analysis/message-timing.py` redoes the timing and pairing counts on any recording (`periods`, `pair`,
`around`, `values`, `show --fields`).

"Protected" means the code has no call, jump or pointer from plain code: it is only reached from the
Themida-protected sections, so its caller cannot be followed statically.

## Shared machinery

- **The per-frame update.** `0x18aee30` (slot 1 of 24 method tables, among them 0x34e6eb0, 0x34e7b88,
  0x34e83d8, which `client-messages.md` lists as "origin") calls `0x2da1b40(singleton, now)` every
  frame. That singleton (0x4310 bytes, pointer at `[0x3bda7b0]`, made by 0x2d04a70, constructor
  0x2d66ef0) holds the timers of C 0x13f, C 0x1a7 and most C 0x1ef kinds.
- **Server-set switches.** `0x98eae0(id, default)` reads an integer from a settings map at
  `[0x3bf53f8]` (`0x98ec40(id)` is its yes/no form): intervals and kill switches of several reports
  come from the server. Which server message fills that map is not known.
- **Helpers.** 0x9790d0(last, period, now) = "period has passed"; 0x7acf50(lo, hi) = random in
  [lo, hi); 0x761770 = change a packet's opcode after building it; 0x763560 = a second send function
  (most C 0x1ef kinds use it); 0x7615d0 / 0x7619c0 = remember an offset / write a count there later.

## Integrity

### C 0x70 client_context_report (5 subtypes; confirmed)

| Subtype | Seen | Content | When | Builder |
|---|---:|---|---|---|
| 1 | 1,984 | u32 100, u32 A, u32 A (changes every time), u32 2, u8 0, five scrambled values, Dr6, Dr7 | about 1 in 31 sends: built only when a send counter n % 31 == 0, riding on ordinary messages | 0xcef840 (protected) |
| 2 | 62 | u32 100, 0, 0, u32 2, the same five values, Dr6, Dr7 | first message of every connection (62/62) | 0x1667600, from the connection start 0x16626f0 (call at 0x1663f64) |
| 4 | 60 | u32 100 | once per channel connection, with the first answer to S 0x20 05 | 0x166a660 (protected) |
| 5 | 188 | u32 game clock in ms (`[[0x3bf38c8]+0x60]`), u32 a counter (~32 per second: likely frames since the last report) | answers S 0x20 `05` (all), the server asks every 120-243 s | 0xd04970 (protected) |
| 13 | 66 | a 36-character UUID string, u8 0 | answers S 0x20 `0c` (median 56 ms); once unasked on login connections | 0xd1fea0, from a result queue (0xd1f8c0 -> 0xd1f830) |

The five values of subtypes 1 and 2: with a random r and the CRC-32 table T at 0x3b72360,
f1 = r ^ T[0x1b], f2 = Dr0 ^ r ^ T[0x7f], f3 = Dr1 ^ r ^ T[6], f4 = (Dr2 ^ r) - T[4],
f5 = (Dr3 ^ r) + T[0xd2]. The code asks for `CONTEXT_DEBUG_REGISTERS` (0x100010) through function
pointers (likely GetCurrentThread / GetThreadContext). All 1,970 decoded messages give Dr0-Dr7 = 0.
**Hardware breakpoints would show up here and in C 0x9c.**

The subtype-13 UUID is not the registry MachineGuid and not fixed hardware: it changed between two
game processes. Likely from the Nexon SDK (nexon_api_x64.dll exports `nxapi_get_device_id`); not
confirmed.

### C 0x13f sent_packet_counter (confirmed layout and timer; meaning likely)

- **Timer:** in 0x2da1b40 at 0x2da453b, every 30,000 ms since `[this+0x41b0]` (recorded: median
  31.0 s, 30.0-36.9 s over 822 intervals). Server kill switch: setting 0x1ae.
- **Layout** (builder 0x2dd9360): u8 reset flag; u32 N1 + N1 x {u32 opcode, u32 M, M x {u32 k2,
  u32 count}}; u32 N2 + N2 x {u32 opcode, u32 count}.
- **What fills it:** SendPacket 0x1661780 itself counts sends of 0x13e/0x143/0x274 (0x1677610) and
  0xe1-0xe6/0x249 (0x16775c0) into map 2; eight builders of those messages (0x1aa8730, 0x20b4f50,
  0x297c150, 0x297cfd0, 0x297ed20, 0x2980cb0, 0x2982aa0, 0x2986590) count into map 1 via 0x2dd9170.
- **Recorded:** all 917 are empty (11 bytes): the scraper never attacks. Likely a check that the
  attack-type packets sent match the ones the game logic made (injected packets).

### C 0x1f9 / 0x1fa / 0x202 decoy_report (confirmed)

0x2edc670 builds a C 0x1ef body {u32 0x65, u32 rand 0-9, u32 rand 0-14} and then sends it under a
random opcode: 0x1ef, 0x1f9, 0x1fa or 0x202. All 15 recorded copies are this (14 bytes, values in
range; 0x1ef 5, 0x1f9 6, 0x1fa 2, 0x202 2), about one per channel connection 610-668 s after it opens.
The real builders never ran:
- 0x1f9: 0xd0f800, only from 0xd067a0 (anti-cheat area; no callers): u32 0x3f, u64, u32 n, n x six
  u64.
- 0x202: 0x2f376c0: a random first delay up to 30 min, then hourly when a value set by protected
  code is 0x1aff01; fires once.
- 0x1fa: has no builder of its own.

### C 0x1f3 key_sequence_fingerprint, S 0x5ac key_check_start (trigger confirmed; purpose likely)

- **S 0x5ac** comes every 21:00, empty (handler 0x1b00f90, case 0x5ac of the server switch 0x18b1840).
  It clears the key map `0x3c04748` and arms a recorder in 0x1aeb0a0.
- The recorder 0x1b01950 (from the input path 0x1ae4c70) keeps only key releases (WM_KEYUP /
  WM_SYSKEYUP). After 60 s the filter 0x1b01c30 runs; after 360 s the list is sent if it qualifies:
  300 keys, at least 4 different keys used 5+ times, no run of 100 of one key.
- **C 0x1f3** subtype 4: u32 4, u32 n, n x {u32 XOR of the key codes in 4 byte lanes, 32-character
  MD5 hex of the 300-key sequence}.
- **Recorded:** 3 of the 23 windows sent one, each exactly 6:00 after its S 0x5ac (3/3). The XOR
  bytes fit Esc and arrow keys, the keys the scraper presses. Likely an anti-macro check.

### C 0x286 key_event_log (likely)

One seen (18:36:45, 717 bytes, while browsing shops): header u32 1, u32 0, three u8, u32 1096,
u32 54, then 54 records of 12 bytes {u16 key code (Esc, Left, Up), u16 value, u8 down/up, u8 1,
zeros}. Builder 0x1aeb7a0, from 0x1af9b54, next to the 0x1f3 key recorder. Trigger unknown.

### C 0x265, C 0x266, S 0x1d, C 0x267 (order confirmed 2/2)

Sent together at 17:12:43 and 18:23:42 (at room changes; most room changes send nothing; trigger
unknown).
- **C 0x265 performance_report:** double system CPU % (PDH `\Processor(_TOTAL)\% Processor Time`),
  double process CPU % (GetProcessTimes), u64 working set, u64 virtual memory in use
  (GlobalMemoryStatusEx), u32 likely frame rate (59/60), u32 a setting (default 50), two u32 and two
  doubles of unknown meaning, u32 1, u32 0. Gate: `[0x3bda7b0]+0x3608 == 1`.
- **C 0x266:** built in protected code (0x2d0fa30 jumps into Themida): u64, u64 token, u32 ms tick.
- **S 0x1d:** echoes the tick, a u64 and a new u64 token; the next C 0x266 carries that token (1/1).
- **C 0x267:** u32 97, then 98: likely the ms the C 0x266 -> S 0x1d round trip took (85 ms measured at the proxy). Both rounds came during the scraper's 5-minute pauses without input.
- C 0x264 (never seen; 0x2d0f650): a global u32 and virtual memory in use, once when the client stage
  goes from 2 to 3 (from 0x2127880).

### C 0x9c answers S 0x1b: the 10-second check (confirmed)

- **S 0x1b** every 10.1 s (2,671 on 56 connections), 46 bytes: u64 address + u32 length of a memory
  range to **checksum**, u32 tag, u64 address + u32 length of a memory range to **copy back raw**,
  u8 flag, u8 1, u64 a new challenge, u64 the client's previous one. Both ranges and the flag were 0 in
  2,671/2,671: the server **can** ask for a checksum or a copy of any memory of the game, but did not.
- **C 0x9c** (149 bytes, median 11 ms later; all 2,777 parse). The builder 0x1668850 decodes S 0x1b
  itself, so it is the handler (no static caller: the dispatch is protected); it sends through
  0x16653c0. Sections split by the marker 123456789:
  1. u32 100; a u16 k and a protected u64; the checksum of the asked range (each byte shifted by
     k % 19);
  2. the tag, address and length echoed, the raw bytes, address ^ 0x9e3779b9;
  3. two u32 filled by protected code when the flag is set (0);
  4. **the debug registers**: ContextFlags 0x100010 (CONTEXT_DEBUG_REGISTERS), calls through
     [0x3359308] then [0x3c08a88] (GetCurrentThread, GetThreadContext: confirmed by a live read); with a random r and
     the MSB-first CRC-32 table T at 0x3b72360: r^T[0x1b], (Dr0^r)^T[0x7f], (Dr1^r)^T[6],
     (Dr2^r)-T[4], (Dr3^r)+T[0xd2], Dr6, Dr7. All 0 in 2,777/2,777. Five identical copies of this
     code exist; one runs each time;
  5. **a process-scan status** from 0xd070d0: at most every 30 min it snapshots all processes, opens
     each (access 0x410) and reads its path and name; only an encrypted status is sent: 0 = no scan
     this time, 1 = scanned (16 times, 30.0 min apart, 13:27-20:58), 2 = none could be opened. The
     list itself is not sent here;
  6. the challenge chain (from protected code 0xd06af0, 0xd06b60);
  7. a u32 from the socket object; three counters reset per report: key and input events from the
     window-message handler (0x2ce1c20 -> +0x42e8, 0x2cd27a0 -> +0x42e4; equal in 2,751/2,777,
     median 17 per 10 s) and +0x42ec (0).
- What earlier looked like "32 values" is 29 identical copies of the memory read-back code, picked
  at random or by level-like thresholds: obfuscation.
- After sending, it checks that a pointer (0x3c00f70) lies inside the game image; if not it logs and
  may wipe its own stack (a deliberate crash). The live read shows that pointer is 0x1661826, inside
  SendPacket (0x1661780): this is a **SendPacket hook detector** (a cheat that redirects the send
  function trips it).

### C 0xc5 answers S 0x4f: is the game window in front? (confirmed)

Every ~60 s a burst of six S 0x4f (n = 0..5; 394 bursts); each gets one C 0xc5 (u8 n, u8 flag) ~13 ms
later. The builder 0x166cf40 is the S 0x4f handler. The flag is 1 only if two functions resolved at run
time ([0x3c08750] = GetFocus, [0x3c08808] = GetForegroundWindow; confirmed by a live read) both return
the game's main window. Always 1 here.

### C 0xba input_idle_flag (confirmed)

0xd101d0 checks at most once a second whether there was keyboard or mouse input in the last 5,000 ms
(last-input time 0x3bf9e50, stamped by 0xd101b0 from the input handlers 0x2cceac0 and 0x2cd27a0) and
sends `0xd18100(0xba, flag, 1)` only when the flag changes: 0 = idle 5 s, 1 = input again. The opcode is
passed in a register, which is why the static map missed it. Recorded: strictly alternating (76 x 0,
76 x 1). The scraper's key presses count as input. Who calls 0xd101d0 is protected.

### C 0x407 / S 0x381: the 6-minute challenge chain (confirmed)

The first C 0x407 comes 0.6-1.3 s after channel entry, then exactly every 360.0 s (gate 0xd07c30,
feature 0xe7, jumps into protected code; the builder is protected). S 0x381 answers every one (105/105,
median 95 ms): u32 V1, 0, u32 V2, 0. The next C 0x407 (18 bytes) carries a new value W (bytes 0-3),
V2's low 16 bits (bytes 4-5) and bits 16-23 (byte 11), and a varying check byte (13): a chain that
holds even across connections (103/104), so the client keeps it for the whole process. Dropping or
replaying one breaks the chain.

### C 0x77 answers S 0x2b: file CRCs (confirmed on disk)

S 0x2b comes 0.5 s after the login connection opens: u32 254 and 254 file names. C 0x77 ~0.4 s later
(builder 0xd12960 from 0x1bc71e0, the login stage, method table 0x350d970; the check runs in 0xd12370):
constants 0x4e8ee646, 0x68860bfd, 250307, 1; the ms the check took (361, 361, 350); 0xe3c; 0; the CRC
of the CRC table itself (0x36368b8b, a self-test); count + 0x29f3d35; then per file in S 0x2b's order
the name (bytes rotated left 1) and **CRC-32 of the whole file** (MSB-first, poly 0x04C11DB7, init 0,
no final XOR) + 0x2497d08d. Matches the files on disk, 254/254 (568 MB).

### C 0xa2, 0xa3, 0xa4: the data-file list (one handler; one sign-in)

Handler 0xd144f0 (plain code, no static caller) reads u32 n and n names from **S 0x2c** (confirmed: 130134
re-decoded offline; S 0x2c came at 14.485 s, u32 180 + 180 `Data\...\*.wz` names, 5,982 bytes consumed
exactly, right after the character list), then sends, 86 ms later (the exe path from [0x3c082a8] =
GetModuleFileNameA, confirmed by a live read):
- C 0xa2, encrypted with a random r (dword i: ((((v - c)^0xa1aab4bb) - (r>>7)) - 0x764f140d)^r, c
  growing by 4r): the game's exe path, u32 180, u8 1 (the count matched), u32 180;
- C 0xa3: 36 pages of {u32 page, u32 5, 5 nibble-swapped names}: the 180 .wz files;
- C 0xa4: the same names as NT paths (`\??\C:\Nexon\...`), likely of open file handles.
Built by the computed-opcode site 0xd17a40, so not protected.

### Not seen

C 0x191 is in no recording of 2026-11-15 once every connection's opcode table is applied (the earlier
"1 seen" came from the table parser bug); a 17-byte unresolved message on 130134 connection 4
(`01000000 00000000 01 01 01 fe000000`, 0xfe = 254) is a candidate only.

## Identity

### C 0xb9 device_stamp, S 0x3c device_stamp_issue (confirmed)

- S 0x3c comes first on each channel connection with a new stamp; C 0xb9 follows within 0-40 ms.
- C 0xb9 sends the stamp from the **previous** connection's S 0x3c (58/58; the other 2 had no earlier
  connection in the recordings), then the client stores the new one.
- Content (each byte shifted left one bit): u8 found, then `YYYYMMDD/HHMMSS|account number|stamp id|`.
- Builder 0x166e280 (protected; likely the S 0x3c handler) reads `maple_hf2` from
  HKCU\Software\Wizet\MapleStoryClassic, reverses it and sends it (0x16704e0), then saves the new one,
  reversed. So the "device fingerprint" is issued by the server; the client keeps and replays it.

### C 0x76 client_environment (sign-in, protected)

Once per sign-in, about 2.9 s after S 0x44, before S 0xf. Bytes `00 50 11 00 05 00 00 00` (0x50 = 80
is likely the world), the launcher's NP12 sign-in token, the 16-byte machine id (as in C 0x7d), u32 5,
the LAN IPv4 address, the CPU model string (likely registry ProcessorNameString, code 0x165aa60),
`Microsoft Windows 10`, u32 RAM in MB, u32 4096, u32 logical CPUs, u32 unknown, 19 unknown bytes,
u32 time-zone offset in minutes, time-zone name, country (`US`), language (`en-US`), u32 0.

### C 0x78 hardware_identity (sign-in, protected; confirmed)

In the same millisecond as, just before, C 0x79 select_character; identical all 3 times: u32 0,
`01 00 2e`, u32 an id (also in C 0x7d and S 0x194), u8 0, the Wi-Fi MAC as text, the hardware id as
text, i32 -1. The hardware id = hex of the first 10 bytes of the 16-byte machine id (Ethernet MAC +
`00000043`), the same as C 0x7d's. Likely source: MachineIdLib.dll `MIDLib_GetMachineId` (it uses
GetAdaptersInfo and GetVolumeInformationA; `00000043` is likely a volume serial). Not verified.

### C 0x1c3 own_character_report (confirmed)

Own character id and name. Builder 0x29e7b90 runs every 600,000 ms and sends only when
`rand() % 6 == 0`; 4 seen, all on the same 10-minute grid. Origin: 0x29585b4 in 0x29536a0 (table
0x3594840); data from `[0x3bda7b0]` +0x2324 (id) and +0x2350 (name). No reply.

## Telemetry

### C 0x1ef event_report (one opcode, ~120 kinds; the first u32 is the kind)

| Kind | Seen | Size | What | Builder, timer |
|---|---:|---:|---|---|
| 0x01 | 230 | 118-682 | u32 N, N x {skill id, level, check}: your skill list with a check value per skill | 0x98bbf0 from 0x2da1b40; every setting 0x15b (default 120 s; median 124 s); at most setting 0x15c (100) entries per batch |
| 0x02 | 230 | 58-194 | u32 N, N x {id, check2} | 0x98c080, right after kind 1 |
| 0x27 | 93 | 22 | u64 global counter, u32 0, u32 an object's value (1008-22686) | 0x2dd3570 from 0x1af6530; per object every 300 s, or when the value is over 30,000 |
| 0x76 | 8 | 7 | **Cheat Engine check**: registry HKCU Software\Cheat Engine, HKLM SOFTWARE\Classes\.CETRAINER, HKCU ...\VersionCheck LastCheck (strings hidden with inserted `\r`); u8 0 = not found | 0xd15860 / 0xd15b10 (no callers), about hourly |
| 0x52 | 7 | 58 | u32 4, 4 x {u32 slot, u64 item id}: the equipped items | 0x2dd4f30 from 0x2da1b40, hourly |
| 0x20 | 3 | 18 | four zeros | 0x2dd20c0 from 0x2da1b40, every 2 h (setting 0xfc) |
| 0x65 | 5 | 14 | the decoy (see C 0x1f9) | 0x2edc670 |

All other kinds exist in the code but were not seen; main areas: 0x98b-0x98c (kinds 1-4), 0xd06-0xd1d
(anti-cheat: 7, 0xb, 0xc, 0x11, 0x12, 0x59, 0x5e, 0x76), 0x1ae-0x1af (0x2d-0x2f, 0x57, 0x60-0x75),
0x2dd0-0x2dd6 (singleton methods, 0xd-0x56), 0x2ed-0x2f0 (0x44, 0x61-0x6b, 0x72, the decoy).

### C 0x1a7 skill_check_report (confirmed)

u32 N1, N1 x {id, value}, u32 N2, N2 x {id, value, check}; length = 2 + 4 + 8 N1 + 4 + 12 N2 (49/49
parse). Builder 0x2dd7a60 from 0x2da1b40 every frame; it sends only when not empty, which is why
PACKETS.md saw 3,003 constructions for 3 sends. Rate limits from server settings 0x159 (default
50001: at most 50 entries every 1 s) and 0x15a (default 10010: at most 10 entries every 10 s). Records
are queued by 0x814110 (callers 0x2800f0, 0x2ab880, 0x2ac2f0, 0x2acfa0, 0x2afe00, 0x2b2ea7, 0x98bbf0);
ids seen are skill ids (1001000 ... 4201003: job x 10000 + skill). Mostly sent 3-34 ms after another player's skill use S 0x2b9 (34/49 within 50 ms): skills the client meets for the first time, with a check value computed from that skill level's data (likely a check for edited data files).

### C 0xbe hourly_activity_summary (confirmed)

Every hour at the same second (14:36:25 ... 21:36:25, 8/8): u32 1, u32 60, active minutes (53-60),
the most common place bucket (8 every time). Builder 0x2ef2c40 (called from protected code) keeps 60
one-minute slots (flags 0x3c13738, 12 counters per minute at 0x3c13780) filled by 0x2ef2ba0 from the
window-message handler 0x2cceac0 (mouse moves to the same spot are ignored); it sends only when 50+
minutes were active. Bucket (0x2ef2e60, client stage at 0x3c11074): 2 = no field, 8 = a field flag
(field+0xa8 -> +0x12c, likely town / Free Market), else 9-11. A second recorder 0x2ee3440 feeds
C 0x1ef kind 0x6b.

### C 0x424 resource_usage_report (confirmed)

Every ~31 min (30.5-34.6) on a timer, not tied to connections: u32 N, N x {u32 category (1 sound,
3 map image, 4 map object), path, u64 use count}. Builder 0x26a6a0 (method slot 0x3370f48) sends the
top 100; 0x26b2f0 the rest in a second C 0x424 in the same millisecond (15/15); then the counts reset.

### Join logs C 0x421, 0x420, 0x41f, 0x422, then C 0x425

One burst, same millisecond, order 0x421, 0x420, 0x41f, 0x422, from 0x2dd8620(singleton, kind)
(kind 1-6; also needs `0x1924180()` and singleton+0x3455 == 0; switch 0x1da).
- Shared header (0x512580): UTC time to the ms, world 80, account number, an id, u32 9, character
  name, u32 0, kind, 0, 0, a one-letter tag (`M` in 0x420, `U` in 0x41f/0x422), -1, 0.
- 0x421: kind and S 0x194's log id with a counter (29/29). 0x420: one record per equipped item (ids,
  u64 -1, stats); 1140 bytes. 0x41f: small id/value lists. 0x422: 44 numbers as text (likely stats).
- Kind 1 (2 seen): the first channel after sign-in, 0.7 s after C 0x7d. Kind 3 (27 seen, in 25 of ~48
  channel connections): 73-869 s after entry, from 0x2d6d620 (method 0x18aa2e0) when
  singleton+0x2f30 != 0 and +0x1e8 == 7,200,000.
- **C 0x425** (22 B; builder 0x2e043b0, called from 0x2dd8620 right after the four logs; 25/30 in that
  order): u64 from context +0x38 (0), u64 the character's money (-1 with no character), u32 from context
  +0x23d0 (0). All 30 identical. Purpose likely part of the same log.

### C 0x8f client_event_log

`ELog|16|VERSION|...|DATETIME|...|WID|80|Channel|...|Socket|ip:port|...|throw CDisconnectException|...
|CONNECTION_FROM_GAME_CLOSED|...` lines: at a re-login, the log of the previous disconnect (2 seen).
Builder 0x166f840 reads up to 0x2000 bytes of the log (lines made at 0x16700b0); the connection start
0x16626f0 sends 0x70/2, 0x71, 0x8f, 0x90, 0x91 in that order when there is something to send.

## World (formerly unknown)

- **C 0x153 quest_action** (likely): u8 4, u32 7707, u32 9010000 (an NPC), u16 x, u16 y; one at the
  daily reset (00:00 UTC), answered by S 0x8b about the same id 87 ms later. Builder 0x1f9ba50 from
  0x2e5b520 (27 callers).

## Channel entry, map loads and sign-in (round 2)

- **C 0x161 = the screen resolution** (confirmed), the answer to S 0x340 (53/53, median 57 ms; S 0x340
  -> 0x2a74140 -> 0x295b640 -> 0x29cde20): u16 mode (1 800x600, 2 1024x768, 3 1366x768, 4 1280x720,
  5 1920x1080, 6 1920x1200, else -1), then twice u32 width x 10000 + height (0x1126f40, 0x1127e20/30).
  The recorded `03 00 60 72 d0 00 ...` = 1366x768.
- **C 0x177 answers S 0x165** (confirmed): S 0x165 carries u32 V; the client works out X from object
  0x3bfa838 (fields +0xbc, +0xc0, +0xec, +0xf0: -2 if +0xf0 or +0xc0 is set, else 5 x (a*b/20 + 1)) and
  sends C 0x177 with X only when X != V. V = -1 was followed by C 0x177 54/54 times, V = -2 never. What
  the object measures is unknown (its creator uses UI-settings strings).
- **C 0x155** (empty; confirmed trigger): after the server changes your buffs (S 0x7f / S 0x80 with
  byte 2 = 1) when the changed mask overlaps a run-time mask at 0x3bf4920 (likely movement stats).
  Builders 0x2e17150, 0x2e165a0, 0x2e5d680. 2423/2423 within 2 s of an S 0x7f/0x80 (median 9 ms): one
  per map load.
- **C 0x23a, C 0x24f** (empty, back to back; trigger confirmed): from 0x2d6b9b0, a one-time setup on
  the first channel after a sign-in (S 0x1a9 -> 0x21277e0 -> 0x2127880 -> 0x212e730 -> 0x2d6b9b0, only
  when there is no character data yet). Names unknown.
- **C 0xef = set title item** (likely): builder 0x2e0dd90 refuses within 2,000 ms of the last one,
  accepts only item ids 3,700,000-3,709,999 (title items), looks the item up in inventory type 3, then
  sends u32 item id, u32 inventory slot. The SetField path (0x295afb0) sends (0, 0) when no title is
  found: the two seen, between C 0x2da and C 0x186 on the first channel after a sign-in. S 0x2b3 is
  another player's title item.
- **C 0x19b = key preset change** (static only): u8 1 or 2 + u32 (builders 0x1a929f0 / 0x1a92a80) when
  the user picks another preset; the server sends the selection in S 0x5f6 / 0x5f7. Not seen.
- **Sign-in** (details in `sign-in.md`): C 0x71 the server-issued registry marker `maple_ur` replayed at
  every login connection (confirmed); C 0x72 the patcher log, once per process (likely); C 0x80 world
  list request, C 0x75 select world, C 0xbc channel status request (confirmed); C 0xa1 an
  acknowledgement (likely). Client opcodes are probably not renamed on the login server.

## Names of the hidden Windows functions (live read)

Themida wiped MapleStory.exe's import names on disk. `analysis/live-imports.py` reads the running
game's pointer slots (read-only, from outside) and names each pointer from the DLL it lands in. The
import table holds 496 functions; besides it, the game fills these tables itself at run time:

- **.data 0x3c08290-0x3c08a88: ~250 Windows functions it looks up itself**, among them
  GetCurrentThread (0x3c082f0; also the import slot 0x3359308), **GetThreadContext** (0x3c08a88),
  **GetFocus** (0x3c08750), **GetForegroundWindow** (0x3c08808), GetModuleFileNameA (0x3c082a8),
  timeGetTime (0x3c089a8; also import 0x3359dc0), **OpenProcess, TerminateProcess, CreateProcessA,
  WinExec, SuspendThread, ResumeThread**, **FindWindowA, EnumThreadWindows, GetWindowTextA**,
  **SetWindowsHookExA**, **GetAsyncKeyState**, GetKeyState, the clipboard functions (OpenClipboard,
  GetClipboardData, SetClipboardData ...), registry, file and the socket functions (socket, connect,
  send, recv, sendto, recvfrom, WSASend, WSARecv ...).
- **.data 0x3bf36d0-0x3bf38b8: NexonAnalytics64.dll's API** (60 exports), including `inputProc`,
  `enqueueInputAction`, `registerKeymapInfo`, `setInputLogLevel/Option`, `enqueueSystemInfoLog`,
  `setCurrGameState`, `enqueueStageLog`, `enqueueErrorLog`. No plain-code caller of the input functions
  was found (see `docs/guides/PROTOCOL.md`, HTTPS services).
- **.data 0x3bfda00-0x3bfda78: jypc.dll** (16 exports with hashed names): Nexon "jyp" performance
  telemetry, see PROTOCOL.md.
- **.data 0x3c07750: PCOM.dll** (PcCreateObject, PcSerializeObject ...); **.data 0x3bbcb68: dbghelp.dll**
  (SymInitialize, StackWalk64, MiniDumpWriteDump: crash dumps).
- **0x3c00f70 = 0x1661826, inside SendPacket**: the pointer the C 0x9c builder checks (above).

## Still unknown

What fills the server settings map,
the callers of the protected builders, the subtype-13 UUID's producer, some C 0x76 fields, C 0x41f
and C 0x422's values, the bucket-8 flag of C 0xbe, C 0x265's trigger, C 0x286's trigger.
