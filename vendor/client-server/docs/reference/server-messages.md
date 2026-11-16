# Server messages: how the client handles them, and what they are

From the 2026-11-15 recordings (proxy-20261115-130134, -132117, -134015, -204932;
64 channel connections, all for one character) and MapleStory.exe build
0x6AEB667B (static, on disk; addresses are RVAs). Body offsets count from the
start of the body (bytes 0-1 are the opcode). **Confirmed** = handler read and
recordings agree, with counts; **likely** = layout plus timing or older-client
patterns; **unknown** = as stated. Names and short notes are in
`traffic/protocol.py`; counts per type in `message-breakdown.md`; the sign-in in
`sign-in.md`. Values tied to the character or account are described, not shown.
`traffic/fields.py` decodes S 0x165, 0x2b9, 0x472 and 0x5f5; `analysis/message-timing.py who` redoes the
"a player in the room" counts. `server-dispatch.md` is the generated opcode-to-handler map; regenerate and
check it with `analysis/re-tool.py dispatch APPDATA/MapleStory.exe --check`.

## How the client dispatches server messages

- **Decoders** (CInPacket): Decode1 0x75c8e0, Decode2 0x75c980, Decode4 0x75ca20,
  Decode8 0x75cd10, DecodeDouble 0x75cdb0, DecodeStr 0x75ce50 (u16 length +
  bytes), DecodeBuffer(n) 0x75d080.
- **Top level.** The receive loop 0x1667470 hands each message to:
  - **the context handler 0x2d7bfb0** (called at 0x16674a6) for 0x72..0x39d, a
    switch on opcode - 0x72 (table 0x2d7f144); opcodes it has no case for fall
    through to the field handler;
  - **CClientSocket::ProcessPacket 0x1667bc0**, which jumps straight into the
    Themida-virtualised code. It handles 0x1c..0x52, much of 0x72..0x1a8 and
    0x5cb / 0x5d4 / 0x62c / 0x62d. Their handlers have no direct caller and no
    method-table slot, so they are found only by matching decode order with a
    function nothing calls (S 0x39 0x99a470, S 0x3a 0x99bb80, S 0x5d4 0xd24750).
    The rest stay unmapped: that needs the VM's own handler table.
- **Field handler 0x18b1840** (a method in 10 method tables, called by the stage
  subclasses): 0x1ad..0x22c through a jump table at 0x18b3918; 0x4d5..0x5ae
  through a byte index 0x18b3b84 / table 0x18b3b18; then range checks:
  - 0x22d..0x3a2 -> **user pool 0x2a74140**: 0x22d enter (0x2a75220), 0x22e
    leave; 0x22f..0x29c "common" user messages 0x2a75df0 (pets 0x281-0x288 ->
    0x2830770); 0x29d..0x2ce "remote" (another player) 0x2a76560, which reads the
    u32 character id first (tables 0x2a76a74, 0x2a76b10/0x2a76b50); 0x2cf..0x3a1
    "local" (your character) 0x295b640, table 0x295e818;
  - 0x53..0x71 -> 0x1c0e260; 0x5f5..0x5f7 -> 0x1a91820; 0x452..0x46b NPCs
    0x1f020b0; 0x471..0x472 drops 0x1833060; 0x1a9..0x1ac -> 0x21277e0 (0x1a9 ->
    set_field 0x2127880).
- **Flood guard.** The remote-player dispatcher counts messages: more than 100
  (or 200) within 1 s sets a flag (object +0x41c8), after which only the attacks
  0x2a8-0x2ab are processed (0x2a99f90).
- **Your own character arrives as an S 0x22d** too, once per map load, usually
  last; its id (body offset 6 in S 0x22d) equals the id in C 0x1c3 on all 64
  connections.

## World

| Opcode | Name (confidence) | Fields | Handler | Evidence |
|---|---|---|---|---|
| S 0x2b9 | user_effect (confirmed for type 1) | u32 character id, u8 effect type; type 1: u32 skill id, u32 user level, u32 skill level | 0x2821e50 (also your own 0x2d1) | id is a player in the room 186/189; types 1 (171), 15 (17), 4 (1); real buff skill ids; C 0x1a7 follows (first sighting of a skill) |
| S 0x2a8 / 0x2aa | user_melee_attack / user_magic_attack (likely, strong) | u32 character id, u16 level, u32 skill id, ... | 0x2a8d790 (0x2a8-0x2ab) | 34/34 and 5/5 players in the room; warrior / magician skill ids; 0x2ab likely the touch attack |
| S 0x2ba | user_temp_stat_set (likely) | u32 character id, 124-byte buff mask (0xac7bb0), per-flag values, u16 delay, u8 | 0x2a90cf0 | 31/32 in the room |
| S 0x2bb | user_temp_stat_reset (likely) | u32 character id, 124-byte mask, u8 (131 B) | 0x2a90f00 | 2894/2983 in the room; one flag (dword 8 bit 15) in 2911, right after a player or pet enters |
| S 0x2bd | user_guild_info (likely) | u32 character id, u32 guild id, str name, u16 mark bg, u8 colour, u16 mark, u8 colour, u32 ... | 0x2a90090 | all 712 carry no guild; 696 right after the player's S 0x22d / 0x281 |
| S 0x2b0 | user_emotion (likely) | u32 character id, u32 expression (1-7), u32 duration (-1 default), u8 | 0x2821d40 -> 0x28c8cd0 | 58/60 in the room |
| S 0x2b2 | user_effect_item (likely) | u32 character id, u32 item id | 0x2a8f8a0 -> 0x28187c0 | 8 zero, one cash effect item |
| S 0x2b3 | user_title_item (likely) | u32 item id, u8 has text, [str] | 0x2819bd0 (C 0xef's builder calls the same 0x2819b40) | all 37 zero; 34/37 right after S 0x279 |
| S 0x279 | user_field_ready (likely, strong timing) | u32 character id, u8 (1 in 6071, 0 in 40) | 0x28f5190 | others: ~0.7 s after their S 0x22d (3590/3685); yours: after your C 0x196 (2363/2426, median 67 ms) |
| S 0x209 | unnamed: a per-player record list kept by the field | u32 character id, u8 a, u8 b; a=b=0: clean-up + u32 key, u8; else u32 count x {u32 key, u8, record} | 0x1910850 (list at field +0xa8 -> +0x1bc0) | once per map load for you (a=b=1, empty, 2426); right after each S 0x22e for the leaver (3591) |
| S 0x283 | pet_action (likely) | u32 owner id, u32 pet index, u8s | 0x2830770 -> 0x1f50b20 | 14/14 owners in the room |
| S 0x472 | drop_leave_field (confirmed) | u32 drop id, u8 how (0 expired; 2 picked up + u32 picker id) | 0x183ed10 | 17/17 drop ids match an earlier S 0x471 (whose drop id is at offset 4) |
| S 0x168 | unnamed key/value | u32, u32 -> client map at 0x3bfdfe0 | 0x2e6ef40 | 1 seen (2, 0) |

## Your own character and map loads

| Opcode | Name (confidence) | Fields | Handler | Evidence |
|---|---|---|---|---|
| S 0x7e | stat_changed (likely) | u8 (1 unlocks a pending request), u8, u8; u32 change mask + one field per bit (bit 16 EXP, bit 18 mesos); u8, u8 N, u8 [u32, u32] | 0x2e14950 | mask 0 in all 7342; three per map load (N = 2, 3, then 1) |
| S 0x7f / 0x80 | temp_stat_set / temp_stat_reset, your buffs (likely) | u8 exclusive-request flag, u8 "send C 0x155", u8, 124-byte mask | 0x2e165a0 / 0x2e17150 | headers 01 01 01; two per map load, just before S 0x1a9; trigger C 0x155 |
| S 0x165 | unnamed value check (fields and trigger confirmed) | u32 V | inline in 0x2d7bfb0 (0x2d7e80d) | the client computes X from object 0x3bfa838; if X != V it sends **C 0x177** with X. V = -2 in 2494, -1 in 65, 0 in 1; C 0x177 followed V = -1 54/54 times and never V = -2 |
| S 0x370 | unnamed value on your character | u32 -> own user +0x3fbc | local table (0x295de5b) | always 0, once per load, just before S 0x165 |
| S 0x340 | resolution request (confirmed) | empty | 0x2a74140 -> 0x295b640 -> 0x29cde20 | builds **C 0x161** (screen resolution); 53/53, median 57 ms |
| S 0x327 | unnamed flag | u8 (always 0) -> context +0x3455 | local case 0x295ce8f | if 0, compares a per-character value (key 7292) with the user's |
| S 0x39d | ignored by this client | u64 FILETIME 1900-01-01, u32 | none (default case) | 3 distinct u32 values over 64 connections |

## Channel entry

Sent once per channel connection (identical on all 64 unless noted):

| Opcode | Name (confidence) | Fields | Handler | Notes |
|---|---|---|---|---|
| S 0x5f5 | key_bindings (confirmed) | 4 presets: u8 use default; else 89 x {u8 type, u32 action}; u8 flag; if 1, 32 x u32 | 0x1a91820 -> 0x1a91430 | 1,342 B; presets 0-2 at 0x3c03070, 3 at 0x3c03e60; UI refreshed |
| S 0x5f6 / 0x5f7 | selected key preset (confirmed) | u32 | 0x1a91820 (globals 0x3c03e58 / 0x3c03e5c) | both 0; the user's change sends **C 0x19b** (u8 1 or 2 + u32; builders 0x1a929f0 / 0x1a92a80) |
| S 0x39 | server settings (confirmed) | count x {u32 id, u32 value, u32 value2, str scope} | 0x99a470 (VM-called) | 14 entries, scope "All" / "Project\|Center"; filtered on All / AllServer / Project / Client; also on the login connection; ids' meaning unknown |
| S 0x3a | server rules (confirmed list; use likely) | count x {u32 type, u32 id, str value, str scope} | 0x99bb80 (VM-called) | rule kinds TEXT / SID / CLIENT_VER, set_int, vector_int, WhiteList / BlackList; one rule: type 4, a list of ~45 e-mail domains, "AllServer"; also on the login connection |
| S 0x1ca | closes a UI object (confirmed), purpose unknown | empty | inline 0x18b1bab | deletes the object at [[0x3bdc150]+0x420] |
| S 0x5d4 | multi-type message; type 15 = a level table (likely) | u32 type 0..15; type 15: count x {u32 id, u32 level, u32 requirement, u64 amount, u32 item, u32, u32} | 0xd24750 (found by structure) | first channel after a sign-in; 5 levels x 9 items, a 5-level upgrade cost table; feature unknown |
| S 0x575 | unnamed (UI) | u8 subtype ... | 0x21e7750 | same UI singleton 0x3bda830 as S 0x5d4; first channel only |

VM-dispatched, so only the bodies are known (unnamed): 0xab (4 per connection:
subtypes 0x80, 0x81 with 4 (count, value) pairs, 0x01 with two amounts and the
character id, 0x68), 0xa9 (subtypes 0x15, 0x19, 0x27 + u8 0), 0x98 (character
id + zeros), 0x16b (character id, small ints, a short name), 0x156 (a FILETIME),
0x16c (double 1.0), 0xad (999,999,999 twice), 0xc6 ("kill_count" = "0"), 0x1a5
(small counters), 0x5cb, 0x97, 0x94, 0x96, 0x95, 0xbe (server), 0x1a8, 0xfe,
0x1e, and empty 0x1c, 0x2e, 0xcb. Only on the first channel after a sign-in:
0x183 (15 ids), 0x184 (tiered tables with dates), 0x118 ("Maple Events"), 0x113
(a 12-character hex id), 0x138, 0xe5, 0x13c, 0x12c, 0x131, 0x137, 0x149,
0x16d, 0x10e.

## Server timers (timing confirmed; handlers VM-dispatched, meaning unknown)

| Message | When | Body | Reply |
|---|---|---|---|
| S 0x72 | first 3.9-9.4 s after the connection opens, then every 60.39 s (p10-p90 60.20-60.90; 452 gaps) | 7 zero bytes (516/516) | none |
| S 0x18c | 0.1-0.3 s after the connection opens (right after S 0x5cb), then every 422.55 s (419.9-427.2; 39 gaps) | one of **10 fixed 4-byte values**, apparently random, the same set on every connection | none |
| S 0x62d | on the clock: every 600.0 s at about mm:m6:45-m6:58 UTC (49 of 50) | empty; 50 on 44 connections | none |
| S 0x62c | once per connection, 609-667 s after it opens (15 of the 16 connections over ~11 min) | empty | none (same timing as the client's decoy report, C 0x1f9/0x1fa/0x202) |

## Still unknown, and why

- **VM dispatch:** the handlers of 0x1c..0x52, most of 0x72..0x1a8 and the
  timers are reached only from the Themida-virtualised ProcessPacket, so they are
  not named; mapping them needs the VM's handler table.
- No class names: RTTI is stripped for the UI singletons (0x3bda830, 0x3bdc150),
  and UI text is in the StringPool, not in plain strings.
- Names for S 0x209, 0x165, 0x370, 0x168; S 0x7e's byte N; what object 0x3bfa838
  measures; which buff flags (8,15) and (11,10) are; the S 0x39 setting ids and
  the use of the S 0x3a domain list; S 0x5d4's feature. S 0x5d4 / 0x183 / 0x184 /
  0x575 rest on 2 instances.
