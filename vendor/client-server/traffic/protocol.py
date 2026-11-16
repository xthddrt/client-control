"""What each game message is, as far as the evidence goes.

Key: (direction, opcode). C = client to server, S = server to client. Opcodes
are the real ones (client opcodes after the connection's table, stream.py).
Confidence:
  confirmed - content and timing checked repeatedly against what the game did
              (the scraper's log, the in-process SendPacket record);
  supported - the content (strings, ids) or a strict request/answer pairing
              shows it, without an independent check of every field.
Evidence refers to the 2026-11-15 recordings (proxy-20261115-130134,
proxy-20261115-132117, proxy-20261115-134015: 290,670 messages, 48
connections, 1,626 map loads, 3 sign-ins) unless it says otherwise;
docs/guides/PROTOCOL.md has the details. A message not listed here is unnamed,
never guessed. Names of NPCs and items come from the game's own String data
(Data/String/String_000.wz).

PURPOSE (below) puts every message type seen so far in one purpose group, named
or not: what it is for, as far as the evidence shows.

Text in some messages is hidden by shifting each byte left one bit
(see reveal_shifted_text).
"""

from __future__ import annotations

NAMES = {
    # --- both servers ---------------------------------------------------------
    ("C", 0x70): ("client_context_report", "confirmed",
                  "u8 subtype: 1 = the CPU debug registers Dr0-Dr3 scrambled with a random value and CRC-32 table "
                  "entries, then Dr6/Dr7, riding on about 1 in 31 sends (1984 seen; all decode to 0); 2 = the same "
                  "at every connection start (first message, 62); 4 = u32 100 once per channel (60); 5 = game clock "
                  "and a frame counter, answering S 0x20 05 (188); 13 = a per-process UUID string (not MachineGuid), "
                  "answering S 0x20 0c (66)"),
    ("S", 0x32): ("opcode_table", "confirmed",
                  "DES-EDE2 text; decrypts every later client opcode of the connection "
                  "(28/28 SendPacket matches)"),
    ("S", 0x4f): ("client_state_poll", "confirmed",
                  "every ~60 s a burst of six, n = 0..5 (394 bursts); each is answered by C 0xc5"),
    ("C", 0xc5): ("client_state_poll_answer", "confirmed",
                  "~13 ms after each S 0x4f with the same n and a flag; the builder 0x166cf40 is the S 0x4f handler: "
                  "the flag is 1 when two run-time-resolved functions both return the game window (likely "
                  "GetForegroundWindow and GetActiveWindow: 'the game window is in front'); always 1 here"),
    ("S", 0x72): ("minute_tick", "supported",
                  "every 60.4 s, 0, 5 or 10 s from the start of an S 0x4f poll; 7 zero bytes; no client answer"),
    ("S", 0xc1): ("server_hour", "confirmed",
                  "byte 4 = the UTC hour (52/52), byte 2 = the day of the week (0 on Sunday 2026-11-15, 1 on "
                  "Monday); mostly at channel entry"),
    ("S", 0x18c): ("timer_7min", "supported",
                   "every 422.5 s (p10 420.8, p90 424.5), 4 random-looking bytes that no client message repeats; "
                   "purpose unknown"),
    ("S", 0x20): ("report_request", "confirmed",
                  "byte 05 -> C 0x70 subtype 5 (154/154), 0c -> subtype 13 (46/46), median 13 ms later"),
    ("C", 0xb9): ("device_stamp", "confirmed",
                  "shifted text 'date/time|account number|stamp id|': the stamp the server gave in S 0x3c on the "
                  "PREVIOUS connection (58/58), kept reversed in HKCU Software\\Wizet\\MapleStoryClassic maple_hf2"),
    ("S", 0x3c): ("device_stamp_issue", "confirmed",
                  "first on each channel connection: a new stamp (shifted text) for the client to store and replay "
                  "as C 0xb9 next time"),
    # --- login server ---------------------------------------------------------
    ("S", 0x1a): ("login_ping", "supported", "every 10-13 s on the login server"),
    ("C", 0x9b): ("login_pong", "supported", "within 60 ms after each S 0x1a (17/17)"),
    ("C", 0x73): ("passport_login", "supported",
                  "carries the launcher's NP12 passport, the same as MapleStory.exe's -nxl argument"),
    ("C", 0x76): ("client_environment", "supported",
                  "at sign-in: the launcher's NP12 token, the 16-byte machine id (as in C 0x7d), the LAN IPv4 "
                  "address, CPU model, Windows version, RAM MB, logical CPUs, time-zone offset and name, country, "
                  "language"),
    ("C", 0x78): ("hardware_identity", "confirmed",
                  "at sign-in, with C 0x79: an account-side id, the Wi-Fi MAC, and the hardware id = hex of the "
                  "machine id's first 10 bytes (Ethernet MAC + 00000043), the same as C 0x7d's"),
    ("C", 0x8f): ("client_event_log", "supported",
                  "text 'ELog|16|VERSION|...|DATETIME|...': at a re-login, the log of the previous disconnect "
                  "(CDisconnectException, CONNECTION_FROM_GAME_CLOSED; 2 seen)"),
    ("S", 0x2b): ("program_file_check_list", "confirmed",
                  "0.5 s after the login connection opens: u32 n (254), n file names (Canvas.dll, ...)"),
    ("S", 0x2c): ("data_file_check_list", "supported", "list of the client's data files (Data\\Base\\Base.wz, ...)"),
    ("C", 0x77): ("file_check_report", "confirmed",
                  "answers S 0x2b: constants, the ms the check took, a CRC of the CRC table (self-test), the count, "
                  "then per file its name (bytes rotated left 1) and CRC-32 of the whole file (MSB-first, init 0) + "
                  "0x2497d08d: matches the files on disk (254/254); builder 0xd12960 in the login stage"),
    ("S", 0x0): ("login_result", "supported", "account id and the masked e-mail address"),
    ("S", 0xb): ("world_list", "supported", "world and channel names ('Windia', 'Windia-1', ...)"),
    ("S", 0xf): ("character_list", "supported", "the account's characters by name"),
    ("C", 0x79): ("select_character", "supported", "the chosen character's id and name"),
    # --- channel server -------------------------------------------------------
    ("C", 0x7d): ("channel_enter", "supported",
                  "first game message on every channel connection: account id, character id, "
                  "the hardware id of C 0x78"),
    ("S", 0x194): ("session_log_id", "supported", "text '80_<n>_<date+time>_'; echoed by C 0x421"),
    ("C", 0x41f): ("join_log_a", "supported",
                   "one burst 0x421, 0x420, 0x41f, 0x422 (and 0x425), same header: time, world, account, ids, "
                   "character name, kind; kind 1 = first channel after sign-in, kind 3 = later on a timer while "
                   "in the game (27 seen); this one: small id/value lists"),
    ("C", 0x420): ("equipment_log", "supported", "join-log burst: one record per equipped item (ids, stats); 1140 bytes"),
    ("C", 0x421): ("join_log_ack", "supported", "the S 0x194 session log id with a counter"),
    ("C", 0x422): ("stats_log", "supported", "join-log burst: 44 numbers as text, likely the character's stats"),
    ("C", 0xdb): ("move", "confirmed", "SendPacket constructor and bodies (docs/guides/PACKETS.md)"),
    ("C", 0xd3): ("enter_portal", "confirmed",
                  "portal name strings ('in17', 'out00') at the scraper's room changes; S 0x1a9 within "
                  "0.15 s (30/30, median 108 ms; proxy-20261115-130134)"),
    ("S", 0x1a9): ("set_field", "supported",
                   "once per map change and at channel entry (then 3.7 KB with the own character)"),
    ("S", 0x22d): ("user_enter_field", "supported",
                   "other characters' names, pets and looks, one per player in the room"),
    ("S", 0x22e): ("user_leave_field", "supported", "6 bytes: a character id"),
    ("S", 0x281): ("pet_enter_field", "supported", "pet names ('Snail', 'Black Kitty')"),
    ("S", 0x23d): ("shop_in_field", "supported",
                   "shop title and its object id, the id later sent by C 0x181 to enter it"),
    ("C", 0x181): ("mini_room_action", "confirmed",
                   "u32 action: 2 = enter shop (+ u32 object id), 3 = leave; at every scraper shop visit"),
    ("S", 0x57a): ("mini_room_result", "confirmed",
                   "after every C 0x181 (620/620 within 1 s, median 65 ms): action 2 = owner and title, "
                   "action 3 = closed"),
    ("S", 0x57b): ("shop_item_list", "confirmed",
                   "u16 item count at offset 6 equals the scraper's count (6/6); first price 68,999 "
                   "matched the scraper's reading"),
    ("S", 0x579): ("mini_room_left", "supported", "after each C 0x181 action 3"),
    ("S", 0xae): ("broadcast_message", "supported",
                  "type byte at offset 2: 2, 3 and 8 carry 'Name : text' megaphone lines (one names "
                  "another channel), type 4 is empty and comes on every map load"),
    ("S", 0x22f): ("field_chat", "supported",
                   "char id, u8, u32, name, text ('sell 60% dagger att scroll 420K'): 996 of 1029 parse so; "
                   "the char id is a player in the room (95%)"),
    ("S", 0x29d): ("user_move", "supported",
                   "char id of a player in the room (97%), then a movement path laid out like C 0xdb's"),
    ("S", 0x282): ("pet_move", "supported",
                   "char id of a pet owner (85% of messages are from players with a known pet, against "
                   "42% for S 0x29d), u32 0, a movement path without the foothold field"),
    ("S", 0x452): ("npc_enter_field", "confirmed",
                   "object id (0x1e0a-0x1e0d), the NPC template at offset 6 (800007 Free Market Maple TV, "
                   "800008 Fredrick, 800009 Scrooge, 800018 Lewis in String.wz), position; ~2 per map load"),
    ("S", 0x456): ("npc_action", "supported",
                   "the object id of an S 0x452 NPC and an action byte, every ~2.6 s; the room's copy of the "
                   "controlling client's C 0x326"),
    ("S", 0x454): ("npc_control", "supported",
                   "a byte (1 = this client now controls the NPC), then S 0x452's layout; C 0x326 follows"),
    ("C", 0x326): ("npc_action_from_controller", "confirmed",
                   "the S 0x454 controller's NPC action; the server repeats the same bytes as S 0x456 to the "
                   "room ~35 ms later (19/19, proxy-20261115-204932)"),
    ("S", 0x471): ("drop_enter_field", "confirmed",
                   "a real item id at offset 21 (135/136: 'Lupin's Banana', 'Tree Branch', arrows...); "
                   "its object id is what pickup C 0x32b sends (docs/guides/PACKETS.md)"),
    ("S", 0x2b8): ("user_look_changed", "supported",
                   "a player's char id, then equipment item ids (offset 27, 112/112: helmets, hats...)"),
    ("S", 0x2b7): ("user_chair", "supported", "a player's char id and a chair item id ('Red Chair', 'The Green "
                   "Relaxer'; 18/34; the others carry 0: standing up)"),
    ("S", 0x2a9): ("user_ranged_attack", "supported",
                   "a player's char id and the projectile item id at offset 47 (25/25: throwing stars, arrows)"),
    ("S", 0x23f): ("user_scroll_effect", "supported",
                   "a player's char id and an upgrade scroll item id at offset 8 (9/9)"),
    ("S", 0x1c0): ("message_box_enter_field", "supported",
                   "the 'Snowy Snow' item and \"Gom2's Snowy Message: S> Kumbi 600k\" (1 seen)"),
    ("C", 0x1fe): ("character_info_request", "supported", "a character's name (1 seen), answered by S 0xa4"),
    ("S", 0xa4): ("character_info", "supported", "1,198 bytes about the named character, equipment included (1 seen)"),
    ("S", 0x8b): ("character_records", "supported",
                  "key=value text: 'LastDate=..;count10min=..;count30min=..', 'X=..;T=..', daily/weekly "
                  "quest resets 'q.._d_Rst', 'craftingWeekly_Rst'"),
    ("S", 0x166): ("server_time", "supported", "a FILETIME equal to the moment it is sent (45/45 channel entries)"),
    ("S", 0x19f): ("sign_in_time", "supported", "a FILETIME: the session's sign-in time, the same on later channels"),
    ("S", 0x36b): ("day_changed", "supported", "came at 00:00:01 UTC carrying that time (1 seen)"),
    ("C", 0xa3): ("data_file_list_report", "confirmed",
                  "36 pages of 5 nibble-swapped names: the 180 .wz files on disk; with C 0xa2 and 0xa4 from one "
                  "handler 0xd144f0 of a server list (likely S 0x2c), at one sign-in"),
    ("C", 0xa4): ("data_file_path_report", "confirmed",
                  "the same 180 files as NT paths (\\??\\C:\\Nexon\\...), likely of open file handles"),
    ("C", 0x424): ("resource_usage_report", "confirmed",
                   "every ~31 min (30.5-34.6): u32 n, n x (u32 category 1 sound / 3 map image / 4 map object, "
                   "path, u64 use count), the top 100 then the rest in a second 0x424"),
    ("C", 0x407): ("protected_check_6min", "confirmed",
                  "0.6-1.3 s after channel entry, then every 360.0 s; built in protected code (gate 0xd07c30): "
                  "a new value, the previous S 0x381's second value (a chain kept across connections, 103/104) "
                  "and a check byte"),
    ("S", 0x381): ("protected_check_6min_answer", "confirmed",
                   "answers C 0x407 (105/105, median 95 ms): u32 V1, 0, u32 V2, 0; V2 comes back in the next C 0x407"),
    # --- reports and checks (docs/reference/client-message-origins.md has the code paths) ---
    ("C", 0xba): ("input_idle_flag", "confirmed",
                  "u8: 0 = no keyboard/mouse input for 5 s, 1 = input again; checked once a second, sent only on a "
                  "change (strictly alternating, 76/76); builder 0xd101d0 -> 0xd18100"),
    ("C", 0xa2): ("file_list_result", "supported",
                  "encrypted: the game's exe path, u32 180, u8 1 (all listed files found), u32 180; before C 0xa3"),
    ("C", 0x13f): ("sent_packet_counter", "confirmed",
                   "every 30 s (0x2da1b40 per frame; median 31.0 s): u8 reset flag, a map of opcode -> counts filled "
                   "by the builders of attack-type messages, a map of sends counted by SendPacket itself for "
                   "0x13e/0x143/0x274/0xe1-0xe6/0x249; empty here (917/917 = 11 bytes); likely a requested-vs-sent "
                   "packet check"),
    ("C", 0x1ef): ("event_report", "confirmed",
                   "u32 kind first, ~120 kinds in the code; seen: 1 and 2 = record checks every 120 s (230 each), "
                   "0x27 = an object's value every 300 s (93), 0x52 = 4 equipment slots and item ids hourly (7), "
                   "0x76 = Cheat Engine registry check hourly, u8 0 = not found (8), 0x20 = four zeros every 2 h (3), "
                   "0x65 = decoy (see 0x1f9)"),
    ("C", 0x1a7): ("skill_check_report", "confirmed",
                   "u32 n1, n1 x (skill id, level), u32 n2, n2 x (skill id, level, check value): skills the client "
                   "meets for the first time, mostly just after another player's skill use S 0x2b9 (34/49 within "
                   "50 ms); the check comes from that skill level's data (likely edited-data detection); sent only "
                   "when not empty (49/49 parse)"),
    ("C", 0x1f9): ("decoy_report", "confirmed",
                   "all recorded ones are 0x2edc670's decoy: an event_report body (kind 0x65, rand 0-9, rand 0-14, "
                   "14 bytes) sent under a random one of 0x1ef/0x1f9/0x1fa/0x202 (15/15); the real 0x1f9 builder "
                   "0xd0f800 (anti-cheat area) never ran"),
    ("C", 0x1fa): ("decoy_report", "confirmed", "only made by the 0x1ef decoy (see 0x1f9)"),
    ("C", 0x202): ("decoy_report", "confirmed", "the decoy (see 0x1f9); the real builder 0x2f376c0 never ran"),
    ("C", 0xbe): ("hourly_activity_summary", "confirmed",
                  "every hour at the same second (8/8): u32 1, u32 60, active minutes (53-60), the most common "
                  "place bucket; from window messages counted per minute; sent only with 50+ active minutes"),
    ("C", 0x1c3): ("own_character_report", "supported",
                   "own character id and name; a 10-minute timer sends it with chance 1/6 (4 seen, on the grid)"),
    ("S", 0x5ac): ("key_check_start", "supported",
                   "every 21 min, empty; arms the client's key recorder (handler 0x1b00f90): C 0x1f3 follows "
                   "exactly 6:00 later when 300 key releases were collected (3/3)"),
    ("C", 0x1f3): ("key_sequence_fingerprint", "supported",
                   "subtype 4: count, then XOR of key codes and the MD5 (hex) of the 300-key sequence; likely an "
                   "anti-macro check"),
    ("C", 0x286): ("key_event_log", "supported", "54 records of key code, value, down/up (Esc and arrows; 1 seen)"),
    ("C", 0x265): ("performance_report", "supported",
                   "CPU % (system and process), working set, virtual memory in use, frame rate and more (2 seen, "
                   "each followed by C 0x266, S 0x1d, C 0x267)"),
    ("C", 0x266): ("protected_token_report", "supported",
                   "built in protected code: u64, the u64 token of the previous S 0x1d, a millisecond tick"),
    ("S", 0x1d): ("protected_token_answer", "supported", "echoes C 0x266's tick, a u64 and a new u64 token"),
    ("C", 0x267): ("protected_token_ack", "supported",
                   "u32 97, then 98 after S 0x1d; likely the ms the C 0x266 -> S 0x1d round trip took (85 ms at "
                   "the proxy)"),
    ("C", 0x153): ("quest_action", "supported",
                   "u8 4, quest-like id 7707, NPC 9010000, a position; right after the daily reset (1 seen), "
                   "answered by S 0x8b about the same id"),
    # --- changing channel -----------------------------------------------------
    ("C", 0x228): ("channel_entry_client_1", "supported",
                   "at channel entry in 40 of 45 channel connections (twice in 2), then C 0x161"),
    ("S", 0x340): ("screen_resolution_request", "confirmed",
                   "empty; its handler 0x29cde20 (local-user table 0x295e818) builds C 0x161 (53/53, median 57 ms)"),
    ("C", 0x161): ("screen_resolution", "confirmed",
                   "answers S 0x340: u16 mode (1 800x600, 2 1024x768, 3 1366x768, 4 1280x720, 5 1920x1080, "
                   "6 1920x1200), u32 width*10000+height twice (here 1366x768)"),
    ("S", 0x165): ("client_value_check", "supported",
                   "u32 V once per map load; the client works out its own value X from object 0x3bfa838 "
                   "(-2, or 5*(a*b/20+1)) and sends C 0x177 when X != V (inline case 0x2d7e80d)"),
    ("C", 0x177): ("client_value_check_answer", "confirmed",
                   "u32 X, only after an S 0x165 whose value differs: 54/54 after V = -1, none after V = -2"),
    ("C", 0xd4): ("change_channel", "confirmed",
                  "byte at offset 2 = channel - 1, then a u32 tick: 10/10 against the scraper's "
                  "channel changes (02 = ch 3, 00 = ch 1, 20 = ch 33, 1a = 27, 18 = 25, 03 = 4)"),
    ("S", 0x1b8): ("change_channel_refused", "confirmed",
                   "the scraper logged 7 refused changes; 7 of these came, each after C 0xd4"),
    ("S", 0x19): ("channel_server_addresses", "confirmed",
                  "count, then IPv4 + u16 port entries; the next connection went to one of them (7/7)"),
    ("S", 0x10): ("channel_server_addresses_login", "supported",
                  "login server, after C 0x79: the same address list; the channel connection followed (2/2)"),
    ("C", 0x14e): ("floor_portal", "supported",
                   "portal name pairs ('up00' -> 'up01') and positions, at each of the scraper's floor moves"),
    # --- map load: in this order once per S 0x1a9 (179/179 in the 2026-11-15 recordings) ---
    **{("S", op): (f"field_init_{n}", "supported", "once per map load, always in this order (179/179)")
       for n, op in enumerate((0x1fa, 0x82, 0x20f, 0x211, 0x384, 0x26f, 0x180, 0x314, 0x1f4, 0x215, 0x216),
                              start=1)},
    **{("C", op): (f"field_entered_{n}", "supported", "once per map load, always in this order (179/179)")
       for n, op in enumerate((0xde, 0x2da, 0x186, 0x196), start=1)},
    # --- a fixed 10-second cycle; its purpose is not known --------------------
    # every ~10 s the server asks twice: S 0x1b -> C 0x9c, S 0x62e -> C 0x42a
    ("S", 0x1b): ("debug_register_check", "confirmed",
                  "every 10.1 s: a memory range to checksum, a tag, a memory range to send back raw, a flag (all 0 "
                  "here, 2671/2671: never used), a new challenge and the client's previous one"),
    ("C", 0x9c): ("debug_register_report", "confirmed",
                  "answers S 0x1b (median 11 ms; the builder 0x1668850 is its handler), sections split by the "
                  "marker 123456789: the checksum of the asked range, the tag and the raw range echoed, the CPU "
                  "debug registers Dr0-Dr3/Dr6/Dr7 (GetThreadContext form, scrambled with a random value and CRC-32 "
                  "table entries; all 0 in 2777), a process-scan status (every 30 min all processes are opened and "
                  "read; 1 = scanned, 16 times), the challenge chain, input-event counters since the last check. "
                  "Hardware breakpoints show up here"),
    ("S", 0x62e): ("ping", "confirmed", "every ~10 s, empty; always answered by C 0x42a (2144/2144)"),
    ("C", 0x42a): ("pong", "confirmed", "answers S 0x62e, empty (builder 0x166bac0 writes no field)"),
    # --- round 2 (2026-11-15 evening): docs/reference/server-messages.md and sign-in.md ---
    # other players in the room: u32 character id first (a player in the room in 95%+), user pool 0x2a74140
    ("S", 0x2b9): ("user_effect", "confirmed",
                   "char id, u8 effect type; type 1 = skill use: u32 skill id, u32 user level, u32 skill level "
                   "(171 seen; handler 0x2821e50); C 0x1a7 often follows"),
    ("S", 0x2a8): ("user_melee_attack", "supported", "char id, u16, u32 skill id (warrior/close-range skills); "
                   "handler 0x2a8d790 serves 0x2a8-0x2ab"),
    ("S", 0x2aa): ("user_magic_attack", "supported", "as S 0x2a8 with magician skill ids"),
    ("S", 0x2ba): ("user_buffs_set", "supported", "char id, 124-byte buff mask (0xac7bb0), values, u16 delay, u8"),
    ("S", 0x2bb): ("user_buffs_reset", "supported", "char id, 124-byte buff mask, u8 (handler 0x2a90f00)"),
    ("S", 0x2bd): ("user_guild_info", "supported", "char id, u32 guild id, str name, guild mark fields; "
                   "all empty here (712)"),
    ("S", 0x2b0): ("user_emotion", "supported", "char id, u32 expression 1-7, u32 duration, u8"),
    ("S", 0x2b2): ("user_effect_item", "supported", "char id, u32 item id (5010008 once)"),
    ("S", 0x2b3): ("user_title_item", "supported", "u32 title item id (3700000-3709999 range), u8, [str]; all 0 here"),
    ("S", 0x279): ("user_field_ready", "supported",
                   "char id, u8: a player finished loading the map, ~0.7 s after its S 0x22d (3590/3685); "
                   "for you, ~67 ms after your C 0x196"),
    ("S", 0x283): ("pet_action", "supported", "owner char id, u32 pet index, u8s"),
    ("S", 0x472): ("drop_leave_field", "confirmed",
                   "u32 drop id (17/17 match an earlier S 0x471), u8 how: 0 expired, 2 picked up + picker char id"),
    ("S", 0x209): ("field_user_records", "supported",
                   "char id, u8, u8, then a keyed record list kept by the field (handler 0x1910850); once per load "
                   "for you, and after every S 0x22e to clear the leaving player's entries; meaning unknown"),
    # your own character (context handler 0x2d7bfb0 for 0x72..0x39d)
    ("S", 0x7e): ("own_stat_changed", "supported", "u8 x3, u32 change mask (0 in all 7342 here), fields, u8 N"),
    ("S", 0x80): ("own_buffs_reset", "supported", "u8 x3, 124-byte buff mask; 2 per map load (S 0x7f = set)"),
    ("C", 0x155): ("own_buffs_changed_ack", "confirmed",
                   "empty; after S 0x7f/0x80 whose mask touches a run-time set of buff flags (2423/2423 within 2 s)"),
    ("S", 0x370): ("own_value_3fbc", "supported", "u32 stored at own user +0x3fbc; 0, once per load; meaning unknown"),
    # channel entry
    ("S", 0x5f5): ("key_bindings", "confirmed",
                   "4 key presets of 89 entries (u8 type + u32 action) or 'use default', then 32 quick slots "
                   "(handler 0x1a91430)"),
    ("S", 0x5f6): ("key_preset_selected_1", "confirmed", "u32 stored at 0x3c03e58; changed by C 0x19b"),
    ("S", 0x5f7): ("key_preset_selected_2", "confirmed", "u32 stored at 0x3c03e5c; changed by C 0x19b"),
    ("S", 0x39): ("server_settings", "confirmed",
                  "count x {u32 id, u32 value, u32 value2, str scope ('All', 'Project|Center')} into the settings "
                  "map read by 0x98eae0 (handler 0x99a470); also on the login server"),
    ("S", 0x3a): ("server_rules", "confirmed",
                  "count x {u32 kind, u32 id, str value, str scope}: TEXT/SID/CLIENT_VER, set_int, vector_int, "
                  "White/BlackList (handler 0x99bb80); here one list of ~45 e-mail domains"),
    ("S", 0x5d4): ("table_update", "supported",
                   "u32 type 0-15 then a type-specific body (handler 0xd24750); type 15 = a 5-level upgrade cost "
                   "table; first channel after sign-in only"),
    ("S", 0x39d): ("ignored_by_client", "supported", "FILETIME 1900-01-01 + u32; no case in this build's handler"),
    ("S", 0x62d): ("ten_minute_tick", "supported", "empty, every 600 s aligned to the clock (unix time mod 600 ~ 410 s)"),
    ("S", 0x62c): ("connection_ten_minutes", "supported", "empty, once per connection 609-667 s after it opens"),
    ("C", 0x425): ("join_log_money", "supported",
                   "u64, u64 your character's mesos, u32: right after the join logs C 0x421-0x422 (25/30)"),
    ("C", 0x23a): ("first_channel_setup_1", "supported",
                   "empty, once on the first channel after sign-in (set_field -> 0x212e730 -> 0x2d6b9b0)"),
    ("C", 0x24f): ("first_channel_setup_2", "supported", "empty, right after C 0x23a"),
    ("C", 0xef): ("set_title_item", "supported",
                  "u32 title item id (3700000-3709999), u32 inventory slot; (0, 0) at sign-in when none"),
    # sign-in (login server; docs/reference/sign-in.md)
    ("C", 0x71): ("login_connect_marker", "confirmed",
                  "at connect: flags, a registry write test, and the server-issued marker kept in "
                  "HKCU\\Software\\Wizet\\MapleStoryClassic\\maple_ur, replayed every login"),
    ("C", 0x72): ("patcher_log_report", "supported", "once per process: u8 1, u8 found, lines of Patcher.log; then u8 0"),
    ("C", 0x80): ("world_list_request", "confirmed", "empty; answered by S 0x61 + S 0xb + S 0xb end (3/3)"),
    ("S", 0x61): ("login_screen_theme", "supported", "a string ('default') used for the world-select art path"),
    ("C", 0x75): ("select_world", "confirmed", "u8 0, u32 world id, u8, u8; answered by S 0xe in 45 ms (3/3)"),
    ("S", 0xe): ("select_world_result", "confirmed", "u8 result, str, u32 world id, u32 (handler 0x1bd25a0)"),
    ("C", 0xbc): ("channel_status_request", "confirmed", "u8 world id; built in the S 0xe handler"),
    ("S", 0x44): ("channel_status", "confirmed", "world id, channel list, per-channel load and state (40 channels)"),
    ("S", 0x11): ("select_channel_result", "supported", "result + the account block; answers C 0x76 (3/3)"),
    ("S", 0xd): ("login_auth", "supported", "u32 account number, u32 world id ('LoginAuth' event)"),
    ("S", 0x43): ("file_check_ack", "supported", "empty, 93-115 ms after C 0x77 (3/3)"),
}


def _group(name, note, client=(), server=()):
    return {**{("C", op): (name, note) for op in client}, **{("S", op): (name, note) for op in server}}


# What each message is for. Every type seen in the 2026-11-15 recordings is here.
PURPOSE = {
    **_group("world", "players, pets, NPCs, items and effects in the room you are in",
             client=(0xdb, 0x1fe, 0x326, 0x153, 0xef),
             server=(0x22d, 0x22e, 0x29d, 0x281, 0x282, 0x452, 0x454, 0x456, 0x471, 0x472, 0x279, 0x209,
                     0x2bb, 0x2bd, 0x2b9, 0x2b0, 0x2b3, 0x2ba, 0x283, 0x2b8, 0x2b7, 0x2a8, 0x2a9, 0x2aa,
                     0x23f, 0x2b2, 0x168, 0xa4)),
    **_group("maps", "moving between maps and loading one",
             client=(0xd3, 0x14e, 0xde, 0x2da, 0x186, 0x196, 0x155),
             server=(0x1a9, 0x1fa, 0x82, 0x20f, 0x211, 0x384, 0x26f, 0x180, 0x314, 0x1f4, 0x215, 0x216,
                     0x370, 0x165, 0x7e, 0x80)),
    **_group("channel_entry", "your character's data, sent once when a channel connection starts "
             "(the 0x183.. group only on the first channel after a sign-in)",
             client=(0x7d, 0x228, 0x177, 0x425, 0x23a, 0x24f),
             server=(0x39, 0x3a, 0x32, 0x2e, 0x1a5, 0x1e, 0x1ca, 0x98, 0x5f5, 0x5f6, 0x1a8, 0x5f7, 0x94,
                     0x96, 0x95, 0x5cb, 0xc6, 0xad, 0xbe, 0x327, 0xfe, 0x156, 0x166, 0x16c, 0xcb,
                     0x39d, 0x16b, 0x97, 0x19f, 0xab, 0xa9, 0x1c, 0x8b, 0x183, 0x184, 0x5d4, 0x16d, 0xe5,
                     0x12c, 0x131, 0x575, 0x138, 0x137, 0x149, 0x10e, 0x118, 0x113, 0x13c, 0x36b, 0xc1)),
    **_group("shops", "Free Market shops: signs, entering, contents, leaving",
             client=(0x181,), server=(0x23d, 0x57a, 0x57b, 0x579)),
    **_group("chat", "chat in the room, megaphones, message boards",
             server=(0x22f, 0xae, 0x1c0)),
    **_group("login_session", "signing in, choosing world and character, keeping and changing the connection",
             client=(0x73, 0x79, 0x9b, 0x75, 0x7a, 0x80, 0x96, 0xa1, 0xa6, 0xbc, 0xc1, 0xd4, 0x42a),
             server=(0x0, 0xb, 0xf, 0x10, 0x1a, 0x19, 0x1b8, 0x21, 0x23, 0x31, 0x43, 0x44, 0x4d, 0x61, 0xd,
                     0xe, 0x11, 0x62e)),
    **_group("integrity", "file checks, debug-register checks, client-state polls and checks built in the "
             "game's protected code",
             client=(0x77, 0xa3, 0xa4, 0xa2, 0xba, 0x407, 0x9c, 0xc5, 0x13f, 0x1f9, 0x1fa, 0x202, 0x1f3, 0x286,
                     0x266, 0x267, 0x70),
             server=(0x2b, 0x2c, 0x381, 0x1b, 0x4f, 0x5ac, 0x1d)),
    **_group("identity", "reports about this PC and device",
             client=(0x76, 0x78, 0xb9, 0x1c3, 0x71, 0x161), server=(0x3c, 0x340)),
    **_group("telemetry", "logs, metrics and usage reports, and the server's requests for reports",
             client=(0x8f, 0x41f, 0x420, 0x421, 0x422, 0x424, 0x1ef, 0x1a7, 0xbe, 0x265, 0x72),
             server=(0x194, 0x20)),
    **_group("periodic_unknown", "steady server timers whose purpose is not known",
             server=(0x72, 0x18c, 0x62c, 0x62d)),
}


def purpose_of(direction, opcode):
    """(group, what the group means) for 'client_to_server'/'server_to_client' and an int opcode, else (None, None)."""
    if opcode is None:
        return None, None
    return PURPOSE.get(("C" if direction == "client_to_server" else "S", opcode), (None, None))


def name_of(direction, opcode):
    """(name, confidence) for 'client_to_server'/'server_to_client' and an int opcode, else (None, None)."""
    if opcode is None:
        return None, None
    entry = NAMES.get(("C" if direction == "client_to_server" else "S", opcode))
    return (entry[0], entry[1]) if entry else (None, None)


def reveal_shifted_text(body):
    """Text hidden by a one-bit left shift: even bytes shifted back, odd bytes shown as '.'."""
    return bytes((b >> 1) if b % 2 == 0 and 0x20 <= b >> 1 < 0x7F else 0x2E for b in body).decode("ascii")
