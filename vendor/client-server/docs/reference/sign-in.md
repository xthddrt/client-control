# The sign-in, message by message (login server, port 8484)

From the three sign-ins recorded on 2026-11-15: the game process's first sign-in
(proxy-20261115-130134, its server side decoded offline with
`traffic.proxy.decode_recording`) and two re-logins in the same process
(-132117, -134015). MapleStory.exe build 0x6AEB667B; addresses are RVAs. Times
are seconds from the connection opening. **Confirmed** = handler or builder read
and the recordings agree (3/3 unless noted); **likely** = shape and timing only.
Personal values (account number, e-mail, ids) are described, never shown.
`analysis/message-timing.py show REC --type any --conn N` prints one connection's message timeline;
`traffic/fields.py` decodes C 0x75 and S 0x44. `server-dispatch.md` includes the regenerated login-stage
jump table and its checked handler routes.

## How the client handles login-server messages

- **Login-stage handler `0x1bc83d0`** (method-table slot 0x350dab0), the login
  counterpart of the field handler 0x18b1840: a switch over opcodes 0..0x61 (byte
  table 0x1bc8a00, offsets 0x1bc8978).
  - 0x0 -> 0x1bd0200, 0xb -> 0x1bd1cc0, 0xc and 0xd inline, 0xe -> 0x1bd25a0,
    0xf -> 0x1bd2a40, 0x10 -> 0x1bd8fd0, 0x11 -> 0x1bd10b0.
  - 0x12-0x17 -> 0x1bd17f0 / 0x1bd60e0 / 0x1bd8a80 / 0x1bd6b00 / 0x1bd7ac0 /
    0x1bd8650; 0x24 / 0x25 / 0x26 -> 0x1bda350 / 0x1bdae80 / 0x1bdb2d0.
  - 0x28, 0x2a, 0x33-0x38, 0x46, 0x47, 0x49 inline or small helpers; 0x44 ->
    0x1bcb570, 0x45 -> 0x1bcb700, 0x52 -> 0x1bda6a0, 0x61 -> 0x1bdcd90; 0x22 ignored.
  - Outside the table: 0x53-0x71 -> 0x1c0e260, 0x1a9-0x1ac -> 0x21277e0, 0x5f8 ->
    0x1bdb580, 0x61f -> 0x1bdca40, 0x624 -> 0x1bcc220, 0xfbe -> 0x1bcbf30.
- **Not in that switch:** 0x1a, 0x1b, 0x20, 0x21, 0x23, 0x2b, 0x2c, 0x31, 0x39,
  0x3a, 0x43, 0x4d, 0x4f, 0x113. They go to the connection-level dispatcher
  `0x1667bc0` (called from the receive loop 0x1678c80 at 0x16794b8), which is
  Themida-virtualised, so which handler serves S 0x21 / 0x23 / 0x31 / 0x43 / 0x4d
  cannot be read; they are matched by shape and timing only.
- **Client opcodes are probably not renamed on the login server.** The login
  server never sends an opcode table (S 0x32). Two client messages at or above
  0xC7 were seen there, wire 0x2e7 (6 bytes) and 0x1ef (22 bytes), and both match
  a static builder of exactly that size (likely, 2 cases).

## First sign-in of a game process (130134)

| t (s) | dir | opcode | name (confidence) | what it means |
|---|---|---|---|---|
| 0.43 | C | 0x70 | client_context_report, subtype 2 | debug registers at connection start |
| 0.43 | C | 0x71 | login_connect_marker (confirmed) | the server-issued registry marker, below |
| 0.44-1.57 | C | 0xa6 x22 | unnamed (likely loading steps) | u32 step ids 1, 0xb, 2, 5, 3, 4, 0xc..0x1c while the game finishes loading; first launch only; builder 0x2d4cba0 |
| 0.48 | S | 0x20 | report_request | 5 zero bytes |
| 0.52 | S | 0x39 / 0x3a / 0x2b / 0x21 / 0x23 | opening burst, same ms | 0x39 server settings and 0x3a server rules (server-messages.md); 0x2b the 254 program files to check; 0x21 bytes `01 00`; 0x23 empty |
| 1.22 | C | 0xa1 | unnamed (likely an ack) | below |
| 1.22 | C | 0x72 | patcher_log_report (likely) | below |
| 1.27 | S | 0x31 | unnamed | u8 1 |
| 1.28 | C | 0xc1 | unnamed, empty | 2 ms after S 0x31; first launch only; builder 0x166cbf0 |
| 1.32 | S | 0x4d | unnamed | u8 1; first launch only |
| 1.57 | C | 0x70 subtype 1 | | random debug-register check |
| 8.91 | C | 0x73 | passport_login | the launcher's NP12 passport |
| 8.98 | S | 0x0 | login_result | then S 0x4f x6 / C 0xc5 x6 (window-state polls) |
| 9.30 | C | 0x9b, 0x7a, 0x77 | login_pong, unnamed 24 B, file_check_report | |
| 9.40 | S | 0x43 | file_check_ack (likely) | empty, 93 ms after C 0x77 (93-115 ms in 3/3) |
| 9.87 | C | 0x70 subtype 13 | | device id |
| 10.29 | C | 0x80 | world_list_request (confirmed) | empty |
| 10.34 | S | 0x61 | login_screen_theme (likely) | string "default" |
| 10.43 | S | 0xb, 0xb | world_list | the second is the end marker (ff) |
| 11.06 | C | 0x75 | select_world (confirmed) | world 80 |
| 11.10 | S | 0xe | select_world_result (confirmed) | |
| 11.11 | C | 0xbc | channel_status_request (confirmed) | u8 world 80 |
| 11.15 | S | 0x44 | channel_status (confirmed) | 291 B, 40 channels with load |
| 14.32 | C | 0x76 | client_environment | also carries the world and channel at its start |
| 14.39 | S | 0x11 | select_channel_result (likely) | 108 B account block |
| 14.44 | S | 0xd / 0x20 `0c` / 0x113 / 0xf | login_auth (likely) / report request / unnamed / character_list | 0x113 = account number + a 12-character hex id |
| 14.44 | C | 0x96, 0x70 subtype 13 | 0x96 sent once per process from the S 0xd case | |
| 14.49 | S | 0x2c | data_file_check_list (confirmed) | u32 180 + 180 names |
| 14.57 | C | 0xa2, 36x 0xa3, 36x 0xa4 | the answer to S 0x2c | 86 ms later, all within 6 ms |
| 18.18 | C | 0x78, 0x79 | hardware_identity, select_character | |
| 18.25 | S | 0x10 | channel_server_addresses_login | |
| 18.30 | | | close | the channel connection follows |

Request -> answer times (3/3): C 0x80 -> S 0x61 46-47 ms; C 0x75 -> S 0xe 45 ms;
C 0xbc -> S 0x44 44-46 ms; C 0x76 -> S 0x11 55-56 ms.

## Re-logins in the same process (132117, 134015)

- At 0.42 s C 0x70, C 0x71, C 0x8f (the log of the previous disconnect) and C
  0xa1 leave in the same millisecond, all from the connect routine 0x16626f0.
- The server's opening burst includes S 0x31; there is no C 0xc1, S 0x4d or C 0xa6.
- C 0x73 at ~0.9 s, then 3 ms later C 0x72 = `00` (already reported in this
  process) and C 0x77; then S 0x0, and S 0x43 115 ms after C 0x77.
- The client then waits, answering S 0x1a pings with C 0x9b every 10-13 s, for 6
  min (132117) or 85 s (134015), before C 0x80; after that the order is as above.
- No C 0x96 (once per process), no S 0x2c and no C 0xa2/0xa3/0xa4.

## Client messages

- **C 0x71 login_connect_marker** (52 B; builder 0x16676e0, called only from the
  connect routine 0x16626f0 at 0x1663f83, login branch). Same bytes 3/3. u8 1,
  u32 1, u32 100, u8 0, u8 from account+0x22b4, three u8 (all 0); u8 = 1 if a
  registry write test passes (0x166e650 writes 10 random bytes to the REG_BINARY
  value `maple_te` and reads them back); then u32 length + the bytes of
  `HKCU\Software\Wizet\MapleStoryClassic\maple_ur` (31 bytes; matches Wine's
  user.reg byte for byte). `maple_ur` is written by 0x166e0f0, a VM-called
  server-message handler that also sends C 0x95 with the same block: **a
  server-issued marker kept in the registry and replayed at every login
  connection**, like C 0xb9's stamp.
- **C 0xa1** (6 B, u32 0): the value at connection+0x14c, set by handler
  0x1677810 from a server message that pushes data chunks (which one is unknown).
  Sent at connect when that transfer is already done, or from the receive loop at
  0x167907b when it finishes. Likely an acknowledgement.
- **C 0x72 patcher_log_report** (likely; builder 0x166b1f0, VM-called; content
  0x2f31780 -> 0x2f30a20). Once per process: u8 1, u8 "Patcher.log found",
  then a string of lines taken from Patcher.log (" -> ", "(...)", "eof"); every
  later login u8 0 only. Patcher.log does not exist here, which fits `01 00` and
  an empty string.
- **C 0x80 world_list_request** (empty; builder 0x1be1150): sent only when the
  login stage is idle (+0xd4 == 0), then marks it busy. Callers: the login
  dialog's "login" button 0x11b5a20, the post-login routine 0x1bc4690, the S 0xf
  handler 0x1bd2a40. Answered by S 0x61 + S 0xb + S 0xb end.
- **C 0x75 select_world** (9 B; builder 0x1bcde80; callers 0x1210ab6 (UI),
  0x1bc7ea9): u8 0, u32 world id, u8 = an account string is set, u8 a cached
  setting.
- **C 0xbc channel_status_request** (u8 world id): built in the S 0xe handler at
  0x1bd298f when the result is 0 and the world exists; also by 0x1bdca40 (S 0x61f).

## Server messages

- **S 0xe select_world_result** (0x1bd25a0): u8 result, str message, u32 world
  id, u32 (-1). Non-zero: an error dialog (0x1bc8b40); zero: C 0xbc and the next
  screen (0x1be0f20).
- **S 0x44 channel_status** (0x1bcb570): u32 world id; u32 n + n x (u8 channel
  index, u8 flag) (40 pairs); u8 m + m x (u32 load, u8 state). Stored per channel
  (+8 load, 47-73 here; +0x1c state==1; +0x18 state != 2), then the channel list
  with load bars is redrawn (0x120eb80).
- **S 0x11 select_channel_result** (likely; 0x1bd10b0): u8 result, str message;
  failure returns to the title. Then the account block: account number, the
  12-character hex id, a FILETIME, 8 bytes that change every time, the masked
  e-mail and small fields; stored with the same helpers as S 0x0. Answers C 0x76.
- **S 0xd login_auth** (likely; inline 0x1bc8581): u32 account number -> 0x2ee20d0
  (raises a "LoginAuth" event), u32 world id; sends C 0x96 once per process.
- **S 0x61 login_screen_theme** (likely; 0x1bdcd90): one string ("default"),
  used in the world-select screen's `Map/Obj/%s.img/...` art path.
- **S 0x2c data_file_check_list** (confirmed): at 14.485 s, 5,982 B = u32 180 +
  180 strings, consumed exactly: every `Data\...\*.wz`. Handler 0xd144f0 builds C
  0xa2 86 ms later, then 36 C 0xa3 and 36 C 0xa4. Only at this, the process's
  first sign-in; why the server asked then is unknown.
- **S 0x21, 0x23, 0x31, 0x4d** (VM-dispatched): the only two-u8 handler in that
  set is 0x166b130 (u8 #1 to 0x1675d10, u8 #2 to connection+0x144; likely S
  0x21); the one-u8 handlers 0x166b050 (0 -> error 0x6ad) and 0x166cb80
  (-> connection+0x158) are likely S 0x31 / S 0x4d in some order.
- **S 0x43 file_check_ack** (likely): empty, 93-115 ms after C 0x77 in all 3.

## Unknown

The opcode-to-handler step inside 0x1667bc0; what S 0x21's flags control;
which server message sets C 0xa1's value; S 0x113, C 0x7a, C 0x96, C 0xa6 beyond
the notes above. Two of the three sign-ins are re-logins in one process.
