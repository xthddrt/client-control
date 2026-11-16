# Everything the game communicates: what we know

This is the overview. It says, for every kind of traffic the game's programs send or receive: who
sends it, which way it goes, how much, what it means, how sure we are, and where the details and the
code that found them are. Measured on 2026-11-15 on this PC (Linux, Wine), with MapleMarket's scraper
playing.

"Up" = client to server (this PC sends). "Down" = server to client (this PC receives).

## 1. The whole picture

From 13:40 to 21:49 (8.2 hours): 934 TCP connections, **21.8 MB up and 102.2 MB down** (the shares below
are from the same data rounded; the generated table has the exact figures). Generated
table: [reference/traffic-breakdown.md](reference/traffic-breakdown.md).

| Category | Sender | Up | Down | Can we read it? |
|---|---|---:|---:|---|
| Game: channel servers | MapleStory.exe | 2.15 MB (10%) | 95.5 MB (96%) | **Yes, fully decoded both ways** |
| Game: login server | MapleStory.exe | 10 KB | 10 KB | **Yes** |
| Analytics | NexonAnalytics64.dll | **13.9 MB (65%)** | 0.65 MB | **Yes, for connections open at a read of the game's memory** (section 5) |
| Anti-cheat check-in | grap-communicator64.aes | 5.0 MB (24%) | 2.4 MB | Replies yes (older work), requests no |
| Anti-cheat settings | NGS anti-cheat | 8 KB | 0.28 MB | No (HTTPS) |
| Crash reporter play-time counter | CrashReporter.dll | 28 KB | 0.23 MB | **Yes**, from its code and Wine's web cache |
| Nexon session-token refresh (port 47611) | nmconew64.dll | 0.26 MB | 0.26 MB | **Yes, fully decoded** |
| "Who is playing" counter (port 8913) | nexon_x64.dll; the launcher | 6 KB | 6 KB | **Yes** (plain text) |
| Launcher web (QUIC, UDP 443) | the launcher | 4 KB | 8.5 KB | No (encrypted) |

What stands out:
- The biggest upload is **not the game**: Nexon's analytics library sends about 6.5 times more than
  the game itself, and the anti-cheat about 2.4 times more.
- Downloads are almost all the game world (other players, shops, maps).

## 2. How it is captured

`analysis/game-proxy.sh` puts every Wine program of the game (launcher, game, overlay, anti-cheat) in
one group and:
- sends **every IPv4 TCP connection** of that group through the proxy (`traffic/proxy.py`), which
  records every byte with a timestamp, decrypts and names game messages live, and notes the server
  name of TLS connections;
- writes **everything else** (UDP, QUIC, ICMP, IPv6) of the group to a pcap.

Not covered: traffic between the game's own programs on this PC (127.0.0.1), name lookups (through
the PC's own resolver), and connections that were already open when a recording started.
**Game start is not recorded yet:** the current game process started at 13:36, before the 13:40
recording, and the 13:01 recording that did include a start only took the game ports. Two things talk
only at game start (jypc.dll, port 58880). The proxy now runs all the time, so the next normal
relaunch of the game will be recorded with everything. In this
window the first pcap (13:40-20:49) captured nothing; the one since 20:49 works. The pcap's packets to
192.0.2.1:9 (a reserved test address) are not the game's.

## 3. The game servers (decoded)

**How the encryption works** (docs/guides/PROTOCOL.md, section 2): the server opens with an
unencrypted handshake holding two 4-byte keys (IVs). Each frame has a 4-byte header derived from the
IV; the IV changes after each frame. Client bodies are AES-256-OFB in blocks (restarting after 1456
bytes, then every 1460); server bodies are AES on the login server and "subtract the IV's first byte"
on channel servers. Client message numbers above 0xC6 are shuffled per connection; the server's first
large message (0x32, DES-encrypted) is the table that unshuffles them.

**What is in it** (373,193 messages; generated tables per type:
[reference/message-breakdown.md](reference/message-breakdown.md)):

| Group | Up (61,420 messages) | Down (311,773 messages) |
|---|---:|---:|
| World: players, pets, NPCs, items, effects around you | 13.6% (your movement) | 43.0% |
| Shops: signs, entering, item lists | 42.9% | 37.0% |
| Maps: portals, map loading | 22.4% | 13.9% |
| Integrity: checks of the client | 14.7% | 1.8% |
| Sign-in and session: login, channel change, 10 s ping | 4.5% | 0.9% |
| Telemetry: logs and reports | 1.3% | 0.1% |
| Channel entry: your character's data when joining | 0.4% | 0.9% |
| Identity: this PC and device | 0.1% | 0.02% |
| Chat | - | 2.3% |
| Timers of unknown purpose (S 0x72 every minute, S 0x18c every 7 min) | - | 0.2% |
| Unknown | 2 messages | 0.02% |

Most messages have a name and every type seen has a group; the names, with their evidence, are in
`traffic/protocol.py`. Round 2 (2026-11-15 evening) mapped:
- **the whole sign-in**, step by step both ways ([reference/sign-in.md](reference/sign-in.md));
- **what the server sends when you join a channel**: your key bindings, server settings and rules
  (one rule is a list of about 45 e-mail domains), a request for your screen resolution;
- **the busy world messages**: other players' skills, attacks, buffs, guild, faces, title items,
  "finished loading the map", items vanishing from the floor; your own stats and buffs at each map
  load ([reference/server-messages.md](reference/server-messages.md)).

About 30 server message types, mostly sent once when you join a channel, are handled inside the
game's protected (scrambled) code, so their names cannot be read from the program; only their
contents are known.

**Question and answer pairs** (blocking one half breaks the other):
- you ask: shop 0x181 -> 0x57a/0x57b (0x579 on leaving); portal 0xd3 -> 0x1a9 + 11 map messages ->
  your 4 "map loaded" messages; change channel 0xd4 -> 0x19 (address) or 0x1b8 (refused); 6-minute
  check 0x407 -> 0x381; performance report 0x265 + 0x266 -> 0x1d -> 0x267;
- the server asks: 0x1b -> 0x9c (debug registers, every 10 s); 0x4f -> 0xc5 (client state, every
  60 s); 0x62e -> 0x42a (ping, every 10 s); 0x20 -> 0x70 (reports); 0x2b/0x2c -> 0x77 (file check);
  0x3c -> 0xb9 (device stamp); 0x5ac -> 0x1f3 six minutes later (key check); 0x454 -> 0x326 -> 0x456
  (NPC control); 0x340 -> 0x161 (screen resolution); 0x165 -> 0x177 (only when the values differ);
  0x7f/0x80 (your buffs) -> 0x155.

## 4. What the client reports about itself

Details and code paths: [reference/client-message-origins.md](reference/client-message-origins.md).

- **Debugger checks.** The CPU's debug registers (hardware breakpoints) are sent scrambled in C 0x9c
  every 10 s, in C 0x70 subtype 2 at every connection start and in C 0x70 subtype 1 on about 1 in 31
  sends. All are 0 here. **Never use hardware breakpoints on the live game.**
- **Memory checks the server can ask for.** Every 10 s the server's S 0x1b may name a memory range
  for the client to checksum and another to send back raw. In these recordings it never did (all 0).
- **Process scan.** Every 30 min the client opens every process on the PC and reads its path and name;
  the 10-second report carries only whether it scanned (16 times), not the list.
- **Is anyone at the keyboard, is the window in front.** C 0xba flips between "no input for 5 s" and
  "input again"; C 0xc5 (every 60 s, six times) says whether the game window is the active one; the
  10-second report counts input events.
- **Cheat Engine check.** Hourly, C 0x1ef kind 0x76 reports whether Cheat Engine's registry keys
  exist (0 = no).
- **Input checks.** Every 21 min the server sends S 0x5ac; the client records key releases for 6 min
  and, if 300 were pressed, sends an MD5 of the sequence (C 0x1f3). C 0x286 is a raw key log. C 0xbe
  every hour summarises how many minutes had input and where the character was.
- **Packet counting.** Every 30 s C 0x13f compares attack-type messages made by the game with those
  sent (empty here: the scraper never attacks). C 0x1a7 and C 0x1ef kinds 1/2 send check values of
  skills (yours every 120 s, others' when first seen), likely to catch edited data files.
- **The 6-minute challenge.** C 0x407 / S 0x381 pass a value back and forth that lasts the whole game
  process: dropping or replaying one breaks it.
- **Decoys.** About once per channel connection, a meaningless report is sent under a random one of
  four message numbers (C 0x1ef/0x1f9/0x1fa/0x202), likely to confuse anyone mapping the protocol.
- **Files.** At sign-in the server lists 254 program files (S 0x2b) and the client answers with a
  CRC-32 of each whole file (C 0x77; matched on disk 254/254). Once it also listed its 180 data files
  and their paths (C 0xa2, 0xa3, 0xa4).
- **This PC.** At sign-in: CPU model, Windows version, RAM, CPU count, LAN IP address, time zone,
  country and language (C 0x76); the Wi-Fi MAC and a hardware id made from the Ethernet MAC and a
  volume serial (C 0x78, also in C 0x7d on every channel). A per-process UUID answers S 0x20 0c.
- **Screen resolution.** When you join a channel the server asks (S 0x340) and the client answers
  with its resolution (C 0x161; 1366x768 here).
- **Registry marker.** At every login connection the client sends back a value the server once stored
  in the registry (C 0x71, `maple_ur`), and once per launch a summary of the patcher's log (C 0x72).
- **Hook check.** After each 10-second report the client checks that its own send function has not
  been redirected; if it has, it can crash itself on purpose.
- **Hidden tools.** The game looks up about 250 Windows functions by hand so they do not show in the
  program file. A read of the running game's memory (from outside, read-only) named them all; they
  include tools to watch other programs and windows (open, stop or end a process, find windows and
  read their titles, hook input, read key states, use the clipboard).
- **Device stamp.** The server gives a stamp on each channel (S 0x3c); the client stores it in the
  registry and sends it back on the next connection (C 0xb9): a server-issued device marker.
- **The character.** Every 10 min with chance 1/6, its id and name (C 0x1c3); at channel entry and
  later, equipment and stats logs (C 0x420, 0x422) and the equipped items hourly (C 0x1ef kind 0x52).
- **Performance.** CPU, memory and frame rate now and then (C 0x265), with a token exchange built in
  protected code (C 0x266, S 0x1d, C 0x267).
- **Usage.** Which sounds and map images were used, every ~31 min (C 0x424); the log of the last disconnect at re-login (C 0x8f).

Many intervals and switches come from the server (a settings map the client reads), so Nexon can
change them without an update.

## 5. The other services

Details: docs/guides/PROTOCOL.md, section 1.

- **Analytics** (`public.api.nexon.com`, NexonAnalytics64.dll): two connections at a time, each about
  an hour, 1.7 MB per hour up. **Decrypted** for 48 minutes (its keys were read from the running game's
  memory with `analysis/tls-keys.py`, section 8). Every record carries the **account number, session id, public IP, country and two machine
  ids**. What it sends:
  - **every mouse movement, click and wheel turn in the game window**, with times and positions, in
    batches of 1,000 (about every 90 s), with your character, map and position;
  - every click again, every 10 s, from the library's own input logger;
  - **every key press and release**, every 5 minutes, with your character's position;
  - every 10 minutes, **raw copies of three pieces of the game's memory**: your account and character
    data, a sign the game is running under Wine, and **a list of the running Windows programs** (under
    Wine that is only the game's own programs, not your Linux programs);
  - loading stages at start and exit, and a play-time summary at quit.
  No window titles, clipboard or screenshots were found in it.
- **Anti-cheat check-in** (`x-csauth.ngs.nexon.com`, grap-communicator64.aes): a new connection every
  62 s, ~10 KB up, ~5 KB down. The replies can be read (older work in this repo): a token, the next
  check time, an emergency stop, a detection list and a "you were caught" message. The requests use
  a cipher tied to this PC that is not broken; older work links their periodic size bumps to the
  anti-cheat's screenshot feature.
- **Anti-cheat settings** (`x-config.ngs.nexon.com`): ~47 KB at session start: the list of switched-on
  checks and the detection signatures.
- **Crash reporter** (`68bd384lrg.execute-api...amazonaws.com`, CrashReporter.dll from Nexon Korea's
  "LiveAssist"): at game start it fetches `{"rate":100, "period":10}`, then every 10 minutes sends an
  **anonymous** request `playtime-accumulator?project=mscw_gllive&period=10&rate=100` and gets
  `success`: a count of play time. Its crash reports (to `bolo7yechd...`) would carry account ID,
  hardware ID, computer name, hardware details, a screenshot and the crash dump; 15 were attempted on
  Nov 10-12 and refused by the server.
- **Session-token refresh** (port 47611, nmconew64.dll), **fully decoded**: every 60-119 s (the server
  picks the wait) the game hands in its Nexon sign-in token and gets a new one. No hardware data.
- **"Who is playing" counter** (port 8913, nexon_x64.dll): `regs:<product>:<account hash>`, then
  `ping`/`pong` about every 50 s. The account hash is the same in every session.
- **jypc.dll** (`jyp.nexon.com`, port 9994): Nexon performance telemetry: frame times, memory, CPU and
  graphics card, and stack samples during slow frames. It talks at only **about 1 game start in 10**
  (a dice roll at start); in the current run it stayed silent (read from memory). Never recorded.
- **Anti-cheat reachability check** (port 58880): a single empty web request at game start. Not in
  today's recordings.
- **Launcher web** (QUIC): one short fetch from a content network.
- **Not real traffic:** the "UDP to a Korean address" and "UDP 8913" in older logs are Windows asking
  which network card would be used (the analytics library reads its own IP and MAC that way); no
  packet is sent.

## 6. What we do not know yet

- **The anti-cheat's requests** (a cipher tied to this PC). The analytics upload is now read, but only
  for connections open when the game's memory is read; older ones cannot be decrypted later.
- **Game-start traffic**: recorded for the first time on 2026-11-15 at 23:08 (the second game, on
  display :6), not analyzed yet.
- **About 30 server message types** handled in the game's protected code, and the two server timers
  (S 0x72 every minute, always zeros; S 0x18c every 7 min, one of 10 fixed values): contents known,
  meaning not.
- What blocking each thing would do: **none of it has been tested**. Educated guesses are in
  section 7.

## 7. If you wanted to filter (guesses, untested)

| Traffic | Likely effect of blocking |
|---|---|
| Game: world, shops, maps, sign-in, channel entry | the game stops working |
| Game: integrity checks and their answers | disconnect or flag: the server expects the answers |
| Game: telemetry reports | probably nothing visible, but the server may notice missing reports it asked for (S 0x20) |
| Game: chat | probably safe |
| Analytics | probably safe |
| Anti-cheat check-in | likely a kick |
| Crash reporter play-time counter | very likely harmless; blocking the start-up settings request stops it completely |
| Crash reports | stops PC details being sent after a crash |
| Port 47611 | may end long sessions |

## 8. The code that found all this

| Script | What it does |
|---|---|
| `analysis/game-proxy.sh`, `traffic/proxy.py` | captures everything (section 2) |
| `traffic/stream.py`, `traffic/transport.py` | decrypts game connections (handshake, IVs, AES, opcode tables) |
| `traffic/protocol.py` | names and groups of every game message, with evidence |
| `analysis/message-breakdown.py` | the per-type game table (reference/message-breakdown.md) |
| `analysis/traffic-breakdown.py` | the all-traffic table (reference/traffic-breakdown.md) |
| `analysis/client-origins.py` | static map of where each client message is built in MapleStory.exe (reference/client-messages.md) |
| `analysis/capture-senders.sh`, `analysis/senders-report.py` | which program and module makes each send (monitor-filter's kfilter, audit only) |
| `analysis/tls-summary.py` | what an HTTPS connection shows without decrypting: record sizes, TLS library fingerprint, certificates |
| `analysis/wininet-cache.py` | the URLs, reply headers and replies WinINet kept in Wine's web cache |
| `analysis/pe-xrefs.py` | where a DLL uses a string, and the outline of a function (used on CrashReporter.dll) |
| `analysis/nmco-decode.py` | decodes port 47611 from the recordings (tokens masked); `--check` counts clean parses |
| `analysis/live-imports.py` | names the Windows functions the running game holds (read-only, from outside; needs root) |
| `analysis/tls-memscan.py`, `analysis/tls-keys.py`, `analysis/tls-keys-watch.sh`, `traffic/tls12.py` | decrypt the analytics upload (section 5): read the TLS keys from the running game's memory (**read-only**, needs sudo; it runs outside Wine, so **the game cannot see it**), keep only keys proven on a recorded record (standard key-log file), then print the requests and record types with values masked. Works **only for connections open at the time of the read**. The keys and the decrypted data stay private (mode 600, never in git); steps in docs/guides/PROTOCOL.md, "Decrypting the analytics upload" |
| `analysis/decode-heartbeats.py`, `analysis/ngs-mitm.py` | anti-cheat heartbeat decoding through a man-in-the-middle proxy (older work) |

To rebuild the generated tables:

```bash
.venv/bin/python analysis/traffic-breakdown.py captures/proxy-*.jsonl --pcap captures/proxy-<stamp>-other.pcap > docs/reference/traffic-breakdown.md
.venv/bin/python analysis/message-breakdown.py captures/proxy-*.jsonl > docs/reference/message-breakdown.md
```

The recordings themselves stay in `captures/` (not in git: they hold account data).
