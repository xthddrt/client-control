# Client-server protocol: what the game family sends and receives

Status 2026-11-15, client build 0x6AEB667B (MapleStory.exe "maplestorycw").
Everything here was read from the client's code or checked on recordings made
with `analysis/game-proxy.sh` while MapleMarket scraped; open points are listed
as open. Names and their evidence live in `traffic/protocol.py`.

## 1. Every connection the game family makes

From monitor-filter's audit log (every network decision of every Wine program)
and the proxy's recordings:

| Program | Peer | What it is | Captured as |
|---|---|---|---|
| MapleStory.exe | TCP 8484 | login server | proxy, decoded both ways |
| MapleStory.exe | TCP 85xx | channel servers | proxy, decoded both ways |
| MapleStory.exe, launcher | TCP 8913 | concurrent-user counter (nexon_x64.dll `NXCCUReporter`): plain text `regs:<product id>:<hashedUserNo>`, then `ping`/`pong`; see below | proxy, raw (text) |
| MapleStory.exe | "UDP 8913" in the audit | **no packets**: pairs of address lookups (glibc's getaddrinfo sorting probe, a UDP connect with no data) while resolving the ping host | - |
| MapleStory.exe | TCP 443 `x-csauth.ngs.nexon.com` | NGS anti-cheat check-in (TLS 1.3); see below | proxy, TLS (server name only) |
| MapleStory.exe | TCP 443 `public.api.nexon.com` | NexonAnalytics64.dll uploads (TLS 1.2); see below | proxy; decrypted with keys read from the game's memory (below) |
| MapleStory.exe, launcher, overlay | TCP 443 | other HTTPS | proxy, TLS (server name only) |
| launcher | UDP 443 | one short QUIC (HTTP/3) session to a CloudFront edge, ~4 KB up / 8.5 KB down: a web fetch | other-packets pcap, encrypted |
| MapleStory.exe | TCP 47611 | nmconew64.dll session-token refresh, **fully decoded**; see below | proxy, raw |
| grap-core64.aes, then MapleStory.exe | TCP 58880 (54.238.121.146) | anti-cheat reachability check at game start: a 77-byte `GET / HTTP/1.1` with no data (2026-11-13 audit; not in the 2026-11-15 recordings, which started after the game) | proxy, raw |
| jypc.dll | TCP 9994 `jyp.nexon.com` | performance telemetry, at about 1 in 10 game starts; see below (never seen on the wire) | proxy, raw |
| MapleStory.exe | "UDP to 222.122.222.69 and broadcast" in the audit | **no packets**: NexonAnalytics64.dll (0x158640) calls `GetBestInterface(inet_addr("222.122.222.69"))` to find the adapter (local IP and MAC) that routes toward Korea; Wine answers with a UDP connect that sends nothing. The broadcast entries are likely the same lookup on an unresolvable name | - |
| all | DNS | through the PC's own resolver (127.0.0.53): local, not captured as game traffic | - |
| all | 127.0.0.1 TCP | the game's programs talking to each other (nexon_runtime) | not captured: local |

`analysis/game-proxy.sh` takes all of it: every IPv4 TCP connection of the
game's Wine programs goes through the proxy, every other packet (UDP, ICMP, all
IPv6) of those programs is written to `captures/proxy-<stamp>-other.pcap`.

IPv6 TCP is copied to the pcap but not proxied, so a policy cannot refuse it
(none was seen; the audit's IPv6 traffic was the launcher's DNS).

Not decrypted yet: TLS and QUIC (see "HTTPS services" below for what is known
without decrypting and the ways to decrypt). Port 47611 is decoded
(`analysis/nmco-decode.py`). Not recorded yet: a game start with every port
captured (jypc.dll and port 58880 talk only then).

### Which part of the game sends each connection

`analysis/capture-senders.sh` (monitor-filter's kfilter in audit mode: nothing is
denied; the running game is tracked, no restart) logs every send with the first
non-Wine Windows module on the sending thread's stack; `analysis/senders-report.py`
turns the log into this table. 10 minutes of scraping, 2026-11-15 16:16:

| Server | Sent by | Sends / bytes |
|---|---|---|
| game channel servers | MapleStory.exe: its protected `.themida` section (the usual send path) and its `.text` | 1,042 / 37 KB |
| `public.api.nexon.com` :443 | **NexonAnalytics64.dll** (Nexon's analytics library) | 67 / 330 KB |
| `x-csauth.ngs.nexon.com` :443 | **grap-communicator64.aes** (the anti-cheat's communicator) | 50 / 108 KB |
| two Amazon addresses :47611 | **nmconew64.dll** (Nexon messenger core, NMCO) | 6 / 4.9 KB |
| 35.165.11.5 :8913 (ping service) | nexon_x64.dll in the game; the launcher too | 26 / 130 B |
| `68bd384lrg.execute-api.ap-northeast-1.amazonaws.com` :443 | **CrashReporter.dll** (Nexon's crash reporter, loaded by the game): its playtime counter, sent through WinINet (no module on the stack at the send); see below | 3 / 583 B |
| the launcher's HTTPS (CloudFront) | no module: the launcher runs as a 32-bit program, whose sends kfilter cannot attribute | 9 / 702 B |

An older monitor-filter recording (2026-11-15 00:56) agrees for the anti-cheat:
its connect to x-csauth's address had grap-communicator64.aes on the stack.
`x-config.ngs.nexon.com` was not used in this window.

### Amazon API (execute-api, Tokyo): the crash reporter's playtime counter

Read from the recordings (2026-11-15 13:40-21:30), Wine's WinINet cache
(`users/<user>/AppData/Local/Microsoft/Windows/INetCache/Content.IE5/index.dat`,
which keeps each URL and its reply headers) and CrashReporter.dll (Nexon Korea
"LiveAssist" crash reporter 2.0.1.36, `NEXON Infratech CR`; RVAs below are in it):

- **Who.** MapleStory.exe loads `appdata/CrashReporter.dll` and names its project
  `mscw_gllive` (the string is in MapleStory.exe). The overlay and grap-core64.aes
  load their own copies (`NxOverlay/`, `grap/CrashReporter_64.dll`); only one
  playtime stream is seen, the game's. HTTP goes through WinINet, i.e. Wine's
  TLS (TLS 1.2, no ALPN, CCM suites and FFDHE groups in the ClientHello), which is
  why kfilter finds no module on the stack.
- **At game start** (0x192e0): `GET /prod/collection-settings?project=mscw_gllive`
  -> `{"rate":100, "period":10}`. The client rolls `rand() % 100`; if it is below
  `rate`, the recorder is on with `period` minutes (x 60,000 ms). Otherwise, and
  when the request or its JSON fails, no timer is made and nothing more is sent.
- **Then** (0x18d60): `CreateTimerQueueTimer` with the first call after half a
  period and then every period; the callback (0x18a50 -> 0x18ef0) sends
  `GET /prod/playtime-accumulator?project=mscw_gllive&period=10&rate=100`, user
  agent `NexonCrashReporter`. Reply: `success` (7 bytes).
- **On the wire:** one connection every 600.0 s (47/47, always at :x1:29; first
  13:41:29 = 5 min after the settings request at 13:36:29), always 583 bytes up
  and 4,895 down (mostly the TLS handshake and Amazon's certificate chain); one
  223-byte request record (199 bytes of HTTP: the URL, Host and a header or two,
  no room for an account or device id) and one 391-byte reply record; the server
  closes the idle connection after 60 s.
- **Meaning:** an anonymous count of play time (each request = one period of the
  game running), switched and sampled by the server (`rate`, `period`). The server
  still sees the PC's IP address.
- **The same DLL also has** `/prod/startup-info-recorder` and
  `/prod/crexception-prop` on `bolo7yechd.execute-api...` (not seen), and crash
  report fields: ACCOUNT_ID, CR_USERID, CR_HWID, CR_HWCONFIG, COMPUTER_NAME, CPU,
  GPU, OS, memory, module hashes, a screenshot of the game window, the dump and
  log files. Crash uploads are made by CrashReportClient.exe:
  `/prod/crweb-config` (`{"action": "None", "propCheck": true, "url": null,
  "message": null, "ratio": 100}`) then `/prod/crlog-collector`; the cache holds
  32 and 15 of those from 2026-11-10 to 11-12, the last answered
  `{"message":"Missing Authentication Token"}` (API Gateway's refusal).

### Port 47611: Nexon's session-token refresh (nmconew64.dll) — decoded

Read from nmconew64.dll (Nexon messenger core "NMCO", which kept its C++ class
names) and checked on every recorded message: `analysis/nmco-decode.py --check`
parses 708 of 708 (2026-11-15 recordings) with no byte left over. RVAs are in
nmconew64.dll.

- **Frame** (reader 0x17ded0, stream 0x17c660 -> 0x17c770): u16 BE length of the
  rest, u16 BE **packet type**; then the stream: u8 0x18, u24 BE length; then the
  block: u8 flags (bit 0 zlib, bit 1 encrypted, bit 2 CRC; `0x02` here), u24 BE
  body size, u32 BE **key** (the value that changes in every message), u32 BE
  **field check** (fixed per direction: each field read updates it, e.g. a u32
  does `x = x<<8 ^ 0xcdff8135`; 0x17ac70 compares; it matches 690/690), body.
- **Cipher** (0x187a10 / 0x187a70): per little-endian word i,
  `p[i] = T[i % 16] ^ c[i] ^ p[i-1] ^ key`, T = 16 fixed words at .data 0x2afac0.
  (The earlier "layer 1 / 64-byte keystream" reading was this, seen from outside.)
- **Request, type 0x18 `CUUpdateSession2Packet`** (read 0xde450): u32 version 2,
  u8 flag 0, u32 0x0200A0D0 (MapleStory's NMCO game code, likely; the game passes
  it at 0x1decc80), text (empty), text = an **NP12 passport token**
  (`NP12:us:0:<account number>:...`, 394 characters). All 345 the same shape.
- **Reply, type 0x16 `CUUpdateSessionReplyPacket`** (read 0xde720; the old note
  said 0x18): u32 result 0, text (empty), text = a **new NP12 token**, u32 0,
  u32 0, u32 **seconds until the next refresh** (60-119, mean 90).
- **Trigger (confirmed):** a refresh thread (0xf2b80 -> 0xf2ba0) waits that many
  seconds, then (0xf2c60 -> 0xe25e0 -> 0xe2220) opens a new connection (5 s
  timeout, 3 tries), sends the current token, stores the new one and the next
  delay. Each request carries the previous reply's token (343/344; the one break
  is a new sign-in); every token is used once; the server answers in 41 ms.
- **Meaning:** a rolling session-token refresh, about every 90 s, timed by the
  server. No hardware data in what was recorded. A version-1 path (type 0x17,
  0xe1d70, not seen) would add a 24-byte machine blob built from the MAC of the
  adapter toward the server.
- **All packet classes** (factory 0xd6c70); only 0x18 and 0x16 were seen:

| Type | Class |
|---|---|
| 0x0b, 0x0f, 0x10, 0x14, 0x33 / 0x0c, 0x11, 0x34 | CUSignInPacket / CUSignInReplyPacket |
| 0x0d, 0x35 / 0x0e, 0x36 | CUSignOutPacket / CUSignOutReplyPacket |
| 0x12 / 0x13 | CUSecurityLoginCNRequest / Reply (China) |
| 0x15, 0x17, 0x18 / 0x16 | CUUpdateSession2Packet (v1 / v1 with flag / v2) / CUUpdateSessionReplyPacket |
| 0x2d / 0x2e | CURequestOldFashionInfo / Reply (meaning unknown) |
| 0x31 / 0x32 | CUGameTokenRequest2 / Reply2 |
| 0x37 / 0x38 | CUGetPasswordHashKey / Reply |
| 0x39 / 0x3a | CUPCBangLogin / Reply (internet-cafe login) |
| 0x3f / 0x40, 0x41 / 0x42 | CUTPATokenLogin, CUPlugTokenLogin / Replies |

The tokens are live credentials with the account number inside:
`nmco-decode.py` masks them.

### Port 8913: the concurrent-user counter (nexon_x64.dll)

nexon_x64.dll (the launcher's DLL, also loaded by the game; class
`NXCCUReporter`) builds `regs:%s:%s\n` at 0x4270, then sends `ping\n` / gets
`pong\n` about every 50 s (confirmed):

- the first value is the product id the caller passes in: **59813** from
  MapleStory.exe (the launcher's `installed-apps.db` maps it to maplestorycw),
  **10000** from the launcher (likely its own id);
- the second is `hashedUserNo`, a 44-character base64 value (32 bytes, probably a
  SHA-256 of the user number), which the DLL asks the launcher for over local RPC
  (`ncalrpc`, JSON call `_get_configuration`, 0x5950; the same call returns the
  counter's server name and port). It is the same for the launcher and the game
  in every session: **a stable per-account identifier**, not quoted here.

### HTTPS services (what is known without decrypting)

Each of these programs **bundles its own OpenSSL** and opens its own socket, so
Wine's TLS stack is not involved. The anti-cheat's `.aes` files
(`grap-communicator64.aes`, `grap-core64.aes`, `grap-updater.aes`) are ordinary
PE DLLs; the extension is cosmetic.

- **Analytics, `public.api.nexon.com`** (NexonAnalytics64.dll, Nexon "DataSDK"
  3130; OpenSSL 3.0.17, boost.asio, cJSON, librdkafka for an optional Kafka path
  not seen in use). TLS 1.2, no ALPN, two connections open in parallel, each about
  an hour and 0.4-1.3 MB up: **the biggest upload of the PC** (1.7 MB/h).
  - **Decrypted (2026-11-15, 48.5 minutes, 282 requests, 1.48 MB)** with TLS keys read
    from the running game's memory (read-only; OpenSSL wipes a session's keys soon after
    it closes, so only connections open at the time of the read can be decrypted). The
    tools are in this repo (see "Decrypting the analytics upload" below); the keys and the
    decrypted data stay local. Each upload is an HTTPS `POST
    /stream-processor-proxy/ap-northeast-1/client.all.secure`, `application/x-ndjson`
    (one JSON record per line, uncompressed), user agent `NexonAnalytics SDK`, two
    constant key headers built into the DLL (not quoted); every reply is `200` with an
    empty body. The two parallel connections carry one stream (one sequence number).
  - **Fields on every record:** time, sequence numbers, SDK version, the **public IP
    and country** (from `GET /toy/v2/country` at start), two machine ids (`mid` 64 hex,
    `mid2` 32 hex), an install id, **nexonsn, accountno, sessionid**.
  - **What is sent** (share of bytes):

    | Record | Built by | When | Content |
    |---|---|---|---|
    | `ETC_MSMouseEvent` (39%) | MapleStory.exe (window-message recorder 0x2ee3440 -> 0x2ef2f90) | every 1,000 mouse messages (~90 s), and at a map change | **every mouse message of the game window**: `age_ms,x,y,msg` with window coordinates; 71% are moves (512), then left down/up, double-click, wheel; plus the character (id, name, level, class, guild, world), the map id and the character's position, window size, a place type (8 = town / Free Market, as in C 0xbe), two 64-bit hashes |
    | `NXLog_InputEventSequence` (26%) | the DLL's own input logger (`inputloglevel` 1) | every 10 s | every **click, double-click and wheel turn** with ms time and window x,y; no keys and no moves at this level; the screen resolution |
    | `ETC_BU_CData` (19%) | MapleStory.exe (0x1cd7c80; the dump builders jump into protected code) | every ~600 s, three records | **raw memory dumps of three game objects**: each is a pointer address (RVAs 0x3bda7b0, 0x3bda828, 0x3bf38c8) plus the object's bytes (17,168, 22,528 and 456 B). The first is the main client object: account number, character id, a Wine-detection flag at +0x42e0 and a **Windows process-list snapshot** (process ids, parents, threads, start times, memory; under Wine only Wine programs: the launcher, nexon_runtime, conhost). The second is your character object (id and name in plain text). The third is a small object whose constructor checks for `winemac.drv`. All three contain Wine's Linux-side addresses |
    | `ETC_MSInputEvent` (14%) | MapleStory.exe (0x572410) | every 300 s | **every key press and release** of the last 300 s: `time,vk,down/up,state,count,x,y` with the character's map position |
    | `NXLog_SdkSummary` (1%) | the DLL | every 300 s | counts of records asked for and sent, by type |
    | `stability` | the game | at start and exit | loading stages with times: InitGameLogManager, InitializePCOM, ConnectLogin, InitNGS, InitResMan, InitGr2D, LoadGameData, InitClientComplete, LoginGameServer, SelectWorld, SelectCharacter; GameEnd, CleanUpClientComplete, UnInitializePCOM, DestroySecurityClient |
    | `initialize`, `NXLog_SystemInfo`, `NXLog_GRCInfo`, `NXLog_DevLog` | the DLL | once at start | SDK settings (exe path, library versions, server URLs); system info that under Wine holds only the sound device (the WMI hardware queries likely fail); a settings status |
    | `Custom_GameEndUIInfo`, `UIActionEvent` | the game | at quit | character, level, experience at login and at quit, play time; the click |

    Not seen in 48.5 minutes: heartbeat, funnel, key-binding records. No window
    titles, clipboard or screen content; the only data about other programs is the
    process list inside the first memory dump.
  - The game sends its `ETC_*` records through one function (0x51f200, 253 call
    sites, a per-type on/off setting), which calls the DLL's `enqueueNxLog`
    (slot 0x3bf37c0, by slot order). About 120 `ETC_*` type names exist in the
    game (table 0x5166a0); the ones above are those seen.
  - Compared with the game's own packets: C 0x286 (a key log), C 0x1f3 (an MD5 of
    300 key releases) and C 0xbe (an hourly count of active minutes) are small
    summaries of what this upload sends raw.
  - Hardware inventory through WMI is in the code (Win32_Processor,
    Win32_VideoController, disks, network adapters, keyboard, pointing device,
    battery); under Wine the start-up `NXLog_SystemInfo` carried none of it.
  - The game's own direct calls are stage and error logs (`enqueueStageLog`
    "GC:InitClientComplete", "GC:GameEnd"...; `enqueueErrorLog`
    "GC:ThreatDetected", "GC:NGSXRunFailed"...).
- **Anti-cheat check-in, `x-csauth.ngs.nexon.com`** (grap-communicator64.aes,
  Poco C++ 1.12.4 over OpenSSL). TLS 1.3, ALPN http/1.1, one new connection per
  check-in every ~62 s: ~10.1 KB request, 174 + 444 B reply. The request body uses
  a device-bound cipher inside the protected grap modules (not broken); earlier
  work in this repo attributes its periodic +500-830 B bumps to screenshot chunks
  of the anti-cheat's screen-capture feature (mechanism shown, image contents not
  read). The reply is readable offline (`foundations/ngs_cipher.py`,
  `analysis/decode-heartbeats.py`): token, auth cycle (~64 s), emergency stop,
  detection list, config-changed flag, terminate message.
- **Anti-cheat settings, `x-config.ngs.nexon.com`**: TLS 1.3, ~700 B request,
  ~47 KB reply in the same readable format: the feature map and the pushed
  detection signatures. Fetched at session start or when a check-in sets
  `config_changed`.

**Ways to decrypt the analytics upload:**

| Way | Reaches analytics? | Needs | Note |
|---|---|---|---|
| `SSLKEYLOGFILE` (Wine's GnuTLS 3.8.3 honours it) | **no** | game restart | only covers WinINet/schannel users (the crash reporter) and the game's own libcurl, not the three services above |
| man-in-the-middle with a trusted certificate | yes, with transparent redirection | a CA in the prefix's Windows root store, iptables redirect, game restart | not tried; proven earlier for the NGS hosts (they honour HTTP_PROXY); analytics ignores HTTP_PROXY; no certificate pins found |
| **read OpenSSL's session secrets from the live process** (used) | yes, for connections open at the read | sudo; read-only memory reads | no restart, no certificate; see below |

**Decrypting the analytics upload** (`analysis/tls-keys.py`, `analysis/tls-memscan.py`,
`traffic/tls12.py`):

1. `analysis/tls-keys.py needles <recording>` lists the client/server randoms and session ids
   of the open analytics connections in a proxy recording.
2. `sudo .venv/bin/python -I analysis/tls-memscan.py <game pid> <scan> @<needles>` finds them in
   the game's memory and saves the memory around them (and one pointer away). **Read-only**: it
   only opens `/proc/<pid>/maps` and `/proc/<pid>/mem` for reading; no attach, no writes, no
   signals. It runs outside Wine, so **the game cannot see it**. It needs sudo for
   `/proc/<pid>/mem`.
3. `analysis/tls-keys.py find <recording> <scan> --keylog <file>` tries every 48-byte window
   of the scan as the TLS 1.2 master secret and keeps one only if it decrypts the connection's
   recorded Finished record (the AES-GCM tag proves it). The result is a standard
   `SSLKEYLOGFILE` (`CLIENT_RANDOM <client random> <master secret>`; Wireshark reads it too).
4. `analysis/tls-keys.py decrypt <recording> --keylog <file>` decrypts every record and prints
   the HTTP requests, replies and NDJSON record types with **values masked**; `--plaintext FILE`
   writes everything in clear.
   `--fields` adds a masked summary of every record type (the csv lists by field, the
   `ETC_BU_CData` dumps with the process list in the first, the stability stages, the SdkSummary
   counts); `--until "YYYY-MM-DD HH:MM:SS"` cuts the recording (the table above is
   `--until "2026-11-15 23:13:20"` on the 20:49 recording). Field names of the csv lists:
   `NXLog_InputEventSequence` mouseEvents `time,x,y,event,device` (event LD/LU/WH or empty);
   `ETC_MSMouseEvent` mousedatas `age_ms,x,y,msg,extra1,extra2` (msg = the window message; extra
   `HND|1` and `FID|<map id>` on the entry of a map change); `ETC_MSInputEvent` keydatas
   `time,vk,msg,state,count,x,y` (msg 256/257 key down/up). `ETC_BU_CData` `bu_d` is
   base64(u64 object address) | base64(object bytes).
5. Without keys, `analysis/tls-keys.py sizes <recording>` lists each connection's requests by
   size, which tells the record types apart (one type per request; the three dumps go together
   as one 50-60 KB request).

Only **connections open at the time of the memory read** can be decrypted: OpenSSL wipes a
connection's secrets soon after it closes, and each connection (about an hour) has its own.
`analysis/tls-keys-watch.sh <recording> <pid> <keylog>` repeats steps 1-3 a minute after each
new analytics connection (it needs `sudo -n` to work without a password). The scans, keylogs and
plaintext hold account data and keys: the tools write them mode 600 and refuse to write them in
this repo except the git-ignored `captures/`; keep them private.

### jypc.dll: "jyp" performance telemetry (never seen on the wire)

Nexon jypc.dll 1.1.0.5 (appdata/), loaded at game start by MapleStory.exe
(0x2d4c8c0, project name "maple_kr"); the game resolves 16 of its 18 exports
(hashed names) at run time (.data 0x3bfda00-0x3bfda78). Confirmed in its code and
in live memory:

- **What it records:** labels (InitPhase, LoginStage, Level, JobCode, SkillID
  every 10 s, Vsync, game/draw frame times, likely a map label), per-frame
  timings, PDH counters (pages/s, disk bytes/s), process memory, whether the
  window is in front; hardware and OS (message 0x166: OS version, CPU name, RAM,
  GPU vendor/device ids, video memory); and, during slow frames, stack samples of
  registered threads (SuspendThread + GetThreadContext) with the module list.
- **Where:** TCP `jyp.nexon.com:9994`. The server speaks first (id 0x95, 20 bytes,
  or id 0x15a); the client answers hello 0x113 (three random values and
  0x8d2cf844); after that every byte is XOR-ed with a 116-byte MT19937 key seeded
  from the hello: scrambling, not encryption. Frames are u32 LE total length, u32 LE
  id, body; the hello's u32 at byte 16 seeds a std::mt19937, whose first 29 outputs
  key the client's bytes after the hello, the next 29 the server's bytes after its
  0x11b frame. `analysis/jyp-decode.py <recording>` descrambles and splits a recorded
  connection (tested on synthetic data only).
- **When:** it rolls 1-10 at game start and connects only on 1 (**about 1 in 10
  game starts**), or always when the name resolves to 127.0.0.1, 52.192.168.126
  or a non-IPv4 address; otherwise it sets a stop flag and stays silent until the
  game ends. In the current game run the flag is 1 (live read): nothing sent, five
  messages queued.
- **Why no recording shows it:** no recording has covered a game start with every
  port captured (the 13:01 recording did include a start, but its proxy only took
  ports 8400-8999). Measuring the 1-in-10 needs recorded game starts with all TCP
  and DNS.

### Hosts compiled into the game's DLLs but never seen in the recordings

The complete generated per-binary inventory is in [compiled-hosts.md](../reference/compiled-hosts.md).
Its values are string-shape candidates, not proof that a connection is made.

| Where | Host | Purpose |
|---|---|---|
| MapleStory.exe | 54.180.211.235:24200, 43.200.157.16:24200 (AWS Seoul), next to private 192.168.128.75-84:5160 test servers | unknown |
| MapleStory.exe | `private.api.nexon.com/inference/textclassifier` | likely chat moderation |
| MapleStory.exe | `login-mscw.maplestory.nexon.net` | likely a login fallback |
| CrashReporter.dll | `cr*.nexon.co.kr`, `bolo7yechd...` | after crashes only |
| NexonAnalytics64.dll | `config.na.nexon.com`, 3.14.1.70 | settings |
| nps64.dll | `external-api.cem.nexon.com` | unknown |
| WzMss.dll | `api.maplestory.nexon.com` (SOAP boards) | on a user action |
| messenger DLLs | many platform / SSO / live-log hosts | unknown |
| grap (anti-cheat) | 54.238.121.146:58880 | reachability check at game start |

## 2. The game transport

Read from the client's code (addresses are RVAs in MapleStory.exe):

- **Handshake.** The server speaks first, unencrypted: u16 length, then 19
  bytes (channel servers) or 52 bytes (login server). It contains the client's
  and the server's 4-byte starting IVs (channel: at body offsets 9 and 13).
- **Frames.** 4-byte header `w0 w1`: `w0 = high16(iv) ^ 0x00DF` (client) or
  `^ 0xFFFE` (server), body length = `w0 ^ w1`. After each frame the IV rolls
  (`foundations/transport-cipher.py`).
- **Body cipher** (0x75d970): the body is processed in blocks of 1456 bytes,
  then 1460; each block starts again from the frame's IV.
  - mode 1, AES-256-OFB from the IV repeated four times (0x140cea430): every
    client message, and the login server's replies;
  - mode 2, subtract `iv[0]` from every byte (0x140763a70): channel server
    replies. (The earlier "XOR with iv[0]" model got only some bytes right.)
- **Opcode table.** On a channel connection the server's third message, 0x32,
  is `u32 size` + DES-EDE2-ECB text (key at .rdata 0x34d3ee8, used at
  0x166d411): `"876|v1|v2|..."`. Client opcode `0xC7 + i` goes on the wire as
  `v(i+1)`; opcodes below 0xC7 go out unchanged; table values are 5000 or
  more, so the two never collide. A new table comes with every channel
  connection. Server opcodes are never renamed.

Checked on six full connections (login and channel, 2026-11-14 and -15): every
frame of both directions decrypts; 53 of 53 in-process SendPacket bodies equal
the decrypted frames; 28 of 28 known opcodes sit at their table position.

## 3. What the messages mean

`traffic/protocol.py` lists every named message with its evidence. In short:

**Login** (in order): C 0x70 context (machine UUID) - S 0x2b/0x2c program and
data file lists - C 0x73 passport login (the launcher's NP12 token) - C 0x76
environment (CPU model, Windows version) - C 0x77 file check report - S 0x0
login result (account id, masked e-mail) - S 0xb world list - C 0x78 hardware
identity (a MAC address, a hardware id) - S 0xf character list - C 0x79 select
character. Keep-alive: S 0x1a / C 0x9b.

**Channel**: C 0x70 then C 0x7d channel enter (account id, character id,
hardware id) - S 0x32 opcode table - S 0x1a9 set field - S 0x194 session log
id and C 0x41f-0x422 join logs - C 0xb9 / S 0x3c device stamp (date, Nexon
account number, device fingerprint).

**In a Free Market room**: S 0x22d a player in the room (name, pets, looks;
the character id at offset 6), S 0x452 within 0.3 s after each, S 0x22e a
player left, S 0x281 a pet, S 0x23d a shop (title, object id), S 0x29d a
player moving, S 0x282 a pet moving (both: the character id at offset 2, then
a movement path laid out like the client's own C 0xdb), S 0x22f room chat
(id, name, text), C 0xd3 portal (name such as `in17`) answered by S 0x1a9,
C 0x14e floor portals (`up00` -> `up01`).

**Map load**: after every S 0x1a9, eleven server messages in a fixed order
(`field_init_1` .. `_11`, S 0x1fa .. 0x216) and four client messages
(`field_entered_1` .. `_4`, C 0xde, 0x2da, 0x186, 0x196): 179 of 179 loads.

**Changing channel**: C 0xd4, byte 2 = channel - 1 (10/10 against the
scraper's log); refused: S 0x1b8 (7/7); accepted: S 0x19, three IPv4 + port
addresses of the new channel server, and the next connection goes to one of
them (7/7). After character selection the login server does the same with
S 0x10.

**Shops**: C 0x181 action 2 + object id enters a shop; S 0x57a gives owner and
title, S 0x57b the item list (u16 count at offset 6; item prices inside, the
first matched the scraper's reading); C 0x181 action 3 leaves, S 0x579 and a
short S 0x57a confirm.

**Broadcasts**: S 0xae, type byte 2, 3 or 8 = megaphone `Name : text` (also
from other channels); type 4, empty, comes with every map load.

**The steady cycles** (from 2,347 cycles of each, 7.5 hours):

- **Every ~10 s, a debug-register check.** The server sends S 0x1b; 11 ms later
  (median, 2347/2347) the client answers C 0x9c. The builder of C 0x9c
  (0x1668850) five times sets ContextFlags = 0x100010
  (`CONTEXT_DEBUG_REGISTERS`) in a `CONTEXT`, zeroes Dr0-Dr3, Dr6 and Dr7, calls
  a function looked up at run time with it (the form of `GetThreadContext`), and
  writes the registers XOR-ed with CRC-32 table entries; it also writes 32 values
  mixed with 0x9e3779b9 (the TEA constant), between the marker 123456789. So the
  server sees the CPU's hardware-breakpoint registers every 10 s: **the
  in-process observer `analysis/outgoing-packet-capture.py`, which sets hardware
  breakpoints, is visible to it.**
- **Every ~10 s, a ping**: S 0x62e (empty) -> C 0x42a (empty), 2144/2144.
- **Every 60.4 s, a client-state poll**: the server sends S 0x4f n = 0..4; 13.6
  ms later each is answered by C 0xc5 (n, flag) (2219/2260). The flag is 1 when
  two system calls resolved at run time return the game's own value (the form of
  an "is the game window active" test); it was always 1 (the scraper keeps the
  window active).
- **Every 60.4 s**, S 0x72 (7 zero bytes) from the same server schedule (0, 5
  or 10 s from the poll's start); no answer; purpose unknown.
- **Every 6 minutes**, C 0x407 (built in the protected code) -> S 0x381
  (84/84).
- **Every 7 minutes** (422.5 s), S 0x18c with 4 random-looking bytes that no
  client message repeats; purpose unknown.
- Not a cycle: S 0xc1 carries the UTC hour (52/52) and the day of the week,
  mostly at channel entry.

**More, from 7.5 hours of recordings** (290,670 messages, 48 connections,
1,626 map loads, 3 sign-ins):

- **NPCs**: S 0x452 brings an NPC into the map (its template at offset 6 is a
  String.wz NPC: 800007 Free Market Maple TV, 800008 Fredrick, 800009 Scrooge,
  800018 Lewis), S 0x456 is its action (every ~2.6 s). S 0x454 gives an NPC's
  control to a client (byte 1 = yours); the controlling client sends each action
  as C 0x326 and the server repeats it to the room as S 0x456 (19/19, ~35 ms
  later; proxy-20261115-204932, while the scraper stood still at 21:06).
- **Items and effects around you**, by item ids from String.wz: S 0x471 an item
  dropped on the floor (135/136), S 0x2b8 a player's equipment changed, S 0x2b7
  a player sits on a chair, S 0x2a9 a ranged attack with its projectile, S
  0x23f an upgrade scroll used, S 0x1c0 a message board ("Snowy Message").
- **Room chat** is S 0x22f (id, name, text: 996/1029); S 0xae is megaphones.
- **Character data at channel entry**: 29 server messages come exactly once per
  channel connection (45/45), in a fixed order, within 0.3 s of connecting
  (S 0x166 the server's time, S 0x19f the sign-in time, S 0x8b key=value
  records such as `LastDate=..;count10min=..` and quest resets, S 0xc6
  `kill_count`, S 0x16b the character's name); 15 more only on the first channel
  after a sign-in (3/3). The client answers with C 0x228, 0x161, 0x177.
- **The server asks for reports**: S 0x20 byte 05 -> C 0x70 subtype 5
  (154/154), 0c -> subtype 13 (46/46). C 0x70 subtype 1 follows shop actions
  and map loads at once.
- **More file checks at sign-in**: C 0xa3 and 0xa4 are nibble-swapped text: the
  180 data file names, and the same files with their full local path.
- **Usage telemetry**: C 0x424 lists resource paths the client loaded
  (`Sound/UI.img/BtMouseOver`, `Map/Map/Map0/080002007.img`).

Coverage now: **96% of client messages (37 of 68 types) and 90% of server
messages (57 of 134 types) are named**, and every type seen has a purpose group
(`traffic/protocol.py` PURPOSE; decoded messages carry it as `purpose`):

| Purpose | Share of messages | What |
|---|---|---|
| world | 40.5% | players, pets, NPCs, items and effects in your room |
| shops | 36.3% | shop signs, entering, contents, leaving |
| maps | 13.7% | moving between maps and loading one |
| integrity | 3.3% | file checks, the 10 s debug-register check, the 60 s client-state poll, the 6 min protected check |
| chat | 2.3% | room chat, megaphones, message boards |
| login_session | 1.6% | sign-in, world/character choice, channel change, the 10 s ping |
| channel_entry | 0.8% | character data when a channel connection starts |
| identity | 0.7% | reports about this PC and device |
| telemetry | 0.6% | logs, metrics, usage reports, report requests |
| periodic_unknown | 0.2% | two server timers: S 0x72 (60 s, zeros) and S 0x18c (7 min) |
| unknown | 0.03% | 15 rare types (101 messages) |

These figures are from the first count; the current counts per type are in
[`docs/reference/message-breakdown.md`](../reference/message-breakdown.md). Round 2
(2026-11-15 evening) named most of the frequent unnamed ones: S 0x7e / 0x80 (your
own stats and buffs), S 0x279 (a player finished loading the map), S 0x2bb /
0x2ba / 0x2bd (another player's buffs and guild), C 0x155 (after your buffs
change), C 0xba (5-second input-idle flag), C 0x161 / 0x177 (answers to S 0x340 /
0x165), and the whole sign-in: see
[`docs/reference/server-messages.md`](../reference/server-messages.md),
[`docs/reference/sign-in.md`](../reference/sign-in.md) and
[`docs/reference/client-message-origins.md`](../reference/client-message-origins.md).

**What exists but was never seen.** The client builds messages at 2,064 places
in its code with 679 distinct opcodes (0x70 .. 0x432); these recordings saw 58,
so a scraper session shows about 9% of what the client can send. C 0x76, 0x78
and 0x407 have no plain constructor call: they are built in the protected
(virtualised) code. C 0xba, 0xa3 and 0xa4 are built in plain code through a
computed opcode (0xd101d0, 0xd144f0). C 0x191 was never actually sent (the
earlier sighting was the opcode-table parser bug).

### What the client tells the servers about this PC and account

C 0x70 subtype 13 a UUID-style device id (source unknown), the other subtypes the
CPU debug registers; C 0x71 a server-issued marker kept in the registry; C 0x73 /
0x76 the launcher passport, CPU model, Windows version, RAM, CPU count, time zone,
country and language; C 0x161 the screen resolution; C 0x78 a MAC address and a hardware id; C 0x7d the same
hardware id on every channel; C 0xb9 the Nexon account number and a device
fingerprint; C 0x77 a check value for every program and data file; C 0x8f the
client's event log. Recordings therefore hold login tokens and hardware
identifiers: they are written mode 0600 and `captures/` is ignored by git.

## 4. Where each client message comes from

`analysis/client-origins.py` reads MapleStory.exe on disk (the game is not
touched) and writes [`docs/reference/client-messages.md`](../reference/client-messages.md):
for every client opcode, the functions that build it, the fields they write in
code order (Encode1/2/4/8, text, byte runs, and helpers that write fields
themselves), whether the builder sends it, the nearest event handler (a method
called through a class's method table), and the part of the client it sits in.

- 678 opcodes are built at 2,060 places (37 more take a computed opcode); 546
  trace up to an event handler within six steps.
- The file kept almost no class names (123), and none of these handlers'
  classes, so parts of the client are found by place in the code (a compiler
  keeps one source file together): 140 parts; the ones that build a named
  message are, for example, the connection code beside SendPacket (0x70, 0x7d,
  0x8f, the login keep-alive, the 10-second cycle), the login screen (0x73),
  the shop code (0x181), portals and channel change (0xd3, 0xd4), the map-load
  code (0x186, 0x196), the join logs (0x41f, 0x420, 0x422), and one part that builds
  101 opcodes including the periodic reports 0x13f, 0x1a7 and 0x1ef.
- Checked against the recordings: 22 recorded opcodes match a fixed static
  layout exactly (e.g. 0xd4 = 21 bytes, 0x181 = 6 and 10 bytes), 18 have a
  variable-length part, 11 differ because the tool lists fields in code order
  and does not follow loops or branches (0xdb's movement path is a loop).
- Seen but built in protected (virtualised) code, so not traced: C 0x76, 0x78
  (the PC reports) and 0x407. Server messages: see
  [`docs/reference/server-messages.md`](../reference/server-messages.md) for how
  the client dispatches them and which handlers are reachable.
- Next: the live call chain of each send (the in-process SendPacket observer,
  unwinding with the file's .pdata) names the event behind each handler; it
  attaches to the running game, so it is a separate decision.

## 5. How to name more messages

1. Record while the game does something known (MapleMarket's `crawl_*.log`
   gives each action's time).
2. `python -m traffic proxy-decode <recording>` (decodes again with the current
   code), then look at the messages around the action's time.
3. A name goes into `traffic/protocol.py` only with its evidence: matching
   text or ids, or a strict request/answer pairing counted over the recording.
   `protocol.reveal_shifted_text` shows text hidden by a one-bit shift (C 0x77,
   C 0xb9, S 0x2c, S 0x3c).
