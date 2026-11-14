# monitor-filter

Two tools for the Nexon / MapleStory family (launcher, nexon_client, nexon_agent,
nexon_runtime, NGService, MapleStory and its grap/overlay parts), started together:

- `filter/` - **kfilter** enforces: Windows `kfilter.sys` + `kfilterctl`, Linux `kfilterd`
  (BPF LSM) + `kfilterctl`. See `filter/README.md`, `filter/docs/`.
- `monitor/` - **msmon** observes and records everything the family does, including what
  kfilter cannot filter, and kfilter's own decisions. See `monitor/README.md`, `monitor/docs/`.

> **Status.** Linux (Ubuntu 24.04, kernel 7.0, Wine 11.0) is built and tested: every root test
> and an end-to-end `monfilter.py run` pass in throwaway Wine prefixes. Neither half has been run
> against the real Nexon client. **Windows is UNVERIFIED:** only offline checks ran (Win64 ABI
> sizes, the shared policy matcher); nothing was compiled with MSVC or the WDK, the
> drivers have never been loaded and the Windows path of `monfilter.py run` has never run.
> [PARITY.md](PARITY.md) lists, for every Windows capability, what Linux does.

Layout: `filter/` and `monitor/` keep their own build, docs and tests (and their git histories);
`abi/` checks the shared structures on both OSes; `monfilter.py`, `build.sh`/`build.cmd` and
`tests/` tie them together.

## One command

```sh
./monfilter.py build                 # compile both halves, no tests (./build.sh, build.cmd on Windows)
./monfilter.py test                  # build the test binaries and run every offline check
./monfilter.py run                   # audit mode: nothing is blocked, everything is recorded
./monfilter.py run --block           # enforce; kfilter is turned off again when the run ends
./monfilter.py run --block --keep-enforcing   # leave enforcement on (pinned) after the run
./monfilter.py stop                  # end a run from another terminal; always turns kfilter off and unpins it
./monfilter.py status
./monfilter.py report <bundle>       # the tuning report for a session (dir, .zip or events.jsonl)
```

`run` re-runs itself with sudo; the client runs as you. On Linux it starts kfilterd (or
adopts a running one), loads `filter/policy/linux-default-policy.txt` with `/@HOME@` and
`/@WINEPREFIX@` filled in, starts msmon-agent on every Nexon root (client, launcher, NGS) with
socket payloads and pcap on, waits until it records, then runs `~/.local/bin/nexon-launcher`
(WINEPREFIX `~/.wine-nexon`) under `kfilterctl launch`. When the family exits (or on Ctrl-C /
`stop`) it stops the client, msmon (final drain), kfilter, packs the session and writes
`~/monfilter-sessions/<run>/<session>-tuning.md` and `.json` (one root-only directory per run,
handed to you at the end). The session is kept as `<session>.zip` alone once it reads back whole
(about 15x smaller than unpacked); `report` reads the zip as it is.

`run` refuses to start while the prefix is already running (the Nexon Launcher is open): close
it first, or use `--attach` to record the running one (kfilter then cannot see how its processes
started, and msmon joins them late).

Block mode with an unreviewed policy stops the client. If the client never starts, `run` waits:
end it with Ctrl-C or `monfilter.py stop`.

Options: `--policy FILE`, `--prefix DIR`, `--client DIR`, `--log-dir DIR`, `--no-payloads`
(metadata only), `--attach` (tools only; start the client yourself), `--entry PROGRAM ARGS...`
(last option; becomes the policy's launch `root`).

Linux hiding, containment and traps (`filter/docs/LINUX.md`, "Hiding and isolation"). All are
off except the private `/proc`; Windows refuses them:

| Option | What the client gets |
|---|---|
| (default) / `--no-private-proc` | a private `/proc` mounted `hidepid=invisible` and its own cgroup namespace (`/proc/self/cgroup` reads `0::/`); `--no-private-proc` keeps the host's view |
| `--hostname NAME` | its own host name (UTS namespace) |
| `--uname26` | `uname` reports a 2.6 kernel release (personality `UNAME26`) |
| `--time-offset SECONDS\|random` | uptime shifted by that many seconds (time namespace; `random`: 1 to 30 days); the wall clock and the TSC are not |
| `--user ACCOUNT` | runs as that dedicated account (not root); needs a `--prefix` that account owns, and X, sound and GPU access granted to it |
| `--trap-cpuid` | an in-process shim (`LD_PRELOAD`, visible to the program, which can also read the options file beside it; neither the options nor the log path is in its environment) traps and logs every CPUID leaf, answered as the hardware does (the per-core leaves as the core the thread runs on answers them) |
| `--cpuid-mask LEAVES` | the shim zeroes those identity leaves (e.g. `0x80000002-0x80000004`, the brand string) |
| `--trap-rdtsc` | the shim also traps and logs RDTSC/RDTSCP (forensic: slows every time read; Chrome's sandboxed processes, the sign-in Chrome's, die at their first) |
| `--nested-x [auto\|xwayland\|xephyr]` | its own X server (rootful Xwayland or Xephyr, a fresh cookie); every other X and Wayland socket, GNOME's Xwayland cookie and the desktop's Xauthority are refused |
| `--dbus-proxy` | session and system bus through `xdg-dbus-proxy --filter --log` (only the bus itself and the login keyring, `org.freedesktop.secrets`, which the sign-in Chrome's cookies need and which opens the whole unlocked keyring to the family; Wine's UDisks2, BlueZ and Avahi queries are refused); the real buses and AT-SPI are refused |
| `--tls-keylog` | `SSLKEYLOGFILE` pointing into the bundle, for stacks that honour it (Chromium/CEF), to decrypt `events.pcapng` offline |

Whatever the options, the client's environment is an allowlist (account, locale, display, buses,
sound, Wine and graphics settings): sudo's variables, which name the tools, never reach it.

What the client writes (`cpu-trap.log`, `tls-keys.log`) lands in the bundle's `client/`; the
proxies' and the nested server's logs (`dbus-*.log`, `nested-x.log`) next to `events.jsonl`. The
session's own socket rules are put first in the policy: in audit mode a would-deny on a desktop
socket shows the client going around the nested X server or the proxy.

The session bundle holds the client's socket bytes and packets (sensitivity `secrets`): the
log directory is private to you. Share only `monitor/tools/redact_session.py` output.

## The tuning loop

1. `./monfilter.py run` and use the client normally.
2. Read `<session>-tuning.md`. Per program and layer it lists **BLOCKED**, **WOULD BLOCK**
   (audit), **ALLOWED BY RULE** (with the rule), **WENT THROUGH WITH NO RULE** (msmon saw it,
   kfilter made no decision: a gap kfilter could close) and **NOT FILTERABLE** (activity no
   kfilter layer covers), then **NOT SEEN BY EITHER TOOL** (the session's coverage notes and
   the known residue) and the CPU instructions the client trapped (with `--trap-cpuid`). Then
   candidate rules: denies for gaps (an `audit` line first in a Linux rule-only layer: `peer`,
   `thread-peer`, `system`, `dns`, `thread`, `/anon/...`, which decide only what a rule names),
   exact image-scoped replacements for broad allows, and exact allows for would-blocks the
   client needs.
3. Move the lines you accept into the policy, run again; `--block` once WOULD BLOCK holds only
   what should be refused.

## Tests

`build` never runs tests, and a policy change needs no rebuild (`run --policy FILE`).

- No root: `./monfilter.py test` (builds the test binaries first): ABI, kfilter's matcher,
  daemon and default policy, msmon's regression, PE unwinder, pcap writer, wineserver decoder,
  kernel aggregates, watchpoints and redaction, `monfilter.py run` with fake daemons, and the report
  on a synthetic session.
- Root, one at a time, after `./monfilter.py test` (they load BPF programs; never against the
  real client): `filter/tests/linux_lsm_test.sh`, `linux_launch_test.sh`, `linux_wine_test.sh`;
  `monitor/tests/linux_ebpf_test.sh`, `linux_wine_test.sh`, `linux_budget_test.sh` (msmon's CPU
  budget and what `--watch` costs the watched threads: it passes before msmon runs in the live loop again),
  `linux_watch_test.sh` (`--watch` hardware watchpoints: their hit cap, fds and module moves, and their
  debug-register conflict with a tracer); and the joint run in a throwaway
  prefix:

  ```sh
  S=$(mktemp -d); WINEPREFIX=$S/p /opt/wine-stable/bin/wineboot -i
  ./monfilter.py run --prefix $S/p --client $S/p/drive_c/windows/system32 --log-dir $S/logs \
      --entry /opt/wine-stable/bin/wine cmd.exe /c echo monfilter
  ```
- Root, and safe beside a running kfilterd or msmon (fresh, unpinned maps; nothing attached):
  `tests/bpf_verify.sh` (every BPF program of both halves loads; verified instructions per program)
  and `tests/bpf_bench.sh` (kfilter's kernel matching run on synthetic decisions).

Windows: `build.cmd`, and `monfilter.py run` from an elevated prompt (sc.exe, kfilterctl.exe,
msmon-agent.exe) are written but have never run on Windows.
