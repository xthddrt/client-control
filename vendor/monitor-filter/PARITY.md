# Windows → Linux parity

The contract: Linux has every capability Windows has, or the row says why it cannot exist under
Wine (N/A). Windows-only extras are not a goal; Linux-only extras are listed at the end.

Windows column: what the code does. **It has never run** (see README). Linux column: built and
covered by the root tests on Ubuntu 24.04 / kernel 7.0 / Wine 11.0 (protocol 930 only).

## monitor (msmon): what is recorded

| Windows capability | Linux |
|---|---|
| Process start / exit / exec | yes: eBPF tracepoints (proc connector fallback) |
| Thread create / exit | yes: `task_newtask`, wineserver `new_thread` |
| Image load (`PsSetLoadImageNotifyRoutine`) | yes: recorded at the mapping (mmap / mprotect), plus a `/proc/maps` poll |
| File operations | yes, with byte counts, errno and stack |
| File snapshots | yes (the prefix is a snapshot root) |
| Registry, with values up to 64 KiB | yes for Wine 11.0 through the wineserver decoder; values up to about 8 KiB per request, larger ones marked partial |
| Process / thread handle opens and duplicates (Ob callbacks) | yes: wineserver `open_process`, `open_thread`, `dup_handle`, `get_next_*`, `new_thread`; native ptrace / pidfd |
| Network connect / accept (WFP) | yes: syscalls and TCP tracepoints |
| DNS (ETW) | yes: parsed from the wire |
| RPC (ETW) | yes: DCE/RPC binds and requests on Wine's ncalrpc / ncacn_np pipes (endpoint, interface, opnum) |
| WMI (ETW) | yes: COM activation, provider loads, and each `ExecQuery`'s WQL text (a uprobe on Wine's in-process `wbemprox.dll`) |
| CodeIntegrity (ETW) | N/A: no WDAC under Wine. Driver loads in winedevice.exe are recorded as `driver_load` |
| Named pipes and IPC | yes, with named-pipe bytes and RPC stub arguments as `ipc_data` payloads; SysV and POSIX queues |
| Device IOCTLs | yes: ioctl syscalls and winedevice IRPs, named by driver |
| Volume information | yes: wineserver `get_volume_info` |
| BlackCat (kernel driver) attribution | N/A: there is no Windows kernel; a `.sys` runs inside winedevice.exe in user space. Its work is attributed as brokered by winedevice, with the driver as component |
| User-mode stack / caller module | yes: PE frames on every syscall (Windows: 24 frames on some events) |
| 32-bit processes | yes: ia32 syscalls, `socketcall` and `ipc` subcalls included (the Nexon launcher family is 32-bit under this Wine) |
| Process command line, CreateInfo | yes: the whole argv at exec, and `new_process`'s Windows command line, image, directory and parent override |
| kfilter decisions | yes: `kfilter_decision` records (msmon owns the decision ring) |

## filter (kfilter): what can be blocked

| Windows capability | Linux |
|---|---|
| File open / read / write (minifilter) | yes: BPF LSM (fanotify fallback) |
| Delete, rename, link, set-security, truncate | yes: BPF LSM (not in the fanotify fallback) |
| Execute / section mapping | yes: `mmap_file`, `file_mprotect` |
| Registry (18 classes) | yes for Wine 11.0, decided in the request pipe. N/A: the program gets `STATUS_ACCESS_VIOLATION`, not `STATUS_ACCESS_DENIED` (that needs a Wine patch) |
| Volume identity | yes; `statfs` (`f_fsid`) is logged, not refused |
| Attributes-only opens (`FILE_READ_ATTRIBUTES`) | yes: stat, access, readlink, xattrs and change watches are `query` decisions (`block-file-queries`); Windows maps attributes-only creates to the same right |
| Child process creation | yes |
| Launch, admission, allow-launch | yes |
| AppContainer launch | N/A: no package SID under Wine. Substitute: launch cgroup, privilege drop, `no_new_privs`, optional network and UTS namespaces |
| Process memory and handle rights (Ob) | yes: ptrace, `process_vm_*`, kill, and wineserver handle requests (open / dup / get_next / new_process) |
| Thread handle rights | yes: wineserver `open_thread` / `dup_handle` |
| Raw disk | yes, including Wine's `\??\PhysicalDrive*` opens |
| Identity devices (NSI, MountMgr, SCSI, HID, USB) | yes: identity character devices and netlink, and Wine's NT device opens (`\??\Nsi`, `\Device\MountPointManager`, `\??\HID#...`) |
| Named pipes | yes: Wine's `\??\pipe\...` creates and opens (`pipe` rules) |
| Named sections (shared memory by name) | yes: Wine's `open_mapping`/`create_mapping` by name (`file` rules on `\Sessions\*\BaseNamedObjects\...`) |
| Network adapter / MAC queries | yes: netlink and `SIOCGIF*` |
| Connect / listen / accept (WFP) | yes, including UDP per peer |
| RISK events, degraded status, decision ring | yes |
| Enforcement survives the daemon or driver stopping | yes in block mode: pinned BPF; `monfilter.py stop` / `kfilterctl off` unloads |

Not mediated on Linux (no Windows counterpart either): page faults on existing mappings,
io_uring splices into a request pipe, work done entirely inside the kernel. io_uring rings are a
`/system/io_uring` decision, and what a ring opens and reads is decided as the program's own.

Windows lacks, for rules that work on Linux: `hide` (Windows refuses with `ACCESS_DENIED`), and
every rule-only target below. `kfilterctl` reports them unenforced there: block mode refuses such a
policy, audit mode warns and loads the rest.

## Linux-only extras

kfilter (BPF layer only; `kfilterctl check` on Windows or `--no-bpf` reports them unenforced):

- Rule-only targets, decided only where a rule names them: `peer` and `thread-peer` (one
  protected program opening, reading, writing, suspending or creating threads in another),
  `thread` (thread creation), `dns` (each name the program looks up), and `system`:
  `uname`/`sysinfo`, socket creation by family, type and protocol, memfds, `userfaultfd`,
  io_uring, secret memory, keyrings, SysV IPC, `arch_prctl`, executable anonymous memory
  (`/system/memory/...`), every wineserver request (`/system/wine/<request>`: enumeration, token,
  debugger and named-object requests as before; any other where a rule names it, such as
  `send_message`, `set_hook` or `get_clipboard_data`), win32k-level calls (`/system/win32k/<function>[/<key>]`, which
  Windows cannot hook: a key, a clipboard format, a hook id, or whose window it is), ntdll-level calls Wine answers
  in-process (`/system/ntdll/<function>[/<class>]`: debugger, process, thread, system and own-memory queries), and WMI
  queries per class and method calls (`/system/wmi/<class>[/<method>]`; Windows' WMI runs out of process).
- Names Windows has no equivalent for: pseudo files `/anon/...` (memfd, SysV shm, POSIX queues,
  pipes made outside the family), `/proc/@self|@family|@wine|@outside`, `hide` (ENOENT).
- `module=` on message, system, thread and dns rules; message rules and `block-connection`; message rules on sends to
  AF_UNIX peers (`unix=`, ABI 12: a kill switch for an X11, D-Bus or Pulse connection, not a per-request filter).
- `addr=` on peer, thread-peer and system rules (ABI 10): memory ranges, absolute or from a module of the target,
  that a read, write, VirtualQueryEx, mapped-file query, hardware breakpoint or native `process_vm_*`,
  `/proc/<pid>/mem` access or ptrace attach must overlap (an allow: lie within); one location refused instead of
  every access.
- What a Wine request reaches past its own decision (ABI 11): another program's windows and threads by the peer
  pseudo-rights `window-query`, `window-set`, `window-message` and `input` (`value=` the message, offset or key), a
  process or thread handle at any offset (`value=<request>`), and keys under the request
  (`/system/wine/set_hook/13/global`, `/system/wine/ioctl/<NT name>/0x<code>`, `/system/rpc/<interface>/<opnum>`...);
  only rules naming each meet it.
- ioctls by value on any device, file or anonymous inode; driver (`.sys`) loads in winedevice.
- ABI 11: every syscall of both x86 tables by name and key (`/system/syscall/<name>[/<key>]`, attached only for the
  calls a rule names); the hooks and spaces kfilter did not decide (`/system/fcntl`, `/system/socket/shutdown`,
  `/system/socketpair`, `/system/rlimit`, `/system/task`, `/system/cred`, `/system/capability`, `/system/namespace`,
  `/system/memory/low` and data memory `/system/memory/<private|shared>/<rw|r|none>`, `/system/ipc/create`,
  `/system/fork`, `/system/ptrace/traceme`, `/system/kernel`, `/system/prctl`, `/system/statfs`), every netlink family
  and type (`/net/netlink/<family>/<type>`), every socket ioctl (`/net/ioctl/0x<code>`), an ioctl's argument
  (`value=0x<ioctl>:0x<argument>`), the rights `lock`, `chdir` and `touch` on file and dir rules, AF_UNIX servers as
  pipe `listen`, and the switches `block-process-signals` (signals and SIGIO across the family's boundary) and
  `block-process-queries` (`PTRACE_MODE_READ` checks across it). Each is decided only while a rule names it.
- The `direct` flag on decisions for syscalls a Windows program makes itself, and
  `block-direct-syscall`.
- At launch: a private `hidepid` `/proc` and cgroup namespace, host name, `uname26`, a time
  namespace, a dedicated account (the counterparts of AppContainer and a separate low-integrity
  user), the CPUID/RDTSC trap shim with identity-leaf masking, a nested X server (Windows: a
  separate desktop or window station, not implemented), a D-Bus proxy, a TLS key log.

msmon:

- Socket payload bytes and pcapng; TLS plaintext of Wine's schannel (GnuTLS) as `tls_plaintext`.
- Brokered attribution: wineserver's and winedevice's work names the program it serves.
- Every syscall and wineserver request counted per process (`syscall_counts`,
  `wineserver_request_counts`); refused process creation; one record per address read in
  another process.
- Wineserver requests: thread context and debug registers, APCs, suspend, hide-from-debugger,
  named objects, tokens, input injection, hooks, clipboard formats, atoms; system enumeration
  (process list, windows, handles, TCP table).
- Calls Wine answers in-process (`win32u.so`, `ntdll.so`) through per-process uprobes.
- Kernel events: io_uring and AIO operations, signals received, trapped instructions (CPUID and
  RDTSC faulting, UMIP), capability checks, module requests, credential changes; first touches
  of shared mappings (`--page-faults`); anonymous executable regions named when they hold a PE.
- Native helpers the client starts stay tracked (`--native-depth`).

## What neither tool can see or block

On either OS (the tuning report's **NOT SEEN BY EITHER TOOL** adds the session's own notes):

- Instructions that never trap: XGETBV, RDPID, LSL/LAR, RDRAND/RDSEED; RDFSBASE/RDGSBASE and
  RDPKRU unless the kernel boots with `nofsgsbase`/`nopku` (unverified here). CPUID and RDTSC are
  seen only with `--trap-cpuid`/`--trap-rdtsc`, and only masked, never refused.
- Cache, TSX and other timing side channels (`tsx=off` removes TSX).
- Game-protocol plaintext inside PE code (its own crypto, OpenSSL/BoringSSL DLLs, CEF): only
  ciphertext crosses a socket; `--tls-keylog` helps only a stack that honours `SSLKEYLOGFILE`.
- Reads of memory already mapped: shared sections, Wine's desktop and queue shared memory (Wine
  11's `GetAsyncKeyState`/`GetCursorPos` state), `KUSER_SHARED_DATA`; msmon `--page-faults` sees
  first touches only.
- vDSO calls (`clock_gettime`, `gettimeofday`, `getcpu`): no syscall (`--trap-rdtsc` shows the
  TSC reads behind them). The vDSO also undoes two launch options on Linux, and only `vdso=0` on
  the kernel command line (a system setting) removes it: its ELF notes give the real kernel
  version and build-id whatever `--uname26` says, and under `--time-offset` the real clock data
  stays mapped in `[vvar]` (the true boot time).
- RPC calls and the bytes moved over a Windows named pipe under Wine are recorded, not decided:
  kfilter decides the pipe's create and open (`pipe` rules on `\??\pipe\...`), not what flows
  through it.
- Work done entirely inside the kernel.
