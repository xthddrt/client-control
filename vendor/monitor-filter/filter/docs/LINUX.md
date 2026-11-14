# kernel-filter on Linux

> **Runtime-checked in a VM, not against the real client.** `./build.sh` compiles and runs
> `kfilterctl self-test`, `kfilterd-test` (decision logic and socket protocol, no root)
> and the policy-tool self-test. `sudo tests/linux_lsm_test.sh`, `sudo tests/linux_launch_test.sh`
> and `sudo tests/linux_wine_test.sh` (root; stop any running kfilterd) check the BPF layer,
> the fallback and the Wine attribution. Run them before relying on it.

Target: Ubuntu 24.04, kernel 7.0 (BPF LSM, fanotify permission events, proc connector,
nftables with `socket cgroupv2`). The client is a Windows program, so on Linux it runs
under Wine 11.

## Deciding what the Windows program does, not what Wine does

Under Wine the program's work is split across processes:

| What the program does | Who makes the syscall under Wine | How kfilter decides it |
|---|---|---|
| reads, writes and mappings of its open files, exec, child processes, UDP sends | the program | as the program (as on Windows) |
| opening and creating files (`NtCreateFile`), delete-on-close, rename, hard links, truncation | wineserver | **as the program**: wineserver is charged to the client whose request it is serving |
| creating sockets, TCP `connect`/`bind`/`listen`/`accept` (AFD) | wineserver | **as the program**, and the socket records the program as its owner |
| `OpenProcess`/`OpenThread`/`DuplicateHandle` across the family (the rights `TerminateProcess`, `CreateRemoteThread`, `VirtualAllocEx`, `MapViewOfSection` need) | wineserver, from the program's request | **decoded from the request** and decided when the handle is made: OPEN/THREAD-OPEN rules for the program, HANDLE/THREAD-HANDLE rules for an outside opener (strict mode) |
| `ReadProcessMemory`/`WriteProcessMemory` of another process | wineserver (`process_vm_*`) | **as the program** (OPEN rules), or as the outside client (HANDLE rules) |
| registry access | wineserver, in memory: no syscall at all | **decoded from the program's request** to wineserver and decided before it is sent |
| adapter, MAC, ARP and disk queries (`\Device\Nsi`, the mount manager) | winedevice.exe | **as the program** while winedevice handles its device request |

How (`linux/bpf/kfilter.bpf.c`, "Wine" section):

- **Marking.** An exec of a Wine loader (`wine`, `wine64`, `wine-preloader`,
  `wine64-preloader`) marks the task as a Wine client, and an exec of `wineserver` marks the
  broker. kfilterd marks the ones already running when it starts.
  - wineserver is never itself protected, even when the family starts it.
- **Charging wineserver to a client.**
  - A Wine thread's first request to wineserver (`init_first_thread` or `init_thread`, which
    carry its unix pid/tid and reply fd), or later its TEB's request fd, registers its
    request and reply pipes. This works with or without a policy loaded, so key handles
    opened at start-up have names when a policy arrives.
  - wineserver reading a registered request pipe is serving that client. Until it writes the
    reply, its opens, connects, memory accesses and signals are decided as the client's.
  - Those events carry `KFILTER_EVENT_FLAG_BROKERED` (0x800) and the client's pid. `watch`
    shows the program as `cmd.exe(brokered)`.
  - wineserver's own housekeeping (registry saves, timers) is charged to no one.
- **Windows ids.** A process's Windows pid and tid come from wineserver's reply to its
  `init_first_thread`, a thread's tid from its creator's `new_thread` reply; never from the
  program's memory (its TEB). A process or thread whose id kfilter did not learn (started
  before kfilterd) counts as outside the family.
- **winedevice.** wineserver's reply to winedevice's `get_next_device_request` names the
  client thread. That winedevice thread is charged to the client until it asks for its next
  request.
- **Naming.** Each Wine process is named by its Windows image the first time it can be. The
  name is `argv[0]`, which Wine rewrites to `C:\...\Program.exe`, or to the bare name a
  program was started as (`wine start.exe` leaves `start.exe`).
  - It is read once and never re-read, so the program cannot rename itself afterwards.
  - Events carry the program's file name in `Image`, for example `MapleStory.exe`.
- **Supported Wine.** Request decoding and attribution apply to programs run by a Wine install
  that speaks wineserver protocol 930 (Wine 11.0 and its point releases).
  - kfilterd finds these installs by their `ntdll.so` (`/opt/wine-stable`, `-staging`,
    `-devel`, `/usr/local`): the number its version check compares the server's with, or Wine
    11.0's build string.
  - An install there that speaks another protocol is reported: `status` lists the `wine` class
    degraded, kfilterd says which install at start, and block mode for a policy that protects a
    Windows program is refused (its programs' registry, handle, peer, `/system/wine` and NT
    object requests would go undecided).
  - Programs run by a Wine elsewhere, such as Ubuntu's Wine 9 under `/usr/lib`, are named but
    not attributed, because their request layout and TEB offsets differ; nothing reports them.
- **Refusing a request.** A refused registry request fails the program's write to wineserver
  with EFAULT. Wine's only graceful answer to that is `STATUS_ACCESS_VIOLATION` for the call,
  so the program sees that instead of the `STATUS_ACCESS_DENIED` Windows would return.
  A refused `ioctl` with an output buffer is the exception: Wine 11 then reads a wait handle
  from its unwritten reply (the request's output size) and waits on it, so the call fails with
  `STATUS_INVALID_HANDLE`, or waits on a real handle of that number.

## How the layers map

kfilterd first loads its BPF LSM layer (`linux/bpf/kfilter.bpf.c`, built when clang, bpftool
and libbpf are present).

- **Compiled policy.** The policy is compiled into the layer's maps:
  - literal paths go in a hash, with every parent directory probed (NT names lowercased); a
    candidate's own path is compared with the request's before it decides
  - up to 256 wildcard rules
  - network rules, counted uses and phases

  There are two such rule sets. A policy is written into the one not in force and one word
  (`kb_live`) then switches to it, so every lookup meets either the old policy's rules or
  the new one's, never a mix; `kfilterctl policy` returns once no decision still reads the old
  set (the RCU grace period the kernel waits out after an update of a map of maps). A write
  to the set that fails refuses the policy before the switch. The switches and counts in the
  layer's configuration follow a moment after the rules, each the old value or the new.
- **Decisions.** Every hook is decided in the kernel with the same first-match, rights,
  image, audit/would-deny and block semantics as `driver/policy.c`. Decisions reach the same
  ring (`kfilterctl watch`) and counters, and `kfilterctl status` lists the layer as `bpf`.
- **Working memory** is per task. A decision preempted on its CPU cannot see another task's
  state, which matters on `PREEMPT_LAZY` kernels. The softirq hooks use a per-CPU area of their
  own.

| Windows (kfilter.sys) | Linux BPF layer (default) |
|---|---|
| minifilter pre-create | `lsm/file_open` (all filesystems, including `/proc`, devtmpfs and hot-plugged devices), including wineserver's opens for the program; `lsm/file_receive` for files passed to it over SCM_RIGHTS |
| read/write of an open file | `lsm/file_permission`. Rights are decided once per open, as on Windows: reads and writes within an open's decided rights are not decided again. A received or inherited file is decided on its first use. |
| delete, rename, link, set-information, set-security | `lsm/path_unlink`, `path_rmdir`, `path_rename` (old name: rename; new name: write), `path_link` (old name: rename+read), `path_symlink`, `path_mkdir`, `path_mknod`, `path_truncate`, `file_truncate`, `path_chmod`, `path_chown`, `inode_setxattr`, `inode_removexattr`, `inode_setattr` (explicit times) |
| attributes-only create (`query`), directory change notification | `block-file-queries`: `lsm/inode_getattr` (stat, statx, fstat), `inode_permission` with `MAY_ACCESS` (access, faccessat2), `inode_readlink`, `inode_getxattr`, `inode_listxattr` as `query` on the file, dir or pipe; `lsm/path_notify` (inotify, fanotify, dnotify) as `enumerate` on a dir, `read` on a file. `lsm/sb_statfs` is only logged (an `audit` volume record, value 0) under `block-volume-serial`. |
| section mapping | `lsm/mmap_file`, `lsm/file_mprotect`: `execute` for code; `read` for a data view, plus `write` for a shared writable one |
| registry callback (`block-registry`) | the program's requests to wineserver: `open_key`, `create_key`, `get_key_value`, `set_key_value`, `enum_key` (index -1: query), `enum_key_value` (refused under any value-scoped deny, as on Windows), `delete_key`, `delete_key_value`, `rename_key` (both names), `save_registry`, `load_registry`, `unload_registry`. Full key names come from a handle table filled from wineserver's replies. |
| raw disk / identity device filters | `lsm/file_open` and `lsm/file_ioctl` (+ `file_ioctl_compat` for 32-bit programs) on block devices (`block-raw-disk`) and identity character devices: `device` rules, value = the ioctl as `0x%08X` |
| device, named-pipe and named-section opens through Wine (`block-files`) | the program's `open_file_object`, `create_named_pipe`, `open_mapping` and `create_mapping` (named) requests to wineserver: objects with no unix file behind them (`\??\PhysicalDrive0`, `\Device\MountPointManager`, `\??\Nsi`, `\??\HID#...`, `\Device\Afd`, `\??\pipe\...`). Named sections (shared memory other programs open by name, or probe for: `\Sessions\1\BaseNamedObjects\...`) are `file` decisions too, with section rights (query and map-read: read; map-write: write; map-execute: execute); names relative to an object directory resolve through the directory's name from `open_directory`/`create_directory`. A sleepable hook on `writev` faults Wine's request data in first, so a name in a page the program has not touched yet is not a name failure. A pipe is a `pipe` decision, anything else a `file` decision on its NT name (`deny|file|\??\PhysicalDrive*`, any case). A name relative to a handle kfilter named is joined to it; to one it did not, a name failure. Only the open is decided: reads, writes and ioctls on the handle are wineserver's. A refusal fails the request (Wine returns `STATUS_ACCESS_VIOLATION`). |
| volume serial (`block-volume-serial`) | `FS_IOC_GETFSUUID`, `FS_IOC_GETFSSYSFSPATH`, `FS_IOC_GETFSLABEL` on any file: `volume` rules (default deny), value = the ioctl. Under Wine, the program's `get_volume_info` requests for FileFsVolumeInformation (1: serial, label) and FileFsObjectIdInformation (8), which Wine answers from its mount manager: `volume` decisions on the handle's NT name (else `\Device\Volume`), value = the class (a `volume` rule names it: `allow|volume|\??\C:|rights=read`) |
| NSI / NDIS filters (`block-network-adapter`) | `lsm/netlink_send`: `RTM_GETLINK`, `RTM_GETADDR`, `RTM_GETROUTE`, `RTM_GETNEIGH` and sock_diag as `device` decisions on `/net/netlink/route` and `/net/netlink/sock_diag` (value = message type); interface and wireless ioctls on a socket on `/net/ioctl` (value = the ioctl). Default deny, as on Windows. |
| process-creation refusal | every exec-open of a protected task (`lsm/file_open` of an exec open, `__FMODE_EXEC` in its open flags): `process` rules; `lsm/bprm_check_security`: the launch handshake and admission of a `/` protect name; for a Windows protect name, admission when Wine names the process |
| process tracking | task storage: `lsm/task_alloc` protects a protected task's children and threads before they run |
| object callbacks (`block-process-memory`) | `lsm/ptrace_access_check` (ptrace attach, `/proc/<pid>/mem`, `process_vm_*`) across the family. wineserver acts for its client. An outside program needs a `handle` allow and the client an `open` allow for the target, granting `vm_operation,vm_read,vm_write`. Rules name a Windows program by its image. `lsm/task_kill`: the client signalling an outside process needs an `open` allow granting `terminate`. |
| WFP ALE callouts | `lsm/socket_connect`, `socket_sendmsg` (unconnected datagrams), `socket_bind`, `socket_listen`, `socket_accept`, `inet_conn_request` (incoming TCP, by source) and `socket_sock_rcv_skb` (incoming UDP, by source) for sockets made for the program, including by wineserver. UDP is authorised per peer. IPv4-mapped IPv6 addresses are decided as IPv4. |
| (none: WFP stream inspection is not used on Windows) | `lsm/socket_sendmsg`, `lsm/socket_recvmsg`: **each message** a protected program sends or receives on an INET socket, after its connection was allowed (message rules, `block-connection`), and each send to an AF_UNIX peer a `unix=` message rule names |
| named pipes / ALPC endpoints | Unix sockets: `connect` and unconnected `sendmsg` are `pipe` decisions on the socket's path, `/@name` for an abstract socket (rights `connect`) |
| (none) | always refused to a protected task: `prctl(PR_SET_MM)`, kernel module/firmware loads, `bpf()`, `perf_event_open` (logged as `process` decisions). `PR_SET_PTRACER` is allowed: Wine sets it so wineserver can reach the client, and kfilter decides that access itself. |

`kfilterd --no-bpf`, or a kernel or build without BPF LSM, uses the earlier layers:

| Windows (kfilter.sys) | Linux fallback (kfilterd --no-bpf) |
|---|---|
| minifilter pre-create | fanotify `FAN_OPEN_PERM`/`FAN_ACCESS_PERM` on every marked filesystem; the requested access is read from the blocked thread's `/proc/<tid>/syscall` |
| process-creation refusal | fanotify `FAN_OPEN_EXEC_PERM`; process tracking through the proc connector plus a lazy parent check |
| raw disk / identity device filters | inode marks on block devices and `/dev/hidraw*`, `/dev/sg*`, `/dev/bsg/*`, `/dev/bus/usb/*`, `/dev/nvme*`, and on such nodes added later (kernel uevents); opens and reads use `device` rules (`raw-device`) |
| WFP ALE callouts | one nftables table `inet kfilter`, matched on the launch cgroup `/sys/fs/cgroup/kfilter` |
| `\\.\KFilter` IOCTLs | root-only socket `/run/kfilter.sock`, same requests and structs (`linux/kfilter_socket.h`) |
| AppContainer launch | `kfilterctl launch`: session cgroup, privilege drop to `SUDO_UID`, `PR_SET_NO_NEW_PRIVS`, admission handshake before exec, `--no-network` (network namespace), `--hostname` (UTS namespace), `--private-proc`, `--user` and the other hiding options (see "Hiding and isolation") |
| registry, volume identity, adapters, process memory, file queries, Wine attribution | none. In block mode, `block-registry`, `block-volume-serial`, `block-network-adapter`, `block-process-memory` and `block-file-queries` are refused rather than claimed. |

`driver/policy.c`, `driver/events.c` and `driver/match.c` are compiled unchanged into
`kfilterd` through `linux/posix_shim.h`, so first-match rules, rights, counted rules, image
rules, audit/would-deny and the decision ring behave as in the driver.

## Build and run

```sh
./build.sh                      # build/linux/kfilterd, kfilterctl, kfilterd-test
sudo build/linux/kfilterd &     # or install linux/kfilterd.service by hand; --no-bpf: fallback layers
sudo build/linux/kfilterctl status
sudo build/linux/kfilterctl check policy/linux-default-policy.txt   # warns of rules that reach further than they look
sudo build/linux/kfilterctl policy policy/linux-default-policy.txt
# Either start the Nexon launcher as usual (MapleStory.exe and the other protected programs
# are protected when Wine names them), or launch through kfilterctl:
sudo --preserve-env=DISPLAY,WAYLAND_DISPLAY,XDG_RUNTIME_DIR,WINEPREFIX \
    build/linux/kfilterctl launch /opt/wine-stable/bin/wine 'C:\Nexon\Library\maplestorycw\appdata\MapleStory.exe'
sudo build/linux/kfilterctl watch 30
sudo build/linux/kfilterctl on        # block; `audit` and `off` as on Windows
```

`launch` must run as root, because it talks to kfilterd and creates the session cgroup.
- It runs the client as the user who invoked `sudo`, waits for it, and returns its exit status.
- `--no-network` starts the client in an empty network namespace. Under Wine the program's
  sockets are wineserver's, so `launch` refuses `--no-network` while a wineserver already
  serves the prefix. Run `wineserver -k` for the prefix first.
- `--hostname NAME` gives the session its own host name (UTS namespace). This is what
  `GetComputerName`, `gethostname` and `uname` report. Start it with no wineserver running for
  the prefix.
- A Wine loader is admitted for the Windows program it runs, which must be protected or under
  the root: `--program 'C:\...\x.exe'`, or by default wine's first `.exe` argument. A script
  that runs wine (`kfilterctl launch ~/.local/bin/nexon-launcher`) is admitted for the `.exe`
  names it contains, or for its `--program`.
- `--uname26`, `--time-offset`, `--private-proc`, `--user`, `--trap-cpuid`, `--trap-rdtsc`,
  `--cpuid-mask` and `--trap-log` hide the host and contain the client; see "Hiding and
  isolation". Options may follow the program anywhere among its arguments.
- The client gets only an allowlist of `launch`'s environment: `HOME`, `USER`, `LOGNAME` (the
  client account's), `PATH`, `TERM`, `LANG`, `LANGUAGE`, `LC_*`, `TZ`, `DISPLAY`, `XAUTHORITY`,
  `WAYLAND_DISPLAY`, `XDG_*`, `DBUS_SESSION_BUS_ADDRESS`, `DBUS_SYSTEM_BUS_ADDRESS`, `PULSE_*`,
  `SSLKEYLOGFILE`, `WINE*`, `MESA_*`, `DXVK_*`, `VKD3D_*`, `__GL_*`, `VK_*` and `PROTON_*`: what
  `relax/kf-launcher`, `monfilter.py run` and the Nexon launcher script pass or read. sudo's own
  variables (`SUDO_COMMAND` spells out this command line and kfilterctl's path; `SUDO_USER`,
  `SUDO_UID`, `SUDO_GID`, which `launch` reads itself to drop privileges), `MAIL`, `SHELL` and the
  rest stay behind. `--keep-env NAME` (repeatable; `NAME*` is a prefix, `*` alone is refused)
  keeps more, e.g. `--keep-env LD_LIBRARY_PATH`.

Block mode fails closed: kfilterd pins its BPF links, so they keep enforcing if kfilterd dies,
and a restarted kfilterd takes the pinned layer over and adopts the saved policy
(`/run/kfilter/policy`). A layer pinned by a kfilterd before the two rule sets is taken over
with its policy in force (an end mark is added after its wildcard and network rules). Before
going back to a kfilterd of an earlier ABI, run `kfilterctl stop`: taking this layer over, it
cannot load the saved policy (another ABI), and its programs would decide by this policy's
rules (an `addr=` rule as one without it; one before the rule sets by set 0, which may hold
the policy before last) until it is given a policy. Only
`kfilterctl off` or `kfilterctl stop` (off, unpin, kfilterd exits; the service's `ExecStop`)
ends it. Without the BPF layer only the nftables table survives; `kfilterctl status` says
`fail-open`. Block mode also refuses a policy with rules no active layer enforces (message
rules without BPF, for example); audit mode loads it and `status` lists the class as degraded.

While msmon-agent records a session it owns the decision ring (reads take events off it), so
`kfilterctl watch` and `clear` are refused with EBUSY. Follow the `kfilter_decision` records in
the msmon session log instead. `kfilterctl session <tag>` sets the tag kfilterd reports with
its decisions.

In block mode with `block-process-create`, a protected Windows program started outside a
launch, for example MapleStory.exe from the Nexon launcher, is admitted only through the
launch pass: `sudo kfilterctl allow-launch nexon_client.exe 1 60`.

The creator is the program that called CreateProcess, matched on its Windows image name, or
on its executable's name. Wine's CreateProcess double-forks, which leaves the new program's
parent a reaper; kfilter follows the creator through that fork instead. Under plain
`wine x.exe`, the creator is Wine's `start.exe`. Without the pass the program is
killed when Wine names it, before its own code runs.

## Policy on Linux

`policy/linux-default-policy.txt` turns every layer on (`block-file-queries` included) and
audits each rule-only layer (`peer`, `thread-peer`, `system`, `dns`, `thread`, `message`,
`/anon/pipe/@outside`). It denies, in audit and block mode alike, only what runs showed Wine
does not need: identity sources (DMI, MACs, disk serials, monitor EDID, the ARP table, IPv6
interface ids), the host's socket and address tables (`/proc/*/net/tcp`, `udp`, `unix`, which
lists kfilter's socket, `fib_trie`, `snmp`...; not `net/dev`, which the game reads around a
channel change), the kernel's and the monitors' traces (`hide`: modules, BTF, the build-id),
other users' `/proc` entries
(`hide`, their `/proc/<pid>/net` too), escape surfaces (`/dev/uinput`, raw ALSA capture, systemd's and the credential
agents' sockets, Docker), the side resolvers and WPAD names, io_uring rings, secret memory and
executable memfds. It never denies `statfs`, the implicit ancestor queries or Wine's own pipes.
It audits winedevice's Bluetooth and USB driver loads (`winebth.sys`, `wineusb.sys`).

- **Paths.** Linux paths are matched **case-sensitively**; `*` is still the only wildcard.
  - `check`, `policy`, `default` and `launch` reject `C:\` and `\Device\` file paths.
  - `simulate`, `evaluate` and `self-test` still read Windows policies and captures.
- **`protect` names:**
  - A name starting with `/` is a Linux executable (suffix of the exe path).
  - Any other name is a **Windows program**, matched on its Windows image without case:
    `protect MapleStory.exe`, or `protect \MapleStory.exe` as in the Windows policy.
  - Protecting the Wine loader (`/wine64-preloader`) still works, but it protects every Wine
    program, the launcher included.
- **`registry` rules** name NT keys, `\REGISTRY\MACHINE\...` and `\REGISTRY\USER\<sid>\...`,
  matched without case. Wine's user SID is `S-1-5-21-0-0-0-<uid>`; use `*` for it. The
  Windows identity hard-denies apply unchanged.
- **`handle`, `open` and `launch` rules** name the other program by Linux path, by Windows
  image (`C:\Program Files (x86)\Nexon\*\nexon_client.exe`), or by a pattern starting with
  `\`.
- **`image=<glob>`, on any rule (network rules too):**
  - The rule applies only when the program making the request matches.
  - A pattern with a separator matches the whole Windows image path; one without matches its
    file name. Matching ignores case.
  - A program Wine has not named yet, or a native program, matches no `image=` pattern.
  - Example: `deny|registry|\REGISTRY\MACHINE\SOFTWARE\Microsoft\Cryptography|value=MachineGuid|image=grap-core64.aes`.
- **Counted rules:**
  - `uses=N`, `phase=P` and `opens` work on allow, deny and audit rules.
  - A counted deny refuses the first N matching requests (`uses=1`: block once). After that
    it steps aside and the rules below it decide.
  - A counted allow allows N requests and is then spent: the request is refused unless a
    later rule allows it.
  - Rights are counted once per open, not once per read or write.
- **Pipe rules on Unix sockets.** Unix sockets are `pipe` rules with `rights=connect`.
  Under default-deny the program needs at least the prefix's wineserver socket
  (`allow|pipe|/tmp/.wine-*/server-*/socket|rights=connect`), and usually X11 or Wayland, the
  sound server and D-Bus. Allow them from an audit run.
- **Synthetic device paths.**
  - `/net/netlink/route` and `/net/netlink/sock_diag` are netlink queries;
    `value=0x00000012` is `RTM_GETLINK`.
  - `/net/ioctl` is the socket interface ioctls.
  - `glibc`'s `getaddrinfo` with `AI_ADDRCONFIG` sends `RTM_GETADDR` (`0x00000016`), so a
    client that resolves names may need a counted allow for it under
    `block-network-adapter`. The audit run shows whether it does.
- **Exec opens.** ELF interpreters (`ld-linux*.so`) are exec'd too, so strict policies need
  `allow|process` rules for them (see `policy/linux-default-policy.txt`).
- **Process paths** are the executed file with symlinks resolved: `/usr/bin/wine` is
  `/usr/lib/wine/wine`.
- **Pseudo files** have no path and are named `/anon/<name>`: `/anon/memfd:<name>`,
  `/anon/SYSV<key>` (SysV shm, `SYSV00000000` for `IPC_PRIVATE`) and `/anon/mqueue/<name>`
  (POSIX message queues, however opened). Shared-anonymous memory made executable is
  `/system/memory/shared/...` (below).
  They are rule-only: with no rule naming them they are allowed and not logged, even under
  `default-deny`.
- **Pipes from outside the family** are `pipe` decisions on `/anon/pipe/<the program that made
  it>` (its Windows image under Wine), or `/anon/pipe/@outside` when kfilter does not follow its
  maker (a shell's pipe on the program's stdin, a pipe passed over SCM_RIGHTS), rights `read` and
  `write`, rule-only and once per open file. Pipes the family or wineserver made, and Wine's
  request and reply pipes, are never decided. Example: `deny|pipe|/anon/pipe/@outside|rights=write`.
- **ioctls on any file.** A `deny` or `audit` device rule also decides ioctls on devices that
  are not identity devices, on files and on anonymous inodes (`/anon/[userfaultfd]`,
  `/anon/dmabuf`), rule-only, value = the ioctl:
  `audit|device|/dev/dri/renderD*|value=0xC0106446` logs Intel GPU identity reads
  (`I915_GETPARAM`). io_uring passthrough commands (`uring_cmd`) are decided as the ioctl.
  An allow on such a path may leave out `uses=` (a GPU's ioctls come every frame); on a path a
  decision with no rule can name (identity devices, any name directly in `/dev`, which may be a
  block device, `/net/ioctl`, `/net/netlink/...`) an allow still needs `uses=N`.
- **Driver loads.** The `.sys` code winedevice.exe maps is a `file` execute decision of
  winedevice's own (`image=winedevice.exe`), rule-only. A deny makes that driver fail to start: the
  refusal is of the `mprotect` that makes a section executable, which Wine 11 logs and goes on to
  run the driver, so the winedevice.exe hosting it ends with every driver it hosts
  (`tests/linux_wine_test.sh`: refusing `wineusb.sys` ends winebus's host, winebus 1067, and
  `winebth.sys` there never starts). Wine's own drivers (mountmgr, nsiproxy, winebus...) are
  needed by the whole prefix. Example: `deny|file|/*BlackCat64.sys|image=winedevice.exe`. The
  default policy only audits `winebth.sys` and `wineusb.sys` (`rights=execute`) for that reason.
- **WMI** is served inside the program by Wine's `wbemprox.dll`, which reads the real sources
  (DMI files, the registry, device requests). Refuse the sources (the default policy denies
  DMI), or WMI as a whole: `deny|file|/*/wbemprox.dll|rights=execute` or a registry deny on
  `\REGISTRY\MACHINE\SOFTWARE\Classes\CLSID\{4590F811-1D3A-11D0-891F-00AA004B2E24}` (the
  `WbemLocator` class). A single query class is refused with `deny|system|/system/wmi/<class>`
  (see the `system` target below).
- **`/proc/<pid>`** is named by whose process it is: `/proc/@self`, `/proc/@family` (another
  protected program), `/proc/@wine` (a Wine process or wineserver outside the family) or
  `/proc/@outside`.
- **Rule-only targets** (ABI 9): `peer`, `thread-peer`, `system`, `dns` and `thread` are
  decided only where a rule names them; a spent counted allow (`uses=N`) refuses. `hide` on a
  deny rule makes its refusals fail with `ENOENT`.
  - **`peer` and `thread-peer`**: one protected Wine program reaching another (path: the
    other program's Windows image; `image=`: the requester; rights: process or thread access
    names). Decided on `open_process`, `open_thread`, `get_next_*` and `dup_handle` inside the
    family, and on each request through a handle to any other Wine program kfilter tracks,
    protected or not (`explorer.exe`, `services.exe`, `winedevice.exe` too; a handle to an
    outside program is also decided when it is made, as `open`): `read_process_memory`
    (`vm-read`), `write_process_memory` (`vm-write,vm-operation`), `queue_apc`
    (`CreateRemoteThread`: `create-thread`; `VirtualAllocEx`/`ProtectEx`, views:
    `vm-operation`; `VirtualQueryEx`: `query-information`; remote `DuplicateHandle`:
    `dup-handle`; `QueueUserAPC`: `set-context`), `get_thread_context` (`get-context`),
    `set_thread_context` (`set-context`), `suspend_thread`/`resume_thread`,
    `suspend_process`/`resume_process`, `debug_process` (`suspend-resume`), `terminate_*`
    (`terminate`), `get_process_info`, `get_process_image_name`, `get_process_vm_counters`,
    `get_process_debug_info` (`query-limited-information`), `get_mapping_filename`
    (`GetMappedFileName`: `query-information`), `set_process_info` (`set-information`) and
    `open_token` (`OpenProcessToken`: `query-information`; `OpenThreadToken`:
    `query-information` of the thread). A refusal fails the request (Wine:
    `STATUS_ACCESS_VIOLATION`). A rule without `rights=` refuses every request to that
    program decided by process or thread rights, also kinds of access a later version decides that way
    (`kfilterctl check` warns), never the window, message and input decisions or the ones `value=` alone
    names (below); give it the rights it is for. Examples: `deny|thread-peer|C:\*\MapleStory.exe|rights=get-context|image=grap-core64.aes`,
    `deny|peer|C:\*\explorer.exe|rights=vm-read|image=grap-core64.aes`.
    Through a handle to a process kfilter cannot name (one from `NtGetNextProcess`, or not
    seen made), `read_process_memory`, `write_process_memory`, `get_thread_context` and
    `set_thread_context` are decided when wineserver reaches the target's task for them
    (`process_vm_readv`, `ptrace`), by the program that task runs; a refusal fails
    wineserver's call (`EPERM`; Wine: `STATUS_ACCESS_DENIED`) and the decision is `brokered`.
    It is decided once per request: wineserver's later reaches for the same request (Wine 11
    falls back from a refused `process_vm_readv` to `ptrace` and `/proc/<pid>/mem`) meet the
    same verdict without another event.
    Every other request through such a handle (`VirtualQueryEx`, `GetMappedFileName`, process
    queries, suspension...) is decided at once on the placeholder program `\@unknown` (peer, or
    thread-peer for a thread handle): only a rule naming it (`deny|peer|\@unknown|...`) meets
    it; wildcard rules (`\*`) and rules naming programs never do, so a policy written before it
    meets exactly what it met before (these requests were not decided then; `kfilterctl check`
    warns of a pattern that matches `\@unknown` without naming it). When wineserver's
    reply to a `get_process_info` (`NtQueryInformationProcess`, `GetProcessId`) or
    `get_thread_info` through such a handle names its process, that process serves `addr=`
    rules alone: module ranges are found in its table, and after an allowed `\@unknown`
    decision a request that reaches memory is decided again on that program, by `addr=` rules
    only; every other rule still meets requests through the handle on `\@unknown` alone.
  - **What a request reaches past its own decision** (ABI 11), decided after it (once it is allowed), each kind
    only by rules naming it, so a rule written before it meets exactly what it met:
    - Another program's **windows and threads**, as `peer` decisions on the program owning them, by the
      pseudo-rights `window-query` (`get_window_info`, `get_window_text`, `get_window_tree`, rectangles, regions,
      properties, layered and class info, `is_window_hung`, `get_windows_offset`, `get_thread_desktop`),
      `window-set` (`set_window_pos`, `set_window_info`, `set_window_text`, `set_parent`, `set_window_owner`,
      `destroy_window`, z-order, redraw, regions, properties, the foreground, focus, active window, caret,
      `set_class_info`), `window-message` (`send_message`: `SendMessage`, `SendMessageTimeout`,
      `SendNotifyMessage`, `PostMessage`, `PostThreadMessage`) and `input` (`register_hotkey`,
      `unregister_hotkey`, `set_capture_window`, `attach_thread_input`, `get_thread_input`). `value=` names
      the message (`send_message`), the `GetWindowLong` or class offset, or the hotkey's key, as 0x%08X:
      `deny|peer|C:\*|rights=window-message|value=0x0000004A|image=grap-core64.aes` refuses `WM_COPYDATA` to
      every program. Only a rule naming one of these rights by name meets them (kfilterctl marks it): a rule
      without `rights=` meets exactly the handle accesses it met before and none of these, nor does one with a hex
      mask (`rights=0x1fffff`) or naming only process rights; a rule naming only these meets no handle access.
      Their bits are the generic rights' (0x10000000 `input`, 0x20000000 `window-query`, 0x40000000
      `window-set`, 0x80000000 `window-message`, the event's value), which no process or thread access decision
      carries. A message goes to the thread its id names
      (wineserver delivers by it, not by the window), found from the ids `init_first_thread` and `new_thread`
      replies gave; a window is found by the low 16 bits of its handle (as wineserver finds it, a high word of 0
      or 0xFFFF at any generation) in an owner map `create_window` replies fill for every Wine program. A
      request naming two windows (`set_parent`, `set_window_owner`, `get_windows_offset`) or two threads
      (`attach_thread_input`) is decided on each other program's, the changed one first. The requester's own
      windows and the desktop's (no program's) are no decision when kfilter saw them made. A window kfilter
      cannot place (made before kfilterd started or before a new wineserver, a stale generation, an owner that
      exited) is `\@unknown-window`, a thread `\@unknown-thread`: only deny and audit rules naming it with a
      pseudo-right meet it (an allow there is not loaded: it cannot vouch for a window it does not know; a rule
      there without a pseudo-right meets nothing; `kfilterctl check` warns of both); wildcard rules never do.
      This includes the requester's own windows and threads kfilter did not see made: at the first start of a
      kfilterd with this map, every window the running game made, so a deny of `\@unknown-window` scoped to a
      protected program can refuse that program's own window requests (`check` warns). The owner map is shared
      by every Wine prefix and forgotten when a wineserver starts. Wine changes another program's window (its
      position, its window long) by a message to the owner's thread (`WM_WINE_*`, 0x8000000N), not by the
      request: `value=0x8000000*` with `window-message` names those.
    - A **process or thread handle at any offset**: `assign_job` and `process_in_job` (the process at 0x10),
      `new_thread` in another program, `get_thread_info`, `get_thread_times`, `cancel_sync`,
      `get_process_idle_event`, `make_process_system`, `grant_process_admin_token`, as `peer` or `thread-peer`
      decisions with the access wineserver asks of the handle (for `get_thread_info` the query rights asked, or
      `query-limited-information` when none are, as Wine's own `NtQueryInformationThread` asks), met only by
      rules whose `value=` names the request: `deny|thread-peer|C:\*\MapleStory.exe|value=get_thread_*|image=grap-core64.aes`.
      A handle kfilter cannot name is `\@unknown`, as above; one to the program's own child that has not started
      yet (its first thread, which `CreateProcess` makes before the child starts, the job Chromium puts it in) is
      no decision.
    - `value=` on `peer` and `thread-peer` rules otherwise names `get_thread_context`'s flags on another
      program's thread: `deny|thread-peer|C:\*\MapleStory.exe|rights=get-context|value=0x00000010` refuses only
      the debug-register read (not the late decision through a handle kfilter cannot name). `value=` matches
      the whole value: `0x00000010` is a read of the debug registers alone; `0x0000001*` also one asking for
      more of the first registers.
  - **`addr=`** (ABI 10) narrows a `peer`, `thread-peer` or `system` rule to memory: it meets
    only a decision on memory that overlaps one of its ranges (an allow: that lies within
    them), so one location is refused instead of every access of that kind. Up to 16 comma-separated ranges per rule, each
    `0xLOW-0xHIGH` (absolute, inclusive, hexadecimal; `0x` optional; one address is one byte)
    or `MODULE+0xLOW-0xHIGH` (offsets from the image base of `MODULE`, a file name pattern, in
    the target program); the ranges of one rule may name different modules. Examples:
    `deny|peer|C:\*\MapleStory.exe|rights=vm-read|addr=MapleStory.exe+0x1000-0x1FFF|image=grap-core64.aes`
    (the anti-cheat may read the rest of the game, not that page),
    `deny|peer|C:\*\MapleStory.exe|rights=vm-write,vm-operation|addr=0x140000000-0x14FFFFFFF`,
    `deny|thread-peer|C:\*\MapleStory.exe|rights=set-context|addr=MapleStory.exe+0x1000-0x1FFF`
    (no hardware breakpoint there), `deny|system|/system/wine/self/read_process_memory|addr=0x10000-0x1FFFF`
    (a program reading itself through Wine).
    - Decisions that carry an address: `read_process_memory` and `write_process_memory`
      (address and size); `queue_apc` system APCs into another process: `VirtualQueryEx` (one
      byte), `VirtualAllocEx` and `MapViewOfSection` at a chosen address, `VirtualFreeEx`,
      `VirtualProtectEx`, `FlushInstructionCache`, `VirtualLock`/`UnlockEx`, `UnmapViewOfSection`
      (one byte at the view); `get_mapping_filename` and `get_image_view_info`
      (`NtQueryVirtualMemory` MemoryImageInformation), one byte; `set_thread_context` with debug
      registers (each enabled DR0-DR3, its length from DR7); the late decisions on a handle
      kfilter cannot name; and native access inside the family: a member's own
      `process_vm_readv`/`process_vm_writev` into another (the first 8 remote iovecs) and its
      `read`/`write`/`pread64`/`pwrite64` of another member's `/proc/<pid>/mem` (its own
      `/proc/self/mem` is decided as `/system/wine/self/read_process_memory` or
      `write_process_memory`), and a member's ptrace attach (or seize) to another, after which
      it can read and write any address and debug register: a peer and a thread-peer decision
      with every right on an unknown address. `get_image_view_info` and the native access were
      never decided before: only `addr=` rules meet them, with or without
      `block-process-memory` (Yama's ptrace scope 1 already refuses native access between
      programs that are not parent and child).
    - Any other decision (`open_process`, `get_process_info`, a user APC, a context that
      enables no debug register) never meets an `addr=` rule, and rules without `addr=` decide
      exactly as before.
    - Fail closed: an unknown address (an unreadable iovec, more than 8, a ptrace attach, a
      free or map of a whole region, a context or memory APC whose address lies past the first
      chunk of a request split over several writes, a `/proc/<pid>/mem` access by `readv` or
      io_uring, no room to record what a decision reaches) matches deny and audit rules, never
      allow rules; so does a module range when the target's module table is not known or not
      current. A module the current table shows absent does not match (the rule's other ranges
      still can).
    - Module tables: kfilterd reads `/proc/<pid>/maps` of protected Wine programs only: the
      image base and SizeOfImage of every image view of a PE file (mapped at offset 0, with code
      within SizeOfImage), Wine's own DLLs included; a view of the whole file (`MapViewOfFile`,
      `LoadLibraryEx` as a data file, as `GetFileVersionInfo` does) is data, not a module. On any
      other target (and on `\@unknown` without a process a reply named) a module range is
      unknown. The lag window: a table is stale from the moment Wine registers an image view of
      its program (`map_image_view`, `map_builtin_view`: a DLL or EXE load) until kfilterd has
      reread it, about 50 to 250 ms later (longer while kfilterd is busy); code made executable
      (JIT, unpacking), data views and protection changes leave it current. A module just
      loaded is not in it between its mapping and that registration (well under a
      millisecond), so its ranges match nothing then. A policy whose module patterns change
      leaves every table stale until it is reread; an unloaded module keeps its base until the
      next reread. A pattern matching several modules means the lowest-addressed; a range past
      SizeOfImage is cut there. An image Windows code mapped itself, not from a file, has no
      entry.
    - Containment for allows: an `allow ...|addr=` decides an access only when each range it
      reaches lies within one of the rule's ranges; a deny or audit decides any access that
      overlaps one. An allow carved out of a later deny never lets the deny's bytes through
      (an access touching both is the deny's).
    - The event of a decision an `addr=` rule made names what was reached after the program's
      path: ` addr=0x<16 hex digits>+<bytes>` for its first range (`,...` when it reached more,
      `?` for an unknown part); msmon's `kfilter_decision` record shows it, and its rule text
      shows `addr=`. Other rules' events on the same requests keep the bare path.
    - Capacity: the ranges live beside the rule (one rule slot however many); at most 1024
      `addr=` rules in a policy, whose modules count against the 32 `module=` patterns (after
      them: an `addr=` rule never moves a `module=` rule's pattern). Offline (`kfilterctl
      simulate`, `evaluate`) and without the BPF layer an `addr=` rule never matches; block mode
      refuses it there. The plain loads and stores a program makes in its own memory cannot be
      decided by any hook.
  - **`system`**: every wineserver request a protected program writes is `/system/wine/<request>`
    (its name in Wine's protocol: `send_message`, `set_hook`, `get_clipboard_data`,
    `assign_job`, `lock_file`, ...), decided only where a `system` rule names it past
    `/system/wine/`: the literal path (`deny|system|/system/wine/set_hook|image=grap-core64.aes`),
    or a pattern whose fixed text reaches into the name (`/system/wine/get_key*`). A rule with a
    star right after `/system/wine/` or sooner (`/system/wine/*`, `/system/*`), or on
    `/system/wine` or `/system` itself, never meets these: refusing `select`, `get_message`,
    `close_handle` or `init_thread` stops a program, and only a rule naming them should
    (`kfilterctl check` warns about broad rules there). Rights by name: `query` for
    `get*`, `query*`, `enum*`, `list*`, `is_*`, `find_*`, `check_*`, `compare_*` and `open_*`,
    `create` for `create_*`, `write` for the rest. The request's other decisions (registry, NT
    object, handle, volume) follow when it is allowed. `init_first_thread` is not decided (its
    reply names the process to kfilter); a request no rule names costs one map lookup, plus, for a
    protected program's request with data, reading its chunks' sizes. A program
    can chunk a request's data as it likes (`wine_server_call` is exported): the chunks are
    joined before a name is read (the first 4 KiB; a name past them, behind a large security
    descriptor, is joined from its own offset), and a write whose chunks do not add up to
    the request's size is refused as one Wine never makes (below).
    The requests decided before every request was, with their own targets and rights:
    `list_processes`,
    `get_system_handles`, `get_tcp_connections`, `get_udp_endpoints`, `get_window_list`,
    `get_window_tree`, `get_window_text`, `get_directory_entries`, `query_symlink`,
    `open_winstation/<name>` and `open_desktop/<name>` (`query`),
    `open_token` on its own process or thread (rights `query`), `adjust_token_privileges` and `set_thread_info` with
    ThreadHideFromDebugger (`write`); named objects as
    `/system/wine/<create_|open_><event|mutex|semaphore|mapping|directory|symlink>/<name>`
    (`create`, `query`; the name as given, relative to its root directory such as
    `\BaseNamedObjects`, case-sensitive; unnamed creates are not decided; a named section
    (`mapping`) allowed here is then also a `file` decision on its full NT name, see
    `block-files` above); and the
    per-handle requests above on the program's own threads or process through a real handle.
    Through `GetCurrentProcess()` or `GetCurrentThread()` they are
    `/system/wine/self/<request>` instead (same rights), so a rule such as
    `deny|system|/system/wine/get_thread_context` never meets Wine's own requests on itself;
    decided only while a `system` rule names `/system/wine/self` itself (a broad `/system/wine/*`
    does not turn it on, but matches them once such a rule exists). Example:
    `deny|system|/system/wine/self/read_process_memory|image=grap-core64.aes`.
    Keys (ABI 11): after a request's own decision on `/system/wine/<request>` (which keeps its rules, path and
    event text), these requests are decided again on a keyed path, which only rules whose fixed text reaches past
    `/system/wine/<request>/` meet (not one on the bare request, exact or not, nor a broader pattern):
    `set_hook/<WH id>/<global|process|thread>` (`deny|system|/system/wine/set_hook/13/global`: no low-level
    keyboard hook), `get_key_state/<0x vkey, 8 lowercase hex digits|all>`,
    `send_hardware_message/<injected|hardware>/<keyboard|mouse|hid>` (`SendInput` is injected; `value=` the
    key), `set_cursor/<pos|clip|show>` (one decision for each it does), `update_rawinput_devices/<inputsink|normal>`,
    `get_clipboard_data/<format>`, `ioctl/<NT name>/0x<code>` and `read/<NT name>`, `write/<NT name>` (the handle
    named by its open, also a `create_file` while such a rule exists, `@unknown` otherwise; a volume's identity
    ioctls: `deny|system|/system/wine/ioctl/\??\C:/0x002d1400`), `new_process/<child image>` with
    `/spoofed-parent` (a parent handle given) and `/debug` (under a debug object), `@unknown` for an image that
    cannot be read. On a named pipe whose bind kfilter saw, a DCE/RPC call by `write` or
    `FSCTL_PIPE_TRANSCEIVE` is `/system/rpc/<interface uuid>/<opnum>`
    (`deny|system|/system/rpc/367abb81-9844-35f1-ad32-98f038001003/19`: svcctl's `RStartServiceW`; the first
    context of the pipe's bind, little-endian PDUs). Paths match case-sensitively: write hex lowercase.
    `value=` on `system` rules (ABI 11) names `get_thread_context`'s flags (`value=0x00000010`: the
    debug-register check), `register_hotkey`'s key, `get_volume_info`'s class (every class), each privilege of
    `adjust_token_privileges` (its LUID: `value=0x00000014`, SeDebugPrivilege, wherever it lies in the request)
    and `set_thread_info`'s mask (`value=0x00000001`, its priority; without ThreadHideFromDebugger these are
    decided by `value=` rules alone); a rule without `value=` decides these requests as before. `value=` matches
    the whole 0x%08X text, a mask exactly: `value=0x00000010` on `get_thread_context` misses a read asking for
    more registers (0x0000001F, 0x0000003F): name each mask, or a pattern (`value=0x0000001*` for 0x10
    to 0x1F). These requests were decided before by their own
    rules alone, so a `value=` rule on them that kfilter accepted but never met (it carried no value) meets them
    now.
  - **`system`**, the program's syscalls (refusals are `EPERM` or `EACCES`; Wine starts with any
    of them refused):
    - `/system/uname` and `/system/sysinfo` (`query`; x64 and int 0x80 entries). Wine reads the
      Windows host name from the prefix registry, not from uname.
    - `/system/socket/<family>/<type>/<protocol>` (`create`): `unix`, `inet`, `inet6`,
      `netlink` and `packet`, `stream`, `dgram`, `raw` and `seqpacket` by name, the rest by
      number, e.g. `/system/socket/netlink/raw/15` (the udev monitor), `/system/socket/inet/raw/1`
      (ICMP). wineserver's sockets for the program are the program's.
    - `/system/memfd/<name>` (`create`, plus `execute` with `MFD_EXEC`), `/system/userfaultfd`
      (Wine falls back without it), `/system/io_uring` (a ring; what it then opens and reads is
      decided as the program's own), `/system/secretmem` (memfd_secret), all `create`.
    - `/system/keyring/<type>/<description>` (e.g. `keyring/_ses`): every key and keyring
      keyctl, add_key and request_key reach; `write` for write, link, setattr and unlink,
      `read` otherwise. A keyring the program makes for itself is not decided.
    - `/system/ipc/<shm|msg|sem>/<key, 8 hex digits>` (`00000000` for `IPC_PRIVATE`): each use
      of a SysV object (get by key, attach, send, receive, op, stat), `read` and/or `write` as
      asked; creating one is not decided. The attach itself is also a mapping of
      `/anon/SYSV<key>`.
    - `/system/arch_prctl/0x<option>` (`0x1011` `ARCH_GET_CPUID`): `query` for the gets, `write`
      otherwise. Wine sets FS/GS through it on each thread. `ARCH_SET_CPUID` names its
      argument: `/system/arch_prctl/0x1012/0` turns CPUID faulting on (what `launch --trap-cpuid`
      does in each process), `/0x1012/1` turns it off, so `deny|system|/system/arch_prctl/0x1012/1`
      keeps the trap armed.
    - `/system/sched` (`write`): `sched_setaffinity`, `sched_setscheduler`, `sched_setparam` and
      `sched_setattr` on any task, `/system/sched/nice` (`setpriority`) and `/system/sched/ioprio`
      (`ioprio_set`); wineserver's for the client it serves (Wine's `SetThreadAffinityMask`,
      thread priorities) are the client's. A rule on `/system/sched` covers all three.
    - `/system/sockopt/<level>/<optname>`: `getsockopt` (`query`) and `setsockopt` (`write`),
      level `socket`, `ip`, `ipv6`, `tcp`, `udp` or its number, the option by number, e.g.
      `/system/sockopt/socket/4` (`SO_ERROR`), `/system/sockopt/tcp/1` (`TCP_NODELAY`);
      `/system/sockname` and `/system/peername` (`query`): `getsockname`, `getpeername`.
      wineserver's on the program's sockets are the program's. Example:
      `deny|system|/system/sockopt|rights=write|image=grap-core64.aes`.
    - `/system/mount` (`write`): `mount`, `umount`, `pivot_root`, `move_mount`;
      `/system/syslog`: the kernel log (`syslog`, `/dev/kmsg`), `query` to read it or its size,
      `write` to clear it or set the console; `/system/time` (`write`): setting the clock
      (`clock_settime`, `settimeofday`, an `adjtimex` that changes it). The kernel refuses all
      of them to an unprivileged program anyway; the decision records the attempt.
    - `/system/map<path>`: a file the program maps into memory (`mmap`; under Wine
      `MapViewOfFile`, `NtMapViewOfSection`, its DLL and image views), `execute` for code,
      `read` for data, plus `write` for a shared writable view, e.g.
      `/system/map/home/u/.wine/drive_c/Nexon/Library/maplestorycw/appdata/MapleStory.exe`.
      Every mapping, also within an open that was allowed (the `file` decision counts an open's
      rights once); decided only while a `system` rule names `/system/map` itself (not a broad
      `/system/*`), so a program's mappings cost nothing otherwise; a broad rule then matches
      them too. A path of 496 bytes or more passes undecided. A refusal
      fails the `mmap` with `EPERM` (Wine: the view fails). Example:
      `deny|system|/system/map/*/maplestorycw/appdata/*|image=grap-core64.aes`.
    - `/system/memory/<private|shared|image>/<rx|rwx>` (`execute`): anonymous memory the
      program maps executable or makes executable (`mmap`, `mprotect`, `VirtualAlloc`/
      `VirtualProtect` under Wine), or writable while executable. `shared` is
      `MAP_SHARED|MAP_ANONYMOUS`; `image` lies inside a PE image Wine mapped (a section of an
      image whose file alignment is under a page, which Wine copies into anonymous memory:
      deny `private` without breaking such images); `private` is everything else (JIT, unpacked
      or injected code). Example: `deny|system|/system/memory/private|image=MapleStory.exe`.
      Classified only while a `system` rule can name `/system/memory/`. A refusal fails the
      call with `EPERM`; under Wine `VirtualProtect` fails, while a `VirtualAlloc` that asks for
      executable memory still returns it, inaccessible (Wine ignores its failed `mprotect`).
      Chromium/V8 (the launcher UI) and .NET JIT need `private`.
    - `bpf()` and `perf_event_open` stay refused with no rule, as before.
    - `/system/syscall/<name>[/<key>]` (ABI 11): every syscall of both x86 tables, the program's
      own (wineserver's and winedevice's while serving it are not), `query` for the ones that only
      read (`get*`, `stat*`, `uname`...) and `write` otherwise, rule-only; a refusal fails the call
      with `EPERM`. An ia32 call (a 32-bit program, or `int 0x80` from a 64-bit one) carries its
      x86_64 name where it has one, as msmon records it: `fcntl64` is `fcntl`, `futex_time64`
      `futex`, `mmap2` `mmap`, `getuid32` `getuid`; ia32-only calls keep theirs (`sigaction`,
      `signal`, `waitpid`). ia32's `socketcall` and `ipc` are the call they carry
      (`socketcall(SYS_CONNECT)` is `connect`, `ipc(SHMDT)` `shmdt`, a socket call's key read from
      its argument block), so a rule on `connect` meets the 32-bit family's connects too; one with
      a call number neither names stays `socketcall` or `ipc`. The table is generated from this
      kernel's syscall tables and BTF (`filter/tools/gen_syscalls.py` writes
      `linux/bpf/kfilter_syscalls.h`); calls that never return (`exit`, `exit_group`) are left out,
      and so are the ones this kernel does not implement (`rseq_slice_yield`, i386 `uselib`).
      `kfilterctl check` warns about a name neither table has. Like the vDSO's, the legacy
      vsyscall page's `gettimeofday`, `time` and `getcpu` enter no syscall and are not decided.
      - Keys: the signal (`rt_sigaction/5`: a SIGTRAP handler; `sigaction`, `signal`, `kill`,
        `tkill`, `tgkill`, `rt_sigqueueinfo`, `pidfd_send_signal`), `how` (`rt_sigprocmask`), the
        command (`fcntl/6` is `F_SETLK`; `keyctl`, `prctl`, `ptrace`'s request, `seccomp`'s
        operation, `futex`'s without the private and clock flags), the advice (`madvise`,
        `fadvise64`, `process_madvise`), the clock (`clock_*`, `timer_create`), `who`/`which`
        (`getrusage/-1`, `getpriority`, `setitimer`), the number of descriptors (`poll`, `ppoll`,
        `select`, `pselect6`), the socket family (`socket`) and, as `0x<hex>`, flags
        (`getrandom/0x1`, `dup3`, `pipe2`, `eventfd2`, `timerfd_create`, `signalfd4`,
        `epoll_create1`, `inotify_init1`, `memfd_secret`, `pidfd_open`, `close_range`, `clone`,
        `unshare`, `setns`, `landlock_*`), the persona (`personality/0x800000`: clearing UNAME26
        defeats `launch --uname26`) and `ioctl`'s command; `wait4/any|child|group` and
        `waitid/...` by whom they wait for. Every other call has no key: `/system/syscall/getpid`.
        An ia32 call's key is the x86_64 call's: `fcntl64`'s `F_GETLK64`, `F_SETLK64` and
        `F_SETLKW64` are `fcntl/5`, `/6` and `/7`, the old `select` takes `nfds` from its argument
        block; `ioctl`'s command is each ABI's own number.
      - `addr=`: `munmap`, `mremap` (its old range), `msync`, `mlock`, `mlock2`, `munlock`,
        `mbind`, `pkey_mprotect`, `mprotect`, `madvise`, `remap_file_pages` and `mseal` reach
        `[address, address + length)` of the program's own memory, so `deny|system|/system/syscall/munmap|addr=MapleStory.exe+0-0xFFFFF`
        keeps a range mapped; rules without `addr=` meet them as any other.
      - Only rules naming the space meet these decisions: `/system/*`, `/system/sys*` or a literal
        `/system` written for the older decisions never do; `/system/syscall/*` does once a call
        is decided. `block-direct-syscall` refuses them as any other decision (`DIRECT`).
      - Attached on demand: each call is decided by an fmod_ret on its entry point
        (`__x64_sys_<name>`, `__ia32_sys_<name>` or the `__ia32_compat_sys_<name>` the ia32 table
        enters; a zero-argument call's `__do_sys_<name>` serves both tables), which kfilterd
        attaches only while a `system` rule names that call: a literal
        `/system/syscall/<name>[/...]` or a wildcard whose fixed head reaches into the name
        (`/system/syscall/rt_sig*`). `/system/syscall/*`, `/system/*` and `/system/syscall`
        attach nothing. An attached call costs **every process on the system** a trampoline on
        each call (for any task but a protected program's the decision returns at once), and a
        rule naming a call stays attached until no rule names it; a policy naming none attaches
        none. A protected program's call (or key, for a call with one) that no rule of the policy
        in force names returns after one lookup of what the rules name (`kb_syscall_keys`); one
        a rule names is a full decision (about 1.5 us of decision work in the bench before the
        caller's stack walk), on every such call. kfilterd holds a descriptor per entry point
        (about 780; it raises its open-file limit). An entry point this kernel lacks, or whose
        prototype is not the one the decision program was built for, is left unloaded and a rule
        naming its call reports the `system` class degraded (block mode is refused), never
        silently undecided. A kfilterd taking a pinned layer over keeps its entry points until
        the policy it adopts attaches its own.
      - Hot calls: `futex`, `poll`, `ppoll`, `select`, `pselect6`, `rt_sigprocmask` and
        `sigprocmask` run all the time in every Wine process (MapleStory: 33.7 million
        `rt_sigprocmask` and 400,000 `futex` in 4.6 minutes). A rule on one must name its argument
        (`deny|system|/system/syscall/futex/9|image=...`: `FUTEX_WAIT_BITSET`); `kfilterctl`
        refuses `/system/syscall/futex` and `/system/syscall/futex/*`, and in the kernel no rule
        that does not name the argument meets them, because a deny of every call stops Wine (its
        waits and signal masks fail).
      - Wine's channel to wineserver: its requests and replies are `read`, `write`, `readv`,
        `writev`, `recvmsg`, `sendmsg` and `close` calls, so a deny of one of them ends the Wine
        process (only `EFAULT` is a refusal Wine survives there), and each one a protected program
        makes is a decision while a rule names it: `kfilterctl check` warns about such rules.
  - **Decisions added in ABI 11** (hooks kfilter did not use, and finer decisions in the ones it did). None of them
    was made before, so a policy written before them decides exactly as it did: each is rule-only, a hook makes it
    only while some rule names its space or right (kfilterd keeps one bit per kind, so a policy naming none of them
    costs nothing more and `block-direct-syscall` refuses nothing more), and only rules naming it meet it. A hook of
    these that does not attach takes away only its kinds: block mode is refused for a policy naming one of them (or
    `block-process-signals`, for the SIGIO hooks), not for the others:
    - a new space is met only by rules whose path names it past its root: `/system/*`, `/system/f*` or a literal
      `/system` (written for the older decisions) never meet `/system/fcntl/...`; `/system/fcntl/*` does;
    - the new rights `lock`, `chdir` and `touch` (file and dir rules) lie outside the every-right default of a rule
      without `rights=`, and a `pipe` deny without `rights=` covers every right but `listen`;
    - a peer decision of a new kind (a signal, a `PTRACE_MODE_READ` check, a SIGIO) is met only by `peer` rules whose
      `value=` names one (`rights=terminate|value=signal:0x00000013`: SIGSTOP; `value=ptrace:0x00000009`), not by one
      with another `value=` (a window message's number); a `peer` rule without `rights=` or `value=` keeps meeting
      exactly the Wine requests it met. A rule naming a signal or mode meets nothing else, so `kfilterctl check` asks no
      `rights=` of it: no Wine request on the program, no window, message or handle-offset decision; and no `value=`
      rule of those kinds (`value=*` included) meets a signal, SIGIO or READ decision. Its `rights=` still narrow it (a
      signal asks `terminate`, a probe `query-limited-information`, a READ check `query-information`): `check` warns of
      one whose `rights=` exclude that, whose `value=` cannot match `signal:0x%08X` or `ptrace:0x%08X` (`signal:10`),
      that names a pseudo-right, or that is a `thread-peer` rule (signals and READ checks are decided on a process).
    - Locks: `fcntl` `F_SETLK`/`F_SETLKW`/OFD locks and `flock` on a file or directory (wineserver's `LockFile` for the
      program is the program's) are a `file` or `dir` decision on its path, right `lock`, value `F_RDLCK` or `F_WRLCK`
      (unlocks are not decided): `deny|file|/home/*/.wine*/*.lock|rights=lock|value=F_WRLCK`.
    - `/system/fcntl/<setown|setown_ex|setsig|setlease|notify|add_seals>` (`write`): the `fcntl` commands that send
      signals or change a file's reach.
    - SIGIO: the signal a file raises for the processes its owner names (`F_SETOWN`, `F_SETOWN_EX`, `FIOSETOWN`,
      `SIOCSPGRP`; `F_SETSIG`'s signal, else SIGIO) is decided as a signal its owner's setter sends (see signals below):
      when the owner is set (the `fcntl` or socket `ioctl` fails with `EPERM`; a process group is decided by its
      leader, one whose leader exited not at all), and again when a task raises it (a pipe or tty write). One a
      socket's softirq raises is not decided when sent (no task's working memory may be used in an interrupt): its
      owner's setup was.
    - `/system/socket/shutdown/<rd|wr|rdwr>` (`write`); `/system/socketpair/<family>/<type>/<protocol>` (`create`;
      each socket's own creation is `/system/socket/...` as before).
    - An AF_UNIX connection or datagram reaching a socket a protected program made (squatting a name others use) is
      that program's `pipe` decision on its address (`/@name` or its path), right `listen`, from anyone.
    - `/system/rlimit/<resource>[/other]` (`cpu`, `nofile`, `memlock`...; `write`, `query` for a read of another's):
      `setrlimit` and `prlimit64` on the program itself, `/other` for `prlimit64` on another process.
    - `/system/task/<getscheduler|getioprio|getpgid|getsid|setpgid>` (`query`; `setpgid` `write`) on a task of
      another process (its own are not decided).
    - `/system/cred/<setuid|setgid|setgroups|capset|capget>` (`capget` `query`, the others `write`).
    - `/system/capability/<name>` (`sys_admin`, `net_raw`...; `query`): a capability check on the program's own
      credentials. A refusal fails the call as if the capability were missing (`EPERM`). The kernel checks
      capabilities very often: decided only while a rule names `/system/capability`.
    - `/system/namespace/user` (`create`): a new user namespace (`unshare`, `clone`); `/system/memory/low`
      (`create`): a mapping placed below `mmap_min_addr` (the kernel already refuses one without `CAP_SYS_RAWIO`).
    - `/system/ipc/create/<shm|msg|sem>/<key>` (`create`): creating a SysV object (its uses are
      `/system/ipc/<kind>/<key>` as before, which `/system/ipc/*` keeps meeting).
    - `/system/fork` (`create`): a process the program creates without a thread (`fork`, `vfork`, `clone`; its exec
      is decided apart). Wine's `CreateProcess` forks twice.
    - `/system/ptrace/traceme` (`write`): `ptrace(PTRACE_TRACEME)`.
    - `/system/kernel/module/<name>` (`create`): a module the kernel loads for the program (a `socket()` of an absent
      family runs modprobe; a refusal fails that call); `/system/kernel/load/<module|firmware|kexec-image|...>`
      (`create`): data handed to the kernel from a buffer (`init_module`). Loads from a file stay refused with no rule.
    - `/system/prctl/0x<option>` (4 hex digits, 8 past 0xFFFF; `query` for the gets, `write` otherwise): every option
      but `PR_SET_MM`, which stays refused with no rule. `deny|system|/system/prctl/0x001a` keeps the launch's RDTSC
      trap armed (`PR_SET_TSC`); `0x000f` is `PR_SET_NAME`, `0x0016` `PR_SET_SECCOMP`.
    - Signals (`kill`, `tgkill`, `tkill`, `pidfd_send_signal`, `rt_sigqueueinfo`): one inside the family is a `peer`
      decision on the target program, right `terminate`, value the signal as `signal:0x%08X` (a `kill(pid, 0)` probe:
      right `query-limited-information`, value `signal:0x00000000`), met only by peer rules naming one, its event the
      target program followed by ` signal=0x00000013`; one into the family
      from outside, and a probe out of it, need with `block-process-signals` a `handle` (into) or `open` (out) allow
      granting that right (`allow|handle|/usr/bin/bash|rights=terminate|risk=me`; the family's other signals out of it
      stay `block-process-memory`'s). Only signals the sender makes itself: wineserver's (Wine's suspensions, context
      reads and APCs while serving a request, already decided as that request, and its own exits) and winedevice's
      for a client are never decided. With `block-process-signals` on, whatever must still kill the game (the shell,
      a block-testing loop) needs its `handle` allow.
    - `PTRACE_MODE_READ` checks (`kcmp`, `process_madvise`, `move_pages`, `migrate_pages`, `get_robust_list`, and
      opening `/proc/<pid>/environ`, `maps`, `smaps`, `pagemap`, `stack`, `fd`, `exe`...; not the NOAUDIT ones
      `/proc/<pid>/stat` makes on every read): inside the family a `peer` decision, right `query-information`, value the
      mode as `ptrace:0x%08X` (`ptrace:0x00000009`: `PTRACE_MODE_READ_FSCREDS`, a `/proc` file), met only by peer rules
      naming one, its event the target program followed by ` ptrace=0x00000009`; across the family's boundary, with
      `block-process-queries`, a `handle` (into) or `open` (out) allow granting `query-information`. wineserver serving a
      client, and winedevice serving one, check for it; wineserver's own checks outside a request are Wine's.
    - `/system/memory/<private|shared>/<rw|r|none>` (`write`): anonymous memory the program maps (`mmap`; under Wine
      `VirtualAlloc`, `NtAllocateVirtualMemory`) or protects (`mprotect`, `VirtualProtect`, guard pages) without
      execute, reaching `[address, address + length)` of its own memory for `addr=` rules. A mapping is decided where the
      kernel has placed it (`lsm/mmap_addr`), so a mapping without `MAP_FIXED` is decided at its real address, not as
      an unknown one; a `/dev/zero` mapping stays the `file` decision it was. Decided only while a rule names a data
      protection past the kind (`r`, `rw`, `none`, or a wildcard whose fixed text past the kind starts one of them):
      `/system/memory/private/*`, `/system/memory/private` and the `rx` and `rwx` rules (written for executable memory)
      neither meet these nor make them decisions; `/system/memory/private/r*` meets `r` and `rw` (and `rx`, `rwx` as
      before). MapleStory makes about 40,000 such `mprotect` calls in 5 minutes: each is a decision while such a rule
      exists.
    - `/system/statfs<path>` (`query`): `statfs`, `fstatfs` (the `volume` audit event under `block-volume-serial`
      stays as it was). `kfilterctl check` warns about a deny: Wine checks filesystem types with it.
    - Times set to now (`utimensat` with no times, `touch`): a `file` or `dir` decision, right `touch`.
    - `chdir`, `fchdir` (and `chroot`): a `dir` decision, right `chdir`, named by the inode's first alias as `access`
      is (`deny|dir|/home/*/secret|rights=chdir`).
    - TCP Fast Open: a TCP `sendto`/`sendmsg` with a name and `MSG_FASTOPEN` connects without `connect()`, so it is
      the `network` connect decision a `connect()` to that address is (before, only message rules saw it).
    - AF_UNIX servers: a bind to an abstract name (`@/tmp/.X11-unix/X6`, squatting a display), and a `listen` or
      `accept` on any unix socket, are the program's `pipe` decision on `/@name` (or the socket's path), right
      `listen` (`deny|pipe|/@/tmp/.X11-unix/X*|rights=listen`). A bind to a path stays the `file` write on that path
      (`path_mknod`) it was.
    - Netlink: every message no older decision takes is a `device` decision on `/net/netlink/<family>/<type>`
      (`route`, `audit`, `kobject_uevent`, `xfrm`... or the protocol's number; the message type in decimal), value the
      type, rule-only, met only by rules naming the family past its slash: `deny|device|/net/netlink/audit/*`. The
      older `/net/netlink/route` (the four `RTM_GET*` queries) and `/net/netlink/sock_diag` under
      `block-network-adapter` stay as they were (`/net/netlink/route` meets neither `/net/netlink/route/24` nor any
      new path). Generic netlink by family name: looking a family up (`CTRL_CMD_GETFAMILY`) is
      `/net/netlink/generic/<name>` (`nl80211`: a refusal hides the family, so its scans fail), a message to it
      `/net/netlink/generic/<name>/<command>` (kfilterd reads the names from the controller at each policy load; a
      family registered later is named by its id), the controller's other commands `/net/netlink/generic/nlctrl/<n>`.
    - Socket ioctls: every one outside the interface and wireless ones `block-network-adapter` decides as `/net/ioctl`
      is a `device` decision on `/net/ioctl/0x<code>` (8 lowercase hex digits; `0x00008901` `FIOSETOWN`, `0x00008902`
      `SIOCSPGRP`), rule-only, met only by rules naming `/net/ioctl/...` (not the literal `/net/ioctl`).
    - An ioctl's argument: a device ioctl an older decision allowed is decided again with value
      `0x<ioctl>:0x<the first 32 bits its argument points to>` (`?` when unreadable), met only by device rules whose
      `value=` names an argument (has a `:`): `deny|device|/dev/dri/renderD*|value=0xC0106446:0x00000002` (Intel
      `I915_GETPARAM` of one parameter). An allow may name one too. A `value=` over the command alone (`0xC01064*`,
      `*`) never meets it. Its event is the device path followed by ` arg=0x00000002`.
  - **`system`**, calls Wine answers inside the program's own process, through uprobes (no
    request or syscall to decide them by; Linux goes past Windows here, which has no hook for
    win32k):
    - `/system/win32k/<function>` (`query`): a `win32u.so` export Windows code called, such as
      `NtUserGetAsyncKeyState`, `NtUserGetKeyState`, `NtUserGetCursorPos`,
      `NtUserGetForegroundWindow`, `NtUserBuildHwndList` (`EnumWindows`),
      `NtUserFindWindowEx`, `NtUserInternalGetWindowText`, `NtGdiBitBlt`, `NtGdiGetPixel`,
      `NtUserSetWindowsHookEx`, `NtUserGetRawInputData`. kfilterd puts `kb_win32k` on the
      functions the rules name (patterns are expanded against the exports) in the x86_64-unix and
      i386-unix `win32u.so` of each Wine 11 install, so every Wine process on the host gets a
      breakpoint in those functions; for any task but a protected program's it returns at once.
      Only a call through Wine's syscall dispatcher (in `ntdll.so`) is decided, not Wine's own
      calls between its libraries: kfilterd finds the dispatcher in each `ntdll.so` (the function holding its
      one service table selection, bounded by `.eh_frame_hdr`: Wine 11 exports no symbol for it) and the kernel
      compares where the call returns; in an install where it is not found a `win32u.so` call is decided by its
      return into `ntdll.so` (which calls none of them), as before. A refusal returns at once: 0 (`FALSE`, no window, key up), or
      `STATUS_ACCESS_DENIED` for the NTSTATUS ones (`NtUserBuildHwndList`: `EnumWindows` finds
      no window). A function a literal rule names that a `win32u.so` lacks, or a failed attach,
      reports the `system` class degraded. Denying input polling (`GetAsyncKeyState`) breaks
      games that poll keys; screen reads (`NtGdiBitBlt` from the desktop) are the usual deny.
    - `/system/win32k/<function>/<key>` (`query`): after the function's own decision (as above, unchanged), a
      call of a keyed function is decided again on its key, by rules whose fixed text reaches past
      `/system/win32k/<function>/` alone (not a rule on the function, not `/system/win32k/*`), and only while a rule
      names that function's keys: a virtual key for `NtUserGetAsyncKeyState` and `NtUserGetKeyState` (`0x%08x`, 8
      lowercase hex digits as `get_key_state`'s: `0x00000070` is `VK_F1`, `0x0000007a` `VK_F11`; `kfilterctl check`
      warns of an uppercase one, which meets nothing), a clipboard format for `NtUserGetClipboardData` (decimal), a
      hook id for `NtUserSetWindowsHookEx` (signed decimal: `13` `WH_KEYBOARD_LL`, `-1`), and for
      `NtUserInternalGetWindowText`, `NtUserGetClassName`, `NtUserGetDC`, `NtUserGetWindowDC`, `NtUserPrintWindow`,
      `NtUserCallHwndParam`, `NtUserMessageCall`, `NtUserPostMessage`, `NtUserSetWindowLong(Ptr)` and
      `NtUserSetWindowPos` whose window it is, by the window owners kfilter records from wineserver's replies:
      `@self`, `@other` (another program's, or `HWND_BROADCAST`), `@desktop` (the desktop's, or none: the screen) or
      `@unknown` (one kfilter cannot place: made before kfilterd started, a stale handle, another Wine's), which, as
      `\@unknown-window`, only rules naming it meet (no wildcard) and no allow can vouch for (one is not loaded).
      Example: `deny|system|/system/win32k/NtUserInternalGetWindowText/@other` stops reading other programs' window
      titles only; add `.../@unknown` for windows kfilter cannot place. A key cannot let through what the function's
      own decision refuses. What no rule can meet is skipped: a function attached for its keys alone makes no decision
      of its own (nothing attached it before keys existed, so a `/system/*` rule does not meet it), and a call on the
      program's own window or the desktop none while no rule's text can reach its `@self` or `@desktop`.
      `NtUserCallHwndParam` is behind `GetWindowLong`, `GetWindowRect` and `ClientToScreen`, which a game calls every
      frame, and `NtUserMessageCall` behind each `SendMessage`: while a rule names one, each call in every Wine
      process takes the probe's trap (about 1-2 us; `tests/linux_lsm_test.sh` measures it, `HWND_NS_MAX`), and a
      call on the program's own window adds only the return-address check and the owner lookup under a rule on
      `@other`, no rule matching; `kfilterctl check` warns of these probes and of `NtQueryVirtualMemory`'s.
    - `/system/ntdll/<function>[/<class>]`: one of the `ntdll.so` calls Wine answers in-process that msmon probes,
      no other (a probe costs every Wine process a trap a call): `NtQuerySystemInformation(Ex)/<class>` (`5`
      process list, `11` modules, `35` kernel debugger), `NtQueryInformationProcess/<class>` (`7` `DebugPort`,
      `30` `DebugObjectHandle`, `31` `DebugFlags`), `NtSetInformationProcess/<class>`,
      `NtQueryInformationThread/<class>`, `NtSetInformationThread/<class>` (`17` `HideFromDebugger`),
      `NtQueryObject/<class>`, `NtQueryVirtualMemory/<class>` (on the program's own memory, its address for
      `addr=` rules; another process's is its `APC_VIRTUAL_QUERY`, a `peer` decision), `NtGetContextThread` and
      `NtSetContextThread` (`value=` the `CONTEXT`'s `ContextFlags`, `0x%08X`: `0x0010001*` has the debug
      registers), `NtCreateThreadEx` (in another process it is its `APC_CREATE_THREAD`, a `peer` `create-thread`
      decision), `NtQuerySystemEnvironmentValue(Ex)`, `NtQueryLicenseValue`, `NtSystemDebugControl`; classes in
      decimal. Rights: `query`, `write` for the `Set` calls and `NtSystemDebugControl`, `create` for
      `NtCreateThreadEx`. Met only by rules naming `/system/ntdll` (a literal `/system`, `/system/*` do not); a rule
      on the function meets each of its classes. Only Windows code's calls through the dispatcher are decided, never
      Wine's own (its unix side calls several of these, and `win32u.so` asks `NtQuerySystemInformation` at its
      start): in an install whose dispatcher kfilterd does not find, none is (the `system` class degraded while a
      rule names `/system/ntdll`). A refusal returns `STATUS_ACCESS_DENIED`. A deny of a whole call also refuses
      what the program's own runtime asks at start (`kfilterctl check` warns): name the class. Example:
      `deny|system|/system/ntdll/NtQueryInformationProcess/7`.
    - `/system/wmi/<class>` (`query`, the class lowercased: `kfilterctl` lowers these rule paths,
      as WQL classes have no case; `@other` for a query without `FROM` or a path without a class):
      a WQL query through `IWbemServices::ExecQuery` or `ExecQueryAsync`, or an object path or
      class through `GetObject` or `CreateInstanceEnum` (`Win32_BIOS`, `Win32_BIOS=@`,
      `\\<computer>\ROOT\CIMV2:Win32_BIOS`: Wine queries `SELECT * FROM <class>` for them), in
      Wine's in-process `wbemprox.dll` (x64 and i386), refused with `WBEM_E_ACCESS_DENIED` (an
      async query's sink is never called). kfilterd finds the methods through the DLL's DWARF
      vtable and probes them in each protected program that loads it; a uprobe is installed only in code
      that is not writable when it registers, so the program is stopped (`SIGSTOP`) from the
      moment its `wbemprox.dll` code turns executable until the probe is on (a few
      milliseconds). Example: `deny|system|/system/wmi/Win32_ComputerSystemProduct`. Not
      decided: `GetObjectAsync`, `CreateInstanceEnumAsync` and `ExecMethodAsync` (failing stubs in Wine 11).
    - `/system/wmi/<class>/<method>` (`execute`, lowercased): a method call through `IWbemServices::ExecMethod`
      (`Win32_Process.Create`, `Win32_Service.StopService` on an instance path), met only by rules naming a class's
      methods (past `/system/wmi/<class>/`): a rule on the class, or `/system/wmi/*`, meets its queries alone, as
      before methods were decided. Only while such a rule is loaded are methods decided: a method name that is no
      identifier (or a call without an object path) is then a name failure, refused; without one, no call is. Example:
      `deny|system|/system/wmi/Win32_Process/Create`.
    - Only rules whose fixed head lies in these namespaces make the probes: a broad
      `deny|system|/system/*` does not put breakpoints in every Wine process. The `win32u.so` and `ntdll.so`
      probes are pinned with the layer in block mode; the `ExecQuery` ones end with kfilterd. A Windows program
      calling a `win32u.so` or `ntdll.so` function directly (not through its `ntdll.dll` stub) is not decided.
  - **`dns`**: each name the program looks up itself: a query it sends to port 53 (UDP, or
    TCP with the length in the same send), path the queried name lowercase without a leading
    `/` (`wpad`, `*.nexon.com`, any case), value its type (1 A, 28 AAAA), rights `query`. Under
    Wine, Windows lookups resolve through the host's libc inside the program, so each is the
    program's own query to the resolver (`127.0.0.53`). A refusal fails that send with `EPERM`,
    so the name does not resolve (`getaddrinfo` fails). A
    query whose name cannot be read (a compression pointer, more than one question) is a name
    failure, refused in block mode once any `dns` rule exists. Close the side resolvers with
    pipe rules so every lookup takes that path: `deny|pipe|/var/run/nscd/socket`,
    `deny|pipe|/run/systemd/resolve/io.systemd.Resolve`, `deny|pipe|/var/run/avahi-daemon/socket`
    (glibc falls back to its own UDP query). Not seen: DNS over HTTPS or TLS, port 5353/5355,
    and a TCP query whose first send is only its length (glibc's, after the UDP query of the
    same name). Example: `deny|dns|wpad`, `audit|dns|*`.
  - **`thread`**: each thread a protected program creates (`task_alloc`), path its program
    (`EPERM` from `clone`; under Wine `CreateThread` fails).
  - **`module=`** on `system`, `thread` and `dns` rules matches the module whose code made the
    request, found as for message rules (below); on other rules it matches nothing.
- **Direct syscalls.** A decision on a request a Windows program made with its own `syscall`
  instruction, past Wine (a copied ntdll stub, inline assembly, shellcode), carries the
  `direct` event flag (0x2000): the instruction lies in anonymous memory other than the vDSO or
  in a mapped PE image, where Wine's own syscalls come from ELF code. `block-direct-syscall on`
  denies every such decision (file, process, registry, system, dns, thread and connection
  decisions; audit mode logs a would-deny). Wine never makes one itself. Not seen: a syscall
  no hook decides, and an `mprotect`'s own decision (the task holds its memory lock).
  - Not decided: a query (not a memory or context request) through a handle kfilter did not see
    made (inherited by the program, or evicted), or to a process kfilter cannot name (a child
    before Wine starts it, one that has exited, one from `NtGetNextProcess`).
- **Metadata queries (`block-file-queries`, with `block-files`).** stat, access, readlink and
  xattr reads without an open ask for `query`; a change watch asks for `enumerate` (dir) or
  `read` (file).
  - Every file, dir or pipe allow with another right also allows `query` (Wine stats before
    each open), and a deny or audit with `read` also covers `query`. `rights=query` alone
    allows metadata only. Windows decides attributes-only creates as `query` with the same rules.
  - Under `default-deny` the directories above each allow and the `root` are allowed `query`
    (exact, up to the first `*`, after every explicit rule; `kfilterctl policy` marks them
    `implicit`), so realpath walks work. `/` is never decided.
  - A query on an fd whose open was decided (fstat, `AT_EMPTY_PATH`, fgetxattr) is not decided
    again; one on an `O_PATH` or inherited fd, or on the cwd, is decided by path.
  - Queries spend no use of a counted rule. Allowed queries are not logged; refusals, audits
    and would-denies are.
  - A refusal is `EPERM`; with `hide` it is `ENOENT`, which Wine reports as not found.
- **Open rights.**
  - A directory open asks for `read,enumerate`.
  - `O_TRUNC` and `O_CREAT|O_EXCL` add `write`, as `FILE_OVERWRITE`/`FILE_CREATE` do.
  - An open whose arguments cannot be read asks for `read,write`.
- **Not enforced.** `appcontainer` loads with a note and is not enforced.
- **Handle rules.** `open`, `handle`, `thread-open` and `thread-handle` rules are decided by
  the BPF layer on Wine 11.0's `open_process`, `open_thread`, `get_next_process`,
  `get_next_thread` and `dup_handle` requests, as `driver/object.c` decides handles. Wine
  cannot grant fewer rights, so a refusal fails the whole request instead of stripping
  rights. A handle the client duplicates that kfilter did not see made (inherited, or
  forgotten) counts as one to an unknown outside process: asking process rights for the copy
  is decided (`DUPLICATE_SAME_ACCESS` from the client's own handle is not), so an event or
  file duplicated with explicit access that overlaps process rights is refused too. Not
  decided: the process and thread handles `CreateProcess` returns to an outside creator, and
  plain Linux signals from outside processes to the client. Without BPF (`--no-bpf`) none of this is decided: block
  mode with `block-process-memory` or thread rules is refused, audit mode warns.
- **BPF layer limits.** Any of the following refuses block mode; audit mode loads without
  the rule.
  - a rule path of 256 bytes or more
  - a value of 128 bytes or more
  - an image of 64 bytes or more
  - more than 256 wildcard rules, counting literal rules past the 8th on one literal path
    (the first 8 rules on a path are looked up by its hash; later ones are tried like
    wildcard rules, so `deny|system|/system/wine/open_directory|image=<program>` for 15
    programs loads, as 8 hashed and 7 tried on every decision)

  A resolved path of 512 bytes or more, or of 64 components or more (each mount crossing
  counts as one), is a name failure, which is denied in block mode.
- **Network rules:**
  - An allow still needs one host, port, `tcp|udp`, `rights=connect`, `uses=N` and `risk=`.
  - With the BPF layer, network rules cover every protected program and every socket
    wineserver makes for it. `uses=N` admits N connections (for UDP, N peers, not packets)
    per policy load, and phases are shared with the other layers.
  - UDP uses are per peer: the first datagram to a peer is decided, and replies from it or
    later datagrams to it pass without another use (up to 8 peers per socket; a policy reload
    re-decides).
  - With the fallback, `uses=N` is an nft set of size N, and a network rule in phase 2 or
    later is refused.

## Messages: filtering client-server traffic on an allowed connection

A connection rule (`network`) decides whether the game may reach a server at all. Message
rules then decide **every single send** (and, optionally, receive) on that connection, before
it leaves. Wine's socket I/O is done by the game process itself, so this sees the game's own
traffic. The data is what goes on the wire: for the game that is ciphertext, matched as bytes.

```
deny|message|ip=54.68.216.33|port=8585|proto=tcp|match=0A1B@4      # bytes 0A 1B at offset 4
deny|message|port=8585|size=1000-65535                              # sends of 1000 bytes or more
deny|message|port=8585|index=1                                      # the first send on a connection
deny|message|port=8585|match=BEEF@0|uses=1                          # block once, then let through
audit|message|image=grap-core64.aes                                 # log everything grap sends
deny|message|port=8585|module=grap64.dll                            # sends made by grap64.dll's code
deny|message|rights=send,receive|ip=1.2.3.4                         # cut traffic with a host both ways
message-default deny                                                # strictest: only allowed sends go
```

| Field | Meaning |
|---|---|
| `ip=`, `port=`, `proto=` | the peer, as in network rules; omitted, any |
| `rights=` | `send` (default) and/or `receive` |
| `size=A-B` | the send's byte count (one number: exactly that) |
| `index=A-B` | the message's number on its connection in that direction, 1 = the first (attempts, refused ones included) |
| `match=HEX@OFFSET` | 1 to 16 bytes at that offset (within the first 4096 bytes of the send's first buffer) |
| `module=` | under Wine, the Windows module (DLL or EXE file name, `*` and `?` allowed, any case) whose code made the send or receive; see below |
| `image=`, `uses=`, `phase=`, `opens`, `risk=` | as on every rule |

- **Order.** First match wins. A message no rule decides is allowed, unless
  `message-default deny` is set. Message rules apply with `block-network on`; with
  `network-loopback on`, loopback traffic is not decided.
- **Refusal.** The send (or receive) fails with `EPERM`, and the connection stays open: TCP
  keeps its stream intact, because nothing half-sent goes out. Under Wine the game sees that
  call fail.
- **Receives** are decided before their data arrives, so only the peer, the number and the
  program apply to them.
- **Events.** Every decision a rule makes, and every default refusal, is logged with the
  direction, peer, connection, number, size and first 64 bytes:
  `send tcp 54.68.216.33:8585 socket:[1887735] #12 len=821 data=0a1b...`. msmon's log
  carries the complete bytes of every message.
- **The calling module (`module=`).** `image=` names the program; `module=` names the code
  inside it. At each send or receive the kernel reads the thread's Windows stack where it
  entered Wine (TEB, `syscall_frame`) and takes the first return address that lies in one of
  the program's own modules: Wine's DLLs and the prefix's `windows` directory are skipped
  (as msmon's `caller_module`), so for a game that is e.g. `MapleStory.exe` or `grap64.dll`
  rather than `ws2_32.dll`. kfilterd keeps each protected Wine program's module code ranges
  in the kernel (from `/proc/<pid>/maps`), rereading them when the program maps or makes code
  executable. Events show it: `send tcp ... len=8 caller=grap64.dll+0x1a2b3 data=...`; a
  message with no known caller has no `caller=` and matches no `module=` rule.
- **Blocking one live connection:** `kfilterctl block-connection socket:[1887735] both`
  (or `send`, `receive`) refuses everything on that connection from now on;
  `unblock-connection` lifts it. The socket inode is in `kfilterctl watch` and in msmon's
  records.
- **Limits.**
  - Bytes sent through `sendfile`/`splice` are decided on size only, not on their bytes.
  - `match=` looks only at a send's first buffer.
  - `module=`: a module's code ranges reach the kernel about 50 ms after Wine makes them
    executable; a send in that window has no caller. The caller is found by scanning the
    first 2 KB of the Windows stack, not by unwinding, so a stale return address left in a
    Wine frame can name the wrong module, and a call made from code outside every module
    (memory the game allocated) names the module further up the stack. A program has at
    most 128 code ranges and a policy 32 distinct `module=` patterns. 64-bit programs only:
    this Wine runs 32-bit programs (the launcher family, NGService) as i386 processes
    (old WoW64), whose sends have no caller, so `module=` never matches them.
  - Message rules are enforced by the BPF layer only, not by the fallback and not on
    Windows.

### Sends to AF_UNIX peers (`unix=`)

A message rule naming `unix=` decides each send of a protected program to an AF_UNIX peer
(ABI 12): the X server, D-Bus, PulseAudio or PipeWire, another program's socket. The peer is
named by its path (`/tmp/.X11-unix/X5`), or `/@name` for an abstract socket
(`/@/tmp/.X11-unix/X5`, which is not the path). `unix=` is a glob on the whole name (a `*` for
more, case-sensitive), shorter than 128 characters: unlike a `pipe` rule, `unix=/tmp/.X11-unix`
meets nothing (`/tmp/.X11-unix/*` the sockets in it; `kfilterctl check` warns).

```
deny|message|unix=/@/tmp/.X11-unix/X5|match=6C00@0              # an X11 connection setup, little-endian
audit|message|unix=/run/user/*/bus|image=grap-core64.aes          # log what grap sends to the session bus
deny|message|unix=/run/user/*/pulse/native|index=1-3              # the first three sends to PulseAudio
deny|message|unix=/tmp/kf.sock|size=4096-65535                    # large sends to one socket
```

- **What names the peer.** A send on a connected socket (stream, seqpacket, a connected
  datagram) names the address its peer was bound to: a path walked from where it was bound
  (symlinks resolved, as `pipe` listen decisions name it, unlike its `pipe` connect decision:
  a client connecting to `/var/run/dbus/system_bus_socket` sends to
  `/run/dbus/system_bus_socket`; `kfilterctl check` warns of a `unix=` path through a symlink),
  or `/@name`. A `sendto` with an address names that address as written, as its `pipe` connect
  decision does (a relative path from the cwd); its message is decided only when that decision
  allowed it. A peer bound to nothing has
  no name and is never decided: a `socketpair`'s (Chromium's and Wine's own IPC), and a server's
  end of a connection from an unbound client (the program as the server sends to nobody a rule
  can name). An autobound peer is `/@` and its five hex digits.
- **Selectors.** `size=`, `index=` (the send's number on its socket, counted while a `unix=`
  rule is loaded: a socket that sent before has its earlier sends uncounted), `match=`,
  `image=`, `module=`, `uses=`, `phase=`, `opens`, `risk=`. Sends only: `ip=`, `port=`,
  `proto=` and `rights=receive` are refused with `unix=`.
- **Only `unix=` rules meet these sends**, and they meet nothing else: a message rule
  without `ip=` (any address) and every `network` rule decide INET traffic alone, and a `pipe`
  rule decides the connect. A send no `unix=` rule meets passes unlogged, whatever
  `message-default` says (Wine's server socket, the desktop's sockets). Like every message rule,
  they apply with `block-network on` (`kfilterctl check` warns without it).
- **Refusing one write ends the connection.** A refused send writes nothing, but the X11,
  D-Bus and PulseAudio client libraries treat the write error as fatal (xcb shuts the
  connection, libdbus disconnects, libpulse drops its stream; a skipped X11 request also puts
  the request numbering out of step), so in practice the first refusal is a kill switch for
  that connection, not a per-request filter (a refused `match=` on an X11 request kills the
  game's display connection). On Wine's own server socket (`/tmp/.wine-<uid>/server-*/socket`,
  its file descriptor passing) one refusal ends every Wine program of the family.
  `kfilterctl check` warns of a deny on an X11, D-Bus or Pulse socket without `match=` or
  `index=`, and of any deny (or counted allow) meeting Wine's server socket. Refusing single
  X11, D-Bus or Pulse requests belongs to the server side (an X server's SECURITY extension,
  `xdg-dbus-proxy`, a restricted Pulse socket).
- **Events** name the peer, and show none of the bytes sent (X11, D-Bus and PulseAudio
  authentication cookies travel there; msmon records them with `--log-content`), though
  `match=` decides on them: `send unix /@/tmp/.X11-unix/X5 socket:[1887735] #3 len=12`.
- **Cost.** A policy without `unix=` rules pays one map lookup on an AF_UNIX send of a
  protected program (Wine's server socket and Chromium's IPC are AF_UNIX and very hot); with
  them, each such send is named (a dentry walk for a path peer) and run against the message
  rules. `kfilterctl block-connection` stays INET only.

## Hiding and isolation

What the client can learn about the machine and the monitoring without any refused call, and the
launch options that hide it. All are off unless asked for; `monfilter.py run` turns on only
`--private-proc` (`--no-private-proc` turns it off) and passes the others as the same flags. Start
the client with no wineserver running for its prefix (`wineserver -k`), so that wineserver starts
inside the same namespaces.

- **Host name, kernel release, uptime.** `--hostname NAME` (UTS namespace), `--uname26` (uname
  reports `2.6.<x>`; Wine runs, 32- and 64-bit), `--time-offset SECONDS` (time namespace: monotonic
  and boot time, so uptime, `sysinfo` and `GetTickCount`, shifted; `monfilter.py run --time-offset
  random` picks 1 to 30 days). Wine's Windows computer name comes from the prefix registry. Still
  visible: `/proc/version`, `/proc/sys/kernel/osrelease` and `version` (hide them with rules, e.g.
  `deny|file|/proc/version|hide`), the wall clock, and the TSC (counts since boot, unless
  `--trap-rdtsc`).
- **`--private-proc`**: a mount namespace with its own procfs (`hidepid=invisible`, other
  accounts' processes, including `/proc/1`, are gone) and a cgroup namespace rooted at the launch
  cgroup, with `/sys/fs/cgroup` remounted (`/proc/self/cgroup` reads `0::/` instead of
  `/kfilter/launch-<pid>`). No pid namespace: kfilter and msmon match wineserver's `unix_pid`
  fields against global pids. With the same account the client still sees all of that account's
  processes (browsers, terminals, agents): that needs `--user`. Limit: the fallback layer's
  fanotify mount marks (used only where a filesystem mark is refused) do not cover the new
  namespace's mounts; the BPF layer and filesystem marks do.
- **`--user ACCOUNT`**: the client runs as a dedicated account instead of the sudo caller, so
  hidepid hides every process of yours, and the Windows user name and profile are the account's.
  A one-time setup, by hand: `sudo useradd -m -s /usr/sbin/nologin nexon`, a prefix owned by it
  (`sudo -u nexon env WINEPREFIX=/home/nexon/.wine-nexon wineboot -i`, then install the client
  there; never move your own prefix), and access it would otherwise lack: a display (use
  `monfilter.py run --nested-x`, whose cookie the account can read), sound (a Pulse/PipeWire socket
  for the account, or none), and the GPU (`setfacl -m u:nexon:rw /dev/dri/renderD128`, reset at
  logout). Then `monfilter.py run --user nexon --prefix /home/nexon/.wine-nexon --nested-x`.
  `NoNewPrivs: 1` in `/proc/self/status` stays visible; it is required.
- **Monitor traces** the client can read: `/proc/kallsyms` (`bpf_prog_*` symbols), `/proc/modules`,
  `/sys/kernel/security/lsm` (`bpf`), `/sys/fs/bpf`, `/sys/kernel/debug`. Hide them with `hide`
  rules (`deny|file|/proc/kallsyms|hide`, `deny|dir|/sys/fs/bpf|hide`, ...).
- **CPUID and RDTSC/RDTSCP** (`--trap-cpuid`, `--trap-rdtsc`, `--cpuid-mask LEAVES`, `--trap-log
  FILE`). No tracer can be used: wineserver ptrace-attaches to its clients (debug registers,
  memory), and a second tracer makes those attaches fail. Instead `linux/shim/kfshim.c` (built
  for x86_64 and i386 into `build/linux/shim/lib/<multiarch>/libkfshim.so`) is preloaded into
  every dynamically linked process of the launch (wine-preloader's ld.so honours `LD_PRELOAD`),
  except wineserver. `launch` writes the trap options to a directory of its own,
  `/tmp/kfshim.XXXXXX/config`, with a copy of each shim build in
  `/tmp/kfshim.XXXXXX/lib/<multiarch>/` (root's, readable by every account: the program's maps
  name no build path, and a `--user` account need not read the build), and preloads
  `/tmp/kfshim.XXXXXX/$LIB/libkfshim.so`: the options travel inside the preload path, so every
  process that loads the shim finds them, whatever closes inherited descriptors (Chromium's
  launcher closes them all) or rebuilds the environment (Wine builds a native child's from the
  Windows environment block), and no environment the program reads (`environ`,
  `/proc/self/environ`, the Windows block Wine makes from it) holds them or the log path. The
  program can still read them in the directory `LD_PRELOAD` names (and the open log in
  `/proc/self/fd`). A process the shim loads into without them (its directory removed, the shim
  preloaded by hand) exits 126 with `kfshim: no trap configuration ...` on stderr, as does one
  where a trap it was asked for cannot be armed (no `cpuid_fault`, a policy refusing the
  `arch_prctl`): never untrapped in silence. The directory stays after `launch` returns (the
  family outlives it: `wine start` returns at once), one per trapped launch, named in its
  `launched ... shim=DIR` line, until it is removed or `/tmp` is cleared at boot. Under
  `default-deny` every process must be allowed it: `monfilter.py run` puts
  `allow|file|/tmp/kfshim.*|rights=read,execute,query` first; a policy of one's own needs the
  same, or ld.so is refused the library (and runs the program untrapped, saying so). The shim snapshots the CPUID leaves, turns on CPUID faulting
  (`arch_prctl(ARCH_SET_CPUID, 0)`) and RDTSC faulting (`PR_SET_TSC`), and answers each fault
  from its own `SIGSEGV` handler; every other `SIGSEGV` goes to the handler the program
  installed (it interposes `sigaction` and `signal`). A leaf that differs between cores (1, 4, 6,
  0xb, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1f, 0x80000006, 0x8000001e: APIC ids, and on a hybrid CPU
  the core type, caches, TLBs and frequencies) is answered as the trapping thread's core answers
  it: before arming, the shim moves its starting thread through every CPU of its affinity mask and
  reads them there (a few ms per process start on 16 CPUs), and a trap finds its core with LSL on
  the per-CPU segment, as the vDSO's `getcpu` does. The handler makes no syscall for a CPUID, so a
  seccomp sandbox (Chrome's kills on `arch_prctl`) and kfilter's `arch_prctl` rule never see it;
  a CPU outside the start mask reads as the start core's. The others come from the snapshot, and a
  leaf past its range reads as the hardware answers it (Intel: the highest basic leaf's data; AMD
  and others: zeros), the hypervisor range 0x40000000+ from the snapshot when leaf 1 says there is
  one.
  `--cpuid-mask` zeroes identity leaves only
  (`0x80000002-0x80000004` the brand string, `0x16`, `0x17`, `0x3`): feature leaves stay true,
  because code trusts them and XGETBV cannot be masked. The log (`--trap-log`, written by the
  client, so it must be able to write there) has a line per process at the first use of each leaf
  or instruction (`kfshim pid= exe=<comm> bits=64|32 insn=cpuid leaf= subleaf= [masked=1] first
  ip=`) and per-process totals at exit (`... count=N`); a time read through the vDSO says
  `vdso=1`. msmon records every trap on its own, from the kernel (`system:cpuid`). Costs and limits:
  - an emulated CPUID or RDTSC costs about 1.6 µs here (a native RDTSC 7 ns, a native CPUID
    0.1 to 3.7 µs by leaf): a timing check can see it, and `--trap-rdtsc` (every TSC-based vDSO
    time read traps too) is forensic only. Under `wine cmd /c exit` each Wine process traps a few
    dozen CPUIDs, 64- and 32-bit;
  - the program can see `LD_PRELOAD` (it must be in the environment at each exec for ld.so, so
    `/proc/self/environ` would show it even if the shim took it out of `environ`, and children
    started through glibc's own exec paths would lose the shim), the options file beside it and
    the shim's copy in its maps, and can turn the traps off with raw syscalls. `ARCH_GET_CPUID`
    and `PR_GET_TSC` report the truth;
  - `deny|system|/system/arch_prctl/0x1012/1` (in the default policy) refuses turning CPUID
    faulting off; the shim never does, so the rule names only the program's own attempts;
  - reading the real TSC takes `prctl(PR_SET_TSC)` in the handler, which Chrome's seccomp policy
    kills on: under `--trap-rdtsc` Chrome's sandboxed processes (the sign-in Chrome's renderers,
    GPU and utility processes) die at their first RDTSC (checked with headless Chrome;
    `--trap-cpuid` alone runs it);
  - code that sets `SIGSEGV` through a raw `rt_sigaction` bypasses the shim and dies at its next
    CPUID; static programs never load it (and are not trapped);
  - RDTSC faulting outlives `execve` and ld.so reads the TSC before any constructor, so the shim
    turns it off around `execve`, `execv`, `execvp`, `execvpe` and `posix_spawn(p)`; a program
    started through `execl*`, `system` or `popen` dies at start under `--trap-rdtsc`;
  - ld.so's own CPUIDs run before the shim and are not seen;
  - the shim directory layout follows Debian/Ubuntu's `$LIB` (`lib/x86_64-linux-gnu`,
    `lib/i386-linux-gnu`); without the 32-bit libc runtime only the 64-bit shim is built. The
    client's account must be able to write the log.
- **vDSO** (`clock_gettime`, `gettimeofday`, `time`, `getcpu`): no syscall, so nothing records
  them. Removing the vDSO needs a tracer at each exec (the auxiliary vector is read before any
  constructor), which wineserver's ptrace rules out. With `--trap-rdtsc` each TSC-based vDSO time
  read traps and is logged `insn=rdtscp vdso=1`; `getcpu` (RDPID/LSL) and the vvar page stay
  invisible, as do KUSER_SHARED_DATA time reads. Two tells no launch option removes, because the
  kernel maps the vDSO at each exec and only `vdso=0` on the kernel command line (a system setting
  that slows every program's time calls) takes it away:
  - its ELF notes carry the kernel's `LINUX_VERSION_CODE` and build-id, whatever `--uname26`
    reports and the `/proc/version` hide rule hides;
  - under `--time-offset` the time namespace's `[vvar]` mapping keeps the real clock data beside
    the namespace's offsets, so the real boot time can still be worked out.
- **Instructions that cannot be trapped from user space**: XGETBV, RDPID, LSL, RDFSBASE/RDGSBASE,
  RDPKRU, RDRAND/RDSEED, RDSSP, cache and TSX timing. A boot profile for fingerprint-hardened
  sessions (documentation only; it changes the whole machine and needs a reboot):
  `nofsgsbase nopku tsx=off` on the kernel command line makes RDFSBASE/RDGSBASE/WRFSBASE and
  RDPKRU/WRPKRU raise `#UD` (`SIGILL`, which msmon then records as the process's own fault signal: a `coverage`
  record `self_signal` naming it, `name=sigill`, not a `signal_received`) and removes
  TSX timing. Not verified here: Wine and glibc are expected to fall back to `arch_prctl` for
  FS/GS (slower syscalls), and software relying on protection keys loses them.
  `cat /proc/cmdline` shows the current parameters.
- **X11.** On a Wayland desktop X clients share one Xwayland: any of them lists every X window,
  reads the screen (GetImage), records keys (RECORD) and injects input (XTEST). There is no
  SECURITY extension in Xwayland, so an untrusted cookie is impossible there; inside a nested
  server the client is alone, so an untrusted cookie would add nothing. `monfilter.py run
  --nested-x [auto|xwayland|xephyr]` gives the session its own server (rootful Xwayland on
  Wayland, Xephyr on X11; it runs as you, in its own window) with a fresh cookie, sets `DISPLAY`
  and `XAUTHORITY` for the client, drops `WAYLAND_DISPLAY`, and puts rules first that allow the
  nested display and then refuse every other X socket (`/tmp/.X11-unix/X*` and their abstract twins
  `/@/tmp/.X11-unix/X*`, displays started later too), every Wayland socket
  (`/run/user/*/wayland-*`), GNOME's Xwayland cookie (`/run/user/*/.mutter-Xwaylandauth.*`) and
  the desktop's Xauthority file (`monfilter.other_display_rules(n)` writes the display part, for
  a policy of one's own as well). In audit mode those
  refusals are would-deny events: the client going around the nested display. Expect a separate
  window, a separate clipboard, and possibly no IME.
- **D-Bus.** `monfilter.py run --dbus-proxy` runs `xdg-dbus-proxy --filter --log` for the
  session and the system bus (as you), points `DBUS_SESSION_BUS_ADDRESS`/`DBUS_SYSTEM_BUS_ADDRESS`
  at it, and refuses the real buses and the accessibility bus (`/run/user/*/at-spi/*`) first. Each
  call is logged (`dbus-bus.log`, `dbus-system_bus.log` in the bundle). The client may talk to the
  bus itself and to the names in `monfilter.DBUS_TALK`: only the login keyring
  (`org.freedesktop.secrets`). A recorded session showed winedevice asking UDisks2 (disk serials)
  and BlueZ (Bluetooth devices, a pairing agent) for their objects and nexon_client's printing
  asking Avahi, all of them refused now (Wine finds no such service). The sign-in Chrome keeps
  its cookie key in the keyring (its profile's cookies are `v11`, the keyring-key format, on
  GNOME): without it the profile would read as signed out. The keyring name opens the whole
  unlocked keyring to every family process; each call to it is in the log. Add a name to
  `DBUS_TALK` only from a session's `dbus-*.log`.
- **PulseAudio/PipeWire.** Any client can list other applications (pids, binaries) and open the
  microphone. No proxy exists; with `deny|pipe|/run/user/*/pulse/native` and
  `deny|pipe|/run/user/*/pipewire-0` the client has no sound (Wine falls back to no audio
  device). A restricted per-session PipeWire socket is not provided.
- **TLS keys.** `monfilter.py run --tls-keylog` sets `SSLKEYLOGFILE` for the client so the session's
  pcap can be decrypted offline (Wireshark's TLS key log file). Chromium/CEF (BoringSSL, in
  nexon_client) reads it as a Windows path, so it is given through the prefix's drive that maps
  the directory (`Z:/tmp/monfilter-client-*/tls-keys.log`). Wine's own GnuTLS (schannel, WinHTTP)
  reads the same variable as a Unix path and so logs only when no drive maps the directory.
  OpenSSL 3 DLLs (MapleStory's `libssl-3-x64.dll`) ignore it, and the game's own encryption is out
  of reach. The variable is visible to the program.

Files the client writes (trap log, TLS keys) and the nested X cookie live in a private
`/tmp/monfilter-client-*` directory during the run (owned by the client's account, your group,
since the X server and proxies run as you), and end up in the bundle's `client/` directory.

## Limits

With the BPF layer:

- **Registry refusals** reach the program as `STATUS_ACCESS_VIOLATION`, not
  `STATUS_ACCESS_DENIED` (see above). Wine's own `reg.exe` prints nothing and exits 0 when a
  value read is refused; the value is not disclosed.
- **Registry handles.** Requests sent before a thread's TEB exists (process start-up), and
  keys a process opened before kfilterd started or before it was protected, have no name.
  Using such a handle is a name failure, as on Windows. Inherited or duplicated key handles
  are not followed.
- **Key name length.** Registry names are kept as ASCII: other characters match only `*` or
  `?`. A key name of 512 bytes or more, or a value name of 128 bytes or more, is a name
  failure.
- **Housekeeping.** wineserver's own work, which no client request starts, is decided for
  no one. Asynchronous work that wineserver finishes after replying is not charged either.
- **Device brokers.** Only winedevice is followed; other services the program calls over
  RPC (`rpcss`, `services`) act on their own.
- **Writes to wineserver.** A protected program may write to a request pipe only as Wine
  does: its own pipe, one whole request header per `write`/`writev`, data chunks that add up to
  the header's request size. Anything else (a duplicated fd of another process's pipe, split
  headers, a request number past the protocol's, chunks past or short of the size) is refused,
  because it could reach wineserver undecided. So are `vmsplice`, `splice` and `tee` into a
  request pipe, and any write to one by a protected task that is not a decoded Wine process (a
  shell it exec'd, a program it handed the pipe to). Each is a `process` event with value
  `0x4000` (plus the syscall number for the splice family): a deny in block mode, a would-deny
  in audit mode. io_uring splices into the pipe are not mediated.
- **Security descriptors.** `get_security_object` and `set_security_object` on a handle kfilter
  named are `registry` decisions on its name (`read`, `set-security`), whatever it reaches: a
  key, an NT object or named pipe opened by name, an object directory. A `file` or `pipe` rule
  on that name does not meet them (deciding them so would make those rules refuse what they did
  not before); a `registry` rule on the name does, and under `block-registry` with
  `default-deny` they are refused unless one allows them.
- **Programs started before kfilterd.** A Windows program that was already running when
  kfilterd started is named but not admitted by a `protect` name, so restarting kfilterd in
  block mode never kills a running client. Start the client after kfilterd, or run
  `kfilterctl track` to protect the running programs that match a `protect` name.
- **Working memory.** Each decision uses about 7 KB of per-task working memory, allocated
  without sleeping. If that fails in block mode, the operation is refused with `ENOMEM`
  (fail closed), and so is an exec while protect names and `block-process-create` are on.
- **Created files.** A denied `open(O_CREAT)` is refused at `file_open`, after the kernel
  made the inode, so it can leave an empty file.
- **Not mediated:** page faults on an existing mapping and work done entirely inside the
  kernel. `statfs` (`f_fsid`) is logged as an audit `volume` event under
  `block-volume-serial`, never refused. io_uring opens and reads run in the program or its `iou-wrk`
  threads (protected like any thread), so they are decided as its own; `/system/io_uring`
  refuses rings altogether.
- **Loading** and verifying the programs takes several seconds before the socket appears.
- **Counted rules** are counted per layer: the BPF layer keeps its own uses, reset at every
  policy load (also of the same policy) or launch pass. A device allow with `uses=N` on a GPU
  under a `deny|device` rule takes a use per ioctl, so it runs out within seconds; leave
  `uses=` out there (see Devices).
- **Policy reload.** Each lookup reads one rule set, but a request decided by several (a Wine
  registry write: its request, key and rename; a send: its address, DNS name and message) can
  have its parts decided by the old and the new policy when a load switches between them, and
  pass although each policy alone refuses one part.
- **Addresses read twice.** What a Wine request reaches is read from the program's memory when
  it writes the request, and the remote iovecs of a family member's `process_vm_readv`/`writev`
  after the kernel copied them: another thread of the program can change them in between, so
  the decision can see other addresses than the access uses. A `queue_apc` whose APC type
  itself lies past the request's first written chunk is taken for one that reaches no memory.
- **Stopping kfilterd** detaches the programs and lets every later operation through.

With the fallback layers (`--no-bpf`):

- **No Wine attribution, Windows protect names, registry or `image=`.** No program is named,
  so `image=` rules match nothing.
- **Unmediated file changes.** fanotify cannot deny delete, rename, link, chmod/chown or
  truncate through an existing handle; kfilterd does not see them. `msmon-agent` records
  deletes and renames.
- **Not mediated:** ptrace and `process_vm_readv` (process memory), page faults on an
  existing mapping, ioctls on an already-open device, `mmap(PROT_EXEC)` of an already-open
  file.
- **Only marked filesystems are covered.** Not marked:
  - `proc`, cgroup, `devpts`, `debugfs`/`tracefs`
  - `fuse`, whose server could deadlock on the event descriptor
  - `devtmpfs` apart from the devices listed above, because opening a watchdog or serial
    node for an event is not harmless
- **Named pipes.** The kernel opens every file it reports to kfilterd. For a named pipe on a
  marked filesystem that open is a momentary reader, so a writer opening a FIFO with no
  reader is not held back and may later get `EPIPE`.
- **Network scope.** Network rules cover processes in `/sys/fs/cgroup/kfilter`, that is,
  started with `kfilterctl launch`. Incoming connections are checked; `bind` and `listen`
  themselves are not.
- **Overhead.** Every open and read on a marked filesystem, by any process, waits for
  kfilterd, and unprotected ones need one `/proc` read. Expect overhead under heavy I/O.
- **Mount namespaces.** Paths of processes in another mount namespace (Flatpak, Steam's
  pressure-vessel, `unshare -m`) are matched as the process sees them. The event's mount is
  looked up by id in the process's `/proc/<pid>/mountinfo`; a mount it does not have is a
  name failure.
- **Stopping kfilterd** lets every pending and later operation through (fanotify allows when
  the group closes), and removes the nftables table.

## Tools

- `tools/kfilter_policy.py` and `tools/analyze_reachability.py` are the one implementation;
  `Build-Policy.ps1` and `Analyze-Reachability.ps1` are thin Windows wrappers over them. Both
  accept NT and Linux captures. `tools/tuning_report.py` (`monfilter.py report`) sorts a
  session's actions into blocked, would block, allowed by rule, went through with no rule,
  and not filterable, names them as kfilter does (`/system/...`, `/anon/...`,
  `/proc/@self|@family|@wine|@outside`, `dns` names, `peer` targets), lists what neither tool
  sees, and proposes candidate rules (an `audit` line first for a rule-only layer).
- Not ported: `Install-NetworkPolicy.ps1`, `Simulate-Policy.ps1` (use `kfilterctl simulate`),
  `tests/*.ps1` and the Windows probes. `tests/linux_wine_test.sh` runs Wine's own `reg.exe`
  and `cmd.exe` instead.

## Running with msmon: one command

`../monfilter.py run` (repository root) starts kfilterd, loads the policy (audit unless
`--block`), starts msmon-agent on every Nexon root with payloads on, waits until it records,
launches the client under `kfilterctl launch`, and at the end stops msmon, then kfilter,
packs the session and writes the tuning report (`monfilter.py report <bundle>`). See the
repository README for the options and the tuning loop.
