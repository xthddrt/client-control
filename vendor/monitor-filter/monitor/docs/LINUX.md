# Linux agent

On Linux there is no driver. `msmon-agent` runs its own sensors (`agent/linux/`) and
feeds their records through the same queue format, sequence numbering, hash-chained
JSONL writer, classifier and session bundle as the Windows agent, so `verify_log.py`,
`session_pack.py`, `sensor_report.py` and `tools/analysis/` read Linux bundles unchanged.

## Build and check

```sh
./build.sh
```

Needs g++ (C++17) and python3. It builds `build/linux/msmon-agent` only; `./build.sh tests`
also builds the test binaries, which the top-level `tests/run_offline.sh` runs.

The kernel (eBPF) sensors also need clang, bpftool, the libbpf headers and the running
kernel's BTF (`/sys/kernel/btf/vmlinux`):

```sh
sudo apt install clang-18 libbpf-dev linux-tools-common linux-tools-$(uname -r)
```

Without them `build.sh` says so and builds the agent without them; it then uses the
fanotify, proc connector and polling sensors below. `CLANG=`, `BPFTOOL=` and
`LIBBPF_INCLUDE=` point the build at tools outside `PATH`.

Root-only check (run it in a VM): `sudo tests/linux_ebpf_test.sh`. With Wine 11.0 in
`/opt/wine-stable` (or `WINE_ROOT=`), `sudo tests/linux_wine_test.sh` records `reg query`, `reg add`
and `tasklist` in a temporary prefix it creates as `$SUDO_USER` and checks the wineserver-decoded
records, the PE frames and the decoder's coverage notes. `sudo tests/linux_watch_test.sh` checks
`--watch` ([Watchpoints](#watchpoints)) on a native probe and, with Wine, on a PE module.

## Run

```sh
sudo build/linux/msmon-agent --client ~/.wine-nexon/drive_c/Nexon/Library/maplestorycw --log-dir /var/tmp/msmon-sessions
sudo build/linux/msmon-agent --pid 1234 --log-dir /var/tmp/msmon-sessions --once
```

Under Wine `/proc/<pid>/exe` is the Wine loader, never `MapleStory.exe`. A process is in
scope when its image is under a root, when it execs a Wine loader (wine, a preloader, wineserver) with
its current directory under a root (checked in the kernel at the exec: Wine starts a Windows program in
its current directory, so the client and its launcher are recorded from Wine's start-up on, `process_start`
`scope=wine_exec_cwd:<directory>`), when it has an executable file mapping under a
root (checked in the kernel at `mmap`, `scope=exec_mapping:<file>`, and in `/proc/<pid>/maps`), when it is the
wineserver of the client's prefix (its `WINEPREFIX`, default `$HOME/.wine`), when it is `kfilterctl launch`'s child
(checked in the kernel at its first exec: the child joins its session cgroup `kfilter/launch-<launcher pid>` before it
execs, so the launch wrapper, `nexon-launcher` and its `xdpyinfo`, `grep` and `/usr/bin/wine`, is recorded from its
first instruction, `scope=kfilter_launch:launch-<launcher pid>`; only the launcher's own child joins, its parent's pid
being the cgroup's name, and without the cgroup the launch joins at Wine's exec or at kfilter's first decision for it,
as a native helper while it runs a native program), or when it descends from a process in scope. The launch wrapper's native programs are in scope (recorded
in full) until one execs a Wine loader, which ends the wrapper. Other programs in the prefix (the Nexon launcher) are not in
scope unless they map an executable under a root; the prefix's brokers are (wineserver,
winedevice.exe, services.exe, rpcss.exe, plugplay.exe, explorer.exe and svchost.exe: they serve
the client's RPC, so a prefix booted before the agent has them joined by the `/proc` rescan). A
descendant that execs a native program (anything whose basename does not start with `wine` and
is not under the root, e.g. `xdg-open` and the browser it starts) stays tracked as a native helper,
since kfilter keeps deciding for it: its exec `process_start` ends with
`;attribution=native_helper;native_depth=N`, every record of it and its children carries
`;attribution=native_helper`, and what it starts, whom it talks to, what it asks of the
system and which files it opens and renames are records (exec, fork, socket, connect, bind, listen, accept, ptrace,
process_vm_*, signals, the pid-taking calls, prctl and the credential calls, module loads, memfd_create, `system:`
calls, kernel events; open, creat, openat, openat2, open_by_handle_at, unlink, unlinkat, rmdir, rename, renameat,
renameat2, link, linkat, symlink, symlinkat, mkdir, mkdirat, mknod, mknodat). Its reads, writes, sends and receives
(read, write, pread64, pwrite64, readv, writev, preadv, pwritev, preadv2, pwritev2, sendto, recvfrom, sendmsg, recvmsg,
sendmmsg, recvmmsg; both ABIs but the ia32 `socketcall` multiplexer's) are kernel aggregates per (process, call, the
fd's inode) with their bytes and failures, the first of each key a second a record (see [Kernel
aggregates](#kernel-aggregates)): a browser's ~24 processes put no ring record on each call. Its other file calls
(stat, getdents, close, chmod, truncate, ioctl, fsync, file mmaps, ...) are counted only. Its sockets are not tagged
and its bytes never read, so no payload or packet of a browser is captured. `--native-depth N` (default 3) is how many native execs
in a row stay tracked; the next one (and `--native-depth 0` at the first) leaves scope: the exec is
recorded, then a `process_exit` with value1 1 and `untracked;native_exec`, and neither it nor its
children are followed; kfilter's later decisions for it do not bring it back. A process kfilter decides for that the
agent did not track yet (`kfilter_family_tracked`: a browser kept from before the agent's start, a dropped helper's
child) joins as a native helper at depth 1 when it runs a native program (not a Wine loader, not under a root), and
in full otherwise. The Google sign-in hand-off (a process `winebrowser.exe` forks, known by its main thread's
name, which Wine gives every process after its Windows image: `xdg-open`, `google-chrome`, `chrome`, its zygote,
renderers, GPU and network processes, `chrome_crashpad_handler`, the `xdg-settings` shell helpers, 8 of them past depth
3 in a recorded session) is followed to `max(N, 8)` (`ebpf_active` says `handoff_depth=`), so it needs no option of its
own: a loop that starts the agent without `--native-depth` gets 3 for other helpers and 8 for the hand-off. The
hand-off flag stays on the browser for its whole life (MapleMarket's `xdg-open` keeps a Chrome per display), so a kept
browser's steady calls cost the agent for hours, not only at sign-in: its reads, writes, sends and receives stay one
record and one summary per key a second, but its opens, `memfd_create`, `clone3`, `prctl` and the like are a ring record
each (path walk and user stack); `linux_budget_test.sh` bounds the agent at `BROWSER_CPU_PCT` (5%) for an assumed
300 opens and 100 `memfd_create` a second (measure a real kept Chrome's rate before msmon goes back into the loop). The
prefix is the nearest folder above `--client` that holds
`system.reg`, or `--prefix DIR`. `/proc` is rescanned every second for processes that
started outside the tracked tree (a wineserver started earlier, a client service).
The prefix is a snapshot root: the `*.reg` files wineserver saves (it writes a temporary
file and renames it into place) are copied into the session, up to 16 MiB each. Other text
files are copied whole up to 256 KiB; a bigger one (a growing log) is copied from where its last
copy ended (`file_snapshot` detail `offset=`, `mode=delta`), or its newest 256 KiB the first time
or when more than that was appended (`mode=tail`).

`--no-ebpf` keeps the kernel sensors off. `--log-real-input` also logs the user's own keys that pass
wineserver (winex11's keyboard input, keyboard messages, low-level keyboard hooks' calls); by default
their keys are left out (see [Wineserver requests](#wineserver-requests)). `--log-environment` also logs
the value of every environment variable an exec starts with (`process_environment`); by default only the
names, and the values of Wine's, the loader's and the graphics stack's variables (`WINE*`, `LD_*`,
`DXVK_*`, `VKD3D_*`, `MESA_*`, `__GL_*`, `PROTON_*`, `DISPLAY`, `WAYLAND_DISPLAY`), are written: another
value may hold a secret the user exported, so it is `withheld:<bytes>`. A bundle recorded with either is marked
`sensitivity=secrets`, and `redact_session.py` withholds those keys and values again in its copy (docs/STORAGE.md).
`--log-content` also logs contents
msmon otherwise names, sizes or hashes only ([Contents](#contents---log-content); off for privacy and
volume). `--window-probes` also probes Wine's window functions ([Function probes](#function-probes); off:
each call of a probed function takes a trap, and the game calls `NtUserCallHwndParam` every frame). `--watch WHERE:LENGTH:ACCESS` (up to
four) logs a process's own loads and stores at an address with hardware data breakpoints ([Watchpoints](#watchpoints)).

`MapleStory.exe` is not required: any `--client`/`--scope-root` directory with an
executable file directly inside it is accepted (the first by name is hashed as the
client; `MapleStory.exe` is preferred when present), or `--pid`. Paths are used as given (absolute, case-sensitive). Stop with
Ctrl+C, SIGTERM or `--stop-file`.

Root is needed for the kernel sensors (CAP_BPF, CAP_PERFMON, CAP_MAC_ADMIN for the LSM
hooks), for fanotify and for the process-events connector (CAP_SYS_ADMIN, CAP_NET_ADMIN,
CAP_DAC_READ_SEARCH). Without it the agent still runs and writes a valid,
chain-verified log, but records `fanotify_unavailable` / `proc_connector_unavailable` and
marks those registrations failed in `coverage.json`; only `/proc` polling (images and
sockets of your own processes) is active.

## Sensors

With root and a BPF-capable kernel the kernel sensors are used, and the user-space sensors
of the classes they cover are not started (coverage notes `*_superseded`). The maps poll
is the exception: it always stays active and owns `image_load`, because Wine maps PE
modules without `PROT_EXEC` and makes their code sections executable with `mprotect`.

| Sensor (slot) | Source | Records |
|---|---|---|
| `linux.ebpf_process` (48/54) | `tp_btf/task_newtask` (tracking copied before the child runs), `sched_process_fork/exec/exit`, `fexit/security_mmap_file` and `fexit/security_file_mprotect` (an untracked process mapping an executable under any scope root, or mprotecting a mapped file executable, joins the scope; every root (client root and `--extra-root`s, symlinks resolved) is matched in the kernel) | `process_start` (fork = inherited; exec = value1 1 with the image and the whole argv read from the new image's mm at `sched_process_exec` (up to 4 KiB, then the 1024-character record limit), plus `;env:NAME=value` for WINEPREFIX, WINEDLLOVERRIDES, WINEDEBUG, WINELOADER, WINESERVER, WINEARCH, LD_PRELOAD, LD_LIBRARY_PATH and LD_AUDIT found in its environment; a refused clone/clone3/fork/vfork = value1 3, `clone_failed;`), `coverage` `process_environment` after an exec's `process_start` (the whole environment it started with, read from the new image's mm in 4 KiB `MM_ENV` parts up to 64 KiB: `NAME=value;...`, values `withheld:<bytes>` but Wine's, the loader's and the graphics stack's unless `--log-environment`; value0 the environment's bytes, value1 the part when the 1024-character limit splits it, `env_truncated=<bytes kept>` when the kernel kept less; cost: per exec of a tracked process one `MM_ENV` ring record per 4 KiB of environment, at most 16, about 1-10 us), `process_exit` and `thread_exit` with the exit code (`exit_code=<wait status>;exit_status=N`, or `signal=N[;core_dumped=1]` for a death by signal: `task->exit_code` at `sched_process_exit`), `thread_start`, `thread_exit` (a Wine thread's exit carries its Windows ids from its TEB ClientId: value1 and `win_pid=`/`win_tid=` in the detail; at start the thread has no TEB yet, its Windows tid appears with its wineserver requests, and its start address with its `init_thread` request, `entry=`) |
| `linux.ebpf_file` (49/55) | `tp_btf/sys_enter` + `sys_exit` for 268 syscalls of tracked processes; every other syscall is a kernel aggregate ([Kernel aggregates](#kernel-aggregates)) | `file_create` (open*, mkdir, mknod; `userfaultfd:[ino]`, `memfd_secret:[ino]`, `fanotify_init:[ino]`, `io_uring_setup:[ino]`, `mq:/<name>`), `file_read`/`file_write` (value0 bytes transferred, value1 offset; also recvmmsg/sendmmsg, and sendfile, copy_file_range, splice and tee, whose bytes move fd to fd without a user buffer: the text is the input fd's file, `out=<the output fd's file, or socket:/pipe:/file:[ino]>;out_fd=N` the output's, collapsed per output; a read of another process's `/proc/<pid>/mem` or `pagemap` is collapsed per offset (the address), and every record of a `/proc/<pid>/` file of another process has that process as target_process_id), `file_close`, `file_set_information` (unlink 13, rename 10 as `rename;from`/`rename;to`, link 11, truncate 20), `file_set_security` (chmod/chown/utimes), `file_query_information` (stat, access, readlink, statfs, name_to_handle_at, file_getattr, getsockname/getpeername, cachestat; `system:<call>` with `;path=` for the calls that name the machine or change it: uname, sysinfo, statmount, listmount, listns, lsm_* (they show the bpf LSM), landlock_*, syslog, mincore, mseal, bpf, perf_event_open, keyctl/add_key/request_key, io_uring_enter/io_uring_register and io_setup/io_submit/io_destroy/io_cancel (the operations: [Kernel events](#kernel-events)), setpriority, ioprio_set, the mount family (mount, umount2, pivot_root, chroot, move_mount, open_tree*, fs*), swapon/off, acct, uselib, quotactl*, clock/time setters, sethostname, setdomainname, reboot, vhangup, kexec_*, iopl, ioperm), `file_directory_control` (getdents, value1 bytes; fanotify_mark), `file_set_ea`/`file_query_ea` (also the 6.13+ `*xattrat` calls with their dirfd); `coverage` `syscall_counts` |
| `linux.ebpf_net` (50/56) | the same syscalls on sockets | `network_connect` (connect; sendto and sendmsg with an address), `network_accept` (accept; recvfrom and recvmsg with a source; `bind;` with the local address; `listen;` with value1 the backlog), `network_flow_close` (close of a socket; value0 socket inode) |
| `linux.ebpf_ipc` (51/57) | AF_UNIX connect/accept, kill/tkill/tgkill | `network_connect`/`network_accept` with `unix:` endpoints, `process_handle` (`signal=N`, target_process_id) |
| `linux.ebpf_device` (52/58) | ioctl, getsockopt/setsockopt | `file_device_control` (value0 request, value1 argument; for socket options the level and the option, as Windows' AFD info ioctls) |
| `linux.ebpf_wineserver` (60/61) | `tp_btf/sys_enter` write/writev and `sys_exit` read on a Wine thread's wineserver request/reply pipes (`mm_ws_*`) | see [Wineserver requests](#wineserver-requests) |
| `linux.ebpf_memory` (53/59) | mmap, mprotect (anonymous memory that is not executable, munmap, mremap, madvise, brk, msync, mlock: [Kernel aggregates](#kernel-aggregates); an anonymous executable region is read through `/proc/<pid>/mem`: a PE image at the region or at the 64 KiB boundary below it is an `image_load` `anon_pe:<export name>@<base>` with `source=anonymous_pe;timestamp=;machine=;module=` and joins the PE frames, the region's record says `anon_pe=<base>`; anything else adds `first_page_sha256=` to its record; the read happens when the record is processed, so a region freed by then is not read), ptrace, process_vm_readv/writev; `lsm/ptrace_access_check`, `lsm/bpf`, `lsm/perf_event_open` | `file_section` (file or executable mappings; value0 flags, value1 protection); `image_load` at the mapping, as Windows' load-image notify (value0 base, value1 size; `source=mmap` for an executable file mmap, `source=pe_header` for a PE header mapping at offset 0, value1 SizeOfImage, `source=mprotect` for `fexit/security_file_mprotect` making a file mapping executable, base = vma start - file offset); an executable mapping some LSM refused (kfilter in block mode) is an `image_load` with the errno in `status` and `image_map_denied;` in the detail (fexit sees the final verdict, so attach order does not matter); the maps poll stays the fallback and skips loads already written; `process_handle` (ptrace request or VM read/write, target_process_id, `remote=` the first remote iovec's address and `remote_iov=base:len,...` every remote iovec with its length (16 at most, `,+` past them), collapsed only when all of them repeat; `prctl;option=N`, PR_SET_PTRACER naming its target, and the same shape for arch_prctl (ARCH_SET_CPUID, SET_GS), personality, modify_ldt, set_thread_area, seccomp, unshare, setns and the credential calls (set*id, setgroups, capset); `clone;namespaces;` for a clone with CLONE_NEW* flags; `init_module`/`finit_module`/`delete_module`; `pidfd_open`, `pidfd_getfd`, `pidfd_send_signal`, `process_madvise`, `process_mrelease`, `kcmp`, `rt_sigqueueinfo`, `rt_tgsigqueueinfo`, `move_pages` (with `pages=` the page addresses it asks about, 16 at most, and `query=1` when it moves nothing: nodes NULL), `migrate_pages`, `get_robust_list`, `prlimit64`, `sched_*` with the pid as target); `file_section` also for SysV message queues and semaphores (`sysv_msg:`/`sysv_sem:key=` or `id=`), shmdt/shmctl and POSIX queues (`mq:/<name>`); the tracked tree is refused ptrace of and signals to the agent and to kfilterd (`lsm/ptrace_access_check`, `lsm/task_kill`; `self_protection_denied=ptrace`/`kill` records with `protected=msmon-agent` or `protected=kfilterd`; kfilterd is a root process named `kfilterd`, looked for at the start and again when it is gone, `ebpf_active` `kfilterd_protected=<pid>`); `bpf()` and `perf_event_open` are refused only with `LinuxSessionProtectTree(true)` (an agent `--protect-tree` flag; default off, so an audit run changes nothing the client does and kfilter's policy owns those calls); with `--watch`, a process's own accesses to the addresses it names (`watch_*` records, [Watchpoints](#watchpoints)) |

Every syscall record carries the syscall name, all six arguments, the result and the
duration in `detail`, the thread in `thread_id`, the negative errno in `status`, and up to
8 user return addresses as the stack (resolved against `image_load` ranges into `modules`).
A syscall Windows code made with its own `syscall` or `int 0x80` instruction, past Wine, says
`direct_syscall=1` (kfilter's test: its return address is in anonymous memory other than the vDSO, or in
a file mapping with a PE header at offset 0; Wine's own calls come from ELF code; cached per thread by
the vma of its last syscall site; not for a native helper).
Paths are rebuilt in the kernel from the task's dentries and its fd table, cwd or dirfd
(pipes, sockets and anonymous inodes are named `pipe:[ino]`, `socket:[ino]`,
`anon_inode:[ino]`); a path the kernel could not resolve falls back to the agent's fd table.
When the ring is full a record is dropped and counted as a sequence gap.

Repeats are collapsed: the same call by one process on the same target (path, endpoint,
ioctl request or target process) with the same errno is written at most once per window
(agent `--repeat-window-ms`, default 1000; 0 writes every call, which is gigabytes a minute
under Wine; `ebpf_active` says `repeat_window_ms=`). The first call of each window keeps its
full record; the calls after it are counted, and the count
(`repeats_before=N;repeat_bytes=B;repeat_span_us=..;repeat_tids=<up to 4 threads>[,+]`, plus
`repeat_offsets=low-high` for file reads and writes) is added to the next record of that key or
written as a `repeats_tail` record (value0 bytes, value1 count) when the process exits or
leaves scope, or once the key has been idle 10 s (or two windows) by the records' clock, when it is also dropped: a
session-long process keyed per address does not grow the agent's memory without end. A device's non-executable mappings (the GPU's `/dev/dri` buffers) collapse the same way
by device, protection and flags, and wineserver `map_view`/`unmap_view` of data sections by section,
size and access (an image view never). A fork's inherited mappings are its parent's: kept for its
PE frames, not written again as `image_load`s. Cross-process calls collapse only when they repeat exactly: ptrace by request,
target and address, process_vm_readv/writev by target and remote address, the pid-taking
calls by their first three arguments, wineserver `read/write_process_memory` by handle,
address and length, so every address read in another process keeps its record (the trade:
an anti-cheat scanning memory writes a record per address). Mutations (unlink, rename, link, mkdir,
truncate, chmod/chown, set-xattr), mappings, execs, bind/listen, prctl (but PR_SET_TSC, two per
RDTSC kfshim emulates under `--trap-rdtsc`) and module loads are never collapsed. Counts still
held when the agent stops (under a window of calls per key) are written as `repeats_tail` records
then, timed at the last counted call, and so are the wineserver requests still waiting for their reply
(decoded without it).

Nothing a tracked process does is wholly unseen: `mm_sys_enter` counts every syscall number
(ia32 ones apart, before any table lookup) that is not a kernel aggregate (below) and `mm_ws_enter`
every wineserver request, wanted or not, per process in a per-CPU hash (`counts`, 32768 keys; full,
it refuses a new key and counts `counts_full`). When the process ends or leaves scope (and at the
stop for those still running) the agent writes them, with the calls its kernel aggregates counted,
as `coverage` records `syscall_counts` (sensor `linux.ebpf_file`; `name=calls`, ia32 calls as
`ia32:name`) and `wineserver_request_counts` (`linux.ebpf_wineserver`), split into
`recorded=1` (calls that also have records or summaries: every wineserver request and every syscall
number) and `recorded=0` (counted only: numbers out of range, `nr65535`),
value0 the calls in the record, value1 its part when the 1024-character limit splits one.

### Kernel aggregates

Every syscall number of either ABI that no record names is counted in the kernel per (process,
call, key argument) instead of only per process: `sys_agg` (a global BPF function, verified once,
called from `mm_sys_enter` before anything else is done for the call) adds it to a per-CPU hash
(16384 keys; full: `agg_full`, and the call takes the record path, so it is still counted):
calls, failures (counted at the call's exit), the first and last call (CLOCK_BOOTTIME), and for
calls with an address the lowest address, the highest end and the bytes of their ranges. There are
two such maps, `agg0` and `agg1`; the array of maps `agg_live` names the one calls are counted in.
Every second the agent points `agg_live` at the other one (the update returns after an RCU grace
period, when no program holds an element of the first any more), drains the first
(`bpf_map_lookup_and_delete_batch`) with nothing writing it, and writes each aggregate as one summary
in the agent's own repeats form; so no call lands in an element after its key was read, or in one the
kernel reused for another key. Before a process's exit record (and an exec that leaves scope) the agent
takes that process's keys alone from the live map (it makes no more calls); the other processes'
wait for their second. The maps are not preallocated: kernel memory follows the keys in use, about
1 KiB each with 16 possible CPUs (a few hundred keys a second under the game: well under 1 MiB).

| Field | Value |
|---|---|
| type, sensor | `file_section` (`linux.ebpf_memory`) for memory calls, else `file_query_information` (`linux.ebpf_file`) |
| text | `system:<call>` (`system:ia32:<call>` for an ia32 number, by its own ia32 name; `system:nr<N>` for a number no kernel has) |
| value0, value1 | the ranges' bytes, the calls |
| timestamp | the last call |
| detail | `repeats_tail;syscall=<call>;aggregate=kernel[;<key name>=<key>];repeats_before=<calls>;repeat_bytes=<bytes>;repeat_span_us=<first to last>;errors=<failed calls>[;repeat_offsets=<lowest>-<highest end>]` (no `repeat_tids`: the kernel keeps no threads) |

A native helper's reads, writes, sends and receives (above) are aggregated at their exit, where the bytes are known
(`native_io`, a global function), per (process, call, the fd's inode and its type): summaries `system:<call>` (type
`file_query_information`) with `ino=<inode>;inode_type=<socket|pipe|file|dir|char|anon_inode>` (a socket's or pipe's
inode number can equal a file's; inodes of one type on two filesystems with one number still share a key),
`repeat_bytes` the bytes moved (none for sendmmsg and recvmmsg, whose result is messages) and `errors` the failed calls
(EAGAIN among them). The first call of each key since the agent's last drain is not in the summary but a record of its
own, as the call's record would be (`file_read`, `file_write`, `network_connect` for a send to an address,
`network_accept` for a receive from one) with `;native_io=sampled;ino=<inode>;inode_type=<type>` (and
`;endpoints=<local> -> <remote>` for a TCP or UDP socket): no duration, no stack, never its bytes, and the file named by
the path the helper (or its parent) opened an inode of that number and type by, else by its type (`socket:[N]`, `pipe:[N]`, `file:[N]`, `anon_inode:[N]` for an eventfd);
the kernel walks no path for it (a walk costs about 200,000 verified instructions, past `mm_sys_enter`'s budget). So a
key costs at most one record and one summary a second however busy it is. The other processes' calls of these numbers
are records as before; another process's exit of one costs a task-storage lookup (`native_io_threads`, which marks
only the threads that made a native helper's call at its entry), no call into `sys_agg` and no tracked-map lookup
(`linux_budget_test.sh` bounds it at `UNTRACKED_NS_MAX`, 30 ns).

A Wine process's aggregated call that Windows code made itself (see `direct_syscall=1` above; a
per-thread cache keeps it to a task-storage lookup a call) is counted apart and its summary says
`direct_syscall=1`; `syscall_counts` adds it to its call. Calls seccomp or syscall user dispatch stopped
before `sys_enter` (which neither counts nor records them) are summaries `system:seccomp:<call>` and
`system:dispatch:<call>` (see [Kernel events](#kernel-events)), in `syscall_counts` as `seccomp:<call>=N`
and `dispatch:<call>=N` (recorded=1).

Wineserver's hot requests are aggregated in the same maps (`ws_agg`, see [Wineserver requests](#wineserver-requests)),
their summaries `linux.ebpf_wineserver` with `syscall=wineserver:<request>` and `ws=<request>` (as the
request's own records have it: `system:select` is also the Linux select's summary). So are the requests and messages
of X11 and PulseAudio connections (per socket and op, a run of one op as one count; [Socket bytes and
DNS](#socket-bytes-and-dns)), their summaries `etw_rpc` (`linux.ebpf_ipc`) on the connection's endpoint with
`syscall=unix_service;aggregate=kernel;interface=;operation=;direction=;socket=`.

The keys (`agent/linux/sysagg.h` `kAggCalls`, F4's keys): rt_sigprocmask/sigprocmask `how`, futex
`op` (with the futex words' range), futex_wait/wake/waitv/requeue `flags`, lseek/_llseek
`whence`, fcntl `cmd`, epoll_ctl `op`, getrusage `who`, getrlimit `resource`, clock_*/timer_create
`clock`, get/setitimer `which`, getrandom, dup3, pipe2, eventfd2, signalfd4, timerfd_create,
epoll_create1, inotify_init1, close_range and rseq `flags`, sched_get_priority_* `policy`, exit and
exit_group `code` (a thread's and the process's exit code). The others (poll, select, epoll_wait,
sched_yield, getpid and the other identity reads, nanosleep, set_robust_list, set_tid_address,
sigaltstack, rt_sigreturn, restart_syscall, the calls no kernel has ...) have no key.

Anonymous memory (`mm_sys_exit` calls `sys_agg` for an mmap or mremap without a pending record):
an anonymous mapping that is not executable is counted at its exit with the range it returned
(`prot=`), an mprotect that does not make memory executable at its entry (`prot=`, PROT_NONE guard
pages included), every munmap, brk (the break asked for), msync, madvise (`advice=`), mlock*,
munlock*, mbind, set/get_mempolicy, remap_file_pages and map_shadow_stack with their ranges, and
mremap at its exit with the old and the new range (its bytes the two lengths, its offsets spanning
both) and `prot=` the moved mapping's protection
(`0x5`: executable memory moved, which no LSM hook sees; `0x100`: not found). Executable mappings
and protections stay records (`image_load`, `anon_pe`, `first_page_sha256`).

fcntl is aggregated by command but for the ones that change who is signalled or what is locked or
watched, which stay `file_device_control` records (value0 the command, value1 its argument): F_SETLK,
F_SETLKW, F_OFD_SETLK, F_OFD_SETLKW and the ia32 F_SETLK64/F_SETLKW64 (ia32 fcntl 55 runs
compat_sys_fcntl64, as fcntl64 does), F_SETOWN, F_SETOWN_EX, F_SETSIG, F_SETLEASE, F_NOTIFY and
F_ADD_SEALS (a lock's byte range is not read). The once counted-only calls that are rare and name a
directory, a file, another process or a signal are records: chdir and fchdir (`file_query_information`
with the directory), getcwd, umask, setsid, setrlimit, capget and rt_sigaction (with sigaction and
signal: `rt_sigaction;option=<signal>`) as `process_handle` `<call>;option=`, setpgid, getpgid,
getsid, wait4/waitpid and sched_getparam/getscheduler/rr_get_interval/getattr with the pid as
target, getpriority, ioprio_get, waitid and sync as `system:<call>`, sync_file_range (`file_flush`),
fadvise64 and readahead (`file_query_information` on the file), flock (`file_device_control`) and
socketpair. prctl records carry `;name=` (PR_SET_NAME) and `;vma_name=` (PR_SET_VMA).

Cost: an aggregated call takes two array lookups, one per-CPU hash update (an allocation the first
time its key is seen in a second) and a boot-clock read at its entry, in place of the `counts`
update it took before (the maps are plain per-CPU hashes, whose lookups the kernel inlines; counts'
LRU lookups were helper calls); no ring traffic. At the exit of a call without a record (of any
process) `mm_sys_exit` reads the task and looks up `aggcfg`; only a failing aggregated call, or an
mmap or mremap, then goes on into `sys_agg` (the `tracked` lookup and the update). An anonymous
mapping or protection that is not executable used to go through the whole record path (a 2 KB pending
record, the user stack, the PE context and a 1.5-2 KB ring record, decoded and dropped by the agent); it
is now that one update. Not yet measured on the game: `tests/linux_budget_test.sh` (root, for the
test window) measures the agent's CPU and the hot calls' cost with and without it, and passes before
msmon goes back into the live loop (it was taken out at 105% of a core, 2026-11-12 17:21).
Limits: an aggregate of a process the session has not admitted yet (its fork or scope record still
queued) is held until it is; one whose fork or scope record was lost (every record queued before it
processed without that, or its exit read) is dropped with the process's counts, its calls counted as
`unadmitted` in `ebpf_losses`.

Every operation kfilter's BPF layer can refuse has a record here: file open/read/write/
readdir, delete/rename/link/symlink/mkdir/mknod/truncate/chmod/chown/xattr/explicit times,
executable mappings, ioctls, exec, fork, ptrace-checked process access (ptrace,
process_vm_*, `/proc/<pid>/mem` opens, pidfd_getfd, process_madvise, kcmp), signals,
prctl PR_SET_MM/PR_SET_PTRACER, module loads, bpf/perf_event_open, connect, sendto/sendmsg
peers, bind, listen, accept and recvfrom/recvmsg sources. A refused call appears with its
negative errno in `status`; the decision itself is the KFilter record read from kfilterd.

Syscalls of 32-bit (ia32) processes are recorded. This Wine (11.0 under /opt/wine-stable) has an
i386-unix tree, so 32-bit PE programs (the Nexon launcher, nexon_client, nexon_agent, NGService) run
as 32-bit unix processes (`i386-unix/wine-preloader`) making ia32 syscalls (old WoW64), not inside a
64-bit process. `agent/linux/bpf_ia32.inc` maps each ia32 number to the x86_64 call of the same meaning
(stat64 to stat, mmap2 to mmap with its offset in pages, the *_time64 and 32-bit-uid variants to theirs);
the record says `MM_F_COMPAT`,
arguments come from bx, cx, dx, si, di, bp, and compat msghdr, mmsghdr, iovec and argv layouts are read
as such (peers and payloads included). 32-bit glibc makes its socket calls through `socketcall`
(102) and its SysV IPC through `ipc` (117): `mm_sys_enter` maps their subcalls (keys
`MM_IA32_SOCKETCALL`/`MM_IA32_IPC` + subcall in `ia32_nr`) and unpacks the arguments (socketcall's
u32 array; ipc's registers in the x86_64 order, shmat's address read back from `*third` at exit), so
a 32-bit client's sends, receives and shared memory are recorded like the 64-bit ones. The old-ABI
olduname/oldolduname (as uname), oldstat/oldfstat/oldlstat and readdir are mapped too, and `old_mmap`
(90: Wine's i386 preloader maps with it) as mmap, its struct read and its byte offset given in pages
as mmap2's. The other ia32 numbers are kernel aggregates by their own ia32 number. A Wine built
new-WoW64 only (no i386-unix) would run 32-bit PE code in 64-bit processes with no ia32 syscalls; PE
frames then show the 64-bit side (see "PE frames").

### Kernel events

`agent/linux/bpf/kev.bpf.h` (agent: `bpf_kev.inc`): `MM_KEV` records from hooks that observe
only (tracepoints, fentry/fexit), in three optional groups (`ebpf_active` `uring=`, `kevents=`,
`page_faults=`; coverage note `kernel_events`):

- `uring` (`mm_uring_*`): `tp_btf/io_uring_submit_req` takes each io_uring request of a tracked
  process with its fd's file (or the open's path, the connect's address), `tp_btf/io_uring_complete`
  adds its result, and one record is written as the call it stands for, detail
  `via=io_uring;op=<name>;res=;fd=;user_data=;dur_ns=`: `file_read`/`file_write` (value0 bytes),
  `file_create` for openat/openat2 (value0 open flags, value1 the fd, which is named from then on),
  `file_close`, `network_connect` (endpoint), `network_accept`, `file_flush`,
  `file_query_information` (statx), anything else `file_device_control` (value0 the opcode). SQPOLL
  and io-wq threads belong to the submitter's process. `fentry/aio_prep_rw` gives each Linux AIO read
  or write its file (`via=aio;opcode=;requested=;offset=`, no result). The setup and submit calls
  are syscall records (`io_uring_setup:[ino]`, `system:io_uring_enter`, `system:io_setup`, ...).
  Limits: no bytes; statx/unlinkat/renameat/mkdirat name no path; fixed files no file; a multishot
  request's later completions are not recorded.
- `kevents` (`mm_kev_*`): `tp_btf/signal_generate` writes a signal another process or the kernel sends
  a tracked one (a debugger, `kill` from a shell, wineserver's SIGUSR1/SIGQUIT, SIGCHLD) as
  `process_handle` `signal_received;signal=;name=;code=;sender_pid=;sender_context=<comm>;result=`
  (target_process_id the sender for a user-sent signal). A process's own fault signals (SIGTRAP: int3,
  which x86 sends as SI_KERNEL, a single step `trap_trace`, a hardware breakpoint hit `trap_hwbkpt`;
  SIGSEGV: an access violation `segv_maperr`, a guard-page or write-watch hit `segv_accerr`; SIGILL,
  SIGBUS, SIGFPE; SIGSYS from seccomp `sys_seccomp` or syscall user dispatch `sys_user_dispatch`) are
  counted in the kernel aggregates per (signal, code, ip page) with the fault addresses' range: the first
  of a key since the agent's last drain is an observer `coverage` record text `self_signal` (not
  `process_handle`: no kfilter decision is the fault's)
  `self_signal;signal=;name=;code=;code_name=;ip=;addr=<si_addr>;trap=<trap number>;error_code=<page-fault
  error code: bit 1 a write, bit 4 an instruction fetch>` (SIGTRAP `;dr6=` the debug status: bits 0-3 the
  hardware breakpoint hit, 14 a single step; SIGSYS `;syscall=;arch=`), value0 the fault address, value1
  the signal, with the user stack; the others its summary each second (`repeats_tail;syscall=self_signal;
  aggregate=kernel;signal=;name=;code=;code_name=;ip_page=;repeats_before=;...;repeat_offsets=<lowest>-
  <highest fault address>`), so a Wine guard-page or write-watch storm costs one per-CPU update a fault
  and two records a second per code page. Other signals a process sends itself are its kill/tgkill
  records. `fexit/security_ptrace_access_check` writes an untracked process's access check on a tracked
  one (a debugger's attach, process_vm_readv/writev, an open of `/proc/<pid>/mem` in attach mode; maps,
  smaps, environ, fd... in audited read mode; the NOAUDIT read checks every `/proc/<pid>/stat` read makes
  are left out, and so are the monitors' own: the agent's, and kfilterd's module polls and open decisions)
  the same way, per (actor, mode, the actor's syscall) under the target: an observer `coverage` record
  text `outside_access` whose process_id is the target and target_process_id the actor (the reverse of
  `process_handle`, whose process_id is always the actor: so no reader takes it for the tracked
  program's own handle), `outside_access;actor_pid=;mode=;mode_names=read|attach|fscreds|realcreds;
  call=<its syscall>;actor_tid=;actor_comm=;ret=;actor_exe=<its executable, last>`, status the check's
  result (a refusal by Yama or kfilter included), and its summary `repeats_tail;syscall=outside_access;
  aggregate=kernel;actor_pid=;mode=;mode_names=;call=;actor_exe=;...` (a check the DAC test refuses first,
  another user without CAP_SYS_PTRACE, never reaches the hook). Cost: a trampoline, the mode test and one
  tracked lookup on every ptrace access check on the machine (each `/proc/<pid>/` open of another
  process, ps and top included), about 0.1 us. A process's
  own SIGSEGV with SI_KERNEL (CPUID
  or RDTSC faulting, RDPMC, RDMSR, IN/OUT, INT n, other #GP) and `fixup_umip_exception` returning true
  (SGDT, SIDT, SLDT, STR, SMSW emulated with dummy values) are `file_query_information`
  `system:<instruction>` with `insn=;ip=;bytes=<first 4>;source=sigsegv|umip_emulated` (CPUID:
  `leaf=;subleaf=`, value0/value1), collapsed per address (and leaf). `fexit/security_capable` writes
  an audited capability check (`process_handle` `capability:<name>`, `capability;cap=;opts=;ret=`),
  `fexit/security_kernel_module_request` a module autoload request (text the module alias, e.g.
  `net-pf-12`), `fentry/commit_creds` a change of uid, euid, gid, egid or effective capabilities
  (`cred_change;uid=old->new;...`; an exec that keeps them is not recorded). Mounts and user
  namespaces are the syscall records of the mount family, unshare, setns and `clone;namespaces;`;
  keyrings are `system:keyctl`/`add_key`/`request_key`.
- `seccomp` (`mm_seccomp_*`): `fexit/__secure_computing` (no arguments on this kernel: the number is
  the task's `orig_ax`) and `fexit/syscall_user_dispatch` count a tracked process's calls they stopped
  before `sys_enter` (seccomp RET_ERRNO, TRAP, TRACE without a tracer, a refused USER_NOTIF; syscall user
  dispatch, which runs first of all and whose SIGSYS is also a `self_signal`) per call as the kernel
  aggregates `system:seccomp:<call>` and `system:dispatch:<call>`; a RET_KILL never returns: the
  process's exit code says SIGSYS. Every call of a seccomp-filtered process on the machine passes the
  fexit trampoline (a compare when the call is allowed); dispatch's only for processes that turned it on.
- `faults` (`mm_fault_*`, only with `--page-faults`): `tp_btf/page_fault_user` with `bpf_find_vma`
  writes the first touch of each page of a shared mapping with a file (MAP_SHARED files, memfd, SysV
  shm, shared anonymous memory) per process and access kind as `file_read`/`file_write`
  `via=page_fault;address=;ip=;error_code=;offset=` (value0 4096, value1 the file offset), collapsed
  per mapping and kind. Only a page not mapped yet faults (fault-around maps up to 16 neighbours of a
  read fault), so accesses to resident pages stay unseen. Off by default: every fault of a tracked
  process looks up its vma.

Losses that are not ring drops are counted in the per-CPU `losses` map and written at each flush as
the `ebpf_losses` coverage record: `pending_overwrite` (a thread's next call found its previous one
still pending), `pending_stale` (a thread ended with a call pending), `ws_rejected` (a write on a Wine
request pipe that was not one whole request: each also a `request_pipe_rejected` record),
`scratch_reuse` (`mm_sys_enter` and `unix_head` run preemptible: a call
whose per-CPU record another task rewrote meanwhile is dropped; `unix_head`'s bytes are `unparsed`), `pending_full` (4096 calls were
pending: this call's record is lost), `counts_full` (the counts map was full: a call in no
`syscall_counts`) and `agg_full` (the aggregate map was full: a call counted, not summarized; a fault
signal, an outside check or a stopped call not counted at all), the agent's own `unadmitted` (calls of
a process the kernel tracked and the session never admitted, its fork or scope record lost: in no
summary and no `syscall_counts`; its counts keys are deleted at its exit), `uring_unfinished` (io_uring
operations stored at submission whose completion record was never written: evicted from the 1024-entry
in-flight LRU, a CQE_SKIP_SUCCESS request, or in flight at the stop) and `ucall_unreported` (in-process
calls the function probes' one-a-second limit left out that no later record and no drain at the stop
reported: an evicted rate-limit key's), `unix_full` (AF_UNIX connects the desktop-service map had no room for:
their traffic is not walked). The other LRU maps evict only what is no loss (pipes of ended
threads, pages already reported) or need more than 1024 to 4096 threads in one call or request at once. The pending and counts maps are not LRU, so a full map refuses and counts instead of
evicting unseen. The first four were 0 in the eBPF and Wine tests before the kernel aggregates
(`linux_wine_test.sh` now checks `ws_rejected` stays 0 under real Wine); a second pending slot or
task-storage records are the upgrade if one is not.

Verifier cost (`bpf_verify` on this kernel, 46 programs, 4,761,039 verified instructions, about 5 s to load; the
limit is 1,000,000 a program). A global function's instructions count in every program that calls it, so moving logic
into one keeps its paths from multiplying with the caller's but not out of its total. The largest:
`mm_sys_enter` 809,322 (806,136 before native helpers' I/O: `native_io`, reached through `sys_agg`), `mm_sys_exit`
629,258 (626,036 before `native_io` and its `native_io_threads` gate; 538,286 before the desktop services: `unix_head`'s framing, D-Bus's
included, and its 256-byte header part), `mm_exec` 571,159 (575,685 before the launch scope, `scope_launch`, and one
`wine_image` call instead of two; 290,904 before the environment and the Wine-exec scope:
`scope_wine_exec`'s second `walk_path`, a static function verified at each call), `mm_mmap_file` 551,520,
`mm_file_mprotect` 551,591, `mm_uring_submit` 534,413, `mm_kev_outside` 267,391 (its executable's `walk_path`).
Smaller ones that grew: `mm_kev_signal` 590 to 1,576 (the fault signals' aggregate), `mm_ws_exit` 857 to 964 (window
owners), `mm_fork` 206 to 217, `mm_exit` 530 to 552 (exit codes), `mm_newtask` 56 to 128 (the hand-off's name check);
`mm_up_call` and `mm_up_call32` fell to about 3,300 (the rate key's second field instead of a fold). New: `mm_seccomp_filter` 317, `mm_seccomp_dispatch` 315,
`mm_unix_release` 31.

## Kernel sensor upgrades

Each part below has its own BPF and agent files. `tcp`, `packets`, `wineserver` and the socket
tags they share (`socks`) are optional program groups: if the verifier refuses one, the object
is loaded without it and `ebpf_active` says so (`optional=socks:on,tcp:load_failed:22,...`).

### PE frames

Wine runs a PE program's syscalls on its own per-thread stack, so the 8 user frames of a syscall record
stop in Wine's unix code (`ntdll.so`). At `sys_exit`, `read_pe` (`bpf/pe.bpf.h`) takes the thread's TEB
from its GS base (TEB `Self` must equal it, else the thread has no TEB and is skipped) and, when the
thread's sp is on Wine's kernel stack below its `syscall_frame` (Wine's `is_inside_syscall`), copies the
frame's rip, rsp and rbp and up to 512 bytes of the PE stack at rsp (up to the TEB's `StackBase`). Such a
record is a full 2080-byte event; others stay 1536 bytes. The agent (`pe.cpp`, `bpf_pe.inc`) turns it into
up to 16 PE frames placed before the unix frames: rip (inside the `NtXxx` stub of `ntdll.dll`), then the
return addresses unwound with the x64 `.pdata`/`.xdata` of the mapped PE images (each file parsed once from
disk), then, where unwinding stops, the words of the rest of the copied stack that point into PE code
sections. `detail` gets `pe_frames=N` and, for scan finds, `pe_scanned=M`. `modules` (resolved in stack
order, deduplicated, at most 8) therefore reads Windows side first, then unix side, e.g. `ntdll.dll`,
`kernelbase.dll`, the game's module, `ntdll.so`, `libc.so.6`; `tools/analysis/common.py` `caller_module`
skips Wine's own, the prefix's `windows` and the system's modules. This applies to every record built from
a syscall (and the wineserver-request records); process, thread, TCP and packet records have no PE side.

A PE image's `image_load` is one record per load: value0 is its header mapping (file offset 0), value1 its
`SizeOfImage`, so code Wine reads into anonymous memory (sections not page-aligned in the file) resolves
too. Coverage: a `pe_frames` note, and `pe_frames=16;pe_stack_bytes=512` in the `ebpf_active` detail.

- Coverage limit: only 512 bytes of PE stack are copied, so a frame larger than what is left (ping.exe's
  `main` takes 760 bytes) ends the unwinding and the scan of the rest may name stale addresses. A frame
  register other than rbp, an indirect unwind entry or a missing image also end it (packed code without
  `.pdata` is scan-only). ia32 Wine threads (TEB from their set_thread_area descriptor, syscall_frame at
  TEB+0x218, kernel_stack at TEB+0x23c) give eip and then the 4-byte stack words inside PE code
  (`pe_i386=1`; i386 images have no `.pdata`, so nothing is unwound). Under new WoW64 a thread would show
  its 64-bit side (`wow64*.dll`), not the 32-bit caller.
  Frames resolve against the images of the last maps scan, and a repeat-collapsed record keeps the
  first call's frames.

### Socket bytes and DNS

Every byte a tracked process sends or receives on an `AF_INET`, `AF_INET6` or `AF_NETLINK`
socket with `read`, `write`, `readv`, `writev`, `preadv2`, `pwritev2`, `sendto`, `recvfrom`, `sendmsg`,
`recvmsg`, `sendmmsg` or `recvmmsg` (all iovecs, every message) is logged. `mm_sys_exit` copies the bytes
the call moved (bounded by its result) into a separate 64 MiB ring (`payload_ring`) in 4 KiB
pieces with `bpf_loop`, before the call's record; the agent writes them as a `network_data`
payload on the call's own I/O record (`file_read`/`file_write`, or `network_connect`/
`network_accept` when the call names a peer), Base64 in 8 KiB chunks linked by `operation_id`
(docs/LOG_SCHEMA.md §4). Sent bytes carry `payload_input`. The detail adds
`endpoints=local -> remote` of the socket (`netlink=<protocol>` for netlink), and
`sendmmsg`/`recvmmsg` write one series per message with `msg=<index>` (value0 its bytes).
Calls that carry bytes are never collapsed into repeat counts. Wine's own socket I/O
(`sendmsg`/`recvmsg` from `ntdll.so`) is the game's path. `ebpf_active` names the settings
(`payload=on;payload_chunk=4096;payload_call_max=1048576`).

At most 1 MiB is captured per call; the rest is counted (`payload_partial`,
`payload_missing=<bytes>;payload_stop=limit`). A full payload ring or an unreadable buffer
stops that call's capture (`payload_stop=ring_full` or `fault`; `steps` after 4096 walk
steps; `truncated` when a `MSG_TRUNC` call reported more than its buffers held;
`chunks_lost` when the agent lost bytes the kernel captured, past its 64 MiB of held chunks). A
partial series keeps whole 8 KiB chunks only, and a call with none is one record flagged
`payload_unavailable`, its reason (`payload_ring_full`, `payload_fault`, `payload_truncated`,
`payload_chunks_lost`) first in the detail; `sendmmsg`/`recvmmsg` messages after the stop get one
such record with `msg_missing=<first>-<last>`. Such operations count as incomplete, as on Windows.

DNS messages to or from port 53 (UDP, and TCP with its 2-byte length framing across calls) are
parsed from those bytes in the agent (`agent/linux/dns.cpp`, self-tested by `build.sh`) into
`etw_dns` records: `text` the queried name, `detail`
`query_type=N;dns_id=N[;rcode=N;answers=TYPE value|...];transport=udp|tcp;server=address:53`,
value0 3006 for a query and 3008 for a response, `operation_id` the payload it came from.

`--no-payloads` turns all of this off in the kernel (`mm_config.flags`; the ring shrinks to
one page) and in the agent: no bytes and no `etw_dns`.

Limits:

- Most game traffic is TLS or the game's own encryption: it is logged as ciphertext. TLS through
  Wine's schannel (WinHTTP, WinINet, secur32) is also logged as plaintext ([Function probes](#function-probes));
  TLS inside PE code (OpenSSL or BoringSSL DLLs, CEF) and the game's own crypto are not.
- Only `AF_INET`, `AF_INET6` and `AF_NETLINK` sockets: not `AF_UNIX` or pipe contents (X11,
  D-Bus, Wine's named pipes) unless `--log-content` ([Contents](#contents---log-content)), never wineserver's
  protocol pipes (decoded instead), not `sendfile`/`splice`/`copy_file_range` into a socket, not io_uring,
  (ia32 processes are captured: compat msghdr/mmsghdr/iovec layouts.)
- `MSG_PEEK` reads are not captured (wineserver peeks one byte on every readable socket; the
  bytes are captured when they are read), nor `MSG_TRUNC` reads on TCP (the kernel discards
  those bytes without copying them).
- Bytes in pages not resident when the call returns (`payload_fault`) and calls that found
  the payload ring full (`payload_ring_full`) are missing; send buffers are read at the
  call's return, so another thread rewriting one during the call is seen rewritten.
- The client's pings (`IcmpSendEcho`, `IcmpSendEcho2Ex`) are not its own sockets: Wine's iphlpapi sends
  `IOCTL_NSIPROXY_WINE_ICMP_ECHO` to `\Device\Nsi`, and nsiproxy.sys opens the ICMP socket inside
  `winedevice.exe`, a Wine service outside the tracked tree. Neither the echo bytes nor its packets
  (pcapng) are captured, and the wineserver decoder records only AFD ioctls, not this one.
- DNS is parsed only from the client's own port-53 traffic: names resolved by another process
  (systemd-resolved's upstream queries, DNS-over-TLS or -HTTPS) are not seen.

Desktop services over `AF_UNIX` are named instead (`bpf/unix.bpf.h`, `bpf/unix_bpf.h`): a connect to X11
(`/.X11-unix/X<n>`, abstract or not), the D-Bus session or system bus, the AT-SPI bus, PulseAudio (`pulse/native`),
PipeWire or Wayland adds `service=<x11|dbus_session|dbus_system|atspi|pulse|pipewire|wayland>` to its
`network_connect`, and every later I/O record of that socket adds `service=;peer=<endpoint>`. In the kernel, a tracked
process's AF_UNIX connect makes the socket pending (`unix_svc`, a hash of 4096: a full one refuses the connect and
counts it, `ebpf_losses` `unix_full`, rather than dropping a live connection's state; a state leaves with its socket's
last reference, `fentry/unix_release`, optional group `unix`) and its first send says which protocol it opens: X11's
connection setup (`l`/`B`, protocol 11), D-Bus's credentials NUL and SASL `AUTH`, a PulseAudio control packet's
descriptor; any other socket (Wine's server socket, nscd, Chromium's IPC) leaves. On such a connection `unix_head`
(global BPF functions, so their paths do not multiply with `mm_sys_exit`'s; their instructions still count in its
verifier total, 626,036 now) gathers each `write`, `writev`, `sendto`, `sendmsg`, `sendmmsg`, `read`, `readv`,
`recvfrom`, `recvmsg` and `recvmmsg` over all its iovecs and messages, at most 4 KiB of it after the header part the
previous call ended inside (up to 256 bytes), payloads on or off, and frames every request or message in those bytes:
X11's requests of 4-byte units with BIG-REQUESTS lengths, an X11 server's 32-byte replies, errors and events with a
reply's or GenericEvent's length, PulseAudio's 20-byte descriptor and tagstruct command, D-Bus's 16-byte header,
fields and body (each message in its own byte order). A message the call only began is passed over in the next calls
and a header it cut is carried to the next, so a reader of any size stays in step:

- X11 and PulseAudio: every request or message is counted per socket and op in `agg`, a run of one op as one count. A
  sent op that is the first since the agent last drained `agg` is sampled (left out of its summary, calls and bytes):
  the call's bytes go to the agent as an `MM_UNIX` head before its record, and the agent writes one `etw_rpc` record per
  sampled request on the endpoint:
  `interface=x11;operation=<request>[;fields]` and `interface=pulse;operation=<COMMAND>`. The rest of each second
  are kernel summaries, `etw_rpc` on the endpoint with `repeats_tail;syscall=unix_service;aggregate=kernel;
  interface=;operation=;direction=sent|received;socket=<inode>;repeats_before=<messages>;repeat_bytes=<bytes>`.
  What the server sent is summaries only: `operation=reply`, `error:<error>:<request>` (the failed request named),
  `event:<event>` (`sent_event:` for a SendEvent's; XInput2 and Present GenericEvents by type, an extension's events
  and errors as `<EXTENSION>.event<n>`/`.error<n>`). So a per-frame X11 stream costs one record and one summary per
  op a second, and receives (input events at mouse rate) only summaries.
- Every core X11 request is named (`kX11Requests`), and extension requests as `<EXTENSION>.<request>`: the agent
  asks each display once, as any client would, for its extension table (a connection without authorization, or on a
  display that refuses one (monfilter's `--nested-x`) with the MIT-MAGIC-COOKIE-1 of the client that used it, read from
  its `XAUTHORITY` and never logged; the setup, one `QueryExtension` per name, closed; coverage `x11_display`
  `endpoint=;status=ok[;auth=client_cookie]|refused:...|skipped:tracked_server;extensions=XTEST:132,...`), so
  `XTEST.FakeInput`, `RECORD.CreateContext`, `X-Resource.QueryClientIds`, `MIT-SHM.GetImage`,
  `Composite.NameWindowPixmap`, `DRI3.Open`, `XInputExtension.XIQueryPointer`, `XFIXES.GetCursorImage` and the rest
  are named (`<EXTENSION>.<minor>` past the tables, `ext<major>.<minor>` on a display that refused the agent, and
  before its answer is in). The asking runs on a thread of its own, started at the client's connect, so no display
  holds the records up: one second a try, however the peer trickles its bytes; never a server whose `SO_PEERCRED`
  pid is tracked (a program's own listener at an `/.X11-unix/X<n>` name would see the agent ask, and get the cookie);
  the cookie only from a regular file of at most 64 KiB that the client's fs uid owns (no FIFO, device, symlink or
  another user's file, though the agent runs as root). The
  sampled request's fields say what it touches: `QueryExtension` and `InternAtom`'s `name=`, a window, property,
  type, selection or drawable, `GetImage`'s and `MIT-SHM.GetImage`'s area, a grab's window, `WarpPointer`'s place,
  `SendEvent`'s `destination=;event=`, `XTEST.FakeInput`'s `type=;root=;x=;y=`, `X-Resource.QueryClientIds`'
  clients, `RECORD`'s context and client and range counts. Property data, image bytes and keys are not: a
  `SendEvent` or `FakeInput` key or button is `input=withheld` without `--log-real-input`.
- D-Bus (a method is its strings): each call's messages, both ways, are listed at their starts in a head, at most 64
  heads a second per socket (the messages past them are summaries by type, `operation=method_call|method_return|
  error|signal`); the agent names each listed message from its start as
  `interface=dbus_*;operation=<interface.member>;[message=signal;]destination=;path=;serial=;sender=`, a reply as
  `operation=method_return;reply_serial=`, an error as `operation=error:<name>;reply_serial=`, received ones with
  `direction=received` (UDisks2's `GetManagedObjects` reply, a bus signal), a call or signal whose header fields the
  head does not hold by its type with `fields_cut=1`. A header whose fields fit 256 bytes is carried whole when a call
  cuts it, so GDBus (which reads the 16-byte header alone, then the rest) and libdbus (2048 bytes a read, wherever a
  message ends) are named alike. The SASL handshake's calls before (until a send ends in `BEGIN`, a receive starts a
  message) are summaries `operation=sasl`, their bytes a raw head the agent skips the lines of. Bodies are not read.

Bytes past the walk (past 4 KiB of a call, or 1024 messages) are summarized as `operation=unparsed` with their bytes;
a write past it stays in step (clients write whole requests, and a partial write's unsent rest is passed over), a
receive past it loses the framing and the socket's later receives are `unparsed` (xcb reads at most 4 KiB a call).
The bytes themselves are not logged (`--log-content` logs them as payloads). Cost: every recorded AF_UNIX call pays
one `unix_svc` lookup; a call on a service connection the gather (one user read per iovec, at most 4 KiB copied) and
one `agg` update per run of an op, about 0.5-2 us; a head crosses the ring only when an op is new that second (and
for D-Bus, at most 64 a second per socket), so the ring carries no more per call than the call's own record; every
AF_UNIX socket's release on the machine, one hash delete (`mm_unix_release`, about 0.1 us). The program is
preemptible: a task that runs `unix_head` on the same CPU meanwhile rewrites its per-CPU work, which is then counted
(`ebpf_losses` `scratch_reuse`, the call's bytes `unparsed`) and the socket's state left as it was. Limits:
PipeWire's and Wayland's protocols are only labelled; sockets connected before the process was tracked are not
walked; an X11 server's reply is not matched to its request (only errors name theirs).

**The log now holds secrets**: login tokens, passwords and chat sent without encryption,
server addresses, interface and MAC data from netlink replies, and window titles (wineserver
`get_window_text`). Bundles are marked `sensitivity=secrets` when the eBPF net sensor or the
wineserver decoder ran with payloads (otherwise `payload`); `redact_session.py` removes all of these
and marks its copy `metadata`; see docs/STORAGE.md. Record with `--no-payloads` for a log to share.

### Contents (`--log-content`)

Off by default: it records what the user and the programs exchange, not only that they did (privacy), and its
volume is the bytes themselves. With it:

- AF_UNIX and pipe bytes (X11, D-Bus, PulseAudio, Chromium's IPC, Wine's named pipes and RPC; never wineserver's
  protocol pipes, which are decoded) are captured as socket bytes are (`payload_ring`, up to 1 MiB a call, both
  directions) and logged as `network_data` payloads of at most one 8 KiB chunk a message (`payload_missing=;
  payload_stop=content_cap` for the rest), the record saying `content_bytes=<captured>;content_sha256=<of them all>`.
  Such records are never collapsed: one a call. Credentials a client sends over such a socket (X11's
  MIT-MAGIC-COOKIE, PulseAudio's cookie, D-Bus's SASL) are in them, and so is what the user types and copies,
  whatever `--log-real-input` says: X11 `KeyPress`/`KeyRelease` and XInput2 raw key events, selection (clipboard)
  transfers in X11 properties, an input method's D-Bus calls, a clipboard pipe, a launcher's IPC carrying a typed
  password. `--log-real-input` decides only the keys the decoders name (wineserver's input requests and messages,
  X11 requests' `detail=`).
- A DRM device's or a socket's `ioctl` argument struct as the call left it: `arg_bytes=<hex>` on its
  `file_device_control` record, 64 bytes (32 when 64 are not readable; a DRM ioctl's size field bounds it): GPU
  parameters, an interface's MAC address (`SIOCGIFHWADDR`), a wireless ESSID (`SIOCGIWESSID`).
- IRP results (`set_irp_result`) and overlapped I/O results (`get_async_result`, ioctl answers) as `ipc_data`
  payloads of all their captured bytes (8 KiB), not the first 1 KiB, with `--no-payloads` too.
- Clipboard data that passes wineserver: `set_clipboard_data`'s and `get_clipboard_data`'s `sha256=` (and
  `hashed_bytes=` past 8 KiB), its bytes not logged there (the X11 selection transfer of the same data is in the
  AF_UNIX bytes above).

`ebpf_active` and `wineserver_requests` say `content=on` or `content=off(--log-content)`. `--no-payloads` does not
turn it off; the payload ring stays 64 MiB when either is on. The bundle is marked `sensitivity=secrets`, and
`redact_session.py` drops the payloads, `arg_bytes=` and the content and clipboard hashes (docs/STORAGE.md).

### Socket join

Under Wine, wineserver creates, connects, binds, accepts and closes the sockets and the game only
reads and writes them (the same inode; wineserver's `connect` record carries it in `value0`, the
game's I/O names `socket:[ino]`). The agent joins them in user space (`agent/linux/socket_join.h`,
fed by `agent/linux/bpf_join.inc` from the syscall records; no BPF code): a socket one tracked
process made is attributed to every other tracked process that reads or writes it.

- At that process's first I/O on the socket: a `network_flow_established` for it, with the maker's
  endpoint in `text`, the inode in `value0`, protocol and port packed in `value1`,
  `status` 0 (the maker's errno, e.g. -115 EINPROGRESS, is `creator_status`), flag and attribution
  `service_correlated`, no stack, and `detail` starting with how the maker got it (`connect;`,
  `accept;`, `bind;` or `listen;`), then `family`, `type`, `creator_pid`, `creator_start`,
  `creator_status`, `creator_time`, `first_use` (the call) and `first_use_ret`.
- Its `network_flow_close` (same `value0`, so `tools/analysis/network_timeline.py` pairs them):
  `close;service_correlated;reason=...;bytes_sent=N;bytes_received=N` and the creator fields. The
  bytes are what that process moved on the socket, without MSG_PEEK reads and sendmmsg/recvmmsg
  (which return message counts). It is written when the maker closes the socket or exits
  (`socket_closed`) or leaves scope (`untracked`), the process exits (`process_exit`) or leaves
  scope (`untracked`), the inode returns from `socket`/`accept` (`inode_reused`) or tracking stops
  (`session_end`).
- Several processes on one socket each get their own pair. The process's own closes stay plain
  `close;` records and end nothing: Wine clients close per-call fds.

One game connect thus gives the wineserver `network_connect` (`syscall=connect`), the game's request
view (`ws=ioctl`, wineserver upgrade) and the game's flow pair, with no type repeated. Coverage
note: `socket_join`.

Limits (`shortcut:` comments in `socket_join.h`): only sockets made while the agent runs are known;
a socket its maker never bound or connected (a UDP socket the game only `sendto`s on) is not joined,
nor is one whose connect failed other than with EINPROGRESS; a lost connect (ring full) leaves a
socket unjoined, a lost close of the maker delays the flow close to an exit or the agent stop, and
lost I/O records are missing from the byte totals, as are bytes
`sendfile`/`splice`/`copy_file_range` move into a socket (only their input fd is resolved; bytes
they take out of one count as received); a helper that hands its socket to another process and
closes its own fd ends the join early.

### TCP lifecycle

TCP connections are followed as Windows follows them with `Microsoft-Windows-TCPIP`
(`tp_btf/inet_sock_set_state`, `tcp_receive_reset`, `tcp_send_reset`, `tcp_retransmit_skb` and
`lsm/sock_graft`, group `tcp`). A socket is followed once it carries a socket tag (`socks`: a
tracked process created, connected, sent or received on it; a listener's connections carry its tag
from the handshake on; `accept()` tags the accepted socket), and its state changes, the resets it
receives and sends and its retransmissions are logged as `etw_tcp` for the tag's first tracked user,
never for whatever task the CPU was running (most of them happen in softirq context). Under Wine that
user is wineserver (it calls `connect()` and `accept()` for every process of the prefix);
`user_pid=<pid>` names the game once it sent or received on the socket, and `sock_ino` joins the
game's `socket:[ino]` records. `text` is `local -> remote`, `value0` the Windows event id (0 for
`state_change` and `retransmit`, which have none), `value1` the socket cookie (one per connection;
the packet capture's pcapng comments carry the same cookie), `status` the negative socket error.
`detail` is `event=<name>`, `from=`/`to=` (state changes) or `state=`, `sock_ino`, then `user_pid`,
`err`, `shutdown` (1 receive, 2 send side shut), `orphan=1` (no descriptor left), `reason` (resets
sent, the kernel's `sk_rst_reason` name), `rexmit` (retransmissions so far), `srtt_us`,
`bytes_acked`, `bytes_received`.

Names: `SYN_SENT -> ESTABLISHED` connect_completed; `SYN_SENT -> CLOSE` connect_failed
(connect_timeout on ETIMEDOUT, abort_issued without an error); an accept accept_completed;
`ESTABLISHED -> FIN_WAIT1` and `CLOSE_WAIT -> LAST_ACK` close_issued (`shutdown=2` is
`shutdown(SHUT_WR)`, 3 a close); `ESTABLISHED -> CLOSE_WAIT`, `FIN_WAIT1 -> CLOSING` and
`FIN_WAIT2 -> CLOSE` of a socket still open fin_received; `LAST_ACK`, `CLOSING` or a closed
`FIN_WAIT2 -> CLOSE` disconnect_completed; `-> CLOSE` after a timeout retransmit_timeout
(keepalive_timeout when nothing was being retransmitted, by `icsk_retransmits`: the kernel purges
`packets_out` before that `CLOSE`; disconnect_timeout from `FIN_WAIT1`, `CLOSING` or `LAST_ACK`);
`-> CLOSE` without an error from a data state
abort_issued (a reset_sent with its reason follows); a received RST reset_received
(`state=SYN_SENT`: the connect was refused); every other transition state_change. Retransmissions
(`connect_retransmit` in `SYN_SENT`) are collapsed per connection like syscall repeats, and the counts
still held are written before the connection's `CLOSE` record, as the generic `repeats_tail` record
(value0 0, value1 the count, not the cookie: join it by `text`, the endpoints). Records carry
`observer_record`, as on Windows. `fin_received` before the owner's
`close_issued` means the remote closed it; `reset_received` that the remote reset it.

Limits (`tcp_lifecycle` coverage record): connections no tracked process touched since tracking
began, the TIME_WAIT/FIN_WAIT2 minisocket that replaces a closed socket (the remote FIN after
`close()`, FIN-WAIT-2 timeouts) and resets sent for segments no socket owns (a SYN to a closed port)
are not seen. `--no-etw` does not turn it off; `--no-ebpf` does.

### Packet capture

The client's packets are written as pcapng beside the events: `events.pcapng` in a bundle
(`<output stem>.pcapng` otherwise), rotated at the events' part size (`--max-file-mb`) into
`events.pcapng.1`, `.2`, ... on its own byte count: `events.pcapng.N` does not cover the same time as
`events.jsonl.N`; each part's `first_utc` and `last_utc` are in its `packet_capture_part` record.
Every IP packet (TCP, UDP, ICMP of the client's own ping sockets; IPv4 and IPv6; both directions, handshakes,
retransmissions, RST and FIN included) of a socket a tracked process used is kept, up to 64 KiB per packet
(`orig_len` keeps the full length; the cut is counted as `truncated`).

- **Kernel side** (`bpf/pkt.bpf.h`, optional group `packets`): `mm_skb_egress` and `mm_skb_ingress`
  are `cgroup_skb` programs attached to the cgroup v2 root `/sys/fs/cgroup` with a BPF link
  (`BPF_F_ALLOW_MULTI`, so they run beside systemd's and kfilter's programs). They always return 1:
  traffic is never dropped or changed. A packet is copied (`bpf_skb_load_bytes`, from the IP header)
  to the 32 MiB `pkts` ring only if its socket carries an `mm_socks` tag, which the socket LSM hooks
  (`socks`) set when a tracked process creates, connects, sends or receives on it. Ring overflows are
  counted in `pkt_drops` and reported as `ring_drops`.
- **Format**: one interface, `LINKTYPE_RAW` (101), `if_tsresol` 10^-7 s (the log's FILETIME unit),
  snaplen 65536. One Enhanced Packet Block per packet with the capture time, the direction in
  `epb_flags` (1 inbound, 2 outbound) and an `opt_comment`
  `pid=<owner>;process=<comm>;socket=socket:[<inode>];cookie=<cookie>[;wineserver=<pid>][;held=1][;gso_segs=<n>][;pending_skipped=<n>]`.
  The cookie is the socket cookie: the same number is `value1` of the tcp upgrade's `etw_tcp`
  records, the join key between the two.
- **Attribution**: under Wine, wineserver creates and connects the sockets of its clients, the Nexon
  launcher's too. A socket is the game's once a tracked process other than wineserver sends or
  receives on it (the tag's `owner`). Until then the kernel captures at most 256 KiB of it
  (the rest is counted, `pending_skipped`) and the agent holds those packets (16 MiB in all; past
  it the socket held longest is dropped, counted in `held_overflow`, so a new socket's handshake is
  always kept): they are written, marked `held=1`, when the owner appears, and dropped, counted as
  `unattributed_*`, when its maker (wineserver; without one, the owner) closes it or the session
  ends; another process's close of its own per-call fd ends nothing. A close takes effect only after
  the `pkts` ring was read to its end, so a socket's last packets (a FIN that attributes it) are
  never outrun by its close event. A packet that raced the owner's first send/recv on another CPU
  (still `owner` 0) is written with the owner already known for its cookie.
- **Chain**: each closed part becomes a `packet_capture_part` coverage record (path, part, packet
  count, wire and captured bytes, file size, SHA-256, first and last time, ring drops) in the hash
  chained log; `packet_capture` totals it at the end. `packet_capture_active` at start names the
  settings; `packet_capture_unavailable` says why there is no capture (no eBPF, the group refused,
  an attach failure: then neither direction stays attached); `packet_capture_disabled` is written
  under `--no-packets` or `--no-payloads`. The parts are listed in `checksums.json` like every
  bundle file (docs/STORAGE.md).
- **Hashing**: a closed part is hashed on its own thread, so a rotation never stalls the BPF thread
  that also drains the events ring.
- **Detach**: at the end the final drain has the BPF thread destroy both links, read the `pkts`
  ring to its end and the drop count, and only then writes the `packet_capture` totals (after 5 s
  without that they carry `final_read=timed_out`). The links are also destroyed when the agent exits;
  the kernel detaches them when the agent is killed (their fds close). `tests/ebpf_checks/packets.sh`
  checks both with `bpftool cgroup show`.

Limits: a GSO/GRO super-packet is captured as one packet as the socket saw it (`gso_segs`
in the comment, `gso_packets` in the totals), not as the frames on the wire, and may exceed the MTU
and the 64 KiB cut. Packets the kernel sends for a socket that no longer has a full socket (TIME_WAIT
ACKs, RSTs for unknown ports) are not captured, nor are ICMP errors about the game's traffic (port
unreachable, fragmentation needed: the kernel handles them without the socket's receive filter) or
ICMP the kernel generates itself; only ICMP of ping sockets is, and only of the client's own: Wine's
`IcmpSendEcho` pings leave from `winedevice.exe` (nsiproxy.sys), outside the tracked tree, and are not
captured (see Socket bytes and DNS). The SYN, SYN-ACK and final ACK of a
connection the game accepts carry the listener's cookie and inode (the kernel runs the programs on
the listener): they are attributed only when the listener has an owner, and their cookie is not the
accepted socket's `etw_tcp` `value1`. The maker's close of any of its fds of a socket counts as the
socket's end for held packets. Packets of the probe's loopback exchanges appear twice (egress of one socket, ingress
of the other). pcapng parts contain the game's traffic in clear (keep them like `sensitivity=secrets`
bundles).

### Wineserver requests

Under Wine the client asks wineserver for registry access, handle opens, file creates, named
pipes and sections, enumerations and socket connects; wineserver then makes the Linux syscall, so
the syscall records name wineserver. `mm_ws_enter` copies every request a tracked Wine thread
writes to its request pipe (the fds in its TEB: GS base on x86_64, the `set_thread_area` TLS entry
on ia32; the request fd must be a pipe): the 64-byte fixed part and up to 8 KiB of its data, but for
the hot requests it counts in the kernel (below). A
thread's first request (`init_first_thread`, `init_thread`) names its reply and wait pipes before its
TEB is in use; `ws_early` keeps them, so Wine's start-up requests (the DllOverrides, AppDefaults and
Image File Execution Options keys) are captured too, without Windows ids, their replies read on the
reply pipe's inode.
`mm_ws_exit` copies the reply it reads back (64 bytes, plus up to 8 KiB of data for registry
values, enumerated names, volume information, window text, messages, ioctl and async output, and the
replies whose only vararg is a string). `agent/linux/wineserver.cpp` decodes protocol 930 (wine-11.0)
into records of the requesting process and thread, with its user stack and (pecaller) PE frames;
`status` is the reply's NTSTATUS. Every request is recorded: by a decoder of its own (the table), or
by the generic decoder (the last rows):

| Request | Record |
|---|---|
| `open_key`, `create_key`, `delete_key`, `enum_key`, `get_key_value`, `set_key_value`, `enum_key_value`, `delete_key_value`, `rename_key` | `registry_*`: text the full key path (handles are tracked from replies and forgotten at `close_handle` or when the handle value is given out again; an unknown one is `hkey:0x..`), detail the value name; set/query/enumerated values are `registry_value` payloads as on Windows |
| `open_process`, `open_thread`, `dup_handle`, `debug_process`, `get_next_process`, `get_next_thread`, `new_thread` | `process_handle` / `thread_handle`: `desired_access`, target the unix pid when the Windows pid belongs to a tracked client, detail `open_process;win_pid=N;handle=..`. As with the Windows Ob callbacks, handles to the requester's own process or threads write no such record (a generic one instead). Process handles are learned from `open_process` and `new_process` replies (and `close_handle`, a generic record, forgets a handle); a `dup_handle` copy, also one within the process, inherits its source's target and access, and pseudo handles are the caller's own process or thread. A `get_next_process` handle names no Windows pid, and a `get_next_thread` handle no thread id |
| `read_process_memory`, `write_process_memory` | `process_handle`, value0 1 / 2, value1 the length, detail with handle, `win_pid` and address (collapsed only when handle, address and length repeat) |
| `new_process` | `process_handle` as the creator's handle to its child (Windows' process-create notify): `desired_access`, value0 1, detail `new_process;win_pid=<child>;process_flags=..` with `parent_override=` (a PROC_THREAD_ATTRIBUTE_PARENT_PROCESS handle's Windows pid), `debug=1`, `token=1` when given, then `win_image=`, `curdir=`, `desktop=` and last `win_cmdline=` (the whole Windows command line, within the 8 KiB captured; `;truncated` when cut); `redact_session.py` redacts it without `--keep-commands` |
| `create_file`, `open_file_object`, `create_named_pipe` | `file_create`: text the unix path (`create_file`) or the NT name, detail `create_file;nt=...`, value0 disposition << 24 \| options, value1 the handle |
| `create_mapping` (named only), `open_mapping` | `file_section`, value0 the `SEC_*` flags; detail `file_access` (what ntdll derived from the page protection, which wineserver never sees) |
| `get_volume_info` | `file_query_volume_information`, value0 the class, a `volume_information` payload |
| `list_processes`, `get_system_handles`, `get_window_list`, `get_window_tree`, `get_window_text`, `get_tcp_connections`, `get_udp_endpoints` | `file_query_information`, text `system:<request>`, value1 the count (`get_window_text`: the text length; `get_window_tree`: 0, detail `;parent=0x..`); `get_window_text` adds `;text=` (with payloads) or `;text_bytes=N` |
| `ioctl` AFD connect / bind / listen / accept | `network_connect` / `network_accept`: text the endpoint, value0 0, detail `connect;family=2;ws=ioctl;afd=connect;socket=..`; status the ioctl's (a pending connect is `0x103` with `;pending`: Wine completes it by APC, and netattr's `network_flow_established` gives the outcome) |
| `ioctl`, every other code (DeviceIoControl, NtFsControlFile) | `file_device_control` as the minifilter's: text the handle's NT name, value0 the code, value1 the input bytes, detail `ioctl;ws=ioctl;handle=;code=;out_size=` and a synchronous answer's `out_bytes=;sha256=` (its first 1 KiB an `ipc_data` payload); collapsed per handle and code (a kernel aggregate, below) |
| `get_thread_context`, `set_thread_context`, `suspend_thread`/`resume_thread`, `suspend_process`/`resume_process`, `terminate_process`/`terminate_thread`, `set_thread_info`, `set_process_info`, `get_process_info`, `get_process_image_name`, `get_process_vm_counters`, `get_process_debug_info`, `get_thread_info`, `get_thread_times`, `get_mapping_filename`, `queue_apc`, `get_apc_result`, `create_debug_obj`, `continue_debug_event` | `process_handle` / `thread_handle` of the handle's target (value0 the request, desired_access the handle's access), detail `<request>;handle=..;win_pid=|win_tid=..` plus `flags=` and `dr0..dr7=` (the debug registers of the reply's or request's context), `count=`, `exit_code=`, `hide_from_debugger=1`, `image=`, `address=;name=`, or the APC: `type=virtual_alloc|virtual_protect|virtual_query|map_view|create_thread|...;addr=;size=;prot=` (VirtualAllocEx, VirtualProtectEx, NtMapViewOfSection into another process, CreateRemoteThread), its result `apc_result;...;status=;addr=;size=`. The caller's own process and threads write nothing, except debug-register context and hide-from-debugger. `set_thread_context`, `queue_apc`, terminate and set-info are never collapsed; a `get_process_info`/`get_thread_info` reply names a `get_next_process`/`get_next_thread` handle |
| `create_*`/`open_*` of events, keyed events, mutexes, semaphores, timers, mailslots, object directories, symlinks, completion ports, jobs; `open_winstation`, `open_desktop` | `file_create`, text the full object path (the rootdir's name, e.g. `\Sessions\1\BaseNamedObjects\Global\X`), value0 FILE_OPEN_IF (create) or FILE_OPEN (open) << 24, value1 the handle, detail `<request>;object=<kind>` (`target=` of a symlink); unnamed objects write nothing; collapsed by name |
| `open_token`, `create_token`, `duplicate_token`, `filter_token`, `create_linked_token`, `adjust_token_privileges`, `get_token_privileges`, `get_token_info`, `make_process_system`, `grant_process_admin_token` | `process_handle` of the token's process (the caller's own too), detail `<request>;handle=..;win_pid=..` with `privs=SeDebugPrivilege(enabled),...`, `count=`, `elevated=` |
| `get_security_object`, `set_security_object` | `file_query_security` / `file_set_security` of a file, key or named object (text its name), value0 the SECURITY_INFORMATION, value1 the descriptor bytes; a process's or thread's as `process_handle` / `thread_handle` |
| `get_directory_entries`, `query_symlink`, `get_object_name`, `get_object_type`, `get_object_types`, `enum_winstation`, `get_handle_unix_name`, `add_atom`, `find_atom`, `add_user_atom`, `set_hook`, `send_hardware_message`, `register_hotkey`, `attach_thread_input`, `get_key_state`, `set_key_state`, `get_last_input_time`, `get_cursor_history`, `set_cursor`, `get_rawinput_buffer`, `update_rawinput_devices`, `set_clipboard_data`, `get_clipboard_data`, `set_clipboard_viewer`, `add_clipboard_listener` | `file_query_information`, text `system:<request>`, value0 the request, detail `ws=<request>;object=..` with `target=`, `name=`, `type=`, `unix=`, `atom=`, `names=` (directory entries, with payloads), `hook=keyboard_ll;scope=global;module=`, `input=keyboard;vkey=..;injected=1`, `format=;bytes=` (clipboard contents are not kept); target another process whose window, thread or hook it names. Injected input (SendInput) and cursor moves and clips are records each; winex11's own input (the user's keys and mouse moves) and cursor shape changes are kernel aggregates per type, their first of a second recorded with `injected=0`, a key without its `vkey`/`scan` (with `--log-real-input`: with them, and every key recorded). Not a record each by default: that would log the user's typing rhythm and mouse path, and the cursor's shape changes with mouse moves |
| `send_message` (SendMessage, PostMessage, SendNotifyMessage, PostThreadMessage) | `file_query_information` `system:send_message`, value1 the message, target the destination (the thread id's process, else the window's creator; none for the sender's own threads and windows), detail `ws=send_message;type=other_process|posted|notify|...;to_tid=;win=;msg=;wparam=;lparam=;data_bytes=;sha256=;flags=;timeout=` (a keyboard message: `input=withheld` without `--log-real-input`); collapsed per destination and message |
| `get_message` | `file_query_information` `system:get_message`, value1 the message: what the thread received, `win=;msg=;type=;wparam=;lparam=;x=;y=;time=` (keyboard messages, raw input and low-level keyboard hook calls: `input=withheld` without `--log-real-input`); nothing waiting (STATUS_PENDING): the request's fields only; collapsed per window and message. Captured per call with its reply (not a kernel aggregate: what was received is only in the reply; about 50 a second under the game) |
| `get_async_result`, `set_irp_result` (and the result `get_next_device_request` carries for the IRP before) | an overlapped I/O's output (`system:get_async_result`, `out_bytes=;sha256=`); a driver's answer to an IRP as the IRP's record (`file_device_control` for an ioctl, text the device, target the client, value0 the code, value1 the information, detail `irp_result;irp=;code=;status=;information=;out_bytes=;sha256=;client_win_tid=;driver=`, status the IRP's); the output's first 1 KiB is an `ipc_data` payload (capped), its SHA-256 over all that was captured (`hashed_bytes=` when the output was longer than 8 KiB) |
| `create_window`, `destroy_window` | generic (below); their replies keep the window's creator, so `send_message` and the window requests of another process's windows name it as the target (a window made before the agent watched has none). The kernel keeps the same owners in `ws_windows` (by the handle's user-handle index, `(low word) >> 1` as wineserver's `handle_to_entry`, with its generation: a handle passed as its low word alone, or with 0 or 0xFFFF as its high word, names the same window) for the window probes ([Function probes](#function-probes)); the windows wineserver frees with their thread or process (no `destroy_window` reply) leave it when the agent reads that thread's exit or the process's end, each while the entry still names that window |
| Every other request, numbers past the table (`unknown`, `req=`), and the own-process, unnamed and bookkeeping cases above | `file_query_information`, text `system:<request>`, value0 the request, detail `ws=<request>` and every fixed field of the protocol-930 table (`;<field>=<value>`: handles and flags hex, counts and Windows ids decimal, rectangles as four ints), a handle's name or Windows id when the decoder knows it (`;<field>_name=`, `_win_pid=`, `_win_tid=`, at request time), a sole UTF-16 vararg (`;name=`, `;class=`, ...; window text only with payloads, else `text_bytes=`), object attributes (`;rootdir=;name=`), else `;data_bytes=`, the reply's fields (`;reply_<field>=`) and string; bytes of the fixed part no field covers (Wine zeroes them: a field the table lacks, or what a hand-made `wine_server_call` carries) as `;unknown@0x<offset>=0x<word>` (`;reply_unknown@`). Target another tracked process a handle, window or Windows id names; collapsed per request and its first field (`set_window_pos`: its window; `close_handle` and `accept_hardware_message` per request: close_handle is 170 calls a second under the game, nearly each of a handle of its own, so only the first of a second names its handle). `init_thread` (sent through `ws_early`, before the TEB is in use) gives a new thread's start address as `entry=` |
| a write on a request pipe that is not one whole request of the writer's thread | `file_write`, text `pipe:[<inode>]`, target the pipe's owner, value0 the syscall's count, detail `request_pipe_rejected;reason=chunks|resumed|size|unreadable|form|total|foreign_pipe|splice|other_call;syscall=;fd=;count=;owner_pid=` and `req=;request_size=` of a header it carried (`total`: writev chunks that hold more or less than request_size, checked before a hot request is aggregated, since wineserver would read the rest as another request; `other_call`: pwritev2 or sendfile). kfilter refuses these in block mode for a protected program, but `total`, another thread's pipe of the same process, and sendfile (it fills a pipe without file_permission). One record each, also counted as `ebpf_losses` `ws_rejected`. Not checked here: io_uring and AIO writes into a request pipe (only their own `via=io_uring`/`via=aio` records) |
| `get_window_info`, `get_window_parents`, `get_class_windows`, `get_window_children_from_point`, `get_window_rectangles`, `get_window_property`, `get_thread_input`, `get_clipboard_info` (Wine 11 answers its own windows in-process, so these are mostly about windows of other processes) | `file_query_information`, text `system:<request>`, value0 the request, detail `ws=<request>;window=..` with `offset=<GWL_*>;info=<value>` (GetWindowLong, GetWindowInfo), `class=`/`atom=` (FindWindow; value1 the windows found), `x=;y=` (WindowFromPoint; value1 the windows), `window_rect=;client_rect=` (GetWindowRect), `name=;data=` (GetProp), `tid=` (GetGUIThreadInfo; target the client owning that thread), `owner=;seqno=` (GetClipboardOwner, GetClipboardSequenceNumber). Collapsed per window and question; the reply's values and the point stay out of the key |
| `set_fd_disp_info`, `set_fd_name_info`, `set_fd_eof_info`, `read_directory_changes` | `file_set_information` as the minifilter's: value0 13 (`delete;`), 10 (two records `rename;from;` / `rename;to;...;unix=`), 11 (`link;target=`), 20 (value1 the size); `file_directory_control` value0 2 (notify change directory), value1 the filter. Text the handle's NT name |
| `map_view`, `map_image_view`, `unmap_view` | `file_section`, text the section's name or file, value0 the base, value1 the size, detail `base=;size=;entry=;machine=` (an image view: the loader's own load); `unmap_view` of an image view is that module's unload (FreeLibrary): `image_unload=1`, never collapsed |
| `save_registry`, `load_registry`, `unload_registry`, `set_registry_notification` | `registry_query` (`save_registry;file=`, `notify;filter=`), `registry_create` (`load_registry;file=`), `registry_delete` (`unload_registry`) |

Handles are named across processes: a `dup_handle` into another tracked client gives the copy the source's name
there, a child created with inherited handles (`new_process` with PROCESS_CREATE_FLAGS_INHERIT_HANDLES, or its
handle list) starts with its parent's names at the same values, `alloc_file_handle` names its handle from
`/proc/<pid>/fd`, and `get_object_name`/`get_handle_unix_name` replies name a handle not seen opened. Named-pipe
and device reads and writes carry their bytes as an `ipc_data` payload (the first record of a collapse window), and
an RPC request its stub's first 1 KiB (`stub_bytes=`), with svcctl's `service=`, `access=` and `binary=`
(ROpenServiceW, RCreateServiceW) decoded.

wineserver's own syscalls name the client they serve: `mm_ws_exit` sees wineserver (comm `wineserver*`) read a
64-byte request header from a request pipe `mm_ws_enter` registered (`ws_pipes`: each tracked Wine thread's
request, reply and wait pipe inodes) and keeps that client in `ws_serving` until wineserver polls again;
`mm_sys_exit` then gives wineserver's records `target_process_id` the client, `service_correlated`, and
`;served_pid=<pid>;served_request=wineserver:<request>;attribution=brokered_wineserver` (unlink and rename of the
client's files, ptrace on its debug registers, process_vm_readv, AFD socket calls). Async completions, timers and
process-exit cleanup serve no one. The reads and writes of the protocol pipes themselves (millions under Wine) are
counted only (`syscall_counts`), not recorded: the requests they carry are decoded above.

Hot requests are kernel aggregates (`ws_agg`, the [kernel aggregates](#kernel-aggregates)' maps, key
`MM_COUNT_WS | request`), once their writev's chunks are found to add up to request_size: select (flags), event_op (handle, op), get_async_result, ioctl (handle, code; not the
AFD and pipe-transceive codes), remove/add_completion (handle), get_thread_completion,
set_async_direct_result, set_queue_mask, get_queue_status, start/finish_hook_chain (hook id), get_hook_info,
recv/send_socket (socket), get_handle_fd and get_mapping_info (handle), accept_hardware_message,
send_hardware_message (flags, type; not injected input) and set_cursor (flags; not moves and clips). The first
call of a key since the agent's last drain is captured whole (its record carries `;aggregate=sampled`; one
within a second of the one before is folded into the agent's own repeats of it); the others
are counted, and each second a summary `system:<request>` (`linux.ebpf_wineserver`, value1 the calls) says
`repeats_tail;syscall=wineserver:<request>;aggregate=kernel;ws=<request>;<key fields>;repeats_before=;repeat_bytes=0;repeat_span_us=;errors=0`.
`wineserver_request_counts` has every request as `recorded=1`. Other repeats are collapsed as for syscalls
(pseudo syscall 1000 + request, name `wineserver:<request>`). A request whose reply never came is
written with `;no_reply` (except when the agent stops: those are not written). The decoder runs for a process only when the `ntdll.so` it maps holds the
`wine-11.0` build string (Wine refuses a server of another protocol; a client already gone when its
first request is drained gets the last `ntdll.so` seen, `;assumed=1`); the first request of each
process writes a `wineserver_decoder` coverage record (`active=1;build=wine-11.0;protocol=930;ntdll=...`),
and the session notes `wineserver_requests` or `wineserver_requests_unavailable`. With
`--no-payloads` the records keep their metadata only. Limits: a value whose captured bytes are
short of the whole (over about 8 KiB minus its name for `set_key_value`/`enum_key_value`) is
`payload_unavailable` with `payload_truncated;value=<name>` (also when a data page was not yet
faulted in at the request); a query whose buffer is smaller than the value (a size probe:
wineserver answers success) has no payload and `;buffer=N` in the detail; one over 8 KiB read back by
`get_key_value` is its first 8-KiB chunk of a partial series; keys opened before tracking are
named by handle; ia32 clients get PE frames from their i386 TEB (`pe_i386=1`).

A winedevice.exe that was already running when the agent started (the prefix's services.exe is
tracked as a broker, so this happens only when the prefix was up before the agent) is joined late:
the agent writes one `driver_load` per `.sys` mapped in it (detail `reconstructed=1`) and resolves
IRPs on devices it never saw created through the driver objects in winedevice's memory (x64 only).

Without the kernel sensors (`--no-ebpf`, no root, or an agent built without clang):

| Sensor (slot) | Source | Records |
|---|---|---|
| `linux.fanotify` (40/44) | fanotify mount marks: `FAN_ACCESS`, `FAN_MODIFY`, `FAN_CLOSE_WRITE`; filesystem marks with `FAN_REPORT_DFID_NAME`: `FAN_CREATE`, `FAN_DELETE`, `FAN_MOVE` | `file_read`, `file_write`, `file_close`, `file_create`, `file_set_information` (value0 13 = unlink, 10 = rename; detail `unlink`, `rename;from`, `rename;to`) |
| `linux.proc_connector` (41/45) | netlink process-events connector | `process_start` (fork from a tracked process = inherited; exec of an image under a root = explicit; a tracked exec is logged again with value1 = 1), `process_exit` |
| `linux.maps_poll` (42/46) | `/proc/<pid>/maps` on track, on an executable file mmap/mprotect, and every 2 s (also with the kernel sensors) | `image_load` per executable file mapping (value0 base, value1 span) the kernel sensors did not already write (fallback: native PE images whose sections Wine reads into anonymous memory, mappings made at exec) |
| `linux.net_poll` (43/47) | `/proc/net/{tcp,tcp6,udp,udp6}` every 1 s, owners via `/proc/<pid>/fd` | `network_connect`, `network_accept`, `network_flow_close` (value0 socket inode) |

Process identity is PID plus start time (from `/proc/<pid>/stat`, in FILETIME units).
Paths come from the event fd (`/proc/self/fd`) or the directory handle plus name; an
unresolved path sets `missing_path` (the entry name stays in the detail).

### Function probes

`agent/linux/bpf/up.bpf.h` (agent: `bpf_up.inc`), optional group `uprobes` (`mm_up_*`; `ebpf_active`
`uprobes=`, coverage note `function_probes`): uprobes on functions Wine answers inside the process, with
no syscall and no wineserver request. As kfilter's `kb_win32k`, each library is one `uprobe_multi` link per
file for every process that maps it, and the programs return at once for an untracked process: another
Wine prefix using the same install (or, for `libgnutls.so.30`, any GnuTLS program) takes the trap but
records nothing. The `ntdll.so` and `win32u.so` of the Wine installs kfilter decodes (`/opt/wine-stable`,
`-staging`, `-devel`, `/usr/local`) are probed at start; any other library when a tracked process first
maps it executable: the copy thread spots the mmap record as it leaves the ring and a worker thread
attaches (about 8 ms a link), so neither the record processing lag nor the attach holds anything up; a
joined process brings the ones its maps already hold. The functions' file offsets come from each library's
`.dynsym`, read by the agent (libbpf 1.3's lookup by name finds none). The agent raises its open-file
limit to the hard maximum for the links. Observation only.

- `win32u.so` (x86_64-unix and i386-unix): `NtUserGetAsyncKeyState`, `NtUserGetKeyState`,
  `NtUserGetKeyboardState`, `NtUserGetCursorPos`/`GetCursorInfo`, `NtUserGetForegroundWindow`,
  `NtUserGetGUIThreadInfo` (Wine 11 serves these from desktop shared memory), `NtUserBuildHwndList`,
  `NtUserInternalGetWindowText`, `NtUserGetClassName`, `NtUserFindWindowEx` (with the class name),
  `NtUserGetClipboardData`, raw input, `NtUserSetWindowsHookEx` (hook id, module name),
  `NtUserSetWinEventHook`, `NtUserSendInput`, `NtUserGetDC`/`GetWindowDC`, `NtUserPrintWindow`,
  `NtGdiBitBlt`/`StretchBlt`
  (keyed by source DC: a screen capture), `NtGdiGetPixel`, `NtGdiGetDIBitsInternal`, display and adapter
  enumeration. `ntdll.so`: `NtQuerySystemInformation(Ex)`, `NtQuery/SetInformationProcess`,
  `NtQuery/SetInformationThread`, `NtQueryVirtualMemory`, `NtGet/SetContextThread`, `NtQueryObject`,
  `NtCreateThreadEx`, `NtQueryLicenseValue`, `NtQuerySystemEnvironmentValue(Ex)` (with the name),
  `NtSystemDebugControl`. Each call is a `file_query_information` `system:<function>` with
  `call=;args=<six>;[class_name=;][handle=self;][string=;]library=<arch>-unix/<file>` and the call's PE
  frames (the caller in user32.dll, the client's module); value0 the key argument (virtual key, class,
  handle, window, source DC), value1 `calls_skipped`. One record per process, function and key argument
  per second (`NtQueryVirtualMemory`: handle and the address's page, so each page a VirtualQuery(Ex) walk asks
  about keeps its record, at most 64 pages a second per process: past them the calls are kernel summaries
  `repeats_tail;syscall=NtQueryVirtualMemory;aggregate=kernel;key=<handle>;repeats_before=;repeat_offsets=<the
  pages' range>`, so a walk of thousands of regions costs no more than 64 records a second); the calls in between
  are counted in BPF (`calls_skipped=N` on the next one; those still held at the stop are
  `repeats_tail;syscall=<function>;key=;[page=;]repeats_before=N` records), so polling costs a trap (about 1-2 us)
  per call but no ring record. Arguments are SysV registers on x86_64 (Wine
  11's unix side) and the stack on i386. Return values are not read.
- Window functions, only with `--window-probes` (off by default; `function_probes` says `window_probes=`):
  `NtUserCallHwndParam` (GetWindowThreadProcessId, GetWindowLong, GetClassLong, GetWindowRect of any window: Wine 11
  answers them from the shared user handle table with no request; keyed by window and code,
  `class_name=GetWindowThread|GetWindowLongW|...`), `NtUserMessageCall` (SendMessage, SendMessageTimeout,
  SendNotifyMessage, DefWindowProc, CallWindowProc...: keyed by window and message, `class_name=` the call type),
  `NtUserPostMessage` (keyed by window and message), `NtUserSetWindowLong`/`NtUserSetWindowLongPtr` (keyed by window
  and offset, `class_name=GWLP_WNDPROC|GWL_STYLE|...`: another program's window procedure replaced is subclassing) and
  `NtUserSetWindowPos` (keyed by window; its seventh argument, the flags, is not read). The kernel leaves out every
  call on a window the caller made (`ws_windows`, from `create_window` replies: [Wineserver
  requests](#wineserver-requests)) or on none (NULL: the caller's own queue), before the rate limit: only other
  programs' windows are recorded, `target_process_id` and `owner_pid=` their owner, `owner=unknown` for a window made
  before tracking (or a broadcast), `msg_name=WM_GETTEXT|WM_COPYDATA|WM_CLOSE|...` for a message; a keyboard
  message's wparam and lparam are `withheld` (`input=withheld`) without `--log-real-input`. Off by default because the
  filter does not remove the trap: each call of a probed function costs one (about 1-2 us), however filtered, and the
  game calls `NtUserCallHwndParam` every frame and `NtUserMessageCall` for every message it dispatches; probed by
  default once, it put msmon at 98% of a core, blacked the game's window at launch and dropped about 1 channel change
  in 4 (2026-11-12). `tests/linux_wine_test.sh` measures the cost per call (`hwndparam_ns=`), with and without the
  probes, for the decision to turn them on.
- `libgnutls.so.30` (both arches; Wine's schannel in `secur32.so`, so WinHTTP, WinINet and SSPI
  callers): `gnutls_record_send`/`gnutls_record_recv` entry saves the buffer, a uretprobe reads what the
  call moved and sends it to `payload_ring` as socket bytes are. Each call is a `file_write`/`file_read`
  of `tls:session=<gnutls session>` with `tls_plaintext;via=gnutls;call=;requested=;ret=;arch=` and a
  `tls_plaintext` payload (up to 1 MiB per call; never collapsed); with `--no-payloads` only the
  metadata, collapsed. schannel moves the ciphertext itself, so the record names no socket: the same
  thread's next socket send (previous receive) carries it, and `events.pcapng` holds the ciphertext.
  Native programs using GnuTLS are probed too when tracked (native helpers record no payloads).
- `wbemprox.dll` (PE code): `IWbemServices::ExecQuery`, `ExecQueryAsync`, `GetObject` and
  `CreateInstanceEnum`, found through the vtable that Wine's DWARF names (`pe.cpp` `PeWmiMethods`; the
  async `GetObject`/`CreateInstanceEnum` are failing stubs in Wine 11), are probed per process at their file offsets once the mprotect making
  wbemprox's code executable has returned (a uprobe is installed only in a mapping that is not writable
  when it registers, and Wine maps PE sections writable first): the copy thread spots that mprotect and
  the worker attaches it before any queued library; the link is dropped at the process's exit. Each query is an `etw_wmi`
  `query:<class>` with `operation=exec_query;query=<WQL>;language=WQL;source=uprobe` (`exec_query_async`
  likewise; `get_object`/`create_instance_enum` with `query=<object path>;language=path`, the class as
  Wine's `parse_path` takes it) (`--no-payloads`:
  strings and numbers in the WQL replaced, as on Windows) and PE frames from the probe's own registers.

Limits: the first process to map a library outside those installs (`libgnutls.so.30` included), and a
process's first queries after wbemprox's code turns executable, are not seen for the milliseconds the attach
takes; the
breakpoints (and the kernel's `[uprobes]` page, once one is hit) in ntdll.so, win32u.so and libgnutls are
visible to the integrity checks of every process that maps them, untracked ones included, and wbemprox's to
the tracked process's own; a Wine build whose wbemprox has no DWARF gets no query text;
TLS inside PE code (OpenSSL 1.1/3 DLLs, BoringSSL in CEF/Electron) and game-protocol crypto stay
ciphertext: the bytes can be decrypted from `events.pcapng` with a key log the program writes
(`SSLKEYLOGFILE`, which GnuTLS honours too; `editcap --inject-secrets tls,<keys> events.pcapng`).

### Watchpoints

`--watch WHERE:LENGTH:ACCESS` (up to four; without it nothing below is loaded or run) logs a tracked process's own
loads and stores at an address, which no syscall, request or fault shows: each watch is a hardware data breakpoint
(`perf_event_open` `PERF_TYPE_BREAKPOINT`) on every thread of each process it applies to (`agent/linux/watch.cpp`,
`bpf/watch.bpf.c`, a BPF object of its own). Logging only: a data breakpoint traps after the access, so nothing can be
refused.

- WHERE is `MODULE+0xOFFSET`, from the base of that module in every tracked process that has it loaded, or
  `0xADDRESS`, in every tracked process (wineserver and native helpers included). An absolute address therefore takes
  a debug register on every thread of the family (the census counted 258 client threads, besides wineserver, every
  Chromium helper and grap-core64.aes): while it is watched, every Windows program's SetThreadContext with debug
  registers fails (see the conflict below) and every thread pays the context-switch cost (see Cost). Give the game's
  addresses as `MODULE+0xOFFSET`, or track the one process with `--pid`. The module is looked up in msmon's
  image list of the process (its executable PE images as the maps scan found them: at track, at an executable mmap or
  mprotect, every 2 s) by file name without case, or by the export name of a PE image found in anonymous memory; its
  first load counts. LENGTH is 1, 2, 4 or 8 bytes and the address (or offset) a multiple of it. ACCESS is `w`
  (writes) or `rw` (reads and writes); `r` is watched as `rw`, since an x86 data breakpoint cannot trap reads alone.
  The agent refuses at start (exit code 2, with the reason) a fifth watch (a thread has 4 debug registers and can
  match every watch), any other length, an unaligned address or offset, a number that is not `0x` hex, an offset past
  4 GiB and an address outside user space (0x1 to 0x7fffffffefff: the kernel's breakpoint check counts the last page
  below 0x800000000000 as kernel space and would refuse it on every thread). `MapleStory.exe+0x1234:8:rw` is refused
  (0x1234 is not a multiple of 8): `MapleStory.exe+0x1230:8:rw`, or `MapleStory.exe+0x1234:4:rw` with
  `MapleStory.exe+0x1238:4:rw`.
- A new scan of a process's images resolves its watches again: a module loaded at another base takes its watches
  along (`watch_attached` with `previous=`), one unloaded drops them (`watch_detached;reason=module_unloaded`). Wine
  reads a native image's sections into anonymous memory, so the image list also holds the image as a PE found there
  (by its export name); that copy goes when its file image goes, so it does not hold a watch on the freed base.
- Every 100 ms the agent lists each watched process's threads (`/proc/<pid>/task`) and opens the breakpoints a thread
  lacks, with `mm_watch_hit` attached (the watch's index as the link's cookie); those of threads that ended are
  closed. A thread started later is unwatched for its first 100 ms at most. The breakpoints are not inherited: an
  inherited one makes the program's own `clone` reserve debug registers for the new thread (and fail when it cannot),
  and a thread made by one that held none (its registers taken) would stay unwatched without a record.
- Records (sensor `linux.ebpf_memory`, `process_handle` on the process itself, text `watch:<WHERE:LENGTH:ACCESS>`;
  `watch_conflict` for a tracer's failed write):
  - `watch_hit;address=;length=;access=w|rw;ip=;ip_module=<module>+0x<offset>;count=;span_us=`, one per thread, ip,
    watch and second: `mm_watch_hit` counts every hit in the kernel per (thread, second, ip, watch) and writes no
    sample; the agent reads and deletes a key 2 s after its second began. value0 is the address, value1 the hits, the
    timestamp the last hit's. ip is the instruction after the access (for a repeated string instruction, itself);
    `ip_module` when it lies in a PE image. Accesses the kernel makes for the thread's syscalls are not counted
    (`exclude_kernel`): the syscall's own record shows them.
  - `watch_throttled;address=;length=;access=;cap=10000;ip=;ip_module=` (value0 the address, value1 the cap): the
    thread's breakpoint was hit 10,000 times within one second, at any of its instructions (`mm_watch_hit` compares
    the breakpoint's perf count with the one it had when the second's key began; ip is the instruction whose hit
    reached the cap), and reported on the `watch_over` ring buffer (one record per 10,000 hits until it is closed).
    The agent closes it at once and does not reopen it on that thread; a watch whose module moved starts over at its
    new address. The hits up to then are in that second's `watch_hit` records.
  - `watch_attached;address=;length=;access=[;module_base=][;previous=]` and
    `watch_detached;reason=module_unloaded;...`: where a watch is in a process (thread 0, value0 the address).
  - `watch_conflict;side=watch;address=;length=;access=;errno=28` (status -28): the thread's 4 debug registers are
    taken, so the watch's breakpoint cannot be opened on it; `watch_failed;...;errno=N` for any other errno. Once per
    thread and watch: it is not retried.
  - `watch_conflict;side=program;register=drN;value=;tracer_pid=;count=;span_us=` (status -28, value0 the value
    written, value1 the writes): the thread's tracer wrote its debug register N with `PTRACE_POKEUSR` and it failed
    ENOSPC (`mm_watch_ptrace`, `fexit/arch_ptrace`), per thread, register and second.
  - coverage `watch_active` (`watches=;keys=4096;thread_rescan_ms=100;hit_cap=10000;ptrace_conflicts=on`, or
    `off:errno=N` when `fexit/arch_ptrace` did not load (no BTF for `arch_ptrace`, no fexit: the object is loaded
    again without it, and hits are still counted) or did not attach) or `watch_unavailable` (errno: no BPF build, no
    root, no BTF, or the `watch_over` ring buffer did not open: no watch runs without its cap), and at the stop
    `watch_losses` (`hits_full=`: hits and conflicts not counted because the 4096 keys were taken).
- The conflict with Wine. A Windows program's SetThreadContext with debug registers is wineserver's ptrace of the
  thread (the family does it often: the census counted 22,648 POKEUSR writes on 258 client threads in 5 minutes).
  Wine 11's wineserver (its `set_thread_context`, read from the binary) writes DR7 = 0, then DR0, DR1, DR2, DR3 and
  DR6, then DR7 with the enable bits 0x55 (its result unchecked), then DR7, and stops at the first checked write that
  fails. The first write of each of DR0-DR3 registers a ptrace breakpoint, which takes one of the thread's 4 debug
  registers for the thread's life, enabled or not. On a thread holding W watches the write of DR(4-W) fails ENOSPC
  (DR3 for one watch); DR7 never does, since no enable bit is written before all four are registered. wineserver
  stops there and the program's call fails (wineserver turns ENOSPC into STATUS_DISK_FULL), which the program can
  notice, and DR7 has already been zeroed: hardware breakpoints the program set earlier are left disabled. Each such
  failure is a `side=program` record (under Wine 11 always one of dr0-dr3). A thread whose registers wineserver took
  first cannot be watched (`side=watch`). Reads do not show the watches (GetThreadContext's PEEKUSR returns
  wineserver's own ptrace values), but every hit is a user debug trap, at which the kernel restarts the thread's
  ptrace DR6, so a program reading DR6 after one of its own hardware breakpoints fired can find its trap bits cleared
  when a watch hit came in between. Watch the game only while that is acceptable.
- Cost, paid by the watched threads:
  - A hit is a #DB trap on the thread that made the access (an exception round trip, about a microsecond) and
    `mm_watch_hit` (80 verified instructions: the breakpoint's perf count, one hash lookup or an insert); no ring
    buffer and no agent work per hit. The cap bounds it: a breakpoint hit 10,000 times in one second (about 1% of a
    core in traps) is closed for good on that thread as soon as the agent reads its `watch_over` record (a wakeup,
    normally well under a millisecond), so a hot address costs a thread about 10,000 traps per watch, once.
  - Each switch of a thread holding breakpoints, out and back in, runs perf's task context switch and, per
    breakpoint, a debug-register write out and two in (serializing `MOV DR`): estimated at about 1 µs with 4 watches
    from the kernel's code, not measured (opening breakpoints needs root); `tests/linux_budget_test.sh` measures it
    on two watched threads (budget 4 µs a futex round trip). Wine client threads switch on most wineserver requests:
    MapleStory.exe made about 59,000 a second in the 22:08 session (16.3 million writev in 277 s), so 4 watches on
    all its threads cost it up to about 6% of a core in switches alone, hit or not; with `0xADDRESS`, wineserver and
    every other thread of the family pay the same.
  - The agent reads `/proc/<pid>/task` of each watched process every 100 ms and walks `watch_hits` every second;
    `mm_watch_ptrace` runs on every `ptrace` call on the machine (wineserver's are a few hundred a second at most).
    Each breakpoint is two fds (its event and its link), so the fd limit goes to its hard maximum.
- Privacy: addresses, instruction pointers and counts; never the bytes at the address.
- Limits: a 32-bit tracer's debug-register writes (compat ptrace) are not seen (wineserver is 64-bit); a hit in the
  microseconds of the stop can miss the last read; a thread's accesses after its breakpoint passed the cap are not
  seen (`watch_throttled` says from when).

## Coverage limits

Written as coverage records at session start and listed here.

With the kernel sensors:

- File contents are not captured; work done inside the kernel has no syscall record unless a
  kernel event covers it (io_uring and AIO operations, signals, trapped instructions,
  capability checks, module requests, credential changes). Accesses to pages already mapped are
  unseen (first touches of shared mappings only with `--page-faults`; a process's own loads and stores only at
  the addresses `--watch` names), as are vDSO time calls
  (clock_gettime, gettimeofday, time, getcpu make no syscall) and unprivileged instructions the
  kernel does not trap (XGETBV, RDRAND, RDPID, ...). The upgrades above list their own limits.
- Without the wineserver decoder, Wine's registry is file-level (the prefix's `*.reg` files),
  not per key.
- Paths of 256 bytes or more are truncated (`truncated_path`); a detail cut at the record's string
  limit (1024 characters, 768 with a payload chunk) is flagged `truncated_detail`.
- Module unloads: a wineserver `unmap_view` of an image view (`image_unload=1`) names a Windows module's
  at once; any other (a unix library's dlclose) is a `file_section` `image_unload;source=maps_poll`
  when the 2 s maps poll no longer lists an image it listed executable, so one loaded and unloaded in
  between is missed.
- Loading and verifying the BPF programs takes a few seconds; the agent prints
  `Registered` once they are live.

Without them:

- fanotify events carry no byte counts, offsets, open flags or status; those fields are 0.
  The kernel merges queued events on one object; a queue overflow is counted as a drop
  (sequence gap).
- Sockets are polled once a second: shorter-lived sockets are missed, the first poll reports
  already-open sockets, and timestamps are poll times.
- Executable mappings are polled every 2 s; a library mapped and unmapped in between is missed.
  An executable file mmap or `mprotect` triggers an extra scan, so a newly loaded module is
  recorded at once even though the periodic poll still owns `image_load` under eBPF.
- `registry_unavailable`, `etw_unavailable`, `blackcat_not_applicable`: no key-level registry, ETW
  (WMI/DNS/RPC/TCPIP/CodeIntegrity) or BlackCat sensors exist. The Windows driver's
  registration slots (20-38) are reported failed with ENOSYS.
- `payload_unavailable`: there are no registry values or volume-information queries to
  capture. Hardware identity appears as file events on `/sys/class/dmi/id/*`,
  `/proc/cpuinfo`, `/sys/block/*/serial` (classified `hardware_identity`).
- No thread, handle, stack attribution, memory or payload sensors.
- Without root, only processes running at start (or `--pid`) are tracked; their children
  are not.

## KFilter

The agent reads kfilterd over `/run/kfilter.sock` (see `filter/linux/kfilter_socket.h`):
`GET_STATUS` (0x800) and `READ_EVENTS` (0x802), ABI 9 structures with 32-bit fields and
4-byte `wchar_t`. If the socket is absent the session records `kfilter_unavailable`.

## Windows-only parts

Not ported: `driver/`, `tools/windows-test/`, the PowerShell tests in `tests/`
and `tests/fixtures/`, `build.cmd`, `tests/integration_regression.cmd`.
`tools/analyze_client.py` parses PE images only; ELF files are counted and reported as an
`elf_inventory` gap. The scenario files in `tests/scenarios/` name Windows sensors.

## Running with kfilter: one command

`../monfilter.py run` (repository root) starts kfilterd, loads the policy (audit unless
`--block`), starts msmon-agent on every Nexon root with payloads on, waits until it records,
launches the client under `kfilterctl launch`, and at the end stops msmon, then kfilter,
packs the session and writes the tuning report (`monfilter.py report <bundle>`). See the
repository README for the options and the tuning loop.
