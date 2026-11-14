#!/bin/sh
# Runtime check of kfilterd's BPF LSM layer (needs root; run in a VM:
# `sudo tests/linux_lsm_test.sh` after ./build.sh tests; stop any running kfilterd first).
# A launched probe tries open/read, unlink, rename, truncate, chmod, mmap(PROT_EXEC),
# process memory, connect, UDP sends and metadata queries (stat, access, readlink, xattrs, watches;
# ENOENT for a hide rule) on objects the policy denies: in block mode each must fail with EPERM
# and appear in `kfilterctl watch`; in audit mode each must succeed and appear as would-deny. So must
# the rule-only system decisions (uname and sysinfo, also by int 0x80, a socket family, memfd,
# userfaultfd, io_uring, keyrings, SysV IPC, arch_prctl, executable anonymous memory), an ioctl by
# value, a POSIX message queue, a pipe from outside the family and a DNS name (the resolver answers
# the others, audited), while those no rule names log nothing; an audit|message|index=1 rule logs
# each connection's first send only. Then: message rules under network-loopback on (exempt, as connections are);
# block-connection answers (refused in audit mode, the block gone with its socket); RISK
# records for risk= allows; fail closed (a protected program stays confined after kfilterd is
# killed in block mode, a restarted kfilterd takes the pinned layer over, off unpins it); and,
# with Wine, thread-handle rules, a process handle copied with more rights than it was opened
# with, raw requests to wineserver past Wine (vmsplice, splice, an exec'd shell, a protected
# shell writing a request pipe), the registry flush, notify and security requests, and peer,
# thread-peer, system and thread rules between two protected programs, Wine running with uname,
# sysinfo, userfaultfd and private executable memory refused (its unaligned image still loads),
# a Linux syscall the probe makes itself flagged direct and refused by block-direct-syscall,
# winedevice's driver loads decided, and calls Wine answers in-process refused by uprobes (win32u.so's
# GetCursorPos and window list, also i386, GetAsyncKeyState by key and InternalGetWindowText by the window's owner;
# ntdll.so's NtQueryInformationProcess by class, Wine's own calls undecided; wbemprox's ExecQuery per WQL class in wmic,
# x64 and i386, and its ExecQueryAsync, GetObject, CreateInstanceEnum and ExecMethod, x64; NtUserCallHwndParam's
# per-call cost while a rule names it, HWND_NS_MAX), and what a request reaches past its own
# decision (another program's window and thread by the pseudo-rights, ones a fresh kfilterd cannot place on
# \@unknown-window and \@unknown-thread, a handle at any offset, keyed hooks, input and ioctls, an RPC call)
# (tests/linux_lsm_wine_probe.c in a throwaway prefix). ABI 11's decisions on the probe's own actions (lsm-probe k4,
# lsm-probe32): syscalls by name, the hooks kfilter did not use and the finer ones; ABI 12's sends to AF_UNIX peers by unix=
# message rules (lsm-probe k6). Then the same under `kfilterd --no-bpf`
# (fanotify and nftables): the open is still refused, and kfilterctl status no longer lists the
# bpf layer.
set -u
cd "$(dirname "$0")/.."
bin=build/linux
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 2; }
work=$(mktemp -d)
log="$work/kfilterd.log"
port=47311
fail=0

sleep 600 &
outside=$!

start_daemon() {
    rm -f /run/kfilter.sock
    "$bin/kfilterd" "$@" 2>>"$log" &
    daemon=$!
    for _ in $(seq 1 60); do [ -S /run/kfilter.sock ] && break; sleep 0.5; done
}

stop_daemon() {
    "$bin/kfilterctl" off >/dev/null 2>&1
    kill "$daemon" 2>/dev/null
    wait "$daemon" 2>/dev/null
}

write_policy() {   # $1 = mode, $2 = block-network on|off, $3 = BPF-only layers on|off, $4 = network-loopback
    cat >"$work/policy.txt" <<POLICY
mode $1
protect /lsm-probe
block-files on
block-process-create on
block-process-memory ${3:-on}
block-network-adapter ${3:-on}
block-file-queries ${3:-on}
block-volume-serial ${3:-on}
block-network $2
network-loopback ${4:-off}
network-default allow
deny|file|/etc/hostname
allow|file|$work/files/img-allow|rights=read|exact|image=lsm-probe|risk=test
deny|file|$work/files/img-allow
deny|file|$work/files/img-deny|image=lsm-probe
deny|file|$work/files/no-delete|rights=delete
deny|file|$work/files/no-rename|rights=rename
deny|file|$work/files/no-write|rights=write
deny|file|$work/files/no-chmod|rights=set-security
deny|file|$work/files/no-exec|rights=execute
deny|network|ip=127.0.0.1|port=$port|proto=tcp|rights=connect
allow|network|ip=127.0.0.1/32|port=$((port + 1))|proto=udp|rights=connect|uses=1|risk=test
deny|network|ip=127.0.0.1|port=$((port + 1))|proto=udp|rights=connect
deny|network|ip=127.0.0.1|port=$((port + 2))|proto=udp|rights=connect
deny|pipe|/@kfilter-test|rights=connect
deny|pipe|$work/files/rel.sock|rights=connect
allow|file|$work/files/once|rights=read|uses=1|risk=test
deny|file|$work/files/once
deny|file|$work/files/deny-once|uses=1
deny|process|$work/files/no-run|exact
deny|file|/anon/SYSV4b46*
audit|file|/anon/memfd:kf-probe
audit|file|/anon/SYSV00000000
deny|file|/proc/@outside/status|hide
deny|file|$work/files/meta
deny|dir|$work/files/meta
deny|file|$work/files/hidden|hide
audit|file|$work/files/meta-ok
deny|message|port=$((port + 3))|match=DEAD@0
deny|message|port=$((port + 3))|size=300
deny|message|port=$((port + 3))|index=5
deny|message|port=$((port + 3))|match=BEEF@0|uses=1
audit|message|rights=send|index=1
deny|system|/system/uname
audit|system|/system/sysinfo
deny|system|/system/socket/netlink/raw/15
deny|system|/system/memfd/kf-deny
deny|system|/system/userfaultfd
deny|system|/system/io_uring
deny|system|/system/keyring
deny|system|/system/ipc/msg
deny|system|/system/arch_prctl/0x1011
deny|system|/system/memory/private
deny|system|/system/memory/shared
deny|system|/system/sockopt/socket/8|rights=write
audit|system|/system/peername|image=kf-none1
audit|system|/system/peername|image=kf-none2
audit|system|/system/peername|image=kf-none3
audit|system|/system/peername|image=kf-none4
audit|system|/system/peername|image=kf-none5
audit|system|/system/peername|image=kf-none6
audit|system|/system/peername|image=kf-none7
audit|system|/system/peername|image=kf-none8
deny|system|/system/peername
deny|system|/system/map$work/files/map-deny
deny|dns|kf-deny.*
deny|dns|kf-aaaa.example|value=28
audit|dns|*
deny|device|/dev/null|value=0x00005401
allow|device|$work/files/ioctl-ok|value=0x0000541B|risk=test
deny|device|$work/files/ioctl-ok
deny|file|/anon/mqueue/kf-probe
deny|pipe|/anon/pipe/@outside|rights=read
POLICY
    # Without the BPF layer message, system, dns and ioctl rules cannot be enforced, and block mode refuses them.
    [ -n "${KF_NO_MESSAGES:-}" ] && sed -i '/|message|/d; /|system|/d; /|dns|/d; /^deny|device|/d' "$work/policy.txt"
    return 0
}

run_probe() {   # $1 = mode, $2 = block-network, $3 = BPF-only layers, $4 = network-loopback; prints the probe's report
    mkdir -p "$work/files"
    mkdir -p "$work/files/meta"
    for name in no-delete no-rename no-write no-chmod no-exec once deny-once meta/f hidden meta-ok img-allow img-deny map-deny ioctl-ok; do echo data >"$work/files/$name"; done
    ln -sf f "$work/files/meta/l"
    deep="$work/files/deep/$(printf 'd/%.0s' $(seq 1 64))"   # deeper than the kernel walks
    mkdir -p "$deep" && echo data >"$deep/file"
    cp /bin/true "$work/files/no-run"
    rm -f "$work/files/renamed" "$work/files/inode" "$work/files/go"
    write_policy "$1" "${2:-on}" "${3:-on}" "${4:-off}"
    "$bin/kfilterctl" policy "$work/policy.txt" --no-track >/dev/null 2>&1 || { echo "FAIL $1: policy rejected"; fail=1; }
    "$bin/kfilterctl" clear >/dev/null 2>&1
    cp "$bin/lsm-probe" "$work/lsm-probe"
    # As root, whoever ran sudo: the probe's own access must not fail before kfilter decides
    # (a root-only temp dir, ptrace limits on another user's process).
    # Its stdin is a pipe this shell made: from outside the family (/anon/pipe/@outside).
    printf x | env -u SUDO_UID -u SUDO_GID -u SUDO_USER "$bin/kfilterctl" launch "$work/lsm-probe" "$work/files" "$outside" "$port" \
        >"$work/report" 2>/dev/null &
    probe=$!
    # The probe writes its connection's socket inode, waits for "go", then sends again:
    # block that live connection in both directions in between.
    for _ in $(seq 1 100); do [ -s "$work/files/inode" ] && break; sleep 0.1; done
    blocked=failed
    [ -s "$work/files/inode" ] && "$bin/kfilterctl" block-connection "$(cat "$work/files/inode")" both >/dev/null 2>&1 &&
        blocked=ok
    touch "$work/files/go"
    wait "$probe"
    cat "$work/report"
    echo "block_connection=$blocked"
    # The probe is gone and its socket with it: so is the block (unblocking it fails).
    if [ -s "$work/files/inode" ]; then
        if "$bin/kfilterctl" unblock-connection "$(cat "$work/files/inode")" >/dev/null 2>&1; then
            echo "stale_block=kept"
        else
            echo "stale_block=gone"
        fi
    fi
}

expect_all() {   # $1 = label, $2 = expected word, $3 = report
    for action in open_read unlink rename truncate chmod mmap_exec process_vm_readv proc_mem connect; do
        echo "$3" | grep -qx "$action=$2" || { echo "FAIL $1: $action is not $2"; fail=1; }
    done
}

start_daemon
"$bin/kfilterctl" status | grep -q 'registered:.*bpf' || { echo "FAIL: kfilterd did not attach the BPF layer"; fail=1; }

# A root or protect name the BPF maps cannot hold must refuse block mode, not
# silently drop the protection (plan K2; a 143-byte protect path and 260+ root).
long=$(printf 'a%.0s' $(seq 1 130))
mkdir -p "$work/$long"
cat >"$work/long-name.txt" <<POLICY
mode block
protect $work/$long/xprobe
block-files on
block-process-create on
block-raw-disk on
deny|process|/*
POLICY
before=$("$bin/kfilterctl" status | grep -E '^(mode|rules):')
if "$bin/kfilterctl" policy "$work/long-name.txt" --no-track >/dev/null 2>&1; then
    echo "FAIL #20: long protect name accepted in block mode"; fail=1
fi
after=$("$bin/kfilterctl" status | grep -E '^(mode|rules):')
[ "$before" = "$after" ] || { echo "FAIL #20: failed policy replaced the previous config"; fail=1; }
grep -q 'too long for the kernel layer' "$log" || { echo "FAIL #20: daemon did not report the long protect name"; fail=1; }

longroot=$(printf 'b%.0s' $(seq 1 260))
cat >"$work/long-root.txt" <<POLICY
mode block
root $work/$longroot
block-files on
deny|file|/etc/hostname
POLICY
if "$bin/kfilterctl" policy "$work/long-root.txt" --no-track >/dev/null 2>&1; then
    echo "FAIL #20: long root accepted in block mode"; fail=1
fi

# Audit mode loads with the warning; switching the same config to block is refused.
sed 's/^mode block$/mode audit/' "$work/long-name.txt" >"$work/long-name-audit.txt"
if ! "$bin/kfilterctl" policy "$work/long-name-audit.txt" --no-track >/dev/null 2>&1; then
    echo "FAIL #20: long protect name rejected in audit mode"; fail=1
fi
if "$bin/kfilterctl" on >/dev/null 2>&1; then
    echo "FAIL #20: block mode accepted the long protect name after audit"; fail=1
fi

# A rule only a degraded part of the BPF layer decides (a win32u.so function no Wine here has)
# refuses block mode; audit mode loads it.
printf 'mode block\nprotect /lsm-probe\ndeny|system|/system/win32k/NtUserKfNoSuchCall\n' >"$work/degraded.txt"
"$bin/kfilterctl" policy "$work/degraded.txt" --no-track >/dev/null 2>&1 &&
    { echo "FAIL: block mode accepted a system rule the degraded layer cannot decide"; fail=1; }
grep -q 'block mode refused: the BPF layer is degraded' "$log" || { echo "FAIL: no degraded refusal logged"; fail=1; }
sed -i 's/^mode block$/mode audit/' "$work/degraded.txt"
"$bin/kfilterctl" policy "$work/degraded.txt" --no-track >/dev/null 2>&1 ||
    { echo "FAIL: audit mode rejected the degraded system rule"; fail=1; }

report=$(run_probe block)
expect_all block denied "$report"
# UDP is authorised per peer: the second datagram to the uses=1 peer passes without a decision.
for line in image_allow=ok image_deny=denied image_fork=ok udp_first=ok udp_repeat=ok udp_other=denied unix_connect=denied unix_relative=denied netlink_getlink=denied \
            counted_read=ok counted_reopen=denied deny_once_first=denied deny_once_second=ok \
            msg_plain=ok msg_match=denied msg_size=denied msg_fourth=ok msg_index=denied \
            msg_once_first=denied msg_once_second=ok msg_blocked_send=denied msg_blocked_recv=denied \
            exec_denied=denied block_connection=ok stale_block=gone memfd_map=ok shm_private=ok shm_keyed=denied \
            anon_shared_exec=denied anon_exec=denied zero_exec=denied deep_open=denied dns_deny=denied dns_allow=ok \
            dns_type=denied dns_type_other=sent proc_self=ok proc_family=ok proc_outside=hidden \
            meta_stat=denied meta_lstat=denied meta_statx=denied meta_access=denied meta_faccessat2=denied \
            meta_readlink=denied meta_getxattr=denied meta_listxattr=denied meta_opath_fstat=denied \
            meta_opath_statx=denied meta_cwd_statx=denied meta_watch=denied hide_stat=hidden hide_open=hidden \
            meta_fd=ok statfs=ok sys_uname=denied sys_uname32=denied sys_sysinfo=ok sys_sysinfo32=ok \
            sys_socket_uevent=denied sys_socket_inet=ok sys_memfd=denied sys_userfaultfd=denied sys_io_uring=denied \
            sys_keyring=denied sys_msgsnd=denied sys_arch_prctl=denied ioctl_tcgets=denied ioctl_fionread=ok \
            ioctl_allowed=ok ioctl_other=denied \
            mqueue=denied pipe_stdin=denied pipe_own=ok sys_setsockopt=denied sys_getsockopt=ok sys_getpeername=denied \
            map_read=ok map_file=denied; do
    echo "$report" | grep -qx "$line" || { echo "FAIL block: expected $line"; fail=1; }
done
watch=$("$bin/kfilterctl" watch 1)
# Metadata queries are file/dir decisions with rights query (0x80), a watch is enumerate (0x40);
# a query on a decided open is not decided again; statfs is an audit volume record.
echo "$watch" | grep 'deny ' | grep ' file ' | grep 'value=0x80 ' | grep -q "$work/files/meta/f" ||
    { echo "FAIL block: no query deny event"; fail=1; }
echo "$watch" | grep 'deny ' | grep ' dir ' | grep 'value=0x40 ' | grep -q "$work/files/meta$" ||
    { echo "FAIL block: no watch deny event"; fail=1; }
echo "$watch" | grep 'meta-ok' | grep -q 'value=0x80 ' && { echo "FAIL block: a query on a decided open was decided"; fail=1; }
echo "$watch" | grep 'audit ' | grep 'value=0x1 ' | grep -q 'meta-ok' || { echo "FAIL block: no audit event for the meta-ok open"; fail=1; }
echo "$watch" | grep 'audit ' | grep ' volume ' | grep -q "$work/files" || { echo "FAIL block: no statfs record"; fail=1; }
# Pseudo files are /anon/<name> (never "/"), decided only by a rule naming them; /proc/<pid> by whose it is.
for needle in /anon/memfd:kf-probe /anon/SYSV00000000 /proc/@self/status /proc/@family/status; do
    echo "$watch" | grep -q -- "$needle" || { echo "FAIL block: no decision on $needle"; fail=1; }
done
echo "$watch" | grep 'deny ' | grep -q '/anon/SYSV4b46' || { echo "FAIL block: no deny event for the keyed SysV shm"; fail=1; }
echo "$watch" | grep 'deny ' | grep -q '/proc/@outside/status' || { echo "FAIL block: no deny event for /proc/@outside"; fail=1; }
echo "$watch" | grep -q 'kf-unlisted' && { echo "FAIL block: a decision on an /anon file no rule names"; fail=1; }
# System decisions, rule-only: each named one is decided (sysinfo audited), unnamed ones not at all.
for needle in /system/uname /system/socket/netlink/raw/15 /system/memfd/kf-deny /system/userfaultfd /system/io_uring \
              /system/keyring/ /system/ipc/msg/00000000 /system/arch_prctl/0x1011 /anon/mqueue/kf-probe \
              /anon/pipe/@outside 'value=0x5401 .*/dev/null' /system/memory/private/rwx /system/memory/shared/rx \
              /system/sockopt/socket/8 /system/peername "/system/map$work/files/map-deny"; do
    echo "$watch" | grep 'deny ' | grep -q -- "$needle" || { echo "FAIL block: no deny event for $needle"; fail=1; }
done
echo "$watch" | grep 'audit ' | grep -q ' system .*/system/sysinfo' || { echo "FAIL block: no audit event for sysinfo"; fail=1; }
# DNS: the queried name, lowercase, value its type (A); every other lookup audited.
echo "$watch" | grep 'deny ' | grep ' dns ' | grep 'value=0x1 ' | grep -q ' kf-deny.example$' ||
    { echo "FAIL block: no dns deny event"; fail=1; }
echo "$watch" | grep 'audit ' | grep ' dns ' | grep -q ' localhost$' || { echo "FAIL block: no dns audit event"; fail=1; }
# audit|message|index=1: each connection's first send, with its bytes, and no later one.
echo "$watch" | grep 'audit ' | grep -q "send tcp 127.0.0.1:$((port + 3)) socket:\[[0-9]*\] #1 len=5 data=48454c4c4f" ||
    { echo "FAIL block: no audit event for a connection's first send"; fail=1; }
echo "$watch" | grep -q "send tcp 127.0.0.1:$((port + 3)) socket:\[[0-9]*\] #4 " &&
    { echo "FAIL block: an event for a later send no rule names"; fail=1; }
# FIONREAD on /dev/null (ioctl_fionread) is the ioctl no rule names; ioctl-ok's FIONREAD meets its risk= allow.
echo "$watch" | grep -E -q '/system/socket/inet|/system/memfd/kf-probe|/anon/pipe/[^@]|value=0x541b /dev/null$' &&
    { echo "FAIL block: a system, pipe or ioctl decision no rule names"; fail=1; }
echo "$watch" | grep -q ' /$' && { echo "FAIL block: a decision on the path /"; fail=1; }
for needle in /etc/hostname no-delete no-rename no-write no-chmod no-exec 127.0.0.1; do
    echo "$watch" | grep 'deny ' | grep -q -- "$needle" || { echo "FAIL block: no deny event for $needle"; fail=1; }
done
echo "$watch" | grep 'deny ' | grep -q 'flags=0x20 ' || { echo "FAIL block: no process-memory deny event"; fail=1; }
echo "$watch" | grep 'deny ' | grep -q '/net/netlink/route' || { echo "FAIL block: no netlink deny event"; fail=1; }
echo "$watch" | grep 'deny ' | grep -q '/@kfilter-test' || { echo "FAIL block: no unix socket deny event"; fail=1; }
echo "$watch" | grep 'deny ' | grep -q "$work/files/rel.sock" || { echo "FAIL block: no deny event for the relative unix socket"; fail=1; }
echo "$watch" | grep 'deny ' | grep ' process ' | grep -q 'no-run' || { echo "FAIL block: no process-create deny event"; fail=1; }
echo "$watch" | grep 'deny ' | grep -q "send tcp 127.0.0.1:$((port + 3)) socket:\[[0-9]*\] #2 len=4 data=dead0102" ||
    { echo "FAIL block: no message deny event with its bytes"; fail=1; }
echo "$watch" | grep 'deny ' | grep -q "receive tcp 127.0.0.1:$((port + 3))" || { echo "FAIL block: no blocked receive event"; fail=1; }
# A risk= allow is also a RISK record, as on Windows: a file and a network one.
echo "$watch" | grep 'RISK ' | grep -q "$work/files/once" || { echo "FAIL block: no RISK record for the file allow"; fail=1; }
echo "$watch" | grep 'RISK ' | grep -q "udp 127.0.0.1:$((port + 1))" || { echo "FAIL block: no RISK record for the network allow"; fail=1; }
report=$(run_probe audit)
expect_all audit ok "$report"
# block-connection fails where it would do nothing (audit mode).
for line in msg_match=ok msg_size=ok msg_index=ok msg_blocked_send=ok exec_denied=ok unix_relative=ok block_connection=failed \
            shm_keyed=ok proc_outside=ok meta_stat=ok meta_readlink=ok meta_watch=ok hide_stat=ok hide_open=ok \
            sys_uname=ok sys_uname32=ok sys_socket_uevent=ok sys_memfd=ok sys_userfaultfd=ok sys_io_uring=ok sys_keyring=ok \
            sys_msgsnd=ok sys_arch_prctl=ok ioctl_tcgets=ok ioctl_other=ok mqueue=ok pipe_stdin=ok anon_exec=ok anon_shared_exec=ok \
            zero_exec=ok deep_open=ok dns_deny=sent dns_allow=ok dns_type=sent sys_setsockopt=ok sys_getpeername=ok \
            map_file=ok; do
    echo "$report" | grep -qx "$line" || { echo "FAIL audit: expected $line"; fail=1; }
done
watch=$("$bin/kfilterctl" watch 1)
echo "$watch" | grep -q 'audit .*flags=0x1 .*no-delete' || { echo "FAIL audit: no would-deny event"; fail=1; }
echo "$watch" | grep -q "audit .*flags=0x1 .*value=0x80 .*$work/files/meta/f" || { echo "FAIL audit: no would-deny query event"; fail=1; }
echo "$watch" | grep -q " system *audit *flags=0x1 .*/system/uname" || { echo "FAIL audit: no would-deny system event"; fail=1; }

# network-loopback on exempts message rules on 127.0.0.1 as it exempts connections; a
# block-connection still holds (it names one connection).
report=$(run_probe block on on on)
for line in connect=ok msg_match=ok msg_size=ok msg_index=ok msg_once_first=ok msg_blocked_send=denied; do
    echo "$report" | grep -qx "$line" || { echo "FAIL loopback: expected $line"; fail=1; }
done

# Reloads under load: two policies of 6,000 rules whose sysinfo allow for the probe sits at different places before a
# deny for everyone load in turn (as relax/live_block.py's steady and change policies), while the probe calls sysinfo
# without pause. A reload switches the rule set whole, so it is never refused.
for variant in 1 2; do
    {
        echo "mode block"; echo "protect /lsm-probe"
        seq 1 $((variant * 7)) | sed 's|^|deny\|file\|/kf-reload/a|; s|$|\|exact|'
        echo "allow|system|/system/sysinfo|exact|rights=query|image=lsm-probe"
        seq 1 6000 | sed "s|^|deny\\|file\\|/kf-reload/v$variant/b|; s|\$|\\|exact|"
        echo "deny|system|/system/sysinfo|exact"
    } >"$work/reload-$variant.txt"
done
cp "$bin/lsm-probe" "$work/lsm-probe"
"$bin/kfilterctl" policy "$work/reload-1.txt" --no-track >/dev/null 2>&1 || { echo "FAIL reload: policy rejected"; fail=1; }
( while [ ! -e "$work/reload-done" ]; do
      "$bin/kfilterctl" policy "$work/reload-2.txt" --no-track >/dev/null 2>&1
      "$bin/kfilterctl" policy "$work/reload-1.txt" --no-track >/dev/null 2>&1
  done ) &
reloader=$!
report=$(env -u SUDO_UID -u SUDO_GID -u SUDO_USER "$bin/kfilterctl" launch "$work/lsm-probe" sysinfo 3000000 2>/dev/null)
touch "$work/reload-done"
wait "$reloader"
echo "$report" | grep -qx "sysinfo_loop=ok" || { echo "FAIL reload: the probe was refused sysinfo during a reload"; fail=1; }

# addr= on native access inside the family (ABI 10): the probe reads a child's memory (process_vm_readv,
# /proc/<pid>/mem) and its own (/proc/self/mem) inside and outside a denied range; more than 8 iovecs is an unknown
# address, and so is a ptrace attach (every address, every right). Decided without block-process-memory; the events
# of the addr= rules name the address.
for mode in block audit; do
    cat >"$work/addr-policy.txt" <<POLICY
mode $mode
protect /lsm-probe
deny|peer|/*/lsm-probe|rights=vm-read|addr=0x500001000-0x500001FFF
deny|system|/system/wine/self/read_process_memory|addr=0x500001000-0x500001FFF
POLICY
    "$bin/kfilterctl" policy "$work/addr-policy.txt" --no-track >/dev/null 2>&1 || { echo "FAIL addr $mode: policy rejected"; fail=1; continue; }
    "$bin/kfilterctl" clear >/dev/null 2>&1
    report=$(env -u SUDO_UID -u SUDO_GID -u SUDO_USER "$bin/kfilterctl" launch "$work/lsm-probe" addr 2>/dev/null)
    outcome=denied
    word=deny
    [ "$mode" = audit ] && { outcome=ok; word=audit; }
    for line in addr_vm_in=$outcome addr_vm_out=ok addr_vm_many=$outcome addr_mem_in=$outcome addr_mem_out=ok \
                addr_self_in=$outcome addr_self_out=ok addr_attach=$outcome; do
        echo "$report" | grep -qx "$line" || { echo "FAIL addr $mode: expected $line (got: $(echo $report))"; fail=1; }
    done
    watch=$("$bin/kfilterctl" watch 1)
    for event in ' peer .*lsm-probe addr=0x0000000500001010+4$' ' system .*/system/wine/self/read_process_memory addr=0x0000000500001010+4$' \
                 ' peer .*lsm-probe addr=.*,?$' ' peer .*lsm-probe addr=?$'; do
        printf '%s\n' "$watch" | grep "$word " | grep -q "$event" || { echo "FAIL addr $mode: no $word event like $event"; fail=1; }
    done
done

# ABI 11: the probe's own syscalls by name and key (x86_64, int 0x80 and a zero-argument call; lsm-probe32: an i386
# program through the compat entries), the hooks kfilter did not use and the finer decisions in those it had, each
# refused by the rule naming it (block) or logged (audit); the action next to each, which no rule names, passes
# without an event. Inside the family (the probe's child): a signal, a SIGIO owner and a READ check, by peer rules
# naming the signal or mode (value=signal:0x..., ptrace:0x...).
k4=$work/files/k4
mkdir -p "$k4/k4-statfs" "$k4/chdir-deny" "$k4/chdir-ok"
for name in lock-ok lock-deny touch-deny touch-ok ioctl-arg; do echo data >"$k4/$name"; done
cp "$bin/lsm-probe" "$work/lsm-probe"
[ -x "$bin/lsm-probe32" ] && cp "$bin/lsm-probe32" "$work/lsm-probe32"
for mode in block audit; do
    cat >"$work/k4-policy.txt" <<POLICY
mode $mode
protect /lsm-probe
protect /lsm-probe32
block-files on
block-network on
network-loopback off
network-default allow
block-process-signals on
block-process-queries on
deny|system|/system/syscall/rt_sigaction/5
deny|system|/system/syscall/getppid
deny|system|/system/syscall/fcntl/6
deny|system|/system/syscall/munmap|addr=0x520001000-0x520001FFF,0x52001000-0x52001FFF
deny|system|/system/syscall/poll/7
deny|system|/system/syscall/sched_getsch*
deny|system|/system/syscall/getpeername
deny|system|/system/fork|uses=1
deny|file|$k4/lock-deny|rights=lock
deny|system|/system/fcntl/setown
deny|system|/system/socketpair/unix/stream/0
deny|system|/system/socket/shutdown/wr
deny|network|ip=127.0.0.1|port=$((port + 5))|proto=tcp|rights=connect
deny|pipe|/@kf-k4-bind|rights=listen
deny|device|/net/netlink/generic/nl80211
deny|device|/net/netlink/route/34
deny|device|/net/ioctl/0x0000541b
deny|device|$k4/ioctl-arg|value=0x0000541B:0x00000007
deny|system|/system/rlimit/core
deny|system|/system/rlimit/nofile/other
deny|system|/system/task/getpgid
deny|system|/system/cred/setgroups
deny|system|/system/capability/sys_nice
deny|system|/system/namespace/user
deny|system|/system/ipc/create/msg/4b46*
deny|system|/system/ptrace/traceme
deny|system|/system/kernel/module/net-pf-12
deny|system|/system/prctl/0x000f
deny|system|/system/memory/low
deny|system|/system/memory/private/rw|addr=0x530000000-0x530000FFF
deny|system|/system/memory/private/r|addr=0x531000000-0x531000FFF
deny|system|/system/statfs$k4/k4-statfs
deny|file|$k4/touch-deny|rights=touch
deny|dir|$k4/chdir-deny|rights=chdir
deny|peer|$work/lsm-probe|value=signal:0x0000000A
deny|peer|$work/lsm-probe|value=signal:0x0000001D
deny|peer|$work/lsm-probe|value=ptrace:0x00000009
POLICY
    "$bin/kfilterctl" policy "$work/k4-policy.txt" --no-track >/dev/null 2>&1 || { echo "FAIL k4 $mode: policy rejected"; fail=1; continue; }
    "$bin/kfilterctl" clear >/dev/null 2>&1
    report=$(env -u SUDO_UID -u SUDO_GID -u SUDO_USER "$bin/kfilterctl" launch "$work/lsm-probe" k4 "$k4" "$outside" "$port" 2>/dev/null)
    named="fork_first sc_sigaction_trap sc_sigaction32_trap sc_getppid sc_getppid32 sc_fcntl_setlk sc_munmap_in sc_munmap32_in
           sc_poll_named sc_wildcard lock_deny fcntl_setown socketpair_named shutdown_named tcp_fastopen unix_bind_named
           genl_lookup_named netlink_route_named socket_ioctl_named ioctl_argument_named rlimit_named rlimit_outside
           task_getpgid_outside cred_setgroups capability_named namespace_user ipc_create_named ptrace_traceme prctl_named
           kill_probe_outside kcmp_outside memory_low memory_rw_named memory_r_named statfs_named touch_named chdir_named
           fchdir_named sc_socketcall32_named sigio_owner_outside sigio_owner_ex_outside memory_rw_hint_named
           signal_family_named sigio_owner_family_named read_family_named"
    other="sc_sigaction_usr1 sc_fcntl_getfl sc_munmap_out sc_munmap32_out sc_poll_other lock_other fcntl_getown lock_open
           socketpair_other shutdown_other unix_bind_other genl_lookup_other socket_ioctl_other ioctl_argument_other
           rlimit_other task_getpgid_self task_getsid_outside ipc_create_other prctl_other kill_probe_self memory_rw_other
           statfs_other touch_times chdir_other sc_socketcall32_other sigio_owner_self memory_rw_hintless
           signal_family_other read_family_other"
    if [ -x "$work/lsm-probe32" ]; then
        report="$report
$(env -u SUDO_UID -u SUDO_GID -u SUDO_USER "$bin/kfilterctl" launch "$work/lsm-probe32" 2>/dev/null)"
        named="$named sc32_sigaction_trap sc32_getppid sc32_fcntl64_setlk sc32_munmap_in"
        other="$other sc32_sigaction_usr1 sc32_fcntl64_getfl sc32_munmap_out"
    else
        echo "k4: no lsm-probe32 (no i386 build): its rows were not run"
    fi
    outcome=denied
    word=deny
    [ "$mode" = audit ] && { outcome=ok; word=audit; }
    for row in $named; do
        echo "$report" | grep -qx "$row=$outcome" || { echo "FAIL k4 $mode: expected $row=$outcome"; fail=1; }
    done
    for row in $other; do
        echo "$report" | grep -qx "$row=ok" || { echo "FAIL k4 $mode: expected $row=ok"; fail=1; }
    done
    watch=$("$bin/kfilterctl" watch 1)
    for needle in /system/syscall/rt_sigaction/5 /system/syscall/getppid /system/syscall/fcntl/6 \
                  '/system/syscall/munmap addr=0x0000000520001000+4096' '/system/syscall/munmap addr=0x0000000052001000+4096' \
                  /system/syscall/poll/7 /system/syscall/sched_getscheduler /system/fork "$k4/lock-deny" /system/fcntl/setown \
                  /system/socketpair/unix/stream/0 /system/socket/shutdown/wr "127.0.0.1:$((port + 5))" /@kf-k4-bind \
                  /net/netlink/generic/nl80211 /net/netlink/route/34 /net/ioctl/0x0000541b "$k4/ioctl-arg arg=0x00000007" \
                  /system/syscall/getpeername /system/rlimit/core \
                  /system/rlimit/nofile/other /system/task/getpgid /system/cred/setgroups /system/capability/sys_nice \
                  /system/namespace/user /system/ipc/create/msg/4b46 /system/ptrace/traceme /system/kernel/module/net-pf-12 \
                  /system/prctl/0x000f /system/memory/low '/system/memory/private/rw addr=0x0000000530000000+4096' \
                  '/system/memory/private/r addr=0x0000000531000000+4096' "/system/statfs$k4/k4-statfs" "$k4/touch-deny" \
                  "$k4/chdir-deny" 'lsm-probe signal=0x0000000A' 'lsm-probe signal=0x0000001D' 'lsm-probe ptrace=0x00000009'; do
        printf '%s\n' "$watch" | grep "$word " | grep -q -- "$needle" || { echo "FAIL k4 $mode: no $word event for $needle"; fail=1; }
    done
    # The probe, kcmp and the two SIGIO owners out of the family: open decisions on the outside program (sleep).
    [ "$(printf '%s\n' "$watch" | grep "$word " | grep ' open ' | grep -c 'sleep')" -ge 4 ] ||
        { echo "FAIL k4 $mode: no $word events for the kill probe, kcmp and the SIGIO owners"; fail=1; }
    printf '%s\n' "$watch" | grep -E -q '/system/syscall/(rt_sigaction/10|poll/1$)|/system/socketpair/unix/dgram|shutdown/rd|/system/rlimit/nofile$|/system/task/getsid|addr=0x0000000532000000|/system/prctl/0x0010|kf-none|/net/ioctl/0x00005411|kf-k4-free|signal=0x0000000C|ptrace=0x00000011' &&
        { echo "FAIL k4 $mode: an event for an action no rule names"; fail=1; }
done

# ABI 12: sends to AF_UNIX peers, by message rules naming the peer (unix=): to a connected abstract server by match=, to a
# path server by size=, a datagram's sendto by index= (its socket's first send) and by the peer's path (absolute, and
# relative to the cwd), each refused (block) or logged (audit) and named as a connect to it is; the send next to each,
# and a socketpair's (its peer has no name), pass without an event.
k6=$work/files/k6
mkdir -p "$k6"
for mode in block audit; do
    cat >"$work/k6-policy.txt" <<POLICY
mode $mode
protect /lsm-probe
block-network on
network-loopback off
network-default allow
deny|message|unix=/@kf-k6-x11|match=6C00@0
deny|message|unix=$k6/kf-k6.sock|size=5
deny|message|unix=/@kf-k6-dgram|index=1
deny|message|unix=$k6/kf-k6-dgram.sock
POLICY
    "$bin/kfilterctl" policy "$work/k6-policy.txt" --no-track >/dev/null 2>&1 || { echo "FAIL k6 $mode: policy rejected"; fail=1; continue; }
    "$bin/kfilterctl" clear >/dev/null 2>&1
    report=$(env -u SUDO_UID -u SUDO_GID -u SUDO_USER "$bin/kfilterctl" launch "$work/lsm-probe" k6 "$k6" 2>/dev/null)
    outcome=denied
    word=deny
    [ "$mode" = audit ] && { outcome=ok; word=audit; }
    for row in unix_match_named unix_size_named unix_index_named unix_sendto_named unix_sendto_relative_named; do
        echo "$report" | grep -qx "$row=$outcome" || { echo "FAIL k6 $mode: expected $row=$outcome"; fail=1; }
    done
    for row in unix_match_other unix_size_other unix_index_other unix_sendto_other unix_socketpair_other; do
        echo "$report" | grep -qx "$row=ok" || { echo "FAIL k6 $mode: expected $row=ok"; fail=1; }
    done
    watch=$("$bin/kfilterctl" watch 1)
    for needle in 'send unix /@kf-k6-x11 socket:' "send unix $k6/kf-k6.sock socket:" 'send unix /@kf-k6-dgram socket:' \
                  "send unix $k6/kf-k6-dgram.sock socket:"; do
        printf '%s\n' "$watch" | grep "$word " | grep -q -- "$needle" || { echo "FAIL k6 $mode: no $word event for $needle"; fail=1; }
    done
    printf '%s\n' "$watch" | grep -E -q 'kf-k6-free|data=4200|kf-k6.sock socket:\[[0-9]*\] #2 |kf-k6-dgram socket:\[[0-9]*\] #2 ' &&
        { echo "FAIL k6 $mode: an event for a send no rule names"; fail=1; }
done

# Fail closed: block mode pins the BPF links. A protected program stays confined after
# kfilterd is killed; a new kfilterd takes the pinned layer over; only off unpins it.
pins=/sys/fs/bpf/kfilter
write_policy block on on
"$bin/kfilterctl" policy "$work/policy.txt" --no-track >/dev/null 2>&1 || { echo "FAIL pin: policy rejected"; fail=1; }
[ -n "$(ls "$pins/links" 2>/dev/null)" ] || { echo "FAIL pin: block mode pinned no links"; fail=1; }
mkdir -p "$work/pin"
cp "$(readlink -f /bin/sh)" "$work/pin/lsm-probe"   # a shell under the protected name
env -u SUDO_UID -u SUDO_GID -u SUDO_USER "$bin/kfilterctl" launch "$work/pin/lsm-probe" -c \
    'cd "$1"; while [ ! -e go ]; do sleep 0.1; done
     if cat /etc/hostname >/dev/null 2>&1; then echo pinned_open=ok; else echo pinned_open=denied; fi' \
    sh "$work/pin" >"$work/pin/report" 2>/dev/null &
pinned=$!
sleep 1
kill -9 "$daemon"
wait "$daemon" 2>/dev/null
# The killed kfilterd's pid is no longer exempt from the ptrace decision (its atexit never ran).
bpftool -j map dump pinned "$pins/maps/kb_config" 2>/dev/null | grep -q '"daemon_tgid":0' ||
    { echo "FAIL pin: the pinned layer still exempts the dead kfilterd's pid"; fail=1; }
touch "$work/pin/go"
wait "$pinned"
grep -qx pinned_open=denied "$work/pin/report" || { echo "FAIL pin: the open passed once kfilterd was gone"; fail=1; }
# Taken over as a layer pinned before the rule sets (no kb_live pin): end marks after set 0's lists, then the saved
# policy; a protected program's open is still refused afterwards.
rm -f "$pins/maps/kb_live"
# A program the killed kfilterd had stopped for WMI probing (kb_wmi_stopped) is resumed by the next.
sleep 60 &
stopped=$!
kill -STOP "$stopped"
key=$(printf '0x%02x 0x%02x 0x%02x 0x%02x' $((stopped & 255)) $((stopped >> 8 & 255)) $((stopped >> 16 & 255)) $((stopped >> 24)))
bpftool map update pinned "$pins/maps/kb_wmi_stopped" key $key value $key || { echo "FAIL pin: no kb_wmi_stopped"; fail=1; }
start_daemon
grep -q 'T (stopped)' "/proc/$stopped/status" && { echo "FAIL pin: a program stopped for WMI probing stays stopped"; fail=1; }
kill -CONT "$stopped"
kill "$stopped"
grep -q 'took over the pinned BPF layer' "$log" || { echo "FAIL pin: the new kfilterd did not take the pins over"; fail=1; }
[ -n "$(ls "$pins/links" 2>/dev/null)" ] || { echo "FAIL pin: a restart dropped the pins"; fail=1; }
env -u SUDO_UID -u SUDO_GID -u SUDO_USER "$bin/kfilterctl" launch "$work/pin/lsm-probe" -c \
    'if cat /etc/hostname >/dev/null 2>&1; then echo adopted_open=ok; else echo adopted_open=denied; fi' \
    >"$work/pin/adopted" 2>/dev/null
grep -qx adopted_open=denied "$work/pin/adopted" || { echo "FAIL pin: the layer taken over without kb_live let the open pass"; fail=1; }
"$bin/kfilterctl" off >/dev/null 2>&1
[ -e "$pins" ] && { echo "FAIL pin: off left $pins"; fail=1; }
# A taken-over layer's syscall entry points stay pinned until a policy replaces them: without the saved policy (not
# adopted), the calls its rules name are still decided by the policy in its maps.
printf 'mode block\nprotect /lsm-probe\nblock-files on\ndeny|system|/system/syscall/getppid\n' >"$work/pin-syscall.txt"
"$bin/kfilterctl" policy "$work/pin-syscall.txt" --no-track >/dev/null 2>&1 || { echo "FAIL pin syscall: policy rejected"; fail=1; }
ls "$pins/links" 2>/dev/null | grep -qx kb_s_do_sys_getppid || { echo "FAIL pin syscall: getppid's entry point not pinned"; fail=1; }
kill -9 "$daemon"
wait "$daemon" 2>/dev/null
rm -f /run/kfilter/policy
start_daemon
ls "$pins/links" 2>/dev/null | grep -qx kb_s_do_sys_getppid ||
    { echo "FAIL pin syscall: a takeover without a policy to adopt dropped getppid's entry point"; fail=1; }
# Started directly, protected by its name in the maps: kfilterctl launch needs kfilterd's own policy to admit it.
report=$(env -u SUDO_UID -u SUDO_GID -u SUDO_USER "$work/lsm-probe" k4 "$k4" "$outside" "$port" 2>/dev/null)
echo "$report" | grep -qx sc_getppid=denied || { echo "FAIL pin syscall: getppid passed after the takeover"; fail=1; }
"$bin/kfilterctl" off >/dev/null 2>&1

# Wine: thread-handle rules and the registry requests Windows decides beyond open, query and
# set (flush, change notification, key security), from wineserver's protocol. The probe is a
# Windows program built here (no CRT) and run in a throwaway prefix of the user who ran sudo.
wine=/opt/wine-stable/bin/wine
clang=$(command -v clang-18 || command -v clang || true)
if [ -x "$wine" ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ] && [ -n "$clang" ] &&
   ld -V 2>/dev/null | grep -q i386pep; then
    home=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    prefix="$work/prefix"
    as_user() {
        runuser -u "$SUDO_USER" -- env HOME="$home" WINEPREFIX="$prefix" WINEDEBUG=-all \
            WINEDLLOVERRIDES='mscoree,mshtml=;winemenubuilder.exe=d' DISPLAY= WAYLAND_DISPLAY= "$@"
    }
    chmod 755 "$work"
    mkdir -p "$prefix"
    chown "$SUDO_USER" "$prefix"
    wlib=/opt/wine-stable/lib/wine/x86_64-windows
    if "$clang" -target x86_64-w64-windows-gnu -O2 -ffreestanding -fno-stack-protector -fno-builtin \
           -c tests/linux_lsm_wine_probe.c -o "$work/kfprobe.o" &&
       ld -m i386pep --subsystem console -e start -o "$work/kfprobe.exe" "$work/kfprobe.o" \
           "$wlib/libkernel32.a" "$wlib/libadvapi32.a" "$wlib/libntdll.a" "$wlib/libuser32.a" "$wlib/libole32.a"; then
        chmod 755 "$work/kfprobe.exe"
        cp "$work/kfprobe.exe" "$work/kfpeer.exe"   # the other protected program kfprobe.exe starts
        echo data >"$work/hidden"
        chmod 644 "$work/hidden"
        # A protected shell (not Wine) writes a raw close_handle(0) to the pipe kfprobe.exe
        # registered as its request pipe.
        cp "$(readlink -f /bin/sh)" "$work/kfsh"
        zeros=$(printf '\\0%.0s' $(seq 1 63))
        cat >"$work/raw.sh" <<SH
{ "\$1" "\$2" register
  if printf '\\025$zeros' 2>/dev/null; then echo raw_pipe_write=ok >&2
  else echo raw_pipe_write=denied >&2; fi; } | cat >/dev/null
SH
        echo "creating a test Wine prefix (a minute or two)..."
        as_user timeout 600 "$wine" wineboot -i >/dev/null 2>&1 || { echo "FAIL wine: wineboot"; fail=1; }
        as_user /opt/wine-stable/bin/wineserver -p 600 >/dev/null 2>&1
        # Windows without a display: the null driver (the probe makes a window to enumerate).
        as_user "$wine" reg.exe add 'HKCU\Software\Wine\Drivers' /v Graphics /d null /f >/dev/null 2>&1
        for key in Flush Notify GetSecurity SetSecurity Double Long; do
            as_user "$wine" reg.exe add "HKCU\\Software\\KfProbe\\$key" /f >/dev/null 2>&1
        done
        for mode in block audit; do
            # Each key's open is allowed once (uses=1): the request after it meets the deny.
            cat >"$work/wine-policy.txt" <<POLICY
mode $mode
protect kfprobe.exe
protect /kfsh
block-registry on
block-process-memory on
block-files on
block-file-queries on
deny|file|$work/hidden|hide
deny|thread-peer|Z:\\*\\kfpeer.exe|rights=get-context|image=kfprobe.exe
deny|peer|Z:\\*\\kfpeer.exe|rights=vm-read,create-thread|image=kfprobe.exe
deny|system|/system/wine/list_processes|module=kfpeer.exe
deny|system|/system/wine/get_system_handles|module=nomatch.dll
deny|system|/system/wine/create_mutex/kf-probe|module=kfpeer.exe
deny|thread|Z:\\*\\kfpeer.exe|module=kfpeer.exe
deny|system|/system/uname
deny|system|/system/sysinfo|exact|image=kfnone1.exe
deny|system|/system/sysinfo|exact|image=kfnone2.exe
deny|system|/system/sysinfo|exact|image=kfnone3.exe
deny|system|/system/sysinfo|exact|image=kfnone4.exe
deny|system|/system/sysinfo|exact|image=kfnone5.exe
deny|system|/system/sysinfo|exact|image=kfnone6.exe
deny|system|/system/sysinfo|exact|image=kfnone7.exe
deny|system|/system/sysinfo|exact|image=kfnone8.exe
allow|system|/system/sysinfo|exact|rights=read,write,execute,delete,rename,set-security,enumerate,query,create,connect,listen,raw-device,open|image=kfpeer.exe
deny|system|/system/sysinfo
deny|system|/system/userfaultfd
deny|system|/system/memory/private|image=kfprobe.exe
block-direct-syscall on
audit|file|/*/mountmgr.sys|image=winedevice.exe
block-volume-serial on
deny|pipe|\\??\\pipe\\kfprobe-denied
deny|file|\\??\\MountPointManager
deny|file|\\Sessions\\*\\kfprobe-section-denied
allow|thread-open|C:\\*|rights=query-limited-information|risk=test
allow|open|C:\\*|rights=dup-handle,query-information|risk=test
allow|registry|\\REGISTRY\\USER\\*\\Software\\KfProbe\\Flush|rights=read,enumerate|uses=1
deny|registry|\\REGISTRY\\USER\\*\\Software\\KfProbe\\Flush
deny|registry|\\REGISTRY\\USER\\*\\Software\\KfProbe\\Double
allow|registry|\\REGISTRY\\USER\\*\\Software\\KfProbe\\Long|rights=read,enumerate
allow|registry|\\REGISTRY\\USER\\*\\Software\\KfProbe\\Notify|rights=read,enumerate|uses=1
deny|registry|\\REGISTRY\\USER\\*\\Software\\KfProbe\\Notify
allow|registry|\\REGISTRY\\USER\\*\\Software\\KfProbe\\GetSecurity|rights=read,enumerate|uses=1
deny|registry|\\REGISTRY\\USER\\*\\Software\\KfProbe\\GetSecurity
allow|registry|\\REGISTRY\\USER\\*\\Software\\KfProbe\\SetSecurity|rights=read,set-security|uses=1
deny|registry|\\REGISTRY\\USER\\*\\Software\\KfProbe\\SetSecurity
POLICY
            "$bin/kfilterctl" policy "$work/wine-policy.txt" --no-track >/dev/null 2>&1 ||
                { echo "FAIL wine $mode: policy rejected"; fail=1; continue; }
            "$bin/kfilterctl" clear >/dev/null 2>&1
            if [ "$mode" = block ]; then
                # A fresh wineserver, whose winedevice loads its drivers under this policy; warmed
                # up, so the outside processes kfprobe.exe reaches are already named.
                as_user /opt/wine-stable/bin/wineserver -k >/dev/null 2>&1
                as_user /opt/wine-stable/bin/wineserver -p 600 >/dev/null 2>&1
                as_user "$wine" cmd /c exit >/dev/null 2>&1
            fi
            report=$(as_user "$wine" "$work/kfprobe.exe" 2>/dev/null)
            report="$report
$(as_user "$work/kfsh" "$work/raw.sh" "$wine" "$work/kfprobe.exe" 2>&1)"
            if [ "$mode" = block ]; then
                expected="thread_open=denied thread_open_query=ok thread_dup_out=denied reg_flush=denied
                          reg_notify=denied reg_get_security=denied reg_set_security=denied process_open=denied
                          thread_next_dup=denied thread_open_forged=denied thread_open_own=ok
                          process_next_dup=denied event_dup=ok event_dup_sync=ok vmsplice_request=denied
                          splice_request=denied exec_request=denied raw_pipe_write=denied attr_hidden=hidden
                          peer_thread_context=denied peer_thread_query=ok peer_read_memory=denied
                          peer_remote_thread=denied peer_list_processes=denied peer_system_handles=ok
                          peer_thread_create=denied peer_named_mutex=denied anon_exec=denied direct_open=denied
                          reg_double_backslash=denied
                          nt_pipe_create=ok nt_pipe_open=ok nt_pipe_denied=denied nt_device=denied volume_serial=denied
                          section_create=ok section_open=ok section_denied=denied section_dup=ok section_dup_copy=ok event_dup_modify=ok token_dup=ok reg_long_value=ok"
                inproc="win32k_cursor=denied win32k_enum=denied win32k_i386=ok wmi_bios=denied wmi_os=ok wmi_bios32=denied
                        wmi_star=denied wmi_long=denied wmi_unsized=denied wmi_dash=denied wmi_module=denied
                        wmi_get_object=denied wmi_get_object_key=denied wmi_get_object_os=ok wmi_instance_enum=denied
                        wmi_async=denied wmi_method=denied win32k_key_f1=denied win32k_key_a=ok win32k_text_own=ok
                        win32k_text_other=denied ntdll_debug_port=denied ntdll_basic=ok ntdll_wine_own=ok"
            else
                expected="thread_open=ok thread_open_query=ok thread_dup_out=ok reg_flush=ok reg_notify=ok
                          reg_get_security=ok reg_set_security=ok process_open=ok thread_next_dup=ok
                          thread_open_forged=ok thread_open_own=ok process_next_dup=ok event_dup=ok
                          event_dup_sync=ok vmsplice_request=ok splice_request=ok exec_request=ok raw_pipe_write=ok
                          attr_hidden=ok peer_thread_context=ok peer_thread_query=ok peer_read_memory=ok
                          peer_remote_thread=ok peer_list_processes=ok peer_system_handles=ok peer_thread_create=ok
                          peer_named_mutex=ok anon_exec=ok direct_open=ok reg_double_backslash=ok
                          nt_pipe_create=ok nt_pipe_open=ok nt_pipe_denied=ok nt_device=ok volume_serial=ok
                          section_create=ok section_open=ok section_denied=ok section_dup=ok section_dup_copy=ok event_dup_modify=ok token_dup=ok reg_long_value=ok"
                inproc="win32k_cursor=ok win32k_enum=ok win32k_i386=ok wmi_bios=ok wmi_os=ok wmi_bios32=ok
                        wmi_star=ok wmi_long=ok wmi_unsized=ok wmi_dash=ok wmi_module=ok
                        wmi_get_object=ok wmi_get_object_key=ok wmi_get_object_os=ok wmi_instance_enum=ok wmi_async=ok
                        wmi_method=ok win32k_key_f1=ok win32k_key_a=ok win32k_text_own=ok win32k_text_other=ok
                        ntdll_debug_port=ok ntdll_basic=ok ntdll_wine_own=ok"
            fi
            for line in $expected; do
                echo "$report" | grep -qx "$line" || { echo "FAIL wine $mode: expected $line (got: $(echo $report))"; fail=1; }
            done
            # printf, not echo: dash's echo ends at a Windows path's "\c" (Z:\tmp\claude-...).
            watch=$("$bin/kfilterctl" watch 1)
            word=deny
            [ "$mode" = audit ] && word=audit
            for target in thread-open thread-handle registry open peer thread-peer; do
                printf '%s\n' "$watch" | grep 'kfprobe.exe' | grep " $target " | grep -q "$word " ||
                    { echo "FAIL wine $mode: no $word event for $target"; fail=1; }
            done
            for target in system thread; do
                printf '%s\n' "$watch" | grep 'kfpeer.exe' | grep " $target " | grep -q "$word " ||
                    { echo "FAIL wine $mode: no $word event for kfpeer.exe's $target"; fail=1; }
            done
            # Wine runs with uname, sysinfo and userfaultfd refused; winedevice's driver loads are decided.
            printf '%s\n' "$watch" | grep 'kfprobe.exe' | grep "$word " | grep -q ' /system/uname$' ||
                { echo "FAIL wine $mode: no $word event for uname"; fail=1; }
            # The block loop's report (00:07; the loop had loaded the deny first, 04cbf1d): a Wine program's image= allow
            # ahead of a deny for everyone, here the 9th rule on the path (tried with the wildcard rules), lets that
            # program's sysinfo through, no one else's.
            printf '%s\n' "$watch" | grep 'kfpeer.exe' | grep ' system ' | grep 'allow ' | grep -q ' /system/sysinfo$' ||
                { echo "FAIL wine $mode: kfpeer.exe's sysinfo not allowed by its image= allow"; fail=1; }
            printf '%s\n' "$watch" | grep 'kfpeer.exe' | grep ' system ' | grep "$word " | grep -q ' /system/sysinfo$' &&
                { echo "FAIL wine $mode: kfpeer.exe's sysinfo met the deny for everyone"; fail=1; }
            printf '%s\n' "$watch" | grep 'kfprobe.exe' | grep ' system ' | grep "$word " | grep -q ' /system/sysinfo$' ||
                { echo "FAIL wine $mode: no $word event for kfprobe.exe's sysinfo"; fail=1; }
            printf '%s\n' "$watch" | grep 'kfprobe.exe' | grep "$word " | grep -q ' /system/memory/private/rwx$' ||
                { echo "FAIL wine $mode: no $word event for private executable memory"; fail=1; }
            # The probe's own open syscall: flagged direct (0x2000), refused by block-direct-syscall.
            direct=0x2000
            [ "$mode" = audit ] && direct=0x2001
            printf '%s\n' "$watch" | grep 'kfprobe.exe' | grep "$word " | grep "flags=$direct " | grep -q ' /etc/hostname$' ||
                { echo "FAIL wine $mode: no direct $word event for the probe's own open"; fail=1; }
            [ "$mode" = audit ] || printf '%s\n' "$watch" | grep 'winedevice.exe' | grep 'audit ' | grep -q '/mountmgr.sys$' ||
                { echo "FAIL wine $mode: no audit event for winedevice's mountmgr.sys"; fail=1; }
            printf '%s\n' "$watch" | grep 'kfprobe.exe' | grep "$word " | grep -q ' volume ' ||
                { echo "FAIL wine $mode: no $word event for the volume serial query"; fail=1; }
            for name in 'kfprobe-denied' 'MountPointManager' 'kfprobe-section-denied'; do
                printf '%s\n' "$watch" | grep 'kfprobe.exe' | grep "$word " | grep -q "$name" ||
                    { echo "FAIL wine $mode: no $word event for the NT object $name"; fail=1; }
            done
            # Raw requests: by vmsplice (278), splice (275), and undecoded writes (0x4000).
            for value in 0x4116 0x4113 0x4000; do
                printf '%s\n' "$watch" | grep "$word " | grep -q " value=$value " ||
                    { echo "FAIL wine $mode: no $word event for the raw request $value"; fail=1; }
            done
            printf '%s\n' "$watch" | grep 'kfprobe.exe' | grep "$word " | grep 'value=0x80 ' | grep -q "$work/hidden" ||
                { echo "FAIL wine $mode: no $word event for the hidden file's query"; fail=1; }
            printf '%s\n' "$watch" | grep 'kfprobe.exe' | grep ' thread-open ' | grep -q 'RISK ' ||
                { echo "FAIL wine $mode: no RISK record for the thread-open allow"; fail=1; }
            # Calls Wine answers in-process (uprobes): win32u.so x64 and i386, wbemprox's ExecQuery
            # x64 and i386. A run and policy of their own: wmic's file decisions would crowd the watch.
            # K5: a key (VK_F1 refused, VK_A not), another program's window (kfpeer.exe's title refused, its own not),
            # ntdll.so's ProcessDebugPort (ProcessBasicInformation not), an ExecMethod; Wine's own calls not decided:
            # ProcessDebugPort asked by ntdll.so's NtClose itself (the probe closes a bad handle with BeingDebugged set:
            # it returns into ntdll.so outside the dispatcher, so it is no event; the two events are kernel32's start_process,
            # whose CheckRemoteDebuggerPresent before the entry point is Windows code, and the probe's own call), and the class
            # win32u.so's own start asks of NtQuerySystemInformation (62) denied without one event (through win32u.so's
            # PLT: it returns into win32u.so, so this one shows a return outside ntdll.so, not the dispatcher check).
            cat >"$work/inproc-policy.txt" <<POLICY
mode $mode
protect kfprobe.exe
deny|system|/system/win32k/NtUserGetCursorPos
deny|system|/system/win32k/NtUserBuildHwndList
deny|system|/system/win32k/NtUserGetAsyncKeyState|image=rundll32.exe
deny|system|/system/win32k/NtUserGetAsyncKeyState/0x00000070|image=kfprobe.exe
deny|system|/system/win32k/NtUserInternalGetWindowText/@other|image=kfprobe.exe
deny|system|/system/ntdll/NtQueryInformationProcess/7|image=kfprobe.exe
deny|system|/system/ntdll/NtQuerySystemInformation/62|image=kfprobe.exe
deny|system|/system/wmi/Win32_BIOS
deny|system|/system/wmi/Win32_Processor|module=kfprobe.exe
deny|system|/system/wmi/Win32_Process/KfNoSuchMethod
POLICY
            "$bin/kfilterctl" policy "$work/inproc-policy.txt" --no-track >/dev/null 2>&1 ||
                { echo "FAIL wine $mode: in-process policy rejected"; fail=1; }
            "$bin/kfilterctl" clear >/dev/null 2>&1
            report=$(as_user "$wine" "$work/kfprobe.exe" inproc 2>/dev/null)
            for line in $inproc; do
                echo "$report" | grep -qx "$line" || { echo "FAIL wine $mode: expected $line (got: $(echo $report))"; fail=1; }
            done
            watch=$("$bin/kfilterctl" watch 1)
            for event in 'kfprobe.exe.* /system/win32k/NtUserGetCursorPos$' 'kfprobe.exe.* /system/win32k/NtUserBuildHwndList$' \
                         'rundll32.exe.* /system/win32k/NtUserGetAsyncKeyState$' \
                         'kfprobe.exe.* /system/win32k/NtUserGetAsyncKeyState/0x00000070$' \
                         'kfprobe.exe.* /system/win32k/NtUserInternalGetWindowText/@other$' \
                         'kfprobe.exe.* /system/ntdll/NtQueryInformationProcess/7$' \
                         'kfprobe.exe.* /system/wmi/win32_process/kfnosuchmethod$'; do
                printf '%s\n' "$watch" | grep "$word " | grep -q "$event" ||
                    { echo "FAIL wine $mode: no $word event for $event"; fail=1; }
            done
            debug_port=$(printf '%s\n' "$watch" | grep 'kfprobe.exe' | grep "$word " | grep -c ' /system/ntdll/NtQueryInformationProcess/7$')
            [ "$debug_port" = 2 ] ||
                { echo "FAIL wine $mode: $debug_port ProcessDebugPort events, not kernel32's start and the probe's own call alone (NtClose's own is Wine's)"; fail=1; }
            printf '%s\n' "$watch" | grep 'kfprobe.exe' | grep -q '/system/ntdll/NtQuerySystemInformation/62' &&
                { echo "FAIL wine $mode: Wine's own NtQuerySystemInformation(62) (win32u.so's start) was decided"; fail=1; }
            printf '%s\n' "$watch" | grep 'kfprobe.exe' | grep -q '/system/win32k/NtUserGetAsyncKeyState/0x00000041' &&
                { echo "FAIL wine $mode: VK_A met a rule"; fail=1; }
            if [ "$mode" = block ]; then
                # NtUserCallHwndParam's cost (K5): GetWindowRect of its own window (Wine answers it through
                # NtUserCallHwndParam, as MapleStory's every-frame GetWindowLong and ClientToScreen) with no rule naming the
                # call, then with one naming its keys (each call takes the uprobe's trap, then its owner is looked up).
                # Fails past HWND_NS_MAX ns added a call (default 5000): at an assumed 1,000 such calls a second that is
                # 5 ms of each second (0.5% of a core), charged to every Wine process mapping win32u.so while it is loaded.
                printf 'mode block\nprotect kfprobe.exe\n' >"$work/hwnd-off.txt"
                printf 'mode block\nprotect kfprobe.exe\ndeny|system|/system/win32k/NtUserCallHwndParam/@other\n' >"$work/hwnd-on.txt"
                hwnd_ns() {
                    "$bin/kfilterctl" policy "$1" --no-track >/dev/null 2>&1 &&
                        as_user "$wine" "$work/kfprobe.exe" hwndparam 2>/dev/null | sed -n 's/^hwndparam_ns=//p'
                }
                # ... and with 2,000 system rules as well (the loop's policies' size), 250 of them wildcards (the kernel holds
                # 256): a call on its own window decides nothing under a rule on @other (kfilterd's KB_UP_SKIP_*), so the rule
                # set adds nothing to it.
                {
                    cat "$work/hwnd-on.txt"
                    i=0
                    while [ "$i" -lt 2000 ]; do
                        if [ "$i" -lt 250 ]; then echo "deny|system|/system/wine/*_k$i|image=x$i.exe"
                        else echo "deny|system|/system/wine/open_mutex/kf_k$i|image=x$i.exe"; fi
                        i=$((i + 1))
                    done
                } >"$work/hwnd-big.txt"
                off=$(hwnd_ns "$work/hwnd-off.txt")
                on=$(hwnd_ns "$work/hwnd-on.txt")
                big=$(hwnd_ns "$work/hwnd-big.txt")
                if [ -z "$off" ] || [ -z "$on" ] || [ -z "$big" ]; then
                    echo "FAIL wine: no NtUserCallHwndParam timing (off '$off', on '$on', big '$big')"; fail=1
                elif [ $((on - off)) -gt "${HWND_NS_MAX:-5000}" ] || [ $((big - off)) -gt "${HWND_NS_MAX:-5000}" ]; then
                    echo "FAIL wine: NtUserCallHwndParam's probe adds $((on - off)) ns a call, $((big - off)) with 2,000 rules ($off ns without it)"; fail=1
                else
                    echo "wine: NtUserCallHwndParam $off ns a call, $on ns probed, $big ns probed under 2,000 more rules"
                fi
            fi
            [ "$(printf '%s\n' "$watch" | grep "$word " | grep -c 'wmic.exe.* /system/wmi/win32_bios$')" -ge 2 ] ||
                { echo "FAIL wine $mode: no $word events for both wmic queries of Win32_BIOS"; fail=1; }
            # addr= rules (ABI 10): kfprobe.exe reaches into kfpeer.exe ("target") inside and outside the ranges, by a
            # handle kfilter named and one from NtGetNextProcess (\@unknown, with a range of its own, until
            # get_process_info names it: then kfpeer.exe's query rule refuses addr_next_query_in, and its read rule
            # addr_next_read_in at wineserver's process_vm_readv and its fallbacks); a module named but not loaded matches
            # nothing; its own memory written by pseudo handle (/system/wine/self/write_process_memory: Wine 11 reads its own
            # memory without a request); 8 addr= rules on kfpeer.exe's own path before the 9th. block-process-signals:
            # wineserver's SIGUSR1 for SuspendThread and GetThreadContext (addr_dr_out, addr_get_context) is Wine's own.
            peerwin="Z:$(printf '%s' "$work/kfpeer.exe" | tr '/' '\\')"
            {
                printf '%s\n' "mode $mode" "protect kfprobe.exe" "block-process-signals on" \
                    'deny|peer|Z:\*\kfpeer.exe|rights=vm-read|addr=0x500001000-0x500001FFF,kfpeer.exe+0x1000-0x1FFF|image=kfprobe.exe' \
                    'deny|peer|Z:\*\kfpeer.exe|rights=vm-read|addr=notloaded.dll+0-0x7FFFFFFF|image=kfprobe.exe' \
                    'deny|peer|Z:\*\kfpeer.exe|rights=query-information|addr=0x500001000-0x500001FFF|image=kfprobe.exe' \
                    'deny|peer|Z:\*\kfpeer.exe|addr=0x500001000-0x500001FFF|image=kfprobe.exe' \
                    'deny|thread-peer|Z:\*\kfpeer.exe|rights=set-context|addr=0x500001000-0x500001FFF|image=kfprobe.exe' \
                    'deny|system|/system/wine/self/write_process_memory|addr=0x510001000-0x510001FFF|image=kfprobe.exe' \
                    'deny|peer|\@unknown|rights=query-information|addr=0x500002000-0x500002FFF|image=kfprobe.exe'
                for i in 1 2 3 4 5 6 7 8; do
                    printf '%s\n' "deny|peer|$peerwin|rights=vm-read|addr=0x60000${i}000-0x60000${i}FFF|image=kfprobe.exe"
                done
                printf '%s\n' "deny|peer|$peerwin|rights=vm-read|addr=0x500003000-0x500003FFF|image=kfprobe.exe"
            } >"$work/addr-policy.txt"
            "$bin/kfilterctl" policy "$work/addr-policy.txt" --no-track >/dev/null 2>&1 ||
                { echo "FAIL wine $mode: addr= policy rejected"; fail=1; }
            "$bin/kfilterctl" clear >/dev/null 2>&1
            report=$(as_user "$wine" "$work/kfprobe.exe" addr 2>/dev/null)
            outcome=denied
            [ "$mode" = audit ] && outcome=ok
            for line in addr_read_in=$outcome addr_read_out=ok addr_edge_low=$outcome addr_edge_high=ok addr_marker_query=ok \
                        addr_spill_read=$outcome addr_module_in=$outcome addr_module_out=ok addr_query_in=$outcome \
                        addr_query_out=ok addr_dr_in=$outcome addr_dr_out=ok addr_get_context=ok addr_self_in=$outcome \
                        addr_self_out=ok addr_unknown_query_in=$outcome addr_unknown_query_out=ok \
                        addr_next_read_in=$outcome addr_next_query_in=$outcome addr_next_read_out=ok; do
                echo "$report" | grep -qx "$line" || { echo "FAIL wine $mode: expected $line (got: $(echo $report))"; fail=1; }
            done
            watch=$("$bin/kfilterctl" watch 1)
            for event in ' peer .*kfpeer.exe addr=0x0000000500001010+2$' ' thread-peer .*kfpeer.exe addr=0x0000000500001010+1$' \
                         ' system .*/system/wine/self/write_process_memory addr=0x0000000510001010+2$' \
                         ' peer .*@unknown addr=0x0000000500002010+1$'; do
                printf '%s\n' "$watch" | grep 'kfprobe.exe' | grep "$word " | grep -q "$event" ||
                    { echo "FAIL wine $mode: no $word event like $event"; fail=1; }
            done
            # Every wineserver request is /system/wine/<request> where a rule names it: one of each family, a name split
            # across wine_server_call's data chunks (decided whole), and chunks that do not add up to the header's
            # request_size (a raw request, 0x4000). A broad audit rule keeps meeting the requests decided before (the
            # token's open) and none a rule must name (select, get_message, close_handle, init_thread).
            requests="send_message set_foreground_window get_clipboard_data set_hook assign_job duplicate_token
                      get_object_name add_atom set_input_desktop lock_file"
            {
                # The split name's deny ahead of the broad rule, which meets open_mutex too (first match).
                printf '%s\n' "mode $mode" "protect kfprobe.exe" \
                    'deny|system|/system/wine/open_mutex/\BaseNamedObjects\kfprobe-split|image=kfprobe.exe' \
                    'audit|system|/system/wine/*|image=kfprobe.exe'
                for request in $requests; do printf '%s\n' "deny|system|/system/wine/$request|image=kfprobe.exe"; done
            } >"$work/requests-policy.txt"
            "$bin/kfilterctl" policy "$work/requests-policy.txt" --no-track >/dev/null 2>&1 ||
                { echo "FAIL wine $mode: requests policy rejected"; fail=1; }
            "$bin/kfilterctl" clear >/dev/null 2>&1
            report=$(as_user timeout 120 "$wine" "$work/kfprobe.exe" requests 2>/dev/null)
            # Audit mode lets the short write through, after which wineserver reads garbage: its lines are not checked.
            [ "$mode" = block ] && for name in req_send_message req_foreground req_clipboard req_hook req_job req_token \
                                               req_object_name req_atom req_desktop req_lock split_name split_short; do
                echo "$report" | grep -qx "$name=denied" || { echo "FAIL wine $mode: expected $name=denied (got: $(echo $report))"; fail=1; }
            done
            watch=$("$bin/kfilterctl" watch 1)
            for request in $requests; do
                printf '%s\n' "$watch" | grep 'kfprobe.exe' | grep "$word " | grep -q " /system/wine/$request\$" ||
                    { echo "FAIL wine $mode: no $word event for /system/wine/$request"; fail=1; }
            done
            printf '%s\n' "$watch" | grep 'kfprobe.exe' | grep "$word " | grep -qF '/system/wine/open_mutex/\BaseNamedObjects\kfprobe-split' ||
                { echo "FAIL wine $mode: no $word event for the split name"; fail=1; }
            printf '%s\n' "$watch" | grep "$word " | grep -q ' value=0x4000 ' ||
                { echo "FAIL wine $mode: no $word event for the short chunks"; fail=1; }
            printf '%s\n' "$watch" | grep 'kfprobe.exe' | grep 'audit ' | grep -q ' /system/wine/open_token$' ||
                { echo "FAIL wine $mode: the broad audit rule no longer meets open_token"; fail=1; }
            printf '%s\n' "$watch" | grep -E ' /system/wine/(select|get_message|close_handle|init_thread)$' &&
                { echo "FAIL wine $mode: a broad rule met a request only a rule naming it decides"; fail=1; }
            # What a request reaches past its own decision (ABI 11): kfpeer.exe's window and thread by the pseudo-rights
            # (WM_COPYDATA by value=, its window by its full handle, its low 16 bits and a high word 0xFFFF; WM_USER+1
            # sent, notified, posted and posted to its thread; a raw set_window_pos, the handle at 0x14;
            # SetWindowLongPtr, which Wine sends as its internal message; its text read, audited), its process and thread
            # through a handle (value=<request>), keys (a global hook, an injected 'A', MountPointManager's ioctl by code)
            # and an RPC call (svcctl's RStartServiceW). WM_NULL, a thread hook and 'B' are named by no rule.
            {
                printf '%s\n' "mode $mode" "protect kfprobe.exe" \
                    'deny|peer|Z:\*\kfpeer.exe|rights=window-message|value=0x0000004A|image=kfprobe.exe' \
                    'deny|peer|Z:\*\kfpeer.exe|rights=window-message|value=0x00000401|image=kfprobe.exe' \
                    'deny|peer|Z:\*\kfpeer.exe|rights=window-message|value=0x8000000*|image=kfprobe.exe' \
                    'deny|peer|Z:\*\kfpeer.exe|rights=window-set|image=kfprobe.exe' \
                    'audit|peer|Z:\*\kfpeer.exe|rights=window-query|image=kfprobe.exe' \
                    'deny|peer|Z:\*\kfpeer.exe|value=assign_job|image=kfprobe.exe' \
                    'deny|thread-peer|Z:\*\kfpeer.exe|value=get_thread_times|image=kfprobe.exe' \
                    'deny|system|/system/wine/set_hook/13/global|image=kfprobe.exe' \
                    'deny|system|/system/wine/send_hardware_message/injected/keyboard|value=0x00000041|image=kfprobe.exe' \
                    'deny|system|/system/wine/ioctl/\??\MountPointManager/0x006d0008|image=kfprobe.exe' \
                    'deny|system|/system/rpc/367abb81-9844-35f1-ad32-98f038001003/19|image=kfprobe.exe'
            } >"$work/reach-policy.txt"
            "$bin/kfilterctl" policy "$work/reach-policy.txt" --no-track >/dev/null 2>&1 ||
                { echo "FAIL wine $mode: reach policy rejected"; fail=1; }
            "$bin/kfilterctl" clear >/dev/null 2>&1
            report=$(as_user timeout 120 "$wine" "$work/kfprobe.exe" reach 2>/dev/null)
            outcome=denied
            [ "$mode" = audit ] && outcome=ok
            for line in win_copydata=$outcome win_copydata_low16=$outcome win_copydata_high=$outcome win_send=$outcome \
                        win_notify=$outcome win_post=$outcome win_post_thread=$outcome win_set_pos=$outcome \
                        win_set_long=$outcome win_null=ok win_text=ok job_assign=$outcome thread_times=$outcome \
                        hook_global=$outcome hook_thread=ok input_a=$outcome input_b=ok ioctl_mountmgr=$outcome \
                        svc_start=$outcome; do
                echo "$report" | grep -qx "$line" || { echo "FAIL wine $mode: expected $line (got: $(echo $report))"; fail=1; }
            done
            watch=$("$bin/kfilterctl" watch 1)
            for event in ' peer .* value=0x80000000 .*kfpeer.exe$' ' peer .* value=0x40000000 .*kfpeer.exe$' \
                         ' peer .* value=0x101 .*kfpeer.exe$' ' thread-peer .* value=0x800 .*kfpeer.exe$' \
                         ' system .* /system/wine/set_hook/13/global$' ' system .* /system/wine/send_hardware_message/injected/keyboard$' \
                         ' system .* /system/wine/ioctl/\\??\\MountPointManager/0x006d0008$' \
                         ' system .* /system/rpc/367abb81-9844-35f1-ad32-98f038001003/19$'; do
                printf '%s\n' "$watch" | grep 'kfprobe.exe' | grep "$word " | grep -q "$event" ||
                    { echo "FAIL wine $mode: no $word event like $event"; fail=1; }
            done
            printf '%s\n' "$watch" | grep 'kfprobe.exe' | grep 'audit ' | grep -q ' peer .* value=0x20000000 .*kfpeer.exe$' ||
                { echo "FAIL wine $mode: no audit of the window text read"; fail=1; }
        done
        # A window and thread kfilter cannot place: kfpeer.exe makes its window, then kfilterd starts afresh (stop unpins
        # the layer), so neither is known: only rules naming \@unknown-window and \@unknown-thread meet them, and the allow
        # on \@unknown-window (before its deny) is not loaded.
        as_user "$wine" "$work/kfpeer.exe" window >/dev/null 2>&1 &
        held=$!
        sleep 3
        stop_daemon
        start_daemon
        printf '%s\n' 'mode block' 'protect kfprobe.exe' \
            'allow|peer|\@unknown-window|rights=window-set|image=kfprobe.exe' \
            'deny|peer|\@unknown-window|rights=window-set|image=kfprobe.exe' \
            'deny|peer|\@unknown-thread|rights=window-message|image=kfprobe.exe' >"$work/unplaced-policy.txt"
        "$bin/kfilterctl" policy "$work/unplaced-policy.txt" --no-track >/dev/null 2>&1 ||
            { echo "FAIL wine unplaced: policy rejected"; fail=1; }
        "$bin/kfilterctl" clear >/dev/null 2>&1
        report=$(as_user timeout 60 "$wine" "$work/kfprobe.exe" reach unplaced 2>/dev/null)
        for line in win_set_pos=denied win_null=denied win_set_long=denied win_unknown_message=denied; do
            echo "$report" | grep -qx "$line" || { echo "FAIL wine unplaced: expected $line (got: $(echo $report))"; fail=1; }
        done
        watch=$("$bin/kfilterctl" watch 1)
        for placeholder in '\\@unknown-window$' '\\@unknown-thread$'; do
            printf '%s\n' "$watch" | grep 'kfprobe.exe' | grep 'deny ' | grep -q "$placeholder" ||
                { echo "FAIL wine unplaced: no refusal on $placeholder"; fail=1; }
        done
        wait "$held"
        # Strict mode: an outside Wine program opening the client needs a handle rule (would-deny here).
        printf 'mode audit\nprotect kfprobe.exe\ndefault-deny on\nblock-process-memory on\n' >"$work/wine-policy.txt"
        "$bin/kfilterctl" policy "$work/wine-policy.txt" --no-track >/dev/null 2>&1 ||
            { echo "FAIL wine strict: policy rejected"; fail=1; }
        "$bin/kfilterctl" clear >/dev/null 2>&1
        cp "$work/kfprobe.exe" "$work/kfout.exe"
        as_user "$wine" "$work/kfprobe.exe" hold >/dev/null 2>&1 &
        held=$!
        report=$(as_user "$wine" "$work/kfout.exe" outside 2>/dev/null)
        wait "$held"
        echo "$report" | grep -qx outside_open=ok || { echo "FAIL wine strict: expected outside_open=ok (got: $(echo $report))"; fail=1; }
        "$bin/kfilterctl" watch 1 | grep 'kfout.exe' | grep ' handle ' | grep -q 'audit ' ||
            { echo "FAIL wine strict: no would-deny for the outside open of the client"; fail=1; }
        # A kfilterd that takes a pinned layer over keeps the running client's module table
        # (module= rules) current: code it maps after the restart is read in.
        printf 'mode block\nprotect kfprobe.exe\nblock-process-memory on\n' >"$work/wine-policy.txt"
        "$bin/kfilterctl" policy "$work/wine-policy.txt" --no-track >/dev/null 2>&1 ||
            { echo "FAIL wine restart: policy rejected"; fail=1; }
        as_user "$wine" "$work/kfprobe.exe" hold >/dev/null 2>&1 &
        held=$!
        sleep 4
        kill -9 "$daemon"
        wait "$daemon" 2>/dev/null
        start_daemon
        sleep 6   # it maps code 12 s in, after the restart, and runs 10 s more
        mods=$(bpftool -j map dump pinned /sys/fs/bpf/kfilter/maps/kb_mods 2>/dev/null | python3 -c '
import json, sys
rows = [r.get("formatted", r)["value"] for r in json.load(sys.stdin)]
print(len(rows), sum(1 for v in rows if v["dirty"]))' 2>/dev/null)
        [ "$mods" = "1 0" ] ||
            { echo "FAIL wine restart: the client's module table is not current (tables, stale: $mods)"; fail=1; }
        wait "$held"
        as_user /opt/wine-stable/bin/wineserver -k >/dev/null 2>&1
    else
        echo "FAIL wine: the probe did not build"; fail=1
    fi
else
    echo "SKIP wine: needs Wine at $wine, sudo from a user account, clang and ld -m i386pep"
fi
stop_daemon

# Fallback: fanotify (and nftables, when nf_tables is loaded) without the BPF layer.
start_daemon --no-bpf
"$bin/kfilterctl" status | grep -q 'registered:.*bpf' && { echo "FAIL --no-bpf: bpf layer listed"; fail=1; }
network=off
"$bin/kfilterctl" status | grep -q 'registered:.*network' && network=on
# Process memory and adapters have no fallback layer: block mode with them is refused there.
# So are message rules: a block-mode policy that has them must be rejected, not half-enforced.
write_policy block "$network" off
"$bin/kfilterctl" policy "$work/policy.txt" --no-track >/dev/null 2>&1 &&
    { echo "FAIL --no-bpf: block mode accepted message rules it cannot enforce"; fail=1; }
report=$(KF_NO_MESSAGES=1 run_probe block "$network" off)
echo "$report" | grep -qx "open_read=denied" || { echo "FAIL --no-bpf: the open was not refused"; fail=1; }
echo "$report" | grep -qx "unlink=ok" || { echo "FAIL --no-bpf: fanotify cannot refuse unlink, yet it failed"; fail=1; }
stop_daemon

kill "$outside" 2>/dev/null
# Never leave a pinned layer behind.
[ -e /sys/fs/bpf/kfilter ] && { echo "FAIL: pins left in /sys/fs/bpf/kfilter"; rm -rf /sys/fs/bpf/kfilter; fail=1; }
[ "$fail" = 0 ] && echo "linux lsm test: PASS" || { tail -20 "$log"; echo "linux lsm test: FAIL"; }
rm -rf "$work"
exit "$fail"
