#!/usr/bin/env python3
"""Writes filter/linux/bpf/kfilter_syscalls.h: the /system/syscall/<name>[/<key>] decisions (kfilter.bpf.c) for
every syscall of both x86 tables, from this kernel's tables and BTF.

  gen_syscalls.py [--headers DIR] [--btf FILE] [--error-injection FILE] [--out FILE]

DIR is the kernel's build headers (/usr/src/linux-headers-$(uname -r)): arch/x86/include/generated/asm/syscalls_{64,32}.h
say which function each number enters (the ia32 table's compat one where it has two), generated/uapi/asm/unistd_{64,32}.h
name the numbers. FILE is `bpftool btf dump file /sys/kernel/btf/vmlinux format raw` (read here when not given): an entry
point is fmod_ret's target only when BTF has it (a zero-argument call has only __do_sys_<name>, which serves both tables,
or __do_compat_sys_<name> for the ia32 table's compat one) and, given the error injection list (root:
/sys/kernel/debug/error_injection/list), when it may change a return.
An ia32 call carries its x86_64 name where one exists (fcntl64, futex_time64, mmap2, getuid32: fcntl, futex, mmap,
getuid), as msmon records it; its keys are the x86_64 call's (fcntl64's LFS lock commands as F_GETLK..F_SETLKW, the old
select's nfds from its argument block), and socketcall and ipc decide as the call they carry (kfilter.bpf.c), so their
entry points serve those names too. Calls that never return (exit, exit_group) and unimplemented numbers are left out.
"""
import argparse
import os
import re
import subprocess
import sys

# A call's key: (kind, argument index on x86_64, its index on ia32 where it differs, mask). LOCK64: ia32 fcntl's command,
# its LFS lock commands as x86_64's; AT beside a kind: the argument points to the key (a 32-bit word).
DEC, HEX, WAIT, WAITID, LOCK64, AT = 1, 2, 3, 4, 5, 0x80
KEYS = {
    'rt_sigaction': (DEC, 0), 'sigaction': (DEC, 0), 'signal': (DEC, 0),
    'rt_sigprocmask': (DEC, 0), 'sigprocmask': (DEC, 0),
    'fcntl': (DEC, 1), 'ioctl': (HEX, 1),
    'madvise': (DEC, 2), 'process_madvise': (DEC, 3), 'fadvise64': (DEC, 3),
    'getrandom': (HEX, 2), 'dup3': (HEX, 2), 'pipe2': (HEX, 1), 'eventfd2': (HEX, 1), 'timerfd_create': (HEX, 1),
    'signalfd4': (HEX, 3), 'epoll_create1': (HEX, 0), 'inotify_init1': (HEX, 0), 'memfd_secret': (HEX, 0),
    'pidfd_open': (HEX, 1), 'close_range': (HEX, 2), 'clone': (HEX, 0), 'unshare': (HEX, 0), 'setns': (HEX, 1),
    'landlock_create_ruleset': (HEX, 2), 'landlock_restrict_self': (HEX, 1), 'landlock_add_rule': (DEC, 1),
    'personality': (HEX, 0), 'arch_prctl': (HEX, 0), 'reboot': (HEX, 2),
    'futex': (DEC, 1, None, 0x7F), 'seccomp': (DEC, 0), 'keyctl': (DEC, 0), 'prctl': (DEC, 0), 'ptrace': (DEC, 0),
    'clock_gettime': (DEC, 0), 'clock_settime': (DEC, 0), 'clock_getres': (DEC, 0), 'clock_nanosleep': (DEC, 0),
    'clock_adjtime': (DEC, 0), 'timer_create': (DEC, 0),
    'getrusage': (DEC, 0), 'getpriority': (DEC, 0), 'setpriority': (DEC, 0), 'setitimer': (DEC, 0),
    'getitimer': (DEC, 0), 'set_mempolicy': (DEC, 0), 'mbind': (DEC, 2), 'iopl': (DEC, 0), 'syslog': (DEC, 0),
    'socket': (DEC, 0), 'socketpair': (DEC, 0), 'bpf': (DEC, 0),
    'kill': (DEC, 1), 'tkill': (DEC, 1), 'tgkill': (DEC, 2), 'rt_sigqueueinfo': (DEC, 1),
    'rt_tgsigqueueinfo': (DEC, 2), 'pidfd_send_signal': (DEC, 1),
    'wait4': (WAIT, 0), 'waitpid': (WAIT, 0), 'waitid': (WAITID, 0),
    'poll': (DEC, 1), 'ppoll': (DEC, 1), 'select': (DEC, 0), 'pselect6': (DEC, 0),
}
# ia32 calls whose key argument sits elsewhere (by their ia32 name).
IA32_ARG = {'fadvise64': 4, 'fadvise64_64': 5}
# ia32's multiplexed calls: the x86_64 calls socketcall's SYS_* and ipc's call numbers name (kfilter.bpf.c decodes them).
SUBCALLS = {'socketcall': ('socket', 'bind', 'connect', 'listen', 'accept', 'getsockname', 'getpeername', 'socketpair',
                           'sendto', 'recvfrom', 'shutdown', 'setsockopt', 'getsockopt', 'sendmsg', 'recvmsg', 'accept4',
                           'recvmmsg', 'sendmmsg'),
            'ipc': ('semop', 'semget', 'semctl', 'semtimedop', 'msgsnd', 'msgrcv', 'msgget', 'msgctl', 'shmat', 'shmdt',
                    'shmget', 'shmctl')}
# Calls on the caller's own memory: [argument, argument + length) for addr= rules.
ADDRESS = {name: (0, 1) for name in ('munmap', 'mremap', 'msync', 'mlock', 'mlock2', 'munlock', 'mbind', 'pkey_mprotect',
                                      'madvise', 'mprotect', 'remap_file_pages', 'mseal')}
# Called all the time by every process (Wine waits and signal masks): decided only by rules naming their argument.
HOT = {'futex', 'poll', 'ppoll', 'select', 'pselect6', 'rt_sigprocmask', 'sigprocmask'}
QUERY_PREFIX = ('get', 'sched_get', 'clock_get', 'timer_get', 'timerfd_get', 'lsm_get', 'lsm_list', 'list',
                'io_getevents', 'io_pgetevents')
QUERY = {'times', 'time', 'uname', 'sysinfo', 'ustat', 'sysfs', 'mincore', 'cachestat', 'capget', 'statfs', 'fstatfs',
         'statx', 'newfstatat', 'fstat', 'stat', 'lstat', 'access', 'faccessat', 'faccessat2', 'readlink', 'readlinkat',
         'rt_sigpending', 'sigpending', 'fgetxattr', 'lgetxattr', 'flistxattr', 'llistxattr', 'sgetmask',
         'statmount', 'sched_rr_get_interval', 'lookup_dcookie', 'getdents', 'getdents64', 'file_getattr'}
# ia32 names of an x86_64 call that are not its name with a suffix dropped.
IA32_ALIAS = {'mmap2': 'mmap', '_llseek': 'lseek', 'ugetrlimit': 'getrlimit', '_newselect': 'select',
              'fstatat64': 'newfstatat', 'fadvise64_64': 'fadvise64', 'readdir': 'getdents', 'oldstat': 'stat',
              'oldlstat': 'lstat', 'oldfstat': 'fstat', 'olduname': 'uname', 'oldolduname': 'uname'}


def numbers(path):
    names = {}
    for line in open(path):
        found = re.match(r'#define __NR_(\w+) (\d+)$', line.strip())
        if found:
            names[int(found.group(2))] = found.group(1)
    return names


def entries(path):
    table = {}
    for line in open(path):
        found = re.match(r'__SYSCALL(_WITH_COMPAT|_NORETURN)?\((\d+), (\w+)(?:, (\w+))?\)', line.strip())
        if not found:
            continue
        kind, nr, native, compat = found.groups()
        if native == 'sys_ni_syscall' or kind == '_NORETURN':
            continue
        table[int(nr)] = compat if kind == '_WITH_COMPAT' else native
    return table


def btf_functions(text):
    """FUNC name -> the name of its FUNC_PROTO's first parameter ('regs' or '__unused' for entry points)."""
    protos, functions, current = {}, {}, None
    for line in text.splitlines():
        head = re.match(r"\[(\d+)\] (\w+) '([^']*)'(?: type_id=(\d+))?", line)
        if head:
            current = None
            number, kind, name, type_id = head.groups()
            if kind == 'FUNC_PROTO':
                current = int(number)
                protos[current] = None
            elif kind == 'FUNC':
                functions[name] = int(type_id)
            continue
        param = re.match(r"\s+'([^']*)' type_id=", line)
        if param and current is not None and protos[current] is None:
            protos[current] = param.group(1)
    return {name: protos.get(proto) for name, proto in functions.items()}


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--headers', default='/usr/src/linux-headers-' + os.uname().release)
    parser.add_argument('--btf')
    parser.add_argument('--error-injection')
    parser.add_argument('--out', default=os.path.join(os.path.dirname(__file__), '../linux/bpf/kfilter_syscalls.h'))
    args = parser.parse_args()
    generated = os.path.join(args.headers, 'arch/x86/include/generated')
    btf = open(args.btf).read() if args.btf else subprocess.run(
        ['bpftool', 'btf', 'dump', 'file', '/sys/kernel/btf/vmlinux', 'format', 'raw'],
        check=True, capture_output=True, text=True).stdout
    functions = btf_functions(btf)
    injectable = None
    if args.error_injection:
        injectable = {line.split()[0] for line in open(args.error_injection) if line.strip()}
    names64 = numbers(os.path.join(generated, 'uapi/asm/unistd_64.h'))
    names32 = numbers(os.path.join(generated, 'uapi/asm/unistd_32.h'))
    known = set(names64.values())

    def fold(name):
        if name in known:
            return name
        if name in IA32_ALIAS:
            return IA32_ALIAS[name]
        for suffix in ('_time64', '64', '32', '_time32'):
            if name.endswith(suffix) and name[:-len(suffix)] in known:
                return name[:-len(suffix)]
        return name

    def target(abi, implementation):
        """The entry point a table's number enters, and its group (0: regs, 1: __unused), or None."""
        base = implementation[4:] if implementation.startswith('sys_') else implementation
        candidates = ['__' + abi + '_' + implementation, '__do_sys_' + base]
        if implementation.startswith('compat_sys_'):
            candidates.append('__do_compat_sys_' + implementation[len('compat_sys_'):])
        for function in candidates:
            proto = functions.get(function)
            if proto not in ('regs', '__unused'):
                continue
            if injectable is not None and function not in injectable:
                continue
            return function, 0 if proto == 'regs' else 1
        return None

    rows, stubs, missing = [], {}, []
    entries64 = entries(os.path.join(generated, 'asm/syscalls_64.h'))
    for abi, table, names in (('x64', entries64, names64),
                              ('ia32', entries(os.path.join(generated, 'asm/syscalls_32.h')), names32)):
        for nr in sorted(table):
            raw = names.get(nr)
            if raw is None:
                continue
            name = fold(raw) if abi == 'ia32' else raw
            found = target(abi, table[nr])
            if found is None:
                missing.append(f'{abi} {nr} {raw} ({table[nr]})')
                continue
            function, group = found
            key = KEYS.get(name, (0, 0))
            kind, arg, mask = key[0], key[1], key[3] if len(key) > 3 else 0xFFFFFFFF
            if abi == 'ia32' and raw in IA32_ARG:
                arg = IA32_ARG[raw]
            if abi == 'ia32' and name == 'fcntl':
                kind = LOCK64
            if abi == 'ia32' and table[nr].endswith('old_select'):
                kind |= AT
            address, length = ADDRESS.get(name, (7, 7))
            query = name.startswith(QUERY_PREFIX) or name in QUERY
            rows.append((abi, nr, name, kind, arg, mask, address, length, int(query), int(name in HOT)))
            stub = stubs.setdefault(function, [group, []])
            for served in (name,) + (SUBCALLS.get(name, ()) if abi == 'ia32' else ()):
                if served not in stub[1]:
                    stub[1].append(served)
    longest = max(len(row[2]) for row in rows)
    out = []
    out.append('/* Generated by filter/tools/gen_syscalls.py from Linux %s\'s x86 syscall tables and BTF: do not edit.\n'
               ' * KB_SYSCALL(abi, nr, name, key, argument, mask, address argument, length argument, query, hot): the\n'
               ' * decision /system/syscall/<name>[/<key>] of a call; KB_STUB(program, entry point, group, names): an fmod_ret\n'
               ' * program on an entry point (group 0 takes `regs`, 1 `__unused`) and the names of the calls it serves.\n'
               ' * Left out (never return, unimplemented, or no entry point fmod_ret can take here): %d. */'
               % (os.path.basename(args.headers.rstrip('/')).replace('linux-headers-', ''), len(missing)))
    out.append('#define KB_SYSCALL_NAME %d' % (longest + 1 if longest + 1 > 24 else 24))
    # Each group's decision program is loaded for (never attached to) the entry point of its lowest x86_64 number.
    for group in (0, 1):
        first = min((row[1], function) for function, (g, served) in stubs.items() if g == group
                    for row in rows if row[0] == 'x64' and row[2] in served and target('x64', entries64[row[1]]) ==
                    (function, group))
        out.append('#define KB_SYSCALL_DECIDER%d "%s"' % (group, first[1]))
    out.append('#ifdef KB_SYSCALL')
    for abi, nr, name, kind, arg, mask, address, length, query, hot in rows:
        out.append('KB_SYSCALL(%s, %d, "%s", %d, %d, 0x%X, %d, %d, %d, %d)'
                   % ('KB_X64' if abi == 'x64' else 'KB_IA32', nr, name, kind, arg, mask, address, length, query, hot))
    out.append('#endif')
    out.append('#ifdef KB_STUB')
    for function in sorted(stubs):
        group, served = stubs[function]
        out.append('KB_STUB(kb_s_%s, %s, %d, "%s")' % (function.strip('_'), function, group, ' '.join(served)))
    out.append('#endif')
    with open(args.out, 'w') as file:
        file.write('\n'.join(out) + '\n')
    print('%d calls, %d entry points, %d left out' % (len(rows), len(stubs), len(missing)), file=sys.stderr)
    for line in missing:
        print('  left out: ' + line, file=sys.stderr)


if __name__ == '__main__':
    main()
