#!/usr/bin/env python3
"""Offline checks of monfilter.py's run preparation: the default policies filled for a user
and prefix pass `kfilterctl check`, the run's mode wins over the file's, --entry becomes the
launch root, unfilled placeholders stay inert, and unenforceable rules are found."""
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import types

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import monfilter  # noqa: E402


def check(condition, message):
    if not condition:
        sys.exit(f'[fail] {message}')


def preflight():
    """`run` refuses a prefix whose wineserver runs: found by its cwd (the server dir), its
    WINEPREFIX, or a listening server socket; a stale socket file or another prefix is not."""
    with tempfile.TemporaryDirectory() as scratch:
        scratch = pathlib.Path(scratch)
        prefix, other, proc, tmp = scratch / 'prefix', scratch / 'other', scratch / 'proc', scratch / 'tmp'
        for folder in (prefix, other, proc / 'net'):
            folder.mkdir(parents=True)
        info = prefix.stat()
        server = tmp / f'.wine-{info.st_uid}' / f'server-{info.st_dev:x}-{info.st_ino:x}'
        server.mkdir(parents=True)
        (server / 'socket').touch()   # stale: not listening
        (proc / 'net' / 'unix').write_text('Num RefCount Protocol Flags Type St Inode Path\n')

        def process(pid, comm, cwd, prefix_env=None):
            entry = proc / str(pid)
            entry.mkdir()
            (entry / 'comm').write_text(comm + '\n')
            (entry / 'cwd').symlink_to(cwd)
            (entry / 'environ').write_bytes(b'HOME=/x\0' + (f'WINEPREFIX={prefix_env}\0'.encode() if prefix_env else b''))

        process(10, 'bash', server)
        process(11, 'wineserver', scratch, other)
        check(monfilter.prefix_wineserver(prefix, proc, tmp) == '', 'no wineserver of the prefix runs')
        check(monfilter.prefix_wineserver(scratch / 'missing', proc, tmp) == '', 'a missing prefix')
        (proc / 'net' / 'unix').write_text(f'0000: 00000002 00000000 00010000 0001 01 1 {server}/socket\n')
        check('listening' in monfilter.prefix_wineserver(prefix, proc, tmp), 'a listening server socket')
        (proc / 'net' / 'unix').write_text('')
        process(12, 'wineserver', scratch, str(prefix) + '/')
        check('pid 12 has WINEPREFIX' in monfilter.prefix_wineserver(prefix, proc, tmp), 'by WINEPREFIX')
        shutil.rmtree(proc / '12')
        process(9, 'wineserver64', server)
        found = monfilter.prefix_wineserver(prefix, proc, tmp)
        check(found.startswith('wineserver pid ') and str(server) in found, f'by the server dir: {found}')

        # run (not --attach) stops before anything starts, naming the way out.
        args = types.SimpleNamespace(keep_enforcing=False, block=False, prefix=str(prefix), client=None, entry=None,
                                     attach=False, user_env=None)
        real, state, sudo = monfilter.prefix_wineserver, monfilter.STATE, os.environ.get('SUDO_UID')
        try:
            monfilter.prefix_wineserver = lambda path: real(path, proc, tmp)
            monfilter.STATE = scratch / 'state.json'
            os.environ['SUDO_UID'] = str(os.getuid() or 1)
            try:
                monfilter.run(args)
                check(False, 'run started with the prefix running')
            except SystemExit as stop:
                check('close the Nexon Launcher' in str(stop) and '--attach' in str(stop), f'message: {stop}')
            check(not (scratch / 'state.json').exists(), 'nothing started before the refusal')
        finally:
            monfilter.prefix_wineserver, monfilter.STATE = real, state
            os.environ.pop('SUDO_UID') if sudo is None else os.environ.update(SUDO_UID=sudo)


def client_files():
    """ClientFiles.collect copies only the client's regular files, within one budget for them all,
    and always removes its directory."""
    with tempfile.TemporaryDirectory() as scratch:
        client = monfilter.ClientFiles(os.getuid(), os.getgid())
        client.write('tls-keys.log', b'CLIENT_RANDOM x y\n')
        client.write('Xauthority', b'cookie')
        os.mkdir(f'{client.path}/d')
        os.mkfifo(f'{client.path}/fifo')
        for name, size in (('huge.log', monfilter.CLIENT_FILE_MAX + 1), ('half1.log', monfilter.CLIENT_FILE_MAX // 2 + 1),
                           ('half2.log', monfilter.CLIENT_FILE_MAX // 2 + 1)):
            with open(f'{client.path}/{name}', 'wb') as sparse:
                sparse.truncate(size)
        destination = pathlib.Path(scratch) / 'client'
        client.collect(destination)
        collected = sorted(os.listdir(destination))
        check(collected in (['half1.log', 'tls-keys.log'], ['half2.log', 'tls-keys.log']), f'collected: {collected}')
        check(not os.path.exists(client.path), 'the client directory is removed')


def main():
    policy = ROOT / 'filter' / 'policy' / 'linux-default-policy.txt'
    raw = policy.read_text(encoding='utf-8')
    check('/@WINEPREFIX@/drive_c/Nexon/Library/maplestorycw' in raw and 'root /@HOME@/' in raw, 'placeholders')
    for name in monfilter.FAMILY:
        check(f'protect {name}\n' in raw, f'linux policy does not protect {name}')
        for windows in ('default-policy.txt', 'contain-policy.txt'):
            text = (ROOT / 'filter' / 'policy' / windows).read_text(encoding='utf-8')
            check(f'protect \\{name}\n' in text, f'{windows} does not protect {name}')

    home, prefix = '/home/tester', '/home/tester/games/nexon prefix'
    filled = monfilter.prepare_policy(policy, 'block', home, prefix, f'{home}/.local/bin/nexon-launcher', False)
    # /@NAME@ is a placeholder; /proc/@self and its kin are kfilter's own names.
    check(not re.search(r'/@[A-Z]+@', ''.join(line for line in filled.splitlines() if not line.startswith('#'))),
          'unfilled placeholder')
    check('\nmode block\n' in f'\n{filled}' and 'mode audit' not in filled, 'the run mode replaces the file mode')
    check(f'root|{home}/.local/bin/nexon-launcher\n' in filled, 'launch root')
    check(f'allow|file|{prefix}/drive_c/Nexon/Library/maplestorycw|' in filled, 'client root allow')
    custom = monfilter.prepare_policy(policy, 'audit', home, prefix, '/opt/My Games/maple.sh', True)
    check('root|/opt/My Games/maple.sh\n' in custom and custom.count('\nroot') == 1, '--entry becomes the launch root')
    # A home with a space: the launch root keeps the whole path (not '/home/john').
    spaced = monfilter.prepare_policy(policy, 'block', '/home/john doe', prefix, '', False)
    check('root|/home/john doe/.local/bin/nexon-launcher\n' in spaced, 'spaced home root')
    check(monfilter.prepare_policy(ROOT / 'tests' / 'monfilter_test.py', 'audit', home, prefix, '', False)
          .startswith('mode audit\n'), 'a policy without a mode line gets one')

    windows = monfilter.WINDOWS
    try:
        monfilter.WINDOWS = True
        found = monfilter.unenforceable('mode audit\ndeny|message|ip=1.2.3.4|port=1|proto=tcp\n'
                                        'deny|network|ip=1.2.3.4|module=x.dll\nallow|file|\\x\n')
        check(len(found) == 2, f'Windows: message and module= rules: {found}')
        monfilter.WINDOWS = False
        check(monfilter.unenforceable('appcontainer MapleStoryCW\ndeny|message|ip=1.2.3.4|port=1\n') ==
              ['line 1: appcontainer has no Linux equivalent (the launch cgroup is used)'], 'Linux: appcontainer')
        check(monfilter.unenforceable(raw) == [], 'the default Linux policy is fully enforceable')
    finally:
        monfilter.WINDOWS = windows
    preflight()
    client_files()

    kfilterctl = ROOT / 'filter' / 'build' / 'linux' / 'kfilterctl'
    if not kfilterctl.exists():
        print('note: kfilterctl not built; filled policies not checked')
    else:
        with tempfile.TemporaryDirectory() as scratch:
            for name, text in (('filled', filled), ('custom', custom), ('raw', raw), ('spaced', spaced)):
                path = pathlib.Path(scratch) / f'{name}.txt'
                path.write_text(text, encoding='utf-8')
                result = subprocess.run([str(kfilterctl), 'check', str(path)], capture_output=True, text=True)
                check(result.returncode == 0, f'{name} policy: {result.stderr}')
                roots = {'custom': '/opt/My Games/maple.sh', 'spaced': '/home/john doe/.local/bin/nexon-launcher'}
                if name in roots:   # parsed whole, not cut at the space
                    check(f'root: {roots[name]}\n' in result.stdout, f'{name} root: {result.stdout}')
            # Filled, the family's own tree is allowed and other programs' data stays refused; a run in
            # ~/.wine keeps its own prefix while other prefixes stay refused.
            path = pathlib.Path(scratch) / 'filled.txt'
            own = pathlib.Path(scratch) / 'own.txt'
            own.write_text(monfilter.prepare_policy(policy, 'block', home, f'{home}/.wine', '', False), encoding='utf-8')
            for policy_file, target, probe, expect in (
                    (path, 'file', f'{prefix}/drive_c/Nexon/Library/maplestorycw/appdata/MapleStory.exe', 'allow'),
                    (path, 'file', f'{prefix}/drive_c/windows/system32/kernel32.dll', 'allow'),
                    (path, 'file', '/etc/machine-id', 'deny'),
                    (path, 'file', f'{home}/.mozilla/firefox/cookies.sqlite', 'deny'),
                    (path, 'process', f'{home}/.local/bin/nexon-launcher', 'allow'),
                    (own, 'file', f'{home}/.wine/drive_c/Nexon/Library/maplestorycw/MapleStory.exe', 'allow'),
                    (own, 'file', f'{home}/.wine/dosdevices/c:', 'allow'),
                    (own, 'file', '/home/other/.wine/drive_c/users/other/secret.txt', 'deny'),
                    # the host's sockets and addresses, allowed as the program's own /proc but net/dev
                    (path, 'file', '/proc/@self/net/tcp', 'deny'),
                    (path, 'file', '/proc/@family/net/unix', 'deny'),
                    (path, 'file', '/proc/@self/task/7/net/snmp6', 'deny'),
                    (path, 'file', '/proc/@self/net/dev', 'allow'),
                    (path, 'file', '/proc/@self/maps', 'allow')):
                result = subprocess.run([str(kfilterctl), 'evaluate', str(policy_file), target, probe, 'read' if
                                         target == 'file' else 'create'], capture_output=True, text=True)
                check(result.stdout.split()[:1] == [expect], f'{probe}: {result.stdout.strip()} (want {expect})')
            # Hidden by their own rules, not refused by default-deny (rule=0): the kernel's BTF and modules,
            # and another program's /proc/<pid>/net, which reads as not found like its other entries.
            listed = subprocess.run([str(kfilterctl), 'check', str(path)], capture_output=True, text=True).stdout
            rules = {int(line.split()[0]): line for line in listed.splitlines() if line.split()[:1] and line.split()[0].isdigit()}
            for probe, rule in (('/sys/kernel/btf/vmlinux', '/sys/kernel/btf'),
                                ('/sys/module/i915/parameters/enable_guc', '/sys/module'),
                                ('/proc/@outside/net/tcp', '/proc/@outside'), ('/proc/@outside/net/arp', '/proc/@outside')):
                decided = subprocess.run([str(kfilterctl), 'evaluate', str(path), 'file', probe, 'read'],
                                         capture_output=True, text=True).stdout.split()
                line = rules.get(int(decided[1][5:]), '') if decided[1:2] and decided[1].startswith('rule=') else ''
                check(decided[:1] == ['deny'] and line.endswith(' ' + rule) and ' hide ' in line, f'{probe}: {decided} {line}')
            # winedevice's Bluetooth and USB driver loads: audited ahead of the Wine allows that cover them
            # (evaluate has no image=, so by the order `check` prints).
            order = lambda rule: next(i for i, line in enumerate(listed.splitlines()) if line.endswith(' ' + rule))
            check(order('/*/winebth.sys') < order('/opt/wine-stable') and
                  order('/*/wineusb.sys') < order(f'{prefix}/drive_c/windows'), 'driver rules first')
            check(all(line.split()[1] == 'audit' and ' rights=execute image=winedevice.exe ' in line
                      for line in listed.splitlines() if line.endswith(('/*/winebth.sys', '/*/wineusb.sys'))), 'driver audits')
            # --nested-x's and the live loop's display rules ahead of the policy: only that display.
            displays = pathlib.Path(scratch) / 'displays.txt'
            displays.write_text('\n'.join(monfilter.other_display_rules(5)) + '\n' + filled, encoding='utf-8')
            for target, probe, rights, expect in (
                    ('pipe', '/tmp/.X11-unix/X5', 'connect', 'allow'), ('pipe', '/@/tmp/.X11-unix/X5', 'connect', 'allow'),
                    ('pipe', '/@/tmp/.X11-unix/X0', 'connect', 'deny'), ('pipe', '/tmp/.X11-unix/X50', 'connect', 'deny'),
                    ('pipe', '/run/user/1000/wayland-0', 'connect', 'deny'),
                    ('file', '/run/user/1000/.mutter-Xwaylandauth.P3GRY3', 'read', 'deny')):
                result = subprocess.run([str(kfilterctl), 'evaluate', str(displays), target, probe, rights],
                                        capture_output=True, text=True)
                decided = result.stdout.split()   # ['deny', 'rule=N']: by one of the display rules
                check(decided[:1] == [expect] and 1 <= int(decided[1][5:]) <= 6, f'{probe}: {result.stdout.strip()}')
    # Only the zip is kept once it reads back whole; a broken one keeps the unpacked session.
    import zipfile
    with tempfile.TemporaryDirectory() as scratch:
        for good in (True, False):
            session = pathlib.Path(scratch) / f'session-{good}'
            session.mkdir()
            (session / 'events.jsonl').write_text('{}\n')
            archive = pathlib.Path(f'{session}.zip')
            if good:
                with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as bundle:
                    bundle.write(session / 'events.jsonl', 'events.jsonl')
            else:
                archive.write_bytes(b'not a zip')
            kept = monfilter.archive_only(session)
            check(kept == (archive if good else session) and session.exists() != good, f'archive_only({good}): {kept}')
    print('monfilter_test passed')


if __name__ == '__main__':
    main()
