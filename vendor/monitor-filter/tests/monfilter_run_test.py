#!/usr/bin/env python3
"""`monfilter.py run` end to end without root: kfilterd, kfilterctl and msmon-agent are
replaced by fakes that log every call, the client by a short `sleep` carrying the prefix.
Checks the start order, the stop order, the report, and the cleanup when msmon fails; signals
at each stage; the family found by lineage only; the run directory root writes cannot be
redirected from; the user's PATH; pins a dead kfilterd left."""
import os
import pathlib
import re
import signal
import sys
import subprocess
import tempfile
import threading
import time
import types

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import monfilter  # noqa: E402

KFILTERCTL = r'''#!/usr/bin/env python3
import os, sys, pathlib
here = pathlib.Path(__file__).parent
with open(here / 'calls', 'a') as log: log.write('kfilterctl ' + ' '.join(sys.argv[1:2]) + '\n')
command = sys.argv[1]
if command == 'help':
    print('Usage:\n  kfilterctl status\n  kfilterctl stop    (Linux)\n  kfilterctl session <tag>\n')
elif command == 'status':
    sys.exit(0 if (here / 'up').exists() else 1)
elif command in ('stop', 'off', 'policy', 'session') and not (here / 'up').exists():
    sys.exit('Cannot open the kfilterd socket: kfilterd must be running')
elif command == 'stop':
    (here / 'up').unlink()
    (here / 'pinned').unlink(missing_ok=True)
elif command == 'launch':
    # The run's launch options (after the program) and what the client gets: recorded, then dropped.
    names = ('DISPLAY', 'XAUTHORITY', 'WAYLAND_DISPLAY', 'DBUS_SESSION_BUS_ADDRESS', 'DBUS_SYSTEM_BUS_ADDRESS',
             'SSLKEYLOGFILE')
    (here / 'launch').write_text(' '.join(sys.argv[2:]) + '\n' + ' '.join(f'{n}={os.environ.get(n)}' for n in names))
    words, argv = iter(sys.argv[2:]), []
    for word in words:
        if word in ('--hostname', '--time-offset', '--user', '--cpuid-mask', '--trap-log'):
            value = next(words)
            if word == '--trap-log':   # what the shim would write
                pathlib.Path(value).write_text('kfshim pid=1 exe=x bits=64 insn=cpuid leaf=0x0 subleaf=0x0 count=1\n')
        elif not word.startswith('--'):
            argv.append(word)
    os.execvp(argv[0], argv)
'''
KFILTERD = r'''#!/usr/bin/env python3
import os, pathlib, time
here = pathlib.Path(__file__).parent
with open(here / 'calls', 'a') as log: log.write('kfilterd start\n')
time.sleep(float(os.environ.get('FAKE_KFILTERD_SLOW', '0')))   # loading the BPF layer
(here / 'up').touch()
while (here / 'up').exists(): time.sleep(0.1)
with open(here / 'calls', 'a') as log: log.write('kfilterd exit\n')
'''
AGENT = r'''#!/usr/bin/env python3
import json, os, pathlib, sys, time
here = pathlib.Path(__file__).parent
args = dict(zip(sys.argv[1::2], sys.argv[2::2]))
with open(here / 'calls', 'a') as log: log.write('agent start\n')
(here / 'agent-args').write_text(args['--log-dir'] + '\n' + args['--stop-file'] + '\n' + args['--client'])
if os.environ.get('FAKE_AGENT_DIE'): sys.exit(3)
session = pathlib.Path(args['--log-dir']) / args['--test-id']
session.mkdir(parents=True)
decision = dict(type='kfilter_decision', process_id=7, text='/etc/machine-id',
                detail='action=would_deny;layer=file;target=file;rule_id=0;rights=0x1;image=MapleStory.exe;'
                       'decision=would_deny;rule=')
(session / 'events.jsonl').write_text(json.dumps(decision) + '\n')
print('Registered 0 client/helper/descendant processes.', flush=True)
print('Writing ' + str(session / 'events.jsonl'), flush=True)
while not pathlib.Path(args['--stop-file']).exists(): time.sleep(0.1)
with open(here / 'calls', 'a') as log: log.write('agent stopped\n')
'''


XSERVER = r'''#!/usr/bin/env python3
import os, sys, time
fd = int(sys.argv[sys.argv.index('-displayfd') + 1])
os.write(fd, b'77\n')
time.sleep(60)
'''
DBUS_PROXY = r'''#!/usr/bin/env python3
import pathlib, socket, sys, time
with open(pathlib.Path(__file__).parent / 'dbus-args', 'a') as log: log.write(' '.join(sys.argv[3:]) + '\n')
socket.socket(socket.AF_UNIX).bind(sys.argv[2])
time.sleep(60)
'''


def check(condition, message):
    if not condition:
        sys.exit(f'[fail] {message}')


def run(scratch, die=False, entry=('sleep', '3'), block=False, keep=False, stop_after=None, user_env=(),
        signal_after=None, slow_kfilterd=0, **options):
    fakes = scratch / 'bin'
    fakes.mkdir(exist_ok=True)
    for name, text in (('kfilterctl', KFILTERCTL), ('kfilterd', KFILTERD), ('msmon-agent', AGENT),
                       ('Xwayland', XSERVER), ('xdg-dbus-proxy', DBUS_PROXY)):
        (fakes / name).write_text(text)
        (fakes / name).chmod(0o755)
    (fakes / 'calls').write_text('')
    prefix, client = scratch / 'prefix', scratch / 'client'
    prefix.mkdir(exist_ok=True)
    client.mkdir(exist_ok=True)
    monfilter.BIN = {'kfilterctl': fakes / 'kfilterctl', 'kfilterd': fakes / 'kfilterd', 'agent': fakes / 'msmon-agent'}
    monfilter.STATE_DIR = scratch / 'state'
    monfilter.STATE, monfilter.STOP_REQUEST = monfilter.STATE_DIR / 'state.json', monfilter.STATE_DIR / 'stop'
    monfilter.LEFTOVERS = (fakes / 'pinned',)
    os.environ['SUDO_UID'] = str(os.getuid())
    os.environ['FAKE_KFILTERD_SLOW'] = str(slow_kfilterd)
    os.environ.pop('FAKE_AGENT_DIE', None)
    if die:
        os.environ['FAKE_AGENT_DIE'] = '1'
    args = types.SimpleNamespace(block=block, keep_enforcing=keep, policy=None, no_payloads=False, attach=False,
                                 entry=list(entry), prefix=str(prefix), client=str(client),
                                 log_dir=str(scratch / 'logs'), user_env=['DISPLAY=:9', *user_env],
                                 **dict(dict.fromkeys(('hostname', 'uname26', 'time_offset', 'no_private_proc', 'user',
                                                       'trap_cpuid', 'trap_rdtsc', 'cpuid_mask', 'nested_x',
                                                       'dbus_proxy', 'tls_keylog')), **options))
    if stop_after:   # what `monfilter.py stop` does while the run waits
        threading.Timer(stop_after, lambda: monfilter.STOP_REQUEST.write_text('unpin')).start()
    if signal_after:   # (seconds, signal): a Ctrl-C, kill or closed terminal at that point
        threading.Timer(signal_after[0], lambda: os.kill(os.getpid(), signal_after[1])).start()
    handed = []
    hand_over = monfilter.hand_over
    monfilter.hand_over = lambda fd, uid: (handed.append(uid), hand_over(fd, uid))
    saved = os.dup(1), os.dup(2)   # SIGHUP points them at /dev/null
    code = None
    try:
        monfilter.run(args)
    except SystemExit as error:
        code = error.code
    finally:
        os.dup2(saved[0], 1)
        os.dup2(saved[1], 2)
        monfilter.hand_over = hand_over
        for number in monfilter.STOP_SIGNALS:   # the run leaves them ignored
            signal.signal(number, signal.default_int_handler if number == signal.SIGINT else signal.SIG_DFL)
    check(handed == [os.getuid()], 'the run directory was not handed over')
    return code, (fakes / 'calls').read_text().split('\n')[:-1], scratch / 'logs'


def gone(pattern):
    return subprocess.run(['pgrep', '-f', pattern], capture_output=True).returncode != 0


def hand_over_test():
    """Directories and regular files go to the user, never through a link."""
    with tempfile.TemporaryDirectory(prefix='monfilter-run-test-') as scratch:
        top = pathlib.Path(scratch) / 'run'
        (top / 'session').mkdir(parents=True)
        (top / 'session' / 'events.jsonl').write_text('')
        (top / 'link').symlink_to('/etc/passwd')
        (top / 'session' / 'dirlink').symlink_to('/etc')
        calls, chown = [], os.chown
        os.chown = lambda path, uid, gid, **kw: calls.append((path, kw.get('follow_symlinks', True)))
        fd = os.open(top, os.O_RDONLY | os.O_DIRECTORY)
        try:
            monfilter.hand_over(fd, 4242)
        finally:
            os.chown = chown
            os.close(fd)
        names = sorted(str(path) for path, _ in calls if isinstance(path, str))
        check(names == ['events.jsonl', 'session'], f'handed over: {calls}')
        check(all(not follow for path, follow in calls if isinstance(path, str)), 'chown followed a link')
        check(any(path == fd for path, _ in calls), 'the run directory itself was not handed over')


def main():
    if monfilter.WINDOWS:
        print('monfilter_run_test: Linux only, skipped')
        return
    hand_over_test()
    with tempfile.TemporaryDirectory(prefix='monfilter-run-test-') as scratch:
        scratch = pathlib.Path(scratch)
        (scratch / 'logs').mkdir()
        (scratch / 'logs').chmod(0o1777)   # a shared --log-dir: left as it is
        code, calls, logs = run(scratch)
        check(code is None, f'run failed: {code}')
        # The policy only after msmon records: no decision before its ring has a reader.
        expected = ['kfilterctl check', 'kfilterctl status', 'kfilterd start', 'kfilterctl status',
                    'kfilterctl help', 'kfilterctl session', 'agent start', 'kfilterctl policy', 'kfilterctl launch',
                    'agent stopped', 'kfilterctl off', 'kfilterctl help', 'kfilterctl stop', 'kfilterd exit']
        squeezed = [call for index, call in enumerate(calls) if call != 'kfilterctl status' or
                    index == 0 or calls[index - 1] != 'kfilterctl status']
        check(squeezed[:len(expected)] == expected, f'call order:\n{calls}')
        reports = list(logs.glob('*/*-tuning.json'))
        check(len(reports) == 1 and 'would_block' in reports[0].read_text(), 'tuning report not written')
        run_dir = reports[0].parent
        check((run_dir / run_dir.name / 'kfilter-policy.txt').exists(), 'policy not copied into the bundle')
        check(oct(run_dir.stat().st_mode & 0o777) == '0o700', 'run directory is not private')
        check(oct(logs.stat().st_mode & 0o7777) == '0o1777', 'a shared log directory was changed')
        log_dir, stop_file, _ = (scratch / 'bin' / 'agent-args').read_text().split('\n')
        check(log_dir.startswith('/proc/'), f'msmon writes through a path the user can redirect: {log_dir}')
        check(stop_file == str(monfilter.STATE_DIR / 'agent-stop') and not list(logs.rglob('*.stop')),
              f'the stop file is where the client can write it: {stop_file}')
        check(not monfilter.STATE.exists(), 'state file left behind')

    # msmon fails at start in a --block --keep-enforcing run: nothing ran, so nothing stays on.
    with tempfile.TemporaryDirectory(prefix='monfilter-run-test-') as scratch:
        code, calls, _ = run(pathlib.Path(scratch), die=True, block=True, keep=True)
        check(code and 'msmon-agent exited' in str(code), f'agent failure not reported: {code}')
        check('kfilterctl launch' not in calls, 'client launched although msmon failed')
        check(calls[-3:] == ['kfilterctl help', 'kfilterctl stop', 'kfilterd exit'] and 'kfilterctl off' in calls,
              f'kfilter not stopped after the failure:\n{calls}')
    # `monfilter.py stop` during a --block --keep-enforcing run: the client (a child of the
    # launch) is stopped and kfilter is still turned off and unpinned.
    with tempfile.TemporaryDirectory(prefix='monfilter-run-test-') as scratch:
        marker = f'monfilter-run-test-{os.getpid()}'
        started = time.time()
        code, calls, _ = run(pathlib.Path(scratch), entry=('bash', '-c', f'(exec -a {marker} sleep 60) & wait'),
                             block=True, keep=True, stop_after=3)
        check(code is None and time.time() - started < 30, f'stop request not honoured: {code}')
        check(gone(marker), 'client left running')
        check(calls[-3:] == ['kfilterctl help', 'kfilterctl stop', 'kfilterd exit'], f'not unpinned:\n{calls}')
        check(calls.index('agent stopped') < calls.index('kfilterctl off'), 'kfilter stopped before msmon')
    # The launch fails while another process runs with the same WINEPREFIX: the run ends, and
    # that process is neither the family nor killed.
    with tempfile.TemporaryDirectory(prefix='monfilter-run-test-') as scratch:
        scratch = pathlib.Path(scratch)
        (scratch / 'prefix').mkdir()
        bystander = subprocess.Popen(['sleep', '60'], env=dict(os.environ, WINEPREFIX=str(scratch / 'prefix')))
        try:
            started = time.time()
            code, calls, _ = run(scratch, entry=('false',))
            check(code is None and time.time() - started < 20, f'a failed launch did not end the run: {code}')
            check(bystander.poll() is None, 'a process outside the family was killed')
        finally:
            bystander.kill()
    # SIGHUP (terminal closed) while the client runs: the full stop, bundle and report.
    with tempfile.TemporaryDirectory(prefix='monfilter-run-test-') as scratch:
        marker = f'monfilter-hup-test-{os.getpid()}'
        code, calls, logs = run(pathlib.Path(scratch), entry=('bash', '-c', f'exec -a {marker} sleep 60'),
                                signal_after=(4, signal.SIGHUP))
        check(code is None and gone(marker), f'SIGHUP: client left running ({code})')
        check(calls[-3:] == ['kfilterctl help', 'kfilterctl stop', 'kfilterd exit'] and 'agent stopped' in calls,
              f'SIGHUP: not stopped:\n{calls}')
        check(list(logs.glob('*/*-tuning.json')), 'SIGHUP: no report')
    # SIGTERM while kfilterd is still loading: kfilterd is stopped, nothing else starts.
    with tempfile.TemporaryDirectory(prefix='monfilter-run-test-') as scratch:
        fakes = pathlib.Path(scratch) / 'bin'
        code, calls, _ = run(pathlib.Path(scratch), signal_after=(1.5, signal.SIGTERM), slow_kfilterd=5)
        check(code is None and 'agent start' not in calls, f'SIGTERM during start: {code}\n{calls}')
        check(gone(str(fakes / 'kfilterd')), 'kfilterd left running after an interrupted start')
    # kfilterd dies in a --block run, leaving its pins: the run restarts it and stops it.
    with tempfile.TemporaryDirectory(prefix='monfilter-run-test-') as scratch:
        fakes = pathlib.Path(scratch) / 'bin'
        code, calls, _ = run(pathlib.Path(scratch), block=True,
                             entry=('bash', '-c', f'touch {fakes}/pinned; rm {fakes}/up; sleep 30'))
        check(code is None and not (fakes / 'pinned').exists(), f'pins a dead kfilterd left stayed:\n{calls}')
        check(calls.count('kfilterd start') == 2 and calls[-2:] == ['kfilterctl stop', 'kfilterd exit'],
              f'dead kfilterd not restarted and stopped:\n{calls}')
        # The same leftovers with no run: `monfilter.py stop` removes them.
        (fakes / 'pinned').touch()
        monfilter.stop(None)
        check(not (fakes / 'pinned').exists() and not (fakes / 'up').exists(), '`stop` left the pins')
    # A bare --entry is found on the user's PATH (sudo's is not theirs), and its real path is the root.
    with tempfile.TemporaryDirectory(prefix='monfilter-run-test-') as scratch:
        scratch = pathlib.Path(scratch)
        (scratch / 'real').mkdir()
        (scratch / 'ubin').mkdir()
        (scratch / 'real' / 'launcher').write_text('#!/bin/sh\nexec sleep 1\n')
        (scratch / 'real' / 'launcher').chmod(0o755)
        (scratch / 'ubin' / 'my-launcher').symlink_to(scratch / 'real' / 'launcher')
        code, calls, logs = run(scratch, entry=('my-launcher',),
                                user_env=[f'PATH={scratch / "ubin"}:{os.environ["PATH"]}'])
        check(code is None and 'kfilterctl launch' in calls, f'user PATH entry: {code}')
        policy = next(logs.glob('*/kfilter-policy.txt')).read_text()
        check(f'root|{(scratch / "real" / "launcher").resolve()}\n' in policy, 'entry root is not its real path')
        first = policy.split('\n', 1)[0]
        check(first.startswith('allow|handle|/') and first.endswith('/msmon-agent|rights=vm-operation,vm-read,'
                                                                   'vm-write|risk=msmon'),
              f'msmon may read the protected programs\' memory: {first}')
    # Hiding, traps and the session's own X server and D-Bus proxies: kfilterctl launch gets the options,
    # the client its display, buses and key log (a Windows path through Z:), the policy refuses the
    # desktop's sockets first, and what the client wrote ends up in the bundle; nothing is left running.
    with tempfile.TemporaryDirectory(prefix='monfilter-run-test-') as scratch:
        scratch = pathlib.Path(scratch)
        (scratch / 'prefix' / 'dosdevices').mkdir(parents=True)
        (scratch / 'prefix' / 'dosdevices' / 'z:').symlink_to('/')
        code, calls, logs = run(scratch, hostname='kf', uname26=True, time_offset='random', trap_cpuid=True,
                                cpuid_mask='0x80000002-0x80000004', nested_x='auto', dbus_proxy=True, tls_keylog=True,
                                user_env=[f'PATH={scratch / "bin"}:{os.environ["PATH"]}', 'WAYLAND_DISPLAY=wayland-0',
                                          'XDG_RUNTIME_DIR=/run/user/1', 'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1/bus'])
        argv, env = (scratch / 'bin' / 'launch').read_text().split('\n')
        client = re.search(r'--trap-log (/tmp/monfilter-client-\w+)/cpu-trap.log', argv)
        check(code is None and client and re.search(r'--hostname kf --uname26 --time-offset \d+ --private-proc '
                                                    r'--trap-cpuid --cpuid-mask 0x80000002-0x80000004 ', argv), argv)
        client = client[1]
        check(env == f'DISPLAY=:77 XAUTHORITY={client}/Xauthority WAYLAND_DISPLAY=None DBUS_SESSION_BUS_ADDRESS='
                     f'unix:path={client}/bus DBUS_SYSTEM_BUS_ADDRESS=unix:path={client}/system_bus '
                     f'SSLKEYLOGFILE=Z:/{client[1:]}/tls-keys.log', env)
        policy_file = next(logs.glob('*/kfilter-policy.txt'))
        policy = policy_file.read_text()
        real = monfilter.ROOT / 'filter' / 'build' / 'linux' / 'kfilterctl'
        check(not real.exists() or subprocess.run([str(real), 'check', str(policy_file)], capture_output=True).returncode
              == 0, 'the session rules do not pass kfilterctl check')
        session = policy.split('\n')[1:]
        check(session[:6] == monfilter.other_display_rules('77') and 'deny|pipe|/run/user/1/wayland-0' in session and
              'deny|pipe|/run/user/*/bus' in session, f'session rules:\n{policy}')
        check((scratch / 'bin' / 'dbus-args').read_text() == '--filter --log --talk=org.freedesktop.secrets\n' * 2,
              f"the proxies may talk to: {(scratch / 'bin' / 'dbus-args').read_text()}")
        check('allow|file|/tmp/kfshim.*|rights=read,execute,query' in session and
              not any('/shim|' in rule for rule in session), 'trap shim allows')
        check(list(logs.glob('*/*/client/cpu-trap.log')) and not pathlib.Path(client).exists(), 'client files')
        check((scratch / 'bin' / 'agent-args').read_text().endswith(f'\n{scratch / "client"}'), 'msmon client root')
        check(gone(str(scratch / 'bin' / 'Xwayland')) and gone(str(scratch / 'bin' / 'xdg-dbus-proxy')), 'left running')
    # The client swaps the run directory for a symlink: root's writes do not follow it.
    with tempfile.TemporaryDirectory(prefix='monfilter-run-test-') as scratch:
        scratch = pathlib.Path(scratch)
        logs = scratch / 'logs'
        swap = (f'cd {logs} && d=$(ls -d monfilter-*) && mv "$d" moved && mkdir ../elsewhere && '
                f'ln -s ../elsewhere "$d" && sleep 1')
        code, calls, _ = run(scratch, entry=('bash', '-c', swap))
        moved = list((logs / 'moved').glob('*/kfilter-policy.txt'))
        check(code is None and moved, f'bundle not in the real run directory: {code}')
        check(not any((scratch / 'elsewhere').iterdir()), 'a root write followed the planted symlink')
    print('monfilter_run_test passed')


if __name__ == '__main__':
    main()
