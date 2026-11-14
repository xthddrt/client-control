#!/usr/bin/env python3
"""monfilter: one command for msmon (observe) and kfilter (enforce) around the Nexon family.

  monfilter.py build                  compile both halves (build.sh / build.cmd); no tests
  monfilter.py test                   build the test binaries and run every offline check
  monfilter.py run [options]          kfilter + policy, msmon, the client; stop; bundle; report
  monfilter.py stop                   end a run (also: kfilter off and unpinned, even --keep-enforcing)
  monfilter.py status                 the run's state and `kfilterctl status`
  monfilter.py report <bundle>        the tuning report (blocked / would block / allowed / gaps)

`run` (Linux): starts kfilterd (or adopts a running one), loads the policy (audit unless
--block), starts msmon-agent on every Nexon root with payload and packet capture (unless
--no-payloads) and waits until it records, then starts the entry point under `kfilterctl
launch` (default ~/.local/bin/nexon-launcher with WINEPREFIX=~/.wine-nexon; --attach starts
only the tools). It waits for the whole family to exit, Ctrl-C, or `monfilter.py stop`, then
stops in order: the family (if it still runs), msmon (stop file, final drain), kfilter (off,
unpinned, kfilterd stopped; unless --block --keep-enforcing), session_pack, and the report.
Runs as root: it re-runs itself with sudo; the client itself runs as the invoking user (or --user).
Linux hiding and isolation options (--hostname, --uname26, --time-offset, --user, --trap-cpuid,
--trap-rdtsc, --cpuid-mask, --nested-x, --dbus-proxy, --tls-keylog) are off; a private /proc and
cgroup view is on (--no-private-proc). What the client writes lands in the bundle's client/.
Each run gets its own directory <log-dir>/<run>/ (bundle, report, policy, logs), root-only
while the run lasts and handed to the user at the end; pack and report run as the user.

Windows: the same flow with sc.exe, kfilterctl.exe and msmon-agent.exe (UNVERIFIED: never run).
The session bundle holds socket payloads and packets (secrets); it is labelled so and the
run directory is private to the user.
"""
import argparse
import json
import os
import random
import re
import select
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'filter' / 'tools'))
WINDOWS = os.name == 'nt'
# Every program of the family; kfilter protects them by name, msmon by their roots.
FAMILY = ('MapleStory.exe', 'nexon_launcher.exe', 'nexon_client.exe', 'nexon_agent.exe', 'nexon_runtime.exe',
          'NGService.exe', 'DwarfAxe.exe', 'CrashReportClient.exe', 'grap-core64.aes', 'grap-updater.aes',
          'grap-communicator64.aes')
if WINDOWS:
    BIN = {'kfilterctl': ROOT / 'filter/build/Release/tool/kfilterctl.exe',
           'agent': ROOT / 'monitor/build/Release/agent/msmon-agent.exe'}
    STATE_DIR = Path(os.environ.get('ProgramData', r'C:\ProgramData')) / 'monfilter'
    POLICY = ROOT / 'filter/policy/default-policy.txt'
else:
    BIN = {'kfilterctl': ROOT / 'filter/build/linux/kfilterctl', 'kfilterd': ROOT / 'filter/build/linux/kfilterd',
           'agent': ROOT / 'monitor/build/linux/msmon-agent'}
    STATE_DIR = Path('/run/monfilter')
    POLICY = ROOT / 'filter/policy/linux-default-policy.txt'
STATE = STATE_DIR / 'state.json'
STOP_REQUEST = STATE_DIR / 'stop'
# What a kfilterd that died in block mode leaves enforcing: the saved policy and the pinned maps.
LEFTOVERS = (Path('/run/kfilter/policy'), Path('/sys/fs/bpf/kfilter/maps/kb_config'))
# What the run passes to the client from the user's session (sudo drops it). PATH: the entry
# and the programs it runs are found on the user's PATH, not sudo's secure_path.
USER_ENV = ('PATH', 'DISPLAY', 'WAYLAND_DISPLAY', 'XAUTHORITY', 'XDG_RUNTIME_DIR', 'DBUS_SESSION_BUS_ADDRESS',
            'PULSE_SERVER', 'LANG', 'LC_ALL', 'WINEDEBUG')


def say(message):
    print(f'monfilter: {message}', flush=True)


def fail(message):
    raise SystemExit(f'monfilter: {message}')


def tool(name):
    path = BIN[name]
    if not path.exists():
        found = shutil.which(path.name)
        if not found:
            fail(f'{path} is missing: run `monfilter.py build` first')
        return found
    return str(path)


def kfilterctl(*args, check=True, quiet=False):
    result = subprocess.run([tool('kfilterctl'), *args], capture_output=True, text=True)
    if not quiet:
        sys.stdout.write(result.stdout)
        sys.stderr.write(result.stderr)
    if check and result.returncode != 0:
        fail(f'kfilterctl {" ".join(args)} failed ({result.returncode})')
    return result


def kfilter_command(*names):
    """The first of `names` that this kfilterctl offers (from its usage text), or None."""
    usage = kfilterctl('help', check=False, quiet=True).stdout
    offered = set(re.findall(r'^\s*kfilterctl\s+([a-z-]+)', usage, re.M))
    return next((name for name in names if name in offered), None)


def unenforceable(text):
    """Policy lines no layer of this OS enforces (owner: refuse in block mode, warn in audit)."""
    problems = []
    for number, line in enumerate(text.splitlines(), 1):
        fields = line.strip().split('|')
        if WINDOWS and (fields[1:2] == ['message'] or any(field.startswith('module=') for field in fields)):
            problems.append(f'line {number}: message and module= rules are enforced on Linux only')
        if not WINDOWS and line.split()[:1] == ['appcontainer']:
            problems.append(f'line {number}: appcontainer has no Linux equivalent (the launch cgroup is used)')
    return problems


def prepare_policy(source, mode, home, prefix, entry_exe, custom_entry):
    """The policy as loaded: placeholders filled, the run's mode, the entry as launch root."""
    text = Path(source).read_text(encoding='utf-8-sig')
    text = text.replace('/@WINEPREFIX@', str(prefix)).replace('/@HOME@', str(home))
    # The '|' form: a whitespace-split `root` line cuts a path at its first space.
    text = re.sub(r'(?m)^root[ \t]+(.*?)[ \t]*$', lambda match: f'root|{match[1]}', text)
    if custom_entry and entry_exe:
        text = re.sub(r'(?m)^root\|.*$', lambda _: f'root|{entry_exe}', text)
    text, count = re.subn(r'(?m)^mode\s+\S+', f'mode {mode}', text)
    return text if count else f'mode {mode}\n{text}'


def write_state(state):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(state, indent=1), encoding='utf-8')


def read_state():
    try:
        return json.loads(STATE.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return None


def alive(pid):
    if not pid:
        return False
    if WINDOWS:
        result = subprocess.run(['tasklist', '/FI', f'PID eq {pid}', '/NH'], capture_output=True, text=True)
        return str(pid) in result.stdout
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def prefix_wineserver(prefix, proc=Path('/proc'), tmp=Path('/tmp')):
    """Linux: why the prefix's wineserver is running ('' if it is not). Wineserver chdirs to
    its server dir /tmp/.wine-<uid>/server-<dev>-<ino> of the prefix and listens on `socket`
    there; a stale socket file (a killed server) is not in /proc/net/unix."""
    try:
        info = os.stat(prefix)
    except OSError:
        return ''
    server = tmp / f'.wine-{info.st_uid}' / f'server-{info.st_dev:x}-{info.st_ino:x}'
    wanted = os.path.realpath(prefix)
    for entry in proc.iterdir() if proc.is_dir() else ():
        if not entry.name.isdigit():
            continue
        try:
            if not (entry / 'comm').read_text().startswith('wineserver'):
                continue
            if os.readlink(entry / 'cwd') == str(server):
                return f'wineserver pid {entry.name} serves it ({server})'
            environ = dict(item.split('=', 1) for item in (entry / 'environ').read_bytes().decode(
                errors='replace').split('\0') if '=' in item)
        except OSError:
            continue
        if environ.get('WINEPREFIX') and os.path.realpath(environ['WINEPREFIX']) == wanted:
            return f'wineserver pid {entry.name} has WINEPREFIX={environ["WINEPREFIX"]}'
    try:
        listening = (proc / 'net' / 'unix').read_text().split()
    except OSError:
        listening = []
    if str(server / 'socket') in listening:
        return f'{server}/socket is listening'
    return ''


def wait_exit(process, seconds):
    try:
        process.wait(timeout=seconds)
        return True
    except subprocess.TimeoutExpired:
        return False


def remove_leftovers():
    """Block mode a dead kfilterd left (pinned BPF links, saved policy) keeps enforcing: restart
    kfilterd, which adopts it, and stop it, which turns it off and unpins."""
    if (WINDOWS or not any(path.exists() for path in LEFTOVERS)
            or kfilterctl('status', check=False, quiet=True).returncode == 0):
        return
    say('kfilterd is gone but its block mode still enforces: restarting kfilterd to remove it')
    daemon = subprocess.Popen([tool('kfilterd')], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              start_new_session=True)
    for _ in range(100):
        if daemon.poll() is not None or kfilterctl('status', check=False, quiet=True).returncode == 0:
            break
        time.sleep(0.2)
    kfilterctl(kfilter_command('shutdown', 'stop', 'unpin') or 'stop', check=False)
    if not wait_exit(daemon, 10):
        daemon.kill()
        daemon.wait()
    if any(path.exists() for path in LEFTOVERS):
        say('WARNING: kfilter block mode is still enforced; `sudo kfilterd` then `sudo kfilterctl stop` removes it')


# ---------------------------------------------------------------- files the run writes

def as_user(uid):
    """subprocess arguments that run a child as the user (uid, groups, HOME) instead of root."""
    if WINDOWS or not uid:
        return {}
    import pwd
    user = pwd.getpwuid(uid)
    drop = {'user': uid, 'group': user.pw_gid, 'env': dict(os.environ, HOME=user.pw_dir)}
    if os.geteuid() == 0:
        drop['extra_groups'] = os.getgrouplist(user.pw_name, user.pw_gid)
    return drop


def make_run_dir(log_dir, name, uid):
    """A fresh 0700 directory for this run inside log_dir (never log_dir itself: it may be
    shared), and (fd, path) for it. Root writes only through /proc/<pid>/fd/<fd>, which no
    rename or symlink in the user's log_dir can redirect; the directory stays root's until
    hand_over, so nothing the user plants is inside it."""
    if WINDOWS:
        (log_dir / name).mkdir(parents=True)
        return None, str(log_dir / name)
    if not log_dir.is_dir() and subprocess.run(['mkdir', '-p', '--', str(log_dir)], **as_user(uid)).returncode:
        fail(f'cannot create {log_dir}')   # made as the user: only where the user may write
    parent = os.open(log_dir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        info = os.fstat(parent)
        if info.st_uid != uid and not info.st_mode & stat.S_ISVTX:
            fail(f'{log_dir} is neither yours nor a shared (sticky) directory: choose another --log-dir')
        os.mkdir(name, 0o700, dir_fd=parent)
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    finally:
        os.close(parent)
    if os.fstat(fd).st_uid != os.geteuid():
        os.close(fd)
        fail(f'{log_dir / name} was replaced while it was created')
    return fd, f'/proc/{os.getpid()}/fd/{fd}'


def hand_over(fd, uid):
    """Give the run directory's directories and regular files to the user, never through a link."""
    for _, dirs, files, dir_fd in os.fwalk(dir_fd=fd):
        for name in dirs + files:
            mode = os.stat(name, dir_fd=dir_fd, follow_symlinks=False).st_mode
            if stat.S_ISDIR(mode) or stat.S_ISREG(mode):
                os.chown(name, uid, -1, dir_fd=dir_fd, follow_symlinks=False)
    os.chown(fd, uid, -1)


# ---------------------------------------------------------------- hiding, traps and the session's own services

def launch_options(args, client_dir):
    """`kfilterctl launch` options for the run's hiding, containment and trap flags (Linux). Only the
    private /proc and cgroup view is on by default: it changes nothing a same-user client uses."""
    options = ['--hostname', args.hostname] if args.hostname else []
    options += ['--uname26'] if args.uname26 else []
    if args.time_offset:
        offset = str(random.randint(86400, 30 * 86400)) if args.time_offset == 'random' else args.time_offset
        options += ['--time-offset', offset]
    options += [] if args.no_private_proc else ['--private-proc']
    options += ['--user', args.user] if args.user else []
    options += ['--trap-cpuid'] if args.trap_cpuid else []
    options += ['--trap-rdtsc'] if args.trap_rdtsc else []
    options += ['--cpuid-mask', args.cpuid_mask] if args.cpuid_mask else []
    if args.trap_cpuid or args.trap_rdtsc or args.cpuid_mask:
        options += ['--trap-log', f'{client_dir}/cpu-trap.log']
    return options


def windows_path(prefix, path):
    """path as the prefix's Windows programs name it, through the dosdevices drive that maps it
    (Z: is / in a default prefix), with '/' separators; None when no drive maps it."""
    found = None
    for drive in (Path(prefix) / 'dosdevices').glob('?:'):
        target = os.path.realpath(drive).rstrip('/')
        if path.startswith(target + '/') and (found is None or len(target) > len(found[1])):
            found = (drive.name[0].upper(), target)
    return None if found is None else f'{found[0]}:/{path[len(found[1]) + 1:]}'


CLIENT_FILE_MAX = 64 << 20   # a trap or TLS key log is far smaller


class ClientFiles:
    """A directory for what the client and the session's helpers write (trap log, TLS keys, X cookie,
    D-Bus proxy sockets): in /tmp so a dedicated account reaches it, short enough for socket paths,
    owned by the client's account with the invoking user's group (the helpers run as that user).
    Root writes and collects only through the directory's fd, never following a link."""

    def __init__(self, uid, gid):
        self.path = tempfile.mkdtemp(prefix='monfilter-client-')
        self.fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.uid, self.gid = uid, gid
        os.fchown(self.fd, uid, gid)
        os.fchmod(self.fd, 0o770)

    def write(self, name, data):
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640, dir_fd=self.fd)
        try:
            os.write(fd, data)
            os.fchown(fd, self.uid, self.gid)
        finally:
            os.close(fd)

    def collect(self, destination):
        """Copies the regular files, at most CLIENT_FILE_MAX bytes in all, into destination (the bundle),
        then removes the directory. The client wrote them: anything else is left out."""
        try:
            destination.mkdir(exist_ok=True)
            left = CLIENT_FILE_MAX   # a budget for the whole directory: sparse files cost the client nothing
            for name in os.listdir(self.fd):
                try:
                    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd)
                except OSError:
                    continue   # sockets, links
                try:
                    info = os.fstat(fd)
                    if not stat.S_ISREG(info.st_mode) or name == 'Xauthority':
                        continue
                    if info.st_size > left:
                        say(f'client file {name} left out: {info.st_size} bytes')
                        continue
                    left -= info.st_size
                    (destination / name).write_bytes(os.read(fd, info.st_size))
                finally:
                    os.close(fd)
        finally:
            os.close(self.fd)
            shutil.rmtree(self.path, ignore_errors=True)


def wait_for(path, process, seconds=10):
    for _ in range(seconds * 10):
        if os.path.exists(path) or process.poll() is not None:
            break
        time.sleep(0.1)
    return os.path.exists(path)


def other_display_rules(display):
    """Policy rules (first match wins) that leave the client X display :<display> alone: every other X
    server, by path or abstract socket and started now or later, every Wayland compositor and GNOME's
    Xwayland cookie are refused. For --nested-x and for the live loop's policies (relax/live_block.py)."""
    return [f'allow|pipe|/tmp/.X11-unix/X{display}|rights=connect',
            f'allow|pipe|/@/tmp/.X11-unix/X{display}|rights=connect',
            'deny|pipe|/tmp/.X11-unix/X*', 'deny|pipe|/@/tmp/.X11-unix/X*', 'deny|pipe|/run/user/*/wayland-*',
            'deny|file|/run/user/*/.mutter-Xwaylandauth.*']


# The bus names --dbus-proxy lets the client reach (xdg-dbus-proxy --talk). The recorded session
# live-1112-220823 showed winedevice.exe asking UDisks2 and BlueZ for their objects (GetManagedObjects 42,
# RegisterAgent 1: disk serials, Bluetooth devices) and nexon_client.exe Avahi (CUPS browsing for
# printers), nothing else but the bus itself, which the proxy always answers: all three refused, Wine
# finds no such service. The sign-in Chrome (past msmon's depth, not recorded) keeps its cookie key in
# the login keyring: its profile's cookies are all v11, the keyring-key format (GNOME picks libsecret),
# so without the Secret Service the profile reads as signed out. That name opens the whole unlocked
# keyring to the family; the proxy logs every call to it.
DBUS_TALK = ('org.freedesktop.secrets',)


def session_services(args, prefix, client, user, env_user, work, started):
    """The session's own X server and D-Bus proxies (opt-in), run as the invoking user (added to
    started), and the TLS key log: (client environment changes, policy rules to put first). The rules
    refuse the desktop's own sockets (audit mode: would-deny events show the client going around them)
    and allow the session's."""
    env, rules = {}, []
    if args.nested_x:
        kind = args.nested_x if args.nested_x != 'auto' else 'xwayland' if env_user.get('WAYLAND_DISPLAY') else 'xephyr'
        # FamilyWild with no address or display number: libXau uses it for any display (-displayfd picks it).
        field = lambda data: len(data).to_bytes(2, 'big') + data
        client.write('Xauthority', b'\xff\xff' + field(b'') + field(b'') + field(b'MIT-MAGIC-COOKIE-1') +
                     field(os.urandom(16)))
        command = ['Xwayland', '-geometry', '1280x800'] if kind == 'xwayland' else ['Xephyr', '-screen', '1280x800',
                                                                                   '-resizeable']
        read, write = os.pipe()
        server = subprocess.Popen([*command, '-displayfd', str(write), '-auth', f'{client.path}/Xauthority', '-nolisten',
                                   'tcp'], pass_fds=(write,), stdout=open(Path(work, 'nested-x.log'), 'w'),
                                  stderr=subprocess.STDOUT, start_new_session=True, **user)
        started.append(server)
        os.close(write)
        number = os.read(read, 16).decode().strip() if select.select([read], [], [], 20)[0] else ''
        os.close(read)
        if not number.isdigit():
            fail(f'the nested X server ({command[0]}) did not start; see nested-x.log in the run directory')
        env.update(DISPLAY=f':{number}', XAUTHORITY=f'{client.path}/Xauthority', WAYLAND_DISPLAY=None)
        rules += other_display_rules(number)
        if env_user.get('WAYLAND_DISPLAY'):   # (a runtime directory outside /run/user)
            rules.append(f'deny|pipe|{env_user.get("XDG_RUNTIME_DIR", "")}/{env_user["WAYLAND_DISPLAY"]}')
        if env_user.get('XAUTHORITY'):
            rules.append(f'deny|file|{env_user["XAUTHORITY"]}')
    if args.dbus_proxy:
        session = env_user.get('DBUS_SESSION_BUS_ADDRESS', '')
        buses = [('system_bus', 'unix:path=/run/dbus/system_bus_socket', 'DBUS_SYSTEM_BUS_ADDRESS')]
        buses += [('bus', session, 'DBUS_SESSION_BUS_ADDRESS')] if session.startswith('unix:path=') else []
        rules += ['deny|pipe|/run/dbus/system_bus_socket', 'deny|pipe|/run/user/*/bus', 'deny|pipe|/run/user/*/at-spi/*']
        for name, address, variable in buses:
            # Filtering is what makes xdg-dbus-proxy parse, and so log, each call; the rest is refused.
            proxy = subprocess.Popen(['xdg-dbus-proxy', address, f'{client.path}/{name}', '--filter', '--log',
                                      *(f'--talk={talk}' for talk in DBUS_TALK)],
                                     stdout=open(Path(work, f'dbus-{name}.log'), 'w'),
                                     stderr=subprocess.STDOUT, start_new_session=True, umask=0, **user)
            started.append(proxy)
            if not wait_for(f'{client.path}/{name}', proxy):
                fail(f'xdg-dbus-proxy for {address} did not start; see dbus-{name}.log in the run directory')
            env[variable] = f'unix:path={client.path}/{name}'
            rules.append(f'allow|pipe|{client.path}/{name}|rights=connect')
    if args.tls_keylog:
        # Chromium/CEF (BoringSSL) reads it as a Windows path; Wine's GnuTLS reads the same variable as a
        # Unix path, which a drive-letter path is not, so it logs only when no drive maps the directory.
        keys = f'{client.path}/tls-keys.log'
        env['SSLKEYLOGFILE'] = windows_path(prefix, keys) or keys
    if args.trap_cpuid or args.trap_rdtsc or args.cpuid_mask:
        # kfilterctl launch's trap shim: its options and its copy of the library (under default-deny each
        # process would otherwise be refused them).
        rules.append('allow|file|/tmp/kfshim.*|rights=read,execute,query')
    rules.append(f'allow|file|{client.path}/*|rights=read,write,create,query')
    return env, rules


def descendants(pid):
    """Every process below pid (by PPid in /proc)."""
    children = {}
    for entry in Path('/proc').iterdir():
        if entry.name.isdigit():
            try:
                parent = int((entry / 'stat').read_text().rsplit(')', 1)[1].split()[1])
            except (OSError, IndexError, ValueError):
                continue
            children.setdefault(parent, []).append(int(entry.name))
    found, todo = [], [pid]
    while todo:
        for child in children.get(todo.pop(), []):
            found.append(child)
            todo.append(child)
    return found


# ---------------------------------------------------------------- the client family

class Family:
    """The launched client's processes: the launch cgroup on Linux, image names on Windows."""

    def __init__(self):
        self.cgroup = None
        self.cgroup_seen = False
        self.launch = None

    def pids(self):
        if WINDOWS:
            result = subprocess.run(['tasklist', '/FO', 'CSV', '/NH'], capture_output=True, text=True)
            names = {name.lower() for name in FAMILY}
            return [int(row[1]) for row in (line.strip('"').split('","') for line in result.stdout.splitlines())
                    if len(row) > 1 and row[0].lower() in names and row[1].isdigit()]
        if self.cgroup and self.cgroup.is_dir():
            self.cgroup_seen = True
            try:
                return [int(pid) for pid in (self.cgroup / 'cgroup.procs').read_text().split()]
            except OSError:
                return []
        if self.cgroup_seen:
            return []   # kfilterctl removed the emptied cgroup
        # No launch cgroup (kfilterctl warned it could not make one, or the launch failed):
        # only what runs below `kfilterctl launch`, which waits for the client. Never matched by
        # environment: the user's own processes with the same WINEPREFIX are not the family.
        # shortcut: a process that daemonizes away from the launch is missed; the cgroup catches it.
        if self.launch is None or self.launch.poll() is not None:
            return []
        return descendants(self.launch.pid)

    def running(self):
        return (self.launch is not None and self.launch.poll() is None) or bool(self.pids())

    def kill(self):
        if self.launch is None:
            return   # --attach: not ours to stop
        if WINDOWS:
            for name in FAMILY:
                subprocess.run(['taskkill', '/F', '/T', '/IM', name], capture_output=True)
            return
        if self.cgroup and (self.cgroup / 'cgroup.kill').exists():
            try:
                (self.cgroup / 'cgroup.kill').write_text('1')
            except OSError:
                pass
        for pid in self.pids():
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        if self.launch.poll() is None:
            self.launch.terminate()
        for _ in range(50):
            if not self.pids():
                break
            time.sleep(0.1)
        if self.cgroup:
            try:
                self.cgroup.rmdir()
            except OSError:
                pass


# ---------------------------------------------------------------- run

def interrupted(number, _frame):
    if number == getattr(signal, 'SIGHUP', None):
        # The terminal is gone: writing to it would fail every later cleanup step.
        quiet = os.open(os.devnull, os.O_WRONLY)
        os.dup2(quiet, 1)
        os.dup2(quiet, 2)
    raise KeyboardInterrupt


STOP_SIGNALS = [getattr(signal, name) for name in ('SIGINT', 'SIGTERM', 'SIGHUP') if hasattr(signal, name)]

def user_context(args):
    """(home, uid) of the user the client runs as; root's own run uses the prefix owner."""
    if WINDOWS:
        return Path(os.environ.get('USERPROFILE', str(Path.home()))), None
    import pwd
    uid = int(os.environ.get('SUDO_UID', '0') or 0)
    if uid == 0 and args.prefix and Path(args.prefix).exists():
        uid = Path(args.prefix).stat().st_uid
    if uid == 0:
        fail('refusing to run the client as root: run monfilter.py as your user (it uses sudo itself)')
    return Path(pwd.getpwuid(uid).pw_dir), uid


def reexec_as_root(argv):
    """Linux: re-run with sudo, carrying what the root side cannot know about the user."""
    extra = []
    if argv[0] != 'run':
        os.execvp('sudo', ['sudo', sys.executable, str(Path(__file__).resolve()), *argv])
    if '--prefix' not in argv:
        extra += ['--prefix', os.environ.get('WINEPREFIX') or str(Path.home() / '.wine-nexon')]
    for name in USER_ENV:
        if name in os.environ:
            extra += ['--user-env', f'{name}={os.environ[name]}']
    # Right after the subcommand: --entry takes everything after it.
    os.execvp('sudo', ['sudo', sys.executable, str(Path(__file__).resolve()), argv[0], *extra, *argv[1:]])


def run(args):
    if args.keep_enforcing and not args.block:
        fail('--keep-enforcing needs --block')
    previous = read_state()
    if previous and alive(previous.get('pid')):
        fail(f'a run is already active (pid {previous["pid"]}); `monfilter.py stop` ends it')
    home, uid = user_context(args)
    if WINDOWS:
        prefix = Path('C:/')
        client = Path(args.client or r'C:\Nexon\Library\maplestorycw')
        extra_roots = [Path(r'C:\Program Files (x86)\Nexon\Nexon Launcher'), Path(r'C:\ProgramData\Nexon\NGS')]
        entry = args.entry or [r'C:\Program Files (x86)\Nexon\Nexon Launcher\nexon_launcher.exe']
    else:
        prefix = Path(args.prefix or home / '.wine-nexon')
        drive = prefix / 'drive_c'
        client = Path(args.client or drive / 'Nexon/Library/maplestorycw')
        extra_roots = [drive / 'Program Files (x86)/Nexon/Nexon Launcher', drive / 'ProgramData/Nexon/NGS']
        entry = args.entry or [str(home / '.local/bin/nexon-launcher')]
        # The launch would join a running wineserver: the family is then outside kfilterctl launch.
        running = None if args.attach else prefix_wineserver(prefix)
        if running:
            fail(f'the Wine prefix {prefix} is already running ({running}): close the Nexon Launcher '
                 '(and everything else in that prefix) first, or use --attach to record the running one')
    linux_only = [name for name in ('hostname', 'uname26', 'time_offset', 'user', 'trap_cpuid', 'trap_rdtsc',
                                    'cpuid_mask', 'nested_x', 'dbus_proxy', 'tls_keylog') if getattr(args, name)]
    if WINDOWS and linux_only:
        fail(f'Linux-only options: {", ".join(linux_only)}')
    client_uid = uid
    if args.user:
        import pwd
        try:
            client_uid = pwd.getpwnam(args.user).pw_uid
        except KeyError:
            fail(f'--user: no account {args.user}')
        if not prefix.is_dir() or prefix.stat().st_uid != client_uid:
            fail(f'--user {args.user} needs --prefix <a Wine prefix owned by {args.user}>')
    env_user = dict(item.split('=', 1) for item in args.user_env or [])
    entry_exe = shutil.which(entry[0], path=env_user.get('PATH'))
    entry_exe = os.path.realpath(entry_exe) if entry_exe else entry[0]   # kfilterctl launch admits the real path
    mode = 'block' if args.block else 'audit'
    log_dir = Path(args.log_dir or home / 'monfilter-sessions')
    test_id = time.strftime('monfilter-%Y%m%dT%H%M%S-') + mode
    run_dir = log_dir / test_id
    session_dir = run_dir / test_id   # msmon's bundle: --log-dir <run_dir> --test-id <test_id>
    # The agent's stop file is root's: the client must not be able to end its own recording.
    state = {'pid': os.getpid(), 'mode': mode, 'keep_enforcing': args.keep_enforcing, 'session_dir': str(session_dir),
             'log_dir': str(log_dir), 'stop_file': str(STATE_DIR / 'agent-stop')}
    agent_stop = Path(state['stop_file'])
    cleanup = []   # run in reverse: family, msmon, kfilter, kfilterd
    family = Family()
    agent = None
    run_fd, work, completed = None, None, False
    client_files, services = None, []   # what the client writes (trap log, TLS keys); the session's X, D-Bus
    unpin = [True]   # --keep-enforcing counts only once the client stage is reached

    def stop_kfilter(started):
        if not unpin[0] and not (STOP_REQUEST.exists() and 'unpin' in STOP_REQUEST.read_text()):
            say('block mode stays on (--keep-enforcing): `monfilter.py stop` turns it off and unpins it')
            return
        kfilterctl('off', check=False)
        if WINDOWS:
            return
        shutdown = kfilter_command('shutdown', 'stop', 'unpin')
        if started is not None:
            # off, BPF links unpinned, kfilterd exits; one that does not answer is terminated
            sent = shutdown and started.poll() is None and kfilterctl(shutdown, check=False).returncode == 0
            if not (sent and wait_exit(started, 10)):
                started.terminate()
                if not wait_exit(started, 10):
                    started.kill()
        elif shutdown:
            say(f'kfilterd was already running: left running with mode off (`kfilterctl {shutdown}` stops it)')
        remove_leftovers()

    for number in STOP_SIGNALS:
        signal.signal(number, interrupted)
    try:
        write_state(state)
        STOP_REQUEST.unlink(missing_ok=True)
        agent_stop.unlink(missing_ok=True)
        run_fd, work = make_run_dir(log_dir, test_id, uid)

        def stop_services():
            for process in services:
                process.terminate()
                if not wait_exit(process, 5):
                    process.kill()
                    process.wait()
        cleanup.append(stop_services)   # last: after the family and the tools
        session_env, session_rules = {}, []
        if not WINDOWS and (args.nested_x or args.dbus_proxy or args.tls_keylog or args.trap_cpuid or
                            args.trap_rdtsc or args.cpuid_mask):
            import pwd
            client_files = ClientFiles(client_uid, pwd.getpwuid(uid).pw_gid)
            helper = as_user(uid)
            helper['env'] = dict(helper.get('env', os.environ), **env_user)
            session_env, session_rules = session_services(args, prefix, client_files, helper, env_user, work, services)
        policy_text = prepare_policy(args.policy or POLICY, mode, home, prefix, entry_exe, bool(args.entry))
        if not WINDOWS:
            # msmon reads the protected programs' memory (PE images, stacks, Wine's request data):
            # its own binary, by exact path, or block mode blinds the monitor.
            session_rules = [f"allow|handle|{BIN['agent'].resolve()}|rights=vm-operation,vm-read,vm-write"
                             f"|risk=msmon"] + session_rules
        # First match wins: the session's rules come before the policy's own.
        policy_text = ''.join(f'{rule}\n' for rule in session_rules) + policy_text
        policy_file = Path(work, 'kfilter-policy.txt')
        policy_file.write_text(policy_text, encoding='utf-8')
        checked = kfilterctl('check', str(policy_file), check=False, quiet=True)
        if checked.returncode != 0:
            fail(f'{run_dir / policy_file.name}: {checked.stderr.strip()}')
        problems = unenforceable(policy_text)
        for problem in problems:
            say(f'{"refused" if args.block else "warning"}: {problem}')
        if problems and args.block:
            fail('block mode refuses a policy with rules this OS cannot enforce (audit mode only warns)')

        # 1. kfilter: the driver/daemon, then the policy.
        started = None
        cleanup.append(lambda: stop_kfilter(started))   # first: an interrupt while kfilterd loads stops it too
        if WINDOWS:
            for service in ('kfilter', 'msmon'):
                if 'RUNNING' not in subprocess.run(['sc.exe', 'query', service], capture_output=True, text=True).stdout:
                    subprocess.run(['sc.exe', 'start', service], check=False)
        elif kfilterctl('status', check=False, quiet=True).returncode == 0:
            say('kfilterd is running: adopted')
        else:
            log = open(Path(work, 'kfilterd.log'), 'w')
            started = subprocess.Popen([tool('kfilterd')], stdout=log, stderr=subprocess.STDOUT,
                                       start_new_session=True)
            state['kfilterd_pid'] = started.pid
            write_state(state)
            for _ in range(100):
                if started.poll() is not None:
                    fail(f'kfilterd exited ({started.returncode}); see {run_dir / "kfilterd.log"}')
                if kfilterctl('status', check=False, quiet=True).returncode == 0:
                    break
                time.sleep(0.2)
            else:
                fail('kfilterd did not answer within 20 s')
        # A tag on kfilter's decisions, set before msmon opens the ring (msmon may then claim it).
        tag_command = None if WINDOWS else kfilter_command('session', 'session-tag', 'tag')
        if tag_command:
            state['session_tag'] = int.from_bytes(os.urandom(6), 'little') | 1
            kfilterctl(tag_command, str(state['session_tag']), check=False)

        # 2. msmon, before anything of the family starts, on every Nexon root.
        command = [tool('agent'), '--client', str(client), '--log-dir', work, '--test-id', test_id,
                   '--stop-file', state['stop_file'], '--scenario', 'mixed']
        if not WINDOWS:
            command += ['--prefix', str(prefix)]
        for root in extra_roots:
            if root.is_dir():
                command += ['--extra-root', str(root)]
        if args.no_payloads:
            command.append('--no-payloads')
        agent_log = open(Path(work, 'agent.log'), 'w')
        # The agent's "Writing" line (sensors, kfilter reader and log all open) is not flushed
        # into a pipe; stdbuf line-buffers it (libstdc++ cout goes through stdio).
        if shutil.which('stdbuf'):
            command = ['stdbuf', '-oL', *command]
        agent = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                 errors='replace', **({} if WINDOWS else {'start_new_session': True}))
        state['agent_pid'] = agent.pid
        write_state(state)
        ready = threading.Event()

        def pump():
            for line in agent.stdout:
                agent_log.write(line)
                agent_log.flush()
                if line.startswith('Writing '):
                    ready.set()
                elif line.startswith('Registered '):
                    # shortcut: without stdbuf (Windows) "Writing" may never arrive before exit;
                    # "Registered" is flushed and precedes it by the log and kfilter set-up.
                    threading.Timer(5, ready.set).start()
        threading.Thread(target=pump, daemon=True).start()

        def stop_agent():
            agent_stop.touch()
            if not wait_exit(agent, 120):
                say('msmon-agent did not stop within 120 s: terminating it')
                agent.terminate()
                if not wait_exit(agent, 30):
                    agent.kill()
        cleanup.append(stop_agent)
        while not ready.wait(0.5):
            if agent.poll() is not None:
                fail(f'msmon-agent exited ({agent.returncode}) before recording; see {run_dir / "agent.log"}')
        say(f'msmon is recording: {session_dir}')
        # The policy only now: kfilter decides nothing until msmon reads its ring, so a burst (a
        # client starting at once, under --attach) cannot overflow the ring before anyone reads it.
        kfilterctl('policy', str(policy_file))
        if args.block and 'fail-open' in kfilterctl('status', check=False, quiet=True).stdout:
            fail('kfilter reports block mode as fail-open (not pinned): refusing to run')

        # 3. The family, under kfilter's launch (admission, cgroup, privilege drop).
        cleanup.append(family.kill)
        if not args.attach:
            env = dict(os.environ, **env_user)
            if not WINDOWS:
                import pwd
                user = pwd.getpwuid(uid)
                env.update(WINEPREFIX=str(prefix), HOME=str(home), USER=user.pw_name, LOGNAME=user.pw_name,
                           SUDO_UID=str(uid), SUDO_GID=str(user.pw_gid))
                for name, value in session_env.items():
                    env.pop(name, None) if value is None else env.update({name: value})
            options = [] if WINDOWS else launch_options(args, client_files.path if client_files else '')
            family.launch = subprocess.Popen([tool('kfilterctl'), 'launch', *entry, *options], env=env,
                                             **({} if WINDOWS else {'start_new_session': True}))
            if not WINDOWS:
                family.cgroup = Path(f'/sys/fs/cgroup/kfilter/launch-{family.launch.pid}')
            say(f'launched {" ".join(entry)} ({mode} mode); Ctrl-C or `monfilter.py stop` ends the run')
        else:
            say('--attach: start the client yourself; Ctrl-C or `monfilter.py stop` ends the run')
        unpin[0] = not (args.block and args.keep_enforcing)
        time.sleep(2)
        while not STOP_REQUEST.exists():
            if agent.poll() is not None:
                say('msmon-agent stopped unexpectedly: stopping the client')
                break
            if started is not None and started.poll() is not None:
                say('kfilterd stopped unexpectedly: stopping the client')
                break
            if not args.attach and not family.running():
                if family.launch.returncode:
                    say(f'kfilterctl launch exited with {family.launch.returncode}')
                say('the client family has exited')
                break
            time.sleep(1)
        completed = True
    except KeyboardInterrupt:
        say('interrupted: stopping')
        completed = True
    finally:
        for number in STOP_SIGNALS:
            signal.signal(number, signal.SIG_IGN)   # cleanup and the handover must not be cut short
        for step in reversed(cleanup):
            try:
                step()
            except (Exception, SystemExit) as error:   # every later step still runs
                say(f'cleanup step failed: {error}')
        STATE.unlink(missing_ok=True)
        STOP_REQUEST.unlink(missing_ok=True)
        agent_stop.unlink(missing_ok=True)
        recorded = completed and agent is not None and Path(work, test_id).is_dir()
        try:
            if recorded:
                for name in ('kfilter-policy.txt', 'nested-x.log', 'dbus-bus.log', 'dbus-system_bus.log'):
                    if Path(work, name).exists():
                        shutil.copyfile(Path(work, name), Path(work, test_id, name))
            if client_files is not None:
                client_files.collect(Path(work, test_id, 'client') if recorded else Path(work, 'client'))
        except Exception as error:   # the client wrote those files: hand_over and finish still run
            say(f'policy, session logs or client files not copied into the bundle: {error}')
        if run_fd is not None:
            try:
                if uid:
                    hand_over(run_fd, uid)   # also after a failure: the user must be able to delete it
            except OSError as error:
                say(f'cannot hand {run_dir} over to you: {error}')
            os.close(run_fd)
        if recorded:
            finish(session_dir, uid)


def archive_only(session_dir):
    """The bundle's .zip once it reads back whole, the unpacked session removed (about 15x the size); the
    directory itself when there is no sound zip. `monfilter.py report` and tuning_report read either."""
    import zipfile
    archive = Path(f'{session_dir}.zip')
    try:
        with zipfile.ZipFile(archive) as bundle:
            if bundle.testzip() is not None or not any(name.startswith('events.jsonl') for name in bundle.namelist()):
                return Path(session_dir)
    except (OSError, zipfile.BadZipFile):
        return Path(session_dir)
    shutil.rmtree(session_dir)
    return archive


def finish(session_dir, uid):
    """session_pack and the tuning report, as the user, on the handed-over run directory."""
    user = as_user(uid)
    packed = subprocess.run([sys.executable, str(ROOT / 'monitor/tools/session_pack.py'), str(session_dir)],
                            **user).returncode == 0
    if not packed:
        say('session_pack failed; the report is made from the unpacked session')
    reported = subprocess.run([sys.executable, str(ROOT / 'filter/tools/tuning_report.py'), str(session_dir),
                               '--out', f'{session_dir}-tuning.md', '--json', f'{session_dir}-tuning.json'],
                              **user).returncode == 0
    if not reported:
        say('the tuning report failed')
    bundle = archive_only(session_dir) if packed and reported else session_dir
    say(f'bundle {bundle}; report {session_dir}-tuning.md')


# ---------------------------------------------------------------- stop, status, build, report

def stop(_args):
    state = read_state()
    if state and alive(state.get('pid')):
        STOP_REQUEST.write_text('unpin')
        say(f'asked run {state["pid"]} to stop')
        for _ in range(300):
            if not alive(state['pid']):
                return
            time.sleep(1)
        fail(f'run {state["pid"]} did not stop within 5 minutes')
    # No live run (or it was killed): stop what it left.
    if state and state.get('agent_pid') and alive(state['agent_pid']):
        (STATE_DIR / 'agent-stop').touch()   # root's own file, whatever an older state names
        say('asked msmon-agent to stop')
    kfilterctl('off', check=False)
    shutdown = None if WINDOWS else kfilter_command('shutdown', 'stop', 'unpin')
    if shutdown:
        kfilterctl(shutdown, check=False)
    remove_leftovers()
    STATE.unlink(missing_ok=True)


def status(_args):
    state = read_state()
    if state:
        state['run_alive'] = alive(state.get('pid'))
        print(json.dumps(state, indent=1))
    else:
        print('no run is active')
    return kfilterctl('status', check=False).returncode


def build(_args):
    command = ['cmd', '/c', str(ROOT / 'build.cmd')] if WINDOWS else ['sh', str(ROOT / 'build.sh')]
    return subprocess.run(command).returncode


def test(_args):
    if not WINDOWS:
        return subprocess.run(['sh', str(ROOT / 'tests/run_offline.sh')]).returncode
    for command in ([str(BIN['kfilterctl']), 'self-test'], ['cmd', '/c', str(ROOT / 'monitor/tests/integration_regression.cmd')],
                    [sys.executable, str(ROOT / 'tests/report_test.py')]):
        if subprocess.run(command).returncode:
            return 1
    return 0


def report(args):
    import tuning_report
    argv = [args.bundle, '--top', str(args.top)]
    for option in ('policy', 'out', 'json'):
        if getattr(args, option):
            argv += [f'--{option}', getattr(args, option)]
    tuning_report.main(argv)
    return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0],
                                     formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('build', help='compile both halves (no tests)')
    sub.add_parser('test', help='build the test binaries and run every offline check')
    runner = sub.add_parser('run', help='kfilter + msmon + the client, then bundle and report')
    runner.add_argument('--block', action='store_true', help='enforce (default: audit, nothing blocked)')
    runner.add_argument('--keep-enforcing', action='store_true', help='with --block: leave enforcement on at exit')
    runner.add_argument('--policy', help=f'policy file (default {POLICY.relative_to(ROOT)})')
    runner.add_argument('--no-payloads', action='store_true', help='metadata only: no socket bytes, no pcap')
    runner.add_argument('--entry', nargs=argparse.REMAINDER, help='program and arguments to launch (last option)')
    runner.add_argument('--attach', action='store_true', help='start only the tools; the client is started by hand')
    runner.add_argument('--prefix', help='Wine prefix (Linux; default $WINEPREFIX or ~/.wine-nexon)')
    runner.add_argument('--client', help='client root for msmon (default the MapleStory install)')
    runner.add_argument('--log-dir', help='where session bundles go (default ~/monfilter-sessions)')
    runner.add_argument('--user-env', action='append', help=argparse.SUPPRESS)
    hiding = runner.add_argument_group('Linux hiding, containment and traps (all off but the private /proc; '
                                       'filter/docs/LINUX.md)')
    hiding.add_argument('--hostname', help='the session host name (UTS namespace)')
    hiding.add_argument('--uname26', action='store_true', help='uname reports a 2.6 kernel release')
    hiding.add_argument('--time-offset', metavar='SECONDS|random', help='shift uptime (time namespace)')
    hiding.add_argument('--no-private-proc', action='store_true',
                        help='keep the host /proc and cgroup view (default: a hidepid /proc and a cgroup namespace)')
    hiding.add_argument('--user', help='run the client as this dedicated account (with --prefix owned by it)')
    hiding.add_argument('--trap-cpuid', action='store_true', help='trap and log each CPUID leaf (in-process shim)')
    hiding.add_argument('--trap-rdtsc', action='store_true', help='trap and log RDTSC/RDTSCP (forensic: slows time reads)')
    hiding.add_argument('--cpuid-mask', metavar='LEAVES', help='zero identity leaves, e.g. 0x80000002-0x80000004')
    hiding.add_argument('--nested-x', nargs='?', const='auto', choices=('auto', 'xwayland', 'xephyr'),
                        help="the client's own X server; the desktop's X sockets are refused")
    hiding.add_argument('--dbus-proxy', action='store_true',
                        help='session and system bus through xdg-dbus-proxy --log; the real buses are refused')
    hiding.add_argument('--tls-keylog', action='store_true',
                        help='SSLKEYLOGFILE for the client into the bundle (decrypts the pcap offline)')
    sub.add_parser('stop', help='end the run; kfilter off and unpinned')
    sub.add_parser('status', help='show the run and kfilter status')
    reporter = sub.add_parser('report', help='tuning report for a session bundle')
    reporter.add_argument('bundle', help='session directory, bundle .zip or events.jsonl')
    reporter.add_argument('--policy', help='default: kfilter-policy.txt in the bundle')
    reporter.add_argument('--out', help='markdown (default: stdout)')
    reporter.add_argument('--json', help='JSON report')
    reporter.add_argument('--top', type=int, default=25)
    args = parser.parse_args(argv)
    if args.command in ('run', 'stop', 'status'):
        if WINDOWS:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                fail('run this from an elevated (administrator) prompt')
        elif os.geteuid() != 0:
            reexec_as_root(argv)
    return {'build': build, 'test': test, 'run': run, 'stop': stop, 'status': status, 'report': report}[args.command](args) or 0


if __name__ == '__main__':
    sys.exit(main())
