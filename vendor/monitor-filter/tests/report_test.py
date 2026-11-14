#!/usr/bin/env python3
"""Offline end-to-end check of the tuning report: a synthetic session (msmon records plus
kfilter_decision records, old and new detail formats) -> `monfilter.py report` -> every
category, the candidate rules, the zip input, and the policy rule numbering (against
`kfilterctl check` when it is built, which must also load every candidate rule)."""
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
KFILTERCTL = ROOT / 'filter' / 'build' / 'linux' / 'kfilterctl'
sys.path.insert(0, str(ROOT / 'filter' / 'tools'))
import tuning_report  # noqa: E402

LAUNCHER = '/home/u/.wine-nexon/drive_c/Program Files (x86)/Nexon/Nexon Launcher'
WINE = '/opt/wine-stable/lib/wine/x86_64-unix/wine-preloader'
POLICY = f"""mode audit
protect MapleStory.exe
default-deny on
block-files on
deny|registry|\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Cryptography|value=MachineGuid
deny|file|/etc/hostname
allow|file|{LAUNCHER}|rights=read,execute|image=nexon_*
allow|network|ip=203.0.113.9/32|port=443|proto=tcp|rights=connect|uses=1|risk=test
deny|file|/etc/machine-id
"""


def record(kind, pid, text='', detail='', **extra):
    base = dict(protocol=5, schema_version=1, source='agent', sequence=0, timestamp='2026-11-08T00:00:00Z',
                session_id=1, type=kind, type_id=0, process_id=pid, process_start_time=1, process_path='',
                parent_process_id=1, thread_id=pid, target_process_id=0, target_process_start_time=0, flags=0,
                status=0, status_name='', status_hex='0x00000000', desired_access=0, category='unknown',
                outside_client=False, attribution='process_only', value0=0, value1=0, operation_id=0,
                text=text, detail=detail, component='', modules=[])
    base.update(extra)
    return json.dumps(base)


def decision(pid, path, action, layer, rule_id, image, rights='0x00000001', rule=''):
    detail = (f'action={action};layer={layer};target={layer};rule_id={rule_id};rights={rights};image={image};'
              f'pid={pid};brokered=0;generation=1;decision={action};flags=0x00000000;rule={rule}')
    return record('kfilter_decision', pid, path, detail, component='kfilter')


EVENTS = [
    record('coverage', 0, 'kfilter_available', 'abi=9;mode=audit;degraded=0x00000000'),
    # Linux: msmon names the exec by Wine's loader; the program is named by kfilter's image=.
    record('process_start', 100, '/opt/wine-stable/bin/wine64-preloader', 'exec', value0=1),
    record('process_start', 300, 'C:\\Program Files (x86)\\Nexon\\Nexon Launcher\\nexon_launcher.exe'),
    record('process_start', 200, 'C:\\Program Files (x86)\\Nexon\\Nexon Launcher\\bin\\nexon_client\\nexon_client.exe',
           parent_process_id=300),
    # MapleStory's exec was decided (process_create, by pid); nexon_client's start (by the launcher) was not.
    decision(100, '/opt/wine-stable/bin/wine', 'allow', 'process_create', 0, 'MapleStory.exe', rights='0x00000100'),
    # BLOCKED, with the rule text carried in the decision.
    decision(100, '/etc/machine-id', 'deny', 'file', 5, 'MapleStory.exe', rule='deny file /etc/machine-id'),
    record('file_create', 100, '/etc/machine-id', 'syscall=openat;ret=-13'),
    # WOULD BLOCK, old (pre-merge) detail format and no image=: named from the pid's other decisions.
    record('kfilter_decision', 100, '\\REGISTRY\\MACHINE\\HARDWARE\\DESCRIPTION',
           'target=registry;action=deny;decision=would_deny;target_id=4;action_id=3;flags=0x00000001;'
           'rights=0x00000001;rule_id=0;generation=1'),
    record('registry_open', 100, '\\REGISTRY\\MACHINE\\HARDWARE\\DESCRIPTION', 'wineserver;open_key'),
    decision(100, 'tcp 203.0.113.5:443', 'would_deny', 'network', 0, 'MapleStory.exe', rights='0x00000200'),
    # msmon writes 'local -> remote'; kfilter only the remote.
    record('network_connect', 100, '192.168.1.20:50123 -> 203.0.113.5:443', 'connect;family=2;syscall=connect;ret=0'),
    # ALLOWED BY RULE, broad rule 3 (text from the policy file): candidate exact replacement.
    decision(200, f'{LAUNCHER}/bin/x.dll', 'allow', 'file', 3, 'nexon_client.exe', rights='0x00000005'),
    record('image_load', 200, f'{LAUNCHER}/bin/x.dll', 'source=mmap'),
    # NO RULE: seen by msmon, never decided by kfilter.
    record('file_read', 100, '/home/u/.mozilla/firefox/cookies.sqlite', 'syscall=read;ret=4096'),
    record('network_connect', 100, '192.168.1.20:50124 -> 198.51.100.7:8484', 'connect;family=2;syscall=connect;ret=0'),
    # Rule-only layers no rule names yet (Linux): NO RULE, with an audit candidate.
    record('file_query_information', 100, 'system:uname', 'syscall=uname;ret=0'),
    record('thread_start', 100),
    # NOT FILTERABLE (Windows: WMI is served by its service).
    record('etw_wmi', 200, 'SELECT * FROM Win32_BIOS', 'wmi'),
    record('process_exit', 100),
]


def check(condition, message):
    if not condition:
        sys.exit(f'[fail] {message}')


def paths(report, image, category):
    return {entry['path'] or entry['layer'] for entry in report['programs'][image][category]}


def main():
    with tempfile.TemporaryDirectory(prefix='monfilter-report-test-') as scratch:
        bundle = pathlib.Path(scratch) / 'session'
        bundle.mkdir()
        (bundle / 'events.jsonl').write_text('\n'.join(EVENTS) + '\n', encoding='utf-8')
        (bundle / 'kfilter-policy.txt').write_text(POLICY, encoding='utf-8')
        out, out_json = pathlib.Path(scratch) / 'tuning.md', pathlib.Path(scratch) / 'tuning.json'
        result = subprocess.run([sys.executable, str(ROOT / 'monfilter.py'), 'report', str(bundle),
                                 '--out', str(out), '--json', str(out_json)], capture_output=True, text=True)
        check(result.returncode == 0, f'report failed: {result.stdout}{result.stderr}')
        report = json.loads(out_json.read_text(encoding='utf-8'))
        markdown = out.read_text(encoding='utf-8')

        check(paths(report, 'MapleStory.exe', 'blocked') == {'/etc/machine-id'}, 'BLOCKED')
        check(paths(report, 'MapleStory.exe', 'would_block') ==
              {'\\REGISTRY\\MACHINE\\HARDWARE\\DESCRIPTION', 'tcp 203.0.113.5:443'}, 'WOULD BLOCK')
        allowed = report['programs']['nexon_client.exe']['allowed_by_rule']
        check(len(allowed) == 1 and allowed[0]['rule_id'] == 3 and 'image=nexon_*' in allowed[0]['rule'] and
              allowed[0]['rights'] == 'execute,read', f'ALLOWED BY RULE: {allowed}')
        check(paths(report, 'MapleStory.exe', 'no_rule') ==
              {'/home/u/.mozilla/firefox/cookies.sqlite', '192.168.1.20:50124 -> 198.51.100.7:8484', '/system/uname',
               'thread'}, 'NO RULE')
        check('wine64-preloader' not in report['programs'], 'a Wine loader named a program')
        check(not report['programs']['nexon_client.exe']['no_rule'], 'the decided image load is not a gap')
        check(paths(report, 'nexon_launcher.exe', 'no_rule') ==
              {'C:\\Program Files (x86)\\Nexon\\Nexon Launcher\\bin\\nexon_client\\nexon_client.exe'},
              'NO RULE (launcher): the undecided start of nexon_client is the launcher\'s')
        check(any(entry['layer'] == 'process' and entry['rule_id'] == 0
                  for entry in report['programs']['MapleStory.exe']['allowed_by_rule']), 'process_create allow')
        check(not report['programs']['MapleStory.exe']['not_filterable'], 'uname and threads are rule-only layers now')
        check(paths(report, 'nexon_client.exe', 'not_filterable') == {'WMI query (served by the WMI service)'},
              'NOT FILTERABLE (WMI)')
        tighten = [item['rule'] for item in report['candidates_tighten']]
        for expected in ('deny|file|/home/u/.mozilla/firefox|image=MapleStory.exe',
                         'deny|network|ip=198.51.100.7|port=8484|image=MapleStory.exe',
                         f'allow|file|{LAUNCHER}/bin/x.dll|rights=execute,read|exact|image=nexon_client.exe',
                         'audit|system|/system/uname|image=MapleStory.exe', 'audit|thread|\\MapleStory.exe'):
            check(expected in tighten, f'candidate missing: {expected}\n{tighten}')
        check(any(rule.startswith('# review process C:') for rule in tighten), 'process gap review line')
        needed = [item['rule'] for item in report['candidates_if_needed']]
        check('allow|registry|\\REGISTRY\\MACHINE\\HARDWARE\\DESCRIPTION|rights=read|exact|image=MapleStory.exe'
              in needed, f'exact allow for a would-block missing: {needed}')
        for title in list(tuning_report.TITLES.values()) + ['NOT SEEN BY EITHER TOOL']:
            check(title in markdown, f'markdown lacks {title}')
        accepts(tighten + needed, 'fixture')

        archive = pathlib.Path(scratch) / 'session.zip'
        with zipfile.ZipFile(archive, 'w') as handle:
            for name in ('events.jsonl', 'kfilter-policy.txt'):
                handle.write(bundle / name, name)
        zipped = tuning_report.main([str(archive), '--out', os.devnull])
        check(zipped['totals'] == report['totals'], 'zip bundle gives different totals')

    # Rule numbering must match kfilterctl's (the report falls back to it for rule text).
    if KFILTERCTL.exists():
        with tempfile.TemporaryDirectory() as scratch:
            policy = pathlib.Path(scratch) / 'policy.txt'
            policy.write_text(POLICY, encoding='utf-8')
            checked = subprocess.run([str(KFILTERCTL), 'check', str(policy)], capture_output=True, text=True)
            check(checked.returncode == 0, f'kfilterctl check: {checked.stderr}')
            listed = checked.stdout
            ids = {int(match.group(1)): match.group(2) for match in
                   re.finditer(r'^\s+(\d+) (\w+)\s', listed, re.M)}
            ours = tuning_report.load_policy_rules(str(policy))[0]
            check(set(ids) == set(ours), f'rule IDs differ: kfilterctl {sorted(ids)} vs {sorted(ours)}')
            check(all(ours[rule_id].startswith(action) for rule_id, action in ids.items()), 'rule actions differ')
    else:
        print('note: kfilterctl not built; rule numbering not cross-checked')
    # msmon percent-encodes image=: a hostile program name cannot replace or cut fields.
    fields = tuning_report.detail_fields('action=deny;layer=file;target=file;rule_id=5;rights=0x00000001;'
                                         'image=a%3Blayer%3Dx%3Brule%3D%25.exe;pid=7;rule=deny file /x')
    check(fields['image'] == 'a;layer=x;rule=%.exe' and fields['layer'] == 'file' and fields['rule_id'] == '5' and
          fields['pid'] == '7' and fields['rule'] == 'deny file /x', f'escaped image= parse: {fields}')
    regressions()
    wine_labels()
    linux_layers()
    key_forms()
    wine_requests()
    symlinked()
    block_allows()
    msmon_records()
    policies(KFILTERCTL if KFILTERCTL.exists() else None)
    print('report_test passed')


def msmon_records():
    """msmon's later records: a hardware watchpoint on the process's own memory (watch_*, process_handle watch:<spec>)
    is no rule's, a library the /proc maps poll found gone (image_unload;source=maps_poll) is no action, a desktop
    service's summary on a socket whose connect msmon did not see (socket:[ino], unix_service) is AF_UNIX I/O and not an
    RPC call, and the process's own fault signals and outside processes' access checks (observer coverage records
    self_signal and outside_access) are neither actions nor the session's coverage notes."""
    maple = 'MapleStory.exe'
    wine = '/opt/wine-stable/lib/wine/x86_64-unix/wine-preloader'
    watch = 'watch:grap64.dll+0x1000:4:w'
    report = analyzed([
        decision(100, '/x', 'allow', 'file', 0, maple),
        record('process_handle', 100, watch, 'watch_attached;address=0x7f0001000;length=4;access=w', target_process_id=100),
        record('process_handle', 100, watch, 'watch_hit;address=0x7f0001000;length=4;access=w;ip=0x401000',
               target_process_id=100),
        record('process_handle', 100, watch, 'repeats_tail;syscall=watch_hit;aggregate=kernel;repeats_before=9',
               target_process_id=100),
        record('file_section', 100, '/usr/lib/x86_64-linux-gnu/libfoo.so', 'image_unload;source=maps_poll;base=0x7f0000000000',
               process_path=wine),
        record('etw_rpc', 100, 'socket:[4242]', 'repeats_tail;syscall=unix_service;aggregate=kernel;interface=x11;'
               'operation=GetImage;direction=sent;socket=4242;repeats_before=3'),
        record('coverage', 100, 'self_signal', 'self_signal;signal=4;name=sigill;code=2;code_name=ill_illopn;ip=0x1000;'
               'addr=0x1000;trap=6;error_code=0x0', flags=0x20),
        record('coverage', 100, 'self_signal', 'repeats_tail;syscall=self_signal;aggregate=kernel;signal=5;name=sigtrap;'
               'repeats_before=4', flags=0x20),
        record('coverage', 100, 'outside_access', 'outside_access;actor=1;mode=0x11;syscall=kcmp;actor_tid=1;actor_comm=ps;'
               'ret=0;actor_exe=/usr/bin/ps', target_process_id=1, flags=0x20),
    ])
    check(paths(report, maple, 'not_filterable') == {tuning_report.NF_WATCH, tuning_report.NF_UNIX},
          f'msmon records not filterable: {paths(report, maple, "not_filterable")}')
    check(not gaps(report, maple), f'msmon records read as gaps: {gaps(report, maple)}')
    check(report['not_seen'] == list(tuning_report.BLIND_SPOTS) and not report['kfilter_coverage'],
          f'coverage records read as coverage notes: {report["not_seen"]} {report["kfilter_coverage"]}')


def accepts(rules, what):
    """Every candidate line loads (kfilterctl check refuses the whole policy at its first bad line)."""
    if not KFILTERCTL.exists():
        return
    with tempfile.TemporaryDirectory() as scratch:
        policy = pathlib.Path(scratch) / 'candidates.txt'
        policy.write_text('protect \\MapleStory.exe\n' + '\n'.join(rules) + '\n', encoding='utf-8')
        checked = subprocess.run([str(KFILTERCTL), 'check', str(policy)], capture_output=True, text=True)
    check(checked.returncode == 0, f'{what}: kfilterctl check refuses a candidate: {checked.stderr}\n{rules}')


def analyzed(events, coverage_only=False):
    with tempfile.TemporaryDirectory() as scratch:
        part = pathlib.Path(scratch) / 'events.jsonl'
        part.write_text('\n'.join(events) + '\n', encoding='utf-8')
        programs, coverage, _, flags, decisions, observed = tuning_report.analyze([str(part)], '')
    tighten, _ = tuning_report.candidates(programs, flags, 25)
    _, report = tuning_report.render('x', '', programs, coverage, decisions, observed, tighten, [], 25)
    return report


def wine_labels():
    """Under Wine: socket messages without message rules are one gap (decided at connect), a handle
    inside the protected family is a peer gap, prctl is not filterable; other handles name their target;
    a name-failure decision is listed by that."""
    with tempfile.TemporaryDirectory() as scratch:
        policy = pathlib.Path(scratch) / 'policy.txt'
        policy.write_text(POLICY, encoding='utf-8')
        part = pathlib.Path(scratch) / 'events.jsonl'
        part.write_text('\n'.join([
            decision(100, '/x', 'allow', 'file', 0, 'MapleStory.exe'),
            decision(500, '/y', 'allow', 'file', 0, 'grap-core64.aes'),
            record('thread_handle', 500, '', 'open_thread;win_tid=1', target_process_id=100),
            record('process_handle', 500, '', 'open_process;win_pid=9', target_process_id=999),
            record('network_connect', 100, '127.0.0.1:1', 'sendto;syscall=sendto'),
            record('process_handle', 100, '', 'prctl;option=15'),
            # Wine NT objects: a pipe open is decided as a pipe; wineserver-moved I/O on it is the read request's
            # (/system/wine/read, rule-only: a gap no rule names yet).
            decision(100, '\\??\\pipe\\x', 'would_deny', 'pipe', 0, 'MapleStory.exe'),
            record('file_create', 100, '\\??\\pipe\\x', 'open_file_object;rootdir=0x0'),
            record('file_read', 100, '\\??\\pipe\\x', 'read;ws=read;handle=0x4'),
            # A device opened by NT name and a named section are file decisions by that name.
            decision(100, '\\??\\PhysicalDrive0', 'would_deny', 'file', 0, 'MapleStory.exe'),
            record('file_create', 100, '\\??\\PhysicalDrive0', 'open_file_object;rootdir=0x0', process_path=WINE),
            decision(100, '\\Sessions\\1\\BaseNamedObjects\\shm', 'would_deny', 'file', 0, 'MapleStory.exe'),
            record('file_section', 100, '\\Sessions\\1\\BaseNamedObjects\\shm', 'open_mapping;rootdir=0x1c',
                   process_path=WINE),
            # Netlink is decided at the send (device /net/netlink/...): one decision covers the socket's records.
            decision(100, '/net/netlink/route', 'would_deny', 'device', 0, 'MapleStory.exe'),
            record('network_connect', 100, 'family=16', 'sendto;family=16;syscall=sendto'),
            # Network actions that are not decidable connections.
            record('network_accept', 100, '0.0.0.0:0', 'bind;family=2;syscall=bind'),
            record('network_connect', 100, 'family=0', 'connect;family=0;syscall=connect'),
            record('network_accept', 100, '', 'accept;ws=ioctl;afd=accept;socket=0xce4'),
            # Not actions to decide: a mapping msmon found already there, the start of tracking, the first
            # thread of a new process, a same-access copy of a non-process handle, a Wine driver's IRP.
            record('image_load', 100, '/usr/lib/x86_64-linux-gnu/libz.so.1', ''),
            record('process_start', 100, '', '', flags_names=['inherited_track']),
            record('thread_handle', 100, '', 'new_thread;process=0x44;win_pid=48'),
            record('process_handle', 100, '', 'dup_handle;object=unknown;src_process=0xffffffff;src_handle=0x8;'
                   'dst_process=0x160;options=0x3'),
            record('file_device_control', 100, 'device:0x7fff00', 'irp=ioctl;client_win_tid=32'),
            record('kfilter_decision', 100, '', 'action=would_deny;layer=registry;target=registry;rule_id=0;'
                   'rights=0x00000001;image=MapleStory.exe;decision=would_deny;flags_names=would_deny|name_failure'),
        ]) + '\n', encoding='utf-8')
        programs = tuning_report.analyze([str(part)], str(policy))[0]
    grap, maple = programs['grap-core64.aes'], programs['MapleStory.exe']
    check({(e['layer'], e['path']) for e in grap['no_rule']} ==
          {('handle', 'open_process -> pid 999'), ('thread-peer', 'open_thread -> MapleStory.exe')},
          f'outside handle / in-family peer: {grap["no_rule"]}')
    with tempfile.TemporaryDirectory() as scratch:
        # unix= rules alone decide no INET message: still the one gap, not a rule per send.
        unix_policy = pathlib.Path(scratch) / 'policy.txt'
        unix_policy.write_text(POLICY + 'block-network on\ndeny|message|unix=/@kf\n', encoding='utf-8')
        events = pathlib.Path(scratch) / 'events.jsonl'
        events.write_text('\n'.join([decision(100, '/x', 'allow', 'file', 0, 'MapleStory.exe'),
                                     record('network_connect', 100, '127.0.0.1:1', 'sendto;syscall=sendto')]) + '\n',
                          encoding='utf-8')
        unix_only = tuning_report.analyze([str(events)], str(unix_policy))[0]['MapleStory.exe']
    check([e['path'] for e in unix_only['no_rule']] == [tuning_report.MESSAGE_NO_RULES],
          f'unix= rules alone count as no message rules: {unix_only["no_rule"]}')
    check([e['path'] for e in maple['no_rule']] == [tuning_report.MESSAGE_NO_RULES, '/system/wine/read'] and
          {e['layer'].split(' (')[0] for e in maple['not_filterable']} ==
          {'process control', 'bind to an ephemeral port',
           'connect to AF_UNSPEC', 'Winsock request to wineserver', 'mapping already present when msmon looked',
           'first thread of a new process', 'copy of a handle that is no process or thread, with the same access'},
          f'message / prctl / NT: {maple}')
    tighten, needed = tuning_report.candidates(programs, set(), 25)
    rules = [item['rule'] for item in tighten]
    for expected in ('audit|thread-peer|\\MapleStory.exe|image=grap-core64.aes', 'audit|message|rights=send|index=1'):
        check(expected in rules, f'candidate missing: {expected}\n{rules}')
    check(any(e['path'].startswith('(name kfilter could not resolve') for e in maple['would_block']),
          'name failure listed')
    needed = [item['rule'] for item in needed]
    check(needed and not any('could not resolve' in rule for rule in needed),
          f'exact allows for the NT names, none for a name kfilter could not resolve: {needed}')
    accepts(rules + needed, 'wine labels')


def key_forms():
    """kfilter's names for msmon's: an abstract Unix socket, Wine's Z: drive, and a sysfs symlink resolved."""
    check(tuning_report.key_of('pipe', 'unix:@/tmp/.X11-unix/X0') == '/@/tmp/.X11-unix/X0', 'abstract socket key')
    check(tuning_report.key_of('pipe', 'unix:/run/x.sock') == '/run/x.sock', 'unix socket key')
    # msmon's coalesced repeats (repeats_tail) and a socket's teardown are sorted as the action they repeat, or none.
    tail = {'type': 'network_connect', 'text': 'family=0', 'detail': 'repeats_tail;syscall=connect'}
    check(tuning_report.observed_layer(tail, tuning_report.detail_fields(tail['detail'] + ';family=0'))[1]
          .startswith('connect to AF_UNSPEC'), 'repeated AF_UNSPEC connect')
    close = {'type': 'etw_tcp', 'text': '127.0.0.1:0 -> 0.0.0.0:0', 'detail': 'event=state_change;from=LISTEN;to=CLOSE'}
    check(tuning_report.observed_layer(close, tuning_report.detail_fields(close['detail'])) is None, 'tcp teardown')
    sched = {'type': 'process_handle', 'target_process_id': 12, 'detail': 'sched_setaffinity;syscall=sched_setaffinity'}
    check(tuning_report.handle_layer('handle', '', sched, tuning_report.detail_fields(sched['detail']), 10, set(),
                                     str, {})[:2] == ('system', '/system/sched'), 'wineserver scheduling a thread')
    listen = dict(close, detail='event=state_change;from=CLOSE;to=LISTEN')
    check(tuning_report.observed_layer(listen, tuning_report.detail_fields(listen['detail'])) ==
          ('network', '127.0.0.1:0'), 'tcp listen by its local address')
    links = sorted(pathlib.Path('/sys/bus/usb/devices').glob('*')) if os.path.isdir('/sys/bus/usb/devices') else []
    if links:   # a host with USB in sysfs: the symlink resolves, also behind Wine's Z: drive
        real = os.path.realpath(links[0])
        check(tuning_report.key_of('file', f'/home/u/.wine/dosdevices/z:{links[0]}/idVendor') == real + '/idVendor',
              f'sysfs symlink key: {links[0]}')


def wine_requests():
    """The report's request names are kfilter's (kfilter_bpf.h KB_WINE_REQUESTS), and both are msmon's, which was read
    from the wineserver binary (monitor/agent/linux/wineserver.cpp), in number order."""
    header = (ROOT / 'filter/linux/bpf/kfilter_bpf.h').read_text(encoding='utf-8')
    kfilter = re.findall(r'X\((\w+), [QCW]\)', header[header.index('#define KB_WINE_REQUESTS(X)'):])
    decoder = (ROOT / 'monitor/agent/linux/wineserver.cpp').read_text(encoding='utf-8')
    table = re.search(r'kProtocol930\[\] = R"\((.*?)\)";', decoder, re.S).group(1)   # one request a line, its name first
    msmon = [line.split()[0] for line in table.splitlines() if line.strip()]
    check(len(kfilter) == 306 and kfilter == msmon, f'kfilter and msmon number the requests alike: {len(kfilter)}')
    check(list(tuning_report.WINE_REQUESTS) == kfilter, 'the report numbers them as kfilter does')


def block_allows():
    """Block mode: each refused action gets the allow that lets it through, in its layer's form (a network or
    device allow with a uses= budget of what was used); kfilterctl takes every one."""
    with tempfile.TemporaryDirectory() as scratch:
        part = pathlib.Path(scratch) / 'events.jsonl'
        part.write_text('\n'.join([
            decision(100, '/etc/fonts/fonts.conf', 'deny', 'file', 0, 'MapleStory.exe'),
            decision(100, 'tcp 203.0.113.9:8484', 'deny', 'network', 0, 'MapleStory.exe', rights='0x00000200'),
            decision(100, 'udp 255.255.255.255:0', 'deny', 'network', 0, 'MapleStory.exe', rights='0x00002000'),
            decision(100, '/net/netlink/route', 'deny', 'device', 0, 'MapleStory.exe'),
            decision(100, '\\??\\C:', 'deny', 'volume', 0, 'MapleStory.exe'),
            decision(100, 'C:\\windows\\system32\\winedevice.exe', 'deny', 'open', 0, 'MapleStory.exe', rights='0x00000412'),
            # ABI 11's rights: a lock, a chdir and a touch
            decision(100, '/home/u/.wine/x.lock', 'deny', 'file', 0, 'MapleStory.exe', rights='0x00008000'),
            decision(100, '/home/u/secret', 'deny', 'dir', 0, 'MapleStory.exe', rights='0x00010000'),
            decision(100, '/home/u/stamp', 'deny', 'file', 0, 'MapleStory.exe', rights='0x00020000'),
        ]) + '\n', encoding='utf-8')
        programs = tuning_report.analyze([str(part)], '')[0]
    needed = [item['rule'] for item in tuning_report.candidates(programs, None, 25)[1]]
    for expected in ('allow|file|/etc/fonts/fonts.conf|rights=read|exact|image=MapleStory.exe',
                     'allow|network|ip=203.0.113.9/32|port=8484|proto=tcp|rights=connect|uses=1|risk=needed|image=MapleStory.exe',
                     'allow|device|/net/netlink/route|rights=raw-device|uses=1|risk=needed|image=MapleStory.exe',
                     'allow|volume|\\??\\C:|rights=read|exact|image=MapleStory.exe',
                     'allow|open|C:\\windows\\system32\\winedevice.exe|rights=create-thread,vm-read,query-information|'
                     'risk=needed|image=MapleStory.exe',
                     'allow|file|/home/u/.wine/x.lock|rights=lock|exact|image=MapleStory.exe',
                     'allow|dir|/home/u/secret|rights=chdir|exact|image=MapleStory.exe',
                     'allow|file|/home/u/stamp|rights=touch|exact|image=MapleStory.exe'):
        check(expected in needed, f'block-mode allow missing: {expected}\n{needed}')
    check(not any('255.255.255.255' in rule for rule in needed), f'no allow for a portless send: {needed}')
    accepts(needed, 'block-mode allows')


def symlinked():
    """kfilter decides the file a symlink leads to; msmon logs the link: not a gap."""
    with tempfile.TemporaryDirectory() as scratch:
        real = pathlib.Path(scratch) / 'real.otf'
        real.write_text('x')
        link = pathlib.Path(scratch) / 'fonts'
        link.symlink_to(scratch)
        report = analyzed([decision(100, os.path.realpath(real), 'would_deny', 'file', 0, 'MapleStory.exe'),
                           record('file_create', 100, f'{link}/real.otf', 'syscall=openat;ret=3')])
    check(not gaps(report, 'MapleStory.exe'), f'symlinked path: {gaps(report, "MapleStory.exe")}')



def linux_layers():
    """One case per Linux layer of ABI 9: msmon's spelling of an action is matched to the kfilter name that
    decided it, a rule-only action no rule names is a gap with an audit candidate, the rest is not filterable;
    plus what neither tool sees and the client's CPU trap log."""
    maple = 'MapleStory.exe'
    wine = '/opt/wine-stable/lib/wine/x86_64-unix/wine-preloader'
    report = analyzed([
        record('coverage', 0, 'kernel_events', 'uring=on;not_seen=vdso_calls(no syscall),accesses_to_resident_pages'),
        # Decided: Wine request, win32u call, WMI class, /anon file, /proc/<pid>, executable memory, message, dns.
        decision(100, '/system/wine/list_processes', 'audit', 'system', 7, maple, '0x00000080'),
        record('file_query_information', 100, 'system:list_processes', 'ws=list_processes'),
        decision(100, '/system/win32k/NtGdiBitBlt', 'would_deny', 'system', 8, maple, '0x00000080'),
        record('file_query_information', 100, 'system:NtGdiBitBlt', 'call=NtGdiBitBlt;library=x86_64-unix/win32u.so'),
        decision(100, '/system/wmi/win32_bios', 'deny', 'system', 9, maple, '0x00000080'),
        record('etw_wmi', 100, 'query:Win32_BIOS', 'operation=exec_query;source=uprobe'),
        decision(100, '/anon/memfd:mesa', 'allow', 'file', 10, maple, '0x00000003'),
        record('file_section', 100, 'memfd:[5]', 'syscall=mmap;ret=1'),
        decision(100, '/proc/@outside/status', 'deny', 'file', 11, maple),
        record('file_read', 100, '/proc/4242/status', 'syscall=read;ret=10'),
        decision(100, '/system/memory/private/rwx', 'audit', 'system', 12, maple, '0x00000004'),
        record('file_section', 100, 'mprotect:0x1000', 'syscall=mprotect;ret=0;args=0x1000,0x1000,0x7;first_page_sha256=ab'),
        record('file_create', 100, 'socket:[77]', 'socket;family=2;type=1;protocol=6;syscall=socket;ret=5'),
        decision(100, 'send tcp 203.0.113.9:443 socket:[77] #1 len=5 data=16', 'audit', 'message', 10001, maple),
        record('file_write', 100, 'socket:[77]', 'syscall=sendmsg;ret=5'),
        decision(100, 'wpad.lan', 'deny', 'dns', 13, maple),
        record('etw_dns', 100, 'wpad.lan', 'query'),
        decision(100, 'cdn.example.com', 'audit', 'dns', 14, maple),   # by a broad rule: an exact allow narrows it
        decision(100, '/', 'audit', 'file', 15, maple),                # ... but no rule names the root
        record('etw_dns', 100, 'cdn.example.com', 'query'),
        # Own process by a real handle and its own token: /system/wine/<request> gaps; a statfs: no candidate.
        record('process_handle', 100, '', 'read_process_memory;handle=0x60;win_pid=32;address=0x1000', target_process_id=100),
        record('process_handle', 100, '', 'adjust_token_privileges;handle=0x18;win_pid=32;privs=SeDebugPrivilege(enabled)',
               target_process_id=100),
        record('file_query_volume_information', 100, '/', 'syscall=statfs;ret=0'),
        # Every wineserver request is /system/wine/<request> (rule-only): a pipe's read, a timer Wine serves by its
        # NT name, a hook. Its own thread by pseudo handle: /system/wine/self/.
        record('file_read', 100, '\\??\\Pipe\\DwarfIPCPipe1680', 'read;ws=read;handle=0x448', process_path=wine),
        record('file_create', 100, '\\Sessions\\1\\BaseNamedObjects\\GameTimer', 'create_timer;object=timer',
               process_path=wine),
        record('thread_handle', 100, '', 'get_thread_context;handle=0xfffffffe;win_tid=36;flags=0x10', target_process_id=100),
        # Rule-only, no rule yet: dns, socket creation, named object, arch_prctl; a path query (no policy).
        record('etw_dns', 100, 'login.example.com', 'query'),
        record('file_create', 100, 'socket:[78]', 'socket;family=2;type=3;protocol=1;syscall=socket;ret=6'),
        record('file_create', 100, '\\BaseNamedObjects\\grap', 'create_mutex;object=mutex'),
        record('process_handle', 100, '', 'arch_prctl;option=4114;syscall=arch_prctl;ret=0'),
        record('file_device_control', 100, 'socket:[77]', 'getsockopt;syscall=getsockopt;ret=0'),
        record('file_query_information', 100, 'system:syslog', 'syscall=syslog;ret=0'),
        record('file_query_information', 100, '/etc/os-release', 'syscall=newfstatat;ret=0;args=0xffffff9c,0x1,0x2,0x0'),
        # Not filterable.
        record('process_handle', 100, '', 'signal_received;signal=10;sender_pid=1', target_process_id=1),
        record('process_handle', 100, 'capability:sys_admin', 'capability;cap=21'),
        record('file_query_information', 100, 'system:cpuid', 'insn=cpuid;leaf=0x0;source=sigsegv'),
        record('file_query_information', 100, 'system:set_hook', 'ws=set_hook;hook=WH_KEYBOARD_LL'),
        record('file_query_information', 100, 'system:NtQuerySystemInformation', 'call=x;library=x86_64-unix/ntdll.so'),
        record('file_write', 100, 'socket:[79]', 'syscall=sendmsg;ret=4;service=x11;peer=unix:/tmp/.X11-unix/X0'),
        # A wineserver request's kernel summary is the request's (ws=), not the Linux select's.
        record('file_query_information', 100, 'system:select',
               'repeats_tail;syscall=wineserver:select;aggregate=kernel;ws=select;flags=0x2;repeats_before=5'),
        # msmon's fcntl and flock records are device controls, not ioctls on a device.
        record('file_device_control', 100, '/home/u/.wine/user.reg', 'syscall=fcntl;ret=0;args=0x5,0x6,0x7ffc0000'),
        record('file_device_control', 100, '/dev/sda', 'repeats_tail;syscall=flock;repeats_before=2'),
        record('file_device_control', 100, 'socket:[77]', 'syscall=fcntl;ret=0;args=0x5,0x8,0x64'),
        record('file_device_control', 100, 'socket:[78]', 'syscall=fcntl;ret=0;args=0x5,0x3,0x0'),   # F_GETFL
        record('file_device_control', 100, '/tmp/x.lock', 'syscall=flock;ret=0;args=0x5,0x8'),   # LOCK_UN
        # A native helper's I/O summary is its sampled record's; an inode msmon could not name has no path.
        record('file_query_information', 100, 'system:read',
               'repeats_tail;syscall=read;aggregate=kernel;ino=42;attribution=native_helper;repeats_before=9'),
        record('file_read', 100, 'file:[42]', 'syscall=read;ret=10'),
    ])
    check(gaps(report, maple) == {'login.example.com', '/system/socket/inet/raw/1', '/system/socket/inet/stream/6',
                                  '/system/wine/create_mutex', '/system/arch_prctl/0x1012', '/etc/os-release',
                                  '/system/wine/read_process_memory', '/system/wine/adjust_token_privileges', '/',
                                  '/system/wine/self/get_thread_context', '/system/sockopt', '/system/syslog',
                                  '/system/wine/read', '/system/wine/create_timer', '/system/wine/set_hook',
                                  '/home/u/.wine/user.reg', '/dev/sda', '/system/fcntl/setown', '/system/wine/select'},
          f'linux gaps: {gaps(report, maple)}')
    check(paths(report, maple, 'not_filterable') == {tuning_report.NF_SIGNAL, tuning_report.NF_CONTROL,
                                                     tuning_report.NF_INSN,
                                                     tuning_report.NF_NTDLL, tuning_report.NF_UNIX,
                                                     tuning_report.NF_LOCK, tuning_report.NF_UNNAMED},
          f'linux not filterable: {paths(report, maple, "not_filterable")}')
    blocked = {entry['path']: entry['rights'] for entry in report['programs'][maple]['blocked']}
    check(blocked == {'/system/wmi/win32_bios': 'query', '/proc/@outside/status': 'read', 'wpad.lan': 'query'},
          f'blocked (a dns value is its query type; kfilter decides query): {blocked}')
    check('send tcp 203.0.113.9:443' in paths(report, maple, 'allowed_by_rule'), 'message listed by its peer')
    rules = [item['rule'] for item in report['candidates_tighten']]
    for expected in ('audit|dns|login.example.com|image=MapleStory.exe',
                     'audit|system|/system/socket/inet/raw/1|image=MapleStory.exe',
                     'audit|system|/system/wine/create_mutex|image=MapleStory.exe',
                     'audit|system|/system/arch_prctl/0x1012|image=MapleStory.exe',
                     'audit|system|/system/wine/read_process_memory|image=MapleStory.exe',
                     'allow|dns|cdn.example.com|rights=query|exact|image=MapleStory.exe'):
        check(expected in rules, f'candidate missing: {expected}\n{rules}')
    check(not any(rule.startswith('deny|volume') for rule in rules), f'a statfs candidate: {rules}')
    accepts(rules, 'linux layers')
    check('vdso calls(no syscall) (kernel_events)' in report['not_seen'], f'not seen: {report["not_seen"]}')
    # block-file-queries on: an allowed query leaves no event, so an undecided one is no gap.
    quiet = analyzed([record('coverage', 0, 'kfilter_status', 'abi=9;mode=audit;flags=0x00001001'),
                      decision(100, '/x', 'allow', 'file', 1, maple),
                      record('file_query_information', 100, '/etc/os-release', 'syscall=statx;ret=0;args=0x0,0x1,0x0')])
    check(not gaps(quiet, maple) and any('allowed without an event' in note for note in quiet['notes']),
          f'quiet queries: {quiet["notes"]}')
    with tempfile.TemporaryDirectory() as scratch:
        (pathlib.Path(scratch) / 'client').mkdir()
        (pathlib.Path(scratch) / 'client' / 'cpu-trap.log').write_text(
            'kfshim pid=7 exe=MapleStory.exe bits=64 insn=cpuid leaf=0x80000002 subleaf=0x0 masked=1 first ip=0x1\n'
            'kfshim pid=7 exe=MapleStory.exe bits=64 insn=cpuid leaf=0x80000002 subleaf=0x0 masked=1 count=3\n',
            encoding='utf-8')
        trap = tuning_report.cpu_trap(scratch)
    check(trap == {'cpuid': {'count': 3, 'processes': [maple], 'leaves': [], 'masked': ['0x80000002']}},
          f'cpu trap log: {trap}')

def gaps(report, image):
    return {entry['path'] for entry in report['programs'].get(image, {}).get('no_rule', [])}


def regressions():
    maple = 'C:\\Nexon\\Library\\maplestorycw\\MapleStory.exe'
    device = '\\Device\\HarddiskVolume3\\Nexon\\Library\\maplestorycw\\MapleStory.exe'
    explorer = '\\Device\\HarddiskVolume3\\Windows\\explorer.exe'
    report = analyzed([
        # A second MapleStory.exe kfilter never protected: its read is a gap, not covered by pid 100's deny.
        decision(100, '/etc/hostname', 'deny', 'file', 2, 'MapleStory.exe'),
        record('file_create', 100, '/etc/hostname', 'syscall=openat;ret=-13'),
        record('file_read', 600, '/etc/hostname', 'syscall=read;ret=12', process_path=maple),
        # Linux: a process Wine has not named, seen only by its loader: no image= is guessed.
        record('process_start', 700, '/opt/wine-stable/bin/wine64-preloader', 'exec', parent_process_id=100,
               value0=1),
        record('file_read', 700, '/home/u/.ssh/id_rsa', 'syscall=read;ret=10'),
        # Windows: creations are decided in the creator's context (pid 300, the launcher).
        record('process_start', 300, 'C:\\Nexon Launcher\\nexon_launcher.exe'),
        decision(300, device, 'deny', 'process_create', 0, 'nexon_launcher.exe', rights='0x00000100'),
        record('process_start', 400, device, parent_process_id=300, status=0xC0000022),
        decision(300, device.replace('MapleStory', 'DwarfAxe'), 'allow', 'process_create', 9, 'nexon_launcher.exe',
                 rights='0x00000100'),
        record('process_start', 401, device.replace('MapleStory', 'DwarfAxe'), parent_process_id=300),
        record('process_start', 402, device.replace('MapleStory', 'NGService'), parent_process_id=300),
        record('process_start', 403, '/usr/bin/xdg-open', 'exec_failed;ret=-13', parent_process_id=100),
        # MapleStory opens an outside process: kfilter decides it as 'open', msmon logs a process_handle.
        record('kfilter_decision', 100, explorer, 'target=open;action=deny;decision=would_deny;rule_id=0;'
               'rights=0x001fffff;generation=1'),
        record('process_handle', 100, explorer, 'open'),
    ])
    check(gaps(report, 'MapleStory.exe') == {'/etc/hostname', '/opt/wine-stable/bin/wine64-preloader'},
          f'unprotected copy / loader exec: {gaps(report, "MapleStory.exe")}')
    check(gaps(report, 'pid 700') == {'/home/u/.ssh/id_rsa'} and 'wine64-preloader' not in report['programs'],
          'an unnamed Wine process stays unnamed')
    check(gaps(report, 'nexon_launcher.exe') == {device.replace('MapleStory', 'NGService')},
          f'process starts: refused and decided ones are not gaps: {report["programs"]}')
    would = report['programs']['MapleStory.exe']['would_block']
    check([entry['rights'] for entry in would if entry['layer'] == 'open'] == ['0x001fffff'],
          f'an access mask is not kfilter rights: {would}')
    tighten = [item['rule'] for item in report['candidates_tighten']]
    for expected in ('deny|file|/home/u/.ssh', f'deny|process|{device.replace("MapleStory", "NGService")}'
                     '|image=nexon_launcher.exe'):
        check(expected in tighten, f'candidate missing: {expected}\n{tighten}')
    check(not any('wine64-preloader' in rule and not rule.startswith('#') for rule in tighten),
          f'a Wine loader in a candidate rule: {tighten}')

    # Linux runs (e2e): what kfilter decided under another spelling, or what never went through, is no gap.
    prefix = '/home/u/p'
    report = analyzed([
        decision(800, f'{prefix}/drive_c/windows/Fonts', 'allow', 'file', 4, 'cmd.exe'),
        record('file_create', 800, f'{prefix}/dosdevices/c:/windows/Fonts', 'create_file'),
        decision(800, '/home/u/.cache/fc/x.cache', 'would_deny', 'file', 0, 'cmd.exe'),
        record('file_create', 800, '/home/u/.cache/fc//../fc/x.cache', 'syscall=openat;ret=3'),
        decision(800, '/tmp/t', 'would_deny', 'file', 0, 'cmd.exe'),
        record('file_create', 800, f'{prefix}/dosdevices/z:/tmp/t', 'syscall=openat;ret=3'),
        record('file_create', 800, '/home/u/.cache/fc/missing', 'syscall=openat;ret=-2', status=-2),
        record('file_create', 800, '/home/u/refused', 'syscall=openat;ret=-13', status=-13),
        decision(800, '\\REGISTRY\\MACHINE\\SOFTWARE\\X', 'would_deny', 'registry', 0, 'cmd.exe'),
        record('registry_query', 800, 'hkey:0x18', 'wineserver;query'),
        record('registry_query', 801, 'hkey:0x18', 'wineserver;query', process_path='C:\\reg.exe'),
        record('file_read', 800, 'pipe:[123]', 'syscall=read;ret=64'),
    ])
    check(gaps(report, 'cmd.exe') == {'/home/u/refused'}, f'e2e spellings: {gaps(report, "cmd.exe")}')
    check(gaps(report, 'reg.exe') == {'hkey:0x18'}, 'an unnamed key of an undecided program is a gap')
    check(paths(report, 'cmd.exe', 'not_filterable') == {tuning_report.NF_PIPE}, 'anonymous pipe I/O')
    # An unprotected Wine process (--attach) is named by its exec's command line, the latest exec winning.
    loader = '/opt/wine-stable/lib/wine/i386-unix/wine-preloader'
    report = analyzed([
        record('process_start', 900, loader, 'start.exe /exec cmd.exe /c echo;scope=exec_mapping:/p/x.dll'),
        record('file_read', 900, '/home/u/a', 'syscall=read;ret=1'),
        record('process_start', 901, loader, 'start.exe /exec reg.exe query'),
        record('process_start', 901, loader.replace('i386', 'x86_64'), '/opt/w/x86_64-windows C:\\windows\\system32\\reg.exe q'),
        record('file_read', 901, '/home/u/b', 'syscall=read;ret=1'),
    ])
    check(gaps(report, 'start.exe') == {'/home/u/a'} and gaps(report, 'reg.exe') == {'/home/u/b'},
          f'Wine programs named from the exec: {list(report["programs"])}')

    # Lost decisions are flagged.
    status = 'abi=8;mode=audit;dropped_delta=0;name_failures=0;degraded=0x00000000'
    quiet = analyzed([record('coverage', 0, 'kfilter_status', status)])
    check(not any('lost' in note for note in quiet['notes']), f'false loss note: {quiet["notes"]}')
    for coverage in ([record('coverage', 0, 'kfilter_status', status.replace('dropped_delta=0', 'dropped_delta=7'))],
                     [record('coverage', 0, 'kfilter_status', status + ';session_changed=1')],
                     [record('coverage', 0, 'kfilter_status', status),
                      record('coverage', 0, 'kfilter_unavailable', 'decision read failed')]):
        notes = analyzed(coverage)['notes']
        check(any('decisions were lost' in note for note in notes), f'loss not flagged: {notes}')

    # Every rotation part is read, not only the first 20.
    with tempfile.TemporaryDirectory() as scratch:
        base = pathlib.Path(scratch) / 'events.jsonl'
        for name in [base.name] + [f'{base.name}.{index}' for index in range(1, 26)]:
            (base.parent / name).write_text('', encoding='utf-8')
        check(len(tuning_report.expand_parts(str(base))) == 26, 'rotation parts after .20 dropped')


def policies(kfilterctl):
    sys.path.insert(0, str(ROOT))
    import monfilter
    for name in ('default-policy.txt', 'contain-policy.txt', 'strict-policy.txt'):
        text = (ROOT / 'filter' / 'policy' / name).read_text(encoding='utf-8')
        for program in monfilter.FAMILY:
            check(f'protect \\{program}\n' in text, f'{name} does not protect {program}')
    if kfilterctl is None:
        return
    with tempfile.TemporaryDirectory() as scratch:
        def evaluate(policy, target, path):
            result = subprocess.run([str(kfilterctl), 'evaluate', str(policy), target, path,
                                     'create' if target == 'process' else 'read'], capture_output=True, text=True)
            check(result.returncode == 0, f'evaluate {policy}: {result.stderr}')
            return result.stdout.split()[0]

        linux = pathlib.Path(scratch) / 'linux.txt'
        linux.write_text(monfilter.prepare_policy(ROOT / 'filter' / 'policy' / 'linux-default-policy.txt', 'block',
                                                  '/home/u', '/home/u/.wine-nexon', '', False), encoding='utf-8')
        for tool in ('/opt/wine-stable/lib/wine/x86_64-windows/wmic.exe', '/usr/lib/wine/x86_64-windows/getmac.exe',
                     '/usr/lib/x86_64-linux-gnu/wine/i386-windows/systeminfo.exe',
                     '/usr/lib64/wine/x86_64-windows/whoami.exe'):
            check(evaluate(linux, 'file', tool) == 'deny', f'linux policy lets the client run {tool}')
        check(evaluate(linux, 'file', '/usr/lib/wine/x86_64-windows/kernel32.dll') == 'allow', 'Wine DLLs denied')
        # Windows policies: evaluate runs on Linux, without the drive-path root and image= (it has no requester).
        child = '\\Device\\HarddiskVolume3\\Program Files (x86)\\Nexon\\Nexon Launcher\\bin\\nexon_client\\nexon_client.exe'
        for name in ('contain-policy.txt', 'strict-policy.txt'):
            text = (ROOT / 'filter' / 'policy' / name).read_text(encoding='utf-8')
            windows = pathlib.Path(scratch) / name
            windows.write_text(re.sub(r'(?m)^root .*\n', '', text.replace('|image=nexon_*', '')).replace(
                'mode audit', 'mode block'), encoding='utf-8')
            check(evaluate(windows, 'process', child) == 'allow', f'{name}: the launcher cannot start {child}')
            check(evaluate(windows, 'process', '\\Device\\HarddiskVolume3\\Windows\\System32\\cmd.exe') == 'deny',
                  f'{name}: process creation outside the family is allowed')


if __name__ == '__main__':
    main()
