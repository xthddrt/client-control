#!/usr/bin/env python3
"""Identify every outside program reached by the client family, across one or
more monitor captures.

The one implementation (tools/Analyze-Reachability.ps1 wraps it on Windows). Builds the
client family from process-start records (client root, known image names),
then aggregates, per outside program:

  - Executed: process_start where the parent is in the family.
  - Loaded:   image_load in a family process outside the client tree.
  - File:     file_* events whose target belongs to another program.
  - Pipe:     named-pipe paths.

For each target it also reports whether the current kfilter policy covers it
and, if not, emits a candidate rule. Sessions with rotation parts
(name.jsonl, name.jsonl.1, ...) are read in order. Both NT and Linux ('/')
capture paths are understood.

Example:
  tools/analyze_reachability.py --log "00-baseline.jsonl;01-manual.jsonl" \\
      --policy policy/default-policy.txt --out reachability.md --out-policy rules.txt
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys

NT_CLIENT = re.compile(r'^(\\Device\\HarddiskVolume\d+\\Nexon\\Library\\maplestorycw)', re.I)
# Under Wine the client tree sits inside a prefix (…/drive_c/Nexon/…); the volume part is unknowable.
LINUX_CLIENT = re.compile(r'^(/(?:[^/]+/)*?Nexon/Library/maplestorycw)')
KNOWN_NAMES = ('MapleStory.exe', 'grap-core64.aes', 'grap-updater.aes', 'NGService.exe',
               'DwarfAxe.exe', 'CrashReportClient.exe', 'grap-communicator64.aes',
               'nexon_launcher.exe', 'nexon_client.exe', 'nexon_agent.exe', 'nexon_runtime.exe')
# Linux equivalents of \Windows\: loader and runtime trees (prefix match also covers lib32/lib64, wine-*).
LINUX_RUNTIME = ('/usr/lib', '/lib', '/opt/wine')
HIDDEN_KINDS = ('Client', 'WindowsComponent', 'Runtime', 'Unknown')

NT_OWNERS = [(re.compile(pattern, re.I), kind, owner, root) for pattern, kind, owner, root in (
    (r'^(\\Device\\HarddiskVolume\d+\\Windows\\System32\\drivers)\\([^\\]+)$', 'Driver', 2, '{1}'),
    (r'^(\\Device\\HarddiskVolume\d+\\Windows(?:\\[^\\]+)*)\\([^\\]+\.exe)$', 'WindowsProgram', 2, '{1}'),
    (r'^(\\Device\\HarddiskVolume\d+\\Windows\\)', 'WindowsComponent', 'Windows', '{1}'),
    # WindowsApps keeps the bare root when no package name follows.
    (r'^(\\Device\\HarddiskVolume\d+\\Program Files\\WindowsApps)\\?([^\\]*)', 'Program', 2,
     lambda g: g[1] + ('\\' + g[2] if g[2] else '')),
    (r'^(\\Device\\HarddiskVolume\d+\\Program Files(?: \(x86\))?\\Common Files)\\([^\\]+)', 'Shared', 2, '{1}\\{2}'),
    (r'^(\\Device\\HarddiskVolume\d+\\Program Files(?: \(x86\))?)\\([^\\]+)', 'Program', 2, '{1}\\{2}'),
    (r'^(\\Device\\HarddiskVolume\d+\\ProgramData)\\([^\\]+)', 'Program', 2, '{1}\\{2}'),
    (r'^(\\Device\\HarddiskVolume\d+\\Users\\[^\\]+\\AppData\\(?:Local|LocalLow|Roaming)\\Programs)\\([^\\]+)', 'Program', 2, '{1}\\{2}'),
    (r'^(\\Device\\HarddiskVolume\d+\\Users\\[^\\]+\\AppData\\(?:Local|LocalLow|Roaming))\\([^\\]+)', 'AppData', 2, '{1}\\{2}'),
    (r'^(\\Device\\HarddiskVolume\d+\\Users\\[^\\]+)', 'UserData', 'user profile', '{1}'),
    (r'^(\\Device\\NamedPipe)', 'Pipe', 'named pipes', '{1}'),
)]
LINUX_OWNERS = [(re.compile(pattern), kind, owner, root) for pattern, kind, owner, root in (
    (r'^(/(?:usr/)?s?bin)/([^/]+)$', 'SystemProgram', 2, '{1}'),
    (r'^(/opt)/([^/]+)', 'Program', 2, '{1}/{2}'),
    (r'^(/home/[^/]+/\.(?:local/share|config|cache))/([^/]+)', 'AppData', 2, '{1}/{2}'),
    (r'^(/home/[^/]+)', 'UserData', 'user profile', '{1}'),
)]


def is_linux(path):
    return path.startswith('/')


def in_client(path):
    return bool((LINUX_CLIENT if is_linux(path) else NT_CLIENT).match(path))


def leaf(path):
    return path.rsplit('/' if is_linux(path) else '\\', 1)[-1]


def known(image):
    name = leaf(image)
    return name in KNOWN_NAMES if is_linux(image) else name.lower() in [n.lower() for n in KNOWN_NAMES]


def is_runtime(path):
    if is_linux(path):
        return path.startswith(LINUX_RUNTIME)
    return bool(re.match(r'^(\\Device\\HarddiskVolume\d+\\Windows\\|\\SystemRoot\\)', path, re.I))


def expand_parts(base):
    result = [base] if os.path.exists(base) else []
    index = 0
    while True:   # msmon-agent rotates without a part limit
        index += 1
        candidate = f'{base}.{index}'
        if not os.path.exists(candidate):
            break
        result.append(candidate)
    return result


def get_owner(path):
    """Return (kind, owner, root)."""
    if not path:
        return 'Unknown', '(no path)', ''
    match = (LINUX_CLIENT if is_linux(path) else NT_CLIENT).match(path)
    if match:
        return 'Client', 'client', match.group(1)
    if is_linux(path) and is_runtime(path):
        return 'Runtime', 'runtime', ''
    for pattern, kind, owner, root in (LINUX_OWNERS if is_linux(path) else NT_OWNERS):
        match = pattern.match(path)
        if match:
            groups = ('',) + match.groups()
            return (kind, groups[owner] if isinstance(owner, int) else owner,
                    root(groups) if callable(root) else root.format(*groups))
    return 'Other', 'other', ''


def usable_root(root):
    if not root:
        return False
    if is_linux(root):
        return root.strip('/').count('/') >= 1  # not '/', '/home', '/opt' ...
    if re.match(r'^\\Device\\HarddiskVolume\d+$', root, re.I):
        return False
    if re.match(r'^\\Device\\HarddiskVolume\d+\\(ProgramData|Users)$', root, re.I):
        return False
    return True


def sanitize(text):
    text = re.sub(r'(?i)(\\Users\\)[^\\|]+', r'\1<user>', text)
    return re.sub(r'(/home/)[^/|]+', r'\1<user>', text)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--log', required=True, help="captures separated by ';'")
    parser.add_argument('--policy', default='')
    parser.add_argument('--out', default='reachability-report.md')
    parser.add_argument('--out-policy', default='')
    parser.add_argument('--top', type=int, default=15)
    args = parser.parse_args()

    log_paths = [part.strip() for part in args.log.split(';') if part.strip()]
    if not log_paths:
        sys.exit('no logs given')

    kfilterctl = None
    if args.policy and os.path.exists(args.policy):
        build = ('build', 'Release', 'tool', 'kfilterctl.exe') if os.name == 'nt' else ('build', 'linux', 'kfilterctl')
        kfilterctl = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', *build)
        if not os.path.exists(kfilterctl):
            kfilterctl = shutil.which('kfilterctl')
            if not kfilterctl:
                sys.exit(f'kfilterctl not found ({os.path.join(*build)} or PATH)')

    def verdict(path, target, rights='read'):
        if not kfilterctl:
            return 'no policy'
        if target == 'process':
            rights = 'create'
        result = subprocess.run([kfilterctl, 'evaluate', args.policy, target, path, rights],
                                capture_output=True, text=True)
        if result.returncode != 0:
            sys.exit(f'kfilterctl evaluate failed for {path}')
        fields = result.stdout.split()
        decision = fields[0] if fields else ''
        match = re.match(r'^rule=(\d+)$', fields[1]) if len(fields) > 1 else None
        rule_id = int(match.group(1)) if match else 0
        if decision == 'deny':
            return 'covered'
        if decision == 'would-deny':
            return 'covered' if rule_id > 0 else 'uncovered'
        if decision == 'audit':
            return 'audit-only'
        return 'allowed' if rule_id > 0 else 'uncovered'

    # ------------------------------------------------------------------ replay
    sessions = []
    proc_starts = {}   # pid -> {'parent', 'image', 'count'}
    module_loads = {}  # pid -> {module: count}
    file_reach = {}    # (pid, kind, owner, root) -> dict
    owner_cache = {}

    for base in log_paths:
        parts = expand_parts(base)
        if not parts:
            print(f'WARNING: not found: {base}', file=sys.stderr)
            continue
        records = gaps = 0
        dropped = None
        coverage = set()
        for part in parts:
            tail = ''
            with open(part, encoding='utf-8-sig', errors='replace') as handle:
                for line in handle:
                    if line.strip():
                        tail = line
                    try:
                        record = json.loads(line)
                    except ValueError:
                        continue
                    if not isinstance(record, dict):
                        continue
                    kind = str(record.get('type', ''))
                    if kind == 'observer_sequence_gap':
                        gaps += 1
                    if 'type' not in record or 'process_id' not in record or 'text' not in record:
                        continue
                    records += 1
                    pid = int(record['process_id'])
                    text = record['text'] or ''
                    if kind == 'coverage':
                        if text:
                            coverage.add(text)
                        continue
                    if kind == 'process_start':
                        entry = proc_starts.setdefault(pid, {'pid': pid, 'parent': int(record.get('parent_process_id', 0)),
                                                             'image': text, 'count': 0})
                        entry['count'] += 1
                        continue
                    if kind == 'image_load':
                        if text:
                            loads = module_loads.setdefault(pid, {})
                            loads[text] = loads.get(text, 0) + 1
                        continue
                    if not kind.startswith('file_') or not text:
                        continue
                    if text not in owner_cache:
                        owner_cache[text] = get_owner(text)
                    owner = owner_cache[text]
                    if owner[0] in HIDDEN_KINDS:
                        continue
                    entry = file_reach.setdefault((pid,) + owner, {'events': 0, 'bytes': 0, 'paths': {}, 'example': text})
                    entry['events'] += 1
                    if kind == 'file_read':
                        entry['bytes'] += int(record.get('value0', 0))
                    entry['paths'][text] = entry['paths'].get(text, 0) + 1
            # summary is written by the agent as the very last record of the session
            try:
                summary = json.loads(tail)
            except ValueError:
                summary = None
            if isinstance(summary, dict) and summary.get('type') == 'observer_summary':
                dropped = summary.get('driver_dropped_events')
        sessions.append({
            'name': os.path.basename(base), 'parts': len(parts), 'records': records,
            'dropped': '' if dropped is None else dropped, 'gaps': gaps,
            'object': 'unavailable' if 'object_callbacks_unavailable' in coverage else 'active',
            'network': 'unavailable' if 'network_callbacks_unavailable' in coverage
                       else 'partial' if 'network_callbacks_partial' in coverage else 'active',
            'blackcat': 'loaded' if 'blackcat_loaded' in coverage else 'not loaded'})

    # --------------------------------------------------------------- family & report
    # The PS version also loops "children inherit if client-tree"; every client-tree image is already
    # admitted here, so that loop never adds anything and is not ported.
    family = {entry['pid'] for entry in proc_starts.values() if in_client(entry['image']) or known(entry['image'])}

    lines, policy_lines = [], []
    lines += ['# Outside-program reachability', '',
              f'Captures: {len(log_paths)}   Client family processes: {len(family)}']
    lines += [f'- {pid} {proc_starts[pid]["image"] if pid in proc_starts else f"pid {pid}"}' for pid in sorted(family)]
    lines += ['', '## Sessions', '',
              '| capture | parts | records | dropped | gap records | object callbacks | network | BlackCat |',
              '|---|---|---|---|---|---|---|---|']
    lines += [f'| {s["name"]} | {s["parts"]} | {s["records"]} | {s["dropped"]} | {s["gaps"]} | {s["object"]} '
              f'| {s["network"]} | {s["blackcat"]} |' for s in sessions]
    lines += ['',
              'Object callbacks were unavailable in every capture, so process/thread handle opens are not',
              'observed. Network callbacks were unavailable, so WFP connect/accept events are absent.',
              'Dropped counts come from each session summary; the captures are incomplete by that amount.',
              '']

    lines += ['## Executed by the client (process creation)', '',
              '| image | launches | parent pids | policy |', '|---|---|---|---|']
    executed = [e for e in proc_starts.values() if e['parent'] in family and e['pid'] not in family]
    for entry in sorted(executed, key=lambda e: e['count'], reverse=True):
        result = verdict(entry['image'], 'process')
        lines.append(f'| {entry["image"]} | {entry["count"]} | {entry["parent"]} | {result} |')
        if result in ('uncovered', 'audit-only') and usable_root(entry['image']):
            policy_lines.append(f'deny|process|{entry["image"]}')
    lines.append('')

    lines += ['## Loaded into a client process (image_load)', '', '| module | loads | policy |', '|---|---|---|']
    modules = {}
    for pid in family:
        for module, count in module_loads.get(pid, {}).items():
            if in_client(module) or is_runtime(module):
                continue
            modules[module] = modules.get(module, 0) + count
    for module in sorted(modules, key=modules.get, reverse=True)[:args.top]:
        result = verdict(module, 'file', 'execute')
        lines.append(f'| {module} | {modules[module]} | {result} |')
        if result in ('uncovered', 'audit-only') and usable_root(module):
            # The event being covered is an execute-only image open; a data-only deny
            # (read+write) would not intersect it and would not stop the load.
            policy_lines.append(f'deny|file|{module}|rights=execute')
    lines.append('')

    lines += ['## File reaches by outside program', '',
              '| kind | program | events | MB read | distinct paths | policy | example |',
              '|---|---|---|---|---|---|---|']
    grouped = {}
    for (pid, kind, owner, root), entry in file_reach.items():
        if pid not in family:
            continue
        group = grouped.setdefault((kind, owner, root), {'events': 0, 'bytes': 0, 'paths': set(),
                                                          'example': entry['example']})
        group['events'] += entry['events']
        group['bytes'] += entry['bytes']
        group['paths'].update(entry['paths'])
    for (kind, owner, root), group in sorted(grouped.items(), key=lambda item: item[1]['events'], reverse=True)[:args.top]:
        result = verdict(group['example'], 'file')
        lines.append(f'| {kind} | {owner} | {group["events"]} | {group["bytes"] / 1048576:,.1f} | {len(group["paths"])} '
                     f'| {result} | {group["example"]} |')
        if result in ('uncovered', 'audit-only') and usable_root(root):
            policy_lines.append(f'deny|file|{root}|data-only')
    lines.append('')

    lines += ['## Reaches by client process', '', '| client process | kind | outside target | events |', '|---|---|---|---|']
    by_process = {}
    for (pid, kind, owner, _), entry in file_reach.items():
        if pid not in family:
            continue
        image = leaf(proc_starts[pid]['image']) if pid in proc_starts else f'pid {pid}'
        by_process[(image, kind, owner)] = by_process.get((image, kind, owner), 0) + entry['events']
    for entry in executed:
        if entry['parent'] not in proc_starts:
            continue
        key = (leaf(proc_starts[entry['parent']]['image']), 'Executed', leaf(entry['image']))
        by_process[key] = by_process.get(key, 0) + entry['count']
    for key in sorted(by_process, key=by_process.get, reverse=True)[:30]:
        lines.append(f'| {key[0]} | {key[1]} | {key[2]} | {by_process[key]} |')
    lines.append('')

    unique_rules = list(dict.fromkeys(policy_lines))
    lines += ['## Candidate rules for uncovered targets', '']
    lines += unique_rules or ['(none)']
    lines.append('')

    with open(args.out, 'w', encoding='utf-8') as handle:
        handle.write('\n'.join(sanitize(line) for line in lines) + '\n')
    print(f'Wrote {args.out}')
    if args.out_policy:
        # Written even when empty, so callers can rely on the file existing.
        with open(args.out_policy, 'w', encoding='utf-8') as handle:
            handle.write(''.join(sanitize(line) + '\n' for line in unique_rules))
        print(f'Wrote {args.out_policy}')


if __name__ == '__main__':
    main()
