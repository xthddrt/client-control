#!/usr/bin/env python3
"""Build a candidate kfilter policy from an msmon (monitor/) JSONL capture.

The one implementation (tools/Build-Policy.ps1 wraps it on Windows). Reads a monitor log,
aggregates what the selected process(es) touched, and writes:
  - a markdown report of file and registry prefixes, split into the
    application's own tree, the OS loader/runtime, its publisher, and
    everything else;
  - a policy file with allow rules for the application's own tree and loader
    paths, deny rules for the other-prefix list, and a data-only catch-all.

NT captures (\\Device\\HarddiskVolume3\\..., \\REGISTRY\\...) produce NT rules;
Linux captures (/home/u/..., /usr/lib/...) produce '/' rules.

The generated policy is a starting point: review the report, then merge the
interesting lines into policy/default-policy.txt. Rules are first-match, so
keep the allow lines above the deny lines they should override.

Example:
  tools/kfilter_policy.py --log session.jsonl --pid 5540 \\
      --client-root /home/u/.wine/drive_c/Nexon/Library/maplestorycw \\
      --out generated-policy.txt --report generated-report.md
"""
import argparse
import json
import os
import re
import sys

FULL = 'rights=read,write,execute,delete,rename,set-security'
# Linux equivalents of the Windows loader trees; '*' also covers lib32/lib64 and wine-staging/devel.
LINUX_LOADER = ('/usr/lib', '/lib', '/opt/wine')

NT_BUCKETS = [re.compile(p, re.I) for p in (
    r'^(\\Device\\HarddiskVolume\d+\\Users\\[^\\]+\\AppData\\(?:Local|LocalLow|Roaming)(?:\\Programs)?\\[^\\]+)',
    r'^(\\Device\\HarddiskVolume\d+\\Users\\[^\\]+\\AppData\\(?:Local|LocalLow|Roaming)\\[^\\]+\\[^\\]+)',
    r'^(\\Device\\HarddiskVolume\d+\\Program Files(?: \(x86\))?\\[^\\]+)',
    r'^(\\Device\\HarddiskVolume\d+\\ProgramData\\[^\\]+)',
    r'^(\\Device\\HarddiskVolume\d+\\Windows\\System32\\[^\\]+)',
)]


def prefix_of(path, depth, client_root):
    if not path:
        return ''
    if path.startswith('/'):
        # Wine prefixes put the client tree deeper than `depth`; bucket it whole so it classifies as own.
        if client_root.startswith('/') and (path == client_root or path.startswith(client_root + '/')):
            return client_root
        return '/' + '/'.join(path.lstrip('/').split('/')[:depth])
    # Vendor-level buckets for the noisy roots, so a deny rule covers one
    # application instead of the whole AppData tree.
    for bucket in NT_BUCKETS:
        match = bucket.match(path)
        if match:
            return match.group(1)
    return '\\' + '\\'.join(path.lstrip('\\').split('\\')[:depth])


def classify(prefix, client_root):
    if prefix.startswith('/'):
        if client_root and prefix.startswith(client_root):
            return 'own'
        if re.search(r'/Nexon($|/)', prefix):
            return 'publisher'
        if prefix.startswith(LINUX_LOADER):
            return 'windows'
        return 'other'
    if client_root and prefix.lower().startswith(client_root.lower()):
        return 'own'
    if re.search(r'\\Nexon($|\\)', prefix, re.I):
        return 'publisher'
    if re.search(r'^(\\[^\\]+)?\\Windows', prefix, re.I):
        return 'windows'
    return 'other'


def records(path):
    with open(path, encoding='utf-8-sig', errors='replace') as handle:
        for line in handle:
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if isinstance(record, dict) and 'type' in record and 'process_id' in record and 'text' in record:
                yield record


def build(args):
    if not args.log or not os.path.exists(args.log):
        sys.exit(f'log not found: {args.log}')
    pids = args.pid or []
    wanted = bool(pids)
    root = args.client_root
    file_counts, registry_counts, image_names, pid_counts = {}, {}, {}, {}
    total = 0

    for record in records(args.log):
        pid = int(record['process_id'])
        kind = str(record['type'])
        text = record['text'] or ''
        if kind == 'process_start':
            pid_counts[pid] = pid_counts.get(pid, 0) + 1
            if (not wanted or pid in pids) and text:
                image_names[pid] = text
            continue
        if wanted and pid not in pids:
            continue
        if kind.startswith('file_') or kind.startswith('registry_'):
            prefix = prefix_of(text, 5, root)
            if prefix:
                counts = file_counts if kind.startswith('file_') else registry_counts
                counts[prefix] = counts.get(prefix, 0) + 1
        total += 1

    if not wanted:
        top = max(pid_counts, key=pid_counts.get) if pid_counts else 0
        print(f'No --pid given; using the process with the most events (PID {top}).')
        pids = [top]

    linux = root.startswith('/') if root else any(
        p.startswith('/') for p in list(file_counts) + list(image_names.values()))
    sep = '/' if linux else '\\'

    by_class = {'own': [], 'publisher': [], 'windows': [], 'other': []}
    for prefix, count in file_counts.items():
        by_class[classify(prefix, root)].append((prefix, count))
    for entries in by_class.values():
        entries.sort(key=lambda entry: entry[1], reverse=True)
    registry_list = sorted(registry_counts.items(), key=lambda entry: entry[1], reverse=True)

    protect = []
    for pid in pids:
        if pid in image_names:
            image = image_names[pid]
            image_sep = '/' if image.startswith('/') else '\\'
            leaf = image_sep + image.rsplit(image_sep, 1)[-1]
            if leaf not in protect:
                protect.append(leaf)
    if not protect:
        protect = [sep + 'unknown.exe']

    own_total = sum(count for _, count in by_class['own'])
    other_total = sum(count for _, count in by_class['other'])

    report = ['# Capture-derived access report', '', f'Log: `{args.log}`', '',
              f'Processes: {", ".join(str(p) for p in pids)}', '',
              f'Events considered: {total}',
              f"File events in the application's own tree: {own_total}",
              f'File events outside it: {other_total}', '']
    sections = (('Other paths (candidates for deny)', by_class['other'], 40),
                ('Publisher paths', by_class['publisher'], 20),
                ('Loader/runtime paths' if linux else 'Windows paths', by_class['windows'], 25),
                ('Registry prefixes', registry_list, 30))
    for title, entries, limit in sections:
        report += [f'## {title}', '']
        report += [f'- {count}: {prefix}' for prefix, count in entries[:limit]]
        report.append('')
    report.append('Review before blocking: a deny rule that covers a path the application needs will break it.')
    with open(args.report, 'w', encoding='utf-8') as handle:
        handle.write('\n'.join(report) + '\n')

    policy = ['# Generated by tools/kfilter_policy.py from a monitor capture.',
              f'# Log: {args.log}',
              '# Review docs/POLICY.md and merge into policy/default-policy.txt.',
              '', 'mode audit', '']
    policy += [f'protect {name}' for name in protect]
    policy += ['', 'block-files on', 'block-registry on', 'block-volume-serial on', 'block-process-memory on', '']
    if linux:
        policy.append('# Allow: own tree, loader/runtime, temp.')
        if root:
            policy.append(f'allow|file|{root}|{FULL}|risk=anti-cheat-surface')
        policy += [f'allow|file|{path}*|{FULL}' for path in LINUX_LOADER]
        policy.append(f'allow|file|/tmp|{FULL}')
    else:
        policy.append('# Allow: own tree, publisher, Windows loader, temp.')
        if root:
            policy.append(f'allow|file|{root}|{FULL}|risk=anti-cheat-surface')
        policy += [
            f'allow|file|\\Device\\HarddiskVolume*\\Nexon|{FULL}|risk=anti-cheat-surface',
            f'allow|file|\\Device\\HarddiskVolume*\\Users\\*\\AppData\\Local\\Nexon|{FULL}',
            f'allow|file|\\Device\\HarddiskVolume*\\Users\\*\\AppData\\Roaming\\Nexon|{FULL}',
            f'allow|file|\\Device\\HarddiskVolume*\\Windows\\System32|{FULL}|ext=dll,other|risk=windows-dll-surface',
            f'allow|file|\\Device\\HarddiskVolume*\\Windows\\WinSxS|{FULL}',
            f'allow|file|\\Device\\HarddiskVolume*\\Windows\\Microsoft.NET|{FULL}',
            f'allow|file|\\Device\\HarddiskVolume*\\Users\\*\\AppData\\Local\\Temp|{FULL}',
            '', '# Allow: registry the client needs.',
            'allow|registry|\\REGISTRY\\USER\\*\\Software\\Wizet|rights=read,write,delete,rename,set-security,enumerate',
            'allow|registry|\\REGISTRY\\MACHINE\\SOFTWARE\\Wizet|rights=read,write,delete,rename,set-security,enumerate',
            'allow|registry|\\REGISTRY\\USER\\*\\Software\\Nexon|rights=read,write,delete,rename,set-security,enumerate',
            'allow|registry|\\REGISTRY\\MACHINE\\SOFTWARE\\Nexon|rights=read,write,delete,rename,set-security,enumerate',
        ]
    policy += ['', '# Deny: other applications observed in the capture.']
    file_rules = by_class['other'][:args.max_file_rules]
    policy += [f'deny|file|{prefix}|ext=exe,dll,sys,ocx|data-only' for prefix, _ in file_rules]
    policy += ['', '# Deny: registry identity prefixes observed in the capture.']
    registry_rules = 0
    for prefix, _ in registry_list:
        if registry_rules >= args.max_registry_rules:
            break
        if (re.search(r'\\Software\\(Wizet|Nexon)', prefix, re.I)
                or re.search(r'\\CurrentControlSet\\Services\\(WinSock2|Dnscache)', prefix, re.I)
                or re.search(r'\\Windows NT\\CurrentVersion', prefix, re.I)):
            continue
        policy.append(f'deny|registry|{prefix}')
        registry_rules += 1
    policy += ['', '# Catch-all: any other PE data read outside the allow list.',
               'deny|file|/*|ext=exe,dll,sys,ocx|data-only' if linux
               else 'deny|file|\\Device\\HarddiskVolume*|ext=exe,dll,sys,ocx|data-only']
    with open(args.out, 'w', encoding='utf-8') as handle:
        handle.write('\n'.join(policy) + '\n')

    print(f'Wrote {args.report} and {args.out}')
    print(f'File rules: {len(file_rules)}, registry rules: {registry_rules} '
          f'(limits {args.max_file_rules}/{args.max_registry_rules}).')
    if len(file_rules) + registry_rules > 50:
        print('WARNING: The generated policy is large; the driver accepts at most 64 rules.', file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--log', default='')
    parser.add_argument('--pid', '--process-id', type=int, action='append', help='repeatable')
    parser.add_argument('--client-root', default='')
    parser.add_argument('--out', default='generated-policy.txt')
    parser.add_argument('--report', default='generated-report.md')
    parser.add_argument('--max-file-rules', type=int, default=24)
    parser.add_argument('--max-registry-rules', type=int, default=12)
    args = parser.parse_args()
    build(args)


if __name__ == '__main__':
    main()
