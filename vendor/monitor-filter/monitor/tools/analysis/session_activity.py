#!/usr/bin/env python3
"""Summarise what each tracked process did outside itself, into a JSON report; --show prints one process."""

import argparse
import collections
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from common import dos_path, iter_events, path_prefix, process_rights, registry_key, short_image  # noqa: E402

IOCTL = {
    0x2D1400: "IOCTL_STORAGE_QUERY_PROPERTY (disk model/serial)",
    0x2D1080: "IOCTL_STORAGE_GET_DEVICE_NUMBER",
    0x560000: "IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS",
    0x70000: "IOCTL_DISK_GET_DRIVE_GEOMETRY",
    0x700A0: "IOCTL_DISK_GET_DRIVE_GEOMETRY_EX",
    0x74080: "SMART_GET_VERSION",
    0x7C088: "SMART_RCV_DRIVE_DATA (disk identify/serial)",
    0x4D0008: "IOCTL_MOUNTDEV_QUERY_DEVICE_NAME",
    0x4D008: "IOCTL_SCSI_MINIPORT",
    0x41018: "IOCTL_SCSI_GET_ADDRESS",
}

BUCKETS = [
    ("client folder (maplestorycw)", r"^c:\\nexon\\library\\maplestorycw"),
    ("Nexon ProgramData (NGS/BlackCat)", r"^c:\\programdata\\nexon"),
    ("Nexon launcher folder", r"^c:\\program files \(x86\)\\nexon"),
    ("your Temp folder", r"^c:\\users\\<you>\\appdata\\local\\temp"),
    ("your AppData\\Local", r"^c:\\users\\<you>\\appdata\\local"),
    ("your AppData\\Roaming", r"^c:\\users\\<you>\\appdata\\roaming"),
    ("your AppData\\LocalLow", r"^c:\\users\\<you>\\appdata\\locallow"),
    ("your user profile (other)", r"^c:\\users\\<you>"),
    ("Windows Prefetch", r"^c:\\windows\\prefetch"),
    ("Windows system files", r"^c:\\windows"),
    ("ProgramData (other)", r"^c:\\programdata"),
    ("Program Files (other)", r"^c:\\program files"),
    ("named pipes", r"^\\device\\namedpipe"),
    ("mailslots", r"^\\device\\mailslot"),
    ("volumes / disks", r"^\\device\\harddiskvolume\d+\\?$|^\\device\\harddisk|^\\device\\physicaldrive|^c:\\?$"),
    ("other devices", r"^\\device\\"),
    # Linux agent paths (absolute, /home/<user> already replaced by dos_path).
    ("your home folder", r"^/home/<you>/"),
    ("temporary files (/tmp, /var/tmp)", r"^/(var/)?tmp/"),
    ("hardware identity files", r"^/sys/(class/dmi/id|devices/virtual/dmi/id)/|^/proc/cpuinfo$|^/etc/machine-id$|"
                                r"^/var/lib/dbus/machine-id$|^/sys/.*/serial$"),
    ("/proc (process and kernel state)", r"^/proc/"),
    ("/sys (devices and kernel)", r"^/sys/"),
    ("/dev (devices)", r"^/dev/"),
    ("/etc (system configuration)", r"^/etc/"),
    ("system files (/usr, /lib, /opt)", r"^/(usr|lib|lib64|bin|sbin|opt)/"),
    ("/run and /var", r"^/(run|var)/"),
]

IDENTITY = re.compile(r"Cryptography|MachineGuid|ComputerName|HARDWARE\\DESCRIPTION|SystemInformation|BIOS|"
                      r"Enum\\(PCI|USB|SCSI|STORAGE|IDE|DISPLAY|HID)|MountedDevices|NetworkCards|"
                      r"Tcpip\\Parameters\\Interfaces|ProductId|InstallDate|DigitalProductId|NetworkList|Disk\\Enum",
                      re.I)


def bucket(path):
    lowered = dos_path(path).lower()
    for name, pattern in BUCKETS:
        if re.search(pattern, lowered):
            return name
    return "other: " + lowered[:40]


class Process:
    def __init__(self):
        self.image = "?"
        self.parent = None
        self.start = self.end = None
        self.flags = []
        self.switches = []
        self.sections = collections.defaultdict(collections.Counter)
        self.file_buckets = collections.defaultdict(collections.Counter)


def incarnation_spans(session_dir):
    """Log timestamps of every incarnation a process_start/exit record proves."""
    spans = collections.defaultdict(list)
    for event in iter_events(session_dir):
        kind = event.get("type")
        pid = event.get("process_id") or 0
        start = event.get("process_start_time") or 0
        stamp = event.get("timestamp") or ""
        if start == 0:
            if kind == "process_exit":
                ended = incarnation_at(spans, pid, stamp)
                if ended is not None:
                    for span in spans[pid]:
                        if span[0] == ended and span[2] is None:
                            span[2] = stamp
                            break
            continue
        if kind == "process_start":
            spans[pid].append([start, stamp, None])
        elif kind == "process_exit":
            for span in spans[pid]:
                if span[0] == start:
                    span[2] = stamp
                    break
    return spans


def incarnation_at(spans, pid, stamp):
    """The incarnation alive at stamp, never a later one; None if none was."""
    best = None
    for start, begin, end in spans.get(pid, ()):
        if begin and stamp and begin <= stamp and (end is None or stamp <= end):
            if best is None or start > best:
                best = start
    return best


def collect(session_dir):
    # One row per incarnation: a reused PID is a different process. A producer
    # that omits the start (kfilter_decision) belongs to the incarnation that was
    # alive at the event's own timestamp; it is never charged to a newer process.
    spans = incarnation_spans(session_dir)
    processes = collections.defaultdict(Process)
    for event in iter_events(session_dir):
        kind = event.get("type")
        if kind in (None, "coverage", "coverage_usage", "observer_summary", "observer_sequence_gap", "etw_unattributed"):
            continue
        pid = event.get("process_id") or 0
        start = event.get("process_start_time") or 0
        if start == 0:
            start = incarnation_at(spans, pid, event.get("timestamp") or "") or 0
        process = processes[(pid, start)]
        if event.get("process_path") and process.image == "?":
            process.image = short_image(event["process_path"])
        sections = process.sections
        sections["types"][kind] += 1
        text = event.get("text") or ""
        detail = event.get("detail") or ""
        if event.get("component"):
            sections["blackcat"][(kind, short_image(text) if kind.endswith("handle") else dos_path(text)[:90])] += 1
        if event.get("category") == "hardware_identity":
            sections["hardware"][f"{kind} {dos_path(text)[:80]} {detail[:60]}".strip()] += 1

        if kind == "process_start":
            process.image = short_image(text)
            process.parent = event.get("parent_process_id")
            process.start = event.get("timestamp")
            process.flags = event.get("flags_names") or []
            process.switches = sorted(set(re.findall(r"(?:^|\s)(-{1,2}[A-Za-z][\w-]*)", detail)))[:12]
        elif kind == "process_exit":
            process.end = max(process.end or "", event.get("timestamp") or "") or None
        elif kind == "image_load":
            path = dos_path(text)
            if not path.lower().startswith(("c:\\windows", "/usr/")):
                sections["images_non_windows"][path] += 1
        elif kind.startswith("file_"):
            name = bucket(text)
            process.file_buckets[name][kind] += 1
            path = dos_path(text)
            if name == "named pipes":
                sections["pipes"][path] += 1
            if kind == "file_device_control":
                code = event.get("value0") or 0
                sections["device_control"][(path, IOCTL.get(code, hex(code)))] += 1
            if kind == "file_write":
                sections["writes"][path] += 1
            elif kind == "file_set_information" and event.get("value0") in (10, 13, 64, 65):
                action = "rename" if event["value0"] in (10, 65) else "delete"
                sections["deletes_renames"][(path, action)] += 1
            elif kind == "file_create" and event.get("status") == 0 and ((event.get("value0") or 0) >> 24) in (0, 2, 3, 4, 5):
                sections["created"][path] += 1
            elif kind == "file_read" and "maplestorycw" not in path.lower():
                sections["reads_outside_client"][path_prefix(path, 6)] += 1
        elif kind.startswith("registry"):
            key = registry_key(text)
            value_name = detail if "=" not in detail else ""
            writes = kind in ("registry_set_value", "registry_delete", "registry_rename") or \
                (kind == "registry_create" and event.get("status") == 0)
            if writes:
                sections["registry_writes"][(kind.replace("registry_", ""), key, value_name)] += 1
            else:
                sections["registry_read_prefixes"]["\\".join(key.split("\\")[:4])] += 1
                if IDENTITY.search(key) and event.get("status") == 0:
                    sections["registry_identity_reads"][key + ("\\" + value_name if value_name else "")] += 1
        elif kind in ("network_connect", "network_accept"):
            match = re.match(r"[\d.:a-f\[\]]+:\d+ -> ([\d.:a-f\[\]]+:\d+)", text)
            if match:
                target = "network_local" if match.group(1).startswith("127.") else "network"
                sections[target][(kind, match.group(1))] += 1
        elif kind == "etw_dns":
            sections["dns"][text] += 1
        elif kind == "etw_wmi":
            sections["wmi"][(text, detail[:160])] += 1
        elif kind == "etw_tcp":
            sections["tcp"][(detail, text)] += 1
        elif kind in ("process_handle", "thread_handle"):
            target = short_image(text) or f"pid {event.get('target_process_id')}"
            granted = event.get("value1") or 0
            rights = process_rights(granted) if kind == "process_handle" else hex(granted)
            sections["handles"][(kind, target, rights)] += 1
    return processes


def report(processes, session_dir, limit):
    def top(counter):
        return [[list(key) if isinstance(key, tuple) else key, count] for key, count in counter.most_common(limit)]

    output = {"session": pathlib.Path(session_dir).name, "processes": []}
    unattributed = []
    for (pid, created), process in sorted(processes.items(), key=lambda item: -sum(item[1].sections["types"].values())):
        if pid == 0:
            continue
        if created == 0:
            # No incarnation was alive at these events' timestamps, so they name no
            # process. Keep them visible instead of inventing a start-0 process row.
            unattributed.append({
                "pid": pid, "image": process.image,
                "events": sum(process.sections["types"].values()),
                "types": top(process.sections["types"]),
            })
            continue
        parents = [(parent_created, parent) for (parent_pid, parent_created), parent in processes.items()
                   if parent_pid == process.parent and parent_created != 0 and parent_created <= created]
        parent = max(parents, key=lambda item: item[0])[1].image if parents else None
        entry = {
            "pid": pid, "process_start_time": created,
            "image": process.image, "parent": process.parent, "parent_image": parent,
            "start": process.start, "end": process.end, "flags": process.flags, "switches": process.switches,
            "events": sum(process.sections["types"].values()),
            "file_buckets": {name: dict(counter) for name, counter in
                             sorted(process.file_buckets.items(), key=lambda item: -sum(item[1].values()))},
        }
        for name, counter in process.sections.items():
            entry[name] = top(counter)
        output["processes"].append(entry)
    if unattributed:
        output["unattributed"] = unattributed
    return output


def show(output, pid, sections, limit):
    found = False
    for process in output["processes"]:
        if process["pid"] != pid:
            continue
        found = True
        print(f"== {process['image']} pid={pid} parent={process['parent_image']}({process['parent']}) "
              f"{process['start']} -> {process['end']} flags={process['flags']} events={process['events']}")
        for key, value in process.items():
            if key in ("pid", "process_start_time", "image", "parent", "parent_image", "start", "end", "flags", "events") or not value:
                continue
            if sections and key not in sections:
                continue
            print(f"-- {key}")
            items = value.items() if isinstance(value, dict) else value[:limit]
            for item in items:
                print("  ", item)
    if found:
        return 0
    print(f"pid {pid} not in report", file=sys.stderr)
    return 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("session_dir")
    parser.add_argument("--out", help="write the JSON report here (default: <session>/activity.json)")
    parser.add_argument("--report", help="read an existing JSON report instead of the session")
    parser.add_argument("--show", type=int, metavar="PID", help="print one process from the report")
    parser.add_argument("--sections", help="comma-separated sections to print with --show")
    parser.add_argument("--limit", type=int, default=40, help="entries kept per section")
    args = parser.parse_args()

    if args.report:
        with open(args.report, encoding="utf-8") as stream:
            output = json.load(stream)
    else:
        output = report(collect(args.session_dir), args.session_dir, args.limit)
        target = pathlib.Path(args.out) if args.out else pathlib.Path(args.session_dir) / "activity.json"
        with open(target, "w", encoding="utf-8") as stream:
            json.dump(output, stream, indent=1, ensure_ascii=False)
        print(f"wrote {target}")
        for process in output["processes"]:
            print(f"   {process['pid']:>6} {process['image']:22} {process['events']:8} events")
    if args.show is not None:
        return show(output, args.show, args.sections.split(",") if args.sections else None, args.limit)
    return 0


if __name__ == "__main__":
    sys.exit(main())
