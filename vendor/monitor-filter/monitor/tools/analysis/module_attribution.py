#!/usr/bin/env python3
"""Which module inside a process made its handle opens, identity reads, device IOCTLs and executable opens."""

import argparse
import collections
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from common import caller_module, iter_events, process_rights, short_image  # noqa: E402

IDENTITY = re.compile(r"MachineGuid|HardwareID|CentralProcessor|SystemBiosVersion|BIOS|ComputerName|"
                      r"Enum\\(PCI|USB|HID|BTH|DISPLAY)|Tcpip\\Parameters\\Interfaces", re.I)


def identity_kind(text):
    if "MachineGuid" in text:
        return "MachineGuid"
    if "Enum" in text:
        return "device HardwareID"
    if re.search("CentralProcessor|BIOS", text, re.I):
        return "CPU/BIOS"
    if "Tcpip" in text:
        return "network interfaces"
    if "ComputerName" in text:
        return "computer name"
    return "other"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("session_dir")
    parser.add_argument("--process", default="MapleStory.exe", help="image name to attribute (default MapleStory.exe)")
    args = parser.parse_args()

    handles = collections.Counter()
    targets = collections.defaultdict(set)
    identity = collections.Counter()
    ioctls = collections.Counter()
    executables = collections.Counter()
    unresolved = collections.Counter()
    for event in iter_events(args.session_dir, contains='"stack_frames"'):
        if short_image(event.get("process_path")).lower() != args.process.lower():
            continue
        kind = event.get("type")
        who = caller_module(event)
        text = event.get("text") or ""
        if event.get("stack_unresolved") and kind != "etw_rpc":
            unresolved[(kind, who)] += event["stack_unresolved"]
        if kind == "process_handle":
            key = (who, process_rights(event.get("value1") or 0))
            handles[key] += 1
            targets[key].add(short_image(text) or f"pid{event.get('target_process_id')}")
        elif kind in ("registry_query", "registry_open") and IDENTITY.search(text + "\\" + (event.get("detail") or "")):
            identity[(identity_kind(text + (event.get("detail") or "")), who)] += 1
        elif kind == "file_device_control":
            ioctls[(hex(event.get("value0") or 0), short_image(text) or text, who)] += 1
        elif kind == "file_create" and text.lower().endswith((".exe", ".dll", ".sys")) and "maplestorycw" not in text.lower():
            executables[who] += 1

    print(f"== {args.process} process handles: (module, granted rights) -> count, targets")
    for (who, rights), count in handles.most_common(25):
        names = sorted(targets[(who, rights)])
        print(f"   {count:5}  {who:30} {rights:40} {len(names)} targets e.g. {', '.join(names[:6])}")
    print("== identity reads: (what, module) -> count")
    for key, count in identity.most_common(25):
        print("  ", count, key)
    print("== device IOCTLs: (code, target, module) -> count")
    for key, count in ioctls.most_common(15):
        print("  ", count, key)
    print("== opens of executables outside the client folder, by module:", executables.most_common(12))
    print("== user-mode frames in no loaded image (driver events), by (type, module):", unresolved.most_common(12))
    return 0


if __name__ == "__main__":
    sys.exit(main())
