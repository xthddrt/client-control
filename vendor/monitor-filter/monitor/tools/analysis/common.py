"""Shared helpers for reading msmon session bundles."""

import glob
import json
import os
import re

# Windows modules that sit between the caller and the kernel on most stacks.
# The first module in a stack that is not in this set is the one that asked.
WINDOWS_MODULES = {
    "ntdll.dll", "kernelbase.dll", "kernel32.dll", "advapi32.dll", "sechost.dll", "win32u.dll", "combase.dll",
    "rpcrt4.dll", "ucrtbase.dll", "msvcrt.dll", "wow64.dll", "wow64cpu.dll", "user32.dll", "msvcp_win.dll",
    "ws2_32.dll", "mswsock.dll", "cfgmgr32.dll", "setupapi.dll", "crypt32.dll", "wintrust.dll", "imagehlp.dll",
    "psapi.dll", "dbghelp.dll", "wbemcomn.dll", "fastprox.dll", "wbemprox.dll", "oleaut32.dll", "ole32.dll",
    "shlwapi.dll", "shell32.dll", "version.dll", "iphlpapi.dll", "dhcpcsvc.dll", "winnsi.dll", "nsi.dll",
    "bcrypt.dll", "cryptsp.dll", "rsaenh.dll", "profapi.dll", "winsta.dll", "wtsapi32.dll", "msasn1.dll",
    "cryptbase.dll", "devobj.dll", "kernel.appcore.dll", "dxgi.dll", "d3d11.dll", "dxdiagn.dll", "powrprof.dll",
    "pdh.dll", "gdi32full.dll", "gdi32.dll", "sspicli.dll", "netapi32.dll", "srvcli.dll", "wkscli.dll",
}

PROCESS_RIGHTS = [(0x1, "TERMINATE"), (0x2, "CREATE_THREAD"), (0x8, "VM_OPERATION"), (0x10, "VM_READ"),
                  (0x20, "VM_WRITE"), (0x40, "DUP_HANDLE"), (0x80, "CREATE_PROCESS"), (0x200, "SET_INFORMATION"),
                  (0x400, "QUERY_INFORMATION"), (0x800, "SUSPEND_RESUME"), (0x1000, "QUERY_LIMITED_INFORMATION")]


def event_parts(bundle):
    """Log parts in write order: events.jsonl, events.jsonl.1, .2, ..."""
    parts = glob.glob(os.path.join(bundle, "events.jsonl*"))
    return sorted(parts, key=lambda path: (len(path), path))


def iter_lines(bundle):
    for part in event_parts(bundle):
        with open(part, encoding="utf-8") as stream:
            yield from stream


def iter_events(bundle, contains=None):
    """Decoded events; `contains` skips lines without that substring before decoding (much faster)."""
    for line in iter_lines(bundle):
        if contains is not None and contains not in line:
            continue
        try:
            yield json.loads(line)
        except ValueError:
            continue


def short_image(path):
    return re.split(r"[\\/]", path or "")[-1]


def dos_path(path, volume=r"\Device\HarddiskVolume3", drive="C:"):
    """Device path to drive letter, with the user name replaced. Adjust `volume` for other machines.

    Linux paths are already absolute; only the /home/<user> name is replaced."""
    text = path or ""
    if text.startswith("/"):
        return re.sub(r"^/home/[^/]+/", "/home/<you>/", text)
    if text.startswith(volume):
        text = drive + text[len(volume):]
    text = re.sub(r"^\\\?\?\\", "", text)
    return re.sub(r"\\Users\\[^\\]+\\", r"\\Users\\<you>\\", text)


def path_prefix(path, parts):
    """The first `parts` components of a Windows or Linux path, in its own separator."""
    separator = "/" if path.startswith("/") else "\\"
    return separator.join(path.split(separator)[:parts])


def registry_key(key):
    """Kernel registry path to the familiar HKLM / HKCU form, with ControlSet00n folded."""
    text = re.sub(r"^\\REGISTRY\\USER\\S-1-5-21-[\d-]+(_Classes)?",
                  lambda match: "HKCU" + ("\\Classes" if match.group(1) else ""), key or "", flags=re.I)
    text = re.sub(r"^\\REGISTRY\\MACHINE", "HKLM", text, flags=re.I)
    text = re.sub(r"^\\REGISTRY\\USER", "HKU", text, flags=re.I)
    return re.sub(r"ControlSet00\d", "CurrentControlSet", text, flags=re.I)


# Linux: Wine's own PE and unix modules, the prefix's Windows directory and system libraries are never the
# caller either (with PE frames a Wine stack reads ntdll.dll, kernelbase.dll, game.exe, ntdll.so, libc.so.6).
SYSTEM_PATH = re.compile(r"^/(usr/)?lib(32|64)?/|/lib(32|64)?/wine/|/drive_c/windows/", re.I)


def caller_module(event):
    """First non-Windows module on the event's stack, or a marker when there is none."""
    modules = event.get("modules") or []
    names = [short_image(module) for module in modules]
    own = [name for module, name in zip(modules, names)
           if name.lower() not in WINDOWS_MODULES and not SYSTEM_PATH.search(module)]
    if own:
        return own[0]
    if names:
        return "(windows only: " + ">".join(names[:3]) + ")"
    return "(no stack)"


def process_rights(granted):
    if granted & 0x1FFFFF == 0x1FFFFF:
        return "ALL_ACCESS"
    names = [name for bit, name in PROCESS_RIGHTS if granted & bit]
    return "|".join(names) or hex(granted)


def hhmmss(timestamp):
    """2026-10-29T19:52:20.385Z -> 19:52:20.385 (UTC)."""
    return (timestamp or "")[11:23]
