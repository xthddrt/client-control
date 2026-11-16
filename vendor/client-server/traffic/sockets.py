"""Attribute a local TCP endpoint to a process through its socket inode.

Used by the NGS proxy addon: mitmproxy knows the client-side address but not the
Windows/Wine process. A broker (wineserver) may own the fd, so a unique
non-broker owner is chosen only when the evidence identifies one.
"""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path


BROKERS = {"wine", "wine64", "wine-preloader", "wine64-preloader", "wineserver", "wineserver64"}


def _table_address(text, ipv6):
    try:
        raw = bytearray.fromhex(text)
    except ValueError:
        return None
    if ipv6:
        if len(raw) != 16:
            return None
        for offset in range(0, 16, 4):
            raw[offset:offset + 4] = raw[offset:offset + 4][::-1]
    else:
        if len(raw) != 4:
            return None
        raw.reverse()
    try:
        return str(ipaddress.ip_address(bytes(raw)))
    except ValueError:
        return None


def _start_time(path):
    try:
        fields = (path / "stat").read_text(encoding="utf-8", errors="replace").rsplit(")", 1)[1].split()
        return int(fields[19])
    except (OSError, IndexError, ValueError):
        return None


class SocketOwnerResolver:
    def __init__(self, proc=Path("/proc")):
        self.proc = Path(proc)
        self.cache = {}

    def inodes(self, address, port):
        try:
            wanted = ipaddress.ip_address(address)
        except ValueError:
            return set()
        found = set()
        for name, ipv6 in (("tcp", False), ("tcp6", True)):
            try:
                lines = (self.proc / "net" / name).read_text(encoding="utf-8", errors="replace").splitlines()[1:]
            except OSError:
                continue
            for line in lines:
                fields = line.split()
                if len(fields) < 10:
                    continue
                address_hex, separator, port_hex = fields[1].partition(":")
                if not separator:
                    continue
                try:
                    if int(port_hex, 16) != int(port):
                        continue
                except ValueError:
                    continue
                decoded = _table_address(address_hex, ipv6)
                if decoded is None:
                    continue
                try:
                    if ipaddress.ip_address(decoded) == wanted:
                        found.add(int(fields[9]))
                except ValueError:
                    continue
        return found

    def lookup(self, address):
        """Return unique application attribution, or all candidates when ambiguous."""
        if not address or len(address) < 2:
            return {"pid": None, "name": None, "path": None,
                    "evidence": "client_address_unavailable"}
        host, port = str(address[0]), int(address[1])
        key = (host, port)
        if key in self.cache:
            return self.cache[key]
        inodes = self.inodes(host, port)
        candidates = []
        if inodes:
            try:
                processes = [entry for entry in self.proc.iterdir() if entry.name.isdecimal()]
            except OSError:
                processes = []
            for process in processes:
                try:
                    fds = list((process / "fd").iterdir())
                except OSError:
                    continue
                for fd in fds:
                    try:
                        target = os.readlink(fd)
                    except OSError:
                        continue
                    if target.startswith("socket:[") and target[8:-1].isdigit():
                        inode = int(target[8:-1])
                        if inode not in inodes:
                            continue
                        try:
                            name = (process / "comm").read_text(
                                encoding="utf-8", errors="replace"
                            ).strip()
                        except OSError:
                            name = None
                        try:
                            path = os.readlink(process / "exe")
                        except OSError:
                            path = None
                        candidates.append({
                            "pid": int(process.name),
                            "name": name,
                            "path": path,
                            "start_time_ticks": _start_time(process),
                            "socket_inode": inode,
                            "evidence": "proc_fd_socket_inode",
                        })
                        break
        applications = [
            candidate for candidate in candidates
            if (candidate.get("name") or "").lower() not in BROKERS
        ]
        if len(applications) == 1:
            result = dict(applications[0])
            result["candidates"] = candidates
            result["attribution"] = "unique_non_broker" if len(candidates) > 1 else "unique_owner"
        else:
            result = {
                "pid": None,
                "name": None,
                "path": None,
                "candidates": candidates,
                "socket_inode": sorted(inodes)[0] if len(inodes) == 1 else None,
                "evidence": "ambiguous_socket_owners" if applications else "application_owner_not_found",
            }
        self.cache[key] = result
        return result
