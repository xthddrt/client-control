"""Live-capture helpers: process identity and current socket destinations.

SendPacket receives a packet object, not a socket. Under Wine/Proton the game
normally has one established game-channel socket, so the process's socket table
can supply the destination. If several established sockets exist, the
destination is reported as ambiguous and a destination rule does not match.
"""

from __future__ import annotations

import os
import re
import socket as _socket
import struct
import subprocess
from pathlib import Path

SERVICE_PORTS = {
    80, 443, 8080, 8443, 8550, 8551, 8552, 8553, 8554, 8555, 8556, 8557,
    8558, 8559, 8560, 8561, 8562, 8563, 8564, 8565, 8566, 8575, 8585, 8595,
    8913,
}


def process_info(pid, build=None):
    pid = int(pid)
    name = None
    path = None
    try:
        name = Path(f"/proc/{pid}/comm").read_text(encoding="utf-8", errors="replace").strip() or None
    except OSError:
        pass
    try:
        path = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        pass
    record = {
        "pid": pid,
        "name": name,
        "path": path,
        "attribution": "process_table",
    }
    if build:
        record["build"] = build
        if "pe_timestamp" in build:
            record["build_timestamp"] = build["pe_timestamp"]
            record["pe_timestamp"] = build["pe_timestamp"]
        if "module_base" in build:
            record["module_base"] = build["module_base"]
    return record


def _socket_inodes(pid):
    inodes = set()
    try:
        entries = list(Path(f"/proc/{pid}/fd").iterdir())
    except OSError:
        return inodes
    for entry in entries:
        try:
            target = os.readlink(entry)
        except OSError:
            continue
        match = re.fullmatch(r"socket:\[(\d+)\]", target)
        if match:
            inodes.add(int(match.group(1)))
    return inodes


def _decode_ipv4(value):
    # /proc/net/tcp prints address as little-endian hex bytes.
    raw = bytes.fromhex(value)
    if len(raw) != 4:
        return None
    return ".".join(str(byte) for byte in reversed(raw))


def _decode_ipv6(value):
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        return None
    if len(raw) != 16:
        return None
    # /proc prints four 32-bit words, each in host (little) byte order.
    words = b"".join(raw[index:index + 4][::-1] for index in range(0, 16, 4))
    try:
        return str(_socket.inet_ntop(_socket.AF_INET6, words))
    except OSError:
        return None


def _read_tcp_table(path, ipv6=False):
    result = {}
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()[1:]
    except OSError:
        return result
    for line in lines:
        fields = line.split()
        if len(fields) < 10:
            continue
        local, remote, state, inode = fields[1], fields[2], fields[3], fields[9]
        if state != "01":  # TCP_ESTABLISHED
            continue
        try:
            inode = int(inode)
        except ValueError:
            continue
        try:
            local_ip_hex, local_port_hex = local.rsplit(":", 1)
            remote_ip_hex, remote_port_hex = remote.rsplit(":", 1)
        except ValueError:
            continue
        ip = _decode_ipv6(remote_ip_hex) if ipv6 else _decode_ipv4(remote_ip_hex)
        if ip is None:
            continue
        result[inode] = {
            "ip": ip,
            "port": int(remote_port_hex, 16),
            "local_ip": _decode_ipv6(local_ip_hex) if ipv6 else _decode_ipv4(local_ip_hex),
            "local_port": int(local_port_hex, 16),
        }
    return result


def _parse_endpoint(text):
    text = text.strip()
    if text.startswith("["):
        host, _, port = text[1:].partition("]:")
    else:
        host, _, port = text.rpartition(":")
    if not host or not port.isdigit():
        return None
    return (host, int(port))


def _ss_peers(pid, name=None):
    """Fallback for Wine, where the game process may not own the socket fd."""
    try:
        output = subprocess.run(
            ["ss", "-tnp"], capture_output=True, text=True, timeout=2, check=False
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    peers = []
    seen = set()
    token = f"pid={pid},"
    for line in output.splitlines():
        if token not in line and not (name and f'("{name}"' in line):
            continue
        fields = line.split()
        if len(fields) < 6:
            continue
        remote = _parse_endpoint(fields[4])
        if remote and remote not in seen:
            seen.add(remote)
            peers.append({"ip": remote[0], "port": remote[1], "source": "ss"})
    return peers


def active_endpoints(pid):
    """Return current established TCP peers for this process, with evidence."""
    inodes = _socket_inodes(pid)
    table = {}
    table.update(_read_tcp_table(f"/proc/{pid}/net/tcp"))
    table.update(_read_tcp_table(f"/proc/{pid}/net/tcp6", ipv6=True))
    peers = []
    seen = set()
    for inode in inodes:
        entry = table.get(inode)
        if not entry:
            continue
        key = (entry["ip"], entry["port"])
        if key in seen:
            continue
        seen.add(key)
        peers.append({
            "ip": entry["ip"],
            "port": entry["port"],
            "local_ip": entry.get("local_ip"),
            "local_port": entry.get("local_port"),
            "socket_inode": inode,
        })
    source = "proc"
    if not peers:
        try:
            name = Path(f"/proc/{pid}/comm").read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            name = None
        peers = _ss_peers(pid, name)
        source = "ss_fallback" if peers else "none"
    return {
        "peers": peers,
        "destination": peers[0] if len(peers) == 1 else None,
        "ambiguous": len(peers) > 1,
        "socket_inodes": sorted(inodes),
        "source": source,
        "reason": (
            None if len(peers) == 1 else
            "no established socket found" if not peers else
            f"{len(peers)} established peers; SendPacket does not name the socket"
        ),
    }


def is_service_port(port):
    return port in SERVICE_PORTS
