"""Standalone Linux capture: tcpdump bytes + /proc socket attribution.

This is a standalone alternative to external session capture. It does not use
eBPF, a driver, or another repository. tcpdump writes the pcap; periodic /proc
snapshots write an attribution sidecar that ingest can join to pcap flows.
"""

from __future__ import annotations

import ipaddress
import json
import os
import shutil
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from .util import format_ns, sha256_file, write_jsonl


@dataclass
class Owner:
    pid: int
    name: str | None
    path: str | None


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


def _read_table(path: Path, protocol, ipv6):
    rows = {}
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[1:]
    except OSError:
        return rows
    for line in lines:
        fields = line.split()
        if len(fields) < 10:
            continue
        local_text, separator, remote_text = fields[1].partition(":")
        if not separator:
            continue
        remote_ip_text, remote_separator, remote_port_text = fields[2].partition(":")
        if not remote_separator:
            continue
        local_ip = _table_address(local_text, ipv6)
        remote_ip = _table_address(remote_ip_text, ipv6)
        if local_ip is None or remote_ip is None:
            continue
        try:
            local_port = int(fields[1].rsplit(":", 1)[1], 16)
            remote_port = int(fields[2].rsplit(":", 1)[1], 16)
            inode = int(fields[9])
        except ValueError:
            continue
        if remote_port == 0:
            continue
        rows[inode] = {
            "protocol": protocol,
            "local": (local_ip, local_port),
            "remote": (remote_ip, remote_port),
            "state": fields[3],
        }
    return rows


def _socket_owners(proc_root: Path, pids=None):
    owners = {}
    if pids:
        processes = [proc_root / str(pid) for pid in pids]
    else:
        try:
            processes = [entry for entry in proc_root.iterdir() if entry.name.isdecimal()]
        except OSError:
            processes = []
    for process in processes:
        try:
            name = (process / "comm").read_text(encoding="utf-8", errors="replace").strip() or None
        except OSError:
            name = None
        try:
            path = os.readlink(process / "exe")
        except OSError:
            path = None
        try:
            fds = list((process / "fd").iterdir())
        except OSError:
            continue
        for fd in fds:
            try:
                target = os.readlink(fd)
            except OSError:
                continue
            if not target.startswith("socket:[") or not target[8:-1].isdigit():
                continue
            inode = int(target[8:-1])
            owners.setdefault(inode, Owner(int(process.name), name, path))
    return owners


def snapshot(proc_root=Path("/proc"), pids=None):
    """Return inode -> owner/endpoint rows for the current instant."""
    owners = _socket_owners(proc_root, pids)
    rows = {}
    for protocol, ipv6, paths in (
        ("tcp", False, ("net/tcp",)),
        ("tcp", True, ("net/tcp6",)),
        ("udp", False, ("net/udp",)),
        ("udp", True, ("net/udp6",)),
    ):
        for relative in paths:
            table = _read_table(proc_root / relative, protocol, ipv6)
            for inode, row in table.items():
                owner = owners.get(inode)
                if owner is None:
                    continue
                if protocol == "tcp" and row["state"] != "01":
                    continue
                rows[(protocol, row["local"], row["remote"], owner.pid, inode)] = {
                    "kind": "attribution",
                    "protocol": protocol,
                    "local": list(row["local"]),
                    "remote": list(row["remote"]),
                    "pid": owner.pid,
                    "name": owner.name,
                    "path": owner.path,
                    "socket_inode": inode,
                }
    return rows


def _merge(observations, rows, time_ns):
    for key, row in rows.items():
        existing = observations.get(key)
        if existing is None:
            row["first_seen_ns"] = time_ns
            row["last_seen_ns"] = time_ns
            row["observations"] = 1
            observations[key] = row
        else:
            existing["last_seen_ns"] = time_ns
            existing["observations"] += 1


def capture(seconds, out_dir, interface="any", pcap_filter="tcp or udp",
            poll_interval=0.5, pids=None, proc_root=Path("/proc")):
    if seconds <= 0 or seconds > 3600:
        raise ValueError("seconds must be between 1 and 3600")
    if poll_interval < 0.1 or poll_interval > 10:
        raise ValueError("poll_interval must be between 0.1 and 10 seconds")
    tool = "dumpcap" if shutil.which("dumpcap") else "tcpdump" if shutil.which("tcpdump") else None
    if tool is None:
        raise RuntimeError("dumpcap or tcpdump is required for standalone capture")
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    pcap = out_dir / "capture.pcap"
    log = out_dir / "capture-tool.log"
    attribution = out_dir / "attribution.jsonl"
    metadata = out_dir / "capture.json"
    if pcap.exists():
        raise FileExistsError(f"refusing to overwrite existing capture: {pcap}")

    observations = {}
    started_ns = time.time_ns()
    started = time.monotonic()
    pattern = out_dir / "capture-%Y%m%d-%H%M%S.pcap"
    duration = max(1, int(seconds + 0.999))
    if tool == "dumpcap":
        command = [
            "dumpcap", "-i", interface, "-f", pcap_filter, "-w", str(pcap),
            "-P", "-a", f"duration:{duration}", "-q",
        ]
    else:
        command = ["tcpdump"]
        if os.geteuid() == 0:
            command += ["-Z", "root"]
        command += [
            "-i", interface, "-nn", "-s0", "-U", "-G", str(duration), "-W", "1",
            "-w", str(pattern), pcap_filter,
        ]
    interrupted = False
    with open(log, "wb") as log_handle:
        process = subprocess.Popen(
            command, stdout=subprocess.DEVNULL, stderr=log_handle,
            start_new_session=True,
        )
        try:
            time.sleep(0.25)  # let the tool open the interface before the first snapshot
            while process.poll() is None and time.monotonic() - started < seconds + 5:
                try:
                    _merge(observations, snapshot(proc_root, pids), time.time_ns())
                except OSError:
                    pass
                remaining = seconds - (time.monotonic() - started)
                if remaining <= 0:
                    # The capture tool auto-stops at its duration; keep the
                    # attribution loop alive briefly so the file is complete.
                    time.sleep(min(poll_interval, 1.0))
                    if process.poll() is not None:
                        break
                    continue
                time.sleep(min(poll_interval, remaining))
        except KeyboardInterrupt:
            interrupted = True
            if process.poll() is None:
                try:
                    process.send_signal(signal.SIGINT)
                except (OSError, PermissionError):
                    try:
                        os.killpg(os.getpgid(process.pid), signal.SIGINT)
                    except (OSError, PermissionError):
                        pass
        finally:
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                try:
                    process.terminate()
                    process.wait(timeout=5)
                except (OSError, PermissionError, subprocess.TimeoutExpired):
                    pass
    if tool == "tcpdump" and not pcap.exists():
        candidates = sorted(out_dir.glob("capture-*.pcap"), key=lambda item: item.stat().st_mtime)
        if candidates:
            candidates[-1].rename(pcap)
    if not pcap.exists():
        raise RuntimeError(f"{tool} did not create {pcap}; see {log}")
    ended_ns = time.time_ns()
    if process.returncode not in (0, None) and not interrupted:
        try:
            detail = log.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            detail = ""
        hint = ""
        if "permission" in detail.lower() or "not permitted" in detail.lower():
            hint = " Run under sudo or grant CAP_NET_RAW."
        raise RuntimeError(
            f"{tool} exited with status {process.returncode}; see {log}.{hint}"
        )
    records = sorted(observations.values(), key=lambda row: (
        row["first_seen_ns"], row["pid"], row["protocol"], row["local"], row["remote"],
    ))
    write_jsonl(attribution, records)
    result = {
        "schema": "client-control.traffic-capture/v1",
        "started_ns": started_ns,
        "started_utc": format_ns(started_ns),
        "ended_ns": ended_ns,
        "ended_utc": format_ns(ended_ns),
        "seconds_requested": seconds,
        "seconds_elapsed": round(time.monotonic() - started, 3),
        "interrupted": interrupted,
        "interface": interface,
        "pcap_filter": pcap_filter,
        "pids": list(pids) if pids else None,
        "tool": tool,
        "pcap": str(pcap),
        "pcap_bytes": pcap.stat().st_size,
        "pcap_sha256": sha256_file(pcap),
        "tool_status": process.returncode,
        "attribution_records": len(records),
        "attribution": str(attribution),
        "note": "Attribution is a periodic /proc snapshot; a short-lived socket or a Wine broker fd can be missing or ambiguous.",
    }
    metadata.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if os.geteuid() == 0:
        try:
            uid = int(os.environ.get("SUDO_UID", ""))
            gid = int(os.environ.get("SUDO_GID", ""))
        except ValueError:
            uid = gid = None
        if uid is not None:
            for path in (out_dir, pcap, attribution, metadata, log):
                try:
                    os.chown(path, uid, gid)
                except OSError:
                    pass
    return result
