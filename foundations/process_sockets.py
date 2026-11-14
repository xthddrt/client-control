"""Attribute a local TCP endpoint to a process through its socket inode."""

import ipaddress
import os
from pathlib import Path


BROKERS = {"wine", "wine64", "wine-preloader", "wine64-preloader", "wineserver", "wineserver64"}


def _table_address(text, v6):
    raw = bytearray.fromhex(text)
    if v6:
        if len(raw) != 16:
            return None
        for offset in range(0, 16, 4):
            raw[offset:offset + 4] = raw[offset:offset + 4][::-1]
    else:
        if len(raw) != 4:
            return None
        raw.reverse()
    return str(ipaddress.ip_address(bytes(raw)))


def _start_time(path):
    try:
        fields = (path / "stat").read_text().rsplit(")", 1)[1].split()
        return int(fields[19])
    except (OSError, IndexError, ValueError):
        return None


class SocketOwnerResolver:
    def __init__(self, proc=Path("/proc")):
        self.proc = Path(proc)
        self.cache = {}

    def inodes(self, address, port):
        wanted = ipaddress.ip_address(address)
        found = set()
        for name, v6 in (("tcp", False), ("tcp6", True)):
            try:
                lines = (self.proc / "net" / name).read_text().splitlines()[1:]
            except OSError:
                continue
            for line in lines:
                fields = line.split()
                if len(fields) < 10:
                    continue
                local = fields[1]
                address_hex, separator, port_hex = local.partition(":")
                if not separator or int(port_hex, 16) != port:
                    continue
                decoded = _table_address(address_hex, v6)
                if decoded is not None and ipaddress.ip_address(decoded) == wanted:
                    found.add(fields[9])
        return found

    def lookup(self, address):
        """Return unique application attribution, or all candidates when it is ambiguous."""
        if not address or len(address) < 2:
            return {"pid": None, "name": None, "evidence": "client_address_unavailable"}
        host, port = address[0], int(address[1])
        key = (str(host), port)
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
                    if target.startswith("socket:[") and target[8:-1] in inodes:
                        try:
                            name = (process / "comm").read_text().strip()
                        except OSError:
                            name = None
                        candidates.append({
                            "pid": int(process.name), "name": name, "start_time_ticks": _start_time(process),
                            "socket_inode": target[8:-1], "evidence": "proc_fd_socket_inode",
                        })
                        break
        applications = [candidate for candidate in candidates if candidate.get("name") not in BROKERS]
        if len(applications) == 1:
            result = dict(applications[0])
            result["candidates"] = candidates
            result["attribution"] = "unique_non_broker" if len(candidates) > 1 else "unique_owner"
        else:
            result = {"pid": None, "name": None, "candidates": candidates,
                      "socket_inode": sorted(inodes)[0] if len(inodes) == 1 else None,
                      "evidence": "ambiguous_socket_owners" if applications else "application_owner_not_found"}
        self.cache[key] = result
        return result


def self_test():
    import tempfile
    with tempfile.TemporaryDirectory() as temporary:
        proc = Path(temporary)
        (proc / "net").mkdir()
        (proc / "net" / "tcp").write_text(
            "  sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode\n"
            "  0: 0100007F:3039 00000000:0000 01 00000000:00000000 00:00000000 00000000 1000 0 42 1 0 0 0\n"
        )
        for pid, name in ((100, "MapleStory.exe"), (200, "wineserver")):
            (proc / str(pid) / "fd").mkdir(parents=True)
            (proc / str(pid) / "comm").write_text(name + "\n")
            (proc / str(pid) / "stat").write_text(f"{pid} ({name}) S" + " 0" * 18 + " 12345\n")
            (proc / str(pid) / "fd" / "1").symlink_to("socket:[42]")
        resolver = SocketOwnerResolver(proc)
        result = resolver.lookup(("127.0.0.1", 12345))
        assert result["pid"] == 100 and result["attribution"] == "unique_non_broker"
        assert result["socket_inode"] == "42" and len(result["candidates"]) == 2
        assert result["start_time_ticks"] == 12345
    print("PASS: socket-inode process attribution with wineserver disambiguation.")


if __name__ == "__main__":
    self_test()
