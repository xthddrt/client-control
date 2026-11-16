#!/usr/bin/env python3
"""Read-only search of a running process's memory for TLS handshake bytes; saves the memory around them.

    sudo .venv/bin/python -I analysis/tls-memscan.py <pid> captures/tls-scan-<stamp>.pkl @captures/tls-needles.txt
    sudo .venv/bin/python -I analysis/tls-memscan.py <pid> <out.pkl> <hex needle> [<hex needle> ...]

The needles (client/server randoms and session ids of open connections) come from
`analysis/tls-keys.py needles`. For every place a needle is found this saves the 16 KB around it and,
one level deep, 2 KB at every 8-byte value in that window that points into readable memory: OpenSSL
keeps a connection's master secret next to its randoms or one pointer away. `analysis/tls-keys.py find`
then picks the master secret out of the saved bytes.

READ-ONLY: it opens /proc/<pid>/maps and /proc/<pid>/mem with "rb" only. It never writes to the
process, never attaches (no ptrace), never stops or signals it, and the game cannot see it (nothing
happens inside Windows/Wine). Needs root for /proc/<pid>/mem. Standard library only, so it runs with -I.

The output holds memory of the game (keys, account data): it is a new file (never overwrites one),
mode 600, owned by the user who ran sudo, and refused inside the repository except captures/.
OpenSSL wipes a connection's secrets soon after the connection closes, so only connections open at
the time of the read can be found.
"""

import os
import pickle
import struct
import sys

CHUNK, OVERLAP, WINDOW, POINTED = 16 << 20, 64, 16384, 2048


def main():
    pid, out = int(sys.argv[1]), os.path.realpath(sys.argv[2])
    repo = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    if out.startswith(repo + os.sep) and not out.startswith(os.path.join(repo, "captures") + os.sep):
        sys.exit(f"{out}: memory contents stay out of the repository; use captures/ or a folder outside it")
    needles = [bytes.fromhex(h) for a in sys.argv[3:]
               for h in (open(a[1:]).read().split() if a.startswith("@") else [a])]
    needles = [n for n in needles if len(n) >= 16]   # shorter ones would match by chance
    if not needles:
        sys.exit("no needles of 16 bytes or more")

    maps = []
    with open(f"/proc/{pid}/maps", "rb") as f:
        for line in f:
            parts = line.split()
            lo, hi = (int(x, 16) for x in parts[0].split(b"-"))
            name = parts[5].decode(errors="replace") if len(parts) > 5 else ""
            if parts[1][:1] == b"r" and name not in ("[vvar]", "[vsyscall]", "[vvar_vclock]"):
                maps.append((lo, hi, parts[1].decode(), name))

    def readable(a):
        return any(lo <= a < hi for lo, hi, _, _ in maps)

    hits, blocks, scanned = [], {}, 0
    with open(f"/proc/{pid}/mem", "rb", buffering=0) as mem:
        def read(a, n):
            try:
                mem.seek(a)
                return mem.read(n)
            except OSError:
                return b""

        for lo, hi, perms, name in maps:
            for a in range(lo, hi, CHUNK):
                data = read(a, min(CHUNK + OVERLAP, hi - a))
                if not data:
                    break
                scanned += len(data)
                for i, n in enumerate(needles):
                    j = data.find(n)
                    while j >= 0:
                        if j < CHUNK:   # a hit in the overlap is found again by the next chunk
                            hits.append((i, a + j, perms, name))
                        j = data.find(n, j + 1)
        for _, addr, _, _ in hits:
            base = max(addr - WINDOW // 2, 0) & ~7
            if base in blocks:
                continue
            window = blocks[base] = read(base, WINDOW)
            for off in range(0, len(window) - 7, 8):
                p = struct.unpack_from("<Q", window, off)[0]
                if 0x10000 <= p < 1 << 47 and readable(p) and (p - 256) & ~7 not in blocks:
                    blocks[(p - 256) & ~7] = read((p - 256) & ~7, POINTED)

    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        pickle.dump({"needles": needles, "hits": hits, "blocks": blocks}, f)
    if "SUDO_UID" in os.environ:
        os.chown(out, int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"]))
    print(f"scanned {scanned >> 20} MiB in {len(maps)} mappings; {len(hits)} hits; {len(blocks)} blocks saved to {out}")


if __name__ == "__main__":
    main()
