"""Diff every readable/writable process-memory region in bounded chunks."""

from pathlib import Path


CHUNK_SIZE = 1024 * 1024


def writable_regions(pid):
    regions = []
    with open(f"/proc/{pid}/maps") as stream:
        for line in stream:
            fields = line.split(None, 5)
            if len(fields) < 2 or "rw" not in fields[1]:
                continue
            low, high = (int(value, 16) for value in fields[0].split("-"))
            if high - low > 512 << 20 or low >= 0x7F0000000000:
                continue
            path = fields[5].strip() if len(fields) == 6 else ""
            if path in ("[vvar]", "[vdso]", "[vsyscall]"):
                continue
            regions.append((low, high, path))
    return regions


def snapshot(reader, pid):
    chunks = {}
    errors = []
    for low, high, path in writable_regions(pid):
        for address in range(low, high, CHUNK_SIZE):
            size = min(CHUNK_SIZE, high - address)
            try:
                data = reader.read(address, size)
            except (OSError, RuntimeError) as error:
                errors.append({"address": hex(address), "path": path, "error": str(error)})
                continue
            chunks[address] = (path, data)
    return {"chunks": chunks, "errors": errors}


def diff(before, after):
    changes = []
    before_chunks = before["chunks"] if before else {}
    after_chunks = after["chunks"]
    for address, (path, data) in after_chunks.items():
        previous = before_chunks.get(address)
        if previous is not None and previous[1] == data:
            continue
        changes.append({
            "address": hex(address), "path": path,
            "before": previous[1].hex() if previous is not None else None,
            "after": data.hex(),
        })
    for address, (path, data) in before_chunks.items():
        if address not in after_chunks:
            changes.append({"address": hex(address), "path": path, "before": data.hex(), "after": None})
    return {
        "changed_chunks": changes,
        "changed_chunk_count": len(changes),
        "read_errors": (before["errors"] if before else []) + after["errors"],
        "atomic": False,
    }
