#!/usr/bin/env python3
import argparse
import collections
import datetime as dt
import hashlib
import json
from pathlib import Path


MACHINES = {0x14C: "x86", 0x8664: "x86-64", 0xAA64: "ARM64"}
SUBSYSTEMS = {1: "native", 2: "windows_gui", 3: "windows_console"}


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def decode(value):
    if isinstance(value, bytes):
        return value.rstrip(b"\0").decode("utf-8", "replace")
    return str(value)


def version_info(pe):
    result = {}
    for group in getattr(pe, "FileInfo", []):
        for item in group:
            if item.Key == b"StringFileInfo":
                for table in item.StringTable:
                    for key, value in table.entries.items():
                        result[decode(key)] = decode(value)
    return result


def pe_metadata(path):
    import pefile  # only needed for PE images, so an ELF-only client inventories without it

    pe = pefile.PE(str(path), fast_load=False)
    try:
        security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        result = {
            "machine": MACHINES.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine)),
            "timestamp_utc": dt.datetime.fromtimestamp(
                pe.FILE_HEADER.TimeDateStamp, dt.timezone.utc
            ).isoformat(),
            "characteristics": pe.FILE_HEADER.Characteristics,
            "image_base": pe.OPTIONAL_HEADER.ImageBase,
            "entry_point_rva": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            "subsystem": SUBSYSTEMS.get(pe.OPTIONAL_HEADER.Subsystem, pe.OPTIONAL_HEADER.Subsystem),
            "checksum": pe.OPTIONAL_HEADER.CheckSum,
            "authenticode_directory_present": security.VirtualAddress != 0 and security.Size != 0,
            "version": version_info(pe),
            "sections": [],
            "imports": [],
            "delay_imports": [],
            "exports": [],
            "debug_paths": [],
        }
        for section in pe.sections:
            result["sections"].append({
                "name": decode(section.Name),
                "virtual_address": section.VirtualAddress,
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "characteristics": section.Characteristics,
                "entropy": round(section.get_entropy(), 4),
            })
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            result["imports"].append({
                "dll": decode(entry.dll),
                "symbols": [decode(item.name) if item.name else f"ordinal:{item.ordinal}" for item in entry.imports],
            })
        for entry in getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", []):
            result["delay_imports"].append({
                "dll": decode(entry.dll),
                "symbols": [decode(item.name) if item.name else f"ordinal:{item.ordinal}" for item in entry.imports],
            })
        export = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        if export:
            result["exports"] = [
                {"ordinal": item.ordinal, "name": decode(item.name) if item.name else None, "rva": item.address}
                for item in export.symbols
            ]
        for entry in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []):
            if hasattr(entry.entry, "PdbFileName"):
                result["debug_paths"].append(decode(entry.entry.PdbFileName))
        return result
    finally:
        pe.close()


def analyze(root):
    root = root.resolve()
    files = []
    extensions = collections.Counter()
    pe_count = 0
    elf_count = 0
    pkg1_count = 0
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        with path.open("rb") as stream:
            data = stream.read(96)
        suffix = path.suffix.lower()
        extensions[suffix or "<none>"] += 1
        record = {
            "path": path.relative_to(root).as_posix(),
            "size": path.stat().st_size,
            "sha256": sha256(path),
            "extension": suffix or "<none>",
            "header_hex": data[:16].hex(),
        }
        if data.startswith(b"MZ"):
            record["kind"] = "pe"
            record["pe"] = pe_metadata(path)
            pe_count += 1
        elif data.startswith(b"\x7fELF"):
            # Only PE images are parsed; ELF files are listed and reported as a gap below.
            record["kind"] = "elf"
            elf_count += 1
        elif data.startswith(b"PKG1"):
            pkg1_count += 1
            record["kind"] = "pkg1"
            record["pkg1"] = {
                "declared_file_size": int.from_bytes(data[4:8], "little"),
                "header_size": int.from_bytes(data[12:16], "little"),
                "banner": data[16:60].rstrip(b"\0").decode("ascii", "replace"),
            }
        elif suffix == ".ini":
            record["kind"] = "text_index"
            record["text"] = path.read_text(encoding="utf-8-sig", errors="replace")
        elif suffix in {".txt", ".bat", ".md5", ".hash"}:
            record["kind"] = "text"
            record["text"] = path.read_text(encoding="utf-8-sig", errors="replace")
        elif suffix in {".aes", ".ms"}:
            record["kind"] = "opaque_or_encrypted_container"
        else:
            record["kind"] = "binary_data"
        files.append(record)
    return {
        "schema": 1,
        "generated_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "root": str(root),
        "summary": {
            "files": len(files),
            "bytes": sum(item["size"] for item in files),
            "pe_images": pe_count,
            "elf_images": elf_count,
            "pkg1_containers": pkg1_count,
            "extensions": dict(sorted(extensions.items())),
            "gaps": ["elf_inventory: ELF headers, imports and needed libraries are not parsed"] if elf_count else [],
        },
        "files": files,
    }


def main():
    parser = argparse.ArgumentParser(description="Inventory MapleStory client files and native PE metadata.")
    parser.add_argument("client", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    result = analyze(args.client)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], indent=2))


if __name__ == "__main__":
    main()
