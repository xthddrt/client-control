# Read-only static-analysis toolkit

These helpers consolidate the reusable executable-analysis logic from the research scratch scripts. They read PE files on disk; they do not open a process, attach a debugger, or use captures. `capstone` and `pefile` are already in the repository requirements.

Run commands from the repository root. Set `APPDATA` to the game's `appdata` directory; no machine-specific path is stored in the tools.

```bash
# Annotated disassembly: packet decoders/encoders, imports, strings and method slots.
.venv/bin/python analysis/re-tool.py dis "$APPDATA/MapleStory.exe" 0x1b00f90

# Function bounds, direct callers, method-table slots and RTTI class names.
.venv/bin/python analysis/re-tool.py func "$APPDATA/MapleStory.exe" 0x1b00f90

# Direct calls, common RIP-relative operands and absolute pointers to one RVA.
.venv/bin/python analysis/re-tool.py xrefs "$APPDATA/MapleStory.exe" 0x1b00f90

# C 0x1ef build sites and the first kind constant passed to EncodeBuffer.
.venv/bin/python analysis/re-tool.py kinds "$APPDATA/MapleStory.exe" --check

# Regenerate the checked server dispatch and compiled-host references.
.venv/bin/python analysis/re-tool.py dispatch "$APPDATA/MapleStory.exe" \
  --markdown docs/reference/server-dispatch.md --check
.venv/bin/python analysis/re-tool.py hosts "$APPDATA" \
  --markdown docs/reference/compiled-hosts.md
```

`--cache captures/NAME.pkl` before the subcommand reuses function and reference indexes after checking the file's SHA-256. Load only caches you created; pickle is not a safe format for untrusted files. Without `--cache`, the direct-call and method-slot indexes are rebuilt and the RIP index is built only for `xrefs`.

## Modules

- `image.py`: x64 PE loading, `.pdata` function bounds, direct calls, RIP references, method tables, RTTI and validated caching.
- `annotate.py`: disassembly with CInPacket/COutPacket calls labelled and ASCII/UTF-16 strings resolved.
- `dispatch.py`: the profiled login, context, field and user-pool tables and range routes, plus generated Markdown.
- `kinds.py`: the C 0x1ef constructor-site search and stack-slot constant tracking.
- `hosts.py`: host, URL, IP and explicit `:port` extraction from ASCII and UTF-16 strings in appdata binaries.

Dispatch and kind-site addresses apply only to MapleStory.exe PE timestamp `0x6AEB667B`; other builds are rejected. Dispatch rows retain the case address and route. `inline` means handling code in the dispatcher itself. A direct-call path is a static lead, not proof of every runtime route. Themida-virtualised dispatch remains unresolved. Host extraction does not guess integer-only port constants.

Synthetic tests are in `traffic/tests/test_reverse.py`. Run the full suite with:

```bash
.venv/bin/python -m unittest discover -s traffic/tests -t .
```
