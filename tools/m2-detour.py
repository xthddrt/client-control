#!/usr/bin/env python3
"""
M2 — client-side echo-loop detour with a self-healing pristine-substitution table.

Defeats DC-1's SERVER-DIRECTED arbitrary memory read (PM-119): the OnAliveReq
echo loop at 0x141667cac reads byte[ptr+i] for a server-chosen ptr and hashes the
bytes into the +68 integrity digest. By detouring the read through a substitution
table, any address inside one of OUR .text patches (GRAP no-ops), inside the detour
site itself, or inside the cave is reported as its PRISTINE (unpatched) byte — so
our .text modifications are invisible to the server's integrity read.  Self-healing:
the detector's own probe of the mitigation reads clean.

Mechanism: PTRACE_ATTACH + /proc/PID/mem write (bypasses r-xp page perms, no DR/HW
breakpoints => kill-safe, kernel auto-detaches on exit).

Layout (no-ASLR build, dump VA == live VA):
  detour site   0x141667cd1  `mov rcx,[rsp+0x28]`  (5 bytes -> E9 rel32)
  movzx         0x141667cd6  `movzx edx,byte[rcx+rax]`
  return target 0x141667cda  `lea rcx,[rsp+0x180]`
  cave          0x14334bc3a .. 0x14334c000  (966 bytes, .text tail zeros)

Substitution entry = {u64 start, u64 end_excl, u64 pristine_ptr}; sentinel start==0.
pristine_ptr==0 means "return 0" (used for the cave-self zero-fill).

Usage:
  m2-detour.py PID status
  m2-detour.py PID on            # apply detour + cave (payload patches from PATCHES[])
  m2-detour.py PID off           # restore detour site + zero the cave
  m2-detour.py PID verify        # assemble+report offline (no process needed if PID=0)
"""
import ctypes, os, sys

# ---- addresses (build 1.5.3.1, base 0x140000000) ----
DETOUR_VA   = 0x1416689a1
DETOUR_ORIG = bytes.fromhex("488b4c2428")   # mov rcx,[rsp+0x28]
RETURN_VA   = 0x1416689aa
CAVE_START  = 0x14335891a
CAVE_END    = 0x143359000
TEXT_END    = 0x143359000

# ---- GRAP no-op payload patches: list of (va, patched_bytes) ----
# Each region is auto-covered by the substitution table with its PRISTINE bytes
# (read from the live process BEFORE patching). Empty => M2 is an inert no-op
# (reads reproduce original bytes) — used to validate the detour is DC-safe first.
PATCHES = []

# Allow a payload to be injected via env for experiments:
#   M2_PATCHES="0x141000464:90,0x141000465:90"   (va:hexbyte[,va:hexbyte...])
_envp = os.environ.get("M2_PATCHES", "").strip()
if _envp:
    for item in _envp.split(","):
        va_s, hx = item.split(":")
        PATCHES.append((int(va_s, 16), bytes.fromhex(hx)))

PTRACE_ATTACH = 16
PTRACE_DETACH = 17
_libc = ctypes.CDLL("libc.so.6", use_errno=True)
_libc.ptrace.restype = ctypes.c_long
_libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]

def ptrace(req, pid, addr=0, data=0):
    r = _libc.ptrace(req, pid, ctypes.c_void_p(addr), ctypes.c_void_p(data))
    if r == -1:
        e = ctypes.get_errno()
        if e: raise OSError(e, os.strerror(e))
    return r

def rd(pid, addr, n):
    with open(f"/proc/{pid}/mem", "rb", 0) as m:
        m.seek(addr); return m.read(n)

def wr(pid, addr, b):
    with open(f"/proc/{pid}/mem", "wb", 0) as m:
        m.seek(addr); return m.write(b)

def assemble(table_va, stub_va=CAVE_START):
    """Assemble the cave stub. Two-pass not needed: imm64 + rel32 are fixed size,
    so stub length is invariant; caller passes the table VA that follows the stub."""
    from keystone import Ks, KS_ARCH_X86, KS_MODE_64
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    asm = f"""
        mov     rcx, [rsp+0x28]
        add     rax, rcx
        push    r11
        mov     r11, {table_va}
      scan:
        mov     rcx, [r11]
        test    rcx, rcx
        jz      default
        cmp     rax, rcx
        jb      adv
        mov     rcx, [r11+8]
        cmp     rax, rcx
        jae     adv
        mov     rcx, [r11]
        sub     rax, rcx
        mov     rcx, [r11+0x10]
        test    rcx, rcx
        jz      zero
        movzx   edx, byte ptr [rcx+rax]
        jmp     done
      zero:
        xor     edx, edx
        jmp     done
      adv:
        add     r11, 0x18
        jmp     scan
      default:
        movzx   edx, byte ptr [rax]
      done:
        pop     r11
        jmp     {RETURN_VA}
    """
    code, _ = ks.asm(asm, stub_va)
    return bytes(code)

def build_cave(pid):
    """Return (cave_bytes, entries_desc). cave_bytes is written at CAVE_START.
    Reads pristine bytes for PATCHES from the live process (must be pre-patch)."""
    # pass 1: assemble with placeholder table VA to learn stub length (fixed size)
    stub = assemble(table_va=CAVE_START + 0x100)
    stub_len = len(stub)
    table_va = CAVE_START + stub_len
    # collect substitution entries + their pristine blobs
    entries = []   # (start, end_excl, pristine_bytes_or_None)  None => zero-fill
    # 1) detour site: pristine = original 5 bytes
    entries.append((DETOUR_VA, DETOUR_VA + 5, DETOUR_ORIG))
    # 2) GRAP payload patches: pristine read live (pre-patch)
    for va, patched in PATCHES:
        pris = rd(pid, va, len(patched)) if pid else b"\x00" * len(patched)
        entries.append((va, va + len(patched), pris))
    # 3) cave self-coverage: zero-fill (original .text padding was all 00)
    entries.append((CAVE_START, CAVE_END, None))
    # layout: [stub][table: N*24 + sentinel 24][blobs...]
    n = len(entries)
    blob_region_va = table_va + (n + 1) * 24
    table = b""
    blobs = b""
    for (start, end, pris) in entries:
        if pris is None:
            ptr = 0
        else:
            ptr = blob_region_va + len(blobs)
            blobs += pris
        table += start.to_bytes(8, "little") + end.to_bytes(8, "little") + ptr.to_bytes(8, "little")
    table += (0).to_bytes(24, "little")  # sentinel
    cave = stub + table + blobs
    if CAVE_START + len(cave) > CAVE_END:
        raise RuntimeError(f"cave overflow: need {len(cave)}B, have {CAVE_END-CAVE_START}B")
    return cave, entries, stub_len, table_va

def apply_on(pid):
    cave, entries, stub_len, table_va = build_cave(pid)
    # re-assemble stub against the REAL table VA (same length, verified)
    stub = assemble(table_va=table_va)
    assert len(stub) == stub_len, "stub length drift"
    cave = stub + cave[stub_len:]
    from keystone import Ks, KS_ARCH_X86, KS_MODE_64
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    jmp, _ = ks.asm(f"jmp {CAVE_START}", DETOUR_VA)
    detour = bytes(jmp)
    assert len(detour) == 5, f"detour not 5 bytes: {detour.hex()}"
    # safety: confirm detour site is pristine before writing
    cur = rd(pid, DETOUR_VA, 5)
    if cur != DETOUR_ORIG:
        print(f"[!] detour site not pristine ({cur.hex()} != {DETOUR_ORIG.hex()}); abort"); return
    ptrace(PTRACE_ATTACH, pid); os.waitpid(pid, 0)
    try:
        # read pristine for payload (pre-patch) and save a restore sidecar
        restore = {}
        for va, patched in PATCHES:
            restore[f"{va:#x}"] = rd(pid, va, len(patched)).hex()
        wr(pid, CAVE_START, cave)                 # cave first (stub+table+blobs)
        wr(pid, DETOUR_VA, detour)                # arm the detour (substitution live)
        for va, patched in PATCHES:               # then write payload (now covered)
            wr(pid, va, patched)
        back_c = rd(pid, CAVE_START, len(cave))
        back_d = rd(pid, DETOUR_VA, 5)
        print(f"[+] cave   {len(cave)}B  {'OK' if back_c==cave else 'FAIL'}")
        print(f"[+] detour {detour.hex()}  {'OK' if back_d==detour else 'FAIL'}")
        for va, patched in PATCHES:
            bk = rd(pid, va, len(patched))
            print(f"[+] payload {va:#x} <- {patched.hex()} (pristine {restore[f'{va:#x}']})  {'OK' if bk==patched else 'FAIL'}")
        print(f"[i] stub={stub_len}B table@{table_va:#x} entries={len(entries)} payload={len(PATCHES)}")
        if restore:
            import json as _j; _j.dump(restore, open("/tmp/m2-restore.json", "w"))
            print(f"[i] restore sidecar -> /tmp/m2-restore.json")
    finally:
        ptrace(PTRACE_DETACH, pid); print("[i] detached; tracee resumed.")

def apply_off(pid):
    import json as _j
    restore = {}
    try: restore = _j.load(open("/tmp/m2-restore.json"))
    except Exception: pass
    ptrace(PTRACE_ATTACH, pid); os.waitpid(pid, 0)
    try:
        for va_s, hx in restore.items():          # restore payloads to pristine
            va = int(va_s, 16); wr(pid, va, bytes.fromhex(hx))
            print(f"[+] payload {va:#x} restored -> {hx}")
        wr(pid, DETOUR_VA, DETOUR_ORIG)           # disarm detour
        wr(pid, CAVE_START, b"\x00" * (CAVE_END - CAVE_START))  # zero cave
        back_d = rd(pid, DETOUR_VA, 5)
        print(f"[+] detour restored {back_d.hex()}  {'OK' if back_d==DETOUR_ORIG else 'FAIL'}")
        print(f"[+] cave zeroed")
    finally:
        ptrace(PTRACE_DETACH, pid); print("[i] detached; tracee resumed.")

def status(pid):
    cur = rd(pid, DETOUR_VA, 5)
    st = "ORIGINAL" if cur == DETOUR_ORIG else "DETOURED" if cur[0] == 0xE9 else "UNKNOWN"
    print(f"[i] detour site {DETOUR_VA:#x}: {cur.hex(' ')}  state={st}")
    if cur[0] == 0xE9:
        import struct
        rel = struct.unpack("<i", cur[1:5])[0]
        print(f"    -> jmp {DETOUR_VA+5+rel:#x}  (cave={CAVE_START:#x})")

def verify():
    """Offline self-test: assemble, disassemble, sanity-check sizes."""
    sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
    import dl  # dump reader for pristine cross-check
    cave, entries, stub_len, table_va = build_cave(pid=0)
    stub = assemble(table_va=table_va)
    print(f"[verify] stub={stub_len}B  table@{table_va:#x}  entries={len(entries)}  cave_total={len(cave)}B / {CAVE_END-CAVE_START}B budget")
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    print("[verify] stub disassembly:")
    for ins in md.disasm(stub, CAVE_START):
        print(f"    {ins.address:#x}: {ins.mnemonic:6} {ins.op_str}")
    # cross-check dump pristine at detour site
    d = dl.read(DETOUR_VA, 5)
    print(f"[verify] dump detour bytes {d.hex()}  {'OK' if d==DETOUR_ORIG else 'MISMATCH'}")

def main():
    if len(sys.argv) >= 3 and sys.argv[2] == "verify" or (len(sys.argv) >= 2 and sys.argv[1] == "verify"):
        verify(); return
    pid = int(sys.argv[1]); op = sys.argv[2]
    if op == "status": status(pid)
    elif op == "on":    apply_on(pid)
    elif op == "off":   apply_off(pid)
    elif op == "verify": verify()
    else: print("ops: status | on | off | verify")

if __name__ == "__main__":
    main()
