#!/usr/bin/env python3
"""grap-core-crash.py  — rebuild of the lost ntwf-hook.py core-crash vehicle.

Built on grap-core-procmem.py's /proc/<core>/mem machinery. Instead of the
tolerated DATA edit (WriteFile IAT pointer swap), this installs a CODE patch:
an inline E9 detour at the ENTRY of Wine ntdll's NtWriteFile syscall stub,
redirecting to a counter+trampoline stub in an ntdll .text code cave.

Empirically (session dbc12b13, checkpoints 012/013): the code patch into ntdll
is FATAL to grap-core64 — the core faults when NtWriteFile is next called
(~instant to ~5s). A CRASH-kill (abrupt fault, IPC pipe left half-open) EVADES
the server liveness auditor, unlike a clean SIGTERM (which gets kicked in
~28-79s). Core-death is then tolerated for in-session play; world/channel
re-entry or re-login requires a live core.

Commands:
  analyze  (default)  : resolve NtWriteFile + find ntdll cave. READ ONLY, no writes.
  arm                 : DRY-RUN plan (prints bytes, no write). Add --go to apply (FATAL).
  verify              : check whether core is still alive (post-crash confirmation).

Addresses are re-resolved live every run (per-launch ASLR of the Wine PE area).
"""
import os, struct, sys, time, json

STATE_FILE = "/tmp/grap-core-crash.state"

def _is_zombie(pid):
    try:
        for line in open(f'/proc/{pid}/status'):
            if line.startswith('State:'):
                return 'Z' in line.split(':', 1)[1]
    except Exception:
        pass
    return False

def find_proc(comm):
    for d in os.listdir('/proc'):
        if d.isdigit():
            try:
                if open(f'/proc/{d}/comm').read().strip() == comm and not _is_zombie(int(d)):
                    return int(d)
            except Exception:
                pass
    return None

find_core  = lambda: find_proc('grap-core64.aes')
find_maple = lambda: find_proc('MapleStory.exe')

class Mem:
    def __init__(self, pid, write=False):
        self.pid = pid
        self.fd = os.open(f'/proc/{pid}/mem', os.O_RDWR if write else os.O_RDONLY)
    def rd(self, a, n):
        os.lseek(self.fd, a, 0); return os.read(self.fd, n)
    def wr(self, a, b):
        os.lseek(self.fd, a, 0); return os.write(self.fd, b)
    def close(self):
        os.close(self.fd)

def cstr(m, a, maxlen=128):
    out = b''
    while len(out) < maxlen:
        c = m.rd(a + len(out), 16)
        if not c:
            break
        if b'\0' in c:
            return (out + c[:c.index(b'\0')]).decode('latin1')
        out += c
    return out.decode('latin1')

def ntdll_base(pid):
    """PE ntdll.dll base = the r--p header page of the .../x86_64-windows/ntdll.dll file."""
    best = None
    for line in open(f'/proc/{pid}/maps'):
        p = line.split()
        if len(p) >= 6 and p[5].endswith('x86_64-windows/ntdll.dll'):
            lo = int(p[0].split('-')[0], 16)
            off = int(p[2], 16)
            if off == 0:
                return lo
            best = min(best, lo) if best else lo
    return best

def resolve_export(m, base, want):
    """Parse ntdll PE export directory; return VA of the named export."""
    assert m.rd(base, 2) == b'MZ', "no MZ at ntdll base"
    e = struct.unpack('<I', m.rd(base + 0x3c, 4))[0]
    nt = base + e
    assert m.rd(nt, 2) == b'PE', "no PE sig in ntdll"
    opt = nt + 24
    exp_rva, exp_sz = struct.unpack('<II', m.rd(opt + 112, 8))  # data dir[0] = export
    ed = base + exp_rva
    nfunc, nname = struct.unpack('<II', m.rd(ed + 0x14, 8))
    aof, aon, aoo = struct.unpack('<III', m.rd(ed + 0x1c, 12))
    names = m.rd(base + aon, nname * 4)
    ords  = m.rd(base + aoo, nname * 2)
    for i in range(nname):
        nrva = struct.unpack('<I', names[i*4:i*4+4])[0]
        nm = cstr(m, base + nrva, 48)
        if nm == want:
            o = struct.unpack('<H', ords[i*2:i*2+2])[0]
            frva = struct.unpack('<I', m.rd(base + aof + o*4, 4))[0]
            return base + frva
    return None

def regions(pid, prot='r-xp'):
    out = []
    for line in open(f'/proc/{pid}/maps'):
        p = line.split()
        if prot in p[1]:
            lo, hi = (int(x, 16) for x in p[0].split('-'))
            out.append((lo, hi, p[5] if len(p) > 5 else ''))
    return out

def find_cave(m, lo, hi, need=64):
    pos = lo; run = 0; rb = None; CH = 0x80000
    while pos < hi:
        buf = m.rd(pos, min(CH, hi - pos))
        if not buf:
            pos += CH; run = 0; continue
        for i, b in enumerate(buf):
            if b in (0, 0xCC):
                if rb is None or b == rb:
                    run += 1
                else:
                    run = 1
                rb = b
                if run >= need:
                    return pos + i - run + 1
            else:
                run = 0; rb = None
        pos += len(buf)
    return None

def ntdll_cave(pid, m, need=64):
    for lo, hi, name in regions(pid, 'r-xp'):
        if name.endswith('x86_64-windows/ntdll.dll'):
            c = find_cave(m, lo, hi, need)
            if c:
                return c
    return None

# Detour: at NtWriteFile entry write  E9 rel32 -> cave.
# Steal the first STOLEN bytes (>=5, whole-instruction-safe-ish for a syscall stub).
STOLEN = 16
CNT_OFF = 0x80  # counter qword, well past the stub code

def build_cave_stub(cave, entry, stolen_bytes):
    # inc qword [rip+d1]              ; FF 05 d1
    # <stolen prologue bytes>         ; re-execute original entry bytes
    # mov rax, imm64 (entry+STOLEN)   ; 48 B8 ..
    # jmp rax                         ; FF E0
    code = b''
    d1 = (cave + CNT_OFF) - (cave + 6)
    code += b'\xff\x05' + struct.pack('<i', d1)
    code += stolen_bytes
    code += b'\x48\xb8' + struct.pack('<Q', entry + STOLEN)
    code += b'\xff\xe0'
    assert len(code) <= CNT_OFF, "stub overruns counter slot"
    return code + b'\x00' * (CNT_OFF + 8 - len(code))

def build_detour(entry, cave):
    rel = cave - (entry + 5)
    assert -0x80000000 <= rel <= 0x7fffffff, "detour out of rel32 range"
    return b'\xe9' + struct.pack('<i', rel) + b'\x90' * (STOLEN - 5)

def analyze():
    core = find_core()
    if not core:
        print("core not found"); return None
    m = Mem(core)
    base = ntdll_base(core)
    nt = resolve_export(m, base, 'NtWriteFile')
    cave = ntdll_cave(core, m, 64)
    entry_bytes = m.rd(nt, STOLEN) if nt else b''
    m.close()
    print(f"core pid        = {core}")
    print(f"ntdll PE base   = 0x{base:x}")
    print(f"NtWriteFile     = 0x{nt:x}  (last session: 0x6fffffefeb00)")
    print(f"  entry bytes   = {entry_bytes.hex()}")
    print(f"ntdll cave      = 0x{cave:x}" if cave else "ntdll cave      = NONE (>=64B)")
    return {'core': core, 'base': base, 'nt': nt, 'cave': cave,
            'entry_bytes': entry_bytes.hex()}

def arm(go=False):
    info = analyze()
    if not info or not info['nt'] or not info['cave']:
        print("cannot arm: missing NtWriteFile or cave"); return
    core, nt, cave = info['core'], info['nt'], info['cave']
    m = Mem(core)
    stolen = m.rd(nt, STOLEN)
    m.close()
    stub   = build_cave_stub(cave, nt, stolen)
    detour = build_detour(nt, cave)
    print("\n--- CRASH PLAN (CODE patch into ntdll = FATAL to core) ---")
    print(f"  detour @0x{nt:x} : {detour.hex()}")
    print(f"  stub   @0x{cave:x}: {stub[:32].hex()}... ({len(stub)}B, counter@+0x{CNT_OFF:x})")
    if not go:
        print("\nDRY-RUN. Re-run with:  arm --go   to apply (this WILL crash the core).")
        return
    mw = Mem(core, write=True)
    mw.wr(cave, stub)
    if mw.rd(cave, len(stub)) != stub:
        print("CAVE WRITE MISMATCH — aborting before detour"); mw.close(); return
    mw.wr(nt, detour)                      # <-- the fatal code patch
    back = mw.rd(nt, len(detour))
    mw.close()
    json.dump({'core': core, 'nt': nt, 'cave': cave, 'stolen': stolen.hex(),
               'ts': time.time()}, open(STATE_FILE, 'w'))
    print(f"\nARMED: detour installed @0x{nt:x} readback={back.hex()}")
    print("Core will fault when NtWriteFile is next called. Run `verify` to confirm death.")

def verify():
    core = find_core(); maple = find_maple()
    print(f"grap-core64.aes = {core if core else 'GONE (crashed)'}")
    print(f"MapleStory.exe  = {maple if maple else 'GONE'}")
    if core is None and maple:
        print("=> CORE DEAD, GAME ALIVE (crash-kill successful).")
    elif core:
        print("=> core still alive (not yet faulted, or NtWriteFile not called).")

if __name__ == '__main__':
    a = sys.argv[1:]
    if not a or a[0] == 'analyze':
        analyze()
    elif a[0] == 'arm':
        arm(go=('--go' in a))
    elif a[0] == 'verify':
        verify()
    else:
        print(__doc__)
