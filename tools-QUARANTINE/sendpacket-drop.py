"""Stealth selective DROP at the real SendPacket (RVA 0x1660360).

For each outbound packet whose opcode is in DROP set, redirect execution to the
return address (SendPacket returns TRUE without transmitting) -> the packet never
hits the wire; the caller's own COutPacket is left intact and destructed normally.
All other opcodes pass through untouched. Read opcode @ COutPacket+0x434.

DR0 exec BP on main thread (no .text write). Monitors the game-channel socket to
flag a disconnect. SIGINT (kill -2) stops cleanly (DR restore + detach).
usage: sendpacket-drop.py PID SECONDS OUT.json [OPCODE_HEX ...]   (default 0x1ef)
"""
import ctypes, importlib.util, json, os, signal, struct, sys, time, glob as _glob
from pathlib import Path
WS = Path('/home/<redacted>/Desktop/NGS-GRAP-MapleStory-Research/workspace-position-research')


def load(n, p):
    s = importlib.util.spec_from_file_location(n, p)
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


observer = load('reset_observer', WS / 'observe-position-reset.py')
shared = load('attack_observer', WS / 'overhead-attacks.py')
ch = observer.character
prof = json.loads((WS / 'profile.json').read_text())

pid = int(sys.argv[1])
dur = float(sys.argv[2])
out = sys.argv[3]
DROP = set(int(x, 16) for x in sys.argv[4:]) or {0x1ef}
SENDPACKET_RVA = 0x1660360


def chan_inodes():
    try:
        fds = _glob.glob(f'/proc/{pid}/fd/*')
    except Exception:
        return {}
    socks = set()
    for f in fds:
        try:
            l = os.readlink(f)
            if l.startswith('socket:['):
                socks.add(l[8:-1])
        except Exception:
            pass
    res = {}
    try:
        for line in open('/proc/net/tcp'):
            p = line.split()
            if len(p) < 10 or p[3] != '01':
                continue
            ino = p[9]
            if ino not in socks:
                continue
            rport = int(p[2].split(':')[1], 16)
            if 8500 <= rport <= 8599 or rport == 8913:
                res[ino] = rport
    except Exception:
        pass
    return res


r = ch.Reader(pid)
base, _ = ch.find_image(r, pid, prof)
target = base + SENDPACKET_RVA

hist = {}
dropped = {}
drop_events = []
total = 0
attached = stopped = False
saved = None
deliver = 0
dc_at = None

st = dict(l.split(':', 1) for l in Path(f'/proc/{pid}/status').read_text().splitlines())
if int(st['TracerPid']):
    raise SystemExit('already traced')

print(f'base={base:#x} SendPacket={target:#x} DROP={{{",".join(hex(x) for x in sorted(DROP))}}} dur={dur}s', flush=True)
try:
    observer.ptrace(pid, 0x4206); attached = True
    observer.ptrace(pid, 0x4207)
    state = observer.wait_stop(pid, 1); stopped = True
    deliver = shared.pending_signal(pid, state)
    saved = {s: observer.ptrace(pid, 3, 848 + s * 8) & 0xFFFFFFFFFFFFFFFF for s in (0, 6, 7)}
    if saved[7] & 3:
        raise RuntimeError('DR0 slot busy')
    observer.ptrace(pid, 6, 848, target)
    observer.ptrace(pid, 6, 848 + 7 * 8, (saved[7] & ~0xF0003) | 1)
    observer.ptrace(pid, 6, 848 + 6 * 8, 0)
    observer.ptrace(pid, 7, 0, deliver); deliver = 0; stopped = False
    ch0 = chan_inodes(); lastchk = 0; dc_at = None
    print(f'ARMED; channel sockets={sorted(ch0.values())}. kill -2 to stop.', flush=True)
    t0 = time.monotonic()
    while time.monotonic() - t0 < dur:
        if ch0 and time.monotonic() - lastchk > 0.5:
            lastchk = time.monotonic()
            if not (set(chan_inodes()) & set(ch0)):
                dc_at = round(lastchk - t0, 2)
                print(f'*** DC DETECTED t={dc_at}s (channel socket closed) dropped={sum(dropped.values())} ***', flush=True)
                break
        try:
            state = observer.wait_stop(pid, 0.2)
        except TimeoutError:
            continue
        stopped = True
        sig = os.WSTOPSIG(state)
        if sig != signal.SIGTRAP:
            observer.ptrace(pid, 7, 0, sig); stopped = False; continue
        dr6 = observer.ptrace(pid, 3, 848 + 6 * 8)
        if not dr6 & 1:
            deliver = sig; raise RuntimeError('foreign trap')
        regs = observer.Registers(); observer.ptrace(pid, 12, 0, ctypes.addressof(regs))
        pkt = regs.rcx & 0xFFFFFFFFFFFFFFFF
        try:
            op = struct.unpack('<I', r.read(pkt + 0x434, 4))[0]
            ln = struct.unpack('<I', r.read(pkt + 0x428, 4))[0]
        except Exception:
            op = ln = None
        if op is not None:
            total += 1
            hist[op] = hist.get(op, 0) + 1
            if op in DROP:
                # redirect to return address: pop retaddr, rip=retaddr, rax=TRUE -> no transmit
                rsp = regs.rsp & 0xFFFFFFFFFFFFFFFF
                try:
                    retaddr = struct.unpack('<Q', r.read(rsp, 8))[0]
                except Exception:
                    retaddr = None
                if retaddr:
                    try:
                        body = r.read(pkt + 8, min(48, max(2, ln if ln else 2))).hex()
                    except Exception:
                        body = None
                    regs.rip = retaddr
                    regs.rsp = (rsp + 8) & 0xFFFFFFFFFFFFFFFF
                    regs.rax = 1
                    observer.ptrace(pid, 13, 0, ctypes.addressof(regs))  # PTRACE_SETREGS
                    dropped[op] = dropped.get(op, 0) + 1
                    drop_events.append({'t': round(time.monotonic() - t0, 3), 'op': hex(op), 'len': ln, 'ret': hex(retaddr), 'body': body})
                    print(f'  DROP op={op:#06x} len={ln} ret={retaddr:#x} (total_dropped={sum(dropped.values())})', flush=True)
        observer.ptrace(pid, 6, 848 + 6 * 8, 0)
        observer.ptrace(pid, 7); stopped = False
finally:
    if attached:
        if not stopped:
            observer.ptrace(pid, 0x4207)
            state = observer.wait_stop(pid, 1)
            deliver = shared.pending_signal(pid, state, {})
        if saved:
            for s in (7, 0, 6):
                observer.ptrace(pid, 6, 848 + s * 8, saved[s])
        observer.ptrace(pid, 17, 0, deliver)
        print(f'DETACHED total_traps={total} dropped={sum(dropped.values()) if dropped else 0}', flush=True)
    json.dump({
        'base': hex(base), 'sendpacket_va': hex(target),
        'drop_set': [hex(x) for x in sorted(DROP)],
        'total': total, 'dc_at': dc_at,
        'dropped': {hex(k): v for k, v in dropped.items()},
        'histogram': {hex(k): v for k, v in sorted(hist.items(), key=lambda kv: -kv[1])},
        'drop_events': drop_events,
    }, open(out, 'w'), indent=1)
