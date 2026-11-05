"""Stealth outbound-packet observer at the REAL CClientSocket::SendPacket.

Behavior-verified entry this build: RVA 0x1661780 (VA 0x141661780), rcx=COutPacket*.
  - opcode  @ COutPacket+0x434 (u32)
  - length  @ COutPacket+0x428 (u32)
  - body    @ COutPacket+0x008 (inline, opcode duplicated at +0x008 too)
This supersedes the inherited the external researcher anchor 0x1632B10 (that VA is a generic
shared_ptr-release epilogue, NOT SendPacket -- false byte-signature match).

Read-only: DR0 hardware exec breakpoint on the main thread; no .text write, no
payload modification. Builds an opcode histogram + sample bodies to classify
traffic (telemetry vs gameplay). SIGINT (kill -2) to stop cleanly (restores DR,
detaches). usage: sendpacket-observe.py PID SECONDS OUT.json
"""
import ctypes, importlib.util, json, os, signal, struct, sys, time
from pathlib import Path
WS = Path(__file__).resolve().parent


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
SENDPACKET_RVA = 0x1661780
SAMPLES_PER_OP = 4
BODY_CAP = 64

r = ch.Reader(pid)
base, _ = ch.find_image(r, pid, prof)
target = base + SENDPACKET_RVA

hist = {}          # opcode -> count
samples = {}       # opcode -> list of hex bodies
lengths = {}       # opcode -> set of observed lengths (as sorted list at end)
total = 0
attached = stopped = False
saved = None
deliver = 0

st = dict(l.split(':', 1) for l in Path(f'/proc/{pid}/status').read_text().splitlines())
if int(st['TracerPid']):
    raise SystemExit('already traced')

print(f'base={base:#x} SendPacket={target:#x} dur={dur}s -> {out}', flush=True)
try:
    observer.ptrace(pid, 0x4206); attached = True       # PTRACE_SEIZE
    observer.ptrace(pid, 0x4207)                         # PTRACE_INTERRUPT
    state = observer.wait_stop(pid, 1); stopped = True
    deliver = shared.pending_signal(pid, state)
    saved = {s: observer.ptrace(pid, 3, 848 + s * 8) & 0xFFFFFFFFFFFFFFFF for s in (0, 6, 7)}
    if saved[7] & 3:
        raise RuntimeError('DR0 slot busy')
    observer.ptrace(pid, 6, 848, target)                           # DR0 = SendPacket
    observer.ptrace(pid, 6, 848 + 7 * 8, (saved[7] & ~0xF0003) | 1)  # enable DR0 exec, len=00
    observer.ptrace(pid, 6, 848 + 6 * 8, 0)
    observer.ptrace(pid, 7, 0, deliver); deliver = 0; stopped = False
    print('ARMED; observing outbound traffic (read-only). kill -2 to stop.', flush=True)
    t0 = time.monotonic()
    while time.monotonic() - t0 < dur:
        try:
            state = observer.wait_stop(pid, 0.5)
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
            body = r.read(pkt + 8, min(BODY_CAP, max(2, ln if ln else 2)))
        except Exception:
            op = ln = None; body = None
        if op is not None:
            total += 1
            hist[op] = hist.get(op, 0) + 1
            lengths.setdefault(op, set()).add(ln)
            if body is not None and len(samples.setdefault(op, [])) < SAMPLES_PER_OP:
                samples[op].append(body.hex())
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
        print(f'DETACHED total_traps={total} distinct_opcodes={len(hist)}', flush=True)
    result = {
        'base': hex(base), 'sendpacket_rva': hex(SENDPACKET_RVA),
        'sendpacket_va': hex(target), 'total': total,
        'histogram': {hex(k): v for k, v in sorted(hist.items(), key=lambda kv: -kv[1])},
        'lengths': {hex(k): sorted(x for x in v if x is not None) for k, v in lengths.items()},
        'samples': {hex(k): v for k, v in samples.items()},
    }
    json.dump(result, open(out, 'w'), indent=1)
    print('--- opcode histogram (desc) ---', flush=True)
    for k, v in sorted(hist.items(), key=lambda kv: -kv[1]):
        ls = sorted(x for x in lengths[k] if x is not None)
        print(f'  op={k:#06x} count={v:<5} lens={ls}', flush=True)
