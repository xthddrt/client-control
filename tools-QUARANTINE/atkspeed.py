"""0xe1 melee ATTACK-SPEED boost — legit-cadence paced forge (atkspeed-boost todo).

Builds on the PROVEN in-context the external researcher outbound forge (replay-attack-seq.py), but
changes the emission policy to respect the operator's observed safe envelope:
"overhead-only, up to ~3x speed does not cause cooldown/detection". The DCs in
PM-8/PM-10/PM-11/PM-12 came from BURSTS of surplus hits with near-identical ticks
(a telltale dup/speed signature). This tool instead makes every emitted swing look
like a believable NEXT swing:

  1. CLAIMED-RATE CAP: never let (real+injected) swings exceed MULT x the player's
     own measured base swing rate. MULT defaults to 3.0 (the stated ceiling).
  2. REALISTIC TICK ADVANCE: each injected copy's @32 client tick is advanced by a
     REAL per-swing amount (TICKSTEP, measured at 720..4200/swing, default ~1000),
     and @18 combo is bumped, so the server sees a plausibly-timed subsequent swing
     rather than a zero-gap duplicate.
  3. SLIDING-WINDOW THROTTLE: a 1.0s wall-clock window counts emissions; injection
     stops the instant the window would exceed the cap, so sustained rate stays
     <= MULT x base even if the player spams.

Per real 0xe1 swing we inject at most floor(MULT)-1 extra copies (3x => +2), each
gated by the throttle. Position is the client's own (always valid). Mirrors unchanged.

NOTE (future work): true real-time SPACING of the extra sends would need a timer
thread doing the forge between real swings; holding the network thread stopped to
sleep would freeze the game. This version caps and shapes the CLAIMED cadence; tune
MULT/TICKSTEP on a DE-PRIMED account (current account budget is saturated, PM-12).

Channel-socket monitor flags a DC. Main thread only. kill -2 stops clean.
usage: atkspeed.py PID SECONDS OUT.json MULT [TICKSTEP] [MAXINJECT]
  MULT     target speed multiplier cap (e.g. 3.0)
  TICKSTEP realistic per-swing tick advance for @32 (default 1000)
  MAXINJECT total injected-copy budget (0 = unlimited within the run)
"""
import ctypes, importlib.util, json, os, signal, struct, sys, time, glob as _glob
from collections import deque
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
pt = observer.ptrace
Registers = observer.Registers

pid = int(sys.argv[1])
dur = float(sys.argv[2])
out = sys.argv[3]
MULT = float(sys.argv[4])
TICKSTEP = int(sys.argv[5]) if len(sys.argv) > 5 else 1000
MAXINJECT = int(sys.argv[6]) if len(sys.argv) > 6 else 0
OFF_COMBO = 18
OFF_TICK = 32
SENDPACKET_RVA = 0x1660360
OP = 0xe1
OBJ = 0x500
DRB = 848
RF = 0x10000
PEEK, POKE, CONT, GETREGS, SETREGS, DETACH = 3, 6, 7, 12, 13, 17
WINDOW = 1.0                      # sliding-window length (s) for the rate cap
EXTRA_PER_SWING = max(0, int(MULT) - 1)   # 3.0 -> 2 extra copies per real swing

memfd = os.open(f'/proc/{pid}/mem', os.O_RDWR)


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
            if p[9] not in socks:
                continue
            rport = int(p[2].split(':')[1], 16)
            if 8500 <= rport <= 8599 or rport == 8913:
                res[p[9]] = rport
    except Exception:
        pass
    return res


r = ch.Reader(pid)
base, _ = ch.find_image(r, pid, prof)
target = base + SENDPACKET_RVA

st = dict(l.split(':', 1) for l in Path(f'/proc/{pid}/status').read_text().splitlines())
if int(st['TracerPid']):
    raise SystemExit('already traced')

injected = 0
real_e1 = 0
total = 0
attached = stopped = False
saved = None
deliver = 0
dc_at = None

emit_times = deque()             # wall-clock of recent emissions (real+injected)
swing_wall = deque(maxlen=8)     # wall-clock of recent REAL swings -> base rate est


def getregs():
    rg = Registers(); pt(pid, GETREGS, 0, ctypes.addressof(rg)); return rg


def setregs(rg):
    pt(pid, SETREGS, 0, ctypes.addressof(rg))


def wait_trap(timeout=1.0):
    return observer.wait_stop(pid, timeout)


def window_count(now):
    while emit_times and now - emit_times[0] > WINDOW:
        emit_times.popleft()
    return len(emit_times)


def base_rate():
    """Estimate player's real swings/sec from recent real-swing gaps."""
    if len(swing_wall) < 2:
        return 1.0                      # prior: ~1 swing/sec
    span = swing_wall[-1] - swing_wall[0]
    return (len(swing_wall) - 1) / span if span > 0 else 1.0


print(f'base={base:#x} SendPacket={target:#x} ATKSPEED MULT={MULT} (+{EXTRA_PER_SWING}/swing) '
      f'TICKSTEP={TICKSTEP} dur={dur}s maxinject={MAXINJECT or "inf"}', flush=True)
try:
    pt(pid, 0x4206); attached = True
    pt(pid, 0x4207)
    state = observer.wait_stop(pid, 1); stopped = True
    deliver = shared.pending_signal(pid, state)
    saved = {s: pt(pid, PEEK, DRB + s * 8) & 0xFFFFFFFFFFFFFFFF for s in (0, 1, 6, 7)}
    if saved[7] & 0xF:
        raise RuntimeError('DR0/DR1 slot busy')
    clean7 = saved[7] & ~0x00FF000F
    ARM0 = clean7 | 0x1
    ARM1 = clean7 | 0x4
    pt(pid, POKE, DRB + 0 * 8, target)
    pt(pid, POKE, DRB + 6 * 8, 0)
    pt(pid, POKE, DRB + 7 * 8, ARM0)
    pt(pid, CONT, 0, deliver); deliver = 0; stopped = False
    ch0 = chan_inodes(); lastchk = 0
    print(f'ARMED; channel sockets={sorted(ch0.values())}. Attack a mob now. kill -2 to stop.', flush=True)
    t0 = time.monotonic()
    while time.monotonic() - t0 < dur:
        if ch0 and time.monotonic() - lastchk > 0.5:
            lastchk = time.monotonic()
            if not (set(chan_inodes()) & set(ch0)):
                dc_at = round(lastchk - t0, 2)
                print(f'*** DC DETECTED t={dc_at}s injected={injected} real_e1={real_e1} ***', flush=True)
                break
        try:
            state = wait_trap(0.2)
        except TimeoutError:
            continue
        stopped = True
        sig = os.WSTOPSIG(state)
        if sig != signal.SIGTRAP:
            pt(pid, CONT, 0, sig); stopped = False; continue
        dr6 = pt(pid, PEEK, DRB + 6 * 8)
        if not dr6 & 1:
            deliver = sig; raise RuntimeError('foreign trap')
        regs0 = getregs()
        pkt = regs0.rcx & 0xFFFFFFFFFFFFFFFF
        try:
            op = struct.unpack('<I', r.read(pkt + 0x434, 4))[0]
        except Exception:
            op = None
        total += 1
        now = time.monotonic()
        if op == OP:
            real_e1 += 1
            swing_wall.append(now)
            emit_times.append(now)                 # the genuine swing itself counts
            cap = max(1.0, MULT * base_rate())     # emissions allowed in WINDOW
            snap = os.pread(memfd, OBJ, pkt)
            ret_addr = struct.unpack('<Q', os.pread(memfd, 8, regs0.rsp))[0]
            base_tick = struct.unpack_from('<I', snap, 8 + OFF_TICK)[0]
            base_combo = struct.unpack_from('<H', snap, 8 + OFF_COMBO)[0]
            want = EXTRA_PER_SWING
            if MAXINJECT:
                want = min(want, MAXINJECT - injected)
            done = 0
            for i in range(1, want + 1):
                nowi = time.monotonic()
                if window_count(nowi) + 1 > cap:   # throttle: would exceed MULT x base
                    break
                os.pwrite(memfd, snap, pkt)
                new_tick = (base_tick + i * TICKSTEP) & 0xFFFFFFFF
                new_combo = (base_combo + i) & 0xFFFF
                os.pwrite(memfd, struct.pack('<I', new_tick), pkt + 8 + OFF_TICK)
                os.pwrite(memfd, struct.pack('<H', new_combo), pkt + 8 + OFF_COMBO)
                rg = Registers(); ctypes.memmove(ctypes.addressof(rg), ctypes.addressof(regs0), ctypes.sizeof(rg))
                rg.rip = target; rg.rcx = pkt; rg.rsp = regs0.rsp
                setregs(rg)
                pt(pid, POKE, DRB + 1 * 8, ret_addr)
                pt(pid, POKE, DRB + 6 * 8, 0)
                pt(pid, POKE, DRB + 7 * 8, ARM1)
                pt(pid, CONT, 0, 0)
                try:
                    state = wait_trap(1.0)
                except TimeoutError:
                    print('  !! inject timeout — aborting this swing', flush=True); break
                d6 = pt(pid, PEEK, DRB + 6 * 8)
                if not d6 & 2:
                    print(f'  !! unexpected trap during inject dr6={d6:#x} — aborting', flush=True); break
                injected += 1; done += 1
                emit_times.append(time.monotonic())
            os.pwrite(memfd, snap, pkt)
            regs0.eflags |= RF
            setregs(regs0)
            pt(pid, POKE, DRB + 7 * 8, ARM0)
            pt(pid, POKE, DRB + 6 * 8, 0)
            pt(pid, CONT, 0, 0); stopped = False
            if real_e1 <= 3 or real_e1 % 20 == 0:
                print(f'  swing real_e1={real_e1} +{done} (inj_total={injected}, base~{base_rate():.2f}/s cap={cap:.1f})', flush=True)
        else:
            regs0.eflags |= RF
            setregs(regs0)
            pt(pid, POKE, DRB + 6 * 8, 0)
            pt(pid, CONT, 0, 0); stopped = False
finally:
    if attached:
        if not stopped:
            pt(pid, 0x4207)
            try:
                state = observer.wait_stop(pid, 1)
                deliver = shared.pending_signal(pid, state, {})
            except Exception:
                deliver = 0
        if saved:
            for s in (7, 0, 1, 6):
                try: pt(pid, POKE, DRB + s * 8, saved[s])
                except Exception: pass
        try: pt(pid, DETACH, 0, deliver)
        except Exception: pass
        print(f'DETACHED total_traps={total} real_e1={real_e1} injected={injected} dc_at={dc_at}', flush=True)
    os.close(memfd)
    json.dump({
        'base': hex(base), 'sendpacket_va': hex(target), 'MULT': MULT, 'TICKSTEP': TICKSTEP,
        'extra_per_swing': EXTRA_PER_SWING, 'real_e1': real_e1, 'injected': injected,
        'total_traps': total, 'dc_at': dc_at,
    }, open(out, 'w'), indent=1)
