"""Scoped attack-speed boost via animation-frame shortening (no ptrace).

PM-17 model: a local swing is an action (actor+0x7e8 = action id) made of frames.
actor+0xb70 = frame index, actor+0xb74 = ms left in the current frame (counts down
on the game's dilated clock). The next swing starts when the last frame ends, so
attack rate = 1 / action length. Each time a NEW frame of an ATTACK action starts,
we rewrite its remaining time to remaining / FACTOR -> attacks FACTOR x faster on
top of the global speedhack (2.0 x 1.5 = 3x attacks, movement stays 2x).

Only the local actor and only attack action ids are touched. Writes use
process_vm_writev (root; /proc/pid/mem writes return EIO without a tracer), so no tracer is used and overhead-attacks.py can keep the
ptrace. Ctrl-C / kill -2 stops; nothing to restore (frame timers are transient).
usage: atkspeed-frames.py PID SECONDS FACTOR [--dry]
"""
import ctypes, importlib.util, json, os, signal, struct, sys, time
from pathlib import Path
WS = Path(__file__).resolve().parent
s = importlib.util.spec_from_file_location('c', WS / 'locate-character.py')
ch = importlib.util.module_from_spec(s); s.loader.exec_module(ch)
prof = json.loads((WS / 'profile.json').read_text())
pid = int(sys.argv[1]); dur = float(sys.argv[2]); FACTOR = float(sys.argv[3])
DRY = '--dry' in sys.argv
if not 1.0 <= FACTOR <= 3.0:
    raise SystemExit('FACTOR must be 1.0..3.0')
pa = prof['polearm_attacks']
ATTACK_ACTIONS = set(pa['overhead_actions']) | set(pa['stab_actions']) | {0}
OFF_ACTION, OFF_FRAME = 0x7ec, 0xb70          # frame idx @0xb70, remaining ms @0xb74

r = ch.Reader(pid)
base, _ = ch.find_image(r, pid, prof)
root = base + int(prof['rvas']['character_global'], 16)
memfd = os.open(f'/proc/{pid}/mem', os.O_RDONLY)


class _Iov(ctypes.Structure):
    _fields_ = [('base', ctypes.c_void_p), ('len', ctypes.c_size_t)]


_libc = ctypes.CDLL(None, use_errno=True)
_libc.process_vm_writev.restype = ctypes.c_ssize_t


def write_i32(addr, value):
    buf = ctypes.create_string_buffer(struct.pack('<i', value), 4)
    local = _Iov(ctypes.cast(buf, ctypes.c_void_p), 4)
    remote = _Iov(addr, 4)
    if _libc.process_vm_writev(pid, ctypes.byref(local), 1, ctypes.byref(remote), 1, 0) != 4:
        raise OSError(ctypes.get_errno(), 'process_vm_writev failed')
stop = False
signal.signal(signal.SIGINT, lambda *a: globals().__setitem__('stop', True))
signal.signal(signal.SIGTERM, lambda *a: globals().__setitem__('stop', True))

prev_key = None
pending = None            # (actor, key, target) awaiting confirmation
frames = writes = rewrites = swings = 0
saved_ms = 0
starts = []               # (t, action) of each swing start
ends = []                 # t when an attack action stopped being current
in_attack = False
print(f'ATKSPEED-FRAMES pid={pid} factor={FACTOR} dry={DRY} actions={sorted(ATTACK_ACTIONS)} dur={dur}s', flush=True)
t0 = time.monotonic()
try:
    while not stop and time.monotonic() - t0 < dur:
        try:
            actor = r.qword(root)
            if not actor:
                time.sleep(0.01); continue
            action = struct.unpack('<i', os.pread(memfd, 4, actor + OFF_ACTION))[0]
            fidx, rem = struct.unpack('<ii', os.pread(memfd, 8, actor + OFF_FRAME))
        except OSError:
            time.sleep(0.01); continue
        key = (actor, action, fidx)
        now = time.monotonic() - t0
        attacking = action in ATTACK_ACTIONS and rem > 0
        if in_attack and (not attacking or (prev_key and fidx < prev_key[2])):
            ends.append(now)
        in_attack = attacking
        if attacking:
            if key != prev_key:
                frames += 1
                if fidx == 0:
                    swings += 1
                    starts.append((now, action))
                target = max(1, int(rem / FACTOR))
                if not DRY:
                    write_i32(actor + OFF_FRAME + 4, target)
                    writes += 1; saved_ms += rem - target
                pending = (key, target)
            elif pending and pending[0] == key and rem > pending[1] + 5 and not DRY:
                # game overwrote our value in the same tick; apply once more
                write_i32(actor + OFF_FRAME + 4, pending[1])
                rewrites += 1; pending = None
        prev_key = key
        time.sleep(0.001)
finally:
    os.close(memfd); r.close()
    el = time.monotonic() - t0
    gaps = [round(starts[i][0] - starts[i - 1][0], 3) for i in range(1, len(starts))]
    anim = []; idle = []
    for i, (st, _a) in enumerate(starts):
        e = next((x for x in ends if x > st), None)
        if e is None:
            continue
        anim.append(e - st)
        if i + 1 < len(starts):
            idle.append(starts[i + 1][0] - e)
    avg = lambda v: round(sum(v) / len(v), 3) if v else None
    print(f'swing_gap_avg={avg(gaps)}s anim_avg={avg(anim)}s idle_after_anim_avg={avg(idle)}s', flush=True)
    print('first gaps:', gaps[:15], 'actions:', [a for _, a in starts[:15]], flush=True)
    print(f'STOPPED t={el:.1f}s swings={swings} attack_frames={frames} writes={writes} '
          f'rewrites={rewrites} game_ms_saved={saved_ms}', flush=True)
