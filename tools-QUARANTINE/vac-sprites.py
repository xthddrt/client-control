"""Visual mob "vac": hold every mob's controller-A position at the player.

Controller A (CMob+0x2b8, protected doubles X@+0x170, Y@+0x188, Y-mirror @+0x128) is the
displayed/simulated mob position. Holding it moves the SPRITES; the server-side mob position
(and the server's hit validation) is unaffected -- see CONTINUATION-LOG mob-hitbox tests.
Controller B (+0x2c0) is NEVER written (A+B together + player hit = hard crash, 23:19 test).

Writes: process_vm_writev (root, no ptrace) -- one 14-byte write per value (encoded double +
key/meta untouched + checksum) so the game never reads a torn block. Heap data only.
usage: vac-sprites.py PID SECONDS [--y] [--front PX] [--face left|right] [--spread PX] [--radius PX]
  --dry      scan, select, and encode without any process memory writes
  --front    place the pile PX ahead of the player (facing inferred from X movement; default 0)
  --face     initial facing before the player moves (default right)
  --count N  pull only N mobs (the nearest ones at least --min-dist away), kept stable across rescans
  --min-dist candidate mobs must be at least this far from the player at selection (default 0)
  --no-auto-face  keep --face fixed (knockback otherwise flips the inferred facing)
  --y        also hold Y (pull across platforms). Auto-repoints each pulled mob to the
             PLAYER's foothold so the knockback/physics walk stays valid (PM-23 crash fix)
  --no-fh    with --y, do NOT sync the foothold pointer (crash-prone A/B experiment only)
  --no-pin   don't pin post-copy X (+0x1d0) and zero velocity (+0x1b8/+0x1a0); default pins (anti-flicker)
  --hold-b   also hold controller B (server keyframe) at the forced spot so the per-keyframe B->A
             reset can't snap the mob back (PM-29). Crash-prone; on-screen gate then can't see real pos
  --spread   fan mobs out +-PX around the player instead of stacking exactly (default 0)
  --radius   only pull mobs within this X distance of the player (default: all)
  --view W H only pull mobs whose REAL (server) position is within +-W, +-H of the player
             (default ~half the 2560x1440 viewport; --view 0 0 disables the on-screen gate)
  --no-top-up  with --count, don't pull a replacement after a pulled mob dies/leaves
  --chain-delay S  with --count + top-up (chain), wait S seconds after a pulled mob dies before pulling the next (default 1.0)
  --park N   pull one mob at a time, hold it PARK_HOLD s (--park-hold, default 2.5) on a slot along the
             player's foothold (--park-gap PX apart), then release it for good; N=0 = until stopped
  --fixed-anchor  (park) freeze the park spot at the player's position/foothold at startup; the
             player may walk away and mobs keep landing on that spot
  --control-stdin  stop when stdin reads "stop" or closes (GUI); prints ARMED / DETACHED:
  --no-verify-park  (park) disable snap-back detection (default ON in park): normally, after
             releasing a mob we re-read its real (controller-B) X at --verify-at offsets (default
             1,2.5,4 s); if it snapped > --verify-snap px from the slot it is owned by another
             client, so we tag that mobID foreign and skip it for --foreign-cooldown s. A mobID we
             already parked that reappears as a candidate within --repull-window s is also tagged
             foreign (snaps can lag). Tune: --verify-at 1,2.5,4 --verify-snap 350 --repull-window 30
Stop: Ctrl-C / kill -2. Nothing to restore: the game re-simulates A from its own state.
"""
import array, ctypes, importlib.util, json, math, signal, struct, sys, time
from pathlib import Path

WS = Path(__file__).resolve().parent
_s = importlib.util.spec_from_file_location('c', WS / 'locate-character.py')
ch = importlib.util.module_from_spec(_s); _s.loader.exec_module(ch)
prof = json.loads((WS / 'profile.json').read_text())
_sm = importlib.util.spec_from_file_location('mob_profile', WS / 'mob_profile.py')
mob_profile = importlib.util.module_from_spec(_sm); _sm.loader.exec_module(mob_profile)
# Build-specific CMob addresses live in profile.json's "mob_offsets" (single source
# of truth; re-derive in-game after a client update -- see mob_profile.py / README).
MOFF = mob_profile.load_mob_offsets(prof)
CMOB_VTABLE_RVA = MOFF['cmob_vtable_rva']
CTRL_A = MOFF['ctrl_a']
CTRL_B = MOFF['ctrl_b']
OFF_X, OFF_Y, OFF_Y2 = MOFF['x'], MOFF['y'], MOFF['y2']
# Controller-A integrator state (PM-28 dump): +0x1d0 = post-copy X (what is rendered/used after
# the per-frame copy), +0x1b8 = X velocity (mob AI walk speed), +0x1a0 = Y velocity. Writing only
# +0x170 lets the integrator re-advance X by v*dt every frame -> flicker. Pinning all of them holds still.
OFF_X_POST, OFF_VX, OFF_VY = MOFF['x_post'], MOFF['vx'], MOFF['vy']
# Controller B (server keyframe) extras: foothold-relative X (+0x248 pre, +0x278 post) and
# foothold-relative velocity (+0x260, +0x290). The game copies B -> A on every server mob-move
# keyframe (PM-29), so --hold-b keeps B at the forced spot too.
OFF_B_REL, OFF_B_REL2, OFF_B_VREL, OFF_B_VREL2 = MOFF['b_rel'], MOFF['b_rel2'], MOFF['b_vrel'], MOFF['b_vrel2']
# Movement-controller foothold slots (same layout as the player controller, profile
# controller_offsets): +0x2b0 = protected/encoded foothold pointer, +0x2c8 = plain pointer.
OFF_FH_ENC, OFF_FH_PLAIN = MOFF['fh_enc'], MOFF['fh_plain']
MOB_ID_OFF, HP_OFF = MOFF['mob_id'], MOFF['hp']
# CMob+0xaf0 == 1 when the server made THIS client the mob's controller (PM-67). Mobs another
# client controls snap back when pulled, so they're skipped up front (--no-own-filter disables).
CONTROLLED_OFF = MOFF['controlled']

args = sys.argv[1:]
pid = int(args[0]); dur = float(args[1])
DRY = '--dry' in args
if DRY:
    print('DRY-RUN: scanning, selection, and encoding only; all process writes are suppressed.', flush=True)
HOLD_Y = '--y' in args
# When pulling Y across platforms, a mob's own foothold pointer goes stale (it still
# references its origin platform) and the knockback/physics integrator walks that far-away
# foothold slope on the next hit -> client crash (PM-23). Repointing a Y-pulled mob to the
# PLAYER's foothold keeps position<->foothold consistent so the walk stays valid. On by
# default whenever --y is used; --no-fh disables it for A/B experiments.
FH_SYNC = HOLD_Y and '--no-fh' not in args
PIN = '--no-pin' not in args
HOLD_B = '--hold-b' in args
SPREAD = float(args[args.index('--spread') + 1]) if '--spread' in args else 0.0
RADIUS = float(args[args.index('--radius') + 1]) if '--radius' in args else math.inf
FRONT = float(args[args.index('--front') + 1]) if '--front' in args else 0.0
AUTO_FACE = '--no-auto-face' not in args
NO_TOP_UP = '--no-top-up' in args
# Chain mode (--count N with top-up): after a pulled mob dies, wait CHAIN_DELAY s before pulling
# the next, so a fresh mob never overlaps one still in its death animation (co-located mobs
# + hits = freeze/crash, PM-27/PM-31).
CHAIN_DELAY = float(args[args.index('--chain-delay') + 1]) if '--chain-delay' in args else 1.0
COUNT = int(args[args.index('--count') + 1]) if '--count' in args else 0
MIN_DIST = float(args[args.index('--min-dist') + 1]) if '--min-dist' in args else 0.0
RESCAN = float(args[args.index('--rescan') + 1]) if '--rescan' in args else 2.0
FAST_SCAN = float(args[args.index('--fast-scan') + 1]) if '--fast-scan' in args else 0.25
# On-screen gate: a mob is pulled only while its REAL (controller-B/server) position is
# within +-VIEW_W (X) and +-VIEW_H (Y) of the player. Defaults ~= half the 2560x1440
# viewport in world units; shrink with --view W H for a safety margin, --view 0 0 disables.
VIEW_W = float(args[args.index('--view') + 1]) if '--view' in args else 1200.0
VIEW_H = float(args[args.index('--view') + 2]) if '--view' in args else 680.0
chosen = []
# --park N: pull mobs one at a time, hold each PARK_HOLD s at its own slot along the player's
# foothold, then RELEASE it (never written again) and pull the next; exit after N parked.
PARK = '--park' in args
PARK_N = int(args[args.index('--park') + 1]) if '--park' in args else 0  # 0 = unlimited
PARK_HOLD = float(args[args.index('--park-hold') + 1]) if '--park-hold' in args else 2.5
PARK_GAP = float(args[args.index('--park-gap') + 1]) if '--park-gap' in args else 60.0
parked = {}      # obj -> mobID
park_slot = {}   # obj -> target X
chosen_at = {}
park_anchor = None
park_count = 0
_diag = [0.0]
FIXED_ANCHOR = '--fixed-anchor' in args
CONTROL_STDIN = '--control-stdin' in args
# Background scanner: default ON in park mode (--no-bg-scan to disable); RESCAN becomes
# the full-heap interval there (default raised to 5s), FAST_SCAN the hot-region interval.
BG_SCAN = ('--bg-scan' in args or PARK) and '--no-bg-scan' not in args
if BG_SCAN and '--rescan' not in args:
    RESCAN = 5.0
park_seq = 0     # monotonically increasing slot counter (parallel holds never share a slot)
# --pull-interval S: minimum seconds between consecutive pulls (staggers parallel holds so
# jumps are spread out instead of N at the same instant; caps the rate at 1/S).
PULL_INTERVAL = float(args[args.index('--pull-interval') + 1]) if '--pull-interval' in args else 0.0
last_pull_at = 0.0
# Verify-then-commit (snap-back detection for maps with other players). After a mob is
# released we re-read its REAL (controller-B) position once; if it snapped far from the
# target slot it belongs to another client (controllership is server-assigned per mob and
# only the controlling client's moves stick), so we tag that mobID foreign and skip it for
# a cooldown instead of wasting holds + DC budget on it. --no-verify-park disables.
VERIFY_PARK = PARK and '--no-verify-park' not in args
VERIFY_DELAY = float(args[args.index('--verify-delay') + 1]) if '--verify-delay' in args else 0.8
# Snap-backs can happen several seconds after release, so re-check real position at several
# offsets after release (comma list), not just once. The last offset bounds how long we watch.
VERIFY_AT = [float(x) for x in args[args.index('--verify-at') + 1].split(',')] if '--verify-at' in args else [1.0, 2.5, 4.0]
VERIFY_SNAP = float(args[args.index('--verify-snap') + 1]) if '--verify-snap' in args else 350.0
FOREIGN_COOLDOWN = float(args[args.index('--foreign-cooldown') + 1]) if '--foreign-cooldown' in args else 20.0
# A mobID we already parked that reappears as a candidate within this window snapped back
# (timing-independent snap signal): tag it foreign without waiting for a verify re-read.
REPULL_WINDOW = float(args[args.index('--repull-window') + 1]) if '--repull-window' in args else 30.0
# --no-foreign-skip: keep detecting/logging snap-backs but DON'T exclude those mobIDs from
# pulling. The foreign set otherwise only grows while running (owned mobs that patrol >VERIFY_SNAP
# or re-enter range get tagged and the cooldown keeps refreshing), which starves throughput until
# a restart clears it. This switch lets the operator A/B that effect live from the GUI.
FOREIGN_SKIP = '--no-foreign-skip' not in args
OWN_FILTER = '--no-own-filter' not in args
# --invert-own: pull ONLY mobs we do NOT control (+0xaf0 != 1). Hypothesis test (PM-69): our
# client only REPORTS moves for mobs it controls, so moving un-controlled mobs should send no
# mob-move packet -> no server-side DC-3 violation. Likely trade-off: the server overrides our
# writes for un-controlled mobs (snap-back), so they may not actually suck. Pure diagnostic.
INVERT_OWN = '--invert-own' in args
skipped_unowned = 0
verify_pending = {}   # obj -> (release_t, slot_x, mobID, [remaining_offsets])
foreign_ids = {}      # mobID -> cooldown_until_monotonic
parked_ids = {}       # mobID -> last parked monotonic (for re-pull snap detection)
skipped_foreign = 0   # candidate skips because mobID is on foreign cooldown
skipped_repull = 0    # candidate skips because a parked mobID reappeared (re-pull signal)
last_diag = 0.0       # periodic throughput/foreign-set diagnostic
# --own-dump PATH: snapshot CMob + controller-B bytes at pull time (pre-hold), label each with
# the verify verdict, write JSON at exit -> offline diff to locate the mob-ownership field.
OWN_DUMP = args[args.index('--own-dump') + 1] if '--own-dump' in args else None
own_pre = {}          # obj -> (mobID, cmob_hex, ctrlB_hex)
own_recs = []
stuck_ok = 0          # parks confirmed stuck
snapped = 0           # parks detected snapped back (foreign)
ever_chosen = False
FACING = -1 if '--face' in args and args[args.index('--face') + 1] == 'left' else 1
# --glide PXS: move each pulled mob toward its slot at PXS px/s instead of teleporting it there in
# one frame. Our client reports controlled mobs' movement to the server; whole-map teleports look
# like impossible mob speed and are the suspected cause of the delayed park disconnect (PM-68).
# The park hold timer starts on ARRIVAL. 0 = legacy teleport.
GLIDE = float(args[args.index('--glide') + 1]) if '--glide' in args else 0.0
# --glide-hz N: cap how often glide actually advances AND re-writes a mob's commanded position.
# The main loop runs ~2000Hz; unthrottled glide therefore writes ~1000x/s per travelling mob (huge
# write-volume spike vs teleport's one-shot). Suspected to trip a tamper/integrity write-rate check
# (PM-68 hard crash). Throttling to e.g. 15Hz keeps motion smooth with ~60x fewer writes. 0 = every loop.
GLIDE_HZ = float(args[args.index('--glide-hz') + 1]) if '--glide-hz' in args else 15.0
glide_pos = {}    # obj -> [x, y] current commanded position
glide_t = {}      # obj -> last advance time
glide_wrote = {}  # obj -> last time its write-round ran (throttle gate while travelling)
arrived_at = {}   # obj -> monotonic arrival at slot
pull_from = {}    # obj -> (x, y, t) at pull


def held_for(m, now):
    if GLIDE:
        return now - arrived_at[m] if m in arrived_at else -1.0
    return now - chosen_at.get(m, now)


def glide_step(m, tx, ty, now):
    pos = glide_pos.get(m)
    if pos is None:
        return tx, ty
    dt = min(0.1, now - glide_t.get(m, now)); glide_t[m] = now
    step = GLIDE * dt
    for i, target in ((0, tx), (1, ty)):
        if target is None:
            continue
        d = target - pos[i]
        pos[i] = target if abs(d) <= step else pos[i] + math.copysign(step, d)
    if m not in arrived_at and abs(pos[0] - tx) < 1 and (ty is None or abs(pos[1] - ty) < 1):
        arrived_at[m] = now
        fx, fy, ft = pull_from.get(m, (pos[0], pos[1], now))
        print(f'  ARRIVED mob {chosen_id.get(m, 0):#08x} dist={math.hypot(tx - fx, (ty if ty is not None else fy) - fy):.0f} '
              f'travel={now - ft:.2f}s', flush=True)
    return pos[0], (pos[1] if ty is not None else None)


# --log PATH: tee all output to PATH with wall-clock timestamps (DC forensics).
if '--log' in args:
    class _Tee:
        def __init__(self, path):
            self.f = open(path, 'a', buffering=1); self.o = sys.stdout; self.bol = True
        def write(self, s):
            self.o.write(s)
            for line in s.splitlines(True):
                if self.bol:
                    self.f.write(time.strftime('%H:%M:%S') + f'.{int(time.time() * 1000) % 1000:03d} ')
                self.f.write(line); self.bol = line.endswith('\n')
        def flush(self):
            self.o.flush(); self.f.flush()
    sys.stdout = _Tee(args[args.index('--log') + 1])
    print('LOG ' + ' '.join(sys.argv), flush=True)


class _Iov(ctypes.Structure):
    _fields_ = [('base', ctypes.c_void_p), ('len', ctypes.c_size_t)]


_libc = ctypes.CDLL(None, use_errno=True)
_libc.process_vm_writev.restype = ctypes.c_ssize_t


def vm_write(addr, data):
    if DRY:
        return True
    buf = ctypes.create_string_buffer(bytes(data), len(data))
    local = _Iov(ctypes.cast(buf, ctypes.c_void_p), len(data))
    remote = _Iov(addr, len(data))
    return _libc.process_vm_writev(pid, ctypes.byref(local), 1, ctypes.byref(remote), 1, 0) == len(data)


r = ch.Reader(pid)
base, _ = ch.find_image(r, pid, prof)
MOB_VT = base + CMOB_VTABLE_RVA


def dec(w):
    try:
        return r.protected(w, 8)['value']
    except Exception:
        return None


def enc_write(w, val):
    """Re-encode `val` into the protected double at wrapper w (same scheme as Reader.protected)."""
    try:
        bk = r.qword(w + 8)
        blk = bytearray(r.read(bk, 16))
        key = blk[8]; cs = 0x9A65; out = bytearray()
        for p in struct.pack('<d', val):
            key = key or 42; e = p ^ key; out.append(e); key = (e + key + 42) & 255
            cs = (((cs >> 13) + key) | (cs << 3)) & 0xFFFF
        if r.qword(w + 8) != bk:
            return False
        blk[0:8] = out; blk[12:14] = struct.pack('<H', cs)
        return vm_write(bk, blk[:14])
    except Exception:
        return False


def _rotr5(v):
    return ((v >> 5) | (v << 27)) & 0xFFFFFFFF


def encode_pointer(slot20, value):
    """Re-encode `value` into a 20-byte protected_pointer block, keeping the slot's seeds a,b.
    Inverse of Reader.protected_pointer: value_low = rotl5(c)^a  ->  c = rotr5(value_low ^ a)."""
    a, b, _c, _d, _exp = struct.unpack('<IIIII', slot20)
    lo, hi = value & 0xFFFFFFFF, (value >> 32) & 0xFFFFFFFF
    c = _rotr5(lo ^ a)
    d = _rotr5(hi ^ b)
    checksum = (_rotr5(0xBAADF00D ^ a) + c) & 0xFFFFFFFF
    checksum = (_rotr5(checksum ^ b) + d) & 0xFFFFFFFF
    return struct.pack('<IIIII', a, b, c, d, checksum)


def set_mob_foothold(ca, value):
    """Point a mob's movement controller at foothold pointer `value` (encoded slot + plain slot)."""
    try:
        slot = r.read(ca + OFF_FH_ENC, 20)
        if r.protected_pointer(ca + OFF_FH_ENC) == value:
            return None  # already synced
    except Exception:
        try:
            slot = r.read(ca + OFF_FH_ENC, 20)
        except Exception:
            return False
    ok = vm_write(ca + OFF_FH_ENC, encode_pointer(slot, value))
    ok &= vm_write(ca + OFF_FH_PLAIN, struct.pack('<Q', value))
    return ok


def rw_regions():
    out = []
    for line in open(f'/proc/{pid}/maps'):
        a, perm = line.split()[:2]
        lo, hi = (int(x, 16) for x in a.split('-'))
        if 'rw' not in perm or hi - lo > 512 << 20 or lo >= 0x7f0000000000:
            continue
        out.append((lo, hi))
    return out


def scan_mobs(regions=None, hot_out=None):
    """Find CMob objects by vtable. ``regions`` limits the scan (hot-region fast path);
    regions that contained a mob are added to ``hot_out``."""
    found = []
    needle = struct.pack('<Q', MOB_VT)
    for lo, hi in (rw_regions() if regions is None else regions):
        try:
            d = r.read(lo, hi - lo)
        except Exception:
            continue
        j = d.find(needle)
        while j != -1:
            if j % 8 == 0:
                found.append(lo + j)
                if hot_out is not None:
                    hot_out.add((lo, hi))
            j = d.find(needle, j + 8)
    good = []
    for m in found:
        try:
            ca = r.qword(m + CTRL_A) - 0x20
        except Exception:
            continue
        x, y = dec(ca + OFF_X), dec(ca + OFF_Y)
        if x is not None and y is not None and abs(x) < 1e5 and abs(y) < 1e5:
            good.append(m)
    return good


# Background scanner (--bg-scan, default in park mode): a forked process scans the
# few heap regions that hold CMobs every FAST_SCAN s and the whole rw heap every
# RESCAN s, sending the mob list over a pipe. It has its own GIL, so a scan can never
# stall the write loop mid-hold (the cause of PM-43 snap-backs) and new spawns are
# seen in ~FAST_SCAN instead of only after a starved full rescan.
def _scanner_main(conn, fast, full):
    import os as _os
    # Inherited park handlers would swallow terminate(); restore defaults so the
    # parent can always stop us, and ignore Ctrl-C (the parent handles it).
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    hot = set()
    last_full = 0.0
    parent = _os.getppid()
    while _os.getppid() == parent:
        t = time.monotonic()
        is_full = not hot or t - last_full >= full
        found_hot = set()
        try:
            good = scan_mobs(None if is_full else sorted(hot), found_hot)
        except Exception:
            good = None
        if good is not None:
            hot = found_hot if is_full else (hot | found_hot)
            if is_full:
                last_full = t
            try:
                conn.send((good, is_full, time.monotonic() - t))
            except (BrokenPipeError, EOFError, OSError):
                return
        time.sleep(max(0.0, (fast if hot else 1.0) - (time.monotonic() - t)))


def start_bg_scanner(fast, full):
    import multiprocessing as mp
    ctx = mp.get_context('fork')
    parent_conn, child_conn = ctx.Pipe(duplex=False)
    proc = ctx.Process(target=_scanner_main, args=(child_conn, fast, full), daemon=True)
    proc.start()
    child_conn.close()
    return proc, parent_conn


def player_pos():
    global PLAYER_CTRL
    for _ in range(50):
        try:
            sn = ch.snapshot(r, pid, base, prof)
            PLAYER_CTRL = int(sn['controller'], 16)
            return sn['cached_x']['value'], sn['cached_y']['value']
        except Exception:
            time.sleep(0.01)
    return None


PLAYER_CTRL = None


def fh_x1(ptr):
    try:
        return float(r.unpack('<i', ptr)[0]) if ptr else None
    except Exception:
        return None


def player_foothold():
    """Current player foothold pointer value (the target footing for Y-pulled mobs)."""
    if PLAYER_CTRL is None:
        return None
    try:
        return r.protected_pointer(PLAYER_CTRL + OFF_FH_ENC)
    except Exception:
        return None


stop = False
signal.signal(signal.SIGINT, lambda *a: globals().__setitem__('stop', True))
signal.signal(signal.SIGTERM, lambda *a: globals().__setitem__('stop', True))


def _stdin_control():
    for line in sys.stdin:
        if line.strip() == 'stop':
            break
    globals()['stop'] = True


if CONTROL_STDIN:
    import threading
    threading.Thread(target=_stdin_control, daemon=True).start()

def mob_xy(m):
    try:
        ca = r.qword(m + CTRL_A) - 0x20
        return dec(ca + OFF_X), dec(ca + OFF_Y)
    except Exception:
        return None, None


def mob_real_xy(m):
    """Real/server mob position from controller B (we never overwrite B)."""
    try:
        cb = r.qword(m + CTRL_B) - 0x20
        return dec(cb + OFF_X), dec(cb + OFF_Y)
    except Exception:
        return None, None


def _tag_foreign(mid, rx, slot_x, reason):
    global snapped
    if foreign_ids.get(mid, 0) <= time.monotonic():
        snapped += 1
        print(f'  SNAP-BACK mob {mid:#08x} realX={rx if rx is None else f"{rx:.0f}"} '
              f'slot={slot_x:.0f} ({reason}) -> foreign, skip {FOREIGN_COOLDOWN:.0f}s', flush=True)
    foreign_ids[mid] = time.monotonic() + FOREIGN_COOLDOWN


def verify_parks():
    """Idea B: re-read each released mob's REAL (controller-B) position at several offsets after
    release (snap-backs can lag a few seconds). If it snapped far from its slot the mob is owned
    by another client (controllership is server-assigned per mob); tag that mobID foreign so we
    stop re-pulling it (re-pulls waste holds + DC budget). The first offset that confirms a
    verdict settles that mob."""
    global stuck_ok
    if not VERIFY_PARK or not verify_pending:
        return
    now = time.monotonic()
    for m in list(verify_pending):
        rel_t, slot_x, mid, offs = verify_pending[m]
        if not offs or now < rel_t + offs[0]:
            continue
        offs.pop(0)  # this checkpoint is due
        pre = own_pre.get(m)
        if not alive(m) or mob_id(m) != mid:
            verify_pending.pop(m, None); own_pre.pop(m, None)
            continue  # killed/reused before we could check: treat as fine (not counted)
        rx, _ry = mob_real_xy(m)
        if rx is None:
            if not offs:
                verify_pending.pop(m, None); own_pre.pop(m, None)
            continue
        if abs(rx - slot_x) > VERIFY_SNAP:
            if pre and pre[0] == mid:
                own_recs.append({'mid': mid, 'verdict': 'snapped', 'd': abs(rx - slot_x), 'cmob': pre[1], 'cb': pre[2]})
            _tag_foreign(mid, rx, slot_x, f'd={abs(rx - slot_x):.0f}')
            verify_pending.pop(m, None); own_pre.pop(m, None)
        elif not offs:  # survived every checkpoint at its slot -> genuinely stuck
            stuck_ok += 1
            if pre and pre[0] == mid:
                own_recs.append({'mid': mid, 'verdict': 'stuck', 'd': abs(rx - slot_x), 'cmob': pre[1], 'cb': pre[2]})
            verify_pending.pop(m, None); own_pre.pop(m, None)


def on_screen(m, pp):
    if not VIEW_W and not VIEW_H:
        return True
    x, y = mob_real_xy(m)
    if x is None or y is None:
        return False
    return abs(x - pp[0]) <= VIEW_W and abs(y - pp[1]) <= VIEW_H


dead = set()
next_pull_at = 0.0
kills = 0
chosen_id = {}


def owned(m):
    try:
        return r.unpack('<I', m + CONTROLLED_OFF)[0] == 1
    except Exception:
        return False


def mob_id(m):
    try:
        return r.qword(m + MOB_ID_OFF) & 0xFFFFFF
    except Exception:
        return None


dying_since = {}
dying_since_logged = set()


def hp_pct(m):
    try:
        return r.qword(m + HP_OFF) & 0xFFFFFFFF
    except Exception:
        return 0


released = set()


def dying(m):
    """CMob death state seen ~0.4s before free: +0x4e4 0->1, +0x504 0->2, +0x50c.. -> 0x7fffffff."""
    try:
        d = r.read(m + 0x4e4, 0x30)
    except Exception:
        return True
    a, b, c = struct.unpack_from('<I', d, 0)[0], struct.unpack_from('<I', d, 0x20)[0], struct.unpack_from('<I', d, 0x28)[0]
    return a != 0 or b != 0 or c == 0x7fffffff


def alive(m):
    """Object still a live CMob (freed/reused memory loses the vtable or controller decode)."""
    try:
        if r.qword(m) != MOB_VT:
            return False
        cb = r.qword(m + CTRL_B) - 0x20
        return dec(cb + OFF_X) is not None
    except Exception:
        return False


def select(all_mobs, pp):
    """Keep previously chosen mobs that still exist AND stay on screen; top up with nearest."""
    global chosen, ever_chosen, kills, next_pull_at, skipped_foreign, skipped_repull
    visible = [m for m in all_mobs if alive(m) and on_screen(m, pp)]
    if not COUNT:
        if INVERT_OWN:
            return [m for m in visible if not owned(m)]
        return [m for m in visible if owned(m)] if OWN_FILTER else visible
    if PARK:
        global stop
        for m in list(chosen):
            held = held_for(m, time.monotonic())
            if held >= PARK_HOLD and not (alive(m) and not dying(m)) and time.monotonic() - _diag[0] > 1.0:
                _diag[0] = time.monotonic()
                print(f'  PARK-WAIT mob {chosen_id.get(m, 0):#08x} held={held:.1f}s alive={alive(m)} dying={dying(m)}', flush=True)
            if held >= PARK_HOLD and alive(m) and not dying(m):
                chosen.remove(m)
                parked[m] = chosen_id.get(m, 0)
                released.add(m)
                global park_count
                park_count += 1
                mid_rel = chosen_id.get(m, 0)
                if VERIFY_PARK:
                    verify_pending[m] = (time.monotonic(), park_slot.get(m, 0.0),
                                         mid_rel, list(VERIFY_AT))
                parked_ids[mid_rel] = time.monotonic()
                print(f'  PARKED #{park_count} mob {parked[m]:#08x} at X={park_slot.get(m, 0):.0f} held={held:.1f}s t={time.monotonic():.1f} -> released', flush=True)
        if PARK_N > 0 and park_count >= PARK_N and not chosen:
            stop = True
            return []
        visible = [m for m in visible if not (m in parked and mob_id(m) == parked[m])]
    keep = []
    for m in chosen:
        if m in visible and mob_id(m) == chosen_id.get(m):
            keep.append(m)
        elif (alive(m) and mob_id(m) == chosen_id.get(m)
              and time.monotonic() - dying_since.setdefault(m, time.monotonic()) < 4.0):
            if m not in dying_since_logged:
                dying_since_logged.add(m)
                print(f'  HOLD-OFF mob {chosen_id.get(m, 0):#08x} still exists (hp={hp_pct(m)} vis={m in visible}); waiting for free', flush=True)
            # dying but not freed yet: never pull a 2nd mob onto it (stacked-hit crash)
            return list(chosen)
        else:
            kills += 1
            next_pull_at = time.monotonic() + CHAIN_DELAY
            print(f'  CHAIN pulled mob {chosen_id.get(m, 0):#08x} gone (#{kills}); next in {CHAIN_DELAY}s', flush=True)
            chosen_id.pop(m, None); dying_since.pop(m, None)
    chosen = keep
    if NO_TOP_UP and ever_chosen:
        return list(chosen)
    if time.monotonic() < next_pull_at:
        return list(chosen)
    cands = []
    for m in visible:
        if m in chosen:
            continue
        mid = mob_id(m)
        now_m = time.monotonic()
        if INVERT_OWN:
            # test mode: pull ONLY mobs we do NOT control (never report their moves)
            if owned(m):
                global skipped_unowned
                skipped_unowned += 1
                continue
        elif OWN_FILTER:
            # Ownership is read directly, so the snap-back heuristics (which only ever grow a
            # blacklist and starve throughput) are bypassed: pull iff we control it right now.
            if not owned(m):
                skipped_unowned += 1
                continue
        elif foreign_ids.get(mid, 0) > now_m:
            skipped_foreign += 1
            if FOREIGN_SKIP:
                continue  # known foreign (snapped back); skip until cooldown expires
        parked_at = parked_ids.get(mid)
        if not OWN_FILTER and parked_at is not None and now_m - parked_at < REPULL_WINDOW:
            # we already parked this mobID and here it is back in candidate range -> it snapped
            # back (timing-independent signal); tag foreign and skip instead of re-pulling it.
            rx, _ry = mob_real_xy(m)
            _tag_foreign(mid, rx, park_slot.get(m, 0.0), 're-pull')
            skipped_repull += 1
            if FOREIGN_SKIP:
                continue
        x, y = mob_xy(m)
        if x is None or y is None:
            continue
        d = math.hypot(x - pp[0], y - pp[1])
        if d >= MIN_DIST:
            cands.append((d, m))
    if PARK and not cands and not chosen and time.monotonic() - _diag[0] > 1.0:
        _diag[0] = time.monotonic()
        nxy = sum(1 for m in visible if None in mob_xy(m))
        print(f'  NO-CAND all={len(all_mobs)} alive={sum(1 for m in all_mobs if alive(m))} '
              f'eligible={len(visible)} xy_none={nxy} too_close={len(visible) - nxy}', flush=True)
    for _d, m in sorted(cands)[:COUNT - len(chosen)]:
        global last_pull_at
        if PULL_INTERVAL and time.monotonic() - last_pull_at < PULL_INTERVAL:
            break
        last_pull_at = time.monotonic()
        chosen.append(m)
        ever_chosen = True
        mid = mob_id(m) or 0
        chosen_id[m] = mid; released.discard(m); chosen_at[m] = time.monotonic()
        arrived_at.pop(m, None)
        glide_wrote.pop(m, None)
        if GLIDE:
            gx, gy = mob_xy(m)
            if gx is not None and gy is not None:
                glide_pos[m] = [gx, gy]; glide_t[m] = time.monotonic()
                pull_from[m] = (gx, gy, time.monotonic())
        if OWN_DUMP:
            try:
                cbp = r.qword(m + CTRL_B) - 0x20
                own_pre[m] = (mid, r.read(m, 0x1100).hex(), r.read(cbp, 0x300).hex())
            except Exception:
                pass
        if PARK:
            global park_anchor, PLAYER_FH
            lp = None if FIXED_ANCHOR else player_pos()
            if lp:
                park_anchor = lp[0]
                PLAYER_FH = player_foothold() or PLAYER_FH
            global park_seq
            k = park_seq % 10
            park_seq += 1
            off = ((k // 2) + 1) * PARK_GAP * (1 if k % 2 == 0 else -1)
            sx = park_anchor + off
            try:
                x1, x2 = sorted((float(r.unpack('<i', PLAYER_FH)[0]), float(r.unpack('<i', PLAYER_FH + 8)[0])))
                sx = min(max(sx, x1 + 15), x2 - 15)
            except Exception:
                pass
            park_slot[m] = sx
        print(f'  CHOSEN obj {m:#x} mobID={mid:#08x} dist={_d:.0f} t={time.monotonic():.1f}', flush=True)
    return list(chosen)


pp = player_pos()
if pp is None:
    raise SystemExit('cannot read player position')
park_anchor = pp[0]
PLAYER_FH = player_foothold() if PARK else None
if PARK and PLAYER_FH:
    print(f'park foothold x1..x2 = {r.unpack("<i", PLAYER_FH)[0]}..{r.unpack("<i", PLAYER_FH + 8)[0]} anchor={park_anchor:.0f}', flush=True)
all_mobs = scan_mobs()
mobs = select(all_mobs, pp)
print(f'VAC pid={pid} player=({pp[0]:.0f},{pp[1]:.0f}) mobs={len(all_mobs)} pulling={len(mobs)} hold_y={HOLD_Y} '
      f'fh_sync={FH_SYNC} pin={PIN} hold_b={HOLD_B} spread={SPREAD} front={FRONT} face={FACING} view=({VIEW_W},{VIEW_H}) no_top_up={NO_TOP_UP} dur={dur}s', flush=True)
for m in mobs:
    ca = r.qword(m + CTRL_A) - 0x20
    mid = r.qword(m + MOB_ID_OFF) & 0xFFFFFF
    print(f'  mob obj={m:#x} mobID={mid:#08x} A=({dec(ca + OFF_X):.0f},{dec(ca + OFF_Y):.0f})', flush=True)

# encoder self-test on the first mob: write X back unchanged, confirm decode
if mobs:
    w = r.qword(mobs[0] + CTRL_A) - 0x20 + OFF_X
    x0 = dec(w)
    assert x0 is not None and enc_write(w, x0) and abs(dec(w) - x0) < 1e-6, 'encoder self-test failed'
    print('encoder self-test OK', flush=True)

# pointer-encoder self-test: re-encode the first mob's OWN foothold pointer and confirm it
# round-trips through protected_pointer before we ever point a mob at the player's foothold.
if mobs:
    ca0 = r.qword(mobs[0] + CTRL_A) - 0x20
    try:
        fh0 = r.protected_pointer(ca0 + OFF_FH_ENC)
        slot0 = r.read(ca0 + OFF_FH_ENC, 20)
        a, b = struct.unpack_from('<II', slot0)
        reslot = encode_pointer(slot0, fh0)
        ra, rb, rc, rd, rexp = struct.unpack('<IIIII', reslot)
        lo, hi = fh0 & 0xFFFFFFFF, (fh0 >> 32) & 0xFFFFFFFF
        rt = (((rc << 5 | rc >> 27) & 0xFFFFFFFF) ^ ra) | ((((rd << 5 | rd >> 27) & 0xFFFFFFFF) ^ rb) << 32)
        assert ra == a and rb == b and rt == fh0, 'pointer-encoder round-trip failed'
        print(f'pointer-encoder self-test OK (fh={fh0:#x})', flush=True)
    except Exception as e:
        print(f'pointer-encoder self-test skipped: {e!r}', flush=True)

PLAYER_FH = player_foothold() if FH_SYNC else None
PLAYER_FH_X1 = fh_x1(PLAYER_FH)
if FH_SYNC:
    print(f'player foothold = {PLAYER_FH:#x}' if PLAYER_FH else 'player foothold UNREADABLE', flush=True)

PROBE = args[args.index('--probe-death') + 1] if '--probe-death' in args else None
probe_snaps = []; last_probe = 0.0
TRACE = '--trace' in args; last_trace = 0.0
if PARK:
    print(f'ARMED park anchor=({pp[0]:.0f},{pp[1]:.0f}) fixed={FIXED_ANCHOR} hold={PARK_HOLD}s gap={PARK_GAP}px', flush=True)
t0 = time.monotonic(); last_scan = t0; last_pp = t0
writes = fails = flips = vanished = spawned = 0
bg_proc = bg_conn = None
bg_fast = bg_full = 0
bg_time = 0.0
if BG_SCAN:
    bg_proc, bg_conn = start_bg_scanner(FAST_SCAN, RESCAN)
    print(f'bg-scan started pid={bg_proc.pid} fast={FAST_SCAN}s full={RESCAN}s', flush=True)
try:
    while not stop and time.monotonic() - t0 < dur:
        now = time.monotonic()
        verify_parks()
        if now - last_diag >= 5.0:
            last_diag = now
            active_foreign = sum(1 for t in foreign_ids.values() if t > now)
            print(f'  DIAG t={now - t0:.1f}s parked={park_count} chosen={len(chosen)} '
                  f'mobs={len(all_mobs)} foreign_active={active_foreign}/{len(foreign_ids)} '
                  f'stuck_ok={stuck_ok} snapped={snapped} skip_foreign={skipped_foreign} '
                  f'skip_repull={skipped_repull} filter={"on" if FOREIGN_SKIP else "OFF"} '
                  f'owned={sum(1 for m in all_mobs if owned(m))}/{len(all_mobs)} skip_unowned={skipped_unowned} '
                  f'own_filter={"on" if OWN_FILTER else "OFF"} '
                  f'writes={writes} w/s={writes / max(0.1, now - t0):.0f}'
                  f'{f" glide={GLIDE:.0f}px/s@{GLIDE_HZ:.0f}Hz" if GLIDE else ""}', flush=True)
        if PARK and any(held_for(m, now) >= PARK_HOLD for m in chosen):
            mobs = select(all_mobs, pp)
        holding = PARK and any(held_for(m, now) < PARK_HOLD for m in chosen)
        new = None
        if bg_conn is not None:
            try:
                while bg_conn.poll():
                    new, was_full, took = bg_conn.recv()
                    if was_full: bg_full += 1
                    else: bg_fast += 1
                    bg_time += took
            except (EOFError, OSError):
                print('bg-scan pipe closed; falling back to inline rescan', flush=True)
                bg_conn = None
        elif now - last_scan > RESCAN and not holding:
            new = scan_mobs()
        if new is not None:
            last_scan = now
            gone = set(all_mobs) - set(new); born = set(new) - set(all_mobs)
            lost = [m for m in mobs if m not in new]
            for m in lost:
                print(f'  PULLED MOB GONE {m:#x}', flush=True)
            vanished += len(gone); spawned += len(born); all_mobs = new
            mobs = select(all_mobs, pp)
            if gone or born or bg_conn is None:
                print(f't={now - t0:.1f}s rescan mobs={len(all_mobs)} pulling={len(mobs)} gone={len(gone)} new={len(born)} '
                      f'writes={writes} fails={fails}', flush=True)
        if now - last_pp > 0.05 and FIXED_ANCHOR:
            last_pp = now
            mobs = select(all_mobs, pp)
        elif now - last_pp > 0.05:
            npp = player_pos() or pp; last_pp = now
            if FH_SYNC:
                PLAYER_FH = player_foothold()
                PLAYER_FH_X1 = fh_x1(PLAYER_FH)
            if AUTO_FACE and abs(npp[0] - pp[0]) > 1.5:
                nf = 1 if npp[0] > pp[0] else -1
                if nf != FACING:
                    FACING = nf; flips += 1
            pp = npp
            mobs = select(all_mobs, pp)
        px, py = pp
        if TRACE and now - last_trace > 0.25:
            last_trace = now
            for m in mobs:
                try:
                    ca = r.qword(m + CTRL_A) - 0x20; cb = r.qword(m + CTRL_B) - 0x20
                    rx = struct.unpack('<i', r.read(cb + 0x324, 4))[0]
                    ax, ay, bx, by = dec(ca + OFF_X), dec(ca + OFF_Y), dec(cb + OFF_X), dec(cb + OFF_Y)
                    f = lambda v: 'None' if v is None else f'{v:.0f}'
                    print(f'  TRACE t={now - t0:.2f} mob {chosen_id.get(m, 0):#08x} A=({f(ax)},{f(ay)}) B=({f(bx)},{f(by)}) realX={rx} hp={hp_pct(m)} player=({px:.0f},{py:.0f})', flush=True)
                except Exception as e:
                    print(f'  TRACE err {e}', flush=True)
        if PROBE and now - last_probe > 0.1:
            last_probe = now
            for m in mobs:
                try:
                    probe_snaps.append((now - t0, m, chosen_id.get(m, 0), r.read(m, 0x1000).hex()))
                except Exception:
                    probe_snaps.append((now - t0, m, chosen_id.get(m, 0), None))
        park_ready = PARK and any(held_for(m, now) >= PARK_HOLD for m in mobs)
        if COUNT and (not mobs or park_ready or any(m in released for m in mobs)
                      or any(not alive(m) or mob_id(m) != chosen_id.get(m) for m in mobs)):
            mobs = select(all_mobs, pp)
        for i, m in enumerate(mobs):
            if m in released:
                continue
            if dying(m):
                released.add(m)
                print(f'  DYING mob {chosen_id.get(m, 0):#08x} t={now - t0:.2f} -> writes stopped', flush=True)
                continue
            if not on_screen(m, pp):
                continue
            try:
                ca = r.qword(m + CTRL_A) - 0x20
            except Exception:
                continue
            x = dec(ca + OFF_X)
            if x is None or abs(x - px) > RADIUS:
                continue
            if GLIDE and GLIDE_HZ > 0 and m in glide_pos and m not in arrived_at:
                if now - glide_wrote.get(m, 0.0) < 1.0 / GLIDE_HZ:
                    continue   # throttle: skip this mob's entire write round until next glide tick
                glide_wrote[m] = now
            tx = park_slot.get(m, px) if PARK else px + FACING * FRONT + (SPREAD * ((i % 5) - 2) / 2 if SPREAD else 0.0)
            ty = py
            if GLIDE:
                tx, gy = glide_step(m, tx, py if HOLD_Y else None, now)
                if gy is not None:
                    ty = gy
            if abs(x - tx) > 0.5:
                if enc_write(ca + OFF_X, tx): writes += 1
                else: fails += 1
            if PIN:
                for off, val in ((OFF_X_POST, tx), (OFF_VX, 0.0), (OFF_VY, 0.0)):
                    v = dec(ca + off)
                    if v is not None and abs(v - val) > 0.5:
                        if enc_write(ca + off, val): writes += 1
                        else: fails += 1
            if HOLD_Y:
                if FH_SYNC and PLAYER_FH:
                    res = set_mob_foothold(ca, PLAYER_FH)
                    if res is True: writes += 1
                    elif res is False: fails += 1
                for off in (OFF_Y, OFF_Y2):
                    y = dec(ca + off)
                    if y is not None and abs(y - ty) > 0.5:
                        if enc_write(ca + off, ty): writes += 1
                        else: fails += 1
            if HOLD_B:
                try:
                    cb = r.qword(m + CTRL_B) - 0x20
                except Exception:
                    cb = None
                if cb:
                    if FH_SYNC and PLAYER_FH:
                        res = set_mob_foothold(cb, PLAYER_FH)
                        if res is True: writes += 1
                        elif res is False: fails += 1
                    vals = [(OFF_X, tx), (OFF_X_POST, tx), (OFF_VX, 0.0), (OFF_VY, 0.0),
                            (OFF_B_VREL, 0.0), (OFF_B_VREL2, 0.0)]
                    if PLAYER_FH_X1 is not None:
                        vals += [(OFF_B_REL, tx - PLAYER_FH_X1), (OFF_B_REL2, tx - PLAYER_FH_X1)]
                    if HOLD_Y:
                        vals += [(OFF_Y, ty), (OFF_Y2, ty)]
                    for off, val in vals:
                        v = dec(cb + off)
                        if v is not None and abs(v - val) > 0.5:
                            if enc_write(cb + off, val): writes += 1
                            else: fails += 1
        time.sleep(0.0005)
finally:
    r.close()
    if bg_proc is not None:
        bg_proc.terminate()
        bg_proc.join(1.0)
        if bg_proc.is_alive():
            bg_proc.kill()
            bg_proc.join(1.0)
        print(f'bg-scan stopped: fast={bg_fast} full={bg_full} avg={bg_time / max(1, bg_fast + bg_full):.3f}s', flush=True)
    if OWN_DUMP:
        json.dump(own_recs, open(OWN_DUMP, 'w'))
        print(f'own-dump: {len(own_recs)} labelled snapshots -> {OWN_DUMP}', flush=True)
    if PROBE:
        import json
        json.dump(probe_snaps, open(PROBE, 'w'))
        print(f'probe: {len(probe_snaps)} snaps -> {PROBE}', flush=True)
    print(f'STOPPED t={time.monotonic() - t0:.1f}s parked={park_count} chain_kills={kills} mobs={len(mobs)} writes={writes} fails={fails} facing_flips={flips} vanished={vanished} spawned={spawned} stuck_ok={stuck_ok} snapped={snapped} foreign={len(foreign_ids)} skip_foreign={skipped_foreign} skip_repull={skipped_repull}', flush=True)
print('DETACHED: dry-run complete; no process memory was written.' if DRY else 'DETACHED: vac stopped cleanly (nothing to restore)', flush=True)
