"""Route B server-authority test: at the melee send-site (RVA 0x2979607, rcx=COutPacket*),
rewrite the outbound 0xe1 target mobID+position to a far (out-of-range) decoy mob.
First trap = no-op self-test (rewrite same value + read-back). Subsequent traps = swap.
Edits are transient (next packet rebuilt from game state). usage: edit-melee-swap.py PID SECONDS OUT.json
"""
import ctypes, importlib.util, json, os, signal, struct, sys, time, array
from pathlib import Path
WS=Path(__file__).resolve().parent
def load(n,p):
    s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
observer=load('reset_observer',WS/'observe-position-reset.py'); shared=load('attack_observer',WS/'overhead-attacks.py')
ch=observer.character; prof=json.loads((WS/'profile.json').read_text())
pid=int(sys.argv[1]); dur=float(sys.argv[2]); out=sys.argv[3]
EMODE=sys.argv[4] if len(sys.argv)>4 else 'far'   # far=distant decoy; cycle=rotate on-screen; near=nearest in-range mob
UNTIL_DC = (len(sys.argv)>5 and sys.argv[5]=='untildc')
import glob as _glob
def chan_inodes():
    """map socket-inode->dst for this pid's game-channel TCP conns (remote port 85xx)."""
    try: fds=_glob.glob(f'/proc/{pid}/fd/*')
    except Exception: return {}
    socks=set()
    for f in fds:
        try:
            l=os.readlink(f)
            if l.startswith('socket:['): socks.add(l[8:-1])
        except Exception: pass
    out={}
    try:
        for line in open('/proc/net/tcp'):
            p=line.split()
            if len(p)<10 or p[3]!='01': continue  # ESTABLISHED
            ino=p[9]
            if ino not in socks: continue
            rport=int(p[2].split(':')[1],16)
            if 8500<=rport<=8599 or rport==8913: out[ino]=rport  # game channel 85xx or 8913
    except Exception: pass
    return out
RVA=0x2979607
r=ch.Reader(pid); base,_=ch.find_image(r,pid,prof); target=base+RVA; MOB=base+0x35154c8
mem=open(f'/proc/{pid}/mem','r+b',0)
def dec(w):
    for _ in range(40):
        try: return r.protected(w,8)['value']
        except Exception: time.sleep(0.001)
# initial full scan -> candidate mob object slots
mobaddrs=[]
for line in open(f'/proc/{pid}/maps'):
    a,perm=line.split()[:2]; lo,hi=(int(x,16) for x in a.split('-'))
    if 'rw' not in perm or hi-lo>512<<20 or lo>=0x7f0000000000: continue
    try: d=r.read(lo,hi-lo)
    except Exception: continue
    arr=array.array('Q',d[:len(d)//8*8]); mobaddrs+=[lo+j*8 for j,q in enumerate(arr) if q==MOB]
mobaddrs=list(set(mobaddrs))
def refresh():
    """Re-read current mobID+pos from known slots (cheap; no full rescan). Stale slots (vtable changed) skipped."""
    out=[]
    for m in mobaddrs:
        try:
            if r.qword(m)!=MOB: continue
            mid=struct.unpack('<I',r.read(m+0x3a0,4))[0]
            cb=r.qword(m+0x2c0)-0x20
            X=dec(cb+0x170); Y=dec(cb+0x188)
            if X is None or Y is None: continue
            out.append({'addr':m,'mid':mid,'low3':bytes(struct.pack('<I',mid&0xFFFFFF)[:3]),'X':X,'Y':Y})
        except Exception: pass
    return out
def player():
    for _ in range(40):
        try: sn=ch.snapshot(r,pid,base,prof); return sn['cached_x']['value'],sn['cached_y']['value']
        except Exception: time.sleep(0.01)
    return None,None
mobs=refresh(); px,py=player()
decoy=max(mobs,key=lambda m:(m['X']-px)**2+(m['Y']-py)**2) if mobs and px is not None else None
onscreen=[m for m in mobs if px is not None and ((m['X']-px)**2+(m['Y']-py)**2)**0.5<700]
print(f'player=({px},{py}) slots={len(mobaddrs)} mobs={len(mobs)} onscreen={len(onscreen)} mode={EMODE}',flush=True)
if EMODE=='cycle':
    for m in onscreen: print(f'  cycle target mid={m["mid"]:#x} pos=({m["X"]:.0f},{m["Y"]:.0f})',flush=True)
if decoy: print(f'DECOY mob={decoy["addr"]:#x} mid={decoy["mid"]:#x} low3={decoy["low3"].hex()} pos=({decoy["X"]:.0f},{decoy["Y"]:.0f}) dist={((decoy["X"]-px)**2+(decoy["Y"]-py)**2)**0.5:.0f}px',flush=True)
events=[]; attached=stopped=False; saved=None; deliver=0; trap=0
st=dict(l.split(':',1) for l in Path(f'/proc/{pid}/status').read_text().splitlines())
if int(st['TracerPid']): raise SystemExit('already traced')
try:
    observer.ptrace(pid,0x4206);attached=True;observer.ptrace(pid,0x4207)
    state=observer.wait_stop(pid,1);stopped=True;deliver=shared.pending_signal(pid,state)
    saved={s:observer.ptrace(pid,3,848+s*8)&0xFFFFFFFFFFFFFFFF for s in (0,1,2,3,6,7)}
    if saved[7]&0xFF: raise RuntimeError('slots busy')
    observer.ptrace(pid,6,848,target)
    ctl=(saved[7]&~0xFFFF00FF)|1
    observer.ptrace(pid,6,848+7*8,ctl); observer.ptrace(pid,6,848+6*8,0)
    observer.ptrace(pid,7,0,deliver);deliver=0;stopped=False
    t0=time.monotonic()
    ch0=chan_inodes(); lastchk=0; dc_at=None
    print(f'channel sockets at start: {sorted(ch0.values())}',flush=True)
    while time.monotonic()-t0<dur:
        if UNTIL_DC and ch0 and time.monotonic()-lastchk>0.5:
            lastchk=time.monotonic()
            if not (set(chan_inodes()) & set(ch0)):
                dc_at=round(lastchk-t0,2); print(f'DC DETECTED t={dc_at}s (channel socket closed) swaps={sum(1 for e in events if e.get("verify"))}',flush=True); break
        try: state=observer.wait_stop(pid,0.2)
        except TimeoutError: continue
        stopped=True; sig=os.WSTOPSIG(state)
        if sig!=signal.SIGTRAP: observer.ptrace(pid,7,0,sig);stopped=False;continue
        dr6=observer.ptrace(pid,3,848+6*8)
        if not dr6&1: deliver=sig; raise RuntimeError('foreign trap')
        regs=observer.Registers(); observer.ptrace(pid,12,0,ctypes.addressof(regs))
        pkt=regs.rcx&0xFFFFFFFFFFFFFFFF
        try:
            op=struct.unpack('<I',r.read(pkt+0x434,4))[0]; ln=struct.unpack('<I',r.read(pkt+0x428,4))[0]
            body=bytearray(r.read(pkt+8,min(256,max(8,ln))))
        except Exception as e:
            op=ln=None; body=None
        rec={'t':round(time.monotonic()-t0,3),'wall':round(time.time(),4),'trap':trap,'op':hex(op) if op is not None else None,'len':ln,'pkt':hex(pkt)}
        if body is not None and op==0xe1:
            # refresh mob state each trap (snapshot goes stale as mobs move/die/respawn)
            fresh=refresh(); fpx,fpy=player()
            # find real target: a fresh mob whose low3 mobID appears in body
            realm=None; idxs=[]
            for m in fresh:
                i=body.find(m['low3'])
                if i>=0 and (decoy is None or m['addr']!=decoy['addr']):
                    realm=m; j=0
                    while True:
                        k=body.find(m['low3'],j)
                        if k<0: break
                        idxs.append(k); j=k+1
                    break
            # fallback: identify real target straight from the packet (offset 125/124), not our list
            rfb=None
            if not idxs:
                for off in (125,124):
                    if body is not None and len(body)>=off+3:
                        rid=bytes(body[off:off+3]); rfb=rid
                        j=0
                        while True:
                            k=body.find(rid,j)
                            if k<0: break
                            idxs.append(k); j=k+1
                        if idxs: break
            rec['real_mid']=hex(realm['mid']) if realm else ('pkt:'+rfb.hex() if rfb else None)
            rec['real_pos']=[round(realm['X']),round(realm['Y'])] if realm else None
            rec['id_offsets']=idxs
            # choose swap target by mode
            def pick():
                near=[m for m in fresh if (realm is None or m['addr']!=realm['addr']) and fpx is not None
                      and ((m['X']-fpx)**2+(m['Y']-fpy)**2)**0.5<700]
                if EMODE=='far': return decoy
                if EMODE=='cycle': return near[(trap-1)%len(near)] if near else None
                if EMODE=='near':  # nearest OTHER mob within melee-plausible range
                    return min(near,key=lambda m:(m['X']-fpx)**2+(m['Y']-fpy)**2) if near else None
                if EMODE=='sweep':  # escalate distance: rank mobs by dist, pick farther each swing
                    others=[m for m in fresh if (realm is None or m['addr']!=realm['addr']) and fpx is not None]
                    others.sort(key=lambda m:(m['X']-fpx)**2+(m['Y']-fpy)**2)
                    return others[min(trap-1,len(others)-1)] if others else None
                return None
            if trap==0:
                ok=True
                if idxs:
                    orig=bytes(body[idxs[0]:idxs[0]+3])
                    for k in idxs:
                        mem.seek(pkt+8+k); mem.write(orig)
                    rb=r.read(pkt+8,len(body))
                    ok=all(rb[k:k+3]==orig for k in idxs)
                rec['selftest']='write-path OK' if ok else 'WRITE FAILED'
                print(f'  trap0 SELFTEST {rec["selftest"]} real={rec["real_mid"]} idOffsets={idxs}',flush=True)
            elif EMODE=='bands' and idxs and ln>=48 and fpx is not None:
                # keep REAL mobID; push CLAIMED position outward from player, radius steps PER SWING
                STEPS=[200,350,500,700,900,1200,1500,1900,2400,3000,3800]
                si=min(trap-1,len(STEPS)-1); R=STEPS[si]
                rx=(realm['X']-fpx) if realm else 1.0; ry=(realm['Y']-fpy) if realm else 0.0
                mag=(rx*rx+ry*ry)**0.5 or 1.0
                cx=fpx+rx/mag*R; cy=fpy+ry/mag*R
                for po in (36,44):
                    mem.seek(pkt+8+po); mem.write(struct.pack('<hh',round(cx),round(cy)))
                rb=r.read(pkt+8,len(body))
                rec['band_radius']=R; rec['claimed_pos']=[round(cx),round(cy)]
                rec['real_pos']=[round(realm['X']),round(realm['Y'])] if realm else None
                rec['verify']=struct.unpack('<hh',rb[36:40])==(round(cx),round(cy))
                print(f'  trap{trap} bands R={R} claimed=({cx:.0f},{cy:.0f}) real_mid={rec["real_mid"]} verify={rec["verify"]}',flush=True)
            elif idxs:
                tgt=pick()
                if tgt is not None:
                    for k in idxs:
                        mem.seek(pkt+8+k); mem.write(tgt['low3'])
                    posset=[]
                    if ln>=48:
                        for po in (36,44):
                            mem.seek(pkt+8+po); mem.write(struct.pack('<hh',round(tgt['X']),round(tgt['Y']))); posset.append(po)
                    rb=r.read(pkt+8,len(body))
                    tdist=round(((tgt['X']-fpx)**2+(tgt['Y']-fpy)**2)**0.5) if fpx is not None else None
                    rec['swapped_to']=hex(tgt['mid']); rec['pos_offsets']=posset; rec['tgt_dist']=tdist
                    rec['verify']=all(rb[k:k+3]==tgt['low3'] for k in idxs)
                    print(f'  trap{trap} {EMODE} real {rec["real_mid"]}@{idxs} -> {tgt["mid"]:#x} dist={tdist} pos{posset} verify={rec["verify"]}',flush=True)
        events.append(rec); trap+=1
        observer.ptrace(pid,6,848+6*8,0); observer.ptrace(pid,7);stopped=False
finally:
    if attached:
        if not stopped:
            observer.ptrace(pid,0x4207);state=observer.wait_stop(pid,1);deliver=shared.pending_signal(pid,state,{})
        if saved:
            for s in (7,0,1,2,3,6): observer.ptrace(pid,6,848+s*8,saved[s])
        observer.ptrace(pid,17,0,deliver); print('DETACHED traps=',trap,flush=True)
    json.dump({'base':hex(base),'rva':hex(RVA),'decoy':(decoy and {'mid':hex(decoy['mid']),'pos':[round(decoy['X']),round(decoy['Y'])]}),'events':events},open(out,'w'),indent=1)
