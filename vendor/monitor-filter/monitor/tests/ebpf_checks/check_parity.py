"""Windows-parity checks of the kernel sensors, called by tests/linux_ebpf_test.sh check():
- image_load at the mapping (PsSetLoadImageNotifyRoutine): the probe's exec mmap (source=mmap) and its
  mmap + mprotect(PROT_EXEC) (source=mprotect, fexit/security_file_mprotect), both unmapped at once;
- a thread exit carries the Windows ids of its TEB (the probe's thread sets one: pid 0x1234, tid 0x5678);
- msmon observes only: the tracked probe's bpf() is not refused, its kill(agent, 0) is (self-protection);
- the ia32 probe (32-bit, run from the extra root): its ia32 syscalls are recorded with their x86_64 meaning,
  paths, the failing open's status, the compat sendmsg peer and payload (made through socketcall, as 32-bit glibc
  does), its SysV segment through ipc (shmat's address read back from *third), olduname as uname, mmap2's
  image_load, PE frames from its i386 TEB syscall_frame (pe_i386=1), syscall_counts naming the multiplexers, glibc's
  ipc(MSGRCV) version 0 unpacked from its ipc_kludge and fanotify_mark's path behind its split 64-bit mask."""
import base64
import re


def check(mode, path, events, mine, pids, coverage, problems):
    if mode not in ("ebpf", "nopayloads"):
        return
    images = [e for e in mine if e["type"] == "image_load"]
    if not any("source=mmap" in e["detail"] and e["text"].endswith("/probe-b.txt") for e in images):
        problems.append("parity: no image_load source=mmap for probe-b.txt (written at the mapping, not by the poll)")
    if not any("source=mprotect" in e["detail"] and e["text"].endswith("/probe-x.txt") for e in images):
        problems.append("parity: no image_load source=mprotect for probe-x.txt")
    if not any(e["type"] == "thread_exit" and "win_tid=22136" in e.get("detail", "") and e["value1"] == 22136 for e in mine):
        problems.append("parity: no thread_exit carrying the thread's Windows id (win_tid=22136)")
    if any("self_protection_denied=bpf" in e.get("detail", "") or "self_protection_denied=perf" in e.get("detail", "")
           for e in events):
        problems.append("parity: bpf/perf_event_open refused although --protect-tree was not given")
    if not any("self_protection_denied=kill" in e.get("detail", "") for e in mine):
        problems.append("parity: the probe's kill(agent, 0) was not refused (self_protection_denied=kill)")
    if not any(e["type"] == "coverage" and e["text"] == "ebpf_active" and "kernel_roots=2" in e["detail"] and
               "protect_tree=0" in e["detail"] and "repeat_window_ms=1000" in e["detail"] for e in events):
        problems.append("parity: ebpf_active does not say kernel_roots=2, protect_tree=0 and repeat_window_ms=1000")

    ia32 = {e["process_id"] for e in events if e["type"] == "process_start" and
            "ia32_probe" in e.get("text", "") + e.get("process_path", "")}
    if not ia32:
        problems.append("parity: the ia32 probe (under the extra root) was not tracked")
        return
    rec = [e for e in events if e.get("process_id") in ia32]

    def has(test):
        return any(test(e) for e in rec)
    if not has(lambda e: e["type"] == "file_create" and e["text"].endswith("/ia32-a.txt") and "syscall=open;" in e["detail"]):
        problems.append("parity: ia32 open of ia32-a.txt not recorded")
    if not has(lambda e: e["type"] == "file_write" and e["text"].endswith("/ia32-a.txt") and e["value0"] == 6):
        problems.append("parity: ia32 write of 6 bytes not recorded")
    if not has(lambda e: e["type"] == "file_query_information" and e["text"].endswith("/ia32-a.txt") and "syscall=stat;" in e["detail"]):
        problems.append("parity: ia32 stat64 not recorded as stat")
    if not has(lambda e: e["type"] == "file_create" and e["status"] != 0 and e["text"].endswith("ia32-missing.txt")):
        problems.append("parity: ia32 failing open has no nonzero status")
    if not has(lambda e: e["type"] == "image_load" and e["text"].endswith("/ia32-a.txt") and "source=mmap" in e["detail"]):
        problems.append("parity: ia32 mmap2 PROT_EXEC gave no image_load")
    if not has(lambda e: e["type"] == "network_connect" and "sendmsg;" in e["detail"] and e["text"].startswith("127.0.0.1:")):
        problems.append("parity: ia32 socketcall(SENDMSG) has no sendmsg record with its peer (compat msghdr)")
    if not has(lambda e: e["type"] == "file_section" and e["text"].startswith("sysv_shm:key=")) or \
            not has(lambda e: e["type"] == "file_section" and e["text"].startswith("sysv_shm:id=") and e["value1"] != 0):
        problems.append("parity: ia32 ipc(SHMGET/SHMAT) not recorded as shmget/shmat with the attach address")
    if not has(lambda e: "syscall=msgrcv;" in e["detail"] and re.search(r";args=(0x[0-9a-f]+,){3}0x5,", e["detail"])):
        problems.append("parity: ia32 ipc(MSGRCV) version 0 has no msgtyp 5 (its ipc_kludge not read)")
    if not has(lambda e: e["type"] == "file_directory_control" and e["text"].endswith("/ia32-a.txt") and
               e["detail"].startswith("fanotify_mark;mask=0x20;")):
        problems.append("parity: ia32 fanotify_mark has no path and mask 0x20 (mask_lo/mask_hi split)")
    if not has(lambda e: e["text"] == "system:uname" and "syscall=uname;" in e["detail"]):
        problems.append("parity: ia32 olduname not recorded as system:uname")
    if not has(lambda e: e["type"] == "coverage" and e["text"] == "syscall_counts" and e["detail"].startswith("recorded=1;") and
               ";ia32:socketcall=" in e["detail"] and ";ia32:ipc=" in e["detail"]):
        problems.append("parity: ia32 syscall_counts do not count socketcall and ipc")
    if mode == "ebpf" and not has(lambda e: "syscall=sendmsg;" in e.get("detail", "") and
                                  e.get("payload", {}).get("kind") == "network_data" and
                                  base64.b64decode(e["payload"]["data"]) == b"ia32"):
        problems.append("parity: ia32 sendmsg payload (\"ia32\", compat msghdr/iovec) not captured")
    if not has(lambda e: "pe_i386=1" in e.get("detail", "") and "pe_frames=" in e["detail"] and e.get("stack_frames", 0) > 0):
        problems.append("parity: ia32 records carry no i386 PE frames (pe_i386=1)")
