/* Kernel events (kev.bpf.h: the uring, kevents and faults groups): each MM_KEV record becomes one record of an
 * existing type (docs/LINUX.md "Kernel events"). Included by bpf.cpp at global scope after Record/Repeated. */

namespace {

bool gPageFaults = false;   /* --page-faults: load the faults group */

/* IORING_OP_* names (enum io_uring_op, kernel 7.0). */
const char* const kUringOps =
    "nop readv writev fsync read_fixed write_fixed poll_add poll_remove sync_file_range sendmsg recvmsg timeout "
    "timeout_remove accept async_cancel link_timeout connect fallocate openat close files_update statx read write "
    "fadvise madvise send recv openat2 epoll_ctl splice provide_buffers remove_buffers tee shutdown renameat unlinkat "
    "mkdirat symlinkat linkat msg_ring fsetxattr setxattr fgetxattr getxattr socket uring_cmd send_zc sendmsg_zc "
    "read_multishot waitid futex_wait futex_wake futex_waitv fixed_fd_install ftruncate bind listen recv_zc epoll_wait "
    "readv_fixed writev_fixed pipe nop128 uring_cmd128";

const char* const kCapabilities =
    "chown dac_override dac_read_search fowner fsetid kill setgid setuid setpcap linux_immutable net_bind_service "
    "net_broadcast net_admin net_raw ipc_lock ipc_owner sys_module sys_rawio sys_chroot sys_ptrace sys_pacct sys_admin "
    "sys_boot sys_nice sys_resource sys_time sys_tty_config mknod lease audit_write audit_control setfcap mac_override "
    "mac_admin syslog wake_alarm block_suspend audit_read perfmon bpf checkpoint_restore";

/* Word index of a space-separated table, or "<fallback><index>". BPF thread only. */
std::wstring Word(const char* table, uint64_t index, const char* fallback)
{
    static std::unordered_map<const char*, std::vector<std::wstring>> split;
    std::vector<std::wstring>& words = split[table];
    if (words.empty()) {
        std::istringstream in(table);
        for (std::string word; in >> word;) words.push_back(LinuxWide(word));
    }
    return index < words.size() ? words[index] : LinuxWide(fallback) + std::to_wstring(index);
}

/* The trapped instruction from its first bytes: its name (system:<name>), or "gp_fault" for another #GP. */
std::wstring InsnName(uint64_t bytes)
{
    uint8_t b[8];
    std::memcpy(b, &bytes, sizeof(b));
    unsigned at = 0;
    /* operand/address size, segment, rep and REX prefixes */
    while (at < 4 && (b[at] == 0x66 || b[at] == 0x67 || b[at] == 0xf2 || b[at] == 0xf3 || b[at] == 0x2e || b[at] == 0x36 ||
                      b[at] == 0x3e || b[at] == 0x26 || b[at] == 0x64 || b[at] == 0x65 || (b[at] & 0xf0) == 0x40))
        at++;
    const uint8_t op = b[at], next = b[at + 1], reg = (b[at + 2] >> 3) & 7;
    if (op == 0xe4 || op == 0xe5 || op == 0xec || op == 0xed || op == 0x6c || op == 0x6d) return L"in";
    if (op == 0xe6 || op == 0xe7 || op == 0xee || op == 0xef || op == 0x6e || op == 0x6f) return L"out";
    if (op == 0xcd) return L"int_" + Hex(next).substr(2);
    if (op == 0xf4) return L"hlt";
    if (op == 0xfa || op == 0xfb) return op == 0xfa ? L"cli" : L"sti";
    if (op != 0x0f) return L"gp_fault";
    switch (next) {
    case 0xa2: return L"cpuid";
    case 0x31: return L"rdtsc";
    case 0x33: return L"rdpmc";
    case 0x32: return L"rdmsr";
    case 0x30: return L"wrmsr";
    case 0x01:
        if (b[at + 2] == 0xf9) return L"rdtscp";
        return reg == 0 ? L"sgdt" : reg == 1 ? L"sidt" : reg == 4 ? L"smsw" : L"0f01_" + std::to_wstring(reg);
    case 0x00: return reg == 0 ? L"sldt" : reg == 1 ? L"str" : L"0f00_" + std::to_wstring(reg);
    default: return L"gp_fault";
    }
}

/* One io_uring operation (submission and completion in one record): the record type of the call it stands for, the
 * detail via=io_uring;op=<name>. */
void OnUring(const mm_event& e, const std::wstring& note)
{
    const unsigned op = static_cast<unsigned>(e.args[0]);
    const std::wstring name = Word(kUringOps, op, "op");
    const bool success = e.ret >= 0;
    std::wstring file = FilePath(e);
    const std::wstring path = Join(Text(e.kdir_a, sizeof(e.kdir_a)), Text(e.path_a, sizeof(e.path_a)));
    const int64_t fd = static_cast<int64_t>(e.args[1]);
    if (file.empty() && fd >= 0) {
        auto known = gBpf.fds.find((static_cast<uint64_t>(e.tgid) << 32) | static_cast<uint32_t>(fd));
        if (known != gBpf.fds.end()) file = known->second;
    }
    std::wstring detail = L"via=io_uring;op=" + name + L";res=" + std::to_wstring(e.ret) + L";fd=" + std::to_wstring(fd) +
                          L";user_data=" + Hex(e.args[2]) + L";dur_ns=" + std::to_wstring(e.dur_ns) + note;
    const bool socket = S_ISSOCK(e.mode);
    const unsigned fileSensor = socket ? MSMON_SENSOR_LINUX_EBPF_NET : MSMON_SENSOR_LINUX_EBPF_FILE;
    const ULONG truncated = (e.flags & (MM_F_TRUNC_A | MM_F_TRUNC_K)) != 0 ? MsMonFlagTruncatedPath : 0;
    unsigned sensor = fileSensor;
    ULONG type = MsMonFileDeviceControl;
    uint64_t value0 = op, value1 = 0;
    std::wstring text = file;
    switch (op) {
    case 1: case 4: case 10: case 22: case 27: case 49: case 58: case 60:   /* readv read_fixed recvmsg read recv ... */
        type = MsMonFileRead;
        value0 = success ? e.ret : 0;
        break;
    case 2: case 5: case 9: case 23: case 26: case 47: case 48: case 61:    /* writev write_fixed sendmsg write send ... */
        type = MsMonFileWrite;
        value0 = success ? e.ret : 0;
        break;
    case 18: case 28:   /* openat, openat2: the path asked for; the fd it returns is named from now on */
        type = MsMonFileCreate;
        sensor = MSMON_SENSOR_LINUX_EBPF_FILE;
        text = !path.empty() ? path : file;
        value0 = e.args[3];
        value1 = success ? e.ret : 0;
        if (success && !text.empty()) gBpf.fds[(static_cast<uint64_t>(e.tgid) << 32) | static_cast<uint32_t>(e.ret)] = text;
        detail += L";open_flags=" + Hex(e.args[3]);
        break;
    case 19:
        type = MsMonFileClose;
        gBpf.fds.erase((static_cast<uint64_t>(e.tgid) << 32) | static_cast<uint32_t>(fd));
        break;
    case 16: {
        unsigned family = 0;
        uint16_t port = 0;
        text = Endpoint(e, family, port);
        sensor = family == AF_UNIX ? MSMON_SENSOR_LINUX_EBPF_IPC : MSMON_SENSOR_LINUX_EBPF_NET;
        type = MsMonNetworkConnect;
        value0 = e.ino;
        value1 = port;
        break;
    }
    case 13:
        type = MsMonNetworkAccept;
        sensor = MSMON_SENSOR_LINUX_EBPF_NET;
        value0 = e.ino;
        break;
    case 3: case 8:
        type = MsMonFileFlush;
        break;
    case 21:
        type = MsMonFileQueryInformation;
        break;
    default:
        break;
    }
    if (text.empty()) text = L"io_uring:" + name;
    const bool bytes = type == MsMonFileRead || type == MsMonFileWrite;
    if (Repeated(e, "io_uring", sensor, type, text, op, bytes, detail)) return;
    Record(e, sensor, type, value0, value1, text, detail, truncated);
}

void OnKev(const mm_event& e)
{
    LinuxSession& session = *gBpf.session;
    uint64_t start = 0;
    ULONG trackFlags = 0;
    if (!session.Tracked(e.tgid, start, trackFlags)) return;
    const std::wstring note = NativeNote(e.tgid);
    switch (e.nr) {
    case MM_KEV_URING:
        OnUring(e, note);
        break;
    case MM_KEV_AIO: {
        /* IOCB_CMD_PREAD 0, PWRITE 1, PREADV 7, PWRITEV 8; rw_type READ 0, WRITE 1 */
        const bool write = e.args[4] != 0;
        const std::wstring file = FilePath(e);
        std::wstring detail = L"via=aio;opcode=" + std::to_wstring(e.args[0]) + L";fd=" + std::to_wstring(e.args[1]) +
                              L";requested=" + std::to_wstring(e.args[2]) + L";offset=" + Hex(e.args[3]) + note;
        const unsigned sensor = S_ISSOCK(e.mode) ? MSMON_SENSOR_LINUX_EBPF_NET : MSMON_SENSOR_LINUX_EBPF_FILE;
        const ULONG type = write ? MsMonFileWrite : MsMonFileRead;
        if (Repeated(e, "aio", sensor, type, file, e.args[0], false, detail, e.args[3])) break;
        Record(e, sensor, type, e.args[2], e.args[3], file, detail, file.empty() ? MsMonFlagMissingPath : 0);
        break;
    }
    case MM_KEV_SIGNAL: {
        static const char* const names = "0 hup int quit ill trap abrt bus fpe kill usr1 segv usr2 pipe alrm term stkflt chld cont "
                                          "stop tstp ttin ttou urg xcpu xfsz vtalrm prof winch io pwr sys";
        const uint64_t signal = e.args[0];
        const std::wstring comm = Text(e.path_a, 16);
        std::wstring detail = L"signal_received;signal=" + std::to_wstring(signal) + L";name=sig" + Word(names, signal, "rt") +
                              L";code=" + std::to_wstring(static_cast<int64_t>(e.args[1])) + L";sender_pid=" +
                              std::to_wstring(e.args[4]) + L";sender_context=" + comm + L";result=" + std::to_wstring(e.args[2]) +
                              L";group=" + std::to_wstring(e.args[3]) + note;
        if (Repeated(e, "signal_received", MSMON_SENSOR_LINUX_EBPF_IPC, MsMonProcessHandle, {},
                     (static_cast<uint64_t>(e.target_tgid) << 8) | (signal & 0xff), false, detail))
            break;
        Record(e, MSMON_SENSOR_LINUX_EBPF_IPC, MsMonProcessHandle, 0, signal, {}, detail, 0, e.target_tgid);
        break;
    }
    case MM_KEV_INSN: {
        /* As a system:<call> record (Op::SystemInfo): the instruction asks the machine, value0/value1 CPUID's leaf. */
        const std::wstring name = InsnName(e.args[1]);
        const bool cpuid = name == L"cpuid";
        std::wstring bytes;
        for (unsigned index = 0; index < 4; index++) {
            wchar_t two[4];
            swprintf(two, 4, L"%02x", static_cast<unsigned>((e.args[1] >> (8 * index)) & 0xff));
            bytes += (index ? L" " : L"") + std::wstring(two);
        }
        std::wstring detail = L"insn=" + name + L";ip=" + Hex(e.args[0]) + L";bytes=" + bytes +
                              (cpuid ? L";leaf=" + Hex(static_cast<uint32_t>(e.args[2])) + L";subleaf=" + Hex(static_cast<uint32_t>(e.args[3])) : L"") +
                              L";source=" + (e.args[4] == MM_INSN_UMIP ? L"umip_emulated" : L"sigsegv") + note;
        const std::wstring text = L"system:" + name;
        if (Repeated(e, "insn", MSMON_SENSOR_LINUX_EBPF_FILE, MsMonFileQueryInformation, text,
                     cpuid ? Mix({e.args[0], static_cast<uint32_t>(e.args[2]), static_cast<uint32_t>(e.args[3])}) : e.args[0], false, detail))
            break;
        Record(e, MSMON_SENSOR_LINUX_EBPF_FILE, MsMonFileQueryInformation, cpuid ? static_cast<uint32_t>(e.args[2]) : 0,
               cpuid ? static_cast<uint32_t>(e.args[3]) : 0, text, detail, 0);
        break;
    }
    case MM_KEV_SELFSIG: {
        /* The first fault of its (signal, code, ip page) since the last drain of agg; the rest are its summary
         * (sysagg.h SelfSignalSummary). An observer coverage record self_signal: value0 the fault address, value1 the
         * signal. */
        const std::wstring detail = SelfSignalDetail(e.args[0], static_cast<int64_t>(e.args[1]), e.args[2], e.args[3], e.args[4],
                                                     e.args[5]) + note;
        Record(e, MSMON_SENSOR_LINUX_EBPF_MEMORY, MsMonCoverage, e.args[3], e.args[0], L"self_signal", detail, MsMonFlagObserverRecord);
        break;
    }
    case MM_KEV_OUTSIDE: {
        /* An untracked process's access check on this one (identity: the target), the first of its (actor, mode, call)
         * since the last drain of agg (the rest: sysagg.h OutsideSummary): an observer coverage record outside_access,
         * target_process_id the actor, actor_exe= its executable (last: a path may hold ';'), status the check's result,
         * value0 the PTRACE_MODE_* bits. */
        const std::wstring exe = (e.flags & MM_F_KPATH) != 0 ? FilePath(e) : Text(e.path_a, 16);
        gBpf.outsiders[e.target_tgid] = {exe, std::chrono::steady_clock::now()};
        const std::wstring detail = L"outside_access" + OutsideFields(e.target_tgid, e.args[0], CountName(e.args[2] & (MM_COUNT_COMPAT | 0xffff))) +
                                    L";actor_tid=" + std::to_wstring(e.args[3]) + L";actor_comm=" + Text(e.path_a, 16) +
                                    L";ret=" + std::to_wstring(static_cast<int64_t>(e.args[1])) + note + L";actor_exe=" + exe;
        Record(e, MSMON_SENSOR_LINUX_EBPF_MEMORY, MsMonCoverage, e.args[0], 0, L"outside_access", detail,
               MsMonFlagObserverRecord | ((e.flags & MM_F_TRUNC_K) != 0 ? MsMonFlagTruncatedPath : 0), e.target_tgid);
        break;
    }
    case MM_KEV_CAP: {
        const std::wstring name = Word(kCapabilities, e.args[0], "cap");
        std::wstring detail = L"capability;cap=" + std::to_wstring(e.args[0]) + L";name=cap_" + name + L";opts=" + Hex(e.args[1]) +
                              L";ret=" + std::to_wstring(e.ret) + note;
        if (Repeated(e, "capable", MSMON_SENSOR_LINUX_EBPF_MEMORY, MsMonProcessHandle, L"capability:" + name, 0, false, detail))
            break;
        Record(e, MSMON_SENSOR_LINUX_EBPF_MEMORY, MsMonProcessHandle, e.args[0], e.args[1], L"capability:" + name, detail, 0);
        break;
    }
    case MM_KEV_MODULE: {
        const std::wstring name = Text(e.path_a, sizeof(e.path_a));
        std::wstring detail = L"module_request;ret=" + std::to_wstring(e.ret) + note;
        if (Repeated(e, "module_request", MSMON_SENSOR_LINUX_EBPF_MEMORY, MsMonProcessHandle, name, 0, false, detail)) break;
        Record(e, MSMON_SENSOR_LINUX_EBPF_MEMORY, MsMonProcessHandle, 0, 0, name, detail, 0);
        break;
    }
    case MM_KEV_CRED: {
        auto change = [](const wchar_t* what, uint64_t pair) {
            return std::wstring(L";") + what + L"=" + std::to_wstring(pair >> 32) + L"->" + std::to_wstring(static_cast<uint32_t>(pair));
        };
        std::wstring detail = L"cred_change" + change(L"uid", e.args[0]) + change(L"euid", e.args[1]) + change(L"gid", e.args[2]) +
                              change(L"egid", e.args[3]) + L";cap_effective=" + Hex(e.args[4]) + L"->" + Hex(e.args[5]) + note;
        Record(e, MSMON_SENSOR_LINUX_EBPF_MEMORY, MsMonProcessHandle, static_cast<uint32_t>(e.args[0]),
               static_cast<uint32_t>(e.args[1]), {}, detail, 0);
        break;
    }
    case MM_KEV_FAULT: {
        /* value0 the page's bytes, value1 its file offset; collapsed per mapping and access kind */
        const bool write = (e.args[2] & 2) != 0;
        const std::wstring file = FilePath(e);
        std::wstring detail = L"via=page_fault;address=" + Hex(e.args[0]) + L";ip=" + Hex(e.args[1]) + L";error_code=" +
                              Hex(e.args[2]) + L";offset=" + Hex(e.args[3]) + note;
        const ULONG type = write ? MsMonFileWrite : MsMonFileRead;
        if (Repeated(e, "page_fault", MSMON_SENSOR_LINUX_EBPF_MEMORY, type, file, write, false, detail, e.args[3])) break;
        Record(e, MSMON_SENSOR_LINUX_EBPF_MEMORY, type, 4096, e.args[3], file, detail,
               (e.flags & MM_F_TRUNC_K) != 0 ? MsMonFlagTruncatedPath : 0);
        break;
    }
    default:
        break;
    }
}

std::wstring GroupState(const char* name)
{
    const Group* group = FindGroup(name);
    return group->state == 0 ? std::wstring(L"on") : group->state == -1 ? std::wstring(L"off") : L"load_failed:" + std::to_wstring(group->state);
}

int KevOpened(std::wstring& detail, unsigned&)
{
    detail += L";uring=" + GroupState("uring") + L";kevents=" + GroupState("kevents") + L";page_faults=" + GroupState("faults") +
              L";seccomp=" + GroupState("seccomp");
    return 0;
}

void KevNotes(Notes& notes)
{
    notes.emplace_back(L"kernel_events",
                       L"uring=" + GroupState("uring") + L";kevents=" + GroupState("kevents") + L";page_faults=" +
                           GroupState("faults") + (gPageFaults ? L"" : L"(opt-in:--page-faults)") +
                           L";seccomp=" + GroupState("seccomp") +
                           L";records=io_uring+aio(via=),signal_received,self_signal(coverage),outside_access(coverage),"
                           L"system:<instruction>,capability,module_request,cred_change,page_fault(via=),"
                           L"seccomp:/dispatch:<call>;not_seen=vdso_calls(clock_gettime/gettimeofday/time/getcpu make no"
                           L" syscall),unprivileged_instructions(xgetbv/rdrand/rdpid...),accesses_to_resident_pages,"
                           L"outside_checks_refused_before_the_lsm(another_user_without_cap_sys_ptrace)");
}

/* The losses map (MM_LOSS_*) and the agent's unadmitted calls as the ebpf_losses coverage record: written at every
 * flush, totals so far. Two are differences: uring_unfinished (io_uring operations stored at submission and never
 * written at completion: evicted from uring_inflight, no CQE, or in flight at the stop) and ucall_unreported (calls the
 * uprobes' rate limit left out that no record or the stop's drain reported: an evicted up_rate key's). unix_full:
 * AF_UNIX connects unix_svc had no room for (their service traffic is not walked). */
void KevLosses()
{
    bpf_map* map = gBpf.object ? bpf_object__find_map_by_name(gBpf.object, "losses") : nullptr;
    if (map == nullptr) return;
    std::vector<uint64_t> values(static_cast<size_t>(std::max(libbpf_num_possible_cpus(), 1)));
    static const wchar_t* names[MM_LOSS_URING_STORED] = {L"pending_overwrite", L"pending_stale", L"ws_rejected", L"scratch_reuse",
                                                         L"pending_full",      L"counts_full",   L"agg_full"};
    uint64_t totals[MM_LOSS_KEYS] = {};
    LinuxRecord record;
    record.sensor = MSMON_SENSOR_LINUX_EBPF_FILE;
    record.type = MsMonCoverage;
    record.flags = MsMonFlagObserverRecord;
    record.text = L"ebpf_losses";
    for (uint32_t index = 0; index < MM_LOSS_KEYS; index++) {
        if (bpf_map_lookup_elem(bpf_map__fd(map), &index, values.data()) == 0) {
            for (uint64_t value : values) totals[index] += value;
        }
        if (index >= MM_LOSS_URING_STORED) continue;
        record.value0 += totals[index];
        record.detail += std::wstring(index ? L";" : L"") + names[index] + L"=" + std::to_wstring(totals[index]);
    }
    auto difference = [](uint64_t all, uint64_t written) { return all > written ? all - written : 0; };
    const uint64_t unfinished = difference(totals[MM_LOSS_URING_STORED], totals[MM_LOSS_URING_DONE]);
    const uint64_t unreported = difference(totals[MM_LOSS_UCALL_SKIPPED], totals[MM_LOSS_UCALL_REPORTED] + gBpf.upDrained);
    record.value0 += unfinished + unreported + totals[MM_LOSS_UNIX_FULL];
    record.detail += L";uring_unfinished=" + std::to_wstring(unfinished) + L";ucall_unreported=" + std::to_wstring(unreported) +
                     L";unix_full=" + std::to_wstring(totals[MM_LOSS_UNIX_FULL]);
    /* The agent's own: calls of processes the kernel tracked and the session never admitted (AggHeld). */
    record.value0 += gBpf.aggHeld.lost;
    record.detail += L";unadmitted=" + std::to_wstring(gBpf.aggHeld.lost);
    gBpf.session->Write(record);
}

}  // namespace
