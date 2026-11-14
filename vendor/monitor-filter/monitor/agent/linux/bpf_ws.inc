/* Wineserver requests (wineserver upgrade): bpf.cpp's hooks for ws.bpf.h. The ring records go to the
 * pure decoder in wineserver.cpp; what it returns is written here as records of the requesting
 * process and thread (docs/LINUX.md "Wineserver requests"). */
#include "wineserver.h"

namespace {

struct WsState {
    WsDecoder decoder;
    struct Process {
        uint64_t startNs = 0;
        bool active = false;
    };
    std::unordered_map<uint32_t, Process> processes;   /* tgid -> decoder gate */
    std::string lastBuild, lastPath;                     /* the last ntdll.so read from a live process */
    bool attached = false;
    std::mutex joinedMutex;
    std::vector<std::pair<uint32_t, uint64_t>> joined;   /* (pid, start) tracked late; WsPoll takes them */
};
WsState gWs;
bool gRealInput = false;   /* --log-real-input: the user's own keys are logged too */

void WsConfigure(bpf_object* object)
{
    gWs.decoder.SetPayloads(gBpf.payloads);
    gWs.decoder.SetRealInput(gRealInput);
    gWs.decoder.SetContent(gBpf.content);
    /* A late-joined winedevice's kernel objects (root reads any process's memory). */
    gWs.decoder.SetReader([](uint32_t tgid, uint64_t address, uint64_t& value) {
        const int fd = open(("/proc/" + std::to_string(tgid) + "/mem").c_str(), O_RDONLY | O_CLOEXEC);
        uint64_t word = 0;
        const bool ok = fd >= 0 && pread(fd, &word, sizeof(word), static_cast<off_t>(address)) == sizeof(word);
        if (fd >= 0) close(fd);
        if (ok) value = word;
        return ok;
    });
    bpf_map* map = bpf_object__find_map_by_name(object, "ws_cfg");
    if (map == nullptr) return;
    const mm_ws_config config = WsCaptureConfig(gRealInput, gBpf.content);
    const uint32_t zero = 0;
    bpf_map_update_elem(bpf_map__fd(map), &zero, &config, BPF_ANY);
}

int WsOpened(std::wstring& detail, unsigned& registered)
{
    gWs.attached = Attached("mm_ws_enter") && Attached("mm_ws_exit");
    if (gWs.attached) {
        registered |= 1u << (MSMON_SENSOR_LINUX_EBPF_WINESERVER - MSMON_SENSOR_LINUX_EBPF_PROCESS);
        detail += L";wineserver=on";
        return 0;
    }
    const Group* group = FindGroup("wineserver");
    detail += L";wineserver=off(" +
              (group->state == 0    ? std::wstring(L"attach_failed")
               : group->state == -1 ? std::wstring(L"off")
                                    : L"load_failed:" + std::to_wstring(group->state)) +
              L")";
    return 0;
}

/* One decoded record: identity and stack from its request, then collapsed or written. */
void WsWrite(WsRecord& out)
{
    const mm_ws_event& request = *out.request;
    LinuxRecord& record = out.record;
    record.pid = request.tgid;
    record.tid = request.tid;
    record.start = HertzTicksToFileTime(request.start_ns);
    record.timestamp = BootToFileTime(out.tsNs);
    if (out.collapse) {
        /* Repeated's key: the pseudo syscall 1000 + request, the status, the target text and RepeatKey. */
        mm_event shell{};
        shell.tgid = request.tgid;
        shell.tid = request.tid;
        shell.start_ns = request.start_ns;
        shell.ts_ns = out.tsNs;
        shell.nr = 1000 + request.req;
        shell.ret = record.status;
        if (Repeated(shell, WsRequestName(request.req), record.sensor, record.type, record.text, out.repeatKey, false,
                     record.detail))
            return;
    }
    uint64_t targetStart = 0;
    ULONG targetFlags = 0;
    if (record.target != 0 && gBpf.session->Tracked(record.target, targetStart, targetFlags)) record.targetStart = targetStart;
    PeFrames(request.pe, request.tgid, record.start, request.stack, std::min<uint32_t>(request.frames, MM_FRAMES), record);
    if (out.payload) {
        gBpf.session->WritePayloadSeries(record, out.payloadKind, out.payloadTotal, out.bytes);
    } else {
        gBpf.session->Write(record);
    }
}

/* The decoder runs only for a client whose ntdll.so is a build it has the protocol of; the first event
 * of each process writes the wineserver_decoder record that says so. */
bool WsActive(const mm_ws_event& event)
{
    WsState::Process& process = gWs.processes[event.tgid];
    if (process.startNs == event.start_ns) return process.active;
    std::string path;
    std::string build = WsNtdllBuild(event.tgid, path);
    /* The ring is drained after the request: a short-lived client may be gone (maps empty). Only a
     * Wine thread (TEB, pipe fd) produces these events, so assume the last ntdll.so seen. */
    const bool assumed = path.empty() && !gWs.lastPath.empty();
    if (assumed) {
        build = gWs.lastBuild;
        path = gWs.lastPath;
    } else if (!path.empty()) {
        gWs.lastBuild = build;
        gWs.lastPath = path;
    }
    const unsigned protocol = WsProtocolForBuild(build);
    process = {event.start_ns, protocol == kWsProtocol};
    LinuxRecord record;
    record.sensor = MSMON_SENSOR_LINUX_EBPF_WINESERVER;
    record.type = MsMonCoverage;
    record.flags = MsMonFlagObserverRecord;
    record.pid = event.tgid;
    record.tid = event.tid;
    record.start = HertzTicksToFileTime(event.start_ns);
    record.text = L"wineserver_decoder";
    record.detail = L"active=" + std::to_wstring(process.active ? 1 : 0) + L";build=" + LinuxWide(build.empty() ? "unknown" : build) +
                    L";protocol=" + std::to_wstring(protocol) + L";ntdll=" + LinuxWide(path) + (assumed ? L";assumed=1" : L"");
    gBpf.session->Write(record);
    return process.active;
}

void WsRing(const void* data, size_t size)
{
    constexpr size_t head = offsetof(mm_ws_event, data);
    if (size < head) return;
    static mm_ws_event event;   /* about 17 KB: not on the stack per record */
    std::memcpy(&event, data, std::min(size, sizeof(event)));
    event.data_len = std::min<uint32_t>({event.data_len, static_cast<uint32_t>(std::min<size_t>(size - head, MM_WS_DATA)),
                                         MM_WS_DATA});
    LinuxSession& session = *gBpf.session;
    WsPoll();   /* a late-joined winedevice's drivers before its next IRP */
    session.Enter(MSMON_SENSOR_LINUX_EBPF_WINESERVER);
    uint64_t start = 0;
    ULONG flags = 0;
    if (!session.Tracked(event.tgid, start, flags)) return;
    if (!WsActive(event)) return;
    gWs.decoder.Event(event, WsWrite);
}

void WsJoined(uint32_t pid, uint64_t start)
{
    std::lock_guard<std::mutex> lock(gWs.joinedMutex);
    gWs.joined.emplace_back(pid, start);
}

/* On the ring thread: a winedevice.exe that joined late (the prefix poll) loaded its drivers unseen; they are
 * read back from its maps (.sys PE images) and handed to the decoder (WsDecoder::Joined). */
void WsPoll()
{
    std::vector<std::pair<uint32_t, uint64_t>> joined;
    {
        std::lock_guard<std::mutex> lock(gWs.joinedMutex);
        joined.swap(gWs.joined);
    }
    for (const auto& [pid, start] : joined) {
        uint64_t tracked = 0;
        ULONG flags = 0;
        if (!gWs.attached || !gBpf.session->Tracked(pid, tracked, flags) || tracked != start) continue;
        std::ifstream cmdline("/proc/" + std::to_string(pid) + "/cmdline", std::ios::binary);
        std::string argv0, ntdll;
        std::getline(cmdline, argv0, '\0');
        if (!LinuxWinedevice(LinuxWide(argv0)) || WsProtocolForBuild(WsNtdllBuild(pid, ntdll)) != kWsProtocol) continue;
        std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
        std::vector<WsDriver> drivers;
        for (const MappedImage& image : MappedImages(maps)) {
            const std::string& path = image.path;
            if (image.pe && path.size() > 4 && strcasecmp(path.c_str() + path.size() - 4, ".sys") == 0)
                drivers.push_back({image.base, image.base + image.size, LinuxWide(path)});
        }
        if (LinuxProcessStart(pid) != start) continue;   /* the pid was reused while its maps were read */
        static mm_ws_event identity;   /* about 17 KB */
        identity = {};
        identity.tgid = identity.tid = pid;
        identity.req = 63;   /* create_mapping, as a live driver load */
        identity.start_ns = (start - LinuxBootFileTime()) * 100;   /* HertzTicksToFileTime gives Start back */
        timespec now{};
        clock_gettime(CLOCK_BOOTTIME, &now);
        identity.ts_ns = static_cast<uint64_t>(now.tv_sec) * 1000000000ull + now.tv_nsec;
        gWs.decoder.Joined(identity, drivers, WsWrite);
    }
}

/* Windows wineserver freed with their thread or process had no destroy_window reply: their owners leave ws_windows
 * (each while it still names that window: a create_window since keeps its own), so a call on a window that index names
 * next is not taken for the old creator's (up.bpf.h). WinTid 0: every thread's. */
void WsWindowsGone(uint32_t tgid, uint32_t winTid)
{
    const std::vector<uint32_t> handles = gWs.decoder.DropWindows(tgid, winTid);
    bpf_map* map = gBpf.object ? bpf_object__find_map_by_name(gBpf.object, "ws_windows") : nullptr;
    for (const uint32_t handle : map != nullptr ? handles : std::vector<uint32_t>()) {
        const uint32_t index = mm_ws_window_index(handle);
        mm_ws_window owner{};
        if (index == 0 || bpf_map_lookup_elem(bpf_map__fd(map), &index, &owner) != 0 || owner.tgid != tgid || owner.gen != handle >> 16)
            continue;
        const mm_ws_window none{};
        bpf_map_update_elem(bpf_map__fd(map), &index, &none, BPF_ANY);
    }
}

void WsForget(const mm_event& e)
{
    WsWindowsGone(e.tgid, 0);
    gWs.decoder.Forget(e.tgid, WsWrite);
    gWs.processes.erase(e.tgid);
}

void WsClose()
{
    gWs.decoder.Reset();
    gWs.processes.clear();
    gWs.lastBuild.clear();
    gWs.lastPath.clear();
    gWs.attached = false;
    {
        std::lock_guard<std::mutex> lock(gWs.joinedMutex);
        gWs.joined.clear();
    }
    WsNtdllReset();
}

void WsNotes(Notes& notes)
{
    if (GroupOn("wineserver") && gWs.attached) {
        notes.emplace_back(
            L"wineserver_requests",
            L"protocol=" + std::to_wstring(kWsProtocol) +
                L";builds=wine-11.0;records=registry,process_handle,thread_handle,file_create,file_section,"
                L"file_query_volume_information,file_query_information,network_connect,network_accept,"
                L"file_read,file_write,file_system_control,file_close,file_flush,file_device_control,file_set_information,"
                L"file_directory_control,file_device_control,file_query_security,file_set_security,etw_rpc,etw_wmi,"
                L"etw_code_integrity;other_requests=system:<request>;hot_requests=kernel_aggregate+sampled;"
                L"rejected_writes=each;winedevice=component+brokered_winedevice;winedevice_late=reconstructed;"
                L"wineserver_syscalls=served_pid+brokered_wineserver;protocol_pipes=counted_only;input=all;real_keys=" +
                (gRealInput ? std::wstring(L"on") : std::wstring(L"off(--log-real-input)")) + L";content=" +
                (gBpf.content ? std::wstring(L"on") : std::wstring(L"off(--log-content)")) + L";window_owners=create_window" +
                L";payloads=" +
                (gBpf.payloads ? L"on" : L"off") + L";request_bytes=" + std::to_wstring(MM_WS_DATA) +
                L";reply_bytes=" + std::to_wstring(MM_WS_DATA) + L";gate=ntdll_build");
        return;
    }
    const Group* group = FindGroup("wineserver");
    notes.emplace_back(L"wineserver_requests_unavailable",
                       group->state == 0    ? std::wstring(L"attach_failed")
                       : group->state == -1 ? std::wstring(L"group_off")
                                            : L"load_failed:" + std::to_wstring(group->state));
}

}  // namespace
