#pragma once

#include "../telemetry.h"
#include "../../include/msmon_coverage.h"
#include <condition_variable>
#include <thread>
#include <utility>

/* One record with every header field a sensor can fill (Log fills the common ones). */
struct LinuxRecord {
    unsigned sensor = MSMON_SENSOR_SLOTS;
    ULONG type = 0;
    DWORD pid = 0;
    DWORD tid = 0;
    DWORD parent = 0;
    DWORD target = 0;
    uint64_t start = 0;
    uint64_t timestamp = 0;   /* FILETIME; 0 = now */
    ULONG flags = 0;
    long status = 0;
    uint64_t value0 = 0;
    uint64_t value1 = 0;
    std::wstring text;
    std::wstring detail;
    std::wstring component;                   /* header Component: the driver winedevice.exe works for */
    std::vector<uint64_t> stack;
    ULONG desiredAccess = 0;                  /* header DesiredAccess */
    uint64_t targetStart = 0;                 /* header TargetProcessStartTime */
    uint64_t operation = 0;                   /* operation_id of a record without a payload */
    const MSMON_PAYLOAD* payload = nullptr;   /* one chunk; WritePayloadSeries fills it */
};

/* Set before LinuxSession::Start; false keeps the eBPF sensors off (--no-ebpf). */
void LinuxSessionUseEbpf(bool enabled);
/* Set before LinuxSession::Start; true also refuses the tracked tree bpf() and perf_event_open (default off:
 * msmon observes only, so an audit run does not change what the client can do; the agent itself is always
 * protected from ptrace and signals of the tracked tree). */
void LinuxSessionProtectTree(bool enabled);
/* Set before LinuxSession::Start: the eBPF repeat-collapse window (default 1000 ms; 0 writes every call). */
void LinuxSessionRepeatWindow(uint64_t milliseconds);
/* Set before LinuxSession::Start: native programs a tracked process execs stay tracked as native helpers (a reduced
 * set of calls) for this many execs in a row (default 3; 0 untracks them at once). */
void LinuxSessionNativeDepth(uint64_t depth);
/* Set before LinuxSession::Start: also record first touches of shared mapped pages (eBPF faults group; off). */
void LinuxSessionPageFaults(bool enabled);
/* Set before LinuxSession::Start: also log the user's own keys (winex11's keyboard input and keyboard messages through
 * wineserver; off: their keys are left out, privacy). */
void LinuxSessionRealInput(bool enabled);
/* Set before LinuxSession::Start: also log the value of every environment variable an exec starts with
 * (process_environment; off: only the variable names and Wine's, the loader's and the graphics stack's values, since a
 * value may hold a secret the user exported). */
void LinuxSessionLogEnvironment(bool enabled);
/* Set before LinuxSession::Start: also log contents msmon otherwise names, sizes or hashes only (off: privacy and
 * volume): AF_UNIX and pipe bytes (one 8 KiB chunk a message logged, all captured hashed), DRM and socket ioctls'
 * argument structs, IRP and async results in full, clipboard data's SHA-256. */
void LinuxSessionLogContent(bool enabled);
/* Set before LinuxSession::Start: also probe the window functions (NtUserCallHwndParam, NtUserMessageCall,
 * NtUserPostMessage, NtUserSetWindowLong(Ptr), NtUserSetWindowPos; off: each call of a probed function takes a trap,
 * and the game calls NtUserCallHwndParam every frame). Only other programs' windows are recorded. */
void LinuxSessionWindowProbes(bool enabled);
/* Set before LinuxSession::Start: one more hardware watchpoint (--watch MODULE+0xOFFSET:LENGTH:ACCESS or
 * 0xADDRESS:LENGTH:ACCESS, at most 4; watch.cpp); false and why when it is refused. None: nothing is watched. */
bool LinuxSessionWatch(const std::wstring& spec, std::wstring& error);

/*
 * In-process stand-in for the Windows driver.  The Linux sensors log records here in
 * the driver's wire format (MSMON_EVENT_HEADER + strings), with one sequence and one
 * bounded queue, so agent.cpp reads, gap-checks and accounts them unchanged.
 */
class LinuxSession {
public:
    static LinuxSession& Instance();
    bool Start(const MSMON_SESSION_CONFIG& config);
    void Stop();
    /* Family: a process kfilter decides for (agent.cpp drainKfilter); it joins as a native helper when it runs a
     * native program, and not at all when the kernel dropped it past --native-depth. */
    bool Track(DWORD pid, uint64_t expectedStart, ULONG flags, bool family = false);
    void StopTracking();
    bool Read(DWORD waitMs, std::vector<BYTE>& buffer, DWORD& bytes);
    void Statistics(MSMON_STATISTICS& statistics);
    void Coverage(MSMON_COVERAGE& coverage);
    /* Coverage records (text, detail) the agent writes at session start. */
    std::vector<std::pair<std::wstring, std::wstring>> Notes();

    /* Sensor side. */
    bool Stopping() const { return stopping_.load(); }
    bool Tracked(DWORD pid, uint64_t& start, ULONG& flags) const;
    std::vector<std::pair<DWORD, uint64_t>> TrackedProcesses() const;
    /* Track without logging; false once tracking has stopped. Native: BpfTrack's. */
    bool Admit(DWORD pid, uint64_t start, ULONG flags, bool native = false);
    void Forget(DWORD pid, uint64_t start);
    bool UnderRoot(const std::wstring& path) const;
    void Log(unsigned sensor, ULONG type, DWORD pid, uint64_t start, ULONG flags, uint64_t value0, uint64_t value1,
             const std::wstring& text, const std::wstring& detail = {}, DWORD parent = 0);
    /* false when the record was not queued (stopped, or the queue is full). MsMonFlagServiceCorrelated
     * in its flags makes its attribution service_correlated. */
    bool Write(const LinuxRecord& record);
    /* MsMonLogPayloadSeries: Record once per MSMON_PAYLOAD_CHUNK_BYTES of Data, all chunks under
     * Record.operation (0: a new one); Total above Data's size leaves the series partial, and then Data
     * must be whole chunks (tools/verify_log.py refuses a short chunk that is not the last). Stops at the
     * first chunk the queue refuses, so an operation never has a hole. */
    bool WritePayloadSeries(LinuxRecord record, ULONG kind, uint64_t total, const std::vector<BYTE>& data);
    /* A new operation_id (one counter for every sensor, as the driver's MsMonNextOperationId). */
    uint64_t NextOperation() { return ++operations_; }
    void Enter(unsigned sensor);
    void SkipUntracked();
    /* A source lost events it cannot name: burn a sequence number so the agent logs a gap. */
    void NoteDropped();

private:
    void Registered(unsigned slot, int error);
    void PollLoop();

    mutable std::mutex mutex_;
    std::condition_variable data_;
    std::condition_variable wake_;
    std::deque<std::vector<BYTE>> queue_;
    uint64_t queuedBytes_ = 0;
    uint64_t queueRecords_ = 0;
    uint64_t queueBytesLimit_ = 0;
    uint64_t sequence_ = 0;
    uint64_t dropped_ = 0;
    uint64_t sessionId_ = 0;
    std::atomic<uint64_t> operations_{0};
    MSMON_COVERAGE coverage_{};
    struct TrackedProcess {
        uint64_t start = 0;
        ULONG flags = 0;
    };
    std::unordered_map<DWORD, TrackedProcess> tracked_;
    std::vector<std::wstring> roots_;
    std::vector<std::pair<std::wstring, std::wstring>> notes_;
    std::vector<std::thread> threads_;
    std::atomic<bool> stopping_{false};
    bool running_ = false;
    bool tracking_ = false;
    bool ebpf_ = false;
    bool pollNet_ = true;
};

/* The agent's driver handle, backed by LinuxSession. */
class DeviceSession {
public:
    ~DeviceSession()
    {
        if (started_) LinuxSession::Instance().Stop();
    }
    bool Open() { return true; }
    bool Start(MSMON_SESSION_CONFIG& config)
    {
        started_ = LinuxSession::Instance().Start(config);
        return started_;
    }
    bool Track(DWORD pid, uint64_t startTime, ULONG flags) { return LinuxSession::Instance().Track(pid, startTime, flags); }
    bool TrackFamily(DWORD pid, uint64_t startTime)
    {
        return LinuxSession::Instance().Track(pid, startTime, MsMonFlagExplicitTrack, true);
    }
    bool Read(DWORD waitMs, std::vector<BYTE>& buffer, DWORD& bytes)
    {
        return LinuxSession::Instance().Read(waitMs, buffer, bytes);
    }
    bool RefreshModules() { return true; }
    bool StopTracking()
    {
        LinuxSession::Instance().StopTracking();
        return true;
    }
    bool Statistics(MSMON_STATISTICS& statistics)
    {
        LinuxSession::Instance().Statistics(statistics);
        return true;
    }
    bool Coverage(MSMON_COVERAGE& coverage)
    {
        LinuxSession::Instance().Coverage(coverage);
        return true;
    }
    std::vector<std::pair<std::wstring, std::wstring>> Notes() { return LinuxSession::Instance().Notes(); }

private:
    bool started_ = false;
};

/* Sensors (one file each).  Open returns 0 or an errno and fills detail. */
int FanotifyOpen(std::wstring& detail);
void FanotifyRun(LinuxSession& session);
void FanotifyClose();
int ProcConnectorOpen(std::wstring& detail);
void ProcConnectorRun(LinuxSession& session);
void ProcConnectorClose();
/* Hold: keep the loads found for ImagesRelease (pid 0: every process's) instead of logging them now. */
/* Inherited: a fork child's maps are its parent's, already logged for it: kept (PE frames, the poll's
 * skip list), not logged again. Unloads (the 2 s poll): log the images the last such scan listed and this one no more. */
void ImagesScan(LinuxSession& session, DWORD pid, uint64_t start, bool hold = false, bool inherited = false, bool unloads = false);
void ImagesRelease(LinuxSession& session, DWORD pid);
/* true the first time a load (pid, start, base, path) is named; ImagesScan then does not log it again. */
bool ImagesClaim(DWORD pid, uint64_t start, uint64_t base, const std::string& path);
void ImagesForget(DWORD pid);
void ImagesReset();
void NetPoll(LinuxSession& session);
void NetReset();
/* eBPF sensors (bpf.cpp).  BpfOpen returns 0 or an errno and sets bit (slot - 48) of
 * Registered for each MSMON_SENSOR_LINUX_EBPF_* sensor that attached; Roots are the scope
 * roots (the first MM_ROOTS go to the kernel) an untracked process's executable mapping is
 * matched against; ProtectTree: LinuxSessionProtectTree. */
int BpfOpen(std::wstring& detail, const std::vector<std::wstring>& roots, bool payloads, bool protectTree,
            unsigned& registered);
void BpfRun(LinuxSession& session);
void BpfClose();
/* Native: a native helper (MM_TRACK_NATIVE at depth 1) when the kernel has no entry for it yet. */
void BpfTrack(DWORD pid, uint64_t start, ULONG flags, bool native);
/* True for a native helper the kernel stopped tracking past --native-depth (mm_exec): it does not join again. */
bool BpfDropped(DWORD pid, uint64_t start);
void BpfForget(DWORD pid);
/* A process that joined tracking after it started (LinuxSession::Track): a winedevice.exe's drivers are
 * reconstructed from its maps (bpf_ws.inc). Any thread. */
void BpfJoined(DWORD pid, uint64_t start);
void BpfClear();
/* Coverage notes of the kernel-sensor upgrades (after ebpf_active), and the records they still hold,
 * written before tracking stops. */
std::vector<std::pair<std::wstring, std::wstring>> BpfNotes();
void BpfFlush();
/* Packet capture to pcapng (packets.cpp). Configure before LinuxSession::Start: Path empty = off;
 * parts rotate at MaxPartBytes (0 = never). Note: the start coverage note, {} when off. TakeNotes:
 * coverage records to chain now (Final: the session ends; closes the last part). */
void PacketsConfigure(const std::wstring& path, uint64_t maxPartBytes);
std::pair<std::wstring, std::wstring> PacketsNote();
std::vector<std::pair<std::wstring, std::wstring>> PacketsTakeNotes(bool final);
/* Watchpoints (watch.cpp), only with LinuxSessionWatch. WatchOpen returns 0 or an errno and fills detail; WatchFlush
 * closes the breakpoints and writes what the kernel still counts, before tracking stops. */
bool WatchWanted();
int WatchOpen(std::wstring& detail);
void WatchRun(LinuxSession& session);
void WatchFlush(LinuxSession& session);
void WatchClose();
/* "/proc/<pid>/cmdline" with NUL separators as spaces, as the Windows command line. */
std::wstring ProcessCommandLine(DWORD pid);
