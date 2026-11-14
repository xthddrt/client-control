#pragma once
/*
 * Decoder of a Wine client's wineserver requests (protocol 930 = wine-11.0), captured by
 * agent/linux/bpf/ws.bpf.h as MM_WS_REQUEST / MM_WS_REPLY records. Pure: no BPF, no session; bpf_ws.inc
 * feeds it ring records and writes what it returns. tests/wineserver_test.cpp drives it with synthetic
 * buffers. docs/LINUX.md "Wineserver requests" lists the records.
 */
#include "session.h"
#include "bpf/monitor_bpf.h"
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

constexpr unsigned kWsProtocol = 930;   /* SERVER_PROTOCOL_VERSION the tables below are for */

/* ws_cfg for protocol 930: every request, the replies whose data is decoded, the hot requests counted per key in the
 * kernel and what is never aggregated (AFD ioctls, injected input, cursor moves), the window requests that keep the
 * kernel's window owners (ws_windows). RealInput (--log-real-input): the user's own input is not aggregated either.
 * Content (--log-content): get_clipboard_data's reply data is captured too (hashed, never logged). */
mm_ws_config WsCaptureConfig(bool realInput, bool content = false);
/* A window message that carries the user's keys (WM_KEYDOWN..WM_UNICHAR, the IME's, raw input, a low-level keyboard
 * hook's call); Type the message_type (0 for a call's own). */
bool WsKeyboardMessage(uint32_t msg, uint32_t type);
/* A kernel aggregate of a wineserver request (agg key MM_COUNT_WS | Request) as its repeats_tail summary: text
 * system:<request>, detail repeats_tail;syscall=wineserver:<request>;aggregate=kernel;<key fields>;repeats_before=... */
LinuxRecord WsAggSummary(uint32_t request, uint64_t key, const mm_agg& total);
/* The wineserver protocol of an ntdll.so build string ("wine-11.0" -> 930); 0 = not decoded. */
unsigned WsProtocolForBuild(const std::string& build);
/* The build string of the ntdll.so process Pid maps (via /proc/<pid>/map_files, else the path), or "";
 * Path is set to the mapping's path. Results are cached by path. */
std::string WsNtdllBuild(uint32_t pid, std::string& path);
void WsNtdllReset();
/* "wineserver:<request>" for a protocol-930 request number (a static string; "wineserver:unknown" past the table). */
const char* WsRequestName(uint32_t request);
/* One connection-oriented DCE/RPC PDU header (C706 12.6), little-endian only. */
struct WsRpcPdu {
    uint8_t ptype = 0;        /* 0 request, 2 response, 3 fault, 11 bind, 12 bind_ack, 14 alter_context */
    uint32_t callId = 0;
    uint32_t context = 0;     /* request: p_cont_id */
    uint32_t opnum = 0;       /* request */
    std::vector<std::pair<uint32_t, std::wstring>> binds;   /* bind / alter_context: context id -> interface */
    std::wstring version;     /* the first bound interface's major.minor */
};
/* Parses the PDU Data starts with (false: not DCE/RPC v5.0 little-endian, or cut before its fields). */
bool WsParseRpc(const uint8_t* data, size_t length, WsRpcPdu& pdu);

/* One decoded record: Record is complete apart from pid/tid/start/timestamp/stack, which the caller takes
 * from Request (and TsNs). */
struct WsRecord {
    LinuxRecord record;
    const mm_ws_event* request = nullptr;   /* the request it decodes (identity, stack, PE context) */
    uint64_t tsNs = 0;                      /* CLOCK_BOOTTIME of the reply (or of the request) */
    bool collapse = false;                  /* may be collapsed by Repeated (key: text + repeatKey) */
    uint64_t repeatKey = 0;
    bool payload = false;                   /* write Bytes as a payload series of PayloadKind */
    ULONG payloadKind = 0;
    uint64_t payloadTotal = 0;
    std::vector<BYTE> bytes;
};

using WsSink = std::function<void(WsRecord&)>;
/* Reads the 8-byte word at Address of process Tgid (false: unreadable). */
using WsReader = std::function<bool(uint32_t tgid, uint64_t address, uint64_t& value)>;
/* A .sys image a winedevice.exe has mapped: [base, end) and its path. */
struct WsDriver {
    uint64_t base = 0, end = 0;
    std::wstring path;
};

class WsDecoder {
public:
    /* Payloads false (--no-payloads): registry and volume records keep their metadata only. */
    void SetPayloads(bool payloads) { payloads_ = payloads; }
    /* RealInput (--log-real-input): the user's own keys (non-injected keyboard input, keyboard messages) are logged too. */
    void SetRealInput(bool realInput) { realInput_ = realInput; }
    /* Content (--log-content): IRP, async and ioctl results are payloads of all their captured bytes (not the first
     * kResultBytes) even with --no-payloads, and clipboard data is hashed (its bytes never logged). */
    void SetContent(bool content) { content_ = content; }
    /* How DeviceRequest reads a late-joined winedevice's DEVICE_OBJECT / DRIVER_OBJECT (none: not resolved). */
    void SetReader(WsReader reader) { reader_ = std::move(reader); }
    /* A winedevice.exe that joined tracking after it loaded its drivers (Identity: its tgid, tid, start_ns,
     * ts_ns): one driver_load record (reconstructed=1) per mapped .sys, and it is a device manager whose
     * IRPs name the driver of their device. Nothing when it was seen making its device manager. */
    void Joined(const mm_ws_event& identity, const std::vector<WsDriver>& drivers, const WsSink& sink);
    /* One ring record (data_len already clamped to the bytes received). */
    void Event(const mm_ws_event& event, const WsSink& sink);
    /* The process exited or exec'd: its unanswered requests are written, its state dropped. */
    void Forget(uint32_t tgid, const WsSink& sink);
    /* The windows Tgid's thread WinTid made (every thread's when WinTid is 0), as whole handles, forgotten: wineserver
     * frees them with their thread or process (destroy_thread_windows, a crash) and no destroy_window reply says so. */
    std::vector<uint32_t> DropWindows(uint32_t tgid, uint32_t winTid);
    void Reset();

private:
    struct Device {
        std::wstring name;     /* \Device\... as create_device named it */
        std::wstring driver;   /* the .sys that was loading when it was created ("" unknown) */
    };
    /* An IRP winedevice was given (get_next_device_request's reply): its driver and client; for its result, also its
     * record type, device and request. */
    struct Irp {
        std::wstring driver;
        uint32_t clientTgid = 0;
        uint32_t clientWinTid = 0;
        ULONG type = 0;
        std::wstring text;               /* the device */
        const wchar_t* what = L"";       /* create, read, ioctl, ... */
        uint32_t code = 0;               /* an ioctl's IoControlCode */
    };
    struct Process {
        std::unordered_map<uint32_t, std::wstring> keys;   /* registry handle -> key path */
        std::unordered_map<uint32_t, uint32_t> processes;  /* process handle -> Windows pid */
        std::unordered_map<uint32_t, uint32_t> threads;    /* thread handle -> Windows tid */
        std::unordered_map<uint32_t, uint32_t> access;     /* process / thread handle -> access asked for */
        std::unordered_map<uint32_t, std::wstring> files;  /* file / pipe / named object / section handle -> NT name */
        std::unordered_map<uint32_t, uint32_t> tokens;     /* token handle -> Windows pid of its process (0 unknown) */
        std::unordered_map<uint32_t, std::pair<uint32_t, uint32_t>> apcs;   /* queue_apc handle -> (Windows pid, APC type) */
        std::unordered_map<uint64_t, std::wstring> views;  /* map_view / map_image_view base -> section name */
        std::unordered_set<uint64_t> imageViews;           /* map_image_view bases: unmapping one unloads an image */
        /* RPC binds per pipe handle: presentation context id -> interface UUID. */
        std::unordered_map<uint32_t, std::unordered_map<uint32_t, std::wstring>> rpc;
        /* winedevice.exe (it made a device manager): its drivers, devices and FILE_OBJECTs. */
        bool winedevice = false;
        std::wstring driver;                                 /* the .sys last mapped as an image */
        std::vector<WsDriver> drivers;                       /* joined late: its .sys images (Joined) */
        std::unordered_map<uint64_t, Device> devices;        /* DEVICE_OBJECT -> device */
        std::unordered_map<uint64_t, uint64_t> fileObjects;  /* FILE_OBJECT -> DEVICE_OBJECT */
        std::unordered_map<uint32_t, uint64_t> creates;      /* create IRP file handle -> DEVICE_OBJECT */
        std::unordered_map<uint32_t, Irp> irps;              /* IRP handle -> the IRP, until its result */
        void Handed(uint32_t handle)
        {
            keys.erase(handle);
            processes.erase(handle);
            threads.erase(handle);
            access.erase(handle);
            files.erase(handle);
            tokens.erase(handle);
            apcs.erase(handle);
            rpc.erase(handle);
            irps.erase(handle);
        }
    };
    /* A request awaiting its reply. Its handles are resolved when it is sent: replies of different threads
     * reach the ring in scheduling order, not in the order wineserver handled them, so by the reply the
     * handle may already be closed and given out again. */
    struct Pending {
        std::unique_ptr<mm_ws_event> event;
        uint32_t winPid = 0;   /* Windows pid the request's process handle named (a thread handle: its tid; 0 unknown) */
        std::wstring key;      /* path of the request's registry key (or parent) handle, "" if none */
        std::wstring name;     /* NT name of the request's file / pipe handle, "" if unknown */
        std::wstring root;     /* NT name of the request's rootdir (named objects) or second handle, "" if unknown */
        uint32_t peer = 0;     /* dup_handle: Windows pid of the destination process (0: the caller's or unknown) */
        uint32_t object = 0;   /* the request's handle is 1 a process, 2 a thread, 3 a token (winPid: its process), 0 other */
        uint32_t granted = 0;  /* the access that handle was opened with (0 unknown) */
        std::wstring fields;   /* the generic decoder's request fields (Fields) */
        uint32_t fieldTarget = 0;   /* the other tracked process a field named (0 none) */
        uint64_t collapseKey = 0;   /* the value of the field a generic record is collapsed by */
    };
    struct Unix {
        uint32_t tgid = 0;
        uint64_t startNs = 0;
    };
    struct Window {
        uint32_t tgid = 0;     /* the process that created it */
        uint32_t winTid = 0;
        uint32_t gen = 0;      /* its handle's high word */
    };
    void Resolve(Pending& pending);
    void Decode(const Pending& pending, const mm_ws_event* reply, const WsSink& sink);
    void Emit(WsRecord& record, const WsSink& sink);
    void Rpc(const Pending& pending, const uint8_t* data, size_t length, const wchar_t* via, const WsSink& sink);
    void DeviceRequest(const Pending& pending, const mm_ws_event& reply, const WsSink& sink);
    void IrpResult(const mm_ws_event& request, uint32_t handle, uint32_t status, uint64_t information, const uint8_t* data,
                   size_t length, uint64_t total, const WsSink& sink);
    void Rejected(const mm_ws_event& event, const WsSink& sink);
    std::wstring Fields(const mm_ws_event& request, Process& process, uint32_t& target);
    std::wstring ReplyFields(const mm_ws_event& request, const mm_ws_event* reply, Process& process, bool forget);
    std::wstring Vararg(const std::vector<std::string>& varargs, const uint8_t* data, size_t length, uint64_t total,
                        const wchar_t* prefix);
    std::wstring Result(WsRecord& out, const uint8_t* bytes, size_t captured, uint64_t total);
    std::wstring Message(uint32_t msg, uint32_t type, uint64_t wparam, uint64_t lparam, const uint8_t* data, size_t length,
                         uint64_t total);
    std::wstring KeyPath(uint32_t tgid, uint32_t handle);
    void Target(uint32_t winPid, WsRecord& out);
    Process* Of(uint32_t winPid);
    std::wstring DriverOf(uint32_t tgid, const Process& process, uint64_t device);
    std::unordered_map<uint32_t, Irp> irps_;                                /* winedevice tid -> the IRP it dispatches */

    bool payloads_ = true;
    bool realInput_ = false;
    bool content_ = false;
    /* Windows by their handle's index (the low 16 bits: a window is also named by those alone) -> who created them,
     * from create_window replies; destroy_window and the creator's end forget them. */
    std::unordered_map<uint32_t, Window> windows_;
    WsReader reader_;
    std::unordered_map<uint32_t, Pending> pending_;                         /* tid -> request awaiting reply */
    std::unordered_map<uint32_t, Process> processes_;                      /* tgid -> handles */
    std::unordered_map<uint32_t, Unix> winPids_;                            /* Windows pid -> unix process */
    /* A child new_process created with inherited handles (Windows pid -> the parent's named handles at the same
     * values), applied when its first request arrives. */
    std::unordered_map<uint32_t, Process> inherits_;
    /* shortcut: winTids_ (and the pending_ entry of a thread that dies mid-request) live until the process
     * exits or execs, a few dozen bytes per Windows thread; drop them on MM_THREAD_EXIT if a client churns
     * through millions of threads. */
    std::unordered_map<uint32_t, Unix> winTids_;                            /* Windows tid -> unix process */
};
