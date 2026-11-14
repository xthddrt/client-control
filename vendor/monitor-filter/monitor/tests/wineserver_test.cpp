/* Self-test of the wineserver request decoder (agent/linux/wineserver.cpp) with synthetic protocol-930
 * request/reply records, as ws.bpf.h sends them. Run by build.sh; no root, no BPF. */
#include "../agent/linux/wineserver.h"
#include <fcntl.h>
#include <climits>
#include <cstdlib>
#include <algorithm>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <map>
#include <memory>

namespace {

int failures = 0;
#define CHECK(what, condition)                                         \
    do {                                                               \
        if (!(condition)) {                                            \
            std::fprintf(stderr, "[fail] %s: %s\n", what, #condition); \
            failures++;                                                \
        }                                                              \
    } while (0)

constexpr uint32_t kTgid = 4242, kTid = 4243, kWinPid = 0x20;
uint64_t gClock = 1000000000ull;

std::unique_ptr<mm_ws_event> Event(uint32_t kind, uint32_t req, const std::vector<uint8_t>& data, uint32_t total)
{
    auto e = std::make_unique<mm_ws_event>();
    e->kind = kind;
    e->tgid = kTgid;
    e->tid = kTid;
    e->req = req;
    e->total = total;
    e->data_len = static_cast<uint32_t>(std::min<size_t>(data.size(), MM_WS_DATA));
    e->win_pid = kind == MM_WS_REQUEST ? kWinPid : 0;
    e->win_tid = kind == MM_WS_REQUEST ? kWinPid + 4 : 0;
    e->start_ns = 77;
    e->ts_ns = gClock += 1000;
    std::memcpy(e->data, data.data(), e->data_len);
    if (kind == MM_WS_REQUEST) {
        std::memcpy(e->fixed, &req, 4);
        std::memcpy(e->fixed + 4, &total, 4);
    }
    return e;
}

void Put32(mm_ws_event& e, size_t offset, uint32_t value) { std::memcpy(e.fixed + offset, &value, 4); }
void Put64(mm_ws_event& e, size_t offset, uint64_t value) { std::memcpy(e.fixed + offset, &value, 8); }
void Put32Bytes(std::vector<uint8_t>& bytes, size_t offset, uint32_t value) { std::memcpy(bytes.data() + offset, &value, 4); }

std::vector<uint8_t> U16(const char* text)
{
    std::vector<uint8_t> out;
    for (; *text; text++) {
        out.push_back(static_cast<uint8_t>(*text));
        out.push_back(0);
    }
    return out;
}

std::vector<uint8_t> Cat(std::vector<uint8_t> a, const std::vector<uint8_t>& b)
{
    a.insert(a.end(), b.begin(), b.end());
    return a;
}

std::vector<uint8_t> Le32(uint32_t value) { return {uint8_t(value), uint8_t(value >> 8), uint8_t(value >> 16), uint8_t(value >> 24)}; }

/* objattr: rootdir, attributes, sd_len 0, name_len, name, padded to 4. */
std::vector<uint8_t> ObjAttr(uint32_t root, const char* name)
{
    const std::vector<uint8_t> text = U16(name);
    std::vector<uint8_t> out = Cat(Cat(Cat(Le32(root), Le32(0x40)), Cat(Le32(0), Le32(static_cast<uint32_t>(text.size())))), text);
    out.resize((out.size() + 3) & ~size_t(3));
    return out;
}

struct Harness {
    WsDecoder decoder;
    std::vector<WsRecord> out;
    WsSink sink = [this](WsRecord& record) { out.push_back(record); };

    /* One request and (unless reply is null) its reply; returns the records written by it. */
    std::vector<WsRecord> Run(mm_ws_event& request, mm_ws_event* reply)
    {
        out.clear();
        decoder.Event(request, sink);
        if (reply != nullptr) decoder.Event(*reply, sink);
        return out;
    }
};

std::unique_ptr<mm_ws_event> Reply(uint32_t req, uint32_t status, const std::vector<uint8_t>& data = {}, uint32_t total = 0)
{
    auto e = Event(MM_WS_REPLY, req, data, total ? total : static_cast<uint32_t>(data.size()));
    Put32(*e, 0, status);
    Put32(*e, 4, e->total);
    return e;
}

std::string Narrow(const std::wstring& text) { return std::string(text.begin(), text.end()); }

/* One generic record of Request (a request no case records as an object of its own): system:<request>. */
bool Generic(const std::vector<WsRecord>& got, const char* request)
{
    return got.size() == 1 && got[0].record.type == MsMonFileQueryInformation && got[0].collapse &&
           Narrow(got[0].record.text) == std::string("system:") + request &&
           Narrow(got[0].record.detail).rfind(std::string("ws=") + request + ";", 0) == 0;
}

bool Bit(const __u64* bits, uint32_t request) { return (bits[request >> 6] >> (request & 63)) & 1; }

}  // namespace

int main()
{
    Harness h;
    const std::wstring root = L"\\Registry\\Machine\\Software\\MsmonProbe";

    /* (a) capture config: every request (numbers past the table too), reply data, the hot requests counted per key in
     * the kernel (their first call of a key per drain captured), what is never aggregated. */
    const mm_ws_config config = WsCaptureConfig(false);
    for (uint32_t request = 0; request < MM_WS_REQUESTS; request++) CHECK("a", Bit(config.want, request));
    CHECK("a", Bit(config.data, 92) && Bit(config.data, 122) && Bit(config.data, 134) && Bit(config.data, 138));
    CHECK("a", Bit(config.data, 110) && Bit(config.data, 200) && !Bit(config.data, 3));   /* atom and module names; no environment */
    CHECK("a", !Bit(config.data, 84));   /* read_process_memory bytes are not kept */
    CHECK("a", Bit(config.agg, 29) && config.key[29][0] == 0 && config.key[29][1] == 0xc);              /* select: flags */
    CHECK("a", Bit(config.agg, 138) && config.key[138][0] == 0x10 && config.key[138][1] == 0xc);         /* ioctl: handle, code */
    CHECK("a", Bit(config.agg, 31) && config.key[31][0] == 0xc && config.key[31][1] == 0x10);            /* event_op */
    CHECK("a", Bit(config.agg, 134) && Bit(config.agg, 121) && Bit(config.agg, 279) && config.key[121][0] == 0x38);
    CHECK("a", !Bit(config.agg, 122) && !Bit(config.agg, 21) && !Bit(config.agg, 87));   /* get_message, close_handle, open_key */
    CHECK("a", !Bit(WsCaptureConfig(true).agg, 121) && Bit(WsCaptureConfig(true).agg, 279));   /* --log-real-input: every key */
    /* the kernel's window owners from create_window and destroy_window; get_clipboard_data's data only with --log-content */
    CHECK("a", config.window_req[0] == 142 && config.window_req[1] == 143);
    CHECK("a", !Bit(config.data, 211) && Bit(WsCaptureConfig(false, true).data, 211));
    CHECK("a", WsKeyboardMessage(0x100, 0) && WsKeyboardMessage(0x102, 0) && !WsKeyboardMessage(0x10, 0) && !WsKeyboardMessage(0x4a, 0));
    CHECK("a", config.ioctl_req == 138 && std::count(std::begin(config.ioctl_codes), std::end(config.ioctl_codes), 0x12032cu) == 1);
    CHECK("a", WsProtocolForBuild("wine-11.0") == 930 && WsProtocolForBuild("wine-10.0") == 0);
    CHECK("a", std::strcmp(WsRequestName(0), "wineserver:new_process") == 0 &&
                   std::strcmp(WsRequestName(305), "wineserver:d3dkmt_mutex_release") == 0 &&
                   std::strcmp(WsRequestName(306), "wineserver:unknown") == 0 &&
                   std::strcmp(WsRequestName(155), "wineserver:set_window_pos") == 0);

    /* (b) open_key: absolute, then relative to the returned handle. */
    {
        auto q = Event(MM_WS_REQUEST, 87, U16("\\Registry\\Machine\\Software\\MsmonProbe"), 0);
        q->total = q->data_len;
        Put32(*q, 12, 0);
        Put32(*q, 16, 0x20019);
        auto r = Reply(87, 0);
        Put32(*r, 8, 0x10);
        auto got = h.Run(*q, r.get());
        CHECK("b", got.size() == 1 && got[0].record.type == MsMonRegistryOpen && got[0].record.text == root);
        CHECK("b", got.size() == 1 && got[0].record.desiredAccess == 0x20019 && got[0].record.status == 0);
        CHECK("b", got.size() == 1 && got[0].record.sensor == MSMON_SENSOR_LINUX_EBPF_WINESERVER && got[0].collapse);
        auto q2 = Event(MM_WS_REQUEST, 87, U16("Sub"), 6);
        Put32(*q2, 12, 0x10);
        auto r2 = Reply(87, 0);
        Put32(*r2, 8, 0x14);
        got = h.Run(*q2, r2.get());
        CHECK("b", got.size() == 1 && got[0].record.text == root + L"\\Sub");
    }
    /* (b2) a key handle duplicated within the process (crypt32's certificate stores) keeps its name. */
    {
        auto dup = Event(MM_WS_REQUEST, 23, {}, 0);
        Put32(*dup, 12, 0xffffffff);
        Put32(*dup, 16, 0x10);
        Put32(*dup, 20, 0xffffffff);
        Put32(*dup, 32, 2);   /* DUPLICATE_SAME_ACCESS */
        auto dupReply = Reply(23, 0);
        Put32(*dupReply, 8, 0x380);
        const auto dupped = h.Run(*dup, dupReply.get());   /* within the process: generic, no process_handle */
        CHECK("b2", Generic(dupped, "dup_handle") && dupped[0].record.detail.find(L";src_handle_name=" + root + L";") != std::wstring::npos);
        auto q = Event(MM_WS_REQUEST, 87, U16("Certificates"), 24);
        Put32(*q, 12, 0x380);
        auto r = Reply(87, 0);
        Put32(*r, 8, 0x384);
        auto got = h.Run(*q, r.get());
        CHECK("b2", got.size() == 1 && got[0].record.text == root + L"\\Certificates");
    }
    /* (c) create_key with objattr rootdir; an unknown parent handle is named. */
    {
        const auto attr = ObjAttr(0x10, "New");
        auto q = Event(MM_WS_REQUEST, 86, attr, static_cast<uint32_t>(attr.size()));
        Put32(*q, 12, 0xf003f);
        auto r = Reply(86, 0);
        Put32(*r, 8, 0x18);
        auto got = h.Run(*q, r.get());
        CHECK("c", got.size() == 1 && got[0].record.type == MsMonRegistryCreate && got[0].record.text == root + L"\\New");
        const auto lost = ObjAttr(0x99, "X");
        auto q2 = Event(MM_WS_REQUEST, 86, lost, static_cast<uint32_t>(lost.size()));
        got = h.Run(*q2, Reply(86, 0).get());
        CHECK("c", got.size() == 1 && got[0].record.text == L"hkey:0x99\\X");
    }
    const auto hello = U16("hello");
    /* (d) set_key_value REG_SZ "hello": input payload, value0 size, value1 type, detail the name. */
    {
        const auto name = U16("Probe");
        auto q = Event(MM_WS_REQUEST, 91, Cat(name, hello), 20);
        Put32(*q, 12, 0x10);
        Put32(*q, 16, 1);
        Put32(*q, 20, 10);
        auto got = h.Run(*q, Reply(91, 0).get());
        CHECK("d", got.size() == 1 && got[0].record.type == MsMonRegistrySetValue && got[0].record.detail == L"Probe");
        CHECK("d", got.size() == 1 && got[0].record.value0 == 10 && got[0].record.value1 == 1 && got[0].payload);
        CHECK("d", got.size() == 1 && got[0].bytes == hello && got[0].payloadTotal == 10 &&
                       (got[0].record.flags & MsMonFlagPayloadInput) && got[0].payloadKind == MsMonPayloadRegistryValue);
    }
    /* (e) get_key_value as RegQueryValueEx does it: a size probe (reply_size 0; wineserver answers success
     * with the total) has no payload and no unavailable flag; the read that follows is one complete chunk
     * and is not a repeat of the probe. */
    {
        auto q = Event(MM_WS_REQUEST, 92, U16("Probe"), 10);
        Put32(*q, 12, 0x10);
        auto r = Reply(92, 0);
        Put32(*r, 8, 1);
        Put32(*r, 12, 10);
        auto got = h.Run(*q, r.get());
        CHECK("e", got.size() == 1 && got[0].record.type == MsMonRegistryQuery && got[0].record.text == root);
        CHECK("e", got.size() == 1 && !got[0].payload && !(got[0].record.flags & MsMonFlagPayloadUnavailable) &&
                       got[0].record.detail == L"Probe;buffer=0");
        const uint64_t probeKey = got.size() == 1 ? got[0].repeatKey : 0;
        auto q2 = Event(MM_WS_REQUEST, 92, U16("Probe"), 10);
        Put32(*q2, 8, 10);
        Put32(*q2, 12, 0x10);
        auto r2 = Reply(92, 0, hello);
        Put32(*r2, 8, 1);
        Put32(*r2, 12, 10);
        got = h.Run(*q2, r2.get());
        CHECK("e", got.size() == 1 && got[0].record.detail == L"Probe" && got[0].record.value1 == 1);
        CHECK("e", got.size() == 1 && got[0].payload && got[0].bytes == hello && got[0].payloadTotal == 10);
        CHECK("e", got.size() == 1 && got[0].collapse && got[0].repeatKey != probeKey);
    }
    /* (f) a failed query: payload_unavailable with the reason first. */
    {
        auto q = Event(MM_WS_REQUEST, 92, U16("Gone"), 8);
        Put32(*q, 12, 0x10);
        auto got = h.Run(*q, Reply(92, 0xC0000034).get());
        CHECK("f", got.size() == 1 && (got[0].record.flags & MsMonFlagPayloadUnavailable) &&
                       got[0].record.detail == L"query_failed;value=Gone" && got[0].record.status == (int32_t)0xC0000034);
    }
    /* (g) enum_key_value (full): the name in the detail, the data as the payload; enum_key's name. */
    {
        auto q = Event(MM_WS_REQUEST, 93, {}, 0);
        Put32(*q, 8, 20);
        Put32(*q, 12, 0x10);
        Put32(*q, 16, 3);
        Put32(*q, 20, 1);
        auto r = Reply(93, 0, Cat(U16("Probe"), hello));
        Put32(*r, 8, 1);
        Put32(*r, 12, 20);
        Put32(*r, 16, 10);
        auto got = h.Run(*q, r.get());
        CHECK("g", got.size() == 1 && got[0].record.type == MsMonRegistryEnumerate && got[0].record.detail == L"Probe");
        CHECK("g", got.size() == 1 && got[0].record.value0 == 3 && got[0].bytes == hello && got[0].payloadTotal == 10);
        auto q2 = Event(MM_WS_REQUEST, 90, {}, 0);
        Put32(*q2, 12, 0x10);
        auto r2 = Reply(90, 0, U16("Sub"));
        Put32(*r2, 44, 6);
        got = h.Run(*q2, r2.get());
        CHECK("g", got.size() == 1 && got[0].record.detail == L"Sub" && !got[0].payload);
    }
    /* (h) open_process: the Windows pid of another tracked client maps to its unix pid. */
    {
        auto other = Event(MM_WS_REQUEST, 87, U16("\\Registry\\Machine"), 34);
        other->tgid = 5000;
        other->tid = 5000;
        other->win_pid = 2457;
        h.Run(*other, nullptr);
        auto q = Event(MM_WS_REQUEST, 27, {}, 0);
        Put32(*q, 12, 2457);
        Put32(*q, 16, 0x10);
        auto r = Reply(27, 0);
        Put32(*r, 8, 0x20);
        auto got = h.Run(*q, r.get());
        CHECK("h", got.size() == 1 && got[0].record.type == MsMonProcessHandle && got[0].record.target == 5000);
        CHECK("h", got.size() == 1 && got[0].record.desiredAccess == 0x10 && got[0].record.value1 == 0x10);
        CHECK("h", got.size() == 1 && got[0].record.detail == L"open_process;win_pid=2457;handle=0x20");
        /* A stronger open of the same process is not a repeat of the weaker one. */
        auto q2 = Event(MM_WS_REQUEST, 27, {}, 0);
        Put32(*q2, 12, 2457);
        Put32(*q2, 16, 0x38);
        auto got2 = h.Run(*q2, Reply(27, 0).get());
        CHECK("h", got.size() == 1 && got2.size() == 1 && got2[0].repeatKey != got[0].repeatKey);
    }
    /* (i) read_process_memory through that handle: value0 1, value1 the length, the target. */
    {
        auto q = Event(MM_WS_REQUEST, 84, {}, 0);
        Put32(*q, 8, 16);
        Put32(*q, 12, 0x20);
        Put64(*q, 16, 0x401000);
        auto got = h.Run(*q, Reply(84, 0).get());
        CHECK("i", got.size() == 1 && got[0].record.value0 == 1 && got[0].record.value1 == 16 && got[0].record.target == 5000);
        CHECK("i", got.size() == 1 && Narrow(got[0].record.detail).rfind("read_process_memory;handle=0x20;win_pid=2457;address=0x401000", 0) == 0);
        Put64(*q, 16, 0x402000);   /* another address: another repeat key, so it is never collapsed into the first */
        auto other = h.Run(*q, Reply(84, 0).get());
        CHECK("i", got.size() == 1 && other.size() == 1 && other[0].repeatKey != got[0].repeatKey);
    }
    /* (i2) Wine reuses the lowest free handle: after close_handle, new_process gets 0x20 for a child. */
    {
        auto close = Event(MM_WS_REQUEST, 21, {}, 0);
        Put32(*close, 12, 0x20);
        const auto closed = h.Run(*close, Reply(21, 0).get());   /* named when it was sent */
        CHECK("i2", Generic(closed, "close_handle") && closed[0].record.target == 5000 &&
                        closed[0].record.detail == L"ws=close_handle;handle=0x20;handle_win_pid=2457" &&
                        closed[0].repeatKey == 0);   /* collapsed per request ('!'), the first of a second naming its handle */
        auto spawn = Event(MM_WS_REQUEST, 0, {}, 0);
        auto spawned = Reply(0, 0);
        Put32(*spawned, 8, 0x1c);
        Put32(*spawned, 12, 3000);
        Put32(*spawned, 16, 0x20);
        const auto children = h.Run(*spawn, spawned.get());
        CHECK("i2", children.size() == 1 && children[0].record.type == MsMonProcessHandle &&
                        Narrow(children[0].record.detail) == "new_process;win_pid=3000;process_flags=0x0");
        auto q = Event(MM_WS_REQUEST, 85, {}, 4);
        Put32(*q, 12, 0x20);
        auto got = h.Run(*q, Reply(85, 0).get());
        CHECK("i2", got.size() == 1 && got[0].record.target == 0 &&
                        Narrow(got[0].record.detail).find(";win_pid=3000;") != std::string::npos);
        /* get_next_process hands out 0x20 again: its pid is unknown, so no win_pid. */
        auto next = Event(MM_WS_REQUEST, 293, {}, 0);
        auto nextReply = Reply(293, 0);
        Put32(*nextReply, 8, 0x20);
        h.Run(*next, nextReply.get());
        got = h.Run(*q, Reply(85, 0).get());
        CHECK("i2", got.size() == 1 && Narrow(got[0].record.detail).find("win_pid") == std::string::npos);
        /* get_window_tree: +8 is the parent window, not a count. */
        auto tree = Event(MM_WS_REQUEST, 154, {}, 0);
        Put32(*tree, 12, 0x10020);
        auto treeReply = Reply(154, 0);
        Put32(*treeReply, 8, 0x10010);
        got = h.Run(*tree, treeReply.get());
        CHECK("i2", got.size() == 1 && got[0].record.value1 == 0 &&
                        Narrow(got[0].record.detail).find(";parent=0x10010") != std::string::npos);
    }
    /* (i4) new_process: objattr, no handles or jobs, startup_info (96 bytes, then curdir, dllpath, imagepath,
     * cmdline, title, desktop), the environment; a parent override names its handle, the command line comes last. */
    {
        std::vector<uint8_t> info(96, 0);
        const std::vector<uint8_t> strings[6] = {U16("C:\\"), {}, U16("C:\\windows\\system32\\cmd.exe"),
                                                 U16("cmd /c echo a;b"), {}, U16("WinSta0\\Default")};
        std::vector<uint8_t> data = ObjAttr(0, "");
        for (int index = 0; index < 6; index++) {
            const std::vector<uint8_t> length = Le32(static_cast<uint32_t>(strings[index].size()));
            std::copy(length.begin(), length.end(), info.begin() + 64 + 4 * index);
        }
        for (const auto& text : strings) info = Cat(info, text);
        data = Cat(Cat(data, info), U16("A=1"));
        auto q = Event(MM_WS_REQUEST, 0, data, static_cast<uint32_t>(data.size()));
        Put32(*q, 20, 0x99);   /* parent_process */
        Put32(*q, 24, 0x4);    /* process flags */
        Put32(*q, 32, 0x1fffff);
        Put32(*q, 40, static_cast<uint32_t>(info.size()));
        auto r = Reply(0, 0);
        Put32(*r, 12, 3100);
        Put32(*r, 16, 0x44);
        auto got = h.Run(*q, r.get());
        CHECK("i4", got.size() == 1 && got[0].record.desiredAccess == 0x1fffff &&
                        Narrow(got[0].record.detail) ==
                            "new_process;win_pid=3100;process_flags=0x4;parent_override=handle:0x99;win_image=C:\\windows\\"
                            "system32\\cmd.exe;curdir=C:\\;desktop=WinSta0\\Default;win_cmdline=cmd /c echo a;b");
    }
    /* (i3) Replies of two threads arrive out of wineserver's order: handles are resolved at request time. */
    {
        constexpr uint32_t kTidA = kTid + 10, kTidB = kTid + 11;
        auto y = Event(MM_WS_REQUEST, 1, {}, 0);   /* process Y (tgid 6000, Windows pid 3100) is known */
        y->tgid = y->tid = 6000;
        y->win_pid = 3100;
        h.Run(*y, nullptr);
        auto as = [](std::unique_ptr<mm_ws_event> e, uint32_t tid) { e->tid = tid; return e; };
        auto open = [&](uint32_t tid, uint32_t winPid, uint32_t handle) {
            auto q = as(Event(MM_WS_REQUEST, 27, {}, 0), tid);
            Put32(*q, 12, winPid);
            auto r = as(Reply(27, 0), tid);
            Put32(*r, 8, handle);
            return std::make_pair(std::move(q), std::move(r));
        };
        auto memory = [&](uint32_t tid) {
            auto q = as(Event(MM_WS_REQUEST, 84, {}, 0), tid);
            Put32(*q, 12, 0x48);
            return q;
        };
        auto close = as(Event(MM_WS_REQUEST, 21, {}, 0), kTidA);
        Put32(*close, 12, 0x48);
        auto closed = as(Reply(21, 0), kTidA);
        auto x = open(kTidA, 2457, 0x48);   /* 0x48 names X (tgid 5000) */
        h.Run(*x.first, x.second.get());
        /* (1) A close request, B open request (gets 0x48), B reply, A reply: 0x48 names Y. */
        auto b = open(kTidB, 3100, 0x48);
        h.Run(*close, nullptr);
        h.Run(*b.first, b.second.get());
        h.Run(*closed, nullptr);
        auto got = h.Run(*memory(kTidB), as(Reply(84, 0), kTidB).get());
        CHECK("i3", got.size() == 1 && got[0].record.target == 6000);
        /* (2) A reads through 0x48 (Y); B closes it and opens X into 0x48, both replying first: A's record names Y. */
        auto read = memory(kTidA);
        h.Run(*read, nullptr);
        close->tid = closed->tid = kTidB;
        h.Run(*close, closed.get());
        auto bx = open(kTidB, 2457, 0x48);
        h.Run(*bx.first, bx.second.get());
        got = h.Run(*as(Reply(84, 0), kTidA), nullptr);
        CHECK("i3", got.size() == 1 && got[0].record.target == 6000 &&
                        Narrow(got[0].record.detail).find(";win_pid=3100;") != std::string::npos);
        got = h.Run(*memory(kTidB), as(Reply(84, 0), kTidB).get());
        CHECK("i3", got.size() == 1 && got[0].record.target == 5000);
    }
    /* (j) create_file: the unix path as text, the NT name in the detail, disposition << 24 | options. */
    {
        const std::string unixPath = "/tmp/msmon-probe.txt";
        const auto data = Cat(ObjAttr(0, "\\??\\unix\\tmp\\msmon-probe.txt"), std::vector<uint8_t>(unixPath.begin(), unixPath.end()));
        auto q = Event(MM_WS_REQUEST, 44, data, static_cast<uint32_t>(data.size()));
        Put32(*q, 12, 0x80100080);
        Put32(*q, 20, 3);
        Put32(*q, 24, 0x60);
        auto r = Reply(44, 0);
        Put32(*r, 8, 0x24);
        auto got = h.Run(*q, r.get());
        CHECK("j", got.size() == 1 && got[0].record.type == MsMonFileCreate && got[0].record.text == L"/tmp/msmon-probe.txt");
        CHECK("j", got.size() == 1 && got[0].record.value0 == ((3ull << 24) | 0x60) && got[0].record.value1 == 0x24);
        CHECK("j", got.size() == 1 && Narrow(got[0].record.detail).rfind("create_file;nt=\\??\\unix\\tmp\\msmon-probe.txt;", 0) == 0);
    }
    /* (k) AFD connect: network_connect with the endpoint; IPv6 too. */
    {
        std::vector<uint8_t> in = Cat(Le32(16), Le32(1));
        const uint8_t sin[16] = {2, 0, 0, 9, 127, 0, 0, 1};
        in.insert(in.end(), sin, sin + 16);
        auto q = Event(MM_WS_REQUEST, 138, in, static_cast<uint32_t>(in.size()));
        Put32(*q, 12, 0x12032c);
        Put32(*q, 16, 0x28);
        auto got = h.Run(*q, Reply(138, 0).get());
        CHECK("k", got.size() == 1 && got[0].record.type == MsMonNetworkConnect && got[0].record.text == L"127.0.0.1:9");
        CHECK("k", got.size() == 1 && got[0].record.value0 == 0 && got[0].record.value1 == 9);
        CHECK("k", got.size() == 1 && Narrow(got[0].record.detail).rfind("connect;family=2;ws=ioctl;afd=connect;", 0) == 0);
        std::vector<uint8_t> in6 = Cat(Le32(28), Le32(0));
        uint8_t sin6[28] = {23, 0, 1, 0xbb};
        sin6[23] = 1;
        in6.insert(in6.end(), sin6, sin6 + 28);
        auto q2 = Event(MM_WS_REQUEST, 138, in6, static_cast<uint32_t>(in6.size()));
        Put32(*q2, 12, 0x12032c);
        got = h.Run(*q2, Reply(138, 0).get());
        CHECK("k", got.size() == 1 && got[0].record.text == L"[0:0:0:0:0:0:0:1]:443" &&
                       Narrow(got[0].record.detail).rfind("connect;family=10;", 0) == 0);
        std::vector<uint8_t> bind = Le32(0);
        bind.insert(bind.end(), sin, sin + 16);
        auto q3 = Event(MM_WS_REQUEST, 138, bind, static_cast<uint32_t>(bind.size()));
        Put32(*q3, 12, 0x12003);
        got = h.Run(*q3, Reply(138, 0).get());
        CHECK("k", got.size() == 1 && got[0].record.type == MsMonNetworkAccept && got[0].record.text == L"127.0.0.1:9" &&
                       Narrow(got[0].record.detail).rfind("bind;family=2;ws=ioctl;afd=bind", 0) == 0);
    }
    /* (l) a pending connect is written at once with STATUS_PENDING (Wine completes it by APC, not get_async_result). */
    {
        std::vector<uint8_t> in = Cat(Le32(16), Le32(0));
        const uint8_t sin[16] = {2, 0, 0x1f, 0x90, 10, 0, 0, 2};
        in.insert(in.end(), sin, sin + 16);
        auto q = Event(MM_WS_REQUEST, 138, in, static_cast<uint32_t>(in.size()));
        Put32(*q, 12, 0x12032c);
        auto got = h.Run(*q, Reply(138, 0x103).get());
        CHECK("l", got.size() == 1 && got[0].record.text == L"10.0.0.2:8080" && got[0].record.status == 0x103 &&
                       Narrow(got[0].record.detail).find(";pending") != std::string::npos);
    }
    /* (m) a request without its reply is written when the process goes. */
    {
        auto q = Event(MM_WS_REQUEST, 88, {}, 0);
        Put32(*q, 12, 0x10);
        h.Run(*q, nullptr);
        CHECK("m", h.out.empty());
        h.out.clear();
        h.decoder.Forget(kTgid, h.sink);
        CHECK("m", h.out.size() == 1 && h.out[0].record.type == MsMonRegistryDelete && h.out[0].record.detail == L"no_reply");
        /* Forget dropped the handle table. */
        auto q2 = Event(MM_WS_REQUEST, 88, {}, 0);
        Put32(*q2, 12, 0x10);
        auto got = h.Run(*q2, Reply(88, 0).get());
        CHECK("m", got.size() == 1 && got[0].record.text == L"hkey:0x10");
    }
    /* (n) create_mapping: unnamed sections are skipped, named ones are file_section. */
    {
        const auto unnamed = ObjAttr(0, "");
        auto q = Event(MM_WS_REQUEST, 63, unnamed, static_cast<uint32_t>(unnamed.size()));
        CHECK("n", Generic(h.Run(*q, Reply(63, 0).get()), "create_mapping"));   /* not a file_section: no name */
        const auto named = ObjAttr(0x30, "MsmonShared");
        auto q2 = Event(MM_WS_REQUEST, 63, named, static_cast<uint32_t>(named.size()));
        Put32(*q2, 20, 3);   /* file_access: FILE_READ_DATA | FILE_WRITE_DATA (PAGE_READWRITE) */
        auto got = h.Run(*q2, Reply(63, 0).get());
        CHECK("n", got.size() == 1 && got[0].record.type == MsMonFileSection && got[0].record.text == L"handle:0x30\\MsmonShared" &&
                       got[0].record.value1 == 0 && Narrow(got[0].record.detail).find(";file_access=0x3;") != std::string::npos);
    }
    /* (o) list_processes: file_query_information system:list_processes with the count. */
    {
        auto q = Event(MM_WS_REQUEST, 76, {}, 0);
        auto r = Reply(76, 0);
        Put32(*r, 12, 57);
        auto got = h.Run(*q, r.get());
        CHECK("o", got.size() == 1 && got[0].record.type == MsMonFileQueryInformation &&
                       got[0].record.text == L"system:list_processes" && got[0].record.value1 == 57 && got[0].collapse);
    }
    /* (p) a 10000-byte value captured at 8192: chunk 0 of 2, partial (whole first chunk), not final. */
    {
        auto q = Event(MM_WS_REQUEST, 92, U16("Big"), 6);
        Put32(*q, 8, 10000);   /* the client's buffer holds the whole value */
        Put32(*q, 12, 0x10);
        auto r = Reply(92, 0, std::vector<uint8_t>(10000, 0x41));
        Put32(*r, 8, 3);
        Put32(*r, 12, 10000);
        auto got = h.Run(*q, r.get());
        const bool ok = got.size() == 1 && got[0].payload;
        CHECK("p", ok && got[0].bytes.size() == MSMON_PAYLOAD_CHUNK_BYTES && got[0].payloadTotal == 10000);
        CHECK("p", ok && (got[0].payloadTotal + MSMON_PAYLOAD_CHUNK_BYTES - 1) / MSMON_PAYLOAD_CHUNK_BYTES == 2 &&
                       got[0].bytes.size() < got[0].payloadTotal);
    }
    /* (q) set_key_value of 9000 bytes with a 10-byte name: only 8182 value bytes arrive -> truncated. */
    {
        auto q = Event(MM_WS_REQUEST, 91, Cat(U16("Probe"), std::vector<uint8_t>(9000, 1)), 9010);
        Put32(*q, 12, 0x10);
        Put32(*q, 16, 3);
        Put32(*q, 20, 10);
        auto got = h.Run(*q, Reply(91, 0).get());
        CHECK("q", got.size() == 1 && !got[0].payload && (got[0].record.flags & MsMonFlagPayloadUnavailable) &&
                       got[0].record.detail == L"payload_truncated;value=Probe" && got[0].record.value0 == 9000);
    }
    /* (r) --no-payloads: the same records, no payload and no unavailable flag. */
    {
        h.decoder.SetPayloads(false);
        auto q = Event(MM_WS_REQUEST, 91, Cat(U16("Probe"), hello), 20);
        Put32(*q, 20, 10);
        auto got = h.Run(*q, Reply(91, 0).get());
        CHECK("r", got.size() == 1 && !got[0].payload && got[0].record.flags == 0 && got[0].record.detail == L"Probe");
        /* Window titles are content: their length only. */
        auto q2 = Event(MM_WS_REQUEST, 157, {}, 0);
        Put32(*q2, 12, 0x1234);
        got = h.Run(*q2, Reply(157, 0, U16("Secret")).get());
        CHECK("r", got.size() == 1 && Narrow(got[0].record.detail).find("text=") == std::string::npos &&
                       Narrow(got[0].record.detail).find(";text_bytes=12") != std::string::npos);
        h.decoder.SetPayloads(true);
    }
    /* (s) the gate: the build string of the ntdll.so this process maps. */
    {
        mkdir("build/tests/ws", 0755);
        mkdir("build/tests/ws/x86_64-unix", 0755);
        const char* path = "build/tests/ws/x86_64-unix/ntdll.so";
        const int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
        static const char content[] = "FAKE\0wine-11.0\0";
        CHECK("s", fd >= 0 && write(fd, content, sizeof(content)) == static_cast<ssize_t>(sizeof(content)));
        void* map = fd >= 0 ? mmap(nullptr, sizeof(content), PROT_READ, MAP_PRIVATE, fd, 0) : MAP_FAILED;
        std::string where;
        CHECK("s", map != MAP_FAILED && WsNtdllBuild(static_cast<uint32_t>(getpid()), where) == "wine-11.0");
        CHECK("s", where.size() > 9 && where.compare(where.size() - 9, 9, "/ntdll.so") == 0);
        if (map != MAP_FAILED) munmap(map, sizeof(content));
        if (fd >= 0) close(fd);
        WsNtdllReset();
        CHECK("s", WsNtdllBuild(static_cast<uint32_t>(getpid()), where) == "" && where.empty());
    }

    /* (t) capture config of the parity records: pipe read/write, device IRPs, FSCTL_PIPE_TRANSCEIVE. */
    {
        const mm_ws_config c = WsCaptureConfig(false);
        auto want = [&](uint32_t n) { return (c.want[n >> 6] >> (n & 63)) & 1; };
        auto data = [&](uint32_t n) { return (c.data[n >> 6] >> (n & 63)) & 1; };
        CHECK("t", want(136) && data(136) && want(137) && !data(137));
        CHECK("t", want(250) && want(251) && want(253) && data(253) && want(255));
        CHECK("t", std::count(std::begin(c.ioctl_codes), std::end(c.ioctl_codes), 0x11c017u) == 1);
    }
    /* (u) RPC over a Wine pipe (bytes as wineserver -d2 traced `wine sc query`): open_file_object names the
     * handle; the bind gives context 0 the svcctl interface; the request's opnum 15 is ROpenSCManagerW. */
    {
        auto open = Event(MM_WS_REQUEST, 45, U16("\\??\\pipe\\svcctl"), 30);
        Put32(*open, 20, 0);
        auto opened = Reply(45, 0);
        Put32(*opened, 8, 0x24);
        auto got = h.Run(*open, opened.get());
        CHECK("u", got.size() == 1 && got[0].record.type == MsMonFileCreate && got[0].record.text == L"\\??\\pipe\\svcctl");
        const std::vector<uint8_t> bind = {
            0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xd0, 0x16,
            0xd0, 0x16, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x81, 0xbb, 0x7a, 0x36,
            0x44, 0x98, 0xf1, 0x35, 0xad, 0x32, 0x98, 0xf0, 0x38, 0x00, 0x10, 0x03, 0x02, 0x00, 0x00, 0x00, 0x04, 0x5d,
            0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00};
        auto write = Event(MM_WS_REQUEST, 137, bind, static_cast<uint32_t>(bind.size()));
        Put32(*write, 16, 0x24);
        got = h.Run(*write, Reply(137, 0).get());
        CHECK("u", got.size() == 2 && got[0].record.type == MsMonEtwRpc && got[1].record.type == MsMonFileWrite);
        CHECK("u", got.size() == 2 && got[0].record.text == L"\\pipe\\svcctl" && got[0].record.value0 == 11);
        CHECK("u", got.size() == 2 && got[0].record.detail.rfind(L"interface_uuid=367abb81-9844-35f1-ad32-98f038001003;"
                                                                  L"interface=SCM/svcctl;version=2.0;", 0) == 0);
        CHECK("u", got.size() == 2 && got[1].record.text == L"\\??\\pipe\\svcctl" && got[1].record.value0 == 72);
        const std::vector<uint8_t> call = {0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00,
                                           0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x00,
                                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
        auto write2 = Event(MM_WS_REQUEST, 137, call, static_cast<uint32_t>(call.size()));
        Put32(*write2, 16, 0x24);
        got = h.Run(*write2, Reply(137, 0).get());
        CHECK("u", got.size() == 2 && got[0].record.type == MsMonEtwRpc &&
                       got[0].record.detail.rfind(L"op=15;interface_uuid=367abb81-9844-35f1-ad32-98f038001003;"
                                                  L"interface=SCM/svcctl;operation=ROpenSCManagerW;context=0;ptype=request;"
                                                  L"call_id=1;protocol=ncacn_np;via=write;handle=0x24", 0) == 0);
        /* Plain pipe bytes: a file_write only. */
        auto write3 = Event(MM_WS_REQUEST, 137, hello, static_cast<uint32_t>(hello.size()));
        Put32(*write3, 16, 0x24);
        got = h.Run(*write3, Reply(137, 0).get());
        CHECK("u", got.size() == 1 && got[0].record.type == MsMonFileWrite);
        WsRpcPdu pdu;
        CHECK("u", !WsParseRpc(hello.data(), hello.size(), pdu) && WsParseRpc(call.data(), call.size(), pdu) && pdu.opnum == 15);
        /* (u2) the request's arguments: ROpenServiceW names the service (NDR: context handle, string, access), and
         * its stub is an ipc_data payload. */
        std::vector<uint8_t> stub(20, 0);
        stub = Cat(Cat(Cat(stub, Le32(9)), Le32(0)), Le32(9));
        stub = Cat(stub, U16("eventlog"));
        stub.push_back(0), stub.push_back(0), stub.push_back(0), stub.push_back(0);   /* NUL, pad to 4 */
        stub = Cat(stub, Le32(0x4));
        std::vector<uint8_t> service = {0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00, 0, 0, 0x00, 0x00,
                                     0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00};
        service = Cat(service, stub);
        service[8] = static_cast<uint8_t>(service.size());
        auto write4 = Event(MM_WS_REQUEST, 137, service, static_cast<uint32_t>(service.size()));
        Put32(*write4, 16, 0x24);
        got = h.Run(*write4, Reply(137, 0).get());
        CHECK("u2", got.size() == 2 && got[0].record.type == MsMonEtwRpc &&
                        got[0].record.detail.find(L"operation=ROpenServiceW;") != std::wstring::npos &&
                        got[0].record.detail.find(L";service=eventlog;access=0x4;stub_bytes=56") != std::wstring::npos &&
                        got[0].payload && got[0].bytes == stub);
    }
    /* (v) WMI: CoCreateInstance(CLSID_WbemLocator) opens its CLSID key: an etw_wmi record beside the registry one. */
    {
        auto q = Event(MM_WS_REQUEST, 87, U16("\\Registry\\Machine\\Software\\Classes\\CLSID\\{4590F811-1D3A-11D0-891F-00AA004B2E24}"), 0);
        q->total = q->data_len;
        Put32(*q, 16, 0x20019);
        auto r = Reply(87, 0);
        Put32(*r, 8, 0x30);
        auto got = h.Run(*q, r.get());
        CHECK("v", got.size() == 2 && got[0].record.type == MsMonEtwWmi && got[0].record.text == L"com:WbemLocator" &&
                       got[0].record.detail.rfind(L"operation=com_activation;clsid={4590F811", 0) == 0);
        auto q2 = Event(MM_WS_REQUEST, 87, U16("InprocServer32"), 28);
        Put32(*q2, 12, 0x30);
        got = h.Run(*q2, Reply(87, 0).get());
        CHECK("v", got.size() == 1 && got[0].record.type == MsMonRegistryOpen);
    }
    /* (w) handle records as the Ob callbacks write them: no record for the own process; dup_handle of a process
     * handle is process_handle with value0 2 and value1 the granted access (DUPLICATE_SAME_ACCESS: the source's). */
    {
        auto self = Event(MM_WS_REQUEST, 27, {}, 0);
        Put32(*self, 12, kWinPid);
        Put32(*self, 16, 0x1fffff);
        auto selfReply = Reply(27, 0);
        Put32(*selfReply, 8, 0x50);
        const auto own = h.Run(*self, selfReply.get());
        CHECK("w", Generic(own, "open_process") && own[0].record.target == 0 &&
                       own[0].record.detail == L"ws=open_process;pid=32;access=0x1fffff;attributes=0x0;reply_handle=0x50");
        auto other = Event(MM_WS_REQUEST, 27, {}, 0);
        Put32(*other, 12, 0x77);
        Put32(*other, 16, 0x10);
        auto otherReply = Reply(27, 0);
        Put32(*otherReply, 8, 0x54);
        auto got = h.Run(*other, otherReply.get());
        CHECK("w", got.size() == 1 && got[0].record.value0 == 1 && got[0].record.value1 == 0x10);
        auto dup = Event(MM_WS_REQUEST, 23, {}, 0);
        Put32(*dup, 12, 0xffffffff);
        Put32(*dup, 16, 0x54);
        Put32(*dup, 20, 0x58);   /* into another process */
        Put32(*dup, 24, 0);
        Put32(*dup, 32, 2);      /* DUPLICATE_SAME_ACCESS */
        auto dupReply = Reply(23, 0);
        Put32(*dupReply, 8, 0x8);
        got = h.Run(*dup, dupReply.get());
        CHECK("w", got.size() == 1 && got[0].record.type == MsMonProcessHandle && got[0].record.value0 == 2 &&
                       got[0].record.value1 == 0x10 && got[0].record.detail.find(L"object=process;") != std::wstring::npos &&
                       got[0].record.detail.find(L";win_pid=119") != std::wstring::npos);
        auto thread = Event(MM_WS_REQUEST, 28, {}, 0);
        Put32(*thread, 12, 0x99);
        Put32(*thread, 16, 0x40);
        auto threadReply = Reply(28, 0);
        Put32(*threadReply, 8, 0x5c);
        CHECK("w", h.Run(*thread, threadReply.get()).size() == 1);
        auto dup2 = Event(MM_WS_REQUEST, 23, {}, 0);
        Put32(*dup2, 12, 0xffffffff);
        Put32(*dup2, 16, 0x5c);
        Put32(*dup2, 20, 0x58);
        Put32(*dup2, 24, 0x8);
        got = h.Run(*dup2, Reply(23, 0).get());
        CHECK("w", got.size() == 1 && got[0].record.type == MsMonThreadHandle && got[0].record.value1 == 0x8 &&
                       got[0].record.detail.find(L"object=thread;") != std::wstring::npos);
    }
    /* (w2) the other handle requests kfilter decides: get_next_thread and new_thread in another process are
     * thread_handle records (value0 1); a copy of another process's handle within the process is a duplicate
     * record and names that process; a pseudo handle is the caller's own; nothing for the own process. */
    {
        auto y = Event(MM_WS_REQUEST, 1, {}, 0);   /* the process 0x54 names (Windows pid 0x77) is tgid 7000 */
        y->tgid = y->tid = 7000;
        y->win_pid = 0x77;
        h.Run(*y, nullptr);
        auto thread = [&](uint32_t req, uint32_t process, uint32_t access, uint32_t tid, uint32_t handle) {
            auto q = Event(MM_WS_REQUEST, req, {}, 0);
            Put32(*q, 12, process);
            Put32(*q, req == 2 ? 16 : 20, access);
            auto r = Reply(req, 0);
            Put32(*r, 8, req == 2 ? tid : handle);
            Put32(*r, 12, handle);
            return h.Run(*q, r.get());
        };
        auto open = [&](uint32_t tid) {
            auto q = Event(MM_WS_REQUEST, 28, {}, 0);
            Put32(*q, 12, tid);
            Put32(*q, 16, 0x8);
            auto r = Reply(28, 0);
            Put32(*r, 8, 0x70);
            return h.Run(*q, r.get());
        };
        CHECK("w2", Generic(thread(2, 0xffffffff, 0x1fffff, 0x300, 0x60), "new_thread"));   /* CreateThread */
        CHECK("w2", Generic(open(0x300), "open_thread"));                                     /* its tid is the caller's */
        CHECK("w2", Generic(thread(294, 0xffffffff, 0x8, 0, 0x64), "get_next_thread"));
        auto got = thread(294, 0x54, 0xa, 0, 0x64);
        CHECK("w2", got.size() == 1 && got[0].record.type == MsMonThreadHandle && got[0].record.target == 7000 &&
                        got[0].record.desiredAccess == 0xa && got[0].record.value0 == 1 && got[0].record.value1 == 0xa &&
                        got[0].record.detail == L"get_next_thread;process=0x54;win_pid=119;last=0x0;handle=0x64");
        got = thread(2, 0x54, 0x1fffff, 0x310, 0x68);   /* a remote thread */
        CHECK("w2", got.size() == 1 && got[0].record.target == 7000 && got[0].record.value1 == 0x1fffff &&
                        got[0].record.detail == L"new_thread;process=0x54;win_pid=119;win_tid=784;handle=0x68");
        got = open(0x310);
        CHECK("w2", got.size() == 1 && got[0].record.target == 7000);
        /* DuplicateHandle(self, 0x54, self, SAME_ACCESS): the copy reaches 7000 too, as its threads do. */
        auto dup = [&](uint32_t handle, uint32_t destination, uint32_t copy) {
            auto q = Event(MM_WS_REQUEST, 23, {}, 0);
            Put32(*q, 12, 0xffffffff);
            Put32(*q, 16, handle);
            Put32(*q, 20, destination);
            Put32(*q, 32, 2);
            auto r = Reply(23, 0);
            Put32(*r, 8, copy);
            return h.Run(*q, r.get());
        };
        got = dup(0x54, 0xffffffff, 0x74);
        CHECK("w2", got.size() == 1 && got[0].record.type == MsMonProcessHandle && got[0].record.value0 == 2 &&
                        got[0].record.value1 == 0x10 && got[0].record.target == 7000);
        got = thread(294, 0x74, 0x8, 0, 0x78);
        CHECK("w2", got.size() == 1 && got[0].record.target == 7000);
        /* get_thread_info names that handle's thread (tid 0x320 of 0x77, never seen): later requests target it. */
        auto info = Event(MM_WS_REQUEST, 14, {}, 0);
        Put32(*info, 12, 0x78);
        auto infoReply = Reply(14, 0);
        Put32(*infoReply, 8, 0x77);
        Put32(*infoReply, 12, 0x320);
        got = h.Run(*info, infoReply.get());
        CHECK("w2", got.size() == 1 && got[0].record.target == 7000 &&
                        got[0].record.detail == L"get_thread_info;handle=0x78;win_tid=800");
        auto suspend = Event(MM_WS_REQUEST, 17, {}, 0);
        Put32(*suspend, 12, 0x78);
        got = h.Run(*suspend, Reply(17, 0).get());
        CHECK("w2", got.size() == 1 && got[0].record.target == 7000 &&
                        got[0].record.detail == L"suspend_thread;handle=0x78;win_tid=800;count=0");
        CHECK("w2", Generic(dup(0xffffffff, 0xffffffff, 0x7c), "dup_handle"));   /* its own process, within itself */
        got = dup(0xfffffffe, 0x54, 0x4);                          /* its own thread handed to 7000 */
        CHECK("w2", got.size() == 1 && got[0].record.type == MsMonThreadHandle && got[0].record.value1 == 0x1fffff &&
                        got[0].record.target == kTgid && got[0].record.detail.find(L"object=thread;") != std::wstring::npos &&
                        got[0].record.detail.find(L";win_tid=36") != std::wstring::npos);
    }
    /* (x) registry values get the Windows friendly decoding: a decoded record as WritePayloadSeries writes it. */
    {
        auto json = [](const WsRecord& got) {
            TelemetryEvent event;
            event.header.Type = got.record.type;
            event.header.Value0 = got.record.value0;
            event.header.Value1 = got.record.value1;
            event.header.Flags = MsMonFlagPayloadPresent | MsMonFlagPayloadFinalChunk;
            event.header.PayloadKind = got.payloadKind;
            event.header.PayloadTotalBytes = got.payloadTotal;
            event.header.PayloadChunkCount = 1;
            event.payload = got.bytes;
            return TelemetryJson(event);
        };
        const auto name = U16("Dword");
        auto q = Event(MM_WS_REQUEST, 91, Cat(name, Le32(1234)), 14);
        Put32(*q, 12, 0x10);
        Put32(*q, 16, 4);   /* REG_DWORD */
        Put32(*q, 20, 10);
        auto got = h.Run(*q, Reply(91, 0).get());
        CHECK("x", got.size() == 1 && got[0].payload && json(got[0]).find("\"decoded_value\":1234") != std::string::npos);
        auto q2 = Event(MM_WS_REQUEST, 92, U16("Probe"), 10);
        Put32(*q2, 8, 10);
        Put32(*q2, 12, 0x10);
        auto r2 = Reply(92, 0, hello);
        Put32(*r2, 8, 1);   /* REG_SZ */
        Put32(*r2, 12, 10);
        got = h.Run(*q2, r2.get());
        CHECK("x", got.size() == 1 && json(got[0]).find("\"decoded_value\":\"hello\"") != std::string::npos);
    }
    /* (y) winedevice.exe: a driver load is etw_code_integrity (decision=not_enforced); its device, the client's
     * IRPs and the work done inside an IRP carry component=<driver>.sys and attribution=brokered_winedevice. */
    {
        constexpr uint32_t kDev = 6000;
        auto as = [](std::unique_ptr<mm_ws_event> e) {
            e->tgid = kDev;
            e->tid = kDev + 1;
            if (e->kind == MM_WS_REQUEST) e->win_pid = 0x200, e->win_tid = 0x204;
            return e;
        };
        CHECK("y", Generic(h.Run(*as(Event(MM_WS_REQUEST, 250, {}, 0)), as(Reply(250, 0)).get()), "create_device_manager"));
        const char* sys = "\\??\\C:\\windows\\system32\\drivers\\BlackCat64.sys";
        const auto attr = Cat(ObjAttr(0, sys), {'/', 'p', '/', 'B', '.', 's', 'y', 's'});
        auto create = as(Event(MM_WS_REQUEST, 44, attr, static_cast<uint32_t>(attr.size())));
        auto created = as(Reply(44, 0));
        Put32(*created, 8, 0x80);
        auto got = h.Run(*create, created.get());
        CHECK("y", got.size() == 1 && got[0].record.component == L"" && (got[0].record.flags & MsMonFlagServiceCorrelated));
        const auto none = ObjAttr(0, "");
        auto map = as(Event(MM_WS_REQUEST, 63, none, static_cast<uint32_t>(none.size())));
        Put32(*map, 16, 0x1000000);
        Put32(*map, 32, 0x80);
        got = h.Run(*map, as(Reply(63, 0)).get());
        CHECK("y", got.size() == 1 && got[0].record.type == MsMonEtwCodeIntegrity && got[0].record.component == L"BlackCat64.sys" &&
                       got[0].record.text == LinuxWide(sys) &&
                       got[0].record.detail.rfind(L"decision=not_enforced;driver_load;driver=BlackCat64.sys", 0) == 0);
        auto device = as(Event(MM_WS_REQUEST, 251, U16("\\Device\\BlackCat"), 32));
        Put64(*device, 16, 0x7000);
        got = h.Run(*device, as(Reply(251, 0)).get());
        CHECK("y", got.size() == 1 && got[0].record.text == L"\\Device\\BlackCat" && got[0].record.component == L"BlackCat64.sys");
        /* The client (kTgid, Windows tid kWinPid + 4) opens the device: a create IRP. */
        auto next = as(Event(MM_WS_REQUEST, 253, {}, 0));
        auto irp = as(Reply(253, 0));
        Put32(*irp, 8, 1);
        Put32(*irp, 12, 0x100080);
        Put64(*irp, 24, 0x7000);
        Put32(*irp, 32, 0x90);
        Put32(*irp, 44, kWinPid + 4);
        got = h.Run(*next, irp.get());
        CHECK("y", got.size() == 1 && got[0].record.type == MsMonFileCreate && got[0].record.text == L"\\Device\\BlackCat" &&
                       got[0].record.target == kTgid && got[0].record.component == L"BlackCat64.sys" &&
                       got[0].record.detail.find(L"attribution=brokered_winedevice;client_pid=4242;client_win_tid=36") !=
                           std::wstring::npos);
        auto pointer = as(Event(MM_WS_REQUEST, 255, {}, 0));
        Put32(*pointer, 16, 0x90);
        Put64(*pointer, 24, 0x9000);
        CHECK("y", Generic(h.Run(*pointer, as(Reply(255, 0)).get()), "set_kernel_object_ptr"));
        /* Its DeviceIoControl: an ioctl IRP on that FILE_OBJECT. */
        auto next2 = as(Event(MM_WS_REQUEST, 253, {}, 0));
        auto ioctl = as(Reply(253, 0));
        Put32(*ioctl, 8, 6);
        Put32(*ioctl, 12, 0x222004);
        Put64(*ioctl, 24, 0x9000);
        Put32(*ioctl, 44, kWinPid + 4);
        Put32(*ioctl, 56, 16);
        got = h.Run(*next2, ioctl.get());
        CHECK("y", got.size() == 1 && got[0].record.type == MsMonFileDeviceControl && got[0].record.text == L"\\Device\\BlackCat" &&
                       got[0].record.value0 == 0x222004 && got[0].record.value1 == 16 && got[0].record.target == kTgid);
        /* The driver reads the client's memory while handling it. */
        auto read = as(Event(MM_WS_REQUEST, 84, {}, 0));
        Put32(*read, 8, 64);
        Put32(*read, 12, 0x4);
        got = h.Run(*read, as(Reply(84, 0)).get());
        CHECK("y", got.size() == 1 && got[0].record.component == L"BlackCat64.sys" &&
                       got[0].record.detail.find(L"client_pid=4242") != std::wstring::npos);
        /* The next get_next_device_request completes the IRP: the driver is still named, the client is not. */
        auto idle = as(Event(MM_WS_REQUEST, 253, {}, 0));
        CHECK("y", h.Run(*idle, nullptr).empty());   /* unanswered: no record when the next request ends it */
        got = h.Run(*as(Event(MM_WS_REQUEST, 84, {}, 0)), as(Reply(84, 0)).get());   /* the idle one first, no_reply */
        CHECK("y", got.size() == 2 && got[0].record.text == L"system:get_next_device_request" &&
                       got[0].record.detail.find(L";no_reply") != std::wstring::npos && got[1].record.component == L"BlackCat64.sys" &&
                       got[1].record.detail.find(L"client_pid") == std::wstring::npos);
    }
    /* (y2) a winedevice.exe that joined after loading its drivers: a reconstructed driver_load per .sys, and
     * its IRPs name the driver their DEVICE_OBJECT's DRIVER_OBJECT points into (DriverStart or DriverInit). */
    {
        constexpr uint32_t kLate = 8000;
        std::map<uint64_t, uint64_t> memory = {
            {0x7108, 0x8000}, {0x8058, 0x31000},              /* device 0x7100: DriverInit in nsiproxy.sys */
            {0x7208, 0x8100}, {0x8118, 0x10000},              /* device 0x7200: DriverStart of mountmgr.sys */
            {0x9108, 0x7100},                                 /* FILE_OBJECT 0x9100 -> device 0x7100 */
        };
        h.decoder.SetReader([&](uint32_t tgid, uint64_t address, uint64_t& value) {
            const auto found = memory.find(address);
            if (tgid != kLate || found == memory.end()) return false;
            value = found->second;
            return true;
        });
        auto identity = Event(MM_WS_REQUEST, 63, {}, 0);
        identity->tgid = identity->tid = kLate;
        const std::vector<WsDriver> drivers = {{0x10000, 0x20000, L"/w/mountmgr.sys"}, {0x30000, 0x40000, L"/w/nsiproxy.sys"}};
        h.out.clear();
        h.decoder.Joined(*identity, drivers, h.sink);
        auto got = h.out;
        CHECK("y2", got.size() == 2 && got[0].record.type == MsMonEtwCodeIntegrity && got[0].record.component == L"mountmgr.sys" &&
                        got[1].record.component == L"nsiproxy.sys" && got[1].record.text == L"/w/nsiproxy.sys" &&
                        got[1].record.detail.rfind(L"decision=not_enforced;driver_load;driver=nsiproxy.sys;reconstructed=1;", 0) == 0 &&
                        got[1].record.detail.find(L"attribution=brokered_winedevice") != std::wstring::npos);
        h.out.clear();
        h.decoder.Joined(*identity, drivers, h.sink);
        CHECK("y2", h.out.empty());   /* once */
        auto as = [](std::unique_ptr<mm_ws_event> e) {
            e->tgid = kLate;
            e->tid = kLate + 1;
            if (e->kind == MM_WS_REQUEST) e->win_pid = 0x400, e->win_tid = 0x404;
            return e;
        };
        auto irp = [&](uint32_t type, uint64_t object) {
            auto r = as(Reply(253, 0));
            Put32(*r, 8, type);
            Put64(*r, 24, object);
            Put32(*r, 44, kWinPid + 4);
            return h.Run(*as(Event(MM_WS_REQUEST, 253, {}, 0)), r.get());
        };
        got = irp(6, 0x9100);   /* an ioctl on a file opened before the join */
        CHECK("y2", got.size() == 1 && got[0].record.type == MsMonFileDeviceControl && got[0].record.component == L"nsiproxy.sys" &&
                        got[0].record.text == L"device:0x7100" && got[0].record.target == kTgid);
        got = irp(1, 0x7200);   /* a create on another driver's device */
        CHECK("y2", got.size() == 1 && got[0].record.component == L"mountmgr.sys");
        got = irp(1, 0x7300);   /* unreadable: several drivers, none named */
        CHECK("y2", got.size() == 1 && got[0].record.component.empty() &&
                        got[0].record.detail.find(L"attribution=brokered_winedevice") != std::wstring::npos);
        h.decoder.SetReader(nullptr);
    }
    /* (aa) cross-process control (msmon-gaps 5): another client's thread and process through the handle table. */
    constexpr uint32_t kOther = 5151, kOtherWin = 0x30;
    auto other = [](std::unique_ptr<mm_ws_event> e) {
        e->tgid = kOther;
        e->tid = kOther + 1;
        if (e->kind == MM_WS_REQUEST) e->win_pid = kOtherWin, e->win_tid = kOtherWin + 4;
        return e;
    };
    auto run = [&](uint32_t req, std::vector<uint8_t> data, std::initializer_list<std::pair<size_t, uint32_t>> fields,
                   uint32_t status, std::initializer_list<std::pair<size_t, uint32_t>> replyFields, std::vector<uint8_t> replyData = {}) {
        auto q = Event(MM_WS_REQUEST, req, data, static_cast<uint32_t>(data.size()));
        for (const auto& [offset, value] : fields) Put32(*q, offset, value);
        auto r = Reply(req, status, replyData);
        for (const auto& [offset, value] : replyFields) Put32(*r, offset, value);
        return h.Run(*q, r.get());
    };
    auto has = [](const std::vector<WsRecord>& got, const wchar_t* text) {
        return got.size() == 1 && got[0].record.detail.find(text) != std::wstring::npos;
    };
    {
        h.Run(*other(Event(MM_WS_REQUEST, 189, {}, 0)), other(Reply(189, 0)).get());   /* the other client is seen */
        run(27, {}, {{12, kOtherWin}, {16, 0x1fffff}}, 0, {{8, 0x60}});                 /* open_process -> 0x60 */
        run(28, {}, {{12, kOtherWin + 4}, {16, 0x48}}, 0, {{8, 0x64}});                 /* open_thread -> 0x64 */
        std::vector<uint8_t> context(1720, 0);
        Put32Bytes(context, 0, 0x8664);
        Put32Bytes(context, 4, 0x10);   /* SERVER_CTX_DEBUG_REGISTERS */
        Put32Bytes(context, 824, 0x401000);
        Put32Bytes(context, 864, 0x1);
        auto got = run(105, {}, {{12, 0x64}, {20, 0x10}}, 0, {}, context);
        CHECK("aa", has(got, L"get_thread_context;handle=0x64;win_tid=52;flags=0x10;dr0=0x401000;") &&
                        got[0].record.type == MsMonThreadHandle && got[0].record.target == kOther &&
                        got[0].record.desiredAccess == 0x48 && has(got, L";dr7=0x1"));
        got = run(106, context, {{12, 0x64}, {16, 0x10}}, 0, {});
        CHECK("aa", has(got, L"set_thread_context;handle=0x64;win_tid=52;native_flags=0x10;dr0=0x401000") && !got[0].collapse);
        CHECK("aa", Generic(run(17, {}, {{12, 0xfffffffe}}, 0, {}), "suspend_thread"));   /* its own thread: no thread_handle */
        CHECK("aa", Generic(run(7, {}, {{12, 0}}, 0, {}), "terminate_process"));   /* terminate_process(0) as the process exits */
        got = run(17, {}, {{12, 0x64}}, 0, {{8, 1}});
        CHECK("aa", has(got, L"suspend_thread;handle=0x64;win_tid=52;count=1"));
        std::vector<uint8_t> apc(64, 0);
        Put32Bytes(apc, 0, 7);   /* APC_VIRTUAL_PROTECT: prot +4, addr +8, size +16 */
        Put32Bytes(apc, 4, 0x40);
        Put32Bytes(apc, 8, 0x10000);
        Put32Bytes(apc, 16, 0x1000);
        got = run(19, apc, {{12, 0x60}}, 0, {{8, 0x68}});
        CHECK("aa", has(got, L"queue_apc;handle=0x60;win_pid=48;type=virtual_protect;addr=0x10000;size=0x1000;prot=0x40") &&
                        got[0].record.type == MsMonProcessHandle && got[0].record.target == kOther);
        got = run(20, {}, {{12, 0x68}}, 0, {{8, 7}, {16, 0x10000}, {24, 0x1000}});
        CHECK("aa", has(got, L"apc_result;handle=0x68;win_pid=48;type=virtual_protect;status=0x0;addr=0x10000;size=0x1000"));
        /* Hide-from-debugger on its own thread is recorded. */
        CHECK("aa", has(run(16, {}, {{12, 0xfffffffe}, {48, 0x40}}, 0, {}), L";hide_from_debugger=1"));
    }
    /* (ab) named objects, symlinks and tokens (msmon-gaps 8). */
    {
        auto got = run(240, U16("\\Sessions\\1\\BaseNamedObjects"), {{12, 0xf}}, 0, {{8, 0x70}});
        CHECK("ab", got.size() == 1 && got[0].record.type == MsMonFileCreate && got[0].record.text == L"\\Sessions\\1\\BaseNamedObjects");
        got = run(36, ObjAttr(0x70, "Global\\Assess"), {{12, 0x1f0001}}, 0, {{8, 0x74}});
        CHECK("ab", got.size() == 1 && got[0].record.text == L"\\Sessions\\1\\BaseNamedObjects\\Global\\Assess" &&
                        got[0].record.value0 == (3ull << 24) && got[0].record.detail == L"create_mutex;object=mutex");
        CHECK("ab", Generic(run(30, ObjAttr(0, ""), {}, 0, {{8, 0x78}}), "create_event"));   /* an unnamed event: no file_create */
        run(243, U16("\\??\\C:"), {{12, 1}}, 0, {{8, 0x7c}});
        got = run(244, {}, {{12, 0x7c}}, 0, {}, U16("\\Device\\HarddiskVolume1"));
        CHECK("ab", got.size() == 1 && got[0].record.text == L"system:query_symlink" &&
                        got[0].record.detail == L"ws=query_symlink;object=\\??\\C:;target=\\Device\\HarddiskVolume1");
        run(220, {}, {{12, 0xffffffff}, {16, 0x28}}, 0, {{8, 0x80}});
        got = run(222, Cat(Cat(Le32(20), Le32(0)), Le32(2)), {{12, 0x80}}, 0, {});
        CHECK("ab", has(got, L"adjust_token_privileges;handle=0x80;win_pid=32;disable_all=0;privs=SeDebugPrivilege(enabled)") &&
                        got[0].record.target == kTgid);   /* its own token: its own process */
    }
    /* (ac) input and hooks (msmon-gaps 6): injected input only, never the user's own. */
    {
        auto got = run(198, U16("hook.dll"), {{12, 13}}, 0, {{8, 0x10010}});
        CHECK("ac", has(got, L"ws=set_hook;id=13;hook=keyboard_ll;scope=global;") && got[0].record.text == L"system:set_hook");
        got = run(121, {}, {{16, 1}, {20, 0x41}}, 0, {});   /* winex11's real key: logged without the key */
        CHECK("ac", got.size() == 1 && got[0].record.detail == L"ws=send_hardware_message;input=keyboard;flags=0x0;window=0x0;injected=0");
        got = run(121, {}, {{16, 1}, {20, 0x41}, {56, 1}}, 0, {});
        CHECK("ac", has(got, L"input=keyboard;vkey=0x41;scan=0x0;flags=0x0;window=0x0;injected=1"));
        CHECK("ac", config.filter[0].req == 121 && config.filter[0].off == 56 && config.filter[0].mask == 1 &&
                        config.filter[1].req == 279 && (config.want[105 >> 6] & (1ull << (105 & 63))));
        /* (ac2) other programs' windows: GetWindowLong, hit tests (keyed without the point), rectangles, FindWindow,
         * GetGUIThreadInfo of another client's thread, the clipboard owner. */
        got = run(146, {}, {{12, 0x10020}, {16, static_cast<uint32_t>(-16)}}, 0, {{16, 0x14cf0000}});
        CHECK("ac2", has(got, L"ws=get_window_info;window=0x10020;offset=-16;info=0x14cf0000;") &&
                         got[0].record.text == L"system:get_window_info" && got[0].collapse);
        got = run(153, {}, {{12, 0x10020}, {16, 5}, {20, 7}}, 0, {{8, 2}});
        const auto hit = run(153, {}, {{12, 0x10020}, {16, 9}, {20, 9}}, 0, {{8, 2}});
        CHECK("ac2", has(got, L"window=0x10020;x=5;y=7") && got[0].record.value1 == 2 && hit.size() == 1 &&
                         hit[0].repeatKey == got[0].repeatKey);
        got = run(156, {}, {{12, 0x10020}}, 0, {{8, 10}, {12, 20}, {16, 810}, {20, 620}});
        CHECK("ac2", has(got, L"window=0x10020;relative=0;window_rect=10,20,810,620;client_rect=0,0,0,0"));
        got = run(152, U16("OLLYDBG"), {{12, 0x10008}}, 0, {{8, 0}});
        CHECK("ac2", has(got, L"ws=get_class_windows;window=0x10008;child=0x0;atom=0x0;class=OLLYDBG"));
        got = run(168, U16("__wine_x11_whole_window"), {{12, 0x10020}}, 0, {{8, 0x3a00007}});
        CHECK("ac2", has(got, L"name=__wine_x11_whole_window;data=0x3a00007"));
        got = run(188, {}, {{12, kOtherWin + 4}}, 0, {});
        CHECK("ac2", has(got, L"ws=get_thread_input;tid=52") && got[0].record.target == kOther);
        CHECK("ac2", run(188, {}, {{12, 0}}, 0, {})[0].record.target == 0);   /* the foreground thread's */
        got = run(215, {}, {}, 0, {{12, 0x10044}, {20, 3}});
        CHECK("ac2", has(got, L"ws=get_clipboard_info;window=0x0;owner=0x10044;viewer=0x0;seqno=3"));
        got = run(147, {}, {{12, 0x10020}, {16, 0x14cf0000}}, 0, {});   /* init_window_info: generic */
        CHECK("ac2", Generic(got, "init_window_info") &&
                         got[0].record.detail == L"ws=init_window_info;handle=0x10020;style=0x14cf0000;ex_style=0x0;is_unicode=0");
    }
    /* (ad) delete/rename through wineserver (msmon-gaps 9): the client's own records of them. */
    {
        auto create = ObjAttr(0, "\\??\\C:\\t.txt");
        run(44, create, {{12, 0x130080}}, 0, {{8, 0x84}});
        std::vector<uint8_t> rename = U16("\\??\\C:\\u.txt");
        const uint32_t nameBytes = static_cast<uint32_t>(rename.size());
        for (const char* p = "/pfx/drive_c/u.txt"; *p; p++) rename.push_back(static_cast<uint8_t>(*p));
        auto got = run(273, rename, {{12, 0x84}, {20, nameBytes}}, 0, {});
        CHECK("ad", got.size() == 2 && got[0].record.type == MsMonFileSetInformation && got[0].record.value0 == 10 &&
                        got[0].record.text == L"\\??\\C:\\t.txt" && got[0].record.detail.rfind(L"rename;from;", 0) == 0 &&
                        got[1].record.text == L"\\??\\C:\\u.txt" &&
                        got[1].record.detail.rfind(L"rename;to;ws=set_fd_name_info;unix=/pfx/drive_c/u.txt;", 0) == 0);
        got = run(272, {}, {{12, 0x84}, {16, 1}}, 0, {});
        CHECK("ad", got.size() == 1 && got[0].record.value0 == 13 && got[0].record.text == L"\\??\\C:\\u.txt" &&
                        got[0].record.detail.rfind(L"delete;", 0) == 0);
        /* (ae) handle names cross processes (msmon-gaps 14): a dup_handle into the other client, an inherited one. */
        run(23, {}, {{12, 0xffffffff}, {16, 0x84}, {20, 0x60}, {32, 2}}, 0, {{8, 0x90}});
        auto read = other(Event(MM_WS_REQUEST, 136, {}, 0));
        Put32(*read, 16, 0x90);
        got = h.Run(*read, other(Reply(136, 0)).get());
        CHECK("ae", got.size() == 1 && got[0].record.text == L"\\??\\C:\\u.txt");
        auto spawn = Event(MM_WS_REQUEST, 0, ObjAttr(0, ""), 16);
        Put32(*spawn, 24, 4);   /* PROCESS_CREATE_FLAGS_INHERIT_HANDLES */
        auto spawned = Reply(0, 0);
        Put32(*spawned, 8, 0x94);
        Put32(*spawned, 12, 0x50);
        Put32(*spawned, 16, 0x98);
        h.Run(*spawn, spawned.get());
        /* The child's own handle at a reused value (0x60: the parent's process handle) names its own file. */
        auto child = [](std::unique_ptr<mm_ws_event> e) {
            e->tgid = 6161, e->tid = 6163;
            if (e->kind == MM_WS_REQUEST) e->win_pid = 0x50, e->win_tid = 0x58;
            return e;
        };
        auto created = child(Reply(44, 0));
        Put32(*created, 8, 0x60);
        h.Run(*child(Event(MM_WS_REQUEST, 44, ObjAttr(0, "\\??\\C:\\v.txt"), 0)), created.get());
        auto security = child(Event(MM_WS_REQUEST, 233, {}, 0));
        Put32(*security, 12, 0x60);
        got = h.Run(*security, child(Reply(233, 0)).get());
        CHECK("ae", got.size() == 1 && got[0].record.type == MsMonFileQuerySecurity && got[0].record.text == L"\\??\\C:\\v.txt");
        auto write = Event(MM_WS_REQUEST, 137, hello, static_cast<uint32_t>(hello.size()));
        write->tgid = 6161, write->tid = 6162, write->win_pid = 0x50, write->win_tid = 0x54;
        Put32(*write, 16, 0x84);
        got = h.Run(*write, nullptr);
        h.decoder.Forget(6161, h.sink);
        CHECK("ae", h.out.size() == 1 && h.out[0].record.text == L"\\??\\C:\\u.txt" && h.out[0].payload &&
                        h.out[0].payloadKind == MsMonPayloadIpcData && h.out[0].bytes == hello);   /* (af) pipe bytes */
    }
    /* (z) snapshots: a Wine prefix's dosdevices/c: path resolves to drive_c; winedevice.exe by its argv[0]. */
    {
        mkdir("build/tests/ws", 0755);
        mkdir("build/tests/ws/pfx", 0755);
        mkdir("build/tests/ws/pfx/drive_c", 0755);
        mkdir("build/tests/ws/pfx/dosdevices", 0755);
        unlink("build/tests/ws/pfx/dosdevices/c:");
        CHECK("z", symlink("../drive_c", "build/tests/ws/pfx/dosdevices/c:") == 0);
        char real[PATH_MAX];
        CHECK("z", realpath("build/tests/ws/pfx/drive_c", real) != nullptr);
        char cwd[PATH_MAX];
        CHECK("z", getcwd(cwd, sizeof(cwd)) != nullptr);
        const std::wstring via = LinuxWide(std::string(cwd) + "/build/tests/ws/pfx/dosdevices/c:/Nexon/_ms_report.ini");
        CHECK("z", LinuxResolvedPath(via) == LinuxWide(std::string(real) + "/Nexon/_ms_report.ini"));
        CHECK("z", LinuxResolvedPath(L"") == L"");
        CHECK("z", LinuxWinedevice(L"C:\\windows\\system32\\winedevice.exe") && LinuxWinedevice(L"WINEDEVICE.EXE") &&
                       !LinuxWinedevice(L"C:\\windows\\system32\\services.exe"));
    }

    /* (ba) the generic decoder: every fixed field of the protocol table, a handle's name at request time, the reply's
     * fields; set_window_pos collapsed by its window (the '*' field), its rectangles as four ints. */
    {
        auto got = run(39, {}, {{12, 0x74}}, 0, {{8, 1}, {12, 1}});   /* query_mutex of \...\Global\Assess (ab) */
        CHECK("ba", Generic(got, "query_mutex") && got[0].repeatKey == 0x74 &&
                        got[0].record.detail == L"ws=query_mutex;handle=0x74;handle_name=\\Sessions\\1\\BaseNamedObjects\\Global\\Assess;"
                                                L"reply_count=0x1;reply_owned=1;reply_abandoned=0");
        auto pos = Event(MM_WS_REQUEST, 155, {}, 0);
        Put32(*pos, 12, 0x14);   /* swp_flags SWP_NOZORDER | SWP_NOACTIVATE */
        Put32(*pos, 20, 0x10044);
        Put32(*pos, 28, static_cast<uint32_t>(-8));
        Put32(*pos, 32, 20);
        Put32(*pos, 36, 808);
        Put32(*pos, 40, 620);
        got = h.Run(*pos, Reply(155, 0).get());
        CHECK("ba", Generic(got, "set_window_pos") && got[0].repeatKey == 0x10044 &&
                        got[0].record.detail.find(L";handle=0x10044;previous=0x0;window=-8,20,808,620;client=0,0,0,0;") != std::wstring::npos);
        /* A string vararg (create_window's class); a handle a reply gives out names nothing it named before. */
        got = run(142, U16("Edit"), {{12, 0x10020}}, 0, {{8, 0x10050}, {12, 0x10020}});
        CHECK("ba", Generic(got, "create_window") && got[0].record.detail.find(L";ex_style=0x0;class=Edit;reply_handle=0x10050;") != std::wstring::npos);
        run(45, U16("\\Device\\HarddiskVolume1"), {{12, 0x80100080}}, 0, {{8, 0x8c}});
        CHECK("ba", has(run(39, {}, {{12, 0x8c}}, 0, {}), L";handle_name=\\Device\\HarddiskVolume1"));
        run(113, {}, {}, 0, {{8, 0x8c}, {12, 0x8c}});   /* get_msg_queue_handle hands out 0x8c */
        CHECK("ba", run(39, {}, {{12, 0x8c}}, 0, {})[0].record.detail ==
                        L"ws=query_mutex;handle=0x8c;reply_count=0x0;reply_owned=0;reply_abandoned=0");
        /* Window text is content: its length only without payloads. */
        h.decoder.SetPayloads(false);
        CHECK("ba", Generic(run(158, U16("Secret"), {{12, 0x10050}}, 0, {}), "set_window_text") &&
                        h.out[0].record.detail == L"ws=set_window_text;handle=0x10050;text_bytes=12");
        h.decoder.SetPayloads(true);
        CHECK("ba", has(run(158, U16("Title"), {{12, 0x10050}}, 0, {}), L";handle=0x10050;text=Title"));
    }
    /* (bb) unknown-field handling: a nonzero word no field covers (request or reply), a request number past the
     * table or past ws_cfg's 512 is "unknown" with every nonzero word. */
    {
        auto got = run(39, {}, {{12, 0x8c}, {48, 0xdead}}, 0, {{40, 7}});
        CHECK("bb", Generic(got, "query_mutex") &&
                        got[0].record.detail == L"ws=query_mutex;handle=0x8c;unknown@0x30=0xdead;reply_count=0x0;reply_owned=0;"
                                                L"reply_abandoned=0;reply_unknown@0x28=0x7");
        got = run(58, {}, {{12, 0x8c}, {16, 0x00020001}, {20, 0x00030000}}, 0, {});   /* icmp_seq is two bytes, then padding */
        CHECK("bb", got.size() == 1 && got[0].record.detail == L"ws=socket_send_icmp_id;handle=0x8c;icmp_id=0x1;icmp_seq=0x2;"
                                                                L"unknown@0x14=0x30000");
        got = run(400, {}, {{12, 7}}, 0xC0000002, {});
        CHECK("bb", got.size() == 1 && got[0].record.text == L"system:unknown" && got[0].record.value0 == 400 &&
                        got[0].record.detail == L"ws=unknown;req=400;unknown@0xc=0x7" && got[0].record.status == (int32_t)0xC0000002);
        got = run(0x10000, {}, {}, 0, {});
        CHECK("bb", got.size() == 1 && got[0].record.detail == L"ws=unknown;req=65536");
    }
    /* (bc) window owners (create_window replies) and send_message: another process's thread or window is the
     * destination, collapsed per destination and message; to the process itself no target; keys withheld. */
    {
        auto created = other(Reply(142, 0));
        Put32(*created, 8, 0x10066);
        h.Run(*other(Event(MM_WS_REQUEST, 142, {}, 0)), created.get());   /* kOther creates window 0x10066 */
        auto message = [&](uint32_t to, uint32_t window, uint32_t msg, uint32_t type, const std::vector<uint8_t>& data) {
            auto q = Event(MM_WS_REQUEST, 119, data, static_cast<uint32_t>(data.size()));
            Put32(*q, 12, to);
            Put32(*q, 16, type);
            Put32(*q, 24, window);
            Put32(*q, 28, msg);
            Put64(*q, 32, 0x30);
            Put64(*q, 40, 0x1234);
            return h.Run(*q, Reply(119, 0).get());
        };
        const std::vector<uint8_t> copy = U16("hello");
        auto got = message(kOtherWin + 4, 0x10066, 0x4a, 5, copy);   /* WM_COPYDATA, SendMessage to another process */
        CHECK("bc", got.size() == 1 && got[0].record.target == kOther && got[0].record.value1 == 0x4a &&
                        got[0].record.detail == L"ws=send_message;type=other_process;to_tid=52;win=0x10066;msg=0x4a;wparam=0x30;"
                                                L"lparam=0x1234;data_bytes=10;sha256=" +
                                                    LinuxWide(Sha256Bytes(copy.data(), copy.size())) + L";flags=0x0;timeout=0");
        const auto byWindow = message(0x999, 0x10066, 0x4a, 6, {});   /* PostMessage: the window names it */
        CHECK("bc", got.size() == 1 && byWindow.size() == 1 && byWindow[0].record.target == kOther &&
                        byWindow[0].repeatKey == got[0].repeatKey && byWindow[0].record.detail.find(L"type=posted;") != std::wstring::npos);
        got = message(kWinPid + 4, 0, 0x4a, 6, {});   /* to its own thread: the same record, no target */
        CHECK("bc", got.size() == 1 && got[0].record.target == 0 && got[0].collapse &&
                        got[0].record.detail.rfind(L"ws=send_message;type=posted;to_tid=" + std::to_wstring(kWinPid + 4) + L";win=0x0;", 0) == 0);
        CHECK("bc", message(0x999, 0x10077, 0x4a, 6, {}).size() == 1);   /* a window not seen created: kept */
        got = message(0x999, 0x10050, 0x102, 6, {});                   /* WM_CHAR to its own window (ba) */
        CHECK("bc", got.size() == 1 && got[0].record.target == 0 &&
                        got[0].record.detail.find(L";msg=0x102;input=withheld;flags=") != std::wstring::npos);
        got = message(kOtherWin + 4, 0x10066, 0x102, 6, {});            /* WM_CHAR */
        CHECK("bc", got.size() == 1 && got[0].record.detail.find(L";msg=0x102;input=withheld;flags=") != std::wstring::npos);
        /* Window requests of another process's window name it as the target (generic and decoded ones). */
        CHECK("bc", run(192, {}, {{12, 0x10066}}, 0, {})[0].record.target == kOther);
        CHECK("bc", run(146, {}, {{12, 0x66}, {16, static_cast<uint32_t>(-16)}}, 0, {})[0].record.target == kOther);
        auto destroy = other(Event(MM_WS_REQUEST, 143, {}, 0));
        Put32(*destroy, 12, 0x10066);
        h.Run(*destroy, other(Reply(143, 0)).get());
        CHECK("bc", run(192, {}, {{12, 0x10066}}, 0, {})[0].record.target == 0);
        /* A thread's windows freed with it (no destroy_window reply): dropped as whole handles, only that thread's. */
        auto made = [&](uint32_t handle, uint32_t winTid) {
            auto q = other(Event(MM_WS_REQUEST, 142, {}, 0));
            q->win_tid = winTid;
            auto r = other(Reply(142, 0));
            Put32(*r, 8, handle);
            h.Run(*q, r.get());
        };
        made(0x20068, kOtherWin + 4);
        made(0x1006a, kOtherWin + 8);
        CHECK("bc", h.decoder.DropWindows(kOther, kOtherWin + 4) == std::vector<uint32_t>{0x20068} &&
                        run(192, {}, {{12, 0x20068}}, 0, {})[0].record.target == 0 &&
                        run(192, {}, {{12, 0x1006a}}, 0, {})[0].record.target == kOther);
        CHECK("bc", h.decoder.DropWindows(kOther, 0) == std::vector<uint32_t>{0x1006a} && h.decoder.DropWindows(kOther, 0).empty());
    }
    /* (bd) get_message: what was received; keyboard messages only with --log-real-input. */
    {
        auto receive = [&](uint32_t msg, uint32_t type) {
            auto q = Event(MM_WS_REQUEST, 122, {}, 0);
            auto r = Reply(122, 0);
            Put32(*r, 8, 0x10020);
            Put32(*r, 12, msg);
            Put64(*r, 16, 0x41);
            Put64(*r, 24, 0x1e0001);
            Put32(*r, 32, type);
            Put32(*r, 36, static_cast<uint32_t>(-3));
            Put32(*r, 40, 4);
            return h.Run(*q, r.get());
        };
        auto got = receive(0x201, 7);
        CHECK("bd", got.size() == 1 && got[0].record.value1 == 0x201 &&
                        got[0].record.detail == L"ws=get_message;flags=0x0;get_win=0x0;win=0x10020;msg=0x201;type=hardware;wparam=0x41;"
                                                L"lparam=0x1e0001;x=-3;y=4;time=0x0");
        got = receive(0x100, 7);   /* WM_KEYDOWN */
        CHECK("bd", got.size() == 1 && got[0].record.detail.find(L";msg=0x100;type=hardware;input=withheld;x=") != std::wstring::npos);
        CHECK("bd", receive(13, 9)[0].record.detail.find(L"input=withheld") != std::wstring::npos);   /* a WH_KEYBOARD_LL call */
        h.decoder.SetRealInput(true);
        CHECK("bd", receive(0x100, 7)[0].record.detail.find(L";msg=0x100;type=hardware;wparam=0x41;") != std::wstring::npos);
        h.decoder.SetRealInput(false);
        auto poll = Event(MM_WS_REQUEST, 122, {}, 0);
        got = h.Run(*poll, Reply(122, 0x103).get());   /* nothing waiting */
        CHECK("bd", got.size() == 1 && got[0].record.detail == L"ws=get_message;flags=0x0;get_win=0x0");
    }
    /* (be) get_async_result: the output's size and SHA-256, its first 1 KiB as the payload (capped). */
    {
        const std::vector<uint8_t> output(2000, 0x41);
        auto q = Event(MM_WS_REQUEST, 134, {}, 0);
        Put64(*q, 16, 0x7f001000);
        auto got = h.Run(*q, Reply(134, 0, output).get());
        CHECK("be", got.size() == 1 && got[0].payload && got[0].bytes.size() == 1024 && got[0].payloadTotal == 1024 &&
                        got[0].payloadKind == MsMonPayloadIpcData &&
                        got[0].record.detail == L"ws=get_async_result;user_arg=0x7f001000;out_bytes=2000;sha256=" +
                                                    LinuxWide(Sha256Bytes(output.data(), output.size())));
    }
    /* (bf) ioctl codes other than AFD's: device control on the handle's NT name, collapsed per handle and code, the
     * answer hashed. */
    {
        run(45, U16("\\Device\\HarddiskVolume1"), {{12, 0x80100080}}, 0, {{8, 0x8c}});
        const std::vector<uint8_t> answer(40, 7);
        auto q = Event(MM_WS_REQUEST, 138, std::vector<uint8_t>(12, 0), 12);
        Put32(*q, 8, 1024);
        Put32(*q, 12, 0x2d1400);   /* IOCTL_STORAGE_QUERY_PROPERTY */
        Put32(*q, 16, 0x8c);
        auto got = h.Run(*q, Reply(138, 0, answer).get());
        CHECK("bf", got.size() == 1 && got[0].record.type == MsMonFileDeviceControl && got[0].record.value0 == 0x2d1400 &&
                        got[0].record.text == L"\\Device\\HarddiskVolume1" && got[0].record.value1 == 12 &&
                        got[0].repeatKey == ((0x8cull << 32) | 0x2d1400) && got[0].collapse &&
                        got[0].record.detail == L"ioctl;ws=ioctl;handle=0x8c;code=0x2d1400;out_size=1024;out_bytes=40;sha256=" +
                                                    LinuxWide(Sha256Bytes(answer.data(), answer.size())));
    }
    /* (bg) IRP results in winedevice: set_irp_result (and the result get_next_device_request carries) as the IRP's
     * record with the client as target, the output hashed and capped. */
    {
        auto device = [](std::unique_ptr<mm_ws_event> e) {
            e->tgid = 6500;
            e->tid = 6501;
            if (e->kind == MM_WS_REQUEST) e->win_pid = 0x600, e->win_tid = 0x604;
            return e;
        };
        h.Run(*device(Event(MM_WS_REQUEST, 250, {}, 0)), device(Reply(250, 0)).get());
        auto irp = [&](uint32_t next, const std::vector<uint8_t>& data, uint32_t prev, uint32_t iosb) {
            auto q = device(Event(MM_WS_REQUEST, 253, data, static_cast<uint32_t>(data.size())));
            Put32(*q, 16, prev);
            Put32(*q, 36, iosb);
            Put32(*q, 40, static_cast<uint32_t>(data.size()));
            auto r = device(Reply(253, 0));
            Put32(*r, 8, 6);   /* ioctl */
            Put32(*r, 12, 0x2d1400);
            Put64(*r, 24, 0x9900);
            Put32(*r, 40, next);
            Put32(*r, 44, kWinPid + 4);
            return h.Run(*q, r.get());
        };
        CHECK("bg", irp(0x304, {}, 0, 0).size() == 1);
        auto result = device(Event(MM_WS_REQUEST, 139, {'1', '2', '3', '4', '5'}, 5));
        Put32(*result, 12, 0x304);
        Put32(*result, 20, 5);
        auto got = h.Run(*result, device(Reply(139, 0)).get());
        CHECK("bg", got.size() == 1 && got[0].record.type == MsMonFileDeviceControl && got[0].record.text == L"file_object:0x9900" &&
                        got[0].record.target == kTgid && got[0].record.value0 == 0x2d1400 && got[0].record.value1 == 5 &&
                        got[0].payload && got[0].bytes == std::vector<uint8_t>({'1', '2', '3', '4', '5'}) &&
                        Narrow(got[0].record.detail).rfind("irp_result;irp=ioctl;code=0x2d1400;status=0x0;information=5;out_bytes=5;sha256=", 0) == 0 &&
                        got[0].record.detail.find(L";client_win_tid=36;driver=") != std::wstring::npos);
        CHECK("bg", irp(0x308, {}, 0, 0).size() == 1);
        got = irp(0x30c, {'x'}, 0x308, 0xC0000010);   /* the previous IRP's result rides along: failed */
        CHECK("bg", got.size() == 2 && got[0].record.status == (int32_t)0xC0000010 && got[0].record.target == kTgid &&
                        Narrow(got[0].record.detail).rfind("irp_result;irp=ioctl;code=0x2d1400;status=0xc0000010;information=1;out_bytes=1;", 0) == 0 &&
                        got[1].record.type == MsMonFileDeviceControl);
    }
    /* (bh) input: winex11's real input is logged per type without keys; --log-real-input adds them; cursor shapes. */
    {
        auto move = [&](int32_t x) { return run(121, {}, {{16, 0}, {20, static_cast<uint32_t>(x)}, {24, 7}, {32, 1}}, 0, {}); };
        auto got = move(-5);
        const auto second = move(9);
        CHECK("bh", got.size() == 1 && second.size() == 1 && got[0].repeatKey == second[0].repeatKey &&
                        got[0].record.detail == L"ws=send_hardware_message;input=mouse;x=-5;y=7;data=0x0;flags=0x1;window=0x0;injected=0");
        h.decoder.SetRealInput(true);
        got = run(121, {}, {{16, 1}, {20, 0x41}}, 0, {});
        const auto next = run(121, {}, {{16, 1}, {20, 0x42}}, 0, {});
        CHECK("bh", got.size() == 1 && next.size() == 1 && got[0].repeatKey != next[0].repeatKey &&
                        got[0].record.detail == L"ws=send_hardware_message;input=keyboard;vkey=0x41;scan=0x0;flags=0x0;window=0x0;injected=0");
        h.decoder.SetRealInput(false);
        CHECK("bh", has(run(279, {}, {{12, 1}, {16, 0x1003}}, 0, {}), L"ws=set_cursor;flags=0x1;handle=0x1003"));
    }
    /* (bi) a thread's start address: init_thread, sent before its TEB is in use (no Windows ids). */
    {
        auto q = Event(MM_WS_REQUEST, 6, {}, 0);
        q->win_pid = q->win_tid = 0;
        Put32(*q, 12, 4300);
        Put32(*q, 16, 31);
        Put32(*q, 20, 33);
        Put64(*q, 24, 0x7ffd0000);
        Put64(*q, 32, 0x140001000);
        auto got = h.Run(*q, Reply(6, 0).get());
        CHECK("bi", Generic(got, "init_thread") &&
                        got[0].record.detail == L"ws=init_thread;unix_tid=4300;reply_fd=31;wait_fd=33;teb=0x7ffd0000;entry=0x140001000;reply_suspend=0");
    }
    /* (bj) request-pipe integrity: each rejected write is a record of its own (another process's pipe, a splice); a
     * request awaiting its reply is not disturbed. */
    {
        auto waiting = Event(MM_WS_REQUEST, 39, {}, 0);
        Put32(*waiting, 12, 0x8c);
        h.Run(*waiting, nullptr);
        auto reject = [&](uint32_t nr, uint32_t reason, uint64_t count, uint32_t owner) {
            mm_ws_reject r{};
            r.ino = 777;
            r.count = count;
            r.fd = 9;
            r.nr = nr;
            r.reason = reason;
            r.owner = owner;
            std::vector<uint8_t> bytes(sizeof(r));
            std::memcpy(bytes.data(), &r, sizeof(r));
            auto e = Event(MM_WS_REQUEST, 29, bytes, 0);
            e->flags = MM_WS_F_REJECTED;
            return h.Run(*e, nullptr);
        };
        auto got = reject(1, MM_WS_REJECT_FOREIGN, 64, kOther);
        CHECK("bj", got.size() == 1 && got[0].record.type == MsMonFileWrite && got[0].record.text == L"pipe:[777]" &&
                        got[0].record.target == kOther && !got[0].collapse && got[0].record.value0 == 64 &&
                        got[0].record.detail == L"request_pipe_rejected;reason=foreign_pipe;syscall=write;fd=9;count=64;owner_pid=5151;"
                                                L"req=select;request_size=0");
        got = reject(275, MM_WS_REJECT_SPLICE, 64, kOther);
        CHECK("bj", got.size() == 1 && got[0].record.detail == L"request_pipe_rejected;reason=splice;syscall=splice;fd=9;count=64;owner_pid=5151");
        got = reject(328, MM_WS_REJECT_OTHER, 2, kTgid);   /* pwritev2 into its own request pipe */
        CHECK("bj", got.size() == 1 && got[0].record.detail == L"request_pipe_rejected;reason=other_call;syscall=pwritev2;fd=9;count=2;owner_pid=4242");
        got = reject(40, MM_WS_REJECT_OTHER, 64, kOther);
        CHECK("bj", got.size() == 1 && got[0].record.detail.rfind(L"request_pipe_rejected;reason=other_call;syscall=sendfile;", 0) == 0);
        got = reject(1, MM_WS_REJECT_SIZE, 3, kTgid);
        CHECK("bj", got.size() == 1 && got[0].record.target == 0 &&
                        got[0].record.detail == L"request_pipe_rejected;reason=size;syscall=write;fd=9;count=3;owner_pid=4242");
        got = h.Run(*Reply(39, 0), nullptr);
        CHECK("bj", Generic(got, "query_mutex"));   /* the waiting request's reply still meets it */
    }
    /* (bk) a kernel aggregate of a request (bpf.cpp AggWrite) and the first call of its key (sampled). */
    {
        mm_agg total{};
        total.calls = 500;
        total.first_ns = 1000000;
        total.last_ns = 3000000;
        total.lo = ~0ull;
        const LinuxRecord summary = WsAggSummary(138, (0x24ull << 32) | 0x12024, total);
        CHECK("bk", summary.sensor == MSMON_SENSOR_LINUX_EBPF_WINESERVER && summary.type == MsMonFileQueryInformation &&
                        summary.text == L"system:ioctl" && summary.value1 == 500 &&
                        summary.detail == L"repeats_tail;syscall=wineserver:ioctl;aggregate=kernel;ws=ioctl;handle=0x24;code=0x12024;"
                                          L"repeats_before=500;repeat_bytes=0;repeat_span_us=2000;errors=0");
        CHECK("bk", WsAggSummary(29, 2, total).detail.find(L";aggregate=kernel;ws=select;flags=0x2;repeats_before=") != std::wstring::npos &&
                        WsAggSummary(134, 0, total).detail.find(L";aggregate=kernel;ws=get_async_result;repeats_before=") != std::wstring::npos);
        auto q = Event(MM_WS_REQUEST, 134, {}, 0);
        q->flags = MM_WS_F_SAMPLED;
        auto got = h.Run(*q, Reply(134, 0).get());
        CHECK("bk", got.size() == 1 && got[0].record.detail == L"ws=get_async_result;user_arg=0x0;out_bytes=0;aggregate=sampled");
        CHECK("bk", run(124, {}, {{12, 77}}, 0, {})[0].repeatKey == 0);   /* accept_hardware_message: per request ('!') */
    }
    /* (bm) a module unload: unmap_view of an image view (map_image_view) names its section and is never collapsed;
     * of a data view (map_view) it stays collapsed and no unload. */
    {
        auto image = Event(MM_WS_REQUEST, 68, {}, 0);   /* map_image_view mapping@c base@10 size@18 */
        Put32(*image, 12, 0x5c);
        Put64(*image, 16, 0x180000000);
        Put64(*image, 24, 0x20000);
        auto got = h.Run(*image, Reply(68, 0).get());
        CHECK("bm", got.size() == 1 && !got[0].collapse);
        auto data = Event(MM_WS_REQUEST, 67, {}, 0);    /* map_view mapping@c access@10 base@18 size@20 */
        Put32(*data, 12, 0x60);
        Put64(*data, 24, 0x7f0000000000);
        Put64(*data, 32, 0x1000);
        h.Run(*data, Reply(67, 0).get());
        auto unmap = [&](uint64_t base) {
            auto q = Event(MM_WS_REQUEST, 71, {}, 0);
            Put64(*q, 16, base);
            return h.Run(*q, Reply(71, 0).get());
        };
        got = unmap(0x180000000);
        CHECK("bm", got.size() == 1 && !got[0].collapse && got[0].record.type == MsMonFileSection &&
                        got[0].record.value0 == 0x180000000 && got[0].record.detail.find(L"unmap_view;base=0x180000000;image_unload=1") == 0);
        got = unmap(0x7f0000000000);
        CHECK("bm", got.size() == 1 && got[0].collapse && got[0].record.detail.find(L"image_unload") == std::wstring::npos);
        got = unmap(0x180000000);   /* unmapped already: no image view there any more */
        CHECK("bm", got.size() == 1 && got[0].record.detail.find(L"image_unload") == std::wstring::npos);
    }
    /* (bn) --log-content: clipboard data hashed (never its bytes), an async result's payload all its captured bytes (not
     * the first 1 KiB), even with --no-payloads; without it neither. */
    {
        const std::vector<uint8_t> copied = U16("hunter2"), output(2000, 0x42);
        const std::wstring copiedHash = LinuxWide(Sha256Bytes(copied.data(), copied.size()));
        auto setData = [&]() {
            auto q = Event(MM_WS_REQUEST, 210, copied, static_cast<uint32_t>(copied.size()));
            Put32(*q, 12, 13);   /* CF_UNICODETEXT */
            return h.Run(*q, Reply(210, 0).get());
        };
        auto getData = [&]() {
            auto q = Event(MM_WS_REQUEST, 211, {}, 0);
            Put32(*q, 12, 13);
            auto r = Reply(211, 0, copied);
            Put32(*r, 12, 0x10044);
            Put32(*r, 20, static_cast<uint32_t>(copied.size()));
            return h.Run(*q, r.get());
        };
        auto async = [&]() {
            auto q = Event(MM_WS_REQUEST, 134, {}, 0);
            return h.Run(*q, Reply(134, 0, output).get());
        };
        auto has = [](const std::vector<WsRecord>& got, const std::wstring& part) {
            return got.size() == 1 && got[0].record.detail.find(part) != std::wstring::npos && !got[0].payload;
        };
        CHECK("bn", has(setData(), L";format=13;bytes=14") && setData()[0].record.detail.find(L"sha256") == std::wstring::npos);
        CHECK("bn", getData()[0].record.detail.find(L"sha256") == std::wstring::npos);
        h.decoder.SetContent(true);
        CHECK("bn", has(setData(), L";format=13;bytes=14;sha256=" + copiedHash));
        CHECK("bn", has(getData(), L";owner=0x10044;bytes=14;sha256=" + copiedHash));
        auto got = async();
        CHECK("bn", got.size() == 1 && got[0].payload && got[0].bytes.size() == 2000);
        h.decoder.SetPayloads(false);
        got = async();
        CHECK("bn", got.size() == 1 && got[0].payload && got[0].bytes.size() == 2000);
        h.decoder.SetContent(false);
        got = async();
        CHECK("bn", got.size() == 1 && !got[0].payload && got[0].record.detail.find(L";sha256=") != std::wstring::npos);
        h.decoder.SetPayloads(true);
    }
    /* (bl) every request of the table, and a number past it, writes a record (a zero request and reply; send_message
     * to another thread). */
    for (uint32_t request = 0; request <= 306; request++) {
        auto q = Event(MM_WS_REQUEST, request, {}, 0);
        if (request == 119) Put32(*q, 12, 0x999);
        const auto got = h.Run(*q, Reply(request, 0).get());
        if (got.empty()) std::fprintf(stderr, "[fail] bl: no record of %s\n", WsRequestName(request));
        CHECK("bl", !got.empty());
    }

    if (failures != 0) {
        std::fprintf(stderr, "wineserver decoder self-test: %d failure(s)\n", failures);
        return 1;
    }
    std::printf("wineserver decoder self-test passed\n");
    return 0;
}
