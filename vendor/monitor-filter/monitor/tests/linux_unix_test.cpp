/* Offline checks of the desktop-service side of msmon (agent/linux/bpf/unix_bpf.h framing as unix.bpf.h runs it,
 * agent/rpc_names.cpp's X11, D-Bus and PulseAudio names, agent/linux/unixproto.h's extension table and summaries) and of
 * the window owner keys the uprobes read (ws_bpf.h). X11, D-Bus and PulseAudio byte streams: requests split over
 * iovecs, several in one write, a request past the 4 KiB walk, a partial write, a header cut between two reads. The
 * kernel side runs as root in tests/ebpf_checks/unixproto.sh. */
#include "../agent/linux/unixproto.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <thread>
#include <vector>

namespace {

bool Check(bool condition, const char* message)
{
    if (!condition) std::cerr << "FAIL: " << message << "\n";
    return condition;
}

using Bytes = std::vector<uint8_t>;

/* One socket's state and one call of unix.bpf.h's unix_head on it, with the gather's concatenation of the call's
 * Buffers (Ret bytes of them moved): the op of every message it framed (a run of one op is one agg count there, unless
 * listed), the D-Bus messages it listed in the head (offset << 16 | type), the bytes it left unparsed, whether a D-Bus
 * head went out (Data: the head's bytes) and whether the call was counted as the SASL handshake's. */
struct Walked {
    std::vector<uint32_t> ops, listed;
    uint64_t unparsed = 0;
    bool head = false, sasl = false;
    Bytes data;
};

Walked Call(mm_unix_sock& s, bool rx, const std::vector<Bytes>& buffers, size_t ret)
{
    Walked out;
    Bytes stream;
    for (const Bytes& buffer : buffers) stream.insert(stream.end(), buffer.begin(), buffer.end());
    const uint64_t asked = stream.size();
    stream.resize(std::min(stream.size(), ret));
    const uint32_t d = rx;
    if (s.svc == 0 || (rx && s.svc == MM_UNIX_PENDING)) return out;
    if (rx && (s.flags & MM_UNIX_S_RX_LOST)) {
        out.unparsed = ret;
        return out;
    }
    const uint32_t skip = s.skip[d], part = s.part_len[d];
    if (skip >= ret) {
        s.skip[d] -= static_cast<uint32_t>(ret);
        return out;
    }
    Bytes head(2 * MM_UNIX_HEAD + 2 * MM_UNIX_PART);
    std::memcpy(head.data(), s.part[d], part);
    const size_t take = std::min<size_t>(ret - skip, MM_UNIX_HEAD);
    std::memcpy(head.data() + part, stream.data() + skip, take);
    const uint32_t len = static_cast<uint32_t>(part + take);
    out.data.assign(head.begin(), head.begin() + len);
    const uint64_t bytes = ret - skip;
    uint32_t at32 = 0, big = (s.flags & MM_UNIX_S_BIG) != 0, list = 0;
    if (s.svc == MM_UNIX_PENDING) {
        s.svc = mm_unix_classify(head.data(), len, &at32, &big);
        if (!s.svc) return out;
        s.flags = (big ? MM_UNIX_S_BIG : 0) | (s.svc == MM_UNIX_X11 ? MM_UNIX_S_RX_SETUP : 0) |
                  (s.svc == MM_UNIX_DBUS ? MM_UNIX_S_TEXT_TX | MM_UNIX_S_TEXT_RX : 0);
    }
    if (s.svc == MM_UNIX_DBUS) {
        list = s.heads < MM_UNIX_DBUS_HEADS;   /* the second's window is the caller's: it resets heads */
        const uint32_t text = rx ? MM_UNIX_S_TEXT_RX : MM_UNIX_S_TEXT_TX;
        if ((s.flags & text) && !(at32 < len && mm_unix_dbus_start(head.data() + at32, len - at32))) {
            if (!rx && len >= 7 && mm_unix_dbus_begin(head.data() + len - 7)) s.flags &= ~text;
            out.sasl = true;
            if (list) s.heads++, out.head = true;
            return out;
        }
        s.flags &= ~text;
    }
    uint64_t at = at32;
    uint32_t incomplete = 0;
    if (rx && (s.flags & MM_UNIX_S_RX_SETUP)) {
        if (len < 8) {
            incomplete = 1;
        } else {
            s.flags &= ~MM_UNIX_S_RX_SETUP;
            at = 8 + mm_unix_u16(head.data() + 6, big) * 4;
        }
    }
    for (uint32_t step = 0; !incomplete && step < MM_UNIX_STEPS && at < len; step++) {
        uint32_t op = 0;
        const uint64_t size = mm_unix_frame(s.svc, rx, big, head.data() + at, static_cast<uint32_t>(len - at), &op);
        if (size == 0) incomplete = 1;
        if (size == 0 || size == ~0ull) break;
        out.ops.push_back(op);
        if (list && out.listed.size() < MM_UNIX_SAMPLED) out.listed.push_back(static_cast<uint32_t>(at) << 16 | (op & 0xffff));
        at += size;
    }
    if (!out.listed.empty()) s.heads++, out.head = true;
    uint32_t next = 0, carry = 0;
    uint64_t unparsed = mm_unix_after(rx, at, len, part, bytes, asked - skip, incomplete, &next, &carry);
    if (unparsed == ~0ull) {
        if (rx) s.flags |= MM_UNIX_S_RX_LOST;
        unparsed = part + bytes > at ? part + bytes - at : 0;
        next = carry = 0;
    }
    s.skip[d] = next;
    s.part_len[d] = carry ? static_cast<uint32_t>(part + bytes - at) : 0;
    if (carry) std::memcpy(s.part[d], head.data() + at, MM_UNIX_PART);
    out.unparsed = unparsed;
    return out;
}

void Le16(Bytes& b, size_t at, uint32_t v)
{
    b[at] = uint8_t(v), b[at + 1] = uint8_t(v >> 8);
}
void Le32(Bytes& b, size_t at, uint32_t v)
{
    for (int i = 0; i < 4; i++) b[at + i] = uint8_t(v >> (8 * i));
}
void Be32(Bytes& b, size_t at, uint32_t v)
{
    for (int i = 0; i < 4; i++) b[at + i] = uint8_t(v >> (24 - 8 * i));
}

/* An X11 request of Size bytes (a multiple of 4): Major, Minor, its length, Fields from offset 4. */
Bytes X11(uint8_t major, uint8_t minor, size_t size)
{
    Bytes b(size);
    b[0] = major, b[1] = minor;
    Le16(b, 2, static_cast<uint32_t>(size / 4));
    return b;
}

/* A D-Bus message: type, serial, its header fields (code, signature, value), a body of Body bytes. */
Bytes Dbus(uint8_t type, uint32_t serial, const std::vector<std::tuple<uint8_t, char, std::string>>& fields, uint32_t body = 0)
{
    Bytes b = {'l', type, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    Le32(b, 8, serial);
    for (const auto& [code, type_, value] : fields) {
        while (b.size() % 8) b.push_back(0);
        b.insert(b.end(), {code, 1, static_cast<uint8_t>(type_), 0});
        if (type_ == 'u') {
            b.resize(b.size() + 4);
            Le32(b, b.size() - 4, static_cast<uint32_t>(std::stoul(value)));
            continue;
        }
        b.resize(b.size() + 4);
        Le32(b, b.size() - 4, static_cast<uint32_t>(value.size()));
        b.insert(b.end(), value.begin(), value.end());
        b.push_back(0);
    }
    Le32(b, 12, static_cast<uint32_t>(b.size() - 16));
    while (b.size() % 8) b.push_back(0);
    Le32(b, 4, body);
    b.resize(b.size() + body);
    return b;
}

/* A fake X server on an abstract socket: one client, its setup answered (Accept; with Cookie only when the client gave
 * it) or refused, each QueryExtension of X11ExtensionNames() answered in order, XTEST, XInputExtension and Present
 * present. */
void FakeServer(int listener, bool accept, std::string cookie)
{
    const int fd = ::accept(listener, nullptr, nullptr);
    if (fd < 0) return;
    uint8_t setup[12];
    if (recv(fd, setup, sizeof(setup), MSG_WAITALL) != sizeof(setup)) return close(fd), void();
    std::vector<uint8_t> auth(((setup[6] + 3u) & ~3u) + ((setup[8] + 3u) & ~3u));
    if (!auth.empty() && recv(fd, auth.data(), auth.size(), MSG_WAITALL) != static_cast<ssize_t>(auth.size())) return close(fd), void();
    const std::string given(auth.begin() + ((setup[6] + 3) & ~3), auth.begin() + ((setup[6] + 3) & ~3) + setup[8]);
    if (!cookie.empty() && given != cookie) accept = false;
    if (!accept) {
        const uint8_t refused[16] = {0, 5, 11, 0, 0, 0, 2, 0, 'N', 'o', ' ', 'a', 'u', 0, 0, 0};
        send(fd, refused, sizeof(refused), MSG_NOSIGNAL);
        close(fd);
        return;
    }
    const uint8_t success[16] = {1, 0, 11, 0, 0, 0, 2, 0, 1, 2, 3, 4, 5, 6, 7, 8};
    send(fd, success, sizeof(success), MSG_NOSIGNAL);
    uint16_t sequence = 0;
    for (const std::string& name : X11ExtensionNames()) {
        uint8_t request[8];
        if (recv(fd, request, sizeof(request), MSG_WAITALL) != sizeof(request)) break;
        std::vector<uint8_t> rest((request[2] | request[3] << 8) * 4u - 8);
        if (recv(fd, rest.data(), rest.size(), MSG_WAITALL) != static_cast<ssize_t>(rest.size())) break;
        uint8_t reply[32] = {1, 0, uint8_t(++sequence), uint8_t(sequence >> 8)};
        if (name == "XTEST") reply[8] = 1, reply[9] = 132;
        if (name == "XInputExtension") reply[8] = 1, reply[9] = 131, reply[10] = 66, reply[11] = 129;
        if (name == "Present") reply[8] = 1, reply[9] = 148;
        send(fd, reply, sizeof(reply), MSG_NOSIGNAL);
    }
    close(fd);
}

/* A server that announces 0xffff * 4 bytes of setup and then sends one every 100 ms until the client goes. */
void TrickleServer(int listener)
{
    const int fd = ::accept(listener, nullptr, nullptr);
    if (fd < 0) return;
    uint8_t setup[12];
    const uint8_t head[8] = {1, 0, 11, 0, 0, 0, 0xff, 0xff};
    if (recv(fd, setup, sizeof(setup), MSG_WAITALL) == sizeof(setup) && send(fd, head, sizeof(head), MSG_NOSIGNAL) == sizeof(head)) {
        const uint8_t one = 0;
        while (send(fd, &one, 1, MSG_NOSIGNAL) == 1) std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    close(fd);
}

/* X11QueryExtensions (with Given as its cookie, Skip as its server test, TimeoutMs) against Server on a fresh abstract
 * name. */
bool Query(const std::function<void(int)>& server, X11Extensions& table, std::string& why, const std::string& given = {},
           const std::function<bool(pid_t)>& skip = {}, int timeoutMs = 2000)
{
    static int count = 0;
    const std::string name = "@msmon-unix-test-" + std::to_string(getpid()) + "-" + std::to_string(++count);
    const int listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path + 1, name.data() + 1, name.size() - 1);
    if (listener < 0 ||
        bind(listener, reinterpret_cast<sockaddr*>(&address), static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + name.size())) != 0 ||
        listen(listener, 1) != 0)
        return false;
    std::thread serving(server, listener);
    const bool ok = X11QueryExtensions("unix:" + name, table, why, timeoutMs, given, skip);
    serving.join();
    close(listener);
    return ok;
}
bool Query(bool accept, X11Extensions& table, std::string& why, const std::string& wanted = {}, const std::string& given = {})
{
    return Query([&](int listener) { FakeServer(listener, accept, wanted); }, table, why, given);
}

}  // namespace

int main()
{
    bool ok = true;

    /* X11: the connection setup classifies the socket and is passed over; a QueryExtension split over three iovecs
     * (header, name, padding, as xcb writes it) and a GetProperty in the same write are framed. */
    mm_unix_sock x{};
    x.svc = MM_UNIX_PENDING;
    const Bytes setup = {'l', 0, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    Bytes header = X11(98, 0, 16);
    Le16(header, 4, 5);
    header.resize(8);
    const Bytes name = {'X', 'T', 'E', 'S', 'T'}, pad = {0, 0, 0};
    const Bytes property = X11(20, 0, 24), focus = X11(43, 0, 4), pointer = X11(38, 0, 8);
    Walked w = Call(x, false, {setup, header, name, pad, property}, 12 + 16 + 24);
    ok &= Check(x.svc == MM_UNIX_X11 && (x.flags & MM_UNIX_S_RX_SETUP) && w.ops == std::vector<uint32_t>{98 << 8, 20 << 8} &&
                    w.unparsed == 0 && x.skip[0] == 0,
                "X11: setup passed over, a QueryExtension split over iovecs and a GetProperty framed");
    w = Call(x, false, {focus, focus, pointer}, 16);
    ok &= Check(w.ops == std::vector<uint32_t>{43 << 8, 43 << 8, 38 << 8}, "X11: several requests in one write");

    /* A request past the 4 KiB walk: an 8 KiB ChangeProperty, then a GetInputFocus in the same write (past the walk:
     * unparsed); a whole write, so the next starts a request. */
    Bytes change = X11(18, 0, 24 + 8192);
    w = Call(x, false, {change, focus}, change.size() + 4);
    ok &= Check(w.ops == std::vector<uint32_t>{18 << 8} && w.unparsed == 4 && x.skip[0] == 0 && x.part_len[0] == 0,
                "X11: a request past 4 KiB is counted unparsed");
    w = Call(x, false, {pointer}, 8);
    ok &= Check(w.ops == std::vector<uint32_t>{38 << 8}, "X11: the next write is framed after a write past 4 KiB");

    /* A partial write: the rest of the request comes next and is passed over. */
    w = Call(x, false, {change}, 3000);
    ok &= Check(w.ops == std::vector<uint32_t>{18 << 8} && x.skip[0] == change.size() - 3000, "X11: a partial write's rest is skipped");
    w = Call(x, false, {Bytes(change.begin() + 3000, change.end())}, change.size() - 3000);
    ok &= Check(w.ops.empty() && x.skip[0] == 0, "X11: the rest of a partially written request");
    /* A partial write past the walk: 1500 GetInputFocus (6000 bytes), 5000 sent: the walk stops at 4 KiB, the unsent
     * 1000 come next. */
    std::vector<Bytes> many(1500, focus);
    w = Call(x, false, many, 5000);
    ok &= Check(w.ops.size() == MM_UNIX_STEPS && w.unparsed == 5000 - 4096 && x.skip[0] == 1000,
                "X11: a partial write past the walk keeps step by its unsent rest");
    w = Call(x, false, {Bytes(1000)}, 1000);
    w = Call(x, false, {focus}, 4);
    ok &= Check(w.ops == std::vector<uint32_t>{43 << 8}, "X11: in step after a partial write past the walk");
    /* BIG-REQUESTS: a length of 0, then the length in units. */
    Bytes bigRequest(40);
    bigRequest[0] = 72;   /* PutImage */
    Le32(bigRequest, 4, 10);
    w = Call(x, false, {bigRequest, focus}, 44);
    ok &= Check(w.ops == std::vector<uint32_t>{72 << 8, 43 << 8}, "X11: a BIG-REQUESTS length");

    /* X11 receives: the setup reply passed over, an event, an error and a reply whose header two reads cut (carried). */
    Bytes reply(16);
    reply[0] = 1;
    Le16(reply, 6, 2);
    Bytes motion(32), error(32), answer(40), xi(40), sent(32);
    motion[0] = 6;
    error[0] = 0, error[1] = 3, error[8] = 0, error[10] = 20;   /* BadWindow from GetProperty */
    answer[0] = 1;
    Le32(answer, 4, 2);
    xi[0] = 35, xi[1] = 131, xi[8] = 13;   /* XI2 RawKeyPress */
    Le32(xi, 4, 2);
    sent[0] = 0x80 | 33;   /* a SendEvent's ClientMessage */
    w = Call(x, true, {reply, motion}, 48);
    ok &= Check(w.ops == std::vector<uint32_t>{6u << 24} && !(x.flags & MM_UNIX_S_RX_SETUP), "X11: setup reply passed, an event framed");
    Bytes cut(error);
    cut.insert(cut.end(), answer.begin(), answer.begin() + 8);
    w = Call(x, true, {cut}, cut.size());
    ok &= Check(w.ops == std::vector<uint32_t>{3u << 16 | 20u << 8} && x.part_len[1] == 8, "X11: an error, and a reply header cut");
    w = Call(x, true, {Bytes(answer.begin() + 8, answer.end()), xi, sent}, 32 + 40 + 32);
    ok &= Check(w.ops == std::vector<uint32_t>{1u << 24, 35u << 24 | 131u << 8 | 13, 33u << 24 | MM_UNIX_X11_SENT} &&
                    x.part_len[1] == 0 && x.skip[1] == 0,
                "X11: the carried header joined, a GenericEvent and a SendEvent's event");
    /* A receive past the walk: its framing is lost, later receives are counted unparsed. */
    w = Call(x, true, {Bytes(5000, 6)}, 5000);
    ok &= Check((x.flags & MM_UNIX_S_RX_LOST) && w.unparsed == 5000 - 4096, "X11: a receive past the walk is lost");
    w = Call(x, true, {motion}, 32);
    ok &= Check(w.ops.empty() && w.unparsed == 32, "X11: receives after a lost one are unparsed");

    /* A big-endian client: its setup (with authorization, padded) and its requests in its own order. */
    mm_unix_sock bx{};
    bx.svc = MM_UNIX_PENDING;
    Bytes bsetup = {'B', 0, 0, 11, 0, 0, 0, 18, 0, 16, 0, 0};
    bsetup.resize(12 + 20 + 16);
    Bytes bpointer = {38, 0, 0, 2, 0, 0, 0, 1};
    w = Call(bx, false, {bsetup, bpointer}, bsetup.size() + 8);
    ok &= Check(bx.svc == MM_UNIX_X11 && (bx.flags & MM_UNIX_S_BIG) && w.ops == std::vector<uint32_t>{38 << 8},
                "X11: a big-endian client's setup and request");

    /* PulseAudio: a descriptor written alone, its tagstruct next (carried, then framed); audio on a memblock channel. */
    mm_unix_sock p{};
    p.svc = MM_UNIX_PENDING;
    Bytes descriptor(20), memblock(20 + 8);
    Be32(descriptor, 0, 10);
    Be32(descriptor, 4, 0xffffffff);
    const Bytes tags = {'L', 0, 0, 0, 28, 'L', 0, 0, 0, 7};
    Be32(memblock, 0, 8);
    w = Call(p, false, {descriptor}, 20);
    ok &= Check(p.svc == MM_UNIX_PULSE && w.ops.empty() && p.part_len[0] == 20, "Pulse: a descriptor alone is carried");
    w = Call(p, false, {tags, memblock}, 10 + 28);
    ok &= Check(w.ops == std::vector<uint32_t>{28, MM_UNIX_PULSE_MEMBLOCK} && p.part_len[0] == 0, "Pulse: its command, then audio");

    /* D-Bus: the credentials NUL and SASL; every call a head. Not a service: the socket leaves. */
    mm_unix_sock bus{}, other{};
    bus.svc = other.svc = MM_UNIX_PENDING;
    const char* auth = "AUTH EXTERNAL 31303030\r\n";
    Bytes sasl(1);
    sasl.insert(sasl.end(), auth, auth + std::strlen(auth));
    w = Call(bus, false, {sasl}, sasl.size());
    ok &= Check(bus.svc == MM_UNIX_DBUS && w.head, "D-Bus: the SASL start classifies it, a head goes out");
    w = Call(bus, false, {Bytes{0}}, 1);
    ok &= Check(w.head, "D-Bus: the NUL byte alone");
    w = Call(other, false, {Bytes{2, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0}}, 12);
    ok &= Check(other.svc == 0, "a socket that opens none of these leaves");

    /* D-Bus framed: the handshake's lines are SASL calls until a send ends in BEGIN (a receive: until one starts a
     * message); then every message is listed at its start in the head, the rest of one a read began is passed over, a
     * header read alone is carried, and the agent names each listed message from its start. */
    {
    auto line = [](const char* chars) { return Bytes(chars, chars + std::strlen(chars)); };
    auto named = [](const Walked& walked, size_t index) {
        const size_t at = walked.listed.at(index) >> 16;
        return DbusMessage(walked.data.data() + at, walked.data.size() - at);
    };
    w = Call(bus, false, {line("NEGOTIATE_UNIX_FD\r\n")}, 19);
    ok &= Check(w.sasl && w.head && (bus.flags & MM_UNIX_S_TEXT_TX), "D-Bus: a SASL line is a SASL call");
    w = Call(bus, false, {line("BEGIN\r\n")}, 7);
    ok &= Check(w.sasl && !(bus.flags & MM_UNIX_S_TEXT_TX), "D-Bus: a send ending in BEGIN ends the sent handshake");
    const Bytes hello = Dbus(1, 1, {{1, 'o', "/org/freedesktop/DBus"}, {6, 's', "org.freedesktop.DBus"},
                                    {2, 's', "org.freedesktop.DBus"}, {3, 's', "Hello"}});
    w = Call(bus, false, {hello}, hello.size());
    ok &= Check(!w.sasl && w.listed == std::vector<uint32_t>{1} && named(w, 0).first == L"org.freedesktop.DBus.Hello",
                "D-Bus: a sent message listed and named");
    w = Call(bus, true, {line("OK 0123456789abcdef\r\nAGREE_UNIX_FD\r\n")}, 36);
    ok &= Check(w.sasl && (bus.flags & MM_UNIX_S_TEXT_RX), "D-Bus: the server's SASL lines");
    /* libdbus reads 2048 bytes a call: a 2.5 KB reply, then a signal the second read holds after the reply's rest. */
    const Bytes reply = Dbus(2, 7, {{5, 'u', "1"}, {7, 's', ":1.5"}}, 2400);
    const Bytes added = Dbus(4, 9, {{1, 'o', "/org/freedesktop/UDisks2"}, {2, 's', "org.freedesktop.DBus.ObjectManager"},
                                    {3, 's', "InterfacesAdded"}, {7, 's', ":1.3"}});
    Bytes stream = reply;
    stream.insert(stream.end(), added.begin(), added.end());
    w = Call(bus, true, {Bytes(stream.begin(), stream.begin() + 2048)}, 2048);
    ok &= Check(!(bus.flags & MM_UNIX_S_TEXT_RX) && w.listed == std::vector<uint32_t>{2} && named(w, 0).first == L"method_return" &&
                    bus.skip[1] == reply.size() - 2048,
                "D-Bus: a read starting a message ends the received handshake; the reply listed, its rest to pass over");
    w = Call(bus, true, {Bytes(stream.begin() + 2048, stream.end())}, stream.size() - 2048);
    ok &= Check(w.listed == std::vector<uint32_t>{4} && named(w, 0).first == L"org.freedesktop.DBus.ObjectManager.InterfacesAdded" &&
                    named(w, 0).second == L";message=signal;path=/org/freedesktop/UDisks2;serial=9;sender=:1.3" && bus.skip[1] == 0,
                "D-Bus: the signal after a reply's rest in the same read is named");
    /* GDBus reads the 16-byte header alone, then the rest: the header is carried and the message named whole. */
    const Bytes owner = Dbus(1, 3, {{1, 'o', "/org/freedesktop/DBus"}, {2, 's', "org.freedesktop.DBus"}, {3, 's', "GetNameOwner"},
                                    {6, 's', "org.freedesktop.DBus"}}, 8);
    w = Call(bus, true, {Bytes(owner.begin(), owner.begin() + 16)}, 16);
    ok &= Check(w.listed.empty() && !w.head && bus.part_len[1] == 16, "D-Bus: a header read alone is carried");
    w = Call(bus, true, {Bytes(owner.begin() + 16, owner.end())}, owner.size() - 16);
    ok &= Check(w.listed == std::vector<uint32_t>{1} && named(w, 0).first == L"org.freedesktop.DBus.GetNameOwner" &&
                    bus.part_len[1] == 0 && bus.skip[1] == 0,
                "D-Bus: the carried header joined to the rest, the message named");
    /* Past the second's heads every message is counted (by type), none listed. */
    bus.heads = MM_UNIX_DBUS_HEADS;
    w = Call(bus, false, {hello, hello}, 2 * hello.size());
    ok &= Check(w.ops == std::vector<uint32_t>{1, 1} && w.listed.empty() && !w.head, "D-Bus: past its heads, messages counted");
    /* BEGIN and the first message in one send: the call goes raw (named from its start), the next one is framed. */
    mm_unix_sock bus2{};
    bus2.svc = MM_UNIX_PENDING;
    Call(bus2, false, {sasl}, sasl.size());
    Bytes begun = line("BEGIN\r\n");
    begun.insert(begun.end(), hello.begin(), hello.end());
    w = Call(bus2, false, {begun}, begun.size());
    const auto raw = DbusMessages(w.data.data(), w.data.size());
    ok &= Check(w.sasl && w.head && raw.size() == 1 && raw[0].first == L"org.freedesktop.DBus.Hello" && (bus2.flags & MM_UNIX_S_TEXT_TX),
                "D-Bus: BEGIN and a message in one send: a raw head, the message named");
    w = Call(bus2, false, {hello}, hello.size());
    ok &= Check(!w.sasl && w.listed == std::vector<uint32_t>{1}, "D-Bus: the next send starts a message and is framed");
    /* A message whose bytes end inside its header fields: named by its type. */
    const auto cut = DbusMessage(hello.data(), 20);
    ok &= Check(cut.first == L"method_call" && cut.second.find(L";fields_cut=1") != std::wstring::npos && DbusTypeName(4) == L"signal" &&
                    DbusTypeName(MM_UNIX_DBUS_SASL) == L"sasl",
                "D-Bus: a message cut in its header fields is named by its type");
    }

    /* Names: an extension table as a display gives it. */
    const X11Extensions table = {{"XTEST", 132, 0, 0}, {"XInputExtension", 131, 66, 129}, {"MIT-SHM", 130, 65, 128},
                                 {"X-Resource", 140, 0, 0}, {"Composite", 142, 0, 0}};
    ok &= Check(X11RequestName(20 << 8, table) == L"GetProperty" && X11RequestName(132 << 8 | 2, table) == L"XTEST.FakeInput" &&
                    X11RequestName(131 << 8 | 47, table) == L"XInputExtension.XIQueryVersion" &&
                    X11RequestName(140 << 8 | 4, table) == L"X-Resource.QueryClientIds" &&
                    X11RequestName(200 << 8 | 5, table) == L"ext200.5" && X11RequestName(125 << 8, table) == L"request125",
                "X11 request names, extensions through the display's table");
    Bytes fake(36);
    fake[0] = 132, fake[1] = 2, fake[2] = 9, fake[4] = 2, fake[5] = 38;
    Le32(fake, 12, 0x2a);
    Le16(fake, 24, 100);
    Le16(fake, 26, 200);
    auto request = X11Request(fake.data(), fake.size(), false, table, false);
    ok &= Check(request.first == L"XTEST.FakeInput" && request.second == L";type=KeyPress;root=0x2a;x=100;y=200;input=withheld",
                "XTEST FakeInput: its type and place, its key withheld");
    request = X11Request(fake.data(), fake.size(), false, table, true);
    ok &= Check(request.second == L";type=KeyPress;root=0x2a;x=100;y=200;detail=38", "XTEST FakeInput: the key with --log-real-input");
    Bytes shm(32);
    shm[0] = 130, shm[1] = 4;
    Le32(shm, 4, 0x400001);
    Le16(shm, 8, 10), Le16(shm, 10, 20), Le16(shm, 12, 640), Le16(shm, 14, 480);
    request = X11Request(shm.data(), shm.size(), false, table, false);
    ok &= Check(request.first == L"MIT-SHM.GetImage" && request.second == L";drawable=0x400001;x=10;y=20;width=640;height=480",
                "MIT-SHM GetImage: the drawable and area");
    Bytes ids(24);
    ids[0] = 140, ids[1] = 4;
    Le32(ids, 4, 2), Le32(ids, 8, 0x400000), Le32(ids, 16, 0x600000);
    request = X11Request(ids.data(), ids.size(), false, table, false);
    ok &= Check(request.second == L";specs=2;clients=0x400000,0x600000", "X-Resource QueryClientIds: the clients");
    Bytes pixmap(12);
    pixmap[0] = 142, pixmap[1] = 6;
    Le32(pixmap, 4, 0x200007), Le32(pixmap, 8, 0x200008);
    request = X11Request(pixmap.data(), pixmap.size(), false, table, false);
    ok &= Check(request.first == L"Composite.NameWindowPixmap" && request.second == L";window=0x200007;pixmap=0x200008",
                "Composite NameWindowPixmap: the window");
    /* Field offsets: GrabKey's key at 10 (byte 1 is owner-events), XIWarpPointer's destination at 24 and 28,
     * XIPassiveGrabDevice's window after its time, Composite.CreateRegionFromBorderClip's window after its region. */
    Bytes grab = X11(33, 1, 16);
    Le32(grab, 4, 0x400001), Le16(grab, 8, 0x8000), grab[10] = 38;
    request = X11Request(grab.data(), grab.size(), false, table, false);
    ok &= Check(request.first == L"GrabKey" && request.second == L";window=0x400001;modifiers=0x8000;key=38", "GrabKey: its key and modifiers");
    Bytes warp = X11(131, 41, 36);
    Le32(warp, 8, 0x400001), Le32(warp, 24, 100u << 16), Le32(warp, 28, 200u << 16);
    Le16(warp, 20, 7), Le16(warp, 22, 9);   /* src_width, src_height */
    request = X11Request(warp.data(), warp.size(), false, table, false);
    ok &= Check(request.second == L";window=0x400001;x=100;y=200", "XIWarpPointer: its destination");
    Bytes passive = X11(131, 54, 32);
    Le32(passive, 4, 0x12345678), Le32(passive, 8, 0x400001);
    request = X11Request(passive.data(), passive.size(), false, table, false);
    ok &= Check(request.first == L"XInputExtension.XIPassiveGrabDevice" && request.second == L";window=0x400001",
                "XIPassiveGrabDevice: its window, not its time");
    Bytes clip = X11(142, 5, 12);
    Le32(clip, 4, 0x600001), Le32(clip, 8, 0x400001);
    request = X11Request(clip.data(), clip.size(), false, table, false);
    ok &= Check(request.first == L"Composite.CreateRegionFromBorderClip" && request.second == L";region=0x600001;window=0x400001",
                "Composite.CreateRegionFromBorderClip: its region and window");
    Bytes send = X11(25, 1, 44);
    Le32(send, 4, 0x500001);
    send[12] = 2, send[13] = 38;   /* a KeyPress */
    request = X11Request(send.data(), send.size(), false, table, false);
    ok &= Check(request.first == L"SendEvent" && request.second == L";destination=0x500001;event=KeyPress;input=withheld",
                "SendEvent: the event, its key withheld");
    ok &= Check(X11ReceivedName(1u << 24, table) == L"reply" && X11ReceivedName(3u << 16 | 20u << 8, table) == L"error:Window:GetProperty" &&
                    X11ReceivedName(6u << 24, table) == L"event:MotionNotify" &&
                    X11ReceivedName(33u << 24 | MM_UNIX_X11_SENT, table) == L"sent_event:ClientMessage" &&
                    X11ReceivedName(35u << 24 | 131u << 8 | 13, table) == L"event:XInputExtension.RawKeyPress" &&
                    X11ReceivedName(67u << 24, table) == L"event:XInputExtension.event1" &&
                    X11ReceivedName(130u << 16 | 131u << 8 | 47, table) == L"error:XInputExtension.error1:XInputExtension.XIQueryVersion",
                "X11 received names: reply, errors with their request, events, XI2's, an extension's");
    ok &= Check(PulseCommandName(5) == L"CREATE_RECORD_STREAM" && PulseCommandName(MM_UNIX_PULSE_OTHER) == L"other" &&
                    PulseCommandName(9999) == L"COMMAND_9999",
                "PulseAudio command names");

    /* D-Bus: a sent Hello after SASL; received: the server's SASL, a method return, an error and a signal. */
    std::string text = std::string(1, '\0') + "AUTH EXTERNAL 31303030\r\nBEGIN\r\n";
    Bytes sentBus(text.begin(), text.end());
    const Bytes hello = Dbus(1, 1, {{1, 'o', "/org/freedesktop/DBus"}, {6, 's', "org.freedesktop.DBus"},
                                    {2, 's', "org.freedesktop.DBus"}, {3, 's', "Hello"}});
    sentBus.insert(sentBus.end(), hello.begin(), hello.end());
    auto messages = DbusMessages(sentBus.data(), sentBus.size());
    ok &= Check(messages.size() == 1 && messages[0].first == L"org.freedesktop.DBus.Hello", "D-Bus: SASL skipped, Hello named");
    text = "OK 0123456789abcdef\r\nAGREE_UNIX_FD\r\n";
    Bytes received(text.begin(), text.end());
    for (const Bytes& m : {Dbus(2, 7, {{5, 'u', "1"}, {7, 's', ":1.5"}}, 16),
                           Dbus(3, 8, {{4, 's', "org.freedesktop.DBus.Error.AccessDenied"}, {5, 'u', "2"}}),
                           Dbus(4, 9, {{1, 'o', "/org/bluez"}, {2, 's', "org.freedesktop.DBus.Properties"},
                                       {3, 's', "PropertiesChanged"}, {7, 's', ":1.3"}})})
        received.insert(received.end(), m.begin(), m.end());
    messages = DbusMessages(received.data(), received.size());
    ok &= Check(messages.size() == 3 && messages[0].first == L"method_return" && messages[0].second == L";reply_serial=1;sender=:1.5" &&
                    messages[1].first == L"error:org.freedesktop.DBus.Error.AccessDenied" && messages[1].second == L";reply_serial=2" &&
                    messages[2].first == L"org.freedesktop.DBus.Properties.PropertiesChanged" &&
                    messages[2].second == L";message=signal;path=/org/bluez;serial=9;sender=:1.3",
                "D-Bus: a method return, an error and a signal received");
    messages = DbusMessages(received.data(), received.size() - 40);   /* the signal cut: read as far as it goes */
    ok &= Check(messages.size() >= 2 && messages[0].first == L"method_return", "D-Bus: a cut message stops the parse, not the rest");

    /* The display's table: asked of a fake X server; a server that refuses the connection leaves none. */
    X11Extensions asked;
    std::string why;
    ok &= Check(Query(true, asked, why) && why == "ok" && asked.size() == 3 && asked[0].name == "XTEST" && asked[0].major == 132 &&
                    asked[1].name == "Present" && asked[1].major == 148,
                "X11QueryExtensions: the present extensions with their majors");
    bool found = false;
    for (const X11Extension& e : asked) found |= e.name == "XInputExtension" && e.major == 131 && e.firstEvent == 66 && e.firstError == 129;
    ok &= Check(found, "X11QueryExtensions: XInputExtension's first event and error");
    ok &= Check(!Query(false, asked, why) && asked.empty() && why == "refused:No au", "X11QueryExtensions: a refused setup");
    const std::string cookie = "0123456789abcdef";
    ok &= Check(!Query(true, asked, why, cookie) && why == "refused:No au" && Query(true, asked, why, cookie, cookie) &&
                    asked.size() == 3,
                "X11QueryExtensions: a display that wants a cookie, refused without it and asked with it");
    /* An Xauthority file: a cookie of display 0, then of display 5 (local), then a wildcard one. */
    auto entry = [](unsigned family, const std::string& number, const std::string& data) {
        std::string out = {char(family >> 8), char(family)};
        for (const std::string& field : {std::string("host"), number, std::string("MIT-MAGIC-COOKIE-1"), data})
            out += std::string{char(field.size() >> 8), char(field.size())} + field;
        return out;
    };
    const std::string xauthority = entry(256, "0", "zero") + entry(256, "5", cookie) + entry(65535, "", "wild");
    ok &= Check(X11Cookie(xauthority, "5") == cookie && X11Cookie(xauthority, "0") == "zero" && X11Cookie(xauthority, "7") == "wild" &&
                    X11Cookie(entry(0, "7", "inet"), "7").empty() && X11Cookie("\x01", "5").empty(),
                "X11Cookie: a display's local or wildcard cookie");
    ok &= Check(!X11QueryExtensions("unix:@msmon-unix-test-nobody", asked, why, 200) && why.rfind("connect_failed", 0) == 0,
                "X11QueryExtensions: no server");
    /* A peer that trickles its setup (a byte every 100 ms of 0xffff * 4) is left at the deadline, not after hours. */
    const auto started = std::chrono::steady_clock::now();
    ok &= Check(!Query(TrickleServer, asked, why, {}, {}, 400) && why == "setup_cut" &&
                    std::chrono::steady_clock::now() - started < std::chrono::milliseconds(1500),
                "X11QueryExtensions: one deadline for the whole query, however the peer trickles");
    /* A server the agent must not ask (a tracked process's listener, by SO_PEERCRED): left before anything is sent. */
    pid_t seen = 0;
    ok &= Check(!Query([](int listener) { FakeServer(listener, true, {}); }, asked, why, cookie,
                       [&](pid_t pid) { seen = pid; return pid == getpid(); }) &&
                    why == "skipped:tracked_server" && seen == getpid(),
                "X11QueryExtensions: a tracked server is skipped by its SO_PEERCRED pid");
    /* The Xauthority file a client names: read only as a regular file its uid owns, of at most 64 KiB. */
    char directory[] = "/tmp/msmon-unix-test-XXXXXX";
    if (mkdtemp(directory) != nullptr) {
        const std::string base = directory, regular = base + "/xauthority", fifo = base + "/fifo", link = base + "/link";
        std::ofstream(regular, std::ios::binary) << xauthority;
        const bool made = mkfifo(fifo.c_str(), 0600) == 0 && symlink(regular.c_str(), link.c_str()) == 0;
        ok &= Check(made && X11AuthorityFile(regular, getuid()) == xauthority && X11AuthorityFile(regular, getuid() + 1).empty() &&
                        X11AuthorityFile(fifo, getuid()).empty() && X11AuthorityFile(link, getuid()).empty() &&
                        X11AuthorityFile("/dev/zero", 0).empty() && X11AuthorityFile(base + "/none", getuid()).empty(),
                    "X11AuthorityFile: the client's own regular file only (no FIFO, device, symlink or other owner)");
        std::ofstream(regular, std::ios::binary) << std::string(65537, 'x');
        ok &= Check(X11AuthorityFile(regular, getuid()).empty(), "X11AuthorityFile: nothing over 64 KiB");
        for (const std::string& path : {regular, fifo, link}) unlink(path.c_str());
        rmdir(directory);
    }

    /* A kernel summary's record. */
    mm_agg total{5, 0, 180, 1000000000, 1500000000, ~0ull, 0};
    LinuxRecord record = UnixAggSummary(MM_COUNT_UNIX | MM_UNIX_X11, 77ull << 32 | (132 << 8 | 2), L"x11",
                                        L"unix:@/tmp/.X11-unix/X5", table, total);
    ok &= Check(record.sensor == MSMON_SENSOR_LINUX_EBPF_IPC && record.type == MsMonEtwRpc && record.text == L"unix:@/tmp/.X11-unix/X5" &&
                    record.value0 == 180 && record.value1 == 5 &&
                    record.detail == L"repeats_tail;syscall=unix_service;aggregate=kernel;interface=x11;operation=XTEST.FakeInput;"
                                     L"direction=sent;socket=77;repeats_before=5;repeat_bytes=180;repeat_span_us=500000;errors=0",
                "a kernel summary of an X11 op");
    record = UnixAggSummary(MM_COUNT_UNIX | MM_UNIX_PULSE | MM_UNIX_RX, 9ull << 32 | 2, L"pulse", L"unix:/run/user/1000/pulse/native",
                            {}, total);
    ok &= Check(record.detail.find(L";interface=pulse;operation=REPLY;direction=received;socket=9;") != std::wstring::npos,
                "a kernel summary of a PulseAudio reply");
    record = UnixAggSummary(MM_COUNT_UNIX | MM_UNIX_X11, 9ull << 32 | MM_UNIX_OP_UNPARSED, L"x11", L"socket:[9]", {}, total);
    ok &= Check(record.detail.find(L";operation=unparsed;") != std::wstring::npos, "a kernel summary of unparsed bytes");
    record = UnixAggSummary(MM_COUNT_UNIX | MM_UNIX_DBUS | MM_UNIX_RX, 9ull << 32 | 4, L"dbus_system", L"unix:/run/dbus/system_bus_socket",
                            {}, total);
    ok &= Check(record.detail.find(L";interface=dbus_system;operation=signal;direction=received;") != std::wstring::npos &&
                    UnixAggSummary(MM_COUNT_UNIX | MM_UNIX_DBUS, 9ull << 32 | MM_UNIX_DBUS_SASL, L"dbus_system", L"x", {}, total)
                            .detail.find(L";operation=sasl;direction=sent;") != std::wstring::npos,
                "kernel summaries of D-Bus messages past the heads (by type) and of the SASL calls");

    /* Window owners (ws_bpf.h): a handle's low word is the index, as wineserver's handle_to_entry takes it; its high word
     * the generation, 0 and 0xffff matching any; no window below the first handle. */
    const mm_ws_window owner{4242, 4243, 1, 0}, none{};
    ok &= Check(mm_ws_window_index(0x00010020) == 0x10 && mm_ws_window_index(0x0020) == 0x10 &&
                    mm_ws_window_index(0xffff0020) == 0x10 && mm_ws_window_index(0x00010021) == 0x10 &&
                    mm_ws_window_index(0xffffffffffff0020ull) == 0x10,
                "a window's index from its handle in any form");
    ok &= Check(mm_ws_window_index(0) == 0 && mm_ws_window_index(0x1f) == 0 && mm_ws_window_index(0xffff) == 0x7fff &&
                    mm_ws_window_index(0x7ffe) < MM_WS_WINDOWS,
                "no window below the first user handle; every index in the map");
    ok &= Check(mm_ws_window_match(&owner, 0x00010020) && mm_ws_window_match(&owner, 0x0020) &&
                    mm_ws_window_match(&owner, 0xffff0020) && mm_ws_window_match(&owner, 0xffffffffffff0020ull) &&
                    !mm_ws_window_match(&owner, 0x00020020) && !mm_ws_window_match(&none, 0x0020),
                "a window's owner by full handle, low word, 0xffff high word; not another generation's");

    if (!ok) return 1;
    std::cout << "linux unix test: PASS\n";
    return 0;
}
