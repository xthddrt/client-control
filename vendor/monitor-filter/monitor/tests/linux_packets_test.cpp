/* Drives agent/linux/packets.cpp with made-up kernel packet records; tests/linux_packets_test.py
 * checks the pcapng parts and the notes printed here. Usage: linux_packets_test DIRECTORY */
#include "../agent/linux/packets.h"
#include <cstdio>

static void Packet(uint64_t cookie, uint64_t ino, DWORD owner, DWORD server, uint16_t dir, const std::string& data,
                   uint32_t length = 0, uint16_t gso = 1, uint32_t skipped = 0)
{
    static uint64_t time = 134070000000000000ull;   /* FILETIME, 2025 */
    mm_pkt h{};
    h.cookie = cookie;
    h.ino = ino;
    h.owner = owner;
    h.server = server;
    h.dir = dir;
    h.cap_len = static_cast<uint32_t>(data.size());
    h.len = length != 0 ? length : h.cap_len;
    h.gso_segs = gso;
    h.skipped = skipped;
    PacketsAdd(h, reinterpret_cast<const unsigned char*>(data.data()), time += 10);
}

int main(int argc, char** argv)
{
    if (argc != 2) return 2;
    const DWORD game = static_cast<DWORD>(getpid()), server = static_cast<DWORD>(getppid());
    PacketsConfigure(LinuxWide(argv[1]) + L"/events.pcapng", 4096);
    if (!PacketsStart(0, L"")) return 3;
    const auto note = PacketsNote();
    printf("%s\t%s\n", WideToUtf8(note.first).c_str(), WideToUtf8(note.second).c_str());
    Packet(1, 11, game, 0, MM_PKT_OUT, "game-out-1");
    Packet(2, 22, 0, server, MM_PKT_OUT, "held-syn");
    Packet(2, 22, 0, server, MM_PKT_IN, "held-synack");
    Packet(2, 22, game, server, MM_PKT_OUT, "game-out-2", 0, 1, 3);      /* flushes the two held packets first */
    Packet(3, 33, 0, server, MM_PKT_OUT, "launcher-1");
    Packet(3, 0, 0, server, MM_PKT_OUT, "launcher-2");                    /* a tag whose inode was reset */
    PacketsSocketClosed(33, server);                                       /* the maker's: at the next poll */
    PacketsPolled(false);                                                  /* both dropped, counted */
    Packet(4, 44, 0, server, MM_PKT_OUT, "held-4");
    PacketsSocketClosed(44, game);                                         /* a per-call fd: ends nothing */
    PacketsPolled(false);                                                  /* held-4 is kept */
    Packet(4, 44, game, server, MM_PKT_IN, "game-in-4");                   /* the game used it: flushes held-4 */
    Packet(4, 44, 0, server, MM_PKT_IN, "late-4");                        /* raced the owner store: the game's */
    Packet(1, 11, game, 0, MM_PKT_IN, std::string(5000, 'x'), 70000, 48);  /* cut and GSO; part 0 passes 4096 bytes */
    Packet(1, 11, game, 0, MM_PKT_OUT, "game-out-3");                     /* goes to events.pcapng.1 */
    Packet(7, 77, 0, server, MM_PKT_OUT, std::string(9 << 20, 'a'));      /* evicted by the next: 16 MiB held */
    Packet(8, 88, 0, server, MM_PKT_OUT, std::string(9 << 20, 'b'));      /* dropped at the end */
    Packet(5, 55, 0, server, MM_PKT_OUT, "never-attributed");             /* dropped at the end */
    PacketsKernelDrops(7);
    for (const auto& note : PacketsTakeNotes(true)) printf("%s\t%s\n", WideToUtf8(note.first).c_str(), WideToUtf8(note.second).c_str());
    printf("game=%u server=%u\n", game, server);
    return 0;
}
