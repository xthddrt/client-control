#pragma once
/* Packet capture (packets.cpp, docs/LINUX.md "Packet capture"). agent.cpp names the first pcapng part
 * (PacketsConfigure, session.h; empty: off); bpf.cpp loads the mm_skb_* programs when PacketsPath() is
 * set and reports with PacketsStart, then feeds the kernel's records to PacketsAdd on the BPF thread;
 * LinuxSession::Start logs PacketsNote(); agent.cpp chains PacketsTakeNotes() as coverage records. */
#include "session.h"
#include "bpf/monitor_bpf.h"

const std::wstring& PacketsPath();
/* Error 0 opens the first part; otherwise capture stays off and PacketsNote names Detail. */
bool PacketsStart(int error, const std::wstring& detail);
/* One kernel record: Data holds packet.cap_len bytes; FileTime is its capture time. */
void PacketsAdd(const mm_pkt& packet, const unsigned char* data, uint64_t fileTime);
/* The kernel's running count of packets it could not queue (pkt_drops). */
void PacketsKernelDrops(uint64_t total);
/* Closer closed an fd of the socket with this inode: when Closer is its maker (wineserver for held
 * packets), its held (unattributed) packets are dropped, counted, at the next PacketsPolled (its last
 * packets may still be in the pkts ring). Ignored while capture is not running. */
void PacketsSocketClosed(uint64_t ino, DWORD closer);
/* BPF thread, each poll: true once the final drain (PacketsTakeNotes(true)) waits for capture to stop. */
bool PacketsStopping();
/* BPF thread, after reading the pkts ring to its end: closes seen so far take effect; Detached: the
 * mm_skb_* programs are gone, so the final drain can write the totals. */
void PacketsPolled(bool detached);
