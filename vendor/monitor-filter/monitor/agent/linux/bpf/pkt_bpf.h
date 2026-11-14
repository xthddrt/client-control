#pragma once
/* Packet capture (packets upgrade, docs/LINUX.md "Packet capture"): packets of sockets tracked processes
 * use (mm_socks tags, socks.bpf.h) go to the pkts ring as struct mm_pkt + the packet bytes. */
#define MM_PKT_MAX 65536        /* bytes kept per packet; len > cap_len marks a cut one */
#define MM_PENDING_MAX 262144   /* bytes captured per socket before a tracked non-wineserver process uses it */
#define MM_PKT_IN 1
#define MM_PKT_OUT 2

/* pkts ring record (48 B, asserted in pkt.bpf.h and packets.cpp); cap_len packet bytes, from the IP
 * header on, follow it. */
struct mm_pkt {
    __u64 ts_ns;     /* CLOCK_BOOTTIME at capture */
    __u64 cookie;    /* bpf_get_socket_cookie: the socket, unique for the boot (= etw_tcp value1) */
    __u64 ino;       /* mm_sock.ino */
    __u32 owner;     /* mm_sock.owner: 0 = only wineserver used the socket so far */
    __u32 server;    /* mm_sock.server */
    __u32 len;       /* skb->len: the whole IP packet (a GSO/GRO super-packet's total) */
    __u32 cap_len;   /* bytes that follow: min(len, MM_PKT_MAX) */
    __u32 skipped;   /* mm_sock.skipped */
    __u16 dir;       /* MM_PKT_IN / MM_PKT_OUT */
    __u16 gso_segs;  /* skb->gso_segs: > 1 for a GSO/GRO super-packet */
};
