#pragma once
/* TCP lifecycle (tcp upgrade, docs/LINUX.md "TCP lifecycle"): shared by tcp.bpf.h and bpf_tcp.inc. */

/* mm_tcp_event.what */
#define MM_TCP_STATE 1     /* inet_sock_set_state: oldstate -> newstate */
#define MM_TCP_ACCEPT 2    /* a tracked process accepted it (lsm/sock_graft); newstate = its state */
#define MM_TCP_RST_IN 3    /* tcp_receive_reset; newstate = the state the RST arrived in */
#define MM_TCP_RST_OUT 4   /* tcp_send_reset; reason = enum sk_rst_reason */
#define MM_TCP_RETRANS 5   /* tcp_retransmit_skb; reason = its err */

/* MM_TCP record (128 bytes). Every field comes from the socket or its mm_socks tag, never from
 * current: most of these run in softirq context. */
struct mm_tcp_event {
    __u32 kind;          /* MM_TCP */
    __u32 what;          /* MM_TCP_* */
    __u32 tgid;          /* mm_sock.maker: the record's process (wineserver under Wine) */
    __u32 sk_err;        /* sk->sk_err, positive errno, 0 = none */
    __u64 start_ns;      /* mm_sock.maker_start */
    __u64 ts_ns;         /* CLOCK_BOOTTIME */
    __u64 cookie;        /* socket cookie (etw_tcp value1, the pcapng comments' cookie) */
    __u64 ino;           /* mm_sock.ino: socket inode, socket:[ino] */
    __u64 bytes_acked;
    __u64 bytes_received;
    __u32 retransmits;   /* icsk_retransmits: RTOs since snd_una last advanced; the write-queue purge
                          * before a timeout's CLOSE zeroes packets_out but keeps this */
    __u32 total_retrans;
    __u32 srtt_us;       /* tcp_sock.srtt_us: smoothed RTT << 3 */
    __s32 reason;        /* MM_TCP_RST_OUT: enum sk_rst_reason; MM_TCP_RETRANS: err */
    __u16 family;        /* AF_INET or AF_INET6 */
    __u16 sport;         /* host order */
    __u16 dport;         /* network order */
    __u8 oldstate;       /* TCP_* */
    __u8 newstate;
    __u8 shutdown;       /* sk_shutdown: 1 receive, 2 send */
    __u8 orphan;         /* 1: the socket has no struct socket (its last fd was closed) */
    __u8 pad[2];
    __u32 owner;         /* mm_sock.owner: the first tracked non-wineserver user (the game), 0 = none */
    __u8 saddr[16];      /* network order; IPv4 in the first 4 bytes */
    __u8 daddr[16];
};

#ifdef __cplusplus
#define MM_TCP_ASSERT static_assert
#else
#define MM_TCP_ASSERT _Static_assert
#endif
MM_TCP_ASSERT(sizeof(struct mm_tcp_event) == 128, "mm_tcp_event size");
MM_TCP_ASSERT(__builtin_offsetof(struct mm_tcp_event, family) == 80, "mm_tcp_event.family");
MM_TCP_ASSERT(__builtin_offsetof(struct mm_tcp_event, owner) == 92, "mm_tcp_event.owner");
MM_TCP_ASSERT(__builtin_offsetof(struct mm_tcp_event, saddr) == 96, "mm_tcp_event.saddr");
