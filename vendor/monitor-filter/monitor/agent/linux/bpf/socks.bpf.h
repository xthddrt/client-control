/*
 * Socket tags (foundation; shared by the tcp and packets upgrades, owned by neither: change it only
 * through the plan). Every INET/INET6 socket a tracked process creates, connects, sends or receives
 * on gets one mm_sock in socket-local storage: freed with the socket, and BPF_F_CLONE copies a
 * listener's tag to each socket accept() will return. Readers (tcp.bpf.h in softirq, pkt.bpf.h in
 * cgroup_skb) look the tag up without creating one, so untagged sockets cost one lookup.
 *
 * Under Wine the maker is wineserver (it does socket()/connect()/accept() for its clients) and the
 * owner is the game process that then sends and receives on the socket itself.
 */

struct mm_sock {
    __u64 cookie;        /* socket these fields belong to; differs = cloned from a listener (own_tag) */
    __u64 ino;           /* socket inode, 0 until a hook sees sock->file */
    __u64 maker_start;   /* maker's group-leader start_boottime (mm_event.start_ns units) */
    __u64 pending;       /* pkt.bpf.h: bytes captured while owner == 0 */
    __u32 maker;         /* first tracked process that used it (wineserver under Wine) */
    __u32 owner;         /* first tracked process other than wineserver that used it; 0 = none yet */
    __u32 server;        /* tracked wineserver that used it; 0 = none */
    __u32 skipped;       /* pkt.bpf.h: packets not captured because pending reached its cap */
};

struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_CLONE);
    __type(key, int);
    __type(value, struct mm_sock);
} mm_socks SEC(".maps");

/* A tag cloned from a listener still carries the listener's cookie: this socket's own fields start now
 * (maker/owner/server stay: the accepting process is the listener's). */
static __always_inline void own_tag(struct mm_sock* s, __u64 cookie)
{
    if (s->cookie == cookie) return;
    s->cookie = cookie;
    s->ino = 0;
    s->pending = 0;
    s->skipped = 0;
}

/* comm is the basename exec set ("wineserver", also "wineserver64"); 10 constant-index compares. */
static __always_inline int wineserver_comm(void)
{
    char comm[16];
    if (bpf_get_current_comm(comm, sizeof(comm))) return 0;
    return comm[0] == 'w' && comm[1] == 'i' && comm[2] == 'n' && comm[3] == 'e' && comm[4] == 's' &&
           comm[5] == 'e' && comm[6] == 'r' && comm[7] == 'v' && comm[8] == 'e' && comm[9] == 'r';
}

/* shortcut: Wine's IcmpSendEcho runs in winedevice.exe (nsiproxy.sys opens the ICMP socket there), an
 * untracked process, so the client's pings are never tagged or captured; bring the prefix's winedevice.exe
 * into scope like its wineserver (WINEPREFIX match in the /proc rescan) if pings matter: its socket is then
 * tagged with owner=winedevice; add the ICMP-echo code to ws_cfg.ioctl_codes to join it to the game's ioctl. */
/* Tags sk (of sock) when current is tracked; returns the tag or 0. Called before the call sends
 * anything (connect's SYN leaves inside connect()). Verifier-safe: no loops; sk is a trusted LSM
 * argument or a direct BTF load of sock->sk, which bpf_sk_storage_get and bpf_get_socket_cookie
 * accept (a BPF_CORE_READ result would be a scalar they refuse); sock->file is only probe-read into
 * scalars; all stores are at constant offsets of a 48-byte map value. */
static __always_inline struct mm_sock* tag_sk(struct sock* sk, struct socket* sock)
{
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct mm_tracked* tracking = bpf_map_lookup_elem(&tracked, &tgid);
    if (!sk || !tracking || (tracking->flags & MM_TRACK_NATIVE)) return 0;   /* a native helper's (a browser's): not captured */
    __u16 family = sk->__sk_common.skc_family;
    if (family != AF_INET && family != AF_INET6) return 0;
    struct mm_sock* s = bpf_sk_storage_get(&mm_socks, sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
    if (!s) return 0;
    own_tag(s, bpf_get_socket_cookie(sk));
    if (s->owner && s->ino) return s;   /* the hot path: a socket the game keeps using */
    __u64 ino = BPF_CORE_READ(sock, file, f_inode, i_ino);
    if (ino) s->ino = ino;
    if (!s->maker) {
        s->maker = tgid;
        s->maker_start = BPF_CORE_READ(bpf_get_current_task_btf(), group_leader, start_boottime);
    }
    if (s->owner) return s;
    if (wineserver_comm()) s->server = tgid;
    else s->owner = tgid;
    return s;
}

static __always_inline void tag_socket(struct socket* sock)
{
    if (sock) tag_sk(sock->sk, sock);
}

/* Tagging never depends on another program's verdict (msmon observes; kfilter decides): a call kfilter
 * refuses is tagged too, so its socket stays attributed. Attach order: BPF LSM programs of one hook run in
 * turn and the first nonzero return skips the rest, so when kfilter's program runs first and refuses, these
 * do not run at all; the socket was tagged at socket_post_create already, and the refused call itself is
 * recorded with its errno by mm_sys_exit. Each returns ret unchanged (0 whenever it runs). */
SEC("lsm/socket_post_create")
int BPF_PROG(mm_sock_create, struct socket* sock, int family, int type, int protocol, int kern, int ret)
{
    if (!kern) tag_socket(sock);
    return ret;
}

SEC("lsm/socket_connect")
int BPF_PROG(mm_sock_connect, struct socket* sock, struct sockaddr* address, int addrlen, int ret)
{
    tag_socket(sock);
    return ret;
}

/* Also reached by write/writev/sendmmsg on a socket. */
SEC("lsm/socket_sendmsg")
int BPF_PROG(mm_sock_send, struct socket* sock, struct msghdr* msg, int size, int ret)
{
    tag_socket(sock);
    return ret;
}

/* Also reached by read/readv/recvmmsg on a socket. */
SEC("lsm/socket_recvmsg")
int BPF_PROG(mm_sock_recv, struct socket* sock, struct msghdr* msg, int size, int flags, int ret)
{
    tag_socket(sock);
    return ret;
}
