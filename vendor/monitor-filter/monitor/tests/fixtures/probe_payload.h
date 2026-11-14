/* Payload upgrade probe actions (tests/ebpf_checks/check_payload.py checks the log). Known bytes cross a
 * loopback TCP pair (also over ::1, with a ::1 UDP datagram) (send/recv after a 1-byte MSG_PEEK, writev/read, one 20000-byte send/recv, and
 * sendmsg/recvmsg without a name, Wine's path) and a UDP pair (sendmsg/recvmsg, a two-message
 * sendmmsg/recvmmsg, and a 20 x 60000-byte sendmmsg past the 1 MiB capture limit), a NETLINK_ROUTE
 * link dump is read with recvmsg, one DNS query goes to the systemd-resolved stub 127.0.0.53:53
 * (no reply is read), and getaddrinfo resolves through glibc as the game does: the log must hold the exact
 * bytes. Then requests to three desktop services over AF_UNIX (named, never captured). Exit codes 30-39, 50. */
#include <linux/netlink.h>
#include <stddef.h>
#include <sys/un.h>
#include <netdb.h>
#include <linux/rtnetlink.h>

static int probe_payload(void)
{
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t length = sizeof(address);
    if (listener < 0 || bind(listener, (struct sockaddr*)&address, sizeof(address)) != 0 || listen(listener, 1) != 0 ||
        getsockname(listener, (struct sockaddr*)&address, &length) != 0) return 30;
    int client = socket(AF_INET, SOCK_STREAM, 0);
    if (client < 0 || connect(client, (struct sockaddr*)&address, sizeof(address)) != 0) return 30;
    int accepted = accept(listener, NULL, NULL);
    if (accepted < 0) return 30;

    static const char ping[] = "msmon-payload-ping-0123456789";
    char got[64];
    if (send(client, ping, sizeof(ping) - 1, 0) != (ssize_t)sizeof(ping) - 1 ||
        recv(accepted, got, 1, MSG_PEEK) != 1 ||
        recv(accepted, got, sizeof(ping) - 1, MSG_WAITALL) != (ssize_t)sizeof(ping) - 1) return 31;
    struct iovec pong[2] = {{(void*)"msmon-payload-", 14}, {(void*)"pong", 4}};
    if (writev(accepted, pong, 2) != 18 || read(client, got, 18) != 18) return 32;
    static char big[20000], bigIn[20000];
    for (int index = 0; index < (int)sizeof(big); index++) big[index] = (char)(index % 251);
    if (send(client, big, sizeof(big), 0) != (ssize_t)sizeof(big) ||
        recv(accepted, bigIn, sizeof(bigIn), MSG_WAITALL) != (ssize_t)sizeof(bigIn) ||
        memcmp(big, bigIn, sizeof(big)) != 0) return 33;
    struct iovec tcpOut = {(void*)"msmon-payload-tcpmsg", 20}, tcpIn = {got, 20};
    struct msghdr tcpMessage;
    memset(&tcpMessage, 0, sizeof(tcpMessage));
    tcpMessage.msg_iov = &tcpOut;
    tcpMessage.msg_iovlen = 1;
    if (sendmsg(client, &tcpMessage, 0) != 20) return 38;
    tcpMessage.msg_iov = &tcpIn;
    if (recvmsg(accepted, &tcpMessage, MSG_WAITALL) != 20 || memcmp(got, "msmon-payload-tcpmsg", 20) != 0) return 38;
    close(accepted);
    close(client);
    close(listener);

    /* The same over ::1: the socket identity's AF_INET6 fields (endpoints=[::1]:port). */
    struct sockaddr_in6 v6, v6From;
    memset(&v6, 0, sizeof(v6));
    v6.sin6_family = AF_INET6;
    v6.sin6_addr = in6addr_loopback;
    socklen_t v6Length = sizeof(v6), v6FromLength = sizeof(v6From);
    listener = socket(AF_INET6, SOCK_STREAM, 0);
    client = socket(AF_INET6, SOCK_STREAM, 0);
    if (listener < 0 || client < 0 || bind(listener, (struct sockaddr*)&v6, sizeof(v6)) != 0 || listen(listener, 1) != 0 ||
        getsockname(listener, (struct sockaddr*)&v6, &v6Length) != 0 || connect(client, (struct sockaddr*)&v6, sizeof(v6)) != 0)
        return 30;
    accepted = accept(listener, NULL, NULL);
    if (accepted < 0 || send(client, "msmon-payload-v6-tcp", 20, 0) != 20 || recv(accepted, got, 20, MSG_WAITALL) != 20)
        return 31;
    close(accepted);
    close(client);
    close(listener);
    int v6Receiver = socket(AF_INET6, SOCK_DGRAM, 0), v6Sender = socket(AF_INET6, SOCK_DGRAM, 0);
    v6.sin6_port = 0;
    v6Length = sizeof(v6);
    if (v6Receiver < 0 || v6Sender < 0 || bind(v6Receiver, (struct sockaddr*)&v6, sizeof(v6)) != 0 ||
        getsockname(v6Receiver, (struct sockaddr*)&v6, &v6Length) != 0 ||
        sendto(v6Sender, "msmon-payload-v6-udp", 20, 0, (struct sockaddr*)&v6, sizeof(v6)) != 20 ||
        recvfrom(v6Receiver, got, sizeof(got), 0, (struct sockaddr*)&v6From, &v6FromLength) != 20) return 35;
    close(v6Sender);
    close(v6Receiver);

    int receiver = socket(AF_INET, SOCK_DGRAM, 0);
    int sender = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in udp;
    memset(&udp, 0, sizeof(udp));
    udp.sin_family = AF_INET;
    udp.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t udpLength = sizeof(udp);
    if (receiver < 0 || sender < 0 || bind(receiver, (struct sockaddr*)&udp, sizeof(udp)) != 0 ||
        getsockname(receiver, (struct sockaddr*)&udp, &udpLength) != 0) return 34;
    char udpBytes[] = "msmon-payload-datagram", udpIn[64];
    struct iovec datagram = {udpBytes, sizeof(udpBytes) - 1};
    struct msghdr message;
    memset(&message, 0, sizeof(message));
    message.msg_name = &udp;
    message.msg_namelen = sizeof(udp);
    message.msg_iov = &datagram;
    message.msg_iovlen = 1;
    if (sendmsg(sender, &message, 0) != (ssize_t)sizeof(udpBytes) - 1) return 35;
    struct sockaddr_in from;
    struct iovec inbound = {udpIn, sizeof(udpIn)};
    memset(&message, 0, sizeof(message));
    message.msg_name = &from;
    message.msg_namelen = sizeof(from);
    message.msg_iov = &inbound;
    message.msg_iovlen = 1;
    if (recvmsg(receiver, &message, 0) != (ssize_t)sizeof(udpBytes) - 1) return 35;

    struct iovec parts[2] = {{(void*)"msmon-payload-mmsg-a", 20}, {(void*)"msmon-payload-mmsg-bb", 21}};
    char in0[32], in1[32];
    struct iovec ins[2] = {{in0, sizeof(in0)}, {in1, sizeof(in1)}};
    struct mmsghdr batch[2];
    memset(batch, 0, sizeof(batch));
    for (int index = 0; index < 2; index++) {
        batch[index].msg_hdr.msg_name = &udp;
        batch[index].msg_hdr.msg_namelen = sizeof(udp);
        batch[index].msg_hdr.msg_iov = &parts[index];
        batch[index].msg_hdr.msg_iovlen = 1;
    }
    if (sendmmsg(sender, batch, 2, 0) != 2) return 36;
    memset(batch, 0, sizeof(batch));
    for (int index = 0; index < 2; index++) {
        batch[index].msg_hdr.msg_iov = &ins[index];
        batch[index].msg_hdr.msg_iovlen = 1;
    }
    if (recvmmsg(receiver, batch, 2, 0, NULL) != 2) return 36;
    /* 20 datagrams of 60000 bytes in one sendmmsg (the receiver drops most; UDP does not block):
     * 17 whole messages fit in the 1 MiB capture, message 17 is partial, 18-19 are msg_missing. */
    static char wide[60000];
    for (int index = 0; index < (int)sizeof(wide); index++) wide[index] = (char)(index % 241);
    struct iovec wideIov = {wide, sizeof(wide)};
    struct mmsghdr wideBatch[20];
    memset(wideBatch, 0, sizeof(wideBatch));
    for (int index = 0; index < 20; index++) {
        wideBatch[index].msg_hdr.msg_name = &udp;
        wideBatch[index].msg_hdr.msg_namelen = sizeof(udp);
        wideBatch[index].msg_hdr.msg_iov = &wideIov;
        wideBatch[index].msg_hdr.msg_iovlen = 1;
    }
    if (sendmmsg(sender, wideBatch, 20, 0) != 20) return 36;

    /* A DNS query (id 0x4d53, msmon-probe.example A) to the resolver stub; nothing reads a reply. */
    static const unsigned char query[] = {0x4d, 0x53, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
                                          11, 'm', 's', 'm', 'o', 'n', '-', 'p', 'r', 'o', 'b', 'e',
                                          7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0, 0, 1, 0, 1};
    struct sockaddr_in stub;
    memset(&stub, 0, sizeof(stub));
    stub.sin_family = AF_INET;
    stub.sin_port = htons(53);
    stub.sin_addr.s_addr = htonl(0x7f000035);
    if (sendto(sender, query, sizeof(query), 0, (struct sockaddr*)&stub, sizeof(stub)) != (ssize_t)sizeof(query)) return 37;
    /* The game's lookup path: glibc res_send connects a UDP socket to the stub, sends A + AAAA in one sendmmsg
     * (no address) and reads each answer with recvfrom. The answer (NXDOMAIN, SERVFAIL offline) is not
     * checked; ai_flags 0 (no AI_ADDRCONFIG) keeps the AAAA query; the final dot skips the search list. */
    struct addrinfo hints, *found = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    if (getaddrinfo("msmon-probe.example.", NULL, &hints, &found) == 0) freeaddrinfo(found);
    close(sender);
    close(receiver);

    /* A NETLINK_ROUTE link dump (interfaces and MAC addresses), its first reply read with recvmsg. */
    int netlink = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    struct {
        struct nlmsghdr header;
        struct ifinfomsg link;
    } dump;
    memset(&dump, 0, sizeof(dump));
    dump.header.nlmsg_len = sizeof(dump);
    dump.header.nlmsg_type = RTM_GETLINK;
    dump.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    dump.header.nlmsg_seq = 1;
    dump.link.ifi_family = AF_UNSPEC;
    static char reply[65536];
    struct iovec replyIov = {reply, sizeof(reply)};
    struct msghdr replyMessage;
    memset(&replyMessage, 0, sizeof(replyMessage));
    replyMessage.msg_iov = &replyIov;
    replyMessage.msg_iovlen = 1;
    if (netlink < 0 || send(netlink, &dump, sizeof(dump), 0) != (ssize_t)sizeof(dump) ||
        recvmsg(netlink, &replyMessage, 0) < (ssize_t)sizeof(struct nlmsghdr)) return 39;
    close(netlink);

    /* Desktop services over AF_UNIX, named by their socket (abstract, so nothing is left behind): a PulseAudio
     * GET_CLIENT_INFO_LIST (sendmsg), a D-Bus ListNames call (sendmsg, header and body in two iovecs) and X11
     * QueryExtension("RECORD") + GetProperty (writev). Exit code 50. */
    static const unsigned char pulse[] = {0, 0, 0, 10, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                          'L', 0, 0, 0, 28, 'L', 0, 0, 0, 7};
    static const unsigned char bus[] = {'l', 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 82, 0, 0, 0,
                                        1, 1, 'o', 0, 21, 0, 0, 0, '/', 'o', 'r', 'g', '/', 'f', 'r', 'e', 'e', 'd', 'e', 's',
                                        'k', 't', 'o', 'p', '/', 'D', 'B', 'u', 's', 0, 0, 0,
                                        6, 1, 's', 0, 20, 0, 0, 0, 'o', 'r', 'g', '.', 'f', 'r', 'e', 'e', 'd', 'e', 's', 'k',
                                        't', 'o', 'p', '.', 'D', 'B', 'u', 's', 0, 0, 0, 0,
                                        3, 1, 's', 0, 9, 0, 0, 0, 'L', 'i', 's', 't', 'N', 'a', 'm', 'e', 's', 0};
    static const unsigned char x11[] = {98, 0, 4, 0, 6, 0, 0, 0, 'R', 'E', 'C', 'O', 'R', 'D', 0, 0,
                                        20, 0, 6, 0, 1, 0, 0, 0, 39, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0};
    static const char* const names[] = {"msmon-probe/pulse/native", "msmon-probe/bus", "msmon-probe/.X11-unix/X9"};
    for (int index = 0; index < 3; index++) {
        struct sockaddr_un unixAddress;
        memset(&unixAddress, 0, sizeof(unixAddress));
        unixAddress.sun_family = AF_UNIX;
        strcpy(unixAddress.sun_path + 1, names[index]);   /* sun_path[0] = 0: abstract */
        const socklen_t unixLength = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + strlen(names[index]));
        int server = socket(AF_UNIX, SOCK_STREAM, 0), peer = socket(AF_UNIX, SOCK_STREAM, 0);
        if (server < 0 || peer < 0 || bind(server, (struct sockaddr*)&unixAddress, unixLength) != 0 || listen(server, 1) != 0 ||
            connect(peer, (struct sockaddr*)&unixAddress, unixLength) != 0) return 50;
        struct iovec pieces[2];
        struct msghdr sent;
        memset(&sent, 0, sizeof(sent));
        sent.msg_iov = pieces;
        ssize_t want = 0, done = 0;
        if (index == 0) {
            pieces[0] = (struct iovec){(void*)pulse, sizeof(pulse)};
            sent.msg_iovlen = 1;
            want = sizeof(pulse);
            done = sendmsg(peer, &sent, 0);
        } else if (index == 1) {
            pieces[0] = (struct iovec){(void*)bus, sizeof(bus)};
            pieces[1] = (struct iovec){(void*)"body", 4};
            sent.msg_iovlen = 2;
            want = sizeof(bus) + 4;
            done = sendmsg(peer, &sent, 0);
        } else {
            pieces[0] = (struct iovec){(void*)x11, sizeof(x11)};
            want = sizeof(x11);
            done = writev(peer, pieces, 1);
        }
        close(peer);
        close(server);
        if (done != want) return 50;
    }
    return 0;
}
