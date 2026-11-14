/* Packet capture probe (packets upgrade; tests/ebpf_checks/check_packets.py finds these bytes in the
 * pcapng): a loopback TCP pair exchanging "msmon-pkt-ping\n" and "msmon-pkt-pong\n" (handshake and
 * FINs included), a UDP datagram "msmon-pkt-udp-probe!", the same over ::1 ("msmon-pkt-v6-tcp!",
 * "msmon-pkt-v6-udp!") and Wine's socket shape (probe_packets_wine). Exit codes 60-69. */

/* ::1: one TCP message each way after the handshake and one UDP datagram (the v6 tag and capture). */
static int probe_packets_v6(void)
{
    struct sockaddr_in6 address;
    memset(&address, 0, sizeof(address));
    address.sin6_family = AF_INET6;
    address.sin6_addr = in6addr_loopback;
    socklen_t length = sizeof(address);
    char buffer[32];
    int listener = socket(AF_INET6, SOCK_STREAM, 0), client = socket(AF_INET6, SOCK_STREAM, 0);
    if (listener < 0 || client < 0 || bind(listener, (struct sockaddr*)&address, sizeof(address)) != 0 ||
        listen(listener, 1) != 0 || getsockname(listener, (struct sockaddr*)&address, &length) != 0 ||
        connect(client, (struct sockaddr*)&address, sizeof(address)) != 0) return 68;
    int server = accept(listener, NULL, NULL);
    if (server < 0 || send(client, "msmon-pkt-v6-tcp!", 17, 0) != 17 || recv(server, buffer, 17, MSG_WAITALL) != 17 ||
        send(server, "msmon-pkt-v6-tcp!", 17, 0) != 17 || recv(client, buffer, 17, MSG_WAITALL) != 17) return 68;
    close(server);
    close(client);
    close(listener);
    int receiver = socket(AF_INET6, SOCK_DGRAM, 0), sender = socket(AF_INET6, SOCK_DGRAM, 0);
    address.sin6_port = 0;
    length = sizeof(address);
    if (receiver < 0 || sender < 0 || bind(receiver, (struct sockaddr*)&address, sizeof(address)) != 0 ||
        getsockname(receiver, (struct sockaddr*)&address, &length) != 0 ||
        sendto(sender, "msmon-pkt-v6-udp!", 17, 0, (struct sockaddr*)&address, sizeof(address)) != 17 ||
        recvfrom(receiver, buffer, sizeof(buffer), 0, NULL, NULL) != 17) return 68;
    close(sender);
    close(receiver);
    return 0;
}

/* Wine's shape: a child named "wineserver" makes and connects the socket and hands it over with
 * SCM_RIGHTS (as wineserver does), the server speaks first ("msmon-pkt-wine-hello"), and the probe
 * (the game) reads the hello through its copy and closes that per-call fd; no packet carries the
 * owner until the child closes the socket 600 ms (three agent polls) later. The handshake and the
 * hello must still be in the pcapng, held=1 (check_packets.py). */
static int probe_packets_wine(void)
{
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t length = sizeof(address);
    int listener = socket(AF_INET, SOCK_STREAM, 0), pair[2];
    if (listener < 0 || bind(listener, (struct sockaddr*)&address, sizeof(address)) != 0 || listen(listener, 1) != 0 ||
        getsockname(listener, (struct sockaddr*)&address, &length) != 0 || socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0)
        return 69;
    char control[CMSG_SPACE(sizeof(int))], byte = 's', buffer[32];
    struct iovec one = {&byte, 1};
    struct msghdr message;
    memset(&message, 0, sizeof(message));
    memset(control, 0, sizeof(control));
    message.msg_iov = &one;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = sizeof(control);
    pid_t child = fork();
    if (child < 0) return 69;
    if (child == 0) {
        prctl(PR_SET_NAME, "wineserver", 0, 0, 0);
        int made = socket(AF_INET, SOCK_STREAM, 0);
        if (made < 0 || connect(made, (struct sockaddr*)&address, sizeof(address)) != 0) _exit(1);
        struct cmsghdr* rights = CMSG_FIRSTHDR(&message);
        rights->cmsg_level = SOL_SOCKET;
        rights->cmsg_type = SCM_RIGHTS;
        rights->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(rights), &made, sizeof(int));
        if (sendmsg(pair[1], &message, 0) != 1 || read(pair[1], &byte, 1) != 1) _exit(1);
        close(made);   /* the maker's close ends the socket */
        _exit(0);
    }
    int game = -1, status = 0;
    if (recvmsg(pair[0], &message, 0) == 1 && CMSG_FIRSTHDR(&message) != NULL)
        memcpy(&game, CMSG_DATA(CMSG_FIRSTHDR(&message)), sizeof(int));
    int server = accept(listener, NULL, NULL);
    if (game < 0 || server < 0 || send(server, "msmon-pkt-wine-hello", 20, 0) != 20 ||
        recv(game, buffer, 20, MSG_WAITALL) != 20 || memcmp(buffer, "msmon-pkt-wine-hello", 20) != 0) return 69;
    close(game);   /* a per-call fd: ends nothing */
    usleep(600000);
    if (write(pair[0], "x", 1) != 1 || waitpid(child, &status, 0) != child || status != 0) return 69;
    close(server);
    close(listener);
    close(pair[0]);
    close(pair[1]);
    return 0;
}

static int probe_packets(void)
{
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t length = sizeof(address);
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0 || bind(listener, (struct sockaddr*)&address, sizeof(address)) != 0 || listen(listener, 1) != 0 ||
        getsockname(listener, (struct sockaddr*)&address, &length) != 0) return 60;
    int client = socket(AF_INET, SOCK_STREAM, 0);
    if (client < 0 || connect(client, (struct sockaddr*)&address, sizeof(address)) != 0) return 61;
    int server = accept(listener, NULL, NULL);
    if (server < 0) return 62;
    char buffer[32];
    if (send(client, "msmon-pkt-ping\n", 15, 0) != 15 || recv(server, buffer, 15, MSG_WAITALL) != 15 ||
        memcmp(buffer, "msmon-pkt-ping\n", 15) != 0) return 63;
    if (send(server, "msmon-pkt-pong\n", 15, 0) != 15 || recv(client, buffer, 15, MSG_WAITALL) != 15 ||
        memcmp(buffer, "msmon-pkt-pong\n", 15) != 0) return 64;
    /* The client's FIN, read as end of stream; the server's FIN follows on close. */
    if (shutdown(client, SHUT_WR) != 0 || recv(server, buffer, sizeof(buffer), 0) != 0) return 65;
    close(server);
    close(client);
    close(listener);

    struct sockaddr_in udp;
    memset(&udp, 0, sizeof(udp));
    udp.sin_family = AF_INET;
    udp.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t udpLength = sizeof(udp);
    int receiver = socket(AF_INET, SOCK_DGRAM, 0), sender = socket(AF_INET, SOCK_DGRAM, 0);
    if (receiver < 0 || sender < 0 || bind(receiver, (struct sockaddr*)&udp, sizeof(udp)) != 0 ||
        getsockname(receiver, (struct sockaddr*)&udp, &udpLength) != 0) return 66;
    if (sendto(sender, "msmon-pkt-udp-probe!", 20, 0, (struct sockaddr*)&udp, sizeof(udp)) != 20 ||
        recvfrom(receiver, buffer, sizeof(buffer), 0, NULL, NULL) != 20 || memcmp(buffer, "msmon-pkt-udp-probe!", 20) != 0)
        return 67;
    close(sender);
    close(receiver);
    int code = probe_packets_v6();
    return code != 0 ? code : probe_packets_wine();
}
