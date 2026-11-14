/* The netattr upgrade's probe actions (the socket join): a socket one process connects and another
 * uses, as wineserver and the game under Wine. The parent connects to its own loopback listener; a
 * forked child sendmsg()s "msmon-netattr-ping" (18 bytes) on that socket, peeks at the 3 bytes the
 * accepted end answers and then recvmsg()s them (Wine's calls; the peek counts nothing); the parent
 * then closes its client fd while the child still runs, so the child gets a network_flow_established
 * at its first sendmsg and a network_flow_close (socket_closed, 18 sent, 3 received). Returns 0 or
 * an exit code 40-49. */
#include <sys/time.h>

/* One sendmsg/recvmsg of Length bytes at Data with Flags; the call's result. */
static ssize_t probe_netattr_msg(int fd, int out, void* data, size_t length, int flags)
{
    struct iovec vector = {data, length};
    struct msghdr message;
    memset(&message, 0, sizeof(message));
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    return out ? sendmsg(fd, &message, flags) : recvmsg(fd, &message, flags);
}

static int probe_netattr(void)
{
    struct timeval timeout = {5, 0};   /* a failed peer ends the probe with 43, not a hang */
    struct sockaddr_in address;
    socklen_t length = sizeof(address);
    char buffer[32];
    int status = 0, sync[2];
    int listener = socket(AF_INET, SOCK_STREAM, 0), client = socket(AF_INET, SOCK_STREAM, 0);
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (listener < 0 || client < 0 || pipe(sync) != 0 || bind(listener, (struct sockaddr*)&address, sizeof(address)) != 0 ||
        listen(listener, 1) != 0 || getsockname(listener, (struct sockaddr*)&address, &length) != 0 ||
        connect(client, (struct sockaddr*)&address, sizeof(address)) != 0 ||
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) return 40;
    int accepted = accept(listener, NULL, NULL);
    if (accepted < 0 || setsockopt(accepted, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) return 41;
    pid_t child = fork();
    if (child < 0) return 42;
    if (child == 0) {
        close(sync[0]);
        if (probe_netattr_msg(client, 1, (void*)"msmon-netattr-ping", 18, 0) != 18 ||
            probe_netattr_msg(client, 0, buffer, 3, MSG_PEEK | MSG_WAITALL) <= 0 ||
            probe_netattr_msg(client, 0, buffer, 3, MSG_WAITALL) != 3 || write(sync[1], "x", 1) != 1) _exit(1);
        sleep(1);   /* still running when the parent closes the socket */
        _exit(0);
    }
    close(sync[1]);
    if (recv(accepted, buffer, 18, MSG_WAITALL) != 18 || write(accepted, "abc", 3) != 3) return 43;
    if (read(sync[0], buffer, 1) != 1) return 44;
    close(client);   /* the maker's close ends the child's use: its network_flow_close */
    close(accepted);
    close(listener);
    close(sync[0]);
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) return 45;
    return 0;
}
