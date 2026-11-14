/* The client side of tests/linux_lsm_test.sh, started with `kfilterctl launch`. Each action
 * prints "name=denied" when it failed with EPERM (the BPF layer's answer; opening
 * /proc/<pid>/mem turns it into EACCES) and "name=ok" otherwise (a different errno, such as
 * ECONNREFUSED or EFAULT, means it was not refused).
 * Usage: lsm-probe DIRECTORY OUTSIDE_PID PORT, lsm-probe k4 DIRECTORY OUTSIDE_PID PORT, or lsm-probe k6 DIRECTORY */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <asm/prctl.h>
#include <grp.h>
#include <linux/genetlink.h>
#include <linux/io_uring.h>
#include <linux/keyctl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <poll.h>
#include <sched.h>
#include <stddef.h>
#include <string.h>
#include <sys/un.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/xattr.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#ifndef FIGETBSZ
#define FIGETBSZ _IO(0x00, 2)   /* <linux/fs.h> */
#endif

static void report(const char* name, int failed)
{
    printf("%s=%s\n", name, failed && (errno == EPERM || errno == EACCES) ? "denied" : "ok");
}

/* A DNS query (of Type: 1 A, 28 AAAA) for Name to the resolver stub 127.0.0.53: "denied" when the
 * send is refused, "ok" when it is answered with an address, "sent" otherwise. */
static void dns_query(const char* label, const char* name, unsigned char type)
{
    unsigned char query[300] = {0x12, 0x34, 0x01, 0x00, 0, 1};
    size_t n = 12;
    for (const char* part = name; *part;) {
        const char* dot = strchr(part, '.');
        size_t len = dot ? (size_t)(dot - part) : strlen(part);
        query[n++] = (unsigned char)len;
        memcpy(&query[n], part, len);
        n += len;
        part += len + (dot != NULL);
    }
    memcpy(&query[n], "\0\0\1\0\1", 5);   /* the root label, type, class IN */
    query[n + 2] = type;
    n += 5;
    unsigned char reply[512];
    struct timeval wait = {2, 0};
    struct sockaddr_in stub = {0};
    stub.sin_family = AF_INET;
    stub.sin_port = htons(53);
    stub.sin_addr.s_addr = htonl(0x7f000035);
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0 || setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &wait, sizeof(wait)) != 0 ||
        connect(sock, (struct sockaddr*)&stub, sizeof(stub)) != 0) {
        printf("%s=failed\n", label);
    } else if (send(sock, query, n, 0) < 0) {
        report(label, 1);
    } else {
        ssize_t got = recv(sock, reply, sizeof(reply), 0);
        printf("%s=%s\n", label, got >= 12 && (reply[3] & 15) == 0 && reply[7] != 0 ? "ok" : "sent");
    }
    if (sock >= 0) close(sock);
}

/* An i386 syscall through int 0x80 (the ia32 entries), from this 64-bit program. */
static long syscall32(long number, long a, long b, long c, long d)
{
    long result = number;
    __asm__ volatile("int $0x80" : "+a"(result) : "b"(a), "c"(b), "d"(c), "S"(d) : "r8", "r9", "r10", "r11", "memory");
    errno = (int)result < 0 && (int)result > -4096 ? -(int)result : 0;
    return (int)result;
}

/* Name=denied when child Pid exited 77 (its action failed with EPERM or EACCES). */
static void report_child(const char* name, pid_t pid)
{
    int status = 0;
    if (pid < 0) {
        printf("%s=failed\n", name);
        return;
    }
    waitpid(pid, &status, 0);
    errno = EPERM;
    report(name, WIFEXITED(status) && WEXITSTATUS(status) == 77);
}

static int refused(void)
{
    return errno == EPERM || errno == EACCES;
}

/*
 * `lsm-probe k4 DIRECTORY OUTSIDE_PID PORT` (tests/linux_lsm_test.sh, ABI 11): what kfilter decides since ABI 11 on
 * actions of the probe's own, each next to one no rule names: its syscalls by name and key (x86_64, i386 by int 0x80, a
 * zero-argument call), the hooks kfilter did not use and the finer decisions in those it had.
 */
static int k4(const char* directory, pid_t outside, int port)
{
    if (chdir(directory) != 0) return 2;
    char buffer[64];
    void* low = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
    if (low == MAP_FAILED) return 2;
    /* The first fork is refused (/system/fork, uses=1), the later ones pass. */
    pid_t child = fork();
    if (child == 0) _exit(0);
    report("fork_first", child < 0);
    if (child > 0) waitpid(child, NULL, 0);

    /* /system/syscall/<name>[/<key>] */
    report("sc_sigaction_trap", syscall(SYS_rt_sigaction, SIGTRAP, NULL, low, 8) != 0);
    report("sc_sigaction_usr1", syscall(SYS_rt_sigaction, SIGUSR1, NULL, low, 8) != 0);
    report("sc_sigaction32_trap", syscall32(174, SIGTRAP, 0, (long)low, 8) != 0);
    report("sc_getppid", syscall(SYS_getppid) < 0);           /* __do_sys_getppid, both tables */
    report("sc_getppid32", syscall32(64, 0, 0, 0, 0) < 0);
    int fd = open("lock-ok", O_RDWR);
    struct flock lock = {.l_type = F_RDLCK, .l_whence = SEEK_SET};
    report("sc_fcntl_setlk", fd < 0 || fcntl(fd, F_SETLK, &lock) != 0);
    report("sc_fcntl_getfl", fd < 0 || fcntl(fd, F_GETFL) < 0);
    char* region = mmap((void*)0x520000000, 0x3000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                        -1, 0);
    report("sc_munmap_in", region == MAP_FAILED || munmap(region + 0x1000, 0x1000) != 0);
    report("sc_munmap_out", region == MAP_FAILED || munmap(region, 0x1000) != 0);
    region = mmap((void*)0x52000000, 0x3000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    report("sc_munmap32_in", region == MAP_FAILED || syscall32(91, (long)region + 0x1000, 0x1000, 0, 0) != 0);
    report("sc_munmap32_out", region == MAP_FAILED || syscall32(91, (long)region, 0x1000, 0, 0) != 0);
    struct pollfd none[7];
    for (int i = 0; i < 7; i++) none[i] = (struct pollfd){-1, 0, 0};
    report("sc_poll_named", syscall(SYS_poll, none, 7, 0) < 0);   /* a hot call: only rules naming nfds meet it */
    report("sc_poll_other", syscall(SYS_poll, none, 1, 0) < 0);
    report("sc_wildcard", syscall(SYS_sched_getscheduler, 0) < 0);
    /* ia32's socketcall carries its call: getpeername through it is /system/syscall/getpeername (fd -1: EBADF if let by). */
    unsigned* words = (unsigned*)low + 256;
    words[0] = (unsigned)-1;
    report("sc_socketcall32_named", syscall32(102, 7 /* SYS_GETPEERNAME */, (long)words, 0, 0) < 0);
    report("sc_socketcall32_other", syscall32(102, 6 /* SYS_GETSOCKNAME */, (long)words, 0, 0) < 0);

    /* Locks and fcntl. */
    report("lock_other", fd < 0 || flock(fd, LOCK_EX) != 0);
    report("fcntl_setown", fd < 0 || fcntl(fd, F_SETOWN, getpid()) != 0);
    report("fcntl_getown", fd < 0 || fcntl(fd, F_GETOWN) < 0);
    if (fd >= 0) close(fd);
    fd = open("lock-deny", O_RDONLY);
    report("lock_open", fd < 0);
    report("lock_deny", fd < 0 || flock(fd, LOCK_SH) != 0);
    if (fd >= 0) close(fd);

    /* Sockets: a pair, its shutdown, Fast Open, an abstract bind, netlink, socket ioctls. */
    int pair[2];
    int made = socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0;
    report("socketpair_named", !made);
    if (made) {
        close(pair[0]);
        close(pair[1]);
    }
    made = socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) == 0;
    report("socketpair_other", !made);
    report("shutdown_named", !made || shutdown(pair[0], SHUT_WR) != 0);
    report("shutdown_other", !made || shutdown(pair[0], SHUT_RD) != 0);
    if (made) {
        close(pair[0]);
        close(pair[1]);
    }
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_port = htons((unsigned short)(port + 5));
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    report("tcp_fastopen", sock < 0 || sendto(sock, "x", 1, MSG_FASTOPEN, (struct sockaddr*)&address, sizeof(address)) < 0);
    if (sock >= 0) close(sock);
    struct sockaddr_un name = {0};
    name.sun_family = AF_UNIX;
    const socklen_t nameLength = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 11);
    memcpy(name.sun_path, "\0kf-k4-bind", 11);
    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    report("unix_bind_named", sock < 0 || bind(sock, (struct sockaddr*)&name, nameLength) != 0);
    if (sock >= 0) close(sock);
    memcpy(name.sun_path, "\0kf-k4-free", 11);
    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    report("unix_bind_other", sock < 0 || bind(sock, (struct sockaddr*)&name, nameLength) != 0 || listen(sock, 1) != 0);
    if (sock >= 0) close(sock);
    struct { struct nlmsghdr header; struct genlmsghdr genl; struct nlattr attribute; char family[8]; } lookup = {0};
    lookup.header.nlmsg_len = sizeof(lookup);
    lookup.header.nlmsg_type = GENL_ID_CTRL;
    lookup.header.nlmsg_flags = NLM_F_REQUEST;
    lookup.genl.cmd = CTRL_CMD_GETFAMILY;
    lookup.genl.version = 1;
    lookup.attribute.nla_len = NLA_HDRLEN + sizeof(lookup.family);
    lookup.attribute.nla_type = CTRL_ATTR_FAMILY_NAME;
    sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
    memcpy(lookup.family, "nl80211", 8);
    report("genl_lookup_named", sock < 0 || send(sock, &lookup, sizeof(lookup), 0) < 0);
    memcpy(lookup.family, "kf-none", 8);
    report("genl_lookup_other", sock < 0 || send(sock, &lookup, sizeof(lookup), 0) < 0);
    if (sock >= 0) close(sock);
    struct { struct nlmsghdr header; struct rtgenmsg body; } rules = {0};
    rules.header.nlmsg_len = sizeof(rules);
    rules.header.nlmsg_type = RTM_GETRULE;   /* 34: not one of block-network-adapter's queries */
    rules.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    report("netlink_route_named", sock < 0 || send(sock, &rules, sizeof(rules), 0) < 0);
    if (sock >= 0) close(sock);
    int pending = 0;
    sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    report("socket_ioctl_named", sock < 0 || ioctl(sock, FIONREAD, &pending) != 0);
    report("socket_ioctl_other", sock < 0 || ioctl(sock, TIOCOUTQ, &pending) != 0);
    if (sock >= 0) close(sock);
    /* A device ioctl by the first 32 bits its argument points to (value=0x0000541B:0x00000007). */
    fd = open("ioctl-arg", O_RDONLY);
    int argument = 7;
    report("ioctl_argument_named", fd < 0 || ioctl(fd, FIONREAD, &argument) != 0);
    argument = 8;
    report("ioctl_argument_other", fd < 0 || ioctl(fd, FIONREAD, &argument) != 0);
    if (fd >= 0) close(fd);

    /* Limits, other processes, credentials, capabilities, namespaces, SysV objects, ptrace, modules. */
    struct rlimit limit;
    report("rlimit_named", getrlimit(RLIMIT_CORE, &limit) != 0 || setrlimit(RLIMIT_CORE, &limit) != 0);
    report("rlimit_other", getrlimit(RLIMIT_NOFILE, &limit) != 0 || setrlimit(RLIMIT_NOFILE, &limit) != 0);
    report("rlimit_outside", prlimit(outside, RLIMIT_NOFILE, NULL, &limit) != 0);
    report("task_getpgid_outside", getpgid(outside) < 0);
    report("task_getpgid_self", getpgid(0) < 0);
    report("task_getsid_outside", getsid(outside) < 0);
    gid_t groups[64];
    int count = getgroups(64, groups);
    report("cred_setgroups", count < 0 || setgroups((size_t)count, groups) != 0);
    report("capability_named", setpriority(PRIO_PROCESS, 0, -1) != 0);   /* CAP_SYS_NICE */
    child = fork();
    if (child == 0) _exit(unshare(CLONE_NEWUSER) != 0 && refused() ? 77 : 0);
    report_child("namespace_user", child);
    int queue = msgget(0x4b460000 | (getpid() & 0xffff), IPC_CREAT | IPC_EXCL | 0600);
    report("ipc_create_named", queue < 0);
    if (queue >= 0) msgctl(queue, IPC_RMID, NULL);
    queue = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
    report("ipc_create_other", queue < 0);
    if (queue >= 0) msgctl(queue, IPC_RMID, NULL);
    child = fork();
    if (child == 0) _exit(ptrace(PTRACE_TRACEME, 0, 0, 0) != 0 && refused() ? 77 : 0);
    report_child("ptrace_traceme", child);
    sock = socket(12, SOCK_STREAM, 0);   /* AF_DECnet, gone since Linux 6.1: the kernel asks for module net-pf-12 */
    printf("kernel_module=%s\n", sock >= 0 ? "made" : "asked");
    if (sock >= 0) close(sock);
    report("prctl_named", prctl(PR_SET_NAME, "kf-k4", 0, 0, 0) != 0);
    report("prctl_other", prctl(PR_GET_NAME, buffer, 0, 0, 0) != 0);
    /* Reaching a process outside the family without a handle: a kill(pid, 0) probe (block-process-signals) and a
     * PTRACE_MODE_READ check (kcmp, block-process-queries). */
    report("kill_probe_outside", kill(outside, 0) != 0);
    report("kill_probe_self", kill(getpid(), 0) != 0);
    report("kcmp_outside", syscall(SYS_kcmp, getpid(), outside, 0 /* KCMP_FILE */, 0, 0) < 0);
    /* A socket's SIGIO owner set outside the family (block-process-signals): a SIGIO its softirq raises is not decided. */
    sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    report("sigio_owner_outside", sock < 0 || ioctl(sock, FIOSETOWN, &outside) != 0);
    struct f_owner_ex owner = {F_OWNER_PID, outside};
    report("sigio_owner_ex_outside", sock < 0 || fcntl(sock, F_SETOWN_EX, &owner) != 0);
    pid_t self = getpid();
    report("sigio_owner_self", sock < 0 || ioctl(sock, FIOSETOWN, &self) != 0);
    /* Inside the family (a child, protected as the probe is): a signal, a file's SIGIO owner and a PTRACE_MODE_READ
     * check, each decided only by the peer rule naming it (value=signal:0x..., ptrace:0x...); SIGUSR2 and kcmp's
     * mode (READ_REALCREDS) no rule names. */
    int ready[2] = {-1, -1};
    pid_t kin = pipe(ready) == 0 ? fork() : -1;
    if (kin == 0) {
        signal(SIGUSR1, SIG_IGN);
        signal(SIGUSR2, SIG_IGN);
        if (write(ready[1], "", 1) != 1) _exit(1);
        pause();
        _exit(0);
    }
    char started = 0;
    if (kin > 0 && read(ready[0], &started, 1) != 1) kin = -1;
    report("signal_family_named", kin <= 0 || kill(kin, SIGUSR1) != 0);
    report("signal_family_other", kin <= 0 || kill(kin, SIGUSR2) != 0);
    report("sigio_owner_family_named", sock < 0 || kin <= 0 || ioctl(sock, FIOSETOWN, &kin) != 0);
    /* A READ_FSCREDS check whose refusal the kernel honours: readlink of /proc/<pid>/exe (Linux 7.0 opens and reads
     * /proc/<pid>/maps with that check refused). */
    char exe[64], target[256];
    snprintf(exe, sizeof(exe), "/proc/%d/exe", (int)kin);
    report("read_family_named", kin <= 0 || readlink(exe, target, sizeof(target)) < 0);
    report("read_family_other", kin <= 0 || syscall(SYS_kcmp, getpid(), kin, 0 /* KCMP_FILE */, 0, 0) < 0);
    if (kin > 0) {
        kill(kin, SIGKILL);
        waitpid(kin, NULL, 0);
    }
    if (ready[0] >= 0) close(ready[0]);
    if (ready[1] >= 0) close(ready[1]);
    if (sock >= 0) close(sock);

    /* Memory: below mmap_min_addr, and data memory by its protection and address. */
    void* page = mmap((void*)0x1000, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    report("memory_low", page == MAP_FAILED);
    if (page != MAP_FAILED) munmap(page, 4096);
    page = mmap((void*)0x530000000, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    report("memory_rw_named", page == MAP_FAILED);
    if (page != MAP_FAILED) munmap(page, 4096);
    page = mmap((void*)0x532000000, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    report("memory_rw_other", page == MAP_FAILED);
    if (page != MAP_FAILED) munmap(page, 4096);
    page = mmap((void*)0x531000000, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    report("memory_r_named", page == MAP_FAILED || mprotect(page, 4096, PROT_READ) != 0);
    if (page != MAP_FAILED) munmap(page, 4096);
    /* Without MAP_FIXED a mapping is decided where the kernel puts it: at its hint, inside the range; elsewhere, not. */
    page = mmap((void*)0x530000000, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    report("memory_rw_hint_named", page == MAP_FAILED);
    if (page != MAP_FAILED) munmap(page, 4096);
    page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    report("memory_rw_hintless", page == MAP_FAILED);
    if (page != MAP_FAILED) munmap(page, 4096);

    /* Files: statfs by path, touch (times set to now), chdir and fchdir. */
    struct statfs volume;
    report("statfs_named", statfs("k4-statfs", &volume) != 0);
    report("statfs_other", statfs(".", &volume) != 0);
    report("touch_named", utimensat(AT_FDCWD, "touch-deny", NULL, 0) != 0);
    struct timespec times[2] = {{1, 0}, {1, 0}};
    report("touch_times", utimensat(AT_FDCWD, "touch-ok", times, 0) != 0);
    report("chdir_named", chdir("chdir-deny") != 0 || chdir(directory) != 0);
    fd = open("chdir-deny", O_RDONLY | O_DIRECTORY);
    report("fchdir_named", fd < 0 || fchdir(fd) != 0 || chdir(directory) != 0);
    if (fd >= 0) close(fd);
    report("chdir_other", chdir("chdir-ok") != 0 || chdir(directory) != 0);
    return 0;
}

/* An AF_UNIX address: Length bytes of sun_path (a leading NUL: an abstract name), and its size. */
static socklen_t unix_address(struct sockaddr_un* address, const char* name, size_t length)
{
    memset(address, 0, sizeof(*address));
    address->sun_family = AF_UNIX;
    memcpy(address->sun_path, name, length);
    return (socklen_t)(offsetof(struct sockaddr_un, sun_path) + length);
}

/* A socket of Type bound to Name (listening if a stream), or connected to it (Connect); -1 when that fails. */
static int unix_socket(int type, const char* name, size_t length, int connected)
{
    struct sockaddr_un address;
    const socklen_t size = unix_address(&address, name, length);
    int sock = socket(AF_UNIX, type, 0);
    if (sock >= 0 && (connected ? connect(sock, (struct sockaddr*)&address, size) == 0
                                : bind(sock, (struct sockaddr*)&address, size) == 0 && (type != SOCK_STREAM || listen(sock, 4) == 0)))
        return sock;
    if (sock >= 0) close(sock);
    return -1;
}

/* Name=denied when Size bytes of Data sent on Sock (to Peer when it is not 0) were refused; =failed without a socket. */
static void unix_send(const char* name, int sock, const char* data, size_t size, const char* peer, size_t length)
{
    struct sockaddr_un address;
    const socklen_t named = peer ? unix_address(&address, peer, length) : 0;
    if (sock < 0) printf("%s=failed\n", name);
    else report(name, sendto(sock, data, size, 0, peer ? (struct sockaddr*)&address : NULL, named) < 0);
}

/*
 * `lsm-probe k6 DIRECTORY` (tests/linux_lsm_test.sh, ABI 12): sends to AF_UNIX peers, decided by the message rules
 * naming the peer (unix=): to a connected abstract server by match= (an X11 setup's byte-order byte), to a path server by
 * size=, a datagram's sendto by index= (its socket's first send) and by a path's name, absolute and relative to the cwd;
 * next to each, a send no rule meets, and a socketpair's (its peer has no name, which no rule can meet).
 */
static int k6(const char* directory)
{
    if (chdir(directory) != 0) return 2;
    const char setup[] = {'l', 0, 11, 0}, other[] = {'B', 0, 11, 0};
    int x11 = unix_socket(SOCK_STREAM, "\0kf-k6-x11", 10, 0);
    int client = x11 < 0 ? -1 : unix_socket(SOCK_STREAM, "\0kf-k6-x11", 10, 1);
    unix_send("unix_match_named", client, setup, sizeof(setup), NULL, 0);
    unix_send("unix_match_other", client, other, sizeof(other), NULL, 0);
    if (client >= 0) close(client);
    int server = unix_socket(SOCK_STREAM, "kf-k6.sock", 10, 0);
    client = server < 0 ? -1 : unix_socket(SOCK_STREAM, "kf-k6.sock", 10, 1);
    unix_send("unix_size_named", client, "12345", 5, NULL, 0);
    unix_send("unix_size_other", client, "1234", 4, NULL, 0);
    if (client >= 0) close(client);
    int dgram = unix_socket(SOCK_DGRAM, "\0kf-k6-dgram", 12, 0), path = unix_socket(SOCK_DGRAM, "kf-k6-dgram.sock", 16, 0);
    int spare = unix_socket(SOCK_DGRAM, "\0kf-k6-free", 11, 0);
    int sender = dgram < 0 || path < 0 || spare < 0 ? -1 : socket(AF_UNIX, SOCK_DGRAM, 0);
    unix_send("unix_index_named", sender, "x", 1, "\0kf-k6-dgram", 12);
    unix_send("unix_index_other", sender, "x", 1, "\0kf-k6-dgram", 12);
    char absolute[200];
    snprintf(absolute, sizeof(absolute), "%s/kf-k6-dgram.sock", directory);
    unix_send("unix_sendto_named", sender, "x", 1, absolute, strlen(absolute));
    unix_send("unix_sendto_relative_named", sender, "x", 1, "kf-k6-dgram.sock", 16);
    unix_send("unix_sendto_other", sender, "x", 1, "\0kf-k6-free", 11);
    int pair[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0) pair[0] = -1;
    unix_send("unix_socketpair_other", pair[0], setup, sizeof(setup), NULL, 0);
    const int opened[] = {x11, server, dgram, path, spare, sender, pair[0], pair[1]};
    for (size_t i = 0; i < sizeof(opened) / sizeof(opened[0]); i++) {
        if (opened[i] >= 0) close(opened[i]);
    }
    unlink("kf-k6.sock");
    unlink("kf-k6-dgram.sock");
    return 0;
}

/* `lsm-probe identity` (tests/linux_launch_test.sh): what the launch's hiding options show the client.
 * The brand string and the TSC reads go through the trap shim when it is armed. */
static int identity(void)
{
    struct utsname name;
    struct sysinfo info;
    char cgroup[256] = "", brand[49] = "";
    unsigned a, b, c, d, lo, hi;
    uname(&name);
    sysinfo(&info);
    FILE* file = fopen("/proc/self/cgroup", "r");
    if (file && fgets(cgroup, sizeof(cgroup), file)) cgroup[strcspn(cgroup, "\n")] = 0;
    if (file) fclose(file);
    for (unsigned i = 0; i < 3; i++) {
        __asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(0x80000002 + i), "c"(0));
        memcpy(brand + 16 * i, (unsigned[]){a, b, c, d}, 16);
    }
    for (int i = 0; i < 3; i++) __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    printf("nodename=%s release=%s uptime=%ld uid=%u cgroup=%s cgroupfs=%s pid1=%s brand=%s\n", name.nodename,
           name.release, info.uptime, (unsigned)getuid(), cgroup,
           access("/sys/fs/cgroup/kfilter", F_OK) == 0 ? "host" : "own", access("/proc/1", F_OK) == 0 ? "visible" : "hidden",
           brand);
    report("cpuid_untrap", syscall(SYS_arch_prctl, ARCH_SET_CPUID, 1) != 0);
    return 0;
}

int main(int argc, char** argv)
{
    if (argc == 2 && strcmp(argv[1], "identity") == 0) return identity();
    if (argc == 5 && strcmp(argv[1], "k4") == 0) return k4(argv[2], (pid_t)atoi(argv[3]), atoi(argv[4]));
    if (argc == 3 && strcmp(argv[1], "k6") == 0) return k6(argv[2]);
    if (argc == 3 && strcmp(argv[1], "sysinfo") == 0) {   /* N sysinfo calls while policies reload */
        struct sysinfo system;
        int refused = 0;
        for (long i = atol(argv[2]); i > 0; i--) refused |= sysinfo(&system) != 0;
        report("sysinfo_loop", refused);
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "addr") == 0) {
        /* addr= rules on its own access to family memory: a child's (a descendant: Yama allows it) by process_vm_readv
         * and /proc/<pid>/mem, and its own by /proc/self/mem, inside and outside 0x500001000-0x500001FFF; a ptrace
         * attach to the child, which reaches every address. */
        char* memory = mmap((void*)0x500000000, 0x3000, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        if (memory == MAP_FAILED) {
            printf("addr_setup=failed\n");
            return 0;
        }
        memset(memory, 1, 0x3000);
        pid_t child = fork();
        if (child == 0) {
            pause();
            _exit(0);
        }
        char buffer[16], path[64];
        struct iovec local = {buffer, 4}, remote = {memory + 0x1010, 4}, many[9];
        report("addr_vm_in", process_vm_readv(child, &local, 1, &remote, 1, 0) < 0);
        remote.iov_base = memory + 0x10;
        report("addr_vm_out", process_vm_readv(child, &local, 1, &remote, 1, 0) < 0);
        for (int i = 0; i < 9; i++) {   /* past the first 8 iovecs the address is unknown: a deny meets it */
            many[i].iov_base = memory + 0x10 + i;
            many[i].iov_len = 1;
        }
        report("addr_vm_many", process_vm_readv(child, &local, 1, many, 9, 0) < 0);
        snprintf(path, sizeof(path), "/proc/%d/mem", (int)child);
        int fd = open(path, O_RDONLY);
        report("addr_mem_in", fd < 0 || pread(fd, buffer, 4, (off_t)(uintptr_t)(memory + 0x1010)) != 4);
        report("addr_mem_out", fd < 0 || pread(fd, buffer, 4, (off_t)(uintptr_t)(memory + 0x10)) != 4);
        if (fd >= 0) close(fd);
        fd = open("/proc/self/mem", O_RDONLY);
        report("addr_self_in", fd < 0 || pread(fd, buffer, 4, (off_t)(uintptr_t)(memory + 0x1010)) != 4);
        report("addr_self_out", fd < 0 || pread(fd, buffer, 4, (off_t)(uintptr_t)(memory + 0x10)) != 4);
        if (fd >= 0) close(fd);
        long attached = ptrace(PTRACE_ATTACH, child, 0, 0);
        report("addr_attach", attached != 0);
        if (attached == 0) {
            waitpid(child, NULL, 0);
            ptrace(PTRACE_DETACH, child, 0, 0);
        }
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        return 0;
    }
    if (argc != 4 || chdir(argv[1]) != 0) return 2;
    pid_t outside = (pid_t)atoi(argv[2]);
    char buffer[64];

    int fd = open("/etc/hostname", O_RDONLY);
    report("open_read", fd < 0 || read(fd, buffer, sizeof(buffer)) < 0);
    if (fd >= 0) close(fd);
    /* image= scopes a rule to a Linux program too (named by its executable at exec): this probe is lsm-probe. */
    fd = open("img-allow", O_RDONLY);
    report("image_allow", fd < 0);
    if (fd >= 0) close(fd);
    fd = open("img-deny", O_RDONLY);
    report("image_deny", fd < 0);
    if (fd >= 0) close(fd);
    /* A forked child that has not exec'd runs this program: it has its name (image=lsm-probe applies to it). */
    pid_t forked = fork();
    if (forked == 0) {
        int cfd = open("img-allow", O_RDONLY);
        _exit(cfd < 0 ? 1 : 0);
    }
    int forkStatus = 1;
    if (forked > 0) waitpid(forked, &forkStatus, 0);
    report("image_fork", forked < 0 || !WIFEXITED(forkStatus) || WEXITSTATUS(forkStatus) != 0);
    report("unlink", unlink("no-delete") != 0);
    report("rename", rename("no-rename", "renamed") != 0);
    report("truncate", truncate("no-write", 0) != 0);
    report("chmod", chmod("no-chmod", 0600) != 0);
    fd = open("no-exec", O_RDONLY);
    void* mapping = fd >= 0 ? mmap(NULL, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0) : MAP_FAILED;
    report("mmap_exec", mapping == MAP_FAILED);
    if (fd >= 0) close(fd);

    /* Process memory of a process outside the family; EFAULT (bad address) means allowed. */
    struct iovec local = {buffer, 8}, remote = {(void*)0x1000, 8};
    report("process_vm_readv", process_vm_readv(outside, &local, 1, &remote, 1, 0) < 0);
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", (int)outside);
    fd = open(path, O_RDONLY);
    report("proc_mem", fd < 0);
    if (fd >= 0) close(fd);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_port = htons((unsigned short)atoi(argv[3]));
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    report("connect", sock < 0 || connect(sock, (struct sockaddr*)&address, sizeof(address)) != 0);
    if (sock >= 0) close(sock);

    /* PORT+1 allows one peer (uses=1, then a deny), PORT+2 denies: decided per peer, not per datagram. */
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    address.sin_port = htons((unsigned short)(atoi(argv[3]) + 1));
    report("udp_first", sock < 0 || sendto(sock, "x", 1, 0, (struct sockaddr*)&address, sizeof(address)) != 1);
    report("udp_repeat", sock < 0 || sendto(sock, "x", 1, 0, (struct sockaddr*)&address, sizeof(address)) != 1);
    address.sin_port = htons((unsigned short)(atoi(argv[3]) + 2));
    report("udp_other", sock < 0 || sendto(sock, "x", 1, 0, (struct sockaddr*)&address, sizeof(address)) != 1);
    if (sock >= 0) close(sock);

    /* A Unix socket is a pipe rule on its path; "/@name" for an abstract one. Allowed, the
     * connect fails with ECONNREFUSED (nobody listens). */
    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un unixAddress = {0};
    unixAddress.sun_family = AF_UNIX;
    memcpy(unixAddress.sun_path, "\0kfilter-test", 13);
    report("unix_connect", sock < 0 ||
           connect(sock, (struct sockaddr*)&unixAddress, (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 13)) != 0);
    if (sock >= 0) close(sock);
    /* A relative path is the file in the cwd (Wine connects to "socket" in its server dir). */
    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un relative = {0};
    relative.sun_family = AF_UNIX;
    memcpy(relative.sun_path, "rel.sock", 9);
    report("unix_relative", sock < 0 || connect(sock, (struct sockaddr*)&relative, sizeof(relative)) != 0);
    if (sock >= 0) close(sock);

    /* Interface enumeration over netlink (block-network-adapter): a device decision. */
    sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    struct { struct nlmsghdr header; struct rtgenmsg body; } request = {0};
    request.header.nlmsg_len = sizeof(request);
    request.header.nlmsg_type = RTM_GETLINK;
    request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    request.body.rtgen_family = AF_UNSPEC;
    report("netlink_getlink", sock < 0 || send(sock, &request, sizeof(request), 0) < 0);
    if (sock >= 0) close(sock);

    /* Rights count once per open: a uses=1 read allow covers every read of that open, and
     * the second open is refused (the rule is spent). */
    fd = open("once", O_RDONLY);
    report("counted_read", fd < 0 || read(fd, buffer, 1) < 0 || read(fd, buffer, 1) < 0);
    if (fd >= 0) close(fd);
    fd = open("once", O_RDONLY);
    report("counted_reopen", fd < 0);
    if (fd >= 0) close(fd);

    /* Messages on an allowed connection (PORT+3): each send is decided on its own. */
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    int yes = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in loop = {0};
    loop.sin_family = AF_INET;
    loop.sin_port = htons((unsigned short)(atoi(argv[3]) + 3));
    loop.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int client = -1, server = -1;
    if (listener >= 0 && bind(listener, (struct sockaddr*)&loop, sizeof(loop)) == 0 && listen(listener, 1) == 0) {
        client = socket(AF_INET, SOCK_STREAM, 0);
        if (client >= 0 && connect(client, (struct sockaddr*)&loop, sizeof(loop)) == 0) server = accept(listener, NULL, NULL);
    }
    if (server < 0) {
        printf("message_setup=failed\n");
    } else {
        char big[300];
        memset(big, 'x', sizeof(big));
        report("msg_plain", send(client, "HELLO", 5, 0) != 5);                     /* #1 */
        report("msg_match", send(client, "\xde\xad\x01\x02", 4, 0) != 4);     /* #2 match=DEAD@0 */
        report("msg_size", send(client, big, sizeof(big), 0) != (ssize_t)sizeof(big));   /* #3 size=300 */
        report("msg_fourth", send(client, "ok", 2, 0) != 2);                       /* #4 */
        report("msg_index", send(client, "ok", 2, 0) != 2);                        /* #5 index=5 */
        report("msg_once_first", send(client, "\xbe\xef", 2, 0) != 2);          /* #6 match=BEEF uses=1 */
        report("msg_once_second", send(client, "\xbe\xef", 2, 0) != 2);         /* #7 */
        /* The test blocks this live connection by its socket inode, then lets us go on. */
        struct stat info;
        if (fstat(client, &info) == 0) {
            FILE* out = fopen("inode", "w");
            if (out) {
                fprintf(out, "%llu\n", (unsigned long long)info.st_ino);
                fclose(out);
            }
        }
        for (int i = 0; i < 100 && access("go", F_OK) != 0; i++) {
            struct timespec pause = {0, 100000000};
            nanosleep(&pause, NULL);
        }
        report("msg_blocked_send", send(client, "after", 5, 0) != 5);
        report("msg_blocked_recv", recv(client, buffer, sizeof(buffer), MSG_DONTWAIT) < 0 && errno != EAGAIN);
        close(server);
    }
    if (client >= 0) close(client);
    if (listener >= 0) close(listener);

    /* Starting a program the policy's process rules deny (block-process-create). */
    pid_t child = fork();
    if (child == 0) {
        char* args[] = {"no-run", NULL};
        execv("no-run", args);
        _exit(errno == EPERM || errno == EACCES ? 77 : 78);
    }
    int status = 0;
    if (child > 0) waitpid(child, &status, 0);
    errno = child > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 77 ? EPERM : 0;
    report("exec_denied", child > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 77);

    /* Pseudo files are /anon/<name>, decided only where a rule names them: a memfd mapping,
     * private and keyed SysV shm (the policy denies the keyed one), and a memfd no rule names.
     * Executable anonymous memory, shared and private, is /system/memory/... */
    fd = memfd_create("kf-probe", 0);
    mapping = fd >= 0 && ftruncate(fd, 4096) == 0 ? mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0) : MAP_FAILED;
    report("memfd_map", mapping == MAP_FAILED);
    if (mapping != MAP_FAILED) munmap(mapping, 4096);
    if (fd >= 0) close(fd);
    fd = memfd_create("kf-unlisted", 0);
    mapping = fd >= 0 && ftruncate(fd, 4096) == 0 ? mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0) : MAP_FAILED;
    if (mapping != MAP_FAILED) munmap(mapping, 4096);
    if (fd >= 0) close(fd);
    int shm = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0600);
    mapping = shm >= 0 ? shmat(shm, NULL, 0) : (void*)-1;
    report("shm_private", mapping == (void*)-1);
    if (mapping != (void*)-1) shmdt(mapping);
    if (shm >= 0) shmctl(shm, IPC_RMID, NULL);
    shm = shmget(0x4b460000 | (getpid() & 0xffff), 4096, IPC_CREAT | IPC_EXCL | 0600);   /* SYSV4b46.... */
    mapping = shm >= 0 ? shmat(shm, NULL, SHM_RDONLY) : (void*)-1;
    report("shm_keyed", shm >= 0 && mapping == (void*)-1);
    if (mapping != (void*)-1) shmdt(mapping);
    if (shm >= 0) shmctl(shm, IPC_RMID, NULL);
    mapping = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    report("anon_shared_exec", mapping == MAP_FAILED || mprotect(mapping, 4096, PROT_READ | PROT_EXEC) != 0);
    if (mapping != MAP_FAILED) munmap(mapping, 4096);
    mapping = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    report("anon_exec", mapping == MAP_FAILED);
    if (mapping != MAP_FAILED) munmap(mapping, 4096);
    fd = open("/dev/zero", O_RDONLY);   /* a private mapping of it is anonymous memory too */
    mapping = fd >= 0 ? mmap(NULL, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0) : MAP_FAILED;
    report("zero_exec", mapping == MAP_FAILED);
    if (mapping != MAP_FAILED) munmap(mapping, 4096);
    if (fd >= 0) close(fd);
    /* A file deeper than the kernel walks (the test made deep/d/.../d/file, 64 d's): a name failure. */
    char deep[160] = "deep/";
    for (int level = 0; level < 64; level++) strcat(deep, "d/");
    strcat(deep, "file");
    fd = open(deep, O_RDONLY);
    report("deep_open", fd < 0);
    if (fd >= 0) close(fd);

    /* Names it looks up: a denied one (any case) and one the resolver answers. */
    dns_query("dns_deny", "KF-Deny.Example", 1);
    dns_query("dns_allow", "localhost", 1);
    dns_query("dns_type", "kf-aaaa.example", 28);   /* a dns rule's value= is the type */
    dns_query("dns_type_other", "kf-aaaa.example", 1);

    /* /proc/<pid> is named by whose process it is: @self, @family (a protected child) and
     * @outside, which the policy hides (ENOENT). */
    fd = open("/proc/self/status", O_RDONLY);
    report("proc_self", fd < 0);
    if (fd >= 0) close(fd);
    child = fork();
    if (child == 0) {
        pause();
        _exit(0);
    }
    snprintf(path, sizeof(path), "/proc/%d/status", (int)child);
    fd = child > 0 ? open(path, O_RDONLY) : -1;
    report("proc_family", fd < 0);
    if (fd >= 0) close(fd);
    if (child > 0) {
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
    }
    snprintf(path, sizeof(path), "/proc/%d/status", (int)outside);
    fd = open(path, O_RDONLY);
    printf("proc_outside=%s\n", fd >= 0 ? "ok" : errno == ENOENT ? "hidden" : "denied");
    if (fd >= 0) close(fd);

    /* Metadata without an open (block-file-queries): every query of meta/ is refused, by path,
     * through an O_PATH fd and as the cwd; hidden seems not to exist; queries on an fd whose
     * open was decided (meta-ok, audited) are not decided again; statfs is only logged. */
    struct stat info;
    struct statx extended;
    struct statfs volume;
    char text[64];
    report("meta_stat", stat("meta/f", &info) != 0);
    report("meta_lstat", lstat("meta/l", &info) != 0);
    report("meta_statx", statx(AT_FDCWD, "meta/f", 0, STATX_BASIC_STATS, &extended) != 0);
    report("meta_access", access("meta/f", F_OK) != 0);
    report("meta_faccessat2", syscall(SYS_faccessat2, AT_FDCWD, "meta/f", R_OK, 0) != 0);
    report("meta_readlink", readlink("meta/l", text, sizeof(text)) < 0);
    report("meta_getxattr", getxattr("meta/f", "user.kf", text, sizeof(text)) < 0);
    report("meta_listxattr", listxattr("meta/f", text, sizeof(text)) < 0);
    fd = open("meta/f", O_PATH);
    report("meta_opath_fstat", fd < 0 || fstat(fd, &info) != 0);
    report("meta_opath_statx", fd < 0 || syscall(SYS_statx, fd, NULL, AT_EMPTY_PATH, STATX_BASIC_STATS, &extended) != 0);
    if (fd >= 0) close(fd);
    report("meta_cwd_statx", chdir("meta") != 0 || syscall(SYS_statx, AT_FDCWD, NULL, AT_EMPTY_PATH, STATX_BASIC_STATS, &extended) != 0);
    if (chdir(argv[1]) != 0) return 2;
    int watch = inotify_init1(IN_CLOEXEC);
    report("meta_watch", watch < 0 || inotify_add_watch(watch, "meta", IN_MODIFY) < 0);
    if (watch >= 0) close(watch);
    printf("hide_stat=%s\n", stat("hidden", &info) == 0 ? "ok" : errno == ENOENT ? "hidden" : "denied");
    fd = open("hidden", O_RDONLY);
    printf("hide_open=%s\n", fd >= 0 ? "ok" : errno == ENOENT ? "hidden" : "denied");
    if (fd >= 0) close(fd);
    fd = open("meta-ok", O_RDONLY);
    report("meta_fd", fd < 0 || fstat(fd, &info) != 0 || fstatat(fd, "", &info, AT_EMPTY_PATH) != 0 ||
                          syscall(SYS_statx, fd, NULL, AT_EMPTY_PATH, STATX_BASIC_STATS, &extended) != 0 ||
                          (fgetxattr(fd, "user.kf", text, sizeof(text)) < 0 && errno != ENODATA));
    if (fd >= 0) close(fd);
    report("statfs", statfs(".", &volume) != 0);

    /* Rule-only system decisions as the policy names them (/system/...); an unnamed inet socket
     * and memfd kf-probe are not decided. Then an ioctl on /dev/null by its value, a POSIX
     * message queue (/anon/mqueue), and the pipe on stdin (made outside the family) next to one
     * of our own. */
    struct utsname host;
    struct sysinfo system;
    void* low = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
    report("sys_uname", uname(&host) != 0);
    report("sys_uname32", low == MAP_FAILED || syscall32(122, (long)low, 0, 0, 0) != 0);
    report("sys_sysinfo", sysinfo(&system) != 0);
    report("sys_sysinfo32", low == MAP_FAILED || syscall32(116, (long)low, 0, 0, 0) != 0);
    sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_KOBJECT_UEVENT);
    report("sys_socket_uevent", sock < 0);
    if (sock >= 0) close(sock);
    sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    report("sys_socket_inet", sock < 0);
    if (sock >= 0) close(sock);
    fd = memfd_create("kf-deny", MFD_CLOEXEC);
    report("sys_memfd", fd < 0);
    if (fd >= 0) close(fd);
    fd = (int)syscall(SYS_userfaultfd, O_CLOEXEC);
    report("sys_userfaultfd", fd < 0);
    if (fd >= 0) close(fd);
    struct io_uring_params ring = {0};
    fd = (int)syscall(SYS_io_uring_setup, 4, &ring);
    report("sys_io_uring", fd < 0);
    if (fd >= 0) close(fd);
    report("sys_keyring", syscall(SYS_keyctl, KEYCTL_GET_KEYRING_ID, KEY_SPEC_SESSION_KEYRING, 1) < 0);
    int queue = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
    struct { long type; char text[1]; } message = {1, {'x'}};
    report("sys_msgsnd", queue < 0 || msgsnd(queue, &message, 1, IPC_NOWAIT) != 0);
    if (queue >= 0) msgctl(queue, IPC_RMID, NULL);
    report("sys_arch_prctl", syscall(SYS_arch_prctl, ARCH_GET_CPUID, 0) < 0);
    fd = open("/dev/null", O_RDWR);
    struct termios terminal;
    int pending = 0;
    report("ioctl_tcgets", fd < 0 || ioctl(fd, TCGETS, &terminal) != 0);
    report("ioctl_fionread", fd < 0 || ioctl(fd, FIONREAD, &pending) != 0);
    if (fd >= 0) close(fd);
    /* A device allow without uses= on a plain file (rule-only): every FIONREAD passes, other ioctls meet the deny. */
    int blockSize = 0;
    fd = open("ioctl-ok", O_RDONLY);
    report("ioctl_allowed", fd < 0 || ioctl(fd, FIONREAD, &pending) != 0 || ioctl(fd, FIONREAD, &pending) != 0);
    report("ioctl_other", fd < 0 || ioctl(fd, FIGETBSZ, &blockSize) != 0);
    if (fd >= 0) close(fd);
    fd = (int)syscall(SYS_mq_open, "kf-probe", O_CREAT | O_RDWR | O_CLOEXEC, 0600, NULL);
    report("mqueue", fd < 0);
    if (fd >= 0) close(fd);
    syscall(SYS_mq_unlink, "kf-probe");
    report("pipe_stdin", read(0, buffer, 1) < 0);
    int own[2];
    report("pipe_own", pipe(own) != 0 || write(own[1], "x", 1) != 1 || read(own[0], buffer, 1) != 1);

    /* Socket options and names: setsockopt SO_RCVBUF and getpeername named, getsockopt not (an unconnected
     * socket's getpeername fails with ENOTCONN once allowed). A file mapping by path (/system/map...):
     * reading map-deny is allowed, mapping it is not. */
    sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    int size = 1 << 16;
    socklen_t sizeLength = sizeof(size);
    struct sockaddr_in peer;
    socklen_t peerLength = sizeof(peer);
    report("sys_setsockopt", sock < 0 || setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) != 0);
    report("sys_getsockopt", sock < 0 || getsockopt(sock, SOL_SOCKET, SO_RCVBUF, &size, &sizeLength) != 0);
    report("sys_getpeername", sock < 0 || getpeername(sock, (struct sockaddr*)&peer, &peerLength) != 0);
    if (sock >= 0) close(sock);
    fd = open("map-deny", O_RDONLY);
    report("map_read", fd < 0 || read(fd, buffer, 1) != 1);
    mapping = fd >= 0 ? mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0) : MAP_FAILED;
    report("map_file", mapping == MAP_FAILED);
    if (mapping != MAP_FAILED) munmap(mapping, 4096);
    if (fd >= 0) close(fd);

    /* A counted deny (uses=1) refuses only the first open. */
    fd = open("deny-once", O_RDONLY);
    report("deny_once_first", fd < 0);
    if (fd >= 0) close(fd);
    fd = open("deny-once", O_RDONLY);
    report("deny_once_second", fd < 0);
    if (fd >= 0) close(fd);
    return 0;
}
