/* One of each action tests/linux_ebpf_test.sh expects the eBPF sensors to record:
 * create/write/read/close, rename, chmod, an executable file mapping, unlink, a failed
 * open, a TCP connect/accept on loopback, a thread, a forked child and a memory read
 * of that child. Then: 100 reads of one file (collapsed into repeat counts), a failing
 * open of a path that just opened fine, a UDP sendmsg/recvmsg with addresses, prctl,
 * pidfd_open, uname, sysinfo, a TCP shutdown, inotify_add_watch, memfd_create, fsync,
 * shmget/shmat, and a child that execs a native program outside the scope (untracked) with a 600-byte argument
 * and WINEDEBUG in its environment (the whole line is recorded). Syscall completeness: 3 raw getcpu calls
 * (counted only: syscall_counts), userfaultfd, arch_prctl(ARCH_GET_CPUID), a clone3 refused for its size,
 * getxattrat (463+) of the scope directory, lsm_list_modules, msgget, 50 process_vm_readv of the child at 50
 * addresses (each kept, not collapsed), and the pread burst from two threads (the tail names both).
 * Windows parity (tests/ebpf_checks/check_parity.py): the thread sets a Wine-like TEB as its GS base (ClientId
 * 0x1234/0x5678) so its exit carries Windows ids; probe-b.txt is unmapped at once (image_load must come from
 * the mapping, not the 2 s poll); probe-x.txt is mapped read-only and mprotect'ed executable (as Wine does PE
 * code); a bpf() map create must not be refused (msmon observes only) and kill(MSMON_AGENT_PID, 0) is refused
 * (self-protection); neither result changes the exit code (the --no-ebpf session runs it too).
 * Kernel events (kev.bpf.h, exit codes 70-79): an io_uring open/write/read/close of probe-uring.txt, an AIO write,
 * a PE image built in anonymous memory and mprotect'ed executable at its 64 KiB-aligned base + 4 KiB, CPUID and RDTSC
 * with faulting on (when the CPU supports CPUID faulting; RDTSC twice at one ip: its records and PR_SET_TSC collapse),
 * SGDT (UMIP), keyctl, a socket of a family with no module (a module request), 3 pages of a MAP_SHARED file read and
 * 1 written (--page-faults), and from the forked child a SIGUSR2 to the probe (signal_received) and, as root, a
 * setresuid to nobody (cred_change).
 * The kernel-sensor upgrades add their own actions in probe_<upgrade>.h (exit codes: payload 30-39,
 * netattr 40-49, unixproto 50-59, packets 60-69, sysall 80-89, gaps 90-99).
 * Usage: linux_ebpf_probe DIRECTORY, or linux_ebpf_probe --exec PROGRAM ARGS... (exec it: a tracked
 * program the test starts from the scope, e.g. wine). tests/ebpf_checks/gaps.sh also runs it as
 * --sleep SECONDS (a tracked target, a stand-in kfilterd), --read PID (an outside reader of another process's memory
 * and maps), --kill0 PID (kill(PID, 0): self-protection) and --unload LIBRARY (dlopen, 3 s, dlclose, 3 s: the maps
 * poll sees it come and go); tests/ebpf_checks/unixproto.sh as --x11 SOCKET (an X11 client of that display). */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <asm/prctl.h>
#include <linux/aio_abi.h>
#include <linux/io_uring.h>
#include <linux/keyctl.h>
#include <ucontext.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <signal.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/shm.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include "probe_payload.h"
#include "probe_netattr.h"
#include "probe_packets.h"
#include "probe_sysall.h"
#include "probe_gaps.h"
#include "probe_unix.h"
#include <dlfcn.h>

/* A Wine-like TEB: NT_TIB.Self at +0x30, ClientId (Windows pid, tid) at +0x40; glibc x86_64 leaves GS unused. */
static unsigned long long fake_teb[0x400 / 8] __attribute__((aligned(64)));

static int burstFd;
static void* burst_main(void* unused)
{
    char byte;
    (void)unused;
    for (int index = 0; index < 50; index++) {
        if (pread(burstFd, &byte, 1, index % 5) != 1) return (void*)1;
    }
    return NULL;
}

static char remoteArea[512];

static void* thread_main(void* unused)
{
    (void)unused;
    fake_teb[0x30 / 8] = (unsigned long long)(unsigned long)fake_teb;
    fake_teb[0x40 / 8] = 0x1234;
    fake_teb[0x48 / 8] = 0x5678;
    (void)syscall(SYS_arch_prctl, ARCH_SET_GS, fake_teb);
    int fd = open("/proc/self/stat", O_RDONLY);
    if (fd >= 0) close(fd);
    return NULL;
}

static volatile int faulted;
static void on_fault(int sig, siginfo_t* info, void* context)
{
    /* CPUID or RDTSC faulted (SI_KERNEL): turn it back on; the instruction runs again on return. */
    (void)sig, (void)info, (void)context;
    faulted++;
    (void)syscall(SYS_arch_prctl, ARCH_SET_CPUID, 1);
    (void)prctl(PR_SET_TSC, PR_TSC_ENABLE);
}

static void on_usr2(int sig) { (void)sig; }

/* One RDTSC site: with faulting on it faults, the handler turns faulting off, it runs again. */
static __attribute__((noinline)) void trapped_rdtsc(void)
{
    unsigned low, high;
    if (prctl(PR_SET_TSC, PR_TSC_SIGSEGV) == 0) __asm__ volatile("rdtsc" : "=a"(low), "=d"(high));
}

/* One io_uring operation on the ring kernel_events sets up: its CQE's res. */
static struct {
    unsigned *tail, *mask, *head, *cmask;
    struct io_uring_sqe* sqes;
    struct io_uring_cqe* cqes;
    int fd;
} ring;
static int uring_op(struct io_uring_sqe* op)
{
    ring.sqes[0] = *op;   /* every sq array slot names sqe 0 */
    __atomic_store_n(ring.tail, *ring.tail + 1, __ATOMIC_RELEASE);
    if (syscall(SYS_io_uring_enter, ring.fd, 1, 1, IORING_ENTER_GETEVENTS, NULL, 0) < 0) return -1000;
    int res = ring.cqes[*ring.head & *ring.cmask].res;
    __atomic_store_n(ring.head, *ring.head + 1, __ATOMIC_RELEASE);
    return res;
}

static int kernel_events(void)
{
    /* io_uring (raw syscalls, no liburing): openat, write, read, close. */
    struct io_uring_params params;
    memset(&params, 0, sizeof(params));
    ring.fd = (int)syscall(SYS_io_uring_setup, 4, &params);
    if (ring.fd < 0) return 70;
    size_t sqBytes = params.sq_off.array + params.sq_entries * sizeof(unsigned),
           cqBytes = params.cq_off.cqes + params.cq_entries * sizeof(struct io_uring_cqe);
    char* sq = mmap(NULL, sqBytes > cqBytes ? sqBytes : cqBytes, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring.fd,
                    IORING_OFF_SQ_RING);
    ring.sqes = mmap(NULL, params.sq_entries * sizeof(struct io_uring_sqe), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                     ring.fd, IORING_OFF_SQES);
    if (sq == MAP_FAILED || ring.sqes == MAP_FAILED || !(params.features & IORING_FEAT_SINGLE_MMAP)) return 71;
    ring.tail = (unsigned*)(sq + params.sq_off.tail);
    ring.mask = (unsigned*)(sq + params.sq_off.ring_mask);
    ring.head = (unsigned*)(sq + params.cq_off.head);
    ring.cmask = (unsigned*)(sq + params.cq_off.ring_mask);
    ring.cqes = (struct io_uring_cqe*)(sq + params.cq_off.cqes);
    unsigned* array = (unsigned*)(sq + params.sq_off.array);
    for (unsigned index = 0; index < params.sq_entries; index++) array[index] = 0;   /* every slot submits sqe 0 */
    char text[8] = "uring!", back[8] = {0};
    struct io_uring_sqe op;
    memset(&op, 0, sizeof(op));
    op.opcode = IORING_OP_OPENAT;
    op.fd = AT_FDCWD;
    op.addr = (unsigned long)"probe-uring.txt";
    op.open_flags = O_CREAT | O_RDWR | O_TRUNC;
    op.len = 0600;
    int file = uring_op(&op);
    if (file < 0) return 72;
    memset(&op, 0, sizeof(op));
    op.opcode = IORING_OP_WRITE;
    op.fd = file;
    op.addr = (unsigned long)text;
    op.len = 6;
    if (uring_op(&op) != 6) return 73;
    op.opcode = IORING_OP_READ;
    op.addr = (unsigned long)back;
    if (uring_op(&op) != 6) return 73;
    memset(&op, 0, sizeof(op));
    op.opcode = IORING_OP_CLOSE;
    op.fd = file;
    if (uring_op(&op) != 0) return 73;
    close(ring.fd);
    unlink("probe-uring.txt");

    /* Linux AIO: one pwrite. */
    aio_context_t aio = 0;
    int target = open("probe-aio.txt", O_CREAT | O_RDWR | O_TRUNC, 0600);
    if (target < 0 || syscall(SYS_io_setup, 1, &aio) != 0) return 74;
    struct iocb block;
    memset(&block, 0, sizeof(block));
    block.aio_lio_opcode = IOCB_CMD_PWRITE;
    block.aio_fildes = (unsigned)target;
    block.aio_buf = (unsigned long)text;
    block.aio_nbytes = 6;
    struct iocb* blocks[1] = {&block};
    struct io_event done;
    if (syscall(SYS_io_submit, aio, 1, blocks) != 1 || syscall(SYS_io_getevents, aio, 1, 1, &done, NULL) != 1) return 74;
    syscall(SYS_io_destroy, aio);
    close(target);
    unlink("probe-aio.txt");

    /* A PE image in anonymous memory (a manual map): headers at a 64 KiB boundary, .text at +0x1000, .rdata (the
     * export directory naming msmonprobe.dll) at +0x2000. It stays mapped: the agent reads it after this call. */
    char* area = mmap(NULL, 0x30000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (area == MAP_FAILED) return 75;
    unsigned char* pe = (unsigned char*)(((unsigned long)area + 0xffff) & ~0xfffful);
    const unsigned optional = 0x58, sections = optional + 0xf0;
    pe[0] = 'M', pe[1] = 'Z';
    *(unsigned*)(pe + 0x3c) = 0x40;
    memcpy(pe + 0x40, "PE\0\0", 4);
    *(unsigned short*)(pe + 0x44) = 0x8664;   /* machine */
    *(unsigned short*)(pe + 0x46) = 2;        /* sections */
    *(unsigned*)(pe + 0x48) = 0x5eadbeef;     /* TimeDateStamp */
    *(unsigned short*)(pe + 0x54) = 0xf0;     /* SizeOfOptionalHeader */
    *(unsigned short*)(pe + optional) = 0x20b;
    *(unsigned*)(pe + optional + 56) = 0x3000;   /* SizeOfImage */
    *(unsigned*)(pe + optional + 108) = 16;      /* NumberOfRvaAndSizes */
    *(unsigned*)(pe + optional + 112) = 0x2000;  /* export directory */
    *(unsigned*)(pe + optional + 116) = 0x40;
    for (int index = 0; index < 2; index++) {
        unsigned char* section = pe + sections + index * 40;
        memcpy(section, index ? ".rdata" : ".text", index ? 6 : 5);
        *(unsigned*)(section + 8) = 0x1000;
        *(unsigned*)(section + 12) = 0x1000 * (index + 1);
        *(unsigned*)(section + 16) = 0x1000;
        *(unsigned*)(section + 20) = 0x400 * (index + 1);
        *(unsigned*)(section + 36) = index ? 0x40000040 : 0x60000020;
    }
    *(unsigned*)(pe + 0x2000 + 12) = 0x2040;
    strcpy((char*)pe + 0x2040, "msmonprobe.dll");
    if (mprotect(pe + 0x1000, 0x1000, PROT_READ | PROT_EXEC) != 0) return 75;

    /* CPUID and RDTSC faulting: each faults once (SIGSEGV SI_KERNEL), the handler turns it off, it runs again. */
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_sigaction = on_fault;
    action.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &action, NULL);
    unsigned a = 0, b, c = 0, d;
    if (syscall(SYS_arch_prctl, ARCH_SET_CPUID, 0) == 0) __asm__ volatile("cpuid" : "+a"(a), "=b"(b), "+c"(c), "=d"(d));
    trapped_rdtsc();
    trapped_rdtsc();
    signal(SIGSEGV, SIG_DFL);
    /* UMIP: the kernel emulates SGDT with a dummy value. */
    unsigned char gdt[10];
    __asm__ volatile("sgdt %0" : "=m"(gdt));
    (void)syscall(SYS_keyctl, KEYCTL_GET_KEYRING_ID, KEY_SPEC_SESSION_KEYRING, 0);
    int decnet = socket(12 /* AF_DECnet: no module, so only the request */, SOCK_SEQPACKET, 0);
    if (decnet >= 0) close(decnet);

    /* A shared file mapping: 3 pages read, 1 written. */
    int shared = open("probe-shared.txt", O_CREAT | O_RDWR | O_TRUNC, 0600);
    if (shared < 0 || ftruncate(shared, 3 * 4096) != 0) return 76;
    volatile char* view = mmap(NULL, 3 * 4096, PROT_READ | PROT_WRITE, MAP_SHARED, shared, 0);
    if (view == MAP_FAILED) return 76;
    char sum = 0;
    for (int page = 0; page < 3; page++) sum += view[page * 4096];
    view[0] = sum + 1;
    munmap((void*)view, 3 * 4096);
    close(shared);
    unlink("probe-shared.txt");
    return 0;
}

/* /proc/<pid>/mem (attach), process_vm_readv, maps and stat of another process (an outside reader's checks). */
static int read_target(int target)
{
    char path[64], buffer[64];
    long value = 0;
    snprintf(path, sizeof(path), "/proc/%d/mem", target);
    int fd = open(path, O_RDONLY);
    if (fd >= 0) close(fd);
    struct iovec local = {&value, sizeof(value)}, remote = {(void*)0x400000, sizeof(value)};
    (void)process_vm_readv(target, &local, 1, &remote, 1, 0);
    static const char* const names[] = {"maps", "stat"};
    for (int index = 0; index < 2; index++) {
        snprintf(path, sizeof(path), "/proc/%d/%s", target, names[index]);
        fd = open(path, O_RDONLY);
        if (fd >= 0 && read(fd, buffer, sizeof(buffer)) < 0) return 1;
        if (fd >= 0) close(fd);
    }
    return 0;
}

int main(int argc, char** argv)
{
    char buffer[64];
    if (argc >= 3 && strcmp(argv[1], "--exec") == 0) {
        execvp(argv[2], argv + 2);
        return 127;
    }
    if (argc == 3 && strcmp(argv[1], "--sleep") == 0) {
        sleep((unsigned)atoi(argv[2]));
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "--kill0") == 0) return kill(atoi(argv[2]), 0) == 0 ? 0 : errno == EPERM ? 1 : 2;
    if (argc == 3 && strcmp(argv[1], "--x11") == 0) return probe_unix(argv[2]);   /* a display socket's path */
    if (argc == 3 && strcmp(argv[1], "--unload") == 0) {
        void* library = dlopen(argv[2], RTLD_NOW);
        if (library == NULL) return 1;
        sleep(3);
        dlclose(library);
        sleep(3);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "--read") == 0) return read_target(atoi(argv[2]));
    if ((argc == 4 || argc == 5) && strcmp(argv[1], "--twice") == 0) {   /* File read twice, Seconds idle, a Marker */
        for (int index = 0; index < 2; index++) {
            int fd = open(argv[2], O_RDONLY);
            if (fd < 0 || read(fd, buffer, 1) < 0) return 1;
            close(fd);
        }
        sleep((unsigned)atoi(argv[3]));
        int marker = argc == 5 ? open(argv[4], O_CREAT | O_WRONLY, 0600) : -1;
        if (marker >= 0) close(marker);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "--kfilterd") == 0) {   /* a stand-in kfilterd: 20 s, reading the pid File names */
        int done = 0;
        for (int tick = 0; tick < 200; tick++) {
            FILE* file = done ? NULL : fopen(argv[2], "r");
            int target = 0;
            if (file != NULL && fscanf(file, "%d", &target) == 1 && target > 0) done = read_target(target) == 0;
            if (file != NULL) fclose(file);
            usleep(100000);
        }
        return 0;
    }
    if (argc != 2 || chdir(argv[1]) != 0) return 2;

    pthread_t thread;
    if (pthread_create(&thread, NULL, thread_main, NULL) == 0) pthread_join(thread, NULL);

    int fd = open("probe-a.txt", O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0 || write(fd, "hello from the probe\n", 21) != 21) return 3;
    close(fd);
    fd = open("probe-a.txt", O_RDONLY);
    if (fd < 0 || read(fd, buffer, sizeof(buffer)) <= 0) return 4;
    close(fd);
    if (rename("probe-a.txt", "probe-b.txt") != 0) return 5;
    if (chmod("probe-b.txt", 0644) != 0) return 6;
    fd = open("probe-b.txt", O_RDONLY);
    void* mapping = fd >= 0 ? mmap(NULL, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0) : MAP_FAILED;
    if (mapping == MAP_FAILED) return 7;
    /* Unmapped at once: image_load must come from the mapping itself, not the 2 s maps poll. */
    munmap(mapping, 4096);
    close(fd);
    fd = open("probe-x.txt", O_CREAT | O_RDWR | O_TRUNC, 0600);
    if (fd < 0 || write(fd, buffer, 64) != 64) return 27;
    mapping = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
    if (mapping == MAP_FAILED || mprotect(mapping, 4096, PROT_READ | PROT_EXEC) != 0) return 28;
    munmap(mapping, 4096);
    close(fd);
    unlink("probe-x.txt");
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_type = BPF_MAP_TYPE_ARRAY;
    attr.key_size = 4;
    attr.value_size = 4;
    attr.max_entries = 1;
    int map = (int)syscall(SYS_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
    if (map >= 0) close(map);
    else if (errno == EPERM) fprintf(stderr, "probe: bpf() refused (EPERM)\n");
    const char* agent = getenv("MSMON_AGENT_PID");
    if (agent && kill(atoi(agent), 0) == 0) fprintf(stderr, "probe: kill(agent, 0) was allowed\n");
    if (unlink("probe-b.txt") != 0) return 8;
    /* Three failed opens in a second: one record, the other two counted into a repeats_tail with the errno. */
    for (int index = 0; index < 3; index++) {
        if (open("probe-missing.txt", O_RDONLY) >= 0) return 9;
    }

    int listener = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t length = sizeof(address);
    if (listener < 0 || bind(listener, (struct sockaddr*)&address, sizeof(address)) != 0 || listen(listener, 1) != 0 ||
        getsockname(listener, (struct sockaddr*)&address, &length) != 0) return 10;
    int client = socket(AF_INET, SOCK_STREAM, 0);
    if (client < 0 || connect(client, (struct sockaddr*)&address, sizeof(address)) != 0) return 11;
    struct sockaddr_in peer;
    socklen_t peerLength = sizeof(peer);
    int accepted = accept(listener, (struct sockaddr*)&peer, &peerLength);
    if (accepted < 0) return 12;
    if (shutdown(client, SHUT_WR) != 0) return 21;
    close(accepted);
    close(client);
    close(listener);

    int pipeFds[2];
    if (pipe(pipeFds) != 0) return 13;
    struct sigaction usr2;
    memset(&usr2, 0, sizeof(usr2));
    usr2.sa_handler = on_usr2;
    usr2.sa_flags = SA_RESTART;
    sigaction(SIGUSR2, &usr2, NULL);
    pid_t child = fork();
    if (child == 0) {
        close(pipeFds[0]);
        fd = open("probe-child.txt", O_CREAT | O_WRONLY, 0600);
        if (fd >= 0) close(fd);
        unlink("probe-child.txt");
        if (write(pipeFds[1], "x", 1) != 1) _exit(1);
        sleep(1);
        kill(getppid(), SIGUSR2);
        if (getuid() == 0) (void)(setresgid(65534, 65534, 65534) || setresuid(65534, 65534, 65534));
        _exit(0);
    }
    close(pipeFds[1]);
    if (read(pipeFds[0], buffer, 1) != 1) return 14;
    struct iovec local = {buffer, 8}, remote = {&address, 8};
    (void)process_vm_readv(child, &local, 1, &remote, 1, 0);
    for (int index = 0; index < 50; index++) {   /* 50 addresses: 50 records, none collapsed */
        remote.iov_base = remoteArea + index * 8;
        (void)process_vm_readv(child, &local, 1, &remote, 1, 0);
    }
    int status = 0;
    waitpid(child, &status, 0);

    fd = open("probe-burst.txt", O_CREAT | O_RDWR | O_TRUNC, 0600);
    if (fd < 0 || write(fd, "burst", 5) != 5) return 15;
    burstFd = fd;
    void* burstFailed = NULL;
    if (pthread_create(&thread, NULL, burst_main, NULL) != 0 || pthread_join(thread, &burstFailed) != 0 || burstFailed)
        return 15;
    for (int index = 0; index < 50; index++) {
        if (pread(fd, buffer, 1, index % 5) != 1) return 15;
    }
    close(fd);
    /* The same open (path and flags) succeeds, then fails within a second: both are recorded. */
    fd = open("probe-burst.txt", O_RDONLY);
    if (fd < 0) return 16;
    close(fd);
    if (unlink("probe-burst.txt") != 0 || open("probe-burst.txt", O_RDONLY) >= 0) return 17;

    int receiver = socket(AF_INET, SOCK_DGRAM, 0), sender = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in udp;
    memset(&udp, 0, sizeof(udp));
    udp.sin_family = AF_INET;
    udp.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t udpLength = sizeof(udp);
    if (receiver < 0 || sender < 0 || bind(receiver, (struct sockaddr*)&udp, sizeof(udp)) != 0 ||
        getsockname(receiver, (struct sockaddr*)&udp, &udpLength) != 0) return 18;
    struct iovec datagram = {buffer, 4};
    struct msghdr message;
    memset(&message, 0, sizeof(message));
    message.msg_name = &udp;
    message.msg_namelen = sizeof(udp);
    message.msg_iov = &datagram;
    message.msg_iovlen = 1;
    if (sendmsg(sender, &message, 0) != 4) return 19;
    struct sockaddr_in from;
    memset(&message, 0, sizeof(message));
    message.msg_name = &from;
    message.msg_namelen = sizeof(from);
    message.msg_iov = &datagram;
    message.msg_iovlen = 1;
    if (recvmsg(receiver, &message, 0) != 4) return 20;
    close(sender);
    close(receiver);

    struct utsname uts;
    struct sysinfo info;
    if (uname(&uts) != 0 || sysinfo(&info) != 0) return 22;
    int watcher = inotify_init1(0);
    if (watcher < 0 || inotify_add_watch(watcher, ".", IN_CREATE) < 0) return 23;
    close(watcher);
    int memory = memfd_create("probe-memfd", 0);
    if (memory < 0) return 24;
    close(memory);
    fd = open("probe-sync.txt", O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0 || write(fd, "x", 1) != 1 || fsync(fd) != 0) return 25;
    close(fd);
    unlink("probe-sync.txt");
    int segment = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0600);
    void* attached = segment >= 0 ? shmat(segment, NULL, 0) : (void*)-1;
    if (attached == (void*)-1) return 26;
    shmdt(attached);
    shmctl(segment, IPC_RMID, NULL);

    for (int index = 0; index < 3; index++) (void)syscall(SYS_getcpu, NULL, NULL, NULL);
    int uffd = (int)syscall(SYS_userfaultfd, 1 /* UFFD_USER_MODE_ONLY */);
    if (uffd >= 0) close(uffd);
    (void)syscall(SYS_arch_prctl, 0x1011 /* ARCH_GET_CPUID */, 0);
    if (syscall(SYS_clone3, NULL, 0) != -1) return 29;   /* EINVAL: no child */
    struct { unsigned long long value; unsigned size, flags; } xattr = {(unsigned long)buffer, sizeof(buffer), 0};
    (void)syscall(464 /* getxattrat */, AT_FDCWD, ".", 0, "user.msmon", &xattr, sizeof(xattr));
    unsigned long long lsms[16];
    unsigned lsmSize = sizeof(lsms);
    (void)syscall(461 /* lsm_list_modules */, lsms, &lsmSize, 0);
    int queue = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
    if (queue >= 0) msgctl(queue, IPC_RMID, NULL);

    int code = kernel_events();
    if (code == 0) code = probe_payload();
    if (code == 0) code = probe_netattr();
    if (code == 0) code = probe_packets();
    if (code == 0) code = probe_sysall();
    if (code == 0) code = probe_gaps();
    if (code != 0) return code;

    (void)prctl(PR_SET_PTRACER, 0, 0, 0, 0);
    child = fork();
    if (child == 0) {
        static char longArgument[601];
        memset(longArgument, 'a', 600);
        memcpy(longArgument + 590, "msmon-tail", 10);
        char* const environment[] = {"HOME=/", "WINEDEBUG=-all", NULL};
        execle("/bin/true", "true", longArgument, (char*)NULL, environment);
        _exit(1);
    }
    int pidfd = (int)syscall(SYS_pidfd_open, child, 0);
    if (pidfd >= 0) close(pidfd);
    waitpid(child, &status, 0);
    /* The native child is untracked: its files must not appear. */
    return 0;
}
