/* The gaps upgrade's probe actions (self-raised signals, calls stopped before sys_enter, direct syscalls, per-address
 * detail, fd-to-fd copies; checks in tests/ebpf_checks/check_gaps.py), in a forked child that exits 42 (its exit
 * code): an int3, 1000 touches of 1000 PROT_NONE pages at one ip (a guard-page storm), a hardware breakpoint (DR0, set
 * by the probe through ptrace) hit by a read, 5 getppid refused by a seccomp filter (EPERM) and one getpgrp trapped by
 * it (SIGSYS), one getppid stopped by syscall user dispatch, uname and 3 getpid from anonymous executable memory
 * (direct syscalls), a sendfile of probe-gaps.txt into an AF_UNIX socket. And from the probe: a process_vm_readv of
 * the child with 3 remote iovecs, a move_pages query of 2 of its pages, 3 preads of its /proc/<pid>/mem at 3 addresses.
 * Returns 0 or an exit code 90-99. */
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <sys/ptrace.h>
#include <sys/sendfile.h>
#include <sys/user.h>
#ifndef PR_SET_SYSCALL_USER_DISPATCH
#define PR_SET_SYSCALL_USER_DISPATCH 59
#endif

static volatile char gapsSelector;   /* syscall user dispatch: 1 blocks, 0 allows */
static volatile long gapsWatched;    /* DR0 watches it */
static char* gapsGuard;              /* 1000 PROT_NONE pages */

static void gaps_fault(int sig, siginfo_t* info, void* context)
{
    (void)context;
    if (sig == SIGSEGV) mprotect((void*)((unsigned long)info->si_addr & ~4095ul), 4096, PROT_READ | PROT_WRITE);
    if (sig == SIGSYS) gapsSelector = 0;   /* its sigreturn (in libc, not the vDSO) must pass dispatch */
}

/* uname(buffer) then 3 getpid with the syscall instruction in anonymous memory (Windows code's own syscalls look so). */
static int gaps_direct(void)
{
    static const unsigned char stub[] = {0x48, 0x89, 0xf8,   /* mov rax, rdi */
                                         0x48, 0x89, 0xf7,   /* mov rdi, rsi */
                                         0x0f, 0x05,         /* syscall */
                                         0xc3};              /* ret */
    unsigned char* code = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (code == MAP_FAILED) return 1;
    memcpy(code, stub, sizeof(stub));
    if (mprotect(code, 4096, PROT_READ | PROT_EXEC) != 0) return 1;
    long (*call)(long, void*) = (long (*)(long, void*))code;
    struct utsname uts;
    if (call(SYS_uname, &uts) != 0) return 1;
    for (int index = 0; index < 3; index++) call(SYS_getpid, NULL);
    munmap(code, 4096);
    return 0;
}

static int gaps_child(int ready)
{
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_sigaction = gaps_fault;
    action.sa_flags = SA_SIGINFO;
    sigaction(SIGTRAP, &action, NULL);
    sigaction(SIGSEGV, &action, NULL);
    sigaction(SIGSYS, &action, NULL);
    __asm__ volatile("int3");
    for (int page = 0; page < 1000; page++) gapsGuard[page * 4096] = 1;
    /* Stopped here while the probe sets DR0/DR7 through ptrace, then the read hits it. */
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0) return 1;
    raise(SIGSTOP);
    if (gapsWatched != 0) return 1;
    if (gaps_direct() != 0) return 1;
    int fd = open("probe-gaps.txt", O_CREAT | O_RDWR | O_TRUNC, 0600), pair[2];
    if (fd < 0 || write(fd, "gaps\n", 5) != 5 || socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0) return 1;
    off_t from = 0;
    if (sendfile(pair[0], fd, &from, 5) != 5) return 1;
    close(fd);
    unlink("probe-gaps.txt");
    /* syscall user dispatch: every call but the vDSO's traps while the selector blocks. */
    if (prctl(PR_SET_SYSCALL_USER_DISPATCH, 1, 0, 0, &gapsSelector) == 0) {
        gapsSelector = 1;
        (void)syscall(SYS_getppid);
        gapsSelector = 0;
        prctl(PR_SET_SYSCALL_USER_DISPATCH, 0, 0, 0, 0);
    }
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getppid, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getpgrp, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {sizeof(filter) / sizeof(filter[0]), filter};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 || syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program) != 0) return 1;
    for (int index = 0; index < 5; index++) {
        if (syscall(SYS_getppid) != -1 || errno != EPERM) return 1;
    }
    (void)syscall(SYS_getpgrp);
    if (write(ready, "x", 1) != 1) return 1;
    sleep(2);   /* the probe reads this process's memory meanwhile */
    return 42;
}

static int probe_gaps(void)
{
    gapsGuard = mmap(NULL, 1000 * 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    int ready[2];
    if (gapsGuard == MAP_FAILED || pipe(ready) != 0) return 90;
    pid_t child = fork();
    if (child == 0) _exit(gaps_child(ready[1]));
    int status = 0;
    if (child < 0 || waitpid(child, &status, WUNTRACED) != child || !WIFSTOPPED(status)) return 91;
    /* DR0 = &gapsWatched, DR7: L0, read/write (RW0 = 3), 8 bytes (LEN0 = 2). */
    if (ptrace(PTRACE_POKEUSER, child, offsetof(struct user, u_debugreg[0]), &gapsWatched) != 0 ||
        ptrace(PTRACE_POKEUSER, child, offsetof(struct user, u_debugreg[7]), 0x1ul | 3ul << 16 | 2ul << 18) != 0 ||
        ptrace(PTRACE_DETACH, child, NULL, (void*)0) != 0)
        return 92;
    char byte;
    if (read(ready[0], &byte, 1) != 1) return 93;
    char buffer[24];
    struct iovec local = {buffer, sizeof(buffer)}, remote[3] = {{(void*)&gapsWatched, 8}, {buffer, 8}, {&status, 4}};
    (void)process_vm_readv(child, &local, 1, remote, 3, 0);
    void* pages[2] = {(void*)&gapsWatched, gapsGuard};
    int where[2];
    (void)syscall(SYS_move_pages, child, 2, pages, NULL, where, 0);
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", child);
    int memory = open(path, O_RDONLY);
    if (memory >= 0) {
        for (int index = 0; index < 3; index++) {
            if (pread(memory, buffer, 8, (off_t)(unsigned long)(gapsGuard + index * 4096)) < 0) break;
        }
        close(memory);
    }
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 42) return 94;
    munmap(gapsGuard, 1000 * 4096);
    return 0;
}
