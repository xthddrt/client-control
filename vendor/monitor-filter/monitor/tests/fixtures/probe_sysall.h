/* The sysall upgrade's probe actions (every syscall recorded: kernel aggregates for the hot and once counted-only
 * calls, records for the rare ones; checks in tests/ebpf_checks/check_sysall.py): 1000 rt_sigprocmask(SIG_BLOCK),
 * 10 futex waits that fail (EAGAIN); anonymous memory that is not executable mapped RW, protected R and NONE, advised
 * away (MADV_DONTNEED), named (PR_SET_VMA "msmon-vma") and unmapped; an executable anonymous page grown by mremap
 * (the source flagged executable); brk(0); a record lock (F_SETLK) and flock on probe-lock.txt and 5 F_GETFL on it,
 * F_SETOWN and F_SETSIG on a pipe, F_ADD_SEALS on a memfd, F_NOTIFY on an empty directory; the thread renamed
 * (PR_SET_NAME "msmon-sysall"), chdir("."), umask(022), a SIGTRAP handler, getrandom(GRND_NONBLOCK), a child that
 * exits 7 (waited for: wait4) and syscall 511, which no kernel has. Returns 0 or an exit code 80-89. */
#include <linux/futex.h>
#include <sys/file.h>
#include <sys/random.h>
#ifndef PR_SET_VMA
#define PR_SET_VMA 0x53564d41
#define PR_SET_VMA_ANON_NAME 0
#endif

static int probe_sysall(void)
{
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    for (int index = 0; index < 1000; index++) (void)syscall(SYS_rt_sigprocmask, SIG_BLOCK, &set, NULL, 8);
    (void)syscall(SYS_rt_sigprocmask, SIG_UNBLOCK, &set, NULL, 8);
    static int word = 1;
    for (int index = 0; index < 10; index++) {
        if (syscall(SYS_futex, &word, FUTEX_WAIT_PRIVATE, 0, NULL, NULL, 0) != -1 || errno != EAGAIN) return 80;
    }

    const size_t size = 16 * 4096;
    char* area = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (area == MAP_FAILED) return 81;
    area[0] = 1;
    if (mprotect(area, 4096, PROT_READ) != 0 || mprotect(area + 4096, 4096, PROT_NONE) != 0 ||
        madvise(area + 8192, 8192, MADV_DONTNEED) != 0) return 82;
    (void)prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, (unsigned long)area, size, (unsigned long)"msmon-vma");
    if (munmap(area, size) != 0) return 83;
    char* code = mmap(NULL, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    char* moved = code == MAP_FAILED ? MAP_FAILED : mremap(code, 4096, 8192, MREMAP_MAYMOVE);
    if (moved == MAP_FAILED || munmap(moved, 8192) != 0) return 84;
    (void)syscall(SYS_brk, 0);

    int fd = open("probe-lock.txt", O_CREAT | O_RDWR | O_TRUNC, 0600);
    struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 1};
    if (fd < 0 || fcntl(fd, F_SETLK, &lock) != 0 || flock(fd, LOCK_EX) != 0) return 85;
    for (int index = 0; index < 5; index++) (void)fcntl(fd, F_GETFL);
    close(fd);
    unlink("probe-lock.txt");
    int fds[2];
    if (pipe(fds) != 0 || fcntl(fds[0], F_SETOWN, getpid()) != 0 || fcntl(fds[0], F_SETSIG, 0) != 0) return 86;
    close(fds[0]);
    close(fds[1]);
    int sealed = memfd_create("probe-seal", MFD_ALLOW_SEALING);
    if (sealed < 0 || fcntl(sealed, F_ADD_SEALS, F_SEAL_SHRINK) != 0) return 86;
    close(sealed);
    /* An empty directory: nothing is created in it, so dnotify never raises SIGIO (whose default kills). */
    int directory = mkdir("probe-notify", 0700) == 0 ? open("probe-notify", O_RDONLY | O_DIRECTORY) : -1;
    if (directory < 0 || fcntl(directory, F_NOTIFY, DN_CREATE) != 0) return 87;
    close(directory);
    rmdir("probe-notify");

    (void)prctl(PR_SET_NAME, "msmon-sysall", 0, 0, 0);
    if (chdir(".") != 0) return 88;
    umask(022);
    struct sigaction trap;
    memset(&trap, 0, sizeof(trap));
    trap.sa_handler = SIG_IGN;
    sigaction(SIGTRAP, &trap, NULL);
    char random[8];
    if (getrandom(random, sizeof(random), GRND_NONBLOCK) != sizeof(random)) return 88;
    pid_t child = fork();
    if (child == 0) _exit(7);
    int status = 0;
    if (child < 0 || waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 7) return 89;
    (void)syscall(511);
    return 0;
}
