/* The load of tests/linux_budget_test.sh (root): CALLS calls each of three hot syscalls the kernel aggregates
 * (rt_sigprocmask, a futex wait that fails with EAGAIN, a poll of no fd), made directly, and the nanoseconds each took
 * on average: "rt_sigprocmask=<ns> futex=<ns> poll=<ns> calls=<CALLS>".
 * "budget_probe watch STORES ROUNDS": the --watch rows (built -no-pie, so the test reads the watched addresses with nm):
 * ROUNDS futex round trips between two threads on one CPU, which hold the breakpoints of every watch but touch none
 * (watched and idle: what the switches cost), then STORES stores to watched (a hot address, closed at the agent's hit
 * cap): "pingpong=<ns per round trip> store_ms=<ms for all stores>".
 * "budget_probe io CALLS": a native helper's busiest I/O (a browser's eventfd wake-ups and its IPC over AF_UNIX socket
 * pairs), run from outside the scope so the agent tracks it as a native helper: CALLS eventfd writes and reads and CALLS
 * sends and receives of 64 bytes on a socket pair, "eventfd_write=<ns> eventfd_read=<ns> unix_send_recv=<ns a pair>".
 * "budget_probe browser SECONDS": a kept browser's steady calls that stay records for a native helper, at an assumed
 * 300 opens (and reads) of /proc/self/stat and 100 memfd_create a second for SECONDS: "opens=<n> memfds=<n>". */
#define _GNU_SOURCE
#include <linux/futex.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

volatile uint32_t watched __attribute__((aligned(8)));
volatile uint64_t idle[3] __attribute__((aligned(8)));
static int turn;   /* whose turn: 0 the main thread's, 1 the partner's */

static double Now(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return now.tv_sec * 1e9 + now.tv_nsec;
}

/* Waits until turn is Want, then gives the turn to the other thread. */
static void Pass(int want)
{
    while (__atomic_load_n(&turn, __ATOMIC_ACQUIRE) != want) syscall(SYS_futex, &turn, FUTEX_WAIT_PRIVATE, !want, NULL, NULL, 0);
    __atomic_store_n(&turn, !want, __ATOMIC_RELEASE);
    syscall(SYS_futex, &turn, FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0);
}

static void* Partner(void* rounds)
{
    for (long index = 0; index < (long)rounds; index++) Pass(1);
    return NULL;
}

static int Watch(long stores, long rounds)
{
    cpu_set_t one;
    CPU_ZERO(&one);
    CPU_SET(sched_getcpu(), &one);
    sched_setaffinity(0, sizeof(one), &one);   /* the partner inherits it: every round trip is two switches */
    usleep(500000);                            /* the agent opens a new thread's breakpoints within 100 ms */
    pthread_t partner;
    if (pthread_create(&partner, NULL, Partner, (void*)rounds) != 0) return 1;
    usleep(500000);
    const double start = Now();
    for (long index = 0; index < rounds; index++) Pass(0);
    const double passed = Now();
    pthread_join(partner, NULL);
    const double stored = Now();
    for (long index = 0; index < stores; index++) watched = (uint32_t)index;
    printf("pingpong=%.0f store_ms=%.1f stores=%ld rounds=%ld\n", (passed - start) / rounds, (Now() - stored) / 1e6, stores, rounds);
    return 0;
}

static int Io(long calls)
{
    int wake = eventfd(0, 0), pair[2];
    if (wake < 0 || socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0) return 1;
    uint64_t one = 1;
    char bytes[64] = {0};
    const double start = Now();
    for (long index = 0; index < calls; index++) (void)!write(wake, &one, sizeof(one));
    const double written = Now();
    for (long index = 0; index < calls; index++) {
        (void)!write(wake, &one, sizeof(one));   /* not timed apart: each read takes the count one write left */
        (void)!read(wake, &one, sizeof(one));
    }
    const double read = Now();
    for (long index = 0; index < calls; index++) {
        (void)!send(pair[0], bytes, sizeof(bytes), 0);
        (void)!recv(pair[1], bytes, sizeof(bytes), 0);
    }
    const double passed = Now();
    const double each = (written - start) / calls;
    printf("eventfd_write=%.0f eventfd_read=%.0f unix_send_recv=%.0f calls=%ld\n", each, (read - written) / calls - each,
           (passed - read) / calls, calls);
    return 0;
}

static int Browser(long seconds)
{
    long opens = 0, memfds = 0;
    char bytes[512];
    for (long tick = 0; tick < seconds * 100; tick++) {   /* every 10 ms: 3 opens and a memfd_create */
        for (int index = 0; index < 3; index++, opens++) {
            int fd = open("/proc/self/stat", O_RDONLY | O_CLOEXEC);
            if (fd < 0) return 1;
            (void)!read(fd, bytes, sizeof(bytes));
            close(fd);
        }
        int shared = memfd_create("budget", MFD_CLOEXEC);
        if (shared < 0) return 1;
        close(shared);
        memfds++;
        usleep(10000);
    }
    printf("opens=%ld memfds=%ld\n", opens, memfds);
    return 0;
}

int main(int argc, char** argv)
{
    if (argc == 3 && strcmp(argv[1], "io") == 0) return atol(argv[2]) > 0 ? Io(atol(argv[2])) : 2;
    if (argc == 3 && strcmp(argv[1], "browser") == 0) return atol(argv[2]) > 0 ? Browser(atol(argv[2])) : 2;
    if (argc == 4 && strcmp(argv[1], "watch") == 0) {
        const long stores = atol(argv[2]), rounds = atol(argv[3]);
        return stores > 0 && rounds > 0 ? Watch(stores, rounds) : 2;
    }
    const long calls = argc > 1 ? atol(argv[1]) : 1000000;
    if (calls <= 0) return 2;
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    static int word = 1;
    const double start = Now();
    for (long index = 0; index < calls; index++) syscall(SYS_rt_sigprocmask, SIG_BLOCK, &set, NULL, 8);
    const double masked = Now();
    for (long index = 0; index < calls; index++) syscall(SYS_futex, &word, FUTEX_WAIT_PRIVATE, 0, NULL, NULL, 0);
    const double waited = Now();
    for (long index = 0; index < calls; index++) syscall(SYS_poll, NULL, 0, 0);
    const double polled = Now();
    printf("rt_sigprocmask=%.0f futex=%.0f poll=%.0f calls=%ld\n", (masked - start) / calls, (waited - masked) / calls,
           (polled - waited) / calls, calls);
    return 0;
}
