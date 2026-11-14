/* The watchpoints' probe (tests/linux_watch_test.sh, root). Usage: watch_probe DIR.
 * Before the agent: a parked thread has its 4 debug registers taken by a tracer, as wineserver leaves a thread after a
 * SetThreadContext with debug registers; DIR/addresses gets "pid= main= parked= counter= flag=". Once DIR/go exists:
 * counter written 1000 times, flag read 500 times and written once, a thread started that sleeps 300 ms, writes
 * counter 100 times, creates DIR/late_written and ends once DIR/late_end exists; then DIR/late_joined, and once
 * DIR/continue exists a thread that sleeps 300 ms and writes counter 1,000,000 times (past the agent's hit cap); then
 * a tracer writes DR0-DR3 of the main thread, which the watches hold in part (the write past them fails ENOSPC);
 * DIR/result gets "late= hot= tracer= conflict_register= conflict_errno=". */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile uint32_t counter __attribute__((aligned(8)));
static volatile uint64_t flag __attribute__((aligned(8)));
static volatile pid_t parkedTid, lateTid, hotTid;
static int park[2];
static const char* directory;

/* Creates DIR/Name. */
static void mark(const char* name)
{
    char path[4096];
    snprintf(path, sizeof(path), "%s/%s", directory, name);
    FILE* file = fopen(path, "w");
    if (file != NULL) fclose(file);
}

/* Waits for DIR/Name (60 s at most): 0, or -1. */
static int await(const char* name)
{
    char path[4096];
    snprintf(path, sizeof(path), "%s/%s", directory, name);
    for (int i = 0; access(path, F_OK) != 0; i++) {
        if (i == 6000) return -1;
        usleep(10000);
    }
    return 0;
}

static void* parked(void* unused)
{
    (void)unused;
    parkedTid = (pid_t)syscall(SYS_gettid);
    char byte;
    while (read(park[0], &byte, 1) < 0 && errno == EINTR) {
    }
    return NULL;
}

static void* late(void* unused)
{
    (void)unused;
    lateTid = (pid_t)syscall(SYS_gettid);
    usleep(300000);   /* the agent opens a new thread's breakpoints within 100 ms */
    for (int i = 0; i < 100; i++) counter++;
    mark("late_written");   /* the test counts the agent's fds while this thread holds its breakpoints */
    await("late_end");
    return NULL;
}

static void* hot(void* unused)
{
    (void)unused;
    hotTid = (pid_t)syscall(SYS_gettid);
    usleep(300000);
    for (uint32_t i = 0; i < 1000000; i++) counter = i;
    return NULL;
}

/* As wineserver's set_thread_context: a child attaches to thread Tid and writes DR0-DR3 (each write registers a ptrace
 * breakpoint, which takes one of the thread's 4 debug registers). Returns the first register whose write failed and
 * sets *Error to its errno (-1: all four took); *Tracer is the child. */
static int take_debug_registers(pid_t tid, int* error, pid_t* tracer)
{
    int out[2];
    if (pipe(out) != 0) return *error = errno, 100;
    *tracer = fork();
    if (*tracer == 0) {
        int result[2] = {100, 0};
        int status;
        if (ptrace(PTRACE_SEIZE, tid, NULL, NULL) == 0 && ptrace(PTRACE_INTERRUPT, tid, NULL, NULL) == 0 &&
            waitpid(tid, &status, __WALL) == tid) {
            result[0] = -1;
            for (int dr = 0; dr < 4 && result[0] < 0; dr++) {
                if (ptrace(PTRACE_POKEUSER, tid, (void*)(offsetof(struct user, u_debugreg) + dr * sizeof(long)),
                           (void*)(uintptr_t)(0x10000 + dr * 8)) != 0) {
                    result[0] = dr;
                    result[1] = errno;
                }
            }
            ptrace(PTRACE_DETACH, tid, NULL, NULL);
        } else {
            result[1] = errno;
        }
        _exit(write(out[1], result, sizeof(result)) == sizeof(result) ? 0 : 1);
    }
    int result[2] = {100, ECHILD};
    close(out[1]);
    if (read(out[0], result, sizeof(result)) != sizeof(result)) result[0] = 100;
    close(out[0]);
    waitpid(*tracer, NULL, 0);
    *error = result[1];
    return result[0];
}

int main(int argc, char** argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: watch_probe DIR\n");
        return 2;
    }
    directory = argv[1];
    char path[4096];
    pthread_t parkThread, lateThread, hotThread;
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);   /* its own child traces it, also under Yama scope 1 without root */
    if (pipe(park) != 0 || pthread_create(&parkThread, NULL, parked, NULL) != 0) return 1;
    while (parkedTid == 0) usleep(1000);
    int error;
    pid_t tracer;
    const int parkedFailed = take_debug_registers(parkedTid, &error, &tracer);
    if (parkedFailed != -1) {
        fprintf(stderr, "watch_probe: the parked thread's debug registers: register %d failed, errno %d\n", parkedFailed, error);
        return 1;
    }
    snprintf(path, sizeof(path), "%s/addresses", directory);
    FILE* file = fopen(path, "w");
    if (file == NULL) return 1;
    fprintf(file, "pid=%d main=%d parked=%d counter=%p flag=%p\n", getpid(), (int)syscall(SYS_gettid), parkedTid,
            (void*)&counter, (void*)&flag);
    fclose(file);
    if (await("go") != 0) return 3;

    for (uint32_t i = 0; i < 1000; i++) counter = i;
    uint64_t sum = 0;
    for (int i = 0; i < 500; i++) sum += flag;
    flag = sum + 1;
    if (pthread_create(&lateThread, NULL, late, NULL) != 0) return 1;
    pthread_join(lateThread, NULL);
    mark("late_joined");
    if (await("continue") != 0) return 3;
    if (pthread_create(&hotThread, NULL, hot, NULL) != 0) return 1;
    pthread_join(hotThread, NULL);
    const int failed = take_debug_registers((pid_t)syscall(SYS_gettid), &error, &tracer);

    snprintf(path, sizeof(path), "%s/result", directory);
    file = fopen(path, "w");
    if (file == NULL) return 1;
    fprintf(file, "late=%d hot=%d tracer=%d conflict_register=%d conflict_errno=%d\n", lateTid, hotTid, tracer, failed, error);
    fclose(file);
    if (write(park[1], "x", 1) != 1) return 1;
    pthread_join(parkThread, NULL);
    return 0;
}
