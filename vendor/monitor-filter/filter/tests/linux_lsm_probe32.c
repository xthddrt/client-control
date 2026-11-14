/* lsm-probe32: an i386 program for tests/linux_lsm_test.sh's ABI 11 rows, built without a C library (build.sh, where
 * the compiler makes i386 code): its syscalls go through the ia32 entry points (compat ones where the kernel has them)
 * and are decided as /system/syscall/<name>[/<key>] under their x86_64 names. Prints "name=denied" when a call failed
 * with EPERM or EACCES and "name=ok" otherwise, as lsm-probe does. */

static long sys(long number, long a, long b, long c, long d, long e)
{
    long result;
    __asm__ volatile("push %%ebp\n\txor %%ebp, %%ebp\n\tint $0x80\n\tpop %%ebp"   /* a sixth argument of 0 */
                     : "=a"(result) : "a"(number), "b"(a), "c"(b), "d"(c), "S"(d), "D"(e) : "memory");
    return result;
}

static void say(const char* text)
{
    long n = 0;
    while (text[n]) n++;
    sys(4, 1, (long)text, n, 0, 0);   /* write */
}

static void report(const char* name, long result)
{
    say(name);
    say(result == -1 || result == -13 ? "=denied\n" : "=ok\n");   /* -EPERM, -EACCES */
}

void _start(void)
{
    static char old[64];
    static short lock[8];   /* struct flock: F_RDLCK of the whole file */
    report("sc32_sigaction_trap", sys(174, 5, 0, (long)old, 8, 0));    /* rt_sigaction(SIGTRAP), compat */
    report("sc32_sigaction_usr1", sys(174, 10, 0, (long)old, 8, 0));
    report("sc32_getppid", sys(64, 0, 0, 0, 0, 0));                     /* __do_sys_getppid */
    long fd = sys(5, (long)".", 0, 0, 0, 0);                              /* open(".", O_RDONLY) */
    report("sc32_fcntl64_setlk", fd < 0 ? fd : sys(221, fd, 6, (long)lock, 0, 0));   /* fcntl64 F_SETLK: fcntl/6 */
    report("sc32_fcntl64_getfl", fd < 0 ? fd : sys(221, fd, 3, 0, 0, 0));
    /* mmap2 of three pages at 0x52000000 (MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE), then munmap by addr= */
    if (sys(192, 0x52000000, 0x3000, 3, 0x100022, -1) == 0x52000000) {
        report("sc32_munmap_in", sys(91, 0x52001000, 0x1000, 0, 0, 0));
        report("sc32_munmap_out", sys(91, 0x52000000, 0x1000, 0, 0, 0));
    } else {
        say("sc32_munmap_setup=failed\n");
    }
    sys(1, 0, 0, 0, 0, 0);   /* exit */
}
