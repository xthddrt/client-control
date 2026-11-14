/*
 * ia32 probe for tests/ebpf_checks/ia32.sh (root): a 32-bit process making ia32 syscalls, as the 32-bit Wine
 * programs (Nexon launcher, nexon_client, NGService) do on a Wine built with i386-unix (old WoW64). It looks
 * like a Wine i386 thread inside a syscall: a set_thread_area TEB (Self +0x18, ClientId +0x20) whose
 * syscall_frame (+0x218) holds eip 0x7bc01234 and esp pointing at a stack whose first word is 0x7bc05678, and
 * kernel_stack (+0x23c) 0, so every syscall carries an ia32 PE context (pe_i386=1). Then it does:
 *   open(ia32-a.txt, O_CREAT) + write 6 bytes + close, stat64 of it, a failing open of ia32-missing.txt,
 *   mmap2 of ia32-a.txt with PROT_READ|PROT_EXEC at offset 0 (image_load), unmapped at once (as the x64 probe's
 *   probe-b.txt: the image_load must come from the mmap record, not from a /proc maps scan that ran first), a
 *   UDP sendmsg of "ia32" to a bound loopback socket and its recvfrom (compat msghdr/iovec: peer address and
 *   payload bytes), all socket calls through socketcall(102) as 32-bit glibc makes them, a SysV segment through
 *   ipc(117) (shmget, shmat, shmdt, shmctl) and olduname(109), a msgrcv as 32-bit glibc makes it (ipc version 0: msgp
 *   and msgtyp 5 in an ipc_kludge; the queue is empty) and fanotify_mark of ia32-a.txt (its 64-bit mask in two registers).
 * Every syscall recorded (check_sysall.py): old_mmap (90, a struct, as Wine's i386 preloader maps) of ia32-a.txt
 *   PROT_READ|PROT_EXEC for 8 KiB and of 8 KiB anonymous RW memory, that memory mprotect'ed PROT_READ and unmapped,
 *   _llseek(SEEK_END), a read lock by fcntl64(F_SETLK64) and an F_GETFL by fcntl (55), rt_sigprocmask(SIG_BLOCK).
 * Freestanding (no libc): builds with gcc -m32 where no 32-bit libc is installed. Run in the directory to use.
 * Exit 0 = every syscall worked.
 */
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

enum { NR_WRITE = 4, NR_OPEN = 5, NR_CLOSE = 6, NR_FCNTL = 55, NR_OLD_MMAP = 90, NR_MUNMAP = 91, NR_SOCKETCALL = 102,
       NR_OLDUNAME = 109, NR_IPC = 117, NR_MPROTECT = 125, NR_LLSEEK = 140, NR_RT_SIGPROCMASK = 175, NR_STAT64 = 195,
       NR_MMAP2 = 192, NR_FCNTL64 = 221, NR_SET_THREAD_AREA = 243, NR_EXIT_GROUP = 252, NR_FANOTIFY_INIT = 338,
       NR_FANOTIFY_MARK = 339 };
/* socketcall and ipc subcalls (linux/net.h, ipc/syscall.c) */
enum { SYS_SOCKET = 1, SYS_BIND = 2, SYS_GETSOCKNAME = 6, SYS_RECVFROM = 12, SYS_SENDMSG = 16 };
enum { MSGRCV = 12, MSGGET = 13, MSGCTL = 14, SHMAT = 21, SHMDT = 22, SHMGET = 23, SHMCTL = 24 };

static long sys6(long n, long a, long b, long c, long d, long e, long f)
{
    long r, nf[2] = {n, f};
    /* ebp carries the 6th argument: loaded through eax (not an esp-relative operand) and restored after. */
    __asm__ volatile("push %%ebp\n\tmov 4(%%eax), %%ebp\n\tmov (%%eax), %%eax\n\tint $0x80\n\tpop %%ebp"
                     : "=a"(r)
                     : "a"(nf), "b"(a), "c"(b), "d"(c), "S"(d), "D"(e)
                     : "memory");
    return r;
}
#define sys3(n, a, b, c) sys6(n, (long)(a), (long)(b), (long)(c), 0, 0, 0)

void* memset(void* d, int c, unsigned long n)
{
    u8* p = d;
    while (n--) *p++ = (u8)c;
    return d;
}

static u8 teb[0x1000] __attribute__((aligned(4096)));
static u8 pestack[64];
static u8 statbuf[256];
static int failed;

static long check(long ret)
{
    if (ret < 0 && ret > -4096) failed = 1;
    return ret;
}

static long socketcall(u32 call, u32 a, u32 b, u32 c, u32 d, u32 e, u32 f)
{
    u32 args[6] = {a, b, c, d, e, f};
    return check(sys3(NR_SOCKETCALL, call, args, 0));
}

static void put32(u8* p, u32 v)
{
    for (int i = 0; i < 4; i++) p[i] = (u8)(v >> (8 * i));
}

struct sockaddr_in32 {
    u16 family;
    u16 port;
    u32 addr;
    u8 zero[8];
};

__attribute__((noinline)) static void actions(void)
{
    long fd = check(sys3(NR_OPEN, "ia32-a.txt", 0101 /* O_WRONLY|O_CREAT */, 0600));
    check(sys3(NR_WRITE, fd, "hello\n", 6));
    check(sys3(NR_CLOSE, fd, 0, 0));
    check(sys3(NR_STAT64, "ia32-a.txt", statbuf, 0));
    if (sys3(NR_OPEN, "ia32-missing.txt", 0, 0) >= 0) failed = 1;
    fd = check(sys3(NR_OPEN, "ia32-a.txt", 0, 0));
    long mapping = check(sys6(NR_MMAP2, 0, 4096, 5 /* PROT_READ|PROT_EXEC */, 2 /* MAP_PRIVATE */, fd, 0));
    check(sys3(NR_MUNMAP, mapping, 4096, 0));
    check(sys3(NR_CLOSE, fd, 0, 0));

    long receiver = socketcall(SYS_SOCKET, 2, 2 /* SOCK_DGRAM */, 0, 0, 0, 0);
    long sender = socketcall(SYS_SOCKET, 2, 2, 0, 0, 0, 0);
    struct sockaddr_in32 address;
    memset(&address, 0, sizeof(address));
    address.family = 2;
    address.addr = 0x0100007f;   /* 127.0.0.1, network order */
    u32 length = sizeof(address);
    socketcall(SYS_BIND, receiver, (u32)(unsigned long)&address, sizeof(address), 0, 0, 0);
    socketcall(SYS_GETSOCKNAME, receiver, (u32)(unsigned long)&address, (u32)(unsigned long)&length, 0, 0, 0);
    static char data[4] = {'i', 'a', '3', '2'};
    u32 iov[2] = {(u32)(unsigned long)data, 4};
    u32 msg[7] = {(u32)(unsigned long)&address, sizeof(address), (u32)(unsigned long)iov, 1, 0, 0, 0};
    socketcall(SYS_SENDMSG, sender, (u32)(unsigned long)msg, 0, 0, 0, 0);
    static char in[16];
    struct sockaddr_in32 from;
    u32 fromLength = sizeof(from);
    socketcall(SYS_RECVFROM, receiver, (u32)(unsigned long)in, sizeof(in), 0, (u32)(unsigned long)&from,
               (u32)(unsigned long)&fromLength);
    check(sys3(NR_CLOSE, sender, 0, 0));
    check(sys3(NR_CLOSE, receiver, 0, 0));

    /* ipc(call, first, second, third, ptr, fifth): SHMAT puts the address at *third. */
    long segment = check(sys6(NR_IPC, SHMGET, 0 /* IPC_PRIVATE */, 4096, 01000 | 0600 /* IPC_CREAT */, 0, 0));
    u32 attached = 0;
    check(sys6(NR_IPC, SHMAT, segment, 0, (long)&attached, 0, 0));
    if (attached == 0) failed = 1;
    check(sys6(NR_IPC, SHMDT, 0, 0, 0, attached, 0));
    check(sys6(NR_IPC, SHMCTL, segment, 0 /* IPC_RMID */ | 0x100 /* IPC_64 */, 0, 0, 0));
    static u8 names[6 * 65];
    check(sys3(NR_OLDUNAME, names, 0, 0));
    long queue = check(sys6(NR_IPC, MSGGET, 0 /* IPC_PRIVATE */, 01000 | 0600, 0, 0, 0));
    static u8 message[16];
    u32 kludge[2] = {(u32)(unsigned long)message, 5};
    if (sys6(NR_IPC, MSGRCV, queue, sizeof(message) - 4, 04000 /* IPC_NOWAIT */, (long)kludge, 0) >= 0) failed = 1;
    check(sys6(NR_IPC, MSGCTL, queue, 0 /* IPC_RMID */ | 0x100 /* IPC_64 */, 0, 0, 0));
    long notify = check(sys3(NR_FANOTIFY_INIT, 0 /* FAN_CLASS_NOTIF */, 0, 0));
    /* fanotify_mark(fd, FAN_MARK_ADD, FAN_OPEN as mask_lo, mask_hi, AT_FDCWD, path) */
    check(sys6(NR_FANOTIFY_MARK, notify, 1, 0x20, 0, -100, (long)"ia32-a.txt"));
    check(sys3(NR_CLOSE, notify, 0, 0));

    /* old_mmap(struct {addr, len, prot, flags, fd, offset}) of the file and of anonymous memory. */
    fd = check(sys3(NR_OPEN, "ia32-a.txt", 0, 0));
    u32 file[6] = {0, 8192, 5 /* PROT_READ|PROT_EXEC */, 2 /* MAP_PRIVATE */, (u32)fd, 0};
    check(sys3(NR_MUNMAP, check(sys3(NR_OLD_MMAP, file, 0, 0)), 8192, 0));
    u32 anonymous[6] = {0, 8192, 3 /* PROT_READ|PROT_WRITE */, 0x22 /* MAP_PRIVATE|MAP_ANONYMOUS */, 0xffffffffu, 0};
    long area = check(sys3(NR_OLD_MMAP, anonymous, 0, 0));
    check(sys3(NR_MPROTECT, area, 4096, 1 /* PROT_READ */));
    check(sys3(NR_MUNMAP, area, 8192, 0));
    u32 position[2];
    check(sys6(NR_LLSEEK, fd, 0, 0, (long)position, 2 /* SEEK_END */, 0));
    static u8 lock[24];   /* compat_flock64 (packed): l_type F_RDLCK, l_whence SEEK_SET, l_start 0 at 4, l_len at 12 */
    lock[12] = 1;
    check(sys3(NR_FCNTL64, fd, 13 /* F_SETLK64 */, lock));
    check(sys3(NR_FCNTL, fd, 3 /* F_GETFL */, 0));
    u32 mask[2] = {1u << 9 /* SIGUSR1 */, 0};
    check(sys6(NR_RT_SIGPROCMASK, 0 /* SIG_BLOCK */, (long)mask, 0, 8, 0, 0));
    check(sys3(NR_CLOSE, fd, 0, 0));
}

__attribute__((force_align_arg_pointer, noreturn)) void _start(void)
{
    /* The syscall frame lives in this frame, above the stack the calls below run on (sp <= frame). */
    u8 frame[0x80];
    memset(frame, 0, sizeof(frame));
    put32(pestack, 0x7bc05678);   /* the return into the "caller of NtXxx" */
    put32(frame + 0x08, 0x7bc01234);
    put32(frame + 0x0c, (u32)(unsigned long)pestack);
    put32(frame + 0x34, (u32)(unsigned long)pestack);
    put32(teb + 0x04, (u32)(unsigned long)pestack + sizeof(pestack));   /* NT_TIB.StackBase */
    put32(teb + 0x18, (u32)(unsigned long)teb);
    put32(teb + 0x20, 0x30);   /* ClientId: Windows pid 0x30, tid 0x34 */
    put32(teb + 0x24, 0x34);
    put32(teb + 0x218, (u32)(unsigned long)frame);
    put32(teb + 0x23c, 0);
    u32 desc[4] = {0xffffffffu, (u32)(unsigned long)teb, 0xfff, 0x1 | 0x10 | 0x40};
    check(sys3(NR_SET_THREAD_AREA, desc, 0, 0));
    actions();
    __asm__ volatile("" : : "r"(frame) : "memory");
    sys3(NR_EXIT_GROUP, failed, 0, 0);
    for (;;) {
    }
}
