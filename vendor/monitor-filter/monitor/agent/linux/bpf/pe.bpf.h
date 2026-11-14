/* The PE (Windows-side) context of the Wine syscall the current thread is in (docs/LINUX.md "PE frames").
 *
 * Wine 11.0 x64: GS base is the thread's TEB for the thread's whole life (arch_prctl(ARCH_SET_GS) once),
 * so task->thread.gsbase is the TEB. A thread inside a Wine syscall runs on Wine's per-thread kernel stack
 * (TEB+0x3a8) below its syscall_frame (TEB+0x378); the frame holds the PE side's rip (inside the NtXxx stub
 * of ntdll.dll), rsp (the qword there returns into the caller of NtXxx) and rbp. The agent unwinds the
 * copied PE stack with the images' .pdata (bpf_pe.inc, pe.cpp). Offsets: WINE_FACTS / signal_x86_64.c. */
#define MM_TEB_SELF 0x30          /* NT_TIB.Self (NT_TIB.StackBase at 0x08) */
#define MM_TEB_SYSCALL_FRAME 0x378
#define MM_FRAME_RIP 0x70         /* syscall_frame: rip 0x70, cs, eflags, rsp 0x88, ss, rbp 0x98 */

/* Wine 11.0 i386 (the 32-bit unix side of old WoW64, as the launcher, nexon_client and NGService run here): FS is
 * the TEB selector, a set_thread_area TLS descriptor; the TEB's ntdll_thread_data (TEB+0x1d4) holds
 * syscall_frame at TEB+0x218 and kernel_stack at TEB+0x23c (unix_private.h; the 0x214/0x218/0x21c offsets are
 * C_ASSERTed there). syscall_frame (signal_i386.c, 0x280 bytes): eip +0x08, esp +0x0c, ebp +0x34;
 * __wine_syscall_dispatcher pops the NtXxx stub's return into eip, so the dword at esp returns into its caller. */
#define MM_TEB32_SELF 0x18        /* NT_TIB.Self (NT_TIB.StackBase at 0x04) */
#define MM_TEB32_SYSCALL_FRAME 0x218
#define MM_TEB32_KERNEL_STACK 0x23c
#define MM_FRAME32_EIP 0x08       /* eip 0x08, esp 0x0c ... ebp 0x34 */

/* The ia32 thread's Wine TEB or 0: the GDT TLS descriptor whose base has Tib.Self (+0x18) == base.
 * Verifier-safe: three unrolled steps; constant offsets and constant-size probe reads. */
static __always_inline __u64 teb32(struct task_struct* task)
{
#pragma unroll
    for (int i = 0; i < 3; i++) {
        __u64 raw = 0;
        __u32 self = 0;
        bpf_probe_read_kernel(&raw, sizeof(raw), __builtin_preserve_access_index(&task->thread.tls_array[i]));
        __u64 base = ((raw >> 16) & 0xffffff) | ((raw >> 56) << 24);
        if (base && bpf_probe_read_user(&self, sizeof(self), (void*)(base + MM_TEB32_SELF)) == 0 && self == base)
            return base;
    }
    return 0;
}

/* read_pe for an ia32 Wine thread: eip/esp/ebp of its syscall_frame and up to MM_PE_BYTES of the 32-bit PE stack
 * (bounded by the TEB's StackBase); sets MM_PE_I386. Verifier-safe as read_pe: no loop beyond teb32's three
 * steps; constant-size reads into stack buffers and one clamped read into pe->stack. */
static __always_inline void read_pe32(struct mm_pe* pe, struct task_struct* task, struct pt_regs* regs)
{
    __u64 teb = teb32(task);
    if (!teb) return;
    __u32 tib[2];   /* ExceptionList, StackBase */
    __u32 wine[10]; /* TEB+0x218 syscall_frame ... TEB+0x23c kernel_stack */
    if (bpf_probe_read_user(tib, sizeof(tib), (const void*)teb) != 0 ||
        bpf_probe_read_user(wine, sizeof(wine), (const void*)(teb + MM_TEB32_SYSCALL_FRAME)) != 0)
        return;
    __u64 frame = wine[0], sp = (__u32)regs->sp;
    if (!frame || sp < wine[(MM_TEB32_KERNEL_STACK - MM_TEB32_SYSCALL_FRAME) / 4] || sp > frame) return;
    __u32 saved[12];   /* eip, esp, cs/ss, ds/es, fs/gs, eax, ebx, ecx, edx, edi, esi, ebp */
    if (bpf_probe_read_user(saved, sizeof(saved), (const void*)(frame + MM_FRAME32_EIP)) != 0 || !saved[0]) return;
    __u64 esp = saved[1];
    pe->rip = saved[0];
    pe->rsp = esp;
    pe->rbp = saved[11];
    pe->flags = MM_PE_I386;
    __u64 n = tib[1] > esp ? tib[1] - esp : MM_PE_BYTES;
    if (n > MM_PE_BYTES) n = MM_PE_BYTES;
    n &= 2 * MM_PE_BYTES - 1;
    if (n > MM_PE_BYTES) n = MM_PE_BYTES;
    if (n && bpf_probe_read_user(pe->stack, n, (const void*)esp) == 0) pe->bytes = n;
}

/* Fills pe->rip/rsp/rbp and up to MM_PE_BYTES of the PE stack at rsp (bounded by the TEB's StackBase), or
 * leaves pe->rip 0 when the thread has no TEB or is not inside a Wine syscall. The caller zeroed rip, bytes and flags.
 * Verifier-safe: no loop; four bpf_probe_read_user calls, three of constant size into stack buffers and one
 * into pe->stack whose size is clamped to [0, MM_PE_BYTES] on the register passed (pe->stack is MM_PE_BYTES
 * long in both callers' buffers). gsbase and regs->sp are direct BTF reads (no helper). */
static __always_inline void read_pe(struct mm_pe* pe, struct task_struct* task, struct pt_regs* regs)
{
    __u64 teb = task->thread.gsbase;
    if (!teb) return;
    __u64 tib[7];   /* ExceptionList, StackBase, StackLimit, SubSystemTib, FiberData, ArbitraryUserPointer, Self */
    if (bpf_probe_read_user(tib, sizeof(tib), (const void*)teb) != 0 || tib[MM_TEB_SELF / 8] != teb) return;
    __u64 wine[7];  /* TEB+0x378 syscall_frame ... TEB+0x3a8 kernel_stack */
    if (bpf_probe_read_user(wine, sizeof(wine), (const void*)(teb + MM_TEB_SYSCALL_FRAME)) != 0) return;
    __u64 frame = wine[0];
    __u64 sp = regs->sp;
    /* Wine's is_inside_syscall(): a thread on the PE stack (or a unix thread) is not in a Wine syscall. */
    if (!frame || sp < wine[6] || sp > frame) return;
    /* shortcut: under new WoW64 (one 64-bit unix process for a 32-bit PE) this reports the 64-bit side
     * (wow64*.dll), not the 32-bit caller; read the I386_CONTEXT at *(TEB+0x1488)+4 (Eip 0xb8, Esp 0xc4) if a
     * Wine built that way is used. The Wine on this host (11.0, old WoW64: i386-unix present) runs 32-bit PE
     * programs as ia32 unix processes, which read_pe32 below covers. */
    __u64 saved[6];  /* rip, cs, eflags, rsp, ss, rbp */
    if (bpf_probe_read_user(saved, sizeof(saved), (const void*)(frame + MM_FRAME_RIP)) != 0 || !saved[0]) return;
    __u64 rsp = saved[3];
    pe->rip = saved[0];
    pe->rsp = rsp;
    pe->rbp = saved[5];
    __u64 n = tib[1] > rsp ? tib[1] - rsp : MM_PE_BYTES;   /* a fiber's stack lies outside the TEB's */
    if (n > MM_PE_BYTES) n = MM_PE_BYTES;
    n &= 2 * MM_PE_BYTES - 1;
    if (n > MM_PE_BYTES) n = MM_PE_BYTES;
    if (n && bpf_probe_read_user(pe->stack, n, (const void*)rsp) == 0) pe->bytes = n;
}

/* The PE context of either kind of Wine thread: Compat = the call is an ia32 syscall. */
static __always_inline void read_pe_any(struct mm_pe* pe, struct task_struct* task, struct pt_regs* regs, int compat)
{
    if (compat) read_pe32(pe, task, regs);
    else read_pe(pe, task, regs);
}
