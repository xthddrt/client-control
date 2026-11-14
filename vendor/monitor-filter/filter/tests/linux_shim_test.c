/* The trap shim's CPUID answers and configuration path (linux/shim/kfshim.c, compiled in whole without
 * its constructor), with no trap armed; then, in a child under a seccomp filter that kills on
 * arch_prctl (as Chrome's sandbox does), a trap armed and answered on every core (needs cpuid_fault).
 * build.sh tests builds it as build/linux/shim-test. */
#define _GNU_SOURCE
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#define KFSHIM_TEST
#include "../linux/shim/kfshim.c"

static int failures;
static void expect(const char* name, int value)
{
    if (!value) {
        printf("FAIL %s\n", name);
        failures++;
    }
}

static void put4(uint32_t l, uint32_t s, uint32_t a, uint32_t b, uint32_t c, uint32_t d)
{
    struct leaf e = {l, s, {a, b, c, d}};
    leaves[leafCount++] = e;
}

static int same(const uint32_t* r, uint32_t a, uint32_t b, uint32_t c, uint32_t d)
{
    return r[0] == a && r[1] == b && r[2] == c && r[3] == d;
}

static int native(uint32_t l, uint32_t s, const uint32_t* r)
{
    uint32_t n[4];
    __cpuid_count(l, s, n[0], n[1], n[2], n[3]);
    return memcmp(n, r, sizeof(n)) == 0;
}

extern int waitpid(int pid, int* status, int options);   /* <sys/wait.h> would bring <signal.h>'s sigaction */

static const uint32_t trapped[] = {1, 4, 0xb, 0x1a, 0x1f};
static uint32_t natives[1024][sizeof(trapped) / sizeof(trapped[0])][4];

/* The child: each core's leaves natively, then CPUID faulting on, arch_prctl fatal, and each core's
 * leaves again through the trap. Exit 0 if all match, 77 without cpuid_fault. */
static int trappedChild(const cpu_set_t* all)
{
    cpu_set_t one;
    unsigned count = sizeof(trapped) / sizeof(trapped[0]);
    for (int cpu = 0; cpu < 1024; cpu++) {
        CPU_ZERO(&one);
        CPU_SET(cpu, &one);
        if (!CPU_ISSET(cpu, all) || sched_setaffinity(0, sizeof(one), &one) != 0) continue;
        for (unsigned i = 0; i < count; i++) {
            uint32_t* n = natives[cpu][i];
            __cpuid_count(trapped[i], 0, n[0], n[1], n[2], n[3]);
        }
    }
    struct ksigaction mine = {(void*)handler, {0}, SA_SIGINFO, 0};
    if (next((void**)&realSigaction, "sigaction") == 0 || realSigaction(SIGSEGV, &mine, 0) != 0) return 2;
    if (syscall(SYS_arch_prctl, ARCH_SET_CPUID, 0) != 0) return 77;
    cpuidOn = 1;
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_arch_prctl, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {sizeof(filter) / sizeof(filter[0]), filter};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 || prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) != 0) return 3;
    int wrong = 0;
    for (int cpu = 0; cpu < 1024; cpu++) {
        CPU_ZERO(&one);
        CPU_SET(cpu, &one);
        if (!CPU_ISSET(cpu, all) || sched_setaffinity(0, sizeof(one), &one) != 0) continue;
        for (unsigned i = 0; i < count; i++) {
            uint32_t r[4];
            __cpuid_count(trapped[i], 0, r[0], r[1], r[2], r[3]);
            wrong |= memcmp(r, natives[cpu][i], sizeof(r)) != 0;
        }
    }
    int sawTrap = 0;
    for (unsigned i = 0; i < 512; i++) sawTrap |= seen[i].key == (1ull << 32 | 1) && seen[i].count > 0;
    return wrong ? 4 : sawTrap ? 0 : 5;
}

int main(void)
{
    (void)start;
    char path[64];
    expect("config beside <dir>/lib/<multiarch>/libkfshim.so",
           configPath("/tmp/kfshim.Ab12Cd/lib/x86_64-linux-gnu/libkfshim.so", path, sizeof(path)) &&
               strcmp(path, "/tmp/kfshim.Ab12Cd/config") == 0);
    expect("the i386 shim's too", configPath("/d/lib/i386-linux-gnu/libkfshim.so", path, sizeof(path)) &&
                                      strcmp(path, "/d/config") == 0);
    expect("no directory above lib", !configPath("/lib/x86_64-linux-gnu/libkfshim.so", path, sizeof(path)));
    expect("a bare name", !configPath("libkfshim.so", path, sizeof(path)));
    expect("too long", !configPath("/a-long-directory/lib/x86_64-linux-gnu/libkfshim.so", path, 20));

    /* A made-up snapshot: Intel, basic leaves up to 0xa, extended up to 0x80000004, no hypervisor. */
    uint32_t r[4];
    put4(0, 0, 0xa, 0x756e6547, 0x6c65746e, 0x49656e69);
    put4(0xa, 0, 1, 2, 3, 4);
    put4(7, 0, 5, 6, 7, 8);
    put4(0x80000002, 0, 9, 9, 9, 9);
    maxBasic = 0xa;
    maxExtended = 0x80000004;
    intel = 1;
    answer(0xa, 0, r);
    expect("a leaf from the snapshot", same(r, 1, 2, 3, 4));
    answer(0xc, 0, r);
    expect("Intel: a basic leaf past the highest reads the highest", same(r, 1, 2, 3, 4));
    answer(0x80000005, 0, r);
    expect("Intel: an extended leaf past the highest too", same(r, 1, 2, 3, 4));
    answer(0x40000000, 0, r);
    expect("Intel: the hypervisor range with no hypervisor too", same(r, 1, 2, 3, 4));
    answer(7, 0, r);
    expect("a subleaf from the snapshot", same(r, 5, 6, 7, 8));
    answer(7, 5, r);
    expect("a subleaf the snapshot lacks, in range: zeros", same(r, 0, 0, 0, 0));
    answer(0x80000003, 0, r);
    expect("an extended leaf in range it lacks: zeros", same(r, 0, 0, 0, 0));
    intel = 0;
    answer(0xc, 0, r);
    expect("AMD and the others: past the highest reads zeros", same(r, 0, 0, 0, 0));
    intel = 1;
    put4(0x40000000, 0, 0x40000001, 0x4b4d564b, 0x564b4d56, 0x4d);
    put4(0x40000001, 0, 7, 0, 0, 0);
    maxHypervisor = 0x40000001;
    answer(0x40000001, 0, r);
    expect("a hypervisor's leaf from the snapshot", same(r, 7, 0, 0, 0));
    answer(0x40000002, 0, r);
    expect("past the hypervisor's highest: Intel's rule", same(r, 1, 2, 3, 4));
    masked[maskCount++] = 0x80000002;
    masked[maskCount++] = 0x16;
    answer(0x80000002, 0, r);
    expect("a masked leaf reads zeros", same(r, 0, 0, 0, 0));
    answer(0x16, 0, r);
    expect("a masked per-core leaf too (never read live)", same(r, 0, 0, 0, 0));

    /* The real snapshot: past each range as this CPU answers; per-core leaves from the core the thread
     * is on, on every core; and from the snapshot on a core the table lacks. */
    leafCount = maskCount = 0;
    maxHypervisor = 0;
    snapshotAll();
    readCores();
    uint32_t past[] = {maxBasic + 1, maxBasic + 7, maxHypervisor ? maxHypervisor + 1 : 0x40000000, maxExtended + 1,
                       0x8fffffff};
    for (unsigned i = 0; i < sizeof(past) / sizeof(past[0]); i++) {
        for (uint32_t s = 0; s < 3; s++) {
            answer(past[i], s, r);
            char name[64];
            snprintf(name, sizeof(name), "leaf %#x subleaf %u as the hardware answers", past[i], s);
            expect(name, native(past[i], s, r));
        }
    }
    cpu_set_t all, one;
    expect("affinity", sched_getaffinity(0, sizeof(all), &all) == 0);
    expect("readCores leaves the affinity mask as it was",
           sched_getaffinity(0, sizeof(one), &one) == 0 && CPU_EQUAL(&one, &all) && coreCount > 0);
    uint32_t first = 0, differs = 0, cpus = 0;
    for (int cpu = 0; cpu < CPU_SETSIZE; cpu++) {
        if (!CPU_ISSET(cpu, &all)) continue;
        CPU_ZERO(&one);
        CPU_SET(cpu, &one);
        if (sched_setaffinity(0, sizeof(one), &one) != 0) continue;
        expect("LSL reads the CPU getcpu does", currentCpu() == (unsigned)sched_getcpu());
        uint32_t ids[] = {1, 4, 6, 0xb, 0x1a, 0x1f};
        for (unsigned i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
            answer(ids[i], 0, r);
            char name[64];
            snprintf(name, sizeof(name), "cpu %d leaf %#x from its own core", cpu, ids[i]);
            expect(name, native(ids[i], 0, r));
        }
        answer(1, 0, r);
        if (cpus++ == 0) first = r[1] >> 24;
        differs |= (r[1] >> 24) != first;
    }
    expect("APIC ids differ between cores (each core's table)", cpus < 2 || differs);
    unsigned tableCpus = coreCount;
    coreCount = 0;
    answer(1, 0, r);
    coreCount = tableCpus;
    uint32_t snapshot1[4] = {0, 0, 0, 0};
    for (unsigned i = 0; i < leafCount; i++) {
        if (leaves[i].leaf == 1) memcpy(snapshot1, leaves[i].r, sizeof(snapshot1));
    }
    expect("a core the table lacks: the snapshot answers", memcmp(r, snapshot1, sizeof(snapshot1)) == 0);
    sched_setaffinity(0, sizeof(all), &all);

    pid_t child = fork();
    if (child == 0) _exit(trappedChild(&all));
    int status = 0;
    waitpid(child, &status, 0);
    if ((status & 0x7f) == 0 && (status >> 8 & 0xff) == 77) {
        printf("shim-test: no cpuid_fault here, the trapped run is skipped\n");
    } else {
        expect("trapped under a seccomp filter that kills on arch_prctl: every core's leaves, no syscall",
               (status & 0x7f) == 0 && (status >> 8 & 0xff) == 0);
        if (status != 0) printf("  child status %#x\n", status);
    }

    if (failures == 0) printf("shim-test: PASS\n");
    return failures == 0 ? 0 : 1;
}
