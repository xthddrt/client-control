/* CPUID as a program sees it, for tests/linux_launch_test.sh: on each CPU it may run on, the leaves
 * that differ between cores, then the leaves past each range. Natively and under `kfilterctl launch
 * --trap-cpuid` it must print the same. */
#define _GNU_SOURCE
#include <cpuid.h>
#include <sched.h>
#include <stdio.h>

static void show(const char* name, unsigned leaf, unsigned sub)
{
    unsigned a, b, c, d;
    __cpuid_count(leaf, sub, a, b, c, d);
    printf(" %s=%08x.%08x.%08x.%08x", name, a, b, c, d);
}

int main(void)
{
    cpu_set_t all, one;
    if (sched_getaffinity(0, sizeof(all), &all) != 0) return 1;
    for (int cpu = 0; cpu < CPU_SETSIZE; cpu++) {
        CPU_ZERO(&one);
        CPU_SET(cpu, &one);
        if (!CPU_ISSET(cpu, &all) || sched_setaffinity(0, sizeof(one), &one) != 0) continue;
        printf("cpu=%d", cpu);
        show("1", 1, 0);
        show("4", 4, 0);
        show("b", 0xb, 0);
        show("b1", 0xb, 1);
        show("1a", 0x1a, 0);
        show("1f", 0x1f, 0);
        show("80000006", 0x80000006, 0);
        printf("\n");
    }
    unsigned top, ext, b, c, d;
    __cpuid(0, top, b, c, d);
    __cpuid(0x80000000, ext, b, c, d);
    printf("past");
    show("basic", top + 1, 0);
    show("hypervisor", 0x40000000, 0);
    show("extended", ext + 1, 0);
    printf("\n");
    return 0;
}
