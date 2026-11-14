/* The DLL of tests/linux_watch_test.sh's Wine session: msmon_dll_watched, watched as watch_wine_dll.dll+RVA, which
 * watch_wine_probe.exe writes after loading this DLL a second time at another base. Built as watch_wine_probe.c is
 * (clang -target x86_64-w64-windows-gnu -ffreestanding -c, ld -m i386pep --dll), with a base relocation (msmon_dll_self)
 * so Wine can load it away from its preferred base. */
__declspec(dllexport) volatile unsigned long long msmon_dll_watched __attribute__((aligned(8)));
__declspec(dllexport) volatile unsigned long long* volatile msmon_dll_self = &msmon_dll_watched;

int __stdcall DllMainCRTStartup(void* module, unsigned reason, void* reserved)
{
    (void)module;
    (void)reason;
    (void)reserved;
    return 1;
}
