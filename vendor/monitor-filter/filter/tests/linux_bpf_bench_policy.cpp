// kfilterctl's policy parser for the BPF bench (linux_bpf_bench.cpp): tool/kfilterctl.cpp compiled into this
// translation unit with its main renamed, so the bench reads a policy exactly as `kfilterctl policy` does
// (linked with kfilterd's objects instead of kfilterctl's offline stand-ins for them).
#define KFILTERCTL_WITH_DAEMON
#define main kfilterctl_main
#include "../tool/kfilterctl.cpp"
#undef main

bool BenchParsePolicy(const char* path, KFILTER_CONFIG* config, std::string& error)
{
    gLinuxPaths = true;
    return ParsePolicy(Utf8ToWide(path), config, error);
}
