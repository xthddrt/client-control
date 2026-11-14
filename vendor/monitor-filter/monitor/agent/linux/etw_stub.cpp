#include "../etw.h"

/*
 * Linux has no ETW.  The collector keeps its deferral and TCP-owner bookkeeping
 * (shared from etw.cpp) but never starts, so the agent records etw_unavailable.
 */

EtwCollector::~EtwCollector()
{
    Stop();
}

bool EtwCollector::Start(std::string& error)
{
    error = "ETW is a Windows facility. Linux equivalents: etw_dns and etw_tcp from linux.ebpf_net; etw_rpc from"
            " linux.ebpf_wineserver (DCE/RPC binds and requests on Wine's ncacn_np/ncalrpc pipes: endpoint, interface,"
            " opnum; no response status unless the read completes at once); etw_wmi from linux.ebpf_wineserver (WMI"
            " COM activation), linux.maps_poll (wbemprox/wbemdisp/wmiutils/fastprox loads) and the uprobes group (the WQL"
            " of each IWbemServices::ExecQuery: Wine's WMI runs in-process); etw_code_integrity: no WDAC under Wine, driver loads in winedevice.exe are"
            " recorded with decision=not_enforced";
    warnings_.push_back(L"etw_unavailable");
    return false;
}

void EtwCollector::Stop()
{
    started_ = false;
}
