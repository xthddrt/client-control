#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wbemidl.h>
#include <lm.h>
#include <lmwksta.h>
#include <cstdio>

static void RpcProbe()
{
    LPBYTE information = nullptr;
    if (NetWkstaGetInfo(nullptr, 100, &information) == NERR_Success && information != nullptr) {
        NetApiBufferFree(information);
    }
}

static void WmiProbe()
{
    HRESULT result = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(result)) return;
    (void)CoInitializeSecurity(nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_DEFAULT,
                               RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr);
    IWbemLocator* locator = nullptr;
    result = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                              IID_IWbemLocator, reinterpret_cast<void**>(&locator));
    if (SUCCEEDED(result) && locator != nullptr) {
        IWbemServices* services = nullptr;
        BSTR nameSpace = SysAllocString(L"ROOT\\CIMV2");
        result = locator->ConnectServer(nameSpace, nullptr, nullptr, nullptr, 0, nullptr, nullptr, &services);
        SysFreeString(nameSpace);
        if (SUCCEEDED(result) && services != nullptr) {
            (void)CoSetProxyBlanket(services, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                                    RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
            IEnumWbemClassObject* rows = nullptr;
            BSTR language = SysAllocString(L"WQL");
            BSTR query = SysAllocString(L"SELECT SerialNumber FROM Win32_BIOS");
            result = services->ExecQuery(language, query,
                                         WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                                         nullptr, &rows);
            SysFreeString(language);
            SysFreeString(query);
            if (SUCCEEDED(result) && rows != nullptr) {
                IWbemClassObject* row = nullptr;
                ULONG returned = 0;
                (void)rows->Next(2000, 1, &row, &returned);
                if (row != nullptr) row->Release();
                rows->Release();
            }
            services->Release();
        }
        locator->Release();
    }
    CoUninitialize();
}

static void DnsProbe(const char* name)
{
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return;
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* answer = nullptr;
    (void)getaddrinfo(name, nullptr, &hints, &answer);
    if (answer != nullptr) freeaddrinfo(answer);
    WSACleanup();
}

int main(int argc, char** argv)
{
    const char* dnsName = argc > 1 ? argv[1] : "msmon-etw-probe.invalid";
    RpcProbe();
    Sleep(300);
    WmiProbe();
    Sleep(300);
    DnsProbe(dnsName);
    Sleep(300);
    std::printf("etw_probe complete\n");
    return 0;
}
