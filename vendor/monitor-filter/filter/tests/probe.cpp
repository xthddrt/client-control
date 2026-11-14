// kfilter-probe - run inside the protected tree and exercise policy boundaries.
// This is a diagnostic fixture, not a security tool. It exits nonzero on an
// operation that the policy is expected to deny only when --expect-deny is set.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>
#include <aclapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

static int Report(const char* operation, BOOL allowed, DWORD error)
{
    std::printf("%-12s %s%s%lu\n", operation, allowed ? "ALLOWED" : "DENIED",
                allowed ? "" : " error=", allowed ? 0 : error);
    return allowed ? 0 : 1;
}

static int ProbeRead(const wchar_t* path)
{
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return Report("read", FALSE, GetLastError());
    char buffer[4096];
    DWORD read = 0;
    BOOL ok = ReadFile(file, buffer, sizeof(buffer), &read, nullptr);
    DWORD error = ok ? 0 : GetLastError();
    CloseHandle(file);
    return Report("read", ok, error);
}

/* A read-only allow must not authorize CREATE_ALWAYS: it truncates the file. */
static int ProbeTruncate(const wchar_t* path)
{
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return Report("truncate", FALSE, GetLastError());
    CloseHandle(file);
    return Report("truncate", TRUE, 0);
}

/* A read-only allow must not authorize FILE_FLAG_DELETE_ON_CLOSE. */
static int ProbeDeleteOnClose(const wchar_t* path)
{
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              nullptr, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, nullptr);
    if (file == INVALID_HANDLE_VALUE) return Report("delete-close", FALSE, GetLastError());
    CloseHandle(file);
    return Report("delete-close", TRUE, 0);
}

static int ProbeProcess(DWORD pid)
{
    HANDLE process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION,
                                 FALSE, pid);
    if (process == nullptr) return Report("process", FALSE, GetLastError());
    char byte = 0;
    SIZE_T read = 0;
    BOOL ok = ReadProcessMemory(process, (LPCVOID)GetModuleHandleW(nullptr), &byte, 1, &read);
    DWORD error = ok ? 0 : GetLastError();
    CloseHandle(process);
    return Report("process", ok, error);
}

static int ProbeDuplicate(DWORD targetPid)
{
    HANDLE target = OpenProcess(PROCESS_DUP_HANDLE, FALSE, targetPid);
    if (target == nullptr) return Report("duplicate", FALSE, GetLastError());
    HANDLE remote = nullptr;
    BOOL ok = DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), target, &remote,
                              PROCESS_VM_READ, FALSE, 0);
    DWORD error = ok ? 0 : GetLastError();
    HANDLE local = nullptr;
    if (ok) {
        ok = DuplicateHandle(target, remote, GetCurrentProcess(), &local,
                             PROCESS_VM_READ, FALSE, DUPLICATE_CLOSE_SOURCE);
        error = ok ? 0 : GetLastError();
        if (ok) remote = nullptr;
    }
    if (remote != nullptr) {
        DuplicateHandle(target, remote, nullptr, nullptr, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
    }
    if (ok) {
        char byte = 0;
        SIZE_T read = 0;
        ok = ReadProcessMemory(local, (LPCVOID)GetModuleHandleW(nullptr), &byte, 1, &read);
        error = ok ? 0 : GetLastError();
    }
    if (local != nullptr) CloseHandle(local);
    CloseHandle(target);
    return Report("duplicate", ok, error);
}

static int ProbeChild(const wchar_t* image)
{
    std::wstring command = L"\"" + std::wstring(image) + L"\"";
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    std::vector<wchar_t> buffer(command.begin(), command.end());
    buffer.push_back(L'\0');
    BOOL ok = CreateProcessW(image, buffer.data(), nullptr, nullptr, FALSE, 0,
                             nullptr, nullptr, &startup, &process);
    DWORD error = ok ? 0 : GetLastError();
    if (ok) {
        TerminateProcess(process.hProcess, 0);
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
    }
    return Report("child", ok, error);
}

static int ProbeDelayedRead(DWORD milliseconds, const wchar_t* path)
{
    Sleep(milliseconds);
    return ProbeRead(path);
}

static int ProbeSpawnRead(const wchar_t* image, DWORD milliseconds, const wchar_t* path)
{
    std::wstring command = L"\"" + std::wstring(image) + L"\" delayed-read " +
                           std::to_wstring(milliseconds) + L" \"" + path + L"\"";
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    std::vector<wchar_t> buffer(command.begin(), command.end());
    buffer.push_back(L'\0');
    BOOL ok = CreateProcessW(image, buffer.data(), nullptr, nullptr, FALSE, 0,
                             nullptr, nullptr, &startup, &process);
    DWORD error = ok ? 0 : GetLastError();
    if (ok) {
        std::printf("child pid=%lu\n", process.dwProcessId);
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
    }
    return Report("spawn-read", ok, error);
}

static int ProbeRegistry(const wchar_t* subkey, const wchar_t* value)
{
    HKEY key = nullptr;
    LONG status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey, 0, KEY_READ, &key);
    if (status != ERROR_SUCCESS) return Report("registry", FALSE, (DWORD)status);
    wchar_t data[512];
    DWORD size = sizeof(data);
    DWORD type = 0;
    status = RegQueryValueExW(key, value, nullptr, &type, (LPBYTE)data, &size);
    RegCloseKey(key);
    return Report("registry", status == ERROR_SUCCESS, (DWORD)status);
}

static int ProbeVolume(const wchar_t* drive)
{
    wchar_t volume[64];
    wchar_t filesystem[64];
    DWORD serial = 0;
    DWORD maximum = 0;
    DWORD flags = 0;
    BOOL ok = GetVolumeInformationW(drive, volume, 64, &serial, &maximum, &flags,
                                    filesystem, 64);
    return Report("volume", ok, ok ? 0 : GetLastError());
}

static int ProbeDirectory(const wchar_t* path)
{
    WIN32_FIND_DATAW data{};
    std::wstring pattern = std::wstring(path) + L"\\*";
    HANDLE find = FindFirstFileW(pattern.c_str(), &data);
    if (find == INVALID_HANDLE_VALUE) return Report("dir", FALSE, GetLastError());
    FindClose(find);
    return Report("dir", TRUE, 0);
}

static int ProbeRaw(const wchar_t* path, DWORD delayMilliseconds)
{
    HANDLE device = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                nullptr, OPEN_EXISTING, 0, nullptr);
    if (device == INVALID_HANDLE_VALUE) return Report("raw", FALSE, GetLastError());
    if (delayMilliseconds != 0) {
        /* Open in audit mode, switch to block while this sleeps, then use the
         * already-open handle: a read here proves the handle survived block mode. */
        std::printf("raw open; waiting %lu ms\n", delayMilliseconds);
        Sleep(delayMilliseconds);
    }
    BYTE sector[512];
    DWORD bytes = 0;
    BOOL read = ReadFile(device, sector, sizeof(sector), &bytes, nullptr);
    if (!read) {
        DWORD error = GetLastError();
        CloseHandle(device);
        return Report("raw", FALSE, error);
    }
    STORAGE_PROPERTY_QUERY query{};
    query.PropertyId = StorageDeviceProperty;
    query.QueryType = PropertyStandardQuery;
    BYTE output[1024];
    DWORD returned = 0;
    BOOL ok = DeviceIoControl(device, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query),
                              output, sizeof(output), &returned, nullptr);
    DWORD error = ok ? 0 : GetLastError();
    CloseHandle(device);
    return Report("raw", ok, error);
}

static int ProbeRename(const wchar_t* path, const wchar_t* destination)
{
    /* No MOVEFILE_COPY_ALLOWED: this must be a same-volume set-information rename. */
    BOOL ok = MoveFileExW(path, destination, 0);
    return Report("rename", ok, ok ? 0 : GetLastError());
}

static int ProbeLink(const wchar_t* path, const wchar_t* destination)
{
    BOOL ok = CreateHardLinkW(destination, path, nullptr);
    return Report("link", ok, ok ? 0 : GetLastError());
}

static int ProbeFsctl(const wchar_t* path, DWORD delayMilliseconds)
{
    /*
     * Control operations are authorized like read+write on the stream handle.
     * Opening with read+write then sleeping lets the operator switch to block
     * mode and send the FSCTL through the already-open (stale-context) handle.
     */
    HANDLE file = CreateFileW(path, GENERIC_READ | GENERIC_WRITE,
                              FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return Report("fsctl", FALSE, GetLastError());
    if (delayMilliseconds != 0) {
        std::printf("fsctl open; waiting %lu ms\n", delayMilliseconds);
        Sleep(delayMilliseconds);
    }
    USHORT compression = 0;
    DWORD returned = 0;
    BOOL ok = DeviceIoControl(file, FSCTL_GET_COMPRESSION, nullptr, 0,
                              &compression, sizeof(compression), &returned, nullptr);
    DWORD error = ok ? 0 : GetLastError();
    CloseHandle(file);
    return Report("fsctl", ok, error);
}

static int ProbeSecurity(const wchar_t* path)
{
    /* Re-apply the object's own DACL. The ACL is unchanged, but the call still
     * issues IRP_MJ_SET_SECURITY, which the minifilter now authorizes with the
     * independent set-security right. */
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    DWORD status = GetNamedSecurityInfoW(const_cast<wchar_t*>(path), SE_FILE_OBJECT,
                                         DACL_SECURITY_INFORMATION, nullptr, nullptr,
                                         nullptr, nullptr, &descriptor);
    if (status != ERROR_SUCCESS) return Report("security", FALSE, status);
    PACL dacl = nullptr;
    BOOL present = FALSE;
    BOOL presentDefault = FALSE;
    if (!GetSecurityDescriptorDacl(descriptor, &present, &dacl, &presentDefault) ||
        !present || dacl == nullptr) {
        LocalFree(descriptor);
        std::printf("security     SKIPPED no DACL\n");
        return 0;
    }
    status = SetNamedSecurityInfoW(const_cast<wchar_t*>(path), SE_FILE_OBJECT,
                                   DACL_SECURITY_INFORMATION, nullptr, nullptr, dacl, nullptr);
    LocalFree(descriptor);
    return Report("security", status == ERROR_SUCCESS, status);
}

static int ProbeRegistryMultiple(const wchar_t* subkey, const wchar_t* value)
{
    HKEY key = nullptr;
    LONG status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey, 0, KEY_READ, &key);
    if (status != ERROR_SUCCESS) return Report("registry-multi", FALSE, (DWORD)status);
    std::vector<BYTE> data(1024);
    VALENTW entry{};
    entry.ve_valuename = const_cast<wchar_t*>(value);
    entry.ve_valueptr = reinterpret_cast<DWORD_PTR>(data.data());
    DWORD size = (DWORD)data.size();
    status = RegQueryMultipleValuesW(key, &entry, 1, reinterpret_cast<wchar_t*>(data.data()), &size);
    RegCloseKey(key);
    return Report("registry-multi", status == ERROR_SUCCESS, (DWORD)status);
}

static int ProbeRegistryEnumeration(const wchar_t* subkey, const wchar_t* value)
{
    /* RegEnumValue returns value data, so a value= deny must also cover
     * enumeration or ProductId/InstallDate/RegisteredOwner leak here. */
    HKEY key = nullptr;
    LONG status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey, 0, KEY_READ, &key);
    if (status != ERROR_SUCCESS) return Report("registry-enum", FALSE, (DWORD)status);
    DWORD index = 0;
    for (;;) {
        wchar_t name[256];
        DWORD nameLength = (DWORD)(sizeof(name) / sizeof(name[0]));
        BYTE data[512];
        DWORD dataSize = sizeof(data);
        status = RegEnumValueW(key, index++, name, &nameLength, nullptr, nullptr,
                               data, &dataSize);
        if (status == ERROR_NO_MORE_ITEMS) {
            status = ERROR_NOT_FOUND;
            break;
        }
        if (status != ERROR_SUCCESS) break;
        if (_wcsicmp(name, value) == 0) {
            RegCloseKey(key);
            return Report("registry-enum", TRUE, 0);
        }
    }
    RegCloseKey(key);
    return Report("registry-enum", FALSE, (DWORD)status);
}

static int ProbePipe(const wchar_t* name)
{
    std::wstring path = L"\\\\.\\pipe\\" + std::wstring(name);
    HANDLE pipe = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                              OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return Report("pipe", FALSE, GetLastError());
    CloseHandle(pipe);
    return Report("pipe", TRUE, 0);
}

static int ProbeNetwork(const wchar_t* host, int port)
{
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return Report("network", FALSE, WSAGetLastError());
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* result = nullptr;
    char service[16];
    char hostUtf8[256] = {};
    sprintf_s(service, "%d", port);
    if (host != nullptr) WideCharToMultiByte(CP_UTF8, 0, host, -1, hostUtf8, sizeof(hostUtf8), nullptr, nullptr);
    int status = getaddrinfo(hostUtf8[0] ? hostUtf8 : nullptr, service, &hints, &result);
    if (status != 0) {
        WSACleanup();
        return Report("network", FALSE, (DWORD)status);
    }
    SOCKET socketHandle = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    BOOL ok = socketHandle != INVALID_SOCKET &&
              connect(socketHandle, result->ai_addr, (int)result->ai_addrlen) == 0;
    DWORD error = ok ? 0 : WSAGetLastError();
    if (socketHandle != INVALID_SOCKET) closesocket(socketHandle);
    freeaddrinfo(result);
    WSACleanup();
    return Report("network", ok, error);
}

static int ProbeAdapter()
{
    ULONG size = 0;
    DWORD status = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, nullptr, &size);
    if (status != ERROR_BUFFER_OVERFLOW) return Report("adapter", FALSE, status);
    std::vector<BYTE> buffer(size);
    IP_ADAPTER_ADDRESSES* addresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
    status = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, addresses, &size);
    return Report("adapter", status == ERROR_SUCCESS, status);
}

static void Usage()
{
    std::printf("kfilter-probe <operation> ...\n"
                "  read <path>\n"
                "  truncate <path>\n"
                "  delete-close <path>\n"
                "  process <pid>\n"
                "  duplicate <target-pid>\n"
                "  child <exe>\n"
                "  spawn-read <exe> <delay-ms> <path>\n"
                "  delayed-read <delay-ms> <path>\n"
                "  registry <HKLM subkey> <value>\n"
                "  registry-multi <HKLM subkey> <value>\n"
                "  registry-enum <HKLM subkey> <value>\n"
                "  volume <drive:>\n"
                "  dir <path>\n"
                "  raw <\\\\.\\PhysicalDrive0|\\\\.\\C:> [delay-ms]\n"
                "  rename <path> <newpath>\n"
                "  link <path> <newpath>\n"
                "  security <path>\n"
                "  fsctl <path> [delay-ms]\n"
                "  pipe <name>\n"
                "  network <host> <port>\n"
                "  adapter\n");
}

int wmain(int argc, wchar_t** argv)
{
    SetConsoleOutputCP(CP_UTF8);
    if (argc < 2) { Usage(); return 2; }
    std::wstring operation = argv[1];
    if (operation == L"adapter") return ProbeAdapter();
    if (argc < 3) { Usage(); return 2; }
    if (operation == L"read") return ProbeRead(argv[2]);
    if (operation == L"truncate") return ProbeTruncate(argv[2]);
    if (operation == L"delete-close") return ProbeDeleteOnClose(argv[2]);
    if (operation == L"process") return ProbeProcess((DWORD)_wtoi(argv[2]));
    if (operation == L"duplicate") return ProbeDuplicate((DWORD)_wtoi(argv[2]));
    if (operation == L"child") return ProbeChild(argv[2]);
    if (operation == L"spawn-read") {
        if (argc < 5) { Usage(); return 2; }
        return ProbeSpawnRead(argv[2], (DWORD)_wtoi(argv[3]), argv[4]);
    }
    if (operation == L"delayed-read") {
        if (argc < 4) { Usage(); return 2; }
        return ProbeDelayedRead((DWORD)_wtoi(argv[2]), argv[3]);
    }
    if (operation == L"registry") {
        if (argc < 4) { Usage(); return 2; }
        return ProbeRegistry(argv[2], argv[3]);
    }
    if (operation == L"registry-multi") {
        if (argc < 4) { Usage(); return 2; }
        return ProbeRegistryMultiple(argv[2], argv[3]);
    }
    if (operation == L"registry-enum") {
        if (argc < 4) { Usage(); return 2; }
        return ProbeRegistryEnumeration(argv[2], argv[3]);
    }
    if (operation == L"volume") return ProbeVolume(argv[2]);
    if (operation == L"dir") return ProbeDirectory(argv[2]);
    if (operation == L"raw") {
        return ProbeRaw(argv[2], argc >= 4 ? (DWORD)_wtoi(argv[3]) : 0);
    }
    if (operation == L"rename" || operation == L"link") {
        if (argc < 4) { Usage(); return 2; }
        return operation == L"rename" ? ProbeRename(argv[2], argv[3])
                                      : ProbeLink(argv[2], argv[3]);
    }
    if (operation == L"pipe") return ProbePipe(argv[2]);
    if (operation == L"security") return ProbeSecurity(argv[2]);
    if (operation == L"fsctl") {
        return ProbeFsctl(argv[2], argc >= 4 ? (DWORD)_wtoi(argv[3]) : 0);
    }
    if (operation == L"network") {
        if (argc < 4) { Usage(); return 2; }
        return ProbeNetwork(argv[2], _wtoi(argv[3]));
    }
    Usage();
    return 2;
}
