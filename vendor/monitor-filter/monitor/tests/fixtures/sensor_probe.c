/*
 * Controlled sensor fixture.  Run it in the isolated VM while the monitor is
 * collecting, then compare the expected scenario events in tests/scenarios.
 * This is not a test of the monitor's correctness; it supplies known activity.
 */

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <aclapi.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")

static void pause_ms(DWORD ms)
{
    Sleep(ms);
}

static int file_probe(void)
{
    wchar_t temp[MAX_PATH];
    wchar_t path[MAX_PATH];
    DWORD length = GetTempPathW(MAX_PATH, temp);
    if (length == 0 || length >= MAX_PATH) return 1;
    swprintf_s(path, MAX_PATH, L"%smsmon-fixture-%lu.bin", temp, GetCurrentProcessId());

    HANDLE file = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return 1;
    char data[4096];
    memset(data, 'A', sizeof(data));
    DWORD written = 0;
    WriteFile(file, data, sizeof(data), &written, NULL);
    FlushFileBuffers(file);
    SetFilePointer(file, 0, NULL, FILE_BEGIN);
    DWORD read = 0;
    ReadFile(file, data, sizeof(data), &read, NULL);

    PSECURITY_DESCRIPTOR security = NULL;
    DWORD securitySize = 0;
    GetFileSecurityW(path, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, NULL, 0, &securitySize);
    if (securitySize != 0) {
        security = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, securitySize);
        if (security != NULL) {
            GetFileSecurityW(path, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                             security, securitySize, &securitySize);
            LocalFree(security);
        }
    }

    HANDLE mapping = CreateFileMappingW(file, NULL, PAGE_READWRITE, 0, 4096, NULL);
    if (mapping != NULL) {
        void* view = MapViewOfFile(mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 4096);
        if (view != NULL) {
            volatile char value = *(volatile char*)view;
            (void)value;
            UnmapViewOfFile(view);
        }
        CloseHandle(mapping);
    }
    CloseHandle(file);
    DeleteFileW(path);
    pause_ms(300);
    return 0;
}

static int registry_probe(void)
{
    HKEY key = NULL;
    wchar_t subkey[128];
    swprintf_s(subkey, 128, L"Software\\msmon-fixture-%lu", GetCurrentProcessId());
    if (RegCreateKeyExW(HKEY_CURRENT_USER, subkey, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &key, NULL) != ERROR_SUCCESS) {
        return 1;
    }
    const wchar_t* text = L"fixture";
    RegSetValueExW(key, L"Text", 0, REG_SZ, (const BYTE*)text,
                   (DWORD)((wcslen(text) + 1) * sizeof(wchar_t)));
    DWORD number = 42;
    RegSetValueExW(key, L"Number", 0, REG_DWORD, (const BYTE*)&number, sizeof(number));
    BYTE large[8192];
    memset(large, 0x5A, sizeof(large));
    RegSetValueExW(key, L"Large", 0, REG_BINARY, large, sizeof(large));

    DWORD type = 0;
    DWORD size = 0;
    RegQueryValueExW(key, L"Text", NULL, &type, NULL, &size);
    if (size != 0) {
        BYTE* buffer = (BYTE*)LocalAlloc(LPTR, size);
        if (buffer != NULL) {
            RegQueryValueExW(key, L"Text", NULL, &type, buffer, &size);
            LocalFree(buffer);
        }
    }
    DWORD index = 0;
    wchar_t valueName[256];
    DWORD valueNameSize = 256;
    while (RegEnumValueW(key, index++, valueName, &valueNameSize, NULL, &type, NULL, &size) == ERROR_SUCCESS) {
        valueNameSize = 256;
    }
    wchar_t childName[256];
    DWORD childSize = 256;
    RegEnumKeyExW(key, 0, childName, &childSize, NULL, NULL, NULL, NULL);

    RegDeleteValueW(key, L"Text");
    RegCloseKey(key);
    RegDeleteKeyW(HKEY_CURRENT_USER, subkey);
    pause_ms(300);
    return 0;
}

static int ipc_probe(void)
{
    wchar_t pipeName[128];
    swprintf_s(pipeName, 128, L"\\\\.\\pipe\\msmon-fixture-%lu", GetCurrentProcessId());
    HANDLE server = CreateNamedPipeW(pipeName, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                                     PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, NULL);
    if (server != INVALID_HANDLE_VALUE) {
        HANDLE client = CreateFileW(pipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (client != INVALID_HANDLE_VALUE) {
            ConnectNamedPipe(server, NULL);
            DWORD written = 0;
            WriteFile(server, "ping", 4, &written, NULL);
            char buffer[8] = {0};
            DWORD read = 0;
            ReadFile(client, buffer, sizeof(buffer), &read, NULL);
            CloseHandle(client);
        }
        DisconnectNamedPipe(server);
        CloseHandle(server);
    }

    wchar_t mailslotName[128];
    swprintf_s(mailslotName, 128, L"\\\\.\\mailslot\\msmon-fixture-%lu", GetCurrentProcessId());
    HANDLE mailslot = CreateMailslotW(mailslotName, 0, 0, NULL);
    if (mailslot != INVALID_HANDLE_VALUE) {
        HANDLE writer = CreateFileW(mailslotName, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (writer != INVALID_HANDLE_VALUE) {
            DWORD written = 0;
            WriteFile(writer, "hello", 5, &written, NULL);
            CloseHandle(writer);
        }
        CloseHandle(mailslot);
    }
    pause_ms(300);
    return 0;
}

static int network_probe(void)
{
    WSADATA wsa;
    memset(&wsa, 0, sizeof(wsa));
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 1;
    SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) {
        WSACleanup();
        return 1;
    }
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (bind(listener, (struct sockaddr*)&address, sizeof(address)) != 0 || listen(listener, 1) != 0) {
        closesocket(listener);
        WSACleanup();
        return 1;
    }
    int size = sizeof(address);
    getsockname(listener, (struct sockaddr*)&address, &size);
    SOCKET client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (client != INVALID_SOCKET) {
        if (connect(client, (struct sockaddr*)&address, sizeof(address)) == 0) {
            SOCKET accepted = accept(listener, NULL, NULL);
            if (accepted != INVALID_SOCKET) {
                const char* message = "fixture";
                send(client, message, (int)strlen(message), 0);
                char buffer[16] = {0};
                recv(accepted, buffer, sizeof(buffer), 0);
                closesocket(accepted);
            }
        }
        closesocket(client);
    }
    closesocket(listener);
    WSACleanup();
    pause_ms(300);
    return 0;
}

static int handles_probe(void)
{
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
    HANDLE thread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentThreadId());
    HANDLE duplicate = NULL;
    if (process != NULL) {
        DuplicateHandle(GetCurrentProcess(), process, GetCurrentProcess(), &duplicate,
                        0, FALSE, DUPLICATE_SAME_ACCESS);
    }
    if (duplicate != NULL) CloseHandle(duplicate);
    if (thread != NULL) CloseHandle(thread);
    if (process != NULL) CloseHandle(process);
    pause_ms(300);
    return 0;
}

int main(int argc, char** argv)
{
    const char* mode = argc > 1 ? argv[1] : "all";
    int result = 0;
    if (strcmp(mode, "file") == 0 || strcmp(mode, "all") == 0) result |= file_probe();
    if (strcmp(mode, "registry") == 0 || strcmp(mode, "all") == 0) result |= registry_probe();
    if (strcmp(mode, "ipc") == 0 || strcmp(mode, "all") == 0) result |= ipc_probe();
    if (strcmp(mode, "network") == 0 || strcmp(mode, "all") == 0) result |= network_probe();
    if (strcmp(mode, "handles") == 0 || strcmp(mode, "all") == 0) result |= handles_probe();
    printf("sensor_probe %s result=%d\n", mode, result);
    return result;
}
