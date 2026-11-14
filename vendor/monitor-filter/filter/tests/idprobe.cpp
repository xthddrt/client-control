#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>
#include <ntddndis.h>
#include <ntddscsi.h>
#include <setupapi.h>
#include <hidclass.h>
#include <intrin.h>
#include <cstdio>
#include <string>
#include <vector>

static const GUID IDPROBE_HID_GUID = {
    0x4D1E55B2, 0xF16F, 0x11CF, { 0x88, 0xCB, 0x00, 0x11, 0x11, 0x00, 0x00, 0x30 }
};
static const GUID IDPROBE_NET_GUID = {  /* GUID_DEVINTERFACE_NET */
    0xCAC88484, 0x7515, 0x4C03, { 0x82, 0xE6, 0x71, 0xA8, 0x7A, 0xBA, 0xC3, 0x61 }
};

#define IOCTL_MOUNTMGR_QUERY_POINTS CTL_CODE(0x0000006D, 2, METHOD_BUFFERED, FILE_ANY_ACCESS)
typedef struct _MOUNTMGR_MOUNT_POINT {
    ULONG SymbolicLinkNameOffset;
    USHORT SymbolicLinkNameLength;
    USHORT Reserved1;
    ULONG UniqueIdOffset;
    USHORT UniqueIdLength;
    USHORT Reserved2;
    ULONG DeviceNameOffset;
    USHORT DeviceNameLength;
    USHORT Reserved3;
} MOUNTMGR_MOUNT_POINT;

enum class Outcome { Got, Blocked, Unverified };
static int gRoutes;
static int gFailures;

static Outcome Report(const char* name, bool got, DWORD error)
{
    Outcome outcome = got ? Outcome::Got
                          : error == ERROR_ACCESS_DENIED ? Outcome::Blocked : Outcome::Unverified;
    std::printf("%-24s %s\n", name,
                outcome == Outcome::Got ? "got" : outcome == Outcome::Blocked ? "blocked" : "unverified");
    return outcome;
}

static void ExpectBlocked(const char* name, Outcome outcome)
{
    gRoutes++;
    if (outcome != Outcome::Blocked) gFailures++;
    (void)name;
}

static Outcome OpenProbe(const wchar_t* path, const char* name)
{
    HANDLE device = CreateFileW(path, GENERIC_READ | GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (device == INVALID_HANDLE_VALUE) return Report(name, false, GetLastError());
    CloseHandle(device);
    return Report(name, true, ERROR_SUCCESS);
}

static Outcome ControlProbe(const wchar_t* path, const char* name, DWORD code,
                            void* input, DWORD inputLength, void* output, DWORD outputLength)
{
    HANDLE device = CreateFileW(path, GENERIC_READ | GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (device == INVALID_HANDLE_VALUE) return Report(name, false, GetLastError());
    DWORD returned = 0;
    BOOL ok = DeviceIoControl(device, code, input, inputLength, output, outputLength, &returned, nullptr);
    DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    CloseHandle(device);
    return Report(name, ok != 0, error);
}

static Outcome StorageProbe(const wchar_t* path, const char* name)
{
    STORAGE_PROPERTY_QUERY query{};
    query.PropertyId = StorageDeviceProperty;
    query.QueryType = PropertyStandardQuery;
    BYTE output[1024];
    return ControlProbe(path, name, IOCTL_STORAGE_QUERY_PROPERTY,
                        &query, sizeof(query), output, sizeof(output));
}

/* Device interface paths from SetupDi, which does not go through \Device\Nsi
 * (denied to the protected process, so GetAdaptersAddresses cannot list adapters). */
static std::vector<std::wstring> InterfacePaths(const GUID& guid)
{
    std::vector<std::wstring> paths;
    HDEVINFO devices = SetupDiGetClassDevsW(&guid, nullptr, nullptr, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (devices == INVALID_HANDLE_VALUE) return paths;
    for (DWORD index = 0;; index++) {
        SP_DEVICE_INTERFACE_DATA interfaceData{};
        interfaceData.cbSize = sizeof(interfaceData);
        if (!SetupDiEnumDeviceInterfaces(devices, nullptr, &guid, index, &interfaceData)) break;
        DWORD needed = 0;
        (void)SetupDiGetDeviceInterfaceDetailW(devices, &interfaceData, nullptr, 0, &needed, nullptr);
        if (needed == 0) continue;
        std::vector<BYTE> detailBytes(needed);
        auto* detail = reinterpret_cast<SP_DEVICE_INTERFACE_DETAIL_DATA_W*>(detailBytes.data());
        detail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);
        if (SetupDiGetDeviceInterfaceDetailW(devices, &interfaceData, detail, needed, &needed, nullptr)) {
            paths.push_back(detail->DevicePath);
        }
    }
    SetupDiDestroyDeviceInfoList(devices);
    return paths;
}

static void ProbeNdis()
{
    int found = 0;
    for (const std::wstring& path : InterfacePaths(IDPROBE_NET_GUID)) {
        ULONG oid = OID_802_3_CURRENT_ADDRESS;
        BYTE output[64];
        ExpectBlocked("ndis-mac", ControlProbe(path.c_str(), "ndis-mac", IOCTL_NDIS_QUERY_GLOBAL_STATS,
                                               &oid, sizeof(oid), output, sizeof(output)));
        found++;
    }
    if (found == 0) ExpectBlocked("ndis", Report("ndis", false, ERROR_NOT_FOUND));
}

static void ProbeScsi()
{
    int found = 0;
    for (ULONG index = 0; index < 256; index++) {
        wchar_t path[64];
        swprintf_s(path, L"\\\\.\\Scsi%lu:", index);
        HANDLE device = CreateFileW(path, GENERIC_READ | GENERIC_WRITE,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        if (device == INVALID_HANDLE_VALUE) {
            DWORD error = GetLastError();
            if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) continue;
            ExpectBlocked("scsi", Report("scsi", false, error));
            found++;
            continue;
        }
        found++;
        BYTE inquiry[4096];
        DWORD returned = 0;
        BOOL ok = DeviceIoControl(device, IOCTL_SCSI_GET_INQUIRY_DATA, nullptr, 0,
                                  inquiry, sizeof(inquiry), &returned, nullptr);
        DWORD error = ok ? ERROR_SUCCESS : GetLastError();
        ExpectBlocked("scsi-inquiry", Report("scsi-inquiry", ok != 0, error));

        struct {
            SCSI_PASS_THROUGH_DIRECT Packet;
            UCHAR Sense[32];
        } request{};
        BYTE data[96];
        request.Packet.Length = sizeof(request.Packet);
        request.Packet.CdbLength = 6;
        request.Packet.DataIn = SCSI_IOCTL_DATA_IN;
        request.Packet.DataTransferLength = sizeof(data);
        request.Packet.TimeOutValue = 5;
        request.Packet.DataBuffer = data;
        request.Packet.SenseInfoOffset = sizeof(request.Packet);
        request.Packet.SenseInfoLength = sizeof(request.Sense);
        request.Packet.Cdb[0] = 0x12;
        request.Packet.Cdb[1] = 1;
        request.Packet.Cdb[2] = 0x80;
        request.Packet.Cdb[4] = sizeof(data);
        returned = 0;
        ok = DeviceIoControl(device, IOCTL_SCSI_PASS_THROUGH_DIRECT,
                             &request, sizeof(request), &request, sizeof(request), &returned, nullptr);
        error = ok ? ERROR_SUCCESS : GetLastError();
        ExpectBlocked("scsi-pass-through", Report("scsi-pass-through", ok != 0, error));
        CloseHandle(device);
    }
    if (found == 0) ExpectBlocked("scsi", Report("scsi", false, ERROR_NOT_FOUND));
}

static void ProbeHid()
{
    int found = 0;
    for (const std::wstring& path : InterfacePaths(IDPROBE_HID_GUID)) {
        ExpectBlocked("hid-open", OpenProbe(path.c_str(), "hid-open"));
        found++;
    }
    if (found == 0) ExpectBlocked("hid", Report("hid", false, ERROR_NOT_FOUND));
}

static void FlagOnly()
{
    BYTE firmware[4096];
    (void)GetSystemFirmwareTable(0x52534D42u, 0, firmware, sizeof(firmware));
    std::printf("%-24s flag-only\n", "smbios");

    HANDLE token = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        BYTE user[512];
        DWORD returned = 0;
        (void)GetTokenInformation(token, TokenUser, user, sizeof(user), &returned);
        CloseHandle(token);
    }
    std::printf("%-24s flag-only\n", "machine-sid");

    int cpu[4];
    __cpuid(cpu, 0);
    std::printf("%-24s flag-only\n", "cpuid");
}

int main()
{
    SetConsoleOutputCP(CP_UTF8);
    ExpectBlocked("disk0-serial", StorageProbe(L"\\\\.\\PhysicalDrive0", "disk0-serial"));
    ExpectBlocked("volume-serial", StorageProbe(L"\\\\.\\C:", "volume-serial"));
    ExpectBlocked("nsi", OpenProbe(L"\\\\.\\Nsi", "nsi"));
    ProbeNdis();
    MOUNTMGR_MOUNT_POINT point{};
    BYTE points[4096];
    ExpectBlocked("mount-points", ControlProbe(L"\\\\.\\MountPointManager", "mount-points",
                                               IOCTL_MOUNTMGR_QUERY_POINTS, &point, sizeof(point),
                                               points, sizeof(points)));
    ProbeScsi();
    ProbeHid();
    FlagOnly();
    return gRoutes != 0 && gFailures == 0 ? 0 : 1;
}
