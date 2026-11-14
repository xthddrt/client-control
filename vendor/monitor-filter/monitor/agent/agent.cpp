#include "telemetry.h"
#include "classify.h"
#include "etw.h"
#include "integrations.h"
#include "../include/msmon_coverage.h"
#ifdef _WIN32
#include <tlhelp32.h>
#include <bcrypt.h>
#include <winver.h>
#else
#include "linux/session.h"
#include <algorithm>
#endif
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <wchar.h>
#include <fstream>
#include <iostream>
#include <memory>
#include <deque>
#include <mutex>
#include <set>
#include <sstream>
#include <thread>
#include <unordered_set>

#ifdef _WIN32
#pragma comment(lib, "version.lib")
#endif

static std::atomic<bool> gStop(false);

static BOOL WINAPI ConsoleHandler(DWORD type)
{
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_CLOSE_EVENT) {
        gStop.store(true);
        return TRUE;
    }
    return FALSE;
}

static uint64_t FileTimeValue(const FILETIME& value)
{
    return (static_cast<uint64_t>(value.dwHighDateTime) << 32) | value.dwLowDateTime;
}

static uint64_t Now()
{
    FILETIME value;
    GetSystemTimeAsFileTime(&value);
    return FileTimeValue(value);
}

static std::wstring UtcStamp(uint64_t fileTime)
{
    FILETIME value{static_cast<DWORD>(fileTime & 0xffffffff), static_cast<DWORD>(fileTime >> 32)};
    SYSTEMTIME time{};
    if (!FileTimeToSystemTime(&value, &time)) return L"unknown";
    wchar_t buffer[40];
    swprintf_s(buffer, L"%04u%02u%02uT%02u%02u%02uZ", time.wYear, time.wMonth, time.wDay,
               time.wHour, time.wMinute, time.wSecond);
    return buffer;
}

static std::wstring SanitizeLabel(const std::wstring& input, const wchar_t* fallback)
{
    std::wstring output;
    for (wchar_t c : input) {
        bool allowed = (c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') ||
                       (c >= L'0' && c <= L'9') || c == L'-' || c == L'_' || c == L'.';
        if (allowed) {
            output.push_back(c);
        } else if (output.empty() || output.back() != L'-') {
            output.push_back(L'-');
        }
    }
    while (!output.empty() && (output.back() == L'-' || output.back() == L'.')) output.pop_back();
    if (output.size() > 64) output.resize(64);
    return output.empty() ? std::wstring(fallback) : output;
}

static bool AllowedLabel(const std::wstring& value, std::initializer_list<const wchar_t*> values)
{
    for (const wchar_t* item : values) {
        if (value == item) return true;
    }
    return false;
}

static std::wstring Utf8ToWide(const std::string& value)
{
    if (value.empty()) return {};
    int length = MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0);
    if (length <= 0) return {};
    std::wstring output(static_cast<size_t>(length), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), output.data(), length);
    return output;
}

static std::wstring MachineLabel()
{
    wchar_t name[256];
    DWORD size = static_cast<DWORD>(std::size(name));
    if (GetComputerNameW(name, &size) == 0) return L"unknown";
    return SanitizeLabel(name, L"unknown");
}

static std::string MachineIdHash()
{
    std::string material;
#ifndef _WIN32
    for (const char* path : {"/etc/machine-id", "/var/lib/dbus/machine-id"}) {
        std::ifstream file(path);
        if (std::getline(file, material) && !material.empty()) break;
    }
    return material.empty() ? std::string() : "sha256:" + Sha256(material);
#else
    wchar_t guid[128];
    DWORD bytes = sizeof(guid);
    if (RegGetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid",
                     RRF_RT_REG_SZ, nullptr, guid, &bytes) == ERROR_SUCCESS) {
        material += WideToUtf8(guid);
    }
    DWORD serial = 0;
    wchar_t volume[256];
    wchar_t filesystem[32];
    if (GetVolumeInformationW(L"C:\\", volume, static_cast<DWORD>(std::size(volume)), &serial,
                              nullptr, nullptr, filesystem, static_cast<DWORD>(std::size(filesystem)))) {
        material += ":" + std::to_string(serial);
    }
    return material.empty() ? std::string() : "sha256:" + Sha256(material);
#endif
}

static std::string ClientVersion(const std::wstring& path)
{
#ifndef _WIN32
    /* ELF executables carry no version resource. */
    (void)path;
    return {};
#else
    DWORD handle = 0;
    DWORD size = GetFileVersionInfoSizeW(path.c_str(), &handle);
    if (size == 0) return {};
    std::vector<BYTE> data(size);
    if (!GetFileVersionInfoW(path.c_str(), 0, size, data.data())) return {};
    VS_FIXEDFILEINFO* info = nullptr;
    UINT length = 0;
    if (!VerQueryValueW(data.data(), L"\\", reinterpret_cast<LPVOID*>(&info), &length) ||
        info == nullptr || length < sizeof(*info)) return {};
    char buffer[64];
    snprintf(buffer, sizeof(buffer), "%u.%u.%u.%u",
             HIWORD(info->dwFileVersionMS), LOWORD(info->dwFileVersionMS),
             HIWORD(info->dwFileVersionLS), LOWORD(info->dwFileVersionLS));
    return buffer;
#endif
}

static std::wstring ExecutablePath()
{
    std::vector<wchar_t> path(32768);
    DWORD size = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (size == 0 || size >= path.size()) return {};
    return std::wstring(path.data(), size);
}

static std::wstring DriverFilePath()
{
#ifndef _WIN32
    /* The Linux sensors are part of the agent binary. */
    return {};
#else
    wchar_t system[32768];
    UINT size = GetSystemDirectoryW(system, static_cast<UINT>(std::size(system)));
    if (size == 0 || size >= std::size(system)) return {};
    return std::wstring(system, size) + L"\\drivers\\msmon.sys";
#endif
}

static bool ReadTextFile(const std::filesystem::path& path, std::string& output)
{
    std::ifstream file(path, std::ios::binary);
    if (!file) return false;
    std::ostringstream buffer;
    buffer << file.rdbuf();
    output = buffer.str();
    return true;
}

static std::string JsonField(const std::string& text, const std::string& key)
{
    const std::string needle = "\"" + key + "\"";
    size_t position = text.find(needle);
    if (position == std::string::npos) return {};
    position = text.find(':', position + needle.size());
    if (position == std::string::npos) return {};
    position = text.find('"', position + 1);
    if (position == std::string::npos) return {};
    size_t end = position + 1;
    while (end < text.size() && text[end] != '"') {
        if (text[end] == '\\') end++;
        end++;
    }
    if (end >= text.size()) return {};
    return text.substr(position + 1, end - position - 1);
}

static bool ReadBuildInfo(std::string& text, std::string& hash)
{
    std::wstring executable = ExecutablePath();
    std::error_code error;
    std::vector<std::filesystem::path> candidates;
    if (!executable.empty()) {
        std::filesystem::path directory = std::filesystem::path(executable).parent_path();
        candidates.push_back(directory / L".." / L".." / L"build-info.json");
        candidates.push_back(directory / L"build-info.json");
    }
    candidates.push_back(std::filesystem::current_path(error) / L"build" / L"build-info.json");
    candidates.push_back(std::filesystem::current_path(error) / L"build-info.json");
    for (const auto& candidate : candidates) {
        if (ReadTextFile(candidate, text)) {
            hash = Sha256(text);
            return true;
        }
    }
    return false;
}

static void WriteTextFile(const std::filesystem::path& path, const std::string& content)
{
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (file) file << content;
}

static bool GenerateUuid(std::wstring& uuid, std::wstring& shortId, uint64_t& numericId)
{
    BYTE bytes[16]{};
    if (BCryptGenRandom(nullptr, bytes, sizeof(bytes), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) return false;
    bytes[6] = static_cast<BYTE>((bytes[6] & 0x0F) | 0x40);
    bytes[8] = static_cast<BYTE>((bytes[8] & 0x3F) | 0x80);
    wchar_t buffer[40];
    swprintf_s(buffer, L"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
               bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
               bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);
    uuid = buffer;
    shortId = uuid.substr(0, 8);
    numericId = 0;
    for (int index = 0; index < 8; index++) numericId = (numericId << 8) | bytes[index];
    if (numericId == 0) numericId = 1;
    return true;
}

struct SessionLabels {
    std::wstring uuid;
    std::wstring uuidShort;
    uint64_t id = 0;
    std::wstring label;
    std::wstring testId;
    std::wstring scenario;
    std::wstring phase;
    std::wstring machine;
    std::string machineHash;
    uint64_t iteration = 1;
    std::wstring started;
};

struct SessionBinaryInfo {
    std::string agentHash;
    std::string driverHash;
    std::string buildInfoHash;
    std::string buildCommit;
    std::string clientVersion;
    std::string clientHash;
    bool buildInfoPresent = false;
    std::string buildInfoRaw;
};

static std::string BuildCoverageJson(
    const MSMON_COVERAGE& coverage, const MSMON_COVERAGE* start, bool supported, const EtwCollector* etw,
    uint64_t queueDrops, unsigned parts, uint64_t bytes, const std::wstring& sessionUuid,
    const std::wstring& kfilterState, uint64_t kfilterDropped,
    const std::unordered_map<unsigned long, uint64_t>& eventCounts)
{
    auto delta = [&](uint64_t end, uint64_t begin) { return end - begin; };
    std::ostringstream json;
    json << "{\"schema_version\":1,\"session_uuid\":\"" << WideToUtf8(sessionUuid) << "\""
         << ",\"driver_supported\":" << (supported ? "true" : "false")
         << ",\"driver\":{\"version\":" << coverage.Version
         << ",\"registration_ok\":" << coverage.RegistrationOk
         << ",\"registration_failed\":" << coverage.RegistrationFailed
         << ",\"event_attempted\":[";
    for (unsigned index = 0; index < MSMON_EVENT_SLOTS; index++) {
        if (index != 0) json << ',';
        json << delta(coverage.EventAttempted[index], start ? start->EventAttempted[index] : 0);
    }
    json << "],\"event_dropped\":[";
    for (unsigned index = 0; index < MSMON_EVENT_SLOTS; index++) {
        if (index != 0) json << ',';
        json << delta(coverage.EventDropped[index], start ? start->EventDropped[index] : 0);
    }
    json << "],\"sensor_entered\":[";
    for (unsigned index = 0; index < MSMON_SENSOR_SLOTS; index++) {
        if (index != 0) json << ',';
        json << delta(coverage.SensorEntered[index], start ? start->SensorEntered[index] : 0);
    }
    json << "],\"sensor_logged\":[";
    for (unsigned index = 0; index < MSMON_SENSOR_SLOTS; index++) {
        if (index != 0) json << ',';
        json << delta(coverage.SensorLogged[index], start ? start->SensorLogged[index] : 0);
    }
    json << "],\"registration_status\":[";
    for (unsigned index = 0; index < MSMON_SENSOR_SLOTS; index++) {
        if (index != 0) json << ',';
        json << coverage.RegistrationStatus[index];
    }
    json << "],\"skip_untracked\":" << delta(coverage.SkipUntracked, start ? start->SkipUntracked : 0)
         << ",\"skip_irql\":" << delta(coverage.SkipIrql, start ? start->SkipIrql : 0)
         << ",\"skip_no_name\":" << delta(coverage.SkipNoName, start ? start->SkipNoName : 0)
         << ",\"alloc_failures\":" << delta(coverage.AllocFailures, start ? start->AllocFailures : 0)
         << ",\"track_failures\":" << delta(coverage.TrackFailures, start ? start->TrackFailures : 0)
         << ",\"queue_drops\":" << delta(coverage.QueueDrops, start ? start->QueueDrops : 0)
         << ",\"blackcat_matches\":" << delta(coverage.BlackCatMatches, start ? start->BlackCatMatches : 0)
         << ",\"payload_captured\":[";
    for (size_t index = 0; index < std::size(coverage.PayloadCaptured); index++) {
        if (index != 0) json << ',';
        json << delta(coverage.PayloadCaptured[index], start ? start->PayloadCaptured[index] : 0);
    }
    json << "]}"
         << ",\"agent\":{\"writer_parts\":" << parts
         << ",\"writer_bytes\":" << bytes
         << ",\"etw_queue_drops\":" << queueDrops
         << ",\"kfilter_state\":\"" << JsonEscape(WideToUtf8(kfilterState)) << "\""
         << ",\"kfilter_dropped_events\":" << kfilterDropped;
    if (etw != nullptr) {
        static const char* providers[EtwCollector::PROVIDERS] = {"wmi", "dns", "rpc", "tcp", "codeintegrity"};
        json << ",\"etw_lost\":" << etw->LostEvents()
             << ",\"etw_parse_failures\":" << etw->ParseFailures()
             << ",\"etw_unattributed\":" << etw->UnattributedCount()
             << ",\"etw_pending_overflow\":" << etw->PendingOverflow()
             << ",\"etw_providers\":[";
        for (int index = 0; index < EtwCollector::PROVIDERS; index++) {
            if (index != 0) json << ',';
            json << "{\"name\":\"" << providers[index] << "\""
                 << ",\"received\":" << etw->Received(index)
                 << ",\"parsed\":" << etw->Parsed(index)
                 << ",\"emitted\":" << etw->Emitted(index)
                 << ",\"deferred\":" << etw->Deferred(index)
                 << ",\"expired\":" << etw->Expired(index) << "}";
        }
        json << "]";
    } else {
        json << ",\"etw_lost\":0,\"etw_parse_failures\":0,\"etw_unattributed\":0"
             << ",\"etw_pending_overflow\":0,\"etw_providers\":[]";
    }
    json << ",\"event_counts\":{";
    bool firstCount = true;
    for (const auto& item : eventCounts) {
        if (!firstCount) json << ',';
        firstCount = false;
        json << "\"" << item.first << "\":" << item.second;
    }
    json << "}}}";
    return json.str();
}

static std::string BuildSessionMeta(
    const SessionLabels& labels, const SessionBinaryInfo& binaries,
    const std::wstring& clientRoot, const std::wstring& scopeRoot,
    bool payload, bool secrets, bool etw, uint64_t queueRecords, uint64_t queueBytes,
    const std::wstring& outcome, const std::wstring& ended,
    uint64_t events, uint64_t dropped, uint64_t driverGaps, uint64_t etwGaps,
    uint64_t records, uint64_t bytes, unsigned parts)
{
    (void)secrets;   /* Linux only */
    std::ostringstream json;
    json << "{\"schema_version\":1"
         << ",\"session_uuid\":\"" << WideToUtf8(labels.uuid) << "\""
         << ",\"session_id\":" << labels.id
         << ",\"session_label\":\"" << JsonEscape(WideToUtf8(labels.label)) << "\""
         << ",\"test_id\":\"" << JsonEscape(WideToUtf8(labels.testId)) << "\""
         << ",\"scenario\":\"" << WideToUtf8(labels.scenario) << "\""
         << ",\"phase\":\"" << WideToUtf8(labels.phase) << "\""
         << ",\"iteration\":" << labels.iteration
         << ",\"machine_label\":\"" << WideToUtf8(labels.machine) << "\""
         << ",\"machine_id_hash\":\"" << labels.machineHash << "\""
         << ",\"started_utc\":\"" << WideToUtf8(labels.started) << "\""
         << ",\"ended_utc\":\"" << WideToUtf8(ended) << "\""
         << ",\"outcome\":\"" << WideToUtf8(outcome) << "\""
         << ",\"client_root\":\"" << JsonEscape(WideToUtf8(clientRoot)) << "\""
         << ",\"scope_root\":\"" << JsonEscape(WideToUtf8(scopeRoot)) << "\""
         << ",\"client_version\":\"" << binaries.clientVersion << "\""
         << ",\"client_sha256\":\"" << binaries.clientHash << "\""
         << ",\"agent_sha256\":\"" << binaries.agentHash << "\""
         << ",\"driver_sha256\":\"" << binaries.driverHash << "\""
         << ",\"build_info_present\":" << (binaries.buildInfoPresent ? "true" : "false")
         << ",\"build_info_sha256\":\"" << binaries.buildInfoHash << "\""
         << ",\"build_commit\":\"" << JsonEscape(binaries.buildCommit) << "\""
         << ",\"config\":{\"payload_mode\":\"" << (payload ? "full" : "metadata") << "\""
         << ",\"etw\":" << (etw ? "true" : "false")
         << ",\"queue_records\":" << queueRecords
         << ",\"queue_bytes\":" << queueBytes << "}"
#ifndef _WIN32
         /* The Linux log holds the client's socket bytes (tokens, chat, netlink MAC data) once the eBPF
          * net sensor or the wineserver decoder runs with payloads: docs/STORAGE.md. */
         << ",\"sensitivity\":\"" << (secrets ? "secrets" : payload ? "payload" : "metadata") << "\""
#endif
         << ",\"events\":" << events
         << ",\"driver_dropped_events\":" << dropped
         << ",\"driver_sequence_gaps\":" << driverGaps
         << ",\"etw_sequence_gaps\":" << etwGaps
         << ",\"record_count\":" << records
         << ",\"raw_bytes\":" << bytes
         << ",\"part_count\":" << parts;
    if (binaries.buildInfoPresent) {
        json << ",\"build_info_raw\":\"" << JsonEscape(binaries.buildInfoRaw) << "\"";
    }
    json << "}";
    return json.str();
}

#ifndef _WIN32
static std::wstring FullPath(const std::wstring& input)
{
    std::error_code error;
    if (input.empty()) return {};
    std::wstring output = std::filesystem::absolute(input, error).lexically_normal().wstring();
    while (output.size() > 1 && output.back() == L'/') output.pop_back();
    return error ? std::wstring() : output;
}

/* Linux paths are used as they are: the sensors see the same absolute names. */
static bool DevicePath(const std::wstring& dosPath, std::wstring& devicePath, std::string& error)
{
    if (dosPath.empty() || dosPath[0] != L'/') {
        error = "Only absolute paths are supported";
        return false;
    }
    devicePath = dosPath;
    return true;
}

static bool ProcessIdentity(DWORD pid, std::wstring& path, uint64_t& startTime)
{
    return LinuxProcessIdentity(pid, path, startTime);
}
#else
static std::wstring FullPath(const std::wstring& input)
{
    DWORD needed = GetFullPathNameW(input.c_str(), 0, nullptr, nullptr);
    if (needed == 0) return {};
    std::wstring output(needed, L'\0');
    if (GetFullPathNameW(input.c_str(), needed, output.data(), nullptr) == 0) return {};
    output.resize(std::wcslen(output.c_str()));
    while (output.size() > 3 && output.back() == L'\\') output.pop_back();
    return output;
}

static bool DevicePath(const std::wstring& dosPath, std::wstring& devicePath, std::string& error)
{
    if (dosPath.size() < 3 || dosPath[1] != L':') {
        error = "Only local drive-letter client paths are supported";
        return false;
    }
    wchar_t drive[3] = {dosPath[0], L':', L'\0'};
    wchar_t device[32768];
    DWORD length = QueryDosDeviceW(drive, device, static_cast<DWORD>(std::size(device)));
    if (length == 0) {
        error = "QueryDosDevice failed with Win32 " + std::to_string(GetLastError());
        return false;
    }
    devicePath = device + dosPath.substr(2);
    return true;
}

static bool ProcessIdentity(DWORD pid, std::wstring& path, uint64_t& startTime)
{
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process == nullptr) return false;
    DWORD size = 32768;
    path.resize(size);
    BOOL ok = QueryFullProcessImageNameW(process, 0, path.data(), &size);
    FILETIME created{}, exited{}, kernel{}, user{};
    if (ok) {
        path.resize(size);
        ok = GetProcessTimes(process, &created, &exited, &kernel, &user);
        if (ok) startTime = FileTimeValue(created);
    }
    CloseHandle(process);
    return ok != 0;
}

class DeviceSession {
public:
    ~DeviceSession()
    {
        if (started_) {
            DWORD bytes = 0;
            (void)DeviceIoControl(handle_, MSMON_IOCTL_STOP_SESSION, nullptr, 0, nullptr, 0, &bytes, nullptr);
        }
        if (handle_ != INVALID_HANDLE_VALUE) CloseHandle(handle_);
    }

    bool Open()
    {
        handle_ = CreateFileA(MSMON_USER_DEVICE_PATH, GENERIC_READ | GENERIC_WRITE,
                              0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        return handle_ != INVALID_HANDLE_VALUE;
    }

    bool Start(MSMON_SESSION_CONFIG& config)
    {
        DWORD bytes = 0;
        started_ = DeviceIoControl(handle_, MSMON_IOCTL_START_SESSION, &config, sizeof(config),
                                   nullptr, 0, &bytes, nullptr) != 0;
        return started_;
    }

    bool Track(DWORD pid, uint64_t startTime, ULONG flags)
    {
        MSMON_TRACK_REQUEST request{pid, flags, startTime};
        DWORD bytes = 0;
        return DeviceIoControl(handle_, MSMON_IOCTL_TRACK_PID, &request, sizeof(request),
                               nullptr, 0, &bytes, nullptr) != 0;
    }

    bool Read(DWORD waitMs, std::vector<BYTE>& buffer, DWORD& bytes)
    {
        MSMON_READ_REQUEST request{waitMs, static_cast<ULONG>(buffer.size())};
        bytes = 0;
        return DeviceIoControl(handle_, MSMON_IOCTL_READ_EVENTS, &request, sizeof(request),
                               buffer.data(), static_cast<DWORD>(buffer.size()), &bytes, nullptr) != 0;
    }

    bool RefreshModules()
    {
        DWORD bytes = 0;
        return DeviceIoControl(handle_, MSMON_IOCTL_REFRESH_MODULES, nullptr, 0,
                               nullptr, 0, &bytes, nullptr) != 0;
    }

    bool StopTracking()
    {
        DWORD bytes = 0;
        return DeviceIoControl(handle_, MSMON_IOCTL_STOP_TRACKING, nullptr, 0,
                               nullptr, 0, &bytes, nullptr) != 0;
    }

    bool Statistics(MSMON_STATISTICS& statistics)
    {
        DWORD bytes = 0;
        return DeviceIoControl(handle_, MSMON_IOCTL_STATISTICS, nullptr, 0,
                               &statistics, sizeof(statistics), &bytes, nullptr) != 0;
    }

    bool Coverage(MSMON_COVERAGE& coverage)
    {
        DWORD bytes = 0;
        std::memset(&coverage, 0, sizeof(coverage));
        return DeviceIoControl(handle_, MSMON_IOCTL_COVERAGE, nullptr, 0,
                               &coverage, sizeof(coverage), &bytes, nullptr) != 0 &&
               bytes >= sizeof(coverage);
    }

private:
    HANDLE handle_ = INVALID_HANDLE_VALUE;
    bool started_ = false;
};
#endif

/*
 * Drains the driver on its own thread.  When reading shared one loop with
 * decoding, classification, hashing and disk writes, the driver's bounded
 * nonpaged queue overflowed during the client's start-up burst (about 250,000
 * file reads in a few seconds) and most of those events were dropped.  Raw
 * read batches now wait here in pageable user memory instead.
 *
 * The reader uses its own device handle.  Device handles are synchronous,
 * so the I/O manager serialises IOCTLs per handle; on the shared handle the
 * main thread's once-per-second module refresh, which waits for the kernel's
 * loaded-module lock, held reads back while BlackCat was being loaded and
 * verified, and about 27,000 client events overflowed the driver queue.  The
 * reader handle never starts a session, so closing it does not stop one.
 */
static const size_t DRIVER_PUMP_LIMIT_BYTES = 256u * 1024u * 1024u;

class DriverPump {
public:
    DriverPump(DWORD waitMs, size_t limitBytes)
        : waitMs_(waitMs), limitBytes_(limitBytes) {}
    ~DriverPump() { Stop(); }

    bool Start()
    {
        if (!device_.Open()) return false;
        worker_ = std::thread([this] { Run(); });
        return true;
    }

    /* Call after StopTracking: read until the driver queue is empty, then finish. */
    void RequestDrain() { drain_.store(true); }

    void Stop()
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stop_ = true;
        }
        space_.notify_all();
        if (worker_.joinable()) worker_.join();
    }

    /* Move every queued batch into `out`, waiting up to timeoutMs for the first. */
    void Take(std::deque<std::vector<BYTE>>& out, DWORD timeoutMs)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        data_.wait_for(lock, std::chrono::milliseconds(timeoutMs),
                       [this] { return !batches_.empty() || finished_; });
        out.swap(batches_);
        batches_.clear();
        bufferedBytes_ = 0;
        lock.unlock();
        space_.notify_all();
    }

    /* True once the reader has finished and every batch has been taken. */
    bool Done() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return finished_ && batches_.empty();
    }

    /* The reader stopped on an error: Win32 code, or invalidCount for a bad byte count. */
    bool Failed(DWORD& error, bool& invalidCount) const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        error = error_;
        invalidCount = invalidCount_;
        return failed_;
    }

    size_t BufferedBytes() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return bufferedBytes_;
    }

    size_t PeakBytes() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return peakBytes_;
    }

    uint64_t BackpressureWaits() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return backpressureWaits_;
    }

    size_t LimitBytes() const { return limitBytes_; }

private:
    void Finish(bool failed, DWORD error, bool invalidCount)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        failed_ = failed;
        error_ = error;
        invalidCount_ = invalidCount;
        finished_ = true;
        data_.notify_all();
    }

    void Run()
    {
        std::vector<BYTE> scratch(MSMON_READ_MAX_BYTES);
        /* The client's start-up saturates every core; keep the drain ahead of it. */
        (void)SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
        for (;;) {
            {
                std::unique_lock<std::mutex> lock(mutex_);
                if (!stop_ && bufferedBytes_ >= limitBytes_) {
                    /* The driver queue absorbs the wait; overflow there is still counted. */
                    backpressureWaits_++;
                    space_.wait(lock, [this] { return stop_ || bufferedBytes_ < limitBytes_; });
                }
                if (stop_) {
                    finished_ = true;
                    data_.notify_all();
                    return;
                }
            }
            const bool drain = drain_.load();
            DWORD bytes = 0;
            if (!device_.Read(drain ? 0 : waitMs_, scratch, bytes)) {
                DWORD error = GetLastError();
                Finish(true, error != 0 ? error : ERROR_GEN_FAILURE, false);
                return;
            }
            if (bytes > scratch.size()) {
                Finish(true, ERROR_INVALID_DATA, true);
                return;
            }
            std::lock_guard<std::mutex> lock(mutex_);
            if (bytes != 0) {
                batches_.emplace_back(scratch.begin(), scratch.begin() + bytes);
                bufferedBytes_ += bytes;
                if (bufferedBytes_ > peakBytes_) peakBytes_ = bufferedBytes_;
                data_.notify_one();
            }
            if (drain && bytes == 0) {
                finished_ = true;
                data_.notify_all();
                return;
            }
        }
    }

    DeviceSession device_;
    const DWORD waitMs_;
    const size_t limitBytes_;
    std::thread worker_;
    std::atomic<bool> drain_{false};
    mutable std::mutex mutex_;
    std::condition_variable data_;
    std::condition_variable space_;
    std::deque<std::vector<BYTE>> batches_;
    size_t bufferedBytes_ = 0;
    size_t peakBytes_ = 0;
    uint64_t backpressureWaits_ = 0;
    bool stop_ = false;
    bool finished_ = false;
    bool failed_ = false;
    bool invalidCount_ = false;
    DWORD error_ = 0;
};

static bool IsUnderRoot(const std::wstring& root, const std::wstring& path)
{
    if (path.size() <= root.size()) return false;
#ifdef _WIN32
    if (_wcsnicmp(path.c_str(), root.c_str(), root.size()) != 0) return false;
    return path[root.size()] == L'\\';
#else
    return path.compare(0, root.size(), root) == 0 && (root == L"/" || path[root.size()] == L'/');
#endif
}

static bool IsUnderAnyRoot(const std::vector<std::wstring>& roots, const std::wstring& path)
{
    for (const auto& root : roots) {
        if (IsUnderRoot(root, path)) return true;
    }
    return false;
}

static std::wstring JoinRoots(const std::vector<std::wstring>& roots)
{
    std::wstring joined;
    for (const auto& root : roots) {
        if (!joined.empty()) joined += L'|';
        joined += root;
    }
    return joined;
}

/*
 * Copies small text files that tracked processes write under the client and
 * Nexon data folders into the session bundle.  The client writes short-lived
 * diagnostics (for example _ms_report.ini when a server connection drops)
 * and deletes them within a second, and the driver does not capture file
 * contents.  A copy is taken once a file has had no write for 150 ms, at most
 * once every 2 s per file, within per-session limits; each copy is logged
 * with its SHA-256 so the hash chain covers it.
 */
class FileSnapshotter {
public:
    FileSnapshotter(const std::filesystem::path& sessionDir, std::vector<std::wstring> roots)
        : directory_(sessionDir / L"snapshots"), roots_(std::move(roots))
    {
#ifdef _WIN32
        for (wchar_t letter = L'A'; letter <= L'Z'; letter++) {
            wchar_t drive[3] = {letter, L':', L'\0'};
            wchar_t target[1024];
            if (QueryDosDeviceW(drive, target, static_cast<DWORD>(std::size(target))) != 0) {
                devices_.emplace_back(target, drive);
            }
        }
#else
        /* Event paths are kernel-resolved (drive_c); a root named through dosdevices/c: or a symlink is not. */
        for (auto& root : roots_) root = LinuxResolvedPath(root);
#endif
    }

    void Note(const std::wstring& devicePath)
    {
        std::wstring path = DosPath(devicePath);
        if (path.empty() || !Eligible(path)) return;
        pending_[path] = GetTickCount64() + SETTLE_MS;
    }

    /* Take the copies that are due; with flush, take every pending copy now. */
    template <typename Log>
    bool Process(bool flush, Log&& log)
    {
        const uint64_t now = GetTickCount64();
        for (auto it = pending_.begin(); it != pending_.end();) {
            uint64_t& last = taken_[it->first];
            if (!flush && (it->second > now || (last != 0 && now - last < INTERVAL_MS))) {
                ++it;
                continue;
            }
            std::wstring path = it->first;
            it = pending_.erase(it);
            last = now;
            if (!Take(path, log)) return false;
        }
        return true;
    }

private:
    static constexpr uint64_t SETTLE_MS = 150;
    static constexpr uint64_t INTERVAL_MS = 2000;
    static constexpr uint64_t MAX_FILE_BYTES = 256u * 1024u;
    static constexpr uint64_t MAX_REG_FILE_BYTES = 16u * 1024u * 1024u;
    static constexpr uint64_t MAX_TOTAL_BYTES = 64ull * 1024ull * 1024ull;
    static constexpr unsigned MAX_FILES = 2000;

    std::wstring DosPath(const std::wstring& devicePath) const
    {
#ifndef _WIN32
        return LinuxResolvedPath(devicePath);   /* a rename target can name dosdevices/c: */
#endif
        for (const auto& device : devices_) {
            const std::wstring& prefix = device.first;
            if (devicePath.size() > prefix.size() &&
                _wcsnicmp(devicePath.c_str(), prefix.c_str(), prefix.size()) == 0 &&
                devicePath[prefix.size()] == L'\\') {
                return device.second + devicePath.substr(prefix.size());
            }
        }
        return {};
    }

    bool Eligible(const std::wstring& path) const
    {
        static const wchar_t* extensions[] = {L".ini", L".log", L".txt", L".json", L".xml", L".cfg", L".reg"};
        std::wstring extension = std::filesystem::path(path).extension().wstring();
        bool textual = false;
        for (const wchar_t* candidate : extensions) {
            if (_wcsicmp(extension.c_str(), candidate) == 0) textual = true;
        }
        return textual && IsUnderAnyRoot(roots_, path);
    }

    template <typename Log>
    bool Take(const std::wstring& path, Log&& log)
    {
        if (files_ >= MAX_FILES || totalBytes_ >= MAX_TOTAL_BYTES) {
            if (limitLogged_) return true;
            limitLogged_ = true;
            return log(L"file_snapshot_limit", L"files=" + std::to_wstring(files_) +
                                                   L";bytes=" + std::to_wstring(totalBytes_));
        }
        HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                  nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) {
            return log(L"file_snapshot_missed", L"path=" + path + L";win32=" + std::to_wstring(GetLastError()));
        }
        LARGE_INTEGER size{};
        std::vector<BYTE> data;
        SnapshotRange range;
        bool ok = GetFileSizeEx(file, &size) != 0;
        if (ok) {
            /* A Wine system.reg is several MB and rewritten whole: its head. Another file past the limit is a growing
             * log (an anti-cheat's own): what was appended since its last copy, not the same head again. */
            const bool registryFile = _wcsicmp(std::filesystem::path(path).extension().wstring().c_str(), L".reg") == 0;
            const uint64_t total = static_cast<uint64_t>(size.QuadPart);
            range = registryFile ? SnapshotRange{0, std::min<uint64_t>(total, MAX_REG_FILE_BYTES), L"head"}
                                 : SnapshotRangeOf(total, saved_[path], MAX_FILE_BYTES);
            LARGE_INTEGER at{};
            at.QuadPart = static_cast<int64_t>(range.from);
            data.resize(static_cast<size_t>(range.bytes));
            DWORD read = 0;
            if (range.from != 0) ok = SetFilePointerEx(file, at, nullptr, FILE_BEGIN) != 0;
            if (ok && !data.empty()) ok = ReadFile(file, data.data(), static_cast<DWORD>(data.size()), &read, nullptr) != 0;
            data.resize(read);
            if (ok) saved_[path] = range.from + read;
        }
        CloseHandle(file);
        if (!ok) {
            return log(L"file_snapshot_missed", L"path=" + path + L";win32=" + std::to_wstring(GetLastError()));
        }
        std::error_code directoryError;
        std::filesystem::create_directories(directory_, directoryError);
        wchar_t prefix[16];
        swprintf_s(prefix, L"%05u_", ++files_);
        std::filesystem::path saved = directory_ / (std::wstring(prefix) + std::filesystem::path(path).filename().wstring());
        std::ofstream out(saved, std::ios::binary);
        if (!data.empty()) out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
        const bool written = static_cast<bool>(out);
        out.close();
        totalBytes_ += data.size();
        const std::string hash = Sha256Bytes(data.data(), data.size());
        return log(L"file_snapshot",
                   L"path=" + path + L";bytes=" + std::to_wstring(data.size()) +
                   L";file_bytes=" + std::to_wstring(size.QuadPart) + L";offset=" + std::to_wstring(range.from) +
                   L";mode=" + range.mode +
                   L";sha256=" + std::wstring(hash.begin(), hash.end()) +
                   L";saved=snapshots\\" + saved.filename().wstring() + (written ? L"" : L";save_failed=1"));
    }

    std::filesystem::path directory_;
    std::vector<std::wstring> roots_;
    std::vector<std::pair<std::wstring, std::wstring>> devices_;
    std::unordered_map<std::wstring, uint64_t> pending_;
    std::unordered_map<std::wstring, uint64_t> taken_;
    std::unordered_map<std::wstring, uint64_t> saved_;   /* path -> end of its last copy */
    unsigned files_ = 0;
    uint64_t totalBytes_ = 0;
    bool limitLogged_ = false;
};

static unsigned TrackExisting(DeviceSession& device, const std::vector<std::wstring>& scopeRoots,
                              ProcessScope& scope, const std::wstring& winePrefix = {})
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;
    std::vector<PROCESSENTRY32W> processes;
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            processes.push_back(entry);
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);

    std::unordered_map<DWORD, uint64_t> tracked;
    unsigned count = 0;
    bool changed = true;
    while (changed) {
        changed = false;
        for (const auto& process : processes) {
            if (tracked.count(process.th32ProcessID) != 0) continue;
            if (process.th32ProcessID == GetCurrentProcessId()) continue;
            std::wstring path;
            uint64_t startTime = 0;
            if (!ProcessIdentity(process.th32ProcessID, path, startTime)) continue;
            /* A rescan: already tracked, but a parent for the processes still to check. */
            if (scope.IsTracked(process.th32ProcessID, startTime)) {
                tracked[process.th32ProcessID] = startTime;
                changed = true;
                continue;
            }
            bool inherited = false;
            auto parent = tracked.find(process.th32ParentProcessID);
            if (parent != tracked.end()) {
                std::wstring parentPath;
                uint64_t parentStart = 0;
                inherited = ProcessIdentity(process.th32ParentProcessID, parentPath, parentStart) &&
                            ProcessScope::ValidParentIncarnation(parent->second, parentStart, startTime);
            }
#ifdef _WIN32
            if (!inherited && !IsUnderAnyRoot(scopeRoots, path)) continue;
#else
            /* Under Wine the image is the loader: also an executable mapping under a root or the prefix. */
            if (!inherited && !IsUnderAnyRoot(scopeRoots, path) &&
                !LinuxInScope(process.th32ProcessID, scopeRoots, winePrefix)) continue;
#endif
            ULONG flags = inherited ? MsMonFlagInheritedTrack : MsMonFlagExplicitTrack;
            if (device.Track(process.th32ProcessID, startTime, flags)) {
                tracked[process.th32ProcessID] = startTime;
                scope.AddProcess(process.th32ProcessID, startTime, path);
                count++;
                changed = true;
            }
        }
    }
    return count;
}

/* The executable whose hash and version identify the client; empty when there is none. */
static std::filesystem::path ClientExecutable(const std::wstring& scopeRoot)
{
    std::error_code error;
#ifdef _WIN32
    std::filesystem::path executable = std::filesystem::path(scopeRoot) / L"MapleStory.exe";
    return std::filesystem::exists(executable, error) ? executable : std::filesystem::path();
#else
    /* MapleStory.exe when present (else e.g. CrashReportClient.exe sorts first); otherwise any
       client: the first (by name) executable regular file directly under the scope root. */
    std::filesystem::path maple = std::filesystem::path(scopeRoot) / L"MapleStory.exe";
    if (std::filesystem::is_regular_file(maple, error)) return maple;
    std::vector<std::filesystem::path> found;
    for (const auto& entry : std::filesystem::directory_iterator(scopeRoot, error)) {
        if (entry.is_regular_file(error) && access(entry.path().c_str(), X_OK) == 0) found.push_back(entry.path());
    }
    std::sort(found.begin(), found.end());
    return found.empty() ? std::filesystem::path() : found.front();
#endif
}

static std::wstring DefaultOutputPath()
{
    SYSTEMTIME time{};
    GetLocalTime(&time);
    wchar_t path[128];
    swprintf_s(path, L"msmon-%04u%02u%02u-%02u%02u%02u.jsonl",
               time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond);
    return path;
}

static void Usage()
{
    std::cout << "Usage: msmon-agent [--client DIRECTORY] [--scope-root DIRECTORY] [--output FILE] [--pid PID] "
                 "[--log-dir DIR] [--session-label LABEL] [--test-id ID] [--scenario NAME] [--phase NAME] "
                 "[--iteration N] [--machine-label NAME] [--outcome-override NAME] [--compact] "
                 "[--wait-ms N] [--max-file-mb N] [--queue-records N] [--queue-mb N] "
                 "[--stop-file FILE] [--extra-root DIRECTORY]... [--no-etw] [--no-payloads] [--once]"
#ifndef _WIN32
                 " [--prefix WINEPREFIX] [--no-ebpf] [--no-packets] [--protect-tree] [--repeat-window-ms N]"
                 " [--native-depth N] [--page-faults] [--log-real-input] [--log-environment] [--log-content]"
                 " [--window-probes] [--watch WHERE:LENGTH:ACCESS]..."
#endif
                 "\n"
                 "Without --extra-root, %ProgramData%\\Nexon\\NGS and %ProgramFiles(x86)%\\Nexon\\Nexon Launcher are\n"
                 "added when they exist. Processes kfilter decides for (its protected family) are tracked too.\n"
#ifndef _WIN32
                 "--prefix defaults to the nearest folder above --client that holds system.reg; every process\n"
                 "running with that WINEPREFIX is in scope. --no-ebpf uses fanotify, the proc connector and\n"
                 "/proc polling instead of the kernel (eBPF) sensors. --no-packets writes no pcapng; --no-payloads\n"
                 "also turns off socket byte and packet capture. --protect-tree also refuses bpf() and\n"
                 "perf_event_open to the tracked tree (default: observe only). --repeat-window-ms collapses\n"
                 "repeats of one call per window (default 1000; 0 records every call: gigabytes per minute).\n"
                 "--native-depth keeps native programs the client starts (xdg-open, a browser) tracked with a reduced set of\n"
                 "calls for N execs in a row (default 3; 0 untracks them; the sign-in hand-off winebrowser.exe starts: at\n"
                 "least 8). --page-faults also records the first touch of each page of shared mappings (memfd, SysV\n"
                 "shm, MAP_SHARED files). --log-real-input also logs the\n"
                 "user's own keys that pass wineserver (winex11's keyboard input, keyboard messages; default: left out).\n"
                 "--log-environment also logs every environment variable's value at an exec (process_environment; default:\n"
                 "the names, and the values of Wine's, the loader's and the graphics stack's variables only).\n"
                 "--log-content also logs contents otherwise only named, sized or hashed (privacy and volume: off by\n"
                 "default): AF_UNIX and pipe bytes (X11, D-Bus, PulseAudio, Wine's named pipes; 8 KiB a message logged,\n"
                 "all captured hashed), DRM and socket ioctl argument structs, IRP and async results, clipboard hashes.\n"
                 "Those bytes hold what the user types and copies, whatever --log-real-input says: X11 key events and\n"
                 "selection (clipboard) transfers, an input method's D-Bus calls, a launcher's IPC with a typed password.\n"
                 "--window-probes also probes the window functions (NtUserCallHwndParam, NtUserMessageCall,\n"
                 "NtUserPostMessage, NtUserSetWindowLong(Ptr), NtUserSetWindowPos): only calls on other programs'\n"
                 "windows are recorded, but every call takes a trap (the game calls NtUserCallHwndParam every frame).\n"
                 "--watch logs a tracked process's own accesses to 1, 2, 4 or 8 aligned bytes with a hardware data\n"
                 "breakpoint on each of its threads, counted per thread, instruction and second: WHERE is MODULE+0xOFFSET\n"
                 "(from that module's base, followed when it moves) or 0xADDRESS (in every tracked process), ACCESS w or rw\n"
                 "(r is watched as rw: x86 has no breakpoint on reads alone); at most 4, the debug registers of a thread,\n"
                 "which wineserver also sets for a Windows program's SetThreadContext (docs/LINUX.md \"Watchpoints\").\n"
#endif
                 ;
}

static bool ParseNumber(const wchar_t* text, uint64_t& value)
{
    wchar_t* end = nullptr;
    value = std::wcstoull(text, &end, 10);
    return end != text && end != nullptr && *end == L'\0';
}

int wmain(int argc, wchar_t** argv)
{
#ifdef _WIN32
    std::wstring clientRoot = L"C:\\Nexon\\Library\\maplestorycw";
#else
    std::wstring clientRoot;
#endif
    std::wstring scopeRootArg;
    std::vector<std::wstring> extraRootArgs;
    std::wstring output = DefaultOutputPath();
    std::wstring logDir;
    std::wstring sessionLabel;
    std::wstring testId;
    std::wstring scenario = L"mixed";
    std::wstring phase = L"steady";
    std::wstring machineLabelArg;
    std::wstring outcomeOverride;
    uint64_t iteration = 1;
    bool compact = false;
    bool outputSet = false;
    uint64_t waitMs = 100;
    uint64_t maxFileBytes = 64ull * 1024ull * 1024ull;
    uint64_t queueRecords = MSMON_MAX_QUEUE_RECORDS;
    uint64_t queueBytes = MSMON_DEFAULT_QUEUE_BYTES;
    bool once = false;
    bool enableEtw = true;
    bool capturePayloads = true;
    bool logContent = false;   /* --log-content: AF_UNIX, pipe and ioctl bytes in the log (bpf.cpp) */
    bool logPrivate = false;   /* --log-real-input, --log-environment: the user's keys, every environment value */
    std::filesystem::path stopFile;
    bool stopFileEnabled = false;
    std::vector<DWORD> explicitPids;
#ifndef _WIN32
    bool clientSet = false;
    bool useEbpf = true;
    bool capturePackets = true;
    bool protectTree = false;
    std::wstring prefixArg;
#endif

    for (int index = 1; index < argc; index++) {
        std::wstring argument = argv[index];
        uint64_t value = 0;
        if (argument == L"--help" || argument == L"-h") {
            Usage();
            return 0;
        } else if (argument == L"--once") {
            once = true;
        } else if (argument == L"--no-etw") {
            enableEtw = false;
        } else if (argument == L"--no-payloads") {
            capturePayloads = false;
#ifndef _WIN32
        } else if (argument == L"--no-ebpf") {
            useEbpf = false;
        } else if (argument == L"--no-packets") {
            capturePackets = false;
        } else if (argument == L"--protect-tree") {
            protectTree = true;
        } else if (index + 1 < argc && argument == L"--prefix") {
            prefixArg = argv[++index];
        } else if (index + 1 < argc && argument == L"--repeat-window-ms" && ParseNumber(argv[index + 1], value)) {
            LinuxSessionRepeatWindow(value);
            index++;
        } else if (index + 1 < argc && argument == L"--native-depth" && ParseNumber(argv[index + 1], value)) {
            LinuxSessionNativeDepth(value);
            index++;
        } else if (argument == L"--page-faults") {
            LinuxSessionPageFaults(true);
        } else if (argument == L"--log-real-input") {
            logPrivate = true;
            LinuxSessionRealInput(true);
        } else if (argument == L"--log-environment") {
            logPrivate = true;
            LinuxSessionLogEnvironment(true);
        } else if (argument == L"--log-content") {
            logContent = true;
            LinuxSessionLogContent(true);
        } else if (argument == L"--window-probes") {
            LinuxSessionWindowProbes(true);
        } else if (index + 1 < argc && argument == L"--watch") {
            std::wstring refused;
            if (!LinuxSessionWatch(argv[++index], refused)) {
                std::cerr << WideToUtf8(refused) << "\n";
                return 2;
            }
#endif
        } else if (index + 1 < argc && argument == L"--client") {
            clientRoot = argv[++index];
#ifndef _WIN32
            clientSet = true;
#endif
        } else if (index + 1 < argc && argument == L"--scope-root") {
            scopeRootArg = argv[++index];
        } else if (index + 1 < argc && argument == L"--extra-root") {
            extraRootArgs.push_back(argv[++index]);
        } else if (index + 1 < argc && argument == L"--output") {
            output = argv[++index];
            outputSet = true;
        } else if (index + 1 < argc && (argument == L"--log-dir" || argument == L"--session-dir")) {
            logDir = argv[++index];
        } else if (index + 1 < argc && argument == L"--session-label") {
            sessionLabel = argv[++index];
        } else if (index + 1 < argc && argument == L"--test-id") {
            testId = argv[++index];
        } else if (index + 1 < argc && argument == L"--scenario") {
            scenario = argv[++index];
        } else if (index + 1 < argc && argument == L"--phase") {
            phase = argv[++index];
        } else if (index + 1 < argc && argument == L"--machine-label") {
            machineLabelArg = argv[++index];
        } else if (index + 1 < argc && argument == L"--outcome-override") {
            outcomeOverride = argv[++index];
        } else if (index + 1 < argc && argument == L"--iteration" && ParseNumber(argv[index + 1], value)) {
            iteration = value;
            index++;
        } else if (argument == L"--compact") {
            compact = true;
        } else if (index + 1 < argc && argument == L"--stop-file") {
            stopFile = argv[++index];
            stopFileEnabled = true;
        } else if (index + 1 < argc && argument == L"--wait-ms" && ParseNumber(argv[index + 1], value)) {
            waitMs = value;
            index++;
        } else if (index + 1 < argc && argument == L"--max-file-mb" && ParseNumber(argv[index + 1], value)) {
            maxFileBytes = value * 1024ull * 1024ull;
            index++;
        } else if (index + 1 < argc && argument == L"--queue-records" && ParseNumber(argv[index + 1], value)) {
            queueRecords = value;
            index++;
        } else if (index + 1 < argc && argument == L"--queue-mb" && ParseNumber(argv[index + 1], value)) {
            queueBytes = value * 1024ull * 1024ull;
            index++;
        } else if (index + 1 < argc && argument == L"--pid" && ParseNumber(argv[index + 1], value) && value <= MAXDWORD) {
            explicitPids.push_back(static_cast<DWORD>(value));
            index++;
        } else {
            Usage();
            return 2;
        }
    }

    if (!AllowedLabel(scenario, {L"startup", L"login", L"gameplay", L"cash_shop", L"file_io",
                                 L"registry", L"wmi", L"dns", L"rpc", L"network", L"ipc",
                                 L"idle", L"shutdown", L"mixed", L"other"})) {
        std::cerr << "Invalid --scenario value.\n";
        return 2;
    }
    if (!AllowedLabel(phase, {L"startup", L"steady", L"shutdown"})) {
        std::cerr << "Invalid --phase value.\n";
        return 2;
    }
    if (!outcomeOverride.empty() &&
        !AllowedLabel(outcomeOverride, {L"completed", L"agent_stopped", L"agent_killed",
                                        L"driver_stopped", L"crash", L"timeout", L"unknown"})) {
        std::cerr << "Invalid --outcome-override value.\n";
        return 2;
    }
    if (iteration == 0) iteration = 1;
    SetDecodedFields(!compact);
    std::wstring sessionUuid;
    std::wstring uuidShort;
    uint64_t sessionId = 0;
    if (!GenerateUuid(sessionUuid, uuidShort, sessionId)) {
        std::cerr << "Could not generate a session UUID.\n";
        return 1;
    }
    if (sessionLabel.empty()) sessionLabel = scenario;
    sessionLabel = SanitizeLabel(sessionLabel, L"session");
    machineLabelArg = machineLabelArg.empty() ? MachineLabel() : SanitizeLabel(machineLabelArg, L"unknown");

#ifndef _WIN32
    if (!clientSet) {
        if (!scopeRootArg.empty()) {
            clientRoot = scopeRootArg;
        } else if (!explicitPids.empty()) {
            std::wstring image;
            uint64_t startTime = 0;
            if (!ProcessIdentity(explicitPids.front(), image, startTime) || image.empty()) {
                std::cerr << "Cannot read /proc/" << explicitPids.front() << "/exe; pass --client.\n";
                return 1;
            }
            clientRoot = std::filesystem::path(image).parent_path().wstring();
        } else {
            std::cerr << "Linux needs --client, --scope-root or --pid.\n";
            return 1;
        }
    }
#endif

    clientRoot = FullPath(clientRoot);
    if (clientRoot.empty()) {
        std::cerr << "Could not resolve the client root.\n";
        return 1;
    }

    /*
     * The folder the user names and the folder containing the executable are
     * not always the same.  The installation root is ...\maplestorycw, while
     * the game and its helpers live in ...\maplestorycw\appdata.  Keep the
     * classification root at the named folder, but auto-detect appdata for
     * the process scope.  An explicit --scope-root always wins.
     */
    std::wstring scopeRoot = scopeRootArg.empty() ? clientRoot : FullPath(scopeRootArg);
    if (scopeRoot.empty()) {
        std::cerr << "Could not resolve the scope root.\n";
        return 1;
    }
    std::error_code fsError;
    if (scopeRootArg.empty() &&
        !std::filesystem::exists(std::filesystem::path(scopeRoot) / L"MapleStory.exe", fsError) &&
        std::filesystem::exists(std::filesystem::path(scopeRoot) / L"appdata" / L"MapleStory.exe", fsError)) {
        scopeRoot = (std::filesystem::path(scopeRoot) / L"appdata").wstring();
    }
    const std::filesystem::path clientExe = ClientExecutable(scopeRoot);
    if (clientExe.empty() && explicitPids.empty()) {
#ifdef _WIN32
        std::cerr << "No MapleStory.exe was found under scope root:\n  " << WideToUtf8(scopeRoot)
#else
        std::cerr << "No executable file was found directly under scope root:\n  " << WideToUtf8(scopeRoot)
#endif
                  << "\nUse --scope-root to point at the folder containing the executable, or --pid for an already running process.\n";
        return 1;
    }

    std::wstring scopeNt;
    std::wstring clientNt;
    std::string error;
    if (!DevicePath(scopeRoot, scopeNt, error)) {
        std::cerr << "Scope root: " << error << "\n";
        return 1;
    }
    if (!DevicePath(clientRoot, clientNt, error)) {
        std::cerr << "Client root: " << error << "\n";
        return 1;
    }

    std::wstring winePrefix;
#ifndef _WIN32
    if (!prefixArg.empty()) {
        winePrefix = FullPath(prefixArg);
    } else {
        /* The Wine prefix is the nearest folder above the client that holds system.reg. */
        for (std::filesystem::path folder = clientRoot; !folder.empty() && folder != folder.root_path();
             folder = folder.parent_path()) {
            if (std::filesystem::exists(folder / L"system.reg", fsError)) {
                winePrefix = folder.wstring();
                break;
            }
        }
    }
#endif

    /*
     * The NGS security service runs from %ProgramData%\Nexon\NGS and is
     * started by the service control manager, not by the client, so it is
     * neither under the client scope nor a descendant of a tracked process.
     * The Nexon Launcher family (nexon_launcher, nexon_client, nexon_agent,
     * nexon_runtime) lives outside the client root and starts the client.
     */
    std::vector<std::wstring> extraRoots;
    std::error_code extraRootError;
    if (extraRootArgs.empty()) {
        std::filesystem::path programDataPath;
        wchar_t programData[MAX_PATH];
        DWORD programDataLength = GetEnvironmentVariableW(L"ProgramData", programData, MAX_PATH);
        if (programDataLength != 0 && programDataLength < MAX_PATH) programDataPath = programData;
#ifndef _WIN32
        /* Under Wine, %ProgramData% is the prefix's drive_c/ProgramData. */
        if (!winePrefix.empty()) programDataPath = std::filesystem::path(winePrefix) / L"drive_c" / L"ProgramData";
#endif
        if (!programDataPath.empty()) {
            std::filesystem::path ngs = programDataPath / L"Nexon" / L"NGS";
            if (std::filesystem::is_directory(ngs, extraRootError)) extraRoots.push_back(ngs.wstring());
        }
        std::filesystem::path programFilesPath;
        wchar_t programFiles[MAX_PATH];
        DWORD programFilesLength = GetEnvironmentVariableW(L"ProgramFiles(x86)", programFiles, MAX_PATH);
        if (programFilesLength != 0 && programFilesLength < MAX_PATH) programFilesPath = programFiles;
#ifndef _WIN32
        if (!winePrefix.empty()) programFilesPath = std::filesystem::path(winePrefix) / L"drive_c" / L"Program Files (x86)";
#endif
        if (!programFilesPath.empty()) {
            std::filesystem::path launcher = programFilesPath / L"Nexon" / L"Nexon Launcher";
            if (std::filesystem::is_directory(launcher, extraRootError)) extraRoots.push_back(launcher.wstring());
        }
    } else {
        for (const auto& extraRootArg : extraRootArgs) extraRoots.push_back(FullPath(extraRootArg));
    }
    if (extraRoots.size() > MSMON_EXTRA_ROOTS) {
        std::cerr << "At most " << MSMON_EXTRA_ROOTS << " --extra-root directories are supported.\n";
        return 1;
    }
    std::vector<std::wstring> extraNt;
    for (auto& extraRoot : extraRoots) {
        while (extraRoot.size() > 3 && (extraRoot.back() == L'\\' || extraRoot.back() == L'/')) extraRoot.pop_back();
        std::wstring rootNt;
        if (extraRoot.empty() || !DevicePath(extraRoot, rootNt, error)) {
            std::cerr << "Extra root " << WideToUtf8(extraRoot) << ": " << error << "\n";
            return 1;
        }
        if (rootNt.size() >= MSMON_CLIENT_PATH_CHARS) {
            std::cerr << "Extra root NT path is too long: " << WideToUtf8(extraRoot) << "\n";
            return 1;
        }
        extraNt.push_back(rootNt);
    }
    std::vector<std::wstring> scopeRoots{scopeRoot};
    scopeRoots.insert(scopeRoots.end(), extraRoots.begin(), extraRoots.end());
#ifndef _WIN32
    LinuxSessionUseEbpf(useEbpf);
    LinuxSessionProtectTree(protectTree);
#endif
#ifdef _WIN32
    wchar_t windowsBuffer[32768];
    if (GetWindowsDirectoryW(windowsBuffer, static_cast<UINT>(std::size(windowsBuffer))) == 0) {
        std::cerr << "Could not resolve the Windows directory.\n";
        return 1;
    }
    std::wstring windowsDos = windowsBuffer;
#else
    /* The OS runtime the classifier calls windows_runtime: libraries and programs under /usr. */
    std::wstring windowsDos = L"/usr";
#endif
    std::wstring windowsNt;
    if (!DevicePath(windowsDos, windowsNt, error)) {
        std::cerr << error << "\n";
        return 1;
    }

    std::wstring startedUtc = UtcStamp(Now());
    std::wstring resolvedTestId = testId.empty() ? std::wstring() : SanitizeLabel(testId, L"session");
    wchar_t iterationText[8];
    swprintf_s(iterationText, L"%02llu", static_cast<unsigned long long>(iteration));
    std::filesystem::path sessionDir;
    if (!logDir.empty()) {
        if (outputSet) {
            std::cerr << "Use either --output or --log-dir, not both.\n";
            return 2;
        }
        std::wstring base = FullPath(logDir);
        if (base.empty()) {
            std::cerr << "Could not resolve --log-dir.\n";
            return 1;
        }
        if (resolvedTestId.empty()) {
            resolvedTestId = startedUtc + L"__" + machineLabelArg + L"__" + scenario +
                             L"__iter" + iterationText + L"__" + uuidShort;
        }
        sessionDir = std::filesystem::path(base) / resolvedTestId;
        std::error_code createError;
        std::filesystem::create_directories(sessionDir, createError);
        if (createError) {
            std::cerr << "Could not create the session directory: " << createError.message() << "\n";
            return 1;
        }
        output = (sessionDir / L"events.jsonl").wstring();
    } else if (resolvedTestId.empty()) {
        resolvedTestId = startedUtc + L"__" + machineLabelArg + L"__" + scenario +
                         L"__iter" + iterationText + L"__" + uuidShort;
    }

    SessionLabels labels;
    labels.uuid = sessionUuid;
    labels.uuidShort = uuidShort;
    labels.id = sessionId;
    labels.label = sessionLabel;
    labels.testId = resolvedTestId;
    labels.scenario = scenario;
    labels.phase = phase;
    labels.machine = machineLabelArg;
    labels.machineHash = MachineIdHash();
    labels.iteration = iteration;
    labels.started = startedUtc;

    SessionBinaryInfo binaries;
    std::string buildText;
    std::string buildHash;
    binaries.buildInfoPresent = ReadBuildInfo(buildText, buildHash);
    binaries.buildInfoRaw = buildText;
    binaries.buildInfoHash = buildHash;
    binaries.buildCommit = JsonField(buildText, "commit");
    if (binaries.buildCommit.empty()) binaries.buildCommit = "unknown";
    binaries.agentHash = Sha256File(ExecutablePath());
    binaries.driverHash = Sha256File(DriverFilePath());
    if (!clientExe.empty()) {
        binaries.clientVersion = ClientVersion(clientExe.wstring());
        binaries.clientHash = Sha256File(clientExe.wstring());
    }

    /* Until the sensors report (and if the agent dies first): assume the socket bytes are in the log. */
    bool payloadSecrets = capturePayloads || logContent || logPrivate;
    if (!sessionDir.empty()) {
        WriteTextFile(sessionDir / L"session_meta.json",
                      BuildSessionMeta(labels, binaries, clientRoot, scopeRoot, capturePayloads, payloadSecrets,
                                       enableEtw, queueRecords, queueBytes, L"in_progress", L"",
                                       0, 0, 0, 0, 0, 0, 0));
    }

    MSMON_SESSION_CONFIG config{};
    config.SessionId = sessionId;
    config.QueueRecords = static_cast<ULONG>(queueRecords);
    config.QueueBytes = static_cast<ULONG>(queueBytes);
    config.PayloadMode = capturePayloads ? 1u : 0u;
    if (scopeNt.size() >= MSMON_CLIENT_PATH_CHARS) {
        std::cerr << "The scope NT path is too long for the session configuration.\n";
        return 1;
    }
    wcscpy_s(config.ClientRoot, MSMON_CLIENT_PATH_CHARS, scopeNt.c_str());
    for (size_t rootIndex = 0; rootIndex < extraNt.size(); rootIndex++) {
        wcscpy_s(config.ExtraRoots[rootIndex], MSMON_CLIENT_PATH_CHARS, extraNt[rootIndex].c_str());
    }

#ifndef _WIN32
    /* The client's packets (pcapng) beside the events file: events.pcapng in a bundle. */
    PacketsConfigure(capturePayloads && capturePackets
                         ? std::filesystem::path(output).replace_extension(L".pcapng").wstring()
                         : std::wstring(),
                     maxFileBytes);
#endif
    DeviceSession device;
    if (!device.Open()) {
        std::cerr << "Cannot open " MSMON_USER_DEVICE_PATH ": Win32 error " << GetLastError()
                  << ". Use a properly signed driver in an isolated test VM.\n";
        return 1;
    }
    if (!device.Start(config)) {
        std::cerr << "Could not start the driver session: Win32 error " << GetLastError() << "\n";
        return 1;
    }
    if (!device.RefreshModules()) {
        std::cerr << "Could not refresh kernel module attribution: Win32 error " << GetLastError() << "\n";
        return 1;
    }
    MSMON_COVERAGE startCoverage{};
    bool startCoverageSupported = device.Coverage(startCoverage);

    ProcessScope scope;
    unsigned registered = TrackExisting(device, scopeRoots, scope, winePrefix);
    for (DWORD pid : explicitPids) {
        std::wstring path;
        uint64_t startTime = 0;
        if (ProcessIdentity(pid, path, startTime) && device.Track(pid, startTime, MsMonFlagExplicitTrack)) {
            scope.AddProcess(pid, startTime, path);
            registered++;
        } else {
            std::cerr << "Could not track explicit PID " << pid << ".\n";
        }
    }
    std::cout << "Registered " << registered << " client/helper/descendant processes." << std::endl;   // tests wait for this line in a redirected log
    const unsigned initiallyTracked = registered;
    if (registered == 0) {
        std::cout << "No client process is running yet; waiting for a tracked image to start.\n";
    }

    JsonlWriter writer(output, maxFileBytes);
    if (!writer.Open()) {
        std::cerr << "Cannot open output log.\n";
        return 1;
    }
    OutsideClassifier classifier(clientRoot, clientNt, windowsDos, windowsNt);
    SessionSummary summary;
    summary.SetInitiallyTracked(initiallyTracked);
    EventQueue etwQueue;
    std::unique_ptr<EtwCollector> etw;
    /* The ring keeps decisions from earlier runs; only events from this instant belong here. */
    const uint64_t kfilterSessionStart = Now();
    KFilterReader kfilter(sessionId, kfilterSessionStart);
    KFILTER_STATUS kfilterStart{};
    KFILTER_STATUS kfilterLatest{};
    std::wstring kfilterState;
    std::wstring kfilterDetail;
    uint64_t kfilterDropped = 0;
    bool kfilterActive = false;

    auto writeCoverage = [&](const std::wstring& text, const std::wstring& detail,
                             ULONG attribution = MsMonAttributionUnknown) {
        TelemetryEvent event;
        event.source = "agent";
        event.header.Size = sizeof(event.header);
        event.header.Version = MSMON_PROTOCOL_VERSION;
        event.header.Type = MsMonCoverage;
        event.header.Flags = MsMonFlagObserverRecord;
        event.header.Timestamp = Now();
        event.header.SessionId = sessionId;
        event.header.Attribution = attribution;
        event.text = text;
        event.detail = detail;
        event.outsideClient = false;
        return writer.Write(TelemetryJson(event));
    };
#ifndef _WIN32
    /* Packet capture parts closed so far (packet_capture_part) and, at the end, its totals. */
    auto drainPackets = [&](bool final) {
        for (const auto& note : PacketsTakeNotes(final)) {
            if (!writeCoverage(note.first, note.second)) return false;
        }
        return true;
    };
#endif

    if (!writeCoverage(L"session_start", L"client_root=" + clientRoot + L";scope_root=" + scopeRoot +
                                          L";extra_roots=" + JoinRoots(extraRoots))) return 1;
    {
        std::wstring context = L"schema_version=1;session_uuid=" + sessionUuid +
                               L";session_label=" + sessionLabel +
                               L";test_id=" + resolvedTestId +
                               L";scenario=" + scenario +
                               L";phase=" + phase +
                               L";iteration=" + std::to_wstring(iteration) +
                               L";machine_label=" + machineLabelArg +
                               L";machine_id_hash=" + Utf8ToWide(labels.machineHash) +
                               L";started_utc=" + startedUtc +
                               L";client_version=" + Utf8ToWide(binaries.clientVersion) +
                               L";client_sha256=" + Utf8ToWide(binaries.clientHash) +
                               L";agent_sha256=" + Utf8ToWide(binaries.agentHash) +
                               L";driver_sha256=" + Utf8ToWide(binaries.driverHash) +
                               L";build_commit=" + Utf8ToWide(binaries.buildCommit) +
                               L";build_info_present=" + (binaries.buildInfoPresent ? L"true" : L"false");
        if (!writeCoverage(L"session_context", context)) return 1;
    }
    kfilterActive = kfilter.Open(kfilterStart, kfilterState, kfilterDetail);
    kfilterLatest = kfilterStart;
    if (!writeCoverage(kfilterActive ? L"kfilter_status" : kfilterState, kfilterDetail)) return 1;
    {
        std::wstring callbacks;
        bool firstCallback = true;
        auto appendCallback = [&](const wchar_t* name) {
            if (!firstCallback) callbacks += L',';
            callbacks += name;
            firstCallback = false;
        };
        auto registrationSucceeded = [&](unsigned slot) {
            const uint64_t bit = 1ull << slot;
            return startCoverageSupported &&
                   (startCoverage.RegistrationOk & bit) != 0 &&
                   (startCoverage.RegistrationFailed & bit) == 0;
        };
        bool fileRegistered = false;
        bool registryRegistered = false;
        if (startCoverageSupported) {
            if (registrationSucceeded(MSMON_SENSOR_REG_PROCESS_NOTIFY)) appendCallback(L"process");
            if (registrationSucceeded(MSMON_SENSOR_REG_THREAD_NOTIFY)) appendCallback(L"thread");
            if (registrationSucceeded(MSMON_SENSOR_REG_IMAGE_NOTIFY)) appendCallback(L"image");
            if (registrationSucceeded(MSMON_SENSOR_REG_OBJECT_PROCESS)) appendCallback(L"object_process");
            if (registrationSucceeded(MSMON_SENSOR_REG_OBJECT_THREAD)) appendCallback(L"object_thread");
            if (registrationSucceeded(MSMON_SENSOR_REG_LINUX_FANOTIFY)) appendCallback(L"fanotify");
            if (registrationSucceeded(MSMON_SENSOR_REG_LINUX_PROC_CONNECTOR)) appendCallback(L"proc_connector");
            if (registrationSucceeded(MSMON_SENSOR_REG_LINUX_MAPS_POLL)) appendCallback(L"maps_poll");
            if (registrationSucceeded(MSMON_SENSOR_REG_LINUX_NET_POLL)) appendCallback(L"net_poll");
            static const wchar_t* ebpfNames[] = {L"ebpf_process", L"ebpf_file", L"ebpf_net",
                                                 L"ebpf_ipc", L"ebpf_device", L"ebpf_memory"};
            for (unsigned index = 0; index < std::size(ebpfNames); index++) {
                if (registrationSucceeded(MSMON_SENSOR_REG_LINUX_EBPF_PROCESS + index)) appendCallback(ebpfNames[index]);
            }
            if (registrationSucceeded(MSMON_SENSOR_REG_LINUX_EBPF_WINESERVER)) appendCallback(L"ebpf_wineserver");
            fileRegistered = registrationSucceeded(MSMON_SENSOR_REG_FILTER_REGISTER) &&
                             registrationSucceeded(MSMON_SENSOR_REG_FILTER_START);
            if (fileRegistered) {
                appendCallback(L"file");
                appendCallback(L"file_section");
                appendCallback(L"file_security");
                appendCallback(L"file_ea");
            }
            registryRegistered = registrationSucceeded(MSMON_SENSOR_REG_REGISTRY);
            if (registryRegistered) appendCallback(L"registry");
            static const unsigned wfpSlots[] = {
                MSMON_SENSOR_REG_WFP_0, MSMON_SENSOR_REG_WFP_1,
                MSMON_SENSOR_REG_WFP_2, MSMON_SENSOR_REG_WFP_3,
                MSMON_SENSOR_REG_WFP_4, MSMON_SENSOR_REG_WFP_5
            };
            static const wchar_t* wfpNames[] = {
                L"wfp_connect_v4", L"wfp_connect_v6", L"wfp_accept_v4",
                L"wfp_accept_v6", L"wfp_flow_v4", L"wfp_flow_v6"
            };
            for (size_t index = 0; index < std::size(wfpSlots); index++) {
                if (registrationSucceeded(wfpSlots[index])) appendCallback(wfpNames[index]);
            }
            if (callbacks.empty()) callbacks = L"none";
        } else {
            callbacks = L"unknown";
        }
        const wchar_t* fileState = !startCoverageSupported ? L"unknown" : (fileRegistered ? L"true" : L"false");
        const bool registryNames = registryRegistered || registrationSucceeded(MSMON_SENSOR_REG_LINUX_EBPF_WINESERVER);
        const wchar_t* registryState = !startCoverageSupported ? L"unknown" : (registryNames ? L"true" : L"false");
        std::wstring manifest = L"scope_root=" + scopeRoot +
                                L";extra_roots=" + JoinRoots(extraRoots) +
                                L";inside_root=" + clientRoot +
                                L";driver_callbacks=" + callbacks +
                                L";minifilter_npfs=" + fileState +
                                L";file_section_acquire=" + fileState +
                                L";registry_enum_names=" + registryState +
                                L";memory=false;ui=false;hardware_direct=false";
        if (!startCoverageSupported) manifest += L";driver_registration=unknown";
#ifdef _WIN32
        manifest += L";" + IntegrationCoverageState(enableEtw, kfilterState);
#else
        /* ETW never runs on Linux (etw_unavailable follows). */
        manifest += L";" + IntegrationCoverageState(false, kfilterState);
#endif
        manifest += sessionDir.empty() ? L";file_snapshots=disabled" : L";file_snapshots=client_text_files";
        manifest += L";etw_level=verbose;payload_mode=";
        manifest += capturePayloads ? L"full" : L"metadata";
        manifest += L";blind_spots=per_page_mmap_io,named_pipe_payload,memory_ops,ui_clipboard_input,hardware_direct,brokered_actions,tls_plaintext";
        if (!writeCoverage(L"coverage_manifest", manifest)) return 1;
    }
#ifndef _WIN32
    auto registeredOk = [&](unsigned slot) {
        return startCoverageSupported && (startCoverage.RegistrationOk & (1ull << slot)) != 0;
    };
    const bool ebpfFile = registeredOk(MSMON_SENSOR_REG_LINUX_EBPF_FILE);
    const bool ebpfNet = registeredOk(MSMON_SENSOR_REG_LINUX_EBPF_NET);
    const bool wineserverDecoded = registeredOk(MSMON_SENSOR_REG_LINUX_EBPF_WINESERVER);
    payloadSecrets = (capturePayloads && (ebpfNet || wineserverDecoded)) ||
                     ((logContent || logPrivate) && (ebpfFile || ebpfNet || wineserverDecoded));
    const std::wstring hardware = L"hardware identity is seen as file events on /sys/class/dmi/id/*, /proc/cpuinfo and"
                                  L" /sys/block/*/serial";
    if (!capturePayloads) {
        if (!writeCoverage(L"payload_capture_disabled",
                           L"Metadata-only mode (--no-payloads): no socket bytes, DNS names, packets (pcapng), registry"
                           L" values or volume information are captured")) return 1;
    } else if (!ebpfNet && !wineserverDecoded) {
        if (!writeCoverage(L"payload_unavailable",
                           L"The kernel (eBPF) sensors are not running: socket bytes, DNS names, packets, registry values"
                           L" and volume information are not captured; " + hardware +
                           L"; file contents are not captured")) return 1;
    } else if (!writeCoverage(L"payload_capture_enabled",
                              std::wstring(L"Logs contain secrets: ") +
                                  (ebpfNet ? L"the bytes tracked processes send and receive on INET/INET6/netlink"
                                             L" sockets (network_data payloads on their I/O records, up to 1 MiB per"
                                             L" call; TLS through Wine's schannel is also tls_plaintext payloads on"
                                             L" tls:session= records, other TLS and game-encrypted traffic stays"
                                             L" ciphertext), DNS names"
                                             L" (etw_dns) and their packets (pcapng, see packet_capture_*)"
                                           : L"") +
                                  (ebpfNet && wineserverDecoded ? L"; " : L"") +
                                  (wineserverDecoded ? L"registry values and volume information decoded from wineserver"
                                                       L" requests (the first 8 KiB of each), window texts read and set,"
                                                       L" named-pipe and device reads and writes and RPC stubs, and the"
                                                       L" first 1 KiB of ioctl, overlapped I/O and IRP results (device"
                                                       L" answers such as disk serials; ipc_data payloads)"
                                                     : L"") +
                                  L"; not captured: file contents, AF_UNIX and pipe bytes without --log-content (X11, D-Bus"
                                  L" and PulseAudio requests are named as etw_rpc, the bytes not kept), sendfile/splice/io_uring"
                                  L" I/O, the ICMP echo of the client's IcmpSendEcho pings (Wine sends it from"
                                  L" winedevice.exe, outside the tracked tree), any bytes of native helpers (a browser"
                                  L" the client opens: its starts, connects and endpoints are recorded, not its traffic); " +
                                  hardware)) return 1;
    if (ebpfFile) {
        if (!writeCoverage(L"coverage_limit",
                           std::wstring(L"eBPF records cover the recorded syscalls of tracked processes, 32-bit (ia32)"
                                        L" ones and socketcall/ipc subcalls included (argument values, result, duration,"
                                        L" kernel-resolved paths, 8 user frames, and PE frames on Wine threads); every other"
                                        L" syscall, and the hot wineserver requests, are kernel aggregates: counted per"
                                        L" process, call and key argument and written as one summary each a second"
                                        L" (aggregate=kernel; a request's first call of each key in that second also as a"
                                        L" record, aggregate=sampled); every other wineserver request is a record;"
                                        L" syscall_counts and wineserver_request_counts give each process's calls per number"
                                        L" (recorded=0: numbers out of range only); io_uring and AIO operations, signals"
                                        L" received, a process's own fault signals (self_signal), outside processes' access"
                                        L" checks on the tracked ones (outside_access), calls seccomp or syscall user"
                                        L" dispatch stopped, trapped instructions, capability checks, module requests and"
                                        L" credential changes are kernel_events; not file contents, other work done inside"
                                        L" the kernel, accesses to pages already mapped (first touches of shared mappings"
                                        L" only with --page-faults; a process's own loads and stores only at the addresses"
                                        L" --watch names), vDSO time calls (no syscall), a native helper's file calls but"
                                        L" its opens and renames (its reads, writes, sends and receives are kernel aggregates"
                                        L" per inode, a sampled first call each a second: native_io=sampled), or anything"
                                        L" past its native depth; losses without a ring drop are counted in ebpf_losses; ") +
                               (wineserverDecoded ? L"registry comes from wineserver requests (wineserver_requests); "
                                                  : L"registry is file-level (Wine *.reg files); ") +
                               L"paths over 255 bytes are truncated (truncated_path), details over the record limit too"
                               L" (truncated_detail); pre-start activity and records lost when a ring is"
                               L" full (sequence gaps) are not guaranteed")) return 1;
    } else if (!writeCoverage(L"coverage_limit",
                       L"fanotify file events carry no byte counts, offsets, open flags or status; sockets are polled"
                       L" from /proc/net once a second (shorter-lived sockets are missed, already-open ones are reported"
                       L" by the first poll, timestamps are poll times); executable mappings are polled from"
                       L" /proc/<pid>/maps every two seconds; no thread, handle, registry, ETW, stack or payload sensors;"
                       L" pre-start activity and dropped events are not guaranteed")) return 1;
    for (const auto& note : device.Notes()) {
        if (!writeCoverage(note.first, note.second)) return 1;
    }
    if ((!capturePayloads || !capturePackets) &&
        !writeCoverage(L"packet_capture_disabled", capturePayloads ? L"--no-packets" : L"--no-payloads (metadata-only mode)"))
        return 1;
#else
    if (!writeCoverage(capturePayloads ? L"payload_capture_enabled" : L"payload_capture_disabled",
                       capturePayloads ?
                           L"Exact registry values and volume information will be logged; logs may contain hardware identifiers and registry secrets. Registry values are capped at 64 KiB; WMI result rows, direct adapter-API results, file contents, and network contents remain unavailable" :
                           L"Metadata-only mode; no registry value or volume payload capture")) return 1;
    if (!writeCoverage(L"coverage_limit",
                       L"Handle-less process/window snapshots, per-page mapped I/O, named-pipe/ALPC/COM payloads, brokered existing-browser launches, direct adapter/firmware APIs, protected processes, pre-start activity, and dropped events are not guaranteed")) return 1;
    if (!writeCoverage(L"static_hardware_boundary",
                       L"MachineIdLib.dll imports process/window enumeration, GetVolumeInformationA, and GetAdaptersInfo; static imports do not prove runtime invocation",
                       MsMonAttributionStaticEvidence)) return 1;
    {
        DWORD required = QueryDosDeviceW(nullptr, nullptr, 0);
        unsigned discovered = 0;
        if (required != 0) {
            std::vector<wchar_t> devices(required);
            DWORD length = QueryDosDeviceW(nullptr, devices.data(), required);
            if (length != 0) {
                for (const wchar_t* cursor = devices.data(); *cursor != L'\0'; cursor += std::wcslen(cursor) + 1) {
                    std::wstring name = cursor;
                    if (name.find(L"BlackCat") == std::wstring::npos &&
                        name.find(L"blackcat") == std::wstring::npos &&
                        name.find(L"NGS") == std::wstring::npos &&
                        name.find(L"ngs") == std::wstring::npos) continue;
                    wchar_t targetBuffer[32768];
                    DWORD targetLength = QueryDosDeviceW(name.c_str(), targetBuffer,
                                                         static_cast<DWORD>(std::size(targetBuffer)));
                    std::wstring target = targetLength != 0 ? targetBuffer : L"<unavailable>";
                    discovered++;
                    if (!writeCoverage(L"blackcat_device_discovered", name + L" -> " + target)) return 1;
                }
            }
        }
        if (!writeCoverage(L"blackcat_device_discovery",
                           L"matches=" + std::to_wstring(discovered))) return 1;
    }
#endif
    if (enableEtw) {
        etw = std::make_unique<EtwCollector>(scope, etwQueue, sessionId, capturePayloads, scopeRoots);
        if (!etw->Start(error)) {
            if (!writeCoverage(L"etw_unavailable", std::wstring(error.begin(), error.end()))) return 1;
            etw.reset();
        } else {
            for (const auto& warning : etw->Warnings()) {
                if (!writeCoverage(L"etw_provider_coverage", warning)) return 1;
            }
        }
    } else if (!writeCoverage(L"etw_disabled", L"Started with --no-etw")) {
        return 1;
    }

    SetConsoleCtrlHandler(ConsoleHandler, TRUE);
    std::cout << "Writing " << WideToUtf8(output) << "\n";
    std::vector<BYTE> buffer(MSMON_READ_MAX_BYTES);
    uint64_t previousDriverSequence = 0;
    uint64_t previousEtwSequence = 0;
    uint64_t driverGaps = 0;
    uint64_t etwGaps = 0;
    uint64_t totalEvents = 0;
    std::unordered_map<unsigned long, uint64_t> eventCounts;
    uint64_t nextModuleRefresh = GetTickCount64() + 1000;
    uint64_t nextStatistics = GetTickCount64() + 30000;
    bool moduleRefreshWarning = false;
    int result = 0;

    auto writeGap = [&](const std::string& source, uint64_t after, uint64_t before) {
        std::ostringstream json;
        json << "{\"type\":\"observer_sequence_gap\",\"source\":\"" << source
             << "\",\"after_sequence\":" << after << ",\"before_sequence\":" << before
             << ",\"missing_events\":" << (before - after - 1) << "}";
        return writer.Write(json.str());
    };

    auto writeEvent = [&](TelemetryEvent& event) {
        if (event.source == "etw") {
            if (event.header.Sequence > previousEtwSequence + 1) {
                uint64_t gap = event.header.Sequence - previousEtwSequence - 1;
                etwGaps += gap;
                if (!writeGap("etw", previousEtwSequence, event.header.Sequence)) return false;
            }
            previousEtwSequence = event.header.Sequence;
        }
        if (event.processPath.empty() && event.header.ProcessId != 0) {
            event.processPath = scope.Path(event.header.ProcessId, event.header.ProcessStartTime);
        }
        classifier.Classify(event);
        AccountSessionEvent(summary, event, totalEvents, eventCounts);
        return writer.Write(TelemetryJson(event));
    };

    /* pid -> (start, exit) of tracked processes that exited, for kfilter decisions read after the exit. */
    std::unordered_map<DWORD, std::pair<uint64_t, uint64_t>> exitedLifetimes;
    auto drainKfilter = [&]() {
        if (!kfilterActive) return true;
        std::vector<TelemetryEvent> events;
        std::vector<KFilterFamilyProcess> family;
        std::wstring readError;
        const bool readOk = kfilter.Drain(events, family, readError);
        /* The target set is the union: whatever kfilter guards is monitored too, even outside the
         * roots (launcher helpers, services). Started after the decision means a reused PID. */
        std::unordered_set<DWORD> checked;
        for (const auto& member : family) {
            if (scope.StartTime(member.pid) != 0 || !checked.insert(member.pid).second) continue;
            std::wstring path;
            uint64_t startTime = 0;
            if (!ProcessIdentity(member.pid, path, startTime) || startTime == 0 || startTime > member.timestamp) continue;
#ifdef _WIN32
            if (!device.Track(member.pid, startTime, MsMonFlagExplicitTrack)) continue;
#else
            /* A native program joins as a native helper; one the kernel dropped past --native-depth stays out. */
            if (!device.TrackFamily(member.pid, startTime)) continue;
#endif
            scope.AddProcess(member.pid, startTime, path);
            if (etw) etw->ReplayProcess(member.pid);
            if (!writeCoverage(L"kfilter_family_tracked", L"pid=" + std::to_wstring(member.pid) +
                                                         L";process_start_time=" + std::to_wstring(startTime) +
                                                         L";path=" + path)) return false;
        }
        std::unordered_map<DWORD, uint64_t> running;
        for (auto& event : events) {
            /* Join to msmon's process identity (pid + start time) when that incarnation was running. A
             * decision can be read after its process exited (REPEAT summaries come late) or before the
             * sensor ring's start record reaches scope: then the exited one, or the live one. */
            uint64_t startTime = scope.StartTime(event.header.ProcessId);
            const auto gone = exitedLifetimes.find(event.header.ProcessId);
            if (startTime == 0 && gone != exitedLifetimes.end() && event.header.Timestamp <= gone->second.second) {
                startTime = gone->second.first;
            } else if (startTime == 0 && event.header.ProcessId != 0) {
                auto found = running.find(event.header.ProcessId);
                if (found == running.end()) {
                    std::wstring path;
                    uint64_t live = 0;
                    if (!ProcessIdentity(event.header.ProcessId, path, live)) live = 0;
                    found = running.emplace(event.header.ProcessId, live).first;
                }
                startTime = found->second;
            }
            if (startTime != 0 && startTime <= event.header.Timestamp) event.header.ProcessStartTime = startTime;
            if (!writeEvent(event)) return false;
        }
        if (!readOk) {
            kfilterActive = false;
            kfilterState = L"kfilter_unavailable";
            kfilter.Close();
            return writeCoverage(kfilterState, L"decision read failed; integration disabled;error=" + readError);
        }
        return true;
    };

    auto drainEtw = [&]() {
        std::vector<TelemetryEvent> events;
        for (;;) {
            events.clear();
            size_t count = etwQueue.Drain(events, 8192);
            if (count == 0) break;
            for (auto& event : events) {
                if (!writeEvent(event)) return false;
            }
        }
        return true;
    };

    std::unique_ptr<FileSnapshotter> snapshotter;
    if (!sessionDir.empty()) {
        std::vector<std::wstring> snapshotRoots{clientRoot, scopeRoot};
        for (const wchar_t* variable : {L"LOCALAPPDATA", L"APPDATA"}) {
            wchar_t value[MAX_PATH];
            DWORD length = GetEnvironmentVariableW(variable, value, MAX_PATH);
            if (length != 0 && length < MAX_PATH) snapshotRoots.push_back((std::filesystem::path(value) / L"Nexon").wstring());
        }
        /* The Wine prefix (it holds drive_c, so AppData\Nexon too); its *.reg files are the
         * registry wineserver saves (file-level). */
        if (!winePrefix.empty()) snapshotRoots.push_back(winePrefix);
        snapshotter = std::make_unique<FileSnapshotter>(sessionDir, snapshotRoots);
        if (!writeCoverage(L"file_snapshots", L"roots=" + JoinRoots(snapshotRoots) +
                                                L";extensions=.ini|.log|.txt|.json|.xml|.cfg|.reg;max_bytes=262144"
                                                L";reg_max_bytes=16777216")) return 1;
    }
    auto logSnapshot = [&](const std::wstring& text, const std::wstring& detail) { return writeCoverage(text, detail); };
    bool draining = false;
    bool driverDone = false;
    std::wstring outcome = once ? L"completed" : L"unknown";
    std::unique_ptr<DriverPump> pump;
    if (!once) {
        pump = std::make_unique<DriverPump>(static_cast<DWORD>(waitMs), DRIVER_PUMP_LIMIT_BYTES);
        if (!pump->Start()) {
            std::cerr << "Cannot open a reader handle to " MSMON_USER_DEVICE_PATH ": Win32 error "
                      << GetLastError() << "\n";
            return 1;
        }
    }
    std::deque<std::vector<BYTE>> batches;
    do {
        std::error_code stopError;
        bool stopFileRequested = stopFileEnabled && std::filesystem::exists(stopFile, stopError);
        if (!once && !draining && (gStop.load() || stopFileRequested)) {
            outcome = gStop.load() ? L"agent_stopped" : L"completed";
            if (!device.StopTracking()) {
                std::cerr << "Could not stop driver tracking: Win32 error " << GetLastError() << "\n";
                result = 1;
                break;
            }
            pump->RequestDrain();
            draining = true;
        }
        batches.clear();
        if (pump) {
            pump->Take(batches, static_cast<DWORD>(waitMs));
        } else {
            DWORD bytes = 0;
            if (!device.Read(static_cast<DWORD>(waitMs), buffer, bytes)) {
                std::cerr << "Driver read failed: Win32 error " << GetLastError() << "\n";
                outcome = L"driver_stopped";
                result = 1;
                break;
            }
            if (bytes > buffer.size()) {
                std::cerr << "Driver returned an invalid byte count.\n";
                result = 1;
                break;
            }
            batches.emplace_back(buffer.begin(), buffer.begin() + bytes);
        }
        for (const auto& batch : batches) {
            const DWORD bytes = static_cast<DWORD>(batch.size());
            DWORD offset = 0;
            while (offset < bytes) {
                TelemetryEvent event;
                DWORD consumed = 0;
                if (!DecodeDriverEvent(batch.data() + offset, bytes - offset, event, consumed, error) || consumed == 0) {
                    std::cerr << "Invalid driver event: " << error << "\n";
                    result = 1;
                    break;
                }
                offset += consumed;
                if (event.header.SessionId != sessionId) {
                    std::cerr << "Driver returned an event from another session.\n";
                    result = 1;
                    break;
                }
                if (previousDriverSequence != 0 && event.header.Sequence <= previousDriverSequence) {
                    std::cerr << "Driver sequence is not increasing.\n";
                    result = 1;
                    break;
                }
                if (event.header.Sequence > previousDriverSequence + 1) {
                    uint64_t gap = event.header.Sequence - previousDriverSequence - 1;
                    driverGaps += gap;
                    if (!writeGap("driver", previousDriverSequence, event.header.Sequence)) {
                        result = 1;
                        break;
                    }
                }
                previousDriverSequence = event.header.Sequence;
                /* A creation another driver (kfilter) refused, or a failed exec, is logged with its
                 * status and never becomes a live tracked image. */
                if (event.header.Type == MsMonProcessStart && event.header.Status == 0) {
                    uint64_t start = event.header.ProcessStartTime != 0 ? event.header.ProcessStartTime : event.header.Value0;
                    scope.AddProcess(event.header.ProcessId, start, event.text);
                    if (etw) etw->ReplayProcess(event.header.ProcessId);
                } else if (event.header.Type == MsMonProcessExit) {
                    event.processPath = scope.Path(event.header.ProcessId, event.header.ProcessStartTime);
                    scope.RemoveProcess(event.header.ProcessId, event.header.ProcessStartTime);
                    // shortcut: forgets every exit at 65536 entries (a late decision then has no start time), fine per run.
                    if (exitedLifetimes.size() >= 65536) exitedLifetimes.clear();
                    exitedLifetimes[event.header.ProcessId] = {event.header.ProcessStartTime, event.header.Timestamp};
                } else if (event.header.Type == MsMonImageLoad) {
                    scope.AddImage(event.header.ProcessId, event.header.ProcessStartTime,
                                   event.header.Value0, event.header.Value1, event.text);
                }
                if (snapshotter && event.header.Type == MsMonFileWrite) snapshotter->Note(event.text);
                /* wineserver saves a registry file under a temporary name and renames it into place. */
                if (snapshotter && event.header.Type == MsMonFileSetInformation && event.header.Value0 == 10 &&
                    event.detail.compare(0, 9, L"rename;to") == 0) {
                    snapshotter->Note(event.text);
                }
                if (!event.stackAddresses.empty()) {
                    /* Name the modules inside the process that made the request. */
                    event.modules = scope.ResolveStack(event.stackPid, event.stackAddresses.data(),
                                                       event.stackAddresses.size(), &event.stackUnresolved);
                    if (!event.modules.empty()) event.header.Attribution = MsMonAttributionStackResolved;
                }
                if (!writeEvent(event)) {
                    std::cerr << "Could not write the event log.\n";
                    result = 1;
                    break;
                }
            }
            if (result != 0) break;
        }
        if (result != 0) break;
        if (pump) {
            /* Report a reader failure only after every batch it queued has been written. */
            DWORD pumpError = 0;
            bool invalidCount = false;
            if (pump->Failed(pumpError, invalidCount) && pump->Done()) {
                if (invalidCount) {
                    std::cerr << "Driver returned an invalid byte count.\n";
                } else {
                    std::cerr << "Driver read failed: Win32 error " << pumpError << "\n";
                    outcome = L"driver_stopped";
                }
                result = 1;
                break;
            }
            driverDone = pump->Done();
        }
        if (etw) etw->ExpirePending(GetTickCount64());
        if (snapshotter && !snapshotter->Process(false, logSnapshot)) {
            result = 1;
            break;
        }
#ifndef _WIN32
        if (!drainPackets(false)) {
            result = 1;
            break;
        }
#endif
        if (result != 0 || !drainKfilter() || !drainEtw()) {
            result = 1;
            break;
        }
        if (!draining && GetTickCount64() >= nextModuleRefresh) {
            if (!device.RefreshModules() && !moduleRefreshWarning) {
                if (!writeCoverage(L"module_refresh_failed",
                                   L"BlackCat image mapping could not be refreshed; direct stack attribution may be incomplete")) {
                    result = 1;
                    break;
                }
                moduleRefreshWarning = true;
            }
            nextModuleRefresh = GetTickCount64() + 1000;
#ifndef _WIN32
            /* Processes the kernel inheritance cannot see (started outside the tracked tree
             * but in the prefix, or mapping the client) join within a second. */
            TrackExisting(device, scopeRoots, scope, winePrefix);
#endif
        }
        if (!draining && kfilterActive && GetTickCount64() >= nextStatistics) {
            /* The decision ring drops when it fills: report each new loss as it happens. */
            KFILTER_STATUS current{};
            std::wstring statusError;
            if (kfilter.Status(current, statusError) &&
                (current.DroppedEvents != kfilterLatest.DroppedEvents || current.SessionTag != kfilterLatest.SessionTag)) {
                if (!writeCoverage(L"kfilter_status", KFilterStatusDetail(current, &kfilterStart))) {
                    result = 1;
                    break;
                }
                kfilterLatest = current;
            }
        }
        if (!draining && GetTickCount64() >= nextStatistics) {
            /*
             * Periodic statistics keep drop and queue pressure visible even if
             * the session ends abruptly (bugcheck, kill, power loss), where the
             * final summary is never written.
             */
            MSMON_STATISTICS statistics{};
            if (device.Statistics(statistics)) {
                TelemetryEvent event;
                event.source = "agent";
                event.header.Size = sizeof(event.header);
                event.header.Version = MSMON_PROTOCOL_VERSION;
                event.header.Type = MsMonCoverage;
                event.header.Flags = MsMonFlagObserverRecord;
                event.header.Timestamp = Now();
                event.header.SessionId = sessionId;
                event.header.Value0 = statistics.DroppedEvents;
                event.header.Value1 = statistics.QueuedEvents;
                event.text = L"driver_statistics";
                event.detail = L"queued=" + std::to_wstring(statistics.QueuedEvents) +
                               L";queued_bytes=" + std::to_wstring(statistics.QueuedBytes) +
                               L";dropped=" + std::to_wstring(statistics.DroppedEvents) +
                               L";tracked=" + std::to_wstring(statistics.TrackedProcesses) +
                               L";queue_record_limit=" + std::to_wstring(statistics.QueueRecordLimit) +
                               L";queue_byte_limit=" + std::to_wstring(statistics.QueueByteLimit) +
                               L";agent_buffered_bytes=" + std::to_wstring(pump ? pump->BufferedBytes() : 0) +
                               L";agent_peak_buffered_bytes=" + std::to_wstring(pump ? pump->PeakBytes() : 0);
                event.outsideClient = false;
                if (!writeEvent(event)) {
                    result = 1;
                    break;
                }
            }
            nextStatistics = GetTickCount64() + 30000;
        }
    } while (!once && !(draining && driverDone));

    if (pump) {
        pump->Stop();
        if (!writeCoverage(L"driver_pump",
                           L"peak_buffered_bytes=" + std::to_wstring(pump->PeakBytes()) +
                           L";limit_bytes=" + std::to_wstring(pump->LimitBytes()) +
                           L";backpressure_waits=" + std::to_wstring(pump->BackpressureWaits()))) {
            result = 1;
        }
    }

    if (!drainKfilter()) result = 1;
    if (kfilterActive) {
        std::wstring statusError;
        if (kfilter.Status(kfilterLatest, statusError)) {
            kfilterDropped = kfilterLatest.DroppedEvents >= kfilterStart.DroppedEvents ?
                kfilterLatest.DroppedEvents - kfilterStart.DroppedEvents : 0;
            if (!writeCoverage(L"kfilter_status", KFilterStatusDetail(kfilterLatest, &kfilterStart))) result = 1;
        } else {
            kfilterState = L"kfilter_unavailable";
            if (!writeCoverage(kfilterState, L"final status failed;error=" + statusError)) result = 1;
        }
    }
    kfilter.Close();

    if (etw != nullptr) {
        /*
         * The session is ending: any event still waiting for a process-start
         * record is now permanently unattributed.  Emit those coverage
         * records before stopping the session so they are not lost.
         */
        etw->ExpirePending(~0ull);
        etw->Stop();
        /* Stop joins the ETW worker; expire anything it queued in the race. */
        etw->ExpirePending(~0ull);
    }
    if (!drainEtw()) result = 1;
    if (snapshotter && !snapshotter->Process(true, logSnapshot)) result = 1;
#ifndef _WIN32
    if (!drainPackets(true)) result = 1;
#endif
    if (etw != nullptr) {
        if (!writeCoverage(L"etw_accounting",
                           L"unattributed=" + std::to_wstring(etw->UnattributedCount()) +
                           L";pending_overflow=" + std::to_wstring(etw->PendingOverflow()) +
                           L";pending_after=" + std::to_wstring(etw->PendingCount()) +
                           L";lost_events=" + std::to_wstring(etw->LostEvents()) +
                           L";parse_failures=" + std::to_wstring(etw->ParseFailures()) +
                           L";queue_drops=" + std::to_wstring(etwQueue.Dropped()))) {
            result = 1;
        }
    }
    MSMON_COVERAGE coverage{};
    bool coverageSupported = device.Coverage(coverage);
    const MSMON_COVERAGE* startCoveragePtr =
        (startCoverageSupported && coverageSupported) ? &startCoverage : nullptr;
    if (!coverageSupported) {
        (VOID)writeCoverage(L"coverage_unsupported",
                            L"The driver does not expose MSMON_IOCTL_COVERAGE; sensor counters are unavailable");
    }
    uint64_t coverageAttempted = 0;
    uint64_t coverageDropped = 0;
    uint64_t coverageEntered = 0;
    uint64_t coverageLogged = 0;
    for (unsigned index = 0; index < MSMON_EVENT_SLOTS; index++) {
        coverageAttempted += coverage.EventAttempted[index] -
                             (startCoveragePtr ? startCoveragePtr->EventAttempted[index] : 0);
        coverageDropped += coverage.EventDropped[index] -
                           (startCoveragePtr ? startCoveragePtr->EventDropped[index] : 0);
    }
    for (unsigned index = 0; index < MSMON_SENSOR_SLOTS; index++) {
        coverageEntered += coverage.SensorEntered[index] -
                           (startCoveragePtr ? startCoveragePtr->SensorEntered[index] : 0);
        coverageLogged += coverage.SensorLogged[index] -
                          (startCoveragePtr ? startCoveragePtr->SensorLogged[index] : 0);
    }
    if (!sessionDir.empty()) {
        WriteTextFile(sessionDir / L"coverage.json",
                      BuildCoverageJson(coverage, startCoveragePtr, coverageSupported, etw.get(),
                                        etwQueue.Dropped(), writer.PartCount(), writer.TotalBytes(),
                                        sessionUuid, kfilterState, kfilterDropped, eventCounts));
    }
    {
        std::wstring detail = L"schema_version=1;driver_supported=" +
                              std::wstring(coverageSupported ? L"true" : L"false") +
                              L";event_attempted=" + std::to_wstring(coverageAttempted) +
                              L";event_dropped=" + std::to_wstring(coverageDropped) +
                              L";sensor_entered=" + std::to_wstring(coverageEntered) +
                              L";sensor_logged=" + std::to_wstring(coverageLogged) +
                              L";registration_failed=" + std::to_wstring(coverage.RegistrationFailed) +
                              L";blackcat_matches=" + std::to_wstring(coverage.BlackCatMatches) +
                              L";etw_unattributed=" + std::to_wstring(etw ? etw->UnattributedCount() : 0) +
                              L";etw_queue_drops=" + std::to_wstring(etwQueue.Dropped());
        TelemetryEvent event;
        event.source = "agent";
        event.header.Size = sizeof(event.header);
        event.header.Version = MSMON_PROTOCOL_VERSION;
        event.header.Type = MsMonCoverageUsage;
        event.header.Flags = MsMonFlagObserverRecord;
        event.header.Timestamp = Now();
        event.header.SessionId = sessionId;
        event.header.Value0 = coverageDropped;
        event.header.Value1 = coverageAttempted;
        event.header.Attribution = MsMonAttributionUnknown;
        event.text = L"coverage_usage";
        event.detail = detail;
        event.outsideClient = false;
        if (!writeEvent(event)) result = 1;
    }
    MSMON_STATISTICS statistics{};
    if (!device.Statistics(statistics)) {
        std::cerr << "Could not read final driver statistics.\n";
        result = 1;
    } else {
        std::string summaryJson = summary.Json(statistics, etwQueue.Dropped(), driverGaps, etwGaps);
        if (!writer.Write(summaryJson)) result = 1;
        if (!sessionDir.empty()) {
            WriteTextFile(sessionDir / L"summary.json", summaryJson);
        }
        std::cout << "Events written: " << totalEvents << "; driver gaps: " << driverGaps
                  << "; ETW gaps: " << etwGaps << "; driver drops: " << statistics.DroppedEvents
                  << "; ETW queue drops: " << etwQueue.Dropped() << "\n";
    }
    if (outcome == L"unknown" && once) outcome = L"completed";
    if (!outcomeOverride.empty()) outcome = outcomeOverride;
    if (!sessionDir.empty()) {
        WriteTextFile(sessionDir / L"session_meta.json",
                      BuildSessionMeta(labels, binaries, clientRoot, scopeRoot, capturePayloads, payloadSecrets,
                                       enableEtw, queueRecords, queueBytes, outcome, UtcStamp(Now()),
                                       totalEvents, statistics.DroppedEvents, driverGaps, etwGaps,
                                       writer.RecordCount(), writer.TotalBytes(), writer.PartCount()));
        std::cout << "Session bundle: " << WideToUtf8(sessionDir.wstring()) << "\n";
    }
    if (!writer.Close()) result = 1;
    SetConsoleCtrlHandler(ConsoleHandler, FALSE);
    return result;
}

#ifndef _WIN32
int main(int argc, char** argv)
{
    std::vector<std::wstring> arguments;
    for (int index = 0; index < argc; index++) arguments.push_back(LinuxWide(argv[index]));
    std::vector<wchar_t*> pointers;
    for (auto& argument : arguments) pointers.push_back(argument.data());
    pointers.push_back(nullptr);
    return wmain(argc, pointers.data());
}
#endif
