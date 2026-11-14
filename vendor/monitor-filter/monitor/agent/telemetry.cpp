#include "telemetry.h"
#ifdef _WIN32
#include <bcrypt.h>
#endif
#include <algorithm>
#include <cstring>
#include <iomanip>
#include <set>
#include <sstream>

static bool gDecodedFields = true;

void SetDecodedFields(bool enabled)
{
    gDecodedFields = enabled;
}

static void InsertModule(std::vector<ModuleRange>& modules, uint64_t base, uint64_t size, const std::wstring& path)
{
    auto duplicate = std::find_if(modules.begin(), modules.end(), [&](const ModuleRange& module) {
        return module.base == base;
    });
    if (duplicate != modules.end()) modules.erase(duplicate);
    modules.push_back({base, size, path});
    std::sort(modules.begin(), modules.end(), [](const ModuleRange& left, const ModuleRange& right) {
        return left.base < right.base;
    });
}

void ProcessScope::AddProcess(DWORD pid, uint64_t startTime, const std::wstring& path)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto& process = processes_[pid];
    /* A new incarnation owns nothing of the old one, including its image: an
     * empty process-start text must not inherit the dead process's path. */
    if (process.startTime != startTime) {
        process.modules.clear();
        process.path.clear();
    }
    process.startTime = startTime;
    if (!path.empty()) process.path = path;
    auto early = earlyImages_.find(pid);
    if (early != earlyImages_.end()) {
        if (early->second.created == startTime) {
            for (const auto& module : early->second.modules) {
                InsertModule(process.modules, module.base, module.size, module.path);
            }
        }
        earlyImages_.erase(early);
    }
}

void ProcessScope::RemoveProcess(DWORD pid, uint64_t startTime)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto found = processes_.find(pid);
    if (found != processes_.end() &&
        (startTime == 0 || found->second.startTime == 0 || found->second.startTime == startTime)) {
        processes_.erase(found);
    }
    auto early = earlyImages_.find(pid);
    if (early != earlyImages_.end() && (startTime == 0 || early->second.created == startTime)) {
        earlyImages_.erase(early);
    }
}

void ProcessScope::AddImage(DWORD pid, uint64_t startTime, uint64_t base, uint64_t size, const std::wstring& path)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (base == 0 || size == 0) return;
    auto found = processes_.find(pid);
    if (found == processes_.end() || found->second.startTime != startTime) {
        if (earlyImages_.size() >= 256 && earlyImages_.find(pid) == earlyImages_.end()) {
            earlyImages_.erase(earlyImages_.begin());
        }
        auto& early = earlyImages_[pid];
        if (early.created != startTime) {
            early.created = startTime;
            early.modules.clear();
        }
        InsertModule(early.modules, base, size, path);
        return;
    }
    InsertModule(found->second.modules, base, size, path);
}

bool ProcessScope::IsTracked(DWORD pid, uint64_t expectedStartTime) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto found = processes_.find(pid);
    return found != processes_.end() &&
           (expectedStartTime == 0 || found->second.startTime == expectedStartTime);
}

uint64_t ProcessScope::StartTime(DWORD pid) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto found = processes_.find(pid);
    return found == processes_.end() ? 0 : found->second.startTime;
}

std::wstring ProcessScope::Path(DWORD pid) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto found = processes_.find(pid);
    return found == processes_.end() ? std::wstring() : found->second.path;
}

std::wstring ProcessScope::Path(DWORD pid, uint64_t expectedStartTime) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto found = processes_.find(pid);
    return expectedStartTime != 0 && found != processes_.end() &&
           found->second.startTime == expectedStartTime ? found->second.path : std::wstring();
}

std::vector<std::wstring> ProcessScope::ResolveStack(DWORD pid, const uint64_t* addresses, size_t count,
                                                     size_t* unresolved) const
{
    static const uint64_t USER_ADDRESS_LIMIT = 0x0000800000000000ull;
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::wstring> result;
    if (unresolved != nullptr) *unresolved = 0;
    auto found = processes_.find(pid);
    if (found == processes_.end() || addresses == nullptr) return result;
    std::set<std::wstring> seen;
    for (size_t index = 0; index < count; index++) {
        uint64_t address = addresses[index];
        bool matched = false;
        for (const auto& module : found->second.modules) {
            if (address >= module.base && address - module.base < module.size) {
                matched = true;
                if (result.size() < 8 && seen.insert(module.path).second) result.push_back(module.path);
                break;
            }
        }
        if (!matched && unresolved != nullptr && address != 0 && address < USER_ADDRESS_LIMIT) (*unresolved)++;
    }
    return result;
}

bool EventQueue::Push(TelemetryEvent&& event)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (events_.size() >= capacity_) {
        dropped_.fetch_add(1);
        return false;
    }
    events_.push_back(std::move(event));
    return true;
}

size_t EventQueue::Drain(std::vector<TelemetryEvent>& output, size_t maximum)
{
    std::lock_guard<std::mutex> lock(mutex_);
    size_t count = 0;
    while (count < maximum && !events_.empty()) {
        output.push_back(std::move(events_.front()));
        events_.pop_front();
        count++;
    }
    return count;
}

static std::string WideToUtf8(const wchar_t* value, size_t length)
{
    if (value == nullptr || length == 0) return {};
    int size = WideCharToMultiByte(CP_UTF8, 0, value, static_cast<int>(length),
                                   nullptr, 0, nullptr, nullptr);
    if (size <= 0) return {};
    std::string result(static_cast<size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value, static_cast<int>(length),
                        result.data(), size, nullptr, nullptr);
    return result;
}

std::string WideToUtf8(const std::wstring& value)
{
    return WideToUtf8(value.data(), value.size());
}

std::string JsonEscape(const std::string& value)
{
    std::ostringstream output;
    for (unsigned char c : value) {
        switch (c) {
        case '"': output << "\\\""; break;
        case '\\': output << "\\\\"; break;
        case '\b': output << "\\b"; break;
        case '\f': output << "\\f"; break;
        case '\n': output << "\\n"; break;
        case '\r': output << "\\r"; break;
        case '\t': output << "\\t"; break;
        default:
            if (c < 0x20) {
                output << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                       << static_cast<unsigned>(c) << std::dec << std::setfill(' ');
            } else {
                output << static_cast<char>(c);
            }
        }
    }
    return output.str();
}

std::string EventTypeName(unsigned long type)
{
    switch (type) {
    case MsMonProcessStart: return "process_start";
    case MsMonProcessExit: return "process_exit";
    case MsMonThreadStart: return "thread_start";
    case MsMonThreadExit: return "thread_exit";
    case MsMonImageLoad: return "image_load";
    case MsMonProcessHandle: return "process_handle";
    case MsMonThreadHandle: return "thread_handle";
    case MsMonFileCreate: return "file_create";
    case MsMonFileRead: return "file_read";
    case MsMonFileWrite: return "file_write";
    case MsMonFileSetInformation: return "file_set_information";
    case MsMonFileDirectoryControl: return "file_directory_control";
    case MsMonFileCleanup: return "file_cleanup";
    case MsMonFileDeviceControl: return "file_device_control";
    case MsMonFileSystemControl: return "file_system_control";
    case MsMonFileQueryVolumeInformation: return "file_query_volume_information";
    case MsMonFileQueryInformation: return "file_query_information";
    case MsMonFileSection: return "file_section";
    case MsMonFileClose: return "file_close";
    case MsMonFileFlush: return "file_flush";
    case MsMonFileQuerySecurity: return "file_query_security";
    case MsMonFileSetSecurity: return "file_set_security";
    case MsMonFileQueryEa: return "file_query_ea";
    case MsMonFileSetEa: return "file_set_ea";
    case MsMonRegistryOpen: return "registry_open";
    case MsMonRegistryCreate: return "registry_create";
    case MsMonRegistrySetValue: return "registry_set_value";
    case MsMonRegistryDelete: return "registry_delete";
    case MsMonRegistryRename: return "registry_rename";
    case MsMonRegistryQuery: return "registry_query";
    case MsMonRegistryEnumerate: return "registry_enumerate";
    case MsMonNetworkConnect: return "network_connect";
    case MsMonNetworkAccept: return "network_accept";
    case MsMonNetworkFlowEstablished: return "network_flow_established";
    case MsMonNetworkFlowClose: return "network_flow_close";
    case MsMonEtwWmi: return "etw_wmi";
    case MsMonEtwDns: return "etw_dns";
    case MsMonEtwRpc: return "etw_rpc";
    case MsMonEtwUnattributed: return "etw_unattributed";
    case MsMonEtwTcp: return "etw_tcp";
    case MsMonEtwCodeIntegrity: return "etw_code_integrity";
    case MsMonCoverage: return "coverage";
    case MsMonCoverageUsage: return "coverage_usage";
    case MsMonKfilterDecision: return "kfilter_decision";
    default: return "unknown";
    }
}

std::string CategoryName(unsigned long category)
{
    switch (category) {
    case MsMonCategoryClientData: return "client_data";
    case MsMonCategoryWindowsRuntime: return "windows_runtime";
    case MsMonCategoryExternalProcess: return "external_process";
    case MsMonCategoryBrowserInteraction: return "browser_interaction";
    case MsMonCategoryHardwareIdentity: return "hardware_identity";
    case MsMonCategoryUserData: return "user_data";
    case MsMonCategoryRegistry: return "registry";
    case MsMonCategoryNetwork: return "network";
    case MsMonCategoryIpc: return "ipc";
    default: return "unknown";
    }
}

std::string AttributionName(unsigned long attribution)
{
    switch (attribution) {
    case MsMonAttributionProcessOnly: return "process_only";
    case MsMonAttributionStackResolved: return "stack_resolved";
    case MsMonAttributionServiceCorrelated: return "service_correlated";
    case MsMonAttributionStaticEvidence: return "static_evidence";
    default: return "unknown";
    }
}

std::string Timestamp(uint64_t value)
{
    FILETIME fileTime{};
    SYSTEMTIME systemTime{};
    fileTime.dwLowDateTime = static_cast<DWORD>(value & 0xffffffff);
    fileTime.dwHighDateTime = static_cast<DWORD>(value >> 32);
    if (!FileTimeToSystemTime(&fileTime, &systemTime)) return {};
    char buffer[32];
    snprintf(buffer, sizeof(buffer), "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
             systemTime.wYear, systemTime.wMonth, systemTime.wDay,
             systemTime.wHour, systemTime.wMinute, systemTime.wSecond, systemTime.wMilliseconds);
    return buffer;
}

#ifdef _WIN32
static std::string HexDigest(const unsigned char* digest, size_t size)
{
    static const char hex[] = "0123456789abcdef";
    std::string result(size * 2, '0');
    for (size_t index = 0; index < size; index++) {
        result[index * 2] = hex[digest[index] >> 4];
        result[index * 2 + 1] = hex[digest[index] & 0xf];
    }
    return result;
}

/*
 * The log writer hashes every record into the chain.  Opening and closing an
 * algorithm provider per record dominated the writer's cost during bursts, so
 * use the shared SHA-256 pseudo-handle and the one-shot BCryptHash.
 */
std::string Sha256Bytes(const void* data, size_t size)
{
    unsigned char digest[32];
    if (BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0,
                   reinterpret_cast<PUCHAR>(const_cast<void*>(data)), static_cast<ULONG>(size),
                   digest, sizeof(digest)) != 0) {
        return {};
    }
    return HexDigest(digest, sizeof(digest));
}

#endif

std::string Sha256(const std::string& input)
{
    return Sha256Bytes(input.data(), input.size());
}

#ifdef _WIN32

std::string Sha256File(const std::wstring& path)
{
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return {};
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objectSize = 0;
    DWORD resultSize = 0;
    std::vector<unsigned char> object;
    unsigned char digest[32];
    std::vector<unsigned char> buffer(1u << 20);
    std::string result;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0 &&
        BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectSize),
                          sizeof(objectSize), &resultSize, 0) == 0) {
        object.resize(objectSize);
        if (BCryptCreateHash(algorithm, &hash, object.data(), objectSize, nullptr, 0, 0) == 0) {
            bool ok = true;
            for (;;) {
                DWORD read = 0;
                if (!ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr)) {
                    ok = false;
                    break;
                }
                if (read == 0) break;
                if (BCryptHashData(hash, buffer.data(), read, 0) != 0) {
                    ok = false;
                    break;
                }
            }
            if (ok && BCryptFinishHash(hash, digest, sizeof(digest), 0) == 0) {
                result = HexDigest(digest, sizeof(digest));
            }
            BCryptDestroyHash(hash);
        }
    }
    if (algorithm != nullptr) BCryptCloseAlgorithmProvider(algorithm, 0);
    CloseHandle(file);
    return result;
}
#endif

std::string StatusName(long status)
{
    struct Entry { unsigned long code; const char* name; };
    static const Entry entries[] = {
        {0x00000000, "STATUS_SUCCESS"},
        {0x00000103, "STATUS_PENDING"},
        {0x80000005, "STATUS_BUFFER_OVERFLOW"},
        {0x80000006, "STATUS_NO_MORE_FILES"},
        {0xC0000023, "STATUS_BUFFER_TOO_SMALL"},
        {0x8000001A, "STATUS_NO_MORE_ENTRIES"},
        {0xC000000F, "STATUS_NO_SUCH_FILE"},
        {0xC0000022, "STATUS_ACCESS_DENIED"},
        {0xC0000033, "STATUS_OBJECT_NAME_INVALID"},
        {0xC0000034, "STATUS_OBJECT_NAME_NOT_FOUND"},
        {0xC0000035, "STATUS_OBJECT_NAME_COLLISION"},
        {0xC0000056, "STATUS_DELETE_PENDING"},
        {0xC00000B5, "STATUS_IO_TIMEOUT"},
        {0xC000020C, "STATUS_CONNECTION_DISCONNECTED"},
        {0xC000020D, "STATUS_CONNECTION_RESET"},
        {0xC0000236, "STATUS_CONNECTION_REFUSED"},
        {0xC0000237, "STATUS_GRACEFUL_DISCONNECT"},
        {0xC0000241, "STATUS_CONNECTION_ABORTED"},
        {0xC00000BA, "STATUS_FILE_IS_A_DIRECTORY"},
        {0xC0000101, "STATUS_DIRECTORY_NOT_EMPTY"},
        {0xC0000225, "STATUS_NOT_FOUND"},
        {0xC00000CC, "STATUS_BAD_NETWORK_NAME"},
    };
    for (const auto& entry : entries) {
        if (entry.code == static_cast<uint32_t>(status)) return entry.name;
    }
#ifndef _WIN32
    /* Linux sensors and kfilterd report positive errno values. */
    if (status > 0 && status < 4096) {
        const char* name = strerrorname_np(static_cast<int>(status));
        if (name != nullptr) return name;
    }
#endif
    return {};
}

std::string StatusHex(long status)
{
    char buffer[16];
    snprintf(buffer, sizeof(buffer), "0x%08X", static_cast<uint32_t>(status));
    return buffer;
}

std::string FlagsNames(unsigned long flags)
{
    struct Entry { unsigned long bit; const char* name; };
    static const Entry entries[] = {
        {MsMonFlagExplicitTrack, "explicit_track"},
        {MsMonFlagInheritedTrack, "inherited_track"},
        {MsMonFlagTruncatedPath, "truncated_path"},
        {MsMonFlagMissingPath, "missing_path"},
        {MsMonFlagServiceCorrelated, "service_correlated"},
        {MsMonFlagObserverRecord, "observer_record"},
        {MsMonFlagPayloadPresent, "payload_present"},
        {MsMonFlagPayloadUnavailable, "payload_unavailable"},
        {MsMonFlagPayloadFinalChunk, "payload_final_chunk"},
        {MsMonFlagPayloadInput, "payload_input"},
        {MsMonFlagPayloadPartial, "payload_partial"},
        {MsMonFlagTruncatedDetail, "truncated_detail"},
    };
    std::string output = "[";
    bool first = true;
    for (const auto& entry : entries) {
        if ((flags & entry.bit) == 0) continue;
        if (!first) output += ",";
        first = false;
        output += "\"";
        output += entry.name;
        output += "\"";
    }
    output += "]";
    return output;
}

std::string DesiredAccessHex(unsigned long access)
{
    char buffer[16];
    snprintf(buffer, sizeof(buffer), "0x%08X", static_cast<uint32_t>(access));
    return buffer;
}

JsonlWriter::JsonlWriter(std::filesystem::path basePath, uint64_t maximumBytes)
    : basePath_(std::move(basePath)), maximumBytes_(maximumBytes), chain_(64, '0') {}

bool JsonlWriter::Open()
{
    stream_.open(basePath_, std::ios::binary | std::ios::trunc);
    bytes_ = 0;
    return static_cast<bool>(stream_);
}

bool JsonlWriter::Write(const std::string& json)
{
    if (json.empty() || json.back() != '}') return false;
    if (maximumBytes_ != 0 && bytes_ != 0 && bytes_ >= maximumBytes_) {
        if (!Close()) return false;
        std::filesystem::path rotated = basePath_;
        rotated += L"." + std::to_wstring(++part_);
        stream_.open(rotated, std::ios::binary | std::ios::trunc);
        if (!stream_) return false;
        bytes_ = 0;
    }
    std::string indexed = json.substr(0, json.size() - 1) +
                          ",\"record_index\":" + std::to_string(++recordIndex_) + "}";
    chain_ = Sha256(chain_ + indexed);
    if (chain_.empty()) return false;
    std::string line = indexed.substr(0, indexed.size() - 1) + ",\"chain\":\"" + chain_ + "\"}\n";
    stream_.write(line.data(), static_cast<std::streamsize>(line.size()));
    bytes_ += line.size();
    totalBytes_ += line.size();
    return static_cast<bool>(stream_);
}

bool JsonlWriter::Close()
{
    if (!stream_.is_open()) return true;
    stream_.flush();
    bool result = static_cast<bool>(stream_);
    stream_.close();
    return result;
}

static std::string Base64(const std::vector<BYTE>& data)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string output;
    output.reserve((data.size() + 2) / 3 * 4);
    for (size_t index = 0; index < data.size(); index += 3) {
        uint32_t value = static_cast<uint32_t>(data[index]) << 16;
        if (index + 1 < data.size()) value |= static_cast<uint32_t>(data[index + 1]) << 8;
        if (index + 2 < data.size()) value |= data[index + 2];
        output.push_back(alphabet[(value >> 18) & 63]);
        output.push_back(alphabet[(value >> 12) & 63]);
        output.push_back(index + 1 < data.size() ? alphabet[(value >> 6) & 63] : '=');
        output.push_back(index + 2 < data.size() ? alphabet[value & 63] : '=');
    }
    return output;
}

static const char* PayloadKindName(ULONG kind)
{
    switch (kind) {
    case MsMonPayloadRegistryValue: return "registry_value";
    case MsMonPayloadVolumeInformation: return "volume_information";
    case MsMonPayloadNetworkData: return "network_data";
    case MsMonPayloadIpcData: return "ipc_data";
    case MsMonPayloadTlsPlaintext: return "tls_plaintext";
    default: return "unknown";
    }
}

static std::wstring DecodeUtf16(const BYTE* data, size_t bytes)
{
    if ((bytes & 1) != 0) return {};
    std::wstring output;
    output.reserve(bytes / 2);
    for (size_t offset = 0; offset < bytes; offset += 2) {
        uint16_t c;
        std::memcpy(&c, data + offset, sizeof(c));
        output.push_back(static_cast<wchar_t>(c));
    }
    while (!output.empty() && output.back() == L'\0') output.pop_back();
    return output;
}

static void AppendDecodedValue(std::ostringstream& json, const TelemetryEvent& event)
{
    const auto& header = event.header;
    if (header.PayloadChunkCount != 1 || header.PayloadTotalBytes != event.payload.size()) return;
    if (header.PayloadKind == MsMonPayloadRegistryValue) {
        ULONG type = static_cast<ULONG>(header.Value1);
        if (type == REG_SZ || type == REG_EXPAND_SZ || type == REG_LINK) {
            json << ",\"decoded_value\":\"" << JsonEscape(WideToUtf8(DecodeUtf16(
                event.payload.data(), event.payload.size()))) << "\"";
        } else if (type == REG_MULTI_SZ) {
            json << ",\"decoded_value\":[";
            size_t offset = 0;
            bool first = true;
            while (offset + 1 < event.payload.size()) {
                size_t end = offset;
                while (end + 1 < event.payload.size()) {
                    uint16_t c;
                    std::memcpy(&c, event.payload.data() + end, sizeof(c));
                    if (c == 0) break;
                    end += 2;
                }
                if (end > offset) {
                    if (!first) json << ',';
                    first = false;
                    json << '\"' << JsonEscape(WideToUtf8(DecodeUtf16(
                        event.payload.data() + offset, end - offset))) << '\"';
                }
                if (end + 1 >= event.payload.size()) break;
                offset = end + 2;
            }
            json << "]";
        } else if (type == REG_DWORD && event.payload.size() == sizeof(uint32_t)) {
            uint32_t value;
            std::memcpy(&value, event.payload.data(), sizeof(value));
            json << ",\"decoded_value\":" << value;
        } else if (type == REG_QWORD && event.payload.size() == sizeof(uint64_t)) {
            uint64_t value;
            std::memcpy(&value, event.payload.data(), sizeof(value));
            json << ",\"decoded_value\":" << value;
        }
    } else if (header.PayloadKind == MsMonPayloadVolumeInformation && header.Value0 == 1u &&
               event.payload.size() >= 18) {
        uint64_t created;
        uint32_t serial;
        uint32_t labelBytes;
        std::memcpy(&created, event.payload.data(), sizeof(created));
        std::memcpy(&serial, event.payload.data() + 8, sizeof(serial));
        std::memcpy(&labelBytes, event.payload.data() + 12, sizeof(labelBytes));
        if (labelBytes <= event.payload.size() - 18 && (labelBytes & 1) == 0) {
            char serialHex[9];
            snprintf(serialHex, sizeof(serialHex), "%08X", serial);
            json << ",\"decoded_value\":{\"volume_serial_number\":" << serial
                 << ",\"volume_serial_hex\":\"" << serialHex
                 << "\",\"volume_creation_time\":\"" << Timestamp(created)
                 << "\",\"volume_label\":\"" << JsonEscape(WideToUtf8(DecodeUtf16(
                        event.payload.data() + 18, labelBytes))) << "\"}";
        }
    }
}

std::string TelemetryJson(const TelemetryEvent& event)
{
    const auto& header = event.header;
    const std::string statusName = StatusName(header.Status);
    const std::string statusText = statusName.empty() ? StatusHex(header.Status) : statusName;
    std::ostringstream json;
    json << "{\"protocol\":" << header.Version
         << ",\"schema_version\":1"
         << ",\"source\":\"" << JsonEscape(event.source)
         << "\",\"sequence\":" << header.Sequence
         << ",\"timestamp\":\"" << Timestamp(header.Timestamp)
         << "\",\"session_id\":" << header.SessionId
         << ",\"type\":\"" << EventTypeName(header.Type)
         << "\",\"type_id\":" << header.Type
         << ",\"process_id\":" << header.ProcessId
         << ",\"process_start_time\":" << header.ProcessStartTime
         << ",\"process_path\":\"" << JsonEscape(WideToUtf8(event.processPath)) << "\""
         << ",\"parent_process_id\":" << header.ParentProcessId
         << ",\"thread_id\":" << header.ThreadId
         << ",\"target_process_id\":" << header.TargetProcessId
         << ",\"target_process_start_time\":" << header.TargetProcessStartTime
         << ",\"flags\":" << header.Flags;
    if (gDecodedFields) json << ",\"flags_names\":" << FlagsNames(header.Flags);
    json << ",\"status\":" << static_cast<int32_t>(header.Status)
         << ",\"status_name\":\"" << JsonEscape(statusText) << "\""
         << ",\"status_hex\":\"" << StatusHex(header.Status) << "\""
         << ",\"desired_access\":" << header.DesiredAccess;
    if (gDecodedFields) json << ",\"desired_access_hex\":\"" << DesiredAccessHex(header.DesiredAccess) << "\"";
    json << ",\"category\":\"" << CategoryName(header.Category)
         << "\",\"outside_client\":" << (event.outsideClient ? "true" : "false")
         << ",\"attribution\":\"" << AttributionName(header.Attribution)
         << "\",\"value0\":" << header.Value0
         << ",\"value1\":" << header.Value1
         << ",\"operation_id\":" << header.OperationId
         << ",\"text\":\"" << JsonEscape(WideToUtf8(event.text))
         << "\",\"detail\":\"" << JsonEscape(WideToUtf8(event.detail))
         << "\",\"component\":\"" << JsonEscape(WideToUtf8(event.component)) << "\"";
    if ((header.Flags & MsMonFlagPayloadPresent) != 0) {
        json << ",\"payload\":{\"kind\":\"" << PayloadKindName(header.PayloadKind)
             << "\",\"encoding\":\"base64\",\"data\":\"" << Base64(event.payload)
             << "\",\"operation_id\":" << header.OperationId
             << ",\"total_bytes\":" << header.PayloadTotalBytes
             << ",\"byte_offset\":" << header.PayloadByteOffset
             << ",\"chunk_index\":" << header.PayloadChunkIndex
             << ",\"chunk_count\":" << header.PayloadChunkCount
             << ",\"final_chunk\":" << ((header.Flags & MsMonFlagPayloadFinalChunk) != 0 ? "true" : "false")
             << "}";
        AppendDecodedValue(json, event);
    }
    if ((header.Flags & MsMonFlagPayloadUnavailable) != 0) json << ",\"payload_unavailable\":true";
    json << ",\"modules\":[";
    for (size_t index = 0; index < event.modules.size(); index++) {
        if (index != 0) json << ',';
        json << '\"' << JsonEscape(WideToUtf8(event.modules[index])) << '\"';
    }
    json << "]";
    if (!event.stackAddresses.empty()) {
        json << ",\"stack_frames\":" << event.stackAddresses.size()
             << ",\"stack_unresolved\":" << event.stackUnresolved;
    }
    json << "}";
    return json.str();
}

bool DecodeDriverEvent(const BYTE* data, DWORD available, TelemetryEvent& event,
                       DWORD& consumed, std::string& error)
{
    consumed = 0;
    if (data == nullptr || available < sizeof(MSMON_EVENT_HEADER)) {
        error = "partial event header";
        return false;
    }
    std::memcpy(&event.header, data, sizeof(event.header));
    const auto& header = event.header;
    if (header.Version != MSMON_PROTOCOL_VERSION) {
        error = "protocol version mismatch";
        return false;
    }
    if (header.Size < sizeof(header) || header.Size > MSMON_MAX_EVENT_RECORD_BYTES || header.Size > available) {
        error = "invalid or partial event record size";
        return false;
    }
    auto validString = [&](unsigned short offset, unsigned short bytes) {
        if (offset == 0 && bytes == 0) return true;
        return offset >= sizeof(header) && (bytes % sizeof(wchar_t)) == 0 &&
               offset <= header.Size && bytes <= header.Size - offset;
    };
    if (!validString(header.TextOffset, header.TextBytes) ||
        !validString(header.DetailOffset, header.DetailBytes) ||
        !validString(header.ComponentOffset, header.ComponentBytes)) {
        error = "invalid event string bounds";
        return false;
    }
    if (header.StackFrames != 0) {
        const size_t stackBytes = static_cast<size_t>(header.StackFrames) * sizeof(uint64_t);
        if (header.StackFrames > MSMON_MAX_STACK_FRAMES || header.StackOffset < sizeof(header) ||
            header.StackOffset > header.Size || stackBytes > header.Size - header.StackOffset) {
            error = "invalid event stack bounds";
            return false;
        }
        event.stackAddresses.resize(header.StackFrames);
        std::memcpy(event.stackAddresses.data(), data + header.StackOffset, stackBytes);
        event.stackPid = header.ProcessId;
    }
    if ((header.Flags & MsMonFlagPayloadPresent) != 0) {
        if ((header.Flags & MsMonFlagPayloadUnavailable) != 0 || header.OperationId == 0 ||
            (header.PayloadKind != MsMonPayloadRegistryValue && header.PayloadKind != MsMonPayloadVolumeInformation &&
             header.PayloadKind != MsMonPayloadNetworkData && header.PayloadKind != MsMonPayloadIpcData &&
             header.PayloadKind != MsMonPayloadTlsPlaintext) ||
            header.PayloadChunkCount == 0 || header.PayloadChunkIndex >= header.PayloadChunkCount ||
            header.PayloadBytes > MSMON_PAYLOAD_CHUNK_BYTES ||
            header.PayloadByteOffset > header.PayloadTotalBytes ||
            header.PayloadBytes > header.PayloadTotalBytes - header.PayloadByteOffset ||
            header.PayloadByteOffset % MSMON_PAYLOAD_CHUNK_BYTES != 0 ||
            header.PayloadChunkIndex != header.PayloadByteOffset / MSMON_PAYLOAD_CHUNK_BYTES) {
            error = "invalid payload metadata";
            return false;
        }
        uint64_t expectedChunks = header.PayloadTotalBytes == 0 ? 1 :
            (header.PayloadTotalBytes + MSMON_PAYLOAD_CHUNK_BYTES - 1) / MSMON_PAYLOAD_CHUNK_BYTES;
        if (expectedChunks != header.PayloadChunkCount ||
            ((header.PayloadChunkIndex + 1 == header.PayloadChunkCount) !=
             ((header.Flags & MsMonFlagPayloadFinalChunk) != 0))) {
            error = "inconsistent payload chunk metadata";
            return false;
        }
        if (header.PayloadBytes != 0) {
            if (header.PayloadOffset < sizeof(header) || header.PayloadOffset > header.Size ||
                header.PayloadBytes > header.Size - header.PayloadOffset) {
                error = "invalid payload bounds";
                return false;
            }
            event.payload.assign(data + header.PayloadOffset,
                                 data + header.PayloadOffset + header.PayloadBytes);
        }
    } else if (header.PayloadBytes != 0) {
        error = "payload bytes without payload flag";
        return false;
    }
    if (header.TextBytes != 0) {
        const wchar_t* text = reinterpret_cast<const wchar_t*>(data + header.TextOffset);
        event.text.assign(text, text + header.TextBytes / sizeof(wchar_t));
    }
    if (header.DetailBytes != 0) {
        const wchar_t* detail = reinterpret_cast<const wchar_t*>(data + header.DetailOffset);
        event.detail.assign(detail, detail + header.DetailBytes / sizeof(wchar_t));
    }
    if (header.ComponentBytes != 0) {
        const wchar_t* component = reinterpret_cast<const wchar_t*>(data + header.ComponentOffset);
        event.component.assign(component, component + header.ComponentBytes / sizeof(wchar_t));
    }
    event.source = "driver";
    consumed = header.Size;
    return true;
}
