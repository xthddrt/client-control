#pragma once

#ifdef _WIN32
#include <windows.h>
#else
#include "linux/win32.h"
#endif
#include <atomic>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>
#include "../include/msmon_protocol.h"

struct TelemetryEvent {
    MSMON_EVENT_HEADER header{};
    std::wstring text;
    std::wstring detail;
    std::wstring component;
    std::wstring processPath;
    std::vector<std::wstring> modules;
    std::vector<BYTE> payload;
    /* Raw ETW stack, retained until the event is emitted so late image loads
     * can still be resolved.  Never written to JSON. */
    DWORD stackPid = 0;
    std::vector<uint64_t> stackAddresses;
    /* User-mode frames that fell in no known module (unbacked code, or a module loaded before tracking). */
    size_t stackUnresolved = 0;
    std::string source = "driver";
    bool outsideClient = true;
};

struct ModuleRange {
    uint64_t base = 0;
    uint64_t size = 0;
    std::wstring path;
};

struct ProcessInfo {
    uint64_t startTime = 0;
    std::wstring path;
    std::vector<ModuleRange> modules;
};

struct EarlyImage {
    uint64_t created = 0;
    std::vector<ModuleRange> modules;
};

class ProcessScope {
public:
    static bool ValidParentIncarnation(uint64_t trackedStart, uint64_t currentStart, uint64_t childStart)
    {
        return trackedStart == currentStart && currentStart != 0 && childStart != 0 && currentStart <= childStart;
    }
    void AddProcess(DWORD pid, uint64_t startTime, const std::wstring& path);
    void RemoveProcess(DWORD pid, uint64_t startTime);
    void AddImage(DWORD pid, uint64_t startTime, uint64_t base, uint64_t size, const std::wstring& path);
    bool IsTracked(DWORD pid, uint64_t expectedStartTime = 0) const;
    uint64_t StartTime(DWORD pid) const;
    std::wstring Path(DWORD pid) const;
    std::wstring Path(DWORD pid, uint64_t expectedStartTime) const;
    std::vector<std::wstring> ResolveStack(DWORD pid, const uint64_t* addresses, size_t count,
                                           size_t* unresolved = nullptr) const;

private:
    mutable std::mutex mutex_;
    std::unordered_map<DWORD, ProcessInfo> processes_;
    /* Image loads the driver reported before the process-start record. */
    std::unordered_map<DWORD, EarlyImage> earlyImages_;
};

class EventQueue {
public:
    explicit EventQueue(size_t capacity = 32768) : capacity_(capacity) {}
    bool Push(TelemetryEvent&& event);
    size_t Drain(std::vector<TelemetryEvent>& output, size_t maximum);
    uint64_t Dropped() const { return dropped_.load(); }

private:
    size_t capacity_;
    mutable std::mutex mutex_;
    std::deque<TelemetryEvent> events_;
    std::atomic<uint64_t> dropped_{0};
};

class JsonlWriter {
public:
    JsonlWriter(std::filesystem::path basePath, uint64_t maximumBytes);
    bool Open();
    bool Write(const std::string& json);
    bool Close();
    uint64_t RecordCount() const { return recordIndex_; }
    uint64_t TotalBytes() const { return totalBytes_; }
    unsigned PartCount() const { return part_ + 1; }
    const std::string& ChainHead() const { return chain_; }

private:
    std::filesystem::path basePath_;
    uint64_t maximumBytes_;
    uint64_t bytes_ = 0;
    uint64_t totalBytes_ = 0;
    uint64_t recordIndex_ = 0;
    unsigned part_ = 0;
    std::ofstream stream_;
    std::string chain_;
};

/* The bytes a text-file snapshot copies from a file of Size bytes whose previous copy ended at Saved (0: none): within
 * Limit the whole file; past it (a growing log) what was appended since that copy, or the newest Limit bytes when
 * more was appended or the file is new to the snapshotter (mode tail: bytes before From were not copied). */
struct SnapshotRange {
    uint64_t from = 0;
    uint64_t bytes = 0;
    const wchar_t* mode = L"whole";
};
inline SnapshotRange SnapshotRangeOf(uint64_t size, uint64_t saved, uint64_t limit)
{
    if (size <= limit) return {0, size, L"whole"};
    if (saved > 0 && saved < size && size - saved <= limit) return {saved, size - saved, L"delta"};
    return {size - limit, limit, L"tail"};
}

std::string WideToUtf8(const std::wstring& value);
std::string JsonEscape(const std::string& value);
std::string Timestamp(uint64_t value);
std::string EventTypeName(unsigned long type);
std::string CategoryName(unsigned long category);
std::string AttributionName(unsigned long attribution);
std::string Sha256(const std::string& input);
std::string Sha256Bytes(const void* data, size_t size);
std::string Sha256File(const std::wstring& path);
std::string StatusName(long status);
std::string StatusHex(long status);
std::string FlagsNames(unsigned long flags);
std::string DesiredAccessHex(unsigned long access);
void SetDecodedFields(bool enabled);
std::string TelemetryJson(const TelemetryEvent& event);
bool DecodeDriverEvent(const BYTE* data, DWORD available, TelemetryEvent& event,
                       DWORD& consumed, std::string& error);
