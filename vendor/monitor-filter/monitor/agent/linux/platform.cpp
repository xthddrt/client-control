#include "../telemetry.h"
#include <algorithm>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <sstream>
#include <vector>

void GetSystemTimeAsFileTime(FILETIME* value)
{
    timespec now{};
    clock_gettime(CLOCK_REALTIME, &now);
    uint64_t ticks = MSMON_UNIX_EPOCH_AS_FILETIME + static_cast<uint64_t>(now.tv_sec) * 10000000ull +
                     static_cast<uint64_t>(now.tv_nsec) / 100u;
    value->dwLowDateTime = static_cast<DWORD>(ticks & 0xffffffffu);
    value->dwHighDateTime = static_cast<DWORD>(ticks >> 32);
}

static void FillSystemTime(const tm& parts, unsigned milliseconds, SYSTEMTIME* time)
{
    time->wYear = static_cast<WORD>(parts.tm_year + 1900);
    time->wMonth = static_cast<WORD>(parts.tm_mon + 1);
    time->wDayOfWeek = static_cast<WORD>(parts.tm_wday);
    time->wDay = static_cast<WORD>(parts.tm_mday);
    time->wHour = static_cast<WORD>(parts.tm_hour);
    time->wMinute = static_cast<WORD>(parts.tm_min);
    time->wSecond = static_cast<WORD>(parts.tm_sec);
    time->wMilliseconds = static_cast<WORD>(milliseconds);
}

BOOL FileTimeToSystemTime(const FILETIME* value, SYSTEMTIME* time)
{
    uint64_t ticks = (static_cast<uint64_t>(value->dwHighDateTime) << 32) | value->dwLowDateTime;
    if (ticks < MSMON_UNIX_EPOCH_AS_FILETIME) return FALSE;
    ticks -= MSMON_UNIX_EPOCH_AS_FILETIME;
    time_t seconds = static_cast<time_t>(ticks / 10000000ull);
    tm parts{};
    if (gmtime_r(&seconds, &parts) == nullptr) return FALSE;
    FillSystemTime(parts, static_cast<unsigned>((ticks % 10000000ull) / 10000ull), time);
    return TRUE;
}

void GetLocalTime(SYSTEMTIME* time)
{
    timespec now{};
    clock_gettime(CLOCK_REALTIME, &now);
    tm parts{};
    localtime_r(&now.tv_sec, &parts);
    FillSystemTime(parts, static_cast<unsigned>(now.tv_nsec / 1000000), time);
}

uint64_t GetTickCount64()
{
    timespec now{};
    clock_gettime(CLOCK_MONOTONIC, &now);
    return static_cast<uint64_t>(now.tv_sec) * 1000ull + static_cast<uint64_t>(now.tv_nsec) / 1000000ull;
}

/* Invalid UTF-8 (Linux paths are arbitrary bytes) decodes to U+FFFD per bad byte. */
std::wstring LinuxWide(const std::string& value)
{
    std::wstring output;
    output.reserve(value.size());
    for (size_t index = 0; index < value.size();) {
        const unsigned char lead = static_cast<unsigned char>(value[index]);
        size_t length = lead < 0x80 ? 1 : (lead >> 5) == 0x6 ? 2 : (lead >> 4) == 0xe ? 3 : (lead >> 3) == 0x1e ? 4 : 0;
        uint32_t code = length == 1 ? lead : length == 2 ? (lead & 0x1f) : length == 3 ? (lead & 0x0f) : (lead & 0x07);
        bool valid = length != 0 && index + length <= value.size();
        for (size_t next = 1; valid && next < length; next++) {
            const unsigned char c = static_cast<unsigned char>(value[index + next]);
            valid = (c & 0xc0) == 0x80;
            code = (code << 6) | (c & 0x3f);
        }
        static const uint32_t minimum[] = {0, 0, 0x80, 0x800, 0x10000};
        if (valid && (code < minimum[length] || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff))) valid = false;
        output.push_back(valid ? static_cast<wchar_t>(code) : L'\xfffd');
        index += valid ? length : 1;
    }
    return output;
}

std::string LinuxNarrow(const std::wstring& value)
{
    std::string output;
    output.reserve(value.size());
    for (wchar_t wide : value) {
        uint32_t code = static_cast<uint32_t>(wide);
        if (code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) code = 0xfffd;
        if (code < 0x80) {
            output.push_back(static_cast<char>(code));
        } else if (code < 0x800) {
            output.push_back(static_cast<char>(0xc0 | (code >> 6)));
            output.push_back(static_cast<char>(0x80 | (code & 0x3f)));
        } else if (code < 0x10000) {
            output.push_back(static_cast<char>(0xe0 | (code >> 12)));
            output.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3f)));
            output.push_back(static_cast<char>(0x80 | (code & 0x3f)));
        } else {
            output.push_back(static_cast<char>(0xf0 | (code >> 18)));
            output.push_back(static_cast<char>(0x80 | ((code >> 12) & 0x3f)));
            output.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3f)));
            output.push_back(static_cast<char>(0x80 | (code & 0x3f)));
        }
    }
    return output;
}

int MultiByteToWideChar(UINT, DWORD, const char* input, int inputLength, wchar_t* output, int outputLength)
{
    if (input == nullptr || inputLength < 0) return 0;
    std::wstring wide = LinuxWide(std::string(input, static_cast<size_t>(inputLength)));
    if (outputLength == 0) return static_cast<int>(wide.size());
    if (outputLength < static_cast<int>(wide.size())) return 0;
    wmemcpy(output, wide.data(), wide.size());
    return static_cast<int>(wide.size());
}

int WideCharToMultiByte(UINT, DWORD, const wchar_t* input, int inputLength, char* output, int outputLength,
                        const char*, BOOL*)
{
    if (input == nullptr || inputLength < 0) return 0;
    std::string narrow = LinuxNarrow(std::wstring(input, static_cast<size_t>(inputLength)));
    if (outputLength == 0) return static_cast<int>(narrow.size());
    if (outputLength < static_cast<int>(narrow.size())) return 0;
    std::memcpy(output, narrow.data(), narrow.size());
    return static_cast<int>(narrow.size());
}

static DWORD CopyOut(const std::wstring& value, wchar_t* buffer, DWORD size)
{
    if (value.size() + 1 > size) return static_cast<DWORD>(value.size() + 1);
    wmemcpy(buffer, value.c_str(), value.size() + 1);
    return static_cast<DWORD>(value.size());
}

DWORD GetEnvironmentVariableW(const wchar_t* name, wchar_t* buffer, DWORD size)
{
    const char* value = getenv(LinuxNarrow(name).c_str());
    return value == nullptr ? 0 : CopyOut(LinuxWide(value), buffer, size);
}

BOOL GetComputerNameW(wchar_t* buffer, DWORD* size)
{
    char name[256]{};
    if (gethostname(name, sizeof(name) - 1) != 0) return FALSE;
    DWORD written = CopyOut(LinuxWide(name), buffer, *size);
    if (written >= *size) return FALSE;
    *size = written;
    return TRUE;
}

DWORD GetModuleFileNameW(HANDLE, wchar_t* buffer, DWORD size)
{
    char path[4096];
    ssize_t length = readlink("/proc/self/exe", path, sizeof(path));
    if (length <= 0 || length >= static_cast<ssize_t>(sizeof(path))) return 0;
    std::wstring wide = LinuxWide(std::string(path, static_cast<size_t>(length)));
    DWORD written = CopyOut(wide, buffer, size);
    return written >= size ? size : written;
}

static PHANDLER_ROUTINE gConsoleHandler = nullptr;

static void SignalHandler(int signal)
{
    if (gConsoleHandler != nullptr) gConsoleHandler(signal == SIGINT ? CTRL_C_EVENT : CTRL_CLOSE_EVENT);
}

BOOL SetConsoleCtrlHandler(PHANDLER_ROUTINE handler, BOOL add)
{
    gConsoleHandler = add ? handler : nullptr;
    struct sigaction action{};
    action.sa_handler = add ? SignalHandler : SIG_DFL;
    action.sa_flags = SA_RESTART;
    sigemptyset(&action.sa_mask);
    for (int signal : {SIGINT, SIGTERM, SIGHUP}) sigaction(signal, &action, nullptr);
    return TRUE;
}

long BCryptGenRandom(void*, BYTE* buffer, ULONG size, ULONG)
{
    size_t done = 0;
    while (done < size) {
        ssize_t got = getrandom(buffer + done, size - done, 0);
        if (got < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        done += static_cast<size_t>(got);
    }
    return 0;
}

/* Every shim HANDLE is one of these, so CloseHandle can free any of them. */
struct ShimHandle {
    virtual ~ShimHandle() = default;
};

struct FileHandle : ShimHandle {
    int fd = -1;
    ~FileHandle() override { if (fd >= 0) close(fd); }
};

struct SnapshotHandle : ShimHandle {
    std::vector<PROCESSENTRY32W> entries;
    size_t next = 0;
};

HANDLE CreateFileW(const wchar_t* path, DWORD, DWORD, void*, DWORD, DWORD, HANDLE)
{
    /* O_NONBLOCK: a FIFO a tracked process names *.log must not hang the snapshot copy. */
    int fd = open(LinuxNarrow(path).c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return INVALID_HANDLE_VALUE;
    auto* handle = new FileHandle;
    handle->fd = fd;
    return handle;
}

BOOL ReadFile(HANDLE file, void* buffer, DWORD size, DWORD* read, void*)
{
    auto* handle = dynamic_cast<FileHandle*>(static_cast<ShimHandle*>(file));
    if (handle == nullptr) return FALSE;
    ssize_t got;
    do {
        got = ::read(handle->fd, buffer, size);
    } while (got < 0 && errno == EINTR);
    if (got < 0) return FALSE;
    *read = static_cast<DWORD>(got);
    return TRUE;
}

BOOL GetFileSizeEx(HANDLE file, LARGE_INTEGER* size)
{
    auto* handle = dynamic_cast<FileHandle*>(static_cast<ShimHandle*>(file));
    struct stat info{};
    if (handle == nullptr || fstat(handle->fd, &info) != 0) return FALSE;
    size->QuadPart = info.st_size;
    return TRUE;
}

BOOL SetFilePointerEx(HANDLE file, LARGE_INTEGER distance, LARGE_INTEGER* position, DWORD method)
{
    auto* handle = dynamic_cast<FileHandle*>(static_cast<ShimHandle*>(file));
    const int whence = method == FILE_BEGIN ? SEEK_SET : method == FILE_END ? SEEK_END : SEEK_CUR;
    const off_t at = handle == nullptr ? -1 : lseek(handle->fd, distance.QuadPart, whence);
    if (at < 0) return FALSE;
    if (position != nullptr) position->QuadPart = at;
    return TRUE;
}

BOOL CloseHandle(HANDLE handle)
{
    if (handle == nullptr || handle == INVALID_HANDLE_VALUE) return FALSE;
    delete static_cast<ShimHandle*>(handle);
    return TRUE;
}

HANDLE CreateToolhelp32Snapshot(DWORD, DWORD)
{
    DIR* directory = opendir("/proc");
    if (directory == nullptr) return INVALID_HANDLE_VALUE;
    auto* snapshot = new SnapshotHandle;
    while (dirent* entry = readdir(directory)) {
        char* end = nullptr;
        unsigned long pid = strtoul(entry->d_name, &end, 10);
        if (end == entry->d_name || *end != '\0' || pid == 0 || pid > MAXDWORD) continue;
        DWORD parent = 0;
        if (LinuxProcessStart(static_cast<DWORD>(pid), &parent) == 0) continue;
        snapshot->entries.push_back({sizeof(PROCESSENTRY32W), static_cast<DWORD>(pid), parent});
    }
    closedir(directory);
    return snapshot;
}

static BOOL NextProcess(HANDLE snapshot, PROCESSENTRY32W* entry)
{
    auto* handle = dynamic_cast<SnapshotHandle*>(static_cast<ShimHandle*>(snapshot));
    if (handle == nullptr || handle->next >= handle->entries.size()) return FALSE;
    *entry = handle->entries[handle->next++];
    return TRUE;
}

BOOL Process32FirstW(HANDLE snapshot, PROCESSENTRY32W* entry)
{
    auto* handle = dynamic_cast<SnapshotHandle*>(static_cast<ShimHandle*>(snapshot));
    if (handle == nullptr) return FALSE;
    handle->next = 0;
    return NextProcess(snapshot, entry);
}

BOOL Process32NextW(HANDLE snapshot, PROCESSENTRY32W* entry)
{
    return NextProcess(snapshot, entry);
}

/* Boot time is read once: /proc/stat's btime can shift by a second as the clock is adjusted,
 * which would make one process appear as two incarnations. */
uint64_t LinuxBootFileTime()
{
    static const uint64_t boot = [] {
        std::ifstream stat("/proc/stat");
        std::string key;
        uint64_t seconds = 0;
        while (stat >> key) {
            if (key == "btime" && (stat >> seconds)) break;
            stat.ignore(1 << 20, '\n');
        }
        return MSMON_UNIX_EPOCH_AS_FILETIME + seconds * 10000000ull;
    }();
    return boot;
}

uint64_t LinuxProcessStart(DWORD pid, DWORD* parent)
{
    std::ifstream file("/proc/" + std::to_string(pid) + "/stat");
    std::string text;
    if (!std::getline(file, text)) return 0;
    /* The command name may contain spaces and parentheses; fields resume after the last ')'. */
    size_t close = text.rfind(')');
    if (close == std::string::npos) return 0;
    std::istringstream fields(text.substr(close + 2));
    std::string field;
    uint64_t startTicks = 0;
    for (int index = 3; fields >> field; index++) {
        if (index == 4 && parent != nullptr) *parent = static_cast<DWORD>(strtoul(field.c_str(), nullptr, 10));
        if (index == 22) {
            startTicks = strtoull(field.c_str(), nullptr, 10);
            break;
        }
    }
    static const long hertz = sysconf(_SC_CLK_TCK);
    if (hertz <= 0) return 0;
    return LinuxBootFileTime() + startTicks * (10000000ull / static_cast<uint64_t>(hertz));
}

bool LinuxProcessIdentity(DWORD pid, std::wstring& path, uint64_t& startTime)
{
    char target[4096];
    ssize_t length = readlink(("/proc/" + std::to_string(pid) + "/exe").c_str(), target, sizeof(target));
    if (length <= 0 || length >= static_cast<ssize_t>(sizeof(target))) return false;
    startTime = LinuxProcessStart(pid);
    if (startTime == 0) return false;
    path = LinuxWide(std::string(target, static_cast<size_t>(length)));
    return true;
}

/* Wine rewrites argv[0] to the Windows image: "C:\\windows\\system32\\winedevice.exe". */
bool LinuxWinedevice(const std::wstring& argv0)
{
    return wcscasecmp(argv0.substr(argv0.find_last_of(L"\\/") + 1).c_str(), L"winedevice.exe") == 0;
}

static std::wstring Argv0(const std::string& base)
{
    std::ifstream file(base + "/cmdline", std::ios::binary);
    std::string first;
    std::getline(file, first, '\0');
    return LinuxWide(first);
}

std::wstring LinuxResolvedPath(const std::wstring& path)
{
    std::error_code error;
    const std::filesystem::path resolved = std::filesystem::weakly_canonical(LinuxNarrow(path), error);
    return error || resolved.empty() ? path : LinuxWide(resolved.string());
}

static std::string WithoutTrailingSlash(std::string path)
{
    while (path.size() > 1 && path.back() == '/') path.pop_back();
    return path;
}

bool LinuxInScope(DWORD pid, const std::vector<std::wstring>& roots, const std::wstring& prefix)
{
    const std::string base = "/proc/" + std::to_string(pid);
    std::ifstream maps(base + "/maps");
    std::string line;
    while (std::getline(maps, line)) {
        std::istringstream fields(line);
        std::string range, perms, offset, device, inode, path;
        if (!(fields >> range >> perms >> offset >> device >> inode)) continue;
        std::getline(fields >> std::ws, path);
        if (path.empty() || path[0] != '/' || perms.size() < 3 || perms[2] != 'x') continue;
        for (const auto& root : roots) {
            const std::string narrow = WithoutTrailingSlash(LinuxNarrow(root));
            if (!narrow.empty() && path.size() > narrow.size() && path.compare(0, narrow.size(), narrow) == 0 &&
                path[narrow.size()] == '/') {
                return true;
            }
        }
    }
    if (prefix.empty()) return false;
    /* Only the prefix's brokers join by prefix: wineserver does work for the client (process memory
     * reads, file and registry requests) and winedevice.exe runs its drivers (an anti-cheat .sys, IRPs).
     * The launcher and other programs in the prefix are not the client; they join only by mapping an
     * executable under a root, as the client does. */
    std::wstring image;
    uint64_t startTime = 0;
    if (!LinuxProcessIdentity(pid, image, startTime)) return false;
    /* services.exe too: the winedevice.exe and services it starts later (a game's anti-cheat driver) are then
     * tracked from fork, before they load anything. And the other brokers a booted prefix keeps running, which serve
     * the client's RPC: rpcss.exe (DCOM activation), plugplay.exe (device enumeration), explorer.exe (shell, tray,
     * desktop window), svchost.exe (the services it hosts). */
    const std::wstring argv0 = Argv0(base);
    const std::wstring name = argv0.substr(argv0.find_last_of(L"\\/") + 1);
    bool broker = false;
    for (const wchar_t* candidate : {L"services.exe", L"rpcss.exe", L"plugplay.exe", L"explorer.exe", L"svchost.exe"})
        broker = broker || wcscasecmp(name.c_str(), candidate) == 0;
    if (image.substr(image.find_last_of(L'/') + 1).rfind(L"wineserver", 0) != 0 && !LinuxWinedevice(argv0) && !broker)
        return false;
    /* environ is NUL-separated and readable by the owner or root. */
    std::ifstream file(base + "/environ", std::ios::binary);
    std::string environment((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    std::string winePrefix, home;
    for (size_t start = 0; start < environment.size();) {
        size_t end = environment.find('\0', start);
        if (end == std::string::npos) end = environment.size();
        const std::string entry = environment.substr(start, end - start);
        if (entry.compare(0, 11, "WINEPREFIX=") == 0) winePrefix = entry.substr(11);
        if (entry.compare(0, 5, "HOME=") == 0) home = entry.substr(5);
        start = end + 1;
    }
    if (winePrefix.empty()) {
        if (home.empty()) return false;
        winePrefix = home + "/.wine";
    }
    return WithoutTrailingSlash(winePrefix) == WithoutTrailingSlash(LinuxNarrow(prefix));
}

/* FIPS 180-4 SHA-256; the hash chain and every bundle checksum depend on it. */
namespace {
struct Sha256State {
    uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    unsigned char block[64];
    size_t used = 0;
    uint64_t bits = 0;

    static uint32_t Rotate(uint32_t value, int count) { return (value >> count) | (value << (32 - count)); }

    void Compress()
    {
        static const uint32_t k[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
        uint32_t w[64];
        for (int index = 0; index < 16; index++) {
            w[index] = (uint32_t(block[index * 4]) << 24) | (uint32_t(block[index * 4 + 1]) << 16) |
                       (uint32_t(block[index * 4 + 2]) << 8) | block[index * 4 + 3];
        }
        for (int index = 16; index < 64; index++) {
            uint32_t s0 = Rotate(w[index - 15], 7) ^ Rotate(w[index - 15], 18) ^ (w[index - 15] >> 3);
            uint32_t s1 = Rotate(w[index - 2], 17) ^ Rotate(w[index - 2], 19) ^ (w[index - 2] >> 10);
            w[index] = w[index - 16] + s0 + w[index - 7] + s1;
        }
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int index = 0; index < 64; index++) {
            uint32_t t1 = hh + (Rotate(e, 6) ^ Rotate(e, 11) ^ Rotate(e, 25)) + ((e & f) ^ (~e & g)) + k[index] + w[index];
            uint32_t t2 = (Rotate(a, 2) ^ Rotate(a, 13) ^ Rotate(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
            hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }

    void Update(const unsigned char* data, size_t size)
    {
        bits += static_cast<uint64_t>(size) * 8;
        while (size != 0) {
            size_t take = std::min(size, sizeof(block) - used);
            std::memcpy(block + used, data, take);
            used += take;
            data += take;
            size -= take;
            if (used == sizeof(block)) {
                Compress();
                used = 0;
            }
        }
    }

    std::string Finish()
    {
        const uint64_t length = bits;
        const unsigned char pad = 0x80;
        Update(&pad, 1);
        const unsigned char zero = 0;
        while (used != 56) Update(&zero, 1);
        unsigned char tail[8];
        for (int index = 0; index < 8; index++) tail[index] = static_cast<unsigned char>(length >> (56 - index * 8));
        Update(tail, sizeof(tail));
        static const char hex[] = "0123456789abcdef";
        std::string result;
        for (uint32_t word : h) {
            for (int shift = 28; shift >= 0; shift -= 4) result.push_back(hex[(word >> shift) & 0xf]);
        }
        return result;
    }
};
}

std::string Sha256Bytes(const void* data, size_t size)
{
    Sha256State state;
    state.Update(static_cast<const unsigned char*>(data), size);
    return state.Finish();
}

std::string Sha256File(const std::wstring& path)
{
    int fd = open(LinuxNarrow(path).c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return {};
    Sha256State state;
    std::vector<unsigned char> buffer(1u << 20);
    bool ok = true;
    for (;;) {
        ssize_t got = ::read(fd, buffer.data(), buffer.size());
        if (got < 0 && errno == EINTR) continue;
        if (got < 0) ok = false;
        if (got <= 0) break;
        state.Update(buffer.data(), static_cast<size_t>(got));
    }
    close(fd);
    return ok ? state.Finish() : std::string();
}
