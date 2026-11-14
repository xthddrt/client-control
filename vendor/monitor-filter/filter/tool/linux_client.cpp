// Linux side of kfilterctl: the kfilterd socket in place of \\.\KFilter, the few
// Win32 helpers linux_compat.h declares, and `launch`.

#include "linux_compat.h"
#include "../linux/kfilter_socket.h"

#include <sys/mount.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <sched.h>
#include <signal.h>
#include <dirent.h>
#include <unistd.h>
#include <climits>
#include <cstdlib>
#include <algorithm>
#include <fstream>
#include <iterator>
#include <string>
#include <memory>
#include <vector>

int WideCharToMultiByte(unsigned, DWORD, const wchar_t* wide, int wideLength,
                        char* output, int outputLength, const char*, BOOL*)
{
    std::string text;
    for (int index = 0; index < wideLength; index++) {
        uint32_t code = (uint32_t)wide[index];
        if (code < 0x80) {
            text.push_back((char)code);
        } else if (code < 0x800) {
            text.push_back((char)(0xC0 | (code >> 6)));
            text.push_back((char)(0x80 | (code & 0x3F)));
        } else if (code < 0x10000) {
            text.push_back((char)(0xE0 | (code >> 12)));
            text.push_back((char)(0x80 | ((code >> 6) & 0x3F)));
            text.push_back((char)(0x80 | (code & 0x3F)));
        } else {
            text.push_back((char)(0xF0 | (code >> 18)));
            text.push_back((char)(0x80 | ((code >> 12) & 0x3F)));
            text.push_back((char)(0x80 | ((code >> 6) & 0x3F)));
            text.push_back((char)(0x80 | (code & 0x3F)));
        }
    }
    if (output == nullptr || outputLength == 0) return (int)text.size();
    if ((int)text.size() > outputLength) return 0;
    memcpy(output, text.data(), text.size());
    return (int)text.size();
}

int MultiByteToWideChar(unsigned, DWORD, const char* text, int textLength, wchar_t* output, int outputLength)
{
    std::wstring wide;
    for (int index = 0; index < textLength;) {
        unsigned char lead = (unsigned char)text[index];
        int extra = lead < 0x80 ? 0 : (lead >> 5) == 6 ? 1 : (lead >> 4) == 14 ? 2 : (lead >> 3) == 30 ? 3 : -1;
        if (extra < 0 || index + extra >= textLength + (extra == 0)) {
            wide.push_back((wchar_t)0xFFFD);
            index++;
            continue;
        }
        uint32_t code = extra == 0 ? lead : (uint32_t)(lead & (0x3F >> extra));
        for (int next = 1; next <= extra; next++) code = (code << 6) | ((unsigned char)text[index + next] & 0x3F);
        wide.push_back((wchar_t)code);
        index += extra + 1;
    }
    if (output == nullptr || outputLength == 0) return (int)wide.size();
    if ((int)wide.size() > outputLength) return 0;
    wmemcpy(output, wide.data(), wide.size());
    return (int)wide.size();
}

static std::string Narrow(const std::wstring& value)
{
    int length = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), (int)value.size(), nullptr, 0, nullptr, nullptr);
    std::string text((size_t)length, '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), (int)value.size(), text.data(), length, nullptr, nullptr);
    return text;
}

static std::wstring Wide(const std::string& value)
{
    int length = MultiByteToWideChar(CP_UTF8, 0, value.data(), (int)value.size(), nullptr, 0);
    std::wstring text((size_t)length, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.data(), (int)value.size(), text.data(), length);
    return text;
}

BOOL DeleteFileW(const wchar_t* path)
{
    return unlink(Narrow(path).c_str()) == 0;
}

BOOL FileTimeToSystemTime(const FILETIME* fileTime, SYSTEMTIME* systemTime)
{
    uint64_t value = ((uint64_t)fileTime->dwHighDateTime << 32) | fileTime->dwLowDateTime;
    if (value < KFILTER_UNIX_EPOCH_AS_FILETIME) return FALSE;
    value -= KFILTER_UNIX_EPOCH_AS_FILETIME;
    time_t seconds = (time_t)(value / 10000000u);
    struct tm parts {};
    if (gmtime_r(&seconds, &parts) == nullptr) return FALSE;
    systemTime->wYear = (WORD)(parts.tm_year + 1900);
    systemTime->wMonth = (WORD)(parts.tm_mon + 1);
    systemTime->wDayOfWeek = (WORD)parts.tm_wday;
    systemTime->wDay = (WORD)parts.tm_mday;
    systemTime->wHour = (WORD)parts.tm_hour;
    systemTime->wMinute = (WORD)parts.tm_min;
    systemTime->wSecond = (WORD)parts.tm_sec;
    systemTime->wMilliseconds = (WORD)((value / 10000u) % 1000u);
    return TRUE;
}

BOOL SystemTimeToTzSpecificLocalTime(const void*, const SYSTEMTIME* universal, SYSTEMTIME* local)
{
    struct tm parts {};
    parts.tm_year = universal->wYear - 1900;
    parts.tm_mon = universal->wMonth - 1;
    parts.tm_mday = universal->wDay;
    parts.tm_hour = universal->wHour;
    parts.tm_min = universal->wMinute;
    parts.tm_sec = universal->wSecond;
    time_t seconds = timegm(&parts);
    struct tm converted {};
    if (localtime_r(&seconds, &converted) == nullptr) return FALSE;
    local->wYear = (WORD)(converted.tm_year + 1900);
    local->wMonth = (WORD)(converted.tm_mon + 1);
    local->wDayOfWeek = (WORD)converted.tm_wday;
    local->wDay = (WORD)converted.tm_mday;
    local->wHour = (WORD)converted.tm_hour;
    local->wMinute = (WORD)converted.tm_min;
    local->wSecond = (WORD)converted.tm_sec;
    local->wMilliseconds = universal->wMilliseconds;
    return TRUE;
}

HANDLE OpenDevice()
{
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un address {};
    address.sun_family = AF_UNIX;
    strncpy(address.sun_path, KFILTER_SOCKET_PATH, sizeof(address.sun_path) - 1);
    if (fd < 0 || connect(fd, (struct sockaddr*)&address, sizeof(address)) != 0) {
        int error = errno;
        if (fd >= 0) close(fd);
        std::fprintf(stderr, "Cannot open %s (%s).\n", KFILTER_SOCKET_PATH, strerror(error));
        std::fprintf(stderr, "kfilterd must be running; run this as root.\n");
        errno = error;
        return INVALID_HANDLE_VALUE;
    }
    return (HANDLE)fd;
}

static bool Transfer(int fd, void* buffer, size_t length, bool sending)
{
    char* cursor = (char*)buffer;
    while (length != 0) {
        ssize_t count = sending ? send(fd, cursor, length, MSG_NOSIGNAL) : recv(fd, cursor, length, 0);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            if (count == 0) errno = EPIPE;
            return false;
        }
        cursor += count;
        length -= (size_t)count;
    }
    return true;
}

bool Ioctl(HANDLE device, DWORD code, void* input, DWORD inputLength,
           void* output, DWORD outputLength, DWORD* returned)
{
    int fd = (int)device;
    KFILTER_SOCKET_REQUEST request {};
    request.Code = (code >> 2) & 0xFFFu;   // the IOCTL function number
    request.InputLength = input != nullptr ? inputLength : 0;
    request.OutputCapacity = output != nullptr ? outputLength : 0;
    if (!Transfer(fd, &request, sizeof(request), true) ||
        (request.InputLength != 0 && !Transfer(fd, input, request.InputLength, true))) {
        return false;
    }
    KFILTER_SOCKET_REPLY reply {};
    if (!Transfer(fd, &reply, sizeof(reply), false)) return false;
    if (reply.OutputLength > request.OutputCapacity) {
        errno = EPROTO;
        return false;
    }
    if (reply.OutputLength != 0 && !Transfer(fd, output, reply.OutputLength, false)) return false;
    if (reply.Error != 0) {
        errno = (int)reply.Error;
        return false;
    }
    if (returned != nullptr) *returned = reply.OutputLength;
    return true;
}

static std::string ResolveImage(const std::string& image)
{
    char resolved[PATH_MAX];
    if (image.find('/') != std::string::npos) return realpath(image.c_str(), resolved) ? resolved : "";
    const char* path = getenv("PATH");
    std::string directories = path != nullptr ? path : "/usr/bin:/bin";
    size_t start = 0;
    while (start <= directories.size()) {
        size_t end = directories.find(':', start);
        std::string candidate = directories.substr(start, end == std::string::npos ? std::string::npos : end - start);
        candidate = (candidate.empty() ? "." : candidate) + "/" + image;
        if (access(candidate.c_str(), X_OK) == 0 && realpath(candidate.c_str(), resolved) != nullptr) return resolved;
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return "";
}

/* Run the client as the user who invoked sudo, not as root. */
static bool DropPrivileges()
{
    const char* uidText = getenv("SUDO_UID");
    if (geteuid() != 0 || uidText == nullptr) {
        if (geteuid() == 0) std::fprintf(stderr, "warning: no SUDO_UID; the client runs as root\n");
        return true;
    }
    uid_t uid = (uid_t)strtoul(uidText, nullptr, 10);
    struct passwd* user = getpwuid(uid);
    if (user == nullptr) return false;
    if (initgroups(user->pw_name, user->pw_gid) != 0 || setgid(user->pw_gid) != 0 || setuid(uid) != 0) return false;
    if (getuid() != uid || geteuid() != uid || setuid(0) == 0) return false;   // the drop must not be reversible
    setenv("HOME", user->pw_dir, 1);
    setenv("USER", user->pw_name, 1);
    setenv("LOGNAME", user->pw_name, 1);
    return true;
}

/* The Wine prefix the client runs in: WINEPREFIX, else the invoking user's ~/.wine. */
static std::string WinePrefix(uid_t& uid)
{
    const char* uidText = getenv("SUDO_UID");
    uid = uidText != nullptr ? (uid_t)strtoul(uidText, nullptr, 10) : getuid();
    if (const char* configured = getenv("WINEPREFIX")) return configured;
    if (struct passwd* user = getpwuid(uid)) return std::string(user->pw_dir) + "/.wine";
    return {};
}

/* The wineserver serving the client's prefix, if one is running: under Wine it creates and
 * connects the program's sockets, in its own network namespace. 0 when there is none. */
static pid_t PrefixWineserver()
{
    uid_t uid = 0;
    std::string prefix = WinePrefix(uid);
    struct stat info {};
    if (prefix.empty() || stat(prefix.c_str(), &info) != 0) return 0;
    char server[128];
    std::snprintf(server, sizeof(server), "/tmp/.wine-%u/server-%llx-%llx", (unsigned)uid,
                  (unsigned long long)info.st_dev, (unsigned long long)info.st_ino);
    DIR* proc = opendir("/proc");
    if (proc == nullptr) return 0;
    pid_t found = 0;
    while (struct dirent* entry = readdir(proc)) {
        pid_t pid = (pid_t)strtol(entry->d_name, nullptr, 10);
        if (pid <= 0) continue;
        char link[PATH_MAX] = {};
        std::string base = "/proc/" + std::to_string(pid);
        ssize_t length = readlink((base + "/exe").c_str(), link, sizeof(link) - 1);
        std::string exe = length > 0 ? std::string(link, (size_t)length) : std::string();
        if (exe.size() < 11 || exe.compare(exe.size() - 11, 11, "/wineserver") != 0) continue;
        length = readlink((base + "/cwd").c_str(), link, sizeof(link) - 1);
        if (length > 0 && std::string(link, (size_t)length) == server) {
            found = pid;
            break;
        }
    }
    closedir(proc);
    return found;
}

static bool EndsWithExe(const std::string& text)
{
    if (text.size() < 4) return false;
    std::string tail = text.substr(text.size() - 4);
    for (char& c : tail) c = (char)tolower((unsigned char)c);
    return tail == ".exe";
}

static bool WineLoaderPath(const std::string& path)
{
    std::string name = path.substr(path.find_last_of('/') + 1);
    return name == "wine" || name == "wine64" || name == "wine-preloader" || name == "wine64-preloader";
}

/* The Windows programs a launcher script names (`exec wine start ... nexon_client.exe`): each
 * *.exe file name in its first 64 KiB, as \\name.exe. Empty when Path is not a #! script. */
static std::vector<std::string> ScriptPrograms(const std::string& path)
{
    std::vector<std::string> programs;
    std::string text(65536, '\0');
    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    ssize_t length = fd >= 0 ? read(fd, text.data(), text.size()) : -1;
    if (fd >= 0) close(fd);
    if (length < 2 || text[0] != '#' || text[1] != '!') return programs;
    text.resize((size_t)length);
    std::string lower = text;
    for (char& c : lower) c = (char)tolower((unsigned char)c);
    for (size_t end = lower.find(".exe"); end != std::string::npos; end = lower.find(".exe", end + 4)) {
        size_t start = end;
        while (start > 0 && (isalnum((unsigned char)text[start - 1]) || strchr("_.-", text[start - 1]) != nullptr)) start--;
        std::string name = "\\" + text.substr(start, end + 4 - start);
        if (start < end && std::find(programs.begin(), programs.end(), name) == programs.end()) programs.push_back(name);
    }
    return programs;
}

/* The Linux file behind a Windows drive path (C:\x\y.exe) in the client's prefix, as Wine
 * maps it through dosdevices; empty when it does not exist. */
static std::string LinuxPathOf(const std::string& program)
{
    if (program.size() < 3 || program[1] != ':' || program[2] != '\\') return {};
    uid_t uid = 0;
    std::string prefix = WinePrefix(uid);
    std::string path = prefix + "/dosdevices/" + (char)tolower((unsigned char)program[0]) + ":";
    for (size_t index = 2; index < program.size(); index++) path += program[index] == '\\' ? '/' : program[index];
    char resolved[PATH_MAX];
    return prefix.empty() || realpath(path.c_str(), resolved) == nullptr ? std::string() : std::string(resolved);
}

/* --cpuid-mask "0x80000002-0x80000004,0x16" as the shim's "80000002,80000003,80000004,16". Identity
 * leaves only (brand string, frequencies, SoC vendor, serial number): feature leaves stay true,
 * because code trusts them and XGETBV cannot be masked. */
static bool MaskedLeaves(const std::string& value, std::string& leaves)
{
    for (size_t start = 0;;) {
        size_t end = value.find(',', start);
        std::string item = value.substr(start, end - start);
        char* stop = nullptr;
        unsigned long low = strtoul(item.c_str(), &stop, 16), high = low;
        if (*stop == '-') high = strtoul(stop + 1, &stop, 16);
        if (item.empty() || *stop != '\0' || high < low || high - low > 2) return false;
        for (unsigned long leaf = low; leaf <= high; leaf++) {
            if (leaf != 0x3 && leaf != 0x16 && leaf != 0x17 && (leaf < 0x80000002 || leaf > 0x80000004)) return false;
            char text[16];
            std::snprintf(text, sizeof(text), "%s%lx", leaves.empty() ? "" : ",", leaf);
            leaves += text;
        }
        if (end == std::string::npos) return true;
        start = end + 1;
    }
}

/* What the client keeps of kfilterctl's environment (relax/kf-launcher's and `monfilter.py run`'s): the
 * account, locale, terminal, display, buses, sound server and TLS key log, Wine's and the graphics
 * stack's settings. sudo's own variables (SUDO_COMMAND spells out this launch) and the rest stay
 * behind; --keep-env adds names. NAME* is a prefix. */
static const char* const kClientEnvironment[] = {
    "HOME", "USER", "LOGNAME", "PATH", "TERM", "LANG", "LANGUAGE", "LC_*", "TZ", "DISPLAY", "XAUTHORITY",
    "WAYLAND_DISPLAY", "XDG_*", "DBUS_SESSION_BUS_ADDRESS", "DBUS_SYSTEM_BUS_ADDRESS", "PULSE_*", "SSLKEYLOGFILE",
    "WINE*", "MESA_*", "DXVK_*", "VKD3D_*", "__GL_*", "VK_*", "PROTON_*",
};

static bool NameMatches(const std::string& name, const std::string& pattern)
{
    if (pattern.empty() || pattern.back() != '*') return name == pattern;
    return name.compare(0, pattern.size() - 1, pattern, 0, pattern.size() - 1) == 0;
}

/* The entries of `environment` the allowlist or `keep` (--keep-env) names, for the client's execve. */
std::vector<std::string> ClientEnvironment(char* const* environment, const std::vector<std::string>& keep)
{
    std::vector<std::string> kept;
    for (char* const* entry = environment; *entry != nullptr; entry++) {
        std::string text = *entry;
        size_t equals = text.find('=');
        if (equals == std::string::npos) continue;
        std::string name = text.substr(0, equals);
        auto matches = [&](const std::string& pattern) { return NameMatches(name, pattern); };
        if (std::any_of(std::begin(kClientEnvironment), std::end(kClientEnvironment), matches) ||
            std::any_of(keep.begin(), keep.end(), matches)) {
            kept.push_back(text);
        }
    }
    return kept;
}

/* --keep-env's value: a variable name, or a prefix ending in * (not * alone, which would keep sudo's). */
bool EnvironmentPattern(const std::string& value)
{
    size_t length = !value.empty() && value.back() == '*' ? value.size() - 1 : value.size();
    return length > 0 && value.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_") >= length;
}

static const char* const kShimArches[] = {"x86_64-linux-gnu", "i386-linux-gnu"};   // ld.so's $LIB names

void RemoveShimDirectory(const std::string& directory)
{
    for (const char* arch : kShimArches) {
        unlink((directory + "/lib/" + arch + "/libkfshim.so").c_str());
        rmdir((directory + "/lib/" + arch).c_str());
    }
    rmdir((directory + "/lib").c_str());
    unlink((directory + "/config").c_str());
    rmdir(directory.c_str());
}

// A new file of root's that every account can read, whatever the umask.
static bool WriteShared(const std::string& path, const std::string& data)
{
    int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);
    bool written = fd >= 0 && fchmod(fd, 0644) == 0 && write(fd, data.data(), data.size()) == (ssize_t)data.size();
    if (fd >= 0) close(fd);
    return written;
}

static bool SharedDirectory(const std::string& path)
{
    return mkdir(path.c_str(), 0755) == 0 && chmod(path.c_str(), 0755) == 0;
}

/* --trap-*: the shim's configuration and a copy of each shim (lib/<multiarch>/libkfshim.so) in a
 * directory of its own, preloaded as <dir>/$LIB/libkfshim.so: the configuration travels in LD_PRELOAD's
 * path, so it reaches every process that loads the shim and none of their environments, and the
 * program's maps name no build path. Root's, readable by any account. Empty on failure. */
std::string ShimDirectory(const std::string& shim, const std::string& config)
{
    char directory[] = "/tmp/kfshim.XXXXXX";
    if (mkdtemp(directory) == nullptr) return {};
    std::string made = directory;
    bool complete = WriteShared(made + "/config", config) && SharedDirectory(made + "/lib");
    for (const char* arch : kShimArches) {
        std::ifstream in(shim + "/lib/" + arch + "/libkfshim.so", std::ios::binary);
        if (!complete || !in) continue;   // no i386 shim: launch has warned
        std::string library((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        complete = !in.bad() && SharedDirectory(made + "/lib/" + arch) &&
                   WriteShared(made + "/lib/" + arch + "/libkfshim.so", library);
    }
    if (!complete || chmod(directory, 0755) != 0) {
        RemoveShimDirectory(made);
        return {};
    }
    return made;
}

int LaunchLinux(const std::wstring& image, int argc, wchar_t** argv, int first, bool network)
{
    std::string path = ResolveImage(Narrow(image));
    if (path.empty()) {
        std::fprintf(stderr, "cannot find executable %s\n", Narrow(image).c_str());
        return 2;
    }
    std::vector<std::string> arguments = { path };
    std::string hostname;
    std::string program;   // --program: the Windows program a Wine loader or script runs
    std::string account;   // --user: a dedicated account instead of the sudo caller
    std::string timeOffset;
    std::string trap;      // the shim's configuration: "cpuid rdtsc log=... mask=..."
    std::vector<std::string> keep;   // --keep-env: more of the environment for the client
    bool uname26 = false;
    bool privateProc = false;
    for (int index = first; index < argc; index++) {
        if (wcscmp(argv[index], L"--no-network") == 0) continue;
        if (wcscmp(argv[index], L"--uname26") == 0) {
            uname26 = true;
            continue;
        }
        if (wcscmp(argv[index], L"--private-proc") == 0) {
            privateProc = true;
            continue;
        }
        if (wcscmp(argv[index], L"--trap-cpuid") == 0 || wcscmp(argv[index], L"--trap-rdtsc") == 0) {
            trap += wcscmp(argv[index], L"--trap-cpuid") == 0 ? " cpuid" : " rdtsc";
            continue;
        }
        bool valued = wcscmp(argv[index], L"--user") == 0 || wcscmp(argv[index], L"--time-offset") == 0 ||
                      wcscmp(argv[index], L"--trap-log") == 0 || wcscmp(argv[index], L"--cpuid-mask") == 0 ||
                      wcscmp(argv[index], L"--keep-env") == 0;
        if (valued) {
            if (index + 1 >= argc || argv[index + 1][0] == L'\0') {
                std::fprintf(stderr, "%ls needs a value\n", argv[index]);
                return 2;
            }
            std::string option = Narrow(argv[index]), value = Narrow(argv[++index]);
            if (option == "--keep-env") {
                if (!EnvironmentPattern(value)) {
                    std::fprintf(stderr, "--keep-env takes a variable name, or a prefix ending in *: %s\n", value.c_str());
                    return 2;
                }
                keep.push_back(value);
            } else if (option == "--user") {
                account = value;
            } else if (option == "--time-offset") {
                char* end = nullptr;
                strtoll(value.c_str(), &end, 10);
                if (*end != '\0') {
                    std::fprintf(stderr, "--time-offset needs whole seconds, e.g. 864000\n");
                    return 2;
                }
                timeOffset = value;
            } else if (option == "--trap-log") {
                if (value[0] != '/' || value.find(' ') != std::string::npos) {
                    std::fprintf(stderr, "--trap-log needs an absolute path without spaces\n");
                    return 2;
                }
                trap += " log=" + value;
            } else {
                std::string leaves;
                if (!MaskedLeaves(value, leaves)) {
                    std::fprintf(stderr, "--cpuid-mask takes hex leaves or ranges among 0x3, 0x16, 0x17 and "
                                         "0x80000002-0x80000004 (identity only), not %s\n", value.c_str());
                    return 2;
                }
                trap += " cpuid mask=" + leaves;
            }
            continue;
        }
        if (wcscmp(argv[index], L"--program") == 0) {
            if (index + 1 >= argc || argv[index + 1][0] == L'\0') {
                std::fprintf(stderr, "--program needs the Windows program, e.g. C:\\Nexon\\...\\MapleStory.exe\n");
                return 2;
            }
            program = Narrow(argv[++index]);
            continue;
        }
        if (wcscmp(argv[index], L"--hostname") == 0) {
            if (index + 1 >= argc) {
                std::fprintf(stderr, "--hostname needs a name\n");
                return 2;
            }
            hostname = Narrow(argv[++index]);
            if (hostname.empty() || hostname.size() > 64) {
                std::fprintf(stderr, "--hostname needs a name of 1 to 64 characters\n");
                return 2;
            }
            continue;
        }
        if (wcscmp(argv[index], L"--appcontainer") == 0) {
            std::fprintf(stderr, "note: --appcontainer has no Linux equivalent; the kfilter cgroup is used\n");
            index++;
            continue;
        }
        arguments.push_back(Narrow(argv[index]));
    }

    // --user: the client (and the prefix default, ~account/.wine) belong to that account.
    if (!account.empty()) {
        struct passwd* user = getpwnam(account.c_str());
        if (user == nullptr || user->pw_uid == 0) {
            std::fprintf(stderr, "--user needs an existing account other than root: %s\n", account.c_str());
            return 2;
        }
        setenv("SUDO_UID", std::to_string(user->pw_uid).c_str(), 1);
        setenv("SUDO_GID", std::to_string(user->pw_gid).c_str(), 1);
    }
    // --trap-*: the shim built beside kfilterctl, one per ELF class; ld.so picks it by $LIB.
    // shortcut: the shim/lib/<multiarch> layout is Debian/Ubuntu's $LIB; elsewhere ld.so cannot
    // find it and the program runs untrapped. Copy to the distribution's $LIB names when needed.
    std::string preload;
    std::string shimLibrary;   // checked again in the child, as the account ld.so loads it for
    // Removed unless the exec went ahead: the family outlives the launch (`wine start` returns at once).
    struct ShimGuard {
        std::string directory;
        bool keep = false;
        ~ShimGuard() { if (!keep && !directory.empty()) RemoveShimDirectory(directory); }
    } shimDirectory;
    if (!trap.empty()) {
        if (trap.find("cpuid") == std::string::npos && trap.find("rdtsc") == std::string::npos) {
            std::fprintf(stderr, "--trap-log needs --trap-cpuid, --trap-rdtsc or --cpuid-mask\n");
            return 2;
        }
        char self[PATH_MAX] = {};
        ssize_t length = readlink("/proc/self/exe", self, sizeof(self) - 1);
        std::string shim = std::string(self, length > 0 ? (size_t)length : 0);
        shim = shim.substr(0, shim.find_last_of('/') + 1) + "shim";
        shimLibrary = shim + "/lib/x86_64-linux-gnu/libkfshim.so";
        if (access(shimLibrary.c_str(), R_OK) != 0) {
            std::fprintf(stderr, "--trap-*: no %s (./build.sh)\n", shimLibrary.c_str());
            return 2;
        }
        if (access((shim + "/lib/i386-linux-gnu/libkfshim.so").c_str(), R_OK) != 0) {
            std::fprintf(stderr, "warning: no i386 shim; 32-bit processes run untrapped\n");
        }
        shimDirectory.directory = ShimDirectory(shim, trap.substr(1));
        if (shimDirectory.directory.empty()) {
            std::fprintf(stderr, "--trap-*: cannot make the shim's directory in /tmp (%s)\n", strerror(errno));
            return 2;
        }
        preload = shimDirectory.directory + "/$LIB/libkfshim.so";
        shimLibrary = shimDirectory.directory + "/lib/x86_64-linux-gnu/libkfshim.so";
    }

    // A Wine loader is admitted for the Windows program it runs: --program, else its first
    // .exe argument (`wine start /d DIR nexon_client.exe`). A script has to name it.
    if (program.empty() && WineLoaderPath(path)) {
        for (size_t index = 1; index < arguments.size() && program.empty(); index++) {
            if (EndsWithExe(arguments[index])) program = arguments[index];
        }
    }
    std::wstring admitted = Wide(path);
    if (program.empty()) {
        // A launcher script without --program: the programs it names are the candidates.
        for (const std::string& candidate : ScriptPrograms(path)) {
            if (admitted.size() + candidate.size() + 1 >= KFILTER_MAX_NAME) break;
            admitted += L'\0';
            admitted += Wide(candidate);
        }
    } else {
        // A bare name lands on a name boundary like a protect entry: \name.exe.
        std::string windows = program.find_first_of("\\/") == std::string::npos ? "\\" + program : program;
        std::string unixPath = program[0] == '/' ? program : LinuxPathOf(program);
        admitted += L'\0';
        admitted += Wide(windows);
        if (!unixPath.empty()) {
            admitted += L'\0';
            admitted += Wide(unixPath);
        }
        if (admitted.size() >= KFILTER_MAX_NAME) {
            std::fprintf(stderr, "the launch image and --program are too long together\n");
            return 2;
        }
    }

    // Under Wine the program's sockets are wineserver's: an empty network namespace for the
    // child is only real if wineserver starts inside it too.
    if (!network) {
        if (pid_t server = PrefixWineserver()) {
            std::fprintf(stderr,
                         "Launch is refused: --no-network, but wineserver %d already serves this Wine prefix and\n"
                         "would make the program's connections outside the new network namespace.\n"
                         "Close the prefix's programs and run `wineserver -k` for it first.\n", (int)server);
            return 1;
        }
    }

    HANDLE device = OpenDevice();
    if (device == INVALID_HANDLE_VALUE) {
        std::fprintf(stderr, "Launch is refused: kfilterd is not available.\n");
        return 1;
    }
    KFILTER_STATUS status {};
    if (!Ioctl(device, KFILTER_IOCTL_GET_STATUS, nullptr, 0, &status, sizeof(status), nullptr) ||
        !Ioctl(device, KFILTER_IOCTL_REGISTER_LAUNCHER, nullptr, 0, nullptr, 0, nullptr)) {
        std::fprintf(stderr, "Launcher registration failed: %s\n", strerror(errno));
        CloseHandle(device);
        return 1;
    }

    // The session cgroup is what nftables matches network rules on.
    std::string cgroup = "/sys/fs/cgroup/kfilter/launch-" + std::to_string(getpid());
    mkdir("/sys/fs/cgroup/kfilter", 0755);
    bool haveCgroup = mkdir(cgroup.c_str(), 0755) == 0;
    if (!haveCgroup) {
        if ((status.Flags & KFILTER_CFG_BLOCK_NETWORK) != 0) {
            std::fprintf(stderr, "Launch is refused: cannot create %s (%s) for the network rules.\n",
                         cgroup.c_str(), strerror(errno));
            CloseHandle(device);
            return 1;
        }
        std::fprintf(stderr, "warning: no session cgroup (%s)\n", strerror(errno));
    }

    // ready: the child finished its setup (cgroup, privilege drop), so admission only
    // covers the exec. gate: admitted, go ahead.
    int gate[2];
    int ready[2];
    if (pipe2(gate, O_CLOEXEC) != 0 || pipe2(ready, O_CLOEXEC) != 0) {
        CloseHandle(device);
        return 1;
    }
    pid_t child = fork();
    if (child < 0) {
        CloseHandle(device);
        return 1;
    }
    if (child == 0) {
        close(gate[1]);
        close(ready[0]);
        if (haveCgroup) {
            int procs = open((cgroup + "/cgroup.procs").c_str(), O_WRONLY | O_CLOEXEC);
            std::string self = std::to_string(getpid());
            if (procs < 0 || write(procs, self.c_str(), self.size()) != (ssize_t)self.size()) {
                std::fprintf(stderr, "cannot join %s\n", cgroup.c_str());
                _exit(126);
            }
            close(procs);
        }
        // --no-network: an empty network namespace, the strongest Linux form of
        // "no internetClient capability".
        if (!network && unshare(CLONE_NEWNET) != 0) {
            std::perror("unshare(CLONE_NEWNET)");
            _exit(126);
        }
        // --hostname: the session's own host and domain name (UTS namespace), which is what
        // GetComputerName, gethostname and uname report to the program. Run wineserver -k
        // first so the prefix's wineserver starts inside it as well.
        if (!hostname.empty() &&
            (unshare(CLONE_NEWUTS) != 0 || sethostname(hostname.c_str(), hostname.size()) != 0 ||
             setdomainname("", 0) != 0)) {
            std::perror("--hostname");
            _exit(126);
        }
        // --time-offset: monotonic and boot time (uptime, GetTickCount) shifted. The child enters
        // the time namespace at exec; the offsets must be set before anything is in it.
        if (!timeOffset.empty()) {
            std::string offsets = "monotonic " + timeOffset + " 0\nboottime " + timeOffset + " 0\n";
            int file = unshare(CLONE_NEWTIME) == 0 ? open("/proc/self/timens_offsets", O_WRONLY | O_CLOEXEC) : -1;
            if (file < 0 || write(file, offsets.data(), offsets.size()) != (ssize_t)offsets.size()) {
                std::perror("--time-offset");
                _exit(126);
            }
            close(file);
        }
        // --private-proc: a procfs that shows only the client account's processes, and a cgroup
        // namespace rooted at the launch cgroup, so neither names the session or kfilter. No pid
        // namespace: kfilter and msmon match wineserver's unix_pid fields against global pids.
        if (privateProc) {
            if (unshare(CLONE_NEWNS | CLONE_NEWCGROUP) != 0 || mount(nullptr, "/", nullptr, MS_REC | MS_SLAVE, nullptr) != 0 ||
                mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, "hidepid=invisible") != 0) {
                std::perror("--private-proc");
                _exit(126);
            }
            // The same superblock cannot be mounted over itself (EBUSY): detach the host's view first.
            if (umount2("/sys/fs/cgroup", MNT_DETACH) != 0 ||
                mount("cgroup2", "/sys/fs/cgroup", "cgroup2", MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr) != 0) {
                std::perror("warning: --private-proc keeps the host's /sys/fs/cgroup");
            }
        }
        // --uname26: uname reports a 2.6 release; /proc/version and osrelease are policy's (hide rules).
        if (uname26 && personality((unsigned long)personality(0xffffffff) | UNAME26) == -1) {
            std::perror("--uname26");
            _exit(126);
        }
        if (!DropPrivileges() || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
            std::fprintf(stderr, "cannot drop privileges\n");
            _exit(126);
        }
        // After the drop: HOME, USER and LOGNAME are the client account's.
        std::vector<std::string> environment = ClientEnvironment(environ, keep);
        if (!preload.empty()) {
            // ld.so skips a preload it cannot read and runs the program untrapped.
            std::string config = shimDirectory.directory + "/config";
            if (access(shimLibrary.c_str(), R_OK) != 0 || access(config.c_str(), R_OK) != 0) {
                std::fprintf(stderr, "--trap-*: the client's account cannot read %s or %s\n", shimLibrary.c_str(),
                             config.c_str());
                _exit(126);
            }
            auto others = std::find_if(environment.begin(), environment.end(),
                                       [](const std::string& entry) { return entry.rfind("LD_PRELOAD=", 0) == 0; });
            std::string value = "LD_PRELOAD=" + preload;
            if (others == environment.end()) environment.push_back(value);
            else *others = value + (others->size() > 11 ? " " + others->substr(11) : "");
        }
        if (write(ready[1], "r", 1) != 1) _exit(126);
        close(ready[1]);
        char go = 0;
        if (read(gate[0], &go, 1) != 1) _exit(126);   // not admitted: never exec
        std::vector<char*> pointers, variables;
        for (auto& argument : arguments) pointers.push_back(argument.data());
        pointers.push_back(nullptr);
        for (auto& variable : environment) variables.push_back(variable.data());
        variables.push_back(nullptr);
        execve(path.c_str(), pointers.data(), variables.data());
        std::perror("execve");
        _exit(127);
    }
    close(gate[0]);
    close(ready[1]);
    char childReady = 0;
    bool setupDone = read(ready[0], &childReady, 1) == 1;
    close(ready[0]);
    if (!setupDone) {
        std::fprintf(stderr, "Launch failed: the child could not be prepared.\n");
        close(gate[1]);
        waitpid(child, nullptr, 0);
        if (haveCgroup) rmdir(cgroup.c_str());
        CloseHandle(device);
        return 1;
    }

    std::unique_ptr<KFILTER_ADMIT_REQUEST> request(new KFILTER_ADMIT_REQUEST());
    request->ProcessId = (ULONG)child;
    wmemcpy(request->ImagePath, admitted.data(), admitted.size());   // NUL-separated, zero-filled
    request->Flags = admitted.size() > path.size() ? KFILTER_ADMIT_FLAG_PROGRAM : 0;
    if (!Ioctl(device, KFILTER_IOCTL_ADMIT_PROCESS, request.get(), sizeof(*request), nullptr, 0, nullptr)) {
        if (!program.empty()) {
            std::fprintf(stderr, "ADMIT_PROCESS failed: %s (is %s protected or under the root, and %s a Wine loader "
                                 "or a script?)\n", strerror(errno), program.c_str(), path.c_str());
        } else {
            std::fprintf(stderr, "ADMIT_PROCESS failed: %s (is %s protected by the policy? A Wine loader or a "
                                 "script that runs one needs --program <Windows program>)\n",
                         strerror(errno), path.c_str());
        }
        kill(child, SIGKILL);
        close(gate[1]);
        waitpid(child, nullptr, 0);
        if (haveCgroup) rmdir(cgroup.c_str());
        CloseHandle(device);
        return 1;
    }
    shimDirectory.keep = true;
    (void)!write(gate[1], "g", 1);
    close(gate[1]);
    // shim=: the trap shim's directory, which outlives the launch (remove it once the family is gone).
    std::fprintf(stderr, "launched pid=%d cgroup=%s network=%s%s%s\n", (int)child, haveCgroup ? cgroup.c_str() : "none",
                 network ? "policy" : "off", shimDirectory.directory.empty() ? "" : " shim=",
                 shimDirectory.directory.c_str());

    // The launcher registration lives as long as this process, as on Windows.
    int waitStatus = 0;
    while (waitpid(child, &waitStatus, 0) < 0 && errno == EINTR) {}
    if (haveCgroup) rmdir(cgroup.c_str());   // fails harmlessly while descendants remain
    CloseHandle(device);
    if (WIFEXITED(waitStatus)) return WEXITSTATUS(waitStatus);
    return 128 + (WIFSIGNALED(waitStatus) ? WTERMSIG(waitStatus) : 0);
}
