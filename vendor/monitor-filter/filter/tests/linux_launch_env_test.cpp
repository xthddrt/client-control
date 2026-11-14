// kfilterctl launch's parts that need neither root nor kfilterd (tool/linux_client.cpp): the client's
// environment allowlist, and the trap shim's configuration directory as the built shim reads it.
//
//   build.sh tests builds it as build/linux/launch-test; tests/run_offline.sh runs it with the
//   build's shim directory: build/linux/launch-test build/linux/shim

#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <algorithm>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

std::vector<std::string> ClientEnvironment(char* const* environment, const std::vector<std::string>& keep);
bool EnvironmentPattern(const std::string& value);
std::string ShimDirectory(const std::string& shim, const std::string& config);
void RemoveShimDirectory(const std::string& directory);

static int gFailures = 0;
static void Expect(const char* name, bool value)
{
    if (!value) {
        std::printf("FAIL %s\n", name);
        gFailures++;
    }
}

static std::string Contents(const std::string& path)
{
    std::ifstream in(path, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

static bool Has(const std::vector<std::string>& list, const std::string& entry)
{
    return std::find(list.begin(), list.end(), entry) != list.end();
}

/* /bin/true with the shim preloaded from `preload` (and KFILTER_TRAP, which no longer configures it):
 * its exit status, and its stderr in `error`. */
static int RunPreloaded(const std::string& preload, std::string& error)
{
    int output[2];
    if (pipe(output) != 0) return -1;
    pid_t child = fork();
    if (child == 0) {
        dup2(output[1], 2);
        close(output[0]);
        std::string variable = "LD_PRELOAD=" + preload, trap = "KFILTER_TRAP=cpuid rdtsc";
        char* arguments[] = {(char*)"/bin/true", nullptr};
        char* environment[] = {variable.data(), trap.data(), nullptr};
        execve("/bin/true", arguments, environment);
        _exit(127);
    }
    close(output[1]);
    error.clear();
    char buffer[512];
    for (ssize_t count; (count = read(output[0], buffer, sizeof(buffer))) > 0;) error.append(buffer, (size_t)count);
    close(output[0]);
    int status = 0;
    waitpid(child, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}

int main(int argc, char** argv)
{
    // What relax/kf-launcher's `sudo -n env ... kfilterctl launch` and `monfilter.py run` hand kfilterctl.
    std::vector<std::string> given = {
        "SUDO_COMMAND=/usr/bin/env HOME=/home/u /home/u/monitor-filter/filter/build/linux/kfilterctl launch x",
        "SUDO_USER=u", "SUDO_UID=1000", "SUDO_GID=1000", "MAIL=/var/mail/root", "SHELL=/bin/bash", "LS_COLORS=rs=0",
        "HOME=/home/u", "USER=u", "LOGNAME=u", "PATH=/usr/bin:/bin", "TERM=xterm", "LANG=C.UTF-8", "LC_ALL=C",
        "DISPLAY=:5", "XAUTHORITY=/home/u/.Xauthority", "WAYLAND_DISPLAY=", "XDG_RUNTIME_DIR=/run/user/1000",
        "XDG_CURRENT_DESKTOP=ubuntu:GNOME", "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
        "DBUS_SYSTEM_BUS_ADDRESS=unix:path=/tmp/c/system_bus", "PULSE_SERVER=unix:/run/user/1000/pulse/native",
        "SSLKEYLOGFILE=Z:/tmp/c/tls-keys.log", "WINEPREFIX=/home/u/.wine-nexon", "WINEDEBUG=-all",
        "MESA_VK_WSI_DEBUG=sw", "DXVK_HUD=0", "__GL_SYNC_TO_VBLANK=0", "KFILTER_TRAP=cpuid log=/home/u/x.log",
        "LD_PRELOAD=/home/u/other.so", "LCX=1", "NOEQUALS",
    };
    std::vector<char*> pointers;
    for (auto& entry : given) pointers.push_back(entry.data());
    pointers.push_back(nullptr);

    std::vector<std::string> kept = ClientEnvironment(pointers.data(), {});
    for (const char* dropped : {"SUDO_", "MAIL=", "SHELL=", "LS_COLORS=", "KFILTER_TRAP=", "LD_PRELOAD=", "LCX=", "NOEQUALS"}) {
        Expect(dropped, std::none_of(kept.begin(), kept.end(),
                                     [&](const std::string& entry) { return entry.rfind(dropped, 0) == 0; }));
    }
    for (const char* wanted : {"HOME=/home/u", "USER=u", "LOGNAME=u", "PATH=/usr/bin:/bin", "TERM=xterm", "LANG=C.UTF-8",
                               "LC_ALL=C", "DISPLAY=:5", "XAUTHORITY=/home/u/.Xauthority", "WAYLAND_DISPLAY=",
                               "XDG_RUNTIME_DIR=/run/user/1000", "XDG_CURRENT_DESKTOP=ubuntu:GNOME",
                               "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
                               "DBUS_SYSTEM_BUS_ADDRESS=unix:path=/tmp/c/system_bus",
                               "PULSE_SERVER=unix:/run/user/1000/pulse/native", "SSLKEYLOGFILE=Z:/tmp/c/tls-keys.log",
                               "WINEPREFIX=/home/u/.wine-nexon", "WINEDEBUG=-all", "MESA_VK_WSI_DEBUG=sw", "DXVK_HUD=0",
                               "__GL_SYNC_TO_VBLANK=0"}) {
        Expect(wanted, Has(kept, wanted));
    }
    Expect("kept in the given order", kept.front() == "HOME=/home/u");
    std::vector<std::string> more = ClientEnvironment(pointers.data(), {"LD_PRELOAD", "LS_*"});
    Expect("--keep-env NAME", Has(more, "LD_PRELOAD=/home/u/other.so"));
    Expect("--keep-env PREFIX*", Has(more, "LS_COLORS=rs=0") && !Has(more, "SHELL=/bin/bash"));
    Expect("--keep-env takes NAME and PREFIX*", EnvironmentPattern("LD_PRELOAD") && EnvironmentPattern("LS_*"));
    for (const char* refused : {"*", "", "A B", "A=1", "A*B", "**"}) Expect(refused, !EnvironmentPattern(refused));

    // The shim's directory: root's config beside copies of the shims (the program's maps name no build
    // path), read by the built shim through the preload path; the shim loaded without it exits 126
    // rather than run untrapped.
    char shim[PATH_MAX];
    if (argc < 2 || realpath(argv[1], shim) == nullptr) {
        std::printf("FAIL usage: launch-test <build/linux/shim>\n");
        return 1;
    }
    char scratch[] = "/tmp/kfshim-test.XXXXXX";
    Expect("scratch directory", mkdtemp(scratch) != nullptr);
    std::string log = std::string(scratch) + "/trap.log";
    std::string directory = ShimDirectory(shim, "log=" + log);
    struct stat info {};
    Expect("the directory is made", directory.rfind("/tmp/kfshim.", 0) == 0 && stat(directory.c_str(), &info) == 0 &&
                                        (info.st_mode & 07777) == 0755);
    Expect("its config, readable by any account", stat((directory + "/config").c_str(), &info) == 0 &&
                                                      (info.st_mode & 07777) == 0644 && info.st_size == (off_t)log.size() + 4);
    Expect("its lib is a directory, not a link to the build", lstat((directory + "/lib").c_str(), &info) == 0 &&
                                                                  S_ISDIR(info.st_mode) && (info.st_mode & 07777) == 0755);
    for (const char* arch : {"x86_64-linux-gnu", "i386-linux-gnu"}) {
        std::string copy = directory + "/lib/" + arch + "/libkfshim.so", built = std::string(shim) + "/lib/" + arch + "/libkfshim.so";
        if (access(built.c_str(), F_OK) != 0) continue;
        Expect(arch, lstat((directory + "/lib/" + arch).c_str(), &info) == 0 && S_ISDIR(info.st_mode) &&
                         (info.st_mode & 07777) == 0755 && lstat(copy.c_str(), &info) == 0 && S_ISREG(info.st_mode) &&
                         (info.st_mode & 07777) == 0644 && Contents(copy) == Contents(built) && !Contents(copy).empty());
    }
    std::string error;
    Expect("the shim reads its configuration beside the preload path",
           RunPreloaded(directory + "/$LIB/libkfshim.so", error) == 0 && access(log.c_str(), F_OK) == 0);
    Expect("and says nothing", error.empty());
    Expect("without it the shim refuses to run untrapped",
           RunPreloaded(std::string(shim) + "/$LIB/libkfshim.so", error) == 126 &&
               error.find("no trap configuration") != std::string::npos);
    RemoveShimDirectory(directory);
    Expect("the directory is removed", access(directory.c_str(), F_OK) != 0);
    unlink(log.c_str());
    rmdir(scratch);

    if (gFailures == 0) std::printf("launch-test: PASS\n");
    return gFailures == 0 ? 0 : 1;
}
