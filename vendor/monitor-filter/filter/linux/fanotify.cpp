// fanotify permission decisions for kfilterd (the Linux side of driver/file_filter.c,
// the process-create refusal and the raw/identity device filters).
//
// Every open, read and exec on a marked filesystem waits for this thread. Events of
// unprotected processes are allowed after one /proc read; protected ones go through
// KfDecideWithRights, so first-match rules, audit/would-deny, counted rules and the
// decision ring behave exactly as in the driver.
//
// This thread must never open a file on a marked filesystem: the kernel would hold that
// open for this same thread's answer. It only reads /proc, which is never marked.

#include "kf_linux.h"

#include <linux/netlink.h>
#include <sys/fanotify.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

namespace {

int gFanotify = -1;
int gProcConnector = -1;
int gUevents = -1;

constexpr uint64_t kPermissionMask = FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM | FAN_ACCESS_PERM;

/* Filesystems that are not marked: kernel views kfilterd reads itself (proc), or whose
 * event descriptor could block on another process (fuse) or have side effects
 * (devtmpfs: opening a watchdog or serial node for the event is not harmless). */
bool SkippedFilesystem(const std::string& type)
{
    static const char* skipped[] = {
        "proc", "cgroup", "cgroup2", "devpts", "mqueue", "debugfs", "tracefs", "securityfs",
        "pstore", "bpf", "configfs", "fusectl", "autofs", "hugetlbfs", "binfmt_misc",
        "efivarfs", "rpc_pipefs", "nsfs", "devtmpfs",
    };
    if (type == "fuse" || type == "fuseblk" || type.rfind("fuse.", 0) == 0) return true;
    for (const char* name : skipped) {
        if (type == name) return true;
    }
    return false;
}

/* Character devices that identify the machine; the Windows device filter's HID, USB,
 * SCSI and NVMe counterparts. Every other character device (null, tty, dri, snd) is an
 * ordinary file to the policy. */
bool IdentityDevice(const std::string& path)
{
    static const char* prefixes[] = { "/dev/hidraw", "/dev/sg", "/dev/bsg/", "/dev/bus/usb/", "/dev/nvme" };
    for (const char* prefix : prefixes) {
        if (path.rfind(prefix, 0) == 0) return true;
    }
    return false;
}

std::string MountUnescape(const std::string& value)
{
    std::string output;
    for (size_t index = 0; index < value.size(); index++) {
        if (value[index] == '\\' && index + 3 < value.size()) {
            output.push_back((char)strtol(value.substr(index + 1, 3).c_str(), nullptr, 8));
            index += 3;
        } else {
            output.push_back(value[index]);
        }
    }
    return output;
}

bool MarkFilesystems()
{
    FILE* mounts = fopen("/proc/self/mountinfo", "re");
    if (mounts == nullptr) return false;
    std::set<dev_t> marked;
    bool root = false;
    char line[4096];
    while (fgets(line, sizeof(line), mounts) != nullptr) {
        // id parent major:minor root mountpoint options ... - fstype source superoptions
        char point[4096];
        if (sscanf(line, "%*s %*s %*s %*s %4095s", point) != 1) continue;
        const char* separator = strstr(line, " - ");
        if (separator == nullptr) continue;
        char type[256];
        if (sscanf(separator + 3, "%255s", type) != 1 || SkippedFilesystem(type)) continue;
        std::string path = MountUnescape(point);
        struct stat status;
        if (stat(path.c_str(), &status) != 0 || marked.count(status.st_dev) != 0) continue;
        uint64_t mask = kPermissionMask | FAN_ONDIR;
        int result = fanotify_mark(gFanotify, FAN_MARK_ADD | FAN_MARK_FILESYSTEM, mask, AT_FDCWD, path.c_str());
        if (result != 0) result = fanotify_mark(gFanotify, FAN_MARK_ADD | FAN_MARK_MOUNT, mask, AT_FDCWD, path.c_str());
        if (result != 0) {
            fprintf(stderr, "kfilterd: not mediated: %s (%s): %s\n", path.c_str(), type, strerror(errno));
            continue;
        }
        marked.insert(status.st_dev);
        if (path == "/") root = true;
    }
    fclose(mounts);
    return root;
}

/* Inode marks on the block and identity devices present now. Hot-plugged ones are not
 * covered until restart. Returns false when any mark failed. */
bool MarkDevices(const std::string& directory, bool& all)
{
    DIR* listing = opendir(directory.c_str());
    if (listing == nullptr) return false;
    struct dirent* entry;
    while ((entry = readdir(listing)) != nullptr) {
        if (entry->d_name[0] == '.') continue;
        std::string path = directory + "/" + entry->d_name;
        struct stat status;
        if (lstat(path.c_str(), &status) != 0) continue;
        if (S_ISDIR(status.st_mode)) {
            if (path == "/dev/bsg" || path == "/dev/bus" || path.rfind("/dev/bus/usb", 0) == 0) MarkDevices(path, all);
            continue;
        }
        if (!S_ISBLK(status.st_mode) && !(S_ISCHR(status.st_mode) && IdentityDevice(path))) continue;
        if (fanotify_mark(gFanotify, FAN_MARK_ADD, FAN_OPEN_PERM | FAN_ACCESS_PERM, AT_FDCWD, path.c_str()) != 0) {
            fprintf(stderr, "kfilterd: device not mediated: %s: %s\n", path.c_str(), strerror(errno));
            all = false;
        }
    }
    closedir(listing);
    return true;
}

std::string DescriptorPath(int fd)
{
    char buffer[PATH_MAX];
    ssize_t length = readlink(("/proc/self/fd/" + std::to_string(fd)).c_str(), buffer, sizeof(buffer) - 1);
    if (length <= 0 || buffer[0] != '/') return {};
    return std::string(buffer, (size_t)length);
}

bool ReadProc(const std::string& path, char* buffer, size_t size, size_t& length)
{
    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    ssize_t count = read(fd, buffer, size - 1);
    close(fd);
    if (count <= 0) return false;
    buffer[count] = '\0';
    length = (size_t)count;
    return true;
}

/* A device node the kernel announced: marked as MarkDevices marks it at start. */
void MarkDevice(const std::string& path)
{
    struct stat status;
    if (lstat(path.c_str(), &status) != 0) return;
    if (!S_ISBLK(status.st_mode) && !(S_ISCHR(status.st_mode) && IdentityDevice(path))) return;
    if (fanotify_mark(gFanotify, FAN_MARK_ADD, FAN_OPEN_PERM | FAN_ACCESS_PERM, AT_FDCWD, path.c_str()) != 0) {
        fprintf(stderr, "kfilterd: hot-plugged device not mediated: %s: %s\n", path.c_str(), strerror(errno));
    }
}

/* Kernel uevents (root only): block, HID, USB, SCSI-generic and NVMe nodes added after start. */
int UeventOpen()
{
    int fd = socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_KOBJECT_UEVENT);
    if (fd < 0) return -1;
    struct sockaddr_nl address {};
    address.nl_family = AF_NETLINK;
    address.nl_groups = 1;
    if (bind(fd, (struct sockaddr*)&address, sizeof(address)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

void UeventDrain()
{
    char buffer[8192];
    ssize_t length;
    while ((length = recv(gUevents, buffer, sizeof(buffer) - 1, MSG_DONTWAIT)) > 0) {
        buffer[length] = '\0';
        std::string action, name;
        // "add@/devices/...\0ACTION=add\0DEVNAME=sdb\0SUBSYSTEM=block\0..."
        for (size_t at = 0; at < (size_t)length; at += strlen(buffer + at) + 1) {
            const char* field = buffer + at;
            if (strncmp(field, "ACTION=", 7) == 0) action = field + 7;
            if (strncmp(field, "DEVNAME=", 8) == 0) name = field + 8;
        }
        // A removed node's inode mark goes with the inode; only additions need work.
        if (action == "add" && !name.empty() && name.find("..") == std::string::npos) {
            MarkDevice(name[0] == '/' ? name : "/dev/" + name);
        }
    }
}

/* Mount id -> mount point for one mount namespace, from a mountinfo file. */
struct MountTable {
    uint64_t loaded = 0;
    std::map<int, std::string> points;
};

uint64_t NowSeconds()
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t)now.tv_sec;
}

std::map<int, std::string> ReadMountPoints(const std::string& file)
{
    std::map<int, std::string> points;
    FILE* mounts = fopen(file.c_str(), "re");
    if (mounts == nullptr) return points;
    char line[4096];
    while (fgets(line, sizeof(line), mounts) != nullptr) {
        int id = 0;
        char point[4096];
        if (sscanf(line, "%d %*s %*s %*s %4095s", &id, point) == 2) points[id] = MountUnescape(point);
    }
    fclose(mounts);
    return points;
}

/* Cached per namespace for a second; the table is re-read when a mount id is unknown. */
std::map<int, std::string> MountPoints(ino_t ns, const std::string& file, bool refresh)
{
    static std::mutex lock;
    static std::map<ino_t, MountTable> tables;
    std::lock_guard<std::mutex> guard(lock);
    MountTable& table = tables[ns];
    uint64_t now = NowSeconds();
    if (refresh || table.loaded == 0 || now - table.loaded >= 1) {
        table.points = ReadMountPoints(file);
        table.loaded = now;
    }
    return table.points;
}

ino_t MountNamespace(const std::string& process)
{
    struct stat status;
    return stat(("/proc/" + process + "/ns/mnt").c_str(), &status) == 0 ? status.st_ino : 0;
}

int MountId(int fd)
{
    char text[1024];
    size_t length = 0;
    if (!ReadProc("/proc/self/fdinfo/" + std::to_string(fd), text, sizeof(text), length)) return -1;
    const char* field = strstr(text, "mnt_id:");
    return field != nullptr ? (int)strtol(field + 7, nullptr, 10) : -1;
}

std::string Below(const std::string& path, const std::string& point)
{
    if (point == "/") return path;
    if (path.compare(0, point.size(), point) != 0 || (path.size() > point.size() && path[point.size()] != '/')) return {};
    return path.size() == point.size() ? "/" : path.substr(point.size());
}

/*
 * The event file's path as the task sees it, for a task in another mount namespace (Flatpak,
 * pressure-vessel, unshare): the path inside its mount, placed under that mount's point in the
 * task's mountinfo. Empty when the mount is not in the task's namespace: unresolved, not guessed.
 */
std::string TaskViewPath(pid_t tid, int fd, const std::string& ours)
{
    static const ino_t self = MountNamespace("self");
    ino_t theirs = MountNamespace(std::to_string(tid));
    if (theirs == 0 || theirs == self || ours.empty()) return ours;
    int id = MountId(fd);
    if (id < 0) return {};
    const auto mine = MountPoints(self, "/proc/self/mountinfo", false);
    auto own = mine.find(id);
    // A mount outside kfilterd's namespace is printed up to its own namespace's root: that
    // is already the task's view. A mount both namespaces share is re-anchored below.
    if (own == mine.end()) return ours;
    std::string inside = Below(ours, own->second);
    if (inside.empty()) return {};
    const std::string file = "/proc/" + std::to_string(tid) + "/mountinfo";
    auto table = MountPoints(theirs, file, false);
    auto found = table.find(id);
    if (found == table.end()) {
        table = MountPoints(theirs, file, true);
        found = table.find(id);
        if (found == table.end()) return {};
    }
    if (found->second == "/") return inside;
    return inside == "/" ? found->second : found->second + inside;
}

} // namespace

/*
 * fanotify does not say how a file is being opened. The opening thread is blocked in
 * its open syscall waiting for us, so /proc/<tid>/syscall still shows the arguments.
 * Returns 0 when they cannot be read; the caller then assumes read+write.
 */
ULONG KfOpenRights(pid_t tid, bool& exec)
{
    exec = false;
    char text[512];
    size_t length = 0;
    if (!ReadProc("/proc/" + std::to_string(tid) + "/syscall", text, sizeof(text), length)) return 0;
    unsigned long long args[7] = {};
    long number = -1;
    if (sscanf(text, "%ld %llx %llx %llx %llx", &number, &args[0], &args[1], &args[2], &args[3]) < 1) return 0;

    // 32-bit tasks report i386 numbers: their auxv entries are 4-byte pairs, so the first
    // 8 bytes read as one key larger than any AT_* value.
    bool compat = false;
    {
        char auxv[16];
        size_t auxLength = 0;
        if (ReadProc("/proc/" + std::to_string(tid) + "/auxv", auxv, sizeof(auxv), auxLength) && auxLength >= 8) {
            uint64_t key;
            memcpy(&key, auxv, sizeof(key));
            compat = key > 64;
        }
    }
    unsigned long long flags;
    bool known = true;
    if (!compat) {
        switch (number) {
        case 2: flags = args[1]; break;                        // open
        case 85: flags = O_CREAT | O_WRONLY | O_TRUNC; break;  // creat
        case 257: flags = args[2]; break;                      // openat
        case 304: flags = args[2]; break;                      // open_by_handle_at
        case 437: flags = 0; known = false; break;             // openat2: read below
        case 59: case 322: exec = true; return KFILTER_RIGHT_EXECUTE;   // execve, execveat
        default: return 0;
        }
    } else {
        switch (number) {
        case 5: flags = args[1]; break;
        case 8: flags = O_CREAT | O_WRONLY | O_TRUNC; break;
        case 295: flags = args[2]; break;
        case 342: flags = args[2]; break;
        case 437: flags = 0; known = false; break;
        case 11: case 358: exec = true; return KFILTER_RIGHT_EXECUTE;
        default: return 0;
        }
    }
    if (!known) {
        // struct open_how starts with the u64 flags.
        int memory = open(("/proc/" + std::to_string(tid) + "/mem").c_str(), O_RDONLY | O_CLOEXEC);
        if (memory < 0) return 0;
        uint64_t how = 0;
        ssize_t read = pread(memory, &how, sizeof(how), (off_t)args[2]);
        close(memory);
        if (read != (ssize_t)sizeof(how)) return 0;
        flags = how;
    }
    ULONG rights = 0;
    switch (flags & O_ACCMODE) {
    case O_RDONLY: rights = KFILTER_RIGHT_READ; break;
    case O_WRONLY: rights = KFILTER_RIGHT_WRITE; break;
    default: rights = KFILTER_RIGHT_READ | KFILTER_RIGHT_WRITE; break;
    }
    // As KfCreateRights does for FILE_OVERWRITE/FILE_CREATE: truncation or exclusive
    // creation is a write even through a read-only open.
    if ((flags & O_TRUNC) != 0 || ((flags & O_CREAT) != 0 && (flags & O_EXCL) != 0)) rights |= KFILTER_RIGHT_WRITE;
    return rights;
}

namespace {

bool Decide(const struct fanotify_event_metadata* event)
{
    KfTask task;
    if (!KfReadTask(event->pid, task)) {
        // The task is blocked in the kernel for us, so this is rare; with nothing
        // protected there is nothing to fail closed for.
        return KfPolicyMode() == KFILTER_MODE_BLOCK && KfProcessTrackedCount() != 0;
    }
    if (task.tgid == getpid()) return false;
    bool isProtected = KfTaskProtected(task);
    std::string narrow = DescriptorPath(event->fd);
    if (isProtected) narrow = TaskViewPath(event->pid, event->fd, narrow);
    std::wstring path = KfWide(narrow);

    if ((event->mask & FAN_OPEN_EXEC_PERM) != 0) {
        if (narrow.empty()) {
            if (!isProtected) return false;
            KfSetCurrentProcess(task.tgid, true);
            return KfDecideWithRights(KFILTER_TARGET_PROCESS, NULL, KFILTER_RIGHT_CREATE, NULL, 0,
                                      NULL, NULL, NULL, 0) != FALSE;
        }
        return KfProcessExec(task, isProtected, path);
    }
    if (!isProtected) return false;

    struct stat status {};
    bool haveStatus = fstat(event->fd, &status) == 0;
    ULONG target = KFILTER_TARGET_FILE;
    ULONG rights;
    bool exec = false;
    if ((event->mask & FAN_ACCESS_PERM) != 0) {
        rights = KFILTER_RIGHT_READ;
    } else {
        rights = KfOpenRights(event->pid, exec);
        if (rights == 0) rights = KFILTER_RIGHT_READ | KFILTER_RIGHT_WRITE;
    }
    if (haveStatus && S_ISDIR(status.st_mode)) {
        target = KFILTER_TARGET_DIR;
        rights = (event->mask & FAN_ACCESS_PERM) != 0 ? KFILTER_RIGHT_ENUMERATE
                                                      : (rights | KFILTER_RIGHT_ENUMERATE);
    } else if (haveStatus && S_ISFIFO(status.st_mode)) {
        target = KFILTER_TARGET_PIPE;
    } else if (haveStatus && ((S_ISBLK(status.st_mode) && KfPolicyBlockRawDisk()) ||
                              (S_ISCHR(status.st_mode) && IdentityDevice(narrow)))) {
        target = KFILTER_TARGET_DEVICE;
        rights = KFILTER_RIGHT_RAW_DEVICE;
    }

    KfSetCurrentProcess(task.tgid, true);
    UNICODE_STRING name;
    name.Length = (USHORT)(path.size() * sizeof(WCHAR) > 0xFFF0 ? 0xFFF0 : path.size() * sizeof(WCHAR));
    name.MaximumLength = name.Length;
    name.Buffer = (PWSTR)path.c_str();
    // Device requests carry their control code as the value, as device.c does; opens
    // and reads have none, so value=0x00000000 authorizes them.
    WCHAR valueText[16];
    UNICODE_STRING value;
    UNICODE_STRING* valuePointer = NULL;
    if (target == KFILTER_TARGET_DEVICE) {
        ULONG length = KfDeviceValueText(0, valueText, 16);
        value.Length = value.MaximumLength = (USHORT)(length * sizeof(WCHAR));
        value.Buffer = valueText;
        valuePointer = &value;
    }
    // A path that cannot be resolved is a name failure: denied in block mode.
    return KfDecideWithRights(target, narrow.empty() ? NULL : &name, rights, valuePointer, 0,
                              NULL, NULL, NULL, 0) != FALSE;
}

void Loop()
{
    alignas(struct fanotify_event_metadata) char buffer[65536];
    struct pollfd fds[3] = { { gFanotify, POLLIN, 0 }, { gProcConnector, POLLIN, 0 }, { gUevents, POLLIN, 0 } };
    for (;;) {
        if (poll(fds, 3, -1) < 0) {
            if (errno == EINTR) continue;
            perror("kfilterd: poll");
            _exit(1);
        }
        // Fork notices first, so a child's first open already finds its entry.
        if (gProcConnector >= 0 && (fds[1].revents & POLLIN) != 0) KfProcConnectorDrain(gProcConnector);
        if (gUevents >= 0 && (fds[2].revents & POLLIN) != 0) UeventDrain();
        if ((fds[0].revents & POLLIN) == 0) continue;
        ssize_t length = read(gFanotify, buffer, sizeof(buffer));
        if (length < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            // The kernel could not open one event's object for us (EACCES on a mount root
            // cannot reach, ENOENT, EMFILE...): it has already answered that event, the
            // rest of the queue is fine. Exiting would let every later operation through.
            if (errno != EBADF && errno != EINVAL && errno != EFAULT) {
                static unsigned reported = 0;
                if (reported++ < 8) perror("kfilterd: fanotify read (event skipped)");
                continue;
            }
            perror("kfilterd: fanotify read");
            _exit(1);
        }
        auto* event = (struct fanotify_event_metadata*)buffer;
        for (; FAN_EVENT_OK(event, length); event = FAN_EVENT_NEXT(event, length)) {
            if (event->vers != FANOTIFY_METADATA_VERSION) {
                fprintf(stderr, "kfilterd: fanotify metadata version mismatch\n");
                _exit(1);
            }
            if (event->fd < 0) continue;
            if ((event->mask & kPermissionMask) != 0) {
                struct fanotify_response response;
                response.fd = event->fd;
                response.response = Decide(event) ? FAN_DENY : FAN_ALLOW;
                if (write(gFanotify, &response, sizeof(response)) != (ssize_t)sizeof(response)) {
                    perror("kfilterd: fanotify response");
                }
            }
            close(event->fd);
        }
    }
}

} // namespace

bool KfFanotifyStart(uint32_t& registered)
{
    gFanotify = fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_UNLIMITED_QUEUE |
                                  FAN_UNLIMITED_MARKS | FAN_REPORT_TID,
                              O_RDONLY | O_LARGEFILE | O_CLOEXEC | O_NONBLOCK);
    if (gFanotify < 0) {
        perror("kfilterd: fanotify_init (needs root)");
        return false;
    }
    if (MarkFilesystems()) registered |= KFILTER_REG_MINIFILTER;
    else fprintf(stderr, "kfilterd: the root filesystem is not mediated; file layer unavailable\n");
    bool all = true;
    if (MarkDevices("/dev", all) && all) registered |= KFILTER_REG_DISK | KFILTER_REG_DEVICE;
    else fprintf(stderr, "kfilterd: device marks incomplete; disk/device layers unavailable\n");

    gUevents = UeventOpen();
    if (gUevents < 0) perror("kfilterd: uevent socket (hot-plugged devices are not marked)");
    gProcConnector = KfProcConnectorOpen();
    if (gProcConnector >= 0) registered |= KFILTER_REG_PROCESS;
    else perror("kfilterd: proc connector");
    std::thread(Loop).detach();
    return true;
}
