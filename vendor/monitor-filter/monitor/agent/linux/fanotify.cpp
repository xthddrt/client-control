#include "session.h"
#include <fcntl.h>
#include <poll.h>
#include <sys/fanotify.h>
#include <sys/vfs.h>
#include <fstream>
#include <sstream>

/*
 * File events from two fanotify groups over every mount:
 *  - a mount-marked group (fd per event, path from /proc/self/fd) for FAN_ACCESS,
 *    FAN_MODIFY and FAN_CLOSE_WRITE -> file_read, file_write, file_close;
 *  - a filesystem-marked FAN_REPORT_DFID_NAME group for FAN_CREATE, FAN_DELETE and
 *    FAN_MOVE -> file_create and file_set_information (Value0 13 = unlink, 10 = rename,
 *    the Windows FileDisposition/FileRename classes the analysis already reads).
 * fanotify reports no byte counts, offsets, open flags or result status, so those
 * fields stay zero.  A path that cannot be resolved is logged with MsMonFlagMissingPath.
 */

namespace {
int gNotify = -1;
int gDirent = -1;
struct MountFd {
    __kernel_fsid_t fsid;
    int fd;
};
std::vector<MountFd> gMounts;

/* FILE_CREATE in the create-disposition byte, as the driver's create options carry it. */
const uint64_t CREATE_DISPOSITION_CREATE = 2ull << 24;
const uint64_t FILE_RENAME_INFORMATION = 10;
const uint64_t FILE_DISPOSITION_INFORMATION = 13;
}

static std::string Unescape(const std::string& field)
{
    std::string output;
    for (size_t index = 0; index < field.size(); index++) {
        /* mountinfo writes space, tab, newline and backslash as \ooo octal escapes. */
        if (field[index] == '\\' && index + 3 < field.size()) {
            output.push_back(static_cast<char>(std::stoi(field.substr(index + 1, 3), nullptr, 8)));
            index += 3;
        } else {
            output.push_back(field[index]);
        }
    }
    return output;
}

static std::vector<std::string> MountPoints()
{
    std::vector<std::string> points;
    std::ifstream file("/proc/self/mountinfo");
    std::string line;
    while (std::getline(file, line)) {
        std::istringstream fields(line);
        std::string id, parent, device, root, point;
        if (fields >> id >> parent >> device >> root >> point) points.push_back(Unescape(point));
    }
    return points;
}

int FanotifyOpen(std::wstring& detail)
{
    /* Either group may be refused on its own (an unprivileged user namespace allows only the
     * second, on filesystems it owns); the counts in detail say which records can appear. */
    gNotify = fanotify_init(FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK, O_RDONLY | O_LARGEFILE | O_CLOEXEC);
    int lastError = gNotify < 0 ? errno : 0;
    const int notifyError = lastError;
    gDirent = fanotify_init(FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK | FAN_REPORT_DFID_NAME, O_RDONLY | O_CLOEXEC);
    const int direntError = gDirent < 0 ? errno : 0;
    if (gDirent < 0) lastError = errno;
    unsigned mounts = 0, mountFailures = 0, filesystems = 0, filesystemFailures = 0;
    for (const auto& point : MountPoints()) {
        if (gNotify >= 0 && fanotify_mark(gNotify, FAN_MARK_ADD | FAN_MARK_MOUNT,
                                          FAN_ACCESS | FAN_MODIFY | FAN_CLOSE_WRITE, AT_FDCWD, point.c_str()) == 0) {
            mounts++;
        } else if (gNotify >= 0) {
            mountFailures++;
            lastError = errno;
        }
        if (gDirent < 0) continue;
        /* Not O_PATH: fanotify_mark refuses O_PATH descriptors with EBADF. */
        int fd = open(point.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        struct statfs info{};
        if (fd < 0 || fstatfs(fd, &info) != 0) {
            if (fd >= 0) close(fd);
            continue;
        }
        __kernel_fsid_t fsid;
        std::memcpy(&fsid, &info.f_fsid, sizeof(fsid));
        bool known = false;
        for (const auto& mount : gMounts) known = known || std::memcmp(&mount.fsid, &fsid, sizeof(fsid)) == 0;
        /* Pseudo filesystems without file handles refuse filesystem marks; their names stay unseen. */
        if (known || fanotify_mark(gDirent, FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
                                   FAN_CREATE | FAN_DELETE | FAN_MOVE | FAN_ONDIR, fd, nullptr) != 0) {
            if (!known) {
                filesystemFailures++;
                lastError = errno;
            }
            close(fd);
            continue;
        }
        filesystems++;
        gMounts.push_back({fsid, fd});
    }
    detail = L"notify_group_errno=" + std::to_wstring(notifyError) +
             L";mount_marks=" + std::to_wstring(mounts) + L";mount_mark_failures=" + std::to_wstring(mountFailures) +
             L";filesystem_marks=" + std::to_wstring(filesystems) +
             L";filesystem_mark_failures=" + std::to_wstring(filesystemFailures) +
             L";dirent_group_errno=" + std::to_wstring(direntError);
    if (mounts == 0 && filesystems == 0) {
        FanotifyClose();
        return lastError != 0 ? lastError : ENOENT;
    }
    return 0;
}

void FanotifyClose()
{
    if (gNotify >= 0) close(gNotify);
    if (gDirent >= 0) close(gDirent);
    gNotify = gDirent = -1;
    for (const auto& mount : gMounts) close(mount.fd);
    gMounts.clear();
}

static bool FdPath(int fd, std::string& path)
{
    char target[4096];
    ssize_t length = readlink(("/proc/self/fd/" + std::to_string(fd)).c_str(), target, sizeof(target));
    if (length <= 0 || length >= static_cast<ssize_t>(sizeof(target))) return false;
    path.assign(target, static_cast<size_t>(length));
    return true;
}

/* The tracked owner of an event, or false (counted as untracked). */
static bool Owner(LinuxSession& session, const fanotify_event_metadata* metadata, uint64_t& start)
{
    session.Enter(MSMON_SENSOR_LINUX_FANOTIFY);
    ULONG flags = 0;
    if (session.Tracked(static_cast<DWORD>(metadata->pid), start, flags)) return true;
    session.SkipUntracked();
    return false;
}

static void ReadNotify(LinuxSession& session)
{
    alignas(fanotify_event_metadata) char buffer[65536];
    ssize_t length = read(gNotify, buffer, sizeof(buffer));
    if (length <= 0) return;
    for (auto* metadata = reinterpret_cast<fanotify_event_metadata*>(buffer); FAN_EVENT_OK(metadata, length);
         metadata = FAN_EVENT_NEXT(metadata, length)) {
        if (metadata->vers != FANOTIFY_METADATA_VERSION) break;
        if ((metadata->mask & FAN_Q_OVERFLOW) != 0) {
            session.NoteDropped();
            continue;
        }
        uint64_t start = 0;
        const bool tracked = Owner(session, metadata, start);
        std::string path;
        const bool resolved = tracked && metadata->fd >= 0 && FdPath(metadata->fd, path);
        if (metadata->fd >= 0) close(metadata->fd);
        if (!tracked) continue;
        const ULONG flags = resolved ? 0 : MsMonFlagMissingPath;
        const DWORD pid = static_cast<DWORD>(metadata->pid);
        const std::wstring text = LinuxWide(path);
        if ((metadata->mask & FAN_ACCESS) != 0)
            session.Log(MSMON_SENSOR_LINUX_FANOTIFY, MsMonFileRead, pid, start, flags, 0, 0, text);
        if ((metadata->mask & FAN_MODIFY) != 0)
            session.Log(MSMON_SENSOR_LINUX_FANOTIFY, MsMonFileWrite, pid, start, flags, 0, 0, text);
        if ((metadata->mask & FAN_CLOSE_WRITE) != 0)
            session.Log(MSMON_SENSOR_LINUX_FANOTIFY, MsMonFileClose, pid, start, flags, 0, 0, text);
    }
}

/* Directory handle + name from a FAN_REPORT_DFID_NAME record; needs CAP_DAC_READ_SEARCH. */
static bool DirentPath(const fanotify_event_metadata* metadata, std::string& path, std::string& entry)
{
    const char* cursor = reinterpret_cast<const char*>(metadata) + metadata->metadata_len;
    const char* end = reinterpret_cast<const char*>(metadata) + metadata->event_len;
    while (cursor + sizeof(fanotify_event_info_header) <= end) {
        auto* info = reinterpret_cast<const fanotify_event_info_header*>(cursor);
        if (info->len == 0 || cursor + info->len > end) return false;
        if (info->info_type == FAN_EVENT_INFO_TYPE_DFID_NAME) {
            auto* fid = reinterpret_cast<const fanotify_event_info_fid*>(info);
            auto* handle = reinterpret_cast<file_handle*>(const_cast<unsigned char*>(fid->handle));
            const char* name = reinterpret_cast<const char*>(handle->f_handle) + handle->handle_bytes;
            entry = name;
            for (const auto& mount : gMounts) {
                if (std::memcmp(&mount.fsid, &fid->fsid, sizeof(fid->fsid)) != 0) continue;
                int directory = open_by_handle_at(mount.fd, handle, O_PATH | O_CLOEXEC);
                if (directory < 0) return false;
                const bool ok = FdPath(directory, path);
                close(directory);
                if (ok && std::strcmp(name, ".") != 0) path += (path == "/" ? "" : "/") + std::string(name);
                return ok;
            }
            return false;
        }
        cursor += info->len;
    }
    return false;
}

/* fanotify merges queued events on one name, so one record may carry several bits;
 * they are logged in lifecycle order: create, rename away, rename here, unlink. */
static void ReadDirent(LinuxSession& session)
{
    alignas(fanotify_event_metadata) char buffer[65536];
    ssize_t length = read(gDirent, buffer, sizeof(buffer));
    if (length <= 0) return;
    for (auto* metadata = reinterpret_cast<fanotify_event_metadata*>(buffer); FAN_EVENT_OK(metadata, length);
         metadata = FAN_EVENT_NEXT(metadata, length)) {
        if (metadata->vers != FANOTIFY_METADATA_VERSION) break;
        if ((metadata->mask & FAN_Q_OVERFLOW) != 0) {
            session.NoteDropped();
            continue;
        }
        uint64_t start = 0;
        if (!Owner(session, metadata, start)) continue;
        std::string path, entry;
        const bool resolved = DirentPath(metadata, path, entry);
        const ULONG flags = resolved ? 0 : MsMonFlagMissingPath;
        const DWORD pid = static_cast<DWORD>(metadata->pid);
        const std::wstring text = LinuxWide(path);
        /* An unresolved directory still leaves the entry name. */
        const std::wstring suffix = ((metadata->mask & FAN_ONDIR) != 0 ? L";directory" : L"") +
                                       (resolved || entry.empty() ? std::wstring() : L";name=" + LinuxWide(entry));
        if ((metadata->mask & FAN_CREATE) != 0)
            session.Log(MSMON_SENSOR_LINUX_FANOTIFY, MsMonFileCreate, pid, start, flags, CREATE_DISPOSITION_CREATE, 0,
                        text, L"create" + suffix);
        if ((metadata->mask & FAN_MOVED_FROM) != 0)
            session.Log(MSMON_SENSOR_LINUX_FANOTIFY, MsMonFileSetInformation, pid, start, flags,
                        FILE_RENAME_INFORMATION, 0, text, L"rename;from" + suffix);
        if ((metadata->mask & FAN_MOVED_TO) != 0)
            session.Log(MSMON_SENSOR_LINUX_FANOTIFY, MsMonFileSetInformation, pid, start, flags,
                        FILE_RENAME_INFORMATION, 0, text, L"rename;to" + suffix);
        if ((metadata->mask & FAN_DELETE) != 0)
            session.Log(MSMON_SENSOR_LINUX_FANOTIFY, MsMonFileSetInformation, pid, start, flags,
                        FILE_DISPOSITION_INFORMATION, 0, text, L"unlink" + suffix);
    }
}

void FanotifyRun(LinuxSession& session)
{
    pollfd descriptors[2] = {{gNotify, POLLIN, 0}, {gDirent, POLLIN, 0}};
    const nfds_t count = gDirent >= 0 ? 2 : 1;
    while (!session.Stopping()) {
        if (poll(descriptors, count, 200) <= 0) continue;
        if ((descriptors[0].revents & POLLIN) != 0) ReadNotify(session);
        if (count == 2 && (descriptors[1].revents & POLLIN) != 0) ReadDirent(session);
    }
}
