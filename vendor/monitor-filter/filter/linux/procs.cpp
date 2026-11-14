// Protected-process identity for kfilterd (the Linux side of driver/process.c).
//
// A process is identified by PID plus /proc start time, never by PID alone. Admitted
// and tracked processes are stored; descendants inherit protection when they were
// forked after their parent was admitted. The proc connector reports fork/exec/exit,
// and every fanotify decision also checks the parent lazily, because the two kernel
// channels are not ordered: a child may open a file before its fork event is read.

#include "kf_linux.h"

#include <linux/cn_proc.h>
#include <linux/connector.h>
#include <linux/netlink.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <mutex>
#include <unordered_map>

namespace {

/* No fixed table as in the driver, but a bound so a fork bomb cannot exhaust kfilterd. */
constexpr size_t kMaxTracked = 4096;
constexpr ULONG kAllowMaxStarts = 8;

struct Entry {
    uint64_t start = 0;
    uint64_t since = 0;        // children forked at or after this tick inherit
    ULONG generation = 0;
    std::wstring image;
    std::wstring expect;       // launch handshake: the image the first exec must be
    std::wstring program;      // KfProgramImage, read on first use
};

std::mutex gLock;
std::unordered_map<pid_t, Entry> gTracked;
pid_t gLauncherPid = 0;
uint64_t gLauncherStart = 0;

std::mutex gAllowLock;
uint64_t gAllowUntil = 0;      // CLOCK_MONOTONIC ns, 0 = closed
ULONG gAllowLeft = 0;
std::wstring gAllowCreator;

thread_local pid_t tCurrentPid = 0;
thread_local bool tCurrentProtected = false;

bool ReadSmallFile(const std::string& path, std::string& text)
{
    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    char buffer[4096];
    ssize_t length = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);
    if (length <= 0) return false;
    text.assign(buffer, (size_t)length);
    return true;
}

uint64_t NowTicks()
{
    struct timespec now;
    clock_gettime(CLOCK_BOOTTIME, &now);
    long hz = sysconf(_SC_CLK_TCK);
    return (uint64_t)now.tv_sec * (uint64_t)hz + (uint64_t)now.tv_nsec / (1000000000ull / (uint64_t)hz);
}

uint64_t NowMonotonic()
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t)now.tv_sec * 1000000000ull + (uint64_t)now.tv_nsec;
}

std::wstring BaseName(const std::wstring& path)
{
    size_t slash = path.find_last_of(L'/');
    return slash == std::wstring::npos ? path : path.substr(slash + 1);
}

UNICODE_STRING Unicode(const std::wstring& value)
{
    UNICODE_STRING string;
    size_t bytes = value.size() * sizeof(WCHAR);
    if (bytes > 0xFFF0) bytes = 0xFFF0;
    string.Length = (USHORT)bytes;
    string.MaximumLength = (USHORT)bytes;
    string.Buffer = (PWSTR)value.c_str();
    return string;
}

void LogProcess(pid_t tgid, ULONG action, NTSTATUS status, const std::wstring& image)
{
    UNICODE_STRING name = Unicode(image);
    KfLogEventFor(UlongToHandle((ULONG)tgid), KFILTER_TARGET_PROCESS, action,
                  KFILTER_EVENT_FLAG_PROCESS_CREATE, status, 0, 0, &name);
}

/* gLock held. */
NTSTATUS AddLocked(pid_t tgid, const Entry& entry)
{
    auto found = gTracked.find(tgid);
    if (found != gTracked.end() && found->second.start == entry.start) return STATUS_ALREADY_REGISTERED;
    if (found == gTracked.end() && gTracked.size() >= kMaxTracked) return STATUS_INSUFFICIENT_RESOURCES;
    gTracked[tgid] = entry;
    return STATUS_SUCCESS;
}

bool CurrentIsLauncher()
{
    std::lock_guard<std::mutex> guard(gLock);
    return gLauncherPid != 0 && gLauncherPid == tCurrentPid && KfStartTime(tCurrentPid) == gLauncherStart;
}

/* The armed launcher started this exec itself (its forked copy is exec'ing), or a LAUNCH
 * broker whose parent is the armed launcher did. Mirrors KfProcessLaunchedBy. */
bool LaunchedBy(const std::wstring& creator, const KfTask& task)
{
    std::wstring current = KfExePath(task.tgid);   // still the pre-exec image
    if (!current.empty() && BaseName(current) == creator) return true;
    std::wstring parent = KfExePath(task.ppid);
    if (parent.empty() || BaseName(parent) != creator || current.empty()) return false;
    // account=system on Linux means the broker runs as root.
    std::string status;
    bool root = false;
    if (ReadSmallFile("/proc/" + std::to_string(task.tgid) + "/status", status)) {
        const char* uid = strstr(status.c_str(), "\nUid:");
        root = uid != nullptr && strtol(uid + 5, nullptr, 10) == 0;
    }
    UNICODE_STRING image = Unicode(current);
    return KfPolicyLaunchBroker(&image, root ? TRUE : FALSE) != FALSE;
}

bool TakeLaunchPass(const KfTask& task)
{
    std::wstring creator;
    uint64_t now = NowMonotonic();
    {
        std::lock_guard<std::mutex> guard(gAllowLock);
        if (gAllowUntil != 0 && now >= gAllowUntil) gAllowUntil = 0;
        if (gAllowUntil == 0) return false;
        creator = gAllowCreator;
    }
    if (!LaunchedBy(creator, task)) return false;
    std::lock_guard<std::mutex> guard(gAllowLock);
    bool match = gAllowUntil != 0 && now < gAllowUntil && gAllowLeft != 0;
    if (match && --gAllowLeft == 0) gAllowUntil = 0;
    return match;
}

bool ProtectedName(const std::wstring& image)
{
    UNICODE_STRING name = Unicode(image);
    return !image.empty() && KfPolicyMatchesProtectedName(&name) != FALSE;
}

/* A script (#!) runs its interpreter; nexon-launcher-style scripts exec wine. */
bool IsScript(const std::wstring& path)
{
    char magic[2] = {};
    int fd = open(KfNarrow(path).c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    bool script = read(fd, magic, sizeof(magic)) == (ssize_t)sizeof(magic) && magic[0] == '#' && magic[1] == '!';
    close(fd);
    return script;
}

/* ADMIT's image check. Image is what the child will exec. With KFILTER_ADMIT_FLAG_PROGRAM a
 * Wine loader or a script that runs one is admitted for the Windows program after it in
 * Field (its Windows name, then optionally its Linux path); that program, not the loader,
 * must be protected or under the root. A protected image started any other way still needs
 * the launch pass. */
bool AdmitsImage(const std::wstring& image, const wchar_t* field, ULONG flags)
{
    if (ProtectedName(image)) return true;
    if ((flags & KFILTER_ADMIT_FLAG_PROGRAM) == 0 || !(KfWineLoader(image) || IsScript(image))) return false;
    for (size_t offset = image.size() + 1; offset < KFILTER_MAX_NAME && field[offset] != L'\0';) {
        std::wstring program(field + offset, KfLengthBounded(field + offset, KFILTER_MAX_NAME - (ULONG)offset));
        if (ProtectedName(program)) return true;
        offset += program.size() + 1;
    }
    return false;
}

} // namespace

std::wstring KfWide(const std::string& value)
{
    std::wstring output;
    size_t index = 0;
    while (index < value.size()) {
        unsigned char lead = (unsigned char)value[index];
        size_t extra = lead < 0x80 ? 0 : (lead >> 5) == 6 ? 1 : (lead >> 4) == 14 ? 2 : (lead >> 3) == 30 ? 3 : 4;
        if (extra == 4 || index + extra >= value.size() + (extra == 0)) {
            // Not UTF-8 (Linux names are bytes): keep the byte visible as U+FFFD.
            output.push_back((wchar_t)0xFFFD);
            index++;
            continue;
        }
        uint32_t code = extra == 0 ? lead : (uint32_t)(lead & (0x3F >> extra));
        for (size_t next = 1; next <= extra; next++) code = (code << 6) | ((unsigned char)value[index + next] & 0x3F);
        output.push_back((wchar_t)code);
        index += extra + 1;
    }
    return output;
}

std::string KfNarrow(const std::wstring& value)
{
    std::string output;
    for (wchar_t character : value) {
        uint32_t code = (uint32_t)character;
        if (code < 0x80) {
            output.push_back((char)code);
        } else if (code < 0x800) {
            output.push_back((char)(0xC0 | (code >> 6)));
            output.push_back((char)(0x80 | (code & 0x3F)));
        } else if (code < 0x10000) {
            output.push_back((char)(0xE0 | (code >> 12)));
            output.push_back((char)(0x80 | ((code >> 6) & 0x3F)));
            output.push_back((char)(0x80 | (code & 0x3F)));
        } else {
            output.push_back((char)(0xF0 | (code >> 18)));
            output.push_back((char)(0x80 | ((code >> 12) & 0x3F)));
            output.push_back((char)(0x80 | ((code >> 6) & 0x3F)));
            output.push_back((char)(0x80 | (code & 0x3F)));
        }
    }
    return output;
}

uint64_t KfStartTime(pid_t pid)
{
    std::string text;
    if (pid <= 0 || !ReadSmallFile("/proc/" + std::to_string(pid) + "/stat", text)) return 0;
    size_t close = text.rfind(')');
    if (close == std::string::npos) return 0;
    // Fields after the command: state is field 3, starttime field 22.
    const char* cursor = text.c_str() + close + 1;
    for (int field = 3; field < 22; field++) {
        cursor = strchr(cursor + 1, ' ');
        if (cursor == nullptr) return 0;
    }
    return strtoull(cursor + 1, nullptr, 10);
}

bool KfReadTask(pid_t tid, KfTask& task)
{
    std::string text;
    if (tid <= 0 || !ReadSmallFile("/proc/" + std::to_string(tid) + "/status", text)) return false;
    const char* tgid = strstr(text.c_str(), "\nTgid:");
    const char* ppid = strstr(text.c_str(), "\nPPid:");
    if (tgid == nullptr || ppid == nullptr) return false;
    task.tid = tid;
    task.tgid = (pid_t)strtol(tgid + 6, nullptr, 10);
    task.ppid = (pid_t)strtol(ppid + 6, nullptr, 10);
    task.start = KfStartTime(task.tgid);
    return task.tgid > 0 && task.start != 0;
}

std::wstring KfExePath(pid_t pid)
{
    char buffer[PATH_MAX];
    if (pid <= 0) return {};
    ssize_t length = readlink(("/proc/" + std::to_string(pid) + "/exe").c_str(), buffer, sizeof(buffer) - 1);
    if (length <= 0) return {};
    return KfWide(std::string(buffer, (size_t)length));
}

bool KfWineLoader(const std::wstring& path)
{
    std::wstring name = BaseName(path);
    return name == L"wine" || name == L"wine64" || name == L"wine-preloader" || name == L"wine64-preloader";
}

std::wstring KfProgramImage(pid_t pid)
{
    std::wstring exe = KfExePath(pid);
    if (exe.empty() || !KfWineLoader(exe)) return exe;
    std::string arguments;
    if (!ReadSmallFile("/proc/" + std::to_string(pid) + "/cmdline", arguments)) return exe;
    std::string first = arguments.substr(0, arguments.find('\0'));
    // Wine rewrites argv[0] to the Windows program once its loader has started (C:\...\x.exe,
    // or the bare name it was started as); until then argv[0] is the loader (a Unix path, or a
    // bare loader name) and the process is named by the loader.
    bool loader = first.empty() || first[0] == '/' || KfWineLoader(KfWide("/" + first));
    return loader ? exe : KfWide(first);
}

bool KfTaskProtected(const KfTask& task)
{
    std::lock_guard<std::mutex> guard(gLock);
    auto self = gTracked.find(task.tgid);
    if (self != gTracked.end()) {
        if (self->second.start == task.start) return true;
        gTracked.erase(self);   // PID reuse: the stored identity is gone
    }
    auto parent = gTracked.find(task.ppid);
    if (parent == gTracked.end() || task.start < parent->second.since) return false;
    if (KfStartTime(task.ppid) != parent->second.start) return false;
    Entry child;
    child.start = task.start;
    child.since = task.start;
    child.generation = parent->second.generation;
    child.image = KfExePath(task.tgid);
    // A full table must not leave a descendant unconstrained: it stays protected for
    // this decision and is re-derived from its parent next time.
    (void)AddLocked(task.tgid, child);
    return true;
}

bool KfProcessExec(const KfTask& task, bool isProtected, const std::wstring& path)
{
    ULONG mode = KfPolicyMode();
    BOOLEAN enforce = mode == KFILTER_MODE_BLOCK && KfPolicyBlockProcessCreate();
    UNICODE_STRING image = Unicode(path);

    if (isProtected) {
        bool mismatch = false;
        {
            std::lock_guard<std::mutex> guard(gLock);
            auto found = gTracked.find(task.tgid);
            if (found != gTracked.end() && !found->second.expect.empty()) {
                mismatch = found->second.expect != path;
                found->second.expect.clear();
                found->second.image = path;
            }
        }
        if (mismatch) {
            // The admitted child is not starting the image kfilterctl named.
            KfCountDenied();
            LogProcess(task.tgid, mode == KFILTER_MODE_BLOCK ? KFilterActionDeny : KFilterActionAudit,
                       STATUS_OBJECT_NAME_INVALID, path);
            if (mode == KFILTER_MODE_BLOCK) return true;
        }
        KfSetCurrentProcess(task.tgid, true);
        return KfDecideWithRights(KFILTER_TARGET_PROCESS, &image, KFILTER_RIGHT_CREATE, NULL, 0,
                                  NULL, NULL, NULL, 0) != FALSE;
    }

    if (!KfPolicyMatchesProtectedName(&image)) return false;
    // A protected image started outside the launcher handshake: refused in block mode
    // unless the one-time launch pass admits it; tracked as a family root otherwise.
    if (enforce) {
        if (!TakeLaunchPass(task)) {
            KfCountDenied();
            LogProcess(task.tgid, KFilterActionDeny, STATUS_ACCESS_DENIED, path);
            return true;
        }
        LogProcess(task.tgid, KFilterActionAllow, STATUS_SUCCESS, path);
    }
    Entry entry;
    entry.start = task.start;
    entry.since = NowTicks();   // children it forked before this exec stay outside
    entry.generation = KfPolicyGeneration();
    entry.image = path;
    NTSTATUS status;
    {
        std::lock_guard<std::mutex> guard(gLock);
        status = AddLocked(task.tgid, entry);
    }
    if (!NT_SUCCESS(status) && KfAdmissionCreationDenied(mode, (KF_ULONG)status)) {
        KfCountDenied();
        LogProcess(task.tgid, KFilterActionDeny, status, path);
        return true;
    }
    return false;
}

int KfProcConnectorOpen()
{
    int fd = socket(PF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_CONNECTOR);
    if (fd < 0) return -1;
    struct sockaddr_nl address {};
    address.nl_family = AF_NETLINK;
    address.nl_groups = CN_IDX_PROC;
    address.nl_pid = 0;
    if (bind(fd, (struct sockaddr*)&address, sizeof(address)) != 0) {
        close(fd);
        return -1;
    }
    // nlmsghdr + cn_msg + the op, built by hand: cn_msg ends in a flexible array.
    alignas(struct nlmsghdr) char request[NLMSG_SPACE(sizeof(struct cn_msg) + sizeof(enum proc_cn_mcast_op))] = {};
    struct nlmsghdr* header = (struct nlmsghdr*)request;
    struct cn_msg* message = (struct cn_msg*)NLMSG_DATA(header);
    enum proc_cn_mcast_op op = PROC_CN_MCAST_LISTEN;
    header->nlmsg_len = NLMSG_LENGTH(sizeof(struct cn_msg) + sizeof(op));
    header->nlmsg_type = NLMSG_DONE;
    header->nlmsg_pid = (uint32_t)getpid();
    message->id.idx = CN_IDX_PROC;
    message->id.val = CN_VAL_PROC;
    message->len = sizeof(op);
    memcpy(message->data, &op, sizeof(op));
    if (send(fd, request, header->nlmsg_len, 0) != (ssize_t)header->nlmsg_len) {
        close(fd);
        return -1;
    }
    return fd;
}

void KfProcConnectorDrain(int socket)
{
    alignas(struct nlmsghdr) char buffer[8192];
    ssize_t length;
    while ((length = recv(socket, buffer, sizeof(buffer), MSG_DONTWAIT)) > 0) {
        for (struct nlmsghdr* header = (struct nlmsghdr*)buffer; NLMSG_OK(header, (size_t)length);
             header = NLMSG_NEXT(header, length)) {
            struct cn_msg* message = (struct cn_msg*)NLMSG_DATA(header);
            if (message->id.idx != CN_IDX_PROC || message->id.val != CN_VAL_PROC) continue;
            struct proc_event* event = (struct proc_event*)message->data;
            std::lock_guard<std::mutex> guard(gLock);
            if (event->what == PROC_EVENT_FORK) {
                pid_t child = event->event_data.fork.child_tgid;
                if (event->event_data.fork.child_pid != child) continue;   // a thread
                auto parent = gTracked.find(event->event_data.fork.parent_tgid);
                if (parent == gTracked.end()) continue;
                Entry entry;
                entry.start = KfStartTime(child);
                if (entry.start == 0 || entry.start < parent->second.since) continue;
                entry.since = entry.start;
                entry.generation = parent->second.generation;
                entry.image = parent->second.image;
                (void)AddLocked(child, entry);
            } else if (event->what == PROC_EVENT_EXEC) {
                auto found = gTracked.find(event->event_data.exec.process_tgid);
                if (found != gTracked.end()) found->second.image = KfExePath(found->first);
            } else if (event->what == PROC_EVENT_EXIT) {
                pid_t pid = event->event_data.exit.process_pid;
                if (pid != event->event_data.exit.process_tgid) continue;
                gTracked.erase(pid);
                if (pid == gLauncherPid) gLauncherPid = 0;
            }
        }
    }
}

extern "C" {

BOOLEAN KfProcessIsProtectedCurrent(VOID)
{
    return tCurrentProtected ? TRUE : FALSE;
}

ULONG KfProcessImageOf(HANDLE ProcessId, PWCHAR Buffer, ULONG Capacity)
{
    pid_t pid = (pid_t)HandleToULong(ProcessId);
    std::wstring program;
    if (Buffer == nullptr || Capacity == 0) return 0;
    Buffer[0] = L'\0';
    {
        std::lock_guard<std::mutex> guard(gLock);
        auto found = gTracked.find(pid);
        if (found == gTracked.end()) return 0;
        program = found->second.program;
    }
    if (program.empty()) {
        // Read outside the lock. Kept once final: a Wine process whose argv[0] is not yet
        // rewritten is named by its loader for now and read again next time.
        program = KfProgramImage(pid);
        if (!program.empty() && !KfWineLoader(program)) {
            std::lock_guard<std::mutex> guard(gLock);
            auto found = gTracked.find(pid);
            if (found != gTracked.end()) found->second.program = program;
        }
    }
    ULONG length = (ULONG)(program.size() < Capacity ? program.size() : Capacity - 1);
    wmemcpy(Buffer, program.data(), length);
    Buffer[length] = L'\0';
    return length;
}

ULONG KfProcessTrackedCount(VOID)
{
    std::lock_guard<std::mutex> guard(gLock);
    return (ULONG)gTracked.size();
}

VOID KfProcessClearTracking(VOID)
{
    std::lock_guard<std::mutex> guard(gLock);
    for (const auto& entry : gTracked) KfBpfUnprotect(entry.first);
    gTracked.clear();
}

NTSTATUS KfProcessTrack(HANDLE ProcessId)
{
    pid_t pid = (pid_t)HandleToULong(ProcessId);
    if (pid <= 0) return STATUS_INVALID_PARAMETER;
    uint64_t start = KfStartTime(pid);
    if (start == 0) return STATUS_INVALID_CID;
    std::wstring image = KfExePath(pid);
    // Kernel threads have no image and are never protected: a confirmed non-match.
    if (image.empty()) return KfStartTime(pid) != 0 ? STATUS_NOT_FOUND : STATUS_INVALID_CID;
    UNICODE_STRING name = Unicode(image);
    // Under Wine the exe is the loader: a Windows protect name matches the Windows image.
    std::wstring program = KfWineLoader(image) ? KfProgramImage(pid) : std::wstring();
    UNICODE_STRING programName = Unicode(program);
    if (!KfPolicyMatchesProtectedName(&name) && (program.empty() || !KfPolicyMatchesProtectedName(&programName))) {
        return STATUS_NOT_FOUND;
    }
    Entry entry;
    entry.start = start;
    entry.since = NowTicks();   // children it forked before now are not adopted
    entry.generation = KfPolicyGeneration();
    entry.image = image;
    std::lock_guard<std::mutex> guard(gLock);
    NTSTATUS status = AddLocked(pid, entry);
    if (NT_SUCCESS(status)) KfBpfProtect(pid, std::wstring());
    return status == STATUS_ALREADY_REGISTERED ? STATUS_SUCCESS : status;
}

NTSTATUS KfProcessRegisterLauncher(VOID)
{
    uint64_t start = KfStartTime(tCurrentPid);
    if (tCurrentPid <= 0 || start == 0) return STATUS_INVALID_PARAMETER;
    std::lock_guard<std::mutex> guard(gLock);
    gLauncherPid = tCurrentPid;
    gLauncherStart = start;
    return STATUS_SUCCESS;
}

NTSTATUS KfProcessAllowLaunch(const KFILTER_ALLOW_LAUNCH_REQUEST* Request)
{
    ULONG seconds = Request->ArmSeconds == 0 ? 120 : Request->ArmSeconds;
    ULONG starts = Request->Starts == 0 ? 1 : Request->Starts;
    ULONG length = 0;
    while (length < KFILTER_MAX_NAME && Request->CreatorName[length] != L'\0') length++;
    if (length == 0 || length == KFILTER_MAX_NAME) return STATUS_INVALID_PARAMETER;
    if (seconds > 600) seconds = 600;
    if (starts > kAllowMaxStarts) return STATUS_INVALID_PARAMETER;
    {
        std::lock_guard<std::mutex> guard(gAllowLock);
        gAllowCreator.assign(Request->CreatorName, length);
        gAllowLeft = starts;
        gAllowUntil = NowMonotonic() + (uint64_t)seconds * 1000000000ull;
    }
    KfBpfAllowLaunch(std::wstring(Request->CreatorName, length), starts, seconds);
    KfPolicyResetCounts();
    KfBpfResetCounts();
    return STATUS_SUCCESS;
}

/*
 * The launch handshake. On Windows the child is created suspended with its image
 * already mapped, so ADMIT can check the image. On Linux the forked child still runs
 * kfilterctl until it execs, so ADMIT is only accepted from the registered launcher for
 * its own child, and the image is checked at the child's first exec instead.
 */
NTSTATUS KfProcessAdmit(const KFILTER_ADMIT_REQUEST* Request)
{
    if (Request == NULL || Request->ProcessId == 0) return STATUS_INVALID_PARAMETER;
    if (Request->ImagePath[0] == L'\0') return STATUS_INVALID_PARAMETER;
    if (Request->Generation != 0 && Request->Generation != KfPolicyGeneration()) return STATUS_REVISION_MISMATCH;
    if (Request->SidLength != 0) return STATUS_INVALID_SID;
    if (!CurrentIsLauncher()) return STATUS_ACCESS_DENIED;
    KfTask child;
    if (!KfReadTask((pid_t)Request->ProcessId, child) || child.tgid != (pid_t)Request->ProcessId) {
        return STATUS_INVALID_CID;
    }
    if (child.ppid != tCurrentPid) return STATUS_ACCESS_DENIED;
    std::wstring image(Request->ImagePath, KfLengthBounded(Request->ImagePath, KFILTER_MAX_NAME));
    if (!AdmitsImage(image, Request->ImagePath, Request->Flags)) return STATUS_ACCESS_DENIED;
    Entry entry;
    entry.start = child.start;
    entry.since = child.start;
    entry.generation = KfPolicyGeneration();
    entry.image = image;
    entry.expect = image;
    std::lock_guard<std::mutex> guard(gLock);
    NTSTATUS status = AddLocked(child.tgid, entry);
    /* The kernel checks the handshake image at the child's exec. */
    if (NT_SUCCESS(status) || status == STATUS_ALREADY_REGISTERED) KfBpfProtect(child.tgid, image);
    return status == STATUS_ALREADY_REGISTERED ? STATUS_SUCCESS : status;
}

} // extern "C"

void KfProcessMirror(pid_t tgid, bool add)
{
    std::lock_guard<std::mutex> guard(gLock);
    if (!add) {
        gTracked.erase(tgid);
        if (tgid == gLauncherPid) gLauncherPid = 0;
        return;
    }
    Entry entry;
    entry.start = KfStartTime(tgid);
    if (entry.start == 0) return;
    entry.since = entry.start;
    entry.generation = KfPolicyGeneration();
    entry.image = KfExePath(tgid);
    (void)AddLocked(tgid, entry);
}

void KfSetCurrentProcess(pid_t tgid, bool isProtected)
{
    tCurrentPid = tgid;
    tCurrentProtected = isProtected;
}

extern "C" HANDLE PsGetCurrentProcessId(void)
{
    return UlongToHandle((ULONG)tCurrentPid);
}
