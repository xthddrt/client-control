// kfilterd - the Linux counterpart of kfilter.sys.
//
// It holds the policy in driver/policy.c and the decision ring in driver/events.c,
// decides fanotify permission events (fanotify.cpp), follows processes through the
// proc connector (procs.cpp) and installs static network rules as nftables
// (net.cpp). kfilterctl and msmon-agent talk to it over a root-only Unix socket
// that carries the same requests and structs as the Windows IOCTLs
// (kfilter_socket.h).

#include "kf_linux.h"
#include "kfilter_socket.h"

#include <sys/random.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <poll.h>
#include <signal.h>
#include <unistd.h>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <map>
#include <memory>
#include <vector>

uint32_t gKfRegisteredMask = 0;
uid_t gKfNetworkUid = (uid_t)-1;

/* bpf_loader.cpp (kf-bpf). KfBpfPin pins the attached links and their maps in bpffs so the
 * layer keeps enforcing after kfilterd exits (idempotent); KfBpfUnpin removes the pins.
 * KfBpfDegraded: the KFILTER_STATUS_DEGRADED_* classes whose programs did not attach. Weak:
 * a build without them refuses block mode on the BPF layer instead of failing open. */
bool KfBpfPin() __attribute__((weak));
void KfBpfUnpin() __attribute__((weak));
uint32_t KfBpfDegraded() __attribute__((weak));

bool KfMessagesUnenforced(const KFILTER_CONFIG* config, uint32_t degraded)
{
    // REG_BPF also stands for the layers that did attach: take only these classes' reasons.
    const uint32_t classes = KFILTER_STATUS_DEGRADED_MESSAGE | KFILTER_STATUS_DEGRADED_QUERY | KFILTER_STATUS_DEGRADED_SYSTEM;
    // A Windows program (a '\' protect name) may run under the Wine install kfilter cannot decode.
    bool windows = false;
    for (ULONG index = 0; index < config->ProtectedCount && index < KFILTER_MAX_PROTECTED; index++) {
        windows |= config->Protected[index][0] == L'\\';
    }
    return config->Mode == KFILTER_MODE_BLOCK &&
           ((degraded & classes & KfPolicyUnenforced(config, gKfRegisteredMask & ~KFILTER_REG_BPF, nullptr)) != 0 ||
            ((degraded & KFILTER_STATUS_DEGRADED_WINE) != 0 && windows));
}

namespace {

/* Not a Linux NTSTATUS in posix_shim.h; the reply is EBUSY. */
#define KF_STATUS_DEVICE_BUSY ((NTSTATUS)0x80000011)

uint64_t gSessionTag = 0;
/* The monitor session that alone reads the decision ring (KFILTER_SESSION_OWN_EVENTS). */
pid_t gRingOwner = 0;
uint64_t gRingOwnerStart = 0;
bool gPinned = false;          // the BPF links outlive kfilterd
uint32_t gUnenforced = 0;      // KfPolicyUnenforced of the live policy
bool gStop = false;            // KFILTER_OP_SHUTDOWN was served
/* The block-mode policy a restarted kfilterd adopts; empty in the unit test. */
std::string gSavedPolicy;

int ErrnoFor(NTSTATUS status)
{
    switch (status) {
    case STATUS_SUCCESS: return 0;
    case STATUS_NOT_FOUND: return ENOENT;                  // kfilterctl: ERROR_NOT_FOUND
    case STATUS_INVALID_PARAMETER: return EINVAL;          // ERROR_INVALID_PARAMETER
    case STATUS_INVALID_CID: return ESRCH;                 // ERROR_INVALID_HANDLE
    case STATUS_ACCESS_DENIED: return EACCES;
    case STATUS_BUFFER_TOO_SMALL: return ENOBUFS;
    case STATUS_REVISION_MISMATCH: return EPROTO;
    case STATUS_DEVICE_NOT_READY: return ENODEV;
    case STATUS_INSUFFICIENT_RESOURCES: return ENOMEM;
    case STATUS_INVALID_SID: return EPERM;
    case STATUS_OBJECT_NAME_INVALID: return ENOEXEC;
    case STATUS_NOT_SUPPORTED: return EOPNOTSUPP;
    case STATUS_INVALID_DEVICE_REQUEST: return ENOTTY;
    case KF_STATUS_DEVICE_BUSY: return EBUSY;
    default: return EIO;
    }
}

/* The live generation, so a failed network install can be rolled back to it. */
std::unique_ptr<char[]> CopyConfig(ULONG& size)
{
    size = KfPolicyGetConfig(nullptr, 0);
    std::unique_ptr<char[]> copy(new char[size]());
    KfPolicyGetConfig((PKFILTER_CONFIG)copy.get(), size);
    return copy;
}

/*
 * Fail closed: block mode outlives kfilterd. The BPF links are pinned and the policy is saved
 * for a restarted kfilterd to adopt (the nftables table of the fallback stays too). Any other
 * mode lets go of both, so only an explicit off or stop ends enforcement.
 */
NTSTATUS KeepAcrossExit(const KFILTER_CONFIG* config, ULONG length)
{
    if (config->Mode != KFILTER_MODE_BLOCK) {
        // Also pins a previous kfilterd left (adopted at start): idempotent.
        if (KfBpfUnpin != nullptr) KfBpfUnpin();
        gPinned = false;
        if (!gSavedPolicy.empty()) unlink(gSavedPolicy.c_str());
        return STATUS_SUCCESS;
    }
    if (KfBpfActive()) {
        if (KfBpfPin == nullptr || !KfBpfPin()) {
            fprintf(stderr, "kfilterd: block mode refused: the BPF layer cannot be pinned, so it would end with kfilterd\n");
            return STATUS_NOT_SUPPORTED;
        }
        gPinned = true;
    } else {
        fprintf(stderr, "kfilterd: warning: without the BPF layer, file and process enforcement ends when kfilterd exits\n");
    }
    if (!gSavedPolicy.empty()) {
        std::string temporary = gSavedPolicy + ".new";
        std::ofstream file(temporary, std::ios::binary | std::ios::trunc);
        file.write((const char*)config, length);
        file.close();
        if (!file || rename(temporary.c_str(), gSavedPolicy.c_str()) != 0) {
            fprintf(stderr, "kfilterd: warning: cannot save the policy to %s; a restart will not adopt it\n",
                    gSavedPolicy.c_str());
        }
    }
    return STATUS_SUCCESS;
}

NTSTATUS SetConfig(const KFILTER_CONFIG* config, ULONG length)
{
    ULONG previousSize = 0;
    std::unique_ptr<char[]> previous = CopyConfig(previousSize);
    NTSTATUS status = KfPolicySetConfig(config, length);
    if (!NT_SUCCESS(status)) return status;
    /* The BPF layer holds its own compiled copy; one it cannot hold is refused like nft, and
     * so are rules its missing hooks or uprobes (attached by KfBpfApply) would not decide. */
    status = KfBpfApply(config);
    if (NT_SUCCESS(status) && KfBpfActive() && KfBpfDegraded != nullptr && KfMessagesUnenforced(config, KfBpfDegraded())) {
        fprintf(stderr, "kfilterd: block mode refused: the BPF layer is degraded (0x%x) for rules this policy has\n",
                KfBpfDegraded());
        status = STATUS_NOT_SUPPORTED;
    }
    if (NT_SUCCESS(status)) status = KfNetworkApply(config);
    if (NT_SUCCESS(status)) status = KeepAcrossExit(config, length);
    if (!NT_SUCCESS(status)) {
        // A published policy whose network table is missing would claim more than it
        // enforces: go back to the previous generation.
        auto* old = (const KFILTER_CONFIG*)previous.get();
        if (NT_SUCCESS(KfPolicySetConfig(old, previousSize))) {
            (void)KfBpfApply(old);
            (void)KfNetworkApply(old);
            (void)KeepAcrossExit(old, previousSize);
        }
        return status;
    }
    /* Block mode refused these in KfPolicySetConfig; audit mode loads them and says so. */
    ULONG rule = 0;
    gUnenforced = KfPolicyUnenforced(config, gKfRegisteredMask, &rule);
    if (gUnenforced != 0) {
        fprintf(stderr, "kfilterd: warning: policy generation %u has rules no active layer enforces "
                        "(degraded 0x%x, first rule %u); they are not decided\n",
                (unsigned)KfPolicyGeneration(), gUnenforced, (unsigned)rule);
    }
    return status;
}

/* Status classes whose layer is missing although the policy turns them on. */
uint32_t LayerGaps(ULONG flags)
{
    static const struct { ULONG flag; uint32_t layer; uint32_t degraded; } layers[] = {
        { KFILTER_CFG_BLOCK_FILES, KFILTER_REG_MINIFILTER, KFILTER_STATUS_DEGRADED_FILES },
        { KFILTER_CFG_BLOCK_REGISTRY, KFILTER_REG_REGISTRY, KFILTER_STATUS_DEGRADED_REGISTRY },
        { KFILTER_CFG_BLOCK_PROCESS_MEMORY, KFILTER_REG_OBJECT, KFILTER_STATUS_DEGRADED_MEMORY },
        { KFILTER_CFG_BLOCK_PROCESS_SIGNALS, KFILTER_REG_OBJECT, KFILTER_STATUS_DEGRADED_MEMORY },
        { KFILTER_CFG_BLOCK_PROCESS_QUERIES, KFILTER_REG_OBJECT, KFILTER_STATUS_DEGRADED_MEMORY },
        { KFILTER_CFG_BLOCK_PROCESS_CREATE, KFILTER_REG_PROCESS, KFILTER_STATUS_DEGRADED_PROCESS },
        { KFILTER_CFG_BLOCK_RAW_DISK, KFILTER_REG_DISK, KFILTER_STATUS_DEGRADED_RAW_DISK },
        { KFILTER_CFG_BLOCK_NETWORK, KFILTER_REG_NETWORK, KFILTER_STATUS_DEGRADED_NETWORK },
        { KFILTER_CFG_BLOCK_VOLUME_SERIAL, KFILTER_REG_BPF, KFILTER_STATUS_DEGRADED_VOLUME },
        { KFILTER_CFG_BLOCK_NETWORK_ADAPTER, KFILTER_REG_NSI, KFILTER_STATUS_DEGRADED_ADAPTER },
    };
    uint32_t degraded = (gKfRegisteredMask & KFILTER_REG_DEVICE) == 0 ? KFILTER_STATUS_DEGRADED_DEVICE : 0;
    for (const auto& layer : layers) {
        if ((flags & layer.flag) != 0 && (gKfRegisteredMask & layer.layer) == 0) degraded |= layer.degraded;
    }
    return degraded;
}

/* Another live process owns the decision ring; a dead owner's claim lapses. */
bool RingOwnedByOther(pid_t peer)
{
    if (gRingOwner == 0 || gRingOwner == peer) return false;
    if (KfStartTime(gRingOwner) == gRingOwnerStart) return true;
    gRingOwner = 0;
    return false;
}

/* One request, as main.c's KfDeviceControl handles the matching IOCTL. */
NTSTATUS Dispatch(uint32_t code, const std::vector<char>& input, uint32_t capacity, std::vector<char>& output,
                  pid_t peer)
{
    switch (code) {
    case KFILTER_OP_GET_STATUS: {
        if (capacity < sizeof(KFILTER_STATUS)) return STATUS_BUFFER_TOO_SMALL;
        KFILTER_STATUS status;
        KfPolicyGetStatus(&status);
        status.Registered = gKfRegisteredMask;
        status.SessionTag = gSessionTag;
        status.DroppedEvents += KfBpfDropped();
        if (status.Mode != KFILTER_MODE_OFF) {
            status.Degraded |= LayerGaps(status.Flags) | gUnenforced;
            if (KfBpfActive() && KfBpfDegraded != nullptr) status.Degraded |= KfBpfDegraded();
        }
        if (status.Mode == KFILTER_MODE_BLOCK && !gPinned) status.Degraded |= KFILTER_STATUS_FAIL_OPEN;
        KfNetworkCounters(&status);
        output.assign((char*)&status, (char*)&status + sizeof(status));
        return STATUS_SUCCESS;
    }
    case KFILTER_OP_SET_CONFIG:
        if (input.size() < KFILTER_CONFIG_SIZE(0)) return STATUS_BUFFER_TOO_SMALL;
        return SetConfig((const KFILTER_CONFIG*)input.data(), (ULONG)input.size());
    case KFILTER_OP_GET_CONFIG: {
        ULONG size = KfPolicyGetConfig(nullptr, 0);
        if (size > capacity) return STATUS_BUFFER_TOO_SMALL;
        output.assign(size, 0);
        if (KfPolicyGetConfig((PKFILTER_CONFIG)output.data(), size) > size) return STATUS_BUFFER_TOO_SMALL;
        return STATUS_SUCCESS;
    }
    case KFILTER_OP_READ_EVENTS: {
        // Reads take events off the ring: while msmon owns it, nobody else may.
        if (RingOwnedByOther(peer)) return KF_STATUS_DEVICE_BUSY;
        ULONG maximum = capacity / sizeof(KFILTER_EVENT);
        if (maximum == 0) return STATUS_BUFFER_TOO_SMALL;
        if (maximum > KFILTER_RING_CAPACITY) maximum = KFILTER_RING_CAPACITY;
        if (input.size() >= sizeof(KFILTER_READ_REQUEST)) {
            KFILTER_READ_REQUEST request;
            memcpy(&request, input.data(), sizeof(request));
            if (request.MaximumEvents != 0 && request.MaximumEvents < maximum) maximum = request.MaximumEvents;
        }
        output.assign((size_t)maximum * sizeof(KFILTER_EVENT), 0);
        ULONG count = KfReadEvents((PKFILTER_EVENT)output.data(), maximum);
        output.resize((size_t)count * sizeof(KFILTER_EVENT));
        return STATUS_SUCCESS;
    }
    case KFILTER_OP_CLEAR_EVENTS:
        if (RingOwnedByOther(peer)) return KF_STATUS_DEVICE_BUSY;
        KfClearEvents();
        return STATUS_SUCCESS;
    case KFILTER_OP_TRACK_PID: {
        if (input.size() < sizeof(KFILTER_TRACK_REQUEST)) return STATUS_BUFFER_TOO_SMALL;
        KFILTER_TRACK_REQUEST request;
        memcpy(&request, input.data(), sizeof(request));
        return KfProcessTrack(UlongToHandle(request.ProcessId));
    }
    case KFILTER_OP_ADMIT_PROCESS: {
        if (input.size() < sizeof(KFILTER_ADMIT_REQUEST)) return STATUS_BUFFER_TOO_SMALL;
        std::unique_ptr<KFILTER_ADMIT_REQUEST> request(new KFILTER_ADMIT_REQUEST());
        memcpy(request.get(), input.data(), sizeof(*request));
        request->ImagePath[KFILTER_MAX_NAME - 1] = L'\0';
        return KfProcessAdmit(request.get());
    }
    case KFILTER_OP_REGISTER_LAUNCHER:
        return KfProcessRegisterLauncher();
    case KFILTER_OP_ALLOW_LAUNCH: {
        if (input.size() < sizeof(KFILTER_ALLOW_LAUNCH_REQUEST)) return STATUS_BUFFER_TOO_SMALL;
        std::unique_ptr<KFILTER_ALLOW_LAUNCH_REQUEST> request(new KFILTER_ALLOW_LAUNCH_REQUEST());
        memcpy(request.get(), input.data(), sizeof(*request));
        NTSTATUS status = KfProcessAllowLaunch(request.get());
        if (NT_SUCCESS(status)) {
            // Restoring the counted rules includes the network uses held in nft sets.
            ULONG size = 0;
            std::unique_ptr<char[]> config = CopyConfig(size);
            (void)KfNetworkApply((const KFILTER_CONFIG*)config.get());
        }
        return status;
    }
    case KFILTER_OP_CLEAR_TRACKING:
        KfProcessClearTracking();
        return STATUS_SUCCESS;
    case KFILTER_OP_BLOCK_CONNECTION: {
        if (input.size() < sizeof(KFILTER_CONNECTION_REQUEST)) return STATUS_BUFFER_TOO_SMALL;
        KFILTER_CONNECTION_REQUEST request;
        memcpy(&request, input.data(), sizeof(request));
        if (request.SocketInode == 0 || (request.Directions & ~KFILTER_RIGHTS_MESSAGE) != 0) return STATUS_INVALID_PARAMETER;
        // Only the BPF layer sees each send and receive.
        if (!KfBpfActive()) return STATUS_DEVICE_NOT_READY;
        return KfBpfBlockConnection(request.SocketInode, request.Directions);
    }
    case KFILTER_OP_SET_SESSION: {
        if (input.size() < sizeof(KFILTER_SESSION_REQUEST)) return STATUS_BUFFER_TOO_SMALL;
        KFILTER_SESSION_REQUEST request;
        memcpy(&request, input.data(), sizeof(request));
        if ((request.Flags & ~KFILTER_SESSION_OWN_EVENTS) != 0) return STATUS_INVALID_PARAMETER;
        if ((request.Flags & KFILTER_SESSION_OWN_EVENTS) != 0) {
            if (RingOwnedByOther(peer)) return KF_STATUS_DEVICE_BUSY;
            uint64_t start = KfStartTime(peer);
            if (start == 0) return STATUS_INVALID_CID;
            gRingOwner = peer;
            gRingOwnerStart = start;
        } else if (gRingOwner == peer) {
            gRingOwner = 0;
        }
        if (request.SessionTag != 0) gSessionTag = request.SessionTag;
        return STATUS_SUCCESS;
    }
    case KFILTER_OP_SHUTDOWN: {
        // Off first: that unpins the BPF links, drops the saved policy and the nft table.
        ULONG size = 0;
        std::unique_ptr<char[]> config = CopyConfig(size);
        ((KFILTER_CONFIG*)config.get())->Mode = KFILTER_MODE_OFF;
        NTSTATUS status = SetConfig((const KFILTER_CONFIG*)config.get(), size);
        if (NT_SUCCESS(status)) gStop = true;
        return status;
    }
    default:
        return STATUS_INVALID_DEVICE_REQUEST;
    }
}

bool ReadAll(int fd, void* buffer, size_t length)
{
    char* cursor = (char*)buffer;
    while (length != 0) {
        ssize_t count = read(fd, cursor, length);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        cursor += count;
        length -= (size_t)count;
    }
    return true;
}

bool WriteAll(int fd, const void* buffer, size_t length)
{
    const char* cursor = (const char*)buffer;
    while (length != 0) {
        ssize_t count = send(fd, cursor, length, MSG_NOSIGNAL);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        cursor += count;
        length -= (size_t)count;
    }
    return true;
}

} // namespace

bool KfServe(int client, pid_t peer)
{
    KFILTER_SOCKET_REQUEST request;
    if (!ReadAll(client, &request, sizeof(request))) return false;
    if (request.InputLength > KFILTER_SOCKET_MAX_INPUT) return false;
    std::vector<char> input(request.InputLength);
    if (request.InputLength != 0 && !ReadAll(client, input.data(), input.size())) return false;
    std::vector<char> output;
    // Launcher registration and admission refer to the caller, as the IOCTLs do.
    KfSetCurrentProcess(peer, false);
    NTSTATUS status = Dispatch(request.Code, input, request.OutputCapacity, output, peer);
    if (!NT_SUCCESS(status)) output.clear();
    KFILTER_SOCKET_REPLY reply;
    reply.Error = (uint32_t)ErrnoFor(status);
    reply.OutputLength = (uint32_t)output.size();
    return WriteAll(client, &reply, sizeof(reply)) &&
           (output.empty() || WriteAll(client, output.data(), output.size()));
}

#ifndef KFILTERD_NO_MAIN   /* tests/linux_daemon_test.cpp links the rest */
namespace {

int Listen()
{
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct sockaddr_un address {};
    address.sun_family = AF_UNIX;
    strncpy(address.sun_path, KFILTER_SOCKET_PATH, sizeof(address.sun_path) - 1);
    unlink(KFILTER_SOCKET_PATH);
    mode_t old = umask(0077);
    int result = bind(fd, (struct sockaddr*)&address, sizeof(address));
    umask(old);
    if (result != 0 || chmod(KFILTER_SOCKET_PATH, 0600) != 0 || listen(fd, 8) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* A kfilterd that exited in block mode (crash, kill, Restart=on-failure) left its pinned
 * links and this policy: take the policy back so status, off and stop see what the kernel
 * still enforces. */
void AdoptSavedPolicy()
{
    std::ifstream file(gSavedPolicy, std::ios::binary);
    if (!file) return;
    std::vector<char> saved((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    NTSTATUS status = saved.size() >= KFILTER_CONFIG_SIZE(0) && saved.size() <= sizeof(KFILTER_CONFIG)
                          ? SetConfig((const KFILTER_CONFIG*)saved.data(), (ULONG)saved.size())
                          : STATUS_INVALID_PARAMETER;
    if (NT_SUCCESS(status)) {
        fprintf(stderr, "kfilterd: adopted the block-mode policy a previous kfilterd left (%s)\n", gSavedPolicy.c_str());
    } else {
        // Kept: `kfilterctl off` or `kfilterctl stop` removes it with the pins.
        fprintf(stderr, "kfilterd: cannot adopt %s (0x%08x); pinned BPF links may still enforce it. "
                        "`kfilterctl stop` ends them\n", gSavedPolicy.c_str(), (unsigned)status);
    }
}

void Usage()
{
    fprintf(stderr, "Usage: kfilterd [--net-uid UID] [--no-bpf]\n"
                    "  --net-uid UID  match network rules on this uid when nftables cannot match\n"
                    "                 the launch cgroup " KFILTER_CGROUP_ROOT "\n"
                    "  --no-bpf       do not load the BPF LSM layer; use fanotify and nftables\n");
}

} // namespace

#endif

extern "C" {
ULONG KfDriverRegisteredMask(VOID) { return gKfRegisteredMask; }
/* Raw disks are inode marks taken at start; there is no attach to re-arm. */
BOOLEAN KfDiskDegraded(VOID) { return FALSE; }
NTSTATUS KfDiskRearm(VOID) { return STATUS_SUCCESS; }
BOOLEAN KfDeviceDegraded(VOID) { return FALSE; }
}

#ifndef KFILTERD_NO_MAIN
int main(int argc, char** argv)
{
    bool useBpf = true;
    for (int index = 1; index < argc; index++) {
        if (strcmp(argv[index], "--net-uid") == 0 && index + 1 < argc) {
            gKfNetworkUid = (uid_t)strtoul(argv[++index], nullptr, 10);
        } else if (strcmp(argv[index], "--no-bpf") == 0) {
            useBpf = false;
        } else {
            Usage();
            return 2;
        }
    }
    if (geteuid() != 0) {
        fprintf(stderr, "kfilterd: must run as root (fanotify permission events, proc connector, nftables)\n");
        return 1;
    }
    /* The BPF layer holds a descriptor per program (one per syscall entry point: about 900), past a shell's 1024. */
    struct rlimit files {};
    if (getrlimit(RLIMIT_NOFILE, &files) == 0 && files.rlim_cur < files.rlim_max) {
        files.rlim_cur = files.rlim_max;
        setrlimit(RLIMIT_NOFILE, &files);
    }
    // Blocked before any thread starts, so only the signalfd below sees them.
    sigset_t signals;
    sigemptyset(&signals);
    sigaddset(&signals, SIGTERM);
    sigaddset(&signals, SIGINT);
    sigaddset(&signals, SIGHUP);
    pthread_sigmask(SIG_BLOCK, &signals, nullptr);
    signal(SIGPIPE, SIG_IGN);

    if (getrandom(&gSessionTag, sizeof(gSessionTag), 0) != (ssize_t)sizeof(gSessionTag)) gSessionTag = (uint64_t)time(nullptr);
    if (!NT_SUCCESS(KfPolicyInitialize()) || !NT_SUCCESS(KfEventsInitialize())) return 1;
    /* The BPF layer decides every hook in the kernel; fanotify, the proc connector and
     * nftables remain the fallback when it cannot load (or with --no-bpf). */
    if (!useBpf || !KfBpfStart(gKfRegisteredMask)) {
        if (KfNetworkProbe()) gKfRegisteredMask |= KFILTER_REG_NETWORK;
        if (!KfFanotifyStart(gKfRegisteredMask)) return 1;
    }
    mkdir("/run/kfilter", 0700);
    gSavedPolicy = "/run/kfilter/policy";
    AdoptSavedPolicy();
    int listener = Listen();
    if (listener < 0) {
        perror("kfilterd: " KFILTER_SOCKET_PATH);
        return 1;
    }
    int quit = signalfd(-1, &signals, SFD_CLOEXEC);
    fprintf(stderr, "kfilterd: ready, layers 0x%x, socket " KFILTER_SOCKET_PATH "\n", gKfRegisteredMask);
    if (KfBpfActive() && KfBpfPin == nullptr) {
        fprintf(stderr, "kfilterd: this build cannot pin the BPF layer; block mode is refused\n");
    }

    std::map<int, pid_t> clients;
    for (;;) {
        std::vector<struct pollfd> fds = { { listener, POLLIN, 0 }, { quit, POLLIN, 0 } };
        for (const auto& client : clients) fds.push_back({ client.first, POLLIN, 0 });
        if (poll(fds.data(), fds.size(), -1) < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if ((fds[1].revents & POLLIN) != 0) break;
        if ((fds[0].revents & POLLIN) != 0) {
            int client = accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
            struct ucred peer {};
            socklen_t length = sizeof(peer);
            if (client >= 0 && getsockopt(client, SOL_SOCKET, SO_PEERCRED, &peer, &length) == 0 && peer.uid == 0) {
                clients[client] = peer.pid;
            } else if (client >= 0) {
                close(client);
            }
        }
        for (size_t index = 2; index < fds.size(); index++) {
            if (fds[index].revents == 0) continue;
            if ((fds[index].revents & POLLIN) == 0 || !KfServe(fds[index].fd, clients[fds[index].fd])) {
                close(fds[index].fd);
                clients.erase(fds[index].fd);
            }
        }
        if (gStop) break;
    }
    // Pending permission events are allowed by the kernel once the fanotify group closes.
    // Block mode keeps the pinned BPF links and the nftables table: only off or stop ends it.
    if (KfPolicyMode() != KFILTER_MODE_BLOCK) KfNetworkRemove();
    else fprintf(stderr, "kfilterd: exiting in block mode; pinned BPF links and the nftables table stay until `kfilterctl stop`\n");
    unlink(KFILTER_SOCKET_PATH);
    fprintf(stderr, "kfilterd: stopped\n");
    return 0;
}
#endif
