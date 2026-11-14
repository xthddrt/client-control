#pragma once

/* Internal interfaces of kfilterd, the Linux replacement for kfilter.sys. */

extern "C" {
#include "../driver/kf.h"
}
#include <sys/types.h>
#include <cstdint>
#include <map>
#include <string>

/* kfilterd.cpp */
/* Who policy.c/events.c decide and log for on this thread. */
void KfSetCurrentProcess(pid_t tgid, bool isProtected);
extern uint32_t gKfRegisteredMask;      /* KFILTER_REG_* layers that came up */
/* Block mode with message, dns, metadata-query or system rules that no hook decides, Degraded
 * holding their KFILTER_STATUS_DEGRADED_* class (a program or uprobe that did not attach), or
 * protecting a Windows program while a Wine install is not decoded (KFILTER_STATUS_DEGRADED_WINE). */
bool KfMessagesUnenforced(const KFILTER_CONFIG* config, uint32_t degraded);

/* procs.cpp: identity of the task behind a fanotify event or a socket peer. */
struct KfTask {
    pid_t tid = 0;
    pid_t tgid = 0;
    pid_t ppid = 0;
    uint64_t start = 0;   /* /proc/<tgid>/stat starttime, clock ticks since boot */
};
bool KfReadTask(pid_t tid, KfTask& task);
uint64_t KfStartTime(pid_t pid);               /* 0 when the process is gone */
std::wstring KfExePath(pid_t pid);             /* readlink /proc/<pid>/exe, empty on failure */
/* Whether Path names one of Wine's loaders (wine, wine64, wine-preloader, wine64-preloader). */
bool KfWineLoader(const std::wstring& path);
/* The program a process runs: under Wine its Windows image (argv[0], which Wine rewrites to
 * e.g. C:\Nexon\...\MapleStory.exe), otherwise its exe path. Empty when the process is gone. */
std::wstring KfProgramImage(pid_t pid);
std::wstring KfWide(const std::string& value);
std::string KfNarrow(const std::wstring& value);
/* Whether the task's process is protected, adopting it when its parent is and it was
 * forked after the parent was admitted (the proc connector may not have told us yet). */
bool KfTaskProtected(const KfTask& task);
/* FAN_OPEN_EXEC_PERM. Returns true to deny. Handles the launch handshake image check,
 * the process-create decision and the refusal of protected images started outside it. */
bool KfProcessExec(const KfTask& task, bool isProtected, const std::wstring& path);
int KfProcConnectorOpen();                     /* -1 when unavailable */
void KfProcConnectorDrain(int socket);

/* fanotify.cpp */
bool KfFanotifyStart(uint32_t& registered);    /* starts the decision thread */
/* Rights of the open the blocked thread Tid is making, from /proc/<tid>/syscall; 0 when
 * unknown. Exec is set for the open inside execve. */
ULONG KfOpenRights(pid_t tid, bool& exec);

/* procs.cpp: the BPF layer protected (Add) or saw exit (!Add) a process. */
void KfProcessMirror(pid_t tgid, bool add);

/* bpf_loader.cpp: the BPF LSM layer. KfBpfStart loads and attaches it (false: not
 * available, kfilterd uses fanotify and nftables); the rest are no-ops without it. */
bool KfBpfStart(uint32_t& registered);
bool KfBpfActive();
NTSTATUS KfBpfApply(const KFILTER_CONFIG* config);
void KfBpfResetCounts();
void KfBpfProtect(pid_t tgid, const std::wstring& expect);
void KfBpfUnprotect(pid_t tgid);
void KfBpfAllowLaunch(const std::wstring& creator, ULONG starts, ULONG seconds);
ULONG KfBpfDropped();
/* The target a decision on one of the kernel's own targets (KB_TARGET_ARGUMENT, KB_TARGET_SIGNAL) is logged as. */
uint32_t KfBpfPublicTarget(uint32_t target);
/* Refuse every send and/or receive on the connection with this socket inode (0: lift).
 * Fails (DEVICE_NOT_READY, NOT_SUPPORTED: not block mode with block-network, NOT_FOUND: no
 * protected program holds that socket or no such block) instead of doing nothing. */
NTSTATUS KfBpfBlockConnection(uint64_t socketInode, ULONG directions);
/* The Wine requests Config's system rules name past /system/wine/ (kb_wnamed), one bit each. */
void KfBpfWineNamed(const KFILTER_CONFIG* config, uint64_t named[]);
/* The wineserver protocol of an x86_64 ntdll.so's bytes (0: not found). */
unsigned KfWineProtocol(const std::string& file);
/* A system rule (Path narrowed) whose fixed text reaches into a keyed space, so it meets keyed decisions alone. */
bool KfBpfKeyedRule(const KFILTER_RULE& rule, const std::string& path);
/* The functions of a win32u.so or ntdll.so (its exports) Config's system rules name, with their kb_win32k cookie bits. */
std::map<std::string, uint64_t> KfBpfUprobeFunctions(const KFILTER_CONFIG* config, bool ntdll,
                                                     const std::map<std::string, uint64_t>& exports);
/* Wine's syscall dispatcher in an ntdll.so's bytes, as file offsets [start, end); false when not found. */
bool KfWineDispatcher(const std::string& file, uint64_t& start, uint64_t& end);
/* The target a kernel decision is logged as (the kernel's own targets: their public one). */
uint32_t KfBpfPublicTarget(uint32_t target);

/* kfilterd.cpp: one request on a client connection; false closes it. */
bool KfServe(int client, pid_t peer);

/* net.cpp: static network rules as an nftables table matched on the launch cgroup. */
bool KfNetworkProbe();
NTSTATUS KfNetworkApply(const KFILTER_CONFIG* config);
void KfNetworkCounters(KFILTER_STATUS* status);
void KfNetworkRemove();
#define KFILTER_CGROUP_ROOT "/sys/fs/cgroup/kfilter"
