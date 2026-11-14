// Static network rules for kfilterd (the Linux side of driver/network.c).
//
// The policy's network rules become one nftables table, `inet kfilter`, whose base
// chains only look at sockets of processes in the launch cgroup (KFILTER_CGROUP_ROOT,
// see `kfilterctl launch`), or of one UID when cgroup matching is unavailable. New
// outgoing connections take the connect rules, new incoming ones the listen rules,
// first match wins. A counted allow (uses=N) admits N connections per policy load
// through a dynamic set of that size. Audit mode logs and accepts what block mode
// rejects. Named counters feed `kfilterctl status`.

#include "kf_linux.h"

#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>

extern uid_t gKfNetworkUid;   // kfilterd.cpp: --net-uid, the fallback match

namespace {

bool gCgroupMatch = false;
bool gUidMatch = false;
bool gInstalled = false;   // only a table kfilterd loaded is removed

/* Run nft with Script on stdin; Output receives stdout. Returns its exit status. */
int RunNft(const std::string& script, const char* const* arguments, std::string* output)
{
    int input[2];
    int result[2];
    if (pipe(input) != 0) return -1;
    if (pipe(result) != 0) {
        close(input[0]);
        close(input[1]);
        return -1;
    }
    pid_t child = fork();
    if (child < 0) return -1;
    if (child == 0) {
        dup2(input[0], 0);
        dup2(result[1], 1);
        close(input[1]);
        close(result[0]);
        execv("/usr/sbin/nft", (char* const*)arguments);
        _exit(127);
    }
    close(input[0]);
    close(result[1]);
    size_t written = 0;
    while (written < script.size()) {
        ssize_t count = write(input[1], script.data() + written, script.size() - written);
        if (count <= 0) break;
        written += (size_t)count;
    }
    close(input[1]);
    char buffer[4096];
    ssize_t count;
    while ((count = read(result[0], buffer, sizeof(buffer))) > 0) {
        if (output != nullptr) output->append(buffer, (size_t)count);
    }
    close(result[0]);
    int status = 0;
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

int LoadNft(const std::string& script, bool checkOnly)
{
    static const char* const apply[] = { "nft", "-f", "-", nullptr };
    static const char* const check[] = { "nft", "-c", "-f", "-", nullptr };
    return RunNft(script, checkOnly ? check : apply, nullptr);
}

std::string Selector()
{
    if (gCgroupMatch) return "socket cgroupv2 level 1 \"kfilter\"";
    return "meta skuid " + std::to_string(gKfNetworkUid);
}

std::string AddressText(const KFILTER_NET_RULE& rule)
{
    char text[INET6_ADDRSTRLEN];
    if (inet_ntop(rule.Family == 4 ? AF_INET : AF_INET6, rule.Address, text, sizeof(text)) == nullptr) return {};
    return std::string(text) + "/" + std::to_string(rule.PrefixLength);
}

std::string Verdict(ULONG action, ULONG mode, ULONG ruleId)
{
    std::string id = std::to_string(ruleId);
    if (action == KFilterActionAllow) return "counter name \"kf_allow\" accept";
    if (action == KFilterActionAudit) return "counter name \"kf_allow\" log prefix \"kfilter audit rule=" + id + " \" accept";
    if (mode == KFILTER_MODE_BLOCK) return "counter name \"kf_deny\" log prefix \"kfilter deny rule=" + id + " \" reject";
    return "counter name \"kf_would_deny\" log prefix \"kfilter would-deny rule=" + id + " \" accept";
}

/* One rule as an nft rule for the connect (remote = destination) or listen (remote =
 * source of the incoming connection) direction. */
std::string RuleText(const KFILTER_NET_RULE& rule, bool listen, ULONG mode)
{
    std::string text = rule.Family == 4 ? "ip " : "ip6 ";
    text += listen ? "saddr " : "daddr ";
    text += AddressText(rule) + " ";
    if (rule.Protocol == 6) text += "meta l4proto tcp ";
    else if (rule.Protocol == 17) text += "meta l4proto udp ";
    if (rule.Port != 0) {
        if (rule.Protocol == 0) text += "meta l4proto { tcp, udp } ";
        text += std::string("th ") + (listen ? "sport " : "dport ") + std::to_string(rule.Port) + " ";
    }
    ULONG uses = (rule.Count & KFILTER_COUNT_USES) >> KFILTER_COUNT_USES_SHIFT;
    if (rule.Action == KFilterActionAllow && uses != 0) {
        text += "add @kf_uses_" + std::to_string(rule.RuleId) + (listen ? "_in" : "_out") + " { ct id } ";
    }
    return text + Verdict(rule.Action, mode, rule.RuleId);
}

std::string Table(const KFILTER_CONFIG* config, bool probe)
{
    std::string script = "table inet kfilter\ndelete table inet kfilter\ntable inet kfilter {\n";
    script += "  counter kf_allow {}\n  counter kf_deny {}\n  counter kf_would_deny {}\n";
    if (!probe) {
        for (ULONG index = 0; index < config->NetworkRuleCount; index++) {
            const KFILTER_NET_RULE& rule = config->Network[index];
            ULONG uses = (rule.Count & KFILTER_COUNT_USES) >> KFILTER_COUNT_USES_SHIFT;
            if (rule.Action != KFilterActionAllow || uses == 0 || (rule.Rights & KFILTER_RIGHTS_MESSAGE) != 0) continue;
            for (const char* direction : { "_out", "_in" }) {
                script += "  set kf_uses_" + std::to_string(rule.RuleId) + direction +
                          " { typeof ct id; size " + std::to_string(uses) + "; flags dynamic; }\n";
            }
        }
    }
    script += "  chain output { type filter hook output priority 0; policy accept; " + Selector() +
              " ct state new jump kf_connect; }\n";
    script += "  chain input { type filter hook input priority 0; policy accept; " + Selector() +
              " ct state new jump kf_listen; }\n";
    for (int listen = 0; listen < 2; listen++) {
        script += listen ? "  chain kf_listen {\n" : "  chain kf_connect {\n";
        if (!probe) {
            if ((config->Flags & KFILTER_CFG_NET_ALLOW_LOOPBACK) != 0) {
                script += listen ? "    iifname \"lo\" accept\n" : "    oifname \"lo\" accept\n";
            }
            ULONG right = listen ? KFILTER_RIGHT_LISTEN : KFILTER_RIGHT_CONNECT;
            for (ULONG index = 0; index < config->NetworkRuleCount; index++) {
                const KFILTER_NET_RULE& rule = config->Network[index];
                if (rule.Rights != 0 && (rule.Rights & right) == 0) continue;
                script += "    " + RuleText(rule, listen != 0, config->Mode) + "\n";
            }
            ULONG fallback = (config->Flags & KFILTER_CFG_NET_DEFAULT_ALLOW) != 0 ? KFilterActionAllow : KFilterActionDeny;
            script += "    " + Verdict(fallback, config->Mode, 0) + "\n";
        }
        script += "  }\n";
    }
    return script + "}\n";
}

} // namespace

bool KfNetworkProbe()
{
    if (access("/usr/sbin/nft", X_OK) != 0) return false;
    mkdir(KFILTER_CGROUP_ROOT, 0755);
    gCgroupMatch = true;
    // A table left by a kfilterd that did not stop cleanly would keep filtering.
    static const char* stale = "table inet kfilter\ndelete table inet kfilter\n";
    if (LoadNft(Table(nullptr, true), true) == 0) return LoadNft(stale, false) == 0;
    gCgroupMatch = false;
    if (gKfNetworkUid == (uid_t)-1) {
        fprintf(stderr, "kfilterd: nftables cannot match " KFILTER_CGROUP_ROOT
                        " and no --net-uid was given; network layer unavailable\n");
        return false;
    }
    gUidMatch = LoadNft(Table(nullptr, true), true) == 0 && LoadNft(stale, false) == 0;
    if (gUidMatch) fprintf(stderr, "kfilterd: network rules match uid %u instead of the launch cgroup\n", gKfNetworkUid);
    return gUidMatch;
}

void KfNetworkRemove()
{
    if (!gInstalled) return;
    if (LoadNft("table inet kfilter\ndelete table inet kfilter\n", false) == 0) gInstalled = false;
}

NTSTATUS KfNetworkApply(const KFILTER_CONFIG* config)
{
    /* The BPF layer's socket hooks decide network rules; no table is needed. */
    if (KfBpfActive() || config->Mode == KFILTER_MODE_OFF || (config->Flags & KFILTER_CFG_BLOCK_NETWORK) == 0) {
        KfNetworkRemove();
        return STATUS_SUCCESS;
    }
    if ((gKfRegisteredMask & KFILTER_REG_NETWORK) == 0) return STATUS_DEVICE_NOT_READY;
    for (ULONG index = 0; index < config->NetworkRuleCount; index++) {
        // Phases open on other layers' decisions, which a static table cannot follow.
        // Refuse rather than treat a later-phase allow as open.
        // Message rules are the BPF layer's alone; nftables never sees them.
        if ((config->Network[index].Rights & KFILTER_RIGHTS_MESSAGE) != 0) continue;
        if ((config->Network[index].Count & KFILTER_COUNT_PHASE) > 1) return STATUS_NOT_SUPPORTED;
    }
    std::string script = Table(config, false);
    if (LoadNft(script, false) != 0) {
        fprintf(stderr, "kfilterd: nft rejected the network table:\n%s", script.c_str());
        return STATUS_UNSUCCESSFUL;
    }
    gInstalled = true;
    return STATUS_SUCCESS;
}

void KfNetworkCounters(KFILTER_STATUS* status)
{
    static const char* const list[] = { "nft", "list", "counters", "table", "inet", "kfilter", nullptr };
    std::string output;
    if (KfBpfActive() || (gKfRegisteredMask & KFILTER_REG_NETWORK) == 0 || RunNft("", list, &output) != 0) return;
    struct { const char* name; KF_ULONG* field; } counters[] = {
        { "counter kf_allow", &status->Allowed },
        { "counter kf_deny", &status->Denied },
        { "counter kf_would_deny", &status->WouldDeny },
    };
    for (const auto& counter : counters) {
        size_t position = output.find(counter.name);
        if (position == std::string::npos) continue;
        position = output.find("packets ", position);
        if (position == std::string::npos) continue;
        KF_ULONG packets = (KF_ULONG)strtoul(output.c_str() + position + 8, nullptr, 10);
        *counter.field += packets;
        if (counter.field == &status->WouldDeny) status->Audited += packets;
    }
}
