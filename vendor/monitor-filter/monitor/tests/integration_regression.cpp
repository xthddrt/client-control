#include "../agent/integrations.h"
#include "../agent/classify.h"
#include "../agent/etw.h"
#include "../agent/rpc_names.h"
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <tuple>
#include <vector>

static bool Check(bool condition, const char* message)
{
    if (!condition) std::cerr << "FAIL: " << message << "\n";
    return condition;
}

int main()
{
    bool ok = true;
    ProcessScope processScope;
    processScope.AddProcess(41, 100, L"C:\\client.exe");
    ok &= Check(processScope.IsTracked(41, 100), "tracked PID accepts its process incarnation");
    ok &= Check(!processScope.IsTracked(41, 101), "tracked PID rejects a reused incarnation");
    ok &= Check(!processScope.IsTracked(42, 100), "unknown PID is not tracked");
    ok &= Check(processScope.Path(41, 100) == L"C:\\client.exe",
                "a process path is borrowed only for the exact incarnation");
    ok &= Check(processScope.Path(41, 0).empty() && processScope.Path(41, 101).empty(),
                "start-less and mismatched records cannot borrow a process path");
    processScope.AddProcess(41, 200, L"C:\\new-client.exe");
    ok &= Check(processScope.Path(41, 100).empty() && processScope.Path(41, 200) == L"C:\\new-client.exe",
                "a reused PID cannot lend its new path to the old incarnation");
    /* #76: the exit record was dropped, so 42@100 is still known when Windows
     * reuses the PID for an incarnation whose start carries no image name. */
    {
        ProcessScope reused;
        reused.AddProcess(42, 100, L"C:\\old.exe");
        reused.AddProcess(42, 200, L"");
        ok &= Check(reused.Path(42, 200).empty() && reused.Path(42, 100).empty(),
                    "an empty process-start text cannot inherit the old incarnation's path");
        reused.AddProcess(42, 200, L"C:\\new.exe");
        reused.AddProcess(42, 200, L"");
        ok &= Check(reused.Path(42, 200) == L"C:\\new.exe",
                    "a repeated start record keeps its own incarnation's path");
    }
    ok &= Check(ProcessScope::ValidParentIncarnation(100, 100, 100),
                "snapshot inheritance accepts the exact parent incarnation");
    ok &= Check(!ProcessScope::ValidParentIncarnation(100, 101, 100) &&
                !ProcessScope::ValidParentIncarnation(101, 101, 100) &&
                !ProcessScope::ValidParentIncarnation(100, 100, 99),
                "snapshot inheritance rejects reused, later, and older-parent identities");

    /* #55: an explicit track names the incarnation the caller resolved. */
    ok &= Check(MsMonTrackAdmitsStart(0, 123456), "an unspecified start admits the live process");
    ok &= Check(MsMonTrackAdmitsStart(100, 100), "the requested incarnation is admitted");
    ok &= Check(!MsMonTrackAdmitsStart(100, 101), "a reused PID is refused, not tracked");

    {
        ProcessScope early;
        const uint64_t address = 0x1000;
        early.AddImage(42, 100, address, 0x200, L"C:\\old.dll");
        early.AddProcess(42, 101, L"C:\\client.exe");
        ok &= Check(early.ResolveStack(42, &address, 1).empty(),
                    "early images do not cross into a reused process incarnation");
        early.AddImage(42, 100, address, 0x200, L"C:\\client.dll");
        early.AddProcess(42, 100, L"C:\\client.exe");
        auto modules = early.ResolveStack(42, &address, 1);
        ok &= Check(modules.size() == 1 && modules[0] == L"C:\\client.dll",
                    "early images merge for the captured incarnation");
        early.AddImage(43, 100, address, 0x200, L"C:\\old.dll");
        early.RemoveProcess(43, 100);
        early.AddProcess(43, 100, L"C:\\client.exe");
        ok &= Check(early.ResolveStack(43, &address, 1).empty(),
                    "process exit discards unmatched early images");
    }

    /*
     * A deferred ETW event belongs to the incarnation it was captured for: a
     * reused PID must not release it, and an unknown identity never does.
     */
    {
        EventQueue queue;
        ProcessScope scope;
        EtwCollector collector(scope, queue, 1, true, {});
        TelemetryEvent deferred;
        deferred.source = "etw";
        deferred.header.Size = sizeof(deferred.header);
        deferred.header.Version = MSMON_PROTOCOL_VERSION;
        deferred.header.Type = MsMonEtwWmi;
        deferred.header.ProcessId = 42;
        collector.Defer(TelemetryEvent(deferred), 100);
        scope.AddProcess(42, 101, L"C:\\client.exe");
        ok &= Check(collector.ReplayProcess(42) == 0,
                    "a reused PID does not release another incarnation's deferred event");
        ok &= Check(collector.PendingCount() == 1, "the mismatched event stays pending to expire");
        scope.AddProcess(42, 100, L"C:\\client.exe");
        ok &= Check(collector.ReplayProcess(42) == 1, "the deferred event is released for its incarnation");
        ok &= Check(collector.PendingCount() == 0, "a released event leaves the pending queue");
        std::vector<TelemetryEvent> emitted;
        ok &= Check(queue.Drain(emitted, 1) == 1 && emitted[0].header.ProcessStartTime == 100,
                    "a replayed event keeps its captured incarnation");
        collector.Defer(TelemetryEvent(deferred), 0);
        ok &= Check(collector.ReplayProcess(42) == 0, "an event with no known identity never replays");
        ok &= Check(collector.PendingCount() == 1, "an unidentified event is left to expire");
    }

    /*
     * TCP attribution: a connection's cached owner is only usable while that
     * exact incarnation is tracked; a reused PID is not the old owner.
     */
    {
        EventQueue queue;
        ProcessScope scope;
        EtwCollector collector(scope, queue, 1, true, {});
        scope.AddProcess(42, 100, L"C:\\client.exe");
        ok &= Check(!collector.RememberTcpOwner(9, 42, 101, L"192.0.2.1:443"),
                    "a stale incarnation is not cached as a connection owner");
        ok &= Check(!collector.RememberTcpOwner(9, 42, 0, L"192.0.2.1:443"),
                    "an unknown identity is not cached as a connection owner");
        ok &= Check(collector.RememberTcpOwner(9, 42, 100, L"192.0.2.1:443"),
                    "the live owner is cached");
        DWORD owner = 0;
        uint64_t ownerStart = 0;
        std::wstring ownerEndpoints;
        ProcessFacts stale;
        stale.ok = true;
        stale.created = 101;
        ok &= Check(!collector.ResolveTcpOwner(10, 42, stale, ownerEndpoints, owner, ownerStart),
                    "a direct TCP owner must match the tracked incarnation");
        ProcessFacts live;
        live.ok = true;
        live.created = 100;
        ok &= Check(collector.ResolveTcpOwner(10, 42, live, ownerEndpoints, owner, ownerStart) &&
                        owner == 42 && ownerStart == 100,
                    "a direct TCP owner returns its validated incarnation");
        ProcessFacts unknown;
        ok &= Check(collector.ResolveTcpOwner(9, 0, unknown, ownerEndpoints, owner, ownerStart) &&
                        owner == 42 && ownerStart == 100 && ownerEndpoints == L"192.0.2.1:443",
                    "a cached TCP owner returns its captured incarnation");
        collector.ForgetTcpOwner(9);
        ok &= Check(!collector.ResolveTcpOwner(9, 0, unknown, ownerEndpoints, owner, ownerStart),
                    "a closed connection cannot lend its owner to a reused TCB");
        ok &= Check(collector.RememberTcpOwner(9, 42, 100, L"192.0.2.1:443"),
                    "the current connection can be cached after eviction");
        /* A record that names a live non-client process must not borrow the cache. */
        ProcessFacts unrelated;
        unrelated.ok = true;
        unrelated.created = 500;
        ok &= Check(!collector.ResolveTcpOwner(9, 43, unrelated, ownerEndpoints, owner, ownerStart),
                    "a named non-client process does not inherit a cached TCP owner");
        ok &= Check(!collector.ResolveTcpOwner(9, 0, unknown, ownerEndpoints, owner, ownerStart),
                    "the stale TCB entry is dropped when a foreign process reuses it");
        ok &= Check(collector.RememberTcpOwner(9, 42, 100, L"192.0.2.1:443"),
                    "the client can cache the connection again after a foreign reuse");
        scope.AddProcess(42, 101, L"C:\\client.exe");
        ok &= Check(ownerStart == 100, "TCP attribution does not re-read a reused PID's start time");
        ok &= Check(!collector.ResolveTcpOwner(9, 0, unknown, ownerEndpoints, owner, ownerStart),
                    "a reused PID no longer owns the cached connection");
    }
    /* Linux paths classify through the same separator-folded terms. */
    {
        OutsideClassifier linuxClassifier(L"/opt/client", L"/opt/client", L"/usr", L"/usr");
        auto category = [&](unsigned long type, const wchar_t* path) {
            TelemetryEvent file;
            file.header.Type = type;
            file.text = path;
            linuxClassifier.Classify(file);
            return file.header.Category;
        };
        ok &= Check(category(MsMonFileRead, L"/sys/devices/virtual/dmi/id/product_uuid") == MsMonCategoryHardwareIdentity &&
                        category(MsMonFileRead, L"/proc/cpuinfo") == MsMonCategoryHardwareIdentity &&
                        category(MsMonFileRead, L"/sys/devices/pci0000:00/0000:00:1d.0/nvme/nvme0/serial") ==
                            MsMonCategoryHardwareIdentity &&
                        category(MsMonFileCreate, L"/etc/machine-id") == MsMonCategoryHardwareIdentity,
                    "Linux identity files are hardware identity");
        ok &= Check(category(MsMonFileRead, L"/opt/client/data.bin") == MsMonCategoryClientData &&
                        category(MsMonImageLoad, L"/usr/lib/libc.so.6") == MsMonCategoryWindowsRuntime &&
                        category(MsMonFileRead, L"/proc/self/maps") == MsMonCategoryWindowsRuntime &&
                        category(MsMonFileWrite, L"/home/user/.config/x") == MsMonCategoryUserData &&
                        category(MsMonFileRead, L"/system/x") == MsMonCategoryUnknown,
                    "Linux client, runtime and user paths");
    }

    const auto& opnumProperties = RpcOpnumProperties();
    ok &= Check(opnumProperties.size() == 3 && opnumProperties[0] == L"ProcNum" &&
                opnumProperties[1] == L"OpNum" && opnumProperties[2] == L"OperationNum",
                "RPC opnum property aliases");
    GUID wkssvc{ 0x6bffd098, 0xa112, 0x3610,
                 { 0x98, 0x33, 0x46, 0xc3, 0xf8, 0x7e, 0x34, 0x5a } };
    ok &= Check(RpcGuidText(wkssvc) == L"6bffd098-a112-3610-9833-46c3f87e345a",
                "RPC GUID decoding");
    std::wstring service;
    std::wstring method;
    ok &= Check(RpcOperationName(L"{6BFFD098-A112-3610-9833-46C3F87E345A}", 0, service, method) &&
                service == L"Wkssvc" && method == L"NetrWkstaGetInfo", "Wkssvc operation name");
    ok &= Check(RpcOperationName(L"484809d6-4239-471b-b5bc-61df8c23ac48", 5, service, method) &&
                service == L"WTS/TermSrvSession" && method == L"RpcGetUserName", "WTS operation name");
    ok &= Check(!RpcOperationName(L"5ca4a760-ebb1-11cf-8611-00a0245420ed", 5, service, method),
                "Legacy WTS operation is not mislabeled");
    ok &= Check(RpcOperationName(L"12345778-1234-abcd-ef00-0123456789ab", 7, service, method) &&
                service == L"LSA/lsarpc" && method == L"LsarQueryInformationPolicy", "LSA operation name");
    ok &= Check(RpcOperationName(L"12345778-1234-abcd-ef00-0123456789ac", 17, service, method) &&
                service == L"SAMR" && method == L"SamrLookupNamesInDomain", "SAMR operation name");
    ok &= Check(!RpcOperationName(L"12345778-1234-abcd-ef00-0123456789ac", 999, service, method),
                "unknown RPC operation stays raw");
    {
        /* Desktop services over AF_UNIX (Linux): the service of an endpoint and the requests a send's first bytes name. */
        ok &= Check(UnixService(L"unix:@/tmp/.X11-unix/X0") == L"x11" && UnixService(L"unix:/run/user/1000/bus") == L"dbus_session" &&
                        UnixService(L"unix:/run/user/1000/pulse/native") == L"pulse" &&
                        UnixService(L"unix:/run/dbus/system_bus_socket") == L"dbus_system" &&
                        UnixService(L"unix:/tmp/run/client/system_bus") == L"dbus_system" &&
                        UnixService(L"unix:/tmp/.wine-1000/server-803-1f/socket").empty(),
                    "AF_UNIX endpoints name their desktop service");
        /* QueryExtension("RECORD"), GetProperty: every request is named with what it touches. */
        const uint8_t query[] = {98, 0, 4, 0, 6, 0, 0, 0, 'R', 'E', 'C', 'O', 'R', 'D', 0, 0};
        const X11Extensions none;
        auto request = X11Request(query, sizeof(query), false, none, false);
        ok &= Check(request.first == L"QueryExtension" && request.second == L";extension=RECORD", "an X11 QueryExtension names its extension");
        const uint8_t property[] = {20, 0, 6, 0, 1, 0, 0, 0, 39, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0};
        request = X11Request(property, sizeof(property), false, none, false);
        ok &= Check(request.first == L"GetProperty" &&
                        request.second == L";window=0x1;property=0x27;type=0x0;offset=0;length=256",
                    "an X11 GetProperty names its window and property");
        std::vector<uint8_t> bus = {'l', 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0};
        for (const auto& [code, type, value] : {std::tuple<uint8_t, char, std::string>{1, 'o', "/org/freedesktop/DBus"},
                                                {6, 's', "org.freedesktop.DBus"}, {2, 's', "org.freedesktop.DBus"},
                                                {3, 's', "ListNames"}}) {
            while (bus.size() % 8) bus.push_back(0);
            bus.insert(bus.end(), {code, 1, static_cast<uint8_t>(type), 0, static_cast<uint8_t>(value.size()), 0, 0, 0});
            bus.insert(bus.end(), value.begin(), value.end());
            bus.push_back(0);
        }
        bus[12] = static_cast<uint8_t>(bus.size() - 16);
        const auto calls = DbusMessages(bus.data(), bus.size());
        ok &= Check(calls.size() == 1 && calls[0].first == L"org.freedesktop.DBus.ListNames" &&
                        calls[0].second == L";destination=org.freedesktop.DBus;path=/org/freedesktop/DBus;serial=1",
                    "a D-Bus method call is named with its destination and path");
        ok &= Check(PulseCommandName(28) == L"GET_CLIENT_INFO_LIST" && PulseCommandName(0xffff) == L"memblock",
                    "a PulseAudio command is named");
    }
    ok &= Check(MsMonNetworkUnregisterComplete(0) != 0, "callout unregister success is complete");
    ok &= Check(MsMonNetworkUnregisterComplete(static_cast<long>(0xC0220001)) != 0,
                "callout already absent is complete");
    ok &= Check(MsMonNetworkUnregisterComplete(static_cast<long>(0xC022000A)) == 0,
                "callout in use is not complete");
    ok &= Check(MsMonNetworkUnregisterComplete(static_cast<long>(0x80000011)) == 0,
                "busy callout is not complete");
    ok &= Check(MsMonNetworkUnregisterComplete(static_cast<long>(0xC0000001)) == 0,
                "ordinary unregister failure is not complete");
    /*
     * Flow removal has its own terminal set: STATUS_SUCCESS (flowDeleteFn already ran
     * synchronously) and STATUS_UNSUCCESSFUL (no context associated). STATUS_PENDING is
     * success-valued but the asynchronous flowDeleteFn is still to come, so freeing the
     * context there frees memory the engine still references.
     */
    ok &= Check(MsMonFlowRemoveComplete(0) != 0, "flow removal success is complete");
    ok &= Check(MsMonFlowRemoveComplete(static_cast<long>(0xC0000001)) != 0,
                "already-removed flow is complete");
    ok &= Check(MsMonFlowRemoveComplete(0x00000103) == 0, "pending flow removal is not complete");
    ok &= Check(MsMonFlowRemoveComplete(static_cast<long>(0xC0000225)) == 0,
                "generic not-found flow removal is not complete");
    ok &= Check(MsMonFlowRemoveComplete(static_cast<long>(0xC0000022)) == 0,
                "an ordinary flow removal failure is not complete");

    /* The real kfilter ABI (integrations.h includes filter/driver/kfilter.h); abi/abi_test.c pins both OSes. */
    ok &= Check(sizeof(KFILTER_EVENT) == (sizeof(wchar_t) == 2 ? 1192u : 2344u) &&
                sizeof(KFILTER_STATUS) == 80 && sizeof(KFILTER_READ_REQUEST) == 8, "ABI 8 layouts");
    KFILTER_EVENT source{};
    source.Timestamp = 134000000000000000ull;   /* a real FILETIME (2025), so the JSON timestamp renders */
    source.ProcessId = 42;
    source.Target = KFILTER_TARGET_REGISTRY;
    source.Action = KFilterActionAudit;
    source.Flags = KFILTER_EVENT_FLAG_WOULD_DENY;
    source.Status = static_cast<KF_LONG>(0xC0000022);
    source.Value = 0x81;
    source.RuleId = 17;
    source.Generation = 9;
    wcscpy_s(source.Path, L"\\REGISTRY\\MACHINE\\Synthetic");
    wcscpy_s(source.Image, L"MapleStory.exe");

    TelemetryEvent event = KFilterDecisionEvent(source, 77, 1);
    TelemetryEvent second = KFilterDecisionEvent(source, 77, 2);
    ok &= Check(event.header.Sequence == 1 && second.header.Sequence == 2,
                "decisions are numbered from 1");
    ok &= Check(event.header.Sequence != 0 && second.header.Sequence != 0,
                "a decision sequence is never zero");
    ok &= Check(event.header.Sequence != second.header.Sequence,
                "decision identities are unique");
    ok &= Check(event.header.Type == MsMonKfilterDecision, "decision event type");
    ok &= Check(event.header.SessionId == 77 && event.header.ProcessId == 42, "session and PID");
    ok &= Check(event.header.Timestamp == source.Timestamp && event.header.Status == source.Status,
                "timestamp and status");
    ok &= Check(event.header.DesiredAccess == source.Value && event.header.Value0 == source.Target &&
                event.header.Value1 == source.RuleId, "rights, target, and rule");
    ok &= Check(event.text == source.Path && event.component == L"kfilter.sys", "path and component");
    ok &= Check(event.detail.rfind(L"action=would_deny;layer=registry;target=registry;rule_id=17;rights=0x00000081;"
                                   L"rights_names=read,query;image=MapleStory.exe;pid=42;brokered=0;generation=9;", 0) == 0,
                "a decision leads with action, layer, target, rule, rights, image, pid, brokered, generation");
    ok &= Check(event.detail.find(L";decision=would_deny;") != std::wstring::npos &&
                event.detail.find(L";kfilter_action=audit;") != std::wstring::npos,
                "audit-mode denial is would_deny; the raw kfilter action is kept");
    ok &= Check(event.detail.size() >= 6 && event.detail.compare(event.detail.size() - 6, 6, L";rule=") == 0,
                "rule= is last and empty without rule text");

    source.Flags = 0;
    source.Action = KFilterActionDeny;
    event = KFilterDecisionEvent(source, 77, 3, L"deny registry \\REGISTRY\\MACHINE\\Synthetic rights=read");
    ok &= Check(event.detail.rfind(L"action=deny;", 0) == 0 && event.detail.find(L"would_deny") == std::wstring::npos,
                "enforced denial is deny");
    ok &= Check(event.detail.find(L";rule=deny registry \\REGISTRY\\MACHINE\\Synthetic rights=read") != std::wstring::npos,
                "rule text is carried");

    source.Action = KFilterActionAudit;
    event = KFilterDecisionEvent(source, 77, 4);
    ok &= Check(event.detail.rfind(L"action=audit;", 0) == 0, "explicit audit rule stays audit");
    source.Action = KFilterActionRisk;
    source.Target = KFILTER_TARGET_NETWORK;
    source.Flags = KFILTER_EVENT_FLAG_NETWORK | KFILTER_EVENT_FLAG_RISK;
    event = KFilterDecisionEvent(source, 77, 5);
    ok &= Check(event.detail.rfind(L"action=risk;layer=network;", 0) == 0 &&
                event.detail.find(L"kfilter_action=RISK") != std::wstring::npos &&
                event.detail.find(L"flags_names=network|risk;") != std::wstring::npos,
                "risk rule use is decoded");
    ok &= Check(event.detail.find(L";rights=0x00000081;rights_names=read,query;") != std::wstring::npos,
                "a RISK network record's Value is the right");
    /* Any other network decision carries the remote port in Value, not rights. */
    source.Action = KFilterActionAudit;
    source.Flags = KFILTER_EVENT_FLAG_NETWORK;
    source.Value = 443;
    event = KFilterDecisionEvent(source, 77, 5);
    ok &= Check(event.detail.find(L";rule_id=17;port=443;image=") != std::wstring::npos &&
                event.detail.find(L"rights") == std::wstring::npos,
                "a network decision logs its port, not rights names");

    /* ABI 8: a brokered message decision; Value is a byte count, not rights. */
    source.Action = KFilterActionDeny;
    source.Flags = KFILTER_EVENT_FLAG_MESSAGE | KFILTER_EVENT_FLAG_BROKERED;
    source.Value = 300;
    event = KFilterDecisionEvent(source, 77, 6);
    ok &= Check(event.detail.rfind(L"action=deny;layer=message;target=network;rule_id=17;bytes=300;image=MapleStory.exe;"
                                   L"pid=42;brokered=1;", 0) == 0 &&
                event.detail.find(L"rights=") == std::wstring::npos,
                "a message decision logs bytes and the brokered flag");
    /* ABI 8: REPEAT puts the collapse count in Generation. */
    source.Flags = KFILTER_EVENT_FLAG_REPEAT;
    source.Value = 0x81;
    source.Generation = 12;
    event = KFilterDecisionEvent(source, 77, 6);
    ok &= Check(event.detail.find(L";repeat=12;") != std::wstring::npos &&
                event.detail.find(L"generation=") == std::wstring::npos,
                "a repeat count is not logged as the generation");
    source.Flags = 0;
    source.Generation = 9;

    source.Action = KFilterActionAudit;
    source.Target = KFILTER_TARGET_DEVICE;
    source.Value = 0x006D0008;
    event = KFilterDecisionEvent(source, 77, 6);
    ok &= Check(event.detail.find(L"target=device") != std::wstring::npos &&
                event.detail.find(L"ioctl=0x006D0008") != std::wstring::npos &&
                event.detail.find(L"rights=") == std::wstring::npos,
                "device decisions expose the IOCTL");
    source.Target = KFILTER_TARGET_REGISTRY;
    source.Value = 0x81;

    /* Outside-process targets keep their names; their Value is an access mask (no rights names). */
    {
        struct TargetCase { unsigned long value; const wchar_t* name; };
        const TargetCase targets[] = {
            { 0x00000100u, L"handle" }, { 0x00000200u, L"launch" },
            { 0x00000400u, L"open" }, { 0x00000800u, L"thread-handle" },
            { 0x00001000u, L"thread-open" }
        };
        for (const auto& target : targets) {
            source.Target = target.value;
            event = KFilterDecisionEvent(source, 77, 6);
            const std::wstring prefix = L"target=" + std::wstring(target.name) + L";";
            ok &= Check(event.detail.find(prefix) != std::wstring::npos,
                        "an outside target is decoded by name");
            ok &= Check(event.detail.find(L"target=unknown") == std::wstring::npos &&
                        event.detail.find(L"target_id=" + std::to_wstring(target.value)) != std::wstring::npos,
                        "an outside target keeps its numeric id");
            ok &= Check(event.detail.find(target.value == KFILTER_TARGET_LAUNCH ? L";rights=0x00000081;rights_names="
                                                                                : L";access=0x00000081;image=") !=
                            std::wstring::npos && (target.value == KFILTER_TARGET_LAUNCH ||
                                                   event.detail.find(L"rights") == std::wstring::npos),
                        "a handle crossing logs an access mask, a launch logs rights");
        }
        /* A PROCESS decision that is no process start: a crossing's mask or a refusal code. */
        source.Target = KFILTER_TARGET_PROCESS;
        event = KFilterDecisionEvent(source, 77, 6);
        ok &= Check(event.detail.find(L";access=0x00000081;") != std::wstring::npos &&
                        event.detail.find(L"rights") == std::wstring::npos,
                    "a process crossing logs an access mask");
        source.Target = KFILTER_TARGET_REGISTRY;

        /* The program name is percent-encoded: it cannot add, replace or cut detail fields. */
        wcscpy_s(source.Image, L"a;layer=x;rule_id=9;rule=%.exe");
        event = KFilterDecisionEvent(source, 77, 6);
        ok &= Check(event.detail.find(L";image=a%3Blayer%3Dx%3Brule_id%3D9%3Brule%3D%25.exe;pid=42;") !=
                        std::wstring::npos &&
                        event.detail.find(L";rule=") == event.detail.rfind(L";rule=") &&
                        event.detail.find(L";layer=") == event.detail.rfind(L";layer="),
                    "image= is escaped");
        wcscpy_s(source.Image, L"MapleStory.exe");
    }

    /* ABI 10: a decision on memory names what it reached after the program, and its addr= rule. */
    {
        KFILTER_EVENT memory = source;
        memory.Target = KFILTER_TARGET_PEER;
        memory.Value = 0x10;
        wcscpy_s(memory.Path, L"C:\\Nexon\\MapleStory.exe addr=0x0000000140001000+16");
        event = KFilterDecisionEvent(memory, 77, 6,
                                     L"deny peer C:\\*\\MapleStory.exe access=0x00000010 addr=MapleStory.exe+0x1000-0x1fff");
        ok &= Check(event.text == memory.Path && event.detail.find(L";access=0x00000010;") != std::wstring::npos &&
                        event.detail.find(L";rule=deny peer C:\\*\\MapleStory.exe access=0x00000010 "
                                          L"addr=MapleStory.exe+0x1000-0x1fff") != std::wstring::npos,
                    "a memory decision carries the address it reached and its addr= rule");
    }

    /* Target-set union: which decisions name a member of kfilter's protected family. */
    {
        KFILTER_EVENT probe = source;
        ok &= Check(KFilterDecisionNamesFamily(probe), "a registry decision names the client");
        probe.Flags = KFILTER_EVENT_FLAG_BROKERED;
        ok &= Check(KFilterDecisionNamesFamily(probe), "a brokered decision names the client it was charged to");
        probe.Flags = 0;
        probe.Target = KFILTER_TARGET_HANDLE;
        ok &= Check(!KFilterDecisionNamesFamily(probe), "a handle decision names the outside opener");
        probe.Target = KFILTER_TARGET_LAUNCH;
        ok &= Check(!KFilterDecisionNamesFamily(probe), "a launch decision names the broker");
        /* DuplicateHandle runs in the caller's context: an outside caller can hand the client a handle. */
        probe.Target = KFILTER_TARGET_OPEN;
        ok &= Check(!KFilterDecisionNamesFamily(probe), "an open decision may name an outside duplicator");
        probe.Target = KFILTER_TARGET_THREAD_OPEN;
        ok &= Check(!KFilterDecisionNamesFamily(probe), "a thread-open decision may name an outside duplicator");
        probe.Target = KFILTER_TARGET_PROCESS;
        ok &= Check(!KFilterDecisionNamesFamily(probe), "a process crossing may name an outside duplicator");
        probe.Target = KFILTER_TARGET_NETWORK;
        ok &= Check(KFilterDecisionNamesFamily(probe), "a network decision names the client");
        probe.Target = KFILTER_TARGET_PROCESS;
        probe.Flags = KFILTER_EVENT_FLAG_PROCESS_CREATE;
        probe.Action = KFilterActionDeny;
        ok &= Check(!KFilterDecisionNamesFamily(probe), "a refused process start names no family member");
        probe.Action = KFilterActionAllow;
#ifdef _WIN32
        ok &= Check(!KFilterDecisionNamesFamily(probe), "Windows logs a process start in the creator's context");
#else
        ok &= Check(KFilterDecisionNamesFamily(probe), "an admitted exec names the new family member");
#endif
        probe.Flags = 0;
        probe.ProcessId = 0;
        ok &= Check(!KFilterDecisionNamesFamily(probe), "PID 0 is nobody");
    }

    /* Rule text, as kfilterctl prints the policy. */
    {
        KFILTER_RULE rule{};
        rule.Action = KFilterActionDeny;
        rule.Targets = KFILTER_TARGET_FILE;
        rule.Rights = KFILTER_RIGHT_READ | KFILTER_RIGHT_WRITE;
        rule.RuleId = 17;
        rule.Count = (2u << KFILTER_COUNT_USES_SHIFT) | 1u;
        wcscpy_s(rule.Path, L"C:\\Windows\\System32\\drivers\\etc\\hosts");
        wcscpy_s(rule.Image, L"nexon_client.exe");
        ok &= Check(KFilterRuleText(rule) == L"deny file C:\\Windows\\System32\\drivers\\etc\\hosts rights=read,write"
                                             L" image=nexon_client.exe uses=2 phase=1",
                    "a rule's text");
        KFILTER_RULE memory{};
        memory.Action = KFilterActionDeny;
        memory.Targets = KFILTER_TARGET_PEER;
        memory.Rights = 0x10;
        memory.Flags = KFILTER_RULE_ADDRESS;
        wcscpy_s(memory.Path, L"C:\\*\\MapleStory.exe");
        wcscpy_s(memory.Value, L"MapleStory.exe");
        wcscpy_s(memory.Image, L"grap-core64.aes");
        memory.AddressCount = 2;
        memory.AddressModule[0] = 1;
        memory.Address[0] = {0x1000, 0x1fff};
        memory.Address[1] = {0x140000000ull, 0x14fffffffull};
        ok &= Check(KFilterRuleText(memory) == L"deny peer C:\\*\\MapleStory.exe access=0x00000010"
                                               L" addr=MapleStory.exe+0x1000-0x1fff,0x140000000-0x14fffffff image=grap-core64.aes",
                    "an addr= rule's text: its ranges, module-relative after the module");
        KFILTER_NET_RULE net{};
        net.Action = KFilterActionAllow;
        net.Family = 4;
        net.Protocol = 6;
        net.PrefixLength = 24;
        net.Port = 8484;
        net.Rights = KFILTER_RIGHT_CONNECT;
        const unsigned char address[4] = {10, 1, 2, 0};
        std::memcpy(net.Address, address, sizeof(address));
        ok &= Check(KFilterNetRuleText(net) == L"allow network 10.1.2.0/24 tcp port=8484 rights=connect",
                    "a network rule's text");
        KFILTER_NET_RULE peer{};
        peer.Action = KFilterActionDeny;
        peer.Family = KFILTER_NET_FAMILY_UNIX;
        peer.Rights = KFILTER_RIGHT_SEND;
        peer.MatchLength = 1;
        peer.Match[0] = 0x6C;
        wcscpy_s(peer.Unix, L"/@/tmp/.X11-unix/X5");
        ok &= Check(KFilterNetRuleText(peer) == L"deny network unix=/@/tmp/.X11-unix/X5 rights=send match=6C@0",
                    "a unix message rule's text names its peer");

        /* The reader names the rule of the generation it holds, and reports the family PIDs. */
        std::vector<unsigned char> storage(KFILTER_CONFIG_SIZE(1));
        KFILTER_CONFIG* config = reinterpret_cast<KFILTER_CONFIG*>(storage.data());
        config->Generation = 9;
        config->RuleCount = 1;
        config->NetworkRuleCount = 1;
        config->Rules[0] = rule;
        net.RuleId = 10001;
        config->Network[0] = net;
        KFilterReader reader(77, 0);
        reader.SetRules(*config);
        std::vector<TelemetryEvent> converted;
        std::vector<KFilterFamilyProcess> family;
        KFILTER_EVENT batch[4] = {source, source, source, source};
        batch[1].Generation = 10;                          /* a later policy: its rule 17 is unknown here */
        batch[2].Flags = KFILTER_EVENT_FLAG_REPEAT;        /* Generation is a count */
        batch[2].Generation = 10;
        batch[3].Target = KFILTER_TARGET_HANDLE;
        batch[3].RuleId = 10001;
        batch[3].ProcessId = 99;
        reader.ConvertBatch(batch, 4, converted, &family);
        ok &= Check(converted.size() == 4 &&
                    converted[0].detail.find(L";rule=deny file C:\\Windows") != std::wstring::npos &&
                    converted[1].detail.find(L";rule=deny") == std::wstring::npos &&
                    converted[2].detail.find(L";rule=deny file") != std::wstring::npos &&
                    converted[3].detail.find(L";rule=allow network 10.1.2.0/24") != std::wstring::npos,
                    "rule text follows the held generation");
        ok &= Check(family.size() == 3 && family[0].pid == 42 && family[0].timestamp == source.Timestamp,
                    "family PIDs come from decisions about the client, not outside openers");
    }

    /* The decision ring survives across runs: only events from this session may be written. */
    ok &= Check(!KFilterDecisionInSession(source, source.Timestamp + 1),
                "a decision from before the session start is excluded");
    ok &= Check(KFilterDecisionInSession(source, source.Timestamp),
                "a decision at the session boundary is included");
    ok &= Check(KFilterDecisionInSession(source, source.Timestamp - 1),
                "a decision after the session start is included");
    ok &= Check(KFilterDecisionEvent(source, 77, 1).header.Sequence == 1,
                "the first accepted decision keeps sequence 1");

    KFILTER_EVENT staleEvent = source;
    staleEvent.Timestamp = source.Timestamp - 1;
    KFilterReader sessionReader(77, source.Timestamp);
    std::vector<TelemetryEvent> converted;
    sessionReader.ConvertBatch(&staleEvent, 1, converted);
    ok &= Check(converted.empty(), "a pre-session decision is not converted");
    sessionReader.ConvertBatch(&source, 1, converted);
    ok &= Check(converted.size() == 1 && converted.front().header.Sequence == 1,
                "accepted decisions are numbered from 1");
    sessionReader.ConvertBatch(&source, 1, converted);
    ok &= Check(converted.size() == 2 && converted.back().header.Sequence == 2,
                "numbering continues across batches");

    KFILTER_STATUS start{};
    start.DroppedEvents = 3;
    KFILTER_STATUS end = start;
    end.AbiVersion = KFILTER_ABI_VERSION;
    end.Mode = 2;
    end.DroppedEvents = 8;
    const std::wstring status = KFilterStatusDetail(end, &start);
    ok &= Check(status.find(L"mode=block") != std::wstring::npos &&
                status.find(L"dropped_delta=5") != std::wstring::npos, "status and drop delta");
    ok &= Check(status.find(L"session_changed") == std::wstring::npos, "same kfilter session");
    end.SessionTag = start.SessionTag + 1;
    ok &= Check(KFilterStatusDetail(end, &start).find(L";session_changed=1") != std::wstring::npos,
                "a kfilter restart (new session tag) is reported");
    ok &= Check(EventTypeName(MsMonEtwCodeIntegrity) == "etw_code_integrity" &&
                EventTypeName(MsMonKfilterDecision) == "kfilter_decision", "JSON event names");

    TelemetryEvent integrity;
    integrity.source = "etw";
    integrity.header.Size = sizeof(integrity.header);
    integrity.header.Version = MSMON_PROTOCOL_VERSION;
    integrity.header.Type = MsMonEtwCodeIntegrity;
    integrity.header.Flags = MsMonFlagObserverRecord;
    integrity.header.Sequence = 1;
    integrity.header.Timestamp = source.Timestamp;
    integrity.header.SessionId = 77;
    integrity.header.ProcessId = 4;
    integrity.header.Value0 = 3077;
    integrity.component = L"WDAC";
    integrity.text = L"C:\\Synthetic\\BlackCat64.sys";
    integrity.detail = L"decision=blocked;event_id=3077";

    TelemetryEvent firstDecision = KFilterDecisionEvent(source, 77, 1);
    TelemetryEvent secondDecision = KFilterDecisionEvent(source, 77, 2);

    /* Observer coverage carries sequence 0 and must not inflate the event totals. */
    TelemetryEvent coverage;
    coverage.source = "agent";
    coverage.header.Size = sizeof(coverage.header);
    coverage.header.Version = MSMON_PROTOCOL_VERSION;
    coverage.header.Type = MsMonCoverageUsage;
    coverage.header.Flags = MsMonFlagObserverRecord;
    coverage.header.Sequence = 0;
    coverage.header.Timestamp = source.Timestamp;
    coverage.header.SessionId = 77;
    coverage.text = L"coverage_usage";
    ok &= Check(!CountsAsSessionEvent(coverage), "a sequence-0 coverage record is not an event");
    ok &= Check(CountsAsSessionEvent(firstDecision), "a numbered decision is an event");

    MSMON_STATISTICS statistics{};
    SessionSummary summary;
    summary.Add(coverage);
    ok &= Check(summary.Json(statistics, 0, 0, 0).find("\"events\":0") != std::string::npos,
                "coverage alone is not counted as an event");
    summary.Add(firstDecision);
    summary.Add(secondDecision);
    summary.Add(integrity);
    ok &= Check(summary.Json(statistics, 0, 0, 0).find("\"events\":3") != std::string::npos,
                "observer_summary counts only identified events");

    /* Payload bookkeeping is bounded, and a completed series retains no chunks. */
    {
        SessionSummary payloads;
        for (unsigned index = 0; index < 5000; index++) {
            TelemetryEvent payload;
            payload.header.Sequence = index + 1;
            payload.header.Type = MsMonRegistryQuery;
            payload.header.Flags = MsMonFlagPayloadPresent;
            payload.header.OperationId = index + 1;
            payload.header.PayloadChunkCount = 1;
            payload.header.PayloadChunkIndex = 0;
            payload.header.PayloadTotalBytes = 4;
            payload.header.PayloadBytes = 4;
            payload.payload = { 1, 2, 3, 4 };
            payloads.Add(payload);
        }
        const std::string json = payloads.Json(statistics, 0, 0, 0);
        ok &= Check(json.find("\"payload_operations\":5000") != std::string::npos,
                    "every payload operation is counted");
        ok &= Check(json.find("\"complete_payload_operations\":5000") != std::string::npos,
                    "a completed payload series counts once");
        ok &= Check(json.find("\"incomplete_payload_operations\":0") != std::string::npos,
                    "a completed payload series leaves no incomplete entry");
        ok &= Check(json.find("\"payload_operations_pending\":0") != std::string::npos,
                    "completed payload series retain no chunk bookkeeping");
    }

    /*
     * #53/#57: a late, lower OperationId must survive the insert that evicts the
     * oldest pending series. 4096 incomplete series fill the table; inserting id
     * 1 raises it to 4097 and evicts one of them, and must not free the node it
     * just inserted; finishing id 1 then removes exactly one entry.
     */
    {
        SessionSummary late;
        TelemetryEvent payload;
        payload.source = "driver";
        payload.header.Type = MsMonRegistryQuery;
        payload.header.Flags = MsMonFlagPayloadPresent;
        payload.header.PayloadChunkCount = 2;
        payload.header.PayloadTotalBytes = 8;
        payload.header.PayloadBytes = 4;
        payload.payload = { 1, 2, 3, 4 };
        for (unsigned index = 0; index < 4096; index++) {
            payload.header.Sequence = index + 1;
            payload.header.OperationId = 1000 + index;
            payload.header.PayloadChunkIndex = 0;
            late.Add(payload);
        }
        payload.header.OperationId = 1;
        payload.header.PayloadChunkIndex = 0;
        late.Add(payload);
        payload.header.PayloadChunkIndex = 1;
        late.Add(payload);
        const std::string json = late.Json(statistics, 0, 0, 0);
        ok &= Check(json.find("\"payload_operations\":4097") != std::string::npos,
                    "the late operation survives its own eviction");
        ok &= Check(json.find("\"complete_payload_operations\":1") != std::string::npos,
                    "the late operation completes after eviction");
        ok &= Check(json.find("\"incomplete_payload_operations\":4096") != std::string::npos,
                    "the evicted series stays counted as incomplete");
        ok &= Check(json.find("\"payload_operations_pending\":4095") != std::string::npos,
                    "one series is evicted and the late one is released on completion");
    }

    /*
     * The unit the agent uses for session_meta.json and coverage.json: the summary, the total
     * and the per-type counts must come from one decision, or the counts drift from verify_log.
     */
    SessionSummary accounted;
    uint64_t accountedTotal = 0;
    std::unordered_map<unsigned long, uint64_t> accountedCounts;
    AccountSessionEvent(accounted, coverage, accountedTotal, accountedCounts);
    AccountSessionEvent(accounted, firstDecision, accountedTotal, accountedCounts);
    AccountSessionEvent(accounted, secondDecision, accountedTotal, accountedCounts);
    AccountSessionEvent(accounted, integrity, accountedTotal, accountedCounts);
    ok &= Check(accountedTotal == 3, "session_meta event total matches the verifier");
    ok &= Check(accounted.Json(statistics, 0, 0, 0).find("\"events\":3") != std::string::npos,
                "accounted summary matches the session total");
    ok &= Check(accountedCounts.size() == 2 &&
                accountedCounts.count(MsMonCoverage) == 0 &&
                accountedCounts.count(MsMonCoverageUsage) == 0,
                "coverage records stay out of event_counts");

    {
        auto volumeEvent = [](ULONG informationClass, const std::vector<BYTE>& bytes) {
            TelemetryEvent volume;
            volume.header.Size = sizeof(volume.header);
            volume.header.Version = MSMON_PROTOCOL_VERSION;
            volume.header.Type = MsMonFileQueryVolumeInformation;
            volume.header.Flags = MsMonFlagPayloadPresent | MsMonFlagPayloadFinalChunk;
            volume.header.Value0 = informationClass;
            volume.header.PayloadKind = MsMonPayloadVolumeInformation;
            volume.header.PayloadChunkCount = 1;
            volume.header.PayloadTotalBytes = bytes.size();
            volume.payload = bytes;
            return volume;
        };
        std::vector<BYTE> identity(26, 0);
        const uint32_t serial = 0x12345678;
        const uint32_t labelBytes = 8;
        std::memcpy(identity.data() + 8, &serial, sizeof(serial));
        std::memcpy(identity.data() + 12, &labelBytes, sizeof(labelBytes));
        const char16_t label[] = u"VOL1";
        std::memcpy(identity.data() + 18, label, labelBytes);
        const std::string identityJson = TelemetryJson(volumeEvent(1, identity));
        ok &= Check(identityJson.find("\"volume_serial_hex\":\"12345678\"") != std::string::npos &&
                        identityJson.find("\"volume_label\":\"VOL1\"") != std::string::npos,
                    "a volume-information payload keeps its real serial and label");

        std::vector<BYTE> sizeInformation(24, 0);
        const uint32_t clusters = 0x11223344;
        std::memcpy(sizeInformation.data() + 8, &clusters, sizeof(clusters));
        const std::string sizeJson = TelemetryJson(volumeEvent(3, sizeInformation));
        ok &= Check(sizeJson.find("volume_serial_number") == std::string::npos &&
                        sizeJson.find("volume_label") == std::string::npos,
                    "a size-information payload is not decoded as a volume identity");
    }

    {
        /* A Linux socket payload chunk (MsMonPayloadNetworkData) decodes and names its kind. */
        std::vector<BYTE> record(sizeof(MSMON_EVENT_HEADER) + 8, 0);
        MSMON_EVENT_HEADER header{};
        header.Size = static_cast<unsigned long>(record.size());
        header.Version = MSMON_PROTOCOL_VERSION;
        header.Type = MsMonFileWrite;
        header.Flags = MsMonFlagPayloadPresent | MsMonFlagPayloadPartial | MsMonFlagPayloadInput;
        header.OperationId = 9;
        header.PayloadTotalBytes = 9000;
        header.PayloadChunkCount = 2;
        header.PayloadKind = MsMonPayloadNetworkData;
        header.PayloadOffset = sizeof(MSMON_EVENT_HEADER);
        header.PayloadBytes = 8;
        std::memcpy(record.data(), &header, sizeof(header));
        std::memcpy(record.data() + sizeof(header), "msmon-ok", 8);
        TelemetryEvent decoded;
        DWORD consumed = 0;
        std::string decodeError;
        ok &= Check(DecodeDriverEvent(record.data(), static_cast<DWORD>(record.size()), decoded, consumed, decodeError) &&
                        decoded.payload.size() == 8,
                    "a network_data payload chunk decodes");
        ok &= Check(TelemetryJson(decoded).find("\"kind\":\"network_data\"") != std::string::npos,
                    "a network_data payload names its kind");
        /* The same chunk as a Wine pipe's bytes (MsMonPayloadIpcData). */
        reinterpret_cast<MSMON_EVENT_HEADER*>(record.data())->PayloadKind = MsMonPayloadIpcData;
        ok &= Check(DecodeDriverEvent(record.data(), static_cast<DWORD>(record.size()), decoded, consumed, decodeError) &&
                        TelemetryJson(decoded).find("\"kind\":\"ipc_data\"") != std::string::npos,
                    "an ipc_data payload chunk decodes and names its kind");
        reinterpret_cast<MSMON_EVENT_HEADER*>(record.data())->PayloadKind = MsMonPayloadTlsPlaintext;
        ok &= Check(DecodeDriverEvent(record.data(), static_cast<DWORD>(record.size()), decoded, consumed, decodeError) &&
                        TelemetryJson(decoded).find("\"kind\":\"tls_plaintext\"") != std::string::npos,
                    "a tls_plaintext payload chunk decodes and names its kind");
        /* A detail the Linux session cut at its string limit is flagged as a cut path is. */
        reinterpret_cast<MSMON_EVENT_HEADER*>(record.data())->Flags |= MsMonFlagTruncatedDetail;
        ok &= Check(DecodeDriverEvent(record.data(), static_cast<DWORD>(record.size()), decoded, consumed, decodeError) &&
                        TelemetryJson(decoded).find("\"truncated_detail\"") != std::string::npos,
                    "a cut detail is flagged truncated_detail");
    }

    JsonlWriter writer(L"build/tests/integration-events.jsonl", 0);
    ok &= Check(writer.Open(), "open JSONL output");
    ok &= Check(writer.Write(TelemetryJson(firstDecision)), "write first KFilter JSON");
    ok &= Check(writer.Write(TelemetryJson(secondDecision)), "write second KFilter JSON");
    ok &= Check(writer.Write(TelemetryJson(coverage)), "write coverage JSON");
    ok &= Check(writer.Write(TelemetryJson(integrity)), "write CodeIntegrity JSON");
    ok &= Check(writer.Close(), "close JSONL output");

    /* verify_log.py keys written events on (source, sequence); zero would hide them. */
    std::ifstream written("build/tests/integration-events.jsonl");
    std::vector<std::string> sequences;
    std::string line;
    while (std::getline(written, line)) {
        if (line.find("\"type\":\"kfilter_decision\"") == std::string::npos) continue;
        const size_t at = line.find("\"sequence\":");
        ok &= Check(at != std::string::npos, "written decision carries a sequence");
        if (at == std::string::npos) continue;
        size_t stop = line.find_first_of(",}", at);
        if (stop == std::string::npos) stop = line.size();
        sequences.push_back(line.substr(at + 11, stop - at - 11));
    }
    ok &= Check(sequences.size() == 2, "two decisions were written");
    ok &= Check(sequences.size() == 2 && sequences[0] == "1" && sequences[1] == "2",
                "written decisions are numbered 1..N");

    /* The fixture must be the record class production writes at shutdown (type 111). */
    std::ifstream serialized("build/tests/integration-events.jsonl");
    unsigned coverageUsageRecords = 0;
    while (std::getline(serialized, line)) {
        if (line.find("\"type\":\"coverage_usage\"") == std::string::npos) continue;
        coverageUsageRecords++;
        ok &= Check(line.find("\"type_id\":111") != std::string::npos,
                    "serialized coverage record has the production type id");
        ok &= Check(line.find("\"sequence\":0") != std::string::npos,
                    "serialized coverage record stays a non-event");
    }
    ok &= Check(coverageUsageRecords == 1, "exactly one coverage_usage record was written");

    const std::wstring manifestOn = IntegrationCoverageState(true, L"kfilter_available");
    ok &= Check(manifestOn.find(L"etw=wmi,dns,rpc,tcp,codeintegrity") != std::wstring::npos,
                "manifest lists the CodeIntegrity provider");
    ok &= Check(manifestOn.find(L"kfilter=kfilter_available") != std::wstring::npos,
                "manifest reports the KFilter state");
    ok &= Check(manifestOn.find(L"wdac=etw") != std::wstring::npos,
                "manifest reports WDAC ingestion");
    const std::wstring manifestOff = IntegrationCoverageState(false, L"kfilter_unavailable");
    ok &= Check(manifestOff.find(L"etw=disabled") != std::wstring::npos,
                "manifest shows ETW disabled");
    ok &= Check(manifestOff.find(L"wdac=disabled") != std::wstring::npos,
                "manifest shows WDAC disabled");

    {
        /* A growing log past the snapshot limit: its newest bytes, then what each copy after that appended. */
        const uint64_t KiB = 1024, limit = 256 * KiB;
        const SnapshotRange first = SnapshotRangeOf(1024 * KiB, 0, limit);
        const SnapshotRange grown = SnapshotRangeOf(1124 * KiB, first.from + first.bytes, limit);
        const SnapshotRange burst = SnapshotRangeOf(1524 * KiB, grown.from + grown.bytes, limit);
        ok &= Check(first.from == 768 * KiB && first.bytes == limit && std::wstring(first.mode) == L"tail",
                    "a large log's first snapshot is its newest bytes");
        ok &= Check(grown.from == 1024 * KiB && grown.bytes == 100 * KiB && std::wstring(grown.mode) == L"delta",
                    "the next snapshot is what was appended since");
        ok &= Check(burst.from == 1268 * KiB && burst.bytes == limit && std::wstring(burst.mode) == L"tail",
                    "an append past the limit keeps its newest bytes");
        ok &= Check(std::wstring(SnapshotRangeOf(100, 50, limit).mode) == L"whole", "a small file is copied whole");
    }

    if (!ok) return 1;
    std::cout << "integration regression passed\n";
    return 0;
}
