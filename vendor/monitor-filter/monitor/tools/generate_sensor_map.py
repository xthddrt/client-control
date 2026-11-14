#!/usr/bin/env python3
"""Generate coverage/sensor-map.json from the protocol and telemetry names."""

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "include" / "msmon_protocol.h"
TELEMETRY = ROOT / "agent" / "telemetry.cpp"
OUTPUT = ROOT / "coverage" / "sensor-map.json"

CALLBACKS = [
    (0, "process.notify", "driver/process.c::MsMonProcessNotifyInner", "process_start,process_exit", "startup,gameplay"),
    (1, "thread.notify", "driver/process.c::MsMonThreadNotify", "thread_start,thread_exit", "startup,gameplay"),
    (2, "image.notify", "driver/process.c::MsMonImageNotify", "image_load", "startup,gameplay"),
    (3, "object.process", "driver/object.c::MsMonObjectPre", "process_handle", "gameplay"),
    (4, "object.thread", "driver/object.c::MsMonObjectPre", "thread_handle", "gameplay"),
    (5, "file.pre_create", "driver/file_filter.c::MsMonPreCreate", "file_create", "file_io,gameplay"),
    (6, "file.post_create", "driver/file_filter.c::MsMonPostCreate", "file_create", "file_io,gameplay"),
    (7, "file.pre_op", "driver/file_filter.c::MsMonPreOperation", "file_read,file_write", "file_io,gameplay"),
    (8, "file.post_op", "driver/file_filter.c::MsMonPostOperation", "file_read,file_write", "file_io,gameplay"),
    (9, "registry.callback", "driver/registry.c::MsMonRegistryCallback", "registry_open,registry_query", "registry,gameplay"),
    (10, "wfp.classify", "driver/network.c::MsMonWfpClassify", "network_connect,network_accept", "network,gameplay"),
    (11, "wfp.notify", "driver/network.c::MsMonWfpNotify", "", "network,gameplay"),
    (12, "blackcat.check", "driver/attribution.c::MsMonCurrentIsBlackCat", "", "gameplay"),
    (13, "ioctl.dispatch", "driver/driver.c::MsMonDeviceControl", "", "startup,shutdown"),
    (40, "linux.fanotify", "agent/linux/fanotify.cpp::FanotifyRun",
     "file_create,file_read,file_write,file_close,file_set_information", "file_io,gameplay"),
    (41, "linux.proc_connector", "agent/linux/proc_connector.cpp::ProcConnectorRun", "process_start,process_exit",
     "startup,gameplay"),
    (42, "linux.maps_poll", "agent/linux/images.cpp::ImagesScan", "image_load,etw_wmi", "startup,gameplay"),
    (43, "linux.net_poll", "agent/linux/net.cpp::NetPoll", "network_connect,network_accept,network_flow_close",
     "network,gameplay"),
    (48, "linux.ebpf_process", "agent/linux/bpf/monitor.bpf.c::mm_fork,mm_exec,mm_exit,mm_mmap_file,mm_file_mprotect",
     "process_start,process_exit,thread_start,thread_exit", "startup,gameplay"),
    (49, "linux.ebpf_file", "agent/linux/bpf/monitor.bpf.c::mm_sys_enter,mm_sys_exit",
     "file_create,file_read,file_write,file_close,file_set_information,file_set_security,file_query_information,"
     "file_directory_control,file_set_ea,file_query_ea,coverage", "file_io,gameplay"),
    (50, "linux.ebpf_net", "agent/linux/bpf/monitor.bpf.c::mm_sys_enter,mm_sys_exit,mm_sock_*,mm_tcp_*,mm_skb_*",
     "network_connect,network_accept,network_flow_established,network_flow_close,file_read,file_write,etw_dns,etw_tcp",
     "network,gameplay"),
    (51, "linux.ebpf_ipc", "agent/linux/bpf/monitor.bpf.c::mm_sys_enter,mm_sys_exit",
     "network_connect,network_accept,process_handle", "ipc,gameplay"),
    (52, "linux.ebpf_device", "agent/linux/bpf/monitor.bpf.c::mm_sys_enter,mm_sys_exit", "file_device_control",
     "file_io,gameplay"),
    (53, "linux.ebpf_memory",
     "agent/linux/bpf/monitor.bpf.c::mm_sys_exit,mm_mmap_file,mm_file_mprotect,mm_ptrace,mm_kill,mm_bpf,mm_perf",
     "file_section,process_handle,image_load", "gameplay"),
    (60, "linux.ebpf_wineserver", "agent/linux/bpf/ws.bpf.h::mm_ws_enter,mm_ws_exit; agent/linux/wineserver.cpp::WsDecoder",
     "registry_open,registry_create,registry_set_value,registry_delete,registry_rename,registry_query,"
     "registry_enumerate,process_handle,thread_handle,file_create,file_section,file_query_volume_information,"
     "file_query_information,network_connect,network_accept,file_read,file_write,file_system_control,file_close,"
     "file_flush,file_device_control,etw_rpc,etw_wmi,etw_code_integrity,coverage",
     "registry,startup,gameplay,rpc,wmi,ipc"),
]

REGISTRATIONS = {
    20: "process.notify",
    21: "thread.notify",
    22: "image.notify",
    23: "object.process",
    24: "object.thread",
    25: "filter.register",
    26: "filter.start",
    27: "registry.callback",
    28: "wfp.callout0",
    29: "wfp.callout1",
    30: "wfp.callout2",
    31: "wfp.callout3",
    32: "wfp.callout4",
    33: "wfp.callout5",
    34: "wfp.engine",
    38: "attribution",
}

LINUX_REGISTRATIONS = {
    44: "linux.fanotify",
    45: "linux.proc_connector",
    46: "linux.maps_poll",
    47: "linux.net_poll",
    54: "linux.ebpf_process",
    55: "linux.ebpf_file",
    56: "linux.ebpf_net",
    57: "linux.ebpf_ipc",
    58: "linux.ebpf_device",
    59: "linux.ebpf_memory",
    61: "linux.ebpf_wineserver",
}


# Events written by the agent itself rather than a driver callback.
AGENT_EVENTS = {
    "etw_code_integrity": "agent/etw.cpp::OnCodeIntegrityRecord",
    "kfilter_decision": "agent/integrations.cpp::KFilterDecisionEvent",
}


def expected_for(name):
    if name.startswith(("process_", "thread_", "image_")):
        return ["startup", "gameplay"]
    if name.startswith("file_"):
        return ["file_io", "gameplay"]
    if name.startswith("registry_"):
        return ["registry", "gameplay"]
    if name.startswith("network_"):
        return ["network", "gameplay"]
    if name == "etw_wmi":
        return ["wmi", "gameplay"]
    if name == "etw_dns":
        return ["dns", "gameplay"]
    if name == "etw_rpc":
        return ["rpc", "gameplay"]
    if name == "etw_tcp":
        return ["network", "gameplay"]
    return ["startup", "shutdown"]


def main():
    protocol = PROTOCOL.read_text(encoding="utf-8")
    telemetry = TELEMETRY.read_text(encoding="utf-8")
    names = dict(re.findall(r"case (MsMon\w+): return \"([^\"]+)\";", telemetry))
    block = re.search(r"typedef enum _MSMON_EVENT_TYPE \{(.*?)\} MSMON_EVENT_TYPE;", protocol, re.S)
    if not block:
        print("event enum not found", file=sys.stderr)
        return 1
    ids = {name: int(value) for name, value in re.findall(r"^\s*(MsMon\w+) = (\d+)", block.group(1), re.M)}
    sensors = []
    for name, type_id in sorted(ids.items(), key=lambda item: item[1]):
        event_name = names.get(name)
        if not event_name:
            continue
        sensors.append({
            "sensor_id": "event." + event_name,
            "kind": "event",
            "event_type": event_name,
            "type_id": type_id,
            "implementation": AGENT_EVENTS.get(event_name, "driver event " + name),
            "expected_in": [] if event_name in AGENT_EVENTS else expected_for(event_name),
            "status": "active",
        })
    for slot, sensor_id, implementation, events, expected in CALLBACKS:
        sensors.append({
            "sensor_id": sensor_id,
            "kind": "callback",
            "slot": slot,
            "implementation": implementation,
            "event_types": [item for item in events.split(",") if item],
            "expected_in": expected.split(","),
            "status": "active",
        })
    for slot, sensor_id in REGISTRATIONS.items():
        sensors.append({
            "sensor_id": "registration." + sensor_id,
            "kind": "registration",
            "slot": slot,
            "implementation": "driver registration call",
            "expected_in": ["startup"],
            "status": "active",
        })
    for slot, sensor_id in LINUX_REGISTRATIONS.items():
        sensors.append({
            "sensor_id": "registration." + sensor_id,
            "kind": "registration",
            "slot": slot,
            "implementation": "agent/linux/session.cpp::LinuxSession::Start",
            "expected_in": ["startup"],
            "status": "active",
        })
    for index, name in enumerate(("wmi", "dns", "rpc")):
        sensors.append({
            "sensor_id": "etw." + name,
            "kind": "agent",
            "provider": name,
            "implementation": "agent/etw.cpp",
            "expected_in": [name, "gameplay"],
            "status": "active",
        })
    sensors.append({
        "sensor_id": "etw.codeintegrity",
        "kind": "agent",
        "provider": "codeintegrity",
        "implementation": "agent/etw.cpp",
        "expected_in": [],
        "status": "active",
    })
    for name, implementation in (
        ("per_page_mmap", "section acquire only; no page-fault callbacks"),
        ("memory_ops", "no process-memory/APC/remote-thread callbacks"),
        ("ui_clipboard_input", "no UI/clipboard/input sensor"),
        ("broker_com", "no broker/COM/DPAPI correlation"),
        ("tls_plaintext", "no TLS plaintext"),
        ("direct_hardware", "no direct firmware/port/MSR sensor"),
    ):
        sensors.append({
            "sensor_id": "blind_spot." + name,
            "kind": "blind_spot",
            "implementation": implementation,
            "expected_in": [],
            "status": "blind_spot",
        })
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps({"schema_version": 1, "sensors": sensors}, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUTPUT} with {len(sensors)} sensors")
    return 0


if __name__ == "__main__":
    sys.exit(main())
