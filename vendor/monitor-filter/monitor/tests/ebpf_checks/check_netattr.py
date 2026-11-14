"""The netattr upgrade's checks (the socket join), called by tests/linux_ebpf_test.sh check(): the probe's
child used a socket its parent connected (probe_netattr.h), so it must have a service_correlated
network_flow_established at its first sendmsg and a network_flow_close with its own bytes (a MSG_PEEK
recvmsg counts nothing) when the parent closed the socket, both with value0 the inode of the parent's
network_connect. The fallback (--no-ebpf) has no join."""
import re


def check(mode, path, events, mine, pids, coverage, problems):
    if mode == "fallback":
        return

    def count(e, key):
        found = re.search(r"(?:^|;)" + key + r"=(\d+)", e["detail"])
        return int(found.group(1)) if found else -1

    # The inodes the probe connected to 127.0.0.1 (value0), by connecting process: the join's pairing key.
    connects = {(e["process_id"], e["value0"]) for e in mine
                if e["type"] == "network_connect" and e["text"].startswith("127.0.0.1:") and e["value0"]}
    joined = [e for e in mine if e.get("flags", 0) & 0x10 and e.get("attribution") == "service_correlated"
              and (count(e, "creator_pid"), e["value0"]) in connects]
    opened = {e["value0"] for e in joined if e["type"] == "network_flow_established" and
              e["text"].startswith("127.0.0.1:") and "first_use=sendmsg;" in e["detail"]}
    if not opened:
        problems.append("netattr: no service_correlated network_flow_established (value0 its parent's connect inode)"
                        " for the child using its parent's socket")
    if not any(e["type"] == "network_flow_close" and e["value0"] in opened and "reason=socket_closed" in e["detail"]
               and count(e, "bytes_sent") == 18 and count(e, "bytes_received") == 3 for e in joined):
        problems.append("netattr: no service_correlated network_flow_close with the established flow's value0 and the"
                        " child's 18 bytes sent and 3 received")
    if "socket_join" not in coverage:
        problems.append("netattr: no socket_join coverage record")
