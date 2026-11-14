# Packet capture (packets upgrade). Sourced by tests/linux_ebpf_test.sh; check_packets.py checks the pcapng.
# packets_end: the mm_skb_* cgroup links must be gone from the root cgroup after the agents exit, also
# after a kill -9 (the kernel detaches a link when its fd closes). Needs bpftool.
packets_session() { :; }

packets_attached() {
    "$packets_bpftool" cgroup show /sys/fs/cgroup 2>/dev/null | grep -q "mm_skb_"
}

packets_end() {
    packets_bpftool=$(command -v bpftool || { [ -x /usr/sbin/bpftool ] && echo /usr/sbin/bpftool; } || true)
    [ -n "$packets_bpftool" ] || { echo "packets: no bpftool, detach check skipped"; return; }
    if packets_attached; then echo "FAIL packets: mm_skb_* still attached to /sys/fs/cgroup after the sessions"; fail=1; fi
    packets_log="$work/packets-kill.log"
    build/linux/msmon-agent --scope-root "$work/ebpf/scope" --output "$work/packets-kill.jsonl" --no-etw >"$packets_log" 2>&1 &
    packets_agent=$!
    for _ in $(seq 1 60); do grep -q Registered "$packets_log" && break; sleep 0.5; done
    "$packets_bpftool" cgroup show /sys/fs/cgroup 2>/dev/null | grep -q "mm_skb_egress" ||
        { echo "FAIL packets: mm_skb_egress not attached to /sys/fs/cgroup while the agent runs"; fail=1; }
    kill -9 "$packets_agent"
    wait "$packets_agent" 2>/dev/null
    sleep 1
    if packets_attached; then echo "FAIL packets: mm_skb_* still attached after kill -9 of the agent"; fail=1; fi
}
