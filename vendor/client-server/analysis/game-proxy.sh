#!/bin/bash
# Captures every connection the game family makes (MapleStory, the Nexon launcher,
# the anti-cheat, the overlay: every process of the Wine prefix) until Ctrl-C or SIGTERM.
#
#   analysis/game-proxy.sh [--policy FILE]
#
# 1. The proxy (python -m traffic proxy) starts on 127.0.0.1:$CS_PROXY_PORT.
# 2. A user scope cs-game-<stamp> is made, and every Wine program (wineserver, the
#    preloaders) whose environment has a WINEPREFIX in $CS_WINEPREFIX (colon-separated;
#    default ~/.wine-nexon:~/.wine-nexon-2, the two scrapers' games on :5 and :6)
#    is moved into it within half a second of starting
#    (already-running ones too). Wine's sockets are created by wineserver, so a
#    socket belongs to the scope once wineserver is in it.
# 3. nftables, tables ip cs_proxy and inet cs_capture:
#    - every IPv4 TCP connection from the scope, any port, goes through the proxy
#      (recorded, decoded, policy); TCP to ports $CS_PROXY_PORTS from any process
#      too, so a game connection made before adoption is still caught;
#    - every other packet of the scope, both ways (UDP: DNS, QUIC, the 8913 ping,
#      ...; ICMP; all IPv6), is copied to nflog group $CS_NFLOG_GROUP (7) and written by dumpcap to
#      captures/proxy-<stamp>-other.pcap.
# 4. On exit the rules go first (new connections go straight to the server), dumpcap
#    stops, and the proxy takes no new connections but keeps the open ones until they
#    end (the game's next channel change); a second Ctrl-C cuts them. Starting this
#    script again meanwhile is fine. If the proxy dies with the rules in
#    place, new connections from the game are refused (fail closed); running this
#    script again or `sudo nft delete table ip cs_proxy` clears it.
# Loopback (127.0.0.0/8, ::1) is local IPC between the game's own programs, not
# client-server traffic, and is not taken. IPv6 TCP is only copied to the pcap,
# not proxied, so a policy cannot refuse it.
set -euo pipefail
umask 077

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
PORTS=${CS_PROXY_PORTS:-8400-8999}
PORT=${CS_PROXY_PORT:-18400}
IFS=: read -ra PREFIX_LIST <<< "${CS_WINEPREFIX:-$HOME/.wine-nexon:$HOME/.wine-nexon-2}"
PREFIX=$(for p in "${PREFIX_LIST[@]}"; do realpath -m "$p"; done | paste -sd'|')   # (an alternation for grep -E)
# Only Wine's own programs: a browser Wine opens (the scraper's sign-in Chrome) inherits WINEPREFIX too.
WINESERVER=$(command -v wineserver) || { echo "wineserver is not in PATH" >&2; exit 1; }
WINE_DIR=$(dirname "$(dirname "$(realpath "$WINESERVER")")")
MARK=0x4353      # the proxy's own server connections carry this mark and are not redirected
CTMARK=0x4347    # connections of the game scope, for the capture of their replies
NFLOG_GROUP=${CS_NFLOG_GROUP:-7}
STAMP=$(date +%Y%m%d-%H%M%S)
RECORDING="$ROOT/captures/proxy-$STAMP.jsonl"
PCAP="$ROOT/captures/proxy-$STAMP-other.pcap"
SCOPE=cs-game-$STAMP.scope
CGROUP_REL="user.slice/user-$(id -u).slice/user@$(id -u).service/app.slice/$SCOPE"
CGROUP="/sys/fs/cgroup/$CGROUP_REL"
PYTHON="$ROOT/.venv/bin/python"
[[ -x $PYTHON ]] || PYTHON=python3
ARGS=()
if [[ ${1:-} == "--policy" && -f ${2:-} ]]; then
    ARGS=(--policy "$(realpath "$2")")
elif (( $# )); then
    echo "Usage: analysis/game-proxy.sh [--policy FILE]" >&2
    exit 2
fi

say() { echo "$(date '+%F %T') $*" >&2; }
sudo nft delete table ip cs_proxy 2>/dev/null || true      # left by an earlier crash
sudo nft delete table inet cs_capture 2>/dev/null || true
mkdir -p "$ROOT/captures"
cd "$ROOT"
PIDS=()
stop() {
    # Rules first: from now on new connections go straight to the server. Connections already
    # open through the proxy are left to end on their own (cutting the game's channel connection
    # drops it to its login screen: 2026-11-15 13:21); a second Ctrl-C or SIGTERM cuts them.
    trap - EXIT INT TERM
    sudo nft delete table ip cs_proxy 2>/dev/null && say "redirect removed: new connections go straight to the server"
    sudo nft delete table inet cs_capture 2>/dev/null || true
    for pid in "${PIDS[@]:1}"; do sudo kill -TERM "$pid" 2>/dev/null || true; done
    sudo kill -TERM "${PIDS[0]}" 2>/dev/null || true
    trap 'say "cutting the connections still open"; sudo kill -TERM "${PIDS[0]}" 2>/dev/null || true' INT TERM
    while kill -0 "${PIDS[0]}" 2>/dev/null; do wait "${PIDS[0]}" 2>/dev/null || true; done
    say "stopped; recording $RECORDING, other packets $PCAP"
}
trap stop EXIT INT TERM

# 1. the proxy: as this user, with only CAP_NET_ADMIN (to set SO_MARK) added
sudo setpriv --reuid="$(id -u)" --regid="$(id -g)" --init-groups \
    --inh-caps=+net_admin --ambient-caps=+net_admin \
    "$PYTHON" -m traffic proxy --listen "127.0.0.1:$PORT" --file "$RECORDING" \
    --mark "$MARK" "${ARGS[@]}" </dev/null &
PIDS+=($!)
for _ in $(seq 50); do
    ss -Hltn "sport = :$PORT" | grep -q . && break
    kill -0 "${PIDS[0]}" 2>/dev/null || { say "the proxy did not start"; exit 1; }
    sleep 0.1
done
ss -Hltn "sport = :$PORT" | grep -q . || { say "the proxy is not listening on $PORT"; exit 1; }

# 2. the scope, held by a sleep, and the adopter
systemd-run --user --scope --unit="$SCOPE" --quiet sleep infinity </dev/null &
PIDS+=($!)
for _ in $(seq 50); do [[ -d $CGROUP ]] && break; sleep 0.1; done
[[ -d $CGROUP ]] || { say "scope $SCOPE was not made"; exit 1; }
adopt() {
    local failed=""
    while sleep 0.5; do
        for env in $(grep -lzE "^WINEPREFIX=($PREFIX)/?$" /proc/[0-9]*/environ 2>/dev/null); do
            pid=${env#/proc/}; pid=${pid%/environ}
            exe=$(readlink "/proc/$pid/exe" 2>/dev/null) || continue
            [[ $exe == "$WINE_DIR"/* && ${exe##*/} =~ ^(wineserver|wine(64)?(-preloader)?)$ ]] || continue
            grep -qF "$SCOPE" "/proc/$pid/cgroup" 2>/dev/null && continue
            if echo "$pid" > "$CGROUP/cgroup.procs" 2>/dev/null; then
                say "adopted $pid $(cat "/proc/$pid/comm" 2>/dev/null)"
            elif [[ " $failed " != *" $pid "* ]]; then
                failed+=" $pid"
                say "COULD NOT ADOPT $pid $(cat "/proc/$pid/comm" 2>/dev/null) ($(cat "/proc/$pid/cgroup")): its traffic is not captured, only TCP to ports $PORTS"
            fi
        done
    done
}
adopt &
PIDS+=($!)

# 3. the capture of everything that is not proxied, then the rules
# (dumpcap, not tcpdump: Ubuntu's AppArmor profile for tcpdump refuses signals from a confined caller, sudo or
# not, so a tcpdump started from such a session can't be stopped, and it keeps the nflog group: 2026-11-15 13:35)
# (as this user with only the capture capabilities: dumpcap run as root drops to an unprivileged user and then
# can't write into captures/, which is 0700)
sudo setpriv --reuid="$(id -u)" --regid="$(id -g)" --init-groups \
    --inh-caps=+net_admin,+net_raw --ambient-caps=+net_admin,+net_raw \
    dumpcap -q -P -i "nflog:$NFLOG_GROUP" -w "$PCAP" 2>>"$ROOT/captures/proxy-$STAMP-dumpcap.log" </dev/null &
PIDS+=($!)
sleep 0.5
kill -0 "${PIDS[-1]}" 2>/dev/null || { say "dumpcap did not start: $(cat "$ROOT/captures/proxy-$STAMP-dumpcap.log")"; exit 1; }
sudo nft -f - <<EOF
table ip cs_proxy {
    chain output {
        type nat hook output priority dstnat; policy accept;
        meta mark $MARK return
        ip daddr 127.0.0.0/8 return
        socket cgroupv2 level 5 "$CGROUP_REL" meta l4proto tcp redirect to :$PORT
        tcp dport $PORTS redirect to :$PORT
    }
}
table inet cs_capture {
    chain output {
        type filter hook output priority filter; policy accept;
        oifname "lo" return
        socket cgroupv2 level 5 "$CGROUP_REL" ct mark set ct mark or $CTMARK
        ct mark and $CTMARK == $CTMARK meta nfproto ipv4 meta l4proto tcp return
        ct mark and $CTMARK == $CTMARK log group $NFLOG_GROUP
    }
    chain input {
        type filter hook input priority filter; policy accept;
        iifname "lo" return
        ct mark and $CTMARK == $CTMARK meta nfproto ipv4 meta l4proto tcp return
        ct mark and $CTMARK == $CTMARK log group $NFLOG_GROUP
    }
}
EOF
say "capturing: TCP of $SCOPE and TCP to ports $PORTS through 127.0.0.1:$PORT -> $RECORDING;"
say "  everything else of $SCOPE -> $PCAP (Ctrl-C stops)"
wait "${PIDS[0]}"
