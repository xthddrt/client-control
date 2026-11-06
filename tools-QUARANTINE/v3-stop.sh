#!/bin/bash
set -euo pipefail

IPTABLES=/usr/sbin/iptables
CHAIN=MSCW_NGS_SHIELD
STATE=/run/mscw-ngs-shield.pid

if (( EUID != 0 )); then
    exec sudo -- "$(readlink -f "$0")"
fi

if [[ -r $STATE ]]; then
    read -r pid < "$STATE" || true
    if [[ ${pid:-} =~ ^[0-9]+$ ]] && [[ -r /proc/$pid/cmdline ]]; then
        cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline")
        if [[ $cmdline == *shield-blackout-v3.sh* ]]; then
            kill -INT "$pid"
            for _ in {1..50}; do
                kill -0 "$pid" 2>/dev/null || break
                sleep 0.1
            done
        fi
    fi
fi

while $IPTABLES -C OUTPUT -j "$CHAIN" >/dev/null 2>&1; do
    $IPTABLES -D OUTPUT -j "$CHAIN"
done
if $IPTABLES -L "$CHAIN" -n >/dev/null 2>&1; then
    $IPTABLES -nvL "$CHAIN"
    $IPTABLES -F "$CHAIN"
    $IPTABLES -X "$CHAIN"
fi
rm -f "$STATE"
echo "Shield v3 stopped; firewall rules removed."
