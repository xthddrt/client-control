#!/bin/bash
set -euo pipefail

PROCESS_NAME=${1:-MapleStory.exe}
DRY_RUN=${2:-}
IPTABLES=/usr/sbin/iptables
CHAIN=MSCW_NGS_SHIELD
STATE=/run/mscw-ngs-shield.pid
SCRIPT_PATH=$(readlink -f "$0")

if [[ $DRY_RUN != "" && $DRY_RUN != "--dry-run" ]]; then
    echo "Usage: $0 [MapleStory.exe] [--dry-run]" >&2
    exit 2
fi

mapfile -t game_pids < <(pgrep -x -- "$PROCESS_NAME")
if [[ ${#game_pids[@]} != 1 ]]; then
    echo "Expected one $PROCESS_NAME process; found ${#game_pids[@]}." >&2
    exit 1
fi
GAME_PID=${game_pids[0]}
mapfile -t wineserver_pids < <(pgrep -x wineserver)
if [[ ${#wineserver_pids[@]} != 1 ]]; then
    echo "Expected one wineserver process; found ${#wineserver_pids[@]}." >&2
    exit 1
fi

cgroup_for_pid() {
    local line
    while IFS= read -r line; do
        if [[ $line == 0::* ]]; then
            printf '%s\n' "${line#0::}"
            return 0
        fi
    done < "/proc/$1/cgroup"
    return 1
}

declare -A cgroup_set=()
for path in "$(cgroup_for_pid "$GAME_PID")" "$(cgroup_for_pid "${wineserver_pids[0]}")"; do
    case "$path" in
        /user.slice/*/app.slice/*.scope) ;;
        *)
            echo "Refusing an unsafe or unsupported game cgroup: $path" >&2
            exit 1
            ;;
    esac
    if [[ ! -f "/sys/fs/cgroup$path/cgroup.procs" ]]; then
        echo "The game cgroup is not available: $path" >&2
        exit 1
    fi
    cgroup_set["${path#/}"]=1
done
mapfile -t CGROUPS < <(printf '%s\n' "${!cgroup_set[@]}" | sort)

if [[ $DRY_RUN == "--dry-run" ]]; then
    echo "DRY RUN: no firewall changes; game PID=$GAME_PID"
    for cgroup in "${CGROUPS[@]}"; do
        echo "REJECT game cgroup $cgroup tcp *:443"
        echo "REJECT game cgroup $cgroup tcp *:8484"
    done
    echo "Other application cgroups and game ports are not targets. Lower the shield before logout/login."
    exit 0
fi

if (( EUID != 0 )); then
    exec sudo -- "$SCRIPT_PATH" "$PROCESS_NAME"
fi
if $IPTABLES -L "$CHAIN" -n >/dev/null 2>&1; then
    echo "Shield chain already exists; run v3-stop.sh before raising it again." >&2
    exit 1
fi

created=0
cleanup() {
    if (( created )); then
        while $IPTABLES -C OUTPUT -j "$CHAIN" >/dev/null 2>&1; do
            $IPTABLES -D OUTPUT -j "$CHAIN"
        done
        $IPTABLES -F "$CHAIN" >/dev/null 2>&1 || true
        $IPTABLES -X "$CHAIN" >/dev/null 2>&1 || true
        created=0
    fi
    rm -f "$STATE"
    echo "Shield v3 stopped; firewall rules removed."
}
trap cleanup EXIT
trap 'exit 0' INT TERM

$IPTABLES -N "$CHAIN"
created=1
for cgroup in "${CGROUPS[@]}"; do
    $IPTABLES -A "$CHAIN" -p tcp -m cgroup --path "$cgroup" --dport 443 -m limit --limit 30/min --limit-burst 60 -j LOG --log-prefix "MSCW_NGS_SHIELD " --log-level 6
    $IPTABLES -A "$CHAIN" -p tcp -m cgroup --path "$cgroup" --dport 443 -j REJECT --reject-with tcp-reset
    $IPTABLES -A "$CHAIN" -p tcp -m cgroup --path "$cgroup" --dport 8484 -m limit --limit 30/min --limit-burst 60 -j LOG --log-prefix "MSCW_NGS_SHIELD " --log-level 6
    $IPTABLES -A "$CHAIN" -p tcp -m cgroup --path "$cgroup" --dport 8484 -j REJECT --reject-with tcp-reset
done
$IPTABLES -I OUTPUT 1 -j "$CHAIN"
printf '%s\n' "$$" > "$STATE"

echo "SHIELD ACTIVE: ${#CGROUPS[@]} game/Wine cgroups blocked on tcp/443 and tcp/8484; PID=$GAME_PID"
# The logout telemetry flush is synchronous; keep this block in-session only.
echo "Leave the game channels alone. Run v3-stop.sh before logout/login."
echo "View rate-limited block logs with: journalctl -k -g MSCW_NGS_SHIELD -f"
while kill -0 "$GAME_PID" 2>/dev/null; do
    sleep 2
done
