#!/bin/bash
set -euo pipefail
umask 077

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
DURATION=${1:-60}
if (( $# )); then
    shift
fi
if (( $# > 1 )) || [[ $# -eq 1 && $1 != "--fresh-tick" ]]; then
    echo "Usage: analysis/replay-32b.sh [SECONDS] [--fresh-tick]" >&2
    exit 2
fi
MODE_ARGS=("$@")
if ! [[ $DURATION =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    echo "Usage: analysis/replay-32b.sh [SECONDS] [--fresh-tick]" >&2
    exit 2
fi

STAMP=$(date +%Y%m%d-%H%M%S)
PCAP="$ROOT/captures/replay-32b-session-$STAMP.pcap"
EVENTS="$ROOT/captures/replay-32b-events-$STAMP.json"
DRIVER="$ROOT/captures/replay-32b-driver-$STAMP.log"
OWNER=${SUDO_USER:-$USER}
GROUP=$(id -gn "$OWNER")

sudo -v
mapfile -t PIDS < <(pgrep -x MapleStory.exe)
if [[ ${#PIDS[@]} -ne 1 ]]; then
    echo "Expected exactly one running MapleStory.exe process; found ${#PIDS[@]}." >&2
    exit 1
fi
PID=${PIDS[0]}
mapfile -t ENDPOINTS < <(sudo -n ss -tnp | awk '/MapleStory.exe/ {print $5}' | sort -u)
if [[ ${#ENDPOINTS[@]} -eq 0 ]]; then
    echo "No active MapleStory TCP endpoints found." >&2
    exit 1
fi
mapfile -t PORTS < <(printf '%s\n' "${ENDPOINTS[@]##*:}" | sort -u)
FILTER="tcp and ("
for port in "${PORTS[@]}"; do
    FILTER+="port ${port} or "
done
FILTER="${FILTER% or })"

mkdir -p "$ROOT/captures"
chmod 700 "$ROOT/captures"
{
    printf 'PID: %s\n' "$PID"
    printf 'Endpoints: %s\n' "${ENDPOINTS[*]}"
    printf 'Capture filter: %s\n' "$FILTER"
} > "$DRIVER"

TCPDUMP_PID=""
cleanup() {
    if [[ -n $TCPDUMP_PID ]]; then
        sudo -n kill -INT "$TCPDUMP_PID" 2>/dev/null || true
        wait "$TCPDUMP_PID" 2>/dev/null || true
        TCPDUMP_PID=""
    fi
    for path in "$PCAP" "$EVENTS" "$DRIVER"; do
        if [[ -f $path ]]; then
            sudo -n chown "$OWNER:$GROUP" "$path"
        fi
    done
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

sudo -n tcpdump -i any -nn -s0 -U -w "$PCAP" "$FILTER" >> "$DRIVER" 2>&1 &
TCPDUMP_PID=$!
sleep 2
if ! kill -0 "$TCPDUMP_PID" 2>/dev/null; then
    echo "tcpdump failed to start; see $DRIVER" >&2
    exit 1
fi

echo "Perform exactly one pickup within $DURATION seconds. Its 0x32b will be sent twice."
set +e
sudo -n env PYTHONDONTWRITEBYTECODE=1 \
    "$ROOT/.venv/bin/python" -u "$ROOT/analysis/replay-32b.py" \
    auto "$DURATION" "$EVENTS" "${MODE_ARGS[@]}" 2>&1 | tee -a "$DRIVER"
STATUS=${PIPESTATUS[0]}
set -e
sleep 1
cleanup
trap - EXIT INT TERM
printf 'Replay and inbound response log: %s\nPCAP: %s\nDriver log: %s\n' "$EVENTS" "$PCAP" "$DRIVER"
exit "$STATUS"
