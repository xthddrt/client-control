#!/bin/bash
set -euo pipefail
umask 077

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
DURATION=${1:-60}
if (( $# )); then
    shift
fi
DEEP_ARGS=()
DROP_ARGS=()
while (( $# )); do
    if [[ $1 == "--drop-opcode" && $# -ge 2 && $2 =~ ^(0[xX][0-9a-fA-F]+|[0-9]+)$ && ${#DROP_ARGS[@]} -eq 0 ]]; then
        DROP_ARGS=("$1" "$2")
        shift 2
        continue
    fi
    if [[ $1 != "--deep-opcode" || $# -lt 2 || ! $2 =~ ^(0[xX][0-9a-fA-F]+|[0-9]+)$ ]]; then
        echo "Usage: tools-QUARANTINE/capture-outgoing.sh [SECONDS] [--deep-opcode HEX ...] [--drop-opcode HEX]" >&2
        exit 2
    fi
    DEEP_ARGS+=("$1" "$2")
    shift 2
done
if ! [[ $DURATION =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    echo "Usage: tools-QUARANTINE/capture-outgoing.sh [SECONDS] [--deep-opcode HEX ...] [--drop-opcode HEX]" >&2
    exit 2
fi

STAMP=$(date +%Y%m%d-%H%M%S)
PCAP="$ROOT/captures/outgoing-session-$STAMP.pcap"
EVENTS="$ROOT/captures/outgoing-events-$STAMP.jsonl"
DRIVER="$ROOT/captures/outgoing-driver-$STAMP.log"
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
    printf 'Deep arguments: %s\n' "${DEEP_ARGS[*]-}"
    printf 'Drop arguments: %s\n' "${DROP_ARGS[*]-}"
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

echo "Capturing MapleStory PID $PID for $DURATION seconds."
echo "Packet events: $EVENTS"
echo "Raw PCAP: $PCAP"
if [[ ${#DROP_ARGS[@]} -ne 0 ]]; then
    echo "Filtering only ${DROP_ARGS[1]}; every other outgoing packet passes. Incoming PCAP is unchanged."
fi
set +e
sudo -n env PYTHONDONTWRITEBYTECODE=1 \
    "$ROOT/.venv/bin/python" -u "$ROOT/tools-QUARANTINE/outgoing-packet-capture.py" \
    "$PID" "$DURATION" "$EVENTS" "${DEEP_ARGS[@]}" "${DROP_ARGS[@]}" 2>&1 | tee -a "$DRIVER"
STATUS=${PIPESTATUS[0]}
set -e
cleanup
trap - EXIT INT TERM
printf 'Packet log: %s\nPCAP: %s\nDriver log: %s\n' "$EVENTS" "$PCAP" "$DRIVER"
exit "$STATUS"
