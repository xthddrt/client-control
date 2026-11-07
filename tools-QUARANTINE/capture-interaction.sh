#!/bin/bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
DURATION=${1:-120}
STAMP=$(date +%Y%m%d-%H%M%S)
PCAP="$ROOT/captures/interaction-session-$STAMP.pcap"
EVENTS="$ROOT/captures/interaction-events-$STAMP.jsonl"
DRIVER="$ROOT/captures/interaction-driver-$STAMP.log"
DECODE="$ROOT/captures/interaction-decode-$STAMP.log"
OWNER=${SUDO_USER:-$USER}
GROUP=$(id -gn "$OWNER")

sudo -v
mapfile -t PIDS < <(pgrep -x MapleStory.exe)
if [[ ${#PIDS[@]} -ne 1 ]]; then
    echo "Expected exactly one running MapleStory.exe process; found ${#PIDS[@]}." >&2
    exit 1
fi
PID=${PIDS[0]}
mapfile -t ENDPOINTS < <(ss -tnp | awk '/MapleStory.exe/ {print $5}' | sort -u)
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
printf 'Capture filter: %s\n' "$FILTER" > "$DRIVER"
TCPDUMP_PID=""
cleanup() {
    if [[ -n $TCPDUMP_PID ]]; then
        sudo -n kill -INT "$TCPDUMP_PID" 2>/dev/null || true
        wait "$TCPDUMP_PID" 2>/dev/null || true
        TCPDUMP_PID=""
    fi
    for path in "$PCAP" "$EVENTS" "$DRIVER" "$DECODE" "$PCAP.decrypted.json"; do
        if [[ -f $path ]]; then
            sudo -n chown "$OWNER:$GROUP" "$path"
        fi
    done
}
trap cleanup EXIT INT TERM

sudo -n tcpdump -i any -nn -s0 -U -w "$PCAP" "$FILTER" >> "$DRIVER" 2>&1 &
TCPDUMP_PID=$!
sleep 2
if ! kill -0 "$TCPDUMP_PID" 2>/dev/null; then
    echo "tcpdump failed to start; see $DRIVER" >&2
    exit 1
fi

echo "Capturing MapleStory PID $PID and endpoints: ${ENDPOINTS[*]}"
echo "Full writable-memory diffs plus full-duplex packets. Kill a mob and pick up its item within ${DURATION}s."
if sudo -n env PYTHONDONTWRITEBYTECODE=1 \
    "$ROOT/.venv/bin/python" -u "$ROOT/tools-QUARANTINE/drop-observe.py" \
    --full-memory "$PID" "$DURATION" "$EVENTS"; then
    STATUS=0
else
    STATUS=$?
fi
cleanup
trap - EXIT INT TERM

if "$ROOT/.venv/bin/python" "$ROOT/tools-QUARANTINE/wire-session-decrypt.py" "$PCAP" > "$DECODE" 2>&1; then
    echo "Offline decryption finished: $PCAP.decrypted.json"
else
    echo "Offline decryption needs review: $DECODE" >&2
fi
for path in "$PCAP" "$EVENTS" "$DRIVER" "$DECODE" "$PCAP.decrypted.json"; do
    if [[ -f $path ]]; then
        sudo -n chown "$OWNER:$GROUP" "$path"
    fi
done
exit "$STATUS"
