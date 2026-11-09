#!/bin/bash
set -euo pipefail
umask 077

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
DURATION=${1:-600}
if ! [[ $DURATION =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    echo "Usage: analysis/replay-rng-drops.sh [SECONDS]" >&2
    exit 1
fi

STAMP=$(date +%Y%m%d-%H%M%S)
OUTPUT="$ROOT/captures/rng-drops-$STAMP-$$.json"
DRIVER="$ROOT/captures/rng-drops-$STAMP-$$.log"
OWNER=${SUDO_USER:-$USER}
GROUP=$(id -gn "$OWNER")

sudo -v
mkdir -p "$ROOT/captures"
chmod 700 "$ROOT/captures"
cleanup() {
    for path in "$OUTPUT" "$DRIVER"; do
        if [[ -f $path ]]; then
            sudo -n chown "$OWNER:$GROUP" "$path"
        fi
    done
}
trap cleanup EXIT

echo "Auto-detecting the current MapleStory PID. Leave MapleStory running."
echo "Recording 100 damaging attacks with the same fixed critical RNG state; no control attacks."
set +e
sudo -n env TRACE_DROPS=1 FIXED_ONLY=1 PYTHONDONTWRITEBYTECODE=1 \
    "$ROOT/.venv/bin/python" -u "$ROOT/tools/damage-rng.py" replay \
    --words 0x178e8921 0xa8fc3ce8 0x000000e4 \
    --replays 100 --seconds "$DURATION" --output "$OUTPUT" \
    2>&1 | tee "$DRIVER"
STATUS=${PIPESTATUS[0]}
set -e
printf 'Result: %s\nTerminal log: %s\n' "$OUTPUT" "$DRIVER"
exit "$STATUS"
