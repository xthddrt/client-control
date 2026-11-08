#!/bin/bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
DURATION=${1:-120}
TEST_MODE=${TEST_MODE:-0}
DUPLICATE_32B=${DUPLICATE_32B:-0}
if [[ $DUPLICATE_32B != 0 && $DUPLICATE_32B != 1 ]]; then
    echo "DUPLICATE_32B must be 0 or 1." >&2
    exit 1
fi
if [[ $DUPLICATE_32B == 1 && $TEST_MODE != 0 ]]; then
    echo "DUPLICATE_32B cannot be combined with TEST_MODE field experiments." >&2
    exit 1
fi
case "$TEST_MODE" in
    0) ;;
    1) echo "TEST_MODE=1: double meso in 0x471; pickup remains native." ;;
    2|3|4|5|6|7|8|9|10|11)
        echo "TEST_MODE=$TEST_MODE: native pickup, then increment the selected 0x32b field by one."
        echo "The drop object ID at 0x0f is not changed; this is a metadata-trust experiment." ;;
    12) echo "TEST_MODE=12: zero one nonzero 0x3f3+6 value; object ID unchanged." ;;
    *) echo "TEST_MODE must be 0, 1, 2 through 11, or 12." >&2; exit 1 ;;
esac
if [[ $DUPLICATE_32B == 1 ]]; then
    echo "DUPLICATE_32B=1: duplicate only the first pickup after the original send returns."
fi
STAMP=$(date +%Y%m%d-%H%M%S)
OUTPUT="$ROOT/captures/packets-$STAMP.jsonl"
DRIVER="$ROOT/captures/packets-$STAMP.log"
OWNER=${SUDO_USER:-$USER}
GROUP=$(id -gn "$OWNER")

if ! [[ $DURATION =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    echo "Usage: tools-QUARANTINE/capture-packets.sh [SECONDS]" >&2
    exit 1
fi
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
trap cleanup EXIT INT TERM

echo "Starting plaintext packet observation for $DURATION seconds. Leave MapleStory running."
echo "The terminal prints ARMED when recording starts, then traffic summaries every five seconds."
set +e
sudo -n env TEST_MODE="$TEST_MODE" DUPLICATE_32B="$DUPLICATE_32B" PYTHONDONTWRITEBYTECODE=1 \
    "$ROOT/.venv/bin/python" -u "$ROOT/tools-QUARANTINE/packet-observe.py" \
    auto "$DURATION" "$OUTPUT" 2>&1 | tee "$DRIVER"
STATUS=${PIPESTATUS[0]}
set -e
printf 'Packet log: %s\nDriver log: %s\n' "$OUTPUT" "$DRIVER"
exit "$STATUS"
