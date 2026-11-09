#!/bin/bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
OUTPUT="$ROOT/captures/rng-100.jsonl"
COUNT=${1:-100}
OWNER=${SUDO_USER:-$USER}
GROUP=$(id -gn "$OWNER")

mkdir -p "$ROOT/captures"
chmod 700 "$ROOT/captures"

if sudo env PYTHONDONTWRITEBYTECODE=1 \
    "$ROOT/.venv/bin/python" "$ROOT/analysis/rng-dataset.py" \
    auto 1800 "$OUTPUT" "$COUNT"; then
    STATUS=0
else
    STATUS=$?
fi

if [[ -f $OUTPUT ]]; then
    sudo chown "$OWNER:$GROUP" "$OUTPUT"
fi
exit "$STATUS"
