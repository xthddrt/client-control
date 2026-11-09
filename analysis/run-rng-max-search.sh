#!/bin/bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
CANDIDATES="$ROOT/captures/rng-max-100-candidates.json"
RESULTS="$ROOT/captures/rng-max-100-results.jsonl"
DRIVER="$ROOT/captures/rng-max-100-driver.log"
OWNER=${SUDO_USER:-$USER}
GROUP=$(id -gn "$OWNER")

if sudo env PYTHONDONTWRITEBYTECODE=1 \
    "$ROOT/.venv/bin/python" -u "$ROOT/analysis/rng-max-search.py" \
    run auto 1800 "$CANDIDATES" "$RESULTS" 2>&1 | tee "$DRIVER"; then
    STATUS=0
else
    STATUS=$?
fi

for path in "$RESULTS" "$DRIVER"; do
    if [[ -f $path ]]; then
        sudo chown "$OWNER:$GROUP" "$path"
    fi
done
exit "$STATUS"
