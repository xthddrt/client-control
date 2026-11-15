#!/bin/bash
set -euo pipefail
umask 077

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
PYTHON="$ROOT/.venv/bin/python"
PROFILE="$ROOT/foundations/grap-core-profile.json"
if (( $# < 1 || $# > 3 )); then
    echo "Usage: $0 CORE_PID [SECONDS] [OUTPUT_DIRECTORY]" >&2
    exit 2
fi
PID=$1
DURATION=${2:-120}
OUTPUT=${3:-$ROOT/captures/grap-bitblt-$(date +%Y%m%d-%H%M%S)}
"$PYTHON" - "$DURATION" "$PID" "$PROFILE" <<'PY'
import json, math, os, sys
seconds = float(sys.argv[1])
pid = int(sys.argv[2])
if not math.isfinite(seconds) or seconds <= 0:
    raise SystemExit("SECONDS must be finite and positive")
with open(f"/proc/{pid}/comm") as stream:
    if stream.read().strip() != "grap-core64.aes":
        raise SystemExit("PID is not a live grap-core64.aes process")
if not os.path.isfile(sys.argv[3]):
    raise SystemExit("GRAP profile is missing")
PY

mkdir -p "$OUTPUT"
TARGET=$(sudo -n "$PYTHON" - "$PID" "$PROFILE" <<'PY'
import json, os, struct, sys
pid = int(sys.argv[1])
profile = json.load(open(sys.argv[2]))
bases = set()
with open(f"/proc/{pid}/maps") as stream:
    for line in stream:
        parts = line.split()
        if len(parts) == 6 and int(parts[2], 16) == 0 and parts[5].endswith("/" + profile["process_name"]):
            bases.add(int(parts[0].split("-")[0], 16))
if len(bases) != 1:
    raise SystemExit(f"Expected one core image base, found {list(bases)}")
base = bases.pop()
with open(f"/proc/{pid}/mem", "rb", buffering=0) as stream:
    target = struct.unpack("<Q", os.pread(stream.fileno(), 8, base + int(profile["rvas"]["bitblt_iat"], 0)))[0]
print(hex(target))
PY
)

children=()
cleanup() {
    for child in ${children[@]+"${children[@]}"}; do
        kill -TERM "$child" 2>/dev/null || true
    done
    for child in ${children[@]+"${children[@]}"}; do
        wait "$child" 2>/dev/null || true
    done
}
trap cleanup EXIT INT TERM
for task in /proc/"$PID"/task/*; do
    [[ -d $task ]] || continue
    tid=${task##*/}
    sudo -n "$PYTHON" "$ROOT/analysis/debug-watch.py" "$tid" "$TARGET" "$DURATION" \
        "$OUTPUT/tid-$tid.json" --execute --profile "$PROFILE" > "$OUTPUT/tid-$tid.log" 2>&1 &
    children+=("$!")
done
failures=0
for child in "${children[@]}"; do
    if ! wait "$child"; then
        failures=$((failures + 1))
    fi
done
children=()
"$PYTHON" - "$OUTPUT" "$TARGET" "$DURATION" "$failures" <<'PY'
import json, os, pathlib, sys
output = pathlib.Path(sys.argv[1])
rows = []
for path in sorted(output.glob("tid-*.json")):
    row = json.loads(path.read_text())
    rows.append({"file": path.name, "pid": row["pid"], "watch_hits": row["watch_hits"],
                 "matched_events": row["matched_events"], "error": row["error"]})
result = {
    "schema": "client-control.grap-bitblt-watch.v1",
    "target": sys.argv[2], "api": "BitBlt", "duration_seconds": float(sys.argv[3]),
    "coverage": "threads_present_at_launch_only",
    "threads": rows, "failures": int(sys.argv[4]),
    "watch_hits": sum(row["watch_hits"] for row in rows),
    "matched_events": sum(row["matched_events"] for row in rows),
    "screenshot_or_upload_proven": False,
    "note": "A BitBlt call is not by itself proof of surveillance or upload. No image or screen contents were read."
}
with os.fdopen(os.open(output / "summary.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
print(json.dumps(result, indent=2))
if result["failures"] or any(row["error"] for row in rows):
    raise SystemExit(1)
PY
