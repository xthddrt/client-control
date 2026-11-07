#!/bin/bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
exec env TEST_MODE=0 DUPLICATE_32B=1 "$ROOT/tools-QUARANTINE/capture-packets.sh" "$@"
