#!/bin/bash
# Which Windows module of the game family makes each network send, for SECONDS (default 600).
#
#   analysis/capture-senders.sh [SECONDS]
#   .venv/bin/python analysis/senders-report.py captures/senders-<stamp>.log [--recording captures/proxy-*.jsonl]
#
# Uses monitor-filter's kfilter (KFILTER_DIR, default ~/monitor-filter/filter/build/linux) in
# audit mode with analysis/senders-policy.txt: nothing is denied. Loading the policy also tracks
# the game's programs that are already running, so the game need not restart. Each send is logged
# as `send tcp <ip>:<port> ... caller=<module>+<offset>` (the first module on the Windows stack that
# is not Wine's; none when the code is outside every loaded module).
# If kfilterd was not running, it is stopped again at the end (`kfilterctl stop`); a kfilterd
# that was already running (another session's) keeps running, and its policy is NOT restored:
# the script refuses to run then.
set -euo pipefail
umask 077

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
K=${KFILTER_DIR:-$HOME/monitor-filter/filter/build/linux}
SECONDS_TO_WATCH=${1:-600}
[[ $SECONDS_TO_WATCH =~ ^[0-9]+$ ]] || { echo "Usage: analysis/capture-senders.sh [SECONDS]" >&2; exit 2; }
LOG="$ROOT/captures/senders-$(date +%Y%m%d-%H%M%S).log"
mkdir -p "$ROOT/captures"

if pgrep -x kfilterd >/dev/null; then
    echo "kfilterd is already running (another run or session): not touching its policy" >&2
    exit 1
fi
sudo "$K/kfilterctl" check "$ROOT/analysis/senders-policy.txt" >/dev/null
stop() { trap - EXIT INT TERM; sudo "$K/kfilterctl" stop >/dev/null 2>&1 && echo "kfilter stopped" >&2; }
trap stop EXIT INT TERM
(setsid sudo "$K/kfilterd" >"$LOG.kfilterd" 2>&1 </dev/null &)
for _ in $(seq 60); do sudo "$K/kfilterctl" status >/dev/null 2>&1 && break; sleep 0.5; done
sudo "$K/kfilterctl" policy "$ROOT/analysis/senders-policy.txt" >&2
echo "recording sends for $SECONDS_TO_WATCH s to $LOG" >&2
sudo timeout $((SECONDS_TO_WATCH + 30)) "$K/kfilterctl" watch "$SECONDS_TO_WATCH" >"$LOG" || true
sudo "$K/kfilterctl" status | grep -E "decisions|dropped" >&2
