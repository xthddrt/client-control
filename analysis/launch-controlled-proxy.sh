#!/bin/bash
set -euo pipefail
umask 077

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
MITMDUMP="$ROOT/.venv/bin/mitmdump"
CA_SOURCE="$HOME/.mitmproxy/mitmproxy-ca-cert.pem"
PREFIX="$HOME/.wine-nexon"
CA_TARGET="$PREFIX/drive_c/mitm-ca.pem"
STAMP=$(date +%Y%m%d-%H%M%S)
OUTPUT="$ROOT/captures/controlled-$STAMP"
EVENTS="$OUTPUT/events.jsonl"
FLOWS="$OUTPUT/flows.mitm"
PROXY_LOG="$OUTPUT/proxy.log"
PROCESSES=${CONTROLLED_PROCESSES:-MapleStory.exe,grap-core64.aes,grap-communicator64.aes,nexon_client.exe,nexon_launcher.exe,nexon_runtime.exe,NGService.exe,python,python3}
OWNER=${SUDO_USER:-$USER}
GROUP=$(id -gn "$OWNER")
POLICY_ARGS=()
SCREENSHOT_ARGS=()
if [[ -n ${TRAFFIC_POLICY:-} ]]; then
    if [[ ! -r $TRAFFIC_POLICY ]]; then
        echo "Traffic policy is not readable: $TRAFFIC_POLICY" >&2
        exit 1
    fi
    POLICY_ARGS=(--set "traffic_policy=$TRAFFIC_POLICY")
fi
if [[ ${NGS_SCREENSHOT_FILTER:-0} == 1 ]]; then
    SCREENSHOT_ARGS=(--set ngs_screenshot_filter=true)
fi
if [[ ! -f $MITMDUMP || ! -f $CA_SOURCE ]]; then
    echo "Need $MITMDUMP and an existing $CA_SOURCE." >&2
    exit 1
fi
if pgrep -x mitmdump >/dev/null; then
    echo "Another mitmdump is running; do not replace its process-selection rules." >&2
    exit 1
fi
if [[ ! $PROCESSES =~ ^[A-Za-z0-9_.!*,/:-]+$ ]]; then
    echo "CONTROLLED_PROCESSES contains invalid characters." >&2
    exit 1
fi
mkdir -p "$OUTPUT"
cp "$CA_SOURCE" "$CA_TARGET"

cat > "$OUTPUT/session.json" <<EOF
{"schema":"client-control.controlled-proxy-session.v1","process_spec":"$PROCESSES","mode":"local","default_action":"allow","coverage":"selected local processes only; no claim of uninstrumented or kernel-path coverage","events":"$EVENTS","flows":"$FLOWS"}
EOF
cat > "$OUTPUT/env.sh" <<EOF
# Source before launching MapleMarket or the Nexon launcher.
export REQUESTS_CA_BUNDLE='C:\mitm-ca.pem'
export CURL_CA_BUNDLE='C:\mitm-ca.pem'
export SSL_CERT_FILE='C:\mitm-ca.pem'
export NODE_EXTRA_CA_CERTS='C:\mitm-ca.pem'
export CLIENT_CONTROL_SESSION='$OUTPUT'
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy
EOF

sudo -n env PYTHONDONTWRITEBYTECODE=1 "$MITMDUMP" \
    -s "$ROOT/analysis/controlled-proxy.py" \
    --mode "local:$PROCESSES" \
    --set confdir="$HOME/.mitmproxy" \
    --set rawtcp=true --set connection_strategy=lazy \
    --set "ngs_neutralize=${NGS_NEUTRALIZE:-false}" --set ngs_log="$EVENTS" \
    "${POLICY_ARGS[@]}" "${SCREENSHOT_ARGS[@]}" -w "$FLOWS" > "$PROXY_LOG" 2>&1 &
PROXY_PID=$!
cleanup() {
    kill -INT "$PROXY_PID" 2>/dev/null || true
    wait "$PROXY_PID" 2>/dev/null || true
    sudo -n chown -R "$OWNER:$GROUP" "$OUTPUT"
}
trap cleanup EXIT INT TERM
sleep 3
if ! kill -0 "$PROXY_PID" 2>/dev/null; then
    echo "Controlled proxy failed to start; see $PROXY_LOG" >&2
    exit 1
fi

echo "Controlled proxy active for: $PROCESSES"
echo "Events: $EVENTS"
echo "Flows: $FLOWS"
echo "Default: forward unchanged; NGS client requests receive an explicit decode trial."
echo "Environment for MapleMarket: source $OUTPUT/env.sh"
if (( $# )); then
    set +e
    "$@"
    STATUS=$?
    set -e
    exit "$STATUS"
fi
echo "Press Ctrl+C to stop the controlled proxy."
while true; do
    sleep 3600
done
