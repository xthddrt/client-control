#!/bin/bash
set -euo pipefail
umask 077

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
MITMDUMP="$ROOT/.venv/bin/mitmdump"
PREFIX="$HOME/.wine-nexon"
LAUNCHER="$PREFIX/drive_c/Program Files (x86)/Nexon/Nexon Launcher/nexon_launcher.exe"
CA_SOURCE="$HOME/.mitmproxy/mitmproxy-ca-cert.pem"
CA_TARGET="$PREFIX/drive_c/mitm-ca.pem"
STAMP=$(date +%Y%m%d-%H%M%S)
CAPTURES="$ROOT/captures"
FLOWS="$CAPTURES/ngs-flows-$STAMP.mitm"
EVENTS="$CAPTURES/ngs-events-$STAMP.jsonl"
PROXY_LOG="$CAPTURES/ngs-proxy-$STAMP.log"

if pgrep -f 'nexon_launcher.exe|nexon_client.exe|nexon_runtime.exe|MapleStory.exe' >/dev/null; then
    echo "Close MapleStory and the Nexon launcher before starting the proxied session." >&2
    exit 1
fi
for required in "$MITMDUMP" "$LAUNCHER"; do
    if [[ ! -f $required ]]; then
        echo "Required file is missing: $required" >&2
        exit 1
    fi
done
mkdir -p "$CAPTURES"

"$MITMDUMP" -s "$ROOT/analysis/ngs-mitm.py" \
    --listen-host 127.0.0.1 --listen-port 8080 \
    --set connection_strategy=lazy \
    --set ngs_neutralize=true --set ngs_log="$EVENTS" \
    -w "$FLOWS" > "$PROXY_LOG" 2>&1 &
PROXY_PID=$!
cleanup() {
    kill "$PROXY_PID" 2>/dev/null || true
    wait "$PROXY_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM
sleep 3
if ! kill -0 "$PROXY_PID" 2>/dev/null; then
    echo "mitmproxy failed to start; see $PROXY_LOG" >&2
    exit 1
fi
if [[ ! -f $CA_SOURCE ]]; then
    echo "mitmproxy did not create its CA certificate: $CA_SOURCE" >&2
    exit 1
fi
cp "$CA_SOURCE" "$CA_TARGET"

echo "Proxy active. Starting Nexon with NGS response neutralization."
echo "Event log: $EVENTS"
echo "Flow capture: $FLOWS"

export WINEPREFIX="$PREFIX"
export HTTP_PROXY=http://127.0.0.1:8080 HTTPS_PROXY=http://127.0.0.1:8080
export http_proxy=http://127.0.0.1:8080 https_proxy=http://127.0.0.1:8080
export REQUESTS_CA_BUNDLE='C:\mitm-ca.pem' CURL_CA_BUNDLE='C:\mitm-ca.pem'
export SSL_CERT_FILE='C:\mitm-ca.pem' NODE_EXTRA_CA_CERTS='C:\mitm-ca.pem'
unset NO_PROXY no_proxy
wine "$LAUNCHER"
echo "Nexon started; the proxy will remain active until you press Ctrl+C here."
while true; do
    sleep 3600
done
