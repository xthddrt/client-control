#!/bin/bash
# Reads the analytics TLS keys soon after each new analytics connection opens, so its upload can be
# decrypted later (OpenSSL wipes a connection's keys soon after it closes).
#
#   analysis/tls-keys-watch.sh captures/proxy-<stamp>.jsonl <game pid> captures/analytics.keylog
#
# Each time the recording gets a ClientHello for the analytics host: wait 60 s (handshake done), list
# the open analytics connections without a key, read the game's memory once (tls-memscan.py:
# read-only, through sudo -n, so sudo must not ask for a password), and add the verified keys to the
# keylog. Then: analysis/tls-keys.py decrypt <recording> --keylog <keylog>. Ctrl-C stops it.
set -u
REC=$1 PID=$2 KEYLOG=$3 SNI=${SNI:-public.api.nexon.com}
cd "$(dirname "$0")/.." || exit 1
umask 077
PY=$PWD/.venv/bin/python NEEDLES=captures/tls-needles.txt
tail -n0 -F "$REC" | grep --line-buffered -F '"tls_client_hello"' | grep --line-buffered -F "\"$SNI\"" |
while read -r _; do
  echo "$(date +%T) new connection to $SNI"
  sleep 60
  "$PY" analysis/tls-keys.py needles "$REC" --keylog "$KEYLOG" --sni "$SNI" > "$NEEDLES" || continue
  [ -s "$NEEDLES" ] || continue
  scan=captures/tls-scan-$(date +%Y%m%d-%H%M%S).pkl
  sudo -n "$PY" -I analysis/tls-memscan.py "$PID" "$scan" "@$NEEDLES" &&
    "$PY" analysis/tls-keys.py find "$REC" "$scan" --keylog "$KEYLOG" --sni "$SNI"
done
