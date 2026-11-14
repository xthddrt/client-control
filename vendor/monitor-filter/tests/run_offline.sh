#!/bin/sh
# Every check that needs no root (`monfilter.py test`): builds both halves with their test binaries,
# then the shared ABI, kfilter's matcher, daemon and default policy, msmon's regression, PE unwinder,
# pcap writer, wineserver decoder, kernel aggregates, desktop-service decoders and watchpoints, session redaction, and
# the orchestrator and tuning report.
# The root tests are listed in README.md and run separately.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
sh "$root/build.sh" tests
f="$root/filter/build/linux"
m="$root/monitor/build/linux"

echo "== abi"
bash "$root/abi/check.sh"

echo "== filter"
cd "$root/filter"
"$f/kfilterctl" self-test
"$f/kfilterd-test"
"$f/launch-test" "$f/shim"
"$f/shim-test"
"$f/kfilterctl" check policy/linux-default-policy.txt >/dev/null

echo "== monitor"
cd "$root/monitor"
"$m/integration_regression"
"$m/linux_pe_test"
"$m/wineserver_test"
"$m/linux_sysagg_test"
"$m/linux_unix_test"
"$m/linux_watch_test"
for test in tests/*_test.py; do python3 "$test"; done

echo "== orchestrator"
cd "$root"
python3 tests/monfilter_test.py
python3 tests/monfilter_run_test.py
python3 tests/report_test.py
echo "offline checks passed"
