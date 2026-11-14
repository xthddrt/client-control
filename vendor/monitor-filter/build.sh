#!/bin/sh
# Linux build of both halves: compile only (tests: tests/run_offline.sh). Installs and starts nothing.
set -eu
cd "$(dirname "$0")"
sh filter/build.sh "$@"
bash monitor/build.sh "$@"
