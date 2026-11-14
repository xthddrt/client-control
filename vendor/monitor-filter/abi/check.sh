#!/usr/bin/env bash
# Compile-time ABI check (abi/abi_test.c) for both layouts: Linux (C and C++, as kfilterd,
# kfilterctl and msmon-agent include it) and Windows x64 via clang's MSVC target (no WDK).
set -euo pipefail
cd "$(dirname "$0")"
clang="${CLANG:-$(command -v clang-18 || command -v clang)}"
"${CC:-cc}" -std=c11 -fsyntax-only abi_test.c
"${CXX:-c++}" -x c++ -std=c++17 -fsyntax-only abi_test.c
"$clang" --target=x86_64-pc-windows-msvc -std=c11 -fsyntax-only -fshort-wchar abi_test.c
echo "abi check passed (linux, windows x64)"
