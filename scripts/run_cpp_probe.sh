#!/usr/bin/env sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BUILD="$ROOT/native/cpp/build"
cmake -S "$ROOT/native/cpp" -B "$BUILD" -DCMAKE_BUILD_TYPE=Release
cmake --build "$BUILD" --parallel
"$BUILD/mbl-probe" --jsonl > "${1:-$ROOT/datasets/cpp_probe.jsonl}"
