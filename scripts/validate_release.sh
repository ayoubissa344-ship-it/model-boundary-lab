#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

# Respect the platform's temporary directory instead of hardcoding /tmp.
TEMP_BASE="${TMPDIR:-${TMP:-/tmp}}"
mkdir -p "$TEMP_BASE"
WORK_TMP="$(mktemp -d "$TEMP_BASE/mbl-release.XXXXXX")"
trap 'rm -rf "$WORK_TMP"' EXIT

printf '\n== Python unit suite ==\n'
python -m unittest discover -s tests -v

printf '\n== Python CLI check ==\n'
python -m mbl --version
python -m mbl doctor --out "$WORK_TMP/mbl-doctor-release-check.json"
test -s "$WORK_TMP/mbl-doctor-release-check.json"

printf '\n== TypeScript evidence checks ==\n'
if command -v npm >/dev/null 2>&1; then
  (cd native/typescript && npm test)
else
  echo 'SKIP: npm unavailable'
fi

printf '\n== C++ observation probe build ==\n'
if command -v cmake >/dev/null 2>&1 && command -v c++ >/dev/null 2>&1; then
  cmake -S native/cpp -B "$WORK_TMP/mbl-cpp-build" \
    -DCMAKE_BUILD_TYPE=Release
  cmake --build "$WORK_TMP/mbl-cpp-build" --parallel 2

  set +e
  "$WORK_TMP/mbl-cpp-build/mbl-probe" --jsonl \
    > "$WORK_TMP/mbl-cpp-probe.jsonl"
  rc=$?
  set -e

  echo "probe_exit=$rc (2 means one or more fields were inconclusive, not a security verdict)"
else
  echo 'SKIP: cmake/C++ compiler unavailable'
fi

printf '\nValidation completed. This does not test kernel isolation or model-weight confidentiality.\n'
