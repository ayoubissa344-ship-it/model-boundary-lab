#!/data/data/com.termux/files/usr/bin/bash
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

OUT="evidence/release-check.txt"
mkdir -p evidence
TMP="${OUT}.tmp"
: > "$TMP"
exec > >(tee "$TMP") 2>&1

echo "MODELBOUNDARY_LAB_RELEASE_CHECK"
date -u '+UTC=%Y-%m-%dT%H:%M:%SZ' || true
echo "ROOT=$ROOT"
echo

echo "== Toolchain =="
rustc --version
cargo --version
uname -a
echo

echo "== Policy validation =="
if [ -f security/policy.json ]; then
  python -m json.tool security/policy.json >/dev/null
  echo "POLICY_JSON=PASS"
  sha256sum security/policy.json
else
  echo "POLICY_JSON=FAIL_MISSING"
  exit 1
fi
echo

echo "== Rust tests =="
cargo test --offline --manifest-path native/rust/mbl-sandbox/Cargo.toml
echo "RUST_TESTS=PASS"
echo

echo "== Seccomp probe self-test =="
cargo run --offline --manifest-path native/rust/mbl-sandbox/Cargo.toml -- --self-test
echo "SECCOMP_SELF_TEST=PASS"
echo

echo "== Python tests, if present =="
if [ -d tests ]; then
  MBL_CORE="$(find . -type f -path '*/mbl/core.py' \
    -not -path '*/.venv/*' -not -path '*/venv/*' \
    -not -path '*/site-packages/*' -print -quit)"

  if [ -z "$MBL_CORE" ]; then
    echo "PYTHON_PACKAGE=NOT_FOUND"
    echo "PYTHON_TESTS=BLOCKED_PACKAGE_LAYOUT_UNKNOWN"
    echo "Inspect source layout before changing imports."
    exit 1
  fi

  MBL_IMPORT_ROOT="${MBL_CORE%/mbl/core.py}"
  export PYTHONPATH="$PWD/$MBL_IMPORT_ROOT${PYTHONPATH:+:$PYTHONPATH}"
  echo "PYTHON_IMPORT_ROOT=$MBL_IMPORT_ROOT"

  python -m unittest discover -s tests
  echo "PYTHON_TESTS=PASS"
else
  echo "PYTHON_TESTS=NOT_CONFIGURED"
fi
echo

echo "== Artifact hashes =="
sha256sum native/rust/mbl-sandbox/src/main.rs
if [ -f native/rust/mbl-sandbox/Cargo.lock ]; then
  sha256sum native/rust/mbl-sandbox/Cargo.lock
fi
BIN="native/rust/mbl-sandbox/target/debug/mbl-sandbox"
if [ -x "$BIN" ]; then
  sha256sum "$BIN"
else
  echo "LOCAL_BINARY_HASH=NOT_AVAILABLE"
fi
echo

echo "== Isolation status =="
echo "SECCOMP_SELECTED_SYSCALL=TESTED"
echo "COMPREHENSIVE_SYSCALL_POLICY=NOT_VERIFIED"
echo "FILESYSTEM_ISOLATION=NOT_VERIFIED"
echo "NETWORK_ISOLATION=NOT_VERIFIED"
echo "MODEL_RUNTIME_INTEGRATION=NOT_VERIFIED"
echo "CROSS_PLATFORM_ENFORCEMENT=NOT_VERIFIED"
echo "SANDBOX_STATUS=NOT_ESTABLISHED"
echo
echo "REPORT=$OUT"
mv "$TMP" "$OUT"
