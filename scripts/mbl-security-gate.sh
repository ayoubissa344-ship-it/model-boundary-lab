#!/data/data/com.termux/files/usr/bin/bash
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 70

OUT="$ROOT/evidence/security-gate-$(date -u +%Y%m%dT%H%M%SZ).txt"
mkdir -p "$ROOT/evidence"

exec > >(tee "$OUT") 2>&1

echo "MODELBOUNDARY LAB SECURITY GATE"
echo "UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "DEVICE_ARCH=$(uname -m)"
echo "KERNEL=$(uname -sr)"
echo

FAIL=0

echo "=== 1. Rust tests ==="
if cargo test --offline --manifest-path native/rust/mbl-sandbox/Cargo.toml; then
    echo "RUST_TESTS=PASS"
else
    echo "RUST_TESTS=FAIL"
    FAIL=1
fi

echo
echo "=== 2. Runtime seccomp probe ==="
if cargo run --offline --manifest-path native/rust/mbl-sandbox/Cargo.toml -- --self-test; then
    echo "SECCOMP_PROBE=PASS"
else
    echo "SECCOMP_PROBE=FAIL"
    FAIL=1
fi

echo
echo "=== 3. Process security state ==="
if [ -r /proc/self/status ]; then
    grep -E '^(Seccomp|CapEff|CapBnd|NoNewPrivs):' /proc/self/status || true
else
    echo "PROC_STATUS=UNAVAILABLE"
fi

echo
echo "=== 4. Namespace capability probe ==="
if command -v unshare >/dev/null 2>&1; then
    if unshare --user true >/dev/null 2>&1; then
        echo "USER_NAMESPACE=AVAILABLE"
    else
        echo "USER_NAMESPACE=UNAVAILABLE"
        FAIL=1
    fi

    if unshare --mount true >/dev/null 2>&1; then
        echo "MOUNT_NAMESPACE=AVAILABLE"
    else
        echo "MOUNT_NAMESPACE=UNAVAILABLE"
        FAIL=1
    fi

    if unshare --net true >/dev/null 2>&1; then
        echo "NETWORK_NAMESPACE=AVAILABLE"
    else
        echo "NETWORK_NAMESPACE=UNAVAILABLE"
        FAIL=1
    fi
else
    echo "UNSHARE_TOOL=UNAVAILABLE"
    FAIL=1
fi

echo
echo "=== 5. Isolation claims ==="
echo "FILESYSTEM_ISOLATION=NOT_VERIFIED"
echo "NETWORK_ISOLATION=NOT_VERIFIED"
echo "MODEL_RUNTIME_INTEGRATION=NOT_VERIFIED"
echo "SANDBOX_STATUS=NOT_ESTABLISHED"

echo
echo "=== 6. Source and binary fingerprints ==="
if [ -f native/rust/mbl-sandbox/src/main.rs ]; then
    sha256sum native/rust/mbl-sandbox/src/main.rs
fi

BIN="native/rust/mbl-sandbox/target/debug/mbl-sandbox"
if [ -f "$BIN" ]; then
    sha256sum "$BIN"
else
    echo "BINARY=NOT_FOUND"
    FAIL=1
fi

echo
if [ "$FAIL" -eq 0 ]; then
    echo "GATE_RESULT=PROBES_PASSED"
    echo "SECURITY_INTERPRETATION=PARTIAL_ONLY"
    echo "NOTE=Passing probes do not establish complete isolation."
    exit 0
else
    echo "GATE_RESULT=FAIL_CLOSED"
    echo "SECURITY_INTERPRETATION=REQUIRED_CAPABILITY_OR_TEST_MISSING"
    exit 1
fi
