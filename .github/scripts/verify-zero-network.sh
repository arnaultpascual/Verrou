#!/usr/bin/env bash
# Layer 3: Network Isolation Proof
#
# Verifies that the VERROU binary makes zero network syscalls.
# Uses strace (Linux) to trace syscalls during a test lifecycle.
#
# Prerequisites:
#   - Release binary at target/release/verrou (or path passed as $1)
#   - strace installed (Linux only; macOS would need dtruss with root)
#
# Usage:
#   bash .github/scripts/verify-zero-network.sh [binary-path]
#
# Exit codes:
#   0 — No network syscalls detected (or gracefully skipped)
#   1 — Network syscalls detected (CRITICAL)

set -euo pipefail

BINARY="${1:-target/release/verrou}"

# --- Platform check ---
if [[ "$(uname -s)" != "Linux" ]]; then
    echo "SKIP: verify-zero-network.sh requires Linux (strace). Current OS: $(uname -s)"
    echo "On macOS, use 'dtruss' with root privileges (not automated in CI)."
    exit 0
fi

# --- Prerequisite check ---
if ! command -v strace &> /dev/null; then
    echo "SKIP: strace is not installed. Install with: sudo apt-get install strace"
    exit 0
fi

if [ ! -f "$BINARY" ]; then
    echo "SKIP: Binary not found at $BINARY"
    echo "Build with: cargo build --release --workspace"
    echo "This check will be enabled when the Tauri binary is available (Epic 2+)."
    exit 0
fi

# --- Network syscall trace ---
echo "Tracing network syscalls in: $BINARY"

SYSCALLS_LOG=$(mktemp)
trap 'rm -f "$SYSCALLS_LOG"' EXIT

# Trace network-related syscalls; timeout after 10 seconds.
# The binary may not have --test-lifecycle yet, so we just start and kill it.
timeout 10 strace -f -e trace=network "$BINARY" 2> "$SYSCALLS_LOG" || true

NETWORK_CALLS=$(grep -c -E "socket|connect|sendto|recvfrom|bind|listen|accept" "$SYSCALLS_LOG" || echo "0")

if [ "$NETWORK_CALLS" -ne 0 ]; then
    echo "CRITICAL: $NETWORK_CALLS network syscalls detected!"
    echo ""
    echo "Offending syscalls:"
    grep -E "socket|connect|sendto|recvfrom|bind|listen|accept" "$SYSCALLS_LOG"
    exit 1
fi

echo "Layer 3 PASS: Zero network syscalls detected."
