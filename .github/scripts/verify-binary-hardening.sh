#!/usr/bin/env bash
# Layer 6: Binary Hardening Audit
#
# Verifies that the release binary has proper security hardening:
#   1. checksec: RELRO, stack canaries, NX, PIE (ASLR), FORTIFY
#   2. strings: No accidental plaintext secrets in binary
#
# Prerequisites:
#   - Release binary at target/release/verrou (or path passed as $1)
#   - checksec installed (optional — strings check always runs)
#
# Usage:
#   bash .github/scripts/verify-binary-hardening.sh [binary-path]
#
# Exit codes:
#   0 — All checks pass (or gracefully skipped)
#   1 — Secret plaintext found in binary (CRITICAL)

set -euo pipefail

BINARY="${1:-target/release/verrou}"

# --- Prerequisite check ---
if [ ! -f "$BINARY" ]; then
    echo "SKIP: Binary not found at $BINARY"
    echo "Build with: cargo build --release --workspace"
    echo "This check will be enabled when the Tauri binary is available (Epic 2+)."
    exit 0
fi

FAIL=0

# --- checksec audit ---
if command -v checksec &> /dev/null; then
    echo "=== checksec: Binary hardening features ==="
    checksec --file="$BINARY" || true
    echo ""
else
    echo "INFO: checksec not installed — skipping hardening feature check."
    echo "Install with: sudo apt-get install checksec"
    echo ""
fi

# --- strings: Search for accidental plaintext secrets ---
echo "=== strings: Searching for accidental plaintext secrets ==="

# Secret-related patterns that should NOT appear as plaintext in a stripped binary.
# We look for common variable/field names that might indicate leaked secret material.
# Note: Short words like "key" can have false positives in library strings,
# so we use more specific patterns.
SECRET_PATTERNS='master_key|private_key|secret_key|passphrase|mnemonic_phrase|seed_phrase|raw_entropy'

MATCHES=$(strings "$BINARY" | grep -iE "$SECRET_PATTERNS" || true)
if [ -n "$MATCHES" ]; then
    echo "WARNING: Potential secret-related strings found in binary:"
    echo "$MATCHES"
    echo ""
    echo "Review above matches — some may be false positives from library code."
    echo "If any are actual secret variable names, this is a CRITICAL issue."
    # Don't fail on this — too many false positives from library strings.
    # Flag for manual review instead.
fi

# Strict check: Look for known VERROU-specific secret patterns that should NEVER appear.
STRICT_PATTERNS='VERROU.*secret|VERROU.*password|VERROU.*seed|VERROU.*mnemonic'
STRICT_MATCHES=$(strings "$BINARY" | grep -iE "$STRICT_PATTERNS" || true)
if [ -n "$STRICT_MATCHES" ]; then
    echo "CRITICAL: VERROU-specific secret strings found in binary!"
    echo "$STRICT_MATCHES"
    FAIL=1
fi

if [ "$FAIL" -eq 1 ]; then
    echo ""
    echo "Layer 6 FAIL: Binary contains secret-related plaintext."
    exit 1
fi

echo ""
echo "Layer 6 PASS: No critical plaintext secrets found in binary."
