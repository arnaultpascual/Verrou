#!/usr/bin/env bash
# Check that no tracing/log/print calls contain secret-related variable names.
# This prevents accidental logging of key material.

set -euo pipefail

echo "Checking for secret material in logging calls..."

SECRET_WORDS='key|secret|password|passphrase|seed|entropy|mnemonic|master_key|private_key'

# Check tracing macros (single and multi-line via field names)
PATTERNS=(
    "tracing::(trace|debug|info|warn|error)!\(.*\b($SECRET_WORDS)\b"
    "(println|eprintln|print|eprint)!\(.*\b($SECRET_WORDS)\b"
    "log::(trace|debug|info|warn|error)!\(.*\b($SECRET_WORDS)\b"
    "#\[instrument.*\b($SECRET_WORDS)\b"
)

FAIL=0
for PATTERN in "${PATTERNS[@]}"; do
    MATCHES=$(grep -rn --include='*.rs' -E "$PATTERN" crates/ src-tauri/src/ 2>/dev/null || true)
    if [ -n "$MATCHES" ]; then
        echo "ERROR: Found potential secret logging:"
        echo "$MATCHES"
        FAIL=1
    fi
done

if [ "$FAIL" -eq 1 ]; then
    echo ""
    echo "Never log variables containing key material."
    echo "Use masked output or remove the log statement."
    exit 1
fi

echo "No secret logging found."
