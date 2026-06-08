#!/usr/bin/env bash
#
# release-macos.sh — build, sign, notarize, and staple a Verrou release on macOS.
#
# This runs entirely on your Mac. It produces a Gatekeeper-clean .dmg you can
# upload to a GitHub release by hand. No CI, no secrets in the repo or env:
# Apple credentials live in the macOS keychain (see one-time setup below).
#
# ── One-time setup ───────────────────────────────────────────────────────────
#   1. A "Developer ID Application" certificate must be in your login keychain
#      (you already have one). Verify:  security find-identity -v -p codesigning
#   2. Store notarization credentials in the keychain ONCE. Pick ONE:
#
#      a) App Store Connect API key (recommended — doesn't expire):
#         xcrun notarytool store-credentials "verrou-notary" \
#           --key   /path/to/AuthKey_XXXX.p8 \
#           --key-id     <KEY_ID> \
#           --issuer     <ISSUER_UUID>
#
#      b) Apple ID + app-specific password:
#         xcrun notarytool store-credentials "verrou-notary" \
#           --apple-id  "you@example.com" \
#           --team-id   "<YOUR_TEAM_ID>" \
#           --password  "<app-specific-password>"
#
#   The profile name ("verrou-notary") is all this script needs afterwards.
#   Override it with VERROU_NOTARY_PROFILE if you used a different name.
#
# ── Usage ────────────────────────────────────────────────────────────────────
#   ./scripts/release-macos.sh              # universal (Intel + Apple Silicon)
#   ./scripts/release-macos.sh --host       # this machine's architecture only
#   ./scripts/release-macos.sh --check      # run the test gates first, then build
#
set -euo pipefail

PROFILE="${VERROU_NOTARY_PROFILE:-verrou-notary}"
TARGET="universal-apple-darwin"
RUN_CHECKS=0

for arg in "$@"; do
  case "$arg" in
    --host)  TARGET="" ;;
    --check) RUN_CHECKS=1 ;;
    *) echo "Unknown argument: $arg" >&2; exit 2 ;;
  esac
done

# ── Helpers ──────────────────────────────────────────────────────────────────
bold() { printf '\033[1m%s\033[0m\n' "$*"; }
step() { printf '\n\033[1;36m▶ %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

# Run from the repo root regardless of where the script is invoked from.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
[[ -f src-tauri/tauri.conf.json ]] || die "Run from the Verrou repo (src-tauri/tauri.conf.json not found)."

VERSION="$(grep -m1 '"version"' src-tauri/tauri.conf.json | sed -E 's/.*"version" *: *"([^"]+)".*/\1/')"

# ── Preflight ────────────────────────────────────────────────────────────────
step "Preflight checks"
command -v xcrun >/dev/null      || die "xcrun not found — install Xcode Command Line Tools."
xcrun --find notarytool >/dev/null 2>&1 || die "notarytool not found — update Xcode / Command Line Tools."
command -v npm >/dev/null        || die "npm not found."

IDENTITY="$(security find-identity -v -p codesigning | awk -F\" '/Developer ID Application/ {print $2; exit}')"
[[ -n "$IDENTITY" ]] || die "No 'Developer ID Application' identity in the keychain."
export APPLE_SIGNING_IDENTITY="$IDENTITY"
bold "  Signing identity : $IDENTITY"
bold "  Notary profile   : $PROFILE"
bold "  Version          : $VERSION"
bold "  Target           : ${TARGET:-host ($(uname -m))}"

# Confirm the notary profile resolves before we spend minutes building.
# (`notarytool history` validates the stored credentials with a quick API call.)
xcrun notarytool history --keychain-profile "$PROFILE" >/dev/null 2>&1 \
  || die "Notary profile '$PROFILE' not usable. Store it once (see header) or set VERROU_NOTARY_PROFILE."

if [[ "$TARGET" == "universal-apple-darwin" ]]; then
  for t in x86_64-apple-darwin aarch64-apple-darwin; do
    rustup target list --installed 2>/dev/null | grep -qx "$t" || { step "Adding rust target $t"; rustup target add "$t"; }
  done
fi

# ── Optional gates ───────────────────────────────────────────────────────────
if [[ "$RUN_CHECKS" == "1" ]]; then
  step "Running test gates (cargo + frontend)"
  cargo fmt --all -- --check
  cargo clippy --workspace --all-targets -- -D warnings
  cargo test --workspace --no-fail-fast
  npm run lint:css
  npx tsc --noEmit
  npm test
fi

# ── Build (Tauri signs the .app: hardened runtime + entitlements.plist) ──────
step "Building + signing (this takes a few minutes)"
# NOTE: this is a Cargo workspace, so the target dir is at the repo root
# (target/), not src-tauri/target/.
if [[ -n "$TARGET" ]]; then
  npm run tauri build -- --target "$TARGET"
  BUNDLE="target/$TARGET/release/bundle"
else
  npm run tauri build
  BUNDLE="target/release/bundle"
fi

APP="$(ls -dt "$BUNDLE"/macos/*.app 2>/dev/null | head -1 || true)"
DMG="$(ls -t  "$BUNDLE"/dmg/*.dmg  2>/dev/null | head -1 || true)"
[[ -n "$APP" ]] || die "No .app produced under $BUNDLE/macos/."
[[ -n "$DMG" ]] || die "No .dmg produced under $BUNDLE/dmg/."

step "Verifying the signature on the app"
codesign --verify --deep --strict --verbose=2 "$APP"
codesign --display --verbose=2 "$APP" 2>&1 | grep -i "Authority=Developer ID Application" \
  || die "App is not signed with a Developer ID Application certificate."

# ── Notarize + staple (credentials read from the keychain profile) ───────────
step "Submitting to Apple notary service (waits for the result)"
xcrun notarytool submit "$DMG" --keychain-profile "$PROFILE" --wait

step "Stapling the notarization ticket"
xcrun stapler staple "$DMG"
xcrun stapler validate "$DMG"

step "Final Gatekeeper assessment"
spctl -a -t open --context context:primary-signature -vvv "$DMG" || true

SHA="$(shasum -a 256 "$DMG" | awk '{print $1}')"

step "Done ✓"
bold "  Artifact : $DMG"
bold "  SHA-256  : $SHA"
cat <<EOF

Next steps (manual, by design):
  1. Tag the release:   git tag v$VERSION && git push origin v$VERSION
  2. Create the GitHub release for that tag and attach:
       $DMG
  3. (Optional) paste the SHA-256 above into the release notes.
EOF
