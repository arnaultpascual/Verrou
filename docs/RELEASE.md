# Releasing Verrou (macOS)

Verrou is released **manually from a Mac** — no CI, no Apple credentials in the
repo or in GitHub. You build, sign, notarize, and staple locally with one
script, then upload the `.dmg` to a GitHub release by hand.

## Why notarize?

Without notarization, macOS Gatekeeper shows *"Verrou can't be opened because
Apple cannot check it for malicious software"* and users must right-click →
Open (or run `xattr -d`). A notarized + stapled `.dmg` opens with a normal
double-click on any Mac, offline.

## One-time setup

You already have the hard part — a **Developer ID Application** certificate in
your login keychain. Confirm it:

```bash
security find-identity -v -p codesigning | grep "Developer ID Application"
```

Then store notarization credentials in the keychain **once**. The release script
reads them by profile name (`verrou-notary`) and never sees the secret itself.
Pick one method:

**A) App Store Connect API key — recommended (keys don't expire):**

```bash
# Create the key at appstoreconnect.apple.com → Users and Access → Integrations
xcrun notarytool store-credentials "verrou-notary" \
  --key    /path/to/AuthKey_XXXXXXXXXX.p8 \
  --key-id      <KEY_ID> \
  --issuer      <ISSUER_UUID>
```

**B) Apple ID + app-specific password:**

```bash
# Create an app-specific password at appleid.apple.com → Sign-In and Security
xcrun notarytool store-credentials "verrou-notary" \
  --apple-id "you@example.com" \
  --team-id  "<YOUR_TEAM_ID>" \
  --password "<app-specific-password>"
```

That's it — the secret now lives in the macOS keychain, not in this repo.

## Cutting a release

1. Bump the version in **`src-tauri/tauri.conf.json`** and
   **`src-tauri/Cargo.toml`** (keep them in sync), commit.
2. Run the script:

   ```bash
   ./scripts/release-macos.sh            # universal (Intel + Apple Silicon)
   # ./scripts/release-macos.sh --host   # only this machine's architecture
   # ./scripts/release-macos.sh --check  # run all test gates first, then build
   ```

   It will: build + sign (hardened runtime + `entitlements.plist`) → submit to
   Apple → wait for the result → staple the ticket → verify with `spctl`, and
   print the final `.dmg` path + its SHA-256.

3. Tag and publish (the script prints these too):

   ```bash
   git tag v<version> && git push origin v<version>
   ```

   Create the GitHub release for that tag and attach the `.dmg`.

## What's signed where

- **The `.app`** is signed by `tauri build` with your Developer ID cert,
  hardened runtime, and `src-tauri/entitlements.plist` (intentionally empty —
  least privilege; see the comments in that file).
- **The `.dmg`** is notarized and stapled by the script.
- Signing identity is auto-detected from your keychain at build time
  (`APPLE_SIGNING_IDENTITY`), so it is **not** hardcoded in the public config.

## Troubleshooting

- **`Notary profile 'verrou-notary' not usable`** — run the one-time
  `store-credentials` step above (or set `VERROU_NOTARY_PROFILE` to your name).
- **Notarization "Invalid"** — run
  `xcrun notarytool log <submission-id> --keychain-profile verrou-notary` for the
  per-file reasons (almost always an unsigned/un-hardened nested binary).
- **App won't launch after notarization** (rare, a JIT/codesign error in
  Console) — a dependency may need a specific hardened-runtime exception. Add the
  single required key to `entitlements.plist` and document why.
- **Universal build fails on the vendored OpenSSL/SQLCipher** — fall back to
  `--host` for a single-arch build while you investigate.
