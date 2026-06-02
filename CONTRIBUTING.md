# Contributing to Verrou

Thanks for your interest in contributing! Verrou is a security-critical,
offline-first vault, so a few rules below exist specifically to keep that
guarantee intact. Please read them before opening a pull request.

For anything security-sensitive, **do not open a public issue** — follow
[`SECURITY.md`](SECURITY.md) instead.

## Before you start

- **Open an issue first** for anything non-trivial (new features, refactors,
  dependency changes). This avoids wasted work on changes we can't accept.
- By contributing, you agree that your contributions are licensed under the
  project's [GPL-3.0-or-later](LICENSE) license.
- This project follows a [Code of Conduct](CODE_OF_CONDUCT.md). By participating
  you agree to uphold it.

## Non-negotiable invariants

These are enforced in CI and reviewed on every PR. A change that weakens any of
them will not be merged without explicit discussion:

- **Zero network.** `verrou-crypto-core` and `verrou-vault` must never depend on
  network-capable crates (no HTTP/DNS/socket/async-runtime). The Tauri shell has
  no `shell`, `http`, or `fs` capabilities.
- **Lean crypto core.** `verrou-crypto-core` stays under **30 direct
  dependencies** and compiles standalone (no Tauri).
- **Never log secrets.** No `key`/`secret`/`password`/`seed`/`entropy` passed to
  any logging macro (CI greps for this and fails the build).
- **Secret types.** Use `SecretVec`/`SecretString` (never raw `Vec<u8>`/`String`)
  for sensitive data, and derive `Zeroize`/`ZeroizeOnDrop` on key material.
- **IPC returns DTOs only** — never domain entities — with
  `#[serde(rename_all = "camelCase")]`. Raw secrets never cross the IPC boundary.
- **Constant-time** comparison for all MAC/tag checks (use `ring::constant_time`,
  never `==`).

The architecture overview lives in the [README](README.md#architecture), and the
cryptographic rationale in [`docs/CRYPTO_DESIGN.md`](docs/CRYPTO_DESIGN.md) /
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Development setup

**Prerequisites**

- [Rust](https://rustup.rs/) (stable)
- [Node.js](https://nodejs.org/) 20+
- Platform dependencies for [Tauri 2.0](https://v2.tauri.app/start/prerequisites/)

**Run it**

```bash
npm install            # frontend deps
npm run tauri dev      # compile Rust + launch with hot reload
```

## Gates — must be green before you open a PR

Run the same checks CI runs:

```bash
# Rust
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --no-fail-fast
cargo deny check

# Frontend
npm test
tsc --noEmit
npm run lint:css
```

CI additionally runs the scripts in `.github/scripts/` (zero-network
verification, secret-logging scan, binary-hardening checks).

## Pull requests

- Keep PRs focused and reasonably small; one logical change per PR.
- Reference the issue you're addressing (`Closes #123`).
- Add or update tests for behavior changes. Rust tests live inline
  (`#[cfg(test)] mod tests`) and in `tests/`; frontend tests live in
  `src/__tests__/`.
- Update [`CHANGELOG.md`](CHANGELOG.md) under **Unreleased**.
- **Never commit** secrets, `.env` files, `*.db` vaults, `*.verrou` exports, or
  build artifacts.
- Fill out the PR template checklist honestly.

## Code style

- Rust: `rustfmt` (100-char max width), `clippy` clean. Workspace lints deny
  `unwrap_used` and `arithmetic_side_effects` — use `checked_*` arithmetic and
  proper error handling.
- TypeScript/SolidJS: CSS Modules with design tokens (no magic numbers), all
  user-facing strings via i18n, IPC calls through `createResource`/service
  functions (never raw `invoke()` in component bodies).

Thank you for helping make Verrou better and safer.
