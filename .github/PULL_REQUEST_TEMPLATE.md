<!-- Thanks for contributing to Verrou! Please fill out the checklist below. -->

## Summary

<!-- What does this PR do, and why? -->

Closes #

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Refactor / internal
- [ ] Documentation
- [ ] Build / CI

## Gates

<!-- All must be green. See CONTRIBUTING.md. -->

- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` is clean
- [ ] `cargo test --workspace` passes
- [ ] `cargo deny check` passes
- [ ] `npm test` and `tsc --noEmit` pass
- [ ] `npm run lint:css` passes
- [ ] `CHANGELOG.md` updated under **Unreleased**

## Security checklist

- [ ] No secret material is passed to any logging macro.
- [ ] Sensitive values use `SecretVec`/`SecretString` and derive `Zeroize` where applicable.
- [ ] No network-capable crates added to `verrou-crypto-core` or `verrou-vault`.
- [ ] `verrou-crypto-core` is still under 30 direct dependencies.
- [ ] IPC commands return DTOs only (with `#[serde(rename_all = "camelCase")]`).
- [ ] MAC/tag comparisons use constant-time helpers (no `==`).
- [ ] No secrets, `.env`, `*.db`, `*.verrou`, or build artifacts are committed.
