# Changelog

All notable changes to Verrou are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

First public pre-1.0 alpha. Highlights since the project went open:

### Added

- Post-quantum protection for portable backups: encrypted `.verrou` exports are
  key-wrapped with a hybrid X25519 + ML-KEM-1024 KEM and signed with a hybrid
  Ed25519 + ML-DSA-65 signature. The signature is verified fail-closed before
  any decryption.
- Deterministic per-vault KEM and signing keypairs derived from the master key
  on unlock (no extra storage, no migration).
- Cryptographic design and threat-model documentation
  (`docs/CRYPTO_DESIGN.md`, `docs/THREAT_MODEL.md`).
- Fuzz targets for the untrusted import parsers and the export-envelope parser.

### Changed

- The export envelope is now mandatory; legacy non-envelope `.verrou` files are
  no longer accepted (pre-release, no compatibility burden).
- Documentation corrected to describe the cryptography exactly as implemented
  (data at rest is symmetric → quantum-resistant; post-quantum public-key
  primitives protect exports/backups).
- Runtime path handling centralized.

### Security

- Sensitive reveals and backup *restore* require re-authentication.
- Revealed secrets are cleared on window blur/hide and on vault lock; the
  clipboard is cleared on lock (manual, tray, and auto-lock).
- Import hardening: bounded allocation, single transaction with rollback, and
  no internal error leakage across the IPC boundary.

[Unreleased]: https://github.com/arnaultpascual/Verrou/commits/main
