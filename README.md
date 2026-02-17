# Verrou

**Sovereign, offline-first, post-quantum encrypted digital vault.**

Verrou is a desktop application that securely stores your most sensitive digital secrets — 2FA codes (TOTP/HOTP), seed phrases (BIP39), recovery codes, credentials, and secure notes — using hybrid post-quantum encryption. It never connects to the internet. All data stays on your device.

## Key Features

- **Post-quantum encryption** — Hybrid X25519 + ML-KEM-1024 key encapsulation, AES-256-GCM symmetric encryption, Argon2id key derivation, BLAKE3 hashing
- **Fully offline** — Zero network dependencies. No HTTP, DNS, or socket libraries in the entire dependency tree
- **TOTP/HOTP generation** — Built-in authenticator with clipboard concealment and auto-clear
- **BIP39 seed phrases** — Full support for 12/15/18/21/24-word mnemonics with optional passphrase (25th word), 10 languages
- **Credential manager** — Passwords, usernames, URLs, custom fields, password history, and strength analysis
- **Secure notes** — Encrypted freeform text with server-side search (content never leaves Rust)
- **Folder organization** — Nested folders with drag-and-drop, pinning, and tagging
- **Import/Export** — Aegis, Google Authenticator, 2FAS import. Encrypted `.verrou` format export
- **QR transfer** — Desktop-to-desktop vault transfer via animated QR codes (no network)
- **Paper backup** — Printable encrypted PDF backup
- **Biometric unlock** — Touch ID / Windows Hello / fingerprint (with graceful degradation)
- **Hardware security** — Secure Enclave (macOS) and TPM 2.0 (Windows) key storage
- **Password generator** — Cryptographic random passwords and diceware passphrases (EFF wordlist)
- **Password health** — Reuse detection, weakness scoring, age tracking, missing 2FA alerts
- **System tray** — Quick-access popup for TOTP codes without opening the main window
- **Internationalization** — English and French, with pluggable locale system
- **Themes** — Light, dark, and system-following modes

## Architecture

```
verrou-crypto-core  ──>  verrou-vault  ──>  src-tauri  ──>  SolidJS frontend
(cryptographic primitives)  (business logic)  (Tauri IPC shell)  (WebView UI)
```

| Crate | Role | Network deps |
|---|---|---|
| `verrou-crypto-core` | Pure crypto: KEM, KDF, AEAD, BLAKE3, TOTP, BIP39, slots, signatures | None |
| `verrou-vault` | Vault lifecycle, entries, folders, attachments, import/export, SQLCipher | None |
| `src-tauri` | Tauri 2.0 commands, platform integration, clipboard, tray, biometric | Tauri only |

The frontend uses [SolidJS](https://www.solidjs.com/) with [Kobalte](https://kobalte.dev/) primitives, CSS Modules, and the `@solid-primitives/i18n` i18n system.

## Security Model

- **3-layer encryption** — Session key (Argon2id) wraps master key, master key wraps entry keys, entry keys encrypt data
- **Hybrid KEM** — Both X25519 (classical) and ML-KEM-1024 (post-quantum) must contribute to derive the shared secret
- **Zero-network enforcement** — CI verifies no network-capable crate exists in `verrou-crypto-core` or `verrou-vault` dependency trees
- **Memory protection** — `mlock` pinning, `Zeroize` on drop for all key material
- **Clipboard concealment** — macOS `NSPasteboard` concealed type, Windows clipboard history exclusion, configurable auto-clear
- **Brute-force protection** — Rate-limited unlock attempts with exponential backoff
- **Binary hardening** — Release builds use LTO, single codegen unit, overflow checks, symbol stripping
- **SQLCipher** — Database encrypted at rest with raw key injection (no double KDF)
- **Vault integrity** — BLAKE3 checksums verified on every unlock

## Build from Source

### Prerequisites

- [Rust](https://rustup.rs/) (stable)
- [Node.js](https://nodejs.org/) 20+
- Platform dependencies for [Tauri 2.0](https://v2.tauri.app/start/prerequisites/)

### Development

```bash
# Install frontend dependencies
npm install

# Run in development mode (compiles Rust + launches app)
npm run tauri dev

# Build for production (outputs platform installer)
npm run tauri build
```

### Standalone Crate Builds

```bash
# Crypto-core (no Tauri dependencies)
cargo build --lib -p verrou-crypto-core

# Vault (no Tauri dependencies)
cargo build --lib -p verrou-vault

# Full workspace
cargo build --workspace
```

### Tests

```bash
# Rust tests (crypto KAT vectors, integration, proptests)
cargo test --workspace

# Frontend tests (components, hooks, IPC)
npm test
```

### Linting

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check
```

## Project Structure

```
Verrou/
├── crates/
│   ├── verrou-crypto-core/     # Cryptographic primitives (audit target)
│   │   ├── src/
│   │   │   ├── kem.rs          # X25519 + ML-KEM-1024 hybrid KEM
│   │   │   ├── kdf.rs          # Argon2id key derivation
│   │   │   ├── symmetric.rs    # AES-256-GCM AEAD
│   │   │   ├── slots.rs        # Key slot wrapping (password/biometric/recovery/hardware)
│   │   │   ├── vault_format.rs # Binary vault format (seal/unseal)
│   │   │   ├── totp.rs         # TOTP/HOTP generation (RFC 6238/4226)
│   │   │   ├── bip39/          # BIP39 mnemonic (10 languages)
│   │   │   ├── password/       # Password/passphrase generation
│   │   │   ├── signing.rs      # Ed25519 vault signing
│   │   │   ├── transfer/       # QR transfer encryption
│   │   │   ├── biometric.rs    # Biometric token types
│   │   │   ├── hardware_key.rs # Hardware security key types
│   │   │   └── memory.rs       # mlock/Zeroize memory protection
│   │   └── tests/              # KAT vectors, proptests, integration
│   └── verrou-vault/           # Business logic
│       ├── src/
│       │   ├── lifecycle.rs    # Create, unlock, lock, change password
│       │   ├── entries.rs      # CRUD for all secret types
│       │   ├── folders.rs      # Folder hierarchy
│       │   ├── attachments.rs  # File attachments
│       │   ├── import/         # Aegis, Google Auth, 2FAS, .verrou
│       │   ├── export/         # .verrou encrypted export
│       │   ├── health.rs       # Password health analysis
│       │   ├── preferences.rs  # User settings
│       │   └── transfer.rs     # QR transfer session management
│       └── tests/              # Integration tests
├── src-tauri/                  # Tauri application shell
│   ├── src/
│   │   ├── commands/           # IPC command handlers
│   │   ├── platform/           # OS-specific (clipboard, biometric, tray, hardware key)
│   │   └── lib.rs              # Command registration
│   └── Cargo.toml
├── src/                        # SolidJS frontend
│   ├── features/               # Feature modules (entries, vault, folders, etc.)
│   ├── components/             # Shared UI components
│   ├── i18n/                   # Translations (en, fr)
│   └── styles/                 # CSS Modules + design tokens
├── .github/workflows/ci.yml   # CI: build, lint, clippy, tests, security checks
└── LICENSE                     # GPL-3.0-or-later
```

## CI Pipeline

Every push and PR runs:

1. Frontend build (`npm run build`)
2. Rust workspace build
3. `cargo fmt` check
4. `cargo clippy` with `-D warnings`
5. `cargo deny` (license and advisory audit)
6. Zero-network dependency verification
7. Crypto-core dependency count check (max 30 direct deps)
8. Secret logging scan
9. Rust test suite
10. Frontend test suite
11. Binary hardening verification (PRs only)

## Contributing

Contributions are welcome. Please open an issue before starting work on large changes.

1. Fork the repository
2. Create a feature branch
3. Ensure `cargo test --workspace` and `npm test` pass
4. Ensure `cargo clippy --workspace --all-targets -- -D warnings` is clean
5. Open a pull request

## License

[GPL-3.0-or-later](LICENSE) — Copyright 2026 Arnault Pascual
