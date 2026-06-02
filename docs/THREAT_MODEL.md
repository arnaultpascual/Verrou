# Verrou — Threat Model

This document states what Verrou defends against, what it explicitly does not,
and the assumptions those guarantees rest on. It complements
[`CRYPTO_DESIGN.md`](./CRYPTO_DESIGN.md).

## Assets

1. **Vault secrets** — TOTP/HOTP secrets, BIP39 seed phrases, recovery codes,
   credentials (passwords), secure notes, attachments.
2. **The master key** — the 256-bit key that unlocks all of the above.
3. **Exports / backups** — portable `.verrou` files containing the same secrets.
4. **Metadata** — entry names, issuers, folder structure (encrypted at rest).

## Trust assumptions

- The **operating system and hardware are trusted** while the app runs. Verrou
  cannot defend secrets against a compromised kernel, root-level malware, a
  hardware keylogger, or a malicious OS clipboard/keychain service.
- The **user's device is physically controlled** by the user. Verrou reduces
  exposure when a *locked* device or a *vault file* is stolen, not when an
  attacker operates an *unlocked* session.
- The **WebView (frontend) is untrusted.** All cryptography runs in Rust; the
  IPC boundary returns display-safe DTOs only, and sensitive reveals require
  re-authentication. A compromised WebView must not be able to exfiltrate
  secrets beyond what the user has explicitly revealed.

## Adversaries and defenses

### A1 — Offline attacker with the encrypted vault file / stolen locked device
The strongest realistic adversary. Has the `vault.db`, `vault.verrou`, and any
exports, but not the password.
- **Defense:** data at rest is AES-256 (SQLCipher) + per-field AES-256-GCM; the
  master key is unwrapped only via Argon2id over the password (memory-hard,
  hardware-tuned). Brute force pays the full Argon2id cost per guess.

### A2 — Quantum-capable attacker ("harvest now, decrypt later")
Stores the encrypted vault/export today to decrypt with a future quantum
computer.
- **Defense:** the at-rest and unlock paths are **symmetric** (AES-256 +
  Argon2id + HKDF), which are quantum-resistant — and there is **no classical
  public-key primitive guarding data at rest** for Shor's algorithm to attack.
  Exports add a **hybrid X25519+ML-KEM-1024** KEM wrap and a hybrid
  Ed25519+ML-DSA-65 signature, so a captured backup resists quantum decryption
  even if the password is weak, and a break of *either* the classical or the
  post-quantum half alone is survivable.

### A3 — Tampering with stored data or backups
- **Defense:** AES-256-GCM tags and SQLCipher per-page HMAC detect at-rest
  modification; `.verrou` exports are signed (hybrid) and verified **fail-closed
  before any decryption**. Vault integrity is checked on unlock.

### A4 — Brute-force / online guessing of the master password
- **Defense:** memory-hard Argon2id + rate-limited unlock attempts with
  exponential backoff.

### A5 — Untrusted / compromised WebView
- **Defense:** IPC returns DTOs only (never domain entities); seed phrases and
  recovery codes are **not** returned by general read commands — only via
  re-authenticated `reveal_*` paths; backup *restore* requires password re-auth;
  the untrusted import parsers and export-envelope parser are bounds-checked and
  fuzzed (no panic/OOM on arbitrary input).

### A6 — Memory disclosure (swap, core dump, cold boot)
- **Defense:** key material is `mlock`-pinned and `Zeroize`d on drop; secret
  types never render in the clear; CI blocks secret logging. *Caveat:* serde
  (de)serialization creates short-lived intermediate `String`s that cannot be
  individually zeroized — an accepted, documented residual.

### A7 — Clipboard / shoulder-surfing leakage
- **Defense:** copied secrets use the OS "concealed" clipboard type, are
  excluded from clipboard history where supported, auto-clear after a timeout,
  and are **cleared immediately on vault lock** (manual, tray, or auto-lock).
  Revealed secrets in the quick-access popup clear on window blur and on lock.

### A8 — Supply-chain / dependency risk
- **Defense (partial):** `cargo deny` enforces license/advisory/source policy
  and bans network-capable crates; the crypto-core crate caps direct
  dependencies and is zero-network (CI-verified). This *reduces* but does not
  *eliminate* supply-chain risk.

## Out of scope (explicit non-goals)

- A compromised OS, kernel, or root-level malware; hardware implants/keyloggers.
- An attacker with access to an **already-unlocked** vault session.
- **Extraction of the stored biometric secret** from a compromised OS keychain.
  The biometric unlock path is symmetric (quantum-safe) but the secret is
  currently *stored* in the keychain rather than bound to a non-exportable
  Secure-Enclave/TPM key. Non-extractable hardware binding is **roadmapped**
  (requires real-device testing + external audit).
- Advanced physical side-channels (power/EM analysis) beyond the constant-time
  comparisons used for MAC/tag checks.
- Denial of service against the local app process itself.
- Coercion of the user to unlock ("rubber-hose"); there is no duress mechanism.

## Cryptographic assumptions

Security rests on the standard hardness of AES-256, SHA-2/SHA-3, Argon2id,
X25519, ML-KEM-1024, Ed25519, and ML-DSA-65. The hybrid constructions are
designed so that a complete break of the classical **or** the post-quantum
component alone does not compromise confidentiality (KEM) or authenticity
(signature).

## Reporting a vulnerability

See [`SECURITY.md`](../SECURITY.md) for the responsible-disclosure process and
security contact. *(Pending — to be added before public release.)*
