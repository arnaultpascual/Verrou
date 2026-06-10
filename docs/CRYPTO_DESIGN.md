# Verrou — Cryptographic Design

This document describes Verrou's cryptography **as implemented**. It is the
reference for reviewers and auditors. Where a capability is roadmapped rather
than shipped, it is marked explicitly.

> **Design stance.** Verrou is offline-first. A local vault does not *need*
> public-key cryptography for its core job, so the data-at-rest path is
> **entirely symmetric** — which is inherently quantum-resistant. Post-quantum
> *public-key* primitives (ML-KEM, ML-DSA) are used where they add real value:
> protecting and authenticating portable **exports/backups**.

## Primitives

| Purpose | Primitive | Notes |
|---|---|---|
| Symmetric AEAD | AES-256-GCM (`ring`) | 96-bit random nonce per message; 128-bit tag |
| Database at rest | SQLCipher (AES-256-CBC + per-page HMAC) | raw 256-bit key, `kdf_iter=1` |
| Password KDF | Argon2id (RFC 9106) | tiered, hardware-calibrated |
| Fast KDF / combiner | HKDF-SHA256 | key derivation, hybrid combiner, biometric |
| Hashing | BLAKE3 | integrity, password-reuse grouping |
| Hybrid KEM | X25519 + ML-KEM-1024 (`libcrux` ≥ 0.0.9) | export key-wrapping |
| Hybrid signature | Ed25519 + ML-DSA-65 (`libcrux` ≥ 0.0.9) | export authenticity |
| CSPRNG | OS RNG (`getrandom` via `OsRng`) | all keys, nonces, salts |

All randomness for keys/nonces/salts comes from the OS CSPRNG. No non-CSPRNG is
used for secret material.

## Encryption at rest (defense in depth)

Two symmetric layers protect stored data:

1. **Layer 1 — SQLCipher.** The entire SQLite database is encrypted with
   AES-256 + per-page HMAC. The 256-bit key is injected raw
   (`PRAGMA key = "x'<hex>'"; PRAGMA kdf_iter = 1`) — Verrou does its own KDF, so
   SQLCipher's internal PBKDF2 is disabled.
2. **Layer 2 — per-field AES-256-GCM.** Each entry's secret payload is
   additionally sealed with AES-256-GCM under the master key before storage.

Both layers are symmetric. AES-256 and Argon2id are quantum-resistant (Grover
gives at most a square-root speedup, leaving AES-256 at ~128-bit effective
security; memory-hardness defeats quantum brute force). **No classical
public-key cryptography guards data at rest**, so there is nothing for Shor's
algorithm to break — i.e. no "harvest-now-decrypt-later" exposure of the vault.

## Key hierarchy and slots

```
unlock factor ──derive──► wrapping key ──AES-256-GCM unwrap──► master key ──► data
```

- **Master key**: a random 256-bit value (`OsRng`) generated at vault creation.
  It is never stored in the clear; only wrapped copies (slots) are persisted.
- **Key slots**: each slot is an AES-256-GCM-wrapped copy of the same master
  key, under a 32-byte *wrapping key*, with a **per-slot-type AAD**
  (`verrou-slot-{password,biometric,recovery,hardware}`) so a slot of one type
  cannot be unwrapped as another. Adding/removing a slot never re-encrypts data.
- Wrapping keys per factor:
  - **Password / Recovery** → Argon2id over the password / recovery code.
  - **Biometric** → HKDF-SHA256 over a high-entropy secret held in the OS
    keychain (see "Biometric").

### Header integrity (keyed MAC)

The unencrypted header (KDF params, slots, salts) carries a **keyed BLAKE3 MAC**
over its authenticated subset — `version`, `session_params`, `sensitive_params`,
`slot_count`, slots, and slot salts. The MAC key is derived from the master key
(`BLAKE3-KDF`, context `VERROU-HEADER-MAC-v1`), so it is computed only when the
key is available (vault creation and every slot mutation) and **verified
fail-closed on unlock** with a constant-time comparison. Mutable brute-force
counters are excluded so they can update without the key.

This detects at-rest tampering of metadata that a normal password-slot unwrap
does not exercise — e.g. a downgraded `sensitive_params` or a swapped/removed
recovery slot. Vaults created before this field adopt a MAC on first unlock
(trust-on-first-use); the field is `serde`-optional, so old and new app versions
stay format-compatible.

### KDF tiering

Argon2id parameters are calibrated to the user's hardware at vault creation and
stored in the vault header. Calibration finds the achievable memory ceiling
(512 → 256 → 128 MiB by trial allocation), then **times a real derivation** and
scales iterations so each tier approximates its target (Argon2id runtime is
linear in `t_cost`). Two parameter sets are stored:

| Tier | Target | Baseline params |
|---|---|---|
| Fast | ~1 s | 256 MiB, ≥2 passes, 4 lanes |
| Balanced | ~1.5–2 s | 512 MiB, ≥3 passes, 4 lanes |
| Maximum | ~3–4 s | 512 MiB, ≥4 passes, 4 lanes |

Iteration counts rise on fast hardware (to hold per-guess cost near the target)
and fall on slow hardware (clamped to a floor of 2), so the table shows
baselines, not fixed values. `derive` also rejects out-of-range parameters
(memory capped at 4 GiB) so a tampered header or malicious import cannot force an
allocation large enough to abort the process.

The unlock delay is *real* Argon2id work (memory-hard), not an artificial delay
— it is the brute-force cost an attacker pays per guess.

> **Known limitation (H5).** Sensitive-operation re-auth currently runs the
> vault's `session_params` tier, not always Maximum. Aligning sensitive re-auth
> to a Maximum-tier slot is tracked for the key-slot rework.

## Long-term vault keypairs

Each vault has a long-term **hybrid KEM keypair** (X25519 + ML-KEM-1024) and a
**hybrid signing keypair** (Ed25519 + ML-DSA-65). They are **deterministically
derived from the master key** via HKDF-SHA256 on every unlock —
`derive_keypair(master_key, context)` with domain-separated labels
(`VERROU-KEM-KEYPAIR-v1` / `VERROU-SIGN-KEYPAIR-v1`) — so they are stable across
unlocks and require **no storage and no migration**. Private key material never
leaves `verrou-crypto-core`.

## Exports and backups (post-quantum in the data path)

An exported `.verrou` file is a binary **envelope** (magic `VRENV1`) wrapping the
encrypted payload, adding two post-quantum guarantees:

1. **KEM key-wrapping.** A fresh random content key encrypts the payload
   (AES-256-GCM). That content key is encapsulated to the vault's hybrid KEM
   public key (`encapsulate` → ciphertext + shared secret; the content key is
   sealed under the shared secret). The same vault can re-import **without the
   export password**. A password slot is also present (Argon2id) for portability
   / restoring to a different or freshly-installed vault.
2. **Hybrid signature.** The whole envelope is signed with the vault's
   Ed25519 + ML-DSA-65 keypair; the signing public key is embedded.

On import, the signature is **verified fail-closed before any decryption**. The
content key is recovered via the KEM path (same vault) or the password slot
(portability). The envelope is mandatory — a non-envelope file is rejected.

The hybrid construction means a break of **either** the classical **or** the
post-quantum half alone is survivable: the combiner is
`HKDF-SHA256(x25519_ss ‖ ml_kem_ss)`, and both signature components must verify.

## QR device transfer

Desktop-to-desktop transfer derives an AES-256-GCM key from a one-time diceware
verification phrase via HKDF-SHA256 (`verrou-qr-transfer-v1`). Symmetric →
quantum-resistant. No network is used; data moves as scanned QR chunks.

## Memory protection

Key material uses `secrecy`/`SecretBuffer` types with `mlock` pinning and
`Zeroize`-on-drop. Secret types never implement `Debug`/`Display` in the clear.
CI fails the build if a logging macro is passed `key`/`secret`/`password`/
`seed`/`entropy`.

## Biometric unlock

Enrollment generates a random 32-byte secret stored in the OS keychain with
biometric access control (Touch ID / Windows Hello). Unlock retrieves it after
a biometric prompt and derives the slot wrapping key via HKDF-SHA256. This path
is **fully symmetric → quantum-safe**, and hardware-gated by the OS biometric.

> **Roadmap (deferred).** The biometric secret is currently *stored* in the
> keychain (extractable if the keychain is compromised). A future hardening will
> bind it to a **non-exportable Secure-Enclave (macOS) / TPM (Windows)
> resident key** so the wrapping key cannot be extracted even if storage is
> compromised. This is a hardware-extraction hardening (the path is already
> quantum-safe) and requires real-device testing + external audit. Hardware-key
> (security-token) unlock is detection-only today; full unlock is roadmapped.

## Post-quantum posture — summary

| Surface | Mechanism | Quantum-safe? |
|---|---|---|
| Data at rest (DB + fields) | AES-256 + Argon2id | Yes (symmetric) |
| Password / recovery unlock | Argon2id → AES-256-GCM slot | Yes (symmetric) |
| Biometric unlock | HKDF(keychain secret) → slot | Yes (symmetric) |
| Export / backup confidentiality | Hybrid X25519+ML-KEM-1024 KEM-wrap (+ Argon2id password slot) | Yes (hybrid PQ) |
| Export / backup authenticity | Hybrid Ed25519+ML-DSA-65 signature | Yes (hybrid PQ) |
| QR transfer | HKDF(phrase) → AES-256-GCM | Yes (symmetric) |

There is no point in the design where a classical public-key primitive is the
sole protector of a secret.

## Validation

KAT vectors pin every primitive (AES-GCM, Argon2id, HKDF combiner, X25519,
ML-KEM-1024, ML-DSA-65, Ed25519, TOTP/HOTP, BIP39, biometric HKDF, derived
keypairs). Property tests, a Welch t-test timing-side-channel test, and
zeroize-on-drop sentinel tests run in CI. The untrusted import parsers and the
export-envelope parser are fuzzed (no panic / OOM on arbitrary input).
