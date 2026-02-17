//! Hybrid KEM: X25519 + ML-KEM-1024.
//!
//! This module provides:
//! - [`generate_keypair`] — generate a hybrid X25519 + ML-KEM-1024 key pair
//! - [`encapsulate`] — encapsulate a shared secret for a recipient's public key
//! - [`decapsulate`] — recover the shared secret using the recipient's private key
//!
//! # Layer 3 Encryption
//!
//! This is Layer 3 of the 3-layer VERROU encryption model:
//! - Layer 1: `SQLCipher` (entire DB file)
//! - Layer 2: AES-256-GCM (per-field, `symmetric.rs`)
//! - **Layer 3: PQ hybrid KEM (key wrapping for export, this module)**
//!
//! # Hybrid Security Guarantee (NFR14)
//!
//! Both algorithms must be broken simultaneously to compromise the shared
//! secret. If either X25519 or ML-KEM-1024 remains secure, the HKDF-derived
//! output is computationally indistinguishable from random.

use crate::error::CryptoError;
use crate::memory::SecretBuffer;
use rand::rngs::OsRng;
use rand::RngCore;
use ring::hkdf;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// X25519 public key length in bytes (256 bits).
pub const X25519_PUBLIC_KEY_LEN: usize = 32;

/// X25519 private key length in bytes (256 bits).
const X25519_PRIVATE_KEY_LEN: usize = 32;

/// ML-KEM-1024 public key length in bytes (FIPS 203).
pub const ML_KEM_PUBLIC_KEY_LEN: usize = 1568;

/// ML-KEM-1024 private key length in bytes (FIPS 203).
const ML_KEM_PRIVATE_KEY_LEN: usize = 3168;

/// ML-KEM-1024 ciphertext length in bytes (FIPS 203).
pub const ML_KEM_CIPHERTEXT_LEN: usize = 1568;

/// Combined shared secret output length in bytes (256 bits).
pub const SHARED_SECRET_LEN: usize = 32;

/// ML-KEM-1024 key generation seed size (FIPS 203: d || z = 64 bytes).
const ML_KEM_KEYGEN_SEED_LEN: usize = 64;

/// ML-KEM-1024 encapsulation randomness size (32 bytes).
const ML_KEM_ENCAPS_RAND_LEN: usize = 32;

/// HKDF domain separation info string for the hybrid KEM combiner.
const HKDF_INFO: &[u8] = b"VERROU-HYBRID-KEM-v1";

/// Combined X25519 + ML-KEM shared secret input length for HKDF (64 bytes).
const COMBINED_SS_LEN: usize = 64;

// ---------------------------------------------------------------------------
// HKDF output length marker
// ---------------------------------------------------------------------------

/// Marker type for `ring::hkdf::Prk::expand` — requests 32-byte output.
struct HkdfLen32;

impl hkdf::KeyType for HkdfLen32 {
    fn len(&self) -> usize {
        SHARED_SECRET_LEN
    }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Hybrid public key: X25519 + ML-KEM-1024.
///
/// This is the recipient's public key used by the sender during encapsulation.
/// Safe to transmit in the clear.
///
/// Use [`HybridPublicKey::new`] to construct with length validation, or
/// deserialize via serde (length is validated at [`encapsulate`] time).
#[must_use = "public key must be stored or transmitted"]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HybridPublicKey {
    /// X25519 public key (32 bytes).
    pub x25519: [u8; X25519_PUBLIC_KEY_LEN],
    /// ML-KEM-1024 public key (1568 bytes).
    pub ml_kem: Vec<u8>,
}

impl HybridPublicKey {
    /// Create a new `HybridPublicKey` with length validation.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::KeyEncapsulation`] if the ML-KEM public key
    /// is not exactly [`ML_KEM_PUBLIC_KEY_LEN`] (1568) bytes.
    pub fn new(x25519: [u8; X25519_PUBLIC_KEY_LEN], ml_kem: Vec<u8>) -> Result<Self, CryptoError> {
        if ml_kem.len() != ML_KEM_PUBLIC_KEY_LEN {
            return Err(CryptoError::KeyEncapsulation(format!(
                "invalid ML-KEM public key length: {} bytes (expected {ML_KEM_PUBLIC_KEY_LEN})",
                ml_kem.len()
            )));
        }
        Ok(Self { x25519, ml_kem })
    }
}

/// Hybrid private key: X25519 + ML-KEM-1024.
///
/// Both private key components are stored in [`SecretBuffer`] (mlocked, zeroized
/// on drop). This type intentionally does NOT implement `Serialize` to prevent
/// accidental serialization of private key material.
pub struct HybridPrivateKey {
    /// X25519 private key (32 bytes) in secure memory.
    pub(crate) x25519: SecretBuffer,
    /// ML-KEM-1024 private key (3168 bytes) in secure memory.
    pub(crate) ml_kem: SecretBuffer,
}

impl std::fmt::Debug for HybridPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HybridPrivateKey(***)")
    }
}

/// Hybrid ciphertext: X25519 ephemeral public key + ML-KEM-1024 ciphertext.
///
/// Produced by [`encapsulate`] and consumed by [`decapsulate`].
///
/// Use [`HybridCiphertext::new`] to construct with length validation.
#[must_use = "ciphertext must be stored or transmitted"]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HybridCiphertext {
    /// Sender's ephemeral X25519 public key (32 bytes).
    pub x25519_public: [u8; X25519_PUBLIC_KEY_LEN],
    /// ML-KEM-1024 ciphertext (1568 bytes).
    pub ml_kem_ciphertext: Vec<u8>,
}

impl HybridCiphertext {
    /// Create a new `HybridCiphertext` with length validation.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::KeyEncapsulation`] if the ML-KEM ciphertext
    /// is not exactly [`ML_KEM_CIPHERTEXT_LEN`] (1568) bytes.
    pub fn new(
        x25519_public: [u8; X25519_PUBLIC_KEY_LEN],
        ml_kem_ciphertext: Vec<u8>,
    ) -> Result<Self, CryptoError> {
        if ml_kem_ciphertext.len() != ML_KEM_CIPHERTEXT_LEN {
            return Err(CryptoError::KeyEncapsulation(format!(
                "invalid ML-KEM ciphertext length: {} bytes (expected {ML_KEM_CIPHERTEXT_LEN})",
                ml_kem_ciphertext.len()
            )));
        }
        Ok(Self {
            x25519_public,
            ml_kem_ciphertext,
        })
    }
}

/// Hybrid key pair: public + private.
///
/// Produced by [`generate_keypair`].
#[must_use = "key pair must be stored"]
pub struct HybridKeyPair {
    /// Public key (safe to share).
    pub public: HybridPublicKey,
    /// Private key (must be kept secret).
    pub private: HybridPrivateKey,
}

impl std::fmt::Debug for HybridKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HybridKeyPair(***)")
    }
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

/// Generate a hybrid X25519 + ML-KEM-1024 key pair.
///
/// Both private key components are stored in [`SecretBuffer`] (mlocked,
/// zeroized on drop). The ML-KEM key pair is generated using 64 bytes
/// of CSPRNG randomness per FIPS 203.
///
/// # Errors
///
/// Returns [`CryptoError::KeyEncapsulation`] if CSPRNG or key generation fails.
/// Returns [`CryptoError::SecureMemory`] if secure buffer allocation fails.
pub fn generate_keypair() -> Result<HybridKeyPair, CryptoError> {
    // -- X25519 via x25519-dalek StaticSecret --
    let x25519_secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let x25519_public = x25519_dalek::PublicKey::from(&x25519_secret);

    let mut x25519_sk_bytes = x25519_secret.to_bytes();
    let x25519_sk_buf = SecretBuffer::new(&x25519_sk_bytes).map_err(|e| {
        x25519_sk_bytes.zeroize();
        CryptoError::SecureMemory(format!("X25519 private key allocation failed: {e}"))
    })?;
    x25519_sk_bytes.zeroize();
    // x25519_secret is Zeroize-on-drop via x25519-dalek "zeroize" feature.

    // -- ML-KEM-1024 via libcrux --
    let mut ml_kem_seed = [0u8; ML_KEM_KEYGEN_SEED_LEN];
    OsRng.fill_bytes(&mut ml_kem_seed);

    let ml_kem_kp = libcrux_ml_kem::mlkem1024::generate_key_pair(ml_kem_seed);
    ml_kem_seed.zeroize();

    let ml_kem_pub_raw: &[u8] = ml_kem_kp.pk();
    let ml_kem_sec_raw: &[u8] = ml_kem_kp.sk();

    let ml_kem_sk_buf = SecretBuffer::new(ml_kem_sec_raw).map_err(|e| {
        CryptoError::SecureMemory(format!("ML-KEM private key allocation failed: {e}"))
    })?;

    let mut ml_kem_pk_vec = Vec::with_capacity(ML_KEM_PUBLIC_KEY_LEN);
    ml_kem_pk_vec.extend_from_slice(ml_kem_pub_raw);

    Ok(HybridKeyPair {
        public: HybridPublicKey {
            x25519: x25519_public.to_bytes(),
            ml_kem: ml_kem_pk_vec,
        },
        private: HybridPrivateKey {
            x25519: x25519_sk_buf,
            ml_kem: ml_kem_sk_buf,
        },
    })
}

// ---------------------------------------------------------------------------
// Encapsulation
// ---------------------------------------------------------------------------

/// Encapsulate a shared secret for the recipient's hybrid public key.
///
/// Generates a fresh ephemeral X25519 key pair, performs ECDH with the
/// recipient's X25519 public key, encapsulates against the recipient's
/// ML-KEM-1024 public key, and combines both shared secrets via
/// HKDF-SHA256 with domain separation.
///
/// Returns a [`HybridCiphertext`] (to send to the recipient) and the
/// combined [`SecretBuffer`] (the shared secret).
///
/// # Errors
///
/// Returns [`CryptoError::KeyEncapsulation`] if:
/// - The ML-KEM public key is invalid (FIPS 203 validation failure)
/// - HKDF derivation fails
///
/// Returns [`CryptoError::SecureMemory`] if secure buffer allocation fails.
pub fn encapsulate(
    recipient_public: &HybridPublicKey,
) -> Result<(HybridCiphertext, SecretBuffer), CryptoError> {
    // -- Validate ML-KEM public key (FIPS 203 requirement) --
    let ml_kem_pk = ml_kem_public_key_from_bytes(&recipient_public.ml_kem)?;
    if !libcrux_ml_kem::mlkem1024::validate_public_key(&ml_kem_pk) {
        return Err(CryptoError::KeyEncapsulation(
            "invalid ML-KEM-1024 public key".into(),
        ));
    }

    // -- X25519 ephemeral ECDH --
    let ephemeral_secret = x25519_dalek::EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = x25519_dalek::PublicKey::from(&ephemeral_secret);

    let peer_x25519_pk = x25519_dalek::PublicKey::from(recipient_public.x25519);
    let x25519_shared = ephemeral_secret.diffie_hellman(&peer_x25519_pk);
    // ephemeral_secret is consumed by diffie_hellman (move semantics) and zeroized.

    // -- ML-KEM-1024 encapsulation --
    let mut ml_kem_rand = [0u8; ML_KEM_ENCAPS_RAND_LEN];
    OsRng.fill_bytes(&mut ml_kem_rand);

    let (ml_kem_ct, ml_kem_ss) = libcrux_ml_kem::mlkem1024::encapsulate(&ml_kem_pk, ml_kem_rand);
    ml_kem_rand.zeroize();

    // -- Combine via HKDF-SHA256 --
    let combined = combine_shared_secrets(x25519_shared.as_bytes(), &ml_kem_ss)?;

    // -- Build ciphertext --
    let mut ml_kem_ct_vec = Vec::with_capacity(ML_KEM_CIPHERTEXT_LEN);
    ml_kem_ct_vec.extend_from_slice(ml_kem_ct.as_ref());

    let ciphertext = HybridCiphertext {
        x25519_public: ephemeral_public.to_bytes(),
        ml_kem_ciphertext: ml_kem_ct_vec,
    };

    Ok((ciphertext, combined))
}

// ---------------------------------------------------------------------------
// Decapsulation
// ---------------------------------------------------------------------------

/// Recover the shared secret using the recipient's hybrid private key.
///
/// Performs X25519 ECDH with the sender's ephemeral public key and
/// ML-KEM-1024 decapsulation, then combines both shared secrets via
/// the same HKDF-SHA256 derivation used in [`encapsulate`].
///
/// # Errors
///
/// Returns [`CryptoError::KeyEncapsulation`] if:
/// - The X25519 private key has incorrect length
/// - The ML-KEM private key has incorrect length
/// - The ML-KEM ciphertext has incorrect length
/// - HKDF derivation fails
///
/// Returns [`CryptoError::SecureMemory`] if secure buffer allocation fails.
pub fn decapsulate(
    ciphertext: &HybridCiphertext,
    private_key: &HybridPrivateKey,
) -> Result<SecretBuffer, CryptoError> {
    // -- Reconstruct X25519 static secret from stored bytes --
    let x25519_sk_bytes = private_key.x25519.expose();
    if x25519_sk_bytes.len() != X25519_PRIVATE_KEY_LEN {
        return Err(CryptoError::KeyEncapsulation(format!(
            "invalid X25519 private key length: {} bytes (expected {X25519_PRIVATE_KEY_LEN})",
            x25519_sk_bytes.len()
        )));
    }
    let mut sk_arr = [0u8; X25519_PRIVATE_KEY_LEN];
    sk_arr.copy_from_slice(x25519_sk_bytes);
    let x25519_secret = x25519_dalek::StaticSecret::from(sk_arr);
    sk_arr.zeroize();

    // -- X25519 ECDH with sender's ephemeral public key --
    let peer_ephemeral_pk = x25519_dalek::PublicKey::from(ciphertext.x25519_public);
    let x25519_shared = x25519_secret.diffie_hellman(&peer_ephemeral_pk);
    // x25519_secret is Zeroize-on-drop via x25519-dalek "zeroize" feature.

    // -- ML-KEM-1024 decapsulation --
    let ml_kem_secret_key = ml_kem_private_key_from_bytes(private_key.ml_kem.expose())?;
    let ml_kem_ct = ml_kem_ciphertext_from_bytes(&ciphertext.ml_kem_ciphertext)?;

    let ml_kem_shared = libcrux_ml_kem::mlkem1024::decapsulate(&ml_kem_secret_key, &ml_kem_ct);

    // -- Combine via HKDF-SHA256 (same derivation as encapsulate) --
    combine_shared_secrets(x25519_shared.as_bytes(), &ml_kem_shared)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Combine two 32-byte shared secrets via HKDF-SHA256 with domain separation.
///
/// Input: `x25519_ss (32 bytes) || ml_kem_ss (32 bytes)` = 64 bytes IKM.
/// Salt: empty (per RFC 5869 — filled with zeros internally).
/// Info: `b"VERROU-HYBRID-KEM-v1"` for domain separation.
/// Output: 32 bytes.
fn combine_shared_secrets(
    x25519_ss: &[u8; SHARED_SECRET_LEN],
    ml_kem_ss: &[u8; SHARED_SECRET_LEN],
) -> Result<SecretBuffer, CryptoError> {
    // Concatenate both shared secrets.
    let mut combined = [0u8; COMBINED_SS_LEN];
    combined[..SHARED_SECRET_LEN].copy_from_slice(x25519_ss);
    combined[SHARED_SECRET_LEN..].copy_from_slice(ml_kem_ss);

    // HKDF-SHA256 Extract.
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]);
    let prk = salt.extract(&combined);
    combined.zeroize();

    // HKDF-SHA256 Expand with domain separation.
    let okm = prk
        .expand(&[HKDF_INFO], HkdfLen32)
        .map_err(|_| CryptoError::KeyEncapsulation("HKDF expand failed".into()))?;

    let mut output = [0u8; SHARED_SECRET_LEN];
    okm.fill(&mut output)
        .map_err(|_| CryptoError::KeyEncapsulation("HKDF fill failed".into()))?;

    let result = SecretBuffer::new(&output)
        .map_err(|e| CryptoError::SecureMemory(format!("shared secret allocation failed: {e}")))?;
    output.zeroize();

    Ok(result)
}

/// Parse ML-KEM-1024 public key from bytes.
fn ml_kem_public_key_from_bytes(
    bytes: &[u8],
) -> Result<libcrux_ml_kem::mlkem1024::MlKem1024PublicKey, CryptoError> {
    libcrux_ml_kem::mlkem1024::MlKem1024PublicKey::try_from(bytes).map_err(|_| {
        CryptoError::KeyEncapsulation(format!(
            "invalid ML-KEM public key length: {} bytes (expected {ML_KEM_PUBLIC_KEY_LEN})",
            bytes.len()
        ))
    })
}

/// Parse ML-KEM-1024 private key from bytes.
fn ml_kem_private_key_from_bytes(
    bytes: &[u8],
) -> Result<libcrux_ml_kem::mlkem1024::MlKem1024PrivateKey, CryptoError> {
    libcrux_ml_kem::mlkem1024::MlKem1024PrivateKey::try_from(bytes).map_err(|_| {
        CryptoError::KeyEncapsulation(format!(
            "invalid ML-KEM private key length: {} bytes (expected {ML_KEM_PRIVATE_KEY_LEN})",
            bytes.len()
        ))
    })
}

/// Parse ML-KEM-1024 ciphertext from bytes.
fn ml_kem_ciphertext_from_bytes(
    bytes: &[u8],
) -> Result<libcrux_ml_kem::mlkem1024::MlKem1024Ciphertext, CryptoError> {
    libcrux_ml_kem::mlkem1024::MlKem1024Ciphertext::try_from(bytes).map_err(|_| {
        CryptoError::KeyEncapsulation(format!(
            "invalid ML-KEM ciphertext length: {} bytes (expected {ML_KEM_CIPHERTEXT_LEN})",
            bytes.len()
        ))
    })
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CryptoError;

    #[test]
    fn generate_keypair_produces_correct_lengths() {
        let kp = generate_keypair().expect("keygen should succeed");
        assert_eq!(kp.public.x25519.len(), X25519_PUBLIC_KEY_LEN);
        assert_eq!(kp.public.ml_kem.len(), ML_KEM_PUBLIC_KEY_LEN);
        assert_eq!(kp.private.x25519.len(), X25519_PRIVATE_KEY_LEN);
        assert_eq!(kp.private.ml_kem.len(), ML_KEM_PRIVATE_KEY_LEN);
    }

    #[test]
    fn encapsulate_decapsulate_roundtrip() {
        let kp = generate_keypair().expect("keygen should succeed");
        let (ct, ss_enc) = encapsulate(&kp.public).expect("encapsulate should succeed");
        let ss_dec = decapsulate(&ct, &kp.private).expect("decapsulate should succeed");
        assert_eq!(
            ss_enc.expose(),
            ss_dec.expose(),
            "encapsulate/decapsulate shared secrets must match"
        );
    }

    #[test]
    fn wrong_private_key_produces_different_shared_secret() {
        let kp1 = generate_keypair().expect("keygen should succeed");
        let kp2 = generate_keypair().expect("keygen should succeed");
        let (ct, ss_enc) = encapsulate(&kp1.public).expect("encapsulate should succeed");

        // Decapsulate with wrong key pair — ML-KEM implicit rejection means
        // decapsulate still returns a value, but it differs from the original.
        let ss_wrong = decapsulate(&ct, &kp2.private).expect("decapsulate should succeed");
        assert_ne!(
            ss_enc.expose(),
            ss_wrong.expose(),
            "wrong private key should produce different shared secret"
        );
    }

    #[test]
    fn tampered_x25519_ciphertext_produces_different_shared_secret() {
        let kp = generate_keypair().expect("keygen should succeed");
        let (mut ct, ss_enc) = encapsulate(&kp.public).expect("encapsulate should succeed");

        // Tamper with X25519 ephemeral public key.
        ct.x25519_public[0] ^= 0xFF;

        let ss_tampered = decapsulate(&ct, &kp.private).expect("decapsulate should succeed");
        assert_ne!(
            ss_enc.expose(),
            ss_tampered.expose(),
            "tampered X25519 ciphertext should produce different shared secret"
        );
    }

    #[test]
    fn tampered_ml_kem_ciphertext_produces_different_shared_secret() {
        let kp = generate_keypair().expect("keygen should succeed");
        let (mut ct, ss_enc) = encapsulate(&kp.public).expect("encapsulate should succeed");

        // Tamper with ML-KEM ciphertext — implicit rejection returns different secret.
        ct.ml_kem_ciphertext[0] ^= 0xFF;

        let ss_tampered = decapsulate(&ct, &kp.private).expect("decapsulate should succeed");
        assert_ne!(
            ss_enc.expose(),
            ss_tampered.expose(),
            "tampered ML-KEM ciphertext should produce different shared secret"
        );
    }

    #[test]
    fn two_encapsulations_produce_different_ciphertexts() {
        let kp = generate_keypair().expect("keygen should succeed");
        let (ct_a, _) = encapsulate(&kp.public).expect("encapsulate should succeed");
        let (ct_b, _) = encapsulate(&kp.public).expect("encapsulate should succeed");
        assert_ne!(
            ct_a.x25519_public, ct_b.x25519_public,
            "ephemeral X25519 public keys should differ"
        );
        assert_ne!(
            ct_a.ml_kem_ciphertext, ct_b.ml_kem_ciphertext,
            "ML-KEM ciphertexts should differ"
        );
    }

    #[test]
    fn private_key_debug_is_masked() {
        let kp = generate_keypair().expect("keygen should succeed");
        let debug = format!("{:?}", kp.private);
        assert_eq!(debug, "HybridPrivateKey(***)");
    }

    #[test]
    fn keypair_debug_is_masked() {
        let kp = generate_keypair().expect("keygen should succeed");
        let debug = format!("{kp:?}");
        assert_eq!(debug, "HybridKeyPair(***)");
    }

    #[test]
    fn public_key_and_ciphertext_serde_roundtrip() {
        let kp = generate_keypair().expect("keygen should succeed");
        let (ct, _) = encapsulate(&kp.public).expect("encapsulate should succeed");

        // Public key serde.
        let pk_json =
            serde_json::to_string(&kp.public).expect("public key serialize should succeed");
        let pk_deser: HybridPublicKey =
            serde_json::from_str(&pk_json).expect("public key deserialize should succeed");
        assert_eq!(kp.public.x25519, pk_deser.x25519);
        assert_eq!(kp.public.ml_kem, pk_deser.ml_kem);

        // Ciphertext serde.
        let ct_json = serde_json::to_string(&ct).expect("ciphertext serialize should succeed");
        let ct_deser: HybridCiphertext =
            serde_json::from_str(&ct_json).expect("ciphertext deserialize should succeed");
        assert_eq!(ct.x25519_public, ct_deser.x25519_public);
        assert_eq!(ct.ml_kem_ciphertext, ct_deser.ml_kem_ciphertext);
    }

    #[test]
    fn encapsulate_with_invalid_ml_kem_public_key_returns_error() {
        let kp = generate_keypair().expect("keygen should succeed");
        let bad_pk = HybridPublicKey {
            x25519: kp.public.x25519,
            ml_kem: vec![0u8; 10], // Too short — invalid.
        };
        let result = encapsulate(&bad_pk);
        assert!(
            matches!(result, Err(CryptoError::KeyEncapsulation(_))),
            "invalid ML-KEM public key should yield CryptoError::KeyEncapsulation"
        );
    }

    #[test]
    fn shared_secret_is_32_bytes() {
        let kp = generate_keypair().expect("keygen should succeed");
        let (_, ss) = encapsulate(&kp.public).expect("encapsulate should succeed");
        assert_eq!(ss.len(), SHARED_SECRET_LEN);
    }

    #[test]
    fn shared_secret_debug_is_masked() {
        let kp = generate_keypair().expect("keygen should succeed");
        let (_, ss) = encapsulate(&kp.public).expect("encapsulate should succeed");
        let debug = format!("{ss:?}");
        assert_eq!(debug, "SecretBuffer(***)");
    }

    // -- AC3: Hybrid security guarantee — zeroed single shared secret --

    #[test]
    fn zeroed_x25519_still_produces_valid_hkdf_output() {
        // Simulate X25519 being broken: its shared secret is all zeros.
        // The HKDF output must still be valid (non-zero, 32 bytes) from
        // the ML-KEM shared secret alone.
        let x25519_ss = [0u8; SHARED_SECRET_LEN];
        let ml_kem_ss: [u8; SHARED_SECRET_LEN] = [
            0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x11, 0x22, 0x33, 0x44,
            0x55, 0x66, 0x77, 0x88,
        ];
        let result = combine_shared_secrets(&x25519_ss, &ml_kem_ss)
            .expect("HKDF should succeed even with zeroed X25519");
        assert_eq!(result.len(), SHARED_SECRET_LEN);
        assert_ne!(result.expose(), &[0u8; SHARED_SECRET_LEN]);
        // Output must not be constant (all same byte).
        let first = result.expose()[0];
        assert!(result.expose().iter().any(|&b| b != first));
    }

    #[test]
    fn zeroed_ml_kem_still_produces_valid_hkdf_output() {
        // Simulate ML-KEM being broken: its shared secret is all zeros.
        // The HKDF output must still be valid from the X25519 secret alone.
        let x25519_ss: [u8; SHARED_SECRET_LEN] = [
            0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35,
            0x0f, 0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c,
            0x1e, 0x16, 0x17, 0x42,
        ];
        let ml_kem_ss = [0u8; SHARED_SECRET_LEN];
        let result = combine_shared_secrets(&x25519_ss, &ml_kem_ss)
            .expect("HKDF should succeed even with zeroed ML-KEM");
        assert_eq!(result.len(), SHARED_SECRET_LEN);
        assert_ne!(result.expose(), &[0u8; SHARED_SECRET_LEN]);
        let first = result.expose()[0];
        assert!(result.expose().iter().any(|&b| b != first));
    }

    #[test]
    fn zeroed_single_secret_differs_from_both_zeroed() {
        // Verify that zeroing one algorithm produces different output
        // than zeroing both (the HKDF extracts entropy from whichever
        // algorithm is unbroken).
        let real_ss: [u8; SHARED_SECRET_LEN] = [0xAA; SHARED_SECRET_LEN];
        let zero_ss = [0u8; SHARED_SECRET_LEN];

        let both_zero = combine_shared_secrets(&zero_ss, &zero_ss).expect("HKDF should succeed");
        let x25519_only = combine_shared_secrets(&real_ss, &zero_ss).expect("HKDF should succeed");
        let ml_kem_only = combine_shared_secrets(&zero_ss, &real_ss).expect("HKDF should succeed");

        // All three must be distinct.
        assert_ne!(both_zero.expose(), x25519_only.expose());
        assert_ne!(both_zero.expose(), ml_kem_only.expose());
        assert_ne!(x25519_only.expose(), ml_kem_only.expose());
    }

    // -- H2 fix: Constructor validation tests --

    #[test]
    fn hybrid_public_key_new_validates_length() {
        let valid = HybridPublicKey::new(
            [0u8; X25519_PUBLIC_KEY_LEN],
            vec![0u8; ML_KEM_PUBLIC_KEY_LEN],
        );
        assert!(valid.is_ok());

        let too_short = HybridPublicKey::new([0u8; X25519_PUBLIC_KEY_LEN], vec![0u8; 100]);
        assert!(matches!(too_short, Err(CryptoError::KeyEncapsulation(_))));

        let too_long = HybridPublicKey::new([0u8; X25519_PUBLIC_KEY_LEN], vec![0u8; 2000]);
        assert!(matches!(too_long, Err(CryptoError::KeyEncapsulation(_))));
    }

    #[test]
    fn hybrid_ciphertext_new_validates_length() {
        let valid = HybridCiphertext::new(
            [0u8; X25519_PUBLIC_KEY_LEN],
            vec![0u8; ML_KEM_CIPHERTEXT_LEN],
        );
        assert!(valid.is_ok());

        let too_short = HybridCiphertext::new([0u8; X25519_PUBLIC_KEY_LEN], vec![0u8; 10]);
        assert!(matches!(too_short, Err(CryptoError::KeyEncapsulation(_))));
    }

    // -- Story 1.11 H1 fix: Sentinel-pattern zeroize tests --

    /// Sentinel pattern for memory forensics.
    const SENTINEL: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];

    /// Verify `HybridPrivateKey` X25519 component is zeroed after drop.
    ///
    /// We fill the X25519 `SecretBuffer` with a sentinel pattern, capture
    /// the data pointer, drop the key pair, then verify the sentinel is
    /// absent from the freed memory. This is the same approach used in
    /// the `SecretBuffer` zeroize tests.
    ///
    /// **UB caveat:** Reading freed memory is undefined behavior. This is
    /// a best-effort smoke test for debug-mode only.
    #[test]
    fn hybrid_private_key_x25519_sentinel_cleared_after_drop() {
        let sentinel_data: Vec<u8> = SENTINEL
            .iter()
            .copied()
            .cycle()
            .take(X25519_PRIVATE_KEY_LEN)
            .collect();
        let x25519_buf = SecretBuffer::new(&sentinel_data).expect("allocation should succeed");

        let data_ptr: *const u8 = x25519_buf.expose().as_ptr();
        let data_len: usize = x25519_buf.expose().len();

        // Verify sentinel is present before drop.
        assert_eq!(&x25519_buf.expose()[..4], &SENTINEL);

        // Create a minimal HybridPrivateKey with our sentinel-filled buffer.
        // ml_kem can be any valid SecretBuffer — we only test x25519 here.
        let ml_kem_buf = SecretBuffer::new(&[0u8; 32]).expect("allocation should succeed");
        let pk = HybridPrivateKey {
            x25519: x25519_buf,
            ml_kem: ml_kem_buf,
        };
        drop(pk);

        // SAFETY: Reading freed memory — UB, debug-mode best-effort only.
        let sentinel_found = unsafe {
            let slice = std::slice::from_raw_parts(data_ptr, data_len);
            slice.windows(4).any(|w| w == SENTINEL)
        };

        assert!(
            !sentinel_found,
            "Sentinel pattern found in HybridPrivateKey.x25519 after drop — zeroize may have failed"
        );
    }

    /// Verify `HybridPrivateKey` ML-KEM component is zeroed after drop.
    #[test]
    fn hybrid_private_key_ml_kem_sentinel_cleared_after_drop() {
        let sentinel_data: Vec<u8> = SENTINEL.iter().copied().cycle().take(512).collect();
        let ml_kem_buf = SecretBuffer::new(&sentinel_data).expect("allocation should succeed");

        let data_ptr: *const u8 = ml_kem_buf.expose().as_ptr();
        let data_len: usize = ml_kem_buf.expose().len();

        assert_eq!(&ml_kem_buf.expose()[..4], &SENTINEL);

        let x25519_buf =
            SecretBuffer::new(&[0u8; X25519_PRIVATE_KEY_LEN]).expect("allocation should succeed");
        let pk = HybridPrivateKey {
            x25519: x25519_buf,
            ml_kem: ml_kem_buf,
        };
        drop(pk);

        let sentinel_found = unsafe {
            let slice = std::slice::from_raw_parts(data_ptr, data_len);
            slice.windows(4).any(|w| w == SENTINEL)
        };

        assert!(
            !sentinel_found,
            "Sentinel pattern found in HybridPrivateKey.ml_kem after drop — zeroize may have failed"
        );
    }
}
