//! Hybrid signing: Ed25519 + ML-DSA-65.
//!
//! This module provides:
//! - [`generate_signing_keypair`] — generate a hybrid Ed25519 + ML-DSA-65 key pair
//! - [`sign`] — produce both Ed25519 and ML-DSA-65 signatures over a message
//! - [`verify`] — verify that both signatures are valid (fail if either is invalid)
//!
//! # Release Artifact Integrity (NFR32)
//!
//! These hybrid signatures are used to sign release binaries, checksums, and
//! SBOMs. Both classical (Ed25519) and post-quantum (ML-DSA-65) signatures
//! must verify — if either algorithm is compromised, the other independently
//! protects the integrity of signed artifacts.
//!
//! # Domain Separation
//!
//! ML-DSA-65 signs with context `b"VERROU-HYBRID-SIG-v1"` to prevent
//! cross-protocol signature reuse. Ed25519 (via `ring`) uses `PureEd25519`
//! without a context parameter.

use crate::error::CryptoError;
use crate::memory::SecretBuffer;
use rand::rngs::OsRng;
use rand::RngCore;
use ring::signature::{self, Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Ed25519 public key length in bytes (256 bits).
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;

/// Ed25519 seed (private key) length in bytes (256 bits).
pub const ED25519_SEED_LEN: usize = 32;

/// Ed25519 signature length in bytes (512 bits).
pub const ED25519_SIGNATURE_LEN: usize = 64;

/// ML-DSA-65 verification key (public key) length in bytes (FIPS 204).
pub const ML_DSA_65_VERIFICATION_KEY_LEN: usize = 1952;

/// ML-DSA-65 signing key (private key) length in bytes (FIPS 204).
#[cfg(test)]
const ML_DSA_65_SIGNING_KEY_LEN: usize = 4032;

/// ML-DSA-65 signature length in bytes (FIPS 204).
pub const ML_DSA_65_SIGNATURE_LEN: usize = 3309;

/// ML-DSA-65 key generation randomness size (32 bytes).
const ML_DSA_KEYGEN_RAND_LEN: usize = 32;

/// ML-DSA-65 signing randomness size (32 bytes).
const ML_DSA_SIGN_RAND_LEN: usize = 32;

/// ML-DSA context string for domain separation.
const ML_DSA_CONTEXT: &[u8] = b"VERROU-HYBRID-SIG-v1";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Hybrid signing public key: Ed25519 + ML-DSA-65.
///
/// This is the signer's public key used by anyone to verify signatures.
/// Safe to distribute publicly.
///
/// Use [`HybridSigningPublicKey::new`] to construct with length validation.
#[must_use = "public key must be stored or published"]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HybridSigningPublicKey {
    /// Ed25519 public key (32 bytes).
    pub ed25519: [u8; ED25519_PUBLIC_KEY_LEN],
    /// ML-DSA-65 verification key (1952 bytes).
    pub ml_dsa: Vec<u8>,
}

impl HybridSigningPublicKey {
    /// Create a new `HybridSigningPublicKey` with length validation.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Signature`] if the ML-DSA verification key
    /// is not exactly [`ML_DSA_65_VERIFICATION_KEY_LEN`] (1952) bytes.
    pub fn new(
        ed25519: [u8; ED25519_PUBLIC_KEY_LEN],
        ml_dsa: Vec<u8>,
    ) -> Result<Self, CryptoError> {
        if ml_dsa.len() != ML_DSA_65_VERIFICATION_KEY_LEN {
            return Err(CryptoError::Signature(format!(
                "invalid ML-DSA verification key length: {} bytes (expected {ML_DSA_65_VERIFICATION_KEY_LEN})",
                ml_dsa.len()
            )));
        }
        Ok(Self { ed25519, ml_dsa })
    }
}

/// Hybrid signing key pair: Ed25519 seed + ML-DSA-65 signing key + public key.
///
/// Private key components are stored in [`SecretBuffer`] (mlocked, zeroized
/// on drop). This type intentionally does NOT implement `Serialize` to prevent
/// accidental serialization of private key material.
pub struct HybridSigningKeyPair {
    /// Ed25519 seed (32 bytes) in secure memory.
    pub(crate) ed25519_seed: SecretBuffer,
    /// ML-DSA-65 signing key (4032 bytes) in secure memory.
    pub(crate) ml_dsa_signing_key: SecretBuffer,
    /// Public key (safe to share).
    pub public: HybridSigningPublicKey,
}

impl std::fmt::Debug for HybridSigningKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HybridSigningKeyPair(***)")
    }
}

/// Hybrid signature: Ed25519 + ML-DSA-65.
///
/// Produced by [`sign`] and consumed by [`verify`]. Both signature
/// components must verify for the overall verification to succeed.
///
/// Use [`HybridSignature::new`] to construct with length validation.
#[must_use = "signature must be stored or transmitted"]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HybridSignature {
    /// Ed25519 signature (64 bytes).
    pub ed25519: Vec<u8>,
    /// ML-DSA-65 signature (3309 bytes).
    pub ml_dsa: Vec<u8>,
}

impl HybridSignature {
    /// Create a new `HybridSignature` with length validation.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Signature`] if either signature component
    /// has an incorrect length.
    pub fn new(ed25519: Vec<u8>, ml_dsa: Vec<u8>) -> Result<Self, CryptoError> {
        if ed25519.len() != ED25519_SIGNATURE_LEN {
            return Err(CryptoError::Signature(format!(
                "invalid Ed25519 signature length: {} bytes (expected {ED25519_SIGNATURE_LEN})",
                ed25519.len()
            )));
        }
        if ml_dsa.len() != ML_DSA_65_SIGNATURE_LEN {
            return Err(CryptoError::Signature(format!(
                "invalid ML-DSA signature length: {} bytes (expected {ML_DSA_65_SIGNATURE_LEN})",
                ml_dsa.len()
            )));
        }
        Ok(Self { ed25519, ml_dsa })
    }
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

/// Generate a hybrid Ed25519 + ML-DSA-65 signing key pair.
///
/// The Ed25519 key pair is created from a random 32-byte seed via
/// `ring::signature::Ed25519KeyPair`. The ML-DSA-65 key pair is generated
/// via `libcrux_ml_dsa::ml_dsa_65` with 32 bytes of CSPRNG randomness.
///
/// Both private key components are stored in [`SecretBuffer`] (mlocked,
/// zeroized on drop).
///
/// # Errors
///
/// Returns [`CryptoError::Signature`] if key generation fails.
pub fn generate_signing_keypair() -> Result<HybridSigningKeyPair, CryptoError> {
    // --- Ed25519 key pair ---
    let mut ed25519_seed_bytes = [0u8; ED25519_SEED_LEN];
    OsRng.fill_bytes(&mut ed25519_seed_bytes);

    let ed25519_kp = Ed25519KeyPair::from_seed_unchecked(&ed25519_seed_bytes).map_err(|e| {
        ed25519_seed_bytes.zeroize();
        CryptoError::Signature(format!("Ed25519 key generation failed: {e}"))
    })?;

    let mut ed25519_pk = [0u8; ED25519_PUBLIC_KEY_LEN];
    ed25519_pk.copy_from_slice(ed25519_kp.public_key().as_ref());

    let ed25519_seed_buf = SecretBuffer::new(&ed25519_seed_bytes).map_err(|e| {
        ed25519_seed_bytes.zeroize();
        CryptoError::SecureMemory(format!("Ed25519 seed allocation failed: {e}"))
    })?;
    ed25519_seed_bytes.zeroize();

    // --- ML-DSA-65 key pair ---
    let mut ml_dsa_keygen_rand = [0u8; ML_DSA_KEYGEN_RAND_LEN];
    OsRng.fill_bytes(&mut ml_dsa_keygen_rand);

    let ml_dsa_kp = libcrux_ml_dsa::ml_dsa_65::generate_key_pair(ml_dsa_keygen_rand);
    ml_dsa_keygen_rand.zeroize();

    let ml_dsa_vk_bytes = ml_dsa_kp.verification_key.as_ref().to_vec();
    // SAFETY NOTE: `ml_dsa_kp.signing_key` (4032 bytes) is not zeroized after this
    // copy because libcrux types do not implement `Zeroize` or `ZeroizeOnDrop`.
    // The authoritative copy lives in `ml_dsa_sk_buf` (mlocked, zeroized on drop).
    // This is an accepted limitation tracked for future improvement when libcrux
    // adds zeroization support.
    let ml_dsa_sk_buf = SecretBuffer::new(ml_dsa_kp.signing_key.as_slice()).map_err(|e| {
        CryptoError::SecureMemory(format!("ML-DSA signing key allocation failed: {e}"))
    })?;

    let public = HybridSigningPublicKey {
        ed25519: ed25519_pk,
        ml_dsa: ml_dsa_vk_bytes,
    };

    Ok(HybridSigningKeyPair {
        ed25519_seed: ed25519_seed_buf,
        ml_dsa_signing_key: ml_dsa_sk_buf,
        public,
    })
}

// ---------------------------------------------------------------------------
// Sign
// ---------------------------------------------------------------------------

/// Produce a hybrid Ed25519 + ML-DSA-65 signature over a message.
///
/// The Ed25519 key pair is reconstructed from the stored seed. ML-DSA-65
/// signs with fresh 32-byte randomness and the context string
/// `b"VERROU-HYBRID-SIG-v1"` for domain separation.
///
/// # Errors
///
/// Returns [`CryptoError::Signature`] if either signing operation fails.
pub fn sign(
    message: &[u8],
    keypair: &HybridSigningKeyPair,
) -> Result<HybridSignature, CryptoError> {
    // --- Ed25519 ---
    let ed25519_kp = Ed25519KeyPair::from_seed_and_public_key(
        keypair.ed25519_seed.expose(),
        &keypair.public.ed25519,
    )
    .map_err(|e| CryptoError::Signature(format!("Ed25519 key reconstruction failed: {e}")))?;

    let ed25519_sig = ed25519_kp.sign(message);
    let ed25519_sig_bytes = ed25519_sig.as_ref().to_vec();

    // --- ML-DSA-65 ---
    let mut ml_dsa_sign_rand = [0u8; ML_DSA_SIGN_RAND_LEN];
    OsRng.fill_bytes(&mut ml_dsa_sign_rand);

    let ml_dsa_sk = libcrux_ml_dsa::ml_dsa_65::MLDSA65SigningKey::new(
        keypair
            .ml_dsa_signing_key
            .expose()
            .try_into()
            .map_err(|_| {
                ml_dsa_sign_rand.zeroize();
                CryptoError::Signature("ML-DSA signing key has invalid length".to_string())
            })?,
    );

    let ml_dsa_result =
        libcrux_ml_dsa::ml_dsa_65::sign(&ml_dsa_sk, message, ML_DSA_CONTEXT, ml_dsa_sign_rand);
    ml_dsa_sign_rand.zeroize();
    let ml_dsa_sig = ml_dsa_result
        .map_err(|e| CryptoError::Signature(format!("ML-DSA signing failed: {e:?}")))?;

    let ml_dsa_sig_bytes = ml_dsa_sig.as_ref().to_vec();

    Ok(HybridSignature {
        ed25519: ed25519_sig_bytes,
        ml_dsa: ml_dsa_sig_bytes,
    })
}

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

/// Verify a hybrid Ed25519 + ML-DSA-65 signature.
///
/// Both Ed25519 and ML-DSA-65 signatures must be valid for verification
/// to succeed. Ed25519 is checked first (faster), then ML-DSA-65.
///
/// # Errors
///
/// Returns [`CryptoError::Signature`] if either signature is invalid.
pub fn verify(
    message: &[u8],
    sig: &HybridSignature,
    public_key: &HybridSigningPublicKey,
) -> Result<(), CryptoError> {
    // --- Ed25519 verification (fast path first) ---
    let ed25519_pk = signature::UnparsedPublicKey::new(&signature::ED25519, &public_key.ed25519);
    ed25519_pk
        .verify(message, &sig.ed25519)
        .map_err(|_| CryptoError::Signature("Ed25519 verification failed".to_string()))?;

    // --- ML-DSA-65 verification ---
    let ml_dsa_vk_arr: &[u8; ML_DSA_65_VERIFICATION_KEY_LEN] =
        public_key.ml_dsa.as_slice().try_into().map_err(|_| {
            CryptoError::Signature(format!(
                "invalid ML-DSA verification key length: {} bytes (expected {ML_DSA_65_VERIFICATION_KEY_LEN})",
                public_key.ml_dsa.len()
            ))
        })?;

    let ml_dsa_vk = libcrux_ml_dsa::ml_dsa_65::MLDSA65VerificationKey::new(*ml_dsa_vk_arr);

    let ml_dsa_sig_arr: &[u8; ML_DSA_65_SIGNATURE_LEN] =
        sig.ml_dsa.as_slice().try_into().map_err(|_| {
            CryptoError::Signature(format!(
                "invalid ML-DSA signature length: {} bytes (expected {ML_DSA_65_SIGNATURE_LEN})",
                sig.ml_dsa.len()
            ))
        })?;

    let ml_dsa_sig = libcrux_ml_dsa::ml_dsa_65::MLDSA65Signature::new(*ml_dsa_sig_arr);

    libcrux_ml_dsa::ml_dsa_65::verify(&ml_dsa_vk, message, ML_DSA_CONTEXT, &ml_dsa_sig)
        .map_err(|_| CryptoError::Signature("ML-DSA verification failed".to_string()))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_signing_keypair_produces_valid_lengths() {
        let kp = generate_signing_keypair().expect("keygen should succeed");

        // Ed25519 seed = 32 bytes
        assert_eq!(kp.ed25519_seed.expose().len(), ED25519_SEED_LEN);
        // Ed25519 public key = 32 bytes
        assert_eq!(kp.public.ed25519.len(), ED25519_PUBLIC_KEY_LEN);
        // ML-DSA-65 signing key = 4032 bytes
        assert_eq!(
            kp.ml_dsa_signing_key.expose().len(),
            ML_DSA_65_SIGNING_KEY_LEN
        );
        // ML-DSA-65 verification key = 1952 bytes
        assert_eq!(kp.public.ml_dsa.len(), ML_DSA_65_VERIFICATION_KEY_LEN);
    }

    #[test]
    fn sign_verify_roundtrip() {
        let kp = generate_signing_keypair().expect("keygen should succeed");
        let message = b"Release artifact v1.0.0 checksum";

        let sig = sign(message, &kp).expect("signing should succeed");
        verify(message, &sig, &kp.public).expect("verification should succeed");
    }

    #[test]
    fn verify_with_wrong_public_key_fails() {
        let kp1 = generate_signing_keypair().expect("keygen should succeed");
        let kp2 = generate_signing_keypair().expect("keygen should succeed");
        let message = b"signed with kp1";

        let sig = sign(message, &kp1).expect("signing should succeed");
        let result = verify(message, &sig, &kp2.public);

        assert!(result.is_err());
        assert!(matches!(result, Err(CryptoError::Signature(_))));
    }

    #[test]
    fn verify_with_tampered_ed25519_signature_fails() {
        let kp = generate_signing_keypair().expect("keygen should succeed");
        let message = b"original message";

        let mut sig = sign(message, &kp).expect("signing should succeed");
        // Flip a byte in the Ed25519 signature
        sig.ed25519[0] ^= 0xFF;

        let result = verify(message, &sig, &kp.public);
        assert!(result.is_err());
        assert!(matches!(result, Err(CryptoError::Signature(_))));
    }

    #[test]
    fn verify_with_tampered_ml_dsa_signature_fails() {
        let kp = generate_signing_keypair().expect("keygen should succeed");
        let message = b"original message";

        let mut sig = sign(message, &kp).expect("signing should succeed");
        // Flip a byte in the ML-DSA signature
        sig.ml_dsa[0] ^= 0xFF;

        let result = verify(message, &sig, &kp.public);
        assert!(result.is_err());
        assert!(matches!(result, Err(CryptoError::Signature(_))));
    }

    #[test]
    fn verify_with_tampered_message_fails() {
        let kp = generate_signing_keypair().expect("keygen should succeed");
        let message = b"original message";

        let sig = sign(message, &kp).expect("signing should succeed");
        let result = verify(b"tampered message", &sig, &kp.public);

        assert!(result.is_err());
        assert!(matches!(result, Err(CryptoError::Signature(_))));
    }

    #[test]
    fn two_signatures_on_same_message_differ() {
        let kp = generate_signing_keypair().expect("keygen should succeed");
        let message = b"same message";

        let sig1 = sign(message, &kp).expect("signing should succeed");
        let sig2 = sign(message, &kp).expect("signing should succeed");

        // Ed25519 is deterministic — same sig for same message+key
        assert_eq!(sig1.ed25519, sig2.ed25519);
        // ML-DSA uses fresh randomness — signatures should differ
        assert_ne!(sig1.ml_dsa, sig2.ml_dsa);

        // Both must still verify
        verify(message, &sig1, &kp.public).expect("sig1 should verify");
        verify(message, &sig2, &kp.public).expect("sig2 should verify");
    }

    #[test]
    fn signing_public_key_serde_roundtrip() {
        let kp = generate_signing_keypair().expect("keygen should succeed");

        let json = serde_json::to_string(&kp.public).expect("serialize should succeed");
        let deserialized: HybridSigningPublicKey =
            serde_json::from_str(&json).expect("deserialize should succeed");

        assert_eq!(deserialized.ed25519, kp.public.ed25519);
        assert_eq!(deserialized.ml_dsa, kp.public.ml_dsa);
    }

    #[test]
    fn hybrid_signature_serde_roundtrip() {
        let kp = generate_signing_keypair().expect("keygen should succeed");
        let message = b"serde roundtrip test";

        let sig = sign(message, &kp).expect("signing should succeed");
        let json = serde_json::to_string(&sig).expect("serialize should succeed");
        let deserialized: HybridSignature =
            serde_json::from_str(&json).expect("deserialize should succeed");

        assert_eq!(deserialized.ed25519, sig.ed25519);
        assert_eq!(deserialized.ml_dsa, sig.ml_dsa);

        // Deserialized signature should still verify
        verify(message, &deserialized, &kp.public).expect("deserialized sig should verify");
    }

    #[test]
    fn private_key_debug_is_masked() {
        let kp = generate_signing_keypair().expect("keygen should succeed");
        let debug_str = format!("{kp:?}");

        assert_eq!(debug_str, "HybridSigningKeyPair(***)");
        assert!(!debug_str.contains("ed25519_seed"));
        assert!(!debug_str.contains("ml_dsa_signing_key"));
    }

    #[test]
    fn hybrid_signing_public_key_new_validates_length() {
        let ed25519_pk = [0u8; ED25519_PUBLIC_KEY_LEN];

        // Valid length should succeed
        let valid =
            HybridSigningPublicKey::new(ed25519_pk, vec![0u8; ML_DSA_65_VERIFICATION_KEY_LEN]);
        assert!(valid.is_ok());

        // Wrong length should fail
        let too_short = HybridSigningPublicKey::new(ed25519_pk, vec![0u8; 100]);
        assert!(too_short.is_err());
        assert!(matches!(too_short, Err(CryptoError::Signature(_))));

        let too_long =
            HybridSigningPublicKey::new(ed25519_pk, vec![0u8; ML_DSA_65_VERIFICATION_KEY_LEN + 1]);
        assert!(too_long.is_err());
        assert!(matches!(too_long, Err(CryptoError::Signature(_))));
    }

    #[test]
    fn hybrid_signature_new_validates_lengths() {
        // Valid lengths should succeed
        let valid = HybridSignature::new(
            vec![0u8; ED25519_SIGNATURE_LEN],
            vec![0u8; ML_DSA_65_SIGNATURE_LEN],
        );
        assert!(valid.is_ok());

        // Wrong Ed25519 length should fail
        let bad_ed25519 = HybridSignature::new(vec![0u8; 32], vec![0u8; ML_DSA_65_SIGNATURE_LEN]);
        assert!(bad_ed25519.is_err());
        assert!(matches!(bad_ed25519, Err(CryptoError::Signature(_))));

        // Wrong ML-DSA length should fail
        let bad_ml_dsa = HybridSignature::new(vec![0u8; ED25519_SIGNATURE_LEN], vec![0u8; 100]);
        assert!(bad_ml_dsa.is_err());
        assert!(matches!(bad_ml_dsa, Err(CryptoError::Signature(_))));
    }

    // -- Story 1.11 H1 fix: Sentinel-pattern zeroize tests --

    /// Sentinel pattern for memory forensics.
    const SENTINEL: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];

    /// Verify `HybridSigningKeyPair` Ed25519 seed is zeroed after drop.
    ///
    /// Fills the `ed25519_seed` `SecretBuffer` with a sentinel pattern,
    /// captures the data pointer, drops the key pair, then verifies the
    /// sentinel is absent from freed memory.
    ///
    /// **UB caveat:** Reading freed memory is undefined behavior. This is
    /// a best-effort smoke test for debug-mode only.
    #[test]
    fn hybrid_signing_keypair_ed25519_sentinel_cleared_after_drop() {
        let sentinel_data: Vec<u8> = SENTINEL
            .iter()
            .copied()
            .cycle()
            .take(ED25519_SEED_LEN)
            .collect();
        let ed25519_buf = SecretBuffer::new(&sentinel_data).expect("allocation should succeed");

        let data_ptr: *const u8 = ed25519_buf.expose().as_ptr();
        let data_len: usize = ed25519_buf.expose().len();

        assert_eq!(&ed25519_buf.expose()[..4], &SENTINEL);

        let ml_dsa_buf = SecretBuffer::new(&[0u8; 32]).expect("allocation should succeed");
        let kp = HybridSigningKeyPair {
            ed25519_seed: ed25519_buf,
            ml_dsa_signing_key: ml_dsa_buf,
            public: HybridSigningPublicKey {
                ed25519: [0u8; ED25519_PUBLIC_KEY_LEN],
                ml_dsa: vec![0u8; ML_DSA_65_VERIFICATION_KEY_LEN],
            },
        };
        drop(kp);

        let sentinel_found = unsafe {
            let slice = std::slice::from_raw_parts(data_ptr, data_len);
            slice.windows(4).any(|w| w == SENTINEL)
        };

        assert!(
            !sentinel_found,
            "Sentinel pattern found in HybridSigningKeyPair.ed25519_seed after drop — zeroize may have failed"
        );
    }

    /// Verify `HybridSigningKeyPair` ML-DSA signing key is zeroed after drop.
    #[test]
    fn hybrid_signing_keypair_ml_dsa_sentinel_cleared_after_drop() {
        let sentinel_data: Vec<u8> = SENTINEL.iter().copied().cycle().take(512).collect();
        let ml_dsa_buf = SecretBuffer::new(&sentinel_data).expect("allocation should succeed");

        let data_ptr: *const u8 = ml_dsa_buf.expose().as_ptr();
        let data_len: usize = ml_dsa_buf.expose().len();

        assert_eq!(&ml_dsa_buf.expose()[..4], &SENTINEL);

        let ed25519_buf =
            SecretBuffer::new(&[0u8; ED25519_SEED_LEN]).expect("allocation should succeed");
        let kp = HybridSigningKeyPair {
            ed25519_seed: ed25519_buf,
            ml_dsa_signing_key: ml_dsa_buf,
            public: HybridSigningPublicKey {
                ed25519: [0u8; ED25519_PUBLIC_KEY_LEN],
                ml_dsa: vec![0u8; ML_DSA_65_VERIFICATION_KEY_LEN],
            },
        };
        drop(kp);

        let sentinel_found = unsafe {
            let slice = std::slice::from_raw_parts(data_ptr, data_len);
            slice.windows(4).any(|w| w == SENTINEL)
        };

        assert!(
            !sentinel_found,
            "Sentinel pattern found in HybridSigningKeyPair.ml_dsa_signing_key after drop — zeroize may have failed"
        );
    }
}
