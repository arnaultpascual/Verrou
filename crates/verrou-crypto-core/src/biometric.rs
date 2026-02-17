//! Biometric key derivation for vault unlock.
//!
//! Derives a 256-bit wrapping key from a biometric token using HKDF-SHA256.
//! Unlike passwords (Argon2id), biometric tokens are already high-entropy
//! (32 bytes from OS CSPRNG), so HKDF is used for instant derivation (~1μs).
//!
//! # Key Hierarchy
//!
//! ```text
//! Biometric Token ──► HKDF-SHA256 ──► Biometric Key ──► unwraps ──► Master Key
//! ```

use rand::rngs::OsRng;
use rand::RngCore;
use ring::hkdf;
use zeroize::Zeroize;

use crate::error::CryptoError;
use crate::memory::{SecretBuffer, SecretBytes};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// HKDF salt for biometric key derivation (domain separation).
const HKDF_SALT: &[u8] = b"verrou-biometric-v1";

/// HKDF info string for slot wrapping key derivation.
const HKDF_INFO: &[u8] = b"slot-wrapping-key";

/// Minimum token length in bytes.
const MIN_TOKEN_LEN: usize = 16;

/// Expected wrapping key length (256 bits).
const WRAPPING_KEY_LEN: usize = 32;

// ---------------------------------------------------------------------------
// HKDF key type
// ---------------------------------------------------------------------------

/// Marker type for `ring::hkdf::Prk::expand` — requests 32-byte output.
struct BiometricKeyType;

impl hkdf::KeyType for BiometricKeyType {
    fn len(&self) -> usize {
        WRAPPING_KEY_LEN
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Derive a 256-bit wrapping key from a biometric token via HKDF-SHA256.
///
/// The token is typically a random 32-byte secret stored in the OS keychain
/// with biometric access control. HKDF is used (not Argon2id) because:
/// - Biometric tokens are already high-entropy (OS CSPRNG)
/// - The OS rate-limits biometric attempts at the hardware level
/// - Instant derivation (~1μs) makes biometric unlock feel responsive
///
/// # Arguments
///
/// - `token` — at least 16 bytes of high-entropy material from the OS keychain
///
/// # Errors
///
/// Returns [`CryptoError::Biometric`] if the token is too short or HKDF fails.
pub fn derive_biometric_wrapping_key(token: &[u8]) -> Result<SecretBuffer, CryptoError> {
    if token.len() < MIN_TOKEN_LEN {
        return Err(CryptoError::Biometric(format!(
            "biometric token too short: {} bytes (minimum {MIN_TOKEN_LEN})",
            token.len()
        )));
    }

    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, HKDF_SALT);
    let prk = salt.extract(token);
    let okm = prk
        .expand(&[HKDF_INFO], BiometricKeyType)
        .map_err(|_| CryptoError::Biometric("HKDF expand failed".into()))?;

    let mut key_bytes = [0u8; WRAPPING_KEY_LEN];
    okm.fill(&mut key_bytes)
        .map_err(|_| CryptoError::Biometric("HKDF fill failed".into()))?;

    let buf = SecretBuffer::new(&key_bytes)?;
    key_bytes.zeroize();
    Ok(buf)
}

/// Generate a random biometric enrollment token.
///
/// During enrollment, a random 32-byte secret is generated and stored in
/// the OS keychain with biometric access control. The wrapping key is then
/// derived from this token via [`derive_biometric_wrapping_key`].
///
/// Returns `(secret_token, token_id)` where:
/// - `secret_token` — 32 random bytes to store in OS keychain (zeroized on drop)
/// - `token_id` — 16-byte identifier for the keychain entry (not secret)
///
/// # Errors
///
/// Returns [`CryptoError::Biometric`] if the CSPRNG fails.
pub fn generate_biometric_enrollment_token() -> Result<(SecretBytes<32>, Vec<u8>), CryptoError> {
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);

    let mut id = [0u8; 16];
    OsRng.fill_bytes(&mut id);

    let secret_bytes = SecretBytes::<32>::new(secret);
    secret.zeroize();

    Ok((secret_bytes, id.to_vec()))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_produces_32_byte_key() {
        let token = [0xAA_u8; 32];
        let key = derive_biometric_wrapping_key(&token).expect("derivation should succeed");
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn derive_is_deterministic() {
        let token = [0xBB_u8; 32];
        let key1 = derive_biometric_wrapping_key(&token).expect("derivation should succeed");
        let key2 = derive_biometric_wrapping_key(&token).expect("derivation should succeed");
        assert_eq!(key1.expose(), key2.expose());
    }

    #[test]
    fn different_tokens_produce_different_keys() {
        let token_a = [0xAA_u8; 32];
        let token_b = [0xBB_u8; 32];
        let key_a = derive_biometric_wrapping_key(&token_a).expect("derivation should succeed");
        let key_b = derive_biometric_wrapping_key(&token_b).expect("derivation should succeed");
        assert_ne!(key_a.expose(), key_b.expose());
    }

    #[test]
    fn rejects_empty_token() {
        let result = derive_biometric_wrapping_key(&[]);
        assert!(result.is_err());
        assert!(
            matches!(result, Err(CryptoError::Biometric(_))),
            "empty token should yield CryptoError::Biometric"
        );
    }

    #[test]
    fn rejects_short_token() {
        let result = derive_biometric_wrapping_key(&[0x42; 15]);
        assert!(result.is_err());
        assert!(
            matches!(result, Err(CryptoError::Biometric(_))),
            "15-byte token should be rejected (minimum 16)"
        );
    }

    #[test]
    fn accepts_minimum_length_token() {
        let token = [0xCC_u8; 16];
        let key = derive_biometric_wrapping_key(&token).expect("16-byte token should succeed");
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn generate_enrollment_token_produces_unique_secrets() {
        let (secret1, id1) =
            generate_biometric_enrollment_token().expect("generation should succeed");
        let (secret2, id2) =
            generate_biometric_enrollment_token().expect("generation should succeed");
        assert_ne!(secret1.expose(), secret2.expose());
        assert_ne!(id1, id2);
    }

    #[test]
    fn generate_enrollment_token_correct_sizes() {
        let (secret, id) =
            generate_biometric_enrollment_token().expect("generation should succeed");
        assert_eq!(secret.expose().len(), 32);
        assert_eq!(id.len(), 16);
    }

    #[test]
    fn enrollment_token_roundtrip_with_derivation() {
        let (secret, _id) =
            generate_biometric_enrollment_token().expect("generation should succeed");
        let key = derive_biometric_wrapping_key(secret.expose())
            .expect("derivation from enrollment token should succeed");
        assert_eq!(key.len(), 32);

        // Derive again with same token — should be deterministic.
        let key2 = derive_biometric_wrapping_key(secret.expose())
            .expect("second derivation should succeed");
        assert_eq!(key.expose(), key2.expose());
    }
}
