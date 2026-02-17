//! Hardware security key derivation for vault unlock.
//!
//! Derives a 256-bit wrapping key from a hardware security token using HKDF-SHA256.
//! Like biometric tokens, hardware tokens are already high-entropy (32 bytes from
//! OS CSPRNG), so HKDF is used for instant derivation (~1μs).
//!
//! The hardware token is stored in a platform hardware security module (Secure
//! Enclave on macOS, TPM 2.0 on Windows/Linux), providing defense-in-depth:
//! even if the keychain backup is compromised, the wrapping key cannot be
//! derived without the hardware module.
//!
//! # Key Hierarchy
//!
//! ```text
//! Hardware Token ──► HKDF-SHA256 ──► Hardware Key ──► unwraps ──► Master Key
//! ```
//!
//! # Domain Separation from Biometric
//!
//! Uses different HKDF salt (`verrou-hardware-v1`) than biometric (`verrou-biometric-v1`)
//! so even identical token bytes would produce different wrapping keys.

use rand::rngs::OsRng;
use rand::RngCore;
use ring::hkdf;
use zeroize::Zeroize;

use crate::error::CryptoError;
use crate::memory::{SecretBuffer, SecretBytes};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// HKDF salt for hardware key derivation (domain separation from biometric).
const HKDF_SALT: &[u8] = b"verrou-hardware-v1";

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
struct HardwareKeyType;

impl hkdf::KeyType for HardwareKeyType {
    fn len(&self) -> usize {
        WRAPPING_KEY_LEN
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Derive a 256-bit wrapping key from a hardware security token via HKDF-SHA256.
///
/// The token is typically a random 32-byte secret stored in a hardware security
/// module (Secure Enclave, TPM 2.0) and encrypted with a hardware-bound key.
/// HKDF is used (not Argon2id) because:
/// - Hardware tokens are already high-entropy (OS CSPRNG)
/// - The hardware module rate-limits access at the platform level
/// - Instant derivation (~1μs) avoids blocking the unlock path
///
/// # Arguments
///
/// - `token` — at least 16 bytes of high-entropy material from the hardware module
///
/// # Errors
///
/// Returns [`CryptoError::HardwareKey`] if the token is too short or HKDF fails.
pub fn derive_hardware_wrapping_key(token: &[u8]) -> Result<SecretBuffer, CryptoError> {
    if token.len() < MIN_TOKEN_LEN {
        return Err(CryptoError::HardwareKey(format!(
            "hardware token too short: {} bytes (minimum {MIN_TOKEN_LEN})",
            token.len()
        )));
    }

    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, HKDF_SALT);
    let prk = salt.extract(token);
    let okm = prk
        .expand(&[HKDF_INFO], HardwareKeyType)
        .map_err(|_| CryptoError::HardwareKey("HKDF expand failed".into()))?;

    let mut key_bytes = [0u8; WRAPPING_KEY_LEN];
    okm.fill(&mut key_bytes)
        .map_err(|_| CryptoError::HardwareKey("HKDF fill failed".into()))?;

    let buf = SecretBuffer::new(&key_bytes)?;
    key_bytes.zeroize();
    Ok(buf)
}

/// Generate a random hardware security enrollment token.
///
/// During vault creation or hardware security enrollment, a random 32-byte
/// secret is generated and stored in the platform hardware security module
/// (Secure Enclave / TPM). The wrapping key is then derived from this token
/// via [`derive_hardware_wrapping_key`].
///
/// Returns 32 random bytes as a [`SecretBytes`] (zeroized on drop).
#[must_use]
pub fn generate_hardware_token() -> SecretBytes<32> {
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let bytes = SecretBytes::<32>::new(secret);
    secret.zeroize();
    bytes
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
        let key = derive_hardware_wrapping_key(&token).expect("derivation should succeed");
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn derive_is_deterministic() {
        let token = [0xBB_u8; 32];
        let key1 = derive_hardware_wrapping_key(&token).expect("derivation should succeed");
        let key2 = derive_hardware_wrapping_key(&token).expect("derivation should succeed");
        assert_eq!(key1.expose(), key2.expose());
    }

    #[test]
    fn different_tokens_produce_different_keys() {
        let token_a = [0xAA_u8; 32];
        let token_b = [0xBB_u8; 32];
        let key_a = derive_hardware_wrapping_key(&token_a).expect("derivation should succeed");
        let key_b = derive_hardware_wrapping_key(&token_b).expect("derivation should succeed");
        assert_ne!(key_a.expose(), key_b.expose());
    }

    #[test]
    fn different_salt_from_biometric() {
        // Same token through both derivation paths should produce different keys.
        let token = [0xDD_u8; 32];
        let hw_key = derive_hardware_wrapping_key(&token).expect("hw derivation should succeed");
        let bio_key = crate::biometric::derive_biometric_wrapping_key(&token)
            .expect("bio derivation should succeed");
        assert_ne!(
            hw_key.expose(),
            bio_key.expose(),
            "hardware and biometric keys must differ due to different HKDF salt"
        );
    }

    #[test]
    fn rejects_empty_token() {
        let result = derive_hardware_wrapping_key(&[]);
        assert!(result.is_err());
        assert!(
            matches!(result, Err(CryptoError::HardwareKey(_))),
            "empty token should yield CryptoError::HardwareKey"
        );
    }

    #[test]
    fn rejects_short_token() {
        let result = derive_hardware_wrapping_key(&[0x42; 15]);
        assert!(result.is_err());
        assert!(
            matches!(result, Err(CryptoError::HardwareKey(_))),
            "15-byte token should be rejected (minimum 16)"
        );
    }

    #[test]
    fn accepts_minimum_length_token() {
        let token = [0xCC_u8; 16];
        let key = derive_hardware_wrapping_key(&token).expect("16-byte token should succeed");
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn generate_token_produces_unique_values() {
        let t1 = generate_hardware_token();
        let t2 = generate_hardware_token();
        assert_ne!(t1.expose(), t2.expose());
    }

    #[test]
    fn generate_token_correct_size() {
        let t = generate_hardware_token();
        assert_eq!(t.expose().len(), 32);
    }

    #[test]
    fn token_roundtrip_with_derivation() {
        let token = generate_hardware_token();
        let key1 = derive_hardware_wrapping_key(token.expose())
            .expect("derivation from generated token should succeed");
        let key2 =
            derive_hardware_wrapping_key(token.expose()).expect("second derivation should succeed");
        assert_eq!(key1.expose(), key2.expose());
    }
}
