//! AES-256-GCM authenticated encryption.
//!
//! This module provides:
//! - [`encrypt`] — encrypt plaintext with a random nonce, returning [`SealedData`]
//! - [`decrypt`] — decrypt and authenticate [`SealedData`], returning [`SecretBuffer`]
//! - [`SealedData`] — nonce + ciphertext + tag container (serializable)
//!
//! # Layer 2 Encryption
//!
//! This is Layer 2 of the 3-layer VERROU encryption model:
//! - Layer 1: `SQLCipher` (entire DB file)
//! - **Layer 2: AES-256-GCM (per-field, this module)**
//! - Layer 3: PQ hybrid KEM (key wrapping for export)

use crate::error::CryptoError;
use crate::memory::SecretBuffer;
use rand::rngs::OsRng;
use rand::RngCore;
use ring::aead;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// AES-256-GCM nonce length in bytes (96 bits).
pub const NONCE_LEN: usize = 12;

/// AES-256-GCM authentication tag length in bytes (128 bits).
pub const TAG_LEN: usize = 16;

/// AES-256-GCM key length in bytes (256 bits).
pub const KEY_LEN: usize = 32;

/// Minimum valid serialized length: nonce + empty ciphertext + tag.
const MIN_SEALED_LEN: usize = NONCE_LEN + TAG_LEN;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Authenticated ciphertext container — nonce + ciphertext + tag.
///
/// Wire format: `nonce (12 bytes) || ciphertext (variable) || tag (16 bytes)`.
///
/// The nonce is randomly generated per encryption call and must travel with
/// the ciphertext for decryption. The tag provides authentication — any
/// modification to the nonce, ciphertext, or tag will cause decryption to fail.
#[must_use = "encrypted data must be stored or transmitted"]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealedData {
    /// 96-bit random nonce, unique per encryption.
    pub nonce: [u8; NONCE_LEN],
    /// Encrypted data (same length as original plaintext).
    pub ciphertext: Vec<u8>,
    /// 128-bit authentication tag.
    pub tag: [u8; TAG_LEN],
}

impl SealedData {
    /// Serialize to wire format: `nonce || ciphertext || tag`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let capacity = NONCE_LEN
            .saturating_add(self.ciphertext.len())
            .saturating_add(TAG_LEN);
        let mut out = Vec::with_capacity(capacity);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out.extend_from_slice(&self.tag);
        out
    }

    /// Deserialize from wire format: `nonce || ciphertext || tag`.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::Encryption` if the input is shorter than 28 bytes
    /// (12-byte nonce + 0-byte ciphertext + 16-byte tag).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < MIN_SEALED_LEN {
            return Err(CryptoError::Encryption(format!(
                "sealed data too short: {} bytes (minimum {MIN_SEALED_LEN})",
                bytes.len()
            )));
        }

        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[..NONCE_LEN]);

        // Defensive: checked_sub cannot fail here because the length guard above
        // guarantees bytes.len() >= NONCE_LEN + TAG_LEN, but we keep it to satisfy
        // the workspace `arithmetic_side_effects = "deny"` lint.
        let ct_len = bytes
            .len()
            .checked_sub(NONCE_LEN.saturating_add(TAG_LEN))
            .ok_or_else(|| CryptoError::Encryption("sealed data length underflow".into()))?;

        let ct_start = NONCE_LEN;
        let ct_end = ct_start.saturating_add(ct_len);
        let ciphertext = bytes[ct_start..ct_end].to_vec();

        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&bytes[ct_end..]);

        Ok(Self {
            nonce,
            ciphertext,
            tag,
        })
    }
}

// ---------------------------------------------------------------------------
// Core encryption
// ---------------------------------------------------------------------------

/// Encrypt plaintext using AES-256-GCM with a random 96-bit nonce.
///
/// Returns a [`SealedData`] containing the nonce, ciphertext, and authentication
/// tag. The nonce is generated from `OsRng` (CSPRNG) and is unique per call.
///
/// # Arguments
///
/// - `plaintext` — data to encrypt (may be empty)
/// - `key` — exactly 32 bytes (256-bit AES key)
/// - `aad` — additional authenticated data (authenticated but not encrypted; may be empty)
///
/// # Errors
///
/// Returns `CryptoError::Encryption` if:
/// - The key is not exactly 32 bytes
/// - The underlying encryption operation fails
pub fn encrypt(plaintext: &[u8], key: &[u8], aad: &[u8]) -> Result<SealedData, CryptoError> {
    if key.len() != KEY_LEN {
        return Err(CryptoError::Encryption(format!(
            "invalid key length: {} bytes (expected {KEY_LEN})",
            key.len()
        )));
    }

    let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, key)
        .map_err(|_| CryptoError::Encryption("failed to create AES-256-GCM key".into()))?;
    let less_safe_key = aead::LessSafeKey::new(unbound);

    // Generate random 96-bit nonce.
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

    // Encrypt in place — plaintext buffer becomes ciphertext.
    let mut in_out = plaintext.to_vec();
    let Ok(tag) =
        less_safe_key.seal_in_place_separate_tag(nonce, aead::Aad::from(aad), &mut in_out)
    else {
        in_out.zeroize();
        return Err(CryptoError::Encryption(
            "AES-256-GCM encryption failed".into(),
        ));
    };

    let mut tag_bytes = [0u8; TAG_LEN];
    tag_bytes.copy_from_slice(tag.as_ref());

    Ok(SealedData {
        nonce: nonce_bytes,
        ciphertext: in_out,
        tag: tag_bytes,
    })
}

/// Decrypt AES-256-GCM authenticated ciphertext.
///
/// Returns the plaintext as a [`SecretBuffer`] (zeroized on drop). The
/// intermediate decryption buffer is zeroized after copying into the
/// `SecretBuffer`.
///
/// # Arguments
///
/// - `sealed` — the [`SealedData`] to decrypt
/// - `key` — exactly 32 bytes (256-bit AES key, must match encryption key)
/// - `aad` — additional authenticated data (must match what was used during encryption)
///
/// # Errors
///
/// Returns `CryptoError::Encryption` if the key is not exactly 32 bytes.
/// Returns `CryptoError::Decryption` if authentication fails (tampered data,
/// wrong key, or wrong AAD).
pub fn decrypt(sealed: &SealedData, key: &[u8], aad: &[u8]) -> Result<SecretBuffer, CryptoError> {
    if key.len() != KEY_LEN {
        return Err(CryptoError::Encryption(format!(
            "invalid key length: {} bytes (expected {KEY_LEN})",
            key.len()
        )));
    }

    let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, key)
        .map_err(|_| CryptoError::Encryption("failed to create AES-256-GCM key".into()))?;
    let less_safe_key = aead::LessSafeKey::new(unbound);

    let nonce = aead::Nonce::assume_unique_for_key(sealed.nonce);

    // Build ciphertext || tag buffer for open_in_place.
    let mut ct_tag = Vec::with_capacity(sealed.ciphertext.len().saturating_add(TAG_LEN));
    ct_tag.extend_from_slice(&sealed.ciphertext);
    ct_tag.extend_from_slice(&sealed.tag);

    let plaintext_slice = less_safe_key
        .open_in_place(nonce, aead::Aad::from(aad), &mut ct_tag)
        .map_err(|_| CryptoError::Decryption)?;

    let result = SecretBuffer::new(plaintext_slice)
        .map_err(|e| CryptoError::SecureMemory(format!("secure buffer allocation failed: {e}")))?;
    ct_tag.zeroize();
    Ok(result)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed test key — 32 bytes of 0xAA.
    const TEST_KEY: [u8; KEY_LEN] = [0xAA; KEY_LEN];

    /// Different key for wrong-key tests.
    const WRONG_KEY: [u8; KEY_LEN] = [0xBB; KEY_LEN];

    #[test]
    fn encrypt_produces_correct_lengths() {
        let plaintext = b"hello, VERROU!";
        let sealed = encrypt(plaintext, &TEST_KEY, &[]).expect("encrypt should succeed");
        assert_eq!(sealed.nonce.len(), NONCE_LEN);
        assert_eq!(sealed.tag.len(), TAG_LEN);
        assert_eq!(sealed.ciphertext.len(), plaintext.len());
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let plaintext = b"secret vault data";
        let sealed = encrypt(plaintext, &TEST_KEY, &[]).expect("encrypt should succeed");
        let decrypted = decrypt(&sealed, &TEST_KEY, &[]).expect("decrypt should succeed");
        assert_eq!(decrypted.expose(), plaintext);
    }

    #[test]
    fn decrypt_fails_on_tampered_ciphertext() {
        let mut tampered = encrypt(b"test data", &TEST_KEY, &[]).expect("encrypt should succeed");
        if let Some(byte) = tampered.ciphertext.first_mut() {
            *byte ^= 0xFF;
        }
        let result = decrypt(&tampered, &TEST_KEY, &[]);
        assert!(
            matches!(result, Err(CryptoError::Decryption)),
            "tampered ciphertext should yield CryptoError::Decryption"
        );
    }

    #[test]
    fn decrypt_fails_on_tampered_tag() {
        let mut tampered = encrypt(b"test data", &TEST_KEY, &[]).expect("encrypt should succeed");
        tampered.tag[0] ^= 0xFF;
        let result = decrypt(&tampered, &TEST_KEY, &[]);
        assert!(
            matches!(result, Err(CryptoError::Decryption)),
            "tampered tag should yield CryptoError::Decryption"
        );
    }

    #[test]
    fn decrypt_fails_with_wrong_key() {
        let sealed = encrypt(b"test data", &TEST_KEY, &[]).expect("encrypt should succeed");
        let result = decrypt(&sealed, &WRONG_KEY, &[]);
        assert!(
            matches!(result, Err(CryptoError::Decryption)),
            "wrong key should yield CryptoError::Decryption"
        );
    }

    #[test]
    fn decrypt_fails_with_modified_nonce() {
        let mut tampered = encrypt(b"test data", &TEST_KEY, &[]).expect("encrypt should succeed");
        tampered.nonce[0] ^= 0xFF;
        let result = decrypt(&tampered, &TEST_KEY, &[]);
        assert!(
            matches!(result, Err(CryptoError::Decryption)),
            "modified nonce should yield CryptoError::Decryption"
        );
    }

    #[test]
    fn encrypt_rejects_wrong_key_length_short() {
        let result = encrypt(b"test", &[0u8; 31], &[]);
        assert!(result.is_err());
        let err_msg = format!("{}", result.expect_err("should fail"));
        assert!(err_msg.contains("invalid key length"));
    }

    #[test]
    fn encrypt_rejects_wrong_key_length_long() {
        let result = encrypt(b"test", &[0u8; 33], &[]);
        let err_msg = format!("{}", result.expect_err("should fail"));
        assert!(err_msg.contains("invalid key length"));
    }

    #[test]
    fn encrypt_empty_plaintext_succeeds() {
        let sealed = encrypt(&[], &TEST_KEY, &[]).expect("encrypt empty should succeed");
        assert!(sealed.ciphertext.is_empty());
        let decrypted = decrypt(&sealed, &TEST_KEY, &[]).expect("decrypt empty should succeed");
        assert!(decrypted.expose().is_empty());
    }

    #[test]
    fn two_encrypts_produce_different_nonces() {
        let sealed_a = encrypt(b"same data", &TEST_KEY, &[]).expect("encrypt should succeed");
        let sealed_b = encrypt(b"same data", &TEST_KEY, &[]).expect("encrypt should succeed");
        assert_ne!(sealed_a.nonce, sealed_b.nonce, "nonces should differ");
    }

    #[test]
    fn sealed_data_serde_roundtrip() {
        let sealed = encrypt(b"serde test", &TEST_KEY, &[]).expect("encrypt should succeed");
        let json = serde_json::to_string(&sealed).expect("serialize should succeed");
        let deserialized: SealedData =
            serde_json::from_str(&json).expect("deserialize should succeed");
        assert_eq!(sealed.nonce, deserialized.nonce);
        assert_eq!(sealed.ciphertext, deserialized.ciphertext);
        assert_eq!(sealed.tag, deserialized.tag);
    }

    #[test]
    fn sealed_data_to_from_bytes_roundtrip() {
        let sealed = encrypt(b"bytes test", &TEST_KEY, &[]).expect("encrypt should succeed");
        let bytes = sealed.to_bytes();
        let restored = SealedData::from_bytes(&bytes).expect("from_bytes should succeed");
        assert_eq!(sealed.nonce, restored.nonce);
        assert_eq!(sealed.ciphertext, restored.ciphertext);
        assert_eq!(sealed.tag, restored.tag);
    }

    #[test]
    fn sealed_data_from_bytes_rejects_short_input() {
        let result = SealedData::from_bytes(&[0u8; 27]);
        assert!(result.is_err());
    }

    #[test]
    fn aad_mismatch_causes_decryption_failure() {
        let sealed =
            encrypt(b"aad test", &TEST_KEY, b"correct aad").expect("encrypt should succeed");
        let result = decrypt(&sealed, &TEST_KEY, b"wrong aad");
        assert!(
            matches!(result, Err(CryptoError::Decryption)),
            "AAD mismatch should yield CryptoError::Decryption"
        );
    }

    #[test]
    fn encrypt_decrypt_with_aad_roundtrip() {
        let aad = b"entry-id:12345";
        let plaintext = b"sensitive field value";
        let sealed = encrypt(plaintext, &TEST_KEY, aad).expect("encrypt should succeed");
        let decrypted = decrypt(&sealed, &TEST_KEY, aad).expect("decrypt should succeed");
        assert_eq!(decrypted.expose(), plaintext);
    }

    #[test]
    fn decrypt_output_is_secret_buffer() {
        let sealed = encrypt(b"secret", &TEST_KEY, &[]).expect("encrypt should succeed");
        let decrypted = decrypt(&sealed, &TEST_KEY, &[]).expect("decrypt should succeed");
        // Debug output should be masked.
        let debug = format!("{decrypted:?}");
        assert_eq!(debug, "SecretBuffer(***)");
    }
}
