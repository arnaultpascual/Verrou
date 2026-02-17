//! Key slot system for multi-method vault unlock.
//!
//! This module provides:
//! - [`create_slot`] — wrap a master key with a wrapping key, producing a [`KeySlot`]
//! - [`unwrap_slot`] — unwrap a [`KeySlot`] to recover the master key as [`SecretBuffer`]
//!
//! # Slot-Based Key Hierarchy
//!
//! Each slot independently wraps the same random 256-bit master key.
//! Adding or removing a slot never touches other slots or re-encrypts data.
//!
//! ```text
//! Password Key ──► wraps ──► Random Master Key
//! Biometric Key ──► wraps ──► Random Master Key (same)
//! Recovery Key ──► wraps ──► Random Master Key (same)
//! ```
//!
//! # Domain Separation
//!
//! Each [`SlotType`] uses a distinct AAD tag when wrapping with AES-256-GCM,
//! preventing cross-type slot confusion (e.g., a password slot cannot be
//! unwrapped as a biometric slot).

use crate::error::CryptoError;
use crate::memory::SecretBuffer;
use crate::symmetric::{self, SealedData};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Master key length in bytes (256 bits).
pub const MASTER_KEY_LEN: usize = 32;

/// Wrapping key length in bytes (256 bits).
pub const WRAPPING_KEY_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Unlock method type for a key slot.
///
/// Each variant uses a distinct AAD tag for AES-256-GCM domain separation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlotType {
    /// Master password derived key (via Argon2id).
    Password,
    /// Biometric token derived key (via HKDF).
    Biometric,
    /// Recovery code derived key (via Argon2id).
    Recovery,
    /// Hardware security token derived key (via HKDF, Secure Enclave/TPM protected).
    HardwareSecurity,
}

impl SlotType {
    /// Return the AAD tag for this slot type.
    ///
    /// Used as additional authenticated data in AES-256-GCM to ensure
    /// a slot created for one type cannot be unwrapped as another.
    #[must_use]
    pub const fn aad_tag(&self) -> &'static [u8] {
        match self {
            Self::Password => b"verrou-slot-password",
            Self::Biometric => b"verrou-slot-biometric",
            Self::Recovery => b"verrou-slot-recovery",
            Self::HardwareSecurity => b"verrou-slot-hardware",
        }
    }

    /// Return a string identifier for this slot type (used in DB records).
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Biometric => "biometric",
            Self::Recovery => "recovery",
            Self::HardwareSecurity => "hardware",
        }
    }
}

/// A key slot: an AES-256-GCM wrapped copy of the master key.
///
/// Multiple `KeySlot` instances can coexist, each wrapping the same master
/// key with a different wrapping key. Slots are independent — adding or
/// removing one never affects others.
#[must_use = "key slot must be stored in the vault header"]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeySlot {
    /// The unlock method this slot serves.
    pub slot_type: SlotType,
    /// The master key encrypted with the wrapping key (AES-256-GCM).
    pub wrapped_key: SealedData,
}

// ---------------------------------------------------------------------------
// Slot operations
// ---------------------------------------------------------------------------

/// Wrap a master key into a new [`KeySlot`].
///
/// The master key is encrypted with AES-256-GCM using the wrapping key and
/// the slot type's AAD tag for domain separation.
///
/// # Arguments
///
/// - `master_key` — exactly 32 bytes (the vault master key)
/// - `wrapping_key` — exactly 32 bytes (derived from password, biometric, or recovery)
/// - `slot_type` — the unlock method this slot serves
///
/// # Errors
///
/// Returns [`CryptoError::InvalidKeyMaterial`] if either key is not exactly 32 bytes.
/// Returns [`CryptoError::Encryption`] if the underlying AES-256-GCM operation fails.
pub fn create_slot(
    master_key: &[u8],
    wrapping_key: &[u8],
    slot_type: SlotType,
) -> Result<KeySlot, CryptoError> {
    if master_key.len() != MASTER_KEY_LEN {
        return Err(CryptoError::InvalidKeyMaterial(format!(
            "invalid master key length: {} bytes (expected {MASTER_KEY_LEN})",
            master_key.len()
        )));
    }
    if wrapping_key.len() != WRAPPING_KEY_LEN {
        return Err(CryptoError::InvalidKeyMaterial(format!(
            "invalid wrapping key length: {} bytes (expected {WRAPPING_KEY_LEN})",
            wrapping_key.len()
        )));
    }

    let wrapped_key = symmetric::encrypt(master_key, wrapping_key, slot_type.aad_tag())?;

    Ok(KeySlot {
        slot_type,
        wrapped_key,
    })
}

/// Unwrap a [`KeySlot`] to recover the master key.
///
/// The wrapping key and slot type's AAD tag must match what was used in
/// [`create_slot`]. The returned [`SecretBuffer`] is mlocked and zeroized
/// on drop.
///
/// # Arguments
///
/// - `slot` — the key slot to unwrap
/// - `wrapping_key` — exactly 32 bytes (must match the key used to create the slot)
///
/// # Errors
///
/// Returns [`CryptoError::InvalidKeyMaterial`] if the wrapping key is not exactly 32 bytes.
/// Returns [`CryptoError::Decryption`] if the wrapping key is wrong, data is tampered,
/// or the slot type AAD doesn't match.
pub fn unwrap_slot(slot: &KeySlot, wrapping_key: &[u8]) -> Result<SecretBuffer, CryptoError> {
    if wrapping_key.len() != WRAPPING_KEY_LEN {
        return Err(CryptoError::InvalidKeyMaterial(format!(
            "invalid wrapping key length: {} bytes (expected {WRAPPING_KEY_LEN})",
            wrapping_key.len()
        )));
    }

    symmetric::decrypt(&slot.wrapped_key, wrapping_key, slot.slot_type.aad_tag())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed master key for tests — 32 bytes of 0xAA.
    const TEST_MASTER_KEY: [u8; MASTER_KEY_LEN] = [0xAA; MASTER_KEY_LEN];

    /// Fixed wrapping key for tests — 32 bytes of 0xBB.
    const TEST_WRAPPING_KEY: [u8; WRAPPING_KEY_LEN] = [0xBB; WRAPPING_KEY_LEN];

    /// Different wrapping key for wrong-key tests.
    const WRONG_WRAPPING_KEY: [u8; WRAPPING_KEY_LEN] = [0xCC; WRAPPING_KEY_LEN];

    #[test]
    fn create_unwrap_roundtrip_password() {
        let slot = create_slot(&TEST_MASTER_KEY, &TEST_WRAPPING_KEY, SlotType::Password)
            .expect("create_slot should succeed");
        assert_eq!(slot.slot_type, SlotType::Password);

        let unwrapped = unwrap_slot(&slot, &TEST_WRAPPING_KEY).expect("unwrap_slot should succeed");
        assert_eq!(unwrapped.expose(), &TEST_MASTER_KEY);
    }

    #[test]
    fn create_unwrap_roundtrip_biometric() {
        let slot = create_slot(&TEST_MASTER_KEY, &TEST_WRAPPING_KEY, SlotType::Biometric)
            .expect("create_slot should succeed");
        assert_eq!(slot.slot_type, SlotType::Biometric);

        let unwrapped = unwrap_slot(&slot, &TEST_WRAPPING_KEY).expect("unwrap_slot should succeed");
        assert_eq!(unwrapped.expose(), &TEST_MASTER_KEY);
    }

    #[test]
    fn create_unwrap_roundtrip_recovery() {
        let slot = create_slot(&TEST_MASTER_KEY, &TEST_WRAPPING_KEY, SlotType::Recovery)
            .expect("create_slot should succeed");
        assert_eq!(slot.slot_type, SlotType::Recovery);

        let unwrapped = unwrap_slot(&slot, &TEST_WRAPPING_KEY).expect("unwrap_slot should succeed");
        assert_eq!(unwrapped.expose(), &TEST_MASTER_KEY);
    }

    #[test]
    fn unwrap_with_wrong_key_fails() {
        let slot = create_slot(&TEST_MASTER_KEY, &TEST_WRAPPING_KEY, SlotType::Password)
            .expect("create_slot should succeed");

        let result = unwrap_slot(&slot, &WRONG_WRAPPING_KEY);
        assert!(result.is_err());
        assert!(
            matches!(result, Err(CryptoError::Decryption)),
            "wrong key should yield CryptoError::Decryption"
        );
    }

    #[test]
    fn unwrap_with_tampered_ciphertext_fails() {
        let mut slot = create_slot(&TEST_MASTER_KEY, &TEST_WRAPPING_KEY, SlotType::Password)
            .expect("create_slot should succeed");

        if let Some(byte) = slot.wrapped_key.ciphertext.first_mut() {
            *byte ^= 0xFF;
        }

        let result = unwrap_slot(&slot, &TEST_WRAPPING_KEY);
        assert!(result.is_err());
        assert!(
            matches!(result, Err(CryptoError::Decryption)),
            "tampered ciphertext should yield CryptoError::Decryption"
        );
    }

    #[test]
    fn unwrap_with_tampered_tag_fails() {
        let mut slot = create_slot(&TEST_MASTER_KEY, &TEST_WRAPPING_KEY, SlotType::Password)
            .expect("create_slot should succeed");

        slot.wrapped_key.tag[0] ^= 0xFF;

        let result = unwrap_slot(&slot, &TEST_WRAPPING_KEY);
        assert!(result.is_err());
        assert!(
            matches!(result, Err(CryptoError::Decryption)),
            "tampered tag should yield CryptoError::Decryption"
        );
    }

    #[test]
    fn cross_slot_type_unwrap_fails() {
        let slot = create_slot(&TEST_MASTER_KEY, &TEST_WRAPPING_KEY, SlotType::Password)
            .expect("create_slot should succeed");

        // Forge a slot with the wrong type — AAD mismatch should cause decryption failure.
        let forged = KeySlot {
            slot_type: SlotType::Biometric,
            wrapped_key: slot.wrapped_key,
        };

        let result = unwrap_slot(&forged, &TEST_WRAPPING_KEY);
        assert!(result.is_err());
        assert!(
            matches!(result, Err(CryptoError::Decryption)),
            "cross-type AAD mismatch should yield CryptoError::Decryption"
        );
    }

    #[test]
    fn create_slot_rejects_short_master_key() {
        let result = create_slot(&[0u8; 31], &TEST_WRAPPING_KEY, SlotType::Password);
        assert!(result.is_err());
        assert!(
            matches!(result, Err(CryptoError::InvalidKeyMaterial(_))),
            "short master key should yield CryptoError::InvalidKeyMaterial"
        );
    }

    #[test]
    fn create_slot_rejects_long_master_key() {
        let result = create_slot(&[0u8; 33], &TEST_WRAPPING_KEY, SlotType::Password);
        assert!(result.is_err());
        assert!(
            matches!(result, Err(CryptoError::InvalidKeyMaterial(_))),
            "long master key should yield CryptoError::InvalidKeyMaterial"
        );
    }

    #[test]
    fn create_slot_rejects_short_wrapping_key() {
        let result = create_slot(&TEST_MASTER_KEY, &[0u8; 31], SlotType::Password);
        assert!(result.is_err());
        assert!(
            matches!(result, Err(CryptoError::InvalidKeyMaterial(_))),
            "short wrapping key should yield CryptoError::InvalidKeyMaterial"
        );
    }

    #[test]
    fn create_slot_rejects_long_wrapping_key() {
        let result = create_slot(&TEST_MASTER_KEY, &[0u8; 33], SlotType::Password);
        assert!(result.is_err());
        assert!(
            matches!(result, Err(CryptoError::InvalidKeyMaterial(_))),
            "long wrapping key should yield CryptoError::InvalidKeyMaterial"
        );
    }

    #[test]
    fn two_slots_same_keys_different_ciphertexts() {
        let slot_a = create_slot(&TEST_MASTER_KEY, &TEST_WRAPPING_KEY, SlotType::Password)
            .expect("create_slot should succeed");
        let slot_b = create_slot(&TEST_MASTER_KEY, &TEST_WRAPPING_KEY, SlotType::Password)
            .expect("create_slot should succeed");

        // Different random nonces → different ciphertexts.
        assert_ne!(
            slot_a.wrapped_key.nonce, slot_b.wrapped_key.nonce,
            "nonces should differ"
        );
    }

    #[test]
    fn key_slot_serde_roundtrip() {
        let slot = create_slot(&TEST_MASTER_KEY, &TEST_WRAPPING_KEY, SlotType::Recovery)
            .expect("create_slot should succeed");

        let json = serde_json::to_string(&slot).expect("serialize should succeed");
        let deserialized: KeySlot =
            serde_json::from_str(&json).expect("deserialize should succeed");

        assert_eq!(deserialized.slot_type, slot.slot_type);
        assert_eq!(deserialized.wrapped_key.nonce, slot.wrapped_key.nonce);
        assert_eq!(
            deserialized.wrapped_key.ciphertext,
            slot.wrapped_key.ciphertext
        );
        assert_eq!(deserialized.wrapped_key.tag, slot.wrapped_key.tag);

        // Deserialized slot should still unwrap correctly.
        let unwrapped =
            unwrap_slot(&deserialized, &TEST_WRAPPING_KEY).expect("unwrap should succeed");
        assert_eq!(unwrapped.expose(), &TEST_MASTER_KEY);
    }

    #[test]
    fn create_unwrap_roundtrip_hardware_security() {
        let slot = create_slot(
            &TEST_MASTER_KEY,
            &TEST_WRAPPING_KEY,
            SlotType::HardwareSecurity,
        )
        .expect("create_slot should succeed");
        assert_eq!(slot.slot_type, SlotType::HardwareSecurity);

        let unwrapped = unwrap_slot(&slot, &TEST_WRAPPING_KEY).expect("unwrap_slot should succeed");
        assert_eq!(unwrapped.expose(), &TEST_MASTER_KEY);
    }

    #[test]
    fn hardware_security_cross_type_fails() {
        let slot = create_slot(
            &TEST_MASTER_KEY,
            &TEST_WRAPPING_KEY,
            SlotType::HardwareSecurity,
        )
        .expect("create_slot should succeed");

        // Forge a slot with the wrong type — AAD mismatch.
        let forged = KeySlot {
            slot_type: SlotType::Biometric,
            wrapped_key: slot.wrapped_key,
        };

        let result = unwrap_slot(&forged, &TEST_WRAPPING_KEY);
        assert!(result.is_err());
        assert!(
            matches!(result, Err(CryptoError::Decryption)),
            "HardwareSecurity→Biometric cross-type should fail"
        );
    }

    #[test]
    fn hardware_security_as_str() {
        assert_eq!(SlotType::HardwareSecurity.as_str(), "hardware");
        assert_eq!(SlotType::Password.as_str(), "password");
        assert_eq!(SlotType::Biometric.as_str(), "biometric");
        assert_eq!(SlotType::Recovery.as_str(), "recovery");
    }

    #[test]
    fn slot_type_serde_roundtrip() {
        for slot_type in [
            SlotType::Password,
            SlotType::Biometric,
            SlotType::Recovery,
            SlotType::HardwareSecurity,
        ] {
            let json = serde_json::to_string(&slot_type).expect("serialize should succeed");
            let deserialized: SlotType =
                serde_json::from_str(&json).expect("deserialize should succeed");
            assert_eq!(deserialized, slot_type);
        }
    }

    #[test]
    fn multiple_independent_slots_unwrap_to_same_master_key() {
        let password_slot = create_slot(
            &TEST_MASTER_KEY,
            &[0x01; WRAPPING_KEY_LEN],
            SlotType::Password,
        )
        .expect("create password slot should succeed");
        let biometric_slot = create_slot(
            &TEST_MASTER_KEY,
            &[0x02; WRAPPING_KEY_LEN],
            SlotType::Biometric,
        )
        .expect("create biometric slot should succeed");
        let recovery_slot = create_slot(
            &TEST_MASTER_KEY,
            &[0x03; WRAPPING_KEY_LEN],
            SlotType::Recovery,
        )
        .expect("create recovery slot should succeed");
        let hw_slot = create_slot(
            &TEST_MASTER_KEY,
            &[0x04; WRAPPING_KEY_LEN],
            SlotType::HardwareSecurity,
        )
        .expect("create hardware security slot should succeed");

        let mk_from_password =
            unwrap_slot(&password_slot, &[0x01; WRAPPING_KEY_LEN]).expect("unwrap should succeed");
        let mk_from_biometric =
            unwrap_slot(&biometric_slot, &[0x02; WRAPPING_KEY_LEN]).expect("unwrap should succeed");
        let mk_from_recovery =
            unwrap_slot(&recovery_slot, &[0x03; WRAPPING_KEY_LEN]).expect("unwrap should succeed");
        let mk_from_hw =
            unwrap_slot(&hw_slot, &[0x04; WRAPPING_KEY_LEN]).expect("unwrap should succeed");

        assert_eq!(mk_from_password.expose(), &TEST_MASTER_KEY);
        assert_eq!(mk_from_biometric.expose(), &TEST_MASTER_KEY);
        assert_eq!(mk_from_recovery.expose(), &TEST_MASTER_KEY);
        assert_eq!(mk_from_hw.expose(), &TEST_MASTER_KEY);
    }

    #[test]
    fn create_slot_rejects_empty_master_key() {
        let result = create_slot(&[], &TEST_WRAPPING_KEY, SlotType::Password);
        assert!(result.is_err());
        assert!(
            matches!(result, Err(CryptoError::InvalidKeyMaterial(_))),
            "empty master key should yield CryptoError::InvalidKeyMaterial"
        );
    }

    #[test]
    fn create_slot_rejects_empty_wrapping_key() {
        let result = create_slot(&TEST_MASTER_KEY, &[], SlotType::Password);
        assert!(result.is_err());
        assert!(
            matches!(result, Err(CryptoError::InvalidKeyMaterial(_))),
            "empty wrapping key should yield CryptoError::InvalidKeyMaterial"
        );
    }

    #[test]
    fn unwrapped_master_key_matches_original() {
        let original = [0x42_u8; MASTER_KEY_LEN];
        let slot = create_slot(&original, &TEST_WRAPPING_KEY, SlotType::Password)
            .expect("create_slot should succeed");
        let unwrapped = unwrap_slot(&slot, &TEST_WRAPPING_KEY).expect("unwrap_slot should succeed");
        assert_eq!(
            unwrapped.expose(),
            &original,
            "unwrapped key must exactly match the original master key"
        );
    }
}
