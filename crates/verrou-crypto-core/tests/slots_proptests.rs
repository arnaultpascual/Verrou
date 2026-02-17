#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

//! Property-based tests for key slot wrap/unwrap.
//!
//! Verifies the algebraic invariant:
//! `∀ mk, wk, st: unwrap(create(mk, wk, st), wk) == mk`

use proptest::prelude::*;
use verrou_crypto_core::slots::{create_slot, unwrap_slot, SlotType};
use verrou_crypto_core::CryptoError;

fn slot_type_strategy() -> impl Strategy<Value = SlotType> {
    prop_oneof![
        Just(SlotType::Password),
        Just(SlotType::Biometric),
        Just(SlotType::Recovery),
        Just(SlotType::HardwareSecurity),
    ]
}

proptest! {
    /// For any master key, wrapping key, and slot type, unwrapping a
    /// freshly created slot with the same wrapping key recovers the
    /// original master key.
    #[test]
    fn wrap_unwrap_roundtrip(
        master_key in proptest::array::uniform32(0u8..),
        wrapping_key in proptest::array::uniform32(0u8..),
        slot_type in slot_type_strategy(),
    ) {
        let slot = create_slot(&master_key, &wrapping_key, slot_type)
            .expect("create_slot should succeed for valid-length keys");
        let unwrapped = unwrap_slot(&slot, &wrapping_key)
            .expect("unwrap_slot should succeed with correct wrapping key");
        prop_assert_eq!(unwrapped.expose(), &master_key[..]);
    }

    /// Unwrapping with a different wrapping key always fails.
    #[test]
    fn wrong_key_always_fails(
        master_key in proptest::array::uniform32(0u8..),
        wrapping_key in proptest::array::uniform32(0u8..),
        wrong_key in proptest::array::uniform32(0u8..),
        slot_type in slot_type_strategy(),
    ) {
        prop_assume!(wrapping_key != wrong_key);
        let slot = create_slot(&master_key, &wrapping_key, slot_type)
            .expect("create_slot should succeed");
        let result = unwrap_slot(&slot, &wrong_key);
        prop_assert!(
            matches!(result, Err(CryptoError::Decryption)),
            "wrong key must yield CryptoError::Decryption, got: {:?}",
            result
        );
    }

    /// Unwrapping a slot with a different slot type's AAD always fails
    /// (domain separation).
    #[test]
    fn cross_slot_type_rejection(
        master_key in proptest::array::uniform32(0u8..),
        wrapping_key in proptest::array::uniform32(0u8..),
        slot_type in slot_type_strategy(),
    ) {
        let slot = create_slot(&master_key, &wrapping_key, slot_type)
            .expect("create_slot should succeed");

        // Forge a slot with a different type — AAD mismatch should cause failure.
        let other_type = match slot_type {
            SlotType::Password => SlotType::Biometric,
            SlotType::Biometric => SlotType::Recovery,
            SlotType::Recovery => SlotType::HardwareSecurity,
            SlotType::HardwareSecurity => SlotType::Password,
        };
        let forged = verrou_crypto_core::slots::KeySlot {
            slot_type: other_type,
            wrapped_key: slot.wrapped_key,
        };

        let result = unwrap_slot(&forged, &wrapping_key);
        prop_assert!(
            matches!(result, Err(CryptoError::Decryption)),
            "cross-type AAD mismatch must yield CryptoError::Decryption, got: {:?}",
            result
        );
    }
}
