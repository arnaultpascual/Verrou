#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

//! Property-based tests for `.verrou` vault file format.

use proptest::prelude::*;
use verrou_crypto_core::kdf::Argon2idParams;
use verrou_crypto_core::slots::MASTER_KEY_LEN;
use verrou_crypto_core::vault_format::{
    deserialize, serialize, VaultHeader, FORMAT_VERSION, MAGIC, PADDING_BOUNDARY,
};
use verrou_crypto_core::CryptoError;

/// Fixed master key for property tests.
const PROP_MASTER_KEY: [u8; MASTER_KEY_LEN] = [0xDD; MASTER_KEY_LEN];

/// Create a minimal header for property tests.
#[allow(clippy::missing_const_for_fn)]
fn prop_header() -> VaultHeader {
    VaultHeader {
        version: FORMAT_VERSION,
        slot_count: 0,
        session_params: Argon2idParams {
            m_cost: 262_144,
            t_cost: 3,
            p_cost: 4,
        },
        sensitive_params: Argon2idParams {
            m_cost: 524_288,
            t_cost: 4,
            p_cost: 4,
        },
        unlock_attempts: 0,
        last_attempt_at: None,
        total_unlock_count: 0,
        slots: vec![],
        slot_salts: vec![],
    }
}

proptest! {
    /// Serialize→deserialize always recovers the original payload.
    #[test]
    fn roundtrip_preserves_payload(
        payload in proptest::collection::vec(any::<u8>(), 0..8192),
    ) {
        let blob = serialize(&prop_header(), &payload, &PROP_MASTER_KEY)
            .expect("serialize should succeed");
        let (header, recovered) = deserialize(&blob, &PROP_MASTER_KEY)
            .expect("deserialize should succeed");

        prop_assert_eq!(recovered.expose(), payload.as_slice());
        prop_assert_eq!(header.version, FORMAT_VERSION);
    }

    /// Output is always 64 KB-aligned regardless of payload size.
    #[test]
    fn output_always_64kb_aligned(
        payload in proptest::collection::vec(any::<u8>(), 0..16384),
    ) {
        let blob = serialize(&prop_header(), &payload, &PROP_MASTER_KEY)
            .expect("serialize should succeed");

        prop_assert_eq!(
            blob.len() % PADDING_BOUNDARY,
            0,
            "blob length {} is not a multiple of {}",
            blob.len(),
            PADDING_BOUNDARY
        );
    }

    /// Wrong master key always produces Decryption error.
    #[test]
    fn wrong_key_always_fails(
        payload in proptest::collection::vec(any::<u8>(), 0..4096),
        wrong_key in proptest::array::uniform32(0u8..),
    ) {
        // Skip the rare case where wrong_key == PROP_MASTER_KEY.
        prop_assume!(wrong_key != PROP_MASTER_KEY);

        let blob = serialize(&prop_header(), &payload, &PROP_MASTER_KEY)
            .expect("serialize should succeed");
        let result = deserialize(&blob, &wrong_key);

        prop_assert!(
            matches!(result, Err(CryptoError::Decryption)),
            "wrong key must yield CryptoError::Decryption, got: {:?}",
            result
        );
    }

    /// Output always starts with the VROU magic bytes.
    #[test]
    fn output_starts_with_magic(
        payload in proptest::collection::vec(any::<u8>(), 0..2048),
    ) {
        let blob = serialize(&prop_header(), &payload, &PROP_MASTER_KEY)
            .expect("serialize should succeed");

        prop_assert_eq!(&blob[..4], MAGIC.as_slice());
    }
}
