#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

//! Property-based tests for AES-256-GCM symmetric encryption.

use proptest::prelude::*;
use verrou_crypto_core::symmetric::{decrypt, encrypt, KEY_LEN};

/// Fixed key for property tests.
const PROP_KEY: [u8; KEY_LEN] = [0xCC; KEY_LEN];

proptest! {
    /// Encrypt→decrypt roundtrip always recovers original plaintext (empty AAD).
    #[test]
    fn encrypt_decrypt_roundtrip(
        plaintext in proptest::collection::vec(any::<u8>(), 0..4096),
    ) {
        let sealed = encrypt(&plaintext, &PROP_KEY, &[])
            .expect("encrypt should succeed");
        let decrypted = decrypt(&sealed, &PROP_KEY, &[])
            .expect("decrypt should succeed");
        prop_assert_eq!(decrypted.expose(), plaintext.as_slice());
    }

    /// Encrypt→decrypt roundtrip with arbitrary AAD.
    #[test]
    fn encrypt_decrypt_roundtrip_with_aad(
        plaintext in proptest::collection::vec(any::<u8>(), 0..2048),
        aad in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        let sealed = encrypt(&plaintext, &PROP_KEY, &aad)
            .expect("encrypt should succeed");
        let decrypted = decrypt(&sealed, &PROP_KEY, &aad)
            .expect("decrypt should succeed");
        prop_assert_eq!(decrypted.expose(), plaintext.as_slice());
    }
}
