#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

//! Property-based tests for Argon2id key derivation.

use proptest::prelude::*;
use verrou_crypto_core::kdf::{derive, Argon2idParams};

/// Small params for fast property tests.
const PROP_PARAMS: Argon2idParams = Argon2idParams {
    m_cost: 32,
    t_cost: 1,
    p_cost: 1,
};

proptest! {
    /// Derived key is always exactly 32 bytes regardless of password/salt content.
    #[test]
    fn derive_always_32_bytes(
        password in proptest::collection::vec(any::<u8>(), 1..128),
        salt in proptest::collection::vec(any::<u8>(), 16..64),
    ) {
        let key = derive(&password, &salt, &PROP_PARAMS)
            .expect("derive should succeed with valid inputs");
        prop_assert_eq!(key.len(), 32);
    }

    /// Different params produce different keys for the same password+salt.
    #[test]
    fn different_params_different_keys(
        password in proptest::collection::vec(any::<u8>(), 1..64),
    ) {
        let salt = b"proptest_salt_16b";
        let params_a = Argon2idParams { m_cost: 32, t_cost: 1, p_cost: 1 };
        let params_b = Argon2idParams { m_cost: 32, t_cost: 2, p_cost: 1 };

        let key_a = derive(&password, salt, &params_a)
            .expect("derive with params_a should succeed");
        let key_b = derive(&password, salt, &params_b)
            .expect("derive with params_b should succeed");

        prop_assert_ne!(key_a.expose(), key_b.expose());
    }
}
