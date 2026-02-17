#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

//! Property-based tests for the hybrid KEM module.

use proptest::prelude::*;
use verrou_crypto_core::kem;

proptest! {
    /// For every freshly generated key pair, encapsulate → decapsulate
    /// must produce identical shared secrets.
    #[test]
    fn roundtrip_shared_secret_matches(_seed in 0u64..1000) {
        let kp = kem::generate_keypair().expect("keygen should succeed");
        let (ct, ss_enc) = kem::encapsulate(&kp.public).expect("encapsulate should succeed");
        let ss_dec = kem::decapsulate(&ct, &kp.private).expect("decapsulate should succeed");
        prop_assert_eq!(
            ss_enc.expose(),
            ss_dec.expose(),
            "shared secret mismatch in roundtrip"
        );
    }

    /// Each encapsulation with the same public key must produce a unique
    /// shared secret (different ephemeral randomness).
    #[test]
    fn encapsulations_produce_unique_shared_secrets(_seed in 0u64..100) {
        let kp = kem::generate_keypair().expect("keygen should succeed");
        let (_, ss_a) = kem::encapsulate(&kp.public).expect("encapsulate should succeed");
        let (_, ss_b) = kem::encapsulate(&kp.public).expect("encapsulate should succeed");
        prop_assert_ne!(
            ss_a.expose(),
            ss_b.expose(),
            "two encapsulations with same key must produce different shared secrets"
        );
    }
}
