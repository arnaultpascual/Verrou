//! RFC 9106 Section 5.4 — Argon2id Known-Answer Test vectors.
//!
//! These tests verify our `derive` function against the reference implementation.
//! Note: The RFC test vector uses a secret key and associated data, so we test
//! the raw `argon2` crate directly for the KAT vector, and test our `derive()`
//! wrapper separately with small params.

use verrou_crypto_core::kdf::{derive, Argon2idParams};

/// RFC 9106 Section 5.4 — Argon2id test vector.
///
/// This uses secret+AD which our `derive()` doesn't support, so we test
/// the underlying argon2 crate directly for the exact KAT match.
#[test]
fn rfc9106_section_5_4_argon2id() {
    // RFC 9106 Section 5.4 test vector:
    // Type: Argon2id, Version: 0x13
    // Memory: 32 KiB, Iterations: 3, Parallelism: 4
    // Password:  01 01 01 01 ... (32 bytes of 0x01)
    // Salt:      02 02 02 02 ... (16 bytes of 0x02)
    // Secret:    03 03 03 03 ... (8 bytes of 0x03)
    // AD:        04 04 04 04 ... (12 bytes of 0x04)
    let password = [0x01u8; 32];
    let salt = [0x02u8; 16];
    let secret = [0x03u8; 8];
    let ad_bytes = [0x04u8; 12];

    let ad = argon2::AssociatedData::new(&ad_bytes).expect("AD should be valid");
    // Build params with AD using ParamsBuilder (the RFC vector uses secret+AD)
    let mut builder = argon2::ParamsBuilder::new();
    builder.m_cost(32);
    builder.t_cost(3);
    builder.p_cost(4);
    builder.output_len(32);
    builder.data(ad);
    let params_with_ad = builder.build().expect("params with AD should be valid");

    let argon2 = argon2::Argon2::new_with_secret(
        &secret,
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params_with_ad,
    )
    .expect("argon2 with secret should be valid");

    let mut output = [0u8; 32];
    argon2
        .hash_password_into(&password, &salt, &mut output)
        .expect("hash_password_into should succeed");

    let expected: [u8; 32] = [
        0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c, 0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b, 0x53,
        0xc9, 0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e, 0xb5, 0x25, 0x20, 0xe9, 0x6b, 0x01,
        0xe6, 0x59,
    ];

    assert_eq!(
        output, expected,
        "RFC 9106 Section 5.4 Argon2id KAT vector mismatch"
    );
}

/// Additional test: verify our `derive()` wrapper produces consistent results
/// with small (test-only) parameters.
#[test]
fn derive_consistency_small_params() {
    let params = Argon2idParams {
        m_cost: 32,
        t_cost: 1,
        p_cost: 1,
    };
    let password = b"test_password";
    let salt = b"0123456789abcdef"; // 16 bytes

    // Derive twice with same inputs — must match.
    let key_a = derive(password, salt, &params).expect("derive should succeed");
    let key_b = derive(password, salt, &params).expect("derive should succeed");
    assert_eq!(key_a.expose(), key_b.expose());
    assert_eq!(key_a.len(), 32);
}

/// Verify that the raw argon2 crate with our exact parameter pattern (no secret, no AD)
/// gives the same output as our `derive()` wrapper.
#[test]
fn derive_matches_raw_argon2() {
    let params = Argon2idParams {
        m_cost: 64, // 64 KiB
        t_cost: 2,
        p_cost: 1,
    };
    let password = b"match_test";
    let salt = b"salt_for_matching";

    // Our derive() wrapper
    let our_key = derive(password, salt, &params).expect("derive should succeed");

    // Direct argon2 crate call
    let argon2_params = argon2::Params::new(64, 2, 1, Some(32)).expect("params should be valid");
    let argon2 = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2_params,
    );
    let mut raw_output = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut raw_output)
        .expect("raw argon2 should succeed");

    assert_eq!(
        our_key.expose(),
        &raw_output,
        "derive() wrapper must match raw argon2 crate output"
    );
}
