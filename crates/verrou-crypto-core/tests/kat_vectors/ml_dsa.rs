//! ML-DSA-65 (FIPS 204) Known-Answer Tests.
//!
//! Verifies that `libcrux_ml_dsa::ml_dsa_65` produces deterministic key pairs
//! from known randomness and that sign/verify roundtrips succeed.

use libcrux_ml_dsa::ml_dsa_65;

/// ML-DSA-65 key generation is deterministic given the same randomness.
#[test]
fn ml_dsa_65_keygen_deterministic() {
    let randomness = [0xAA_u8; 32];

    let kp1 = ml_dsa_65::generate_key_pair(randomness);
    let kp2 = ml_dsa_65::generate_key_pair(randomness);

    assert_eq!(
        kp1.verification_key.as_ref(),
        kp2.verification_key.as_ref(),
        "same randomness must produce same verification key"
    );
    assert_eq!(
        kp1.signing_key.as_slice(),
        kp2.signing_key.as_slice(),
        "same randomness must produce same signing key"
    );
}

/// ML-DSA-65 sign/verify roundtrip with deterministic keygen.
#[test]
fn ml_dsa_65_sign_verify_roundtrip() {
    let keygen_rand = [0xBB_u8; 32];
    let sign_rand = [0xCC_u8; 32];
    let message = b"VERROU release artifact v1.0.0";
    let context = b"VERROU-HYBRID-SIG-v1";

    let kp = ml_dsa_65::generate_key_pair(keygen_rand);

    let sig = ml_dsa_65::sign(&kp.signing_key, message, context, sign_rand)
        .expect("signing should succeed");

    ml_dsa_65::verify(&kp.verification_key, message, context, &sig)
        .expect("verification should succeed");
}

/// ML-DSA-65 key sizes match FIPS 204 specification.
#[test]
fn ml_dsa_65_key_sizes_match_fips_204() {
    let randomness = [0x42_u8; 32];
    let kp = ml_dsa_65::generate_key_pair(randomness);

    assert_eq!(
        kp.verification_key.as_ref().len(),
        1952,
        "ML-DSA-65 verification key must be 1952 bytes"
    );
    assert_eq!(
        kp.signing_key.as_slice().len(),
        4032,
        "ML-DSA-65 signing key must be 4032 bytes"
    );
}

/// ML-DSA-65 signature size matches FIPS 204 specification.
#[test]
fn ml_dsa_65_signature_size_matches_fips_204() {
    let keygen_rand = [0x42_u8; 32];
    let sign_rand = [0x43_u8; 32];
    let message = b"size check";
    let context = b"test";

    let kp = ml_dsa_65::generate_key_pair(keygen_rand);
    let sig = ml_dsa_65::sign(&kp.signing_key, message, context, sign_rand)
        .expect("signing should succeed");

    assert_eq!(
        sig.as_ref().len(),
        3309,
        "ML-DSA-65 signature must be 3309 bytes"
    );
}

/// ML-DSA-65 verification key is deterministic — pin first 16 bytes
/// from known randomness `[0xAA; 32]` to detect algorithm changes
/// across libcrux-ml-dsa versions.
#[test]
fn ml_dsa_65_verification_key_pinned_prefix() {
    let randomness = [0xAA_u8; 32];
    let kp = ml_dsa_65::generate_key_pair(randomness);
    let vk = kp.verification_key.as_ref();

    // Hardcoded expected prefix — derived once from libcrux-ml-dsa 0.0.6.
    // If this test fails after a dependency update, the keygen algorithm changed.
    #[rustfmt::skip]
    let expected_prefix: [u8; 16] = [
        0x2A, 0x3C, 0xD5, 0x53, 0x79, 0x10, 0x45, 0xA9,
        0x36, 0x33, 0x93, 0xC3, 0xF7, 0x20, 0x86, 0x60,
    ];

    assert_eq!(
        &vk[..16],
        &expected_prefix,
        "ML-DSA-65 verification key prefix must match pinned value (libcrux-ml-dsa 0.0.6)"
    );
}

/// ML-DSA-65 verification fails with wrong key.
#[test]
fn ml_dsa_65_verify_wrong_key_fails() {
    let keygen_rand1 = [0x01_u8; 32];
    let keygen_rand2 = [0x02_u8; 32];
    let sign_rand = [0x03_u8; 32];
    let message = b"wrong key test";
    let context = b"test";

    let kp1 = ml_dsa_65::generate_key_pair(keygen_rand1);
    let kp2 = ml_dsa_65::generate_key_pair(keygen_rand2);

    let sig = ml_dsa_65::sign(&kp1.signing_key, message, context, sign_rand)
        .expect("signing should succeed");

    let result = ml_dsa_65::verify(&kp2.verification_key, message, context, &sig);
    assert!(result.is_err(), "verification with wrong key must fail");
}

/// ML-DSA-65 verification fails with tampered message.
#[test]
fn ml_dsa_65_verify_tampered_message_fails() {
    let keygen_rand = [0x04_u8; 32];
    let sign_rand = [0x05_u8; 32];
    let context = b"test";

    let kp = ml_dsa_65::generate_key_pair(keygen_rand);
    let sig = ml_dsa_65::sign(&kp.signing_key, b"original", context, sign_rand)
        .expect("signing should succeed");

    let result = ml_dsa_65::verify(&kp.verification_key, b"tampered", context, &sig);
    assert!(
        result.is_err(),
        "verification with tampered message must fail"
    );
}

/// Different signing randomness produces different signatures.
#[test]
fn ml_dsa_65_different_randomness_different_signatures() {
    let keygen_rand = [0x06_u8; 32];
    let sign_rand1 = [0x07_u8; 32];
    let sign_rand2 = [0x08_u8; 32];
    let message = b"same message";
    let context = b"test";

    let kp = ml_dsa_65::generate_key_pair(keygen_rand);
    let sig1 = ml_dsa_65::sign(&kp.signing_key, message, context, sign_rand1)
        .expect("signing should succeed");
    let sig2 = ml_dsa_65::sign(&kp.signing_key, message, context, sign_rand2)
        .expect("signing should succeed");

    assert_ne!(
        sig1.as_ref(),
        sig2.as_ref(),
        "different signing randomness must produce different signatures"
    );

    // Both must still verify
    ml_dsa_65::verify(&kp.verification_key, message, context, &sig1).expect("sig1 should verify");
    ml_dsa_65::verify(&kp.verification_key, message, context, &sig2).expect("sig2 should verify");
}
