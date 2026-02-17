//! Integration tests for hybrid Ed25519 + ML-DSA-65 signing.
//!
//! Tests full sign → verify roundtrips with realistic message sizes,
//! cross-key rejection, and error type validation.

use verrou_crypto_core::signing::{generate_signing_keypair, sign, verify};
use verrou_crypto_core::CryptoError;

/// Full hybrid sign → verify roundtrip with a single byte.
#[test]
fn roundtrip_1_byte_message() {
    let kp = generate_signing_keypair().expect("keygen should succeed");
    let message = &[0x42_u8];

    let sig = sign(message, &kp).expect("signing should succeed");
    verify(message, &sig, &kp.public).expect("verification should succeed");
}

/// Full hybrid sign → verify roundtrip with 1 KB payload.
#[test]
fn roundtrip_1kb_message() {
    let kp = generate_signing_keypair().expect("keygen should succeed");
    let message = vec![0xAB_u8; 1024];

    let sig = sign(&message, &kp).expect("signing should succeed");
    verify(&message, &sig, &kp.public).expect("verification should succeed");
}

/// Full hybrid sign → verify roundtrip with 1 MB payload.
#[test]
fn roundtrip_1mb_message() {
    let kp = generate_signing_keypair().expect("keygen should succeed");
    let message = vec![0xCD_u8; 1_048_576];

    let sig = sign(&message, &kp).expect("signing should succeed");
    verify(&message, &sig, &kp.public).expect("verification should succeed");
}

/// Cross-key rejection: sign with key A, verify with key B.
#[test]
fn cross_keypair_verification_fails() {
    let kp_a = generate_signing_keypair().expect("keygen A should succeed");
    let kp_b = generate_signing_keypair().expect("keygen B should succeed");
    let message = b"signed with key A";

    let sig = sign(message, &kp_a).expect("signing should succeed");
    let result = verify(message, &sig, &kp_b.public);

    assert!(result.is_err(), "verification with wrong key must fail");
    assert!(
        matches!(result, Err(CryptoError::Signature(_))),
        "error must be CryptoError::Signature"
    );
}

/// Verify returns `CryptoError::Signature` on failure (not a generic error).
#[test]
fn verify_error_type_is_signature() {
    let kp = generate_signing_keypair().expect("keygen should succeed");
    let message = b"correct message";

    let sig = sign(message, &kp).expect("signing should succeed");
    let result = verify(b"wrong message", &sig, &kp.public);

    assert!(result.is_err());
    match result {
        Err(CryptoError::Signature(msg)) => {
            assert!(!msg.is_empty(), "error message should not be empty");
        }
        other => panic!("expected CryptoError::Signature, got: {other:?}"),
    }
}
