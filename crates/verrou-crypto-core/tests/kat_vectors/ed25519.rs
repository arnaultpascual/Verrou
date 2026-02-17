//! RFC 8032 Section 7.1 — Ed25519 Known-Answer Tests.
//!
//! Verifies that `ring::signature::Ed25519KeyPair` produces correct
//! public keys and signatures for the RFC 8032 test vectors.

use ring::signature::{self, Ed25519KeyPair, KeyPair};

/// RFC 8032 Section 7.1, Test Vector #1 (empty message).
///
/// Seed → public key derivation and signing are verified against
/// the published reference values.
#[test]
fn rfc8032_test_vector_1_empty_message() {
    // Seed (private key, 32 bytes)
    let seed = hex_to_bytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");

    // Expected public key (32 bytes)
    let expected_pk =
        hex_to_bytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");

    // Expected signature (64 bytes) over the empty message
    let expected_sig = hex_to_bytes(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
         5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    );

    let message: &[u8] = b""; // empty message

    // 1. Verify seed → public key derivation
    let key_pair = Ed25519KeyPair::from_seed_unchecked(&seed).expect("seed should be valid");
    assert_eq!(
        key_pair.public_key().as_ref(),
        expected_pk.as_slice(),
        "derived public key must match RFC 8032 expected value"
    );

    // 2. Verify signature matches expected value
    let sig = key_pair.sign(message);
    assert_eq!(
        sig.as_ref(),
        expected_sig.as_slice(),
        "Ed25519 signature must match RFC 8032 expected value"
    );

    // 3. Verify signature verifies against expected public key
    let pk = signature::UnparsedPublicKey::new(&signature::ED25519, &expected_pk);
    pk.verify(message, sig.as_ref())
        .expect("signature must verify with expected public key");
}

/// RFC 8032 Section 7.1, Test Vector #2 (single byte `0x72`).
///
/// Verifies sign + verify with a non-empty message.
#[test]
fn rfc8032_test_vector_2_single_byte() {
    let seed = hex_to_bytes("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");

    let expected_pk =
        hex_to_bytes("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");

    let expected_sig = hex_to_bytes(
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
         085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    );

    let message: &[u8] = &[0x72];

    let key_pair = Ed25519KeyPair::from_seed_unchecked(&seed).expect("seed should be valid");
    assert_eq!(
        key_pair.public_key().as_ref(),
        expected_pk.as_slice(),
        "derived public key must match RFC 8032 expected value"
    );

    let sig = key_pair.sign(message);
    assert_eq!(
        sig.as_ref(),
        expected_sig.as_slice(),
        "Ed25519 signature must match RFC 8032 expected value"
    );

    let pk = signature::UnparsedPublicKey::new(&signature::ED25519, &expected_pk);
    pk.verify(message, sig.as_ref())
        .expect("signature must verify with expected public key");
}

/// Verify that Ed25519 signing is deterministic.
#[test]
fn ed25519_signing_is_deterministic() {
    let seed = hex_to_bytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let message = b"determinism test";

    let kp1 = Ed25519KeyPair::from_seed_unchecked(&seed).expect("keygen");
    let kp2 = Ed25519KeyPair::from_seed_unchecked(&seed).expect("keygen");

    let sig1 = kp1.sign(message);
    let sig2 = kp2.sign(message);

    assert_eq!(
        sig1.as_ref(),
        sig2.as_ref(),
        "Ed25519 must produce identical signatures for same seed+message"
    );
}

/// Decode a hex string to bytes.
#[allow(clippy::arithmetic_side_effects)]
fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
        .collect()
}
