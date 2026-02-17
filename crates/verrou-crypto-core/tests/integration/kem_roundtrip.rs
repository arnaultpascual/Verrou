//! Integration tests for the hybrid KEM module.
//!
//! Tests full hybrid KEM roundtrips with realistic key sizes and
//! verifies that all outputs conform to the expected types.

use verrou_crypto_core::kem;

/// Full hybrid KEM roundtrip: generate → encapsulate → decapsulate.
#[test]
fn full_hybrid_kem_roundtrip() {
    let kp = kem::generate_keypair().expect("keygen should succeed");

    // Verify key sizes.
    assert_eq!(kp.public.x25519.len(), kem::X25519_PUBLIC_KEY_LEN);
    assert_eq!(kp.public.ml_kem.len(), kem::ML_KEM_PUBLIC_KEY_LEN);

    // Encapsulate.
    let (ct, ss_enc) = kem::encapsulate(&kp.public).expect("encapsulate should succeed");

    // Verify ciphertext sizes.
    assert_eq!(ct.x25519_public.len(), kem::X25519_PUBLIC_KEY_LEN);
    assert_eq!(ct.ml_kem_ciphertext.len(), kem::ML_KEM_CIPHERTEXT_LEN);

    // Decapsulate.
    let ss_dec = kem::decapsulate(&ct, &kp.private).expect("decapsulate should succeed");

    // Shared secrets must match.
    assert_eq!(ss_enc.expose(), ss_dec.expose());
    assert_eq!(ss_enc.len(), kem::SHARED_SECRET_LEN);
}

/// Multiple roundtrips produce different shared secrets.
#[test]
fn multiple_roundtrips_produce_unique_secrets() {
    let kp = kem::generate_keypair().expect("keygen should succeed");

    let (ct_a, ss_a) = kem::encapsulate(&kp.public).expect("encapsulate should succeed");
    let (ct_b, ss_b) = kem::encapsulate(&kp.public).expect("encapsulate should succeed");

    // Different ciphertexts.
    assert_ne!(ct_a.x25519_public, ct_b.x25519_public);
    assert_ne!(ct_a.ml_kem_ciphertext, ct_b.ml_kem_ciphertext);

    // Different shared secrets.
    assert_ne!(ss_a.expose(), ss_b.expose());

    // Both decapsulate correctly.
    let dec_a = kem::decapsulate(&ct_a, &kp.private).expect("decapsulate a should succeed");
    let dec_b = kem::decapsulate(&ct_b, &kp.private).expect("decapsulate b should succeed");
    assert_eq!(ss_a.expose(), dec_a.expose());
    assert_eq!(ss_b.expose(), dec_b.expose());
}

/// Shared secret output is a `SecretBuffer` with masked debug.
#[test]
fn shared_secret_is_secret_buffer() {
    let kp = kem::generate_keypair().expect("keygen should succeed");
    let (_, ss) = kem::encapsulate(&kp.public).expect("encapsulate should succeed");
    let debug = format!("{ss:?}");
    assert_eq!(debug, "SecretBuffer(***)");
    assert!(!debug.contains("0x"));
}

/// Cross-key-pair encapsulation/decapsulation produces mismatched secrets.
#[test]
fn cross_keypair_decapsulation_fails() {
    let kp1 = kem::generate_keypair().expect("keygen 1 should succeed");
    let kp2 = kem::generate_keypair().expect("keygen 2 should succeed");

    let (ct, ss_enc) = kem::encapsulate(&kp1.public).expect("encapsulate should succeed");

    // Decapsulate with wrong key — ML-KEM implicit rejection returns a value,
    // but it won't match the original.
    let ss_wrong = kem::decapsulate(&ct, &kp2.private).expect("decapsulate should succeed");
    assert_ne!(ss_enc.expose(), ss_wrong.expose());
}
