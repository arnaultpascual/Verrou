//! ML-KEM-1024 deterministic tests.
//!
//! `libcrux-ml-kem` is formally verified via hax/F* against the FIPS 203
//! specification. These tests verify determinism: the same seed always
//! produces the same key pair and the same encapsulation randomness
//! always produces the same ciphertext + shared secret.

use libcrux_ml_kem::mlkem1024;

/// Verify ML-KEM-1024 key generation is deterministic — same seed produces
/// same key pair.
#[test]
fn ml_kem_1024_keygen_deterministic() {
    let seed = [0x42u8; 64];
    let kp_a = mlkem1024::generate_key_pair(seed);
    let kp_b = mlkem1024::generate_key_pair(seed);

    assert_eq!(
        kp_a.pk(),
        kp_b.pk(),
        "same seed must produce same public key"
    );
    assert_eq!(
        kp_a.sk(),
        kp_b.sk(),
        "same seed must produce same private key"
    );
}

/// Verify ML-KEM-1024 encapsulation is deterministic — same public key +
/// randomness produces same ciphertext and shared secret.
#[test]
fn ml_kem_1024_encaps_deterministic() {
    let seed = [0xAA; 64];
    let kp = mlkem1024::generate_key_pair(seed);

    let enc_rand = [0xBB; 32];
    let (ct_a, ss_a) = mlkem1024::encapsulate(kp.public_key(), enc_rand);
    let (ct_b, ss_b) = mlkem1024::encapsulate(kp.public_key(), enc_rand);

    assert_eq!(
        ct_a.as_ref(),
        ct_b.as_ref(),
        "same randomness must produce same ciphertext"
    );
    assert_eq!(
        ss_a, ss_b,
        "same randomness must produce same shared secret"
    );
}

/// Verify ML-KEM-1024 encapsulate → decapsulate roundtrip with deterministic
/// seed produces consistent shared secrets.
#[test]
fn ml_kem_1024_roundtrip_deterministic() {
    let seed = [0x55; 64];
    let kp = mlkem1024::generate_key_pair(seed);

    let enc_rand = [0x77; 32];
    let (ct, ss_encaps) = mlkem1024::encapsulate(kp.public_key(), enc_rand);
    let ss_decaps = mlkem1024::decapsulate(kp.private_key(), &ct);

    assert_eq!(
        ss_encaps, ss_decaps,
        "encapsulate and decapsulate must produce same shared secret"
    );
}

/// Verify ML-KEM-1024 key sizes match FIPS 203 constants.
#[test]
fn ml_kem_1024_key_sizes_match_fips_203() {
    let seed = [0x00; 64];
    let kp = mlkem1024::generate_key_pair(seed);

    assert_eq!(
        kp.pk().len(),
        1568,
        "ML-KEM-1024 public key must be 1568 bytes"
    );
    assert_eq!(
        kp.sk().len(),
        3168,
        "ML-KEM-1024 private key must be 3168 bytes"
    );

    let enc_rand = [0x11; 32];
    let (ct, ss) = mlkem1024::encapsulate(kp.public_key(), enc_rand);
    assert_eq!(
        ct.as_ref().len(),
        1568,
        "ML-KEM-1024 ciphertext must be 1568 bytes"
    );
    assert_eq!(ss.len(), 32, "ML-KEM-1024 shared secret must be 32 bytes");
}

/// Verify ML-KEM-1024 public key validation — valid key returns true.
#[test]
fn ml_kem_1024_validate_public_key_valid() {
    let seed = [0xCC; 64];
    let kp = mlkem1024::generate_key_pair(seed);
    assert!(
        mlkem1024::validate_public_key(kp.public_key()),
        "validly generated public key must pass validation"
    );
}

/// Verify ML-KEM-1024 public key validation — max-valued key returns false.
///
/// A public key where all coefficients are set to the maximum value (0xFF)
/// will exceed the modulus q=3329, failing the FIPS 203 validation check.
#[test]
fn ml_kem_1024_validate_public_key_invalid() {
    let maxed = mlkem1024::MlKem1024PublicKey::from([0xFF; 1568]);
    assert!(
        !mlkem1024::validate_public_key(&maxed),
        "max-valued public key must fail validation"
    );
}
