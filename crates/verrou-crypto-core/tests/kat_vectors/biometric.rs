//! Known-Answer-Test for biometric HKDF-SHA256 wrapping-key derivation.
//!
//! Verifies that `derive_biometric_wrapping_key` with a fixed 32-byte token
//! and the domain constants:
//!   - salt = `b"verrou-biometric-v1"`
//!   - info = `b"slot-wrapping-key"`
//!
//! produces the exact same 32-byte output at every build.  Any future change
//! to the salt, info string, HKDF variant, or output length will break this
//! assertion and force a deliberate, reviewed update of the pinned vector.
//!
//! # Input
//! Fixed token: `[0x42; 32]` (all-`B` bytes — chosen for human readability).
//!
//! # Pinned vector (captured 2026-05-30 against ring 0.17 HKDF-SHA256)
//! ```text
//! 00 e2 e9 28 b8 1d c0 1b  a3 9d ab 1b 38 bf 4a 63
//! 19 64 43 d7 da c9 f6 bc  e6 5f 06 82 0e d9 63 c7
//! ```

use verrou_crypto_core::biometric::derive_biometric_wrapping_key;

/// KAT: HKDF-SHA256(ikm = [0x42;32], salt = "verrou-biometric-v1",
///                  info = "slot-wrapping-key") → pinned 32-byte vector.
///
/// This pins the exact derivation output so that any silent change to the
/// biometric wrapping-key derivation (salt, info, algorithm) causes an
/// immediate test failure.
#[test]
fn biometric_hkdf_wrapping_key_kat() {
    // Fixed high-entropy token (all-0x42 = 'B').  Deterministic input.
    let token = [0x42_u8; 32];

    let key = derive_biometric_wrapping_key(&token)
        .expect("HKDF derivation of a 32-byte token must succeed");

    // Pinned vector — DO NOT change without a security review.
    // Re-derive by running the biometric crate tests with `-- --nocapture`
    // after any intentional change.
    let expected: [u8; 32] = [
        0x00, 0xe2, 0xe9, 0x28, 0xb8, 0x1d, 0xc0, 0x1b, 0xa3, 0x9d, 0xab, 0x1b, 0x38, 0xbf, 0x4a,
        0x63, 0x19, 0x64, 0x43, 0xd7, 0xda, 0xc9, 0xf6, 0xbc, 0xe6, 0x5f, 0x06, 0x82, 0x0e, 0xd9,
        0x63, 0xc7,
    ];

    assert_eq!(
        key.expose(),
        &expected,
        "biometric HKDF-SHA256 output changed — verify intentional and update the pinned vector"
    );
}

/// Sanity: a different token must yield a different output (confirms the KAT
/// token is not accidentally hitting a degenerate path).
#[test]
fn biometric_hkdf_different_token_differs_from_kat() {
    let kat_token = [0x42_u8; 32];
    let other_token = [0xff_u8; 32];

    let kat_key = derive_biometric_wrapping_key(&kat_token).expect("KAT derivation must succeed");
    let other_key =
        derive_biometric_wrapping_key(&other_token).expect("alternative derivation must succeed");

    assert_ne!(
        kat_key.expose(),
        other_key.expose(),
        "different tokens must produce different wrapping keys"
    );
}
