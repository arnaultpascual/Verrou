//! RFC 7748 Section 6.1 — X25519 Known-Answer Test vectors.
//!
//! These tests verify `x25519-dalek` against the official RFC 7748 test
//! vectors and confirm that our `StaticSecret` usage produces correct
//! shared secrets.

use x25519_dalek::{PublicKey, StaticSecret};

/// RFC 7748 Section 6.1 — Alice & Bob X25519 test vector.
///
/// ```text
/// Alice private: 77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a
/// Alice public:  8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a
/// Bob private:   5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb
/// Bob public:    de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f
/// Shared secret: 4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742
/// ```
#[test]
fn rfc7748_section_6_1_x25519() {
    let alice_private: [u8; 32] = [
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66,
        0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9,
        0x2c, 0x2a,
    ];
    let alice_public_expected: [u8; 32] = [
        0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7,
        0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b,
        0x4e, 0x6a,
    ];
    let bob_private: [u8; 32] = [
        0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e,
        0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88,
        0xe0, 0xeb,
    ];
    let bob_public_expected: [u8; 32] = [
        0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35,
        0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88,
        0x2b, 0x4f,
    ];
    let expected_shared_secret: [u8; 32] = [
        0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f,
        0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16,
        0x17, 0x42,
    ];

    // Reconstruct Alice's key pair.
    let alice_secret = StaticSecret::from(alice_private);
    let alice_public = PublicKey::from(&alice_secret);
    assert_eq!(
        alice_public.as_bytes(),
        &alice_public_expected,
        "Alice public key mismatch"
    );

    // Reconstruct Bob's key pair.
    let bob_secret = StaticSecret::from(bob_private);
    let bob_public = PublicKey::from(&bob_secret);
    assert_eq!(
        bob_public.as_bytes(),
        &bob_public_expected,
        "Bob public key mismatch"
    );

    // Alice computes shared secret: alice_private * bob_public.
    let alice_shared = alice_secret.diffie_hellman(&bob_public);
    assert_eq!(
        alice_shared.as_bytes(),
        &expected_shared_secret,
        "Alice shared secret mismatch"
    );

    // Bob computes shared secret: bob_private * alice_public.
    let bob_shared = bob_secret.diffie_hellman(&alice_public);
    assert_eq!(
        bob_shared.as_bytes(),
        &expected_shared_secret,
        "Bob shared secret mismatch"
    );

    // Both must produce the same shared secret.
    assert_eq!(
        alice_shared.as_bytes(),
        bob_shared.as_bytes(),
        "Alice and Bob shared secrets must match"
    );
}
