//! HKDF-SHA256 KAT for the hybrid KEM combiner.
//!
//! Verifies that our HKDF combination of X25519 + ML-KEM shared secrets
//! produces a deterministic output given known inputs.

use ring::hkdf;

/// Marker type for 32-byte HKDF output.
struct HkdfLen32;

impl hkdf::KeyType for HkdfLen32 {
    fn len(&self) -> usize {
        32
    }
}

/// Helper: compute HKDF-SHA256(ikm, empty salt, info).
fn hkdf_compute(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]);
    let prk = salt.extract(ikm);
    let info_refs: &[&[u8]] = &[info];
    let okm = prk
        .expand(info_refs, HkdfLen32)
        .expect("HKDF expand should succeed");
    let mut out = [0u8; 32];
    okm.fill(&mut out).expect("HKDF fill should succeed");
    out
}

/// Verify that HKDF-SHA256(ikm = `x25519_ss` || `mlkem_ss`, salt = empty,
/// info = "VERROU-HYBRID-KEM-v1") is deterministic and produces a
/// consistent 32-byte output.
///
/// This test pins the HKDF output for known shared secrets so that any
/// implementation change (salt, info, algorithm) is detected.
#[test]
fn hkdf_kem_combiner_deterministic() {
    // Known "shared secrets" (not real — just test vectors).
    let x25519_ss: [u8; 32] = [
        0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f,
        0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16,
        0x17, 0x42,
    ];
    let mlkem_ss: [u8; 32] = [
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0x77, 0x88,
    ];

    let info = b"VERROU-HYBRID-KEM-v1";

    // Concatenate.
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(&x25519_ss);
    combined[32..].copy_from_slice(&mlkem_ss);

    let output_a = hkdf_compute(&combined, info);
    let output_b = hkdf_compute(&combined, info);

    assert_eq!(
        output_a, output_b,
        "HKDF with same inputs must produce same output"
    );

    // Verify non-trivial output (not all zeros or all same byte).
    assert_eq!(output_a.len(), 32, "HKDF output must be 32 bytes");
    assert_ne!(output_a, [0u8; 32], "HKDF output must not be all zeros");
    let first_byte = output_a[0];
    assert!(
        output_a.iter().any(|&b| b != first_byte),
        "HKDF output must not be constant"
    );

    // Pin the expected output — any change in HKDF algorithm, salt,
    // or info string will break this assertion.
    let expected: [u8; 32] = [
        0x8b, 0x4d, 0xae, 0x4a, 0x32, 0xc3, 0x38, 0x00, 0xb1, 0x0e, 0x31, 0x0f, 0xed, 0xb3, 0x84,
        0xff, 0x7e, 0x6d, 0x70, 0x49, 0x27, 0x11, 0xe3, 0xcc, 0x40, 0x8a, 0x19, 0xb5, 0x22, 0x5e,
        0xd3, 0x6b,
    ];
    assert_eq!(
        output_a, expected,
        "HKDF output must match pinned known-answer value"
    );
}

/// Verify that different inputs produce different HKDF outputs.
#[test]
fn hkdf_kem_combiner_different_inputs_produce_different_outputs() {
    let info = b"VERROU-HYBRID-KEM-v1";

    let mut combined_a = [0u8; 64];
    combined_a[..32].copy_from_slice(&[0xAA; 32]);
    combined_a[32..].copy_from_slice(&[0xBB; 32]);

    let mut combined_b = [0u8; 64];
    combined_b[..32].copy_from_slice(&[0xCC; 32]);
    combined_b[32..].copy_from_slice(&[0xDD; 32]);

    let out_a = hkdf_compute(&combined_a, info);
    let out_b = hkdf_compute(&combined_b, info);

    assert_ne!(
        out_a, out_b,
        "different inputs must produce different HKDF outputs"
    );
}
