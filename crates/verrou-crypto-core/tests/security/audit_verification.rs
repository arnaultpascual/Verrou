//! Phase 5 — Security audit verification tests.
//!
//! These tests validate the security properties identified during the
//! comprehensive 5-phase security audit of `verrou-crypto-core`.
//!
//! Each test corresponds to a specific audit finding and is designed to
//! prevent regressions in critical cryptographic invariants:
//!
//! 1. AAD domain separation prevents cross-context decryption
//! 2. Ciphertext does not contain plaintext substrings
//! 3. Rapid encryptions produce unique nonces (no reuse)
//! 4. Slot cross-type confusion rejected by AAD mismatch
//! 5. Hybrid KEM: both components contribute to shared secret
//! 6. KDF avalanche effect — single bit change produces ~50% bit difference
//! 7. SecretBuffer/SecretBytes debug output never leaks content
//! 8. Truncated ciphertext is rejected
//! 9. Single bit-flip in ciphertext is detected by GCM tag

use std::collections::HashSet;
use verrou_crypto_core::kdf::Argon2idParams;
use verrou_crypto_core::kem::{decapsulate, encapsulate, generate_keypair};
use verrou_crypto_core::memory::{SecretBuffer, SecretBytes};
use verrou_crypto_core::slots::{
    create_slot, unwrap_slot, KeySlot, SlotType, MASTER_KEY_LEN, WRAPPING_KEY_LEN,
};
use verrou_crypto_core::symmetric::{self, SealedData};

/// Fixed test key — 32 bytes of 0xAA.
const TEST_KEY: [u8; 32] = [0xAA; 32];

/// Small Argon2id params for fast tests — 32 KiB, 1 iteration, 1 lane.
const FAST_PARAMS: Argon2idParams = Argon2idParams {
    m_cost: 32,
    t_cost: 1,
    p_cost: 1,
};

const SALT_A: &[u8; 16] = b"audit_salt_aaaaa";
const SALT_B: &[u8; 16] = b"audit_salt_bbbbb";

// ═══════════════════════════════════════════════════════════════════════════
// Test 1: AAD domain separation prevents cross-context decryption
// ═══════════════════════════════════════════════════════════════════════════

/// Encrypt with one AAD, decrypt with a different AAD — must fail.
///
/// This validates that domain-separated AAD tags (e.g., "verrou-entry-aad",
/// "verrou-attachment-aad") prevent ciphertext from being decrypted in
/// a different context, even with the correct key.
#[test]
fn aad_domain_separation_prevents_cross_context_decryption() {
    let plaintext = b"sensitive entry data";
    let aad_entry = b"verrou-entry-aad";
    let aad_attachment = b"verrou-attachment-aad";

    let sealed =
        symmetric::encrypt(plaintext, &TEST_KEY, aad_entry).expect("encrypt should succeed");

    // Same key, same ciphertext, but wrong AAD → must fail.
    let result = symmetric::decrypt(&sealed, &TEST_KEY, aad_attachment);
    assert!(
        result.is_err(),
        "cross-context AAD decryption must fail — domain separation violated"
    );

    // Correct AAD → must succeed.
    let decrypted = symmetric::decrypt(&sealed, &TEST_KEY, aad_entry)
        .expect("correct AAD decryption should succeed");
    assert_eq!(decrypted.expose(), plaintext);
}

/// All 7 VERROU domain AAD tags must produce distinct ciphertexts.
///
/// Even with identical plaintext and key, different AAD tags must produce
/// ciphertexts that cannot be cross-decrypted.
#[test]
fn all_aad_tags_are_mutually_incompatible() {
    let aad_tags: &[&[u8]] = &[
        b"verrou-entry-aad",
        b"verrou-attachment-aad",
        b"verrou-slot-password",
        b"verrou-slot-biometric",
        b"verrou-slot-recovery",
        b"verrou-slot-hardware",
        b"VERROU-HYBRID-KEM-v1",
    ];

    let plaintext = b"cross-tag test data";

    for (i, &encrypt_aad) in aad_tags.iter().enumerate() {
        let sealed =
            symmetric::encrypt(plaintext, &TEST_KEY, encrypt_aad).expect("encrypt should succeed");

        for (j, &decrypt_aad) in aad_tags.iter().enumerate() {
            let result = symmetric::decrypt(&sealed, &TEST_KEY, decrypt_aad);
            if i == j {
                assert!(
                    result.is_ok(),
                    "same AAD tag must decrypt successfully (tag index {i})"
                );
            } else {
                assert!(
                    result.is_err(),
                    "cross-AAD decryption must fail: encrypt with tag[{i}], decrypt with tag[{j}]"
                );
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 2: Ciphertext does not contain plaintext substrings
// ═══════════════════════════════════════════════════════════════════════════

/// The ciphertext must not contain any recognizable substring of the plaintext.
///
/// AES-256-GCM is a stream cipher mode — even a single repeated byte at the
/// same position would indicate a nonce reuse or implementation bug.
#[test]
fn ciphertext_does_not_contain_plaintext_substring() {
    // Use a distinctive, long plaintext with recognizable patterns.
    let plaintext = b"THIS_IS_A_VERY_DISTINCTIVE_PLAINTEXT_PATTERN_ABCDEFGHIJKLMNOP";

    let sealed =
        symmetric::encrypt(plaintext, &TEST_KEY, b"audit-test").expect("encrypt should succeed");

    // Check that no 8-byte window from the plaintext appears in the ciphertext.
    for window in plaintext.windows(8) {
        assert!(
            !sealed.ciphertext.windows(8).any(|w| w == window),
            "plaintext substring found in ciphertext — encryption may be broken"
        );
    }

    // Also verify the entire plaintext doesn't appear.
    assert!(
        !sealed
            .ciphertext
            .windows(plaintext.len())
            .any(|w| w == plaintext.as_slice()),
        "full plaintext found verbatim in ciphertext"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 3: Rapid encryptions produce unique nonces (1000 iterations)
// ═══════════════════════════════════════════════════════════════════════════

/// 1000 rapid encryptions must produce 1000 unique nonces.
///
/// AES-256-GCM security relies on nonce uniqueness. A repeated nonce with
/// the same key catastrophically breaks confidentiality (XOR of plaintexts).
/// With 96-bit random nonces, P(collision) ≈ 2^-56 for 1000 samples.
#[test]
fn rapid_encryptions_produce_unique_nonces() {
    let mut nonces = HashSet::new();

    for _ in 0..1000 {
        let sealed =
            symmetric::encrypt(b"nonce test", &TEST_KEY, b"audit").expect("encrypt should succeed");
        let inserted = nonces.insert(sealed.nonce);
        assert!(
            inserted,
            "nonce collision detected in 1000 encryptions — CSPRNG may be broken"
        );
    }

    assert_eq!(nonces.len(), 1000);
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 4: Slot cross-type confusion rejected
// ═══════════════════════════════════════════════════════════════════════════

/// A slot created with one `SlotType` must not unwrap when presented as another.
///
/// This validates the domain separation enforced by `SlotType::aad_tag()`.
/// All 4×3 = 12 cross-type combinations must fail.
#[test]
fn slot_cross_type_confusion_rejected_all_combinations() {
    let master_key = [0xAA; MASTER_KEY_LEN];
    let wrapping_key = [0xBB; WRAPPING_KEY_LEN];

    let slot_types = [
        SlotType::Password,
        SlotType::Biometric,
        SlotType::Recovery,
        SlotType::HardwareSecurity,
    ];

    for &create_type in &slot_types {
        let slot = create_slot(&master_key, &wrapping_key, create_type)
            .expect("create_slot should succeed");

        for &unwrap_type in &slot_types {
            // Forge the slot with a different type.
            let test_slot = KeySlot {
                slot_type: unwrap_type,
                wrapped_key: slot.wrapped_key.clone(),
            };

            let result = unwrap_slot(&test_slot, &wrapping_key);
            if create_type == unwrap_type {
                let unwrapped = result.expect("same-type unwrap should succeed");
                assert_eq!(
                    unwrapped.expose(),
                    &master_key,
                    "unwrapped master key must match original"
                );
            } else {
                assert!(
                    result.is_err(),
                    "cross-type unwrap must fail: created as {create_type:?}, unwrapped as {unwrap_type:?}"
                );
            }
        }
    }
}

/// Each `SlotType` has a distinct AAD tag — no two types share the same tag.
#[test]
fn slot_type_aad_tags_are_all_distinct() {
    let types = [
        SlotType::Password,
        SlotType::Biometric,
        SlotType::Recovery,
        SlotType::HardwareSecurity,
    ];

    let mut tags: HashSet<&[u8]> = HashSet::new();
    for t in &types {
        let tag = t.aad_tag();
        assert!(
            tags.insert(tag),
            "duplicate AAD tag found for {:?}: {:?}",
            t,
            std::str::from_utf8(tag)
        );
    }

    assert_eq!(tags.len(), types.len());
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 5: Hybrid KEM — both components contribute to shared secret
// ═══════════════════════════════════════════════════════════════════════════

/// Tampering with either KEM component must change the shared secret.
///
/// This validates the hybrid security guarantee: both X25519 and ML-KEM-1024
/// must contribute to the final HKDF output. If either component is
/// tampered, the resulting shared secret must differ.
#[test]
fn hybrid_kem_both_components_contribute() {
    let kp = generate_keypair().expect("keygen should succeed");
    let (ct, ss_original) = encapsulate(&kp.public).expect("encapsulate should succeed");

    // Tamper X25519 ephemeral public key → different DH → different HKDF output.
    let mut ct_x25519_tampered = ct.clone();
    ct_x25519_tampered.x25519_public[0] ^= 0xFF;
    let ss_x25519_tampered = decapsulate(&ct_x25519_tampered, &kp.private)
        .expect("decapsulate with tampered X25519 should succeed (no auth failure)");
    assert_ne!(
        ss_original.expose(),
        ss_x25519_tampered.expose(),
        "tampering X25519 component must change the shared secret"
    );

    // Tamper ML-KEM ciphertext → implicit rejection → different HKDF output.
    let mut ct_mlkem_tampered = ct.clone();
    ct_mlkem_tampered.ml_kem_ciphertext[0] ^= 0xFF;
    let ss_mlkem_tampered = decapsulate(&ct_mlkem_tampered, &kp.private)
        .expect("decapsulate with tampered ML-KEM should succeed (implicit rejection)");
    assert_ne!(
        ss_original.expose(),
        ss_mlkem_tampered.expose(),
        "tampering ML-KEM component must change the shared secret"
    );

    // Both tampered → must differ from original AND from each individual tamper.
    let mut ct_both_tampered = ct;
    ct_both_tampered.x25519_public[0] ^= 0xFF;
    ct_both_tampered.ml_kem_ciphertext[0] ^= 0xFF;
    let ss_both_tampered = decapsulate(&ct_both_tampered, &kp.private)
        .expect("decapsulate with both tampered should succeed");
    assert_ne!(ss_original.expose(), ss_both_tampered.expose());
    assert_ne!(ss_x25519_tampered.expose(), ss_both_tampered.expose());
    assert_ne!(ss_mlkem_tampered.expose(), ss_both_tampered.expose());
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 6: KDF avalanche effect
// ═══════════════════════════════════════════════════════════════════════════

/// A single-bit difference in the password must cause ~50% bit difference
/// in the derived key (avalanche effect).
///
/// For Argon2id (or any good KDF), changing 1 bit of input should flip
/// approximately half the output bits. We accept 30%-70% (strict bounds).
#[test]
fn kdf_avalanche_effect_single_bit_change() {
    let password_a = b"avalanche_test_password!";
    let mut password_b = *password_a;
    // Flip one bit in the first byte.
    password_b[0] ^= 0x01;

    let key_a = verrou_crypto_core::kdf::derive(password_a, SALT_A, &FAST_PARAMS)
        .expect("KDF should succeed");
    let key_b = verrou_crypto_core::kdf::derive(&password_b, SALT_A, &FAST_PARAMS)
        .expect("KDF should succeed");

    // Count differing bits (Hamming distance).
    let hamming: u32 = key_a
        .expose()
        .iter()
        .zip(key_b.expose().iter())
        .map(|(&a, &b)| (a ^ b).count_ones())
        .sum();

    // 256 total bits → expect ~128 flipped (50%).
    // Accept 30%-70% (77-179 bits) as a generous but meaningful bound.
    let total_bits: u32 = 256;
    let min_expected = total_bits * 30 / 100; // 76.8 → 76
    let max_expected = total_bits * 70 / 100; // 179.2 → 179

    assert!(
        hamming >= min_expected && hamming <= max_expected,
        "KDF avalanche: {hamming}/{total_bits} bits differ ({:.1}%) — expected 30%-70%",
        f64::from(hamming) / f64::from(total_bits) * 100.0
    );
}

/// Different salts with the same password must produce completely different keys.
#[test]
fn kdf_different_salts_produce_independent_keys() {
    let key_a = verrou_crypto_core::kdf::derive(b"same_password", SALT_A, &FAST_PARAMS)
        .expect("KDF should succeed");
    let key_b = verrou_crypto_core::kdf::derive(b"same_password", SALT_B, &FAST_PARAMS)
        .expect("KDF should succeed");

    assert_ne!(key_a.expose(), key_b.expose());

    // Also verify avalanche — >25% of bits should differ.
    let hamming: u32 = key_a
        .expose()
        .iter()
        .zip(key_b.expose().iter())
        .map(|(&a, &b)| (a ^ b).count_ones())
        .sum();
    assert!(
        hamming > 64,
        "salt change produced too few bit differences: {hamming}/256"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 7: SecretBuffer/SecretBytes debug masking
// ═══════════════════════════════════════════════════════════════════════════

/// Debug and Display output must never contain raw byte values.
///
/// This prevents accidental leakage through logging, error messages,
/// or debug output. Tests all secret container types.
#[test]
fn secret_containers_debug_never_leaks_content() {
    // SecretBuffer with known content.
    let data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
    let buf = SecretBuffer::new(&data).expect("allocation should succeed");
    let debug = format!("{buf:?}");
    let display = format!("{buf}");
    assert_eq!(debug, "SecretBuffer(***)");
    assert_eq!(display, "SecretBuffer(***)");
    assert!(!debug.contains("de") && !debug.contains("DE"));
    assert!(!debug.contains("cafe") && !debug.contains("CAFE"));

    // SecretBytes with known content.
    let key = SecretBytes::<32>::new([0xFF; 32]);
    let debug = format!("{key:?}");
    let display = format!("{key}");
    assert_eq!(debug, "SecretBytes<32>(***)");
    assert_eq!(display, "SecretBytes<32>(***)");
    assert!(!debug.contains("ff") && !debug.contains("FF"));
    assert!(!debug.contains("255"));
}

/// Different secret contents produce identical debug output.
///
/// An attacker observing debug output must not be able to distinguish
/// between different secret values.
#[test]
fn secret_debug_is_content_independent() {
    let buf_a = SecretBuffer::new(&[0x00; 64]).expect("allocation should succeed");
    let buf_b = SecretBuffer::new(&[0xFF; 64]).expect("allocation should succeed");
    let buf_c =
        SecretBuffer::new(b"completely different content").expect("allocation should succeed");

    assert_eq!(format!("{buf_a:?}"), format!("{buf_b:?}"));
    assert_eq!(format!("{buf_b:?}"), format!("{buf_c:?}"));
    assert_eq!(format!("{buf_a}"), format!("{buf_c}"));
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 8: Truncated ciphertext is rejected
// ═══════════════════════════════════════════════════════════════════════════

/// Truncated ciphertext (missing bytes) must be rejected.
///
/// Tests multiple truncation points: empty, half, missing tag, missing
/// last byte. All must fail with a decryption error.
#[test]
fn truncated_ciphertext_rejected() {
    let plaintext = b"truncation test data for audit verification";
    let sealed =
        symmetric::encrypt(plaintext, &TEST_KEY, b"audit").expect("encrypt should succeed");

    let full_bytes = sealed.to_bytes();

    // Empty input.
    assert!(
        SealedData::from_bytes(&[]).is_err(),
        "empty ciphertext must be rejected"
    );

    // Just the nonce (12 bytes), no ciphertext or tag.
    assert!(
        SealedData::from_bytes(&full_bytes[..12]).is_err(),
        "nonce-only input must be rejected"
    );

    // Nonce + partial tag (27 bytes < minimum 28).
    assert!(
        SealedData::from_bytes(&full_bytes[..27]).is_err(),
        "truncated input below minimum must be rejected"
    );

    // Full structure but with truncated ciphertext — should parse but fail to decrypt.
    if full_bytes.len() > 29 {
        // Remove one byte from the middle of the ciphertext.
        let mut tampered = full_bytes[..12].to_vec(); // nonce
        tampered.extend_from_slice(&full_bytes[12..full_bytes.len() - 17]); // ciphertext minus 1
        tampered.extend_from_slice(&full_bytes[full_bytes.len() - 16..]); // tag
        let parsed = SealedData::from_bytes(&tampered);
        if let Ok(parsed_sealed) = parsed {
            let result = symmetric::decrypt(&parsed_sealed, &TEST_KEY, b"audit");
            assert!(
                result.is_err(),
                "truncated ciphertext should fail authentication"
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 9: Single bit-flip detection
// ═══════════════════════════════════════════════════════════════════════════

/// A single bit-flip in any byte of the ciphertext must be detected.
///
/// AES-256-GCM provides 128-bit authentication. Flipping any bit in the
/// nonce, ciphertext, or tag must cause decryption to fail.
#[test]
fn single_bit_flip_detected_in_ciphertext() {
    let plaintext = b"bit flip detection test data";
    let sealed =
        symmetric::encrypt(plaintext, &TEST_KEY, b"audit").expect("encrypt should succeed");

    // Flip each bit in the ciphertext portion.
    for byte_idx in 0..sealed.ciphertext.len() {
        for bit_pos in 0..8u8 {
            let mut tampered = sealed.clone();
            tampered.ciphertext[byte_idx] ^= 1 << bit_pos;
            let result = symmetric::decrypt(&tampered, &TEST_KEY, b"audit");
            assert!(
                result.is_err(),
                "bit flip at ciphertext[{byte_idx}] bit {bit_pos} was not detected"
            );
        }
    }
}

/// A single bit-flip in any byte of the authentication tag must be detected.
#[test]
fn single_bit_flip_detected_in_tag() {
    let plaintext = b"tag bit flip test";
    let sealed =
        symmetric::encrypt(plaintext, &TEST_KEY, b"audit").expect("encrypt should succeed");

    for byte_idx in 0..sealed.tag.len() {
        for bit_pos in 0..8u8 {
            let mut tampered = sealed.clone();
            tampered.tag[byte_idx] ^= 1 << bit_pos;
            let result = symmetric::decrypt(&tampered, &TEST_KEY, b"audit");
            assert!(
                result.is_err(),
                "bit flip at tag[{byte_idx}] bit {bit_pos} was not detected"
            );
        }
    }
}

/// A single bit-flip in any byte of the nonce must be detected.
#[test]
fn single_bit_flip_detected_in_nonce() {
    let plaintext = b"nonce bit flip test";
    let sealed =
        symmetric::encrypt(plaintext, &TEST_KEY, b"audit").expect("encrypt should succeed");

    for byte_idx in 0..sealed.nonce.len() {
        for bit_pos in 0..8u8 {
            let mut tampered = sealed.clone();
            tampered.nonce[byte_idx] ^= 1 << bit_pos;
            let result = symmetric::decrypt(&tampered, &TEST_KEY, b"audit");
            assert!(
                result.is_err(),
                "bit flip at nonce[{byte_idx}] bit {bit_pos} was not detected"
            );
        }
    }
}
