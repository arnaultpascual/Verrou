//! NIST SP 800-38D — AES-256-GCM Known-Answer Test vectors.
//!
//! These tests verify the `ring` crate's AES-256-GCM implementation against
//! official NIST test vectors (GCMEncryptExtIV256.rsp), and verify our
//! `encrypt()`/`decrypt()` wrapper roundtrip integrity.

use ring::aead;
use verrou_crypto_core::symmetric::{decrypt, encrypt, SealedData, KEY_LEN, NONCE_LEN, TAG_LEN};

/// NIST SP 800-38D Test Case 14 — AES-256-GCM with plaintext (no AAD).
///
/// Key:     0000...0000 (32 bytes)
/// IV:      0000...0000 (12 bytes)
/// PT:      0000...0000 (16 bytes)
/// AAD:     (empty)
/// CT:      cea7403d4d606b6e074ec5d3baf39d18
/// Tag:     d0d1c8a799996bf0265b98b5d48ab919
#[test]
fn nist_test_case_14_aes256_gcm() {
    let key = [0u8; 32];
    let nonce_bytes = [0u8; 12];
    let plaintext = [0u8; 16];

    let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, &key).expect("key should be valid");
    let less_safe_key = aead::LessSafeKey::new(unbound);

    let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
    let mut in_out = plaintext.to_vec();
    let tag = less_safe_key
        .seal_in_place_separate_tag(nonce, aead::Aad::empty(), &mut in_out)
        .expect("seal should succeed");

    let expected_ct: [u8; 16] = [
        0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e, 0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d,
        0x18,
    ];
    let expected_tag: [u8; 16] = [
        0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0, 0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a, 0xb9,
        0x19,
    ];

    assert_eq!(
        in_out.as_slice(),
        &expected_ct,
        "NIST Test Case 14 ciphertext mismatch"
    );
    assert_eq!(
        tag.as_ref(),
        &expected_tag,
        "NIST Test Case 14 tag mismatch"
    );

    // Verify decryption roundtrip via LessSafeKey.
    let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
    let mut ct_tag = in_out.clone();
    ct_tag.extend_from_slice(tag.as_ref());
    let decrypted = less_safe_key
        .open_in_place(nonce, aead::Aad::empty(), &mut ct_tag)
        .expect("open should succeed");
    assert_eq!(decrypted, &plaintext);
}

/// NIST SP 800-38D Test Case 16 — AES-256-GCM with plaintext AND AAD.
///
/// Key:     feffe9928665731c6d6a8f9467308308
///          feffe9928665731c6d6a8f9467308308
/// IV:      cafebabefacedbaddecaf888
/// PT:      d9313225f88406e5a55909c5aff5269a
///          86a7a9531534f7da2e4c303d8a318a72
///          1c3c0c95956809532fcf0e2449a6b525
///          b16aedf5aa0de657ba637b39
/// AAD:     feedfacedeadbeeffeedfacedeadbeef
///          abaddad2
/// CT:      522dc1f099567d07f47f37a32a84427d
///          643a8cdcbfe5c0c97598a2bd2555d1aa
///          8cb08e48590dbb3da7b08b1056828838
///          c5f61e6393ba7a0abcc9f662
/// Tag:     76fc6ece0f4e1768cddf8853bb2d551b
#[test]
fn nist_test_case_16_aes256_gcm_with_aad() {
    let key: [u8; 32] = [
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83,
        0x08, 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30,
        0x83, 0x08,
    ];
    let nonce_bytes: [u8; 12] = [
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
    ];
    let plaintext: [u8; 60] = [
        0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26,
        0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31,
        0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49,
        0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39,
    ];
    let aad: [u8; 20] = [
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe,
        0xef, 0xab, 0xad, 0xda, 0xd2,
    ];

    let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, &key).expect("key should be valid");
    let less_safe_key = aead::LessSafeKey::new(unbound);

    let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
    let mut in_out = plaintext.to_vec();
    let tag = less_safe_key
        .seal_in_place_separate_tag(nonce, aead::Aad::from(&aad[..]), &mut in_out)
        .expect("seal should succeed");

    let expected_ct: [u8; 60] = [
        0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07, 0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42,
        0x7d, 0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9, 0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55,
        0xd1, 0xaa, 0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d, 0xa7, 0xb0, 0x8b, 0x10, 0x56,
        0x82, 0x88, 0x38, 0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a, 0xbc, 0xc9, 0xf6, 0x62,
    ];
    let expected_tag: [u8; 16] = [
        0x76, 0xfc, 0x6e, 0xce, 0x0f, 0x4e, 0x17, 0x68, 0xcd, 0xdf, 0x88, 0x53, 0xbb, 0x2d, 0x55,
        0x1b,
    ];

    assert_eq!(
        in_out.as_slice(),
        &expected_ct,
        "NIST Test Case 16 ciphertext mismatch"
    );
    assert_eq!(
        tag.as_ref(),
        &expected_tag,
        "NIST Test Case 16 tag mismatch"
    );
}

/// Verify our `encrypt()`/`decrypt()` wrapper roundtrip is correct
/// (uses random nonce, so not a KAT — but proves wrapper integrity).
#[test]
fn wrapper_encrypt_decrypt_roundtrip_kat() {
    let key = [0x42u8; KEY_LEN];
    let plaintext = b"NIST AES-GCM wrapper verification";
    let aad = b"story-1.4-kat";

    let sealed = encrypt(plaintext, &key, aad).expect("encrypt should succeed");

    // Verify sealed data structure.
    assert_eq!(sealed.nonce.len(), NONCE_LEN);
    assert_eq!(sealed.tag.len(), TAG_LEN);
    assert_eq!(sealed.ciphertext.len(), plaintext.len());
    // Ciphertext should not be the same as plaintext.
    assert_ne!(sealed.ciphertext.as_slice(), plaintext.as_slice());

    let decrypted = decrypt(&sealed, &key, aad).expect("decrypt should succeed");
    assert_eq!(decrypted.expose(), plaintext);
}

/// Verify `SealedData` wire format: `to_bytes` → `from_bytes` → decrypt.
#[test]
fn wrapper_sealed_data_wire_format_roundtrip() {
    let key = [0x55u8; KEY_LEN];
    let plaintext = b"wire format verification data";

    let sealed = encrypt(plaintext, &key, &[]).expect("encrypt should succeed");
    let wire = sealed.to_bytes();

    // Wire format should be nonce || ciphertext || tag.
    assert_eq!(wire.len(), NONCE_LEN + plaintext.len() + TAG_LEN);

    let restored = SealedData::from_bytes(&wire).expect("from_bytes should succeed");
    let decrypted = decrypt(&restored, &key, &[]).expect("decrypt should succeed");
    assert_eq!(decrypted.expose(), plaintext);
}
