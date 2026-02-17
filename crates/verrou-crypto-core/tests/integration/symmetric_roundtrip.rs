//! Integration tests for AES-256-GCM encrypt→serialize→deserialize→decrypt.
//!
//! Tests realistic payload sizes and verifies `SecretBuffer` output properties.

use verrou_crypto_core::symmetric::{decrypt, encrypt, SealedData, KEY_LEN};

/// Integration key — 32 bytes.
const INT_KEY: [u8; KEY_LEN] = [0xDD; KEY_LEN];

#[test]
fn roundtrip_1kb_payload() {
    let plaintext = vec![0x42u8; 1024];
    let sealed = encrypt(&plaintext, &INT_KEY, &[]).expect("encrypt 1KB should succeed");
    let wire = sealed.to_bytes();
    let restored = SealedData::from_bytes(&wire).expect("from_bytes should succeed");
    let decrypted = decrypt(&restored, &INT_KEY, &[]).expect("decrypt should succeed");
    assert_eq!(decrypted.expose(), plaintext.as_slice());
}

#[test]
fn roundtrip_64kb_payload() {
    let plaintext = vec![0x55u8; 65_536];
    let sealed = encrypt(&plaintext, &INT_KEY, &[]).expect("encrypt 64KB should succeed");
    let json = serde_json::to_string(&sealed).expect("serialize should succeed");
    let deserialized: SealedData = serde_json::from_str(&json).expect("deserialize should succeed");
    let decrypted = decrypt(&deserialized, &INT_KEY, &[]).expect("decrypt should succeed");
    assert_eq!(decrypted.expose(), plaintext.as_slice());
}

#[test]
fn roundtrip_1mb_payload() {
    let plaintext = vec![0x77u8; 1_048_576];
    let sealed = encrypt(&plaintext, &INT_KEY, &[]).expect("encrypt 1MB should succeed");
    let wire = sealed.to_bytes();
    let restored = SealedData::from_bytes(&wire).expect("from_bytes should succeed");
    let decrypted = decrypt(&restored, &INT_KEY, &[]).expect("decrypt should succeed");
    assert_eq!(decrypted.expose(), plaintext.as_slice());
}

#[test]
fn decrypt_output_is_secret_buffer_masked() {
    let sealed = encrypt(b"integration secret", &INT_KEY, &[]).expect("encrypt should succeed");
    let decrypted = decrypt(&sealed, &INT_KEY, &[]).expect("decrypt should succeed");
    // Debug output should be masked — SecretBuffer hides contents.
    let debug = format!("{decrypted:?}");
    assert_eq!(debug, "SecretBuffer(***)");
}
