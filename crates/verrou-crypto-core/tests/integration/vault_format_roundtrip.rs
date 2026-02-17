//! Integration tests for vault file format serialize/deserialize cycle.
//!
//! Tests the full vault format lifecycle with realistic key hierarchies,
//! multi-slot headers, and cross-module composition (KDF + slots + symmetric + format).

use rand::rngs::OsRng;
use rand::RngCore;
use verrou_crypto_core::kdf::Argon2idParams;
use verrou_crypto_core::slots::{create_slot, unwrap_slot, SlotType, MASTER_KEY_LEN};
use verrou_crypto_core::vault_format::{
    deserialize, serialize, VaultHeader, FORMAT_VERSION, PADDING_BOUNDARY,
};
use verrou_crypto_core::CryptoError;

/// Generate a random 32-byte key from `OsRng`.
fn random_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

/// Create a realistic vault header with the given slots.
fn realistic_header(slots: Vec<verrou_crypto_core::slots::KeySlot>) -> VaultHeader {
    let salt_count = slots.len();
    VaultHeader {
        version: FORMAT_VERSION,
        slot_count: u8::try_from(slots.len()).expect("slot count fits u8"),
        session_params: Argon2idParams {
            m_cost: 262_144,
            t_cost: 3,
            p_cost: 4,
        },
        sensitive_params: Argon2idParams {
            m_cost: 524_288,
            t_cost: 4,
            p_cost: 4,
        },
        unlock_attempts: 0,
        last_attempt_at: None,
        total_unlock_count: 0,
        slots,
        slot_salts: vec![vec![]; salt_count],
    }
}

/// Full lifecycle: generate keys → create slots → serialize → deserialize → unwrap slots.
#[test]
fn full_lifecycle_with_key_slots() {
    let master_key = random_key();
    let pw_wrapping = random_key();
    let rec_wrapping = random_key();

    let pw_slot =
        create_slot(&master_key, &pw_wrapping, SlotType::Password).expect("password slot");
    let rec_slot =
        create_slot(&master_key, &rec_wrapping, SlotType::Recovery).expect("recovery slot");

    let header = realistic_header(vec![pw_slot, rec_slot]);
    let payload = b"encrypted vault database contents";

    // Serialize to .verrou binary.
    let blob = serialize(&header, payload, &master_key).expect("serialize");

    // Deserialize.
    let (recovered_header, recovered_payload) =
        deserialize(&blob, &master_key).expect("deserialize");

    assert_eq!(recovered_payload.expose(), payload);
    assert_eq!(recovered_header.slot_count, 2);
    assert_eq!(recovered_header.slots.len(), 2);

    // Verify slots still unwrap to the same master key.
    let mk_pw = unwrap_slot(&recovered_header.slots[0], &pw_wrapping).expect("pw unwrap");
    let mk_rec = unwrap_slot(&recovered_header.slots[1], &rec_wrapping).expect("rec unwrap");
    assert_eq!(mk_pw.expose(), &master_key);
    assert_eq!(mk_rec.expose(), &master_key);
}

/// Verify file size stays 64 KB-aligned across a range of payload sizes.
#[test]
fn alignment_across_payload_sizes() {
    let master_key = random_key();
    let header = realistic_header(vec![]);

    for size in [0, 1, 100, 1024, 4096, 65_000, 65_536, 100_000] {
        let payload = vec![0xABu8; size];
        let blob = serialize(&header, &payload, &master_key).expect("serialize");
        assert_eq!(
            blob.len() % PADDING_BOUNDARY,
            0,
            "blob for payload size {size} is not 64KB-aligned: {} bytes",
            blob.len()
        );
    }
}

/// Cross-module composition: KDF params survive roundtrip correctly.
#[test]
fn kdf_params_survive_roundtrip() {
    let master_key = random_key();
    let header = VaultHeader {
        version: FORMAT_VERSION,
        slot_count: 0,
        session_params: Argon2idParams {
            m_cost: 131_072,
            t_cost: 2,
            p_cost: 2,
        },
        sensitive_params: Argon2idParams {
            m_cost: 1_048_576,
            t_cost: 8,
            p_cost: 8,
        },
        unlock_attempts: 42,
        last_attempt_at: None,
        total_unlock_count: 0,
        slots: vec![],
        slot_salts: vec![],
    };

    let blob = serialize(&header, b"test", &master_key).expect("serialize");
    let (recovered, _) = deserialize(&blob, &master_key).expect("deserialize");

    assert_eq!(recovered.session_params.m_cost, 131_072);
    assert_eq!(recovered.session_params.t_cost, 2);
    assert_eq!(recovered.session_params.p_cost, 2);
    assert_eq!(recovered.sensitive_params.m_cost, 1_048_576);
    assert_eq!(recovered.sensitive_params.t_cost, 8);
    assert_eq!(recovered.sensitive_params.p_cost, 8);
    assert_eq!(recovered.unlock_attempts, 42);
}

/// Wrong key produces the correct error variant.
#[test]
fn wrong_key_error_type() {
    let master_key = random_key();
    let wrong_key = random_key();
    let header = realistic_header(vec![]);

    let blob = serialize(&header, b"secret", &master_key).expect("serialize");
    let result = deserialize(&blob, &wrong_key);

    assert!(
        matches!(result, Err(CryptoError::Decryption)),
        "wrong key should yield CryptoError::Decryption, got: {result:?}"
    );
}

/// Invalid key length produces the correct error variant.
#[test]
fn invalid_key_length_error_type() {
    let master_key = random_key();
    let header = realistic_header(vec![]);
    let blob = serialize(&header, b"test", &master_key).expect("serialize");

    let short_key = [0u8; MASTER_KEY_LEN - 1];
    let result = deserialize(&blob, &short_key);
    assert!(
        matches!(result, Err(CryptoError::InvalidKeyMaterial(_))),
        "short key should yield InvalidKeyMaterial"
    );

    let long_key = [0u8; MASTER_KEY_LEN + 1];
    let result = deserialize(&blob, &long_key);
    assert!(
        matches!(result, Err(CryptoError::InvalidKeyMaterial(_))),
        "long key should yield InvalidKeyMaterial"
    );
}
