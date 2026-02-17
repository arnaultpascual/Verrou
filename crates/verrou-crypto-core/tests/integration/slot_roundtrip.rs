//! Integration tests for key slot create/unwrap cycle.
//!
//! Tests full slot lifecycle with realistic keys and multi-slot scenarios.

use rand::rngs::OsRng;
use rand::RngCore;
use verrou_crypto_core::slots::{create_slot, unwrap_slot, KeySlot, SlotType, WRAPPING_KEY_LEN};
use verrou_crypto_core::CryptoError;

/// Generate a random 32-byte key from `OsRng`.
fn random_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

/// Full create → unwrap cycle with realistic random keys.
#[test]
fn roundtrip_with_random_keys() {
    let master_key = random_key();
    let wrapping_key = random_key();

    let slot = create_slot(&master_key, &wrapping_key, SlotType::Password)
        .expect("create_slot should succeed");
    let unwrapped = unwrap_slot(&slot, &wrapping_key).expect("unwrap_slot should succeed");
    assert_eq!(unwrapped.expose(), &master_key);
}

/// Multi-slot independence: create Password + Biometric + Recovery slots
/// for the same master key, unwrap each, verify all return identical bytes.
#[test]
fn multi_slot_independence() {
    let master_key = random_key();
    let pw_key = random_key();
    let bio_key = random_key();
    let rec_key = random_key();

    let pw_slot = create_slot(&master_key, &pw_key, SlotType::Password)
        .expect("password slot should succeed");
    let bio_slot = create_slot(&master_key, &bio_key, SlotType::Biometric)
        .expect("biometric slot should succeed");
    let rec_slot = create_slot(&master_key, &rec_key, SlotType::Recovery)
        .expect("recovery slot should succeed");

    let mk_pw = unwrap_slot(&pw_slot, &pw_key).expect("password unwrap should succeed");
    let mk_bio = unwrap_slot(&bio_slot, &bio_key).expect("biometric unwrap should succeed");
    let mk_rec = unwrap_slot(&rec_slot, &rec_key).expect("recovery unwrap should succeed");

    assert_eq!(mk_pw.expose(), &master_key);
    assert_eq!(mk_bio.expose(), &master_key);
    assert_eq!(mk_rec.expose(), &master_key);
}

/// Slot removal simulation: removing one slot from a collection doesn't
/// affect the ability to unwrap remaining slots.
#[test]
fn slot_removal_does_not_affect_remaining() {
    let master_key = random_key();
    let keys: Vec<[u8; WRAPPING_KEY_LEN]> = (0..3).map(|_| random_key()).collect();
    let types = [SlotType::Password, SlotType::Biometric, SlotType::Recovery];

    let mut slots: Vec<KeySlot> = keys
        .iter()
        .zip(types.iter())
        .map(|(wk, st)| create_slot(&master_key, wk, *st).expect("create_slot should succeed"))
        .collect();

    // Remove the biometric slot (index 1).
    let _ = slots.remove(1);

    // Remaining slots should still unwrap correctly.
    let mk_pw = unwrap_slot(&slots[0], &keys[0]).expect("password unwrap after removal");
    let mk_rec = unwrap_slot(&slots[1], &keys[2]).expect("recovery unwrap after removal");

    assert_eq!(mk_pw.expose(), &master_key);
    assert_eq!(mk_rec.expose(), &master_key);
}

/// Cross-key rejection with random keys.
#[test]
fn cross_key_rejection_random() {
    let master_key = random_key();
    let wrapping_key = random_key();
    let wrong_key = random_key();

    let slot = create_slot(&master_key, &wrapping_key, SlotType::Password)
        .expect("create_slot should succeed");

    let result = unwrap_slot(&slot, &wrong_key);
    assert!(result.is_err());
    assert!(
        matches!(result, Err(CryptoError::Decryption)),
        "wrong key should yield CryptoError::Decryption"
    );
}
