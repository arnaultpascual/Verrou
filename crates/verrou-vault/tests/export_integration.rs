#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

//! Integration tests for vault export.
//!
//! These tests exercise the full export pipeline:
//! re-authentication, entry/folder/attachment collection,
//! payload serialization, encryption, and .verrou binary generation.

use std::path::Path;

use verrou_crypto_core::kdf::{Argon2idParams, CalibratedPresets, KdfPreset};
use verrou_crypto_core::memory::SecretBytes;
use verrou_crypto_core::slots::{self, SlotType};
use verrou_crypto_core::vault_format;
use verrou_vault::error::VaultError;
use verrou_vault::export::verrou_format::{export_vault, ExportVaultRequest};
use verrou_vault::lifecycle::{self, CreateVaultRequest, UnlockVaultRequest};
use verrou_vault::{add_entry, AddEntryParams, Algorithm, EntryData, EntryType, VaultDb};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

const TEST_PASSWORD: &[u8] = b"test-export-password-42";

const fn test_calibrated() -> CalibratedPresets {
    CalibratedPresets {
        fast: Argon2idParams {
            m_cost: 32,
            t_cost: 1,
            p_cost: 1,
        },
        balanced: Argon2idParams {
            m_cost: 64,
            t_cost: 2,
            p_cost: 1,
        },
        maximum: Argon2idParams {
            m_cost: 128,
            t_cost: 3,
            p_cost: 1,
        },
    }
}

/// Create and unlock a vault, returning the DB connection and master key.
fn setup_vault(dir: &Path) -> (VaultDb, SecretBytes<32>) {
    let calibrated = test_calibrated();
    let req = CreateVaultRequest {
        password: TEST_PASSWORD,
        preset: KdfPreset::Fast,
        vault_dir: dir,
        calibrated: &calibrated,
    };
    lifecycle::create_vault(&req).expect("vault creation should succeed");

    let unlock_req = UnlockVaultRequest {
        password: TEST_PASSWORD,
        vault_dir: dir,
    };
    let result = lifecycle::unlock_vault(&unlock_req).expect("vault unlock should succeed");
    (result.db, result.master_key)
}

fn totp_params(name: &str, secret: &str) -> AddEntryParams {
    AddEntryParams {
        entry_type: EntryType::Totp,
        name: name.to_string(),
        issuer: Some("example.com".to_string()),
        folder_id: None,
        algorithm: Algorithm::SHA1,
        digits: 6,
        period: 30,
        counter: 0,
        pinned: false,
        tags: Vec::new(),
        data: EntryData::Totp {
            secret: secret.to_string(),
        },
    }
}

fn note_params(name: &str, content: &str) -> AddEntryParams {
    AddEntryParams {
        entry_type: EntryType::SecureNote,
        name: name.to_string(),
        issuer: None,
        folder_id: None,
        algorithm: Algorithm::SHA1,
        digits: 6,
        period: 30,
        counter: 0,
        pinned: false,
        tags: Vec::new(),
        data: EntryData::SecureNote {
            body: content.to_string(),
            tags: vec![],
        },
    }
}

/// Recover the master key from export .verrou bytes using a password.
fn recover_export_key(export_data: &[u8], password: &[u8]) -> SecretBytes<32> {
    let header = vault_format::parse_header_only(export_data).expect("export header should parse");

    let password_slot = header
        .slots
        .iter()
        .enumerate()
        .find(|(_, s)| s.slot_type == SlotType::Password)
        .expect("export must have a password slot");

    let salt = &header.slot_salts[password_slot.0];
    let wrapping_key = verrou_crypto_core::kdf::derive(password, salt, &header.session_params)
        .expect("KDF derivation should succeed");

    let mk_buf = slots::unwrap_slot(password_slot.1, wrapping_key.expose())
        .expect("slot unwrap should succeed");

    let mut arr = [0u8; 32];
    arr.copy_from_slice(mk_buf.expose());
    SecretBytes::new(arr)
}

// ---------------------------------------------------------------------------
// AC #1: Export succeeds on empty vault (zero entries/folders/attachments)
// ---------------------------------------------------------------------------

#[test]
fn export_empty_vault_succeeds() {
    let tmp = tempfile::tempdir().unwrap();
    let (db, master_key) = setup_vault(tmp.path());

    let req = ExportVaultRequest {
        password: TEST_PASSWORD,
        master_key: master_key.expose(),
        vault_dir: tmp.path(),
    };

    let result = export_vault(db.connection(), &req).expect("export should succeed");
    assert_eq!(result.entry_count, 0);
    assert_eq!(result.folder_count, 0);
    assert_eq!(result.attachment_count, 0);
    assert!(
        !result.export_data.is_empty(),
        "export data must not be empty"
    );
}

// ---------------------------------------------------------------------------
// AC #2: Export with entries produces correct counts and valid .verrou binary
// ---------------------------------------------------------------------------

#[test]
fn export_with_entries_produces_valid_verrou_binary() {
    let tmp = tempfile::tempdir().unwrap();
    let (db, master_key) = setup_vault(tmp.path());

    // Add test entries.
    add_entry(
        db.connection(),
        &master_key,
        &totp_params("GitHub", "JBSWY3DPEHPK3PXP"),
    )
    .unwrap();
    add_entry(
        db.connection(),
        &master_key,
        &totp_params("GitLab", "KRSXG5CTMVRXEZLU"),
    )
    .unwrap();
    add_entry(
        db.connection(),
        &master_key,
        &note_params("Server SSH", "root@10.0.0.1"),
    )
    .unwrap();

    let req = ExportVaultRequest {
        password: TEST_PASSWORD,
        master_key: master_key.expose(),
        vault_dir: tmp.path(),
    };

    let result = export_vault(db.connection(), &req).expect("export should succeed");
    assert_eq!(result.entry_count, 3);
    assert_eq!(result.folder_count, 0);
    assert_eq!(result.attachment_count, 0);

    // Verify .verrou magic bytes (VROU).
    assert_eq!(
        &result.export_data[..4],
        b"VROU",
        "magic bytes must be VROU"
    );

    // Verify the header is parseable.
    let header =
        vault_format::parse_header_only(&result.export_data).expect("export header should parse");
    assert_eq!(header.slot_count, 1, "export must have exactly one slot");
    assert_eq!(header.slots[0].slot_type, SlotType::Password);
}

// ---------------------------------------------------------------------------
// AC #3: Export key is independent (fresh per export)
// ---------------------------------------------------------------------------

#[test]
fn export_uses_fresh_independent_key() {
    let tmp = tempfile::tempdir().unwrap();
    let (db, master_key) = setup_vault(tmp.path());

    add_entry(
        db.connection(),
        &master_key,
        &totp_params("Test", "JBSWY3DPEHPK3PXP"),
    )
    .unwrap();

    let req = ExportVaultRequest {
        password: TEST_PASSWORD,
        master_key: master_key.expose(),
        vault_dir: tmp.path(),
    };

    // Export twice — keys must differ.
    let result1 = export_vault(db.connection(), &req).unwrap();
    let result2 = export_vault(db.connection(), &req).unwrap();

    let key1 = recover_export_key(&result1.export_data, TEST_PASSWORD);
    let key2 = recover_export_key(&result2.export_data, TEST_PASSWORD);

    assert_ne!(
        key1.expose(),
        key2.expose(),
        "each export must use a unique master key"
    );

    // Export key must differ from vault session key.
    assert_ne!(
        key1.expose(),
        master_key.expose(),
        "export key must differ from session master key"
    );
}

// ---------------------------------------------------------------------------
// AC #4: Export can be decrypted with the export password
// ---------------------------------------------------------------------------

#[test]
fn export_file_can_be_decrypted_with_password() {
    let tmp = tempfile::tempdir().unwrap();
    let (db, master_key) = setup_vault(tmp.path());

    add_entry(
        db.connection(),
        &master_key,
        &totp_params("Decrypt Test", "ABCDEFGHIJ234567"),
    )
    .unwrap();

    let req = ExportVaultRequest {
        password: TEST_PASSWORD,
        master_key: master_key.expose(),
        vault_dir: tmp.path(),
    };

    let result = export_vault(db.connection(), &req).unwrap();

    // Recover export master key from password.
    let export_key = recover_export_key(&result.export_data, TEST_PASSWORD);

    // Deserialize full .verrou to get plaintext payload.
    let (_header, plaintext) = vault_format::deserialize(&result.export_data, export_key.expose())
        .expect("deserialization with export key should succeed");

    // Parse the JSON payload.
    let payload: serde_json::Value =
        serde_json::from_slice(plaintext.expose()).expect("payload should be valid JSON");

    assert_eq!(payload["version"], 1);
    let entries = payload["entries"]
        .as_array()
        .expect("entries must be an array");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["name"], "Decrypt Test");
    assert_eq!(entries[0]["data"]["secret"], "ABCDEFGHIJ234567");
}

// ---------------------------------------------------------------------------
// AC #5: Export fails with wrong password
// ---------------------------------------------------------------------------

#[test]
fn export_fails_with_wrong_password() {
    let tmp = tempfile::tempdir().unwrap();
    let (db, master_key) = setup_vault(tmp.path());

    let req = ExportVaultRequest {
        password: b"wrong-password-entirely",
        master_key: master_key.expose(),
        vault_dir: tmp.path(),
    };

    let result = export_vault(db.connection(), &req);
    assert!(result.is_err(), "export should fail with wrong password");
    let err = result.unwrap_err();
    assert!(
        matches!(err, VaultError::InvalidPassword),
        "error should be InvalidPassword, got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// AC #6: Export with folders includes folder data
// ---------------------------------------------------------------------------

#[test]
fn export_includes_folders() {
    let tmp = tempfile::tempdir().unwrap();
    let (db, master_key) = setup_vault(tmp.path());

    // Create folders.
    verrou_vault::create_folder(db.connection(), "Work").unwrap();
    verrou_vault::create_folder(db.connection(), "Personal").unwrap();

    // Add an entry.
    add_entry(
        db.connection(),
        &master_key,
        &totp_params("GitHub", "JBSWY3DPEHPK3PXP"),
    )
    .unwrap();

    let req = ExportVaultRequest {
        password: TEST_PASSWORD,
        master_key: master_key.expose(),
        vault_dir: tmp.path(),
    };

    let result = export_vault(db.connection(), &req).unwrap();
    assert_eq!(result.entry_count, 1);
    assert_eq!(result.folder_count, 2);

    // Decrypt and verify folder data in payload.
    let export_key = recover_export_key(&result.export_data, TEST_PASSWORD);
    let (_header, plaintext) =
        vault_format::deserialize(&result.export_data, export_key.expose()).unwrap();
    let payload: serde_json::Value = serde_json::from_slice(plaintext.expose()).unwrap();

    let folders = payload["folders"]
        .as_array()
        .expect("folders must be an array");
    assert_eq!(folders.len(), 2);

    let names: Vec<&str> = folders
        .iter()
        .map(|f| f["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"Work"), "folders should contain 'Work'");
    assert!(
        names.contains(&"Personal"),
        "folders should contain 'Personal'"
    );
}

// ---------------------------------------------------------------------------
// AC #7: Export preserves multiple entry types
// ---------------------------------------------------------------------------

#[test]
fn export_preserves_all_entry_types() {
    let tmp = tempfile::tempdir().unwrap();
    let (db, master_key) = setup_vault(tmp.path());

    // TOTP entry.
    add_entry(
        db.connection(),
        &master_key,
        &totp_params("My TOTP", "SECRET1"),
    )
    .unwrap();

    // Secure note.
    add_entry(
        db.connection(),
        &master_key,
        &note_params("My Note", "confidential info"),
    )
    .unwrap();

    // Seed phrase.
    let seed_params = AddEntryParams {
        entry_type: EntryType::SeedPhrase,
        name: "My Seed".to_string(),
        issuer: None,
        folder_id: None,
        algorithm: Algorithm::SHA1,
        digits: 6,
        period: 30,
        counter: 0,
        pinned: false,
        tags: Vec::new(),
        data: EntryData::SeedPhrase {
            words: vec!["abandon".into(), "ability".into(), "able".into()],
            passphrase: None,
        },
    };
    add_entry(db.connection(), &master_key, &seed_params).unwrap();

    let req = ExportVaultRequest {
        password: TEST_PASSWORD,
        master_key: master_key.expose(),
        vault_dir: tmp.path(),
    };

    let result = export_vault(db.connection(), &req).unwrap();
    assert_eq!(result.entry_count, 3);

    // Decrypt and verify each entry type preserved.
    let export_key = recover_export_key(&result.export_data, TEST_PASSWORD);
    let (_header, plaintext) =
        vault_format::deserialize(&result.export_data, export_key.expose()).unwrap();
    let payload: serde_json::Value = serde_json::from_slice(plaintext.expose()).unwrap();

    let entries = payload["entries"].as_array().unwrap();
    let types: Vec<&str> = entries
        .iter()
        .map(|e| e["entry_type"].as_str().unwrap())
        .collect();
    assert!(types.contains(&"totp"), "should contain totp entry");
    assert!(
        types.contains(&"secure_note"),
        "should contain secure_note entry"
    );
    assert!(
        types.contains(&"seed_phrase"),
        "should contain seed_phrase entry"
    );

    // Verify seed phrase words are preserved.
    let seed_entry = entries
        .iter()
        .find(|e| e["entry_type"] == "seed_phrase")
        .unwrap();
    let words = seed_entry["data"]["words"].as_array().unwrap();
    assert_eq!(words.len(), 3);
    assert_eq!(words[0], "abandon");
}
