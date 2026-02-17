#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::redundant_clone,
    clippy::too_many_lines,
    clippy::cloned_ref_to_slice_refs
)]

//! Integration tests for QR transfer serialization and import.
//!
//! Tests the full roundtrip: serialize entries from one vault → import
//! into another vault, verifying data integrity across the transfer.

use std::path::Path;

use verrou_crypto_core::kdf::{Argon2idParams, CalibratedPresets, KdfPreset};
use verrou_crypto_core::memory::SecretBytes;
use verrou_vault::lifecycle::{self, CreateVaultRequest};
use verrou_vault::transfer::{import_transfer_entries, serialize_entries_for_transfer};
use verrou_vault::{
    add_entry, get_entry, list_entries, AddEntryParams, Algorithm, CustomField, CustomFieldType,
    EntryData, EntryType, PasswordHistoryEntry, VaultDb,
};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

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

fn setup_vault(dir: &Path) -> (VaultDb, SecretBytes<32>) {
    let password = b"test-password-for-transfer";
    let calibrated = test_calibrated();
    let req = CreateVaultRequest {
        password,
        preset: KdfPreset::Fast,
        vault_dir: dir,
        calibrated: &calibrated,
    };
    lifecycle::create_vault(&req).expect("vault creation should succeed");

    let unlock_req = lifecycle::UnlockVaultRequest {
        password,
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn roundtrip_single_totp_entry() {
    let src_dir = tempfile::tempdir().unwrap();
    let dst_dir = tempfile::tempdir().unwrap();

    let (src_db, src_key) = setup_vault(src_dir.path());
    let (dst_db, dst_key) = setup_vault(dst_dir.path());

    let src = src_db.connection();
    let dst = dst_db.connection();

    // Create entry in source vault.
    let entry = add_entry(src, &src_key, &totp_params("GitHub", "JBSWY3DPEHPK3PXP")).unwrap();

    // Serialize.
    let payload = serialize_entries_for_transfer(src, &src_key, &[entry.id.clone()]).unwrap();

    // Import into destination vault.
    let imported = import_transfer_entries(dst, &dst_key, &payload).unwrap();
    assert_eq!(imported, 1);

    // Verify the entry exists in destination.
    let dst_entries = list_entries(dst).unwrap();
    assert_eq!(dst_entries.len(), 1);
    assert_eq!(dst_entries[0].name, "GitHub");
    assert_eq!(dst_entries[0].issuer.as_deref(), Some("example.com"));
    assert_eq!(dst_entries[0].entry_type, EntryType::Totp);
}

#[test]
fn roundtrip_multiple_entry_types() {
    let src_dir = tempfile::tempdir().unwrap();
    let dst_dir = tempfile::tempdir().unwrap();

    let (src_db, src_key) = setup_vault(src_dir.path());
    let (dst_db, dst_key) = setup_vault(dst_dir.path());

    let src = src_db.connection();
    let dst = dst_db.connection();

    // Create various entry types.
    let totp = add_entry(src, &src_key, &totp_params("TOTP Entry", "AAAA")).unwrap();

    let seed = add_entry(
        src,
        &src_key,
        &AddEntryParams {
            entry_type: EntryType::SeedPhrase,
            name: "Bitcoin Wallet".into(),
            issuer: None,
            folder_id: None,
            algorithm: Algorithm::SHA1,
            digits: 6,
            period: 30,
            counter: 0,
            pinned: true,
            tags: vec!["crypto".into()],
            data: EntryData::SeedPhrase {
                words: vec!["abandon".into(), "ability".into(), "able".into()],
                passphrase: Some("test25".into()),
            },
        },
    )
    .unwrap();

    let note = add_entry(
        src,
        &src_key,
        &AddEntryParams {
            entry_type: EntryType::SecureNote,
            name: "API Keys".into(),
            issuer: None,
            folder_id: None,
            algorithm: Algorithm::SHA1,
            digits: 6,
            period: 30,
            counter: 0,
            pinned: false,
            tags: vec!["work".into(), "api".into()],
            data: EntryData::SecureNote {
                body: "sk-12345\nsk-67890".into(),
                tags: vec!["work".into(), "api".into()],
            },
        },
    )
    .unwrap();

    let cred = add_entry(
        src,
        &src_key,
        &AddEntryParams {
            entry_type: EntryType::Credential,
            name: "Example Login".into(),
            issuer: Some("example.com".into()),
            folder_id: None,
            algorithm: Algorithm::SHA1,
            digits: 6,
            period: 30,
            counter: 0,
            pinned: false,
            tags: Vec::new(),
            data: EntryData::Credential {
                password: "p@ss123!".into(),
                username: Some("admin".into()),
                urls: vec!["https://example.com".into()],
                notes: Some("Production".into()),
                linked_totp_id: None,
                custom_fields: vec![CustomField {
                    label: "API Key".into(),
                    value: "key-abc".into(),
                    field_type: CustomFieldType::Hidden,
                }],
                password_history: vec![PasswordHistoryEntry {
                    password: "old-pass".into(),
                    changed_at: "2026-01-01T00:00:00Z".into(),
                }],
                template: Some("web-login".into()),
            },
        },
    )
    .unwrap();

    // Serialize all.
    let ids: Vec<String> = vec![totp.id, seed.id, note.id, cred.id];
    let payload = serialize_entries_for_transfer(src, &src_key, &ids).unwrap();

    // Import into destination vault.
    let imported = import_transfer_entries(dst, &dst_key, &payload).unwrap();
    assert_eq!(imported, 4);

    let dst_entries = list_entries(dst).unwrap();
    assert_eq!(dst_entries.len(), 4);

    // Verify seed phrase data integrity.
    let seed_entry = dst_entries
        .iter()
        .find(|e| e.name == "Bitcoin Wallet")
        .unwrap();
    let seed_full = get_entry(dst, &dst_key, &seed_entry.id).unwrap();
    match &seed_full.data {
        EntryData::SeedPhrase { words, passphrase } => {
            assert_eq!(words, &["abandon", "ability", "able"]);
            assert_eq!(passphrase.as_deref(), Some("test25"));
        }
        _ => panic!("wrong variant"),
    }
    assert!(seed_full.pinned);

    // Verify credential data integrity.
    let cred_entry = dst_entries
        .iter()
        .find(|e| e.name == "Example Login")
        .unwrap();
    let cred_full = get_entry(dst, &dst_key, &cred_entry.id).unwrap();
    match &cred_full.data {
        EntryData::Credential {
            password,
            username,
            custom_fields,
            password_history,
            template,
            ..
        } => {
            assert_eq!(password, "p@ss123!");
            assert_eq!(username.as_deref(), Some("admin"));
            assert_eq!(custom_fields.len(), 1);
            assert_eq!(custom_fields[0].label, "API Key");
            assert_eq!(password_history.len(), 1);
            assert_eq!(template.as_deref(), Some("web-login"));
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn roundtrip_with_folders() {
    let src_dir = tempfile::tempdir().unwrap();
    let dst_dir = tempfile::tempdir().unwrap();

    let (src_db, src_key) = setup_vault(src_dir.path());
    let (dst_db, dst_key) = setup_vault(dst_dir.path());

    let src = src_db.connection();
    let dst = dst_db.connection();

    // Create a folder in source vault.
    let folder = verrou_vault::create_folder(src, "Work").unwrap();

    // Create entry in the folder.
    let entry = add_entry(
        src,
        &src_key,
        &AddEntryParams {
            entry_type: EntryType::Totp,
            name: "Slack".into(),
            issuer: Some("slack.com".into()),
            folder_id: Some(folder.id.clone()),
            algorithm: Algorithm::SHA1,
            digits: 6,
            period: 30,
            counter: 0,
            pinned: false,
            tags: Vec::new(),
            data: EntryData::Totp {
                secret: "BBBB".into(),
            },
        },
    )
    .unwrap();

    // Serialize.
    let payload = serialize_entries_for_transfer(src, &src_key, &[entry.id.clone()]).unwrap();

    // Import into destination vault (which has no "Work" folder yet).
    let imported = import_transfer_entries(dst, &dst_key, &payload).unwrap();
    assert_eq!(imported, 1);

    // Verify folder was created in destination.
    let dst_folders = verrou_vault::list_folders_with_counts(dst).unwrap();
    assert_eq!(dst_folders.len(), 1);
    assert_eq!(dst_folders[0].folder.name, "Work");

    // Verify entry is in the new folder.
    let dst_entries = list_entries(dst).unwrap();
    assert_eq!(dst_entries.len(), 1);
    assert_eq!(
        dst_entries[0].folder_id,
        Some(dst_folders[0].folder.id.clone())
    );
}

#[test]
fn roundtrip_empty_entry_list() {
    let src_dir = tempfile::tempdir().unwrap();
    let dst_dir = tempfile::tempdir().unwrap();

    let (src_db, src_key) = setup_vault(src_dir.path());
    let (dst_db, dst_key) = setup_vault(dst_dir.path());

    let src = src_db.connection();
    let dst = dst_db.connection();

    // Serialize with no entries.
    let payload = serialize_entries_for_transfer(src, &src_key, &[]).unwrap();

    let imported = import_transfer_entries(dst, &dst_key, &payload).unwrap();
    assert_eq!(imported, 0);

    let dst_entries = list_entries(dst).unwrap();
    assert!(dst_entries.is_empty());
}

#[test]
fn import_rejects_corrupted_payload() {
    let dst_dir = tempfile::tempdir().unwrap();
    let (dst_db, dst_key) = setup_vault(dst_dir.path());

    let dst = dst_db.connection();

    // Hand-craft a payload with a bad checksum.
    let bad_payload = br#"{"version":1,"entries":[],"checksum":"0000000000000000000000000000000000000000000000000000000000000000"}"#;

    let result = import_transfer_entries(dst, &dst_key, bad_payload);
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(err_msg.contains("checksum mismatch"), "got: {err_msg}");
}

#[test]
fn import_rejects_invalid_json() {
    let dst_dir = tempfile::tempdir().unwrap();
    let (dst_db, dst_key) = setup_vault(dst_dir.path());

    let dst = dst_db.connection();

    let result = import_transfer_entries(dst, &dst_key, b"not json at all");
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("invalid transfer payload"),
        "got: {err_msg}"
    );
}
