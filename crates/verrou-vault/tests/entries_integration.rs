#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

//! Integration tests for entry CRUD operations.
//!
//! These tests exercise the full CRUD lifecycle through `SQLCipher` (Layer 1)
//! and AES-256-GCM encryption (Layer 2).

use std::path::Path;
use std::time::Instant;

use verrou_crypto_core::kdf::{Argon2idParams, CalibratedPresets, KdfPreset};
use verrou_crypto_core::memory::SecretBytes;
use verrou_vault::error::VaultError;
use verrou_vault::lifecycle::{self, CreateVaultRequest};
use verrou_vault::{
    add_entry, delete_entry, get_entry, list_entries, update_entry, AddEntryParams, Algorithm,
    CustomField, CustomFieldType, EntryData, EntryType, PasswordHistoryEntry, UpdateEntryParams,
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

/// Create and unlock a vault, returning the DB connection and master key.
fn setup_vault(dir: &Path) -> (verrou_vault::VaultDb, SecretBytes<32>) {
    let password = b"test-password-for-entries";
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

fn hotp_params(name: &str, secret: &str, counter: u64) -> AddEntryParams {
    AddEntryParams {
        entry_type: EntryType::Hotp,
        name: name.to_string(),
        issuer: None,
        folder_id: None,
        algorithm: Algorithm::SHA1,
        digits: 6,
        period: 30, // HOTP ignores period; use default to satisfy CHECK constraint.
        counter,
        pinned: false,
        tags: Vec::new(),
        data: EntryData::Hotp {
            secret: secret.to_string(),
        },
    }
}

fn seed_phrase_params(name: &str, words: &[&str]) -> AddEntryParams {
    AddEntryParams {
        entry_type: EntryType::SeedPhrase,
        name: name.to_string(),
        issuer: None,
        folder_id: None,
        algorithm: Algorithm::SHA1,
        digits: 6,
        period: 30,
        counter: 0,
        pinned: false,
        tags: Vec::new(),
        data: EntryData::SeedPhrase {
            words: words.iter().map(|w| (*w).to_string()).collect(),
            passphrase: None,
        },
    }
}

fn recovery_code_params(name: &str, codes: &[&str]) -> AddEntryParams {
    AddEntryParams {
        entry_type: EntryType::RecoveryCode,
        name: name.to_string(),
        issuer: Some("service.example.com".to_string()),
        folder_id: None,
        algorithm: Algorithm::SHA1,
        digits: 6,
        period: 30,
        counter: 0,
        pinned: false,
        tags: Vec::new(),
        data: EntryData::RecoveryCode {
            codes: codes.iter().map(|c| (*c).to_string()).collect(),
            used: Vec::new(),
            linked_entry_id: None,
        },
    }
}

fn secure_note_params(name: &str, body: &str) -> AddEntryParams {
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
            body: body.to_string(),
            tags: vec!["test".to_string()],
        },
    }
}

// ---------------------------------------------------------------------------
// CRUD roundtrip tests
// ---------------------------------------------------------------------------

#[test]
fn crud_roundtrip_totp() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, master_key) = setup_vault(dir.path());
    let conn = db.connection();

    // Add
    let entry = add_entry(
        conn,
        &master_key,
        &totp_params("GitHub", "JBSWY3DPEHPK3PXP"),
    )
    .expect("add should succeed");
    assert_eq!(entry.name, "GitHub");
    assert_eq!(entry.entry_type, EntryType::Totp);
    assert_eq!(entry.algorithm, Algorithm::SHA1);
    assert_eq!(entry.digits, 6);
    assert_eq!(entry.period, 30);
    assert!(!entry.pinned);

    // Get
    let fetched = get_entry(conn, &master_key, &entry.id).expect("get should succeed");
    assert_eq!(fetched.name, "GitHub");
    match &fetched.data {
        EntryData::Totp { secret } => assert_eq!(secret, "JBSWY3DPEHPK3PXP"),
        _ => panic!("wrong variant"),
    }

    // Update
    let updates = UpdateEntryParams {
        name: Some("GitHub (Work)".to_string()),
        issuer: None,
        folder_id: None,
        algorithm: Some(Algorithm::SHA256),
        digits: Some(8),
        period: None,
        counter: None,
        pinned: Some(true),
        data: None,
        tags: None,
    };
    let result =
        update_entry(conn, &master_key, &entry.id, &updates).expect("update should succeed");
    assert_eq!(result.name, "GitHub (Work)");
    assert_eq!(result.algorithm, Algorithm::SHA256);
    assert_eq!(result.digits, 8);
    assert!(result.pinned);

    // Verify update persisted
    let refetched = get_entry(conn, &master_key, &entry.id).expect("refetch should succeed");
    assert_eq!(refetched.name, "GitHub (Work)");
    assert_eq!(refetched.algorithm, Algorithm::SHA256);
    assert!(refetched.pinned);

    // Delete
    delete_entry(conn, &entry.id).expect("delete should succeed");

    // Verify deletion
    let err = get_entry(conn, &master_key, &entry.id).expect_err("should be deleted");
    assert!(matches!(err, VaultError::EntryNotFound(_)));
}

#[test]
fn crud_roundtrip_hotp() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, master_key) = setup_vault(dir.path());
    let conn = db.connection();

    let entry = add_entry(
        conn,
        &master_key,
        &hotp_params("VPN", "GEZDGNBVGY3TQOJQ", 42),
    )
    .expect("add should succeed");
    assert_eq!(entry.entry_type, EntryType::Hotp);
    assert_eq!(entry.counter, 42);

    let fetched = get_entry(conn, &master_key, &entry.id).expect("get should succeed");
    assert_eq!(fetched.counter, 42);
    match &fetched.data {
        EntryData::Hotp { secret } => assert_eq!(secret, "GEZDGNBVGY3TQOJQ"),
        _ => panic!("wrong variant"),
    }

    // Update counter
    let updates = UpdateEntryParams {
        name: None,
        issuer: None,
        folder_id: None,
        algorithm: None,
        digits: None,
        period: None,
        counter: Some(43),
        pinned: None,
        data: None,
        tags: None,
    };
    let result =
        update_entry(conn, &master_key, &entry.id, &updates).expect("update should succeed");
    assert_eq!(result.counter, 43);

    delete_entry(conn, &entry.id).expect("delete should succeed");
}

#[test]
fn crud_roundtrip_seed_phrase() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, master_key) = setup_vault(dir.path());
    let conn = db.connection();

    let words = [
        "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd",
        "abuse", "access", "accident",
    ];
    let entry = add_entry(conn, &master_key, &seed_phrase_params("Wallet", &words))
        .expect("add should succeed");
    assert_eq!(entry.entry_type, EntryType::SeedPhrase);

    let fetched = get_entry(conn, &master_key, &entry.id).expect("get should succeed");
    match &fetched.data {
        EntryData::SeedPhrase {
            words: w,
            passphrase,
        } => {
            assert_eq!(w.len(), 12);
            assert_eq!(w[0], "abandon");
            assert!(passphrase.is_none());
        }
        _ => panic!("wrong variant"),
    }

    delete_entry(conn, &entry.id).expect("delete should succeed");
}

#[test]
fn crud_roundtrip_recovery_code() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, master_key) = setup_vault(dir.path());
    let conn = db.connection();

    let codes = ["ABC-123", "DEF-456", "GHI-789"];
    let entry = add_entry(conn, &master_key, &recovery_code_params("Gmail", &codes))
        .expect("add should succeed");
    assert_eq!(entry.entry_type, EntryType::RecoveryCode);

    let fetched = get_entry(conn, &master_key, &entry.id).expect("get should succeed");
    match &fetched.data {
        EntryData::RecoveryCode { codes: c, used, .. } => {
            assert_eq!(c.len(), 3);
            assert_eq!(c[0], "ABC-123");
            assert!(used.is_empty());
        }
        _ => panic!("wrong variant"),
    }

    delete_entry(conn, &entry.id).expect("delete should succeed");
}

#[test]
fn crud_roundtrip_secure_note() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, master_key) = setup_vault(dir.path());
    let conn = db.connection();

    let entry = add_entry(
        conn,
        &master_key,
        &secure_note_params("Server Access", "ssh root@10.0.0.1"),
    )
    .expect("add should succeed");
    assert_eq!(entry.entry_type, EntryType::SecureNote);

    let fetched = get_entry(conn, &master_key, &entry.id).expect("get should succeed");
    match &fetched.data {
        EntryData::SecureNote { body, tags } => {
            assert_eq!(body, "ssh root@10.0.0.1");
            assert_eq!(tags, &["test"]);
        }
        _ => panic!("wrong variant"),
    }

    delete_entry(conn, &entry.id).expect("delete should succeed");
}

#[test]
fn update_entry_secret_re_encrypts() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, master_key) = setup_vault(dir.path());
    let conn = db.connection();

    let entry = add_entry(conn, &master_key, &totp_params("Rotate", "OLDSECRET123"))
        .expect("add should succeed");

    let updates = UpdateEntryParams {
        name: None,
        issuer: None,
        folder_id: None,
        algorithm: None,
        digits: None,
        period: None,
        counter: None,
        pinned: None,
        data: Some(EntryData::Totp {
            secret: "NEWSECRET456".to_string(),
        }),
        tags: None,
    };
    update_entry(conn, &master_key, &entry.id, &updates).expect("update should succeed");

    let fetched = get_entry(conn, &master_key, &entry.id).expect("get should succeed");
    match &fetched.data {
        EntryData::Totp { secret } => assert_eq!(secret, "NEWSECRET456"),
        _ => panic!("wrong variant"),
    }
}

// ---------------------------------------------------------------------------
// list_entries tests
// ---------------------------------------------------------------------------

#[test]
fn list_entries_returns_metadata_only() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, master_key) = setup_vault(dir.path());
    let conn = db.connection();

    add_entry(conn, &master_key, &totp_params("Bravo", "SECRET1")).expect("add 1");
    add_entry(conn, &master_key, &totp_params("Alpha", "SECRET2")).expect("add 2");

    let items = list_entries(conn).expect("list should succeed");
    assert_eq!(items.len(), 2);
    // Sorted by name ASC (neither is pinned).
    assert_eq!(items[0].name, "Alpha");
    assert_eq!(items[1].name, "Bravo");
}

#[test]
fn list_entries_pinned_first() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, master_key) = setup_vault(dir.path());
    let conn = db.connection();

    let mut params1 = totp_params("Zebra", "S1");
    params1.pinned = true;
    add_entry(conn, &master_key, &params1).expect("add pinned");
    add_entry(conn, &master_key, &totp_params("Apple", "S2")).expect("add unpinned");

    let items = list_entries(conn).expect("list should succeed");
    assert_eq!(items.len(), 2);
    // Pinned first, then by name.
    assert_eq!(items[0].name, "Zebra");
    assert!(items[0].pinned);
    assert_eq!(items[1].name, "Apple");
    assert!(!items[1].pinned);
}

#[test]
fn list_entries_500_plus_performance() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, master_key) = setup_vault(dir.path());
    let conn = db.connection();

    // Insert 500 entries.
    for i in 0..500 {
        let params = totp_params(&format!("Entry-{i:04}"), "JBSWY3DPEHPK3PXP");
        add_entry(conn, &master_key, &params)
            .unwrap_or_else(|e| panic!("add entry {i} failed: {e}"));
    }

    let start = Instant::now();
    let items = list_entries(conn).expect("list should succeed");
    let elapsed = start.elapsed();

    assert_eq!(items.len(), 500);
    // NFR3: list_entries must complete in <100ms for 500+ entries.
    assert!(
        elapsed.as_millis() < 100,
        "list_entries took {elapsed:?} for 500 entries — exceeds 100ms NFR3 target"
    );
}

// ---------------------------------------------------------------------------
// Error handling tests
// ---------------------------------------------------------------------------

#[test]
fn get_nonexistent_entry_returns_not_found() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, master_key) = setup_vault(dir.path());
    let conn = db.connection();

    let err = get_entry(conn, &master_key, "nonexistent-uuid").expect_err("should return error");
    assert!(matches!(err, VaultError::EntryNotFound(_)));
}

#[test]
fn update_nonexistent_entry_returns_not_found() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, master_key) = setup_vault(dir.path());
    let conn = db.connection();

    let updates = UpdateEntryParams {
        name: Some("New Name".to_string()),
        issuer: None,
        folder_id: None,
        algorithm: None,
        digits: None,
        period: None,
        counter: None,
        pinned: None,
        data: None,
        tags: None,
    };
    let err = update_entry(conn, &master_key, "nonexistent-uuid", &updates)
        .expect_err("should return error");
    assert!(matches!(err, VaultError::EntryNotFound(_)));
}

#[test]
fn delete_nonexistent_entry_returns_not_found() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, _master_key) = setup_vault(dir.path());
    let conn = db.connection();

    let err = delete_entry(conn, "nonexistent-uuid").expect_err("should return error");
    assert!(matches!(err, VaultError::EntryNotFound(_)));
}

#[test]
fn double_delete_returns_not_found() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, master_key) = setup_vault(dir.path());
    let conn = db.connection();

    let entry =
        add_entry(conn, &master_key, &totp_params("Temp", "SECRET")).expect("add should succeed");
    delete_entry(conn, &entry.id).expect("first delete should succeed");

    let err = delete_entry(conn, &entry.id).expect_err("second delete should fail");
    assert!(matches!(err, VaultError::EntryNotFound(_)));
}

// ---------------------------------------------------------------------------
// CHECK constraint tests
// ---------------------------------------------------------------------------

#[test]
fn check_constraint_rejects_invalid_entry_type() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, _master_key) = setup_vault(dir.path());
    let conn = db.connection();

    let result = conn.execute(
        "INSERT INTO entries (id, entry_type, name, encrypted_data, created_at, updated_at) \
         VALUES ('test-id', 'invalid_type', 'Test', X'00', '2026-01-01', '2026-01-01')",
        [],
    );
    assert!(
        result.is_err(),
        "invalid entry_type should be rejected by CHECK constraint"
    );
}

#[test]
fn check_constraint_accepts_all_five_entry_types() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, _master_key) = setup_vault(dir.path());
    let conn = db.connection();

    let types = [
        "totp",
        "hotp",
        "seed_phrase",
        "recovery_code",
        "secure_note",
    ];
    for (i, entry_type) in types.iter().enumerate() {
        let id = format!("type-test-{i}");
        conn.execute(
            "INSERT INTO entries (id, entry_type, name, encrypted_data, created_at, updated_at) \
             VALUES (?1, ?2, ?3, X'00', '2026-01-01', '2026-01-01')",
            rusqlite::params![id, entry_type, format!("Test {entry_type}")],
        )
        .unwrap_or_else(|e| panic!("entry_type '{entry_type}' should be accepted: {e}"));
    }
}

// ---------------------------------------------------------------------------
// Folder FK cascade test
// ---------------------------------------------------------------------------

#[test]
fn delete_folder_sets_entry_folder_id_to_null() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, master_key) = setup_vault(dir.path());
    let conn = db.connection();

    // Create a folder.
    conn.execute(
        "INSERT INTO folders (id, name, created_at, updated_at) \
         VALUES ('folder-1', 'Work', '2026-01-01', '2026-01-01')",
        [],
    )
    .expect("insert folder");

    // Add an entry in that folder.
    let mut params = totp_params("In Folder", "SECRET123");
    params.folder_id = Some("folder-1".to_string());
    let entry = add_entry(conn, &master_key, &params).expect("add entry in folder");
    assert_eq!(entry.folder_id.as_deref(), Some("folder-1"));

    // Delete the folder.
    conn.execute("DELETE FROM folders WHERE id = 'folder-1'", [])
        .expect("delete folder");

    // Verify entry's folder_id is now NULL (ON DELETE SET NULL).
    let fetched = get_entry(conn, &master_key, &entry.id).expect("get entry after folder delete");
    assert!(
        fetched.folder_id.is_none(),
        "folder_id should be NULL after folder deletion"
    );
}

// ---------------------------------------------------------------------------
// Layer 2 encryption roundtrip tests
// ---------------------------------------------------------------------------

#[test]
fn layer2_encryption_produces_different_ciphertexts() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, master_key) = setup_vault(dir.path());
    let conn = db.connection();

    // Add two entries with the same secret.
    let e1 =
        add_entry(conn, &master_key, &totp_params("Same1", "IDENTICAL_SECRET")).expect("add 1");
    let e2 =
        add_entry(conn, &master_key, &totp_params("Same2", "IDENTICAL_SECRET")).expect("add 2");

    // Fetch raw encrypted_data blobs.
    let blob1: Vec<u8> = conn
        .query_row(
            "SELECT encrypted_data FROM entries WHERE id = ?1",
            [&e1.id],
            |row| row.get(0),
        )
        .expect("fetch blob 1");
    let blob2: Vec<u8> = conn
        .query_row(
            "SELECT encrypted_data FROM entries WHERE id = ?1",
            [&e2.id],
            |row| row.get(0),
        )
        .expect("fetch blob 2");

    // AES-256-GCM uses random nonces, so same plaintext → different ciphertext.
    assert_ne!(
        blob1, blob2,
        "identical secrets should produce different ciphertexts"
    );
}

#[test]
fn layer2_decryption_with_correct_key_succeeds() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, master_key) = setup_vault(dir.path());
    let conn = db.connection();

    let entry = add_entry(
        conn,
        &master_key,
        &totp_params("Decrypt Test", "TESTSECRET"),
    )
    .expect("add should succeed");

    let fetched = get_entry(conn, &master_key, &entry.id).expect("decrypt should succeed");
    match &fetched.data {
        EntryData::Totp { secret } => assert_eq!(secret, "TESTSECRET"),
        _ => panic!("wrong variant"),
    }
}

// ---------------------------------------------------------------------------
// All five entry types in a single vault
// ---------------------------------------------------------------------------

#[test]
fn all_five_entry_types_coexist() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, master_key) = setup_vault(dir.path());
    let conn = db.connection();

    let _e1 = add_entry(conn, &master_key, &totp_params("TOTP Entry", "S1")).expect("totp");
    let _e2 = add_entry(conn, &master_key, &hotp_params("HOTP Entry", "S2", 0)).expect("hotp");
    let _e3 = add_entry(
        conn,
        &master_key,
        &seed_phrase_params("Seed", &["abandon", "ability"]),
    )
    .expect("seed");
    let _e4 = add_entry(
        conn,
        &master_key,
        &recovery_code_params("Recovery", &["CODE1"]),
    )
    .expect("recovery");
    let _e5 = add_entry(conn, &master_key, &secure_note_params("Note", "body")).expect("note");

    let items = list_entries(conn).expect("list should succeed");
    assert_eq!(items.len(), 5);

    let types: Vec<EntryType> = items.iter().map(|i| i.entry_type).collect();
    assert!(types.contains(&EntryType::Totp));
    assert!(types.contains(&EntryType::Hotp));
    assert!(types.contains(&EntryType::SeedPhrase));
    assert!(types.contains(&EntryType::RecoveryCode));
    assert!(types.contains(&EntryType::SecureNote));
}

// ---------------------------------------------------------------------------
// Entry ID is valid UUID v4
// ---------------------------------------------------------------------------

#[test]
fn entry_id_is_valid_uuid_v4() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, master_key) = setup_vault(dir.path());
    let conn = db.connection();

    let entry = add_entry(conn, &master_key, &totp_params("UUID Test", "SECRET"))
        .expect("add should succeed");

    // UUID v4 format: 8-4-4-4-12 hex chars with version=4 and variant=8/9/a/b.
    let parts: Vec<&str> = entry.id.split('-').collect();
    assert_eq!(parts.len(), 5, "UUID should have 5 parts");
    assert_eq!(parts[0].len(), 8);
    assert_eq!(parts[1].len(), 4);
    assert_eq!(parts[2].len(), 4);
    assert_eq!(parts[3].len(), 4);
    assert_eq!(parts[4].len(), 12);
    assert!(parts[2].starts_with('4'), "UUID version nibble should be 4");
}

// ---------------------------------------------------------------------------
// Timestamps are ISO 8601
// ---------------------------------------------------------------------------

#[test]
fn timestamps_are_iso8601() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, master_key) = setup_vault(dir.path());
    let conn = db.connection();

    let entry = add_entry(conn, &master_key, &totp_params("Time Test", "SECRET"))
        .expect("add should succeed");

    // ISO 8601 basic check: contains 'T' separator and 'Z' suffix.
    assert!(
        entry.created_at.contains('T'),
        "created_at should be ISO 8601"
    );
    assert!(
        entry.created_at.ends_with('Z'),
        "created_at should end with Z"
    );
    assert!(
        entry.updated_at.contains('T'),
        "updated_at should be ISO 8601"
    );
}

// ---------------------------------------------------------------------------
// Update with null issuer/folder_id (clear optional fields)
// ---------------------------------------------------------------------------

#[test]
fn update_clears_optional_fields() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, master_key) = setup_vault(dir.path());
    let conn = db.connection();

    let entry = add_entry(conn, &master_key, &totp_params("Clear Test", "SECRET"))
        .expect("add should succeed");
    assert!(entry.issuer.is_some());

    let updates = UpdateEntryParams {
        name: None,
        issuer: Some(None), // Explicitly clear issuer.
        folder_id: None,
        algorithm: None,
        digits: None,
        period: None,
        counter: None,
        pinned: None,
        data: None,
        tags: None,
    };
    let result =
        update_entry(conn, &master_key, &entry.id, &updates).expect("update should succeed");
    assert!(result.issuer.is_none(), "issuer should be cleared");

    let fetched = get_entry(conn, &master_key, &entry.id).expect("get should succeed");
    assert!(fetched.issuer.is_none(), "cleared issuer should persist");
}

// ---------------------------------------------------------------------------
// Credential CRUD roundtrip
// ---------------------------------------------------------------------------

fn credential_params(name: &str, password: &str) -> AddEntryParams {
    AddEntryParams {
        entry_type: EntryType::Credential,
        name: name.to_string(),
        issuer: Some("example.com".to_string()),
        folder_id: None,
        algorithm: Algorithm::SHA1,
        digits: 6,
        period: 30,
        counter: 0,
        pinned: false,
        tags: Vec::new(),
        data: EntryData::Credential {
            password: password.to_string(),
            username: Some("admin@example.com".to_string()),
            urls: vec!["https://example.com".to_string()],
            notes: Some("Test credential".to_string()),
            linked_totp_id: None,
            custom_fields: vec![CustomField {
                label: "API Key".to_string(),
                value: "sk-1234".to_string(),
                field_type: CustomFieldType::Hidden,
            }],
            password_history: Vec::new(),
            template: None,
        },
    }
}

#[test]
fn crud_roundtrip_credential() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, master_key) = setup_vault(dir.path());
    let conn = db.connection();

    // Add
    let entry = add_entry(
        conn,
        &master_key,
        &credential_params("GitHub Login", "s3cur3P@ss"),
    )
    .expect("add credential should succeed");
    assert_eq!(entry.name, "GitHub Login");
    assert_eq!(entry.entry_type, EntryType::Credential);

    // Get — verify all fields decrypt correctly
    let fetched = get_entry(conn, &master_key, &entry.id).expect("get should succeed");
    assert_eq!(fetched.name, "GitHub Login");
    match &fetched.data {
        EntryData::Credential {
            password,
            username,
            urls,
            notes,
            custom_fields,
            password_history,
            template,
            ..
        } => {
            assert_eq!(password, "s3cur3P@ss");
            assert_eq!(username.as_deref(), Some("admin@example.com"));
            assert_eq!(urls, &["https://example.com"]);
            assert_eq!(notes.as_deref(), Some("Test credential"));
            assert_eq!(custom_fields.len(), 1);
            assert_eq!(custom_fields[0].label, "API Key");
            assert_eq!(custom_fields[0].field_type, CustomFieldType::Hidden);
            assert!(password_history.is_empty());
            assert!(template.is_none());
        }
        _ => panic!("wrong variant — expected Credential"),
    }

    // Update password — should trigger password history
    let new_data = EntryData::Credential {
        password: "n3wP@ss!".to_string(),
        username: Some("admin@example.com".to_string()),
        urls: vec!["https://example.com".to_string()],
        notes: Some("Updated credential".to_string()),
        linked_totp_id: None,
        custom_fields: vec![CustomField {
            label: "API Key".to_string(),
            value: "sk-5678".to_string(),
            field_type: CustomFieldType::Hidden,
        }],
        password_history: vec![PasswordHistoryEntry {
            password: "s3cur3P@ss".to_string(),
            changed_at: "2026-02-15T00:00:00Z".to_string(),
        }],
        template: None,
    };

    let updates = UpdateEntryParams {
        name: Some("GitHub Login (Updated)".to_string()),
        issuer: None,
        folder_id: None,
        algorithm: None,
        digits: None,
        period: None,
        counter: None,
        pinned: Some(true),
        data: Some(new_data),
        tags: None,
    };
    let result =
        update_entry(conn, &master_key, &entry.id, &updates).expect("update should succeed");
    assert_eq!(result.name, "GitHub Login (Updated)");
    assert!(result.pinned);

    // Verify updated data decrypts correctly
    let fetched2 = get_entry(conn, &master_key, &entry.id).expect("get after update");
    match &fetched2.data {
        EntryData::Credential {
            password,
            notes,
            custom_fields,
            password_history,
            ..
        } => {
            assert_eq!(password, "n3wP@ss!");
            assert_eq!(notes.as_deref(), Some("Updated credential"));
            assert_eq!(custom_fields[0].value, "sk-5678");
            assert_eq!(password_history.len(), 1);
            assert_eq!(password_history[0].password, "s3cur3P@ss");
        }
        _ => panic!("wrong variant after update"),
    }

    // List should include the credential
    let items = list_entries(conn).expect("list should succeed");
    assert!(items
        .iter()
        .any(|i| i.id == entry.id && i.entry_type == EntryType::Credential));

    // Delete
    delete_entry(conn, &entry.id).expect("delete should succeed");
    assert!(get_entry(conn, &master_key, &entry.id).is_err());
}

#[test]
fn credential_username_column_syncs_on_add_and_update() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, master_key) = setup_vault(dir.path());
    let conn = db.connection();

    // Add credential with username → list should include username
    let entry = add_entry(
        conn,
        &master_key,
        &credential_params("Test Login", "pass123"),
    )
    .expect("add credential");
    let items = list_entries(conn).expect("list after add");
    let item = items.iter().find(|i| i.id == entry.id).expect("find entry");
    assert_eq!(item.username.as_deref(), Some("admin@example.com"));

    // Update with new username → list should reflect change
    let new_data = EntryData::Credential {
        password: "pass123".to_string(),
        username: Some("newuser@example.com".to_string()),
        urls: vec!["https://example.com".to_string()],
        notes: None,
        linked_totp_id: None,
        custom_fields: Vec::new(),
        password_history: Vec::new(),
        template: None,
    };
    let updates = UpdateEntryParams {
        name: None,
        issuer: None,
        folder_id: None,
        algorithm: None,
        digits: None,
        period: None,
        counter: None,
        pinned: None,
        data: Some(new_data),
        tags: None,
    };
    update_entry(conn, &master_key, &entry.id, &updates).expect("update username");
    let items2 = list_entries(conn).expect("list after update");
    let item2 = items2
        .iter()
        .find(|i| i.id == entry.id)
        .expect("find entry");
    assert_eq!(item2.username.as_deref(), Some("newuser@example.com"));

    // Update with username removed → list should show None
    let cleared_data = EntryData::Credential {
        password: "pass123".to_string(),
        username: None,
        urls: Vec::new(),
        notes: None,
        linked_totp_id: None,
        custom_fields: Vec::new(),
        password_history: Vec::new(),
        template: None,
    };
    let updates2 = UpdateEntryParams {
        name: None,
        issuer: None,
        folder_id: None,
        algorithm: None,
        digits: None,
        period: None,
        counter: None,
        pinned: None,
        data: Some(cleared_data),
        tags: None,
    };
    update_entry(conn, &master_key, &entry.id, &updates2).expect("clear username");
    let items3 = list_entries(conn).expect("list after clear");
    let item3 = items3
        .iter()
        .find(|i| i.id == entry.id)
        .expect("find entry");
    assert!(
        item3.username.is_none(),
        "username should be None after clearing"
    );
}

// ---------------------------------------------------------------------------
// Template field round-trip
// ---------------------------------------------------------------------------

#[test]
fn credential_template_field_round_trips() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, master_key) = setup_vault(dir.path());
    let conn = db.connection();

    // Add credential with template set
    let params = AddEntryParams {
        entry_type: EntryType::Credential,
        name: "My Card".to_string(),
        issuer: None,
        folder_id: None,
        algorithm: Algorithm::SHA1,
        digits: 6,
        period: 30,
        counter: 0,
        pinned: false,
        tags: Vec::new(),
        data: EntryData::Credential {
            password: "pass123".to_string(),
            username: None,
            urls: Vec::new(),
            notes: None,
            linked_totp_id: None,
            custom_fields: vec![CustomField {
                label: "Card Number".to_string(),
                value: "4111111111111111".to_string(),
                field_type: CustomFieldType::Hidden,
            }],
            password_history: Vec::new(),
            template: Some("credit_card".to_string()),
        },
    };
    let entry = add_entry(conn, &master_key, &params).expect("add credential with template");

    // Verify template is stored in encrypted data
    let fetched = get_entry(conn, &master_key, &entry.id).expect("get");
    match &fetched.data {
        EntryData::Credential { template, .. } => {
            assert_eq!(template.as_deref(), Some("credit_card"));
        }
        _ => panic!("wrong variant"),
    }

    // Verify template is available in list_entries (plaintext column)
    let items = list_entries(conn).expect("list");
    let item = items
        .iter()
        .find(|i| i.id == entry.id)
        .expect("find in list");
    assert_eq!(item.template.as_deref(), Some("credit_card"));
}

#[test]
fn credential_template_column_syncs_on_update() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, master_key) = setup_vault(dir.path());
    let conn = db.connection();

    // Add credential without template
    let params = credential_params("No Template", "pass");
    let entry = add_entry(conn, &master_key, &params).expect("add");

    let items = list_entries(conn).expect("list");
    let item = items.iter().find(|i| i.id == entry.id).expect("find");
    assert!(item.template.is_none(), "template should be None initially");

    // Update to set a template
    let new_data = EntryData::Credential {
        password: "pass".to_string(),
        username: None,
        urls: Vec::new(),
        notes: None,
        linked_totp_id: None,
        custom_fields: Vec::new(),
        password_history: Vec::new(),
        template: Some("ssh_key".to_string()),
    };
    let updates = UpdateEntryParams {
        name: None,
        issuer: None,
        folder_id: None,
        algorithm: None,
        digits: None,
        period: None,
        counter: None,
        pinned: None,
        data: Some(new_data),
        tags: None,
    };
    update_entry(conn, &master_key, &entry.id, &updates).expect("update with template");

    // Verify both encrypted data and plaintext column are updated
    let fetched = get_entry(conn, &master_key, &entry.id).expect("get after update");
    match &fetched.data {
        EntryData::Credential { template, .. } => {
            assert_eq!(template.as_deref(), Some("ssh_key"));
        }
        _ => panic!("wrong variant"),
    }

    let items2 = list_entries(conn).expect("list after update");
    let item2 = items2
        .iter()
        .find(|i| i.id == entry.id)
        .expect("find after update");
    assert_eq!(item2.template.as_deref(), Some("ssh_key"));
}
