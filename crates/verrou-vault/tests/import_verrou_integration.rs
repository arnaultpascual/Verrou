#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

//! Integration tests for `.verrou` vault import (restore).
//!
//! These tests exercise the full import pipeline:
//! export a vault → import into a different vault → verify data integrity.

use std::path::Path;

use verrou_crypto_core::kdf::{Argon2idParams, CalibratedPresets, KdfPreset};
use verrou_crypto_core::memory::SecretBytes;
use verrou_crypto_core::vault_format;
use verrou_vault::error::VaultError;
use verrou_vault::export::verrou_format::{export_vault, ExportVaultRequest};
use verrou_vault::import::verrou_format::{
    import_verrou_file, validate_verrou_import, DuplicateMode,
};
use verrou_vault::lifecycle::{self, CreateVaultRequest, UnlockVaultRequest};
use verrou_vault::{
    add_attachment, add_entry, create_folder, list_attachments, list_entries,
    list_folders_with_counts, AddEntryParams, Algorithm, EntryData, EntryType, VaultDb,
};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

const TEST_PASSWORD: &[u8] = b"test-import-password-42";
/// The export file is encrypted with the source vault's password
/// (export re-authenticates against the vault header).
const EXPORT_PASSWORD: &[u8] = TEST_PASSWORD;

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

/// Export a vault and return the raw .verrou bytes.
fn export_vault_bytes(
    db: &VaultDb,
    master_key: &SecretBytes<32>,
    vault_dir: &Path,
    password: &[u8],
) -> Vec<u8> {
    let req = ExportVaultRequest {
        password,
        master_key: master_key.expose(),
        vault_dir,
    };
    let result = export_vault(db.connection(), &req).expect("export should succeed");
    result.export_data
}

fn totp_params(name: &str, issuer: &str, secret: &str) -> AddEntryParams {
    AddEntryParams {
        entry_type: EntryType::Totp,
        name: name.to_string(),
        issuer: Some(issuer.to_string()),
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

// ---------------------------------------------------------------------------
// Test 1: Import from empty vault export
// ---------------------------------------------------------------------------

#[test]
fn import_empty_vault_succeeds() {
    let source_dir = tempfile::tempdir().unwrap();
    let (source_db, source_key) = setup_vault(source_dir.path());

    // Export empty vault.
    let export_data =
        export_vault_bytes(&source_db, &source_key, source_dir.path(), EXPORT_PASSWORD);

    // Create target vault.
    let target_dir = tempfile::tempdir().unwrap();
    let (target_db, target_key) = setup_vault(target_dir.path());

    // Validate.
    let preview = validate_verrou_import(target_db.connection(), &export_data, EXPORT_PASSWORD)
        .expect("validation should succeed");

    assert_eq!(preview.total_entries, 0);
    assert_eq!(preview.total_folders, 0);
    assert_eq!(preview.total_attachments, 0);
    assert_eq!(preview.duplicate_count, 0);

    // Import.
    let result = import_verrou_file(
        target_db.connection(),
        &target_key,
        &export_data,
        EXPORT_PASSWORD,
        target_dir.path(),
        DuplicateMode::Skip,
    )
    .expect("import should succeed");

    assert_eq!(result.imported_entries, 0);
    assert_eq!(result.imported_folders, 0);
    assert_eq!(result.imported_attachments, 0);
}

// ---------------------------------------------------------------------------
// Test 2: Full roundtrip — export then import entries
// ---------------------------------------------------------------------------

#[test]
fn import_entries_from_export_file() {
    let source_dir = tempfile::tempdir().unwrap();
    let (source_db, source_key) = setup_vault(source_dir.path());

    // Add entries to source vault.
    add_entry(
        source_db.connection(),
        &source_key,
        &totp_params("GitHub", "github.com", "JBSWY3DPEHPK3PXP"),
    )
    .unwrap();
    add_entry(
        source_db.connection(),
        &source_key,
        &totp_params("GitLab", "gitlab.com", "KRSXG5CTMVRXEZLU"),
    )
    .unwrap();
    add_entry(
        source_db.connection(),
        &source_key,
        &note_params("Server Notes", "root password: hunter2"),
    )
    .unwrap();

    // Export.
    let export_data =
        export_vault_bytes(&source_db, &source_key, source_dir.path(), EXPORT_PASSWORD);

    // Create empty target vault.
    let target_dir = tempfile::tempdir().unwrap();
    let (target_db, target_key) = setup_vault(target_dir.path());

    // Validate.
    let preview = validate_verrou_import(target_db.connection(), &export_data, EXPORT_PASSWORD)
        .expect("validation should succeed");

    assert_eq!(preview.total_entries, 3);
    assert_eq!(preview.duplicate_count, 0);

    // Import.
    let result = import_verrou_file(
        target_db.connection(),
        &target_key,
        &export_data,
        EXPORT_PASSWORD,
        target_dir.path(),
        DuplicateMode::Skip,
    )
    .expect("import should succeed");

    assert_eq!(result.imported_entries, 3);

    // Verify entries exist in target vault.
    let entries = list_entries(target_db.connection()).unwrap();
    assert_eq!(entries.len(), 3);

    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&"GitHub"));
    assert!(names.contains(&"GitLab"));
    assert!(names.contains(&"Server Notes"));
}

// ---------------------------------------------------------------------------
// Test 3: Wrong password is rejected
// ---------------------------------------------------------------------------

#[test]
fn import_fails_with_wrong_password() {
    let source_dir = tempfile::tempdir().unwrap();
    let (source_db, source_key) = setup_vault(source_dir.path());

    add_entry(
        source_db.connection(),
        &source_key,
        &totp_params("Test", "test.com", "JBSWY3DPEHPK3PXP"),
    )
    .unwrap();

    let export_data =
        export_vault_bytes(&source_db, &source_key, source_dir.path(), EXPORT_PASSWORD);

    let target_dir = tempfile::tempdir().unwrap();
    let (target_db, _target_key) = setup_vault(target_dir.path());

    let result = validate_verrou_import(target_db.connection(), &export_data, b"wrong-password");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, VaultError::InvalidPassword),
        "expected InvalidPassword, got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 4: Version mismatch detection
// ---------------------------------------------------------------------------

#[test]
fn import_rejects_newer_format_version() {
    let source_dir = tempfile::tempdir().unwrap();
    let (source_db, source_key) = setup_vault(source_dir.path());

    let export_data =
        export_vault_bytes(&source_db, &source_key, source_dir.path(), EXPORT_PASSWORD);

    // Tamper with the header to set a higher version.
    // The header is JSON after the first 8 bytes (4 magic + 4 length).
    let header = vault_format::parse_header_only(&export_data).unwrap();
    assert_eq!(header.version, 1);

    // Find "version":1 in the header JSON and change to "version":99.
    let header_start = 8; // 4 magic + 4 u32 LE header length
    let header_len = u32::from_le_bytes([
        export_data[4],
        export_data[5],
        export_data[6],
        export_data[7],
    ]) as usize;
    let header_bytes = &export_data[header_start..header_start + header_len];
    let header_json = String::from_utf8_lossy(header_bytes);
    let new_json = header_json.replace("\"version\":1", "\"version\":99");
    let new_bytes = new_json.as_bytes();

    // Replace header bytes in-place (same length since "1" → "99" changes length).
    // Since the length changes, we need to reconstruct the file.
    let mut new_export = Vec::new();
    new_export.extend_from_slice(&export_data[..4]); // magic
    #[allow(clippy::cast_possible_truncation)]
    let header_len_bytes = (new_bytes.len() as u32).to_le_bytes();
    new_export.extend_from_slice(&header_len_bytes); // new header length
    new_export.extend_from_slice(new_bytes); // new header JSON
    new_export.extend_from_slice(&export_data[header_start + header_len..]); // rest of file

    let target_dir = tempfile::tempdir().unwrap();
    let (target_db, _target_key) = setup_vault(target_dir.path());

    let result = validate_verrou_import(target_db.connection(), &new_export, EXPORT_PASSWORD);
    assert!(result.is_err());
    let err = result.unwrap_err();
    // The version check fires in vault_format::parse_header_only() at the crypto
    // layer, producing VaultError::Crypto(VaultFormat(..)), or the import code's
    // own check produces VaultError::Import(..). Accept either.
    match &err {
        VaultError::Import(msg) => {
            assert!(
                msg.contains("newer version") || msg.contains("newer"),
                "error should mention newer version, got: {msg}"
            );
        }
        VaultError::Crypto(inner) => {
            let msg = format!("{inner}");
            assert!(
                msg.contains("newer") || msg.contains("version"),
                "crypto error should mention version, got: {msg}"
            );
        }
        _ => panic!("expected Import or Crypto error, got: {err:?}"),
    }
}

// ---------------------------------------------------------------------------
// Test 5: Duplicate detection — skip mode
// ---------------------------------------------------------------------------

#[test]
fn import_skip_mode_skips_duplicates() {
    let source_dir = tempfile::tempdir().unwrap();
    let (source_db, source_key) = setup_vault(source_dir.path());

    add_entry(
        source_db.connection(),
        &source_key,
        &totp_params("GitHub", "github.com", "JBSWY3DPEHPK3PXP"),
    )
    .unwrap();
    add_entry(
        source_db.connection(),
        &source_key,
        &totp_params("GitLab", "gitlab.com", "KRSXG5CTMVRXEZLU"),
    )
    .unwrap();

    let export_data =
        export_vault_bytes(&source_db, &source_key, source_dir.path(), EXPORT_PASSWORD);

    // Create target vault with one duplicate entry.
    let target_dir = tempfile::tempdir().unwrap();
    let (target_db, target_key) = setup_vault(target_dir.path());
    add_entry(
        target_db.connection(),
        &target_key,
        &totp_params("GitHub", "github.com", "DIFFERENTKEY12345"),
    )
    .unwrap();

    // Validate — should detect 1 duplicate.
    let preview = validate_verrou_import(target_db.connection(), &export_data, EXPORT_PASSWORD)
        .expect("validation should succeed");
    assert_eq!(preview.total_entries, 2);
    assert_eq!(preview.duplicate_count, 1);
    assert_eq!(preview.duplicates[0].name, "GitHub");

    // Import with Skip mode.
    let result = import_verrou_file(
        target_db.connection(),
        &target_key,
        &export_data,
        EXPORT_PASSWORD,
        target_dir.path(),
        DuplicateMode::Skip,
    )
    .expect("import should succeed");

    assert_eq!(
        result.imported_entries, 1,
        "only non-duplicate should be imported"
    );
    assert_eq!(result.skipped_duplicates, 1, "duplicate should be skipped");

    // Verify only 2 entries total (1 original + 1 imported).
    let entries = list_entries(target_db.connection()).unwrap();
    assert_eq!(entries.len(), 2);
}

// ---------------------------------------------------------------------------
// Test 6: Duplicate detection — replace mode
// ---------------------------------------------------------------------------

#[test]
fn import_replace_mode_replaces_duplicates() {
    let source_dir = tempfile::tempdir().unwrap();
    let (source_db, source_key) = setup_vault(source_dir.path());

    add_entry(
        source_db.connection(),
        &source_key,
        &totp_params("GitHub", "github.com", "NEWSECRETKEY12345"),
    )
    .unwrap();
    add_entry(
        source_db.connection(),
        &source_key,
        &totp_params("GitLab", "gitlab.com", "KRSXG5CTMVRXEZLU"),
    )
    .unwrap();

    let export_data =
        export_vault_bytes(&source_db, &source_key, source_dir.path(), EXPORT_PASSWORD);

    // Target vault has an old version of GitHub.
    let target_dir = tempfile::tempdir().unwrap();
    let (target_db, target_key) = setup_vault(target_dir.path());
    add_entry(
        target_db.connection(),
        &target_key,
        &totp_params("GitHub", "github.com", "OLDSECRETKEY12345"),
    )
    .unwrap();

    // Import with Replace mode.
    let result = import_verrou_file(
        target_db.connection(),
        &target_key,
        &export_data,
        EXPORT_PASSWORD,
        target_dir.path(),
        DuplicateMode::Replace,
    )
    .expect("import should succeed");

    // imported_entries counts all newly inserted entries:
    // GitHub (replaced = deleted + re-inserted) + GitLab (new) = 2.
    assert_eq!(
        result.imported_entries, 2,
        "both entries imported (1 replacement + 1 new)"
    );
    assert_eq!(result.replaced_entries, 1, "one duplicate was replaced");

    // Verify 2 entries total (replaced GitHub + new GitLab).
    let entries = list_entries(target_db.connection()).unwrap();
    assert_eq!(entries.len(), 2);
}

// ---------------------------------------------------------------------------
// Test 7: Folders are imported with correct remapping
// ---------------------------------------------------------------------------

#[test]
fn import_folders_with_remapping() {
    let source_dir = tempfile::tempdir().unwrap();
    let (source_db, source_key) = setup_vault(source_dir.path());

    // Create folders in source.
    let work_folder = create_folder(source_db.connection(), "Work").unwrap();

    // Add entry in folder.
    let mut params = totp_params("Work GitHub", "github.com", "JBSWY3DPEHPK3PXP");
    params.folder_id = Some(work_folder.id);
    add_entry(source_db.connection(), &source_key, &params).unwrap();

    let export_data =
        export_vault_bytes(&source_db, &source_key, source_dir.path(), EXPORT_PASSWORD);

    // Target vault is empty.
    let target_dir = tempfile::tempdir().unwrap();
    let (target_db, target_key) = setup_vault(target_dir.path());

    let result = import_verrou_file(
        target_db.connection(),
        &target_key,
        &export_data,
        EXPORT_PASSWORD,
        target_dir.path(),
        DuplicateMode::Skip,
    )
    .expect("import should succeed");

    assert_eq!(result.imported_entries, 1);
    assert_eq!(result.imported_folders, 1);

    // Verify folder exists in target.
    let folders = list_folders_with_counts(target_db.connection()).unwrap();
    assert_eq!(folders.len(), 1);
    assert_eq!(folders[0].folder.name, "Work");
    assert_eq!(
        folders[0].entry_count, 1,
        "folder should contain the imported entry"
    );
}

// ---------------------------------------------------------------------------
// Test 8: Folder deduplication by name
// ---------------------------------------------------------------------------

#[test]
fn import_reuses_existing_folders_by_name() {
    let source_dir = tempfile::tempdir().unwrap();
    let (source_db, source_key) = setup_vault(source_dir.path());

    let folder = create_folder(source_db.connection(), "Work").unwrap();
    let mut params = totp_params("Work Entry", "work.com", "JBSWY3DPEHPK3PXP");
    params.folder_id = Some(folder.id);
    add_entry(source_db.connection(), &source_key, &params).unwrap();

    let export_data =
        export_vault_bytes(&source_db, &source_key, source_dir.path(), EXPORT_PASSWORD);

    // Target vault already has a "Work" folder.
    let target_dir = tempfile::tempdir().unwrap();
    let (target_db, target_key) = setup_vault(target_dir.path());
    create_folder(target_db.connection(), "Work").unwrap();

    let result = import_verrou_file(
        target_db.connection(),
        &target_key,
        &export_data,
        EXPORT_PASSWORD,
        target_dir.path(),
        DuplicateMode::Skip,
    )
    .expect("import should succeed");

    assert_eq!(
        result.imported_folders, 0,
        "existing folder should be reused, not created"
    );

    // Verify only 1 folder total (reused).
    let folders = list_folders_with_counts(target_db.connection()).unwrap();
    assert_eq!(folders.len(), 1);
    assert_eq!(folders[0].folder.name, "Work");
    assert_eq!(
        folders[0].entry_count, 1,
        "entry should be assigned to existing folder"
    );
}

// ---------------------------------------------------------------------------
// Test 9: Backup is created before import
// ---------------------------------------------------------------------------

#[test]
fn import_creates_backup_before_modification() {
    let source_dir = tempfile::tempdir().unwrap();
    let (source_db, source_key) = setup_vault(source_dir.path());

    add_entry(
        source_db.connection(),
        &source_key,
        &totp_params("Test", "test.com", "JBSWY3DPEHPK3PXP"),
    )
    .unwrap();

    let export_data =
        export_vault_bytes(&source_db, &source_key, source_dir.path(), EXPORT_PASSWORD);

    let target_dir = tempfile::tempdir().unwrap();
    let (target_db, target_key) = setup_vault(target_dir.path());

    // No backups should exist before import.
    let backups_before = verrou_vault::list_backups(target_dir.path()).unwrap();
    assert!(
        backups_before.is_empty(),
        "no backups should exist before import"
    );

    // Import.
    import_verrou_file(
        target_db.connection(),
        &target_key,
        &export_data,
        EXPORT_PASSWORD,
        target_dir.path(),
        DuplicateMode::Skip,
    )
    .expect("import should succeed");

    // Verify backup was created.
    let backups_after = verrou_vault::list_backups(target_dir.path()).unwrap();
    assert_eq!(
        backups_after.len(),
        1,
        "one backup should be created during import"
    );
}

// ---------------------------------------------------------------------------
// Test 10: Multiple entry types preserved through roundtrip
// ---------------------------------------------------------------------------

#[test]
fn import_preserves_all_entry_types() {
    let source_dir = tempfile::tempdir().unwrap();
    let (source_db, source_key) = setup_vault(source_dir.path());

    // TOTP
    add_entry(
        source_db.connection(),
        &source_key,
        &totp_params("My TOTP", "example.com", "JBSWY3DPEHPK3PXP"),
    )
    .unwrap();

    // Secure note
    add_entry(
        source_db.connection(),
        &source_key,
        &note_params("My Note", "secret stuff"),
    )
    .unwrap();

    // Seed phrase
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
    add_entry(source_db.connection(), &source_key, &seed_params).unwrap();

    let export_data =
        export_vault_bytes(&source_db, &source_key, source_dir.path(), EXPORT_PASSWORD);

    // Import into empty target.
    let target_dir = tempfile::tempdir().unwrap();
    let (target_db, target_key) = setup_vault(target_dir.path());

    let result = import_verrou_file(
        target_db.connection(),
        &target_key,
        &export_data,
        EXPORT_PASSWORD,
        target_dir.path(),
        DuplicateMode::Skip,
    )
    .expect("import should succeed");

    assert_eq!(result.imported_entries, 3);

    let entries = list_entries(target_db.connection()).unwrap();
    let types: Vec<EntryType> = entries.iter().map(|e| e.entry_type).collect();
    assert!(types.contains(&EntryType::Totp));
    assert!(types.contains(&EntryType::SecureNote));
    assert!(types.contains(&EntryType::SeedPhrase));
}

// ---------------------------------------------------------------------------
// Test 11: Attachments survive the roundtrip
// ---------------------------------------------------------------------------

#[test]
fn import_preserves_attachments() {
    let source_dir = tempfile::tempdir().unwrap();
    let (source_db, source_key) = setup_vault(source_dir.path());

    // Add an entry with an attachment.
    let entry = add_entry(
        source_db.connection(),
        &source_key,
        &note_params("Secure Doc", "has an attachment"),
    )
    .unwrap();

    let file_data = b"Hello, this is a test attachment!";
    add_attachment(
        source_db.connection(),
        &source_key,
        &entry.id,
        "readme.txt",
        "text/plain",
        file_data,
    )
    .unwrap();

    // Verify attachment exists in source.
    let source_attachments = list_attachments(source_db.connection(), &entry.id).unwrap();
    assert_eq!(source_attachments.len(), 1);
    assert_eq!(source_attachments[0].filename, "readme.txt");

    // Export.
    let export_data =
        export_vault_bytes(&source_db, &source_key, source_dir.path(), EXPORT_PASSWORD);

    // Import into empty target.
    let target_dir = tempfile::tempdir().unwrap();
    let (target_db, target_key) = setup_vault(target_dir.path());

    let preview = validate_verrou_import(target_db.connection(), &export_data, EXPORT_PASSWORD)
        .expect("validation should succeed");
    assert_eq!(preview.total_entries, 1);
    assert_eq!(preview.total_attachments, 1);

    let result = import_verrou_file(
        target_db.connection(),
        &target_key,
        &export_data,
        EXPORT_PASSWORD,
        target_dir.path(),
        DuplicateMode::Skip,
    )
    .expect("import should succeed");

    assert_eq!(result.imported_entries, 1);
    assert_eq!(result.imported_attachments, 1);

    // Verify attachment exists in target (under the remapped entry ID).
    let target_entries = list_entries(target_db.connection()).unwrap();
    assert_eq!(target_entries.len(), 1);

    let target_attachments =
        list_attachments(target_db.connection(), &target_entries[0].id).unwrap();
    assert_eq!(target_attachments.len(), 1);
    assert_eq!(target_attachments[0].filename, "readme.txt");
    assert_eq!(target_attachments[0].mime_type, "text/plain");
    #[allow(clippy::cast_possible_wrap)]
    let expected_size = file_data.len() as i64;
    assert_eq!(target_attachments[0].size_bytes, expected_size);
}
