#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects
)]

//! Integration tests for `.verrou` vault import (restore).
//!
//! These tests exercise the full import pipeline:
//! export a vault → import into a different vault → verify data integrity.

use std::path::Path;

use verrou_crypto_core::kdf::{Argon2idParams, CalibratedPresets, KdfPreset};
use verrou_crypto_core::memory::SecretBytes;
use verrou_crypto_core::vault_format;
use verrou_vault::error::VaultError;
use verrou_vault::export::envelope;
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
    let preview = validate_verrou_import(
        target_db.connection(),
        &export_data,
        EXPORT_PASSWORD,
        Some(&target_key),
    )
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
    let preview = validate_verrou_import(
        target_db.connection(),
        &export_data,
        EXPORT_PASSWORD,
        Some(&target_key),
    )
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

    // Pass None so the envelope's password fallback is exercised directly
    // (a wrong importing-vault key would otherwise also fall back, but None
    // makes the intent explicit: this asserts the password path rejects).
    let result = validate_verrou_import(
        target_db.connection(),
        &export_data,
        b"wrong-password",
        None,
    );
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

    // `export_data` is now a PQ envelope wrapping the raw `vault_format` blob.
    // To exercise the inner version check, we extract the inner blob, bump its
    // header version to 99, then re-assemble a *validly signed* envelope around
    // the tampered inner blob (reusing the original KEM fields). The signature
    // must pass so the version check — not the signature check — is what fires.
    let parsed = envelope::parse_envelope(&export_data).expect("envelope should parse");

    let inner = parsed.inner_blob;
    let header = vault_format::parse_header_only(inner).unwrap();
    assert_eq!(header.version, 1);

    // Find "version":1 in the inner header JSON and change to "version":99.
    let header_start = 8; // 4 magic + 4 u32 LE header length
    let header_len = u32::from_le_bytes([inner[4], inner[5], inner[6], inner[7]]) as usize;
    let header_bytes = &inner[header_start..header_start + header_len];
    let header_json = String::from_utf8_lossy(header_bytes);
    let new_json = header_json.replace("\"version\":1", "\"version\":99");
    let new_bytes = new_json.as_bytes();

    // Reconstruct the tampered inner blob (length changes "1" → "99").
    let mut new_inner = Vec::new();
    new_inner.extend_from_slice(&inner[..4]); // magic
    #[allow(clippy::cast_possible_truncation)]
    let header_len_bytes = (new_bytes.len() as u32).to_le_bytes();
    new_inner.extend_from_slice(&header_len_bytes);
    new_inner.extend_from_slice(new_bytes);
    new_inner.extend_from_slice(&inner[header_start + header_len..]);

    // Re-wrap into a validly signed envelope around the tampered inner blob.
    let sign_kp = verrou_crypto_core::signing::derive_signing_keypair(
        source_key.expose(),
        envelope::VAULT_SIGN_CONTEXT,
    )
    .unwrap();
    let parts = envelope::EnvelopeParts {
        kem_ciphertext: &parsed.kem_ciphertext,
        wrapped_cek: &parsed.wrapped_cek,
        signing_public: &sign_kp.public,
        inner_blob: &new_inner,
    };
    let signed = envelope::assemble_signed_portion(&parts).unwrap();
    let sig = verrou_crypto_core::signing::sign(&signed, &sign_kp).unwrap();
    let new_export = envelope::finish_envelope(signed, &sig).unwrap();

    let target_dir = tempfile::tempdir().unwrap();
    let (target_db, _target_key) = setup_vault(target_dir.path());

    // None → password fallback path; the inner version check rejects it.
    let result = validate_verrou_import(target_db.connection(), &new_export, EXPORT_PASSWORD, None);
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
    let preview = validate_verrou_import(
        target_db.connection(),
        &export_data,
        EXPORT_PASSWORD,
        Some(&target_key),
    )
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

    let preview = validate_verrou_import(
        target_db.connection(),
        &export_data,
        EXPORT_PASSWORD,
        Some(&target_key),
    )
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

// ---------------------------------------------------------------------------
// PQ-B: post-quantum export envelope tests
// ---------------------------------------------------------------------------

/// An exported file is a PQ envelope (magic `VRENV1`), not a raw `vault_format`.
#[test]
fn export_produces_pq_envelope() {
    let dir = tempfile::tempdir().unwrap();
    let (db, key) = setup_vault(dir.path());
    let export_data = export_vault_bytes(&db, &key, dir.path(), EXPORT_PASSWORD);

    assert!(
        envelope::has_envelope_magic(&export_data),
        "export must be wrapped in a PQ envelope"
    );
    // And the envelope parses + its signature verifies with the embedded key.
    let parsed = envelope::parse_envelope(&export_data).expect("envelope parses");
    verrou_crypto_core::signing::verify(
        parsed.signed_portion,
        &parsed.signature,
        &parsed.signing_public,
    )
    .expect("embedded signature must verify");
}

/// Re-importing into the SAME vault recovers the content key via the KEM path,
/// with NO password needed — proven by passing a deliberately wrong password.
#[test]
fn import_via_kem_path_same_vault_without_password() {
    let dir = tempfile::tempdir().unwrap();
    let (db, key) = setup_vault(dir.path());

    add_entry(
        db.connection(),
        &key,
        &totp_params("KemEntry", "kem.example", "JBSWY3DPEHPK3PXP"),
    )
    .unwrap();

    let export_data = export_vault_bytes(&db, &key, dir.path(), EXPORT_PASSWORD);

    // Validate with a WRONG password but the correct (same-vault) master key.
    // The KEM path must recover the CEK, so validation succeeds regardless.
    let preview = validate_verrou_import(
        db.connection(),
        &export_data,
        b"this-password-is-deliberately-wrong",
        Some(&key),
    )
    .expect("KEM path should recover CEK without a valid password");
    assert_eq!(preview.total_entries, 1);

    // Import back into the same vault (Skip → existing entry is a duplicate).
    let result = import_verrou_file(
        db.connection(),
        &key,
        &export_data,
        b"still-the-wrong-password",
        dir.path(),
        DuplicateMode::Skip,
    )
    .expect("KEM-path import should succeed without a valid password");
    // The single entry already exists → skipped as a duplicate.
    assert_eq!(result.skipped_duplicates, 1);
    assert_eq!(result.imported_entries, 0);
}

/// Cross-vault import (different master key) succeeds via the password path:
/// the KEM path fails (wrong vault) and falls back to the inner password slot.
#[test]
fn import_cross_vault_falls_back_to_password() {
    let source_dir = tempfile::tempdir().unwrap();
    let (source_db, source_key) = setup_vault(source_dir.path());
    add_entry(
        source_db.connection(),
        &source_key,
        &totp_params("CrossVault", "x.example", "JBSWY3DPEHPK3PXP"),
    )
    .unwrap();
    let export_data =
        export_vault_bytes(&source_db, &source_key, source_dir.path(), EXPORT_PASSWORD);

    // Different target vault → different KEM key. KEM unwrap fails, password
    // fallback (correct EXPORT_PASSWORD) succeeds.
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
    .expect("cross-vault import should succeed via password fallback");
    assert_eq!(result.imported_entries, 1);

    let entries = list_entries(target_db.connection()).unwrap();
    assert!(entries.iter().any(|e| e.name == "CrossVault"));
}

/// A tampered envelope signature is rejected fail-closed, before any decryption.
#[test]
fn import_rejects_tampered_signature_fail_closed() {
    let source_dir = tempfile::tempdir().unwrap();
    let (source_db, source_key) = setup_vault(source_dir.path());
    add_entry(
        source_db.connection(),
        &source_key,
        &totp_params("Sig", "sig.example", "JBSWY3DPEHPK3PXP"),
    )
    .unwrap();
    let mut export_data =
        export_vault_bytes(&source_db, &source_key, source_dir.path(), EXPORT_PASSWORD);

    // Flip the final byte — inside the trailing signature.
    let last = export_data.len() - 1;
    export_data[last] ^= 0xFF;

    let target_dir = tempfile::tempdir().unwrap();
    let (target_db, target_key) = setup_vault(target_dir.path());

    // Both same-vault-key and password are irrelevant: the signature check
    // fires first and aborts the import.
    let result = validate_verrou_import(
        target_db.connection(),
        &export_data,
        EXPORT_PASSWORD,
        Some(&target_key),
    );
    assert!(result.is_err(), "tampered signature must be rejected");
    match result.unwrap_err() {
        VaultError::Import(msg) => {
            assert!(
                msg.contains("signature") || msg.contains("envelope"),
                "expected a signature/envelope rejection, got: {msg}"
            );
        }
        other => panic!("expected Import error, got: {other:?}"),
    }
}

/// A tampered envelope BODY (inner blob) is rejected fail-closed by the
/// signature check, before any decryption is attempted.
#[test]
fn import_rejects_tampered_body_fail_closed() {
    let source_dir = tempfile::tempdir().unwrap();
    let (source_db, source_key) = setup_vault(source_dir.path());
    add_entry(
        source_db.connection(),
        &source_key,
        &totp_params("Body", "body.example", "JBSWY3DPEHPK3PXP"),
    )
    .unwrap();
    let export_data =
        export_vault_bytes(&source_db, &source_key, source_dir.path(), EXPORT_PASSWORD);

    // Flip a byte deep inside the inner-blob region (well past the header and
    // the KEM/signing-key fields, but before the trailing signature).
    let parsed = envelope::parse_envelope(&export_data).unwrap();
    let inner_len = parsed.inner_blob.len();
    assert!(inner_len > 0);
    // Locate the inner blob within the full buffer and flip a middle byte.
    let signed_len = parsed.signed_portion.len();
    let flip_at = signed_len - (inner_len / 2);
    let mut tampered = export_data.clone();
    tampered[flip_at] ^= 0xFF;

    let target_dir = tempfile::tempdir().unwrap();
    let (target_db, target_key) = setup_vault(target_dir.path());

    let result = validate_verrou_import(
        target_db.connection(),
        &tampered,
        EXPORT_PASSWORD,
        Some(&target_key),
    );
    assert!(result.is_err(), "tampered body must be rejected");
    assert!(
        matches!(result.unwrap_err(), VaultError::Import(_)),
        "tampered body should yield an Import error (fail-closed)"
    );
}

/// A non-envelope file (e.g. a stripped inner `vault_format` blob) is rejected.
/// Verrou exports are always PQ envelopes — there is no pre-launch installed
/// base of the old raw format, and a mandatory envelope guarantees every import
/// is signature-verified and KEM-wrapped.
#[test]
fn import_rejects_non_envelope_file() {
    let source_dir = tempfile::tempdir().unwrap();
    let (source_db, source_key) = setup_vault(source_dir.path());
    add_entry(
        source_db.connection(),
        &source_key,
        &totp_params("Legacy", "legacy.example", "JBSWY3DPEHPK3PXP"),
    )
    .unwrap();
    let export_data =
        export_vault_bytes(&source_db, &source_key, source_dir.path(), EXPORT_PASSWORD);

    // Strip the envelope to obtain a bare inner `vault_format` blob.
    let inner = envelope::parse_envelope(&export_data)
        .unwrap()
        .inner_blob
        .to_vec();
    assert!(
        !envelope::has_envelope_magic(&inner),
        "inner blob must not carry the envelope magic"
    );

    let target_dir = tempfile::tempdir().unwrap();
    let (target_db, target_key) = setup_vault(target_dir.path());

    // A non-envelope file must be rejected by both validate and import.
    let validate = validate_verrou_import(
        target_db.connection(),
        &inner,
        EXPORT_PASSWORD,
        Some(&target_key),
    );
    assert!(
        validate.is_err(),
        "non-envelope file must be rejected at validate"
    );

    let imported = import_verrou_file(
        target_db.connection(),
        &target_key,
        &inner,
        EXPORT_PASSWORD,
        target_dir.path(),
        DuplicateMode::Skip,
    );
    assert!(
        imported.is_err(),
        "non-envelope file must be rejected at import"
    );
}
