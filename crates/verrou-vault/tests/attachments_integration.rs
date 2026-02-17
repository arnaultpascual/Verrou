#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

//! Integration tests for file attachment CRUD operations.
//!
//! These tests exercise the full attachment lifecycle: add, list, get+decrypt,
//! delete, and cascade deletion when the parent entry is removed.

use std::path::Path;

use verrou_crypto_core::kdf::{Argon2idParams, CalibratedPresets, KdfPreset};
use verrou_crypto_core::memory::SecretBytes;
use verrou_vault::error::VaultError;
use verrou_vault::lifecycle::{self, CreateVaultRequest};
use verrou_vault::{
    add_attachment, add_entry, count_attachments, delete_attachment, delete_entry, get_attachment,
    list_attachments, AddEntryParams, Algorithm, EntryData, EntryType,
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

fn setup_vault(dir: &Path) -> (verrou_vault::VaultDb, SecretBytes<32>) {
    let password = b"test-password-for-attachments";
    let calibrated = test_calibrated();
    let req = CreateVaultRequest {
        password,
        preset: KdfPreset::Fast,
        vault_dir: dir,
        calibrated: &calibrated,
    };
    lifecycle::create_vault(&req).expect("vault creation");

    let unlock_req = lifecycle::UnlockVaultRequest {
        password,
        vault_dir: dir,
    };
    let result = lifecycle::unlock_vault(&unlock_req).expect("vault unlock");
    (result.db, result.master_key)
}

fn credential_params(name: &str) -> AddEntryParams {
    AddEntryParams {
        entry_type: EntryType::Credential,
        name: name.to_string(),
        issuer: None,
        folder_id: None,
        algorithm: Algorithm::SHA1,
        digits: 6,
        period: 30,
        counter: 0,
        pinned: false,
        tags: Vec::new(),
        data: EntryData::Credential {
            password: "test-password".to_string(),
            username: Some("user@example.com".to_string()),
            urls: vec!["https://example.com".to_string()],
            notes: None,
            linked_totp_id: None,
            custom_fields: Vec::new(),
            password_history: Vec::new(),
            template: None,
        },
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn add_and_list_attachments() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, master_key) = setup_vault(dir.path());
    let conn = db.connection();

    let entry = add_entry(conn, &master_key, &credential_params("GitHub")).expect("add entry");

    // Add an attachment.
    let content = b"SSH private key content here";
    let meta = add_attachment(
        conn,
        &master_key,
        &entry.id,
        "id_ed25519",
        "application/octet-stream",
        content,
    )
    .expect("add attachment");

    assert_eq!(meta.filename, "id_ed25519");
    #[allow(clippy::cast_possible_wrap)]
    {
        assert_eq!(meta.size_bytes, content.len() as i64);
    }

    // List attachments.
    let list = list_attachments(conn, &entry.id).expect("list");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].id, meta.id);
    assert_eq!(list[0].filename, "id_ed25519");
}

#[test]
fn get_and_decrypt_attachment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, master_key) = setup_vault(dir.path());
    let conn = db.connection();

    let entry = add_entry(conn, &master_key, &credential_params("GitLab")).expect("add entry");

    let content = b"Certificate PEM content\n-----BEGIN CERTIFICATE-----\nMIIBxTCCA...";
    let meta = add_attachment(
        conn,
        &master_key,
        &entry.id,
        "cert.pem",
        "application/x-pem-file",
        content,
    )
    .expect("add attachment");

    // Get and decrypt.
    let (fetched_meta, decrypted) = get_attachment(conn, &master_key, &meta.id).expect("get");
    assert_eq!(fetched_meta.filename, "cert.pem");
    assert_eq!(decrypted, content);
}

#[test]
fn delete_attachment_removes_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, master_key) = setup_vault(dir.path());
    let conn = db.connection();

    let entry = add_entry(conn, &master_key, &credential_params("AWS")).expect("add entry");

    let meta = add_attachment(
        conn,
        &master_key,
        &entry.id,
        "key.pem",
        "application/x-pem-file",
        b"key data",
    )
    .expect("add");

    assert_eq!(count_attachments(conn, &entry.id).expect("count"), 1);

    delete_attachment(conn, &meta.id).expect("delete");

    assert_eq!(count_attachments(conn, &entry.id).expect("count"), 0);
    assert!(list_attachments(conn, &entry.id).expect("list").is_empty());
}

#[test]
fn delete_nonexistent_attachment_errors() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, _master_key) = setup_vault(dir.path());
    let conn = db.connection();

    let err = delete_attachment(conn, "nonexistent-id").unwrap_err();
    assert!(matches!(err, VaultError::AttachmentNotFound(_)));
}

#[test]
fn cascade_delete_on_entry_removal() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, master_key) = setup_vault(dir.path());
    let conn = db.connection();

    let entry = add_entry(conn, &master_key, &credential_params("Heroku")).expect("add entry");

    add_attachment(
        conn,
        &master_key,
        &entry.id,
        "file1.txt",
        "text/plain",
        b"content1",
    )
    .expect("add 1");
    add_attachment(
        conn,
        &master_key,
        &entry.id,
        "file2.txt",
        "text/plain",
        b"content2",
    )
    .expect("add 2");

    assert_eq!(count_attachments(conn, &entry.id).expect("count"), 2);

    // Delete the parent entry — cascade should remove attachments.
    delete_entry(conn, &entry.id).expect("delete entry");

    assert_eq!(count_attachments(conn, &entry.id).expect("count"), 0);
}

#[test]
fn file_size_limit_enforced() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, master_key) = setup_vault(dir.path());
    let conn = db.connection();

    let entry = add_entry(conn, &master_key, &credential_params("Test")).expect("add entry");

    // 10 MB + 1 byte → should fail.
    let too_large = vec![0u8; 10 * 1024 * 1024 + 1];
    let err = add_attachment(
        conn,
        &master_key,
        &entry.id,
        "big.bin",
        "application/octet-stream",
        &too_large,
    )
    .unwrap_err();
    assert!(matches!(err, VaultError::FileSizeLimitExceeded { .. }));
}

#[test]
fn attachment_count_limit_enforced() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, master_key) = setup_vault(dir.path());
    let conn = db.connection();

    let entry = add_entry(conn, &master_key, &credential_params("Count Test")).expect("add entry");

    // Add 10 attachments (the max).
    for i in 0..10 {
        add_attachment(
            conn,
            &master_key,
            &entry.id,
            &format!("file{i}.txt"),
            "text/plain",
            format!("content {i}").as_bytes(),
        )
        .expect("add");
    }

    assert_eq!(count_attachments(conn, &entry.id).expect("count"), 10);

    // 11th should fail.
    let err = add_attachment(
        conn,
        &master_key,
        &entry.id,
        "file10.txt",
        "text/plain",
        b"overflow",
    )
    .unwrap_err();
    assert!(matches!(err, VaultError::AttachmentCountExceeded { .. }));
}

#[test]
fn attachment_for_nonexistent_entry_errors() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, master_key) = setup_vault(dir.path());
    let conn = db.connection();

    let err = add_attachment(
        conn,
        &master_key,
        "no-such-entry",
        "f.txt",
        "text/plain",
        b"data",
    )
    .unwrap_err();
    assert!(matches!(err, VaultError::EntryNotFound(_)));
}

#[test]
fn multiple_entries_have_independent_attachments() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, master_key) = setup_vault(dir.path());
    let conn = db.connection();

    let entry_a = add_entry(conn, &master_key, &credential_params("Entry A")).expect("add a");
    let entry_b = add_entry(conn, &master_key, &credential_params("Entry B")).expect("add b");

    add_attachment(
        conn,
        &master_key,
        &entry_a.id,
        "a.txt",
        "text/plain",
        b"for A",
    )
    .expect("add a");
    add_attachment(
        conn,
        &master_key,
        &entry_b.id,
        "b.txt",
        "text/plain",
        b"for B",
    )
    .expect("add b");

    assert_eq!(
        list_attachments(conn, &entry_a.id).expect("list a").len(),
        1
    );
    assert_eq!(
        list_attachments(conn, &entry_b.id).expect("list b").len(),
        1
    );

    // Delete entry A — B's attachment remains.
    delete_entry(conn, &entry_a.id).expect("delete a");
    assert_eq!(count_attachments(conn, &entry_a.id).expect("count a"), 0);
    assert_eq!(count_attachments(conn, &entry_b.id).expect("count b"), 1);
}
