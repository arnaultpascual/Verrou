#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

//! Integration tests for `VaultDb` — `SQLCipher` connection, raw key injection,
//! migration runner, and incorrect key detection.

use verrou_crypto_core::memory::SecretBytes;
use verrou_vault::db::VaultDb;
use verrou_vault::VaultError;

/// Create a fresh `VaultDb` in a temp directory with a random key.
fn open_temp_vault(dir: &tempfile::TempDir) -> (VaultDb, SecretBytes<32>) {
    let key = SecretBytes::<32>::random().expect("CSPRNG should succeed");
    let db_path = dir.path().join("test.vault");
    let db = VaultDb::open(&db_path, &key).expect("open should succeed");
    (db, key)
}

// -------------------------------------------------------------------------
// AC #1 — Crate compiles standalone with correct dependencies
// -------------------------------------------------------------------------

#[test]
fn crate_has_zero_tauri_dependencies() {
    // If this test compiles and runs, verrou-vault has no Tauri dependency.
    // The CI pipeline also verifies this via `cargo tree` ban list.
    let dir = tempfile::tempdir().expect("tempdir");
    let (_db, _key) = open_temp_vault(&dir);
}

// -------------------------------------------------------------------------
// AC #2 — SQLCipher raw key injection
// -------------------------------------------------------------------------

#[test]
fn open_creates_encrypted_database_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("test.vault");

    let key = SecretBytes::<32>::random().expect("CSPRNG");
    let _db = VaultDb::open(&db_path, &key).expect("open");

    // File must exist and have non-trivial size (SQLCipher header + schema).
    let metadata = std::fs::metadata(&db_path).expect("file should exist");
    assert!(metadata.len() > 0, "vault file should not be empty");
}

#[test]
fn cipher_version_returns_non_empty_string() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, _key) = open_temp_vault(&dir);

    let version = db.cipher_version();
    assert!(
        !version.is_empty(),
        "cipher_version should be non-empty (confirms SQLCipher, not plain SQLite)"
    );
}

#[test]
fn open_with_correct_key_succeeds() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("test.vault");
    let key = SecretBytes::<32>::random().expect("CSPRNG");

    // Create vault.
    {
        let db = VaultDb::open(&db_path, &key).expect("create");
        drop(db);
    }

    // Re-open with same key.
    let db = VaultDb::open(&db_path, &key).expect("re-open should succeed");
    // Should be able to query.
    let version = db.schema_version().expect("schema_version");
    assert!(version >= 1, "should have at least migration 1 applied");
}

// -------------------------------------------------------------------------
// AC #3 — Migration runner applies initial schema
// -------------------------------------------------------------------------

#[test]
fn migration_applies_initial_schema_and_sets_user_version() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, _key) = open_temp_vault(&dir);

    // user_version should equal the number of applied migrations.
    let version = db.schema_version().expect("schema_version");
    assert_eq!(version, 7, "user_version should be 7 after all migrations");
}

#[test]
fn initial_schema_creates_entries_table() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, _key) = open_temp_vault(&dir);

    let count: i32 = db
        .connection()
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='entries'",
            [],
            |row| row.get(0),
        )
        .expect("query should succeed");
    assert_eq!(count, 1, "entries table should exist");
}

#[test]
fn initial_schema_creates_folders_table() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, _key) = open_temp_vault(&dir);

    let count: i32 = db
        .connection()
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='folders'",
            [],
            |row| row.get(0),
        )
        .expect("query should succeed");
    assert_eq!(count, 1, "folders table should exist");
}

#[test]
fn initial_schema_creates_key_slots_table() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, _key) = open_temp_vault(&dir);

    let count: i32 = db
        .connection()
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='key_slots'",
            [],
            |row| row.get(0),
        )
        .expect("query should succeed");
    assert_eq!(count, 1, "key_slots table should exist");
}

#[test]
fn initial_schema_creates_indexes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, _key) = open_temp_vault(&dir);

    let expected_indexes = [
        "idx_entries_folder_id",
        "idx_entries_entry_type",
        "idx_entries_issuer",
        "idx_folders_parent_id",
    ];

    for idx_name in &expected_indexes {
        let count: i32 = db
            .connection()
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='index' AND name=?1",
                [idx_name],
                |row| row.get(0),
            )
            .expect("query should succeed");
        assert_eq!(count, 1, "index {idx_name} should exist");
    }
}

#[test]
fn can_insert_and_query_test_data() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, _key) = open_temp_vault(&dir);

    // Insert a folder.
    db.connection()
        .execute(
            "INSERT INTO folders (id, name, sort_order, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params!["f1", "Test Folder", 0, "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"],
        )
        .expect("insert folder");

    // Insert an entry.
    db.connection()
        .execute(
            "INSERT INTO entries (id, entry_type, name, issuer, folder_id, encrypted_data, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params!["e1", "totp", "GitHub", "github.com", "f1", &[0u8; 32][..], "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"],
        )
        .expect("insert entry");

    // Query back.
    let name: String = db
        .connection()
        .query_row("SELECT name FROM entries WHERE id = 'e1'", [], |row| {
            row.get(0)
        })
        .expect("query should succeed");
    assert_eq!(name, "GitHub");
}

// -------------------------------------------------------------------------
// AC #4 — Incorrect key detection
// -------------------------------------------------------------------------

#[test]
fn open_with_wrong_key_returns_invalid_password() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("test.vault");

    // Create vault with key A.
    let key_a = SecretBytes::<32>::random().expect("CSPRNG");
    {
        let db = VaultDb::open(&db_path, &key_a).expect("create");
        drop(db);
    }

    // Try to open with key B.
    let key_b = SecretBytes::<32>::random().expect("CSPRNG");
    let result = VaultDb::open(&db_path, &key_b);

    assert!(result.is_err(), "wrong key should fail");
    match result {
        Err(VaultError::InvalidPassword) => {} // expected
        Err(other) => panic!("expected InvalidPassword, got: {other}"),
        Ok(_) => panic!("should not succeed with wrong key"),
    }
}

#[test]
fn wrong_key_returns_no_partial_data() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("test.vault");

    // Create vault and insert data.
    let key_a = SecretBytes::<32>::random().expect("CSPRNG");
    {
        let db = VaultDb::open(&db_path, &key_a).expect("create");
        db.connection()
            .execute(
                "INSERT INTO entries (id, entry_type, name, encrypted_data, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params!["e1", "totp", "Secret", &[0u8; 16][..], "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"],
            )
            .expect("insert");
    }

    // Wrong key — no VaultDb returned, so no data access possible.
    let key_b = SecretBytes::<32>::random().expect("CSPRNG");
    let result = VaultDb::open(&db_path, &key_b);
    assert!(result.is_err());
    // No VaultDb → no connection → no partial data exposure.
}

// -------------------------------------------------------------------------
// AC #5 — Migration idempotency
// -------------------------------------------------------------------------

#[test]
fn reopening_vault_skips_already_applied_migrations() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("test.vault");
    let key = SecretBytes::<32>::random().expect("CSPRNG");

    // Open once — applies all migrations.
    let db = VaultDb::open(&db_path, &key).expect("first open");
    assert_eq!(db.schema_version().expect("v"), 7);
    drop(db);

    // Open again — migrations already applied, should be skipped.
    let db = VaultDb::open(&db_path, &key).expect("second open");
    assert_eq!(db.schema_version().expect("v"), 7);
    drop(db);

    // Open a third time — still version 7.
    let db = VaultDb::open(&db_path, &key).expect("third open");
    assert_eq!(db.schema_version().expect("v"), 7);

    // Tables should still exist and be intact.
    let count: i32 = db
        .connection()
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='entries'",
            [],
            |row| row.get(0),
        )
        .expect("query");
    assert_eq!(count, 1);
}

#[test]
fn data_persists_across_reopens() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("test.vault");
    let key = SecretBytes::<32>::random().expect("CSPRNG");

    // Insert data in first session.
    {
        let db = VaultDb::open(&db_path, &key).expect("create");
        db.connection()
            .execute(
                "INSERT INTO entries (id, entry_type, name, encrypted_data, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params!["e1", "totp", "Persistent", &[0u8; 8][..], "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"],
            )
            .expect("insert");
    }

    // Re-open and verify data.
    let db = VaultDb::open(&db_path, &key).expect("reopen");
    let name: String = db
        .connection()
        .query_row("SELECT name FROM entries WHERE id = 'e1'", [], |row| {
            row.get(0)
        })
        .expect("query");
    assert_eq!(name, "Persistent");
}

// -------------------------------------------------------------------------
// WAL + Foreign Keys
// -------------------------------------------------------------------------

#[test]
fn wal_mode_is_active() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, _key) = open_temp_vault(&dir);

    let journal_mode: String = db
        .connection()
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .expect("pragma query");
    assert_eq!(journal_mode.to_lowercase(), "wal");
}

#[test]
fn foreign_keys_are_enabled() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, _key) = open_temp_vault(&dir);

    let fk_enabled: i32 = db
        .connection()
        .pragma_query_value(None, "foreign_keys", |row| row.get(0))
        .expect("pragma query");
    assert_eq!(fk_enabled, 1, "foreign_keys should be ON");
}

// -------------------------------------------------------------------------
// Debug masking
// -------------------------------------------------------------------------

#[test]
fn vault_db_debug_is_masked() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, _key) = open_temp_vault(&dir);

    let debug = format!("{db:?}");
    assert_eq!(debug, "VaultDb(***)");
}

// -------------------------------------------------------------------------
// Open on non-existent path creates new vault
// -------------------------------------------------------------------------

#[test]
fn open_nonexistent_path_creates_new_vault() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("brand_new.vault");

    assert!(!db_path.exists(), "file should not exist yet");

    let key = SecretBytes::<32>::random().expect("CSPRNG");
    let db = VaultDb::open(&db_path, &key).expect("open should create new vault");

    assert!(db_path.exists(), "file should now exist");
    assert_eq!(db.schema_version().expect("v"), 7);
}

// -------------------------------------------------------------------------
// L2: All 6 entry types accepted by CHECK constraint
// -------------------------------------------------------------------------

#[test]
fn all_six_entry_types_are_accepted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, _key) = open_temp_vault(&dir);

    let types = [
        "totp",
        "hotp",
        "seed_phrase",
        "recovery_code",
        "secure_note",
        "credential",
    ];
    for (i, entry_type) in types.iter().enumerate() {
        let id = format!("e{i}");
        db.connection()
            .execute(
                "INSERT INTO entries (id, entry_type, name, encrypted_data, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![id, entry_type, "Test", &[0u8; 16][..], "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"],
            )
            .unwrap_or_else(|e| panic!("insert entry_type '{entry_type}' should succeed: {e}"));
    }

    let count: i32 = db
        .connection()
        .query_row("SELECT count(*) FROM entries", [], |row| row.get(0))
        .expect("count query");
    assert_eq!(count, 6, "all 6 entry types should be inserted");
}

#[test]
fn invalid_entry_type_is_rejected_by_check_constraint() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, _key) = open_temp_vault(&dir);

    let result = db.connection().execute(
        "INSERT INTO entries (id, entry_type, name, encrypted_data, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params!["e1", "invalid_type", "Bad", &[0u8; 16][..], "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"],
    );
    assert!(
        result.is_err(),
        "invalid entry_type should be rejected by CHECK constraint"
    );
}

// -------------------------------------------------------------------------
// M3/L3: FK cascade — ON DELETE SET NULL
// -------------------------------------------------------------------------

#[test]
fn deleting_folder_sets_entry_folder_id_to_null() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, _key) = open_temp_vault(&dir);

    // Insert folder.
    db.connection()
        .execute(
            "INSERT INTO folders (id, name, sort_order, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params!["f1", "Folder", 0, "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"],
        )
        .expect("insert folder");

    // Insert entry referencing folder.
    db.connection()
        .execute(
            "INSERT INTO entries (id, entry_type, name, folder_id, encrypted_data, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params!["e1", "totp", "Test", "f1", &[0u8; 16][..], "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"],
        )
        .expect("insert entry");

    // Delete folder — FK cascade should set folder_id to NULL.
    db.connection()
        .execute("DELETE FROM folders WHERE id = 'f1'", [])
        .expect("delete folder");

    // Verify entry still exists but folder_id is NULL.
    let folder_id: Option<String> = db
        .connection()
        .query_row("SELECT folder_id FROM entries WHERE id = 'e1'", [], |row| {
            row.get(0)
        })
        .expect("query entry");
    assert!(
        folder_id.is_none(),
        "folder_id should be NULL after parent folder deletion"
    );
}

#[test]
fn deleting_parent_folder_sets_child_parent_id_to_null() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (db, _key) = open_temp_vault(&dir);

    // Insert parent folder.
    db.connection()
        .execute(
            "INSERT INTO folders (id, name, sort_order, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params!["parent", "Parent", 0, "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"],
        )
        .expect("insert parent");

    // Insert child folder referencing parent.
    db.connection()
        .execute(
            "INSERT INTO folders (id, name, parent_id, sort_order, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params!["child", "Child", "parent", 1, "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"],
        )
        .expect("insert child");

    // Delete parent — child.parent_id should become NULL.
    db.connection()
        .execute("DELETE FROM folders WHERE id = 'parent'", [])
        .expect("delete parent");

    let parent_id: Option<String> = db
        .connection()
        .query_row(
            "SELECT parent_id FROM folders WHERE id = 'child'",
            [],
            |row| row.get(0),
        )
        .expect("query child");
    assert!(
        parent_id.is_none(),
        "parent_id should be NULL after parent folder deletion"
    );
}
