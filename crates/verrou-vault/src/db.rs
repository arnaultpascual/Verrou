//! `SQLCipher` database connection, raw key injection, and migration runner.
//!
//! This module manages the encrypted database layer for VERROU vaults.
//! The encryption key is injected as a raw 256-bit key via
//! `PRAGMA key = "x'<hex>'"` with `PRAGMA kdf_iter = 1` to skip
//! `SQLCipher`'s internal PBKDF2 (our Argon2id already derived the key).

use std::fmt;
use std::path::Path;

use rusqlite::Connection;
use verrou_crypto_core::memory::SecretBytes;
use zeroize::Zeroize;

use crate::error::VaultError;

// ---------------------------------------------------------------------------
// Embedded migrations
// ---------------------------------------------------------------------------

/// Forward-only SQL migrations, embedded at compile time.
/// Index 0 → version 1, index 1 → version 2, etc.
const MIGRATIONS: &[&str] = &[
    include_str!("../migrations/001_initial_schema.sql"),
    include_str!("../migrations/002_add_entry_columns.sql"),
    include_str!("../migrations/003_add_tags_column.sql"),
    include_str!("../migrations/004_add_credential_type.sql"),
    include_str!("../migrations/005_add_username_column.sql"),
    include_str!("../migrations/006_create_attachments_table.sql"),
    include_str!("../migrations/007_add_template_column.sql"),
];

// ---------------------------------------------------------------------------
// VaultDb
// ---------------------------------------------------------------------------

/// Handle to an open, decrypted `SQLCipher` database.
///
/// Holds a [`rusqlite::Connection`] that has already been keyed and migrated.
/// All vault I/O flows through this struct.
pub struct VaultDb {
    conn: Connection,
}

impl fmt::Debug for VaultDb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VaultDb(***)")
    }
}

impl VaultDb {
    /// Open (or create) an encrypted vault database at `path`.
    ///
    /// 1. Opens the `SQLCipher` database file.
    /// 2. Injects the raw 256-bit key and disables internal PBKDF2.
    /// 3. Verifies the key is correct by querying `sqlite_master`.
    /// 4. Enables WAL journal mode and foreign key enforcement.
    /// 5. Runs any pending migrations.
    ///
    /// # Errors
    ///
    /// - [`VaultError::InvalidPassword`] if the key is wrong.
    /// - [`VaultError::Database`] for other `SQLCipher` errors.
    /// - [`VaultError::Migration`] if a migration fails.
    pub fn open(path: &Path, raw_key: &SecretBytes<32>) -> Result<Self, VaultError> {
        let conn = Connection::open(path)?;

        // --- Raw key injection ---
        inject_raw_key(&conn, raw_key)?;

        // --- Verify key (wrong key → SQLITE_NOTADB on first read) ---
        verify_key(&conn)?;

        // --- Enable WAL + foreign keys ---
        conn.execute_batch("PRAGMA journal_mode = WAL;")?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;

        let mut db = Self { conn };

        // --- Run pending migrations ---
        db.run_migrations()?;

        Ok(db)
    }

    /// Open (or create) an encrypted vault database from a raw key slice.
    ///
    /// Same as [`open`](Self::open) but accepts a `&[u8]` instead of
    /// `SecretBytes<32>`. The caller must ensure the slice is exactly 32 bytes.
    ///
    /// # Errors
    ///
    /// - [`VaultError::Crypto`] if the key is not exactly 32 bytes.
    /// - [`VaultError::InvalidPassword`] if the key is wrong.
    /// - [`VaultError::Database`] for other `SQLCipher` errors.
    /// - [`VaultError::Migration`] if a migration fails.
    pub fn open_raw(path: &Path, raw_key: &[u8]) -> Result<Self, VaultError> {
        if raw_key.len() != 32 {
            return Err(VaultError::Crypto(
                verrou_crypto_core::CryptoError::InvalidKeyMaterial(format!(
                    "expected 32-byte key, got {} bytes",
                    raw_key.len()
                )),
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(raw_key);
        let key = SecretBytes::new(arr);
        Self::open(path, &key)
    }

    /// Returns a reference to the underlying [`rusqlite::Connection`].
    ///
    /// Primarily for use in tests and downstream CRUD operations.
    #[must_use]
    pub const fn connection(&self) -> &Connection {
        &self.conn
    }

    /// Returns the `SQLCipher` version string.
    ///
    /// Returns an empty string if `SQLCipher` is not linked (plain `SQLite`
    /// fallback) — the pragma simply returns no rows in that case.
    #[must_use]
    pub fn cipher_version(&self) -> String {
        self.conn
            .pragma_query_value(None, "cipher_version", |row| row.get(0))
            .unwrap_or_default()
    }

    /// Returns the current schema version (`PRAGMA user_version`).
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::Database`] if the pragma query fails.
    pub fn schema_version(&self) -> Result<i32, VaultError> {
        let v: i32 = self
            .conn
            .pragma_query_value(None, "user_version", |row| row.get(0))?;
        Ok(v)
    }

    // -----------------------------------------------------------------------
    // Migration runner
    // -----------------------------------------------------------------------

    /// Apply all pending migrations sequentially.
    ///
    /// Each migration is wrapped in a transaction. The `user_version` pragma
    /// is bumped atomically on commit.
    fn run_migrations(&mut self) -> Result<(), VaultError> {
        let current = self.schema_version()?;

        for (idx, sql) in MIGRATIONS.iter().enumerate() {
            // Migration versions are 1-indexed: index 0 → version 1.
            let version = idx
                .checked_add(1)
                .and_then(|v| i32::try_from(v).ok())
                .ok_or_else(|| VaultError::Migration("migration index overflow".into()))?;

            if version <= current {
                continue; // already applied
            }

            let tx = self.conn.transaction().map_err(|e| {
                VaultError::Migration(format!(
                    "failed to start transaction for migration {version}: {e}"
                ))
            })?;

            tx.execute_batch(sql)
                .map_err(|e| VaultError::Migration(format!("migration {version} failed: {e}")))?;

            tx.pragma_update(None, "user_version", version)
                .map_err(|e| {
                    VaultError::Migration(format!(
                        "failed to update user_version to {version}: {e}"
                    ))
                })?;

            tx.commit().map_err(|e| {
                VaultError::Migration(format!("failed to commit migration {version}: {e}"))
            })?;
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Build the raw hex key literal and execute the `PRAGMA key` + `PRAGMA kdf_iter = 1`.
///
/// The hex key string and PRAGMA statement are zeroized immediately after use
/// to prevent key material from lingering on the heap.
fn inject_raw_key(conn: &Connection, raw_key: &SecretBytes<32>) -> Result<(), VaultError> {
    let mut hex_key = encode_hex(raw_key.expose());
    let mut pragma = format!("PRAGMA key = \"x'{hex_key}'\";");

    let result = conn.execute_batch(&pragma);

    // Zeroize key material from heap before propagating errors.
    hex_key.zeroize();
    pragma.zeroize();

    result?;
    conn.execute_batch("PRAGMA kdf_iter = 1;")?;
    Ok(())
}

/// Verify the key by touching `sqlite_master`.
///
/// `SQLCipher` defers key verification until the first database read.
/// If the key is wrong, this returns `SQLITE_NOTADB` which our
/// `From<rusqlite::Error>` impl maps to [`VaultError::InvalidPassword`].
fn verify_key(conn: &Connection) -> Result<(), VaultError> {
    conn.execute_batch("SELECT count(*) FROM sqlite_master;")?;
    Ok(())
}

/// Encode a byte slice as a lowercase hex string.
///
/// Uses `std::fmt::Write` to avoid pulling in an external `hex` crate.
#[must_use]
pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for &b in bytes {
        // write! on a String is infallible — the only error source is
        // allocation, which would panic before returning Err.
        let _ = write!(s, "{b:02x}");
    }
    s
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_hex_empty() {
        assert_eq!(encode_hex(&[]), "");
    }

    #[test]
    fn encode_hex_known_vector() {
        let bytes = [0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(encode_hex(&bytes), "deadbeef");
    }

    #[test]
    fn encode_hex_32_bytes_produces_64_chars() {
        let bytes = [0xAB; 32];
        let hex = encode_hex(&bytes);
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn encode_hex_all_zeros() {
        let bytes = [0u8; 4];
        assert_eq!(encode_hex(&bytes), "00000000");
    }

    #[test]
    fn encode_hex_all_ff() {
        let bytes = [0xFF; 4];
        assert_eq!(encode_hex(&bytes), "ffffffff");
    }

    /// Verify `VaultDb` is `Send` (required for Tauri state management).
    #[allow(dead_code)]
    const fn assert_send<T: Send>() {}

    #[allow(dead_code)]
    const _: () = assert_send::<VaultDb>();
}

#[cfg(test)]
mod proptest_tests {
    use proptest::prelude::*;

    use super::encode_hex;

    proptest! {
        #[test]
        fn random_keys_produce_valid_hex(key_bytes in proptest::collection::vec(any::<u8>(), 32)) {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&key_bytes);
            let hex = encode_hex(&arr);
            prop_assert_eq!(hex.len(), 64);
            prop_assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }
}
