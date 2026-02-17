//! Encrypted file attachment CRUD for vault entries.
//!
//! Each attachment is encrypted with AES-256-GCM using a key derived
//! from the master key and the parent entry's ID via BLAKE3 KDF.
//! Metadata (filename, MIME type, size) is stored as plaintext under
//! Layer 1 (`SQLCipher`); the file content is Layer 2 encrypted.

use rusqlite::params;
use serde::{Deserialize, Serialize};
use verrou_crypto_core::memory::SecretBytes;
use verrou_crypto_core::symmetric::{self, SealedData};

use crate::error::VaultError;
use crate::lifecycle::{generate_uuid, now_iso8601};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum file size per attachment: 10 MB.
const MAX_FILE_SIZE: usize = 10 * 1024 * 1024;

/// Maximum number of attachments per entry.
const MAX_ATTACHMENTS_PER_ENTRY: usize = 10;

/// Domain separation tag for attachment encryption (AAD).
const ATTACHMENT_AAD: &[u8] = b"verrou-attachment-v1";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Attachment metadata (no encrypted content).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentMetadata {
    pub id: String,
    pub entry_id: String,
    pub filename: String,
    pub mime_type: String,
    pub size_bytes: i64,
    pub created_at: String,
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/// Derive an entry-specific AES-256-GCM key for attachment encryption.
///
/// Uses BLAKE3 in KDF mode with the master key as input keying material
/// and a context string that includes the entry ID for domain separation.
fn derive_attachment_key(master_key: &SecretBytes<32>, entry_id: &str) -> [u8; 32] {
    let context = format!("verrou-attachment-key-v1:{entry_id}");
    blake3::derive_key(&context, master_key.expose())
}

// ---------------------------------------------------------------------------
// CRUD operations
// ---------------------------------------------------------------------------

/// Add a new encrypted attachment to an entry.
///
/// Validates size and count limits, derives an entry-specific key,
/// encrypts the file data, and stores it in the `attachments` table.
///
/// # Errors
///
/// - [`VaultError::FileSizeLimitExceeded`] if data exceeds 10 MB
/// - [`VaultError::AttachmentCountExceeded`] if entry already has 10 attachments
/// - [`VaultError::EntryNotFound`] if the parent entry does not exist
/// - [`VaultError::Crypto`] if encryption fails
/// - [`VaultError::Database`] if the SQL INSERT fails
#[allow(clippy::cast_possible_wrap)]
pub fn add_attachment(
    conn: &rusqlite::Connection,
    master_key: &SecretBytes<32>,
    entry_id: &str,
    filename: &str,
    mime_type: &str,
    data: &[u8],
) -> Result<AttachmentMetadata, VaultError> {
    // Validate file size.
    if data.len() > MAX_FILE_SIZE {
        return Err(VaultError::FileSizeLimitExceeded {
            max_bytes: MAX_FILE_SIZE,
            actual_bytes: data.len(),
        });
    }

    // Verify parent entry exists.
    let entry_exists: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM entries WHERE id = ?1)",
            params![entry_id],
            |row| row.get(0),
        )
        .map_err(|e| VaultError::Database(format!("failed to check entry existence: {e}")))?;
    if !entry_exists {
        return Err(VaultError::EntryNotFound(entry_id.to_string()));
    }

    // Validate attachment count.
    let count = count_attachments(conn, entry_id)?;
    if count >= MAX_ATTACHMENTS_PER_ENTRY as i64 {
        return Err(VaultError::AttachmentCountExceeded {
            max: MAX_ATTACHMENTS_PER_ENTRY,
            entry_id: entry_id.to_string(),
        });
    }

    // Derive entry-specific key and encrypt.
    let derived_key = derive_attachment_key(master_key, entry_id);
    let sealed = symmetric::encrypt(data, &derived_key, ATTACHMENT_AAD)?;
    let encrypted_blob = sealed.to_bytes();

    let id = generate_uuid();
    let now = now_iso8601();
    let size_bytes = data.len() as i64;

    conn.execute(
        "INSERT INTO attachments (id, entry_id, filename, mime_type, size_bytes, encrypted_data, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![id, entry_id, filename, mime_type, size_bytes, encrypted_blob, now],
    )
    .map_err(|e| VaultError::Database(format!("failed to insert attachment: {e}")))?;

    Ok(AttachmentMetadata {
        id,
        entry_id: entry_id.to_string(),
        filename: filename.to_string(),
        mime_type: mime_type.to_string(),
        size_bytes,
        created_at: now,
    })
}

/// List attachment metadata for an entry (no encrypted content).
///
/// Returns metadata only — the BLOB column is not read.
///
/// # Errors
///
/// Returns [`VaultError::Database`] if the query fails.
pub fn list_attachments(
    conn: &rusqlite::Connection,
    entry_id: &str,
) -> Result<Vec<AttachmentMetadata>, VaultError> {
    let mut stmt = conn
        .prepare(
            "SELECT id, entry_id, filename, mime_type, size_bytes, created_at \
             FROM attachments WHERE entry_id = ?1 ORDER BY created_at ASC",
        )
        .map_err(|e| VaultError::Database(format!("failed to prepare attachment query: {e}")))?;

    let rows = stmt
        .query_map(params![entry_id], |row| {
            Ok(AttachmentMetadata {
                id: row.get(0)?,
                entry_id: row.get(1)?,
                filename: row.get(2)?,
                mime_type: row.get(3)?,
                size_bytes: row.get(4)?,
                created_at: row.get(5)?,
            })
        })
        .map_err(|e| VaultError::Database(format!("failed to query attachments: {e}")))?;

    let mut result = Vec::new();
    for row in rows {
        result.push(
            row.map_err(|e| VaultError::Database(format!("failed to read attachment: {e}")))?,
        );
    }
    Ok(result)
}

/// Get an attachment's metadata and decrypted content.
///
/// Reads the encrypted BLOB, derives the entry-specific key, and decrypts.
/// The returned `Vec<u8>` contains the plaintext file content. The caller
/// is responsible for zeroizing this buffer after use.
///
/// # Errors
///
/// - [`VaultError::AttachmentNotFound`] if no attachment matches the ID
/// - [`VaultError::Crypto`] if decryption fails
/// - [`VaultError::Database`] if the query fails
pub fn get_attachment(
    conn: &rusqlite::Connection,
    master_key: &SecretBytes<32>,
    attachment_id: &str,
) -> Result<(AttachmentMetadata, Vec<u8>), VaultError> {
    let row = conn
        .query_row(
            "SELECT id, entry_id, filename, mime_type, size_bytes, encrypted_data, created_at \
             FROM attachments WHERE id = ?1",
            params![attachment_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, String>(6)?,
                ))
            },
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => {
                VaultError::AttachmentNotFound(attachment_id.to_string())
            }
            other => VaultError::Database(format!("failed to query attachment: {other}")),
        })?;

    let (id, entry_id, filename, mime_type, size_bytes, encrypted_blob, created_at) = row;

    // Derive entry-specific key and decrypt.
    let derived_key = derive_attachment_key(master_key, &entry_id);
    let sealed = SealedData::from_bytes(&encrypted_blob)?;
    let plaintext = symmetric::decrypt(&sealed, &derived_key, ATTACHMENT_AAD)?;

    let metadata = AttachmentMetadata {
        id,
        entry_id,
        filename,
        mime_type,
        size_bytes,
        created_at,
    };

    Ok((metadata, plaintext.expose().to_vec()))
}

/// Delete an attachment by ID.
///
/// # Errors
///
/// - [`VaultError::AttachmentNotFound`] if no attachment matches the ID
/// - [`VaultError::Database`] if the DELETE fails
pub fn delete_attachment(
    conn: &rusqlite::Connection,
    attachment_id: &str,
) -> Result<(), VaultError> {
    let rows_affected = conn
        .execute(
            "DELETE FROM attachments WHERE id = ?1",
            params![attachment_id],
        )
        .map_err(|e| VaultError::Database(format!("failed to delete attachment: {e}")))?;

    if rows_affected == 0 {
        return Err(VaultError::AttachmentNotFound(attachment_id.to_string()));
    }

    Ok(())
}

/// Count the number of attachments for an entry.
///
/// Used internally for limit validation.
///
/// # Errors
///
/// Returns [`VaultError::Database`] if the query fails.
pub fn count_attachments(conn: &rusqlite::Connection, entry_id: &str) -> Result<i64, VaultError> {
    conn.query_row(
        "SELECT COUNT(*) FROM attachments WHERE entry_id = ?1",
        params![entry_id],
        |row| row.get(0),
    )
    .map_err(|e| VaultError::Database(format!("failed to count attachments: {e}")))
}

// ---------------------------------------------------------------------------
// MIME type helper
// ---------------------------------------------------------------------------

/// Infer MIME type from a filename extension.
///
/// Falls back to `application/octet-stream` for unknown extensions.
#[must_use]
pub fn mime_from_filename(filename: &str) -> &'static str {
    match filename
        .rsplit('.')
        .next()
        .map(str::to_lowercase)
        .as_deref()
    {
        Some("pdf") => "application/pdf",
        Some("txt" | "text") => "text/plain",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("svg") => "image/svg+xml",
        Some("json") => "application/json",
        Some("xml") => "application/xml",
        Some("zip") => "application/zip",
        Some("key" | "pem" | "crt" | "cer") => "application/x-pem-file",
        Some("p12" | "pfx") => "application/x-pkcs12",
        Some("gpg" | "asc") => "application/pgp-encrypted",
        _ => "application/octet-stream",
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mime_detection_known_extensions() {
        assert_eq!(mime_from_filename("doc.pdf"), "application/pdf");
        assert_eq!(mime_from_filename("key.pem"), "application/x-pem-file");
        assert_eq!(mime_from_filename("photo.JPG"), "image/jpeg");
        assert_eq!(mime_from_filename("data.json"), "application/json");
        assert_eq!(mime_from_filename("archive.zip"), "application/zip");
    }

    #[test]
    fn mime_detection_unknown_extension() {
        assert_eq!(mime_from_filename("file.xyz"), "application/octet-stream");
        assert_eq!(mime_from_filename("noext"), "application/octet-stream");
    }

    #[test]
    fn derive_key_different_entries_produce_different_keys() {
        let master = SecretBytes::new([0xAB; 32]);
        let key_a = derive_attachment_key(&master, "entry-a");
        let key_b = derive_attachment_key(&master, "entry-b");
        assert_ne!(key_a, key_b);
    }

    #[test]
    fn derive_key_same_entry_is_deterministic() {
        let master = SecretBytes::new([0xCD; 32]);
        let key1 = derive_attachment_key(&master, "entry-1");
        let key2 = derive_attachment_key(&master, "entry-1");
        assert_eq!(key1, key2);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let master = SecretBytes::new([0x42; 32]);
        let entry_id = "test-entry-id";
        let plaintext = b"Hello, this is a test file content!";

        let key = derive_attachment_key(&master, entry_id);
        let sealed = symmetric::encrypt(plaintext, &key, ATTACHMENT_AAD).unwrap();
        let blob = sealed.to_bytes();

        let sealed2 = SealedData::from_bytes(&blob).unwrap();
        let decrypted = symmetric::decrypt(&sealed2, &key, ATTACHMENT_AAD).unwrap();
        assert_eq!(decrypted.expose(), plaintext);
    }

    #[test]
    fn wrong_entry_key_fails_decryption() {
        let master = SecretBytes::new([0x42; 32]);
        let key_a = derive_attachment_key(&master, "entry-a");
        let key_b = derive_attachment_key(&master, "entry-b");

        let sealed = symmetric::encrypt(b"secret data", &key_a, ATTACHMENT_AAD).unwrap();
        let blob = sealed.to_bytes();

        let sealed2 = SealedData::from_bytes(&blob).unwrap();
        let result = symmetric::decrypt(&sealed2, &key_b, ATTACHMENT_AAD);
        assert!(result.is_err());
    }
}
