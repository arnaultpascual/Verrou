//! Entry serialization for QR desktop-to-desktop transfer.
//!
//! Serializes selected vault entries into a compact JSON payload with
//! a BLAKE3 integrity checksum, ready for chunking and encryption by
//! `verrou-crypto-core::transfer`. On the receiving side, deserializes
//! and imports entries into the vault within a single transaction.
//!
//! Folder references use names (not IDs) for portability across vaults.

use rusqlite::params;
use serde::{Deserialize, Serialize};
use verrou_crypto_core::memory::SecretBytes;

use crate::entries::{self, AddEntryParams, Algorithm, EntryData, EntryType};
use crate::error::VaultError;
use crate::folders;

// ---------------------------------------------------------------------------
// Transfer payload types
// ---------------------------------------------------------------------------

/// Version tag for the transfer wire format.
const TRANSFER_FORMAT_VERSION: u8 = 1;

/// Complete transfer payload (serialized to JSON).
#[derive(Serialize, Deserialize)]
pub struct TransferPayload {
    /// Format version for forward compatibility.
    pub version: u8,
    /// The entries being transferred.
    pub entries: Vec<TransferEntry>,
    /// BLAKE3 checksum of the serialized entries (hex-encoded).
    pub checksum: String,
}

/// A single entry in the transfer payload.
///
/// Uses folder *name* (not ID) so entries can be imported into a
/// different vault that may have different folder UUIDs.
#[derive(Serialize, Deserialize)]
pub struct TransferEntry {
    pub entry_type: EntryType,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub folder_name: Option<String>,
    pub algorithm: Algorithm,
    pub digits: u32,
    pub period: u32,
    pub counter: u64,
    pub pinned: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    pub data: EntryData,
}

// ---------------------------------------------------------------------------
// Serialization (sender side)
// ---------------------------------------------------------------------------

/// Serialize selected entries for transfer.
///
/// Fetches and decrypts each entry, resolves folder IDs to names,
/// builds a `TransferPayload` with a BLAKE3 checksum, and returns
/// the serialized JSON bytes.
///
/// # Errors
///
/// - [`VaultError::EntryNotFound`] if any entry ID is invalid
/// - [`VaultError::Crypto`] if decryption fails
/// - [`VaultError::Database`] if folder lookup fails
pub fn serialize_entries_for_transfer(
    conn: &rusqlite::Connection,
    master_key: &SecretBytes<32>,
    entry_ids: &[String],
) -> Result<Vec<u8>, VaultError> {
    let mut transfer_entries = Vec::with_capacity(entry_ids.len());

    for entry_id in entry_ids {
        let entry = entries::get_entry(conn, master_key, entry_id)?;

        // Resolve folder_id → folder_name for portability.
        let folder_name = if let Some(ref fid) = entry.folder_id {
            resolve_folder_name(conn, fid)?
        } else {
            None
        };

        // Read tags from plaintext column.
        let tags = read_entry_tags(conn, entry_id)?;

        transfer_entries.push(TransferEntry {
            entry_type: entry.entry_type,
            name: entry.name,
            issuer: entry.issuer,
            folder_name,
            algorithm: entry.algorithm,
            digits: entry.digits,
            period: entry.period,
            counter: entry.counter,
            pinned: entry.pinned,
            tags,
            data: entry.data,
        });
    }

    // Compute checksum over the entries JSON.
    let entries_json = serde_json::to_vec(&transfer_entries)
        .map_err(|e| VaultError::Export(format!("failed to serialize transfer entries: {e}")))?;
    let checksum = blake3::hash(&entries_json).to_hex().to_string();

    let payload = TransferPayload {
        version: TRANSFER_FORMAT_VERSION,
        entries: transfer_entries,
        checksum,
    };

    serde_json::to_vec(&payload)
        .map_err(|e| VaultError::Export(format!("failed to serialize transfer payload: {e}")))
}

// ---------------------------------------------------------------------------
// Deserialization & import (receiver side)
// ---------------------------------------------------------------------------

/// Import entries from a transfer payload.
///
/// Deserializes the JSON payload, verifies the BLAKE3 checksum,
/// resolves (or creates) folders by name, and inserts all entries
/// within a single transaction.
///
/// Returns the number of entries imported.
///
/// # Errors
///
/// - [`VaultError::Import`] if the checksum fails or the format is invalid
/// - [`VaultError::Crypto`] if encryption fails during insert
/// - [`VaultError::Database`] if the transaction fails
pub fn import_transfer_entries(
    conn: &rusqlite::Connection,
    master_key: &SecretBytes<32>,
    data: &[u8],
) -> Result<usize, VaultError> {
    let payload: TransferPayload = serde_json::from_slice(data)
        .map_err(|e| VaultError::Import(format!("invalid transfer payload: {e}")))?;

    if payload.version != TRANSFER_FORMAT_VERSION {
        return Err(VaultError::Import(format!(
            "unsupported transfer format version: {} (expected {TRANSFER_FORMAT_VERSION})",
            payload.version
        )));
    }

    // Verify checksum.
    let entries_json = serde_json::to_vec(&payload.entries)
        .map_err(|e| VaultError::Import(format!("failed to re-serialize entries: {e}")))?;
    let computed = blake3::hash(&entries_json).to_hex().to_string();

    if computed != payload.checksum {
        return Err(VaultError::Import(
            "transfer payload checksum mismatch — data may be corrupted".to_string(),
        ));
    }

    // Import within a single transaction.
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| VaultError::Database(format!("failed to begin transaction: {e}")))?;

    let mut imported = 0usize;

    for entry in &payload.entries {
        // Resolve folder_name → folder_id (create if missing).
        let folder_id = if let Some(ref name) = entry.folder_name {
            Some(resolve_or_create_folder(conn, name)?)
        } else {
            None
        };

        let params = AddEntryParams {
            entry_type: entry.entry_type,
            name: entry.name.clone(),
            issuer: entry.issuer.clone(),
            folder_id,
            algorithm: entry.algorithm,
            digits: entry.digits,
            period: entry.period,
            counter: entry.counter,
            pinned: entry.pinned,
            tags: entry.tags.clone(),
            data: entry.data.clone(),
        };

        entries::add_entry(conn, master_key, &params)?;
        imported = imported.saturating_add(1);
    }

    tx.commit()
        .map_err(|e| VaultError::Database(format!("failed to commit transfer import: {e}")))?;

    Ok(imported)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Resolve a folder ID to its name.
fn resolve_folder_name(
    conn: &rusqlite::Connection,
    folder_id: &str,
) -> Result<Option<String>, VaultError> {
    let name: Option<String> = conn
        .query_row(
            "SELECT name FROM folders WHERE id = ?1",
            params![folder_id],
            |row| row.get(0),
        )
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(VaultError::Database(format!(
                "failed to resolve folder name: {other}"
            ))),
        })?;
    Ok(name)
}

/// Find a folder by name, or create it if it doesn't exist.
fn resolve_or_create_folder(conn: &rusqlite::Connection, name: &str) -> Result<String, VaultError> {
    // Try to find existing folder by name (case-insensitive).
    let existing: Option<String> = conn
        .query_row(
            "SELECT id FROM folders WHERE LOWER(name) = LOWER(?1)",
            params![name],
            |row| row.get(0),
        )
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(VaultError::Database(format!(
                "failed to find folder by name: {other}"
            ))),
        })?;

    if let Some(id) = existing {
        return Ok(id);
    }

    // Create the folder.
    let folder = folders::create_folder(conn, name)?;
    Ok(folder.id)
}

/// Read tags for an entry from the plaintext column.
fn read_entry_tags(conn: &rusqlite::Connection, entry_id: &str) -> Result<Vec<String>, VaultError> {
    let tags_json: String = conn
        .query_row(
            "SELECT COALESCE(tags, '[]') FROM entries WHERE id = ?1",
            params![entry_id],
            |row| row.get(0),
        )
        .map_err(|e| VaultError::Database(format!("failed to read entry tags: {e}")))?;

    serde_json::from_str(&tags_json)
        .map_err(|_| VaultError::Database(format!("invalid tags JSON for entry {entry_id}")))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entries::{CustomField, PasswordHistoryEntry};

    #[test]
    fn transfer_entry_serde_roundtrip_totp() {
        let entry = TransferEntry {
            entry_type: EntryType::Totp,
            name: "GitHub".into(),
            issuer: Some("github.com".into()),
            folder_name: Some("Work".into()),
            algorithm: Algorithm::SHA1,
            digits: 6,
            period: 30,
            counter: 0,
            pinned: true,
            tags: vec!["dev".into()],
            data: EntryData::Totp {
                secret: "JBSWY3DPEHPK3PXP".into(),
            },
        };

        let json = serde_json::to_string(&entry).expect("serialize");
        let parsed: TransferEntry = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(parsed.entry_type, EntryType::Totp);
        assert_eq!(parsed.name, "GitHub");
        assert_eq!(parsed.issuer.as_deref(), Some("github.com"));
        assert_eq!(parsed.folder_name.as_deref(), Some("Work"));
        assert!(parsed.pinned);
        assert_eq!(parsed.tags, vec!["dev"]);
    }

    #[test]
    fn transfer_entry_serde_roundtrip_credential() {
        let entry = TransferEntry {
            entry_type: EntryType::Credential,
            name: "Example Login".into(),
            issuer: None,
            folder_name: None,
            algorithm: Algorithm::SHA1,
            digits: 6,
            period: 30,
            counter: 0,
            pinned: false,
            tags: Vec::new(),
            data: EntryData::Credential {
                password: "s3cret!".into(),
                username: Some("admin".into()),
                urls: vec!["https://example.com".into()],
                notes: None,
                linked_totp_id: None,
                custom_fields: vec![CustomField {
                    label: "API Key".into(),
                    value: "sk-123".into(),
                    field_type: crate::entries::CustomFieldType::Hidden,
                }],
                password_history: vec![PasswordHistoryEntry {
                    password: "old".into(),
                    changed_at: "2026-01-01T00:00:00Z".into(),
                }],
                template: Some("web-login".into()),
            },
        };

        let json = serde_json::to_string(&entry).expect("serialize");
        let parsed: TransferEntry = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(parsed.entry_type, EntryType::Credential);
        match &parsed.data {
            EntryData::Credential {
                password, username, ..
            } => {
                assert_eq!(password, "s3cret!");
                assert_eq!(username.as_deref(), Some("admin"));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn transfer_payload_checksum_verification() {
        let entries = vec![TransferEntry {
            entry_type: EntryType::SecureNote,
            name: "My Note".into(),
            issuer: None,
            folder_name: None,
            algorithm: Algorithm::SHA1,
            digits: 6,
            period: 30,
            counter: 0,
            pinned: false,
            tags: Vec::new(),
            data: EntryData::SecureNote {
                body: "Secret content".into(),
                tags: Vec::new(),
            },
        }];

        let entries_json = serde_json::to_vec(&entries).unwrap();
        let checksum = blake3::hash(&entries_json).to_hex().to_string();

        let payload = TransferPayload {
            version: TRANSFER_FORMAT_VERSION,
            entries,
            checksum,
        };

        let serialized = serde_json::to_vec(&payload).unwrap();

        // Deserialize and verify.
        let parsed: TransferPayload = serde_json::from_slice(&serialized).unwrap();
        let re_json = serde_json::to_vec(&parsed.entries).unwrap();
        let re_checksum = blake3::hash(&re_json).to_hex().to_string();

        assert_eq!(re_checksum, parsed.checksum);
    }

    #[test]
    fn transfer_payload_bad_checksum_detected() {
        let entries = vec![TransferEntry {
            entry_type: EntryType::Totp,
            name: "Test".into(),
            issuer: None,
            folder_name: None,
            algorithm: Algorithm::SHA1,
            digits: 6,
            period: 30,
            counter: 0,
            pinned: false,
            tags: Vec::new(),
            data: EntryData::Totp {
                secret: "AAAA".into(),
            },
        }];

        let payload = TransferPayload {
            version: TRANSFER_FORMAT_VERSION,
            entries,
            checksum: "0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
        };

        let serialized = serde_json::to_vec(&payload).unwrap();

        // Deserialize and verify checksum fails.
        let parsed: TransferPayload = serde_json::from_slice(&serialized).unwrap();
        let re_json = serde_json::to_vec(&parsed.entries).unwrap();
        let re_checksum = blake3::hash(&re_json).to_hex().to_string();

        assert_ne!(re_checksum, parsed.checksum);
    }

    #[test]
    fn transfer_payload_empty_entries() {
        let entries: Vec<TransferEntry> = Vec::new();
        let entries_json = serde_json::to_vec(&entries).unwrap();
        let checksum = blake3::hash(&entries_json).to_hex().to_string();

        let payload = TransferPayload {
            version: TRANSFER_FORMAT_VERSION,
            entries,
            checksum,
        };

        let serialized = serde_json::to_vec(&payload).unwrap();
        let parsed: TransferPayload = serde_json::from_slice(&serialized).unwrap();

        assert!(parsed.entries.is_empty());
        assert_eq!(parsed.version, TRANSFER_FORMAT_VERSION);
    }
}
