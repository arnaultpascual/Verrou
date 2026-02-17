//! Import parsers and shared import infrastructure for VERROU.
//!
//! Each parser module implements a single function:
//! `parse_X(input) -> Result<Vec<ImportedEntry>, ImportError>`
//!
//! Shared types (`ImportedEntry`, `ImportSummary`) and operations
//! (`check_duplicates`, `import_entries`) live here.

pub mod aegis;
pub mod google_auth;
pub mod twofas;
pub mod verrou_format;

use rusqlite::params;
use serde::Serialize;
use verrou_crypto_core::memory::SecretBytes;

use crate::entries::{self, AddEntryParams, Algorithm, EntryData, EntryType};
use crate::error::VaultError;

// ---------------------------------------------------------------------------
// Import error types
// ---------------------------------------------------------------------------

/// Categorized error for import parsing operations.
#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    /// The input data format is invalid (not valid protobuf, JSON, etc.).
    #[error("invalid format: {0}")]
    InvalidFormat(String),

    /// An algorithm or OTP type in the import data is not supported.
    #[error("unsupported: {0}")]
    Unsupported(String),

    /// The input data is corrupted or truncated.
    #[error("corrupted data: {0}")]
    Corrupted(String),

    /// Base64 or other encoding error.
    #[error("encoding error: {0}")]
    Encoding(String),
}

// ---------------------------------------------------------------------------
// Shared types
// ---------------------------------------------------------------------------

/// A parsed entry ready for import into the vault.
///
/// Generic across all import sources (Google Auth, Aegis, 2FAS).
/// Fields map directly to `AddEntryParams`.
#[derive(Debug)]
pub struct ImportedEntry {
    /// Entry type (TOTP or HOTP).
    pub entry_type: EntryType,
    /// Display name (e.g., "user@example.com").
    pub name: String,
    /// Optional issuer (e.g., "GitHub").
    pub issuer: Option<String>,
    /// Base32-encoded secret key.
    pub secret: String,
    /// OTP algorithm.
    pub algorithm: Algorithm,
    /// OTP digit count (6 or 8).
    pub digits: u32,
    /// TOTP period in seconds.
    pub period: u32,
    /// HOTP counter (0 for TOTP).
    pub counter: u64,
}

/// Information about a detected duplicate entry.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DuplicateInfo {
    /// Index in the parsed entries list.
    pub index: usize,
    /// Name of the parsed entry.
    pub name: String,
    /// Issuer of the parsed entry.
    pub issuer: Option<String>,
    /// ID of the existing vault entry.
    pub existing_id: String,
    /// Name of the existing vault entry.
    pub existing_name: String,
}

/// Information about an unsupported entry.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnsupportedInfo {
    /// Index in the raw parsed data.
    pub index: usize,
    /// Name from the import data (if available).
    pub name: String,
    /// Issuer from the import data (if available).
    pub issuer: Option<String>,
    /// Reason the entry is unsupported (e.g., "MD5 algorithm not supported").
    pub reason: String,
}

/// Information about a malformed entry.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MalformedInfo {
    /// Index in the raw parsed data.
    pub index: usize,
    /// Reason the entry is malformed (e.g., "Empty secret field").
    pub reason: String,
}

/// Summary of a completed import operation.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportSummary {
    /// Number of entries successfully imported.
    pub imported: usize,
    /// Number of entries skipped (duplicates + user choice combined).
    pub skipped: usize,
    /// IDs of newly created entries.
    pub imported_ids: Vec<String>,
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate that a Base32-encoded secret is well-formed and non-empty.
///
/// # Errors
///
/// Returns an error string if the secret is empty or contains invalid Base32 characters.
pub fn validate_secret(secret: &str) -> Result<(), String> {
    if secret.is_empty() {
        return Err("empty secret".to_string());
    }
    // data-encoding's BASE32 uses uppercase A-Z, 2-7 (RFC 4648).
    // Verify by attempting a decode.
    data_encoding::BASE32
        .decode(secret.as_bytes())
        .map_err(|e| format!("invalid Base32: {e}"))?;
    Ok(())
}

/// Validate that digits and period values are within supported ranges.
///
/// # Errors
///
/// Returns an error string if digits or period are outside supported values.
pub fn validate_otp_params(digits: u32, period: u32) -> Result<(), String> {
    if digits != 6 && digits != 8 {
        return Err(format!(
            "unsupported digit count: {digits} (expected 6 or 8)"
        ));
    }
    if !matches!(period, 15 | 30 | 60) {
        return Err(format!(
            "unsupported period: {period}s (expected 15, 30, or 60)"
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Duplicate detection
// ---------------------------------------------------------------------------

/// Check for duplicates against existing vault entries.
///
/// Matches by lowercase (issuer + name) pair. Returns info about
/// each duplicate found.
///
/// # Errors
///
/// Returns [`VaultError::Database`] if the SQL query fails.
pub fn check_duplicates(
    conn: &rusqlite::Connection,
    entries: &[ImportedEntry],
) -> Result<Vec<DuplicateInfo>, VaultError> {
    let mut duplicates = Vec::new();

    let mut stmt = conn
        .prepare(
            "SELECT id, name, issuer FROM entries \
             WHERE LOWER(name) = LOWER(?1) \
             AND (LOWER(issuer) = LOWER(?2) OR (issuer IS NULL AND ?2 IS NULL))",
        )
        .map_err(|e| VaultError::Database(format!("failed to prepare duplicate check: {e}")))?;

    for (idx, entry) in entries.iter().enumerate() {
        let issuer_param = entry.issuer.as_deref();
        let rows: Vec<(String, String)> = stmt
            .query_map(params![entry.name, issuer_param], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e| VaultError::Database(format!("duplicate check query failed: {e}")))?
            .filter_map(Result::ok)
            .collect();

        for (existing_id, existing_name) in rows {
            duplicates.push(DuplicateInfo {
                index: idx,
                name: entry.name.clone(),
                issuer: entry.issuer.clone(),
                existing_id,
                existing_name,
            });
        }
    }

    Ok(duplicates)
}

// ---------------------------------------------------------------------------
// Transactional bulk import
// ---------------------------------------------------------------------------

/// Import entries into the vault within a single transaction.
///
/// Entries at indices in `skip_indices` are excluded (e.g., user-confirmed
/// duplicates to skip). All remaining entries are inserted atomically.
///
/// # Errors
///
/// Returns `VaultError::Database` if the transaction fails.
/// On any error, the entire batch is rolled back.
pub fn import_entries(
    conn: &rusqlite::Connection,
    master_key: &SecretBytes<32>,
    entries: &[ImportedEntry],
    skip_indices: &[usize],
) -> Result<ImportSummary, VaultError> {
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| VaultError::Database(format!("failed to begin transaction: {e}")))?;

    let mut imported = 0usize;
    let mut imported_ids = Vec::new();

    for (idx, entry) in entries.iter().enumerate() {
        if skip_indices.contains(&idx) {
            continue;
        }

        let params = AddEntryParams {
            entry_type: entry.entry_type,
            name: entry.name.clone(),
            issuer: entry.issuer.clone(),
            folder_id: None,
            algorithm: entry.algorithm,
            digits: entry.digits,
            period: entry.period,
            counter: entry.counter,
            pinned: false,
            tags: Vec::new(),
            data: match entry.entry_type {
                EntryType::Totp => EntryData::Totp {
                    secret: entry.secret.clone(),
                },
                EntryType::Hotp => EntryData::Hotp {
                    secret: entry.secret.clone(),
                },
                _ => {
                    return Err(VaultError::Import(format!(
                        "unexpected entry type for OTP import: {:?}",
                        entry.entry_type
                    )));
                }
            },
        };

        let result = entries::add_entry(conn, master_key, &params)?;
        imported_ids.push(result.id);
        imported = imported.saturating_add(1);
    }

    tx.commit()
        .map_err(|e| VaultError::Database(format!("failed to commit import: {e}")))?;

    Ok(ImportSummary {
        imported,
        skipped: skip_indices.len(),
        imported_ids,
    })
}
