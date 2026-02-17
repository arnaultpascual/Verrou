//! Encrypted `.verrou` vault import (restore).
//!
//! Parses an exported `.verrou` file, validates its contents against the
//! current vault, and imports entries, folders, and attachments.
//!
//! # Security Model
//!
//! - The import file's password is independent of the current vault's password
//! - A fresh master key is recovered from the import file's password slot
//! - Imported entries are re-encrypted with the current vault's master key
//! - A backup is created before any database modification
//! - The entire import runs in a single transaction (atomic rollback on failure)

use std::collections::HashMap;
use std::path::Path;

use rusqlite::params;
use serde::Serialize;
use zeroize::Zeroize;

use verrou_crypto_core::kdf;
use verrou_crypto_core::memory::SecretBytes;
use verrou_crypto_core::slots::{self, SlotType};
use verrou_crypto_core::vault_format::{self, FORMAT_VERSION};

use crate::attachments;
use crate::entries::{self, AddEntryParams};
use crate::error::VaultError;
use crate::export::verrou_format::{ExportPayload, ExportedEntry};
use crate::folders;
use crate::lifecycle;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// How to handle duplicate entries during import.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DuplicateMode {
    /// Skip entries that match existing vault entries.
    Skip,
    /// Replace existing entries with imported ones.
    Replace,
}

/// Preview of a `.verrou` import file after validation.
#[derive(Debug)]
pub struct VerrouImportPreview {
    /// Total entries in the import file.
    pub total_entries: usize,
    /// Total folders in the import file.
    pub total_folders: usize,
    /// Total attachments in the import file.
    pub total_attachments: usize,
    /// Number of entries that match existing vault entries.
    pub duplicate_count: usize,
    /// Preview of each entry.
    pub entries: Vec<VerrouEntryPreview>,
    /// Details of duplicate entries.
    pub duplicates: Vec<VerrouDuplicateInfo>,
}

/// Preview of a single entry from the import file.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerrouEntryPreview {
    /// Index in the import file's entry list.
    pub index: usize,
    /// Entry display name.
    pub name: String,
    /// Optional issuer.
    pub issuer: Option<String>,
    /// Entry type string (e.g., "totp", "credential").
    pub entry_type: String,
}

/// Details about a duplicate entry found during validation.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerrouDuplicateInfo {
    /// Index in the import file's entry list.
    pub index: usize,
    /// Name of the imported entry.
    pub name: String,
    /// Issuer of the imported entry.
    pub issuer: Option<String>,
    /// Entry type string.
    pub entry_type: String,
    /// ID of the existing vault entry.
    pub existing_id: String,
    /// Name of the existing vault entry.
    pub existing_name: String,
}

/// Result of a completed `.verrou` import operation.
#[derive(Debug)]
pub struct VerrouImportResult {
    /// Number of entries imported.
    pub imported_entries: usize,
    /// Number of folders imported (new folders created).
    pub imported_folders: usize,
    /// Number of attachments imported.
    pub imported_attachments: usize,
    /// Number of entries skipped as duplicates.
    pub skipped_duplicates: usize,
    /// Number of existing entries replaced.
    pub replaced_entries: usize,
}

// ---------------------------------------------------------------------------
// Validation (Phase 1)
// ---------------------------------------------------------------------------

/// Validate and preview a `.verrou` import file.
///
/// Decrypts the file with the provided password, checks format version
/// compatibility, and detects duplicate entries against the current vault.
///
/// # Errors
///
/// - [`VaultError::InvalidPassword`] if the password is incorrect
/// - [`VaultError::Import`] if the file format is invalid or version is too new
/// - [`VaultError::Crypto`] if decryption fails
pub fn validate_verrou_import(
    conn: &rusqlite::Connection,
    file_data: &[u8],
    import_password: &[u8],
) -> Result<VerrouImportPreview, VaultError> {
    // Step 1: Parse and decrypt the file.
    let payload = decrypt_import_file(file_data, import_password)?;

    // Step 2: Build entry previews.
    let entries: Vec<VerrouEntryPreview> = payload
        .entries
        .iter()
        .enumerate()
        .map(|(idx, e)| VerrouEntryPreview {
            index: idx,
            name: e.name.clone(),
            issuer: e.issuer.clone(),
            entry_type: e.entry_type.as_db_str().to_string(),
        })
        .collect();

    // Step 3: Check for duplicates.
    let duplicates = check_verrou_duplicates(conn, &payload.entries)?;

    Ok(VerrouImportPreview {
        total_entries: payload.entries.len(),
        total_folders: payload.folders.len(),
        total_attachments: payload.attachments.len(),
        duplicate_count: duplicates.len(),
        entries,
        duplicates,
    })
}

// ---------------------------------------------------------------------------
// Import (Phase 2)
// ---------------------------------------------------------------------------

/// Import entries, folders, and attachments from a `.verrou` file.
///
/// # Flow
///
/// 1. Re-decrypt the import file (stateless re-parse)
/// 2. Create a backup of the current vault
/// 3. Begin a single `SQLCipher` transaction
/// 4. Import folders (with ID remapping)
/// 5. Import entries (with duplicate handling)
/// 6. Import attachments (with entry ID remapping)
/// 7. Commit transaction
///
/// # Errors
///
/// - [`VaultError::InvalidPassword`] if the import file password is incorrect
/// - [`VaultError::Import`] if the file format is invalid
/// - [`VaultError::Database`] if the transaction fails (fully rolled back)
pub fn import_verrou_file(
    conn: &rusqlite::Connection,
    master_key: &SecretBytes<32>,
    file_data: &[u8],
    import_password: &[u8],
    vault_dir: &Path,
    duplicate_mode: DuplicateMode,
) -> Result<VerrouImportResult, VaultError> {
    // Step 1: Re-decrypt the import file.
    let payload = decrypt_import_file(file_data, import_password)?;

    // Step 2: Create backup before modifying the vault.
    lifecycle::create_backup(vault_dir)?;

    // Step 3: Begin transaction.
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| VaultError::Database(format!("failed to begin import transaction: {e}")))?;

    // Step 4: Import folders (with ID remapping).
    let folder_map = import_folders(conn, &payload)?;

    // Step 5: Import entries (with duplicate handling).
    let (entry_map, entry_stats) =
        import_entries(conn, master_key, &payload, &folder_map, duplicate_mode)?;

    // Step 6: Import attachments (with entry ID remapping).
    let attachment_count = import_attachments(conn, master_key, &payload, &entry_map)?;

    // Step 7: Commit transaction.
    tx.commit()
        .map_err(|e| VaultError::Database(format!("failed to commit import: {e}")))?;

    Ok(VerrouImportResult {
        imported_entries: entry_stats.imported,
        imported_folders: folder_map.values().filter(|v| v.is_new).count(),
        imported_attachments: attachment_count,
        skipped_duplicates: entry_stats.skipped,
        replaced_entries: entry_stats.replaced,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Decrypt and parse a `.verrou` import file.
fn decrypt_import_file(
    file_data: &[u8],
    import_password: &[u8],
) -> Result<ExportPayload, VaultError> {
    // Parse header to check version and find password slot.
    let header = vault_format::parse_header_only(file_data)?;

    // Version compatibility check.
    if header.version > FORMAT_VERSION {
        return Err(VaultError::Import(
            "This vault was created with a newer version of VERROU. Please update the application."
                .to_string(),
        ));
    }

    // Find the password slot.
    let (slot_index, password_slot) = header
        .slots
        .iter()
        .enumerate()
        .find(|(_, s)| s.slot_type == SlotType::Password)
        .ok_or_else(|| VaultError::Import("no password slot found in import file".into()))?;

    let salt = header
        .slot_salts
        .get(slot_index)
        .ok_or_else(|| VaultError::Import("missing salt for password slot".into()))?;

    // Derive wrapping key and recover the import master key.
    let wrapping_key = kdf::derive(import_password, salt, &header.session_params)?;
    let import_master_key = slots::unwrap_slot(password_slot, wrapping_key.expose())
        .map_err(|_| VaultError::InvalidPassword)?;

    // Decrypt the payload.
    let (_header, payload_bytes) =
        vault_format::deserialize(file_data, import_master_key.expose())?;

    // Parse the JSON payload.
    let mut payload_vec = payload_bytes.expose().to_vec();
    let payload: ExportPayload = serde_json::from_slice(&payload_vec)
        .map_err(|e| VaultError::Import(format!("failed to parse import payload: {e}")))?;

    // Zeroize intermediate.
    payload_vec.zeroize();

    // Validate payload version.
    if payload.version != 1 {
        return Err(VaultError::Import(format!(
            "unsupported import payload version: {}",
            payload.version
        )));
    }

    Ok(payload)
}

/// Check for duplicate entries in the import file against the current vault.
///
/// Matches by `LOWER(name) + entry_type + LOWER(issuer)`.
fn check_verrou_duplicates(
    conn: &rusqlite::Connection,
    entries: &[ExportedEntry],
) -> Result<Vec<VerrouDuplicateInfo>, VaultError> {
    let mut duplicates = Vec::new();

    let mut stmt = conn
        .prepare(
            "SELECT id, name FROM entries \
             WHERE LOWER(name) = LOWER(?1) \
             AND entry_type = ?2 \
             AND (LOWER(issuer) = LOWER(?3) OR (issuer IS NULL AND ?3 IS NULL))",
        )
        .map_err(|e| VaultError::Database(format!("failed to prepare duplicate check: {e}")))?;

    for (idx, entry) in entries.iter().enumerate() {
        let issuer_param = entry.issuer.as_deref();
        let rows: Vec<(String, String)> = stmt
            .query_map(
                params![entry.name, entry.entry_type.as_db_str(), issuer_param],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .map_err(|e| VaultError::Database(format!("duplicate check query failed: {e}")))?
            .filter_map(Result::ok)
            .collect();

        for (existing_id, existing_name) in rows {
            duplicates.push(VerrouDuplicateInfo {
                index: idx,
                name: entry.name.clone(),
                issuer: entry.issuer.clone(),
                entry_type: entry.entry_type.as_db_str().to_string(),
                existing_id,
                existing_name,
            });
        }
    }

    Ok(duplicates)
}

/// Folder mapping entry — tracks old ID → new ID and whether it was newly created.
struct FolderMapping {
    new_id: String,
    is_new: bool,
}

/// Import folders from the payload, deduplicating by name.
///
/// Returns a mapping from old folder ID → new folder ID.
fn import_folders(
    conn: &rusqlite::Connection,
    payload: &ExportPayload,
) -> Result<HashMap<String, FolderMapping>, VaultError> {
    let mut folder_map: HashMap<String, FolderMapping> = HashMap::new();

    // Load existing folders to check for name matches.
    let existing_folders = folders::list_folders_with_counts(conn)?;

    for exported_folder in &payload.folders {
        // Check if a folder with the same name already exists.
        let existing = existing_folders
            .iter()
            .find(|f| f.folder.name.to_lowercase() == exported_folder.name.to_lowercase());

        if let Some(existing_item) = existing {
            // Reuse existing folder.
            folder_map.insert(
                exported_folder.id.clone(),
                FolderMapping {
                    new_id: existing_item.folder.id.clone(),
                    is_new: false,
                },
            );
        } else {
            // Create new folder.
            let new_folder = folders::create_folder(conn, &exported_folder.name)?;
            folder_map.insert(
                exported_folder.id.clone(),
                FolderMapping {
                    new_id: new_folder.id,
                    is_new: true,
                },
            );
        }
    }

    Ok(folder_map)
}

/// Import entry statistics.
struct EntryImportStats {
    imported: usize,
    skipped: usize,
    replaced: usize,
}

/// Import entries from the payload with duplicate handling.
///
/// Returns a mapping from old entry ID → new entry ID, and import statistics.
fn import_entries(
    conn: &rusqlite::Connection,
    master_key: &SecretBytes<32>,
    payload: &ExportPayload,
    folder_map: &HashMap<String, FolderMapping>,
    duplicate_mode: DuplicateMode,
) -> Result<(HashMap<String, String>, EntryImportStats), VaultError> {
    let mut entry_map: HashMap<String, String> = HashMap::new();
    let mut stats = EntryImportStats {
        imported: 0,
        skipped: 0,
        replaced: 0,
    };

    // Pre-check duplicates for the whole batch.
    let duplicates = check_verrou_duplicates(conn, &payload.entries)?;
    let duplicate_indices: HashMap<usize, &VerrouDuplicateInfo> =
        duplicates.iter().map(|d| (d.index, d)).collect();

    for (idx, exported_entry) in payload.entries.iter().enumerate() {
        if let Some(dup_info) = duplicate_indices.get(&idx) {
            match duplicate_mode {
                DuplicateMode::Skip => {
                    stats.skipped = stats.skipped.saturating_add(1);
                    // Map old ID to existing ID for attachment handling.
                    entry_map.insert(exported_entry.id.clone(), dup_info.existing_id.clone());
                    continue;
                }
                DuplicateMode::Replace => {
                    // Delete existing entry first.
                    entries::delete_entry(conn, &dup_info.existing_id)?;
                    stats.replaced = stats.replaced.saturating_add(1);
                }
            }
        }

        // Remap folder_id using the folder mapping.
        let new_folder_id = exported_entry
            .folder_id
            .as_ref()
            .and_then(|old_id| folder_map.get(old_id))
            .map(|mapping| mapping.new_id.clone());

        // Parse tags from the export format (JSON string or None).
        let tags: Vec<String> = exported_entry
            .tags
            .as_ref()
            .and_then(|t| serde_json::from_str(t).ok())
            .unwrap_or_default();

        let params = AddEntryParams {
            entry_type: exported_entry.entry_type,
            name: exported_entry.name.clone(),
            issuer: exported_entry.issuer.clone(),
            folder_id: new_folder_id,
            algorithm: exported_entry.algorithm,
            digits: exported_entry.digits,
            period: exported_entry.period,
            counter: exported_entry.counter,
            pinned: exported_entry.pinned,
            tags,
            data: exported_entry.data.clone(),
        };

        let new_entry = entries::add_entry(conn, master_key, &params)?;
        entry_map.insert(exported_entry.id.clone(), new_entry.id);
        stats.imported = stats.imported.saturating_add(1);
    }

    Ok((entry_map, stats))
}

/// Import attachments from the payload with entry ID remapping.
fn import_attachments(
    conn: &rusqlite::Connection,
    master_key: &SecretBytes<32>,
    payload: &ExportPayload,
    entry_map: &HashMap<String, String>,
) -> Result<usize, VaultError> {
    let mut count: usize = 0;

    for exported_attachment in &payload.attachments {
        // Remap entry ID.
        let Some(new_entry_id) = entry_map.get(&exported_attachment.entry_id) else {
            // Entry was not imported (e.g., skipped duplicate with no ID mapping).
            continue;
        };

        attachments::add_attachment(
            conn,
            master_key,
            new_entry_id,
            &exported_attachment.filename,
            &exported_attachment.mime_type,
            &exported_attachment.data,
        )?;

        count = count.saturating_add(1);
    }

    Ok(count)
}
