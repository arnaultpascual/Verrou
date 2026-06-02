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

/// Maximum allowed size (in bytes) for a single attachment in an import file.
///
/// Must match the `MAX_FILE_SIZE` limit enforced by `attachments.rs` so that
/// oversized data is rejected *before* any allocation is retained, preventing
/// denial-of-service via a crafted export file with a giant `data` field.
const IMPORT_MAX_ATTACHMENT_BYTES: usize = 10 * 1024 * 1024; // 10 MiB

use verrou_crypto_core::kdf;
use verrou_crypto_core::memory::{SecretBuffer, SecretBytes};
use verrou_crypto_core::slots::{self, SlotType};
use verrou_crypto_core::vault_format::{self, FORMAT_VERSION};
use verrou_crypto_core::{kem, signing, symmetric};

use crate::attachments;
use crate::entries::{self, AddEntryParams};
use crate::error::VaultError;
use crate::export::envelope::{self, KEM_CEK_AAD, VAULT_KEM_CONTEXT};
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
/// Decrypts the file (envelope or legacy raw format), checks format version
/// compatibility, and detects duplicate entries against the current vault.
///
/// `vault_master_key` is the *importing* vault's master key (the unlocked
/// session). When the import file is a post-quantum envelope produced by the
/// same vault, the content key is recovered via the KEM path (no password
/// needed); otherwise the password slot is used. Pass `None` to force the
/// password path (e.g. when no session is available).
///
/// # Errors
///
/// - [`VaultError::InvalidPassword`] if the password is incorrect
/// - [`VaultError::Import`] if the file format is invalid, the envelope
///   signature fails (fail-closed), or the version is too new
/// - [`VaultError::Crypto`] if decryption fails
pub fn validate_verrou_import(
    conn: &rusqlite::Connection,
    file_data: &[u8],
    import_password: &[u8],
    vault_master_key: Option<&SecretBytes<32>>,
) -> Result<VerrouImportPreview, VaultError> {
    // Step 1: Parse and decrypt the file.
    let payload = decrypt_import_file(file_data, import_password, vault_master_key)?;

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
/// - [`VaultError::Import`] if the file format is invalid (or, for an envelope,
///   the signature fails to verify — fail-closed before any decryption)
/// - [`VaultError::Database`] if the transaction fails (fully rolled back)
pub fn import_verrou_file(
    conn: &rusqlite::Connection,
    master_key: &SecretBytes<32>,
    file_data: &[u8],
    import_password: &[u8],
    vault_dir: &Path,
    duplicate_mode: DuplicateMode,
) -> Result<VerrouImportResult, VaultError> {
    // Step 1: Re-decrypt the import file. The current vault's master key enables
    // the KEM recovery path when importing an envelope this vault produced.
    let payload = decrypt_import_file(file_data, import_password, Some(master_key))?;

    // Step 2: Create backup before modifying the vault.
    lifecycle::create_backup(vault_dir)?;

    // Step 3: Begin transaction.
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| VaultError::Database(format!("failed to begin import transaction: {e}")))?;

    // Step 4: Import folders (with ID remapping).
    // All writes go through &tx so they participate in the explicit transaction.
    let folder_map = import_folders(&tx, &payload)?;

    // Step 5: Import entries (with duplicate handling).
    let (entry_map, entry_stats) =
        import_entries(&tx, master_key, &payload, &folder_map, duplicate_mode)?;

    // Step 6: Import attachments (with entry ID remapping).
    let attachment_count = import_attachments(&tx, master_key, &payload, &entry_map)?;

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
///
/// Verrou exports are always post-quantum envelopes (magic `VRENV1`): the
/// signature is verified **fail-closed** before any decryption, then the
/// content key is recovered via the KEM path when `vault_master_key` matches
/// the source vault, otherwise via the password slot inside the inner blob.
/// A non-envelope file is rejected — there is no pre-launch installed base of
/// the old raw `vault_format` export, so a mandatory envelope guarantees every
/// import is signature-verified and KEM-wrapped.
fn decrypt_import_file(
    file_data: &[u8],
    import_password: &[u8],
    vault_master_key: Option<&SecretBytes<32>>,
) -> Result<ExportPayload, VaultError> {
    // Verrou exports are always PQ envelopes. Reject anything else: a mandatory
    // envelope guarantees every import is signature-verified and KEM-wrapped.
    if !envelope::has_envelope_magic(file_data) {
        return Err(VaultError::Import(
            "not a valid Verrou export (missing post-quantum envelope)".into(),
        ));
    }
    decrypt_envelope_import(file_data, import_password, vault_master_key)
}

/// Decrypt a post-quantum export envelope.
///
/// Verifies the hybrid signature over the signed portion with the embedded
/// public key (fail-closed) *before* touching any ciphertext, then recovers the
/// content key via KEM (if the importing vault's master key matches the source
/// vault) or the inner password slot, and finally deserializes the inner blob.
fn decrypt_envelope_import(
    file_data: &[u8],
    import_password: &[u8],
    vault_master_key: Option<&SecretBytes<32>>,
) -> Result<ExportPayload, VaultError> {
    // Parse structure (bounds-checked, no trust placed in contents yet).
    let parsed = envelope::parse_envelope(file_data)?;

    // FAIL-CLOSED: verify the hybrid signature before any decryption. A failure
    // here aborts the import without ever processing the inner blob.
    signing::verify(
        parsed.signed_portion,
        &parsed.signature,
        &parsed.signing_public,
    )
    .map_err(|_| VaultError::Import("export envelope signature verification failed".into()))?;

    // Recover the export content key (CEK): prefer the KEM path when the
    // importing vault's master key reproduces the source vault's KEM key pair.
    let content_key = recover_content_key(&parsed, import_password, vault_master_key)?;

    deserialize_inner_blob(parsed.inner_blob, content_key.expose())
}

/// Recover the export content key for an envelope.
///
/// Tries the KEM path first (decapsulate with the importing vault's derived KEM
/// private key, then AEAD-unwrap the sealed CEK). If no master key is supplied,
/// or the KEM path fails (e.g. the envelope came from a *different* vault), it
/// falls back to the inner blob's password slot.
fn recover_content_key(
    parsed: &envelope::ParsedEnvelope<'_>,
    import_password: &[u8],
    vault_master_key: Option<&SecretBytes<32>>,
) -> Result<SecretBuffer, VaultError> {
    if let Some(master_key) = vault_master_key {
        if let Some(cek) = try_recover_content_key_via_kem(parsed, master_key.expose()) {
            return Ok(cek);
        }
    }

    // Fall back to the password slot inside the inner blob (cross-vault import
    // or no session key available).
    let import_master_key = recover_password_slot_key(parsed.inner_blob, import_password)?;
    Ok(import_master_key)
}

/// Attempt KEM-based content-key recovery.
///
/// Returns `Some(cek)` only if both decapsulation produces a shared secret AND
/// the wrapped CEK authenticates under it (correct vault). Returns `None` on
/// any failure so the caller can fall back to the password path. Errors are
/// intentionally swallowed here — a mismatch is an expected, benign outcome
/// when importing another vault's export.
fn try_recover_content_key_via_kem(
    parsed: &envelope::ParsedEnvelope<'_>,
    master_key: &[u8],
) -> Option<SecretBuffer> {
    let kem_keypair = kem::derive_keypair(master_key, VAULT_KEM_CONTEXT).ok()?;
    let shared_secret = kem::decapsulate(&parsed.kem_ciphertext, &kem_keypair.private).ok()?;
    // AEAD-unwrap authenticates: a wrong vault yields a different shared secret
    // and decryption fails, so this returns None and we fall back to password.
    symmetric::decrypt(&parsed.wrapped_cek, shared_secret.expose(), KEM_CEK_AAD).ok()
}

/// Recover an inner-blob content key from its password slot.
///
/// Shared by the legacy raw-file path and the envelope password fallback.
/// Validates the version, locates the password slot, derives the wrapping key
/// via Argon2id, and unwraps the slot.
fn recover_password_slot_key(
    inner_blob: &[u8],
    import_password: &[u8],
) -> Result<SecretBuffer, VaultError> {
    let header = vault_format::parse_header_only(inner_blob)?;

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

    // Derive wrapping key and recover the import content key.
    let wrapping_key = kdf::derive(import_password, salt, &header.session_params)?;
    slots::unwrap_slot(password_slot, wrapping_key.expose())
        .map_err(|_| VaultError::InvalidPassword)
}

/// Deserialize an inner `vault_format` blob with a recovered content key into a
/// validated [`ExportPayload`].
///
/// Performs the AEAD payload decryption, JSON parse, payload-version check, and
/// attachment-size guard. The payload version must still be checked here even
/// for the legacy path; the header version is checked in
/// [`recover_password_slot_key`].
fn deserialize_inner_blob(
    inner_blob: &[u8],
    content_key: &[u8],
) -> Result<ExportPayload, VaultError> {
    // For the KEM path the header version has not been checked yet, so verify it
    // here too (cheap, and keeps the envelope path fail-fast on newer formats).
    let header = vault_format::parse_header_only(inner_blob)?;
    if header.version > FORMAT_VERSION {
        return Err(VaultError::Import(
            "This vault was created with a newer version of VERROU. Please update the application."
                .to_string(),
        ));
    }

    // Decrypt the payload.
    let (_header, payload_bytes) = vault_format::deserialize(inner_blob, content_key)?;

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

    // M1 — reject oversized attachment data *before* any further processing.
    check_attachment_sizes(&payload)?;

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

/// Validate attachment sizes in a parsed payload.
///
/// Rejects any attachment whose decoded `data` exceeds [`IMPORT_MAX_ATTACHMENT_BYTES`]
/// or whose `size_bytes` field is inconsistent with the actual data length.
/// Called immediately after JSON deserialization, before any database writes,
/// to prevent denial-of-service via a crafted export file with an oversized attachment.
fn check_attachment_sizes(payload: &ExportPayload) -> Result<(), VaultError> {
    for (i, att) in payload.attachments.iter().enumerate() {
        if att.data.len() > IMPORT_MAX_ATTACHMENT_BYTES {
            return Err(VaultError::FileSizeLimitExceeded {
                max_bytes: IMPORT_MAX_ATTACHMENT_BYTES,
                actual_bytes: att.data.len(),
            });
        }
        if usize::try_from(att.size_bytes) != Ok(att.data.len()) {
            return Err(VaultError::Import(format!(
                "attachment {i}: declared size {} does not match data length {}",
                att.size_bytes,
                att.data.len()
            )));
        }
    }
    Ok(())
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
    conn: &rusqlite::Transaction<'_>,
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
    conn: &rusqlite::Transaction<'_>,
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
    conn: &rusqlite::Transaction<'_>,
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::export::verrou_format::{ExportPayload, ExportedAttachment};

    /// Build a minimal `ExportPayload` with a single attachment whose `data`
    /// field has the given byte count.
    fn make_payload_with_attachment(data_len: usize) -> ExportPayload {
        let data = vec![0u8; data_len];
        ExportPayload {
            version: 1,
            exported_at: "2024-01-01T00:00:00Z".to_string(),
            entries: Vec::new(),
            folders: Vec::new(),
            attachments: vec![ExportedAttachment {
                id: "att-1".to_string(),
                entry_id: "entry-1".to_string(),
                filename: "test.bin".to_string(),
                mime_type: "application/octet-stream".to_string(),
                size_bytes: i64::try_from(data_len).unwrap_or(i64::MAX),
                data,
                created_at: "2024-01-01T00:00:00Z".to_string(),
            }],
        }
    }

    #[test]
    fn attachment_at_limit_is_accepted() {
        let payload = make_payload_with_attachment(IMPORT_MAX_ATTACHMENT_BYTES);
        assert!(check_attachment_sizes(&payload).is_ok());
    }

    #[test]
    fn attachment_one_byte_over_limit_is_rejected() {
        let payload = make_payload_with_attachment(IMPORT_MAX_ATTACHMENT_BYTES + 1);
        let err = check_attachment_sizes(&payload).unwrap_err();
        assert!(
            matches!(
                err,
                VaultError::FileSizeLimitExceeded {
                    max_bytes: IMPORT_MAX_ATTACHMENT_BYTES,
                    ..
                }
            ),
            "expected FileSizeLimitExceeded, got: {err:?}"
        );
    }

    #[test]
    fn attachment_declared_size_mismatch_is_rejected() {
        let mut payload = make_payload_with_attachment(100);
        // Tamper: claim a different size than the actual data length.
        payload.attachments[0].size_bytes = 999;
        let err = check_attachment_sizes(&payload).unwrap_err();
        assert!(
            matches!(err, VaultError::Import(_)),
            "expected Import error for size mismatch, got: {err:?}"
        );
    }

    #[test]
    fn empty_attachments_list_passes() {
        let payload = ExportPayload {
            version: 1,
            exported_at: "2024-01-01T00:00:00Z".to_string(),
            entries: Vec::new(),
            folders: Vec::new(),
            attachments: Vec::new(),
        };
        assert!(check_attachment_sizes(&payload).is_ok());
    }
}
