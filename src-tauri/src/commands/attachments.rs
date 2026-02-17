//! File attachment IPC commands.
//!
//! All file I/O (read from disk, write to disk) is performed in Rust
//! via `std::fs`. The frontend only provides file paths obtained from
//! `tauri-plugin-dialog` (open/save dialogs).

#![allow(clippy::significant_drop_tightening, clippy::missing_errors_doc)]

use std::path::Path;

use serde::{Deserialize, Serialize};
use tauri::State;
use zeroize::Zeroize;

use crate::state::ManagedVaultState;

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

/// Attachment metadata returned to the frontend.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentMetadataDto {
    pub id: String,
    pub entry_id: String,
    pub filename: String,
    pub mime_type: String,
    pub size_bytes: i64,
    pub created_at: String,
}

impl From<verrou_vault::AttachmentMetadata> for AttachmentMetadataDto {
    fn from(m: verrou_vault::AttachmentMetadata) -> Self {
        Self {
            id: m.id,
            entry_id: m.entry_id,
            filename: m.filename,
            mime_type: m.mime_type,
            size_bytes: m.size_bytes,
            created_at: m.created_at,
        }
    }
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

fn map_vault_error(err: &verrou_vault::VaultError) -> String {
    match err {
        verrou_vault::VaultError::EntryNotFound(_) => {
            "Entry not found. It may have been deleted.".to_string()
        }
        verrou_vault::VaultError::AttachmentNotFound(_) => {
            "Attachment not found. It may have been deleted.".to_string()
        }
        verrou_vault::VaultError::Locked => "Vault is locked. Please unlock first.".to_string(),
        verrou_vault::VaultError::FileSizeLimitExceeded {
            max_bytes,
            actual_bytes,
        } => {
            let max_mb = max_bytes / (1024 * 1024);
            let actual_mb = actual_bytes / (1024 * 1024);
            format!("File is too large ({actual_mb} MB). Maximum allowed size is {max_mb} MB.")
        }
        verrou_vault::VaultError::AttachmentCountExceeded { max, .. } => {
            format!("Maximum of {max} attachments per entry reached.")
        }
        _ => "Operation failed. Please try again.".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// Add a file attachment to an entry.
///
/// Reads the file from `file_path`, encrypts it, and stores it in the vault.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn add_attachment(
    vault_state: State<'_, ManagedVaultState>,
    entry_id: String,
    file_path: String,
) -> Result<AttachmentMetadataDto, String> {
    let state = vault_state
        .lock()
        .map_err(|_| "Internal error: failed to acquire vault lock".to_string())?;
    let session = state
        .as_ref()
        .ok_or_else(|| "Vault is locked. Please unlock first.".to_string())?;

    // Read file from disk.
    let path = Path::new(&file_path);
    let mut data = std::fs::read(path).map_err(|e| format!("Failed to read file: {e}"))?;

    // Extract filename from path.
    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unnamed");

    let mime_type = verrou_vault::mime_from_filename(filename);

    let result = verrou_vault::add_attachment(
        session.db.connection(),
        &session.master_key,
        &entry_id,
        filename,
        mime_type,
        &data,
    )
    .map_err(|e| map_vault_error(&e));

    // Zeroize file content from memory.
    data.zeroize();

    result.map(AttachmentMetadataDto::from)
}

/// List attachment metadata for an entry (no file content).
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn list_attachments(
    vault_state: State<'_, ManagedVaultState>,
    entry_id: String,
) -> Result<Vec<AttachmentMetadataDto>, String> {
    let state = vault_state
        .lock()
        .map_err(|_| "Internal error: failed to acquire vault lock".to_string())?;
    let session = state
        .as_ref()
        .ok_or_else(|| "Vault is locked. Please unlock first.".to_string())?;

    verrou_vault::list_attachments(session.db.connection(), &entry_id)
        .map(|list| list.into_iter().map(AttachmentMetadataDto::from).collect())
        .map_err(|e| map_vault_error(&e))
}

/// Export (decrypt and save) an attachment to disk.
///
/// Decrypts the attachment and writes it to `save_path`. The decrypted
/// content is zeroized from memory after the write completes.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn export_attachment(
    vault_state: State<'_, ManagedVaultState>,
    attachment_id: String,
    save_path: String,
) -> Result<(), String> {
    let state = vault_state
        .lock()
        .map_err(|_| "Internal error: failed to acquire vault lock".to_string())?;
    let session = state
        .as_ref()
        .ok_or_else(|| "Vault is locked. Please unlock first.".to_string())?;

    let (_metadata, mut plaintext) =
        verrou_vault::get_attachment(session.db.connection(), &session.master_key, &attachment_id)
            .map_err(|e| map_vault_error(&e))?;

    let write_result = std::fs::write(&save_path, &plaintext);

    // Zeroize decrypted content from memory regardless of write outcome.
    plaintext.zeroize();

    write_result.map_err(|e| format!("Failed to save file: {e}"))
}

/// Delete an attachment by ID.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn delete_attachment(
    vault_state: State<'_, ManagedVaultState>,
    attachment_id: String,
) -> Result<(), String> {
    let state = vault_state
        .lock()
        .map_err(|_| "Internal error: failed to acquire vault lock".to_string())?;
    let session = state
        .as_ref()
        .ok_or_else(|| "Vault is locked. Please unlock first.".to_string())?;

    verrou_vault::delete_attachment(session.db.connection(), &attachment_id)
        .map_err(|e| map_vault_error(&e))
}
