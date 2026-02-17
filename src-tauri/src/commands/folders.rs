//! Folder CRUD IPC commands.
//!
//! Each command returns a DTO with `#[serde(rename_all = "camelCase")]`.

#![allow(clippy::significant_drop_tightening, clippy::missing_errors_doc)]

use serde::{Deserialize, Serialize};
use tauri::State;

use crate::state::ManagedVaultState;

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderDto {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    pub sort_order: i32,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderWithCountDto {
    #[serde(flatten)]
    pub folder: FolderDto,
    pub entry_count: u32,
}

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

fn folder_to_dto(f: &verrou_vault::Folder) -> FolderDto {
    FolderDto {
        id: f.id.clone(),
        name: f.name.clone(),
        parent_id: f.parent_id.clone(),
        sort_order: f.sort_order,
        created_at: f.created_at.clone(),
        updated_at: f.updated_at.clone(),
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// Create a new folder.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn create_folder(
    name: String,
    vault_state: State<'_, ManagedVaultState>,
) -> Result<FolderDto, String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err("Folder name cannot be empty.".to_string());
    }
    if trimmed.len() > 100 {
        return Err("Folder name too long (max 100 characters).".to_string());
    }

    let state = vault_state
        .lock()
        .map_err(|_| "Internal error: failed to acquire vault lock".to_string())?;
    let session = state
        .as_ref()
        .ok_or_else(|| "Vault is locked. Please unlock first.".to_string())?;

    let folder = verrou_vault::create_folder(session.db.connection(), trimmed)
        .map_err(|e| format!("Failed to create folder: {e}"))?;

    Ok(folder_to_dto(&folder))
}

/// List all folders with entry counts.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn list_folders(
    vault_state: State<'_, ManagedVaultState>,
) -> Result<Vec<FolderWithCountDto>, String> {
    let state = vault_state
        .lock()
        .map_err(|_| "Internal error: failed to acquire vault lock".to_string())?;
    let session = state
        .as_ref()
        .ok_or_else(|| "Vault is locked. Please unlock first.".to_string())?;

    let items = verrou_vault::list_folders_with_counts(session.db.connection())
        .map_err(|e| format!("Failed to list folders: {e}"))?;

    Ok(items
        .iter()
        .map(|item| FolderWithCountDto {
            folder: folder_to_dto(&item.folder),
            entry_count: item.entry_count,
        })
        .collect())
}

/// Rename an existing folder.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn rename_folder(
    folder_id: String,
    new_name: String,
    vault_state: State<'_, ManagedVaultState>,
) -> Result<FolderDto, String> {
    let trimmed = new_name.trim();
    if trimmed.is_empty() {
        return Err("Folder name cannot be empty.".to_string());
    }
    if trimmed.len() > 100 {
        return Err("Folder name too long (max 100 characters).".to_string());
    }

    let state = vault_state
        .lock()
        .map_err(|_| "Internal error: failed to acquire vault lock".to_string())?;
    let session = state
        .as_ref()
        .ok_or_else(|| "Vault is locked. Please unlock first.".to_string())?;

    let folder = verrou_vault::rename_folder(session.db.connection(), &folder_id, trimmed)
        .map_err(|e| format!("Failed to rename folder: {e}"))?;

    Ok(folder_to_dto(&folder))
}

/// Delete a folder (entries are moved to "All").
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn delete_folder(
    folder_id: String,
    vault_state: State<'_, ManagedVaultState>,
) -> Result<(), String> {
    let state = vault_state
        .lock()
        .map_err(|_| "Internal error: failed to acquire vault lock".to_string())?;
    let session = state
        .as_ref()
        .ok_or_else(|| "Vault is locked. Please unlock first.".to_string())?;

    verrou_vault::delete_folder(session.db.connection(), &folder_id)
        .map_err(|e| format!("Failed to delete folder: {e}"))
}
