//! Vault export IPC command.
//!
//! Exports the entire vault as an encrypted `.verrou` file.
//! Requires re-authentication (password verification) before export.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tauri::State;
use zeroize::Zeroize;

use crate::state::ManagedVaultState;

use super::vault::UnlockErrorResponse;

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

/// Result returned to the frontend on successful vault export.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportVaultResponse {
    /// Number of entries exported.
    pub entry_count: usize,
    /// Number of folders exported.
    pub folder_count: usize,
    /// Number of attachments exported.
    pub attachment_count: usize,
}

// ---------------------------------------------------------------------------
// IPC command
// ---------------------------------------------------------------------------

/// Export the entire vault as an encrypted `.verrou` file.
///
/// The password is verified against the vault header (re-authentication).
/// A fresh encryption key is generated for the export file, independent
/// of the session's master key.
///
/// # Errors
///
/// Returns a structured JSON error string for invalid password, I/O
/// failure, or internal errors.
#[allow(clippy::needless_pass_by_value)] // Tauri requires owned types for IPC
#[tauri::command]
pub async fn export_vault(
    password: String,
    save_path: String,
    vault_dir: String,
    vault_state: State<'_, ManagedVaultState>,
) -> Result<ExportVaultResponse, String> {
    let mut master_key_copy = [0u8; 32];
    {
        let guard = vault_state
            .lock()
            .map_err(|_| "Internal error: failed to acquire vault lock".to_string())?;
        let session = guard
            .as_ref()
            .ok_or_else(|| "Vault is not unlocked.".to_string())?;
        master_key_copy.copy_from_slice(session.master_key.expose());
        drop(guard);
    }

    tauri::async_runtime::spawn_blocking(move || {
        let vault_path = PathBuf::from(&vault_dir);

        // Scope borrows of master_key_copy so we can zeroize it afterwards.
        let result = {
            let req = verrou_vault::ExportVaultRequest {
                password: password.as_bytes(),
                master_key: &master_key_copy,
                vault_dir: &vault_path,
            };

            let db_path = vault_path.join("vault.db");
            let db = verrou_vault::VaultDb::open_raw(&db_path, &master_key_copy)
                .map_err(|e| format!("Failed to open vault database: {e}"))?;

            match verrou_vault::export_vault(db.connection(), &req) {
                Ok(r) => Ok(r),
                Err(verrou_vault::VaultError::InvalidPassword) => {
                    Err(serde_json::to_string(&UnlockErrorResponse {
                        code: "INVALID_PASSWORD".into(),
                        message: "Password is incorrect. Please try again.".into(),
                        remaining_ms: None,
                    })
                    .unwrap_or_else(|_| "Password is incorrect.".into()))
                }
                Err(verrou_vault::VaultError::Io(_)) => {
                    Err(serde_json::to_string(&UnlockErrorResponse {
                        code: "IO_ERROR".into(),
                        message:
                            "A file system error occurred during export. Please check disk space and try again."
                                .into(),
                        remaining_ms: None,
                    })
                    .unwrap_or_else(|_| "File system error.".into()))
                }
                Err(e) => {
                    Err(serde_json::to_string(&UnlockErrorResponse {
                        code: "INTERNAL_ERROR".into(),
                        message: format!("Export failed: {e}"),
                        remaining_ms: None,
                    })
                    .unwrap_or_else(|_| "Export failed.".into()))
                }
            }
        };

        // Zeroize the master key copy now that all borrows are dropped.
        master_key_copy.zeroize();

        let result = result?;

        // Write export data to the user-selected path.
        std::fs::write(&save_path, &result.export_data).map_err(|e| {
            serde_json::to_string(&UnlockErrorResponse {
                code: "IO_ERROR".into(),
                message: format!("Failed to write export file: {e}"),
                remaining_ms: None,
            })
            .unwrap_or_else(|_| format!("Failed to write export file: {e}"))
        })?;

        Ok(ExportVaultResponse {
            entry_count: result.entry_count,
            folder_count: result.folder_count,
            attachment_count: result.attachment_count,
        })
    })
    .await
    .map_err(|e| format!("Export task failed: {e}"))?
}
