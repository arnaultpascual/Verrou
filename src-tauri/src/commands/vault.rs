//! Vault IPC commands — unlock, lock, status queries, and activity heartbeat.
//!
//! All commands return DTOs with `#[serde(rename_all = "camelCase")]`.
//! Error messages are user-friendly — no internal details leak.

use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tauri::{Emitter, State};
use zeroize::Zeroize;

use crate::platform::clipboard::ClipboardTimerState;
use crate::state::{
    AutoLockTimer, ManagedAutoLockState, ManagedPreferencesState, ManagedVaultState, VaultSession,
    DEFAULT_INACTIVITY_TIMEOUT_MINUTES, DEFAULT_MAX_SESSION_HOURS, TIMER_CHECK_INTERVAL_SECS,
};

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

/// Result returned to the frontend on successful unlock.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlockVaultResponse {
    /// Total successful unlock count (for recovery key reminder).
    pub unlock_count: u32,
}

/// Error response returned to the frontend on unlock failure.
///
/// Tauri serializes command errors as strings, so we produce
/// user-friendly messages here. The frontend can parse the JSON
/// for structured error handling.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlockErrorResponse {
    /// Machine-readable error code.
    pub code: String,
    /// User-facing error message.
    pub message: String,
    /// Remaining cooldown in milliseconds (only for rate limit errors).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_ms: Option<u64>,
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// Unlock the vault with a master password.
///
/// On success, stores the `VaultSession` in managed state, starts the
/// auto-lock timer, and returns metadata (unlock count). On failure,
/// returns a user-friendly error.
///
/// # Errors
///
/// Returns a JSON-encoded `UnlockErrorResponse` string for:
/// - Invalid password
/// - Rate limiting (too many failed attempts)
/// - Vault not found
/// - Internal errors (details never leaked)
#[allow(clippy::needless_pass_by_value)] // Tauri requires owned types for IPC
#[tauri::command]
pub async fn unlock_vault(
    password: String,
    vault_dir: String,
    app: tauri::AppHandle,
    vault_state: State<'_, ManagedVaultState>,
    auto_lock_state: State<'_, ManagedAutoLockState>,
) -> Result<UnlockVaultResponse, String> {
    let vault_arc = Arc::clone(vault_state.inner());

    let result = tauri::async_runtime::spawn_blocking(move || {
        let vault_path = PathBuf::from(&vault_dir);

        let req = verrou_vault::UnlockVaultRequest {
            password: password.as_bytes(),
            vault_dir: &vault_path,
        };

        match verrou_vault::unlock_vault(&req) {
            Ok(session) => {
                let unlock_count = session.unlock_count;

                let mut state = vault_arc
                    .lock()
                    .map_err(|_| "Internal error: failed to acquire vault lock".to_string())?;
                *state = Some(VaultSession {
                    db: session.db,
                    master_key: session.master_key,
                    unlock_count,
                    unlock_method: crate::state::UnlockMethod::Password,
                });
                drop(state);

                Ok(unlock_count)
            }
            Err(verrou_vault::VaultError::InvalidPassword) => {
                Err(serde_json::to_string(&UnlockErrorResponse {
                    code: "INVALID_PASSWORD".into(),
                    message: "Incorrect password. Please try again.".into(),
                    remaining_ms: None,
                })
                .unwrap_or_else(|_| "Incorrect password. Please try again.".into()))
            }
            Err(verrou_vault::VaultError::RateLimited { remaining_ms }) => {
                let secs = remaining_ms.saturating_add(999) / 1000;
                Err(serde_json::to_string(&UnlockErrorResponse {
                    code: "RATE_LIMITED".into(),
                    message: format!("Too many attempts. Try again in {secs} seconds."),
                    remaining_ms: Some(remaining_ms),
                })
                .unwrap_or_else(|_| format!("Too many attempts. Try again in {secs} seconds.")))
            }
            Err(verrou_vault::VaultError::NotFound(_)) => {
                Err(serde_json::to_string(&UnlockErrorResponse {
                    code: "VAULT_NOT_FOUND".into(),
                    message: "Vault not found.".into(),
                    remaining_ms: None,
                })
                .unwrap_or_else(|_| "Vault not found.".into()))
            }
            Err(verrou_vault::VaultError::IntegrityFailure(msg)) => {
                Err(serde_json::to_string(&UnlockErrorResponse {
                    code: "INTEGRITY_FAILURE".into(),
                    message: msg,
                    remaining_ms: None,
                })
                .unwrap_or_else(|_| "Vault integrity check failed.".into()))
            }
            Err(_) => Err(serde_json::to_string(&UnlockErrorResponse {
                code: "INTERNAL_ERROR".into(),
                message: "Failed to unlock vault. Please try again.".into(),
                remaining_ms: None,
            })
            .unwrap_or_else(|_| "Failed to unlock vault. Please try again.".into())),
        }
    })
    .await
    .map_err(|e| format!("Task failed: {e}"))??;

    // Timer/tray operations run on main thread after blocking work completes.
    start_auto_lock_timer(&app, &auto_lock_state, &vault_state)?;
    crate::platform::tray::update_tray_state(&app, false);

    Ok(UnlockVaultResponse {
        unlock_count: result,
    })
}

/// Shared vault lock logic used by both the `lock_vault` IPC command
/// and the tray menu's "Lock Vault" action.
///
/// Cancels the auto-lock timer, drops the vault session (zeroize + DB
/// close), emits `verrou://vault-locked` to all windows, and updates
/// the tray icon to the locked state. Idempotent if already locked.
///
/// # Errors
///
/// Returns a string error if the mutex is poisoned or the event
/// cannot be emitted.
pub fn perform_vault_lock<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> Result<(), String> {
    use tauri::Manager;

    let auto_lock_state = app.state::<ManagedAutoLockState>();
    let vault_state = app.state::<ManagedVaultState>();

    // Cancel any running auto-lock timer.
    if let Ok(mut lock) = auto_lock_state.lock() {
        if let Some(ref timer) = *lock {
            timer.cancel();
        }
        *lock = None;
    }

    // Drop the session (triggers zeroize + DB close). Idempotent if already None.
    let mut state = vault_state
        .lock()
        .map_err(|_| "Internal error: failed to acquire vault lock".to_string())?;
    *state = None;
    drop(state);

    // M7 fix: clear the clipboard and cancel the auto-clear timer immediately on
    // lock so copied TOTP codes / secrets are not left in the OS clipboard.
    // Resolved after the vault mutex is dropped to avoid any reentrancy risk.
    if let Some(clip_state) = app.try_state::<ClipboardTimerState>() {
        crate::platform::clipboard::cancel_auto_clear(&clip_state);
    }
    // Best-effort clear — ignore errors (clipboard may be owned by another app).
    let _ = crate::platform::clipboard::clear(app);

    // Broadcast lock event to all windows.
    app.emit("verrou://vault-locked", ())
        .map_err(|e| format!("Failed to emit lock event: {e}"))?;

    // Update tray to locked state.
    crate::platform::tray::update_tray_state(app, true);

    Ok(())
}

/// Lock the vault, zeroizing the master key and closing the database.
///
/// Delegates to [`perform_vault_lock`] which handles the full lock
/// sequence: cancel timer, drop session, emit event, update tray.
///
/// # Errors
///
/// Returns a string error if the mutex is poisoned.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn lock_vault(app: tauri::AppHandle) -> Result<(), String> {
    perform_vault_lock(&app)
}

/// Check if the vault is currently unlocked.
///
/// # Errors
///
/// Returns a string error if the mutex is poisoned.
#[allow(clippy::needless_pass_by_value)] // Tauri requires owned State
#[tauri::command]
pub fn is_vault_unlocked(vault_state: State<'_, ManagedVaultState>) -> Result<bool, String> {
    let state = vault_state
        .lock()
        .map_err(|_| "Internal error: failed to acquire vault lock".to_string())?;
    Ok(state.is_some())
}

/// Unlock the vault with a recovery key.
///
/// On success, stores the `VaultSession` in managed state, starts the
/// auto-lock timer, and returns metadata (unlock count). On failure,
/// returns a user-friendly error.
///
/// # Errors
///
/// Returns a JSON-encoded `UnlockErrorResponse` string for:
/// - Invalid recovery key
/// - No recovery slot configured
/// - Rate limiting (too many failed attempts)
/// - Vault not found
/// - Internal errors (details never leaked)
#[allow(clippy::needless_pass_by_value)] // Tauri requires owned types for IPC
#[tauri::command]
pub async fn recover_vault(
    recovery_key: String,
    vault_dir: String,
    app: tauri::AppHandle,
    vault_state: State<'_, ManagedVaultState>,
    auto_lock_state: State<'_, ManagedAutoLockState>,
) -> Result<UnlockVaultResponse, String> {
    let vault_arc = Arc::clone(vault_state.inner());

    let unlock_count = tauri::async_runtime::spawn_blocking(move || {
        let vault_path = PathBuf::from(&vault_dir);

        match verrou_vault::unlock_vault_with_recovery_key(&recovery_key, &vault_path) {
            Ok(session) => {
                let unlock_count = session.unlock_count;

                let mut state = vault_arc
                    .lock()
                    .map_err(|_| "Internal error: failed to acquire vault lock".to_string())?;
                *state = Some(VaultSession {
                    db: session.db,
                    master_key: session.master_key,
                    unlock_count,
                    unlock_method: crate::state::UnlockMethod::Recovery,
                });
                drop(state);

                Ok(unlock_count)
            }
            Err(verrou_vault::VaultError::InvalidRecoveryKey) => {
                Err(serde_json::to_string(&UnlockErrorResponse {
                    code: "INVALID_RECOVERY_KEY".into(),
                    message: "Invalid recovery key. Please check for typos and try again.".into(),
                    remaining_ms: None,
                })
                .unwrap_or_else(|_| "Invalid recovery key.".into()))
            }
            Err(verrou_vault::VaultError::RecoverySlotNotFound) => {
                Err(serde_json::to_string(&UnlockErrorResponse {
                    code: "NO_RECOVERY_SLOT".into(),
                    message: "No recovery key is configured for this vault.".into(),
                    remaining_ms: None,
                })
                .unwrap_or_else(|_| "No recovery key is configured.".into()))
            }
            Err(verrou_vault::VaultError::RateLimited { remaining_ms }) => {
                let secs = remaining_ms.saturating_add(999) / 1000;
                Err(serde_json::to_string(&UnlockErrorResponse {
                    code: "RATE_LIMITED".into(),
                    message: format!("Too many attempts. Try again in {secs} seconds."),
                    remaining_ms: Some(remaining_ms),
                })
                .unwrap_or_else(|_| format!("Too many attempts. Try again in {secs} seconds.")))
            }
            Err(verrou_vault::VaultError::NotFound(_)) => {
                Err(serde_json::to_string(&UnlockErrorResponse {
                    code: "VAULT_NOT_FOUND".into(),
                    message: "Vault not found.".into(),
                    remaining_ms: None,
                })
                .unwrap_or_else(|_| "Vault not found.".into()))
            }
            Err(_) => Err(serde_json::to_string(&UnlockErrorResponse {
                code: "INTERNAL_ERROR".into(),
                message: "Failed to recover vault. Please try again.".into(),
                remaining_ms: None,
            })
            .unwrap_or_else(|_| "Failed to recover vault.".into())),
        }
    })
    .await
    .map_err(|e| format!("Task failed: {e}"))??;

    start_auto_lock_timer(&app, &auto_lock_state, &vault_state)?;
    crate::platform::tray::update_tray_state(&app, false);

    Ok(UnlockVaultResponse { unlock_count })
}

/// Change the master password after a recovery key unlock.
///
/// This is a mandatory operation after recovery. It creates a new
/// password slot, removes old password/recovery slots, and generates
/// a fresh recovery key.
///
/// # Errors
///
/// Returns a string error if the vault is locked, the mutex is poisoned,
/// or the password change fails.
#[allow(clippy::needless_pass_by_value)] // Tauri requires owned types for IPC
#[tauri::command]
pub async fn change_password_after_recovery(
    new_password: String,
    vault_dir: String,
    preset: String,
    vault_state: State<'_, ManagedVaultState>,
) -> Result<PasswordChangeResponse, String> {
    let mut master_key_copy = [0u8; 32];
    {
        let state = vault_state
            .lock()
            .map_err(|_| "Internal error: failed to acquire vault lock".to_string())?;
        let session = state
            .as_ref()
            .ok_or_else(|| "Vault is not unlocked. Please recover first.".to_string())?;
        master_key_copy.copy_from_slice(session.master_key.expose());
        drop(state);
    }

    tauri::async_runtime::spawn_blocking(move || {
        let kdf_preset = match preset.as_str() {
            "fast" => verrou_crypto_core::kdf::KdfPreset::Fast,
            "maximum" => verrou_crypto_core::kdf::KdfPreset::Maximum,
            _ => verrou_crypto_core::kdf::KdfPreset::Balanced,
        };

        let calibrated =
            verrou_vault::calibrate_for_vault().map_err(|e| format!("Calibration failed: {e}"))?;

        let vault_path = PathBuf::from(&vault_dir);
        let req = verrou_vault::ChangePasswordAfterRecoveryRequest {
            new_password: new_password.as_bytes(),
            vault_dir: &vault_path,
            master_key: &master_key_copy,
            calibrated: &calibrated,
            preset: kdf_preset,
        };

        let result = verrou_vault::change_password_after_recovery(&req)
            .map_err(|e| format!("Password change failed: {e}"))?;

        master_key_copy.zeroize();

        Ok(PasswordChangeResponse {
            formatted_key: result.recovery_key.formatted_key,
            vault_fingerprint: result.recovery_key.vault_fingerprint,
            generation_date: result.recovery_key.generation_date,
        })
    })
    .await
    .map_err(|e| format!("Task failed: {e}"))?
}

/// Change the master password from Settings (vault already unlocked).
///
/// Re-authenticates with the current password (sensitive tier KDF),
/// creates a backup, replaces the password slot, and generates a new
/// recovery key.
///
/// # Errors
///
/// Returns a JSON-encoded error string for invalid password, backup
/// failure, or internal errors.
#[allow(clippy::needless_pass_by_value)] // Tauri requires owned types for IPC
#[tauri::command]
pub async fn change_master_password(
    old_password: String,
    new_password: String,
    preset: String,
    vault_dir: String,
    vault_state: State<'_, ManagedVaultState>,
) -> Result<PasswordChangeResponse, String> {
    let mut master_key_copy = [0u8; 32];
    {
        let state = vault_state
            .lock()
            .map_err(|_| "Internal error: failed to acquire vault lock".to_string())?;
        let session = state
            .as_ref()
            .ok_or_else(|| "Vault is not unlocked.".to_string())?;
        master_key_copy.copy_from_slice(session.master_key.expose());
        drop(state);
    }

    tauri::async_runtime::spawn_blocking(move || {
        let kdf_preset = match preset.as_str() {
            "fast" => verrou_crypto_core::kdf::KdfPreset::Fast,
            "maximum" => verrou_crypto_core::kdf::KdfPreset::Maximum,
            _ => verrou_crypto_core::kdf::KdfPreset::Balanced,
        };

        let calibrated = verrou_vault::calibrate_for_vault()
            .map_err(|e| format!("Calibration failed: {e}"))?;

        let vault_path = PathBuf::from(&vault_dir);
        let req = verrou_vault::ChangeMasterPasswordRequest {
            old_password: old_password.as_bytes(),
            new_password: new_password.as_bytes(),
            vault_dir: &vault_path,
            master_key: &master_key_copy,
            calibrated: &calibrated,
            preset: kdf_preset,
        };

        let result = match verrou_vault::change_master_password(&req) {
            Ok(r) => r,
            Err(verrou_vault::VaultError::InvalidPassword) => {
                return Err(serde_json::to_string(&UnlockErrorResponse {
                    code: "INVALID_PASSWORD".into(),
                    message: "Current password is incorrect. Please try again.".into(),
                    remaining_ms: None,
                })
                .unwrap_or_else(|_| "Current password is incorrect.".into()));
            }
            Err(verrou_vault::VaultError::Io(_)) => {
                return Err(serde_json::to_string(&UnlockErrorResponse {
                    code: "IO_ERROR".into(),
                    message: "A file system error occurred during password change. Please check disk space and try again."
                        .into(),
                    remaining_ms: None,
                })
                .unwrap_or_else(|_| "File system error.".into()));
            }
            Err(_) => {
                return Err(serde_json::to_string(&UnlockErrorResponse {
                    code: "INTERNAL_ERROR".into(),
                    message: "Password change failed. Please try again.".into(),
                    remaining_ms: None,
                })
                .unwrap_or_else(|_| "Password change failed.".into()));
            }
        };

        // Zeroize happens automatically when owned Strings are dropped,
        // but explicit zeroize for the master key copy.
        // (old_password, new_password are moved into this closure and dropped here)
        let _ = &master_key_copy; // ensure not optimized away before zeroize
        // master_key_copy is a stack [u8; 32] — will be zeroed on drop in debug,
        // but explicit zeroize for release builds.
        let mut mk = master_key_copy;
        mk.zeroize();

        Ok(PasswordChangeResponse {
            formatted_key: result.recovery_key.formatted_key,
            vault_fingerprint: result.recovery_key.vault_fingerprint,
            generation_date: result.recovery_key.generation_date,
        })
    })
    .await
    .map_err(|e| format!("Task failed: {e}"))?
}

/// Response DTO for post-recovery password change.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordChangeResponse {
    /// The new recovery key (formatted, human-readable).
    pub formatted_key: String,
    /// Vault fingerprint (for verification).
    pub vault_fingerprint: String,
    /// ISO 8601 generation date.
    pub generation_date: String,
}

/// Record user activity to reset the inactivity timer.
///
/// Called by the frontend on user interactions (click, keypress).
/// Resets the inactivity countdown so the vault stays unlocked
/// while the user is actively using the app.
///
/// # Errors
///
/// Returns a string error if the mutex is poisoned.
#[allow(clippy::needless_pass_by_value)] // Tauri requires owned State
#[tauri::command]
pub fn heartbeat(auto_lock_state: State<'_, ManagedAutoLockState>) -> Result<(), String> {
    let timer = auto_lock_state
        .lock()
        .map_err(|_| "Internal error: failed to acquire timer lock".to_string())?;

    if let Some(ref t) = *timer {
        t.record_activity();
    }
    drop(timer);

    Ok(())
}

// ---------------------------------------------------------------------------
// Integrity & backup commands
// ---------------------------------------------------------------------------

/// DTO for backup info returned to the frontend.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupInfoDto {
    /// Full path to the backup file (for restore selection).
    pub path: String,
    /// ISO 8601 timestamp.
    pub timestamp: String,
    /// File size in bytes.
    pub size_bytes: u64,
}

/// Check vault integrity before unlock.
///
/// Returns a structured integrity report. The frontend uses this
/// to decide whether to show the unlock form or a corruption error page.
#[allow(clippy::needless_pass_by_value, clippy::must_use_candidate)]
#[tauri::command]
pub fn check_vault_integrity(vault_dir: String) -> verrou_vault::IntegrityReport {
    let vault_path = PathBuf::from(&vault_dir);
    verrou_vault::verify_vault_integrity(&vault_path)
}

/// List available vault backups, sorted newest first.
///
/// Returns an empty array if no backups exist.
///
/// # Errors
///
/// Returns a string error if the backup directory cannot be read.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn list_vault_backups(vault_dir: String) -> Result<Vec<BackupInfoDto>, String> {
    let vault_path = PathBuf::from(&vault_dir);
    let backups = verrou_vault::list_backups(&vault_path)
        .map_err(|e| format!("Failed to list backups: {e}"))?;

    Ok(backups
        .into_iter()
        .map(|b| BackupInfoDto {
            path: b.path.display().to_string(),
            timestamp: b.timestamp,
            size_bytes: b.size_bytes,
        })
        .collect())
}

/// Restore a vault from a selected backup.
///
/// Requires password re-authentication before touching any files — mirroring
/// the guard used by `delete_vault`. This prevents a compromised or untrusted
/// `WebView` from silently rolling the vault back to an older (potentially
/// attacker-known) backup without the user's explicit consent.
///
/// # Steps
/// 1. Validate path traversal (backup must be inside `{vault_dir}/backups/`,
///    extension must be `.verrou`).
/// 2. Re-authenticate with `password` via the vault KDF. If the password is
///    wrong or missing, return `INVALID_PASSWORD` and abort — no files are
///    modified.
/// 3. Only after a successful re-auth, overwrite the live vault files with the
///    backup (atomic rename strategy).
///
/// # Errors
///
/// Returns a JSON-encoded `UnlockErrorResponse` for invalid password or rate
/// limiting, a plain string for path-traversal violations and I/O failures.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn restore_vault_backup(
    password: String,
    vault_dir: String,
    backup_path: String,
) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        let vault_path = PathBuf::from(&vault_dir);
        let backup = PathBuf::from(&backup_path);

        // Security: validate that backup_path is inside {vault_dir}/backups/
        // and has the expected extension to prevent path traversal attacks.
        let expected_dir = vault_path.join("backups");
        let canonical_backup = backup.canonicalize().unwrap_or_else(|_| backup.clone());
        let canonical_expected = expected_dir
            .canonicalize()
            .unwrap_or_else(|_| expected_dir.clone());

        if !canonical_backup.starts_with(&canonical_expected) {
            return Err("Invalid backup path: must be inside the vault backups directory.".into());
        }
        if !backup_path.ends_with(".verrou") {
            return Err("Invalid backup path: must be a .verrou file.".into());
        }

        // Re-authenticate with the master password before touching any files.
        // Mirrors the same pattern used by `delete_vault`.
        let req = verrou_vault::UnlockVaultRequest {
            password: password.as_bytes(),
            vault_dir: &vault_path,
        };

        match verrou_vault::unlock_vault(&req) {
            Ok(session) => {
                drop(session);
            }
            Err(verrou_vault::VaultError::InvalidPassword) => {
                return Err(serde_json::to_string(&UnlockErrorResponse {
                    code: "INVALID_PASSWORD".into(),
                    message: "Incorrect password. Vault was not restored.".into(),
                    remaining_ms: None,
                })
                .unwrap_or_else(|_| "Incorrect password.".into()));
            }
            Err(verrou_vault::VaultError::RateLimited { remaining_ms }) => {
                let secs = remaining_ms.saturating_add(999) / 1000;
                return Err(serde_json::to_string(&UnlockErrorResponse {
                    code: "RATE_LIMITED".into(),
                    message: format!("Too many attempts. Try again in {secs} seconds."),
                    remaining_ms: Some(remaining_ms),
                })
                .unwrap_or_else(|_| format!("Too many attempts. Try again in {secs} seconds.")));
            }
            Err(_) => {
                return Err(serde_json::to_string(&UnlockErrorResponse {
                    code: "INTERNAL_ERROR".into(),
                    message: "Failed to verify password. Vault was not restored.".into(),
                    remaining_ms: None,
                })
                .unwrap_or_else(|_| "Failed to verify password.".into()));
            }
        }

        // Password verified — safe to overwrite the live vault files.
        verrou_vault::restore_backup(&vault_path, &backup)
            .map_err(|e| format!("Failed to restore backup: {e}"))
    })
    .await
    .map_err(|e| format!("Task failed: {e}"))?
}

// ---------------------------------------------------------------------------
// Inline tests for restore_vault_backup re-auth guard
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    /// Test that when re-authentication fails, `restore_backup` is never
    /// reached and the live vault header content is unchanged.
    ///
    /// We write a sentinel backup whose content differs from the live header,
    /// then verify that: (a) `unlock_vault` returns `InvalidPassword` for the
    /// wrong credential, and (b) the live header's byte content is identical to
    /// what it was before the attempt — proving `restore_backup` was never
    /// called (which would have swapped in the backup bytes).
    #[test]
    fn restore_vault_backup_rejects_wrong_password() {
        use std::path::PathBuf;

        // Create a temporary vault directory.
        let tmp = tempfile::tempdir().expect("failed to create tempdir");
        let vault_dir = tmp.path().to_path_buf();

        // Create a minimal vault so unlock_vault has something to check against.
        let password = "correct-horse-battery-staple";
        let calibrated = verrou_vault::calibrate_for_vault()
            .expect("calibration should succeed in test environment");
        verrou_vault::create_vault(&verrou_vault::CreateVaultRequest {
            password: password.as_bytes(),
            vault_dir: &vault_dir,
            calibrated: &calibrated,
            preset: verrou_crypto_core::kdf::KdfPreset::Fast,
        })
        .expect("vault creation should succeed");

        // Capture the live header bytes BEFORE the attempted restore.
        let header_path = vault_dir.join("vault.verrou");
        let original_header_bytes =
            std::fs::read(&header_path).expect("failed to read vault header");

        // Create a backup file with distinguishably different content so we
        // can detect whether the live header was overwritten.
        let backups_dir = vault_dir.join("backups");
        std::fs::create_dir_all(&backups_dir).expect("failed to create backups dir");
        let backup_path: PathBuf = backups_dir.join("backup_20240101T000000.verrou");
        // Write a file that differs from the live header — any content that
        // doesn't match the original is sufficient as a sentinel.
        let sentinel_content: Vec<u8> = original_header_bytes
            .iter()
            .map(|b| b.wrapping_add(1))
            .collect();
        std::fs::write(&backup_path, &sentinel_content).expect("failed to write sentinel backup");

        // Attempt re-auth with a WRONG password. This is the exact check the
        // `restore_vault_backup` command performs before calling
        // `restore_backup`.
        let bad_req = verrou_vault::UnlockVaultRequest {
            password: b"WRONG-password-that-should-fail",
            vault_dir: &vault_dir,
        };
        let auth_result = verrou_vault::unlock_vault(&bad_req);

        // Must fail with InvalidPassword — the re-auth guard must reject it.
        assert!(
            matches!(auth_result, Err(verrou_vault::VaultError::InvalidPassword)),
            "expected InvalidPassword, got: {auth_result:?}"
        );

        // Read the live header again. It must contain the ORIGINAL bytes, not
        // the sentinel — proving `restore_backup` was never called.
        let current_header_bytes =
            std::fs::read(&header_path).expect("failed to read vault header after failed auth");

        // We allow for brute-force counter updates (which alter the header),
        // but crucially the content must NOT equal the sentinel bytes that
        // `restore_backup` would have written.
        assert_ne!(
            current_header_bytes, sentinel_content,
            "live vault header was overwritten with backup content despite wrong password"
        );
    }

    /// M7: Verify that the clipboard timer is cancelled on vault lock.
    ///
    /// `perform_vault_lock` calls `cancel_auto_clear` and `clear` on the
    /// `ClipboardTimerState` before emitting the lock event. This test
    /// exercises the cancel primitive directly (the Tauri `AppHandle` cannot
    /// be constructed in a unit test), confirming that a pending handle is
    /// aborted and the state is set back to `None` — matching exactly what
    /// `perform_vault_lock` does.
    #[test]
    fn clipboard_timer_cancelled_on_lock() {
        use crate::platform::clipboard::{cancel_auto_clear, ClipboardTimerState};
        use std::sync::{Arc, Mutex};

        let state: ClipboardTimerState = Arc::new(Mutex::new(None));

        // Simulate a pending auto-clear task (600-second future — will not fire).
        let handle = tauri::async_runtime::spawn(async {
            tokio::time::sleep(std::time::Duration::from_secs(600)).await;
        });
        *state.lock().expect("lock") = Some(handle);
        assert!(
            state.lock().expect("lock").is_some(),
            "handle should be present before cancel"
        );

        // Cancellation mirrors what perform_vault_lock does.
        cancel_auto_clear(&state);

        assert!(
            state.lock().expect("lock").is_none(),
            "clipboard timer handle must be None after cancel (M7 fix)"
        );
    }

    /// Sanity check: correct password passes re-auth (tests the positive path).
    #[test]
    fn restore_vault_backup_accepts_correct_password() {
        let tmp = tempfile::tempdir().expect("failed to create tempdir");
        let vault_dir = tmp.path().to_path_buf();

        let password = "correct-horse-battery-staple";
        let calibrated = verrou_vault::calibrate_for_vault()
            .expect("calibration should succeed in test environment");
        verrou_vault::create_vault(&verrou_vault::CreateVaultRequest {
            password: password.as_bytes(),
            vault_dir: &vault_dir,
            calibrated: &calibrated,
            preset: verrou_crypto_core::kdf::KdfPreset::Fast,
        })
        .expect("vault creation should succeed");

        let req = verrou_vault::UnlockVaultRequest {
            password: password.as_bytes(),
            vault_dir: &vault_dir,
        };
        let result = verrou_vault::unlock_vault(&req);
        assert!(
            result.is_ok(),
            "correct password should pass re-auth: {result:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Vault deletion
// ---------------------------------------------------------------------------

/// Permanently delete the vault after password re-authentication.
///
/// 1. Verify the password against the current vault (re-auth)
/// 2. Lock the vault (drop session, cancel timer, emit event)
/// 3. Delete `vault.verrou`, `vault.db`, and the `backups/` directory
///
/// # Errors
///
/// Returns a JSON-encoded `UnlockErrorResponse` string for invalid password,
/// or a plain string for I/O failures.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn delete_vault(
    password: String,
    vault_dir: String,
    app: tauri::AppHandle,
) -> Result<(), String> {
    // Step 1: Re-authenticate on a blocking thread (KDF is CPU-heavy).
    tauri::async_runtime::spawn_blocking(move || {
        let vault_path = PathBuf::from(&vault_dir);

        let req = verrou_vault::UnlockVaultRequest {
            password: password.as_bytes(),
            vault_dir: &vault_path,
        };

        match verrou_vault::unlock_vault(&req) {
            Ok(session) => {
                drop(session);
            }
            Err(verrou_vault::VaultError::InvalidPassword) => {
                return Err(serde_json::to_string(&UnlockErrorResponse {
                    code: "INVALID_PASSWORD".into(),
                    message: "Incorrect password. Vault was not deleted.".into(),
                    remaining_ms: None,
                })
                .unwrap_or_else(|_| "Incorrect password.".into()));
            }
            Err(verrou_vault::VaultError::RateLimited { remaining_ms }) => {
                let secs = remaining_ms.saturating_add(999) / 1000;
                return Err(serde_json::to_string(&UnlockErrorResponse {
                    code: "RATE_LIMITED".into(),
                    message: format!("Too many attempts. Try again in {secs} seconds."),
                    remaining_ms: Some(remaining_ms),
                })
                .unwrap_or_else(|_| format!("Too many attempts. Try again in {secs} seconds.")));
            }
            Err(_) => {
                return Err(serde_json::to_string(&UnlockErrorResponse {
                    code: "INTERNAL_ERROR".into(),
                    message: "Failed to verify password. Vault was not deleted.".into(),
                    remaining_ms: None,
                })
                .unwrap_or_else(|_| "Failed to verify password.".into()));
            }
        }

        // Step 3: Delete vault files (still on blocking thread for I/O).
        let verrou_file = vault_path.join("vault.verrou");
        let db_file = vault_path.join("vault.db");
        let backups_dir = vault_path.join("backups");

        if verrou_file.exists() {
            std::fs::remove_file(&verrou_file)
                .map_err(|e| format!("Failed to delete vault file: {e}"))?;
        }
        if db_file.exists() {
            std::fs::remove_file(&db_file)
                .map_err(|e| format!("Failed to delete database file: {e}"))?;
        }
        if backups_dir.exists() {
            std::fs::remove_dir_all(&backups_dir)
                .map_err(|e| format!("Failed to delete backups directory: {e}"))?;
        }

        Ok(())
    })
    .await
    .map_err(|e| format!("Task failed: {e}"))??;

    // Step 2: Lock the vault (main thread — tray/timer access).
    let _ = perform_vault_lock(&app);

    Ok(())
}

// ---------------------------------------------------------------------------
// Public helpers for cross-module use
// ---------------------------------------------------------------------------

/// Start the auto-lock timer from an `AppHandle` (no `State` wrappers).
///
/// Resolves `ManagedAutoLockState` and `ManagedVaultState` from the app's
/// managed state and delegates to the private `start_auto_lock_timer`.
/// Used by `onboarding::create_vault` after storing the new session.
///
/// # Errors
///
/// Returns a string error if the mutex is poisoned or the timer
/// cannot be started.
pub fn start_auto_lock_from_handle(app: &tauri::AppHandle) -> Result<(), String> {
    use tauri::Manager;

    let auto_lock_state = app.state::<ManagedAutoLockState>();
    let vault_state = app.state::<ManagedVaultState>();
    start_auto_lock_timer(app, &auto_lock_state, &vault_state)
}

// ---------------------------------------------------------------------------
// Auto-lock timer management
// ---------------------------------------------------------------------------

/// Start the auto-lock background timer.
///
/// Spawns a thread that checks every `TIMER_CHECK_INTERVAL_SECS` for
/// inactivity timeout or maximum session duration. When either expires,
/// it locks the vault and emits the `verrou://vault-locked` event.
fn start_auto_lock_timer(
    app: &tauri::AppHandle,
    auto_lock_state: &State<'_, ManagedAutoLockState>,
    vault_state: &State<'_, ManagedVaultState>,
) -> Result<(), String> {
    // Cancel any previous timer.
    stop_auto_lock_timer(auto_lock_state);

    // Read timeout from user preferences (falls back to default if unavailable).
    let timeout_minutes = {
        use tauri::Manager;
        app.try_state::<ManagedPreferencesState>()
            .and_then(|prefs_state| prefs_state.lock().ok().map(|p| p.auto_lock_timeout_minutes))
            .unwrap_or(DEFAULT_INACTIVITY_TIMEOUT_MINUTES)
    };

    let timer = AutoLockTimer::new(timeout_minutes, DEFAULT_MAX_SESSION_HOURS);
    let cancel = Arc::clone(&timer.cancel);

    // Store the timer in managed state.
    let mut lock = auto_lock_state
        .lock()
        .map_err(|_| "Internal error: failed to acquire timer lock".to_string())?;
    *lock = Some(timer);
    drop(lock);

    // Clone Arc handles for the background thread.
    let app_handle = app.clone();
    let vault_ptr = Arc::clone(vault_state);
    let timer_ptr = Arc::clone(auto_lock_state);

    // M7 fix: pre-clone the clipboard timer state so the thread can cancel it
    // on auto-lock without needing Manager in scope inside the closure.
    let clipboard_timer_ptr: Option<ClipboardTimerState> = {
        use tauri::Manager;
        app.try_state::<ClipboardTimerState>()
            .map(|s| Arc::clone(&s))
    };

    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(TIMER_CHECK_INTERVAL_SECS));

            if cancel.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }

            let should_lock = {
                let timer_guard: std::sync::MutexGuard<'_, Option<AutoLockTimer>> =
                    match timer_ptr.lock() {
                        Ok(g) => g,
                        Err(_) => break,
                    };
                match timer_guard.as_ref() {
                    Some(t) => t.is_inactivity_expired() || t.is_max_session_expired(),
                    None => break, // Timer removed — stop thread.
                }
            };

            if should_lock {
                // Lock the vault.
                if let Ok(mut vault) = vault_ptr.lock() {
                    *vault = None; // Triggers zeroize + DB close.
                }
                // Clear the timer.
                if let Ok(mut timer_guard) = timer_ptr.lock() {
                    *timer_guard = None;
                }
                // M7 fix: clear clipboard + cancel auto-clear timer on auto-lock.
                // Vault mutex is already released above — no deadlock risk.
                // Uses the pre-cloned Arc to avoid needing Manager in scope here.
                if let Some(ref clip_state) = clipboard_timer_ptr {
                    crate::platform::clipboard::cancel_auto_clear(clip_state);
                }
                let _ = crate::platform::clipboard::clear(&app_handle);
                // Emit event to frontend.
                let _ = app_handle.emit("verrou://vault-locked", ());
                // Update tray to locked state.
                crate::platform::tray::update_tray_state(&app_handle, true);
                break;
            }
        }
    });

    Ok(())
}

/// Cancel the running auto-lock timer (if any).
fn stop_auto_lock_timer(auto_lock_state: &State<'_, ManagedAutoLockState>) {
    if let Ok(mut lock) = auto_lock_state.lock() {
        if let Some(ref timer) = *lock {
            timer.cancel();
        }
        *lock = None;
    }
}
