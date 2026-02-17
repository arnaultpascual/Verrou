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
/// Copies the backup `.verrou` and `.db` files over the current vault.
///
/// # Errors
///
/// Returns a string error if the backup file doesn't exist or restoration fails.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn restore_vault_backup(vault_dir: String, backup_path: String) -> Result<(), String> {
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

    verrou_vault::restore_backup(&vault_path, &backup)
        .map_err(|e| format!("Failed to restore backup: {e}"))
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
