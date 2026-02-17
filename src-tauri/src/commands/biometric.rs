//! Biometric IPC commands — check availability, unlock, enroll, revoke.
//!
//! All commands return DTOs with `#[serde(rename_all = "camelCase")]`.
//! Error messages are user-friendly — no internal details leak.

use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tauri::State;
use zeroize::Zeroize;

use crate::platform::ManagedPlatformCapabilities;
use crate::state::{ManagedVaultState, VaultSession};

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

/// Biometric capability information returned to the frontend.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BiometricCapabilityResponse {
    /// Whether biometric hardware is available on this device.
    pub available: bool,
    /// Human-readable provider name (e.g., "Touch ID", "Windows Hello").
    pub provider_name: String,
    /// Whether biometric is enrolled for the current vault.
    pub enrolled: bool,
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// Check biometric availability and enrollment status.
///
/// Reads hardware availability from the session-level platform capabilities
/// cache (no re-detection). Enrollment status is queried live from the vault
/// header because it can change during a session.
///
/// # Errors
///
/// Returns a string error if the vault header cannot be read.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn check_biometric_availability(
    vault_dir: String,
    caps: State<'_, ManagedPlatformCapabilities>,
) -> Result<BiometricCapabilityResponse, String> {
    let available = caps.biometric_available;
    let provider_name = caps.biometric_provider_name.clone();

    let vault_path = PathBuf::from(&vault_dir);
    let enrolled = if vault_path.join("vault.verrou").exists() {
        verrou_vault::has_biometric_slot(&vault_path).unwrap_or(false)
    } else {
        false
    };

    Ok(BiometricCapabilityResponse {
        available,
        provider_name,
        enrolled,
    })
}

/// Unlock the vault with biometric authentication.
///
/// Triggers the native biometric prompt (Touch ID, Windows Hello),
/// retrieves the biometric secret from the OS keychain, derives the
/// wrapping key via HKDF, and unwraps the biometric slot.
///
/// On success, stores the `VaultSession` in managed state, starts
/// the auto-lock timer, and returns the unlock count.
///
/// # Errors
///
/// Returns a JSON-encoded error string for:
/// - Biometric cancelled by user
/// - Biometric authentication failed
/// - No biometric slot configured
/// - Rate limiting (shared counter)
/// - Internal errors
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn unlock_vault_biometric(
    vault_dir: String,
    app: tauri::AppHandle,
    vault_state: State<'_, ManagedVaultState>,
) -> Result<super::vault::UnlockVaultResponse, String> {
    let vault_arc = Arc::clone(vault_state.inner());

    let unlock_count = tauri::async_runtime::spawn_blocking(move || {
        let provider = crate::platform::biometric::create_biometric_provider();
        let vault_path = PathBuf::from(&vault_dir);

        // Step 1: Authenticate via biometric — triggers native prompt.
        let token = provider.authenticate(&vault_dir).map_err(|e| {
            use crate::platform::biometric::BiometricError;
            match e {
                BiometricError::UserCancelled => {
                    make_error("BIOMETRIC_CANCELLED", "Biometric verification cancelled.")
                }
                BiometricError::NotAvailable => make_error(
                    "BIOMETRIC_NOT_AVAILABLE",
                    "Biometric hardware not available.",
                ),
                BiometricError::NotEnrolled => make_error(
                    "BIOMETRIC_NOT_ENROLLED",
                    "Biometric is not enrolled for this vault.",
                ),
                BiometricError::AuthenticationFailed(_) => make_error(
                    "BIOMETRIC_FAILED",
                    "Biometric verification failed. You can unlock with your master password.",
                ),
                BiometricError::PlatformError(msg) => {
                    tracing::error!("biometric platform error: {msg}");
                    make_error(
                        "BIOMETRIC_FAILED",
                        "Biometric verification failed. You can unlock with your master password.",
                    )
                }
            }
        })?;

        // Step 2: Unlock vault with the biometric token.
        match verrou_vault::unlock_vault_with_biometric(token.expose(), &vault_path) {
            Ok(session) => {
                let unlock_count = session.unlock_count;

                let mut state = vault_arc
                    .lock()
                    .map_err(|_| "Internal error: failed to acquire vault lock".to_string())?;
                *state = Some(VaultSession {
                    db: session.db,
                    master_key: session.master_key,
                    unlock_count,
                    unlock_method: crate::state::UnlockMethod::Biometric,
                });
                drop(state);

                Ok(unlock_count)
            }
            Err(verrou_vault::VaultError::BiometricSlotNotFound) => Err(make_error(
                "BIOMETRIC_NOT_ENROLLED",
                "Biometric is not enrolled for this vault.",
            )),
            Err(verrou_vault::VaultError::BiometricUnlockFailed) => Err(make_error(
                "BIOMETRIC_FAILED",
                "Biometric verification failed. You can unlock with your master password.",
            )),
            Err(verrou_vault::VaultError::RateLimited { remaining_ms }) => {
                Err(make_rate_limited_error(remaining_ms))
            }
            Err(_) => Err(make_error(
                "INTERNAL_ERROR",
                "Failed to unlock vault. Please try again.",
            )),
        }
    })
    .await
    .map_err(|e| format!("Task failed: {e}"))??;

    // Start auto-lock timer and update tray (main thread).
    super::vault::start_auto_lock_from_handle(&app)?;
    crate::platform::tray::update_tray_state(&app, false);

    Ok(super::vault::UnlockVaultResponse { unlock_count })
}

/// Enroll biometric for the current vault.
///
/// Requires the master password for re-authentication. Generates a
/// random biometric enrollment token, stores it in the OS keychain
/// with biometric access control, and creates a biometric slot in
/// the vault header.
///
/// Re-authentication uses [`verrou_vault::verify_vault_password`] to
/// avoid side effects (no unlock count increment, no DB connection).
///
/// # Errors
///
/// Returns a string error if:
/// - Vault is locked
/// - Password is incorrect (re-auth)
/// - Biometric hardware not available
/// - Keychain storage fails
/// - Slot creation fails
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn enroll_biometric(
    password: String,
    vault_dir: String,
    vault_state: State<'_, ManagedVaultState>,
) -> Result<(), String> {
    // Extract master key from session.
    let mut master_key_copy = [0u8; 32];
    {
        let guard = vault_state
            .lock()
            .map_err(|_| "Internal error: failed to acquire vault lock".to_string())?;
        let session = guard.as_ref().ok_or("Vault is not unlocked.")?;
        master_key_copy.copy_from_slice(session.master_key.expose());
        drop(guard);
    }

    tauri::async_runtime::spawn_blocking(move || {
        let vault_path = PathBuf::from(&vault_dir);

        // Step 1: Re-authenticate with password (no side effects).
        let _verified_key = verrou_vault::verify_vault_password(password.as_bytes(), &vault_path)
            .map_err(|e| match e {
            verrou_vault::VaultError::InvalidPassword => {
                make_error("INVALID_PASSWORD", "Incorrect password. Please try again.")
            }
            verrou_vault::VaultError::RateLimited { remaining_ms } => {
                make_rate_limited_error(remaining_ms)
            }
            _ => make_error("INTERNAL_ERROR", "Failed to verify password."),
        })?;

        // Step 2: Generate biometric enrollment token.
        let (secret, _id) = verrou_crypto_core::biometric::generate_biometric_enrollment_token()
            .map_err(|e| format!("Failed to generate biometric token: {e}"))?;

        // Step 3: Store token in OS keychain with biometric access control.
        let provider = crate::platform::biometric::create_biometric_provider();
        if !provider.is_available() {
            master_key_copy.zeroize();
            return Err(make_error(
                "BIOMETRIC_NOT_AVAILABLE",
                "Biometric hardware is not available on this device.",
            ));
        }

        // Use vault_dir as vault_id for keychain.
        provider.enroll(&vault_dir, secret.expose()).map_err(|e| {
            master_key_copy.zeroize();
            format!("Failed to store biometric secret: {e}")
        })?;

        // Step 4: Add biometric slot to vault header.
        if let Err(e) =
            verrou_vault::add_biometric_slot(&vault_path, &master_key_copy, secret.expose())
        {
            // Rollback: remove keychain entry.
            let _ = provider.revoke(&vault_dir);
            master_key_copy.zeroize();
            return Err(format!("Failed to create biometric slot: {e}"));
        }

        // Step 5: Opportunistically set up hardware security (fire-and-forget).
        crate::commands::hardware_key::try_setup_hardware_security(&vault_dir, &master_key_copy);

        master_key_copy.zeroize();
        Ok(())
    })
    .await
    .map_err(|e| format!("Task failed: {e}"))?
}

/// Revoke biometric enrollment for the current vault.
///
/// Requires the master password for re-authentication. Removes the
/// biometric slot from the vault header and deletes the keychain entry.
///
/// Re-authentication uses [`verrou_vault::verify_vault_password`] to
/// avoid side effects (no unlock count increment, no DB connection).
///
/// # Errors
///
/// Returns a string error if:
/// - Vault is locked
/// - Password is incorrect (re-auth)
/// - No biometric slot exists
/// - Slot removal or keychain deletion fails
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn revoke_biometric(
    password: String,
    vault_dir: String,
    vault_state: State<'_, ManagedVaultState>,
) -> Result<(), String> {
    let mut master_key_copy = [0u8; 32];
    {
        let guard = vault_state
            .lock()
            .map_err(|_| "Internal error: failed to acquire vault lock".to_string())?;
        let session = guard.as_ref().ok_or("Vault is not unlocked.")?;
        master_key_copy.copy_from_slice(session.master_key.expose());
        drop(guard);
    }

    tauri::async_runtime::spawn_blocking(move || {
        let vault_path = PathBuf::from(&vault_dir);

        // Step 1: Re-authenticate with password (no side effects).
        let _verified_key = verrou_vault::verify_vault_password(password.as_bytes(), &vault_path)
            .map_err(|e| match e {
            verrou_vault::VaultError::InvalidPassword => {
                make_error("INVALID_PASSWORD", "Incorrect password. Please try again.")
            }
            verrou_vault::VaultError::RateLimited { remaining_ms } => {
                make_rate_limited_error(remaining_ms)
            }
            _ => make_error("INTERNAL_ERROR", "Failed to verify password."),
        })?;

        // Step 2: Remove biometric slot from vault header.
        verrou_vault::remove_biometric_slot(&vault_path, &master_key_copy).map_err(
            |e| match e {
                verrou_vault::VaultError::BiometricSlotNotFound => make_error(
                    "BIOMETRIC_NOT_ENROLLED",
                    "Biometric is not enrolled for this vault.",
                ),
                _ => format!("Failed to remove biometric slot: {e}"),
            },
        )?;

        // Step 3: Delete keychain entry.
        let provider = crate::platform::biometric::create_biometric_provider();
        let _ = provider.revoke(&vault_dir); // Best-effort — slot already removed.

        master_key_copy.zeroize();
        Ok(())
    })
    .await
    .map_err(|e| format!("Task failed: {e}"))?
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a JSON-encoded error string matching `UnlockErrorResponse`.
fn make_error(code: &str, message: &str) -> String {
    serde_json::to_string(&super::vault::UnlockErrorResponse {
        code: code.into(),
        message: message.into(),
        remaining_ms: None,
    })
    .unwrap_or_else(|_| message.to_string())
}

/// Build a JSON-encoded `RATE_LIMITED` error with the actual remaining milliseconds.
fn make_rate_limited_error(remaining_ms: u64) -> String {
    let secs = remaining_ms.saturating_add(999) / 1000;
    serde_json::to_string(&super::vault::UnlockErrorResponse {
        code: "RATE_LIMITED".into(),
        message: format!("Too many attempts. Try again in {secs} seconds."),
        remaining_ms: Some(remaining_ms),
    })
    .unwrap_or_else(|_| format!("Too many attempts. Try again in {secs} seconds."))
}
