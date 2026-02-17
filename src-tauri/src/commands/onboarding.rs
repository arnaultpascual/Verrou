//! Onboarding IPC commands — vault detection, KDF calibration, vault creation,
//! and recovery key generation.
//!
//! These commands drive the 4-step onboarding wizard. After `create_vault`
//! succeeds the vault is immediately unlocked (session stored, auto-lock
//! started), so the user lands on the entries screen.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tauri::{Manager, State};
use zeroize::Zeroize;

use crate::state::{ManagedVaultState, VaultSession};

// ---------------------------------------------------------------------------
// DTOs — camelCase wrappers for crypto-core types that use snake_case
// ---------------------------------------------------------------------------

/// camelCase wrapper for `verrou_crypto_core::kdf::Argon2idParams`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Argon2idParamsDto {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl From<&verrou_crypto_core::kdf::Argon2idParams> for Argon2idParamsDto {
    fn from(p: &verrou_crypto_core::kdf::Argon2idParams) -> Self {
        Self {
            m_cost: p.m_cost,
            t_cost: p.t_cost,
            p_cost: p.p_cost,
        }
    }
}

/// Calibrated presets for the 3 KDF tiers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CalibratedPresetsDto {
    pub fast: Argon2idParamsDto,
    pub balanced: Argon2idParamsDto,
    pub maximum: Argon2idParamsDto,
}

/// Result of `check_vault_status`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultStatusDto {
    /// `"no-vault"` | `"locked"` | `"unlocked"`
    pub state: String,
    /// Resolved app data directory (vault files live here).
    pub vault_dir: String,
}

/// Result of `create_vault`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateVaultDto {
    pub vault_path: String,
    pub db_path: String,
    pub kdf_preset: String,
}

/// Result of `generate_recovery_key`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryKeyDto {
    pub formatted_key: String,
    pub vault_fingerprint: String,
    pub generation_date: String,
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// Detect whether a vault exists and its lock state.
///
/// Resolves the app data directory, checks for `vault.verrou`, and
/// cross-references with the in-memory session to determine state.
///
/// # Returns
///
/// - `"no-vault"` — first launch, show onboarding
/// - `"locked"` — vault file exists, session not active
/// - `"unlocked"` — vault file exists, session active
///
/// # Errors
///
/// Returns a string error if the app data directory cannot be resolved
/// or the vault state mutex is poisoned.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn check_vault_status(
    app: tauri::AppHandle,
    vault_state: State<'_, ManagedVaultState>,
) -> Result<VaultStatusDto, String> {
    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("Failed to resolve app data dir: {e}"))?;

    let vault_file = data_dir.join("vault.verrou");
    let has_vault = vault_file.exists();

    let is_unlocked = vault_state
        .lock()
        .map_err(|_| "Internal error: failed to acquire vault lock".to_string())?
        .is_some();

    let state = if !has_vault {
        "no-vault"
    } else if is_unlocked {
        "unlocked"
    } else {
        "locked"
    };

    Ok(VaultStatusDto {
        state: state.to_string(),
        vault_dir: data_dir.display().to_string(),
    })
}

/// Benchmark the host hardware and return calibrated KDF presets.
///
/// Wraps `verrou_vault::calibrate_for_vault()` which internally calls
/// `verrou_crypto_core::kdf::calibrate()`. Takes ~200-800ms depending
/// on hardware.
///
/// # Errors
///
/// Returns a string error if the KDF calibration fails (e.g. memory
/// allocation failure on constrained systems).
#[tauri::command]
pub async fn benchmark_kdf() -> Result<CalibratedPresetsDto, String> {
    tauri::async_runtime::spawn_blocking(|| {
        let calibrated = verrou_vault::calibrate_for_vault()
            .map_err(|e| format!("KDF calibration failed: {e}"))?;

        Ok(CalibratedPresetsDto {
            fast: Argon2idParamsDto::from(&calibrated.fast),
            balanced: Argon2idParamsDto::from(&calibrated.balanced),
            maximum: Argon2idParamsDto::from(&calibrated.maximum),
        })
    })
    .await
    .map_err(|e| format!("Task failed: {e}"))?
}

/// Create a new vault, then immediately unlock it.
///
/// 1. Calibrate KDF presets (hardware benchmark)
/// 2. Create vault files (`vault.verrou` + `vault.db`)
/// 3. Unlock the new vault to get a session
/// 4. Store session in managed state, start auto-lock timer
///
/// The double KDF (~3-6s) is acceptable because this runs behind the
/// `SecurityCeremony` animation during onboarding.
///
/// # Errors
///
/// Returns a string error if calibration, creation, or unlock fails.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn create_vault(
    mut password: String,
    preset: String,
    app: tauri::AppHandle,
    vault_state: State<'_, ManagedVaultState>,
) -> Result<CreateVaultDto, String> {
    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("Failed to resolve app data dir: {e}"))?;

    let vault_arc = Arc::clone(vault_state.inner());

    tauri::async_runtime::spawn_blocking(move || {
        // Ensure the data directory exists.
        if !data_dir.exists() {
            std::fs::create_dir_all(&data_dir)
                .map_err(|e| format!("Failed to create app data dir: {e}"))?;
        }

        // Parse KDF preset.
        let kdf_preset = match preset.as_str() {
            "fast" => verrou_crypto_core::kdf::KdfPreset::Fast,
            "maximum" => verrou_crypto_core::kdf::KdfPreset::Maximum,
            _ => verrou_crypto_core::kdf::KdfPreset::Balanced,
        };

        // Step 1: Calibrate.
        let calibrated = verrou_vault::calibrate_for_vault()
            .map_err(|e| format!("KDF calibration failed: {e}"))?;

        // Step 2: Create vault.
        let create_req = verrou_vault::CreateVaultRequest {
            password: password.as_bytes(),
            preset: kdf_preset,
            vault_dir: &data_dir,
            calibrated: &calibrated,
        };

        let create_result = verrou_vault::create_vault(&create_req)
            .map_err(|e| format!("Vault creation failed: {e}"))?;

        // Step 3: Unlock the new vault to get a session.
        let unlock_req = verrou_vault::UnlockVaultRequest {
            password: password.as_bytes(),
            vault_dir: &data_dir,
        };

        let session = verrou_vault::unlock_vault(&unlock_req)
            .map_err(|e| format!("Failed to unlock new vault: {e}"))?;

        // Zeroize password as early as possible.
        password.zeroize();

        // Step 4: Opportunistically set up hardware security (fire-and-forget).
        {
            let vault_dir_str = data_dir.display().to_string();
            crate::commands::hardware_key::try_setup_hardware_security(
                &vault_dir_str,
                session.master_key.expose(),
            );
        }

        // Step 5: Store session in managed state.
        {
            let mut state = vault_arc
                .lock()
                .map_err(|_| "Internal error: failed to acquire vault lock".to_string())?;
            *state = Some(VaultSession {
                db: session.db,
                master_key: session.master_key,
                unlock_count: session.unlock_count,
                unlock_method: crate::state::UnlockMethod::Password,
            });
        }

        // Build the response DTO.
        let preset_str = match kdf_preset {
            verrou_crypto_core::kdf::KdfPreset::Fast => "fast",
            verrou_crypto_core::kdf::KdfPreset::Balanced => "balanced",
            verrou_crypto_core::kdf::KdfPreset::Maximum => "maximum",
        };

        Ok((
            CreateVaultDto {
                vault_path: create_result.vault_path.display().to_string(),
                db_path: create_result.db_path.display().to_string(),
                kdf_preset: preset_str.to_string(),
            },
            app,
        ))
    })
    .await
    .map_err(|e| format!("Task failed: {e}"))?
    .map(|(dto, app)| {
        // These must run on the main thread (tray/timer access).
        let _ = super::vault::start_auto_lock_from_handle(&app);
        crate::platform::tray::update_tray_state(&app, false);
        dto
    })
}

/// Generate a recovery key for the currently unlocked vault.
///
/// Reads the master key from the stored session, calls
/// `verrou_vault::add_recovery_slot()`, and returns the formatted key.
///
/// # Errors
///
/// Returns a string error if the vault is locked or key generation fails.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn generate_recovery_key(
    vault_state: State<'_, ManagedVaultState>,
    app: tauri::AppHandle,
) -> Result<RecoveryKeyDto, String> {
    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("Failed to resolve app data dir: {e}"))?;

    // Copy master key bytes while holding the lock, then release.
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
        let req = verrou_vault::AddRecoverySlotRequest {
            vault_dir: &data_dir,
            master_key: &master_key_copy,
        };

        let result = verrou_vault::add_recovery_slot(&req)
            .map_err(|e| format!("Recovery key generation failed: {e}"))?;

        // Zeroize the master key copy.
        master_key_copy.zeroize();

        Ok(RecoveryKeyDto {
            formatted_key: result.formatted_key,
            vault_fingerprint: result.vault_fingerprint,
            generation_date: result.generation_date,
        })
    })
    .await
    .map_err(|e| format!("Task failed: {e}"))?
}
