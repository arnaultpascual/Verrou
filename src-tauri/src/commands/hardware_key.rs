//! Hardware security IPC commands — check availability and status.
//!
//! All commands return DTOs with `#[serde(rename_all = "camelCase")]`.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tauri::State;

use crate::platform::ManagedPlatformCapabilities;

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

/// Hardware security status returned to the frontend.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HardwareSecurityStatus {
    /// Whether hardware security is available on this device.
    pub available: bool,
    /// Human-readable provider name (e.g., "Secure Enclave", "TPM 2.0").
    pub provider_name: String,
    /// Whether a hardware security slot exists for the current vault.
    pub enabled: bool,
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// Check hardware security availability and whether a hardware slot exists.
///
/// Reads hardware availability from the session-level platform capabilities
/// cache (no re-detection). Slot existence is queried live from the vault
/// header because it can change during a session.
///
/// # Errors
///
/// Returns a string error if the vault header cannot be read.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn check_hardware_security(
    vault_dir: String,
    caps: State<'_, ManagedPlatformCapabilities>,
) -> Result<HardwareSecurityStatus, String> {
    let available = caps.hardware_security_available;
    let provider_name = caps.hardware_security_provider_name.clone();

    let vault_path = PathBuf::from(&vault_dir);
    let enabled = if vault_path.join("vault.verrou").exists() {
        verrou_vault::has_hardware_security_slot(&vault_path).unwrap_or(false)
    } else {
        false
    };

    Ok(HardwareSecurityStatus {
        available,
        provider_name,
        enabled,
    })
}

// ---------------------------------------------------------------------------
// Internal helpers (used by other commands)
// ---------------------------------------------------------------------------

/// Opportunistically set up hardware security for a vault.
///
/// Called after vault creation or biometric enrollment. If hardware security
/// is available and no hardware slot exists, generates a token, stores it
/// in the hardware module, and creates a hardware security slot.
///
/// **This is fire-and-forget**: failures are logged but never block the caller.
pub fn try_setup_hardware_security(vault_dir: &str, master_key: &[u8]) {
    let provider = crate::platform::hardware_key::create_hardware_key_provider();
    if !provider.is_available() {
        tracing::debug!("Hardware security not available — skipping setup");
        return;
    }

    let vault_path = std::path::PathBuf::from(vault_dir);
    if verrou_vault::has_hardware_security_slot(&vault_path).unwrap_or(false) {
        tracing::debug!("Hardware security slot already exists — skipping");
        return;
    }

    // Generate a random hardware token.
    let token = verrou_crypto_core::hardware_key::generate_hardware_token();

    // Store token in hardware security module.
    if let Err(e) = provider.store_key(vault_dir, token.expose()) {
        tracing::warn!("Hardware security token storage failed: {e}");
        return;
    }

    // Add hardware security slot to vault.
    if let Err(e) =
        verrou_vault::add_hardware_security_slot(&vault_path, master_key, token.expose())
    {
        tracing::warn!("Hardware security slot creation failed: {e}");
        // Best-effort cleanup of stored token.
        let _ = provider.delete_key(vault_dir);
    } else {
        tracing::info!("Hardware security slot created successfully");
    }
}
