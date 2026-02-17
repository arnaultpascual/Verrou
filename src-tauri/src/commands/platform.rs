//! Platform IPC commands — capabilities, app info, and OS settings.
//!
//! All commands return DTOs with `#[serde(rename_all = "camelCase")]`.

use serde::{Deserialize, Serialize};
use tauri::State;

use crate::platform::ManagedPlatformCapabilities;

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

/// Application version and build metadata returned to the frontend.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppInfoDto {
    /// Semantic version from Cargo.toml (e.g., "0.1.0").
    pub version: String,
    /// Short git commit hash at build time (e.g., "abc1234").
    pub commit_hash: String,
    /// Build date in YYYY-MM-DD format.
    pub build_date: String,
    /// Source code repository URL.
    pub repository: String,
    /// SPDX license identifier.
    pub license: String,
}

/// Platform capabilities returned to the frontend.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlatformCapabilitiesDto {
    /// OS type string (e.g., "macos", "windows", "linux", "unknown").
    pub os_type: String,
    /// Whether biometric hardware is available on this device.
    pub biometric_available: bool,
    /// Human-readable biometric provider name (e.g., "Touch ID", "None").
    pub biometric_provider_name: String,
    /// Whether hardware security is available on this device.
    pub hardware_security_available: bool,
    /// Human-readable hardware security provider name (e.g., "Secure Enclave", "None").
    pub hardware_security_provider_name: String,
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// Return cached platform capabilities detected at startup.
///
/// This command reads from the session-level cache — no re-detection occurs.
/// The capabilities are immutable for the lifetime of the application.
#[must_use]
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn get_platform_capabilities(
    caps: State<'_, ManagedPlatformCapabilities>,
) -> PlatformCapabilitiesDto {
    PlatformCapabilitiesDto {
        os_type: caps.os_type.as_str().to_string(),
        biometric_available: caps.biometric_available,
        biometric_provider_name: caps.biometric_provider_name.clone(),
        hardware_security_available: caps.hardware_security_available,
        hardware_security_provider_name: caps.hardware_security_provider_name.clone(),
    }
}

/// Return application version and build metadata.
///
/// Version comes from `Cargo.toml`, commit hash and build date are
/// embedded at compile time by `build.rs`.
#[must_use]
#[tauri::command]
pub fn get_app_info() -> AppInfoDto {
    AppInfoDto {
        version: env!("CARGO_PKG_VERSION").to_string(),
        commit_hash: env!("VERROU_BUILD_HASH").to_string(),
        build_date: env!("VERROU_BUILD_DATE").to_string(),
        repository: option_env!("CARGO_PKG_REPOSITORY")
            .unwrap_or("https://github.com/cyanodroid/verrou")
            .to_string(),
        license: option_env!("CARGO_PKG_LICENSE")
            .unwrap_or("GPL-3.0-or-later")
            .to_string(),
    }
}

/// Open the OS network/privacy settings to let the user verify
/// zero-network permissions.
///
/// Uses platform-specific URIs:
/// - macOS: Privacy & Security settings pane
/// - Windows: Network status settings
/// - Linux: best-effort `gnome-control-center` or `xdg-open`
///
/// # Errors
///
/// Returns a string error if the OS settings could not be opened.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn open_os_network_settings(
    caps: State<'_, ManagedPlatformCapabilities>,
) -> Result<(), String> {
    match caps.os_type.as_str() {
        "macos" => open::that("x-apple.systempreferences:com.apple.preference.security?Privacy")
            .map_err(|e| format!("Failed to open OS settings: {e}")),
        "windows" => open::that("ms-settings:network-status")
            .map_err(|e| format!("Failed to open OS settings: {e}")),
        "linux" => {
            // open::that() passes its argument to xdg-open which expects a URI,
            // not a command+argument string. Use std::process::Command directly.
            std::process::Command::new("gnome-control-center")
                .arg("network")
                .spawn()
                .map(|_| ())
                .map_err(|e| format!("Failed to open network settings: {e}"))
        }
        _ => Err("Cannot open OS settings on this platform.".to_string()),
    }
}
