//! Platform autostart registration via `tauri-plugin-autostart`.
//!
//! Wraps the Tauri autostart plugin to provide enable/disable/query
//! functionality for OS login startup registration.
//!
//! Platform behavior:
//! - macOS: `LaunchAgent` plist in `~/Library/LaunchAgents/`
//! - Windows: Registry entry at `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
//! - Linux: `.desktop` file in `~/.config/autostart/`

use tauri::Runtime;
use tauri_plugin_autostart::ManagerExt;

/// Enable autostart — registers the app with the OS login startup mechanism.
///
/// # Errors
///
/// Returns a string error if registration fails (insufficient permissions,
/// OS restriction, or unsupported platform).
pub fn enable_autostart<R: Runtime>(app: &tauri::AppHandle<R>) -> Result<(), String> {
    let manager = app.autolaunch();
    manager
        .enable()
        .map_err(|e| format!("Failed to enable autostart: {e}"))
}

/// Disable autostart — removes the app from OS login startup.
///
/// # Errors
///
/// Returns a string error if deregistration fails.
pub fn disable_autostart<R: Runtime>(app: &tauri::AppHandle<R>) -> Result<(), String> {
    let manager = app.autolaunch();
    manager
        .disable()
        .map_err(|e| format!("Failed to disable autostart: {e}"))
}

/// Check if autostart is currently enabled at the OS level.
///
/// # Errors
///
/// Returns a string error if the status cannot be queried.
pub fn is_autostart_enabled<R: Runtime>(app: &tauri::AppHandle<R>) -> Result<bool, String> {
    let manager = app.autolaunch();
    manager
        .is_enabled()
        .map_err(|e| format!("Failed to check autostart status: {e}"))
}

#[cfg(test)]
mod tests {
    // Autostart functions require a running Tauri AppHandle with the
    // autostart plugin initialized, which is only available in integration
    // tests.  The module's correctness is validated via:
    //  1. Frontend tests (mock IPC, verify toggle behavior)
    //  2. Manual platform tests (macOS/Windows/Linux boot sequence)
}
