//! Clipboard IPC commands — concealed write with auto-clear timer.
//!
//! These commands delegate to `platform::clipboard` for platform-specific
//! concealment and manage the backend auto-clear timer so the frontend
//! doesn't need to track clipboard lifetimes.

use tauri::State;

use crate::platform::clipboard::ClipboardTimerState;
use crate::state::ManagedPreferencesState;

/// Write text to the clipboard with platform-specific concealment and
/// schedule an auto-clear timer using the configured preference timeout.
///
/// - macOS: `NSPasteboard` concealed type prevents clipboard history capture.
/// - Windows: `ExcludeClipboardContentFromMonitorProcessing` format set.
/// - Linux: Standard clipboard write (no concealment available).
///
/// The auto-clear timer runs in the Rust backend. If a previous timer
/// is active, it is cancelled before starting the new one.
///
/// # Errors
///
/// Returns a string error if the clipboard write fails or state is poisoned.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn clipboard_write_concealed(
    text: String,
    app: tauri::AppHandle,
    prefs_state: State<'_, ManagedPreferencesState>,
    timer_state: State<'_, ClipboardTimerState>,
) -> Result<(), String> {
    crate::platform::clipboard::write_concealed(&text, &app)?;

    // Read timeout from current preferences (not cached — changes take effect immediately)
    let timeout_ms = prefs_state
        .lock()
        .map(|p| p.clipboard_auto_clear_ms)
        .unwrap_or(30_000);

    crate::platform::clipboard::schedule_auto_clear(&timer_state, timeout_ms, app);

    Ok(())
}

/// Clear the clipboard and cancel any pending auto-clear timer.
///
/// # Errors
///
/// Returns a string error if the clipboard clear fails.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn clipboard_clear(
    app: tauri::AppHandle,
    timer_state: State<'_, ClipboardTimerState>,
) -> Result<(), String> {
    crate::platform::clipboard::cancel_auto_clear(&timer_state);
    crate::platform::clipboard::clear(&app)
}
