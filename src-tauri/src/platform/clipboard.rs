//! Platform-specific clipboard operations with concealment and auto-clear.
//!
//! - **macOS**: Uses `NSPasteboard` with `org.nspasteboard.ConcealedType` marker
//!   to prevent clipboard managers from recording OTP codes.
//! - **Windows**: Uses `ExcludeClipboardContentFromMonitorProcessing` format
//!   to exclude entries from Windows clipboard history.
//! - **Linux**: Falls back to `tauri-plugin-clipboard-manager` standard write
//!   (no concealment available).
//!
//! The auto-clear timer runs in the Rust backend via `tauri::async_runtime`
//! so it persists across frontend window lifecycle events.

use std::sync::{Arc, Mutex};

use tauri::AppHandle;

// ── Auto-clear timer state ───────────────────────────────────────────

/// Handle to a spawned auto-clear task. Wrapped in `Arc<Mutex<..>>` for
/// thread-safe access from IPC commands.
pub type ClipboardTimerState = Arc<Mutex<Option<tauri::async_runtime::JoinHandle<()>>>>;

/// Schedule an auto-clear of the clipboard after `timeout_ms` milliseconds.
///
/// Cancels any previously scheduled timer before starting a new one.
/// A timeout of `0` clears the clipboard immediately.
pub fn schedule_auto_clear(timer_state: &ClipboardTimerState, timeout_ms: u32, app: AppHandle) {
    cancel_auto_clear(timer_state);

    let handle = tauri::async_runtime::spawn(async move {
        if timeout_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(u64::from(timeout_ms))).await;
        }
        // Best-effort clear — ignore errors (clipboard may be locked by another app)
        let _ = clear(&app);
    });

    if let Ok(mut guard) = timer_state.lock() {
        *guard = Some(handle);
    }
}

/// Cancel the currently scheduled auto-clear timer, if any.
pub fn cancel_auto_clear(timer_state: &ClipboardTimerState) {
    if let Ok(mut guard) = timer_state.lock() {
        if let Some(handle) = guard.take() {
            handle.abort();
        }
    }
}

// ── Platform-specific clipboard write ────────────────────────────────

/// Write text to the system clipboard with platform-specific concealment.
///
/// On macOS, adds the `org.nspasteboard.ConcealedType` marker so clipboard
/// managers (Alfred, Paste, etc.) skip this entry. On Windows, sets the
/// `ExcludeClipboardContentFromMonitorProcessing` format to hide from
/// clipboard history (`Win+V`). On Linux, falls back to a standard write
/// via `tauri-plugin-clipboard-manager`.
///
/// # Errors
///
/// Returns an error string if the clipboard write fails.
pub fn write_concealed(text: &str, app: &AppHandle) -> Result<(), String> {
    platform_write_concealed(text, app)
}

/// Clear the clipboard.
///
/// # Errors
///
/// Returns an error string if the clipboard clear fails.
pub fn clear(app: &AppHandle) -> Result<(), String> {
    platform_clear(app)
}

// ── macOS implementation ─────────────────────────────────────────────

#[cfg(target_os = "macos")]
fn macos_write_concealed(text: &str) -> Result<(), String> {
    use objc2_app_kit::NSPasteboard;
    use objc2_foundation::{NSData, NSString};

    let pasteboard = NSPasteboard::generalPasteboard();
    pasteboard.clearContents();

    // Write the text as public.utf8-plain-text
    let ns_text = NSString::from_str(text);
    let text_type = NSString::from_str("public.utf8-plain-text");
    let ok = pasteboard.setString_forType(&ns_text, &text_type);
    if !ok {
        return Err("Failed to write text to NSPasteboard".to_string());
    }

    // Set the concealed type marker — an empty data blob signals "don't record this"
    let concealed_type = NSString::from_str("org.nspasteboard.ConcealedType");
    let empty_data = NSData::new();
    let _ = pasteboard.setData_forType(Some(&empty_data), &concealed_type);

    Ok(())
}

#[cfg(target_os = "macos")]
#[allow(clippy::unnecessary_wraps)]
fn macos_clear() -> Result<(), String> {
    use objc2_app_kit::NSPasteboard;
    use objc2_foundation::NSString;

    let pasteboard = NSPasteboard::generalPasteboard();
    pasteboard.clearContents();

    // Write empty string so paste operations get nothing
    let ns_empty = NSString::from_str("");
    let text_type = NSString::from_str("public.utf8-plain-text");
    let _ = pasteboard.setString_forType(&ns_empty, &text_type);

    Ok(())
}

#[cfg(target_os = "macos")]
fn platform_write_concealed(text: &str, _app: &AppHandle) -> Result<(), String> {
    macos_write_concealed(text)
}

#[cfg(target_os = "macos")]
fn platform_clear(_app: &AppHandle) -> Result<(), String> {
    macos_clear()
}

// ── Windows implementation ───────────────────────────────────────────

#[cfg(target_os = "windows")]
fn windows_write_concealed(text: &str) -> Result<(), String> {
    use clipboard_win::raw;

    // Register the exclusion format (before opening — no cleanup needed on failure)
    let cf_exclude = raw::register_format("ExcludeClipboardContentFromMonitorProcessing")
        .ok_or("Failed to register clipboard exclusion format")?;

    // Open clipboard — must call raw::close() on ALL paths after this point
    raw::open().map_err(|e| format!("Failed to open clipboard: {e}"))?;

    let result = (|| -> Result<(), String> {
        // Empty must be called after open, before writing
        let _ = raw::empty();

        // Write the text as Unicode (CF_UNICODETEXT = 13)
        let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
        let bytes: &[u8] =
            unsafe { std::slice::from_raw_parts(wide.as_ptr().cast::<u8>(), wide.len() * 2) };
        raw::set_without_clear(13, bytes)
            .map_err(|e| format!("Failed to write text to clipboard: {e}"))?;

        // Set the exclusion format (empty data) to prevent clipboard history capture
        raw::set_without_clear(cf_exclude.get(), &[0u8])
            .map_err(|e| format!("Failed to set clipboard exclusion: {e}"))?;

        Ok(())
    })();

    // Always close the clipboard, even on error
    raw::close();

    result
}

#[cfg(target_os = "windows")]
fn windows_clear() -> Result<(), String> {
    use clipboard_win::raw;

    raw::open().map_err(|e| format!("Failed to open clipboard: {e}"))?;
    let _ = raw::empty();
    raw::close();

    Ok(())
}

#[cfg(target_os = "windows")]
fn platform_write_concealed(text: &str, _app: &AppHandle) -> Result<(), String> {
    windows_write_concealed(text)
}

#[cfg(target_os = "windows")]
fn platform_clear(_app: &AppHandle) -> Result<(), String> {
    windows_clear()
}

// ── Linux fallback ───────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn platform_write_concealed(text: &str, app: &AppHandle) -> Result<(), String> {
    use tauri_plugin_clipboard_manager::ClipboardExt;

    // No concealment API available on Linux — standard clipboard write
    app.clipboard()
        .write_text(text)
        .map_err(|e| format!("Clipboard write failed: {e}"))
}

#[cfg(target_os = "linux")]
fn platform_clear(app: &AppHandle) -> Result<(), String> {
    use tauri_plugin_clipboard_manager::ClipboardExt;

    app.clipboard()
        .clear()
        .map_err(|e| format!("Clipboard clear failed: {e}"))
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timer_state_defaults_to_none() {
        let state: ClipboardTimerState = Arc::new(Mutex::new(None));
        assert!(state.lock().expect("lock").is_none());
    }

    #[test]
    fn cancel_on_empty_state_does_not_panic() {
        let state: ClipboardTimerState = Arc::new(Mutex::new(None));
        cancel_auto_clear(&state);
        assert!(state.lock().expect("lock").is_none());
    }

    #[test]
    fn cancel_clears_handle() {
        let state: ClipboardTimerState = Arc::new(Mutex::new(None));
        // Manually insert a dummy handle to test cancel
        let handle = tauri::async_runtime::spawn(async {
            tokio::time::sleep(std::time::Duration::from_secs(600)).await;
        });
        *state.lock().expect("lock") = Some(handle);
        assert!(state.lock().expect("lock").is_some());

        cancel_auto_clear(&state);
        assert!(state.lock().expect("lock").is_none());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_write_and_clear_succeed() {
        // Integration test — writes to the real system clipboard.
        let result = macos_write_concealed("test-verrou-clipboard");
        assert!(result.is_ok());
        let result = macos_clear();
        assert!(result.is_ok());
    }
}
