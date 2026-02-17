//! Global hotkey registration and event handling.
//!
//! Registers keyboard shortcuts via `tauri-plugin-global-shortcut` and
//! dispatches actions (show popup, lock vault) when they fire.
//!
//! Platform notes:
//! - macOS: No Accessibility permission needed for global shortcuts.
//! - Windows: Fully supported, no quirks.
//! - Linux (X11): Works via `XGrabKey`.
//! - Linux (Wayland): NOT supported — requires `XWayland` fallback.

use serde::Serialize;
use tauri_plugin_global_shortcut::Shortcut;

use verrou_vault::preferences::HotkeyBindings;

/// Outcome of a single shortcut registration attempt.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HotkeyRegistrationResult {
    /// Human-readable binding name (e.g. `"quickAccess"`).
    pub name: String,
    /// The shortcut string that was registered (e.g. `"CmdOrCtrl+Shift+V"`).
    pub shortcut: String,
    /// Whether registration succeeded.
    pub success: bool,
    /// Error message on failure, `None` on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Register both default hotkeys.
///
/// Returns a result for each binding. Failures are logged but do not
/// prevent other bindings from being registered.
pub fn register_hotkeys<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    bindings: &HotkeyBindings,
) -> Vec<HotkeyRegistrationResult> {
    vec![
        register_single(app, "quickAccess", &bindings.quick_access),
        register_single(app, "lockVault", &bindings.lock_vault),
    ]
}

/// Unregister all global shortcuts.
pub fn unregister_hotkeys<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    use tauri_plugin_global_shortcut::GlobalShortcutExt;

    if let Err(e) = app.global_shortcut().unregister_all() {
        tracing::warn!("Failed to unregister global shortcuts: {e}");
    }
}

/// Register a single shortcut string.
fn register_single<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    name: &str,
    combo: &str,
) -> HotkeyRegistrationResult {
    use tauri_plugin_global_shortcut::GlobalShortcutExt;

    let shortcut: Shortcut = match combo.parse() {
        Ok(s) => s,
        Err(e) => {
            return HotkeyRegistrationResult {
                name: name.to_string(),
                shortcut: combo.to_string(),
                success: false,
                error: Some(format!("Invalid shortcut syntax: {e}")),
            };
        }
    };

    match app.global_shortcut().register(shortcut) {
        Ok(()) => HotkeyRegistrationResult {
            name: name.to_string(),
            shortcut: combo.to_string(),
            success: true,
            error: None,
        },
        Err(e) => HotkeyRegistrationResult {
            name: name.to_string(),
            shortcut: combo.to_string(),
            success: false,
            error: Some(format!("{e}")),
        },
    }
}

/// Parse a shortcut string and compare it against a stored `Shortcut`.
///
/// Returns `true` if the given shortcut matches the stored combo string.
#[must_use]
pub fn shortcut_matches(shortcut: &Shortcut, combo_str: &str) -> bool {
    combo_str
        .parse::<Shortcut>()
        .map(|parsed| *shortcut == parsed)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_result_fields() {
        let result = HotkeyRegistrationResult {
            name: "quickAccess".into(),
            shortcut: "CmdOrCtrl+Shift+V".into(),
            success: true,
            error: None,
        };
        assert!(result.success);
        assert!(result.error.is_none());
        assert_eq!(result.name, "quickAccess");
    }

    #[test]
    fn registration_result_with_error() {
        let result = HotkeyRegistrationResult {
            name: "lockVault".into(),
            shortcut: "BadShortcut".into(),
            success: false,
            error: Some("parse error".into()),
        };
        assert!(!result.success);
        assert!(result.error.is_some());
    }

    #[test]
    fn default_binding_strings_parse_as_shortcuts() {
        let bindings = HotkeyBindings::default();
        assert!(
            bindings.quick_access.parse::<Shortcut>().is_ok(),
            "default quick_access should parse"
        );
        assert!(
            bindings.lock_vault.parse::<Shortcut>().is_ok(),
            "default lock_vault should parse"
        );
    }

    #[test]
    fn shortcut_matches_works() {
        let shortcut: Shortcut = "CmdOrCtrl+Shift+V".parse().expect("valid shortcut");
        assert!(shortcut_matches(&shortcut, "CmdOrCtrl+Shift+V"));
        assert!(!shortcut_matches(&shortcut, "CmdOrCtrl+Shift+L"));
    }

    #[test]
    fn shortcut_matches_handles_invalid_string() {
        let shortcut: Shortcut = "CmdOrCtrl+Shift+V".parse().expect("valid shortcut");
        assert!(!shortcut_matches(&shortcut, "not-a-shortcut"));
    }

    #[test]
    fn serde_serialization() {
        let result = HotkeyRegistrationResult {
            name: "quickAccess".into(),
            shortcut: "CmdOrCtrl+Shift+V".into(),
            success: true,
            error: None,
        };
        let json = serde_json::to_string(&result).expect("serialize result");
        assert!(json.contains("\"name\""));
        assert!(json.contains("\"shortcut\""));
        assert!(json.contains("\"success\""));
        // error should be skipped when None
        assert!(!json.contains("\"error\""));
    }
}
