//! Non-sensitive user preferences — stored as plain JSON outside the vault.
//!
//! Readable before vault unlock so hotkeys, theme, and language can be
//! applied immediately on app start.  Sensitive preferences live inside
//! the `SQLCipher` database (not managed here).

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

// ── Top-level preferences ──────────────────────────────────────────

/// Non-sensitive application preferences.
///
/// Persisted to `{data_dir}/preferences.json` and loaded before vault
/// unlock.  All fields have sensible defaults via [`Default`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Preferences {
    /// UI theme: `"system"`, `"light"`, or `"dark"`.
    #[serde(default = "default_theme")]
    pub theme: String,

    /// ISO 639-1 language code (e.g. `"en"`, `"fr"`).
    #[serde(default = "default_language")]
    pub language: String,

    /// Minutes of inactivity before the vault auto-locks (1–60).
    #[serde(default = "default_auto_lock_timeout")]
    pub auto_lock_timeout_minutes: u32,

    /// Global keyboard shortcut bindings.
    #[serde(default)]
    pub hotkeys: HotkeyBindings,

    /// Milliseconds before the clipboard is auto-cleared after OTP copy.
    #[serde(default = "default_clipboard_auto_clear")]
    pub clipboard_auto_clear_ms: u32,

    /// Whether the sidebar starts collapsed.
    #[serde(default)]
    pub sidebar_collapsed: bool,

    /// Whether to launch the app on system boot.
    #[serde(default)]
    pub launch_on_boot: bool,

    /// Whether to start minimized to system tray.
    #[serde(default)]
    pub start_minimized: bool,
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            theme: default_theme(),
            language: default_language(),
            auto_lock_timeout_minutes: default_auto_lock_timeout(),
            hotkeys: HotkeyBindings::default(),
            clipboard_auto_clear_ms: default_clipboard_auto_clear(),
            sidebar_collapsed: false,
            launch_on_boot: false,
            start_minimized: false,
        }
    }
}

fn default_theme() -> String {
    "system".into()
}
fn default_language() -> String {
    "en".into()
}
const fn default_auto_lock_timeout() -> u32 {
    15
}
const fn default_clipboard_auto_clear() -> u32 {
    30_000
}

// ── Hotkey bindings ────────────────────────────────────────────────

/// Global keyboard shortcut bindings.
///
/// Stored in the cross-platform `CmdOrCtrl` format so bindings are
/// portable across macOS / Windows / Linux.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HotkeyBindings {
    /// Shortcut to summon the quick-access popup.
    #[serde(default = "default_quick_access")]
    pub quick_access: String,

    /// Shortcut to lock the vault immediately.
    #[serde(default = "default_lock_vault")]
    pub lock_vault: String,
}

impl Default for HotkeyBindings {
    fn default() -> Self {
        Self {
            quick_access: default_quick_access(),
            lock_vault: default_lock_vault(),
        }
    }
}

fn default_quick_access() -> String {
    "CmdOrCtrl+Shift+V".into()
}
fn default_lock_vault() -> String {
    "CmdOrCtrl+Shift+L".into()
}

// ── File I/O ───────────────────────────────────────────────────────

const PREFERENCES_FILE: &str = "preferences.json";

impl Preferences {
    /// Load preferences from `{data_dir}/preferences.json`.
    ///
    /// Returns [`Default::default()`] when the file is missing or
    /// contains invalid JSON (corrupt-file recovery).
    #[must_use]
    pub fn load(data_dir: &Path) -> Self {
        let path = data_dir.join(PREFERENCES_FILE);
        fs::read_to_string(&path).map_or_else(
            |_| Self::default(),
            |contents| serde_json::from_str(&contents).unwrap_or_default(),
        )
    }

    /// Persist preferences to `{data_dir}/preferences.json`.
    ///
    /// Uses an atomic write pattern (write to `.tmp`, then rename) to
    /// prevent corruption from partial writes or crashes.
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if the directory does not exist or the
    /// file system rejects the write/rename.
    pub fn save(&self, data_dir: &Path) -> std::io::Result<()> {
        let path = data_dir.join(PREFERENCES_FILE);
        let tmp = data_dir.join(".preferences.json.tmp");

        let json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        fs::write(&tmp, &json)?;

        // Restrict file permissions to owner-only on Unix (defense-in-depth)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
        }

        fs::rename(&tmp, &path)?;

        Ok(())
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn default_values_are_correct() {
        let prefs = Preferences::default();
        assert_eq!(prefs.theme, "system");
        assert_eq!(prefs.language, "en");
        assert_eq!(prefs.auto_lock_timeout_minutes, 15);
        assert_eq!(prefs.clipboard_auto_clear_ms, 30_000);
        assert!(!prefs.sidebar_collapsed);
    }

    #[test]
    fn default_hotkey_bindings_use_cmdorctrl_format() {
        let bindings = HotkeyBindings::default();
        assert_eq!(bindings.quick_access, "CmdOrCtrl+Shift+V");
        assert_eq!(bindings.lock_vault, "CmdOrCtrl+Shift+L");
    }

    #[test]
    fn load_returns_default_on_missing_file() {
        let dir = TempDir::new().unwrap();
        let prefs = Preferences::load(dir.path());
        assert_eq!(prefs, Preferences::default());
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = TempDir::new().unwrap();

        let prefs = Preferences {
            theme: "dark".into(),
            hotkeys: HotkeyBindings {
                quick_access: "CmdOrCtrl+Shift+X".into(),
                ..HotkeyBindings::default()
            },
            sidebar_collapsed: true,
            ..Preferences::default()
        };

        prefs.save(dir.path()).unwrap();
        let loaded = Preferences::load(dir.path());

        assert_eq!(loaded, prefs);
    }

    #[test]
    fn load_recovers_from_corrupt_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(PREFERENCES_FILE);
        fs::write(&path, "{ this is not valid json }}}").unwrap();

        let prefs = Preferences::load(dir.path());
        assert_eq!(prefs, Preferences::default());
    }

    #[test]
    fn load_handles_partial_json_with_defaults() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(PREFERENCES_FILE);
        // Only theme is set — all other fields should default
        fs::write(&path, r#"{"theme":"dark"}"#).unwrap();

        let prefs = Preferences::load(dir.path());
        assert_eq!(prefs.theme, "dark");
        assert_eq!(prefs.language, "en");
        assert_eq!(prefs.auto_lock_timeout_minutes, 15);
        assert_eq!(prefs.hotkeys, HotkeyBindings::default());
    }

    #[test]
    fn save_is_atomic_via_tmp_file() {
        let dir = TempDir::new().unwrap();
        let prefs = Preferences::default();
        prefs.save(dir.path()).unwrap();

        // The tmp file should NOT exist after a successful save
        let tmp = dir.path().join(".preferences.json.tmp");
        assert!(!tmp.exists());

        // The actual file SHOULD exist
        let path = dir.path().join(PREFERENCES_FILE);
        assert!(path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn save_sets_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let prefs = Preferences::default();
        prefs.save(dir.path()).unwrap();

        let path = dir.path().join(PREFERENCES_FILE);
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "preferences.json should be owner-only (0600)");
    }

    #[test]
    fn serde_uses_camel_case() {
        let prefs = Preferences::default();
        let json = serde_json::to_string(&prefs).unwrap();
        assert!(json.contains("autoLockTimeoutMinutes"));
        assert!(json.contains("clipboardAutoClearMs"));
        assert!(json.contains("sidebarCollapsed"));
        assert!(json.contains("quickAccess"));
        assert!(json.contains("lockVault"));
        // Must NOT contain snake_case
        assert!(!json.contains("auto_lock_timeout_minutes"));
        assert!(!json.contains("clipboard_auto_clear_ms"));
        assert!(!json.contains("quick_access"));
        assert!(!json.contains("lock_vault"));
    }
}
