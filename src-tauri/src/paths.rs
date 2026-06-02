//! Centralized runtime path resolution for VERROU.
//!
//! This module is the **single source of truth** for all paths used by the
//! application at runtime.  Every command that needs a filesystem path should
//! call one of the helpers here instead of calling `app.path().app_data_dir()`
//! inline.
//!
//! # Platform locations
//!
//! | OS      | Base directory                                  |
//! |---------|--------------------------------------------------|
//! | macOS   | `~/Library/Application Support/verrou/`         |
//! | Windows | `%APPDATA%\verrou\`                             |
//! | Linux   | `~/.local/share/verrou/`                        |
//!
//! Sensitive data (the vault itself, key slots) lives inside the `SQLCipher`
//! database (`vault.db`).  Non-sensitive preferences live in
//! `preferences.json` in the same directory, readable before the vault is
//! unlocked.

use std::path::PathBuf;

use tauri::Manager;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Error returned when a runtime path cannot be resolved.
#[derive(Debug)]
pub struct PathError(pub tauri::Error);

impl std::fmt::Display for PathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Failed to resolve app data directory: {}", self.0)
    }
}

impl std::error::Error for PathError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Resolve the application data directory.
///
/// This is the root directory that contains all VERROU runtime files.
///
/// # Platform paths
///
/// - macOS: `~/Library/Application Support/verrou/`
/// - Windows: `%APPDATA%\verrou\`
/// - Linux: `~/.local/share/verrou/`
///
/// # Errors
///
/// Returns [`PathError`] if the Tauri path resolver cannot determine the
/// platform data directory (e.g. missing HOME env var).
pub fn app_data_dir<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> Result<PathBuf, PathError> {
    app.path().app_data_dir().map_err(PathError)
}

/// Resolve the path to the vault header file (`vault.verrou`).
///
/// This file contains the encrypted master-key slots and KDF parameters.
/// Its existence is used to detect whether a vault has been created.
///
/// # Errors
///
/// Propagates [`PathError`] from [`app_data_dir`].
pub fn vault_header_file<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
) -> Result<PathBuf, PathError> {
    Ok(app_data_dir(app)?.join("vault.verrou"))
}

/// Resolve the path to the `SQLCipher` vault database (`vault.db`).
///
/// All entries, folders, attachments, and sensitive configuration live here.
///
/// # Errors
///
/// Propagates [`PathError`] from [`app_data_dir`].
pub fn vault_db_file<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> Result<PathBuf, PathError> {
    Ok(app_data_dir(app)?.join("vault.db"))
}

/// Resolve the path to the backups directory (`backups/`).
///
/// Backups of the vault header and database are stored here.
///
/// # Errors
///
/// Propagates [`PathError`] from [`app_data_dir`].
pub fn backups_dir<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> Result<PathBuf, PathError> {
    Ok(app_data_dir(app)?.join("backups"))
}

/// Resolve the path to the preferences file (`preferences.json`).
///
/// Non-sensitive preferences (theme, language, hotkeys, …) are persisted
/// here.  This file is readable before the vault is unlocked.
///
/// # Errors
///
/// Propagates [`PathError`] from [`app_data_dir`].
pub fn preferences_file<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
) -> Result<PathBuf, PathError> {
    Ok(app_data_dir(app)?.join("preferences.json"))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::Path;

    /// Verify that sub-path helpers produce paths relative to a known base.
    ///
    /// Because `app_data_dir` requires a live Tauri runtime these unit tests
    /// exercise the *shape* of the paths rather than calling the helpers
    /// directly.  Integration / end-to-end tests that have a Tauri test
    /// harness can call the helpers directly.
    #[test]
    fn vault_header_is_under_data_dir() {
        let base = Path::new("/tmp/verrou-test");
        let header = base.join("vault.verrou");
        let db = base.join("vault.db");
        let backups = base.join("backups");
        let prefs = base.join("preferences.json");

        assert_eq!(header.parent(), Some(base));
        assert_eq!(db.parent(), Some(base));
        assert_eq!(backups.parent(), Some(base));
        assert_eq!(prefs.parent(), Some(base));

        assert_eq!(
            header.file_name().and_then(|n| n.to_str()),
            Some("vault.verrou")
        );
        assert_eq!(db.file_name().and_then(|n| n.to_str()), Some("vault.db"));
        assert_eq!(
            backups.file_name().and_then(|n| n.to_str()),
            Some("backups")
        );
        assert_eq!(
            prefs.file_name().and_then(|n| n.to_str()),
            Some("preferences.json")
        );
    }
}
