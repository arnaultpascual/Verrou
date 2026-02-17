//! Preferences IPC commands — read, write, and update hotkey bindings.
//!
//! All commands return DTOs with `#[serde(rename_all = "camelCase")]`.

#![allow(clippy::significant_drop_tightening)]

use serde::{Deserialize, Serialize};
use tauri::{Manager, State};

use crate::state::{ManagedAutoLockState, ManagedPreferencesState};

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

/// Frontend-facing preferences DTO.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreferencesDto {
    pub theme: String,
    pub language: String,
    pub auto_lock_timeout_minutes: u32,
    pub hotkeys: HotkeyBindingsDto,
    pub clipboard_auto_clear_ms: u32,
    pub sidebar_collapsed: bool,
    pub launch_on_boot: bool,
    pub start_minimized: bool,
}

/// Frontend-facing hotkey bindings DTO.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HotkeyBindingsDto {
    pub quick_access: String,
    pub lock_vault: String,
}

// ── Conversions ────────────────────────────────────────────────────

impl From<verrou_vault::preferences::Preferences> for PreferencesDto {
    fn from(p: verrou_vault::preferences::Preferences) -> Self {
        Self {
            theme: p.theme,
            language: p.language,
            auto_lock_timeout_minutes: p.auto_lock_timeout_minutes,
            hotkeys: HotkeyBindingsDto {
                quick_access: p.hotkeys.quick_access,
                lock_vault: p.hotkeys.lock_vault,
            },
            clipboard_auto_clear_ms: p.clipboard_auto_clear_ms,
            sidebar_collapsed: p.sidebar_collapsed,
            launch_on_boot: p.launch_on_boot,
            start_minimized: p.start_minimized,
        }
    }
}

impl From<PreferencesDto> for verrou_vault::preferences::Preferences {
    fn from(dto: PreferencesDto) -> Self {
        Self {
            theme: dto.theme,
            language: dto.language,
            auto_lock_timeout_minutes: dto.auto_lock_timeout_minutes,
            hotkeys: verrou_vault::preferences::HotkeyBindings {
                quick_access: dto.hotkeys.quick_access,
                lock_vault: dto.hotkeys.lock_vault,
            },
            clipboard_auto_clear_ms: dto.clipboard_auto_clear_ms,
            sidebar_collapsed: dto.sidebar_collapsed,
            launch_on_boot: dto.launch_on_boot,
            start_minimized: dto.start_minimized,
        }
    }
}

impl From<verrou_vault::preferences::HotkeyBindings> for HotkeyBindingsDto {
    fn from(h: verrou_vault::preferences::HotkeyBindings) -> Self {
        Self {
            quick_access: h.quick_access,
            lock_vault: h.lock_vault,
        }
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// Get the current application preferences.
///
/// # Errors
///
/// Returns a string error if the preferences mutex is poisoned.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn get_preferences(
    prefs_state: State<'_, ManagedPreferencesState>,
) -> Result<PreferencesDto, String> {
    let prefs = prefs_state
        .lock()
        .map_err(|_| "Internal error: failed to acquire preferences lock".to_string())?;
    Ok(PreferencesDto::from(prefs.clone()))
}

/// Update application preferences and persist to disk.
///
/// When `autoLockTimeoutMinutes` changes and a timer is running,
/// the auto-lock timer is restarted with the new timeout.
///
/// When `launchOnBoot` changes, autostart registration is updated.
///
/// # Errors
///
/// Returns a string error if the preferences cannot be saved.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn set_preferences(
    prefs: PreferencesDto,
    app: tauri::AppHandle,
    prefs_state: State<'_, ManagedPreferencesState>,
    auto_lock_state: State<'_, ManagedAutoLockState>,
) -> Result<(), String> {
    let new_timeout = prefs.auto_lock_timeout_minutes;
    let new_prefs: verrou_vault::preferences::Preferences = prefs.into();

    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("Failed to resolve app data dir: {e}"))?;

    new_prefs
        .save(&data_dir)
        .map_err(|e| format!("Failed to save preferences: {e}"))?;

    // Read old timeout and update in-memory preferences (single lock scope).
    let old_timeout = {
        let mut state = prefs_state
            .lock()
            .map_err(|_| "Internal error: failed to acquire preferences lock".to_string())?;
        let old_timeout = state.auto_lock_timeout_minutes;
        *state = new_prefs;
        old_timeout
    };

    // Restart timer if timeout changed and a timer is active.
    if new_timeout != old_timeout {
        if let Ok(mut timer_guard) = auto_lock_state.lock() {
            if timer_guard.is_some() {
                // Cancel old timer and start new one with updated timeout.
                if let Some(ref timer) = *timer_guard {
                    timer.cancel();
                }
                *timer_guard = None;
                drop(timer_guard);

                // Re-start via the vault module's public helper.
                if let Err(e) = super::vault::start_auto_lock_from_handle(&app) {
                    eprintln!(
                        "Warning: failed to restart auto-lock timer after preferences change: {e}"
                    );
                }
            }
        }
    }

    Ok(())
}

/// Enable autostart — registers the app for OS login startup.
///
/// # Errors
///
/// Returns a string error if registration fails.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn enable_autostart(app: tauri::AppHandle) -> Result<(), String> {
    crate::platform::autostart::enable_autostart(&app)
}

/// Disable autostart — removes the app from OS login startup.
///
/// # Errors
///
/// Returns a string error if deregistration fails.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn disable_autostart(app: tauri::AppHandle) -> Result<(), String> {
    crate::platform::autostart::disable_autostart(&app)
}

/// Check if autostart is currently enabled at the OS level.
///
/// # Errors
///
/// Returns a string error if the status cannot be queried.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn get_autostart_status(app: tauri::AppHandle) -> Result<bool, String> {
    crate::platform::autostart::is_autostart_enabled(&app)
}

/// Update a single hotkey binding, re-register it, and persist.
///
/// On failure, the previous binding is preserved and an error is returned.
///
/// The mutex is held only during reads and writes — shortcut registration
/// (an OS syscall) happens outside the lock to avoid blocking concurrent
/// preferences access.
///
/// # Errors
///
/// Returns a string error if the shortcut string is invalid,
/// registration fails, or preferences cannot be saved.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn update_hotkey_binding(
    name: String,
    new_combo: String,
    app: tauri::AppHandle,
    prefs_state: State<'_, ManagedPreferencesState>,
) -> Result<HotkeyBindingsDto, String> {
    use tauri_plugin_global_shortcut::GlobalShortcutExt;

    // Validate the shortcut string parses correctly
    let new_shortcut: tauri_plugin_global_shortcut::Shortcut = new_combo
        .parse()
        .map_err(|e| format!("Invalid shortcut \"{new_combo}\": {e}"))?;

    // Phase 1: Read current state and validate (short lock)
    let old_combo = {
        let prefs = prefs_state
            .lock()
            .map_err(|_| "Internal error: failed to acquire preferences lock".to_string())?;

        let old = match name.as_str() {
            "quickAccess" => prefs.hotkeys.quick_access.clone(),
            "lockVault" => prefs.hotkeys.lock_vault.clone(),
            _ => return Err(format!("Unknown hotkey name: {name}")),
        };

        // Self-conflict check: make sure the new combo doesn't match the other binding
        let other_combo = match name.as_str() {
            "quickAccess" => &prefs.hotkeys.lock_vault,
            "lockVault" => &prefs.hotkeys.quick_access,
            _ => unreachable!(),
        };
        if new_combo == *other_combo {
            let other_name = if name == "quickAccess" {
                "Lock Vault"
            } else {
                "Quick Access"
            };
            return Err(format!("This shortcut is already assigned to {other_name}"));
        }

        old
    }; // lock released

    // Phase 2: Re-register shortcuts (no lock held — OS syscalls)
    if let Ok(old_shortcut) = old_combo.parse::<tauri_plugin_global_shortcut::Shortcut>() {
        let _ = app.global_shortcut().unregister(old_shortcut);
    }

    if let Err(e) = app.global_shortcut().register(new_shortcut) {
        // Re-register old binding on failure
        if let Ok(old_shortcut) = old_combo.parse::<tauri_plugin_global_shortcut::Shortcut>() {
            let _ = app.global_shortcut().register(old_shortcut);
        }
        return Err(format!(
            "Could not register shortcut {new_combo}. It may be in use by another application. ({e})"
        ));
    }

    // Phase 3: Persist updated state (short lock)
    let mut prefs = prefs_state
        .lock()
        .map_err(|_| "Internal error: failed to acquire preferences lock".to_string())?;

    match name.as_str() {
        "quickAccess" => prefs.hotkeys.quick_access = new_combo,
        "lockVault" => prefs.hotkeys.lock_vault = new_combo,
        _ => unreachable!(),
    }

    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("Failed to resolve app data dir: {e}"))?;

    prefs
        .save(&data_dir)
        .map_err(|e| format!("Failed to save preferences: {e}"))?;

    Ok(HotkeyBindingsDto::from(prefs.hotkeys.clone()))
}

/// Reset a hotkey binding to its default value and re-register.
///
/// Checks for conflicts with the other current binding before resetting.
///
/// # Errors
///
/// Returns a string error if the default conflicts with the other
/// binding, registration fails, or preferences cannot be saved.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn reset_hotkey_binding(
    name: String,
    app: tauri::AppHandle,
    prefs_state: State<'_, ManagedPreferencesState>,
) -> Result<HotkeyBindingsDto, String> {
    use tauri_plugin_global_shortcut::GlobalShortcutExt;

    let defaults = verrou_vault::preferences::HotkeyBindings::default();

    let default_combo = match name.as_str() {
        "quickAccess" => &defaults.quick_access,
        "lockVault" => &defaults.lock_vault,
        _ => return Err(format!("Unknown hotkey name: {name}")),
    };

    let new_shortcut: tauri_plugin_global_shortcut::Shortcut = default_combo
        .parse()
        .map_err(|e| format!("Invalid default shortcut: {e}"))?;

    // Phase 1: Read current state, check conflicts (short lock)
    let old_combo = {
        let prefs = prefs_state
            .lock()
            .map_err(|_| "Internal error: failed to acquire preferences lock".to_string())?;

        // Conflict check: default must not match the other current binding
        let other_combo = match name.as_str() {
            "quickAccess" => &prefs.hotkeys.lock_vault,
            "lockVault" => &prefs.hotkeys.quick_access,
            _ => unreachable!(),
        };
        if *default_combo == *other_combo {
            let other_name = if name == "quickAccess" {
                "Lock Vault"
            } else {
                "Quick Access"
            };
            return Err(format!(
                "Cannot reset: default shortcut conflicts with current {other_name} binding"
            ));
        }

        match name.as_str() {
            "quickAccess" => prefs.hotkeys.quick_access.clone(),
            "lockVault" => prefs.hotkeys.lock_vault.clone(),
            _ => unreachable!(),
        }
    }; // lock released

    // Phase 2: Re-register shortcuts (no lock held — OS syscalls)
    if let Ok(old_shortcut) = old_combo.parse::<tauri_plugin_global_shortcut::Shortcut>() {
        let _ = app.global_shortcut().unregister(old_shortcut);
    }

    if let Err(e) = app.global_shortcut().register(new_shortcut) {
        return Err(format!(
            "Could not register default shortcut {default_combo}. ({e})"
        ));
    }

    // Phase 3: Persist (short lock)
    let mut prefs = prefs_state
        .lock()
        .map_err(|_| "Internal error: failed to acquire preferences lock".to_string())?;

    match name.as_str() {
        "quickAccess" => prefs.hotkeys.quick_access.clone_from(default_combo),
        "lockVault" => prefs.hotkeys.lock_vault.clone_from(default_combo),
        _ => unreachable!(),
    }

    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("Failed to resolve app data dir: {e}"))?;

    prefs
        .save(&data_dir)
        .map_err(|e| format!("Failed to save preferences: {e}"))?;

    Ok(HotkeyBindingsDto::from(prefs.hotkeys.clone()))
}
