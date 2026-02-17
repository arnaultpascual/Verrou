//! VERROU Tauri application — thin IPC shell.
//!
//! This crate is the entry point for the Tauri desktop app.
//! It registers plugins, defines IPC commands, and wires up
//! the frontend to `verrou-vault` and `verrou-crypto-core`.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::arithmetic_side_effects))]

pub mod commands;
pub mod platform;
pub mod state;

// TODO: Centralized runtime path resolution
// pub mod paths;

use std::sync::{Arc, Mutex};

use tauri::{include_image, Emitter, Manager};

use platform::clipboard::ClipboardTimerState;
use platform::ManagedPlatformCapabilities;
use state::{ManagedAutoLockState, ManagedPreferencesState, ManagedVaultState};

/// Run the Tauri application.
///
/// # Panics
///
/// Panics if the Tauri runtime fails to initialize (missing system
/// dependencies, invalid configuration, or resource allocation failure).
#[allow(clippy::too_many_lines)]
pub fn run() {
    let vault_state: ManagedVaultState = Arc::new(Mutex::new(None));
    let auto_lock_state: ManagedAutoLockState = Arc::new(Mutex::new(None));
    let clipboard_timer_state: ClipboardTimerState = Arc::new(Mutex::new(None));

    // Detect platform capabilities once at startup (session-level cache).
    let platform_caps: ManagedPlatformCapabilities =
        Arc::new(platform::detect_platform_capabilities());

    tauri::Builder::default()
        .manage(vault_state)
        .manage(auto_lock_state)
        .manage(clipboard_timer_state)
        .manage(platform_caps)
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_positioner::init())
        .setup(|app| {
            // ── Load preferences ──────────────────────────────────
            let data_dir = app.path().app_data_dir()?;
            if !data_dir.exists() {
                std::fs::create_dir_all(&data_dir)?;
            }
            let prefs = verrou_vault::preferences::Preferences::load(&data_dir);
            let hotkey_bindings = prefs.hotkeys.clone();
            let start_minimized = prefs.start_minimized;

            let prefs_state: ManagedPreferencesState = Arc::new(Mutex::new(prefs));
            app.manage(prefs_state);

            // ── Global shortcut plugin with handler ───────────────
            // The handler dispatches based on which shortcut fired.
            // Bindings are captured here; re-registration on update
            // is handled by the update_hotkey_binding IPC command.
            let prefs_for_handler: ManagedPreferencesState =
                Arc::clone(app.state::<ManagedPreferencesState>().inner());

            app.handle().plugin(
                tauri_plugin_global_shortcut::Builder::new()
                    .with_handler(move |app_handle, shortcut, event| {
                        if event.state == tauri_plugin_global_shortcut::ShortcutState::Pressed {
                            // Read current bindings to handle re-configured shortcuts
                            let bindings = prefs_for_handler
                                .lock()
                                .map(|p| p.hotkeys.clone())
                                .unwrap_or_default();

                            if platform::hotkeys::shortcut_matches(shortcut, &bindings.quick_access)
                            {
                                platform::tray::handle_tray_left_click(app_handle);
                            } else if platform::hotkeys::shortcut_matches(
                                shortcut,
                                &bindings.lock_vault,
                            ) {
                                let _ = commands::vault::perform_vault_lock(app_handle);
                            }
                        }
                    })
                    .build(),
            )?;

            // ── Register hotkeys ──────────────────────────────────
            let results = platform::hotkeys::register_hotkeys(app.handle(), &hotkey_bindings);

            for result in &results {
                if !result.success {
                    tracing::warn!(
                        "Hotkey registration failed: {} ({}) — {}",
                        result.name,
                        result.shortcut,
                        result.error.as_deref().unwrap_or("unknown error"),
                    );

                    // Emit failure event so frontend can show notification
                    let _ = app
                        .handle()
                        .emit("verrou://hotkey-registration-failed", result);
                }
            }

            // ── Window icon (visible in Dock during dev) ─────────
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.set_icon(include_image!("icons/128x128.png"));

                // ── Start minimized to tray ──────────────────────
                if start_minimized {
                    let _ = window.hide();
                }
            }

            // ── System tray ──────────────────────────────────────
            platform::tray::create_tray(app.handle())?;

            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if window.label() == "main" {
                    // Close-to-tray: hide the main window instead of quitting.
                    // "Quit" from the tray menu calls app.exit(0) which bypasses this.
                    api.prevent_close();
                    let _ = window.hide();
                }
                // Popup windows (e.g. quick-access): allow normal close.
                // They are lazily recreated on next tray click.
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::onboarding::check_vault_status,
            commands::onboarding::benchmark_kdf,
            commands::onboarding::create_vault,
            commands::onboarding::generate_recovery_key,
            commands::vault::unlock_vault,
            commands::vault::lock_vault,
            commands::vault::is_vault_unlocked,
            commands::vault::heartbeat,
            commands::vault::recover_vault,
            commands::vault::change_password_after_recovery,
            commands::vault::change_master_password,
            commands::vault::check_vault_integrity,
            commands::vault::list_vault_backups,
            commands::vault::restore_vault_backup,
            commands::vault::delete_vault,
            commands::entries::list_entries,
            commands::entries::add_entry,
            commands::entries::get_entry,
            commands::entries::update_entry,
            commands::entries::delete_entry,
            commands::entries::delete_entry_with_auth,
            commands::entries::reveal_seed_phrase,
            commands::entries::reveal_recovery_codes,
            commands::entries::get_recovery_stats,
            commands::entries::get_all_recovery_stats,
            commands::entries::toggle_recovery_code_used,
            commands::entries::update_recovery_codes,
            commands::entries::get_linked_recovery_count,
            commands::entries::reveal_password,
            commands::entries::search_note_content,
            commands::entries::get_password_health,
            commands::preferences::get_preferences,
            commands::preferences::set_preferences,
            commands::preferences::update_hotkey_binding,
            commands::preferences::reset_hotkey_binding,
            commands::preferences::enable_autostart,
            commands::preferences::disable_autostart,
            commands::preferences::get_autostart_status,
            commands::clipboard::clipboard_write_concealed,
            commands::clipboard::clipboard_clear,
            commands::import::validate_google_auth_import,
            commands::import::confirm_google_auth_import,
            commands::import::validate_aegis_import,
            commands::import::confirm_aegis_import,
            commands::import::validate_twofas_import,
            commands::import::confirm_twofas_import,
            commands::import::validate_verrou_import,
            commands::import::confirm_verrou_import,
            commands::bip39::bip39_validate_word,
            commands::bip39::bip39_suggest_words,
            commands::bip39::bip39_validate_phrase,
            commands::folders::create_folder,
            commands::folders::list_folders,
            commands::folders::rename_folder,
            commands::folders::delete_folder,
            commands::password_generator::generate_password,
            commands::attachments::add_attachment,
            commands::attachments::list_attachments,
            commands::attachments::export_attachment,
            commands::attachments::delete_attachment,
            commands::export::export_vault,
            commands::paper_backup::generate_paper_backup_data,
            commands::qr_transfer::prepare_qr_transfer,
            commands::qr_transfer::receive_qr_transfer,
            commands::qr_transfer::set_screen_capture_protection,
            commands::qr_transfer::save_transfer_file,
            commands::qr_transfer::load_transfer_file,
            commands::biometric::check_biometric_availability,
            commands::biometric::unlock_vault_biometric,
            commands::biometric::enroll_biometric,
            commands::biometric::revoke_biometric,
            commands::hardware_key::check_hardware_security,
            commands::platform::get_platform_capabilities,
            commands::platform::get_app_info,
            commands::platform::open_os_network_settings,
        ])
        .build(tauri::generate_context!())
        .expect("error building VERROU")
        .run(|_app, event| {
            // Keep the app alive when all windows are closed (tray stays active).
            if let tauri::RunEvent::ExitRequested { api, .. } = event {
                api.prevent_exit();
            }
        });
}
