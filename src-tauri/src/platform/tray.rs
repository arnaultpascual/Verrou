//! System tray / menu bar integration.
//!
//! - macOS: menu bar icon (top-right)
//! - Windows: notification area (bottom-right)
//! - Linux: `StatusNotifierItem` / libappindicator (context menu only; click events not emitted)
//!
//! The tray reflects vault lock state with two icon variants (shield outline = locked,
//! filled shield = unlocked) and swaps the context menu accordingly.

use tauri::{
    include_image,
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Manager, Runtime, WebviewUrl, WebviewWindowBuilder,
};
use tauri_plugin_positioner::{Position, WindowExt};

/// Unique identifier used for `app.tray_by_id()`.
const TRAY_ID: &str = "verrou-tray";

/// Window label for the quick-access popup.
pub const POPUP_LABEL: &str = "quick-access";

// Menu item IDs
const MENU_OPEN: &str = "open-verrou";
const MENU_LOCK: &str = "lock-vault";
const MENU_QUIT: &str = "quit";

// ── Tray creation ────────────────────────────────────────────────

/// Create and register the system tray icon.
///
/// Called once from `lib.rs` `.setup()`. Starts in the **locked** state
/// (shield outline icon, no "Lock Vault" menu item).
///
/// # Errors
///
/// Returns a Tauri error if menu items or tray icon fail to build.
pub fn create_tray<R: Runtime>(app: &tauri::AppHandle<R>) -> tauri::Result<()> {
    let locked_menu = build_locked_menu(app)?;

    TrayIconBuilder::with_id(TRAY_ID)
        .tooltip("VERROU \u{2014} Vault locked")
        .icon(include_image!("icons/tray-locked.png"))
        .icon_as_template(cfg!(target_os = "macos"))
        .menu(&locked_menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| {
            handle_menu_event(app, event.id.as_ref());
        })
        .on_tray_icon_event(|tray, event| {
            // Track tray icon position for positioner plugin
            tauri_plugin_positioner::on_tray_event(tray.app_handle(), &event);

            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                handle_tray_left_click(tray.app_handle());
            }
        })
        .build(app)?;

    Ok(())
}

// ── Menu builders ────────────────────────────────────────────────

/// Build the context menu for the **locked** state.
///
/// Items: Open VERROU, Quit
fn build_locked_menu<R: Runtime>(app: &tauri::AppHandle<R>) -> tauri::Result<Menu<R>> {
    let open_i = MenuItem::with_id(app, MENU_OPEN, "Open VERROU", true, None::<&str>)?;
    let sep = PredefinedMenuItem::separator(app)?;
    let quit_i = MenuItem::with_id(app, MENU_QUIT, "Quit", true, None::<&str>)?;
    Menu::with_items(app, &[&open_i, &sep, &quit_i])
}

/// Build the context menu for the **unlocked** state.
///
/// Items: Open VERROU, Lock Vault, Quit
fn build_unlocked_menu<R: Runtime>(app: &tauri::AppHandle<R>) -> tauri::Result<Menu<R>> {
    let open_i = MenuItem::with_id(app, MENU_OPEN, "Open VERROU", true, None::<&str>)?;
    let lock_i = MenuItem::with_id(app, MENU_LOCK, "Lock Vault", true, None::<&str>)?;
    let sep = PredefinedMenuItem::separator(app)?;
    let quit_i = MenuItem::with_id(app, MENU_QUIT, "Quit", true, None::<&str>)?;
    Menu::with_items(app, &[&open_i, &lock_i, &sep, &quit_i])
}

// ── Event handlers ───────────────────────────────────────────────

/// Handle context menu item clicks.
fn handle_menu_event<R: Runtime>(app: &tauri::AppHandle<R>, item_id: &str) {
    match item_id {
        MENU_OPEN => show_main_window(app),
        MENU_LOCK => lock_vault_from_tray(app),
        MENU_QUIT => app.exit(0),
        _ => {}
    }
}

/// Handle left-click on the tray icon.
///
/// Creates (first time) or toggles the quick-access popup window.
/// The popup is positioned near the tray icon via `tauri-plugin-positioner`.
pub fn handle_tray_left_click<R: Runtime>(app: &tauri::AppHandle<R>) {
    if let Some(popup) = app.get_webview_window(POPUP_LABEL) {
        // Toggle existing popup
        if popup.is_visible().unwrap_or_default() {
            let _ = popup.hide();
        } else {
            let _ = popup
                .as_ref()
                .window()
                .move_window(Position::TrayBottomCenter);
            let _ = popup.show();
            let _ = popup.set_focus();
        }
    } else {
        // Create popup on first tray click (lazy creation)
        match WebviewWindowBuilder::new(app, POPUP_LABEL, WebviewUrl::App("popup.html".into()))
            .decorations(false)
            .always_on_top(true)
            .skip_taskbar(true)
            .inner_size(400.0, 350.0)
            .resizable(false)
            .visible(false)
            .focused(true)
            .build()
        {
            Ok(popup) => {
                let _ = popup
                    .as_ref()
                    .window()
                    .move_window(Position::TrayBottomCenter);
                let _ = popup.show();
            }
            Err(e) => {
                tracing::warn!("Failed to create quick-access popup: {e}");
            }
        }
    }
}

// ── Window management ────────────────────────────────────────────

/// Show and focus the main application window.
fn show_main_window<R: Runtime>(app: &tauri::AppHandle<R>) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

// ── Vault state integration ──────────────────────────────────────

/// Lock the vault from the tray menu.
///
/// Delegates to [`crate::commands::vault::perform_vault_lock`] which
/// handles the full lock sequence (cancel timer, drop session, emit
/// event, update tray).
fn lock_vault_from_tray<R: Runtime>(app: &tauri::AppHandle<R>) {
    let _ = crate::commands::vault::perform_vault_lock(app);
}

/// Update the tray icon, menu, and tooltip to reflect vault lock state.
///
/// Called after vault lock/unlock operations to keep the tray in sync.
pub fn update_tray_state<R: Runtime>(app: &tauri::AppHandle<R>, is_locked: bool) {
    let Some(tray) = app.tray_by_id(TRAY_ID) else {
        return;
    };

    if is_locked {
        let _ = tray.set_tooltip(Some("VERROU \u{2014} Vault locked"));
        let _ = tray.set_icon(Some(include_image!("icons/tray-locked.png")));
        if let Ok(menu) = build_locked_menu(app) {
            let _ = tray.set_menu(Some(menu));
        }
    } else {
        let _ = tray.set_tooltip(Some("VERROU \u{2014} Vault unlocked"));
        let _ = tray.set_icon(Some(include_image!("icons/tray-unlocked.png")));
        if let Ok(menu) = build_unlocked_menu(app) {
            let _ = tray.set_menu(Some(menu));
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tray_id_is_stable() {
        assert_eq!(TRAY_ID, "verrou-tray");
    }

    #[test]
    fn popup_label_is_stable() {
        assert_eq!(POPUP_LABEL, "quick-access");
    }

    #[test]
    fn menu_item_ids_are_distinct() {
        let ids = [MENU_OPEN, MENU_LOCK, MENU_QUIT];
        for (i, a) in ids.iter().enumerate() {
            for (j, b) in ids.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "duplicate menu item ID");
                }
            }
        }
    }
}
