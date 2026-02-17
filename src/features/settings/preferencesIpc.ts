/**
 * IPC service for preferences commands.
 * Uses Tauri invoke() in desktop mode, mock fallback in browser.
 */

// ---------------------------------------------------------------------------
// Tauri detection
// ---------------------------------------------------------------------------

const IS_TAURI =
  typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

// ---------------------------------------------------------------------------
// DTOs — mirror Rust camelCase DTOs exactly
// ---------------------------------------------------------------------------

export interface HotkeyBindingsDto {
  quickAccess: string;
  lockVault: string;
}

export interface PreferencesDto {
  theme: string;
  language: string;
  autoLockTimeoutMinutes: number;
  hotkeys: HotkeyBindingsDto;
  clipboardAutoClearMs: number;
  sidebarCollapsed: boolean;
  launchOnBoot: boolean;
  startMinimized: boolean;
}

// ---------------------------------------------------------------------------
// Mock state (browser dev mode)
// ---------------------------------------------------------------------------

const DEFAULTS: PreferencesDto = {
  theme: "system",
  language: "en",
  autoLockTimeoutMinutes: 15,
  hotkeys: {
    quickAccess: "CmdOrCtrl+Shift+V",
    lockVault: "CmdOrCtrl+Shift+L",
  },
  clipboardAutoClearMs: 30_000,
  sidebarCollapsed: false,
  launchOnBoot: false,
  startMinimized: false,
};

let mockPrefs: PreferencesDto = { ...DEFAULTS, hotkeys: { ...DEFAULTS.hotkeys } };

// ---------------------------------------------------------------------------
// IPC functions
// ---------------------------------------------------------------------------

/** Get current preferences. */
export async function getPreferences(): Promise<PreferencesDto> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<PreferencesDto>("get_preferences");
  }
  return { ...mockPrefs, hotkeys: { ...mockPrefs.hotkeys } };
}

/** Update all preferences. */
export async function setPreferences(prefs: PreferencesDto): Promise<void> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    await invoke("set_preferences", { prefs });
    return;
  }
  mockPrefs = { ...prefs, hotkeys: { ...prefs.hotkeys } };
}

/**
 * Update a single hotkey binding.
 *
 * Validates the combo string format and checks for self-conflicts.
 * Returns the updated hotkey bindings on success.
 */
export async function updateHotkeyBinding(
  name: string,
  newCombo: string,
): Promise<HotkeyBindingsDto> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<HotkeyBindingsDto>("update_hotkey_binding", { name, newCombo });
  }

  // Mock validation
  if (!newCombo.includes("+")) {
    throw `Invalid shortcut "${newCombo}": must include at least one modifier and a key`;
  }

  const otherName = name === "quickAccess" ? "lockVault" : "quickAccess";
  const otherCombo = mockPrefs.hotkeys[otherName as keyof HotkeyBindingsDto];
  if (newCombo === otherCombo) {
    const label = name === "quickAccess" ? "Lock Vault" : "Quick Access";
    throw `This shortcut is already assigned to ${label}`;
  }

  if (name === "quickAccess") {
    mockPrefs.hotkeys.quickAccess = newCombo;
  } else if (name === "lockVault") {
    mockPrefs.hotkeys.lockVault = newCombo;
  } else {
    throw `Unknown hotkey name: ${name}`;
  }

  return { ...mockPrefs.hotkeys };
}

/**
 * Reset a hotkey binding to its default value.
 *
 * Returns the updated hotkey bindings.
 */
export async function resetHotkeyBinding(
  name: string,
): Promise<HotkeyBindingsDto> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<HotkeyBindingsDto>("reset_hotkey_binding", { name });
  }

  if (name === "quickAccess") {
    mockPrefs.hotkeys.quickAccess = DEFAULTS.hotkeys.quickAccess;
  } else if (name === "lockVault") {
    mockPrefs.hotkeys.lockVault = DEFAULTS.hotkeys.lockVault;
  } else {
    throw `Unknown hotkey name: ${name}`;
  }

  return { ...mockPrefs.hotkeys };
}

/**
 * Enable autostart — registers the app for OS login startup.
 *
 * Throws on failure (insufficient permissions, OS restriction).
 */
export async function enableAutostart(): Promise<void> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    await invoke("enable_autostart");
    return;
  }
  // Mock: no-op
}

/**
 * Disable autostart — removes the app from OS login startup.
 *
 * Throws on failure.
 */
export async function disableAutostart(): Promise<void> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    await invoke("disable_autostart");
    return;
  }
  // Mock: no-op
}

/**
 * Check if autostart is currently enabled at the OS level.
 *
 * Returns `false` in browser dev mode.
 */
export async function getAutostartStatus(): Promise<boolean> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<boolean>("get_autostart_status");
  }
  return false;
}

/** Default hotkey bindings (for display/comparison). */
export const DEFAULT_HOTKEYS: HotkeyBindingsDto = {
  quickAccess: DEFAULTS.hotkeys.quickAccess,
  lockVault: DEFAULTS.hotkeys.lockVault,
};

/** Reset mock state to defaults (test hygiene). */
export function resetMockPreferences(): void {
  mockPrefs = { ...DEFAULTS, hotkeys: { ...DEFAULTS.hotkeys } };
}

// ---------------------------------------------------------------------------
// App info & OS settings IPC
// ---------------------------------------------------------------------------

export interface AppInfoDto {
  version: string;
  commitHash: string;
  buildDate: string;
  repository: string;
  license: string;
}

/** Get application version and build metadata. */
export async function getAppInfo(): Promise<AppInfoDto> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<AppInfoDto>("get_app_info");
  }
  return {
    version: "0.1.0",
    commitHash: "dev",
    buildDate: "dev",
    repository: "https://github.com/cyanodroid/verrou",
    license: "GPL-3.0-or-later",
  };
}

/** Open the OS network/privacy settings for offline verification. */
export async function openOsNetworkSettings(): Promise<void> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    await invoke("open_os_network_settings");
    return;
  }
  // Mock: no-op in browser dev mode
}
