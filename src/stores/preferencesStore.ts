/**
 * Global preferences store — loaded at app startup, before vault unlock.
 *
 * Theme is applied immediately on load to prevent flash.
 * Components read preferences reactively via derived accessors.
 * Updates are persisted to disk via IPC + localStorage cache.
 */

import { createSignal } from "solid-js";
import type { PreferencesDto } from "../features/settings/preferencesIpc";
import { getPreferences, setPreferences } from "../features/settings/preferencesIpc";

// ---------------------------------------------------------------------------
// Signals
// ---------------------------------------------------------------------------

const [preferences, setPreferencesSignal] = createSignal<PreferencesDto | null>(null);

let initCalled = false;

// ---------------------------------------------------------------------------
// Theme application
// ---------------------------------------------------------------------------

/** MediaQueryList for system color-scheme changes. */
let systemThemeQuery: MediaQueryList | null = null;
let systemThemeHandler: ((e: MediaQueryListEvent) => void) | null = null;

/**
 * Apply the given theme to the document root element.
 *
 * - `"light"` → sets `data-theme="light"`
 * - `"dark"` → sets `data-theme="dark"`
 * - `"system"` → removes `data-theme`, lets CSS `prefers-color-scheme` rule decide
 */
export function applyTheme(theme: string): void {
  if (typeof document === "undefined") return;

  // Clean up previous system listener
  if (systemThemeHandler && systemThemeQuery) {
    systemThemeQuery.removeEventListener("change", systemThemeHandler);
    systemThemeHandler = null;
  }

  if (theme === "system") {
    delete document.documentElement.dataset.theme;
    // Listen for OS changes
    systemThemeQuery = window.matchMedia("(prefers-color-scheme: dark)");
    systemThemeHandler = () => {
      // No-op: CSS handles it via :root:not([data-theme]) media query.
      // We just need to ensure no data-theme attribute is set.
      delete document.documentElement.dataset.theme;
    };
    systemThemeQuery.addEventListener("change", systemThemeHandler);
  } else {
    document.documentElement.dataset.theme = theme;
  }

  // Cache in localStorage for flash prevention
  try {
    localStorage.setItem("verrou-theme", theme);
  } catch {
    // localStorage may be unavailable (private browsing, etc.)
  }
}

// ---------------------------------------------------------------------------
// Derived accessors
// ---------------------------------------------------------------------------

/** Raw preferences (null until initialized). */
export const rawPreferences = preferences;

/** Whether preferences have been loaded. */
export const preferencesLoaded = (): boolean => preferences() !== null;

/** Current theme: "system", "light", or "dark". */
export const currentTheme = (): string => preferences()?.theme ?? "system";

/** Inactivity lock timeout in minutes. */
export const autoLockTimeoutMinutes = (): number =>
  preferences()?.autoLockTimeoutMinutes ?? 15;

/** Whether the sidebar is collapsed. */
export const sidebarCollapsed = (): boolean =>
  preferences()?.sidebarCollapsed ?? false;

/** Clipboard auto-clear timeout in milliseconds. */
export const clipboardAutoClearMs = (): number =>
  preferences()?.clipboardAutoClearMs ?? 30_000;

/** Whether app should launch on system boot. */
export const launchOnBoot = (): boolean =>
  preferences()?.launchOnBoot ?? false;

/** Whether app should start minimized to tray. */
export const startMinimized = (): boolean =>
  preferences()?.startMinimized ?? false;

/** Current language code (ISO 639-1). */
export const currentLanguage = (): string =>
  preferences()?.language ?? "en";

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

/**
 * Load preferences from the backend (once per session).
 * Applies the theme immediately after loading.
 * Subsequent calls are no-ops. Safe to call from multiple components.
 */
export async function initPreferences(): Promise<void> {
  if (initCalled) return;
  initCalled = true;

  try {
    const prefs = await getPreferences();
    setPreferencesSignal(prefs);
    applyTheme(prefs.theme);
  } catch {
    // Use defaults on failure — theme will follow system
    setPreferencesSignal({
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
    });
    applyTheme("system");
  }
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

/**
 * Merge a partial preferences update, persist to disk via IPC, and update the store.
 *
 * Uses optimistic local update — applies immediately so the UI stays responsive,
 * then reverts if the backend persist fails.
 *
 * @param patch — partial preferences to merge with current values
 */
export async function updatePreferences(patch: Partial<PreferencesDto>): Promise<void> {
  const current = preferences();
  if (!current) return;

  const updated: PreferencesDto = { ...current, ...patch };

  // Optimistic: update local state + theme first so the UI responds instantly.
  setPreferencesSignal(updated);
  if (patch.theme !== undefined) {
    applyTheme(updated.theme);
  }

  // Persist to backend — revert on failure.
  try {
    await setPreferences(updated);
  } catch {
    // Revert to previous state
    setPreferencesSignal(current);
    if (patch.theme !== undefined) {
      applyTheme(current.theme);
    }
  }
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/**
 * Reset the store (for testing only).
 * @internal
 */
export function _resetPreferencesStore(): void {
  setPreferencesSignal(null);
  initCalled = false;
  if (systemThemeHandler && systemThemeQuery) {
    systemThemeQuery.removeEventListener("change", systemThemeHandler);
    systemThemeHandler = null;
  }
}
