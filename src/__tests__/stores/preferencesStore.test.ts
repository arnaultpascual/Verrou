import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock preferencesIpc module
const mockGetPreferences = vi.fn();
const mockSetPreferences = vi.fn();

vi.mock("../../features/settings/preferencesIpc", () => ({
  getPreferences: (...args: unknown[]) => mockGetPreferences(...args),
  setPreferences: (...args: unknown[]) => mockSetPreferences(...args),
}));

import {
  initPreferences,
  updatePreferences,
  currentTheme,
  autoLockTimeoutMinutes,
  sidebarCollapsed,
  clipboardAutoClearMs,
  launchOnBoot,
  startMinimized,
  preferencesLoaded,
  applyTheme,
  _resetPreferencesStore,
} from "../../stores/preferencesStore";

const DEFAULT_PREFS = {
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

describe("preferencesStore", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    _resetPreferencesStore();
    // Clear any theme set on document
    delete document.documentElement.dataset.theme;
    try { localStorage.removeItem("verrou-theme"); } catch { /* */ }
  });

  it("returns null/defaults before init", () => {
    expect(preferencesLoaded()).toBe(false);
    expect(currentTheme()).toBe("system");
    expect(autoLockTimeoutMinutes()).toBe(15);
    expect(sidebarCollapsed()).toBe(false);
    expect(clipboardAutoClearMs()).toBe(30_000);
    expect(launchOnBoot()).toBe(false);
    expect(startMinimized()).toBe(false);
  });

  it("loads preferences via IPC and sets signal", async () => {
    mockGetPreferences.mockResolvedValue({
      ...DEFAULT_PREFS,
      theme: "dark",
      autoLockTimeoutMinutes: 30,
    });

    await initPreferences();

    expect(preferencesLoaded()).toBe(true);
    expect(currentTheme()).toBe("dark");
    expect(autoLockTimeoutMinutes()).toBe(30);
  });

  it("applies theme to document on init", async () => {
    mockGetPreferences.mockResolvedValue({
      ...DEFAULT_PREFS,
      theme: "light",
    });

    await initPreferences();

    expect(document.documentElement.dataset.theme).toBe("light");
  });

  it("only calls IPC once (init guard)", async () => {
    mockGetPreferences.mockResolvedValue(DEFAULT_PREFS);

    await initPreferences();
    await initPreferences();

    expect(mockGetPreferences).toHaveBeenCalledTimes(1);
  });

  it("uses defaults when IPC fails", async () => {
    mockGetPreferences.mockRejectedValue(new Error("IPC not available"));

    await initPreferences();

    expect(preferencesLoaded()).toBe(true);
    expect(currentTheme()).toBe("system");
  });

  it("updatePreferences merges patch and persists", async () => {
    mockGetPreferences.mockResolvedValue(DEFAULT_PREFS);
    mockSetPreferences.mockResolvedValue(undefined);

    await initPreferences();
    await updatePreferences({ theme: "dark" });

    expect(currentTheme()).toBe("dark");
    expect(autoLockTimeoutMinutes()).toBe(15); // unchanged
    expect(mockSetPreferences).toHaveBeenCalledTimes(1);
    const savedPrefs = mockSetPreferences.mock.calls[0][0];
    expect(savedPrefs.theme).toBe("dark");
    expect(savedPrefs.autoLockTimeoutMinutes).toBe(15);
  });

  it("updatePreferences applies theme immediately on theme change", async () => {
    mockGetPreferences.mockResolvedValue(DEFAULT_PREFS);
    mockSetPreferences.mockResolvedValue(undefined);

    await initPreferences();
    await updatePreferences({ theme: "light" });

    expect(document.documentElement.dataset.theme).toBe("light");
  });

  it("updatePreferences reverts on IPC failure", async () => {
    mockGetPreferences.mockResolvedValue(DEFAULT_PREFS);
    mockSetPreferences.mockRejectedValue(new Error("disk full"));

    await initPreferences();
    await updatePreferences({ theme: "dark" });

    // Should revert to original value after IPC failure
    expect(currentTheme()).toBe("system");
  });

  it("updatePreferences reverts theme on IPC failure", async () => {
    mockGetPreferences.mockResolvedValue(DEFAULT_PREFS);
    mockSetPreferences.mockRejectedValue(new Error("disk full"));

    await initPreferences();
    await updatePreferences({ theme: "light" });

    // Theme should be reverted back to system (data-theme removed)
    expect(document.documentElement.dataset.theme).toBeUndefined();
  });

  it("derived accessors return correct values", async () => {
    mockGetPreferences.mockResolvedValue({
      theme: "light",
      language: "fr",
      autoLockTimeoutMinutes: 45,
      hotkeys: { quickAccess: "CmdOrCtrl+Shift+V", lockVault: "CmdOrCtrl+Shift+L" },
      clipboardAutoClearMs: 60_000,
      sidebarCollapsed: true,
      launchOnBoot: true,
      startMinimized: true,
    });

    await initPreferences();

    expect(currentTheme()).toBe("light");
    expect(autoLockTimeoutMinutes()).toBe(45);
    expect(sidebarCollapsed()).toBe(true);
    expect(clipboardAutoClearMs()).toBe(60_000);
    expect(launchOnBoot()).toBe(true);
    expect(startMinimized()).toBe(true);
  });

  it("reset clears state for test isolation", async () => {
    mockGetPreferences.mockResolvedValue(DEFAULT_PREFS);

    await initPreferences();
    expect(preferencesLoaded()).toBe(true);

    _resetPreferencesStore();
    expect(preferencesLoaded()).toBe(false);
  });
});

describe("applyTheme", () => {
  beforeEach(() => {
    delete document.documentElement.dataset.theme;
    try { localStorage.removeItem("verrou-theme"); } catch { /* */ }
  });

  it("sets data-theme='light' for light", () => {
    applyTheme("light");
    expect(document.documentElement.dataset.theme).toBe("light");
  });

  it("sets data-theme='dark' for dark", () => {
    applyTheme("dark");
    expect(document.documentElement.dataset.theme).toBe("dark");
  });

  it("removes data-theme for system", () => {
    document.documentElement.dataset.theme = "light";
    applyTheme("system");
    expect(document.documentElement.dataset.theme).toBeUndefined();
  });

  it("caches theme in localStorage", () => {
    applyTheme("dark");
    expect(localStorage.getItem("verrou-theme")).toBe("dark");
  });
});
