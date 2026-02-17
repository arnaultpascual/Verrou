import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock preferences store
let mockTheme = "system";
let mockTimeout = 15;
let mockLaunchOnBoot = false;
let mockStartMinimized = false;
let mockLoaded = true;
const mockUpdatePreferences = vi.fn().mockResolvedValue(undefined);

vi.mock("../../../stores/preferencesStore", () => ({
  currentTheme: () => mockTheme,
  autoLockTimeoutMinutes: () => mockTimeout,
  launchOnBoot: () => mockLaunchOnBoot,
  startMinimized: () => mockStartMinimized,
  preferencesLoaded: () => mockLoaded,
  updatePreferences: (...args: unknown[]) => mockUpdatePreferences(...args),
}));

// Mock autostart IPC
const mockEnableAutostart = vi.fn().mockResolvedValue(undefined);
const mockDisableAutostart = vi.fn().mockResolvedValue(undefined);

vi.mock("../../../features/settings/preferencesIpc", () => ({
  enableAutostart: (...args: unknown[]) => mockEnableAutostart(...args),
  disableAutostart: (...args: unknown[]) => mockDisableAutostart(...args),
}));

// Mock toast
const mockToastSuccess = vi.fn();
const mockToastError = vi.fn();

vi.mock("../../../components/useToast", () => ({
  useToast: () => ({
    success: mockToastSuccess,
    error: mockToastError,
    info: vi.fn(),
  }),
}));

import { render, fireEvent } from "@solidjs/testing-library";
import { PreferencesSection } from "../../../features/settings/PreferencesSection";

describe("PreferencesSection", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockTheme = "system";
    mockTimeout = 15;
    mockLaunchOnBoot = false;
    mockStartMinimized = false;
    mockLoaded = true;
    mockEnableAutostart.mockResolvedValue(undefined);
    mockDisableAutostart.mockResolvedValue(undefined);
    mockUpdatePreferences.mockResolvedValue(undefined);
  });

  it("renders preferences section when loaded", () => {
    const { getByTestId } = render(() => <PreferencesSection />);
    expect(getByTestId("preferences-section")).toBeDefined();
  });

  it("does not render when preferences not loaded", () => {
    mockLoaded = false;
    const { queryByTestId } = render(() => <PreferencesSection />);
    expect(queryByTestId("preferences-section")).toBeNull();
  });

  it("renders theme selector with three options", () => {
    const { getByTestId } = render(() => <PreferencesSection />);
    expect(getByTestId("theme-light")).toBeDefined();
    expect(getByTestId("theme-dark")).toBeDefined();
    expect(getByTestId("theme-system")).toBeDefined();
  });

  it("shows system theme as active by default", () => {
    const { getByTestId } = render(() => <PreferencesSection />);
    const systemBtn = getByTestId("theme-system");
    expect(systemBtn.getAttribute("aria-checked")).toBe("true");
  });

  it("calls updatePreferences when theme button clicked", async () => {
    const { getByTestId } = render(() => <PreferencesSection />);
    fireEvent.click(getByTestId("theme-dark"));
    expect(mockUpdatePreferences).toHaveBeenCalledWith({ theme: "dark" });
  });

  it("renders lock timeout slider", () => {
    const { getByTestId } = render(() => <PreferencesSection />);
    expect(getByTestId("lock-timeout")).toBeDefined();
  });

  it("shows current timeout value", () => {
    mockTimeout = 30;
    const { getByTestId } = render(() => <PreferencesSection />);
    expect(getByTestId("timeout-value").textContent).toContain("30 min");
  });

  it("calls updatePreferences when timeout slider changes", () => {
    const { container } = render(() => <PreferencesSection />);
    const slider = container.querySelector("#lock-timeout-slider") as HTMLInputElement;
    fireEvent.input(slider, { target: { value: "25" } });
    expect(mockUpdatePreferences).toHaveBeenCalledWith({ autoLockTimeoutMinutes: 25 });
  });

  it("renders startup behavior toggles", () => {
    const { getByTestId } = render(() => <PreferencesSection />);
    expect(getByTestId("startup-behavior")).toBeDefined();
    expect(getByTestId("launch-on-boot")).toBeDefined();
    expect(getByTestId("start-minimized")).toBeDefined();
  });

  it("start minimized is disabled when launch on boot is off", () => {
    mockLaunchOnBoot = false;
    const { getByTestId } = render(() => <PreferencesSection />);
    const input = getByTestId("start-minimized") as HTMLInputElement;
    expect(input.disabled).toBe(true);
  });

  it("start minimized is enabled when launch on boot is on", () => {
    mockLaunchOnBoot = true;
    const { getByTestId } = render(() => <PreferencesSection />);
    const input = getByTestId("start-minimized") as HTMLInputElement;
    expect(input.disabled).toBe(false);
  });

  it("enabling launch on boot calls enableAutostart and shows success toast", async () => {
    const { getByTestId } = render(() => <PreferencesSection />);
    const toggle = getByTestId("launch-on-boot") as HTMLInputElement;
    await fireEvent.click(toggle);

    // Wait for async handler
    await vi.waitFor(() => {
      expect(mockEnableAutostart).toHaveBeenCalled();
    });
    expect(mockUpdatePreferences).toHaveBeenCalledWith({ launchOnBoot: true });
    expect(mockToastSuccess).toHaveBeenCalled();
  });

  it("disabling launch on boot calls disableAutostart and resets startMinimized", async () => {
    mockLaunchOnBoot = true;
    const { getByTestId } = render(() => <PreferencesSection />);
    const toggle = getByTestId("launch-on-boot") as HTMLInputElement;
    await fireEvent.click(toggle);

    await vi.waitFor(() => {
      expect(mockDisableAutostart).toHaveBeenCalled();
    });
    expect(mockUpdatePreferences).toHaveBeenCalledWith({
      launchOnBoot: false,
      startMinimized: false,
    });
    expect(mockToastSuccess).toHaveBeenCalled();
  });

  it("reverts toggle and shows error toast when autostart fails", async () => {
    mockEnableAutostart.mockRejectedValue(new Error("Permission denied"));
    const { getByTestId } = render(() => <PreferencesSection />);
    const toggle = getByTestId("launch-on-boot") as HTMLInputElement;
    await fireEvent.click(toggle);

    await vi.waitFor(() => {
      expect(mockToastError).toHaveBeenCalled();
    });
    expect(mockUpdatePreferences).not.toHaveBeenCalled();
    // Verify the checkbox was reverted to unchecked
    expect(toggle.checked).toBe(false);
  });
});
