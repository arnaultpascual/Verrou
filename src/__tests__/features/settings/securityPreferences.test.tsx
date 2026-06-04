import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock preferences store — controls auto-lock + clipboard values.
let mockTimeout = 15;
let mockClipboardMs = 30_000;
let mockLoaded = true;
const mockUpdatePreferences = vi.fn().mockResolvedValue(undefined);

vi.mock("../../../stores/preferencesStore", () => ({
  autoLockTimeoutMinutes: () => mockTimeout,
  clipboardAutoClearMs: () => mockClipboardMs,
  preferencesLoaded: () => mockLoaded,
  updatePreferences: (...args: unknown[]) => mockUpdatePreferences(...args),
}));

import { render, fireEvent } from "@solidjs/testing-library";
import { SecurityPreferences } from "../../../features/settings/SecurityPreferences";

describe("SecurityPreferences", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockTimeout = 15;
    mockClipboardMs = 30_000;
    mockLoaded = true;
    mockUpdatePreferences.mockResolvedValue(undefined);
  });

  it("renders when preferences are loaded", () => {
    const { getByTestId } = render(() => <SecurityPreferences />);
    expect(getByTestId("security-preferences")).toBeDefined();
  });

  it("does not render when preferences not loaded", () => {
    mockLoaded = false;
    const { queryByTestId } = render(() => <SecurityPreferences />);
    expect(queryByTestId("security-preferences")).toBeNull();
  });

  // ── Auto-lock timeout (relocated from PreferencesSection) ──

  it("renders the auto-lock timeout slider", () => {
    const { getByTestId } = render(() => <SecurityPreferences />);
    expect(getByTestId("lock-timeout")).toBeDefined();
  });

  it("shows the current auto-lock timeout value", () => {
    mockTimeout = 30;
    const { getByTestId } = render(() => <SecurityPreferences />);
    expect(getByTestId("timeout-value").textContent).toContain("30 min");
  });

  it("writes autoLockTimeoutMinutes when the slider changes", () => {
    const { container } = render(() => <SecurityPreferences />);
    const slider = container.querySelector(
      "#lock-timeout-slider",
    ) as HTMLInputElement;
    fireEvent.input(slider, { target: { value: "25" } });
    expect(mockUpdatePreferences).toHaveBeenCalledWith({
      autoLockTimeoutMinutes: 25,
    });
  });

  // ── Clipboard auto-clear timeout (NEW control) ──

  it("renders the clipboard auto-clear select with the expected options", () => {
    const { getByTestId } = render(() => <SecurityPreferences />);
    const select = getByTestId("clipboard-clear-select") as HTMLSelectElement;
    expect(select).toBeDefined();
    const values = Array.from(select.options).map((o) => o.value);
    expect(values).toEqual(["10000", "30000", "60000", "120000"]);
  });

  it("READS the current clipboardAutoClearMs preference into the select", () => {
    mockClipboardMs = 60_000;
    const { getByTestId } = render(() => <SecurityPreferences />);
    const select = getByTestId("clipboard-clear-select") as HTMLSelectElement;
    expect(select.value).toBe("60000");
  });

  it("reflects the default 30s preference when unset", () => {
    mockClipboardMs = 30_000;
    const { getByTestId } = render(() => <SecurityPreferences />);
    const select = getByTestId("clipboard-clear-select") as HTMLSelectElement;
    expect(select.value).toBe("30000");
  });

  it("WRITES clipboardAutoClearMs when a new option is selected", () => {
    const { getByTestId } = render(() => <SecurityPreferences />);
    const select = getByTestId("clipboard-clear-select") as HTMLSelectElement;
    fireEvent.change(select, { target: { value: "120000" } });
    expect(mockUpdatePreferences).toHaveBeenCalledWith({
      clipboardAutoClearMs: 120_000,
    });
  });

  it("does not write when the selected value is not a known option", () => {
    const { getByTestId } = render(() => <SecurityPreferences />);
    const select = getByTestId("clipboard-clear-select") as HTMLSelectElement;
    // Simulate an out-of-range value (defensive guard in the handler).
    fireEvent.change(select, { target: { value: "999" } });
    expect(mockUpdatePreferences).not.toHaveBeenCalled();
  });
});
