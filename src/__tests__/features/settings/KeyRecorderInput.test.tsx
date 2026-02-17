import { render, fireEvent, waitFor } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach } from "vitest";

// Mock preferences IPC — we import KeyboardShortcuts which contains KeyRecorderInput
vi.mock("../../../features/settings/preferencesIpc", () => ({
  getPreferences: vi.fn().mockResolvedValue({
    theme: "system",
    language: "en",
    autoLockTimeoutMinutes: 15,
    hotkeys: {
      quickAccess: "CmdOrCtrl+Shift+V",
      lockVault: "CmdOrCtrl+Shift+L",
    },
    clipboardAutoClearMs: 30000,
    sidebarCollapsed: false,
  }),
  updateHotkeyBinding: vi.fn().mockResolvedValue({
    quickAccess: "CmdOrCtrl+Shift+V",
    lockVault: "CmdOrCtrl+Shift+L",
  }),
  resetHotkeyBinding: vi.fn().mockResolvedValue({
    quickAccess: "CmdOrCtrl+Shift+V",
    lockVault: "CmdOrCtrl+Shift+L",
  }),
  DEFAULT_HOTKEYS: {
    quickAccess: "CmdOrCtrl+Shift+V",
    lockVault: "CmdOrCtrl+Shift+L",
  },
}));

// Mock useToast
vi.mock("../../../components", async (importOriginal) => {
  const original = await importOriginal<Record<string, unknown>>();
  return {
    ...original,
    useToast: () => ({
      success: vi.fn(),
      error: vi.fn(),
      info: vi.fn(),
      dismiss: vi.fn(),
      clear: vi.fn(),
    }),
  };
});

import { KeyboardShortcuts } from "../../../features/settings/KeyboardShortcuts";

describe("KeyRecorderInput", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("captures Ctrl+Shift+key combo", async () => {
    const { findByTestId, container } = render(() => <KeyboardShortcuts />);

    const changeBtn = await findByTestId("change-quickAccess");
    fireEvent.click(changeBtn);

    const input = container.querySelector("[role='textbox']") as HTMLElement;
    fireEvent.keyDown(input, { key: "K", ctrlKey: true, shiftKey: true });

    await waitFor(() => {
      const kbd = container.querySelector("kbd");
      expect(kbd?.textContent).toBe("Ctrl+Shift+K");
    });
  });

  it("captures Cmd+Shift+key combo on meta key", async () => {
    const { findByTestId, container } = render(() => <KeyboardShortcuts />);

    const changeBtn = await findByTestId("change-quickAccess");
    fireEvent.click(changeBtn);

    const input = container.querySelector("[role='textbox']") as HTMLElement;
    fireEvent.keyDown(input, { key: "J", metaKey: true, shiftKey: true });

    await waitFor(() => {
      const kbd = container.querySelector("kbd");
      expect(kbd?.textContent).toBe("Cmd+Shift+J");
    });
  });

  it("ignores modifier-only key presses", async () => {
    const { findByTestId, container, findByText } = render(() => (
      <KeyboardShortcuts />
    ));

    const changeBtn = await findByTestId("change-quickAccess");
    fireEvent.click(changeBtn);

    const input = container.querySelector("[role='textbox']") as HTMLElement;

    // Press only Shift (modifier-only)
    fireEvent.keyDown(input, { key: "Shift", shiftKey: true });

    // Should still show placeholder
    const placeholder = await findByText("Press key combination...");
    expect(placeholder).toBeDefined();
  });

  it("cancels recording on Escape", async () => {
    const { findByTestId, container, queryByText } = render(() => (
      <KeyboardShortcuts />
    ));

    const changeBtn = await findByTestId("change-quickAccess");
    fireEvent.click(changeBtn);

    const input = container.querySelector("[role='textbox']") as HTMLElement;
    fireEvent.keyDown(input, { key: "Escape" });

    await waitFor(() => {
      expect(queryByText("Press key combination...")).toBeNull();
    });
  });

  it("captures Alt+key combo", async () => {
    const { findByTestId, container } = render(() => <KeyboardShortcuts />);

    const changeBtn = await findByTestId("change-lockVault");
    fireEvent.click(changeBtn);

    const input = container.querySelector("[role='textbox']") as HTMLElement;
    fireEvent.keyDown(input, { key: "L", ctrlKey: true, altKey: true });

    await waitFor(() => {
      // Scope to the recorder container to avoid picking up the other row's kbd
      const recorder = input.closest("[class*='recorder']") as HTMLElement;
      const kbd = recorder?.querySelector("kbd");
      expect(kbd?.textContent).toBe("Ctrl+Alt+L");
    });
  });

  it("ignores key press without any modifier", async () => {
    const { findByTestId, container, findByText } = render(() => (
      <KeyboardShortcuts />
    ));

    const changeBtn = await findByTestId("change-quickAccess");
    fireEvent.click(changeBtn);

    const input = container.querySelector("[role='textbox']") as HTMLElement;

    // Press 'V' without any modifier
    fireEvent.keyDown(input, { key: "V" });

    // Should still show placeholder
    const placeholder = await findByText("Press key combination...");
    expect(placeholder).toBeDefined();
  });

  it("has accessible role and label", async () => {
    const { findByTestId, container } = render(() => <KeyboardShortcuts />);

    const changeBtn = await findByTestId("change-quickAccess");
    fireEvent.click(changeBtn);

    const input = container.querySelector("[role='textbox']") as HTMLElement;
    expect(input).not.toBeNull();
    expect(input.getAttribute("aria-label")).toBe(
      "Press key combination...",
    );
  });

  it("confirm button is disabled until combo captured", async () => {
    const { findByTestId, findByText } = render(() => <KeyboardShortcuts />);

    const changeBtn = await findByTestId("change-quickAccess");
    fireEvent.click(changeBtn);

    const confirmBtn = await findByText("Confirm");
    // Button component uses aria-disabled instead of HTML disabled
    expect(confirmBtn.getAttribute("aria-disabled")).toBe("true");
  });
});
