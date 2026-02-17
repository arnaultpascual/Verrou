import { render, fireEvent, waitFor } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach } from "vitest";

// Mock preferences IPC
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
    quickAccess: "CmdOrCtrl+Shift+X",
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
const mockToastSuccess = vi.fn();
const mockToastError = vi.fn();
vi.mock("../../../components", async (importOriginal) => {
  const original = await importOriginal<Record<string, unknown>>();
  return {
    ...original,
    useToast: () => ({
      success: mockToastSuccess,
      error: mockToastError,
      info: vi.fn(),
      dismiss: vi.fn(),
      clear: vi.fn(),
    }),
  };
});

import {
  updateHotkeyBinding,
  resetHotkeyBinding,
} from "../../../features/settings/preferencesIpc";
import { KeyboardShortcuts } from "../../../features/settings/KeyboardShortcuts";

describe("KeyboardShortcuts", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders section title and description", async () => {
    const { findByText } = render(() => <KeyboardShortcuts />);

    const title = await findByText("Keyboard Shortcuts");
    expect(title).toBeDefined();

    const desc = await findByText(/Global hotkeys work from any application/);
    expect(desc).toBeDefined();
  });

  it("displays current bindings in table", async () => {
    const { findByText } = render(() => <KeyboardShortcuts />);

    const qaLabel = await findByText("Quick Access");
    expect(qaLabel).toBeDefined();

    const lockLabel = await findByText("Lock Vault");
    expect(lockLabel).toBeDefined();
  });

  it("shows Change buttons for each binding", async () => {
    const { findByTestId } = render(() => <KeyboardShortcuts />);

    const changeQA = await findByTestId("change-quickAccess");
    expect(changeQA).toBeDefined();

    const changeLock = await findByTestId("change-lockVault");
    expect(changeLock).toBeDefined();
  });

  it("opens key recorder on Change click", async () => {
    const { findByTestId, findByText } = render(() => <KeyboardShortcuts />);

    const changeBtn = await findByTestId("change-quickAccess");
    fireEvent.click(changeBtn);

    const placeholder = await findByText("Press key combination...");
    expect(placeholder).toBeDefined();
  });

  it("cancels recording on Cancel click", async () => {
    const { findByTestId, findByText, queryByText } = render(() => (
      <KeyboardShortcuts />
    ));

    const changeBtn = await findByTestId("change-quickAccess");
    fireEvent.click(changeBtn);

    await findByText("Press key combination...");

    const cancelBtn = await findByText("Cancel");
    fireEvent.click(cancelBtn);

    await waitFor(() => {
      expect(queryByText("Press key combination...")).toBeNull();
    });
  });

  it("calls updateHotkeyBinding on confirm", async () => {
    const { findByTestId, findByText, container } = render(() => (
      <KeyboardShortcuts />
    ));

    const changeBtn = await findByTestId("change-quickAccess");
    fireEvent.click(changeBtn);

    // Find the recorder input and simulate key press
    const recorderInput = container.querySelector("[role='textbox']") as HTMLElement;
    expect(recorderInput).not.toBeNull();

    fireEvent.keyDown(recorderInput, {
      key: "X",
      ctrlKey: true,
      shiftKey: true,
    });

    const confirmBtn = await findByText("Confirm");
    fireEvent.click(confirmBtn);

    await waitFor(() => {
      expect(updateHotkeyBinding).toHaveBeenCalledWith(
        "quickAccess",
        "CmdOrCtrl+Shift+X",
      );
    });
  });

  it("shows success toast after update", async () => {
    const { findByTestId, findByText, container } = render(() => (
      <KeyboardShortcuts />
    ));

    const changeBtn = await findByTestId("change-quickAccess");
    fireEvent.click(changeBtn);

    const recorderInput = container.querySelector("[role='textbox']") as HTMLElement;
    fireEvent.keyDown(recorderInput, {
      key: "X",
      ctrlKey: true,
      shiftKey: true,
    });

    const confirmBtn = await findByText("Confirm");
    fireEvent.click(confirmBtn);

    await waitFor(() => {
      expect(mockToastSuccess).toHaveBeenCalled();
    });
  });

  it("shows error toast on update failure", async () => {
    (updateHotkeyBinding as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      "Could not register shortcut. It may be in use by another application.",
    );

    const { findByTestId, findByText, container } = render(() => (
      <KeyboardShortcuts />
    ));

    const changeBtn = await findByTestId("change-quickAccess");
    fireEvent.click(changeBtn);

    const recorderInput = container.querySelector("[role='textbox']") as HTMLElement;
    fireEvent.keyDown(recorderInput, {
      key: "X",
      ctrlKey: true,
      shiftKey: true,
    });

    const confirmBtn = await findByText("Confirm");
    fireEvent.click(confirmBtn);

    await waitFor(() => {
      expect(mockToastError).toHaveBeenCalled();
    });
  });

  it("calls resetHotkeyBinding on reset click", async () => {
    // Override getPreferences to return a non-default binding
    const { getPreferences } = await import(
      "../../../features/settings/preferencesIpc"
    );
    (getPreferences as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      theme: "system",
      language: "en",
      autoLockTimeoutMinutes: 15,
      hotkeys: {
        quickAccess: "CmdOrCtrl+Shift+X",
        lockVault: "CmdOrCtrl+Shift+L",
      },
      clipboardAutoClearMs: 30000,
      sidebarCollapsed: false,
    });

    const { findByTestId } = render(() => <KeyboardShortcuts />);

    const resetBtn = await findByTestId("reset-quickAccess");
    fireEvent.click(resetBtn);

    await waitFor(() => {
      expect(resetHotkeyBinding).toHaveBeenCalledWith("quickAccess");
      expect(mockToastSuccess).toHaveBeenCalled();
    });
  });
});
