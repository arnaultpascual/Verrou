import { render, fireEvent, waitFor } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { CorruptionErrorPage } from "../../../features/vault/CorruptionErrorPage";

// Capture mock functions for assertions
const mockListVaultBackups = vi.fn();
const mockRestoreVaultBackup = vi.fn();
const mockToastSuccess = vi.fn();
const mockToastError = vi.fn();

// Mock the IPC functions
vi.mock("../../../features/vault/ipc", () => ({
  listVaultBackups: (...args: unknown[]) => mockListVaultBackups(...args),
  restoreVaultBackup: (...args: unknown[]) => mockRestoreVaultBackup(...args),
  parseUnlockError: (errorStr: string) => {
    try {
      return JSON.parse(errorStr);
    } catch {
      return { code: "UNKNOWN", message: errorStr || "An unexpected error occurred." };
    }
  },
}));

// Mock useToast
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

function renderCorruptionPage(overrides?: { message?: string; onRestored?: () => void }) {
  const props = {
    message: overrides?.message ?? "Your vault file appears corrupted or tampered with.",
    onRestored: overrides?.onRestored ?? vi.fn(),
  };
  return render(() => <CorruptionErrorPage {...props} />);
}

/** Helper: show backup list, select first item, click restore button, then return the modal confirm button */
async function openConfirmModal(queries: ReturnType<typeof renderCorruptionPage>) {
  const { getByTestId, findAllByTestId, findByTestId } = queries;
  fireEvent.click(getByTestId("show-backups-btn"));
  const items = await findAllByTestId("backup-item");
  fireEvent.click(items[0]);
  const restoreBtn = await findByTestId("restore-btn");
  fireEvent.click(restoreBtn);
  await waitFor(() => {
    expect(document.querySelector("[data-testid='confirm-restore-btn']")).not.toBeNull();
  });
}

describe("CorruptionErrorPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockListVaultBackups.mockResolvedValue([
      {
        path: "/mock/backups/vault-2026-02-10T12-30-00Z.verrou",
        timestamp: "2026-02-10T12:30:00Z",
        sizeBytes: 65536,
      },
      {
        path: "/mock/backups/vault-2026-02-09T08-15-00Z.verrou",
        timestamp: "2026-02-09T08:15:00Z",
        sizeBytes: 32768,
      },
    ]);
    mockRestoreVaultBackup.mockResolvedValue(undefined);
  });

  // 7.11: CorruptionErrorPage renders error message and restore button
  it("renders error heading and message", () => {
    const { getByTestId } = renderCorruptionPage();
    expect(getByTestId("corruption-heading").textContent).toBe("Vault Integrity Error");
    expect(getByTestId("corruption-message").textContent).toBe(
      "Your vault file appears corrupted or tampered with."
    );
  });

  it("renders restore from backup button", () => {
    const { getByTestId } = renderCorruptionPage();
    expect(getByTestId("show-backups-btn")).toBeDefined();
    expect(getByTestId("show-backups-btn").textContent).toContain("Restore from backup");
  });

  it("renders recovery guidance text", () => {
    const { getByText } = renderCorruptionPage();
    expect(getByText("If you have a backup, you can restore from it.")).toBeDefined();
  });

  // 7.12: Clicking "Restore from backup" shows backup list
  it("shows backup list after clicking restore button", async () => {
    const { getByTestId, findByTestId } = renderCorruptionPage();

    fireEvent.click(getByTestId("show-backups-btn"));

    const backupList = await findByTestId("backup-list");
    expect(backupList).toBeDefined();

    await waitFor(() => {
      const items = backupList.querySelectorAll("[data-testid='backup-item']");
      expect(items.length).toBe(2);
    });
  });

  it("shows no backups message when list is empty", async () => {
    mockListVaultBackups.mockResolvedValue([]);

    const { getByTestId, findByTestId } = renderCorruptionPage();

    fireEvent.click(getByTestId("show-backups-btn"));

    const noBackups = await findByTestId("no-backups");
    expect(noBackups.textContent).toContain("No backups available");
  });

  // 7.13: Selecting a backup, confirming and entering password triggers restore
  it("selecting a backup and confirming with correct password triggers restore", async () => {
    const onRestored = vi.fn();
    const queries = renderCorruptionPage({ onRestored });

    await openConfirmModal(queries);

    // Password input must be present in the confirm modal
    const passwordInput = document.querySelector("[data-testid='restore-password-input']") as HTMLInputElement;
    expect(passwordInput).not.toBeNull();
    fireEvent.input(passwordInput, { target: { value: "correct-password" } });

    const confirmBtn = document.querySelector("[data-testid='confirm-restore-btn']") as HTMLElement;
    fireEvent.click(confirmBtn);

    await waitFor(() => {
      expect(mockRestoreVaultBackup).toHaveBeenCalledWith(
        "/mock/backups/vault-2026-02-10T12-30-00Z.verrou",
        "correct-password"
      );
    });
  });

  // 7.14: Successful restore shows success toast
  it("shows success toast after successful restore", async () => {
    const onRestored = vi.fn();
    const queries = renderCorruptionPage({ onRestored });

    await openConfirmModal(queries);

    const passwordInput = document.querySelector("[data-testid='restore-password-input']") as HTMLInputElement;
    fireEvent.input(passwordInput, { target: { value: "correct-password" } });

    const confirmBtn = document.querySelector("[data-testid='confirm-restore-btn']") as HTMLElement;
    fireEvent.click(confirmBtn);

    await waitFor(() => {
      expect(mockToastSuccess).toHaveBeenCalledWith("Vault restored successfully");
    });

    await waitFor(() => {
      expect(onRestored).toHaveBeenCalled();
    });
  });

  it("shows error toast when restore fails with a generic error", async () => {
    mockRestoreVaultBackup.mockRejectedValue(new Error("disk error"));

    const queries = renderCorruptionPage();
    await openConfirmModal(queries);

    const passwordInput = document.querySelector("[data-testid='restore-password-input']") as HTMLInputElement;
    fireEvent.input(passwordInput, { target: { value: "some-password" } });

    const confirmBtn = document.querySelector("[data-testid='confirm-restore-btn']") as HTMLElement;
    fireEvent.click(confirmBtn);

    await waitFor(() => {
      expect(mockToastError).toHaveBeenCalledWith(
        "Failed to restore from backup."
      );
    });
  });

  // Wrong-password error: inline message inside modal
  it("shows inline invalid-password error when INVALID_PASSWORD is returned", async () => {
    mockRestoreVaultBackup.mockRejectedValue(
      JSON.stringify({ code: "INVALID_PASSWORD", message: "Incorrect password. Please try again." })
    );

    const queries = renderCorruptionPage();
    await openConfirmModal(queries);

    const passwordInput = document.querySelector("[data-testid='restore-password-input']") as HTMLInputElement;
    fireEvent.input(passwordInput, { target: { value: "wrong-password" } });

    const confirmBtn = document.querySelector("[data-testid='confirm-restore-btn']") as HTMLElement;
    fireEvent.click(confirmBtn);

    // Modal stays open, inline error appears
    await waitFor(() => {
      const errorEl = document.querySelector("[data-testid='restore-password-error']");
      expect(errorEl).not.toBeNull();
      expect(errorEl!.textContent).toContain("Incorrect password");
    });

    // Toast error should NOT be shown for invalid password
    expect(mockToastError).not.toHaveBeenCalled();
  });

  // Rate-limited error: inline message inside modal
  it("shows inline rate-limited error when RATE_LIMITED is returned", async () => {
    mockRestoreVaultBackup.mockRejectedValue(
      JSON.stringify({ code: "RATE_LIMITED", message: "Too many attempts. Please wait." })
    );

    const queries = renderCorruptionPage();
    await openConfirmModal(queries);

    const passwordInput = document.querySelector("[data-testid='restore-password-input']") as HTMLInputElement;
    fireEvent.input(passwordInput, { target: { value: "some-password" } });

    const confirmBtn = document.querySelector("[data-testid='confirm-restore-btn']") as HTMLElement;
    fireEvent.click(confirmBtn);

    await waitFor(() => {
      const errorEl = document.querySelector("[data-testid='restore-password-error']");
      expect(errorEl).not.toBeNull();
      expect(errorEl!.textContent).toContain("Too many attempts");
    });

    expect(mockToastError).not.toHaveBeenCalled();
  });

  it("shows password-required error when confirm clicked with empty password", async () => {
    const queries = renderCorruptionPage();
    await openConfirmModal(queries);

    // Do NOT fill in password — click confirm immediately
    const confirmBtn = document.querySelector("[data-testid='confirm-restore-btn']") as HTMLElement;
    fireEvent.click(confirmBtn);

    await waitFor(() => {
      const errorEl = document.querySelector("[data-testid='restore-password-error']");
      expect(errorEl).not.toBeNull();
      expect(errorEl!.textContent).toContain("Password is required");
    });

    expect(mockRestoreVaultBackup).not.toHaveBeenCalled();
  });

  it("restore button has aria-disabled until a backup is selected", async () => {
    const { getByTestId, findByTestId } = renderCorruptionPage();

    fireEvent.click(getByTestId("show-backups-btn"));

    const restoreBtn = await findByTestId("restore-btn");
    expect(restoreBtn.getAttribute("aria-disabled")).toBe("true");
  });

  it("confirm modal contains password input", async () => {
    const queries = renderCorruptionPage();
    await openConfirmModal(queries);

    const passwordInput = document.querySelector("[data-testid='restore-password-input']");
    expect(passwordInput).not.toBeNull();
    expect((passwordInput as HTMLInputElement).type).toBe("password");
  });

  it("confirm modal shows confirmation text", async () => {
    const queries = renderCorruptionPage();
    await openConfirmModal(queries);

    await waitFor(() => {
      const confirmText = document.body.textContent;
      expect(confirmText).toContain(
        "This will replace your current vault with the selected backup. Continue?"
      );
    });
  });
});
