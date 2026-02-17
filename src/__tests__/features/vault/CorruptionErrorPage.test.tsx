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

  // 7.13: Selecting a backup and confirming triggers restore
  it("selecting a backup and confirming triggers restore", async () => {
    const onRestored = vi.fn();
    const { getByTestId, findAllByTestId, findByTestId } = renderCorruptionPage({
      onRestored,
    });

    // Show backup list
    fireEvent.click(getByTestId("show-backups-btn"));

    // Wait for backups to load
    const items = await findAllByTestId("backup-item");
    expect(items.length).toBe(2);

    // Select first backup
    fireEvent.click(items[0]);

    // Click restore button
    const restoreBtn = await findByTestId("restore-btn");
    fireEvent.click(restoreBtn);

    // Confirm dialog renders in a portal — query document directly
    await waitFor(() => {
      const confirmText = document.body.textContent;
      expect(confirmText).toContain(
        "This will replace your current vault with the selected backup. Continue?"
      );
    });

    // Click confirm button (also in portal)
    const confirmBtn = document.querySelector("[data-testid='confirm-restore-btn']") as HTMLElement;
    expect(confirmBtn).not.toBeNull();
    fireEvent.click(confirmBtn);

    // Wait for restore to complete
    await waitFor(() => {
      expect(mockRestoreVaultBackup).toHaveBeenCalledWith(
        "/mock/backups/vault-2026-02-10T12-30-00Z.verrou"
      );
    });
  });

  // 7.14: Successful restore shows success toast
  it("shows success toast after successful restore", async () => {
    const onRestored = vi.fn();
    const { getByTestId, findAllByTestId, findByTestId } = renderCorruptionPage({
      onRestored,
    });

    // Show backups → select → restore → confirm
    fireEvent.click(getByTestId("show-backups-btn"));
    const items = await findAllByTestId("backup-item");
    fireEvent.click(items[0]);

    const restoreBtn = await findByTestId("restore-btn");
    fireEvent.click(restoreBtn);

    // Wait for modal to appear in portal
    await waitFor(() => {
      expect(document.querySelector("[data-testid='confirm-restore-btn']")).not.toBeNull();
    });

    const confirmBtn = document.querySelector("[data-testid='confirm-restore-btn']") as HTMLElement;
    fireEvent.click(confirmBtn);

    await waitFor(() => {
      expect(mockToastSuccess).toHaveBeenCalledWith("Vault restored successfully");
    });

    await waitFor(() => {
      expect(onRestored).toHaveBeenCalled();
    });
  });

  it("shows error toast when restore fails", async () => {
    mockRestoreVaultBackup.mockRejectedValue(new Error("disk error"));

    const { getByTestId, findAllByTestId, findByTestId } = renderCorruptionPage();

    fireEvent.click(getByTestId("show-backups-btn"));
    const items = await findAllByTestId("backup-item");
    fireEvent.click(items[0]);

    const restoreBtn = await findByTestId("restore-btn");
    fireEvent.click(restoreBtn);

    await waitFor(() => {
      expect(document.querySelector("[data-testid='confirm-restore-btn']")).not.toBeNull();
    });

    const confirmBtn = document.querySelector("[data-testid='confirm-restore-btn']") as HTMLElement;
    fireEvent.click(confirmBtn);

    await waitFor(() => {
      expect(mockToastError).toHaveBeenCalledWith(
        "Failed to restore from backup."
      );
    });
  });

  it("restore button has aria-disabled until a backup is selected", async () => {
    const { getByTestId, findByTestId } = renderCorruptionPage();

    fireEvent.click(getByTestId("show-backups-btn"));

    const restoreBtn = await findByTestId("restore-btn");
    expect(restoreBtn.getAttribute("aria-disabled")).toBe("true");
  });
});
