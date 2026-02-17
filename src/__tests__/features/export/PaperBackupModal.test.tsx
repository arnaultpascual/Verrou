import { render, fireEvent, waitFor } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { PaperBackupModal } from "../../../features/export/PaperBackupModal";

// Mock useToast
const mockToast = {
  success: vi.fn(),
  error: vi.fn(),
  info: vi.fn(),
  dismiss: vi.fn(),
  clear: vi.fn(),
};

vi.mock("../../../components/useToast", () => ({
  useToast: () => mockToast,
}));

// Mock paperBackupIpc — default: resolves with mock data
const mockGeneratePaperBackupData = vi.fn();

vi.mock("../../../features/export/paperBackupIpc", () => ({
  generatePaperBackupData: (...args: unknown[]) =>
    mockGeneratePaperBackupData(...args),
}));

// Mock vault IPC for parseUnlockError
vi.mock("../../../features/vault/ipc", () => ({
  parseUnlockError: (err: string) => {
    try {
      const parsed = JSON.parse(err);
      return { code: parsed.code, message: parsed.message };
    } catch {
      return { code: "UNKNOWN", message: err };
    }
  },
  getVaultDir: () => "/mock/vault",
}));

const MOCK_BACKUP_DATA = {
  seeds: [
    {
      name: "Bitcoin Wallet",
      words: ["abandon", "ability", "able", "about", "above", "absent",
        "absorb", "abstract", "absurd", "abuse", "access", "about"],
      wordCount: 12,
      hasPassphrase: false,
    },
  ],
  recoveryCodes: [
    {
      name: "Google Account",
      issuer: "google.com",
      codes: ["ABCD-1234", "EFGH-5678"],
      used: [0],
      totalCodes: 2,
      remainingCodes: 1,
    },
  ],
  generatedAt: "2026-02-15T14:30:00Z",
  vaultFingerprint: "a1b2c3d4e5f6a7b8",
  contentChecksum: "abc123checksum",
};

beforeEach(() => {
  mockToast.success.mockClear();
  mockToast.error.mockClear();
  mockGeneratePaperBackupData.mockReset();
  mockGeneratePaperBackupData.mockResolvedValue(MOCK_BACKUP_DATA);
});

function renderModal(
  overrides: Partial<{ open: boolean; onClose: () => void }> = {},
) {
  const onClose = overrides.onClose ?? vi.fn();
  const result = render(() => (
    <PaperBackupModal open={overrides.open ?? true} onClose={onClose} />
  ));
  return { ...result, onClose };
}

describe("PaperBackupModal", () => {
  describe("input phase (AC #1)", () => {
    it("shows password input and warning", () => {
      renderModal();

      expect(document.body.textContent).toContain("Paper Backup");
      expect(document.body.textContent).toContain(
        "unencrypted seed phrases and recovery codes",
      );
      expect(document.body.textContent).toContain("Master Password");
      expect(
        document.querySelector("[data-testid='paper-backup-submit']"),
      ).toBeTruthy();
    });

    it("disables submit when password is empty", () => {
      renderModal();

      const btn = document.querySelector(
        "[data-testid='paper-backup-submit']",
      ) as HTMLButtonElement;
      expect(btn.getAttribute("aria-disabled")).toBe("true");
    });
  });

  describe("preview phase (AC #2, #3)", () => {
    it("shows backup document after successful auth", async () => {
      renderModal();

      // Enter password
      const input = document.querySelector(
        "input[type='password']",
      ) as HTMLInputElement;
      fireEvent.input(input, { target: { value: "testpass" } });

      // Submit
      const form = input.closest("form")!;
      fireEvent.submit(form);

      // Wait for preview
      await waitFor(() => {
        expect(
          document.querySelector("[data-testid='paper-backup-document']"),
        ).toBeTruthy();
      });

      expect(document.body.textContent).toContain("Bitcoin Wallet");
      expect(document.body.textContent).toContain("Google Account");
      expect(document.body.textContent).toContain(
        "Store this document in a secure physical location",
      );
    });

    it("shows warning banner in preview phase", async () => {
      renderModal();

      const input = document.querySelector(
        "input[type='password']",
      ) as HTMLInputElement;
      fireEvent.input(input, { target: { value: "testpass" } });
      fireEvent.submit(input.closest("form")!);

      await waitFor(() => {
        expect(
          document.querySelector("[data-testid='paper-backup-document']"),
        ).toBeTruthy();
      });

      expect(document.body.textContent).toContain(
        "unencrypted seed phrases",
      );
    });

    it("shows Print and Close buttons in preview", async () => {
      renderModal();

      const input = document.querySelector(
        "input[type='password']",
      ) as HTMLInputElement;
      fireEvent.input(input, { target: { value: "testpass" } });
      fireEvent.submit(input.closest("form")!);

      await waitFor(() => {
        expect(
          document.querySelector("[data-testid='paper-backup-print']"),
        ).toBeTruthy();
        expect(
          document.querySelector("[data-testid='paper-backup-close']"),
        ).toBeTruthy();
      });
    });
  });

  describe("error phase", () => {
    it("shows error message on auth failure", async () => {
      mockGeneratePaperBackupData.mockRejectedValueOnce("Incorrect password.");

      renderModal();

      const input = document.querySelector(
        "input[type='password']",
      ) as HTMLInputElement;
      fireEvent.input(input, { target: { value: "wrongpass" } });
      fireEvent.submit(input.closest("form")!);

      await waitFor(() => {
        const alert = document.querySelector("[data-testid='paper-backup-error']");
        expect(alert).toBeTruthy();
        expect(alert!.textContent).toContain("Incorrect password");
      });
    });

    it("shows Try Again button on error", async () => {
      mockGeneratePaperBackupData.mockRejectedValueOnce("Incorrect password.");

      renderModal();

      const input = document.querySelector(
        "input[type='password']",
      ) as HTMLInputElement;
      fireEvent.input(input, { target: { value: "wrongpass" } });
      fireEvent.submit(input.closest("form")!);

      await waitFor(() => {
        expect(
          document.querySelector("[data-testid='paper-backup-retry']"),
        ).toBeTruthy();
      });
    });

    it("returns to input phase on retry", async () => {
      mockGeneratePaperBackupData.mockRejectedValueOnce("Incorrect password.");

      renderModal();

      const input = document.querySelector(
        "input[type='password']",
      ) as HTMLInputElement;
      fireEvent.input(input, { target: { value: "wrongpass" } });
      fireEvent.submit(input.closest("form")!);

      await waitFor(() => {
        expect(
          document.querySelector("[data-testid='paper-backup-retry']"),
        ).toBeTruthy();
      });

      fireEvent.click(
        document.querySelector("[data-testid='paper-backup-retry']")!,
      );

      await waitFor(() => {
        expect(
          document.querySelector("[data-testid='paper-backup-submit']"),
        ).toBeTruthy();
      });
    });
  });

  describe("close and cleanup (AC #4)", () => {
    it("calls onClose when Close button is clicked", async () => {
      const onClose = vi.fn();
      renderModal({ onClose });

      const input = document.querySelector(
        "input[type='password']",
      ) as HTMLInputElement;
      fireEvent.input(input, { target: { value: "testpass" } });
      fireEvent.submit(input.closest("form")!);

      await waitFor(() => {
        expect(
          document.querySelector("[data-testid='paper-backup-close']"),
        ).toBeTruthy();
      });

      fireEvent.click(
        document.querySelector("[data-testid='paper-backup-close']")!,
      );

      expect(onClose).toHaveBeenCalled();
    });

    it("does not render document when modal is closed", () => {
      renderModal({ open: false });

      expect(
        document.querySelector("[data-testid='paper-backup-document']"),
      ).toBeNull();
      expect(
        document.querySelector("[data-testid='paper-backup-submit']"),
      ).toBeNull();
    });
  });
});
