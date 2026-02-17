import { render, fireEvent, waitFor } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { ConfirmDeleteSeedModal } from "../../../features/seed/ConfirmDeleteSeedModal";

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

// Mock deleteSeedPhrase
const mockDeleteSeedPhrase = vi.fn<(entryId: string, password: string) => Promise<void>>();

vi.mock("../../../features/seed/ipc", () => ({
  deleteSeedPhrase: (...args: unknown[]) => mockDeleteSeedPhrase(...(args as [string, string])),
}));

// Mock copyToClipboard (may be imported transitively)
vi.mock("../../../features/entries/ipc", () => ({
  copyToClipboard: vi.fn().mockResolvedValue(undefined),
}));

const defaultProps = {
  open: true,
  entryId: "seed-123",
  walletName: "Bitcoin Wallet",
  onDeleted: vi.fn(),
  onCancel: vi.fn(),
};

beforeEach(() => {
  vi.clearAllMocks();
  mockDeleteSeedPhrase.mockResolvedValue(undefined);
});

describe("ConfirmDeleteSeedModal", () => {
  describe("heightened language", () => {
    it("renders modal title", () => {
      render(() => <ConfirmDeleteSeedModal {...defaultProps} />);
      expect(document.body.textContent).toContain("Delete Seed Phrase");
    });

    it("displays wallet name in confirmation message", () => {
      render(() => <ConfirmDeleteSeedModal {...defaultProps} />);
      const body = document.querySelector("[data-testid='confirm-delete-seed-body']");
      expect(body).toBeTruthy();
      expect(body!.textContent).toContain("Bitcoin Wallet");
    });

    it("contains heightened warning text", () => {
      render(() => <ConfirmDeleteSeedModal {...defaultProps} />);
      const body = document.querySelector("[data-testid='confirm-delete-seed-body']");
      expect(body!.textContent).toContain("permanently remove the encrypted seed");
      expect(body!.textContent).toContain("This cannot be undone.");
    });
  });

  describe("button layout", () => {
    it("shows Cancel and Delete buttons", () => {
      render(() => <ConfirmDeleteSeedModal {...defaultProps} />);
      const buttons = Array.from(document.querySelectorAll("button"));
      const cancelBtn = buttons.find((b) => b.textContent?.includes("Cancel"));
      const deleteBtn = buttons.find((b) => b.textContent?.includes("Delete"));
      expect(cancelBtn).toBeTruthy();
      expect(deleteBtn).toBeTruthy();
    });

    it("calls onCancel when Cancel is clicked", () => {
      render(() => <ConfirmDeleteSeedModal {...defaultProps} />);
      const buttons = Array.from(document.querySelectorAll("button"));
      const cancelBtn = buttons.find((b) => b.textContent?.includes("Cancel"));
      fireEvent.click(cancelBtn!);
      expect(defaultProps.onCancel).toHaveBeenCalled();
    });
  });

  describe("re-auth flow", () => {
    it("opens ReAuthPrompt when Delete is clicked", async () => {
      render(() => <ConfirmDeleteSeedModal {...defaultProps} />);
      const deleteBtn = document.querySelector("[data-testid='confirm-delete-seed-btn']") as HTMLElement;
      fireEvent.click(deleteBtn);

      await waitFor(() => {
        expect(document.body.textContent).toContain("Verify Your Identity");
      });
    });

    it("calls deleteSeedPhrase after re-auth and shows success toast", async () => {
      render(() => <ConfirmDeleteSeedModal {...defaultProps} />);

      // Click Delete to open ReAuth
      const deleteBtn = document.querySelector("[data-testid='confirm-delete-seed-btn']") as HTMLElement;
      fireEvent.click(deleteBtn);

      await waitFor(() => {
        expect(document.body.textContent).toContain("Verify Your Identity");
      });

      // Type password and submit
      const passwordInput = document.querySelector("input[type='password']") as HTMLInputElement;
      if (passwordInput) {
        fireEvent.input(passwordInput, { target: { value: "correct-password" } });
        const form = document.querySelector("form");
        if (form) {
          fireEvent.submit(form);

          await waitFor(
            () => {
              expect(mockDeleteSeedPhrase).toHaveBeenCalledWith("seed-123", "correct-password");
              expect(mockToast.success).toHaveBeenCalledWith("Bitcoin Wallet deleted");
              expect(defaultProps.onDeleted).toHaveBeenCalled();
            },
            { timeout: 5000 },
          );
        }
      }
    });

    it("shows error toast when deletion fails", async () => {
      mockDeleteSeedPhrase.mockRejectedValue("Incorrect password. Seed phrase not deleted.");

      render(() => <ConfirmDeleteSeedModal {...defaultProps} />);

      const deleteBtn = document.querySelector("[data-testid='confirm-delete-seed-btn']") as HTMLElement;
      fireEvent.click(deleteBtn);

      await waitFor(() => {
        expect(document.body.textContent).toContain("Verify Your Identity");
      });

      const passwordInput = document.querySelector("input[type='password']") as HTMLInputElement;
      if (passwordInput) {
        fireEvent.input(passwordInput, { target: { value: "wrong-password" } });
        const form = document.querySelector("form");
        if (form) {
          fireEvent.submit(form);

          await waitFor(
            () => {
              expect(mockToast.error).toHaveBeenCalledWith("Incorrect password. Seed phrase not deleted.");
            },
            { timeout: 5000 },
          );
        }
      }
    });
  });
});
