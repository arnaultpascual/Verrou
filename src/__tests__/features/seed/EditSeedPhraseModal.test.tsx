import { render, fireEvent, waitFor } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { EditSeedPhraseModal } from "../../../features/seed/EditSeedPhraseModal";

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

// Mock getEntry and updateEntry
const mockGetEntry = vi.fn();
const mockUpdateEntry = vi.fn();

vi.mock("../../../features/entries/ipc", () => ({
  getEntry: (...args: unknown[]) => mockGetEntry(...args),
  updateEntry: (...args: unknown[]) => mockUpdateEntry(...args),
  copyToClipboard: vi.fn().mockResolvedValue(undefined),
}));

const MOCK_SEED_ENTRY = {
  id: "seed-123",
  entryType: "seed_phrase",
  name: "Bitcoin Wallet",
  issuer: "ledger.com",
  algorithm: "SHA1",
  digits: 6,
  period: 30,
  counter: 0,
  pinned: false,
  createdAt: "2026-02-05T10:00:00Z",
  updatedAt: "2026-02-05T10:00:00Z",
  secret: "abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress actual",
};

const defaultProps = {
  open: true,
  entryId: "seed-123",
  onClose: vi.fn(),
  onSuccess: vi.fn(),
};

/** Find an input element by its associated label text */
function findInputByLabel(labelText: string): HTMLInputElement | null {
  const labels = Array.from(document.querySelectorAll("label"));
  const label = labels.find((l) => l.textContent?.includes(labelText));
  if (!label) return null;
  const forAttr = label.getAttribute("for");
  if (forAttr) return document.getElementById(forAttr) as HTMLInputElement;
  return label.querySelector("input");
}

beforeEach(() => {
  vi.clearAllMocks();
  mockGetEntry.mockResolvedValue({ ...MOCK_SEED_ENTRY });
  mockUpdateEntry.mockResolvedValue({
    id: "seed-123",
    entryType: "seed_phrase",
    name: "Bitcoin Wallet",
    issuer: "ledger.com",
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    pinned: false,
    createdAt: "2026-02-05T10:00:00Z",
    updatedAt: "2026-02-05T10:00:00Z",
  });
});

describe("EditSeedPhraseModal", () => {
  describe("metadata display", () => {
    it("renders modal title", async () => {
      render(() => <EditSeedPhraseModal {...defaultProps} />);
      await waitFor(() => {
        expect(document.body.textContent).toContain("Edit Seed Phrase");
      });
    });

    it("pre-populates wallet name from entry", async () => {
      render(() => <EditSeedPhraseModal {...defaultProps} />);
      await waitFor(() => {
        const nameInput = findInputByLabel("Wallet Name");
        expect(nameInput).toBeTruthy();
        expect(nameInput!.value).toBe("Bitcoin Wallet");
      });
    });

    it("pre-populates issuer from entry", async () => {
      render(() => <EditSeedPhraseModal {...defaultProps} />);
      await waitFor(() => {
        const issuerInput = findInputByLabel("Issuer / Network");
        expect(issuerInput).toBeTruthy();
        expect(issuerInput!.value).toBe("ledger.com");
      });
    });

    it("displays read-only word count", async () => {
      render(() => <EditSeedPhraseModal {...defaultProps} />);
      await waitFor(() => {
        const wordCountEl = document.querySelector("[data-testid='edit-seed-word-count']");
        expect(wordCountEl).toBeTruthy();
        expect(wordCountEl!.textContent).toContain("24 words");
      });
    });

    it("shows info banner about immutable seed words", async () => {
      render(() => <EditSeedPhraseModal {...defaultProps} />);
      await waitFor(() => {
        const banner = document.querySelector("[data-testid='edit-seed-info-banner']");
        expect(banner).toBeTruthy();
        expect(banner!.textContent).toContain("To change the seed phrase words, delete this entry and add a new one.");
      });
    });
  });

  describe("form validation", () => {
    it("shows error when wallet name is empty", async () => {
      render(() => <EditSeedPhraseModal {...defaultProps} />);

      await waitFor(() => {
        expect(findInputByLabel("Wallet Name")).toBeTruthy();
      });

      const nameInput = findInputByLabel("Wallet Name")!;
      fireEvent.input(nameInput, { target: { value: "" } });

      const saveBtn = document.querySelector("[data-testid='edit-seed-save-btn']") as HTMLElement;
      fireEvent.click(saveBtn);

      await waitFor(() => {
        expect(document.body.textContent).toContain("Wallet name is required.");
      });
    });

    it("shows error when wallet name exceeds 100 chars", async () => {
      render(() => <EditSeedPhraseModal {...defaultProps} />);

      await waitFor(() => {
        expect(findInputByLabel("Wallet Name")).toBeTruthy();
      });

      const nameInput = findInputByLabel("Wallet Name")!;
      fireEvent.input(nameInput, { target: { value: "a".repeat(101) } });

      const saveBtn = document.querySelector("[data-testid='edit-seed-save-btn']") as HTMLElement;
      fireEvent.click(saveBtn);

      await waitFor(() => {
        expect(document.body.textContent).toContain("Wallet name too long");
      });
    });
  });

  describe("save flow", () => {
    it("calls updateEntry and shows success toast on save", async () => {
      render(() => <EditSeedPhraseModal {...defaultProps} />);

      await waitFor(() => {
        expect(findInputByLabel("Wallet Name")).toBeTruthy();
      });

      const nameInput = findInputByLabel("Wallet Name")!;
      fireEvent.input(nameInput, { target: { value: "Ethereum Wallet" } });

      const saveBtn = document.querySelector("[data-testid='edit-seed-save-btn']") as HTMLElement;
      fireEvent.click(saveBtn);

      await waitFor(() => {
        expect(mockUpdateEntry).toHaveBeenCalledWith(
          expect.objectContaining({
            id: "seed-123",
            name: "Ethereum Wallet",
          }),
        );
        expect(mockToast.success).toHaveBeenCalledWith("Ethereum Wallet saved");
        expect(defaultProps.onSuccess).toHaveBeenCalled();
        expect(defaultProps.onClose).toHaveBeenCalled();
      });
    });

    it("shows error toast when updateEntry fails", async () => {
      mockUpdateEntry.mockRejectedValue("Database error");

      render(() => <EditSeedPhraseModal {...defaultProps} />);

      await waitFor(() => {
        expect(document.querySelector("[data-testid='edit-seed-save-btn']")).toBeTruthy();
      });

      const saveBtn = document.querySelector("[data-testid='edit-seed-save-btn']") as HTMLElement;
      fireEvent.click(saveBtn);

      await waitFor(() => {
        expect(mockToast.error).toHaveBeenCalledWith("Database error");
      });
    });
  });

  describe("passphrase editing", () => {
    it("shows passphrase checkbox toggle", async () => {
      render(() => <EditSeedPhraseModal {...defaultProps} />);

      await waitFor(() => {
        const toggle = document.querySelector("[data-testid='edit-seed-passphrase-toggle']");
        expect(toggle).toBeTruthy();
      });
    });

    it("shows passphrase input when checkbox is checked", async () => {
      render(() => <EditSeedPhraseModal {...defaultProps} />);

      await waitFor(() => {
        expect(document.querySelector("[data-testid='edit-seed-passphrase-toggle']")).toBeTruthy();
      });

      const toggle = document.querySelector("[data-testid='edit-seed-passphrase-toggle']") as HTMLInputElement;
      fireEvent.click(toggle);

      await waitFor(() => {
        const passwordInput = document.querySelector("input[type='password']");
        expect(passwordInput).toBeTruthy();
      });
    });

    it("includes passphrase in update when set", async () => {
      render(() => <EditSeedPhraseModal {...defaultProps} />);

      await waitFor(() => {
        expect(document.querySelector("[data-testid='edit-seed-passphrase-toggle']")).toBeTruthy();
      });

      // Enable passphrase
      const toggle = document.querySelector("[data-testid='edit-seed-passphrase-toggle']") as HTMLInputElement;
      fireEvent.click(toggle);

      await waitFor(() => {
        expect(document.querySelector("input[type='password']")).toBeTruthy();
      });

      // Type passphrase
      const passphraseInput = document.querySelector("input[type='password']") as HTMLInputElement;
      fireEvent.input(passphraseInput, { target: { value: "my-secret-passphrase" } });

      // Save
      const saveBtn = document.querySelector("[data-testid='edit-seed-save-btn']") as HTMLElement;
      fireEvent.click(saveBtn);

      await waitFor(() => {
        expect(mockUpdateEntry).toHaveBeenCalledWith(
          expect.objectContaining({
            passphrase: "my-secret-passphrase",
          }),
        );
      });
    });
  });

  describe("delete button", () => {
    it("shows delete button when onDelete is provided", async () => {
      const onDelete = vi.fn();
      render(() => <EditSeedPhraseModal {...defaultProps} onDelete={onDelete} />);

      await waitFor(() => {
        const deleteBtn = document.querySelector("[data-testid='edit-seed-delete-btn']");
        expect(deleteBtn).toBeTruthy();
      });
    });

    it("calls onDelete when delete button is clicked", async () => {
      const onDelete = vi.fn();
      render(() => <EditSeedPhraseModal {...defaultProps} onDelete={onDelete} />);

      await waitFor(() => {
        expect(document.querySelector("[data-testid='edit-seed-delete-btn']")).toBeTruthy();
      });

      const deleteBtn = document.querySelector("[data-testid='edit-seed-delete-btn']") as HTMLElement;
      fireEvent.click(deleteBtn);

      expect(onDelete).toHaveBeenCalledWith("seed-123", "Bitcoin Wallet");
    });

    it("hides delete button when onDelete is not provided", async () => {
      render(() => <EditSeedPhraseModal {...defaultProps} />);

      await waitFor(() => {
        expect(document.querySelector("[data-testid='edit-seed-save-btn']")).toBeTruthy();
      });

      const deleteBtn = document.querySelector("[data-testid='edit-seed-delete-btn']");
      expect(deleteBtn).toBeNull();
    });
  });
});
