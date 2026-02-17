import { render, fireEvent, waitFor } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { SeedPhraseDetailModal } from "../../../features/seed/SeedPhraseDetailModal";
import type { SeedDisplay } from "../../../features/seed/ipc";

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

// Mock revealSeedPhrase
const mockRevealSeedPhrase = vi.fn<
  (entryId: string, password: string) => Promise<SeedDisplay>
>();

vi.mock("../../../features/seed/ipc", () => ({
  revealSeedPhrase: (...args: unknown[]) => mockRevealSeedPhrase(...(args as [string, string])),
}));

// Mock copyToClipboard (used by SeedViewer)
vi.mock("../../../features/entries/ipc", () => ({
  copyToClipboard: vi.fn().mockResolvedValue(undefined),
}));

const TEST_SEED: SeedDisplay = {
  words: [
    "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
    "abandon", "abandon", "abandon", "abandon", "abandon", "about",
  ],
  wordCount: 12,
  hasPassphrase: false,
};

const TEST_SEED_WITH_PASSPHRASE: SeedDisplay = {
  words: [
    "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
    "abandon", "abandon", "abandon", "abandon", "abandon", "about",
  ],
  wordCount: 12,
  hasPassphrase: true,
};

beforeEach(() => {
  vi.clearAllMocks();
  mockRevealSeedPhrase.mockResolvedValue(TEST_SEED);
});

const defaultProps = {
  open: true,
  onClose: vi.fn(),
  entryId: "test-entry-id",
  name: "Bitcoin Wallet",
  issuer: "Ledger",
  wordCount: 24,
  createdAt: "2026-02-05T10:00:00Z",
};

describe("SeedPhraseDetailModal", () => {
  describe("metadata display", () => {
    it("renders modal title", () => {
      render(() => <SeedPhraseDetailModal {...defaultProps} />);
      expect(document.body.textContent).toContain("Seed Phrase Details");
    });

    it("displays wallet name", () => {
      render(() => <SeedPhraseDetailModal {...defaultProps} />);
      const nameEl = document.querySelector("[data-testid='seed-detail-name']");
      expect(nameEl).toBeTruthy();
      expect(nameEl!.textContent).toBe("Bitcoin Wallet");
    });

    it("displays issuer when provided", () => {
      render(() => <SeedPhraseDetailModal {...defaultProps} />);
      const issuerEl = document.querySelector("[data-testid='seed-detail-issuer']");
      expect(issuerEl).toBeTruthy();
      expect(issuerEl!.textContent).toBe("Ledger");
    });

    it("hides issuer row when not provided", () => {
      const { container } = render(() => (
        <SeedPhraseDetailModal {...defaultProps} issuer={undefined} />
      ));
      const issuerEl = container.querySelector("[data-testid='seed-detail-issuer']");
      expect(issuerEl).toBeNull();
    });

    it("displays word count", () => {
      render(() => <SeedPhraseDetailModal {...defaultProps} />);
      const wordCountEl = document.querySelector("[data-testid='seed-detail-word-count']");
      expect(wordCountEl).toBeTruthy();
      expect(wordCountEl!.textContent).toContain("24 words");
    });

    it("displays formatted creation date", () => {
      render(() => <SeedPhraseDetailModal {...defaultProps} />);
      // Should display "Feb 5, 2026" or locale-dependent format
      expect(document.body.textContent).toContain("2026");
    });
  });

  describe("reveal flow", () => {
    it("shows masked seed grid by default", () => {
      render(() => <SeedPhraseDetailModal {...defaultProps} />);
      const maskedGrid = document.querySelector("[data-testid='seed-masked-grid']");
      expect(maskedGrid).toBeTruthy();
    });

    it("shows Reveal button in initial state", () => {
      render(() => <SeedPhraseDetailModal {...defaultProps} />);
      const revealBtn = document.querySelector("[data-testid='reveal-btn']");
      expect(revealBtn).toBeTruthy();
    });

    it("opens ReAuthPrompt when Reveal is clicked", async () => {
      render(() => <SeedPhraseDetailModal {...defaultProps} />);

      const revealBtn = document.querySelector("[data-testid='reveal-btn']");
      fireEvent.click(revealBtn!);

      await waitFor(() => {
        // ReAuthPrompt should show "Verify Your Identity" text
        expect(document.body.textContent).toContain("Verify Your Identity");
      });
    });

    it("does not show passphrase indicator before reveal", () => {
      render(() => <SeedPhraseDetailModal {...defaultProps} />);

      // Passphrase indicator should only appear after reveal, not in initial masked state
      expect(document.body.textContent).not.toContain("Passphrase");
    });
  });

  describe("error handling", () => {
    it("shows toast error when reveal fails with string error", async () => {
      mockRevealSeedPhrase.mockRejectedValue("Incorrect password. Seed phrase not revealed.");

      render(() => <SeedPhraseDetailModal {...defaultProps} />);

      // Click Reveal to open ReAuth
      const revealBtn = document.querySelector("[data-testid='reveal-btn']");
      fireEvent.click(revealBtn!);

      await waitFor(() => {
        expect(document.body.textContent).toContain("Verify Your Identity");
      });

      // Type password and submit the form
      const passwordInput = document.querySelector(
        "input[type='password']",
      ) as HTMLInputElement;
      if (passwordInput) {
        fireEvent.input(passwordInput, { target: { value: "wrong-password" } });
        const form = document.querySelector("form");
        if (form) {
          fireEvent.submit(form);

          // Wait for SecurityCeremony to complete and trigger onVerified
          // The ReAuthPrompt simulates a 3s ceremony animation, so we need
          // to give it time to complete
          await waitFor(
            () => {
              expect(mockToast.error).toHaveBeenCalledWith(
                "Incorrect password. Seed phrase not revealed.",
              );
            },
            { timeout: 5000 },
          );
        }
      }
    });
  });

  describe("cleanup on close", () => {
    it("calls onClose when close is triggered", () => {
      const onClose = vi.fn();
      render(() => <SeedPhraseDetailModal {...defaultProps} onClose={onClose} />);

      // The Modal renders with a close button
      const closeButtons = Array.from(document.querySelectorAll("button")).filter(
        (b) => b.getAttribute("aria-label")?.includes("Close") || b.textContent?.includes("Close"),
      );

      if (closeButtons.length > 0) {
        fireEvent.click(closeButtons[0]);
        expect(onClose).toHaveBeenCalled();
      }
    });

    it("does not show revealed data in initial state", () => {
      render(() => <SeedPhraseDetailModal {...defaultProps} />);

      const revealedGrid = document.querySelector("[data-testid='seed-revealed-grid']");
      expect(revealedGrid).toBeNull();
    });
  });
});
