import { render, fireEvent, waitFor } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { SeedViewer } from "../../../features/seed/SeedViewer";
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

// Mock copyToClipboard
const mockCopyToClipboard = vi.fn().mockResolvedValue(undefined);
vi.mock("../../../features/entries/ipc", () => ({
  copyToClipboard: (...args: unknown[]) => mockCopyToClipboard(...args),
}));

beforeEach(() => {
  vi.clearAllMocks();
});

afterEach(() => {
  vi.restoreAllMocks();
});

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

describe("SeedViewer", () => {
  describe("masked state", () => {
    it("renders masked grid with correct word count", () => {
      render(() => (
        <SeedViewer
          wordCount={12}
          hasPassphrase={false}
          revealedData={null}
          onRevealRequest={vi.fn()}
          onClear={vi.fn()}
        />
      ));

      const grid = document.querySelector("[data-testid='seed-masked-grid']");
      expect(grid).toBeTruthy();
      const maskedWords = grid!.children;
      expect(maskedWords.length).toBe(12);
    });

    it("renders 24-word masked grid", () => {
      render(() => (
        <SeedViewer
          wordCount={24}
          hasPassphrase={false}
          revealedData={null}
          onRevealRequest={vi.fn()}
          onClear={vi.fn()}
        />
      ));

      const grid = document.querySelector("[data-testid='seed-masked-grid']");
      expect(grid!.children.length).toBe(24);
    });

    it("shows masked dots for each word", () => {
      render(() => (
        <SeedViewer
          wordCount={12}
          hasPassphrase={false}
          revealedData={null}
          onRevealRequest={vi.fn()}
          onClear={vi.fn()}
        />
      ));

      expect(document.body.textContent).toContain("\u25CF\u25CF\u25CF\u25CF\u25CF");
    });

    it("displays word numbers starting from 1", () => {
      render(() => (
        <SeedViewer
          wordCount={12}
          hasPassphrase={false}
          revealedData={null}
          onRevealRequest={vi.fn()}
          onClear={vi.fn()}
        />
      ));

      expect(document.body.textContent).toContain("1");
      expect(document.body.textContent).toContain("12");
    });

    it("shows Reveal button", () => {
      render(() => (
        <SeedViewer
          wordCount={12}
          hasPassphrase={false}
          revealedData={null}
          onRevealRequest={vi.fn()}
          onClear={vi.fn()}
        />
      ));

      expect(document.body.textContent).toContain("Reveal");
    });

    it("calls onRevealRequest when Reveal button is clicked", () => {
      const onRevealRequest = vi.fn();
      render(() => (
        <SeedViewer
          wordCount={12}
          hasPassphrase={false}
          revealedData={null}
          onRevealRequest={onRevealRequest}
          onClear={vi.fn()}
        />
      ));

      const revealBtn = document.querySelector("[data-testid='reveal-btn']");
      fireEvent.click(revealBtn!);
      expect(onRevealRequest).toHaveBeenCalledTimes(1);
    });

    it("does not show countdown timer in masked state", () => {
      render(() => (
        <SeedViewer
          wordCount={12}
          hasPassphrase={false}
          revealedData={null}
          onRevealRequest={vi.fn()}
          onClear={vi.fn()}
        />
      ));

      const timer = document.querySelector("[data-testid='countdown-timer']");
      expect(timer).toBeNull();
    });
  });

  describe("revealed state", () => {
    it("shows revealed word grid", () => {
      render(() => (
        <SeedViewer
          wordCount={12}
          hasPassphrase={false}
          revealedData={TEST_SEED}
          onRevealRequest={vi.fn()}
          onClear={vi.fn()}
        />
      ));

      const grid = document.querySelector("[data-testid='seed-revealed-grid']");
      expect(grid).toBeTruthy();
    });

    it("displays all 12 words", () => {
      render(() => (
        <SeedViewer
          wordCount={12}
          hasPassphrase={false}
          revealedData={TEST_SEED}
          onRevealRequest={vi.fn()}
          onClear={vi.fn()}
        />
      ));

      expect(document.body.textContent).toContain("abandon");
      expect(document.body.textContent).toContain("about");
    });

    it("shows countdown timer", () => {
      render(() => (
        <SeedViewer
          wordCount={12}
          hasPassphrase={false}
          revealedData={TEST_SEED}
          onRevealRequest={vi.fn()}
          onClear={vi.fn()}
        />
      ));

      const timer = document.querySelector("[data-testid='countdown-timer']");
      expect(timer).toBeTruthy();
      expect(timer!.textContent).toContain("Hiding in");
      expect(timer!.textContent).toContain("60s");
    });

    it("shows Copy All and Hide buttons", () => {
      render(() => (
        <SeedViewer
          wordCount={12}
          hasPassphrase={false}
          revealedData={TEST_SEED}
          onRevealRequest={vi.fn()}
          onClear={vi.fn()}
        />
      ));

      expect(document.body.textContent).toContain("Copy All");
      expect(document.body.textContent).toContain("Hide");
    });

    it("hides the Reveal button when data is shown", () => {
      render(() => (
        <SeedViewer
          wordCount={12}
          hasPassphrase={false}
          revealedData={TEST_SEED}
          onRevealRequest={vi.fn()}
          onClear={vi.fn()}
        />
      ));

      const revealBtn = document.querySelector("[data-testid='reveal-btn']");
      expect(revealBtn).toBeNull();
    });

    it("calls onClear when Hide button is clicked", () => {
      const onClear = vi.fn();
      render(() => (
        <SeedViewer
          wordCount={12}
          hasPassphrase={false}
          revealedData={TEST_SEED}
          onRevealRequest={vi.fn()}
          onClear={onClear}
        />
      ));

      const hideBtn = document.querySelector("[data-testid='hide-btn']");
      fireEvent.click(hideBtn!);
      expect(onClear).toHaveBeenCalledTimes(1);
    });

    it("copies seed phrase to clipboard on Copy All click", async () => {
      render(() => (
        <SeedViewer
          wordCount={12}
          hasPassphrase={false}
          revealedData={TEST_SEED}
          onRevealRequest={vi.fn()}
          onClear={vi.fn()}
        />
      ));

      const copyBtn = document.querySelector("[data-testid='copy-all-btn']");
      fireEvent.click(copyBtn!);

      await waitFor(() => {
        expect(mockCopyToClipboard).toHaveBeenCalledWith(TEST_SEED.words.join(" "));
        expect(mockToast.success).toHaveBeenCalledWith(
          "Seed phrase in clipboard \u2014 clears in 30s",
        );
      });
    });

    it("shows toast error when copy fails", async () => {
      mockCopyToClipboard.mockRejectedValueOnce(new Error("copy failed"));

      render(() => (
        <SeedViewer
          wordCount={12}
          hasPassphrase={false}
          revealedData={TEST_SEED}
          onRevealRequest={vi.fn()}
          onClear={vi.fn()}
        />
      ));

      const copyBtn = document.querySelector("[data-testid='copy-all-btn']");
      fireEvent.click(copyBtn!);

      await waitFor(() => {
        expect(mockToast.error).toHaveBeenCalledWith("Failed to copy seed phrase");
      });
    });

    it("shows passphrase indicator when hasPassphrase is true", () => {
      render(() => (
        <SeedViewer
          wordCount={12}
          hasPassphrase={true}
          revealedData={TEST_SEED_WITH_PASSPHRASE}
          onRevealRequest={vi.fn()}
          onClear={vi.fn()}
        />
      ));

      expect(document.body.textContent).toContain("BIP39 passphrase is set");
    });

    it("does not show passphrase indicator when hasPassphrase is false", () => {
      render(() => (
        <SeedViewer
          wordCount={12}
          hasPassphrase={false}
          revealedData={TEST_SEED}
          onRevealRequest={vi.fn()}
          onClear={vi.fn()}
        />
      ));

      expect(document.body.textContent).not.toContain("BIP39 passphrase is set");
    });
  });

  describe("countdown timer", () => {
    it("decrements timer every second", async () => {
      vi.useFakeTimers();

      render(() => (
        <SeedViewer
          wordCount={12}
          hasPassphrase={false}
          revealedData={TEST_SEED}
          onRevealRequest={vi.fn()}
          onClear={vi.fn()}
        />
      ));

      const timer = document.querySelector("[data-testid='countdown-timer']");
      expect(timer!.textContent).toContain("60s");

      vi.advanceTimersByTime(1000);
      await waitFor(() => {
        expect(timer!.textContent).toContain("59s");
      });

      vi.advanceTimersByTime(4000);
      await waitFor(() => {
        expect(timer!.textContent).toContain("55s");
      });

      vi.useRealTimers();
    });

    it("calls onClear when timer reaches zero", async () => {
      vi.useFakeTimers();
      const onClear = vi.fn();

      render(() => (
        <SeedViewer
          wordCount={12}
          hasPassphrase={false}
          revealedData={TEST_SEED}
          onRevealRequest={vi.fn()}
          onClear={onClear}
        />
      ));

      // Advance to just before expiry
      vi.advanceTimersByTime(59000);
      expect(onClear).not.toHaveBeenCalled();

      // Advance to expiry
      vi.advanceTimersByTime(1000);
      await waitFor(() => {
        expect(onClear).toHaveBeenCalledTimes(1);
      });

      vi.useRealTimers();
    });
  });
});
