import { render, fireEvent } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { SeedViewer } from "../../../features/seed/SeedViewer";
import type { SeedDisplay } from "../../../features/seed/ipc";

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
  ...TEST_SEED,
  hasPassphrase: true,
};

/**
 * SeedViewer is now purely presentational — the reveal lifecycle (countdown,
 * clipboard, vault-lock clearing, cleanup) lives in the parent via `useReveal` /
 * `useRevealCopy` / `AutoHideCountdown`. These tests cover only the rendering and
 * the callback wiring.
 */
describe("SeedViewer", () => {
  describe("masked state", () => {
    it("renders masked grid with correct word count", () => {
      render(() => (
        <SeedViewer
          wordCount={12}
          hasPassphrase={false}
          revealedData={null}
          onRevealRequest={vi.fn()}
          onCopyAll={vi.fn()}
          onHide={vi.fn()}
        />
      ));

      const grid = document.querySelector("[data-testid='seed-masked-grid']");
      expect(grid).toBeTruthy();
      expect(grid!.children.length).toBe(12);
    });

    it("renders 24-word masked grid", () => {
      render(() => (
        <SeedViewer
          wordCount={24}
          hasPassphrase={false}
          revealedData={null}
          onRevealRequest={vi.fn()}
          onCopyAll={vi.fn()}
          onHide={vi.fn()}
        />
      ));

      const grid = document.querySelector("[data-testid='seed-masked-grid']");
      expect(grid!.children.length).toBe(24);
    });

    it("shows masked dots for each word and no real words", () => {
      render(() => (
        <SeedViewer
          wordCount={12}
          hasPassphrase={false}
          revealedData={null}
          onRevealRequest={vi.fn()}
          onCopyAll={vi.fn()}
          onHide={vi.fn()}
        />
      ));

      expect(document.body.textContent).toContain("●●●●●");
      expect(document.body.textContent).not.toContain("abandon");
      expect(document.body.textContent).not.toContain("about");
    });

    it("shows Reveal button and fires onRevealRequest", () => {
      const onRevealRequest = vi.fn();
      render(() => (
        <SeedViewer
          wordCount={12}
          hasPassphrase={false}
          revealedData={null}
          onRevealRequest={onRevealRequest}
          onCopyAll={vi.fn()}
          onHide={vi.fn()}
        />
      ));

      const revealBtn = document.querySelector("[data-testid='reveal-btn']");
      expect(revealBtn).toBeTruthy();
      fireEvent.click(revealBtn!);
      expect(onRevealRequest).toHaveBeenCalledTimes(1);
    });

    it("does not render the injected countdown while masked", () => {
      render(() => (
        <SeedViewer
          wordCount={12}
          hasPassphrase={false}
          revealedData={null}
          onRevealRequest={vi.fn()}
          onCopyAll={vi.fn()}
          onHide={vi.fn()}
          countdown={<div data-testid="injected-countdown">timer</div>}
        />
      ));

      expect(document.querySelector("[data-testid='injected-countdown']")).toBeNull();
    });
  });

  describe("revealed state", () => {
    it("shows revealed word grid with all words", () => {
      render(() => (
        <SeedViewer
          wordCount={12}
          hasPassphrase={false}
          revealedData={TEST_SEED}
          onRevealRequest={vi.fn()}
          onCopyAll={vi.fn()}
          onHide={vi.fn()}
        />
      ));

      const grid = document.querySelector("[data-testid='seed-revealed-grid']");
      expect(grid).toBeTruthy();
      expect(grid!.textContent).toContain("abandon");
      expect(grid!.textContent).toContain("about");
    });

    it("renders the injected countdown slot while revealed", () => {
      render(() => (
        <SeedViewer
          wordCount={12}
          hasPassphrase={false}
          revealedData={TEST_SEED}
          onRevealRequest={vi.fn()}
          onCopyAll={vi.fn()}
          onHide={vi.fn()}
          countdown={<div data-testid="injected-countdown">timer</div>}
        />
      ));

      expect(document.querySelector("[data-testid='injected-countdown']")).toBeTruthy();
    });

    it("shows Copy All and Hide buttons", () => {
      render(() => (
        <SeedViewer
          wordCount={12}
          hasPassphrase={false}
          revealedData={TEST_SEED}
          onRevealRequest={vi.fn()}
          onCopyAll={vi.fn()}
          onHide={vi.fn()}
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
          onCopyAll={vi.fn()}
          onHide={vi.fn()}
        />
      ));

      expect(document.querySelector("[data-testid='reveal-btn']")).toBeNull();
    });

    it("fires onCopyAll when Copy All is clicked", () => {
      const onCopyAll = vi.fn();
      render(() => (
        <SeedViewer
          wordCount={12}
          hasPassphrase={false}
          revealedData={TEST_SEED}
          onRevealRequest={vi.fn()}
          onCopyAll={onCopyAll}
          onHide={vi.fn()}
        />
      ));

      fireEvent.click(document.querySelector("[data-testid='copy-all-btn']")!);
      expect(onCopyAll).toHaveBeenCalledTimes(1);
    });

    it("fires onHide when Hide is clicked", () => {
      const onHide = vi.fn();
      render(() => (
        <SeedViewer
          wordCount={12}
          hasPassphrase={false}
          revealedData={TEST_SEED}
          onRevealRequest={vi.fn()}
          onCopyAll={vi.fn()}
          onHide={onHide}
        />
      ));

      fireEvent.click(document.querySelector("[data-testid='hide-btn']")!);
      expect(onHide).toHaveBeenCalledTimes(1);
    });

    it("shows passphrase indicator only when hasPassphrase is true", () => {
      const { unmount } = render(() => (
        <SeedViewer
          wordCount={12}
          hasPassphrase={true}
          revealedData={TEST_SEED_WITH_PASSPHRASE}
          onRevealRequest={vi.fn()}
          onCopyAll={vi.fn()}
          onHide={vi.fn()}
        />
      ));
      expect(document.body.textContent).toContain("BIP39 passphrase is set");
      unmount();

      render(() => (
        <SeedViewer
          wordCount={12}
          hasPassphrase={false}
          revealedData={TEST_SEED}
          onRevealRequest={vi.fn()}
          onCopyAll={vi.fn()}
          onHide={vi.fn()}
        />
      ));
      expect(document.body.textContent).not.toContain("BIP39 passphrase is set");
    });
  });
});
