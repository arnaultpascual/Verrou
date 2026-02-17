import { render, waitFor } from "@solidjs/testing-library";
import { describe, expect, it, vi, afterEach } from "vitest";
import { SeedViewer } from "../../features/seed/SeedViewer";
import type { SeedDisplay } from "../../features/seed/ipc";

// Mock useToast
vi.mock("../../components/useToast", () => ({
  useToast: () => ({
    success: vi.fn(),
    error: vi.fn(),
    info: vi.fn(),
    dismiss: vi.fn(),
    clear: vi.fn(),
  }),
}));

// Mock copyToClipboard
vi.mock("../../features/entries/ipc", () => ({
  copyToClipboard: vi.fn().mockResolvedValue(undefined),
}));

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

describe("SeedViewer security — auto-clear", () => {
  it("words are present in DOM when revealed", () => {
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
    expect(grid!.textContent).toContain("abandon");
    expect(grid!.textContent).toContain("about");
  });

  it("words are removed from DOM when data is cleared (null)", () => {
    const { unmount } = render(() => (
      <SeedViewer
        wordCount={12}
        hasPassphrase={false}
        revealedData={null}
        onRevealRequest={vi.fn()}
        onClear={vi.fn()}
      />
    ));

    // In masked state, actual words should NOT appear in the DOM
    const grid = document.querySelector("[data-testid='seed-revealed-grid']");
    expect(grid).toBeNull();
    expect(document.body.textContent).not.toContain("abandon");
    expect(document.body.textContent).not.toContain("about");

    unmount();
  });

  it("calls onClear when timer expires (60s timeout)", async () => {
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

    // Words should be visible initially
    expect(document.body.textContent).toContain("abandon");

    // Advance time to 60 seconds
    vi.advanceTimersByTime(60_000);

    await waitFor(() => {
      expect(onClear).toHaveBeenCalledTimes(1);
    });

    vi.useRealTimers();
  });

  it("does not call onClear before timeout", () => {
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

    // Advance to 59 seconds (1 second before timeout)
    vi.advanceTimersByTime(59_000);
    expect(onClear).not.toHaveBeenCalled();

    vi.useRealTimers();
  });

  it("calls onClear on unmount when data is revealed", () => {
    const onClear = vi.fn();

    const { unmount } = render(() => (
      <SeedViewer
        wordCount={12}
        hasPassphrase={false}
        revealedData={TEST_SEED}
        onRevealRequest={vi.fn()}
        onClear={onClear}
      />
    ));

    // Unmount should trigger cleanup that calls onClear
    unmount();
    expect(onClear).toHaveBeenCalled();
  });

  it("does not call onClear on unmount when data is masked", () => {
    const onClear = vi.fn();

    const { unmount } = render(() => (
      <SeedViewer
        wordCount={12}
        hasPassphrase={false}
        revealedData={null}
        onRevealRequest={vi.fn()}
        onClear={onClear}
      />
    ));

    unmount();
    // onClear should NOT be called since data was already masked
    expect(onClear).not.toHaveBeenCalled();
  });

  it("clears interval on unmount to prevent memory leaks", () => {
    vi.useFakeTimers();
    const clearIntervalSpy = vi.spyOn(globalThis, "clearInterval");
    const onClear = vi.fn();

    const { unmount } = render(() => (
      <SeedViewer
        wordCount={12}
        hasPassphrase={false}
        revealedData={TEST_SEED}
        onRevealRequest={vi.fn()}
        onClear={onClear}
      />
    ));

    unmount();
    expect(clearIntervalSpy).toHaveBeenCalled();

    vi.useRealTimers();
  });

  it("masked state shows dots, not actual words", () => {
    render(() => (
      <SeedViewer
        wordCount={12}
        hasPassphrase={false}
        revealedData={null}
        onRevealRequest={vi.fn()}
        onClear={vi.fn()}
      />
    ));

    // Should show masked dots
    expect(document.body.textContent).toContain("\u25CF\u25CF\u25CF\u25CF\u25CF");
    // Should NOT show any actual words
    expect(document.body.textContent).not.toContain("abandon");
  });
});
