import { render } from "@solidjs/testing-library";
import { describe, expect, it, afterEach } from "vitest";
import { SeedViewer } from "../../features/seed/SeedViewer";
import type { SeedDisplay } from "../../features/seed/ipc";

/**
 * Security — seed phrase DOM leakage.
 *
 * SeedViewer is presentational; the auto-hide countdown and clearing now live in
 * `useReveal` (see useReveal.test.ts for the timeout / clear-on-lock / cleanup
 * guarantees). This file pins the remaining SeedViewer guarantee: the real BIP39
 * words must appear in the DOM ONLY when `revealedData` is set, and must be fully
 * gone (replaced by masked dots) the moment it is `null`.
 */

afterEach(() => {
  // no-op — kept for symmetry with other security suites
});

const TEST_SEED: SeedDisplay = {
  words: [
    "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
    "abandon", "abandon", "abandon", "abandon", "abandon", "about",
  ],
  wordCount: 12,
  hasPassphrase: false,
};

describe("SeedViewer security — DOM leakage", () => {
  it("words are present in DOM when revealed", () => {
    render(() => (
      <SeedViewer
        wordCount={12}
        hasPassphrase={false}
        revealedData={TEST_SEED}
        onRevealRequest={() => {}}
        onCopyAll={() => {}}
        onHide={() => {}}
      />
    ));

    const grid = document.querySelector("[data-testid='seed-revealed-grid']");
    expect(grid).toBeTruthy();
    expect(grid!.textContent).toContain("abandon");
    expect(grid!.textContent).toContain("about");
  });

  it("words are absent from DOM when masked (null)", () => {
    const { unmount } = render(() => (
      <SeedViewer
        wordCount={12}
        hasPassphrase={false}
        revealedData={null}
        onRevealRequest={() => {}}
        onCopyAll={() => {}}
        onHide={() => {}}
      />
    ));

    expect(document.querySelector("[data-testid='seed-revealed-grid']")).toBeNull();
    expect(document.body.textContent).not.toContain("abandon");
    expect(document.body.textContent).not.toContain("about");

    unmount();
  });

  it("masked state shows dots, not actual words", () => {
    render(() => (
      <SeedViewer
        wordCount={12}
        hasPassphrase={false}
        revealedData={null}
        onRevealRequest={() => {}}
        onCopyAll={() => {}}
        onHide={() => {}}
      />
    ));

    expect(document.body.textContent).toContain("●●●●●");
    expect(document.body.textContent).not.toContain("abandon");
  });

  it("words are removed from the DOM after the viewer unmounts", () => {
    const { unmount } = render(() => (
      <SeedViewer
        wordCount={12}
        hasPassphrase={false}
        revealedData={TEST_SEED}
        onRevealRequest={() => {}}
        onCopyAll={() => {}}
        onHide={() => {}}
      />
    ));

    expect(document.body.textContent).toContain("abandon");
    unmount();
    expect(document.body.textContent).not.toContain("abandon");
  });
});
