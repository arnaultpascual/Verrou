import { render } from "@solidjs/testing-library";
import { describe, expect, it } from "vitest";
import { PaperBackupDocument } from "../../../features/export/PaperBackupDocument";
import type { PaperBackupData } from "../../../features/export/paperBackupIpc";

const MOCK_DATA: PaperBackupData = {
  seeds: [
    {
      name: "Bitcoin Wallet",
      issuer: undefined,
      words: [
        "abandon", "ability", "able", "about", "above", "absent",
        "absorb", "abstract", "absurd", "abuse", "access", "accident",
        "account", "accuse", "achieve", "acid", "acoustic", "acquire",
        "across", "act", "action", "actor", "actress", "zoo",
      ],
      wordCount: 24,
      hasPassphrase: true,
    },
    {
      name: "Ethereum Wallet",
      issuer: "eth.org",
      words: [
        "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
        "abandon", "abandon", "abandon", "abandon", "abandon", "about",
      ],
      wordCount: 12,
      hasPassphrase: false,
    },
  ],
  recoveryCodes: [
    {
      name: "Google Account",
      issuer: "google.com",
      codes: ["ABCD-1234", "EFGH-5678", "IJKL-9012", "MNOP-3456"],
      used: [0, 2],
      totalCodes: 4,
      remainingCodes: 2,
    },
  ],
  generatedAt: "2026-02-15T14:30:00Z",
  vaultFingerprint: "a1b2c3d4e5f6a7b8",
  contentChecksum: "e3b0c44298fc1c149afbf4c8996fb924",
};

describe("PaperBackupDocument", () => {
  it("renders the document with header", () => {
    render(() => <PaperBackupDocument data={MOCK_DATA} />);

    expect(document.body.textContent).toContain("VERROU Paper Backup");
    expect(document.body.textContent).toContain("CONFIDENTIAL");
    expect(document.body.textContent).toContain("2026-02-15T14:30:00Z");
    expect(document.body.textContent).toContain("a1b2c3d4e5f6a7b8");
  });

  it("renders seed phrases section with all words", () => {
    render(() => <PaperBackupDocument data={MOCK_DATA} />);

    expect(document.querySelector("[data-testid='seeds-section']")).toBeTruthy();
    expect(document.body.textContent).toContain("Seed Phrases");
    expect(document.body.textContent).toContain("Bitcoin Wallet");
    expect(document.body.textContent).toContain("Ethereum Wallet");
    // Check individual words
    expect(document.body.textContent).toContain("abandon");
    expect(document.body.textContent).toContain("zoo");
  });

  it("shows issuer when available", () => {
    render(() => <PaperBackupDocument data={MOCK_DATA} />);

    expect(document.body.textContent).toContain("(eth.org)");
  });

  it("shows passphrase warning for protected seeds", () => {
    render(() => <PaperBackupDocument data={MOCK_DATA} />);

    expect(document.body.textContent).toContain(
      "Passphrase protected (25th word not included",
    );
  });

  it("renders recovery codes section with used/unused status", () => {
    render(() => <PaperBackupDocument data={MOCK_DATA} />);

    expect(
      document.querySelector("[data-testid='recovery-section']"),
    ).toBeTruthy();
    expect(document.body.textContent).toContain("Recovery Codes");
    expect(document.body.textContent).toContain("Google Account");
    expect(document.body.textContent).toContain("(google.com)");
    expect(document.body.textContent).toContain("ABCD-1234");
    expect(document.body.textContent).toContain("EFGH-5678");
    expect(document.body.textContent).toContain("2 of 4 remaining");
  });

  it("renders footer with checksum and warning", () => {
    render(() => <PaperBackupDocument data={MOCK_DATA} />);

    expect(document.body.textContent).toContain("Content Checksum (BLAKE3):");
    expect(document.body.textContent).toContain(
      "e3b0c44298fc1c149afbf4c8996fb924",
    );
    expect(document.body.textContent).toContain(
      "Store this document in a secure physical location",
    );
  });

  it("shows empty state when no entries", () => {
    const emptyData: PaperBackupData = {
      ...MOCK_DATA,
      seeds: [],
      recoveryCodes: [],
    };
    render(() => <PaperBackupDocument data={emptyData} />);

    expect(document.body.textContent).toContain(
      "No seed phrases or recovery codes found",
    );
    expect(
      document.querySelector("[data-testid='seeds-section']"),
    ).toBeNull();
    expect(
      document.querySelector("[data-testid='recovery-section']"),
    ).toBeNull();
  });

  it("displays word numbers in the grid", () => {
    render(() => <PaperBackupDocument data={MOCK_DATA} />);

    // First seed has 24 words — check first and last numbers
    expect(document.body.textContent).toContain("1.");
    expect(document.body.textContent).toContain("24.");
  });
});
