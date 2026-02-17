import { render, fireEvent } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { PopupResultItem } from "../../../features/quick-access/PopupResultItem";
import type { EntryMetadataDto } from "../../../features/entries/ipc";

// Mock generateTotpCode via the useTotpCode dependency
vi.mock("../../../features/entries/ipc", async (importOriginal) => {
  const original = await importOriginal<Record<string, unknown>>();
  return {
    ...original,
    generateTotpCode: vi.fn().mockResolvedValue({
      code: "654321",
      remainingSeconds: 20,
    }),
  };
});

const TOTP_ENTRY: EntryMetadataDto = {
  id: "totp-1",
  entryType: "totp",
  name: "GitHub",
  issuer: "github.com",
  algorithm: "SHA1",
  digits: 6,
  period: 30,
  pinned: false,
  createdAt: "2026-01-01T00:00:00Z",
  updatedAt: "2026-01-01T00:00:00Z",
};

const SEED_ENTRY: EntryMetadataDto = {
  id: "seed-1",
  entryType: "seed_phrase",
  name: "Bitcoin Wallet",
  issuer: "ledger.com",
  algorithm: "SHA1",
  digits: 6,
  period: 30,
  pinned: false,
  createdAt: "2026-01-01T00:00:00Z",
  updatedAt: "2026-01-01T00:00:00Z",
};

describe("PopupResultItem", () => {
  const onSelect = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders entry name and issuer", () => {
    const { getByText } = render(() => (
      <PopupResultItem
        entry={TOTP_ENTRY}
        isSelected={false}
        index={0}
        onSelect={onSelect}
      />
    ));

    expect(getByText("GitHub")).toBeDefined();
    expect(getByText("github.com")).toBeDefined();
  });

  it("renders type badge", () => {
    const { getByText } = render(() => (
      <PopupResultItem
        entry={TOTP_ENTRY}
        isSelected={false}
        index={0}
        onSelect={onSelect}
      />
    ));

    expect(getByText("TOTP")).toBeDefined();
  });

  it("sets aria-selected when selected", () => {
    const { container } = render(() => (
      <PopupResultItem
        entry={TOTP_ENTRY}
        isSelected={true}
        index={0}
        onSelect={onSelect}
      />
    ));

    const option = container.querySelector("[role='option']");
    expect(option?.getAttribute("aria-selected")).toBe("true");
  });

  it("sets aria-selected false when not selected", () => {
    const { container } = render(() => (
      <PopupResultItem
        entry={TOTP_ENTRY}
        isSelected={false}
        index={0}
        onSelect={onSelect}
      />
    ));

    const option = container.querySelector("[role='option']");
    expect(option?.getAttribute("aria-selected")).toBe("false");
  });

  it("shows masked placeholder for non-TOTP entries", () => {
    const { container } = render(() => (
      <PopupResultItem
        entry={SEED_ENTRY}
        isSelected={false}
        index={0}
        onSelect={onSelect}
      />
    ));

    // Seed phrase entry should show masked dots, not a live code
    expect(container.textContent).toContain("\u00B7\u00B7\u00B7");
  });

  it("has correct id based on index", () => {
    const { container } = render(() => (
      <PopupResultItem
        entry={TOTP_ENTRY}
        isSelected={false}
        index={3}
        onSelect={onSelect}
      />
    ));

    const option = container.querySelector("#popup-result-3");
    expect(option).not.toBeNull();
  });

  it("has aria-label with entry info", () => {
    const { container } = render(() => (
      <PopupResultItem
        entry={TOTP_ENTRY}
        isSelected={false}
        index={0}
        onSelect={onSelect}
      />
    ));

    const option = container.querySelector("[role='option']");
    const label = option?.getAttribute("aria-label") ?? "";
    expect(label).toContain("GitHub");
    expect(label).toContain("totp");
  });

  describe("credential entry display", () => {
    const CREDENTIAL_ENTRY: EntryMetadataDto = {
      id: "cred-1",
      entryType: "credential",
      name: "GitHub Login",
      issuer: "github.com",
      username: "admin@github.com",
      algorithm: "SHA1",
      digits: 6,
      period: 30,
      pinned: false,
      createdAt: "2026-01-01T00:00:00Z",
      updatedAt: "2026-01-01T00:00:00Z",
    };

    it("shows key icon and masked dots for credential entries", () => {
      const { container } = render(() => (
        <PopupResultItem
          entry={CREDENTIAL_ENTRY}
          isSelected={false}
          index={0}
          onSelect={onSelect}
        />
      ));
      // Credential entries show bullet dots (not generic middle dots)
      expect(container.textContent).toContain("\u2022\u2022\u2022\u2022");
    });

    it("shows username for credential entries", () => {
      const { getByText } = render(() => (
        <PopupResultItem
          entry={CREDENTIAL_ENTRY}
          isSelected={false}
          index={0}
          onSelect={onSelect}
        />
      ));
      expect(getByText("admin@github.com")).toBeDefined();
    });

    it("renders Password type badge for credential entries", () => {
      const { getByText } = render(() => (
        <PopupResultItem
          entry={CREDENTIAL_ENTRY}
          isSelected={false}
          index={0}
          onSelect={onSelect}
        />
      ));
      expect(getByText("Password")).toBeDefined();
    });
  });

  describe("pin toggle", () => {
    it("renders pin toggle when onTogglePin is provided", () => {
      const { container } = render(() => (
        <PopupResultItem
          entry={TOTP_ENTRY}
          isSelected={false}
          index={0}
          onSelect={onSelect}
          onTogglePin={vi.fn()}
        />
      ));

      const toggle = container.querySelector("[data-testid='popup-pin-toggle']");
      expect(toggle).toBeTruthy();
    });

    it("does not render pin toggle when onTogglePin is absent", () => {
      const { container } = render(() => (
        <PopupResultItem
          entry={TOTP_ENTRY}
          isSelected={false}
          index={0}
          onSelect={onSelect}
        />
      ));

      const toggle = container.querySelector("[data-testid='popup-pin-toggle']");
      expect(toggle).toBeNull();
    });

    it("calls onTogglePin with (id, true) when clicking unpinned entry", () => {
      const onTogglePin = vi.fn();
      const { container } = render(() => (
        <PopupResultItem
          entry={TOTP_ENTRY}
          isSelected={false}
          index={0}
          onSelect={onSelect}
          onTogglePin={onTogglePin}
        />
      ));

      const toggle = container.querySelector("[data-testid='popup-pin-toggle']") as HTMLElement;
      fireEvent.click(toggle);
      expect(onTogglePin).toHaveBeenCalledWith("totp-1", true);
    });

    it("calls onTogglePin with (id, false) when clicking pinned entry", () => {
      const onTogglePin = vi.fn();
      const pinnedEntry = { ...TOTP_ENTRY, pinned: true };
      const { container } = render(() => (
        <PopupResultItem
          entry={pinnedEntry}
          isSelected={false}
          index={0}
          onSelect={onSelect}
          onTogglePin={onTogglePin}
        />
      ));

      const toggle = container.querySelector("[data-testid='popup-pin-toggle']") as HTMLElement;
      fireEvent.click(toggle);
      expect(onTogglePin).toHaveBeenCalledWith("totp-1", false);
    });

    it("has correct aria-label for unpinned state", () => {
      const { container } = render(() => (
        <PopupResultItem
          entry={TOTP_ENTRY}
          isSelected={false}
          index={0}
          onSelect={onSelect}
          onTogglePin={vi.fn()}
        />
      ));

      const toggle = container.querySelector("[data-testid='popup-pin-toggle']");
      expect(toggle?.getAttribute("aria-label")).toBe("Pin this entry");
    });

    it("has correct aria-label for pinned state", () => {
      const pinnedEntry = { ...TOTP_ENTRY, pinned: true };
      const { container } = render(() => (
        <PopupResultItem
          entry={pinnedEntry}
          isSelected={false}
          index={0}
          onSelect={onSelect}
          onTogglePin={vi.fn()}
        />
      ));

      const toggle = container.querySelector("[data-testid='popup-pin-toggle']");
      expect(toggle?.getAttribute("aria-label")).toBe("Unpin this entry");
    });

    it("does not trigger onSelect when clicking pin toggle", () => {
      const onTogglePin = vi.fn();
      const { container } = render(() => (
        <PopupResultItem
          entry={TOTP_ENTRY}
          isSelected={false}
          index={0}
          onSelect={onSelect}
          onTogglePin={onTogglePin}
        />
      ));

      const toggle = container.querySelector("[data-testid='popup-pin-toggle']") as HTMLElement;
      fireEvent.click(toggle);
      expect(onTogglePin).toHaveBeenCalled();
      expect(onSelect).not.toHaveBeenCalled();
    });

    it("toggles pin on Enter key without triggering parent keydown", () => {
      const onTogglePin = vi.fn();
      const { container } = render(() => (
        <PopupResultItem
          entry={TOTP_ENTRY}
          isSelected={false}
          index={0}
          onSelect={onSelect}
          onTogglePin={onTogglePin}
        />
      ));

      const toggle = container.querySelector("[data-testid='popup-pin-toggle']") as HTMLElement;
      fireEvent.keyDown(toggle, { key: "Enter" });
      expect(onTogglePin).toHaveBeenCalledWith("totp-1", true);
      expect(onSelect).not.toHaveBeenCalled();
    });

    it("toggles pin on Space key", () => {
      const onTogglePin = vi.fn();
      const { container } = render(() => (
        <PopupResultItem
          entry={TOTP_ENTRY}
          isSelected={false}
          index={0}
          onSelect={onSelect}
          onTogglePin={onTogglePin}
        />
      ));

      const toggle = container.querySelector("[data-testid='popup-pin-toggle']") as HTMLElement;
      fireEvent.keyDown(toggle, { key: " " });
      expect(onTogglePin).toHaveBeenCalledWith("totp-1", true);
    });

    it("includes pinned in aria-label for pinned entries", () => {
      const pinnedEntry = { ...TOTP_ENTRY, pinned: true };
      const { container } = render(() => (
        <PopupResultItem
          entry={pinnedEntry}
          isSelected={false}
          index={0}
          onSelect={onSelect}
          onTogglePin={vi.fn()}
        />
      ));

      const option = container.querySelector("[role='option']");
      const label = option?.getAttribute("aria-label") ?? "";
      expect(label).toContain("pinned");
    });
  });
});
