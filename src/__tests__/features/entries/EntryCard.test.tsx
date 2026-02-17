import { render, fireEvent } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { EntryCard } from "../../../features/entries/EntryCard";
import type { EntryMetadataDto } from "../../../features/entries/ipc";
import { _resetMockStore } from "../../../features/entries/ipc";
import * as ipc from "../../../features/entries/ipc";

/** Stub matchMedia for CountdownRing (used inside TOTP cards). */
function stubMatchMedia() {
  vi.stubGlobal("matchMedia", (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  }));
}

/** Flush microtasks + small delay for crypto.subtle to resolve. */
function flushAsync(ms = 80): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

let writeTextMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  stubMatchMedia();
  _resetMockStore();
  writeTextMock = vi.fn().mockResolvedValue(undefined);
  Object.assign(navigator, {
    clipboard: { writeText: writeTextMock, readText: vi.fn() },
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

// Use real mock store IDs for TOTP entries so useTotpCode can resolve
const totpEntry: EntryMetadataDto = {
  id: "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
  entryType: "totp",
  name: "GitHub",
  issuer: "github.com",
  algorithm: "SHA1",
  digits: 6,
  period: 30,
  pinned: true,
  createdAt: "2026-02-05T10:00:00Z",
  updatedAt: "2026-02-05T10:00:00Z",
};

const hotpEntry: EntryMetadataDto = {
  id: "d4e5f6a7-b8c9-4d0e-1f2a-3b4c5d6e7f80",
  entryType: "hotp",
  name: "Legacy VPN",
  issuer: "vpn.corp.example.com",
  algorithm: "SHA1",
  digits: 6,
  period: 30,
  pinned: false,
  createdAt: "2026-02-04T14:00:00Z",
  updatedAt: "2026-02-06T08:00:00Z",
};

const seedEntry: EntryMetadataDto = {
  id: "e5f6a7b8-c9d0-4e1f-2a3b-4c5d6e7f8091",
  entryType: "seed_phrase",
  name: "Bitcoin Wallet",
  issuer: "ledger.com",
  algorithm: "SHA1",
  digits: 6,
  period: 30,
  pinned: false,
  createdAt: "2026-02-05T12:00:00Z",
  updatedAt: "2026-02-05T12:00:00Z",
};

const recoveryEntry: EntryMetadataDto = {
  id: "f6a7b8c9-d0e1-4f2a-3b4c-5d6e7f809102",
  entryType: "recovery_code",
  name: "Google Account",
  issuer: "google.com",
  algorithm: "SHA1",
  digits: 6,
  period: 30,
  pinned: false,
  createdAt: "2026-02-05T13:00:00Z",
  updatedAt: "2026-02-05T13:00:00Z",
};

const noteEntry: EntryMetadataDto = {
  id: "a7b8c9d0-e1f2-4a3b-4c5d-6e7f80910213",
  entryType: "secure_note",
  name: "Server Credentials",
  algorithm: "SHA1",
  digits: 6,
  period: 30,
  pinned: false,
  createdAt: "2026-02-05T14:00:00Z",
  updatedAt: "2026-02-05T14:00:00Z",
};

describe("EntryCard", () => {
  describe("common card shell", () => {
    it("renders entry name", () => {
      render(() => <EntryCard entry={totpEntry} />);
      expect(document.body.textContent).toContain("GitHub");
    });

    it("renders issuer when present", () => {
      render(() => <EntryCard entry={totpEntry} />);
      expect(document.body.textContent).toContain("github.com");
    });

    it("omits issuer when absent", () => {
      render(() => <EntryCard entry={noteEntry} />);
      expect(document.body.textContent).not.toContain("undefined");
    });

    it("renders TypeBadge", () => {
      render(() => <EntryCard entry={totpEntry} />);
      expect(document.body.textContent).toContain("TOTP");
    });

    it("shows pin indicator when pinned", () => {
      render(() => <EntryCard entry={totpEntry} />);
      const pinIcon = document.querySelector("[aria-label='Pinned']");
      expect(pinIcon).toBeTruthy();
    });

    it("hides pin indicator when not pinned", () => {
      render(() => <EntryCard entry={hotpEntry} />);
      const pinIcon = document.querySelector("[aria-label='Pinned']");
      expect(pinIcon).toBeNull();
    });

    it("has descriptive aria-label", () => {
      render(() => <EntryCard entry={totpEntry} />);
      const card = document.querySelector("[role='listitem']") ??
        document.querySelector("li");
      expect(card?.getAttribute("aria-label")).toContain("GitHub");
      expect(card?.getAttribute("aria-label")).toContain("TOTP");
    });
  });

  describe("interaction and keyboard accessibility", () => {
    it("calls onSelect with entry id on click", () => {
      const onSelect = vi.fn();
      render(() => <EntryCard entry={totpEntry} onSelect={onSelect} />);
      const card = document.querySelector("li");
      card?.click();
      expect(onSelect).toHaveBeenCalledWith(totpEntry.id);
    });

    it("calls onSelect on Enter key for non-TOTP entry", () => {
      const onSelect = vi.fn();
      render(() => <EntryCard entry={seedEntry} onSelect={onSelect} />);
      const card = document.querySelector("li");
      fireEvent.keyDown(card!, { key: "Enter" });
      expect(onSelect).toHaveBeenCalledWith(seedEntry.id);
    });

    it("calls onSelect on Space key for non-TOTP entry", () => {
      const onSelect = vi.fn();
      render(() => <EntryCard entry={seedEntry} onSelect={onSelect} />);
      const card = document.querySelector("li");
      fireEvent.keyDown(card!, { key: " " });
      expect(onSelect).toHaveBeenCalledWith(seedEntry.id);
    });

    it("Enter on TOTP card triggers copy instead of onSelect", () => {
      const onSelect = vi.fn();
      render(() => <EntryCard entry={totpEntry} onSelect={onSelect} />);
      const card = document.querySelector("li");
      const copyTrigger = document.querySelector("[data-testid='copy-trigger']");
      const clickSpy = vi.spyOn(copyTrigger as HTMLElement, "click");
      fireEvent.keyDown(card!, { key: "Enter" });
      expect(onSelect).not.toHaveBeenCalled();
      expect(clickSpy).toHaveBeenCalled();
      clickSpy.mockRestore();
    });

    it("has tabindex 0 when onSelect is provided", () => {
      render(() => <EntryCard entry={totpEntry} onSelect={vi.fn()} />);
      const card = document.querySelector("li");
      expect(card?.getAttribute("tabindex")).toBe("0");
    });

    it("has no tabindex when onSelect is not provided", () => {
      render(() => <EntryCard entry={totpEntry} />);
      const card = document.querySelector("li");
      expect(card?.hasAttribute("tabindex")).toBe(false);
    });
  });

  describe("pin toggle", () => {
    it("renders interactive pin toggle when onTogglePin is provided", () => {
      render(() => <EntryCard entry={totpEntry} onTogglePin={vi.fn()} />);
      const toggle = document.querySelector("[data-testid='pin-toggle']");
      expect(toggle).toBeTruthy();
    });

    it("shows static pin indicator when onTogglePin is absent and entry is pinned", () => {
      render(() => <EntryCard entry={totpEntry} />);
      const pinIcon = document.querySelector("[aria-label='Pinned']");
      expect(pinIcon).toBeTruthy();
      const toggle = document.querySelector("[data-testid='pin-toggle']");
      expect(toggle).toBeNull();
    });

    it("hides pin indicator when onTogglePin is absent and entry is unpinned", () => {
      render(() => <EntryCard entry={hotpEntry} />);
      const pinIcon = document.querySelector("[aria-label='Pinned']");
      expect(pinIcon).toBeNull();
      const toggle = document.querySelector("[data-testid='pin-toggle']");
      expect(toggle).toBeNull();
    });

    it("has aria-label 'Unpin this entry' when pinned", () => {
      render(() => <EntryCard entry={totpEntry} onTogglePin={vi.fn()} />);
      const toggle = document.querySelector("[data-testid='pin-toggle']");
      expect(toggle?.getAttribute("aria-label")).toBe("Unpin this entry");
    });

    it("has aria-label 'Pin this entry' when unpinned", () => {
      render(() => <EntryCard entry={hotpEntry} onTogglePin={vi.fn()} />);
      const toggle = document.querySelector("[data-testid='pin-toggle']");
      expect(toggle?.getAttribute("aria-label")).toBe("Pin this entry");
    });

    it("calls onTogglePin with (id, true) when clicking unpinned entry", () => {
      const onTogglePin = vi.fn();
      render(() => <EntryCard entry={hotpEntry} onTogglePin={onTogglePin} />);
      const toggle = document.querySelector("[data-testid='pin-toggle']") as HTMLElement;
      fireEvent.click(toggle);
      expect(onTogglePin).toHaveBeenCalledWith(hotpEntry.id, true);
    });

    it("calls onTogglePin with (id, false) when clicking pinned entry", () => {
      const onTogglePin = vi.fn();
      render(() => <EntryCard entry={totpEntry} onTogglePin={onTogglePin} />);
      const toggle = document.querySelector("[data-testid='pin-toggle']") as HTMLElement;
      fireEvent.click(toggle);
      expect(onTogglePin).toHaveBeenCalledWith(totpEntry.id, false);
    });

    it("does not trigger card onSelect when clicking pin toggle", () => {
      const onSelect = vi.fn();
      const onTogglePin = vi.fn();
      render(() => <EntryCard entry={hotpEntry} onSelect={onSelect} onTogglePin={onTogglePin} />);
      const toggle = document.querySelector("[data-testid='pin-toggle']") as HTMLElement;
      fireEvent.click(toggle);
      expect(onTogglePin).toHaveBeenCalled();
      expect(onSelect).not.toHaveBeenCalled();
    });

    it("toggles pin on Enter key", () => {
      const onTogglePin = vi.fn();
      render(() => <EntryCard entry={hotpEntry} onTogglePin={onTogglePin} />);
      const toggle = document.querySelector("[data-testid='pin-toggle']") as HTMLElement;
      fireEvent.keyDown(toggle, { key: "Enter" });
      expect(onTogglePin).toHaveBeenCalledWith(hotpEntry.id, true);
    });

    it("toggles pin on Space key", () => {
      const onTogglePin = vi.fn();
      render(() => <EntryCard entry={hotpEntry} onTogglePin={onTogglePin} />);
      const toggle = document.querySelector("[data-testid='pin-toggle']") as HTMLElement;
      fireEvent.keyDown(toggle, { key: " " });
      expect(onTogglePin).toHaveBeenCalledWith(hotpEntry.id, true);
    });
  });

  describe("TOTP content zone (live code)", () => {
    it("shows placeholder before code loads", () => {
      render(() => <EntryCard entry={totpEntry} />);
      // Before async fetch, placeholder is shown
      expect(document.body.textContent).toContain("--- ---");
    });

    it("renders live TOTP code after fetch", async () => {
      render(() => <EntryCard entry={totpEntry} />);
      await flushAsync();
      const live = document.querySelector("[data-testid='live-totp-code']");
      expect(live).toBeTruthy();
      // 6-digit code with space: "XXX XXX"
      expect(live?.textContent).toMatch(/^\d{3} \d{3}$/);
    });

    it("renders CountdownRing for TOTP", async () => {
      render(() => <EntryCard entry={totpEntry} />);
      await flushAsync();
      const ring = document.querySelector("[data-testid='countdown-ring']");
      expect(ring).toBeTruthy();
    });

    it("has aria-live='polite' on TOTP code zone", async () => {
      render(() => <EntryCard entry={totpEntry} />);
      await flushAsync();
      const zone = document.querySelector("[aria-live='polite']");
      expect(zone).toBeTruthy();
    });

    it("shows 8-digit code with 4-4 grouping", async () => {
      const entry8: EntryMetadataDto = {
        ...totpEntry,
        id: "c3d4e5f6-a7b8-4c9d-0e1f-2a3b4c5d6e7f",
        digits: 8,
      };
      render(() => <EntryCard entry={entry8} />);
      await flushAsync();
      const live = document.querySelector("[data-testid='live-totp-code']");
      expect(live?.textContent).toMatch(/^\d{4} \d{4}$/);
    });
  });

  describe("HOTP content zone", () => {
    it("renders placeholder code for HOTP", () => {
      render(() => <EntryCard entry={hotpEntry} />);
      expect(document.body.textContent).toContain("--- ---");
    });

    it("renders HOTP badge", () => {
      render(() => <EntryCard entry={hotpEntry} />);
      expect(document.body.textContent).toContain("HOTP");
    });
  });

  describe("seed_phrase content zone", () => {
    it("renders masked dots", () => {
      render(() => <EntryCard entry={seedEntry} />);
      const masked = document.querySelector("[data-testid='seed-masked']");
      expect(masked).toBeTruthy();
    });

    it("shows word count", () => {
      render(() => <EntryCard entry={seedEntry} />);
      expect(document.body.textContent).toContain("24 words");
    });
  });

  describe("recovery_code content zone", () => {
    it("shows remaining codes text", () => {
      render(() => <EntryCard entry={recoveryEntry} />);
      expect(document.body.textContent).toContain("Linked recovery codes");
    });
  });

  describe("secure_note content zone", () => {
    it("shows secure note label", () => {
      render(() => <EntryCard entry={noteEntry} />);
      expect(document.body.textContent).toContain("Secure note");
    });
  });

  describe("credential content zone", () => {
    const credentialEntry: EntryMetadataDto = {
      id: "b8c9d0e1-f2a3-4b4c-5d6e-7f8091021324",
      entryType: "credential",
      name: "GitHub Login",
      issuer: "github.com",
      algorithm: "SHA1",
      digits: 6,
      period: 30,
      pinned: false,
      username: "admin@github.com",
      createdAt: "2026-02-10T09:00:00Z",
      updatedAt: "2026-02-10T09:00:00Z",
    };

    it("renders masked password indicator", () => {
      render(() => <EntryCard entry={credentialEntry} />);
      expect(document.body.textContent).toContain("••••••");
    });

    it("renders username when present", () => {
      render(() => <EntryCard entry={credentialEntry} />);
      expect(document.body.textContent).toContain("admin@github.com");
    });

    it("hides username section when absent", () => {
      const noUsername = { ...credentialEntry, username: undefined };
      render(() => <EntryCard entry={noUsername} />);
      expect(document.body.textContent).not.toContain("admin@github.com");
    });

    it("renders Password type badge", () => {
      render(() => <EntryCard entry={credentialEntry} />);
      expect(document.body.textContent).toContain("Password");
    });

    it("shows issuer in header", () => {
      render(() => <EntryCard entry={credentialEntry} />);
      expect(document.body.textContent).toContain("github.com");
    });
  });

  describe("copy-to-clipboard (TOTP)", () => {
    it("copies code to clipboard on click of code zone", async () => {
      render(() => <EntryCard entry={totpEntry} />);
      await flushAsync(200);
      const trigger = document.querySelector("[data-testid='copy-trigger']");
      expect(trigger).toBeTruthy();
      fireEvent.click(trigger!);
      await flushAsync(300);
      expect(writeTextMock).toHaveBeenCalled();
      const written = writeTextMock.mock.calls[0][0] as string;
      expect(written).toMatch(/^\d{6}$/);
    });

    it("copies code on Enter key press on code zone", async () => {
      render(() => <EntryCard entry={totpEntry} />);
      await flushAsync(200);
      const trigger = document.querySelector("[data-testid='copy-trigger']");
      fireEvent.keyDown(trigger!, { key: "Enter" });
      await flushAsync(300);
      expect(writeTextMock).toHaveBeenCalled();
      const written = writeTextMock.mock.calls[0][0] as string;
      expect(written).toMatch(/^\d{6}$/);
    });

    it("does not trigger card onSelect when clicking code zone", async () => {
      const onSelect = vi.fn();
      render(() => <EntryCard entry={totpEntry} onSelect={onSelect} />);
      await flushAsync();
      const trigger = document.querySelector("[data-testid='copy-trigger']");
      fireEvent.click(trigger!);
      await flushAsync();
      expect(onSelect).not.toHaveBeenCalled();
    });

    it("waits for fresh code when remaining < 2 seconds", async () => {
      vi.useFakeTimers();
      const generateSpy = vi.spyOn(ipc, "generateTotpCode")
        .mockResolvedValueOnce({ code: "111111", remainingSeconds: 1 })
        .mockResolvedValueOnce({ code: "222222", remainingSeconds: 30 });
      render(() => <EntryCard entry={totpEntry} />);
      const trigger = document.querySelector("[data-testid='copy-trigger']");
      fireEvent.click(trigger!);
      await vi.advanceTimersByTimeAsync(1100);
      expect(writeTextMock).toHaveBeenCalledWith("222222");
      generateSpy.mockRestore();
      vi.useRealTimers();
    });

    it("does not schedule frontend auto-clear timer (Rust backend handles it)", async () => {
      vi.useFakeTimers();
      const generateSpy = vi.spyOn(ipc, "generateTotpCode").mockResolvedValue({
        code: "123456",
        remainingSeconds: 20,
      });
      render(() => <EntryCard entry={totpEntry} />);
      const trigger = document.querySelector("[data-testid='copy-trigger']");
      fireEvent.click(trigger!);
      await vi.advanceTimersByTimeAsync(100);
      expect(writeTextMock).toHaveBeenCalledWith("123456");
      // Advance past old 30s timer — should NOT clear clipboard from frontend
      await vi.advanceTimersByTimeAsync(35_000);
      // Only the original write — no frontend auto-clear
      expect(writeTextMock).toHaveBeenCalledTimes(1);
      generateSpy.mockRestore();
      vi.useRealTimers();
    });

    it("does NOT add copy trigger to non-TOTP entries", () => {
      render(() => <EntryCard entry={seedEntry} />);
      const trigger = document.querySelector("[data-testid='copy-trigger']");
      expect(trigger).toBeNull();
    });

    it("handles copy error gracefully", async () => {
      const generateSpy = vi.spyOn(ipc, "generateTotpCode").mockRejectedValue(
        new Error("Entry deleted"),
      );
      render(() => <EntryCard entry={totpEntry} />);
      await flushAsync();
      const trigger = document.querySelector("[data-testid='copy-trigger']");
      fireEvent.click(trigger!);
      await flushAsync();
      // Should not throw — error handled internally
      expect(writeTextMock).not.toHaveBeenCalled();
      generateSpy.mockRestore();
    });
  });
});
