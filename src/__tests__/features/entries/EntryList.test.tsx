import { render } from "@solidjs/testing-library";
import { describe, expect, it, vi } from "vitest";
import { EntryList } from "../../../features/entries/EntryList";
import type { EntryMetadataDto } from "../../../features/entries/ipc";

// Use real mock store IDs so useTotpCode → generateTotpCode can resolve
const mockEntries: EntryMetadataDto[] = [
  {
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
  },
  {
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
  },
  {
    id: "a7b8c9d0-e1f2-4a3b-4c5d-6e7f80910213",
    entryType: "secure_note",
    name: "Server Credentials",
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    pinned: false,
    createdAt: "2026-02-05T14:00:00Z",
    updatedAt: "2026-02-05T14:00:00Z",
  },
];

describe("EntryList", () => {
  describe("with entries", () => {
    it("renders all entries", () => {
      render(() => <EntryList entries={mockEntries} />);
      expect(document.body.textContent).toContain("GitHub");
      expect(document.body.textContent).toContain("Bitcoin Wallet");
      expect(document.body.textContent).toContain("Server Credentials");
    });

    it("uses semantic ul element", () => {
      render(() => <EntryList entries={mockEntries} />);
      const list = document.querySelector("ul");
      expect(list).toBeTruthy();
    });

    it("renders li elements for each entry", () => {
      render(() => <EntryList entries={mockEntries} />);
      const items = document.querySelectorAll("li");
      expect(items.length).toBe(3);
    });

    it("renders TypeBadge for each entry", () => {
      render(() => <EntryList entries={mockEntries} />);
      expect(document.body.textContent).toContain("TOTP");
      expect(document.body.textContent).toContain("Seed");
      expect(document.body.textContent).toContain("Note");
    });

    it("calls onSelect when entry is clicked", () => {
      const onSelect = vi.fn();
      render(() => <EntryList entries={mockEntries} onSelect={onSelect} />);
      const firstItem = document.querySelector("li");
      firstItem?.click();
      expect(onSelect).toHaveBeenCalledWith("a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d");
    });
  });

  describe("empty state", () => {
    it("shows empty message when no entries", () => {
      render(() => <EntryList entries={[]} />);
      expect(document.body.textContent).toContain("Your vault is empty");
    });

    it("shows Add Entry button in empty state", () => {
      const onAdd = vi.fn();
      render(() => <EntryList entries={[]} onAdd={onAdd} />);
      const addBtn = Array.from(document.querySelectorAll("button")).find((b) =>
        b.textContent?.includes("Add Entry"),
      );
      expect(addBtn).toBeTruthy();
    });

    it("calls onAdd when Add Entry button is clicked", () => {
      const onAdd = vi.fn();
      render(() => <EntryList entries={[]} onAdd={onAdd} />);
      const addBtn = Array.from(document.querySelectorAll("button")).find((b) =>
        b.textContent?.includes("Add Entry"),
      );
      addBtn?.click();
      expect(onAdd).toHaveBeenCalled();
    });
  });

  describe("search empty state", () => {
    it("shows search-specific message when searchQuery is provided", () => {
      render(() => <EntryList entries={[]} searchQuery="github" />);
      expect(document.body.textContent).toContain("No entries match");
      expect(document.body.textContent).toContain("github");
    });

    it("shows vault empty message when no searchQuery", () => {
      render(() => <EntryList entries={[]} />);
      expect(document.body.textContent).toContain("Your vault is empty");
      expect(document.body.textContent).not.toContain("No entries match");
    });

    it("does not show Add Entry button in search empty state", () => {
      render(() => <EntryList entries={[]} searchQuery="zzz" onAdd={vi.fn()} />);
      expect(document.body.textContent).toContain("No entries match");
      const addBtn = Array.from(document.querySelectorAll("button")).find((b) =>
        b.textContent?.includes("Add Entry"),
      );
      expect(addBtn).toBeUndefined();
    });
  });
});
