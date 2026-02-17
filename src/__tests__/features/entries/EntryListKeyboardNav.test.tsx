import { render, fireEvent } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { EntryList } from "../../../features/entries/EntryList";
import type { EntryMetadataDto } from "../../../features/entries/ipc";

/** Stub matchMedia for CountdownRing. */
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

describe("EntryList keyboard navigation", () => {
  beforeEach(() => {
    stubMatchMedia();
    Element.prototype.scrollIntoView = vi.fn();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("ArrowDown moves focus to first card when pressed on list", () => {
    const onSelect = vi.fn();
    render(() => <EntryList entries={mockEntries} onSelect={onSelect} />);
    const list = document.querySelector("ul")!;

    fireEvent.keyDown(list, { key: "ArrowDown" });

    const items = document.querySelectorAll("li");
    expect(items[0]).toHaveFocus();
  });

  it("ArrowDown moves focus sequentially through cards", () => {
    const onSelect = vi.fn();
    render(() => <EntryList entries={mockEntries} onSelect={onSelect} />);
    const list = document.querySelector("ul")!;
    const items = document.querySelectorAll("li");

    // First ArrowDown → focus first
    fireEvent.keyDown(list, { key: "ArrowDown" });
    expect(items[0]).toHaveFocus();

    // Second ArrowDown → focus second
    fireEvent.keyDown(items[0], { key: "ArrowDown" });
    expect(items[1]).toHaveFocus();

    // Third ArrowDown → focus third
    fireEvent.keyDown(items[1], { key: "ArrowDown" });
    expect(items[2]).toHaveFocus();
  });

  it("ArrowDown wraps from last to first", () => {
    const onSelect = vi.fn();
    render(() => <EntryList entries={mockEntries} onSelect={onSelect} />);
    const list = document.querySelector("ul")!;
    const items = document.querySelectorAll("li");

    // Navigate to last item
    fireEvent.keyDown(list, { key: "ArrowDown" });
    fireEvent.keyDown(items[0], { key: "ArrowDown" });
    fireEvent.keyDown(items[1], { key: "ArrowDown" });
    expect(items[2]).toHaveFocus();

    // Wrap to first
    fireEvent.keyDown(items[2], { key: "ArrowDown" });
    expect(items[0]).toHaveFocus();
  });

  it("ArrowUp wraps from first to last", () => {
    const onSelect = vi.fn();
    render(() => <EntryList entries={mockEntries} onSelect={onSelect} />);
    const list = document.querySelector("ul")!;
    const items = document.querySelectorAll("li");

    // Go to first item
    fireEvent.keyDown(list, { key: "ArrowDown" });
    expect(items[0]).toHaveFocus();

    // ArrowUp wraps to last
    fireEvent.keyDown(items[0], { key: "ArrowUp" });
    expect(items[2]).toHaveFocus();
  });

  it("ArrowUp moves focus upward", () => {
    const onSelect = vi.fn();
    render(() => <EntryList entries={mockEntries} onSelect={onSelect} />);
    const list = document.querySelector("ul")!;
    const items = document.querySelectorAll("li");

    // Navigate down to second item
    fireEvent.keyDown(list, { key: "ArrowDown" });
    fireEvent.keyDown(items[0], { key: "ArrowDown" });
    expect(items[1]).toHaveFocus();

    // ArrowUp goes back to first
    fireEvent.keyDown(items[1], { key: "ArrowUp" });
    expect(items[0]).toHaveFocus();
  });

  it("Enter on TOTP entry does NOT call onSelect (triggers copy instead)", () => {
    const onSelect = vi.fn();
    render(() => <EntryList entries={mockEntries} onSelect={onSelect} />);
    const list = document.querySelector("ul")!;
    const items = document.querySelectorAll("li");

    // Navigate to first item (TOTP entry)
    fireEvent.keyDown(list, { key: "ArrowDown" });
    expect(items[0]).toHaveFocus();

    // Enter on TOTP should NOT call onSelect
    fireEvent.keyDown(items[0], { key: "Enter" });
    expect(onSelect).not.toHaveBeenCalled();
  });

  it("Enter on non-TOTP entry calls onSelect", () => {
    const onSelect = vi.fn();
    render(() => <EntryList entries={mockEntries} onSelect={onSelect} />);
    const list = document.querySelector("ul")!;
    const items = document.querySelectorAll("li");

    // Navigate to seed phrase entry (index 1)
    fireEvent.keyDown(list, { key: "ArrowDown" });
    fireEvent.keyDown(items[0], { key: "ArrowDown" });
    expect(items[1]).toHaveFocus();

    // Enter should call onSelect for non-TOTP
    fireEvent.keyDown(items[1], { key: "Enter" });
    expect(onSelect).toHaveBeenCalledWith("e5f6a7b8-c9d0-4e1f-2a3b-4c5d6e7f8091");
  });

  it("scrollIntoView is called when navigating", () => {
    const onSelect = vi.fn();
    render(() => <EntryList entries={mockEntries} onSelect={onSelect} />);
    const list = document.querySelector("ul")!;

    fireEvent.keyDown(list, { key: "ArrowDown" });

    expect(Element.prototype.scrollIntoView).toHaveBeenCalledWith({ block: "nearest" });
  });

  it("does not navigate when list is empty", () => {
    render(() => <EntryList entries={[]} />);
    // No ul rendered in empty state
    const list = document.querySelector("ul");
    expect(list).toBeNull();
  });

  it("Home key moves focus to first card", () => {
    const onSelect = vi.fn();
    render(() => <EntryList entries={mockEntries} onSelect={onSelect} />);
    const list = document.querySelector("ul")!;
    const items = document.querySelectorAll("li");

    // Navigate to last item
    fireEvent.keyDown(list, { key: "ArrowDown" });
    fireEvent.keyDown(items[0], { key: "ArrowDown" });
    fireEvent.keyDown(items[1], { key: "ArrowDown" });
    expect(items[2]).toHaveFocus();

    // Home should go to first
    fireEvent.keyDown(items[2], { key: "Home" });
    expect(items[0]).toHaveFocus();
  });

  it("End key moves focus to last card", () => {
    const onSelect = vi.fn();
    render(() => <EntryList entries={mockEntries} onSelect={onSelect} />);
    const list = document.querySelector("ul")!;
    const items = document.querySelectorAll("li");

    // Focus first
    fireEvent.keyDown(list, { key: "ArrowDown" });
    expect(items[0]).toHaveFocus();

    // End should go to last
    fireEvent.keyDown(items[0], { key: "End" });
    expect(items[2]).toHaveFocus();
  });
});
