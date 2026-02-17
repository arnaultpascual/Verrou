import { render, fireEvent, waitFor } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { MemoryRouter, Route } from "@solidjs/router";
import { Header } from "../../../features/layout/Header";
import { setVaultState } from "../../../stores/vaultStore";
import { setSearchQuery, clearSearch, searchQuery } from "../../../stores/searchStore";

// Mock lockVault IPC
vi.mock("../../../features/vault/ipc", () => ({
  lockVault: vi.fn(() => Promise.resolve()),
}));

/** Render Header inside a MemoryRouter so useNavigate() works. */
function renderHeader() {
  return render(() => (
    <MemoryRouter>
      <Route path="/" component={() => <Header />} />
    </MemoryRouter>
  ));
}

describe("Header", () => {
  beforeEach(() => {
    setVaultState("unlocked");
    clearSearch();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("renders the app title VERROU", () => {
    const { getByText } = renderHeader();
    expect(getByText("VERROU")).toBeDefined();
  });

  it("renders h1 with VERROU text", () => {
    const { container } = renderHeader();
    const h1 = container.querySelector("h1");
    expect(h1).not.toBeNull();
    expect(h1!.textContent).toBe("VERROU");
  });

  it("renders search input placeholder", () => {
    const { getByPlaceholderText } = renderHeader();
    expect(getByPlaceholderText("Search entries...")).toBeDefined();
  });

  it("renders search input as enabled", () => {
    const { getByPlaceholderText } = renderHeader();
    const input = getByPlaceholderText("Search entries...") as HTMLInputElement;
    expect(input.disabled).toBe(false);
  });

  it("renders settings button", () => {
    const { getByLabelText } = renderHeader();
    expect(getByLabelText("Settings")).toBeDefined();
  });

  it("renders settings button as a button element", () => {
    const { getByLabelText } = renderHeader();
    const btn = getByLabelText("Settings");
    expect(btn.tagName).toBe("BUTTON");
  });

  it("renders header element", () => {
    const { container } = renderHeader();
    const header = container.querySelector("header");
    expect(header).not.toBeNull();
  });

  // -- Lock button tests (Story 2.9) ----------------------------------

  it("renders lock button when vault is unlocked", () => {
    setVaultState("unlocked");
    const { getByLabelText } = renderHeader();
    expect(getByLabelText("Lock vault")).toBeDefined();
  });

  it("lock button is a button element", () => {
    setVaultState("unlocked");
    const { getByLabelText } = renderHeader();
    const btn = getByLabelText("Lock vault");
    expect(btn.tagName).toBe("BUTTON");
  });

  it("hides lock button when vault is locked", () => {
    setVaultState("locked");
    const { queryByLabelText } = renderHeader();
    expect(queryByLabelText("Lock vault")).toBeNull();
  });

  it("hides lock button when vault state is no-vault", () => {
    setVaultState("no-vault");
    const { queryByLabelText } = renderHeader();
    expect(queryByLabelText("Lock vault")).toBeNull();
  });

  it("clicking lock button calls lockVault IPC", async () => {
    const { lockVault } = await import("../../../features/vault/ipc");
    setVaultState("unlocked");
    const { getByLabelText } = renderHeader();
    const btn = getByLabelText("Lock vault");

    fireEvent.click(btn);

    await waitFor(() => {
      expect(lockVault).toHaveBeenCalledTimes(1);
    });
  });

  it("clicking lock button transitions state to locked", async () => {
    setVaultState("unlocked");
    const { getByLabelText } = renderHeader();
    const btn = getByLabelText("Lock vault");

    fireEvent.click(btn);

    await waitFor(() => {
      // After click, lock button should disappear (state = locked)
      expect(document.querySelector("[aria-label='Lock vault']")).toBeNull();
    });
  });

  // -- Search input tests (Story 3.6) ------------------------------------

  describe("search input", () => {
    it("typing updates search store", () => {
      const { getByPlaceholderText } = renderHeader();
      const input = getByPlaceholderText("Search entries...") as HTMLInputElement;
      fireEvent.input(input, { target: { value: "github" } });
      expect(searchQuery()).toBe("github");
    });

    it("displays current search query value", () => {
      setSearchQuery("test");
      const { getByPlaceholderText } = renderHeader();
      const input = getByPlaceholderText("Search entries...") as HTMLInputElement;
      expect(input.value).toBe("test");
    });

    it("/ key focuses the search input", () => {
      const { getByPlaceholderText } = renderHeader();
      const input = getByPlaceholderText("Search entries...") as HTMLInputElement;
      // Ensure input is NOT focused initially
      expect(document.activeElement).not.toBe(input);
      // Press / on the document
      fireEvent.keyDown(document, { key: "/" });
      expect(document.activeElement).toBe(input);
    });

    it("/ key does not focus when already in an input", () => {
      const { getByPlaceholderText } = renderHeader();
      const input = getByPlaceholderText("Search entries...") as HTMLInputElement;
      input.focus();
      // Typing / while focused should NOT prevent normal typing
      // (the handler guards against this)
      fireEvent.keyDown(input, { key: "/" });
      // Input should still be focused (no change)
      expect(document.activeElement).toBe(input);
    });

    it("Escape clears search and blurs input", () => {
      const { getByPlaceholderText } = renderHeader();
      const input = getByPlaceholderText("Search entries...") as HTMLInputElement;
      // Focus and type
      input.focus();
      fireEvent.input(input, { target: { value: "test" } });
      expect(searchQuery()).toBe("test");
      // Press Escape
      fireEvent.keyDown(input, { key: "Escape" });
      expect(searchQuery()).toBe("");
      expect(document.activeElement).not.toBe(input);
    });
  });
});
