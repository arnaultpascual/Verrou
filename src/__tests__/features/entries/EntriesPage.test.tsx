import { render, fireEvent, waitFor } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { MemoryRouter, Route, createMemoryHistory } from "@solidjs/router";
import { EntriesPage } from "../../../features/entries/EntriesPage";
import { _resetMockStore } from "../../../features/entries/ipc";
import { setSearchQuery, clearSearch } from "../../../stores/searchStore";

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

function renderPage() {
  return render(() => (
    <MemoryRouter root={(props) => <>{props.children}</>}>
      <Route path="/" component={EntriesPage} />
    </MemoryRouter>
  ));
}

beforeEach(() => {
  _resetMockStore();
  clearSearch();
  mockToast.success.mockClear();
  mockToast.error.mockClear();
});

describe("EntriesPage", () => {
  it("renders page title and Add Entry button", async () => {
    renderPage();

    await waitFor(() => {
      expect(document.body.textContent).toContain("Entries");
      expect(document.body.textContent).toContain("Add Entry");
    });
  });

  it("loads and displays entry list from mock store", async () => {
    renderPage();

    await waitFor(() => {
      expect(document.body.textContent).toContain("GitHub");
      expect(document.body.textContent).toContain("Google");
      expect(document.body.textContent).toContain("AWS Console");
    });
  });

  it("displays all entry types from mock store", async () => {
    renderPage();

    await waitFor(() => {
      expect(document.body.textContent).toContain("Bitcoin Wallet");
      expect(document.body.textContent).toContain("Google Account");
      expect(document.body.textContent).toContain("Server Credentials");
    });
  });

  it("renders TypeBadge for each entry type", async () => {
    renderPage();

    await waitFor(() => {
      expect(document.body.textContent).toContain("TOTP");
      expect(document.body.textContent).toContain("HOTP");
      expect(document.body.textContent).toContain("Seed");
      expect(document.body.textContent).toContain("Recovery");
      expect(document.body.textContent).toContain("Note");
    });
  });

  it("opens AddEntryModal when TOTP Code is selected from dropdown", async () => {
    renderPage();

    // Click "Add Entry" to open the dropdown menu
    const addBtn = Array.from(document.querySelectorAll("button")).find((b) =>
      b.textContent?.includes("Add Entry"),
    );
    expect(addBtn).toBeTruthy();
    fireEvent.click(addBtn!);

    // Wait for dropdown to appear, then click "TOTP Code"
    await waitFor(() => {
      expect(document.body.textContent).toContain("TOTP Code");
    });

    const totpOption = Array.from(document.querySelectorAll("button")).find((b) =>
      b.textContent?.includes("TOTP Code"),
    );
    expect(totpOption).toBeTruthy();
    fireEvent.click(totpOption!);

    await waitFor(() => {
      const dialog = document.querySelector("[role='dialog']");
      expect(dialog).toBeTruthy();
      expect(document.body.textContent).toContain("Add TOTP Entry");
    });
  });

  it("shows issuer when available", async () => {
    renderPage();

    await waitFor(() => {
      expect(document.body.textContent).toContain("github.com");
    });
  });

  it("shows pin toggle for pinned entries", async () => {
    renderPage();

    await waitFor(() => {
      const pinToggle = document.querySelector("[data-testid='pin-toggle']");
      expect(pinToggle).toBeTruthy();
      expect(pinToggle?.getAttribute("aria-label")).toBe("Unpin this entry");
    });
  });

  // -- Search filtering tests (Story 3.6) ---------------------------------

  describe("search filtering", () => {
    it("filters entries when search query is set", async () => {
      renderPage();

      await waitFor(() => {
        expect(document.body.textContent).toContain("GitHub");
      });

      setSearchQuery("github");

      await waitFor(() => {
        expect(document.body.textContent).toContain("GitHub");
        expect(document.body.textContent).not.toContain("Bitcoin Wallet");
      });
    });

    it("shows search empty state when no results match", async () => {
      renderPage();

      await waitFor(() => {
        expect(document.body.textContent).toContain("GitHub");
      });

      setSearchQuery("zzzzzznothing");

      await waitFor(() => {
        expect(document.body.textContent).toContain("No entries match");
        expect(document.body.textContent).toContain("zzzzzznothing");
      });
    });

    it("shows all entries when search is cleared", async () => {
      renderPage();

      await waitFor(() => {
        expect(document.body.textContent).toContain("GitHub");
      });

      setSearchQuery("github");

      await waitFor(() => {
        expect(document.body.textContent).not.toContain("Google");
      });

      clearSearch();

      await waitFor(() => {
        expect(document.body.textContent).toContain("GitHub");
        expect(document.body.textContent).toContain("Google");
      });
    });

    it("announces result count via aria-live region", async () => {
      renderPage();

      await waitFor(() => {
        expect(document.body.textContent).toContain("GitHub");
      });

      setSearchQuery("git");

      await waitFor(() => {
        const liveRegion = document.querySelector("[aria-live='polite'][role='status']");
        expect(liveRegion).toBeTruthy();
        expect(liveRegion!.textContent).toContain("entries found");
      });
    });

    it("does not show aria-live announcement when search is empty", async () => {
      renderPage();

      await waitFor(() => {
        expect(document.body.textContent).toContain("GitHub");
      });

      const liveRegion = document.querySelector("[aria-live='polite'][role='status']");
      if (liveRegion) {
        expect(liveRegion.textContent).toBe("");
      }
    });
  });

  // -- Edit entry integration tests (Story 3.7) ----------------------------

  describe("edit entry", () => {
    it("opens EditEntryModal when an entry card is clicked", async () => {
      renderPage();

      // Wait for entries to load
      await waitFor(() => {
        expect(document.body.textContent).toContain("GitHub");
      });

      // Click on the first entry card (GitHub — pinned, so first in list)
      const firstCard = document.querySelector("li");
      expect(firstCard).toBeTruthy();
      fireEvent.click(firstCard!);

      // Edit modal should open
      await waitFor(() => {
        const dialogs = document.querySelectorAll("[role='dialog']");
        expect(dialogs.length).toBeGreaterThan(0);
        expect(document.body.textContent).toContain("Edit Entry");
      });
    });

    it("pre-fills edit modal with clicked entry data", async () => {
      renderPage();

      await waitFor(() => {
        expect(document.body.textContent).toContain("GitHub");
      });

      // Click first card
      const firstCard = document.querySelector("li");
      fireEvent.click(firstCard!);

      // Wait for edit form to load with pre-filled values
      await waitFor(() => {
        const inputs = Array.from(document.querySelectorAll("input"));
        expect(inputs.find((i) => i.value === "GitHub")).toBeTruthy();
        expect(inputs.find((i) => i.value === "github.com")).toBeTruthy();
      });
    });
  });

  // -- Delete entry integration tests (Story 3.8) ----------------------------

  describe("delete entry", () => {
    it("shows Delete button in edit modal", async () => {
      renderPage();

      await waitFor(() => {
        expect(document.body.textContent).toContain("GitHub");
      });

      // Click entry to open edit modal
      const firstCard = document.querySelector("li");
      fireEvent.click(firstCard!);

      await waitFor(() => {
        expect(document.body.textContent).toContain("Edit Entry");
      });

      // Delete button should be visible
      const deleteBtn = Array.from(document.querySelectorAll("button")).find(
        (b) => b.textContent === "Delete",
      );
      expect(deleteBtn).toBeTruthy();
    });

    it("opens confirmation modal when Delete is clicked", async () => {
      renderPage();

      await waitFor(() => {
        expect(document.body.textContent).toContain("GitHub");
      });

      // Click entry → edit modal
      const firstCard = document.querySelector("li");
      fireEvent.click(firstCard!);

      await waitFor(() => {
        expect(document.body.textContent).toContain("Edit Entry");
      });

      // Wait for form to populate, then click Delete
      await waitFor(() => {
        const inputs = Array.from(document.querySelectorAll("input"));
        expect(inputs.find((i) => i.value === "GitHub")).toBeTruthy();
      });

      const deleteBtn = Array.from(document.querySelectorAll("button")).find(
        (b) => b.textContent === "Delete",
      );
      fireEvent.click(deleteBtn!);

      // Confirmation modal should appear
      await waitFor(() => {
        expect(document.body.textContent).toContain("Delete Entry");
        expect(document.body.textContent).toContain("Delete 'GitHub'?");
        expect(document.body.textContent).toContain("This action cannot be undone.");
      });
    });

    it("deletes entry and shows toast on confirm", async () => {
      renderPage();

      await waitFor(() => {
        expect(document.body.textContent).toContain("GitHub");
      });

      // Click entry → edit modal
      const firstCard = document.querySelector("li");
      fireEvent.click(firstCard!);

      await waitFor(() => {
        const inputs = Array.from(document.querySelectorAll("input"));
        expect(inputs.find((i) => i.value === "GitHub")).toBeTruthy();
      });

      // Click Delete → confirmation modal
      const deleteBtn = Array.from(document.querySelectorAll("button")).find(
        (b) => b.textContent === "Delete",
      );
      fireEvent.click(deleteBtn!);

      await waitFor(() => {
        expect(document.body.textContent).toContain("Delete 'GitHub'?");
      });

      // Click the confirm "Delete" button in the confirmation modal
      // There are now two "Delete" buttons — one in edit modal, one in confirm modal
      const allDeleteBtns = Array.from(document.querySelectorAll("button")).filter(
        (b) => b.textContent === "Delete",
      );
      // The last "Delete" button is in the confirmation dialog
      const confirmDeleteBtn = allDeleteBtns[allDeleteBtns.length - 1];
      fireEvent.click(confirmDeleteBtn);

      await waitFor(() => {
        expect(mockToast.success).toHaveBeenCalledWith("Entry deleted");
      });
    });

    it("preserves entry when cancel is clicked in confirmation", async () => {
      renderPage();

      await waitFor(() => {
        expect(document.body.textContent).toContain("GitHub");
      });

      // Click entry → edit modal
      const firstCard = document.querySelector("li");
      fireEvent.click(firstCard!);

      await waitFor(() => {
        const inputs = Array.from(document.querySelectorAll("input"));
        expect(inputs.find((i) => i.value === "GitHub")).toBeTruthy();
      });

      // Click Delete → confirmation modal
      const deleteBtn = Array.from(document.querySelectorAll("button")).find(
        (b) => b.textContent === "Delete",
      );
      fireEvent.click(deleteBtn!);

      await waitFor(() => {
        expect(document.body.textContent).toContain("Delete 'GitHub'?");
      });

      // Click Cancel in confirmation modal
      const cancelBtns = Array.from(document.querySelectorAll("button")).filter(
        (b) => b.textContent === "Cancel",
      );
      const confirmCancelBtn = cancelBtns[cancelBtns.length - 1];
      fireEvent.click(confirmCancelBtn);

      // Confirmation should close but edit modal stays open
      await waitFor(() => {
        expect(document.body.textContent).not.toContain("This action cannot be undone.");
      });

      // Entry should still exist
      expect(mockToast.success).not.toHaveBeenCalled();
    });
  });

  // -- Sidebar type filtering tests -------------------------------------------

  describe("type filtering via URL params", () => {
    function renderPageAtUrl(url: string) {
      const history = createMemoryHistory();
      history.set({ value: url });
      return render(() => (
        <MemoryRouter
          history={history}
          root={(props) => <>{props.children}</>}
        >
          <Route path="/entries" component={EntriesPage} />
        </MemoryRouter>
      ));
    }

    it("shows only TOTP/HOTP entries when ?type=totp", async () => {
      renderPageAtUrl("/entries?type=totp");

      await waitFor(() => {
        // TOTP entries should be visible
        expect(document.body.textContent).toContain("GitHub");
        expect(document.body.textContent).toContain("Google");
      });

      // Non-TOTP entries should be hidden
      expect(document.body.textContent).not.toContain("Bitcoin Wallet");
      expect(document.body.textContent).not.toContain("Server Credentials");
    });

    it("shows only seed entries when ?type=seed", async () => {
      renderPageAtUrl("/entries?type=seed");

      await waitFor(() => {
        expect(document.body.textContent).toContain("Bitcoin Wallet");
      });

      // TOTP entries should be hidden
      expect(document.body.textContent).not.toContain("GitHub");
      expect(document.body.textContent).not.toContain("Google");
    });

    it("shows all entries when no type param", async () => {
      renderPage();

      await waitFor(() => {
        expect(document.body.textContent).toContain("GitHub");
        expect(document.body.textContent).toContain("Bitcoin Wallet");
        expect(document.body.textContent).toContain("Server Credentials");
      });
    });
  });
});
