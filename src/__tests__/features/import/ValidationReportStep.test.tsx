import { render, fireEvent, waitFor } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { ValidationReportStep } from "../../../features/import/ValidationReportStep";
import type { ValidationReportDto } from "../../../features/import/types";

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

// Mock the entries IPC (needed by AddEntryModal)
vi.mock("../../../features/entries/ipc", () => ({
  addEntry: vi.fn().mockResolvedValue({ id: "mock-id", name: "Test", entryType: "totp", algorithm: "SHA1", digits: 6, period: 30, pinned: false, createdAt: "", updatedAt: "" }),
  _resetMockStore: vi.fn(),
}));

beforeEach(() => {
  mockToast.success.mockClear();
  mockToast.error.mockClear();
});

function makeReport(overrides?: Partial<ValidationReportDto>): ValidationReportDto {
  return {
    totalParsed: 10,
    validCount: 6,
    duplicateCount: 2,
    unsupportedCount: 1,
    malformedCount: 1,
    validEntries: [
      { index: 0, name: "GitHub", issuer: "github.com", entryType: "totp", algorithm: "SHA1", digits: 6 },
      { index: 1, name: "GitLab", issuer: undefined, entryType: "totp", algorithm: "SHA1", digits: 6 },
      { index: 2, name: "AWS", issuer: "amazon.com", entryType: "totp", algorithm: "SHA256", digits: 8 },
      { index: 3, name: "Bitwarden", issuer: "bitwarden.com", entryType: "totp", algorithm: "SHA1", digits: 6 },
      { index: 4, name: "Discord", issuer: "discord.com", entryType: "totp", algorithm: "SHA1", digits: 6 },
      { index: 5, name: "Twitter", issuer: "x.com", entryType: "totp", algorithm: "SHA1", digits: 6 },
    ],
    duplicates: [
      { index: 6, name: "Google", issuer: "google.com", existingId: "id-1", existingName: "Google" },
      { index: 7, name: "Outlook", issuer: "microsoft.com", existingId: "id-2", existingName: "Outlook" },
    ],
    unsupported: [
      { index: 8, name: "Steam Guard", issuer: "Steam", reason: "Unsupported type: Steam" },
    ],
    malformed: [
      { index: 9, reason: "Missing secret key" },
    ],
    ...overrides,
  };
}

describe("ValidationReportStep", () => {
  it("renders summary counts", () => {
    const report = makeReport();
    const { getByText } = render(() => (
      <ValidationReportStep report={report} onConfirm={vi.fn()} />
    ));

    expect(getByText("10")).toBeDefined(); // totalParsed
    expect(getByText("6")).toBeDefined();  // validCount
    expect(getByText("2")).toBeDefined();  // duplicateCount
  });

  it("renders valid entries with checkboxes", () => {
    const report = makeReport();
    const { getByText, container } = render(() => (
      <ValidationReportStep report={report} onConfirm={vi.fn()} />
    ));

    expect(getByText("GitHub")).toBeDefined();
    expect(getByText("GitLab")).toBeDefined();

    // All valid entries should have checkboxes (checked by default)
    const checkboxes = container.querySelectorAll("input[type='checkbox']");
    expect(checkboxes.length).toBe(6);
    checkboxes.forEach((cb) => {
      expect((cb as HTMLInputElement).checked).toBe(true);
    });
  });

  it("shows correct import count", () => {
    const report = makeReport();
    const { getByText } = render(() => (
      <ValidationReportStep report={report} onConfirm={vi.fn()} />
    ));

    expect(getByText("6 selected")).toBeDefined();
  });

  it("updates import count when checkbox is toggled", () => {
    const report = makeReport();
    const { getByText, container } = render(() => (
      <ValidationReportStep report={report} onConfirm={vi.fn()} />
    ));

    const checkboxes = container.querySelectorAll("input[type='checkbox']");
    // Uncheck first entry
    fireEvent.change(checkboxes[0], { target: { checked: false } });

    expect(getByText("5 selected")).toBeDefined();
  });

  it("calls onConfirm with correct skip indices", () => {
    const report = makeReport();
    const onConfirm = vi.fn();
    const { container } = render(() => (
      <ValidationReportStep report={report} onConfirm={onConfirm} />
    ));

    // Uncheck entries at index 0 and 2
    const checkboxes = container.querySelectorAll("input[type='checkbox']");
    fireEvent.change(checkboxes[0], { target: { checked: false } });
    fireEvent.change(checkboxes[2], { target: { checked: false } });

    // Find the import button by text
    const buttons = container.querySelectorAll("button");
    let importButton: HTMLButtonElement | null = null;
    buttons.forEach((btn) => {
      if (btn.textContent?.includes("Import")) {
        importButton = btn;
      }
    });
    expect(importButton).not.toBeNull();
    fireEvent.click(importButton!);

    // Skipped: unchecked valid indices (0, 2) + all duplicate indices (6, 7) since none are force-imported
    expect(onConfirm).toHaveBeenCalledWith([0, 2, 6, 7]);
  });

  it("disables import button when no entries are selected", () => {
    const report = makeReport({
      validCount: 1,
      validEntries: [
        { index: 0, name: "Only One", entryType: "totp", algorithm: "SHA1", digits: 6 },
      ],
    });
    const { container } = render(() => (
      <ValidationReportStep report={report} onConfirm={vi.fn()} />
    ));

    // Click the checkbox to uncheck it (toggleEntry via onChange)
    const checkboxes = container.querySelectorAll("input[type='checkbox']");
    fireEvent.click(checkboxes[0]);

    // Button component uses aria-disabled instead of native disabled
    const buttons = container.querySelectorAll("button");
    const importButton = Array.from(buttons).find(btn => btn.textContent?.includes("Import")) ?? null;
    expect(importButton?.getAttribute("aria-disabled")).toBe("true");
  });

  it("shows empty state when no valid entries", () => {
    const report = makeReport({
      validCount: 0,
      validEntries: [],
      duplicateCount: 0,
      duplicates: [],
      unsupportedCount: 0,
      unsupported: [],
      malformedCount: 5,
      totalParsed: 5,
    });
    const { getByText } = render(() => (
      <ValidationReportStep report={report} onConfirm={vi.fn()} />
    ));

    expect(getByText("No importable accounts found")).toBeDefined();
  });

  it("shows duplicates section collapsed by default", () => {
    const report = makeReport();
    const { queryByText } = render(() => (
      <ValidationReportStep report={report} onConfirm={vi.fn()} />
    ));

    // Duplicate entry name should not be visible (collapsed)
    expect(queryByText("Already exists")).toBeNull();
  });

  it("expands duplicates section when header is clicked", () => {
    const report = makeReport();
    const { container, getByText } = render(() => (
      <ValidationReportStep report={report} onConfirm={vi.fn()} />
    ));

    // Find the Duplicates header button
    const headers = container.querySelectorAll("button");
    let dupHeader: HTMLButtonElement | null = null;
    headers.forEach((btn) => {
      if (btn.textContent?.includes("Duplicates")) {
        dupHeader = btn;
      }
    });
    expect(dupHeader).not.toBeNull();
    fireEvent.click(dupHeader!);

    const alreadyExistsElements = container.querySelectorAll("[class*='duplicateMatch']");
    expect(alreadyExistsElements.length).toBe(2);
    expect(alreadyExistsElements[0].textContent).toBe("Already exists");
  });

  it("uses correct count when only 1 selected", () => {
    const report = makeReport({
      validCount: 1,
      validEntries: [
        { index: 0, name: "Single", entryType: "totp", algorithm: "SHA1", digits: 6 },
      ],
    });
    const { getByText } = render(() => (
      <ValidationReportStep report={report} onConfirm={vi.fn()} />
    ));

    expect(getByText("1 selected")).toBeDefined();
  });

  it("renders issuer for entries that have one", () => {
    const report = makeReport();
    const { getByText, queryByText } = render(() => (
      <ValidationReportStep report={report} onConfirm={vi.fn()} />
    ));

    // GitHub has issuer
    expect(getByText("github.com")).toBeDefined();
    // GitLab has no issuer — issuer text should not be rendered
  });

  // ---------------------------------------------------------------------------
  // Story 5.5: "Add manually" buttons
  // ---------------------------------------------------------------------------

  describe("unsupported entry — Add manually (AC1)", () => {
    it("opens AddEntryModal with pre-populated name and issuer", async () => {
      const report = makeReport();
      const { container, findByText } = render(() => (
        <ValidationReportStep report={report} onConfirm={vi.fn()} />
      ));

      // Expand the unsupported section first
      const headers = container.querySelectorAll("button");
      let unsupportedHeader: HTMLButtonElement | null = null;
      headers.forEach((btn) => {
        if (btn.textContent?.includes("Unsupported")) {
          unsupportedHeader = btn;
        }
      });
      expect(unsupportedHeader).not.toBeNull();
      fireEvent.click(unsupportedHeader!);

      // Click "Add manually" on the unsupported entry
      await waitFor(() => {
        const addBtn = Array.from(container.querySelectorAll("button")).find(
          (b) => b.textContent === "Add manually",
        );
        expect(addBtn).toBeTruthy();
        fireEvent.click(addBtn!);
      });

      // AddEntryModal should open with pre-populated fields from unsupported entry
      await waitFor(() => {
        expect(document.body.textContent).toContain("Add TOTP Entry");
        // Verify name and issuer are pre-populated from UnsupportedInfoDto
        const inputs = Array.from(document.querySelectorAll("input"));
        const nameInput = inputs.find((i) => i.value === "Steam Guard");
        expect(nameInput).toBeTruthy();
        const issuerInput = inputs.find((i) => i.value === "Steam");
        expect(issuerInput).toBeTruthy();
      });
    });
  });

  describe("malformed entry — Add manually (AC1)", () => {
    it("opens AddEntryModal with empty initialData", async () => {
      const report = makeReport();
      const { container } = render(() => (
        <ValidationReportStep report={report} onConfirm={vi.fn()} />
      ));

      // Expand malformed section
      const headers = container.querySelectorAll("button");
      let malformedHeader: HTMLButtonElement | null = null;
      headers.forEach((btn) => {
        if (btn.textContent?.includes("Malformed")) {
          malformedHeader = btn;
        }
      });
      expect(malformedHeader).not.toBeNull();
      fireEvent.click(malformedHeader!);

      // Click "Add manually" on the malformed entry
      await waitFor(() => {
        const addButtons = Array.from(container.querySelectorAll("button")).filter(
          (b) => b.textContent === "Add manually",
        );
        // Should find the one in malformed section
        expect(addButtons.length).toBeGreaterThan(0);
        fireEvent.click(addButtons[addButtons.length - 1]);
      });

      // AddEntryModal should open
      await waitFor(() => {
        expect(document.body.textContent).toContain("Add TOTP Entry");
      });
    });
  });

  // ---------------------------------------------------------------------------
  // Story 5.5: Duplicate "Import anyway" toggle (AC2)
  // ---------------------------------------------------------------------------

  describe("duplicate Import anyway toggle (AC2)", () => {
    it("increases import count when 'Import anyway' is clicked", async () => {
      const report = makeReport();
      const { container, getByText } = render(() => (
        <ValidationReportStep report={report} onConfirm={vi.fn()} />
      ));

      // Initially: 6 valid selected
      expect(getByText("6 selected")).toBeDefined();

      // Expand duplicates section
      const headers = container.querySelectorAll("button");
      let dupHeader: HTMLButtonElement | null = null;
      headers.forEach((btn) => {
        if (btn.textContent?.includes("Duplicates")) {
          dupHeader = btn;
        }
      });
      fireEvent.click(dupHeader!);

      // Click "Import anyway" on the first duplicate
      await waitFor(() => {
        const importAnywayBtn = Array.from(container.querySelectorAll("button")).find(
          (b) => b.textContent === "Import anyway",
        );
        expect(importAnywayBtn).toBeTruthy();
        fireEvent.click(importAnywayBtn!);
      });

      // Count should increase to 7 (6 valid + 1 force-imported duplicate)
      expect(getByText("7 selected")).toBeDefined();
    });

    it("excludes force-imported duplicate from skipIndices", async () => {
      const report = makeReport();
      const onConfirm = vi.fn();
      const { container } = render(() => (
        <ValidationReportStep report={report} onConfirm={onConfirm} />
      ));

      // Expand duplicates section
      const headers = container.querySelectorAll("button");
      let dupHeader: HTMLButtonElement | null = null;
      headers.forEach((btn) => {
        if (btn.textContent?.includes("Duplicates")) {
          dupHeader = btn;
        }
      });
      fireEvent.click(dupHeader!);

      // Click "Import anyway" for first duplicate (index 6)
      await waitFor(() => {
        const importAnywayBtn = Array.from(container.querySelectorAll("button")).find(
          (b) => b.textContent === "Import anyway",
        );
        expect(importAnywayBtn).toBeTruthy();
        fireEvent.click(importAnywayBtn!);
      });

      // Click Import button
      const importBtn = Array.from(container.querySelectorAll("button")).find(
        (b) => b.textContent?.includes("Import selected"),
      );
      expect(importBtn).toBeTruthy();
      fireEvent.click(importBtn!);

      // skipIndices should only include duplicate index 7 (the un-toggled one),
      // NOT index 6 (the force-imported one)
      expect(onConfirm).toHaveBeenCalledWith([7]);
    });

    it("reverts import count when 'Skip' is clicked after 'Import anyway'", async () => {
      const report = makeReport();
      const { container, getByText } = render(() => (
        <ValidationReportStep report={report} onConfirm={vi.fn()} />
      ));

      // Initially: 6 valid selected
      expect(getByText("6 selected")).toBeDefined();

      // Expand duplicates section
      const headers = container.querySelectorAll("button");
      let dupHeader: HTMLButtonElement | null = null;
      headers.forEach((btn) => {
        if (btn.textContent?.includes("Duplicates")) {
          dupHeader = btn;
        }
      });
      fireEvent.click(dupHeader!);

      // Click "Import anyway"
      await waitFor(() => {
        const importAnywayBtn = Array.from(container.querySelectorAll("button")).find(
          (b) => b.textContent === "Import anyway",
        );
        expect(importAnywayBtn).toBeTruthy();
        fireEvent.click(importAnywayBtn!);
      });

      expect(getByText("7 selected")).toBeDefined();

      // Click "Skip" to revert
      const skipBtn = Array.from(container.querySelectorAll("button")).find(
        (b) => b.textContent === "Skip",
      );
      expect(skipBtn).toBeTruthy();
      fireEvent.click(skipBtn!);

      // Should revert to 6
      expect(getByText("6 selected")).toBeDefined();
    });

    it("includes both duplicate indices in skipIndices when neither is force-imported", () => {
      const report = makeReport();
      const onConfirm = vi.fn();
      const { container } = render(() => (
        <ValidationReportStep report={report} onConfirm={onConfirm} />
      ));

      // Don't toggle any duplicates — just click Import
      const importBtn = Array.from(container.querySelectorAll("button")).find(
        (b) => b.textContent?.includes("Import selected"),
      );
      expect(importBtn).toBeTruthy();
      fireEvent.click(importBtn!);

      // skipIndices should include both duplicate indices (6 and 7)
      const skipIndices = onConfirm.mock.calls[0][0] as number[];
      expect(skipIndices).toContain(6);
      expect(skipIndices).toContain(7);
    });
  });
});
