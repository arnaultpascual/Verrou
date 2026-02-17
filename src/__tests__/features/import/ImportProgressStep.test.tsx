import { render, waitFor } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { ImportProgressStep } from "../../../features/import/ImportProgressStep";
import type { ValidationReportDto, ImportSummaryDto } from "../../../features/import/types";

// Mock IPC
const mockConfirmGoogleAuth = vi.fn<(...args: unknown[]) => Promise<ImportSummaryDto>>();
const mockConfirmAegis = vi.fn<(...args: unknown[]) => Promise<ImportSummaryDto>>();
const mockConfirmTwofas = vi.fn<(...args: unknown[]) => Promise<ImportSummaryDto>>();

vi.mock("../../../features/import/ipc", () => ({
  confirmGoogleAuthImport: (...args: unknown[]) => mockConfirmGoogleAuth(...args),
  confirmAegisImport: (...args: unknown[]) => mockConfirmAegis(...args),
  confirmTwofasImport: (...args: unknown[]) => mockConfirmTwofas(...args),
}));

function makeReport(): ValidationReportDto {
  return {
    totalParsed: 4,
    validCount: 3,
    duplicateCount: 1,
    unsupportedCount: 0,
    malformedCount: 0,
    validEntries: [
      { index: 0, name: "GitHub", issuer: "github.com", entryType: "totp", algorithm: "SHA1", digits: 6 },
      { index: 1, name: "GitLab", entryType: "totp", algorithm: "SHA1", digits: 6 },
      { index: 2, name: "AWS", issuer: "amazon.com", entryType: "totp", algorithm: "SHA256", digits: 8 },
    ],
    duplicates: [
      { index: 3, name: "Dupe", issuer: "x.com", existingId: "e1", existingName: "Dupe" },
    ],
    unsupported: [],
    malformed: [],
  };
}

function makeSummary(overrides?: Partial<ImportSummaryDto>): ImportSummaryDto {
  return {
    imported: 3,
    skipped: 1,
    importedIds: ["id-1", "id-2", "id-3"],
    ...overrides,
  };
}

describe("ImportProgressStep", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("shows loading state initially", () => {
    mockConfirmGoogleAuth.mockReturnValue(new Promise(() => {})); // never resolves
    const { container } = render(() => (
      <ImportProgressStep
        source="google-auth"
        fileData="data"
        password={null}
        skipIndices={[]}
        report={makeReport()}
        onComplete={vi.fn()}
        onError={vi.fn()}
        onRetry={vi.fn()}
        onDone={vi.fn()}
        summary={null}
        error={null}
      />
    ));
    expect(container.textContent).toContain("Importing entries...");
  });

  it("shows success state with imported count", async () => {
    const summary = makeSummary();
    mockConfirmGoogleAuth.mockResolvedValueOnce(summary);
    const onComplete = vi.fn();

    const { findByText } = render(() => (
      <ImportProgressStep
        source="google-auth"
        fileData="data"
        password={null}
        skipIndices={[3]}
        report={makeReport()}
        onComplete={onComplete}
        onError={vi.fn()}
        onRetry={vi.fn()}
        onDone={vi.fn()}
        summary={null}
        error={null}
      />
    ));

    await waitFor(() => {
      expect(onComplete).toHaveBeenCalledWith(summary);
    });
  });

  it("shows success state when summary is pre-populated", () => {
    const summary = makeSummary();
    const { container } = render(() => (
      <ImportProgressStep
        source="google-auth"
        fileData="data"
        password={null}
        skipIndices={[3]}
        report={makeReport()}
        onComplete={vi.fn()}
        onError={vi.fn()}
        onRetry={vi.fn()}
        onDone={vi.fn()}
        summary={summary}
        error={null}
      />
    ));

    expect(container.textContent).toContain("3 imported");
    expect(container.textContent).toContain("1 skipped");
    // Should not call IPC when summary already present
    expect(mockConfirmGoogleAuth).not.toHaveBeenCalled();
  });

  it("shows imported entry names from report (AC4)", () => {
    const summary = makeSummary();
    const { container } = render(() => (
      <ImportProgressStep
        source="google-auth"
        fileData="data"
        password={null}
        skipIndices={[3]}
        report={makeReport()}
        onComplete={vi.fn()}
        onError={vi.fn()}
        onRetry={vi.fn()}
        onDone={vi.fn()}
        summary={summary}
        error={null}
      />
    ));

    // Valid entries not in skipIndices: GitHub, GitLab, AWS
    expect(container.textContent).toContain("GitHub");
    expect(container.textContent).toContain("GitLab");
    expect(container.textContent).toContain("AWS");
  });

  it("excludes skipped entries from imported names", () => {
    const summary = makeSummary({ imported: 2, skipped: 2 });
    const { container } = render(() => (
      <ImportProgressStep
        source="google-auth"
        fileData="data"
        password={null}
        skipIndices={[1, 3]}
        report={makeReport()}
        onComplete={vi.fn()}
        onError={vi.fn()}
        onRetry={vi.fn()}
        onDone={vi.fn()}
        summary={summary}
        error={null}
      />
    ));

    // Index 1 (GitLab) and 3 (Dupe) should be excluded
    expect(container.textContent).toContain("GitHub");
    expect(container.textContent).not.toContain("GitLab");
    expect(container.textContent).toContain("AWS");
  });

  it("shows error state with 3-part error pattern (AC3)", () => {
    const { container } = render(() => (
      <ImportProgressStep
        source="google-auth"
        fileData="data"
        password={null}
        skipIndices={[]}
        report={makeReport()}
        onComplete={vi.fn()}
        onError={vi.fn()}
        onRetry={vi.fn()}
        onDone={vi.fn()}
        summary={null}
        error="Database write failed"
      />
    ));

    // Title
    expect(container.textContent).toContain("Import failed");
    // Detail
    expect(container.textContent).toContain("No new entries to import.");
    // Action
    expect(container.textContent).toContain("An unexpected error occurred.");
    // Error message
    expect(container.textContent).toContain("Database write failed");
  });

  it("shows 'Go to my vault' button on success", () => {
    const summary = makeSummary();
    const { container } = render(() => (
      <ImportProgressStep
        source="google-auth"
        fileData="data"
        password={null}
        skipIndices={[]}
        report={makeReport()}
        onComplete={vi.fn()}
        onError={vi.fn()}
        onRetry={vi.fn()}
        onDone={vi.fn()}
        summary={summary}
        error={null}
      />
    ));

    expect(container.textContent).toContain("Go to vault");
  });

  it("shows 'Try again' button on error", () => {
    const { container } = render(() => (
      <ImportProgressStep
        source="google-auth"
        fileData="data"
        password={null}
        skipIndices={[]}
        report={makeReport()}
        onComplete={vi.fn()}
        onError={vi.fn()}
        onRetry={vi.fn()}
        onDone={vi.fn()}
        summary={null}
        error="Something went wrong"
      />
    ));

    expect(container.textContent).toContain("Try again");
  });

  it("calls correct IPC for aegis source", async () => {
    const summary = makeSummary();
    mockConfirmAegis.mockResolvedValueOnce(summary);
    const onComplete = vi.fn();

    render(() => (
      <ImportProgressStep
        source="aegis"
        fileData="aegis-data"
        password="secret"
        skipIndices={[1]}
        report={makeReport()}
        onComplete={onComplete}
        onError={vi.fn()}
        onRetry={vi.fn()}
        onDone={vi.fn()}
        summary={null}
        error={null}
      />
    ));

    await waitFor(() => {
      expect(mockConfirmAegis).toHaveBeenCalledWith("aegis-data", "secret", [1]);
      expect(onComplete).toHaveBeenCalledWith(summary);
    });
  });

  it("calls correct IPC for twofas source", async () => {
    const summary = makeSummary();
    mockConfirmTwofas.mockResolvedValueOnce(summary);
    const onComplete = vi.fn();

    render(() => (
      <ImportProgressStep
        source="twofas"
        fileData="twofas-data"
        password={null}
        skipIndices={[]}
        report={makeReport()}
        onComplete={onComplete}
        onError={vi.fn()}
        onRetry={vi.fn()}
        onDone={vi.fn()}
        summary={null}
        error={null}
      />
    ));

    await waitFor(() => {
      expect(mockConfirmTwofas).toHaveBeenCalledWith("twofas-data", undefined, []);
      expect(onComplete).toHaveBeenCalledWith(summary);
    });
  });

  it("calls onError on IPC failure", async () => {
    mockConfirmGoogleAuth.mockRejectedValueOnce("Connection lost");
    const onError = vi.fn();

    render(() => (
      <ImportProgressStep
        source="google-auth"
        fileData="data"
        password={null}
        skipIndices={[]}
        report={makeReport()}
        onComplete={vi.fn()}
        onError={onError}
        onRetry={vi.fn()}
        onDone={vi.fn()}
        summary={null}
        error={null}
      />
    ));

    await waitFor(() => {
      expect(onError).toHaveBeenCalledWith("Connection lost");
    });
  });

  it("does not hide skipped count when 0", () => {
    const summary = makeSummary({ imported: 3, skipped: 0 });
    const { container } = render(() => (
      <ImportProgressStep
        source="google-auth"
        fileData="data"
        password={null}
        skipIndices={[]}
        report={makeReport()}
        onComplete={vi.fn()}
        onError={vi.fn()}
        onRetry={vi.fn()}
        onDone={vi.fn()}
        summary={summary}
        error={null}
      />
    ));

    // "0 skipped" should not appear (skipped section is hidden when count is 0)
    expect(container.textContent).not.toContain("skipped");
  });
});
