import { render, fireEvent, waitFor } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { ExportGuideStep } from "../../../features/import/ExportGuideStep";
import type { ValidationReportDto } from "../../../features/import/types";

// ---------------------------------------------------------------------------
// Mock IPC module
// ---------------------------------------------------------------------------

const mockPickImportFile = vi.fn<(...args: unknown[]) => Promise<string | null>>();
const mockReadImportFile = vi.fn<(...args: unknown[]) => Promise<string>>();
const mockValidateGoogleAuth = vi.fn<(...args: unknown[]) => Promise<ValidationReportDto>>();
const mockValidateAegis = vi.fn<(...args: unknown[]) => Promise<ValidationReportDto>>();
const mockValidateTwofas = vi.fn<(...args: unknown[]) => Promise<ValidationReportDto>>();

vi.mock("../../../features/import/ipc", () => ({
  pickImportFile: (...args: unknown[]) => mockPickImportFile(...args),
  readImportFile: (...args: unknown[]) => mockReadImportFile(...args),
  validateGoogleAuthImport: (...args: unknown[]) => mockValidateGoogleAuth(...args),
  validateAegisImport: (...args: unknown[]) => mockValidateAegis(...args),
  validateTwofasImport: (...args: unknown[]) => mockValidateTwofas(...args),
}));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeMockReport(overrides?: Partial<ValidationReportDto>): ValidationReportDto {
  return {
    totalParsed: 5,
    validCount: 4,
    duplicateCount: 1,
    unsupportedCount: 0,
    malformedCount: 0,
    validEntries: [
      { index: 0, name: "GitHub", issuer: "github.com", entryType: "totp", algorithm: "SHA1", digits: 6 },
      { index: 1, name: "GitLab", entryType: "totp", algorithm: "SHA1", digits: 6 },
      { index: 2, name: "AWS", issuer: "amazon.com", entryType: "totp", algorithm: "SHA256", digits: 8 },
      { index: 3, name: "Discord", issuer: "discord.com", entryType: "totp", algorithm: "SHA1", digits: 6 },
    ],
    duplicates: [{ index: 4, name: "Dupe", issuer: "x.com", existingId: "e1", existingName: "Dupe" }],
    unsupported: [],
    malformed: [],
    ...overrides,
  };
}

/**
 * Find a button by its text content (partial match).
 */
function findButton(container: HTMLElement, text: string): HTMLButtonElement | null {
  const buttons = container.querySelectorAll("button");
  for (const btn of buttons) {
    if (btn.textContent?.includes(text)) return btn;
  }
  return null;
}

/**
 * Find an input element by placeholder.
 */
function findInputByPlaceholder(container: HTMLElement, placeholder: string): HTMLInputElement | null {
  return container.querySelector(`input[placeholder*="${placeholder}"]`) as HTMLInputElement | null;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("ExportGuideStep", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // -------------------------------------------------------------------------
  // Rendering per source
  // -------------------------------------------------------------------------

  describe("Google Authenticator source", () => {
    it("renders the correct guide title", () => {
      const { getByText } = render(() => (
        <ExportGuideStep source="google-auth" onValidated={vi.fn()} />
      ));
      expect(getByText("Export from Google Authenticator")).toBeDefined();
    });

    it("renders numbered instruction steps", () => {
      const { container } = render(() => (
        <ExportGuideStep source="google-auth" onValidated={vi.fn()} />
      ));
      // 5 steps for google-auth
      expect(container.textContent).toContain("1. Open Google Authenticator");
      expect(container.textContent).toContain("5. Paste the migration URI below");
    });

    it("shows a text input for migration URI (not file picker)", () => {
      const { container, queryByText } = render(() => (
        <ExportGuideStep source="google-auth" onValidated={vi.fn()} />
      ));
      const input = findInputByPlaceholder(container, "otpauth-migration");
      expect(input).not.toBeNull();
      expect(queryByText("Choose file...")).toBeNull();
    });

    it("disables parse button when URI is empty", () => {
      const { container } = render(() => (
        <ExportGuideStep source="google-auth" onValidated={vi.fn()} />
      ));
      const parseBtn = findButton(container, "Validate export");
      expect(parseBtn).not.toBeNull();
      expect(
        parseBtn!.disabled || parseBtn!.getAttribute("aria-disabled") === "true",
      ).toBe(true);
    });

    it("enables parse button when URI is entered", () => {
      const { container } = render(() => (
        <ExportGuideStep source="google-auth" onValidated={vi.fn()} />
      ));
      const input = findInputByPlaceholder(container, "otpauth-migration")!;
      fireEvent.input(input, { target: { value: "otpauth-migration://offline?data=abc" } });

      const parseBtn = findButton(container, "Validate export");
      expect(
        !parseBtn!.disabled && parseBtn!.getAttribute("aria-disabled") !== "true",
      ).toBe(true);
    });

    it("calls validateGoogleAuthImport and onValidated on successful parse", async () => {
      const report = makeMockReport();
      mockValidateGoogleAuth.mockResolvedValueOnce(report);

      const onValidated = vi.fn();
      const { container } = render(() => (
        <ExportGuideStep source="google-auth" onValidated={onValidated} />
      ));

      const input = findInputByPlaceholder(container, "otpauth-migration")!;
      fireEvent.input(input, { target: { value: "otpauth-migration://offline?data=abc" } });

      const parseBtn = findButton(container, "Validate export")!;
      fireEvent.click(parseBtn);

      await waitFor(() => {
        expect(mockValidateGoogleAuth).toHaveBeenCalledWith("otpauth-migration://offline?data=abc");
        expect(onValidated).toHaveBeenCalledWith(report, "otpauth-migration://offline?data=abc", undefined);
      });
    });

    it("shows error when parse fails", async () => {
      mockValidateGoogleAuth.mockRejectedValueOnce("Failed to parse the export.");

      const { container, findByText } = render(() => (
        <ExportGuideStep source="google-auth" onValidated={vi.fn()} />
      ));

      const input = findInputByPlaceholder(container, "otpauth-migration")!;
      fireEvent.input(input, { target: { value: "bad-data" } });

      const parseBtn = findButton(container, "Validate export")!;
      fireEvent.click(parseBtn);

      const errorTitle = await findByText("Could not parse this file.");
      expect(errorTitle).toBeDefined();
    });
  });

  describe("Aegis source", () => {
    it("renders the correct guide title", () => {
      const { getByText } = render(() => (
        <ExportGuideStep source="aegis" onValidated={vi.fn()} />
      ));
      expect(getByText("Export from Aegis")).toBeDefined();
    });

    it("shows file picker button (not URI input)", () => {
      const { getByText, container } = render(() => (
        <ExportGuideStep source="aegis" onValidated={vi.fn()} />
      ));
      expect(getByText("Choose file...")).toBeDefined();
      const input = findInputByPlaceholder(container, "otpauth-migration");
      expect(input).toBeNull();
    });

    it("calls pickImportFile when file picker is clicked", async () => {
      mockPickImportFile.mockResolvedValueOnce(null);
      const { getByText } = render(() => (
        <ExportGuideStep source="aegis" onValidated={vi.fn()} />
      ));

      fireEvent.click(getByText("Choose file..."));
      await waitFor(() => {
        expect(mockPickImportFile).toHaveBeenCalledWith("aegis");
      });
    });

    it("shows filename after file is picked", async () => {
      const fileContent = JSON.stringify({ entries: [{ name: "Test" }] });
      mockPickImportFile.mockResolvedValueOnce("/home/user/aegis-backup.json");
      mockReadImportFile.mockResolvedValueOnce(fileContent);
      mockValidateAegis.mockResolvedValueOnce(makeMockReport());

      const { getByText, findByText } = render(() => (
        <ExportGuideStep source="aegis" onValidated={vi.fn()} />
      ));

      fireEvent.click(getByText("Choose file..."));

      const fileName = await findByText("aegis-backup.json");
      expect(fileName).toBeDefined();
    });

    it("auto-parses unencrypted file after pick", async () => {
      const fileContent = JSON.stringify({ entries: [{ name: "Test" }] });
      const report = makeMockReport();
      mockPickImportFile.mockResolvedValueOnce("/home/user/aegis-export.json");
      mockReadImportFile.mockResolvedValueOnce(fileContent);
      mockValidateAegis.mockResolvedValueOnce(report);

      const onValidated = vi.fn();
      const { getByText } = render(() => (
        <ExportGuideStep source="aegis" onValidated={onValidated} />
      ));

      fireEvent.click(getByText("Choose file..."));

      await waitFor(() => {
        expect(mockValidateAegis).toHaveBeenCalledWith(fileContent, undefined);
        expect(onValidated).toHaveBeenCalledWith(report, fileContent, undefined);
      });
    });

    it("prompts for password when encrypted file is detected", async () => {
      // Aegis encrypted: db field is a string (not an object)
      const encrypted = JSON.stringify({ db: "encrypted-blob-base64" });
      mockPickImportFile.mockResolvedValueOnce("/home/user/aegis-encrypted.json");
      mockReadImportFile.mockResolvedValueOnce(encrypted);

      const { getByText, findByText } = render(() => (
        <ExportGuideStep source="aegis" onValidated={vi.fn()} />
      ));

      fireEvent.click(getByText("Choose file..."));

      // Should show password input (label "Backup password")
      const passwordLabel = await findByText("Backup password");
      expect(passwordLabel).toBeDefined();
    });

    it("shows error when file read fails", async () => {
      mockPickImportFile.mockResolvedValueOnce("/home/user/corrupt.json");
      mockReadImportFile.mockRejectedValueOnce(new Error("Cannot read"));

      const { getByText, container } = render(() => (
        <ExportGuideStep source="aegis" onValidated={vi.fn()} />
      ));

      fireEvent.click(getByText("Choose file..."));

      await waitFor(() => {
        const errorTitle = container.querySelector("[class*='errorTitle']");
        expect(errorTitle).not.toBeNull();
        expect(errorTitle!.textContent).toBe("Could not read this file.");
      });
    });

    it("does nothing when file picker is cancelled", async () => {
      mockPickImportFile.mockResolvedValueOnce(null);

      const { getByText, container } = render(() => (
        <ExportGuideStep source="aegis" onValidated={vi.fn()} />
      ));

      fireEvent.click(getByText("Choose file..."));

      await waitFor(() => {
        expect(mockPickImportFile).toHaveBeenCalled();
      });
      expect(mockReadImportFile).not.toHaveBeenCalled();
    });
  });

  describe("2FAS source", () => {
    it("renders the correct guide title", () => {
      const { getByText } = render(() => (
        <ExportGuideStep source="twofas" onValidated={vi.fn()} />
      ));
      expect(getByText("Export from 2FAS")).toBeDefined();
    });

    it("shows file picker button", () => {
      const { getByText } = render(() => (
        <ExportGuideStep source="twofas" onValidated={vi.fn()} />
      ));
      expect(getByText("Choose file...")).toBeDefined();
    });

    it("calls validateTwofasImport for 2FAS files", async () => {
      const fileContent = JSON.stringify({ services: [] });
      const report = makeMockReport();
      mockPickImportFile.mockResolvedValueOnce("/tmp/2fas-backup.json");
      mockReadImportFile.mockResolvedValueOnce(fileContent);
      mockValidateTwofas.mockResolvedValueOnce(report);

      const onValidated = vi.fn();
      const { getByText } = render(() => (
        <ExportGuideStep source="twofas" onValidated={onValidated} />
      ));

      fireEvent.click(getByText("Choose file..."));

      await waitFor(() => {
        expect(mockValidateTwofas).toHaveBeenCalledWith(fileContent, undefined);
        expect(onValidated).toHaveBeenCalledWith(report, fileContent, undefined);
      });
    });
  });

  // -------------------------------------------------------------------------
  // Error handling
  // -------------------------------------------------------------------------

  describe("error handling", () => {
    it("shows encryption error and password field on encrypted error", async () => {
      mockValidateGoogleAuth.mockRejectedValueOnce("This file is encrypted, please provide password.");

      const { container, findByText } = render(() => (
        <ExportGuideStep source="google-auth" onValidated={vi.fn()} />
      ));

      const input = findInputByPlaceholder(container, "otpauth-migration")!;
      fireEvent.input(input, { target: { value: "some-data" } });

      const parseBtn = findButton(container, "Validate export")!;
      fireEvent.click(parseBtn);

      const errorTitle = await findByText("This export is encrypted.");
      expect(errorTitle).toBeDefined();
    });

    it("shows version error for unsupported format (AC3)", async () => {
      mockValidateGoogleAuth.mockRejectedValueOnce("unsupported format version 3");

      const { container, findByText } = render(() => (
        <ExportGuideStep source="google-auth" onValidated={vi.fn()} />
      ));

      const input = findInputByPlaceholder(container, "otpauth-migration")!;
      fireEvent.input(input, { target: { value: "some-data" } });

      const parseBtn = findButton(container, "Validate export")!;
      fireEvent.click(parseBtn);

      const errorTitle = await findByText("This export format is not yet supported.");
      expect(errorTitle).toBeDefined();

      // Should also show the action text
      const action = await findByText("Please check for a VERROU update or try a different export method.");
      expect(action).toBeDefined();
    });

    it("clears error when file picker is clicked again", async () => {
      // First pick fails
      mockPickImportFile.mockResolvedValueOnce("/bad/file.json");
      mockReadImportFile.mockRejectedValueOnce(new Error("Cannot read"));

      const { getByText, container } = render(() => (
        <ExportGuideStep source="aegis" onValidated={vi.fn()} />
      ));

      fireEvent.click(getByText("Choose file..."));
      await waitFor(() => {
        expect(container.querySelector("[class*='errorTitle']")).not.toBeNull();
      });

      // Second pick — error should clear
      mockPickImportFile.mockResolvedValueOnce(null);
      fireEvent.click(getByText("Choose file..."));

      await waitFor(() => {
        expect(container.querySelector("[class*='errorTitle']")).toBeNull();
      });
    });
  });

  // -------------------------------------------------------------------------
  // Parse button state
  // -------------------------------------------------------------------------

  describe("parse button state", () => {
    it("shows 'Validate export' text initially", () => {
      const { container } = render(() => (
        <ExportGuideStep source="google-auth" onValidated={vi.fn()} />
      ));
      const parseBtn = findButton(container, "Validate export");
      expect(parseBtn).not.toBeNull();
    });

    it("disables parse button for file sources when no file loaded", () => {
      const { container } = render(() => (
        <ExportGuideStep source="aegis" onValidated={vi.fn()} />
      ));
      const parseBtn = findButton(container, "Validate export");
      expect(parseBtn).not.toBeNull();
      expect(
        parseBtn!.disabled || parseBtn!.getAttribute("aria-disabled") === "true",
      ).toBe(true);
    });
  });
});
