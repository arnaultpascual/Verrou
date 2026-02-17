/**
 * Mocked IPC service for import commands.
 * Simulates Tauri invoke() calls until src-tauri/src/commands/import.rs is wired.
 * Function signatures match the Rust DTO types for seamless swap.
 */

import type {
  ImportSource,
  ValidationReportDto,
  ImportSummaryDto,
} from "./types";

// ---------------------------------------------------------------------------
// Mock helpers
// ---------------------------------------------------------------------------

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

let nextMockId = 200;
function mockId(): string {
  nextMockId += 1;
  return `mock-import-${nextMockId.toString(16).padStart(8, "0")}`;
}

// ---------------------------------------------------------------------------
// Mock validation report builder
// ---------------------------------------------------------------------------

function buildMockReport(entryCount: number): ValidationReportDto {
  const validEntries = Array.from({ length: Math.max(0, entryCount - 2) }, (_, i) => ({
    index: i,
    name: `Account ${i + 1}`,
    issuer: i % 2 === 0 ? `issuer-${i + 1}.com` : undefined,
    entryType: "totp",
    algorithm: "SHA1",
    digits: 6,
  }));

  const duplicates = entryCount > 3
    ? [
        {
          index: entryCount - 2,
          name: "Duplicate Account",
          issuer: "example.com",
          existingId: "existing-001",
          existingName: "Duplicate Account",
        },
      ]
    : [];

  const unsupported = entryCount > 2
    ? [
        {
          index: entryCount - 1,
          name: "Steam Guard",
          issuer: "Steam",
          reason: "Unsupported type: Steam",
        },
      ]
    : [];

  return {
    totalParsed: validEntries.length + duplicates.length + unsupported.length,
    validCount: validEntries.length,
    duplicateCount: duplicates.length,
    unsupportedCount: unsupported.length,
    malformedCount: 0,
    validEntries,
    duplicates,
    unsupported,
    malformed: [],
  };
}

// ---------------------------------------------------------------------------
// Google Authenticator
// ---------------------------------------------------------------------------

/** Validate a Google Authenticator migration payload without importing. */
export async function validateGoogleAuthImport(
  migrationData: string,
): Promise<ValidationReportDto> {
  await delay(500);

  if (!migrationData.trim()) {
    throw "Invalid migration data: empty input.";
  }

  return buildMockReport(8);
}

/** Confirm and execute a Google Authenticator import. */
export async function confirmGoogleAuthImport(
  migrationData: string,
  skipIndices: number[],
): Promise<ImportSummaryDto> {
  await delay(800);

  if (!migrationData.trim()) {
    throw "Invalid migration data: empty input.";
  }

  const report = buildMockReport(8);
  const imported = report.validCount - skipIndices.length;

  return {
    imported,
    skipped: skipIndices.length + report.duplicateCount,
    importedIds: Array.from({ length: imported }, () => mockId()),
  };
}

// ---------------------------------------------------------------------------
// Aegis
// ---------------------------------------------------------------------------

/** Validate an Aegis vault export without importing. */
export async function validateAegisImport(
  data: string,
  password?: string,
): Promise<ValidationReportDto> {
  await delay(600);

  if (!data.trim()) {
    throw "Invalid Aegis export: empty file.";
  }

  // Simulate encrypted detection
  const looksEncrypted = data.includes('"db"') && !data.includes('"entries"');
  if (looksEncrypted && !password) {
    throw "This Aegis export is encrypted. Please provide the vault password.";
  }

  return buildMockReport(12);
}

/** Confirm and execute an Aegis import. */
export async function confirmAegisImport(
  data: string,
  password?: string,
  skipIndices?: number[],
): Promise<ImportSummaryDto> {
  await delay(1000);

  if (!data.trim()) {
    throw "Invalid Aegis export: empty file.";
  }

  const report = buildMockReport(12);
  const skips = skipIndices ?? [];
  const imported = report.validCount - skips.length;

  return {
    imported,
    skipped: skips.length + report.duplicateCount,
    importedIds: Array.from({ length: imported }, () => mockId()),
  };
}

// ---------------------------------------------------------------------------
// 2FAS
// ---------------------------------------------------------------------------

/** Validate a 2FAS JSON export without importing. */
export async function validateTwofasImport(
  data: string,
  password?: string,
): Promise<ValidationReportDto> {
  await delay(500);

  if (!data.trim()) {
    throw "Invalid 2FAS export: empty file.";
  }

  // Simulate encrypted detection
  const looksEncrypted =
    data.includes('"servicesEncrypted"') &&
    !data.includes('"servicesEncrypted":null') &&
    !data.includes('"servicesEncrypted": null');
  if (looksEncrypted && !password) {
    throw "This 2FAS export is encrypted. Please provide the backup password.";
  }

  return buildMockReport(6);
}

/** Confirm and execute a 2FAS import. */
export async function confirmTwofasImport(
  data: string,
  password?: string,
  skipIndices?: number[],
): Promise<ImportSummaryDto> {
  await delay(700);

  if (!data.trim()) {
    throw "Invalid 2FAS export: empty file.";
  }

  const report = buildMockReport(6);
  const skips = skipIndices ?? [];
  const imported = report.validCount - skips.length;

  return {
    imported,
    skipped: skips.length + report.duplicateCount,
    importedIds: Array.from({ length: imported }, () => mockId()),
  };
}

// ---------------------------------------------------------------------------
// File reading
// ---------------------------------------------------------------------------

/** Whether we're running inside a Tauri webview (vs. test/browser). */
const IS_TAURI =
  typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

/**
 * Read import file content as text.
 * In production: uses a Rust IPC command (NOT @tauri-apps/plugin-fs, which
 * violates the zero-fs-permission capability policy).
 * In dev/test: returns a mock JSON string.
 */
export async function readImportFile(filePath: string): Promise<string> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<string>("read_import_file", { path: filePath });
  }

  // Mock: return a simple JSON structure
  await delay(100);
  return JSON.stringify({
    services: [
      {
        name: "Mock Service",
        secret: "JBSWY3DPEHPK3PXP",
        otp: {
          tokenType: "TOTP",
          algorithm: "SHA1",
          digits: 6,
          period: 30,
          account: "user@example.com",
          issuer: "MockService",
        },
      },
    ],
    schemaVersion: 4,
  });
}

// ---------------------------------------------------------------------------
// File picker
// ---------------------------------------------------------------------------

/** File filter configuration per import source. */
const FILE_FILTERS: Record<ImportSource, { name: string; extensions: string[] }[]> = {
  "google-auth": [{ name: "Text Files", extensions: ["txt"] }],
  aegis: [{ name: "JSON Files", extensions: ["json"] }],
  twofas: [{ name: "JSON Files", extensions: ["json"] }],
};

/**
 * Open native file picker dialog for selecting an import file.
 * Returns the selected file path, or null if cancelled.
 */
export async function pickImportFile(
  source: ImportSource,
): Promise<string | null> {
  if (IS_TAURI) {
    const { open } = await import("@tauri-apps/plugin-dialog");
    const result = await open({
      filters: FILE_FILTERS[source],
      multiple: false,
      directory: false,
    });
    return result ?? null;
  }

  // Mock: return a fake path for dev/test
  await delay(200);
  return `/tmp/mock-import.${source === "google-auth" ? "txt" : "json"}`;
}

// ---------------------------------------------------------------------------
// Reset for testing
// ---------------------------------------------------------------------------

/** Reset mock state (for testing). */
export function _resetMockState(): void {
  nextMockId = 200;
}
