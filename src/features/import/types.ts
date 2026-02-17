/**
 * TypeScript DTO types mirroring Rust import DTOs (camelCase via serde).
 * Source: src-tauri/src/commands/import.rs
 */

// ---------------------------------------------------------------------------
// Import source enum
// ---------------------------------------------------------------------------

export type ImportSource = "google-auth" | "aegis" | "twofas";

// ---------------------------------------------------------------------------
// Response DTOs — returned by validate/confirm commands
// ---------------------------------------------------------------------------

/** Preview of a single importable entry. */
export interface ImportEntryPreviewDto {
  index: number;
  name: string;
  issuer?: string;
  entryType: string;
  algorithm: string;
  digits: number;
}

/** Duplicate entry information for the validation report. */
export interface DuplicateInfoDto {
  index: number;
  name: string;
  issuer?: string;
  existingId: string;
  existingName: string;
}

/** Unsupported entry information for the validation report. */
export interface UnsupportedInfoDto {
  index: number;
  name: string;
  issuer?: string;
  reason: string;
}

/** Malformed entry information for the validation report. */
export interface MalformedInfoDto {
  index: number;
  reason: string;
}

/** Full validation report returned by the validate phase. */
export interface ValidationReportDto {
  totalParsed: number;
  validCount: number;
  duplicateCount: number;
  unsupportedCount: number;
  malformedCount: number;
  validEntries: ImportEntryPreviewDto[];
  duplicates: DuplicateInfoDto[];
  unsupported: UnsupportedInfoDto[];
  malformed: MalformedInfoDto[];
}

/** Result DTO for a completed import. */
export interface ImportSummaryDto {
  imported: number;
  skipped: number;
  importedIds: string[];
}
