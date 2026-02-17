/**
 * IPC service for .verrou vault import (restore) commands.
 * Wraps Tauri invoke() calls for validate/confirm import phases.
 * Falls back to mocks in browser dev mode.
 */

import { getVaultDir } from "../vault/ipc";

// ---------------------------------------------------------------------------
// DTOs (mirror Rust camelCase serde DTOs)
// ---------------------------------------------------------------------------

export interface VerrouEntryPreviewDto {
  index: number;
  name: string;
  issuer?: string;
  entryType: string;
}

export interface VerrouDuplicateInfoDto {
  index: number;
  name: string;
  issuer?: string;
  entryType: string;
  existingId: string;
  existingName: string;
}

export interface VerrouImportPreviewDto {
  totalEntries: number;
  totalFolders: number;
  totalAttachments: number;
  duplicateCount: number;
  entries: VerrouEntryPreviewDto[];
  duplicates: VerrouDuplicateInfoDto[];
}

export type DuplicateMode = "skip" | "replace";

export interface VerrouImportResultDto {
  importedEntries: number;
  importedFolders: number;
  importedAttachments: number;
  skippedDuplicates: number;
  replacedEntries: number;
}

// ---------------------------------------------------------------------------
// Tauri detection
// ---------------------------------------------------------------------------

const IS_TAURI =
  typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

// ---------------------------------------------------------------------------
// IPC functions
// ---------------------------------------------------------------------------

/**
 * Open a native file picker for selecting a `.verrou` import file.
 * Returns the file path, or `null` if cancelled.
 */
export async function pickVerrouImportFile(): Promise<string | null> {
  if (!IS_TAURI) {
    await new Promise((r) => setTimeout(r, 200));
    return "/tmp/mock-import.verrou";
  }

  const { open } = await import("@tauri-apps/plugin-dialog");
  const result = await open({
    filters: [{ name: "VERROU Vault", extensions: ["verrou"] }],
    multiple: false,
    directory: false,
  });
  return result ?? null;
}

/**
 * Validate a `.verrou` import file (Phase 1).
 * Decrypts the file with the provided password and returns a preview.
 */
export async function validateVerrouImport(
  filePath: string,
  password: string,
): Promise<VerrouImportPreviewDto> {
  if (!IS_TAURI) {
    await new Promise((r) => setTimeout(r, 800));
    return {
      totalEntries: 5,
      totalFolders: 2,
      totalAttachments: 1,
      duplicateCount: 1,
      entries: [
        { index: 0, name: "GitHub", issuer: "github.com", entryType: "totp" },
        { index: 1, name: "GitLab", issuer: "gitlab.com", entryType: "totp" },
        { index: 2, name: "Server Notes", entryType: "secure_note" },
        { index: 3, name: "Bitcoin Wallet", entryType: "seed_phrase" },
        { index: 4, name: "AWS Recovery", entryType: "recovery_codes" },
      ],
      duplicates: [
        {
          index: 0,
          name: "GitHub",
          issuer: "github.com",
          entryType: "totp",
          existingId: "mock-existing-001",
          existingName: "GitHub",
        },
      ],
    };
  }

  const { invoke } = await import("@tauri-apps/api/core");
  return invoke<VerrouImportPreviewDto>("validate_verrou_import", {
    request: { filePath, password },
  });
}

/**
 * Confirm and execute the `.verrou` import (Phase 2).
 */
export async function confirmVerrouImport(
  filePath: string,
  password: string,
  duplicateMode: DuplicateMode,
): Promise<VerrouImportResultDto> {
  if (!IS_TAURI) {
    await new Promise((r) => setTimeout(r, 1500));
    return {
      importedEntries: 4,
      importedFolders: 2,
      importedAttachments: 1,
      skippedDuplicates: duplicateMode === "skip" ? 1 : 0,
      replacedEntries: duplicateMode === "replace" ? 1 : 0,
    };
  }

  const { invoke } = await import("@tauri-apps/api/core");
  return invoke<VerrouImportResultDto>("confirm_verrou_import", {
    request: {
      filePath,
      password,
      duplicateMode,
      vaultDir: getVaultDir(),
    },
  });
}
