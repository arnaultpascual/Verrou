/**
 * Export IPC service.
 * Wraps Tauri invoke() calls for vault export operations.
 * Falls back to mocks in browser dev mode.
 */

import { getVaultDir } from "../vault/ipc";

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

export interface ExportVaultResponse {
  entryCount: number;
  folderCount: number;
  attachmentCount: number;
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
 * Export the entire vault as an encrypted .verrou file.
 * Requires the master password for re-authentication.
 */
export async function exportVault(
  password: string,
  savePath: string,
): Promise<ExportVaultResponse> {
  if (!IS_TAURI) {
    // Mock for browser dev mode
    await new Promise((r) => setTimeout(r, 2000));
    return { entryCount: 12, folderCount: 3, attachmentCount: 2 };
  }

  const { invoke } = await import("@tauri-apps/api/core");
  return invoke<ExportVaultResponse>("export_vault", {
    password,
    savePath,
    vaultDir: getVaultDir(),
  });
}

/**
 * Open a native save dialog for selecting the export file location.
 * Returns null if the user cancels.
 */
export async function pickExportLocation(): Promise<string | null> {
  if (!IS_TAURI) {
    return "/mock/vault-export.verrou";
  }

  const { save } = await import("@tauri-apps/plugin-dialog");
  const path = await save({
    defaultPath: "vault-export.verrou",
    title: "Export Vault",
    filters: [{ name: "VERROU Vault", extensions: ["verrou"] }],
  });

  return path ?? null;
}
