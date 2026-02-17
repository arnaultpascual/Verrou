/**
 * QR desktop-to-desktop transfer IPC service.
 * Wraps Tauri invoke() calls for QR transfer operations.
 * Falls back to mocks in browser dev mode.
 */

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

/** Request to prepare a QR transfer (sender side). */
export interface QrTransferPrepareRequest {
  entryIds: string[];
  password?: string;
}

/** Result of preparing a QR transfer. */
export interface QrTransferPrepareResult {
  /** Base64-encoded encrypted chunks (each becomes one QR code). */
  chunks: string[];
  /** Human-readable 4-word verification phrase. */
  verificationCode: string;
  /** Number of entries included. */
  totalEntries: number;
  /** Whether any sensitive entries (seed/recovery) are included. */
  hasSensitive: boolean;
}

/** Request to receive a QR transfer (receiver side). */
export interface QrTransferReceiveRequest {
  /** Base64-encoded encrypted chunks scanned from QR codes. */
  chunks: string[];
  /** Verification phrase entered by the user. */
  verificationCode: string;
}

/** Result of receiving a QR transfer. */
export interface QrTransferReceiveResult {
  /** Number of entries successfully imported. */
  importedCount: number;
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
 * Prepare entries for QR transfer on the sending device.
 * Encrypts and chunks selected entries, returns base64 QR data.
 * Requires password if any seed phrases or recovery codes are selected.
 */
export async function prepareQrTransfer(
  request: QrTransferPrepareRequest,
): Promise<QrTransferPrepareResult> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<QrTransferPrepareResult>("prepare_qr_transfer", { request });
  }

  // Mock for browser dev mode
  await new Promise((r) => setTimeout(r, 1500));
  return {
    chunks: [
      "bW9ja19jaHVua18x",
      "bW9ja19jaHVua18y",
      "bW9ja19jaHVua18z",
      "bW9ja19jaHVua180",
      "bW9ja19jaHVua181",
    ],
    verificationCode: "alpha bravo charlie delta",
    totalEntries: request.entryIds.length,
    hasSensitive: false,
  };
}

/**
 * Receive entries from a QR transfer on the receiving device.
 * Decrypts chunks, reassembles payload, imports entries into vault.
 */
export async function receiveQrTransfer(
  request: QrTransferReceiveRequest,
): Promise<QrTransferReceiveResult> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<QrTransferReceiveResult>("receive_qr_transfer", { request });
  }

  // Mock for browser dev mode
  await new Promise((r) => setTimeout(r, 2000));
  return {
    importedCount: request.chunks.length,
  };
}

/**
 * Enable or disable OS-level screen capture protection.
 * Returns true if protection was applied, false if unavailable on this platform.
 */
export async function setScreenCaptureProtection(
  enabled: boolean,
): Promise<boolean> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<boolean>("set_screen_capture_protection", { enabled });
  }

  // Mock: always returns false (no protection in browser dev mode)
  return false;
}

// ---------------------------------------------------------------------------
// File-based transfer (alternative for desktops without webcam)
// ---------------------------------------------------------------------------

/**
 * Save encrypted transfer chunks to a `.verrou-transfer` file.
 * Opens a save dialog, writes the file via Rust backend.
 * Returns the chosen path, or null if the user cancelled.
 */
export async function saveTransferFile(
  chunks: string[],
): Promise<string | null> {
  if (IS_TAURI) {
    const { save } = await import("@tauri-apps/plugin-dialog");
    const path = await save({
      defaultPath: "transfer.verrou-transfer",
      title: "Save Transfer File",
      filters: [{ name: "VERROU Transfer", extensions: ["verrou-transfer"] }],
    });
    if (!path) return null;

    const { invoke } = await import("@tauri-apps/api/core");
    await invoke("save_transfer_file", { path, chunks });
    return path;
  }

  // Mock for browser dev mode
  return "/mock/transfer.verrou-transfer";
}

/**
 * Load encrypted transfer chunks from a `.verrou-transfer` file.
 * Opens a file dialog, reads the file via Rust backend.
 * Returns the chunks, or null if the user cancelled.
 */
export async function loadTransferFile(): Promise<string[] | null> {
  if (IS_TAURI) {
    const { open } = await import("@tauri-apps/plugin-dialog");
    const path = await open({
      title: "Open Transfer File",
      multiple: false,
      filters: [{ name: "VERROU Transfer", extensions: ["verrou-transfer"] }],
    });
    if (!path) return null;

    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<string[]>("load_transfer_file", { path });
  }

  // Mock for browser dev mode
  return ["bW9ja19jaHVua18x", "bW9ja19jaHVua18y", "bW9ja19jaHVua18z"];
}
