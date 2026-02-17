/**
 * IPC service for file attachment commands.
 * Handles Tauri invoke() calls for attachment CRUD and file dialogs.
 */

// ---------------------------------------------------------------------------
// DTOs — mirror Rust camelCase DTOs
// ---------------------------------------------------------------------------

export interface AttachmentMetadataDto {
  id: string;
  entryId: string;
  filename: string;
  mimeType: string;
  sizeBytes: number;
  createdAt: string;
}

// ---------------------------------------------------------------------------
// Tauri detection
// ---------------------------------------------------------------------------

const IS_TAURI =
  typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

// ---------------------------------------------------------------------------
// File dialog helpers
// ---------------------------------------------------------------------------

/** Open a native file picker. Returns the selected file path, or null if cancelled. */
export async function pickFile(): Promise<string | null> {
  if (IS_TAURI) {
    const { open } = await import("@tauri-apps/plugin-dialog");
    const selected = await open({
      multiple: false,
      title: "Select file to attach",
    });
    if (!selected) return null;
    // open() returns string | string[] depending on multiple flag
    return typeof selected === "string" ? selected : selected[0] ?? null;
  }
  // Browser mock: not supported
  return null;
}

/** Open a native "Save As" dialog. Returns the save path, or null if cancelled. */
export async function pickSaveLocation(
  defaultFilename: string,
): Promise<string | null> {
  if (IS_TAURI) {
    const { save } = await import("@tauri-apps/plugin-dialog");
    const path = await save({
      defaultPath: defaultFilename,
      title: "Save attachment as",
    });
    return path ?? null;
  }
  // Browser mock: not supported
  return null;
}

// ---------------------------------------------------------------------------
// IPC functions
// ---------------------------------------------------------------------------

/** Add a file attachment to an entry. */
export async function addAttachment(
  entryId: string,
  filePath: string,
): Promise<AttachmentMetadataDto> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<AttachmentMetadataDto>("add_attachment", {
      entryId,
      filePath,
    });
  }
  // Browser mock
  return {
    id: `mock-${Date.now()}`,
    entryId,
    filename: filePath.split("/").pop() ?? "file",
    mimeType: "application/octet-stream",
    sizeBytes: 1024,
    createdAt: new Date().toISOString(),
  };
}

/** List attachment metadata for an entry (no file content). */
export async function listAttachments(
  entryId: string,
): Promise<AttachmentMetadataDto[]> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<AttachmentMetadataDto[]>("list_attachments", { entryId });
  }
  // Browser mock: no attachments
  return [];
}

/** Export (decrypt and save) an attachment to disk. */
export async function exportAttachment(
  attachmentId: string,
  savePath: string,
): Promise<void> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    await invoke("export_attachment", { attachmentId, savePath });
    return;
  }
  // Browser mock: no-op
}

/** Delete an attachment by ID. */
export async function deleteAttachment(attachmentId: string): Promise<void> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    await invoke("delete_attachment", { attachmentId });
    return;
  }
  // Browser mock: no-op
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Format bytes into a human-readable string. */
export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
