/**
 * Folder CRUD IPC service.
 * Mirrors Rust folder DTOs for type-safe communication.
 */

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

export interface FolderDto {
  id: string;
  name: string;
  parentId?: string;
  sortOrder: number;
  createdAt: string;
  updatedAt: string;
}

export interface FolderWithCountDto extends FolderDto {
  entryCount: number;
}

// ---------------------------------------------------------------------------
// Runtime detection
// ---------------------------------------------------------------------------

const IS_TAURI = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

// ---------------------------------------------------------------------------
// Mock data store
// ---------------------------------------------------------------------------

let mockFolders: FolderWithCountDto[] = [
  {
    id: "folder-mock-001",
    name: "Work",
    sortOrder: 0,
    createdAt: "2026-02-10T10:00:00Z",
    updatedAt: "2026-02-10T10:00:00Z",
    entryCount: 0,
  },
  {
    id: "folder-mock-002",
    name: "Personal",
    sortOrder: 1,
    createdAt: "2026-02-10T10:00:00Z",
    updatedAt: "2026-02-10T10:00:00Z",
    entryCount: 0,
  },
];

let nextFolderCounter = 10;

const INITIAL_MOCK_FOLDERS: FolderWithCountDto[] = [
  {
    id: "folder-mock-001",
    name: "Work",
    sortOrder: 0,
    createdAt: "2026-02-10T10:00:00Z",
    updatedAt: "2026-02-10T10:00:00Z",
    entryCount: 0,
  },
  {
    id: "folder-mock-002",
    name: "Personal",
    sortOrder: 1,
    createdAt: "2026-02-10T10:00:00Z",
    updatedAt: "2026-02-10T10:00:00Z",
    entryCount: 0,
  },
];

/** Reset the mock folder store to its initial state (for tests). */
export function _resetMockFolders(): void {
  mockFolders = INITIAL_MOCK_FOLDERS.map((f) => ({ ...f }));
  nextFolderCounter = 10;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ---------------------------------------------------------------------------
// IPC functions
// ---------------------------------------------------------------------------

export async function createFolder(name: string, parentId?: string): Promise<FolderDto> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<FolderDto>("create_folder", { name, parentId });
  }

  await delay(50);
  nextFolderCounter++;
  const now = new Date().toISOString();
  // Append after existing siblings in the same group (mirrors the backend).
  const siblingMax = mockFolders
    .filter((f) => (f.parentId ?? undefined) === (parentId ?? undefined))
    .reduce((max, f) => Math.max(max, f.sortOrder), -1);
  const folder: FolderWithCountDto = {
    id: `folder-mock-${nextFolderCounter.toString().padStart(3, "0")}`,
    name: name.trim(),
    parentId,
    sortOrder: siblingMax + 1,
    createdAt: now,
    updatedAt: now,
    entryCount: 0,
  };
  mockFolders.push(folder);
  return folder;
}

/**
 * Move a folder under `newParentId` (top level when `undefined`) at `position`
 * among its new siblings. Reparenting and reordering both go through here.
 *
 * The mock mirrors the Rust `move_folder`: it rejects cycles and densely
 * renumbers the destination sibling group so behaviour matches in dev/tests.
 */
export async function moveFolder(
  folderId: string,
  newParentId: string | undefined,
  position: number,
): Promise<FolderDto> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<FolderDto>("move_folder", { folderId, newParentId, position });
  }

  await delay(50);
  const folder = mockFolders.find((f) => f.id === folderId);
  if (!folder) throw "Folder not found.";

  // Cycle guard: destination must not be the folder itself or a descendant.
  if (newParentId) {
    if (newParentId === folderId) throw "A folder cannot be moved into itself.";
    let cursor: string | undefined = newParentId;
    while (cursor) {
      if (cursor === folderId) {
        throw "A folder cannot be moved into one of its own subfolders.";
      }
      cursor = mockFolders.find((f) => f.id === cursor)?.parentId;
    }
  }

  const siblings = mockFolders
    .filter((f) => (f.parentId ?? undefined) === (newParentId ?? undefined) && f.id !== folderId)
    .sort((a, b) => a.sortOrder - b.sortOrder || a.name.localeCompare(b.name));
  const clamped = Math.max(0, Math.min(position, siblings.length));
  siblings.splice(clamped, 0, folder);
  folder.parentId = newParentId;
  siblings.forEach((f, i) => {
    f.sortOrder = i;
  });
  folder.updatedAt = new Date().toISOString();
  return { ...folder };
}

export async function listFolders(): Promise<FolderWithCountDto[]> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<FolderWithCountDto[]>("list_folders");
  }

  await delay(30);
  return [...mockFolders];
}

export async function renameFolder(folderId: string, newName: string): Promise<FolderDto> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<FolderDto>("rename_folder", { folderId, newName });
  }

  await delay(50);
  const folder = mockFolders.find((f) => f.id === folderId);
  if (!folder) throw "Folder not found.";
  folder.name = newName.trim();
  folder.updatedAt = new Date().toISOString();
  return { ...folder };
}

export async function deleteFolder(folderId: string): Promise<void> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke("delete_folder", { folderId });
  }

  await delay(50);
  const idx = mockFolders.findIndex((f) => f.id === folderId);
  if (idx === -1) throw "Folder not found.";
  mockFolders.splice(idx, 1);
}
