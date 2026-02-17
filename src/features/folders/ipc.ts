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

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ---------------------------------------------------------------------------
// IPC functions
// ---------------------------------------------------------------------------

export async function createFolder(name: string): Promise<FolderDto> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<FolderDto>("create_folder", { name });
  }

  await delay(50);
  nextFolderCounter++;
  const now = new Date().toISOString();
  const folder: FolderWithCountDto = {
    id: `folder-mock-${nextFolderCounter.toString().padStart(3, "0")}`,
    name: name.trim(),
    sortOrder: mockFolders.length,
    createdAt: now,
    updatedAt: now,
    entryCount: 0,
  };
  mockFolders.push(folder);
  return folder;
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
