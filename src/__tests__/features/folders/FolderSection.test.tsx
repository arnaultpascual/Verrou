import { render, fireEvent, waitFor } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { FolderSection } from "../../../features/folders/FolderSection";

// Mock useToast — capture the error spy so we can assert on it.
const mockToastError = vi.fn();
vi.mock("../../../components/useToast", () => ({
  useToast: () => ({
    info: vi.fn(),
    success: vi.fn(),
    error: mockToastError,
    warning: vi.fn(),
  }),
}));

// Mock the IPC module.
const mockListFolders = vi.fn();
const mockCreateFolder = vi.fn();
const mockRenameFolder = vi.fn();
const mockDeleteFolder = vi.fn();

vi.mock("../../../features/folders/ipc", () => ({
  listFolders: (...args: unknown[]) => mockListFolders(...args),
  createFolder: (...args: unknown[]) => mockCreateFolder(...args),
  renameFolder: (...args: unknown[]) => mockRenameFolder(...args),
  deleteFolder: (...args: unknown[]) => mockDeleteFolder(...args),
}));

const SAMPLE_FOLDERS = [
  {
    id: "folder-1",
    name: "Work",
    sortOrder: 0,
    createdAt: "2026-02-10T10:00:00Z",
    updatedAt: "2026-02-10T10:00:00Z",
    entryCount: 3,
  },
];

beforeEach(() => {
  vi.stubGlobal("matchMedia", (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  }));
  mockListFolders.mockResolvedValue([...SAMPLE_FOLDERS]);
});

afterEach(() => {
  vi.restoreAllMocks();
  mockToastError.mockReset();
});

describe("FolderSection", () => {
  it("renders the folder list with names and counts", async () => {
    const { getByText } = render(() => (
      <FolderSection selectedFolderId={null} onSelectFolder={() => {}} />
    ));
    await waitFor(() => {
      expect(getByText("Work")).toBeTruthy();
      expect(getByText("3")).toBeTruthy();
    });
  });

  it("exposes keyboard-accessible rename/delete buttons with aria-labels", async () => {
    const { getByLabelText, getByText } = render(() => (
      <FolderSection selectedFolderId={null} onSelectFolder={() => {}} />
    ));
    await waitFor(() => {
      expect(getByText("Work")).toBeTruthy();
    });
    // Buttons exist in the DOM (focusable <button>s) and carry aria-labels.
    expect(getByLabelText("Rename folder Work")).toBeTruthy();
    expect(getByLabelText("Delete folder Work")).toBeTruthy();
  });

  it("does NOT delete instantly — shows an inline confirmation first", async () => {
    const { getByLabelText, getByText } = render(() => (
      <FolderSection selectedFolderId={null} onSelectFolder={() => {}} />
    ));
    await waitFor(() => {
      expect(getByText("Work")).toBeTruthy();
    });

    fireEvent.click(getByLabelText("Delete folder Work"));

    await waitFor(() => {
      // Confirmation copy states entries are preserved (backend moves them to "All").
      expect(
        getByText('Delete folder "Work"? Entries inside won\'t be deleted.'),
      ).toBeTruthy();
      expect(getByText("Delete")).toBeTruthy();
      expect(getByText("Cancel")).toBeTruthy();
    });
    // Crucially, deleteFolder was NOT called yet.
    expect(mockDeleteFolder).not.toHaveBeenCalled();
  });

  it("calls deleteFolder only after confirm", async () => {
    mockDeleteFolder.mockResolvedValue(undefined);
    const { getByLabelText, getByText } = render(() => (
      <FolderSection selectedFolderId={null} onSelectFolder={() => {}} />
    ));
    await waitFor(() => {
      expect(getByText("Work")).toBeTruthy();
    });

    fireEvent.click(getByLabelText("Delete folder Work"));
    await waitFor(() => expect(getByText("Delete")).toBeTruthy());
    fireEvent.click(getByText("Delete"));

    await waitFor(() => {
      expect(mockDeleteFolder).toHaveBeenCalledWith("folder-1");
    });
  });

  it("cancels the delete confirmation without calling deleteFolder", async () => {
    const { getByLabelText, getByText, queryByText } = render(() => (
      <FolderSection selectedFolderId={null} onSelectFolder={() => {}} />
    ));
    await waitFor(() => {
      expect(getByText("Work")).toBeTruthy();
    });

    fireEvent.click(getByLabelText("Delete folder Work"));
    await waitFor(() => expect(getByText("Cancel")).toBeTruthy());
    fireEvent.click(getByText("Cancel"));

    await waitFor(() => {
      expect(queryByText("Cancel")).toBeNull();
    });
    expect(mockDeleteFolder).not.toHaveBeenCalled();
  });

  it("surfaces a toast error when delete fails", async () => {
    mockDeleteFolder.mockRejectedValue("boom");
    const { getByLabelText, getByText } = render(() => (
      <FolderSection selectedFolderId={null} onSelectFolder={() => {}} />
    ));
    await waitFor(() => {
      expect(getByText("Work")).toBeTruthy();
    });

    fireEvent.click(getByLabelText("Delete folder Work"));
    await waitFor(() => expect(getByText("Delete")).toBeTruthy());
    fireEvent.click(getByText("Delete"));

    await waitFor(() => {
      // String errors are passed straight through to the toast.
      expect(mockToastError).toHaveBeenCalledWith("boom");
    });
  });

  it("surfaces a toast error when create fails", async () => {
    mockCreateFolder.mockRejectedValue(new Error("nope"));
    const { getByText } = render(() => (
      <FolderSection selectedFolderId={null} onSelectFolder={() => {}} />
    ));
    await waitFor(() => {
      expect(getByText("New Folder")).toBeTruthy();
    });

    fireEvent.click(getByText("New Folder"));

    const input = await waitFor(() => {
      const el = document.querySelector("input");
      if (!el) throw new Error("input not rendered");
      return el;
    });
    fireEvent.input(input, { target: { value: "Archive" } });
    fireEvent.keyDown(input, { key: "Enter" });

    await waitFor(() => {
      // Non-string error falls back to the localized message.
      expect(mockToastError).toHaveBeenCalledWith("Failed to create folder.");
    });
  });
});
