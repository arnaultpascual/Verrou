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
const mockMoveFolder = vi.fn();

vi.mock("../../../features/folders/ipc", () => ({
  listFolders: (...args: unknown[]) => mockListFolders(...args),
  createFolder: (...args: unknown[]) => mockCreateFolder(...args),
  renameFolder: (...args: unknown[]) => mockRenameFolder(...args),
  deleteFolder: (...args: unknown[]) => mockDeleteFolder(...args),
  moveFolder: (...args: unknown[]) => mockMoveFolder(...args),
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

// A small tree: Parent → Child, plus a second root folder.
const HIERARCHY = [
  {
    id: "p",
    name: "Parent",
    sortOrder: 0,
    createdAt: "2026-02-10T10:00:00Z",
    updatedAt: "2026-02-10T10:00:00Z",
    entryCount: 0,
  },
  {
    id: "c",
    name: "Child",
    parentId: "p",
    sortOrder: 0,
    createdAt: "2026-02-10T10:00:00Z",
    updatedAt: "2026-02-10T10:00:00Z",
    entryCount: 0,
  },
  {
    id: "p2",
    name: "Second",
    sortOrder: 1,
    createdAt: "2026-02-10T10:00:00Z",
    updatedAt: "2026-02-10T10:00:00Z",
    entryCount: 0,
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
  mockMoveFolder.mockResolvedValue({});
  mockCreateFolder.mockResolvedValue({});
});

afterEach(() => {
  vi.restoreAllMocks();
  mockToastError.mockReset();
  mockMoveFolder.mockReset();
  mockCreateFolder.mockReset();
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
      expect(
        getByText('Delete folder "Work"? Entries inside won\'t be deleted.'),
      ).toBeTruthy();
      expect(getByText("Delete")).toBeTruthy();
      expect(getByText("Cancel")).toBeTruthy();
    });
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
      expect(mockToastError).toHaveBeenCalledWith("Failed to create folder.");
    });
  });

  describe("hierarchy + move", () => {
    beforeEach(() => {
      mockListFolders.mockResolvedValue([...HIERARCHY]);
    });

    it("renders nested folders and a collapsible parent", async () => {
      const { getByText, getByLabelText, queryByText } = render(() => (
        <FolderSection selectedFolderId={null} onSelectFolder={() => {}} />
      ));
      await waitFor(() => {
        expect(getByText("Parent")).toBeTruthy();
        expect(getByText("Child")).toBeTruthy(); // expanded by default
      });

      // Collapse the parent → child disappears.
      fireEvent.click(getByLabelText("Collapse Parent"));
      await waitFor(() => {
        expect(queryByText("Child")).toBeNull();
      });
    });

    it("creates a subfolder under the chosen parent", async () => {
      const { getByText, getByLabelText } = render(() => (
        <FolderSection selectedFolderId={null} onSelectFolder={() => {}} />
      ));
      await waitFor(() => expect(getByText("Parent")).toBeTruthy());

      fireEvent.click(getByLabelText("Add a subfolder to Parent"));
      const input = await waitFor(() => {
        const el = document.querySelector("input");
        if (!el) throw new Error("subfolder input not rendered");
        return el;
      });
      fireEvent.input(input, { target: { value: "Reports" } });
      fireEvent.keyDown(input, { key: "Enter" });

      await waitFor(() => {
        expect(mockCreateFolder).toHaveBeenCalledWith("Reports", "p");
      });
    });

    it("reorders a sibling up via the move button", async () => {
      const { getByText, getByLabelText } = render(() => (
        <FolderSection selectedFolderId={null} onSelectFolder={() => {}} />
      ));
      await waitFor(() => expect(getByText("Second")).toBeTruthy());

      // "Second" is at root index 1 → moving it up targets position 0.
      fireEvent.click(getByLabelText("Move Second up"));
      await waitFor(() => {
        expect(mockMoveFolder).toHaveBeenCalledWith("p2", undefined, 0);
      });
    });

    it("indents a folder under its previous sibling with Alt+ArrowRight", async () => {
      const { getByText } = render(() => (
        <FolderSection selectedFolderId={null} onSelectFolder={() => {}} />
      ));
      await waitFor(() => expect(getByText("Second")).toBeTruthy());

      // Second's previous root sibling is Parent ("p").
      fireEvent.keyDown(getByText("Second").closest("[role='button']")!, {
        key: "ArrowRight",
        altKey: true,
      });
      await waitFor(() => {
        expect(mockMoveFolder).toHaveBeenCalledWith("p2", "p", Number.MAX_SAFE_INTEGER);
      });
    });

    it("outdents a child to the root with Alt+ArrowLeft", async () => {
      const { getByText } = render(() => (
        <FolderSection selectedFolderId={null} onSelectFolder={() => {}} />
      ));
      await waitFor(() => expect(getByText("Child")).toBeTruthy());

      fireEvent.keyDown(getByText("Child").closest("[role='button']")!, {
        key: "ArrowLeft",
        altKey: true,
      });
      await waitFor(() => {
        // Child's parent (p) sits at root index 0 → child lands at root index 1.
        expect(mockMoveFolder).toHaveBeenCalledWith("c", undefined, 1);
      });
    });
  });
});
