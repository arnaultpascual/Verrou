import { render, fireEvent, waitFor } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { AttachmentsSection } from "../../../features/attachments/AttachmentsSection";

// Mock useToast
vi.mock("../../../components/useToast", () => ({
  useToast: () => ({
    info: vi.fn(),
    success: vi.fn(),
    error: vi.fn(),
    warning: vi.fn(),
  }),
}));

// Mock the IPC module
const mockListAttachments = vi.fn();
const mockAddAttachment = vi.fn();
const mockExportAttachment = vi.fn();
const mockDeleteAttachment = vi.fn();
const mockPickFile = vi.fn();
const mockPickSaveLocation = vi.fn();

vi.mock("../../../features/attachments/ipc", () => ({
  listAttachments: (...args: unknown[]) => mockListAttachments(...args),
  addAttachment: (...args: unknown[]) => mockAddAttachment(...args),
  exportAttachment: (...args: unknown[]) => mockExportAttachment(...args),
  deleteAttachment: (...args: unknown[]) => mockDeleteAttachment(...args),
  pickFile: (...args: unknown[]) => mockPickFile(...args),
  pickSaveLocation: (...args: unknown[]) => mockPickSaveLocation(...args),
  formatBytes: (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  },
}));

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
  mockListAttachments.mockResolvedValue([]);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("AttachmentsSection", () => {
  it("renders empty state when no attachments", async () => {
    const { getByText } = render(() => (
      <AttachmentsSection entryId="entry-1" />
    ));
    await waitFor(() => {
      expect(getByText("No attachments")).toBeTruthy();
    });
  });

  it("renders the section title and add button", async () => {
    const { getByText, getByLabelText } = render(() => (
      <AttachmentsSection entryId="entry-1" />
    ));
    await waitFor(() => {
      expect(getByText("Attachments")).toBeTruthy();
      expect(getByLabelText("Add attachment")).toBeTruthy();
    });
  });

  it("renders attachment list with filenames and sizes", async () => {
    mockListAttachments.mockResolvedValue([
      {
        id: "att-1",
        entryId: "entry-1",
        filename: "id_ed25519",
        mimeType: "application/octet-stream",
        sizeBytes: 2048,
        createdAt: "2026-02-15T00:00:00Z",
      },
      {
        id: "att-2",
        entryId: "entry-1",
        filename: "cert.pem",
        mimeType: "application/x-pem-file",
        sizeBytes: 512,
        createdAt: "2026-02-15T00:01:00Z",
      },
    ]);

    const { getByText } = render(() => (
      <AttachmentsSection entryId="entry-1" />
    ));
    await waitFor(() => {
      expect(getByText("id_ed25519")).toBeTruthy();
      expect(getByText("2.0 KB")).toBeTruthy();
      expect(getByText("cert.pem")).toBeTruthy();
      expect(getByText("512 B")).toBeTruthy();
    });
  });

  it("shows delete confirmation on delete click", async () => {
    mockListAttachments.mockResolvedValue([
      {
        id: "att-1",
        entryId: "entry-1",
        filename: "secret.key",
        mimeType: "application/octet-stream",
        sizeBytes: 256,
        createdAt: "2026-02-15T00:00:00Z",
      },
    ]);

    const { getByLabelText, getByText } = render(() => (
      <AttachmentsSection entryId="entry-1" />
    ));

    await waitFor(() => {
      expect(getByText("secret.key")).toBeTruthy();
    });

    fireEvent.click(getByLabelText("Delete secret.key"));

    await waitFor(() => {
      expect(getByText("Delete secret.key?")).toBeTruthy();
      expect(getByText("Delete")).toBeTruthy();
      expect(getByText("Cancel")).toBeTruthy();
    });
  });

  it("calls deleteAttachment on confirm", async () => {
    mockListAttachments.mockResolvedValue([
      {
        id: "att-1",
        entryId: "entry-1",
        filename: "old.pem",
        mimeType: "application/x-pem-file",
        sizeBytes: 100,
        createdAt: "2026-02-15T00:00:00Z",
      },
    ]);
    mockDeleteAttachment.mockResolvedValue(undefined);

    const { getByLabelText, getByText } = render(() => (
      <AttachmentsSection entryId="entry-1" />
    ));

    await waitFor(() => {
      expect(getByText("old.pem")).toBeTruthy();
    });

    // Click delete icon
    fireEvent.click(getByLabelText("Delete old.pem"));

    // Click confirm
    await waitFor(() => {
      expect(getByText("Delete")).toBeTruthy();
    });
    fireEvent.click(getByText("Delete"));

    await waitFor(() => {
      expect(mockDeleteAttachment).toHaveBeenCalledWith("att-1");
    });
  });

  it("calls pickFile and addAttachment on add click", async () => {
    mockPickFile.mockResolvedValue("/tmp/new-key.pem");
    mockAddAttachment.mockResolvedValue({
      id: "att-new",
      entryId: "entry-1",
      filename: "new-key.pem",
      mimeType: "application/x-pem-file",
      sizeBytes: 1024,
      createdAt: "2026-02-15T00:00:00Z",
    });

    const { getByLabelText } = render(() => (
      <AttachmentsSection entryId="entry-1" />
    ));

    await waitFor(() => {
      expect(getByLabelText("Add attachment")).toBeTruthy();
    });

    fireEvent.click(getByLabelText("Add attachment"));

    await waitFor(() => {
      expect(mockPickFile).toHaveBeenCalled();
      expect(mockAddAttachment).toHaveBeenCalledWith("entry-1", "/tmp/new-key.pem");
    });
  });
});
