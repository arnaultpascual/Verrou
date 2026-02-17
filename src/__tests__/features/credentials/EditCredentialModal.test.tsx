import { render, fireEvent, waitFor } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { EditCredentialModal } from "../../../features/credentials/EditCredentialModal";

// Mock useToast
const mockToast = {
  success: vi.fn(),
  error: vi.fn(),
  info: vi.fn(),
  dismiss: vi.fn(),
  clear: vi.fn(),
};

vi.mock("../../../components/useToast", () => ({
  useToast: () => mockToast,
}));

// Mock entries IPC
const mockGetEntry = vi.fn();
const mockUpdateEntry = vi.fn();
const mockListEntries = vi.fn();

vi.mock("../../../features/entries/ipc", () => ({
  getEntry: (...args: unknown[]) => mockGetEntry(...args),
  updateEntry: (...args: unknown[]) => mockUpdateEntry(...args),
  listEntries: (...args: unknown[]) => mockListEntries(...args),
  copyToClipboard: vi.fn().mockResolvedValue(undefined),
}));

// Mock folders IPC
vi.mock("../../../features/folders/ipc", () => ({
  listFolders: vi.fn().mockResolvedValue([
    { id: "folder-1", name: "Work" },
    { id: "folder-2", name: "Personal" },
  ]),
}));

// Mock password generator IPC
vi.mock("../../../features/credentials/ipc", () => ({
  generatePassword: vi.fn().mockResolvedValue({ value: "mock-password-123" }),
}));

const MOCK_CREDENTIAL_ENTRY = {
  id: "cred-123",
  entryType: "credential",
  name: "GitHub",
  issuer: "github.com",
  algorithm: "SHA1",
  digits: 6,
  period: 30,
  counter: 0,
  pinned: false,
  tags: ["dev", "work"],
  folderId: "folder-1",
  createdAt: "2026-02-10T12:00:00Z",
  updatedAt: "2026-02-10T12:00:00Z",
  secret: "",
};

const defaultProps = {
  open: true,
  entryId: "cred-123",
  onClose: vi.fn(),
  onSuccess: vi.fn(),
};

/** Find an input element by its associated label text */
function findInputByLabel(labelText: string): HTMLInputElement | null {
  const labels = Array.from(document.querySelectorAll("label"));
  const label = labels.find((l) => l.textContent?.includes(labelText));
  if (!label) return null;
  const forAttr = label.getAttribute("for");
  if (forAttr) return document.getElementById(forAttr) as HTMLInputElement;
  return label.querySelector("input");
}

beforeEach(() => {
  vi.clearAllMocks();
  mockGetEntry.mockResolvedValue({ ...MOCK_CREDENTIAL_ENTRY });
  mockUpdateEntry.mockResolvedValue({
    id: "cred-123",
    entryType: "credential",
    name: "GitHub",
    issuer: "github.com",
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    pinned: false,
    createdAt: "2026-02-10T12:00:00Z",
    updatedAt: "2026-02-10T12:00:00Z",
  });
  mockListEntries.mockResolvedValue([
    {
      id: "totp-1",
      name: "GitHub TOTP",
      issuer: "github.com",
      entryType: "totp",
      algorithm: "SHA1",
      digits: 6,
      period: 30,
      pinned: false,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    },
  ]);
});

describe("EditCredentialModal", () => {
  describe("pre-population", () => {
    it("renders modal title", async () => {
      render(() => <EditCredentialModal {...defaultProps} />);
      await waitFor(() => {
        expect(document.body.textContent).toContain("Edit Credential");
      });
    });

    it("pre-populates name from entry", async () => {
      render(() => <EditCredentialModal {...defaultProps} />);
      await waitFor(() => {
        const nameInput = findInputByLabel("Name");
        expect(nameInput).toBeTruthy();
        expect(nameInput!.value).toBe("GitHub");
      });
    });

    it("pre-populates tags from entry", async () => {
      render(() => <EditCredentialModal {...defaultProps} />);
      await waitFor(() => {
        expect(document.body.textContent).toContain("dev");
        expect(document.body.textContent).toContain("work");
      });
    });

    it("pre-populates folder selection from entry", async () => {
      render(() => <EditCredentialModal {...defaultProps} />);
      await waitFor(() => {
        const folderSelect = document.getElementById("edit-credential-folder") as HTMLSelectElement;
        expect(folderSelect).toBeTruthy();
        expect(folderSelect.value).toBe("folder-1");
      });
    });

    it("shows empty password field with placeholder hint", async () => {
      render(() => <EditCredentialModal {...defaultProps} />);
      await waitFor(() => {
        const passwordInput = document.querySelector(
          "input[placeholder='Leave blank to keep current password']",
        );
        expect(passwordInput).toBeTruthy();
      });
    });

    it("shows password history hint", async () => {
      render(() => <EditCredentialModal {...defaultProps} />);
      await waitFor(() => {
        expect(document.body.textContent).toContain(
          "Changing the password will save the previous one to password history.",
        );
      });
    });
  });

  describe("form validation", () => {
    it("shows error when name is empty", async () => {
      render(() => <EditCredentialModal {...defaultProps} />);

      await waitFor(() => {
        expect(findInputByLabel("Name")).toBeTruthy();
      });

      const nameInput = findInputByLabel("Name")!;
      fireEvent.input(nameInput, { target: { value: "" } });

      const saveBtn = document.querySelector("[data-testid='edit-credential-save-btn']") as HTMLElement;
      fireEvent.click(saveBtn);

      await waitFor(() => {
        expect(document.body.textContent).toContain("Name is required.");
      });
    });

    it("shows error when name exceeds 100 chars", async () => {
      render(() => <EditCredentialModal {...defaultProps} />);

      await waitFor(() => {
        expect(findInputByLabel("Name")).toBeTruthy();
      });

      const nameInput = findInputByLabel("Name")!;
      fireEvent.input(nameInput, { target: { value: "a".repeat(101) } });

      const saveBtn = document.querySelector("[data-testid='edit-credential-save-btn']") as HTMLElement;
      fireEvent.click(saveBtn);

      await waitFor(() => {
        expect(document.body.textContent).toContain("Name too long");
      });
    });
  });

  describe("save flow", () => {
    it("calls updateEntry and shows success toast on save", async () => {
      render(() => <EditCredentialModal {...defaultProps} />);

      await waitFor(() => {
        expect(findInputByLabel("Name")).toBeTruthy();
      });

      const nameInput = findInputByLabel("Name")!;
      fireEvent.input(nameInput, { target: { value: "GitLab" } });

      const saveBtn = document.querySelector("[data-testid='edit-credential-save-btn']") as HTMLElement;
      fireEvent.click(saveBtn);

      await waitFor(() => {
        expect(mockUpdateEntry).toHaveBeenCalledWith(
          expect.objectContaining({
            id: "cred-123",
            name: "GitLab",
          }),
        );
        expect(mockToast.success).toHaveBeenCalledWith("GitLab saved");
        expect(defaultProps.onSuccess).toHaveBeenCalled();
        expect(defaultProps.onClose).toHaveBeenCalled();
      });
    });

    it("does not include secret when password is empty (keep current)", async () => {
      render(() => <EditCredentialModal {...defaultProps} />);

      await waitFor(() => {
        expect(findInputByLabel("Name")).toBeTruthy();
      });

      const saveBtn = document.querySelector("[data-testid='edit-credential-save-btn']") as HTMLElement;
      fireEvent.click(saveBtn);

      await waitFor(() => {
        expect(mockUpdateEntry).toHaveBeenCalled();
        const callArg = mockUpdateEntry.mock.calls[0][0];
        expect(callArg.secret).toBeUndefined();
      });
    });

    it("includes secret when password is changed", async () => {
      render(() => <EditCredentialModal {...defaultProps} />);

      await waitFor(() => {
        expect(findInputByLabel("Name")).toBeTruthy();
      });

      // Find the password input (New Password)
      const passwordInputs = Array.from(
        document.querySelectorAll("input[type='password']"),
      ) as HTMLInputElement[];
      const passwordInput = passwordInputs.find(
        (el) => el.placeholder === "Leave blank to keep current password",
      );

      if (passwordInput) {
        fireEvent.input(passwordInput, { target: { value: "new-secret-pass!" } });
      }

      const saveBtn = document.querySelector("[data-testid='edit-credential-save-btn']") as HTMLElement;
      fireEvent.click(saveBtn);

      await waitFor(() => {
        expect(mockUpdateEntry).toHaveBeenCalled();
        const callArg = mockUpdateEntry.mock.calls[0][0];
        expect(callArg.secret).toBe("new-secret-pass!");
      });
    });

    it("shows error toast when updateEntry fails", async () => {
      mockUpdateEntry.mockRejectedValue("Database error");

      render(() => <EditCredentialModal {...defaultProps} />);

      await waitFor(() => {
        expect(document.querySelector("[data-testid='edit-credential-save-btn']")).toBeTruthy();
      });

      const saveBtn = document.querySelector("[data-testid='edit-credential-save-btn']") as HTMLElement;
      fireEvent.click(saveBtn);

      await waitFor(() => {
        expect(mockToast.error).toHaveBeenCalledWith("Database error");
      });
    });
  });

  describe("delete button", () => {
    it("shows delete button when onDelete is provided", async () => {
      const onDelete = vi.fn();
      render(() => <EditCredentialModal {...defaultProps} onDelete={onDelete} />);

      await waitFor(() => {
        const deleteBtn = document.querySelector("[data-testid='edit-credential-delete-btn']");
        expect(deleteBtn).toBeTruthy();
      });
    });

    it("calls onDelete with entryId and name when clicked", async () => {
      const onDelete = vi.fn();
      render(() => <EditCredentialModal {...defaultProps} onDelete={onDelete} />);

      await waitFor(() => {
        expect(document.querySelector("[data-testid='edit-credential-delete-btn']")).toBeTruthy();
      });

      const deleteBtn = document.querySelector("[data-testid='edit-credential-delete-btn']") as HTMLElement;
      fireEvent.click(deleteBtn);

      expect(onDelete).toHaveBeenCalledWith("cred-123", "GitHub");
    });

    it("hides delete button when onDelete is not provided", async () => {
      render(() => <EditCredentialModal {...defaultProps} />);

      await waitFor(() => {
        expect(document.querySelector("[data-testid='edit-credential-save-btn']")).toBeTruthy();
      });

      const deleteBtn = document.querySelector("[data-testid='edit-credential-delete-btn']");
      expect(deleteBtn).toBeNull();
    });
  });

  describe("close behavior", () => {
    it("calls onClose when Cancel is clicked", async () => {
      const onClose = vi.fn();
      render(() => <EditCredentialModal {...defaultProps} onClose={onClose} />);

      await waitFor(() => {
        expect(document.querySelector("[data-testid='edit-credential-save-btn']")).toBeTruthy();
      });

      const cancelBtn = Array.from(document.querySelectorAll("button")).find(
        (b) => b.textContent?.includes("Cancel"),
      );
      expect(cancelBtn).toBeTruthy();
      fireEvent.click(cancelBtn!);
      expect(onClose).toHaveBeenCalled();
    });
  });
});
