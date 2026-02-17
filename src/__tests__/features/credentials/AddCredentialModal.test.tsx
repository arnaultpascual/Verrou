import { render, fireEvent, screen } from "@solidjs/testing-library";
import { describe, expect, it, vi } from "vitest";
import { AddCredentialModal } from "../../../features/credentials/AddCredentialModal";

// Mock entries IPC
vi.mock("../../../features/entries/ipc", () => ({
  addEntry: vi.fn().mockResolvedValue({
    id: "mock-cred-1",
    name: "GitHub",
    entryType: "credential",
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    pinned: false,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  }),
  listEntries: vi.fn().mockResolvedValue([
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
  ]),
  copyToClipboard: vi.fn(),
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

describe("AddCredentialModal", () => {
  const defaultProps = {
    open: true,
    onClose: vi.fn(),
    onSuccess: vi.fn(),
  };

  describe("rendering", () => {
    it("renders the modal with correct title", () => {
      render(() => <AddCredentialModal {...defaultProps} />);
      expect(screen.getByText("Add Credential")).toBeDefined();
    });

    it("renders Name input field", () => {
      render(() => <AddCredentialModal {...defaultProps} />);
      expect(screen.getByText("Name")).toBeDefined();
    });

    it("renders Username input field", () => {
      render(() => <AddCredentialModal {...defaultProps} />);
      expect(screen.getByText("Username")).toBeDefined();
    });

    it("renders Password input field", () => {
      render(() => <AddCredentialModal {...defaultProps} />);
      expect(screen.getByText("Password")).toBeDefined();
    });

    it("renders URL section", () => {
      render(() => <AddCredentialModal {...defaultProps} />);
      expect(screen.getByText("URLs")).toBeDefined();
      expect(screen.getByText("Primary URL")).toBeDefined();
    });

    it("renders Notes textarea", () => {
      render(() => <AddCredentialModal {...defaultProps} />);
      expect(screen.getByText("Notes")).toBeDefined();
    });

    it("renders Tags input", () => {
      render(() => <AddCredentialModal {...defaultProps} />);
      expect(screen.getByText("Tags")).toBeDefined();
    });

    it("renders Folder selector", () => {
      render(() => <AddCredentialModal {...defaultProps} />);
      expect(screen.getByText("Folder")).toBeDefined();
    });

    it("renders TOTP link selector", () => {
      render(() => <AddCredentialModal {...defaultProps} />);
      expect(screen.getByText("Link existing TOTP")).toBeDefined();
    });

    it("renders Custom Fields section", () => {
      render(() => <AddCredentialModal {...defaultProps} />);
      expect(screen.getByText("Custom Fields")).toBeDefined();
    });

    it("renders Cancel and Save buttons", () => {
      render(() => <AddCredentialModal {...defaultProps} />);
      expect(screen.getByText("Cancel")).toBeDefined();
      expect(screen.getByText("Save Credential")).toBeDefined();
    });

    it("renders Password Generator (collapsed)", () => {
      render(() => <AddCredentialModal {...defaultProps} />);
      const header = screen.getByRole("button", { name: /password generator/i });
      expect(header).toBeDefined();
    });
  });

  describe("URL management", () => {
    it("starts with one URL field", () => {
      render(() => <AddCredentialModal {...defaultProps} />);
      expect(screen.getByText("Primary URL")).toBeDefined();
    });

    it("adds a new URL field on click", async () => {
      render(() => <AddCredentialModal {...defaultProps} />);
      const addBtn = screen.getByText("Add another URL");
      await fireEvent.click(addBtn);
      expect(screen.getByText("URL 2")).toBeDefined();
    });

    it("shows remove button when multiple URLs exist", async () => {
      render(() => <AddCredentialModal {...defaultProps} />);
      await fireEvent.click(screen.getByText("Add another URL"));
      const removeButtons = document.querySelectorAll("[aria-label^='Remove URL']");
      expect(removeButtons.length).toBeGreaterThan(0);
    });

    it("auto-suggests entry name from first URL domain (AC2)", async () => {
      render(() => <AddCredentialModal {...defaultProps} />);
      const urlInput = document.querySelector(
        "input[placeholder='e.g. https://github.com/login']",
      ) as HTMLInputElement;
      const nameInput = document.querySelector(
        "input[placeholder='e.g. GitHub']",
      ) as HTMLInputElement;
      expect(nameInput.value).toBe("");
      await fireEvent.input(urlInput, {
        target: { value: "https://github.com/login" },
      });
      expect(nameInput.value).toBe("github.com");
    });
  });

  describe("custom fields", () => {
    it("adds a custom field on click", async () => {
      render(() => <AddCredentialModal {...defaultProps} />);
      await fireEvent.click(screen.getByText("Add Custom Field"));
      // Should now have Field Name and Value inputs
      expect(screen.getByText("Field Name")).toBeDefined();
      expect(screen.getByText("Value")).toBeDefined();
    });

    it("shows type selector for custom field", async () => {
      render(() => <AddCredentialModal {...defaultProps} />);
      await fireEvent.click(screen.getByText("Add Custom Field"));
      expect(screen.getByText("Type")).toBeDefined();
      // Check type options exist in a select
      const selects = document.querySelectorAll("select");
      const typeSelect = Array.from(selects).find((s) =>
        Array.from(s.options).some((o) => o.text === "Hidden"),
      );
      expect(typeSelect).not.toBeNull();
    });

    it("removes a custom field on click", async () => {
      render(() => <AddCredentialModal {...defaultProps} />);
      await fireEvent.click(screen.getByText("Add Custom Field"));
      // Find remove button
      const removeBtn = document.querySelector("[aria-label^='Remove field']");
      expect(removeBtn).not.toBeNull();
      await fireEvent.click(removeBtn!);
      // Field Name label should be gone (only from custom fields)
      expect(screen.queryByText("Field Name")).toBeNull();
    });
  });

  describe("validation", () => {
    it("shows error when name is empty on submit", async () => {
      render(() => <AddCredentialModal {...defaultProps} />);
      await fireEvent.click(screen.getByText("Save Credential"));
      expect(screen.getByText("Name is required.")).toBeDefined();
    });

    it("shows error when password is empty on submit", async () => {
      render(() => <AddCredentialModal {...defaultProps} />);
      // Fill name to pass that validation
      const nameInput = document.querySelector("input[placeholder='e.g. GitHub']") as HTMLInputElement;
      await fireEvent.input(nameInput, { target: { value: "GitHub" } });
      await fireEvent.click(screen.getByText("Save Credential"));
      expect(screen.getByText("Password is required.")).toBeDefined();
    });

    it("shows error for name exceeding 100 chars", async () => {
      render(() => <AddCredentialModal {...defaultProps} />);
      const nameInput = document.querySelector("input[placeholder='e.g. GitHub']") as HTMLInputElement;
      const longName = "a".repeat(101);
      await fireEvent.input(nameInput, { target: { value: longName } });
      await fireEvent.click(screen.getByText("Save Credential"));
      expect(screen.getByText("Name too long (max 100 characters).")).toBeDefined();
    });
  });

  describe("submit flow", () => {
    it("calls addEntry and onSuccess on valid submit", async () => {
      const onSuccess = vi.fn();
      const onClose = vi.fn();
      const { addEntry } = await import("../../../features/entries/ipc");

      render(() => (
        <AddCredentialModal open={true} onClose={onClose} onSuccess={onSuccess} />
      ));

      // Fill required fields
      const nameInput = document.querySelector("input[placeholder='e.g. GitHub']") as HTMLInputElement;
      await fireEvent.input(nameInput, { target: { value: "GitHub" } });

      // Fill password via the PasswordInput
      const pwInput = document.querySelector("input[type='password']") as HTMLInputElement;
      await fireEvent.input(pwInput, { target: { value: "SuperSecret123!" } });

      await fireEvent.click(screen.getByText("Save Credential"));

      // Wait for async submit
      await new Promise((r) => setTimeout(r, 200));

      expect(addEntry).toHaveBeenCalled();
      const call = (addEntry as ReturnType<typeof vi.fn>).mock.calls[0][0];
      expect(call.entryType).toBe("credential");
      expect(call.name).toBe("GitHub");
      expect(call.secret).toBe("SuperSecret123!");
    });
  });

  describe("modal behavior", () => {
    it("does not render content when closed", () => {
      render(() => <AddCredentialModal open={false} onClose={vi.fn()} onSuccess={vi.fn()} />);
      expect(screen.queryByText("Add Credential")).toBeNull();
    });

    it("calls onClose when Cancel is clicked", async () => {
      const onClose = vi.fn();
      render(() => <AddCredentialModal open={true} onClose={onClose} onSuccess={vi.fn()} />);
      await fireEvent.click(screen.getByText("Cancel"));
      expect(onClose).toHaveBeenCalled();
    });
  });

  describe("accessibility", () => {
    it("has labeled URL add button", () => {
      render(() => <AddCredentialModal {...defaultProps} />);
      const btn = document.querySelector("[aria-label='Add another URL']");
      expect(btn).not.toBeNull();
    });

    it("has label for Notes textarea", () => {
      render(() => <AddCredentialModal {...defaultProps} />);
      const label = document.querySelector("label[for='credential-notes']");
      expect(label).not.toBeNull();
    });

    it("has label for Folder select", () => {
      render(() => <AddCredentialModal {...defaultProps} />);
      const label = document.querySelector("label[for='credential-folder']");
      expect(label).not.toBeNull();
    });

    it("has label for TOTP link select", () => {
      render(() => <AddCredentialModal {...defaultProps} />);
      const label = document.querySelector("label[for='credential-totp-link']");
      expect(label).not.toBeNull();
    });
  });
});
