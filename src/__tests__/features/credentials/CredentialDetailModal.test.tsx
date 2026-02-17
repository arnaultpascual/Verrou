import { render, fireEvent, waitFor } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { CredentialDetailModal } from "../../../features/credentials/CredentialDetailModal";
import type { CredentialDisplay, TotpCodeDto } from "../../../features/entries/ipc";

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
const mockRevealPassword = vi.fn<
  (entryId: string, password: string) => Promise<CredentialDisplay>
>();
const mockCopyToClipboard = vi.fn().mockResolvedValue(undefined);
const mockGenerateTotpCode = vi.fn<
  (entryId: string) => Promise<TotpCodeDto>
>();

vi.mock("../../../features/entries/ipc", () => ({
  revealPassword: (...args: unknown[]) => mockRevealPassword(...(args as [string, string])),
  copyToClipboard: (...args: unknown[]) => mockCopyToClipboard(...args),
  generateTotpCode: (...args: unknown[]) => mockGenerateTotpCode(...(args as [string])),
}));

// Mock folders IPC
vi.mock("../../../features/folders/ipc", () => ({
  listFolders: vi.fn().mockResolvedValue([
    { id: "folder-1", name: "Work", sortOrder: 0, createdAt: "", updatedAt: "", entryCount: 3 },
    { id: "folder-2", name: "Personal", sortOrder: 1, createdAt: "", updatedAt: "", entryCount: 1 },
  ]),
}));

const TEST_CREDENTIAL: CredentialDisplay = {
  password: "s3cret-p@ss!",
  username: "user@example.com",
  urls: ["https://github.com/login", "https://github.com"],
  notes: "Work account",
  customFields: [
    { label: "API Key", value: "abc-123-xyz", fieldType: "text" },
    { label: "Recovery PIN", value: "9999", fieldType: "hidden" },
  ],
  passwordHistory: [
    { password: "old-pass-1", changedAt: "2026-01-15T10:00:00Z" },
    { password: "old-pass-2", changedAt: "2026-01-01T08:00:00Z" },
  ],
  linkedTotpId: undefined,
};

const TEST_CREDENTIAL_WITH_TOTP: CredentialDisplay = {
  ...TEST_CREDENTIAL,
  linkedTotpId: "totp-linked-1",
};

const TEST_TOTP_CODE: TotpCodeDto = {
  code: "123456",
  remainingSeconds: 18,
};

beforeEach(() => {
  vi.clearAllMocks();
  mockRevealPassword.mockResolvedValue(TEST_CREDENTIAL);
  mockGenerateTotpCode.mockResolvedValue(TEST_TOTP_CODE);
});

const defaultProps = {
  open: true,
  onClose: vi.fn(),
  entryId: "cred-123",
  name: "GitHub",
  issuer: "github.com",
  createdAt: "2026-02-10T12:00:00Z",
};

describe("CredentialDetailModal", () => {
  describe("metadata display", () => {
    it("renders modal title", () => {
      render(() => <CredentialDetailModal {...defaultProps} />);
      expect(document.body.textContent).toContain("Credential Details");
    });

    it("displays credential name", () => {
      render(() => <CredentialDetailModal {...defaultProps} />);
      const nameEl = document.querySelector("[data-testid='credential-detail-name']");
      expect(nameEl).toBeTruthy();
      expect(nameEl!.textContent).toBe("GitHub");
    });

    it("displays issuer when provided", () => {
      render(() => <CredentialDetailModal {...defaultProps} />);
      const issuerEl = document.querySelector("[data-testid='credential-detail-issuer']");
      expect(issuerEl).toBeTruthy();
      expect(issuerEl!.textContent).toBe("github.com");
    });

    it("hides issuer row when not provided", () => {
      const { container } = render(() => (
        <CredentialDetailModal {...defaultProps} issuer={undefined} />
      ));
      const issuerEl = container.querySelector("[data-testid='credential-detail-issuer']");
      expect(issuerEl).toBeNull();
    });

    it("displays formatted creation date", () => {
      render(() => <CredentialDetailModal {...defaultProps} />);
      expect(document.body.textContent).toContain("2026");
    });
  });

  describe("password section (masked state)", () => {
    it("shows masked password by default", () => {
      render(() => <CredentialDetailModal {...defaultProps} />);
      expect(document.body.textContent).toContain("••••••••");
    });

    it("shows Reveal button in initial state", () => {
      render(() => <CredentialDetailModal {...defaultProps} />);
      const revealBtn = document.querySelector("[data-testid='credential-reveal-btn']");
      expect(revealBtn).toBeTruthy();
      expect(revealBtn!.textContent).toContain("Reveal");
    });

    it("opens ReAuthPrompt when Reveal is clicked", async () => {
      render(() => <CredentialDetailModal {...defaultProps} />);

      const revealBtn = document.querySelector("[data-testid='credential-reveal-btn']");
      fireEvent.click(revealBtn!);

      await waitFor(() => {
        expect(document.body.textContent).toContain("Verify Your Identity");
      });
    });

    it("does not show username before reveal", () => {
      render(() => <CredentialDetailModal {...defaultProps} />);
      const usernameEl = document.querySelector("[data-testid='credential-username']");
      expect(usernameEl).toBeNull();
    });
  });

  describe("reveal flow", () => {
    it("shows toast error when reveal fails", async () => {
      mockRevealPassword.mockRejectedValue("Incorrect password. Credential not revealed.");

      render(() => <CredentialDetailModal {...defaultProps} />);

      const revealBtn = document.querySelector("[data-testid='credential-reveal-btn']");
      fireEvent.click(revealBtn!);

      await waitFor(() => {
        expect(document.body.textContent).toContain("Verify Your Identity");
      });

      const passwordInput = document.querySelector(
        "input[type='password']",
      ) as HTMLInputElement;
      if (passwordInput) {
        fireEvent.input(passwordInput, { target: { value: "wrong-password" } });
        const form = document.querySelector("form");
        if (form) {
          fireEvent.submit(form);
          await waitFor(
            () => {
              expect(mockToast.error).toHaveBeenCalledWith(
                "Incorrect password. Credential not revealed.",
              );
            },
            { timeout: 5000 },
          );
        }
      }
    });
  });

  describe("actions", () => {
    it("shows Edit button when onEdit is provided", () => {
      const onEdit = vi.fn();
      render(() => <CredentialDetailModal {...defaultProps} onEdit={onEdit} />);
      const editBtn = document.querySelector("[data-testid='credential-detail-edit-btn']");
      expect(editBtn).toBeTruthy();
    });

    it("calls onEdit with entryId when Edit is clicked", () => {
      const onEdit = vi.fn();
      render(() => <CredentialDetailModal {...defaultProps} onEdit={onEdit} />);
      const editBtn = document.querySelector("[data-testid='credential-detail-edit-btn']") as HTMLElement;
      fireEvent.click(editBtn);
      expect(onEdit).toHaveBeenCalledWith("cred-123");
    });

    it("shows Delete button when onDeleted is provided", () => {
      const onDeleted = vi.fn();
      render(() => <CredentialDetailModal {...defaultProps} onDeleted={onDeleted} />);
      const deleteBtn = document.querySelector("[data-testid='credential-detail-delete-btn']");
      expect(deleteBtn).toBeTruthy();
    });

    it("calls onDeleted when Delete is clicked", () => {
      const onDeleted = vi.fn();
      render(() => <CredentialDetailModal {...defaultProps} onDeleted={onDeleted} />);
      const deleteBtn = document.querySelector("[data-testid='credential-detail-delete-btn']") as HTMLElement;
      fireEvent.click(deleteBtn);
      expect(onDeleted).toHaveBeenCalled();
    });
  });

  describe("tags and folder display", () => {
    it("displays tags when provided", () => {
      render(() => (
        <CredentialDetailModal {...defaultProps} tags={["dev", "work"]} />
      ));
      const tagsEl = document.querySelector("[data-testid='credential-detail-tags']");
      expect(tagsEl).toBeTruthy();
      expect(tagsEl!.textContent).toContain("dev");
      expect(tagsEl!.textContent).toContain("work");
    });

    it("hides tags section when no tags provided", () => {
      const { container } = render(() => (
        <CredentialDetailModal {...defaultProps} tags={[]} />
      ));
      const tagsEl = container.querySelector("[data-testid='credential-detail-tags']");
      expect(tagsEl).toBeNull();
    });

    it("displays folder name when folderId is provided", async () => {
      render(() => (
        <CredentialDetailModal {...defaultProps} folderId="folder-1" />
      ));
      await waitFor(() => {
        const folderEl = document.querySelector("[data-testid='credential-detail-folder']");
        expect(folderEl).toBeTruthy();
        expect(folderEl!.textContent).toBe("Work");
      });
    });

    it("hides folder row when folderId is not provided", () => {
      const { container } = render(() => (
        <CredentialDetailModal {...defaultProps} />
      ));
      const folderEl = container.querySelector("[data-testid='credential-detail-folder']");
      expect(folderEl).toBeNull();
    });
  });

  describe("password history (after reveal)", () => {
    /** Helper: performs the re-auth reveal flow and waits for revealed data to appear. */
    async function performReveal() {
      const revealBtn = document.querySelector("[data-testid='credential-reveal-btn']");
      fireEvent.click(revealBtn!);

      await waitFor(() => {
        expect(document.body.textContent).toContain("Verify Your Identity");
      });

      const passwordInput = document.querySelector("input[type='password']") as HTMLInputElement;
      fireEvent.input(passwordInput, { target: { value: "master-pass" } });
      const form = document.querySelector("form");
      fireEvent.submit(form!);

      await waitFor(
        () => {
          expect(document.querySelector("[data-testid='credential-password-revealed']")).toBeTruthy();
        },
        { timeout: 5000 },
      );
    }

    it("displays password history section after reveal", async () => {
      render(() => <CredentialDetailModal {...defaultProps} />);
      await performReveal();

      await waitFor(() => {
        expect(document.body.textContent).toContain("Password History (2)");
      });
    });

    it("renders history rows with masked passwords", async () => {
      render(() => <CredentialDetailModal {...defaultProps} />);
      await performReveal();

      await waitFor(() => {
        const rows = document.querySelectorAll("[data-testid='credential-history-row']");
        expect(rows.length).toBe(2);
        // Passwords are masked by default
        expect(rows[0].textContent).toContain("••••••••");
      });
    });
  });

  describe("linked TOTP (after reveal)", () => {
    /** Helper: performs the re-auth reveal flow with TOTP-linked credential. */
    async function performRevealWithTotp() {
      mockRevealPassword.mockResolvedValue(TEST_CREDENTIAL_WITH_TOTP);

      const revealBtn = document.querySelector("[data-testid='credential-reveal-btn']");
      fireEvent.click(revealBtn!);

      await waitFor(() => {
        expect(document.body.textContent).toContain("Verify Your Identity");
      });

      const passwordInput = document.querySelector("input[type='password']") as HTMLInputElement;
      fireEvent.input(passwordInput, { target: { value: "master-pass" } });
      const form = document.querySelector("form");
      fireEvent.submit(form!);

      await waitFor(
        () => {
          expect(document.querySelector("[data-testid='credential-password-revealed']")).toBeTruthy();
        },
        { timeout: 5000 },
      );
    }

    it("displays linked TOTP code after reveal", async () => {
      render(() => <CredentialDetailModal {...defaultProps} />);
      await performRevealWithTotp();

      await waitFor(() => {
        const totpEl = document.querySelector("[data-testid='credential-totp-code']");
        expect(totpEl).toBeTruthy();
        expect(totpEl!.textContent).toContain("123");
      });
    });

    it("displays TOTP countdown after reveal", async () => {
      render(() => <CredentialDetailModal {...defaultProps} />);
      await performRevealWithTotp();

      await waitFor(() => {
        const countdownEl = document.querySelector("[data-testid='credential-totp-countdown']");
        expect(countdownEl).toBeTruthy();
        expect(countdownEl!.textContent).toContain("18s");
      });
    });

    it("copies TOTP code to clipboard on click", async () => {
      render(() => <CredentialDetailModal {...defaultProps} />);
      await performRevealWithTotp();

      await waitFor(() => {
        expect(document.querySelector("[data-testid='credential-totp-code']")).toBeTruthy();
      });

      const totpBtn = document.querySelector("[data-testid='credential-totp-code']") as HTMLElement;
      fireEvent.click(totpBtn);

      await waitFor(() => {
        expect(mockCopyToClipboard).toHaveBeenCalledWith("123456");
        expect(mockToast.success).toHaveBeenCalledWith("TOTP code copied");
      });
    });

    it("does not show TOTP section when no linkedTotpId", async () => {
      render(() => <CredentialDetailModal {...defaultProps} />);
      // Default mock returns TEST_CREDENTIAL (no linkedTotpId)

      const revealBtn = document.querySelector("[data-testid='credential-reveal-btn']");
      fireEvent.click(revealBtn!);

      await waitFor(() => {
        expect(document.body.textContent).toContain("Verify Your Identity");
      });

      const passwordInput = document.querySelector("input[type='password']") as HTMLInputElement;
      if (passwordInput) {
        fireEvent.input(passwordInput, { target: { value: "master-pass" } });
        const form = document.querySelector("form");
        fireEvent.submit(form!);

        await waitFor(
          () => {
            expect(document.querySelector("[data-testid='credential-password-revealed']")).toBeTruthy();
          },
          { timeout: 5000 },
        );
      }

      const totpEl = document.querySelector("[data-testid='credential-totp-code']");
      expect(totpEl).toBeNull();
    });
  });

  describe("cleanup on close", () => {
    it("calls onClose when close button is clicked", () => {
      const onClose = vi.fn();
      render(() => <CredentialDetailModal {...defaultProps} onClose={onClose} />);

      const closeButtons = Array.from(document.querySelectorAll("button")).filter(
        (b) => b.textContent?.includes("Close"),
      );

      if (closeButtons.length > 0) {
        fireEvent.click(closeButtons[0]);
        expect(onClose).toHaveBeenCalled();
      }
    });

    it("does not show revealed data in initial state", () => {
      render(() => <CredentialDetailModal {...defaultProps} />);
      const revealedEl = document.querySelector("[data-testid='credential-password-revealed']");
      expect(revealedEl).toBeNull();
    });
  });
});
