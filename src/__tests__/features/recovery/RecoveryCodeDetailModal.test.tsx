import { render, fireEvent, waitFor } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { RecoveryCodeDetailModal } from "../../../features/recovery/RecoveryCodeDetailModal";
import type { RecoveryCodeDisplay } from "../../../features/recovery/ipc";

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

// Mock recovery IPC (reveal / toggle / delete)
const mockRevealRecoveryCodes =
  vi.fn<(entryId: string, password: string) => Promise<RecoveryCodeDisplay>>();
const mockToggleRecoveryCodeUsed =
  vi.fn<(entryId: string, codeIndex: number, password: string) => Promise<RecoveryCodeDisplay>>();
const mockDeleteRecoveryCodeEntry =
  vi.fn<(entryId: string, password: string) => Promise<void>>();

vi.mock("../../../features/recovery/ipc", () => ({
  revealRecoveryCodes: (...args: unknown[]) =>
    mockRevealRecoveryCodes(...(args as [string, string])),
  toggleRecoveryCodeUsed: (...args: unknown[]) =>
    mockToggleRecoveryCodeUsed(...(args as [string, number, string])),
  deleteRecoveryCodeEntry: (...args: unknown[]) =>
    mockDeleteRecoveryCodeEntry(...(args as [string, string])),
}));

const TEST_CODES: RecoveryCodeDisplay = {
  codes: [
    "abcd-1234-efgh-5678",
    "ijkl-9012-mnop-3456",
    "qrst-7890-uvwx-1234",
    "yzab-5678-cdef-9012",
    "ghij-3456-klmn-7890",
  ],
  used: [1],
  totalCodes: 5,
  remainingCodes: 4,
  hasLinkedEntry: false,
};

const LOW_CODES: RecoveryCodeDisplay = {
  codes: ["abcd-1234-efgh-5678", "ijkl-9012-mnop-3456"],
  used: [0],
  totalCodes: 2,
  remainingCodes: 1,
  hasLinkedEntry: false,
};

const NONE_CODES: RecoveryCodeDisplay = {
  codes: ["abcd-1234-efgh-5678"],
  used: [0],
  totalCodes: 1,
  remainingCodes: 0,
  hasLinkedEntry: false,
};

beforeEach(() => {
  vi.clearAllMocks();
  mockRevealRecoveryCodes.mockResolvedValue(TEST_CODES);
  mockToggleRecoveryCodeUsed.mockResolvedValue(TEST_CODES);
  mockDeleteRecoveryCodeEntry.mockResolvedValue(undefined);
});

const defaultProps = {
  open: true,
  onClose: vi.fn(),
  entryId: "test-entry-id",
  name: "GitHub",
  issuer: "GitHub Inc.",
  createdAt: "2026-02-05T10:00:00Z",
};

/** Open the re-auth prompt, enter a password and submit it (drives a real reveal). */
async function revealCodes(password = "correct-horse") {
  const revealBtn = Array.from(document.querySelectorAll("button")).find((b) =>
    b.textContent?.includes("Reveal"),
  );
  fireEvent.click(revealBtn!);

  await waitFor(() => {
    expect(document.body.textContent).toContain("Verify Your Identity");
  });

  const passwordInput = document.querySelector(
    "input[type='password']",
  ) as HTMLInputElement;
  fireEvent.input(passwordInput, { target: { value: password } });
  const form = document.querySelector("form");
  fireEvent.submit(form!);
}

describe("RecoveryCodeDetailModal", () => {
  describe("metadata display", () => {
    it("renders modal title", () => {
      render(() => <RecoveryCodeDetailModal {...defaultProps} />);
      expect(document.body.textContent).toContain("Recovery Code Details");
    });

    it("displays the service name", () => {
      render(() => <RecoveryCodeDetailModal {...defaultProps} />);
      expect(document.body.textContent).toContain("GitHub");
    });

    it("displays issuer when provided", () => {
      render(() => <RecoveryCodeDetailModal {...defaultProps} />);
      expect(document.body.textContent).toContain("GitHub Inc.");
    });

    it("hides issuer label when not provided", () => {
      // Build props WITHOUT an issuer key. Note: `{...defaultProps} issuer={undefined}`
      // does NOT override under SolidJS prop-merge semantics (an explicit `undefined`
      // keeps the spread value), so the key must genuinely be absent.
      const { issuer: _omit, ...noIssuer } = defaultProps;
      document.body.innerHTML = "";
      render(() => <RecoveryCodeDetailModal {...noIssuer} />);
      expect(document.body.textContent).not.toContain("Issuer");
    });

    it("displays formatted creation date", () => {
      render(() => <RecoveryCodeDetailModal {...defaultProps} />);
      expect(document.body.textContent).toContain("2026");
    });
  });

  describe("reveal flow", () => {
    it("shows masked state by default", () => {
      render(() => <RecoveryCodeDetailModal {...defaultProps} />);
      expect(document.body.textContent).toContain("Recovery codes are hidden");
    });

    it("does not show any code in the masked state", () => {
      render(() => <RecoveryCodeDetailModal {...defaultProps} />);
      expect(document.body.textContent).not.toContain("abcd-1234-efgh-5678");
    });

    it("opens ReAuthPrompt when Reveal is clicked", async () => {
      render(() => <RecoveryCodeDetailModal {...defaultProps} />);
      const revealBtn = Array.from(document.querySelectorAll("button")).find((b) =>
        b.textContent?.includes("Reveal"),
      );
      fireEvent.click(revealBtn!);
      await waitFor(() => {
        expect(document.body.textContent).toContain("Verify Your Identity");
      });
    });

    it("reveals the codes after successful re-auth", async () => {
      render(() => <RecoveryCodeDetailModal {...defaultProps} />);
      await revealCodes();
      await waitFor(() => {
        expect(document.body.textContent).toContain("abcd-1234-efgh-5678");
      });
      expect(mockRevealRecoveryCodes).toHaveBeenCalledWith(
        "test-entry-id",
        "correct-horse",
      );
    });

    it("renders the shared auto-hide countdown after reveal", async () => {
      render(() => <RecoveryCodeDetailModal {...defaultProps} />);
      await revealCodes();
      await waitFor(() => {
        expect(
          document.querySelector("[data-testid='auto-hide-countdown']"),
        ).toBeTruthy();
      });
    });

    it("hides the codes again when the countdown Hide button is clicked", async () => {
      render(() => <RecoveryCodeDetailModal {...defaultProps} />);
      await revealCodes();
      await waitFor(() => {
        expect(document.body.textContent).toContain("abcd-1234-efgh-5678");
      });
      const hideBtn = document.querySelector(
        "[data-testid='auto-hide-hide-btn']",
      ) as HTMLElement;
      fireEvent.click(hideBtn);
      await waitFor(() => {
        expect(document.body.textContent).not.toContain("abcd-1234-efgh-5678");
        expect(document.body.textContent).toContain("Recovery codes are hidden");
      });
    });
  });

  describe("alerts", () => {
    it("shows the low-codes warning banner", async () => {
      mockRevealRecoveryCodes.mockResolvedValue(LOW_CODES);
      render(() => <RecoveryCodeDetailModal {...defaultProps} />);
      await revealCodes();
      await waitFor(() => {
        const alert = document.querySelector("[role='alert']");
        expect(alert).toBeTruthy();
        expect(alert!.textContent).toContain("Low recovery codes");
      });
    });

    it("shows the no-codes danger banner", async () => {
      mockRevealRecoveryCodes.mockResolvedValue(NONE_CODES);
      render(() => <RecoveryCodeDetailModal {...defaultProps} />);
      await revealCodes();
      await waitFor(() => {
        const alert = document.querySelector("[role='alert']");
        expect(alert).toBeTruthy();
        expect(alert!.textContent).toContain("No recovery codes remaining");
      });
    });

    it("shows no alert banner when codes are plentiful", async () => {
      render(() => <RecoveryCodeDetailModal {...defaultProps} />);
      await revealCodes();
      await waitFor(() => {
        expect(document.body.textContent).toContain("abcd-1234-efgh-5678");
      });
      expect(document.querySelector("[role='alert']")).toBeNull();
    });
  });

  describe("used/unused toggle", () => {
    it("toggles a code using the retained session password (no countdown restart)", async () => {
      // First reveal returns code 0 unused; toggling marks it used.
      const toggled: RecoveryCodeDisplay = {
        ...TEST_CODES,
        used: [0, 1],
        remainingCodes: 3,
      };
      mockToggleRecoveryCodeUsed.mockResolvedValue(toggled);

      render(() => <RecoveryCodeDetailModal {...defaultProps} />);
      await revealCodes();
      await waitFor(() => {
        expect(document.body.textContent).toContain("abcd-1234-efgh-5678");
      });

      const checkboxes = document.querySelectorAll(
        "input[type='checkbox']",
      ) as NodeListOf<HTMLInputElement>;
      expect(checkboxes.length).toBe(5);

      // First checkbox corresponds to an unused code (unused are sorted first).
      fireEvent.click(checkboxes[0]);

      await waitFor(() => {
        expect(mockToggleRecoveryCodeUsed).toHaveBeenCalledTimes(1);
      });
      // Re-uses the same password captured at reveal.
      expect(mockToggleRecoveryCodeUsed).toHaveBeenCalledWith(
        "test-entry-id",
        expect.any(Number),
        "correct-horse",
      );
      expect(mockToast.success).toHaveBeenCalled();
      // Still revealed — toggling does NOT re-prompt or hide.
      expect(document.body.textContent).toContain("abcd-1234-efgh-5678");
    });

    it("invokes onStatsChanged after a successful toggle", async () => {
      const onStatsChanged = vi.fn();
      render(() => (
        <RecoveryCodeDetailModal {...defaultProps} onStatsChanged={onStatsChanged} />
      ));
      await revealCodes();
      await waitFor(() => {
        expect(document.body.textContent).toContain("abcd-1234-efgh-5678");
      });
      const checkbox = document.querySelector(
        "input[type='checkbox']",
      ) as HTMLInputElement;
      fireEvent.click(checkbox);
      await waitFor(() => {
        expect(onStatsChanged).toHaveBeenCalled();
      });
    });

    it("shows an error toast when the toggle fails", async () => {
      mockToggleRecoveryCodeUsed.mockRejectedValue("Failed to toggle code status.");
      render(() => <RecoveryCodeDetailModal {...defaultProps} />);
      await revealCodes();
      await waitFor(() => {
        expect(document.body.textContent).toContain("abcd-1234-efgh-5678");
      });
      const checkbox = document.querySelector(
        "input[type='checkbox']",
      ) as HTMLInputElement;
      fireEvent.click(checkbox);
      await waitFor(() => {
        expect(mockToast.error).toHaveBeenCalledWith("Failed to toggle code status.");
      });
    });
  });

  describe("delete flow (separate re-auth)", () => {
    it("opens a delete re-auth prompt without revealing codes", async () => {
      render(() => <RecoveryCodeDetailModal {...defaultProps} />);
      const deleteBtn = Array.from(document.querySelectorAll("button")).find(
        (b) => b.textContent?.trim() === "Delete",
      );
      fireEvent.click(deleteBtn!);
      await waitFor(() => {
        expect(document.body.textContent).toContain("Verify Your Identity");
      });
      // Reveal was never triggered.
      expect(mockRevealRecoveryCodes).not.toHaveBeenCalled();
      expect(document.body.textContent).not.toContain("abcd-1234-efgh-5678");
    });

    it("deletes and fires onDeleted after successful re-auth", async () => {
      const onDeleted = vi.fn();
      render(() => (
        <RecoveryCodeDetailModal {...defaultProps} onDeleted={onDeleted} />
      ));
      const deleteBtn = Array.from(document.querySelectorAll("button")).find(
        (b) => b.textContent?.trim() === "Delete",
      );
      fireEvent.click(deleteBtn!);
      await waitFor(() => {
        expect(document.body.textContent).toContain("Verify Your Identity");
      });
      const passwordInput = document.querySelector(
        "input[type='password']",
      ) as HTMLInputElement;
      fireEvent.input(passwordInput, { target: { value: "del-pass" } });
      fireEvent.submit(document.querySelector("form")!);
      await waitFor(() => {
        expect(mockDeleteRecoveryCodeEntry).toHaveBeenCalledWith(
          "test-entry-id",
          "del-pass",
        );
        expect(onDeleted).toHaveBeenCalled();
      });
    });
  });

  describe("error handling", () => {
    it("surfaces an inline error when reveal fails", async () => {
      mockRevealRecoveryCodes.mockRejectedValue(
        "Incorrect password. Recovery codes not revealed.",
      );
      render(() => <RecoveryCodeDetailModal {...defaultProps} />);
      await revealCodes("wrong-password");
      await waitFor(() => {
        expect(document.body.textContent).toContain(
          "Incorrect password. Recovery codes not revealed.",
        );
      });
      // Nothing revealed.
      expect(document.body.textContent).not.toContain("abcd-1234-efgh-5678");
    });
  });

  describe("cleanup on close", () => {
    it("calls onClose when the Close button is clicked", () => {
      const onClose = vi.fn();
      render(() => <RecoveryCodeDetailModal {...defaultProps} onClose={onClose} />);
      const closeBtn = Array.from(document.querySelectorAll("button")).find(
        (b) => b.textContent?.trim() === "Close",
      );
      fireEvent.click(closeBtn!);
      expect(onClose).toHaveBeenCalled();
    });

    it("does not show revealed codes in the initial state", () => {
      render(() => <RecoveryCodeDetailModal {...defaultProps} />);
      expect(
        document.querySelector("[data-testid='auto-hide-countdown']"),
      ).toBeNull();
      expect(document.body.textContent).not.toContain("abcd-1234-efgh-5678");
    });
  });
});
