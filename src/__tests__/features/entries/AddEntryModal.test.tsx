import { render, fireEvent, waitFor } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { AddEntryModal } from "../../../features/entries/AddEntryModal";
import { _resetMockStore } from "../../../features/entries/ipc";

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

beforeEach(() => {
  _resetMockStore();
  mockToast.success.mockClear();
  mockToast.error.mockClear();
});

function renderModal(overrides: Partial<{ open: boolean; onClose: () => void; onSuccess: () => void; initialData: { name?: string; issuer?: string } }> = {}) {
  const onClose = overrides.onClose ?? vi.fn();
  const onSuccess = overrides.onSuccess ?? vi.fn();
  const result = render(() => (
    <AddEntryModal
      open={overrides.open ?? true}
      onClose={onClose}
      onSuccess={onSuccess}
      initialData={overrides.initialData}
    />
  ));
  return { ...result, onClose, onSuccess };
}

function getModal() {
  return document.querySelector("[role='dialog']");
}

describe("AddEntryModal", () => {
  describe("rendering", () => {
    it("shows modal with title when open", () => {
      renderModal();
      expect(document.body.textContent).toContain("Add TOTP Entry");
    });

    it("does not render dialog when closed", () => {
      renderModal({ open: false });
      expect(getModal()).toBeNull();
    });

    it("shows paste area as primary input", () => {
      renderModal();
      const textarea = document.querySelector("#paste-input") as HTMLTextAreaElement;
      expect(textarea).toBeTruthy();
      expect(textarea.tagName).toBe("TEXTAREA");
    });

    it("shows 'Enter manually' link", () => {
      renderModal();
      expect(document.body.textContent).toContain("Enter manually");
    });

    it("shows disabled 'Scan from screen' button", () => {
      renderModal();
      const scanBtn = Array.from(document.querySelectorAll("button")).find((b) =>
        b.textContent?.includes("Scan from screen"),
      );
      expect(scanBtn).toBeTruthy();
      expect(scanBtn!.disabled).toBe(true);
    });

    it("shows Cancel and Save Entry buttons", () => {
      renderModal();
      expect(document.body.textContent).toContain("Cancel");
      expect(document.body.textContent).toContain("Save Entry");
    });
  });

  describe("paste detection — otpauth URI (AC2)", () => {
    it("auto-fills form fields from valid otpauth URI", async () => {
      renderModal();
      const textarea = document.querySelector("#paste-input") as HTMLTextAreaElement;

      fireEvent.input(textarea, {
        target: {
          value:
            "otpauth://totp/GitHub:user%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA256&digits=8&period=60",
        },
      });

      await waitFor(() => {
        expect(document.body.textContent).toContain("Valid otpauth:// URI detected");
      });

      // Form should be visible with pre-filled fields (check DOM property, not attribute)
      const inputs = Array.from(document.querySelectorAll("input"));
      const nameInput = inputs.find((i) => i.value === "user@example.com");
      expect(nameInput).toBeTruthy();

      const issuerInput = inputs.find((i) => i.value === "GitHub");
      expect(issuerInput).toBeTruthy();
    });

    it("shows error for invalid otpauth URI", async () => {
      renderModal();
      const textarea = document.querySelector("#paste-input") as HTMLTextAreaElement;

      fireEvent.input(textarea, {
        target: { value: "otpauth://totp/Test?issuer=NoSecret" },
      });

      await waitFor(() => {
        expect(document.body.textContent).toContain(
          "This doesn't look like a valid setup key",
        );
      });
    });
  });

  describe("paste detection — Base32 key (AC3)", () => {
    it("detects raw Base32 key and shows form fields", async () => {
      renderModal();
      const textarea = document.querySelector("#paste-input") as HTMLTextAreaElement;

      fireEvent.input(textarea, {
        target: { value: "JBSWY3DPEHPK3PXP" },
      });

      await waitFor(() => {
        expect(document.body.textContent).toContain("Valid Base32 key detected");
      });

      // Name field should now be visible
      const labels = Array.from(document.querySelectorAll("label"));
      const nameLabel = labels.find((l) => l.textContent === "Account Name");
      expect(nameLabel).toBeTruthy();
    });
  });

  describe("manual entry (AC4)", () => {
    it("expands form when 'Enter manually' is clicked", async () => {
      renderModal();
      const manualBtn = Array.from(document.querySelectorAll("button")).find((b) =>
        b.textContent?.includes("Enter manually"),
      );
      expect(manualBtn).toBeTruthy();

      fireEvent.click(manualBtn!);

      await waitFor(() => {
        const labels = Array.from(document.querySelectorAll("label"));
        expect(labels.some((l) => l.textContent === "Account Name")).toBe(true);
        expect(labels.some((l) => l.textContent === "Secret Key")).toBe(true);
      });
    });

    it("shows advanced settings when toggled", async () => {
      renderModal();

      // Click manual toggle first
      const manualBtn = Array.from(document.querySelectorAll("button")).find((b) =>
        b.textContent?.includes("Enter manually"),
      );
      fireEvent.click(manualBtn!);

      // Click advanced toggle
      await waitFor(() => {
        const advancedBtn = Array.from(document.querySelectorAll("button")).find(
          (b) => b.textContent?.includes("Advanced settings"),
        );
        expect(advancedBtn).toBeTruthy();
        fireEvent.click(advancedBtn!);
      });

      await waitFor(() => {
        expect(document.querySelector("#select-algorithm")).toBeTruthy();
        expect(document.querySelector("#select-digits")).toBeTruthy();
        expect(document.querySelector("#select-period")).toBeTruthy();
      });
    });
  });

  describe("save flow (AC5)", () => {
    it("saves entry and shows success toast", async () => {
      const onClose = vi.fn();
      const onSuccess = vi.fn();
      renderModal({ onClose, onSuccess });

      const textarea = document.querySelector("#paste-input") as HTMLTextAreaElement;
      fireEvent.input(textarea, {
        target: {
          value:
            "otpauth://totp/GitHub:user@github.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
        },
      });

      await waitFor(() => {
        expect(document.body.textContent).toContain("Valid otpauth:// URI detected");
      });

      // Click Save
      const saveBtn = Array.from(document.querySelectorAll("button")).find((b) =>
        b.textContent?.includes("Save Entry"),
      );
      expect(saveBtn).toBeTruthy();
      fireEvent.click(saveBtn!);

      await waitFor(() => {
        expect(mockToast.success).toHaveBeenCalledWith(
          expect.stringContaining("added to vault"),
        );
        expect(onSuccess).toHaveBeenCalled();
        expect(onClose).toHaveBeenCalled();
      });
    });
  });

  describe("validation errors (AC6)", () => {
    it("shows error when name is empty on save", async () => {
      renderModal();

      // Paste a Base32 key (no name auto-filled)
      const textarea = document.querySelector("#paste-input") as HTMLTextAreaElement;
      fireEvent.input(textarea, {
        target: { value: "JBSWY3DPEHPK3PXP" },
      });

      await waitFor(() => {
        expect(document.body.textContent).toContain("Valid Base32 key detected");
      });

      // Try to save without entering name
      const saveBtn = Array.from(document.querySelectorAll("button")).find((b) =>
        b.textContent?.includes("Save Entry"),
      );
      fireEvent.click(saveBtn!);

      await waitFor(() => {
        expect(document.body.textContent).toContain("Account name is required.");
      });
    });

    it("shows real-time Base32 validation error in manual mode", async () => {
      renderModal();

      const manualBtn = Array.from(document.querySelectorAll("button")).find((b) =>
        b.textContent?.includes("Enter manually"),
      );
      fireEvent.click(manualBtn!);

      await waitFor(() => {
        // Find the secret key input
        const secretInput = Array.from(document.querySelectorAll("input")).find(
          (i) => i.placeholder === "Base32 encoded key",
        );
        expect(secretInput).toBeTruthy();

        fireEvent.input(secretInput!, { target: { value: "NOT-VALID!" } });
      });

      await waitFor(() => {
        expect(document.body.textContent).toContain(
          "Secret must be valid Base32",
        );
      });
    });
  });

  describe("cancel flow", () => {
    it("calls onClose when cancel is clicked", async () => {
      const onClose = vi.fn();
      renderModal({ onClose });

      const cancelBtn = Array.from(document.querySelectorAll("button")).find((b) =>
        b.textContent === "Cancel",
      );
      expect(cancelBtn).toBeTruthy();
      fireEvent.click(cancelBtn!);

      expect(onClose).toHaveBeenCalled();
    });
  });

  describe("accessibility", () => {
    it("has aria-expanded on advanced toggle", async () => {
      renderModal();

      const manualBtn = Array.from(document.querySelectorAll("button")).find((b) =>
        b.textContent?.includes("Enter manually"),
      );
      fireEvent.click(manualBtn!);

      await waitFor(() => {
        const advancedBtn = Array.from(document.querySelectorAll("button")).find(
          (b) => b.textContent?.includes("Advanced settings"),
        );
        expect(advancedBtn).toBeTruthy();
        expect(advancedBtn!.getAttribute("aria-expanded")).toBe("false");
      });
    });

    it("has visible labels for all inputs", () => {
      renderModal();

      const pasteLabel = document.querySelector("label[for='paste-input']");
      expect(pasteLabel).toBeTruthy();
      expect(pasteLabel!.textContent).toContain("Paste your setup key");
    });
  });

  describe("initialData prop (Story 5.5)", () => {
    it("opens in manual mode with pre-populated name and issuer", async () => {
      renderModal({ initialData: { name: "Steam Guard", issuer: "Steam" } });

      await waitFor(() => {
        // Should show manual form fields (name and issuer pre-filled)
        const inputs = Array.from(document.querySelectorAll("input"));
        const nameInput = inputs.find((i) => i.value === "Steam Guard");
        expect(nameInput).toBeTruthy();

        const issuerInput = inputs.find((i) => i.value === "Steam");
        expect(issuerInput).toBeTruthy();
      });
    });

    it("shows secret key input in manual mode", async () => {
      renderModal({ initialData: { name: "Test" } });

      await waitFor(() => {
        const secretInput = Array.from(document.querySelectorAll("input")).find(
          (i) => i.placeholder === "Base32 encoded key",
        );
        expect(secretInput).toBeTruthy();
      });
    });

    it("opens with empty fields when initialData has no values", async () => {
      renderModal({ initialData: {} });

      await waitFor(() => {
        // Should still be in manual mode with empty fields
        const labels = Array.from(document.querySelectorAll("label"));
        expect(labels.some((l) => l.textContent === "Account Name")).toBe(true);
        expect(labels.some((l) => l.textContent === "Secret Key")).toBe(true);
      });
    });

    it("hides paste area and method toggles when initialData is provided", async () => {
      renderModal({ initialData: { name: "Test" } });

      await waitFor(() => {
        // Paste textarea should not be rendered
        const textarea = document.querySelector("#paste-input");
        expect(textarea).toBeNull();

        // "Enter manually" toggle should be hidden
        const manualBtn = Array.from(document.querySelectorAll("button")).find((b) =>
          b.textContent?.includes("Enter manually"),
        );
        expect(manualBtn).toBeFalsy();

        // "Scan from screen" should be hidden
        const scanBtn = Array.from(document.querySelectorAll("button")).find((b) =>
          b.textContent?.includes("Scan from screen"),
        );
        expect(scanBtn).toBeFalsy();
      });
    });
  });
});
