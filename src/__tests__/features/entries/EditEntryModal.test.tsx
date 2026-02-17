import { render, fireEvent, waitFor } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { EditEntryModal } from "../../../features/entries/EditEntryModal";
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

// Known mock store entry IDs
const TOTP_ENTRY_ID = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"; // GitHub, SHA1, 6 digits, 30s
const HOTP_ENTRY_ID = "d4e5f6a7-b8c9-4d0e-1f2a-3b4c5d6e7f80"; // Legacy VPN
const SEED_ENTRY_ID = "e5f6a7b8-c9d0-4e1f-2a3b-4c5d6e7f8091"; // Bitcoin Wallet
const RECOVERY_ENTRY_ID = "f6a7b8c9-d0e1-4f2a-3b4c-5d6e7f809102"; // Google Account
const NOTE_ENTRY_ID = "a7b8c9d0-e1f2-4a3b-4c5d-6e7f80910213"; // Server Credentials

function renderEditModal(
  overrides: Partial<{
    open: boolean;
    entryId: string;
    onClose: () => void;
    onSuccess: () => void;
    onDelete: (entryId: string, entryName: string) => void;
    onExport: (entryId: string, name: string, issuer: string | undefined, entryType: string) => void;
  }> = {},
) {
  const onClose = overrides.onClose ?? vi.fn();
  const onSuccess = overrides.onSuccess ?? vi.fn();
  const onDelete = overrides.onDelete;
  const onExport = overrides.onExport;
  const result = render(() => (
    <EditEntryModal
      open={overrides.open ?? true}
      entryId={overrides.entryId ?? TOTP_ENTRY_ID}
      onClose={onClose}
      onSuccess={onSuccess}
      onDelete={onDelete}
      onExport={onExport}
    />
  ));
  return { ...result, onClose, onSuccess, onDelete, onExport };
}

function getModal() {
  return document.querySelector("[role='dialog']");
}

describe("EditEntryModal", () => {
  describe("rendering (AC #1)", () => {
    it("shows modal with title when open", async () => {
      renderEditModal();
      await waitFor(() => {
        expect(document.body.textContent).toContain("Edit Entry");
      });
    });

    it("does not render dialog when closed", () => {
      renderEditModal({ open: false });
      expect(getModal()).toBeNull();
    });

    it("pre-populates name from fetched entry", async () => {
      renderEditModal({ entryId: TOTP_ENTRY_ID });
      await waitFor(() => {
        const inputs = Array.from(document.querySelectorAll("input"));
        const nameInput = inputs.find((i) => i.value === "GitHub");
        expect(nameInput).toBeTruthy();
      });
    });

    it("pre-populates issuer from fetched entry", async () => {
      renderEditModal({ entryId: TOTP_ENTRY_ID });
      await waitFor(() => {
        const inputs = Array.from(document.querySelectorAll("input"));
        const issuerInput = inputs.find((i) => i.value === "github.com");
        expect(issuerInput).toBeTruthy();
      });
    });

    it("does NOT display the secret field", async () => {
      renderEditModal({ entryId: TOTP_ENTRY_ID });
      // Wait for form to pre-populate
      await waitFor(() => {
        const inputs = Array.from(document.querySelectorAll("input"));
        expect(inputs.find((i) => i.value === "GitHub")).toBeTruthy();
      });
      // Secret should never appear in the form
      expect(document.body.textContent).not.toContain("JBSWY3DPEHPK3PXP");
      const allInputValues = Array.from(document.querySelectorAll("input")).map((i) => i.value);
      expect(allInputValues).not.toContain("JBSWY3DPEHPK3PXP");
      const labels = Array.from(document.querySelectorAll("label"));
      const secretLabel = labels.find((l) => l.textContent?.includes("Secret"));
      expect(secretLabel).toBeUndefined();
    });

    it("shows Cancel and Save Changes buttons", async () => {
      renderEditModal();
      await waitFor(() => {
        expect(document.body.textContent).toContain("Cancel");
        expect(document.body.textContent).toContain("Save Changes");
      });
    });
  });

  describe("type-aware form (AC #6)", () => {
    it("shows advanced settings toggle for TOTP entries", async () => {
      renderEditModal({ entryId: TOTP_ENTRY_ID });
      await waitFor(() => {
        expect(document.body.textContent).toContain("Advanced settings");
      });
    });

    it("shows advanced settings toggle for HOTP entries", async () => {
      renderEditModal({ entryId: HOTP_ENTRY_ID });
      await waitFor(() => {
        expect(document.body.textContent).toContain("Advanced settings");
      });
    });

    it("does NOT show advanced settings for seed_phrase entries", async () => {
      renderEditModal({ entryId: SEED_ENTRY_ID });
      await waitFor(() => {
        const inputs = Array.from(document.querySelectorAll("input"));
        expect(inputs.find((i) => i.value === "Bitcoin Wallet")).toBeTruthy();
      });
      expect(document.body.textContent).not.toContain("Advanced settings");
    });

    it("does NOT show advanced settings for secure_note entries", async () => {
      renderEditModal({ entryId: NOTE_ENTRY_ID });
      await waitFor(() => {
        const inputs = Array.from(document.querySelectorAll("input"));
        expect(inputs.find((i) => i.value === "Server Credentials")).toBeTruthy();
      });
      expect(document.body.textContent).not.toContain("Advanced settings");
    });

    it("does NOT show advanced settings for recovery_code entries", async () => {
      renderEditModal({ entryId: RECOVERY_ENTRY_ID });
      await waitFor(() => {
        const inputs = Array.from(document.querySelectorAll("input"));
        expect(inputs.find((i) => i.value === "Google Account")).toBeTruthy();
      });
      expect(document.body.textContent).not.toContain("Advanced settings");
    });

    it("shows algorithm/digits/period selects when advanced is expanded", async () => {
      renderEditModal({ entryId: TOTP_ENTRY_ID });

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

    it("pre-populates advanced fields with entry values", async () => {
      // AWS Console: SHA256, 8 digits, 30s
      renderEditModal({ entryId: "c3d4e5f6-a7b8-4c9d-0e1f-2a3b4c5d6e7f" });

      await waitFor(() => {
        const advancedBtn = Array.from(document.querySelectorAll("button")).find(
          (b) => b.textContent?.includes("Advanced settings"),
        );
        expect(advancedBtn).toBeTruthy();
        fireEvent.click(advancedBtn!);
      });

      await waitFor(() => {
        const algoSelect = document.querySelector("#select-algorithm") as HTMLSelectElement;
        expect(algoSelect.value).toBe("SHA256");
        const digitsSelect = document.querySelector("#select-digits") as HTMLSelectElement;
        expect(digitsSelect.value).toBe("8");
      });
    });
  });

  describe("parameter change warning (AC #2)", () => {
    it("shows warning when algorithm is changed", async () => {
      renderEditModal({ entryId: TOTP_ENTRY_ID });

      // Open advanced settings
      await waitFor(() => {
        const advancedBtn = Array.from(document.querySelectorAll("button")).find(
          (b) => b.textContent?.includes("Advanced settings"),
        );
        fireEvent.click(advancedBtn!);
      });

      // Change algorithm
      await waitFor(() => {
        const algoSelect = document.querySelector("#select-algorithm") as HTMLSelectElement;
        fireEvent.change(algoSelect, { target: { value: "SHA256" } });
      });

      await waitFor(() => {
        expect(document.body.textContent).toContain(
          "Changing these parameters will generate different codes",
        );
        const alert = document.querySelector("[role='alert']");
        expect(alert).toBeTruthy();
      });
    });

    it("shows warning when digits is changed", async () => {
      renderEditModal({ entryId: TOTP_ENTRY_ID });

      await waitFor(() => {
        const advancedBtn = Array.from(document.querySelectorAll("button")).find(
          (b) => b.textContent?.includes("Advanced settings"),
        );
        fireEvent.click(advancedBtn!);
      });

      await waitFor(() => {
        const digitsSelect = document.querySelector("#select-digits") as HTMLSelectElement;
        fireEvent.change(digitsSelect, { target: { value: "8" } });
      });

      await waitFor(() => {
        const alert = document.querySelector("[role='alert']");
        expect(alert).toBeTruthy();
      });
    });

    it("hides warning when parameters are reverted", async () => {
      renderEditModal({ entryId: TOTP_ENTRY_ID });

      await waitFor(() => {
        const advancedBtn = Array.from(document.querySelectorAll("button")).find(
          (b) => b.textContent?.includes("Advanced settings"),
        );
        fireEvent.click(advancedBtn!);
      });

      // Change algorithm
      await waitFor(() => {
        const algoSelect = document.querySelector("#select-algorithm") as HTMLSelectElement;
        fireEvent.change(algoSelect, { target: { value: "SHA256" } });
      });

      await waitFor(() => {
        expect(document.querySelector("[role='alert']")).toBeTruthy();
      });

      // Revert algorithm
      const algoSelect = document.querySelector("#select-algorithm") as HTMLSelectElement;
      fireEvent.change(algoSelect, { target: { value: "SHA1" } });

      await waitFor(() => {
        expect(document.querySelector("[role='alert']")).toBeNull();
      });
    });
  });

  describe("save flow (AC #3)", () => {
    it("saves changes and shows success toast", async () => {
      const onClose = vi.fn();
      const onSuccess = vi.fn();
      renderEditModal({ entryId: TOTP_ENTRY_ID, onClose, onSuccess });

      // Wait for form to load
      await waitFor(() => {
        const inputs = Array.from(document.querySelectorAll("input"));
        expect(inputs.find((i) => i.value === "GitHub")).toBeTruthy();
      });

      // Change name
      const inputs = Array.from(document.querySelectorAll("input"));
      const nameInput = inputs.find((i) => i.value === "GitHub")!;
      fireEvent.input(nameInput, { target: { value: "GitHub Updated" } });

      // Click save
      const saveBtn = Array.from(document.querySelectorAll("button")).find((b) =>
        b.textContent?.includes("Save Changes"),
      );
      fireEvent.click(saveBtn!);

      await waitFor(() => {
        expect(mockToast.success).toHaveBeenCalledWith("Entry updated");
        expect(onSuccess).toHaveBeenCalled();
        expect(onClose).toHaveBeenCalled();
      });
    });
  });

  describe("cancel flow (AC #4)", () => {
    it("calls onClose when Cancel is clicked without saving", async () => {
      const onClose = vi.fn();
      const onSuccess = vi.fn();
      renderEditModal({ entryId: TOTP_ENTRY_ID, onClose, onSuccess });

      // Wait for form to load
      await waitFor(() => {
        const inputs = Array.from(document.querySelectorAll("input"));
        expect(inputs.find((i) => i.value === "GitHub")).toBeTruthy();
      });

      const cancelBtn = Array.from(document.querySelectorAll("button")).find(
        (b) => b.textContent === "Cancel",
      );
      expect(cancelBtn).toBeTruthy();
      fireEvent.click(cancelBtn!);

      expect(onClose).toHaveBeenCalled();
      expect(onSuccess).not.toHaveBeenCalled();
    });
  });

  describe("validation (AC #5)", () => {
    it("shows error when name is cleared and save is attempted", async () => {
      renderEditModal({ entryId: TOTP_ENTRY_ID });

      await waitFor(() => {
        const inputs = Array.from(document.querySelectorAll("input"));
        expect(inputs.find((i) => i.value === "GitHub")).toBeTruthy();
      });

      // Clear name
      const inputs = Array.from(document.querySelectorAll("input"));
      const nameInput = inputs.find((i) => i.value === "GitHub")!;
      fireEvent.input(nameInput, { target: { value: "" } });

      // Attempt save
      const saveBtn = Array.from(document.querySelectorAll("button")).find((b) =>
        b.textContent?.includes("Save Changes"),
      );
      fireEvent.click(saveBtn!);

      await waitFor(() => {
        expect(document.body.textContent).toContain("Account name is required.");
      });

      // Should NOT call onSuccess
      expect(mockToast.success).not.toHaveBeenCalled();
    });

    it("shows error when issuer exceeds 100 characters", async () => {
      renderEditModal({ entryId: TOTP_ENTRY_ID });

      await waitFor(() => {
        const inputs = Array.from(document.querySelectorAll("input"));
        expect(inputs.find((i) => i.value === "GitHub")).toBeTruthy();
      });

      // Set long issuer
      const inputs = Array.from(document.querySelectorAll("input"));
      const issuerInput = inputs.find((i) => i.value === "github.com")!;
      fireEvent.input(issuerInput, { target: { value: "a".repeat(101) } });

      // Attempt save
      const saveBtn = Array.from(document.querySelectorAll("button")).find((b) =>
        b.textContent?.includes("Save Changes"),
      );
      fireEvent.click(saveBtn!);

      await waitFor(() => {
        expect(document.body.textContent).toContain("Issuer too long");
      });
    });

    it("clears error when user starts typing in name field", async () => {
      renderEditModal({ entryId: TOTP_ENTRY_ID });

      await waitFor(() => {
        const inputs = Array.from(document.querySelectorAll("input"));
        expect(inputs.find((i) => i.value === "GitHub")).toBeTruthy();
      });

      // Clear name and attempt save
      const nameInput = Array.from(document.querySelectorAll("input")).find(
        (i) => i.value === "GitHub",
      )!;
      fireEvent.input(nameInput, { target: { value: "" } });

      const saveBtn = Array.from(document.querySelectorAll("button")).find((b) =>
        b.textContent?.includes("Save Changes"),
      );
      fireEvent.click(saveBtn!);

      await waitFor(() => {
        expect(document.body.textContent).toContain("Account name is required.");
      });

      // Start typing — error should clear
      const nameInputAfter = document.querySelectorAll("input")[0];
      fireEvent.input(nameInputAfter, { target: { value: "N" } });

      await waitFor(() => {
        expect(document.body.textContent).not.toContain("Account name is required.");
      });
    });
  });

  describe("accessibility (AC #7)", () => {
    it("renders as a dialog", async () => {
      renderEditModal();
      await waitFor(() => {
        expect(getModal()).toBeTruthy();
      });
    });

    it("has aria-expanded on advanced toggle", async () => {
      renderEditModal({ entryId: TOTP_ENTRY_ID });

      await waitFor(() => {
        const advancedBtn = Array.from(document.querySelectorAll("button")).find(
          (b) => b.textContent?.includes("Advanced settings"),
        );
        expect(advancedBtn).toBeTruthy();
        expect(advancedBtn!.getAttribute("aria-expanded")).toBe("false");
      });
    });

    it("has visible labels for all form inputs", async () => {
      renderEditModal({ entryId: TOTP_ENTRY_ID });

      await waitFor(() => {
        const labels = Array.from(document.querySelectorAll("label"));
        expect(labels.some((l) => l.textContent === "Account Name")).toBe(true);
        expect(labels.some((l) => l.textContent === "Issuer")).toBe(true);
      });
    });

    it("parameter warning has role='alert'", async () => {
      renderEditModal({ entryId: TOTP_ENTRY_ID });

      await waitFor(() => {
        const advancedBtn = Array.from(document.querySelectorAll("button")).find(
          (b) => b.textContent?.includes("Advanced settings"),
        );
        fireEvent.click(advancedBtn!);
      });

      await waitFor(() => {
        const algoSelect = document.querySelector("#select-algorithm") as HTMLSelectElement;
        fireEvent.change(algoSelect, { target: { value: "SHA512" } });
      });

      await waitFor(() => {
        const alert = document.querySelector("[role='alert']");
        expect(alert).toBeTruthy();
        expect(alert!.textContent).toContain("generate different codes");
      });
    });
  });

  describe("pin toggle control", () => {
    it("shows 'Pin as favorite' checkbox", async () => {
      renderEditModal({ entryId: TOTP_ENTRY_ID });
      await waitFor(() => {
        expect(document.body.textContent).toContain("Pin as favorite");
      });
    });

    it("pre-populates checkbox as checked when entry is pinned", async () => {
      // TOTP_ENTRY_ID (GitHub) is pinned: true in mock store
      renderEditModal({ entryId: TOTP_ENTRY_ID });
      await waitFor(() => {
        const checkbox = document.querySelector("[data-testid='pin-checkbox']") as HTMLInputElement;
        expect(checkbox).toBeTruthy();
        expect(checkbox.checked).toBe(true);
      });
    });

    it("pre-populates checkbox as unchecked when entry is unpinned", async () => {
      // HOTP_ENTRY_ID (Legacy VPN) is pinned: false in mock store
      renderEditModal({ entryId: HOTP_ENTRY_ID });
      await waitFor(() => {
        const checkbox = document.querySelector("[data-testid='pin-checkbox']") as HTMLInputElement;
        expect(checkbox).toBeTruthy();
        expect(checkbox.checked).toBe(false);
      });
    });

    it("toggles pinned state when checkbox is clicked", async () => {
      renderEditModal({ entryId: HOTP_ENTRY_ID });
      await waitFor(() => {
        const checkbox = document.querySelector("[data-testid='pin-checkbox']") as HTMLInputElement;
        expect(checkbox.checked).toBe(false);
      });

      const checkbox = document.querySelector("[data-testid='pin-checkbox']") as HTMLInputElement;
      fireEvent.click(checkbox);

      await waitFor(() => {
        expect(checkbox.checked).toBe(true);
      });
    });
  });

  describe("export URI button", () => {
    it("shows Export URI button for TOTP entries when onExport is provided", async () => {
      const onExport = vi.fn();
      renderEditModal({ entryId: TOTP_ENTRY_ID, onExport });

      await waitFor(() => {
        const btn = document.querySelector("[data-testid='export-uri-btn']");
        expect(btn).toBeTruthy();
        expect(btn!.textContent).toContain("Export URI");
      });
    });

    it("shows Export URI button for HOTP entries when onExport is provided", async () => {
      const onExport = vi.fn();
      renderEditModal({ entryId: HOTP_ENTRY_ID, onExport });

      await waitFor(() => {
        const btn = document.querySelector("[data-testid='export-uri-btn']");
        expect(btn).toBeTruthy();
      });
    });

    it("does NOT show Export URI button for seed_phrase entries", async () => {
      const onExport = vi.fn();
      renderEditModal({ entryId: SEED_ENTRY_ID, onExport });

      await waitFor(() => {
        const inputs = Array.from(document.querySelectorAll("input"));
        expect(inputs.find((i) => i.value === "Bitcoin Wallet")).toBeTruthy();
      });

      expect(document.querySelector("[data-testid='export-uri-btn']")).toBeNull();
    });

    it("does NOT show Export URI button when onExport is not provided", async () => {
      renderEditModal({ entryId: TOTP_ENTRY_ID });

      await waitFor(() => {
        const inputs = Array.from(document.querySelectorAll("input"));
        expect(inputs.find((i) => i.value === "GitHub")).toBeTruthy();
      });

      expect(document.querySelector("[data-testid='export-uri-btn']")).toBeNull();
    });

    it("calls onExport with correct args when clicked", async () => {
      const onExport = vi.fn();
      renderEditModal({ entryId: TOTP_ENTRY_ID, onExport });

      await waitFor(() => {
        const btn = document.querySelector("[data-testid='export-uri-btn']");
        expect(btn).toBeTruthy();
      });

      const btn = document.querySelector("[data-testid='export-uri-btn']") as HTMLButtonElement;
      fireEvent.click(btn);

      expect(onExport).toHaveBeenCalledWith(TOTP_ENTRY_ID, "GitHub", "github.com", "totp");
    });
  });

  describe("delete button (AC #1)", () => {
    it("shows Delete button when onDelete prop is provided", async () => {
      const onDelete = vi.fn();
      renderEditModal({ entryId: TOTP_ENTRY_ID, onDelete });

      await waitFor(() => {
        const buttons = Array.from(document.querySelectorAll("button"));
        expect(buttons.some((b) => b.textContent === "Delete")).toBe(true);
      });
    });

    it("does NOT show Delete button when onDelete prop is omitted", async () => {
      renderEditModal({ entryId: TOTP_ENTRY_ID });

      await waitFor(() => {
        const inputs = Array.from(document.querySelectorAll("input"));
        expect(inputs.find((i) => i.value === "GitHub")).toBeTruthy();
      });

      const buttons = Array.from(document.querySelectorAll("button"));
      expect(buttons.some((b) => b.textContent === "Delete")).toBe(false);
    });

    it("calls onDelete with entryId and entryName when clicked", async () => {
      const onDelete = vi.fn();
      renderEditModal({ entryId: TOTP_ENTRY_ID, onDelete });

      await waitFor(() => {
        const inputs = Array.from(document.querySelectorAll("input"));
        expect(inputs.find((i) => i.value === "GitHub")).toBeTruthy();
      });

      const deleteBtn = Array.from(document.querySelectorAll("button")).find(
        (b) => b.textContent === "Delete",
      );
      expect(deleteBtn).toBeTruthy();
      fireEvent.click(deleteBtn!);

      expect(onDelete).toHaveBeenCalledWith(TOTP_ENTRY_ID, "GitHub");
    });
  });
});
