import { render, fireEvent, waitFor } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { ExportUriModal } from "../../../features/entries/ExportUriModal";
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

// Mock QrCode component to avoid canvas complexity in jsdom
vi.mock("../../../features/entries/QrCode", () => ({
  QrCode: (props: { data: string; size?: number }) => (
    <div data-testid="qr-code" data-qr-data={props.data}>
      QR:{props.data ? "rendered" : "empty"}
    </div>
  ),
}));

const TOTP_ENTRY_ID = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"; // GitHub

beforeEach(() => {
  _resetMockStore();
  mockToast.success.mockClear();
  mockToast.error.mockClear();

  // Provide navigator.clipboard in jsdom
  Object.assign(navigator, {
    clipboard: {
      writeText: vi.fn().mockResolvedValue(undefined),
      readText: vi.fn().mockResolvedValue(""),
    },
  });
});

function renderModal(
  overrides: Partial<{
    open: boolean;
    entryId: string;
    name: string;
    issuer: string;
    entryType: string;
    onClose: () => void;
  }> = {},
) {
  const onClose = overrides.onClose ?? vi.fn();
  const result = render(() => (
    <ExportUriModal
      open={overrides.open ?? true}
      onClose={onClose}
      entryId={overrides.entryId ?? TOTP_ENTRY_ID}
      name={overrides.name ?? "GitHub"}
      issuer={overrides.issuer ?? "github.com"}
      entryType={overrides.entryType ?? "totp"}
    />
  ));
  return { ...result, onClose };
}

/**
 * Drive the re-auth gate: wait for the prompt, enter a password, submit.
 * The export content (URI + QR) only appears after this succeeds.
 */
async function passReAuth(password = "master-pass") {
  await waitFor(() => {
    expect(document.body.textContent).toContain("Verify Your Identity");
  });
  const passwordInput = document.querySelector(
    "input[type='password']",
  ) as HTMLInputElement;
  fireEvent.input(passwordInput, { target: { value: password } });
  const form = document.querySelector("form") as HTMLFormElement;
  fireEvent.submit(form);
}

describe("ExportUriModal", () => {
  describe("re-auth gate", () => {
    it("shows the re-auth prompt before revealing anything", () => {
      renderModal();
      // The export content must not be present until re-auth succeeds.
      expect(
        document.querySelector("[data-testid='export-uri-text']"),
      ).toBeNull();
      expect(document.body.textContent).toContain("Verify Your Identity");
    });

    it("surfaces an inline error when the reveal fails", async () => {
      renderModal({ entryId: "non-existent-id" });
      await passReAuth();
      await waitFor(() => {
        expect(document.body.textContent).toContain("Entry not found.");
      });
      // Still gated — no URI leaked.
      expect(
        document.querySelector("[data-testid='export-uri-text']"),
      ).toBeNull();
    });
  });

  describe("rendering and warning (AC #1, #2)", () => {
    it("displays the warning about secret exposure", async () => {
      renderModal();
      await passReAuth();

      await waitFor(() => {
        expect(document.body.textContent).toContain(
          "This will expose the secret key",
        );
        expect(document.body.textContent).toContain("GitHub");
        expect(document.body.textContent).toContain("trusted applications");
      });
    });

    it("shows modal title 'Export OTP Account'", async () => {
      renderModal();
      await passReAuth();

      await waitFor(() => {
        expect(document.body.textContent).toContain("Export OTP Account");
      });
    });

    it("displays the otpauth:// URI after re-auth", async () => {
      renderModal();
      await passReAuth();

      await waitFor(() => {
        const uriEl = document.querySelector("[data-testid='export-uri-text']");
        expect(uriEl).toBeTruthy();
        expect(uriEl!.textContent).toContain("otpauth://totp/");
        expect(uriEl!.textContent).toContain("JBSWY3DPEHPK3PXP");
      });
    });

    it("renders the QR code component with URI data (AC #3)", async () => {
      renderModal();
      await passReAuth();

      await waitFor(() => {
        const qr = document.querySelector("[data-testid='qr-code']");
        expect(qr).toBeTruthy();
        expect(qr!.getAttribute("data-qr-data")).toContain("otpauth://totp/");
      });
    });

    it("shows Copy URI button", async () => {
      renderModal();
      await passReAuth();

      await waitFor(() => {
        const copyBtn = document.querySelector("[data-testid='copy-uri-btn']");
        expect(copyBtn).toBeTruthy();
        expect(copyBtn!.textContent).toContain("Copy URI");
      });
    });

    it("shows Close button", async () => {
      renderModal();
      await passReAuth();

      await waitFor(() => {
        const closeBtn = document.querySelector(
          "[data-testid='export-uri-close']",
        );
        expect(closeBtn).toBeTruthy();
      });
    });
  });

  describe("copy functionality", () => {
    it("shows success toast when URI is copied", async () => {
      renderModal();
      await passReAuth();

      await waitFor(() => {
        expect(
          document.querySelector("[data-testid='copy-uri-btn']"),
        ).toBeTruthy();
      });

      const copyBtn = document.querySelector(
        "[data-testid='copy-uri-btn']",
      ) as HTMLButtonElement;
      fireEvent.click(copyBtn);

      await waitFor(() => {
        expect(mockToast.success).toHaveBeenCalledWith(
          "URI copied to clipboard",
        );
      });
    });
  });

  describe("close button", () => {
    it("calls onClose when Close button is clicked", async () => {
      const onClose = vi.fn();
      renderModal({ onClose });
      await passReAuth();

      await waitFor(() => {
        expect(
          document.querySelector("[data-testid='export-uri-close']"),
        ).toBeTruthy();
      });

      const closeBtn = document.querySelector(
        "[data-testid='export-uri-close']",
      ) as HTMLButtonElement;
      fireEvent.click(closeBtn);

      expect(onClose).toHaveBeenCalled();
    });
  });

  describe("DOM cleanup on close (AC #4)", () => {
    it("does not display URI when modal is not open", () => {
      renderModal({ open: false });

      // No dialog content should render
      expect(
        document.querySelector("[data-testid='export-uri-text']"),
      ).toBeNull();
      expect(document.querySelector("[data-testid='qr-code']")).toBeNull();
      // Nor the re-auth gate.
      expect(document.body.textContent).not.toContain("Verify Your Identity");
    });
  });
});
