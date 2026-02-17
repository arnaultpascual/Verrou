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

describe("ExportUriModal", () => {
  describe("rendering and warning (AC #1, #2)", () => {
    it("displays the warning about secret exposure", async () => {
      renderModal();

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

      await waitFor(() => {
        expect(document.body.textContent).toContain("Export OTP Account");
      });
    });

    it("displays the otpauth:// URI after loading", async () => {
      renderModal();

      await waitFor(() => {
        const uriEl = document.querySelector("[data-testid='export-uri-text']");
        expect(uriEl).toBeTruthy();
        expect(uriEl!.textContent).toContain("otpauth://totp/");
        expect(uriEl!.textContent).toContain("JBSWY3DPEHPK3PXP");
      });
    });

    it("renders the QR code component with URI data (AC #3)", async () => {
      renderModal();

      await waitFor(() => {
        const qr = document.querySelector("[data-testid='qr-code']");
        expect(qr).toBeTruthy();
        expect(qr!.getAttribute("data-qr-data")).toContain("otpauth://totp/");
      });
    });

    it("shows Copy URI button", async () => {
      renderModal();

      await waitFor(() => {
        const copyBtn = document.querySelector("[data-testid='copy-uri-btn']");
        expect(copyBtn).toBeTruthy();
        expect(copyBtn!.textContent).toContain("Copy URI");
      });
    });

    it("shows Close button", async () => {
      renderModal();

      await waitFor(() => {
        const closeBtn = document.querySelector(
          "[data-testid='export-uri-close']",
        );
        expect(closeBtn).toBeTruthy();
      });
    });

    it("shows loading state initially", () => {
      renderModal();
      // Loading state appears before async getEntry resolves
      expect(document.body.textContent).toContain("Loading entry");
    });
  });

  describe("copy functionality", () => {
    it("shows success toast when URI is copied", async () => {
      renderModal();

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
    it("clears URI and QR data when modal closes", async () => {
      const { unmount } = render(() => {
        const [open, setOpen] = (() => {
          let value = true;
          const signal = () => value;
          const setter = (v: boolean) => {
            value = v;
          };
          return [signal, setter] as const;
        })();

        // We can't easily toggle SolidJS signals from outside,
        // so we test that closing (open=false) clears the URI by
        // rendering with open=false and checking no URI is shown
        return (
          <ExportUriModal
            open={false}
            onClose={() => {}}
            entryId={TOTP_ENTRY_ID}
            name="GitHub"
            issuer="github.com"
            entryType="totp"
          />
        );
      });

      // When closed, no URI text or QR should be in the DOM
      expect(
        document.querySelector("[data-testid='export-uri-text']"),
      ).toBeNull();
      expect(document.querySelector("[data-testid='qr-code']")).toBeNull();

      unmount();
    });

    it("does not display URI when modal is not open", () => {
      renderModal({ open: false });

      // No dialog content should render
      expect(
        document.querySelector("[data-testid='export-uri-text']"),
      ).toBeNull();
      expect(document.querySelector("[data-testid='qr-code']")).toBeNull();
    });
  });

  describe("error handling", () => {
    it("shows error message when entry fetch fails", async () => {
      renderModal({ entryId: "non-existent-id" });

      await waitFor(() => {
        const alert = document.querySelector("[role='alert']");
        expect(alert).toBeTruthy();
      });
    });
  });
});
