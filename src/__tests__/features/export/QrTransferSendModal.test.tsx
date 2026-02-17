import { render, fireEvent, waitFor } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { QrTransferSendModal } from "../../../features/export/QrTransferSendModal";

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
const mockListEntries = vi.fn();

vi.mock("../../../features/entries/ipc", () => ({
  listEntries: (...args: unknown[]) => mockListEntries(...args),
}));

// Mock QR transfer IPC
const mockPrepareQrTransfer = vi.fn();
const mockSetScreenCaptureProtection = vi.fn();

vi.mock("../../../features/export/qrTransferIpc", () => ({
  prepareQrTransfer: (...args: unknown[]) =>
    mockPrepareQrTransfer(...args),
  setScreenCaptureProtection: (...args: unknown[]) =>
    mockSetScreenCaptureProtection(...args),
  saveTransferFile: vi.fn().mockResolvedValue("/mock/path.verrou-transfer"),
  loadTransferFile: vi.fn().mockResolvedValue(["chunk1"]),
}));

// Mock vault IPC
vi.mock("../../../features/vault/ipc", () => ({
  parseUnlockError: (err: string) => {
    try {
      const parsed = JSON.parse(err);
      return { code: parsed.code, message: parsed.message };
    } catch {
      return { code: "UNKNOWN", message: err };
    }
  },
}));

// Mock QrCode component (avoids canvas issues in jsdom)
vi.mock("../../../features/entries/QrCode", () => ({
  QrCode: (props: { data: string }) => (
    <div data-testid="mock-qr-code">{props.data}</div>
  ),
}));

const MOCK_ENTRIES = [
  {
    id: "e1",
    name: "GitHub",
    issuer: "github.com",
    entryType: "totp",
    folderName: null,
    isFavorite: false,
    createdAt: "2026-01-01T00:00:00Z",
    updatedAt: "2026-01-01T00:00:00Z",
  },
  {
    id: "e2",
    name: "Bitcoin Wallet",
    issuer: null,
    entryType: "seed_phrase",
    folderName: null,
    isFavorite: false,
    createdAt: "2026-01-01T00:00:00Z",
    updatedAt: "2026-01-01T00:00:00Z",
  },
  {
    id: "e3",
    name: "Service Recovery",
    issuer: "service.com",
    entryType: "recovery_code",
    folderName: null,
    isFavorite: false,
    createdAt: "2026-01-01T00:00:00Z",
    updatedAt: "2026-01-01T00:00:00Z",
  },
];

const MOCK_PREPARE_RESULT = {
  chunks: ["bW9ja18x", "bW9ja18y", "bW9ja18z"],
  verificationCode: "alpha bravo charlie delta",
  totalEntries: 1,
  hasSensitive: false,
};

beforeEach(() => {
  mockToast.success.mockClear();
  mockToast.error.mockClear();
  mockListEntries.mockReset();
  mockPrepareQrTransfer.mockReset();
  mockSetScreenCaptureProtection.mockReset();

  mockListEntries.mockResolvedValue(MOCK_ENTRIES);
  mockPrepareQrTransfer.mockResolvedValue(MOCK_PREPARE_RESULT);
  mockSetScreenCaptureProtection.mockResolvedValue(true);
});

function renderModal(
  overrides: Partial<{ open: boolean; onClose: () => void }> = {},
) {
  const onClose = overrides.onClose ?? vi.fn();
  const result = render(() => (
    <QrTransferSendModal open={overrides.open ?? true} onClose={onClose} />
  ));
  return { ...result, onClose };
}

describe("QrTransferSendModal", () => {
  describe("select phase", () => {
    it("shows entry list when opened", async () => {
      renderModal();

      await waitFor(() => {
        expect(document.body.textContent).toContain("GitHub");
        expect(document.body.textContent).toContain("Bitcoin Wallet");
        expect(document.body.textContent).toContain("Service Recovery");
      });
    });

    it("shows select all checkbox", async () => {
      renderModal();

      await waitFor(() => {
        expect(document.body.textContent).toContain("Select all");
      });
    });

    it("disables Continue button when nothing selected", async () => {
      renderModal();

      await waitFor(() => {
        const btn = document.querySelector(
          "[data-testid='qr-send-continue']",
        ) as HTMLButtonElement;
        expect(btn).toBeTruthy();
        expect(btn.getAttribute("aria-disabled")).toBe("true");
      });
    });

    it("enables Continue after selecting an entry", async () => {
      renderModal();

      await waitFor(() => {
        expect(document.body.textContent).toContain("GitHub");
      });

      const checkboxes = document.querySelectorAll(
        "input[type='checkbox']",
      );
      // First checkbox is "select all", second is "GitHub"
      fireEvent.click(checkboxes[1]);

      const btn = document.querySelector(
        "[data-testid='qr-send-continue']",
      ) as HTMLButtonElement;
      expect(btn.getAttribute("aria-disabled")).toBeFalsy();
    });

    it("shows selection count", async () => {
      renderModal();

      await waitFor(() => {
        expect(document.body.textContent).toContain("0 of 3 selected");
      });
    });
  });

  describe("auth phase for sensitive entries", () => {
    it("shows auth phase when seed phrase is selected", async () => {
      renderModal();

      await waitFor(() => {
        expect(document.body.textContent).toContain("Bitcoin Wallet");
      });

      // Select the seed phrase entry (index 2, after select-all checkbox)
      const checkboxes = document.querySelectorAll(
        "input[type='checkbox']",
      );
      fireEvent.click(checkboxes[2]);

      // Click continue
      fireEvent.click(
        document.querySelector("[data-testid='qr-send-continue']")!,
      );

      await waitFor(() => {
        expect(document.body.textContent).toContain("Re-authentication is required");
        expect(
          document.querySelector("[data-testid='qr-send-auth']"),
        ).toBeTruthy();
      });
    });

    it("skips auth phase for non-sensitive entries", async () => {
      renderModal();

      await waitFor(() => {
        expect(document.body.textContent).toContain("GitHub");
      });

      // Select only the TOTP entry
      const checkboxes = document.querySelectorAll(
        "input[type='checkbox']",
      );
      fireEvent.click(checkboxes[1]);

      fireEvent.click(
        document.querySelector("[data-testid='qr-send-continue']")!,
      );

      // Should skip directly to preparing phase (SecurityCeremony)
      await waitFor(() => {
        expect(mockPrepareQrTransfer).toHaveBeenCalledWith({
          entryIds: ["e1"],
          password: undefined,
        });
      });
    });
  });

  describe("transfer phase", () => {
    it("shows verification code and QR codes after prepare", async () => {
      renderModal();

      await waitFor(() => {
        expect(document.body.textContent).toContain("GitHub");
      });

      // Select TOTP entry and continue
      const checkboxes = document.querySelectorAll(
        "input[type='checkbox']",
      );
      fireEvent.click(checkboxes[1]);
      fireEvent.click(
        document.querySelector("[data-testid='qr-send-continue']")!,
      );

      await waitFor(() => {
        expect(document.body.textContent).toContain("alpha bravo charlie delta");
        expect(
          document.querySelector("[data-testid='qr-send-done']"),
        ).toBeTruthy();
      });
    });

    it("enables screen capture protection", async () => {
      renderModal();

      await waitFor(() => {
        expect(document.body.textContent).toContain("GitHub");
      });

      const checkboxes = document.querySelectorAll(
        "input[type='checkbox']",
      );
      fireEvent.click(checkboxes[1]);
      fireEvent.click(
        document.querySelector("[data-testid='qr-send-continue']")!,
      );

      await waitFor(() => {
        expect(mockSetScreenCaptureProtection).toHaveBeenCalledWith(true);
      });
    });
  });

  describe("error phase", () => {
    it("shows error on prepare failure", async () => {
      mockPrepareQrTransfer.mockRejectedValueOnce("Transfer failed");

      renderModal();

      await waitFor(() => {
        expect(document.body.textContent).toContain("GitHub");
      });

      const checkboxes = document.querySelectorAll(
        "input[type='checkbox']",
      );
      fireEvent.click(checkboxes[1]);
      fireEvent.click(
        document.querySelector("[data-testid='qr-send-continue']")!,
      );

      await waitFor(() => {
        const error = document.querySelector(
          "[data-testid='qr-send-error']",
        );
        expect(error).toBeTruthy();
        expect(error!.textContent).toContain("Transfer failed");
      });
    });

    it("returns to select phase on retry", async () => {
      mockPrepareQrTransfer.mockRejectedValueOnce("Transfer failed");

      renderModal();

      await waitFor(() => {
        expect(document.body.textContent).toContain("GitHub");
      });

      const checkboxes = document.querySelectorAll(
        "input[type='checkbox']",
      );
      fireEvent.click(checkboxes[1]);
      fireEvent.click(
        document.querySelector("[data-testid='qr-send-continue']")!,
      );

      await waitFor(() => {
        expect(
          document.querySelector("[data-testid='qr-send-retry']"),
        ).toBeTruthy();
      });

      fireEvent.click(
        document.querySelector("[data-testid='qr-send-retry']")!,
      );

      await waitFor(() => {
        expect(
          document.querySelector("[data-testid='qr-send-continue']"),
        ).toBeTruthy();
      });
    });
  });

  describe("cleanup", () => {
    it("calls onClose when Done is clicked", async () => {
      const onClose = vi.fn();
      renderModal({ onClose });

      await waitFor(() => {
        expect(document.body.textContent).toContain("GitHub");
      });

      const checkboxes = document.querySelectorAll(
        "input[type='checkbox']",
      );
      fireEvent.click(checkboxes[1]);
      fireEvent.click(
        document.querySelector("[data-testid='qr-send-continue']")!,
      );

      await waitFor(() => {
        expect(
          document.querySelector("[data-testid='qr-send-done']"),
        ).toBeTruthy();
      });

      fireEvent.click(
        document.querySelector("[data-testid='qr-send-done']")!,
      );

      expect(onClose).toHaveBeenCalled();
    });

    it("disables screen capture protection on close", async () => {
      renderModal();

      await waitFor(() => {
        expect(document.body.textContent).toContain("GitHub");
      });

      const checkboxes = document.querySelectorAll(
        "input[type='checkbox']",
      );
      fireEvent.click(checkboxes[1]);
      fireEvent.click(
        document.querySelector("[data-testid='qr-send-continue']")!,
      );

      await waitFor(() => {
        expect(
          document.querySelector("[data-testid='qr-send-done']"),
        ).toBeTruthy();
      });

      fireEvent.click(
        document.querySelector("[data-testid='qr-send-done']")!,
      );

      await waitFor(() => {
        expect(mockSetScreenCaptureProtection).toHaveBeenCalledWith(false);
      });
    });

    it("does not render when closed", () => {
      renderModal({ open: false });

      expect(
        document.querySelector("[data-testid='qr-send-continue']"),
      ).toBeNull();
    });
  });
});
