import { render, fireEvent, waitFor } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { QrTransferReceiveModal } from "../../../features/export/QrTransferReceiveModal";

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

// Mock QR transfer IPC
const mockReceiveQrTransfer = vi.fn();

vi.mock("../../../features/export/qrTransferIpc", () => ({
  receiveQrTransfer: (...args: unknown[]) =>
    mockReceiveQrTransfer(...args),
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

// Mock jsQR — not needed for unit tests since scanning requires real camera
vi.mock("jsqr", () => ({
  default: vi.fn(() => null),
}));

// Mock getUserMedia — camera is not available in test environment
const mockGetUserMedia = vi.fn();

beforeEach(() => {
  mockToast.success.mockClear();
  mockToast.error.mockClear();
  mockReceiveQrTransfer.mockReset();
  mockGetUserMedia.mockReset();

  mockReceiveQrTransfer.mockResolvedValue({ importedCount: 3 });

  // Setup mock for getUserMedia
  Object.defineProperty(navigator, "mediaDevices", {
    value: { getUserMedia: mockGetUserMedia },
    writable: true,
    configurable: true,
  });
});

function renderModal(
  overrides: Partial<{ open: boolean; onClose: () => void }> = {},
) {
  const onClose = overrides.onClose ?? vi.fn();
  const result = render(() => (
    <QrTransferReceiveModal open={overrides.open ?? true} onClose={onClose} />
  ));
  return { ...result, onClose };
}

describe("QrTransferReceiveModal", () => {
  describe("code entry phase", () => {
    it("shows verification code input when opened", () => {
      renderModal();

      expect(document.body.textContent).toContain(
        "Enter the 4-word verification code",
      );
      expect(
        document.querySelector("[data-testid='qr-receive-code-input']"),
      ).toBeTruthy();
      expect(
        document.querySelector("[data-testid='qr-receive-start-scan']"),
      ).toBeTruthy();
    });

    it("disables Start Scanning with empty code", () => {
      renderModal();

      const btn = document.querySelector(
        "[data-testid='qr-receive-start-scan']",
      ) as HTMLButtonElement;
      expect(btn.getAttribute("aria-disabled")).toBe("true");
    });

    it("disables Start Scanning with less than 4 words", () => {
      renderModal();

      const input = document.querySelector(
        "[data-testid='qr-receive-code-input']",
      ) as HTMLInputElement;
      fireEvent.input(input, { target: { value: "alpha bravo charlie" } });

      const btn = document.querySelector(
        "[data-testid='qr-receive-start-scan']",
      ) as HTMLButtonElement;
      expect(btn.getAttribute("aria-disabled")).toBe("true");
    });

    it("enables Start Scanning with 4 words", () => {
      renderModal();

      const input = document.querySelector(
        "[data-testid='qr-receive-code-input']",
      ) as HTMLInputElement;
      fireEvent.input(input, {
        target: { value: "alpha bravo charlie delta" },
      });

      const btn = document.querySelector(
        "[data-testid='qr-receive-start-scan']",
      ) as HTMLButtonElement;
      expect(btn.getAttribute("aria-disabled")).toBeFalsy();
    });

    it("shows hint about 4-word format", () => {
      renderModal();

      expect(document.body.textContent).toContain(
        "4 words separated by spaces",
      );
    });
  });

  describe("camera permission", () => {
    it("shows camera denied message when getUserMedia fails", async () => {
      mockGetUserMedia.mockRejectedValueOnce(
        new DOMException("Permission denied", "NotAllowedError"),
      );

      renderModal();

      const input = document.querySelector(
        "[data-testid='qr-receive-code-input']",
      ) as HTMLInputElement;
      fireEvent.input(input, {
        target: { value: "alpha bravo charlie delta" },
      });

      const form = input.closest("form")!;
      fireEvent.submit(form);

      await waitFor(() => {
        expect(document.body.textContent).toContain(
          "Camera access is required to scan QR codes",
        );
      });
    });

    it("shows Try Again button on camera denied", async () => {
      mockGetUserMedia.mockRejectedValueOnce(
        new DOMException("Permission denied", "NotAllowedError"),
      );

      renderModal();

      const input = document.querySelector(
        "[data-testid='qr-receive-code-input']",
      ) as HTMLInputElement;
      fireEvent.input(input, {
        target: { value: "alpha bravo charlie delta" },
      });
      fireEvent.submit(input.closest("form")!);

      await waitFor(() => {
        expect(
          document.querySelector(
            "[data-testid='qr-receive-retry-camera']",
          ),
        ).toBeTruthy();
      });
    });
  });

  describe("scanning phase", () => {
    it("shows scanning UI when camera starts", async () => {
      // Mock getUserMedia to return a fake stream
      const mockStream = {
        getTracks: () => [{ stop: vi.fn() }],
      };
      mockGetUserMedia.mockResolvedValueOnce(mockStream);

      renderModal();

      const input = document.querySelector(
        "[data-testid='qr-receive-code-input']",
      ) as HTMLInputElement;
      fireEvent.input(input, {
        target: { value: "alpha bravo charlie delta" },
      });
      fireEvent.submit(input.closest("form")!);

      await waitFor(() => {
        expect(
          document.querySelector("[data-testid='qr-receive-done-scanning']"),
        ).toBeTruthy();
        expect(document.body.textContent).toContain("Scanning for QR codes");
      });
    });

    it("shows error when Done Scanning pressed with no chunks", async () => {
      const mockStream = {
        getTracks: () => [{ stop: vi.fn() }],
      };
      mockGetUserMedia.mockResolvedValueOnce(mockStream);

      renderModal();

      const input = document.querySelector(
        "[data-testid='qr-receive-code-input']",
      ) as HTMLInputElement;
      fireEvent.input(input, {
        target: { value: "alpha bravo charlie delta" },
      });
      fireEvent.submit(input.closest("form")!);

      await waitFor(() => {
        expect(
          document.querySelector("[data-testid='qr-receive-done-scanning']"),
        ).toBeTruthy();
      });

      fireEvent.click(
        document.querySelector("[data-testid='qr-receive-done-scanning']")!,
      );

      await waitFor(() => {
        const error = document.querySelector(
          "[data-testid='qr-receive-error']",
        );
        expect(error).toBeTruthy();
        expect(error!.textContent).toContain("No QR codes were scanned");
      });
    });
  });

  describe("error phase", () => {
    it("returns to code phase on retry", async () => {
      const mockStream = {
        getTracks: () => [{ stop: vi.fn() }],
      };
      mockGetUserMedia.mockResolvedValueOnce(mockStream);

      renderModal();

      const input = document.querySelector(
        "[data-testid='qr-receive-code-input']",
      ) as HTMLInputElement;
      fireEvent.input(input, {
        target: { value: "alpha bravo charlie delta" },
      });
      fireEvent.submit(input.closest("form")!);

      await waitFor(() => {
        expect(
          document.querySelector("[data-testid='qr-receive-done-scanning']"),
        ).toBeTruthy();
      });

      fireEvent.click(
        document.querySelector("[data-testid='qr-receive-done-scanning']")!,
      );

      await waitFor(() => {
        expect(
          document.querySelector("[data-testid='qr-receive-retry']"),
        ).toBeTruthy();
      });

      fireEvent.click(
        document.querySelector("[data-testid='qr-receive-retry']")!,
      );

      await waitFor(() => {
        expect(
          document.querySelector("[data-testid='qr-receive-code-input']"),
        ).toBeTruthy();
      });
    });
  });

  describe("cleanup", () => {
    it("calls onClose when Cancel is clicked", () => {
      const onClose = vi.fn();
      renderModal({ onClose });

      const cancelBtns = document.querySelectorAll("button");
      const cancel = Array.from(cancelBtns).find(
        (b) => b.textContent === "Cancel",
      );
      expect(cancel).toBeTruthy();
      fireEvent.click(cancel!);

      expect(onClose).toHaveBeenCalled();
    });

    it("does not render when closed", () => {
      renderModal({ open: false });

      expect(
        document.querySelector("[data-testid='qr-receive-code-input']"),
      ).toBeNull();
    });

    it("stops camera on close during scanning", async () => {
      const mockStop = vi.fn();
      const mockStream = {
        getTracks: () => [{ stop: mockStop }],
      };
      mockGetUserMedia.mockResolvedValueOnce(mockStream);

      const onClose = vi.fn();
      renderModal({ onClose });

      const input = document.querySelector(
        "[data-testid='qr-receive-code-input']",
      ) as HTMLInputElement;
      fireEvent.input(input, {
        target: { value: "alpha bravo charlie delta" },
      });
      fireEvent.submit(input.closest("form")!);

      await waitFor(() => {
        expect(
          document.querySelector("[data-testid='qr-receive-done-scanning']"),
        ).toBeTruthy();
      });

      // Click cancel during scanning
      const cancelBtns = document.querySelectorAll("button");
      const cancel = Array.from(cancelBtns).find(
        (b) => b.textContent === "Cancel",
      );
      fireEvent.click(cancel!);

      expect(mockStop).toHaveBeenCalled();
      expect(onClose).toHaveBeenCalled();
    });
  });
});
