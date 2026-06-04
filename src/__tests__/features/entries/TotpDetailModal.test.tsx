import { render, fireEvent, waitFor } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { TotpDetailModal } from "../../../features/entries/TotpDetailModal";
import { _resetMockStore } from "../../../features/entries/ipc";

// Mock useToast so we can assert the unified copy toast grammar.
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

/** Stub matchMedia for CountdownRing (used inside the live code zone). */
function stubMatchMedia() {
  vi.stubGlobal("matchMedia", (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  }));
}

/** Flush microtasks + small delay for crypto.subtle (live TOTP) to resolve. */
function flushAsync(ms = 80): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

let writeTextMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  stubMatchMedia();
  _resetMockStore();
  vi.clearAllMocks();
  writeTextMock = vi.fn().mockResolvedValue(undefined);
  Object.assign(navigator, {
    clipboard: { writeText: writeTextMock, readText: vi.fn() },
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

// Real mock-store TOTP id so useTotpCode / useCopyOtp resolve against the
// (non-mocked) ipc layer.
const totpProps = {
  open: true,
  onClose: vi.fn(),
  entryId: "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
  entryType: "totp",
  name: "GitHub",
  issuer: "github.com",
  algorithm: "SHA1",
  digits: 6,
  period: 30,
  createdAt: "2026-02-05T10:00:00Z",
  onEdit: vi.fn(),
  onExport: vi.fn(),
  onDelete: vi.fn(),
};

// Real mock-store HOTP id.
const hotpProps = {
  ...totpProps,
  entryId: "d4e5f6a7-b8c9-4d0e-1f2a-3b4c5d6e7f80",
  entryType: "hotp",
  name: "Legacy VPN",
  issuer: "vpn.corp.example.com",
};

describe("TotpDetailModal", () => {
  describe("metadata display (read-only)", () => {
    it("renders the detail title", () => {
      render(() => <TotpDetailModal {...totpProps} />);
      expect(document.body.textContent).toContain("Code Details");
    });

    it("displays name and issuer in the header", () => {
      render(() => <TotpDetailModal {...totpProps} />);
      expect(document.querySelector("[data-testid='totp-detail-name']")!.textContent).toBe("GitHub");
      expect(document.querySelector("[data-testid='totp-detail-issuer']")!.textContent).toBe("github.com");
    });

    it("hides the issuer row when no issuer is provided", () => {
      // Omit `issuer` entirely — in Solid, an explicit `issuer={undefined}` after
      // a spread does NOT override the spread's value (mergeProps keeps it).
      const { issuer: _issuer, ...noIssuer } = totpProps;
      render(() => <TotpDetailModal {...noIssuer} />);
      expect(document.querySelector("[data-testid='totp-detail-issuer']")).toBeNull();
    });

    it("displays algorithm, digits and period as read-only metadata", () => {
      render(() => <TotpDetailModal {...totpProps} />);
      expect(document.querySelector("[data-testid='totp-detail-algorithm']")!.textContent).toBe("SHA1");
      expect(document.querySelector("[data-testid='totp-detail-digits']")!.textContent).toBe("6");
      expect(document.querySelector("[data-testid='totp-detail-period']")!.textContent).toContain("30");
    });

    it("displays the formatted creation date", () => {
      render(() => <TotpDetailModal {...totpProps} />);
      expect(document.body.textContent).toContain("2026");
    });

    it("does not expose any editable crypto-parameter controls", () => {
      render(() => <TotpDetailModal {...totpProps} />);
      // A read-only detail must not let users edit algorithm/digits/period.
      expect(document.querySelectorAll("select").length).toBe(0);
      expect(document.querySelectorAll("input").length).toBe(0);
    });
  });

  describe("live code (TOTP)", () => {
    it("renders the live code zone and resolves a grouped 6-digit code", async () => {
      render(() => <TotpDetailModal {...totpProps} />);
      const codeEl = document.querySelector("[data-testid='totp-detail-code']");
      expect(codeEl).toBeTruthy();

      await flushAsync();
      // "123 456" grouping for 6 digits.
      expect(codeEl!.textContent).toMatch(/^\d{3} \d{3}$/);
    });

    it("copies the code and shows the unified clears-in toast when clicked", async () => {
      render(() => <TotpDetailModal {...totpProps} />);
      await flushAsync();

      const trigger = document.querySelector("[data-testid='totp-detail-copy']") as HTMLElement;
      expect(trigger).toBeTruthy();
      fireEvent.click(trigger);
      await flushAsync();

      // Concealed clipboard write of a raw (un-grouped) 6-digit code.
      expect(writeTextMock).toHaveBeenCalledTimes(1);
      expect(writeTextMock.mock.calls[0][0]).toMatch(/^\d{6}$/);
      // Unified "{name} copied · clears in {n}s" toast (default 30s clipboard clear).
      expect(mockToast.success).toHaveBeenCalledWith("GitHub copied · clears in 30s");
    });
  });

  describe("footer actions", () => {
    it("invokes onEdit with the entry id", () => {
      const onEdit = vi.fn();
      render(() => <TotpDetailModal {...totpProps} onEdit={onEdit} />);
      fireEvent.click(document.querySelector("[data-testid='totp-detail-edit-btn']")!);
      expect(onEdit).toHaveBeenCalledWith(totpProps.entryId);
    });

    it("invokes onExport with the entry id", () => {
      const onExport = vi.fn();
      render(() => <TotpDetailModal {...totpProps} onExport={onExport} />);
      fireEvent.click(document.querySelector("[data-testid='totp-detail-export-btn']")!);
      expect(onExport).toHaveBeenCalledWith(totpProps.entryId);
    });

    it("invokes onDelete with the entry id and name", () => {
      const onDelete = vi.fn();
      render(() => <TotpDetailModal {...totpProps} onDelete={onDelete} />);
      fireEvent.click(document.querySelector("[data-testid='totp-detail-delete-btn']")!);
      expect(onDelete).toHaveBeenCalledWith(totpProps.entryId, totpProps.name);
    });

    it("invokes onClose when Close is pressed", () => {
      const onClose = vi.fn();
      render(() => <TotpDetailModal {...totpProps} onClose={onClose} />);
      const closeBtn = Array.from(document.querySelectorAll("button")).find(
        (b) => b.textContent === "Close",
      );
      expect(closeBtn).toBeTruthy();
      fireEvent.click(closeBtn!);
      expect(onClose).toHaveBeenCalled();
    });
  });

  describe("HOTP variant", () => {
    it("shows a 'Generate next code' button instead of a live code, without auto-generating", async () => {
      render(() => <TotpDetailModal {...hotpProps} />);

      // HOTP shows the generate action; the TOTP live code zone is not rendered.
      expect(document.querySelector("[data-testid='totp-detail-hotp-generate']")).toBeTruthy();
      expect(document.body.textContent).toContain("Generate next code");
      expect(document.querySelector("[data-testid='totp-detail-copy']")).toBeNull();
      expect(document.querySelector("[data-testid='totp-detail-code']")).toBeNull();

      // Counter is event-based: nothing is generated or copied until the user asks.
      await flushAsync();
      expect(writeTextMock).not.toHaveBeenCalled();
      expect(document.querySelector("[data-testid='totp-detail-hotp-code']")).toBeNull();
    });

    it("generates the next code, copies it with the unified toast, and shows the counter", async () => {
      render(() => <TotpDetailModal {...hotpProps} />);

      const generateBtn = document.querySelector("[data-testid='totp-detail-hotp-generate']") as HTMLElement;
      expect(generateBtn).toBeTruthy();
      fireEvent.click(generateBtn);

      // Concealed clipboard write of a raw (un-grouped) 6-digit code.
      await waitFor(() => {
        expect(writeTextMock).toHaveBeenCalledTimes(1);
      });
      expect(writeTextMock.mock.calls[0][0]).toMatch(/^\d{6}$/);

      // Code is revealed (grouped 3-3) and copyable.
      const codeEl = document.querySelector("[data-testid='totp-detail-hotp-code']");
      expect(codeEl!.textContent).toMatch(/^\d{3} \d{3}$/);
      expect(document.querySelector("[data-testid='totp-detail-hotp-copy']")).toBeTruthy();

      // Counter reflects the advance (mock HOTP entry starts at 42 → 43).
      await waitFor(() => {
        expect(document.querySelector("[data-testid='totp-detail-hotp-counter']")!.textContent).toContain("43");
      });

      // Unified "{name} copied · clears in {n}s" toast (default 30s clipboard clear).
      await waitFor(() => {
        expect(mockToast.success).toHaveBeenCalledWith("Legacy VPN copied · clears in 30s");
      });
    });

    it("still shows read-only metadata for HOTP", () => {
      render(() => <TotpDetailModal {...hotpProps} />);
      expect(document.querySelector("[data-testid='totp-detail-name']")!.textContent).toBe("Legacy VPN");
      expect(document.querySelector("[data-testid='totp-detail-algorithm']")!.textContent).toBe("SHA1");
      expect(document.querySelector("[data-testid='totp-detail-digits']")!.textContent).toBe("6");
    });
  });
});
