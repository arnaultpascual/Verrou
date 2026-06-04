import { render, fireEvent, waitFor } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { ExportVaultModal } from "../../../features/export/ExportVaultModal";

// The Modal portals to document.body, so query the document, not the container.
const byTestId = (id: string) => document.querySelector(`[data-testid='${id}']`);

const mockExportVault = vi.fn();
const mockPickExportLocation = vi.fn();

vi.mock("../../../features/export/ipc", () => ({
  exportVault: (...args: unknown[]) => mockExportVault(...args),
  pickExportLocation: (...args: unknown[]) => mockPickExportLocation(...args),
}));

vi.mock("../../../components/useToast", () => ({
  useToast: () => ({
    success: vi.fn(),
    error: vi.fn(),
    info: vi.fn(),
    dismiss: vi.fn(),
    clear: vi.fn(),
  }),
}));

describe("ExportVaultModal", () => {
  beforeEach(() => {
    mockExportVault.mockReset();
    mockPickExportLocation.mockReset();
  });

  it("asks for the save location BEFORE the password (correct order)", () => {
    render(() => <ExportVaultModal open onClose={() => {}} />);
    // Location step first; the password submit is not reachable yet.
    expect(byTestId("export-choose-location")).toBeTruthy();
    expect(byTestId("export-vault-submit")).toBeNull();
  });

  it("advances to the password step only after a location is chosen", async () => {
    mockPickExportLocation.mockResolvedValue(
      "/Users/me/Downloads/vault-export.verrou",
    );
    render(() => <ExportVaultModal open onClose={() => {}} />);

    fireEvent.click(byTestId("export-choose-location")!);

    await waitFor(() => {
      expect(byTestId("export-vault-submit")).toBeTruthy();
      // The chosen destination is shown.
      expect(document.body.textContent).toContain("vault-export.verrou");
    });
  });

  it("stays on the location step if the save dialog is cancelled", async () => {
    mockPickExportLocation.mockResolvedValue(null);
    render(() => <ExportVaultModal open onClose={() => {}} />);

    fireEvent.click(byTestId("export-choose-location")!);

    await waitFor(() => {
      // Never reached the password step — no master password was typed.
      expect(byTestId("export-vault-submit")).toBeNull();
      expect(byTestId("export-choose-location")).toBeTruthy();
    });
  });

  it("exports to the chosen path after authenticating", async () => {
    mockPickExportLocation.mockResolvedValue("/Users/me/vault-export.verrou");
    mockExportVault.mockResolvedValue({
      entryCount: 5,
      folderCount: 2,
      attachmentCount: 1,
    });
    render(() => <ExportVaultModal open onClose={() => {}} />);

    fireEvent.click(byTestId("export-choose-location")!);
    await waitFor(() => expect(byTestId("export-vault-submit")).toBeTruthy());

    const pwInput = document.querySelector(
      "input[type='password']",
    ) as HTMLInputElement;
    fireEvent.input(pwInput, { target: { value: "master-pass" } });
    fireEvent.click(byTestId("export-vault-submit")!);

    await waitFor(() => {
      expect(mockExportVault).toHaveBeenCalledWith(
        "master-pass",
        "/Users/me/vault-export.verrou",
      );
    });
  });
});
