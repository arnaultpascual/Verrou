import { render, waitFor } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach } from "vitest";

// Mock Tauri APIs before component imports
vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => {}),
}));

vi.mock("@tauri-apps/api/window", () => ({
  getCurrentWindow: () => ({
    onFocusChanged: vi.fn().mockResolvedValue(() => {}),
    hide: vi.fn().mockResolvedValue(undefined),
  }),
}));

// Mock useToast since popup uses ToastProvider
vi.mock("../../../components/useToast", () => ({
  useToast: () => ({
    success: vi.fn(),
    error: vi.fn(),
    info: vi.fn(),
    dismiss: vi.fn(),
    clear: vi.fn(),
  }),
}));

// Mock Kobalte toast (used by ToastProvider)
vi.mock("@kobalte/core/toast", () => ({
  Region: (props: { children: unknown }) => props.children,
  List: () => null,
  Root: (props: { children: unknown }) => props.children,
  Description: (props: { children: unknown }) => props.children,
  CloseButton: () => null,
  toaster: { show: vi.fn(), dismiss: vi.fn(), clear: vi.fn() },
}));

// PopupApp routes on vault status from vault/ipc.checkVaultStatus()
vi.mock("../../../features/vault/ipc", async (importOriginal) => {
  const orig = await importOriginal<Record<string, unknown>>();
  return { ...orig, checkVaultStatus: vi.fn(), setVaultDir: vi.fn() };
});

import { listen } from "@tauri-apps/api/event";
import { checkVaultStatus } from "../../../features/vault/ipc";
import { PopupApp } from "../../../features/quick-access/PopupApp";

const asMock = (fn: unknown) => fn as ReturnType<typeof vi.fn>;

describe("PopupApp", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    asMock(checkVaultStatus).mockResolvedValue({
      state: "locked",
      vaultDir: "/mock",
    });
  });

  it("shows CompactUnlock when vault is locked", async () => {
    asMock(checkVaultStatus).mockResolvedValue({
      state: "locked",
      vaultDir: "/mock",
    });

    const { getByText } = render(() => <PopupApp />);

    await waitFor(() => {
      expect(getByText("Unlock")).toBeDefined();
    });
  });

  it("shows QuickSearch when vault is unlocked", async () => {
    asMock(checkVaultStatus).mockResolvedValue({
      state: "unlocked",
      vaultDir: "/mock",
    });

    const { container } = render(() => <PopupApp />);

    await waitFor(() => {
      const searchInput = container.querySelector("input[role='combobox']");
      expect(searchInput).not.toBeNull();
    });
  });

  it("checks vault status on mount", async () => {
    asMock(checkVaultStatus).mockResolvedValue({
      state: "locked",
      vaultDir: "/mock",
    });

    render(() => <PopupApp />);

    await waitFor(() => {
      expect(checkVaultStatus).toHaveBeenCalled();
    });
  });

  it("listens for vault-locked event", async () => {
    render(() => <PopupApp />);

    await waitFor(() => {
      expect(listen).toHaveBeenCalledWith(
        "verrou://vault-locked",
        expect.any(Function),
      );
    });
  });

  it("transitions to locked state on vault-locked event", async () => {
    asMock(checkVaultStatus).mockResolvedValue({
      state: "unlocked",
      vaultDir: "/mock",
    });

    let lockCallback: (() => void) | undefined;
    asMock(listen).mockImplementation((_event: string, cb: () => void) => {
      lockCallback = cb;
      return Promise.resolve(() => {});
    });

    const { getByText, container } = render(() => <PopupApp />);

    // Initially unlocked — search input visible
    await waitFor(() => {
      const searchInput = container.querySelector("input[role='combobox']");
      expect(searchInput).not.toBeNull();
    });

    // Simulate vault lock event
    lockCallback!();

    // Should transition to locked state
    await waitFor(() => {
      expect(getByText("Unlock")).toBeDefined();
    });
  });

  it("defaults to locked state on status error", async () => {
    asMock(checkVaultStatus).mockRejectedValue("Connection failed");

    const { getByText } = render(() => <PopupApp />);

    await waitFor(() => {
      expect(getByText("Unlock")).toBeDefined();
    });
  });
});
