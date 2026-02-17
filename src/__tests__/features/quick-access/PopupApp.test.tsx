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

import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { PopupApp } from "../../../features/quick-access/PopupApp";

describe("PopupApp", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("shows CompactUnlock when vault is locked", async () => {
    (invoke as ReturnType<typeof vi.fn>).mockResolvedValue(false);

    const { getByText } = render(() => <PopupApp />);

    await waitFor(() => {
      expect(getByText("Unlock")).toBeDefined();
    });
  });

  it("shows QuickSearch when vault is unlocked", async () => {
    (invoke as ReturnType<typeof vi.fn>).mockResolvedValue(true);

    const { container } = render(() => <PopupApp />);

    await waitFor(() => {
      const searchInput = container.querySelector("input[role='combobox']");
      expect(searchInput).not.toBeNull();
    });
  });

  it("calls is_vault_unlocked on mount", async () => {
    (invoke as ReturnType<typeof vi.fn>).mockResolvedValue(false);

    render(() => <PopupApp />);

    await waitFor(() => {
      expect(invoke).toHaveBeenCalledWith("is_vault_unlocked");
    });
  });

  it("listens for vault-locked event", async () => {
    (invoke as ReturnType<typeof vi.fn>).mockResolvedValue(false);

    render(() => <PopupApp />);

    await waitFor(() => {
      expect(listen).toHaveBeenCalledWith(
        "verrou://vault-locked",
        expect.any(Function),
      );
    });
  });

  it("transitions to locked state on vault-locked event", async () => {
    (invoke as ReturnType<typeof vi.fn>).mockResolvedValue(true);

    let lockCallback: (() => void) | undefined;
    (listen as ReturnType<typeof vi.fn>).mockImplementation(
      (_event: string, cb: () => void) => {
        lockCallback = cb;
        return Promise.resolve(() => {});
      },
    );

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

  it("defaults to locked state on invoke error", async () => {
    (invoke as ReturnType<typeof vi.fn>).mockRejectedValue("Connection failed");

    const { getByText } = render(() => <PopupApp />);

    await waitFor(() => {
      expect(getByText("Unlock")).toBeDefined();
    });
  });
});
