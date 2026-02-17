import { render, fireEvent, waitFor } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { MemoryRouter, Route } from "@solidjs/router";
import { ProtectedLayout } from "../../../features/layout/ProtectedLayout";
import { setVaultState, vaultState } from "../../../stores/vaultStore";

// Mock vault IPC
vi.mock("../../../features/vault/ipc", () => ({
  lockVault: vi.fn(() => Promise.resolve()),
  heartbeat: vi.fn(() => Promise.resolve()),
  onVaultLocked: vi.fn((cb: () => void) => {
    const handler = () => cb();
    window.addEventListener("verrou://vault-locked", handler);
    return () => window.removeEventListener("verrou://vault-locked", handler);
  }),
}));

function mockMatchMedia() {
  vi.stubGlobal("matchMedia", (query: string) => ({
    matches: false,
    media: query,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
  }));
}

function renderProtected(content = "Protected Content") {
  return render(() => (
    <MemoryRouter
      root={(props) => (
        <ProtectedLayout>{props.children}</ProtectedLayout>
      )}
    >
      <Route path="/*" component={() => <p>{content}</p>} />
    </MemoryRouter>
  ));
}

describe("LockVault", () => {
  beforeEach(() => {
    localStorage.clear();
    mockMatchMedia();
    setVaultState("unlocked");
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // -- Keyboard shortcut tests -----------------------------------------

  it("Cmd+L triggers lock when vault is unlocked", async () => {
    const { lockVault } = await import("../../../features/vault/ipc");
    renderProtected();

    fireEvent.keyDown(document, { key: "l", metaKey: true });

    await waitFor(() => {
      expect(lockVault).toHaveBeenCalledTimes(1);
    });
  });

  it("Ctrl+L triggers lock when vault is unlocked", async () => {
    const { lockVault } = await import("../../../features/vault/ipc");
    renderProtected();

    fireEvent.keyDown(document, { key: "l", ctrlKey: true });

    await waitFor(() => {
      expect(lockVault).toHaveBeenCalledTimes(1);
    });
  });

  it("Cmd+L does not trigger lock when vault is already locked", async () => {
    const { lockVault } = await import("../../../features/vault/ipc");
    setVaultState("locked");
    renderProtected();

    fireEvent.keyDown(document, { key: "l", metaKey: true });

    // lockVault should not be called since vault is already locked
    expect(lockVault).not.toHaveBeenCalled();
  });

  it("L key without modifier does not trigger lock", async () => {
    const { lockVault } = await import("../../../features/vault/ipc");
    renderProtected();

    fireEvent.keyDown(document, { key: "l" });

    expect(lockVault).not.toHaveBeenCalled();
  });

  // -- Backend event listener tests ------------------------------------

  it("verrou://vault-locked event sets state to locked", async () => {
    renderProtected();
    expect(vaultState()).toBe("unlocked");

    window.dispatchEvent(new Event("verrou://vault-locked"));

    await waitFor(() => {
      expect(vaultState()).toBe("locked");
    });
  });

  it("verrou://vault-locked event causes content to disappear", async () => {
    const { queryByText } = renderProtected();
    expect(queryByText("Protected Content")).not.toBeNull();

    window.dispatchEvent(new Event("verrou://vault-locked"));

    await waitFor(() => {
      expect(queryByText("Protected Content")).toBeNull();
    });
  });

  // -- Visibility change (system event proxy) --------------------------

  it("locks vault when page becomes hidden", async () => {
    const { lockVault } = await import("../../../features/vault/ipc");
    renderProtected();

    // Simulate page hidden (system sleep / minimize)
    Object.defineProperty(document, "visibilityState", {
      value: "hidden",
      writable: true,
      configurable: true,
    });
    fireEvent(document, new Event("visibilitychange"));

    await waitFor(() => {
      expect(lockVault).toHaveBeenCalled();
    });

    // Restore
    Object.defineProperty(document, "visibilityState", {
      value: "visible",
      writable: true,
      configurable: true,
    });
  });

  it("does not lock when page becomes visible", async () => {
    const { lockVault } = await import("../../../features/vault/ipc");
    renderProtected();

    Object.defineProperty(document, "visibilityState", {
      value: "visible",
      writable: true,
      configurable: true,
    });
    fireEvent(document, new Event("visibilitychange"));

    expect(lockVault).not.toHaveBeenCalled();
  });

  // -- Activity heartbeat tests ----------------------------------------

  it("sends heartbeat on click after debounce interval", async () => {
    const { heartbeat } = await import("../../../features/vault/ipc");
    renderProtected();

    fireEvent.click(document);

    await waitFor(() => {
      expect(heartbeat).toHaveBeenCalledTimes(1);
    });
  });

  it("debounces heartbeat — second click within interval is ignored", async () => {
    const { heartbeat } = await import("../../../features/vault/ipc");
    renderProtected();

    fireEvent.click(document);
    fireEvent.click(document);
    fireEvent.click(document);

    await waitFor(() => {
      // Only 1 heartbeat despite 3 clicks (within 30s debounce)
      expect(heartbeat).toHaveBeenCalledTimes(1);
    });
  });
});
