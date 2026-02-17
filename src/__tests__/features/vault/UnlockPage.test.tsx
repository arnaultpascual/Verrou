import { render, fireEvent, waitFor } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { MemoryRouter, Route } from "@solidjs/router";
import { UnlockPage } from "../../../features/vault/UnlockPage";

// Mock the IPC functions
vi.mock("../../../features/vault/ipc", () => ({
  unlockVault: vi.fn().mockResolvedValue({ unlockCount: 1 }),
  parseUnlockError: vi.fn().mockImplementation((errorStr: string) => {
    try {
      return JSON.parse(errorStr);
    } catch {
      return { code: "UNKNOWN", message: errorStr };
    }
  }),
  checkVaultIntegrity: vi.fn().mockResolvedValue({
    status: { kind: "ok" },
    message: "Vault integrity check passed.",
  }),
}));

// Mock the vault store
vi.mock("../../../stores/vaultStore", () => ({
  setVaultState: vi.fn(),
  vaultState: vi.fn().mockReturnValue("locked"),
}));

// Mock the platform store (biometric unavailable by default in tests)
vi.mock("../../../stores/platformStore", () => ({
  isBiometricAvailable: () => false,
  biometricProviderName: () => "None",
  isHardwareSecurityAvailable: () => false,
  hardwareSecurityProviderName: () => "None",
  platformLoaded: () => true,
  initPlatformCapabilities: vi.fn(),
}));

// Mock useToast
vi.mock("../../../components", async (importOriginal) => {
  const original = await importOriginal<Record<string, unknown>>();
  return {
    ...original,
    useToast: () => ({
      success: vi.fn(),
      error: vi.fn(),
      info: vi.fn(),
      dismiss: vi.fn(),
      clear: vi.fn(),
    }),
  };
});

function renderWithRouter() {
  return render(() => (
    <MemoryRouter
      root={(props) => <>{props.children}</>}
    >
      <Route path="/*" component={() => <UnlockPage />} />
    </MemoryRouter>
  ));
}

describe("UnlockPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders heading", () => {
    const { getByText } = renderWithRouter();
    expect(getByText("Vault is locked")).toBeDefined();
  });

  it("renders password input field", () => {
    const { getByText } = renderWithRouter();
    expect(getByText("Master password")).toBeDefined();
  });

  it("renders unlock button", () => {
    const { getByText } = renderWithRouter();
    expect(getByText("Unlock")).toBeDefined();
  });

  it("renders recovery link", () => {
    const { getByText } = renderWithRouter();
    expect(getByText("Forgot password? Use recovery key")).toBeDefined();
  });

  it("renders offline badge", () => {
    const { getByText } = renderWithRouter();
    expect(getByText("Offline by design")).toBeDefined();
  });

  it("unlock button is disabled when password is empty", () => {
    const { container } = renderWithRouter();
    const button = container.querySelector("button[type='submit']") as HTMLButtonElement;
    expect(button.disabled).toBe(true);
  });

  it("has password input with autocomplete current-password", () => {
    const { container } = renderWithRouter();
    const input = container.querySelector("input[type='password']") as HTMLInputElement;
    expect(input).not.toBeNull();
    expect(input.getAttribute("autocomplete")).toBe("current-password");
  });

  it("shows unlock button enabled after typing password", async () => {
    const { container } = renderWithRouter();
    const input = container.querySelector("input[type='password']") as HTMLInputElement;
    const button = container.querySelector("button[type='submit']") as HTMLButtonElement;

    fireEvent.input(input, { target: { value: "test-password" } });
    await waitFor(() => {
      expect(button.disabled).toBe(false);
    });
  });

  it("shows unlock progress view during unlock attempt", async () => {
    const ipc = await import("../../../features/vault/ipc");
    // Make unlock take a long time so we can check the progress state
    (ipc.unlockVault as ReturnType<typeof vi.fn>).mockImplementation(
      () => new Promise((resolve) => setTimeout(() => resolve({ unlockCount: 1 }), 5000))
    );

    const { container, getByText } = renderWithRouter();
    const input = container.querySelector("input[type='password']") as HTMLInputElement;

    fireEvent.input(input, { target: { value: "test-password" } });

    const form = container.querySelector("form");
    fireEvent.submit(form!);

    await waitFor(() => {
      expect(getByText("Vault is locked")).toBeDefined();
      expect(getByText("vault.unlock.progress.deriving")).toBeDefined();
      const progressbar = container.querySelector("[role='progressbar']");
      expect(progressbar).not.toBeNull();
    });
  });

  it("shows error message on wrong password", async () => {
    const ipc = await import("../../../features/vault/ipc");
    (ipc.unlockVault as ReturnType<typeof vi.fn>).mockRejectedValue(
      JSON.stringify({
        code: "INVALID_PASSWORD",
        message: "Incorrect password. Please try again.",
      })
    );

    const { container, findByText } = renderWithRouter();
    const input = container.querySelector("input[type='password']") as HTMLInputElement;

    fireEvent.input(input, { target: { value: "wrong-password" } });

    const form = container.querySelector("form");
    fireEvent.submit(form!);

    const errorMsg = await findByText("Incorrect password. Please try again.");
    expect(errorMsg).toBeDefined();
  });

  it("recovery link has correct href", () => {
    const { container } = renderWithRouter();
    const link = container.querySelector("a[href='/recovery']");
    expect(link).not.toBeNull();
    expect(link!.textContent).toBe("Forgot password? Use recovery key");
  });
});
