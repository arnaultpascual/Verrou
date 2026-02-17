import { render, fireEvent, waitFor } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { MemoryRouter, Route } from "@solidjs/router";
import { RecoveryPage } from "../../../features/vault/RecoveryPage";

// Mock vault IPC
vi.mock("../../../features/vault/ipc", () => ({
  recoverVault: vi.fn((_key: string) => Promise.resolve({ unlockCount: 1 })),
  changePasswordAfterRecovery: vi.fn(() =>
    Promise.resolve({
      formattedKey: "ABCD-EFGH-JKLM-NPQR-STUV-WXYZ-2345",
      vaultFingerprint: "a1b2c3d4e5f67890",
      generationDate: "2026-02-10T00:00:00Z",
    }),
  ),
  parseUnlockError: vi.fn((errorStr: string) => {
    try {
      return JSON.parse(errorStr);
    } catch {
      return { code: "UNKNOWN", message: errorStr || "An unexpected error occurred." };
    }
  }),
  checkVaultIntegrity: vi.fn().mockResolvedValue({
    status: { kind: "ok" },
    message: "Vault integrity check passed.",
  }),
}));

// Mock vault store
vi.mock("../../../stores/vaultStore", () => ({
  setVaultState: vi.fn(),
  vaultState: vi.fn().mockReturnValue("locked"),
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

function renderRecoveryPage() {
  return render(() => (
    <MemoryRouter root={(props) => <>{props.children}</>}>
      <Route path="/*" component={() => <RecoveryPage />} />
    </MemoryRouter>
  ));
}

describe("RecoveryPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // -- Task 8.6: RecoveryPage renders with recovery key input --

  it("renders with recovery key input form", () => {
    const { getByTestId, getByText } = renderRecoveryPage();
    expect(getByTestId("recovery-key-input")).toBeDefined();
    expect(getByText("Recover Your Vault")).toBeDefined();
    expect(getByText("Recover vault")).toBeDefined();
  });

  it("renders description text", () => {
    const { getByText } = renderRecoveryPage();
    expect(
      getByText("Enter the recovery key you saved when you created your vault."),
    ).toBeDefined();
  });

  it("renders recovery key textarea with correct attributes", () => {
    const { getByTestId } = renderRecoveryPage();
    const input = getByTestId("recovery-key-input") as HTMLTextAreaElement;
    expect(input.tagName).toBe("TEXTAREA");
    expect(input.getAttribute("spellcheck")).toBe("false");
    expect(input.getAttribute("autocomplete")).toBe("off");
    expect(input.getAttribute("aria-label")).toBe("Recovery key");
  });

  it("submit button is disabled when input is empty", () => {
    const { getByText } = renderRecoveryPage();
    const btn = getByText("Recover vault") as HTMLButtonElement;
    expect(btn.disabled).toBe(true);
  });

  it("submit button is enabled when input has value", async () => {
    const { getByTestId, getByText } = renderRecoveryPage();
    const input = getByTestId("recovery-key-input") as HTMLTextAreaElement;

    fireEvent.input(input, {
      target: { value: "ABCD-EFGH-JKLM-NPQR-STUV-WXYZ-2345" },
    });

    await waitFor(() => {
      const btn = getByText("Recover vault") as HTMLButtonElement;
      expect(btn.disabled).toBe(false);
    });
  });

  // -- Task 8.7: submitting valid recovery key shows SecurityCeremony then password form --

  it("submitting valid key shows SecurityCeremony then password form", async () => {
    const { recoverVault } = await import("../../../features/vault/ipc");
    const { getByTestId, getByText, findByText } = renderRecoveryPage();

    const input = getByTestId("recovery-key-input") as HTMLTextAreaElement;
    fireEvent.input(input, {
      target: { value: "ABCD-EFGH-JKLM-NPQR-STUV-WXYZ-2345" },
    });

    const btn = getByText("Recover vault");
    fireEvent.click(btn);

    await waitFor(() => {
      expect(recoverVault).toHaveBeenCalledWith("ABCD-EFGH-JKLM-NPQR-STUV-WXYZ-2345");
    });

    // After recovery succeeds, password form should appear.
    const heading = await findByText("Set New Master Password");
    expect(heading).toBeDefined();
  });

  // -- Task 8.8: submitting invalid key shows error message --

  it("submitting invalid key shows error message", async () => {
    const { recoverVault } = await import("../../../features/vault/ipc");
    (recoverVault as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      JSON.stringify({
        code: "INVALID_RECOVERY_KEY",
        message: "Invalid recovery key. Please check for typos and try again.",
      }),
    );

    const { getByTestId, getByText, findByText } = renderRecoveryPage();
    const input = getByTestId("recovery-key-input") as HTMLTextAreaElement;
    fireEvent.input(input, {
      target: { value: "XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX" },
    });

    const btn = getByText("Recover vault");
    fireEvent.click(btn);

    const error = await findByText(
      "Invalid recovery key. Please check for typos and try again.",
    );
    expect(error).toBeDefined();
  });

  // -- Task 8.9: backoff countdown displayed when rate limited --

  it("displays countdown when rate limited", async () => {
    const { recoverVault } = await import("../../../features/vault/ipc");
    (recoverVault as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      JSON.stringify({
        code: "RATE_LIMITED",
        message: "Too many attempts. Try again in 5 seconds.",
        remainingMs: 5000,
      }),
    );

    const { getByTestId, getByText, findByText } = renderRecoveryPage();
    const input = getByTestId("recovery-key-input") as HTMLTextAreaElement;
    fireEvent.input(input, {
      target: { value: "XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX" },
    });

    fireEvent.click(getByText("Recover vault"));

    // Wait for the cooldown status element.
    await waitFor(() => {
      const statusEl = document.querySelector("[role='status']");
      expect(statusEl).not.toBeNull();
      expect(statusEl!.textContent).toMatch(/Try again in/);
    });
  });

  // -- Task 8.10: post-recovery shows new recovery key + print button + checkbox --

  it("post-recovery shows new recovery key display", async () => {
    const { getByTestId, getByText, findByText, findByTestId } = renderRecoveryPage();

    // Phase 1: Enter recovery key.
    const input = getByTestId("recovery-key-input") as HTMLTextAreaElement;
    fireEvent.input(input, {
      target: { value: "ABCD-EFGH-JKLM-NPQR-STUV-WXYZ-2345" },
    });
    fireEvent.click(getByText("Recover vault"));

    // Phase 2: Wait for password form.
    await findByText("Set New Master Password");

    // Enter new password + confirmation.
    const pwInput = document.getElementById("recovery-new-password") as HTMLInputElement;
    const confirmInput = document.getElementById("recovery-confirm-password") as HTMLInputElement;

    fireEvent.input(pwInput, { target: { value: "MyNewStr0ngP@ss!" } });
    fireEvent.input(confirmInput, { target: { value: "MyNewStr0ngP@ss!" } });

    await waitFor(() => {
      const changeBtn = getByTestId("change-password-btn") as HTMLButtonElement;
      expect(changeBtn.disabled).toBe(false);
    });

    fireEvent.click(getByTestId("change-password-btn"));

    // Phase 3: Wait for new recovery key display.
    const newKey = await findByTestId("new-recovery-key");
    expect(newKey.textContent).toBe("ABCD-EFGH-JKLM-NPQR-STUV-WXYZ-2345");

    // Print button should exist.
    const printBtn = await findByTestId("print-btn");
    expect(printBtn).toBeDefined();

    // Confirmation checkbox should exist.
    const checkbox = await findByTestId("confirm-saved-checkbox");
    expect(checkbox).toBeDefined();

    // Finish button should be disabled until checkbox is checked.
    const finishBtn = await findByTestId("finish-btn");
    expect((finishBtn as HTMLButtonElement).disabled).toBe(true);
  });

  it("finish button enabled after confirming recovery key saved", async () => {
    const { getByTestId, getByText, findByText, findByTestId } = renderRecoveryPage();

    // Phase 1: Enter recovery key.
    const input = getByTestId("recovery-key-input") as HTMLTextAreaElement;
    fireEvent.input(input, {
      target: { value: "ABCD-EFGH-JKLM-NPQR-STUV-WXYZ-2345" },
    });
    fireEvent.click(getByText("Recover vault"));

    // Phase 2: Password form.
    await findByText("Set New Master Password");
    const pwInput = document.getElementById("recovery-new-password") as HTMLInputElement;
    const confirmInput = document.getElementById("recovery-confirm-password") as HTMLInputElement;
    fireEvent.input(pwInput, { target: { value: "MyNewStr0ngP@ss!" } });
    fireEvent.input(confirmInput, { target: { value: "MyNewStr0ngP@ss!" } });

    await waitFor(() => {
      expect((getByTestId("change-password-btn") as HTMLButtonElement).disabled).toBe(false);
    });
    fireEvent.click(getByTestId("change-password-btn"));

    // Phase 3: Check the confirmation checkbox.
    const checkbox = await findByTestId("confirm-saved-checkbox");
    fireEvent.click(checkbox);

    await waitFor(() => {
      const finishBtn = getByTestId("finish-btn") as HTMLButtonElement;
      expect(finishBtn.disabled).toBe(false);
    });
  });

  // -- Task 8.11: "Back to password unlock" link --

  it("back to password link is rendered", () => {
    const { getByTestId } = renderRecoveryPage();
    const link = getByTestId("back-to-unlock") as HTMLAnchorElement;
    expect(link).toBeDefined();
    expect(link.getAttribute("href")).toBe("/unlock");
    expect(link.textContent).toBe("Back to password unlock");
  });
});
