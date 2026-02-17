import { render, fireEvent, waitFor } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { MemoryRouter, Route } from "@solidjs/router";

// Mock vault IPC — changeMasterPassword resolves instantly in tests
vi.mock("../../../features/vault/ipc", () => ({
  changeMasterPassword: vi.fn((_old: string, _new: string) =>
    Promise.resolve({
      formattedKey: "MNPQ-RSTU-VWXY-Z234-5678-ABCD-EFGH",
      vaultFingerprint: "f8e7d6c5b4a39281",
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
}));

// Mock useToast
const mockToastSuccess = vi.fn();
const mockToastError = vi.fn();
vi.mock("../../../components", async (importOriginal) => {
  const original = await importOriginal<Record<string, unknown>>();
  return {
    ...original,
    useToast: () => ({
      success: mockToastSuccess,
      error: mockToastError,
      info: vi.fn(),
      dismiss: vi.fn(),
      clear: vi.fn(),
    }),
  };
});

import { SettingsPage } from "../../../features/settings/SettingsPage";

function renderSettingsPage() {
  return render(() => (
    <MemoryRouter root={(props) => <>{props.children}</>}>
      <Route path="/" component={SettingsPage} />
    </MemoryRouter>
  ));
}

describe("SettingsPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // -- Task 5.7: renders password change button --

  it("renders 'Change Master Password' button", () => {
    const { getByTestId, getByText } = renderSettingsPage();
    expect(getByText("Settings")).toBeDefined();
    expect(getByText("Security")).toBeDefined();
    expect(getByTestId("change-password-start")).toBeDefined();
  });

  // -- Task 5.8: clicking button shows current password input --

  it("clicking 'Change Master Password' shows current password input", async () => {
    const { getByTestId, findByText } = renderSettingsPage();

    fireEvent.click(getByTestId("change-password-start"));

    const heading = await findByText("Verify Your Identity");
    expect(heading).toBeDefined();

    const pwInput = document.getElementById("settings-current-password");
    expect(pwInput).not.toBeNull();
  });

  // -- Task 5.9: submitting correct current password shows new password form --

  it("submitting correct current password shows new password form", async () => {
    const { getByTestId, findByText } = renderSettingsPage();

    fireEvent.click(getByTestId("change-password-start"));
    await findByText("Verify Your Identity");

    const pwInput = document.getElementById("settings-current-password") as HTMLInputElement;
    fireEvent.input(pwInput, { target: { value: "my-current-password" } });

    fireEvent.click(getByTestId("verify-password-btn"));

    // Re-auth is a UI gate — transitions immediately to new password form
    const heading = await findByText("Set New Master Password");
    expect(heading).toBeDefined();
  });

  // -- Task 5.10: new password shows strength meter (mode="create") --

  it("new password form has strength meter", async () => {
    const { getByTestId, findByText } = renderSettingsPage();

    fireEvent.click(getByTestId("change-password-start"));
    await findByText("Verify Your Identity");

    const pwInput = document.getElementById("settings-current-password") as HTMLInputElement;
    fireEvent.input(pwInput, { target: { value: "correct" } });
    fireEvent.click(getByTestId("verify-password-btn"));

    await findByText("Set New Master Password");

    const newPwInput = document.getElementById("settings-new-password") as HTMLInputElement;
    expect(newPwInput).not.toBeNull();

    // Type a password to trigger strength meter
    fireEvent.input(newPwInput, { target: { value: "MyStr0ngP@ssw0rd!" } });

    // The PasswordInput with mode="create" renders a strength meter
    await waitFor(() => {
      const strengthEl = document.querySelector("[class*='strengthLabel']");
      expect(strengthEl).not.toBeNull();
    });
  });

  // -- Task 5.11: password change success shows new recovery key + print + checkbox --

  it("successful password change shows new recovery key display", async () => {
    const { getByTestId, findByText, findByTestId } = renderSettingsPage();

    // Phase 1: Start password change
    fireEvent.click(getByTestId("change-password-start"));
    await findByText("Verify Your Identity");

    // Phase 2: Enter current password
    const currentPw = document.getElementById("settings-current-password") as HTMLInputElement;
    fireEvent.input(currentPw, { target: { value: "correct" } });
    fireEvent.click(getByTestId("verify-password-btn"));

    // Phase 3: Enter new password
    await findByText("Set New Master Password");

    const newPw = document.getElementById("settings-new-password") as HTMLInputElement;
    const confirmPw = document.getElementById("settings-confirm-password") as HTMLInputElement;
    fireEvent.input(newPw, { target: { value: "NewStr0ngP@ss!" } });
    fireEvent.input(confirmPw, { target: { value: "NewStr0ngP@ss!" } });

    await waitFor(() => {
      const changeBtn = getByTestId("change-password-btn") as HTMLButtonElement;
      expect(changeBtn.disabled).toBe(false);
    });

    fireEvent.click(getByTestId("change-password-btn"));

    // Phase 4: Recovery key display — mock resolves instantly, 300ms transition
    const keyEl = await findByTestId("new-recovery-key");
    expect(keyEl.textContent).toBe("MNPQ-RSTU-VWXY-Z234-5678-ABCD-EFGH");

    // Print button
    const printBtn = await findByTestId("print-btn");
    expect(printBtn).toBeDefined();

    // Confirmation checkbox
    const checkbox = await findByTestId("confirm-saved-checkbox");
    expect(checkbox).toBeDefined();

    // Finish button disabled until checkbox checked
    const finishBtn = (await findByTestId("finish-btn")) as HTMLButtonElement;
    expect(finishBtn.disabled).toBe(true);
  });

  // -- Task 5.12: finish returns to settings after confirming --

  it("finish button returns to settings after confirming recovery key saved", async () => {
    const { getByTestId, findByText, findByTestId } = renderSettingsPage();

    // Navigate through the full flow
    fireEvent.click(getByTestId("change-password-start"));
    await findByText("Verify Your Identity");

    const currentPw = document.getElementById("settings-current-password") as HTMLInputElement;
    fireEvent.input(currentPw, { target: { value: "correct" } });
    fireEvent.click(getByTestId("verify-password-btn"));

    await findByText("Set New Master Password");

    const newPw = document.getElementById("settings-new-password") as HTMLInputElement;
    const confirmPw = document.getElementById("settings-confirm-password") as HTMLInputElement;
    fireEvent.input(newPw, { target: { value: "NewStr0ngP@ss!" } });
    fireEvent.input(confirmPw, { target: { value: "NewStr0ngP@ss!" } });

    await waitFor(() => {
      const changeBtn = getByTestId("change-password-btn") as HTMLButtonElement;
      expect(changeBtn.disabled).toBe(false);
    });

    fireEvent.click(getByTestId("change-password-btn"));

    // Wait for new key display
    await findByTestId("new-recovery-key");

    // Check the confirmation checkbox
    const checkbox = await findByTestId("confirm-saved-checkbox");
    fireEvent.click(checkbox);

    // Finish button should be enabled now
    await waitFor(() => {
      const finishBtn = getByTestId("finish-btn") as HTMLButtonElement;
      expect(finishBtn.disabled).toBe(false);
    });

    // Click finish
    fireEvent.click(getByTestId("finish-btn"));

    // Should show success toast and return to idle
    await waitFor(() => {
      expect(mockToastSuccess).toHaveBeenCalledWith("Master password changed successfully");
    });

    // Should be back to idle state
    await waitFor(() => {
      expect(getByTestId("change-password-start")).toBeDefined();
    });
  });

  // -- Extra: wrong current password shows error after backend rejects --

  it("wrong current password shows error after change attempt", async () => {
    const { changeMasterPassword } = await import("../../../features/vault/ipc");
    (changeMasterPassword as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      JSON.stringify({
        code: "INVALID_PASSWORD",
        message: "Current password is incorrect. Please try again.",
      }),
    );

    const { getByTestId, findByText, findByTestId } = renderSettingsPage();

    // Enter current password (wrong)
    fireEvent.click(getByTestId("change-password-start"));
    await findByText("Verify Your Identity");

    const currentPw = document.getElementById("settings-current-password") as HTMLInputElement;
    fireEvent.input(currentPw, { target: { value: "wrong" } });
    fireEvent.click(getByTestId("verify-password-btn"));

    // Goes to new password form (re-auth is UI gate)
    await findByText("Set New Master Password");

    // Enter new password and submit
    const newPw = document.getElementById("settings-new-password") as HTMLInputElement;
    const confirmPw = document.getElementById("settings-confirm-password") as HTMLInputElement;
    fireEvent.input(newPw, { target: { value: "NewStr0ngP@ss!" } });
    fireEvent.input(confirmPw, { target: { value: "NewStr0ngP@ss!" } });

    await waitFor(() => {
      const changeBtn = getByTestId("change-password-btn") as HTMLButtonElement;
      expect(changeBtn.disabled).toBe(false);
    });

    fireEvent.click(getByTestId("change-password-btn"));

    // Backend rejects with INVALID_PASSWORD → goes back to reauth with error
    const errorEl = await findByTestId("reauth-error");
    expect(errorEl.textContent).toBe("Current password is incorrect. Please try again.");
  });

  // -- Paper Backup button --

  it("renders Paper Backup button in Export & Backup section", () => {
    const { getByTestId } = renderSettingsPage();
    const btn = getByTestId("paper-backup-btn");
    expect(btn).toBeDefined();
    expect(btn.textContent).toContain("Paper Backup");
  });

  // -- Clipboard info note --

  it("renders clipboard info note with warning about clipboard managers", () => {
    const { getByTestId } = renderSettingsPage();
    const note = getByTestId("clipboard-info-note");
    expect(note).toBeDefined();
    expect(note.textContent).toContain(
      "Some clipboard managers may retain copied codes",
    );
  });

  // -- Extra: cancel returns to idle --

  it("cancel returns to idle state", async () => {
    const { getByTestId, getByText, findByText } = renderSettingsPage();

    fireEvent.click(getByTestId("change-password-start"));
    await findByText("Verify Your Identity");

    // Click cancel
    fireEvent.click(getByText("Cancel"));

    // Should be back to idle
    await waitFor(() => {
      expect(getByTestId("change-password-start")).toBeDefined();
    });
  });
});
