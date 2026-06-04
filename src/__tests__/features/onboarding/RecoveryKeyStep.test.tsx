import { render, fireEvent } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { RecoveryKeyStep } from "../../../features/onboarding/RecoveryKeyStep";
import { wizardStore, setWizardStore } from "../../../features/onboarding/stores";

// Mock clipboard for copy button
vi.mock("../../../features/entries/ipc", () => ({
  copyToClipboard: vi.fn().mockResolvedValue(undefined),
}));

// Mock the IPC functions to avoid real delays
vi.mock("../../../features/onboarding/ipc", () => ({
  createVault: vi.fn().mockResolvedValue({
    vaultPath: "~/.verrou/vault.verrou",
    dbPath: "~/.verrou/vault.db",
    kdfPreset: "balanced",
  }),
  getRecoveryKey: vi.fn().mockResolvedValue({
    formattedKey: "TEST-ABCD-EFGH-JKLM",
    vaultFingerprint: "testfp123",
    generationDate: "2026-02-06T00:00:00.000Z",
  }),
}));

// Mock useToast (now used for error handling)
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

describe("RecoveryKeyStep", () => {
  beforeEach(() => {
    setWizardStore({
      password: "test-password",
      confirmPassword: "test-password",
      kdfPreset: "balanced",
      recoveryKeyConfirmed: false,
      recoveryKey: null,
      vaultFingerprint: null,
      isCreating: false,
    });
  });

  it("renders heading (creation phase)", () => {
    const { getByText } = render(() => (
      <RecoveryKeyStep onValidChange={vi.fn()} />
    ));
    expect(getByText("Creating your vault")).toBeDefined();
  });

  it("renders heading (done phase)", () => {
    setWizardStore("recoveryKey", "SOME-KEY");
    const { getByText } = render(() => (
      <RecoveryKeyStep onValidChange={vi.fn()} />
    ));
    expect(getByText("Save your recovery key")).toBeDefined();
  });

  it("shows an honest indeterminate 'encrypting' message initially", () => {
    const { getByText } = render(() => (
      <RecoveryKeyStep onValidChange={vi.fn()} />
    ));
    expect(getByText("Encrypting your vault…")).toBeDefined();
  });

  it("does NOT show a fake progress bar during creation", () => {
    const { container } = render(() => (
      <RecoveryKeyStep onValidChange={vi.fn()} />
    ));
    // Honest by construction: an indeterminate spinner, never a scripted % bar.
    expect(container.querySelector("[role='progressbar']")).toBeNull();
  });

  it("calls onValidChange(false) when recovery key is not confirmed", () => {
    const onValid = vi.fn();
    render(() => <RecoveryKeyStep onValidChange={onValid} />);
    expect(onValid).toHaveBeenCalledWith(false);
  });

  it("shows recovery key when already set in store", async () => {
    setWizardStore("recoveryKey", "ALREADY-SET-KEY");
    setWizardStore("vaultFingerprint", "fp999");
    const { getByText, findByText } = render(() => (
      <RecoveryKeyStep onValidChange={vi.fn()} />
    ));
    // When recoveryKey is already in store, it skips ceremony
    expect(getByText("ALREADY-SET-KEY")).toBeDefined();
    expect(getByText(/fp999/)).toBeDefined();
  });

  it("shows recovery description when creation is done", () => {
    setWizardStore("recoveryKey", "SOME-KEY");
    const { getByText } = render(() => (
      <RecoveryKeyStep onValidChange={vi.fn()} />
    ));
    expect(getByText(/only way to recover/)).toBeDefined();
  });

  it("shows print button after creation", () => {
    setWizardStore("recoveryKey", "SOME-KEY");
    const { getByText } = render(() => (
      <RecoveryKeyStep onValidChange={vi.fn()} />
    ));
    expect(getByText("Print")).toBeDefined();
  });

  it("shows a confirm-by-re-entry field (not a checkbox) after creation", () => {
    setWizardStore("recoveryKey", "SOME-KEY");
    const { getByText, getByTestId, container } = render(() => (
      <RecoveryKeyStep onValidChange={vi.fn()} />
    ));
    expect(
      getByText("Re-enter your recovery key to confirm you've saved it"),
    ).toBeDefined();
    expect(getByTestId("recovery-confirm-input")).toBeDefined();
    // The old "just tick a box" affordance is gone.
    expect(container.querySelector("input[type='checkbox']")).toBeNull();
  });

  it("warns that the recovery key is shown only once", () => {
    setWizardStore("recoveryKey", "SOME-KEY");
    const { getByText } = render(() => (
      <RecoveryKeyStep onValidChange={vi.fn()} />
    ));
    expect(getByText(/shown once/)).toBeDefined();
  });

  it("only confirms when the key is re-entered correctly (case/separator-insensitive)", () => {
    setWizardStore("recoveryKey", "TEST-ABCD-EFGH-JKLM");
    const onValid = vi.fn();
    const { getByTestId } = render(() => <RecoveryKeyStep onValidChange={onValid} />);
    const input = getByTestId("recovery-confirm-input") as HTMLInputElement;

    fireEvent.input(input, { target: { value: "wrong" } });
    expect(onValid).not.toHaveBeenCalledWith(true);
    expect(wizardStore.recoveryKeyConfirmed).toBe(false);

    fireEvent.input(input, { target: { value: "test abcd efgh jklm" } });
    expect(wizardStore.recoveryKeyConfirmed).toBe(true);
    expect(onValid).toHaveBeenCalledWith(true);
  });

  it("calls onValidChange(true) when already confirmed in store", () => {
    setWizardStore("recoveryKey", "SOME-KEY");
    setWizardStore("recoveryKeyConfirmed", true);
    const onValid = vi.fn();
    render(() => <RecoveryKeyStep onValidChange={onValid} />);
    expect(onValid).toHaveBeenCalledWith(true);
  });

  it("shows copy button after creation", () => {
    setWizardStore("recoveryKey", "SOME-KEY");
    const { getByTestId } = render(() => (
      <RecoveryKeyStep onValidChange={vi.fn()} />
    ));
    expect(getByTestId("copy-recovery-key")).toBeDefined();
  });

  it("has data-testid on recovery key display", () => {
    setWizardStore("recoveryKey", "TEST-KEY");
    const { container } = render(() => (
      <RecoveryKeyStep onValidChange={vi.fn()} />
    ));
    const keyEl = container.querySelector("[data-testid='recovery-key']");
    expect(keyEl).not.toBeNull();
    expect(keyEl!.textContent).toBe("TEST-KEY");
  });
});
