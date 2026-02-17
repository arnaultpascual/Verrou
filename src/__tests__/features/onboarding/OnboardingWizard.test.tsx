import { render, fireEvent } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { MemoryRouter, Route } from "@solidjs/router";
import { OnboardingWizard } from "../../../features/onboarding/OnboardingWizard";
import { setWizardStore } from "../../../features/onboarding/stores";

// Mock clipboard for copy button
vi.mock("../../../features/entries/ipc", () => ({
  copyToClipboard: vi.fn().mockResolvedValue(undefined),
}));

// Mock IPC to avoid real delays
vi.mock("../../../features/onboarding/ipc", () => ({
  createVault: vi.fn().mockResolvedValue({
    vaultPath: "~/.verrou/vault.verrou",
    dbPath: "~/.verrou/vault.db",
    kdfPreset: "balanced",
  }),
  getRecoveryKey: vi.fn().mockResolvedValue({
    formattedKey: "TEST-RECOVERY-KEY",
    vaultFingerprint: "testfp123",
    generationDate: "2026-02-06T00:00:00.000Z",
  }),
  benchmarkKdf: vi.fn().mockResolvedValue({
    fast: { mCost: 262144, tCost: 2, pCost: 4 },
    balanced: { mCost: 524288, tCost: 3, pCost: 4 },
    maximum: { mCost: 524288, tCost: 4, pCost: 4 },
  }),
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

function renderWizard() {
  return render(() => (
    <MemoryRouter
      root={(props) => <>{props.children}</>}
    >
      <Route path="/*" component={() => <OnboardingWizard />} />
    </MemoryRouter>
  ));
}

describe("OnboardingWizard", () => {
  beforeEach(() => {
    setWizardStore({
      password: "",
      confirmPassword: "",
      kdfPreset: "balanced",
      recoveryKeyConfirmed: false,
      recoveryKey: null,
      vaultFingerprint: null,
      isCreating: false,
    });
  });

  it("renders step indicator", () => {
    const { getByText } = renderWizard();
    expect(getByText("Step 1 of 4")).toBeDefined();
  });

  it("starts on password step", () => {
    const { getByText } = renderWizard();
    expect(getByText("Create your password")).toBeDefined();
  });

  it("renders Next button", () => {
    const { getByText } = renderWizard();
    expect(getByText("Next")).toBeDefined();
  });

  it("Next button is disabled by default on step 1", () => {
    const { getByText } = renderWizard();
    const nextBtn = getByText("Next");
    // Button component uses aria-disabled instead of native disabled
    expect(nextBtn.getAttribute("aria-disabled")).toBe("true");
  });

  it("does not show Back button on step 1", () => {
    const { queryByText } = renderWizard();
    expect(queryByText("Back")).toBeNull();
  });

  it("advances to step 2 when password is valid and Next is clicked", () => {
    const strongPass = "correct horse battery staple";
    setWizardStore("password", strongPass);
    setWizardStore("confirmPassword", strongPass);

    const { getByText } = renderWizard();
    // Now the Next button should be enabled
    const nextBtn = getByText("Next");
    fireEvent.click(nextBtn);
    expect(getByText("Step 2 of 4")).toBeDefined();
    expect(getByText("Choose security level")).toBeDefined();
  });

  it("shows Back button on step 2", () => {
    const strongPass = "correct horse battery staple";
    setWizardStore("password", strongPass);
    setWizardStore("confirmPassword", strongPass);

    const { getByText } = renderWizard();
    fireEvent.click(getByText("Next"));
    expect(getByText("Back")).toBeDefined();
  });

  it("goes back to step 1 when Back is clicked on step 2", () => {
    const strongPass = "correct horse battery staple";
    setWizardStore("password", strongPass);
    setWizardStore("confirmPassword", strongPass);

    const { getByText } = renderWizard();
    fireEvent.click(getByText("Next")); // Go to step 2
    fireEvent.click(getByText("Back")); // Go back to step 1
    expect(getByText("Step 1 of 4")).toBeDefined();
    expect(getByText("Create your password")).toBeDefined();
  });

  it("advances from step 2 to step 3", () => {
    const strongPass = "correct horse battery staple";
    setWizardStore("password", strongPass);
    setWizardStore("confirmPassword", strongPass);

    const { getByText } = renderWizard();
    // Step 1 → 2
    fireEvent.click(getByText("Next"));
    // Step 2 → 3 (KDF is always valid)
    fireEvent.click(getByText("Next"));
    expect(getByText("Step 3 of 4")).toBeDefined();
    expect(getByText("Creating your vault")).toBeDefined();
  });

  it("does not show Next button on step 4", () => {
    // Pre-fill all steps so we can navigate to step 4
    const strongPass = "correct horse battery staple";
    setWizardStore("password", strongPass);
    setWizardStore("confirmPassword", strongPass);
    setWizardStore("recoveryKey", "PRE-SET-KEY");
    setWizardStore("recoveryKeyConfirmed", true);

    const { getByText, queryByText } = renderWizard();
    // Step 1 → 2
    fireEvent.click(getByText("Next"));
    // Step 2 → 3
    fireEvent.click(getByText("Next"));
    // Step 3 → 4
    fireEvent.click(getByText("Next"));
    expect(getByText("Step 4 of 4")).toBeDefined();
    expect(getByText("Import Existing Entries")).toBeDefined();
    // No Next button on final step
    expect(queryByText("Next")).toBeNull();
  });

  it("renders the backdrop and card structure", () => {
    const { container } = renderWizard();
    // The wizard uses CSS module classes, check for structural elements
    const divs = container.querySelectorAll("div");
    expect(divs.length).toBeGreaterThan(0);
  });
});
