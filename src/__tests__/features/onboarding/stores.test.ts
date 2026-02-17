import { describe, expect, it, beforeEach } from "vitest";
import { wizardStore, setWizardStore, type WizardState } from "../../../features/onboarding/stores";

describe("wizardStore", () => {
  beforeEach(() => {
    // Reset to defaults
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

  it("has correct default values", () => {
    expect(wizardStore.password).toBe("");
    expect(wizardStore.confirmPassword).toBe("");
    expect(wizardStore.kdfPreset).toBe("balanced");
    expect(wizardStore.recoveryKeyConfirmed).toBe(false);
    expect(wizardStore.recoveryKey).toBeNull();
    expect(wizardStore.vaultFingerprint).toBeNull();
    expect(wizardStore.isCreating).toBe(false);
  });

  it("updates password field", () => {
    setWizardStore("password", "mysecret");
    expect(wizardStore.password).toBe("mysecret");
  });

  it("updates confirmPassword field", () => {
    setWizardStore("confirmPassword", "mysecret");
    expect(wizardStore.confirmPassword).toBe("mysecret");
  });

  it("updates kdfPreset field", () => {
    setWizardStore("kdfPreset", "fast");
    expect(wizardStore.kdfPreset).toBe("fast");

    setWizardStore("kdfPreset", "maximum");
    expect(wizardStore.kdfPreset).toBe("maximum");
  });

  it("updates recoveryKeyConfirmed field", () => {
    setWizardStore("recoveryKeyConfirmed", true);
    expect(wizardStore.recoveryKeyConfirmed).toBe(true);
  });

  it("updates recoveryKey field", () => {
    setWizardStore("recoveryKey", "ABCD-EFGH-JKLM");
    expect(wizardStore.recoveryKey).toBe("ABCD-EFGH-JKLM");
  });

  it("updates vaultFingerprint field", () => {
    setWizardStore("vaultFingerprint", "abc123");
    expect(wizardStore.vaultFingerprint).toBe("abc123");
  });

  it("updates isCreating field", () => {
    setWizardStore("isCreating", true);
    expect(wizardStore.isCreating).toBe(true);
  });

  it("supports batch update via object", () => {
    setWizardStore({
      password: "test",
      confirmPassword: "test",
      kdfPreset: "fast",
    });
    expect(wizardStore.password).toBe("test");
    expect(wizardStore.confirmPassword).toBe("test");
    expect(wizardStore.kdfPreset).toBe("fast");
  });
});
