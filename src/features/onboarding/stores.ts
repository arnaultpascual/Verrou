import { createStore } from "solid-js/store";

export interface WizardState {
  password: string;
  confirmPassword: string;
  kdfPreset: "fast" | "balanced" | "maximum";
  recoveryKeyConfirmed: boolean;
  recoveryKey: string | null;
  vaultFingerprint: string | null;
  isCreating: boolean;
}

const [wizardStore, setWizardStore] = createStore<WizardState>({
  password: "",
  confirmPassword: "",
  kdfPreset: "balanced",
  recoveryKeyConfirmed: false,
  recoveryKey: null,
  vaultFingerprint: null,
  isCreating: false,
});

export { wizardStore, setWizardStore };
