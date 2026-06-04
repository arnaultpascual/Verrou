import type { Component } from "solid-js";
import { Show, createSignal, createEffect, onMount } from "solid-js";
import { Button, Icon, Spinner, useToast } from "../../components";
import { wizardStore, setWizardStore } from "./stores";
import { createVault, getRecoveryKey } from "./ipc";
import { copyToClipboard } from "../entries/ipc";
import { t } from "../../stores/i18nStore";
import styles from "./RecoveryKeyStep.module.css";

export interface RecoveryKeyStepProps {
  onValidChange: (valid: boolean) => void;
}

/** Normalize a recovery key for comparison: drop separators, upper-case. */
function normalizeKey(s: string): string {
  return s.replace(/[^a-z0-9]/gi, "").toUpperCase();
}

export const RecoveryKeyStep: Component<RecoveryKeyStepProps> = (props) => {
  const [creationDone, setCreationDone] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const [copied, setCopied] = createSignal(false);
  const [confirmInput, setConfirmInput] = createSignal("");
  const toast = useToast();

  createEffect(() => {
    props.onValidChange(wizardStore.recoveryKeyConfirmed);
  });

  onMount(() => {
    // Already created (e.g. navigating back) — skip straight to the save view.
    if (wizardStore.recoveryKey) {
      setCreationDone(true);
      return;
    }

    setWizardStore("isCreating", true);
    // Honest by construction: we await the REAL vault creation + recovery-key
    // generation. No scripted phase list, no fake percentage bar — just an
    // indeterminate "working" state that ends when the backend actually does.
    createVault(wizardStore.password, wizardStore.kdfPreset)
      .then(() => getRecoveryKey())
      .then((result) => {
        setWizardStore("recoveryKey", result.formattedKey);
        setWizardStore("vaultFingerprint", result.vaultFingerprint);
        setCreationDone(true);
      })
      .catch(() => {
        setError(t("onboarding.recoveryKey.errorCreate"));
        toast.error(t("onboarding.recoveryKey.toastFailed"));
      })
      .finally(() => {
        setWizardStore("isCreating", false);
      });
  });

  // Confirm by re-entry: the user must type their key back (separators/case
  // ignored). We drive `recoveryKeyConfirmed` imperatively so a value preset
  // elsewhere (e.g. navigating back into the step) is preserved until the
  // field is actually touched.
  const handleConfirmInput = (value: string) => {
    setConfirmInput(value);
    const key = wizardStore.recoveryKey;
    setWizardStore(
      "recoveryKeyConfirmed",
      !!key && normalizeKey(value) === normalizeKey(key),
    );
  };

  const handleCopy = async () => {
    if (!wizardStore.recoveryKey) return;
    try {
      await copyToClipboard(wizardStore.recoveryKey);
      setCopied(true);
      toast.success(t("onboarding.recoveryKey.toastCopied"));
      setTimeout(() => setCopied(false), 2000);
    } catch {
      toast.error(t("onboarding.recoveryKey.toastCopyFailed"));
    }
  };

  return (
    <div class={styles.step}>
      <h2 class={styles.heading}>
        {creationDone()
          ? t("onboarding.recoveryKey.headingSave")
          : t("onboarding.recoveryKey.headingCreating")}
      </h2>

      <Show when={error()}>
        <p class={styles.error} role="alert">
          {error()}
        </p>
      </Show>

      <Show when={!creationDone() && !error()}>
        <div class={styles.creationProgress}>
          <div class={styles.spinnerContainer}>
            <Spinner size={48} />
          </div>
          <p class={styles.phaseMessage}>{t("onboarding.recoveryKey.encrypting")}</p>
          <p class={styles.progressHint}>{t("onboarding.recoveryKey.encryptingHint")}</p>
        </div>
      </Show>

      <Show when={creationDone()}>
        <div class={styles.warning}>
          <Icon name="alert" size={16} class={styles.warningIcon} />
          <span>{t("onboarding.recoveryKey.shownOnce")}</span>
        </div>

        <p class={styles.description}>{t("onboarding.recoveryKey.description")}</p>

        <div class={styles.keyDisplay}>
          <code class={styles.keyText} data-testid="recovery-key">
            {wizardStore.recoveryKey}
          </code>
        </div>

        <Show when={wizardStore.vaultFingerprint}>
          <p class={styles.fingerprint}>
            {t("onboarding.recoveryKey.fingerprint")}{" "}
            <code>{wizardStore.vaultFingerprint}</code>
          </p>
        </Show>

        <div class={styles.actions}>
          <Button variant="ghost" onClick={handleCopy} data-testid="copy-recovery-key">
            <Icon name={copied() ? "check" : "copy"} size={14} />
            {copied() ? t("onboarding.recoveryKey.copied") : t("onboarding.recoveryKey.copy")}
          </Button>
          <Button variant="ghost" onClick={() => window.print()}>
            {t("onboarding.recoveryKey.print")}
          </Button>
        </div>

        <div class={styles.confirm}>
          <label class={styles.confirmInputLabel} for="recovery-confirm">
            {t("onboarding.recoveryKey.confirmReentry")}
          </label>
          <input
            id="recovery-confirm"
            class={styles.confirmInput}
            value={confirmInput()}
            onInput={(e) => handleConfirmInput(e.currentTarget.value)}
            placeholder={t("onboarding.recoveryKey.confirmPlaceholder")}
            autocomplete="off"
            autocapitalize="characters"
            spellcheck={false}
            data-testid="recovery-confirm-input"
          />
          <Show when={confirmInput().length > 0 && !wizardStore.recoveryKeyConfirmed}>
            <span class={styles.confirmHint} role="status">
              {t("onboarding.recoveryKey.confirmMismatch")}
            </span>
          </Show>
        </div>
      </Show>
    </div>
  );
};
