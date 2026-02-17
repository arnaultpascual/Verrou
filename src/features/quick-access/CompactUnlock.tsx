import type { Component } from "solid-js";
import { createSignal, onMount, Show } from "solid-js";
import { Icon } from "../../components/Icon";
import { PasswordInput } from "../../components/PasswordInput";
import { unlockVault, parseUnlockError } from "../vault/ipc";
import { checkBiometricAvailability, unlockVaultBiometric, type BiometricCapability } from "../vault/biometricIpc";
import { t } from "../../stores/i18nStore";
import styles from "./CompactUnlock.module.css";

export interface CompactUnlockProps {
  onSuccess: () => void;
}

/**
 * Compact password field for unlocking the vault from the popup.
 * Auto-focuses on mount. Supports biometric unlock when available.
 */
export const CompactUnlock: Component<CompactUnlockProps> = (props) => {
  const [password, setPassword] = createSignal("");
  const [error, setError] = createSignal("");
  const [isSubmitting, setIsSubmitting] = createSignal(false);
  const [biometric, setBiometric] = createSignal<BiometricCapability | null>(null);
  const [biometricLoading, setBiometricLoading] = createSignal(false);
  let formRef: HTMLFormElement | undefined;

  const biometricReady = () => {
    const b = biometric();
    return b != null && b.available && b.enrolled;
  };

  onMount(async () => {
    try {
      const cap = await checkBiometricAvailability();
      setBiometric(cap);

      // Auto-trigger biometric on popup open.
      if (cap.available && cap.enrolled) {
        handleBiometricUnlock();
      }
    } catch {
      // Silently ignore — just show password form.
    }
  });

  const handleBiometricUnlock = async () => {
    if (biometricLoading() || isSubmitting()) return;

    setBiometricLoading(true);
    setError("");

    try {
      await unlockVaultBiometric();
      props.onSuccess();
    } catch (err) {
      const parsed = parseUnlockError(String(err));
      if (parsed.code !== "BIOMETRIC_CANCELLED") {
        setError(parsed.message);
      }
    } finally {
      setBiometricLoading(false);
    }
  };

  const handleSubmit = async (e: SubmitEvent) => {
    e.preventDefault();
    if (isSubmitting() || !password()) return;

    setIsSubmitting(true);
    setError("");

    try {
      await unlockVault(password());
      props.onSuccess();
    } catch (err) {
      const parsed = parseUnlockError(String(err));
      setError(parsed.message);
      setPassword("");
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <form ref={formRef} class={styles.form} onSubmit={handleSubmit}>
      <div class={styles.lockIcon} aria-hidden="true">
        <svg width="32" height="32" viewBox="0 0 24 24" fill="currentColor">
          <path d="M18 8h-1V6A5 5 0 007 6v2H6a2 2 0 00-2 2v10a2 2 0 002 2h12a2 2 0 002-2V10a2 2 0 00-2-2zm-6 9a2 2 0 110-4 2 2 0 010 4zM9 8V6a3 3 0 116 0v2H9z" />
        </svg>
      </div>

      <Show when={biometricReady()}>
        <button
          type="button"
          class={styles.biometricBtn}
          disabled={isSubmitting() || biometricLoading()}
          onClick={handleBiometricUnlock}
          aria-label={t("quickAccess.ariaUnlockBiometric", { provider: biometric()?.providerName ?? t("quickAccess.biometric") })}
        >
          <Icon name="fingerprint" size={16} />
          <span>
            {biometricLoading()
              ? t("quickAccess.verifying")
              : biometric()?.providerName ?? t("quickAccess.biometric")}
          </span>
        </button>
      </Show>

      <PasswordInput
        label={t("quickAccess.passwordLabel")}
        mode="unlock"
        value={password()}
        onInput={setPassword}
        error={error()}
        disabled={isSubmitting()}
        placeholder={t("quickAccess.passwordPlaceholder")}
      />
      <button
        type="submit"
        class={styles.submitBtn}
        disabled={isSubmitting() || !password()}
      >
        {isSubmitting() ? t("quickAccess.unlocking") : t("quickAccess.unlock")}
      </button>
    </form>
  );
};
