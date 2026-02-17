import type { Component } from "solid-js";
import { createEffect } from "solid-js";
import { PasswordInput, evaluateStrength } from "../../components";
import { wizardStore, setWizardStore } from "./stores";
import { t } from "../../stores/i18nStore";
import styles from "./PasswordStep.module.css";

/** Check if password strength meets minimum requirement (≥ "good") */
function meetsMinStrength(value: string): boolean {
  const strength = evaluateStrength(value);
  return strength === "good" || strength === "excellent";
}

export interface PasswordStepProps {
  onValidChange: (valid: boolean) => void;
}

export const PasswordStep: Component<PasswordStepProps> = (props) => {
  const passwordsMatch = () =>
    wizardStore.password.length > 0 &&
    wizardStore.confirmPassword.length > 0 &&
    wizardStore.password === wizardStore.confirmPassword;

  const showMismatch = () =>
    wizardStore.confirmPassword.length > 0 && !passwordsMatch();

  const isValid = () => meetsMinStrength(wizardStore.password) && passwordsMatch();

  createEffect(() => {
    props.onValidChange(isValid());
  });

  return (
    <div class={styles.step}>
      <h2 class={styles.heading}>{t("onboarding.password.heading")}</h2>
      <p class={styles.description}>
        {t("onboarding.password.description")}
      </p>

      <div class={styles.fields}>
        <PasswordInput
          label={t("onboarding.password.masterLabel")}
          mode="create"
          value={wizardStore.password}
          onInput={(v) => setWizardStore("password", v)}
          placeholder={t("onboarding.password.masterPlaceholder")}
        />

        <PasswordInput
          label={t("onboarding.password.confirmLabel")}
          mode="unlock"
          value={wizardStore.confirmPassword}
          onInput={(v) => setWizardStore("confirmPassword", v)}
          placeholder={t("onboarding.password.confirmPlaceholder")}
          error={showMismatch() ? t("onboarding.password.mismatch") : undefined}
        />
      </div>

      <p class={styles.guidance}>
        {t("onboarding.password.guidance")}
      </p>
    </div>
  );
};
