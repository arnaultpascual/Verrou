import type { Component } from "solid-js";
import { createSignal, Show, onCleanup, createResource } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { PasswordInput, SecurityCeremony, Icon, Button, useToast } from "../../components";
import { setVaultState } from "../../stores/vaultStore";
import { recoverVault, changePasswordAfterRecovery, parseUnlockError, checkVaultIntegrity } from "./ipc";
import { CorruptionErrorPage } from "./CorruptionErrorPage";
import type { PasswordChangeResponse } from "./ipc";
import { t } from "../../stores/i18nStore";
import styles from "./RecoveryPage.module.css";

type RecoveryPhase =
  | "input"        // Entering recovery key
  | "recovering"   // SecurityCeremony during KDF
  | "password"     // Setting new master password
  | "changing"     // SecurityCeremony during password change
  | "newkey"       // Displaying new recovery key
  | "error"        // Error state
  | "cooldown";    // Rate limited

export const RecoveryPage: Component = () => {
  const navigate = useNavigate();
  const toast = useToast();

  // Integrity check gate — same as UnlockPage
  const [integrityVersion, setIntegrityVersion] = createSignal(0);
  const [integrityReport] = createResource(integrityVersion, () => checkVaultIntegrity());

  const integrityFailed = () => {
    const report = integrityReport();
    return report != null && report.status.kind !== "ok";
  };

  const handleRestored = () => {
    setIntegrityVersion((v) => v + 1);
  };

  const [phase, setPhase] = createSignal<RecoveryPhase>("input");
  const [recoveryKey, setRecoveryKey] = createSignal("");
  const [newPassword, setNewPassword] = createSignal("");
  const [confirmPassword, setConfirmPassword] = createSignal("");
  const [errorMessage, setErrorMessage] = createSignal("");
  const [progress, setProgress] = createSignal(0);
  const [remainingMs, setRemainingMs] = createSignal(0);
  const [shake, setShake] = createSignal(false);
  const [newRecoveryKey, setNewRecoveryKey] = createSignal<PasswordChangeResponse | null>(null);
  const [keySaved, setKeySaved] = createSignal(false);

  let countdownInterval: ReturnType<typeof setInterval> | undefined;
  let progressInterval: ReturnType<typeof setInterval> | undefined;

  onCleanup(() => {
    if (countdownInterval) clearInterval(countdownInterval);
    if (progressInterval) clearInterval(progressInterval);
  });

  const formatCountdown = (ms: number): string => {
    const totalSecs = Math.ceil(ms / 1000);
    if (totalSecs >= 60) {
      const mins = Math.floor(totalSecs / 60);
      const secs = totalSecs % 60;
      return `${mins}:${String(secs).padStart(2, "0")}`;
    }
    return `${totalSecs}s`;
  };

  const startCountdown = (ms: number) => {
    setRemainingMs(ms);
    setPhase("cooldown");

    if (countdownInterval) clearInterval(countdownInterval);
    countdownInterval = setInterval(() => {
      setRemainingMs((prev) => {
        const next = prev - 1000;
        if (next <= 0) {
          if (countdownInterval) clearInterval(countdownInterval);
          setPhase("input");
          return 0;
        }
        return next;
      });
    }, 1000);
  };

  const triggerShake = () => {
    setShake(true);
    setTimeout(() => setShake(false), 200);
  };

  const handleRecoverySubmit = async (e?: Event) => {
    e?.preventDefault();
    const key = recoveryKey();
    if (!key || phase() === "recovering" || phase() === "cooldown") return;

    setPhase("recovering");
    setErrorMessage("");
    setProgress(0);

    progressInterval = setInterval(() => {
      setProgress((prev) => (prev >= 90 ? prev : prev + 3));
    }, 100);

    try {
      await recoverVault(key);
      if (progressInterval) clearInterval(progressInterval);
      setProgress(100);

      await new Promise((resolve) => setTimeout(resolve, 300));

      setVaultState("unlocked");
      setPhase("password");
    } catch (err) {
      if (progressInterval) clearInterval(progressInterval);
      setProgress(0);

      const errorStr = typeof err === "string" ? err : String(err);
      const parsed = parseUnlockError(errorStr);

      if (parsed.code === "RATE_LIMITED" && parsed.remainingMs) {
        startCountdown(parsed.remainingMs);
        setErrorMessage(parsed.message);
      } else {
        setPhase("error");
        setErrorMessage(parsed.message);
        triggerShake();
      }
    }
  };

  const passwordsMatch = () =>
    newPassword().length > 0 && newPassword() === confirmPassword();

  const handlePasswordSubmit = async (e?: Event) => {
    e?.preventDefault();
    if (!passwordsMatch() || phase() === "changing") return;

    setPhase("changing");
    setProgress(0);

    progressInterval = setInterval(() => {
      setProgress((prev) => (prev >= 90 ? prev : prev + 5));
    }, 100);

    try {
      const result = await changePasswordAfterRecovery(newPassword());
      if (progressInterval) clearInterval(progressInterval);
      setProgress(100);

      await new Promise((resolve) => setTimeout(resolve, 300));

      setNewRecoveryKey(result);
      setPhase("newkey");
      toast.success(t("vault.recovery.passwordChangeSuccess"));
    } catch {
      if (progressInterval) clearInterval(progressInterval);
      setProgress(0);
      setPhase("password");
      toast.error(t("vault.recovery.passwordChangeError"));
    }
  };

  const handleFinish = () => {
    navigate("/entries", { replace: true });
  };

  const isInputDisabled = () =>
    phase() === "recovering" || phase() === "cooldown";

  return (
    <Show
      when={!integrityFailed()}
      fallback={
        <CorruptionErrorPage
          message={integrityReport()?.message ?? t("vault.corruption.integrityFailed")}
          onRestored={handleRestored}
        />
      }
    >
    <div class={styles.container}>
      {/* SecurityCeremony overlay for recovery KDF or password change */}
      <Show when={phase() === "recovering" || phase() === "changing"}>
        <div class={styles.ceremonyWrapper}>
          <SecurityCeremony
            progress={progress()}
            onComplete={() => {/* handled in async flow */}}
          />
        </div>
      </Show>

      {/* Phase 1: Recovery key input */}
      <Show when={phase() === "input" || phase() === "error" || phase() === "cooldown"}>
        <div class={styles.content}>
          <div class={styles.lockIcon} aria-hidden="true">
            <Icon name="shield" size={48} />
          </div>

          <h1 class={styles.heading}>{t("vault.recovery.heading")}</h1>

          <p class={styles.description}>
            {t("vault.recovery.description")}
          </p>

          <form class={styles.form} onSubmit={handleRecoverySubmit}>
            <div class={`${styles.inputWrapper} ${shake() ? styles.shake : ""}`}>
              <textarea
                class={styles.recoveryInput}
                value={recoveryKey()}
                onInput={(e) => setRecoveryKey(e.currentTarget.value)}
                placeholder={t("vault.recovery.inputPlaceholder")}
                disabled={isInputDisabled()}
                rows={2}
                spellcheck={false}
                autocomplete="off"
                aria-label={t("vault.recovery.inputLabel")}
                data-testid="recovery-key-input"
              />
            </div>

            <Show when={phase() === "error"}>
              <p class={styles.error} role="alert">
                {errorMessage()}
              </p>
            </Show>

            <Show when={phase() === "cooldown"}>
              <p class={styles.cooldown} role="status" aria-live="polite">
                {t("vault.recovery.cooldown", { time: formatCountdown(remainingMs()) })}
              </p>
              <p class={styles.error} role="alert">
                {errorMessage()}
              </p>
            </Show>

            <button
              type="submit"
              class={styles.submitBtn}
              disabled={isInputDisabled() || !recoveryKey()}
            >
              {t("vault.recovery.submitButton")}
            </button>
          </form>

          <a href="/unlock" class={styles.backLink} data-testid="back-to-unlock">
            {t("vault.recovery.backToUnlock")}
          </a>

          <div class={styles.offlineBadge} aria-hidden="true">
            <Icon name="shield" size={14} />
            <span>{t("vault.unlock.offlineBadge")}</span>
          </div>
        </div>
      </Show>

      {/* Phase 2: Set new master password */}
      <Show when={phase() === "password"}>
        <div class={styles.content}>
          <div class={styles.lockIcon} aria-hidden="true">
            <Icon name="shield" size={48} />
          </div>

          <h1 class={styles.heading}>{t("vault.recovery.passwordHeading")}</h1>

          <p class={styles.description}>
            {t("vault.recovery.passwordDescription")}
          </p>

          <form class={styles.form} onSubmit={handlePasswordSubmit}>
            <div class={styles.passwordSection}>
              <PasswordInput
                label={t("vault.recovery.newPasswordLabel")}
                mode="create"
                value={newPassword()}
                onInput={setNewPassword}
                placeholder={t("vault.recovery.newPasswordPlaceholder")}
                id="recovery-new-password"
              />

              <PasswordInput
                label={t("vault.recovery.confirmPasswordLabel")}
                mode="unlock"
                value={confirmPassword()}
                onInput={setConfirmPassword}
                error={
                  confirmPassword().length > 0 && !passwordsMatch()
                    ? t("vault.recovery.confirmPasswordError")
                    : undefined
                }
                placeholder={t("vault.recovery.confirmPasswordPlaceholder")}
                id="recovery-confirm-password"
              />
            </div>

            <button
              type="submit"
              class={styles.submitBtn}
              disabled={!passwordsMatch()}
              data-testid="change-password-btn"
            >
              {t("vault.recovery.changePasswordButton")}
            </button>
          </form>
        </div>
      </Show>

      {/* Phase 3: Display new recovery key */}
      <Show when={phase() === "newkey" && newRecoveryKey()}>
        <div class={styles.content}>
          <div class={styles.lockIcon} aria-hidden="true">
            <Icon name="shield" size={48} />
          </div>

          <h1 class={styles.heading}>{t("vault.recovery.newKeyHeading")}</h1>

          <p class={styles.description}>
            {t("vault.recovery.newKeyDescription")}
          </p>

          <div class={styles.keyDisplay}>
            <code class={styles.keyText} data-testid="new-recovery-key">
              {newRecoveryKey()!.formattedKey}
            </code>
          </div>

          <Show when={newRecoveryKey()!.vaultFingerprint}>
            <p class={styles.fingerprint}>
              {t("settings.vaultFingerprint")} <code>{newRecoveryKey()!.vaultFingerprint}</code>
            </p>
          </Show>

          <div class={styles.printActions}>
            <Button variant="ghost" onClick={() => window.print()} data-testid="print-btn">
              {t("vault.recovery.printButton")}
            </Button>
          </div>

          <label class={styles.confirmLabel}>
            <input
              type="checkbox"
              checked={keySaved()}
              onChange={(e) => setKeySaved(e.currentTarget.checked)}
              data-testid="confirm-saved-checkbox"
            />
            <span>{t("vault.recovery.keySaved")}</span>
          </label>

          <button
            class={styles.submitBtn}
            disabled={!keySaved()}
            onClick={handleFinish}
            data-testid="finish-btn"
          >
            {t("vault.recovery.continueButton")}
          </button>
        </div>
      </Show>
    </div>
    </Show>
  );
};
