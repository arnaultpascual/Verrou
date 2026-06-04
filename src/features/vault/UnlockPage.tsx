import type { Component } from "solid-js";
import { createSignal, onMount, Show, onCleanup, createResource } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { PasswordInput, Spinner, Icon, Logo, useToast } from "../../components";
import {
  isBiometricAvailable as platformBiometricAvailable,
  biometricProviderName as platformBiometricProvider,
} from "../../stores/platformStore";
import { setVaultState } from "../../stores/vaultStore";
import { unlockVault, parseUnlockError, checkVaultIntegrity } from "./ipc";
import { checkBiometricAvailability, unlockVaultBiometric } from "./biometricIpc";
import { CorruptionErrorPage } from "./CorruptionErrorPage";
import { t } from "../../stores/i18nStore";
import styles from "./UnlockPage.module.css";

type UnlockState = "idle" | "unlocking" | "error" | "cooldown" | "success";

export const UnlockPage: Component = () => {
  const navigate = useNavigate();
  const toast = useToast();

  // Integrity check gate — runs before showing unlock form
  const [integrityVersion, setIntegrityVersion] = createSignal(0);
  const [integrityReport] = createResource(integrityVersion, () => checkVaultIntegrity());

  const integrityFailed = () => {
    const report = integrityReport();
    return report != null && report.status.kind !== "ok";
  };

  const handleRestored = () => {
    // Re-run integrity check after restore
    setIntegrityVersion((v) => v + 1);
  };

  const [password, setPassword] = createSignal("");
  const [unlockState, setUnlockState] = createSignal<UnlockState>("idle");
  const [errorMessage, setErrorMessage] = createSignal("");
  const [remainingMs, setRemainingMs] = createSignal(0);
  const [shake, setShake] = createSignal(false);

  // Biometric state — availability from platform store, enrollment from IPC.
  const [biometricEnrolled, setBiometricEnrolled] = createSignal(false);
  const [biometricError, setBiometricError] = createSignal("");
  const [biometricLoading, setBiometricLoading] = createSignal(false);

  const biometricReady = () =>
    platformBiometricAvailable() && biometricEnrolled();

  let passwordRef: HTMLInputElement | undefined;
  let countdownInterval: ReturnType<typeof setInterval> | undefined;

  onMount(async () => {
    passwordRef?.focus();

    // Check biometric enrollment (non-blocking).
    // Hardware availability is already in platform store (instant).
    if (platformBiometricAvailable()) {
      try {
        const cap = await checkBiometricAvailability();
        setBiometricEnrolled(cap.enrolled);

        // Auto-trigger biometric if enrolled.
        if (cap.enrolled) {
          setTimeout(() => handleBiometricUnlock(), 500);
        }
      } catch {
        // Enrollment check failed — biometric button stays hidden.
      }
    }
  });

  onCleanup(() => {
    if (countdownInterval) clearInterval(countdownInterval);
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
    setUnlockState("cooldown");

    if (countdownInterval) clearInterval(countdownInterval);
    countdownInterval = setInterval(() => {
      setRemainingMs((prev) => {
        const next = prev - 1000;
        if (next <= 0) {
          if (countdownInterval) clearInterval(countdownInterval);
          setUnlockState("idle");
          passwordRef?.focus();
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

  const handleBiometricUnlock = async () => {
    if (biometricLoading() || unlockState() === "unlocking" || unlockState() === "cooldown") return;

    setBiometricLoading(true);
    setBiometricError("");

    try {
      const result = await unlockVaultBiometric();

      setUnlockState("success");
      setVaultState("unlocked");

      if (result.unlockCount > 0 && result.unlockCount % 10 === 0) {
        toast.info(t("vault.unlock.recoveryReminder"));
      }

      navigate("/entries", { replace: true });
    } catch (err) {
      const errorStr = typeof err === "string" ? err : String(err);
      const parsed = parseUnlockError(errorStr);

      if (parsed.code === "RATE_LIMITED" && parsed.remainingMs) {
        startCountdown(parsed.remainingMs);
        setErrorMessage(parsed.message);
      } else if (parsed.code === "BIOMETRIC_CANCELLED") {
        // User cancelled — no error message, just stay on form.
      } else {
        setBiometricError(
          t("vault.unlock.biometricError"),
        );
      }
    } finally {
      setBiometricLoading(false);
    }
  };

  const handleSubmit = async (e?: Event) => {
    e?.preventDefault();
    const pw = password();
    if (!pw || unlockState() === "unlocking" || unlockState() === "cooldown") return;

    setUnlockState("unlocking");
    setErrorMessage("");

    try {
      // The genuine wait is the Argon2id KDF running in Rust. We show an
      // indeterminate "Unlocking…" indicator while this promise is pending
      // and snap to done the moment it actually resolves — no scripted phases,
      // no cosmetic delay.
      const result = await unlockVault(pw);

      setUnlockState("success");
      setVaultState("unlocked");

      // Check for recovery key reminder (every 10th unlock)
      if (result.unlockCount > 0 && result.unlockCount % 10 === 0) {
        toast.info(t("vault.unlock.recoveryReminder"));
      }

      navigate("/entries", { replace: true });
    } catch (err) {
      const errorStr = typeof err === "string" ? err : String(err);
      const parsed = parseUnlockError(errorStr);

      if (parsed.code === "RATE_LIMITED" && parsed.remainingMs) {
        startCountdown(parsed.remainingMs);
        setErrorMessage(parsed.message);
      } else {
        setUnlockState("error");
        setErrorMessage(parsed.message);
        triggerShake();
        passwordRef?.focus();
      }
    }
  };

  const handleKeyDown = (e: KeyboardEvent) => {
    if (e.key === "Enter") {
      handleSubmit();
    }
  };

  const isFormDisabled = () =>
    unlockState() === "unlocking" ||
    unlockState() === "cooldown" ||
    unlockState() === "success";

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
        <Show
          when={unlockState() !== "unlocking"}
          fallback={
            <div class={styles.unlockProgress} role="status" aria-live="polite">
              <div class={styles.spinnerContainer}>
                <Spinner size={40} />
              </div>
              <h2 class={styles.unlockProgressHeading}>
                {t("vault.unlock.progress.heading")}
              </h2>
            </div>
          }
        >
          <div class={styles.content}>
            <div class={styles.lockIcon} aria-hidden="true">
              <Logo size={64} />
            </div>

            <h1 class={styles.heading}>{t("vault.unlock.lockedHeading")}</h1>

            <Show when={biometricReady()}>
              <div class={styles.biometricSection}>
                <button
                  type="button"
                  class={styles.biometricBtn}
                  disabled={isFormDisabled() || biometricLoading()}
                  onClick={handleBiometricUnlock}
                  aria-label={t("vault.unlock.biometricButton", { provider: platformBiometricProvider() })}
                >
                  <Icon name="fingerprint" size={20} />
                  <span>
                    {biometricLoading()
                      ? t("vault.unlock.biometricVerifying")
                      : t("vault.unlock.biometricButton", { provider: platformBiometricProvider() })}
                  </span>
                </button>

                <Show when={biometricError()}>
                  <p class={styles.biometricError} role="alert">
                    {biometricError()}
                  </p>
                </Show>

                <div class={styles.divider}>{t("vault.unlock.divider")}</div>
              </div>
            </Show>

            <form class={styles.form} onSubmit={handleSubmit}>
              <div class={`${styles.inputWrapper} ${shake() ? styles.shake : ""}`}>
                <PasswordInput
                  label={t("vault.unlock.passwordLabel")}
                  mode="unlock"
                  value={password()}
                  onInput={setPassword}
                  error={unlockState() === "error" || unlockState() === "cooldown" ? errorMessage() : undefined}
                  disabled={isFormDisabled()}
                  placeholder={t("vault.unlock.passwordPlaceholder")}
                  id="unlock-password"
                />
              </div>

              <Show when={unlockState() === "cooldown"}>
                <p class={styles.cooldown} role="status" aria-live="polite">
                  {t("vault.unlock.cooldown", { time: formatCountdown(remainingMs()) })}
                </p>
              </Show>

              <button
                type="submit"
                class={styles.unlockBtn}
                disabled={isFormDisabled() || !password()}
              >
                {t("vault.unlock.submitButton")}
              </button>
            </form>

            <a
              href="/recovery"
              class={styles.recoveryLink}
              tabindex={0}
            >
              {t("vault.unlock.forgotPassword")}
            </a>

            <div class={styles.offlineBadge} aria-hidden="true">
              <Icon name="shield" size={14} />
              <span>{t("vault.unlock.offlineBadge")}</span>
            </div>
          </div>
        </Show>
      </div>
    </Show>
  );
};
