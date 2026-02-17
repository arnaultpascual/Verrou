import type { Component } from "solid-js";
import { createSignal, createMemo, onMount, Show, onCleanup, createResource } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { PasswordInput, Spinner, Icon, useToast } from "../../components";
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

/** Milestone-based phases for unlock. */
const UNLOCK_PHASE_KEYS = [
  { key: "vault.unlock.progress.deriving", target: 20 },
  { key: "vault.unlock.progress.verifying", target: 55 },
  { key: "vault.unlock.progress.decrypting", target: 80 },
  { key: "vault.unlock.progress.opening", target: 100 },
] as const;

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
  const [phase, setPhase] = createSignal(0);
  const [progress, setProgress] = createSignal(0);
  const [remainingMs, setRemainingMs] = createSignal(0);
  const [shake, setShake] = createSignal(false);

  // Biometric state — availability from platform store, enrollment from IPC.
  const [biometricEnrolled, setBiometricEnrolled] = createSignal(false);
  const [biometricError, setBiometricError] = createSignal("");
  const [biometricLoading, setBiometricLoading] = createSignal(false);

  const biometricReady = () =>
    platformBiometricAvailable() && biometricEnrolled();

  const phaseMessage = createMemo(() => t(UNLOCK_PHASE_KEYS[phase()].key));

  let passwordRef: HTMLInputElement | undefined;
  let countdownInterval: ReturnType<typeof setInterval> | undefined;
  let stopAnim: (() => void) | undefined;
  let creepInterval: ReturnType<typeof setInterval> | undefined;

  /**
   * Smoothly animate progress toward a target over `durationMs`.
   * Returns a cleanup function to stop the animation.
   */
  const animateTo = (target: number, durationMs: number): (() => void) => {
    const start = progress();
    const delta = target - start;
    if (delta <= 0) { setProgress(target); return () => {}; }
    const startTime = performance.now();
    let raf: number;
    const tick = (now: number) => {
      const elapsed = now - startTime;
      const t = Math.min(1, elapsed / durationMs);
      const eased = 1 - (1 - t) * (1 - t);
      setProgress(Math.round(start + delta * eased));
      if (t < 1) { raf = requestAnimationFrame(tick); }
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  };

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
    if (creepInterval) clearInterval(creepInterval);
    stopAnim?.();
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
    setProgress(0);
    setPhase(0);

    // Yield a frame so the browser paints the progress view before
    // the heavy IPC call potentially blocks the event loop.
    await new Promise((r) => requestAnimationFrame(r));

    // Start progress animation
    stopAnim = animateTo(UNLOCK_PHASE_KEYS[0].target, 800);

    // Creep through phases while KDF runs on backend
    creepInterval = setInterval(() => {
      setPhase((p) => {
        const next = Math.min(p + 1, 2); // Cap at phase 2 until backend resolves
        if (next !== p) {
          stopAnim?.();
          stopAnim = animateTo(UNLOCK_PHASE_KEYS[next].target, 2000);
        }
        return next;
      });
    }, 2000);

    try {
      const result = await unlockVault(pw);
      if (creepInterval) clearInterval(creepInterval);
      stopAnim?.();

      // Backend done — animate to 100%
      setPhase(3);
      stopAnim = animateTo(100, 400);

      // Brief pause for visual completion
      await new Promise((resolve) => setTimeout(resolve, 500));

      setUnlockState("success");
      setVaultState("unlocked");

      // Check for recovery key reminder (every 10th unlock)
      if (result.unlockCount > 0 && result.unlockCount % 10 === 0) {
        toast.info(t("vault.unlock.recoveryReminder"));
      }

      navigate("/entries", { replace: true });
    } catch (err) {
      if (creepInterval) clearInterval(creepInterval);
      stopAnim?.();
      setProgress(0);

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
            <div class={styles.unlockProgress}>
              <div class={styles.spinnerContainer}>
                <Spinner size={40} />
              </div>
              <h2 class={styles.unlockProgressHeading}>{t("vault.unlock.heading")}</h2>
              <p class={styles.phaseMessage}>{phaseMessage()}</p>
              <div class={styles.progressWrapper}>
                <div
                  class={styles.progressBar}
                  role="progressbar"
                  aria-valuenow={progress()}
                  aria-valuemin={0}
                  aria-valuemax={100}
                  aria-label={t("vault.unlock.heading")}
                >
                  <div
                    class={styles.progressFill}
                    style={{ width: `${progress()}%` }}
                  />
                </div>
              </div>
              <p class={styles.progressHint}>
                {t("vault.unlock.progress.hint")}
              </p>
            </div>
          }
        >
          <div class={styles.content}>
            <div class={styles.lockIcon} aria-hidden="true">
              <Icon name="shield" size={48} />
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
