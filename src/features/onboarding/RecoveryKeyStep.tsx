import type { Component } from "solid-js";
import { Show, createSignal, createEffect, createMemo, onMount } from "solid-js";
import { Button, Icon, Spinner, useToast } from "../../components";
import { wizardStore, setWizardStore } from "./stores";
import { createVault, getRecoveryKey } from "./ipc";
import { copyToClipboard } from "../entries/ipc";
import { t } from "../../stores/i18nStore";
import styles from "./RecoveryKeyStep.module.css";

export interface RecoveryKeyStepProps {
  onValidChange: (valid: boolean) => void;
}

/** Milestone-based phases for vault creation. */
const PHASE_KEYS = [
  "onboarding.recoveryKey.phase1",
  "onboarding.recoveryKey.phase2",
  "onboarding.recoveryKey.phase3",
  "onboarding.recoveryKey.phase4",
  "onboarding.recoveryKey.phase5",
] as const;

const PHASES = [
  { key: PHASE_KEYS[0], target: 15 },
  { key: PHASE_KEYS[1], target: 45 },
  { key: PHASE_KEYS[2], target: 70 },
  { key: PHASE_KEYS[3], target: 90 },
  { key: PHASE_KEYS[4], target: 100 },
] as const;

export const RecoveryKeyStep: Component<RecoveryKeyStepProps> = (props) => {
  const [phase, setPhase] = createSignal(0);
  const [progress, setProgress] = createSignal(0);
  const [creationDone, setCreationDone] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const [copied, setCopied] = createSignal(false);
  const toast = useToast();

  const phaseMessage = createMemo(() => t(PHASES[phase()].key));

  createEffect(() => {
    props.onValidChange(wizardStore.recoveryKeyConfirmed);
  });

  /**
   * Smoothly animate progress toward a target over `durationMs`.
   * Returns a cleanup function to stop the animation.
   */
  function animateTo(target: number, durationMs: number): () => void {
    const start = progress();
    const delta = target - start;
    if (delta <= 0) { setProgress(target); return () => {}; }
    const startTime = performance.now();
    let raf: number;
    const tick = (now: number) => {
      const elapsed = now - startTime;
      const t = Math.min(1, elapsed / durationMs);
      // Ease-out for natural deceleration
      const eased = 1 - (1 - t) * (1 - t);
      setProgress(Math.round(start + delta * eased));
      if (t < 1) { raf = requestAnimationFrame(tick); }
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }

  onMount(() => {
    if (wizardStore.recoveryKey) {
      setCreationDone(true);
      setProgress(100);
      setPhase(4);
      return;
    }

    setWizardStore("isCreating", true);
    setPhase(0);

    // Yield a frame so the browser paints the progress view before
    // the heavy IPC call potentially blocks the event loop.
    let stopAnim = () => {};
    requestAnimationFrame(() => {
      stopAnim = animateTo(PHASES[0].target, 800);
    });

    // Creep through phases while backend works
    const creepInterval = setInterval(() => {
      setPhase((p) => {
        const next = Math.min(p + 1, 2); // Cap at phase 2 until backend resolves
        if (next !== p) {
          stopAnim();
          stopAnim = animateTo(PHASES[next].target, 2000);
        }
        return next;
      });
    }, 2500);

    createVault(wizardStore.password, wizardStore.kdfPreset)
      .then(() => {
        clearInterval(creepInterval);
        stopAnim();
        // Backend done — jump to "Generating recovery key" phase
        setPhase(3);
        stopAnim = animateTo(PHASES[3].target, 600);
        return getRecoveryKey();
      })
      .then((result) => {
        stopAnim();
        setWizardStore("recoveryKey", result.formattedKey);
        setWizardStore("vaultFingerprint", result.vaultFingerprint);
        // Complete: set progress directly and transition after brief pause
        setPhase(4);
        setProgress(100);
        setTimeout(() => setCreationDone(true), 500);
      })
      .catch(() => {
        clearInterval(creepInterval);
        stopAnim();
        setError(t("onboarding.recoveryKey.errorCreate"));
        toast.error(t("onboarding.recoveryKey.toastFailed"));
        setProgress(0);
      })
      .finally(() => {
        clearInterval(creepInterval);
        setWizardStore("isCreating", false);
      });
  });

  const handleConfirmChange = (e: Event) => {
    const target = e.target as HTMLInputElement;
    setWizardStore("recoveryKeyConfirmed", target.checked);
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
        {creationDone() ? t("onboarding.recoveryKey.headingSave") : t("onboarding.recoveryKey.headingCreating")}
      </h2>

      <Show when={error()}>
        <p class={styles.error} role="alert">{error()}</p>
      </Show>

      <Show when={!creationDone() && !error()}>
        <div class={styles.creationProgress}>
          <div class={styles.spinnerContainer}>
            <Spinner size={48} />
          </div>

          <p class={styles.phaseMessage}>{phaseMessage()}</p>

          <div class={styles.progressWrapper}>
            <div
              class={styles.progressBar}
              role="progressbar"
              aria-valuenow={Math.round(progress())}
              aria-valuemin={0}
              aria-valuemax={100}
              aria-label={t("onboarding.recoveryKey.ariaCreating")}
            >
              <div
                class={styles.progressFill}
                style={{ width: `${progress()}%` }}
              />
            </div>
          </div>

          <p class={styles.progressHint}>
            {t("onboarding.recoveryKey.progressHint")}
          </p>
        </div>
      </Show>

      <Show when={creationDone()}>
        <p class={styles.description}>
          {t("onboarding.recoveryKey.description")}
        </p>

        <div class={styles.keyDisplay}>
          <code class={styles.keyText} data-testid="recovery-key">
            {wizardStore.recoveryKey}
          </code>
        </div>

        <Show when={wizardStore.vaultFingerprint}>
          <p class={styles.fingerprint}>
            {t("onboarding.recoveryKey.fingerprint")} <code>{wizardStore.vaultFingerprint}</code>
          </p>
        </Show>

        <div class={styles.actions}>
          <Button
            variant="ghost"
            onClick={handleCopy}
            data-testid="copy-recovery-key"
          >
            <Icon name={copied() ? "check" : "copy"} size={14} />
            {copied() ? t("onboarding.recoveryKey.copied") : t("onboarding.recoveryKey.copy")}
          </Button>
          <Button variant="ghost" onClick={() => window.print()}>
            {t("onboarding.recoveryKey.print")}
          </Button>
        </div>

        <label class={styles.confirmLabel}>
          <input
            type="checkbox"
            checked={wizardStore.recoveryKeyConfirmed}
            onChange={handleConfirmChange}
          />
          <span>{t("onboarding.recoveryKey.confirmLabel")}</span>
        </label>
      </Show>
    </div>
  );
};
