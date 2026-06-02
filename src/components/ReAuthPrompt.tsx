import type { Component } from "solid-js";
import { Show, createSignal, createEffect, on, onCleanup } from "solid-js";
import { Modal } from "./Modal";
import { PasswordInput } from "./PasswordInput";
import { SecurityCeremony } from "./SecurityCeremony";
import { Button } from "./Button";
import { t } from "../stores/i18nStore";
import styles from "./ReAuthPrompt.module.css";

export interface ReAuthPromptProps {
  /** Controlled open state */
  open: boolean;
  /** Called when dialog should close */
  onClose: () => void;
  /**
   * Perform the real, re-authenticated action with the entered password
   * (e.g. reveal / delete). MUST return a promise that **rejects** if the
   * password is wrong or the action fails: the prompt surfaces the failure
   * inline and keeps itself open for retry. The "Verifying…" ceremony tracks
   * this promise and only shows the success state once it actually resolves —
   * there is no fake timer and no premature "Verified".
   */
  onVerified: (password: string) => Promise<void>;
}

type Phase = "input" | "ceremony";

export const ReAuthPrompt: Component<ReAuthPromptProps> = (props) => {
  const [password, setPassword] = createSignal("");
  const [error, setError] = createSignal("");
  const [phase, setPhase] = createSignal<Phase>("input");
  const [progress, setProgress] = createSignal(0);

  // Reset state when modal opens
  createEffect(
    on(
      () => props.open,
      (open) => {
        if (open) {
          setPassword("");
          setError("");
          setPhase("input");
          setProgress(0);
        }
      },
    ),
  );

  let rampHandle = 0;
  const stopRamp = () => {
    if (rampHandle) {
      cancelAnimationFrame(rampHandle);
      rampHandle = 0;
    }
  };

  // Honest activity indicator: ramp the bar toward — but never reaching — 100
  // while the real verification runs. Completion (100 → "Verified") is set ONLY
  // when the backend actually confirms success, so the ceremony never claims
  // success before the password has been checked.
  const startRamp = () => {
    const start = Date.now();
    const durationToCap = 2000;
    const cap = 90;
    const tick = () => {
      const elapsed = Date.now() - start;
      const pct = Math.min(cap, (elapsed / durationToCap) * cap);
      setProgress(pct);
      if (pct < cap) {
        rampHandle = requestAnimationFrame(tick);
      }
    };
    rampHandle = requestAnimationFrame(tick);
  };

  onCleanup(stopRamp);

  const handleSubmit = async (e: Event) => {
    e.preventDefault();
    if (!password()) {
      setError(t("components.reAuthPrompt.passwordRequired"));
      return;
    }
    setError("");
    setPhase("ceremony");
    setProgress(0);
    startRamp();
    try {
      await props.onVerified(password());
      // Real success — only now mark the ceremony complete ("Verified").
      stopRamp();
      setProgress(100);
    } catch (err) {
      // Wrong password / failure — surface inline and return to input for retry.
      stopRamp();
      setPhase("input");
      setProgress(0);
      setError(
        typeof err === "string"
          ? err
          : err instanceof Error
            ? err.message
            : t("components.reAuthPrompt.failed"),
      );
    }
  };

  return (
    <Modal
      open={props.open}
      onClose={props.onClose}
      title={t("components.reAuthPrompt.title")}
      closeOnOverlayClick={false}
    >
      <Show when={phase() === "input"} fallback={<SecurityCeremony progress={progress()} />}>
        <form onSubmit={handleSubmit} class={styles.form}>
          <p class={styles.description}>{t("components.reAuthPrompt.description")}</p>
          <PasswordInput
            label={t("components.reAuthPrompt.passwordLabel")}
            mode="unlock"
            value={password()}
            onInput={setPassword}
            error={error()}
            placeholder={t("components.reAuthPrompt.passwordPlaceholder")}
          />
          <div class={styles.actions}>
            <Button variant="ghost" onClick={props.onClose}>
              {t("common.cancel")}
            </Button>
            <Button type="submit">{t("common.verify")}</Button>
          </div>
        </form>
      </Show>
    </Modal>
  );
};
