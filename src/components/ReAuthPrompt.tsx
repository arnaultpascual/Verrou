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
  /** Called after successful verification with the password */
  onVerified: (password: string) => void;
}

type Phase = "input" | "ceremony";

export const ReAuthPrompt: Component<ReAuthPromptProps> = (props) => {
  const [password, setPassword] = createSignal("");
  const [error, setError] = createSignal("");
  const [phase, setPhase] = createSignal<Phase>("input");
  const [progress, setProgress] = createSignal(0);

  // Reset state when modal opens
  createEffect(on(() => props.open, (open) => {
    if (open) {
      setPassword("");
      setError("");
      setPhase("input");
      setProgress(0);
    }
  }));

  const handleSubmit = (e: Event) => {
    e.preventDefault();
    if (!password()) {
      setError(t("components.reAuthPrompt.passwordRequired"));
      return;
    }
    setError("");
    setPhase("ceremony");
    simulateProgress();
  };

  let rafHandle = 0;

  const simulateProgress = () => {
    // Simulate KDF verification (~3s) — will be replaced with real Tauri IPC in Story 2.8
    const start = Date.now();
    const duration = 3000;

    const tick = () => {
      const elapsed = Date.now() - start;
      const pct = Math.min(100, (elapsed / duration) * 100);
      setProgress(pct);

      if (pct < 100) {
        rafHandle = requestAnimationFrame(tick);
      }
    };

    rafHandle = requestAnimationFrame(tick);
  };

  onCleanup(() => {
    if (rafHandle) cancelAnimationFrame(rafHandle);
  });

  const handleCeremonyComplete = () => {
    const pw = password();
    props.onVerified(pw);
  };

  return (
    <Modal
      open={props.open}
      onClose={props.onClose}
      title={t("components.reAuthPrompt.title")}
      closeOnOverlayClick={false}
    >
      <Show when={phase() === "input"} fallback={
        <SecurityCeremony
          progress={progress()}
          onComplete={handleCeremonyComplete}
        />
      }>
        <form onSubmit={handleSubmit} class={styles.form}>
          <p class={styles.description}>
            {t("components.reAuthPrompt.description")}
          </p>
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
            <Button type="submit">
              {t("common.verify")}
            </Button>
          </div>
        </form>
      </Show>
    </Modal>
  );
};
