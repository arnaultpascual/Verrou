import type { Component } from "solid-js";
import { Show, For, createSignal, createEffect, on, onCleanup, onMount } from "solid-js";
import { copyToClipboard } from "../entries/ipc";
import { useToast } from "../../components/useToast";
import { Button } from "../../components/Button";
import { Icon } from "../../components/Icon";
import type { SeedDisplay } from "./ipc";
import { t } from "../../stores/i18nStore";
import styles from "./SeedViewer.module.css";

/** Default auto-hide timeout in seconds. */
const DEFAULT_TIMEOUT_SECONDS = 60;

export interface SeedViewerProps {
  /** Word count to show in masked state. */
  wordCount: number;
  /** Whether the entry has a BIP39 passphrase. */
  hasPassphrase: boolean;
  /** Revealed seed data (null when masked). */
  revealedData: SeedDisplay | null;
  /** Called when the user clicks "Reveal". */
  onRevealRequest: () => void;
  /** Called when revealed data should be cleared (timeout, hide, navigation). */
  onClear: () => void;
}

export const SeedViewer: Component<SeedViewerProps> = (props) => {
  const toast = useToast();
  const [remaining, setRemaining] = createSignal(DEFAULT_TIMEOUT_SECONDS);
  let timerHandle: ReturnType<typeof setInterval> | undefined;

  // Start countdown timer when data is revealed
  createEffect(on(() => props.revealedData, (data) => {
    clearCountdown();
    if (data) {
      setRemaining(DEFAULT_TIMEOUT_SECONDS);
      timerHandle = setInterval(() => {
        setRemaining((prev) => {
          const next = prev - 1;
          if (next <= 0) {
            clearCountdown();
            props.onClear();
            return 0;
          }
          return next;
        });
      }, 1000);
    }
  }));

  // Listen for vault-locked event to clear revealed data
  onMount(async () => {
    try {
      const IS_TAURI = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
      if (IS_TAURI) {
        const { listen } = await import("@tauri-apps/api/event");
        const unlisten = await listen("verrou://vault-locked", () => {
          clearCountdown();
          props.onClear();
        });
        onCleanup(unlisten);
      }
    } catch {
      // Non-Tauri environment — no event listener needed
    }
  });

  // Clear on unmount (navigation away)
  onCleanup(() => {
    clearCountdown();
    if (props.revealedData) {
      props.onClear();
    }
  });

  const clearCountdown = () => {
    if (timerHandle !== undefined) {
      clearInterval(timerHandle);
      timerHandle = undefined;
    }
  };

  const handleCopyAll = async () => {
    const data = props.revealedData;
    if (!data) return;
    try {
      await copyToClipboard(data.words.join(" "));
      toast.success(t("seed.viewer.copiedToClipboard"));
    } catch {
      toast.error(t("seed.viewer.copyFailed"));
    }
  };

  const handleHide = () => {
    clearCountdown();
    props.onClear();
  };

  return (
    <div class={styles.container}>
      <Show
        when={props.revealedData}
        fallback={
          <div class={styles.maskedContainer}>
            <div class={styles.maskedGrid} data-testid="seed-masked-grid">
              <For each={Array.from({ length: props.wordCount }, (_, i) => i)}>
                {(i) => (
                  <div class={styles.maskedWord}>
                    <span class={styles.wordNumber}>{i + 1}</span>
                    <span class={styles.maskedDots}>{"\u25CF\u25CF\u25CF\u25CF\u25CF"}</span>
                  </div>
                )}
              </For>
            </div>
            <div class={styles.revealActions}>
              <Button variant="primary" onClick={props.onRevealRequest} data-testid="reveal-btn">
                <Icon name="eye" size={16} />
                {t("seed.viewer.reveal")}
              </Button>
            </div>
          </div>
        }
      >
        {(data) => (
          <div class={styles.revealedContainer}>
            <div class={styles.timerBar} data-testid="countdown-timer">
              <Icon name="clock" size={14} />
              <span>{t("seed.viewer.hidingIn", { remaining: remaining() })}</span>
            </div>
            <div class={styles.wordGrid} data-testid="seed-revealed-grid">
              <For each={data().words}>
                {(word, i) => (
                  <div class={styles.wordCell}>
                    <span class={styles.wordNumber}>{i() + 1}</span>
                    <span class={styles.wordText}>{word}</span>
                  </div>
                )}
              </For>
            </div>
            <Show when={props.hasPassphrase}>
              <div class={styles.passphraseIndicator}>
                <Icon name="key" size={14} />
                <span>{t("seed.viewer.passphraseSet")}</span>
              </div>
            </Show>
            <div class={styles.revealedActions}>
              <Button variant="ghost" onClick={handleCopyAll} data-testid="copy-all-btn">
                <Icon name="copy" size={16} />
                {t("seed.viewer.copyAll")}
              </Button>
              <Button variant="ghost" onClick={handleHide} data-testid="hide-btn">
                <Icon name="eye-off" size={16} />
                {t("seed.viewer.hide")}
              </Button>
            </div>
          </div>
        )}
      </Show>
    </div>
  );
};
