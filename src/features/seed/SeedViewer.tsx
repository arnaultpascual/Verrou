import type { Component, JSX } from "solid-js";
import { Show, For } from "solid-js";
import { Button } from "../../components/Button";
import { Icon } from "../../components/Icon";
import type { SeedDisplay } from "./ipc";
import { t } from "../../stores/i18nStore";
import styles from "./SeedViewer.module.css";

/**
 * SeedViewer — presentational masked/revealed seed phrase grid.
 *
 * Reveal grammar: this component is now purely presentational. The reveal
 * lifecycle (re-auth, the single auto-hide countdown, clipboard copy, vault-lock
 * clearing, and cleanup) lives in the parent via `useReveal` + `useRevealCopy` +
 * `AutoHideCountdown`. SeedViewer just renders the masked grid (with a Reveal
 * button) or the revealed words (with the injected countdown, a Copy All button,
 * and a Hide button) based on `revealedData`.
 */
export interface SeedViewerProps {
  /** Word count to show in masked state. */
  wordCount: number;
  /** Whether the entry has a BIP39 passphrase. */
  hasPassphrase: boolean;
  /** Revealed seed data (null when masked). */
  revealedData: SeedDisplay | null;
  /** Called when the user clicks "Reveal". */
  onRevealRequest: () => void;
  /** Called when the user copies the full phrase. */
  onCopyAll: () => void;
  /** Called when the user clicks "Hide". */
  onHide: () => void;
  /**
   * Countdown affordance rendered above the words while revealed — the parent
   * injects `<AutoHideCountdown>` driven by the shared reveal countdown.
   */
  countdown?: JSX.Element;
}

export const SeedViewer: Component<SeedViewerProps> = (props) => {
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
                    <span class={styles.maskedDots}>{"●●●●●"}</span>
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
            <Show when={props.countdown}>{props.countdown}</Show>
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
              <Button variant="ghost" onClick={props.onCopyAll} data-testid="copy-all-btn">
                <Icon name="copy" size={16} />
                {t("seed.viewer.copyAll")}
              </Button>
              <Button variant="ghost" onClick={props.onHide} data-testid="hide-btn">
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
