/**
 * AutoHideCountdown — the shared "this secret is about to hide itself" affordance.
 *
 * Presentational only. Driven by `remainingMs` from {@link useReveal} (or any
 * countdown source) plus an `onHide` callback. It renders a compact timer bar with
 * the time left and a "Hide" button so the user can dismiss the secret early. The
 * label is announced via `aria-live="polite"` so assistive tech hears the secret
 * is temporary without being interrupted every tick.
 *
 * Formatting: under a minute it reads "Hiding in {n}s"; at a minute or more it
 * reads mm:ss (e.g. "Hiding in 1:00"). This keeps the unified 60s reveal grammar
 * readable whether a type shows seconds or a full minute.
 */

import type { Component } from "solid-js";
import { Icon } from "./Icon";
import { Button } from "./Button";
import { t } from "../stores/i18nStore";
import styles from "./AutoHideCountdown.module.css";

export interface AutoHideCountdownProps {
  /** Milliseconds remaining before the secret auto-hides. */
  remainingMs: number;
  /** Called when the user clicks "Hide" to dismiss the secret early. */
  onHide: () => void;
  /** Optional extra class for layout tweaks at the call site. */
  class?: string;
}

/** Format remaining milliseconds as a human label fragment for the timer bar. */
function formatRemaining(ms: number): string {
  const totalSeconds = Math.max(0, Math.ceil(ms / 1000));
  if (totalSeconds >= 60) {
    const minutes = Math.floor(totalSeconds / 60);
    const seconds = totalSeconds % 60;
    return t("reveal.hidingInClock", {
      time: `${minutes}:${seconds.toString().padStart(2, "0")}`,
    });
  }
  return t("reveal.hidingIn", { seconds: String(totalSeconds) });
}

export const AutoHideCountdown: Component<AutoHideCountdownProps> = (props) => {
  const classes = () =>
    [styles.bar, props.class ?? ""].filter(Boolean).join(" ");

  return (
    <div class={classes()} data-testid="auto-hide-countdown">
      <span class={styles.timer} aria-live="polite">
        <Icon name="eye-off" size={14} class={styles.icon} />
        <span class={styles.label}>{formatRemaining(props.remainingMs)}</span>
      </span>
      <Button
        variant="ghost"
        size="sm"
        onClick={props.onHide}
        class={styles.hideBtn}
        data-testid="auto-hide-hide-btn"
      >
        <Icon name="eye-off" size={14} />
        {t("reveal.hide")}
      </Button>
    </div>
  );
};
