import type { Component } from "solid-js";
import { Show } from "solid-js";
import { useMediaQuery } from "../../hooks/useMediaQuery";
import styles from "./CountdownRing.module.css";

export interface CountdownRingProps {
  remaining: number;
  period: number;
}

const RADIUS = 10;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

export const CountdownRing: Component<CountdownRingProps> = (props) => {
  const prefersReducedMotion = useMediaQuery("(prefers-reduced-motion: reduce)");

  const offset = () =>
    CIRCUMFERENCE * (1 - props.remaining / props.period);

  const isWarning = () => props.remaining <= 5;

  return (
    <Show
      when={!prefersReducedMotion()}
      fallback={
        <span
          class={`${styles.text} ${isWarning() ? styles.textWarning : ""}`}
          aria-label={`${props.remaining} seconds remaining`}
          data-testid="countdown-ring"
        >
          {props.remaining}s
        </span>
      }
    >
      <span
        class={`${styles.ring} ${isWarning() ? styles.warning : ""}`}
        data-testid="countdown-ring"
      >
        <svg
          width="24"
          height="24"
          viewBox="0 0 24 24"
          aria-hidden="true"
          class={styles.svg}
        >
          <circle
            cx="12"
            cy="12"
            r={RADIUS}
            fill="none"
            class={styles.trackCircle}
          />
          <circle
            cx="12"
            cy="12"
            r={RADIUS}
            fill="none"
            class={styles.progressCircle}
            stroke={isWarning() ? "var(--color-warning)" : "var(--color-type-totp)"}
            stroke-dasharray={String(CIRCUMFERENCE)}
            stroke-dashoffset={offset()}
          />
        </svg>
      </span>
    </Show>
  );
};
