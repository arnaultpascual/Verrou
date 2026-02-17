import type { Component } from "solid-js";
import { t } from "../stores/i18nStore";
import styles from "./Spinner.module.css";

export interface SpinnerProps {
  /** Size in pixels (default 16) */
  size?: number;
  /** Additional CSS class */
  class?: string;
}

export const Spinner: Component<SpinnerProps> = (props) => {
  const size = () => props.size ?? 16;

  return (
    <span
      class={`${styles.spinner} ${props.class ?? ""}`.trim()}
      role="status"
      aria-label={t("components.spinner.loading")}
      style={{ width: `${size()}px`, height: `${size()}px` }}
    >
      <svg
        class={styles.ring}
        width={size()}
        height={size()}
        viewBox="0 0 24 24"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        aria-hidden="true"
      >
        <circle
          class={styles.track}
          cx="12"
          cy="12"
          r="10"
          stroke="currentColor"
          stroke-width="3"
        />
        <path
          class={styles.arc}
          d="M12 2a10 10 0 017.07 2.93"
          stroke="currentColor"
          stroke-width="3"
          stroke-linecap="round"
        />
      </svg>
      <span class={styles.srOnly}>{t("components.spinner.loadingText")}</span>
    </span>
  );
};
