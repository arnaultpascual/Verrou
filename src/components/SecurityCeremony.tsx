import type { Component } from "solid-js";
import { Show, createMemo, createEffect, on } from "solid-js";
import { Icon } from "./Icon";
import { t } from "../stores/i18nStore";
import styles from "./SecurityCeremony.module.css";

export interface SecurityCeremonyProps {
  /** Progress value 0-100 */
  progress: number;
  /** Called when progress reaches 100 */
  onComplete?: () => void;
  /** Additional CSS class */
  class?: string;
}

export const SecurityCeremony: Component<SecurityCeremonyProps> = (props) => {
  const isComplete = createMemo(() => props.progress >= 100);
  const clampedProgress = createMemo(() => Math.min(100, Math.max(0, props.progress)));

  // Fire onComplete when progress hits 100
  createEffect(on(isComplete, (complete) => {
    if (complete) {
      props.onComplete?.();
    }
  }));

  return (
    <div class={`${styles.ceremony} ${props.class ?? ""}`.trim()}>
      <div class={`${styles.shield} ${isComplete() ? styles.complete : ""}`}>
        <Show when={isComplete()} fallback={<Icon name="shield" size={48} />}>
          <Icon name="check" size={48} />
        </Show>
      </div>

      <p class={styles.microcopy}>
        {isComplete() ? t("components.securityCeremony.verified") : t("components.securityCeremony.verifying")}
      </p>

      <div class={styles.progressWrapper}>
        <div
          class={styles.progressBar}
          role="progressbar"
          aria-valuenow={clampedProgress()}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-label={t("components.securityCeremony.ariaLabel")}
        >
          <div
            class={styles.progressFill}
            style={{ width: `${clampedProgress()}%` }}
          />
        </div>
      </div>

      <Show when={!isComplete()}>
        <p class={styles.explanation}>
          {t("components.securityCeremony.explanation")}
        </p>
      </Show>
    </div>
  );
};
