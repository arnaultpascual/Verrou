import type { Component } from "solid-js";
import { For } from "solid-js";
import { t } from "../../stores/i18nStore";
import styles from "./StepIndicator.module.css";

export interface StepIndicatorProps {
  currentStep: number;
  labels?: string[];
}

export const StepIndicator: Component<StepIndicatorProps> = (props) => {
  const labels = () => props.labels ?? [
    t("onboarding.steps.password"),
    t("onboarding.steps.security"),
    t("onboarding.steps.recovery"),
    t("onboarding.steps.import"),
  ];

  return (
    <div class={styles.indicator} role="navigation" aria-label={t("onboarding.progress")}>
      <div class={styles.dots}>
        <For each={labels()}>
          {(label, index) => {
            const stepNum = () => index() + 1;
            const isActive = () => stepNum() === props.currentStep;
            const isCompleted = () => stepNum() < props.currentStep;

            return (
              <div class={styles.stepItem}>
                <div
                  class={`${styles.dot} ${isActive() ? styles.active : ""} ${isCompleted() ? styles.completed : ""}`}
                  aria-current={isActive() ? "step" : undefined}
                />
                <span
                  class={`${styles.label} ${isActive() ? styles.activeLabel : ""} ${isCompleted() ? styles.completedLabel : ""}`}
                >
                  {label}
                </span>
              </div>
            );
          }}
        </For>
      </div>
      <p class={styles.stepText}>{t("onboarding.stepText", { current: props.currentStep, total: labels().length })}</p>
    </div>
  );
};
