import type { Component } from "solid-js";
import { createEffect, For } from "solid-js";
import { wizardStore, setWizardStore } from "./stores";
import { t } from "../../stores/i18nStore";
import styles from "./KdfPresetStep.module.css";

interface PresetOption {
  value: "fast" | "balanced" | "maximum";
  label: string;
  recommended: boolean;
  description: string;
  timing: string;
}

const PRESETS: PresetOption[] = [
  {
    value: "fast",
    label: "onboarding.kdf.fast.label",
    recommended: false,
    description: "onboarding.kdf.fast.description",
    timing: "onboarding.kdf.fast.timing",
  },
  {
    value: "balanced",
    label: "onboarding.kdf.balanced.label",
    recommended: true,
    description: "onboarding.kdf.balanced.description",
    timing: "onboarding.kdf.balanced.timing",
  },
  {
    value: "maximum",
    label: "onboarding.kdf.maximum.label",
    recommended: false,
    description: "onboarding.kdf.maximum.description",
    timing: "onboarding.kdf.maximum.timing",
  },
];

export interface KdfPresetStepProps {
  onValidChange: (valid: boolean) => void;
}

export const KdfPresetStep: Component<KdfPresetStepProps> = (props) => {
  // Always valid — a preset is always selected
  createEffect(() => {
    props.onValidChange(true);
  });

  return (
    <div class={styles.step}>
      <h2 class={styles.heading}>{t("onboarding.kdf.heading")}</h2>
      <p class={styles.description}>
        {t("onboarding.kdf.description")}
      </p>

      <div class={styles.presets} role="radiogroup" aria-label={t("onboarding.kdf.ariaLabel")}>
        <For each={PRESETS}>
          {(preset) => {
            const isSelected = () => wizardStore.kdfPreset === preset.value;
            return (
              <button
                type="button"
                class={`${styles.presetCard} ${isSelected() ? styles.selected : ""}`}
                role="radio"
                aria-checked={isSelected()}
                onClick={() => setWizardStore("kdfPreset", preset.value)}
              >
                <div class={styles.presetHeader}>
                  <span class={styles.presetLabel}>{t(preset.label)}</span>
                  {preset.recommended && (
                    <span class={styles.recommended}>{t("onboarding.kdf.recommended")}</span>
                  )}
                </div>
                <p class={styles.presetDescription}>{t(preset.description)}</p>
                <span class={styles.presetTiming}>{t(preset.timing)}</span>
              </button>
            );
          }}
        </For>
      </div>
    </div>
  );
};
