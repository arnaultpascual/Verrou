import type { Component } from "solid-js";
import { createEffect, createResource, For, Show } from "solid-js";
import { wizardStore, setWizardStore } from "./stores";
import { benchmarkKdf } from "./ipc";
import { t } from "../../stores/i18nStore";
import styles from "./KdfPresetStep.module.css";

type PresetValue = "fast" | "balanced" | "maximum";

interface PresetOption {
  value: PresetValue;
  label: string;
  recommended: boolean;
  description: string;
}

const PRESETS: PresetOption[] = [
  {
    value: "fast",
    label: "onboarding.kdf.fast.label",
    recommended: false,
    description: "onboarding.kdf.fast.description",
  },
  {
    value: "balanced",
    label: "onboarding.kdf.balanced.label",
    recommended: true,
    description: "onboarding.kdf.balanced.description",
  },
  {
    value: "maximum",
    label: "onboarding.kdf.maximum.label",
    recommended: false,
    description: "onboarding.kdf.maximum.description",
  },
];

export interface KdfPresetStepProps {
  onValidChange: (valid: boolean) => void;
}

export const KdfPresetStep: Component<KdfPresetStepProps> = (props) => {
  // Always valid — a preset is always selected.
  createEffect(() => {
    props.onValidChange(true);
  });

  // Calibrate against the real hardware so each tier shows the actual
  // Argon2id work it will do on THIS device — no invented "~N seconds".
  const [calibration] = createResource(benchmarkKdf);

  const specFor = (value: PresetValue) => {
    const presets = calibration();
    if (!presets) return null;
    const p = presets[value];
    // m_cost is in KiB; show whole MB. t_cost is the number of passes.
    return { memory: Math.round(p.mCost / 1024), passes: p.tCost };
  };

  return (
    <div class={styles.step}>
      <h2 class={styles.heading}>{t("onboarding.kdf.heading")}</h2>
      <p class={styles.description}>{t("onboarding.kdf.description")}</p>

      <div class={styles.presets} role="radiogroup" aria-label={t("onboarding.kdf.ariaLabel")}>
        <For each={PRESETS}>
          {(preset) => {
            const isSelected = () => wizardStore.kdfPreset === preset.value;
            const spec = () => specFor(preset.value);
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
                <span class={styles.presetTiming}>
                  <Show when={spec()} fallback={t("onboarding.kdf.measuring")}>
                    {(s) =>
                      t("onboarding.kdf.calibrated", {
                        memory: String(s().memory),
                        passes: String(s().passes),
                      })
                    }
                  </Show>
                </span>
              </button>
            );
          }}
        </For>
      </div>
    </div>
  );
};
