import type { Component } from "solid-js";
import { Show } from "solid-js";
import {
  autoLockTimeoutMinutes,
  clipboardAutoClearMs,
  preferencesLoaded,
  updatePreferences,
} from "../../stores/preferencesStore";
import { t } from "../../stores/i18nStore";
import styles from "./SecurityPreferences.module.css";

/** Clipboard auto-clear timeout options, in milliseconds. */
const CLIPBOARD_OPTIONS: readonly { ms: number; labelKey: string }[] = [
  { ms: 10_000, labelKey: "settings.clipboardClear.option10s" },
  { ms: 30_000, labelKey: "settings.clipboardClear.option30s" },
  { ms: 60_000, labelKey: "settings.clipboardClear.option1m" },
  { ms: 120_000, labelKey: "settings.clipboardClear.option2m" },
];

/**
 * Security-related preferences: inactivity auto-lock timeout and clipboard
 * auto-clear timeout. Both are read from and written to the preferences store.
 *
 * Lives inside the Settings "Security" group.
 */
export const SecurityPreferences: Component = () => {
  const handleTimeoutChange = (e: Event) => {
    const value = parseInt((e.target as HTMLInputElement).value, 10);
    if (value >= 1 && value <= 60) {
      updatePreferences({ autoLockTimeoutMinutes: value });
    }
  };

  const handleClipboardChange = (e: Event) => {
    const value = parseInt((e.target as HTMLSelectElement).value, 10);
    if (CLIPBOARD_OPTIONS.some((o) => o.ms === value)) {
      updatePreferences({ clipboardAutoClearMs: value });
    }
  };

  return (
    <Show when={preferencesLoaded()}>
      <div class={styles.group} data-testid="security-preferences">
        {/* Auto-lock timeout slider */}
        <div class={styles.fieldGroup} data-testid="lock-timeout">
          <label class={styles.fieldLabel} for="lock-timeout-slider">
            {t("settings.autoLock.label")}
          </label>
          <div class={styles.sliderRow}>
            <input
              id="lock-timeout-slider"
              type="range"
              class={styles.slider}
              min="1"
              max="60"
              step="1"
              value={autoLockTimeoutMinutes()}
              onInput={handleTimeoutChange}
              aria-valuemin={1}
              aria-valuemax={60}
              aria-valuenow={autoLockTimeoutMinutes()}
              aria-label={t("settings.autoLock.label")}
            />
            <span class={styles.sliderValue} data-testid="timeout-value">
              {autoLockTimeoutMinutes()} min
            </span>
          </div>
          <p class={styles.fieldHint}>
            {t("settings.autoLock.hint", { minutes: String(autoLockTimeoutMinutes()) })}
          </p>
        </div>

        {/* Clipboard auto-clear timeout */}
        <div class={styles.fieldGroup} data-testid="clipboard-clear">
          <label class={styles.fieldLabel} for="clipboard-clear-select">
            {t("settings.clipboardClear.label")}
          </label>
          <select
            id="clipboard-clear-select"
            class={styles.select}
            value={clipboardAutoClearMs()}
            onChange={handleClipboardChange}
            aria-label={t("settings.clipboardClear.ariaLabel")}
            data-testid="clipboard-clear-select"
          >
            {CLIPBOARD_OPTIONS.map((opt) => (
              <option value={opt.ms}>{t(opt.labelKey)}</option>
            ))}
          </select>
          <p class={styles.fieldHint}>
            {t("settings.clipboardClear.hint")}
          </p>
        </div>
      </div>
    </Show>
  );
};
