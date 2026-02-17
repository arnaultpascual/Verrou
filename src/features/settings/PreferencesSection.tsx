import type { Component } from "solid-js";
import { Show, For } from "solid-js";
import {
  currentTheme,
  autoLockTimeoutMinutes,
  launchOnBoot,
  startMinimized,
  preferencesLoaded,
  updatePreferences,
} from "../../stores/preferencesStore";
import {
  enableAutostart,
  disableAutostart,
} from "./preferencesIpc";
import {
  t,
  locale,
  setLocale,
  AVAILABLE_LOCALES,
} from "../../stores/i18nStore";
import type { Locale } from "../../stores/i18nStore";
import { useToast } from "../../components/useToast";
import styles from "./PreferencesSection.module.css";

export const PreferencesSection: Component = () => {
  const toast = useToast();

  const handleThemeChange = (theme: string) => {
    updatePreferences({ theme });
  };

  const handleTimeoutChange = (e: Event) => {
    const value = parseInt((e.target as HTMLInputElement).value, 10);
    if (value >= 1 && value <= 60) {
      updatePreferences({ autoLockTimeoutMinutes: value });
    }
  };

  const handleLaunchOnBootChange = async (e: Event) => {
    const checked = (e.target as HTMLInputElement).checked;
    try {
      if (checked) {
        await enableAutostart();
        await updatePreferences({ launchOnBoot: true });
        toast.success(t("settings.startup.enabledToast"));
      } else {
        await disableAutostart();
        await updatePreferences({ launchOnBoot: false, startMinimized: false });
        toast.success(t("settings.startup.disabledToast"));
      }
    } catch {
      // Revert the toggle on failure
      (e.target as HTMLInputElement).checked = !checked;
      toast.error(t("settings.startup.errorToast"));
    }
  };

  const handleStartMinimizedChange = (e: Event) => {
    const checked = (e.target as HTMLInputElement).checked;
    updatePreferences({ startMinimized: checked });
  };

  const handleLanguageChange = (e: Event) => {
    const code = (e.target as HTMLSelectElement).value as Locale;
    setLocale(code);
    updatePreferences({ language: code });
  };

  return (
    <Show when={preferencesLoaded()}>
      <div class={styles.section} data-testid="preferences-section">
        <h2 class={styles.sectionTitle}>{t("settings.preferences")}</h2>

        {/* Theme selector */}
        <div class={styles.fieldGroup} data-testid="theme-selector">
          <label class={styles.fieldLabel}>{t("settings.theme.label")}</label>
          <div class={styles.themeOptions} role="radiogroup" aria-label={t("settings.theme.selectionAria")}>
            <button
              type="button"
              role="radio"
              aria-checked={currentTheme() === "light"}
              class={`${styles.themeOption} ${currentTheme() === "light" ? styles.themeOptionActive : ""}`}
              onClick={() => handleThemeChange("light")}
              data-testid="theme-light"
            >
              {t("settings.theme.light")}
            </button>
            <button
              type="button"
              role="radio"
              aria-checked={currentTheme() === "dark"}
              class={`${styles.themeOption} ${currentTheme() === "dark" ? styles.themeOptionActive : ""}`}
              onClick={() => handleThemeChange("dark")}
              data-testid="theme-dark"
            >
              {t("settings.theme.dark")}
            </button>
            <button
              type="button"
              role="radio"
              aria-checked={currentTheme() === "system"}
              class={`${styles.themeOption} ${currentTheme() === "system" ? styles.themeOptionActive : ""}`}
              onClick={() => handleThemeChange("system")}
              data-testid="theme-system"
            >
              {t("settings.theme.system")}
            </button>
          </div>
          <p class={styles.fieldHint}>
            {t("settings.theme.hint")}
          </p>
        </div>

        {/* Language selector */}
        <div class={styles.fieldGroup} data-testid="language-selector">
          <label class={styles.fieldLabel} for="language-select">
            {t("settings.language.label")}
          </label>
          <select
            id="language-select"
            class={styles.languageSelect}
            value={locale()}
            onChange={handleLanguageChange}
            data-testid="language-select"
          >
            <For each={AVAILABLE_LOCALES}>
              {(info) => (
                <option value={info.code}>{info.name}</option>
              )}
            </For>
          </select>
          <p class={styles.fieldHint}>
            {t("settings.language.hint")}
          </p>
        </div>

        {/* Lock timeout slider */}
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

        {/* Startup behavior */}
        <div class={styles.fieldGroup} data-testid="startup-behavior">
          <label class={styles.fieldLabel}>{t("settings.startup.label")}</label>

          <div class={styles.toggleRow}>
            <div class={styles.toggleInfo}>
              <span class={styles.toggleLabel}>{t("settings.startup.launchOnBoot")}</span>
              <span class={styles.toggleHint}>
                {t("settings.startup.launchOnBootHint")}
              </span>
            </div>
            <label class={styles.toggle}>
              <input
                type="checkbox"
                class={styles.toggleInput}
                checked={launchOnBoot()}
                onChange={handleLaunchOnBootChange}
                data-testid="launch-on-boot"
              />
              <span class={styles.toggleTrack} />
            </label>
          </div>

          <div class={styles.toggleRow}>
            <div class={styles.toggleInfo}>
              <span class={styles.toggleLabel}>{t("settings.startup.startMinimized")}</span>
              <span class={styles.toggleHint}>
                {t("settings.startup.startMinimizedHint")}
              </span>
            </div>
            <label class={styles.toggle}>
              <input
                type="checkbox"
                class={styles.toggleInput}
                checked={startMinimized()}
                disabled={!launchOnBoot()}
                onChange={handleStartMinimizedChange}
                data-testid="start-minimized"
              />
              <span class={styles.toggleTrack} />
            </label>
          </div>
        </div>
      </div>
    </Show>
  );
};
