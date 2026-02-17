import type { Component } from "solid-js";
import { createSignal, onMount, Show } from "solid-js";
import { t } from "../../stores/i18nStore";
import { getAppInfo } from "./preferencesIpc";
import type { AppInfoDto } from "./preferencesIpc";
import styles from "./AboutSection.module.css";

export const AboutSection: Component = () => {
  const [info, setInfo] = createSignal<AppInfoDto | null>(null);

  onMount(async () => {
    try {
      const data = await getAppInfo();
      setInfo(data);
    } catch {
      // Silently degrade — show nothing if IPC fails
    }
  });

  return (
    <Show when={info()}>
      {(appInfo) => (
        <div class={styles.section} data-testid="about-section">
          <h2 class={styles.title}>{t("settings.about.title")}</h2>

          <dl class={styles.infoList}>
            <div class={styles.infoRow}>
              <dt class={styles.label}>{t("settings.about.versionLabel")}</dt>
              <dd class={styles.value} data-testid="about-version">
                {appInfo().version}
              </dd>
            </div>

            <div class={styles.infoRow}>
              <dt class={styles.label}>{t("settings.about.buildLabel")}</dt>
              <dd class={styles.value} data-testid="about-build">
                <code class={styles.mono}>{appInfo().commitHash}</code>
                <span class={styles.buildDate}>({appInfo().buildDate})</span>
              </dd>
            </div>

            <div class={styles.infoRow}>
              <dt class={styles.label}>{t("settings.about.licenseLabel")}</dt>
              <dd class={styles.value} data-testid="about-license">
                {appInfo().license}
              </dd>
            </div>

            <div class={styles.infoRow}>
              <dt class={styles.label}>{t("settings.about.sourceCodeLabel")}</dt>
              <dd class={styles.value} data-testid="about-source">
                <code class={styles.mono}>{appInfo().repository}</code>
              </dd>
            </div>

            <div class={styles.infoRow}>
              <dt class={styles.label}>{t("settings.about.auditLabel")}</dt>
              <dd class={`${styles.value} ${styles.muted}`} data-testid="about-audit">
                {t("settings.about.auditNotPublished")}
              </dd>
            </div>
          </dl>
        </div>
      )}
    </Show>
  );
};
