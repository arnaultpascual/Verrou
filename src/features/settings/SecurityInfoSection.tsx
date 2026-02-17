import type { Component } from "solid-js";
import { createSignal, Show } from "solid-js";
import { Icon } from "../../components";
import { t } from "../../stores/i18nStore";
import styles from "./SecurityInfoSection.module.css";

export const SecurityInfoSection: Component = () => {
  const [expanded, setExpanded] = createSignal(false);

  return (
    <div class={styles.section} data-testid="security-info-section">
      <h2 class={styles.title}>{t("settings.securityInfo.title")}</h2>

      <p class={styles.summary}>{t("settings.securityInfo.summary")}</p>

      <dl class={styles.infoList}>
        <div class={styles.infoRow}>
          <dt class={styles.label}>{t("settings.securityInfo.encryptionLabel")}</dt>
          <dd class={styles.value}>{t("settings.securityInfo.encryptionValue")}</dd>
        </div>
        <div class={styles.infoRow}>
          <dt class={styles.label}>{t("settings.securityInfo.kdfLabel")}</dt>
          <dd class={styles.value}>{t("settings.securityInfo.kdfValue")}</dd>
        </div>
        <div class={styles.infoRow}>
          <dt class={styles.label}>{t("settings.securityInfo.kemLabel")}</dt>
          <dd class={styles.value}>{t("settings.securityInfo.kemValue")}</dd>
        </div>
      </dl>

      <button
        class={styles.expandButton}
        onClick={() => setExpanded(!expanded())}
        aria-expanded={expanded()}
        data-testid="learn-more-toggle"
        type="button"
      >
        <Icon
          name="chevron-down"
          size={14}
          class={expanded() ? styles.chevronExpanded : styles.chevron}
        />
        {expanded() ? t("settings.securityInfo.learnLess") : t("settings.securityInfo.learnMore")}
      </button>

      <Show when={expanded()}>
        <div class={styles.details} data-testid="security-details">
          <p class={styles.detailItem}>{t("settings.securityInfo.detailAes")}</p>
          <p class={styles.detailItem}>{t("settings.securityInfo.detailArgon2id")}</p>
          <p class={styles.detailItem}>{t("settings.securityInfo.detailX25519")}</p>
          <p class={styles.detailItem}>{t("settings.securityInfo.detailMlKem")}</p>
          <p class={styles.detailLocal}>{t("settings.securityInfo.detailLocal")}</p>
        </div>
      </Show>
    </div>
  );
};
