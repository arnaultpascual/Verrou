import type { Component } from "solid-js";
import { createSignal, createEffect, onCleanup, Show } from "solid-js";
import { Icon } from "../../components";
import { t } from "../../stores/i18nStore";
import { platformCapabilities } from "../../stores/platformStore";
import { openOsNetworkSettings } from "../settings/preferencesIpc";
import styles from "./Footer.module.css";

export const Footer: Component = () => {
  const [popoverOpen, setPopoverOpen] = createSignal(false);

  const togglePopover = () => setPopoverOpen(!popoverOpen());

  const handleVerify = async () => {
    try {
      await openOsNetworkSettings();
    } catch {
      // Best-effort — silently ignore if OS settings can't be opened
    }
  };

  // Dismiss popover on any click outside the badge wrapper.
  // Uses a document-level listener that is only active while the popover is open.
  createEffect(() => {
    if (!popoverOpen()) return;

    const handleClickOutside = (e: MouseEvent) => {
      const target = e.target as HTMLElement;
      if (!target.closest(`.${styles.offlineBadgeWrapper}`)) {
        setPopoverOpen(false);
      }
    };

    document.addEventListener("click", handleClickOutside);
    onCleanup(() => document.removeEventListener("click", handleClickOutside));
  });

  const platformInstruction = () => {
    const os = platformCapabilities()?.osType ?? "unknown";
    switch (os) {
      case "macos":
        return t("footer.offlineBadge.instructionMacos");
      case "windows":
        return t("footer.offlineBadge.instructionWindows");
      default:
        return t("footer.offlineBadge.instructionLinux");
    }
  };

  return (
    <footer class={styles.footer}>
      <div class={styles.offlineBadgeWrapper}>
        <button
          class={styles.offlineBadge}
          onClick={togglePopover}
          aria-label={t("footer.offlineByDesign")}
          aria-expanded={popoverOpen()}
          data-testid="offline-badge"
          type="button"
        >
          <Icon name="shield-check" size={14} class={styles.shieldIcon} />
          <span>{t("footer.offlineByDesign")}</span>
        </button>

        <Show when={popoverOpen()}>
          <div
            class={styles.popover}
            role="dialog"
            aria-label={t("footer.offlineBadge.heading")}
            data-testid="offline-popover"
          >
            <p class={styles.popoverHeading}>
              <Icon name="shield-check" size={16} class={styles.shieldIcon} />
              {t("footer.offlineBadge.heading")}
            </p>
            <p class={styles.popoverDescription}>
              {t("footer.offlineBadge.description")}
            </p>
            <button
              class={styles.verifyButton}
              onClick={handleVerify}
              data-testid="verify-os-settings"
              type="button"
            >
              {t("footer.offlineBadge.verifyButton")}
            </button>
            <p class={styles.platformInstruction}>
              {platformInstruction()}
            </p>
          </div>
        </Show>
      </div>
      <span class={styles.entryCount}>{t("footer.entryCountZero")}</span>
      <span class={styles.version}>{t("footer.version")}</span>
    </footer>
  );
};
