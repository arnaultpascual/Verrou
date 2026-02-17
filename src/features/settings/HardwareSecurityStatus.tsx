import type { Component } from "solid-js";
import { createResource, Show } from "solid-js";
import {
  isHardwareSecurityAvailable as platformHwAvailable,
  hardwareSecurityProviderName as platformHwProvider,
} from "../../stores/platformStore";
import { checkHardwareSecurity } from "../vault/hardwareKeyIpc";
import { t } from "../../stores/i18nStore";
import styles from "./HardwareSecurityStatus.module.css";

/**
 * Read-only hardware security status display for Settings > Security.
 *
 * Hardware availability is read from the platform store (instant, cached).
 * Slot enabled status is queried live because it can change during a session.
 */
export const HardwareSecurityStatus: Component = () => {
  // Enabled status queried live (vault-specific, can change).
  const [status] = createResource(checkHardwareSecurity);

  const isLoading = () => status.loading;
  // Hardware availability from platform store (instant, no IPC).
  const isAvailable = () => platformHwAvailable();
  const isEnabled = () => status()?.enabled ?? false;
  const providerName = () => platformHwProvider();

  return (
    <div class={styles.section} data-testid="hardware-security-status">
      <h3 class={styles.title}>{t("settings.hardware.title")}</h3>

      <Show when={!isLoading()} fallback={
        <p class={styles.status}>{t("settings.hardware.checking")}</p>
      }>
        <Show
          when={isAvailable()}
          fallback={
            <p class={styles.unavailableMessage} data-testid="hw-unavailable">
              {t("settings.hardware.unavailable")}
            </p>
          }
        >
          <p
            class={`${styles.status} ${isEnabled() ? styles.statusActive : ""}`}
            data-testid="hw-status"
          >
            {isEnabled()
              ? t("settings.hardware.activeStatus", { provider: providerName() })
              : t("settings.hardware.availableStatus", { provider: providerName() })}
          </p>
        </Show>
      </Show>
    </div>
  );
};
