/**
 * RecoveryBadge — inline badge showing recovery code stats.
 *
 * Displays "[remaining]/[total]" in the recovery type accent color.
 * Used on TOTP/HOTP entry cards that have linked recovery codes (AC6).
 */

import type { Component } from "solid-js";
import { Show, createResource } from "solid-js";
import { getRecoveryStats } from "./ipc";
import { t } from "../../stores/i18nStore";
import styles from "./RecoveryBadge.module.css";

export interface RecoveryBadgeProps {
  entryId: string;
}

export const RecoveryBadge: Component<RecoveryBadgeProps> = (props) => {
  const [stats] = createResource(() => props.entryId, getRecoveryStats);

  return (
    <Show when={stats() && stats()!.total > 0}>
      <span class={styles.badge} title={t("recovery.badge.title")}>
        {t("recovery.badge.label", { remaining: stats()!.remaining, total: stats()!.total })}
      </span>
    </Show>
  );
};
