import type { Component } from "solid-js";
import { Icon } from "../../components/Icon";
import type { IconName } from "../../components/Icon";
import { t } from "../../stores/i18nStore";
import styles from "./TypeBadge.module.css";

export interface TypeBadgeProps {
  entryType: string;
}

interface TypeConfig {
  labelKey: string;
  icon: IconName;
}

const TYPE_MAP: Record<string, TypeConfig> = {
  totp: { labelKey: "entries.type.totp", icon: "lock" },
  hotp: { labelKey: "entries.type.hotp", icon: "lock" },
  seed_phrase: { labelKey: "entries.type.seed", icon: "shield" },
  recovery_code: { labelKey: "entries.type.recovery", icon: "list" },
  secure_note: { labelKey: "entries.type.note", icon: "lock" },
  credential: { labelKey: "entries.type.credential", icon: "key" },
};

const FALLBACK: TypeConfig = { labelKey: "entries.type.other", icon: "info" };

export const TypeBadge: Component<TypeBadgeProps> = (props) => {
  const config = () => TYPE_MAP[props.entryType] ?? FALLBACK;

  return (
    <span class={styles.badge} data-type={props.entryType}>
      <Icon name={config().icon} size={12} />
      <span class={styles.label}>{t(config().labelKey)}</span>
    </span>
  );
};
