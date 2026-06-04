import type { Component } from "solid-js";
import { Icon } from "../../components/Icon";
import { t } from "../../stores/i18nStore";
import styles from "./FilterChip.module.css";

export interface FilterChipProps {
  /** Visible chip label, e.g. "Folder: Work" or "TOTP". */
  label: string;
  /** Accessible label for the clear button, e.g. "Clear folder filter". */
  clearLabel: string;
  /** Clears this filter. */
  onClear: () => void;
}

/**
 * A removable filter indicator shown near the entries list header.
 *
 * Makes an active folder/type filter legible and clearable so a narrowed
 * list never looks like entries silently vanished.
 */
export const FilterChip: Component<FilterChipProps> = (props) => {
  return (
    <span class={styles.chip}>
      <span class={styles.label}>{props.label}</span>
      <button
        type="button"
        class={styles.clear}
        aria-label={props.clearLabel}
        title={props.clearLabel}
        onClick={() => props.onClear()}
      >
        <Icon name="x" size={12} />
      </button>
    </span>
  );
};
