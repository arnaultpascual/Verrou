import type { Component } from "solid-js";
import { Show } from "solid-js";
import type { EntryMetadataDto } from "../entries/ipc";
import { TypeBadge } from "../entries/TypeBadge";
import { Icon } from "../../components/Icon";
import styles from "./PopupResultItem.module.css";

export interface PopupResultItemProps {
  entry: EntryMetadataDto;
  isSelected: boolean;
  index: number;
  onSelect: () => void;
  onTogglePin?: (entryId: string, pinned: boolean) => void;
}

/**
 * Single entry row in the popup result list.
 * Shows type badge, name, issuer, and pin toggle.
 * Click/Enter opens the detail view.
 */
export const PopupResultItem: Component<PopupResultItemProps> = (props) => {
  return (
    <div
      id={`popup-result-${props.index}`}
      class={`${styles.item} ${props.isSelected ? styles.selected : ""}`}
      role="option"
      aria-selected={props.isSelected}
      aria-label={buildAriaLabel(props.entry)}
      onClick={props.onSelect}
    >
      <div class={styles.info}>
        <TypeBadge entryType={props.entry.entryType} />
        <span class={styles.name}>{props.entry.name}</span>
        <Show when={props.entry.issuer}>
          <span class={styles.issuer}>{props.entry.issuer}</span>
        </Show>
      </div>

      <Show when={props.onTogglePin}>
        <button
          class={`${styles.pinToggle} ${props.entry.pinned ? styles.pinTogglePinned : ""}`}
          aria-label={props.entry.pinned ? "Unpin this entry" : "Pin this entry"}
          data-testid="popup-pin-toggle"
          onClick={(e) => {
            e.stopPropagation();
            props.onTogglePin!(props.entry.id, !props.entry.pinned);
          }}
          onKeyDown={(e) => {
            if (e.key === "Enter" || e.key === " ") {
              e.preventDefault();
              e.stopPropagation();
              props.onTogglePin!(props.entry.id, !props.entry.pinned);
            }
          }}
        >
          <Icon name="star" size={12} />
        </button>
      </Show>
    </div>
  );
};

function buildAriaLabel(entry: EntryMetadataDto): string {
  const parts = [entry.name];
  if (entry.issuer) parts.push(entry.issuer);
  parts.push(entry.entryType);
  if (entry.pinned) parts.push("pinned");
  return parts.join(", ");
}
