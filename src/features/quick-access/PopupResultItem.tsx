import type { Component } from "solid-js";
import { Show, createSignal, createEffect } from "solid-js";
import type { EntryMetadataDto } from "../entries/ipc";
import { useTotpCode } from "../entries/useTotpCode";
import { formatTotpCode } from "../entries/formatCode";
import { CountdownRing } from "../entries/CountdownRing";
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
 * Shows type badge, name, issuer, and live TOTP code for TOTP entries.
 */
export const PopupResultItem: Component<PopupResultItemProps> = (props) => {
  const isTotpEntry = () => props.entry.entryType === "totp";
  const isCredentialEntry = () => props.entry.entryType === "credential";

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
        <Show when={isCredentialEntry() && props.entry.username}>
          <span class={styles.username}>{props.entry.username}</span>
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

      <div class={styles.codeArea}>
        <Show when={isTotpEntry()} fallback={
          <Show when={isCredentialEntry()} fallback={<span class={styles.masked}>&#183;&#183;&#183;</span>}>
            <span class={styles.credentialHint}>
              <Icon name="key" size={12} />
              <span class={styles.masked}>&#8226;&#8226;&#8226;&#8226;</span>
            </span>
          </Show>
        }>
          <TotpDisplay entryId={props.entry.id} period={props.entry.period} digits={props.entry.digits} />
        </Show>
      </div>
    </div>
  );
};

/** Live TOTP code display with countdown ring. */
const TotpDisplay: Component<{ entryId: string; period: number; digits: number }> = (props) => {
  const { code, remainingSeconds } = useTotpCode(props.entryId, props.period);
  const [announcement, setAnnouncement] = createSignal("");

  // Announce "Code refreshed" on period boundary (not every second)
  let prevCode: string | undefined;
  createEffect(() => {
    const current = code();
    if (prevCode !== undefined && current !== prevCode) {
      setAnnouncement("Code refreshed");
      setTimeout(() => setAnnouncement(""), 2000);
    }
    prevCode = current;
  });

  return (
    <div class={styles.totpGroup}>
      <span
        class={styles.code}
        aria-label={`Code: ${code()}, ${remainingSeconds()} seconds remaining`}
      >
        {formatTotpCode(code(), props.digits)}
      </span>
      <CountdownRing remaining={remainingSeconds()} period={props.period} />
      <span class={styles.srOnly} aria-live="polite" role="status">
        {announcement()}
      </span>
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
