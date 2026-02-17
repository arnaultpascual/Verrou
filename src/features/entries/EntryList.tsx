import type { Component } from "solid-js";
import { Show, For } from "solid-js";
import { Button } from "../../components/Button";
import { EntryCard } from "./EntryCard";
import type { EntryMetadataDto } from "./ipc";
import type { RecoveryStatsMap } from "../recovery/ipc";
import { t } from "../../stores/i18nStore";
import styles from "./EntryList.module.css";

export interface EntryListProps {
  entries: EntryMetadataDto[];
  onSelect?: (id: string) => void;
  onAdd?: () => void;
  onTogglePin?: (entryId: string, pinned: boolean) => void;
  searchQuery?: string;
  recoveryStats?: RecoveryStatsMap;
}

export const EntryList: Component<EntryListProps> = (props) => {
  let listRef: HTMLUListElement | undefined;

  const getCards = (): HTMLElement[] => {
    if (!listRef) return [];
    return Array.from(listRef.querySelectorAll<HTMLElement>(":scope > li[tabindex]"));
  };

  const focusCard = (index: number) => {
    const cards = getCards();
    if (cards.length === 0) return;
    const clamped = ((index % cards.length) + cards.length) % cards.length;
    cards[clamped].focus();
    cards[clamped].scrollIntoView({ block: "nearest" });
  };

  const handleKeyDown = (e: KeyboardEvent) => {
    const cards = getCards();
    if (cards.length === 0) return;

    const target = e.target as HTMLElement;
    const currentIndex = cards.indexOf(target);

    switch (e.key) {
      case "ArrowDown": {
        e.preventDefault();
        const next = currentIndex < 0 ? 0 : (currentIndex + 1) % cards.length;
        focusCard(next);
        break;
      }
      case "ArrowUp": {
        e.preventDefault();
        const prev = currentIndex <= 0 ? cards.length - 1 : currentIndex - 1;
        focusCard(prev);
        break;
      }
      case "Home": {
        e.preventDefault();
        focusCard(0);
        break;
      }
      case "End": {
        e.preventDefault();
        focusCard(cards.length - 1);
        break;
      }
    }
  };

  return (
    <Show
      when={props.entries.length > 0}
      fallback={
        <Show
          when={props.searchQuery}
          fallback={
            <div class={styles.empty}>
              <p class={styles.emptyText}>
                {t("entries.empty")}
              </p>
              <Show when={props.onAdd}>
                <Button variant="primary" onClick={() => props.onAdd?.()}>
                  {t("entries.addButton")}
                </Button>
              </Show>
            </div>
          }
        >
          <div class={styles.empty}>
            <p class={styles.emptyText}>
              {t("entries.emptySearch", { query: props.searchQuery ?? "" })}
            </p>
          </div>
        </Show>
      }
    >
      <ul
        ref={listRef}
        class={styles.grid}
        role="list"
        onKeyDown={handleKeyDown}
      >
        <For each={props.entries}>
          {(entry) => (
            <EntryCard entry={entry} onSelect={props.onSelect} onTogglePin={props.onTogglePin} recoveryStats={props.recoveryStats} />
          )}
        </For>
      </ul>
    </Show>
  );
};
