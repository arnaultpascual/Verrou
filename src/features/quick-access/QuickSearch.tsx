import type { Component } from "solid-js";
import { createSignal, onMount, For, Show } from "solid-js";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { listEntries, updateEntry } from "../entries/ipc";
import { filterEntries } from "../entries/filterEntries";
import type { EntryMetadataDto } from "../entries/ipc";
import { PopupResultItem } from "./PopupResultItem";
import { EntryDetailView } from "./EntryDetailView";
import { useToast } from "../../components/useToast";
import { Icon } from "../../components/Icon";
import { t } from "../../stores/i18nStore";
import styles from "./QuickSearch.module.css";

/**
 * Quick search interface for the popup window.
 * Auto-focuses search input, filters entries in real-time,
 * supports keyboard navigation and detail view per entry.
 */
export const QuickSearch: Component = () => {
  const [query, setQuery] = createSignal("");
  const [entries, setEntries] = createSignal<EntryMetadataDto[]>([]);
  const [selectedIndex, setSelectedIndex] = createSignal(0);
  const [selectedEntry, setSelectedEntry] = createSignal<EntryMetadataDto | null>(null);
  const toast = useToast();
  let inputRef: HTMLInputElement | undefined;

  const filtered = () => filterEntries(entries(), query());
  const resultCount = () => filtered().length;

  onMount(async () => {
    try {
      const all = await listEntries();
      setEntries(all);
    } catch {
      // Vault may have been locked between trigger and mount
    }
    inputRef?.focus();
  });

  const openSelectedEntry = () => {
    const items = filtered();
    const idx = selectedIndex();
    if (idx < 0 || idx >= items.length) return;
    setSelectedEntry(items[idx]);
  };

  const handleBack = () => {
    setSelectedEntry(null);
    // Refocus search input on next tick
    setTimeout(() => inputRef?.focus(), 0);
  };

  const handleKeyDown = async (e: KeyboardEvent) => {
    // When in detail view, only Escape is handled (by EntryDetailView itself)
    if (selectedEntry()) return;

    const count = resultCount();

    switch (e.key) {
      case "ArrowDown":
        e.preventDefault();
        setSelectedIndex((i) => (i + 1) % Math.max(count, 1));
        break;

      case "ArrowUp":
        e.preventDefault();
        setSelectedIndex((i) => (i - 1 + Math.max(count, 1)) % Math.max(count, 1));
        break;

      case "Enter":
        e.preventDefault();
        openSelectedEntry();
        break;

      case "Escape":
        e.preventDefault();
        await getCurrentWindow().hide();
        break;
    }
  };

  const handleTogglePin = async (entryId: string, pinned: boolean) => {
    try {
      const all = entries();
      const entry = all.find((e) => e.id === entryId);
      const name = entry?.name ?? "Entry";
      await updateEntry({ id: entryId, pinned });
      toast.success(pinned ? t("quickAccess.pinned", { name }) : t("quickAccess.unpinned", { name }));
      const refreshed = await listEntries();
      setEntries(refreshed);
    } catch {
      toast.error(t("quickAccess.pinFailed"));
    }
  };

  const handleInput = (e: InputEvent) => {
    const target = e.currentTarget as HTMLInputElement;
    setQuery(target.value);
    setSelectedIndex(0);
  };

  return (
    <div class={styles.wrapper} onKeyDown={handleKeyDown}>
      <Show when={selectedEntry()} fallback={
        <>
          <div class={styles.searchRow}>
            <Icon name="search" size={16} class={styles.searchIcon} />
            <input
              ref={inputRef}
              class={styles.searchInput}
              type="text"
              placeholder={t("quickAccess.searchPlaceholder")}
              value={query()}
              onInput={handleInput}
              role="combobox"
              aria-expanded="true"
              aria-controls="popup-results"
              aria-activedescendant={
                resultCount() > 0 ? `popup-result-${selectedIndex()}` : undefined
              }
              autocomplete="off"
              spellcheck={false}
            />
          </div>

          <div
            class={styles.resultCount}
            aria-live="polite"
          >
            {t("quickAccess.resultCount", { count: String(resultCount()) })}
          </div>

          <div
            id="popup-results"
            class={styles.resultList}
            role="listbox"
            aria-label={t("quickAccess.ariaSearchResults")}
          >
            <For each={filtered()}>
              {(entry, index) => (
                <PopupResultItem
                  entry={entry}
                  isSelected={index() === selectedIndex()}
                  index={index()}
                  onSelect={() => {
                    setSelectedIndex(index());
                    setSelectedEntry(entry);
                  }}
                  onTogglePin={handleTogglePin}
                />
              )}
            </For>
            <Show when={resultCount() === 0 && entries().length > 0}>
              <div class={styles.emptyState}>{t("quickAccess.noMatching")}</div>
            </Show>
            <Show when={entries().length === 0}>
              <div class={styles.emptyState}>{t("quickAccess.noEntries")}</div>
            </Show>
          </div>

          <div class={styles.hints}>
            <span>&#8593;&#8595; {t("quickAccess.hintNavigate")}</span>
            <span>&#9166; {t("quickAccess.detail.hintsOpen")}</span>
            <span>esc {t("quickAccess.hintClose")}</span>
          </div>
        </>
      }>
        {(entry) => (
          <EntryDetailView entry={entry()} onBack={handleBack} />
        )}
      </Show>
    </div>
  );
};
