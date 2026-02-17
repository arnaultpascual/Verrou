import type { Component } from "solid-js";
import { createSignal, onMount, For, Show } from "solid-js";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { listEntries, generateTotpCode, copyToClipboard, updateEntry } from "../entries/ipc";
import { filterEntries } from "../entries/filterEntries";
import type { EntryMetadataDto } from "../entries/ipc";
import { PopupResultItem } from "./PopupResultItem";
import { useToast } from "../../components/useToast";
import { Icon } from "../../components/Icon";
import { t } from "../../stores/i18nStore";
import styles from "./QuickSearch.module.css";

/**
 * Quick search interface for the popup window.
 * Auto-focuses search input, filters entries in real-time,
 * supports keyboard navigation and copy-on-Enter.
 */
export const QuickSearch: Component = () => {
  const [query, setQuery] = createSignal("");
  const [entries, setEntries] = createSignal<EntryMetadataDto[]>([]);
  const [selectedIndex, setSelectedIndex] = createSignal(0);
  const [copyFeedback, setCopyFeedback] = createSignal("");
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

  const handleKeyDown = async (e: KeyboardEvent) => {
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
        await copySelectedEntry();
        break;

      case "Escape":
        e.preventDefault();
        await getCurrentWindow().hide();
        break;
    }
  };

  const copySelectedEntry = async () => {
    const items = filtered();
    const idx = selectedIndex();
    if (idx < 0 || idx >= items.length) return;

    const entry = items[idx];

    if (entry.entryType === "credential") {
      if (entry.username) {
        try {
          await copyToClipboard(entry.username);
          setCopyFeedback(t("quickAccess.usernameCopied", { name: entry.name }));
          toast.success(t("quickAccess.usernameCopied", { name: entry.name }));
          setTimeout(async () => {
            await getCurrentWindow().hide();
            setCopyFeedback("");
          }, 500);
        } catch {
          toast.error(t("quickAccess.copyUsernameFailed"));
        }
      } else {
        toast.info(t("quickAccess.openVaultToCopy"));
      }
      return;
    }

    if (entry.entryType !== "totp") return;

    try {
      const result = await generateTotpCode(entry.id);
      await copyToClipboard(result.code);
      setCopyFeedback(t("quickAccess.codeCopied", { name: entry.name }));
      toast.success(t("quickAccess.codeCopied", { name: entry.name }));

      // Auto-clear is handled by the Rust backend (scheduled in clipboard_write_concealed)

      // Auto-dismiss popup after brief delay
      setTimeout(async () => {
        await getCurrentWindow().hide();
        setCopyFeedback("");
      }, 500);
    } catch {
      toast.error(t("quickAccess.copyCodeFailed"));
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
    setSelectedIndex(0); // Reset selection on new input
  };

  return (
    <div class={styles.wrapper} onKeyDown={handleKeyDown}>
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
                copySelectedEntry();
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

      <Show when={copyFeedback()}>
        <div class={styles.copyToast} aria-live="polite" role="status">
          <Icon name="check" size={14} />
          <span>{copyFeedback()}</span>
        </div>
      </Show>

      <div class={styles.hints}>
        <span>&#8593;&#8595; {t("quickAccess.hintNavigate")}</span>
        <span>&#9166; {t("quickAccess.hintCopy")}</span>
        <span>esc {t("quickAccess.hintClose")}</span>
      </div>
    </div>
  );
};
