import type { Component } from "solid-js";
import { createSignal, onMount, For, Show } from "solid-js";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { listEntries, updateEntry, generateTotpCode, generateHotpCode, copyToClipboard } from "../entries/ipc";
import { filterEntries } from "../entries/filterEntries";
import type { EntryMetadataDto } from "../entries/ipc";
import { PopupResultItem } from "./PopupResultItem";
import { EntryDetailView } from "./EntryDetailView";
import { useToast } from "../../components/useToast";
import { clipboardAutoClearMs } from "../../stores/preferencesStore";
import { Icon } from "../../components/Icon";
import { t } from "../../stores/i18nStore";
import styles from "./QuickSearch.module.css";

/** Codes with fewer than this many seconds left are refreshed before copy. */
const STALE_THRESHOLD_S = 2;

/**
 * Whether activating this entry copies a value directly (the hero flow) or
 * opens the detail view. TOTP/HOTP copy the live code; credentials with a
 * plaintext username copy that username. Everything else (and credentials
 * whose only secret is the password) opens the detail view, where the
 * re-auth reveal flow lives — secrets are never copied straight from the list.
 */
function copiesDirectly(entry: EntryMetadataDto): boolean {
  if (entry.entryType === "totp" || entry.entryType === "hotp") return true;
  if (entry.entryType === "credential" && entry.username) return true;
  return false;
}

/**
 * Quick search interface for the popup window.
 * Auto-focuses search input, filters entries in real-time, and supports
 * keyboard navigation. The primary action (Enter or click) copies the result's
 * primary value directly for copyable types (TOTP/HOTP code, credential
 * username); other types open a detail view. Esc hides the popup.
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

  /**
   * Copy an OTP code to the (concealed, auto-clearing) clipboard and hide the
   * popup.
   *
   * TOTP is time-based: refresh the code first if it is about to roll over so
   * the user never copies a stale value. HOTP is counter-based: generate the
   * *next* code (which advances + persists the counter) — there is no rollover.
   */
  const copyTotpCode = async (entry: EntryMetadataDto) => {
    try {
      let code: string;
      if (entry.entryType === "hotp") {
        const result = await generateHotpCode(entry.id);
        code = result.code;
      } else {
        let result = await generateTotpCode(entry.id);
        if (result.remainingSeconds < STALE_THRESHOLD_S) {
          await new Promise<void>((resolve) =>
            setTimeout(resolve, result.remainingSeconds * 1000),
          );
          result = await generateTotpCode(entry.id);
        }
        code = result.code;
      }
      await copyToClipboard(code);
      const seconds = Math.round(clipboardAutoClearMs() / 1000);
      toast.success(
        t("quickAccess.copyCodeCleared", { name: entry.name, seconds: String(seconds) }),
      );
      await getCurrentWindow().hide();
    } catch {
      toast.error(t("quickAccess.copyCodeError"));
    }
  };

  /**
   * Copy a credential's plaintext username (display-safe — never the password)
   * to the concealed clipboard and hide the popup. Passwords still require the
   * re-auth reveal flow inside the detail view; this path never bypasses it.
   */
  const copyCredentialUsername = async (entry: EntryMetadataDto) => {
    if (!entry.username) return;
    try {
      await copyToClipboard(entry.username);
      const seconds = Math.round(clipboardAutoClearMs() / 1000);
      toast.success(
        t("quickAccess.copyUsernameCleared", { name: entry.name, seconds: String(seconds) }),
      );
      await getCurrentWindow().hide();
    } catch {
      toast.error(t("quickAccess.copyUsernameError"));
    }
  };

  /**
   * Primary action for a result (Enter or click). Copyable results copy their
   * primary value directly; everything else opens the detail view (which holds
   * the re-auth reveal flow and per-type guidance).
   */
  const activateEntry = (entry: EntryMetadataDto) => {
    if (!copiesDirectly(entry)) {
      // Secrets that require reveal/re-auth (credential password, seed phrase,
      // recovery code, secure note) open the detail view — never copied here.
      setSelectedEntry(entry);
      return;
    }
    if (entry.entryType === "credential") {
      void copyCredentialUsername(entry);
    } else {
      void copyTotpCode(entry);
    }
  };

  const activateSelected = () => {
    const items = filtered();
    const idx = selectedIndex();
    if (idx < 0 || idx >= items.length) return;
    activateEntry(items[idx]);
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
        activateSelected();
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
                    activateEntry(entry);
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
            <span>{t("quickAccess.hintNavigate")}</span>
            <span>{t("quickAccess.hintCopy")}</span>
            <span>{t("quickAccess.hintClose")}</span>
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
