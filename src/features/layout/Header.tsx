import type { Component } from "solid-js";
import { Show, onMount, onCleanup, createSignal } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { Icon, ShortcutTooltip } from "../../components";
import { vaultState, setVaultState } from "../../stores/vaultStore";
import { searchQuery, setSearchQuery, clearSearch } from "../../stores/searchStore";
import { lockVault } from "../vault/ipc";
import { t } from "../../stores/i18nStore";
import styles from "./Header.module.css";

export const Header: Component = () => {
  const navigate = useNavigate();
  let inputRef: HTMLInputElement | undefined;
  const [focused, setFocused] = createSignal(false);

  const handleLock = async () => {
    try {
      await lockVault();
      setVaultState("locked");
    } catch {
      // Lock failed — rare (poisoned mutex). State remains unlocked.
    }
  };

  const handleSlashKey = (e: KeyboardEvent) => {
    // Ignore if typing in another input/textarea
    const tag = (e.target as HTMLElement)?.tagName;
    if (tag === "INPUT" || tag === "TEXTAREA") return;
    // Ignore if modifier keys held
    if (e.ctrlKey || e.metaKey || e.altKey) return;

    if (e.key === "/") {
      e.preventDefault();
      inputRef?.focus();
    }
  };

  const handleInputKeyDown = (e: KeyboardEvent) => {
    if (e.key === "Escape") {
      clearSearch();
      inputRef?.blur();
    }
  };

  onMount(() => {
    document.addEventListener("keydown", handleSlashKey);
  });

  onCleanup(() => {
    document.removeEventListener("keydown", handleSlashKey);
  });

  return (
    <header class={styles.header}>
      <div class={styles.titleSection}>
        <h1 class={styles.title}>{t("header.title")}</h1>
      </div>
      <div class={styles.searchSection}>
        <div
          class={`${styles.searchWrapper} ${focused() ? styles.searchWrapperFocused : ""}`}
        >
          <Icon name="search" size={14} aria-hidden="true" />
          <input
            ref={inputRef}
            type="text"
            class={styles.searchInput}
            placeholder={t("header.searchPlaceholder")}
            aria-label={t("header.searchLabel")}
            title={t("header.searchHint")}
            value={searchQuery()}
            onInput={(e) => setSearchQuery(e.currentTarget.value)}
            onKeyDown={handleInputKeyDown}
            onFocus={() => setFocused(true)}
            onBlur={() => setFocused(false)}
          />
        </div>
      </div>
      <div class={styles.actions}>
        <Show when={vaultState() === "unlocked"}>
          <ShortcutTooltip shortcut="Ctrl+Shift+L">
            <button
              class={styles.lockBtn}
              onClick={handleLock}
              aria-label={t("header.lockVault")}
              type="button"
            >
              <Icon name="lock" size={18} />
            </button>
          </ShortcutTooltip>
        </Show>
        <button
          class={styles.settingsBtn}
          aria-label={t("header.settings")}
          type="button"
          onClick={() => navigate("/settings")}
        >
          <Icon name="settings" size={18} />
        </button>
      </div>
    </header>
  );
};
