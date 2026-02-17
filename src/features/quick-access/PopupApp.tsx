import type { Component } from "solid-js";
import { createSignal, onMount, onCleanup, Show } from "solid-js";
import { listen } from "@tauri-apps/api/event";
import { invoke } from "@tauri-apps/api/core";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { CompactUnlock } from "./CompactUnlock";
import { QuickSearch } from "./QuickSearch";
import { ToastProvider } from "../../components/ToastProvider";
import styles from "./PopupApp.module.css";

/**
 * Root component for the quick-access popup window.
 * Routes between CompactUnlock (locked) and QuickSearch (unlocked).
 * Auto-dismisses on window blur (standard system popup pattern).
 */
export const PopupApp: Component = () => {
  const [isUnlocked, setIsUnlocked] = createSignal(false);

  onMount(async () => {
    try {
      const unlocked = await invoke<boolean>("is_vault_unlocked");
      setIsUnlocked(unlocked);
    } catch {
      setIsUnlocked(false);
    }
  });

  // Auto-dismiss on window blur (focus lost)
  let unlistenFocus: (() => void) | undefined;
  onMount(async () => {
    const win = getCurrentWindow();
    unlistenFocus = await win.onFocusChanged(({ payload: focused }) => {
      if (!focused) {
        win.hide();
      }
    });
  });

  // Listen for vault lock events broadcast to all windows
  let unlistenLock: (() => void) | undefined;
  onMount(async () => {
    unlistenLock = await listen("verrou://vault-locked", () => {
      setIsUnlocked(false);
    });
  });

  onCleanup(() => {
    unlistenFocus?.();
    unlistenLock?.();
  });

  const handleUnlockSuccess = () => {
    setIsUnlocked(true);
  };

  return (
    <ToastProvider>
      <div class={styles.container}>
        <Show
          when={isUnlocked()}
          fallback={<CompactUnlock onSuccess={handleUnlockSuccess} />}
        >
          <QuickSearch />
        </Show>
      </div>
    </ToastProvider>
  );
};
