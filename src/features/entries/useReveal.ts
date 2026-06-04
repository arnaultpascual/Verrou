/**
 * useReveal — the shared "reveal grammar" primitive for entry detail views.
 *
 * Every high-sensitivity entry type (seed phrase, recovery codes, credential
 * password, …) follows the same dance: the user requests a reveal, re-authenticates
 * with the master password, the secret is shown, and a single auto-hide countdown
 * clears it again. Before this hook each type hand-rolled that flow with subtly
 * different rules (different auto-hide durations, different cleanup, different
 * session-password handling). `useReveal` makes the grammar uniform:
 *
 *   - One re-auth gate (`request()` + `onVerified` wired to `ReAuthPrompt`).
 *   - One auto-hide duration for ALL types — `REVEAL_AUTO_HIDE_MS` (60s, long
 *     enough to read a 24-word seed out loud).
 *   - The entered password is retained as `sessionPassword()` for follow-up
 *     authenticated actions (e.g. the recovery used/unused toggle) and is cleared
 *     together with the revealed data.
 *   - Revealed data is always cleared on hide, on auto-hide expiry, on vault lock,
 *     and on component cleanup — secrets never outlive the view.
 *
 * The hook is generic over the revealed payload `T` (e.g. `SeedDisplay`,
 * `RecoveryCodeDisplay`, `CredentialDisplay`). It performs NO rendering and reads
 * no secrets across the IPC boundary itself — `revealFn` is supplied by the caller
 * and is the only thing that touches the backend.
 *
 * Security note: `onVerified` lets `revealFn`'s rejection propagate unchanged so
 * `ReAuthPrompt` can surface a wrong-password error inline and stay open for retry.
 * It deliberately does NOT swallow errors or fake a success.
 */

import type { Accessor } from "solid-js";
import { createSignal, onCleanup, onMount } from "solid-js";

/**
 * Unified auto-hide duration for every reveal, in milliseconds.
 *
 * 60s is intentionally generous: it is enough time to read a full 24-word BIP39
 * seed aloud or transcribe recovery codes, while still guaranteeing the secret
 * leaves the screen automatically. Do NOT special-case this per entry type — the
 * whole point of the reveal grammar is that the timeout is the same everywhere.
 */
export const REVEAL_AUTO_HIDE_MS = 60_000;

/** Countdown tick resolution. 1s keeps the visible mm:ss / "{n}s" label honest. */
const TICK_MS = 1_000;

export interface UseRevealOptions<T> {
  /**
   * Perform the real, re-authenticated reveal with the entered master password.
   * MUST reject if the password is wrong or the reveal fails — the rejection is
   * propagated to `ReAuthPrompt`, which shows it inline and stays open for retry.
   */
  revealFn: (password: string) => Promise<T>;
  /**
   * Auto-hide duration override (ms). Defaults to {@link REVEAL_AUTO_HIDE_MS}.
   * Provided only as an escape hatch (e.g. tests); production callers should use
   * the default so every type shares one timeout.
   */
  autoHideMs?: number;
  /**
   * Called once, synchronously, right after a successful reveal — after the data
   * and session password are stored and the countdown has started. Use it to kick
   * off type-specific side effects such as starting linked-TOTP polling. Receives
   * the revealed payload and the verified password.
   */
  onReveal?: (data: T, password: string) => void;
  /**
   * Called whenever the reveal is torn down (manual hide, auto-hide expiry, vault
   * lock, or cleanup) AFTER the revealed data, session password, and countdown
   * have been cleared. Use it to stop type-specific side effects such as TOTP
   * polling or to reset per-field visibility state.
   */
  onHide?: () => void;
}

export interface UseRevealReturn<T> {
  /** The revealed payload, or `null` while masked. */
  revealed: Accessor<T | null>;
  /**
   * The master password entered during the most recent successful reveal, or
   * `null` while masked. Retained for follow-up authenticated actions in the same
   * reveal session (e.g. recovery used/unused toggle). Cleared by `hide()`.
   */
  sessionPassword: Accessor<string | null>;
  /** Whether the re-auth prompt is open. */
  showReAuth: Accessor<boolean>;
  /** Open the re-auth prompt to begin a reveal. */
  request: () => void;
  /** Close the re-auth prompt without revealing (the user cancelled). */
  cancelReAuth: () => void;
  /**
   * Pass directly to `<ReAuthPrompt onVerified={...} />`. Runs `revealFn`, and on
   * success stores the data + password, closes the prompt, and starts the unified
   * auto-hide countdown. Lets `revealFn`'s rejection propagate so the prompt shows
   * the error inline.
   */
  onVerified: (password: string) => Promise<void>;
  /** Milliseconds remaining before auto-hide. `0` while masked. */
  remainingMs: Accessor<number>;
  /** Clear revealed data + session password + countdown now. Fires `onHide`. */
  hide: () => void;
}

/**
 * Encapsulate the re-auth → reveal → auto-hide lifecycle for one entry detail view.
 */
export function useReveal<T>(options: UseRevealOptions<T>): UseRevealReturn<T> {
  const autoHideMs = options.autoHideMs ?? REVEAL_AUTO_HIDE_MS;

  const [revealed, setRevealed] = createSignal<T | null>(null);
  const [sessionPassword, setSessionPassword] = createSignal<string | null>(null);
  const [showReAuth, setShowReAuth] = createSignal(false);
  const [remainingMs, setRemainingMs] = createSignal(0);

  let timerHandle: ReturnType<typeof setInterval> | undefined;
  let deadline = 0;

  const clearCountdown = () => {
    if (timerHandle !== undefined) {
      clearInterval(timerHandle);
      timerHandle = undefined;
    }
  };

  const startCountdown = () => {
    clearCountdown();
    deadline = Date.now() + autoHideMs;
    setRemainingMs(autoHideMs);
    timerHandle = setInterval(() => {
      const left = deadline - Date.now();
      if (left <= 0) {
        setRemainingMs(0);
        // Auto-hide expiry — clears data, password, countdown, fires onHide.
        hide();
        return;
      }
      setRemainingMs(left);
    }, TICK_MS);
  };

  const request = () => {
    setShowReAuth(true);
  };

  const cancelReAuth = () => {
    setShowReAuth(false);
  };

  const onVerified = async (password: string): Promise<void> => {
    // Throws on wrong password — we let it propagate so ReAuthPrompt surfaces the
    // error inline and stays open. Nothing is revealed and no countdown starts.
    const data = await options.revealFn(password);
    setRevealed(() => data);
    setSessionPassword(password);
    setShowReAuth(false);
    startCountdown();
    options.onReveal?.(data, password);
  };

  const hide = () => {
    clearCountdown();
    setRemainingMs(0);
    setRevealed(null);
    setSessionPassword(null);
    options.onHide?.();
  };

  // Clear the moment the vault locks — a locked vault must never leave a secret
  // on screen. Tauri-only; harmless no-op in the test/jsdom environment.
  onMount(async () => {
    try {
      const isTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
      if (!isTauri) return;
      const { listen } = await import("@tauri-apps/api/event");
      const unlisten = await listen("verrou://vault-locked", () => {
        hide();
      });
      onCleanup(unlisten);
    } catch {
      // Non-Tauri environment — no event listener needed.
    }
  });

  // Defensive teardown: stop the timer and drop any revealed secret when the
  // owning component unmounts (navigation, modal close).
  onCleanup(() => {
    clearCountdown();
    setRevealed(null);
    setSessionPassword(null);
  });

  return {
    revealed,
    sessionPassword,
    showReAuth,
    request,
    cancelReAuth,
    onVerified,
    remainingMs,
    hide,
  };
}
