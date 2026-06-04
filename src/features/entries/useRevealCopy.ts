/**
 * useRevealCopy — one consistent copy-to-clipboard action for revealed secrets.
 *
 * Every reveal surface copies the same way and says the same thing:
 *
 *   "{label} copied · clears in {clipboardSeconds}s"
 *
 * where `clipboardSeconds` is derived from the user's clipboard auto-clear
 * preference (the same setting the quick-access copy flow uses). The actual copy
 * goes through the concealed-clipboard IPC (`copyToClipboard`), which schedules
 * the Rust-side auto-clear — this hook only standardizes the call + the toast so
 * the grammar reads identically across seed / recovery / credential.
 *
 * Usage:
 *   const copyReveal = useRevealCopy();
 *   await copyReveal(seed.words.join(" "), t("seed.viewer.copyAllLabel"));
 */

import { useToast } from "../../components/useToast";
import { clipboardAutoClearMs } from "../../stores/preferencesStore";
import { t } from "../../stores/i18nStore";
import { copyToClipboard } from "./ipc";

export type RevealCopyFn = (text: string, label: string) => Promise<void>;

/**
 * Returns a `copy(text, label)` function that writes `text` to the concealed,
 * auto-clearing clipboard and shows the unified "{label} copied · clears in {n}s"
 * toast. On failure it shows `t("reveal.copyFailed", { label })` and the promise
 * still resolves (callers do not need a try/catch).
 *
 * @param fallbackLabel — label used in the failure toast if a per-call label is
 *   not meaningful; individual calls always pass their own `label`.
 */
export function useRevealCopy(): RevealCopyFn {
  const toast = useToast();

  return async (text: string, label: string): Promise<void> => {
    try {
      await copyToClipboard(text);
      const seconds = Math.round(clipboardAutoClearMs() / 1000);
      toast.success(t("reveal.copied", { label, seconds: String(seconds) }));
    } catch {
      toast.error(t("reveal.copyFailed", { label }));
    }
  };
}
