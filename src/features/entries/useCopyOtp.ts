import type { Accessor } from "solid-js";
import { createSignal } from "solid-js";
import { useToast } from "../../components/useToast";
import { clipboardAutoClearMs } from "../../stores/preferencesStore";
import { t } from "../../stores/i18nStore";
import { generateTotpCode, copyToClipboard } from "./ipc";

const STALE_THRESHOLD_S = 2;

export interface UseCopyOtpReturn {
  copyCode: () => Promise<void>;
  isCopying: Accessor<boolean>;
}

/**
 * Hook for one-action TOTP code copy to clipboard.
 *
 * Handles: fresh code fetch, stale-code wait, clipboard write,
 * and toast notification. Auto-clear is handled by the Rust backend
 * (scheduled automatically when `copyToClipboard` is called).
 */
export function useCopyOtp(
  entryId: string,
  entryName: string,
  _period: number,
): UseCopyOtpReturn {
  const [isCopying, setIsCopying] = createSignal(false);
  const toast = useToast();

  async function copyCode(): Promise<void> {
    if (isCopying()) return;
    setIsCopying(true);
    try {
      let result = await generateTotpCode(entryId);

      // Stale code prevention: wait for next period if about to expire
      if (result.remainingSeconds < STALE_THRESHOLD_S) {
        await new Promise<void>((resolve) =>
          setTimeout(resolve, result.remainingSeconds * 1000),
        );
        result = await generateTotpCode(entryId);
      }

      await copyToClipboard(result.code);
      const seconds = Math.round(clipboardAutoClearMs() / 1000);
      // Unified copy grammar — same "{label} copied · clears in {n}s" toast the
      // reveal flows use, with the entry name as the label.
      toast.success(t("reveal.copied", { label: entryName, seconds: String(seconds) }));
    } catch {
      toast.error(t("reveal.copyFailed", { label: entryName }));
    } finally {
      setIsCopying(false);
    }
  }

  return { copyCode, isCopying };
}
