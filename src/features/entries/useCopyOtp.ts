import type { Accessor } from "solid-js";
import { createSignal } from "solid-js";
import { useToast } from "../../components/useToast";
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
      toast.success(`${entryName} copied`);
    } catch {
      toast.error("Could not copy code");
    } finally {
      setIsCopying(false);
    }
  }

  return { copyCode, isCopying };
}
