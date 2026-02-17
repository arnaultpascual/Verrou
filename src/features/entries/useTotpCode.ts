import { createSignal, onCleanup, type Accessor } from "solid-js";
import { generateTotpCode } from "./ipc";

export interface UseTotpCodeReturn {
  code: Accessor<string>;
  remainingSeconds: Accessor<number>;
}

/**
 * Reactive hook that generates live TOTP codes and counts down each period.
 * Calls `generateTotpCode` IPC on mount and at every period boundary.
 * Ticks every 1s to update `remainingSeconds` from wall clock (no drift).
 */
export function useTotpCode(entryId: string, period: number): UseTotpCodeReturn {
  const [code, setCode] = createSignal("");
  const [remainingSeconds, setRemainingSeconds] = createSignal(0);

  let lastCode = "";

  async function fetchCode() {
    try {
      const result = await generateTotpCode(entryId);
      if (result.code !== lastCode) {
        lastCode = result.code;
        setCode(result.code);
      }
      setRemainingSeconds(result.remainingSeconds);
    } catch {
      // Entry may have been deleted — stop updating silently
    }
  }

  /** Compute remaining seconds from wall clock (no drift). */
  function wallClockRemaining(): number {
    const now = Math.floor(Date.now() / 1000);
    return period - (now % period);
  }

  // Initial fetch
  fetchCode();

  const timerId = setInterval(() => {
    const remaining = wallClockRemaining();
    setRemainingSeconds(remaining);

    // Period boundary — fetch new code
    if (remaining === period) {
      fetchCode();
    }
  }, 1000);

  onCleanup(() => clearInterval(timerId));

  return { code, remainingSeconds };
}
