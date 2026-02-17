import { describe, expect, it, vi, afterEach } from "vitest";
import { createRoot } from "solid-js";
import { useTotpCode } from "../../../features/entries/useTotpCode";

/** Flush microtasks + delay for getEntry() mock delay + crypto.subtle to resolve. */
function flushAsync(ms = 200): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("useTotpCode", () => {
  it("returns code and remainingSeconds", async () => {
    const result = await new Promise<{ code: string; remainingSeconds: number }>(
      (resolve) => {
        createRoot(async (dispose) => {
          const totp = useTotpCode("a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d", 30);
          await flushAsync();
          resolve({
            code: totp.code(),
            remainingSeconds: totp.remainingSeconds(),
          });
          dispose();
        });
      },
    );

    expect(result.code).toMatch(/^\d{6}$/);
    expect(result.remainingSeconds).toBeGreaterThanOrEqual(1);
    expect(result.remainingSeconds).toBeLessThanOrEqual(30);
  });

  it("decrements remainingSeconds over time", async () => {
    const values: number[] = [];

    await new Promise<void>((resolve) => {
      createRoot(async (dispose) => {
        const totp = useTotpCode("a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d", 30);
        await flushAsync();
        values.push(totp.remainingSeconds());

        // Wait 1.1s for the interval to tick at least once
        await flushAsync(1100);
        values.push(totp.remainingSeconds());

        resolve();
        dispose();
      });
    });

    // After ~1s, remainingSeconds should be less or have wrapped
    expect(values[0]).toBeGreaterThanOrEqual(1);
    expect(values[1]).toBeLessThanOrEqual(values[0]);
  });

  it("cleans up interval on dispose", async () => {
    const clearIntervalSpy = vi.spyOn(globalThis, "clearInterval");

    await new Promise<void>((resolve) => {
      createRoot(async (dispose) => {
        useTotpCode("a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d", 30);
        await flushAsync();
        dispose();
        resolve();
      });
    });

    expect(clearIntervalSpy).toHaveBeenCalled();
  });

  it("returns empty code before initial fetch completes", () => {
    let code = "";
    createRoot((dispose) => {
      const totp = useTotpCode("a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d", 30);
      code = totp.code();
      dispose();
    });

    expect(code).toBe("");
  });

  it("works with 8-digit entries", async () => {
    const result = await new Promise<string>((resolve) => {
      createRoot(async (dispose) => {
        const totp = useTotpCode("c3d4e5f6-a7b8-4c9d-0e1f-2a3b4c5d6e7f", 30);
        await flushAsync();
        resolve(totp.code());
        dispose();
      });
    });

    expect(result).toMatch(/^\d{8}$/);
  });

  it("handles deleted entry gracefully (no unhandled rejection)", async () => {
    await new Promise<void>((resolve) => {
      createRoot(async (dispose) => {
        // Use a non-existent entry ID
        const totp = useTotpCode("nonexistent-id", 30);
        await flushAsync();
        // Should not throw — code stays empty
        expect(totp.code()).toBe("");
        resolve();
        dispose();
      });
    });
  });
});
