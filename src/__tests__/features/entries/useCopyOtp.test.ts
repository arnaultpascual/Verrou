import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createRoot } from "solid-js";
import { useCopyOtp } from "../../../features/entries/useCopyOtp";
import * as ipc from "../../../features/entries/ipc";

// Stub navigator.clipboard
let writeTextMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  writeTextMock = vi.fn().mockResolvedValue(undefined);
  Object.assign(navigator, {
    clipboard: { writeText: writeTextMock, readText: vi.fn() },
  });
  ipc._resetMockStore();
});

afterEach(() => {
  vi.restoreAllMocks();
});

/** Flush async microtasks (real timers). */
function flushAsync(ms = 200): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

describe("useCopyOtp", () => {
  it("copies TOTP code to clipboard on copyCode()", async () => {
    await createRoot(async (dispose) => {
      const { copyCode } = useCopyOtp(
        "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        "GitHub",
        30,
      );
      await copyCode();
      // Should write a 6-digit code (raw, no spaces)
      expect(writeTextMock).toHaveBeenCalledTimes(1);
      const written = writeTextMock.mock.calls[0][0] as string;
      expect(written).toMatch(/^\d{6}$/);
      dispose();
    });
  });

  it("returns isCopying true during copy operation", async () => {
    await createRoot(async (dispose) => {
      const { copyCode, isCopying } = useCopyOtp(
        "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        "GitHub",
        30,
      );
      expect(isCopying()).toBe(false);
      const promise = copyCode();
      // isCopying should be true during the operation
      expect(isCopying()).toBe(true);
      await promise;
      expect(isCopying()).toBe(false);
      dispose();
    });
  });

  it("does not schedule any frontend auto-clear timer", async () => {
    vi.useFakeTimers();
    const generateSpy = vi.spyOn(ipc, "generateTotpCode").mockResolvedValue({
      code: "123456",
      remainingSeconds: 20,
    });
    await createRoot(async (dispose) => {
      const { copyCode } = useCopyOtp(
        "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        "GitHub",
        30,
      );
      await copyCode();
      expect(writeTextMock).toHaveBeenCalledTimes(1);
      expect(writeTextMock).toHaveBeenCalledWith("123456");

      // Advance 30+ seconds — NO auto-clear should fire (Rust backend handles it)
      await vi.advanceTimersByTimeAsync(35_000);
      // Still only 1 call — no frontend timer cleared the clipboard
      expect(writeTextMock).toHaveBeenCalledTimes(1);

      generateSpy.mockRestore();
      dispose();
    });
    vi.useRealTimers();
  });

  it("waits for fresh code when remaining < 2 seconds", async () => {
    vi.useFakeTimers();
    const generateSpy = vi.spyOn(ipc, "generateTotpCode")
      .mockResolvedValueOnce({ code: "111111", remainingSeconds: 1 })
      .mockResolvedValueOnce({ code: "222222", remainingSeconds: 30 });

    await createRoot(async (dispose) => {
      const { copyCode } = useCopyOtp(
        "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        "GitHub",
        30,
      );
      const promise = copyCode();

      // Should wait ~1s then re-fetch
      await vi.advanceTimersByTimeAsync(1100);
      await promise;

      // Should have called generateTotpCode twice
      expect(generateSpy).toHaveBeenCalledTimes(2);
      // Should copy the fresh code
      expect(writeTextMock).toHaveBeenCalledWith("222222");

      generateSpy.mockRestore();
      dispose();
    });
    vi.useRealTimers();
  });

  it("shows error toast on generateTotpCode failure", async () => {
    const generateSpy = vi.spyOn(ipc, "generateTotpCode").mockRejectedValue(
      new Error("Entry not found"),
    );
    await createRoot(async (dispose) => {
      const { copyCode } = useCopyOtp(
        "nonexistent-id",
        "Deleted",
        30,
      );
      // Should not throw — error handled internally
      await copyCode();
      // Clipboard should NOT be written
      expect(writeTextMock).not.toHaveBeenCalled();

      generateSpy.mockRestore();
      dispose();
    });
  });

  it("shows error toast on clipboard write failure", async () => {
    const generateSpy = vi.spyOn(ipc, "generateTotpCode").mockResolvedValue({
      code: "123456",
      remainingSeconds: 20,
    });
    writeTextMock.mockRejectedValueOnce(new Error("Permission denied"));

    await createRoot(async (dispose) => {
      const { copyCode } = useCopyOtp(
        "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        "GitHub",
        30,
      );
      // Should not throw — error handled internally
      await copyCode();

      generateSpy.mockRestore();
      dispose();
    });
  });

  it("prevents re-entrant calls when isCopying is true", async () => {
    await createRoot(async (dispose) => {
      const generateSpy = vi.spyOn(ipc, "generateTotpCode").mockImplementation(
        () => new Promise((resolve) =>
          setTimeout(() => resolve({ code: "123456", remainingSeconds: 20 }), 50),
        ),
      );
      const { copyCode } = useCopyOtp(
        "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        "GitHub",
        30,
      );
      // Fire two concurrent calls
      const first = copyCode();
      const second = copyCode();
      await first;
      await second;
      // generateTotpCode should only be called once (second call returns early)
      expect(generateSpy).toHaveBeenCalledTimes(1);
      generateSpy.mockRestore();
      dispose();
    });
  });
});
