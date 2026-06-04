import { describe, expect, it, vi, afterEach } from "vitest";
import { createRoot } from "solid-js";
import { useReveal, REVEAL_AUTO_HIDE_MS } from "../../../features/entries/useReveal";

interface FakeSecret {
  value: string;
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

/**
 * Run a body inside a Solid reactive root and dispose afterwards, returning the
 * disposer so tests can assert cleanup behavior explicitly.
 */
function withRoot<T>(body: (dispose: () => void) => T): { result: T; dispose: () => void } {
  let result!: T;
  let disposer!: () => void;
  createRoot((dispose) => {
    disposer = dispose;
    result = body(dispose);
  });
  return { result, dispose: disposer };
}

describe("useReveal", () => {
  it("constant is the unified 60s auto-hide", () => {
    expect(REVEAL_AUTO_HIDE_MS).toBe(60_000);
  });

  it("starts masked: no data, no session password, no countdown, reauth closed", () => {
    const { result, dispose } = withRoot(() =>
      useReveal<FakeSecret>({ revealFn: vi.fn() }),
    );

    expect(result.revealed()).toBeNull();
    expect(result.sessionPassword()).toBeNull();
    expect(result.showReAuth()).toBe(false);
    expect(result.remainingMs()).toBe(0);
    dispose();
  });

  it("request() opens the re-auth prompt; cancelReAuth() closes it without revealing", () => {
    const { result, dispose } = withRoot(() =>
      useReveal<FakeSecret>({ revealFn: vi.fn() }),
    );

    result.request();
    expect(result.showReAuth()).toBe(true);

    result.cancelReAuth();
    expect(result.showReAuth()).toBe(false);
    expect(result.revealed()).toBeNull();
    dispose();
  });

  it("onVerified success stores data + session password, closes reauth, starts countdown, fires onReveal", async () => {
    vi.useFakeTimers();
    const secret: FakeSecret = { value: "top-secret" };
    const revealFn = vi.fn(async (pw: string) => {
      expect(pw).toBe("correct horse");
      return secret;
    });
    const onReveal = vi.fn();

    const { result, dispose } = withRoot(() =>
      useReveal<FakeSecret>({ revealFn, onReveal }),
    );

    result.request();
    await result.onVerified("correct horse");

    expect(revealFn).toHaveBeenCalledWith("correct horse");
    expect(result.revealed()).toBe(secret);
    expect(result.sessionPassword()).toBe("correct horse");
    expect(result.showReAuth()).toBe(false);
    expect(result.remainingMs()).toBe(REVEAL_AUTO_HIDE_MS);
    expect(onReveal).toHaveBeenCalledWith(secret, "correct horse");
    dispose();
  });

  it("onVerified rejection propagates and reveals nothing (ReAuthPrompt shows error inline)", async () => {
    const revealFn = vi.fn(async () => {
      throw "Incorrect password.";
    });
    const onReveal = vi.fn();

    const { result, dispose } = withRoot(() =>
      useReveal<FakeSecret>({ revealFn, onReveal }),
    );

    result.request();
    await expect(result.onVerified("wrong")).rejects.toBe("Incorrect password.");

    // Nothing revealed, no session password, prompt stays open for retry, no countdown.
    expect(result.revealed()).toBeNull();
    expect(result.sessionPassword()).toBeNull();
    expect(result.showReAuth()).toBe(true);
    expect(result.remainingMs()).toBe(0);
    expect(onReveal).not.toHaveBeenCalled();
    dispose();
  });

  it("hide() clears data + session password + countdown and fires onHide", async () => {
    const onHide = vi.fn();
    const { result, dispose } = withRoot(() =>
      useReveal<FakeSecret>({ revealFn: async () => ({ value: "x" }), onHide }),
    );

    await result.onVerified("pw");
    expect(result.revealed()).not.toBeNull();

    result.hide();
    expect(result.revealed()).toBeNull();
    expect(result.sessionPassword()).toBeNull();
    expect(result.remainingMs()).toBe(0);
    expect(onHide).toHaveBeenCalledTimes(1);
    dispose();
  });

  it("remainingMs counts down and auto-hides at the unified timeout", async () => {
    vi.useFakeTimers();
    const onHide = vi.fn();
    const { result, dispose } = withRoot(() =>
      useReveal<FakeSecret>({ revealFn: async () => ({ value: "x" }), onHide }),
    );

    await result.onVerified("pw");
    expect(result.remainingMs()).toBe(REVEAL_AUTO_HIDE_MS);

    // Halfway: still revealed, less time remaining.
    vi.advanceTimersByTime(30_000);
    expect(result.revealed()).not.toBeNull();
    expect(result.remainingMs()).toBeLessThanOrEqual(30_000);
    expect(result.remainingMs()).toBeGreaterThan(0);
    expect(onHide).not.toHaveBeenCalled();

    // At the full timeout: cleared + onHide fired.
    vi.advanceTimersByTime(30_000);
    expect(result.revealed()).toBeNull();
    expect(result.sessionPassword()).toBeNull();
    expect(result.remainingMs()).toBe(0);
    expect(onHide).toHaveBeenCalledTimes(1);
    dispose();
  });

  it("does not auto-hide before the timeout elapses", async () => {
    vi.useFakeTimers();
    const { result, dispose } = withRoot(() =>
      useReveal<FakeSecret>({ revealFn: async () => ({ value: "x" }) }),
    );

    await result.onVerified("pw");
    vi.advanceTimersByTime(REVEAL_AUTO_HIDE_MS - 1_000);
    expect(result.revealed()).not.toBeNull();
    dispose();
  });

  it("honors a custom autoHideMs override", async () => {
    vi.useFakeTimers();
    const { result, dispose } = withRoot(() =>
      useReveal<FakeSecret>({ revealFn: async () => ({ value: "x" }), autoHideMs: 5_000 }),
    );

    await result.onVerified("pw");
    expect(result.remainingMs()).toBe(5_000);

    vi.advanceTimersByTime(5_000);
    expect(result.revealed()).toBeNull();
    dispose();
  });

  it("clears the revealed secret + session password on root disposal (cleanup)", async () => {
    const handle = withRoot(() =>
      useReveal<FakeSecret>({ revealFn: async () => ({ value: "x" }) }),
    );

    await handle.result.onVerified("pw");
    expect(handle.result.revealed()).not.toBeNull();
    expect(handle.result.sessionPassword()).toBe("pw");

    handle.dispose();
    expect(handle.result.revealed()).toBeNull();
    expect(handle.result.sessionPassword()).toBeNull();
  });

  it("stops the countdown timer on disposal (no further ticks)", async () => {
    vi.useFakeTimers();
    const clearIntervalSpy = vi.spyOn(globalThis, "clearInterval");
    const onHide = vi.fn();

    const handle = withRoot(() =>
      useReveal<FakeSecret>({ revealFn: async () => ({ value: "x" }), onHide }),
    );

    await handle.result.onVerified("pw");
    handle.dispose();
    expect(clearIntervalSpy).toHaveBeenCalled();

    // Advancing past the timeout must not fire the auto-hide onHide anymore.
    onHide.mockClear();
    vi.advanceTimersByTime(REVEAL_AUTO_HIDE_MS * 2);
    expect(onHide).not.toHaveBeenCalled();
  });
});
