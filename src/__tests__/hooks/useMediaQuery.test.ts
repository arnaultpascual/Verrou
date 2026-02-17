import { describe, expect, it, vi, beforeEach } from "vitest";
import { createRoot } from "solid-js";

describe("useMediaQuery", () => {
  let listeners: Map<string, (e: MediaQueryListEvent) => void>;
  let matchesMap: Map<string, boolean>;

  beforeEach(() => {
    listeners = new Map();
    matchesMap = new Map();

    vi.stubGlobal("matchMedia", (query: string) => {
      const mql = {
        matches: matchesMap.get(query) ?? false,
        media: query,
        addEventListener: (_event: string, handler: (e: MediaQueryListEvent) => void) => {
          listeners.set(query, handler);
        },
        removeEventListener: (_event: string, _handler: (e: MediaQueryListEvent) => void) => {
          listeners.delete(query);
        },
      };
      return mql;
    });
  });

  it("returns initial match state (false)", async () => {
    const { useMediaQuery } = await import("../../hooks/useMediaQuery");
    createRoot((dispose) => {
      const matches = useMediaQuery("(max-width: 959px)");
      expect(matches()).toBe(false);
      dispose();
    });
  });

  it("returns initial match state (true)", async () => {
    matchesMap.set("(max-width: 959px)", true);
    const { useMediaQuery } = await import("../../hooks/useMediaQuery");
    createRoot((dispose) => {
      const matches = useMediaQuery("(max-width: 959px)");
      expect(matches()).toBe(true);
      dispose();
    });
  });

  it("registers change listener", async () => {
    const { useMediaQuery } = await import("../../hooks/useMediaQuery");
    createRoot((dispose) => {
      useMediaQuery("(max-width: 959px)");
      expect(listeners.has("(max-width: 959px)")).toBe(true);
      dispose();
    });
  });

  it("cleans up listener on dispose", async () => {
    const { useMediaQuery } = await import("../../hooks/useMediaQuery");
    createRoot((dispose) => {
      useMediaQuery("(max-width: 959px)");
      expect(listeners.has("(max-width: 959px)")).toBe(true);
      dispose();
      expect(listeners.has("(max-width: 959px)")).toBe(false);
    });
  });

  it("updates when media query changes", async () => {
    const { useMediaQuery } = await import("../../hooks/useMediaQuery");
    createRoot((dispose) => {
      const matches = useMediaQuery("(max-width: 959px)");
      expect(matches()).toBe(false);

      // Simulate media query change
      const handler = listeners.get("(max-width: 959px)");
      handler?.({ matches: true } as MediaQueryListEvent);
      expect(matches()).toBe(true);

      dispose();
    });
  });
});
