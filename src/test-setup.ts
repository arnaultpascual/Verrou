/**
 * Global test setup — runs before each test file.
 * Provides stubs for browser APIs not available in jsdom.
 */

import "@testing-library/jest-dom/vitest";

// Stub window.matchMedia (used by useMediaQuery → CountdownRing)
if (typeof window !== "undefined" && !window.matchMedia) {
  Object.defineProperty(window, "matchMedia", {
    writable: true,
    value: (query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false,
    }),
  });
}
