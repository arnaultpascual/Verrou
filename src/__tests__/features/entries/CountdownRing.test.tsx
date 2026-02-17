import { render } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { CountdownRing } from "../../../features/entries/CountdownRing";

/** Default matchMedia stub — motion NOT reduced (SVG ring path). */
function stubMatchMedia(reduceMotion = false) {
  vi.stubGlobal("matchMedia", (query: string) => ({
    matches: reduceMotion && query === "(prefers-reduced-motion: reduce)",
    media: query,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  }));
}

describe("CountdownRing", () => {
  beforeEach(() => {
    stubMatchMedia(false);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("SVG structure", () => {
    it("renders an SVG element", () => {
      render(() => <CountdownRing remaining={20} period={30} />);
      const svg = document.querySelector("svg");
      expect(svg).toBeTruthy();
    });

    it("renders two circle elements (background + foreground)", () => {
      render(() => <CountdownRing remaining={20} period={30} />);
      const circles = document.querySelectorAll("circle");
      expect(circles.length).toBe(2);
    });

    it("has 24x24 viewBox", () => {
      render(() => <CountdownRing remaining={20} period={30} />);
      const svg = document.querySelector("svg");
      expect(svg?.getAttribute("viewBox")).toBe("0 0 24 24");
    });

    it("has aria-hidden on SVG", () => {
      render(() => <CountdownRing remaining={20} period={30} />);
      const svg = document.querySelector("svg");
      expect(svg?.getAttribute("aria-hidden")).toBe("true");
    });
  });

  describe("stroke-dashoffset calculation", () => {
    it("foreground circle has stroke-dashoffset for progress", () => {
      render(() => <CountdownRing remaining={15} period={30} />);
      const fg = document.querySelectorAll("circle")[1];
      const offset = fg?.getAttribute("stroke-dashoffset");
      expect(offset).toBeTruthy();
      // 50% remaining → half circumference offset
      const circumference = 2 * Math.PI * 10;
      expect(Number(offset)).toBeCloseTo(circumference * 0.5, 0);
    });

    it("full remaining has zero offset", () => {
      render(() => <CountdownRing remaining={30} period={30} />);
      const fg = document.querySelectorAll("circle")[1];
      const offset = fg?.getAttribute("stroke-dashoffset");
      expect(Number(offset)).toBeCloseTo(0, 0);
    });

    it("1 second remaining has nearly full offset", () => {
      render(() => <CountdownRing remaining={1} period={30} />);
      const fg = document.querySelectorAll("circle")[1];
      const offset = fg?.getAttribute("stroke-dashoffset");
      const circumference = 2 * Math.PI * 10;
      expect(Number(offset)).toBeCloseTo(circumference * (29 / 30), 0);
    });
  });

  describe("warning state", () => {
    it("applies warning class when remaining <= 5", () => {
      render(() => <CountdownRing remaining={4} period={30} />);
      const wrapper = document.querySelector("[data-testid='countdown-ring']");
      expect(wrapper?.className).toContain("warning");
    });

    it("does not apply warning class when remaining > 5", () => {
      render(() => <CountdownRing remaining={10} period={30} />);
      const wrapper = document.querySelector("[data-testid='countdown-ring']");
      expect(wrapper?.className).not.toContain("warning");
    });

    it("applies warning at exactly 5 seconds", () => {
      render(() => <CountdownRing remaining={5} period={30} />);
      const wrapper = document.querySelector("[data-testid='countdown-ring']");
      expect(wrapper?.className).toContain("warning");
    });
  });

  describe("reduced motion", () => {
    it("shows text countdown when reduced motion is preferred", () => {
      stubMatchMedia(true);

      render(() => <CountdownRing remaining={23} period={30} />);
      expect(document.body.textContent).toContain("23s");
      const svg = document.querySelector("svg");
      expect(svg).toBeNull();
    });

    it("shows SVG ring when motion is not reduced", () => {
      stubMatchMedia(false);

      render(() => <CountdownRing remaining={23} period={30} />);
      const svg = document.querySelector("svg");
      expect(svg).toBeTruthy();
    });
  });
});
